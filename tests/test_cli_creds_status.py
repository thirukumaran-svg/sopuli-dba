"""``sopuli creds status`` end to end, without a database (#275).

Same arrangement as the other credential-verb CLI files. One assertion runs
through every case here and is the point of the verb: **the session recorded no
login attempt**. `check` spends one per account and this spends none, and the
only way to test the difference is to count.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator

from sopuli import check, status
from sopuli.admin import Resolved
from sopuli.cli import cli
from sopuli.config.model import Vault
from sopuli.config.targets import EXTERNAL
from sopuli.driver.protocol import Credential, Scope, UserState
from sopuli.exit_codes import ExitCode
from sopuli.output.document import SCHEMA_VERSION
from sopuli.secrets import Secret
from sopuli.store import MemoryStore, SecretStore

RUN_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

CONFIG = """\
version: 1
vaults:
  vault-prod:
    type: hashicorp
    addr: https://vault-prod.example.com:8200
targets:
  - name: appdb-alpha
    type: oracle
    dsn: db-prod.example.com:1521/alpha.pdb.example.com
    environment: prod
    labels: { env: prod, tenant: alpha }
    vault: vault-prod
applications:
  - name: acme
    accounts: [acme_web_user, acme_batch_user]
    secret_template: "apps/acme/db#DB_CREDENTIALS/{account}"
"""

LIVE = "Correct-Horse-Battery-9"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8")))


class FakeSession:
    """One target's accounts, and a record of anything it was asked to try.

    ``attempts`` exists to stay empty. It is the assertion every test in this
    file makes.
    """

    def __init__(self, users: Mapping[str, UserState | None]) -> None:
        self.users = dict(users)
        self.attempts: list[str] = []
        self.closed = False

    def scope(self) -> Scope:
        return Scope(type="pdb", container="ALPHA", read_write=True)

    def describe_user(self, account: str) -> UserState | None:
        return self.users.get(account.upper())

    def verify_password(self, account: str, secret: Secret, **_: Any) -> Any:
        self.attempts.append(account.upper())
        raise AssertionError("creds status must never attempt a login")

    def close(self) -> None:
        self.closed = True


def account(name: str, **fields: Any) -> UserState:
    return UserState(**{"name": name, "status": "OPEN", "profile": "APP_PROFILE", **fields})


def ago(days: float) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).isoformat().replace("+00:00", "Z")


Harness = Callable[..., dict[str, Any]]


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Harness:
    def install(
        *,
        document: dict[str, Any] | None = None,
        users: Mapping[str, UserState | None] | None = None,
        connect_error: Exception | None = None,
    ) -> dict[str, Any]:
        store = MemoryStore()
        store.write("apps/acme/db", document if document is not None else _rotated(), cas=0)

        sessions: list[FakeSession] = []

        def fake_connect(
            vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
        ) -> SecretStore:
            return store

        class FakeDriver:
            def __init__(self, **_: Any) -> None:
                pass

            def connect(self, target: Any, credential: Any) -> FakeSession:
                if connect_error is not None:
                    raise connect_error
                session = FakeSession(users if users is not None else _both())
                sessions.append(session)
                return session

        class FakeModule:
            OracleDriver = FakeDriver

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        monkeypatch.setattr("sopuli.cli.resolve_driver", lambda target: FakeModule)
        monkeypatch.setattr("sopuli.cli.admin_resolve", lambda target, **_: _credential())
        return {"store": store, "sessions": sessions}

    return install


def _both() -> dict[str, UserState]:
    return {
        "ACME_WEB_USER": account("ACME_WEB_USER"),
        "ACME_BATCH_USER": account("ACME_BATCH_USER"),
    }


def _rotated() -> dict[str, Any]:
    """A finished rotation, aged differently per account -- §9's own shape."""
    return {
        "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
        "rotated_at": {"acme_web_user": ago(12), "acme_batch_user": ago(94)},
    }


def _credential() -> Any:
    """The admin credential the CLI would have resolved.

    A real :class:`~sopuli.admin.Resolved` rather than a stub with one attribute.
    The command reads its *provenance* as well as its value now -- #477 reports
    where an admin credential came from -- and a stub stops being enough the
    moment anything but `.credential` is read. `external` because these estates
    declare no `admin:` block at all, and it is the one source that carries
    neither a username nor a secret.
    """
    return Resolved(
        credential=Credential(external=True),
        method=EXTERNAL,
        source="an external password store",
    )


def run(runner: CliRunner, config: Path, *args: str) -> Result:
    return runner.invoke(cli, ["creds", "status", "--config", str(config), *args])


def document(result: Result) -> dict[str, Any]:
    return dict(json.loads(result.output))


def row(result: Result, account: str) -> str:
    """That account's line in the **status** table.

    The last one, because the plan prints a row per account first and its columns
    are a different set -- matching the first would assert about the plan while
    claiming to assert about the inventory.
    """
    lines = [line for line in result.output.splitlines() if line.startswith(account)]
    assert lines, f"no row for {account}"
    return lines[-1]


# ------------------------------------------------------- the whole point ---


def test_no_login_is_ever_attempted(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The verb's defining property. `check` spends one per account; this spends
    none, and counting is the only way to tell them apart."""
    harness = estate()
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["sessions"][0].attempts == []


def test_no_lock_is_taken(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """An hourly inventory that blocked rotations would be a worse problem than
    any it solved."""
    estate()
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert "lock" not in document(result)


def test_nothing_in_the_vault_changes(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate()
    before = harness["store"].read("apps/acme/db").version
    run(runner, write_config(CONFIG))

    assert harness["store"].read("apps/acme/db").version == before


# ------------------------------------------------------------- the table ---


def test_the_two_ages_sit_side_by_side(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """§9's drift smell: the same database history answering differently
    depending on which clock is asked."""
    estate()
    result = run(runner, write_config(CONFIG))

    header = next(line for line in result.output.splitlines() if "VAULT_V" in line)
    assert header.index("AGE") < header.index("DB_PW_CHANGED")


def test_the_age_is_the_vault_s(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Q9. The database reports a change 400 days ago and the vault 12; the
    column shows 12."""
    estate(
        users={
            "ACME_WEB_USER": account(
                "ACME_WEB_USER", password_changed_at=datetime.now(UTC) - timedelta(days=400)
            ),
            "ACME_BATCH_USER": account("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG))

    found = row(result, "acme_web_user")
    assert "12d" in found
    assert "400" not in found


#: What the Oracle driver says on 18c without the `SYS.USER$` grant (#386).
NO_COLUMN = (
    "this release has no DBA_USERS.PASSWORD_CHANGE_DATE; GRANT SELECT ON "
    "SYS.USER$ to the service account to read the same date from SYS.USER$.PTIME"
)


def test_an_empty_db_pw_changed_says_why_in_the_document(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    """#386: a consumer cannot see a dash. The field stays absent -- it is the
    honest answer -- and the result says why, under a code."""
    estate(
        users={
            "ACME_WEB_USER": account("ACME_WEB_USER", password_changed_unknown=NO_COLUMN),
            "ACME_BATCH_USER": account(
                "ACME_BATCH_USER", password_changed_at=datetime.now(UTC) - timedelta(days=3)
            ),
        }
    )
    result = run(runner, write_config(CONFIG), "--output", "json")
    found = document(result)

    web = next(one for one in found["results"] if one["account"] == "acme_web_user")
    assert "password_age_days" not in web
    assert [one["code"] for one in web["warnings"]] == ["SOPULI-W021"]
    assert web["warnings"][0]["message"] == NO_COLUMN

    batch = next(one for one in found["results"] if one["account"] == "acme_batch_user")
    assert "password_age_days" in batch
    assert "warnings" not in batch, "a date that was read needs no explanation"
    assert not list(validator.iter_errors(found))


def test_an_empty_db_pw_changed_says_why_once_per_target_in_the_table(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """One missing column on one target is one note, however many accounts sit
    on it -- forty identical lines would teach the reader to skip the block."""
    estate(
        users={
            "ACME_WEB_USER": account("ACME_WEB_USER", password_changed_unknown=NO_COLUMN),
            "ACME_BATCH_USER": account("ACME_BATCH_USER", password_changed_unknown=NO_COLUMN),
        }
    )
    result = run(runner, write_config(CONFIG))

    assert "-" in row(result, "acme_web_user")
    assert result.output.count("GRANT SELECT ON SYS.USER$") == 1
    assert "appdb-alpha: DB_PW_CHANGED is empty for 2 accounts" in result.output


def test_a_quiet_estate_says_so(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """An inventory's ordinary answer is that there is nothing to do, and a
    survey that always ends in a list of counts trains people to skip the last
    line."""
    estate()
    result = run(runner, write_config(CONFIG))

    assert "nothing to act on" in result.output


def test_the_table_is_ascii(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """P4: identical output on every platform."""
    estate()
    run(runner, write_config(CONFIG)).output.encode("ascii")


# --------------------------------------------------------- the threshold ---


def test_max_age_days_marks_the_row_and_the_verdict(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate()
    result = run(runner, write_config(CONFIG), "--max-age-days", "90")

    assert "!" in row(result, "acme_batch_user")
    assert "1 past max age" in result.output


def test_an_unknown_age_is_not_marked(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A credential this tool has never rotated has an age of *unknown*, and
    `--max-age-days` must not select it -- otherwise the first run against a
    freshly adopted estate proposes rotating all of it."""
    estate(document={"DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE}})
    result = run(runner, write_config(CONFIG), "--max-age-days", "1")

    assert "past max age" not in result.output
    assert result.exit_code == ExitCode.SUCCESS


def test_the_threshold_reports_which_clock_it_read(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`password_age_days` in the document means the *database's* age, so the
    vault's travels as a warning that names its source."""
    estate()
    result = run(runner, write_config(CONFIG), "--max-age-days", "90", "--output", "json")

    entry = next(one for one in document(result)["results"] if one["account"] == "acme_batch_user")
    assert any("the vault last rotated" in one["message"] for one in entry["warnings"])


# ------------------------------------------------------------- the states ---


def test_a_missing_account_is_a_row_rather_than_an_omission(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 5 makes the config the whitelist, so an account it declares and
    the database lacks is exactly the row worth seeing."""
    estate(users={"ACME_WEB_USER": account("ACME_WEB_USER")})
    result = run(runner, write_config(CONFIG))

    assert check.ACCOUNT_MISSING in result.output
    assert "1 missing" in result.output


def test_a_staged_rotation_is_surfaced(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate(
        document={
            "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
            "pending": {"acme_web_user": "staged"},
        }
    )
    result = run(runner, write_config(CONFIG))

    assert status.PENDING_APPLY in result.output
    assert "1 awaiting apply" in result.output


def test_a_locked_account_is_counted(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate(
        users={
            "ACME_WEB_USER": account("ACME_WEB_USER", status="LOCKED", locked=True),
            "ACME_BATCH_USER": account("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG))

    assert "1 locked or expired" in result.output


def test_the_rollover_column_tells_three_answers_apart(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """ "Not configured" and "configured and quiet" decide whether a zero-downtime
    rotation is available at all, which is what §6.3 makes an operator ask before
    scheduling one."""
    estate(
        users={
            "ACME_WEB_USER": account("ACME_WEB_USER", rollover_time="1", rollover_active=True),
            "ACME_BATCH_USER": account("ACME_BATCH_USER", rollover_time="0"),
        }
    )
    result = run(runner, write_config(CONFIG))

    assert "window open" in result.output
    assert "not configured" in result.output


# ------------------------------------------------------------ the failures ---


def test_an_unreachable_target_keeps_the_vault_half_of_the_row(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The version and the age came from a document read before any database was
    dialled. An inventory that threw them away because a listener was down would
    answer less than it knows."""
    estate(connect_error=RuntimeError("ORA-12541: no listener"))
    result = run(runner, write_config(CONFIG), "--output", "json")

    body = document(result)
    assert body["exit_code"] == ExitCode.FAILURE
    assert all(one["state"] == check.ERROR for one in body["results"])
    assert "1 unreachable" not in result.output  # json mode prints no table


def test_an_unreachable_target_is_exit_one(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`check`'s rule: an inventory with a hole in it must not look complete."""
    estate(connect_error=RuntimeError("ORA-12541: no listener"))
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.FAILURE
    assert "2 unreachable" in result.output


def test_a_document_that_cannot_be_resolved_still_renders_its_row(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A ref landing on the wrong depth is a real finding that `check` and
    `apply` refuse over. This verb's job is to render the estate around it."""
    estate(document={"DB_CREDENTIALS": "not-a-map"})
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert check.UNVERIFIABLE in result.output


def test_the_document_validates(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    estate()
    result = run(runner, write_config(CONFIG), "--max-age-days", "90", "--output", "json")

    body = document(result)
    assert not list(validator.iter_errors(body))
    assert [one["kind"] for one in body["results"][0]["actions"]] == ["none"]
    assert all(one["changed"] is False for one in body["results"])

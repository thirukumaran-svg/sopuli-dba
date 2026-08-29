"""``sopuli creds apply`` end to end, without a database (#259).

Same arrangement as ``tests/test_cli_creds_check.py``: in-process through
``CliRunner``, with the vault a :class:`~sopuli.store.MemoryStore` and the driver
a fake session. The real ones have their own suites; this file is about *the
command* -- what it reads, in what order, what it issues, what it promotes, and
what it exits with.

Two properties carry most of it, and both are about restraint:

* **nothing is promoted that was not confirmed** (invariant 7), asserted on the
  document the store actually holds afterwards rather than on what the run said;
* **a second run changes nothing** (invariant 9), asserted on the statements the
  fake session recorded rather than on ``changed`` -- a command can report
  ``false`` and still have issued the DDL.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator

from sopuli import check
from sopuli.cli import cli
from sopuli.config.model import Vault
from sopuli.driver.protocol import (
    FAIL,
    PASS,
    SKIPPED,
    VERIFY_LOGIN,
    ChangeResult,
    Scope,
    UserState,
    VerifyResult,
)
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

#: One application over two PDBs, one document per tenant, a field per account --
#: Q7's documented layout, so the shared-document path is the one under test.
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
  - name: appdb-beta
    type: oracle
    dsn: db-prod.example.com:1521/beta.pdb.example.com
    environment: prod
    labels: { env: prod, tenant: beta }
    vault: vault-prod
applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "apps/acme/{target}#DB_CREDENTIALS/{account}"
"""

#: Two accounts in one document, which is what makes the promotion gate visible:
#: both must confirm before either is promoted.
SHARED_CONFIG = """\
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
    vault: vault-prod
applications:
  - name: acme
    accounts: [acme_web_user, acme_batch_user]
    secret_template: "apps/acme/db#DB_CREDENTIALS/{account}"
"""

LIVE = "Correct-Horse-Battery-9"
STAGED = "Vertical-Anchor-Marble-4"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8")))


class FakeSession:
    """One target's worth of answers, and a record of everything it was asked.

    The recording is the point. Half of what `apply` must get right is what it
    does *not* do -- no DDL against a locked account, no second change on a
    re-run, no login beyond the two it budgeted -- and none of that is visible in
    the output.
    """

    def __init__(
        self,
        users: Mapping[str, UserState | None],
        answers: Mapping[str, list[VerifyResult]],
        *,
        set_error: Exception | None = None,
    ) -> None:
        self.users = dict(users)
        self.answers = {name: list(results) for name, results in answers.items()}
        self.set_error = set_error
        self.attempts: list[tuple[str, str]] = []
        self.budgets: list[int] = []
        self.changed: list[tuple[str, str]] = []
        self.closed = False

    def scope(self) -> Scope:
        return Scope(type="pdb", container="ALPHA", read_write=True)

    def describe_user(self, account: str) -> UserState | None:
        return self.users.get(account.upper())

    def verify_password(
        self,
        account: str,
        secret: Secret,
        *,
        method: str = VERIFY_LOGIN,
        lockout_margin: int = 2,
        attempts: int = 1,
    ) -> VerifyResult:
        self.attempts.append((account.upper(), secret.reveal()))
        self.budgets.append(attempts)
        queued = self.answers.get(account.upper(), [])
        return queued.pop(0) if queued else VerifyResult(VERIFY_LOGIN, PASS, latency_ms=9)

    def set_password(self, account: str, secret: Secret) -> ChangeResult:
        if self.set_error is not None:
            raise self.set_error
        self.changed.append((account.upper(), secret.reveal()))
        return ChangeResult(changed=True)

    def close(self) -> None:
        self.closed = True


def user(name: str = "ACME_WEB_USER", **fields: Any) -> UserState:
    return UserState(**{"name": name, "status": "OPEN", **fields})


def passes(count: int = 2) -> list[VerifyResult]:
    return [VerifyResult(VERIFY_LOGIN, PASS, latency_ms=9)] * count


def drifted() -> list[VerifyResult]:
    """Refused, then accepted: the ordinary rotation, before and after."""
    return [
        VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017: invalid credential"),
        VerifyResult(VERIFY_LOGIN, PASS, latency_ms=9),
    ]


Harness = Callable[..., dict[str, Any]]


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Harness:
    """Patch the store and the driver, and hand back what the run will meet."""

    def install(
        *,
        documents: Mapping[str, dict[str, Any]] | None = None,
        users: Mapping[str, UserState | None] | None = None,
        answers: Mapping[str, list[VerifyResult]] | None = None,
        per_target: Mapping[str, Mapping[str, list[VerifyResult]]] | None = None,
        connect_error: Exception | None = None,
        set_error: Exception | None = None,
    ) -> dict[str, Any]:
        store = MemoryStore()
        for path, body in (documents or _staged_two_targets()).items():
            store.write(path, body, cas=0)

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
                scripted = answers if answers is not None else {"ACME_WEB_USER": drifted()}
                if per_target is not None:
                    scripted = per_target[target.name]
                session = FakeSession(
                    users if users is not None else {"ACME_WEB_USER": user()},
                    scripted,
                    set_error=set_error,
                )
                sessions.append(session)
                return session

        class FakeModule:
            OracleDriver = FakeDriver

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        monkeypatch.setattr("sopuli.cli.resolve_driver", lambda target: FakeModule)
        monkeypatch.setattr("sopuli.cli.admin_resolve", lambda target, env: _credential())
        return {"store": store, "sessions": sessions}

    return install


def _staged_two_targets() -> dict[str, dict[str, Any]]:
    return {
        f"apps/acme/{target}": {
            "DB_CREDENTIALS": {"acme_web_user": LIVE},
            "pending": {"acme_web_user": STAGED},
        }
        for target in ("appdb-alpha", "appdb-beta")
    }


def _credential() -> Any:
    class Resolved:
        credential = object()

    return Resolved()


def run(runner: CliRunner, config: Path, *args: str) -> Result:
    return runner.invoke(cli, ["creds", "apply", "--config", str(config), *args])


def document(result: Result) -> dict[str, Any]:
    return dict(json.loads(result.output))


def stored(store: MemoryStore, path: str) -> dict[str, Any]:
    found = store.read(path)
    assert found is not None
    return dict(found.data)


# --------------------------------------------------------- the happy path ---


def test_a_staged_password_is_applied_and_promoted(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §5 end to end: the database takes `pending`, and only then does the
    vault promote it."""
    harness = estate()
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    body = stored(harness["store"], "apps/acme/appdb-alpha")
    assert body["DB_CREDENTIALS"]["acme_web_user"] == STAGED
    assert body["previous"]["acme_web_user"] == LIVE
    assert "acme_web_user" not in body.get("pending", {})


def test_the_database_is_changed_to_the_staged_value(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate()
    run(runner, write_config(CONFIG))

    for session in harness["sessions"]:
        assert session.changed == [("ACME_WEB_USER", STAGED)]


def test_the_promotion_stamps_who_and_when(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §3's stamps, per account, beside the value they describe."""
    harness = estate()
    run(runner, write_config(CONFIG))

    body = stored(harness["store"], "apps/acme/appdb-alpha")
    assert body["rotated_at"]["acme_web_user"].endswith("Z")
    assert "@" in body["rotated_by"]["acme_web_user"]
    assert body["targets"]["acme_web_user"] == ["appdb-alpha"]


def test_the_plan_and_the_source_table_come_before_anything_is_issued(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate()
    result = run(runner, write_config(CONFIG))

    assert result.output.index("Plan:") < result.output.index("SOURCE")
    assert result.output.index("SOURCE") < result.output.index("STATE")


def test_the_document_validates_and_reports_the_promotion(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    estate()
    result = run(runner, write_config(CONFIG), "--output", "json")

    body = document(result)
    assert not list(validator.iter_errors(body))
    kinds = [action["kind"] for action in body["results"][0]["actions"]]
    assert kinds == ["verify", "password_set", "verify", "vault_promote"]
    assert body["results"][0]["secret"]["stage"] == "current"


# ------------------------------------------------------------ idempotency ---


def test_a_second_run_changes_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 9 names `apply` as the convergent verb. With nothing staged and
    a password the database accepts, no DDL is issued at all."""
    harness = estate(
        documents={"apps/acme/appdb-alpha": {"DB_CREDENTIALS": {"acme_web_user": LIVE}}},
        answers={"ACME_WEB_USER": passes(1)},
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["sessions"][0].changed == []
    assert document(result)["results"][0]["changed"] is False


def test_nothing_is_promoted_when_nothing_was_staged(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A run that read `current` is a repair; the vault already holds what it
    should, and writing a new version would be a version describing no change."""
    harness = estate(
        documents={"apps/acme/appdb-alpha": {"DB_CREDENTIALS": {"acme_web_user": LIVE}}},
        answers={"ACME_WEB_USER": passes(1)},
    )
    before = harness["store"].read("apps/acme/appdb-alpha").version
    run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["store"].read("apps/acme/appdb-alpha").version == before


def test_a_repair_beside_a_rotation_exits_zero(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Two documents, one staged and one not. The repair has nothing to promote,
    so counting it as unpromoted would make a run where everything confirmed look
    like UC-1 §8 case 7 -- the database holding the new password while the vault
    still advertises the old one -- and exit 4 with nothing wrong."""
    harness = estate(
        documents={
            "apps/acme/appdb-alpha": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE},
                "pending": {"acme_web_user": STAGED},
            },
            "apps/acme/appdb-beta": {"DB_CREDENTIALS": {"acme_web_user": LIVE}},
        },
        per_target={
            "appdb-alpha": {"ACME_WEB_USER": drifted()},
            "appdb-beta": {"ACME_WEB_USER": passes(1)},
        },
    )
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"] == {}
    assert "previous" not in stored(harness["store"], "apps/acme/appdb-beta")


def test_a_drifted_target_is_repaired_from_current(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The repair case, and the one that makes the pre-flight login worth its
    cost: the same command converges a database that has fallen out of step."""
    harness = estate(
        documents={"apps/acme/appdb-alpha": {"DB_CREDENTIALS": {"acme_web_user": LIVE}}},
        answers={"ACME_WEB_USER": drifted()},
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["sessions"][0].changed == [("ACME_WEB_USER", LIVE)]


# ----------------------------------------------------- what is not touched ---


def test_a_locked_account_is_not_changed(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The DDL would succeed and could never be confirmed. Asserted on the
    session rather than on the state, because a command can report `LOCKED` and
    still have issued the statement."""
    harness = estate(
        users={"ACME_WEB_USER": user(status="LOCKED", locked=True)},
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].changed == []
    assert harness["sessions"][0].attempts == []
    assert check.LOCKED in result.output


def test_a_missing_account_is_reported_and_not_created(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate(users={})
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].changed == []
    assert check.ACCOUNT_MISSING in result.output
    assert result.exit_code == ExitCode.FAILURE


def test_an_empty_vault_fails_rather_than_reporting_success(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A mutating verb that exits 0 having converged nothing is the silent
    failure worth being loud about."""
    harness = estate(documents={"apps/acme/appdb-alpha": {"other": "value"}})
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.FAILURE
    assert harness["sessions"][0].changed == []
    assert "creds generate" in result.output


def test_dry_run_reads_the_vault_and_writes_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 8. The documents are still read -- which stage an account would
    be applied from is the thing worth reviewing, and a read needs no lock."""
    harness = estate()
    result = run(runner, write_config(CONFIG), "--dry-run")

    assert result.exit_code == ExitCode.SUCCESS
    assert "pending" in result.output
    assert "nothing was applied" in result.output
    assert harness["sessions"] == []
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]


# ----------------------------------------------------------- the promotion ---


def test_one_failed_target_stops_the_promotion_for_that_document(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 7 and UC-1 §5: promoting would advertise a password part of the
    estate does not have. Each target has its own document here, so only the one
    that failed is held back."""
    harness = estate(
        per_target={
            "appdb-alpha": {"ACME_WEB_USER": drifted()},
            "appdb-beta": {
                "ACME_WEB_USER": [
                    VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017"),
                    VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017"),
                ]
            },
        }
    )
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.PARTIAL
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"] == {}
    assert stored(harness["store"], "apps/acme/appdb-beta")["pending"]["acme_web_user"] == STAGED


def test_a_changed_database_with_no_promotion_carries_a_warning(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §8's highest-severity row: applications fetch `current`, and until
    the promotion lands they are fetching a password the database no longer
    has."""
    estate(
        answers={
            "ACME_WEB_USER": [
                VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017"),
                VerifyResult(VERIFY_LOGIN, SKIPPED, detail="within 2 of the limit"),
            ]
        }
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")

    warnings = document(result)["results"][0]["warnings"]
    assert any("was not promoted" in one["message"] for one in warnings)


def test_two_accounts_sharing_a_document_promote_together(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Q7's default layout: one write, one version, both accounts."""
    harness = estate(
        documents={
            "apps/acme/db": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
                "pending": {"acme_web_user": STAGED, "acme_batch_user": STAGED},
            }
        },
        users={"ACME_WEB_USER": user(), "ACME_BATCH_USER": user("ACME_BATCH_USER")},
        answers={"ACME_WEB_USER": drifted(), "ACME_BATCH_USER": drifted()},
    )
    before = harness["store"].read("apps/acme/db").version
    result = run(runner, write_config(SHARED_CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["store"].read("apps/acme/db").version == before + 1
    assert stored(harness["store"], "apps/acme/db")["pending"] == {}


def test_one_account_failing_holds_back_its_sibling_too(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """They share a document, so they share its commit. Promoting one and not the
    other would need two writes and would leave a document nobody intended."""
    harness = estate(
        documents={
            "apps/acme/db": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
                "pending": {"acme_web_user": STAGED, "acme_batch_user": STAGED},
            }
        },
        users={"ACME_WEB_USER": user(), "ACME_BATCH_USER": None},
        answers={"ACME_WEB_USER": drifted()},
    )
    result = run(runner, write_config(SHARED_CONFIG))

    assert result.exit_code == ExitCode.PARTIAL
    assert stored(harness["store"], "apps/acme/db")["pending"]["acme_web_user"] == STAGED


# -------------------------------------------------------------- the failures ---


def test_an_unreachable_target_is_a_finding_and_not_a_crash(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """And it means something stronger here than in `check`: a database that
    could not be reached cannot cause a password it does not have to be
    advertised."""
    harness = estate(connect_error=RuntimeError("ORA-12541: no listener"))
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.FAILURE
    assert "ORA-12541" in result.output
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]


def test_a_refused_statement_is_reported_per_account(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """ORA-28003 and friends: the server refused the password. It is reported and
    never regenerated here -- the value came from the vault, and drawing a
    different one would make the vault and the database disagree with what the
    operator staged."""
    harness = estate(set_error=RuntimeError("ORA-28003: password verify function rejected it"))
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.FAILURE
    assert "ORA-28003" in result.output
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]


def test_readonly_refuses_before_anything_connects(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 10's ratchet, and invariant 4's timing."""
    harness = estate()
    result = run(runner, write_config(CONFIG), "--readonly")

    assert harness["sessions"] == []
    assert result.exit_code != ExitCode.SUCCESS


# ------------------------------------------------------- the lockout budget ---


def test_both_logins_are_budgeted_up_front(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §7 mitigation 1 counts attempts per *run*. Asking for one and then
    asking again would let a run spend two on a counter the guard was protecting
    from spending two."""
    harness = estate()
    run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].budgets == [2, 2]


def test_a_declined_pre_flight_still_applies(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The guard declining means the run cannot tell whether a change is needed,
    and `ALTER USER` is not a login -- so applying converges and costs the
    counter nothing."""
    harness = estate(
        answers={
            "ACME_WEB_USER": [
                VerifyResult(VERIFY_LOGIN, SKIPPED, detail="within 2 of the limit"),
                VerifyResult(VERIFY_LOGIN, PASS, latency_ms=9),
            ]
        }
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].changed == [("ACME_WEB_USER", STAGED)]
    assert result.exit_code == ExitCode.SUCCESS

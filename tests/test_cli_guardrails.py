"""The §4 account guardrails, finally asked of something (#286).

`sopuli/driver/guardrails.py` implemented every one of
`02-oracle-privileges.md` §4's five checks, documented `--force`, and had a full
unit suite — and no command imported it. So `creds apply` would issue
`ALTER USER` against an `ORACLE_MAINTAINED` account, or one holding `DBA`,
provided the config declared it.

The unit suite is `tests/driver/test_guardrails.py`, which is about what
`review()` decides. This file is about the part that was missing: **the command
asks, and does the right thing with the answer.** Every case here asserts on the
statements the fake session recorded, because a guardrail that returns a refusal
the command then ignores looks identical in the output to one that worked.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator

from sopuli.apply import SKIPPED
from sopuli.cli import cli
from sopuli.config.model import Vault
from sopuli.driver.protocol import (
    PASS,
    ChangeResult,
    PrivilegeAudit,
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

LIVE = "Correct-Horse-Battery-9"
STAGED = "Vertical-Anchor-Marble-4"

#: Two accounts on one target, so "the run does the rest of its job" is
#: observable: one is guarded and the other must still be applied.
CONFIG = """\
version: 1
defaults:
  policy: app-standard
policies:
  app-standard:
    password: { length: 24, charset: alnum, first_char: alpha }
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

#: The same estate declaring an account whose *name* is on §4 check 5's list.
#: Check 1 has to pass for check 5 to be the one doing the work, so the name has
#: to be declared -- which is the whole point: a site that genuinely runs `SCOTT`
#: says so in its config.
DECLARES_SCOTT = CONFIG.replace(
    "accounts: [acme_web_user, acme_batch_user]", "accounts: [scott, acme_batch_user]"
)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8")))


class FakeSession:
    def __init__(self, users: Mapping[str, UserState]) -> None:
        self.users = dict(users)
        self.attempts: list[str] = []
        self.changed: list[tuple[str, str]] = []

    def scope(self) -> Scope:
        return Scope(type="pdb", container="ALPHA", read_write=True, capabilities=frozenset())

    def privileges(self) -> PrivilegeAudit:
        return PrivilegeAudit()

    def describe_user(self, account: str) -> UserState | None:
        return self.users.get(account.upper())

    def require_rollover(self, account: str) -> None:
        return None

    def finish_rollover(self, account: str) -> ChangeResult:
        return ChangeResult(changed=True)

    def verify_password(self, account: str, secret: Secret, **_: Any) -> VerifyResult:
        self.attempts.append(account.upper())
        held = dict(self.changed).get(account.upper(), LIVE)
        return VerifyResult("login", PASS if secret.reveal() == held else "fail", latency_ms=9)

    def set_password(self, account: str, secret: Secret) -> ChangeResult:
        self.changed.append((account.upper(), secret.reveal()))
        return ChangeResult(changed=True)

    def close(self) -> None:
        return None


def account(name: str, **fields: Any) -> UserState:
    """One account as the database would describe it, guardrail fields included."""
    return UserState(**{"name": name, "status": "OPEN", **fields})


#: An ordinary application account: nothing §4 objects to.
def ordinary(name: str = "ACME_WEB_USER") -> UserState:
    return account(name, vendor_maintained=False)


Harness = Callable[..., dict[str, Any]]


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Harness:
    def install(
        users: Mapping[str, UserState],
        *,
        document: dict[str, Any] | None = None,
        session: type[FakeSession] = FakeSession,
    ) -> dict[str, Any]:
        store = MemoryStore()
        store.write(
            "apps/acme/db",
            document
            or {
                "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
                "pending": {"acme_web_user": STAGED, "acme_batch_user": STAGED},
            },
            cas=0,
        )
        sessions: list[FakeSession] = []

        def fake_connect(
            vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
        ) -> SecretStore:
            return store

        class FakeDriver:
            def __init__(self, **_: Any) -> None:
                pass

            def connect(self, target: Any, credential: Any) -> FakeSession:
                opened = session(users)
                sessions.append(opened)
                return opened

        class FakeModule:
            OracleDriver = FakeDriver

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        monkeypatch.setattr("sopuli.cli.resolve_driver", lambda target: FakeModule)
        monkeypatch.setattr("sopuli.cli.admin_resolve", lambda target, env: _credential())
        return {"store": store, "sessions": sessions}

    return install


def _credential() -> Any:
    class Resolved:
        credential = object()

    return Resolved()


def run(runner: CliRunner, config: Path, *args: str) -> Result:
    return runner.invoke(cli, ["creds", "apply", "--config", str(config), *args])


def document(result: Result) -> dict[str, Any]:
    return dict(json.loads(result.output))


def changed(harness: dict[str, Any]) -> list[str]:
    return [name for session in harness["sessions"] for name, _ in session.changed]


def states(result: Result) -> dict[str, str]:
    return {entry["account"]: entry["state"] for entry in document(result)["results"]}


# ------------------------------------------------------ the checks now fire ---


def test_a_vendor_maintained_account_is_not_touched(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """§4 check 2, and the headline of #286: before this, the DDL was issued."""
    harness = estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert "ACME_WEB_USER" not in changed(harness)
    assert states(result)["acme_web_user"] == SKIPPED


def test_an_account_holding_dba_is_not_touched(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """§4 check 4. `describe_user` reads roles unconditionally for this reason --
    a lazy read would give an empty `roles` that looks exactly like an account
    holding none."""
    harness = estate(
        {
            "ACME_WEB_USER": account(
                "ACME_WEB_USER", vendor_maintained=False, roles=frozenset({"DBA"})
            ),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert "ACME_WEB_USER" not in changed(harness)
    guarded = next(one for one in document(result)["results"] if one["account"] == "acme_web_user")
    assert guarded["state"] == SKIPPED
    assert "DBA" in json.dumps(guarded)


def test_the_deny_list_covers_a_version_that_cannot_answer(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """§4 check 5, which runs only where check 2 said nothing -- 11.2, where
    `ORACLE_MAINTAINED` does not exist and `vendor_maintained` is `None`."""
    harness = estate(
        {
            "SCOTT": account("SCOTT", vendor_maintained=None),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        },
        document={
            "DB_CREDENTIALS": {"scott": LIVE, "acme_batch_user": LIVE},
            "pending": {"scott": STAGED, "acme_batch_user": STAGED},
        },
    )
    run(runner, write_config(DECLARES_SCOTT))

    assert "SCOTT" not in changed(harness)
    assert "ACME_BATCH_USER" in changed(harness)


def test_a_version_that_answers_overrules_the_deny_list(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """§4: "where the database can report ORACLE_MAINTAINED, that answer wins
    outright -- including when it says *no* about a name on the list". Sites do
    call an account `SCOTT`."""
    harness = estate(
        {
            "SCOTT": account("SCOTT", vendor_maintained=False),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        },
        document={
            "DB_CREDENTIALS": {"scott": LIVE, "acme_batch_user": LIVE},
            "pending": {"scott": STAGED, "acme_batch_user": STAGED},
        },
    )
    run(runner, write_config(DECLARES_SCOTT))

    assert "SCOTT" in changed(harness)


# ------------------------------------------------- the run does the rest ---


def test_the_other_accounts_are_still_applied(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """§4's rule: an account that fell inside a broad selection is SKIPPED and
    the run does the rest of its job. Refusing 200 rotations because the 47th
    account was ORACLE_MAINTAINED would make the guardrail more disruptive than
    the mistake it caught."""
    harness = estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    run(runner, write_config(CONFIG))

    assert changed(harness) == ["ACME_BATCH_USER"]


def test_a_skipped_account_costs_no_login(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The check runs before the first verification, not before the statement.

    An account the tool will not touch must not spend an attempt against a
    lockout counter -- which is the same argument UC-1 §7 makes for every login
    this tool budgets.
    """
    harness = estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    run(runner, write_config(CONFIG))

    attempted = [name for session in harness["sessions"] for name in session.attempts]
    assert "ACME_WEB_USER" not in attempted


def test_a_skipped_account_does_not_make_the_run_partial(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A guardrail-refused account is not a target that failed; it is one the run
    was never going to act on. Exit 4 would say "run `apply --repair`" about a
    run where everything the tool was willing to do succeeded — and the repair
    would skip the same account again, every night, forever."""
    estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS


def test_a_run_where_everything_is_skipped_still_exits_zero(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The same answer an empty selection already gives: nothing was eligible."""
    estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": account("ACME_BATCH_USER", vendor_maintained=True),
        }
    )
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS


def test_the_reason_names_every_check_that_refused(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """An operator clearing these has to deal with all of them, and revealing
    them one run at a time would be three runs to learn one fact."""
    estate(
        {
            "ACME_WEB_USER": account(
                "ACME_WEB_USER", vendor_maintained=True, roles=frozenset({"DBA"})
            ),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG), "--output", "json")

    guarded = next(one for one in document(result)["results"] if one["account"] == "acme_web_user")
    reported = json.dumps(guarded)
    # Both checks, in §4's own numbering order: check 2 then check 4.
    assert "the database reports this account as its own" in reported
    assert "the account holds DBA" in reported


# -------------------------------------------------------------- `--force` ---


def test_force_waives_checks_two_to_five(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#89's case: rotating `DBSNMP` is ordinary DBA work, and a tool with no
    override does not prevent it — it moves it to SQL*Plus, where nothing records
    that it happened."""
    harness = estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG), "--force")

    assert result.exit_code == ExitCode.SUCCESS
    assert "ACME_WEB_USER" in changed(harness)


def test_force_records_what_it_waived(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    """§4 requires the waiver to survive the waiving: a `--force` that merely
    returned "allowed" would leave the document unable to say that somebody
    rotated a vendor account on purpose."""
    estate(
        {
            "ACME_WEB_USER": account(
                "ACME_WEB_USER", vendor_maintained=True, roles=frozenset({"DBA"})
            ),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG), "--force", "--output", "json")

    body = document(result)
    assert not list(validator.iter_errors(body))
    forced = next(one for one in body["results"] if one["account"] == "acme_web_user")
    assert [one["check"] for one in forced["overridden"]] == [
        "vendor_maintained",
        "privileged_role",
    ]


def test_force_records_the_waiver_on_an_account_that_needed_no_change(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The no-op path keeps the audit trail (found in review on #298).

    A forced account whose password the database already holds reports
    `changed: false` and issues nothing -- but the waiver was still granted and
    the tool still went on to touch an account §4 would have refused. That it
    turned out to need no change is a fact about the estate, not about what was
    overridden, and an audit trail recording the override only when something
    happened would be missing exactly the runs somebody skims looking for
    `--force`.
    """
    estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        },
        # `current` already holds what the database holds, and no `pending`: the
        # run reads `current`, the login passes, and nothing is issued.
        document={"DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE}},
    )
    result = run(runner, write_config(CONFIG), "--force", "--output", "json")

    forced = next(one for one in document(result)["results"] if one["account"] == "acme_web_user")
    assert forced["changed"] is False
    assert [one["check"] for one in forced["overridden"]] == ["vendor_maintained"]


def test_force_records_the_waiver_on_an_account_that_failed(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """And on the error path, for the same reason: the override happened."""

    class Refusing(FakeSession):
        def set_password(self, name: str, secret: Secret) -> ChangeResult:
            raise RuntimeError("ORA-01031: insufficient privileges")

    harness = estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        },
        session=Refusing,
    )
    result = run(runner, write_config(CONFIG), "--force", "--output", "json")

    assert changed(harness) == []
    forced = next(one for one in document(result)["results"] if one["account"] == "acme_web_user")
    assert forced["state"] == "ERROR"
    assert [one["check"] for one in forced["overridden"]] == ["vendor_maintained"]


def test_a_clean_account_carries_no_overridden_key(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The field records overrides, not intent. A document carrying an empty
    array on every forced run would make the ones that mattered harder to find."""
    estate({"ACME_WEB_USER": ordinary(), "ACME_BATCH_USER": ordinary("ACME_BATCH_USER")})
    result = run(runner, write_config(CONFIG), "--force", "--output", "json")

    assert all("overridden" not in one for one in document(result)["results"])


def test_force_never_waives_check_one(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 5 and #89: acting on an account absent from the config would
    make the tool's own audit trail meaningless, so no flag reaches check 1.

    The database answers to a name the config does not declare -- which is what
    a renamed account looks like -- and `--force` must not get past it.
    """
    harness = estate(
        {
            "ACME_WEB_USER": account("SOMEONE_ELSE", vendor_maintained=False),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    run(runner, write_config(CONFIG), "--force")

    assert "SOMEONE_ELSE" not in changed(harness)


# --------------------------------------------------------------- `rotate` ---


def test_rotate_is_guarded_too(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`rotate` sequences `apply`, so it inherits the guardrail -- asserted rather
    than assumed, because "inherits it" is a property of today's call graph."""
    harness = estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    runner.invoke(
        cli,
        ["creds", "rotate", "--config", str(write_config(CONFIG)), "--confirm"],
    )

    assert "ACME_WEB_USER" not in changed(harness)


def test_rotate_takes_force_as_well(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    runner.invoke(
        cli,
        ["creds", "rotate", "--config", str(write_config(CONFIG)), "--confirm", "--force"],
    )

    assert "ACME_WEB_USER" in changed(harness)

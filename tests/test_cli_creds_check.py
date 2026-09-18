"""``sopuli creds check`` end to end, without a database (#248).

Tier 0 in everything but posture, the same arrangement
``tests/test_cli_lock_status.py`` uses: in-process through ``CliRunner``, with
the two things that would need a network handed in. The vault is a
:class:`~sopuli.store.MemoryStore` and the driver is a fake session; the real
ones have their own suites, and this file is about *the command* -- what it
plans, what it reads, what the document says, and what it exits with.

The seams are :func:`sopuli.store.registry.connect` and
:func:`sopuli.driver.registry.resolve`, patched where ``sopuli.cli`` imported
them. Patching the definitions would leave the already-imported references in
place and quietly test nothing.
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
from sopuli.config.errors import ConfigError
from sopuli.config.model import Vault
from sopuli.driver.protocol import (
    FAIL,
    PASS,
    SKIPPED,
    VERIFY_LOGIN,
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
    secret_template: "apps/acme/{target}#password"
"""

STORED = "Correct-Horse-Battery-9"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8")))


class FakeSession:
    """One target's worth of answers, scripted per account.

    Records what it was asked, because half of UC-1 §7 is about what the tool
    must *not* do -- and "it never attempted a second login" is only testable by
    counting attempts.
    """

    def __init__(
        self,
        users: Mapping[str, UserState | None],
        answers: Mapping[str, VerifyResult],
    ) -> None:
        self.users = users
        self.answers = answers
        self.attempts: list[str] = []
        self.budgets: list[int] = []
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
        self.attempts.append(account)
        self.budgets.append(attempts)
        return self.answers[account.upper()]

    def close(self) -> None:
        self.closed = True


def user(name: str = "ACME_WEB_USER", **fields: Any) -> UserState:
    return UserState(**{"name": name, "status": "OPEN", **fields})


Harness = Callable[..., dict[str, Any]]


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Harness:
    """Patch the store and the driver, and hand back what the run will meet."""

    def install(
        *,
        stored: str | None = STORED,
        users: Mapping[str, UserState | None] | None = None,
        answers: Mapping[str, VerifyResult] | None = None,
        connect_error: Exception | None = None,
    ) -> dict[str, Any]:
        store = MemoryStore()
        if stored is not None:
            for target in ("appdb-alpha", "appdb-beta"):
                store.write(f"apps/acme/{target}", {"password": stored}, cas=0)

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
                session = FakeSession(
                    users if users is not None else {"ACME_WEB_USER": user()},
                    answers
                    if answers is not None
                    else {"ACME_WEB_USER": VerifyResult(VERIFY_LOGIN, PASS, latency_ms=11)},
                )
                sessions.append(session)
                return session

        class FakeModule:
            OracleDriver = FakeDriver

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        monkeypatch.setattr("sopuli.cli.resolve_driver", lambda target: FakeModule)
        monkeypatch.setattr("sopuli.cli.admin_resolve", lambda target, **_: _credential())
        return {"store": store, "sessions": sessions}

    return install


def _credential() -> Any:
    class Resolved:
        credential = object()

    return Resolved()


def run(runner: CliRunner, config: Path, *args: str) -> Result:
    return runner.invoke(cli, ["creds", "check", "--config", str(config), *args])


def document(result: Result) -> dict[str, Any]:
    return dict(json.loads(result.output))


def refused(result: Result) -> int:
    """The exit code a refusal *would* carry at the boundary.

    `CliRunner` drives the group rather than `sopuli.cli.main`, so an exception
    that escapes a verb arrives here as the exception itself and the runner's own
    exit code is 1. The half worth asserting is what the command decided, which
    is the code the exception carries -- the same helper
    `tests/test_cli_lock_break.py` uses, for the same reason.
    """
    assert isinstance(result.exception, ConfigError), result.exception
    return int(result.exception.exit_code)


# ---------------------------------------------------------------- in sync ---


def test_an_estate_in_sync_exits_zero(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate()
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert "all 2 in sync" in result.output


def test_an_absent_password_age_says_why(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    """#386: `password_age_days` is left out where the database would not say,
    and the result carries the reason under `SOPULI-W021` beside the hole --
    a consumer cannot see `creds status`'s dash."""
    reason = "this release has no DBA_USERS.PASSWORD_CHANGE_DATE; GRANT SELECT ON SYS.USER$"
    estate(users={"ACME_WEB_USER": user(password_changed_unknown=reason)})
    result = run(runner, write_config(CONFIG), "--output", "json")

    body = document(result)
    assert not list(validator.iter_errors(body))
    for entry in body["results"]:
        assert "password_age_days" not in entry
        assert [(one["code"], one["message"]) for one in entry["warnings"]] == [
            ("SOPULI-W021", reason)
        ]
    assert result.exit_code == ExitCode.SUCCESS, "informational: nothing gates on it"


def test_a_login_that_raises_keeps_what_was_already_read(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    """Copilot on #421: the account's state is read before the login, so an
    `ERROR` from the login must not discard it. W021 explains a missing
    `password_age_days`, and it has to survive on the path where the row is an
    error too -- as does an age that *was* read."""
    reason = "this release has no DBA_USERS.PASSWORD_CHANGE_DATE; GRANT SELECT ON SYS.USER$"
    # No scripted answer, so `verify_password` raises -- after `describe_user`.
    estate(users={"ACME_WEB_USER": user(password_changed_unknown=reason)}, answers={})
    result = run(runner, write_config(CONFIG), "--output", "json")

    body = document(result)
    assert not list(validator.iter_errors(body))
    for entry in body["results"]:
        assert entry["state"] == check.ERROR
        assert [one["code"] for one in entry["warnings"]] == ["SOPULI-W021"]


def test_the_plan_is_printed_before_anything_is_checked(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §2: selection is resolved and printed before anything is touched."""
    estate()
    result = run(runner, write_config(CONFIG))

    plan_line = result.output.splitlines()[0]
    assert plan_line.startswith("Plan: 1 account x 2 targets = 2 checks")
    assert result.output.index("Plan:") < result.output.index("ACCOUNT")


def test_the_document_validates_and_carries_both_sections(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    """`plan` and `results` at the same grain and in the same order, which is
    what makes a diff between them mechanical."""
    estate()
    result = run(runner, write_config(CONFIG), "--output", "json")

    body = document(result)
    assert not list(validator.iter_errors(body))
    assert [unit["account"] for unit in body["plan"]["units"]] == [
        entry["account"] for entry in body["results"]
    ]
    assert body["summary"]["by_state"] == {check.IN_SYNC: 2}


def test_the_result_records_the_version_the_store_served(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate()
    body = document(run(runner, write_config(CONFIG), "--output", "json"))

    assert body["results"][0]["secret"]["version"] == 1
    assert body["results"][0]["secret"]["stage"] == "current"


# ------------------------------------------------------------------ drift ---


def test_a_rejected_password_is_drift_and_exits_three(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Exit 3 is what makes this schedulable, distinct from the tool failing."""
    estate(
        answers={"ACME_WEB_USER": VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017")},
    )
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.DRIFT
    assert "DRIFT" in result.output
    assert "2 drift" in result.output


def test_one_attempt_per_account_and_never_a_retry(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Mitigation 1, and the whole reason `check` is safe to schedule against a
    production account: a wrong password must cost exactly one failed login."""
    harness = estate(
        answers={"ACME_WEB_USER": VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017")},
    )
    run(runner, write_config(CONFIG))

    assert [session.attempts for session in harness["sessions"]] == [
        ["ACME_WEB_USER"],
        ["ACME_WEB_USER"],
    ]


# --------------------------------------------------- the states that are not drift ---


def test_a_locked_account_is_reported_as_locked_and_exits_zero(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Mitigation 6, and the exit code follows: nothing here established that a
    credential is wrong, so paging the drift watcher would be a false alarm."""
    harness = estate(users={"ACME_WEB_USER": user(status="LOCKED", locked=True)})
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert "LOCKED" in result.output
    assert "2 unverifiable" in result.output
    # And it never tried the password, which is the point of reading status first.
    assert [session.attempts for session in harness["sessions"]] == [[], []]


def test_an_account_the_database_lacks_is_reported_not_created(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate(users={})
    result = run(runner, write_config(CONFIG))

    assert "ACCOUNT_MISSING" in result.output
    assert result.exit_code == ExitCode.SUCCESS


def test_a_declined_login_keeps_the_drivers_reason(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate(
        answers={
            "ACME_WEB_USER": VerifyResult(
                VERIFY_LOGIN,
                SKIPPED,
                lockout_margin_hit=True,
                detail="lcount 8 of 10, within lockout margin",
            )
        },
    )
    result = run(runner, write_config(CONFIG))

    assert "UNVERIFIABLE" in result.output
    assert "lcount 8 of 10" in result.output


def test_a_vault_with_no_password_at_the_ref_is_unverifiable(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A credential that has never been written is a real state of a new
    application, and not the same thing as a database rejecting one."""
    estate(stored=None)
    result = run(runner, write_config(CONFIG))

    assert "UNVERIFIABLE" in result.output
    assert result.exit_code == ExitCode.SUCCESS


# ------------------------------------------------------------ unreachable ---


def test_an_unreachable_target_is_a_finding_and_exits_one(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Exit 1 and never exit 3: a broken check must not page whoever watches for
    drift."""
    estate(connect_error=RuntimeError("ORA-12541: no listener"))
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.FAILURE
    assert "ERROR" in result.output
    assert "ORA-12541" in result.output


def test_an_unreachable_target_does_not_stop_the_rest(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The point of a survey. Both targets appear in `results` even though the
    first one failed."""
    estate(connect_error=RuntimeError("ORA-12541: no listener"))
    body = document(run(runner, write_config(CONFIG), "--output", "json"))

    assert [entry["target"] for entry in body["results"]] == ["appdb-alpha", "appdb-beta"]


# ------------------------------------------------------------- selection ---


def test_a_selector_narrows_the_plan_and_the_results(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate()
    body = document(
        run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")
    )

    assert [entry["target"] for entry in body["results"]] == ["appdb-alpha"]
    assert body["plan"]["blast_radius"]["targets"] == 1


def test_max_targets_refuses_before_anything_connects(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The ceiling is read from the plan, so it fires before the first login."""
    harness = estate()
    config = CONFIG.replace(
        "version: 1\n", "version: 1\ndefaults:\n  safety:\n    max_targets: 1\n"
    )
    result = run(runner, write_config(config))

    assert refused(result) == ExitCode.ABORTED
    assert harness["sessions"] == []


# ------------------------------------------------------------ never mutating ---


def test_the_run_takes_no_lock_and_reports_no_change(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """P5 exempts `check` from locking so an hourly one never blocks a rotation,
    and invariant 9 makes `changed` structurally false for a read-only verb."""
    estate()
    body = document(run(runner, write_config(CONFIG), "--output", "json"))

    assert "lock" not in body
    assert all(entry["changed"] is False for entry in body["results"])
    assert body["summary"]["changed"] == 0


def test_the_session_is_closed_even_when_a_check_fails(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate(
        answers={"ACME_WEB_USER": VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017")},
    )
    run(runner, write_config(CONFIG))

    assert all(session.closed for session in harness["sessions"])


# ------------------------------------------------------- --include-previous ---


def test_the_previous_password_is_asked_about_only_when_requested(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Off by default, because it doubles what the run spends on the failed-login
    counter the lockout guard exists to protect."""
    estate()
    body = document(run(runner, write_config(CONFIG), "--output", "json"))

    assert body["results"][0]["verification"]["previous_password_accepted"] is None


def test_a_live_previous_password_is_reported_without_becoming_drift(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """During a rollover window a yes is expected and confirms the window is
    real; outside one it means an old credential is still live. Neither is a
    disagreement between the vault and the database, so neither is `DRIFT`."""
    harness = estate()
    for target in ("appdb-alpha", "appdb-beta"):
        harness["store"].write(
            f"apps/acme/{target}",
            {"password": STORED, "previous": "Old-Horse-Battery-8"},
            cas=1,
        )
    body = document(run(runner, write_config(CONFIG), "--include-previous", "--output", "json"))

    assert body["results"][0]["verification"]["previous_password_accepted"] is True
    assert body["results"][0]["state"] == check.IN_SYNC
    assert body["exit_code"] == ExitCode.SUCCESS


def test_the_whole_budget_is_declared_before_the_first_attempt(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Mitigation 1 is one attempt per account per *run*, so both attempts are
    reserved against the guard before the first is spent. Asking per value
    checked would quietly double the spend on the counter it protects."""
    harness = estate()
    for target in ("appdb-alpha", "appdb-beta"):
        harness["store"].write(
            f"apps/acme/{target}",
            {"password": STORED, "previous": "Old-Horse-Battery-8"},
            cas=1,
        )
    run(runner, write_config(CONFIG), "--include-previous")

    assert all(session.budgets == [2, 2] for session in harness["sessions"])


def test_no_previous_password_reports_null_rather_than_false(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The ordinary state of a credential that has never been rotated. "We asked
    and it was refused" and "there was nothing to ask about" are different."""
    estate()
    body = document(run(runner, write_config(CONFIG), "--include-previous", "--output", "json"))

    assert body["results"][0]["verification"]["previous_password_accepted"] is None


def test_a_binding_with_no_ref_says_so_rather_than_blaming_a_ref(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Three situations reach one empty read, and they send an operator to three
    different places. Caught by Copilot on #253: the message named a ref that,
    for an application declaring none, does not exist."""
    estate()
    config = CONFIG.replace('    secret_template: "apps/acme/{target}#password"\n', "")
    result = run(runner, write_config(config))

    assert "no secret ref" in result.output
    assert "the vault holds no password at" not in result.output


def test_an_unreachable_target_is_counted_as_failed(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The summary and the exit code have to agree about one run."""
    estate(connect_error=RuntimeError("ORA-12541: no listener"))
    body = document(run(runner, write_config(CONFIG), "--output", "json"))

    assert body["summary"]["failed"] == 2
    assert body["summary"]["unverifiable"] == 0
    assert body["exit_code"] == ExitCode.FAILURE

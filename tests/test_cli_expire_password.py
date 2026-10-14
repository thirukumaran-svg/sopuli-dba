"""`sopuli account expire-password` from the command line.

Tier 0 against a fake session, for the command's own orchestration: that a
preview reads and issues nothing (invariant 8), that a refusal never reaches
the driver, and that a failure after the window closed is reported as the
partial change it is rather than as an untouched account. The driver's
behaviour against Oracle is `tests/driver/test_oracle_expire.py`; the decision
and the view are `tests/test_expire.py`.

Tier 1 once, end to end, because the one thing a fake cannot show is that the
document a real run produces is the one the schema describes.
"""

from __future__ import annotations

import contextlib
import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

from conftest import WriteConfig
from oracle_harness import Environment
from sopuli.cli import cli
from sopuli.config.targets import ADMIN_PASSWORD_ENV
from sopuli.driver.protocol import (
    ACCOUNT_LOCK,
    PASSWORD_EXPIRE,
    ROLLOVER_FINISH,
    AccountChange,
    DriverError,
    PartialAccountChangeError,
    UserState,
)
from sopuli.exit_codes import ExitCode
from sopuli.output.document import SCHEMA_VERSION

ACCOUNT = "acme_dev_alice"

CONFIG = """version: 1

targets:
  - name: tier1-oracle
    type: oracle
    environment: dev
    dsn: "{dsn}"
    admin: {{ username: {user}, auth: {{ method: env }} }}

personal_accounts:
  - accounts: [{account}]
"""

OFFLINE = CONFIG.format(dsn="192.0.2.10:1521/ALPHA", user="SOPULI_SVC", account=ACCOUNT)

RUN_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)


class FakeSession:
    """Just enough of a session for the command: a state, and a record of calls."""

    def __init__(self, status: str = "OPEN", *, fail: Exception | None = None) -> None:
        self.status = status
        self.fail = fail
        self.expired: list[str] = []

    def describe_user(self, account: str) -> UserState | None:
        return UserState(name=account.upper(), status=self.status)

    def byte_limit(self) -> None:
        """A `reset-password` preview asks it. `None` is a target with no limit."""

    def expire_password(self, account: str) -> tuple[AccountChange, ...]:
        self.expired.append(account)
        if self.fail is not None:
            raise self.fail
        return (
            AccountChange(ROLLOVER_FINISH, changed=False, status=self.status, detail="no window"),
            AccountChange(PASSWORD_EXPIRE, changed=True, status=self.status, detail="expired"),
        )

    def close(self) -> None:
        return None


def run(runner: CliRunner, config: Path, *args: str) -> Any:
    return runner.invoke(cli, ["--config", str(config), "account", "expire-password", *args])


def document(result: Any) -> dict[str, Any]:
    found: dict[str, Any] = json.loads(result.output)
    return found


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> list[FakeSession]:
    """Every session the command opens is this one, and the list shows how many."""
    opened: list[FakeSession] = []
    session = FakeSession()

    def open_session(target: Any, run: Any, config: Any) -> FakeSession:
        opened.append(session)
        return session

    monkeypatch.setattr("sopuli.cli._open_session", open_session)
    return opened


# ------------------------------------------------------------------ tier 0 ---


def test_the_account_is_required(runner: CliRunner, write_config: WriteConfig) -> None:
    result = run(runner, write_config(OFFLINE))

    assert result.exit_code == ExitCode.USAGE
    assert "--account" in result.output


def test_a_preview_reads_and_issues_nothing(
    runner: CliRunner, write_config: WriteConfig, fake: list[FakeSession]
) -> None:
    """Invariant 8: a preview must not reach the DDL. The read happens, because
    it is what a preview is for."""
    result = run(
        runner, write_config(OFFLINE), "--account", ACCOUNT, "--dry-run", "--output", "json"
    )

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert len(fake) == 1, "a preview still connects and reads"
    assert fake[0].expired == [], "and issues nothing"
    row = document(result)["results"][0]
    assert row["changed"] is False
    assert row["actions"] == [
        {"kind": PASSWORD_EXPIRE, "applied": False, "detail": row["actions"][0]["detail"]}
    ]
    assert "would be expired" in row["actions"][0]["detail"]


#: What `reset-password` needs as well: a policy, and an unseen delivery so that
#: it previews under `--output json`. A preview opens no delivery store.
RESETTABLE = """
vaults:
  vault-dev:
    type: hashicorp
    addr: https://vault-dev.example.com:8200

policies:
  standard:
    password: { length: 24, charset: alnum, first_char: alpha }

delivery:
  method: vault_wrapped
  vault_wrapped: { vault: vault-dev, ttl: 15m }
"""


@pytest.mark.parametrize("verb", ["expire-password", "suspend", "reset-password"])
@pytest.mark.parametrize(("listed", "expected"), [("dev", True), ("prod", False)])
def test_the_plan_says_whether_the_environment_needs_a_yes(
    runner: CliRunner,
    write_config: WriteConfig,
    fake: list[FakeSession],
    verb: str,
    listed: str,
    expected: bool,
) -> None:
    """The `account` verbs ask `safety.confirm_environments`, and a preview
    reports what the real run would ask (#663)."""
    guarded = (
        OFFLINE.replace(
            "version: 1\n",
            "version: 1\ndefaults:\n  policy: standard\n"
            f"  safety:\n    confirm_environments: [{listed}]\n",
        )
        + RESETTABLE
    )
    result = runner.invoke(
        cli,
        ["--config", str(write_config(guarded)), "account", verb, "--account", ACCOUNT]
        + ["--dry-run", "--output", "json"],
    )

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert document(result)["plan"]["confirmation_required"] is expected


def test_an_undeclared_account_never_reaches_the_driver(
    runner: CliRunner, write_config: WriteConfig, fake: list[FakeSession]
) -> None:
    """Invariant 5, and `--force` does not change it. Exit 0: a refusal is the
    guardrails working, not a failure."""
    result = run(
        runner, write_config(OFFLINE), "--account", "acme_dev_bob", "--force", "--output", "json"
    )

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert fake[0].expired == []
    assert document(result)["results"][0]["state"] == "SKIPPED"


@pytest.mark.parametrize("verb", ["expire-password", "suspend", "reset-password"])
def test_debug_says_why_an_undeclared_account_was_left_alone(
    runner: CliRunner, write_config: WriteConfig, fake: list[FakeSession], verb: str
) -> None:
    """#788: the guardrails' answer, with the account and the target."""
    result = runner.invoke(
        cli,
        ["--config", str(write_config(OFFLINE + RESETTABLE)), "account", verb]
        + ["--account", "acme_dev_bob", "--dry-run", "--debug"],
    )

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "plan: acme_dev_bob on tier1-oracle left alone: SKIPPED, " in result.stderr


class SettledSession(FakeSession):
    """A database where the statement would change nothing: the password is
    already expired, and the account already locked."""

    def expire_password(self, account: str) -> tuple[AccountChange, ...]:
        self.expired.append(account)
        return (
            AccountChange(ROLLOVER_FINISH, changed=False, status=self.status, detail="no window"),
            AccountChange(
                PASSWORD_EXPIRE, changed=False, status=self.status, detail="already expired"
            ),
        )

    def suspend_account(self, account: str) -> AccountChange:
        return AccountChange(
            ACCOUNT_LOCK, changed=False, status=self.status, detail="already locked"
        )


@pytest.mark.parametrize(
    ("verb", "said"), [("expire-password", "already expired"), ("suspend", "already locked")]
)
def test_debug_says_why_the_driver_left_an_account_alone(
    runner: CliRunner,
    write_config: WriteConfig,
    monkeypatch: pytest.MonkeyPatch,
    verb: str,
    said: str,
) -> None:
    """#788: the driver, not the guardrails, found nothing to change."""
    session = SettledSession("EXPIRED & LOCKED")
    monkeypatch.setattr("sopuli.cli._open_session", lambda target, run, config: session)

    result = runner.invoke(
        cli,
        ["--config", str(write_config(OFFLINE)), "account", verb]
        + ["--account", ACCOUNT, "--confirm", "--debug"],
    )

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert f"plan: {ACCOUNT} on tier1-oracle left alone: " in result.stderr
    assert said in result.stderr


def test_a_run_reports_both_statements(
    runner: CliRunner, write_config: WriteConfig, fake: list[FakeSession]
) -> None:
    result = run(runner, write_config(OFFLINE), "--account", ACCOUNT, "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    found = document(result)
    row = found["results"][0]
    assert fake[0].expired == [ACCOUNT]
    assert [action["kind"] for action in row["actions"]] == [ROLLOVER_FINISH, PASSWORD_EXPIRE]
    assert row["changed"] is True
    assert found["summary"]["changed"] == 1
    assert found["command"] == "account.expire-password"


def test_a_failure_after_the_window_closed_is_reported_as_a_change(
    runner: CliRunner,
    write_config: WriteConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The close commits before the expiry fails, so the old password is already
    dead; a row saying `changed: false` with no applied action would claim the
    account was untouched."""
    closed = AccountChange(
        ROLLOVER_FINISH,
        changed=True,
        status="OPEN & IN ROLLOVER",
        detail="rollover window closed; the old password no longer works",
    )
    cause = DriverError("ORA-01031: insufficient privileges", code="ORA-01031")
    session = FakeSession(
        "OPEN & IN ROLLOVER", fail=PartialAccountChangeError(cause, completed=(closed,))
    )
    monkeypatch.setattr("sopuli.cli._open_session", lambda target, run, config: session)

    result = run(runner, write_config(OFFLINE), "--account", ACCOUNT, "--output", "json")

    assert result.exit_code == ExitCode.PARTIAL, result.output
    found = document(result)
    row = found["results"][0]
    assert row["state"] == "ERROR"
    assert row["changed"] is True
    assert [(action["kind"], action["applied"]) for action in row["actions"]] == [
        (ROLLOVER_FINISH, True),
        (PASSWORD_EXPIRE, False),
    ]
    assert row["error"]["code"] == "ORA-01031", "the server's own code survives the wrapping"
    assert found["summary"]["changed"] == 1
    assert found["summary"]["failed"] == 1


def test_the_closing_line_does_not_claim_a_failed_expiry(
    runner: CliRunner,
    write_config: WriteConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The row is a change -- its window closed -- and the summary counts
    it, but no password was expired, so the text line must not say one was."""
    closed = AccountChange(
        ROLLOVER_FINISH,
        changed=True,
        status="OPEN & IN ROLLOVER",
        detail="rollover window closed; the old password no longer works",
    )
    cause = DriverError("ORA-01031: insufficient privileges", code="ORA-01031")
    session = FakeSession(
        "OPEN & IN ROLLOVER", fail=PartialAccountChangeError(cause, completed=(closed,))
    )
    monkeypatch.setattr("sopuli.cli._open_session", lambda target, run, config: session)

    result = run(runner, write_config(OFFLINE), "--account", ACCOUNT)

    assert result.exit_code == ExitCode.PARTIAL, result.output
    last = result.output.rstrip().splitlines()[-1]
    assert last == f"{ACCOUNT}'s password was not expired on any of 1; 1 failed"


def test_closing_only_the_window_of_an_expired_account_still_reads_as_expired(
    runner: CliRunner,
    write_config: WriteConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other side of `test_the_closing_line_does_not_claim_a_failed_expiry`.
    At `EXPIRED & IN ROLLOVER` no expiry is
    issued, only the close, and the run is still what left the account expired
    and nothing else -- so the line keys on the state, not on the action."""

    class WindowOnly(FakeSession):
        def expire_password(self, account: str) -> tuple[AccountChange, ...]:
            return (
                AccountChange(ROLLOVER_FINISH, changed=True, status=self.status, detail="closed"),
                AccountChange(PASSWORD_EXPIRE, changed=False, status=self.status, detail="already"),
            )

    session = WindowOnly("EXPIRED & IN ROLLOVER")
    monkeypatch.setattr("sopuli.cli._open_session", lambda target, run, config: session)

    result = run(runner, write_config(OFFLINE), "--account", ACCOUNT)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    last = result.output.rstrip().splitlines()[-1]
    assert last == f"expired {ACCOUNT}'s password on 1 of 1 targets"


def test_a_failure_before_anything_changed_is_not(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = FakeSession(fail=DriverError("ORA-01031: insufficient privileges"))
    monkeypatch.setattr("sopuli.cli._open_session", lambda target, run, config: session)

    result = run(runner, write_config(OFFLINE), "--account", ACCOUNT, "--output", "json")

    assert result.exit_code == ExitCode.PARTIAL
    row = document(result)["results"][0]
    assert row["changed"] is False
    assert row["actions"][0]["applied"] is False


# ------------------------------------------------------------------ tier 1 ---


LIVE_ACCOUNT = "acme_expire_cli"
LIVE_PASSWORD = "Aa1-cli-pw-000001"


@pytest.fixture
def live_account(live_oracle: Environment, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    oracledb = pytest.importorskip("oracledb")
    user = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
    password = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")
    monkeypatch.setenv(ADMIN_PASSWORD_ENV, password)
    connection = oracledb.connect(user=user, password=password, dsn=live_oracle.dsn)

    def drop() -> None:
        with contextlib.suppress(Exception), connection.cursor() as cursor:
            cursor.execute(f"drop user {LIVE_ACCOUNT} cascade")

    drop()
    with connection.cursor() as cursor:
        cursor.execute(f'create user {LIVE_ACCOUNT} identified by "{LIVE_PASSWORD}"')
        cursor.execute(f"grant create session to {LIVE_ACCOUNT}")
    try:
        yield CONFIG.format(dsn=live_oracle.dsn, user=user, account=LIVE_ACCOUNT)
    finally:
        drop()
        connection.close()


def test_a_real_run_and_its_rerun_validate_against_the_schema(
    runner: CliRunner, write_config: WriteConfig, live_account: str
) -> None:
    config = write_config(live_account)
    validator = Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8")))

    first = run(runner, config, "--account", LIVE_ACCOUNT, "--output", "json")
    second = run(runner, config, "--account", LIVE_ACCOUNT, "--output", "json")

    assert first.exit_code == ExitCode.SUCCESS, first.output
    assert second.exit_code == ExitCode.SUCCESS, second.output
    validator.validate(document(first))
    validator.validate(document(second))
    assert document(first)["results"][0]["changed"] is True
    rerun = document(second)["results"][0]
    assert rerun["changed"] is False, "invariant 9"
    assert rerun["account_status"] == "EXPIRED"

"""`account reset-password` when a statement fails after another committed (#528).

Tier 0, with a fake session. DDL commits as it goes, so a reset that fails half
way has already done the first half, and the row has to say so. Two failure
points, and they are handled differently on purpose:

* **the unlock commits, then the set fails.** The password is what it was, so
  nothing is handed over -- on the unseen path the token already made retrieves a
  value that authenticates nothing, which is UC-2 6.4's recoverable failure;
* **the set commits, then the window close fails.** The password is live, so it
  *is* handed over, and the record and the notification follow (decided in #528):
  withholding it would leave a password nobody holds.

Both are `ERROR` at exit 4 with ``changed: true``, `_expire_one`'s shape for the
same error (#527).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

from conftest import WriteConfig
from sopuli.cli import cli
from sopuli.clock import utc_now
from sopuli.delivery import Receipt
from sopuli.driver.protocol import (
    ACCOUNT_UNLOCK,
    PASSWORD_SET,
    ROLLOVER_FINISH,
    AccountChange,
    DriverError,
    PartialAccountChangeError,
    UserState,
)
from sopuli.exit_codes import ExitCode
from sopuli.lock import Holder, LockDeniedError, LockKey, LockRecord, lock_path
from sopuli.output.document import SCHEMA_VERSION
from sopuli.output.emit import EVENT_SCHEMA_VERSION
from sopuli.secrets import Secret
from sopuli.store import MemoryStore

ACCOUNT = "acme_dev_alice"
TARGET = "tier1-oracle"
TOKEN = "hvs.CAESIFAKEWRAPPINGTOKEN0000"

MANUAL = f"""version: 1

defaults:
  policy: personal-standard
  vault: vault-dev

targets:
  - name: {TARGET}
    type: oracle
    environment: dev
    dsn: "192.0.2.10:1521/ALPHA"
    admin: {{ username: SOPULI_SVC, auth: {{ method: env }} }}

vaults:
  vault-dev:
    type: hashicorp
    addr: https://vault.example.com:8200
    mount: secret
    kv_version: 2
    auth:
      method: token

policies:
  personal-standard:
    password:
      length: 20
      charset: alnum_safe
      first_char: alpha
      require: {{ upper: 1, lower: 1, digit: 1, special: 1 }}

personal_accounts:
  - accounts: [{ACCOUNT}]
    policy: personal-standard

delivery:
  method: manual
  manual:
    force_expire: true
"""

WRAPPED = MANUAL.replace(
    "  method: manual\n  manual:\n    force_expire: true\n",
    "  method: vault_wrapped\n  vault_wrapped:\n    ttl: 15m\n",
)

RUN_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

DENIED = DriverError("ORA-01031: insufficient privileges", code="ORA-01031")

UNLOCKED = AccountChange(
    ACCOUNT_UNLOCK,
    changed=True,
    status="LOCKED(TIMED)",
    detail="account was locked(timed); unlocked",
)
SET = AccountChange(PASSWORD_SET, changed=True, status="OPEN", detail="password set")


class FakeSession:
    """A session whose reset raises what it is told to, and nothing else."""

    def __init__(self, status: str, fail: Exception) -> None:
        self.status = status
        self.fail = fail
        self.reset: list[str] = []

    def describe_user(self, account: str) -> UserState | None:
        return UserState(name=account.upper(), status=self.status)

    def require_no_rollover_window(self, account: str) -> None:
        return None

    def byte_limit(self) -> None:
        return None

    def reset_password(self, account: str, secret: Secret, **_: Any) -> tuple[AccountChange, ...]:
        self.reset.append(account)
        raise self.fail

    def close(self) -> None:
        return None


class FakeBackend:
    """An unseen delivery that always succeeds, before the DDL (6.4)."""

    def deliver(self, secret: Secret, *, account: str, target: str) -> Receipt:
        return Receipt(
            method="vault_wrapped",
            token=Secret(TOKEN),
            accessor="accessor-0001",
            expires_at=datetime(2026, 9, 26, 12, 15, tzinfo=UTC),
        )


class Sent:
    """What reached the record and the notify channel."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self.notified: list[str] = []


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> Sent:
    """A record path, and a writer and a notifier that remember being called.

    The paths are patched in because the config declares no `reset_records:` --
    which would otherwise also bring a lock store this test has no use for.
    """
    seen = Sent()

    def write(run: Any, config: Any, **kwargs: Any) -> None:
        seen.records.append(kwargs)

    def notify(channel: Any, *, account: str, target: Any, receipt: Any) -> None:
        seen.notified.append(account)

    monkeypatch.setattr(
        "sopuli.cli._record_paths",
        lambda config, account, reached: {TARGET: f"personal-resets/{TARGET}/{account}"},
    )
    monkeypatch.setattr("sopuli.cli._write_reset_record", write)
    monkeypatch.setattr("sopuli.cli._notify", notify)
    return seen


def _open(monkeypatch: pytest.MonkeyPatch, session: FakeSession, *, unseen: bool) -> None:
    monkeypatch.setattr("sopuli.cli._open_session", lambda target, run, config: session)
    if unseen:
        monkeypatch.setattr(
            "sopuli.cli._delivery_backends",
            lambda run, config, delivery, reached: {TARGET: FakeBackend()},
        )
    else:
        monkeypatch.setattr("sopuli.cli.is_a_terminal", lambda stream: True)


def _run(runner: CliRunner, config: Path, *args: str, input: str | None = None) -> Any:  # noqa: A002
    return runner.invoke(
        cli,
        ["--config", str(config), "account", "reset-password", "--account", ACCOUNT, *args],
        input=input,
    )


def _row(result: Any) -> dict[str, Any]:
    document = json.loads(result.stdout)
    validator = Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8")))
    assert not list(validator.iter_errors(document)), "the document left its schema"
    row: dict[str, Any] = document["results"][0]
    return row


# ------------------------------------------- the unlock committed, the set not ---


def test_an_unlock_then_a_failed_set_reports_the_unlock_and_hands_nothing_over(
    runner: CliRunner,
    write_config: WriteConfig,
    monkeypatch: pytest.MonkeyPatch,
    sent: Sent,
) -> None:
    """The timed lock is gone and the password is not changed, so the row says the
    first and the operator is handed nothing: the token would retrieve a password
    the account does not have."""
    failure = PartialAccountChangeError(DENIED, completed=(UNLOCKED,))
    _open(monkeypatch, FakeSession("LOCKED(TIMED)", failure), unseen=True)

    result = _run(runner, write_config(WRAPPED), "--output", "json")

    assert result.exit_code == ExitCode.PARTIAL, result.output
    row = _row(result)
    assert row["state"] == "ERROR"
    assert row["changed"] is True
    assert [(one["kind"], one["applied"]) for one in row["actions"]] == [
        (ACCOUNT_UNLOCK, True),
        (PASSWORD_SET, False),
    ]
    assert row["error"]["code"] == "ORA-01031", "the server's own code survives the wrapping"
    assert "handover" not in row
    assert TOKEN not in result.output, "a token for a password the account does not have"
    assert sent.records == [], "a reset that did not happen was journalled"
    assert sent.notified == [], "somebody was told a password is waiting"


def test_an_unlock_then_a_failed_set_prints_no_password_on_the_seen_path(
    runner: CliRunner,
    write_config: WriteConfig,
    monkeypatch: pytest.MonkeyPatch,
    sent: Sent,
) -> None:
    failure = PartialAccountChangeError(DENIED, completed=(UNLOCKED,))
    _open(monkeypatch, FakeSession("LOCKED(TIMED)", failure), unseen=False)

    result = _run(runner, write_config(MANUAL), input="y\n")

    assert result.exit_code == ExitCode.PARTIAL, result.output
    assert "ERROR" in result.output
    assert "unlocked; then: ORA-01031" in result.output
    assert "shown once" not in result.output
    assert sent.records == []


def test_a_failure_before_anything_committed_is_an_ordinary_failure(
    runner: CliRunner,
    write_config: WriteConfig,
    monkeypatch: pytest.MonkeyPatch,
    sent: Sent,
) -> None:
    """The driver raises a plain `DriverError` where nothing changed, and the row
    stays what it always was."""
    _open(monkeypatch, FakeSession("OPEN", DENIED), unseen=True)

    result = _run(runner, write_config(WRAPPED), "--output", "json")

    assert result.exit_code == ExitCode.PARTIAL, result.output
    row = _row(result)
    assert row["changed"] is False
    assert "handover" not in row
    assert TOKEN not in result.output


# ------------------------------------------- the set committed, the close not ---


def test_a_set_then_a_failed_close_still_hands_the_token_over(
    runner: CliRunner,
    write_config: WriteConfig,
    monkeypatch: pytest.MonkeyPatch,
    sent: Sent,
) -> None:
    """#528's decision: the password is live, so it goes to the person.

    Still exit 4 and still `ERROR`, because the old password may work until the
    window ends and that is not what a reset promised. The token goes to stderr
    and never into the document, exactly as on a clean run.
    """
    failure = PartialAccountChangeError(DENIED, completed=(UNLOCKED, SET))
    _open(monkeypatch, FakeSession("LOCKED(TIMED)", failure), unseen=True)

    result = _run(runner, write_config(WRAPPED), "--output", "json")

    assert result.exit_code == ExitCode.PARTIAL, result.output
    row = _row(result)
    assert row["state"] == "ERROR"
    assert row["changed"] is True
    assert [(one["kind"], one["applied"]) for one in row["actions"]] == [
        (ACCOUNT_UNLOCK, True),
        (PASSWORD_SET, True),
        (ROLLOVER_FINISH, False),
    ]
    assert row["error"]["code"] == "ORA-01031"
    assert row["handover"]["accessor"] == "accessor-0001"
    assert TOKEN not in result.stdout, "the token reached the document"
    assert TOKEN in result.stderr, "the password is set and nobody was given it"
    assert len(sent.records) == 1, "a reset that happened was not journalled"
    assert sent.records[0]["expired"] is False
    assert sent.notified == [ACCOUNT]


def test_a_set_then_a_failed_close_still_shows_the_password_on_the_seen_path(
    runner: CliRunner,
    write_config: WriteConfig,
    monkeypatch: pytest.MonkeyPatch,
    sent: Sent,
) -> None:
    """The seen path's form of the same decision. The account now holds an
    expired password; withholding it would leave nobody able to log in."""
    failure = PartialAccountChangeError(DENIED, completed=(SET,))
    _open(monkeypatch, FakeSession("OPEN", failure), unseen=False)

    result = _run(runner, write_config(MANUAL), input="y\n")

    assert result.exit_code == ExitCode.PARTIAL, result.output
    assert "ERROR" in result.output
    assert "the old password may work until it ends" in result.output
    assert "shown once" in result.output
    assert len(sent.records) == 1
    assert sent.records[0]["expired"] is True


def test_the_failed_statement_is_named_from_the_last_that_committed() -> None:
    """Not from how many rows there are (Copilot's review of #536).

    The Oracle driver reports the unlock row even where it issued nothing, so a
    count happens to work against it. The error promises no such prefix, and a
    `completed` of the set alone must still name the close as what failed.
    """
    from sopuli.cli import _reset_actions
    from sopuli.output.document import Error

    failed = Error(category="policy", message="ORA-01031: insufficient privileges")

    assert [(kind, applied) for kind, applied, _ in _reset_actions((SET,), failed)] == [
        (PASSWORD_SET, True),
        (ROLLOVER_FINISH, False),
    ]
    assert [(kind, applied) for kind, applied, _ in _reset_actions((UNLOCKED,), failed)] == [
        (ACCOUNT_UNLOCK, True),
        (PASSWORD_SET, False),
    ]


# ------------------------------------------------------------------ jsonl ---
#
# `account reset-password` streams (#535), unseen paths only: the seen path is
# refused under every machine format, so `password.displayed` has no emitter by
# construction. Per target, as `creds check` streams, because a reset row is
# final when its target is.

EVENT_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-event-{EVENT_SCHEMA_VERSION}.schema.json"
)


class Succeeding(FakeSession):
    """A session whose reset commits."""

    def reset_password(self, account: str, secret: Secret, **_: Any) -> tuple[AccountChange, ...]:
        self.reset.append(account)
        return (SET,)


def _stream(result: Any) -> list[dict[str, Any]]:
    events = Draft202012Validator(json.loads(EVENT_SCHEMA.read_text(encoding="utf-8")))
    lines = [json.loads(line) for line in result.stdout.splitlines()]
    for line in lines:
        assert [error.message for error in events.iter_errors(line)] == [], line
    return lines


def _names(lines: list[dict[str, Any]]) -> list[str]:
    return [line["event"] for line in lines if line["event"] != "diagnostic"]


def test_an_unseen_reset_streams_the_set_and_the_handover_and_never_the_token(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, sent: Sent
) -> None:
    _open(monkeypatch, Succeeding("OPEN", DENIED), unseen=True)

    result = _run(runner, write_config(WRAPPED), "--output", "jsonl")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    lines = _stream(result)
    assert _names(lines) == [
        "run.started",
        "plan.resolved",
        "target.started",
        "password.applied",
        "password.delivered",
        "target.finished",
        "run.finished",
    ]
    delivered = next(line for line in lines if line["event"] == "password.delivered")
    assert (delivered["account"], delivered["target"]) == (ACCOUNT, TARGET)
    assert delivered["data"] == {
        "method": "vault_wrapped",
        "handover": {"accessor": "accessor-0001", "expires_at": "2026-09-26T12:15:00Z"},
    }
    applied = next(line for line in lines if line["event"] == "password.applied")
    assert applied["data"] == {"version": None, "outcome": "RESET"}
    assert TOKEN not in result.stdout, "the wrapping token reached the stream"
    assert TOKEN in result.stderr, "the password is set and nobody was given it"


def test_jsonl_and_json_describe_the_same_reset(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, sent: Sent
) -> None:
    config = write_config(WRAPPED)
    _open(monkeypatch, Succeeding("OPEN", DENIED), unseen=True)
    lines = _stream(_run(runner, config, "--output", "jsonl"))
    body = json.loads(_run(runner, config, "--output", "json").stdout)

    def comparable(entry: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value for key, value in entry.items() if key not in ("duration_ms", "reset_at")
        }

    assert lines[-1]["data"] == {"summary": body["summary"], "exit_code": body["exit_code"]}
    streamed = [line["data"] for line in lines if line["event"] == "target.finished"]
    assert [comparable(one) for one in streamed] == [comparable(one) for one in body["results"]]
    defs = json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))["$defs"]
    shape = Draft202012Validator({"$defs": defs, "$ref": "#/$defs/result"})
    assert [error.message for error in shape.iter_errors(streamed[0])] == []


def test_a_partly_applied_reset_streams_the_set_it_made(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, sent: Sent
) -> None:
    """#528's case on the stream: the password is live and was handed over, so
    both events are there, the row is `ERROR`, and the run is exit 4."""
    failure = PartialAccountChangeError(DENIED, completed=(UNLOCKED, SET))
    _open(monkeypatch, FakeSession("LOCKED(TIMED)", failure), unseen=True)

    lines = _stream(_run(runner, write_config(WRAPPED), "--output", "jsonl"))

    assert {"password.applied", "password.delivered"} <= set(_names(lines))
    finished = next(line for line in lines if line["event"] == "target.finished")
    assert finished["data"]["state"] == "ERROR"
    assert lines[-1]["data"]["exit_code"] == ExitCode.PARTIAL


def test_a_set_that_failed_streams_no_set_and_no_handover(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, sent: Sent
) -> None:
    """The unlock committed and the set did not: nothing was set, and nothing
    that works was handed over, so neither event is sent."""
    failure = PartialAccountChangeError(DENIED, completed=(UNLOCKED,))
    _open(monkeypatch, FakeSession("LOCKED(TIMED)", failure), unseen=True)

    lines = _stream(_run(runner, write_config(WRAPPED), "--output", "jsonl"))

    assert "password.applied" not in _names(lines)
    assert "password.delivered" not in _names(lines)
    assert "target.finished" in _names(lines)


def test_the_seen_path_is_refused_under_jsonl_and_displays_nothing(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, sent: Sent
) -> None:
    """Invariant 2, guard 2, on the mode added after it: `manual` is refused
    before a password is drawn, so there is no `password.displayed` to send."""
    session = Succeeding("OPEN", DENIED)
    _open(monkeypatch, session, unseen=False)

    result = _run(runner, write_config(MANUAL), "--output", "jsonl")

    assert result.exit_code != ExitCode.SUCCESS
    assert "password.displayed" not in result.stdout
    assert session.reset == [], "a password was set on a path that cannot show it"


JOURNALLED = WRAPPED + "\nreset_records:\n  vault: vault-dev\n  prefix: sopuli/personal-resets\n"


def test_a_journalled_reset_streams_its_lock_taken_and_let_go(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, sent: Sent
) -> None:
    """UC-2 §3.3's lock, keyed on the record path, through the manager's observer
    -- the only thing that emits `lock.*` (review of #546)."""
    journal = MemoryStore()
    monkeypatch.setattr("sopuli.cli._reset_journal", lambda run, config: journal)
    _open(monkeypatch, Succeeding("OPEN", DENIED), unseen=True)

    lines = _stream(_run(runner, write_config(JOURNALLED), "--output", "jsonl"))

    assert _names(lines) == [
        "run.started",
        "plan.resolved",
        "lock.acquired",
        "target.started",
        "password.applied",
        "password.delivered",
        "target.finished",
        "lock.released",
        "run.finished",
    ]
    acquired, released = (
        line["data"] for line in lines if line["event"] in ("lock.acquired", "lock.released")
    )
    assert acquired["path"] == released["path"]
    assert ACCOUNT in acquired["path"]
    assert TARGET in acquired["path"]
    assert (acquired["released"], released["released"]) == (False, True)


def test_a_reset_somebody_else_holds_is_streamed_as_denied(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, sent: Sent
) -> None:
    """The collision §3.3 keys the lock to prevent: exit 7, the holder named,
    and no target dialled. The path is read off a clean run rather than
    re-derived here, so this cannot drift from what the verb locks."""
    journal = MemoryStore()
    monkeypatch.setattr("sopuli.cli._reset_journal", lambda run, config: journal)
    session = Succeeding("OPEN", DENIED)
    _open(monkeypatch, session, unseen=True)
    config = write_config(JOURNALLED)
    first = _stream(_run(runner, config, "--output", "jsonl"))
    path = next(line["data"]["path"] for line in first if line["event"] == "lock.acquired")
    key = LockKey(store="vault-dev", path=path)
    held = journal.read(lock_path(key))
    assert held is not None
    journal.write(
        lock_path(key),
        LockRecord.acquired(
            correlation_id="01JSOMEBODYELSE",
            command="account reset-password",
            holder=Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli"),
            now=utc_now(),
        ).to_dict(),
        cas=held.version,
    )
    session.reset.clear()

    result = _run(runner, config, "--output", "jsonl")

    assert isinstance(result.exception, LockDeniedError), result.exception
    lines = _stream(result)
    assert _names(lines) == ["run.started", "plan.resolved", "lock.denied", "run.finished"]
    assert lines[-2]["data"]["holder"]["correlation_id"] == "01JSOMEBODYELSE"
    assert lines[-1]["data"]["exit_code"] == ExitCode.LOCK_HELD
    assert session.reset == []


def test_the_seen_path_previews_under_jsonl_and_hands_nothing_over(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, sent: Sent
) -> None:
    """The seen path's `--dry-run` is exempt from guards 2 to 4 (#441's sixth
    guard): a preview prints a plan and never a password, so it streams -- with
    no `password.*` event at all, because nothing was set, delivered or shown
    (review of #546)."""
    session = Succeeding("OPEN", DENIED)
    _open(monkeypatch, session, unseen=False)

    result = _run(runner, write_config(MANUAL), "--dry-run", "--output", "jsonl")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    names = _names(_stream(result))
    assert names[0] == "run.started"
    assert names[-1] == "run.finished"
    assert "target.finished" in names
    assert not [name for name in names if name.startswith("password.")]
    assert session.reset == []

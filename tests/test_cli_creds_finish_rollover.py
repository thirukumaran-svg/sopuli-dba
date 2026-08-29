"""``sopuli creds finish-rollover`` end to end, without a database (#263).

Same arrangement as ``tests/test_cli_creds_apply.py``: in-process through
``CliRunner``, the vault a :class:`~sopuli.store.MemoryStore` and the driver a
fake session.

The property carrying this file is that **the statement is issued only where it
was decided to be safe**, and it is asserted on what the fake session recorded
rather than on what the run printed -- a command can report `PENDING_APPLY` and
still have closed the window.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator

from sopuli import check
from sopuli import finish_rollover as windows
from sopuli.cli import cli
from sopuli.config.model import Vault
from sopuli.driver.protocol import (
    EXPIRE_PASSWORD,
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

LIVE = "Correct-Horse-Battery-9"
STAGED = "Vertical-Anchor-Marble-4"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8")))


class FakeSession:
    """One target's answers, and a record of what it was asked to do.

    ``closed`` is the assertion that matters: every test about an account this
    verb leaves alone checks that no statement reached the database, because a
    row saying `PENDING_APPLY` beside a window that was closed anyway is exactly
    the bug worth catching.
    """

    def __init__(
        self,
        users: Mapping[str, UserState | None],
        answers: Mapping[str, VerifyResult],
        *,
        capabilities: frozenset[str],
        already_closed: bool = False,
    ) -> None:
        self.users = dict(users)
        self.answers = dict(answers)
        self.capabilities = capabilities
        self.already_closed = already_closed
        self.attempts: list[str] = []
        self.budgets: list[int] = []
        self.closed: list[str] = []

    def scope(self) -> Scope:
        return Scope(type="pdb", container="ALPHA", read_write=True, capabilities=self.capabilities)

    def describe_user(self, account: str) -> UserState | None:
        found = self.users.get(account.upper())
        if found is None:
            return None
        return replace(found, rollover_active=found.rollover_active and not self.already_closed)

    def verify_password(
        self,
        account: str,
        secret: Secret,
        *,
        method: str = VERIFY_LOGIN,
        lockout_margin: int = 2,
        attempts: int = 1,
    ) -> VerifyResult:
        self.attempts.append(account.upper())
        self.budgets.append(attempts)
        return self.answers.get(account.upper(), VerifyResult(VERIFY_LOGIN, PASS, latency_ms=8))

    def finish_rollover(self, account: str) -> ChangeResult:
        if self.already_closed:
            return ChangeResult(changed=False, detail="no rollover window is open")
        self.closed.append(account.upper())
        return ChangeResult(changed=True, detail="rollover window ended")

    def close(self) -> None:
        return None


def in_rollover(name: str = "ACME_WEB_USER", **fields: Any) -> UserState:
    ends_at = datetime.now(UTC) + timedelta(minutes=41)
    return UserState(
        **{
            "name": name,
            "status": "OPEN & IN ROLLOVER",
            "profile": "APP_PROFILE",
            "rollover_active": True,
            "rollover_enabled": True,
            "rollover_time": "1",
            "rollover_ends_at": ends_at,
            **fields,
        }
    )


def quiet(name: str = "ACME_WEB_USER") -> UserState:
    """An account with no window open, which is the ordinary night."""
    return UserState(name=name, status="OPEN", profile="DEFAULT", rollover_active=False)


Harness = Callable[..., dict[str, Any]]


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Harness:
    def install(
        *,
        documents: Mapping[str, dict[str, Any]] | None = None,
        users: Mapping[str, UserState | None] | None = None,
        answers: Mapping[str, VerifyResult] | None = None,
        capabilities: frozenset[str] = frozenset({EXPIRE_PASSWORD}),
        connect_error: Exception | None = None,
        already_closed: bool = False,
    ) -> dict[str, Any]:
        store = MemoryStore()
        for path, body in (documents or _promoted()).items():
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
                session = FakeSession(
                    users if users is not None else {"ACME_WEB_USER": in_rollover()},
                    answers or {},
                    capabilities=capabilities,
                    already_closed=already_closed,
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


def _promoted() -> dict[str, dict[str, Any]]:
    """A finished rotation: `current` holds the new password, nothing staged."""
    return {
        f"apps/acme/{target}": {"DB_CREDENTIALS": {"acme_web_user": LIVE}}
        for target in ("appdb-alpha", "appdb-beta")
    }


def _unfinished() -> dict[str, dict[str, Any]]:
    """A rotation halfway: `pending` staged, `current` still the old password."""
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
    return runner.invoke(cli, ["creds", "finish-rollover", "--config", str(config), *args])


def document(result: Result) -> dict[str, Any]:
    return dict(json.loads(result.output))


# ------------------------------------------------------------ the happy path ---


def test_an_open_window_is_closed(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate()
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["sessions"][0].closed == ["ACME_WEB_USER"]
    assert "rollover window closed" in result.output


def test_the_row_says_how_early_it_was_closed(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Four minutes is a tidy-up and fifty-five is a decision about somebody's
    grace period."""
    estate()
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert "early" in result.output


def test_one_login_is_spent_per_account(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §7 mitigation 1, and the budget declared to the guard before it is
    spent."""
    harness = estate()
    run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].attempts == ["ACME_WEB_USER"]
    assert harness["sessions"][0].budgets == [1]


def test_a_naive_window_end_is_read_as_utc_in_the_document(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    """Oracle's `DATE` is naive, and `to_rfc3339` converts a naive value from the
    *machine's* local time -- so on a laptop three hours off UTC the rendered
    deadline would sit three hours away from the countdown computed off the same
    field. One run, two answers."""
    naive = (datetime.now(UTC) + timedelta(minutes=41)).replace(tzinfo=None)
    # Drifted, so the window is left open and its deadline is still reported --
    # a window this run closed has no deadline left to render.
    estate(
        users={"ACME_WEB_USER": in_rollover(rollover_ends_at=naive)},
        answers={"ACME_WEB_USER": VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017")},
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")

    body = document(result)
    assert not list(validator.iter_errors(body))
    ends_at = body["results"][0]["rollover"]["ends_at"]
    assert ends_at == naive.isoformat() + "Z"


def test_the_document_validates_and_reports_the_window(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    estate()
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")

    body = document(result)
    assert not list(validator.iter_errors(body))
    entry = body["results"][0]
    assert [action["kind"] for action in entry["actions"]] == ["rollover_finish"]
    assert entry["changed"] is True
    # The estate this run *leaves behind*, so the window it just closed is gone.
    assert entry["rollover"] == {"active": False, "profile_rollover_time": "1"}


# ---------------------------------------------------- what is left untouched ---


def test_nothing_open_is_no_change_and_no_statement(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 9, and the ordinary night. Oracle accepts the statement silently
    with no window open, so a run that issued it would report a change every
    time."""
    harness = estate(users={"ACME_WEB_USER": quiet()})
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")

    assert harness["sessions"][0].closed == []
    assert harness["sessions"][0].attempts == []
    assert document(result)["results"][0]["changed"] is False
    assert result.exit_code == ExitCode.SUCCESS


def test_a_staged_pending_leaves_the_window_open_and_spends_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#263's decision. The rotation is unfinished, so `current` is the old
    password -- and under an open window the old password passes, which is why
    this is a vault-side rule and not a login."""
    harness = estate(documents=_unfinished())
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].closed == []
    assert harness["sessions"][0].attempts == []
    assert windows.PENDING_APPLY in result.output
    assert "creds apply" in result.output


def test_a_drifted_account_keeps_its_window_and_exits_three(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Closing would leave nothing that authenticates: neither the password
    applications fetch nor the one about to stop working. Exit 3 is `check`'s
    code and the one a monitoring system already alerts on."""
    harness = estate(
        answers={"ACME_WEB_USER": VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017")}
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].closed == []
    assert result.exit_code == ExitCode.DRIFT
    assert check.DRIFT in result.output


def test_a_declined_login_keeps_the_window(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate(
        answers={"ACME_WEB_USER": VerifyResult(VERIFY_LOGIN, SKIPPED, detail="within 2")}
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].closed == []
    assert check.UNVERIFIABLE in result.output


def test_a_locked_account_keeps_its_window(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate(
        users={"ACME_WEB_USER": in_rollover(status="LOCKED & IN ROLLOVER", locked=True)}
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].closed == []
    assert check.LOCKED in result.output


def test_a_database_that_cannot_close_early_is_skipped(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Not an error: the window elapses on its own, which is what would have
    happened anyway."""
    harness = estate(capabilities=frozenset())
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].closed == []
    assert result.exit_code == ExitCode.SUCCESS
    assert windows.SKIPPED in result.output


def test_a_missing_account_is_reported(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate(users={})
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert check.ACCOUNT_MISSING in result.output


def test_a_window_that_closed_underneath_the_run_is_not_a_change(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """It elapsed, or another run got there first. What this run wanted is true
    and it is not what made it true."""
    estate(already_closed=True)
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")

    assert document(result)["results"][0]["changed"] is False
    assert result.exit_code == ExitCode.SUCCESS


# -------------------------------------------------------------- the preview ---


def test_dry_run_closes_nothing_and_spends_no_login(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 8. A login is a real cost, and a run that changes nothing should
    not pay it -- what a preview is for is which windows are open and how much is
    left on them."""
    harness = estate()
    result = run(runner, write_config(CONFIG), "--dry-run")

    assert all(session.closed == [] for session in harness["sessions"])
    assert all(session.attempts == [] for session in harness["sessions"])
    assert "no window was closed" in result.output
    assert result.exit_code == ExitCode.SUCCESS


def test_the_preview_shows_its_rows_and_what_would_be_closed(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """ "Nothing closed" is true of a preview and is the opposite of what somebody
    ran one to find out."""
    estate()
    result = run(runner, write_config(CONFIG), "--dry-run")

    assert "would end this window" in result.output
    assert "2 would be closed" in result.output
    assert "no window was closed (--dry-run)" in result.output


def test_a_preview_that_cannot_reach_a_target_says_so(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A preview still reaches every database, so an unreachable one is a real
    finding and it sets the exit code. Printing only the plan and the window
    table would leave a non-zero exit nobody could explain."""
    estate(connect_error=RuntimeError("ORA-12541: no listener"))
    result = run(runner, write_config(CONFIG), "--dry-run")

    assert result.exit_code == ExitCode.FAILURE
    assert "ORA-12541" in result.output


def test_a_preview_reports_what_it_would_leave_open(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The half a preview is for, beside the half it would close."""
    estate(documents=_unfinished())
    result = run(runner, write_config(CONFIG), "--dry-run")

    assert windows.PENDING_APPLY in result.output
    assert "nothing would be closed" in result.output


def test_the_preview_shows_what_is_open_and_for_how_long(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Who am I about to cut off, and how early."""
    estate()
    result = run(runner, write_config(CONFIG), "--dry-run")

    assert "WINDOW" in result.output
    assert "open," in result.output


# --------------------------------------------------------------- the failures ---


def test_an_unreachable_target_is_a_finding_and_not_a_crash(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """And the harmless direction: a window nobody closed elapses on its own."""
    estate(connect_error=RuntimeError("ORA-12541: no listener"))
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.FAILURE
    assert "ORA-12541" in result.output


def test_readonly_refuses_before_anything_connects(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate()
    result = run(runner, write_config(CONFIG), "--readonly")

    assert harness["sessions"] == []
    assert result.exit_code != ExitCode.SUCCESS


def test_no_lock_is_taken(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Nothing in any store changes, so there is nothing for the advisory lock to
    protect -- and a nightly job that took one would block the rotation it exists
    to finish."""
    estate()
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert "lock" not in document(result)

"""Suspending an account against a real Oracle (#463). Tier 1.

The statement's shape is tier 0 (`test_oracle_statements.py`) and the
component-wise status parse is too (`test_oracle_accounts.py`). What only a
server can answer is the pair this file exists for, both measured on 26ai Free
23.26.2.0.0 on 2026-09-17, and both measured **twice** because one run is not a
measurement (#326):

* ``ACCOUNT LOCK`` against an already-``LOCKED`` account is accepted silently and
  leaves the status alone — so the driver reads the state first rather than
  issuing and reporting a change (invariant 9, the same shape `_unlock` rests on);
* ``LOCKED(TIMED)`` is **not** already suspended, and the transition to ``LOCKED``
  is real. An account locked by a failed-login limit reads ``LOCKED(TIMED)``;
  ``ACCOUNT LOCK`` takes it to ``LOCKED``. Reporting no change there would say an
  offboarding had already happened when what is true is that somebody mistyped
  their password — and the two states differ in exactly what this verb is for,
  since ``PASSWORD_LOCK_TIME`` clears the first on its own and nothing clears the
  second.

The measurement that made the second case worth a test: the naive check is
``status == "LOCKED"``, which is wrong in both directions. ``LOCKED(TIMED)``
*contains* ``LOCKED``, and the status compounds — ``EXPIRED & LOCKED`` is a real
value — so a substring test calls a timed lock deliberate and an equality test
calls a compound one open. That is #309's ``EXPIRED(GRACE)`` bug, caught before
it cost anything.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from typing import Any

import pytest

from oracle_harness import Environment
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target
from sopuli.driver.protocol import ACCOUNT_LOCK, Credential, DriverError
from sopuli.secrets import Secret

USER = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")

CORRELATION_ID = "5f2d81ac-7b34-4e90-a1c6-90b7d4e25318"

ACCOUNT = "acme_suspend_user"

#: The profile `test/oracle-init/01_test_profiles.sql` creates with a
#: `failed_login_attempts` low enough to reach by trying.
LOCKOUT_PROFILE = "sopuli_lockout"

LIVE = "Su5pend-Pa55-word1"
WRONG = "not-the-password"


@pytest.fixture
def session_module() -> Any:
    return pytest.importorskip("sopuli.driver.oracle.session")


@pytest.fixture
def session(live_oracle: Environment, session_module: Any) -> Iterator[Any]:
    driver = session_module.OracleDriver(env=os.environ, correlation_id=CORRELATION_ID)
    opened = driver.connect(
        ExpandedTarget(
            target=Target(
                name="tier1-oracle",
                type="oracle",
                dsn=live_oracle.dsn,
                admin=AdminCredential(username=USER, auth=AdminAuth(method="env")),
            ),
            index=0,
        ),
        Credential(username=USER, secret=Secret(PASSWORD)),
    )
    try:
        yield opened
    finally:
        opened.close()


def _run(session: Any, *statements: str) -> None:
    with session.connection.cursor() as cursor:
        for statement in statements:
            cursor.execute(statement)


def _drop(session: Any) -> None:
    with contextlib.suppress(Exception):
        _run(session, f"drop user {ACCOUNT} cascade")


@pytest.fixture
def account(session: Any) -> Iterator[Any]:
    _drop(session)
    _run(
        session,
        f'create user {ACCOUNT} identified by "{LIVE}" profile {LOCKOUT_PROFILE}',
        f"grant create session to {ACCOUNT}",
    )
    try:
        yield session
    finally:
        _drop(session)


def _status(session: Any) -> str:
    state = session.describe_user(ACCOUNT)
    assert state is not None
    return str(state.status)


#: `test/oracle-init/01_test_profiles.sql` sets `FAILED_LOGIN_ATTEMPTS 3` on
#: `sopuli_lockout`, so reaching the lock takes three tries and not one. Read
#: from the profile rather than hard-coded would be better still; the profile is
#: fixture data this repository owns, and a test that silently passed on a
#: *different* number is the thing worth avoiding -- which the assertion below
#: does, by failing if the account is not locked when the loop ends.
FAILED_LOGIN_ATTEMPTS = 3


def _lock_by_failing_a_login(session: Any, live_oracle: Environment) -> None:
    """Reach `LOCKED(TIMED)` the way an estate reaches it -- by getting it wrong."""
    oracledb = pytest.importorskip("oracledb")
    for _ in range(FAILED_LOGIN_ATTEMPTS):
        with contextlib.suppress(Exception):
            oracledb.connect(user=ACCOUNT, password=WRONG, dsn=live_oracle.dsn)
    assert _status(session) == "LOCKED(TIMED)", "the lockout profile did not lock the account"


def test_an_open_account_is_suspended(account: Any) -> None:
    change = account.suspend_account(ACCOUNT)

    assert change.action == ACCOUNT_LOCK
    assert change.status == "OPEN"
    assert change.changed is True
    assert "open" in (change.detail or "").lower()
    assert _status(account) == "LOCKED"


def test_a_second_suspend_reports_no_change(account: Any) -> None:
    """Invariant 9, end to end. Oracle accepts the second statement silently."""
    first = account.suspend_account(ACCOUNT)
    second = account.suspend_account(ACCOUNT)

    assert first.changed is True
    assert second.changed is False
    assert second.status == "LOCKED"
    assert "already locked" in (second.detail or "")
    assert _status(account) == "LOCKED"


def test_a_timed_lock_is_not_already_suspended(account: Any, live_oracle: Environment) -> None:
    """The measurement this file exists for: `LOCKED(TIMED)` -> `LOCKED` is a change.

    A failed-login lock expires on its own; this one does not, and a personal
    reset refuses a deliberate `LOCKED` (H4, #455) while it clears a timed one.
    Reporting `changed: False` here would claim an offboarding that never
    happened.
    """
    _lock_by_failing_a_login(account, live_oracle)

    change = account.suspend_account(ACCOUNT)

    assert change.changed is True
    assert change.status == "LOCKED(TIMED)", "the status is the one it read, before it issued"
    assert "locked(timed)" in (change.detail or "").lower()
    assert _status(account) == "LOCKED"


def test_suspending_an_account_that_does_not_exist_is_an_error(session: Any) -> None:
    """The tool creates nothing (Q8), so a name it cannot find is worth stopping for."""
    with pytest.raises(DriverError) as caught:
        session.suspend_account("acme_no_such_user")

    assert "does not exist" in str(caught.value)

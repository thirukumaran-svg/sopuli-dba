"""Unlocking an account against a real Oracle. Tier 1.

The statement's shape is tier 0 (`test_oracle_statements.py`); the decision about
when it is issued at all is tier 0 too (`test_apply.py`). What only a server can
answer is the pair this file exists for:

* an ``ACCOUNT UNLOCK`` against an account that is **not** locked is accepted
  silently and leaves ``ACCOUNT_STATUS`` alone — which is why the driver reads the
  state first rather than issuing and reporting a change (invariant 9, and the
  same measurement `finish_rollover` rests on).

  **It is not inert, though.** Measured on 26ai 23.26.2.0.0
  (``sql/oracle/07_lock_and_rollover_probe.sql``, Q1): the statement resets
  ``SYS.USER$.LCOUNT`` — 2 before, 0 after — on an account that was never
  locked. ``ALTER USER … IDENTIFIED BY`` does not (Q2), so the two differ on
  exactly the counter UC-1 §7's ``--lockout-margin`` reads. Reading the state
  first is therefore load-bearing rather than merely tidy: a driver that issued
  it unconditionally would silently zero that counter on every run;
* ``LOCKED(TIMED)`` — the state a failed-login limit produces, and the one an
  application account is actually found in — is cleared by the same statement as
  a deliberate ``ACCOUNT LOCK``. Oracle has one statement for both, and a tool
  that assumed otherwise would fix the rarer of the two.

Both were measured on 26ai Free 23.26.2.0.0 before this was written.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from typing import Any

import pytest

from oracle_harness import Environment
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target
from sopuli.driver.protocol import (
    ACCOUNT_UNLOCK,
    AccountAttributes,
    Credential,
    DriverError,
)
from sopuli.secrets import Secret

USER = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")

CORRELATION_ID = "1c9b4e73-52a8-4d16-8f0b-7e3a95d2c684"

ACCOUNT = "acme_locked_user"

#: The profile `test/oracle-init/01_test_profiles.sql` creates with a
#: `failed_login_attempts` low enough to reach by trying.
LOCKOUT_PROFILE = "sopuli_lockout"

LIVE = "L0cked-Pa55-word1"
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


UNLOCK = AccountAttributes(unlock=True)


def _lock(session: Any) -> None:
    _run(session, f"alter user {ACCOUNT} account lock")


def _status(session: Any) -> str:
    state = session.describe_user(ACCOUNT)
    assert state is not None
    return str(state.status)


def test_a_locked_account_is_unlocked(account: Any) -> None:
    _lock(account)

    changes = account.apply_attributes(ACCOUNT, UNLOCK)

    assert [change.attribute for change in changes] == [ACCOUNT_UNLOCK]
    assert changes[0].changed is True
    assert _status(account) == "OPEN"


def test_an_open_account_is_reported_rather_than_altered(account: Any) -> None:
    """Invariant 9. Oracle accepts the statement against an open account without
    complaint, so a driver that just issued it would report a change on every run
    of an estate that declares the attribute."""
    changes = account.apply_attributes(ACCOUNT, UNLOCK)

    assert changes[0].changed is False
    assert "not locked" in (changes[0].detail or "")


def test_a_second_unlock_reports_no_change(account: Any) -> None:
    """The re-run invariant 9 is really about, end to end against a server."""
    _lock(account)

    first = account.apply_attributes(ACCOUNT, UNLOCK)
    second = account.apply_attributes(ACCOUNT, UNLOCK)

    assert first[0].changed is True
    assert second[0].changed is False


def test_a_timed_lock_is_cleared_by_the_same_statement(
    account: Any, session_module: Any, live_oracle: Environment
) -> None:
    """`LOCKED(TIMED)` is what a failed-login limit produces, and it is the state
    an application account whose password drifted is actually found in. Reached
    by spending the profile's attempts rather than by asserting Oracle's word for
    it."""
    driver = session_module.OracleDriver(env=os.environ, correlation_id=CORRELATION_ID)
    target = ExpandedTarget(
        target=Target(
            name="as-the-account",
            type="oracle",
            dsn=live_oracle.dsn,
            admin=AdminCredential(username=ACCOUNT, auth=AdminAuth(method="env")),
        ),
        index=0,
    )
    for _ in range(5):
        with contextlib.suppress(Exception):
            driver.connect(target, Credential(username=ACCOUNT, secret=Secret(WRONG))).close()

    state = account.describe_user(ACCOUNT)
    assert state is not None
    assert state.locked, "the profile did not lock the account"

    changes = account.apply_attributes(ACCOUNT, UNLOCK)

    assert changes[0].changed is True
    assert _status(account) == "OPEN"


def test_nothing_is_issued_for_an_empty_request(account: Any) -> None:
    """Opt-in, never inferred: an estate declaring no attributes reads nothing and
    issues nothing, and does not pay a round trip for the ones it did not ask
    for."""
    _lock(account)

    assert account.apply_attributes(ACCOUNT, AccountAttributes()) == ()
    assert _status(account) != "OPEN"


def test_a_missing_account_is_an_error_rather_than_a_silent_no_op(session: Any) -> None:
    """The same refusal `set_password` gives, for the same reason: an attribute
    enforced on nothing would report success for work that could not happen."""
    with pytest.raises(DriverError):
        session.apply_attributes("acme_no_such_user", UNLOCK)

"""Expiring an account's password against a real Oracle (#525). Tier 1.

The statement's shape is tier 0 (`test_oracle_statements.py`). What only a server
can answer is what `sql/oracle/08_expire_password_probe.sql` measured on 26ai
Free 23.26.2.0.0 on 2026-09-25, twice, and each of these tests pins one row of it:

* a second bare ``PASSWORD EXPIRE`` is accepted **silently**, so ``changed:
  false`` has to come from the driver reading the state first (invariant 9);
* ``EXPIRED(GRACE)`` is **not** already expired -- the password still logs in,
  and expiring it is a real change;
* a lock survives it, so the verb neither needs nor does anything about one;
* an open rollover window survives it too, and the old password still
  authenticates -- which is why the driver closes the window first (#525,
  option b), and what the last test proves it did.

Login results are read from the server's own code. ``ORA-28001`` means the
password authenticated and is merely expired; ``ORA-01017`` means it is dead.
"""

from __future__ import annotations

import contextlib
import os
import time
from collections.abc import Iterator
from typing import Any

import pytest

from oracle_harness import Environment
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target
from sopuli.driver.protocol import (
    PASSWORD_EXPIRE,
    PASSWORD_ROLLOVER,
    ROLLOVER_FINISH,
    Credential,
    DriverError,
)
from sopuli.secrets import Secret

USER = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")

CORRELATION_ID = "0c9e6a55-3f1d-4b8e-9d27-5a1e8f4b6c03"

ACCOUNT = "acme_expire_user"

#: Created and dropped by the grace test itself. A one-second lifetime is not
#: something `test/oracle-init` should leave lying around for the rest of the
#: suite to find.
GRACE_PROFILE = "acme_expire_grace"

#: `test/oracle-init/01_test_profiles.sql`, `PASSWORD_ROLLOVER_TIME 1/24`.
ROLLOVER_PROFILE = "sopuli_rollover"

#: `test/oracle-init/01_test_profiles.sql`, `FAILED_LOGIN_ATTEMPTS 3` and a
#: one-minute `PASSWORD_LOCK_TIME` -- reachable by getting the password wrong.
LOCKOUT_PROFILE = "sopuli_lockout"
FAILED_LOGIN_ATTEMPTS = 3
WRONG = "not-the-password"

OLD = "Expire-Pa55-Old1"
NEW = "Expire-Pa55-New2"


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
    with contextlib.suppress(Exception):
        _run(session, f"drop profile {GRACE_PROFILE}")


def _create(session: Any, profile: str = "default") -> None:
    _run(
        session,
        f'create user {ACCOUNT} identified by "{OLD}" profile {profile}',
        f"grant create session to {ACCOUNT}",
    )


@pytest.fixture
def clean(session: Any) -> Iterator[Any]:
    _drop(session)
    try:
        yield session
    finally:
        _drop(session)


@pytest.fixture
def account(clean: Any) -> Any:
    _create(clean)
    return clean


def _status(session: Any) -> str:
    state = session.describe_user(ACCOUNT)
    assert state is not None
    return str(state.status)


def _login(live_oracle: Environment, password: str) -> str:
    """The server's answer to a login, as its ORA- code, or ``OK``."""
    oracledb = pytest.importorskip("oracledb")
    try:
        oracledb.connect(user=ACCOUNT, password=password, dsn=live_oracle.dsn).close()
    except oracledb.DatabaseError as error:
        return f"ORA-{error.args[0].code:05d}"
    return "OK"


def _by_action(changes: tuple[Any, ...]) -> dict[str, Any]:
    return {change.action: change for change in changes}


def test_an_open_account_is_expired(account: Any, live_oracle: Environment) -> None:
    changes = account.expire_password(ACCOUNT)

    assert [change.action for change in changes] == [ROLLOVER_FINISH, PASSWORD_EXPIRE]
    rows = _by_action(changes)
    assert rows[ROLLOVER_FINISH].changed is False
    assert rows[PASSWORD_EXPIRE].changed is True
    assert rows[PASSWORD_EXPIRE].status == "OPEN", "the status it read, before it issued"
    assert _status(account) == "EXPIRED"
    assert _login(live_oracle, OLD) == "ORA-28001", "authenticates, and must be changed"


def test_a_second_expiry_reports_no_change(account: Any) -> None:
    """Invariant 9, end to end. Oracle accepts the second statement silently."""
    account.expire_password(ACCOUNT)
    second = _by_action(account.expire_password(ACCOUNT))

    assert second[PASSWORD_EXPIRE].changed is False
    assert second[ROLLOVER_FINISH].changed is False
    assert "already expired" in (second[PASSWORD_EXPIRE].detail or "")
    assert _status(account) == "EXPIRED"


def test_a_grace_period_is_not_already_expired(clean: Any, live_oracle: Environment) -> None:
    """`EXPIRED(GRACE)` -> `EXPIRED` is a change: the password still logged in before it."""
    _run(
        clean,
        f"create profile {GRACE_PROFILE} limit password_life_time 1/86400 password_grace_time 1",
    )
    _create(clean, GRACE_PROFILE)
    # The status only moves into grace at a login after the lifetime has
    # passed. That login succeeds with a warning, which is the whole point.
    time.sleep(3)
    assert _login(live_oracle, OLD) == "OK"
    assert _status(clean) == "EXPIRED(GRACE)", "the grace profile did not produce a grace period"

    rows = _by_action(clean.expire_password(ACCOUNT))

    assert rows[PASSWORD_EXPIRE].changed is True
    assert rows[PASSWORD_EXPIRE].status == "EXPIRED(GRACE)"
    assert _status(clean) == "EXPIRED"


def test_a_lock_is_left_alone(account: Any) -> None:
    """Expiry and a lock are independent components; this verb unlocks nothing."""
    _run(account, f"alter user {ACCOUNT} account lock")

    rows = _by_action(account.expire_password(ACCOUNT))

    assert rows[PASSWORD_EXPIRE].changed is True
    assert _status(account) == "EXPIRED & LOCKED"


def test_a_timed_lock_is_left_alone(clean: Any, live_oracle: Environment) -> None:
    """The other lock: `LOCKED(TIMED)` becomes `EXPIRED & LOCKED(TIMED)` (#525 E5).

    Reached the way an estate reaches it, by failed logins, so the test pins the
    status Oracle actually produces rather than one the fixture asserted into
    being. A regression that cleared the timed lock, or read it as a reason not
    to expire, fails here.
    """
    _create(clean, LOCKOUT_PROFILE)
    for _ in range(FAILED_LOGIN_ATTEMPTS):
        _login(live_oracle, WRONG)
    assert _status(clean) == "LOCKED(TIMED)", "the lockout profile did not lock the account"

    rows = _by_action(clean.expire_password(ACCOUNT))

    assert rows[PASSWORD_EXPIRE].changed is True
    assert rows[PASSWORD_EXPIRE].status == "LOCKED(TIMED)", "the status it read, before it issued"
    assert _status(clean) == "EXPIRED & LOCKED(TIMED)"


def test_an_open_window_is_closed_first(clean: Any, live_oracle: Environment) -> None:
    """#525 option (b): the old password must not survive the expiry.

    Without the close, 26ai leaves `EXPIRED & IN ROLLOVER` and the old password
    answers ORA-28001 -- it still authenticates, and can set the next one.
    """
    if not clean.scope().supports(PASSWORD_ROLLOVER):
        pytest.skip(f"this target has no {PASSWORD_ROLLOVER} capability")
    _create(clean, ROLLOVER_PROFILE)
    _run(clean, f'alter user {ACCOUNT} identified by "{NEW}"')
    assert _status(clean) == "OPEN & IN ROLLOVER", "the window did not open"

    changes = clean.expire_password(ACCOUNT)

    rows = _by_action(changes)
    assert rows[ROLLOVER_FINISH].changed is True
    assert rows[PASSWORD_EXPIRE].changed is True
    assert _status(clean) == "EXPIRED"
    assert _login(live_oracle, OLD) == "ORA-01017", "the old password is dead"
    assert _login(live_oracle, NEW) == "ORA-28001", "the current one must be changed"


def test_expired_with_a_window_open_is_not_converged(clean: Any, live_oracle: Environment) -> None:
    """Option (b) redefines *done*: `EXPIRED & IN ROLLOVER` still has a window to close.

    This is the state somebody's hand-issued `PASSWORD EXPIRE` leaves, and the
    verb finishes it rather than calling it expired already.
    """
    if not clean.scope().supports(PASSWORD_ROLLOVER):
        pytest.skip(f"this target has no {PASSWORD_ROLLOVER} capability")
    _create(clean, ROLLOVER_PROFILE)
    _run(
        clean,
        f'alter user {ACCOUNT} identified by "{NEW}"',
        f"alter user {ACCOUNT} password expire",
    )
    assert _status(clean) == "EXPIRED & IN ROLLOVER"

    rows = _by_action(clean.expire_password(ACCOUNT))

    assert rows[ROLLOVER_FINISH].changed is True
    assert rows[PASSWORD_EXPIRE].changed is False
    assert _status(clean) == "EXPIRED"
    assert _login(live_oracle, OLD) == "ORA-01017"


def test_a_rollover_profile_with_no_window_open_closes_nothing(clean: Any) -> None:
    """A bare expiry opens no window, so a profile that grants one is not enough."""
    if not clean.scope().supports(PASSWORD_ROLLOVER):
        pytest.skip(f"this target has no {PASSWORD_ROLLOVER} capability")
    _create(clean, ROLLOVER_PROFILE)
    assert _status(clean) == "OPEN"

    rows = _by_action(clean.expire_password(ACCOUNT))

    assert rows[ROLLOVER_FINISH].changed is False
    assert rows[PASSWORD_EXPIRE].changed is True
    assert _status(clean) == "EXPIRED"


def test_expiring_an_account_that_does_not_exist_is_an_error(session: Any) -> None:
    """The tool creates nothing (Q8), so a name it cannot find is worth stopping for."""
    with pytest.raises(DriverError) as caught:
        session.expire_password("acme_no_such_user")

    assert "does not exist" in str(caught.value)

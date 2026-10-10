"""Resetting a personal account's password against a real Oracle. Tier 1.

The statement text is tier 0 (`test_oracle_statements.py`) and so is the
component-wise status parse (`test_oracle_accounts.py`). What only a server can
answer is what the three statements UC-2 §4.1 issues actually *do* to an account,
and the four facts this file exists for are all ones the design turned on:

* an **unseen** reset leaves the account `OPEN` and the old password dead;
* a **seen** reset leaves it `EXPIRED`, and the new password still authenticates
  -- through Oracle's change-at-logon flow rather than by being refused, which is
  the difference between an expired password and a wrong one (§5, `ORA-28001`);
* `LOCKED(TIMED)` is cleared on the way past and a deliberate `LOCKED` is
  refused, which is H4 and the one place this verb and `account suspend`
  have to agree about what a status means;
* the **rollover window is closed by default**, so the old password stops
  working -- and kept where the caller asks, where it does not. §4.3 decided the
  default the opposite way to UC-1 and this is where that claim meets a database.

The fifth is a refusal rather than a behaviour: an expiring reset of an account
on a rollover profile is refused before any DDL, because
`sql/oracle/07_lock_and_rollover_probe.sql` measured that `PASSWORD EXPIRE` does
*not* end the window -- the old password answers `ORA-28001` rather than
`ORA-01017`, so it still authenticates and is itself a way to set the new one.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from typing import Any

import pytest

from oracle_harness import Environment
from sopuli.driver.oracle.statements import PasswordNotAdmissibleError
from sopuli.driver.protocol import (
    ACCOUNT_UNLOCK,
    PASSWORD_ROLLOVER,
    PASSWORD_SET,
    ROLLOVER_FINISH,
    DriverError,
    PartialAccountChangeError,
)
from sopuli.secrets import Secret

ACCOUNT = "acme_reset_user"

#: `test/oracle-init/01_test_profiles.sql` creates both: a failed-login limit low
#: enough to reach by trying, and a one-hour `PASSWORD_ROLLOVER_TIME`.
LOCKOUT_PROFILE = "sopuli_lockout"
ROLLOVER_PROFILE = "sopuli_rollover"

#: Distinct enough that a logon proving one of them is unambiguous about which.
OLD = "Re5et-Old-Pa55word1"
NEW = Secret("Re5et-New-Pa55word2")


def _run(session: Any, *statements: str) -> None:
    with session.connection.cursor() as cursor:
        for statement in statements:
            cursor.execute(statement)


def _drop(session: Any) -> None:
    with contextlib.suppress(Exception):
        _run(session, f"drop user {ACCOUNT} cascade")


def _create(session: Any, *, profile: str | None = None) -> None:
    _drop(session)
    clause = f" profile {profile}" if profile is not None else ""
    _run(
        session,
        f'create user {ACCOUNT} identified by "{OLD}"{clause}',
        f"grant create session to {ACCOUNT}",
    )


@pytest.fixture
def account(session: Any) -> Iterator[Any]:
    """An ordinary account on `DEFAULT`, which grants no rollover window."""
    _create(session)
    try:
        yield session
    finally:
        _drop(session)


@pytest.fixture
def rollover_account(session: Any) -> Iterator[Any]:
    """An account whose profile grants a one-hour window.

    **No try/except around the setup.** Skipping on any exception would read as
    tolerance for 18c and 11g -- where the init script's guarded `CREATE PROFILE`
    does not run -- and is really tolerance for anything at all: a missing
    grant, a typo in the DDL, a database that went away. Every one of those would
    report green while running none of these cases, which is the failure
    `04-testing.md` §1 calls worse than a red suite.

    The release is declared instead, by `@pytest.mark.requires_capability` on
    each test below. That is the mechanism the suite already has for exactly this
    -- the rule being to declare the capability and never to branch on a version
    -- and it skips with a reason before the fixture runs at all.
    """
    _create(session, profile=ROLLOVER_PROFILE)
    try:
        yield session
    finally:
        _drop(session)


def _status(session: Any) -> str:
    state = session.describe_user(ACCOUNT)
    assert state is not None
    return str(state.status)


def _logon(live_oracle: Environment, password: str) -> str:
    """What the server says to a logon with ``password``: ``ok`` or its ORA- code.

    The codes are the answer rather than a pass/fail, because three of them are
    meaningfully different here and only one is a failure: ``ORA-01017`` is a
    dead password, ``ORA-28001`` is a live one whose account is expired -- which
    is Oracle's change flow rather than a refusal (§5) -- and ``ORA-28000`` is a
    lock.
    """
    oracledb = pytest.importorskip("oracledb")
    try:
        oracledb.connect(user=ACCOUNT, password=password, dsn=live_oracle.dsn).close()
    except Exception as error:  # noqa: BLE001 -- the code is what is being asserted
        return str(error).split(":")[0].strip()
    return "ok"


def _by_action(changes: tuple[Any, ...]) -> dict[str, Any]:
    return {change.action: change for change in changes}


# ------------------------------------------------------------- the unseen path ---


def test_an_unseen_reset_sets_the_password_and_leaves_the_account_open(
    account: Any, live_oracle: Environment
) -> None:
    """The default path. Nothing is expired, because nobody but the owner is
    meant to know the value (§1)."""
    changes = account.reset_password(ACCOUNT, NEW, expire=False)

    assert [change.action for change in changes] == [ACCOUNT_UNLOCK, PASSWORD_SET, ROLLOVER_FINISH]
    assert _by_action(changes)[PASSWORD_SET].changed is True
    assert _status(account) == "OPEN"
    assert _logon(live_oracle, NEW.reveal()) == "ok"
    assert _logon(live_oracle, OLD) == "ORA-01017"


def test_every_statement_is_reported_even_where_it_was_not_issued(account: Any) -> None:
    """`apply_attributes`' rule read for a verb: a row per statement the
    operation considered, so an account that was not locked says so rather than
    being absent from the answer."""
    changes = _by_action(account.reset_password(ACCOUNT, NEW, expire=False))

    assert changes[ACCOUNT_UNLOCK].changed is False
    assert "not locked" in (changes[ACCOUNT_UNLOCK].detail or "")
    assert changes[ROLLOVER_FINISH].changed is False
    assert "grants no rollover window" in (changes[ROLLOVER_FINISH].detail or "")


def test_the_status_reported_is_the_one_read_before_anything_was_issued(account: Any) -> None:
    """`AccountChange.status` is the state it found, as it is for `suspend`. A
    row carrying the state afterwards could not say what the reset walked into."""
    changes = account.reset_password(ACCOUNT, NEW, expire=False)

    assert {change.status for change in changes} == {"OPEN"}


# --------------------------------------------------------------- the seen path ---


def test_a_seen_reset_expires_the_account(account: Any, live_oracle: Environment) -> None:
    """§4.1's seen statement, and the thing it buys: the DBA's exposure ends at
    the owner's first logon, because the owner must change it then.

    The new password still **authenticates** -- `ORA-28001` is Oracle's
    change-at-logon flow, not a refusal, which is why §5 says an expired account
    is fixed by the password while a locked one needs the unlock.
    """
    changes = _by_action(account.reset_password(ACCOUNT, NEW, expire=True))

    assert changes[PASSWORD_SET].changed is True
    assert "expired for first logon" in (changes[PASSWORD_SET].detail or "")
    assert _status(account) == "EXPIRED"
    assert _logon(live_oracle, NEW.reveal()) == "ORA-28001"
    assert _logon(live_oracle, OLD) == "ORA-01017"


# ------------------------------------------------------------------ the locks ---


def test_a_timed_lock_is_cleared_on_the_way_past(account: Any, live_oracle: Environment) -> None:
    """H4: a reset unlocks `LOCKED(TIMED)` by default.

    The account is locked the way an estate reaches it -- by getting the password
    wrong -- and the reset is the whole fix: `IDENTIFIED BY` alone leaves the lock
    exactly as it found it (§4.1), so without statement 1 the owner would have a
    password that works and an account that refuses it.
    """
    _create(account, profile=LOCKOUT_PROFILE)
    for _ in range(3):
        assert _logon(live_oracle, "not-the-password") == "ORA-01017"
    assert _status(account) == "LOCKED(TIMED)"

    changes = _by_action(account.reset_password(ACCOUNT, NEW, expire=False))

    assert changes[ACCOUNT_UNLOCK].changed is True
    assert "locked(timed)" in (changes[ACCOUNT_UNLOCK].detail or "").lower()
    assert _status(account) == "OPEN"
    assert _logon(live_oracle, NEW.reveal()) == "ok"


def test_a_deliberate_lock_is_refused_and_nothing_is_issued(
    account: Any, live_oracle: Environment
) -> None:
    """The other half of H4, and the reason the two verbs share
    `deliberately_locked`: handing a working password to somebody who has been
    offboarded would undo the offboarding silently.

    **Proving that nothing was issued takes an unlock**, and the reason is worth
    keeping: a locked account answers `ORA-28000` to *any* password, so asserting
    that the new one fails while the lock is on would pass whether or not
    statement 2 had run. The account is unlocked afterwards and the **old**
    password is what is asked -- it still working is the only thing that says the
    refusal came before the reset rather than after it.
    """
    _run(account, f"alter user {ACCOUNT} account lock")

    with pytest.raises(DriverError) as caught:
        account.reset_password(ACCOUNT, NEW, expire=False)

    assert "does not unlock it" in str(caught.value)
    assert caught.value.password_sent is False
    assert _status(account) == "LOCKED"

    _run(account, f"alter user {ACCOUNT} account unlock")
    assert _logon(live_oracle, OLD) == "ok", "the password was changed by a refused reset"
    assert _logon(live_oracle, NEW.reveal()) == "ORA-01017"


# -------------------------------------------------------------- the rollover ---


@pytest.mark.requires_capability(PASSWORD_ROLLOVER)
def test_the_rollover_window_is_closed_by_default(
    rollover_account: Any, live_oracle: Environment
) -> None:
    """§4.3's decision, measured: *a reset means the new password is the only one
    that works*.

    Without statement 3 the old password keeps authenticating for the length of
    the window -- an hour, on this profile -- which is the exposure the default
    exists to remove.
    """
    changes = _by_action(rollover_account.reset_password(ACCOUNT, NEW, expire=False))

    assert changes[ROLLOVER_FINISH].changed is True
    assert _status(rollover_account) == "OPEN"
    assert _logon(live_oracle, NEW.reveal()) == "ok"
    assert _logon(live_oracle, OLD) == "ORA-01017"


@pytest.mark.requires_capability(PASSWORD_ROLLOVER)
def test_keeping_the_window_leaves_the_old_password_working(
    rollover_account: Any, live_oracle: Environment
) -> None:
    """The flag §4.3 asks for, and the measurement that makes it meaningful: with
    the window open, **both** passwords authenticate.

    This is the reset for somebody who does still know their old password. §4.3
    states the asymmetry rather than leaving it to be discovered -- a reset after
    a suspected disclosure is exactly the case that must not use it.
    """
    changes = _by_action(
        rollover_account.reset_password(ACCOUNT, NEW, expire=False, keep_rollover=True)
    )

    assert changes[ROLLOVER_FINISH].changed is False
    assert "kept, as asked" in (changes[ROLLOVER_FINISH].detail or "")
    assert "IN ROLLOVER" in _status(rollover_account)
    assert _logon(live_oracle, NEW.reveal()) == "ok"
    assert _logon(live_oracle, OLD) == "ok"


@pytest.mark.requires_capability(PASSWORD_ROLLOVER)
def test_an_expiring_reset_is_refused_on_a_rollover_profile(
    rollover_account: Any, live_oracle: Environment
) -> None:
    """The rollover probe's finding, as a refusal. Expiring does **not** end the
    window, so the seen path would leave a second live password behind it.

    Both entry points refuse, and both are asserted: the plan-time call a verb
    makes before drawing a password, and the reset itself, which asks again
    because that is the last point at which refusing costs nothing.
    """
    with pytest.raises(DriverError) as planned:
        rollover_account.require_no_rollover_window(ACCOUNT)

    with pytest.raises(DriverError) as issued:
        rollover_account.reset_password(ACCOUNT, NEW, expire=True)

    for caught in (planned, issued):
        assert "rollover window" in str(caught.value)
        assert ROLLOVER_PROFILE.upper() in str(caught.value)
    assert _logon(live_oracle, OLD) == "ok", "nothing was issued"


def test_the_plan_time_call_says_nothing_where_no_window_is_granted(account: Any) -> None:
    """The other answer, and the one every ordinary account gets. A refusal that
    fired on `DEFAULT` would make the seen path unreachable everywhere."""
    assert account.require_no_rollover_window(ACCOUNT) is None


@pytest.mark.requires_capability(PASSWORD_ROLLOVER)
def test_a_window_open_under_a_profile_since_set_to_zero_is_still_closed(
    session: Any, live_oracle: Environment
) -> None:
    """The condition the grant alone would miss.

    Its own profile rather than the shared fixture's, because the setup mutates
    one: a test that altered `sopuli_rollover` would change what every other
    rollover test sees.

    **Measured twice on 26ai Free 23.26.2.0.0**, because the reasoning and the
    behaviour disagree. Setting `PASSWORD_ROLLOVER_TIME` to zero leaves the
    status reading `OPEN & IN ROLLOVER` while the old password is *already* dead
    -- so the old password does not survive the change on this release, and what
    is actually wrong is that the status lies. Closing it makes the status true,
    and on a release where the old password does outlive the profile change it
    does the safety-critical thing as well.
    """
    profile = "sopuli_reset_stale"
    _drop(session)
    with contextlib.suppress(Exception):
        _run(session, f"drop profile {profile} cascade")
    _run(session, f"create profile {profile} limit password_rollover_time 1/24")
    try:
        _create(session, profile=profile)
        _run(session, f'alter user {ACCOUNT} identified by "{OLD}-rolled"')
        _run(session, f"alter profile {profile} limit password_rollover_time 0")
        assert "IN ROLLOVER" in _status(session), "the setup did not leave a stale window"

        changes = _by_action(session.reset_password(ACCOUNT, NEW, expire=False))

        assert changes[ROLLOVER_FINISH].changed is True
        assert _status(session) == "OPEN"
        assert _logon(live_oracle, NEW.reveal()) == "ok"
    finally:
        _drop(session)
        with contextlib.suppress(Exception):
            _run(session, f"drop profile {profile} cascade")


# ------------------------------------------------------------------- the rest ---


def test_an_inadmissible_password_is_refused_before_the_account_is_unlocked(
    account: Any, live_oracle: Environment
) -> None:
    """The unlock must not go out before the password is known to be admissible.

    Invariant 11 refuses a password containing `"` rather than escaping it. If
    that refusal were discovered while building statement 2, it would come
    *after* statement 1 had already unlocked the account. A reset that raised
    would leave a timed-locked account open on behalf of an operation that never
    happened, which is a state change from a failed run.

    The account being still locked afterwards is the whole assertion. It fails
    if the statements are built as a list literal, which evaluates left to right:
    the unlock goes out and the build raises after it.

    `PasswordNotAdmissibleError` rather than a bare `Exception`, so the test
    cannot pass on some unrelated failure that also left the account locked --
    `Secret` itself accepts the quote, and `admissible` inside
    `alter_user_password` is what refuses it.
    """
    _create(account, profile=LOCKOUT_PROFILE)
    for _ in range(3):
        assert _logon(live_oracle, "not-the-password") == "ORA-01017"
    assert _status(account) == "LOCKED(TIMED)"

    with pytest.raises(PasswordNotAdmissibleError, match="cannot escape") as caught:
        account.reset_password(ACCOUNT, Secret('has-a-"-in-it'), expire=False)

    assert caught.value.password_sent is False

    assert _status(account) == "LOCKED(TIMED)", "the unlock ran before the password was judged"
    assert _logon(live_oracle, OLD) == "ORA-28000"


# ------------------------------------------------------ a failure half way ---


def _fail_statement(session: Any, monkeypatch: pytest.MonkeyPatch, number: int) -> None:
    """Make the ``number``-th statement the session issues fail, and only that one.

    Every statement before it goes to the server for real and commits, which is
    the thing under test: DDL commits as it goes, so what ran before the failure
    has happened. The failure itself is injected, because the refusals a server
    gives at that point -- a verify function, `ORA-28007`, a privilege revoked
    mid-run -- need a profile or a second session this stack does not have, and
    what the driver must do with any of them is the same.
    """
    issued = session._issue
    count = 0

    def issue(statement: Any, *, password: bool = False) -> None:
        nonlocal count
        count += 1
        if count == number:
            # As the real `_issue` marks it: the server refused the statement.
            failure = DriverError("ORA-01031: insufficient privileges", code="ORA-01031")
            failure.password_sent = password
            raise failure
        issued(statement, password=password)

    monkeypatch.setattr(session, "_issue", issue)


def test_an_unlock_that_committed_before_the_set_failed_is_reported(
    account: Any, live_oracle: Environment, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The unlock is not taken back, so the failure carries it.

    A method that only raised would let the command report a `LOCKED(TIMED)`
    account as untouched while it is in fact open.
    """
    _create(account, profile=LOCKOUT_PROFILE)
    for _ in range(3):
        assert _logon(live_oracle, "not-the-password") == "ORA-01017"
    _fail_statement(account, monkeypatch, 2)

    with pytest.raises(PartialAccountChangeError) as caught:
        account.reset_password(ACCOUNT, NEW, expire=False)

    assert [change.action for change in caught.value.completed] == [ACCOUNT_UNLOCK]
    assert caught.value.code == "ORA-01031", "the server's own code survives the wrapping"
    assert caught.value.password_sent is True, "the failing statement was the set (#697)"
    assert _status(account) == "OPEN", "the unlock the error reports did not happen"
    assert _logon(live_oracle, OLD) == "ok", "the password was changed by a failed set"


def test_a_failed_set_on_an_unlocked_account_is_an_ordinary_failure(
    account: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing committed, so nothing is claimed: the unlock row is unchanged and
    a partial error would say otherwise."""
    _fail_statement(account, monkeypatch, 1)

    with pytest.raises(DriverError) as caught:
        account.reset_password(ACCOUNT, NEW, expire=False)

    assert not isinstance(caught.value, PartialAccountChangeError)
    assert caught.value.password_sent is True, "the failing statement was the set (#697)"


@pytest.mark.requires_capability(PASSWORD_ROLLOVER)
def test_a_set_that_committed_before_the_close_failed_is_reported(
    rollover_account: Any, live_oracle: Environment, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The serious case: the new password is live and so is the old one.

    Both logons are asserted because both are the point -- the error has to say
    the password was set, since the caller hands it over on the strength of that,
    and the old one still working is why the row cannot read as success.
    """
    _fail_statement(rollover_account, monkeypatch, 2)

    with pytest.raises(PartialAccountChangeError) as caught:
        rollover_account.reset_password(ACCOUNT, NEW, expire=False)

    assert [change.action for change in caught.value.completed] == [ACCOUNT_UNLOCK, PASSWORD_SET]
    assert caught.value.password_sent is True, "the set before the close went out (#697)"
    assert _logon(live_oracle, NEW.reveal()) == "ok"
    assert _logon(live_oracle, OLD) == "ok", "the window closed although its statement failed"


def test_resetting_an_account_that_does_not_exist_is_an_error(session: Any) -> None:
    """The tool creates nothing (Q8), so a name it cannot find is worth stopping
    for -- and stopping before a password has been delivered anywhere."""
    with pytest.raises(DriverError) as caught:
        session.reset_password("acme_no_such_user", NEW, expire=False)

    assert "does not exist" in str(caught.value)
    assert caught.value.password_sent is False

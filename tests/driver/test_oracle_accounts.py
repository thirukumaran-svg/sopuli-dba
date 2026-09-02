"""Reading an account's state against a real Oracle (#178). Tier 1.

The mapping is tier 0 (`test_accounts.py`). What only a server can answer is
whether the *shapes* are what this code believes: that `ACCOUNT_STATUS` really
does carry `IN ROLLOVER` after a rotation, that `DBA_PROFILES` really does answer
`DEFAULT` for a resource a profile does not set, and that the queries run at all.

Every one of those was measured before the code was written, and they are pinned
here so a future release changing one of them fails rather than drifts.

State is created and dropped per test rather than by recreating the container
(`04-testing.md` §4). Names come from the fictional vocabulary in
`01-configuration.md`, so nothing here resembles a real estate.
"""

from __future__ import annotations

import contextlib
import os
import time
from collections.abc import Iterator
from typing import Any

import pytest

from oracle_harness import Environment
from sopuli.check import grace_warning
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target
from sopuli.driver.protocol import PASS, Credential
from sopuli.secrets import Secret

USER = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")

CORRELATION_ID = "5c2a9b71-8e34-4d06-a7f1-2e9b6c0d1a53"

ACCOUNT = "acme_orders_user"
PROFILE = "acme_orders_prof"
SITE_ROLE = "acme_app_admin"
LOOP_A = "acme_loop_a"
LOOP_B = "acme_loop_b"
FIRST = "First-Pass-1x"
SECOND = "Second-Pass-2x"


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


@pytest.fixture
def account(session: Any) -> Iterator[Any]:
    """One account on a profile that sets two limits and leaves the rest unset.

    The unset ones are the point: they are what report `DEFAULT`, and what
    `PROFILE_QUERY` has to resolve.
    """
    _drop(session)
    _run(
        session,
        f"create profile {PROFILE} limit password_rollover_time 1 failed_login_attempts 5",
        f'create user {ACCOUNT} identified by "{FIRST}" profile {PROFILE}',
        f"grant create session to {ACCOUNT}",
        f"grant connect to {ACCOUNT}",
    )
    try:
        yield session
    finally:
        _drop(session)


def _drop(session: Any) -> None:
    for statement in (f"drop user {ACCOUNT} cascade", f"drop profile {PROFILE} cascade"):
        # Absent is the desired state, so "it was not there" is a success.
        with contextlib.suppress(Exception):
            _run(session, statement)


def test_an_account_is_described_from_the_baseline_grant_set(account: Any) -> None:
    """#86: `check` needs no site-specific grant, so everything here is on the
    documented set — and in particular not `SYS.USER$`."""
    state = account.describe_user(ACCOUNT)

    assert state is not None
    assert state.name == ACCOUNT.upper(), "the spelling the database gave back"
    assert state.status == "OPEN"
    assert not state.locked
    assert not state.expired
    assert state.profile == PROFILE.upper()
    assert state.vendor_maintained is False
    assert "CONNECT" in state.roles


def test_a_missing_account_is_none_rather_than_an_error(session: Any) -> None:
    """UC-1's `ACCOUNT_MISSING`, against a database that really does not have it."""
    assert session.describe_user("acme_no_such_user") is None


def test_the_effective_limit_is_resolved_and_never_the_word_default(account: Any) -> None:
    """`DBA_PROFILES` answers the string `DEFAULT` for an unset resource, so the
    join in `PROFILE_QUERY` is what stands between a caller and a lockout
    threshold that reads `DEFAULT`."""
    state = account.describe_user(ACCOUNT)

    assert state is not None
    assert state.failed_login_limit == "5", "set on the profile, so its own value"


def test_a_rotation_opens_a_rollover_window_the_status_reports(account: Any) -> None:
    """The finding this module rests on.

    No `DBA_*` column mentions rollover — the dictionary was searched. What says
    so is `ACCOUNT_STATUS`, which becomes `OPEN & IN ROLLOVER` the moment the
    password changes on a profile with `PASSWORD_ROLLOVER_TIME` set.
    """
    before = account.describe_user(ACCOUNT)
    assert before is not None
    assert before.rollover_active is False

    _run(account, f'alter user {ACCOUNT} identified by "{SECOND}"')

    after = account.describe_user(ACCOUNT)
    assert after is not None
    assert after.rollover_active is True, f"status was {after.status!r}"
    assert "IN ROLLOVER" in after.status

    # #181 reversed #178's placeholder here. The dictionary still does not say
    # when the window closes -- that was measured, not assumed -- so the value is
    # derived from the change date and the profile's rollover time, and it must
    # land after the rotation that opened the window.
    assert after.rollover_ends_at is not None
    assert after.password_changed_at is not None
    assert after.rollover_ends_at > after.password_changed_at


def test_a_locked_account_is_locked_without_losing_its_status(account: Any) -> None:
    """UC-1 §7 mitigation 6: `LOCKED` is its own state rather than one more way
    to get `ORA-01017`."""
    _run(account, f"alter user {ACCOUNT} account lock")

    state = account.describe_user(ACCOUNT)

    assert state is not None
    assert state.locked is True
    assert "LOCKED" in state.status


def test_the_status_stays_compound_when_two_things_are_true(account: Any) -> None:
    """`EXPIRED & LOCKED` is one column carrying two facts, which is why the
    flags are read as tokens rather than by comparing the whole string."""
    _run(
        account,
        f"alter user {ACCOUNT} password expire",
        f"alter user {ACCOUNT} account lock",
    )

    state = account.describe_user(ACCOUNT)

    assert state is not None
    assert state.locked is True
    assert state.expired is True
    assert "&" in state.status


def test_password_change_date_tracks_a_rotation(account: Any) -> None:
    """#87 is open about where the value comes from on 11.2, not about whether it
    means anything on a release that has the column.

    The assertion is a strict ``>``, and the sleep is what earns it. The column
    has second granularity, so two rotations in the same second are equal — and
    an implementation that always returned the account's original timestamp would
    satisfy ``>=`` while pinning nothing at all.
    """
    before = account.describe_user(ACCOUNT)
    assert before is not None
    assert before.password_changed_at is not None

    time.sleep(1.1)
    _run(account, f'alter user {ACCOUNT} identified by "{SECOND}"')

    after = account.describe_user(ACCOUNT)
    assert after is not None
    assert after.password_changed_at is not None
    assert after.password_changed_at > before.password_changed_at


def test_a_role_held_through_another_role_is_still_found(account: Any) -> None:
    """Guardrail 4's hole, closed and pinned.

    An account granted a site role that itself holds ``DBA`` holds ``DBA``. A
    flat read of `DBA_ROLE_PRIVS` sees only `ACME_APP_ADMIN` and reports nothing
    the guardrail refuses, so the account passes — measured on 26ai before the
    query was changed, which is how this was confirmed rather than argued.
    """
    _run(
        account,
        f"create role {SITE_ROLE}",
        f"grant dba to {SITE_ROLE}",
        f"grant {SITE_ROLE} to {ACCOUNT}",
    )
    try:
        state = account.describe_user(ACCOUNT)

        assert state is not None
        assert SITE_ROLE.upper() in state.roles, "the directly granted role"
        assert "DBA" in state.roles, "and the one it is holding on the account's behalf"
    finally:
        with contextlib.suppress(Exception):
            _run(account, f"drop role {SITE_ROLE}")


def test_oracle_refuses_to_build_a_role_cycle_at_all(account: Any) -> None:
    """Why `NOCYCLE` is defensive rather than load-bearing.

    The first version of this test tried to build a cycle and assert the
    traversal survived it. It cannot: Oracle rejects the second grant outright
    with `ORA-01934`, so the role graph is acyclic by construction and
    `CONNECT BY` has nothing to loop on. Pinned as the refusal it actually is,
    because the wrong version of this test passed locally for the wrong reason —
    the error was scrolling past under `feedback off` while a traversal of `DBA`
    returned plenty of rows and looked like success.
    """
    _run(account, f"create role {LOOP_A}", f"create role {LOOP_B}")
    try:
        _run(account, f"grant {LOOP_A} to {LOOP_B}")

        with pytest.raises(Exception, match="ORA-01934"):
            _run(account, f"grant {LOOP_B} to {LOOP_A}")
    finally:
        for role in (LOOP_A, LOOP_B):
            with contextlib.suppress(Exception):
                _run(account, f"drop role {role}")


def test_the_effective_rollover_time_is_carried(account: Any) -> None:
    """#181 reads this at plan time. One query already resolved it, so reading it
    again from a second, uncoordinated one would be a second chance to disagree
    about the same profile."""
    state = account.describe_user(ACCOUNT)

    assert state is not None
    assert state.rollover_time == "1", "set on the profile"
    assert state.password_reuse_max == "UNLIMITED", "unset, so resolved from DEFAULT"


# --------------------------------------------------------- the grace period ---


GRACE_ACCOUNT = "acme_grace_user"
GRACE_PROFILE = "acme_grace_prof"
GRACE_PASSWORD = "Grace-Pass-3x"

#: One minute, as a fraction of a day. Short enough that a test can outlive it,
#: long enough that the account is not already expired when it is created --
#: Oracle sets `EXPIRY_DATE` at creation, so a zero life time would race the
#: fixture rather than the assertion.
ONE_MINUTE = "1/1440"


@pytest.fixture
def grace_account(session: Any) -> Iterator[Any]:
    """An account whose password is past its life time and inside its grace window.

    **The wait is real and there is no way around it.** `PASSWORD_LIFE_TIME` is
    the only thing that puts an account into `EXPIRED(GRACE)`, its resolution is
    the minute, and no `ALTER` reaches the state directly -- `PASSWORD EXPIRE`
    produces a *hard* `EXPIRED`, which is the state this one has to be
    distinguished from. So the test costs a minute, which is why there is one
    fixture and several assertions over it rather than one each.

    The move into grace happens **at a login**, not at the deadline: the status
    stays `OPEN` until something authenticates and Oracle notices. That login is
    part of the setup rather than the subject.
    """
    _drop_grace(session)
    _run(
        session,
        f"create profile {GRACE_PROFILE} limit "
        f"password_life_time {ONE_MINUTE} password_grace_time 1 "
        f"failed_login_attempts unlimited password_reuse_max unlimited "
        f"password_reuse_time unlimited password_verify_function null",
        f'create user {GRACE_ACCOUNT} identified by "{GRACE_PASSWORD}" profile {GRACE_PROFILE}',
        f"grant create session to {GRACE_ACCOUNT}",
    )
    try:
        _wait_past_expiry(session)
        _touch(session)
        yield session
    finally:
        _drop_grace(session)


def _drop_grace(session: Any) -> None:
    for statement in (
        f"drop user {GRACE_ACCOUNT} cascade",
        f"drop profile {GRACE_PROFILE} cascade",
    ):
        with contextlib.suppress(Exception):
            _run(session, statement)


def _wait_past_expiry(session: Any, *, limit: float = 180.0) -> None:
    """Until the database says the life time has elapsed, asked of the database.

    `sysdate > expiry_date` rather than a client-side sleep of the same length:
    the container's clock is the one the profile is measured against, and a test
    that slept locally would be asserting on this machine's.
    """
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        state = session.describe_user(GRACE_ACCOUNT)
        assert state is not None
        if state.password_expires_at is not None and _elapsed(session):
            return
        time.sleep(5)
    pytest.fail(f"{GRACE_ACCOUNT} did not pass its password life time within {limit}s")


def _elapsed(session: Any) -> bool:
    with session.connection.cursor() as cursor:
        cursor.execute(
            "select case when sysdate > expiry_date then 1 else 0 end "
            "from dba_users where username = :name",
            {"name": GRACE_ACCOUNT.upper()},
        )
        row = cursor.fetchone()
    return bool(row and row[0])


def _touch(session: Any) -> None:
    """One login as the account, which is what moves the status into grace."""
    session.verify_password(GRACE_ACCOUNT.upper(), Secret(GRACE_PASSWORD))


def test_a_password_in_its_grace_period_is_not_read_as_expired(grace_account: Any) -> None:
    """#309, against the database rather than against a string a test wrote.

    `EXPIRED(GRACE)` carries the token `EXPIRED`, and reading the two as one
    made `check` report a working account as expired and skip the login that
    would have proved otherwise.
    """
    state = grace_account.describe_user(GRACE_ACCOUNT)

    assert state is not None
    assert state.status == "EXPIRED(GRACE)", "the spelling this whole fix turns on"
    assert state.in_grace is True
    assert state.expired is False, "the password still works; it is on notice"
    assert state.locked is False


def test_the_grace_window_has_an_end_the_dictionary_reports(grace_account: Any) -> None:
    """`EXPIRY_DATE` during a grace period is the end of the *window*, which is
    the deadline the warning quotes. Without it the warning can say that a
    password is expiring but not when, which is most of its value gone."""
    state = grace_account.describe_user(GRACE_ACCOUNT)

    assert state is not None
    assert state.password_expires_at is not None
    assert grace_warning(state) is not None


def test_the_password_still_authenticates_during_the_grace_period(grace_account: Any) -> None:
    """The fact the whole decision rests on, and the one a status column cannot
    prove on its own. If this ever came back `fail`, reporting `IN_SYNC` for an
    account in grace would be wrong and #309 would need reopening."""
    result = grace_account.verify_password(GRACE_ACCOUNT.upper(), Secret(GRACE_PASSWORD))

    assert result.result == PASS


def test_a_locked_account_in_its_grace_period_is_still_locked(grace_account: Any) -> None:
    """The compound form, and the reason the fix is safe: every locked spelling
    carries `LOCKED`, and every caller tests `locked` before `expired`."""
    _run(grace_account, f"alter user {GRACE_ACCOUNT} account lock")

    state = grace_account.describe_user(GRACE_ACCOUNT)

    assert state is not None
    assert state.status == "EXPIRED(GRACE) & LOCKED"
    assert state.locked is True
    assert state.in_grace is True
    assert state.expired is False


def test_setting_a_password_clears_the_grace_period(grace_account: Any) -> None:
    """Why `apply` is the remedy the warning implies. Oracle clears the expiry
    when a password is set -- that is its behaviour and not a choice this tool
    makes (UC-1 §5) -- so the window closes without any statement aimed at it."""
    grace_account.set_password(GRACE_ACCOUNT.upper(), Secret(SECOND))

    state = grace_account.describe_user(GRACE_ACCOUNT)

    assert state is not None
    assert state.in_grace is False
    assert state.expired is False
    assert "EXPIRED" not in state.status

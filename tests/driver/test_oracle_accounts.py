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
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target
from sopuli.driver.protocol import Credential
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
    assert after.rollover_ends_at is None, "the dictionary does not say when it closes"


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

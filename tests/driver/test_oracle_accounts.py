"""Reading an account's state against a real Oracle. Tier 1.

The mapping is tier 0 (`test_accounts.py`). What only a server can answer is
whether the *shapes* are what this code believes: that `ACCOUNT_STATUS` really
does carry `IN ROLLOVER` after a rotation, that `DBA_PROFILES` really does answer
`DEFAULT` for a resource a profile does not set, and that the queries run at all.

Every one of those was measured before the code was written, and they are pinned
here so a future release changing one of them fails rather than drifts.

State is created and dropped by the tests rather than by recreating the
container (`04-testing.md` §4): per test, except the grace-period accounts,
which live for the module because reaching their state costs a minute. Names
come from the fictional vocabulary in `01-configuration.md`, so nothing here
resembles a real estate.
"""

from __future__ import annotations

import contextlib
import os
import time
from collections.abc import Iterator
from typing import Any

import pytest

from oracle_harness import Environment, decide_skip, execute
from sopuli.check import grace_warning
from sopuli.driver.guardrails import ADMIN_ROLES
from sopuli.driver.oracle.accounts import deliberately_locked
from sopuli.driver.protocol import OFFLINE_VERIFY, PASS, PASSWORD_ROLLOVER
from sopuli.secrets import Secret

USER = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")


ACCOUNT = "acme_orders_user"
PROFILE = "acme_orders_prof"
#: A second account for the password-file test, which must NOT be on `PROFILE`.
#: See :func:`password_file_account`.
PWFILE_ACCOUNT = "acme_pwfile_user"
SITE_ROLE = "acme_app_admin"
LOOP_A = "acme_loop_a"
LOOP_B = "acme_loop_b"
FIRST = "First-Pass-1x"
SECOND = "Second-Pass-2x"


def _run(session: Any, *statements: str) -> None:
    execute(session.connection, *statements)


@pytest.fixture
def account(session: Any) -> Iterator[Any]:
    """One account on a profile that sets two limits and leaves the rest unset.

    The unset ones are the point: they are what report `DEFAULT`, and what
    `PROFILE_QUERY` has to resolve.

    **`PASSWORD_ROLLOVER_TIME` is only in the profile where the server has it.**
    Below 19.12 the resource does not exist and `CREATE PROFILE` is `ORA-02376:
    invalid or redundant resource`, which failed this fixture and errored eleven
    tests on 18c -- nine of which have nothing to do with rollover. The
    two that do declare `password_rollover` and skip with a reason, which is
    §3's rule; the profile follows the same capability rather than a version, so
    what is asked for is what the target said it supports.
    """
    _drop(session)
    limits = "failed_login_attempts 5"
    if PASSWORD_ROLLOVER in session.scope().capabilities:
        limits = f"password_rollover_time 1 {limits}"
    _run(
        session,
        f"create profile {PROFILE} limit {limits}",
        f'create user {ACCOUNT} identified by "{FIRST}" profile {PROFILE}',
        f"grant create session to {ACCOUNT}",
        f"grant connect to {ACCOUNT}",
    )
    try:
        yield session
    finally:
        _drop(session)


def _drop(session: Any) -> None:
    # `SYSDBA` needs no separate revoke here, which was measured rather than
    # assumed: dropping an account that holds it takes its row out of
    # `V$PWFILE_USERS` too. A suppressed `revoke` beside these would fail with
    # `ORA-01031` on this connection anyway, and would read as cleanup that is
    # not happening.
    for statement in (f"drop user {ACCOUNT} cascade", f"drop profile {PROFILE} cascade"):
        # Absent is the desired state, so "it was not there" is a success.
        with contextlib.suppress(Exception):
            _run(session, statement)


def test_an_account_is_described_from_the_baseline_grant_set(account: Any) -> None:
    """`check` needs no site-specific grant, so everything here is on the
    documented set — and in particular not `SYS.USER$`."""
    state = account.describe_user(ACCOUNT)

    assert state is not None
    assert state.name == ACCOUNT.upper(), "the spelling the database gave back"
    assert state.status == "OPEN"
    assert not state.locked
    assert not state.expired
    assert state.profile == PROFILE.upper()
    # `False` where the release has the column and `None` where it has not.
    # `ORACLE_MAINTAINED` arrived in 12.1, so 11.2 answers neither -- and that
    # `None` is load-bearing rather than a gap: guardrail check 5's literal deny
    # list is consulted only where check 2 could not answer, and reading a
    # missing column as "not vendor-maintained" would switch it off.
    assert state.vendor_maintained is not True, "a site-created account either way"
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


@pytest.mark.requires_capability(PASSWORD_ROLLOVER)
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

    # The dictionary does not say when the window closes -- that was measured,
    # not assumed -- so the value is derived from the change date and the
    # profile's rollover time, and it must land after the rotation that opened
    # the window.
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
    """Password age is read from the vault's ``rotated_at`` (Q9), not from this
    column. What this pins is that the column means something on a release that
    has it.

    The assertion is a strict ``>``, and the sleep is what earns it. The column
    has second granularity, so two rotations in the same second are equal — and
    an implementation that always returned the account's original timestamp would
    satisfy ``>=`` while pinning nothing at all.

    **Skipped where the release has no column to read**, on the account's own
    answer rather than on a version. `DBA_USERS.PASSWORD_CHANGE_DATE` arrived in
    19c: 23.26.2.0.0 and 21.3.0.0.0 have it, 18.4.0.0.0 and 11.2.0.2.0 do not
    (`docs/measurements.md` has the full list). Note that `ORACLE_MAINTAINED`
    does *not* travel with it, which is what `_user_row`'s three shapes exist
    for. The account was created moments ago by the fixture, so a release that
    has the column has already filled it; `None` here can only mean the column
    is absent, which makes this a reading and not a version test.

    There is deliberately no capability for it, and decision #386 says there will
    not be: the query is its own probe. Where the column is absent the driver
    reads ``SYS.USER$.PTIME`` instead, if the grant exists, which the tests after
    this one pin.
    """
    before = account.describe_user(ACCOUNT)
    assert before is not None
    if before.password_changed_at is None:
        pytest.skip("this release has no DBA_USERS.PASSWORD_CHANGE_DATE to track")

    time.sleep(1.1)
    _run(account, f'alter user {ACCOUNT} identified by "{SECOND}"')

    after = account.describe_user(ACCOUNT)
    assert after is not None
    assert after.password_changed_at is not None
    assert after.password_changed_at > before.password_changed_at


# --------------------------------------- the PTIME fallback (decision #386) ---


def _has_change_date_column(session: Any) -> bool:
    """Whether this release has `DBA_USERS.PASSWORD_CHANGE_DATE`, asked of the
    server -- `ORA-00904` is the answer, exactly as the driver reads it."""
    capabilities = pytest.importorskip("sopuli.driver.oracle.capabilities")
    with session.connection.cursor() as cursor:
        found = capabilities.read(
            cursor, "select password_change_date from dba_users where rownum = 1"
        )
    return found is not None


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_ptime_is_the_same_clock_as_password_change_date(account: Any) -> None:
    """**The measurement decision #386 rests on, pinned** -- and the guard against
    the fallback becoming a second opinion.

    Only meaningful where both sources exist, so it skips on 18c and 11.2 on the
    server's own answer. On every release that has both it asserts equality to
    the second, after a rotation, so a release where the two part fails here
    rather than reporting a wrong date on the releases below it.
    """
    if not _has_change_date_column(account):
        pytest.skip("this release has no DBA_USERS.PASSWORD_CHANGE_DATE to compare PTIME with")

    time.sleep(1.1)
    _run(account, f'alter user {ACCOUNT} identified by "{SECOND}"')

    with account.connection.cursor() as cursor:
        cursor.execute(
            "select u.password_change_date, s.ptime from dba_users u "
            "join sys.user$ s on s.name = u.username where u.username = :name",
            {"name": ACCOUNT.upper()},
        )
        column, ptime = cursor.fetchone()

    assert column is not None
    assert ptime == column


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_without_the_column_the_fallback_tracks_a_rotation(account: Any) -> None:
    """Decision #386: 18c reports what 21c reports natively.

    The same strict ``>`` and the same sleep as the test above it, for the same
    reason. Skipped where the column exists, because there the fallback is never
    consulted and this would be re-running that test under another name.
    """
    if _has_change_date_column(account):
        pytest.skip("this release has DBA_USERS.PASSWORD_CHANGE_DATE; PTIME is never read")

    before = account.describe_user(ACCOUNT)
    assert before is not None
    assert before.password_changed_at is not None, before.password_changed_unknown
    assert before.password_changed_unknown is None

    time.sleep(1.1)
    _run(account, f'alter user {ACCOUNT} identified by "{SECOND}"')

    after = account.describe_user(ACCOUNT)
    assert after is not None
    assert after.password_changed_at is not None
    assert after.password_changed_at > before.password_changed_at


def test_without_the_column_or_the_grant_the_date_is_absent_and_says_why(account: Any) -> None:
    """Decision #386: the fallback stays ``None`` without the grant.

    The suite's own account holds the grant (the init script makes it), so the
    absence is taken the way the session takes it: ``user_dollar`` is what the
    capability probe hands the driver, and ``False`` is what a session without
    the grant passes. Revoking it here instead would race release gate 4 in the
    same run.
    """
    if _has_change_date_column(account):
        pytest.skip("this release has DBA_USERS.PASSWORD_CHANGE_DATE; no grant is involved")
    accounts_module = pytest.importorskip("sopuli.driver.oracle.accounts")

    with account.connection.cursor() as cursor:
        state = accounts_module.login_state(cursor, ACCOUNT, user_dollar=False)

    assert state is not None
    assert state.password_changed_at is None
    assert state.password_changed_unknown is not None
    assert "SELECT ON SYS.USER$" in state.password_changed_unknown


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


@pytest.mark.requires_capability(PASSWORD_ROLLOVER)
def test_the_effective_rollover_time_is_carried(account: Any) -> None:
    """The rollover profile check reads this at plan time. One query already
    resolved it, so reading it again from a second, uncoordinated one would be a
    second chance to disagree about the same profile."""
    state = account.describe_user(ACCOUNT)

    assert state is not None
    assert state.rollover_time == "1", "set on the profile"
    assert state.password_reuse_max == "UNLIMITED", "unset, so resolved from DEFAULT"


# -------------------------------------------------------------- the password file ---
#
# Guardrail 3's input. Everything below was measured on 26ai Free 23.26.2.0.0;
# the tier-0 fixtures in `test_accounts.py` carry the same literals.


def test_an_ordinary_account_is_not_in_the_password_file(account: Any) -> None:
    """`False`, and specifically not `None`.

    This connection can read `V$PWFILE_USERS` -- `system` holds
    `SELECT_CATALOG_ROLE` -- so the answer is an answer, which is what makes it
    the control for the two cases below.
    """
    state = account.describe_user(ACCOUNT)

    assert state is not None
    assert state.password_file_member is False


@pytest.fixture
def password_file_account(session: Any) -> Iterator[Any]:
    """An ordinary account on the `DEFAULT` profile, for the `SYSDBA` test.

    Deliberately **not** the `account` fixture, and not on `PROFILE`, which sets
    `PASSWORD_ROLLOVER_TIME` for the tests about rollover reporting. Granting
    `SYSDBA` to an account whose profile sets that limit is refused on 21c with
    `ORA-28227: Gradual password rollover is not supported for administrative
    users`, and allowed on 26ai -- measured on 21.3.0.0.0 and 23.26.2.0.0.

    The dependency is incidental: what this test needs is an account an operator
    would have made, and rollover has nothing to do with the password file. So
    it gets its own rather than a version guard, and the difference is recorded
    in `docs/design/02-oracle-privileges.md` §2's `V$PWFILE_USERS` subsection --
    where it is a fact about the password file and about profiles, rather than
    about this fixture.

    The `alter user ... profile` route reaches the same state on 21c and is not
    used here for the same reason: it would preserve a coupling this test never
    needed.

    Skipped outside a PDB, on the scope the *driver observed* rather than on a
    version -- the same shape as `test_oracle_doctor.py`'s root skip. What the
    test is about is a PDB-*local* account, and the root has no such thing:
    `grant sysdba` there is `ORA-65175, cannot grant SYSDBA privilege locally in
    the root` (measured on the 21c root, 2026-09-08). CI's lane is a PDB, so
    this still runs on every pull request.
    """
    scope = session.scope()
    if scope.type != "pdb":
        pytest.skip(f"a PDB-local account needs a PDB session; this one is {scope.type}")
    with contextlib.suppress(Exception):
        _run(session, f"drop user {PWFILE_ACCOUNT} cascade")
    _run(
        session,
        f'create user {PWFILE_ACCOUNT} identified by "{FIRST}"',
        f"grant create session to {PWFILE_ACCOUNT}",
        f"grant connect to {PWFILE_ACCOUNT}",
    )
    try:
        yield session
    finally:
        with contextlib.suppress(Exception):
            _run(session, f"drop user {PWFILE_ACCOUNT} cascade")


def test_a_pdb_local_account_granted_sysdba_appears_in_the_password_file(
    password_file_account: Any, sysdba: Any
) -> None:
    """The account guardrail 3 exists for, and the one checks 2, 4 and 5 miss.

    Measured here rather than assumed, because the obvious reasoning gets it
    wrong twice over: a *local* account in a PDB does land in `V$PWFILE_USERS`
    (with its own `CON_ID`, and visible from `CDB$ROOT` as well), and it does so
    while reading `ORACLE_MAINTAINED = 'N'` and holding no roles. So this is a
    site-created application account that every other §4 check passes, and without
    guardrail 3 the tool would rotate it.

    `SYSDBA` is granted and revoked inside one test, over a `SYS AS SYSDBA`
    connection because `system` is refused it (`ORA-01031`, measured). No
    teardown is needed beyond the fixture's own `drop user`: dropping an account
    that holds `SYSDBA` takes its row out of `V$PWFILE_USERS` as well, which was
    measured rather than assumed.
    """
    execute(sysdba, f"grant sysdba to {PWFILE_ACCOUNT}")
    try:
        state = password_file_account.describe_user(PWFILE_ACCOUNT)

        assert state is not None
        assert state.password_file_member is True
        # The three checks that do not catch it, asserted alongside so the claim
        # above is measured rather than asserted in prose.
        assert state.vendor_maintained is False
        assert not ADMIN_ROLES & state.roles
    finally:
        execute(sysdba, f"revoke sysdba from {PWFILE_ACCOUNT}")

    after = password_file_account.describe_user(PWFILE_ACCOUNT)
    assert after is not None
    assert after.password_file_member is False, "the revoke takes it back out of the view"


# --------------------------------------------------------- the grace period ---


GRACE_PROFILE = "acme_grace_prof"
GRACE_PASSWORD = "Grace-Pass-3x"
#: One account per test that takes :func:`grace_account`. Two of the tests change
#: their account, one by locking it and one by setting a password, so a shared
#: account would make each result depend on the order the tests ran in. A new
#: test of the grace period needs a new name here.
GRACE_ACCOUNTS = tuple(f"acme_grace{n}_user" for n in range(1, 7))

#: One minute, as a fraction of a day. Short enough that a test can outlive it,
#: long enough that the account is not already expired when it is created --
#: Oracle sets `EXPIRY_DATE` at creation, so a zero life time would race the
#: fixture rather than the assertion.
ONE_MINUTE = "1/1440"


@pytest.fixture(scope="module")
def _grace_pool(oracle_target: Environment) -> Iterator[list[str]]:
    """Accounts whose passwords are past their life time and inside the grace window.

    **The wait is real and there is no way around it.** `PASSWORD_LIFE_TIME` is
    the only thing that puts an account into `EXPIRED(GRACE)`, its resolution is
    the minute, and no `ALTER` reaches the state directly -- `PASSWORD EXPIRE`
    produces a *hard* `EXPIRED`, which is the state this one has to be
    distinguished from. So the module waits once, for every account at the same
    time, and each test takes an account of its own from the pool.

    The move into grace happens **at a login**, not at the deadline: the status
    stays `OPEN` until something authenticates and Oracle notices. That login is
    part of the setup rather than the subject.

    Module-scoped, so it is set up before the per-test `live_oracle` fixture that
    reports a missing database. Without a database it yields an empty pool and
    connects to nothing, and :func:`grace_account` then skips, or fails under
    `SOPULI_TEST_TIER1=required`, through `live_oracle`. The connection is raw
    `oracledb` because the driver's `session` fixture is per test.
    """
    if decide_skip(oracle_target) is not None:
        yield []
        return
    oracledb = pytest.importorskip("oracledb")
    pytest.importorskip("sopuli.driver.oracle.session").initialise(env=os.environ)
    connection = oracledb.connect(user=USER, password=PASSWORD, dsn=oracle_target.dsn)
    try:
        _drop_grace(connection)
        execute(
            connection,
            f"create profile {GRACE_PROFILE} limit "
            f"password_life_time {ONE_MINUTE} password_grace_time 1 "
            f"failed_login_attempts unlimited password_reuse_max unlimited "
            f"password_reuse_time unlimited password_verify_function null",
        )
        for name in GRACE_ACCOUNTS:
            execute(
                connection,
                f'create user {name} identified by "{GRACE_PASSWORD}" profile {GRACE_PROFILE}',
                f"grant create session to {name}",
            )
        _wait_past_expiry(connection)
        for name in GRACE_ACCOUNTS:
            oracledb.connect(user=name, password=GRACE_PASSWORD, dsn=oracle_target.dsn).close()
        yield list(GRACE_ACCOUNTS)
    finally:
        _drop_grace(connection)
        connection.close()


@pytest.fixture
def grace_account(live_oracle: Environment, _grace_pool: list[str]) -> str:
    """The name of an account in its grace period that no other test uses."""
    if not _grace_pool:
        pytest.fail("every grace-period account is taken; add a name to GRACE_ACCOUNTS")
    return _grace_pool.pop(0)


def _drop_grace(connection: Any) -> None:
    for statement in (
        *(f"drop user {name} cascade" for name in GRACE_ACCOUNTS),
        f"drop profile {GRACE_PROFILE} cascade",
    ):
        with contextlib.suppress(Exception):
            execute(connection, statement)


def _wait_past_expiry(connection: Any, *, limit: float = 180.0) -> None:
    """Until the database says every account's life time has elapsed.

    `sysdate > expiry_date` rather than a client-side sleep of the same length:
    the container's clock is the one the profile is measured against, and a test
    that slept locally would be asserting on this machine's.
    """
    names = ", ".join(f"'{name.upper()}'" for name in GRACE_ACCOUNTS)
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        with connection.cursor() as cursor:
            cursor.execute(
                "select count(*) from dba_users "
                f"where username in ({names}) and sysdate > expiry_date"
            )
            (elapsed,) = cursor.fetchone()
        if elapsed == len(GRACE_ACCOUNTS):
            return
        time.sleep(5)
    pytest.fail(f"the grace-period accounts did not pass their life time within {limit}s")


def test_a_password_in_its_grace_period_is_not_read_as_expired(
    session: Any, grace_account: str
) -> None:
    """`EXPIRED(GRACE)`, read from the database rather than from a string a test
    wrote.

    `EXPIRED(GRACE)` carries the token `EXPIRED`, and reading the two as one
    made `check` report a working account as expired and skip the login that
    would have proved otherwise.
    """
    state = session.describe_user(grace_account)

    assert state is not None
    assert state.status == "EXPIRED(GRACE)", "the spelling this whole fix turns on"
    assert state.in_grace is True
    assert state.expired is False, "the password still works; it is on notice"
    assert state.locked is False


def test_the_grace_window_has_an_end_the_dictionary_reports(
    session: Any, grace_account: str
) -> None:
    """`EXPIRY_DATE` during a grace period is the end of the *window*, which is
    the deadline the warning quotes. Without it the warning can say that a
    password is expiring but not when, which is most of its value gone."""
    state = session.describe_user(grace_account)

    assert state is not None
    assert state.password_expires_at is not None
    assert grace_warning(state) is not None


def test_the_password_still_authenticates_during_the_grace_period(
    session: Any, grace_account: str
) -> None:
    """The fact the whole decision rests on, and the one a status column cannot
    prove on its own. If this ever came back `fail`, reporting `IN_SYNC` for an
    account in grace would be wrong, and so would the grace reading."""
    result = session.verify_password(grace_account.upper(), Secret(GRACE_PASSWORD))

    assert result.result == PASS


def test_a_locked_account_in_its_grace_period_is_still_locked(
    session: Any, grace_account: str
) -> None:
    """The compound form, and the reason the fix is safe: every locked spelling
    carries `LOCKED`, and every caller tests `locked` before `expired`."""
    _run(session, f"alter user {grace_account} account lock")

    state = session.describe_user(grace_account)

    assert state is not None
    assert state.status == "EXPIRED(GRACE) & LOCKED"
    assert state.locked is True
    assert state.in_grace is True
    assert state.expired is False


def test_setting_a_password_clears_the_grace_period(session: Any, grace_account: str) -> None:
    """Why `apply` is the remedy the warning implies. Oracle clears the expiry
    when a password is set -- that is its behaviour and not a choice this tool
    makes (UC-1 §5) -- so the window closes without any statement aimed at it."""
    session.set_password(grace_account.upper(), Secret(SECOND))

    state = session.describe_user(grace_account)

    assert state is not None
    assert state.in_grace is False
    assert state.expired is False
    assert "EXPIRED" not in state.status


def test_a_grace_period_login_carries_the_servers_own_warning(
    session: Any, grace_account: str
) -> None:
    """The grace-period warning, against the thing that could not be reasoned about.

    A grace-period login **succeeds**, so nothing is raised and the diagnostic
    arrives on the connection instead. Discarding it would break CLAUDE.md's *never
    swallow an ORA- code* in the one place no exception makes it obvious.

    The code is asserted only as *present*, never matched: the same condition is
    `ORA-28098` where the profile limits `PASSWORD_GRACE_TIME` and `ORA-28011`
    where it does not, both on this release, and a test pinning one of them would
    fail on a profile rather than on a regression.
    """
    result = session.verify_password(grace_account.upper(), Secret(GRACE_PASSWORD))

    assert result.result == PASS, "the password is right; the warning is not a verdict"
    assert result.warning is not None
    assert "ORA-" in result.warning
    assert "\n" not in result.warning, "a warning is one line, rendered under a table"


def test_an_ordinary_login_carries_no_warning(account: Any) -> None:
    """The common case, and the reason the field is `None`-by-default: almost
    every login has nothing attached, and a report that said something about all
    of them would say nothing about any."""
    result = account.verify_password(ACCOUNT.upper(), Secret(FIRST))

    assert result.result == PASS
    assert result.warning is None


# ----------------------------------------------------- deliberately locked ---
#
# Tier 0: string parsing, no server. The compound forms below are the ones the
# module docstring measured on 26ai; what is asserted here is which of them mean
# *somebody locked this account* -- the question `account suspend` and H4's
# refusal both turn on.


@pytest.mark.parametrize(
    "status",
    [
        "LOCKED",
        "EXPIRED & LOCKED",
        "LOCKED & IN ROLLOVER",
        "EXPIRED & LOCKED & IN ROLLOVER",
        "EXPIRED(GRACE) & LOCKED",
        "locked",
    ],
)
def test_a_deliberate_lock_is_recognised_in_every_compound_form(status: str) -> None:
    """Equality against the whole string would miss all but the first."""
    assert deliberately_locked(status)


@pytest.mark.parametrize(
    "status",
    [
        "LOCKED(TIMED)",
        "EXPIRED(GRACE) & LOCKED(TIMED)",
        "EXPIRED & LOCKED(TIMED)",
        "OPEN",
        "EXPIRED",
        "EXPIRED(GRACE)",
        "OPEN & IN ROLLOVER",
        "",
    ],
)
def test_a_timed_lock_is_not_a_deliberate_one(status: str) -> None:
    """`LOCKED(TIMED)` contains `LOCKED`, so a substring test gets every one of
    the first three wrong -- which is the `EXPIRED(GRACE)` bug in the other
    field. A failed-login lock is not an offboarding."""
    assert not deliberately_locked(status)


# ------------------------------------- resolving a predicate the other way ---
#
# `account list` asks the mirror of the two questions above: not *what
# does this account carry* but *who carries this*. Both queries are measured
# here rather than reasoned about, because the transitive one has to agree with
# `ROLES_QUERY` above or the listing verb under-reports what a reset would
# accept.

LIST_PROFILE = "acme_listed_prof"
LIST_ROLE = "acme_listed_role"
LIST_PARENT_ROLE = "acme_listed_parent"
LIST_DIRECT = "acme_listed_direct"
LIST_INDIRECT = "acme_listed_indirect"


@pytest.fixture
def predicate_estate(session: Any) -> Iterator[Any]:
    """Two accounts, a profile, and a role held one step away from each.

    ``LIST_INDIRECT`` holds ``LIST_ROLE`` only through ``LIST_PARENT_ROLE``,
    which is the shape a flat `DBA_ROLE_PRIVS` read misses.
    """
    _run(
        session,
        f"create profile {LIST_PROFILE} limit password_life_time 90",
        f"create role {LIST_ROLE}",
        f"create role {LIST_PARENT_ROLE}",
        f"grant {LIST_ROLE} to {LIST_PARENT_ROLE}",
        f'create user {LIST_DIRECT} identified by "Aa1-listed-pw-0001" profile {LIST_PROFILE}',
        f'create user {LIST_INDIRECT} identified by "Aa1-listed-pw-0002"',
        f"grant {LIST_ROLE} to {LIST_DIRECT}",
        f"grant {LIST_PARENT_ROLE} to {LIST_INDIRECT}",
    )
    try:
        yield session
    finally:
        for statement in (
            f"drop user {LIST_DIRECT}",
            f"drop user {LIST_INDIRECT}",
            f"drop role {LIST_PARENT_ROLE}",
            f"drop role {LIST_ROLE}",
            f"drop profile {LIST_PROFILE}",
        ):
            with contextlib.suppress(Exception):
                _run(session, statement)


def test_a_profile_predicate_lists_the_accounts_carrying_it(predicate_estate: Any) -> None:
    found = predicate_estate.accounts_matching(profile=LIST_PROFILE)

    assert LIST_DIRECT.upper() in found
    assert LIST_INDIRECT.upper() not in found, "it is on DEFAULT"


def test_a_role_predicate_finds_the_account_holding_it_through_another(
    predicate_estate: Any,
) -> None:
    """The measurement this query exists for.

    ``admits()`` decides membership from the *traversed* role set, so a flat
    ``where granted_role = :role`` here would list only the direct holder — and
    `account list` would show an operator fewer accounts than a reset would
    accept, which is the one wrong answer a listing verb must not give.
    """
    found = predicate_estate.accounts_matching(role=LIST_ROLE)

    assert LIST_DIRECT.upper() in found, "the direct grant"
    assert LIST_INDIRECT.upper() in found, "and the one held through another role"


def test_the_listing_agrees_with_what_admits_would_say(predicate_estate: Any) -> None:
    """The two halves of H1's predicate, checked against each other on one estate.

    This is the assertion that keeps the listing verb and the mutating verb from
    disagreeing: every name the enumeration returns must be one `admits` accepts.
    """
    from sopuli.config.model import PersonalAccountRule
    from sopuli.personal import admits

    rule = PersonalAccountRule(role=LIST_ROLE)
    for name in predicate_estate.accounts_matching(role=LIST_ROLE):
        state = predicate_estate.describe_user(name)
        assert state is not None
        assert admits(rule, name, profile=state.profile, roles=state.roles), name


def test_a_role_predicate_lists_no_roles_only_accounts(predicate_estate: Any) -> None:
    """A role granted to a role is a grantee like any other, so the traversal
    returns both; the join to `DBA_USERS` is what keeps roles out of a listing of
    accounts."""
    found = predicate_estate.accounts_matching(role=LIST_ROLE)

    assert LIST_PARENT_ROLE.upper() not in found


def test_a_predicate_naming_nothing_is_distinguishable_from_one_matching_nothing(
    predicate_estate: Any,
) -> None:
    """UC-2 §2's asymmetry, and why `resolve_role` exists beside the enumeration:
    both cases are an empty list, so only asking separately tells them apart."""
    assert predicate_estate.resolve_role(LIST_ROLE) == LIST_ROLE.upper()
    assert predicate_estate.resolve_role("acme_no_such_role_at_all") is None
    assert predicate_estate.resolve_profile(LIST_PROFILE) == LIST_PROFILE.upper()
    assert predicate_estate.resolve_profile("acme_no_such_prof_at_all") is None

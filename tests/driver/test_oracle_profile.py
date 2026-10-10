"""Assigning a profile against a real Oracle. Tier 1.

The decision is tier 0 — `test_strategy.py` for whether a run would move an
account, `test_oracle_statements.py` for the statement. What only a server
answers is the pair this file exists for:

* **the dictionary's spelling.** A quoted identifier is case-sensitive, so
  `PROFILE "acme_app_prof"` names nothing on a database whose profile is
  `ACME_APP_PROF`. `resolve_profile` reads the name back out of `DBA_PROFILES`
  before it reaches a statement, which is `02-oracle-privileges.md` §4's rule
  about account names one object along;
* **that the move takes, and takes the profile's limits with it.** A profile
  decides whether a rollover window opens, which is why assigning one is not a
  cosmetic change and why `--strategy` refuses to be named across one.

Measured on 26ai Free 23.26.2.0.0 and 21c XE 21.3.0.0.0, and run on 18c XE
18.4.0.0.0.

**The destination profile is `SOPULI_REUSE`, not `SOPULI_ROLLOVER`**, for
everything except the one test that is about rollover limits. Both come from
`test/oracle-init/01_test_profiles.sql`, so the suite is not asserting against a
profile it invented in the same breath -- but that script cannot create
`SOPULI_ROLLOVER` below 19.12 and says so rather than aborting, so on 18c and
11g it is simply absent. A test that used it as "some other profile that
exists" would fail on 18c with `resolve_profile` answering `None`. What the tests
need is a second profile; only `test_the_move_carries_the_new_profiles_limits`
needs that profile to grant a rollover window, and it declares the capability.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from typing import Any

import pytest

from sopuli.driver.protocol import (
    ATTRIBUTE_SET,
    PASSWORD_ROLLOVER,
    AccountAttributes,
    DriverError,
)

ACCOUNT = "acme_profiled_user"

#: All three are created by `test/oracle-init/01_test_profiles.sql`, so the suite
#: is not asserting against a profile it invented in the same breath.
#:
#: `SOPULI_ROLLOVER` is the exception to that: below 19.12 the script cannot
#: create it, so it exists on 26ai and 21c and not on 18c or 11g. Only the test
#: that asserts on a rollover limit may name it, and that test declares
#: `password_rollover`. Everything else moves the account to `REUSE_PROFILE`,
#: which every version has.
ROLLOVER_PROFILE = "sopuli_rollover"
REUSE_PROFILE = "sopuli_reuse"
LOCKOUT_PROFILE = "sopuli_lockout"

LIVE = "Pr0filed-Pa55-word1"


def _run(session: Any, *statements: str) -> None:
    with session.connection.cursor() as cursor:
        for statement in statements:
            cursor.execute(statement)


def _drop(session: Any) -> None:
    with contextlib.suppress(Exception):
        _run(session, f"drop user {ACCOUNT} cascade")


@pytest.fixture
def account(session: Any) -> Iterator[Any]:
    """An account on the lockout profile, which grants no rollover window."""
    _drop(session)
    _run(session, f'create user {ACCOUNT} identified by "{LIVE}" profile {LOCKOUT_PROFILE}')
    try:
        yield session
    finally:
        _drop(session)


def _profile(session: Any) -> str | None:
    state = session.describe_user(ACCOUNT)
    assert state is not None
    return None if state.profile is None else str(state.profile)


# ------------------------------------------------------------- the spelling ---


def test_a_profile_is_resolved_to_the_dictionarys_spelling(session: Any) -> None:
    """Written lower-case in a file, upper-case in `DBA_PROFILES`, and it is the
    second that may reach a statement."""
    assert session.resolve_profile(REUSE_PROFILE) == REUSE_PROFILE.upper()
    assert session.resolve_profile(REUSE_PROFILE.upper()) == REUSE_PROFILE.upper()


def test_a_profile_this_database_has_not_got_is_none(session: Any) -> None:
    """A fact about this target, not a failure: which profiles exist varies from
    database to database, so the caller decides what it means."""
    assert session.resolve_profile("acme_no_such_prof") is None


# ------------------------------------------------------------ the assignment ---


def test_the_account_is_moved_to_the_declared_profile(account: Any) -> None:
    changes = account.apply_attributes(ACCOUNT, AccountAttributes(profile=REUSE_PROFILE))

    assert [change.attribute for change in changes] == [ATTRIBUTE_SET]
    assert changes[0].changed is True
    assert _profile(account) == REUSE_PROFILE.upper()


def test_the_detail_names_both_profiles(account: Any) -> None:
    """`attribute_set` is a kind two attributes share, so the detail is what says
    which one moved and where from."""
    changes = account.apply_attributes(ACCOUNT, AccountAttributes(profile=REUSE_PROFILE))

    assert changes[0].detail == f"profile {LOCKOUT_PROFILE.upper()} -> {REUSE_PROFILE.upper()}"


def test_an_account_already_on_the_profile_is_not_altered(account: Any) -> None:
    """Invariant 9, and the reason the driver reads the state first."""
    changes = account.apply_attributes(ACCOUNT, AccountAttributes(profile=LOCKOUT_PROFILE))

    assert changes[0].changed is False
    assert "already" in (changes[0].detail or "")


def test_a_second_assignment_reports_no_change(account: Any) -> None:
    first = account.apply_attributes(ACCOUNT, AccountAttributes(profile=REUSE_PROFILE))
    second = account.apply_attributes(ACCOUNT, AccountAttributes(profile=REUSE_PROFILE))

    assert first[0].changed is True
    assert second[0].changed is False


@pytest.mark.requires_capability(PASSWORD_ROLLOVER)
def test_the_move_carries_the_new_profiles_limits(account: Any) -> None:
    """The reason assigning a profile is not cosmetic: a profile decides whether
    `ALTER USER … IDENTIFIED BY` opens a rollover window, so the regime a rotation
    would run under changes with it. This is the fact `--strategy` refuses to be
    named across.

    The only test here that may name `ROLLOVER_PROFILE`, and the reason it
    declares the capability rather than the profile: below 19.12 there is no
    limit for the profile to carry, so there is nothing for this to assert. The
    absence is covered instead by `test_oracle_rollover.py` and by
    `creds apply --strategy rollover` refusing at plan time.
    """
    before = account.describe_user(ACCOUNT)
    assert before is not None
    assert not before.rollover_enabled

    account.apply_attributes(ACCOUNT, AccountAttributes(profile=ROLLOVER_PROFILE))

    after = account.describe_user(ACCOUNT)
    assert after is not None
    assert after.rollover_enabled


def test_a_profile_that_does_not_exist_is_refused_by_name(account: Any) -> None:
    """Not the server's `ORA-02380`: the message names the profile and says the
    tool will not create one, which is Q4's position where an operator meets it."""
    with pytest.raises(DriverError) as refused:
        account.apply_attributes(ACCOUNT, AccountAttributes(profile="acme_no_such_prof"))

    assert "acme_no_such_prof" in str(refused.value)
    assert _profile(account) == LOCKOUT_PROFILE.upper()


def test_a_missing_account_is_an_error_rather_than_a_silent_no_op(session: Any) -> None:
    with pytest.raises(DriverError):
        session.apply_attributes("acme_no_such_user", AccountAttributes(profile=REUSE_PROFILE))


def test_both_attributes_run_in_one_pass(account: Any) -> None:
    """One row each, in `ATTRIBUTE_KINDS` order, which is the order they are
    enforced -- the unlock first, because it is what makes the login that follows
    worth attempting."""
    _run(account, f"alter user {ACCOUNT} account lock")

    changes = account.apply_attributes(
        ACCOUNT, AccountAttributes(unlock=True, profile=REUSE_PROFILE)
    )

    assert [change.changed for change in changes] == [True, True]
    assert _profile(account) == REUSE_PROFILE.upper()

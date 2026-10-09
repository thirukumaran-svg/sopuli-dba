"""`02-oracle-privileges.md` §4, over constructed states.

Pure logic, so every case is reachable: an account in the password file, one
holding `DBA`, one on a version that cannot say whether it is vendor-maintained.
Reaching those against a real database would mean creating an account that
should not exist and granting it things it should not have.
"""

from __future__ import annotations

import pytest

from sopuli.driver.guardrails import (
    DECLARED,
    DENY_LIST,
    ORACLE_SUPPLIED,
    PASSWORD_FILE,
    PRIVILEGED_ROLE,
    VENDOR_MAINTAINED,
    Refusal,
    is_declared,
    review,
)
from sopuli.driver.protocol import UserState

#: What the file declares, in the spelling `01-configuration.md` uses.
DECLARED_SET = ("acme_web_user", "acme_batch_user", "dbsnmp")


def account(
    name: str = "ACME_WEB_USER",
    *,
    vendor_maintained: bool | None = False,
    password_file_member: bool | None = False,
    roles: frozenset[str] = frozenset(),
) -> UserState:
    return UserState(
        name=name,
        status="OPEN",
        vendor_maintained=vendor_maintained,
        password_file_member=password_file_member,
        roles=roles,
    )


def checks(state: UserState) -> set[str]:
    return {refusal.check for refusal in review(state, declared=DECLARED_SET).refusals}


# ------------------------------------------------------------- the ordinary ---


def test_a_declared_ordinary_account_is_permitted() -> None:
    assert review(account(), declared=DECLARED_SET).permitted


def test_the_two_sides_spell_an_account_differently_and_both_are_right() -> None:
    """`01-configuration.md` writes `acme_web_user`; Oracle stores
    `ACME_WEB_USER`, because an unquoted identifier is upper-cased on the way in.

    Comparing exactly would refuse every correctly-declared account on Oracle --
    a guardrail that fires only on its own users.
    """
    assert is_declared("ACME_WEB_USER", DECLARED_SET)
    assert is_declared("acme_web_user", ("ACME_WEB_USER",))
    assert not is_declared("ACME_OTHER_USER", DECLARED_SET)


# ------------------------------------------------------------- the refusals ---


def test_an_undeclared_account_is_refused() -> None:
    """Invariant 5. The config is the whitelist and a selector filters it."""
    assert checks(account("ACME_ROGUE_USER")) == {DECLARED}


def test_a_vendor_maintained_account_is_refused() -> None:
    assert checks(account("DBSNMP", vendor_maintained=True)) == {VENDOR_MAINTAINED}


def test_an_account_in_the_password_file_is_refused() -> None:
    assert checks(account("acme_web_user", password_file_member=True)) == {PASSWORD_FILE}


def test_an_account_holding_an_administrative_role_is_refused() -> None:
    refusals = review(account(roles=frozenset({"CONNECT", "DBA"})), declared=DECLARED_SET).refusals

    assert [refusal.check for refusal in refusals] == [PRIVILEGED_ROLE]
    assert "DBA" in refusals[0].reason
    assert "CONNECT" not in refusals[0].reason


def test_several_reasons_are_all_reported() -> None:
    """One refusal at a time would mean an operator clearing them one run at a
    time, which is four runs to find out the account was never declared."""
    assert checks(
        account("SYS", vendor_maintained=True, password_file_member=True, roles=frozenset({"DBA"}))
    ) == {DECLARED, VENDOR_MAINTAINED, PASSWORD_FILE, PRIVILEGED_ROLE}


# ------------------------------------------------------- the version gap (5) ---


def test_the_deny_list_covers_the_version_that_cannot_answer() -> None:
    """`vendor_maintained is None` means the column does not exist -- 11.2 --
    and that must not read as "no"."""
    assert checks(account("SYSTEM", vendor_maintained=None)) == {DECLARED, DENY_LIST}


def test_the_database_describing_itself_beats_our_list() -> None:
    """A name on the list, on a version that answers, and the answer is no.

    Site accounts do get called things like `SCOTT`. Where the database can say
    whether an account is its own, a list maintained by us must not overrule it —
    otherwise the list becomes a second whitelist nobody agreed to.
    """
    assert "SCOTT" in ORACLE_SUPPLIED
    assert checks(account("SCOTT", vendor_maintained=False)) == {DECLARED}


def test_the_deny_list_is_not_consulted_where_the_flag_says_no() -> None:
    assert DENY_LIST not in checks(account("dbsnmp", vendor_maintained=False))


# ------------------------------------------------------------------ --force ---


def test_force_clears_the_overridable_checks() -> None:
    """Decision P3's case: rotating `DBSNMP` is ordinary DBA work, and it is
    `ORACLE_MAINTAINED`. A tool with no override does not prevent that rotation
    -- it moves it to SQL*Plus, where nothing records it."""
    reviewed = review(account("dbsnmp", vendor_maintained=True), declared=DECLARED_SET, force=True)

    assert reviewed.permitted
    assert [refusal.check for refusal in reviewed.overridden] == [VENDOR_MAINTAINED]


def test_force_never_reaches_the_whitelist() -> None:
    """The half of decision P3 that is invariant 5: two deliberate acts, not one.

    `--force` alone will not rotate an account the file does not name, which is
    what keeps "unusual account, deliberately managed" distinguishable from
    "typo that happened to be forced past".
    """
    reviewed = review(
        account("SYS", vendor_maintained=True, roles=frozenset({"DBA"})),
        declared=DECLARED_SET,
        force=True,
    )

    assert not reviewed.permitted
    assert [refusal.check for refusal in reviewed.refusals] == [DECLARED]
    assert {refusal.check for refusal in reviewed.overridden} == {
        VENDOR_MAINTAINED,
        PRIVILEGED_ROLE,
    }


def test_an_override_survives_the_overriding() -> None:
    """§4 requires the override in the audit event and the JSON output, so a
    waived refusal has to outlive the waiving. A `--force` that merely returned
    "allowed" would leave the run document unable to say what was done on
    purpose."""
    reviewed = review(account("dbsnmp", vendor_maintained=True), declared=DECLARED_SET, force=True)

    assert reviewed.overridden
    assert reviewed.overridden[0].reason
    assert reviewed.overridden[0].account == "dbsnmp"


def test_nothing_is_overridden_when_force_was_not_asked_for() -> None:
    reviewed = review(account("dbsnmp", vendor_maintained=True), declared=DECLARED_SET)

    assert reviewed.overridden == ()
    assert not reviewed.permitted


@pytest.mark.parametrize("check", [VENDOR_MAINTAINED, PASSWORD_FILE, PRIVILEGED_ROLE, DENY_LIST])
def test_every_check_but_the_first_is_overridable(check: str) -> None:
    """The flag covers checks 2-5 only. Asserted per check rather than in
    prose, so a sixth guardrail has to choose a side deliberately."""
    assert Refusal(check, "ACME_WEB_USER", "…").overridable
    assert not Refusal(DECLARED, "ACME_WEB_USER", "…").overridable


# -------------------------------------------------- the third answer (§4.3) ---
#
# Refused, permitted, or *could not establish*. Check 3 is the only one that can
# produce the third today, and it produces it on essentially every estate:
# `V$PWFILE_USERS` is outside §2's grant set on purpose.


def test_an_unreadable_password_file_is_a_caveat_and_never_a_pass() -> None:
    """Guardrail 3's input is `None` when the view cannot be read.

    `if state.password_file_member:` would read `None` as *not a member*, and
    check 3 would never fire. Check 3 does not refuse on `None` -- it must not,
    or a correctly installed estate could apply nothing -- but the not-knowing is
    reported instead of being indistinguishable from a clean account.
    """
    reviewed = review(account(password_file_member=None), declared=DECLARED_SET)

    assert reviewed.permitted
    assert reviewed.refusals == ()
    assert [caveat.check for caveat in reviewed.caveats] == [PASSWORD_FILE]
    assert reviewed.caveats[0].account == "ACME_WEB_USER"
    assert "could not establish" in reviewed.caveats[0].reason


def test_an_answered_check_leaves_no_caveat() -> None:
    """Both answers, because only the absence of one is a caveat. A `False` that
    produced one would make the warning fire on the estates that took the grant,
    which is the reading that teaches people to filter it."""
    assert review(account(password_file_member=False), declared=DECLARED_SET).caveats == ()
    assert review(account(password_file_member=True), declared=DECLARED_SET).caveats == ()


def test_a_caveat_does_not_make_an_account_impermissible() -> None:
    """Stated separately from the reasons above, because it is the property every
    other verb depends on: `permitted` reads `refusals` and nothing else."""
    reviewed = review(account(password_file_member=None), declared=DECLARED_SET)

    assert reviewed.permitted is True


def test_a_caveat_survives_force() -> None:
    """`--force` waives an answer, and a caveat is the absence of one.

    Suppressing it under the flag would hide a missing grant from the one
    operator most likely to be reading what the guardrails did -- and would make
    the report of what this run established depend on a flag about what it was
    allowed to do.
    """
    reviewed = review(
        account("dbsnmp", vendor_maintained=True, password_file_member=None),
        declared=DECLARED_SET,
        force=True,
    )

    assert reviewed.permitted
    assert [refusal.check for refusal in reviewed.overridden] == [VENDOR_MAINTAINED]
    assert [caveat.check for caveat in reviewed.caveats] == [PASSWORD_FILE]


def test_a_caveat_rides_alongside_a_refusal_from_another_check() -> None:
    """The two are independent lists, and an account refused by check 4 with
    check 3 unreadable has both to report."""
    reviewed = review(
        account(password_file_member=None, roles=frozenset({"DBA"})), declared=DECLARED_SET
    )

    assert [refusal.check for refusal in reviewed.refusals] == [PRIVILEGED_ROLE]
    assert [caveat.check for caveat in reviewed.caveats] == [PASSWORD_FILE]

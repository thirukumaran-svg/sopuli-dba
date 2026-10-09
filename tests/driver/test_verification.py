"""The lockout guard, and what a login's outcome means. Tier 0.

UC-1 §7's arithmetic is pure, so it is tested here — and it is the arithmetic
that matters, because release gate 4 is an assertion about a number never
reaching a threshold.

Every code in this file was produced on 26ai Free 23.26.2.0.0 by locking,
expiring and mistyping against a real account. Two of them come out the opposite
way round from the obvious guess, and those two have their own tests saying so.
"""

from __future__ import annotations

import pytest

from sopuli.driver.oracle.verification import (
    ACCOUNT_LOCKED,
    DEFAULT_MARGIN,
    INVALID_CREDENTIALS,
    PASSWORD_EXPIRED,
    PASSWORD_IN_GRACE,
    VERIFICATION_CODES,
    is_verification_outcome,
    margin_reason,
    result_for,
    warning_detail,
)
from sopuli.driver.protocol import FAIL, PASS, UNAVAILABLE

# ------------------------------------------------------------- the margin ---


def test_a_clean_account_under_the_default_profile_is_attempted() -> None:
    assert margin_reason(0, "10") is None


def test_the_margin_is_measured_from_what_is_left() -> None:
    """`FAILED_LOGIN_ATTEMPTS 3` with the default margin of 2 allows exactly one
    attempt from clean, and none once a failure is recorded.

    That is the shape release gate 4 depends on: check a drifted account five
    times and it locks on the fourth without this, and never locks with it.
    """
    assert margin_reason(0, "3") is None
    assert margin_reason(1, "3") is not None
    assert margin_reason(2, "3") is not None


def test_a_refusal_says_what_it_cost() -> None:
    """Reported rather than merely returned: "we chose not to try" is a result,
    and a result with no reason is indistinguishable at 03:00 from a run that
    did nothing."""
    reason = margin_reason(1, "3")

    assert reason is not None
    assert "1 of 3" in reason
    assert "2-attempt margin" in reason


def test_a_second_attempt_is_budgeted_before_it_is_spent() -> None:
    """`--include-previous` is a second login against the same account.

    Mitigation 1 is one attempt per account per run, so a flag that checks the
    previous password too has to ask for the budget up front — restating the rule
    per *value checked* would quietly double the spend on the very counter the
    guard protects.
    """
    # Three attempts left of five: one more is fine, two would eat the margin.
    assert margin_reason(2, "5", attempts=1) is None
    assert margin_reason(2, "5", attempts=2) is not None

    # And with room to spare, the second attempt costs nothing.
    assert margin_reason(0, "5", attempts=2) is None


def test_an_unlimited_profile_has_nothing_to_guard() -> None:
    assert margin_reason(9999, "UNLIMITED") is None
    assert margin_reason(9999, "unlimited") is None


def test_an_absent_counter_does_not_block_the_attempt() -> None:
    """`SELECT ON SYS.USER$` is optional (decision P2), and `check` runs without
    a site-specific grant. So an unavailable guard is not a refusal — it is a
    thing the caller has to say out loud, which `verify_password` does in
    `detail`."""
    assert margin_reason(None, "3") is None


def test_an_unreadable_limit_refuses_rather_than_guesses() -> None:
    """A limit that is neither a count nor `UNLIMITED` is one this code does not
    understand, and a lockout threshold is the wrong thing to guess at."""
    reason = margin_reason(0, "SOMETHING_NEW")

    assert reason is not None
    assert "SOMETHING_NEW" in reason


def test_a_missing_limit_is_not_a_lockout() -> None:
    assert margin_reason(0, None) is None


@pytest.mark.parametrize("margin", [0, 1, 5])
def test_the_margin_is_configurable(margin: int) -> None:
    assert margin_reason(0, "10", margin=margin) is None
    assert margin_reason(10 - margin, "10", margin=margin) is not None


def test_the_default_margin_is_two() -> None:
    assert DEFAULT_MARGIN == 2


# ------------------------------------------------------- reading the answer ---


def test_a_successful_login_passes() -> None:
    assert result_for(None) == (PASS, None)


def test_a_wrong_password_is_drift_and_not_a_crash() -> None:
    """Exit 3, which is what makes `check` schedulable."""
    outcome, _ = result_for(INVALID_CREDENTIALS)

    assert outcome == FAIL


def test_an_expired_password_is_a_pass() -> None:
    """The one that reads backwards.

    Measured: `ORA-28001` comes back **only when the password is correct** — a
    wrong password against an expired account still answers `ORA-01017`. So the
    value matched, and what is wrong with the account is its expiry.

    Treating an error as a failed verification would report drift on every
    expired account in an estate and rotate all of them for no reason.
    """
    outcome, detail = result_for(PASSWORD_EXPIRED)

    assert outcome == PASS
    assert detail is not None
    assert "expired" in detail


def test_a_grace_period_password_is_a_pass() -> None:
    outcome, detail = result_for(PASSWORD_IN_GRACE)

    assert outcome == PASS
    assert detail is not None


def test_a_locked_account_cannot_be_verified_either_way() -> None:
    """The other one that reads backwards.

    Measured: a locked account answers `ORA-28000` whether the password is right
    or wrong. So nothing was learned about the password, and `unavailable` is the
    honest answer — `fail` would report drift on an account whose password may be
    perfectly correct, and drift is what starts a rotation.
    """
    outcome, detail = result_for(ACCOUNT_LOCKED)

    assert outcome == UNAVAILABLE
    assert detail is not None
    assert "locked" in detail


def test_an_unrecognised_code_is_unavailable_rather_than_failed() -> None:
    """Not knowing what happened is not the same as knowing the password is
    wrong, and only one of the two starts a rotation."""
    outcome, detail = result_for("ORA-12541")

    assert outcome == UNAVAILABLE
    assert detail is not None
    assert "ORA-12541" in detail


# ------------------------------------------- findings versus failures ---


@pytest.mark.parametrize("code", [None, *sorted(VERIFICATION_CODES)])
def test_a_verification_outcome_is_an_answer_about_the_password(code: str | None) -> None:
    assert is_verification_outcome(code)


@pytest.mark.parametrize(
    "code",
    [
        "ORA-12154",  # the connect identifier did not resolve
        "ORA-12541",  # no listener
        "ORA-28040",  # no logon protocol client and server can agree
        "ORA-01031",  # the account cannot even create a session
    ],
)
def test_a_failure_of_the_run_is_not_a_verification_outcome(code: str) -> None:
    """These say nothing about the password.

    Each has its own category and exit path already, and folding them into
    `unavailable` would let an unreachable target look like an
    account-level finding — a target nobody can reach reported as a target whose
    password could not be checked.
    """
    assert not is_verification_outcome(code)


def test_drift_carries_the_vendor_code_and_the_server_s_own_words() -> None:
    """CLAUDE.md: an ORA- code is never swallowed.

    A `check` that reports drift without saying what the server said leaves an
    operator comparing "it failed" against an audit trail that has the actual
    diagnostic in it.
    """
    outcome, detail = result_for(INVALID_CREDENTIALS, "invalid username/password; logon denied")

    assert outcome == FAIL
    assert detail is not None
    assert INVALID_CREDENTIALS in detail
    assert "logon denied" in detail


def test_a_detail_survives_a_server_that_said_nothing() -> None:
    outcome, detail = result_for(INVALID_CREDENTIALS)

    assert outcome == FAIL
    assert detail is not None
    assert INVALID_CREDENTIALS in detail


# ------------------------------------------- a warning on a login that worked ---
#
# A connection can carry a diagnostic without failing -- a grace-period login is
# the ordinary case -- and the driver reads it rather than discarding it.
# Measured on 26ai Free 23.26.2.0.0: `ORA-28098` where the profile limits
# PASSWORD_GRACE_TIME and `ORA-28011` where it does not, both on connections that
# succeeded.


def test_a_login_warning_keeps_the_servers_words_and_its_code() -> None:
    """CLAUDE.md's rule, in the one place no exception makes it obvious."""
    found = warning_detail(
        "ORA-28098",
        "ORA-28098: Profile limits PASSWORD_LIFE_TIME and PASSWORD_GRACE_TIME are not "
        "unlimited, password will expire within 1 days.",
    )

    assert "(ORA-28098)" in found
    assert "password will expire within 1 days" in found


def test_the_code_is_said_once() -> None:
    """`oracledb` returns a message that repeats its own code, so the verbatim
    text reads *(ORA-28098): ORA-28098: ...*. Tolerable in the `detail` of a
    failure; not in a line rendered under a table."""
    found = warning_detail("ORA-28098", "ORA-28098: password will expire within 1 days.")

    assert found.count("ORA-28098") == 1


def test_the_documentation_url_is_not_carried() -> None:
    """The client appends it on a second line. A notice is one line, beside other
    accounts' lines."""
    found = warning_detail(
        "ORA-28011",
        "ORA-28011: The password has expired.\nHelp: https://docs.oracle.com/x",
    )

    assert "\n" not in found
    assert "Help:" not in found
    assert "The password has expired." in found


def test_a_warning_with_no_message_still_names_the_code() -> None:
    """A code and nothing else is still worth reporting -- and `_detail` must not
    append a bare colon to it."""
    found = warning_detail("ORA-28011", None)

    assert found.endswith("(ORA-28011)")


def test_a_warning_with_no_code_is_trimmed_the_same_way() -> None:
    """A client can grow `Connection.warning` without putting a code on it, and
    the server's sentence is worth carrying either way.

    The first draft of this returned the message verbatim on that arm, so the
    documentation URL and its newline came back -- the very packaging the coded
    arm strips. One formatter, one rule.
    """
    found = warning_detail(None, "The password has expired.\nHelp: https://docs.oracle.com/x")

    assert found == "the server warned on this login: The password has expired."


def test_a_warning_with_neither_code_nor_message_still_says_something() -> None:
    """Reaching this means the client had a warning object and nothing readable
    on it. Saying so beats an empty string, which reads as no warning at all."""
    assert warning_detail(None, None) == "the server warned on this login"


@pytest.mark.parametrize("code", ["ORA-28098", "ORA-28011", "ORA-99999"])
def test_no_code_is_matched_against_a_list(code: str) -> None:
    """The same condition is two codes on one release depending on the profile, so
    a fixed list would have been wrong the day it was written. Every code formats;
    none is special."""
    assert code in warning_detail(code, "something the server said")

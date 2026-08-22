"""Deciding whether to try a login, and reading what came back (#180).

UC-1 §7's whole argument in one module: **a tool that locks production accounts
while checking them is worse than no tool.** Everything here exists to make the
attempt that never happens as reportable as the one that did.

Four behaviours were measured on 26ai Free 23.26.2.0.0 before any of this was
written, and two of them come out the opposite way round from the obvious guess.

**A wrong password is ``ORA-01017`` and takes ``LCOUNT`` up by one; a right one
puts it back to zero.** Mitigation 3 is therefore not code -- the database does
it -- which is what makes the happy path self-cleaning. Measured 0 -> 1 -> 2 on
two failures, then 0 on a success.

**A locked account answers ``ORA-28000`` whether the password is right or
wrong.** So a locked account cannot be verified at all, and the result is
``unavailable``. Calling it ``fail`` would report drift on an account whose
password may be perfectly correct, and drift is what makes a scheduler start a
rotation.

**An expired password answers ``ORA-28001`` only when the password is
correct** -- a wrong one still answers ``ORA-01017``. So ``ORA-28001`` is a
**pass**: the value matched, and what is wrong with the account is its expiry.
The obvious reading, that an error means verification failed, would report drift
on every expired account in an estate and rotate all of them for no reason.

**The margin is spent before the attempt, not after.** :func:`margin_reason`
answers with what it would cost, and a caller that gets a reason has already
decided not to try.

**The guard is sticky, and an operator needs to know it.** Once the margin is
breached every further attempt is refused, *including one carrying the correct
password* -- the guard cannot know a password is right without spending an
attempt to find out, and spending the last of the margin on a guess is the thing
it exists to prevent. On a tight profile the effect is stark: with
``FAILED_LOGIN_ATTEMPTS 3`` and the default margin of 2, a single drift makes the
account unverifiable by this tool until something else clears ``LCOUNT`` -- the
application logging in successfully, or an operator widening the margin
deliberately. `check` then reports ``skipped`` with the reason rather than a
verdict, which is the honest answer and not a failure.

That is UC-1 §7's trade taken at face value: an account nobody can verify is a
worse report and a better outcome than an account nobody can log into.
"""

from __future__ import annotations

from sopuli.driver.protocol import (
    FAIL,
    PASS,
    SKIPPED,
    UNAVAILABLE,
)

#: UC-1 §7 mitigation 2's default. Two attempts of headroom left untouched.
DEFAULT_MARGIN = 2

#: What ``FAILED_LOGIN_ATTEMPTS`` says when there is no lockout to guard against.
UNLIMITED = "UNLIMITED"

ACCOUNT_LOCKED = "ORA-28000"
PASSWORD_EXPIRED = "ORA-28001"
PASSWORD_IN_GRACE = "ORA-28002"
INVALID_CREDENTIALS = "ORA-01017"


def margin_reason(
    failed_logins: int | None,
    failed_login_limit: str | None,
    *,
    margin: int = DEFAULT_MARGIN,
    attempts: int = 1,
) -> str | None:
    """Why this run must not attempt a login, or ``None`` to go ahead.

    ``attempts`` is how many logins **this run intends against this account**,
    and it is a parameter rather than an assumed 1 because of what
    ``--include-previous`` does. Mitigation 1 says one attempt per account per
    run; a flag that checks the previous password too makes two, and restating
    the rule per *value checked* rather than per account would quietly double
    the spend on the counter the guard is protecting. Asking for the budget up
    front is what keeps the flag honest.

    Returns a sentence rather than a bool because it is reported: "we chose not
    to try" is a result (:data:`~sopuli.driver.protocol.SKIPPED`), and a result
    with no reason attached is indistinguishable at 03:00 from a run that did
    nothing.

    Two ways to have no guard, and they are not the same:

    * **``UNLIMITED``** -- there is no lockout on this profile, so there is
      nothing to protect and the attempt goes ahead.
    * **``failed_logins is None``** -- ``SELECT ON SYS.USER$`` was never granted
      (#86 made it optional), so the guard is *unavailable*. The attempt still
      goes ahead, because #86 also decided `check` runs without a
      site-specific grant -- but the caller is expected to say so plainly rather
      than let an absent guard look like a satisfied one.
    """
    if failed_login_limit is None or failed_login_limit.upper() == UNLIMITED:
        return None
    if failed_logins is None:
        return None

    try:
        limit = int(failed_login_limit)
    except ValueError:
        # A limit that is neither a number nor UNLIMITED is one this code does
        # not understand, and guessing at a lockout threshold is the wrong thing
        # to guess at. Refuse the attempt rather than spend an unknown budget.
        return (
            f"the profile's FAILED_LOGIN_ATTEMPTS is {failed_login_limit!r}, "
            "which is neither a count nor UNLIMITED"
        )

    remaining = limit - failed_logins
    if remaining - attempts < margin:
        return (
            f"{failed_logins} of {limit} failed logins are already recorded, "
            f"and {attempts} more would leave less than the {margin}-attempt margin"
        )
    return None


#: The codes that say something about **this password on this account**, and so
#: are answers rather than failures.
#:
#: Everything else a connection can raise -- ``ORA-12154`` for a DSN that does
#: not resolve, ``ORA-12541`` for a listener that is down, ``ORA-28040`` for a
#: logon protocol client and server cannot agree -- is a failure of the run and
#: is raised. Folding those into ``unavailable`` would let an unreachable target
#: look like an account-level finding, and #172 has already classified each of
#: them into its own category and exit path for exactly that reason.
VERIFICATION_CODES = frozenset(
    {INVALID_CREDENTIALS, ACCOUNT_LOCKED, PASSWORD_EXPIRED, PASSWORD_IN_GRACE}
)


def is_verification_outcome(code: str | None) -> bool:
    """Whether ``code`` is an answer about the password rather than a failure."""
    return code is None or code in VERIFICATION_CODES


def result_for(code: str | None, message: str | None = None) -> tuple[str, str | None]:
    """What a login attempt's outcome means, as ``(result, detail)``.

    ``code`` is ``None`` for a login that succeeded. Callers must have checked
    :func:`is_verification_outcome` first; anything else belongs to the run
    rather than to the password.

    **The vendor code travels with the answer**, including the ordinary
    wrong-password case. CLAUDE.md's rule is that an ORA- code is never
    swallowed, and a `check` that reports drift without saying what the server
    said leaves an operator comparing "it failed" against a trail that has the
    actual diagnostic in it.
    """
    if code is None:
        return PASS, None
    if code == PASSWORD_EXPIRED:
        return PASS, f"the password is correct and has expired ({code})"
    if code == PASSWORD_IN_GRACE:
        return PASS, f"the password is correct and is in its grace period ({code})"
    if code == INVALID_CREDENTIALS:
        return FAIL, _detail("the database rejected this password", code, message)
    if code == ACCOUNT_LOCKED:
        return UNAVAILABLE, _detail(
            "the account is locked, which it answers with whether or not the password is right",
            code,
            message,
        )
    # Defensive: a caller that skipped `is_verification_outcome`.
    return UNAVAILABLE, _detail("the login attempt failed", code, message)


def _detail(summary: str, code: str, message: str | None) -> str:
    """``summary (ORA-xxxxx): what the server said``, with the server's own
    wording preserved rather than rewritten (#172)."""
    text = f"{summary} ({code})"
    return f"{text}: {message}" if message else text


def skipped_detail(reason: str) -> str:
    """What a skipped verification says about itself."""
    return f"no login attempted: {reason}"


__all__ = [
    "ACCOUNT_LOCKED",
    "VERIFICATION_CODES",
    "DEFAULT_MARGIN",
    "INVALID_CREDENTIALS",
    "PASSWORD_EXPIRED",
    "PASSWORD_IN_GRACE",
    "SKIPPED",
    "UNLIMITED",
    "is_verification_outcome",
    "margin_reason",
    "result_for",
    "skipped_detail",
]

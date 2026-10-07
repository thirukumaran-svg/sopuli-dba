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

**A further behaviour was measured later, on 2026-09-02 and the same release,
and it contradicts one of the constants below.** A password in its grace period does
*not* answer with an error at all: the login **succeeds**, and the notice arrives
as ``connection.warning`` -- ``ORA-28098`` where the profile limits
``PASSWORD_GRACE_TIME``, ``ORA-28011`` where it does not. ``ORA-28002`` was not
produced in either shape.

**On 19.3.0.0.0 the code is the documented one, and the shape is the same**
(2026-09-28, #479, twice, thick mode): the login succeeds and
``connection.warning`` carries ``ORA-28002: the password will expire within 1
days``, on a profile that limits ``PASSWORD_GRACE_TIME``. 21c sends ``ORA-28002``
too, seen in SQL*Plus by ``09_reset_from_expired_probe.sql``, though not through
this driver. So which code arrives depends on the release, and *how* it arrives
did not change between 19.3 and 26ai: neither raises. :func:`warning_detail`
treats the code as data and formats either.

Two things follow, and neither is fixed here:

* :data:`PASSWORD_IN_GRACE` and its arm of :func:`result_for` are **unreachable
  on this release**. They are kept rather than deleted because the code is real
  and older lines are unmeasured (tier 2). The grace period is read from
  ``ACCOUNT_STATUS`` instead (below);
* :meth:`~sopuli.driver.oracle.session.OracleSession._attempt` returns
  ``connection.warning`` on a login that succeeds, and the CLI reports it as
  ``SOPULI-W014``. That carries the notice, but it is not a state.

The dependable signal for the grace period is ``DBA_USERS.ACCOUNT_STATUS``, which
says ``EXPIRED(GRACE)`` in both shapes and needs no login
(:mod:`sopuli.driver.oracle.accounts`).
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
#: **Unreachable as an exception on 26ai 23.26.2.0.0 and on 19.3.0.0.0** -- a
#: grace-period login succeeds and the notice arrives as ``connection.warning``:
#: ``ORA-28098`` or ``ORA-28011`` on 26ai, and this very code on 19.3, still as a
#: warning rather than raised. Kept because 18c and 11.2 are unmeasured, and 21c
#: only in SQL*Plus; see the module docstring, #309 and #322.
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


def warning_detail(code: str | None, message: str | None) -> str:
    """What the server said on a login that **succeeded** (#322).

    A connection can carry a diagnostic without failing: a password in its grace
    period connects and Oracle attaches the notice to the connection rather than
    raising. Nothing read it, so it was discarded on every path -- which is the
    rule CLAUDE.md states as *never swallow an ORA- code*, broken in the one place
    where no exception makes it obvious.

    **The code is data, not a branch.** :func:`result_for` above matches specific
    codes because each means a different verdict; there is no verdict to reach
    here -- the login worked -- so this formats whatever arrived and matches
    nothing. That is not laziness: the same condition is ``ORA-28098`` where a
    profile limits ``PASSWORD_GRACE_TIME`` and ``ORA-28011`` where it does not,
    both measured on 26ai, and a fixed list would have been wrong on the second
    the day it was written.

    **One line, and the code said once.** ``oracledb`` hands back a message that
    repeats its own code and appends a documentation URL on a second line, so the
    verbatim text through :func:`_detail` reads *the server warned on this login
    (ORA-28098): ORA-28098: ...* over two lines. That is tolerable in the
    ``detail`` of a failure, which is where :func:`result_for` puts it and where
    it has stayed since #172; it is not tolerable in a warning, which is rendered
    as a line under a table beside other accounts' lines. So the server's own
    sentence is kept and the two pieces of packaging around it are not -- the same
    trade :func:`sopuli.store.survey._first_line` makes, for the same reason.

    ``code`` is optional because a client can grow the attribute without putting
    a code on it, and the server's sentence is worth carrying either way. That
    case formats **here** rather than at the call site: a second spelling of this
    sentence is a second place for the one-line rule to be forgotten, which is
    exactly what happened to the first draft of it.
    """
    sentence = _sentence(code, message)
    summary = "the server warned on this login"
    if code is None:
        return f"{summary}: {sentence}" if sentence else summary
    return _detail(summary, code, sentence)


def _sentence(code: str | None, message: str | None) -> str | None:
    """The server's own sentence, without the code it already carries or the URL
    the client appended after it.

    First line only, unconditionally -- including when there is no ``code`` to
    strip, which is the arm that made this worth extracting.
    """
    if not message:
        return None
    first = message.splitlines()[0].strip()
    prefix = f"{code}:"
    if code is not None and first.startswith(prefix):
        return first[len(prefix) :].strip()
    return first


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
    "warning_detail",
    "UNLIMITED",
    "is_verification_outcome",
    "margin_reason",
    "result_for",
    "skipped_detail",
]

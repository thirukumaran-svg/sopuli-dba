"""What `creds finish-rollover` decides before it closes a window.

UC-1 §6.3 step 4: `ALTER USER … EXPIRE PASSWORD ROLLOVER PERIOD` ends a gradual
password rollover window early, so the old password stops authenticating before
the profile's `PASSWORD_ROLLOVER_TIME` elapses. S2 runs it as a follow-up job
once applications have had their grace period.

Pure, the way :mod:`sopuli.check`, :mod:`sopuli.generate` and :mod:`sopuli.apply`
are, and it borrows `check`'s state vocabulary for the same reason they do: the
four verbs describe one estate and must not give it two names.

**Closing a window is the destructive half of a rotation**, and it is the only
step in UC-1 whose whole purpose is to stop something from working. So most of
this module is the two accounts it refuses to close, and the distinction between
them is what decision #263 turned on.

**Under an open window a `pass` proves less than it usually does.** Both
passwords authenticate, so verifying the vault's `current` cannot tell "the
database has it" from "the database has the previous one and is accepting both"
-- which is the caveat `check` already reports as ``ROLLOVER_ACTIVE``. A **fail**
is conclusive, though, and it is the case worth spending a login on: if `current`
is refused *even with the window open*, then neither password in play is the one
applications fetch, and closing would leave nothing that authenticates.

**The gap a login cannot close is covered on the vault side, for free.** A staged
``pending`` means the rotation is unfinished -- `current` is still the *old*
password -- so closing the window would strand every application that has not
been given the new one. That is exactly the case a naive verification would have
passed and done the damage in, and it costs no attempt at all to see.

Two gates, then, and only one of them is a login:

1. a staged ``pending`` → ``PENDING_APPLY``, window left open;
2. the vault's ``current`` refused → ``DRIFT``, window left open, exit 3.
"""

from __future__ import annotations

from datetime import datetime

from sopuli.apply import Source
from sopuli.check import (
    ACCOUNT_MISSING,
    DRIFT,
    ERROR,
    EXPIRED,
    IN_SYNC,
    LOCKED,
    UNVERIFIABLE,
    Outcome,
)
from sopuli.clock import until
from sopuli.driver.protocol import EXPIRE_PASSWORD, FAIL, PASS, Scope, UserState, VerifyResult
from sopuli.payload import PENDING

__all__ = [
    "PENDING_APPLY",
    "SKIPPED",
    "closed",
    "decide",
    "remaining",
    "settled_before_closing",
]

#: A rotation this run must not finish: the vault has staged a password the
#: database has not been confirmed to hold. From the schema's own enum, which
#: UC-1 §3 put there for this situation exactly.
PENDING_APPLY = "PENDING_APPLY"

#: A window this build cannot close. Also the schema's, and the honest word: the
#: account was passed over, and the window will elapse on its own.
SKIPPED = "SKIPPED"


def settled_before_closing(
    user: UserState | None, source: Source | None, scope: Scope
) -> Outcome | None:
    """The outcome for an account whose window must not be closed, or ``None``.

    In this order, and the order is the argument :func:`sopuli.check.decide`
    makes about status outranking an attempt -- what the database says about the
    account is the *cause* of whatever a login would have seen. Every arm here
    leaves the window open, which is the reversible direction: a window nobody
    closed elapses on its own, and one closed in error cannot be reopened.

    * **No account.** ``ACCOUNT_MISSING``. Nothing to close and nothing to
      create (Q8).
    * **No window open.** ``IN_SYNC`` with ``changed: false`` -- invariant 9, and
      the ordinary answer for the scheduled job S2 describes, which mostly finds
      nothing to do. Measured on 23.26.2.0.0
      (`sql/oracle/07_lock_and_rollover_probe.sql`, step 3), issuing the statement
      anyway is accepted silently and changes nothing, so a run that just issued it
      would report a change every night.
    * **A database that is not open read-write.** ``ERROR``, exit 1. A physical
      standby cannot take the ``ALTER USER``, so it is refused here, before the
      login a close would otherwise spend and before a preview can promise a
      close that would fail. An **unknown** open mode is not refused, for
      :func:`~sopuli.driver.oracle.capabilities.require_read_write`'s reason.
    * **A locked or expired account.** Reported as itself. The window is beside
      the point for an account nothing can authenticate as, and closing it would
      be a mutation nobody asked for on an account already needing attention.
    * **A staged ``pending``.** ``PENDING_APPLY``: the rotation is unfinished, so
      the vault's `current` is the old password and closing the window would
      strand whatever has not been given the new one. **The one refusal that
      costs no login**, and the one a verification would have got wrong -- under
      an open window the old password passes.
    * **Nothing in the vault.** ``UNVERIFIABLE``. There is no password to check
      the database against, so nothing here can say the close is safe.
    * **No way to close it.** ``SKIPPED``, naming the capability. Not an error:
      a window this build cannot end early simply elapses on its own, which is
      what would have happened anyway.
    """
    if user is None:
        return Outcome(
            ACCOUNT_MISSING,
            "the config declares this account; the database has no such user",
        )
    if not user.rollover_active:
        return Outcome(IN_SYNC, "no rollover window is open")
    if scope.read_write is False:
        return Outcome(
            ERROR,
            f"the database is open {scope.open_mode or 'read-only'} and cannot end a "
            "window; point the target at the primary",
        )
    if user.locked or user.expired:
        return Outcome(
            LOCKED if user.locked else EXPIRED,
            f"account is {user.status.lower()}; the window was left open",
        )
    if source is not None and source.stage == PENDING:
        return Outcome(
            PENDING_APPLY,
            "the vault has a password staged that this database is not confirmed to "
            "hold, so `current` is still the old one -- run `sopuli creds apply` first",
        )
    if source is None:
        return Outcome(
            UNVERIFIABLE,
            "the vault holds no password for this account, so nothing can say "
            "closing the window is safe",
        )
    if not scope.supports(EXPIRE_PASSWORD):
        return Outcome(
            SKIPPED,
            f"this database cannot end a window early ({EXPIRE_PASSWORD}); "
            f"it will elapse on its own",
        )
    return None


def decide(verification: VerifyResult) -> Outcome | None:
    """Why the login says not to close, or ``None`` to go ahead.

    ``None`` on a **pass**, which is the weaker half of the answer and known to
    be: the window means both passwords authenticate, so this cannot prove the
    database has the vault's `current` rather than the one before it. What it can
    prove is the negative, and that is the one worth acting on.

    A **fail** is conclusive. Neither password in play is what applications
    fetch, so closing the window would leave nothing that authenticates --
    ``DRIFT``, exit 3, and the window stays open.

    A **declined or unavailable** attempt is ``UNVERIFIABLE`` and also leaves it
    open. The tool could not establish the one thing it spends a login on, and a
    destructive step taken on an answer nobody got is the failure this whole
    module is arranged to avoid.
    """
    if verification.result == PASS:
        return None
    if verification.result == FAIL:
        return Outcome(
            DRIFT,
            f"{_one_line(verification.detail) or 'the vault password was rejected'} "
            f"-- refused even with the window open, so it was left open",
            verification,
        )
    return Outcome(
        UNVERIFIABLE,
        _one_line(verification.detail) or "the attempt was declined; the window was left open",
        verification,
    )


def closed(user: UserState, verification: VerifyResult, *, now: datetime | None = None) -> Outcome:
    """The outcome for a window this run ended.

    ``IN_SYNC``, and the detail says **how early** rather than merely that it
    happened. That number is the one an operator is judged on afterwards: a
    window closed with four minutes left is a tidy-up, and one closed with
    fifty-five is a decision somebody made about an application's grace period.
    """
    left = remaining(user, now=now)
    if left is None:
        return Outcome(IN_SYNC, "rollover window closed", verification)
    return Outcome(IN_SYNC, f"rollover window closed, {left} early", verification)


def remaining(user: UserState, *, now: datetime | None = None) -> str | None:
    """How much of the window is left, as a short phrase, or ``None``.

    ``None`` where the end is not known -- ``rollover_ends_at`` is derived and
    only populated while a window is open, and on a release that reports no
    ``PASSWORD_ROLLOVER_TIME`` there is nothing to derive it from. Saying
    nothing is the right answer there; a zero would read as "it was about to
    close anyway", which is the opposite of not knowing.

    The arithmetic is :func:`sopuli.clock.until`, shared with `creds status` --
    it prints the same figure about the same window, to say what is still open
    rather than what was closed early.
    """
    return until(user.rollover_ends_at, now=now)


def _one_line(detail: str | None) -> str | None:
    """The first line of a driver's message. :func:`sopuli.check._one_line`'s rule."""
    if detail is None:
        return None
    lines = detail.splitlines()
    return lines[0] if lines else None

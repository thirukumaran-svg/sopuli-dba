"""What `creds check` concludes, given what the vault and the database said (#248).

One question per (account, target): does the vault's `current` password work
against this database? UC-1 §7's answer is a :data:`SyncState`, and this module is
where the three inputs -- the stored secret, the account as the database
describes it, and the verification attempt -- become one.

Pure, deliberately. Everything here is a function of values the caller already
holds, so the decision table can be tested without a container and without a
vault: the hard part of `check` is not connecting, it is what the answer *means*
when an account is locked and the password is also wrong.

Three things here are decisions rather than transcription:

**Lock, expiry and a missing account are their own states, not `DRIFT`.** UC-1
§7's mitigation 6 is the reason: a login attempt alone conflates an expired
password, an already-locked account and a genuinely wrong one behind the same
``ORA-01017``, so the account's status is read separately -- from ``DBA_USERS``,
which the baseline grant already covers -- and reported on its own terms.
Otherwise every one of those three tells an operator to go and look at the vault,
and two of them would be sending them to the wrong place.

**Status outranks the verification result.** A locked account whose password also
fails is reported ``LOCKED``, not ``DRIFT``. The lock is both the more urgent fact
and the *cause* of what the login attempt saw, and a state that reported the
symptom would have an operator rotating a credential that was never the problem.

**A rollover window is a state, not a footnote.** During one, both the old and
the new password authenticate (UC-1 §6.3), so a `pass` says less than it usually
does -- it cannot distinguish "the database has the vault's password" from "the
database still has the previous one and is also accepting this". Reporting
``ROLLOVER_ACTIVE`` says exactly that much and no more.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sopuli.clock import as_utc, to_rfc3339, until, utc_now
from sopuli.driver.protocol import (
    FAIL,
    PASS,
    SKIPPED,
    UNAVAILABLE,
    UserState,
    VerifyResult,
)
from sopuli.exit_codes import ExitCode

__all__ = [
    "ACCOUNT_MISSING",
    "DRIFT",
    "ERROR",
    "EXPIRED",
    "IN_SYNC",
    "LOCKED",
    "ROLLOVER_ACTIVE",
    "STATES",
    "UNVERIFIABLE",
    "Outcome",
    "counts",
    "decide",
    "exit_code_for",
    "grace_warning",
    "is_failure",
    "is_inconclusive",
    "password_age_days",
]

#: The vault and the database agree.
IN_SYNC = "IN_SYNC"
#: They do not. Exit 3, and the reason `check` is schedulable.
DRIFT = "DRIFT"
#: A rollover window is open, so both passwords authenticate (UC-1 §6.3).
ROLLOVER_ACTIVE = "ROLLOVER_ACTIVE"
#: The config declares the account and the database does not have it.
ACCOUNT_MISSING = "ACCOUNT_MISSING"
#: The account is locked. Says nothing about the password, on purpose.
LOCKED = "LOCKED"
#: The password is expired. Also says nothing about whether it matches.
EXPIRED = "EXPIRED"
#: Nothing could be concluded -- and *why* is always reported beside it.
UNVERIFIABLE = "UNVERIFIABLE"
#: The check itself failed: a connection, a store, a refused view.
ERROR = "ERROR"

#: Every state this command can report, which is a subset of the schema's enum.
#: ``PENDING_APPLY`` and ``SKIPPED`` belong to verbs that stage or select work;
#: `check` looks at everything it was given and concludes something about all of
#: it.
STATES = (IN_SYNC, DRIFT, ROLLOVER_ACTIVE, ACCOUNT_MISSING, LOCKED, EXPIRED, UNVERIFIABLE, ERROR)

#: States that mean "the vault and the database disagree", for the exit code.
_DRIFTING = frozenset({DRIFT})

#: States that mean "no answer about the password", as opposed to a bad one.
#:
#: :data:`ERROR` is deliberately **not** here. It is counted as ``failed``, which
#: is the counter the document's own exit code agrees with: a run carrying an
#: `ERROR` exits 1, and a ``summary`` reporting ``failed: 0`` beside that would
#: contradict it. The rest are runs that reached the database and learned
#: something about the account without learning anything about its password.
_INCONCLUSIVE = frozenset({UNVERIFIABLE, ACCOUNT_MISSING, LOCKED, EXPIRED})


@dataclass(frozen=True)
class Outcome:
    """One (account, target) checked, as the command reports it.

    ``detail`` is a sentence, always populated, and that is not decoration: at
    03:00 a state without a reason is indistinguishable from a run that did
    nothing, and `SKIPPED`-shaped answers in particular are only useful with the
    reason attached (:func:`~sopuli.driver.oracle.verification.margin_reason`
    returns a sentence for the same reason).
    """

    state: str
    detail: str
    #: The verification as attempted, or ``None`` where the state was settled
    #: before anything was tried -- a missing account has no login to report.
    verification: VerifyResult | None = None


def decide(
    user: UserState | None,
    verification: VerifyResult | None,
    *,
    version: int | None = None,
) -> Outcome:
    """The state for one account, from what the database and the attempt said.

    ``user`` is ``None`` when the account is not there. ``verification`` is
    ``None`` when nothing was attempted -- which is a different thing from an
    attempt that was declined, and the difference matters: the second has a
    reason worth printing and is a :data:`UNVERIFIABLE` with
    ``lockout_margin_hit`` set.

    ``version`` is the vault version the password came from, carried only so the
    detail line can say which one was checked. It is what an operator compares
    against `config show` when two targets disagree.
    """
    if user is None:
        return Outcome(
            ACCOUNT_MISSING,
            "the config declares this account; the database has no such user",
        )

    # Status first, and unconditionally (UC-1 §7 mitigation 6). Both of these are
    # read from `DBA_USERS`, need no site-specific grant, and are the *cause* of
    # what a login attempt would have seen -- so reporting the symptom instead
    # would send somebody to the vault over an account that is simply locked.
    #
    # A comparison (`--method hash`, #437) is not refused by a lock, so it can
    # have run anyway. The state is still the status -- the lock is still the more
    # urgent fact -- and what the comparison found rides after it, so an operator
    # can tell whether unlocking would be enough.
    if user.locked or user.expired:
        state = LOCKED if user.locked else EXPIRED
        found = None if verification is None else _one_line(verification.detail)
        if found is None:
            return Outcome(state, f"account is {user.status.lower()}; the password was not tried")
        where = "" if version is None else f"vault v{version} "
        return Outcome(state, f"account is {user.status.lower()}; {where}{found}", verification)

    if verification is None:
        return Outcome(UNVERIFIABLE, "nothing was attempted")

    return _from_attempt(user, verification, version=version)


def _from_attempt(user: UserState, verification: VerifyResult, *, version: int | None) -> Outcome:
    """The states that depend on what the attempt returned."""
    where = "" if version is None else f"vault v{version} "

    if verification.result == SKIPPED:
        # The tool declined to try. `margin_reason` already phrased why, and
        # re-phrasing it here would be a second wording of one condition.
        return Outcome(
            UNVERIFIABLE,
            _one_line(verification.detail) or "the attempt was declined",
            verification,
        )
    if verification.result == UNAVAILABLE:
        return Outcome(
            UNVERIFIABLE,
            _one_line(verification.detail) or "verification is not available on this target",
            verification,
        )
    if verification.result == PASS:
        # Whatever the driver had to say rides after our own words, and a pass is
        # the branch where that matters most: a login with no lockout guard (the
        # optional `SYS.USER$` grant is absent) still passes, and the only place
        # that says so is this detail. Dropping it made an unguarded check read
        # exactly like a guarded one, which security-model §3 says it never does
        # (#558).
        note = _one_line(verification.detail)
        suffix = f"; {note}" if note else ""
        # A rollover window makes a `pass` mean less than it usually does: both
        # passwords authenticate, so this cannot tell "the database has the
        # vault's password" from "it still has the previous one and accepts
        # both". Saying `IN_SYNC` here would overstate what was measured.
        if user.rollover_active:
            return Outcome(
                ROLLOVER_ACTIVE,
                f"{where}accepted, but a rollover window is open: "
                f"the previous password still works too{suffix}",
                verification,
            )
        return Outcome(IN_SYNC, f"{where}verified by {verification.method}{suffix}", verification)
    if verification.result == FAIL:
        detail = _one_line(verification.detail) or "rejected"
        return Outcome(DRIFT, f"{where}{detail}", verification)

    # A result outside the schema's closed enum. Refused rather than mapped to a
    # state, because every value the vocabulary has is handled above: a new one
    # is a driver this module has not been taught about, and guessing which
    # state it means is how a wrong password becomes an `IN_SYNC`.
    raise ValueError(f"not a verification result: {verification.result!r}")


def _one_line(detail: str | None) -> str | None:
    """The first line of a driver's message, which is all a table row can hold.

    ``oracledb`` appends a documentation URL on its own line to most errors, so
    an ``ORA-01017`` arrives as two lines and a three-column table rendered with
    it becomes four ragged ones. Found by running this against a real container;
    a fake session returning a one-line detail could not have shown it.

    The same trim :func:`sopuli.cli._as_error` already applies to the document's
    ``error.message``, and for the same reason it gives -- a survey puts one line
    per row beside a table. Nothing is lost that identifies the failure: the
    vendor code is in the first line, and where a run carries an ``error`` object
    the driver's full message is on the exception it was built from.
    """
    if detail is None:
        return None
    lines = detail.splitlines()
    return lines[0] if lines else None


def password_age_days(changed_at: datetime | None, *, now: datetime | None = None) -> float | None:
    """How long ago the *database's* password was set, or ``None``.

    Reported beside the vault's own age as a drift smell (Q9, #87) and folded
    into nothing: `--max-age-days` reads the vault's ``rotated_at`` and only
    that, so one age per secret path answers it regardless of how many targets
    share the path.

    ``None`` where the database did not say -- which the driver explains in
    :attr:`~sopuli.driver.protocol.UserState.password_changed_unknown`, and the
    run carries as ``SOPULI-W021`` (#386). Nothing gates on it, so guessing
    would be all cost.

    **A naive timestamp is read as UTC**, because Oracle's ``PASSWORD_CHANGE_DATE``
    is a ``DATE`` and a ``DATE`` carries no zone: ``oracledb`` hands back a naive
    :class:`~datetime.datetime` in whatever zone the server keeps, and this
    function has no way to learn which. Subtracting it from an aware "now" is a
    ``TypeError``, which is how this was found -- against a real container, since
    a test that built its own aware fixture could not reproduce it.

    Reading it as UTC is the proportionate answer rather than the correct one,
    and Q9 (#87) is why that is enough: this number is displayed beside the
    vault's own age as a *drift smell* and nothing gates on it --
    ``--max-age-days`` reads ``rotated_at`` from the vault and only that. So the
    error is bounded by the server's offset, at most a few tenths of a day on a
    figure whose job is to look wrong when something is wrong. Returning ``None``
    instead would discard a useful signal to avoid an inaccuracy nobody acts on,
    and querying ``DBTIMEZONE`` would buy a round trip per target for the same.
    """
    if changed_at is None:
        return None
    moment = as_utc(now if now is not None else utc_now())
    return round((moment - as_utc(changed_at)).total_seconds() / 86400, 1)


def grace_warning(user: UserState | None, *, now: datetime | None = None) -> str | None:
    """What to say beside the state when a password is in its grace period.

    UC-1 §6.4 files the grace period as *informational, surfaced in status*, and
    #309 decided it rides as a warning rather than as a state of its own. The
    argument is that ``state`` is one field: an account in grace may be `IN_SYNC`
    or it may have drifted, and a value that displaced either would hide the
    answer the reader came for. Alongside, both are sayable.

    **Not derived from the login.** The obvious source is `ORA-28002`, which
    ``verification.py`` still names -- and which 26ai does not send: a grace login
    *succeeds*, and the notice arrives as a connection warning carrying
    `ORA-28098` or `ORA-28011` depending on the profile, which nothing reads
    (#322). ``ACCOUNT_STATUS`` says ``EXPIRED(GRACE)`` in every shape and needs no
    login at all, so that is what this asks. It also means the sentence is the
    same on a run where the lockout guard declined to try.

    Three sentences rather than one, because the deadline is most of the value
    and it is not always there:

    * a date, and a countdown to it -- the ordinary case;
    * a date already past. `EXPIRY_DATE` is the end of the window, and a status
      still reading ``EXPIRED(GRACE)`` after it means the database has not yet
      noticed, which it does at the next login. Saying *expires in -2 days* would
      be worse than saying it plainly;
    * no date at all, which is a release that did not give one. The grace period
      is still true and still worth saying; only *when* is missing, and inventing
      it is exactly what :class:`~sopuli.driver.protocol.UserState` refuses to do
      for every other unknown.

    ``None`` for every account not in grace, so a caller can pass any state and
    append what comes back.
    """
    if user is None or not user.in_grace:
        return None

    preamble = "the password is in its grace period: it still works"
    deadline = user.password_expires_at
    if deadline is None:
        return f"{preamble}, and the database did not say when the window closes"

    when = to_rfc3339(as_utc(deadline))
    remaining = until(deadline, now=now)
    if remaining is None:
        return f"{preamble}, and the window closed at {when}"
    return f"{preamble}, and expires {when} (in {remaining})"


def exit_code_for(states: Sequence[str]) -> int:
    """The process exit code for a whole run of `check`.

    Deliberately not "the worst state wins" over one ordering. Three questions,
    asked in the order a scheduler cares about them:

    * **Did anything fail to produce an answer?** That is exit 1 -- a broken
      check, which must not look like a clean one.
    * **Did the vault and the database disagree anywhere?** Exit 3, and P5 makes
      it distinct precisely so a monitoring system can alert on drift without
      alerting on the tool falling over.
    * Otherwise exit 0.

    Error beats drift, which is the ordering worth arguing about. A run that
    reached nine targets and could not reach the tenth found drift on *nine*
    targets' worth of estate -- reporting 3 would say the survey was complete.
    """
    if any(state == ERROR for state in states):
        return int(ExitCode.FAILURE)
    if any(state in _DRIFTING for state in states):
        return int(ExitCode.DRIFT)
    return int(ExitCode.SUCCESS)


def counts(states: Sequence[str]) -> dict[str, int]:
    """``summary.by_state``: how many of each, omitting the states with none.

    Omitting rather than zero-filling, because the schema types it as an open
    object and a document carrying eight zeroes per run is eight lines of noise
    in something consumers diff.
    """
    tally: dict[str, int] = {}
    for state in states:
        tally[state] = tally.get(state, 0) + 1
    return dict(sorted(tally.items()))


def is_inconclusive(state: str) -> bool:
    """Whether this state is "no answer" rather than a bad one.

    ``summary.unverifiable`` counts these together, which is what the operator
    reading "1 drift, 1 unverifiable" wants: the two numbers answer *go and fix
    something* and *go and look at something*, and an account that is locked and
    one whose counter was too close to its limit both belong to the second.

    :data:`ERROR` is not one of them -- see :data:`_INCONCLUSIVE`. It has its own
    counter, because it is the one state where the *tool* rather than the estate
    is what needs looking at.
    """
    return state in _INCONCLUSIVE


def is_failure(state: str) -> bool:
    """Whether the check itself failed, as opposed to answering unhappily.

    ``summary.failed``, and the same condition :func:`exit_code_for` turns into
    exit 1 -- asked in one place so the counter and the exit code cannot
    disagree about one run.
    """
    return state == ERROR

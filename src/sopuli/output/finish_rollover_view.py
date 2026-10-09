"""`creds finish-rollover` as a document and as a table (decision #263).

Same arrangement as the other credential verbs: the shape here, the decision in
:mod:`sopuli.finish_rollover`.

**The window is the subject, so `results[].rollover` carries it.** How much was
left when the run reached the account is the number an operator is judged on
afterwards -- a window closed with four minutes on it is a tidy-up, and one
closed with fifty-five is a decision somebody made about an application's grace
period. The object is emitted for every account whose state this run read,
including the ones it left alone, because "this window is still open and here is
its deadline" is the whole answer for those.

**Nothing here can emit a password.** The verb reads one to verify with and never
reports it; the only value in a row is a duration.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sopuli.check import DRIFT, IN_SYNC, Outcome, counts, is_failure, is_inconclusive
from sopuli.clock import as_utc, to_rfc3339
from sopuli.config.model import Binding
from sopuli.driver.protocol import UserState, VerifyResult
from sopuli.finish_rollover import PENDING_APPLY, SKIPPED, remaining
from sopuli.output.document import Error, Summary
from sopuli.output.palette import Role, paint, state_cell
from sopuli.output.table import Cell, Column, render_table

__all__ = ["build_result", "render_finish", "render_window_table", "summarise"]

_ACCOUNT = 24
_TARGET = 28
_STATE = 16


def build_result(
    binding: Binding,
    outcome: Outcome,
    *,
    user: UserState | None = None,
    changed: bool,
    duration_ms: int | None = None,
    error: Error | None = None,
) -> dict[str, Any]:
    """One ``results[]`` entry.

    ``changed`` is whether this run **closed** a window, and it is the only
    mutation this verb makes. An account with no window open reports
    ``IN_SYNC`` with ``changed: false``, which is invariant 9 for a verb whose
    ordinary night finds nothing to do.

    There is no ``secret`` object. The verb reads a password to verify with and
    changes nothing in any store, so an address here would say the run touched a
    document it never wrote to -- which is the reading `apply`'s own
    ``secret.stage`` was added to give.
    """
    entry: dict[str, Any] = {
        "account": binding.account,
        "target": binding.target,
        "state": outcome.state,
        "changed": changed,
    }
    entry["actions"] = [
        {
            "kind": "rollover_finish",
            # Whether the statement was issued, never whether the run was happy.
            # Every row this verb leaves alone carries `applied: false` and a
            # detail saying which of the several reasons it was.
            "applied": changed,
            "detail": outcome.detail,
        }
    ]
    if outcome.verification is not None:
        entry["verification"] = _verification(outcome.verification)
    if user is not None:
        entry["rollover"] = _rollover(user, closed=changed)
    if duration_ms is not None:
        entry["duration_ms"] = duration_ms
    if error is not None:
        entry["error"] = error.to_dict()
    return entry


def _rollover(user: UserState, *, closed: bool) -> dict[str, Any]:
    """The window as it stands **after** this run.

    ``active`` is what is true now, so a window this run closed reports
    ``false`` -- the run document describes the estate it leaves behind, not the
    one it found. ``ends_at`` goes with it and is therefore omitted once the
    window is gone: there is no deadline left to report, and the schema types it
    as a timestamp rather than a nullable one.

    ``profile_rollover_time`` stays either way. It is what says whether an
    account *can* have a window at all, which is the difference between "nothing
    to close tonight" and "this account never has one".
    """
    still_open = bool(user.rollover_active) and not closed
    found: dict[str, Any] = {
        "active": still_open,
        "profile_rollover_time": user.rollover_time,
    }
    if still_open and user.rollover_ends_at is not None:
        # Through `as_utc`: `to_rfc3339` converts a naive value from the
        # *machine's* local time, which would put this deadline hours away
        # from the countdown `remaining` computes off the same field.
        found["ends_at"] = to_rfc3339(as_utc(user.rollover_ends_at))
    return found


def _verification(result: VerifyResult) -> dict[str, Any]:
    """The login this verb spends, as `check` reports one.

    Emitted for every account it was spent on, including the ones that passed
    and were then closed -- the lockout counters in it are what makes the cost
    of a nightly job auditable, and decision P2 makes the grant behind them
    optional, so a null `lcount` is a real answer rather than a gap.
    """
    return {
        "method": result.method,
        "result": result.result,
        "latency_ms": result.latency_ms,
        "lcount": result.failed_logins,
        "failed_login_attempts_limit": result.failed_login_limit,
        "lockout_margin_hit": result.lockout_margin_hit,
        "previous_password_accepted": None,
    }


def summarise(states: Sequence[str], *, changed: int) -> Summary:
    """The counters this run carries.

    ``ok`` is ``IN_SYNC``, which covers both "closed it" and "there was nothing
    open" -- the two healthy answers, and the reason ``changed`` is beside it
    rather than folded into it. A night that closed nothing because nothing was
    open is a success, and one that closed nothing because everything drifted is
    not; the pair says which.

    ``unverifiable`` counts what `check` counts, plus this verb's two of its own
    (``PENDING_APPLY`` and ``SKIPPED``) -- every one of them is an account the run
    reached, learned something about, and deliberately left alone.
    """
    return Summary(
        total=len(states),
        ok=sum(1 for state in states if state == IN_SYNC),
        changed=changed,
        failed=sum(1 for state in states if is_failure(state)),
        unchanged=len(states) - changed,
        drift=sum(1 for state in states if state == DRIFT),
        unverifiable=sum(1 for state in states if _left_alone(state)),
        by_state=counts(states),
    )


def _left_alone(state: str) -> bool:
    """Whether this state means "reached it, and did not close it".

    `check`'s inconclusive set plus the two this verb adds. Both additions are
    deliberate refusals rather than gaps -- a staged `pending` and a database that
    cannot end a window early -- and grouping them with the locked and the
    unverifiable is right for the counter's own question, which is *how much of
    this estate should somebody go and look at*.
    """
    return is_inconclusive(state) or state in (PENDING_APPLY, SKIPPED)


def render_window_table(rows: Sequence[tuple[Binding, UserState]]) -> list[str]:
    """What is open and how long it has left, printed before anything is closed.

    Under ``--dry-run`` this is the whole output beside the plan, and it is the
    view the flag exists for: closing a window is the one step in UC-1 whose
    purpose is to stop something working, so *who am I about to cut off, and how
    early* is a question that deserves an answer before the fact.
    """
    return list(
        render_table(
            [
                Column("ACCOUNT", _ACCOUNT),
                Column("TARGET", _TARGET),
                Column("WINDOW"),
            ],
            [[binding.account, binding.target, _window(user)] for binding, user in rows],
        )
    )


def _window(user: UserState) -> Cell | str:
    if not user.rollover_active:
        return Cell("none open", Role.MUTED)
    left = remaining(user)
    return "open" if left is None else f"open, {left} left"


def render_finish(
    rows: Sequence[tuple[Binding, Outcome, bool]], *, would_close: int | None = None
) -> str:
    """The result table and the closing line. ``rows`` is (binding, outcome, changed).

    ``would_close`` is set under ``--dry-run`` and is what the closing line
    counts there. Without it a preview would say "nothing closed" -- true, and
    the opposite of the thing somebody ran a preview to find out.
    """
    table = render_table(
        [
            Column("ACCOUNT", _ACCOUNT),
            Column("TARGET", _TARGET),
            Column("STATE", _STATE),
            Column("DETAIL"),
        ],
        [
            [binding.account, binding.target, _state(outcome.state), outcome.detail]
            for binding, outcome, _ in rows
        ],
    )
    return "\n".join(
        [
            *table,
            "",
            _verdict(
                [outcome.state for _, outcome, _ in rows],
                closed=sum(1 for _, _, changed in rows if changed),
                would_close=would_close,
            ),
        ]
    )


def _state(state: str) -> Cell | str:
    """The state cell, coloured by :func:`~sopuli.output.palette.role_for_state`.

    One function decides the role for every verb (decision #395), and this
    command's ``SKIPPED`` rows -- windows that were already closed -- recede
    instead of reading like the rest.
    """
    return state_cell(state)


def _verdict(states: Sequence[str], *, closed: int, would_close: int | None = None) -> str:
    """The closing line: what was closed, then what was deliberately not.

    A run that closed nothing because nothing was open says so plainly, because
    that is the ordinary night and it must not read like a failure.

    Under a preview ``would_close`` replaces the count, and the line ends by
    saying nothing happened. The findings beside it are **not** hypothetical --
    an unreachable target, a staged `pending`, a locked account are all things
    the preview really found, and they are the answer it was run for.
    """
    drift = sum(1 for state in states if state == DRIFT)
    left = sum(1 for state in states if _left_alone(state))
    failed = sum(1 for state in states if is_failure(state))
    if would_close is not None:
        parts = [f"{would_close} would be closed"] if would_close else ["nothing would be closed"]
        if drift:
            parts.append(f"{drift} drift")
        if left - drift > 0:
            parts.append(f"{left - drift} left open")
        if failed:
            parts.append(f"{failed} failed")
        return ", ".join([*parts, "no window was closed (--dry-run)"])

    if not closed and not drift and not left and not failed:
        return paint(f"no rollover window was open on any of {len(states)}", Role.HEADING)

    parts = [f"{closed} closed"] if closed else ["nothing closed"]
    if drift:
        parts.append(f"{drift} drift")
    if left - drift > 0:
        parts.append(f"{left - drift} left open")
    if failed:
        parts.append(f"{failed} failed")
    line = ", ".join(parts)
    return paint(line, Role.HEADING) if closed and not drift and not failed else line

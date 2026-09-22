"""What `account reset-password` reports, and the one place it prints a password.

**This module holds the second ``reveal()`` call in the tool, and that is
invariant 2's fourth permitted plaintext path** (#439, #441). The first is
:mod:`sopuli.output.policy_view`, whose justification is that *a sample is not a
credential*: nothing authenticates with it, it is never stored, and it guards
nothing. This one is different and weaker -- it is a credential somebody can log
in with -- so the narrowing around it is stricter rather than equal.

What makes it allowable is not that it is harmless but that the exposure is
**deliberate, witnessed and time-limited**: an operator asked for the seen path
by name in the configuration, answered a prompt that no flag can answer, and the
password is expired at the moment it is set, so the owner's first logon ends it.

Five structural guards, and none of them is a reminder to be careful:

1. **one reveal site**, here, reachable only through :func:`render_password`,
   which the CLI calls only where the configured method is `manual`;
2. **refused with ``--output json`` and ``--output jsonl``**, and there is no
   property of a ``results[]`` entry a password could occupy even so -- see
   :func:`build_result`, which has no field for one and never will;
3. **refused unless stdout is a terminal**, which `--reveal` has no counterpart
   for and which is the guard the whole argument rests on;
4. **confirmed every time**, and ``--confirm`` cannot answer that prompt;
5. **``force_expire: true``** required on the method, refused at plan time.

Guards 2 to 4 are :func:`sopuli.reset.refuse_seen_path`'s, guard 5 is the config
layer's, and guard 1 is this module existing. A sixth site is a decision, not an
implementation detail (`CLAUDE.md` invariant 2).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sopuli.clock import to_rfc3339
from sopuli.delivery import Handover
from sopuli.driver.guardrails import Refusal
from sopuli.output.document import Error, Summary
from sopuli.output.palette import Role, paint, state_cell
from sopuli.output.table import Cell, Column, render_table
from sopuli.reset import ACCOUNT_MISSING, RESET, SKIPPED
from sopuli.secrets import Secret

_ACCOUNT = 24
_TARGET = 28
_STATE = 16
_STATUS = 22


def render_password(secret: Secret, *, account: str) -> str:
    """The seen path's one emission -- the whole of invariant 2's fourth exception.

    **The only ``reveal()`` outside the tests besides `policy_view`'s**, and it
    is a function rather than an inline call so that the exception has a name, a
    docstring and exactly one caller. `sopuli/cli.py` reaches it only after the
    delivery method is known to be `manual`, the output is known to be text,
    stdout is known to be a terminal, and a human has answered a prompt.

    **Returned rather than printed.** The caller writes it to stdout, which is
    the stream the terminal check was made about -- a function that printed would
    be free to print somewhere else later, and the guard would be about a stream
    nobody checked.

    The value appears on one line of its own, unlabelled beyond the account name.
    Nothing here writes it to a log, and nothing may: the run document, the event
    stream and every log sink are closed to it by having no field for it, which
    is what makes that a property of the contract rather than of this function's
    good behaviour.
    """
    # Invariant 2's fourth exception, the second and last `reveal()` in the tool.
    # Everything that makes it allowable happened before this line was reached.
    return "\n".join(
        [
            paint(f"password for {account}, shown once:", Role.HEADING),
            "",
            f"    {secret.reveal()}",
            "",
            "It is expired: the owner must change it at first logon, which is what ends",
            "your sight of it. It is not stored anywhere and will not be shown again.",
        ]
    )


def build_result(
    account: str,
    target: str,
    *,
    state: str,
    changed: bool,
    actions: Sequence[tuple[str, bool, str | None]] = (),
    status: str | None = None,
    delivered: str | None = None,
    handover: Handover | None = None,
    overridden: Sequence[Refusal] = (),
    duration_ms: int | None = None,
    error: Error | None = None,
) -> dict[str, Any]:
    """One ``results[]`` entry.

    **There is no field a password could go in, and that is guard 2's other
    half.** Refusing ``--output json`` stops the seen path from running when a
    document is being produced; this makes the document unable to carry the value
    whatever runs. The two are one guard asserted twice, and the second is the one
    that survives somebody adding a new output mode.

    ``delivered`` is the *method*, never a value and never a location on the seen
    path: `manual`'s destination is a person, by a route the tool did not carry.
    UC-2 §3.1 makes the same distinction for the record it writes.

    **``handover`` is what an auditor can act on, and it is deliberately not what
    the person fetches with** (#444 part 2). ``accessor`` names the hand-over in
    the store's own audit log and cannot perform it; ``expires_at`` says when
    fetching stops. It arrives as a :class:`~sopuli.delivery.Handover`, whose
    *presence* is the signal and whose fields are nullable within it -- a type with
    no token attribute, so this builder cannot be handed one.

    The retrieval credential itself has no property here and never
    will -- a document is captured, shipped to log aggregation and kept, and a
    token in one outlives the TTL that is the method's whole guarantee. That is the
    same argument the password's absence rests on, made about a different object.

    The section is **absent rather than null on the seen path**, which has neither
    field to fill: `manual`'s hand-over is a person reading a screen, so there is
    no accessor to name and no store clock to expire. A consumer therefore reads
    presence as "the tool put this somewhere" rather than having to compare two
    nulls.

    ``actions`` is one entry per statement the driver considered, in the order it
    considered them -- the unlock, the reset, the window. A row per statement
    rather than one summary, because "the account was not locked" and "the window
    was closed" are separate facts and `account suspend`'s single-action shape
    could not hold three.

    ``changed`` is whether the password was set. It is always ``True`` on a
    successful reset: invariant 9 does not govern this verb (#454), because a
    fresh random draw has nothing to converge on.
    """
    entry: dict[str, Any] = {
        "account": account,
        "target": target,
        "state": state,
        "changed": changed,
        "actions": [
            {"kind": kind, "applied": applied, "detail": detail}
            for kind, applied, detail in actions
        ],
    }
    if status is not None:
        entry["account_status"] = status
    if delivered is not None:
        entry["delivered"] = delivered
    if handover is not None:
        # **Presence says a delivery put the password somewhere**, and that is not
        # the same as either field being populated (Copilot's review of #519). A
        # wrap that returned a token but no accessor and no usable TTL is a real
        # hand-over with nothing to say about itself, and building the section out
        # of "is either field set" reported it as the seen path -- which is the one
        # thing this section's presence exists to tell apart.
        entry["handover"] = {
            "accessor": handover.accessor,
            "expires_at": (
                to_rfc3339(handover.expires_at) if handover.expires_at is not None else None
            ),
        }
    if overridden:
        entry["overridden"] = [
            {"check": refusal.check, "reason": refusal.reason} for refusal in overridden
        ]
    if duration_ms is not None:
        entry["duration_ms"] = duration_ms
    if error is not None:
        entry["error"] = error.to_dict()
    return entry


def summarise(states: Sequence[str], *, changed: int) -> Summary:
    """``summary`` for the run document.

    A refused row is not a failure, for :mod:`sopuli.output.suspend_view`'s
    reason: `SKIPPED` is the guardrails working and `ACCOUNT_MISSING` is an
    ordinary fact about an estate.
    """
    failed = sum(1 for state in states if state not in {RESET, SKIPPED, ACCOUNT_MISSING})
    return Summary(
        total=len(states),
        ok=len(states) - failed,
        changed=changed,
        failed=failed,
    )


def _state(state: str) -> Cell | str:
    return state_cell(state)


def render(
    rows: Sequence[tuple[str, str, str, str | None, str | None]],
    *,
    changed: int = 0,
    preview: bool = False,
    would_reset: int | None = None,
) -> str:
    """The result table and the closing line.

    ``rows`` is (account, target, state, account_status, detail), and
    ``account_status`` is the state the account was in **before** anything was
    issued -- the same reading `account suspend` gives it, so two UC-2 verbs do
    not mean different things by one column.

    ``changed`` is passed in rather than counted from the rows, which is
    `suspend_view`'s lesson taken rather than re-learned: a state word cannot say
    whether *this run* did it.
    """
    table = render_table(
        [
            Column("ACCOUNT", _ACCOUNT),
            Column("TARGET", _TARGET),
            Column("STATE", _STATE),
            Column("WAS", _STATUS),
            Column("DETAIL"),
        ],
        [
            [account, target, _state(state), status or "-", detail or ""]
            for account, target, state, status, detail in rows
        ],
    )
    verdict = _verdict(rows, changed=changed, preview=preview, would_reset=would_reset)
    return "\n".join([*table, "", verdict])


def _verdict(
    rows: Sequence[tuple[str, str, str, str | None, str | None]],
    *,
    changed: int,
    preview: bool,
    would_reset: int | None,
) -> str:
    """One line saying what happened, or what would.

    It names the account once rather than per row: this verb acts on exactly one
    (UC-2 §2), so a count of accounts would always be `1` and what varies is how
    many targets it reached.
    """
    if not rows:
        return "nothing to reset"

    account = rows[0][0]
    if preview:
        count = would_reset if would_reset is not None else 0
        return paint(f"would reset {account} on {count} of {len(rows)} targets", Role.HEADING)

    failed = sum(1 for row in rows if row[2] not in {RESET, SKIPPED, ACCOUNT_MISSING})
    line = (
        f"reset {account} on {changed} of {len(rows)} targets"
        if changed
        else f"{account} was not reset on any of {len(rows)}"
    )
    if failed:
        return paint(f"{line}; {failed} failed", Role.HEADING)
    return paint(line, Role.HEADING)

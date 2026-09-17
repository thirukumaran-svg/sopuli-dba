"""`sopuli account suspend` as a document and as a table (UC-2, #463).

Same arrangement as the credential verbs: the shape here, the decision in
:mod:`sopuli.suspend`.

**The status is the subject**, so every row carries the `ACCOUNT_STATUS` the run
read. UC-2 §5 makes that a rule rather than a nicety -- these verbs report the
state they found and never verify -- and it is what distinguishes the two answers
an operator most needs to tell apart: an account this run locked, and one that was
already locked before anybody typed the command.

**Nothing here can emit a password**, because this verb never has one: it reads no
secret, writes to no store, and issues a statement with no value in it.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sopuli.driver.guardrails import Refusal
from sopuli.driver.protocol import ACCOUNT_LOCK
from sopuli.output.document import Error, Summary
from sopuli.output.palette import Role, paint, state_cell
from sopuli.output.table import Cell, Column, render_table
from sopuli.suspend import ACCOUNT_MISSING, LOCKED, SKIPPED

#: Column widths, in the sibling views' units.
_ACCOUNT = 24
_TARGET = 28
_STATE = 16
_STATUS = 22


def build_result(
    account: str,
    target: str,
    *,
    state: str,
    changed: bool,
    detail: str | None,
    status: str | None = None,
    overridden: Sequence[Refusal] = (),
    duration_ms: int | None = None,
    error: Error | None = None,
) -> dict[str, Any]:
    """One ``results[]`` entry.

    ``changed`` is whether this run **issued** the statement. An account that was
    already locked reports ``LOCKED`` with ``changed: false``, which is invariant
    9 for a verb whose second run finds its work done.

    There is no ``secret`` object, and its absence is not an omission: nothing
    masters a personal account's password (UC-2 §1), so an address here would
    name a document that does not exist.

    ``account_status`` is what the database said before anything was issued. It
    is emitted even for a row this run refused, because "I would not touch it, and
    here is the state it is in" is the whole answer for those.
    """
    entry: dict[str, Any] = {
        "account": account,
        "target": target,
        "state": state,
        "changed": changed,
        "actions": [
            {
                # Whether the statement was issued, never whether the run was
                # happy: every row this verb leaves alone carries `applied:
                # false` and a detail saying which of the reasons it was.
                "kind": ACCOUNT_LOCK,
                "applied": changed,
                "detail": detail,
            }
        ],
    }
    if status is not None:
        entry["account_status"] = status
    if overridden:
        # §4 requires a waived guardrail to survive the waiving, in the document
        # as well as in the audit event -- a `--force` that merely proceeded
        # would leave this unable to say somebody did it on purpose. The pair is
        # `apply`'s own shape, and the schema requires both halves: the check
        # says which guardrail, and the reason is the sentence an operator reads
        # when they go back and ask what was waived and why it had fired.
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

    A refused row is **not** a failure. `SKIPPED` is the guardrails doing their
    job and `ACCOUNT_MISSING` is an ordinary fact about an estate, so neither puts
    a red number in front of an operator who asked a reasonable question. Only an
    error does.
    """
    failed = sum(1 for state in states if state not in {LOCKED, SKIPPED, ACCOUNT_MISSING})
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
    would_suspend: int | None = None,
) -> str:
    """The result table and the closing line.

    ``rows`` is (account, target, state, account_status, detail).

    ``changed`` is how many accounts this run actually locked, and it is passed
    in rather than counted from the rows because **the rows cannot answer it**. A
    row reading ``LOCKED`` may be one this run locked or one that was already
    locked when it arrived, and the first draft of this counted the state -- so a
    second run reported having suspended an account it had not touched. Found by
    running it twice, which is the whole reason that rule exists.

    ``would_suspend`` is set under ``--dry-run`` and is what the closing line
    counts there. Without it a preview would say "nothing suspended" -- true, and
    the opposite of what somebody ran a preview to find out.
    """
    table = render_table(
        [
            Column("ACCOUNT", _ACCOUNT),
            Column("TARGET", _TARGET),
            Column("STATE", _STATE),
            Column("STATUS", _STATUS),
            Column("DETAIL"),
        ],
        [
            [account, target, _state(state), status or "-", detail or ""]
            for account, target, state, status, detail in rows
        ],
    )
    verdict = _verdict(rows, changed=changed, preview=preview, would_suspend=would_suspend)
    return "\n".join([*table, "", verdict])


def _verdict(
    rows: Sequence[tuple[str, str, str, str | None, str | None]],
    *,
    changed: int,
    preview: bool,
    would_suspend: int | None,
) -> str:
    """One line saying what happened, or what would.

    It names the account once rather than per row, because this verb acts on
    exactly one (UC-2 §2) and a count of accounts would always be `1`. What
    varies is how many targets it reached.
    """
    if not rows:
        return "nothing to suspend"

    account = rows[0][0]
    if preview:
        count = would_suspend if would_suspend is not None else 0
        return paint(f"would suspend {account} on {count} of {len(rows)} targets", Role.HEADING)

    failed = sum(1 for row in rows if row[2] not in {LOCKED, SKIPPED, ACCOUNT_MISSING})
    if changed:
        line = f"suspended {account} on {changed} of {len(rows)} targets"
    else:
        already = sum(1 for row in rows if row[2] == LOCKED)
        line = (
            f"{account} was already locked on {already} of {len(rows)}"
            if already
            else f"{account} was not suspended on any of {len(rows)}"
        )

    # A target that could not be reached sets the exit code, so the line that
    # summarises the run has to name it. Without this a run reading
    # `[LOCKED, ERROR]` said "already locked on 1 of 2" and never mentioned the
    # target it could not reach -- true, and the half a reader would act on is
    # the half it left out.
    if failed:
        return paint(f"{line}; {failed} failed", Role.HEADING)
    return paint(line, Role.HEADING)

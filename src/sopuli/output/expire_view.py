"""`sopuli account expire-password` as a document and as a table (UC-2, #525).

Same arrangement as `account suspend`: the shape here, the decision in
:mod:`sopuli.expire`, the statements in the driver.

**Two statements, so a row carries two actions** -- the window close and the
expiry, in the order the driver considered them. That is `reset-password`'s
shape rather than `suspend`'s single action, and for its reason: "no window was
open" and "the password was expired" are separate facts, and on an account at
`EXPIRED & IN ROLLOVER` only the first of them happens.

**Nothing here can emit a password**, because this verb never has one. The
statement it issues has no value in it, and nothing is read from or written to a
store.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sopuli.driver.guardrails import Refusal
from sopuli.driver.protocol import PASSWORD_EXPIRE
from sopuli.expire import ACCOUNT_MISSING, EXPIRED, SKIPPED
from sopuli.output.document import Error, Summary
from sopuli.output.palette import Role, paint, state_cell
from sopuli.output.table import Column, render_table

#: Column widths, in the sibling views' units.
_ACCOUNT = 24
_TARGET = 28
_STATE = 16
_STATUS = 22

#: The states a run can end in without anything having failed.
_FINE = frozenset({EXPIRED, SKIPPED, ACCOUNT_MISSING})


def build_result(
    account: str,
    target: str,
    *,
    state: str,
    changed: bool,
    actions: Sequence[tuple[str, bool, str | None]] = (),
    detail: str | None = None,
    status: str | None = None,
    overridden: Sequence[Refusal] = (),
    duration_ms: int | None = None,
    error: Error | None = None,
) -> dict[str, Any]:
    """One ``results[]`` entry.

    ``actions`` is one ``(kind, applied, detail)`` per statement the driver
    considered. A row that never reached the driver -- refused, missing,
    unreachable, or previewed -- has none, so it carries a single
    ``password_expire`` action with ``applied: false`` and ``detail`` saying
    why, as `account suspend`'s rows do.

    ``changed`` is whether **either** statement was issued. An account found at
    `EXPIRED & IN ROLLOVER` is not converged under #525's option (b): its window
    is closed, the expiry is not reissued, and the row reports ``changed: true``.
    Only an account already expired with no window open reports
    ``changed: false`` -- invariant 9 for this verb.

    ``account_status`` is what the database said before anything was issued, for
    `account suspend`'s reason: ``state: EXPIRED`` with ``changed: false`` cannot
    by itself say whether the account was already expired or would be under
    ``--dry-run``.
    """
    rows = list(actions) or [(PASSWORD_EXPIRE, False, detail)]
    entry: dict[str, Any] = {
        "account": account,
        "target": target,
        "state": state,
        "changed": changed,
        "actions": [
            {"kind": kind, "applied": applied, "detail": said} for kind, applied, said in rows
        ],
    }
    if status is not None:
        entry["account_status"] = status
    if overridden:
        # §4: a waived guardrail survives the waiving, in the document as well as
        # the audit event -- `account suspend`'s shape, and `apply`'s before it.
        entry["overridden"] = [
            {"check": refusal.check, "reason": refusal.reason} for refusal in overridden
        ]
    if duration_ms is not None:
        entry["duration_ms"] = duration_ms
    if error is not None:
        entry["error"] = error.to_dict()
    return entry


def summarise(states: Sequence[str], *, changed: int) -> Summary:
    """``summary`` for the run document. A refusal is not a failure; an error is."""
    failed = sum(1 for state in states if state not in _FINE)
    return Summary(total=len(states), ok=len(states) - failed, changed=changed, failed=failed)


def render(
    rows: Sequence[tuple[str, str, str, str | None, str | None]],
    *,
    changed: int = 0,
    preview: bool = False,
    would_expire: int | None = None,
) -> str:
    """The result table and the closing line.

    ``rows`` is (account, target, state, account_status, detail).

    ``changed`` is passed in rather than counted from the rows, because a row
    reading ``EXPIRED`` may be one this run expired or one it found expired --
    the bug `account suspend`'s first draft had, found by running it twice.
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
            [account, target, state_cell(state), status or "-", detail or ""]
            for account, target, state, status, detail in rows
        ],
    )
    verdict = _verdict(rows, changed=changed, preview=preview, would_expire=would_expire)
    return "\n".join([*table, "", verdict])


def _verdict(
    rows: Sequence[tuple[str, str, str, str | None, str | None]],
    *,
    changed: int,
    preview: bool,
    would_expire: int | None,
) -> str:
    """One line saying what happened, or what would, naming the one account."""
    if not rows:
        return "nothing to expire"

    account = rows[0][0]
    if preview:
        count = would_expire if would_expire is not None else 0
        return paint(
            f"would expire {account}'s password on {count} of {len(rows)} targets", Role.HEADING
        )

    failed = sum(1 for row in rows if row[2] not in _FINE)
    if changed:
        line = f"expired {account}'s password on {changed} of {len(rows)} targets"
    else:
        already = sum(1 for row in rows if row[2] == EXPIRED)
        line = (
            f"{account}'s password was already expired on {already} of {len(rows)}"
            if already
            else f"{account}'s password was not expired on any of {len(rows)}"
        )

    # A target that could not be reached sets the exit code, so the closing line
    # has to name it -- `account suspend`'s lesson.
    if failed:
        return paint(f"{line}; {failed} failed", Role.HEADING)
    return paint(line, Role.HEADING)

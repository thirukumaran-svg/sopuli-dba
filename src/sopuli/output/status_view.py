"""`creds status` as a document and as a table.

UC-1 §9's inventory, which is the one output in this tool designed to be read
across rather than down: an operator scans a column and finds the row that does
not match its neighbours.

**Eight columns, and each earns its place by being unobtainable elsewhere
without a login.** `VAULT_V` and `AGE` come from the vault, `DB_PW_CHANGED`,
`LOCK`, `PROFILE` and `ROLLOVER` from two dictionary views, and the pair of ages
side by side is the drift smell §9 is built around — the same database history
answering differently depending on which clock is asked.

**No `secret` object in `results[]`.** This verb reads a document to age it and
never writes one, and an address here would say it touched something. The
version is on the row where it belongs.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sopuli.check import (
    ACCOUNT_MISSING,
    ERROR,
    counts,
    grace_warning,
    is_failure,
    password_age_days,
)
from sopuli.diagnostics import PASSWORD_CHANGE_DATE_UNKNOWN, PASSWORD_GRACE_PERIOD
from sopuli.driver.oracle.rollover import days as rollover_days
from sopuli.driver.protocol import UserState
from sopuli.output.document import Diagnostic, Error, Summary
from sopuli.output.notices import render_notices
from sopuli.output.palette import Role, paint, state_cell
from sopuli.output.table import Cell, Column, render_table
from sopuli.status import PENDING_APPLY, Row

__all__ = ["build_result", "render_status_table", "summarise"]

_ACCOUNT = 24
_TARGET = 28
_STATE = 16


def build_result(
    row: Row, *, duration_ms: int | None = None, error: Error | None = None
) -> dict[str, Any]:
    """One ``results[]`` entry.

    ``changed`` is always ``False`` and required by the schema anyway, which is
    worth saying rather than leaving to be noticed: this verb cannot mutate
    anything, so a consumer diffing the array gets a run of ``false`` by
    construction. Invariant 9's shape for a read-only verb, as `check` has it.

    The single action is ``none``. There is no ``inventory`` kind in the schema's
    enum and this does not want one — nothing was done, and `none` is the enum's
    own word for exactly that. Inventing a kind would put a verb in the contract
    that describes an absence.

    Warnings are **derived from the row** rather than passed in, unlike `check`'s,
    and that is the difference between the two verbs rather than an inconsistency:
    everything this command reports it read for itself, so :func:`_warnings` has
    the whole :class:`~sopuli.status.Row` and needs nothing from its caller. The
    grace period joins the age warning there (UC-1 §6.4).
    """
    entry: dict[str, Any] = {
        "account": row.binding.account,
        "target": row.binding.target,
        "state": row.outcome.state,
        "changed": False,
        "actions": [{"kind": "none", "applied": False, "detail": row.outcome.detail}],
    }
    # `password_age_days` is the schema's field and it means the *database's* age
    # everywhere else -- `check` fills it from `PASSWORD_CHANGE_DATE`. It is
    # filled the same way here, and the vault's age travels in `warnings` and in
    # the text column instead: two different clocks under one field name is how
    # the confusion §9 warns about gets into a document.
    database_age = _database_age(row.user)
    if database_age is not None:
        entry["password_age_days"] = database_age
    rollover = _rollover(row.user)
    if rollover is not None:
        entry["rollover"] = rollover
    if duration_ms is not None:
        entry["duration_ms"] = duration_ms
    if error is not None:
        entry["error"] = error.to_dict()
    warnings = _warnings(row)
    if warnings:
        entry["warnings"] = warnings
    return entry


def _database_age(user: UserState | None) -> float | None:
    """The database's own age, in the field the schema has for it.

    ``None`` where the database did not say, and :func:`_warnings` says why
    (decision #386). This verb displays it rather than acting on it, so an
    absence costs nothing -- except the explanation, which is why there is one.
    """
    return None if user is None else password_age_days(user.password_changed_at)


def _rollover(user: UserState | None) -> dict[str, Any] | None:
    """The window, and the profile that decides whether there can be one.

    Emitted for every account whose state was read, not only the ones with a
    window open: "this profile grants none" and "this profile grants one and it
    is closed" are different facts about an estate, and an inventory is where
    somebody goes to tell them apart.
    """
    if user is None:
        return None
    return {"active": bool(user.rollover_active), "profile_rollover_time": user.rollover_time}


def _warnings(row: Row) -> list[dict[str, Any]]:
    """What this row wants somebody to notice.

    The age is a warning rather than a column value in the document, because
    ``password_age_days`` already means the database's age and Q9's whole point
    is that the two must not be confused. A consumer reading the vault's age
    reads it here, where the message says which clock it came from.

    The grace period is the second, and this is how it reaches a reader of
    `status` (UC-1 §6.4). It comes from :func:`~sopuli.check.grace_warning`, the
    same function `check` uses, so the two commands cannot describe one window
    differently.

    Built through :class:`~sopuli.output.document.Diagnostic`, because two
    hand-rolled dicts in one array are two chances to disagree about a shape the
    schema states once. The age warning carries no ``code``, because allocating
    one is J3's question, not this list's. ``to_dict`` omits an absent ``code``
    rather than nulling it.
    """
    found = []
    if row.over_age:
        found.append(
            Diagnostic(
                level="warning",
                message=(
                    f"the vault last rotated this {row.age} days ago, past the "
                    f"--max-age-days threshold"
                ),
                account=row.binding.account,
                target=row.binding.target,
            )
        )
    grace = grace_warning(row.user)
    if grace is not None:
        found.append(
            Diagnostic(
                level="warning",
                code=PASSWORD_GRACE_PERIOD,
                message=grace,
                account=row.binding.account,
                target=row.binding.target,
            )
        )
    unknown = None if row.user is None else row.user.password_changed_unknown
    if unknown is not None:
        # Beside the `password_age_days` it explains, one per result.
        found.append(
            Diagnostic(
                level="warning",
                code=PASSWORD_CHANGE_DATE_UNKNOWN,
                message=unknown,
                account=row.binding.account,
                target=row.binding.target,
            )
        )
    return [entry.to_dict() for entry in found]


def summarise(rows: Sequence[Row]) -> Summary:
    """The counters an inventory carries.

    ``ok`` is deliberately **not** a state count here. There is no state this
    verb reports that means "healthy": its ordinary row is ``UNVERIFIABLE``,
    because it never asked (see :mod:`sopuli.status`). So ``ok`` counts the rows
    with nothing to say about them -- no missing account, no lock, no unfinished
    rotation, no age past the threshold -- which is the number an operator
    actually reads a summary for.

    ``changed`` is zero and ``unchanged`` is everything, by construction.
    """
    states = [row.outcome.state for row in rows]
    return Summary(
        total=len(rows),
        ok=sum(1 for row in rows if _quiet(row)),
        changed=0,
        failed=sum(1 for state in states if is_failure(state)),
        unchanged=len(rows),
        unverifiable=sum(1 for row in rows if not _quiet(row) and row.outcome.state != ERROR),
        by_state=counts(states),
    )


def _quiet(row: Row) -> bool:
    """Whether this row is one nobody needs to look at.

    A grace period counts against quiet, and that is not a free choice. Without
    it, a row with a closing window would be quiet, the same as a healthy one,
    and the finding would not be counted at all.
    """
    return row.outcome.state not in (ACCOUNT_MISSING, PENDING_APPLY, ERROR) and not (
        row.over_age or _unhappy(row.user) or _expiring(row.user)
    )


def _unhappy(user: UserState | None) -> bool:
    return user is not None and (user.locked or user.expired)


def _expiring(user: UserState | None) -> bool:
    """In a grace period: the password works, and the window is closing.

    Its own predicate rather than a third arm of :func:`_unhappy`, because the
    verdict names them separately and they want different words. *Locked or
    expired* is a credential that has stopped working; this one has not, so the
    two are not treated as one.
    """
    return user is not None and user.in_grace


def render_status_table(rows: Sequence[Row]) -> str:
    """§9's table, and the line under it.

    The two age columns sit next to each other on purpose. §9's worked example is
    two rows sharing a ``DB_PW_CHANGED`` and differing by 82 days of vault age --
    the same database history, two very different answers depending on which
    clock is asked, and only one of them acted on. Putting them apart, or showing
    one, would hide the thing the table was drawn to show.

    The notice block under it is the same one `check` prints, and it is how the
    grace period reaches a reader of `status` (UC-1 §6.4). No column shows the
    window, so this block is where the text output shows it.
    """
    table = render_table(
        [
            Column("ACCOUNT", _ACCOUNT),
            Column("TARGET", _TARGET),
            Column("STATE", _STATE),
            Column("VAULT_V"),
            Column("AGE"),
            Column("DB_PW_CHANGED"),
            Column("PROFILE"),
            Column("ROLLOVER"),
        ],
        [
            [
                row.binding.account,
                row.binding.target,
                _state(row.outcome.state),
                _version(row.version),
                _age(row),
                _changed_at(row.user),
                _profile(row.user),
                _rollover_cell(row.user),
            ]
            for row in rows
        ],
    )
    return "\n".join([*table, "", _verdict(rows), *render_notices(_notices(rows))])


def _notices(rows: Sequence[Row]) -> list[str]:
    """The grace period, named by the row it belongs to -- and why a
    ``DB_PW_CHANGED`` is empty, named by the target.

    Not the age warning beside them in :func:`_warnings`: the age is already a
    column in this table, and printing ``AGE`` twice would be noise rather than
    emphasis. What has no column is the window and when it closes, and the
    reason behind a ``-``.

    **The reason is grouped per target and reason**, where the document carries
    it per result. An 18c target with forty accounts on it has one
    missing column, and forty identical lines under a table teach the reader to
    skip the notes block -- including the grace period above them.
    """
    found = []
    for row in rows:
        grace = grace_warning(row.user)
        if grace is not None:
            found.append(f"{row.binding.account} on {row.binding.target}: {grace}")

    unknown: dict[tuple[str, str], list[str]] = {}
    for row in rows:
        reason = None if row.user is None else row.user.password_changed_unknown
        if reason is not None:
            unknown.setdefault((row.binding.target, reason), []).append(row.binding.account)
    for (target, reason), accounts in unknown.items():
        who = accounts[0] if len(accounts) == 1 else f"{len(accounts)} accounts"
        found.append(f"{target}: DB_PW_CHANGED is empty for {who}: {reason}")
    return found


def _state(state: str) -> Cell | str:
    """The state cell, coloured by :func:`~sopuli.output.palette.role_for_state`.

    Worth reading twice for this command, because it is the one whose ordinary
    row is ``UNVERIFIABLE`` -- `status` spends no logins, so most rows say the
    password was not checked. Those go **dim** (decision #395), which is the
    whole column receding rather than shouting. It lets the other rows stand out
    without this function naming them.
    """
    return state_cell(state)


def _version(version: int | None) -> Cell | str:
    return Cell("-", Role.MUTED) if version is None else str(version)


def _age(row: Row) -> Cell | str:
    """The vault's age, marked where it is past the threshold.

    ``-`` for a credential this tool has never rotated, which is an age of
    *unknown* rather than of zero -- and `--max-age-days` does not select it.
    """
    if row.age is None:
        return Cell("-", Role.MUTED)
    rendered = f"{row.age:.0f}d"
    return Cell(f"{rendered} !", Role.NOTABLE) if row.over_age else rendered


def _changed_at(user: UserState | None) -> Cell | str:
    """The database's own date, for display and nothing else (Q9).

    ``-`` where the database would not say. On a release with no
    ``PASSWORD_CHANGE_DATE`` -- 18c and 11.2 among those measured -- the date is
    behind the optional ``SYS.USER$`` grant (decision #386). A dash on its own
    does not say which reason applies, so the notes under the table do.
    """
    if user is None or user.password_changed_at is None:
        return Cell("-", Role.MUTED)
    return user.password_changed_at.date().isoformat()


def _profile(user: UserState | None) -> Cell | str:
    if user is None or user.profile is None:
        return Cell("-", Role.MUTED)
    return user.profile


def _rollover_cell(user: UserState | None) -> Cell | str:
    """Whether a window can open here, and whether one is open now.

    Three answers rather than two, because "not configured" and "configured and
    quiet" are what decide whether a zero-downtime rotation is available at all
    -- which is the question §6.3 makes an operator ask before scheduling one.
    """
    if user is None:
        return Cell("-", Role.MUTED)
    if user.rollover_active:
        return Cell("window open", Role.NOTABLE)
    configured = rollover_days(user.rollover_time)
    if not configured:
        return Cell("not configured", Role.MUTED)
    return f"{_hours(configured)} configured"


def _hours(days: float) -> str:
    """A rollover limit as an operator would say it, from :func:`rollover_days`'s
    days -- which a release reading the limit in seconds has been converted to."""
    hours = days * 24
    if hours >= 24 and hours % 24 == 0:
        return f"{int(days)}d"
    if hours >= 1:
        return f"{hours:.0f}h"
    return f"{hours * 60:.0f}m"


def _verdict(rows: Sequence[Row]) -> str:
    """The closing line: the size of the estate, then what to look at.

    An inventory's ordinary answer is that there is nothing to do, and it must
    read that way -- a survey that always ends in a list of counts trains people
    to skip the last line.
    """
    findings = []
    missing = sum(1 for row in rows if row.outcome.state == ACCOUNT_MISSING)
    staged = sum(1 for row in rows if row.outcome.state == PENDING_APPLY)
    over = sum(1 for row in rows if row.over_age)
    expiring = sum(1 for row in rows if _expiring(row.user))
    unhappy = sum(1 for row in rows if _unhappy(row.user))
    failed = sum(1 for row in rows if is_failure(row.outcome.state))
    if missing:
        findings.append(f"{missing} missing")
    if staged:
        findings.append(f"{staged} awaiting apply")
    if over:
        findings.append(f"{over} past max age")
    # Between the two clocks and the two breakages: a window that is closing is
    # more urgent than an age threshold somebody chose and less urgent than a
    # credential that has already stopped working.
    if expiring:
        findings.append(f"{expiring} in a grace period")
    if unhappy:
        findings.append(f"{unhappy} locked or expired")
    if failed:
        findings.append(f"{failed} unreachable")

    counted = f"{len(rows)} account{'' if len(rows) == 1 else 's'}"
    if not findings:
        return paint(f"{counted}, nothing to act on", Role.HEADING)
    return f"{counted}: " + ", ".join(findings)

"""The run document's ``lock`` section (``03-json-output.md`` §2, #83, #105).

What a run says about the locks it took, on exit 7 about the one it did not get,
and — for ``lock status`` — about locks that are somebody else's entirely. The
shape is pinned by ``sopuli-run-1.9.schema.json``; this is the only producer of
it, the same arrangement :mod:`sopuli.output.config_view` and
:mod:`sopuli.output.policy_view` have with their sections.

Three things here are translation rather than transcription.

**The section reports a guarantee, not a mechanism.** ``mode`` is ``cas`` or
``none``, so a consumer branches on whether the run was actually protected
without having to know what KV v1 is. A ``fence`` of ``null`` under ``none`` says
the same thing a second way, and says it per lock.

**A holder is reported differently from how it is stored.** In the record the
correlation id and the command are the *run's* own fields, beside the holder
rather than inside it, because a record describes one run. In the report they are
part of the holder, because there the run being described is somebody else's and
"who is that, and what are they doing" is one question.

**A lock somebody else holds is a different array from one this run took.**
``held[]`` is possessive and ``found[]`` is not; :func:`build_status_section`
says why they are two.

**A record the configuration does not declare is marked, not separated.** It
goes in ``found[]`` with ``declared: false`` (#150) rather than in a third array,
because it is the same kind of thing described the same way -- what differs is
whose it is, which is one boolean. The *text* view does split them, and that is
a rendering decision rather than a contract one: a table is read by eye, and "is
this mine" is the first question somebody asks of a row.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from sopuli.clock import to_rfc3339
from sopuli.lock.errors import LockDeniedError
from sopuli.lock.inspect import LockState
from sopuli.lock.manager import HeldLock, LockManager
from sopuli.lock.record import HELD, RELEASED, LockRecord
from sopuli.output.palette import Role
from sopuli.output.table import Cell, Column, render_table


def build_section(
    manager: LockManager, *, denied: LockDeniedError | None = None
) -> dict[str, Any] | None:
    """The ``lock`` section, or ``None`` when the run took no locks.

    ``None`` rather than an empty object, and the difference is load-bearing:
    absent means the run *needed* no lock — every ``check``, ``status`` and
    ``--dry-run`` — while ``{"mode": "cas", "held": []}`` would describe a run
    that wanted locks and holds none, which is not a state that reaches here.
    """
    if not manager.held and denied is None:
        return None
    section: dict[str, Any] = {"mode": manager.mode}
    if manager.held:
        section["held"] = [_held(one) for one in manager.held]
    if denied is not None:
        section["denied"] = _denied(denied)
    return section


def _held(held: HeldLock) -> dict[str, Any]:
    """One lock, with every field the schema requires.

    All six are required there because this is written when the run ends, by
    which point there is nothing about its own locks the tool does not know. A
    partial entry would describe a producer that lost track of what it had
    locked.
    """
    return {
        "vault": held.key.store,
        "path": held.key.path,
        "fence": held.fence,
        "acquired_at": to_rfc3339(held.record.acquired_at),
        "expires_at": to_rfc3339(held.record.expires_at),
        "released": held.released,
    }


def _denied(denied: LockDeniedError) -> dict[str, Any]:
    """The lock that stopped the run.

    ``reason`` says how it was lost, and the two ways are not the same event:
    ``held`` read somebody's record, so the holder and the timestamps describe
    it; ``race`` lost the compare-and-set write, where the winner's record was
    never read. Reporting an all-null holder for the second would be
    indistinguishable from a vault that answered badly.
    """
    section: dict[str, Any] = {
        "vault": denied.key.store,
        "path": denied.key.path,
        "reason": denied.reason,
    }
    if denied.record is not None:
        section.update(
            holder=_holder(denied.record),
            acquired_at=to_rfc3339(denied.record.acquired_at),
            expires_at=to_rfc3339(denied.record.expires_at),
            expired=denied.expired,
        )
    return section


def _holder(record: LockRecord) -> dict[str, Any]:
    """Who holds it, flattened from the record. Never a value — see the record.

    Every member is nullable in the schema and every one degrades on its own: a
    record written by another version, or half-written, still has to be
    *reportable*, because the alternative is a lock nobody can explain and
    nobody can break.
    """
    holder = record.holder
    return {
        "host": holder.host if holder is not None else None,
        "pid": holder.pid if holder is not None else None,
        "os_user": holder.os_user if holder is not None else None,
        "correlation_id": record.correlation_id or None,
        "command": record.command or None,
    }


# ------------------------------------------------------- somebody else's locks ---


def build_status_section(states: Sequence[LockState], *, mode: str) -> dict[str, Any]:
    """The ``lock`` section for ``lock status`` (#105).

    Records read from a store go in ``found[]``, **beside** ``held[]`` rather
    than inside it. ``held`` is possessive: it is the locks *this run* took and
    whether it let go of them, and every field in it is required precisely
    because the run knows all of them about its own locks. Filling it with
    somebody else's records would make one field mean two things depending on
    ``command`` -- ``released: true`` would flip from "we let go cleanly" to
    "this path is free" -- and a consumer aggregating held locks across runs
    would start counting surveys as acquisitions. That is what invariant 12
    exists to prevent, so the two answers get two arrays.

    **A path with nothing at it is not an entry.** ``found`` means records that
    were read, which keeps every member of an entry required, the same argument
    ``held[]`` makes. How many paths were examined is ``summary.total``; the
    difference between the two numbers is how many are free.

    Emitted even when it is empty, unlike every other run's ``lock`` section.
    Absent there means *no lock was needed*; here an empty ``found`` is the
    finding -- nothing is locked -- and withholding it would make a quiet estate
    indistinguishable from a command that did not look.

    **A record at a path the config does not declare is an entry like any other**,
    carrying ``declared: false`` (#150). Not a third array beside ``held`` and
    ``found``: the argument that split those two was that one field would mean
    different things in each, and nothing of the sort happens here -- every field
    means exactly what it means for a declared record, and the one thing that
    differs is whose the record is. A consumer keeping only its own locks filters
    on a boolean that is always present.
    """
    return {
        "mode": mode,
        "found": [_found(state, state.record) for state in states if state.record is not None],
    }


def _found(state: LockState, record: LockRecord) -> dict[str, Any]:
    """One record, described from outside.

    ``declared`` says whether this configuration binds an account to the path.
    It is on every entry rather than only on the leftovers, because a consumer
    that had to read it as "absent means mine" would be branching on a gap, and
    a gap is what a producer that forgot the field also emits.

    ``state`` is reported as written and ``held`` as
    :attr:`~sopuli.lock.inspect.LockState.is_held` reads it, which is not the
    same thing twice. A record whose ``state`` this build has never heard of is
    held -- that is the safe direction and the answer the manager would give when
    acquiring -- and a consumer that only saw ``held: true`` would have no way to
    tell it from an ordinary one. Reporting both is what lets somebody recognise
    a record written by a newer sopuli, or a half-written one.

    The record arrives as its own argument rather than being read off ``state``
    again: the caller has already established that there is one, and re-narrowing
    it here would need an assertion to say so.
    """
    return {
        "vault": state.key.store,
        "path": state.key.path,
        "held": state.is_held,
        "declared": state.declared,
        "state": record.state,
        "expired": state.expired,
        "version": state.version,
        "acquired_at": to_rfc3339(record.acquired_at),
        "expires_at": to_rfc3339(record.expires_at),
        "holder": _holder(record),
    }


def render_status(
    paths: Sequence[Path],
    states: Sequence[LockState],
    *,
    match: tuple[tuple[str, str], ...] = (),
    mode: str,
) -> str:
    """``lock status`` in text -- the survey a person reads.

    **Only the paths that carry a record appear.** A declared path with nothing
    at it is the ordinary state of most of an estate most of the time, and a
    table listing forty free paths so that two held ones can hide in it is a
    table nobody scans. The count of what was examined is on the last line, which
    is where "and the rest are free" belongs.

    The first column is ``store:path`` -- one cell rather than two, because that
    spelling is what exit 7 prints, what the ``lock.*`` events carry, and what
    ``sopuli lock break`` will take (#149). Splitting it into a VAULT column and
    a PATH column would make the operator reassemble by hand the one string they
    are about to paste.

    **Leftovers get a table of their own** (#150), under a heading that says what
    they are. The alternatives were both worse: a seventh column carrying
    ``yes`` / ``no`` costs width on every row to answer a question that is
    usually "yes", and a marker appended to the LOCK cell would corrupt the one
    string the operator is about to paste into ``lock break``. Two tables also
    put the answer in the heading rather than in a cell, which is where somebody
    scanning the output will actually read it -- and colour alone could not have
    carried it, since ``NO_COLOR`` is honoured.
    """
    lines = [f"config: {paths[0]}"]
    lines.extend(f"        {path} (layered)" for path in paths[1:])
    if match:
        lines.append(f"select: {', '.join(f'{key}={value}' for key, value in match)}")
    lines.append(f"mode:   {mode}")

    found = [state for state in states if state.record is not None]
    mine = [state for state in found if state.declared]
    leftovers = [state for state in found if not state.declared]

    if mine:
        lines.extend(["", *_table(mine)])
    if leftovers:
        lines.extend(
            [
                "",
                "not declared by this config -- a leftover, or another config's:",
                *_table(leftovers),
            ]
        )
    lines.extend(["", _summary(states, found)])
    return "\n".join(lines)


def _table(states: Sequence[LockState]) -> list[str]:
    """One table of records, whosever they are.

    The same columns for both halves, deliberately: a leftover is described by
    exactly the same facts as a declared lock, and giving it a different shape
    would suggest the tool knows less about it than it does.
    """
    return list(
        render_table(
            [
                Column("LOCK", _LOCK),
                Column("STATE"),
                Column("HOLDER", _HOLDER),
                Column("COMMAND", _COMMAND),
                Column("SINCE"),
                Column("EXPIRES"),
            ],
            [_row(state) for state in states],
        )
    )


#: Column caps. `_LOCK` is `_REF`'s width in `config_view`, because it holds the
#: same kind of string -- a store name and a path -- and two views truncating one
#: estate at different points would read as two estates.
_LOCK = 52
_HOLDER = 28
_COMMAND = 16


def _row(state: LockState) -> list[Cell | str]:
    record = state.record
    if record is None:  # pragma: no cover - callers filter
        raise ValueError("a row needs a record")
    return [
        str(state.key),
        _verdict(state, record),
        Cell(_who(record), Role.MUTED if not state.is_held else None),
        record.command or "-",
        to_rfc3339(record.acquired_at),
        to_rfc3339(record.expires_at),
    ]


def _verdict(state: LockState, record: LockRecord) -> Cell | str:
    """The one word somebody is looking for.

    Four outcomes rather than two, because ``held`` alone answers neither
    question an operator has. ``expired`` is the holder that is probably gone;
    the raw state is a record this build does not recognise, which is worth
    seeing rather than flattening into ``held`` -- even though it *is* held, and
    is treated as held everywhere it matters.
    """
    if not record.is_held:
        return Cell(RELEASED, Role.MUTED)
    if state.expired:
        return Cell("expired", Role.NOTABLE)
    if record.state != HELD:
        return Cell(record.state, Role.NOTABLE)
    return HELD


def _who(record: LockRecord) -> str:
    """``os_user@host``, or what is left of it. Never a value -- see the record."""
    holder = record.holder
    if holder is None:
        return "unknown"
    return f"{holder.os_user}@{holder.host}"


def _summary(states: Sequence[LockState], found: Sequence[LockState]) -> str:
    """What was examined, and how much of it is in somebody's way.

    Three numbers rather than one, because they answer different questions:
    ``held`` is what would stop a rotation now, ``expired`` is what somebody
    could clear, and the total is what makes the first two a proportion rather
    than a bare count.

    **The proportion counts declared paths only** (#150). A leftover was never in
    the denominator -- it is not a path this configuration would lock -- and
    folding discovered records in would make "3 of 5" move when somebody else's
    estate changed. They are counted afterwards, in their own clause, because
    finding one is a separate thing to have learned.
    """
    declared = [state for state in states if state.declared]
    leftovers = [state for state in found if not state.declared]
    if not declared and not leftovers:
        return "no lock paths are declared"

    held = [state for state in found if state.declared and state.is_held]
    expired = [state for state in held if state.expired]
    body = f"{len(held)} of {len(declared)} declared lock paths held"
    if expired:
        body += f", {len(expired)} past expiry"
    if leftovers:
        held_leftovers = [state for state in leftovers if state.is_held]
        body += (
            f"; {len(leftovers)} record{'' if len(leftovers) == 1 else 's'} "
            f"at paths this config does not declare ({len(held_leftovers)} held)"
        )
    return body

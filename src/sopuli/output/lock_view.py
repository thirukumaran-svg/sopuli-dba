"""The run document's ``lock`` section (``03-json-output.md`` §2, #83).

What a run says about the locks it took, and — on exit 7 — about the one it did
not get. The shape is pinned by ``sopuli-run-1.5.schema.json``; this is the only
producer of it, the same arrangement :mod:`sopuli.output.config_view` and
:mod:`sopuli.output.policy_view` have with their sections.

Two things here are translation rather than transcription.

**The section reports a guarantee, not a mechanism.** ``mode`` is ``cas`` or
``none``, so a consumer branches on whether the run was actually protected
without having to know what KV v1 is. A ``fence`` of ``null`` under ``none`` says
the same thing a second way, and says it per lock.

**A holder is reported differently from how it is stored.** In the record the
correlation id and the command are the *run's* own fields, beside the holder
rather than inside it, because a record describes one run. In the report they are
part of the holder, because there the run being described is somebody else's and
"who is that, and what are they doing" is one question.
"""

from __future__ import annotations

from typing import Any

from sopuli.clock import to_rfc3339
from sopuli.lock.errors import LockDeniedError
from sopuli.lock.manager import HeldLock, LockManager
from sopuli.lock.record import LockRecord


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

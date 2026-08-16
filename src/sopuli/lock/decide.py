"""Whether a lock can be taken, and with which compare-and-set version (#83).

The interesting part of an advisory lock is not the I/O. It is one question --
given what is at the path, what should happen? -- and keeping the answer in a
function of its arguments is what puts the whole expiry and takeover story in
tier 0, where a stolen lock is a version comparison rather than a container and
a sleep (``04-testing.md`` §4).

The four answers, in the order they are reached:

===================================== ==========================================
nothing at the path                   acquire with ``cas: 0``
a ``released`` record                 acquire with ``cas: <version>``
a held record, still good             refuse: exit 7, naming the holder
a held record, past expiry + skew     acquire with ``cas: <version>`` if
                                      ``break_expired``, else refuse
===================================== ==========================================

Every acquisition is a compare-and-set, including the takeover, and that is the
whole safety argument: the write bumps the version, and the version is the fence
the run being broken checks before its next mutation. So a run whose lock was
taken from it finds out before it touches another database, rather than applying
a password the vault no longer advertises.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sopuli.lock.record import CLOCK_SKEW, LockRecord

#: The compare-and-set value that means "there must be nothing here". A KV v2
#: write with ``cas: 0`` succeeds only against a path that has never held a
#: version -- which is why a lock is released by writing rather than deleting: a
#: delete leaves the metadata, and this write could then never succeed again.
FRESH = 0


@dataclass(frozen=True)
class Found:
    """What the store had at the lock path, and the version it was read at."""

    record: LockRecord
    version: int


@dataclass(frozen=True)
class Acquire:
    """Take the lock, with this compare-and-set version.

    ``broke`` is the expired record being taken over, and ``None`` for an
    ordinary acquisition. It exists so the takeover can be *reported*: replacing
    somebody else's lock is the one acquisition an operator may need to hear
    about afterwards, and by the time the write has succeeded the evidence is
    gone from the path.
    """

    cas: int
    broke: LockRecord | None = None

    @property
    def is_takeover(self) -> bool:
        return self.broke is not None


@dataclass(frozen=True)
class Denied:
    """Somebody else has it. Exit 7, and say who.

    ``expired`` distinguishes the two refusals, which need different words: a
    live holder means wait or coordinate, an expired one means the run that took
    it is gone and this needs ``sopuli lock break`` or ``locking.break_expired``.
    Reporting them the same way sends people to break locks that are in use.
    """

    record: LockRecord
    expired: bool


Decision = Acquire | Denied


def decide(
    found: Found | None,
    *,
    now: datetime,
    break_expired: bool = False,
    skew: timedelta = CLOCK_SKEW,
) -> Decision:
    """What to do about the lock at one path.

    ``found`` is ``None`` when the store has no version at the path at all --
    never when it has one it could not parse. An unreadable payload is still a
    lock (:meth:`~sopuli.lock.record.LockRecord.from_dict`), and treating it as
    absent would mean writing over whatever wrote it.

    This never returns "wait". Nothing in the lock design blocks, so there is no
    third outcome for a caller to implement, and a run that loses a lock reports
    it rather than queueing behind it (#83: no ``--lock-wait``, which is what
    makes deadlock impossible rather than rare).
    """
    if found is None:
        return Acquire(cas=FRESH)
    record = found.record
    if not record.is_held:
        return Acquire(cas=found.version)
    if not record.is_expired(now=now, skew=skew):
        return Denied(record=record, expired=False)
    if break_expired:
        return Acquire(cas=found.version, broke=record)
    return Denied(record=record, expired=True)

"""Time, in the two forms the tool writes it and the one it reads back.

RFC 3339 with a trailing ``Z``, always UTC. That is what the run schema's
``timestamp`` type says, and it is now also what a lock record carries -- which
is why these three moved here out of :mod:`sopuli.output.document`. A timestamp
format is not an output concern once something other than output writes one, and
a lock record whose ``expires_at`` were formatted by a second copy of the same
two lines is a lock record that can disagree with the document describing it.

:func:`measure_skew` joined them for #216, and belongs here for the same reason
the formatters do: comparing this host's clock against somebody else's is a
question about time rather than about the store that answered it, and a second
copy of the arithmetic living inside one backend would be a second reading of
what "a minute out" means.

Nothing here reads the clock except :func:`utc_now`, and callers that care about
*when* take a moment as an argument rather than calling it (``04-testing.md`` §4:
tier 0 is pure, and a test that has to sleep is a test that cannot run beside
another one). :func:`measure_skew` is the strongest case for that rule rather
than an exception to it -- it takes both moments, so a five-minute offset is a
test argument instead of a machine somebody has to misconfigure.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


def utc_now() -> datetime:
    """Current time as an aware UTC datetime."""
    return datetime.now(UTC)


def to_rfc3339(moment: datetime) -> str:
    """RFC 3339 with a trailing ``Z``, as the schema's timestamp type requires."""
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def from_rfc3339(text: str) -> datetime:
    """Parse what :func:`to_rfc3339` writes, and anything else RFC 3339 allows.

    ``fromisoformat`` accepts the trailing ``Z`` from Python 3.11, which is this
    project's floor, so there is no hand-rolled parsing to get wrong.

    A timestamp that arrives **without** an offset is read as UTC rather than as
    local time. It should not happen -- everything the tool writes carries the
    ``Z`` -- but the alternative reading is the one that silently mis-times a
    lock by however many hours the reader's machine is offset, and it would do it
    only on machines that are not on UTC. Raising instead was the other candidate
    and is worse: a record that cannot be parsed is a lock that cannot be
    released.
    """
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


@dataclass(frozen=True)
class Skew:
    """How far a remote clock is from this one, and how sure of it we are.

    Three numbers rather than one, because a single figure cannot be acted on.
    A measurement taken over a network is the remote clock *plus* whatever the
    round trip added, and a report that presented the sum as the difference
    would send somebody to fix NTP over a slow link.
    """

    #: The remote clock minus this host's. Positive means the far end is ahead.
    delta: timedelta
    #: How much of :attr:`delta` the measurement cannot account for -- half the
    #: round trip, plus whatever the far end rounds its own answer to.
    uncertain_by: timedelta
    #: What the reading is being judged against, carried so a report can say
    #: which tolerance it applied rather than leaving a reader to assume one.
    tolerance: timedelta

    @property
    def beyond_tolerance(self) -> bool:
        """Whether **no** reading inside the uncertainty band is acceptable.

        Deliberately the conservative half of the comparison. The alternative --
        judging :attr:`delta` alone -- reports a skew warning on a link slow
        enough to account for the whole difference, which is the one failure
        that would make this measurement not worth taking: an operator who once
        chases a clock that was fine stops believing the next one.
        """
        return abs(self.delta) - self.uncertain_by > self.tolerance


def measure_skew(
    *,
    server: datetime,
    local: datetime,
    round_trip: timedelta,
    tolerance: timedelta,
    resolution: timedelta = timedelta(0),
) -> Skew:
    """How far ``server`` is from ``local``, allowing for what the trip cost.

    ``local`` is this host's clock at the **midpoint** of the request, which is
    the best estimate of the instant the far end read its own: the answer was
    formed somewhere inside the round trip, and the middle is the point no
    further than half of it from wherever that was. Hence ``round_trip / 2`` in
    the uncertainty -- it is not a fudge factor but the exact width of what a
    single request cannot narrow down.

    ``resolution`` is what the far end rounds its answer to, and belongs to the
    source rather than to time: HashiCorp's ``sys/health`` reports whole seconds,
    so a reading of 400 ms from it is indistinguishable from zero and must not be
    presented as a measured difference.

    ``tolerance`` has no default on purpose. The number that matters is
    ``sopuli.lock.record.CLOCK_SKEW`` -- the allowance the lock already makes
    when it decides whether a lease has expired -- and this module cannot import
    it without a cycle, since the lock record formats its timestamps here. So it
    arrives from the call site, where a reader can see *which* assumption is
    being measured. A default would quietly answer that question wrongly the
    first time something else asked.
    """
    return Skew(
        delta=server - local,
        uncertain_by=round_trip / 2 + resolution,
        tolerance=tolerance,
    )

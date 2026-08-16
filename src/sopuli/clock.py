"""Time, in the two forms the tool writes it and the one it reads back.

RFC 3339 with a trailing ``Z``, always UTC. That is what the run schema's
``timestamp`` type says, and it is now also what a lock record carries -- which
is why these three moved here out of :mod:`sopuli.output.document`. A timestamp
format is not an output concern once something other than output writes one, and
a lock record whose ``expires_at`` were formatted by a second copy of the same
two lines is a lock record that can disagree with the document describing it.

Nothing here reads the clock except :func:`utc_now`, and callers that care about
*when* take a moment as an argument rather than calling it (``04-testing.md`` §4:
tier 0 is pure, and a test that has to sleep is a test that cannot run beside
another one).
"""

from __future__ import annotations

from datetime import UTC, datetime


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

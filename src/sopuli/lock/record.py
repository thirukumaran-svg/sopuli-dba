"""The document a lock is, and the transitions it goes through.

One record per secret path, written under a ``locks/`` prefix on the same mount
as the secret, so the secret's own version history stays clean for ``previous``
and rollback. It carries who holds it, what they are doing, and until when:

.. code-block:: json

    {"state": "held",
     "correlation_id": "01J...",
     "holder": {"host": "ci-runner-3", "pid": 8821, "os_user": "svc_sopuli"},
     "command": "creds rotate",
     "acquired_at": "...", "expires_at": "...",
     "selection": "env=prod"}

Nothing here reads a clock or a store. A moment arrives as an argument, which is
what lets the whole expiry story be tested without sleeping (``04-testing.md``
§4).

**The record is never deleted.** :meth:`LockRecord.released` produces a
``released`` record to write over the held one. A delete leaves metadata behind
in KV v2, after which a first acquisition can never compare-and-set against
version 0 again -- and the monotonically increasing version *is* the fencing
token, so nothing about this design survives losing it.
"""

from __future__ import annotations

import getpass
import os
import socket
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sopuli.clock import from_rfc3339, to_rfc3339

#: How long a lock is good for before it is a candidate for takeover. Not a
#: config key: a TTL somebody can raise is a TTL that gets raised the first time
#: a run is slow, and the renewal at each target boundary is the answer to a run
#: that legitimately takes longer than this.
DEFAULT_TTL = timedelta(minutes=15)

#: How far past `expires_at` a lock has to be before it counts as expired. Two
#: machines' clocks disagree, and the one that matters here is a CI runner's
#: against a vault's; a minute is enough to cover ordinary drift and short enough
#: that a real takeover is not delayed into another run's window.
CLOCK_SKEW = timedelta(seconds=60)

HELD = "held"
RELEASED = "released"

#: What a field that should have been text says when it was not. A holder nobody
#: can name is still a holder, and reporting it as `unknown` is the difference
#: between a lock somebody can reason about and one that says `None` at them.
UNKNOWN = "unknown"

#: The keys this version writes. Everything else a record carries is preserved
#: rather than dropped -- see :attr:`LockRecord.extra`.
KNOWN_KEYS = (
    "state",
    "correlation_id",
    "holder",
    "command",
    "acquired_at",
    "expires_at",
    "selection",
)


@dataclass(frozen=True)
class Holder:
    """Who holds a lock. Never a credential -- an identity and a process.

    The same three facts ``invocation.actor`` carries about this run, which is
    deliberate: the question at exit 7 is "is that me, a colleague, or something
    that died", and it is only answerable if both ends describe a runner the same
    way.
    """

    host: str
    pid: int
    os_user: str

    def to_dict(self) -> dict[str, Any]:
        return {"host": self.host, "pid": self.pid, "os_user": self.os_user}

    @classmethod
    def from_dict(cls, data: Any) -> Holder | None:
        """Read a holder, or ``None`` if there is nothing readable there.

        Tolerant on the way in and strict on the way out. A record written by
        another version -- or a half-written one -- must still be *reportable*,
        because the alternative is a lock nobody can explain and nobody can
        break. Every field degrades on its own.
        """
        if not isinstance(data, dict):
            return None
        pid = data.get("pid")
        return cls(
            host=_text(data.get("host"), UNKNOWN),
            pid=pid if isinstance(pid, int) and not isinstance(pid, bool) else 0,
            os_user=_text(data.get("os_user"), UNKNOWN),
        )


def current_holder() -> Holder:
    """Describe this process, degrading rather than raising.

    Same shape as :func:`sopuli.output.document.current_actor`, and for the same
    reason: a container with no passwd entry must not be a container that cannot
    take a lock.
    """
    try:
        os_user = getpass.getuser()
    except Exception:  # noqa: BLE001 - no controlling terminal, no passwd entry, etc.
        os_user = UNKNOWN
    try:
        host = socket.gethostname()
    except Exception:  # noqa: BLE001 - a container with no resolvable name
        host = UNKNOWN
    return Holder(host=host, pid=os.getpid(), os_user=os_user)


@dataclass(frozen=True)
class LockRecord:
    """What sits at a lock path.

    ``state`` is ``held`` or ``released``. An unknown value read from a store is
    kept as written and treated as held (see :meth:`is_held`): guessing that an
    unrecognised state means "free" is the one guess that ends with two runs
    rotating one credential. Kept as written *on the way through* -- the two
    methods that produce a new record from this one, :meth:`renewed` and
    :meth:`released`, each state their own, because each is a claim rather than a
    copy.
    """

    state: str
    correlation_id: str
    holder: Holder | None
    command: str
    acquired_at: datetime
    expires_at: datetime
    selection: str | None = None
    #: Keys this version does not know, kept so a renewal does not drop them.
    #:
    #: Renewing rewrites the whole payload, so a record written by a newer sopuli
    #: -- one that has learned a field this one has not -- would come back
    #: narrower than it went in. Sorted pairs rather than a dict, for the reason
    #: :mod:`sopuli.config.model` gives: a frozen dataclass holding a dict is a
    #: landmine, and sorted pairs serialise deterministically.
    extra: tuple[tuple[str, Any], ...] = field(default_factory=tuple)

    @classmethod
    def acquired(
        cls,
        *,
        correlation_id: str,
        command: str,
        holder: Holder,
        now: datetime,
        ttl: timedelta = DEFAULT_TTL,
        selection: str | None = None,
    ) -> LockRecord:
        """A freshly held record, for the write that takes the lock."""
        return cls(
            state=HELD,
            correlation_id=correlation_id,
            holder=holder,
            command=command,
            acquired_at=now,
            expires_at=now + ttl,
            selection=selection,
        )

    def renewed(self, *, now: datetime, ttl: timedelta = DEFAULT_TTL) -> LockRecord:
        """The same lock, good for another ``ttl``.

        ``acquired_at`` deliberately does not move. It answers "how long has this
        been going on", which is the question somebody staring at exit 7 is
        actually asking, and a renewal that reset it would make a run that has
        been stuck for an hour look a minute old.

        **The state becomes ``held``, even if the record read was in a state this
        version does not recognise**, and that is not the same rule as
        :attr:`extra`'s. An unknown *field* is data this version does not
        understand and has no business dropping. The *state* is a claim, and the
        only claim a renewal makes is "I still hold this" -- carrying somebody
        else's vocabulary forward would be asserting a state this build does not
        implement. In practice the two never meet: a renewal is only ever called
        on a record this run wrote, so its state is one of the two here.
        """
        return LockRecord(
            state=HELD,
            correlation_id=self.correlation_id,
            holder=self.holder,
            command=self.command,
            acquired_at=self.acquired_at,
            expires_at=now + ttl,
            selection=self.selection,
            extra=self.extra,
        )

    def released(self) -> LockRecord:
        """The record to write when letting go. Never a delete -- see the module note."""
        return LockRecord(
            state=RELEASED,
            correlation_id=self.correlation_id,
            holder=self.holder,
            command=self.command,
            acquired_at=self.acquired_at,
            expires_at=self.expires_at,
            selection=self.selection,
            extra=self.extra,
        )

    @property
    def is_held(self) -> bool:
        """Whether this record stands in the way of taking the lock.

        Anything that is not ``released`` is held, including a state this version
        has never heard of. The asymmetry is the safe direction: treating an
        unknown state as free means overwriting a lock somebody else is holding
        under a name we have not learned yet.
        """
        return self.state != RELEASED

    def is_expired(self, *, now: datetime, skew: timedelta = CLOCK_SKEW) -> bool:
        """Whether the holder's claim has lapsed, allowing for clock skew.

        Strictly past ``expires_at + skew``: the margin includes its own last
        instant, so a lock is not expired *at* the boundary. One second either
        way changes nothing operationally and everything about whether the rule
        can be stated -- and a boundary that is stated is a boundary a test can
        sit on.
        """
        return now > self.expires_at + skew

    def is_mine(self, correlation_id: str) -> bool:
        """Whether this record is the one this run wrote.

        Half of the fence. The other half is the version, which lives in the
        store rather than in the payload -- a stolen lock usually shows up as a
        version mismatch first, but a run that lost its lock and had it taken by
        another run of the *same* correlation id could not happen, while a
        version that was reused could. Both are checked.
        """
        return self.correlation_id == correlation_id

    def to_dict(self) -> dict[str, Any]:
        """The payload to write. Unknown keys go back the way they came."""
        data: dict[str, Any] = {
            "state": self.state,
            "correlation_id": self.correlation_id,
            "command": self.command,
            "acquired_at": to_rfc3339(self.acquired_at),
            "expires_at": to_rfc3339(self.expires_at),
        }
        if self.holder is not None:
            data["holder"] = self.holder.to_dict()
        if self.selection is not None:
            data["selection"] = self.selection
        data.update(dict(self.extra))
        return data

    @classmethod
    def from_dict(cls, data: Any, *, now: datetime) -> LockRecord:
        """Read whatever is at a lock path, however little of it makes sense.

        Always a record, never a refusal. There is no "this payload is too broken
        to be a lock" answer that is safe to give: the caller's next move on that
        answer would be to write over it, and something wrote it. A payload that
        is not even an object becomes a held record with nothing known about it,
        which blocks exactly as a lock should and is reported as unreadable when
        it does.

        "Nothing is at this path" is a different answer and does not come from
        here -- the store says so by having no version at all.

        Missing timestamps fall back inwards: ``acquired_at`` to ``now``,
        ``expires_at`` to ``acquired_at``. So a record with no readable expiry is
        treated as having expired the moment it was taken -- or, failing that,
        the moment it was first read -- which makes it breakable after the skew
        margin and still only by somebody who asked to break locks. The other
        reading, "no expiry means it never expires", produces a path that can
        only ever be cleared by hand, from one bad write.
        """
        if not isinstance(data, dict):
            data = {}
        acquired = _moment(data.get("acquired_at"), fallback=now)
        return cls(
            state=_text(data.get("state"), HELD),
            correlation_id=_text(data.get("correlation_id"), ""),
            holder=Holder.from_dict(data.get("holder")),
            command=_text(data.get("command"), ""),
            acquired_at=acquired,
            expires_at=_moment(data.get("expires_at"), fallback=acquired),
            selection=_optional_str(data.get("selection")),
            extra=tuple(
                sorted((key, value) for key, value in data.items() if key not in KNOWN_KEYS)
            ),
        )


def _text(value: Any, fallback: str) -> str:
    """A string field, or the fallback for anything that is not one.

    ``str()`` was the obvious spelling and the wrong one: a record carrying
    ``{"host": null}`` would report a holder on a machine called ``"None"``, and
    a state of ``None`` would compare unequal to ``released`` and read as held
    for a reason nobody could see. Coercion invents a value; this admits there
    is not one.
    """
    return value if isinstance(value, str) else fallback


def _moment(value: Any, *, fallback: datetime) -> datetime:
    if not isinstance(value, str):
        return fallback
    try:
        return from_rfc3339(value)
    except ValueError:
        return fallback


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None

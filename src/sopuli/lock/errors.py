"""Why a run stopped over a lock (#83).

Two failures, and they are not the same event. One happens before anything has
been touched; the other happens with a rotation half done, which is the whole
reason the fence exists.

Both carry ``category = "lock"``, which is already a value in the run schema's
``error.category`` enum. The exception says what kind of failure it is rather
than the boundary inferring one from its type -- the same arrangement
:class:`~sopuli.config.errors.ConfigError` uses, and for the same reason.

**Neither carries an exit code**, unlike ``ConfigError``, and that is deliberate.
:class:`LockDeniedError` is exit 7 and always will be. :class:`LockStolenError` is exit 7
when the run had applied nothing and exit 4 -- partial -- when it had, and only
the command knows which of those it is. An exit code attached here would have to
guess, and guessing "7" would tell a scheduler that nothing happened at exactly
the moment something did.
"""

from __future__ import annotations

from sopuli.lock.keys import LockKey
from sopuli.lock.record import LockRecord


class LockError(Exception):
    """A lock stopped the run."""

    category = "lock"

    def __init__(self, message: str, *, key: LockKey, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.key = key
        self.hint = hint

    def __str__(self) -> str:
        if self.hint:
            return f"{self.message}\n  hint: {self.hint}"
        return self.message


class LockDeniedError(LockError):
    """Somebody else holds it. Nothing has been touched; exit 7.

    ``record`` is the holder's own, when there was one to read. It is ``None``
    for the race: the compare-and-set write lost, which means another run
    acquired between this run's read and its write, and that run's record was
    never read. Re-reading it to say who won would be a second round trip to
    answer a question that running again answers better -- so the run schema's
    ``lock.denied.reason`` distinguishes the two instead.
    """

    def __init__(
        self,
        message: str,
        *,
        key: LockKey,
        record: LockRecord | None = None,
        expired: bool = False,
        hint: str | None = None,
    ) -> None:
        super().__init__(message, key=key, hint=hint)
        self.record = record
        self.expired = expired

    @property
    def reason(self) -> str:
        """``held`` or ``race``, as the run schema names them."""
        return "held" if self.record is not None else "race"


class LockStolenError(LockError):
    """The lock this run held is now somebody else's, found at a fence check.

    The failure the whole fencing design exists to catch: this run stalled, its
    lock expired, another run took it over and rotated, and this one was about to
    apply an ``ALTER USER`` from a plan that is no longer true. It stops here
    instead, having mutated nothing further.

    What it does *not* mean is that this run's earlier writes were undone. They
    stand, and `creds check` is what establishes the resulting state -- run by
    whoever holds the lock now.
    """

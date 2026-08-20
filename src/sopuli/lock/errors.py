"""Why a run stopped over a lock (#83, #149).

Three failures, and they are not the same event. One happens before anything has
been touched; the second happens with a rotation half done, which is the whole
reason the fence exists; the third is a store that could never have made a
takeover safe, and it is the one that carries an exit code -- see
:class:`NoFenceError` for why the other two must not.

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

from sopuli.exit_codes import ExitCode
from sopuli.lock.keys import LockKey
from sopuli.lock.record import LockRecord
from sopuli.store.protocol import StoreError


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


class NoFenceError(StoreError):
    """A lock in this store could not be taken from its holder safely. Exit 5.

    Raised at plan time by ``sopuli lock break`` (#149) for a store with no
    compare-and-set -- including one an operator configured
    ``locking: advisory-only``, which is them conceding exactly this. Breaking a
    lock is survivable only because the write bumps the version and the version
    is the fence the broken run checks before its next mutation. Without one,
    "breaking" a lock is deleting somebody's claim while they carry on rotating,
    which is the outcome the whole design exists to prevent.
    :meth:`~sopuli.lock.manager.LockManager.__post_init__` refuses the unattended
    form of this for the same reason.

    **A** :class:`~sopuli.store.protocol.StoreError` **and not a**
    :class:`LockError`, which is the one thing worth explaining. It carries an
    exit code, and the module note above says a lock error deliberately does not
    -- because for those two the right code depends on what the run had already
    applied, and only the command knows. This one has no such ambiguity: it is
    invariant 4's plan-time capability refusal, raised before anything is read or
    written, and 5 is the code that means it whoever is asking. Sitting in the
    hierarchy that already carries ``exit_code`` and ``category`` is what keeps
    that from being a special case at the boundary.
    """

    category = "capability"
    exit_code = ExitCode.UNSUPPORTED_CAPABILITY

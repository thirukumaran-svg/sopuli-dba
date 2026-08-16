"""The advisory lock: what it is keyed on, what it says, and when it may be taken.

P5 requires one; Q2 (#83) decided it lives in the vault, keyed on the secret path
being mutated, compare-and-set guarded, with the store's version as a fencing
token re-checked before every mutation.

This package is the part of that with no store behind it:

* :mod:`sopuli.lock.keys` -- what a lock is keyed on, and the sorted,
  deduplicated order a run takes several in
* :mod:`sopuli.lock.record` -- the document at the lock path, its transitions,
  and expiry with a clock-skew margin
* :mod:`sopuli.lock.decide` -- acquire, take over, or refuse
* :mod:`sopuli.lock.manager` -- the one part that talks to a store: acquire
  every lock before the first mutation, re-read the fence before every mutation
  after it, renew at target boundaries, release in a ``finally``
* :mod:`sopuli.lock.errors` -- the two ways a lock stops a run

Only the manager performs I/O, and only through :mod:`sopuli.store`'s protocol,
which is why the whole of it is still tier 0 against a store that lives in a
dictionary.
"""

from sopuli.lock.decide import Acquire, Decision, Denied, Found, decide
from sopuli.lock.errors import LockDeniedError, LockError, LockStolenError
from sopuli.lock.keys import LockKey, acquisition_order, lock_key, normalise_path
from sopuli.lock.manager import (
    LOCK_PREFIX,
    MODE_CAS,
    MODE_NONE,
    HeldLock,
    LockableStore,
    LockManager,
    lock_path,
)
from sopuli.lock.record import (
    CLOCK_SKEW,
    DEFAULT_TTL,
    HELD,
    RELEASED,
    Holder,
    LockRecord,
    current_holder,
)

__all__ = [
    "CLOCK_SKEW",
    "DEFAULT_TTL",
    "HELD",
    "LOCK_PREFIX",
    "MODE_CAS",
    "MODE_NONE",
    "RELEASED",
    "Acquire",
    "Decision",
    "Denied",
    "Found",
    "HeldLock",
    "Holder",
    "LockDeniedError",
    "LockError",
    "LockKey",
    "LockManager",
    "LockRecord",
    "LockStolenError",
    "LockableStore",
    "acquisition_order",
    "current_holder",
    "decide",
    "lock_key",
    "lock_path",
    "normalise_path",
]

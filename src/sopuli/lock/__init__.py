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

Nothing here performs I/O or reads a clock. The manager that talks to a store,
holds the fence and releases in a ``finally`` is #96; keeping the decisions
separable from it is what puts them in tier 0.
"""

from sopuli.lock.decide import Acquire, Decision, Denied, Found, decide
from sopuli.lock.keys import LockKey, acquisition_order, lock_key, normalise_path
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
    "RELEASED",
    "Acquire",
    "Decision",
    "Denied",
    "Found",
    "Holder",
    "LockKey",
    "LockRecord",
    "acquisition_order",
    "current_holder",
    "decide",
    "lock_key",
    "normalise_path",
]

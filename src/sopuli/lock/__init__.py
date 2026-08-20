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
* :mod:`sopuli.lock.takeover` -- ending somebody else's claim on purpose, which
  is a different question from wanting the lock for yourself (#149)
* :mod:`sopuli.lock.manager` -- the one part that talks to a store: acquire
  every lock before the first mutation, re-read the fence before every mutation
  after it, renew at target boundaries, release in a ``finally``
* :mod:`sopuli.lock.errors` -- the ways a lock stops a run, and the store that
  could never have made breaking one safe

Only the manager performs I/O, and only through :mod:`sopuli.store`'s protocol,
which is why the whole of it is still tier 0 against a store that lives in a
dictionary.
"""

from sopuli.lock.decide import Acquire, Decision, Denied, Found, decide
from sopuli.lock.errors import LockDeniedError, LockError, LockStolenError, NoFenceError
from sopuli.lock.keys import (
    LockKey,
    acquisition_order,
    lock_key,
    normalise_path,
    parse_lock_key,
)
from sopuli.lock.manager import (
    LOCK_PREFIX,
    MODE_CAS,
    MODE_NONE,
    HeldLock,
    LockableStore,
    LockManager,
    describe_holder,
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
from sopuli.lock.takeover import (
    Nothing,
    Outcome,
    Take,
    break_lock,
    check_fenceable,
    plan_break,
)

__all__ = [
    "plan_break",
    "parse_lock_key",
    "describe_holder",
    "check_fenceable",
    "break_lock",
    "Take",
    "Outcome",
    "Nothing",
    "NoFenceError",
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

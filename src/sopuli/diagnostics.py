"""Warnings that carry a code, and the registry of what each code means.

J3 asks for stable machine-readable codes so that consumers branch on a code
rather than grepping a message, and says they get a documented registry. This is
that registry, opened by the first warning that needed one: #83 requires the
``advisory-only`` weakening to appear in **every run's** output rather than only
in the config file, which is only useful if a consumer can recognise it.

**J3 itself stays open.** What is decided here is the spelling ``SOPULI-Wnnn``,
which `03-json-output.md` already used as its example, and that these two
warnings have codes. Whether *every* warning gets one -- the config layer's §10
findings still do not -- and how numbers are allocated across categories is the
part of J3 nobody has answered, and adding two codes does not answer it.

A code, once emitted, is part of the contract in the same way an enum value is
(``03-json-output.md`` §8): adding one is a minor bump, changing what one means
is not a bump at all but a lie. So the registry maps each to a sentence, and
``tests/test_lock_view.py`` asserts that nothing emits a code the registry
does not describe.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from types import MappingProxyType

from sopuli.clock import to_rfc3339
from sopuli.lock.keys import LockKey
from sopuli.lock.manager import LockableStore, LockManager
from sopuli.lock.record import LockRecord
from sopuli.output.document import Diagnostic

#: A store is holding locks it cannot guard (``locking: advisory-only``, #94).
ADVISORY_LOCKING = "SOPULI-W001"

#: A lock past its expiry was taken from whoever held it (``break_expired``).
LOCK_TAKEN_OVER = "SOPULI-W002"

#: Every code this build can emit, and what each one means. The description is
#: the contract; the message wording around it is not, and may improve.
WARNINGS: MappingProxyType[str, str] = MappingProxyType(
    {
        ADVISORY_LOCKING: (
            "A store in this run is configured `locking: advisory-only`, so its lock "
            "record was written without compare-and-set. The run has no fence: two "
            "runs starting in the same second can both believe they hold the lock."
        ),
        LOCK_TAKEN_OVER: (
            "This run took a lock that was past its expiry, which `locking.break_expired` "
            "permits. The previous holder is fenced -- its next check will fail -- but it "
            "may have applied changes before that."
        ),
    }
)


def lock_diagnostics(manager: LockManager) -> list[Diagnostic]:
    """What a run should say about the locks it took.

    Both warnings describe something that *worked*, which is why they are
    warnings and not errors: the run holds its locks, and it holds them on terms
    the operator should be able to see afterwards without going and reading the
    config file or the vault.
    """
    return [
        *_advisory(manager.stores),
        *(_taken_over(one.key, one.broke) for one in manager.held if one.broke is not None),
    ]


def _advisory(stores: Mapping[str, LockableStore]) -> list[Diagnostic]:
    """One warning naming every store that cannot fence.

    One entry rather than one per lock: the weakening is a property of the store,
    and a run holding eleven locks in one advisory store would otherwise say the
    same thing eleven times.
    """
    unfenced = sorted(name for name, entry in stores.items() if not entry.can_fence)
    if not unfenced:
        return []
    return [
        Diagnostic(
            level="warning",
            code=ADVISORY_LOCKING,
            message=(
                f"locking is advisory-only on {_names(unfenced)}: the lock record was "
                f"written without compare-and-set, so two runs in the same second can "
                f"both hold it"
            ),
        )
    ]


def _taken_over(key: LockKey, broke: LockRecord) -> Diagnostic:
    """Somebody's lock was taken. Said out loud, on the run that took it.

    The evidence is gone from the path the moment the takeover write lands, so if
    this run does not report it, nothing ever does.
    """
    holder = broke.holder
    who = "an unknown holder" if holder is None else f"{holder.os_user}@{holder.host}"
    return Diagnostic(
        level="warning",
        code=LOCK_TAKEN_OVER,
        message=(
            f"took over the expired lock on {key}, held by {who} "
            f"since {to_rfc3339(broke.acquired_at)}"
        ),
    )


def _names(names: Sequence[str]) -> str:
    quoted = [f"{name!r}" for name in names]
    if len(quoted) == 1:
        return f"store {quoted[0]}"
    return "stores " + ", ".join(quoted)

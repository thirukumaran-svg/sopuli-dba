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
from sopuli.config.model import Vault
from sopuli.lock.keys import LockKey
from sopuli.lock.manager import LockableStore, LockManager
from sopuli.lock.record import LockRecord
from sopuli.output.document import Diagnostic
from sopuli.store.registry import BACKENDS, installed

#: A store is holding locks it cannot guard (``locking: advisory-only``, #94).
ADVISORY_LOCKING = "SOPULI-W001"

#: A lock past its expiry was taken from whoever held it (``break_expired``).
LOCK_TAKEN_OVER = "SOPULI-W002"

#: A ``vaults:`` entry names a backend whose client is not installed (#130).
MISSING_BACKEND = "SOPULI-W003"

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
        MISSING_BACKEND: (
            "A `vaults:` entry names a backend whose client is not installed. The config "
            "is valid and the install is incomplete, so `config validate` warns and exits "
            "0; any command that resolves that store to a client fails with SOPULI-20001."
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


def backend_diagnostics(vaults: Sequence[Vault]) -> list[Diagnostic]:
    """One warning per configured store whose backend is not installed (E4).

    A **warning**, never an error, and that is the whole decision: the config is
    valid and the install is incomplete. A validator that calls a good file
    broken is less trustworthy for the case it exists to serve, and validating on
    a laptop a config that runs elsewhere is the common case rather than the
    strange one (ADR-006).

    One per vault rather than one per backend type, unlike :func:`_advisory`
    above: the operator's unit of action here is the store they wrote down, and
    two stores of the same missing type are two lines in the file to look at.
    They do share an install command, which the message repeats, because a
    consumer reading one diagnostic out of the array should not have to find the
    other one to learn what to run.

    Asks :func:`~sopuli.store.registry.installed`, which looks a module up
    without importing it -- so this stays safe to call from an offline command,
    which is the only kind that calls it.
    """
    found = []
    for vault in vaults:
        backend = BACKENDS[vault.type]
        if installed(backend):
            continue
        found.append(
            Diagnostic(
                level="warning",
                code=MISSING_BACKEND,
                message=(
                    f'vault "{vault.name}" declares type "{vault.type}", but that backend '
                    f"is not installed; install it with: {backend.install_command}"
                ),
            )
        )
    return found

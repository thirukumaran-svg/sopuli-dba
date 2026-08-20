"""Warnings that carry a code, and the registry of what each code means.

J3 asks for stable machine-readable codes so that consumers branch on a code
rather than grepping a message, and says they get a documented registry. This is
that registry, opened by the first warning that needed one: #83 requires the
``advisory-only`` weakening to appear in **every run's** output rather than only
in the config file, which is only useful if a consumer can recognise it.

**J3 itself stays open**, and the way this registry has grown is the evidence.
What is decided is the spelling ``SOPULI-Wnnn``, which `03-json-output.md`
already used as its example, and that these five warnings have codes: the two
the advisory lock needed (#83), a configured-but-uninstalled backend (#130), a
store that does not verify its certificate (#135), and a store that could not be
listed (#150). Every one was allocated by hand, at the moment something needed
it.

Whether *every* warning gets one -- the config layer's §10 findings still do not
-- and how numbers are allocated across categories is the part of J3 nobody has
answered, and five hand-picked numbers answer it no better than two did.

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
from sopuli.config.model import ExpandedTarget, Vault
from sopuli.config.references import UNVERIFIED_TRANSPORT
from sopuli.driver.registry import DRIVERS
from sopuli.driver.registry import installed as driver_installed
from sopuli.lock.keys import LockKey
from sopuli.lock.manager import LockableStore, LockManager
from sopuli.lock.record import LockRecord
from sopuli.output.document import Diagnostic
from sopuli.store.registry import BACKENDS, installed

#: A store is holding locks it cannot guard (``locking: advisory-only``, #94).
ADVISORY_LOCKING = "SOPULI-W001"

#: A lock was taken from whoever held it -- automatically, because it was past
#: its expiry and ``locking.break_expired`` permits that, or deliberately by
#: ``sopuli lock break`` (#149). One code, because it is one event: what differs
#: is whether a config key or a person decided it, and a consumer alerting on
#: "somebody's lock was taken" wants both.
LOCK_TAKEN_OVER = "SOPULI-W002"

#: A ``vaults:`` entry names a backend whose client is not installed (#130).
MISSING_BACKEND = "SOPULI-W003"

#: A store in the survey has no ``list`` capability, so the report covers only
#: the paths the configuration declares (#150).
UNLISTABLE_STORE = "SOPULI-W005"

#: A ``targets:`` entry names a driver whose client is not installed (#170).
#: Its own code rather than a widening of :data:`MISSING_BACKEND`, whose
#: registered description names a ``vaults:`` entry: one code meaning "some
#: backend or other is missing" would leave a consumer unable to tell a store it
#: cannot reach from a database it cannot reach, which are different outages.
#: Hand-allocated, like #130's pair, and J3 is still open.
MISSING_DRIVER = "SOPULI-W006"

#: ``SOPULI-W004`` -- imported above rather than defined here. It is raised in
#: the config layer, which cannot import this module (see the constant's own
#: comment in :mod:`sopuli.config.references`), so the definition lives with the
#: code that raises it and the registry below stays the one place that says what
#: it means. Importing it here is also what puts it in this module's namespace,
#: so ``from sopuli.diagnostics import UNVERIFIED_TRANSPORT`` reads the same as
#: every other code.

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
            "A lock was taken from its holder: automatically, because it was past its "
            "expiry and `locking.break_expired` permits that, or deliberately by `sopuli "
            "lock break`. The previous holder is fenced -- its next check will fail -- but "
            "it may have applied changes before that."
        ),
        MISSING_BACKEND: (
            "A `vaults:` entry names a backend whose client is not installed. The config "
            "is valid and the install is incomplete, so `config validate` warns and exits "
            "0; any command that resolves that store to a client fails with SOPULI-20001."
        ),
        MISSING_DRIVER: (
            "A `targets:` entry names a driver whose client is not installed. As with a "
            "store, the config is valid and the install is incomplete, so `config "
            "validate` warns and exits 0; any command that connects to that target fails "
            "with SOPULI-20002."
        ),
        UNVERIFIED_TRANSPORT: (
            "A store in this run is configured `tls.verify: false`, so its certificate is "
            "not checked. Anything on the path can present its own and read every secret "
            "that crosses. The key is under the safety ratchet, so no layer can weaken "
            "this further -- but nothing in the run undoes it either."
        ),
        UNLISTABLE_STORE: (
            "A store in this survey has no `list` capability, so `lock status` reported "
            "only the paths this configuration declares. A lock record left at a path the "
            "file no longer names would not appear -- in that store. Everything reported "
            "is accurate; the survey is narrower than it looks."
        ),
    }
)


def unlistable_stores(names: Sequence[str]) -> list[Diagnostic]:
    """Say that part of the survey could not be looked at (#150).

    A **warning and not a refusal**, which is P2's third answer to a missing
    capability and the reason `list` needed one: refusing would make `lock
    status` a command that works on some backends and not others, and an operator
    with one such store would lose the report for every other store as well.

    But it cannot be silent either, and that is the whole point of emitting it.
    An empty `found[]` is something a consumer acts on -- it concludes there are
    no leftover locks -- and that conclusion has to be earned by having looked.
    A survey that could not look at one store and said nothing would be handing
    back the same document as a clean estate.

    One entry naming every such store rather than one each: the operator's
    question is "how much of this did you actually see", which is one question
    however many stores answer it.
    """
    if not names:
        return []
    return [
        Diagnostic(
            level="warning",
            code=UNLISTABLE_STORE,
            message=(
                f"could not list {_names(sorted(names))}: this survey covers the lock "
                f"paths this configuration declares, and a record left at a path it no "
                f"longer names would not appear"
            ),
        )
    ]


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
    """Somebody's lock was taken by a run that wanted it. Said out loud.

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


def lock_broken(key: LockKey, broke: LockRecord, *, expired: bool) -> list[Diagnostic]:
    """Somebody's lock was taken by a person who asked for it (#149).

    The same code as :func:`_taken_over` and a different sentence, which is the
    arrangement §3 already describes: the code is the contract and the wording
    around it is not. Saying "took over the expired lock" here would be wrong
    half the time -- ``lock break --force`` takes a lock that is still live, and
    that is the case somebody reading the audit trail most needs to see named.

    A **warning** rather than an error, for the reason both of this module's lock
    warnings are: nothing failed. The run did exactly what it was asked, and what
    the operator should be able to see afterwards -- without going and reading
    the vault -- is whose claim it ended.

    A list, so that a caller with nothing to report drops it in the same way it
    drops :func:`unlistable_stores`.
    """
    holder = broke.holder
    who = "an unknown holder" if holder is None else f"{holder.os_user}@{holder.host}"
    claim = "expired" if expired else "live"
    return [
        Diagnostic(
            level="warning",
            code=LOCK_TAKEN_OVER,
            message=(
                f"broke the {claim} lock on {key}, held by {who} "
                f"since {to_rfc3339(broke.acquired_at)}; they are fenced and stop at "
                f"their next check"
            ),
        )
    ]


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


def driver_diagnostics(targets: Sequence[ExpandedTarget]) -> list[Diagnostic]:
    """One warning per configured driver that is not installed (E4).

    The same decision as :func:`backend_diagnostics`, for the same reason: the
    config is valid and the install is incomplete, and a validator that calls a
    good file broken is less trustworthy for the case it exists to serve.

    **Over the expanded estate, not the ``targets:`` list.** Most targets are
    generated -- ``01-configuration.md`` §2's own example writes one
    ``target_sets:`` entry and gets twenty-one PDBs -- so counting the explicit
    entries would report a number nobody recognises, and an estate that declares
    *only* generated targets would get no warning at all. Taking
    :class:`~sopuli.config.model.ExpandedTarget` rather than
    :class:`~sopuli.config.model.Target` is what makes that a type error instead
    of a quiet one.

    **One per distinct type, not one per target**, which is where this parts
    company with the store version. Twenty-one PDBs missing ``oracledb`` would
    otherwise be twenty-one identical lines saying to run one command. A store is
    written out by hand and its name is the thing to go and look at; a target may
    not appear in the file at all. So the warning names the type, counts the
    targets, and names one of them as the place to start reading.
    """
    seen: dict[str, list[str]] = {}
    for target in targets:
        if driver_installed(DRIVERS[target.target.type]):
            continue
        seen.setdefault(target.target.type, []).append(target.name)

    found = []
    for type_name, names in sorted(seen.items()):
        driver = DRIVERS[type_name]
        if len(names) > 1:
            subject = f'{len(names)} targets, including "{names[0]}", declare'
        else:
            subject = f'target "{names[0]}" declares'
        found.append(
            Diagnostic(
                level="warning",
                code=MISSING_DRIVER,
                message=(
                    f'{subject} type "{type_name}", but that driver '
                    f"is not installed; install it with: {driver.install_command}"
                ),
            )
        )
    return found

"""Reading lock records the tool did not write.

Everything else in this package is about a lock a run *holds*:
:mod:`sopuli.lock.manager` acquires, renews, fences and releases, and the whole
of it is written from the holder's point of view. ``sopuli lock status`` asks the
other question -- *what is at these paths, and who put it there* -- and that is a
different enough posture to be worth its own module rather than a read-only mode
on the manager.

Three things follow from asking it as an outsider.

**It takes no lock**, as UC-1 §8 states for ``check``, ``status`` and every
``--dry-run``: an hourly survey that locked would block the rotations it is meant
to report on. Nothing here writes.

**It reads the declared set, and then looks beside it.** The declared paths come
from the config's own bindings, run through the same
:func:`sopuli.lock.keys.lock_key` the manager locks on, so "shares a document"
and "shares a lock" cannot give two different answers here either. But a record
left at a path the config no longer declares -- an application renamed, or
removed -- is exactly the one nobody can see and therefore nobody can clear, so
:func:`discover` lists the store's lock prefix and reports what is there under a
key nothing binds.

**A prefix can be declared without its keys being enumerable**. UC-2's
reset locks are keyed on the reset record's path, which no binding produces, and
an account declared by a *predicate* (H1) cannot be named at all without asking
the database -- which this command never does. So the reset region is surveyed
the way :func:`discover` already surveys a store: by listing it and reporting
what is there. That makes a third answer to "whose is this record", because such
a path is neither a binding's nor a leftover, and
:attr:`LockState.declared_by` carries which of the three it is.

**Invariant 5 is not strained by that**, and the distinction is worth being
precise about. The config is the whitelist for what the tool may *touch*; this
command touches nothing, takes no lock, and writes nothing. Reporting a record is
not reaching for the account it guards, and the report marks the difference --
:attr:`LockState.declared` -- rather than quietly mixing the two sets, so nobody
reads a leftover as part of their own estate.

**Nothing is a refusal.** A path with no record is a state, not an error, and so
is a payload that does not parse as a lock:
:meth:`sopuli.lock.record.LockRecord.from_dict` always produces a record, which
is what makes an unreadable lock *reportable* rather than a lock nobody can
explain.
"""

from __future__ import annotations

from collections.abc import Container, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta

from sopuli.clock import utc_now
from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.model import Config
from sopuli.config.vault_env import DEFAULT_STORE_VARIABLE
from sopuli.lock.keys import LockKey, acquisition_order, lock_key, normalise_path
from sopuli.lock.manager import LOCK_PREFIX, MODE_CAS, MODE_NONE, lock_path
from sopuli.lock.record import CLOCK_SKEW, LockRecord
from sopuli.output.debug import logger
from sopuli.store.protocol import CAS, LIST, SecretStore, Stored

LOG = logger("lock")

#: :attr:`LockState.declared_by` for a path an `applications:` or `accounts:`
#: binding names.
BINDING = "binding"

#: :attr:`LockState.declared_by` for a path under the declared `reset_records:`
#: prefix. A string rather than a second boolean because there is no
#: reason to think this is the last region a configuration will claim by prefix:
#: UC-4 hands accounts over through the same delivery abstraction (UC-2 §6.7),
#: and a third boolean would have to be read together with the first two to mean
#: anything.
RESET_RECORDS = "reset_records"


@dataclass(frozen=True)
class ResetRegion:
    """The prefix `reset_records:` claims, as a membership test.

    A store and a prefix, which is all `reset_records:` declares -- one
    destination for the estate, with each record's own path derived from the
    (target, account) pair under it
    (:func:`sopuli.reset_record.record_path`). So the configuration knows the
    region exactly and the keys in it not at all, which is why this is a
    predicate rather than a set of keys.

    Built by :func:`reset_region` from the config, and ``None`` where no
    `reset_records:` block is declared -- where there is no store there is no
    lock, which is the sentence `SOPULI-W024` already says out loud.
    """

    store: str
    prefix: str

    def covers(self, key: LockKey) -> bool:
        """Whether ``key`` is a record path under this prefix.

        Strictly under it: a record written *at* the prefix itself is not one of
        this tool's, because :func:`sopuli.reset_record.record_path` always
        appends a target and an account. Reporting one as a reset lock would
        claim an estate's own leftover on the strength of a shared prefix.
        """
        return key.store == self.store and key.path.startswith(f"{self.prefix}/")


def reset_region(config: Config) -> ResetRegion | None:
    """Where UC-2's reset locks live, or ``None`` when none are declared.

    The prefix arrives already normalised -- `sopuli/config/reset_records.py`
    does it at load, through the same
    :func:`~sopuli.config.secret_refs.normalise_path` that
    :func:`sopuli.reset_record.record_path` builds a record path with -- and it is
    normalised again here, so that this predicate holds against a
    :class:`~sopuli.config.model.ResetRecords` built any other way. The
    alternative is a region whose prefix no key matches, which reports every
    reset lock as somebody else's leftover, and nothing in the output would
    flag it.
    """
    records = config.reset_records
    if records is None:
        return None
    return ResetRegion(store=records.vault, prefix=normalise_path(records.prefix))


@dataclass(frozen=True)
class LockState:
    """One lock path, as somebody who does not hold it sees it.

    ``record`` is ``None`` for a path with nothing at it, which is the ordinary
    state of a path nobody has locked yet -- and, indistinguishably from here, of
    one whose record was deleted rather than released. The store tells those two
    apart only at the next write (see
    :meth:`sopuli.store.protocol.SecretStore.read`), so a survey does not claim
    to.

    ``version`` is the store's version of the record and is deliberately not
    called a fence. A fence is a claim -- *this version is mine* -- and nothing
    here holds one. It is carried because it is what a takeover has to
    compare-and-set against, and because a version that jumps between two
    surveys is a lock somebody else has been renewing.

    It is ``None`` on a store with no compare-and-set, where the number exists
    and guarantees nothing -- the same reason
    :attr:`sopuli.lock.manager.HeldLock.fence` is null under ``mode: none``.
    Reporting KV v1's constant zero as a version would offer a takeover something
    to compare against that compares equal to everything.
    """

    key: LockKey
    record: LockRecord | None
    version: int | None
    expired: bool
    #: How this configuration accounts for the path, or ``None`` for not at all.
    #:
    #: :data:`BINDING` is the ordinary answer: an `applications:` or `accounts:`
    #: entry binds a document here, and the key was enumerated from the file
    #: before any store was opened.
    #:
    #: :data:`RESET_RECORDS` is the third answer. UC-2's reset locks live
    #: under the `reset_records:` prefix, and the file declares the *prefix*
    #: without being able to name the keys under it -- a predicate-declared
    #: personal account (H1) has no name until a database is asked. So the path
    #: was discovered rather than enumerated, and it is still this estate's.
    #:
    #: ``None`` is a record the store holds and the file accounts for nowhere: an
    #: application that was renamed or removed, or another config's estate
    #: sharing the mount. It is the row an operator cannot otherwise see, and it
    #: is marked rather than mixed in, because "this is one of mine" and "this is
    #: a leftover" call for different actions and the survey is the only place
    #: that knows which is which.
    #:
    #: Defaults to :data:`BINDING` so that a caller which never went looking
    #: describes every row it did find correctly, rather than marking the whole
    #: survey as undeclared by omission.
    declared_by: str | None = BINDING

    @property
    def declared(self) -> bool:
        """Whether this configuration accounts for the path at all.

        Derived rather than stored, and kept rather than replaced by
        :attr:`declared_by`: a consumer filtering *its own* locks out of a survey
        wants one boolean, and it means the same whichever region declared the
        path. Removing it would be a major bump under invariant 12 to save a
        consumer nothing.
        """
        return self.declared_by is not None

    @property
    def is_held(self) -> bool:
        """Whether something stands in the way of taking this lock.

        A path with no record is free. Everything else follows
        :attr:`sopuli.lock.record.LockRecord.is_held`, which treats a state this
        build does not recognise as held -- the safe direction, and the same
        answer the manager would give when acquiring.
        """
        return self.record is not None and self.record.is_held


def declared_locks(config: Config) -> tuple[LockKey, ...]:
    """Every lock the configuration could ever take, in acquisition order.

    Invariant 5's set, seen from the lock's side: one key per (store, secret
    path) the file declares, deduplicated -- so six accounts sharing one document
    are one lock here exactly as they are one lock during a rotation.

    A binding with no secret ref contributes nothing: there is no document to
    lock. A binding whose ref names no *store* is the case
    :func:`sopuli.config.bindings._check_has_somewhere_to_resolve_from` leaves
    open on purpose -- a profile or ``SOPULI_VAULT`` may complete it once a run
    picks one -- and this is the command that needs the answer, so it refuses
    here rather than surveying a store it had to guess (invariant 4).

    :func:`resolvable_locks` is the same walk without the refusal, for the one
    caller that does not need it. See its docstring for why that is not this
    function with a flag.
    """
    keys = []
    for binding in config.bindings:
        if binding.secret is None:
            continue
        if binding.vault is None:
            raise ConfigError(
                f"account {binding.account!r} on target {binding.target!r} names no store, "
                f"so there is no lock path to read",
                at=ROOT.key("vaults"),
                hint=(
                    "name a store on the ref, the application entry, an override, the target, "
                    "or `defaults.vault` -- or, for this run only, "
                    f"`--profile <one with vault:>` or {DEFAULT_STORE_VARIABLE}=<store>"
                ),
            )
        keys.append(lock_key(binding.secret, store=binding.vault))
    return acquisition_order(keys)


def resolvable_locks(config: Config) -> tuple[LockKey, ...]:
    """The keys this configuration declares *and* can name a store for.

    For membership, and only for membership: deciding whether a record found in
    a store is one the configuration declares (``declared: false``). A
    binding whose store is unknown cannot match any discovered path -- there is
    no key to compare -- so leaving it out changes no answer, and refusing over
    it answers a question nobody asked.

    That is what `lock status --select` did. It builds two estates: the narrowed
    one it surveys, and the **unfiltered** one that decides what counts as
    declared, because a path a selector excluded is still one the configuration
    declares and reporting it as a leftover would be alarming and wrong. Both
    calls were :func:`declared_locks`, so an estate where one application
    resolves its store from a profile failed on an account in a *different*
    application that the run was never going to survey -- and the narrowed call
    on the next line could not rescue it, because the unfiltered one had already
    raised.

    **A second function rather than a flag**, because :func:`declared_locks`'s
    refusal is the documented point of it: a command that acts on these keys
    must not survey a store it had to guess (invariant 4). A parameter would put
    "and sometimes not" into the docstring that explains why it always does, and
    the caller that wants the refusal off is the one that is not about to act.
    """
    return acquisition_order(
        [
            lock_key(binding.secret, store=binding.vault)
            for binding in config.bindings
            if binding.secret is not None and binding.vault is not None
        ]
    )


@dataclass(frozen=True)
class Discovery:
    """What listing the stores turned up, and where it could not look.

    Two fields because a partial answer has to admit to being one. ``keys`` is
    what was found; ``unlistable`` names the stores that have no ``list``
    capability, and a report that showed the first without the second would
    claim a clean estate on the strength of a store it never asked.
    """

    keys: tuple[LockKey, ...] = ()
    unlistable: tuple[str, ...] = ()


def discover(declared: Iterable[LockKey], *, stores: Mapping[str, SecretStore]) -> Discovery:
    """Lock records in ``stores`` at paths ``declared`` does not name.

    ``declared`` should be the **unfiltered** estate, even when the survey itself
    is narrowed by ``--select``. A path the operator filtered out is still one
    their configuration declares, and reporting it as a leftover because this run
    was not looking at it would be alarming and wrong. Which stores get listed is
    a different question, and it *does* follow the filter: ``stores`` holds the
    ones the narrowed survey opened, so a selector still decides which vaults are
    contacted at all.

    **A store that cannot list is named, not refused** (P2). Refusing would make
    ``lock status`` a command that works on some backends and not others, which
    is worse than a partial answer that says so -- and the caller turns
    ``unlistable`` into the warning that says it.

    **A listed path that :func:`normalise_path` refuses is skipped**, with a
    debug line. Only a hand-made record can have one, since the tool refuses
    such a path in every ref it reads (#858). The tool could neither read nor
    break the record, because the path does not survive the trip into a URL,
    and raising would end ``lock status`` for every other store.
    """
    known = set(declared)
    found: list[LockKey] = []
    unlistable: list[str] = []
    for name, store in sorted(stores.items()):
        if LIST not in store.supports():
            unlistable.append(name)
            continue
        for path in store.list(LOCK_PREFIX):
            try:
                tail = secret_path(path)
            except ValueError as error:
                LOG.debug("skipped lock path %r in %s: %s", path, name, error)
                continue
            key = LockKey(store=name, path=tail)
            if key not in known:
                found.append(key)
    return Discovery(keys=acquisition_order(found), unlistable=tuple(unlistable))


def secret_path(path: str) -> str:
    """:func:`sopuli.lock.manager.lock_path` inverted, for a path read back.

    Normalised on the way out through the same
    :func:`~sopuli.lock.keys.normalise_path` that built the key, so a record
    written under a differently-spelled path -- a doubled separator, a leading
    one -- resolves to the key the config would have produced and is recognised
    as declared rather than reported as a leftover.
    """
    prefix = f"{LOCK_PREFIX}/"
    tail = path[len(prefix) :] if path.startswith(prefix) else path
    return normalise_path(tail)


def survey(
    keys: Iterable[LockKey],
    *,
    stores: Mapping[str, SecretStore],
    declared: Container[LockKey] | None = None,
    region: ResetRegion | None = None,
    now: datetime | None = None,
    skew: timedelta = CLOCK_SKEW,
) -> tuple[LockState, ...]:
    """Read every key, in order, and say what is at it.

    One moment for the whole survey rather than one per read. Two paths read a
    second apart would otherwise be judged against two different clocks, and the
    one thing a reader compares between rows is which of them has expired. That
    is also why discovered keys are surveyed *in the same call* as declared ones
    rather than in a second pass: one clock, one table.

    ``declared`` is the set to judge :attr:`LockState.declared_by` against, and
    ``None`` means every key here is declared -- the answer for a caller that did
    not list the stores.

    ``region`` is consulted only for a key that set does *not* hold, so a
    binding whose document happens to sit under the reset prefix is reported as
    the binding it is. An enumerated declaration is the more specific one, and
    it is the one an operator can act on by name.
    """
    moment = utc_now() if now is None else now
    return tuple(
        _state(key, stores[key.store], now=moment, skew=skew, declared=declared, region=region)
        for key in keys
    )


def _state(
    key: LockKey,
    store: SecretStore,
    *,
    now: datetime,
    skew: timedelta,
    declared: Container[LockKey] | None = None,
    region: ResetRegion | None = None,
) -> LockState:
    declared_by = _declared_by(key, declared=declared, region=region)
    stored: Stored | None = store.read(lock_path(key))
    if stored is None:
        return LockState(key=key, record=None, version=None, expired=False, declared_by=declared_by)
    record = LockRecord.from_dict(stored.data, now=now)
    return LockState(
        key=key,
        record=record,
        version=stored.version if CAS in store.supports() else None,
        # A released record cannot expire: it is not a claim, so there is nothing
        # to lapse. Reporting one as expired would put a red word beside the row
        # that means everything is fine.
        expired=record.is_held and record.is_expired(now=now, skew=skew),
        declared_by=declared_by,
    )


def _declared_by(
    key: LockKey,
    *,
    declared: Container[LockKey] | None,
    region: ResetRegion | None,
) -> str | None:
    """Which of the three answers this key gets, in order of specificity."""
    if declared is None or key in declared:
        return BINDING
    if region is not None and region.covers(key):
        return RESET_RECORDS
    return None


def mode_of(stores: Mapping[str, SecretStore]) -> str:
    """``cas`` or ``none`` for the stores a survey covered.

    The same rule :attr:`sopuli.lock.manager.LockManager.mode` applies, asked of
    stores rather than of a run: ``none`` if *any* of them cannot fence, because
    reporting the strongest of several guarantees is reporting one that does not
    hold. What it means here is one step removed -- no locks were taken, so this
    is the guarantee those stores can give rather than one in force -- and that
    is the same fact either way: whether a lock in this store would mean
    anything.
    """
    if stores and all(CAS in store.supports() for store in stores.values()):
        return MODE_CAS
    return MODE_NONE

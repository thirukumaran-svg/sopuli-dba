"""Holding the locks a run needs, and the fence that makes holding them mean
something.

Everything difficult about this is in :mod:`sopuli.lock.decide`, which is a
function of its arguments. What is here is the part that talks to a store: take
every lock before the first mutation, re-check the fence before every mutation
after it, renew at target boundaries, and let go in a ``finally``.

Four properties are worth stating, because each is a decision rather than an
implementation:

**All-or-nothing, in sorted order, never waiting.** A run acquires every lock it
needs before it mutates anything (UC-1 §8 step 2). Sorting makes deadlock
structurally impossible rather than unlikely; refusing to wait is what makes the
sort sufficient. A partial acquisition releases what it took and reports the one
that stopped it, having applied nothing.

**The fence is re-read, not remembered.** :meth:`LockManager.check` goes back to
the store before every mutating call. A cached "I hold this" is exactly what a
stalled run has, and it is wrong.

**Release never raises.** It runs in a ``finally``, often while another exception
is on its way out, and a release that failed must not replace the reason the run
stopped. It records the failure instead: ``lock.held[].released`` in the run
document is ``false``, which is a fact worth reporting rather than an error worth
raising over.

**`advisory-only` is a different guarantee, and says so.** On a store with no
compare-and-set the record is still written, but there is no fence, and
:attr:`LockManager.mode` reports ``none`` so the run document can say which
guarantee was actually in force.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta

from sopuli.clock import utc_now
from sopuli.config.locking import LOCK_ADVISORY_ONLY, LOCK_REQUIRED
from sopuli.lock.decide import FRESH, Denied, Found, decide
from sopuli.lock.errors import LockDeniedError, LockStolenError, NoFenceError
from sopuli.lock.keys import LockKey, acquisition_order
from sopuli.lock.record import (
    CLOCK_SKEW,
    DEFAULT_TTL,
    Holder,
    LockRecord,
    current_holder,
)
from sopuli.store.protocol import (
    CAS,
    CasConflictError,
    MetadataNotPermittedError,
    SecretStore,
    Stored,
)

#: Where a lock record lives, relative to the mount the secret is on. Under a
#: prefix rather than beside the secret so the secret's own version history stays
#: clean for `previous` and rollback -- `check --include-previous` reads
#: that history, and interleaving lock writes into it would make "one generation
#: back" mean something different.
LOCK_PREFIX = "locks"

#: What `lock.mode` reports: the guarantee, not the mechanism.
MODE_CAS = "cas"
MODE_NONE = "none"


def lock_path(key: LockKey) -> str:
    """Where the record for ``key`` is written."""
    return f"{LOCK_PREFIX}/{key.path}"


@dataclass(frozen=True)
class LockableStore:
    """A store, and whether it is allowed to hold a lock it cannot guard.

    ``locking`` is the config value from ``vaults.<name>.locking``, carried
    here rather than re-read so the manager cannot disagree with what
    ``config show`` displayed.
    """

    store: SecretStore
    locking: str = LOCK_REQUIRED

    @property
    def can_fence(self) -> bool:
        """Whether this store's writes carry a compare-and-set."""
        return CAS in self.store.supports()


@dataclass(frozen=True)
class Unguarded:
    """A lock path this run could not make refuse an un-CAS'd write.

    Carried rather than raised, because the run is no worse off than it was
    before the tool tried: the record it writes still passes a compare-and-set,
    and what is missing is the store enforcing the same on everybody else. The
    command layer turns each of these into a diagnostic
    (:data:`~sopuli.diagnostics.LOCK_PATH_UNGUARDED`).

    ``reason`` is the store's own refusal, kept whole for the reason every
    driver error is: the remedy is in the message the server wrote, and a
    reworded one loses the capability's name.
    """

    key: LockKey
    reason: str


@dataclass
class HeldLock:
    """One lock this run is holding, and everything the run document reports.

    ``fence`` is the version the acquiring write returned and is ``None`` under
    ``advisory-only``, where there is nothing to fence with. ``broke`` is the
    expired record taken over, kept because by the time the write has succeeded
    the evidence is gone from the path.
    """

    key: LockKey
    record: LockRecord
    fence: int | None
    broke: LockRecord | None = None
    released: bool = False


@dataclass
class LockManager:
    """The locks one run holds, from acquisition to release.

    ``now`` is injected so that expiry, renewal and takeover are testable without
    a clock (``04-testing.md`` §4). ``stores`` is keyed by store name, matching
    :attr:`~sopuli.lock.keys.LockKey.store`.
    """

    stores: Mapping[str, LockableStore]
    correlation_id: str
    command: str
    holder: Holder = field(default_factory=current_holder)
    selection: str | None = None
    break_expired: bool = False
    ttl: timedelta = DEFAULT_TTL
    skew: timedelta = CLOCK_SKEW
    now: Callable[[], datetime] = utc_now
    held: list[HeldLock] = field(default_factory=list)
    #: Paths whose metadata this run could not set. Read by the
    #: command layer after :meth:`preflight`, never by the lock itself.
    unguarded: list[Unguarded] = field(default_factory=list)
    #: Told about each lock as it is taken and as it is let go, so a
    #: streamed run can say so at the moment it happens rather than
    #: reconstructing it afterwards. Called with ``"lock.acquired"`` or
    #: ``"lock.released"`` and the lock. **Only a release that worked is
    #: reported**: one that failed leaves ``released: false`` in the run
    #: document, and an event claiming the release would contradict it. Never
    #: allowed to raise into the manager -- it is called from :meth:`release`,
    #: which must not.
    observer: Callable[[str, HeldLock], None] | None = None

    def __post_init__(self) -> None:
        if self.break_expired and any(
            one.locking == LOCK_ADVISORY_ONLY for one in self.stores.values()
        ):
            # The config layer refuses this combination when the file is read.
            # Refusing it here too is not redundant: a manager built any other
            # way -- a test, a new caller -- must not be able to take over a
            # lock with no fence to stop the run it took it from.
            raise ValueError(
                "break_expired cannot be used with a store whose locking is "
                f"{LOCK_ADVISORY_ONLY!r}: there is no fence to make the takeover safe"
            )

    @property
    def mode(self) -> str:
        """``cas`` or ``none`` -- the guarantee in force for this run.

        ``none`` if *any* store in play cannot fence. A run that reports ``cas``
        while one of its locks is advisory would be reporting the strongest of
        its guarantees rather than the one that holds.
        """
        if all(one.can_fence for one in self.stores.values()):
            return MODE_CAS
        return MODE_NONE

    # ------------------------------------------------------------ pre-flight ---

    def preflight(self, keys: Iterable[LockKey]) -> None:
        """Refuse before the first write if a lock here would not mean anything.

        Two checks, and deliberately not a third:

        * a store with no ``cas`` capability must have been configured
          ``locking: advisory-only``, so that the weakening is written down
          somewhere a reviewer sees rather than discovered at rotation time;
        * a lock path whose metadata says ``cas_required: false`` is refused,
          because that is the setting stopping *another* writer -- an operator
          with a vault CLI -- from clobbering the record without a CAS. The tool
          always passes one itself; this is about everybody else.

        A path with **no metadata at all** is the ordinary state before the first
        lock. Left alone, the first acquisition would create the path with
        ``cas_required`` unset, and the check above would refuse every later run
        until somebody set it by hand. So the guarantee is arranged here, with
        :meth:`~sopuli.store.protocol.SecretStore.require_cas`, and the refusal
        above is left for the case it is about: a path somebody else configured
        without one.

        **Where the store will not let it, the run goes ahead and says so**
        (:data:`~sopuli.diagnostics.LOCK_PATH_UNGUARDED`). Setting metadata is a
        separate Vault capability from writing the record, so a token that has
        locked correctly for a year can refuse this one call, and stopping the
        run would break an install over a guarantee it never had. What is lost is
        protection from *other* writers, which is what it was before the tool
        asked -- so the honest report is a warning, and it names the remedy.

        A third check, ``max_versions: 10``, is deliberately **not** enforced.
        Pruning old versions does not reset the version counter, so fencing
        survives any value of it -- refusing a working vault over a housekeeping
        preference would be a guardrail that only costs.

        **Both refuse with** :class:`~sopuli.lock.errors.NoFenceError` **-- exit
        5, not 7**. Neither is a held lock. Both are invariant 4's shape:
        a plan-time fact about what this store and path can guarantee, decided
        before any lock record is read or written -- the second check does read
        the path's *metadata*, which is how it knows -- and true again on the
        next run and the one after that. Exit 7 means "another process holds the
        lock", so an unattended runner meeting a KV v1 mount would retry for ever
        on a condition that can never clear. ``sopuli lock break`` answers 5 for
        the same fact, through :func:`sopuli.lock.takeover.check_fenceable`, so
        both commands give one answer.

        The second check is the arguable one, and it is 5 rather than 9 on
        purpose. ``cas_required: false`` is not *this tool's* configuration being
        invalid -- the file is fine, and exit 9 would send an operator to it --
        it is the store declining to promise the guarantee the lock is made of.
        The remedy is a vault command, the hint gives it, and what a scheduler
        must not do about either is try again.
        """
        for key in acquisition_order(keys):
            entry = self._store(key)
            if not entry.can_fence and entry.locking != LOCK_ADVISORY_ONLY:
                raise NoFenceError(
                    f"{key} cannot be locked: store {key.store!r} has no compare-and-set",
                    hint=(
                        f"set `vaults.{key.store}.locking: {LOCK_ADVISORY_ONLY}` to proceed "
                        f"without one, or move the secret to a store with versioning"
                    ),
                )
            metadata = entry.store.metadata(lock_path(key))
            if not entry.can_fence:
                continue
            if metadata is None:
                self._require_cas(entry, key)
                continue
            if not metadata.cas_required:
                raise NoFenceError(
                    f"{key} cannot be locked safely: its lock path does not require "
                    f"compare-and-set",
                    hint=(
                        "another writer could replace the lock record without one; set "
                        f"`cas_required` on {lock_path(key)!r} in the mount behind "
                        f"`vaults.{key.store}` -- `vault kv metadata put -cas-required=true "
                        f"<mount>/{lock_path(key)}`"
                    ),
                )

    def _require_cas(self, entry: LockableStore, key: LockKey) -> None:
        """Arrange the guarantee on a path that has never been locked.

        Called only where :meth:`preflight` found no metadata, which on a store
        that can fence means the path is new: this run is about to create it, and
        the metadata it creates it with is the one every later run will be
        judged against.

        A refusal is recorded rather than raised, and only that one -- anything
        else is a store failing at a write it accepted the shape of, which is not
        a policy and not this method's to soften.
        """
        try:
            entry.store.require_cas(lock_path(key))
        except MetadataNotPermittedError as refused:
            self.unguarded.append(Unguarded(key=key, reason=str(refused)))

    # ----------------------------------------------------------- acquisition ---

    @contextmanager
    def holding(self, keys: Iterable[LockKey]) -> Iterator[LockManager]:
        """Take every lock, run the body, and let go whatever happens.

        The ``finally`` is the point. UC-1 §8 step 9 releases on success and on
        every error path, and a context manager makes that structural rather than
        something each command has to remember.
        """
        self.acquire(keys)
        try:
            yield self
        finally:
            self.release()

    def acquire(self, keys: Iterable[LockKey]) -> None:
        """Take every lock, in order, or none of them.

        Releases whatever it had already taken before re-raising **whatever
        stopped it** -- so a run that fails part way through acquisition is a run
        that touched nothing, rather than one holding two locks nobody can
        account for. That is usually
        :class:`~sopuli.lock.errors.LockDeniedError`, a race lost; it is also
        every way a store can fail, and each of them unwinds the same way.

        ``keys`` is materialised first because it is walked **twice** -- once by
        :meth:`preflight` and once here -- and the parameter is typed
        :class:`~collections.abc.Iterable`, which a generator satisfies. A
        generator would otherwise be drained by pre-flight, and the loop would
        find it empty and take no lock.
        """
        wanted = tuple(keys)
        self.preflight(wanted)
        for key in acquisition_order(wanted):
            try:
                self.held.append(self._take(key))
            except BaseException:
                # **Anything**, not just a refusal. A refusal is the expected
                # way to lose a lock, but a store that times out, seals, fails
                # over to a standby, or refuses a token that expired between the
                # first key and the second would otherwise leave every lock
                # already taken sitting in the vault as `held` for the full TTL.
                # `holding()` cannot help: it calls this *before* its `try`, so
                # its `finally` never runs when acquisition is what failed.
                #
                # `BaseException` rather than `Exception`, deliberately. A
                # `KeyboardInterrupt` between two acquisitions is exactly the
                # case an operator most wants cleaned up, and re-raising
                # immediately is what keeps that from being a swallowed signal.
                self.release()
                raise
            self._observe("lock.acquired", self.held[-1])

    def _take(self, key: LockKey) -> HeldLock:
        entry = self._store(key)
        moment = self.now()
        decision = decide(
            self._found(entry.store, key, now=moment),
            now=moment,
            break_expired=self.break_expired,
            skew=self.skew,
        )
        if isinstance(decision, Denied):
            raise LockDeniedError(
                f"{key} is locked by {describe_holder(decision.record)}",
                key=key,
                record=decision.record,
                expired=decision.expired,
                hint=_hint_for(decision),
            )

        record = LockRecord.acquired(
            correlation_id=self.correlation_id,
            command=self.command,
            holder=self.holder,
            now=moment,
            ttl=self.ttl,
            selection=self.selection,
        )
        return HeldLock(
            key=key,
            record=record,
            fence=self._write(entry, key, record, cas=decision.cas),
            broke=decision.broke,
        )

    def _write(
        self,
        entry: LockableStore,
        key: LockKey,
        record: LockRecord,
        *,
        cas: int,
        acquiring: bool = True,
    ) -> int | None:
        """Write a record, translating a lost compare-and-set into the right stop.

        ``cas`` is always a version here; it is the *store* call that receives
        ``None`` for it, under ``advisory-only``, because there is no
        compare-and-set to pass. The version such a write returns is not a fence
        either -- nothing guarantees it is still ours a moment later -- so this
        returns ``None`` rather than it, which keeps the caller from comparing a
        guarantee the store cannot give.

        **``acquiring`` decides which failure a lost CAS is**, and the two
        are not the same event. Acquiring, it is a race: two runs went for a lock
        neither held, one of them lost, and nothing has been touched -- exit 7.
        Renewing or releasing, this run *held* the lock and the write says it
        does not any more, which is a takeover: :class:`LockStolenError`, which
        the command layer already knows how to report against what it had
        applied -- exit 4 with the results kept when something had been, exit 7
        when nothing had.

        Reporting every conflict as the first of those would tell a scheduler
        "exit 7, nothing happened" when a takeover landed between :meth:`check`
        and the renewal write, at a moment a database may just have been
        re-passworded.
        """
        try:
            version = entry.store.write(
                lock_path(key), record.to_dict(), cas=cas if entry.can_fence else None
            )
        except CasConflictError as conflict:
            if not acquiring:
                raise LockStolenError(
                    f"{key} was taken over while this run held it: the write was refused "
                    f"against version {cas}",
                    key=key,
                    hint="this run stopped before its next change; `creds check` says what is true",
                ) from conflict
            raise LockDeniedError(
                f"{key} was taken by another run while this one was acquiring it",
                key=key,
                hint=_race_hint(cas),
            ) from conflict
        return version if entry.can_fence else None

    # ----------------------------------------------------- holding and letting go ---

    def check(self, *keys: LockKey) -> None:
        """Assert this run still holds its locks. Call before every mutation.

        The fence, and the reason a vault-side lock was worth choosing over
        ``DBMS_LOCK``: a stalled run's database session is still alive and still
        holds a ``DBMS_LOCK``, so it would prevent nothing here. Two things are
        compared -- the version and the correlation id -- because they fail in
        different ways. A takeover bumps the version; a record rewritten by
        something that reused a version would still not carry this run's id.

        Under ``advisory-only`` there is no version to compare and the id is
        checked alone. That catches an operator minutes apart and misses two jobs
        in the same second, which is exactly the weaker guarantee ``mode: none``
        reports.

        ``keys`` narrows it to the locks guarding what is about to be written,
        and that is what a per-account mutation wants: before changing one
        document, what has to still be ours is *that* document's lock. Checking
        all of them would be a store read per held lock before every
        ``ALTER USER`` -- on an estate of twenty documents, four hundred reads to
        establish twenty facts, nineteen of which the caller was not about to act
        on. Called with no keys it checks everything, which is what :meth:`renew`
        needs, since a renewal writes to every one of them.

        A key this run does not hold **raises** rather than passing quietly. A
        check that verified nothing is worse than no check at all, because the
        caller believes it ran and mutates on the strength of it.
        """
        for one in self._checking(keys):
            entry = self._store(one.key)
            found = self._found(entry.store, one.key, now=self.now())
            if found is None:
                raise LockStolenError(
                    f"{one.key} is gone: the lock record no longer exists",
                    key=one.key,
                    hint="something deleted it; nothing further was applied",
                )
            if one.fence is not None and found.version != one.fence:
                raise LockStolenError(
                    f"{one.key} was taken over: expected version {one.fence}, "
                    f"found {found.version} held by {describe_holder(found.record)}",
                    key=one.key,
                    hint="this run stopped before its next change; `creds check` says what is true",
                )
            if not found.record.is_mine(self.correlation_id):
                raise LockStolenError(
                    f"{one.key} is now held by {describe_holder(found.record)}",
                    key=one.key,
                    hint="this run stopped before its next change; `creds check` says what is true",
                )

    def _checking(self, keys: Sequence[LockKey]) -> list[HeldLock]:
        """The held locks ``check`` was asked about. See its docstring."""
        if not keys:
            return list(self.held)
        held = {one.key: one for one in self.held}
        missing = [key for key in keys if key not in held]
        if missing:
            raise KeyError(
                f"this run does not hold {', '.join(str(key) for key in missing)}; "
                f"held: {', '.join(str(one.key) for one in self.held) or 'nothing'}"
            )
        return [held[key] for key in keys]

    def renew(self) -> None:
        """Extend every held lock, at a target boundary.

        Checks the fence on the way through, because a renewal is a write and
        every write goes behind the same guard. The version the renewal returns
        becomes the new fence.

        The check is not the whole guard, which is why the write says
        ``acquiring=False``. A takeover can land between the check and the
        write, or on lock *n* after lock *1* has already been rewritten, and what
        that is is a takeover -- not the lost race the acquisition path reports.
        """
        self.check()
        moment = self.now()
        for position, one in enumerate(self.held):
            entry = self._store(one.key)
            renewed = one.record.renewed(now=moment, ttl=self.ttl)
            self.held[position] = replace(
                one,
                record=renewed,
                fence=self._write(entry, one.key, renewed, cas=one.fence or 0, acquiring=False),
            )

    def release(self) -> None:
        """Let go of everything, recording what could not be let go of.

        Never raises. It runs in a ``finally``, usually with an exception already
        on its way out, and a store that has gone unreachable must not replace
        the reason the run stopped with a complaint about tidying up.

        A released lock is a *written* record and never a delete: a KV v2 delete
        leaves the metadata, after which a first acquisition can never
        compare-and-set against version 0 again.
        """
        for position, one in enumerate(self.held):
            if one.released:
                continue
            try:
                self._write(
                    self._store(one.key),
                    one.key,
                    one.record.released(),
                    cas=one.fence or 0,
                    acquiring=False,
                )
            except Exception:  # noqa: BLE001 - see the docstring; this is the finally path
                continue
            self.held[position] = replace(one, released=True)
            self._observe("lock.released", self.held[position])

    def _observe(self, event: str, held: HeldLock) -> None:
        """Tell :attr:`observer`, if there is one, and never fail because of it.

        Swallowed rather than raised for :meth:`release`'s reason: it runs on the
        way out of a run, often with an exception already leaving, and a stream
        that could not be written must not replace why the run stopped -- nor
        leave a lock unreleased because reporting an earlier one failed.
        """
        if self.observer is None:
            return
        with suppress(Exception):
            self.observer(event, held)

    # ----------------------------------------------------------------- innards ---

    def _store(self, key: LockKey) -> LockableStore:
        try:
            return self.stores[key.store]
        except KeyError:
            raise KeyError(
                f"no store named {key.store!r}; known: {', '.join(sorted(self.stores))}"
            ) from None

    def _found(self, store: SecretStore, key: LockKey, *, now: datetime) -> Found | None:
        stored: Stored | None = store.read(lock_path(key))
        if stored is None:
            return None
        return Found(record=LockRecord.from_dict(stored.data, now=now), version=stored.version)


def describe_holder(record: LockRecord) -> str:
    """The holder, as a message says it. Never a value -- see the record's shape.

    Public because ``lock break`` refuses in the same words, and it is the
    same question being answered to the same person: *is that me, a colleague, or
    something that died*. Two spellings of one sentence would make the two
    refusals read as two different findings.
    """
    holder = record.holder
    who = (
        "an unknown holder"
        if holder is None
        else f"{holder.os_user}@{holder.host} pid {holder.pid}"
    )
    command = record.command or "an unknown command"
    return f"{who} running {command}"


def _race_hint(cas: int) -> str:
    """Why a compare-and-set write lost, when there are two ways it could have.

    A ``cas: 0`` write fails on a path that has *any* history, so losing one
    means either another run got there first -- the ordinary case -- or somebody
    deleted the lock record, which leaves the metadata behind and the path
    permanently untakeable by a first acquisition. The tool never deletes, so the
    second is always somebody else's doing, and it is worth naming because
    re-running will not fix it.
    """
    if cas != FRESH:
        return "re-run: whichever run won holds it now, and this one changed nothing"
    return (
        "re-run: whichever run won holds it now, and this one changed nothing. If it "
        "keeps failing, the lock record was deleted rather than released -- the path "
        "keeps its version history, so a first acquisition can never succeed again"
    )


def _hint_for(decision: Denied) -> str:
    if decision.expired:
        return (
            "the lock has expired, so its holder is probably gone -- break it deliberately, "
            "or set `locking.break_expired: true` for an unattended runner"
        )
    return "wait for it to finish, or coordinate with whoever is running it"

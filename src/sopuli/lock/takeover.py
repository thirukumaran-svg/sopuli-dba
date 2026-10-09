"""Taking a lock from its holder on purpose, and fencing them.

:mod:`sopuli.lock.decide` answers the same question for a run that wants a lock
for itself, and the two are deliberately not one function. There, a held lock is
an obstacle and the only takeover on offer is an *expired* one under
``locking.break_expired`` -- a config key, for an unattended runner, with nobody
watching. Here there is a person, they typed the path, and the question is not
"may I proceed" but "may I end somebody else's claim". Different question,
different refusals, different evidence to report.

Four things are settled here rather than in the command, because each is a
decision and not plumbing:

**It never deletes.** The write is a ``released`` record over the held one, with
``cas`` set to the version that was read. A KV v2 delete leaves the metadata
behind, after which a first acquisition can never compare-and-set against version
0 again -- and that monotonic version *is* the fence, so a delete would break
every future lock on the path to clear one.

**The compare-and-set is the whole safety argument.** It bumps the version, so
the run that held the lock fails its next fence check and stops before its next
mutation. Breaking a lock is survivable *because* of that, which is why a store
that cannot fence is refused (:class:`~sopuli.lock.errors.NoFenceError`) rather
than served with a weaker version of the same command.

**An expired lock and a live one are different acts.** An expired one is almost
always a process that died, and confirmation is the right gate. A live one is
somebody working, and it takes ``--force`` as well -- the flag decision P3
settled as an audited override of a guardrail that is not a safety setting. The
refusal in between is exit 7 with the holder named, which is the same answer, in
the same words, that a rotation losing the same lock would give.

**Nothing to break is not a failure.** A path with no record, and one whose
record is already ``released``, are both "there is no claim here" -- exit 0,
``changed: false``, and no mutation record. Invariant 9 falls out of that rather
than being arranged: running ``lock break`` twice reports the second run as
having changed nothing, because by then it has not.

What this module does **not** do is decide whether the path is one the
configuration declares. ``lock status`` answers that and needs the whole
binding table to; ``lock break`` acts on one key an operator named, and the
leftover record at a path the file no longer declares is precisely the one they
need to be able to clear. Invariant 5 is untouched: the write lands under the
store's ``locks/`` prefix, in a store ``vaults:`` declares, and never on the
secret the lock guards.
"""

from __future__ import annotations

from dataclasses import dataclass

from sopuli.config.locking import LOCK_ADVISORY_ONLY
from sopuli.lock.errors import LockDeniedError, NoFenceError
from sopuli.lock.inspect import LockState
from sopuli.lock.keys import LockKey
from sopuli.lock.manager import LockableStore, describe_holder, lock_path
from sopuli.lock.record import LockRecord
from sopuli.store.protocol import CasConflictError, SecretStore

#: Nothing has ever been written at the path -- or a record was deleted, which
#: the store cannot tell apart from this and so neither does the report.
ABSENT = "absent"

#: A record is there and it is not a claim. The ordinary state of a path whose
#: last holder let go cleanly, and what a second ``lock break`` finds.
RELEASED = "released"


@dataclass(frozen=True)
class Nothing:
    """There is no claim at this path to take.

    A state rather than a refusal, and the distinction is the point: the operator
    asked for the path to be clear, and it is. ``reason`` says which of the two
    ways it is clear, because "nobody ever locked this" and "the holder let go"
    are different things to have learned about a path you were told was stuck.
    """

    key: LockKey
    reason: str


@dataclass(frozen=True)
class Take:
    """Break this lock, comparing against the version it was read at.

    Carries the whole :class:`~sopuli.lock.inspect.LockState` rather than the
    three fields the write needs, because the *report* needs the rest: by the
    time the write has landed the holder's record is gone from the path, so if
    this run does not describe it, nothing ever does. That is the same argument
    :func:`sopuli.diagnostics._taken_over` makes for ``break_expired``.
    """

    state: LockState

    @property
    def key(self) -> LockKey:
        return self.state.key

    @property
    def record(self) -> LockRecord:
        """The holder's record. Never ``None`` -- :func:`plan_break` returns
        :class:`Nothing` when there is nothing there, so a ``Take`` exists only
        where one was read."""
        record = self.state.record
        if record is None:  # pragma: no cover - plan_break cannot produce this
            raise ValueError("a takeover needs a record to take")
        return record

    @property
    def version(self) -> int:
        """What the write compares against. Never ``None``: a store with no
        compare-and-set was refused by :func:`check_fenceable` before the read."""
        version = self.state.version
        if version is None:  # pragma: no cover - check_fenceable cannot allow this
            raise ValueError("a takeover needs a version to compare against")
        return version


Outcome = Take | Nothing


def check_fenceable(key: LockKey, entry: LockableStore) -> None:
    """Refuse before reading anything if a takeover here could not be made safe.

    Invariant 4's shape: a command that needs an unavailable capability fails at
    **plan time**, with a distinct exit code and a message naming the capability
    and the target -- never a generic error part-way through. So this is asked
    before the record is read, and the operator learns that this store can never
    serve this command rather than that this particular lock could not be taken.

    Two stores fail it and the message differs, because the remedies do. A store
    marked ``locking: advisory-only`` is the operator having already conceded
    there is no fence here, and the only thing to say is what that costs. A
    store that simply has no ``cas`` capability has a remedy: KV v1 can be given
    versioning in place.

    **``advisory-only`` is refused on the declaration, without asking the store
    what it can do**, and the order of the two checks below is that decision. A
    KV v2 mount marked ``advisory-only`` *would* fence -- the manager keys its
    compare-and-set on :attr:`~sopuli.lock.manager.LockableStore.can_fence`, not
    on this key -- so probing first and returning early would let the break
    through. Two reasons not to:

    * :meth:`~sopuli.lock.manager.LockManager.__post_init__` refuses
      ``break_expired`` on this key alone. Two guards over one combination that
      disagree about whether it is allowed is worse than either answer.
    * A guard that second-guesses a declaration by probing behaves differently on
      two configurations that read identically, and the operator cannot see which
      they have from the file.

    What makes the refusal absolute rather than a weaker guarantee is worth
    stating, because it is stronger than "there is no fence". A break writes the
    *holder's own* record transitioned to ``released``, so it keeps their
    ``correlation_id``. On a store that fences, their next
    :meth:`~sopuli.lock.manager.LockManager.check` fails on the version and they
    stop. On a store that does not, ``fence`` is ``None``, the version comparison
    is skipped, and ``is_mine`` still answers *yes* -- so they would carry on
    rotating having never been told. Not a quieter warning: no warning at all.
    """
    if entry.locking == LOCK_ADVISORY_ONLY:
        raise NoFenceError(
            f"{key} cannot be broken: store {key.store!r} is configured "
            f"`locking: {LOCK_ADVISORY_ONLY}`, so a lock here is not a claim to take",
            hint=(
                "breaking a lock is survivable because the write fences its holder, and "
                "this store is declared not to fence. Remove `locking: advisory-only` if "
                "the mount does support compare-and-set, or clear the record with the "
                "store's own client and accept that nothing stops the run that held it"
            ),
        )
    if entry.can_fence:
        return
    raise NoFenceError(
        f"{key} cannot be broken: store {key.store!r} has no compare-and-set",
        hint=(
            "the write that breaks a lock is what fences its holder, and there is nothing "
            "here to fence with; `vault kv enable-versioning` is in place on an existing mount"
        ),
    )


def plan_break(state: LockState, *, force: bool = False) -> Outcome:
    """What ``lock break`` should do about the record at one path.

    Pure, and a function of what was read: the clock has already been applied by
    :func:`sopuli.lock.inspect.survey`, which judged the whole survey against one
    moment. Keeping the answer here rather than in the command is what puts the
    live/expired distinction in tier 0, where it is a comparison rather than a
    container and a sleep (``04-testing.md`` §4).

    Refuses a **live** lock with :class:`~sopuli.lock.errors.LockDeniedError` --
    exit 7, naming the holder, in the same words a rotation losing the same lock
    would use. Somebody is working; the answer is to talk to them, and ``--force``
    is there for when the answer is that they are not.
    """
    if state.record is None:
        return Nothing(key=state.key, reason=ABSENT)
    if not state.record.is_held:
        return Nothing(key=state.key, reason=RELEASED)
    if not state.expired and not force:
        raise LockDeniedError(
            f"{state.key} is held by {describe_holder(state.record)} and has not expired",
            key=state.key,
            record=state.record,
            expired=False,
            hint=(
                "wait for it to finish, or coordinate with whoever is running it. "
                "`--force` breaks a lock that is still live -- the holder is fenced and "
                "stops at its next check, having applied whatever it applied"
            ),
        )
    return Take(state=state)


def break_lock(take: Take, store: SecretStore) -> int:
    """Write the ``released`` record, and return the version that fences.

    The record written is the **holder's own**, transitioned by
    :meth:`~sopuli.lock.record.LockRecord.released`, so every field it carries is
    preserved -- including the ones a newer sopuli wrote and this build does not
    understand. It therefore still names the holder afterwards, and a later
    ``lock status`` cannot tell a break from a clean release.

    That is a real cost and it is the one already accepted for
    ``locking.break_expired``, where the takeover write overwrites the record
    entirely: the path is not the audit trail, the run document is. A break is
    reported by the run that did it, with ``SOPULI-W002`` and a ``lock.broken``
    entry naming the holder it was taken from. Recording the breaker *in the
    record* was the alternative and would have put the same fact in two places
    that can disagree.

    A lost compare-and-set is reported as a race rather than retried. The version
    moved between the read and the write, which means the holder renewed -- they
    are alive, which is the single most useful thing the operator could learn --
    or somebody else broke it first. Either way the plan this write was computed
    from describes a path that no longer exists.
    """
    try:
        return store.write(lock_path(take.key), take.record.released().to_dict(), cas=take.version)
    except CasConflictError as conflict:
        raise LockDeniedError(
            f"{take.key} moved while it was being broken: it was read at version "
            f"{take.version} and something has written since",
            key=take.key,
            hint=(
                "nothing was written. Whoever holds it renewed it -- which means they are "
                "alive -- or somebody else broke it first; `sopuli lock status` says which"
            ),
        ) from conflict

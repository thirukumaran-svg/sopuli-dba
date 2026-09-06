"""Holding locks, and the fence that makes holding them mean something.

Tier 0, and that is the interesting part: every scenario #83 worried about is
here without a container. Two runs contend by sharing one
:class:`~sopuli.store.MemoryStore`; a stalled run is a manager whose clock did
not move; a stolen lock is a version that did.

The fencing case -- steal a lock mid-run and assert the original aborts before
its next mutation -- is the one the release gate ultimately runs against a real
Vault. What it checks is a version comparison, so it belongs here first.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from sopuli.config.locking import LOCK_ADVISORY_ONLY, LOCK_REQUIRED
from sopuli.exit_codes import ExitCode
from sopuli.lock import (
    CLOCK_SKEW,
    DEFAULT_TTL,
    MODE_CAS,
    MODE_NONE,
    Holder,
    LockableStore,
    LockDeniedError,
    LockError,
    LockKey,
    LockManager,
    LockRecord,
    LockStolenError,
    NoFenceError,
    lock_path,
)
from sopuli.store import MemoryStore, PathMetadata, Stored
from sopuli.store.protocol import StoreError

STORE = "vault-prod"
KEY = LockKey(store=STORE, path="apps/acme/db")
OTHER = LockKey(store=STORE, path="apps/beta/db")
NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
HOLDER = Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli")


class Clock:
    """A clock that only moves when a test says so."""

    def __init__(self, now: datetime = NOW) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


def manager(
    store: MemoryStore,
    *,
    correlation_id: str = "01JMINE",
    clock: Clock | None = None,
    locking: str = LOCK_REQUIRED,
    break_expired: bool = False,
) -> LockManager:
    return LockManager(
        stores={STORE: LockableStore(store=store, locking=locking)},
        correlation_id=correlation_id,
        command="creds rotate",
        holder=HOLDER,
        break_expired=break_expired,
        now=clock or Clock(),
    )


def record_at(store: MemoryStore, key: LockKey = KEY) -> dict[str, Any]:
    stored = store.read(lock_path(key))
    assert stored is not None
    return dict(stored.data)


# ------------------------------------------------------------- acquisition ---


def test_a_lock_is_taken_and_the_record_says_who_has_it() -> None:
    store = MemoryStore()

    manager(store).acquire([KEY])

    written = record_at(store)
    assert written["state"] == "held"
    assert written["correlation_id"] == "01JMINE"
    assert written["holder"]["os_user"] == "svc_sopuli"
    assert written["command"] == "creds rotate"


def test_the_record_is_written_under_the_locks_prefix() -> None:
    """Beside the secret would interleave lock writes into the secret's own
    version history, which `previous` and rollback read."""
    store = MemoryStore()

    manager(store).acquire([KEY])

    assert lock_path(KEY) == "locks/apps/acme/db"
    assert store.read("apps/acme/db") is None


def test_the_fence_is_the_version_the_write_returned() -> None:
    store = MemoryStore()
    run = manager(store)

    run.acquire([KEY])

    assert run.held[0].fence == 1
    assert run.mode == MODE_CAS


def test_a_second_run_loses_and_is_told_who_has_it() -> None:
    """The concurrency gate, in the tier where it costs nothing to run."""
    store = MemoryStore()
    manager(store).acquire([KEY])

    with pytest.raises(LockDeniedError) as caught:
        manager(store, correlation_id="01JTHEIRS").acquire([KEY])

    assert caught.value.reason == "held"
    assert not caught.value.expired
    assert "svc_sopuli@ci-runner-3" in str(caught.value)


def test_a_released_lock_can_be_taken_again() -> None:
    store = MemoryStore()
    first = manager(store)
    first.acquire([KEY])
    first.release()

    second = manager(store, correlation_id="01JNEXT")
    second.acquire([KEY])

    assert record_at(store)["correlation_id"] == "01JNEXT"
    assert second.held[0].fence == 3


def test_losing_the_write_race_is_reported_as_a_race_rather_than_a_holder() -> None:
    """Both runs read an empty path; one write lands, the other is refused.

    The interleaving is forced rather than hoped for: the store lets the other
    run acquire during this one's read, which is precisely the window a
    compare-and-set exists to close. There is no holder to report, because the
    winner's record was never read -- which is why the run schema distinguishes
    `reason: race` from `reason: held`.
    """
    winner_ran = False

    class RacingStore(MemoryStore):
        def read(self, path: str, *, version: int | None = None) -> Stored | None:
            nonlocal winner_ran
            answer = super().read(path, version=version)
            if not winner_ran:
                winner_ran = True
                manager(self, correlation_id="01JWINNER").acquire([KEY])
            return answer

    store = RacingStore()

    with pytest.raises(LockDeniedError) as caught:
        manager(store).acquire([KEY])

    assert caught.value.reason == "race"
    assert caught.value.record is None
    assert record_at(store)["correlation_id"] == "01JWINNER"


def test_a_deleted_lock_record_is_refused_with_the_reason_it_cannot_be_taken() -> None:
    """The delete trap, seen from the run that walks into it.

    A deleted path reads as empty, so acquisition tries `cas: 0` -- and fails,
    because the version history stands. Re-running will never fix it, so the hint
    says what happened rather than only "somebody beat you to it". The tool never
    deletes (#83), which is what makes this always somebody else's doing.
    """
    store = MemoryStore()
    run = manager(store)
    run.acquire([KEY])
    store.delete(lock_path(KEY))

    with pytest.raises(LockDeniedError) as caught:
        manager(store, correlation_id="01JNEXT").acquire([KEY])

    assert "deleted rather than released" in str(caught.value)


# ------------------------------------------------------- all or nothing ---


def test_several_locks_are_taken_before_anything_else_happens() -> None:
    store = MemoryStore()
    run = manager(store)

    run.acquire([OTHER, KEY])

    assert [one.key for one in run.held] == [KEY, OTHER]


def test_a_partial_acquisition_gives_back_what_it_took() -> None:
    """A run that loses a race is a run that touched nothing.

    Without this it would hold one lock and refuse to run, which is the shape of
    a deadlock that needs a human -- and the lock it kept would block the run
    that beat it.
    """
    store = MemoryStore()
    manager(store, correlation_id="01JTHEIRS").acquire([OTHER])

    with pytest.raises(LockDeniedError):
        manager(store).acquire([KEY, OTHER])

    assert record_at(store, KEY)["state"] == "released"
    assert record_at(store, OTHER)["correlation_id"] == "01JTHEIRS"


def test_a_store_that_fails_mid_acquisition_gives_back_what_it_took() -> None:
    """#345: the unwind covers every way acquisition can stop, not just a refusal.

    This unwound on `LockDeniedError` alone, which is the *expected* way to lose
    a lock and not the only one. `_take` reads and writes a store, and the
    HashiCorp adapter raises `StoreError` on a timeout, `StoreAuthError` on a
    token that expired between the first key and the second, and
    `StoreUnavailableError` on a sealed vault or a standby failover. None of
    those is a refusal, so every lock already taken stayed `held` in the vault
    for the full TTL -- and `holding()` could not clean up after it, because
    `acquire` runs before its `try`.
    """

    class Flaky(MemoryStore):
        """Fine for the first lock, unreachable for the second."""

        def read(self, path: str, *, version: int | None = None) -> Stored | None:
            if path == lock_path(OTHER):
                raise StoreError("the store went away mid-acquisition")
            return super().read(path, version=version)

    store = Flaky()
    run = manager(store)

    with pytest.raises(StoreError):
        run.acquire([KEY, OTHER])

    assert record_at(store, KEY)["state"] == "released"
    assert [one.released for one in run.held] == [True]


def test_the_body_never_runs_when_acquisition_fails_and_nothing_stays_held() -> None:
    """The same thing through `holding()`, which is how every command takes locks.

    Worth asserting separately: `holding` calls `acquire` **outside** its `try`,
    so the `finally` that releases on every other path is not what saves this
    one. If the unwind ever moves back inside `acquire`'s old `except`, this
    fails while the test above still describes a function nobody calls directly.
    """

    class Flaky(MemoryStore):
        def read(self, path: str, *, version: int | None = None) -> Stored | None:
            if path == lock_path(OTHER):
                raise StoreError("the store went away mid-acquisition")
            return super().read(path, version=version)

    store = Flaky()
    run = manager(store)
    entered = False

    with pytest.raises(StoreError), run.holding([KEY, OTHER]):
        entered = True  # pragma: no cover - the point is that it does not run

    assert not entered
    assert record_at(store, KEY)["state"] == "released"


def test_an_interrupt_during_acquisition_still_gives_the_locks_back() -> None:
    """`BaseException`, not `Exception`, and this is why.

    A `KeyboardInterrupt` between two acquisitions is the case an operator most
    wants tidied up -- they stopped it, and a lock left behind is the thing they
    then have to go and break. Re-raised immediately, so the interrupt is
    cleaned up after rather than swallowed.
    """

    class Interrupted(MemoryStore):
        def read(self, path: str, *, version: int | None = None) -> Stored | None:
            if path == lock_path(OTHER):
                raise KeyboardInterrupt
            return super().read(path, version=version)

    store = Interrupted()
    run = manager(store)

    with pytest.raises(KeyboardInterrupt):
        run.acquire([KEY, OTHER])

    assert record_at(store, KEY)["state"] == "released"


def test_one_secret_reached_twice_is_locked_once() -> None:
    """UC-1 §5's shared secret: without the dedupe the run's second attempt
    would find its own record and report itself as the holder."""
    store = MemoryStore()
    run = manager(store)

    run.acquire([KEY, KEY])

    assert len(run.held) == 1


# --------------------------------------------------------------- the fence ---


def test_a_run_that_still_holds_its_lock_may_carry_on() -> None:
    store = MemoryStore()
    run = manager(store)
    run.acquire([KEY])

    run.check()


def test_a_stolen_lock_stops_the_run_before_its_next_change() -> None:
    """The fencing case, and the reason `DBMS_LOCK` was rejected.

    A stalled run's database session is still alive, so a session-scoped lock
    would prevent none of this. The version moved, and that is what this run sees
    before it touches another database.
    """
    store = MemoryStore()
    clock = Clock()
    stalled = manager(store, clock=clock)
    stalled.acquire([KEY])

    clock.advance(DEFAULT_TTL + CLOCK_SKEW + timedelta(seconds=1))
    taker = manager(store, correlation_id="01JTHEIRS", clock=clock, break_expired=True)
    taker.acquire([KEY])

    with pytest.raises(LockStolenError) as caught:
        stalled.check()

    assert "taken over" in str(caught.value)
    assert caught.value.key == KEY


def test_a_record_rewritten_by_someone_else_is_caught_by_the_correlation_id() -> None:
    """The other half of the fence, for a version that somehow matches.

    Belt and braces: a takeover bumps the version, so the check above normally
    fires first. This one fires when the version does not move -- an unfenced
    write, or a store that reused a number.
    """
    store = MemoryStore()
    run = manager(store)
    run.acquire([KEY])
    theirs = LockRecord.acquired(
        correlation_id="01JTHEIRS", command="creds rotate", holder=HOLDER, now=NOW
    )
    store.write(lock_path(KEY), theirs.to_dict(), cas=None)
    run.held[0].fence = store.read(lock_path(KEY)).version  # type: ignore[union-attr]

    with pytest.raises(LockStolenError) as caught:
        run.check()

    assert "now held by" in str(caught.value)


def test_a_check_can_be_narrowed_to_the_lock_about_to_be_written_under() -> None:
    """#282: before one `ALTER USER`, what has to still be ours is that account's
    own document lock. Checking all of them would be a store read per held lock
    before every statement, to establish facts nothing was about to act on."""
    store = MemoryStore()
    clock = Clock()
    run = manager(store, clock=clock)
    run.acquire([KEY, OTHER])

    clock.advance(DEFAULT_TTL + CLOCK_SKEW + timedelta(seconds=1))
    manager(store, correlation_id="01JTHEIRS", clock=clock, break_expired=True).acquire([OTHER])

    run.check(KEY)

    with pytest.raises(LockStolenError) as caught:
        run.check(OTHER)
    assert caught.value.key == OTHER


def test_checking_everything_is_still_what_no_arguments_means() -> None:
    """`renew` writes to every held lock, so its check has to cover every one."""
    store = MemoryStore()
    clock = Clock()
    run = manager(store, clock=clock)
    run.acquire([KEY, OTHER])

    clock.advance(DEFAULT_TTL + CLOCK_SKEW + timedelta(seconds=1))
    manager(store, correlation_id="01JTHEIRS", clock=clock, break_expired=True).acquire([OTHER])

    with pytest.raises(LockStolenError):
        run.check()


def test_checking_a_lock_this_run_does_not_hold_raises() -> None:
    """Rather than passing quietly, which is worse than not checking at all: the
    caller believes a check ran and mutates on the strength of it."""
    store = MemoryStore()
    run = manager(store)
    run.acquire([KEY])

    with pytest.raises(KeyError) as caught:
        run.check(OTHER)

    assert str(OTHER) in str(caught.value)


def test_a_lock_record_that_vanished_is_a_stolen_lock_too() -> None:
    """Somebody deleted it. The run has no claim any more, whoever did it."""
    store = MemoryStore()
    run = manager(store)
    run.acquire([KEY])
    store.delete(lock_path(KEY))

    with pytest.raises(LockStolenError) as caught:
        run.check()

    assert "no longer exists" in str(caught.value)


# ------------------------------------------------------------------ renewal ---


def test_renewing_extends_the_lock_and_moves_the_fence() -> None:
    store = MemoryStore()
    clock = Clock()
    run = manager(store, clock=clock)
    run.acquire([KEY])
    clock.advance(timedelta(minutes=10))

    run.renew()

    assert run.held[0].fence == 2
    assert record_at(store)["expires_at"].startswith("2026-08-16T12:25")
    assert record_at(store)["acquired_at"].startswith("2026-08-16T12:00")


def test_renewing_a_stolen_lock_fails_rather_than_taking_it_back() -> None:
    """A renewal is a write, and every write goes behind the same guard."""
    store = MemoryStore()
    clock = Clock()
    stalled = manager(store, clock=clock)
    stalled.acquire([KEY])
    clock.advance(DEFAULT_TTL + CLOCK_SKEW + timedelta(seconds=1))
    taker = manager(store, correlation_id="01JTHEIRS", clock=clock, break_expired=True)
    taker.acquire([KEY])

    with pytest.raises(LockStolenError):
        stalled.renew()


def test_a_takeover_between_the_check_and_the_renewal_write_is_a_takeover() -> None:
    """#346. `renew` checks and then writes, and the gap is real.

    The check is not the whole guard: a takeover can land between it and the
    write, or on lock two after lock one has already been rewritten. `_write`
    translated **every** lost compare-and-set into `LockDeniedError` -- exit 7,
    "nothing has been touched" -- in a message saying the run was *acquiring* a
    lock it had held since the first target. Neither half is true of a renewal.
    """
    store = Contested()
    clock = Clock()
    run = manager(store, clock=clock)
    run.acquire([KEY])
    clock.advance(timedelta(minutes=10))

    with pytest.raises(LockStolenError) as caught:
        run.renew()

    assert store.raced, "nobody raced, so this asserts nothing"
    assert "taken over" in str(caught.value)
    assert "acquiring" not in str(caught.value)


class Contested(MemoryStore):
    """Somebody else writes the lock record in the gap `renew` cannot close.

    A real compare-and-set conflict out of the real store rather than a raised
    exception: the interfering write uses the version this run was about to use,
    so the renewal's own CAS is stale by the time it lands -- which is what
    happens when two runs renew the same lock a moment apart.
    """

    def __init__(self) -> None:
        super().__init__()
        self.raced = False

    def write(self, path: str, data: Mapping[str, Any], *, cas: int | None = None) -> int:
        if not self.raced and path == lock_path(KEY) and cas:
            self.raced = True
            theirs = LockRecord.acquired(
                correlation_id="01JTHEIRS", command="creds rotate", holder=HOLDER, now=NOW
            )
            super().write(path, theirs.to_dict(), cas=cas)
        return super().write(path, data, cas=cas)


def test_a_renewed_lock_is_not_taken_over_by_a_run_that_waited() -> None:
    """The reason renewal exists: a long run must not lose its lock for being long."""
    store = MemoryStore()
    clock = Clock()
    run = manager(store, clock=clock)
    run.acquire([KEY])

    clock.advance(timedelta(minutes=10))
    run.renew()
    clock.advance(timedelta(minutes=10))

    with pytest.raises(LockDeniedError):
        manager(store, correlation_id="01JTHEIRS", clock=clock, break_expired=True).acquire([KEY])


# ------------------------------------------------------------------ release ---


def test_releasing_writes_a_record_and_never_removes_one() -> None:
    store = MemoryStore()
    run = manager(store)
    run.acquire([KEY])

    run.release()

    assert record_at(store)["state"] == "released"
    assert run.held[0].released


def test_a_lock_is_released_even_when_the_body_fails() -> None:
    """UC-1 §8 step 9 releases on every path, which is what `holding` encodes."""
    store = MemoryStore()
    run = manager(store)

    with pytest.raises(RuntimeError), run.holding([KEY]):
        raise RuntimeError("the database went away")

    assert record_at(store)["state"] == "released"


def test_a_failed_release_is_recorded_rather_than_raised() -> None:
    """It runs in a `finally`, usually with an exception on its way out.

    A complaint about tidying up must not replace the reason the run stopped --
    so the failure becomes `lock.held[].released: false`, which the run document
    reports.
    """
    store = MemoryStore()
    run = manager(store)
    run.acquire([KEY])
    run.held[0].fence = 99  # the store will refuse this compare-and-set

    run.release()

    assert not run.held[0].released
    assert record_at(store)["state"] == "held"


def test_releasing_twice_writes_once() -> None:
    """`holding` releases, and a command that also released would otherwise
    write a second tombstone and move the version for no reason."""
    store = MemoryStore()
    run = manager(store)
    run.acquire([KEY])

    run.release()
    run.release()

    assert store.read(lock_path(KEY)).version == 2  # type: ignore[union-attr]


# ------------------------------------------------------------ advisory only ---


def advisory(store: MemoryStore, **kwargs: Any) -> LockManager:
    return manager(store, locking=LOCK_ADVISORY_ONLY, **kwargs)


#: Long enough that a loaded machine still gets there, short enough that a
#: mistake fails the test instead of hanging the suite. Nothing waits on real
#: work here -- the other racer is one dictionary lookup away.
BARRIER_TIMEOUT = 10


@dataclass
class ReadsBeforeWrites(MemoryStore):
    """A store that holds every racer's first read until they have all looked.

    The window that makes ``advisory-only`` unsafe: ``acquire`` reads the path
    and then writes it, so two runs both end up holding one lock exactly when
    both reads land before either write. Across two real processes that happens
    when the machine feels like it -- #197 is a tier-1 test that asserted it
    directly, which is a coin flip, and eventually lost the toss.

    A barrier makes it happen every time. It is **not** a race: no outcome here
    depends on which thread the scheduler favours, only on an ordering that is
    imposed. Threads are the mechanism, not the subject -- and they are what
    lets this force the interleaving *for real*, rather than by handing the
    second reader a stale answer and hoping the difference does not matter.

    Two overrides, and both are load-bearing:

    * :meth:`read` waits, **once per thread**. Only the first read is part of
      the window; ``release`` and ``check`` read too, and a barrier they also
      hit would deadlock the moment one racer finished ahead of the other.
    * :meth:`write` takes a lock, because :class:`MemoryStore` has never needed
      to be thread-safe and its compare-and-set is a check followed by an
      increment. Two threads can both pass ``cas == entry.version`` and both
      commit, which would make the contrast below flaky -- the exact failure
      this whole change is about. A real store serialises writes; so does this,
      now that anything calls it from two threads.
    """

    racers: int = 2

    def __post_init__(self) -> None:
        self._barrier = threading.Barrier(self.racers, timeout=BARRIER_TIMEOUT)
        self._writing = threading.Lock()
        self._looked = threading.local()

    def read(self, path: str, *, version: int | None = None) -> Stored | None:
        answer = super().read(path, version=version)
        if not getattr(self._looked, "yet", False):
            self._looked.yet = True
            self._barrier.wait()
        return answer

    def write(self, path: str, data: Any, *, cas: int | None) -> int:
        with self._writing:
            return super().write(path, data, cas=cas)


def acquire_together(*managers: LockManager) -> list[BaseException]:
    """Every manager acquires :data:`KEY` at once, and nothing is swallowed.

    Returns what was raised rather than letting it escape a worker thread,
    where `pytest` would never see it and the test would pass while doing
    nothing.
    """
    raised: list[BaseException] = []

    def take(run: LockManager) -> None:
        try:
            run.acquire([KEY])
        except BaseException as error:  # noqa: BLE001 - reported, not handled
            raised.append(error)

    threads = [threading.Thread(target=take, args=(run,)) for run in managers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=BARRIER_TIMEOUT * 2)
        assert not thread.is_alive(), "a racer never finished acquiring"
    return raised


def test_a_store_without_compare_and_set_still_writes_a_record() -> None:
    """A courtesy that catches operators minutes apart and misses two CI jobs
    in the same second -- which is what `mode: none` tells a consumer."""
    store = MemoryStore(capabilities=frozenset())
    run = advisory(store)

    run.acquire([KEY])

    assert record_at(store)["state"] == "held"
    assert run.mode == MODE_NONE


def test_an_advisory_lock_has_no_fence() -> None:
    """Reporting the version as a fence would be claiming a guarantee this store
    cannot give: nothing says it is still ours a moment later."""
    store = MemoryStore(capabilities=frozenset())
    run = advisory(store)

    run.acquire([KEY])

    assert run.held[0].fence is None


def test_an_advisory_lock_still_catches_another_run() -> None:
    store = MemoryStore(capabilities=frozenset())
    advisory(store).acquire([KEY])

    with pytest.raises(LockDeniedError):
        advisory(store, correlation_id="01JTHEIRS").acquire([KEY])


def test_an_advisory_lock_notices_it_was_overwritten() -> None:
    """All the fence there is without a version: the correlation id."""
    store = MemoryStore(capabilities=frozenset())
    run = advisory(store)
    run.acquire([KEY])
    theirs = LockRecord.acquired(
        correlation_id="01JTHEIRS", command="creds rotate", holder=HOLDER, now=NOW
    )
    store.write(lock_path(KEY), theirs.to_dict(), cas=None)

    with pytest.raises(LockStolenError):
        run.check()


def test_two_advisory_runs_can_hold_one_lock_at_once() -> None:
    """What ``mode: none`` costs, stated as a test rather than as a warning.

    Both runs look at an empty path, both are entitled to take it, and nothing
    stops the second write. That is the concession an operator makes with
    ``locking: advisory-only`` (#94) and it is the reason the mode is reported
    -- a run claiming ``cas`` here would be claiming a guarantee it does not
    have.

    **Tier 0 because only tier 0 can force it** (#197). The window is between a
    racer's read and its write, and no handshake reaches inside ``acquire`` to
    hold it open; two processes released at one instant land in it *sometimes*.
    In one process the store itself can hold the door, which is what this tier
    is for and what the concurrency gate's own header says it is for.
    """
    store = ReadsBeforeWrites(capabilities=frozenset())
    mine = advisory(store)
    theirs = advisory(store, correlation_id="01JTHEIRS")

    assert acquire_together(mine, theirs) == [], "neither run should have been refused"

    assert mine.mode == theirs.mode == MODE_NONE
    assert mine.held[0].fence is None
    assert theirs.held[0].fence is None
    # Two writes to one path, which is the damage: one record is on top and the
    # other run has no way to notice until its next `check`. Which one landed
    # last is the scheduler's business and is deliberately not asserted -- that
    # both were written is the whole finding.
    assert store.paths[lock_path(KEY)].version == 2


def test_the_same_window_produces_one_winner_where_there_is_a_fence() -> None:
    """The contrast that makes the test above about locking rather than about a
    store that was told to lie.

    Identical interleaving -- both racers read the empty path before either
    writes -- against a store that *has* compare-and-set. Both then write with
    `cas: 0`, one of them gets there first, and the other finds a path that is no
    longer empty and is denied. So the window is real in both cases and only the
    fence closes it, which is exactly what `advisory-only` gives up.

    Which run loses is the scheduler's business and is not asserted. That
    *exactly one* does is the property, and it is the one #197 is about: an
    outcome worth asserting is one the ordering cannot change.
    """
    store = ReadsBeforeWrites()

    raised = acquire_together(manager(store), manager(store, correlation_id="01JTHEIRS"))

    assert len(raised) == 1, f"exactly one run must lose: {raised}"
    assert isinstance(raised[0], LockDeniedError)
    assert store.paths[lock_path(KEY)].version == 1, "the loser must not have written"


def test_breaking_expired_locks_is_refused_where_there_is_no_fence() -> None:
    """#94 refuses this combination in the config; a manager built any other way
    must not be able to reach it either."""
    with pytest.raises(ValueError, match="no fence"):
        advisory(MemoryStore(capabilities=frozenset()), break_expired=True)


# --------------------------------------------------------------- pre-flight ---


def test_a_store_that_cannot_lock_is_refused_before_anything_is_written() -> None:
    store = MemoryStore(capabilities=frozenset())

    with pytest.raises(NoFenceError) as caught:
        manager(store).acquire([KEY])

    assert "no compare-and-set" in str(caught.value)
    assert f"vaults.{STORE}.locking: {LOCK_ADVISORY_ONLY}" in str(caught.value)
    assert store.read(lock_path(KEY)) is None


def test_a_lock_path_that_does_not_require_a_compare_and_set_is_refused() -> None:
    """The setting protects against *another* writer -- an operator with a vault
    CLI -- clobbering the record. The tool always passes a CAS itself."""
    store = MemoryStore()
    store.configure(lock_path(KEY), PathMetadata(cas_required=False))

    with pytest.raises(NoFenceError) as caught:
        manager(store).acquire([KEY])

    assert "cas-required" in str(caught.value)


def test_a_pre_flight_refusal_is_a_capability_refusal_and_not_a_held_lock() -> None:
    """#346. Both pre-flight checks used to raise `LockDeniedError`, which the
    boundary maps to exit 7 -- "another process holds the lock".

    Neither is a held lock, and the difference is what a scheduler does next. A
    KV v1 mount nobody marked `locking: advisory-only` is a fact about the store
    that is true again on the next run and the one after that, so exit 7 had an
    unattended runner retrying for ever on a condition that can never clear.
    Exit 5 says the tool cannot do this here, which is invariant 4's answer and
    the one `sopuli lock break` already gave for the identical fact.
    """
    no_cas = MemoryStore(capabilities=frozenset())
    no_promise = MemoryStore()
    no_promise.configure(lock_path(KEY), PathMetadata(cas_required=False))

    for store in (no_cas, no_promise):
        with pytest.raises(NoFenceError) as caught:
            manager(store).acquire([KEY])

        assert caught.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
        assert caught.value.category == "capability"
        # Not a `LockError` at all, which is what keeps the boundary's
        # `LockDeniedError -> 7` mapping from ever seeing one of these.
        assert not isinstance(caught.value, LockError)


def test_a_path_with_no_metadata_at_all_is_fine() -> None:
    """The ordinary state before the first lock is taken."""
    store = MemoryStore()

    manager(store).acquire([KEY])

    assert record_at(store)["state"] == "held"


def test_max_versions_is_not_enforced() -> None:
    """#83 names `max_versions: 10`, and it is deliberately not a refusal.

    Pruning old versions does not reset the version counter, so fencing survives
    any value of it -- refusing a working vault over a housekeeping preference
    would be a guardrail that only costs.
    """
    store = MemoryStore()
    store.configure(lock_path(KEY), PathMetadata(cas_required=True, max_versions=1))

    manager(store).acquire([KEY])

    assert record_at(store)["state"] == "held"

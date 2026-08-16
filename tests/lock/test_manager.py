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

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from sopuli.config.locking import LOCK_ADVISORY_ONLY, LOCK_REQUIRED
from sopuli.lock import (
    CLOCK_SKEW,
    DEFAULT_TTL,
    MODE_CAS,
    MODE_NONE,
    Holder,
    LockableStore,
    LockDeniedError,
    LockKey,
    LockManager,
    LockRecord,
    LockStolenError,
    lock_path,
)
from sopuli.store import MemoryStore, PathMetadata, Stored

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
        def read(self, path: str) -> Stored | None:
            nonlocal winner_ran
            answer = super().read(path)
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


def test_breaking_expired_locks_is_refused_where_there_is_no_fence() -> None:
    """#94 refuses this combination in the config; a manager built any other way
    must not be able to reach it either."""
    with pytest.raises(ValueError, match="no fence"):
        advisory(MemoryStore(capabilities=frozenset()), break_expired=True)


# --------------------------------------------------------------- pre-flight ---


def test_a_store_that_cannot_lock_is_refused_before_anything_is_written() -> None:
    store = MemoryStore(capabilities=frozenset())

    with pytest.raises(LockDeniedError) as caught:
        manager(store).acquire([KEY])

    assert "no compare-and-set" in str(caught.value)
    assert f"vaults.{STORE}.locking: {LOCK_ADVISORY_ONLY}" in str(caught.value)
    assert store.read(lock_path(KEY)) is None


def test_a_lock_path_that_does_not_require_a_compare_and_set_is_refused() -> None:
    """The setting protects against *another* writer -- an operator with a vault
    CLI -- clobbering the record. The tool always passes a CAS itself."""
    store = MemoryStore()
    store.configure(lock_path(KEY), PathMetadata(cas_required=False))

    with pytest.raises(LockDeniedError) as caught:
        manager(store).acquire([KEY])

    assert "cas-required" in str(caught.value)


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

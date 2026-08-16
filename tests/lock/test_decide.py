"""Acquire, take over, or refuse -- every branch, and both sides of each edge.

This is the test the whole package is arranged for. #83's concurrency and
fencing gates ultimately run against a real Vault, but what they check is a
version comparison and a clock, and both are here without a container: the
takeover that fences a zombie is one `decide` call whose `cas` is not 0.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import get_args

import pytest

from sopuli.lock import (
    CLOCK_SKEW,
    DEFAULT_TTL,
    Acquire,
    Decision,
    Denied,
    Found,
    Holder,
    LockRecord,
    decide,
)
from sopuli.lock.decide import FRESH

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
HOLDER = Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli")
VERSION = 41


def held(*, now: datetime = NOW, correlation_id: str = "01JMINE") -> LockRecord:
    return LockRecord.acquired(
        correlation_id=correlation_id,
        command="creds rotate",
        holder=HOLDER,
        now=now,
    )


def found(record: LockRecord, *, version: int = VERSION) -> Found:
    return Found(record=record, version=version)


def test_an_empty_path_is_taken_against_version_zero() -> None:
    """`cas: 0` succeeds only where no version has ever existed.

    Which is the same fact that makes releasing a delete unthinkable: a deleted
    path keeps its metadata, and this write could then never succeed again.
    """
    decision = decide(None, now=NOW)

    assert decision == Acquire(cas=FRESH)


def test_a_released_lock_is_taken_against_the_version_it_was_read_at() -> None:
    """Not `cas: 0` -- the path has a history, and the fence is that counter."""
    decision = decide(found(held().released()), now=NOW)

    assert decision == Acquire(cas=VERSION)
    assert isinstance(decision, Acquire)
    assert not decision.is_takeover


def test_a_live_lock_is_refused_with_its_holder() -> None:
    record = held()

    decision = decide(found(record), now=NOW + timedelta(minutes=5))

    assert decision == Denied(record=record, expired=False)
    assert isinstance(decision, Denied)
    assert decision.record.holder == HOLDER


def test_an_expired_lock_is_still_refused_by_default() -> None:
    """Breaking one is not self-service: the holder may be mid-rotation.

    An expired lock and a live one are refused differently on purpose -- this one
    tells the operator the holder is gone and there is a way to take it.
    """
    record = held()

    decision = decide(found(record), now=NOW + DEFAULT_TTL + CLOCK_SKEW + timedelta(seconds=1))

    assert decision == Denied(record=record, expired=True)


def test_an_expired_lock_is_taken_over_when_that_was_asked_for() -> None:
    """`locking.break_expired`, and the takeover that fences the zombie.

    The write is a compare-and-set against the version just read, so it bumps the
    counter -- and the run that was broken discovers that at its next fence check,
    before its next `ALTER USER`.
    """
    record = held()

    decision = decide(
        found(record),
        now=NOW + DEFAULT_TTL + CLOCK_SKEW + timedelta(seconds=1),
        break_expired=True,
    )

    assert decision == Acquire(cas=VERSION, broke=record)
    assert isinstance(decision, Acquire)
    assert decision.is_takeover


def test_permission_to_break_does_not_touch_a_live_lock() -> None:
    """The setting permits taking an *expired* lock and nothing else.

    Worth its own case because the dangerous misreading -- break_expired as a
    general override -- would pass every other test in this file.
    """
    record = held()

    decision = decide(found(record), now=NOW + timedelta(minutes=5), break_expired=True)

    assert decision == Denied(record=record, expired=False)


def test_permission_to_break_is_irrelevant_to_a_released_lock() -> None:
    decision = decide(found(held().released()), now=NOW, break_expired=True)

    assert decision == Acquire(cas=VERSION)


# ------------------------------------------------------------------- edges ---


@pytest.mark.parametrize("break_expired", [False, True])
def test_the_expiry_boundary_is_where_the_record_says_it_is(break_expired: bool) -> None:
    """Both sides of one second, with and without permission to break.

    The margin includes its own last instant, so a lock at exactly
    `expires_at + skew` is still held -- and a run must not take one a second
    early on a clock that is a second fast.
    """
    record = held()
    edge = NOW + DEFAULT_TTL + CLOCK_SKEW

    assert decide(found(record), now=edge, break_expired=break_expired) == Denied(
        record=record, expired=False
    )

    after = decide(found(record), now=edge + timedelta(seconds=1), break_expired=break_expired)
    assert after == (
        Acquire(cas=VERSION, broke=record) if break_expired else Denied(record=record, expired=True)
    )


def test_a_wider_skew_holds_the_lock_longer() -> None:
    """The margin is an argument, so a caller with a worse clock can say so."""
    record = held()
    just_past = NOW + DEFAULT_TTL + timedelta(minutes=2)

    assert decide(found(record), now=just_past) == Denied(record=record, expired=True)
    assert decide(found(record), now=just_past, skew=timedelta(minutes=5)) == Denied(
        record=record, expired=False
    )


def test_an_unreadable_payload_blocks_rather_than_being_overwritten() -> None:
    """`found=None` means the store had no version, never that it had a bad one.

    Something wrote whatever is there, and the move after "this is not a lock"
    would be to write over it.
    """
    record = LockRecord.from_dict(["not", "a", "record"], now=NOW)

    assert decide(found(record), now=NOW) == Denied(record=record, expired=False)


def test_there_are_two_outcomes_and_neither_of_them_is_waiting() -> None:
    """No third case, and that is the design rather than an omission.

    Nothing blocks, so two runs cannot each hold half of what the other needs --
    which is what makes deadlock impossible rather than rare. A `Wait` member
    added here later would be a change to #83, not an implementation detail, so
    the union is pinned rather than left to be inferred from the branches above.
    """
    assert set(get_args(Decision)) == {Acquire, Denied}

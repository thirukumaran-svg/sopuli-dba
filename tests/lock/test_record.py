"""The document at a lock path: what it says, and what survives a round trip.

Tier 0 and clock-free -- every moment is an argument, so the expiry cases are
arithmetic rather than a sleep.

The round-trip tests carry more weight than they look like they do. A lock record
is written by one process and read by another, possibly a version apart, and the
renewal path rewrites the whole payload: anything this version drops on the way
in is lost on the way out.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sopuli.lock import (
    CLOCK_SKEW,
    DEFAULT_TTL,
    HELD,
    RELEASED,
    Holder,
    LockRecord,
    current_holder,
)

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
HOLDER = Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli")
CORRELATION = "01J8Z5Q2M4K7N9P0R1S2T3V4W5"


def held(**overrides: Any) -> LockRecord:
    fields: dict[str, Any] = {
        "correlation_id": CORRELATION,
        "command": "creds rotate",
        "holder": HOLDER,
        "now": NOW,
        "selection": "env=prod",
    }
    fields.update(overrides)
    return LockRecord.acquired(**fields)


def test_a_new_record_is_held_and_expires_after_the_ttl() -> None:
    record = held()

    assert record.state == HELD
    assert record.is_held
    assert record.acquired_at == NOW
    assert record.expires_at == NOW + DEFAULT_TTL


def test_the_default_ttl_is_fifteen_minutes() -> None:
    """Pinned as a number because UC-1 §8 states it as one.

    Not a config key: a TTL somebody can raise is one that gets raised the first
    time a run is slow, and renewal at each target boundary is the answer to a
    run that legitimately takes longer.
    """
    assert timedelta(minutes=15) == DEFAULT_TTL
    assert timedelta(seconds=60) == CLOCK_SKEW


def test_a_record_carries_who_holds_it_and_what_they_are_doing() -> None:
    """Everything exit 7 needs to answer "is that me, a colleague, or a corpse"."""
    data = held().to_dict()

    assert data["holder"] == {"host": "ci-runner-3", "pid": 8821, "os_user": "svc_sopuli"}
    assert data["command"] == "creds rotate"
    assert data["correlation_id"] == CORRELATION
    assert data["selection"] == "env=prod"


def test_a_record_never_carries_anything_secret() -> None:
    """Invariant 2 from the direction this record could have broken it.

    A lock names an account and a selection, and neither is a value. There is no
    field here a password could sit in, which is the same property `secret_ref`
    has in the run schema.
    """
    assert set(held().to_dict()) <= {
        "state",
        "correlation_id",
        "holder",
        "command",
        "acquired_at",
        "expires_at",
        "selection",
    }


# --------------------------------------------------------------- transitions ---


def test_renewing_moves_the_expiry_and_not_the_acquisition() -> None:
    """`acquired_at` answers "how long has this been going on".

    That is what somebody staring at exit 7 is actually asking, and a renewal
    that reset it would make a run stuck for an hour look a minute old.
    """
    later = NOW + timedelta(minutes=10)

    renewed = held().renewed(now=later)

    assert renewed.acquired_at == NOW
    assert renewed.expires_at == later + DEFAULT_TTL
    assert renewed.correlation_id == CORRELATION


def test_releasing_writes_a_record_rather_than_removing_one() -> None:
    """The delete that must never happen, asserted as the shape that replaces it.

    A KV v2 delete leaves the metadata, after which `cas: 0` fails forever -- and
    the version counter it would strand is the fencing token, so nothing about
    the design survives losing it.
    """
    released = held().released()

    assert released.state == RELEASED
    assert not released.is_held
    assert released.correlation_id == CORRELATION


def test_a_released_record_still_says_who_held_it() -> None:
    """The audit question outlives the lock: `released` is a tombstone with a name."""
    assert held().released().to_dict()["holder"]["os_user"] == "svc_sopuli"


# -------------------------------------------------------------------- expiry ---


def test_a_lock_is_not_expired_before_its_time() -> None:
    assert not held().is_expired(now=NOW + timedelta(minutes=14))


def test_a_lock_is_not_expired_inside_the_skew_margin() -> None:
    """Two clocks disagree, and the vault's is the one that stamped the record."""
    assert not held().is_expired(now=NOW + DEFAULT_TTL + timedelta(seconds=30))


def test_the_margin_includes_its_own_last_instant() -> None:
    """The boundary is stated, so a test can sit exactly on it.

    One second either way changes nothing operationally and everything about
    whether the rule can be written down.
    """
    edge = NOW + DEFAULT_TTL + CLOCK_SKEW

    assert not held().is_expired(now=edge)
    assert held().is_expired(now=edge + timedelta(seconds=1))


def test_a_renewed_lock_is_not_expired_by_the_original_deadline() -> None:
    record = held().renewed(now=NOW + timedelta(minutes=10))

    assert not record.is_expired(now=NOW + DEFAULT_TTL + timedelta(minutes=5))


def test_a_record_knows_whose_it_is() -> None:
    record = held()

    assert record.is_mine(CORRELATION)
    assert not record.is_mine("01JOTHERRUN")


# ---------------------------------------------------------------- round trip ---


def test_a_record_survives_being_written_and_read_back() -> None:
    record = held()

    assert LockRecord.from_dict(record.to_dict(), now=NOW) == record


def test_a_released_record_round_trips_too() -> None:
    record = held().released()

    assert LockRecord.from_dict(record.to_dict(), now=NOW) == record


def test_a_field_this_version_does_not_know_is_kept() -> None:
    """The forward-compatibility property renewal depends on.

    A newer sopuli writes a field this one has never heard of; this one renews
    the lock, rewriting the whole payload. Dropping the unknown key is how a
    fencing field gets silently lost between two versions sharing a vault.
    """
    written = {**held().to_dict(), "fence_hint": 41, "written_by": "0.99.0"}

    record = LockRecord.from_dict(written, now=NOW)
    renewed = record.renewed(now=NOW + timedelta(minutes=1)).to_dict()

    assert renewed["fence_hint"] == 41
    assert renewed["written_by"] == "0.99.0"


def test_an_unknown_state_is_treated_as_held() -> None:
    """The one asymmetry that matters: unrecognised is not free.

    Reading a state this version has not learned as "nobody holds it" is how two
    runs end up rotating one credential; reading it as held costs a refusal an
    operator can act on.
    """
    record = LockRecord.from_dict({**held().to_dict(), "state": "renewing"}, now=NOW)

    assert record.is_held


def test_a_holder_field_that_is_not_text_degrades_rather_than_being_coerced() -> None:
    """`str(None)` is `"None"`, which reads as a machine somebody owns.

    Coercion invents a value; the fallback admits there is not one. The same
    applies to the record's own text fields -- a `state` of `None` coerced to
    `"None"` would compare unequal to `released` and read as held for a reason
    nobody could see.
    """
    holder = Holder.from_dict({"host": None, "pid": None, "os_user": 7})

    assert holder is not None
    assert holder.host == "unknown"
    assert holder.os_user == "unknown"
    assert holder.pid == 0


def test_a_record_field_that_is_not_text_degrades_too() -> None:
    record = LockRecord.from_dict(
        {**held().to_dict(), "state": None, "correlation_id": None}, now=NOW
    )

    assert record.state == HELD
    assert record.correlation_id == ""


def test_a_renewal_states_held_rather_than_carrying_a_state_forward() -> None:
    """The distinction the `extra` rule does not cover.

    An unknown *field* is data this version does not understand and has no
    business dropping. The *state* is a claim, and the only claim a renewal makes
    is "I still hold this" -- carrying an unrecognised state forward would assert
    something this build does not implement.
    """
    read = LockRecord.from_dict({**held().to_dict(), "state": "renewing"}, now=NOW)

    renewed = read.renewed(now=NOW + timedelta(minutes=1))

    assert renewed.state == HELD
    assert read.is_held


def test_a_payload_that_is_not_a_record_at_all_still_blocks() -> None:
    """Something wrote it, and "too broken to be a lock" is not safe to act on.

    The next move on that answer would be to write over it. So it reads as a held
    record with nothing known about it -- and, having no readable expiry, one
    that is breakable after the margin rather than forever.
    """
    record = LockRecord.from_dict("nonsense", now=NOW)

    assert record.is_held
    assert record.holder is None
    assert not record.is_mine(CORRELATION)
    assert record.is_expired(now=NOW + CLOCK_SKEW + timedelta(seconds=1))


def test_a_record_with_no_expiry_is_breakable_rather_than_permanent() -> None:
    """One bad write must not produce a path that only a human can ever clear."""
    written = held().to_dict()
    del written["expires_at"]

    record = LockRecord.from_dict(written, now=NOW)

    assert record.expires_at == record.acquired_at
    assert record.is_expired(now=NOW + CLOCK_SKEW + timedelta(seconds=1))


def test_an_unparseable_timestamp_falls_back_rather_than_raising() -> None:
    """A record that cannot be parsed would be a lock that cannot be released."""
    record = LockRecord.from_dict({**held().to_dict(), "expires_at": "soon"}, now=NOW)

    assert record.expires_at == NOW


def test_a_timestamp_without_an_offset_is_read_as_utc() -> None:
    """Never as local time: that mis-times a lock only on machines off UTC."""
    written = {**held().to_dict(), "expires_at": "2026-08-16T13:00:00"}

    record = LockRecord.from_dict(written, now=NOW)

    assert record.expires_at == datetime(2026, 8, 16, 13, 0, tzinfo=UTC)


def test_a_holder_written_by_something_else_is_read_as_far_as_it_goes() -> None:
    """Tolerant in, strict out. A half-written holder still has to be reportable."""
    holder = Holder.from_dict({"host": "ci-runner-9"})

    assert holder is not None
    assert holder.host == "ci-runner-9"
    assert holder.pid == 0
    assert holder.os_user == "unknown"


# -------------------------------------------------------------- this process ---


def test_the_current_holder_describes_this_process() -> None:
    holder = current_holder()

    assert holder.pid > 0
    assert holder.host
    assert holder.os_user

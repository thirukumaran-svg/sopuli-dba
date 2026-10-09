"""How far a remote clock is from this one, and when that is worth saying.

Tier 0, and pure: :func:`~sopuli.clock.measure_skew` takes both moments and the
round trip as arguments, so every case below is arithmetic rather than a machine
somebody has to misconfigure.

The interesting half is not the subtraction -- it is the **uncertainty**. A
measurement taken over a network is the remote clock plus whatever the trip
added, and the failure worth writing tests against is the one where a slow link
manufactures a skew warning: an operator who once chases a clock that was fine
stops believing the next report, and the next report is the one about the lock.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sopuli.clock import measure_skew
from sopuli.lock.record import CLOCK_SKEW

NOW = datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC)

#: An instant round trip, so a case that is not about latency says so.
INSTANT = timedelta(0)


def test_two_clocks_that_agree_have_no_skew() -> None:
    skew = measure_skew(server=NOW, local=NOW, round_trip=INSTANT, tolerance=CLOCK_SKEW)

    assert skew.delta == timedelta(0)
    assert not skew.beyond_tolerance


def test_a_server_ahead_of_this_host_reads_positive() -> None:
    """The sign is part of the contract: it says which clock to go and fix."""
    skew = measure_skew(
        server=NOW + timedelta(minutes=5), local=NOW, round_trip=INSTANT, tolerance=CLOCK_SKEW
    )

    assert skew.delta == timedelta(minutes=5)
    assert skew.beyond_tolerance


def test_a_server_behind_this_host_reads_negative_and_still_trips() -> None:
    """Both directions are hazards, and only one of them is intuitive.

    A vault behind this host makes locks look older than they are, so this run
    takes over leases that are still live -- the failure the lock's expiry rule
    (UC-1 §8) exists to prevent. Judging `abs(delta)` rather than the raw
    difference is what covers it.
    """
    skew = measure_skew(
        server=NOW - timedelta(minutes=5), local=NOW, round_trip=INSTANT, tolerance=CLOCK_SKEW
    )

    assert skew.delta == timedelta(minutes=-5)
    assert skew.beyond_tolerance


def test_the_tolerance_is_the_one_the_lock_already_assumes() -> None:
    """Not a number of this module's own choosing.

    The whole argument for measuring skew at all is that `sopuli/lock/decide.py`
    compares a lease's expiry against this machine's clock and allows
    `CLOCK_SKEW` for the two disagreeing. A report judged against some other
    figure would be measuring an assumption nothing makes.
    """
    skew = measure_skew(server=NOW, local=NOW, round_trip=INSTANT, tolerance=CLOCK_SKEW)

    assert skew.tolerance == CLOCK_SKEW
    assert timedelta(seconds=60) == CLOCK_SKEW


def test_exactly_at_the_tolerance_is_within_it() -> None:
    """The boundary, spelled out because both readings are defensible.

    `>` and not `>=`: a lock exactly `CLOCK_SKEW` past its expiry is *not* yet
    expired by `LockRecord.is_expired`, so a clock exactly `CLOCK_SKEW` out is
    not yet beyond what the lock tolerates. The two comparisons have to agree, or
    the report warns about a machine whose locks are still being decided
    correctly.
    """
    skew = measure_skew(
        server=NOW + CLOCK_SKEW, local=NOW, round_trip=INSTANT, tolerance=CLOCK_SKEW
    )

    assert not skew.beyond_tolerance


def test_one_second_past_the_tolerance_trips() -> None:
    skew = measure_skew(
        server=NOW + CLOCK_SKEW + timedelta(seconds=1),
        local=NOW,
        round_trip=INSTANT,
        tolerance=CLOCK_SKEW,
    )

    assert skew.beyond_tolerance


# ---------------------------------------------------------------- latency ---
#
# The half that stops this being a subtraction. A single request cannot say
# *when* inside the round trip the far end read its clock, so half the trip is
# the exact width of what the measurement does not know -- not a fudge factor.


def test_a_difference_the_round_trip_can_explain_is_not_a_finding() -> None:
    """Three minutes out over a four-minute round trip says nothing.

    Absurd as a network condition and exactly right as a test: the point is that
    the comparison is against the *unexplained* part of the difference, and a
    case where latency covers the whole of it is the one that fails if it is not.
    """
    skew = measure_skew(
        server=NOW + timedelta(minutes=3),
        local=NOW,
        round_trip=timedelta(minutes=4),
        tolerance=CLOCK_SKEW,
    )

    assert skew.delta == timedelta(minutes=3)
    assert skew.uncertain_by == timedelta(minutes=2)
    assert not skew.beyond_tolerance


def test_latency_cannot_hide_a_clock_that_is_genuinely_out() -> None:
    """The other side of the same rule, which is what stops it being a mute.

    A slow link widens the band; it does not make the band infinite. Ten minutes
    out over a two-minute trip still leaves nine minutes nothing accounts for.
    """
    skew = measure_skew(
        server=NOW + timedelta(minutes=10),
        local=NOW,
        round_trip=timedelta(minutes=2),
        tolerance=CLOCK_SKEW,
    )

    assert skew.beyond_tolerance


def test_the_source_resolution_widens_the_band_too() -> None:
    """A store answering in whole seconds cannot report half of one.

    HashiCorp's `server_time_utc` is epoch seconds, so a reading of 900 ms
    against it is rounding. Reporting that as a measured difference would be
    inventing precision, which is worse than reporting nothing: it is a number
    somebody could act on.
    """
    skew = measure_skew(
        server=NOW + timedelta(milliseconds=900),
        local=NOW,
        round_trip=INSTANT,
        tolerance=timedelta(0),
        resolution=timedelta(seconds=1),
    )

    assert skew.uncertain_by == timedelta(seconds=1)
    assert not skew.beyond_tolerance

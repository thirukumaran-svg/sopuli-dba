"""Rollover: the profile check, the window, the DDL we refuse to issue. Tier 0.

The days literals were read off 26ai Free 23.26.2.0.0 — in particular `.0416`,
which is what `PASSWORD_ROLLOVER_TIME 1/24` reads back as and which the obvious
implementation gets wrong. The seconds literals (`3600`, `86400`, `604800`) and
off's `-1` were read off 19c EE 19.32.0.0.0 on an OCI Base Database Service DB
system. `5184000` and `60` are the 60-day ceiling in each unit, derived
from Oracle's documented bound rather than read back.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from sopuli.driver.oracle.rollover import alter_profile_ddl, days, is_enabled, window_end

#: What `PASSWORD_ROLLOVER_TIME 1/24` actually reads back as.
ONE_HOUR = ".0416"

CHANGED = datetime(2026, 8, 22, 10, 41, 36)


# ------------------------------------------------------------ the limit ---


def test_the_limit_is_a_fraction_of_a_day_and_not_a_count() -> None:
    """The one that bites.

    `PASSWORD_ROLLOVER_TIME 1/24` reads back as `.0416`. Parsing it as an
    integer is the obvious thing to do beside `FAILED_LOGIN_ATTEMPTS`, and it
    refuses a correctly configured profile — the wrong failure, since
    `--strategy rollover` would then be declined on a database that supports it.
    """
    with pytest.raises(ValueError, match="invalid literal for int"):
        int(ONE_HOUR)

    assert days(ONE_HOUR) == pytest.approx(0.0416)
    assert is_enabled(ONE_HOUR)


@pytest.mark.parametrize("limit", ["1", "7", "0.5", ONE_HOUR])
def test_a_positive_limit_grants_a_window(limit: str) -> None:
    assert is_enabled(limit)


@pytest.mark.parametrize("limit", ["0", "0.0", None, "", "UNLIMITED", "FROM ROOT"])
def test_anything_that_is_not_a_positive_number_grants_none(limit: str | None) -> None:
    """`0` is rollover switched off, and the rest are values this code cannot
    read. Both mean "do not promise a window", which is the safe direction: the
    alternative is planning a zero-downtime rotation that has no window."""
    assert not is_enabled(limit)


def test_an_unreadable_limit_is_none_rather_than_zero() -> None:
    """A window length nobody can read is not a window length of zero, and the
    distinction matters to anything reporting *why* the strategy was refused."""
    assert days("FROM ROOT") is None
    assert days("0") == 0.0


# ------------------------------------------------------------ the window ---


def test_the_window_end_is_the_change_date_plus_the_limit() -> None:
    """Derived, because nothing reports it.

    `DBA_*` and the `V$` views were searched for a column named for rollover and
    there is none — so this is Oracle's documented arithmetic over two values
    that *were* read, rather than a guess about behaviour.
    """
    assert window_end(CHANGED, "1") == CHANGED + timedelta(days=1)
    assert window_end(CHANGED, ONE_HOUR) == CHANGED + timedelta(days=0.0416)


@pytest.mark.parametrize(
    ("changed", "limit"),
    [(None, "1"), (CHANGED, None), (CHANGED, "0"), (None, None), (CHANGED, "nonsense")],
)
def test_a_window_end_needs_both_halves(changed: datetime | None, limit: str | None) -> None:
    """11.2 is the case with neither: no `PASSWORD_CHANGE_DATE` and no
    rollover either, so the pair are never both wanted there."""
    assert window_end(changed, limit) is None


# ---------------------------------------------------- the DDL we refuse ---


def test_the_alter_profile_is_reported_and_never_issued() -> None:
    """Q4 decided that the tool never alters a profile, and this is that
    answer: profiles are shared, so changing one affects accounts nobody selected,
    and `02-oracle-privileges.md` §3 keeps `ALTER PROFILE` off the service
    account deliberately.

    A string, because a string is something an operator runs and a driver
    cannot."""
    ddl = alter_profile_ddl("ACME_APP_PROF")

    assert ddl.startswith("ALTER PROFILE ACME_APP_PROF LIMIT PASSWORD_ROLLOVER_TIME")
    assert ddl.endswith(";")


def test_the_reported_ddl_can_name_a_different_window() -> None:
    assert "PASSWORD_ROLLOVER_TIME 7" in alter_profile_ddl("ACME_APP_PROF", "7")


# ------------------------------------------------- values that are not values ---


@pytest.mark.parametrize("limit", ["nan", "inf", "-inf", "1e400", "NaN", "Infinity"])
def test_a_non_finite_limit_is_unreadable_rather_than_a_window(limit: str) -> None:
    """`float()` accepts these, which is what makes them dangerous.

    Left alone, `inf` satisfies `is_enabled` — claiming a window — and then
    raises `OverflowError` the moment `window_end` tries to describe it. So a
    profile holding a value nobody can use would plan a zero-downtime rotation
    and crash while reporting on it.
    """
    assert days(limit) is None
    assert not is_enabled(limit)
    assert window_end(CHANGED, limit) is None


def test_a_limit_no_profile_can_hold_is_unreadable() -> None:
    """Finite, parseable, and outside both renderings of Oracle's one-hour to
    60-day bound. It is not a window at all, because no unit makes it one --
    counting it as one would need an end that cannot be expressed
    (`timedelta(days=1e10)` overflows)."""
    assert days("1e10") is None
    assert not is_enabled("1e10")
    assert window_end(CHANGED, "1e10") is None


# ------------------------------------------- 19.32.0.0.0 reads it in seconds ---


@pytest.mark.parametrize(
    ("limit", "expected_days"),
    [
        # Each one read back on 19.32.0.0.0 from a profile created as:
        ("3600", 1 / 24),  # 1/24
        ("86400", 1.0),  # 1
        ("604800", 7.0),  # 7
        ("5184000", 60.0),  # 60, the ceiling
        # and the same profiles as 26ai renders them:
        (ONE_HOUR, 0.0416),
        ("1", 1.0),
        ("7", 7.0),
        ("60", 60.0),
    ],
)
def test_the_unit_is_read_off_the_value(limit: str, expected_days: float) -> None:
    """One hour to 60 days is `(0, 60]` in days and `[3600, 5184000]` in seconds,
    and the two do not overlap -- so the value names its own unit, and nothing
    asks which release sent it (invariant 3). Read as days, `3600` would be a
    3600-day window, and `finish-rollover` would say `3599d23h left` of a
    one-hour one."""
    assert days(limit) == pytest.approx(expected_days)
    assert is_enabled(limit)


def test_a_seconds_window_ends_an_hour_after_the_change() -> None:
    """A limit of `3600` is seconds: the window ends an hour on, not 3600 days."""
    assert window_end(CHANGED, "3600") == CHANGED + timedelta(hours=1)


@pytest.mark.parametrize("limit", ["-1", "0", "-1.0"])
def test_off_is_disabled_in_both_renderings(limit: str) -> None:
    """26ai reads "off" as `0` and 19.32.0.0.0 as `-1`. `days` maps any value
    at or below zero to DISABLED, so both come back as `0.0`."""
    assert days(limit) == 0.0
    assert not is_enabled(limit)
    assert window_end(CHANGED, limit) is None


@pytest.mark.parametrize("limit", ["61", "120", "3599", "5184001", "604800000"])
def test_a_value_between_or_beyond_the_two_ranges_is_unreadable(limit: str) -> None:
    """Above 60 days and below an hour of seconds, or past 60 days of seconds:
    no profile holds it, so guessing a unit would be inventing a window."""
    assert days(limit) is None
    assert not is_enabled(limit)

"""The decision table behind `creds check` (#248).

UC-1 §7 is mostly about what *not* to do -- do not retry, do not attempt a login
near the lockout limit, do not fold a locked account into drift -- and this is
where those rules become one answer. Pure, so the interesting cases can be
written down rather than reproduced against a database: an account that is locked
*and* has the wrong password is a two-line test here and a fixture there.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sopuli import check
from sopuli.driver.protocol import (
    FAIL,
    PASS,
    SKIPPED,
    UNAVAILABLE,
    VERIFY_LOGIN,
    UserState,
    VerifyResult,
)
from sopuli.exit_codes import ExitCode

NOW = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)


def user(**fields: object) -> UserState:
    base: dict[str, object] = {"name": "ACME_WEB_USER", "status": "OPEN"}
    return UserState(**{**base, **fields})  # type: ignore[arg-type]


def attempt(result: str, **fields: object) -> VerifyResult:
    return VerifyResult(method=VERIFY_LOGIN, result=result, **fields)  # type: ignore[arg-type]


# ------------------------------------------------------- the ordinary answers ---


def test_a_password_that_works_is_in_sync() -> None:
    outcome = check.decide(user(), attempt(PASS), version=7)

    assert outcome.state == check.IN_SYNC
    assert "v7" in outcome.detail


def test_a_password_that_is_rejected_is_drift() -> None:
    outcome = check.decide(user(), attempt(FAIL, detail="ORA-01017"), version=7)

    assert outcome.state == check.DRIFT
    assert "ORA-01017" in outcome.detail


def test_an_account_the_database_does_not_have() -> None:
    """Out of scope to create it (Q8): `check` reports and `apply` refuses."""
    assert check.decide(None, None).state == check.ACCOUNT_MISSING


# ------------------------------------------------ status outranks the attempt ---


def test_a_locked_account_is_locked_and_not_drift() -> None:
    """Mitigation 6. The lock is both more urgent and the *cause* of what a login
    would have seen, so reporting the symptom would have somebody rotating a
    credential that was never the problem."""
    outcome = check.decide(user(status="LOCKED", locked=True), attempt(FAIL))

    assert outcome.state == check.LOCKED
    assert "not tried" in outcome.detail


def test_an_expired_password_is_expired_and_not_drift() -> None:
    outcome = check.decide(user(status="EXPIRED", expired=True), attempt(FAIL))

    assert outcome.state == check.EXPIRED


def test_a_locked_account_whose_password_is_right_is_still_locked() -> None:
    """The half that proves status is checked *first* rather than as a fallback:
    a `pass` must not turn a locked account into `IN_SYNC`."""
    assert check.decide(user(status="LOCKED", locked=True), attempt(PASS)).state == check.LOCKED


# ------------------------------------------------------------ the lockout guard ---


def test_a_declined_login_is_unverifiable_and_keeps_its_reason() -> None:
    """The state that says "we chose not to try". A result with no reason
    attached is indistinguishable at 03:00 from a run that did nothing, so the
    driver's own sentence is carried rather than re-phrased here."""
    outcome = check.decide(
        user(),
        attempt(SKIPPED, detail="lcount 8 of 10, within lockout margin", lockout_margin_hit=True),
    )

    assert outcome.state == check.UNVERIFIABLE
    assert "lcount 8 of 10" in outcome.detail


def test_an_unavailable_method_is_unverifiable_too() -> None:
    assert check.decide(user(), attempt(UNAVAILABLE)).state == check.UNVERIFIABLE


def test_nothing_attempted_is_not_the_same_as_declined() -> None:
    """Both are `UNVERIFIABLE`; only one has a reason worth printing and a
    `lockout_margin_hit` to report."""
    outcome = check.decide(user(), None)

    assert outcome.state == check.UNVERIFIABLE
    assert outcome.verification is None


# --------------------------------------------------------------- rollover ---


def test_a_pass_during_a_rollover_window_is_not_in_sync() -> None:
    """UC-1 §6.3: both passwords authenticate during the window, so a `pass`
    cannot tell "the database has the vault's password" from "it still has the
    previous one and accepts both". `IN_SYNC` would overstate the measurement."""
    outcome = check.decide(user(rollover_active=True), attempt(PASS), version=7)

    assert outcome.state == check.ROLLOVER_ACTIVE
    assert "previous password still works" in outcome.detail


def test_a_failure_during_a_rollover_window_is_still_drift() -> None:
    """The window makes a success ambiguous; it does not make a rejection so.
    Neither password worked, which is unambiguous."""
    assert check.decide(user(rollover_active=True), attempt(FAIL)).state == check.DRIFT


# ------------------------------------------------------------ the vocabulary ---


def test_a_result_outside_the_enum_is_refused_rather_than_mapped() -> None:
    """Every value the vocabulary has is handled, so a new one is a driver this
    module has not been taught about. Guessing which state it means is how a
    wrong password becomes an `IN_SYNC`."""
    with pytest.raises(ValueError, match="not a verification result"):
        check.decide(user(), attempt("maybe"))


def test_every_state_is_one_the_schema_knows() -> None:
    import json
    from pathlib import Path

    from sopuli.output.document import SCHEMA_VERSION

    root = Path(__file__).resolve().parents[1]
    schema = json.loads(
        (root / "docs" / "schemas" / f"sopuli-run-{SCHEMA_VERSION}.schema.json").read_text(
            encoding="utf-8"
        )
    )

    assert set(check.STATES) <= set(schema["$defs"]["state"]["enum"])


# ------------------------------------------------------------- the exit code ---


def test_drift_anywhere_is_exit_three() -> None:
    """What makes the command schedulable: a monitoring system alerts on 3."""
    assert check.exit_code_for([check.IN_SYNC, check.DRIFT]) == ExitCode.DRIFT


def test_everything_in_sync_is_exit_zero() -> None:
    assert check.exit_code_for([check.IN_SYNC, check.ROLLOVER_ACTIVE]) == ExitCode.SUCCESS


def test_an_error_beats_drift() -> None:
    """The ordering worth arguing about. A run that reached nine targets and
    could not reach the tenth found drift on nine targets' worth of estate --
    reporting 3 would claim the survey was complete."""
    assert check.exit_code_for([check.DRIFT, check.ERROR]) == ExitCode.FAILURE


def test_an_unverifiable_run_is_not_drift() -> None:
    """Exit 3 means "go and fix a credential". Nothing here established that."""
    assert check.exit_code_for([check.UNVERIFIABLE, check.LOCKED]) == ExitCode.SUCCESS


# ----------------------------------------------------------------- the ages ---


def test_password_age_is_reported_in_days() -> None:
    changed = datetime(2026, 8, 16, 0, 0, tzinfo=UTC)

    assert check.password_age_days(changed, now=NOW) == 12.5


def test_an_unknown_change_date_reports_nothing() -> None:
    """Version-dependent and unconfirmed on 11.2, and nothing gates on it (Q9),
    so guessing would be all cost."""
    assert check.password_age_days(None, now=NOW) is None


def test_counts_omit_the_states_with_none() -> None:
    """An open object in the schema; eight zeroes per run is noise in something
    consumers diff."""
    assert check.counts([check.IN_SYNC, check.DRIFT, check.IN_SYNC]) == {
        check.DRIFT: 1,
        check.IN_SYNC: 2,
    }


def test_a_naive_change_date_is_read_as_utc() -> None:
    """The regression a real container found and no unit test had.

    Oracle's `PASSWORD_CHANGE_DATE` is a `DATE`, which carries no zone, so
    `oracledb` returns a naive datetime -- and subtracting it from an aware "now"
    raised `TypeError: can't subtract offset-naive and offset-aware datetimes`,
    failing the whole run at exit 1. Every fixture here had built an aware
    datetime, which is exactly the input the driver never produces.
    """
    naive = datetime(2026, 8, 16, 0, 0)

    assert check.password_age_days(naive, now=NOW) == 12.5


def test_a_naive_now_works_too() -> None:
    """The other half of the same mismatch, so the guard cannot rot from one side."""
    assert (
        check.password_age_days(
            datetime(2026, 8, 16, 0, 0, tzinfo=UTC), now=datetime(2026, 8, 28, 12, 0)
        )
        == 12.5
    )


def test_a_multi_line_driver_message_is_trimmed_to_one_line() -> None:
    """`oracledb` appends a documentation URL on its own line, which turned one
    table row into two ragged ones. Also found against a real container: a fake
    session returning a one-line detail could not have shown it."""
    outcome = check.decide(
        user(),
        attempt(FAIL, detail="ORA-01017: invalid credential\nHelp: https://example.com"),
        version=1,
    )

    assert "\n" not in outcome.detail
    assert "ORA-01017" in outcome.detail

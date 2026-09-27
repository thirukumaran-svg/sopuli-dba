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
from sopuli.diagnostics import PASSWORD_GRACE_PERIOD, WARNINGS
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


UNGUARDED = "the lockout guard is unavailable: SELECT ON SYS.USER$ is not granted"


def test_a_pass_without_the_lockout_guard_says_so() -> None:
    """#558: the driver notes a missing `SYS.USER$` grant in the detail, and a
    pass used to replace it with its own words -- so an unguarded check read
    exactly like a guarded one."""
    outcome = check.decide(user(), attempt(PASS, detail=UNGUARDED), version=7)

    assert outcome.state == check.IN_SYNC
    assert outcome.detail == f"vault v7 verified by login; {UNGUARDED}"


def test_a_rollover_pass_without_the_lockout_guard_says_so_too() -> None:
    outcome = check.decide(user(rollover_active=True), attempt(PASS, detail=UNGUARDED), version=7)

    assert outcome.state == check.ROLLOVER_ACTIVE
    assert outcome.detail.endswith(f"; {UNGUARDED}")


def test_a_guarded_pass_adds_nothing() -> None:
    outcome = check.decide(user(), attempt(PASS), version=7)

    assert outcome.detail == "vault v7 verified by login"


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


# ------------------------------------------------------------ the grace period ---
#
# #309. `EXPIRED(GRACE)` carries the token `EXPIRED`, so an account whose password
# still works came back `expired=True`, `check` reported `EXPIRED`, and the login
# that would have proved otherwise was never attempted. The decision inside that
# issue was whether the grace period gets a `state` of its own: it does not, it
# rides as a warning, because `state` is one field and an account in grace may be
# `IN_SYNC` or may have drifted.


def in_grace(**fields: object) -> UserState:
    return user(status="EXPIRED(GRACE)", in_grace=True, **fields)


def test_a_password_in_its_grace_period_is_verified_like_any_other() -> None:
    """The bug, at the level it was reported. Before #309 this was `EXPIRED` and
    no login happened -- which made a scheduled check blind to drift for exactly
    the window before a forced expiry."""
    outcome = check.decide(in_grace(), attempt(PASS), version=7)

    assert outcome.state == check.IN_SYNC


def test_drift_during_a_grace_period_is_still_drift() -> None:
    """The case a `state` of its own could not have expressed. `IN_GRACE` would
    have had to displace `DRIFT` or be displaced by it, and either way the run
    stops saying something true."""
    outcome = check.decide(in_grace(), attempt(FAIL, detail="ORA-01017"))

    assert outcome.state == check.DRIFT
    assert "ORA-01017" in outcome.detail


def test_a_grace_period_on_a_locked_account_is_still_locked() -> None:
    """Measured: `EXPIRED(GRACE) & LOCKED` and `EXPIRED(GRACE) & LOCKED(TIMED)`
    both parse `locked=True`, and `decide` tests `locked` first. So the fix
    cannot turn a locked account into one this tool will try to log in as."""
    state = user(status="EXPIRED(GRACE) & LOCKED", locked=True, in_grace=True)

    assert check.decide(state, attempt(PASS)).state == check.LOCKED


def test_a_hard_expiry_is_untouched_by_the_grace_fix() -> None:
    """The control. `EXPIRED` alone still settles the answer without a login --
    the password has genuinely stopped working, and mitigation 6 says report the
    cause rather than spend an attempt on the symptom."""
    outcome = check.decide(user(status="EXPIRED", expired=True), attempt(PASS))

    assert outcome.state == check.EXPIRED
    assert "not tried" in outcome.detail


# -------------------------------------------------------------- the warning ---


def test_an_account_not_in_a_grace_period_has_no_warning() -> None:
    """Called for every account, so the ordinary answer has to be nothing."""
    assert check.grace_warning(user()) is None
    assert check.grace_warning(user(status="EXPIRED", expired=True)) is None
    assert check.grace_warning(None) is None


def test_the_warning_carries_the_deadline_and_the_time_left() -> None:
    """*When* is most of the value: "in sync" is the answer, and "expiring on
    Friday" is what makes somebody act on it before the window closes."""
    found = check.grace_warning(
        in_grace(password_expires_at=datetime(2026, 9, 6, 12, 0, tzinfo=UTC)),
        now=datetime(2026, 9, 2, 9, 0, tzinfo=UTC),
    )

    assert found is not None
    assert "still works" in found
    assert "2026-09-06T12:00:00Z" in found
    assert "4d3h" in found


def test_a_naive_expiry_date_is_read_as_utc() -> None:
    """Oracle's `DATE` carries no zone and `oracledb` hands back a naive value.
    Subtracting it from an aware "now" raises, which is how the same bug was
    found in `password_age_days` against a real container -- a test building its
    own aware fixture could not reproduce it."""
    found = check.grace_warning(
        in_grace(password_expires_at=datetime(2026, 9, 6, 12, 0)),
        now=datetime(2026, 9, 2, 9, 0, tzinfo=UTC),
    )

    assert found is not None
    assert "2026-09-06T12:00:00Z" in found


def test_a_window_already_past_is_said_plainly_rather_than_counted_down() -> None:
    """`EXPIRY_DATE` is the end of the window, and a status still reading
    `EXPIRED(GRACE)` after it means the database has not noticed yet -- it does
    at the next login. "Expires in -2 days" would be worse than saying so."""
    found = check.grace_warning(
        in_grace(password_expires_at=datetime(2026, 9, 1, 12, 0, tzinfo=UTC)),
        now=datetime(2026, 9, 2, 9, 0, tzinfo=UTC),
    )

    assert found is not None
    assert "closed at" in found
    assert "(in " not in found


def test_a_grace_period_with_no_date_still_warns() -> None:
    """The grace period is true whether or not the release gave a date, and only
    *when* is missing. Inventing one is what `UserState` refuses to do for every
    other unknown."""
    found = check.grace_warning(in_grace(password_expires_at=None))

    assert found is not None
    assert "did not say when" in found


def test_the_warning_code_is_in_the_registry() -> None:
    """`03-json-output.md` §3: a code is contract, and the registry is what says
    what it means. Asserted here because this is where the message is made."""
    assert PASSWORD_GRACE_PERIOD in WARNINGS
    assert "grace period" in WARNINGS[PASSWORD_GRACE_PERIOD]

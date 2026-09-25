"""The decision table behind `creds finish-rollover` (#263).

Closing a rollover window is the one step in UC-1 whose purpose is to stop
something working, so almost every test here is about an account the command
leaves alone. Pure, so the two refusals can be written down side by side -- and
they need to be, because the difference between them is the whole of #263's
decision:

* a **staged `pending`** is refused for free, and it is the case a login would
  have got wrong, because under an open window the old password passes;
* a **refused `current`** is refused because the login said so, and that is the
  half a login is genuinely good for.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sopuli import check
from sopuli import finish_rollover as windows
from sopuli.apply import Source
from sopuli.clock import until
from sopuli.driver.protocol import (
    EXPIRE_PASSWORD,
    FAIL,
    PASS,
    SKIPPED,
    UNAVAILABLE,
    VERIFY_LOGIN,
    Scope,
    UserState,
    VerifyResult,
)
from sopuli.payload import CURRENT, PENDING
from sopuli.secrets import Secret

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)

ABLE = Scope(type="pdb", container="ALPHA", capabilities=frozenset({EXPIRE_PASSWORD}))


def user(**fields: object) -> UserState:
    base: dict[str, object] = {
        "name": "ACME_WEB_USER",
        "status": "OPEN & IN ROLLOVER",
        "profile": "APP_PROFILE",
        "rollover_active": True,
        "rollover_enabled": True,
        "rollover_time": "1",
        "rollover_ends_at": NOW + timedelta(minutes=41),
    }
    return UserState(**{**base, **fields})  # type: ignore[arg-type]


def attempt(result: str = PASS, **fields: object) -> VerifyResult:
    return VerifyResult(method=VERIFY_LOGIN, result=result, **fields)  # type: ignore[arg-type]


def source(stage: str = CURRENT) -> Source:
    return Source(stage=stage, value=Secret("live"), replaces=None)


# ------------------------------------------------- what is not closed at all ---


def test_an_account_with_no_window_reports_no_change() -> None:
    """Invariant 9, and the ordinary night for the scheduled job S2 describes.
    Issuing the statement anyway is accepted silently by Oracle and changes
    nothing, so a run that did would report a change every time."""
    outcome = windows.settled_before_closing(user(rollover_active=False), source(), ABLE)

    assert outcome is not None
    assert outcome.state == check.IN_SYNC
    assert "no rollover window is open" in outcome.detail


def test_a_missing_account_is_reported_and_not_created() -> None:
    outcome = windows.settled_before_closing(None, source(), ABLE)

    assert outcome is not None
    assert outcome.state == check.ACCOUNT_MISSING


def test_a_read_only_database_is_refused_before_the_login() -> None:
    """#521. A standby cannot take the `ALTER USER`, so the refusal comes here --
    ahead of the login a close would spend, and ahead of a preview promising a
    close that could only fail."""
    standby = Scope(
        type="pdb",
        container="ALPHA",
        capabilities=frozenset({EXPIRE_PASSWORD}),
        open_mode="READ ONLY",
        read_write=False,
    )

    outcome = windows.settled_before_closing(user(), source(), standby)

    assert outcome is not None
    assert outcome.state == check.ERROR
    assert "READ ONLY" in outcome.detail


def test_an_unknown_open_mode_is_not_a_refusal() -> None:
    """`require_read_write`'s rule: a mode nobody could read is not evidence of a
    standby, and refusing on it would turn a missing grant into an outage."""
    assert ABLE.read_write is None
    assert windows.settled_before_closing(user(), source(), ABLE) is None


def test_a_read_only_database_with_no_window_is_still_nothing_to_do() -> None:
    """Nothing would be issued, so there is nothing to refuse."""
    standby = Scope(type="pdb", open_mode="READ ONLY", read_write=False)

    outcome = windows.settled_before_closing(user(rollover_active=False), source(), standby)

    assert outcome is not None
    assert outcome.state == check.IN_SYNC


def test_a_locked_account_keeps_its_window() -> None:
    """The window is beside the point for an account nothing can authenticate
    as, and closing it would be a mutation nobody asked for on an account already
    needing attention."""
    outcome = windows.settled_before_closing(
        user(status="LOCKED & IN ROLLOVER", locked=True), source(), ABLE
    )

    assert outcome is not None
    assert outcome.state == check.LOCKED
    assert "left open" in outcome.detail


def test_an_expired_account_keeps_its_window() -> None:
    outcome = windows.settled_before_closing(
        user(status="EXPIRED & IN ROLLOVER", expired=True), source(), ABLE
    )

    assert outcome is not None
    assert outcome.state == check.EXPIRED


def test_a_staged_pending_is_refused_without_spending_a_login() -> None:
    """#263's decision, and the case a verification would have got wrong: the
    rotation is unfinished, so `current` is the *old* password -- and under an
    open window the old password passes."""
    outcome = windows.settled_before_closing(user(), source(PENDING), ABLE)

    assert outcome is not None
    assert outcome.state == windows.PENDING_APPLY
    assert "creds apply" in outcome.detail
    assert outcome.verification is None


def test_an_empty_vault_leaves_the_window_open() -> None:
    """There is nothing to check the database against, so nothing here can say
    the close is safe."""
    outcome = windows.settled_before_closing(user(), None, ABLE)

    assert outcome is not None
    assert outcome.state == check.UNVERIFIABLE


def test_a_database_that_cannot_close_early_is_skipped_not_failed() -> None:
    """A window this build cannot end simply elapses on its own, which is what
    would have happened anyway."""
    outcome = windows.settled_before_closing(user(), source(), Scope(type="pdb"))

    assert outcome is not None
    assert outcome.state == windows.SKIPPED
    assert EXPIRE_PASSWORD in outcome.detail


def test_an_open_window_with_everything_in_place_is_not_settled() -> None:
    """The one case that goes on to spend a login."""
    assert windows.settled_before_closing(user(), source(), ABLE) is None


def test_the_pending_rule_outranks_the_capability_one() -> None:
    """Both are true on a database that cannot close early *and* has an
    unfinished rotation, and the first is the one worth telling somebody: the
    capability is not going to change, and the rotation is."""
    outcome = windows.settled_before_closing(user(), source(PENDING), Scope(type="pdb"))

    assert outcome is not None
    assert outcome.state == windows.PENDING_APPLY


# ------------------------------------------------------------- the login ---


def test_a_pass_goes_ahead() -> None:
    """The weaker half of the answer, and known to be: the window means both
    passwords authenticate, so this cannot prove the database has `current`
    rather than the one before it."""
    assert windows.decide(attempt(PASS)) is None


def test_a_refused_password_is_drift_and_keeps_the_window() -> None:
    """The conclusive half. Neither password in play is what applications fetch,
    so closing would leave nothing that authenticates."""
    outcome = windows.decide(attempt(FAIL, detail="ORA-01017: invalid credential"))

    assert outcome is not None
    assert outcome.state == check.DRIFT
    assert "ORA-01017" in outcome.detail
    assert "even with the window open" in outcome.detail


def test_a_declined_login_keeps_the_window() -> None:
    """A destructive step taken on an answer nobody got is what this module is
    arranged to avoid."""
    for result in (SKIPPED, UNAVAILABLE):
        outcome = windows.decide(attempt(result, detail="within 2 of the limit"))

        assert outcome is not None
        assert outcome.state == check.UNVERIFIABLE


def test_a_multi_line_driver_message_is_trimmed_to_one() -> None:
    outcome = windows.decide(attempt(FAIL, detail="ORA-01017\nHelp: https://…"))

    assert outcome is not None
    assert "\n" not in outcome.detail


# ---------------------------------------------------------- what was closed ---


def test_a_closed_window_says_how_early() -> None:
    """The number an operator is judged on afterwards: four minutes is a tidy-up
    and fifty-five is a decision about somebody's grace period."""
    outcome = windows.closed(user(), attempt(), now=NOW)

    assert outcome.state == check.IN_SYNC
    assert "41m early" in outcome.detail


def test_a_window_with_no_known_end_still_closes() -> None:
    """`rollover_ends_at` is derived and a release that reports no
    `PASSWORD_ROLLOVER_TIME` gives nothing to derive it from. Saying nothing beats
    a zero, which would read as "it was about to close anyway"."""
    outcome = windows.closed(user(rollover_ends_at=None), attempt(), now=NOW)

    assert outcome.state == check.IN_SYNC
    assert "early" not in outcome.detail


# ------------------------------------------------------------ the remainder ---


def test_minutes_are_rendered_alone_under_an_hour() -> None:
    assert windows.remaining(user(rollover_ends_at=NOW + timedelta(minutes=41)), now=NOW) == "41m"


def test_hours_carry_their_minutes() -> None:
    assert (
        windows.remaining(user(rollover_ends_at=NOW + timedelta(hours=3, minutes=7)), now=NOW)
        == "3h07m"
    )


def test_a_long_window_is_rendered_in_days() -> None:
    assert (
        windows.remaining(user(rollover_ends_at=NOW + timedelta(days=2, hours=5)), now=NOW)
        == "2d5h"
    )


def test_an_elapsed_window_has_no_remainder() -> None:
    """Not "0m": the window is gone, and reporting a duration would say it was
    about to close rather than that it already had."""
    assert windows.remaining(user(rollover_ends_at=NOW - timedelta(minutes=1)), now=NOW) is None


def test_an_unknown_end_has_no_remainder() -> None:
    assert windows.remaining(user(rollover_ends_at=None), now=NOW) is None


def test_a_naive_timestamp_is_read_as_utc() -> None:
    """Oracle's `DATE` carries no zone and `oracledb` hands back a naive value.
    `check.password_age_days` reads one the same way and for the same reason:
    the alternative is a `TypeError` on the subtraction."""
    naive = (NOW + timedelta(minutes=15)).replace(tzinfo=None)

    assert windows.remaining(user(rollover_ends_at=naive), now=NOW) == "15m"


def test_the_countdown_is_shared_with_status() -> None:
    """`clock.until` is the arithmetic, and both verbs print the same figure
    about the same window -- this one to say what it closed early, `creds status`
    (#275) to say what is still open. Two implementations would drift."""
    account = user(rollover_ends_at=NOW + timedelta(minutes=41))

    assert windows.remaining(account, now=NOW) == until(account.rollover_ends_at, now=NOW)

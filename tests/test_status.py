"""The decision table behind `creds status` (#275).

UC-1 §9's inventory. Most of this file is about the line the verb holds: what it
will report from two dictionary views and a vault document, and what it refuses
to conclude because concluding it would need a login.

The property worth the most here is that **an unknown age is not an old one**.
`--max-age-days` will be what `rotate` selects on, and treating "this tool has
never rotated it" as infinitely old would make the first act against a freshly
adopted estate a rotation of everything in it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sopuli import check, status
from sopuli.config.model import Binding
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.driver.protocol import UserState
from sopuli.secrets import Secret
from sopuli.store.credentials import StoredSecret

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)

REF = "apps/acme/db#DB_CREDENTIALS/{account}"


def binding(account: str = "acme_web_user") -> Binding:
    return Binding(
        account=account,
        target="appdb-dev-alpha",
        secret=parse_secret_ref(REF.replace("{account}", account)),
        vault="vault-dev",
    )


def user(**fields: object) -> UserState:
    base: dict[str, object] = {"name": "ACME_WEB_USER", "status": "OPEN"}
    return UserState(**{**base, **fields})  # type: ignore[arg-type]


def stored() -> StoredSecret:
    return StoredSecret(value=Secret("live"), version=7, stage="current")


def document(**extra: object) -> dict[str, object]:
    return {"DB_CREDENTIALS": {"acme_web_user": "live"}, **extra}


# --------------------------------------------------------------- the stamp ---


def test_the_stamp_is_read_per_account_from_the_shared_document() -> None:
    """UC-1 §3 puts it beside the value it describes, because a single account
    can be rotated inside a shared document."""
    doc = document(rotated_at={"acme_web_user": "2026-08-01T09:00:00Z", "other": "2020-01-01Z"})

    found = status.rotated_at(doc, binding())

    assert found == datetime(2026, 8, 1, 9, 0, tzinfo=UTC)


def test_a_document_with_no_stamp_has_no_age() -> None:
    """The ordinary case for a secret this tool has never rotated -- seeded by
    hand, or written by whatever the estate used before. Unknown, not zero."""
    assert status.rotated_at(document(), binding()) is None


def test_a_missing_document_has_no_age() -> None:
    assert status.rotated_at(None, binding()) is None


def test_a_malformed_stamp_is_not_a_crash() -> None:
    """Somebody else's string in somebody else's document. Refusing to display a
    whole inventory over one bad field is the wrong trade for a read-only verb."""
    assert (
        status.rotated_at(document(rotated_at={"acme_web_user": "last tuesday"}), binding()) is None
    )
    assert status.rotated_at(document(rotated_at={"acme_web_user": 17}), binding()) is None


def test_a_binding_with_no_ref_has_no_age() -> None:
    assert status.rotated_at(document(), Binding(account="a", target="t", secret=None)) is None


# ----------------------------------------------------------------- the age ---


def test_the_age_is_days_since_the_stamp() -> None:
    assert status.age_days(NOW - timedelta(days=94, hours=3), now=NOW) == 94.1


def test_no_stamp_is_no_age() -> None:
    assert status.age_days(None, now=NOW) is None


def test_a_naive_stamp_is_read_as_utc() -> None:
    """`clock.as_utc`'s rule, and the reason it is one function: a stamp
    subtracted one way and rendered another is one run saying two things."""
    assert status.age_days((NOW - timedelta(days=2)).replace(tzinfo=None), now=NOW) == 2.0


# ------------------------------------------------------------- the threshold ---


def test_an_age_past_the_limit_is_marked() -> None:
    assert status.exceeds(94.1, 90) is True


def test_an_age_inside_the_limit_is_not() -> None:
    assert status.exceeds(12.0, 90) is False
    assert status.exceeds(90.0, 90) is False


def test_an_unknown_age_is_never_selected() -> None:
    """The property this file exists for. Treating unknown as infinitely old
    would make the tool's first act against a freshly adopted estate a rotation
    of everything in it."""
    assert status.exceeds(None, 90) is False


def test_no_threshold_marks_nothing() -> None:
    assert status.exceeds(9999.0, None) is False


# ---------------------------------------------------------------- the state ---


def test_a_healthy_account_is_unverifiable_and_says_why() -> None:
    """Not `IN_SYNC`. Reporting agreement from a command that never asked would
    be indistinguishable in a document from one `check` produced by trying."""
    outcome = status.decide(user(), stored(), document(), binding())

    assert outcome.state == check.UNVERIFIABLE
    assert "creds check" in outcome.detail


def test_an_account_the_database_does_not_have() -> None:
    """Exactly the row an inventory exists to show: the config declares it,
    invariant 5 makes that the whitelist, and the estate disagrees."""
    outcome = status.decide(None, stored(), document(), binding())

    assert outcome.state == check.ACCOUNT_MISSING


def test_a_locked_account_is_reported_as_locked() -> None:
    outcome = status.decide(user(status="LOCKED", locked=True), stored(), document(), binding())

    assert outcome.state == check.LOCKED


def test_an_expired_account_is_reported_as_expired() -> None:
    outcome = status.decide(user(status="EXPIRED", expired=True), stored(), document(), binding())

    assert outcome.state == check.EXPIRED


def test_a_staged_pending_is_an_inventory_finding() -> None:
    """A rotation nobody finished, visible in the vault alone -- which is what
    makes it this verb's to report rather than `check`'s."""
    doc = document(pending={"acme_web_user": "staged"})

    outcome = status.decide(user(), stored(), doc, binding())

    assert outcome.state == status.PENDING_APPLY
    assert "creds apply" in outcome.detail


def test_an_open_window_reports_how_long_is_left() -> None:
    """The state alone says two passwords work; how long for is what decides
    whether tonight's job has to run `finish-rollover` or can let the window
    elapse."""
    # Half a minute of headroom: the phrase floors to whole minutes, so a
    # deadline exactly 41 minutes out renders as 40m by the time the call
    # lands.
    ends_at = datetime.now(UTC) + timedelta(minutes=41, seconds=30)
    account = user(rollover_active=True, rollover_ends_at=ends_at)

    outcome = status.decide(account, stored(), document(), binding())

    assert outcome.state == check.ROLLOVER_ACTIVE
    assert "41m left" in outcome.detail


def test_an_open_window_with_no_known_end_still_reports_the_state() -> None:
    """`rollover_ends_at` is derived and a release reporting no
    `PASSWORD_ROLLOVER_TIME` gives nothing to derive it from."""
    outcome = status.decide(user(rollover_active=True), stored(), document(), binding())

    assert outcome.state == check.ROLLOVER_ACTIVE
    assert "left" not in outcome.detail


def test_an_empty_vault_says_so_rather_than_borrowing_a_state() -> None:
    """A declared account the vault has nothing for is a gap in the file's own
    story, and an inventory should say it in words."""
    outcome = status.decide(user(), None, None, binding())

    assert outcome.state == check.UNVERIFIABLE
    assert "holds no password" in outcome.detail


def test_a_sibling_s_pending_is_not_this_account_s() -> None:
    """The shared layout, addressed the way the mirror rule addresses it."""
    doc = document(pending={"acme_batch_user": "theirs"})

    assert status.decide(user(), stored(), doc, binding()).state == check.UNVERIFIABLE


def test_the_database_outranks_the_vault() -> None:
    """`check.decide`'s ordering: what the database says about the account is the
    cause of whatever anything downstream would have found. A locked account with
    a staged rotation is locked."""
    doc = document(pending={"acme_web_user": "staged"})

    outcome = status.decide(user(status="LOCKED", locked=True), stored(), doc, binding())

    assert outcome.state == check.LOCKED


def test_a_staged_rotation_outranks_an_open_window() -> None:
    """Both are true after a `generate` under a window. The staged one names a
    next step and the window does not."""
    doc = document(pending={"acme_web_user": "staged"})

    outcome = status.decide(user(rollover_active=True), stored(), doc, binding())

    assert outcome.state == status.PENDING_APPLY

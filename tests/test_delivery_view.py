"""What an unseen delivery prints. Tier 0.

The module under test holds a ``reveal()``, which is why it is worth its own file:
`tests/test_reveal_sites.py` permits the site and this is what says the emission is
the one it was permitted for. What the *verb* does with the result -- which stream
it goes to, and that it never reaches the run document -- is
`tests/test_cli_reset_password.py`'s, against a real Vault.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sopuli.delivery import Handover, Receipt
from sopuli.output.delivery_view import UNKNOWN_EXPIRY, render_handover
from sopuli.output.reset_view import build_result
from sopuli.secrets import Secret

TOKEN = "hvs.EXAMPLE-not-a-real-token-AAAAAAAAAAAAAAAAAAAAAAAA"
WHEN = datetime(2026, 9, 22, 10, 21, 0, tzinfo=UTC)


def handover(**rest: object) -> str | None:
    """One rendered hand-over, for the account and target every test here uses."""
    return render_handover(receipt(**rest), account="acme_dev_alice", target="free-pdb")


def receipt(**rest: object) -> Receipt:
    fields: dict[str, object] = {"method": "vault_wrapped", "token": Secret(TOKEN)}
    fields.update(rest)
    return Receipt(**fields)  # type: ignore[arg-type]


def test_the_token_is_printed_because_the_password_cannot_be() -> None:
    """UC-2 §6.1 bars a retrieval credential from the notify channel and the tool
    carries no other, so the token comes back to the DBA to pass on out of band.
    That is the whole reason this module exists."""
    rendered = handover(expires_at=WHEN)

    assert rendered is not None
    assert TOKEN in rendered
    assert "acme_dev_alice" in rendered


def test_the_expiry_is_the_server_s_own_timestamp() -> None:
    """Reported rather than enforced: nothing here polices a TTL the store is
    already policing, and a second clock would only disagree with the first."""
    rendered = handover(expires_at=WHEN)

    assert rendered is not None
    assert "2026-09-22T10:21:00Z" in rendered


def test_an_unknown_expiry_says_so_rather_than_leaving_a_gap() -> None:
    """A line reading "it stops working at" and then nothing reads as a bug in the
    tool rather than as a fact about the answer."""
    rendered = handover(expires_at=None)

    assert rendered is not None
    assert UNKNOWN_EXPIRY in rendered


def test_the_instruction_not_to_check_it_is_part_of_the_output() -> None:
    """The single use is what makes interception detectable, and it only does that
    if the person who receives the token is the one who unwraps it. A DBA who
    unwraps to check has spent the person's one read, and the person finding it
    spent is the only warning either of them gets -- so the line saying so is doing
    work rather than being polite."""
    rendered = handover(expires_at=WHEN)

    assert rendered is not None
    assert "Do not unwrap it" in rendered
    assert "unwraps once" in rendered


def test_a_receipt_with_nothing_to_carry_renders_nothing() -> None:
    """An identity-scoped path (`vault_path`, TODO(#447)) hands over no bearer
    credential, and neither does mail that has been sent. A heading over an
    empty value would suggest something had gone missing."""
    empty = Receipt(method="vault_path")

    assert render_handover(empty, account="acme_dev_alice", target="free-pdb") is None


def test_the_password_has_no_way_into_this_view() -> None:
    """The structural half of the argument: the only secret this module can be
    handed is the receipt's token. There is no parameter a password could arrive
    through, which is what keeps the `reveal()` here narrow by shape rather than by
    the caller's good behaviour."""
    from inspect import signature

    assert set(signature(render_handover).parameters) == {"receipt", "account", "target"}
    assert set(Receipt.__dataclass_fields__) == {"method", "token", "accessor", "expires_at"}


# ------------------------------------------------ what the document says instead ---


def test_the_result_carries_the_accessor_and_the_expiry() -> None:
    """The half of Vault's answer that names the hand-over and cannot perform it.
    An auditor ties this run to an entry in the vault's own log with it; nobody
    fetches a password with it."""
    entry = build_result(
        "acme_dev_alice",
        "free-pdb",
        state="RESET",
        changed=True,
        delivered="vault_wrapped",
        handover=Handover(accessor="EXAMPLEaccessor000000000", expires_at=WHEN),
    )

    assert entry["handover"] == {
        "accessor": "EXAMPLEaccessor000000000",
        "expires_at": "2026-09-22T10:21:00Z",
    }


def test_the_seen_path_has_no_handover_section_at_all() -> None:
    """Absent rather than two nulls. `manual`'s destination is a person reading a
    screen, so there is no accessor to name and no store clock to expire -- and a
    consumer reads presence as "the tool put this somewhere" instead of having to
    tell an empty hand-over from one it cannot see."""
    entry = build_result(
        "acme_dev_alice", "free-pdb", state="RESET", changed=True, delivered="manual"
    )

    assert "handover" not in entry


def test_a_hand_over_with_no_accessor_still_reports_the_expiry() -> None:
    """Null for the field the answer did not carry, rather than dropping the
    section: a store that wrapped without returning an accessor still gave an
    expiry, and an auditor who cannot name the hand-over can still say when it
    stopped being fetchable."""
    entry = build_result(
        "acme_dev_alice",
        "free-pdb",
        state="RESET",
        changed=True,
        delivered="vault_wrapped",
        handover=Handover(expires_at=WHEN),
    )

    assert entry["handover"] == {"accessor": None, "expires_at": "2026-09-22T10:21:00Z"}


def test_a_handover_that_knows_nothing_about_itself_is_still_reported() -> None:
    """A wrap that returned a token but no accessor and no usable TTL is a
    delivery that happened. Keying the section on "is either field set" would
    report it as the **seen** path -- which is the one thing the section's
    presence exists to tell apart.

    Presence comes from the `Handover` existing at all, which is a fact about
    whether a delivery put the password somewhere rather than about how much the
    store was willing to say."""
    entry = build_result(
        "acme_dev_alice",
        "free-pdb",
        state="RESET",
        changed=True,
        delivered="vault_wrapped",
        handover=Handover(),
    )

    assert entry["handover"] == {"accessor": None, "expires_at": None}


def test_the_reported_half_of_a_receipt_drops_the_token() -> None:
    """The narrowing is a type rather than a convention: what the output layer is
    handed has no token attribute, so it cannot take the wrong one."""
    receipt = Receipt(
        method="vault_wrapped",
        token=Secret(TOKEN),
        accessor="EXAMPLEaccessor000000000",
        expires_at=WHEN,
    )

    reported = receipt.reported()

    assert not hasattr(reported, "token")
    assert (reported.accessor, reported.expires_at) == (receipt.accessor, receipt.expires_at)


def test_no_property_in_the_result_could_hold_the_token() -> None:
    """The structural half, asserted rather than described. `build_result` has no
    parameter a retrieval credential could arrive through -- which is the same
    guarantee the password already has, made about the object UC-2 §6.1 says the
    rule also covers."""
    from inspect import signature

    assert not any("token" in name for name in signature(build_result).parameters)
    assert not any("token" in name for name in Handover.__dataclass_fields__)

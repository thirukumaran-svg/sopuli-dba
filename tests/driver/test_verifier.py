"""The 12C verifier comparison, against verifiers a real server wrote.

Every ``SPARE4`` below was read from 26ai Free 23.26.2.0.0, off
throwaway accounts with known passwords that were dropped straight after. A
vector the derivation produced itself would only prove the code agrees with
itself; these prove it agrees with Oracle. The same derivation reproduced on
21c, 18c, 19.3, 19.32 and 12.2 (``02-oracle-privileges.md`` §2).
"""

from __future__ import annotations

import pytest

from sopuli.driver.oracle.verifier import (
    CURRENT,
    NO_MATCH,
    NO_VERIFIER,
    PREVIOUS,
    Malformed12cVerifierError,
    NotComparableError,
    compare,
    twelve_c,
)
from sopuli.passwords import ByteLimit
from sopuli.secrets import Secret

#: What 26ai answered for the database the vectors came from.
AL32UTF8 = ByteLimit(max_bytes=128, encoding="utf-8", charset="AL32UTF8")

#: ``CREATE USER ... IDENTIFIED BY "Acme-Vector-0001"``.
PLAIN = (
    "S:5C300909F36EB8FAA304852C877F9248FF88782986A884533739056CD8C7;"
    "T:38FF2E94AF46AFB9C8C7BDC217CF51BA859F2E7BE6E272098C1B72A74F433EA63D0E266E34AC0771"
    "D0624240EB6016139C22BB1835E1999F151C5FB7A138962F7FE76566D8BDFE4868001CD7D8AAD589"
)

#: The same password set again by ``ALTER USER``: a fresh salt, so a different
#: verifier for the same value. Why a verifier can only be compared by
#: regenerating from *its own* salt.
RESET = (
    "S:189525C5CDF74C44E4E6E1F1D266C15E8F6F8C76712D82E27BEBFC08FD48;"
    "T:32CACAA1297ED82FFC5E2216E647E128A95F20050076C5AA3FAABE8A3BB50A8CB7314E1EED29F355"
    "62478F01B7809A8B0634913DEF97860AE0C6B1ADDF656BF0D11CBEB596C19DBE5BD215DD8047D169"
)

#: Profile ``SOPULI_ROLLOVER``, created as ``"Acme-Vector-Old1"`` then altered to
#: ``"Acme-Vector-New2"``: a window is open. ``T:`` is the previous password,
#: ``t:`` the current, one salt between them, and ``s:``, ``V:`` and ``U:`` beside
#: them that are not 12C verifiers.
ROLLOVER = (
    "S:002AD0A7D8F3846B42BE11180F82FD23E28B0CD7C2B6BC18ACAEA68B68DD;"
    "T:E5924A372B17465A9F802036625BCB062FB8A70B8BA48A1A81981C28225A20FF5A15B18737D5517F"
    "3DA49C5B72B77BBCEA48CB05AA57BC28C066B089E64BF14C84D4A9EB6F7D9DCE502FD1FDC194C9B4;"
    "t:E7AF0F2EAEAB01DAA13471B5849C5688DDC905C1A04435D03DEFD3EFC935264DD93D8EE835404A53"
    "72E8F326D069C70A4C830B00DB59340551E41742254874AD84D4A9EB6F7D9DCE502FD1FDC194C9B4;"
    "V:C8819F9D4D1506F5163A8810B1545B071C20A146E6D09523E940505870381C7D721710C271E54630"
    "5AF84872863296E0F25C0AD83FE3E224DF5702830CF0584A31E0644741911EB1909C8090477CFFB8;"
    "s:1A8D0792AA491AF5B0E703E9BA320F4A49254ACFC2B6BC18ACAEA68B68DD;"
    "U:BE8467DF40749A3D3DE4C3A950E2CDC68D38B2221CC5B6798768327F9014"
)

#: 11g's shape: ``S:`` alone, nothing 12C to compare.
ELEVEN_G = "S:5C300909F36EB8FAA304852C877F9248FF88782986A884533739056CD8C7"


@pytest.mark.parametrize("spare4", [PLAIN, RESET])
def test_the_right_password_reproduces_the_stored_verifier(spare4: str) -> None:
    assert compare(Secret("Acme-Vector-0001"), spare4, limit=AL32UTF8) == CURRENT


def test_a_wrong_password_does_not() -> None:
    assert compare(Secret("Acme-Vector-0002"), PLAIN, limit=AL32UTF8) == NO_MATCH


def test_the_comparison_is_case_sensitive() -> None:
    """Fed as raw UTF-8 with no case folding, which is what reproduced. A
    case-insensitive comparison would be 10G's weakness, imported."""
    assert compare(Secret("acme-vector-0001"), PLAIN, limit=AL32UTF8) == NO_MATCH


def test_in_a_rollover_window_the_two_passwords_are_told_apart() -> None:
    """What a login cannot do: during a window both passwords authenticate, and
    only the verifier says which of them the vault holds."""
    assert compare(Secret("Acme-Vector-New2"), ROLLOVER, limit=AL32UTF8) == CURRENT
    assert compare(Secret("Acme-Vector-Old1"), ROLLOVER, limit=AL32UTF8) == PREVIOUS
    assert compare(Secret("Acme-Vector-0001"), ROLLOVER, limit=AL32UTF8) == NO_MATCH


def test_only_the_12c_verifiers_are_read() -> None:
    """``S:``, ``s:``, ``V:`` and ``U:`` are left alone. 11G is SHA-1 and never a
    fallback: comparing it would report a stronger check than was made."""
    assert set(twelve_c(ROLLOVER)) == {"T:", "t:"}
    assert set(twelve_c(PLAIN)) == {"T:"}


@pytest.mark.parametrize("spare4", [ELEVEN_G, "", None])
def test_no_12c_verifier_is_its_own_answer_and_not_a_mismatch(spare4: str | None) -> None:
    """Nothing was compared, so nothing can be said to differ. The driver turns
    this into a refusal naming the target (invariant 4)."""
    assert compare(Secret("Acme-Vector-0001"), spare4, limit=AL32UTF8) == NO_VERIFIER


@pytest.mark.parametrize(
    "token",
    ["T:ABCD", "T:" + "Z" * 160, "T:" + "A" * 161],
)
def test_a_malformed_12c_token_is_refused_rather_than_skipped(token: str) -> None:
    """Skipping it would report "no verifier", which hides the one thing this
    module cannot vouch for -- a release whose format changed."""
    with pytest.raises(Malformed12cVerifierError) as raised:
        compare(Secret("Acme-Vector-0001"), f"S:{'0' * 60};{token}", limit=AL32UTF8)

    assert token[2:] not in str(raised.value), "the message names a length, never the token"


def test_a_password_the_character_set_cannot_hold_is_refused_not_mismatched() -> None:
    """On WE8DEC the server stores `Ω` as `¿` and hashes that. Comparing the
    vault's string would report a mismatch for a password that logs in -- false
    drift, which starts rotations. Refused instead, naming the set and no
    character of the password."""
    we8dec = ByteLimit(max_bytes=30, encoding="ascii", charset="WE8DEC")

    with pytest.raises(NotComparableError) as refused:
        compare(Secret("Acme-Vector-Ω1"), PLAIN, limit=we8dec)

    assert "WE8DEC" in str(refused.value)
    assert "Ω" not in str(refused.value)


def test_a_password_the_character_set_holds_exactly_is_compared() -> None:
    """The conversion changes nothing when every character survives it, so the
    UTF-8 of the vault's string is what the server hashed."""
    cp1252 = ByteLimit(max_bytes=30, encoding="cp1252", charset="WE8MSWIN1252")

    assert compare(Secret("Acme-Vector-0001"), PLAIN, limit=cp1252) == CURRENT
    assert compare(Secret("Acme-Vectör-0001"), PLAIN, limit=cp1252) == NO_MATCH

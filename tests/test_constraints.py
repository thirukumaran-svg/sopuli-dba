"""Collecting what the estate said, and the two questions asked of it (#317). Tier 0.

Pure arithmetic over readings the caller gathered, so none of this needs a
database -- which is the point of the split: `cli._constraints_for` opens the
connections and this decides what they meant.

The file leans on one comparison that a first draft got wrong in both directions,
so most of what is asserted here is that the two questions stay separate: a
password this tool *draws* is bound by a byte count alone, and one somebody
*supplies* has to satisfy every target's character set as well.
"""

from __future__ import annotations

import pytest

from sopuli.constraints import (
    NAMED,
    NONE,
    POLICY,
    TARGETS,
    UNKNOWN,
    UNREAD,
    AccountConstraints,
    Constraints,
    survey,
)
from sopuli.diagnostics import (
    PASSWORD_REUSE_ENFORCED,
    VERIFY_FUNCTION_UNCHECKABLE,
    WARNINGS,
    constraint_diagnostics,
)
from sopuli.passwords import ByteLimit

MODERN = ByteLimit(max_bytes=128, encoding="ascii", charset="US7ASCII")
LEGACY = ByteLimit(max_bytes=30, encoding="ascii", charset="US7ASCII")
UNICODE = ByteLimit(max_bytes=128, encoding="utf-8", charset="AL32UTF8")
WESTERN = ByteLimit(max_bytes=128, encoding="cp1252", charset="WE8MSWIN1252")


def test_nothing_asked_is_not_nothing_answered() -> None:
    """``--offline`` and an estate that is down are different runs.

    The same rule ``driver/oracle/privileges.py`` states about a view it cannot
    read: "I looked and found nothing" and "I could not look" are answers a
    report must never merge. Here there is a third -- "I did not look" -- and
    collapsing it into the fallback would report a warning about an estate
    nobody tried to reach.
    """
    assert survey([]).source == UNREAD
    assert survey([], unreachable=("appdb-alpha",)).source == POLICY


def test_no_limit_is_carried_when_nothing_answered() -> None:
    """``None`` and ``()`` are what `candidate_for` already means by "no target
    limit", so the fallback is a default rather than a branch to remember."""
    nothing = survey([], unreachable=("appdb-alpha",))

    assert nothing.drawing_limit is None
    assert nothing.limits == ()


def test_the_draw_is_bound_by_the_smallest_byte_count() -> None:
    found = survey([("modern", MODERN), ("legacy", LEGACY)])

    assert found.drawing_limit == LEGACY
    assert found.source == TARGETS
    assert found.strictest_target == "legacy"


def test_the_draw_ignores_the_encoding() -> None:
    """The bug an earlier draft had, in the direction that refuses valid runs.

    Both targets hold 128 bytes. Comparing "characters guaranteed" would call the
    UTF-8 one stricter -- 32 against 128 -- and cap a generated password at 32
    characters that both databases would have stored happily, because §8's
    alphabets are ASCII and an ASCII character is one byte in either encoding.
    """
    found = survey([("western", WESTERN), ("unicode", UNICODE)])

    assert found.drawing_limit is not None
    assert found.drawing_limit.max_bytes == 128


def test_every_limit_is_kept_for_a_supplied_password() -> None:
    """The bug in the other direction, which is the one that stages an
    unappliable password.

    A supplied password can be storable in ``AL32UTF8`` and not in
    ``WE8MSWIN1252``. Keeping only the limit that won the count would validate
    against one target and stage for both.
    """
    found = survey([("western", WESTERN), ("unicode", UNICODE)])

    assert found.limits == (WESTERN, UNICODE)


def test_a_tie_keeps_the_first_reading() -> None:
    """Nothing depends on which of two identical counts is used, and a run that
    picked a different one each time would be reporting noise as a fact."""
    first = ByteLimit(max_bytes=128, encoding="ascii", charset="US7ASCII")
    second = ByteLimit(max_bytes=128, encoding="ascii", charset="WE8ISO8859P1")
    drawn = survey([("alpha", first), ("beta", second)]).drawing_limit

    assert drawn is not None
    assert drawn.charset == "US7ASCII"


def test_one_reading_names_no_strictest_target() -> None:
    """There was nothing to be strictest *than*, and reporting a winner of a
    one-horse race invites a reader to think an estate was surveyed."""
    assert survey([("only", MODERN)]).strictest_target is None


def test_every_target_that_answered_is_named() -> None:
    found = survey([("alpha", MODERN), ("beta", LEGACY)], unreachable=("gamma",))

    assert found.read == ("alpha", "beta")
    assert found.unreachable == ("gamma",)


@pytest.mark.parametrize(
    ("readings", "unreachable", "expected"),
    [
        ([("alpha", MODERN)], (), False),
        ([("alpha", MODERN)], ("beta",), True),
        ([], ("beta",), False),
    ],
)
def test_partial_means_some_answered_and_some_did_not(
    readings: list[tuple[str, ByteLimit]], unreachable: tuple[str, ...], expected: bool
) -> None:
    """The case a reader is most likely to get wrong: the limits are real, they
    came from databases, and they are still not necessarily every one."""
    assert survey(readings, unreachable=unreachable).partial is expected


def test_the_default_constraints_claim_nothing() -> None:
    assert Constraints().drawing_limit is None
    assert Constraints().limits == ()
    assert Constraints().source == UNREAD
    assert Constraints().partial is False


# ------------------------------------------- what cannot bind anything (#317) ---
#
# UC-1 §4 step 2's other three names. None of them can gate a draw -- a verify
# function is arbitrary PL/SQL that cannot be consulted (invariants 13 and 14)
# and a reuse history is hashed -- so every assertion below is about *reporting*,
# and the one that matters is that a not-knowing never renders as an absence.


def _account(name: str, profile: str = "ACME_PROF", **fields: object) -> AccountConstraints:
    return AccountConstraints(account=name, profile=profile, **fields)  # type: ignore[arg-type]


GUARDED = _account("ACME_WEB_USER", verify_function="ORA12C_STRONG_VERIFY_FUNCTION")
PLAIN = _account("ACME_BATCH_USER", reuse_max="UNLIMITED", reuse_time="UNLIMITED")
REUSING = _account("ACME_BATCH_USER", "ACME_TIGHT_PROF", reuse_max="3", reuse_time="10")
UNREADABLE = _account("ACME_COMMON_USER", verify_function_known=False)


def test_the_three_verify_states_are_three_answers() -> None:
    assert GUARDED.verify_state == NAMED
    assert PLAIN.verify_state == NONE
    assert UNREADABLE.verify_state == UNKNOWN


def test_reuse_is_restricted_unless_both_resources_are_unlimited() -> None:
    """Oracle's `DEFAULT` profile carries `UNLIMITED` for both, and anything else
    restricts something. What it restricts is deliberately not worked out here:
    the two resources interact, and this run measured neither the interaction nor
    the hashed history."""
    assert PLAIN.reuse_enforced is False
    assert REUSING.reuse_enforced is True
    assert _account("X", reuse_max="UNLIMITED", reuse_time="30").reuse_enforced is True


def test_a_named_verify_function_is_reported_with_the_ora_code_it_would_raise() -> None:
    found = constraint_diagnostics(survey([("alpha", MODERN)], accounts=[("alpha", GUARDED)]))

    assert [one.code for one in found] == [VERIFY_FUNCTION_UNCHECKABLE]
    assert "ORA12C_STRONG_VERIFY_FUNCTION" in found[0].message
    assert "ORA-28003" in found[0].message
    assert found[0].target == "alpha"
    assert found[0].account == "ACME_WEB_USER"


def test_a_not_knowing_is_reported_as_one() -> None:
    """The half of #317 that is easy to get wrong in the direction that misleads:
    silence here reads as *no verify function*, which reads as a guarantee."""
    found = constraint_diagnostics(survey([("alpha", MODERN)], accounts=[("alpha", UNREADABLE)]))

    assert [one.code for one in found] == [VERIFY_FUNCTION_UNCHECKABLE]
    assert "FROM ROOT" in found[0].message
    assert "could not be established" in found[0].message


def test_a_profile_naming_no_verify_function_says_nothing() -> None:
    """A diagnostic on the ordinary case is noise a consumer learns to filter."""
    assert constraint_diagnostics(survey([("alpha", MODERN)], accounts=[("alpha", PLAIN)])) == []


def test_reuse_is_reported_only_where_a_password_was_supplied() -> None:
    """Fresh randomness cannot collide with a hashed history, so a warning about
    reuse on an ordinary draw would fire on every run and mean nothing on any of
    them. `--from-stdin` takes whatever an external system dictated, and "the one
    it had last year" is an ordinary thing for one to dictate."""
    asked = survey([("alpha", MODERN)], accounts=[("alpha", REUSING)])

    assert constraint_diagnostics(asked) == []
    supplied = constraint_diagnostics(asked, supplied=True)
    assert [one.code for one in supplied] == [PASSWORD_REUSE_ENFORCED]
    assert "PASSWORD_REUSE_MAX 3" in supplied[0].message
    assert "ORA-28007" in supplied[0].message


def test_one_profile_is_one_notice_however_many_accounts_sit_on_it() -> None:
    """A verify function is a property of the profile. An estate that puts forty
    accounts on one would otherwise be told the same fact forty times."""
    accounts = [("alpha", _account(f"ACME_USER_{n}", verify_function="F")) for n in range(4)]
    found = constraint_diagnostics(survey([("alpha", MODERN)], accounts=accounts))

    assert len(found) == 1
    assert "4 accounts" in found[0].message
    assert found[0].account is None, "a group of four cannot go in a field that holds one"


def test_two_targets_with_the_same_profile_name_are_two_notices() -> None:
    """The profile is a target's object, not the estate's: two databases can name
    one profile and mean different things by it."""
    found = constraint_diagnostics(
        survey(
            [("alpha", MODERN), ("beta", MODERN)],
            accounts=[("alpha", GUARDED), ("beta", GUARDED)],
        )
    )

    assert [one.target for one in found] == ["alpha", "beta"]


def test_an_unread_profile_contributes_no_sentence() -> None:
    """A warning built out of a profile nobody read would be inventing the
    subject of its own sentence."""
    nameless = AccountConstraints(account="ACME_WEB_USER", verify_function_known=False)
    found = constraint_diagnostics(survey([("alpha", MODERN)], accounts=[("alpha", nameless)]))

    assert found == []


def test_the_unreadable_estate_warning_still_comes_out_beside_them() -> None:
    """The two report different things: one is about *this run's password*, the
    other about what will judge it later."""
    found = constraint_diagnostics(
        survey([("alpha", MODERN)], unreachable=("beta",), accounts=[("alpha", GUARDED)]),
    )

    assert [one.code for one in found] == ["SOPULI-W015", VERIFY_FUNCTION_UNCHECKABLE]


def test_every_code_this_module_emits_is_in_the_registry() -> None:
    """`03-json-output.md` §8: a code is contract in the way an enum value is, and
    one nothing describes is a string a consumer has to guess the meaning of."""
    found = constraint_diagnostics(
        survey(
            [("alpha", MODERN)],
            unreachable=("beta",),
            accounts=[("alpha", GUARDED), ("alpha", REUSING)],
        ),
        supplied=True,
    )

    assert len(found) == 3
    for one in found:
        assert one.code in WARNINGS

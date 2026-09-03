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

from sopuli.constraints import POLICY, TARGETS, UNREAD, Constraints, survey
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

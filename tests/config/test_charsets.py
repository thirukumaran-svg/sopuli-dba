"""§8's charsets, once they are characters rather than prose.

Tier 0, and about as pure as this project gets. The tests worth reading are the
ones that pin §8's table against the document, and the one that pins the *absence*
of ``"`` from every alphabet -- an alphabet containing it would produce candidates
the generator throws away for the rest of time (invariant 11).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from sopuli.config import charsets
from sopuli.config.errors import ConfigError
from sopuli.config.model import PasswordPolicy

REFERENCE = Path(__file__).resolve().parents[2] / "docs" / "design" / "01-configuration.md"


def policy(**keys: object) -> PasswordPolicy:
    return PasswordPolicy(**keys)  # type: ignore[arg-type]


# ------------------------------------------------------------- the table ---


def test_alnum_is_letters_and_digits_only() -> None:
    assert set(charsets.ALPHABETS["alnum"]) == set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    )


def test_alnum_safe_adds_exactly_the_seven_specials_section_8_names() -> None:
    """The set §8 and §2 both write out. One character more would be a hazard the
    default charset was chosen to avoid; one fewer would be a silent narrowing.
    `$` and `^` are left out on purpose: a shell and a Compose `.env` file expand
    `$`, and `cmd.exe` reads `^` as an escape (#742)."""
    added = set(charsets.ALPHABETS["alnum_safe"]) - set(charsets.ALPHABETS["alnum"])

    assert added == set("_#-.+=~")
    assert len(charsets.SAFE_SPECIALS) == 7


def test_printable_ascii_is_every_printable_except_space_and_the_quote() -> None:
    alphabet = charsets.ALPHABETS["printable_ascii"]

    assert " " not in alphabet
    assert '"' not in alphabet
    assert len(alphabet) == 93  # 0x21..0x7E is 94, minus the quote
    assert set(alphabet) == {chr(point) for point in range(0x21, 0x7F)} - {'"'}


@pytest.mark.parametrize("name", list(charsets.ALPHABETS))
def test_no_alphabet_contains_the_one_character_no_password_may(name: str) -> None:
    """Invariant 11 at the source. `printable_ascii` is the one that would
    otherwise include it, which is why §8's row says "except space and `"`"."""
    assert charsets.FORBIDDEN not in charsets.ALPHABETS[name]


@pytest.mark.parametrize("name", list(charsets.ALPHABETS))
def test_no_named_alphabet_contains_a_control_character(name: str) -> None:
    """`02-oracle-privileges.md` §4 rejects them in a password."""
    assert not [c for c in charsets.ALPHABETS[name] if charsets.is_control(c)]


def test_the_reference_names_the_same_charsets_as_the_code() -> None:
    """§8's table is the specification. A charset added to one and not the other
    is exactly the drift CLAUDE.md calls a bug in one of them."""
    table = re.findall(r"^\| `(\w+)` \|", REFERENCE.read_text(encoding="utf-8"), re.MULTILINE)

    assert set(charsets.ALPHABETS) <= set(table)
    assert charsets.CUSTOM in table


# ------------------------------------------------------------- alphabets ---


def test_a_policy_with_no_charset_gets_the_documented_default() -> None:
    """§8 names `alnum_safe` the default. Unlike `length`, it is written down, so
    resolving it follows the reference rather than choosing on someone's behalf."""
    assert charsets.alphabet(policy()) == charsets.ALPHABETS[charsets.DEFAULT_CHARSET]


def test_a_custom_charset_uses_what_it_allows() -> None:
    assert charsets.alphabet(policy(charset="custom", allow="abc123")) == "abc123"


def test_a_custom_alphabet_still_loses_the_forbidden_character() -> None:
    """`policies.py` refuses it when the file is read, so this is the second lock:
    no caller can be handed an alphabet that produces unusable passwords."""
    assert charsets.alphabet(policy(charset="custom", allow='ab"c')) == "abc"


# ------------------------------------------- policies a file could never be ---
#
# `policies.py` refuses all three when a config file is read, with a key path this
# module cannot know. These are the same shapes reached by building a
# `PasswordPolicy` in code, where the alternative to an error is a `KeyError`, a
# silently ignored `allow:`, or an empty alphabet -- see `alphabet`.


def test_an_unknown_charset_is_an_error_rather_than_a_key_error() -> None:
    with pytest.raises(ConfigError) as caught:
        charsets.alphabet(policy(charset="alnumm"))

    rendered = str(caught.value)
    assert "unknown charset 'alnumm'" in rendered
    assert "known: alnum, alnum_safe, printable_ascii, custom" in rendered


def test_allow_beside_a_named_charset_is_refused_rather_than_ignored() -> None:
    """Silently ignoring it would hand the caller passwords from an alphabet other
    than the one it asked for, which is worse than refusing."""
    with pytest.raises(ConfigError) as caught:
        charsets.alphabet(policy(charset="alnum", allow="abc"))

    rendered = str(caught.value)
    assert "only applies to `charset: custom`" in rendered
    assert "`charset: alnum`" in rendered


def test_allow_with_no_charset_at_all_is_refused_too() -> None:
    """The default charset is `alnum_safe`, so this `allow:` would be ignored just
    as silently."""
    with pytest.raises(ConfigError) as caught:
        charsets.alphabet(policy(allow="abc"))

    assert "no charset" in str(caught.value)


def test_a_custom_charset_with_nothing_allowed_is_refused() -> None:
    """An empty alphabet reads as "no characters are permitted" rather than as the
    unfinished policy it is."""
    with pytest.raises(ConfigError) as caught:
        charsets.alphabet(policy(charset="custom"))

    assert "must say what it allows" in str(caught.value)


# --------------------------------------------------------------- classes ---


@pytest.mark.parametrize(
    ("character", "expected"),
    [("Q", "upper"), ("q", "lower"), ("7", "digit"), ("#", "special"), ("é", "special")],
)
def test_a_character_counts_towards_one_class(character: str, expected: str) -> None:
    assert charsets.class_of(character) == expected


def test_counts_reports_every_class_including_the_absent_ones() -> None:
    """A caller comparing against `require:` should never have to tell "none" from
    "not counted"."""
    assert charsets.counts("Ab1#") == {"upper": 1, "lower": 1, "digit": 1, "special": 1}
    assert charsets.counts("abc") == {"upper": 0, "lower": 3, "digit": 0, "special": 0}


def test_counts_covers_the_classes_require_can_name() -> None:
    assert set(charsets.counts("x")) == set(charsets.CLASS_NAMES)


def test_classes_present_is_what_makes_an_impossible_require_visible() -> None:
    assert charsets.classes_present(charsets.ALPHABETS["alnum"]) == {"upper", "lower", "digit"}
    assert "special" in charsets.classes_present(charsets.ALPHABETS["alnum_safe"])
    assert charsets.classes_present("abc") == {"lower"}


def test_has_letters_answers_the_first_char_rule() -> None:
    assert charsets.has_letters("abc123")
    assert charsets.has_letters("ABC")
    assert not charsets.has_letters("0123#$")


@pytest.mark.parametrize("character", ["\x00", "\x1f", "\x7f", "\x85"])
def test_control_characters_are_recognised_including_chr_zero(character: str) -> None:
    """Read from the Unicode category rather than an ASCII range, so the C1 block
    counts too -- `\\x85` is a control character that is not below 0x20."""
    assert charsets.is_control(character)


@pytest.mark.parametrize("character", ["a", "#", " ", "é"])
def test_ordinary_characters_are_not_control_characters(character: str) -> None:
    assert not charsets.is_control(character)

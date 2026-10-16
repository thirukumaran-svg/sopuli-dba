"""The ``policies:`` section -- password rules and the account itself.

Tier 0, pure. Most of it is closed sets and ranges; the tests worth reading are
the three that catch a file which looks fine and cannot work. Each of those would
otherwise surface as a rotation that hangs or loops rather than as an error, at
the least convenient possible moment.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.policies import build_policies

APP_STANDARD: dict[str, Any] = {
    "password": {
        "length": 24,
        "charset": "alnum_safe",
        "first_char": "alpha",
        "require": {"upper": 1, "lower": 1, "digit": 1, "special": 1},
    },
    "account": {"unlock_if_locked": False},
}


def document(**policies: Any) -> dict[str, Any]:
    return {"version": 1, "policies": policies}


def only(**keys: Any) -> Any:
    built = build_policies(document(**{"app-standard": {**APP_STANDARD, **keys}}))
    assert len(built) == 1
    return built[0]


def test_a_policy_is_read_whole() -> None:
    policy = only()

    assert policy.name == "app-standard"
    assert policy.password.length == 24
    assert policy.password.charset == "alnum_safe"
    assert policy.password.first_char == "alpha"
    assert policy.password.require == (("digit", 1), ("lower", 1), ("special", 1), ("upper", 1))
    assert policy.account.unlock_if_locked is False


def test_a_config_may_declare_no_policies() -> None:
    assert build_policies({"version": 1}) == ()


def test_a_policy_may_set_nothing_at_all() -> None:
    """An empty policy is a name reserved for later, not a half-finished block:
    unlike `oracle: {}` on a target it has sub-blocks that each mean something,
    and every one of them is optional."""
    (policy,) = build_policies(document(**{"minimal": {}}))

    assert policy.password.charset is None


# --------------------------------------------------------- invariant 11 ---


def test_a_custom_charset_may_not_contain_a_double_quote() -> None:
    """Invariant 11, at the only place a config file can name the character.

    Rejected rather than quietly dropped from the alphabet: a charset that
    silently differs from what the file says is how somebody comes to believe
    their passwords have a character class they do not have.
    """
    with pytest.raises(ConfigError) as caught:
        build_policies(
            document(**{"risky": {"password": {"charset": "custom", "allow": 'abc123!"#'}}})
        )

    rendered = str(caught.value)
    assert 'may not contain `"`' in rendered
    assert "policies.risky.password.allow" in rendered
    assert "no escape for it" in rendered


def test_a_custom_charset_may_not_contain_control_characters() -> None:
    """The same section as invariant 11 rejects these in a password, `CHR(0)`
    included, so an alphabet holding one could only produce candidates the
    generator throws away."""
    with pytest.raises(ConfigError) as caught:
        build_policies(
            document(**{"risky": {"password": {"charset": "custom", "allow": "abc\x00"}}})
        )

    rendered = str(caught.value)
    assert "may not contain control characters" in rendered
    assert "policies.risky.password.allow" in rendered
    assert "CHR(0)" in rendered


def test_a_custom_charset_without_a_double_quote_is_fine() -> None:
    policy = only(password={"charset": "custom", "allow": "abcdef0123456789_-"})

    assert policy.password.allow == "abcdef0123456789_-"


def test_custom_must_say_what_it_allows() -> None:
    with pytest.raises(ConfigError) as caught:
        build_policies(document(**{"risky": {"password": {"charset": "custom"}}}))

    assert "must say what it allows" in str(caught.value)


def test_allow_without_custom_is_refused() -> None:
    """The named charsets are fixed (§8). Accepting `allow:` beside one would
    look like it narrowed the alphabet and do nothing."""
    with pytest.raises(ConfigError) as caught:
        build_policies(document(**{"risky": {"password": {"charset": "alnum", "allow": "abc"}}}))

    rendered = str(caught.value)
    assert "only applies to `charset: custom`" in rendered
    assert "`charset: alnum`" in rendered


# ------------------------------------------------ policies that cannot work ---


def test_requiring_more_characters_than_the_length_is_refused() -> None:
    """No password can satisfy it, so generation would never succeed."""
    with pytest.raises(ConfigError) as caught:
        build_policies(
            document(
                **{
                    "impossible": {
                        "password": {
                            "length": 8,
                            "require": {"upper": 4, "lower": 4, "digit": 4, "special": 4},
                        }
                    }
                }
            )
        )

    rendered = str(caught.value)
    assert "asks for 16 characters but `length:` is 8" in rendered
    assert "never succeed" in rendered


def test_requiring_a_special_from_an_alphanumeric_charset_is_refused() -> None:
    """The same impossibility, one step less obvious -- and the charset that
    would satisfy it is the next row of §8's table."""
    with pytest.raises(ConfigError) as caught:
        build_policies(
            document(
                **{"impossible": {"password": {"charset": "alnum", "require": {"special": 1}}}}
            )
        )

    rendered = str(caught.value)
    assert "has no special characters" in rendered
    assert "alnum_safe" in rendered


def test_requiring_a_class_a_custom_alphabet_lacks_is_refused() -> None:
    """The same impossibility as the row above, on the charset where it is most
    likely: nobody checks a hand-written string of punctuation by eye, and a
    `require:` it cannot satisfy would surface as generation giving up.
    """
    with pytest.raises(ConfigError) as caught:
        build_policies(
            document(
                **{
                    "impossible": {
                        "password": {
                            "charset": "custom",
                            "allow": "abcdef",
                            "require": {"special": 1},
                        }
                    }
                }
            )
        )

    rendered = str(caught.value)
    assert "`allow:` has no special characters" in rendered
    assert "policies.impossible.password.require.special" in rendered
    assert "add special characters to `allow:`" in rendered


def test_requiring_a_letter_class_a_custom_alphabet_lacks_is_refused() -> None:
    """Not only `special`: an `allow:` of digits cannot produce an upper-case
    character either, and the named charsets all can, which is why this case only
    exists for `custom`."""
    with pytest.raises(ConfigError) as caught:
        build_policies(
            document(
                **{
                    "p": {
                        "password": {"charset": "custom", "allow": "0123", "require": {"upper": 1}}
                    }
                }
            )
        )

    assert "`allow:` has no upper characters" in str(caught.value)


def test_first_char_alpha_against_an_alphabet_with_no_letters_is_refused() -> None:
    """`first_char: alpha` is the other way a policy can demand what its alphabet
    cannot give, and it needs no `require:` block to do it."""
    with pytest.raises(ConfigError) as caught:
        build_policies(
            document(
                **{
                    "p": {
                        "password": {"charset": "custom", "allow": "0123#", "first_char": "alpha"}
                    }
                }
            )
        )

    rendered = str(caught.value)
    assert "`first_char: alpha` needs a letter" in rendered
    assert "policies.p.password.first_char" in rendered


def test_requiring_zero_of_a_missing_class_is_not_a_contradiction() -> None:
    """`require: { special: 0 }` asks for nothing, so there is nothing the alphabet
    fails to provide. Refusing it would be arithmetic rather than a rule."""
    assert only(password={"charset": "alnum", "require": {"special": 0}}).password.require == (
        ("special", 0),
    )


def test_the_same_requirement_is_fine_on_a_charset_that_has_specials() -> None:
    assert only(password={"charset": "alnum_safe", "require": {"special": 1}}).password.require == (
        ("special", 1),
    )


def test_requiring_a_negative_count_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_policies(document(**{"odd": {"password": {"require": {"digit": -1}}}}))

    assert "cannot require -1 characters" in str(caught.value)


# ------------------------------------------------------------ closed sets ---


@pytest.mark.parametrize("charset", ["alnum", "alnum_safe", "printable_ascii"])
def test_every_charset_in_the_table_is_accepted(charset: str) -> None:
    assert only(password={"charset": charset}).password.charset == charset


def test_an_unknown_charset_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_policies(document(**{"p": {"password": {"charset": "alnum-safe"}}}))

    rendered = str(caught.value)
    assert "unknown charset 'alnum-safe'" in rendered
    assert "alnum_safe" in rendered


@pytest.mark.parametrize(
    ("block", "flags"),
    [
        ("rotation", ("--strategy", "--max-age-days", "rollover_hours", "keep_previous")),
        ("verify", ("--method", "--lockout-margin")),
    ],
)
def test_a_removed_block_is_refused_by_name(block: str, flags: tuple[str, ...]) -> None:
    """No run read either block, so they were removed (#787). The refusal says
    so, rather than calling a key an older build accepted a typo, and names the
    flags that set what the block named."""
    with pytest.raises(ConfigError) as caught:
        build_policies(document(**{"p": {block: {}}}))

    rendered = str(caught.value)
    assert f"`{block}:` was removed from policies" in rendered
    assert f"policies.p.{block}" in rendered
    assert all(flag in rendered for flag in flags)


# ----------------------------------------------------------------- ranges ---


def test_a_length_below_one_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_policies(document(**{"p": {"password": {"length": 0}}}))

    assert "length must be at least 1, not 0" in str(caught.value)


def test_an_unknown_policy_key_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_policies(document(**{"p": {"passwrod": {}}}))

    rendered = str(caught.value)
    assert "unknown key 'passwrod'" in rendered
    assert "policies.p" in rendered

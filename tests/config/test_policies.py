"""The ``policies:`` section -- password rules, rotation, verification.

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
    "rotation": {
        "strategy": "rollover",
        "rollover_hours": 24,
        "keep_previous": True,
        "max_age_days": 90,
    },
    "verify": {"method": "login", "lockout_margin": 2},
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
    assert policy.rotation.strategy == "rollover"
    assert policy.rotation.rollover_hours == 24
    assert policy.rotation.keep_previous is True
    assert policy.rotation.max_age_days == 90
    assert policy.verify.method == "login"
    assert policy.verify.lockout_margin == 2
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


@pytest.mark.parametrize("strategy", ["rollover", "staged", "direct"])
def test_every_rotation_strategy_uc1_names_is_accepted(strategy: str) -> None:
    assert only(rotation={"strategy": strategy}).rotation.strategy == strategy


def test_an_unknown_rotation_strategy_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_policies(document(**{"p": {"rotation": {"strategy": "immediate"}}}))

    assert "unknown strategy 'immediate'" in str(caught.value)


@pytest.mark.parametrize("method", ["login", "hash", "both", "none"])
def test_every_verify_method_is_accepted(method: str) -> None:
    assert only(verify={"method": method}).verify.method == method


def test_an_unknown_verify_method_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_policies(document(**{"p": {"verify": {"method": "hashh"}}}))

    assert "unknown verify method 'hashh'" in str(caught.value)


def test_scheduled_method_is_gone() -> None:
    """It was run context hiding inside a password policy because there was
    nowhere else to put it. §5 gave it somewhere: a profile overriding
    `verify.method`. The old key must not quietly keep working."""
    with pytest.raises(ConfigError) as caught:
        build_policies(
            document(**{"p": {"verify": {"method": "login", "scheduled_method": "hash"}}})
        )

    assert "unknown key 'scheduled_method'" in str(caught.value)


# ----------------------------------------------------------------- ranges ---


@pytest.mark.parametrize("key", ["length", "rollover_hours", "max_age_days"])
def test_a_count_below_one_is_refused(key: str) -> None:
    block = "password" if key == "length" else "rotation"

    with pytest.raises(ConfigError) as caught:
        build_policies(document(**{"p": {block: {key: 0}}}))

    assert f"{key} must be at least 1, not 0" in str(caught.value)


def test_a_negative_lockout_margin_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_policies(document(**{"p": {"verify": {"lockout_margin": -1}}}))

    assert "lockout_margin cannot be -1" in str(caught.value)


def test_a_zero_lockout_margin_is_allowed() -> None:
    """Zero means "use every attempt the profile allows" -- reckless, and a
    legitimate thing to write down deliberately."""
    assert only(verify={"lockout_margin": 0}).verify.lockout_margin == 0


def test_an_unknown_policy_key_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_policies(document(**{"p": {"passwrod": {}}}))

    rendered = str(caught.value)
    assert "unknown key 'passwrod'" in rendered
    assert "policies.p" in rendered

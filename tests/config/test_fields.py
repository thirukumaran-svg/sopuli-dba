"""The field readers every section builder is made of.

Tier 0, pure: these take raw values and a :class:`KeyPath` and return typed ones.
The thing actually under test in most of them is not the type check -- it is
whether the error says *where*, because that is what the rest of the config layer
is relying on them for.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.fields import (
    describe,
    mapping,
    optional_string,
    reject_unknown_keys,
    sequence,
    string,
    string_list,
)

AT = ROOT.key("applications").index(1)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({}, "a mapping"),
        ([], "a list"),
        ("acme", "a string"),
        (True, "a boolean"),
        (1, "a number"),
        (1.5, "a number"),
        (None, "nothing"),
    ],
)
def test_types_are_named_the_way_a_yaml_author_thinks_of_them(value: Any, expected: str) -> None:
    """Someone editing a config file has never heard of `dict`."""
    assert describe(value) == expected


def test_a_boolean_is_not_described_as_a_number() -> None:
    """`bool` subclasses `int`, so order in the lookup table is load-bearing."""
    assert describe(True) == "a boolean"


# ------------------------------------------------------------------ mapping ---


def test_mapping_accepts_a_mapping() -> None:
    assert mapping({"name": "acme"}, at=AT) == {"name": "acme"}


def test_mapping_rejects_other_types_and_says_where() -> None:
    with pytest.raises(ConfigError) as caught:
        mapping(["acme"], at=AT)

    assert str(caught.value) == "applications[1]: must be a mapping, not a list"


def test_mapping_rejects_a_non_string_key() -> None:
    """YAML allows `1: x`. Nothing in this schema wants it, and quietly
    stringifying it would make the key path a lie."""
    with pytest.raises(ConfigError) as caught:
        mapping({1: "acme"}, at=AT)

    assert "must be a string" in str(caught.value)


# ------------------------------------------------------------------- string ---


def test_string_accepts_a_string() -> None:
    assert string("acme", at=AT) == "acme"


def test_string_rejects_the_wrong_type() -> None:
    with pytest.raises(ConfigError) as caught:
        string(3, at=AT)

    assert "must be a string, not a number" in str(caught.value)


@pytest.mark.parametrize("value", ["", "   ", "\t"], ids=["empty", "spaces", "tab"])
def test_string_rejects_blank(value: str) -> None:
    """`policy: ""` names no policy. Treating it as absent would hide a
    half-finished edit rather than report one."""
    with pytest.raises(ConfigError) as caught:
        string(value, at=AT)

    assert "must not be empty" in str(caught.value)


def test_optional_string_returns_none_when_absent() -> None:
    """Absent and wrong are different failures, so callers never have to tell
    them apart from one return value."""
    assert optional_string({}, "policy", at=AT) is None


def test_optional_string_still_validates_when_present() -> None:
    with pytest.raises(ConfigError) as caught:
        optional_string({"policy": []}, "policy", at=AT)

    assert str(caught.value).startswith("applications[1].policy:")


# --------------------------------------------------------------- sequences ---


def test_sequence_rejects_a_mapping() -> None:
    with pytest.raises(ConfigError) as caught:
        sequence({"a": 1}, at=AT)

    assert "must be a list, not a mapping" in str(caught.value)


def test_string_list_accepts_strings() -> None:
    assert string_list(["acme_web_user", "acme_api_user"], at=AT) == (
        "acme_web_user",
        "acme_api_user",
    )


def test_string_list_names_the_offending_index() -> None:
    """`accounts[3]` sends someone to the right line. "accounts must be a list of
    strings" sends them to re-read all six."""
    with pytest.raises(ConfigError) as caught:
        string_list(["acme_web_user", "acme_api_user", 7], at=ROOT.key("accounts"))

    assert str(caught.value) == "accounts[2]: must be a string, not a number"


# ----------------------------------------------------------- unknown keys ---


def test_known_keys_pass() -> None:
    reject_unknown_keys({"name": "acme"}, allowed=("name", "policy"), at=AT)


def test_an_unknown_key_is_an_error_not_a_warning() -> None:
    """§9, and P3: "a typo in a credential tool must never be silently ignored"."""
    with pytest.raises(ConfigError) as caught:
        reject_unknown_keys({"secret_tmplate": "x"}, allowed=("secret_template",), at=AT)

    rendered = str(caught.value)
    assert "unknown key 'secret_tmplate'" in rendered
    assert "known keys here: secret_template" in rendered


def test_several_unknown_keys_are_reported_together() -> None:
    """One run of the tool, one round of edits. Reporting them one at a time
    turns a typo hunt into a queue."""
    with pytest.raises(ConfigError) as caught:
        reject_unknown_keys({"b": 1, "a": 1}, allowed=("name",), at=AT)

    assert "unknown keys 'a', 'b'" in str(caught.value)

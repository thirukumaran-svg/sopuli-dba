"""The hardened YAML loader.

Tier 0, pure: :func:`parse_yaml` takes a string, so none of this touches a
filesystem.

Each hardening test is paired with the stock-PyYAML behaviour it exists to
prevent, asserted directly against ``yaml.safe_load``. Without that pairing a
reader has to take the docstring's word for what the problem was, and if PyYAML
ever changes its mind the pair fails loudly instead of leaving dead defence in
place.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from sopuli.config.errors import ConfigError
from sopuli.config.yaml_loader import parse_yaml

# --------------------------------------------------------- duplicate keys ---

DUPLICATED = "accounts: [acme_web_user]\npolicy: app-standard\naccounts: [acme_api_user]\n"


def test_stock_pyyaml_silently_drops_a_duplicate_key() -> None:
    """The behaviour being defended against, pinned so it cannot change unnoticed."""
    assert yaml.safe_load(DUPLICATED)["accounts"] == ["acme_api_user"]


def test_a_duplicate_key_is_an_error() -> None:
    """Invariant 5 makes the config the whitelist.

    A whitelist that can silently lose half its entries is not one: this file
    declares two accounts and stock YAML manages one, successfully and quietly.
    """
    with pytest.raises(ConfigError) as caught:
        parse_yaml(DUPLICATED)

    assert "duplicate key 'accounts'" in str(caught.value)


def test_the_duplicate_is_reported_at_the_second_occurrence() -> None:
    """The second one is the one to delete, so that is the line to name."""
    with pytest.raises(ConfigError) as caught:
        parse_yaml(DUPLICATED)

    assert caught.value.line == 3
    assert "first defined at line 1" in str(caught.value)


def test_duplicates_are_caught_inside_nested_mappings() -> None:
    document = "applications:\n  - name: acme\n    policy: a\n    policy: b\n"

    with pytest.raises(ConfigError) as caught:
        parse_yaml(document)

    assert "duplicate key 'policy'" in str(caught.value)


def test_a_merge_key_is_not_a_duplicate() -> None:
    """`<<:` is resolved before the check, so anchors stay usable.

    Without flatten_mapping first, a merged-in key would collide with one
    written longhand and this legitimate file would be refused.
    """
    document = "base: &defaults\n  policy: app-standard\nacme:\n  <<: *defaults\n  name: acme\n"

    assert parse_yaml(document)["acme"] == {"policy": "app-standard", "name": "acme"}


def test_an_unhashable_key_is_still_a_located_config_error() -> None:
    """YAML allows a sequence as a key (`? [a, b]`), and Python cannot hash one.

    The duplicate-key check has to survive that. Testing `key in seen` on a list
    raises TypeError, which would escape as a bare traceback and exit 1 -- a
    regression on stock PyYAML, which reports it properly with a mark. The check
    steps aside and lets PyYAML do that.
    """
    with pytest.raises(ConfigError) as caught:
        parse_yaml("? [alpha, beta]\n: a value\n")

    assert "unhashable" in str(caught.value).lower()
    assert caught.value.line is not None


# ---------------------------------------------------------------- booleans ---


def test_stock_pyyaml_turns_bare_words_into_booleans() -> None:
    assert yaml.safe_load("tenant: no") == {"tenant": False}


@pytest.mark.parametrize("word", ["no", "yes", "on", "off", "No", "YES", "Off"])
def test_yaml_1_1_boolean_words_stay_strings(word: str) -> None:
    """The Norway problem, in a file full of bare words.

    Tenants, environments, PDB suffixes and label values are all unquoted words
    here, and every one of them flows into a rendered secret path. A tenant
    called `no` silently becoming False would not surface until the wrong path
    was written.
    """
    assert parse_yaml(f"tenant: {word}") == {"tenant": word}


@pytest.mark.parametrize(
    ("literal", "expected"),
    [("true", True), ("false", False), ("True", True), ("FALSE", False)],
)
def test_real_booleans_still_parse(literal: str, expected: bool) -> None:
    """The narrowing must not go so far that `readonly: true` stops working."""
    assert parse_yaml(f"readonly: {literal}") == {"readonly": expected}


def test_narrowing_did_not_leak_into_the_shared_safeloader() -> None:
    """Resolvers live on the class, so editing SafeLoader would change PyYAML
    for every other library in the process. Subclassing is what prevents that."""
    assert yaml.safe_load("tenant: no") == {"tenant": False}


# ------------------------------------------------------------ parse errors ---


def test_a_tab_indent_reports_where() -> None:
    with pytest.raises(ConfigError) as caught:
        parse_yaml("accounts:\n\t- acme_web_user\n")

    assert caught.value.line == 2
    assert caught.value.column is not None


def test_a_parse_error_reads_as_one_sentence() -> None:
    """PyYAML splits its message into `problem` and `context`; joined they read
    as English, and separately the context is not actionable enough to be a hint."""
    with pytest.raises(ConfigError) as caught:
        parse_yaml("accounts: [unclosed\n")

    rendered = str(caught.value)
    assert "hint:" not in rendered
    assert "line 2" in rendered or "line 1" in rendered


def test_the_source_is_attached_to_a_parse_error() -> None:
    with pytest.raises(ConfigError) as caught:
        parse_yaml("a:\n\tb: 1\n", source=Path("sopuli.yaml"))

    assert str(caught.value).startswith("sopuli.yaml:2:")


def test_the_source_is_attached_to_a_duplicate_key_error() -> None:
    """The duplicate is found by the constructor, which has no idea what file it
    is reading -- so parse_yaml has to fill the source in on the way out."""
    with pytest.raises(ConfigError) as caught:
        parse_yaml(DUPLICATED, source=Path("sopuli.yaml"))

    assert str(caught.value).startswith("sopuli.yaml:3:")


# -------------------------------------------------------------------- safe ---


def test_a_python_object_tag_is_refused() -> None:
    """The baseline: a config file may arrive from a shared drive.

    `yaml.load` with the default loader would construct this. The whole point of
    deriving from SafeLoader is that no tag can reach a Python constructor.
    """
    with pytest.raises(ConfigError):
        parse_yaml("evil: !!python/object/apply:os.system ['echo pwned']\n")

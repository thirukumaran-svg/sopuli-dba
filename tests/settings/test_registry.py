"""The registry as an artefact: what it declares, and what it refuses to declare.

Tier 0 (04-testing.md §4): pure logic, no containers, no I/O.

Most of this file is about the two lists that must not drift apart --
``SAFETY_SETTINGS`` and the merge policy on each entry -- because that drift is
how invariant 10 would be lost. Not with a wrong policy on a setting somebody
thought about, but with a new setting silently inheriting ``override``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sopuli.output.document import SCHEMA_VERSION
from sopuli.settings.registry import (
    SAFETY_SETTINGS,
    SETTINGS,
    Layer,
    MergePolicy,
    Setting,
    setting,
)

#: Named from the version the code claims, so a schema bump does not need this
#: file edited -- and cannot be half-done, since a rename without a
#: ``SCHEMA_VERSION`` change makes this path miss.
SCHEMA = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)


def test_layer_values_match_the_published_source_enum() -> None:
    """``Layer`` is serialised straight into ``invocation.options[].source``.

    The schema is the contract (invariant 12) and this enum is what the tool will
    write into it, so a layer renamed here without a schema bump has to fail
    somewhere. This is that somewhere -- read from the committed schema rather
    than from a copy of its values, which would only assert the copy.
    """
    document: Any = json.loads(SCHEMA.read_text(encoding="utf-8"))
    published = document["$defs"]["invocation"]["properties"]["options"]["additionalProperties"][
        "properties"
    ]["source"]["enum"]
    assert [str(layer) for layer in Layer] == published


def test_authority_follows_declaration_order() -> None:
    """P3's chain, highest first. The order is the enum's, not a second table."""
    assert Layer.CLI.authority < Layer.ENV.authority < Layer.PROFILE.authority
    assert Layer.BUILTIN.authority == max(one.authority for one in Layer)


def test_every_safety_setting_has_an_entry() -> None:
    """A name in the frozenset with no registry entry is a ratchet over nothing."""
    assert set(SETTINGS) >= SAFETY_SETTINGS


def test_the_registry_and_the_safety_list_agree() -> None:
    """Stated as a test as well as enforced in ``__post_init__``.

    The constructor cannot catch a name added to ``SAFETY_SETTINGS`` and to no
    entry, and this cannot catch a bad entry added in a later PR without running
    it -- between them there is no way to change one list alone.
    """
    ratcheted = {name for name, one in SETTINGS.items() if one.policy is MergePolicy.RATCHET}
    assert ratcheted == set(SAFETY_SETTINGS)


def test_the_safety_settings_are_the_ones_p3_names() -> None:
    """P3 and invariant 10 name the set: dry-run, confirm, max_targets, readonly.

    Pinned so that removing one is a decision somebody makes on purpose rather
    than a line lost in a refactor. ``--confirm`` and ``--force`` have no setting
    yet; when they arrive they belong here, and this assertion is where the
    reminder lives.

    ``locking.break_expired`` joined the set with the advisory lock (#83). P3 does
    not name it because it did not exist when P3 was written, which is the case
    this assertion is meant to catch: it is here on the same argument, not by
    resemblance. ``vaults.*.tls.verify`` joined with C13's partial blocks (#136)
    on the same argument again: §3a puts it under the ratchet, and until a second
    layer could supply it there was nothing for the ratchet to do.
    """
    assert set(SAFETY_SETTINGS) == {
        "safety.dry_run",
        "safety.readonly",
        "safety.max_targets",
        "safety.confirm_environments",
        "locking.break_expired",
        "vaults.*.tls.verify",
    }


def test_a_safety_setting_cannot_be_declared_override() -> None:
    with pytest.raises(ValueError, match="RATCHET"):
        Setting(
            name="safety.dry_run",
            type=bool,
            layers=frozenset({Layer.CLI}),
            policy=MergePolicy.OVERRIDE,
        )


def test_a_ratcheted_setting_must_be_in_the_safety_list() -> None:
    """The other direction, which is the one that hides a setting from review."""
    with pytest.raises(ValueError, match="SAFETY_SETTINGS"):
        Setting(
            name="output",
            type=str,
            layers=frozenset({Layer.CLI}),
            policy=MergePolicy.RATCHET,
        )


def test_merge_policy_has_no_default() -> None:
    """The failure mode is not a wrong policy, it is an unstated one."""
    with pytest.raises(TypeError):
        Setting(  # type: ignore[call-arg]
            name="output",
            type=str,
            layers=frozenset({Layer.CLI}),
        )


def test_a_setting_with_no_layers_is_refused() -> None:
    with pytest.raises(ValueError, match="no layers"):
        Setting(
            name="output",
            type=str,
            layers=frozenset(),
            policy=MergePolicy.OVERRIDE,
        )


def test_a_built_in_default_must_have_the_declared_type() -> None:
    with pytest.raises(ValueError, match="built-in default"):
        Setting(
            name="output",
            type=str,
            layers=frozenset({Layer.CLI}),
            policy=MergePolicy.OVERRIDE,
            builtin=1,
        )


def test_a_boolean_built_in_default_is_not_an_integer_one() -> None:
    """``isinstance(True, int)`` is true in Python, which this must not inherit.

    The same trap the resolver closes for contributions, closed once in
    ``Setting.accepts`` and used by both -- a built-in ``True`` for an int
    setting would otherwise be ratcheted against numbers by ``min()``.
    """
    with pytest.raises(ValueError, match="built-in default"):
        Setting(
            name="safety.max_targets",
            type=int,
            layers=frozenset({Layer.DEFAULTS, Layer.BUILTIN}),
            policy=MergePolicy.RATCHET,
            builtin=True,
        )


def test_accepts_is_the_one_type_rule() -> None:
    """Pinned directly, since both the constructor and the resolver rely on it."""
    max_targets = setting("safety.max_targets")
    assert max_targets.accepts(5)
    assert not max_targets.accepts(True)

    environments = setting("safety.confirm_environments")
    assert environments.accepts(("prod",))
    assert not environments.accepts(("prod", 1))
    assert not environments.accepts(["prod"])


def test_an_unsupported_type_is_refused() -> None:
    """A type with no "safest" rule must not reach the resolver to find out."""
    with pytest.raises(ValueError, match="unsupported type"):
        Setting(
            name="output",
            type=float,
            layers=frozenset({Layer.CLI}),
            policy=MergePolicy.OVERRIDE,
        )


def test_every_entry_declares_a_layer_that_can_supply_its_builtin() -> None:
    """A built-in default is layer 6, so the setting has to accept layer 6."""
    for name, one in SETTINGS.items():
        if one.builtin is not None:
            assert Layer.BUILTIN in one.layers, name


def test_lookup_of_an_unknown_setting_names_the_known_ones() -> None:
    with pytest.raises(KeyError, match="safety.dry_run"):
        setting("safety.dryrun")


def test_is_safety_matches_the_list() -> None:
    assert setting("safety.readonly").is_safety
    assert not setting("output").is_safety

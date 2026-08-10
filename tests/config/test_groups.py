"""The ``groups:`` section, and the ``safety:`` block that several sections share.

A group is a name for a label selection. The `safety:` tests are here rather than
in a file of their own because a group is the smallest section that carries one,
and §8 gives the block the same meaning wherever it appears.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.groups import build_groups
from sopuli.config.targets import build_targets

PROD_PDBS: dict[str, Any] = {"match": {"target_set": "appdb", "env": "prod"}}


def document(**groups: Any) -> dict[str, Any]:
    return {"version": 1, "groups": groups}


def only(**keys: Any) -> Any:
    built = build_groups(document(**{"prod-pdbs": {**PROD_PDBS, **keys}}))
    assert len(built) == 1
    return built[0]


def test_a_group_is_a_named_label_match() -> None:
    group = only()

    assert group.name == "prod-pdbs"
    assert group.match == (("env", "prod"), ("target_set", "appdb"))


def test_a_group_must_say_what_it_matches() -> None:
    with pytest.raises(ConfigError) as caught:
        build_groups(document(**{"prod-pdbs": {}}))

    rendered = str(caught.value)
    assert "must declare what it matches" in rendered
    assert "groups.prod-pdbs.match" in rendered


def test_an_empty_match_is_refused() -> None:
    """A group matching everything is not a group; it is `--all` with a name that
    hides what it does."""
    with pytest.raises(ConfigError) as caught:
        build_groups(document(**{"everything": {"match": {}}}))

    assert "must name at least one label" in str(caught.value)


def test_a_config_may_declare_no_groups() -> None:
    assert build_groups({"version": 1}) == ()


def test_an_unknown_group_key_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_groups(document(**{"prod-pdbs": {**PROD_PDBS, "targets": ["cdb-root-dev"]}}))

    rendered = str(caught.value)
    assert "unknown key 'targets'" in rendered
    assert "known keys here: match, safety" in rendered


def test_whether_a_group_matches_anything_is_not_checked_here() -> None:
    """It needs the target sets expanded, and a group matching nothing today may
    match something the moment a tenant is added -- so it is a question for the
    resolved view, not for the file."""
    assert only(match={"env": "nowhere"}).match == (("env", "nowhere"),)


# ----------------------------------------------------------------- safety ---


def test_a_group_may_carry_a_safety_block() -> None:
    group = only(safety={"max_targets": 5, "confirm_environments": ["prod"], "readonly": True})

    assert group.safety is not None
    assert group.safety.max_targets == 5
    assert group.safety.confirm_environments == ("prod",)
    assert group.safety.readonly is True


def test_unset_safety_fields_stay_none_rather_than_defaulting() -> None:
    """§8: safety does not follow last-one-wins -- the resolved value is the
    safest of all layers. A layer that says nothing has to be distinguishable
    from one that sets the built-in default, or "safest" cannot be computed."""
    group = only(safety={"readonly": True})

    assert group.safety is not None
    assert group.safety.max_targets is None
    assert group.safety.confirm_environments == ()


def test_a_target_may_carry_one_too() -> None:
    """§8 allows a safety block under defaults, a target, a group or a profile.
    One reader, so they cannot drift apart."""
    (target,) = build_targets(
        {
            "version": 1,
            "targets": [
                {
                    "name": "cdb-root-prod",
                    "type": "oracle",
                    "dsn": "db-prod.example.com:1521/CDBPROD.pdb.example.com",
                    "safety": {"readonly": True},
                }
            ],
        }
    )

    assert target.safety is not None
    assert target.safety.readonly is True


def test_max_targets_below_one_is_refused() -> None:
    """`readonly: true` is how a file says "touch nothing", and it says it
    legibly. A max_targets of 0 is far more likely to be a slip that then blocks
    every run for a reason nobody can find."""
    with pytest.raises(ConfigError) as caught:
        build_groups(document(**{"prod-pdbs": {**PROD_PDBS, "safety": {"max_targets": 0}}}))

    rendered = str(caught.value)
    assert "must be at least 1" in rendered
    assert "readonly: true" in rendered


def test_a_quoted_boolean_does_not_set_readonly() -> None:
    """Invariant 10: safety settings only ratchet toward safe. `readonly: "false"`
    read as truthy would be a ratchet in the wrong direction -- and read as a
    non-empty string, it would turn writes off in a file that asked for them."""
    with pytest.raises(ConfigError) as caught:
        build_groups(document(**{"prod-pdbs": {**PROD_PDBS, "safety": {"readonly": "false"}}}))

    assert "must be true or false, not a string" in str(caught.value)


def test_an_unknown_safety_key_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_groups(document(**{"prod-pdbs": {**PROD_PDBS, "safety": {"max_target": 1}}}))

    rendered = str(caught.value)
    assert "unknown key 'max_target'" in rendered
    assert "groups.prod-pdbs.safety" in rendered

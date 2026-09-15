"""`config show`'s `safety` section, and `config.targets[].safety` (#426).

A `safety:` block outside `defaults` was enforced as of #424 and **reported by
nothing**: `config show --explain` said `safety.readonly = false
[built-in default]` for a file whose target set it, and §9 defines that phrase as
precisely *nothing else spoke*. The row was right about the run and silent about
the file, and silence in that direction reads as an answer.

Tier 0: a document in, rendered lines and a JSON dict out.

What is worth asserting is not that the rows appear. It is the four places this
view can mislead:

* **the key path**, which is the thing an operator edits, and which a width cap
  turns into two identical rows;
* **which line owns a patched key**, since a target set's template and its
  `overrides:` entry both write into one flattened block;
* **a defeated relaxation**, which is in the file and is not what any run reads;
* **the JSON value**, which must be the ratcheted answer rather than the
  flattened one -- the two differ exactly where an override asks for less.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click

from sopuli.config.loading import build_config
from sopuli.config.model import Config
from sopuli.output.config_view import build_section, render_text

TARGET = {
    "type": "oracle",
    "dsn": "192.0.2.10:1521/ALPHA",
    "environment": "dev",
    "admin": {"username": "SOPULI_SVC", "auth": {"method": "env"}},
}

TEMPLATE = {
    "name": "appdb-{env}-{tenant}",
    "type": "oracle",
    "dsn": "192.0.2.10:1521/{tenant}",
    "environment": "{env}",
    "admin": {"username": "SOPULI_SVC", "auth": {"method": "env"}},
    "for_each": {"env": {"dev": {"tenant": ["alpha", "beta"]}}},
}


def build(**sections: Any) -> Config:
    return build_config(
        {
            "version": 1,
            "vaults": {"vault-dev": {"type": "hashicorp", "addr": "https://v.example.com"}},
            "accounts": ["acme_app_user"],
            "secret_template": "vault-dev:acme/{env}/db#{account}",
            **sections,
        }
    )


def one_target(safety: Any = None, **sections: Any) -> Config:
    target = {**TARGET, "name": "alpha-0", "labels": {"tier": "app"}}
    if safety is not None:
        target["safety"] = safety
    return build(targets=[target], **sections)


def section(config: Config) -> list[str]:
    """The `safety` block of the rendered view, its heading dropped."""
    # Unstyled, like every other view test here: a heading carries a bold
    # escape, and asserting on the painted form would fail the day the palette
    # changes rather than the day the view does.
    rendered = click.unstyle(render_text([Path("estate.yaml")], config, resolved=False))
    body = rendered.split("\nsafety\n")
    return [] if len(body) == 1 else body[1].split("\n\n")[0].splitlines()


def keys(config: Config) -> list[str]:
    """The `KEY` cell of each row, heading dropped."""
    return [line.split()[0] for line in section(config)[1:]]


def target_json(config: Config, name: str) -> Any:
    """`config.targets[].safety` for one target, from the resolved document."""
    section = build_section([Path("estate.yaml")], config, {}, resolved=True)
    return next(one["safety"] for one in section["targets"] if one["name"] == name)


# --------------------------------------------------------------- the rows ---


def test_a_file_with_no_block_has_no_section() -> None:
    """An empty table under a heading says only that the developer did not check."""
    assert section(one_target()) == []


def test_a_targets_block_is_reported_by_the_key_that_writes_it() -> None:
    rows = section(one_target({"readonly": True}))

    assert rows[0].split() == ["KEY", "VALUE", "NOTE"]
    assert rows[1].startswith("targets[0].safety.readonly")
    assert rows[1].split()[1] == "true"


def test_every_kind_of_place_is_listed() -> None:
    """`defaults` and a profile are in `--explain` already, and leaving them out
    here would make a map of the file's guards miss two of its six kinds."""
    config = build(
        targets=[{**TARGET, "name": "alpha-0", "labels": {"tier": "app"}}],
        groups={"app-pdbs": {"match": {"tier": "app"}, "safety": {"readonly": True}}},
        profiles={"audit": {"safety": {"max_targets": 2}}},
        defaults={"safety": {"confirm_environments": ["prod"]}},
    )

    assert keys(config) == [
        "defaults.safety.confirm_environments",
        "groups.app-pdbs.safety.readonly",
        "profiles.audit.safety.max_targets",
    ]


def test_a_block_writing_three_keys_is_three_rows() -> None:
    config = one_target({"readonly": True, "max_targets": 2, "confirm_environments": ["dev"]})

    assert keys(config) == [
        "targets[0].safety.confirm_environments",
        "targets[0].safety.max_targets",
        "targets[0].safety.readonly",
    ]


def test_a_list_renders_the_way_the_settings_table_writes_one() -> None:
    config = one_target({"confirm_environments": ["prod", "uat"]})

    assert section(config)[1].split(maxsplit=1)[1].strip() == "prod, uat"


# ------------------------------------------------- which line owns a key ---


def test_a_template_is_one_row_however_many_targets_it_generates() -> None:
    """Two targets, one line in the file. A row each would be a table that grows
    with the estate while the thing to edit stays one line."""
    config = build(target_sets={"appdb": {**TEMPLATE, "safety": {"max_targets": 4}}})

    assert keys(config) == ["target_sets.appdb.safety.max_targets"]


def test_an_override_is_its_own_line() -> None:
    config = build(
        target_sets={
            "appdb": {**TEMPLATE, "overrides": {"appdb-dev-beta": {"safety": {"readonly": True}}}}
        }
    )

    assert keys(config) == ["target_sets.appdb.overrides.appdb-dev-beta.safety.readonly"]


def test_a_key_the_override_left_alone_stays_on_the_template() -> None:
    """The flattened block holds the template's answer for every key the patch
    did not write, so addressing all of them at the override reports it as the
    source of values it never mentions."""
    config = build(
        target_sets={
            "appdb": {
                **TEMPLATE,
                "safety": {"max_targets": 4},
                "overrides": {"appdb-dev-beta": {"safety": {"readonly": True}}},
            }
        }
    )

    assert keys(config) == [
        "target_sets.appdb.overrides.appdb-dev-beta.safety.readonly",
        "target_sets.appdb.safety.max_targets",
    ]


def test_the_key_column_is_never_truncated() -> None:
    """Two `target_sets.…overrides.…` paths differ in their tail, so a width cap
    renders the answer as two identical rows -- in the column that *is* the
    answer."""
    config = build(
        target_sets={
            "appdb": {
                **TEMPLATE,
                "overrides": {"appdb-dev-beta": {"safety": {"readonly": True, "max_targets": 2}}},
            }
        }
    )

    written = keys(config)
    assert written == [
        "target_sets.appdb.overrides.appdb-dev-beta.safety.max_targets",
        "target_sets.appdb.overrides.appdb-dev-beta.safety.readonly",
    ]
    assert len(set(written)) == 2


# ------------------------------------------------ the defeated relaxation ---


def relaxing() -> Config:
    """A template that refuses, and an override for one target that asks not to."""
    return build(
        target_sets={
            "appdb": {
                **TEMPLATE,
                "safety": {"readonly": True},
                "overrides": {"appdb-dev-beta": {"safety": {"readonly": False}}},
            }
        }
    )


def test_a_defeated_relaxation_is_shown_and_marked() -> None:
    """Hiding it leaves whoever wrote `readonly: false` with no sign of it;
    showing it unmarked reads as an effective value."""
    rows = {line.split()[0]: line for line in section(relaxing())[1:]}
    override = rows["target_sets.appdb.overrides.appdb-dev-beta.safety.readonly"]

    assert "false" in override
    assert "defeated by the ratchet" in override
    assert "defeated" not in rows["target_sets.appdb.safety.readonly"]


def test_a_template_lowered_on_one_target_is_not_called_defeated() -> None:
    """It still governs every other target the set generates. Marking it would
    tell the reader a line has no effect while it governs the rest."""
    config = build(
        target_sets={
            "appdb": {
                **TEMPLATE,
                "safety": {"max_targets": 4},
                "overrides": {"appdb-dev-beta": {"safety": {"max_targets": 2}}},
            }
        }
    )

    rows = {line.split()[0]: line for line in section(config)[1:]}
    assert "defeated" not in rows["target_sets.appdb.safety.max_targets"]
    assert "defeated" not in rows["target_sets.appdb.overrides.appdb-dev-beta.safety.max_targets"]


def test_a_group_asking_for_less_than_a_target_is_marked() -> None:
    """A ratchet has losers wherever two layers disagree, and this section lists
    every layer -- so resolving only the template/override pair left the other
    pairings reading as effective values (found in review)."""
    config = one_target(
        {"max_targets": 2},
        groups={"app-pdbs": {"match": {"tier": "app"}, "safety": {"max_targets": 50}}},
    )

    rows = {line.split()[0]: line for line in section(config)[1:]}
    assert "defeated" in rows["groups.app-pdbs.safety.max_targets"]
    assert "defeated" not in rows["targets[0].safety.max_targets"]


def test_an_active_profile_asking_for_less_than_defaults_is_marked() -> None:
    config = build_config(
        {
            "version": 1,
            "vaults": {"vault-dev": {"type": "hashicorp", "addr": "https://v.example.com"}},
            "accounts": ["acme_app_user"],
            "secret_template": "vault-dev:acme/{env}/db#{account}",
            "targets": [{**TARGET, "name": "alpha-0", "labels": {"tier": "app"}}],
            "defaults": {"safety": {"readonly": True}},
            "profiles": {"ci": {"safety": {"readonly": False}}},
        },
        # Built here rather than through `one_target`, which selects no profile:
        # an inactive one patches nothing and is the next test's subject.
        profile="ci",
    )

    rows = {line.split()[0]: line for line in section(config)[1:]}
    assert "defeated" in rows["profiles.ci.safety.readonly"]


def test_a_profile_nobody_selected_is_listed_and_never_defeated() -> None:
    """It patches nothing, so it cannot lose a ratchet it never entered -- and it
    still gets a row, because the section says what the file contains."""
    config = one_target(
        defaults={"safety": {"readonly": True}},
        profiles={"ci": {"safety": {"readonly": False}}},
    )

    rows = {line.split()[0]: line for line in section(config)[1:]}
    assert "defeated" not in rows["profiles.ci.safety.readonly"]


# ----------------------------------------------------- the JSON contract ---


def test_a_target_with_no_block_reports_null() -> None:
    """An empty object would read as a block that exists and says nothing."""
    assert target_json(one_target(), "alpha-0") is None


def test_a_targets_block_reaches_the_document() -> None:
    config = one_target({"readonly": True, "max_targets": 2, "confirm_environments": ["dev"]})

    assert target_json(config, "alpha-0") == {
        "readonly": True,
        "max_targets": 2,
        "confirm_environments": ["dev"],
    }


def test_the_json_value_is_ratcheted_rather_than_flattened() -> None:
    """The case the whole property exists to get right: a contract carrying
    `readonly: false` for a target the tool then refuses to mutate is the lie
    this section was added to remove."""
    assert target_json(relaxing(), "appdb-dev-beta") == {"readonly": True}
    assert target_json(relaxing(), "appdb-dev-alpha") == {"readonly": True}


def test_an_override_may_always_refuse_more() -> None:
    """The ratchet runs both ways round."""
    config = build(
        target_sets={
            "appdb": {
                **TEMPLATE,
                "safety": {"max_targets": 50},
                "overrides": {"appdb-dev-beta": {"safety": {"max_targets": 2}}},
            }
        }
    )

    assert target_json(config, "appdb-dev-beta") == {"max_targets": 2}
    assert target_json(config, "appdb-dev-alpha") == {"max_targets": 50}


def test_an_empty_block_reports_null_like_no_block_at_all() -> None:
    """`safety: {}` is a distinct `Safety` object and guards exactly as much as
    no block, so a consumer branching on the difference would branch on nothing
    (found in review). What was written is in `config.declared`."""
    assert target_json(one_target({}), "alpha-0") is None


def test_a_group_is_not_folded_into_a_targets_block() -> None:
    """A group can refuse a mutation on this target and is not a property of it.
    Folding it in would make one object's answer depend on four, and hide which."""
    config = one_target(
        groups={"app-pdbs": {"match": {"tier": "app"}, "safety": {"readonly": True}}}
    )

    assert target_json(config, "alpha-0") is None

"""A ``safety:`` block on a target, a group or a target set, enforced (#424).

The block parsed since the config model was written, validated cleanly, appeared
in ``config show`` and refused nothing: ``readonly: true`` on a target did not
stop a mutation, ``max_targets`` on one bounded no run, and
``confirm_environments`` on one asked nobody anything. Invariant 10's guard
failing in the one direction it must not fail in, with nothing saying so.

Tier 0 (``04-testing.md`` §4): a value object in, an answer out. What the
refusals look like from a command line is ``tests/test_cli_guardrails.py``.

Three things are worth asserting rather than the arithmetic:

* **Which targets count.** The blocks that speak are the ones on targets the plan
  names, because that is the set :class:`~sopuli.plan.BlastRadius` counts and
  ``max_targets`` is compared against it. Two answers to "which targets does this
  run reach" is the bug that fires a ceiling on a run it was never aimed at.
* **That it goes through the one resolver.** The ratchet is one mechanism, and a
  second merge folded onto an already-merged answer would report the winner of
  the first pass rather than the layer somebody has to edit.
* **Where the message points.** A generated target's block may have been written
  in an ``overrides:`` entry, and reporting it against the template sends the
  reader to the one place the value is spelled the way they expected.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import Config
from sopuli.config.selection import Selection, filter_estate
from sopuli.exit_codes import ExitCode
from sopuli.safety import (
    ALLOWED_METHODS,
    CONFIRM_ENVIRONMENTS,
    MAX_TARGETS,
    READONLY,
    RefusedError,
    for_estate,
    readonly_targets,
    refuse_if_readonly,
)
from sopuli.settings import Layer, Resolved
from sopuli.settings.resolver import resolve_all
from sopuli.settings.sources import config_contributions, estate_contributions

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


def estate(*, safety: Any = None, targets: int = 1, **rest: Any) -> Config:
    """An estate of ``targets`` PDBs, the first of which may carry ``safety``."""
    declared: list[dict[str, Any]] = [
        {**TARGET, "name": f"alpha-{index}", "labels": {"tier": "app"}} for index in range(targets)
    ]
    if safety is not None:
        declared[0]["safety"] = safety
    return sections(targets=declared, **rest)


def sections(**rest: Any) -> Config:
    """A whole file, with the parts every estate here needs already written."""
    return build_config(
        {
            "version": 1,
            "vaults": {"vault-dev": {"type": "file", "addr": "./store.json"}},
            "accounts": ["acme_app_user"],
            "secret_template": "vault-dev:acme/{env}/db#{account}",
            **rest,
        }
    )


def folded(config: Config) -> dict[str, Resolved]:
    """The run's settings, re-merged with the estate's own blocks."""
    return for_estate(resolve_all(config_contributions(config)), config)


def readonly_group(name: str = "app-pdbs", tier: str = "app") -> dict[str, Any]:
    return {name: {"match": {"tier": tier}, "safety": {"readonly": True}}}


# ------------------------------------------------------- which blocks speak ---


def test_a_target_this_run_does_not_reach_says_nothing() -> None:
    """The whole reason this merge cannot happen at the boundary.

    ``alpha-0`` is readonly and the run is narrowed to ``alpha-1``; a
    contribution from it would be a refusal about a database this run never
    opens.
    """
    config = estate(safety={"readonly": True}, targets=2)
    narrowed = filter_estate(config, Selection(targets=("alpha-1",)))

    assert estate_contributions(narrowed) == {}
    assert READONLY not in folded(narrowed)


def test_a_target_in_the_plan_contributes_at_layer_four() -> None:
    config = estate(safety={"readonly": True})

    [one] = estate_contributions(config)["safety.readonly"]
    assert one.layer is Layer.OBJECT
    assert one.value is True
    assert one.detail == "targets[0].safety.readonly"


def test_a_group_contributes_when_it_matches_something_in_the_plan() -> None:
    config = estate(groups=readonly_group())

    [one] = estate_contributions(config)["safety.readonly"]
    assert one.layer is Layer.OBJECT
    assert one.detail == "groups.app-pdbs.safety.readonly"


def test_a_group_that_matches_nothing_in_the_plan_says_nothing() -> None:
    """A group is a population, and one this run does not enter does not govern
    it. Nothing selects *by* the group here -- its block applies because a target
    it matches is in the plan, and stops applying when none is."""
    config = estate(groups=readonly_group("db-pdbs", tier="db"))

    assert estate_contributions(config) == {}


def test_a_target_set_template_carries_its_block_to_what_it_generates() -> None:
    """§4: a set's template is a target, so its ``safety:`` is a target's."""
    config = sections(target_sets={"appdb": {**TEMPLATE, "safety": {"readonly": True}}})

    locations = {one.detail for one in estate_contributions(config)["safety.readonly"]}
    assert locations == {"target_sets.appdb.safety.readonly"}


def test_an_override_is_reported_against_the_override() -> None:
    """The template is the one place the value is spelled the way the reader
    expects, so pointing there would be exactly the wrong line."""
    config = sections(
        target_sets={
            "appdb": {**TEMPLATE, "overrides": {"appdb-dev-beta": {"safety": {"readonly": True}}}}
        }
    )

    [one] = estate_contributions(config)["safety.readonly"]
    assert one.detail == "target_sets.appdb.overrides.appdb-dev-beta.safety.readonly"


# ---------------------------------- the override that must not relax (#424) ---
#
# `_patch_target` merges a patch into the template key by key, so a patch's
# `readonly: false` replaces a template's `true` -- and until the review on #425
# the safer of the two was gone before anything could ratchet them. Harmless
# while nothing enforced a target's block, and an invariant 10 hole the moment
# something did: a run narrowed to the patched target had nothing left to be
# safest of. `_patch_target`'s docstring had claimed this could not happen since
# it was written.


def relaxing() -> Config:
    """A template that refuses everything, and an override that asks not to."""
    return sections(
        target_sets={
            "appdb": {
                **TEMPLATE,
                "safety": {"readonly": True, "max_targets": 1, "confirm_environments": ["dev"]},
                "overrides": {
                    "appdb-dev-beta": {
                        "safety": {
                            "readonly": False,
                            "max_targets": 50,
                            "confirm_environments": [],
                        }
                    }
                },
            }
        }
    )


def only_beta(config: Config) -> Config:
    """Narrowed to the patched target, so nothing else can hold the line."""
    return filter_estate(config, Selection(targets=("appdb-dev-beta",)))


def test_an_override_cannot_relax_what_the_template_set() -> None:
    narrowed = only_beta(relaxing())
    answers = folded(narrowed)

    assert answers[READONLY].value is True
    assert answers[MAX_TARGETS].value == 1
    assert answers[CONFIRM_ENVIRONMENTS].value == ("dev",)


def test_the_defeated_override_is_not_the_line_the_message_names() -> None:
    """The template is where the value that held was written, and it is the only
    line editing which changes anything."""
    narrowed = only_beta(relaxing())
    answers = folded(narrowed)

    assert answers[READONLY].location == "target_sets.appdb.safety.readonly"
    assert answers[MAX_TARGETS].location == "target_sets.appdb.safety.max_targets"


def test_a_defeated_override_still_leaves_the_target_named() -> None:
    """The flattened block says ``readonly: false``, so a message reading only
    that would drop the target while the refusal still fired -- the right refusal
    with a worse message, which is the failure hardest to notice."""
    narrowed = only_beta(relaxing())

    with pytest.raises(RefusedError) as raised:
        refuse_if_readonly(folded(narrowed), action="applying a password", estate=narrowed)

    assert "appdb-dev-beta (target_sets.appdb.safety.readonly)" in (raised.value.hint or "")


def test_an_override_that_tightens_wins_and_is_reported() -> None:
    """The ratchet runs both ways round: an override may always refuse *more*,
    and then it is the line to point at."""
    config = sections(
        target_sets={
            "appdb": {
                **TEMPLATE,
                "safety": {"max_targets": 50},
                "overrides": {"appdb-dev-beta": {"safety": {"max_targets": 2}}},
            }
        }
    )
    narrowed = only_beta(config)

    answer = folded(narrowed)[MAX_TARGETS]
    assert answer.value == 2
    assert answer.location == "target_sets.appdb.overrides.appdb-dev-beta.safety.max_targets"


def test_a_key_the_override_left_alone_is_reported_against_the_template() -> None:
    """A patch merges key by key, so the flattened block holds the template's
    answer for every key the patch did not write. Contributing that at the
    override's line would send the reader to a block that does not mention it."""
    config = sections(
        target_sets={
            "appdb": {
                **TEMPLATE,
                "safety": {"readonly": True, "max_targets": 4},
                "overrides": {"appdb-dev-beta": {"safety": {"max_targets": 2}}},
            }
        }
    )
    narrowed = only_beta(config)

    assert folded(narrowed)[READONLY].location == "target_sets.appdb.safety.readonly"


# ------------------------------------------------------------- the ratchet ---


def test_it_ratchets_against_the_layers_already_resolved() -> None:
    """One resolver, one merge. A ``defaults:`` ceiling of 4 and a target's of 1
    resolve to 1, and the reported location is the target's -- the lowest of the
    two contributors to the value that held (§9, "ties resolve downward")."""
    config = estate(safety={"max_targets": 1}, defaults={"safety": {"max_targets": 4}})

    answer = folded(config)[MAX_TARGETS]
    assert answer.value == 1
    assert answer.location == "targets[0].safety.max_targets"


def test_a_target_cannot_relax_what_defaults_set() -> None:
    """Invariant 10 in the direction that matters: layer 4 is *higher* than
    layer 5, and a higher layer still loses when it asks for less safety."""
    config = estate(safety={"readonly": False}, defaults={"safety": {"readonly": True}})

    answer = folded(config)[READONLY]
    assert answer.value is True
    assert answer.location == "defaults.safety.readonly"


def test_confirm_environments_unions_across_the_layers() -> None:
    config = estate(
        safety={"confirm_environments": ["dev"]},
        defaults={"safety": {"confirm_environments": ["prod"]}},
    )

    assert folded(config)[CONFIRM_ENVIRONMENTS].value == ("dev", "prod")


def test_allowed_methods_intersects_across_the_layers() -> None:
    """The other list setting, merged the other way, at the layer only this merge
    can reach (H6, #453). A target permitting less than ``defaults`` does narrow
    the estate's set -- and the union that governs the line above would have
    widened it instead."""
    config = estate(
        safety={"delivery": {"allowed_methods": ["vault_wrapped"]}},
        defaults={"safety": {"delivery": {"allowed_methods": ["vault_wrapped", "manual"]}}},
    )

    answer = folded(config)[ALLOWED_METHODS]
    assert answer.value == ("vault_wrapped",)
    assert answer.location == "targets[0].safety.delivery.allowed_methods"


def test_a_target_disjoint_with_defaults_is_refused_at_the_estate_merge() -> None:
    """The case the boundary cannot see, and the reason the refusal lives in the
    resolver rather than in a verb: these two layers are compatible until a run
    selects the target that makes them disjoint, and every verb reaches the same
    merge without having to remember to check."""
    config = estate(
        safety={"delivery": {"allowed_methods": ["manual"]}},
        defaults={"safety": {"delivery": {"allowed_methods": ["vault_wrapped"]}}},
    )

    with pytest.raises(ConfigError) as raised:
        folded(config)

    assert "resolves to nothing" in str(raised.value)
    assert "targets[0].safety.delivery.allowed_methods allows manual" in str(raised.value)
    assert raised.value.exit_code is ExitCode.CONFIG_INVALID


def test_a_setting_no_object_wrote_is_returned_untouched() -> None:
    config = estate(defaults={"safety": {"readonly": True}})
    before = resolve_all(config_contributions(config))

    assert for_estate(before, config) == before


def test_the_builtin_stays_a_fallback_rather_than_a_contributor() -> None:
    """``safety.readonly`` has a built-in ``false``. Carrying it into the second
    merge would make layer 6 take part in the ratchet rather than fall back to
    it, and would report ``builtin`` as a contributor to an answer a file gave."""
    config = estate(safety={"readonly": True})

    answer = folded(config)[READONLY]
    assert Layer.BUILTIN not in {one.layer for one in answer.contributions}


# --------------------------------------------------------- what it refuses ---


def test_it_refuses_a_mutation_and_names_the_target() -> None:
    config = estate(safety={"readonly": True})

    with pytest.raises(RefusedError) as raised:
        refuse_if_readonly(folded(config), action="applying a password", estate=config)

    assert raised.value.exit_code == ExitCode.ABORTED
    assert raised.value.category == "policy"
    assert "the target it reaches" in str(raised.value)
    assert "alpha-0 (targets[0].safety.readonly)" in (raised.value.hint or "")


def test_a_partial_refusal_says_how_much_and_offers_a_narrowing() -> None:
    """#424 chose a refusal over a partial run, so the message has to hand back
    the mechanism that *does* narrow -- otherwise the operator is told no and
    left to work out what to type."""
    config = estate(safety={"readonly": True}, targets=3)

    with pytest.raises(RefusedError) as raised:
        refuse_if_readonly(folded(config), action="rotating a password", estate=config)

    assert "1 of the 3 targets it reaches" in str(raised.value)
    assert "--target, --group or --select" in (raised.value.hint or "")


def test_a_refusal_nothing_can_escape_does_not_suggest_narrowing() -> None:
    """Advice that cannot work is worse than none: every target is marked, so a
    selector has nothing to leave in."""
    config = estate(targets=3, groups=readonly_group())

    with pytest.raises(RefusedError) as raised:
        refuse_if_readonly(folded(config), action="rotating a password", estate=config)

    assert "every target it reaches" in str(raised.value)
    hint = raised.value.hint or ""
    assert "no narrowing of this run can avoid them" in hint
    assert "--target" not in hint


def test_a_group_marks_the_targets_it_matches() -> None:
    """A group has no key of its own to point a target at, so the message pairs
    the two: which database is protected, and which line protects it."""
    config = estate(groups=readonly_group())

    [marked] = readonly_targets(config)
    assert marked.name == "alpha-0"
    assert marked.location == "groups.app-pdbs.safety.readonly"


def test_a_targets_own_block_wins_over_a_group_that_also_marks_it() -> None:
    """Same layer, so §9's tie-break has nothing to separate them. The target's
    own is the more specific place and the one an operator finds first."""
    config = estate(safety={"readonly": True}, groups=readonly_group())

    [marked] = readonly_targets(config)
    assert marked.location == "targets[0].safety.readonly"


def test_a_long_list_is_abbreviated_and_the_count_is_not() -> None:
    """The message exists so somebody can find the key to edit, and five names do
    that as well as two hundred would."""
    config = estate(targets=9, groups=readonly_group())

    with pytest.raises(RefusedError) as raised:
        refuse_if_readonly(folded(config), action="rotating a password", estate=config)

    assert "every target it reaches" in str(raised.value)
    assert "and 4 more" in (raised.value.hint or "")


def test_without_an_estate_the_message_is_the_one_it_always_was() -> None:
    """The pre-selection gate is unchanged: a ``defaults``-level readonly still
    refuses before a bad selector is judged, which keeps exit 8 for a run that was
    never going to write rather than exit 2 for a typo in it."""
    config = estate(defaults={"safety": {"readonly": True}})

    with pytest.raises(RefusedError) as raised:
        refuse_if_readonly(resolve_all(config_contributions(config)), action="applying a password")

    assert raised.value.args[0] == (
        "applying a password is a mutation, and `safety.readonly` is set"
    )
    assert "defaults.safety.readonly" in (raised.value.hint or "")

"""Which targets a selector names (§3, §4).

Selection is filtering, never construction: every target that comes out of it
came out of expansion first (invariant 5). The tests are written against a mixed
estate -- one explicit target with labels of its own, and a set that generates
the rest -- because C8's whole point is that the two kinds select uniformly.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ArgumentError, ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import Config, TargetSelector
from sopuli.config.selection import filter_estate, matches, parse_selector, select
from sopuli.exit_codes import ExitCode

ESTATE: dict[str, Any] = {
    "version": 1,
    "targets": [
        {
            "name": "cdb-root-dev",
            "type": "oracle",
            "dsn": "db-dev.example.com:1521/CDBDEV.pdb.example.com",
            "labels": {"role": "cdb", "env": "dev"},
        },
        {
            "name": "legacy-box",
            "type": "oracle",
            "dsn": "192.0.2.75:1521/legacy.example.com",
        },
    ],
    "target_sets": {
        "appdb": {
            "type": "oracle",
            "name": "appdb-{env}-{tenant}",
            "dsn": "{host}:1521/{tenant}.pdb.example.com",
            "for_each": {
                "env": {
                    "dev": {"host": "db-dev.example.com", "tenant": ["alpha", "beta"]},
                    "qa": {"host": "db-test.example.com", "tenant": ["alpha"]},
                }
            },
        }
    },
    "groups": {
        "dev-pdbs": {"match": {"target_set": "appdb", "env": "dev"}},
        "everything-appdb": {"match": {"target_set": "appdb"}},
    },
}


def estate() -> Config:
    return build_config(ESTATE)


def names(config: Config, selector: TargetSelector) -> list[str]:
    return [expanded.name for expanded in select(config, selector)]


# ------------------------------------------------------------------ matches ---


def test_every_pair_has_to_match() -> None:
    """A match is an AND. `{env: dev, tenant: alpha}` naming every dev target
    would make `groups:` useless as a way to narrow one."""
    config = estate()
    alpha = next(t.target for t in config.expanded_targets if t.name == "appdb-dev-alpha")

    assert matches(alpha, (("env", "dev"),))
    assert matches(alpha, (("env", "dev"), ("tenant", "alpha")))
    assert not matches(alpha, (("env", "dev"), ("tenant", "beta")))


def test_a_label_the_target_does_not_carry_never_matches() -> None:
    config = estate()
    legacy = next(t.target for t in config.expanded_targets if t.name == "legacy-box")

    assert not matches(legacy, (("env", "dev"),))


# ----------------------------------------------------------------- selectors ---


def test_saying_nothing_selects_the_whole_estate() -> None:
    """§3: `targets` defaults to all targets, which is what an inline
    application relies on."""
    config = estate()

    everything = [expanded.name for expanded in config.expanded_targets]
    assert names(config, TargetSelector()) == everything


def test_names_select_exactly_those_targets() -> None:
    config = estate()

    assert names(config, TargetSelector(names=("legacy-box", "appdb-qa-alpha"))) == [
        "legacy-box",
        "appdb-qa-alpha",
    ]


def test_names_are_returned_in_estate_order_not_the_order_written() -> None:
    """Two applications selecting the same targets by different routes produce
    the same list, so their plan output is comparable line by line."""
    config = estate()

    assert names(config, TargetSelector(names=("appdb-qa-alpha", "cdb-root-dev"))) == [
        "cdb-root-dev",
        "appdb-qa-alpha",
    ]


def test_a_repeated_name_selects_one_target() -> None:
    config = estate()

    assert names(config, TargetSelector(names=("legacy-box", "legacy-box"))) == ["legacy-box"]


def test_a_group_selects_what_its_match_says() -> None:
    config = estate()

    assert names(config, TargetSelector(group="dev-pdbs")) == ["appdb-dev-alpha", "appdb-dev-beta"]


def test_a_match_selects_directly() -> None:
    config = estate()

    assert names(config, TargetSelector(match=(("env", "qa"),))) == ["appdb-qa-alpha"]


def test_an_explicit_target_is_selectable_by_its_own_labels() -> None:
    """C8: labels are allowed on explicit targets so mixed estates select
    uniformly. `env=dev` finds the CDB root and the generated dev PDBs together."""
    config = estate()

    assert names(config, TargetSelector(match=(("env", "dev"),))) == [
        "cdb-root-dev",
        "appdb-dev-alpha",
        "appdb-dev-beta",
    ]


def test_a_match_that_selects_nothing_selects_nothing() -> None:
    """Not an error here. Whether an application selecting no targets is worth
    reporting is a question for the view that renders it, not for the filter."""
    config = estate()

    assert names(config, TargetSelector(match=(("env", "prod"),))) == []


def test_selection_cannot_introduce_a_target(  # invariant 5
) -> None:
    """Every result is an object from the expanded estate, not a name looked up
    and rebuilt. A selector filters the whitelist; it cannot extend it."""
    config = estate()
    selected = select(config, TargetSelector(match=(("target_set", "appdb"),)))

    assert all(expanded in config.expanded_targets for expanded in selected)


# ----------------------------------------------------------- parse_selector ---


def test_one_pair_is_a_match() -> None:
    assert parse_selector(["env=qa"]) == (("env", "qa"),)


def test_several_pairs_in_one_option_are_all_of_them() -> None:
    assert parse_selector(["env=qa,tenant=beta"]) == (("env", "qa"), ("tenant", "beta"))


def test_repeats_accumulate() -> None:
    """`--select env=qa --select tenant=beta` is the same request as writing both
    in one option. Two spellings of one thought should not select differently."""
    assert parse_selector(["env=qa", "tenant=beta"]) == parse_selector(["env=qa,tenant=beta"])


def test_the_result_is_ordered_by_key() -> None:
    """So that two spellings of one selector render identically -- the pairs
    reach `invocation.selection` and the text header, and a document that
    differs by argument order is a document that cannot be diffed."""
    assert parse_selector(["tenant=beta,env=qa"]) == parse_selector(["env=qa,tenant=beta"])


def test_surrounding_space_is_not_part_of_a_label() -> None:
    """`--select "env = qa"` is one shell quoting accident away from normal."""
    assert parse_selector(["env = qa"]) == (("env", "qa"),)


def test_no_selector_at_all_is_an_empty_match() -> None:
    assert parse_selector([]) == ()


def test_the_same_pair_twice_is_not_a_conflict() -> None:
    """Harmless repetition, and refusing it would only punish a generated
    command line that appended the same filter twice."""
    assert parse_selector(["env=qa", "env=qa"]) == (("env", "qa"),)


def test_one_key_with_two_values_is_refused() -> None:
    """A match is a conjunction, so `env=dev,env=qa` can only ever select
    nothing. Answering "or" with an empty estate would be a silent wrong answer
    to a question the tool cannot yet ask (C2)."""
    with pytest.raises(ConfigError) as caught:
        parse_selector(["env=dev,env=qa"])

    assert "selected twice" in str(caught.value)
    assert "dev" in str(caught.value)
    assert "qa" in str(caught.value)


@pytest.mark.parametrize("value", ["env", "env qa", ""])
def test_a_pair_without_an_equals_sign_is_refused(value: str) -> None:
    with pytest.raises(ConfigError) as caught:
        parse_selector([value])

    assert f"'{value}' is not a label match" in str(caught.value)


@pytest.mark.parametrize("value", ["env=", "=qa", "  =  "])
def test_an_empty_side_is_refused(value: str) -> None:
    """`--select env=` is a shell variable that did not expand, which is a
    different mistake from asking for targets whose `env` is empty."""
    with pytest.raises(ConfigError) as caught:
        parse_selector([value])

    assert "empty" in str(caught.value)


def test_a_selector_error_exits_as_a_usage_error() -> None:
    """ "You typed it wrong" is 2, so a scheduler can tell it from a failure.

    An `ArgumentError` rather than a plain `ConfigError`, which is what keeps it
    on 2 now that a bad *file* is 9 (#8). Nothing is wrong with any file here,
    and the location says so: `--select`, not a key path.
    """
    with pytest.raises(ArgumentError) as caught:
        parse_selector(["nonsense"])

    assert caught.value.exit_code == ExitCode.USAGE
    assert str(caught.value.at) == "--select"


# ------------------------------------------------------------ filter_estate ---


def test_filtering_keeps_the_targets_that_carry_every_label() -> None:
    config = filter_estate(estate(), (("env", "dev"), ("tenant", "alpha")))

    assert [expanded.name for expanded in config.expanded_targets] == ["appdb-dev-alpha"]


def test_filtering_keeps_estate_order() -> None:
    """Not the order the selector wrote, for the reason `select` gives: two
    routes to the same set must produce the same list."""
    config = filter_estate(estate(), (("target_set", "appdb"),))
    everything = [expanded.name for expanded in estate().expanded_targets]

    assert [expanded.name for expanded in config.expanded_targets] == [
        name for name in everything if name.startswith("appdb-")
    ]


def test_an_empty_match_changes_nothing() -> None:
    """A command with no `--select` and one whose selector spans the estate take
    the same path, so there is no filtered/unfiltered branch to get wrong."""
    config = estate()

    assert filter_estate(config, ()) is config


def test_a_match_selecting_nothing_leaves_an_empty_estate() -> None:
    config = filter_estate(estate(), (("env", "staging"),))

    assert config.expanded_targets == ()
    assert config.bindings == ()


def test_filtering_cannot_introduce_a_target(  # invariant 5
) -> None:
    """`--force` cannot widen the whitelist and neither can a selector: every
    survivor is an object that was already in the estate."""
    config = estate()
    filtered = filter_estate(config, (("target_set", "appdb"),))

    assert all(expanded in config.expanded_targets for expanded in filtered.expanded_targets)


def test_the_rest_of_the_config_is_untouched() -> None:
    """Filtering narrows what a run acts on, not what the file says. `targets:`
    and `target_sets:` still describe the whole estate, which is what the
    declared view renders."""
    config = estate()
    filtered = filter_estate(config, (("env", "qa"),))

    assert filtered.targets == config.targets
    assert filtered.target_sets == config.target_sets
    assert filtered.groups == config.groups

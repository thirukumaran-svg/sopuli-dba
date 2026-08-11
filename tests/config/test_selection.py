"""Which targets a selector names (§3, §4).

Selection is filtering, never construction: every target that comes out of it
came out of expansion first (invariant 5). The tests are written against a mixed
estate -- one explicit target with labels of its own, and a set that generates
the rest -- because C8's whole point is that the two kinds select uniformly.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.loading import build_config
from sopuli.config.model import Config, TargetSelector
from sopuli.config.selection import matches, select

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

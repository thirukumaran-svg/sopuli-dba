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
from sopuli.config.selection import (
    LeftOut,
    Selection,
    filter_estate,
    filter_to_pairs,
    matches,
    narrow,
    narrow_to_pairs,
    parse_selector,
    refuse_unknown,
    select,
)
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
    on 2 now that a bad *file* is 9 (J7). Nothing is wrong with any file here,
    and the location says so: `--select`, not a key path.
    """
    with pytest.raises(ArgumentError) as caught:
        parse_selector(["nonsense"])

    assert caught.value.exit_code == ExitCode.USAGE
    assert str(caught.value.at) == "--select"


# ------------------------------------------------------------ filter_estate ---


def test_filtering_keeps_the_targets_that_carry_every_label() -> None:
    config = filter_estate(estate(), Selection(select=(("env", "dev"), ("tenant", "alpha"))))

    assert [expanded.name for expanded in config.expanded_targets] == ["appdb-dev-alpha"]


def test_filtering_keeps_estate_order() -> None:
    """Not the order the selector wrote, for the reason `select` gives: two
    routes to the same set must produce the same list."""
    config = filter_estate(estate(), Selection(select=(("target_set", "appdb"),)))
    everything = [expanded.name for expanded in estate().expanded_targets]

    assert [expanded.name for expanded in config.expanded_targets] == [
        name for name in everything if name.startswith("appdb-")
    ]


def test_an_empty_match_changes_nothing() -> None:
    """A command with no `--select` and one whose selector spans the estate take
    the same path, so there is no filtered/unfiltered branch to get wrong."""
    config = estate()

    assert filter_estate(config, Selection()) is config


def test_a_match_selecting_nothing_leaves_an_empty_estate() -> None:
    config = filter_estate(estate(), Selection(select=(("env", "staging"),)))

    assert config.expanded_targets == ()
    assert config.bindings == ()


def test_filtering_cannot_introduce_a_target(  # invariant 5
) -> None:
    """`--force` cannot widen the whitelist and neither can a selector: every
    survivor is an object that was already in the estate."""
    config = estate()
    filtered = filter_estate(config, Selection(select=(("target_set", "appdb"),)))

    assert all(expanded in config.expanded_targets for expanded in filtered.expanded_targets)


def test_the_rest_of_the_config_is_untouched() -> None:
    """Filtering narrows what a run acts on, not what the file says. `targets:`
    and `target_sets:` still describe the whole estate, which is what the
    declared view renders."""
    config = estate()
    filtered = filter_estate(config, Selection(select=(("env", "qa"),)))

    assert filtered.targets == config.targets
    assert filtered.target_sets == config.target_sets
    assert filtered.groups == config.groups


# ------------------------------------------------------- filter_to_pairs ---


BOUND: dict[str, Any] = {
    "version": 1,
    "vaults": {"vault-dev": {"type": "hashicorp"}},
    "target_sets": {
        "appdb": {
            "type": "oracle",
            "name": "appdb-{env}-{tenant}",
            "dsn": "{host}:1521/{tenant}.pdb.example.com",
            "environment": "{env}",
            "vault": "vault-dev",
            "for_each": {
                "env": {"dev": {"host": "db-dev.example.com", "tenant": ["alpha", "beta"]}}
            },
        }
    },
    "applications": [
        {
            "name": "acme",
            "accounts": ["acme_web_user", "acme_batch_user"],
            "secret_template": "acme/{env}/{account}#password",
        }
    ],
}


def bound() -> Config:
    """Two accounts across two targets, so a pair set is not a cross product.

    Four bindings from two accounts and two targets is the whole reason this
    function exists: any selection built from independent dimensions can only
    ask for all four.
    """
    return build_config(BOUND)


def pairs_of(config: Config) -> set[tuple[str, str]]:
    return {(binding.account, binding.target) for binding in config.bindings}


def test_a_pair_set_is_not_a_cross_product() -> None:
    """The reason `Selection` cannot do this.

    One account on one target and the other on the other. `--account a --account
    b --target x --target y` selects all four; this selects the two asked for,
    and the two it leaves out are the logins `--repair` exists to save.
    """
    config = filter_to_pairs(
        bound(),
        [("acme_web_user", "appdb-dev-alpha"), ("acme_batch_user", "appdb-dev-beta")],
    )

    assert pairs_of(config) == {
        ("acme_web_user", "appdb-dev-alpha"),
        ("acme_batch_user", "appdb-dev-beta"),
    }
    assert len(bound().bindings) == 4


def test_an_account_is_matched_case_folded() -> None:
    """A pair set that has been through a database carries Oracle's spelling.
    `--account` already folds for this reason and a pair must not differ."""
    config = filter_to_pairs(bound(), [("ACME_WEB_USER", "appdb-dev-alpha")])

    assert pairs_of(config) == {("acme_web_user", "appdb-dev-alpha")}


def test_a_pair_the_config_no_longer_declares_is_dropped() -> None:  # invariant 5
    """Dropped and not refused, which is the opposite of `refuse_unknown`.

    A document describes a run that already happened, so a pair since removed
    from the config is drift somebody dealt with -- and refusing would make the
    document unusable for the accounts it is still right about.
    """
    config = filter_to_pairs(
        bound(),
        [("acme_web_user", "appdb-dev-alpha"), ("gone_user", "appdb-dev-alpha")],
    )

    assert pairs_of(config) == {("acme_web_user", "appdb-dev-alpha")}


def test_a_pair_naming_an_undeclared_target_is_dropped() -> None:  # invariant 5
    """The other half of the same rule. A target the file no longer declares
    cannot be reached by naming it in a document."""
    config = filter_to_pairs(bound(), [("acme_web_user", "appdb-prod-alpha")])

    assert config.bindings == ()
    assert config.expanded_targets == ()


def test_filtering_to_pairs_cannot_introduce_anything() -> None:  # invariant 5
    """Every survivor is an object that was already in the estate, which is how
    invariant 5 holds structurally here rather than by inspection."""
    config = bound()
    filtered = filter_to_pairs(config, [("acme_web_user", "appdb-dev-alpha")])

    assert all(binding in config.bindings for binding in filtered.bindings)
    assert all(expanded in config.expanded_targets for expanded in filtered.expanded_targets)


def test_a_target_left_with_no_bindings_is_pruned() -> None:
    """What keeps the blast radius honest: a repair of two pairs on one target
    is a run reaching one target, and `max_targets` must answer about that."""
    config = filter_to_pairs(
        bound(),
        [("acme_web_user", "appdb-dev-alpha"), ("acme_batch_user", "appdb-dev-alpha")],
    )

    assert [expanded.name for expanded in config.expanded_targets] == ["appdb-dev-alpha"]


def test_an_empty_pair_set_selects_nothing() -> None:
    """Not "everything", which is `filter_estate`'s rule for an empty
    `Selection` and would be exactly wrong here: an empty repair set means the
    run being repaired left nothing unconfirmed."""
    config = filter_to_pairs(bound(), [])

    assert config.bindings == ()
    assert config.expanded_targets == ()


def test_filtering_to_pairs_leaves_the_rest_of_the_config_untouched() -> None:
    """Filtering narrows what a run acts on, not what the file says.

    Named apart from `filter_estate`'s version of this above: two module-level
    functions with one name is the later one silently replacing the earlier, and
    a test that never runs is worse than one that fails.
    """
    config = bound()
    filtered = filter_to_pairs(config, [("acme_web_user", "appdb-dev-alpha")])

    assert filtered.targets == config.targets
    assert filtered.target_sets == config.target_sets
    assert filtered.applications == config.applications


# ------------------------------------------------- what "named" means ---


class TestNames:
    """`Selection.names` carries §4's guardrail rule, so it is worth its own set.

    An account the operator **named** refuses the run; one that merely fell
    inside a broader selection is skipped. Everything about that rule turns on
    this predicate.
    """

    def test_an_account_selector_names_it(self) -> None:
        assert Selection(accounts=("acme_web_user",)).names("acme_web_user")

    def test_matching_is_case_folded(self) -> None:
        """The file writes `acme_web_user` and Oracle hands back
        `ACME_WEB_USER`; the rule must not turn on which spelling arrived."""
        assert Selection(accounts=("acme_web_user",)).names("ACME_WEB_USER")
        assert Selection(accounts=("ACME_WEB_USER",)).names("acme_web_user")

    def test_another_account_is_not_named(self) -> None:
        assert not Selection(accounts=("acme_web_user",)).names("acme_batch_user")

    def test_naming_a_target_does_not_name_its_accounts(self) -> None:
        """The branch the whole rule depends on.

        The tempting implementation is "the selection resolved to one account, so
        they must have meant it" -- which would make a safety rule change
        behaviour according to how many rows an estate happens to have today.
        """
        assert not Selection(targets=("appdb-alpha",)).names("acme_web_user")

    def test_naming_a_group_or_application_does_not_either(self) -> None:
        assert not Selection(groups=("prod-pdbs",)).names("acme_web_user")
        assert not Selection(applications=("acme",)).names("acme_web_user")

    def test_a_label_selector_does_not_either(self) -> None:
        assert not Selection(select=(("env", "prod"),)).names("acme_web_user")

    def test_an_empty_selection_names_nothing(self) -> None:
        assert not Selection().names("acme_web_user")


# ---------------------------------------------------- unknown names ---


class TestRefuseUnknown:
    """A name that names nothing is a typo; a label that matches nothing is not."""

    def test_a_declared_target_passes(self) -> None:
        refuse_unknown(estate(), Selection(targets=("appdb-dev-alpha",)))

    def test_an_undeclared_target_is_refused(self) -> None:
        with pytest.raises(ArgumentError) as raised:
            refuse_unknown(estate(), Selection(targets=("appdb-nowhere",)))

        assert "appdb-nowhere" in str(raised.value)

    def test_a_label_matching_nothing_is_not_refused(self) -> None:
        """Labels describe an estate that changes underneath them, so an empty
        result is a true answer about today rather than a mistake."""
        refuse_unknown(estate(), Selection(select=(("env", "nowhere"),)))

    def test_the_hint_names_what_is_declared(self) -> None:
        """A typo is cleared by seeing the right spelling."""
        with pytest.raises(ArgumentError) as raised:
            refuse_unknown(estate(), Selection(targets=("appdb-nowhere",)))

        assert "appdb-" in str(raised.value.hint)

    def test_it_reports_every_missing_name_at_once(self) -> None:
        """Three runs to learn one fact is the failure mode of reporting the
        first only -- the same argument the guardrail reasons make."""
        with pytest.raises(ArgumentError) as raised:
            refuse_unknown(estate(), Selection(targets=("nope-one", "nope-two")))

        assert "nope-one" in str(raised.value)
        assert "nope-two" in str(raised.value)


# ------------------------------------------------------------------ left_out ---


GROUPED: dict[str, Any] = {
    **BOUND,
    "groups": {"alpha-pdbs": {"match": {"tenant": "alpha"}}},
    "applications": [
        *BOUND["applications"],
        {
            "name": "acme-reports",
            "accounts": ["acme_report_user"],
            "secret_template": "acme-reports/{env}/{account}#password",
            "targets": ["appdb-dev-alpha"],
        },
    ],
}


def left_out(config: Config, selection: Selection) -> tuple[LeftOut, ...]:
    return narrow(config, selection)[1]


def flags(selection: Selection) -> dict[tuple[str | None, str], str]:
    found = left_out(build_config(GROUPED), selection)
    return {(one.account, one.target): one.flag for one in found}


@pytest.mark.parametrize(
    ("selection", "flag"),
    [
        (Selection(targets=("appdb-dev-alpha",)), "--target"),
        (Selection(select=(("tenant", "alpha"),)), "--select"),
        (Selection(groups=("alpha-pdbs",)), "--group"),
    ],
)
def test_a_target_left_out_is_named_once_with_the_flag_that_did_it(
    selection: Selection, flag: str
) -> None:
    """#788: one line for the target, not one per binding on it."""
    assert flags(selection) == {(None, "appdb-dev-beta"): flag}


@pytest.mark.parametrize(
    ("selection", "flag"),
    [
        (Selection(accounts=("ACME_WEB_USER",)), "--account"),
        (Selection(applications=("acme",)), "--application"),
    ],
)
def test_a_binding_left_out_is_named_with_the_flag_that_did_it(
    selection: Selection, flag: str
) -> None:
    """Checked against what `filter_estate` removes, so the two agree. The
    account in the first case is matched case-folded."""
    config = build_config(GROUPED)
    kept = pairs_of(filter_estate(config, selection))

    found = flags(selection)

    assert set(found) == pairs_of(config) - kept
    assert found
    assert set(found.values()) == {flag}


def test_a_target_left_with_no_bindings_is_named_with_the_binding_flag() -> None:
    """`filter_estate` drops a target that `--application` emptied, so
    `left_out` says so. `acme-reports` is declared on one target only."""
    selection = Selection(applications=("acme-reports",))

    found = left_out(build_config(GROUPED), selection)

    assert LeftOut("appdb-dev-beta", "--application") in found
    narrowed = filter_estate(build_config(GROUPED), selection)
    assert [t.name for t in narrowed.expanded_targets] == ["appdb-dev-alpha"]


def test_a_target_with_no_bindings_is_reported() -> None:
    """`target list` and `doctor` select targets nothing is declared against."""
    found = left_out(estate(), Selection(select=(("env", "qa"),)))

    assert LeftOut("legacy-box", "--select") in found
    assert all(one.account is None for one in found)


def test_saying_nothing_leaves_nothing_out() -> None:
    assert left_out(build_config(GROUPED), Selection()) == ()


def test_the_pairs_a_repair_set_leaves_out_are_named() -> None:
    _, found = narrow_to_pairs(bound(), [("ACME_WEB_USER", "appdb-dev-alpha")])

    accounts = {(one.account, one.target) for one in found if one.account is not None}
    assert accounts == pairs_of(bound()) - {("acme_web_user", "appdb-dev-alpha")}
    assert LeftOut("appdb-dev-beta", "--repair") in found
    assert {one.flag for one in found} == {"--repair"}


def test_an_emptied_target_is_named_with_the_flag_that_removed_its_bindings() -> None:
    """Both binding flags given: the one that removed the target's first
    binding is named, not the first flag the selection has. On beta,
    `acme_web_user` passes `--account` and `--application` removes it."""
    selection = Selection(
        accounts=("acme_report_user", "acme_web_user"), applications=("acme-reports",)
    )

    found = left_out(build_config(GROUPED), selection)

    assert LeftOut("appdb-dev-beta", "--application") in found
    assert all(one.target != "appdb-dev-alpha" or one.account for one in found)


def test_narrow_returns_what_filter_estate_returns() -> None:
    config = build_config(GROUPED)
    selection = Selection(select=(("tenant", "alpha"),), accounts=("acme_web_user",))

    assert narrow(config, selection)[0] == filter_estate(config, selection)

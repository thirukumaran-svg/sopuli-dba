"""Is this personal account declared, and by which rule (H1, #449, #463).

Tier 0, pure: the predicate inputs arrive as a profile string and a role set, so
nothing here needs a database. That is the point of the module's shape, and these
tests are what it buys.

Fixtures use the fictional vocabulary the provenance note requires -- ``jdoe`` for
a person, who is a placeholder and not anybody, and ``acme_*_user`` for an
application's accounts.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import PersonalAccountRule
from sopuli.personal import admits, declared_on, rules_admitting, rules_for

TARGET = {
    "name": "appdb-dev-alpha",
    "type": "oracle",
    "environment": "dev",
    "dsn": "db-dev.example.com:1521/alphadev.pdb.example.com",
    "admin": {"username": "C##SOPULI_SVC", "auth": "prompt"},
    # `environment:` is a first-class field and `labels:` is what a `match:`
    # reads, so a group selecting on `env` needs the label written -- exactly as
    # a target set's dimensions would have written it.
    "labels": {"env": "dev"},
}
OTHER = {
    **TARGET,
    "name": "appdb-qa-alpha",
    "environment": "qa",
    "labels": {"env": "qa"},
}


def config(*rules: dict[str, Any]) -> Any:
    return build_config(
        {
            "version": 1,
            "targets": [TARGET, OTHER],
            "groups": {"dev-pdbs": {"match": {"env": "dev"}}},
            "policies": {
                "personal-standard": {"password": {"length": 24, "charset": "alnum"}},
                "personal-strict": {"password": {"length": 32, "charset": "alnum"}},
            },
            "personal_accounts": list(rules),
        }
    )


# --------------------------------------------------------------- admits ---


def test_an_enumerated_rule_admits_the_names_it_lists() -> None:
    rule = PersonalAccountRule(accounts=("jdoe", "asmith"))
    assert admits(rule, "jdoe")
    assert admits(rule, "asmith")
    assert not admits(rule, "bcarter")


def test_names_are_compared_case_folded() -> None:
    """A file writes `jdoe`; Oracle hands back `JDOE`, having upper-cased it."""
    assert admits(PersonalAccountRule(accounts=("jdoe",)), "JDOE")
    assert admits(PersonalAccountRule(accounts=("JDOE",)), "jdoe")


def test_a_profile_predicate_reads_the_profile_it_was_given() -> None:
    rule = PersonalAccountRule(profile="DEV_USERS")
    assert admits(rule, "jdoe", profile="DEV_USERS")
    assert admits(rule, "jdoe", profile="dev_users")
    assert not admits(rule, "jdoe", profile="APP_PROF")


def test_a_profile_predicate_admits_nothing_when_the_profile_is_unknown() -> None:
    """A profile that could not be read is not a profile named `None`."""
    assert not admits(PersonalAccountRule(profile="DEV_USERS"), "jdoe", profile=None)


def test_a_role_predicate_reads_the_roles_it_was_given() -> None:
    rule = PersonalAccountRule(role="APP_DEVELOPER")
    assert admits(rule, "jdoe", roles=("CONNECT", "APP_DEVELOPER"))
    assert admits(rule, "jdoe", roles=("app_developer",))
    assert not admits(rule, "jdoe", roles=("CONNECT",))


def test_a_role_predicate_admits_nothing_when_no_roles_were_read() -> None:
    """The safe direction: an unreadable role set refuses, it does not permit.

    The opposite of guardrail 4's failure mode, and for the same reason -- a
    check with no input must not read as permission. There, empty meant "holds
    no dangerous role" and passed; here it means "not declared" and refuses.
    """
    assert not admits(PersonalAccountRule(role="APP_DEVELOPER"), "jdoe", roles=())


def test_a_predicate_does_not_fall_back_to_the_account_list() -> None:
    """A rule is one kind of rule. #467 refuses an entry that is both."""
    assert not admits(PersonalAccountRule(profile="DEV_USERS"), "jdoe")


# ------------------------------------------------------------ rules_for ---


def test_a_rule_with_no_selector_applies_to_every_target() -> None:
    resolved = config({"accounts": ["jdoe"]})
    assert len(rules_for(resolved, "appdb-dev-alpha")) == 1
    assert len(rules_for(resolved, "appdb-qa-alpha")) == 1


def test_a_named_selector_limits_where_a_rule_applies() -> None:
    resolved = config({"accounts": ["jdoe"], "targets": ["appdb-dev-alpha"]})
    assert len(rules_for(resolved, "appdb-dev-alpha")) == 1
    assert rules_for(resolved, "appdb-qa-alpha") == ()


def test_a_group_selector_limits_it_too() -> None:
    resolved = config({"accounts": ["jdoe"], "targets": {"group": "dev-pdbs"}})
    assert len(rules_for(resolved, "appdb-dev-alpha")) == 1
    assert rules_for(resolved, "appdb-qa-alpha") == ()


# ----------------------------------------------------------- declared_on ---


def test_declared_on_returns_the_rule_that_admitted_the_account() -> None:
    resolved = config({"accounts": ["jdoe"]}, {"profile": "DEV_USERS"})
    rule = declared_on(resolved, "jdoe", "appdb-dev-alpha")
    assert rule is not None
    assert rule.accounts == ("jdoe",)


def test_declared_on_resolves_a_predicate_from_the_state_it_is_handed() -> None:
    resolved = config({"profile": "DEV_USERS"})
    rule = declared_on(resolved, "bcarter", "appdb-dev-alpha", profile="DEV_USERS")
    assert rule is not None
    assert rule.profile == "DEV_USERS"


def test_an_account_no_rule_admits_is_not_declared() -> None:
    resolved = config({"accounts": ["jdoe"]}, {"profile": "DEV_USERS"})
    assert declared_on(resolved, "bcarter", "appdb-dev-alpha", profile="APP_PROF") is None


def test_a_rule_that_does_not_reach_this_target_does_not_declare_here() -> None:
    """Invariant 5 is per (account, target), because a target is where the DDL lands."""
    resolved = config({"accounts": ["jdoe"], "targets": ["appdb-dev-alpha"]})
    assert declared_on(resolved, "jdoe", "appdb-dev-alpha") is not None
    assert declared_on(resolved, "jdoe", "appdb-qa-alpha") is None


def test_a_file_declaring_no_personal_accounts_declares_none() -> None:
    resolved = build_config({"version": 1, "targets": [TARGET]})
    assert declared_on(resolved, "jdoe", "appdb-dev-alpha") is None


# ------------------------------------------------- overlapping rules (#463) ---


def test_two_rules_may_both_admit_one_account() -> None:
    """Ordinary: an enumerated entry and a predicate can both be true of a person."""
    resolved = config({"accounts": ["jdoe"]}, {"profile": "DEV_USERS"})

    admitting = rules_admitting(resolved, "jdoe", "appdb-dev-alpha", profile="DEV_USERS")

    assert len(admitting) == 2
    assert declared_on(resolved, "jdoe", "appdb-dev-alpha", profile="DEV_USERS") is not None


def test_two_rules_agreeing_on_a_policy_are_not_a_conflict() -> None:
    resolved = config(
        {"accounts": ["jdoe"], "policy": "personal-standard"},
        {"profile": "DEV_USERS", "policy": "personal-standard"},
    )

    rule = declared_on(resolved, "jdoe", "appdb-dev-alpha", profile="DEV_USERS")

    assert rule is not None
    assert rule.policy == "personal-standard"


def test_two_rules_naming_different_policies_are_refused() -> None:
    """Otherwise which policy applies depends on the order somebody wrote them in.

    Not catchable at load time -- whether `DEV_USERS` admits this account is a
    fact about a database -- so it is a plan-time refusal naming both rules.
    """
    resolved = config(
        {"accounts": ["jdoe"], "policy": "personal-standard"},
        {"profile": "DEV_USERS", "policy": "personal-strict"},
    )

    with pytest.raises(ConfigError) as caught:
        declared_on(resolved, "jdoe", "appdb-dev-alpha", profile="DEV_USERS")

    message = str(caught.value)
    assert "different policies" in message
    assert "personal-standard" in message
    assert "personal-strict" in message


def test_a_rule_with_no_policy_does_not_conflict_with_one_that_has_it() -> None:
    """An absent `policy:` is "whatever `defaults:` says", not a third answer."""
    resolved = config(
        {"accounts": ["jdoe"]},
        {"profile": "DEV_USERS", "policy": "personal-strict"},
    )

    rule = declared_on(resolved, "jdoe", "appdb-dev-alpha", profile="DEV_USERS")

    assert rule is not None

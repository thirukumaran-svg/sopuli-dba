"""`personal_accounts:` -- the section H1 (#449) decided and #467 builds.

Tier 0, pure: everything builds from a dict, so there is no filesystem and no
I/O. Fixtures use the fictional vocabulary the provenance note requires --
application ``acme``, accounts ``acme_*_user``, tenants ``alpha``…``theta``, and
``jdoe`` for a person, who is a placeholder and not anybody.

One accept and one reject per rule, and the rejects assert on the *message*: a
rule that fires without saying which key is wrong has not finished its job.

**What is deliberately not tested here**: whether ``profile: DEV_USERS`` names a
profile that exists. That is a question for a database, it is a plan-time refusal
belonging to the verb that resolves the predicate, and §2's asymmetry says it
answers differently from "matched nothing" -- a misspelling is refused, an empty
estate is not. Nothing in this layer can tell those apart.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.personal_accounts import build_personal_accounts


def document(*entries: dict[str, Any]) -> dict[str, Any]:
    return {"version": 1, "personal_accounts": list(entries)}


def only(*entries: dict[str, Any]) -> Any:
    built = build_personal_accounts(document(*entries))
    assert len(built) == 1
    return built[0]


# ------------------------------------------------------------- declaring ---


def test_a_section_that_is_absent_declares_nothing() -> None:
    assert build_personal_accounts({"version": 1}) == ()


def test_accounts_are_read_in_order() -> None:
    entry = only({"accounts": ["jdoe", "asmith"]})
    assert entry.accounts == ("jdoe", "asmith")
    assert not entry.is_predicate


def test_a_profile_predicate_is_not_a_list_of_names() -> None:
    entry = only({"profile": "DEV_USERS"})
    assert entry.profile == "DEV_USERS"
    assert entry.accounts == ()
    assert entry.is_predicate
    assert entry.label == "profile 'DEV_USERS'"


def test_a_role_predicate_is_the_other_one() -> None:
    entry = only({"role": "APP_DEVELOPER"})
    assert entry.role == "APP_DEVELOPER"
    assert entry.is_predicate


def test_an_entry_declaring_nothing_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        only({"policy": "personal-standard"})
    assert "must declare `accounts:`, `profile:` or `role:`" in str(caught.value)


def test_two_ways_of_saying_which_accounts_are_refused_together() -> None:
    """Union or intersection -- neither reading is the obvious one, so neither is picked."""
    with pytest.raises(ConfigError) as caught:
        only({"accounts": ["jdoe"], "profile": "DEV_USERS"})
    message = str(caught.value)
    assert "exactly one" in message
    assert "`accounts:`" in message
    assert "`profile:`" in message


def test_an_empty_section_is_refused_although_an_absent_one_is_not() -> None:
    with pytest.raises(ConfigError) as caught:
        build_personal_accounts({"version": 1, "personal_accounts": []})
    assert "at least one personal account entry" in str(caught.value)


def test_an_unknown_key_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        only({"accounts": ["jdoe"], "secret": "vault-dev:people/jdoe#password"})
    assert "secret" in str(caught.value)


def test_a_selector_and_a_policy_are_carried() -> None:
    entry = only(
        {"accounts": ["jdoe"], "targets": {"group": "dev-pdbs"}, "policy": "personal-standard"}
    )
    assert entry.targets.group == "dev-pdbs"
    assert entry.policy == "personal-standard"


# ------------------------------------------------------------ uniqueness ---


def test_one_name_may_not_be_declared_twice_in_the_section() -> None:
    with pytest.raises(ConfigError) as caught:
        build_personal_accounts(document({"accounts": ["jdoe"]}, {"accounts": ["jdoe"]}))
    assert "duplicate personal account" in str(caught.value)


def test_duplicates_are_found_across_case() -> None:
    """``selection.py`` casefolds, so two spellings are one account to a selector."""
    with pytest.raises(ConfigError) as caught:
        build_personal_accounts(document({"accounts": ["jdoe"]}, {"accounts": ["JDOE"]}))
    assert "duplicate personal account" in str(caught.value)


def test_a_name_may_not_be_both_an_application_account_and_a_personal_one() -> None:
    with pytest.raises(ConfigError) as caught:
        build_config(
            {
                "version": 1,
                "accounts": ["acme_web_user"],
                "personal_accounts": [{"accounts": ["acme_web_user"]}],
            }
        )
    message = str(caught.value)
    assert "declared both as a personal account" in message
    assert "acme_web_user" in message


def test_the_cross_declaration_rule_is_case_insensitive_too() -> None:
    with pytest.raises(ConfigError) as caught:
        build_config(
            {
                "version": 1,
                "applications": [{"name": "acme", "accounts": ["ACME_WEB_USER"]}],
                "personal_accounts": [{"accounts": ["acme_web_user"]}],
            }
        )
    assert "declared both as a personal account" in str(caught.value)


def test_a_predicate_is_not_checked_against_application_accounts() -> None:
    """The collision a predicate can cause is invisible to a file, and H1 says so.

    Not a gap being papered over: whether ``DEV_USERS`` admits ``acme_web_user``
    is a fact about a database, so the verb that resolves the predicate is the
    only place it can be caught. What this pins is that the *file* loads, rather
    than the loader inventing an answer it cannot have.
    """
    config = build_config(
        {
            "version": 1,
            "accounts": ["acme_web_user"],
            "personal_accounts": [{"profile": "DEV_USERS"}],
        }
    )
    assert config.personal_accounts[0].profile == "DEV_USERS"


# ------------------------------------------------------------ references ---


def test_a_policy_that_names_nothing_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_config(
            {"version": 1, "personal_accounts": [{"accounts": ["jdoe"], "policy": "nope"}]}
        )
    assert "policy" in str(caught.value)


def test_a_group_that_names_nothing_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_config(
            {
                "version": 1,
                "personal_accounts": [{"accounts": ["jdoe"], "targets": {"group": "nope"}}],
            }
        )
    assert "group" in str(caught.value)


def test_a_target_that_names_nothing_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_config(
            {
                "version": 1,
                "personal_accounts": [{"accounts": ["jdoe"], "targets": ["appdb-dev-nope"]}],
            }
        )
    assert "target" in str(caught.value)

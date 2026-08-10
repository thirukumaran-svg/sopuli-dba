"""Application entries and the rules that make the account->secret binding safe.

Tier 0, pure: everything here builds from a dict, so there is no filesystem and
no I/O. Fixtures use the fictional vocabulary the provenance note requires --
application ``acme``, accounts ``acme_*_user``, tenants ``alpha``…``theta``.

One accept and one reject per rule. The reject cases assert on the *message*
rather than only on the exception type: a rule that fires without saying which
key is wrong has not finished its job in a file this long.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.applications import build_applications
from sopuli.config.errors import ConfigError

TEMPLATE = "tenants/{tenant}#DB_CREDENTIALS/{account}"


def inline(**keys: Any) -> dict[str, Any]:
    """A minimal inline-form document, with overrides applied on top."""
    return {"version": 1, "accounts": ["acme_web_user"], **keys}


def named(**keys: Any) -> dict[str, Any]:
    """A minimal `applications:` document with one entry."""
    entry = {"name": "acme", "accounts": ["acme_web_user"], **keys}
    return {"version": 1, "applications": [entry]}


def only(document: dict[str, Any]) -> Any:
    applications = build_applications(document)
    assert len(applications) == 1
    return applications[0]


# ---------------------------------------------------------------- accounts ---


def test_accounts_are_read_in_order() -> None:
    application = only(
        inline(accounts=["acme_web_user", "acme_api_user"], secret_template=TEMPLATE)
    )

    assert application.accounts == ("acme_web_user", "acme_api_user")


def test_an_application_must_declare_accounts() -> None:
    """Invariant 5: the config is the whitelist, so nothing is managed by default."""
    with pytest.raises(ConfigError) as caught:
        build_applications({"version": 1, "applications": [{"name": "acme"}]})

    rendered = str(caught.value)
    assert "must declare the accounts it manages" in rendered
    assert "applications[0].accounts" in rendered


def test_an_empty_account_list_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_applications(named(accounts=[]))

    assert "at least one account" in str(caught.value)


def test_a_duplicate_account_is_refused_and_points_at_both() -> None:
    """A duplicate would rotate one account twice in a run, and two password
    changes in quick succession can trip PASSWORD_REUSE into a lockout."""
    with pytest.raises(ConfigError) as caught:
        build_applications(
            named(
                accounts=["acme_web_user", "acme_api_user", "acme_web_user"],
                secret_template=TEMPLATE,
            )
        )

    rendered = str(caught.value)
    assert "duplicate account 'acme_web_user'" in rendered
    assert "applications[0].accounts[2]" in rendered
    assert "already declared at index 0" in rendered


# ------------------------------------------------------------------ secret ---


def test_secret_and_secret_template_are_mutually_exclusive() -> None:
    with pytest.raises(ConfigError) as caught:
        build_applications(named(secret="a/b#c", secret_template=TEMPLATE))

    assert "either `secret:` or `secret_template:`, not both" in str(caught.value)


def test_secret_ref_reports_whichever_was_given() -> None:
    assert (
        only(inline(secret="ops/monitoring/db#password")).secret_ref == "ops/monitoring/db#password"
    )
    assert only(inline(secret_template=TEMPLATE)).secret_ref == TEMPLATE


def test_an_application_may_omit_a_ref_entirely() -> None:
    """`vault` and `secret` both default from elsewhere (§3), so absence is not
    an error at this layer -- resolution decides, and it does not exist yet."""
    assert only(inline()).secret_ref is None


# ------------------------------------------- the account distinctness rule ---


@pytest.mark.parametrize(
    "template",
    [
        "tenants/{tenant}#DB_CREDENTIALS/{account}",
        "apps/{account_lower}/db#password",
        "apps/{account_upper}/db#password",
    ],
)
def test_an_account_token_satisfies_the_rule(template: str) -> None:
    application = only(named(accounts=["acme_web_user", "acme_api_user"], secret_template=template))

    assert len(application.accounts) == 2


def test_several_accounts_without_an_account_token_are_refused() -> None:
    """§9, read as being about accounts rather than scopes.

    Two accounts on one ref means the second password written overwrites the
    first, and whichever application reads the first is locked out at the next
    rotation.
    """
    with pytest.raises(ConfigError) as caught:
        build_applications(
            named(
                accounts=["acme_web_user", "acme_api_user"], secret_template="tenants/{tenant}#DB"
            )
        )

    rendered = str(caught.value)
    assert "2 accounts would share one secret ref" in rendered
    assert "applications[0].secret_template" in rendered
    assert "{account}" in rendered


def test_a_literal_secret_with_several_accounts_is_refused() -> None:
    """The same fault in a starker form: a literal ref cannot vary at all."""
    with pytest.raises(ConfigError) as caught:
        build_applications(
            named(accounts=["acme_web_user", "acme_api_user"], secret="ops/db#password")
        )

    assert "applications[0].secret" in str(caught.value)


def test_one_account_may_share_a_ref_with_nothing() -> None:
    """A single account needs no distinguishing token -- and §6 is explicit that
    one account sharing a password across many PDBs is legal and often
    intended, so the rule must not reach targets."""
    application = only(named(accounts=["report_reader"], secret="reporting/db#password"))

    assert application.secret_ref == "reporting/db#password"


# ----------------------------------------------------------------- targets ---


def test_targets_may_be_a_list_of_names() -> None:
    application = only(named(targets=["cdb-root-dev"]))

    assert application.targets.names == ("cdb-root-dev",)
    assert not application.targets.is_everything


def test_targets_may_be_a_group() -> None:
    assert only(named(targets={"group": "prod-pdbs"})).targets.group == "prod-pdbs"


def test_targets_may_be_a_label_match() -> None:
    application = only(named(targets={"match": {"env": "dev", "tenant": "beta"}}))

    assert application.targets.match == (("env", "dev"), ("tenant", "beta"))


def test_omitting_targets_means_all_of_them() -> None:
    assert only(named()).targets.is_everything


def test_group_and_match_together_are_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_applications(named(targets={"group": "prod-pdbs", "match": {"env": "dev"}}))

    assert "exactly one of `group:` or `match:`" in str(caught.value)


def test_an_unknown_target_selector_key_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_applications(named(targets={"grup": "prod-pdbs"}))

    assert "unknown key 'grup'" in str(caught.value)


def test_an_empty_match_is_refused() -> None:
    """A selector matching everything is not a selector."""
    with pytest.raises(ConfigError) as caught:
        build_applications(named(targets={"match": {}}))

    assert "at least one label" in str(caught.value)


# --------------------------------------------------------------- overrides ---


def test_an_override_patches_the_ref_for_matching_targets() -> None:
    application = only(
        inline(
            secret_template=TEMPLATE,
            overrides=[
                {"where": {"env": "dev"}, "secret_template": "tenants/_shared#DB/{account}"}
            ],
        )
    )

    assert len(application.overrides) == 1
    assert application.overrides[0].where == (("env", "dev"),)
    assert application.overrides[0].secret_template == "tenants/_shared#DB/{account}"


def test_an_override_must_say_where_it_applies() -> None:
    with pytest.raises(ConfigError) as caught:
        build_applications(named(overrides=[{"policy": "relaxed"}]))

    rendered = str(caught.value)
    assert "must say which targets it applies to" in rendered
    assert "applications[0].overrides[0].where" in rendered


def test_an_override_may_not_carry_accounts() -> None:
    """Invariant 5: selectors filter the declared set and cannot extend it.

    A patchable `accounts` would be a label match, somewhere in the middle of a
    long file, that adds to the whitelist. What the tool manages has to be
    readable from `accounts:` alone.
    """
    with pytest.raises(ConfigError) as caught:
        build_applications(
            named(overrides=[{"where": {"env": "dev"}, "accounts": ["acme_extra_user"]}])
        )

    assert "unknown key 'accounts'" in str(caught.value)


def test_an_override_reports_its_index() -> None:
    with pytest.raises(ConfigError) as caught:
        build_applications(
            named(
                overrides=[
                    {"where": {"env": "dev"}, "policy": "a"},
                    {"where": {"env": "qa"}, "polcy": "b"},
                ]
            )
        )

    assert "applications[0].overrides[1]" in str(caught.value)


# -------------------------------------------------------------------- name ---


def test_a_named_entry_must_have_a_name() -> None:
    with pytest.raises(ConfigError) as caught:
        build_applications({"version": 1, "applications": [{"accounts": ["acme_web_user"]}]})

    rendered = str(caught.value)
    assert "must have a name" in rendered
    assert "--application" in rendered


def test_duplicate_application_names_are_refused() -> None:
    document = {
        "version": 1,
        "applications": [
            {"name": "acme", "accounts": ["acme_web_user"]},
            {"name": "acme", "accounts": ["acme_api_user"]},
        ],
    }

    with pytest.raises(ConfigError) as caught:
        build_applications(document)

    rendered = str(caught.value)
    assert "duplicate application name 'acme'" in rendered
    assert "applications[1].name" in rendered


def test_an_empty_applications_list_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_applications({"version": 1, "applications": []})

    assert "at least one application" in str(caught.value)


# ------------------------------------------------------------------ oracle ---


def test_oracle_options_are_read() -> None:
    assert only(named(oracle={"container_clause": "ALL"})).oracle.container_clause == "ALL"


def test_an_unknown_oracle_option_is_refused() -> None:
    """An untyped bag would accept `container_clase: ALL` and silently do
    nothing, which is exactly what §9 exists to prevent."""
    with pytest.raises(ConfigError) as caught:
        build_applications(named(oracle={"container_clase": "ALL"}))

    assert "unknown key 'container_clase'" in str(caught.value)

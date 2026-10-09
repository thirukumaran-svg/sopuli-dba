"""What a run intends, before it does any of it.

The run document's `plan` section. Two properties carry most of these tests:

* **It is a function of the config and the selection, and of nothing else.**
  `03-json-output.md` requires a real run to emit the plan it would have emitted
  under `--dry-run`, so that a plan-versus-`results` diff is mechanical. A plan
  that read a store, a clock or a connection would make two runs of one command
  disagree because somebody else edited the vault in between.
* **Blast radius counts distinct things.** The unit count and the target count
  differ exactly where sharing happens, which is the case every guardrail here
  exists for.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.loading import build_config
from sopuli.config.selection import Selection, filter_estate
from sopuli.plan import ACTION_KINDS, BlastRadius, Plan, PlanUnit, build

VAULTS: dict[str, Any] = {"vault-dev": {"type": "hashicorp"}}

APPDB: dict[str, Any] = {
    "type": "oracle",
    "name": "appdb-{env}-{tenant}",
    "dsn": "{host}:1521/{tenant}.pdb.example.com",
    "environment": "{env}",
    "vault": "vault-dev",
    "oracle": {"scope": "pdb", "container": "{tenant}pdb"},
    "for_each": {
        "env": {
            "dev": {"host": "db-dev.example.com", "tenant": ["alpha", "beta"]},
            "prod": {"host": "db-prod.example.com", "tenant": ["alpha", "beta"]},
        }
    },
}

ACCOUNTS = ["acme_web_user", "acme_api_user"]


def estate(**entry: Any) -> Any:
    """One application over the four generated PDBs, unless narrowed."""
    application = {"name": "acme", "targets": {"group": "app-pdbs"}, **entry}
    return build_config(
        {
            "version": 1,
            "vaults": VAULTS,
            "target_sets": {"appdb": APPDB},
            "groups": {"app-pdbs": {"match": {"target_set": "appdb"}}},
            "applications": [application],
        }
    )


def plan_over(**entry: Any) -> Plan:
    return build(estate(**entry), intent=["verify"])


# --------------------------------------------------------------- the units ---


def test_one_unit_per_binding_in_binding_order() -> None:
    """The same grain as `results[]`, so the two arrays line up.

    Order is the bindings' own -- application, then estate, then declared
    account. `shared_secrets` makes the same argument: a second ordering would
    make one set of names look like two.
    """
    plan = plan_over(
        accounts=ACCOUNTS, secret_template="apps/acme/{tenant}#DB_CREDENTIALS/{account}"
    )

    assert len(plan.units) == 8
    assert [(unit.account, unit.target) for unit in plan.units[:4]] == [
        ("acme_web_user", "appdb-dev-alpha"),
        ("acme_api_user", "appdb-dev-alpha"),
        ("acme_web_user", "appdb-dev-beta"),
        ("acme_api_user", "appdb-dev-beta"),
    ]


def test_the_intent_is_the_verb_s_and_it_reaches_every_unit() -> None:
    """A verb intends one thing over the estate it intends it over.

    A run meaning different things for different accounts would be two runs, and
    `results[]` would have no way to say which was which.
    """
    plan = build(estate(accounts=ACCOUNTS), intent=["generate", "vault_write_pending"])

    assert all(unit.intent == ("generate", "vault_write_pending") for unit in plan.units)


@pytest.mark.parametrize("intent", [["rotate"], ["verify", "check"], [""]])
def test_an_intent_outside_the_schema_enum_is_refused(intent: list[str]) -> None:
    """Refused where it is written rather than at schema validation in CI.

    A `ValueError`: an intent comes from a verb in this codebase and never from a
    file or a command line, so a bad one is a programming error and there is
    nothing for an operator to fix.
    """
    with pytest.raises(ValueError, match="action_kind"):
        build(estate(accounts=ACCOUNTS), intent=intent)


def test_no_intent_at_all_is_refused() -> None:
    """An empty array validates against the schema and says nothing. A unit the
    run intends nothing for is not a unit -- `none` is the way to say that."""
    with pytest.raises(ValueError, match="at least one intent"):
        build(estate(accounts=ACCOUNTS), intent=[])


def test_none_is_a_legal_intent() -> None:
    """It is in the enum, and it is how a plan says "reached, and deliberately
    left alone" -- which `apply --repair` needs for targets already in sync."""
    assert "none" in ACTION_KINDS
    plan = build(estate(accounts=["acme_web_user"]), intent=["none"])
    assert all(unit.intent == ("none",) for unit in plan.units)


# -------------------------------------------------------------- the secret ---


def test_the_unit_carries_the_structured_ref_with_the_resolved_vault() -> None:
    """`config.bindings[].secret` is the canonical string; this is the parts.

    `vault` comes from the binding rather than from the ref, because §7 lets a
    written ref leave the store off and inherit it -- and the plan is what a
    machine is about to address a document with.
    """
    plan = plan_over(
        accounts=["acme_web_user"], secret_template="apps/acme/{tenant}#DB_CREDS/{account}"
    )

    assert plan.units[0].secret == {
        "vault": "vault-dev",
        "path": "apps/acme/alpha",
        "field": "DB_CREDS",
        "pointer": "/acme_web_user",
    }


def test_the_secret_carries_no_version_and_no_timestamp() -> None:
    """Both describe what the store *holds*, and reading it here would make the
    plan a function of something other than the config. They belong to
    `results[]`, once something has actually looked."""
    plan = plan_over(accounts=["acme_web_user"], secret_template="apps/acme/{tenant}#password")

    secret = plan.units[0].secret
    assert secret is not None
    assert "version" not in secret
    assert "updated_at" not in secret


def test_a_binding_with_no_ref_carries_no_secret() -> None:
    """§3 makes `secret` optional and this layer does not invent one."""
    plan = plan_over(accounts=["acme_web_user"])

    assert all(unit.secret is None for unit in plan.units)


def test_a_pinned_version_survives_because_it_is_config() -> None:
    """`@version=7` is written in the file, so it is deterministic and belongs in
    the plan. What must not appear is a version *observed* in the store."""
    plan = plan_over(
        accounts=["acme_web_user"], secret_template="apps/acme/{tenant}#password@version=7"
    )

    assert plan.units[0].secret == {
        "vault": "vault-dev",
        "path": "apps/acme/alpha",
        "field": "password",
        "version": 7,
    }


def test_a_ref_whose_store_nothing_named_yet_emits_no_secret() -> None:
    """C15: §3's chain deliberately leaves out a profile's `vault:` and
    `SOPULI_VAULT`, so a valid file can reach here with `binding.vault is None`.

    `secret_ref` requires `vault` as a *string*, so there is no shape for half an
    address -- and `units[].secret` is optional precisely so a unit can say it
    has none. Emitting `{"vault": null}` would fail schema validation.

    Not refused here, and C15 is what says so: it decided "mostly plan
    time" -- the null is a real temporary state, and the command that actually
    needs a store is what fails, once a run's profile is known and the answer is
    exact. A refusal in the plan builder would fire before that and reject every
    file whose store comes from `SOPULI_VAULT`.
    """
    config = build_config(
        {
            "version": 1,
            "vaults": VAULTS,
            "targets": [{"name": "plain", "type": "oracle", "dsn": "h:1521/x"}],
            "applications": [
                {
                    "name": "acme",
                    "targets": ["plain"],
                    "accounts": ["acme_web_user"],
                    "secret_template": "apps/acme/{account}#password",
                }
            ],
        }
    )
    (binding,) = config.bindings
    assert binding.secret is not None
    assert binding.vault is None

    (unit,) = build(config, intent=["verify"]).units
    assert unit.secret is None


def test_a_unit_with_no_secret_omits_the_key_rather_than_nulling_it() -> None:
    """The schema types `secret` as an object, so a null would fail validation --
    and `additionalProperties: false` means there is nothing else to put there."""
    assert PlanUnit("A", "t", ("verify",)).as_json() == {
        "account": "A",
        "target": "t",
        "intent": ["verify"],
    }


# -------------------------------------------------------- the blast radius ---


def test_it_counts_distinct_targets_and_accounts_not_units() -> None:
    """Two accounts across four PDBs is eight units, four targets, two accounts.

    The distinction is the whole of `max_targets`: counting units would refuse a
    run under a ceiling the operator set for targets.
    """
    plan = plan_over(
        accounts=ACCOUNTS, secret_template="apps/acme/{tenant}#DB_CREDENTIALS/{account}"
    )

    assert len(plan.units) == 8
    assert plan.blast_radius.targets == 4
    assert plan.blast_radius.accounts == 2


def test_several_accounts_in_one_target_is_one_target_s_worth_of_reach() -> None:
    """The case that makes counting units wrong rather than merely different."""
    plan = build(
        estate(
            accounts=ACCOUNTS,
            targets={"match": {"tenant": "alpha", "env": "dev"}},
            secret_template="apps/acme/db#DB_CREDENTIALS/{account}",
        ),
        intent=["verify"],
    )

    assert len(plan.units) == 2
    assert plan.blast_radius == BlastRadius(targets=1, accounts=2, environments=("dev",))


def test_environments_are_named_and_deduplicated_in_estate_order() -> None:
    """`confirm_environments` is asked against names, not a count -- and a set's
    ordering would make the same two environments look like a different two
    between runs."""
    plan = plan_over(accounts=["acme_web_user"], secret_template="apps/acme/{tenant}#password")

    assert plan.blast_radius.environments == ("dev", "prod")


def test_a_target_declaring_no_environment_contributes_none() -> None:
    """`environment:` is optional, and `confirm_environments` matching an empty
    string would be a rule nobody wrote."""
    config = build_config(
        {
            "version": 1,
            "vaults": VAULTS,
            "targets": [
                {"name": "plain", "type": "oracle", "dsn": "h:1521/x", "vault": "vault-dev"}
            ],
            "applications": [{"name": "acme", "targets": ["plain"], "accounts": ["acme_web_user"]}],
        }
    )

    assert build(config, intent=["verify"]).blast_radius.environments == ()


# ------------------------------------------------------------ the sharing ---


def test_sharing_is_narrowed_to_what_this_run_touches() -> None:
    """The distinction from `config.shared_secrets`: that answers "what does my
    file share", this answers "what does *this run* touch that something else
    reads". Selecting one PDB drops the other three from the entry."""
    config = filter_estate(
        estate(accounts=["acme_web_user"], secret_template="apps/acme/db#{account}"),
        Selection(select=(("tenant", "alpha"),)),
    )

    (entry,) = build(config, intent=["verify"]).shared
    assert entry.targets == ("appdb-dev-alpha", "appdb-prod-alpha")


def test_nothing_shared_omits_the_key_rather_than_emitting_an_empty_array() -> None:
    """An empty array reads like a finding that came back negative, and would
    appear in every clean document consumers diff."""
    plan = build(
        estate(
            accounts=["acme_web_user"],
            targets={"match": {"tenant": "alpha", "env": "dev"}},
            secret_template="apps/acme/{tenant}/{account}#password",
        ),
        intent=["verify"],
    )

    assert plan.shared == ()
    assert "shared_secrets" not in plan.as_json()


def test_confirmation_required_is_not_emitted_at_all() -> None:
    """Optional in the schema, and not answerable here: whether a run is asked
    depends on `--confirm`, the profile's `confirm:` and stdin, none of which the
    plan sees. Emitting `false` would claim the run passed no gate."""
    assert "confirmation_required" not in plan_over(accounts=ACCOUNTS).as_json()


# ------------------------------------------------------------- determinism ---


def test_two_builds_over_one_config_are_identical() -> None:
    """The property `03-json-output.md` needs to make a plan-versus-`results`
    diff mechanical: nothing here reads a store, a clock or a connection."""
    config = estate(
        accounts=ACCOUNTS, secret_template="apps/acme/{tenant}#DB_CREDENTIALS/{account}"
    )

    assert build(config, intent=["verify"]).as_json() == build(config, intent=["verify"]).as_json()

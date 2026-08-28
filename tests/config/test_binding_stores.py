"""C15's plan-time half: completing a binding's store once the run is known (#250).

#118 decided the shape and left the mechanism unbuilt: `_vault_for`'s chain runs
while the file is read, a profile's `vault:` and `SOPULI_VAULT` are properties of
a *run*, and so a valid file can finish loading with `binding.vault is None`.
This is the step that answers it.

The property that carries most of these tests is that it **fills gaps and never
overrides**. An exported `SOPULI_VAULT` redirecting a rotation away from the
store a target names would be the worst bug this module could have, and it is
also the easiest one to write.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from sopuli.config import binding_stores
from sopuli.config.binding_stores import NoStoreError
from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import Config
from sopuli.exit_codes import ExitCode

VAULTS: dict[str, Any] = {
    "vault-dev": {"type": "hashicorp"},
    "vault-ci": {"type": "hashicorp"},
}

REF = "apps/acme/{account}#password"


def estate(
    *,
    profile: str | None = None,
    profiles: dict[str, Any] | None = None,
    target: dict[str, Any] | None = None,
    defaults: dict[str, Any] | None = None,
    application: dict[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
) -> Config:
    """One account in one target, with the store named nowhere unless asked."""
    entry: dict[str, Any] = {
        "name": "acme",
        "targets": ["plain"],
        "accounts": ["acme_web_user"],
        "secret_template": REF,
        **(application or {}),
    }
    # A `None` drops the key rather than writing a null: the loader refuses
    # `secret_template: ~`, and what these tests want is a file that never
    # mentioned it.
    entry = {key: value for key, value in entry.items() if value is not None}
    document: dict[str, Any] = {
        "version": 1,
        "vaults": VAULTS,
        "targets": [{"name": "plain", "type": "oracle", "dsn": "h:1521/x", **(target or {})}],
        "applications": [entry],
    }
    if profiles is not None:
        document["profiles"] = profiles
    if defaults is not None:
        document["defaults"] = defaults
    return build_config(document, profile=profile, env=env or {})


def store_of(config: Config) -> str | None:
    (binding,) = config.bindings
    return binding.vault


# ------------------------------------------------------------ what fills it ---


def test_the_environment_supplies_a_store_the_file_left_open() -> None:
    """`SOPULI_VAULT` is layer 2 and is not consulted while bindings are built,
    so this is the first moment it can apply."""
    config = estate()
    assert store_of(config) is None

    assert store_of(binding_stores.complete(config, env={"SOPULI_VAULT": "vault-ci"})) == (
        "vault-ci"
    )


def test_a_profile_supplies_one_too() -> None:
    """§5 puts `vault:` on a profile precisely so a run can say where it reads
    from, and #118 kept it out of the load-time chain."""
    config = estate(profile="ci", profiles={"ci": {"vault": "vault-ci"}})

    assert store_of(binding_stores.complete(config)) == "vault-ci"


def test_the_environment_outranks_the_profile() -> None:
    """P3: `SOPULI_VAULT` is layer 2 and a profile is layer 3. Applied by hand
    here rather than through the settings registry -- #250 decided that -- so
    the order is worth a test of its own rather than trusting the resolver."""
    config = estate(profile="ci", profiles={"ci": {"vault": "vault-ci"}})

    assert store_of(binding_stores.complete(config, env={"SOPULI_VAULT": "vault-dev"})) == (
        "vault-dev"
    )


def test_a_profile_that_names_no_vault_supplies_nothing() -> None:
    config = estate(profile="ci", profiles={"ci": {"output": "json"}})

    assert store_of(binding_stores.complete(config)) is None


# ------------------------------------------------- gaps only, never override ---


def test_a_target_that_names_its_own_store_is_left_alone() -> None:
    """The bug this module could most easily have. A target naming a store is a
    statement about that database; an exported variable is a property of the
    shell a run happened to start in, and must not repoint it."""
    config = estate(target={"vault": "vault-dev"})
    assert store_of(config) == "vault-dev"

    assert store_of(binding_stores.complete(config, env={"SOPULI_VAULT": "vault-ci"})) == (
        "vault-dev"
    )


def test_defaults_vault_is_left_alone_too() -> None:
    """`defaults.vault` is layer 5 and the load-time chain already read it. This
    step runs only where that chain found nothing, so it must not revisit one it
    did find -- even though the variable outranks it."""
    config = estate(defaults={"vault": "vault-dev"})
    assert store_of(config) == "vault-dev"

    assert store_of(binding_stores.complete(config, env={"SOPULI_VAULT": "vault-ci"})) == (
        "vault-dev"
    )


def test_a_ref_with_its_own_prefix_is_left_alone() -> None:
    """§7 calls `vault-dev:path` an explicit vault, and it is the first link of
    the load-time chain."""
    config = estate(application={"secret_template": f"vault-dev:{REF}"})

    assert store_of(binding_stores.complete(config, env={"SOPULI_VAULT": "vault-ci"})) == (
        "vault-dev"
    )


def test_a_binding_with_no_ref_is_not_given_a_store() -> None:
    """§3 makes `secret` optional. An application declaring no ref has nothing to
    resolve, and giving it a store would invent a relationship the file denies."""
    config = estate(application={"secret_template": None})
    config = binding_stores.complete(config, env={"SOPULI_VAULT": "vault-ci"})

    (binding,) = config.bindings
    assert binding.secret is None
    assert binding.vault is None


# ------------------------------------------------------------- doing nothing ---


def test_nothing_to_fill_returns_the_same_object() -> None:
    """Callers run this unconditionally, and the common case is a file that names
    its stores. That case must allocate nothing."""
    config = estate(target={"vault": "vault-dev"})

    assert binding_stores.complete(config, env={"SOPULI_VAULT": "vault-ci"}) is config


def test_no_candidate_returns_the_same_object() -> None:
    config = estate()

    assert binding_stores.complete(config) is config


# ------------------------------------------------------------- a bad name ---


def test_a_selected_store_that_is_not_declared_is_refused() -> None:
    """Invariant 5: a store name resolves against what the file declared."""
    config = estate()

    with pytest.raises(NoStoreError) as raised:
        binding_stores.complete(config, env={"SOPULI_VAULT": "vault-nope"})

    assert "'vault-nope'" in str(raised.value)


def test_the_refusal_names_where_the_name_came_from() -> None:
    """The attribution is the whole content of the error: a name the shell
    supplied is not in the file an operator would otherwise go and search."""
    config = estate()

    with pytest.raises(NoStoreError) as raised:
        binding_stores.complete(config, env={"SOPULI_VAULT": "vault-nope"})

    assert "SOPULI_VAULT" in str(raised.value)


def test_a_profile_cannot_reach_that_refusal_because_load_already_checked() -> None:
    """`check_references` resolves `profiles.<name>.vault` for *every declared*
    profile, not only the active one -- so a bad name there never survives to be
    a candidate. Pinned because `_refuse_dangling` still guards against it, and
    a reader should be able to see why that branch looks unreachable."""
    with pytest.raises(ConfigError, match="no vault named 'vault-nope'"):
        estate(profile="ci", profiles={"ci": {"vault": "vault-nope"}})


def test_a_bad_name_nothing_needed_is_not_refused() -> None:
    """`default_store` defers this check to "whoever depends on the answer", and
    a run that never needed a store did not depend on it. Exported variables
    outlive the shell they were meant for."""
    config = estate(target={"vault": "vault-dev"})

    assert binding_stores.complete(config, env={"SOPULI_VAULT": "vault-nope"}) is config


# ----------------------------------------------------------- what is left ---


def test_unresolved_separates_no_ref_from_no_store() -> None:
    """A plan cannot answer this -- `units[].secret` is omitted for both -- so
    the distinction survives here and nowhere else."""
    assert binding_stores.unresolved(estate()) != ()
    assert binding_stores.unresolved(estate(application={"secret_template": None})) == ()
    assert binding_stores.unresolved(estate(target={"vault": "vault-dev"})) == ()


def test_refusing_names_the_account_and_the_target() -> None:
    """Invariant 4: fail at plan time, naming the thing and the target."""
    with pytest.raises(NoStoreError) as raised:
        binding_stores.refuse_unresolved(estate(), action="checking credentials")

    message = str(raised.value)
    assert "acme_web_user" in message
    assert "plain" in message
    assert "checking credentials" in message
    assert raised.value.exit_code is ExitCode.CONFIG_INVALID


def test_refusing_counts_the_rest_rather_than_listing_them() -> None:
    """A file invoked without its profile produces this for every binding, and a
    hundred near-identical lines is a wall an operator scrolls past."""
    config = estate(application={"accounts": ["acme_web_user", "acme_api_user"]})

    with pytest.raises(NoStoreError, match="1 more of the same"):
        binding_stores.refuse_unresolved(config, action="checking credentials")


def test_refusing_passes_once_everything_resolves() -> None:
    config = binding_stores.complete(estate(), env={"SOPULI_VAULT": "vault-ci"})

    binding_stores.refuse_unresolved(config, action="checking credentials")

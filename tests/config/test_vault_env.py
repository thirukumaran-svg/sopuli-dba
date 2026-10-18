"""§6's vault variables, and where they land in P3's chain.

Tier 0, pure: every case is a dict and a mapping through ``build_config``, so no
test here depends on the shell it ran in. What the variables do once a real
command reads a real environment is ``tests/test_cli_precedence.py``.

Three properties carry the module:

**Addressing.** ``SOPULI_VAULT__VAULT_DEV__ADDR`` names one store; the unnamed
forms name whichever store ``defaults.vault`` -- or ``SOPULI_VAULT`` above it --
resolves to, and refuse rather than guess when nothing does.

**Rank.** Layer 2 over the file, with Vault's own variables ranked below their
``SOPULI_*`` equivalent inside layer 2, all through the one resolver.

**Ambiguity is refused, never resolved.** Two stores whose names map to one
variable spelling, a key that addresses nothing, a store the file never declared.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.codes import THIRD_PARTY_ADDR_OVERRIDES, THIRD_PARTY_VARIABLE_UNAPPLIED
from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import Config, Vault
from sopuli.config.vault_env import (
    ACTIVE_VARIABLES,
    NAMED_KEYS,
    THIRDPARTY_VARIABLES,
    named_variable,
    variable_segment,
)
from sopuli.config.vault_layers import setting_name
from sopuli.exit_codes import ExitCode
from sopuli.settings import Layer, setting

STORE = "vault-dev"
NAMED = named_variable(STORE, "ADDR")

DECLARED = "https://declared.example.com"
NAMED_ADDR = "https://named.example.com"
ACTIVE_ADDR = "https://active.example.com"
THIRDPARTY_ADDR = "https://third-party.example.com"


def document(vault: dict[str, Any] | None = None, **sections: Any) -> dict[str, Any]:
    """A file with one declared store, defaulted to, plus whatever a case adds."""
    return {
        "version": 1,
        "vaults": {STORE: {"type": "hashicorp", **(vault or {})}},
        "defaults": {"vault": STORE, **sections.pop("defaults", {})},
        **sections,
    }


def loaded(env: dict[str, str], vault: dict[str, Any] | None = None, **sections: Any) -> Config:
    return build_config(document(vault, **sections), env=env)


def merged(env: dict[str, str], vault: dict[str, Any] | None = None, **sections: Any) -> Vault:
    config = loaded(env, vault, **sections)
    assert len(config.vaults) == 1
    return config.vaults[0]


# ----------------------------------------------------------------- addressing ---


def test_the_named_form_supplies_one_store() -> None:
    store = merged({NAMED: NAMED_ADDR})

    assert store.addr == NAMED_ADDR
    assert store.patched == ("addr",)


def test_a_hyphen_in_a_store_name_is_an_underscore_in_the_variable() -> None:
    """`-` is not legal in a variable name on any platform this runs on, so the
    mapping has to do something -- and this is the something."""
    assert variable_segment("vault-dev") == "VAULT_DEV"
    assert NAMED == "SOPULI_VAULT__VAULT_DEV__ADDR"


def test_the_unnamed_form_supplies_the_store_defaults_vault_names() -> None:
    assert merged({"SOPULI_VAULT_ADDR": ACTIVE_ADDR}).addr == ACTIVE_ADDR


def test_sopuli_vault_moves_the_unnamed_form_to_another_store() -> None:
    """``SOPULI_VAULT`` is layer 2 of the same setting ``defaults.vault`` writes,
    so it decides which store "the active one" is."""
    config = build_config(
        {
            "version": 1,
            "vaults": {"vault-a": {"type": "hashicorp"}, "vault-b": {"type": "hashicorp"}},
            "defaults": {"vault": "vault-a"},
        },
        env={"SOPULI_VAULT": "vault-b", "SOPULI_VAULT_ADDR": ACTIVE_ADDR},
    )

    assert {one.name: one.addr for one in config.vaults} == {
        "vault-a": None,
        "vault-b": ACTIVE_ADDR,
    }


def test_the_named_form_beats_the_unnamed_one_for_the_same_store() -> None:
    """Both are layer 2. The one that named this store is the more specific
    request, and the resolver keeps the caller's order within a layer."""
    assert merged({NAMED: NAMED_ADDR, "SOPULI_VAULT_ADDR": ACTIVE_ADDR}).addr == NAMED_ADDR


def test_a_variable_addresses_only_the_store_it_names() -> None:
    config = build_config(
        {
            "version": 1,
            "vaults": {"vault-a": {"type": "hashicorp"}, "vault-b": {"type": "hashicorp"}},
        },
        env={named_variable("vault-a", "ADDR"): NAMED_ADDR},
    )

    assert {one.name: one.addr for one in config.vaults} == {"vault-a": NAMED_ADDR, "vault-b": None}


# ---------------------------------------------------------------------- rank ---


def test_the_named_variable_beats_both_file_layers() -> None:
    """The issue's first case: layer 2 over layer 4 over layer 5."""
    store = merged(
        {NAMED: NAMED_ADDR},
        {"addr": DECLARED},
        defaults={"vaults": {STORE: {"addr": "https://defaulted.example.com"}}},
    )

    assert store.addr == NAMED_ADDR


def test_the_named_variable_beats_a_profile() -> None:
    """Layer 3 is the highest the file can reach, and the environment is above it."""
    store = merged(
        {NAMED: NAMED_ADDR},
        profiles={"ci": {"vaults": {STORE: {"addr": "https://from-ci.example.com"}}}},
        defaults={"profile": "ci"},
    )

    assert store.addr == NAMED_ADDR


def test_a_sopuli_variable_beats_the_third_party_one() -> None:
    """§9's worked example, and P3's rule within layer 2: `SOPULI_VAULT_ADDR` beats
    `VAULT_ADDR`, because a variable named for this tool is the more deliberate
    of the two."""
    env = {"SOPULI_VAULT_ADDR": ACTIVE_ADDR, "VAULT_ADDR": THIRDPARTY_ADDR}

    assert merged(env).addr == ACTIVE_ADDR


def test_the_third_party_variable_answers_when_nothing_above_it_did() -> None:
    assert merged({"VAULT_ADDR": THIRDPARTY_ADDR}).addr == THIRDPARTY_ADDR


def test_the_third_party_variable_beats_the_file() -> None:
    """Layer 3 is still above every layer the file has."""
    assert merged({"VAULT_ADDR": THIRDPARTY_ADDR}, {"addr": DECLARED}).addr == THIRDPARTY_ADDR


def test_vault_namespace_and_cacert_reach_their_keys() -> None:
    """The other two of §6's honoured third-party list. ``VAULT_CACERT`` is a
    path to a CA certificate, which is `tls.ca_file`."""
    store = merged({"VAULT_NAMESPACE": "acme", "VAULT_CACERT": "/etc/ssl/acme.pem"})

    assert store.namespace == "acme"
    assert store.tls is not None
    assert store.tls.ca_file == "/etc/ssl/acme.pem"
    assert store.patched == ("namespace", "tls.ca_file")


def test_a_cacert_alone_still_leaves_verification_on() -> None:
    """A `tls:` block conjured by the environment says nothing about `verify`,
    and absent means verified (invariant 10, `VaultTls.verified`)."""
    store = merged({"VAULT_CACERT": "/etc/ssl/acme.pem"})

    assert store.tls is not None
    assert store.tls.verify is None
    assert store.tls.verified


# ------------------------------------------------------------ said nothing ---


def test_nothing_set_changes_nothing() -> None:
    store = merged({}, {"addr": DECLARED})

    assert store.addr == DECLARED
    assert store.patched == ()


def test_an_empty_variable_says_nothing() -> None:
    """§6: set-but-empty counts as unset, so a CI job can clear an inherited
    variable without unsetting it."""
    env = dict.fromkeys((NAMED, "SOPULI_VAULT_ADDR", "VAULT_ADDR", "SOPULI_VAULT"), "")
    store = merged(env, {"addr": DECLARED})

    assert store.addr == DECLARED
    assert store.patched == ()


def test_an_unrelated_variable_is_ignored() -> None:
    """`SOPULI_VAULT_TOKEN` is auth material and belongs to `sopuli/material.py`
    (ADR-007); a token is not a setting and must never be reported as one."""
    assert merged({"SOPULI_VAULT_TOKEN": "s.not-a-setting"}, {"addr": DECLARED}).addr == DECLARED


# ---------------------------------------------------------------- ambiguity ---


def test_two_stores_mapping_to_one_variable_are_refused_naming_both() -> None:
    """`vault-dev` and `vault_dev` are one variable. Picking either would be a
    coin toss between two vaults."""
    with pytest.raises(ConfigError) as raised:
        build_config(
            {
                "version": 1,
                "vaults": {"vault-dev": {"type": "hashicorp"}, "vault_dev": {"type": "hashicorp"}},
            },
            env={NAMED: NAMED_ADDR},
        )

    assert "`vault-dev`" in str(raised.value)
    assert "`vault_dev`" in str(raised.value)
    assert raised.value.exit_code == ExitCode.CONFIG_INVALID


def test_the_collision_is_only_refused_when_the_variable_is_set() -> None:
    """Two names differing only in punctuation are a legal file. The ambiguity is
    not real until something depends on it."""
    config = build_config(
        {
            "version": 1,
            "vaults": {"vault-dev": {"type": "hashicorp"}, "vault_dev": {"type": "hashicorp"}},
        },
        env={},
    )

    assert [one.name for one in config.vaults] == ["vault-dev", "vault_dev"]


def test_a_key_that_addresses_nothing_is_refused_rather_than_ignored() -> None:
    """The failure §6 spells out for `VAULT_SKIP_VERIFY`: the operator set it and
    believes it took effect."""
    with pytest.raises(ConfigError) as raised:
        loaded({named_variable(STORE, "ADDRESS"): NAMED_ADDR})

    assert "addresses no setting" in str(raised.value)
    assert "Addressable keys: ADDR" in str(raised.value)


def test_a_variable_naming_an_undeclared_store_is_refused() -> None:
    """Invariant 5: the config is the whitelist, and a variable cannot extend it."""
    with pytest.raises(ConfigError) as raised:
        loaded({named_variable("vault-prod", "ADDR"): NAMED_ADDR})

    assert "SOPULI_VAULT__VAULT_PROD__ADDR" in str(raised.value)
    assert f"`{STORE}` ({NAMED})" in str(raised.value)


def test_the_refusal_says_so_when_no_store_is_declared_at_all() -> None:
    with pytest.raises(ConfigError) as raised:
        build_config({"version": 1}, env={named_variable("vault-prod", "ADDR"): NAMED_ADDR})

    assert "there is no `vaults:`" in str(raised.value)


# ------------------------------------------------------- no active store ---


def test_the_unnamed_sopuli_variable_is_refused_with_no_default_store() -> None:
    """A variable that silently followed whichever store a binding reached is
    the `vault_settings:` block C13 rejected, spelled differently."""
    with pytest.raises(ConfigError) as raised:
        build_config(
            {"version": 1, "vaults": {STORE: {"type": "hashicorp"}}},
            env={"SOPULI_VAULT_ADDR": ACTIVE_ADDR},
        )

    assert "names no store" in str(raised.value)
    assert "SOPULI_VAULT=<store>" in str(raised.value)
    assert raised.value.exit_code == ExitCode.CONFIG_INVALID


def test_a_third_party_variable_with_no_default_store_warns_instead() -> None:
    """`VAULT_ADDR` is exported in every shell that has run `vault`, and it was
    not set for this tool. Failing a run over somebody else's variable would be
    taking a position on an environment this tool does not own."""
    config = build_config(
        {"version": 1, "vaults": {STORE: {"type": "hashicorp"}}},
        env={"VAULT_ADDR": THIRDPARTY_ADDR},
    )

    [warning] = [one for one in config.warnings if "VAULT_ADDR" in one.message]
    assert "was not applied" in warning.message
    assert warning.code == THIRD_PARTY_VARIABLE_UNAPPLIED
    assert config.vaults[0].addr is None


def test_a_third_party_variable_for_an_undeclared_default_store_has_the_same_code() -> None:
    """One code for both reasons the variable was not applied: either way it was
    ignored, and the message says which."""
    config = build_config(
        {"version": 1, "vaults": {STORE: {"type": "hashicorp"}}},
        env={"VAULT_ADDR": THIRDPARTY_ADDR, "SOPULI_VAULT": "vault-absent"},
    )

    [warning] = [one for one in config.warnings if "VAULT_ADDR" in one.message]
    assert "is not declared" in warning.message
    assert warning.code == THIRD_PARTY_VARIABLE_UNAPPLIED


def test_a_third_party_variable_with_a_default_store_says_nothing() -> None:
    assert merged({"VAULT_ADDR": THIRDPARTY_ADDR}).patched == ("addr",)
    assert loaded({"VAULT_ADDR": THIRDPARTY_ADDR}).warnings == ()


def test_sopuli_vault_naming_an_undeclared_store_is_refused() -> None:
    """`check_references` never sees this one: it resolves names written in the
    file, and this one was written in the environment."""
    with pytest.raises(ConfigError) as raised:
        build_config(
            {"version": 1, "vaults": {STORE: {"type": "hashicorp"}}},
            env={"SOPULI_VAULT": "vault-typo", "SOPULI_VAULT_ADDR": ACTIVE_ADDR},
        )

    assert "'vault-typo'" in str(raised.value)
    assert "SOPULI_VAULT" in str(raised.value)


def test_a_dangling_defaults_vault_is_reported_once() -> None:
    """It is `check_references`' finding, with the message every other dangling
    name in the file gets. Saying it here as well would be one mistake in two
    phrasings."""
    with pytest.raises(ConfigError) as raised:
        build_config(
            {
                "version": 1,
                "vaults": {STORE: {"type": "hashicorp"}},
                "defaults": {"vault": "vault-typo"},
            },
            env={"VAULT_ADDR": THIRDPARTY_ADDR},
        )

    assert str(raised.value).startswith("defaults.vault: no vault named 'vault-typo'")


# ------------------------------------------------------------- the registry ---


@pytest.mark.parametrize("key", sorted(set(ACTIVE_VARIABLES.values()) | set(NAMED_KEYS.values())))
def test_every_sopuli_variable_supplies_a_setting_that_takes_layer_two(key: str) -> None:
    """The variable's spelling and the setting's are two names for one thing, and
    the registry is where the second one has to declare the layer. Asserted here
    rather than left to the resolver, so a variable added without its layer fails
    in the module that added it."""
    assert Layer.ENV in setting(setting_name(key)).layers


@pytest.mark.parametrize("key", sorted(set(THIRDPARTY_VARIABLES.values())))
def test_every_third_party_variable_supplies_a_setting_that_takes_layer_three(key: str) -> None:
    assert Layer.ENV_THIRDPARTY in setting(setting_name(key)).layers


def test_no_environment_variable_addresses_the_ratcheted_key() -> None:
    """`vaults.*.tls.verify` is under invariant 10, and §6 refuses
    `VAULT_SKIP_VERIFY` outright rather than ranking it. Nothing here may quietly
    provide the same reach under another spelling."""
    supplied = {*NAMED_KEYS.values(), *ACTIVE_VARIABLES.values(), *THIRDPARTY_VARIABLES.values()}

    assert "tls.verify" not in supplied
    assert Layer.ENV not in setting("vaults.*.tls.verify").layers
    assert Layer.ENV_THIRDPARTY not in setting("vaults.*.tls.verify").layers


# ------------------------------------------------ VAULT_ADDR over the file ---


def overrides(config: Config) -> list[Any]:
    return [one for one in config.warnings if one.code == THIRD_PARTY_ADDR_OVERRIDES]


def test_vault_addr_over_a_different_declared_addr_warns_naming_both() -> None:
    """P3's order stands, so the variable wins, and the run says so (#865). A
    shell keeps `VAULT_ADDR` from other work, and the run would otherwise send
    its auth material there with nothing said."""
    config = loaded({"VAULT_ADDR": THIRDPARTY_ADDR}, {"addr": DECLARED})

    assert config.vaults[0].addr == THIRDPARTY_ADDR
    [warning] = overrides(config)
    assert THIRDPARTY_ADDR in warning.message
    assert DECLARED in warning.message
    assert "VAULT_ADDR" in warning.message
    assert f"vaults.{STORE}.addr" in warning.message, "it names where the file declares it"


def test_vault_addr_over_a_profile_addr_names_the_profile() -> None:
    """The file's answer is its highest layer, so a profile's `addr` is the one
    the variable overrode."""
    config = build_config(
        document({"addr": DECLARED}, profiles={"ci": {"vaults": {STORE: {"addr": NAMED_ADDR}}}}),
        env={"VAULT_ADDR": THIRDPARTY_ADDR},
        profile="ci",
    )

    [warning] = overrides(config)
    assert NAMED_ADDR in warning.message
    assert "profiles.ci" in warning.message


@pytest.mark.parametrize(
    "declared",
    [
        THIRDPARTY_ADDR,
        f"{THIRDPARTY_ADDR}/",
        "https://third-party.example.com:443",
        "HTTPS://Third-Party.example.com",
    ],
    ids=["equal", "trailing-slash", "default-port", "case"],
)
def test_vault_addr_that_names_the_same_server_says_nothing(declared: str) -> None:
    """A warning on every run for an address that is not different would teach
    operators to ignore it."""
    assert overrides(loaded({"VAULT_ADDR": THIRDPARTY_ADDR}, {"addr": declared})) == []


def test_another_port_is_another_address() -> None:
    config = loaded(
        {"VAULT_ADDR": "https://third-party.example.com:8200"}, {"addr": THIRDPARTY_ADDR}
    )

    assert len(overrides(config)) == 1


@pytest.mark.parametrize(
    ("address", "shown"),
    [
        ("https://ops:s3cret@proxy.example.com:8200", "https://***@proxy.example.com:8200"),
        ("https://ops:s3/cret@proxy.example.com", "https://***@proxy.example.com"),
        ("https://ops:s3?cret@proxy.example.com", "https://***@proxy.example.com"),
        ("https://ops:s3#cret@proxy.example.com", "https://***@proxy.example.com"),
        ("https://ops:s3cret@[proxy", "https://***@[proxy"),
        ("ops:s3cret@proxy.example.com", "***@proxy.example.com"),
    ],
    ids=["plain", "slash", "query", "hash", "unparseable", "no-scheme"],
)
def test_credentials_in_an_address_are_not_repeated_in_the_warning(
    address: str, shown: str
) -> None:
    """The warning reaches every run's output, so userinfo is masked. A `/`, `?`
    or `#` in the password, or an address `urlsplit` cannot parse, still masks."""
    [warning] = overrides(loaded({"VAULT_ADDR": address}, {"addr": DECLARED}))

    assert "s3" not in warning.message
    assert "ops" not in warning.message
    assert shown in warning.message


def test_vault_addr_over_a_defaults_addr_names_the_defaults_key() -> None:
    """`defaults.vaults` is the file too, so overriding it warns."""
    config = loaded(
        {"VAULT_ADDR": THIRDPARTY_ADDR}, defaults={"vaults": {STORE: {"addr": DECLARED}}}
    )

    [warning] = overrides(config)
    assert DECLARED in warning.message
    assert f"defaults.vaults.{STORE}.addr" in warning.message


def test_the_flag_over_the_file_says_nothing() -> None:
    """`--vault-addr` was typed for this run."""
    config = build_config(document({"addr": DECLARED}), vault_addr=ACTIVE_ADDR)

    assert config.vaults[0].addr == ACTIVE_ADDR
    assert overrides(config) == []


def test_vault_addr_where_the_file_declares_no_addr_says_nothing() -> None:
    """Nothing to disagree with: the variable is the only answer."""
    config = loaded({"VAULT_ADDR": THIRDPARTY_ADDR})

    assert config.vaults[0].addr == THIRDPARTY_ADDR
    assert overrides(config) == []


def test_this_tools_own_variable_over_the_file_says_nothing() -> None:
    """`SOPULI_VAULT_ADDR` was set for this tool, so overriding the file is meant."""
    config = loaded({"SOPULI_VAULT_ADDR": ACTIVE_ADDR}, {"addr": DECLARED})

    assert config.vaults[0].addr == ACTIVE_ADDR
    assert overrides(config) == []


def test_vault_addr_that_lost_to_this_tools_own_variable_says_nothing() -> None:
    """The run does not go to `VAULT_ADDR`'s address, so there is nothing to warn of."""
    config = loaded(
        {"VAULT_ADDR": THIRDPARTY_ADDR, "SOPULI_VAULT_ADDR": ACTIVE_ADDR}, {"addr": DECLARED}
    )

    assert overrides(config) == []

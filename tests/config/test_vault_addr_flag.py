"""``--vault-addr``, layer 1 of ``vaults.*.addr`` (#422).

Tier 0, pure: a document and a string in, a merged store out. What the flag does
once a real command line parses it is ``tests/test_cli_precedence.py``.

The flag itself is three lines of click. What is worth testing is the part that
is not the flag:

**It addresses the store §6 already decided the unnamed variables address**, and
refuses where nothing names one. A command line that resolved "the default store"
its own way would be a second definition of it, one layer above the first, and
the two would agree until the day somebody changed one -- so the flag goes
through the same placement code the variables do, and these cases are the proof
rather than the intention.

**It ranks above the environment and below nothing.** That is the whole reason it
exists: an operator redirecting one run should not have to export a variable that
then outlives the command, which on Windows is two statements and a session that
remembers (P4).

**There is no named form**, decided with the flag. A run touching two stores uses
``SOPULI_VAULT__<NAME>__ADDR``; the flag has nowhere to put a store name and is
not going to grow a ``NAME=URL`` grammar to get one.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import Config, Vault
from sopuli.config.vault_env import ADDR_FLAG, named_variable
from sopuli.exit_codes import ExitCode
from sopuli.settings import Layer, setting

STORE = "vault-dev"
NAMED = named_variable(STORE, "ADDR")

DECLARED = "https://declared.example.com"
FLAG_ADDR = "https://flag.example.com"
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


def merged(
    addr: str | None = FLAG_ADDR,
    env: dict[str, str] | None = None,
    vault: dict[str, Any] | None = None,
    **sections: Any,
) -> Vault:
    config: Config = build_config(document(vault, **sections), env=env or {}, vault_addr=addr)
    assert len(config.vaults) == 1
    return config.vaults[0]


# ----------------------------------------------------------------- the layer ---


def test_the_registry_gives_addr_a_cli_layer_and_nothing_else_one() -> None:
    """One key wide, on purpose. A flag per reach key would be six spellings of
    what ``vaults:`` already says once."""
    assert Layer.CLI in setting("vaults.*.addr").layers
    for key in ("mount", "kv_version", "namespace", "timeout_s"):
        assert Layer.CLI not in setting(f"vaults.*.{key}").layers, key


def test_the_flag_supplies_the_store_defaults_vault_names() -> None:
    store = merged()

    assert store.addr == FLAG_ADDR
    assert store.patched == ("addr",)


def test_nothing_written_changes_nothing() -> None:
    assert merged(None, vault={"addr": DECLARED}).addr == DECLARED


def test_an_empty_value_says_nothing() -> None:
    """Consistent with §6's reading of a set-but-empty variable: it is not an
    answer, and treating it as one would make `--vault-addr ""` blank an address
    the file was right about."""
    assert merged("", vault={"addr": DECLARED}).addr == DECLARED


# ------------------------------------------------------------------- ranking ---


def test_the_flag_beats_the_declaration() -> None:
    assert merged(vault={"addr": DECLARED}).addr == FLAG_ADDR


def test_the_flag_beats_the_unnamed_variable() -> None:
    assert merged(env={"SOPULI_VAULT_ADDR": ACTIVE_ADDR}).addr == FLAG_ADDR


def test_the_flag_beats_the_named_variable() -> None:
    """Layer 1 over layer 2, even though the variable is the more *specific*
    request. Specificity ranks within a layer; between layers P3's order does."""
    assert merged(env={NAMED: NAMED_ADDR}).addr == FLAG_ADDR


def test_the_flag_beats_the_third_party_variable() -> None:
    assert merged(env={"VAULT_ADDR": THIRDPARTY_ADDR}).addr == FLAG_ADDR


def test_the_flag_beats_a_profile() -> None:
    config = build_config(
        {
            "version": 1,
            "vaults": {STORE: {"type": "hashicorp", "addr": DECLARED}},
            "defaults": {"vault": STORE},
            "profiles": {"ci": {"vaults": {STORE: {"addr": ACTIVE_ADDR}}}},
        },
        profile="ci",
        vault_addr=FLAG_ADDR,
    )

    assert config.vaults[0].addr == FLAG_ADDR


def test_it_reaches_only_addr() -> None:
    """A store the flag redirected keeps every other key the file wrote. The
    failure this guards is a placement that replaced the store rather than one
    of its settings."""
    store = merged(vault={"addr": DECLARED, "mount": "kv", "kv_version": 2})

    assert (store.addr, store.mount, store.kv_version) == (FLAG_ADDR, "kv", 2)


# --------------------------------------------------------------- addressing ---


def test_sopuli_vault_moves_the_flag_to_another_store() -> None:
    """The flag addresses whichever store is the active one, and `SOPULI_VAULT`
    is layer 2 of the setting that decides which. A flag that had bound to
    `defaults.vault` directly would be a second definition of "default store"."""
    config = build_config(
        {
            "version": 1,
            "vaults": {"vault-a": {"type": "hashicorp"}, "vault-b": {"type": "hashicorp"}},
            "defaults": {"vault": "vault-a"},
        },
        env={"SOPULI_VAULT": "vault-b"},
        vault_addr=FLAG_ADDR,
    )

    assert {one.name: one.addr for one in config.vaults} == {
        "vault-a": None,
        "vault-b": FLAG_ADDR,
    }


def test_it_reaches_one_store_and_not_the_others() -> None:
    """The multi-store case the flag deliberately cannot express: it redirects
    the default store, and the others are the environment's to name."""
    config = build_config(
        {
            "version": 1,
            "vaults": {"vault-a": {"type": "hashicorp"}, "vault-b": {"type": "hashicorp"}},
            "defaults": {"vault": "vault-a"},
        },
        vault_addr=FLAG_ADDR,
    )

    assert {one.name: one.addr for one in config.vaults} == {
        "vault-a": FLAG_ADDR,
        "vault-b": None,
    }


def test_with_no_default_store_it_is_refused_rather_than_guessed() -> None:
    """§6's rule, and the flag inherits it rather than restating it. Following
    whichever store the current binding resolved to is C13's rejected
    `vault_settings:` block spelled as a flag -- it lets an address typed for dev
    follow a changed `vault:` into prod."""
    with pytest.raises(ConfigError) as raised:
        build_config(
            {"version": 1, "vaults": {STORE: {"type": "hashicorp"}}},
            vault_addr=FLAG_ADDR,
        )

    assert raised.value.exit_code == ExitCode.CONFIG_INVALID
    assert ADDR_FLAG in str(raised.value)
    assert "no default one to apply it to" in str(raised.value)
    assert "SOPULI_VAULT=<store>" in (raised.value.hint or "")


def test_a_dangling_default_store_names_the_flag_and_the_key_separately() -> None:
    """Two halves of one sentence: what the operator wrote, and what named the
    store it could not be placed on. Collapsing them reported `defaults.vault`
    as the thing that was typed, which it was not."""
    with pytest.raises(ConfigError) as raised:
        build_config(
            {
                "version": 1,
                "vaults": {STORE: {"type": "hashicorp"}},
                "defaults": {"vault": "nosuch"},
            },
            vault_addr=FLAG_ADDR,
        )

    assert str(raised.value).startswith(f"{ADDR_FLAG} applies to the default store 'nosuch'")
    assert "defaults.vault names it" in (raised.value.hint or "")


def test_the_refusal_is_the_same_shape_the_variable_gets() -> None:
    """One placement rule, so the two cannot drift into two messages."""
    document_without_default = {"version": 1, "vaults": {STORE: {"type": "hashicorp"}}}

    with pytest.raises(ConfigError) as by_flag:
        build_config(document_without_default, vault_addr=FLAG_ADDR)
    with pytest.raises(ConfigError) as by_variable:
        build_config(document_without_default, env={"SOPULI_VAULT_ADDR": ACTIVE_ADDR})

    assert str(by_flag.value).replace(ADDR_FLAG, "X") == str(by_variable.value).replace(
        "SOPULI_VAULT_ADDR", "X"
    )
    assert by_flag.value.hint == by_variable.value.hint

"""The ``vaults:`` section.

Tier 0, pure: everything builds from a dict, so there is no filesystem and no
vault. Fixtures use the fictional vocabulary the provenance note requires --
hosts under ``example.com``, never a real address or mount.

The interesting tests here are the two refusals. A vault entry chooses a backend
and an auth method, and both are closed sets: a free string means a typo loads
happily and the tool then goes looking for passwords somewhere nobody intended.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.vaults import build_vaults

HASHICORP: dict[str, Any] = {
    "type": "hashicorp",
    "addr": "https://vault.example.com",
    "mount": "kv",
    "kv_version": 2,
    "auth": {"method": "token"},
}


def document(**vaults: Any) -> dict[str, Any]:
    return {"version": 1, "vaults": vaults}


def only(**vaults: Any) -> Any:
    built = build_vaults(document(**vaults))
    assert len(built) == 1
    return built[0]


def test_a_vault_is_read_whole() -> None:
    vault = only(**{"vault-prod": HASHICORP})

    assert vault.name == "vault-prod"
    assert vault.type == "hashicorp"
    assert vault.addr == "https://vault.example.com"
    assert vault.mount == "kv"
    assert vault.kv_version == 2
    assert vault.auth is not None
    assert vault.auth.method == "token"


def test_vaults_keep_document_order() -> None:
    """Error messages and `config show` both read better estate-order than
    sorted; anything that needs a stable order sorts when it renders."""
    built = build_vaults(document(**{"vault-prod": HASHICORP, "vault-dev": HASHICORP}))

    assert [vault.name for vault in built] == ["vault-prod", "vault-dev"]


def test_a_config_may_declare_no_vaults() -> None:
    assert build_vaults({"version": 1}) == ()


# ------------------------------------------------------------------- type ---


def test_type_is_required() -> None:
    """Which backend a store is cannot be guessed from the other keys, and
    guessing wrong means reading a password from the wrong place."""
    with pytest.raises(ConfigError) as caught:
        build_vaults(document(**{"vault-dev": {"addr": "https://vault.example.com"}}))

    rendered = str(caught.value)
    assert "vaults.vault-dev.type" in rendered
    assert "must be given" in rendered


def test_an_unknown_type_is_refused_and_lists_the_known_ones() -> None:
    with pytest.raises(ConfigError) as caught:
        build_vaults(document(**{"vault-dev": {"type": "hashicrop"}}))

    rendered = str(caught.value)
    assert "unknown vault type 'hashicrop'" in rendered
    assert "hashicorp" in rendered


def test_a_backend_that_is_only_planned_is_refused() -> None:
    """P2 lists AWS and Azure as "later". A config declaring a store the tool
    cannot reach should fail while it is being written, not at the first
    rotation."""
    with pytest.raises(ConfigError) as caught:
        build_vaults(document(**{"vault-dev": {"type": "aws"}}))

    assert "unknown vault type 'aws'" in str(caught.value)


@pytest.mark.parametrize("kind", ["hashicorp", "oci", "file", "keyring"])
def test_every_backend_p2_puts_in_scope_is_accepted(kind: str) -> None:
    assert only(**{"store": {"type": kind}}).type == kind


def test_only_type_is_required() -> None:
    """A file backend has no address and no mount. P2 puts per-backend
    validation behind the store interface, so demanding a HashiCorp shape of
    every entry would be the top-level vendor bias P1 forbids."""
    vault = only(**{"local": {"type": "file"}})

    assert vault.addr is None
    assert vault.auth is None


# -------------------------------------------------------------- kv_version ---


def test_an_unsupported_kv_version_is_refused() -> None:
    """KV v1 and v2 are different backends with different capabilities (P2);
    3 is a typo rather than a future."""
    with pytest.raises(ConfigError) as caught:
        build_vaults(document(**{"vault-dev": {"type": "hashicorp", "kv_version": 3}}))

    assert "unsupported kv_version 3" in str(caught.value)


def test_kv_version_true_is_not_version_one() -> None:
    """`bool` subclasses `int`, so this passes a naive membership test."""
    with pytest.raises(ConfigError) as caught:
        build_vaults(document(**{"vault-dev": {"type": "hashicorp", "kv_version": True}}))

    assert "must be a number, not a boolean" in str(caught.value)


# --------------------------------------------------------------------- auth ---


@pytest.mark.parametrize("method", ["token", "approle", "oidc", "instance_principal"])
def test_the_auth_methods_p2_names_are_accepted(method: str) -> None:
    vault = only(**{"vault-dev": {"type": "hashicorp", "auth": {"method": method}}})

    assert vault.auth is not None
    assert vault.auth.method == method


def test_an_unknown_auth_method_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_vaults(document(**{"vault-dev": {"type": "hashicorp", "auth": {"method": "tokne"}}}))

    assert "unknown auth method 'tokne'" in str(caught.value)


def test_auth_material_keys_are_refused_and_say_why() -> None:
    """The one place this layer refuses rather than guesses.

    P2 names the methods but never says what the keys pointing at the material
    are called -- only that the file must not hold the material itself. Accepting
    `role_id:` now would fix a schema the vault layer then has to live with, so
    it is an error that names the open question instead.
    """
    with pytest.raises(ConfigError) as caught:
        build_vaults(
            document(
                **{
                    "vault-dev": {
                        "type": "hashicorp",
                        "auth": {"method": "approle", "role_id": "0000"},
                    }
                }
            )
        )

    rendered = str(caught.value)
    assert "unknown key 'role_id'" in rendered
    assert "not specified yet" in rendered
    assert "#27" in rendered


def test_an_auth_block_must_name_a_method() -> None:
    with pytest.raises(ConfigError) as caught:
        build_vaults(document(**{"vault-dev": {"type": "hashicorp", "auth": {}}}))

    assert "must name an auth method" in str(caught.value)


# ---------------------------------------------------------- non_production ---


def test_non_production_defaults_to_false() -> None:
    """§9 refuses a prod target pointed at a non-production store. Defaulting the
    other way would fire that rule on every vault nobody has labelled yet."""
    assert only(**{"vault-dev": HASHICORP}).non_production is False


def test_non_production_is_read_when_set() -> None:
    assert only(**{"local": {"type": "file", "non_production": True}}).non_production is True


def test_a_quoted_boolean_is_not_a_boolean() -> None:
    """`non_production: "false"` is a string, and a truthy one. Reading it as a
    flag would turn the guard off in the file that asked for it."""
    with pytest.raises(ConfigError) as caught:
        build_vaults(document(**{"local": {"type": "file", "non_production": "false"}}))

    assert "must be true or false, not a string" in str(caught.value)


# ------------------------------------------------------------ unknown keys ---


def test_an_unknown_vault_key_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_vaults(document(**{"vault-dev": {"type": "hashicorp", "adrr": "x"}}))

    rendered = str(caught.value)
    assert "unknown key 'adrr'" in rendered
    assert "vaults.vault-dev" in rendered

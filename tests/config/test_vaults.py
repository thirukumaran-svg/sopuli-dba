"""The ``vaults:`` section.

Tier 0, pure: everything builds from a dict, so there is no filesystem and no
vault. Fixtures use the fictional vocabulary the provenance note requires --
hosts under ``example.com``, never a real address or mount.

Two kinds of refusal are worth reading. A vault entry chooses a backend and an
auth method, and both are closed sets: a free string means a typo loads happily
and the tool then goes looking for passwords somewhere nobody intended. And every
secret-bearing key under ``auth:`` is a MaterialRef -- a named environment
variable or file -- so a credential written inline is refused rather than read,
which is P2's constraint and invariant 2's, enforced by shape.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.vaults import AUTH_MATERIAL_KEYS, AUTH_METHODS, build_vaults

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


def auth(**keys: Any) -> Any:
    """The `auth:` block of a vault built from `keys`."""
    return only(**{"vault-dev": {"type": "hashicorp", "auth": keys or None}}).auth


def required_keys(method: str) -> dict[str, Any]:
    """Whatever this method must be given, filled in from its own spec.

    Derived rather than written out so that a method added to the table is
    exercised by the test below without anybody remembering to extend a fixture.
    """
    return {
        key: {"env": key.upper()} if key in AUTH_MATERIAL_KEYS else key
        for key in AUTH_METHODS[method].required
    }


@pytest.mark.parametrize("method", list(AUTH_METHODS))
def test_every_auth_method_p2_names_is_accepted(method: str) -> None:
    """P2's list, pinned. Only the name here; the keys are the tests below."""
    assert auth(method=method, **required_keys(method)).method == method


def test_an_unknown_auth_method_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_vaults(document(**{"vault-dev": {"type": "hashicorp", "auth": {"method": "tokne"}}}))

    assert "unknown auth method 'tokne'" in str(caught.value)


def test_an_auth_block_must_name_a_method() -> None:
    with pytest.raises(ConfigError) as caught:
        build_vaults(document(**{"vault-dev": {"type": "hashicorp", "auth": {}}}))

    rendered = str(caught.value)
    assert "vaults.vault-dev.auth.method" in rendered
    assert "must name a method" in rendered


# ------------------------------------------------------- material, per method ---


def test_approle_names_where_both_halves_come_from() -> None:
    """P2's own example of a method with material: role_id and secret_id, each
    from an environment variable or a file, never inline."""
    block = auth(
        method="approle",
        mount="approle",
        role_id={"env": "SOPULI_VAULT_ROLE_ID"},
        secret_id={"file": "/run/secrets/vault_secret_id"},
    )

    assert block.mount == "approle"
    assert block.role_id is not None
    assert (block.role_id.kind, block.role_id.location) == ("env", "SOPULI_VAULT_ROLE_ID")
    assert block.secret_id is not None
    assert (block.secret_id.kind, block.secret_id.location) == (
        "file",
        "/run/secrets/vault_secret_id",
    )


def test_material_written_inline_is_refused_as_the_wrong_kind_of_thing() -> None:
    """The rule this whole shape exists for (P2, invariant 2). A string here is
    not a type error to be reported as one: it is somebody writing the credential
    into a file that is committed and shared, so the message says that."""
    with pytest.raises(ConfigError) as caught:
        auth(method="approle", role_id="0000", secret_id={"env": "SECRET_ID"})

    rendered = str(caught.value)
    assert "vaults.vault-dev.auth.role_id" in rendered
    assert "auth material is named, not written here" in rendered
    assert "`env:`" in rendered
    assert "`file:`" in rendered


def test_material_written_as_an_unquoted_number_is_the_same_mistake() -> None:
    """An AppRole role_id looks like a number often enough that YAML will hand one
    over as an int. It is still a credential in a committed file."""
    with pytest.raises(ConfigError) as caught:
        auth(method="approle", role_id=1234, secret_id={"env": "SECRET_ID"})

    assert "auth material is named, not written here" in str(caught.value)


def test_a_material_ref_names_exactly_one_source() -> None:
    """Two sources leave nothing to say which was meant, and the tool would have
    to pick one -- silently deciding which credential it authenticates with."""
    with pytest.raises(ConfigError) as caught:
        auth(method="token", token={"env": "VAULT_TOKEN", "file": "~/.vault-token"})

    rendered = str(caught.value)
    assert "must name exactly one source, found 2" in rendered
    assert "'env', 'file'" in rendered


def test_an_empty_material_ref_names_no_source() -> None:
    with pytest.raises(ConfigError) as caught:
        auth(method="token", token={})

    assert "must name exactly one source, found 0" in str(caught.value)


def test_a_material_source_that_is_not_a_source_is_refused() -> None:
    """`command:` is the one somebody will reach for -- Vault has a token helper.
    Shelling out from a credential tool is its own decision, so it is not here."""
    with pytest.raises(ConfigError) as caught:
        auth(method="token", token={"command": "vault-helper get"})

    rendered = str(caught.value)
    assert "unknown material source 'command'" in rendered
    assert "known: env, file" in rendered


def test_a_material_location_must_be_a_string() -> None:
    with pytest.raises(ConfigError) as caught:
        auth(method="token", token={"env": ["VAULT_TOKEN"]})

    assert "vaults.vault-dev.auth.token.env" in str(caught.value)


@pytest.mark.parametrize(
    ("method", "key"),
    [(method, key) for method, spec in AUTH_METHODS.items() for key in spec.keys],
    ids=lambda value: str(value),
)
def test_every_key_a_method_takes_is_read_into_the_model(method: str, key: str) -> None:
    """Accepted and then dropped is the failure this catches.

    A key can be added to a method's spec, pass validation, and never reach the
    model -- and the only symptom is a vault that authenticates as though the line
    had not been written. Exhaustive over (method, key) rather than sampled,
    because the sampled version is what let the gap exist.
    """
    written: Any = {"env": key.upper()} if key in AUTH_MATERIAL_KEYS else key
    block = auth(method=method, **{**required_keys(method), key: written})

    assert getattr(block, key) is not None


def test_identity_fields_stay_inline() -> None:
    """`role`, `username`, `profile` and `mount` name *who* rather than prove it,
    so they are written as they are. Only material is addressed indirectly."""
    block = auth(method="userpass", username="sopuli", password={"env": "PW"}, mount="userpass")

    assert (block.username, block.mount) == ("sopuli", "userpass")


# -------------------------------------------------------- keys and methods ---


def test_a_key_belonging_to_another_method_is_refused_naming_the_method() -> None:
    """The one cross-key rule this block has. `role_id` under `method: token` is
    not a typo -- it is a leftover from an edit that changed the method, and the
    message has to say which method is in force."""
    with pytest.raises(ConfigError) as caught:
        auth(method="token", role_id={"env": "ROLE_ID"})

    rendered = str(caught.value)
    assert "unknown key 'role_id'" in rendered
    assert "`method: token` takes `token`" in rendered


def test_a_method_missing_its_material_is_refused_at_load() -> None:
    """An AppRole with no secret_id cannot authenticate, and finding that out at
    the first rotation is invariant 4's failure mode.

    Reported at the key that is missing rather than at the block, the way a missing
    required key is reported everywhere else -- the path is the line that has to be
    written.
    """
    with pytest.raises(ConfigError) as caught:
        auth(method="approle", role_id={"env": "ROLE_ID"})

    rendered = str(caught.value)
    assert "vaults.vault-dev.auth.secret_id" in rendered
    assert "`method: approle` needs `secret_id`" in rendered
    assert "required for this method: role_id, secret_id" in rendered


def test_several_missing_keys_are_all_named_at_the_first_of_them() -> None:
    """One location, every missing key. Naming only the one the path points at
    would mean fixing it and being told again."""
    with pytest.raises(ConfigError) as caught:
        auth(method="approle")

    rendered = str(caught.value)
    assert "vaults.vault-dev.auth.role_id" in rendered
    assert "needs `role_id`, `secret_id`" in rendered


@pytest.mark.parametrize("method", ["token", "instance_principal", "config_file"])
def test_a_method_that_needs_nothing_may_be_written_as_a_bare_value(method: str) -> None:
    """`auth: token` is sugar for `{ method: token }`, which is what keeps §2's
    and §4's examples valid and lets P2's token source chain stay implicit."""
    vault = only(**{"vault-dev": {"type": "hashicorp", "auth": method}})

    assert vault.auth is not None
    assert vault.auth.method == method
    assert vault.auth.token is None


def test_a_method_that_needs_material_may_not_be_written_as_a_bare_value() -> None:
    """There is nowhere in `auth: approle` to say where role_id comes from, and
    the old draft's answer -- fall through to some other source -- is exactly the
    failure nobody can explain afterwards."""
    with pytest.raises(ConfigError) as caught:
        build_vaults(document(**{"vault-dev": {"type": "hashicorp", "auth": "approle"}}))

    rendered = str(caught.value)
    assert "`approle` cannot be written as a bare value" in rendered
    assert "role_id" in rendered


def test_an_unknown_method_written_as_a_bare_value_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_vaults(document(**{"vault-dev": {"type": "hashicorp", "auth": "tokne"}}))

    assert "unknown auth method 'tokne'" in str(caught.value)


# ---------------------------------------------------------- non_production ---


def test_non_production_defaults_to_false() -> None:
    """§10 refuses a prod target pointed at a non-production store. Defaulting the
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

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
    # The hint says what to *write* rather than repeating the key.
    assert "`secret_id:` is named, not written -- `{ env: NAME }` or `{ file: PATH }`" in rendered


def test_several_missing_keys_are_all_named_at_the_first_of_them() -> None:
    """One location, every missing key. Naming only the one the path points at
    would mean fixing it and being told again."""
    with pytest.raises(ConfigError) as caught:
        auth(method="approle")

    rendered = str(caught.value)
    assert "vaults.vault-dev.auth.role_id" in rendered
    assert "needs `role_id`, `secret_id`" in rendered
    # And the hint explains both, once: two keys sharing a shape are grouped, or a
    # hint says the same sentence twice and stops being read.
    assert "`role_id:` and `secret_id:` are named, not written" in rendered


def test_the_hint_distinguishes_material_from_an_identity_field() -> None:
    """A method can require both kinds, so one sentence about MaterialRefs
    would be wrong. `kubernetes` needs a `role`, which is written as it is, and a
    `jwt`, which is named -- and the hint has to say which is which."""
    with pytest.raises(ConfigError) as caught:
        auth(method="kubernetes")

    rendered = str(caught.value)
    assert "`role:` is written inline" in rendered
    assert "`jwt:` is named, not written" in rendered


def test_the_hint_does_not_merely_repeat_the_message() -> None:
    """The message names the keys and the path names one of them; a hint that
    lists them a third time answers nothing, and CLAUDE.md asks a hint to say
    what to do next."""
    with pytest.raises(ConfigError) as caught:
        auth(method="approle")

    message, hint = str(caught.value).split("hint:")
    assert "env" in hint
    assert "file" in hint
    # Nothing in the hint is only a restatement of the key list.
    assert hint.strip() != ", ".join(("role_id", "secret_id"))
    assert "required for this method" not in message


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
    # The same explanation as the missing-key error, for the same reason:
    # knowing which keys are needed is not knowing what to write in them.
    assert "`role_id:` and `secret_id:` are named, not written" in rendered
    assert "{ env: NAME }" in rendered


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


# ------------------------------------------------------- transport settings ---
#
# ADR-005 puts `namespace`, `timeout_s` and `tls:` in §3a. These are the keys
# the HashiCorp adapter reads: `httpx` has no default timeout, and `tls:` is why
# ADR-005 chose a client that takes a real SSLContext rather than a boolean.


def test_the_transport_keys_are_read() -> None:
    [vault] = build_vaults(
        {
            "vaults": {
                "vault-prod": {
                    **HASHICORP,
                    "namespace": "acme/platform",
                    "timeout_s": 10,
                    "tls": {
                        "ca_file": "/etc/ssl/acme-ca.pem",
                        "server_name": "vault.example.com",
                    },
                }
            }
        }
    )

    assert vault.namespace == "acme/platform"
    assert vault.timeout_s == 10
    assert vault.tls is not None
    assert vault.tls.ca_file == "/etc/ssl/acme-ca.pem"
    assert vault.tls.server_name == "vault.example.com"


def test_the_transport_keys_are_all_optional() -> None:
    """A file backend has no address and no TLS. Requiring any of these would be
    the top-level vendor bias P1 forbids, one level down."""
    [vault] = build_vaults({"vaults": {"local": {"type": "file"}}})

    assert (vault.namespace, vault.timeout_s, vault.tls) == (None, None, None)


def test_verify_is_absent_rather_than_true_when_unwritten() -> None:
    """The distinction the ratchet needs: "nobody said" is not "somebody agreed".

    Once a profile or `defaults:` can patch a store (C13), a layer that
    declined to speak must not read as one that wrote `true` -- otherwise the
    strictest-wins merge cannot tell them apart. `verified` is the effective
    value, and only an explicit `false` turns it off.
    """
    [vault] = build_vaults({"vaults": {"v": {**HASHICORP, "tls": {"ca_path": "/etc/ssl"}}}})

    assert vault.tls is not None
    assert vault.tls.verify is None
    assert vault.tls.verified is True


def test_verify_false_is_read_and_kept() -> None:
    [vault] = build_vaults({"vaults": {"v": {**HASHICORP, "tls": {"verify": False}}}})

    assert vault.tls is not None
    assert vault.tls.verify is False
    assert vault.tls.verified is False


def test_an_unknown_key_under_tls_is_refused() -> None:
    """The block must not become a free-form bag: a misspelled `ca_file` that
    loaded happily would leave the run verifying against the system store while
    the file says otherwise."""
    with pytest.raises(ConfigError) as caught:
        build_vaults({"vaults": {"v": {**HASHICORP, "tls": {"cafile": "/etc/ssl/ca.pem"}}}})

    assert "cafile" in str(caught.value)


def test_a_client_key_without_a_certificate_is_refused() -> None:
    """An edit that stopped halfway. A key alone presents nothing."""
    with pytest.raises(ConfigError) as caught:
        build_vaults({"vaults": {"v": {**HASHICORP, "tls": {"client_key": "/etc/ssl/k.pem"}}}})

    assert "client_key" in str(caught.value)
    assert "client_cert" in str(caught.value)


def test_a_client_certificate_may_stand_alone() -> None:
    """The reverse is not an error: a combined PEM holds both halves, and
    refusing it would refuse a perfectly ordinary way to write mutual TLS."""
    [vault] = build_vaults(
        {"vaults": {"v": {**HASHICORP, "tls": {"client_cert": "/etc/ssl/both.pem"}}}}
    )

    assert vault.tls is not None
    assert vault.tls.client_cert == "/etc/ssl/both.pem"
    assert vault.tls.client_key is None


def test_a_zero_timeout_is_refused_rather_than_read_as_no_timeout() -> None:
    """What a zero means to most clients is "wait forever", which is the opposite
    of why the key exists -- and the advisory lock is held while we wait."""
    with pytest.raises(ConfigError) as caught:
        build_vaults({"vaults": {"v": {**HASHICORP, "timeout_s": 0}}})

    assert "timeout_s" in str(caught.value)


def test_a_negative_timeout_is_refused() -> None:
    with pytest.raises(ConfigError):
        build_vaults({"vaults": {"v": {**HASHICORP, "timeout_s": -5}}})


@pytest.mark.parametrize("mount", ["kv?x", "kv#x", "kv%2f", "k\\v", "kv\t", "kv/../sys", "./kv"])
def test_a_kv_mount_that_changes_the_url_is_refused(mount: str) -> None:
    """The mount goes into the URL as written, as a path does (#858)."""
    with pytest.raises(ConfigError) as caught:
        only(**{"vault-dev": {**HASHICORP, "mount": mount}})

    assert "vaults.vault-dev.mount" in str(caught.value)


def test_an_auth_mount_that_changes_the_url_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        auth(method="userpass", username="sopuli", password={"env": "PW"}, mount="userpass?x")

    assert "auth.mount" in str(caught.value)

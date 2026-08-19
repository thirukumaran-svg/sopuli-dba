"""Partial ``vaults:`` blocks, and the layers they merge into (C13, #136).

Tier 0, pure: every case is a dict through ``build_config``, because the merge
happens at load and its result is what every later reader of a store sees.

Two properties carry the module, and both are easy to get backwards.

**Direction.** A top-level ``vaults:`` entry is P3's layer 4 and
``defaults.vaults:`` is layer 5, so the declaration *outranks* the block that
"patches" it -- the word reads the other way and is right only for a profile.

**The ratchet.** ``tls.verify`` is the one vault key invariant 10 governs, so it
is the one key where highest-layer-wins is not the rule. The tests below assert
it in both directions, because a merge that happened to be right for one of them
by accident is the failure this is here to catch.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import Vault
from sopuli.settings import SAFETY_SETTINGS, setting

STORE = "vault-prod"


def document(vault: dict[str, Any] | None = None, **sections: Any) -> dict[str, Any]:
    """A file with one declared store, plus whatever a case writes over it."""
    return {
        "version": 1,
        "vaults": {STORE: {"type": "hashicorp", **(vault or {})}},
        **sections,
    }


def merged(vault: dict[str, Any] | None = None, **sections: Any) -> Vault:
    config = build_config(document(vault, **sections))
    assert len(config.vaults) == 1
    return config.vaults[0]


def under_defaults(**patch: Any) -> dict[str, Any]:
    return {"defaults": {"vaults": {STORE: patch}}}


# ------------------------------------------------------------------ direction ---


def test_defaults_supplies_a_key_the_declaration_left_out() -> None:
    """Layer 5 answering where layer 4 said nothing, which is the case the block
    exists for: one address written once, for a store declared in a shared file."""
    vault = merged(**under_defaults(addr="https://vault.example.com"))

    assert vault.addr == "https://vault.example.com"
    assert vault.patched == ("addr",)


def test_the_declaration_outranks_defaults_for_a_key_it_wrote() -> None:
    """The direction most likely to be got wrong. P3 puts `vaults.<name>.addr` at
    layer 4 and `defaults.vaults.<name>.addr` at layer 5, so "patch" is exactly
    backwards here -- `defaults:` fills gaps, it does not overwrite."""
    vault = merged(
        {"addr": "https://declared.example.com"},
        **under_defaults(addr="https://defaulted.example.com"),
    )

    assert vault.addr == "https://declared.example.com"
    assert vault.patched == ()


def test_a_store_nobody_patched_is_untouched() -> None:
    vault = merged({"addr": "https://vault.example.com", "mount": "secret"})

    assert vault.addr == "https://vault.example.com"
    assert vault.mount == "secret"
    assert vault.patched == ()


def test_every_reach_key_can_be_supplied_by_a_layer() -> None:
    """The patchable set is the complement of the three guardrails, not §5's
    four-key list -- which was written before `namespace`, `timeout_s` and `tls`
    existed (#135)."""
    vault = merged(
        **under_defaults(
            addr="https://vault.example.com",
            mount="secret",
            kv_version=1,
            namespace="team-a",
            timeout_s=45,
        )
    )

    assert (vault.addr, vault.mount, vault.kv_version) == ("https://vault.example.com", "secret", 1)
    assert (vault.namespace, vault.timeout_s) == ("team-a", 45)
    assert vault.patched == ("addr", "kv_version", "mount", "namespace", "timeout_s")


def test_a_patch_is_validated_as_strictly_as_a_declaration() -> None:
    """One reader for both shapes, so a layer cannot write a `timeout_s: 0` that
    the top-level entry is refused."""
    with pytest.raises(ConfigError) as caught:
        merged(**under_defaults(timeout_s=0))

    assert "timeout_s must be at least 1 second" in str(caught.value)


# -------------------------------------------------------------------- refusals ---


def test_a_patch_naming_an_undeclared_store_is_refused() -> None:
    """A patch *names* a store rather than declaring one, which is the whole of
    C13: one `vaults:` name means one thing everywhere, the audit trail
    included. So it is a dangling reference like any other."""
    with pytest.raises(ConfigError) as caught:
        build_config(document(defaults={"vaults": {"vault-prd": {"addr": "https://x"}}}))

    rendered = str(caught.value)
    assert "no vault named 'vault-prd' is declared" in rendered
    assert "defaults.vaults.vault-prd" in rendered


def test_a_renamed_store_leaves_a_patch_that_is_refused_rather_than_ignored() -> None:
    """The failure worth catching: a rename in `vaults:` and not in `defaults:`.
    Silently ignoring the leftover would mean an `auth:` block written for CI
    quietly not applying, and a run authenticating some other way."""
    with pytest.raises(ConfigError):
        build_config(
            {
                "version": 1,
                "vaults": {"vault-prod-eu": {"type": "hashicorp"}},
                "defaults": {"vaults": {STORE: {"mount": "secret"}}},
            }
        )


@pytest.mark.parametrize(
    ("key", "value", "reason"),
    [
        ("type", "oci", "two stores"),
        ("non_production", True, "guardrail"),
        ("locking", "advisory-only", "guardrail"),
    ],
)
@pytest.mark.parametrize("where", ["defaults", "profile"])
def test_the_three_unpatchable_keys_are_refused_in_both_positions(
    key: str, value: Any, reason: str, where: str
) -> None:
    block = {"vaults": {STORE: {key: value}}}
    sections = {"defaults": block} if where == "defaults" else {"profiles": {"ci": block}}

    with pytest.raises(ConfigError) as caught:
        build_config(document(**sections))

    rendered = str(caught.value)
    assert f"`{key}:` cannot be set on a partial `vaults:` entry" in rendered
    assert reason in rendered
    assert f"vaults.{STORE}.{key}" in rendered


def test_the_type_refusal_does_not_claim_the_safety_ratchet() -> None:
    """`type` is not a safety setting, and a message saying it is would send
    somebody looking for a way to relax a ratchet that has nothing to do with
    it. The other two are guardrails and say so."""
    with pytest.raises(ConfigError) as caught:
        build_config(document(defaults={"vaults": {STORE: {"type": "oci"}}}))

    assert "invariant 10" not in str(caught.value)


def test_an_unknown_key_in_a_patch_lists_only_the_patchable_ones() -> None:
    with pytest.raises(ConfigError) as caught:
        merged(**under_defaults(nope=1))

    rendered = str(caught.value)
    assert "unknown key 'nope'" in rendered
    for absent in ("type", "non_production", "locking"):
        assert f" {absent}," not in rendered


# --------------------------------------------------------------------- the tls ---


def test_tls_merges_key_by_key_rather_than_whole() -> None:
    """A layer mentioning only `server_name` must not drop the CA the
    declaration wrote -- and, more to the point, must not drop a `verify` it
    never spoke about."""
    vault = merged(
        {"tls": {"ca_file": "/etc/ssl/own.pem"}},
        **under_defaults(tls={"server_name": "vault.example.com"}),
    )

    assert vault.tls is not None
    assert vault.tls.ca_file == "/etc/ssl/own.pem"
    assert vault.tls.server_name == "vault.example.com"


def test_no_layer_writing_tls_leaves_no_block_at_all() -> None:
    """ "No block" and "an empty block" stay distinguishable, the same way a
    missing `verify` and a written one do."""
    assert merged(**under_defaults(addr="https://vault.example.com")).tls is None


def test_verify_ratchets_when_the_higher_layer_asks_for_less() -> None:
    """The declaration is layer 4 and outranks `defaults:` for every other key.
    Not this one: invariant 10 says a safety setting cannot be relaxed by a
    higher-precedence source, so the `true` wins from below."""
    config = build_config(
        document({"tls": {"verify": False}}, **under_defaults(tls={"verify": True}))
    )
    vault = config.vaults[0]

    assert vault.tls is not None
    assert vault.tls.verify is True
    assert vault.tls.verified


def test_verify_ratchets_when_the_lower_layer_asks_for_less() -> None:
    """The same rule read the other way, and the direction a plain
    highest-layer-wins merge would get right by accident. Both are asserted so
    that neither can pass for the wrong reason."""
    vault = merged({"tls": {"verify": True}}, **under_defaults(tls={"verify": False}))

    assert vault.tls is not None
    assert vault.tls.verify is True


def test_a_defeated_relaxation_is_reported_rather_than_swallowed() -> None:
    """Something was asked for and safely refused, and the run continues --
    which is exactly the case that is invisible without being said out loud."""
    config = build_config(
        document({"tls": {"verify": False}}, **under_defaults(tls={"verify": True}))
    )

    notes = [str(warning) for warning in config.warnings if "ratchet" in str(warning)]
    assert len(notes) == 1
    assert "vaults.vault-prod.tls.verify" in notes[0]
    assert "defaults.vaults.vault-prod.tls.verify" in notes[0]
    assert "invariant 10" in notes[0]


def test_verify_false_still_reaches_the_transport_when_nothing_contradicts_it() -> None:
    """A ratchet is not a ban. One layer asking for `false` and no layer asking
    for `true` resolves to `false` -- with §10's own warning, which is the
    reviewed, deliberate path the key exists for."""
    vault = merged({"tls": {"verify": False}}, **under_defaults(mount="secret"))

    assert vault.tls is not None
    assert vault.tls.verified is False


def test_the_unverified_transport_warning_reads_the_effective_value() -> None:
    """§10's warning runs after the merge, so a `defaults:` block turning
    verification off is a `defaults:` block that warns."""
    config = build_config(document(**under_defaults(tls={"verify": False})))

    assert any(warning.code == "SOPULI-W004" for warning in config.warnings)


# -------------------------------------------------------------------- the auth ---


def test_auth_is_replaced_whole_rather_than_merged() -> None:
    """A key-by-key merge would produce credentials nobody wrote: `method:
    approle` carrying a leftover `token:` authenticates as nobody."""
    vault = merged(
        {"auth": {"method": "token", "token": {"env": "VAULT_TOKEN"}}},
        **under_defaults(
            auth={
                "method": "approle",
                "role_id": {"env": "SOPULI_VAULT_ROLE_ID"},
                "secret_id": {"env": "SOPULI_VAULT_SECRET_ID"},
            }
        ),
    )

    assert vault.auth is not None
    assert vault.auth.method == "approle"
    assert vault.auth.token is None
    assert "auth" in vault.patched


def test_a_layer_that_writes_no_auth_leaves_the_declaration_s_alone() -> None:
    vault = merged({"auth": "token"}, **under_defaults(mount="secret"))

    assert vault.auth is not None
    assert vault.auth.method == "token"
    assert "auth" not in vault.patched


# ------------------------------------------------------------------- a profile ---


def test_a_profile_s_block_is_parsed_and_kept() -> None:
    """Validated now, applied when something selects a profile (#153). The
    refusals are the half that is useful without activation."""
    config = build_config(
        document(profiles={"ci": {"vaults": {STORE: {"addr": "https://ci.example.com"}}}})
    )

    assert len(config.profiles) == 1
    assert config.profiles[0].vaults[0].name == STORE
    assert config.profiles[0].vaults[0].addr == "https://ci.example.com"


def test_a_profile_s_block_does_not_reach_the_store_yet() -> None:
    """Asserted rather than assumed. Nothing activates a profile, so applying a
    profile's patch would mean applying it to every run -- which is the opposite
    of what a profile is (§5). When #153 lands this test changes to say that the
    *active* profile's block applies."""
    config = build_config(
        document(
            {"addr": "https://declared.example.com"},
            profiles={"ci": {"vaults": {STORE: {"addr": "https://ci.example.com"}}}},
        )
    )

    assert config.vaults[0].addr == "https://declared.example.com"
    assert config.vaults[0].patched == ()


# -------------------------------------------------------------- the registry ---


def test_the_ratcheted_vault_key_is_declared_where_a_reviewer_looks() -> None:
    """The registry's `SAFETY_SETTINGS` is authoritative by design, so the one
    vault key invariant 10 governs has to be *in* it -- which is also what puts
    it inside the generic invariant test in `tests/settings/test_ratchet.py`
    without anyone writing a case for it."""
    assert "vaults.*.tls.verify" in SAFETY_SETTINGS
    assert setting("vaults.*.tls.verify").type is bool
    assert setting("vaults.*.tls.verify").safe_bool is True


def test_the_other_vault_keys_are_not_ratcheted() -> None:
    """An address has no safe direction, and declaring one ratcheted would make
    the ratcheted set unreadable as the thing invariant 10 governs."""
    for name in ("vaults.*.addr", "vaults.*.mount", "vaults.*.kv_version"):
        assert name not in SAFETY_SETTINGS


def test_no_guardrail_has_a_setting_to_be_supplied_through() -> None:
    """`type`, `non_production` and `locking` are refused at parse time, and
    there is deliberately no registry entry for them either -- an entry would
    advertise a merge for a key no layer may write."""
    from sopuli.settings import SETTINGS

    for absent in ("type", "non_production", "locking"):
        assert f"vaults.*.{absent}" not in SETTINGS

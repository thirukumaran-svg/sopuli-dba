"""Building the ``vaults:`` section (§2).

A vault entry says which secret store a target's passwords are mastered in. It
deliberately says very little else: P2 puts vaults behind a store interface, and
the backends differ enough -- a file backend has no address, KV v1 has no
versioning -- that demanding a HashiCorp shape of every entry would be the
top-level vendor bias P1 forbids. So ``type`` is required and the rest is
optional, with per-backend requirements left to the store that reads them.

**Where this layer refuses rather than guesses.** ``auth:`` carries a ``method``
and nothing else. P2 names the methods, so the closed set is grounded in the
reference; P2 does *not* name the keys that point at the material, only that
"auth material is never written to the config file in plaintext; the config
points at *where* the material comes from". Inventing ``role_id:`` here would
fix a schema the vault layer then has to live with, so an unrecognised key inside
``auth:`` is an error pointing at issue #27. Nothing consumes those fields yet.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.fields import (
    choice,
    mapping,
    optional_bool,
    optional_int,
    optional_string,
    reject_unknown_keys,
    required_string,
)
from sopuli.config.model import Vault, VaultAuth

VAULT_KEYS = ("type", "addr", "mount", "kv_version", "auth", "non_production")

#: The backends P2 puts in scope. `aws`/`azure` are listed there as "later" and
#: are absent on purpose: a config that declares a store the tool cannot reach
#: should fail while it is being written, not at the first rotation.
VAULT_TYPES = ("hashicorp", "oci", "file", "keyring")

AUTH_KEYS = ("method",)

#: The methods P2 names, HashiCorp's first and OCI's after. Which of them a given
#: backend actually supports is the store's business, not this layer's -- pairing
#: them here would hard-code a matrix P2 does not state.
AUTH_METHODS = (
    "token",
    "approle",
    "kubernetes",
    "oidc",
    "userpass",
    "instance_principal",
    "resource_principal",
    "config_file",
    "session_token",
)

#: KV v1 and v2 are separate backends with different capabilities (P2), so this
#: is not a version number the tool may branch on casually -- but it is written
#: in the file, and 3 is a typo rather than a future.
KV_VERSIONS = (1, 2)

_UNSPECIFIED_AUTH = (
    "P2 says the config points at *where* auth material comes from, but the keys "
    "that do so are not specified yet -- see issue #27"
)


def build_vaults(document: dict[str, Any]) -> tuple[Vault, ...]:
    """Read ``vaults:`` into entries, in document order."""
    if "vaults" not in document:
        return ()

    at = ROOT.key("vaults")
    entries = mapping(document["vaults"], at=at)
    return tuple(_build_vault(name, entry, at=at.key(name)) for name, entry in entries.items())


def _build_vault(name: str, raw: Any, *, at: KeyPath) -> Vault:
    entry = mapping(raw, at=at)
    reject_unknown_keys(entry, allowed=VAULT_KEYS, at=at)

    return Vault(
        name=name,
        type=choice(
            required_string(entry, "type", at=at, hint=f"one of: {', '.join(VAULT_TYPES)}"),
            allowed=VAULT_TYPES,
            at=at.key("type"),
            noun="vault type",
        ),
        addr=optional_string(entry, "addr", at=at),
        mount=optional_string(entry, "mount", at=at),
        kv_version=_build_kv_version(entry, at=at),
        auth=_build_auth(entry.get("auth"), at=at.key("auth")),
        # Absent means production. §9 refuses a prod target pointed at a
        # non-production store, and defaulting the other way would make that
        # rule fire on every vault nobody has labelled yet.
        non_production=optional_bool(entry, "non_production", at=at) or False,
    )


def _build_kv_version(entry: dict[str, Any], *, at: KeyPath) -> int | None:
    version = optional_int(entry, "kv_version", at=at)
    if version is not None and version not in KV_VERSIONS:
        raise ConfigError(
            f"unsupported kv_version {version}",
            at=at.key("kv_version"),
            hint=f"known: {', '.join(str(candidate) for candidate in KV_VERSIONS)}",
        )
    return version


def _build_auth(raw: Any, *, at: KeyPath) -> VaultAuth | None:
    if raw is None:
        return None
    auth = mapping(raw, at=at)
    reject_unknown_keys(
        auth,
        allowed=AUTH_KEYS,
        at=at,
        hint=f"only `method:` is recognised here -- {_UNSPECIFIED_AUTH}",
    )
    if "method" not in auth:
        raise ConfigError("must name an auth method", at=at.key("method"), hint=_UNSPECIFIED_AUTH)
    return VaultAuth(
        method=choice(auth["method"], allowed=AUTH_METHODS, at=at.key("method"), noun="auth method")
    )

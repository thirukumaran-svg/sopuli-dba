"""Building the ``vaults:`` section (§2).

A vault entry says which secret store a target's passwords are mastered in. It
deliberately says very little else: P2 puts vaults behind a store interface, and
the backends differ enough -- a file backend has no address, KV v1 has no
versioning -- that demanding a HashiCorp shape of every entry would be the
top-level vendor bias P1 forbids. So ``type`` is required and the rest is
optional, with per-backend requirements left to the store that reads them.

``auth:`` says *how* to authenticate and where the material comes from, never
what it is: every secret-bearing key is a :class:`~sopuli.config.model.MaterialRef`
naming an environment variable or a file, so P2's "auth material is never written
to the config file in plaintext" holds by shape rather than by a rule somebody
has to remember. The grammar is in :mod:`sopuli.config.auth`; what is here is the
Oracle-free part of it -- which methods exist, and what each one takes.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.auth import Method, read_material_key, read_method
from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.fields import (
    choice,
    describe,
    mapping,
    optional_bool,
    optional_int,
    optional_string,
    reject_unknown_keys,
    required_string,
)
from sopuli.config.locking import build_lock_mode
from sopuli.config.model import Vault, VaultAuth

VAULT_KEYS = ("type", "addr", "mount", "kv_version", "auth", "non_production", "locking")

#: The backends P2 puts in scope. `aws`/`azure` are listed there as "later" and
#: are absent on purpose: a config that declares a store the tool cannot reach
#: should fail while it is being written, not at the first rotation.
VAULT_TYPES = ("hashicorp", "oci", "file", "keyring")

#: P2's ``staging_labels`` row, by store type: whether the three stages of UC-1
#: §3 are the store's own or emulated in the payload's fields.
#:
#: The distinction decides whether a ref needs a field at all. Where staging is
#: **native**, ``current``/``pending``/``previous`` are versions of the secret,
#: so a ref naming a whole secret stages perfectly well and a field called
#: ``pending`` is just a field. Where it is **emulated**, they are keys beside
#: the container (``sopuli/payload.py``), so a whole-secret ref has nowhere to
#: put them and a container named after one of them collides with it.
#:
#: ``keyring`` is deliberately absent rather than assumed emulated. P2's
#: capability table does not have a row for it, it has no store adapter, and
#: deciding what a single-string-per-entry backend does about staging is P2's
#: call and not a validation function's. Absent means the check that reads this
#: does not fire, which is the reversible direction.
STAGING_NATIVE = "native"
STAGING_EMULATED = "emulated"
STAGING_LABELS = {
    "hashicorp": STAGING_EMULATED,
    "oci": STAGING_NATIVE,
    "file": STAGING_EMULATED,
}

#: The methods P2 names, HashiCorp's first and OCI's after, each with the keys it
#: takes. Which of them a given backend actually supports is the store's business,
#: not this layer's -- pairing them here would hard-code a matrix P2 does not
#: state.
#:
#: Anything with no *required* key may be written as a bare ``auth: NAME``, which
#: includes ``token``: its ``token:`` is optional because P2 already documents a
#: source chain -- ``--vault-token``, ``$VAULT_TOKEN``, ``~/.vault-token``. That
#: chain stays within the method. An earlier draft fell through to AppRole after
#: it, and a fall-through into a *different* method makes an authentication
#: failure impossible to explain.
#:
#: ``mount`` is the auth mount rather than the KV mount on the vault itself, and
#: is optional everywhere it appears -- it defaults to the method's own name, which
#: is the convention every backend here uses.
AUTH_METHODS: dict[str, Method] = {
    "token": Method(optional=("token",)),
    "approle": Method(required=("role_id", "secret_id"), optional=("mount",)),
    "kubernetes": Method(required=("role", "jwt"), optional=("mount",)),
    "oidc": Method(optional=("mount", "role")),
    "userpass": Method(required=("username", "password"), optional=("mount",)),
    "instance_principal": Method(),
    "resource_principal": Method(),
    "config_file": Method(optional=("profile",)),
    "session_token": Method(optional=("profile",)),
}

#: Every key any method may write, for the published schema and for nothing else.
#: Validation is per method: a key here is only accepted beside the method that
#: uses it. Derived rather than written out, so a key cannot reach a method without
#: reaching the schema -- which is why this one list is alphabetical where the rest
#: of the config layer keeps the reference's own order.
AUTH_KEYS = ("method", *sorted({key for spec in AUTH_METHODS.values() for key in spec.keys}))

#: The keys that name *who* rather than prove it, and are therefore written inline.
#: A closed list, because material is the default and inline is the exception --
#: which is P2's rule as code: a key added to a method is a MaterialRef unless
#: somebody says here that it is not.
AUTH_IDENTITY_KEYS = ("mount", "role", "username", "profile")

#: Everything else a method may write, which is everything secret-bearing.
#: ``role_id`` is here even though it is arguably an identifier: carving out one
#: field that may be inline sets a precedent to re-litigate for every method added
#: later.
AUTH_MATERIAL_KEYS = tuple(
    key for key in AUTH_KEYS if key != "method" and key not in AUTH_IDENTITY_KEYS
)

#: KV v1 and v2 are separate backends with different capabilities (P2), so this
#: is not a version number the tool may branch on casually -- but it is written
#: in the file, and 3 is a typo rather than a future.
KV_VERSIONS = (1, 2)


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
        # Absent means production. §10 refuses a prod target pointed at a
        # non-production store, and defaulting the other way would make that
        # rule fire on every vault nobody has labelled yet.
        non_production=optional_bool(entry, "non_production", at=at) or False,
        # Absent means `required`, which is the whole point of the default: a
        # store gets a real lock unless somebody wrote down that it cannot have
        # one (#83).
        locking=build_lock_mode(entry, at=at),
    )


def _shape(key: str) -> str:
    """How one `auth:` key is written, for the error about a missing one (#70).

    The distinction P2 draws, in the one place a reader needs it: material is
    *named* and identity is *written*. Answered per key because a method can
    require both -- `kubernetes` needs a `role` and a `jwt`.
    """
    if key in AUTH_MATERIAL_KEYS:
        return "named, not written -- `{ env: NAME }` or `{ file: PATH }`"
    return "written inline"


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
    """``auth:`` -- the method, its identity fields, and where its material lives.

    The identity fields are read inline and the material fields are not, which is
    the whole of P2's constraint expressed as code: there is no path through here
    that reads a credential out of the config file, because
    :func:`~sopuli.config.auth.read_material` has nowhere to read one from.
    """
    if raw is None:
        return None

    method, auth = read_method(raw, at=at, methods=AUTH_METHODS, noun="auth method", shape=_shape)
    return VaultAuth(
        method=method,
        mount=optional_string(auth, "mount", at=at),
        role=optional_string(auth, "role", at=at),
        username=optional_string(auth, "username", at=at),
        profile=optional_string(auth, "profile", at=at),
        token=read_material_key(auth, "token", at=at),
        role_id=read_material_key(auth, "role_id", at=at),
        secret_id=read_material_key(auth, "secret_id", at=at),
        jwt=read_material_key(auth, "jwt", at=at),
        password=read_material_key(auth, "password", at=at),
    )


#: `vault:` is the *name* of a store in every position it appears -- `defaults:`,
#: a profile, `targets[]`, `applications[]`, an `overrides:` patch, and a
#: SecretRef's `[<vault>:]` prefix -- and is never a block. `SOPULI_VAULT`
#: overrides that name.
#:
#: Settings *of* a store are reached by naming it under `vaults:`, which
#: `defaults:` and a profile may each carry as partial entries patching a
#: top-level declaration. That is C13, decided in #31, and it is §6's
#: `SOPULI_VAULT` / `SOPULI_VAULT__VAULT_DEV__ADDR` pair written in the file
#: rather than a second addressing scheme. Parsing those blocks arrives with the
#: vault layer (#103); until then the closed whitelists refuse them, so the only
#: block form reachable here is a mapping written directly under `vault:`.
VAULT_IS_A_NAME = (
    "`vault:` is a store name everywhere in this file (see `SOPULI_VAULT`); "
    "settings of a store go under `vaults:` keyed by its name, which `defaults:` "
    "and a profile may each carry. See C13, decided in #31"
)


def vault_name(container: dict[str, Any], *, at: KeyPath) -> str | None:
    """Read a ``vault:`` that names a store, refusing the block form."""
    if "vault" not in container:
        return None
    if isinstance(container["vault"], dict):
        raise ConfigError(
            f"`vault:` here is a store name, not {describe(container['vault'])}",
            at=at.key("vault"),
            hint=VAULT_IS_A_NAME,
        )
    return optional_string(container, "vault", at=at)

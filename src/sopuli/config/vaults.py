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
from sopuli.config.model import Vault, VaultAuth, VaultPatch, VaultTls

VAULT_KEYS = (
    "type",
    "addr",
    "mount",
    "kv_version",
    "namespace",
    "timeout_s",
    "tls",
    "auth",
    "non_production",
    "locking",
)

#: ``tls:`` (ADR-005). Four paths, a host name and a boolean. The boolean is the one
#: that is not ordinary config -- see :class:`~sopuli.config.model.VaultTls`.
TLS_KEYS = ("ca_file", "ca_path", "client_cert", "client_key", "server_name", "verify")

#: The three keys a partial entry may **not** carry (C13, §5), each with why.
#:
#: The reasons differ and the messages say so, because the remedies differ. Two
#: are invariant 10 -- a guardrail must not be reachable from the invocation
#: context -- and one is not a safety setting at all, so its message must not
#: claim the ratchet. Somebody told "the safety ratchet forbids it" about ``type``
#: would go looking for a way to relax a ratchet, and there is nothing there.
UNPATCHABLE_KEYS = {
    "type": (
        "a store that is HashiCorp from a laptop and OCI from CI is two stores; "
        "declare the second one under `vaults:` and name it"
    ),
    "non_production": (
        "it is a guardrail -- §10 checks it against a `prod` target -- and invariant 10 "
        "keeps a guardrail out of the invocation context"
    ),
    "locking": (
        "it is a guardrail -- `advisory-only` concedes that a store cannot hold P5's "
        "lock -- and invariant 10 keeps a guardrail out of the invocation context"
    ),
}

#: What a partial entry may carry: the complement, never a second list.
#:
#: Deriving it means a key added to :data:`VAULT_KEYS` becomes patchable unless
#: somebody writes down why it is not, which is the direction that fails safe for
#: readers of the file and loudly for whoever adds a guardrail.
PATCHABLE_KEYS = tuple(key for key in VAULT_KEYS if key not in UNPATCHABLE_KEYS)

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
#: source chain -- ``--vault-token-file``, ``$VAULT_TOKEN``, ``~/.vault-token``. That
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
        # Absent means production. §10 refuses a prod target pointed at a
        # non-production store, and defaulting the other way would make that
        # rule fire on every vault nobody has labelled yet.
        non_production=optional_bool(entry, "non_production", at=at) or False,
        # Absent means `required`, which is the whole point of the default: a
        # store gets a real lock unless somebody wrote down that it cannot have
        # one.
        locking=build_lock_mode(entry, at=at),
        **_reach(entry, at=at),
    )


def build_vault_patches(container: dict[str, Any], *, at: KeyPath) -> tuple[VaultPatch, ...]:
    """A ``vaults:`` block under ``defaults:`` or in a profile (C13).

    Partial entries: every key optional, and ``type`` not accepted at all --
    because there is nothing here to declare. The store is declared once, at the
    top level, and this says something *about* it. A name that matches no
    declaration is refused where every other dangling name in the file is
    (:mod:`sopuli.config.references`), so the message and the exit code are the
    ones a reader already knows.

    What a layer may say is :data:`PATCHABLE_KEYS`, and the three it may not each
    get their own refusal rather than an unknown-key message: a whitelist reply
    would send somebody looking for the right spelling of a key that must not
    exist here, which is the same defect :func:`sopuli.config.profiles._reject_forbidden_keys`
    avoids for ``targets:``.
    """
    if "vaults" not in container:
        return ()
    entries = mapping(container["vaults"], at=at.key("vaults"))
    return tuple(
        _build_patch(name, entry, at=at.key("vaults").key(name)) for name, entry in entries.items()
    )


def _build_patch(name: str, raw: Any, *, at: KeyPath) -> VaultPatch:
    entry = mapping(raw, at=at)
    _reject_unpatchable_keys(entry, at=at)
    reject_unknown_keys(entry, allowed=PATCHABLE_KEYS, at=at)
    return VaultPatch(name=name, **_reach(entry, at=at))


def _reject_unpatchable_keys(entry: dict[str, Any], *, at: KeyPath) -> None:
    """The three keys of :data:`UNPATCHABLE_KEYS`, refused before the whitelist.

    Order matters for the message and not for the outcome, exactly as it does in
    a profile's blocklist: "unknown key `locking`" beside a list of the known ones
    reads as a typo in a key that is spelled perfectly correctly.
    """
    for key in sorted(entry):
        if key in UNPATCHABLE_KEYS:
            raise ConfigError(
                f"`{key}:` cannot be set on a partial `vaults:` entry",
                at=at.key(key),
                hint=f"{UNPATCHABLE_KEYS[key]} (§5, C13)",
            )


def _reach(entry: dict[str, Any], *, at: KeyPath) -> dict[str, Any]:
    """The keys that say how to *reach* a store, read the same way in both shapes.

    One reader for a declaration and for a patch, so a key cannot be validated
    strictly in one and loosely in the other -- which would let a profile write a
    ``timeout_s: 0`` the top-level entry is refused.
    """
    return {
        "addr": optional_string(entry, "addr", at=at),
        "mount": optional_string(entry, "mount", at=at),
        "kv_version": _build_kv_version(entry, at=at),
        "namespace": optional_string(entry, "namespace", at=at),
        "timeout_s": _build_timeout(entry, at=at),
        "tls": _build_tls(entry.get("tls"), at=at.key("tls")),
        "auth": _build_auth(entry.get("auth"), at=at.key("auth")),
    }


def _shape(key: str) -> str:
    """How one `auth:` key is written, for the error about a missing one.

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


def _build_timeout(entry: dict[str, Any], *, at: KeyPath) -> int | None:
    """``timeout_s`` -- seconds, and never zero.

    Refused rather than read as "no timeout", which is what a zero would mean to
    most clients and is the opposite of why the key exists: ADR-005 picked
    ``httpx`` for its explicit deadlines, and the lock is held while we work. An
    operator who genuinely wants no deadline can leave the key out, and gets the
    backend's own default instead of a promise the config file did not make.
    """
    timeout = optional_int(entry, "timeout_s", at=at)
    if timeout is not None and timeout < 1:
        raise ConfigError(
            f"timeout_s must be at least 1 second, not {timeout}",
            at=at.key("timeout_s"),
            hint="leave it out for the backend's own default; 0 is not 'no timeout' here",
        )
    return timeout


def _build_tls(raw: Any, *, at: KeyPath) -> VaultTls | None:
    """``tls:`` -- what verifies the transport, and what identifies us to it.

    None of these is a MaterialRef, and §3a says why: a CA bundle and a server
    name are not credentials, and ``client_key`` names a path rather than holding
    a key.
    """
    if raw is None:
        return None

    entry = mapping(raw, at=at)
    reject_unknown_keys(entry, allowed=TLS_KEYS, at=at)

    tls = VaultTls(
        ca_file=optional_string(entry, "ca_file", at=at),
        ca_path=optional_string(entry, "ca_path", at=at),
        client_cert=optional_string(entry, "client_cert", at=at),
        client_key=optional_string(entry, "client_key", at=at),
        server_name=optional_string(entry, "server_name", at=at),
        # Stays None when unwritten. `VaultTls.verified` is the effective value;
        # the distinction is for the ratchet over C13's partial blocks, which has
        # to tell "nobody said" from "somebody agreed".
        verify=optional_bool(entry, "verify", at=at),
    )

    if tls.client_key is not None and tls.client_cert is None:
        # One direction only. A `client_cert` alone is a perfectly ordinary
        # combined PEM holding both halves, which is why the reverse is not an
        # error -- but a key with no certificate cannot present anything, so it
        # is an edit that stopped halfway rather than a shape anyone meant.
        raise ConfigError(
            "`client_key` needs a `client_cert` beside it",
            at=at.key("client_key"),
            hint=(
                "a client certificate may be written alone when the file holds both "
                "halves; a key alone presents nothing"
            ),
        )
    return tls


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
#: top-level declaration (:func:`build_vault_patches`). That is C13, and it is
#: §6's `SOPULI_VAULT` / `SOPULI_VAULT__VAULT_DEV__ADDR` pair written in the
#: file rather than a second addressing scheme. So the block form this refuses is
#: specifically a mapping written directly under `vault:`, which is the shape
#: that would name no store at all.
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

"""Building the ``targets:`` section, and the target shape ``target_sets:`` reuses.

A target is one database endpoint: what to connect to, as what, in which
container, and which vault masters the passwords there. :func:`read_target` is
the shared reader, because a target set generates exactly this object -- a set's
template *is* a :class:`~sopuli.config.model.Target` with ``{placeholder}``
tokens still in it. Keeping one reader is what stops the two drifting: a field
added to explicit targets but not to generated ones would mean a target set
silently cannot express something the estate can.

Three values are read from closed sets -- ``type``, ``oracle.scope`` and
``admin.auth.method``. A free string there loads happily and then connects
somewhere other than where the author meant, and this file is the whitelist
(invariant 5). Where the reference has not named the vocabulary, the set holds
only what it *has* named and the error says so; see issue #27.

``admin:`` says which of P2's bootstrap sources reaches the database, in the same
grammar as a vault's ``auth:`` (:mod:`sopuli.config.auth`) and with a different
vocabulary. There is no password field and there will not be one: P2 says storing
the admin password in the config file is "not supported at all", so the file names
a wallet, a vault ref, a prompt, or a variable.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.auth import Method, read_method
from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.fields import (
    choice,
    mapping,
    optional_string,
    pairs,
    reject_unknown_keys,
    required_string,
    sequence,
)
from sopuli.config.model import AdminAuth, AdminCredential, Target, TargetOracle
from sopuli.config.safety import build_safety
from sopuli.config.secret_refs import parse_secret_ref

TARGET_KEYS = (
    "name",
    "type",
    "dsn",
    "environment",
    "vault",
    "admin",
    "oracle",
    "labels",
    "safety",
)

#: The driver selector (P1). Only Oracle is implemented, and D6 keeps drivers
#: in-tree until there is a second one, so `type: postgresql` names a driver that
#: does not exist. Refusing it here is invariant 4 applied to config: a target the
#: tool cannot drive should fail while the file is being written, not at the
#: first connection.
TARGET_TYPES = ("oracle",)

ADMIN_KEYS = ("username", "auth")

#: P2's bootstrap sources, in its order of preference, each with the keys it takes.
#: Two are parameterless and so may be written as a bare `auth: prompt`, which is
#: the form §2 and §4 already use.
#:
#: `vault` requires its ref: there is no default path to fall back on, and a
#: credential tool guessing at one is how a run authenticates as something nobody
#: chose. `env` does not, because §6 already names a variable
#: (:data:`ADMIN_PASSWORD_ENV`) for the single-credential case.
#: The source that constrains the rest of the target -- a wallet decides both who
#: connects and how, so §10 has two rules about the keys beside it, enforced in
#: :mod:`sopuli.config.references` once the estate is expanded.
EXTERNAL = "external"

ADMIN_METHODS: dict[str, Method] = {
    EXTERNAL: Method(),
    "vault": Method(required=("secret",)),
    "prompt": Method(),
    "env": Method(optional=("password_env",)),
}

ADMIN_AUTH_KEYS = ("method", *sorted({key for spec in ADMIN_METHODS.values() for key in spec.keys}))

#: §6's variable, and the default for `method: env` when `password_env:` is not
#: given. Named here rather than resolved into the model: an unset value has to
#: stay distinguishable from a written one for `config show --explain` to
#: attribute it (P3).
ADMIN_PASSWORD_ENV = "SOPULI_DB_ADMIN_PASSWORD"

ORACLE_KEYS = ("scope", "container")

#: Every scope P1 names, spelled the way `sopuli-run-1.7.schema.json` already
#: spells them: the run document has typed `scope.type` since it was written, so
#: adopting that vocabulary means the word a file *asserts* and the word the tool
#: *reports* are the same word, and a mismatch needs no translation to explain.
#:
#: `unknown` is deliberately absent. It is observation-only -- something the driver
#: may find, never something a file can claim.
ORACLE_SCOPES = ("non_cdb", "cdb_root", "pdb", "app_root", "app_pdb")


def build_targets(document: dict[str, Any]) -> tuple[Target, ...]:
    """Read ``targets:`` -- the explicitly listed endpoints (§2)."""
    if "targets" not in document:
        return ()

    at = ROOT.key("targets")
    entries = sequence(document["targets"], at=at)
    targets = []
    for index, raw in enumerate(entries):
        entry = mapping(raw, at=at.index(index))
        reject_unknown_keys(entry, allowed=TARGET_KEYS, at=at.index(index))
        targets.append(read_target(entry, at=at.index(index)))

    _reject_duplicate_names(targets, at=at)
    return tuple(targets)


def read_target(entry: dict[str, Any], *, at: KeyPath) -> Target:
    """Read the target-shaped fields out of an already-checked mapping.

    The caller rejects unknown keys, because a target set allows two more of them
    (``for_each``, ``overrides``) and the rejection has to know which set it is
    working from.
    """
    return Target(
        name=required_string(entry, "name", at=at, hint="targets are selected by name"),
        type=choice(
            required_string(entry, "type", at=at, hint=f"one of: {', '.join(TARGET_TYPES)}"),
            allowed=TARGET_TYPES,
            at=at.key("type"),
            noun="target type",
        ),
        dsn=required_string(entry, "dsn", at=at, hint="host:port/service, or a TNS alias"),
        environment=optional_string(entry, "environment", at=at),
        vault=optional_string(entry, "vault", at=at),
        admin=read_admin(entry.get("admin"), at=at.key("admin")),
        oracle=read_oracle(entry.get("oracle"), at=at.key("oracle")),
        labels=() if "labels" not in entry else pairs(entry["labels"], at=at.key("labels")),
        safety=build_safety(entry.get("safety"), at=at.key("safety")),
    )


def read_admin(raw: Any, *, at: KeyPath) -> AdminCredential | None:
    """``admin:`` -- which credential reaches the database, never the password.

    P2 is explicit that storing the admin password in the config file is not
    supported at all, so a ``password:`` here is an unknown key rather than a
    rejected value: there is no field for it to be rejected from.
    """
    if raw is None:
        return None
    admin = mapping(raw, at=at)
    reject_unknown_keys(
        admin,
        allowed=ADMIN_KEYS,
        at=at,
        hint=(
            "known keys here: auth, username -- the password is never written in this "
            "file (P2); `auth:` says where it comes from"
        ),
    )
    _reject_empty(admin, at=at, block_name="admin")

    return AdminCredential(
        username=optional_string(admin, "username", at=at),
        auth=read_admin_auth(admin.get("auth"), at=at.key("auth")),
    )


def read_admin_auth(raw: Any, *, at: KeyPath) -> AdminAuth | None:
    """``admin.auth`` -- one of P2's four sources, and what it needs to say.

    ``method: vault`` carries a whole SecretRef rather than a field of its own:
    the ref grammar already has a vault prefix and §7's tokens, and a second,
    smaller addressing syntax for one credential would be a parser that disagrees
    with the first one somewhere nobody looks.
    """
    if raw is None:
        return None

    method, auth = read_method(
        raw, at=at, methods=ADMIN_METHODS, noun="admin auth method", shape=_shape
    )
    ref = optional_string(auth, "secret", at=at)
    return AdminAuth(
        method=method,
        secret=None if ref is None else parse_secret_ref(ref, at=at.key("secret")),
        password_env=optional_string(auth, "password_env", at=at),
    )


def _shape(key: str) -> str:
    """How one `admin.auth` key is written, for the error about a missing one (#70).

    Only `method: vault` requires anything, and what it requires is a whole
    SecretRef -- which is the answer somebody staring at "needs `secret`" wants,
    since the alternative readings are a bare password (never) and a field of this
    block's own invention (there is none).
    """
    if key == "secret":
        return "a SecretRef -- `[vault:]path#field`, in the target's vault by default (§7)"
    return "written inline"  # pragma: no cover - no other admin key is required


def read_oracle(raw: Any, *, at: KeyPath) -> TargetOracle:
    """``oracle:`` on a target -- which container to operate in.

    Not the application's ``oracle:`` block, which carries ``container_clause``.
    Same key name, different meaning; see :class:`~sopuli.config.model.TargetOracle`.

    Both keys are optional, and **neither constrains the other here**. ``scope``
    and ``container`` are *assertions* about the database rather than settings on
    it: the driver detects the real ones on connect (P1 ``resolve_scope``), and a
    declared value that disagrees with what it finds is an error naming both. That
    catches a DSN edit that silently repointed a target, or a PDB whose role
    changed -- neither of which any load-time rule about these two keys could see.

    So ``scope: pdb`` without a ``container`` is legal unless something actually
    needs the value, and the thing that needs it is §7's ``{container}`` token --
    where §4 rule 4 already makes an unresolved placeholder an error, for a reason
    about the template rather than about the connection. ``scope: cdb_root`` with
    ``container: CDB$ROOT`` is redundant but not contradictory, so the comparison
    on connect decides it rather than the schema.
    """
    if raw is None:
        return TargetOracle()
    options = mapping(raw, at=at)
    reject_unknown_keys(options, allowed=ORACLE_KEYS, at=at)
    _reject_empty(options, at=at, block_name="oracle")

    scope = options.get("scope")
    return TargetOracle(
        scope=(
            None
            if scope is None
            else choice(scope, allowed=ORACLE_SCOPES, at=at.key("scope"), noun="Oracle scope")
        ),
        container=optional_string(options, "container", at=at),
    )


def _reject_empty(block: dict[str, Any], *, at: KeyPath, block_name: str) -> None:
    """A block that is present and says nothing is a half-finished edit.

    The same reading as ``policy: ""`` naming no policy, and as an override that
    patches nothing: absent and empty mean the same thing to the tool, so the
    difference between them is a sentence somebody started and did not finish.
    Reporting it costs one error; hiding it costs a target that turns out not to
    be configured the way the file appears to say.
    """
    if block:
        return
    raise ConfigError(
        f"an empty `{block_name}:` block says nothing",
        at=at,
        hint=f"omit `{block_name}:` entirely, or give it the keys that differ",
    )


def _reject_duplicate_names(targets: list[Target], *, at: KeyPath) -> None:
    """Two targets with one name make `--target` ambiguous, and the second would
    shadow the first everywhere a name is looked up."""
    seen: dict[str, int] = {}
    for index, target in enumerate(targets):
        if target.name in seen:
            raise ConfigError(
                f"duplicate target name {target.name!r}",
                at=at.index(index).key("name"),
                hint=f"already declared at index {seen[target.name]}",
            )
        seen[target.name] = index

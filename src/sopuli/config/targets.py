"""Building the ``targets:`` section, and the target shape ``target_sets:`` reuses.

A target is one database endpoint: what to connect to, as what, in which
container, and which vault masters the passwords there. :func:`read_target` is
the shared reader, because a target set generates exactly this object -- a set's
template *is* a :class:`~sopuli.config.model.Target` with ``{placeholder}``
tokens still in it. Keeping one reader is what stops the two drifting: a field
added to explicit targets but not to generated ones would mean a target set
silently cannot express something the estate can.

Three values are read from closed sets -- ``type``, ``oracle.scope`` and
``admin.auth``. A free string there loads happily and then connects somewhere
other than where the author meant, and this file is the whitelist (invariant 5).
Where the reference has not named the vocabulary, the set holds only what it
*has* named and the error says so; see issue #27 and the note in
:mod:`sopuli.config.vaults`.
"""

from __future__ import annotations

from typing import Any

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
from sopuli.config.model import AdminCredential, Target, TargetOracle
from sopuli.config.safety import build_safety

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

#: P2's bootstrap sources, in its order of preference. `vault` has nowhere yet to
#: say *which* ref -- see issue #27.
ADMIN_SOURCES = ("external", "vault", "prompt", "env")

ORACLE_KEYS = ("scope", "container")

#: The two scopes §2 actually writes. P1 names non-CDB databases and application
#: containers as distinct scopes but gives them no spelling, so they are absent
#: rather than invented; a non-CDB target simply omits `oracle:`. Widening this
#: is a one-line change once the reference names them (issue #27).
ORACLE_SCOPES = ("cdb_root", "pdb")

_UNSPECIFIED_ADMIN = (
    "P2 forbids the admin password in the config file, and the keys that point at "
    "the credential are not specified yet -- see issue #27"
)


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
    """``admin:`` -- which credential reaches the database, never the password."""
    if raw is None:
        return None
    admin = mapping(raw, at=at)
    reject_unknown_keys(admin, allowed=ADMIN_KEYS, at=at, hint=_UNSPECIFIED_ADMIN)
    _reject_empty(admin, at=at, block_name="admin")

    auth = admin.get("auth")
    return AdminCredential(
        username=optional_string(admin, "username", at=at),
        auth=(
            None
            if auth is None
            else choice(auth, allowed=ADMIN_SOURCES, at=at.key("auth"), noun="admin auth source")
        ),
    )


def read_oracle(raw: Any, *, at: KeyPath) -> TargetOracle:
    """``oracle:`` on a target -- which container to operate in.

    Not the application's ``oracle:`` block, which carries ``container_clause``.
    Same key name, different meaning; see :class:`~sopuli.config.model.TargetOracle`.
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

    What is *not* checked is how ``scope`` and ``container`` constrain each
    other. §2 writes ``cdb_root`` without a container and ``pdb`` with one, but
    the reference never says whether that is a rule -- and ``container`` is also
    the ``{container}`` token in a secret template (§6), so it carries
    information beyond which container to connect to. P1 puts per-vendor
    validation behind the driver. Recorded in C9 / issue #27 rather than guessed.
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

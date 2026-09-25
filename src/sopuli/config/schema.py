"""Generating the published config JSON Schema from the config layer itself.

P3 requires a **published** JSON Schema for config files. #20 validated with
hand-written builders instead, deliberately: the rules that matter here do not
express well in JSON Schema, and the errors #20 asked for name the offending key
rather than listing every ``oneOf`` branch that failed to match. That decision
stands. What was still missing is the artefact -- something a YAML language
server can be pointed at, so that editing a 130-line config gives completion and
inline errors instead of a round trip through the tool.

**Generated, not maintained beside the model.** Two hand-written descriptions of
one schema drift, and the one that drifts silently is the published one, because
nothing runs it. So every object here takes its property set from the same
constant the builder uses for ``reject_unknown_keys``, and every closed set from
the same tuple :func:`~sopuli.config.fields.choice` is given. :func:`_object`
refuses to build an object whose type table does not cover its key constant
*exactly* -- so adding a key to ``TARGET_KEYS`` breaks generation here until the
schema learns the key's type, and ``tests/config/test_schema.py`` then fails
until the committed artefact is regenerated.

**What this schema does and does not say.** It is structural: key names, JSON
types, closed sets, required keys, and ``additionalProperties: false`` -- which
is P3's "exits non-zero on unknown keys" in the form an editor can use. The
cross-key rules stay with the builders, where the message can locate the key:
the inline-vs-``applications:`` exclusion, ``secret`` beside ``secret_template``,
two accounts sharing one ref, ``require:`` exceeding ``length:``, ``allow:``
without ``charset: custom``, which keys an ``auth:`` method takes, every name that
must resolve against the section declaring it, and the §5 profile blocklist. A file
this schema accepts may still be refused by ``sopuli config validate``, and that is
the intended division.

Regenerate the committed artefact with::

    python -m sopuli.config.schema > docs/schemas/sopuli-config-1.8.schema.json
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Sequence
from typing import Any

from sopuli.config import (
    applications,
    auth,
    defaults,
    delivery,
    groups,
    loading,
    locking,
    notify,
    personal_accounts,
    policies,
    profiles,
    reset_records,
    safety,
    target_sets,
    targets,
    vaults,
)

#: The artefact's own version, which is not the config file's ``version:``. This
#: one tracks the schema contract the way `sopuli-run-1.11` does -- a new optional
#: key is a minor bump and does not touch a file that already says `version: 1`.
#:
#: 1.0 became 1.1 when `locking:` arrived (#83): a store's `locking:` and a
#: `locking:` block under `defaults` and a profile, all optional, so every file
#: valid under 1.0 is valid under 1.1.
#:
#: 1.1 became 1.2 with a vault's transport settings (#135, ADR-005): `namespace`,
#: `timeout_s` and the `tls:` block. Optional again -- a file that named none of
#: them means exactly what it did before -- which is what makes it a minor bump
#: rather than the other kind.
#:
#: 1.2 became 1.3 with C13's partial `vaults:` blocks (#136): a `vaults:` key
#: under `defaults:` and inside a profile, holding entries that patch a store
#: rather than declare one. Minor for the same reason once more -- and the
#: interesting half is what the new shape *refuses*, since `type`,
#: `non_production` and `locking` are absent from it by construction.
#: 1.3 became 1.4 with UC-2's `personal_accounts:` (H1, #449, #467): a top-level
#: list of accounts that belong to people, by name or by a predicate over a
#: profile or a role. Optional like every bump before it, so a file that declares
#: only applications means exactly what it did. What the shape *refuses* is again
#: the interesting half -- there is no `secret`, no `secret_template`, and exactly
#: one of `accounts`, `profile` and `role` may be written, because nothing masters
#: a personal account's password and two ways of saying which accounts would leave
#: the whitelist ambiguous.
#:
#: 1.4 became 1.5 with UC-2's `reset_records:` (H2, #450, #468): a top-level
#: block naming the store and prefix a reset is journalled under. Optional like
#: every bump before it, and here the optionality is the *specified* behaviour
#: rather than a compatibility courtesy -- a reset with no destination configured
#: warns and runs, because the seen path may have no store at all (UC-2 §3.4). What
#: the shape refuses is the interesting half again: there is no key for a password,
#: a hash or a verifier, and none is coming, because a record that could leak the
#: thing it records would be worse than no record.
#:
#: 1.5 became 1.6 with UC-2's `delivery:` (§6, #440): a top-level block naming how
#: a personal account's new password reaches its owner, with one sub-block per
#: method. Optional like every bump before it. **The sub-blocks are open objects
#: here, deliberately**: which keys `vault_wrapped:` takes is #444's and
#: `one_time_link:`'s is #445's, so a closed set now would be a schema asserting a
#: shape nobody has decided. Each method's issue closes its own, and until then an
#: editor offers the method names and checks nothing inside them -- which is why
#: `sopuli config validate` warns that no method is implemented rather than
#: letting a clean parse read as a working delivery.
#:
#: **#444 did not bump this, and that is a finding rather than an omission.** The
#: 1.6 note below promises that "each method's issue closes its own" sub-block, and
#: `vault_wrapped` is the first issue in a position to try. It cannot, because a
#: sub-block for an *unselected* method is deliberately left unjudged by the
#: builder (#440, `01-configuration.md` §9b's rule that an unselected block is how
#: somebody switches between configurations). Any constraint published here --
#: `required: ["ttl"]`, a pattern on it, `additionalProperties: false` -- would
#: refuse a file the tool accepts, which is the one direction §9b forbids: the
#: schema is the fast incomplete check, and the tool must never be the looser of
#: the two.
#:
#: Closing a sub-block therefore needs a **conditional** schema -- `if` on
#: `method`, `then` the constraints -- and the condition is not a one-liner either,
#: because `method` is optional and its absence *selects* `vault_wrapped`. That is
#: worth doing and it is not #444's: it is one shape that serves all six methods,
#: and it should be built once when a second method has keys to close. Until then
#: the sub-blocks stay open and the tool is the stricter of the two, which is the
#: safe asymmetry.
#:
#: 1.6 became 1.7 with `safety.delivery.allowed_methods` (H6, #453, #498): a
#: `delivery:` sub-block of every `safety:` block, holding the set of UC-2
#: delivery methods that layer permits. Optional like every bump before it, and
#: absent means *no constraint* rather than the empty set -- which is the one
#: reading an intersection cannot get wrong twice. The shape refuses an empty
#: array, because a layer permitting nothing can never be widened by a later one
#: and no run under it could deliver anything; and there is no `forbidden_methods`
#: counterpart, now or later, so an editor offering one is offering a key the
#: tool refuses.
#: 1.7 became 1.8 when `delivery.notify:` got a grammar (#442): `method`, and a
#: `webhook:` block with a MaterialRef `url` and a `template`. **Closed, where
#: `vault_wrapped:` could not be** -- and the difference is the whole of the note
#: above. A method's sub-block is left unjudged when that method is not selected,
#: so a constraint on it would refuse a file the tool accepts; `notify:` is read
#: whichever method is selected, because a notification is a property of the
#: delivery rather than of a method, so closing it refuses exactly what the
#: builder refuses.
#:
#: What is deliberately **not** expressed is the placeholder rule. A pattern
#: approximating it would be a second, weaker statement of UC-2 6.1 -- the rule
#: that the notify channel may not carry the password or anything that retrieves
#: it -- and two statements of one rule drift. It stays with the builder, where
#: the refusal can say why.
SCHEMA_VERSION = "1.8"

SCHEMA_FILENAME = f"sopuli-config-{SCHEMA_VERSION}.schema.json"

SCHEMA_ID = f"https://github.com/villebase/sopuli-dba/schemas/{SCHEMA_FILENAME}"

DRAFT = "https://json-schema.org/draft/2020-12/schema"

Schema = dict[str, Any]


class SchemaError(RuntimeError):
    """The generator and the config layer disagree about a section's keys.

    Always a programming error rather than a config error, which is why it is not
    a :class:`~sopuli.config.errors.ConfigError`: no config file can provoke it.
    It fires when a key was added to a builder's constant and not to the spec
    here, which is exactly the drift this module exists to prevent.
    """


# --------------------------------------------------------------- primitives ---

#: The closest structural reading of :func:`~sopuli.config.fields.string`, which
#: also refuses a string that is only whitespace. An editor cannot usefully be
#: told about that; the builder still is.
STRING: Schema = {"type": "string", "minLength": 1}

#: A count that must leave something to do. `max_targets: 0`, `length: 0` and a
#: zero timeout are all refused by the builders for their own reasons; the shared
#: part of the rule is expressible here.
POSITIVE_INT: Schema = {"type": "integer", "minimum": 1}

BOOLEAN: Schema = {"type": "boolean"}

#: A §7 ref, or a template that expands into one. Typed as a string on purpose:
#: the grammar is parsed by :mod:`sopuli.config.secret_refs`, and a regex
#: approximation of it in a published artefact would be a second, worse parser
#: that disagrees with the first in a way nobody notices until a rotation.
SECRET_REF: Schema = {
    "type": "string",
    "minLength": 1,
    "description": (
        "A SecretRef (01-configuration.md §7): [vault:]path[#field][/pointer], optionally "
        "qualified by one of @version=N (a whole number from 1) or "
        "@stage=current|pending|previous (any case). "
        "In `secret_template` the {tokens} are expanded per account and target, "
        "but a qualifier may not hold one."
    ),
}


def _enum(values: Sequence[str], *, description: str | None = None) -> Schema:
    """A closed set of strings, taken from the tuple the builder validates against."""
    schema: Schema = {"type": "string", "enum": list(values)}
    if description is not None:
        schema["description"] = description
    return schema


def _int_enum(values: Sequence[int]) -> Schema:
    return {"type": "integer", "enum": list(values)}


def _ref(name: str, *, description: str | None = None) -> Schema:
    schema: Schema = {"$ref": f"#/$defs/{name}"}
    if description is not None:
        schema["description"] = description
    return schema


def _array(items: Schema, *, description: str | None = None, **extra: Any) -> Schema:
    schema: Schema = {"type": "array", "items": items}
    if description is not None:
        schema["description"] = description
    schema.update(extra)
    return schema


def _map_of(values: Schema, *, description: str | None = None, **extra: Any) -> Schema:
    """A YAML mapping whose keys are names the author chooses.

    ``vaults:``, ``policies:``, ``groups:``, ``target_sets:`` and ``profiles:``
    are all this shape -- the key is the entry's name, which is why none of the
    entry objects has a ``name`` property of its own.
    """
    schema: Schema = {"type": "object", "additionalProperties": values}
    if description is not None:
        schema["description"] = description
    schema.update(extra)
    return schema


def _object(
    *,
    keys: Iterable[str],
    types: dict[str, Schema],
    required: Sequence[str] = (),
    description: str | None = None,
    min_properties: int | None = None,
) -> Schema:
    """An object whose properties are exactly ``keys``, refusing anything else.

    ``keys`` is always a constant imported from the builder that reads the
    section. The mismatch check is the whole point of routing every object
    through here: a key added to the builder and not to ``types`` cannot produce
    a schema that quietly omits it.
    """
    declared = tuple(keys)
    missing = [key for key in declared if key not in types]
    unknown = sorted(key for key in types if key not in declared)
    if missing or unknown:
        raise SchemaError(
            f"the schema spec does not match the config layer: "
            f"no type for {missing or 'nothing'}, "
            f"type given for unknown {unknown or 'nothing'}"
        )
    undeclared_required = sorted(key for key in required if key not in types)
    if undeclared_required:
        raise SchemaError(f"required keys that are not properties: {undeclared_required}")

    schema: Schema = {"type": "object"}
    if description is not None:
        schema["description"] = description
    schema["additionalProperties"] = False
    if required:
        schema["required"] = list(required)
    if min_properties is not None:
        schema["minProperties"] = min_properties
    # Document order, not sorted: it is the order the reference writes the keys
    # in, so a completion list reads the way the documentation does.
    schema["properties"] = {key: types[key] for key in declared}
    return schema


# ------------------------------------------------------------------ the estate ---


def _labels(*, at_least_one: bool) -> Schema:
    """``labels:`` on a target, and the ``match:`` that selects on them.

    Same shape, one difference: a match may not be empty, because a match of
    ``{}`` selects every target in the estate and is never what was meant by
    writing an exception (:func:`~sopuli.config.fields.label_selector`).
    """
    schema: Schema = {"type": "object", "additionalProperties": STRING}
    if at_least_one:
        schema["minProperties"] = 1
    return schema


def _safety() -> Schema:
    return _object(
        keys=safety.SAFETY_KEYS,
        types={
            "max_targets": POSITIVE_INT,
            "confirm_environments": _array(STRING),
            "readonly": BOOLEAN,
            "delivery": _safety_delivery(),
        },
        description=(
            "Safety settings only ratchet toward safe: the resolved value is the "
            "lowest max_targets, the union of confirm_environments, the intersection "
            "of delivery.allowed_methods, and readonly if any layer sets it "
            "(00-principles.md P3, invariant 10)."
        ),
    )


def _safety_delivery() -> Schema:
    """``safety.delivery:`` -- which UC-2 delivery methods an estate may use.

    A safety axis rather than a key of the top-level ``delivery:`` block, and the
    two are worth telling apart in an editor as well as in a document: that block
    says which method is used and is overridden last-one-wins, this says which
    ones *may* be, and it only ever narrows.

    ``minItems`` is the one constraint the schema can carry: an empty list is a
    configuration under which nothing could ever be delivered, and because the
    set only narrows no later layer could restore anything. The builder refuses
    it with a message that says that; this is §9b's "fast, local, incomplete"
    half of the same check.
    """
    return _object(
        keys=safety.SAFETY_DELIVERY_KEYS,
        types={
            "allowed_methods": _array(
                _enum(delivery.DELIVERY_METHODS),
                description=(
                    "The UC-2 delivery methods this layer permits (01-configuration.md "
                    "9, H6). Ratchets by intersection: each layer may only narrow the "
                    "set, and no higher-precedence layer can restore a method a lower "
                    "one removed. Absent means no constraint. Fail-closed on purpose -- "
                    "a method a later release adds is unusable until an estate names it. "
                    "There is no forbidden_methods key, now or later."
                ),
                minItems=1,
            ),
        },
        description=(
            "Which delivery methods this layer permits. Narrows only; two layers "
            "with no method in common are refused rather than resolved."
        ),
    )


def _locking() -> Schema:
    return _object(
        keys=locking.LOCKING_KEYS,
        types={
            "break_expired": {
                **BOOLEAN,
                "description": (
                    "May an unattended run take over a lock past its expiry, plus a "
                    "60-second skew margin? Off unless written. Safe to exist only "
                    "because the takeover fences the run it broke, so it is refused "
                    "beside a store marked `locking: advisory-only` (#83)."
                ),
            },
        },
        description=(
            "The advisory lock, which lives in the vault and is keyed on the secret "
            "path being mutated (00-principles.md P5, #83). Config-only: breaking a "
            "lock has no flag, per invariant 10."
        ),
    )


def _vault_types() -> dict[str, Schema]:
    """How each key of a vault entry is typed.

    One producer because a declaration and a partial entry (C13) describe the
    same keys, and two copies would be two places for one key's description to
    drift -- the same reason ``_APPLICATION_TYPES`` exists for the inline and
    named application forms. A function rather than a constant only because
    ``_method_or_shorthand`` is defined below it.
    """
    return {
        "type": _enum(vaults.VAULT_TYPES),
        "addr": STRING,
        "mount": STRING,
        "kv_version": _int_enum(vaults.KV_VERSIONS),
        "namespace": {
            **STRING,
            "description": (
                "HashiCorp Enterprise namespace, sent as X-Vault-Namespace. Absent "
                "means the header is not sent at all, which is not the same request "
                "as sending it empty."
            ),
        },
        "timeout_s": {
            **POSITIVE_INT,
            "description": (
                "Request timeout against this store, in seconds. Not optional the "
                "way a stdlib client's would be: httpx has no default (ADR-005), and "
                "the advisory lock is held while the request is outstanding. Zero is "
                "refused rather than read as 'no timeout'."
            ),
        },
        "tls": _ref("vault_tls"),
        "auth": _method_or_shorthand("vault_auth", vaults.AUTH_METHODS),
        "non_production": {
            **BOOLEAN,
            "description": (
                "Absent means production. A target with environment: prod pointed at "
                "a store marked here is refused (§10)."
            ),
        },
        "locking": {
            **_enum(locking.LOCK_MODES),
            "default": locking.DEFAULT_LOCK_MODE,
            "description": (
                "Whether this store can hold P5's advisory lock. `required` is the "
                "default and needs no compare-and-set capability written down: KV "
                "v2 and OCI have one, KV v1 and the file backend do not, and a "
                "mutating command refuses on a store that cannot lock. "
                "`advisory-only` is the operator saying so deliberately -- the "
                "record is still written, every run warns, and the run document "
                "reports lock.mode: none (#83)."
            ),
        },
    }


def _vault() -> Schema:
    return _object(
        keys=vaults.VAULT_KEYS,
        types=_vault_types(),
        required=("type",),
        description=(
            "One named secret store. Only `type` is required: the backends differ "
            "enough that demanding a HashiCorp shape of every entry would be the "
            "vendor bias P1 forbids, so per-backend requirements live behind the "
            "store interface."
        ),
    )


def _method_or_shorthand(block: str, methods: dict[str, auth.Method]) -> Schema:
    """An ``auth:`` block, or the scalar shorthand for it.

    Both positions -- a vault's ``auth:`` and a target's ``admin.auth`` -- take this
    shape, and the shorthand is offered for exactly the methods that need nothing
    else, which is the rule :mod:`sopuli.config.auth` enforces rather than a shorter
    list written out here.
    """
    parameterless = sorted(name for name, spec in methods.items() if spec.is_parameterless)
    return {
        "oneOf": [
            _ref(block),
            _enum(
                parameterless,
                description=(
                    "Shorthand for `{ method: NAME }`, available where the method needs "
                    "nothing else."
                ),
            ),
        ]
    }


def _vault_patches() -> Schema:
    """``vaults:`` under ``defaults:`` or in a profile -- partial entries (C13)."""
    return {
        "type": "object",
        "description": (
            "Settings *of* stores declared at the top level, keyed by name. `vault:` "
            "is always a store name and never a block, so a layer that wants to say "
            "something about a store names it here (C13, decided in issue #31). The "
            "entries are partial: they patch a declaration rather than making one, and "
            "a name not declared under the top-level `vaults:` is an error. Under "
            "`defaults:` this is precedence layer 5, so it is outranked by the "
            "declaration; in a profile it is layer 3, so it outranks it (P3)."
        ),
        "additionalProperties": _ref("vault_patch"),
    }


def _vault_patch() -> Schema:
    types = _vault_types()
    return _object(
        keys=vaults.PATCHABLE_KEYS,
        # The declaration's own types, narrowed to what a layer may write. Taken
        # from the same producer rather than rewritten, so `addr` cannot come to
        # mean one thing in a declaration and another in a patch.
        types={key: types[key] for key in vaults.PATCHABLE_KEYS},
        description=(
            "What a layer may say about a store it did not declare. `type` is absent "
            "because a store that is HashiCorp from a laptop and OCI from CI is two "
            "stores, and one name meaning two things is a name the audit trail cannot "
            "be read with. `non_production` and `locking` are absent because both are "
            "guardrails, and invariant 10 keeps a guardrail out of the invocation "
            "context. Every remaining key is optional: absent means this layer said "
            "nothing, which is what the merge reads."
        ),
    )


def _vault_tls() -> Schema:
    return _object(
        keys=vaults.TLS_KEYS,
        types={
            "ca_file": {**STRING, "description": "Path to a CA bundle file."},
            "ca_path": {**STRING, "description": "Path to a directory of CA certificates."},
            "client_cert": {
                **STRING,
                "description": (
                    "Path to a client certificate for mutual TLS. May hold the key as "
                    "well, which is why it can be written without `client_key`."
                ),
            },
            "client_key": {
                **STRING,
                "description": (
                    "Path to the client key. Needs a `client_cert` beside it: a key "
                    "alone presents nothing."
                ),
            },
            "server_name": {
                **STRING,
                "description": (
                    "Overrides SNI, for a store reached by an address that does not match "
                    "its certificate -- a tunnel, or a load balancer by IP."
                ),
            },
            "verify": {
                **BOOLEAN,
                "default": True,
                "description": (
                    "Verify the store's certificate. Under P3's safety ratchet, so the "
                    "resolved value is the strictest across every layer and no "
                    "higher-precedence source can turn it off once a lower one has it "
                    "on. A run with it off warns into the run document. VAULT_SKIP_VERIFY "
                    "is refused rather than honoured, because an unranked environment "
                    "variable would bypass the ratchet from outside (§6)."
                ),
            },
        },
        description=(
            "How the transport to this store is verified, and what identifies us to it "
            "(ADR-005). None of these is a MaterialRef: a CA bundle is not a credential, "
            "and `client_key` names a path rather than holding a key."
        ),
    )


def _vault_auth() -> Schema:
    """The method block itself.

    Structural, and therefore flat: every key any method may write is a property
    here, and *which* keys go with which method is a relation between two keys, so
    it stays with the builder where the error can name the method (§9b). The
    property set is still generated from the method table, so a key cannot reach a
    method without reaching the schema.
    """
    identity = dict.fromkeys(vaults.AUTH_IDENTITY_KEYS, STRING)
    identity["mount"] = {
        **STRING,
        "description": (
            "The auth mount, not the KV mount on the vault itself. Defaults to the "
            "method's own name."
        ),
    }
    return _object(
        keys=vaults.AUTH_KEYS,
        types={
            "method": _enum(tuple(vaults.AUTH_METHODS)),
            **dict.fromkeys(vaults.AUTH_MATERIAL_KEYS, _ref("material_ref")),
            **identity,
        },
        required=("method",),
        description=(
            "How to authenticate, and where the material comes from -- never the "
            "material itself (P2). Each method takes only its own keys, which the "
            "validator checks; the identity fields are inline and everything "
            "secret-bearing is a MaterialRef."
        ),
    )


def _material_ref() -> Schema:
    """``{ env: NAME }`` or ``{ file: PATH }`` -- exactly one of them.

    The one rule in this whole schema that is a security property rather than a
    convenience: there is no property for a value, so a config file has nowhere to
    write a credential (P2). Expressible structurally, so it is expressed here as
    well as in the builder.
    """
    return {
        "type": "object",
        "description": (
            "Where a piece of auth material comes from: an environment variable or a "
            "file. Not a SecretRef -- this is what you need before you have a vault."
        ),
        "additionalProperties": False,
        "minProperties": 1,
        "maxProperties": 1,
        "properties": dict.fromkeys(auth.MATERIAL_KINDS, STRING),
    }


#: The target-shaped keys, shared by `targets:` entries, a `target_sets:` template
#: and an override patch -- the three places §2 and §4 say are one shape. One
#: table for all three is what stops a key reaching one of them and not the others.
_TARGET_TYPES: dict[str, Schema] = {
    "name": STRING,
    "type": _enum(targets.TARGET_TYPES),
    "dsn": {**STRING, "description": "host:port/service, or a TNS alias."},
    "environment": STRING,
    "vault": {**STRING, "description": "The name of an entry in `vaults:`."},
    "admin": _ref("admin"),
    "oracle": _ref("target_oracle"),
    "labels": _ref("labels"),
    "safety": _ref("safety"),
}


def _target() -> Schema:
    return _object(
        keys=targets.TARGET_KEYS,
        types=_TARGET_TYPES,
        required=("name", "type", "dsn"),
        description="One database endpoint.",
    )


def _admin() -> Schema:
    return _object(
        keys=targets.ADMIN_KEYS,
        types={
            "username": {
                **STRING,
                "description": (
                    "Absent under `auth: external`, where the wallet supplies it, and "
                    "overridable per execution context by SOPULI_DB_ADMIN_USER (§6)."
                ),
            },
            "auth": _method_or_shorthand("admin_auth", targets.ADMIN_METHODS),
        },
        min_properties=1,
        description=(
            "Which credential reaches the database, never the password: storing the "
            "admin password in the config file is not supported at all (P2)."
        ),
    )


def _admin_auth() -> Schema:
    """``admin.auth`` -- P2's bootstrap sources, in the vault block's grammar.

    Same shape, different vocabulary, and the same division of labour: the keys are
    all here, and which of them belongs to which method stays with the validator
    (§9b).
    """
    return _object(
        keys=targets.ADMIN_AUTH_KEYS,
        types={
            "method": _enum(tuple(targets.ADMIN_METHODS)),
            "password_env": {
                **STRING,
                "description": (
                    "The variable holding the admin password, for `method: env`. "
                    f"Defaults to {targets.ADMIN_PASSWORD_ENV}. Still low-assurance (P2)."
                ),
            },
            "secret": {
                **SECRET_REF,
                "description": (
                    "For `method: vault`: a full SecretRef, so it takes a `vault:` prefix "
                    "and §7's tokens. Defaults to the target's own vault."
                ),
            },
        },
        required=("method",),
        description=(
            "P2's bootstrap sources, in its order of preference: external "
            "authentication, a vault path, an interactive prompt, an environment "
            "variable."
        ),
    )


def _target_oracle() -> Schema:
    return _object(
        keys=targets.ORACLE_KEYS,
        types={"scope": _enum(targets.ORACLE_SCOPES), "container": STRING},
        min_properties=1,
        description=(
            "Which container the tool connects to. Not an application's `oracle:` "
            "block, which carries `container_clause` -- same key name, different "
            "meaning."
        ),
    )


def _target_set() -> Schema:
    return _object(
        keys=target_sets.TARGET_SET_KEYS,
        types={
            **_TARGET_TYPES,
            "name": {
                **STRING,
                "description": (
                    "The name *template*, e.g. appdb-{env}-{tenant}. The key this entry "
                    "is written under is the set's own name."
                ),
            },
            "for_each": _ref("for_each"),
            "overrides": _map_of(
                _ref("target_patch"),
                description="Patches keyed by rendered target name (§4 rule 5).",
            ),
        },
        required=("name", "type", "dsn", "for_each"),
        description=(
            "A target template plus the dimensions to expand it over (§4). Listing "
            "35 PDBs by hand is not viable; this generates them."
        ),
    )


def _target_patch() -> Schema:
    return _object(
        keys=target_sets.PATCH_KEYS,
        types={key: value for key, value in _TARGET_TYPES.items() if key != "name"},
        min_properties=1,
        description=(
            "What to change about one generated target. `name` is absent because the "
            "rendered name is the key this patch is found by, so patching it would "
            "make the key a lie."
        ),
    )


def _for_each() -> Schema:
    """``for_each:`` -- one outer dimension, and at most one list inside a value.

    §4 rules 1 and 6, which are rules about shape rather than about how two keys
    relate, so they belong in the schema. What is *not* here is rule 7's
    consequence -- that every value's inner dimension must be the same variable
    -- because that compares values with each other.
    """
    variable: Schema = {
        "oneOf": [
            {"type": ["string", "number"]},
            _array(STRING, minItems=1),
        ],
        "description": (
            "A scalar substituted into the templates, or a list -- which makes it the "
            "inner dimension, at most one per value (§4 rules 2 and 6)."
        ),
    }
    return {
        "type": "object",
        "description": (
            "Exactly one outer dimension, named by its key; under it, one entry per "
            "value of that dimension, holding the variables in scope for it (§4 rule 1)."
        ),
        "minProperties": 1,
        "maxProperties": 1,
        "additionalProperties": _map_of(
            _map_of(variable),
            minProperties=1,
        ),
    }


def _group() -> Schema:
    return _object(
        keys=groups.GROUP_KEYS,
        types={"match": _ref("label_selector"), "safety": _ref("safety")},
        required=("match",),
        description="A name for a label selection over the estate (§4).",
    )


# ---------------------------------------------------------------- policies ---


def _policy() -> Schema:
    return _object(
        keys=policies.POLICY_KEYS,
        types={
            "password": _ref("password_policy"),
            "rotation": _ref("rotation_policy"),
            "verify": _ref("verify_policy"),
            "account": _ref("account_policy"),
        },
        description="Password rules, rotation strategy and verification, under one name.",
    )


def _password_policy() -> Schema:
    return _object(
        keys=policies.PASSWORD_KEYS,
        types={
            "length": POSITIVE_INT,
            "charset": _enum(policies.CHARSETS),
            "allow": {
                **STRING,
                "description": (
                    'Belongs to `charset: custom` and to nothing else. May not contain " '
                    "-- Oracle quoted identifiers have no escape for it (invariant 11) -- "
                    "nor a control character. Must hold every class `require:` asks for."
                ),
            },
            "first_char": _enum(policies.FIRST_CHARS),
            "require": _ref("require"),
        },
        description="§8's charsets and the character classes a password must contain.",
    )


def _require() -> Schema:
    return _object(
        keys=policies.REQUIRE_KEYS,
        types={key: {"type": "integer", "minimum": 0} for key in policies.REQUIRE_KEYS},
        description=(
            "Minimum count per character class. A block no password of this length "
            "and charset could satisfy is refused by the validator, not here."
        ),
    )


def _rotation_policy() -> Schema:
    return _object(
        keys=policies.ROTATION_KEYS,
        types={
            "strategy": _enum(policies.ROTATION_STRATEGIES),
            "rollover_hours": POSITIVE_INT,
            "keep_previous": BOOLEAN,
            "max_age_days": POSITIVE_INT,
        },
        description="How a new password replaces the old one (UC-1 §6).",
    )


def _verify_policy() -> Schema:
    return _object(
        keys=policies.VERIFY_KEYS,
        types={
            "method": _enum(policies.VERIFY_METHODS),
            "lockout_margin": {"type": "integer", "minimum": 0},
        },
        description=(
            "How the tool confirms a password works. Shared with a profile, because "
            "the same estate is verified by login from a laptop and by hash comparison "
            "from a scheduler (§5)."
        ),
    )


def _account_policy() -> Schema:
    return _object(
        keys=policies.ACCOUNT_KEYS,
        types={
            "unlock_if_locked": {
                **BOOLEAN,
                "description": (
                    "`creds apply` unlocks a locked account before setting its password "
                    "(UC-1 §5). Opt-in: without this, a locked account is reported LOCKED "
                    "and its password is left alone."
                ),
            },
            "profile": {
                **STRING,
                "description": (
                    "The profile this account is to sit on. `creds apply` assigns it where "
                    "the account is on a different one (UC-1 §5). The tool never issues "
                    "ALTER PROFILE -- profiles are shared, so changing one reaches accounts "
                    "nobody selected (Q4)."
                ),
            },
        },
        description=(
            "What the tool may do to the account itself, beyond its password. Every "
            "attribute here is opt-in and off by default (§8)."
        ),
    )


# ------------------------------------------------- profiles and the rest ---


def _profile() -> Schema:
    return _object(
        keys=profiles.PROFILE_KEYS,
        types={
            "vault": {**STRING, "description": "The name of an entry in `vaults:`."},
            "vaults": _ref("vault_patches"),
            "verify": _ref("verify_policy"),
            "rotation": _ref("profile_rotation"),
            "safety": _ref("safety"),
            "locking": _ref("locking"),
            "confirm": BOOLEAN,
            "output": _enum(profiles.OUTPUTS),
            "log_level": _enum(profiles.LOG_LEVELS),
            "log_file": STRING,
            "db": _ref("profile_db"),
        },
        description=(
            "Where a run is invoked from -- `interactive`, `ci`, `scheduled` -- never "
            "what it points at. Everything here changes how the tool behaves; nothing "
            "here changes which targets or accounts are in scope (§5)."
        ),
    )


def _profile_rotation() -> Schema:
    return _object(
        keys=profiles.ROTATION_KEYS,
        types={"strategy": _enum(policies.ROTATION_STRATEGIES)},
        description=(
            "Only `strategy`. The rest of a rotation policy describes the credential's "
            "lifecycle, which is a property of the estate rather than of the machine "
            "running the command."
        ),
    )


def _profile_db() -> Schema:
    return _object(
        keys=profiles.DB_KEYS,
        types={"connect_timeout_s": POSITIVE_INT, "query_timeout_s": POSITIVE_INT},
        description="Budgets that differ when nobody is waiting.",
    )


def _defaults() -> Schema:
    return _object(
        keys=defaults.DEFAULTS_KEYS,
        types={
            "vault": {**STRING, "description": "The name of an entry in `vaults:`."},
            "vaults": _ref("vault_patches"),
            "policy": STRING,
            "profile": STRING,
            "safety": _ref("safety"),
            "locking": _ref("locking"),
        },
        description="Precedence layer 5 (P3): the bottom of the config file.",
    )


def _runtime() -> Schema:
    return _object(
        keys=defaults.RUNTIME_KEYS,
        types={"oracle": _ref("runtime_oracle")},
        description="How this installation of the tool is set up, not what it manages.",
    )


def _runtime_oracle() -> Schema:
    return _object(
        keys=defaults.RUNTIME_ORACLE_KEYS,
        types={"client_lib_dir": STRING},
        description=(
            "Where the Instant Client lives. Thick mode is a runtime prerequisite on "
            "every platform (P4, D3)."
        ),
    )


# ------------------------------------------------------------ applications ---

#: The keys an application entry and an inline (top-level) binding share. Built
#: once so the two shapes cannot describe the same key differently -- §1 calls the
#: inline form "exactly sugar for a single unnamed application entry".
_APPLICATION_TYPES: dict[str, Schema] = {
    "name": {**STRING, "description": "What `--application` selects on."},
    "accounts": _ref("accounts"),
    "targets": _ref("application_targets"),
    "vault": {**STRING, "description": "The name of an entry in `vaults:`."},
    "secret": SECRET_REF,
    "secret_template": SECRET_REF,
    "policy": {**STRING, "description": "The name of an entry in `policies:`."},
    "oracle": _ref("oracle_options"),
    "overrides": _ref("overrides"),
}


def _personal_account() -> Schema:
    """One `personal_accounts:` entry (H1, #449).

    ``minProperties`` is not the rule here and would be the wrong one: an entry
    must name **exactly one** of ``accounts``, ``profile`` and ``role``, which is
    a relation between three keys rather than a count, so it stays with the
    builder where the message can say which two were found. What the artefact
    does carry is the absence of ``secret`` and ``secret_template`` -- an editor
    offering them here would be offering mastery over a password nothing masters.
    """
    return _object(
        keys=personal_accounts.PERSONAL_ACCOUNT_KEYS,
        types={
            "accounts": _ref("accounts"),
            "profile": {
                **STRING,
                "description": (
                    "A predicate: every account carrying this database profile. "
                    "Resolved against the database at run time, never from the file."
                ),
            },
            "role": {
                **STRING,
                "description": (
                    "A predicate: every account granted this database role. "
                    "Resolved against the database at run time, never from the file."
                ),
            },
            "targets": _ref("application_targets"),
            "policy": {**STRING, "description": "The name of an entry in `policies:`."},
        },
        description=(
            "Accounts belonging to people, which a DBA resets and hands over (UC-2). "
            "Declared by name or by a predicate over a profile or a role; nothing "
            "masters the password, so there is no secret to bind."
        ),
    )


def _delivery() -> Schema:
    """The `delivery:` block -- how UC-2 hands a password over (§6, #440).

    ``method`` is the closed set and the sub-blocks are **open objects**, which is
    the one thing about this schema worth explaining. A method's keys belong to
    that method's issue, so closing them here would publish a shape nobody has
    decided -- and the generator's own rule, that an object's properties come from
    the constant its builder validates against, has no constant to read for a
    section whose builder deliberately validates only the shape.

    ``method`` is **not required**: absent means :data:`~sopuli.config.delivery.DEFAULT_METHOD`,
    and §6.2 says why that default is `vault_wrapped` rather than the
    strongest-sounding option. What *is* enforced, and what an editor cannot show,
    is that the selected method's sub-block exists -- a cross-key rule, so it stays
    with the builder where the message can name the method (§9b).
    """
    sub_block: Schema = {
        "type": "object",
        "description": (
            "This method's own settings. Unchecked here: a sub-block for a method "
            "that is not selected is left unjudged by the tool, so a constraint "
            "published here would refuse a file the tool accepts. `config validate` "
            "warns when the selected method is not implemented in this build, and "
            "checks the selected method's keys itself."
        ),
    }
    return _object(
        keys=delivery.DELIVERY_KEYS,
        types={
            "method": _enum(
                delivery.DELIVERY_METHODS,
                description=(
                    "How the password reaches the person (UC-2 6.2). All but `manual` are "
                    "unseen -- the tool puts the value where only the owner can fetch it. "
                    "`manual` prints it to the DBA's terminal and is the one method that "
                    "shows a working password to somebody who is not its owner. Absent "
                    "means `vault_wrapped`, which is the default because it works against "
                    "a stock Vault."
                ),
            ),
            "notify": _notify(),
            **dict.fromkeys(delivery.DELIVERY_METHODS, sub_block),
        },
        description=(
            "How a personal account's new password reaches its owner (UC-2 6). One "
            "method, and the sub-block of the same name carries its settings. Absent "
            "means no delivery is configured, which is not the same as choosing the "
            "default."
        ),
    )


def _notify() -> Schema:
    """`delivery.notify:` -- the low-trust channel (#442, UC-2 §6.1).

    **Closed, unlike a delivery method's sub-block**, and the difference is the
    one #444 established: a method's settings are left unjudged when that method
    is not selected, so any constraint published for them would refuse a file the
    tool accepts. `notify:` has no such exemption -- it is read whichever delivery
    method is selected, because a notification is a property of the delivery as a
    whole -- so closing it here refuses exactly what the builder refuses.

    The template's placeholders are **not** expressed as a pattern. A regex that
    approximated :func:`sopuli.config.notify.check_template` would be a second,
    weaker statement of §6.1's rule, and the two would drift; §9b's division puts
    a cross-value rule with the builder, where the message can say *why* a name is
    refused rather than that a string did not match.
    """
    return _object(
        keys=notify.NOTIFY_KEYS,
        types={
            "method": _enum(
                notify.NOTIFY_METHODS,
                description=(
                    "How the person is told a password is waiting (UC-2 6.3). Absent means "
                    "`webhook`, which is the only one there is -- and the enum holds only "
                    "what is decided, unlike `delivery.method`, because nothing defines a "
                    "set of notify channels."
                ),
            ),
            notify.WEBHOOK: _object(
                keys=notify.WEBHOOK_KEYS,
                required=notify.WEBHOOK_KEYS,
                types={
                    "url": {
                        "$ref": "#/$defs/material_ref",
                        "description": (
                            "Where to post. Named rather than written (C9): a chat "
                            "incoming-webhook URL embeds its own credential, so a literal "
                            "one here is a credential in a file people commit -- and it is "
                            "what makes the redaction #442 asked for structural, since the "
                            "model never holds a value to redact."
                        ),
                    },
                    "template": {
                        "type": "string",
                        "description": (
                            "The message, in the estate's own words -- the tool does not "
                            "author it, because what is true of a hand-over differs by "
                            "delivery method. Placeholders are `{account}`, `{target}` and "
                            "`{expires_at}`, and **every other name is refused at load**: "
                            "UC-2 6.1 bars the password *or anything that retrieves it* "
                            "from this channel, so a template naming a token does not "
                            "render empty, it does not load. `{{` is a literal brace."
                        ),
                    },
                },
                description="Where to post and what to say. Both keys required.",
            ),
        },
        description=(
            "The low-trust channel that says a password is ready (#442). It may never "
            "carry the password or anything that retrieves it (UC-2 6.1), which is "
            "enforced by the placeholder set being closed rather than by a list of "
            "forbidden words."
        ),
    )


def _reset_records() -> Schema:
    """The `reset_records:` block -- where UC-2 journals a reset (H2, #468).

    Both keys are required, and ``prefix`` having no default is a decision rather
    than an omission: a default would put records somewhere the file does not
    say, in a store the file does name, so an operator could not tell where the
    journal is by reading the configuration.

    What the artefact cannot carry is the rule that matters most -- that no key
    here may hold a password in any representation. That is a property of the
    *record*, not of this block, and it is asserted against the serialised
    document by :func:`sopuli.reset_record.assert_no_secret`. The structural half
    of it is visible here all the same, in what the object does not offer.
    """
    return _object(
        keys=reset_records.RESET_RECORDS_KEYS,
        types={
            "vault": {**STRING, "description": "The name of an entry in `vaults:`."},
            "prefix": {
                **STRING,
                "description": (
                    "The path records are written under. One record per (target, "
                    "account) is built beneath it."
                ),
            },
        },
        required=("vault", "prefix"),
        description=(
            "Where a personal account's reset is recorded (UC-2 §3.1): who reset it, "
            "by which path, and where it was delivered -- never the password. Not the "
            "delivery target. Absent means no journal is kept, which warns and runs."
        ),
    )


def _application() -> Schema:
    return _object(
        keys=applications.APPLICATION_KEYS,
        types=_APPLICATION_TYPES,
        required=("name", "accounts"),
        description=(
            "These accounts, in these targets, mastered by these secrets, under this "
            "policy -- the sentence §1 says the whole config exists to state."
        ),
    )


def _accounts() -> Schema:
    return _array(
        STRING,
        minItems=1,
        uniqueItems=True,
        description=(
            "The database accounts this application owns. Invariant 5: the config is "
            "the whitelist, so nothing outside this list is ever touched."
        ),
    )


def _application_targets() -> Schema:
    """``targets:`` on an application: names, a group, or a label match (§3).

    Three forms of one key, so a union of value shapes rather than a rule about
    how keys relate -- absent means every target, which is the documented default
    and needs no spelling of its own.
    """
    branches: list[Schema] = [
        _array(STRING, description="Target names, against the expanded estate.")
    ]
    branch_types: dict[str, Schema] = {
        "group": {**STRING, "description": "The name of an entry in `groups:`."},
        "match": _ref("label_selector"),
    }
    branches.extend(
        _object(keys=(key,), types={key: branch_types[key]}, required=(key,))
        for key in applications.TARGET_SELECTOR_KEYS
    )
    return {
        "oneOf": branches,
        "description": "Which targets this entry applies to. Absent means all of them.",
    }


def _oracle_options() -> Schema:
    return _object(
        keys=applications.ORACLE_KEYS,
        types={"container_clause": STRING},
        description=(
            "How `ALTER USER` is written for these accounts. Not a target's `oracle:` "
            "block, which says which container to connect to."
        ),
    )


def _overrides() -> Schema:
    return _array(
        _ref("override"),
        description="Per-label exceptions to this entry's own resolution (§2, §3).",
    )


def _override() -> Schema:
    return _object(
        keys=applications.OVERRIDE_KEYS,
        types={
            "where": _ref("label_selector", description="Which targets the patch applies to."),
            "vault": {**STRING, "description": "The name of an entry in `vaults:`."},
            "secret": SECRET_REF,
            "secret_template": SECRET_REF,
            "policy": {**STRING, "description": "The name of an entry in `policies:`."},
            "oracle": _ref("oracle_options"),
        },
        required=("where",),
        description=(
            "`accounts` is not patchable, and that is a rule rather than an omission: "
            "invariant 5 says selectors filter the declared set and cannot extend it, "
            "not even under --force."
        ),
    )


# ------------------------------------------------------------------- root ---

_ROOT_DESCRIPTION = """\
A sopuli-dba configuration file (docs/design/01-configuration.md).

Structural only, and deliberately so. It describes key names, types, closed sets, \
required keys, and rejects unknown keys -- which is what makes editor completion \
and P3's "a typo in a credential tool must never be silently ignored" work while \
somebody is typing.

The rules it does not express are enforced by `sopuli config validate`, whose \
errors name the offending key: the inline form and `applications:` are mutually \
exclusive; `secret` and `secret_template` are mutually exclusive; two accounts may \
not resolve to one secret ref; `require:` may not exceed `length:` or ask for \
specials a charset does not have; `allow:` belongs to `charset: custom`; an \
`auth:` block may carry only the keys its own `method:` takes; every vault, \
policy, group, profile and target name written anywhere must be declared in the \
section that declares it; a `for_each` must use one inner dimension throughout; \
and a profile may not set a key that would change scope. A file this \
schema accepts may still be refused there.\
"""


def _root() -> Schema:
    """The whole file. ``version:`` is the only required key.

    A config that declares an estate and no binding is legal -- §1 permits a file
    holding only vaults and targets -- and the inline form's keys sit beside
    ``applications:`` as siblings because the exclusion between them is a rule
    about two keys, not about one.
    """
    types: dict[str, Schema] = {
        "version": {
            **_int_enum(loading.SUPPORTED_VERSIONS),
            "description": (
                "The config schema version this file is written for. Required: a file "
                "with no version cannot be migrated later (§9a)."
            ),
        },
        "runtime": _ref("runtime"),
        "defaults": _ref("defaults"),
        "vaults": _map_of(_ref("vault"), description="Named secret stores (§2)."),
        "targets": _array(_ref("target"), description="Explicitly listed endpoints (§2)."),
        "target_sets": _map_of(_ref("target_set"), description="Generated endpoints (§4)."),
        "groups": _map_of(_ref("group"), description="Named label selections (§4)."),
        "policies": _map_of(_ref("policy"), description="Password and rotation rules (§8)."),
        "profiles": _map_of(_ref("profile"), description="Run contexts (§5)."),
        "applications": _array(
            _ref("application"),
            minItems=1,
            description="The binding, for one or more applications (§3).",
        ),
        "personal_accounts": _array(
            _ref("personal_account"),
            minItems=1,
            description="Accounts belonging to people, for UC-2's reset (H1, #449).",
        ),
        "reset_records": _ref("reset_records"),
        "delivery": _ref("delivery"),
    }
    # The inline form is one unnamed application entry hoisted to the top level,
    # so its keys take the entry's own subschemas rather than copies of them.
    types.update({key: _APPLICATION_TYPES[key] for key in applications.INLINE_KEYS})

    return _object(
        keys=loading.TOP_LEVEL_KEYS,
        types=types,
        required=("version",),
        description=_ROOT_DESCRIPTION,
    )


def build_schema() -> Schema:
    """The published config schema, as a JSON-serialisable dict."""
    root = _root()
    return {
        "$schema": DRAFT,
        "$id": SCHEMA_ID,
        "title": "sopuli-dba configuration",
        **root,
        "$defs": {
            "labels": _labels(at_least_one=False),
            "label_selector": _labels(at_least_one=True),
            "safety": _safety(),
            "locking": _locking(),
            "vault": _vault(),
            "vault_patches": _vault_patches(),
            "vault_patch": _vault_patch(),
            "vault_auth": _vault_auth(),
            "vault_tls": _vault_tls(),
            "material_ref": _material_ref(),
            "target": _target(),
            "admin": _admin(),
            "admin_auth": _admin_auth(),
            "target_oracle": _target_oracle(),
            "target_set": _target_set(),
            "target_patch": _target_patch(),
            "for_each": _for_each(),
            "group": _group(),
            "personal_account": _personal_account(),
            "reset_records": _reset_records(),
            "delivery": _delivery(),
            "policy": _policy(),
            "password_policy": _password_policy(),
            "require": _require(),
            "rotation_policy": _rotation_policy(),
            "verify_policy": _verify_policy(),
            "account_policy": _account_policy(),
            "profile": _profile(),
            "profile_rotation": _profile_rotation(),
            "profile_db": _profile_db(),
            "defaults": _defaults(),
            "runtime": _runtime(),
            "runtime_oracle": _runtime_oracle(),
            "application": _application(),
            "accounts": _accounts(),
            "application_targets": _application_targets(),
            "oracle_options": _oracle_options(),
            "overrides": _overrides(),
            "override": _override(),
        },
    }


def dump_schema() -> str:
    """The committed artefact's text, newline-terminated."""
    return json.dumps(build_schema(), indent=2, ensure_ascii=False) + "\n"


def main() -> None:
    """``python -m sopuli.config.schema`` -- write the schema to stdout.

    Bytes rather than text, and UTF-8 rather than the console's codepage: the
    descriptions carry ``§`` and an em dash, and on a Windows console
    ``print`` would encode them as cp1252 or fail outright. The committed
    artefact has to be the same bytes on every platform (P4).
    """
    sys.stdout.buffer.write(dump_schema().encode("utf-8"))


if __name__ == "__main__":  # pragma: no cover
    main()

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
without ``charset: custom``, every name that must resolve against the section
declaring it, and the §5 profile blocklist. A file this schema accepts may still
be refused by ``sopuli config validate``, and that is the intended division.

Regenerate the committed artefact with::

    python -m sopuli.config.schema > docs/schemas/sopuli-config-1.0.schema.json
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Sequence
from typing import Any

from sopuli.config import (
    applications,
    defaults,
    groups,
    loading,
    policies,
    profiles,
    safety,
    target_sets,
    targets,
    vaults,
)

#: The artefact's own version, which is not the config file's ``version:``. This
#: one tracks the schema contract the way `sopuli-run-1.1` does -- a new optional
#: key is a minor bump and does not touch a file that already says `version: 1`.
SCHEMA_VERSION = "1.0"

SCHEMA_FILENAME = f"sopuli-config-{SCHEMA_VERSION}.schema.json"

SCHEMA_ID = f"https://github.com/futville/sopuli-dba/schemas/{SCHEMA_FILENAME}"

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
        "A SecretRef (01-configuration.md §7): [vault:]path[#field][/pointer][@qualifier]. "
        "In `secret_template` the {tokens} are expanded per account and target."
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
        },
        description=(
            "Safety settings only ratchet toward safe: the resolved value is the "
            "lowest max_targets, the union of confirm_environments, and readonly if "
            "any layer sets it (00-principles.md P3, invariant 10)."
        ),
    )


def _vault() -> Schema:
    return _object(
        keys=vaults.VAULT_KEYS,
        types={
            "type": _enum(vaults.VAULT_TYPES),
            "addr": STRING,
            "mount": STRING,
            "kv_version": _int_enum(vaults.KV_VERSIONS),
            "auth": _ref("vault_auth"),
            "non_production": {
                **BOOLEAN,
                "description": (
                    "Absent means production. A target with environment: prod pointed at "
                    "a store marked here is refused (§10)."
                ),
            },
        },
        required=("type",),
        description=(
            "One named secret store. Only `type` is required: the backends differ "
            "enough that demanding a HashiCorp shape of every entry would be the "
            "vendor bias P1 forbids, so per-backend requirements live behind the "
            "store interface."
        ),
    )


def _vault_auth() -> Schema:
    return _object(
        keys=vaults.AUTH_KEYS,
        types={"method": _enum(vaults.AUTH_METHODS)},
        required=("method",),
        description=(
            "How to authenticate, never the material. The keys that point at the "
            "material are not specified yet -- see issue #27."
        ),
    )


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
        types={"username": STRING, "auth": _enum(targets.ADMIN_SOURCES)},
        min_properties=1,
        description=(
            "Which credential reaches the database, never the password: storing the "
            "admin password in the config file is not supported at all (P2)."
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
                    "-- Oracle quoted identifiers have no escape for it (invariant 11)."
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
        types={"unlock_if_locked": BOOLEAN},
        description="What the tool may do to the account itself.",
    )


# ------------------------------------------------- profiles and the rest ---


def _profile() -> Schema:
    return _object(
        keys=profiles.PROFILE_KEYS,
        types={
            "vault": {**STRING, "description": "The name of an entry in `vaults:`."},
            "verify": _ref("verify_policy"),
            "rotation": _ref("profile_rotation"),
            "safety": _ref("safety"),
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
            "policy": STRING,
            "profile": STRING,
            "safety": _ref("safety"),
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
specials a charset does not have; `allow:` belongs to `charset: custom`; every \
vault, policy, group, profile and target name written anywhere must be declared in \
the section that declares it; a `for_each` must use one inner dimension \
throughout; and a profile may not set a key that would change scope. A file this \
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
            "vault": _vault(),
            "vault_auth": _vault_auth(),
            "target": _target(),
            "admin": _admin(),
            "target_oracle": _target_oracle(),
            "target_set": _target_set(),
            "target_patch": _target_patch(),
            "for_each": _for_each(),
            "group": _group(),
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

"""The published config schema, and the coupling that keeps it true.

The requirement is not "there is a schema" -- it is that the schema is
*generated from the model*, so that a field cannot land without it moving. Two
hand-written descriptions of one schema drift, and the one that drifts silently
is the published one, because nothing runs it.

So there are three kinds of test here, and they fail at three different moments:

* :func:`test_the_committed_schema_is_what_the_generator_produces` fails when
  somebody changes the generator and forgets to regenerate the artefact.
* the coupling tests fail when somebody changes the *config layer* -- a key added
  to ``TARGET_KEYS``, a value added to ``VAULT_TYPES`` -- and the generator does
  not know about it. :func:`~sopuli.config.schema._object` already refuses to
  build in that case; these say so in one place a reader can find, and pin the
  closed sets, which ``_object`` does not check.
* the example tests fail when the schema and the documented config disagree,
  which is the failure that would reach a user editing a file.

Comparison is on parsed JSON, never on text: ``core.autocrlf`` is on for most
Windows checkouts, so the committed file's line endings are a property of the
clone rather than of the schema.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from repo_files import requires_repo
from sopuli.config import (
    applications,
    auth,
    defaults,
    delivery,
    groups,
    loading,
    locking,
    personal_accounts,
    policies,
    profiles,
    reset_records,
    safety,
    target_sets,
    targets,
    vaults,
)
from sopuli.config.schema import SCHEMA_FILENAME, SchemaError, build_schema, dump_schema
from sopuli.config.yaml_loader import parse_yaml

ROOT = Path(__file__).resolve().parents[2]
COMMITTED = ROOT / "docs" / "schemas" / SCHEMA_FILENAME
REFERENCE = ROOT / "docs" / "design" / "01-configuration.md"

YAML_BLOCK = re.compile(r"```yaml\n(.*?)```", re.DOTALL)

REGENERATE = f"python -m sopuli.config.schema > docs/schemas/{SCHEMA_FILENAME}"

#: Every object in the schema, beside the constant the config layer validates it
#: with. The generator asserts this too; stating it here is what makes the rule
#: findable by somebody adding a key, rather than only by somebody who broke it.
KEY_SETS: dict[str, tuple[str, ...]] = {
    "": loading.TOP_LEVEL_KEYS,
    "safety": safety.SAFETY_KEYS,
    "vault": vaults.VAULT_KEYS,
    "vault_auth": vaults.AUTH_KEYS,
    "vault_patch": vaults.PATCHABLE_KEYS,
    "vault_tls": vaults.TLS_KEYS,
    "locking": locking.LOCKING_KEYS,
    "material_ref": auth.MATERIAL_KINDS,
    "target": targets.TARGET_KEYS,
    "admin": targets.ADMIN_KEYS,
    "admin_auth": targets.ADMIN_AUTH_KEYS,
    "target_oracle": targets.ORACLE_KEYS,
    "target_set": target_sets.TARGET_SET_KEYS,
    "target_patch": target_sets.PATCH_KEYS,
    "group": groups.GROUP_KEYS,
    "policy": policies.POLICY_KEYS,
    "password_policy": policies.PASSWORD_KEYS,
    "require": policies.REQUIRE_KEYS,
    "rotation_policy": policies.ROTATION_KEYS,
    "verify_policy": policies.VERIFY_KEYS,
    "account_policy": policies.ACCOUNT_KEYS,
    "profile": profiles.PROFILE_KEYS,
    "profile_rotation": profiles.ROTATION_KEYS,
    "profile_db": profiles.DB_KEYS,
    "defaults": defaults.DEFAULTS_KEYS,
    "runtime": defaults.RUNTIME_KEYS,
    "runtime_oracle": defaults.RUNTIME_ORACLE_KEYS,
    "application": applications.APPLICATION_KEYS,
    "override": applications.OVERRIDE_KEYS,
    "oracle_options": applications.ORACLE_KEYS,
    "personal_account": personal_accounts.PERSONAL_ACCOUNT_KEYS,
    "reset_records": reset_records.RESET_RECORDS_KEYS,
    "delivery": delivery.DELIVERY_KEYS,
}

#: Every closed set, beside the tuple :func:`~sopuli.config.fields.choice` is
#: given. Widening one is a one-line change in the config layer, and this is what
#: makes the published artefact follow it.
ENUMS: dict[str, tuple[Any, ...]] = {
    "/properties/version": loading.SUPPORTED_VERSIONS,
    "$defs/vault/properties/type": vaults.VAULT_TYPES,
    "$defs/vault/properties/kv_version": vaults.KV_VERSIONS,
    "$defs/vault_auth/properties/method": tuple(vaults.AUTH_METHODS),
    "$defs/target/properties/type": targets.TARGET_TYPES,
    "$defs/admin_auth/properties/method": tuple(targets.ADMIN_METHODS),
    "$defs/target_oracle/properties/scope": targets.ORACLE_SCOPES,
    "$defs/target_set/properties/type": targets.TARGET_TYPES,
    "$defs/target_patch/properties/type": targets.TARGET_TYPES,
    "$defs/password_policy/properties/charset": policies.CHARSETS,
    "$defs/password_policy/properties/first_char": policies.FIRST_CHARS,
    "$defs/rotation_policy/properties/strategy": policies.ROTATION_STRATEGIES,
    "$defs/profile_rotation/properties/strategy": policies.ROTATION_STRATEGIES,
    "$defs/verify_policy/properties/method": policies.VERIFY_METHODS,
    "$defs/profile/properties/output": profiles.OUTPUTS,
}


def _at(schema: dict[str, Any], pointer: str) -> dict[str, Any]:
    """Walk a ``/``-separated path into the generated schema."""
    node = schema
    for step in pointer.split("/"):
        if step:
            node = node[step]
    return node


def _properties(schema: dict[str, Any], name: str) -> dict[str, Any]:
    """The properties of the root (``""``) or of one ``$defs`` entry."""
    node = schema if not name else schema["$defs"][name]
    properties: dict[str, Any] = node["properties"]
    return properties


def _committed() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(COMMITTED.read_text(encoding="utf-8"))
    return document


def _blocks() -> list[str]:
    blocks: list[str] = YAML_BLOCK.findall(REFERENCE.read_text(encoding="utf-8"))
    return blocks


def _validator() -> Draft202012Validator:
    return Draft202012Validator(build_schema())


def _errors(document: Any) -> list[str]:
    return [
        f"{list(error.absolute_path)}: {error.message}"
        for error in _validator().iter_errors(document)
    ]


# --------------------------------------------------- the artefact is current ---


def test_the_committed_schema_is_what_the_generator_produces() -> None:
    """The one test this module is actually about.

    Without it the published file is a snapshot of what the model looked like
    once, and nothing says when that stopped being true.
    """
    requires_repo(COMMITTED)
    assert COMMITTED.exists(), f"the schema is not committed -- run: {REGENERATE}"
    assert _committed() == build_schema(), f"the committed schema is stale -- run: {REGENERATE}"


def test_the_schema_names_itself_after_the_file_it_is_committed_as() -> None:
    """``$id`` is what an editor resolves ``$ref``s against and what a config file
    points at. A file renamed without its ``$id`` following is a schema that
    claims to be somewhere it is not."""
    assert _committed()["$id"].endswith(f"/{COMMITTED.name}")


def test_the_dump_is_utf8_text_ending_in_one_newline() -> None:
    """The artefact is written by redirecting this text into a file, so it is the
    dump rather than the file that has to be well formed. A missing trailing
    newline shows up as a diff on the last line of every future regeneration."""
    text = dump_schema()
    assert text.endswith("}\n")
    assert not text.endswith("}\n\n")
    assert json.loads(text) == build_schema()


# ------------------------------------------------- coupled to the config layer ---


@pytest.mark.parametrize(("name", "keys"), sorted(KEY_SETS.items()))
def test_every_object_has_exactly_the_keys_the_builder_allows(
    name: str, keys: tuple[str, ...]
) -> None:
    schema = build_schema()
    assert tuple(_properties(schema, name)) == keys


@pytest.mark.parametrize(("pointer", "values"), sorted(ENUMS.items()))
def test_every_closed_set_is_the_one_the_builder_validates_against(
    pointer: str, values: tuple[Any, ...]
) -> None:
    assert _at(build_schema(), pointer)["enum"] == list(values)


def test_there_are_key_sets_and_enums_to_check() -> None:
    """Guards the two tables above: emptied by a bad edit, every test over them
    passes vacuously."""
    assert len(KEY_SETS) > 20
    assert len(ENUMS) > 10


def test_every_object_in_the_schema_has_a_row_in_the_table() -> None:
    """The table has to be **complete**, not merely non-empty.

    Guarding its size catches an emptied table and nothing else. A *new* section
    added without a row here is the failure that actually happens: generation
    still asserts the keys match, but the dedicated per-section check silently
    does not cover the new object, and nobody finds out because every test that
    exists still passes.

    It has happened five times: ``locking``, ``vault_tls``, ``vault_patch``,
    ``personal_account`` and ``reset_records``. All five are in the table above,
    and this is what keeps the sixth from getting in.
    """
    schema = build_schema()
    objects = {
        name
        for name, spec in schema["$defs"].items()
        if spec.get("type") == "object" and "properties" in spec
    }
    missing = sorted(objects - set(KEY_SETS))
    assert not missing, (
        f"these schema objects have no KEY_SETS row, so nothing checks their keys "
        f"against the builder's constant: {missing}"
    )


def test_the_inline_form_is_the_application_entry_hoisted() -> None:
    """§1 calls the inline form "exactly sugar for a single unnamed application
    entry". Two subschemas that merely looked alike would let the sugar and the
    entry accept different things, which is the one difference §1 says there is
    not."""
    schema = build_schema()
    root = _properties(schema, "")
    entry = _properties(schema, "application")

    for key in applications.INLINE_KEYS:
        assert root[key] == entry[key], f"the inline `{key}:` differs from the entry's"


def test_every_secret_bearing_auth_key_is_typed_as_a_material_ref() -> None:
    """P2 in the artefact. A material key typed as a string would have an editor
    completing a credential straight into a file that is committed and shared, and
    the schema is the thing a reader meets before any validator runs.

    The partition is asserted with it: material is the default and inline is the
    exception, so a key in both lists would be a string here and a MaterialRef in
    the builder.
    """
    properties = _properties(build_schema(), "vault_auth")

    assert set(vaults.AUTH_MATERIAL_KEYS).isdisjoint(vaults.AUTH_IDENTITY_KEYS)
    assert vaults.AUTH_MATERIAL_KEYS, "no material keys -- the derivation broke"
    for key in vaults.AUTH_MATERIAL_KEYS:
        assert properties[key] == {"$ref": "#/$defs/material_ref"}, key


def test_the_auth_shorthand_offers_exactly_the_methods_that_need_nothing() -> None:
    """`auth: approle` has nowhere to say where role_id comes from, so the editor
    must not offer it -- the builder refuses it, and an editor that suggested it
    would be sending somebody to that error."""
    branches = _properties(build_schema(), "vault")["auth"]["oneOf"]
    (shorthand,) = [branch for branch in branches if "enum" in branch]

    assert shorthand["enum"] == sorted(
        method for method, spec in vaults.AUTH_METHODS.items() if spec.is_parameterless
    )
    assert "approle" not in shorthand["enum"]


def test_the_target_selector_offers_exactly_the_forms_the_builder_reads() -> None:
    """`targets:` on an application is a list, a group or a match, and nothing
    else -- the third form is what `build_target_selector` refuses to guess at."""
    branches = build_schema()["$defs"]["application_targets"]["oneOf"]
    named = [tuple(branch["properties"]) for branch in branches if "properties" in branch]

    assert branches[0]["type"] == "array"
    assert named == [(key,) for key in applications.TARGET_SELECTOR_KEYS]


def test_a_key_the_generator_does_not_know_stops_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The drift alarm itself, exercised the way it would really fire.

    A key added to the config layer and not to the generator must not produce a
    schema that quietly omits it -- that is precisely the silent divergence the
    issue asks to make impossible.
    """
    monkeypatch.setattr(targets, "TARGET_KEYS", (*targets.TARGET_KEYS, "region"))

    with pytest.raises(SchemaError, match="region"):
        build_schema()


def test_a_key_the_generator_still_describes_stops_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other direction: a key removed from the config layer leaves the schema
    advertising something the tool now rejects, which is worse than omitting it
    -- an editor would complete a key that fails to load."""
    monkeypatch.setattr(targets, "TARGET_KEYS", tuple(k for k in targets.TARGET_KEYS if k != "dsn"))

    with pytest.raises(SchemaError, match="dsn"):
        build_schema()


# ------------------------------------------------------- against real config ---


def test_the_worked_example_validates() -> None:
    """§2's 129-line file is the config a reader meets first. If the published
    schema rejects it, the schema is wrong -- the document is the specification."""
    complete = [block for block in _blocks() if "version:" in block and "runtime:" in block]
    assert len(complete) == 1, "expected exactly one complete worked example in §2"

    assert _errors(parse_yaml(complete[0])) == []


def test_the_two_application_example_validates_on_that_estate() -> None:
    """§3 is a fragment: its binding on §2's estate, which is how
    ``test_design_document_examples.py`` already reads it."""
    estate = {
        key: value
        for key, value in parse_yaml(next(b for b in _blocks() if "runtime:" in b)).items()
        if key != "applications"
    }
    fragment = parse_yaml(next(block for block in _blocks() if "monitoring" in block))

    assert _errors({**estate, **fragment}) == []


def test_the_smallest_legal_file_validates() -> None:
    """A file with a version and nothing else. §1 permits a config that declares
    no accounts, and CI runs the binary against exactly this."""
    assert _errors({"version": 1}) == []


@pytest.mark.parametrize(
    ("why", "document"),
    [
        ("an unknown section", {"version": 1, "targts": []}),
        (
            "an unknown key inside a target",
            {"version": 1, "targets": [{"name": "t", "type": "oracle", "dsn": "d", "vualt": "v"}]},
        ),
        ("a missing version", {"targets": []}),
        ("an unsupported version", {"version": 2}),
        (
            "a charset that is not in §8",
            {"version": 1, "policies": {"p": {"password": {"charset": "alnumm"}}}},
        ),
        (
            "an empty admin block",
            {"version": 1, "targets": [{"name": "t", "type": "oracle", "dsn": "d", "admin": {}}]},
        ),
        (
            "two outer dimensions",
            {
                "version": 1,
                "target_sets": {
                    "s": {
                        "name": "{a}",
                        "type": "oracle",
                        "dsn": "d",
                        "for_each": {"a": {"x": {}}, "b": {"y": {}}},
                    }
                },
            },
        ),
        ("a group matching everything", {"version": 1, "groups": {"g": {"match": {}}}}),
        (
            "auth material written inline",
            {
                "version": 1,
                "vaults": {
                    "v": {
                        "type": "hashicorp",
                        "auth": {"method": "approle", "role_id": "0000", "secret_id": {"env": "S"}},
                    }
                },
            },
        ),
        (
            "a material ref naming two sources",
            {
                "version": 1,
                "vaults": {
                    "v": {
                        "type": "hashicorp",
                        "auth": {"method": "token", "token": {"env": "T", "file": "~/.token"}},
                    }
                },
            },
        ),
        (
            "the shorthand of a method that needs material",
            {"version": 1, "vaults": {"v": {"type": "hashicorp", "auth": "approle"}}},
        ),
    ],
)
def test_the_schema_refuses(why: str, document: dict[str, Any]) -> None:
    """P3: "a typo in a credential tool must never be silently ignored". These are
    the cases the *editor* has to catch, since it never runs the validators."""
    assert _errors(document), f"the schema accepted {why}"

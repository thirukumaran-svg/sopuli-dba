"""The JSON output is a versioned contract (invariant 12), so it is validated.

What a command actually prints is checked against
``docs/schemas/sopuli-run-1.0.schema.json`` — not against a hand-written
expectation that could drift from the schema without anyone noticing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

from sopuli.cli import cli
from sopuli.exit_codes import ExitCode
from sopuli.output.document import RunDocument, Summary, to_rfc3339, utc_now

REPO_ROOT = Path(__file__).resolve().parents[1]
RUN_SCHEMA = REPO_ROOT / "docs" / "schemas" / "sopuli-run-1.0.schema.json"


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(loaded)
    return loaded


@pytest.fixture(scope="module")
def validator(schema: dict[str, Any]) -> Draft202012Validator:
    return Draft202012Validator(schema)


def _errors(validator: Draft202012Validator, document: dict[str, Any]) -> list[str]:
    return [f"{list(error.path)}: {error.message}" for error in validator.iter_errors(document)]


def test_emitted_document_validates(validator: Draft202012Validator) -> None:
    result = CliRunner().invoke(cli, ["config", "show", "--output", "json"])
    assert result.exit_code == ExitCode.SUCCESS
    assert _errors(validator, json.loads(result.output)) == []


def test_document_from_the_builder_validates(validator: Draft202012Validator) -> None:
    document = RunDocument.start("config.validate").finish(
        ExitCode.SUCCESS, Summary(total=1, ok=1, changed=0, failed=0)
    )
    assert _errors(validator, document.to_dict()) == []


def test_optional_sections_are_omitted_not_nulled() -> None:
    """``plan``/``results``/``diagnostics`` are typed object/array by the schema.

    Emitting them as ``null`` would fail validation, so absence has to mean
    absence.
    """
    document = RunDocument.start("config.show").finish(ExitCode.SUCCESS).to_dict()
    for optional in ("plan", "results", "diagnostics"):
        assert optional not in document


def test_timestamps_are_rfc3339_utc_with_trailing_z() -> None:
    stamp = to_rfc3339(utc_now())
    assert stamp.endswith("Z")
    assert "+00:00" not in stamp


def test_correlation_id_is_unique_per_run() -> None:
    """One id joins the JSON, the DB audit trail and the vault version history."""
    first = RunDocument.start("config.show").correlation_id
    second = RunDocument.start("config.show").correlation_id
    assert first != second


def test_command_is_a_value_the_schema_allows(schema: dict[str, Any]) -> None:
    """``command`` is a closed enum, so a new verb needs a schema change too."""
    assert "config.show" in schema["properties"]["command"]["enum"]


def test_actor_never_carries_a_token() -> None:
    """The schema permits vault_identity but it must be an identity, not a secret."""
    document = RunDocument.start("config.show").finish(ExitCode.SUCCESS).to_dict()
    actor = document["invocation"]["actor"]
    assert set(actor) <= {"os_user", "host", "vault_identity", "scheduled"}

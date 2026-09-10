"""The JSON output is a versioned contract (invariant 12), so it is validated.

What a command actually prints is checked against the published run schema —
``docs/schemas/sopuli-run-<SCHEMA_VERSION>.schema.json``, found from the
producer's own constant — not against a hand-written expectation that could
drift from the schema without anyone noticing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

from sopuli.cli import cli
from sopuli.exit_codes import ExitCode
from sopuli.output.document import (
    SCHEMA_VERSION,
    Diagnostic,
    Option,
    RunDocument,
    Summary,
    to_rfc3339,
    utc_now,
)

#: The smallest file the loader accepts, as `tests/conftest.py` spells it.
#: Duplicated rather than imported: `tests` is not a package, and importing
#: the conftest by name gives mypy the same file under two module names.
MINIMAL_CONFIG = "version: 1\n"

REPO_ROOT = Path(__file__).resolve().parents[1]
#: Derived from the producer's own version. The published file is renamed on
#: every bump (03-json-output.md section 8), so naming it literally here means
#: the next bump validates against the previous contract until someone notices.
RUN_SCHEMA = REPO_ROOT / "docs" / "schemas" / f"sopuli-run-{SCHEMA_VERSION}.schema.json"


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


def test_emitted_document_validates(validator: Draft202012Validator, config_file: Path) -> None:
    """Through a real command, against a real config file.

    The file is named rather than discovered: `config show` searches the working
    directory and the user's config directory now, and a contract test must not
    depend on what the machine running it happens to have there.
    """
    result = CliRunner().invoke(
        cli, ["config", "show", "--config", str(config_file), "--output", "json"]
    )
    assert result.exit_code == ExitCode.SUCCESS
    assert _errors(validator, json.loads(result.output)) == []


def test_document_from_the_builder_validates(validator: Draft202012Validator) -> None:
    document = RunDocument.start("config.validate").finish(
        ExitCode.SUCCESS, Summary(total=1, ok=1, changed=0, failed=0)
    )
    assert _errors(validator, document.to_dict()) == []


def test_a_document_carrying_diagnostics_validates(validator: Draft202012Validator) -> None:
    """``diagnostics`` is where a config warning goes in ``--output json``.

    The schema requires ``level`` and ``message`` and forbids anything it does
    not name, so the shape is not obvious enough to assume -- and this is the
    only path by which a §10 warning reaches a machine reader.
    """
    document = RunDocument.start("config.validate")
    document.diagnostics = [Diagnostic(level="warning", message="profile `prod` names nothing")]
    document.finish(ExitCode.SUCCESS)

    emitted = document.to_dict()

    assert _errors(validator, emitted) == []
    assert emitted["diagnostics"] == [
        {"level": "warning", "message": "profile `prod` names nothing"}
    ]


def test_a_document_carrying_options_validates(validator: Draft202012Validator) -> None:
    """``invocation.options`` is the machine-readable form of ``--explain`` (P3).

    The schema requires ``value`` and ``source``, forbids anything else, and pins
    ``source`` to an enum -- so a layer renamed in the resolver has to fail here
    as well as in ``tests/settings/test_registry.py``.
    """
    document = RunDocument.start(
        "config.show",
        options={
            "output": Option(value="json", source="cli", source_detail="--output (verb)"),
            "safety.dry_run": Option(value=True, source="env", source_detail="SOPULI_DRY_RUN"),
        },
    )
    document.finish(ExitCode.SUCCESS)

    emitted = document.to_dict()

    assert _errors(validator, emitted) == []
    assert emitted["invocation"]["options"]["safety.dry_run"] == {
        "value": True,
        "source": "env",
        "source_detail": "SOPULI_DRY_RUN",
    }


def test_options_are_omitted_when_nothing_overrode_anything(
    validator: Draft202012Validator,
) -> None:
    """An empty object would say "nothing overrode anything" once per run, in a
    document consumers diff. Absent says it without saying it every time."""
    document = RunDocument.start("config.show").finish(ExitCode.SUCCESS)

    emitted = document.to_dict()

    assert "options" not in emitted["invocation"]
    assert _errors(validator, emitted) == []


def test_an_option_omits_a_source_detail_it_does_not_have() -> None:
    """A built-in default has no location to point at, and ``source_detail`` is
    typed as a string -- so it is omitted rather than nulled, like every other
    optional field here."""
    assert set(Option(value="text", source="builtin").to_dict()) == {"value", "source"}


def test_a_list_valued_option_reaches_json_as_an_array() -> None:
    """``confirm_environments`` resolves to a tuple, which JSON has no type for.

    No command emits one yet -- the safety block needs the config layer to reach
    the resolver -- but the conversion is here rather than at whichever call site
    first needs it, for the reason redaction is.
    """
    emitted = Option(value=("dev", "prod"), source="defaults").to_dict()

    assert emitted["value"] == ["dev", "prod"]
    assert json.dumps(emitted)


def test_a_diagnostic_omits_the_fields_it_has_no_value_for() -> None:
    """Same rule as the optional sections below, one level down: a run-level
    message has no target and no account, and omitting them keeps a consumer
    testing for presence and one testing for null from disagreeing."""
    emitted = Diagnostic(level="warning", message="m").to_dict()

    assert set(emitted) == {"level", "message"}


def test_optional_sections_are_omitted_not_nulled() -> None:
    """``plan``/``results``/``diagnostics`` are typed object/array by the schema.

    Emitting them as ``null`` would fail validation, so absence has to mean
    absence.
    """
    document = RunDocument.start("config.show").finish(ExitCode.SUCCESS).to_dict()
    for optional in ("plan", "results", "diagnostics"):
        assert optional not in document


# ------------------------------------------- invocation.config_files (#402) ---


def test_a_real_run_names_the_config_file_it_read(config_file: Path) -> None:
    """The field was in the schema and in the committed example for months and
    no run wrote it (#402), so this asserts the producer rather than the shape.

    Through the CLI on purpose: the gap was between what the document *could*
    carry and what the wiring filled in, and a test that built a
    :class:`RunDocument` by hand would have passed throughout.
    """
    result = CliRunner().invoke(
        cli, ["target", "list", "--config", str(config_file), "--output", "json"]
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert json.loads(result.output)["invocation"]["config_files"] == [str(config_file)]


def test_config_files_is_absent_when_no_layer_was_loaded() -> None:
    """Absent and not empty, which is this document's rule everywhere.

    Not "a command that needs no config": there is no such verb, since
    `_pass_invocation` loads one before any command body runs (found in review
    on #402 -- an earlier version of this named `doctor` and `policy sample`,
    both of which exit 9 without a file). What absence means is that the run got
    no further than trying, which is why the empty array would be the wrong
    shape: it would say the run looked and found nothing.
    """
    document = RunDocument.start("policy.sample").finish(ExitCode.CONFIG_INVALID).to_dict()
    assert "config_files" not in document["invocation"]


def test_config_files_keeps_layering_order(tmp_path: Path) -> None:
    """Through repeated `--config`, because the order is the contract.

    `01-configuration.md` §5 layers later files over earlier ones, so a document
    that sorted or reversed these would describe a precedence the run did not
    use. Two names that sort the other way round, so a producer that sorted
    would fail here rather than pass by luck.

    End to end rather than by assigning ``config_files`` directly (found in
    review on #402): the claim under test is about the *wiring* reading
    ``Invocation.sources`` in order, and a test that set the field itself would
    have exercised only the serialiser and passed through any regression there.
    """
    site = tmp_path / "z-site.yaml"
    team = tmp_path / "a-team.yaml"
    for path in (site, team):
        path.write_text(MINIMAL_CONFIG, encoding="utf-8")
        if sys.platform != "win32":
            path.chmod(0o600)

    result = CliRunner().invoke(
        cli,
        ["target", "list", "--config", str(site), "--config", str(team), "--output", "json"],
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert json.loads(result.output)["invocation"]["config_files"] == [str(site), str(team)]


def test_the_committed_example_carries_no_field_the_producer_cannot_write() -> None:
    """What let `config_files` sit unproduced for months (#402).

    ``tests/test_schemas.py`` validates the example against the schema, and it
    passed the whole time -- conformance is not the claim *a run produces this*.
    The example is hand-written and cited from the design documents, so a key in
    it that no run can emit is a documented lie about the tool's output.

    Checked as a subset rather than an equality: an example showing a narrower
    run than the maximum is exactly what an example is for.
    """
    every_field = RunDocument.start("creds.check")
    every_field.profile = "scheduled"
    every_field.config_files = ("/etc/sopuli/config.yaml",)
    every_field.selection = {"applications": ["orders-app"]}
    every_field.options = {"output": Option(value="json", source="cli")}
    producible = set(every_field.finish(ExitCode.SUCCESS).to_dict()["invocation"])

    example = json.loads(
        (REPO_ROOT / "docs" / "schemas" / "example-creds-check-drift.json").read_text(
            encoding="utf-8"
        )
    )
    assert set(example["invocation"]) <= producible


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
    assert set(actor) <= {"os_user", "host", "vault_identity", "unattended"}

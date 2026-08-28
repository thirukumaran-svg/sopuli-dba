"""The `plan` section against the published schema, and the plan a person reads.

Invariant 12: the schema is the test fixture, not documentation written
afterwards. `plan` is stricter than most sections -- `additionalProperties: false`
on the section, on every `units[]` item and on `blast_radius` -- so a field added
in the wrong shape fails here rather than in a consumer.

The text half is checked for the two things UC-1 §7's worked output actually
promises: the header is a sentence an operator can check against what they meant
to type, and sharing is never invisible.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from sopuli.config.loading import build_config
from sopuli.exit_codes import ExitCode
from sopuli.output.document import SCHEMA_VERSION, RunDocument, Summary
from sopuli.output.plan_view import render_plan
from sopuli.plan import ACTION_KINDS, build

REPO_ROOT = Path(__file__).resolve().parents[1]

VAULTS: dict[str, Any] = {"vault-prod": {"type": "hashicorp"}}

APPDB: dict[str, Any] = {
    "type": "oracle",
    "name": "appdb-{env}-{tenant}",
    "dsn": "{host}:1521/{tenant}.pdb.example.com",
    "environment": "{env}",
    "vault": "vault-prod",
    "oracle": {"scope": "pdb", "container": "{tenant}pdb"},
    "for_each": {"env": {"prod": {"host": "db-prod.example.com", "tenant": ["alpha", "beta"]}}},
}


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = REPO_ROOT / "docs" / "schemas" / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
    return Draft202012Validator(json.loads(schema.read_text(encoding="utf-8")))


def estate(**entry: Any) -> Any:
    application = {"name": "acme", "targets": {"group": "app-pdbs"}, **entry}
    return build_config(
        {
            "version": 1,
            "vaults": VAULTS,
            "target_sets": {"appdb": APPDB},
            "groups": {"app-pdbs": {"match": {"target_set": "appdb"}}},
            "applications": [application],
        }
    )


def document_with(section: dict[str, Any] | None) -> dict[str, Any]:
    document = RunDocument.start("creds.check")
    document.plan = section
    return document.finish(ExitCode.SUCCESS, Summary()).to_dict()


# ------------------------------------------------------------- the schema ---


def test_a_plan_validates(validator: Draft202012Validator) -> None:
    plan = build(
        estate(accounts=["acme_web_user"], secret_template="apps/acme/{tenant}#password"),
        intent=["verify"],
    )

    assert not list(validator.iter_errors(document_with(plan.as_json())))


def test_a_shared_plan_validates(validator: Draft202012Validator) -> None:
    """The one-document-many-targets case, which is what the section exists for."""
    plan = build(
        estate(
            accounts=["acme_web_user", "acme_api_user"],
            secret_template="apps/acme/db#DB_CREDENTIALS/{account}",
        ),
        intent=["generate", "vault_write_pending"],
    )

    section = plan.as_json()
    assert section["shared_secrets"][0]["accounts"] == ["acme_web_user", "acme_api_user"]
    assert not list(validator.iter_errors(document_with(section)))


def test_a_plan_whose_store_is_unresolved_validates(validator: Draft202012Validator) -> None:
    """The regression Copilot caught: `secret_ref.vault` is a required *string*,
    so a binding whose store nothing has named yet (C15/#118) emitted
    `{"vault": null}` and failed validation. It now emits no `secret` at all."""
    config = build_config(
        {
            "version": 1,
            "vaults": VAULTS,
            "targets": [{"name": "plain", "type": "oracle", "dsn": "h:1521/x"}],
            "applications": [
                {
                    "name": "acme",
                    "targets": ["plain"],
                    "accounts": ["acme_web_user"],
                    "secret_template": "apps/acme/{account}#password",
                }
            ],
        }
    )

    section = build(config, intent=["verify"]).as_json()
    assert "secret" not in section["units"][0]
    assert not list(validator.iter_errors(document_with(section)))


def test_a_command_that_plans_nothing_has_no_section() -> None:
    """Absent means the command plans nothing -- `config show`, `doctor`, `lock
    status` -- rather than a planning command declining to say."""
    assert "plan" not in document_with(None)


def test_every_action_kind_is_one_the_schema_knows(validator: Draft202012Validator) -> None:
    """The enum is copied into `sopuli.plan` rather than read from the schema at
    runtime, so something has to hold the copy honest."""
    schema = json.loads(
        (REPO_ROOT / "docs" / "schemas" / f"sopuli-run-{SCHEMA_VERSION}.schema.json").read_text(
            encoding="utf-8"
        )
    )

    assert frozenset(schema["$defs"]["action_kind"]["enum"]) == ACTION_KINDS


# --------------------------------------------------------------- the text ---


def test_the_header_says_what_the_count_is_of() -> None:
    """`2 accounts x 2 targets = 4 checks` is a sentence an operator can check
    against what they meant to type; `4 units` is not.

    ASCII `x`, per UC-1 §7's own worked output: nothing this codebase emits is
    outside ASCII, and redirected stdout on Windows is cp1252 (#12).
    """
    plan = build(
        estate(
            accounts=["acme_web_user", "acme_api_user"],
            secret_template="apps/acme/{tenant}#{account}",
        ),
        intent=["verify"],
    )

    assert (
        render_plan(plan, noun="check")
        .splitlines()[0]
        .startswith("Plan: 2 accounts x 2 targets = 4 checks")
    )


def test_the_header_names_the_environments_it_reaches() -> None:
    """`max_targets` is a number and `confirm_environments` is not: an operator
    scanning for whether this run reaches prod is reading for the word."""
    plan = build(estate(accounts=["acme_web_user"]), intent=["verify"])

    assert "prod" in render_plan(plan).splitlines()[0]


def test_one_of_each_reads_in_the_singular() -> None:
    plan = build(
        estate(accounts=["acme_web_user"], targets={"match": {"tenant": "alpha"}}),
        intent=["verify"],
    )

    assert (
        render_plan(plan, noun="check")
        .splitlines()[0]
        .startswith("Plan: 1 account x 1 target = 1 check")
    )


def test_the_table_carries_a_row_per_unit_with_its_document() -> None:
    """`vault:path` -- the spelling `lock status` prints and `lock break` takes,
    because a unit's document is what a lock is keyed on (Q2, #83)."""
    plan = build(
        estate(accounts=["acme_web_user"], secret_template="apps/acme/{tenant}#password"),
        intent=["verify"],
    )

    rendered = render_plan(plan)
    assert "ACCOUNT" in rendered
    assert "vault-prod:apps/acme/alpha" in rendered
    assert "vault-prod:apps/acme/beta" in rendered


def test_a_unit_with_no_document_shows_a_placeholder_rather_than_none() -> None:
    plan = build(estate(accounts=["acme_web_user"]), intent=["verify"])

    assert "None" not in render_plan(plan)


def test_sharing_is_reported_under_a_heading_that_says_what_it_is() -> None:
    """Sharing is legal and often intended (§7); what it must not be is
    invisible. The word is on the line, so `NO_COLOR` loses nothing."""
    plan = build(
        estate(accounts=["acme_web_user"], secret_template="apps/acme/db#password"),
        intent=["verify"],
    )

    assert "shared secrets (1 document):" in render_plan(plan)


def test_nothing_shared_prints_no_heading() -> None:
    plan = build(
        estate(
            accounts=["acme_web_user"],
            targets={"match": {"tenant": "alpha"}},
            secret_template="apps/acme/{tenant}#password",
        ),
        intent=["verify"],
    )

    assert "shared secrets" not in render_plan(plan)


def test_the_rendered_plan_is_ascii() -> None:
    """P4 requires identical behaviour on Windows, where redirected stdout is
    cp1252. A `UnicodeEncodeError` in a plan header would be the last thing an
    operator sees before a run they cannot start."""
    plan = build(
        estate(accounts=["acme_web_user"], secret_template="apps/acme/db#password"),
        intent=["verify"],
    )

    render_plan(plan).encode("ascii")

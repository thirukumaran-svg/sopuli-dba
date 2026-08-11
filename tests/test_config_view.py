"""The two views of a configuration (§2, §4, §7).

The split under test is the useful one. Without `--resolved` the view shows the
*file*: a target set is a template with its dimensions, because the question is
whether the YAML says what it looks like it says. With it, the view shows the
*consequences*: 21 targets, their labels, and the secret ref each account
resolves to.

Both are offline by construction -- these tests build a Config and render it,
and there is nothing in the path that could open a socket even if it wanted to.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from sopuli.config import Config, build_config
from sopuli.output.config_view import build_section, render_text

REPO_ROOT = Path(__file__).resolve().parents[1]
RUN_SCHEMA = REPO_ROOT / "docs" / "schemas" / "sopuli-run-1.1.schema.json"

PATHS = [Path("/etc/sopuli/config.yaml")]

DOCUMENT: dict[str, Any] = {
    "version": 1,
    "vaults": {
        "vault-dev": {"type": "hashicorp", "addr": "https://vault-dev.example.com"},
        "local": {"type": "file", "non_production": True},
    },
    "targets": [
        {
            "name": "cdb-root-dev",
            "type": "oracle",
            "dsn": "db-dev.example.com:1521/CDBDEV.pdb.example.com",
            "environment": "dev",
            "vault": "vault-dev",
            "oracle": {"scope": "cdb_root"},
        }
    ],
    "target_sets": {
        "appdb": {
            "type": "oracle",
            "name": "appdb-{env}-{tenant}",
            "dsn": "{host}:1521/{tenant}.pdb.example.com",
            "environment": "{env}",
            "vault": "vault-dev",
            "oracle": {"scope": "pdb", "container": "{tenant}pdb"},
            "for_each": {
                "env": {"dev": {"host": "db-dev.example.com", "tenant": ["alpha", "beta"]}}
            },
            "overrides": {"appdb-dev-beta": {"dsn": "192.0.2.75:1521/legacy.example.com"}},
        }
    },
    "groups": {"app-pdbs": {"match": {"target_set": "appdb"}}},
    "policies": {"app-standard": {"password": {"length": 24}}},
    "applications": [
        {
            "name": "acme",
            "targets": {"group": "app-pdbs"},
            "accounts": ["acme_web_user"],
            "secret_template": "tenants/{tenant}#DB_CREDENTIALS/{account}",
            "policy": "app-standard",
        }
    ],
}


@pytest.fixture
def config() -> Config:
    return build_config(DOCUMENT)


@pytest.fixture(scope="module")
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8")))


# ------------------------------------------------------------ as loaded ---


def test_the_default_view_shows_the_file_not_its_consequences(config: Config) -> None:
    """A target set appears as the template it is. Showing the 2 targets it
    generates would answer the question `--resolved` is for."""
    text = render_text(PATHS, config, resolved=False)

    assert "appdb-{env}-{tenant}" in text
    assert "appdb-dev-alpha" not in text


def test_the_default_view_names_every_section_of_the_file(config: Config) -> None:
    text = render_text(PATHS, config, resolved=False)

    for section in ("vaults", "targets", "target_sets", "groups", "policies", "applications"):
        assert f"\n{section}\n" in text


def test_a_non_production_store_is_marked(config: Config) -> None:
    """The marking exists so a development store is obviously one (P2), which
    only works if the view says so."""
    assert "non-production" in render_text(PATHS, config, resolved=False)


def test_an_application_shows_what_it_selects_and_what_masters_it(config: Config) -> None:
    text = render_text(PATHS, config, resolved=False)

    assert "group app-pdbs" in text
    assert "tenants/{tenant}#DB_CREDENTIALS/{account}" in text


def test_a_section_the_file_does_not_have_is_left_out(config: Config) -> None:
    """An empty heading is noise, and a reader counts headings."""
    assert "\nprofiles\n" not in render_text(PATHS, config, resolved=False)


# -------------------------------------------------------------- resolved ---


def test_the_resolved_view_shows_the_expanded_estate(config: Config) -> None:
    text = render_text(PATHS, config, resolved=True)

    assert "appdb-dev-alpha" in text
    assert "appdb-dev-beta" in text


def test_the_resolved_view_names_the_source_of_every_target(config: Config) -> None:
    """§4's SOURCE column, in §4's words: generation is invisible until it goes
    wrong, and this is where it stops being invisible."""
    text = render_text(PATHS, config, resolved=True)

    assert "targets" in text
    assert "target_set appdb" in text
    assert "override" in text


def test_the_resolved_view_counts_the_estate(config: Config) -> None:
    assert "3 targets (1 explicit, 2 generated, 1 overridden)" in render_text(
        PATHS, config, resolved=True
    )


def test_a_target_nothing_manages_is_shown_rather_than_warned_about(config: Config) -> None:
    """§2's CDB root: declared for a use case that is not designed yet. The one
    thing it must not be is invisible."""
    text = render_text(PATHS, config, resolved=True)

    assert "1 target managed by nothing: cdb-root-dev" in text


def test_the_resolved_view_shows_the_ref_each_account_lands_on(config: Config) -> None:
    """§1's safety-critical part, printed before anything runs."""
    text = render_text(PATHS, config, resolved=True)

    assert "tenants/alpha#DB_CREDENTIALS/acme_web_user" in text
    assert "tenants/beta#DB_CREDENTIALS/acme_web_user" in text


def test_bindings_are_grouped_under_the_application_that_owns_them(config: Config) -> None:
    assert "bindings: acme (1 account, 2 targets)" in render_text(PATHS, config, resolved=True)


def test_the_layered_sources_are_all_named(config: Config) -> None:
    """Rendered through `str(Path)`, so the separators are the platform's -- a
    Windows user is not shown a POSIX path for a file on their own disk."""
    paths = [Path("/etc/sopuli/config.yaml"), Path("/home/dba/overlay.yaml")]

    text = render_text(paths, config, resolved=True)

    assert f"config: {paths[0]}" in text
    assert f"{paths[1]} (layered)" in text


def test_rendering_is_deterministic(config: Config) -> None:
    """`config show` output is diffed between runs and pasted into tickets."""
    assert render_text(PATHS, config, resolved=True) == render_text(PATHS, config, resolved=True)


# ------------------------------------------------------------------ json ---


def test_the_declared_section_is_the_merged_document(config: Config) -> None:
    """Not a reshaping of it. The question is what the YAML says after layering,
    and normalising on the way out would be a second answer to that question."""
    section = build_section(PATHS, config, DOCUMENT, resolved=False)

    assert section["resolved"] is False
    assert section["declared"] == DOCUMENT
    assert "targets" not in section


def test_the_resolved_section_carries_targets_and_bindings(config: Config) -> None:
    section = build_section(PATHS, config, DOCUMENT, resolved=True)

    assert section["resolved"] is True
    assert "declared" not in section
    assert [target["name"] for target in section["targets"]] == [
        "cdb-root-dev",
        "appdb-dev-alpha",
        "appdb-dev-beta",
    ]
    assert [binding["target"] for binding in section["bindings"]] == [
        "appdb-dev-alpha",
        "appdb-dev-beta",
    ]


def test_a_target_carries_its_labels_and_provenance(config: Config) -> None:
    section = build_section(PATHS, config, DOCUMENT, resolved=True)
    beta = next(t for t in section["targets"] if t["name"] == "appdb-dev-beta")

    assert beta["labels"] == {"env": "dev", "target_set": "appdb", "tenant": "beta"}
    assert beta["target_set"] == "appdb"
    assert beta["overridden"] is True
    assert beta["managed"] is True


def test_an_unmanaged_target_says_so(config: Config) -> None:
    section = build_section(PATHS, config, DOCUMENT, resolved=True)
    root = next(t for t in section["targets"] if t["name"] == "cdb-root-dev")

    assert root["managed"] is False
    assert root["target_set"] is None


def test_a_binding_carries_the_ref_as_written(config: Config) -> None:
    """A string, because it round-trips exactly (§7) and lines up by eye with
    the config file. Never a value."""
    section = build_section(PATHS, config, DOCUMENT, resolved=True)

    assert section["bindings"][0] == {
        "application": "acme",
        "account": "acme_web_user",
        "target": "appdb-dev-alpha",
        "secret": "tenants/alpha#DB_CREDENTIALS/acme_web_user",
        "vault": "vault-dev",
        "policy": "app-standard",
    }


def test_the_sources_are_listed_in_layering_order(config: Config) -> None:
    paths = [Path("/etc/sopuli/config.yaml"), Path("/home/dba/overlay.yaml")]

    section = build_section(paths, config, DOCUMENT, resolved=False)

    assert section["sources"] == [str(paths[0]), str(paths[1])]


@pytest.mark.parametrize(
    "section",
    [
        {"sources": ["a"], "resolved": True, "bindings": []},
        {"sources": ["a"], "resolved": True, "targets": [], "bindings": [], "declared": {}},
        {"sources": ["a"], "resolved": False, "declared": {}, "targets": []},
        {"sources": ["a"], "resolved": False},
    ],
    ids=["resolved-without-targets", "resolved-with-declared", "declared-with-targets", "neither"],
)
def test_the_schema_holds_the_producer_to_one_shape_or_the_other(
    validator: Draft202012Validator, section: dict[str, Any]
) -> None:
    """`resolved` discriminates two shapes, so the schema has to enforce it.

    Without the `allOf`, a regression could emit `resolved: true` carrying no
    targets, or both shapes at once, and still validate -- a producer-side guard
    that guards nothing (§8).
    """
    document = {
        "schema_version": "1.1",
        "tool": {"name": "sopuli", "version": "0.0.0"},
        "command": "config.show",
        "invocation": {
            "correlation_id": "9f1c2e7a-4d3b-4a51-9d2c-0b7f8e6a1234",
            "started_at": "2026-08-11T09:00:00Z",
            "finished_at": "2026-08-11T09:00:01Z",
            "duration_ms": 1000,
            "actor": {"os_user": "dba", "host": "laptop"},
            "dry_run": False,
        },
        "config": section,
        "summary": {"total": 0, "ok": 0, "changed": 0, "failed": 0},
        "exit_code": 0,
    }

    assert list(validator.iter_errors(document)), "the schema accepted a shape it should refuse"


@pytest.mark.parametrize("resolved", [False, True], ids=["declared", "resolved"])
def test_both_views_validate_against_the_schema(
    config: Config, validator: Draft202012Validator, resolved: bool
) -> None:
    """Invariant 12: the JSON output is a versioned contract, and the schema is
    the test fixture rather than documentation written afterwards."""
    from sopuli.output.document import RunDocument, Summary

    document = RunDocument.start("config.show")
    document.config = build_section(PATHS, config, DOCUMENT, resolved=resolved)
    document.finish(0, Summary(total=3, ok=3, changed=0, failed=0))

    errors = [f"{list(e.path)}: {e.message}" for e in validator.iter_errors(document.to_dict())]
    assert errors == []

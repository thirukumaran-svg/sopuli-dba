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
import re
from pathlib import Path
from typing import Any

import click
import pytest
from jsonschema import Draft202012Validator

from sopuli.config import Config, Selection, build_config, filter_estate
from sopuli.config.model import Pairs
from sopuli.output.config_view import build_section, render_target_list, render_text
from sopuli.output.document import SCHEMA_VERSION

REPO_ROOT = Path(__file__).resolve().parents[1]
RUN_SCHEMA = REPO_ROOT / "docs" / "schemas" / f"sopuli-run-{SCHEMA_VERSION}.schema.json"

PATHS = [Path("/etc/sopuli/config.yaml")]

#: One ANSI-wrapped run of text, for reading the palette back out.
STYLED = re.compile(re.escape(chr(27)) + r"\[[0-9;]*m(.*?)" + re.escape(chr(27)) + r"\[0m")

DOCUMENT: dict[str, Any] = {
    "version": 1,
    "vaults": {
        "vault-dev": {"type": "hashicorp", "addr": "https://vault-dev.example.com"},
        "local": {"type": "file", "non_production": True, "locking": "advisory-only"},
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
    "reset_records": {"vault": "vault-dev", "prefix": "sopuli/personal-resets"},
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
    text = click.unstyle(render_text(PATHS, config, resolved=False))

    for section in ("vaults", "targets", "target_sets", "groups", "policies", "applications"):
        assert f"\n{section}\n" in text


def test_a_non_production_store_is_marked(config: Config) -> None:
    """The marking exists so a development store is obviously one (P2), which
    only works if the view says so."""
    assert "non-production" in render_text(PATHS, config, resolved=False)


def test_a_store_that_cannot_lock_is_marked_too(config: Config) -> None:
    """A store excused from locking is the other thing this column is for (Q2).

    Both notes share the column because both say the same kind of thing: this
    store is less than the default assumption. The two also co-occur -- the file
    backend in this fixture is exactly the store somebody would excuse -- so the
    rendering has to survive a row with both, which is why the fixture marks one
    store twice rather than adding a third.
    """
    text = click.unstyle(render_text(PATHS, config, resolved=False))

    assert "non-production, advisory-only" in text


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


def test_a_kind_that_contributed_nothing_is_left_out(config: Config) -> None:
    """`0 explicit` is the absence of a fact, not a fact. Every filtered estate
    and most unfiltered ones are entirely generated, and none of them should
    have to open with a zero."""
    generated_only = filter_estate(config, Selection(select=(("target_set", "appdb"),)))

    summary = render_text(PATHS, generated_only, resolved=True, match=(("target_set", "appdb"),))

    assert "2 targets (2 generated, 1 overridden)" in summary
    assert "0 explicit" not in summary


def test_the_breakdown_survives_when_one_kind_is_all_of_it(config: Config) -> None:
    """Not collapsed to a bare count: §4 keeps provenance visible because
    generation is invisible until it goes wrong."""
    generated_only = filter_estate(config, Selection(select=(("target_set", "appdb"),)))

    assert "(2 generated" in render_text(PATHS, generated_only, resolved=True)


def test_an_estate_with_nothing_in_it_says_so_without_a_breakdown(config: Config) -> None:
    """`0 targets ()` and `0 targets (0 explicit)` are both worse than the
    plain count, which is already the whole story."""
    empty = filter_estate(config, Selection(select=(("env", "staging"),)))

    assert "0 targets" in render_text(PATHS, empty, resolved=True)
    assert "0 targets (" not in render_text(PATHS, empty, resolved=True)


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
        "schema_version": SCHEMA_VERSION,
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


# ---------------------------------------------------------------- colour ---


#: A second estate, with a production target. Kept apart from DOCUMENT so the
#: counts every other test asserts do not move when the palette changes.
PRODUCTION_DOCUMENT: dict[str, Any] = {
    "version": 1,
    "vaults": {"vault-prod": {"type": "hashicorp"}},
    "targets": [
        {
            "name": "appdb-prod",
            "type": "oracle",
            "dsn": "db-prod.example.com:1521/PRODDB.pdb.example.com",
            "environment": "prod",
            "vault": "vault-prod",
        },
        {
            "name": "appdb-dev",
            "type": "oracle",
            "dsn": "db-dev.example.com:1521/DEVDB.pdb.example.com",
            "environment": "dev",
            "vault": "vault-prod",
        },
    ],
}


@pytest.fixture
def production() -> Config:
    return build_config(PRODUCTION_DOCUMENT)


def test_the_section_headings_are_styled(config: Config) -> None:
    """Structure, so the eye finds the sections without reading them."""
    text = render_text(PATHS, config, resolved=False)

    assert f"\n{click.style('vaults', bold=True)}\n" in text


def painted(text: str) -> set[str]:
    """Every styled fragment, with its padding trimmed.

    Reads the roles back out of the rendered text without knowing which colour
    any of them is, so a palette change cannot break a test about *what* is
    emphasised -- which is the part that has to stay true.
    """
    # A role may emit more than one code -- red *and* bold -- so the capture
    # can still hold one. Unstyling it leaves the text the reader sees.
    fragments = (click.unstyle(match).strip() for match in STYLED.findall(text))
    return {fragment for fragment in fragments if fragment}


def test_production_is_styled_and_no_other_environment_is(production: Config) -> None:
    """`prod` is the one value on this screen worth finding without reading:
    §9 keys `confirm_environments` on it. Colouring every environment would make
    the one that matters ordinary again."""
    emphasised = painted(render_text(PATHS, production, resolved=True))

    assert "prod" in emphasised
    assert "dev" not in emphasised


@pytest.mark.parametrize(
    ("word", "resolved"),
    [("override", True), ("non-production", False)],
    ids=["overridden-target", "non-production-store"],
)
def test_the_things_worth_finding_are_styled(config: Config, word: str, resolved: bool) -> None:
    """Each maps onto a field the `config` section already emits -- `overridden`
    and `non_production` -- rather than a second vocabulary that could disagree
    with it (03-json-output.md §1)."""
    lines = render_text(PATHS, config, resolved=resolved).splitlines()

    carrying = [line for line in lines if word in click.unstyle(line)]
    assert carrying, f"{word!r} is not in this view at all"
    assert any(line != click.unstyle(line) for line in carrying)


def test_colour_never_carries_meaning_on_its_own(production: Config) -> None:
    """§1's accessibility floor, asserted rather than intended.

    Everything the palette touches is already a word, so stripping the escapes
    loses decoration and nothing else. If a role were ever the *only* thing
    distinguishing two rows, this is where it would show up -- the word would
    have to be missing from the plain text.
    """
    plain = click.unstyle(render_text(PATHS, production, resolved=True))

    for word in ("prod", "dev", "targets", "appdb-prod", "-"):
        assert word in plain


# ------------------------------------------------------------ target list ---


def test_the_target_list_shows_the_estate(config: Config) -> None:
    text = render_target_list(PATHS, config)

    assert "appdb-dev-alpha" in text
    assert "cdb-root-dev" in text


def test_the_target_list_drops_the_vault_column(config: Config) -> None:
    """§4's example has no VAULT, and the omission is the difference between
    this and the resolved estate table: which store masters a target is a fact
    about the binding, and this view is about the target."""
    listed = click.unstyle(render_target_list(PATHS, config))
    resolved = click.unstyle(render_text(PATHS, config, resolved=True))

    assert "VAULT" in resolved
    assert "VAULT" not in listed


def test_the_target_list_shows_no_bindings(config: Config) -> None:
    """The narrower question. A binding table is what `config show --resolved`
    is for, and printing one here would make the two commands the same."""
    text = render_target_list(PATHS, config)

    assert "bindings:" not in text
    assert "tenants/alpha#DB_CREDENTIALS/acme_web_user" not in text


def test_the_target_list_names_the_source_of_every_target(config: Config) -> None:
    text = click.unstyle(render_target_list(PATHS, config))

    assert "target_set appdb" in text
    assert "override" in text


def test_the_target_list_counts_the_estate_the_same_way(config: Config) -> None:
    """Two commands disagreeing about how many targets exist is the bug worth
    catching, so the summary comes from one function rather than two."""
    summary = "3 targets (1 explicit, 2 generated, 1 overridden)"

    assert summary in render_target_list(PATHS, config)
    assert summary in render_text(PATHS, config, resolved=True)


def test_the_target_list_says_what_it_filtered_by(config: Config) -> None:
    filtered = filter_estate(config, Selection(select=(("env", "dev"),)))

    assert "select: env=dev" in render_target_list(PATHS, filtered, match=(("env", "dev"),))


def test_a_filter_matching_nothing_says_so_rather_than_printing_a_header(
    config: Config,
) -> None:
    empty = filter_estate(config, Selection(select=(("env", "staging"),)))

    text = render_target_list(PATHS, empty, match=(("env", "staging"),))

    assert "no targets carry env=staging" in text
    assert "NAME" not in text


def test_the_target_list_is_deterministic(config: Config) -> None:
    assert render_target_list(PATHS, config) == render_target_list(PATHS, config)


@pytest.mark.parametrize("match", [(), (("env", "staging"),)], ids=["estate", "nothing-matched"])
def test_the_target_list_shows_warnings_in_full(match: Pairs) -> None:
    """A command that reads a config and hides its findings is the same defect
    whichever view does it -- including the path where nothing matched, which
    is exactly when a warning about the file is worth reading."""
    config = build_config({**DOCUMENT, "profiles": {"dev": {"output": "json"}}})

    text = render_target_list(PATHS, filter_estate(config, Selection(select=match)), match=match)

    assert "1 warning:" in text
    assert "named after an environment" in text


# --------------------------------------------------------- shared secrets ---

#: The §2 layout: one document per tenant, several accounts in each.
SHARING: dict[str, Any] = {
    **DOCUMENT,
    "applications": [
        {
            **DOCUMENT["applications"][0],
            "accounts": ["acme_web_user", "acme_api_user"],
        }
    ],
}


@pytest.fixture
def sharing() -> Config:
    return build_config(SHARING)


def test_a_config_that_shares_nothing_says_nothing(config: Config) -> None:
    """One account per document per target: the ordinary case. An empty section
    would read like a finding that came back negative."""
    assert "shared secrets" not in render_text(PATHS, config, resolved=True)
    assert "shared_secrets" not in build_section(PATHS, config, DOCUMENT, resolved=False)
    assert "shared_secrets" not in build_section(PATHS, config, DOCUMENT, resolved=True)


def test_the_resolved_view_names_the_documents_more_than_one_account_lands_in(
    sharing: Config,
) -> None:
    """§7's rule that sharing is never invisible, as a section."""
    text = render_text(PATHS, sharing, resolved=True)

    assert "shared secrets (2 documents):" in text
    assert "tenants/alpha" in text
    assert "acme_web_user, acme_api_user" in text


def test_the_shared_section_is_marked_notable(sharing: Config) -> None:
    """Not an error -- sharing is legal. `notable` is the role for a fact worth
    catching the eye, and the word "shared" is on the line either way."""
    text = render_text(PATHS, sharing, resolved=True)

    assert any("shared secrets" in styled for styled in STYLED.findall(text))


def test_the_json_form_addresses_the_document(sharing: Config) -> None:
    section = build_section(PATHS, sharing, SHARING, resolved=True)

    assert section["shared_secrets"][0] == {
        "secret": {"vault": "vault-dev", "path": "tenants/alpha"},
        "targets": ["appdb-dev-alpha"],
        "accounts": ["acme_web_user", "acme_api_user"],
    }


def test_the_shared_section_validates(sharing: Config, validator: Draft202012Validator) -> None:
    document = {
        "schema_version": SCHEMA_VERSION,
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
        "config": build_section(PATHS, sharing, SHARING, resolved=True),
        "summary": {"total": 0, "ok": 0, "changed": 0, "failed": 0},
        "exit_code": 0,
    }

    validator.validate(document)


def test_a_shared_document_with_no_store_named_still_validates(
    validator: Draft202012Validator,
) -> None:
    """A binding can resolve with no store, and `secret_document.vault` is
    nullable for exactly that case -- unlike `secret_ref`, which describes a ref
    after resolution and requires one (C14). A profile still names a store here
    (C15), which is what keeps this file from being the narrow case
    C15 refuses at load: `vaults:` declares nothing for a profile or
    `SOPULI_VAULT` to point at."""
    document = {
        "version": 1,
        "vaults": {"vault-prod": {"type": "hashicorp"}},
        "profiles": {"scheduled": {"vault": "vault-prod"}},
        "targets": [
            {
                "name": "t1",
                "type": "oracle",
                "dsn": "db.example.com:1521/S.example.com",
                "environment": "dev",
                "oracle": {"scope": "pdb", "container": "P"},
            }
        ],
        "accounts": ["acme_web_user", "acme_api_user"],
        "secret_template": "apps/acme/db#DB_CREDENTIALS/{account}",
    }
    section = build_section(PATHS, build_config(document), document, resolved=True)

    assert section["shared_secrets"][0]["secret"] == {"vault": None, "path": "apps/acme/db"}
    validator.validate(
        {
            "schema_version": SCHEMA_VERSION,
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
    )

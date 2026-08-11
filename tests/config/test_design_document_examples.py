"""Every YAML example in the configuration reference must actually parse.

CLAUDE.md: the design documents are the specification, and if they disagree with
the code that is a bug in one of them. This is the cheapest place to find that
out. `01-configuration.md` §2 is a 129-line worked example nobody has ever run;
without this it stays prose that only looks like a config file.

It also pins the hardened loader against the real thing. Rejecting duplicate
keys and narrowing YAML 1.1 booleans are changes to the dialect, and the test
that they did not break the documented config is to feed them the documented
config.

**If a future example is meant to be invalid** -- illustrating an error message,
say -- fence it as ```` ```text ```` rather than ```` ```yaml ````, or this test
will fail and be right to.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

import pytest

from sopuli.config.applications import build_applications
from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config, load_document
from sopuli.config.yaml_loader import parse_yaml

REFERENCE = Path(__file__).resolve().parents[2] / "docs" / "design" / "01-configuration.md"

YAML_BLOCK = re.compile(r"```yaml\n(.*?)```", re.DOTALL)


def _blocks() -> list[tuple[int, str]]:
    text = REFERENCE.read_text(encoding="utf-8")
    return [(index, match) for index, match in enumerate(YAML_BLOCK.findall(text))]


def test_the_reference_has_examples_to_check() -> None:
    """Guards the regex: a change to the fence style would otherwise leave every
    test below passing over an empty list."""
    assert len(_blocks()) >= 4


@pytest.mark.parametrize(("index", "block"), _blocks(), ids=lambda value: str(value)[:20])
def test_every_yaml_example_parses(index: int, block: str) -> None:
    parse_yaml(block, source=REFERENCE)


def test_the_worked_example_is_a_loadable_document(write_config: Callable[[str], Path]) -> None:
    """§2 is the one complete file in the document -- the others are fragments.

    It is the only block that should satisfy the whole-file rules, so it is the
    only one checked against them.
    """
    complete = [block for _, block in _blocks() if "version:" in block and "runtime:" in block]
    assert len(complete) == 1, "expected exactly one complete worked example in §2"

    document = load_document(write_config(complete[0]))

    assert document["accounts"][0] == "acme_web_user"
    assert document["target_sets"]["appdb"]["for_each"]["env"]["prod"]["tenant"][0] == "alpha"


def test_the_worked_example_builds_the_application_it_describes() -> None:
    """§2 says in prose what it declares; this asserts the code agrees.

    Parsing only proves the YAML is well formed. The document's claim is that
    those six accounts are one unnamed application mastered by one template with
    a dev exception -- which is a statement about the schema layer, not the
    parser.
    """
    complete = next(block for _, block in _blocks() if "runtime:" in block)

    (application,) = build_applications(parse_yaml(complete))

    assert application.is_inline
    assert application.accounts == (
        "acme_web_user",
        "acme_api_user",
        "acme_batch_user",
        "acme_integration_user",
        "acme_search_user",
        "acme_svc_user",
    )
    assert application.secret_template == "tenants/{tenant}#DB_CREDENTIALS/{account}"
    assert application.policy == "app-standard"
    assert [override.where for override in application.overrides] == [(("env", "dev"),)]


def test_the_two_application_example_builds_all_three_entries() -> None:
    """§3's example is the one that shows every field of an entry in use --
    `targets:` as a group and as a list, `secret` beside `secret_template`, and
    the Oracle `container_clause`. If the field table and the builder disagree,
    it shows up here."""
    block = next(block for _, block in _blocks() if "monitoring" in block)

    applications = build_applications(parse_yaml(block))

    assert [application.name for application in applications] == ["acme", "reporting", "monitoring"]
    acme, reporting, monitoring = applications
    assert acme.targets.group == "prod-pdbs"
    assert reporting.secret == "reporting/{env}/db#password"
    assert monitoring.targets.names == ("cdb-root-dev",)
    assert monitoring.oracle.container_clause == "ALL"


def test_the_worked_example_builds_the_estate_it_describes() -> None:
    """§2 is 129 lines of estate that nothing had ever built.

    Parsing proves the YAML is well formed; this proves the sections mean what
    the document says they do -- three vaults, the CDB root as an explicit
    target, one set expanding `env` over its own tenant list per environment,
    and two groups. Every field name in the reference is asserted here by being
    *read*, which is what turns the document into a specification rather than an
    illustration.
    """
    complete = next(block for _, block in _blocks() if "runtime:" in block)

    config = build_config(parse_yaml(complete))

    assert [vault.name for vault in config.vaults] == ["vault-dev", "vault-test", "vault-prod"]
    assert config.vaults[0].auth is not None
    assert config.vaults[0].auth.method == "token"
    assert config.vaults[0].kv_version == 2

    (cdb_root,) = config.targets
    assert cdb_root.name == "cdb-root-dev"
    assert cdb_root.oracle.scope == "cdb_root"
    assert cdb_root.admin is not None
    assert cdb_root.admin.auth == "prompt"

    (appdb,) = config.target_sets
    assert appdb.template.name == "appdb-{env}-{tenant}"
    assert appdb.for_each.dimension == "env"
    assert [value.value for value in appdb.for_each.values] == ["dev", "qa", "prod"]
    assert [
        len(value.inner.values) for value in appdb.for_each.values if value.inner is not None
    ] == [6, 8, 7]
    assert [name for name, _ in appdb.overrides] == ["appdb-qa-delta", "appdb-qa-epsilon"]

    assert [group.name for group in config.groups] == ["dev-pdbs", "prod-pdbs"]
    assert config.groups[1].match == (("env", "prod"), ("target_set", "appdb"))


def test_the_worked_example_expands_into_the_estate_it_promises() -> None:
    """§4 says a set exists because listing 35 PDBs by hand is not viable. This
    is the assertion that it produced them, and produced the right ones.

    §2 declares 6 dev, 8 qa and 7 prod tenants plus one explicit CDB root, and
    two overrides by rendered name. Every rule §4 states about the result is
    visible here: the cross product, the labels, the DSN template, and the
    overridden DSN of the tenant that was migrated.
    """
    complete = next(block for _, block in _blocks() if "runtime:" in block)

    config = build_config(parse_yaml(complete))
    by_name = {expanded.name: expanded for expanded in config.expanded_targets}

    assert len(config.expanded_targets) == 1 + 6 + 8 + 7
    assert config.expanded_targets[0].name == "cdb-root-dev"

    generated = by_name["appdb-prod-eta"]
    assert generated.target_set == "appdb"
    assert generated.target.dsn == "db-prod.example.com:1521/etaprod.pdb.example.com"
    assert generated.target.environment == "prod"
    assert generated.target.vault == "vault-prod"
    assert generated.target.oracle.container == "etaprod"
    assert generated.target.labels == (
        ("env", "prod"),
        ("target_set", "appdb"),
        ("tenant", "eta"),
    )
    assert not generated.overridden

    migrated = by_name["appdb-qa-delta"]
    assert migrated.overridden
    assert migrated.target.dsn == "192.0.2.75:1521/deltaqa.legacy.example.com"
    # The override changed one key; everything else still comes from the template.
    assert migrated.target.labels == (("env", "qa"), ("target_set", "appdb"), ("tenant", "delta"))
    assert migrated.target.vault == "vault-test"


def test_the_two_application_example_sits_on_the_estate_from_2() -> None:
    """§3 says of moving to `applications:` that "nothing else changes".

    So the fragment is read the way the document means it: §2's file with its
    binding replaced. That is also the only way its references resolve --
    `group: prod-pdbs` and `policy: app-standard` are declared in §2 -- which
    makes this the test that the reference's own two examples fit together.
    """
    estate = {
        key: value
        for key, value in parse_yaml(next(b for _, b in _blocks() if "runtime:" in b)).items()
        if key not in ("accounts", "secret_template", "policy", "overrides")
    }
    fragment = parse_yaml(next(block for _, block in _blocks() if "monitoring" in block))

    config = build_config({**estate, **fragment})

    assert [application.name for application in config.applications] == [
        "acme",
        "reporting",
        "monitoring",
    ]
    assert [group.name for group in config.groups] == ["dev-pdbs", "prod-pdbs"]
    assert config.warnings == ()


def test_the_skeleton_is_illustrative_rather_than_loadable() -> None:
    """§1's skeleton lists key names with empty placeholders (`accounts: []`).

    It parses, and it deliberately does not build -- an empty account list is a
    half-finished binding. Recorded rather than left as a surprise, so the next
    person does not "fix" the document to satisfy a test.
    """
    skeleton = next(block for _, block in _blocks() if "# named secret stores" in block)

    with pytest.raises(ConfigError):
        build_applications(parse_yaml(skeleton))


def test_every_section_the_config_layer_cites_exists() -> None:
    """Section numbers rot silently, and this document has already been renumbered
    once -- inserting §5 (profiles) pushed everything below it down one.

    Every ``§N`` in ``sopuli/config/`` refers to this document and nothing else,
    so the attribution is safe to automate. A docstring pointing at §9 for a rule
    that moved to §10 is worse than no citation: it sends a reader to a section
    that exists and says something different.
    """
    sections = set(re.findall(r"^## ([0-9]+[a-z]?)\.", REFERENCE.read_text(encoding="utf-8"), re.M))
    assert {"1", "5", "9a", "11"} <= sections, "the document's own headings changed shape"

    layer = Path(__file__).resolve().parents[2] / "src" / "sopuli" / "config"
    cited: dict[str, set[str]] = {}
    for module in sorted(layer.glob("*.py")):
        for section in re.findall(r"§([0-9]+[a-z]?)", module.read_text(encoding="utf-8")):
            cited.setdefault(section, set()).add(module.name)

    assert cited, "no citations found -- the regex or the layout moved"
    dangling = {
        section: sorted(where) for section, where in cited.items() if section not in sections
    }
    assert not dangling, f"citations of sections that do not exist: {dangling}"


def test_the_worked_example_survives_the_boolean_narrowing() -> None:
    """`pdb_suffix: dev` and friends are bare words in exactly the position the
    Norway problem bites. None of them may come back as a boolean."""
    complete = next(block for _, block in _blocks() if "runtime:" in block)
    for_each = parse_yaml(complete)["target_sets"]["appdb"]["for_each"]["env"]

    for environment, variables in for_each.items():
        assert isinstance(environment, str)
        for name, value in variables.items():
            assert not isinstance(value, bool), f"{environment}.{name} parsed as a boolean"

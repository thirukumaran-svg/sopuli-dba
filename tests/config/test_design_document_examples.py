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
from sopuli.config.schema import SCHEMA_FILENAME
from sopuli.config.vaults import build_vaults
from sopuli.config.yaml_loader import parse_yaml

REFERENCE = Path(__file__).resolve().parents[2] / "docs" / "design" / "01-configuration.md"

YAML_BLOCK = re.compile(r"```yaml\n(.*?)```", re.DOTALL)

#: What makes an example a whole file rather than a fragment: a `version:` at the
#: left margin. §9a requires the key of every config file, so nothing else can be
#: complete and nothing complete can be without it.
TOP_LEVEL_VERSION = re.compile(r"^version:", re.MULTILINE)

#: What §9b's examples put after `$schema=`. Relative to the YAML file, so this is
#: the schema sitting beside the config -- the arrangement somebody copying a
#: worked example will have.
SCHEMA_POINTER = f"./{SCHEMA_FILENAME}"


def _blocks() -> list[tuple[int, str]]:
    text = REFERENCE.read_text(encoding="utf-8")
    return [(index, match) for index, match in enumerate(YAML_BLOCK.findall(text))]


def _blocks_text() -> list[str]:
    return [block for _, block in _blocks()]


def test_the_reference_has_examples_to_check() -> None:
    """Guards the regex: a change to the fence style would otherwise leave every
    test below passing over an empty list."""
    assert len(_blocks()) >= 4


@pytest.mark.parametrize(("index", "block"), _blocks(), ids=lambda value: str(value)[:20])
def test_every_yaml_example_parses(index: int, block: str) -> None:
    parse_yaml(block, source=REFERENCE)


def test_every_complete_example_points_an_editor_at_the_schema() -> None:
    """§9b: a complete example is something a reader copies as a starting file.

    The ``# yaml-language-server:`` line is the only part of using the published
    schema that has to be discovered rather than deduced, so an example that
    omits it hands over a file with no editor support and no hint that any was
    available. Fragments are exempt because they are not files.

    The filename is asserted rather than just the comment: a schema version bump
    renames the artefact, and an example still naming the old one would point at
    a file that is not there -- which an editor reports as nothing at all rather
    than as an error.
    """
    complete = [block for block in _blocks_text() if TOP_LEVEL_VERSION.search(block)]
    assert complete, "no complete examples found -- the filter or the document moved"

    missing = [
        block.splitlines()[0]
        for block in complete
        if f"# yaml-language-server: $schema={SCHEMA_POINTER}" not in block
    ]
    assert not missing, f"complete examples without the §9b schema comment: {missing}"


def test_no_fragment_carries_the_schema_comment() -> None:
    """The other half of the rule, so it stays a distinction rather than a habit.

    A fragment with the line would be telling a reader to point an editor at a
    document that is not one, and the schema would reject it -- correctly, for
    the missing `version:` -- which reads as the schema being wrong.
    """
    offenders = [
        block.splitlines()[0]
        for block in _blocks_text()
        if "yaml-language-server" in block and not TOP_LEVEL_VERSION.search(block)
    ]
    assert not offenders, f"fragments must not carry the schema comment: {offenders}"


def test_the_worked_example_is_a_loadable_document(write_config: Callable[[str], Path]) -> None:
    """§2 is the one complete file in the document -- the others are fragments.

    It is the only block that should satisfy the whole-file rules, so it is the
    only one checked against them.
    """
    complete = [block for _, block in _blocks() if "version:" in block and "runtime:" in block]
    assert len(complete) == 1, "expected exactly one complete worked example in §2"

    document = load_document(write_config(complete[0]))

    assert document["applications"][0]["accounts"][0] == "acme_web_user"
    assert document["target_sets"]["appdb"]["for_each"]["env"]["prod"]["tenant"][0] == "alpha"


def test_the_worked_example_builds_the_application_it_describes() -> None:
    """§2 says in prose what it declares; this asserts the code agrees.

    Parsing only proves the YAML is well formed. The document's claim is that
    those six accounts are one application, scoped to the generated PDBs and
    mastered by one template with a dev exception -- which is a statement about
    the schema layer, not the parser.

    The scoping is the part worth pinning. §2 uses the `applications:` form for
    one application, which §1 permits and this file needs: the estate also holds
    a CDB root that belongs to a different job, and an inline binding would apply
    to that too.
    """
    complete = next(block for _, block in _blocks() if "runtime:" in block)

    (application,) = build_applications(parse_yaml(complete))

    assert not application.is_inline
    assert application.name == "acme"
    assert application.targets.group == "app-pdbs"
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
    and three groups. Every field name in the reference is asserted here by being
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
    assert cdb_root.admin.auth is not None
    assert cdb_root.admin.auth.method == "prompt"

    (appdb,) = config.target_sets
    assert appdb.template.name == "appdb-{env}-{tenant}"
    assert appdb.for_each.dimension == "env"
    assert [value.value for value in appdb.for_each.values] == ["dev", "qa", "prod"]
    assert [
        len(value.inner.values) for value in appdb.for_each.values if value.inner is not None
    ] == [6, 8, 7]
    assert [name for name, _ in appdb.overrides] == ["appdb-qa-delta", "appdb-qa-epsilon"]

    assert [group.name for group in config.groups] == ["app-pdbs", "dev-pdbs", "prod-pdbs"]
    assert config.groups[0].match == (("target_set", "appdb"),)
    assert config.groups[2].match == (("env", "prod"), ("target_set", "appdb"))


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

    # Why §2 has to scope its application: the CDB root carries no labels, so
    # `{tenant}` could never render for it and a binding that applied to "all
    # targets" would be unresolvable. See §2, "Why not the inline form".
    assert by_name["cdb-root-dev"].target.labels == ()

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


def test_the_worked_example_binds_the_accounts_it_declares() -> None:
    """§1 says the config exists to state *these accounts, in these targets,
    mastered by these secrets*. This is that sentence, counted and read back.

    Six accounts across 21 generated PDBs is 126 bindings, and the CDB root is
    bound by none of them -- which is the whole reason §2 scopes its application
    to `app-pdbs`. The dev exception is asserted here rather than only in the
    override tests because §2 is where a reader meets it.
    """
    complete = next(block for _, block in _blocks() if "runtime:" in block)

    config = build_config(parse_yaml(complete))
    by_target: dict[str, list[str]] = {}
    for binding in config.bindings:
        by_target.setdefault(binding.target, []).append(str(binding.secret))

    assert len(config.bindings) == 21 * 6
    assert "cdb-root-dev" not in by_target

    assert by_target["appdb-qa-alpha"][0] == "tenants/alpha#DB_CREDENTIALS/acme_web_user"
    assert by_target["appdb-prod-eta"][0] == "tenants/eta#DB_CREDENTIALS/acme_web_user"
    # The dev exception: one shared document instead of one per tenant.
    assert by_target["appdb-dev-alpha"][0] == "tenants/_shared#DB_CREDENTIALS/acme_web_user"
    assert by_target["appdb-dev-zeta"][0] == "tenants/_shared#DB_CREDENTIALS/acme_web_user"

    qa = next(binding for binding in config.bindings if binding.target == "appdb-qa-alpha")
    assert qa.vault == "vault-test"
    assert qa.policy == "app-standard"
    assert qa.application == "acme"


def test_the_two_application_example_sits_on_the_estate_from_2() -> None:
    """§3 says of moving to `applications:` that "nothing else changes".

    So the fragment is read the way the document means it: §2's file with its
    binding replaced. That is also the only way its references resolve --
    `group: prod-pdbs` and `policy: app-standard` are declared in §2 -- which
    makes this the test that the reference's own two examples fit together.

    Both now write `applications:`, so replacing the binding is replacing one
    key. §3's own claim that "nothing else changes" is the point: the estate
    above it is untouched, including the CDB root that §3's `monitoring` entry
    is the first thing in the reference to bind.
    """
    estate = {
        key: value
        for key, value in parse_yaml(next(b for _, b in _blocks() if "runtime:" in b)).items()
        if key != "applications"
    }
    fragment = parse_yaml(next(block for _, block in _blocks() if "monitoring" in block))

    config = build_config({**estate, **fragment})

    assert [application.name for application in config.applications] == [
        "acme",
        "reporting",
        "monitoring",
    ]
    assert [group.name for group in config.groups] == ["app-pdbs", "dev-pdbs", "prod-pdbs"]
    assert config.warnings == ()


def test_the_auth_example_builds_the_stores_it_describes() -> None:
    """§3a's `auth:` fragment is where a reader learns the shape of a MaterialRef.

    It shows all three forms in one block -- a method with material from an
    environment variable and a file, a method with one optional MaterialRef, and a
    method written as a bare value -- so if the grammar and the document disagree
    about any of them, it shows up here rather than in somebody's config file.
    """
    block = next(block for _, block in _blocks() if "instance_principal" in block)

    prod, dev, oci = build_vaults(parse_yaml(block))

    assert prod.auth is not None
    assert prod.auth.method == "approle"
    assert prod.auth.mount == "approle"
    assert str(prod.auth.role_id) == "env SOPULI_VAULT_ROLE_ID"
    assert str(prod.auth.secret_id) == "file /run/secrets/vault_secret_id"

    assert dev.auth is not None
    assert str(dev.auth.token) == "file ~/.vault-token"

    # The bare form: sugar for `{ method: instance_principal }`, and no material,
    # since a machine identity is not something the file can point at.
    assert oci.auth is not None
    assert oci.auth.method == "instance_principal"
    assert oci.auth.token is None


def test_the_admin_example_builds_the_credentials_it_describes() -> None:
    """§3a's `admin:` fragment shows all four of P2's sources in one estate.

    It is also the document's only worked example of `auth: external`, which
    constrains the target around it -- a TNS alias and no username -- so building it
    proves the rules and the example agree. They are checked against the expanded
    estate, which `build_config` is what runs.
    """
    block = next(block for _, block in _blocks() if "cdb-root-prod" in block)

    # A fragment, so it carries no `version:` of its own -- §9b's rule, and the
    # reason it must not: an example with one has to point an editor at the schema.
    config = build_config({"version": 1, **parse_yaml(block)})
    by_name = {target.name: target for target in config.targets}

    prompted = by_name["cdb-root-dev"].admin
    assert prompted is not None
    assert prompted.auth is not None
    assert prompted.auth.method == "prompt"

    mastered = by_name["cdb-root-qa"].admin
    assert mastered is not None
    assert mastered.auth is not None
    assert str(mastered.auth.secret) == "ops/sopuli/qa/admin#password"

    # External auth: the wallet supplies the username, and the DSN is the alias it
    # is keyed on rather than a host:port/service string.
    wallet = by_name["cdb-root-prod"].admin
    assert wallet is not None
    assert wallet.username is None
    assert by_name["cdb-root-prod"].dsn == "CDBPROD"


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

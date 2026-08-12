"""Target-set expansion: what a template actually generates (§4).

The rules under test are the ones that cannot be checked before a name has been
rendered — a duplicate name, an unresolved placeholder, an override that matches
nothing. §10 lists all three as errors, and each of them fails in a way that is
hard to spot afterwards: a set silently generating 34 targets instead of 35, or
a DSN reaching the driver with `{tenant}` still in it.

Everything here goes through `build_config`, because expansion is not an
optional pass. A config whose set renders two identical names must fail to load,
not fail later when something asks which target `appdb-qa-alpha` means.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import ExpandedTarget

#: Two environments with their own tenant lists — the §3 worked-example shape,
#: cut down to the three targets that make the cross product visible.
APPDB: dict[str, Any] = {
    "type": "oracle",
    "name": "appdb-{env}-{tenant}",
    "dsn": "{host}:1521/{tenant}{pdb_suffix}.pdb.example.com",
    "environment": "{env}",
    "oracle": {"scope": "pdb", "container": "{tenant}{pdb_suffix}"},
    "for_each": {
        "env": {
            "dev": {
                "host": "db-dev.example.com",
                "pdb_suffix": "dev",
                "tenant": ["alpha", "beta"],
            },
            "qa": {
                "host": "db-test.example.com",
                "pdb_suffix": "qa",
                "tenant": ["alpha"],
            },
        }
    },
}

TARGET: dict[str, Any] = {
    "name": "cdb-root-dev",
    "type": "oracle",
    "dsn": "db-dev.example.com:1521/CDBDEV.pdb.example.com",
}


def document(**sections: Any) -> dict[str, Any]:
    return {"version": 1, **sections}


def expand(**sections: Any) -> tuple[ExpandedTarget, ...]:
    return build_config(document(**sections)).expanded_targets


def named(expanded: tuple[ExpandedTarget, ...], name: str) -> ExpandedTarget:
    return next(candidate for candidate in expanded if candidate.name == name)


# ------------------------------------------------------------- the estate ---


def test_a_set_generates_one_target_per_combination() -> None:
    """§4 rule 2: the inner dimension expands per outer value, so a different
    tenant list per environment is two dev targets and one qa target, not the
    same list three times."""
    expanded = expand(target_sets={"appdb": APPDB})

    assert [candidate.name for candidate in expanded] == [
        "appdb-dev-alpha",
        "appdb-dev-beta",
        "appdb-qa-alpha",
    ]


def test_a_value_with_no_list_variable_generates_a_single_target() -> None:
    expanded = expand(
        target_sets={
            "cdb": {
                "type": "oracle",
                "name": "cdb-{env}",
                "dsn": "{host}:1521/CDB{env}.pdb.example.com",
                "for_each": {"env": {"dev": {"host": "db-dev.example.com"}}},
            }
        }
    )

    assert [candidate.name for candidate in expanded] == ["cdb-dev"]


def test_explicit_targets_come_first_and_remember_their_position() -> None:
    """Document order, because that is how the file reads. The index is what
    lets an error about a generated name point at `targets[0]` for the one it
    collided with."""
    expanded = expand(targets=[TARGET], target_sets={"appdb": APPDB})

    assert expanded[0].name == "cdb-root-dev"
    assert expanded[0].target_set is None
    assert expanded[0].index == 0
    assert all(candidate.target_set == "appdb" for candidate in expanded[1:])
    assert all(candidate.index is None for candidate in expanded[1:])


def test_every_templated_field_is_rendered() -> None:
    """A field expansion skipped would keep its braces and reach the driver
    intact, which is exactly what §10's "never an empty string" rule is about —
    so the assertion covers every field the template writes."""
    target = named(expand(target_sets={"appdb": APPDB}), "appdb-qa-alpha").target

    assert target.dsn == "db-test.example.com:1521/alphaqa.pdb.example.com"
    assert target.environment == "qa"
    assert target.oracle.container == "alphaqa"
    assert target.oracle.scope == "pdb"


def test_the_admin_username_and_confirm_environments_render_too() -> None:
    """Two fields nested a level down, which is where a renderer forgets one."""
    expanded = expand(
        target_sets={
            "appdb": {
                **APPDB,
                "admin": {"username": "C##SOPULI_{env}", "auth": "prompt"},
                "safety": {"confirm_environments": ["{env}"]},
            }
        }
    )

    target = named(expanded, "appdb-qa-alpha").target
    assert target.admin is not None
    assert target.admin.username == "C##SOPULI_qa"
    assert target.admin.auth is not None
    assert target.admin.auth.method == "prompt"
    assert target.safety is not None
    assert target.safety.confirm_environments == ("qa",)


def test_the_admin_credentials_own_addresses_render_too() -> None:
    """A level deeper again, and the one that matters most: an admin ref or a
    variable name left unrendered reaches a vault with its braces intact.

    §4's substitution table used to exclude `admin.auth` wholesale, because it was
    a closed-set scalar. Now only `method` is closed, and everything else the block
    carries is an address like any other string the template writes.
    """
    expanded = expand(
        target_sets={
            "appdb": {
                **APPDB,
                "admin": {
                    "auth": {"method": "vault", "secret": "ops/sopuli/{env}/{tenant}#password"}
                },
            }
        }
    )

    target = named(expanded, "appdb-qa-alpha").target
    assert target.admin is not None
    assert target.admin.auth is not None
    assert str(target.admin.auth.secret) == "ops/sopuli/qa/alpha#password"


def test_an_admin_ref_that_cannot_render_is_refused_where_it_was_written() -> None:
    """§4 rule 4 applies here too: never an empty string, and never braces left in
    a path that decides which credential opens a production database."""
    with pytest.raises(ConfigError) as caught:
        expand(
            target_sets={
                "appdb": {
                    **APPDB,
                    "admin": {"auth": {"method": "vault", "secret": "ops/{region}#password"}},
                }
            }
        )

    rendered = str(caught.value)
    assert "nothing to substitute for `{region}`" in rendered
    assert "target_sets.appdb.admin.auth.secret" in rendered


def test_an_admin_variable_name_renders_too() -> None:
    """§6's fixed `SOPULI_DB_ADMIN_PASSWORD` does not scale past one credential,
    and a set is exactly where per-environment names come from."""
    expanded = expand(
        target_sets={
            "appdb": {
                **APPDB,
                "admin": {"auth": {"method": "env", "password_env": "SOPULI_DB_ADMIN_PW_{env}"}},
            }
        }
    )

    target = named(expanded, "appdb-qa-alpha").target
    assert target.admin is not None
    assert target.admin.auth is not None
    assert target.admin.auth.password_env == "SOPULI_DB_ADMIN_PW_qa"


# ---------------------------------------------------------------- labels ---


def test_a_generated_target_carries_its_dimensions_as_labels() -> None:
    """§4: `target_set: appdb, env: qa, tenant: alpha`. This is what makes
    `--select env=qa` and §2's `groups:` work over a generated estate."""
    target = named(expand(target_sets={"appdb": APPDB}), "appdb-qa-alpha").target

    assert target.labels == (("env", "qa"), ("target_set", "appdb"), ("tenant", "alpha"))


def test_only_dimensions_become_labels_not_every_variable() -> None:
    """`host` and `pdb_suffix` say how to connect, not which population a target
    belongs to. Labelling them would make `--select` offer choices that mean
    nothing to select on."""
    target = named(expand(target_sets={"appdb": APPDB}), "appdb-dev-alpha").target

    assert [key for key, _ in target.labels] == ["env", "target_set", "tenant"]


def test_a_template_may_add_labels_of_its_own() -> None:
    expanded = expand(target_sets={"appdb": {**APPDB, "labels": {"tier": "{pdb_suffix}"}}})

    assert named(expanded, "appdb-qa-alpha").target.labels == (
        ("env", "qa"),
        ("target_set", "appdb"),
        ("tenant", "alpha"),
        ("tier", "qa"),
    )


def test_an_explicit_target_keeps_its_own_labels(  # C8: mixed estates select uniformly
) -> None:
    expanded = expand(targets=[{**TARGET, "labels": {"env": "dev", "role": "cdb"}}])

    assert expanded[0].target.labels == (("env", "dev"), ("role", "cdb"))


def test_a_template_label_that_contradicts_a_dimension_is_refused() -> None:
    """Resolving it either way is wrong: the dimension winning makes the file
    say something the estate does not, and the label winning drops the value a
    group is matching on."""
    with pytest.raises(ConfigError) as caught:
        expand(target_sets={"appdb": {**APPDB, "labels": {"env": "production"}}})

    rendered = str(caught.value)
    assert "label 'env' is already 'dev'" in rendered
    assert "target_sets.appdb.labels.env" in rendered


def test_a_placeholder_in_a_label_key_is_reported_against_that_label() -> None:
    """`labels.{tenat}`, not `labels` — the entry as written is the line to go
    and fix, the same as every other key path in the loader."""
    with pytest.raises(ConfigError) as caught:
        expand(target_sets={"appdb": {**APPDB, "labels": {"{tenat}": "yes"}}})

    rendered = str(caught.value)
    assert "nothing to substitute for `{tenat}`" in rendered
    assert "target_sets.appdb.labels.{tenat}" in rendered


def test_a_template_label_that_agrees_with_a_dimension_is_allowed() -> None:
    """`labels: { env: "{env}" }` is redundant, not contradictory. There is no
    disagreement to report, so refusing it would be pedantry."""
    expanded = expand(target_sets={"appdb": {**APPDB, "labels": {"env": "{env}"}}})

    assert named(expanded, "appdb-qa-alpha").target.labels == (
        ("env", "qa"),
        ("target_set", "appdb"),
        ("tenant", "alpha"),
    )


# ---------------------------------------------------------- placeholders ---


def test_an_unresolved_placeholder_is_an_error_not_an_empty_string() -> None:
    """§10. An empty string here is a DSN that connects to the wrong place, or a
    name that collides with every other target missing the same variable."""
    with pytest.raises(ConfigError) as caught:
        expand(target_sets={"appdb": {**APPDB, "dsn": "{hsot}:1521/x"}})

    rendered = str(caught.value)
    assert "nothing to substitute for `{hsot}`" in rendered
    assert "target_sets.appdb.dsn" in rendered
    assert "in scope here: env, host, pdb_suffix, tenant" in rendered


def test_an_empty_placeholder_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        expand(target_sets={"appdb": {**APPDB, "dsn": "{}:1521/x"}})

    assert "empty placeholder" in str(caught.value)


@pytest.mark.parametrize("dsn", ["{host:1521/x", "host}:1521/x", "{a{b}}:1521/x"])
def test_an_unbalanced_brace_is_refused(dsn: str) -> None:
    """There is no escape syntax (C7), so a stray brace is a typo rather than a
    literal. Reporting it as one is better than substituting half of it."""
    with pytest.raises(ConfigError) as caught:
        expand(target_sets={"appdb": {**APPDB, "dsn": dsn}})

    assert "unbalanced brace" in str(caught.value)


def test_a_variable_may_not_shadow_the_dimension_it_sits_under() -> None:
    """`{env}` with two meanings in one scope: whichever won would be an
    arbitrary choice that then decides a rendered secret path."""
    for_each = {"env": {"dev": {"host": "db.example.com", "env": "production"}}}

    with pytest.raises(ConfigError) as caught:
        expand(target_sets={"appdb": {**APPDB, "for_each": for_each}})

    rendered = str(caught.value)
    assert "same name as the dimension" in rendered
    assert "target_sets.appdb.for_each.env.dev.env" in rendered


# ------------------------------------------------------------ uniqueness ---


def test_a_name_template_that_renders_twice_is_refused() -> None:
    """§4 rule 3. Dropping `{tenant}` from the name is the way this happens, and
    the message has to say which combinations collided or there is nothing to
    act on."""
    with pytest.raises(ConfigError) as caught:
        expand(target_sets={"appdb": {**APPDB, "name": "appdb-{env}"}})

    rendered = str(caught.value)
    assert "renders the name 'appdb-dev' twice" in rendered
    assert "env=dev, tenant=alpha and env=dev, tenant=beta" in rendered


def test_a_generated_name_may_not_collide_with_an_explicit_target() -> None:
    """The one `targets:` cannot check for itself. Either would shadow the other
    everywhere a name is looked up."""
    with pytest.raises(ConfigError) as caught:
        expand(targets=[{**TARGET, "name": "appdb-qa-alpha"}], target_sets={"appdb": APPDB})

    rendered = str(caught.value)
    assert "duplicate target name 'appdb-qa-alpha'" in rendered
    assert "target_sets.appdb.name" in rendered
    assert "already declared at targets[0]" in rendered


def test_two_sets_may_not_generate_the_same_name() -> None:
    with pytest.raises(ConfigError) as caught:
        expand(target_sets={"appdb": APPDB, "copy": APPDB})

    assert "already declared at target_sets.appdb" in str(caught.value)


# --------------------------------------------------------------- overrides ---


def test_an_override_patches_the_target_it_names() -> None:
    """§2's own exception: one tenant migrated to another host."""
    expanded = expand(
        target_sets={
            "appdb": {
                **APPDB,
                "overrides": {"appdb-qa-alpha": {"dsn": "192.0.2.75:1521/legacy.example.com"}},
            }
        }
    )

    patched = named(expanded, "appdb-qa-alpha")
    assert patched.target.dsn == "192.0.2.75:1521/legacy.example.com"
    assert patched.overridden
    assert patched.patched == ("dsn",)
    assert not named(expanded, "appdb-dev-alpha").overridden


def test_a_patched_value_is_reported_against_the_override_that_wrote_it() -> None:
    """The template's `vault:` is valid here and the exception's is a typo. An
    error pointing at `target_sets.appdb.vault` would send the reader to the one
    line where the name is spelled correctly."""
    for_each = {"env": {"qa": {"host": "db.example.com", "pdb_suffix": "qa", "tenant": ["alpha"]}}}

    with pytest.raises(ConfigError) as caught:
        expand(
            vaults={"vault-test": {"type": "hashicorp"}},
            target_sets={
                "appdb": {
                    **APPDB,
                    "vault": "vault-test",
                    "for_each": for_each,
                    "overrides": {"appdb-qa-alpha": {"vault": "vault-tset"}},
                }
            },
        )

    rendered = str(caught.value)
    assert "no vault named 'vault-tset'" in rendered
    assert "target_sets.appdb.overrides.appdb-qa-alpha.vault" in rendered


def test_a_key_the_override_left_alone_is_still_reported_against_the_template() -> None:
    """The other half of the same rule: a patch that touches `dsn` does not make
    the template's `vault:` an override's fault."""
    for_each = {"env": {"qa": {"host": "db.example.com", "pdb_suffix": "qa", "tenant": ["alpha"]}}}

    with pytest.raises(ConfigError) as caught:
        expand(
            vaults={"vault-test": {"type": "hashicorp"}},
            target_sets={
                "appdb": {
                    **APPDB,
                    "vault": "vault-tset",
                    "for_each": for_each,
                    "overrides": {"appdb-qa-alpha": {"dsn": "192.0.2.75:1521/legacy"}},
                }
            },
        )

    rendered = str(caught.value)
    assert "target_sets.appdb.vault" in rendered
    assert "overrides" not in rendered


def test_an_override_keeps_the_labels_the_dimensions_attached() -> None:
    """Replacing the mapping would drop the `env=qa` that found this target, so
    a patch adds and changes rather than replaces."""
    expanded = expand(
        target_sets={
            "appdb": {**APPDB, "overrides": {"appdb-qa-alpha": {"labels": {"migrated": "true"}}}}
        }
    )

    assert named(expanded, "appdb-qa-alpha").target.labels == (
        ("env", "qa"),
        ("migrated", "true"),
        ("target_set", "appdb"),
        ("tenant", "alpha"),
    )


def test_an_override_merges_a_nested_block_rather_than_replacing_it() -> None:
    """`oracle: { container: X }` must not silently drop the `scope: pdb` the
    template set — the target would then connect at the wrong level."""
    expanded = expand(
        target_sets={
            "appdb": {**APPDB, "overrides": {"appdb-qa-alpha": {"oracle": {"container": "ALPHA2"}}}}
        }
    )

    target = named(expanded, "appdb-qa-alpha").target
    assert target.oracle.container == "ALPHA2"
    assert target.oracle.scope == "pdb"


def test_an_override_keeps_the_admin_auth_when_it_patches_only_the_username() -> None:
    """The same rule one block over: `admin: { username: X }` must not drop the
    source the template chose, or the target would fall back to no method at all."""
    expanded = expand(
        target_sets={
            "appdb": {
                **APPDB,
                "admin": {"username": "C##SOPULI_SVC", "auth": "prompt"},
                "overrides": {"appdb-qa-alpha": {"admin": {"username": "C##SOPULI_QA"}}},
            }
        }
    )

    target = named(expanded, "appdb-qa-alpha").target
    assert target.admin is not None
    assert target.admin.username == "C##SOPULI_QA"
    assert target.admin.auth is not None
    assert target.admin.auth.method == "prompt"


def test_an_override_replaces_admin_auth_whole_rather_than_merging_it() -> None:
    """The exception to the merge rule, and it is about coherence rather than
    convenience: an `auth:` block's keys belong to its `method:`, so merging
    `{ method: prompt }` over `{ method: vault, secret: ... }` would leave a prompt
    carrying a ref that means nothing. An override that changes the method states
    the whole source, which is one line either way.
    """
    expanded = expand(
        target_sets={
            "appdb": {
                **APPDB,
                "admin": {"auth": {"method": "vault", "secret": "ops/{env}/admin#password"}},
                "overrides": {"appdb-qa-alpha": {"admin": {"auth": "prompt"}}},
            }
        }
    )

    target = named(expanded, "appdb-qa-alpha").target
    assert target.admin is not None
    assert target.admin.auth is not None
    assert target.admin.auth.method == "prompt"
    assert target.admin.auth.secret is None

    untouched = named(expanded, "appdb-dev-beta").target
    assert untouched.admin is not None
    assert untouched.admin.auth is not None
    assert str(untouched.admin.auth.secret) == "ops/dev/admin#password"


def test_an_override_renders_placeholders_in_the_same_scope() -> None:
    """The one string in the estate that could otherwise reach a DSN with its
    braces intact."""
    expanded = expand(
        target_sets={
            "appdb": {
                **APPDB,
                "overrides": {"appdb-qa-alpha": {"dsn": "192.0.2.75:1521/{tenant}.legacy"}},
            }
        }
    )

    assert named(expanded, "appdb-qa-alpha").target.dsn == "192.0.2.75:1521/alpha.legacy"


def test_an_override_naming_nothing_the_set_generates_is_refused() -> None:
    """§10, and the reason is a rename: the template changes, the exceptions
    quietly stop applying, and the migrated host goes back to being wrong."""
    with pytest.raises(ConfigError) as caught:
        expand(target_sets={"appdb": {**APPDB, "overrides": {"appdb-qa-gamma": {"vault": "v"}}}})

    rendered = str(caught.value)
    assert "override 'appdb-qa-gamma' names no target that 'appdb' generates" in rendered
    assert "generated: appdb-dev-alpha, appdb-dev-beta, appdb-qa-alpha" in rendered


def test_the_generated_names_hint_summarises_a_large_set() -> None:
    """35 PDBs listed in an error message is not a hint. The first few show the
    shape the override was aiming at."""
    tenants = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta"]
    for_each = {"env": {"dev": {"host": "db.example.com", "pdb_suffix": "d", "tenant": tenants}}}

    with pytest.raises(ConfigError) as caught:
        expand(
            target_sets={
                "appdb": {**APPDB, "for_each": for_each, "overrides": {"nope": {"vault": "v"}}}
            }
        )

    assert "... (7 in all)" in str(caught.value)


# ------------------------------------------------------ expansion is not opt-in ---


def test_a_third_nesting_level_is_a_config_error_rather_than_flattened() -> None:
    """§4 rule 6, asserted end to end: a mapping where a variable belongs never
    becomes a silently flattened estate."""
    for_each = {"env": {"dev": {"host": "db.example.com", "tenant": {"alpha": ["a", "b"]}}}}

    with pytest.raises(ConfigError) as caught:
        expand(target_sets={"appdb": {**APPDB, "for_each": for_each}})

    assert "not a mapping" in str(caught.value)


def test_a_generated_target_resolves_its_vault_like_any_other() -> None:
    """The reference check runs after expansion, so `vault: "{vault}"` is
    resolved as the store it renders to — not skipped for containing a brace."""
    for_each = {
        "env": {
            "dev": {
                "host": "db.example.com",
                "pdb_suffix": "d",
                "vault": "vault-dv",
                "tenant": ["alpha"],
            }
        }
    }

    with pytest.raises(ConfigError) as caught:
        expand(
            vaults={"vault-dev": {"type": "hashicorp"}},
            target_sets={"appdb": {**APPDB, "vault": "{vault}", "for_each": for_each}},
        )

    rendered = str(caught.value)
    assert "no vault named 'vault-dv'" in rendered
    assert "target_sets.appdb.vault" in rendered


def test_a_generated_prod_target_may_not_use_a_non_production_store() -> None:
    """§10's rule reaches generated targets too. It previously could not: before
    expansion there was no target to ask about."""
    for_each = {"env": {"prod": {"host": "db.example.com", "pdb_suffix": "p", "tenant": ["alpha"]}}}

    with pytest.raises(ConfigError) as caught:
        expand(
            vaults={"local": {"type": "file", "non_production": True}},
            target_sets={"appdb": {**APPDB, "vault": "local", "for_each": for_each}},
        )

    assert "target 'appdb-prod-alpha' is prod but its vault 'local'" in str(caught.value)


def test_expansion_is_deterministic() -> None:
    """`config show --resolved` and plan output are compared between runs, so the
    same file must produce the same estate in the same order."""
    first = expand(targets=[TARGET], target_sets={"appdb": APPDB})
    second = expand(targets=[TARGET], target_sets={"appdb": APPDB})

    assert first == second

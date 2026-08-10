"""The ``target_sets:`` section -- its shape, not its expansion (§4).

Nothing here renders a name or resolves a placeholder. What is checked is that
the set *is* a set: one outer dimension, at most one inner one, nothing nested
deeper. Those rules (§4's 1, 2 and 6) are readable from the shape, and finding
them early matters because a malformed ``for_each`` otherwise surfaces as a
surprising number of generated targets rather than as an error.

Fixtures mirror the §2 worked example in miniature -- ``env`` outer, ``tenant``
inner, tenants ``alpha``…``theta``, hosts under ``example.com``.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.target_sets import build_target_sets

FOR_EACH: dict[str, Any] = {
    "env": {
        "dev": {
            "host": "db-dev.example.com",
            "port": 1521,
            "pdb_suffix": "dev",
            "tenant": ["alpha", "beta"],
        },
        "prod": {
            "host": "db-prod.example.com",
            "port": 1521,
            "pdb_suffix": "prod",
            "tenant": ["alpha", "beta", "gamma"],
        },
    }
}

APPDB: dict[str, Any] = {
    "type": "oracle",
    "name": "appdb-{env}-{tenant}",
    "dsn": "{host}:{port}/{tenant}{pdb_suffix}.pdb.example.com",
    "environment": "{env}",
    "oracle": {"scope": "pdb", "container": "{tenant}{pdb_suffix}"},
    "for_each": FOR_EACH,
}


def document(**sets: Any) -> dict[str, Any]:
    return {"version": 1, "target_sets": sets}


def only(**keys: Any) -> Any:
    built = build_target_sets(document(appdb={**APPDB, **keys}))
    assert len(built) == 1
    return built[0]


def test_a_set_is_a_template_plus_its_dimensions() -> None:
    target_set = only()

    assert target_set.name == "appdb"
    assert target_set.for_each.dimension == "env"
    assert [value.value for value in target_set.for_each.values] == ["dev", "prod"]


def test_the_template_keeps_its_placeholders() -> None:
    """Nothing is rendered at this layer. The template is a Target whose name and
    dsn still contain `{token}`s, which is what expansion will read."""
    template = only().template

    assert template.name == "appdb-{env}-{tenant}"
    assert template.dsn == "{host}:{port}/{tenant}{pdb_suffix}.pdb.example.com"
    assert template.environment == "{env}"
    assert template.oracle.container == "{tenant}{pdb_suffix}"


def test_the_template_is_read_by_the_same_code_as_an_explicit_target() -> None:
    """A field added to explicit targets but not to generated ones would mean a
    target set silently cannot express something the estate can, so the two share
    a reader -- and therefore share their rules."""
    with pytest.raises(ConfigError) as caught:
        build_target_sets(document(appdb={**APPDB, "type": "postgresql"}))

    assert "unknown target type 'postgresql'" in str(caught.value)


def test_a_set_must_declare_for_each() -> None:
    entry = {field: value for field, value in APPDB.items() if field != "for_each"}

    with pytest.raises(ConfigError) as caught:
        build_target_sets(document(appdb=entry))

    rendered = str(caught.value)
    assert "must declare `for_each:`" in rendered
    assert "target_sets.appdb.for_each" in rendered


def test_a_config_may_declare_no_target_sets() -> None:
    assert build_target_sets({"version": 1}) == ()


# ------------------------------------------------------ rule 1: one outer ---


def test_two_outer_dimensions_are_refused() -> None:
    """§4 rule 1. Two outer dimensions is the point at which the expansion stops
    being predictable from reading the file."""
    with pytest.raises(ConfigError) as caught:
        build_target_sets(
            document(appdb={**APPDB, "for_each": {"env": FOR_EACH["env"], "region": {}}})
        )

    rendered = str(caught.value)
    assert "exactly one outer dimension, found 2" in rendered
    assert "'env', 'region'" in rendered


def test_an_empty_for_each_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_target_sets(document(appdb={**APPDB, "for_each": {}}))

    assert "found 0" in str(caught.value)


def test_a_dimension_with_no_values_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_target_sets(document(appdb={**APPDB, "for_each": {"env": {}}}))

    assert "dimension 'env' has no values" in str(caught.value)


# ----------------------------------------------------- rule 2: the inner ---


def test_a_list_variable_becomes_the_inner_dimension() -> None:
    dev = only().for_each.values[0]

    assert dev.inner is not None
    assert dev.inner.name == "tenant"
    assert dev.inner.values == ("alpha", "beta")


def test_each_outer_value_has_its_own_inner_list() -> None:
    """The whole point of the two-level shape: a different tenant list per
    environment, which is what the §2 estate actually looks like."""
    dev, prod = only().for_each.values

    assert dev.inner is not None
    assert prod.inner is not None
    assert dev.inner.values == ("alpha", "beta")
    assert prod.inner.values == ("alpha", "beta", "gamma")


def test_scalar_variables_are_kept_beside_the_inner_dimension() -> None:
    dev = only().for_each.values[0]

    assert dev.variables == (
        ("host", "db-dev.example.com"),
        ("pdb_suffix", "dev"),
        ("port", "1521"),
    )


def test_a_number_is_kept_as_text() -> None:
    """Variables exist to be substituted into templates, so `port: 1521` and
    `port: "1521"` render identically and there is nothing to remember."""
    dev = only().for_each.values[0]

    assert dict(dev.variables)["port"] == "1521"


def test_an_outer_value_may_have_no_inner_dimension() -> None:
    for_each = {"env": {"dev": {"host": "db-dev.example.com"}}}

    (value,) = only(for_each=for_each).for_each.values
    assert value.inner is None


def test_an_empty_list_variable_is_refused() -> None:
    """It would silently generate nothing for that environment -- the kind of
    absence that is only noticed when a password is not rotated."""
    for_each: dict[str, Any] = {"env": {"dev": {"tenant": []}}}

    with pytest.raises(ConfigError) as caught:
        build_target_sets(document(appdb={**APPDB, "for_each": for_each}))

    assert "list variable 'tenant' is empty" in str(caught.value)


def test_a_boolean_variable_is_refused_rather_than_stringified() -> None:
    """The hardened loader already keeps bare `yes`/`no` as strings, so a boolean
    here was written as one -- and `pdb_suffix: True` in a rendered secret path is
    not what anybody meant."""
    for_each = {"env": {"dev": {"pdb_suffix": True}}}

    with pytest.raises(ConfigError) as caught:
        build_target_sets(document(appdb={**APPDB, "for_each": for_each}))

    rendered = str(caught.value)
    assert "not a boolean" in rendered
    assert "target_sets.appdb.for_each.env.dev.pdb_suffix" in rendered


# ------------------------------------------------ rule 6: two levels, stop ---


def test_a_second_list_variable_is_refused() -> None:
    """Two lists in one value is a third dimension. §4 rule 6 and C7 both answer
    it the same way: write a second target set."""
    for_each = {"env": {"dev": {"tenant": ["alpha"], "shard": ["a", "b"]}}}

    with pytest.raises(ConfigError) as caught:
        build_target_sets(document(appdb={**APPDB, "for_each": for_each}))

    rendered = str(caught.value)
    assert "only one list variable" in rendered
    assert "'tenant'" in rendered
    assert "'shard'" in rendered


def test_a_nested_mapping_is_refused_rather_than_flattened() -> None:
    for_each = {"env": {"dev": {"tenant": {"alpha": {"host": "db.example.com"}}}}}

    with pytest.raises(ConfigError) as caught:
        build_target_sets(document(appdb={**APPDB, "for_each": for_each}))

    rendered = str(caught.value)
    assert "must be a value or a list, not a mapping" in rendered
    assert "nesting stops at two levels" in rendered


def test_the_inner_dimension_must_be_the_same_variable_throughout() -> None:
    """Not in §4 as a rule, but implied by what labels are for: dimension values
    become labels, so a set where dev expands over tenants and qa over shards is
    two populations that no single --select can address."""
    for_each = {
        "env": {
            "dev": {"tenant": ["alpha", "beta"]},
            "qa": {"shard": ["one", "two"]},
        }
    }

    with pytest.raises(ConfigError) as caught:
        build_target_sets(document(appdb={**APPDB, "for_each": for_each}))

    rendered = str(caught.value)
    assert "must be the same variable throughout" in rendered
    assert "'shard', 'tenant'" in rendered


# --------------------------------------------------------------- overrides ---


def test_an_override_patches_a_generated_target_by_name() -> None:
    overrides = {"appdb-prod-gamma": {"dsn": "192.0.2.75:1521/gammaprod.legacy.example.com"}}

    ((name, patch),) = only(overrides=overrides).overrides
    assert name == "appdb-prod-gamma"
    assert patch.dsn == "192.0.2.75:1521/gammaprod.legacy.example.com"


def test_an_override_may_not_patch_the_name() -> None:
    """The rendered name is the key the patch is found by, so patching it would
    make the key a lie."""
    with pytest.raises(ConfigError) as caught:
        build_target_sets(
            document(appdb={**APPDB, "overrides": {"appdb-dev-alpha": {"name": "something-else"}}})
        )

    rendered = str(caught.value)
    assert "unknown key 'name'" in rendered
    assert "the rendered name this patch is found by" in rendered


def test_an_empty_patch_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_target_sets(document(appdb={**APPDB, "overrides": {"appdb-dev-alpha": {}}}))

    assert "must change something" in str(caught.value)


def test_a_patch_is_validated_like_the_field_it_patches() -> None:
    with pytest.raises(ConfigError) as caught:
        build_target_sets(
            document(
                appdb={
                    **APPDB,
                    "overrides": {"appdb-dev-alpha": {"oracle": {"scope": "cdb-root"}}},
                }
            )
        )

    rendered = str(caught.value)
    assert "unknown Oracle scope 'cdb-root'" in rendered
    assert "target_sets.appdb.overrides.appdb-dev-alpha.oracle.scope" in rendered


def test_whether_an_override_names_a_real_target_is_not_checked_here() -> None:
    """§10 says an override naming a target the set does not generate is an error
    -- that is what catches a rename. It needs the set expanded, so it belongs
    with expansion; recorded here so its absence is deliberate rather than
    forgotten."""
    overrides = {"appdb-qa-nonexistent": {"dsn": "db.example.com:1521/x"}}

    assert len(only(overrides=overrides).overrides) == 1

"""The ``targets:`` section -- explicit database endpoints.

Tier 0, pure. Fixtures use the fictional vocabulary: hosts under ``example.com``,
tenants ``alpha``…``theta``, the service account ``C##SOPULI_SVC`` the reference
itself uses.

Three fields are read from closed sets -- ``type``, ``oracle.scope`` and
``admin.auth`` -- and those are the tests worth reading. A target is where the
tool decides *which database and which container* it is about to change a
password in; a typo that loads happily there is the expensive kind.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.targets import build_targets

DSN = "db-dev.example.com:1521/CDBDEV.pdb.example.com"

CDB_ROOT: dict[str, Any] = {
    "name": "cdb-root-dev",
    "type": "oracle",
    "environment": "dev",
    "vault": "vault-dev",
    "dsn": DSN,
    "admin": {"username": "C##SOPULI_SVC", "auth": "prompt"},
    "oracle": {"scope": "cdb_root"},
}


def document(*targets: Any) -> dict[str, Any]:
    return {"version": 1, "targets": list(targets)}


def only(**keys: Any) -> Any:
    built = build_targets(document({**CDB_ROOT, **keys}))
    assert len(built) == 1
    return built[0]


def test_a_target_is_read_whole() -> None:
    target = only()

    assert target.name == "cdb-root-dev"
    assert target.type == "oracle"
    assert target.environment == "dev"
    assert target.vault == "vault-dev"
    assert target.dsn == DSN
    assert target.admin is not None
    assert target.admin.username == "C##SOPULI_SVC"
    assert target.admin.auth == "prompt"
    assert target.oracle.scope == "cdb_root"


def test_a_config_may_declare_no_targets() -> None:
    assert build_targets({"version": 1}) == ()


# ------------------------------------------------------- the required three ---


@pytest.mark.parametrize("key", ["name", "type", "dsn"])
def test_name_type_and_dsn_are_required(key: str) -> None:
    entry = {field: value for field, value in CDB_ROOT.items() if field != key}

    with pytest.raises(ConfigError) as caught:
        build_targets(document(entry))

    rendered = str(caught.value)
    assert f"targets[0].{key}" in rendered
    assert "must be given" in rendered


def test_the_driver_type_is_not_defaulted_to_oracle() -> None:
    """P1: "Nothing in the config schema, CLI grammar, or vault layout may be
    Oracle-specific at the top level". Defaulting `type` would be exactly that,
    and it would silently become wrong the day a second driver exists."""
    entry = {field: value for field, value in CDB_ROOT.items() if field != "type"}

    with pytest.raises(ConfigError):
        build_targets(document(entry))


def test_a_driver_that_does_not_exist_yet_is_refused() -> None:
    """D6 keeps drivers in-tree until there is a second one. A target the tool
    cannot drive should fail while the file is being written -- invariant 4
    applied to config."""
    with pytest.raises(ConfigError) as caught:
        build_targets(document({**CDB_ROOT, "type": "postgresql"}))

    rendered = str(caught.value)
    assert "unknown target type 'postgresql'" in rendered
    assert "oracle" in rendered


def test_duplicate_target_names_are_refused() -> None:
    """Two targets with one name make `--target` ambiguous, and the second would
    shadow the first everywhere a name is looked up."""
    with pytest.raises(ConfigError) as caught:
        build_targets(document(CDB_ROOT, {**CDB_ROOT, "dsn": "elsewhere.example.com:1521/X"}))

    rendered = str(caught.value)
    assert "duplicate target name 'cdb-root-dev'" in rendered
    assert "targets[1].name" in rendered
    assert "already declared at index 0" in rendered


# ----------------------------------------------------------------- oracle ---


@pytest.mark.parametrize("scope", ["cdb_root", "pdb"])
def test_the_scopes_the_reference_writes_are_accepted(scope: str) -> None:
    assert only(oracle={"scope": scope}).oracle.scope == scope


def test_a_misspelled_scope_is_refused() -> None:
    """The one that would hurt: `cdb-root` is not a scope, and a target that
    loads with no scope connects somewhere other than the CDB root."""
    with pytest.raises(ConfigError) as caught:
        build_targets(document({**CDB_ROOT, "oracle": {"scope": "cdb-root"}}))

    rendered = str(caught.value)
    assert "unknown Oracle scope 'cdb-root'" in rendered
    assert "cdb_root" in rendered


def test_a_targets_oracle_block_is_not_an_applications() -> None:
    """Same key name, different meaning: a target's `oracle:` says which
    container to connect to, an application's says how `ALTER USER` is written.
    One bag accepting both would let `container_clause` on a target look
    configured and do nothing."""
    with pytest.raises(ConfigError) as caught:
        build_targets(document({**CDB_ROOT, "oracle": {"container_clause": "ALL"}}))

    rendered = str(caught.value)
    assert "unknown key 'container_clause'" in rendered
    assert "known keys here: container, scope" in rendered


def test_a_pdb_target_names_its_container() -> None:
    target = only(oracle={"scope": "pdb", "container": "alphadev"})

    assert target.oracle.container == "alphadev"


def test_omitting_oracle_is_allowed() -> None:
    """A single-instance non-CDB database has no container to name."""
    entry = {field: value for field, value in CDB_ROOT.items() if field != "oracle"}

    (target,) = build_targets(document(entry))
    assert target.oracle.scope is None


@pytest.mark.parametrize("block", ["oracle", "admin"])
def test_an_empty_block_is_refused_even_though_omitting_it_is_fine(block: str) -> None:
    """Absent and empty mean the same thing to the tool, so the difference
    between them is a sentence somebody started and did not finish -- the same
    reading as `policy: ""` naming no policy."""
    with pytest.raises(ConfigError) as caught:
        build_targets(document({**CDB_ROOT, block: {}}))

    rendered = str(caught.value)
    assert f"an empty `{block}:` block says nothing" in rendered
    assert f"targets[0].{block}" in rendered


def test_how_scope_and_container_constrain_each_other_is_not_decided_here() -> None:
    """§2 writes `cdb_root` without a container and `pdb` with one, but never says
    that is a rule -- and `container` is also the `{container}` token in a secret
    template (§6), so it carries information beyond which container to connect
    to. P1 puts per-vendor validation behind the driver. Recorded as C9 / #27
    rather than guessed at, and pinned here so the absence is deliberate.
    """
    assert only(oracle={"scope": "pdb"}).oracle.container is None
    assert only(oracle={"container": "alphadev"}).oracle.scope is None
    assert only(oracle={"scope": "cdb_root", "container": "alphadev"}).oracle.scope == "cdb_root"


# ------------------------------------------------------------------ admin ---


@pytest.mark.parametrize("source", ["external", "vault", "prompt", "env"])
def test_the_bootstrap_sources_p2_ranks_are_accepted(source: str) -> None:
    target = only(admin={"username": "C##SOPULI_SVC", "auth": source})

    assert target.admin is not None
    assert target.admin.auth == source


def test_an_unknown_admin_source_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_targets(document({**CDB_ROOT, "admin": {"auth": "wallet"}}))

    rendered = str(caught.value)
    assert "unknown admin auth source 'wallet'" in rendered
    assert "external" in rendered


def test_an_admin_password_has_nowhere_to_go() -> None:
    """P2: "Storing the admin password in the config file is not supported at
    all." There is no field for one, so it is an unknown key -- and the hint
    says which question is open rather than listing keys."""
    with pytest.raises(ConfigError) as caught:
        build_targets(document({**CDB_ROOT, "admin": {"username": "SYS", "password": "hunter2"}}))

    rendered = str(caught.value)
    assert "unknown key 'password'" in rendered
    assert "#27" in rendered


def test_admin_may_omit_the_username() -> None:
    """External authentication has no username to give (P2 ranks it first), and
    §5 lets `SOPULI_DB_ADMIN_USER` supply one per execution context."""
    target = only(admin={"auth": "external"})

    assert target.admin is not None
    assert target.admin.username is None


# ----------------------------------------------------------------- labels ---


def test_an_explicit_target_may_carry_labels() -> None:
    """C8, which §4 already states as prose: labels on explicit targets let a
    mixed estate be selected uniformly."""
    target = only(labels={"tenant": "alpha", "tier": "gold"})

    assert target.labels == (("tenant", "alpha"), ("tier", "gold"))


def test_labels_are_sorted_rather_than_left_in_yaml_order() -> None:
    assert only(labels={"tier": "gold", "tenant": "alpha"}).labels == (
        ("tenant", "alpha"),
        ("tier", "gold"),
    )


def test_a_target_without_labels_has_none() -> None:
    assert only().labels == ()


def test_a_label_value_must_be_a_string() -> None:
    with pytest.raises(ConfigError) as caught:
        build_targets(document({**CDB_ROOT, "labels": {"tier": ["gold"]}}))

    assert "targets[0].labels.tier" in str(caught.value)


# ------------------------------------------------------------ unknown keys ---


def test_an_unknown_target_key_is_refused_with_its_index() -> None:
    with pytest.raises(ConfigError) as caught:
        build_targets(document(CDB_ROOT, {**CDB_ROOT, "name": "other", "enviroment": "dev"}))

    rendered = str(caught.value)
    assert "unknown key 'enviroment'" in rendered
    assert "targets[1]" in rendered

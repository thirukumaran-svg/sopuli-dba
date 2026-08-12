"""Cross-section rules: every name must name something the file declares.

These are the checks that could not be written until every section existed. The
failure they prevent is not cosmetic — a dangling `vault:` does not stay
dangling, it falls back to `defaults.vault`, and the tool then rotates a
production password into whatever that turns out to be.

Also here, for the same reason: the §10 rules about two keys of *one target*, which
need the estate expanded before the pair exists. `admin.auth: external` constrains
the `dsn` and refuses a `username`, and either half of that pair can arrive from an
`overrides:` patch rather than from the template.

Also here: the one *warning* the config layer produces. §5 makes it a warning
rather than an error deliberately, so the test asserts it does not raise as much
as it asserts what it says.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config

VAULTS: dict[str, Any] = {"vault-dev": {"type": "hashicorp", "addr": "https://v.example.com"}}
TARGET: dict[str, Any] = {
    "name": "cdb-root-dev",
    "type": "oracle",
    "dsn": "db-dev.example.com:1521/CDBDEV.pdb.example.com",
}
POLICIES: dict[str, Any] = {"app-standard": {"password": {"length": 24}}}
GROUPS: dict[str, Any] = {"prod-pdbs": {"match": {"env": "prod"}}}


def document(**sections: Any) -> dict[str, Any]:
    return {"version": 1, **sections}


# ------------------------------------------------------------- vault names ---


def test_a_target_may_name_a_declared_vault() -> None:
    config = build_config(document(vaults=VAULTS, targets=[{**TARGET, "vault": "vault-dev"}]))

    assert config.targets[0].vault == "vault-dev"


def test_a_target_naming_an_undeclared_vault_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_config(document(vaults=VAULTS, targets=[{**TARGET, "vault": "vault-dv"}]))

    rendered = str(caught.value)
    assert "no vault named" in rendered
    assert "targets[0].vault" in rendered
    assert "declared vaults: vault-dev" in rendered


def test_the_hint_says_so_when_there_is_no_vaults_section_at_all() -> None:
    """ "declared vaults: " with nothing after it reads like a bug. The likelier
    mistake is a section that was never written, so the message says that."""
    with pytest.raises(ConfigError) as caught:
        build_config(document(targets=[{**TARGET, "vault": "vault-dev"}]))

    assert "there is no `vaults:`" in str(caught.value)


@pytest.mark.parametrize(
    "section",
    ["application", "override", "profile", "defaults", "target_set", "admin"],
    ids=lambda name: f"from-{name}",
)
def test_every_place_that_names_a_vault_is_checked(section: str) -> None:
    """One resolver, every reference. A rule that covers five of six places is
    the same as no rule, because the sixth is where the typo will be."""
    sections: dict[str, Any] = {"vaults": VAULTS}
    if section == "admin":
        # The admin credential's own ref may carry a prefix, and a dangling one
        # means the tool cannot reach the database at all.
        sections["targets"] = [
            {
                **TARGET,
                "admin": {"auth": {"method": "vault", "secret": "nope:ops/admin#password"}},
            }
        ]
    elif section == "application":
        sections["applications"] = [
            {"name": "acme", "accounts": ["acme_web_user"], "vault": "nope"}
        ]
    elif section == "override":
        sections["applications"] = [
            {
                "name": "acme",
                "accounts": ["acme_web_user"],
                "overrides": [{"where": {"env": "dev"}, "vault": "nope"}],
            }
        ]
    elif section == "profile":
        sections["profiles"] = {"ci": {"vault": "nope"}}
    elif section == "defaults":
        sections["defaults"] = {"vault": "nope"}
    else:
        sections["target_sets"] = {
            "appdb": {
                "type": "oracle",
                "name": "appdb-{env}",
                "dsn": "{host}:1521/x",
                "vault": "nope",
                "for_each": {"env": {"dev": {"host": "db.example.com"}}},
            }
        }

    with pytest.raises(ConfigError) as caught:
        build_config(document(**sections))

    rendered = str(caught.value)
    assert "no vault named 'nope'" in rendered
    if section == "admin":
        # The ref, not the block it sits in: `admin:` has three keys that could
        # each be wrong, and only one of them names a store.
        assert "targets[0].admin.auth.secret" in rendered


def test_the_inline_application_reports_its_reference_at_the_root() -> None:
    """The inline form writes its keys at the top level, so `applications[0].`
    would be a path the file does not contain."""
    with pytest.raises(ConfigError) as caught:
        build_config(document(policies=POLICIES, accounts=["acme_web_user"], policy="nope"))

    assert str(caught.value).startswith("policy:")


def test_a_templated_vault_is_resolved_after_expansion() -> None:
    """A target set's `vault: "{vault}"` resolves from a dimension variable, so
    the name to check is the rendered one. The template keeps its placeholder;
    the generated target names a store."""
    config = build_config(
        document(
            vaults=VAULTS,
            target_sets={
                "appdb": {
                    "type": "oracle",
                    "name": "appdb-{env}",
                    "dsn": "{host}:1521/x",
                    "vault": "{vault}",
                    "for_each": {"env": {"dev": {"host": "db.example.com", "vault": "vault-dev"}}},
                }
            },
        )
    )

    assert config.target_sets[0].template.vault == "{vault}"
    assert config.expanded_targets[0].target.vault == "vault-dev"


@pytest.mark.parametrize(
    "sections",
    [
        {"targets": [{**TARGET, "vault": "{vault}"}]},
        {"applications": [{"name": "acme", "accounts": ["a"], "vault": "{vault}"}]},
        {"profiles": {"ci": {"vault": "{vault}"}}},
        {"defaults": {"vault": "{vault}"}},
    ],
    ids=["target", "application", "profile", "defaults"],
)
def test_a_placeholder_outside_a_target_set_is_refused(sections: dict[str, Any]) -> None:
    """Substitution is for target sets and nothing else.

    An explicit target has no `for_each:` and therefore nothing to substitute
    from, so `{vault}` there is not deferred work -- it is a line copied out of a
    target set that will never resolve. Skipping it because it contains a `{`
    would let any reference bypass resolution just by containing one.
    """
    with pytest.raises(ConfigError) as caught:
        build_config(document(vaults=VAULTS, **sections))

    rendered = str(caught.value)
    assert "contains a placeholder, and this is not a target set" in rendered
    assert "nothing to substitute from" in rendered


# ------------------------------------------------- policies, groups, profiles ---


def test_an_application_naming_an_undeclared_policy_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_config(
            document(
                policies=POLICIES,
                applications=[{"name": "acme", "accounts": ["a"], "policy": "app-standrd"}],
            )
        )

    rendered = str(caught.value)
    assert "no policy named 'app-standrd'" in rendered
    assert "applications[0].policy" in rendered


def test_an_application_naming_an_undeclared_group_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_config(
            document(
                groups=GROUPS,
                applications=[
                    {"name": "acme", "accounts": ["a"], "targets": {"group": "prod-pdb"}}
                ],
            )
        )

    rendered = str(caught.value)
    assert "no group named 'prod-pdb'" in rendered
    assert "applications[0].targets.group" in rendered


def test_defaults_naming_an_undeclared_profile_is_refused() -> None:
    """§5: selecting a profile that does not exist is an error rather than a
    silent fallback, and that has to hold for the one named in the file too."""
    with pytest.raises(ConfigError) as caught:
        build_config(document(profiles={"ci": {"output": "json"}}, defaults={"profile": "cl"}))

    assert "no profile named 'cl'" in str(caught.value)


# --------------------------------------------------- non-production vaults ---


def test_a_prod_target_may_not_be_mastered_by_a_non_production_store() -> None:
    """§10. The marking exists so a development store is obviously one (P2); a
    prod target pointed at it would leave the passwords guarding production
    sitting somewhere chosen for convenience."""
    with pytest.raises(ConfigError) as caught:
        build_config(
            document(
                vaults={"local": {"type": "file", "non_production": True}},
                targets=[{**TARGET, "environment": "prod", "vault": "local"}],
            )
        )

    rendered = str(caught.value)
    assert "is prod but its vault 'local'" in rendered
    assert "non_production: true" in rendered


def test_a_dev_target_may_use_a_non_production_store() -> None:
    config = build_config(
        document(
            vaults={"local": {"type": "file", "non_production": True}},
            targets=[{**TARGET, "environment": "dev", "vault": "local"}],
        )
    )

    assert config.targets[0].vault == "local"


# ------------------------------------------------------ external admin auth ---

ALIAS = "CDBPROD"


def external(**keys: Any) -> Any:
    """A target using external authentication, plus whatever `keys` change."""
    return build_config(
        document(targets=[{**TARGET, "dsn": ALIAS, "admin": {"auth": "external"}, **keys}])
    )


def test_a_wallet_target_names_a_tns_alias() -> None:
    """The shape external auth actually needs: `/@alias`, resolved through
    TNS_ADMIN. Nothing else about the target changes."""
    config = external()

    assert config.targets[0].dsn == ALIAS


def test_external_auth_with_an_ezconnect_dsn_is_refused() -> None:
    """A wallet is keyed on the alias it was created for, so a host:port/service
    string has no entry to match -- and the connection then fails as an
    *authentication* error, which sends the reader to the wrong problem."""
    with pytest.raises(ConfigError) as caught:
        external(dsn="db-prod.example.com:1521/CDBPROD.pdb.example.com")

    rendered = str(caught.value)
    assert "must be a TNS alias" in rendered
    assert "targets[0].dsn" in rendered
    assert "TNS_ADMIN" in rendered


def test_external_auth_with_a_connect_descriptor_is_refused_too() -> None:
    """The other form somebody reaches for. Same reason: the wallet is keyed on an
    alias, not on a descriptor."""
    with pytest.raises(ConfigError) as caught:
        external(dsn="(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db.example.com)(PORT=1521)))")

    assert "must be a TNS alias" in str(caught.value)


def test_external_auth_beside_a_username_is_refused_rather_than_ignored() -> None:
    """The wallet supplies the username. A file naming one while the wallet names
    another would put the wrong answer in every audit record (P5)."""
    with pytest.raises(ConfigError) as caught:
        external(admin={"username": "C##SOPULI_SVC", "auth": "external"})

    rendered = str(caught.value)
    assert "cannot be honoured" in rendered
    assert "targets[0].admin.username" in rendered


def test_another_method_may_pair_a_username_with_any_dsn() -> None:
    """The rules belong to `external` and to nothing else -- every other source
    takes a username, and connects by whatever the DSN says."""
    config = build_config(
        document(
            targets=[
                {
                    **TARGET,
                    "admin": {"username": "C##SOPULI_SVC", "auth": "prompt"},
                }
            ]
        )
    )

    assert config.targets[0].admin is not None
    assert config.targets[0].admin.username == "C##SOPULI_SVC"


def test_an_override_cannot_smuggle_in_an_ezconnect_dsn_under_external_auth() -> None:
    """Why this rule lives after expansion. The template pairs `external` with an
    alias; the patch replaces the DSN, and the pair only exists once both have
    been applied."""
    with pytest.raises(ConfigError) as caught:
        build_config(
            document(
                target_sets={
                    "appdb": {
                        "type": "oracle",
                        "name": "appdb-{env}",
                        "dsn": "CDB{env}",
                        "admin": {"auth": "external"},
                        "for_each": {"env": {"prod": {}}},
                        "overrides": {"appdb-prod": {"dsn": "192.0.2.75:1521/CDBPROD"}},
                    }
                }
            )
        )

    rendered = str(caught.value)
    assert "must be a TNS alias" in rendered
    # Reported against the override, which is the line that wrote the value.
    assert "target_sets.appdb.overrides.appdb-prod.dsn" in rendered


def test_an_override_cannot_smuggle_in_external_auth_under_an_ezconnect_dsn() -> None:
    """The same pair from the other side: the patch changes the method, and the
    template's DSN was never an alias."""
    with pytest.raises(ConfigError) as caught:
        build_config(
            document(
                target_sets={
                    "appdb": {
                        "type": "oracle",
                        "name": "appdb-{env}",
                        "dsn": "db-{env}.example.com:1521/CDB{env}",
                        "admin": {"auth": "prompt"},
                        "for_each": {"env": {"prod": {}}},
                        "overrides": {"appdb-prod": {"admin": {"auth": "external"}}},
                    }
                }
            )
        )

    assert "must be a TNS alias" in str(caught.value)


# --------------------------------------------------------- admin refs ---


def test_an_admin_ref_may_be_templated_in_a_target_set() -> None:
    """Where the values come from: the set's own dimensions, rendered during
    expansion like every other string it writes."""
    config = build_config(
        document(
            target_sets={
                "appdb": {
                    "type": "oracle",
                    "name": "appdb-{env}",
                    "dsn": "db-{env}.example.com:1521/CDB{env}",
                    "admin": {"auth": {"method": "vault", "secret": "ops/{env}/admin#password"}},
                    "for_each": {"env": {"qa": {}, "prod": {}}},
                }
            }
        )
    )

    refs = sorted(
        str(expanded.target.admin.auth.secret)
        for expanded in config.expanded_targets
        if expanded.target.admin is not None and expanded.target.admin.auth is not None
    )
    assert refs == ["ops/prod/admin#password", "ops/qa/admin#password"]


def test_an_admin_ref_written_in_an_override_is_reported_against_the_override() -> None:
    """A value's location is the line that wrote it (§4 rule 5).

    Reported against the template, this would send a reader to the one place the
    store name is spelled correctly -- which is the wrong line by definition when
    the exception is what introduced the typo.
    """
    declared = {"method": "vault", "secret": "vault-dev:ops#password"}
    mistyped = {"method": "vault", "secret": "nope:ops#password"}

    with pytest.raises(ConfigError) as caught:
        build_config(
            document(
                vaults=VAULTS,
                target_sets={
                    "appdb": {
                        "type": "oracle",
                        "name": "appdb-{env}",
                        "dsn": "CDB{env}",
                        "admin": {"auth": declared},
                        "for_each": {"env": {"prod": {}}},
                        "overrides": {"appdb-prod": {"admin": {"auth": mistyped}}},
                    }
                },
            )
        )

    rendered = str(caught.value)
    assert "no vault named 'nope'" in rendered
    assert "target_sets.appdb.overrides.appdb-prod.admin.auth.secret" in rendered


def test_a_templated_admin_ref_on_an_explicit_target_is_refused() -> None:
    """Nothing renders it: §7's tokens are expanded per account and target for an
    application's ref, and the admin credential belongs to no account. §10 says an
    unresolved placeholder is an error rather than an empty string."""
    templated = {"method": "vault", "secret": "ops/{env}/admin#password"}

    with pytest.raises(ConfigError) as caught:
        build_config(document(targets=[{**TARGET, "admin": {"auth": templated}}]))

    rendered = str(caught.value)
    assert "still contains a placeholder" in rendered
    assert "targets[0].admin.auth.secret" in rendered


# ----------------------------------------------------------- the warning ---


def test_a_profile_named_after_an_environment_warns_rather_than_fails() -> None:
    """§5 makes this a warning on purpose: a site may have a reason. The text has
    to say what the flag actually does, because the whole problem is that
    `--profile prod` reads like a selector."""
    config = build_config(
        document(
            targets=[{**TARGET, "environment": "prod"}],
            profiles={"prod": {"output": "json"}},
        )
    )

    (warning,) = config.warnings
    assert "named after an environment" in warning.message
    assert warning.at == "profiles.prod"
    assert "selects no targets" in str(warning)
    assert "interactive, ci, scheduled" in str(warning)


def test_an_environment_from_a_target_set_counts_too() -> None:
    """`environment: "{env}"` over `for_each: { env: {...} }` is how §2's estate
    declares its environments, so a warning that only looked at explicit targets
    would never fire on a real config."""
    config = build_config(
        document(
            target_sets={
                "appdb": {
                    "type": "oracle",
                    "name": "appdb-{env}",
                    "dsn": "{host}:1521/x",
                    "environment": "{env}",
                    "for_each": {
                        "env": {"dev": {"host": "a.example.com"}, "qa": {"host": "b.example.com"}}
                    },
                }
            },
            profiles={"qa": {"output": "json"}},
        )
    )

    assert len(config.warnings) == 1
    assert "profile 'qa'" in config.warnings[0].message


def test_a_well_named_profile_warns_about_nothing() -> None:
    config = build_config(
        document(
            targets=[{**TARGET, "environment": "prod"}],
            profiles={"scheduled": {"output": "jsonl"}, "ci": {"output": "json"}},
        )
    )

    assert config.warnings == ()


def test_a_clean_file_carries_no_warnings() -> None:
    assert build_config(document(vaults=VAULTS)).warnings == ()

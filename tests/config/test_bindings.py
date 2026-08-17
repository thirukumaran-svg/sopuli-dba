"""*These accounts, in these targets, mastered by these secrets* (§1, §3, §7).

§1 calls the account→secret mapping the safety-critical part of the file, and
this is where it stops being prose. Two failures are worth the whole module:
a ref that renders for the wrong account, and a ref that renders for no account
at all because a token had nothing behind it.

Everything goes through `build_config`, because bindings are built at load. A
template that cannot render is a config error, not a surprise at the first
rotation -- the same treatment target-set expansion gets, for the same reason.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import Binding

TARGETS: list[dict[str, Any]] = [
    {
        "name": "cdb-root-dev",
        "type": "oracle",
        "dsn": "db-dev.example.com:1521/CDBDEV.pdb.example.com",
        "environment": "dev",
        "vault": "vault-dev",
        "oracle": {"scope": "cdb_root"},
    }
]

APPDB: dict[str, Any] = {
    "type": "oracle",
    "name": "appdb-{env}-{tenant}",
    "dsn": "{host}:1521/{tenant}.pdb.example.com",
    "environment": "{env}",
    "vault": "{vault}",
    "oracle": {"scope": "pdb", "container": "{tenant}pdb"},
    "for_each": {
        "env": {
            "dev": {
                "host": "db-dev.example.com",
                "vault": "vault-dev",
                "tenant": ["alpha", "beta"],
            },
            "qa": {"host": "db-test.example.com", "vault": "vault-test", "tenant": ["alpha"]},
        }
    },
}

VAULTS: dict[str, Any] = {
    "vault-dev": {"type": "hashicorp"},
    "vault-test": {"type": "hashicorp"},
    "vault-other": {"type": "hashicorp"},
}

GROUPS: dict[str, Any] = {"app-pdbs": {"match": {"target_set": "appdb"}}}


def document(**sections: Any) -> dict[str, Any]:
    return {"version": 1, "vaults": VAULTS, "target_sets": {"appdb": APPDB}, **sections}


def bind(**entry: Any) -> tuple[Binding, ...]:
    """One application over the generated PDBs, unless the entry says otherwise."""
    application = {"name": "acme", "targets": {"group": "app-pdbs"}, **entry}
    return build_config(document(groups=GROUPS, applications=[application])).bindings


def only(**entry: Any) -> Binding:
    bindings = bind(**entry)
    assert len(bindings) == 1, f"expected one binding, got {len(bindings)}"
    return bindings[0]


def one_target(**entry: Any) -> dict[str, Any]:
    """Narrow the fixture to a single target, for the token tests."""
    return {"targets": {"match": {"tenant": "alpha", "env": "qa"}}, **entry}


# ------------------------------------------------------------- the sentence ---


def test_one_binding_per_account_per_target() -> None:
    """The fan-out §1 describes: one account in eleven PDBs is a sentence you
    write once and a list you can count."""
    bindings = bind(
        accounts=["acme_web_user", "acme_api_user"], secret_template="apps/{account}#password"
    )

    assert len(bindings) == 3 * 2
    assert {binding.target for binding in bindings} == {
        "appdb-dev-alpha",
        "appdb-dev-beta",
        "appdb-qa-alpha",
    }


def test_bindings_are_ordered_by_target_then_by_declared_account() -> None:
    """All document order, so the list is stable enough to diff between runs."""
    bindings = bind(accounts=["b_user", "a_user"], secret_template="apps/{account}#password")

    assert [(b.target, b.account) for b in bindings][:4] == [
        ("appdb-dev-alpha", "b_user"),
        ("appdb-dev-alpha", "a_user"),
        ("appdb-dev-beta", "b_user"),
        ("appdb-dev-beta", "a_user"),
    ]


def test_a_target_no_application_selects_has_no_bindings() -> None:
    """§2's CDB root: declared for a use case that is not designed yet. A
    legitimate state, so it is an absence rather than an error."""
    bindings = build_config(
        document(
            targets=TARGETS,
            groups=GROUPS,
            applications=[
                {
                    "name": "acme",
                    "targets": {"group": "app-pdbs"},
                    "accounts": ["acme_web_user"],
                    "secret_template": "apps/{account}#password",
                }
            ],
        )
    ).bindings

    assert "cdb-root-dev" not in {binding.target for binding in bindings}


def test_an_application_may_declare_no_ref_at_all() -> None:
    """§3 makes `secret` optional, and this layer does not invent one."""
    assert only(**one_target(accounts=["acme_web_user"])).secret is None


# ----------------------------------------------------------------- the tokens ---


def test_the_account_tokens_render_per_account() -> None:
    """The one that matters most: §10 refuses a ref that cannot distinguish two
    accounts, and this is the rendering that rule protects."""
    bindings = bind(
        accounts=["Acme_Web_User"],
        secret_template="apps/{account}/{account_lower}/{account_upper}#password",
        targets={"match": {"tenant": "alpha", "env": "qa"}},
    )

    (binding,) = bindings
    assert str(binding.secret) == "apps/Acme_Web_User/acme_web_user/ACME_WEB_USER#password"


def test_the_target_tokens_render_from_the_target() -> None:
    binding = only(
        **one_target(
            accounts=["acme_web_user"], secret_template="{target}/{env}/{container}#password"
        )
    )

    assert str(binding.secret) == "appdb-qa-alpha/qa/alphapdb#password"


def test_a_label_is_a_token() -> None:
    """§7: `{<label>}` is any label on the target, which is what makes one
    template serve a tenant per PDB."""
    binding = only(
        **one_target(accounts=["acme_web_user"], secret_template="tenants/{tenant}#DB/{account}")
    )

    assert str(binding.secret) == "tenants/alpha#DB/acme_web_user"


def test_the_application_token_is_the_entry_name() -> None:
    binding = only(
        **one_target(accounts=["acme_web_user"], secret_template="{application}/creds#password")
    )

    assert str(binding.secret) == "acme/creds#password"


def test_the_application_token_is_empty_in_the_inline_form() -> None:
    """§7 says so explicitly, which makes it the one documented exception to
    "never an empty string"."""
    config = build_config(
        document(
            accounts=["acme_web_user"],
            secret_template="apps/{application}{tenant}#DB/{account}",
        )
    )

    assert str(config.bindings[0].secret) == "apps/alpha#DB/acme_web_user"


def test_a_built_in_token_wins_over_a_label_of_the_same_name() -> None:
    """One of the two is specified and the other is whatever somebody typed."""
    target_set = {**APPDB, "labels": {"target": "not-the-name"}}
    config = build_config(
        {
            "version": 1,
            "vaults": VAULTS,
            "target_sets": {"appdb": target_set},
            "accounts": ["acme_web_user"],
            "secret_template": "apps/{target}#password",
        }
    )

    assert str(config.bindings[0].secret) == "apps/appdb-dev-alpha#password"


@pytest.mark.parametrize(
    ("template", "missing"),
    [("apps/{tenant}", "tenant"), ("apps/{env}", "env"), ("apps/{container}", "container")],
)
def test_a_token_with_nothing_behind_it_is_refused(template: str, missing: str) -> None:
    """§10: never an empty string. A ref rendered with the token dropped
    addresses the *wrong* secret, which is worse than one that addresses none.

    The target carries no labels, no `environment` and no container, so all
    three tokens have nothing behind them -- which is exactly §2's CDB root, and
    the reason its application has to be scoped.
    """
    bare = {"name": "bare", "type": "oracle", "dsn": "db-dev.example.com:1521/x"}

    with pytest.raises(ConfigError) as caught:
        build_config(
            {
                "version": 1,
                "targets": [bare],
                "accounts": ["acme_web_user"],
                "secret_template": template,
            }
        )

    rendered = str(caught.value)
    assert f"nothing to substitute for `{{{missing}}}`" in rendered
    assert "a secret template resolves from the account" in rendered
    assert "secret_template" in rendered


def test_an_unrenderable_ref_names_the_application_it_came_from() -> None:
    with pytest.raises(ConfigError) as caught:
        build_config(
            document(
                groups=GROUPS,
                applications=[
                    {
                        "name": "acme",
                        "targets": {"group": "app-pdbs"},
                        "accounts": ["acme_web_user"],
                        "secret_template": "apps/{nope}",
                    }
                ],
            )
        )

    assert "applications[0].secret_template" in str(caught.value)


def test_a_ref_from_an_override_is_reported_against_that_override() -> None:
    """The location has to travel with the value. Reporting this against the
    entry's own `secret_template:` would point at the one line that renders
    perfectly well for every other target."""
    with pytest.raises(ConfigError) as caught:
        bind(
            accounts=["acme_web_user"],
            secret_template="tenants/{tenant}#DB/{account}",
            overrides=[
                {"where": {"env": "qa"}, "secret_template": "x/{account}#password"},
                {"where": {"env": "dev"}, "secret_template": "tenants/{nope}#DB/{account}"},
            ],
        )

    assert "applications[0].overrides[1].secret_template" in str(caught.value)


def test_an_override_may_use_the_other_key_and_still_be_located() -> None:
    """An entry that writes `secret_template:` may be patched by an override
    that writes `secret:`, so the key reported is the one the *source* used."""
    with pytest.raises(ConfigError) as caught:
        bind(
            accounts=["acme_web_user"],
            secret_template="tenants/{tenant}#DB/{account}",
            overrides=[{"where": {"env": "dev"}, "secret": "creds#password@versio=7"}],
        )

    rendered = str(caught.value)
    assert "applications[0].overrides[0].secret" in rendered
    assert "unknown qualifier 'versio'" in rendered


def test_the_rendered_ref_is_parsed_not_just_substituted() -> None:
    """A token can change the structure of a ref once it has a value, which is
    the one thing §7 says cannot be checked before expansion."""
    with pytest.raises(ConfigError) as caught:
        build_config(
            document(
                groups=GROUPS,
                applications=[
                    {
                        "name": "acme",
                        "targets": {"match": {"tenant": "alpha", "env": "qa"}},
                        "accounts": ["acme_web_user"],
                        "secret_template": "apps/creds#{tenant}/",
                    }
                ],
            )
        )

    assert "empty pointer segment" in str(caught.value)


# --------------------------------------------------------------- overrides ---


def test_an_override_patches_the_targets_it_matches() -> None:
    """§2's dev exception: one shared document instead of one per tenant."""
    bindings = bind(
        accounts=["acme_web_user"],
        secret_template="tenants/{tenant}#DB/{account}",
        overrides=[{"where": {"env": "dev"}, "secret_template": "tenants/_shared#DB/{account}"}],
    )

    by_target = {binding.target: str(binding.secret) for binding in bindings}
    assert by_target["appdb-dev-alpha"] == "tenants/_shared#DB/acme_web_user"
    assert by_target["appdb-qa-alpha"] == "tenants/alpha#DB/acme_web_user"


def test_overrides_apply_in_document_order_and_the_later_one_wins() -> None:
    """§3 calls them "patches applied to matching targets" -- plural, and
    applied. A broad rule narrowed by a later exception is the point."""
    bindings = bind(
        accounts=["acme_web_user"],
        secret_template="tenants/{tenant}#DB/{account}",
        overrides=[
            {"where": {"env": "dev"}, "secret_template": "broad/{account}#password"},
            {"where": {"tenant": "beta"}, "secret_template": "narrow/{account}#password"},
        ],
    )

    by_target = {binding.target: str(binding.secret) for binding in bindings}
    assert by_target["appdb-dev-alpha"] == "broad/acme_web_user#password"
    assert by_target["appdb-dev-beta"] == "narrow/acme_web_user#password"


def test_an_override_patches_key_by_key() -> None:
    """One that sets `vault:` leaves the ref alone, and the other way round."""
    bindings = bind(
        accounts=["acme_web_user"],
        secret_template="tenants/{tenant}#DB/{account}",
        overrides=[{"where": {"env": "dev"}, "vault": "vault-other"}],
    )

    dev = next(b for b in bindings if b.target == "appdb-dev-alpha")
    assert dev.vault == "vault-other"
    assert str(dev.secret) == "tenants/alpha#DB/acme_web_user"


# ------------------------------------------------------- vault and policy ---


def test_the_vault_falls_back_from_the_entry_to_the_target() -> None:
    """§3's chain, in the order it is written there."""
    bindings = bind(accounts=["acme_web_user"], secret_template="apps/{account}#password")

    by_target = {binding.target: binding.vault for binding in bindings}
    assert by_target["appdb-dev-alpha"] == "vault-dev"
    assert by_target["appdb-qa-alpha"] == "vault-test"


def test_an_entry_vault_beats_the_target_vault() -> None:
    binding = only(
        **one_target(
            accounts=["acme_web_user"],
            secret_template="apps/{account}#password",
            vault="vault-other",
        )
    )

    assert binding.vault == "vault-other"


def test_a_ref_naming_its_own_vault_beats_everything() -> None:
    """§7 calls the prefix an *explicit* vault. Anything else would print a ref
    reading `vault-other:...` beside a resolved store of `vault-test`."""
    binding = only(
        **one_target(
            accounts=["acme_web_user"], secret_template="vault-other:apps/{account}#password"
        )
    )

    assert binding.vault == "vault-other"
    assert binding.secret is not None
    assert binding.secret.vault == "vault-other"


def test_the_policy_falls_back_to_defaults() -> None:
    config = build_config(
        document(
            groups=GROUPS,
            policies={"app-standard": {"password": {"length": 24}}},
            defaults={"policy": "app-standard"},
            applications=[
                {
                    "name": "acme",
                    "targets": {"group": "app-pdbs"},
                    "accounts": ["acme_web_user"],
                    "secret_template": "apps/{account}#password",
                }
            ],
        )
    )

    assert {binding.policy for binding in config.bindings} == {"app-standard"}


def test_an_entry_policy_beats_defaults() -> None:
    config = build_config(
        document(
            groups=GROUPS,
            policies={"app-standard": {"password": {"length": 24}}, "strict": {}},
            defaults={"policy": "app-standard"},
            applications=[
                {
                    "name": "acme",
                    "targets": {"group": "app-pdbs"},
                    "accounts": ["acme_web_user"],
                    "secret_template": "apps/{account}#password",
                    "policy": "strict",
                }
            ],
        )
    )

    assert {binding.policy for binding in config.bindings} == {"strict"}


# ------------------------------------------------------------ several apps ---


def test_each_application_binds_its_own_targets() -> None:
    """§3's shape: two applications over one estate, each naming its own scope."""
    config = build_config(
        document(
            targets=TARGETS,
            groups=GROUPS,
            applications=[
                {
                    "name": "acme",
                    "targets": {"group": "app-pdbs"},
                    "accounts": ["acme_web_user"],
                    "secret_template": "tenants/{tenant}#DB/{account}",
                },
                {
                    "name": "monitoring",
                    "targets": ["cdb-root-dev"],
                    "accounts": ["C##MONITOR"],
                    "secret": "ops/monitoring/db/common#password",
                },
            ],
        )
    )

    by_application: dict[str | None, set[str]] = {}
    for binding in config.bindings:
        by_application.setdefault(binding.application, set()).add(binding.target)

    assert by_application["monitoring"] == {"cdb-root-dev"}
    assert "cdb-root-dev" not in by_application["acme"]


def test_a_literal_ref_is_shared_by_every_target_it_binds() -> None:
    """§7: one account across many targets sharing one secret is legal and often
    intended. It is not hidden -- every binding names the same ref, and the view
    that renders them can say so."""
    config = build_config(
        document(
            groups=GROUPS,
            applications=[
                {
                    "name": "acme",
                    "targets": {"group": "app-pdbs"},
                    "accounts": ["acme_web_user"],
                    "secret": "apps/acme/db#password",
                }
            ],
        )
    )

    assert {str(binding.secret) for binding in config.bindings} == {"apps/acme/db#password"}
    assert len(config.bindings) == 3


# ------------------------------------------------------- somewhere to stage ---


def test_a_ref_naming_a_whole_secret_is_refused_while_the_file_is_read() -> None:
    """#111: the refusal existed, at the first rotation. This is when it fires.

    On a store that emulates staging, `pending` and `previous` are keys beside
    the container -- so a ref with no field has nowhere to put them, and the
    document it names cannot hold a rotation at all.
    """
    with pytest.raises(ConfigError) as caught:
        bind(accounts=["acme_web_user"], secret_template="apps/{account}")

    assert "nowhere to stage into" in str(caught.value)
    assert "applications[0].secret_template" in str(caught.value)
    assert "#password" in str(caught.value)


@pytest.mark.parametrize(
    "container",
    ["pending", "previous", "rotated_at", "rotated_by", "policy", "targets"],
)
def test_a_container_named_after_a_staging_key_is_refused(container: str) -> None:
    """The other half of the collision: `#pending/acme_web_user` would put the
    current stage and the pending stage in one document key."""
    with pytest.raises(ConfigError, match="reserved field name"):
        bind(
            accounts=["acme_web_user"],
            secret_template=f"tenants/{{tenant}}#{container}/{{account}}",
        )


def test_a_field_called_current_is_fine() -> None:
    """`current` is where the ref already points, so it is not a root key and
    collides with nothing. The rule is about the keys the mirror generates."""
    bindings = bind(
        accounts=["acme_web_user"], secret_template="tenants/{tenant}#current/{account}"
    )

    assert str(bindings[0].secret) == "tenants/alpha#current/acme_web_user"


def test_a_store_that_stages_natively_is_left_alone() -> None:
    """P2: OCI's stages are versions of the secret, not fields in it.

    So a ref naming a whole secret is the natural OCI layout rather than a
    mistake, and refusing it everywhere would reject a correct config to enforce
    a rule that exists only because HashiCorp KV has to emulate what OCI has.
    """
    config = build_config(
        {
            "version": 1,
            "vaults": {"vault-oci": {"type": "oci"}, **VAULTS},
            "target_sets": {"appdb": APPDB},
            "groups": GROUPS,
            "applications": [
                {
                    "name": "acme",
                    "targets": {"group": "app-pdbs"},
                    "accounts": ["acme_web_user"],
                    "vault": "vault-oci",
                    "secret_template": "apps/{account}",
                }
            ],
        }
    )

    assert str(config.bindings[0].secret) == "apps/acme_web_user"


def test_a_store_with_no_capability_row_is_left_alone() -> None:
    """`keyring` is absent from P2's table, and deciding what it does about
    staging is P2's call rather than this layer's. Absent means the check does
    not fire, which is the reversible direction."""
    config = build_config(
        {
            "version": 1,
            "vaults": {"vault-keyring": {"type": "keyring"}, **VAULTS},
            "target_sets": {"appdb": APPDB},
            "groups": GROUPS,
            "applications": [
                {
                    "name": "acme",
                    "targets": {"group": "app-pdbs"},
                    "accounts": ["acme_web_user"],
                    "vault": "vault-keyring",
                    "secret_template": "apps/{account}",
                }
            ],
        }
    )

    assert str(config.bindings[0].secret) == "apps/acme_web_user"


def test_the_key_reported_is_the_override_that_wrote_the_bad_ref() -> None:
    """Checked per binding, on the rendered ref, so the location is the line
    that actually produced it -- not the entry it patched."""
    with pytest.raises(ConfigError) as caught:
        bind(
            accounts=["acme_web_user"],
            secret_template="tenants/{tenant}#DB/{account}",
            overrides=[{"where": {"env": "dev"}, "secret_template": "shared/{account}"}],
        )

    assert "applications[0].overrides[0].secret_template" in str(caught.value)


def test_a_ref_naming_a_vault_that_is_not_declared_is_refused() -> None:
    """The one way of naming a store that went unchecked.

    `references.py` resolves the other five -- the target's `vault:`, the entry's,
    an override's, a profile's, `defaults.vault` -- and the prefix on an
    `admin.auth.secret`. An application's own prefix could not join them there,
    because it is not resolvable until §7's tokens have been rendered.

    Its own docstring says why that matters: a dangling store name does not stay
    dangling. This one does not even fall back -- the prefix wins outright, so the
    binding resolved to a store that does not exist.
    """
    with pytest.raises(ConfigError) as caught:
        bind(accounts=["acme_web_user"], secret_template="vault-typo:apps/{account}#password")

    assert "no vault named 'vault-typo' is declared" in str(caught.value)
    assert "applications[0].secret_template" in str(caught.value)


def test_a_ref_naming_a_declared_vault_is_fine() -> None:
    """The rule is that the name resolves, not that the prefix is unusual."""
    binding = only(
        **one_target(
            accounts=["acme_web_user"], secret_template="vault-other:apps/{account}#password"
        )
    )

    assert binding.vault == "vault-other"

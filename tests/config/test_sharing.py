"""Which secrets more than one binding lands on (#110).

Sharing is legal and often intended (§7). What it must never be is invisible, so
almost every test here is about a config that is *correct* and still has something
to report -- the failure mode is silence, not a false alarm.

The two axes are deliberately tested apart. A document shared by six accounts in
one PDB and a password shared by one account across eleven PDBs are different
mistakes to make, and an implementation that collapsed them would report the
second and miss the first.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.loading import build_config
from sopuli.config.sharing import SharedSecret, shared_secrets

VAULTS: dict[str, Any] = {"vault-dev": {"type": "hashicorp"}, "vault-other": {"type": "hashicorp"}}

APPDB: dict[str, Any] = {
    "type": "oracle",
    "name": "appdb-{env}-{tenant}",
    "dsn": "{host}:1521/{tenant}.pdb.example.com",
    "environment": "{env}",
    "vault": "vault-dev",
    "oracle": {"scope": "pdb", "container": "{tenant}pdb"},
    "for_each": {
        "env": {"dev": {"host": "db-dev.example.com", "tenant": ["alpha", "beta", "gamma"]}}
    },
}

ACCOUNTS = ["acme_web_user", "acme_api_user", "acme_batch_user"]


def found(**entry: Any) -> tuple[SharedSecret, ...]:
    """Detection over one application spanning the three generated PDBs."""
    application = {"name": "acme", "targets": {"group": "app-pdbs"}, **entry}
    config = build_config(
        {
            "version": 1,
            "vaults": VAULTS,
            "target_sets": {"appdb": APPDB},
            "groups": {"app-pdbs": {"match": {"target_set": "appdb"}}},
            "applications": [application],
        }
    )
    return shared_secrets(config.bindings)


# ------------------------------------------------------------- the axes ---


def test_one_document_per_application_is_shared_by_its_accounts() -> None:
    """Q7's default layout, and the axis #85 added.

    Each tenant gets its own document, so nothing is shared across targets --
    but three accounts land in each, and a write to one sits beside the others.
    """
    shared = found(accounts=ACCOUNTS, secret_template="tenants/{tenant}#DB_CREDENTIALS/{account}")

    assert [entry.path for entry in shared] == ["tenants/alpha", "tenants/beta", "tenants/gamma"]
    assert all(entry.accounts == tuple(ACCOUNTS) for entry in shared)
    assert all(len(entry.targets) == 1 for entry in shared)


def test_one_password_across_every_target_is_shared_by_them() -> None:
    """UC-1 §4's original case: a template with no distinguishing label, so
    rotating one account quietly changes three PDBs."""
    (entry,) = found(accounts=["acme_web_user"], secret_template="apps/acme/{account}#password")

    assert entry.targets == ("appdb-dev-alpha", "appdb-dev-beta", "appdb-dev-gamma")
    assert entry.accounts == ("acme_web_user",)


def test_both_axes_at_once() -> None:
    """One document, three accounts, three PDBs -- and both facts are reported,
    because either alone would understate what a write touches."""
    (entry,) = found(accounts=ACCOUNTS, secret_template="apps/acme/db#DB_CREDENTIALS/{account}")

    assert entry.accounts == tuple(ACCOUNTS)
    assert entry.targets == ("appdb-dev-alpha", "appdb-dev-beta", "appdb-dev-gamma")


def test_a_document_that_is_nobody_else_s_is_not_reported() -> None:
    """One account, one target: the ordinary case, and not a finding.

    The whole point of the field is the sharing somebody might not have intended,
    so reporting every secret would make it worth nothing.
    """
    assert (
        found(
            accounts=["acme_web_user"],
            secret_template="tenants/{tenant}/{account}#password",
            targets={"match": {"tenant": "alpha"}},
        )
        == ()
    )


# --------------------------------------------------------- what it keys on ---


def test_it_keys_on_the_document_not_on_the_ref() -> None:
    """Three accounts in one document are one entry, not three.

    Keying on the full ref would emit three near-identical entries, each
    repeating the same two neighbours -- and it would disagree with the lock,
    which covers the path.
    """
    shared = found(accounts=ACCOUNTS, secret_template="apps/acme/db#DB_CREDENTIALS/{account}")

    assert len(shared) == 1


def test_the_emitted_secret_addresses_the_document() -> None:
    """A vault and a path and no field: the accounts differ below it, and what
    is being described is the thing a write and a compare-and-set operate on."""
    (entry,) = found(accounts=ACCOUNTS, secret_template="apps/acme/db#DB_CREDENTIALS/{account}")

    assert entry.as_json()["secret"] == {"vault": "vault-dev", "path": "apps/acme/db"}


def test_two_spellings_of_one_path_are_one_document() -> None:
    """The same normalisation the lock key uses, so that "shares a document" and
    "shares a lock" cannot give two different answers."""
    shared = found(
        accounts=ACCOUNTS,
        secret_template="apps//acme/db/#DB_CREDENTIALS/{account}",
    )

    assert [entry.path for entry in shared] == ["apps/acme/db"]


def test_one_path_in_two_stores_is_two_documents() -> None:
    """Same argument as the lock key's: they are two documents, and a write to
    one is not a write to the other."""
    config = build_config(
        {
            "version": 1,
            "vaults": VAULTS,
            "target_sets": {"appdb": APPDB},
            "groups": {"app-pdbs": {"match": {"target_set": "appdb"}}},
            "applications": [
                {
                    "name": "acme",
                    "targets": {"group": "app-pdbs"},
                    "accounts": ACCOUNTS,
                    "secret_template": "apps/acme/db#DB_CREDENTIALS/{account}",
                },
                {
                    "name": "acme-mirror",
                    "targets": {"group": "app-pdbs"},
                    "accounts": ACCOUNTS,
                    "vault": "vault-other",
                    "secret_template": "apps/acme/db#DB_CREDENTIALS/{account}",
                },
            ],
        }
    )

    assert {entry.vault for entry in shared_secrets(config.bindings)} == {
        "vault-dev",
        "vault-other",
    }


def test_two_applications_sharing_one_document_are_one_entry() -> None:
    """Co-tenancy that spans application entries. A per-application view cannot
    see this, which is why the grouping is over bindings rather than entries."""
    config = build_config(
        {
            "version": 1,
            "vaults": VAULTS,
            "target_sets": {"appdb": APPDB},
            "groups": {"app-pdbs": {"match": {"target_set": "appdb"}}},
            "applications": [
                {
                    "name": "acme",
                    "targets": {"group": "app-pdbs"},
                    "accounts": ["acme_web_user"],
                    "secret_template": "apps/shared/db#DB_CREDENTIALS/{account}",
                },
                {
                    "name": "reporting",
                    "targets": {"group": "app-pdbs"},
                    "accounts": ["report_reader"],
                    "secret_template": "apps/shared/db#DB_CREDENTIALS/{account}",
                },
            ],
        }
    )

    (entry,) = shared_secrets(config.bindings)
    assert entry.accounts == ("acme_web_user", "report_reader")


def test_an_application_with_no_ref_contributes_nothing() -> None:
    """§3 makes `secret` optional and this layer does not invent one."""
    assert found(accounts=ACCOUNTS) == ()


# ---------------------------------------------------------------- output ---


def test_order_follows_the_bindings() -> None:
    """Document order, so the same names read the same way here as in the
    estate table and the binding rows."""
    shared = found(accounts=ACCOUNTS, secret_template="tenants/{tenant}#DB_CREDENTIALS/{account}")

    assert [entry.path for entry in shared] == ["tenants/alpha", "tenants/beta", "tenants/gamma"]
    assert shared[0].accounts == ("acme_web_user", "acme_api_user", "acme_batch_user")


def test_a_single_account_is_not_emitted_as_a_list_of_one() -> None:
    """The schema's `minItems: 2`. `accounts` reads as "the sharing you might not
    have intended", and one account is the ordinary layout rather than a finding."""
    (entry,) = found(accounts=["acme_web_user"], secret_template="apps/acme/{account}#password")

    assert "accounts" not in entry.as_json()
    assert entry.as_json()["targets"] == list(entry.targets)


@pytest.mark.parametrize(
    "template",
    ["tenants/{tenant}#DB_CREDENTIALS/{account}", "apps/acme/{account}#password"],
    ids=["shared by accounts", "shared by targets"],
)
def test_detection_is_deterministic(template: str) -> None:
    """Read twice from the same file, it says the same thing -- which is what
    lets a plan be reviewed before it is run."""
    assert found(accounts=ACCOUNTS, secret_template=template) == found(
        accounts=ACCOUNTS, secret_template=template
    )


def test_a_document_no_store_is_named_for_still_reports() -> None:
    """A config can name no store at all -- no `vault-name:` prefix, no
    application `vault:`, none on the target, no `defaults.vault`.

    Nothing outside the file can supply one either: `VAULT_ADDR` and
    `--vault-addr` carry an *address*, while a binding carries a store *name*,
    and names come only from `vaults:`. So the null is real rather than
    transitional, and the entry says so instead of being dropped -- what a write
    would touch is worth reporting whether or not the config has said where.
    """
    config = build_config(
        {
            "version": 1,
            "targets": [
                {
                    "name": "t1",
                    "type": "oracle",
                    "dsn": "db.example.com:1521/S.example.com",
                    "environment": "dev",
                    "oracle": {"scope": "pdb", "container": "P"},
                }
            ],
            "accounts": ACCOUNTS,
            "secret_template": "apps/acme/db#DB_CREDENTIALS/{account}",
        }
    )

    (entry,) = shared_secrets(config.bindings)
    assert entry.vault is None
    assert entry.as_json()["secret"] == {"vault": None, "path": "apps/acme/db"}

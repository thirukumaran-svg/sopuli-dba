"""Two accounts whose `pending` would land in the same place (#255).

A config that loads cleanly used to be able to send two accounts' staged
passwords to the same document key, where the merge kept whichever was written
last: one account's new password lost, and the other's given to both. It was
caught at the write boundary by `generate.group`, one lock and one printed plan
too late; #255 moves it to load, which is where a defect in the *file* belongs.

The shape that does it is one character away from the shape that works, which is
why most of this file is about **not** refusing the correct layouts.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import Binding, Config
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.config.sharing import colliding_stages

VAULTS: dict[str, Any] = {
    "vault-dev": {"type": "hashicorp"},
    "vault-oci": {"type": "oci"},
}

ACCOUNTS = ["acme_web_user", "acme_batch_user"]


def load(
    *,
    template: str,
    accounts: list[str] | None = None,
    vault: str = "vault-dev",
    targets: list[dict[str, Any]] | None = None,
) -> Config:
    estate = targets or [{"name": "plain", "type": "oracle", "dsn": "h:1521/x", "vault": vault}]
    return build_config(
        {
            "version": 1,
            "vaults": VAULTS,
            "targets": estate,
            "applications": [
                {
                    "name": "acme",
                    "targets": [target["name"] for target in estate],
                    "accounts": accounts or ACCOUNTS,
                    "secret_template": template,
                }
            ],
        }
    )


# ------------------------------------------------------------- the refusal ---


def test_a_field_per_account_with_no_pointer_is_refused_at_load() -> None:
    """`#{account}` makes each account a root field, so the mirror rule puts
    every account's stage at the document root -- one `pending` for two
    passwords."""
    with pytest.raises(ConfigError, match="would both stage into `pending`") as raised:
        load(template="apps/acme/db#{account}")

    assert "acme_web_user" in raised.value.message
    assert "acme_batch_user" in raised.value.message


def test_the_refusal_names_the_pointer_form_that_works() -> None:
    """The remedy is one character away, and nobody should have to derive it."""
    with pytest.raises(ConfigError) as raised:
        load(template="apps/acme/db#{account}")

    assert "path#FIELD/{account}" in (raised.value.hint or "")


def test_the_refusal_is_located_at_the_application_entry() -> None:
    """§10's rule for every other config error: say where in the file."""
    with pytest.raises(ConfigError) as raised:
        load(template="apps/acme/db#{account}")

    assert str(raised.value.at) == "applications[0]"


def test_the_location_is_the_entry_that_collides_not_the_first_to_name_the_account() -> None:
    """One account may be declared by two application entries, each with its own
    ref, and only one of them collides. Locating by account name alone would send
    an operator to a line that is fine."""
    document: dict[str, Any] = {
        "version": 1,
        "vaults": VAULTS,
        "targets": [{"name": "plain", "type": "oracle", "dsn": "h:1521/x", "vault": "vault-dev"}],
        "applications": [
            {
                "name": "other",
                "targets": ["plain"],
                "accounts": ["acme_web_user"],
                "secret_template": "apps/other/db#password",
            },
            {
                "name": "acme",
                "targets": ["plain"],
                "accounts": ["acme_batch_user", "acme_web_user"],
                "secret_template": "apps/acme/db#{account}",
            },
        ],
    }

    with pytest.raises(ConfigError) as raised:
        build_config(document)

    assert str(raised.value.at) == "applications[1]"


def test_a_template_with_no_account_token_is_still_the_earlier_refusal() -> None:
    """A ref with no `{account}` in it at all sends two accounts to one *field*,
    which is the same loss one step earlier -- and `secret_template` already
    refuses it, by name, before any binding exists.

    Asserted here so the boundary between the two checks stays where it is: this
    one is about a template that does vary per account and still lands them in
    one place. A collision check that also claimed this case would give the same
    file two different error messages depending on which ran first."""
    with pytest.raises(ConfigError, match="would share one secret ref"):
        load(template="apps/acme/db#password")


def test_it_carries_the_config_exit_code() -> None:
    """P5's exit 9: the file is wrong, which is the failure an operator can act
    on -- distinct from "it broke" and from "you typed the command wrong"."""
    with pytest.raises(ConfigError) as raised:
        load(template="apps/acme/db#{account}")

    assert raised.value.exit_code == 9


# ---------------------------------------------------- what must still load ---


def test_the_documented_shared_layout_loads() -> None:
    """Q7's default (#85), and the layout `01-configuration.md` §2 uses. A check
    that rejected this would reject the shape the tool recommends."""
    assert len(load(template="apps/acme/db#DB_CREDENTIALS/{account}").bindings) == 2


def test_one_document_per_account_loads() -> None:
    """The other supported layout: a document each, so nothing is shared and the
    root stage is right."""
    assert len(load(template="apps/acme/{account}#password").bindings) == 2


def test_one_account_at_the_document_root_loads() -> None:
    """UC-1 §3's own worked payload. One account, so there is nothing to collide
    with -- refusing it would reject the example in the design document."""
    assert len(load(accounts=["acme_web_user"], template="apps/acme/db#{account}").bindings) == 1


def test_one_account_across_many_targets_is_not_a_collision() -> None:
    """Eleven PDBs is eleven bindings sharing one document and one stage
    location, and it is the ordinary case: same account, same credential. A
    check that de-duplicated by binding rather than by account would refuse the
    estate §7 is built around."""
    config = load(
        accounts=["acme_web_user"],
        template="apps/acme/db#{account}",
        targets=[
            {"name": "alpha", "type": "oracle", "dsn": "h:1521/a", "vault": "vault-dev"},
            {"name": "beta", "type": "oracle", "dsn": "h:1521/b", "vault": "vault-dev"},
        ],
    )

    assert len(config.bindings) == 2


def test_native_staging_is_left_alone() -> None:
    """`_check_stageable`'s own reason (#111): where a store stages natively the
    stages are versions of the secret, so there is no root `pending` key for two
    accounts to contend over. Refusing this would reject a correct OCI config to
    enforce a rule that exists only because HashiCorp KV emulates staging."""
    assert len(load(template="apps/acme/db#{account}", vault="vault-oci").bindings) == 2


def test_two_accounts_in_two_documents_do_not_collide() -> None:
    """The grouping is per document, so two roots in two documents are two
    places -- which is what makes `{account}` in the *path* a fix as well."""
    assert len(load(template="apps/acme/{account}/db#password").bindings) == 2


# ------------------------------------------------------------ the function ---


def test_one_pair_is_reported_per_document() -> None:
    """A template that gives every account the root has as many pairs as it has
    accounts. Listing them all would bury the one fact worth reading, which is
    that the template is wrong."""
    ref = parse_secret_ref("apps/acme/db#DB_CREDENTIALS")
    bindings = [
        Binding(account=account, target="plain", secret=ref, vault="vault-dev")
        for account in ("one", "two", "three")
    ]

    (collision,) = colliding_stages(bindings)

    assert collision.accounts == ("one", "two")
    assert collision.document == "vault-dev:apps/acme/db"


def test_the_path_is_normalised_before_grouping() -> None:
    """ "Shares a document", "shares a lock" and "collides" go through one
    normaliser, so a doubled separator cannot make one pair look like two."""
    bindings = [
        Binding(
            account="one", target="plain", secret=parse_secret_ref("apps/acme/db#F"), vault="v"
        ),
        Binding(
            account="two", target="plain", secret=parse_secret_ref("/apps//acme/db#F"), vault="v"
        ),
    ]

    assert len(colliding_stages(bindings)) == 1


def test_two_stores_at_one_path_are_two_documents() -> None:
    """The same path in two vaults addresses two documents. Nothing to overwrite."""
    ref = parse_secret_ref("apps/acme/db#F")
    bindings = [
        Binding(account="one", target="plain", secret=ref, vault="vault-dev"),
        Binding(account="two", target="plain", secret=ref, vault="vault-other"),
    ]

    assert colliding_stages(bindings) == ()


def test_a_binding_with_no_ref_contributes_nothing() -> None:
    """§3 makes `secret` optional and this layer does not invent one."""
    bindings = [Binding(account="one", target="plain", secret=None, vault="vault-dev")]

    assert colliding_stages(bindings) == ()

"""SecretRef parsing (§7).

One string addresses a value in any backend, and P2 makes only its *resolution*
backend-specific. So the structure has to be decided once, here, and be right:
a ref parsed into the wrong parts does not fail, it reads or writes a password
somewhere other than where the file says.

Every example §7 gives is parsed below, because the reference's own table is the
specification. The rest are the ambiguities that have to be settled to parse the
grammar at all -- a colon that is not a vault, an `@` that is not a qualifier --
and the malformed refs that must be refused rather than quietly reinterpreted.
"""

from __future__ import annotations

import pytest

from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.secret_refs import SecretRef, parse_secret_ref

# --------------------------------------------------- the reference's table ---


def test_a_bare_path_is_the_whole_secret() -> None:
    ref = parse_secret_ref("apps/orders/prod/db/ORDERS_APP")

    assert ref == SecretRef(path="apps/orders/prod/db/ORDERS_APP")
    assert ref.field is None
    assert ref.pointer_segments == ()


def test_a_field_is_named_after_a_hash() -> None:
    ref = parse_secret_ref("apps/orders/prod/db/ORDERS_APP#password")

    assert ref.path == "apps/orders/prod/db/ORDERS_APP"
    assert ref.field == "password"


def test_a_vault_is_named_before_a_colon() -> None:
    ref = parse_secret_ref("vault-dev:apps/orders/prod/db/creds#password")

    assert ref.vault == "vault-dev"
    assert ref.path == "apps/orders/prod/db/creds"
    assert ref.field == "password"


def test_a_pointer_addresses_into_a_json_field() -> None:
    """§2's layout: several accounts in one `DB_CREDENTIALS` property."""
    ref = parse_secret_ref("tenants/beta#DB_CREDENTIALS/acme_web_user")

    assert ref.path == "tenants/beta"
    assert ref.field == "DB_CREDENTIALS"
    assert ref.pointer == "/acme_web_user"
    assert ref.pointer_segments == ("acme_web_user",)


def test_a_version_can_be_pinned() -> None:
    ref = parse_secret_ref("apps/orders/prod/db/creds#password@version=7")

    assert ref.field == "password"
    assert ref.version == "7"
    assert ref.stage is None


def test_a_stage_can_be_named() -> None:
    ref = parse_secret_ref("apps/orders/prod/db/creds#password@stage=PENDING")

    assert ref.stage == "PENDING"
    assert ref.version is None


def test_a_qualifier_value_is_kept_as_written() -> None:
    """P2 puts per-backend validation behind the store interface. Version
    numbering and the stage vocabulary belong to the backend, so the parser
    carries the text rather than inventing a schema the vault layer then has to
    live with -- the same reasoning as `auth.method` in vaults.py."""
    assert parse_secret_ref("creds#password@version=v3-beta").version == "v3-beta"
    assert parse_secret_ref("creds#password@stage=whatever").stage == "whatever"


# ------------------------------------------------------------ ambiguities ---


def test_a_colon_after_the_path_starts_is_not_a_vault() -> None:
    """Otherwise `tenants/beta#DB:extra` names a vault called `tenants/beta#DB`,
    and the tool looks for a store that was never declared."""
    ref = parse_secret_ref("tenants/beta#DB:extra")

    assert ref.vault is None
    assert ref.path == "tenants/beta"
    assert ref.field == "DB:extra"


def test_a_colon_inside_a_field_is_not_a_vault_either() -> None:
    ref = parse_secret_ref("creds#a:b")

    assert ref.vault is None
    assert ref.field == "a:b"


def test_a_vault_prefix_works_without_any_slash_in_the_path() -> None:
    ref = parse_secret_ref("vault-dev:creds")

    assert ref.vault == "vault-dev"
    assert ref.path == "creds"


def test_an_at_sign_in_a_path_is_not_a_qualifier() -> None:
    """`apps/user@example.com/db` is an ordinary path. A qualifier is only a
    qualifier when what follows it is an assignment."""
    ref = parse_secret_ref("apps/user@example.com/db")

    assert ref.path == "apps/user@example.com/db"
    assert ref.version is None
    assert ref.stage is None


def test_a_path_with_an_at_sign_can_still_be_qualified() -> None:
    ref = parse_secret_ref("apps/user@example.com/db#password@version=2")

    assert ref.path == "apps/user@example.com/db"
    assert ref.field == "password"
    assert ref.version == "2"


def test_an_assignment_inside_the_path_is_not_a_second_qualifier() -> None:
    """A qualifier can only be at the end, so that is the only place looked at.
    Scanning the whole ref for `@...=...` would contradict the rule above and
    reject this, where `@foo=bar` is path text and only `@version=2` qualifies.
    """
    ref = parse_secret_ref("apps/user@foo=bar/db#password@version=2")

    assert ref.path == "apps/user@foo=bar/db"
    assert ref.field == "password"
    assert ref.version == "2"


def test_two_real_qualifiers_are_still_refused() -> None:
    """The other side of the same rule: `@version=1@stage=X` is two of them."""
    with pytest.raises(ConfigError) as caught:
        parse_secret_ref("creds#password@version=1@stage=X")

    assert "more than one qualifier" in str(caught.value)


# ---------------------------------------------------------------- pointers ---


def test_a_pointer_may_have_several_segments() -> None:
    ref = parse_secret_ref("tenants/beta#DB_CREDENTIALS/acme/web/user")

    assert ref.pointer == "/acme/web/user"
    assert ref.pointer_segments == ("acme", "web", "user")


def test_pointer_segments_are_unescaped_per_rfc_6901() -> None:
    """`a~1b` is the single key `a/b`. A store that split on `/` itself would
    write into the wrong place, or create a level that was never meant."""
    ref = parse_secret_ref("tenants/beta#DB/a~1b/c~0d")

    assert ref.pointer_segments == ("a/b", "c~d")


def test_the_escape_order_is_the_one_the_rfc_specifies() -> None:
    """`~01` decodes to `~1`, not to `/`. The other order silently addresses a
    different key."""
    assert parse_secret_ref("creds#DB/a~01b").pointer_segments == ("a~1b",)


# ------------------------------------------------------------ round-tripping ---


@pytest.mark.parametrize(
    "text",
    [
        "apps/orders/prod/db/ORDERS_APP",
        "apps/orders/prod/db/ORDERS_APP#password",
        "vault-dev:apps/orders/prod/db/creds#password",
        "tenants/beta#DB_CREDENTIALS/acme_web_user",
        "apps/orders/prod/db/creds#password@version=7",
        "apps/orders/prod/db/creds#password@stage=PENDING",
        "vault-prod:tenants/beta#DB_CREDENTIALS/acme_web_user@version=3",
        "tenants/{tenant}#DB_CREDENTIALS/{account}",
    ],
)
def test_a_ref_renders_back_to_what_it_was_parsed_from(text: str) -> None:
    """Plan output and the audit trail name a secret by its ref. A rendered form
    that differed from the one in the config file would make the two impossible
    to line up by eye."""
    assert str(parse_secret_ref(text)) == text


# ------------------------------------------------------------- templates ---


def test_a_template_parses_as_the_ref_it_will_become() -> None:
    """The punctuation that gives a ref its shape is literal, and the tokens sit
    inside the parts -- so §2's template can be checked when the file is read
    rather than at the first rotation."""
    ref = parse_secret_ref("tenants/{tenant}#DB_CREDENTIALS/{account}")

    assert ref.path == "tenants/{tenant}"
    assert ref.field == "DB_CREDENTIALS"
    assert ref.pointer_segments == ("{account}",)
    assert ref.is_templated


def test_a_literal_ref_is_not_templated() -> None:
    assert not parse_secret_ref("tenants/beta#DB_CREDENTIALS/acme_web_user").is_templated


def test_a_token_may_carry_the_vault_name() -> None:
    """§4's estate writes `vault: "{vault}"` on a target set, so a ref that does
    the same is not a special case."""
    assert parse_secret_ref("{vault}:tenants/{tenant}").vault == "{vault}"


# ---------------------------------------------------------------- refusals ---


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", "must not be empty"),
        ("   ", "must not be empty"),
        (" creds#password", "leading or trailing whitespace"),
        ("creds#password ", "leading or trailing whitespace"),
        (":creds", "names an empty vault"),
        ("#password", "has no path"),
        ("creds#", "has an empty field"),
        ("creds#a#b", "more than one `#`"),
        ("creds#DB/", "empty pointer segment"),
        ("creds#DB/a//b", "empty pointer segment"),
        ("creds#password@versio=7", "unknown qualifier 'versio'"),
        ("creds#password@version=", "has no value"),
        ("creds#password@version=1@stage=X", "more than one qualifier"),
        ("@version=7", "qualifier with nothing to qualify"),
    ],
    ids=lambda value: str(value)[:28],
)
def test_a_malformed_ref_is_refused_with_its_own_text(text: str, expected: str) -> None:
    """Every message names the ref as written. "the secret ref is invalid" is
    unusable in a file that declares a dozen of them."""
    with pytest.raises(ConfigError) as caught:
        parse_secret_ref(text, at=ROOT.key("applications").index(0).key("secret"))

    rendered = str(caught.value)
    assert expected in rendered
    if text.strip():
        assert repr(text) in rendered


def test_a_refusal_carries_the_key_path_it_was_read_from() -> None:
    """The parser is called from the builders, so its errors have to locate
    themselves the same way every other config error does."""
    with pytest.raises(ConfigError) as caught:
        parse_secret_ref("creds#", at=ROOT.key("applications").index(1).key("secret_template"))

    assert "applications[1].secret_template" in str(caught.value)


def test_the_pointer_to_a_key_named_nothing_is_refused_rather_than_honoured() -> None:
    """RFC 6901 allows it -- `/` addresses the empty key -- but nothing in a
    credential store is named that, so it is a trailing slash somebody left
    behind."""
    with pytest.raises(ConfigError):
        parse_secret_ref("tenants/beta#DB_CREDENTIALS/")

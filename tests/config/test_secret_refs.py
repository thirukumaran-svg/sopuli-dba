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
    assert ref.version == 7
    assert ref.stage is None


def test_a_stage_can_be_named() -> None:
    ref = parse_secret_ref("apps/orders/prod/db/creds#password@stage=pending")

    assert ref.stage == "pending"
    assert ref.version is None


def test_a_stage_is_matched_in_any_case_and_kept_in_one() -> None:
    """C14: OCI writes `PENDING`, so that is the spelling somebody copies
    out of the console -- but one spelling reaches the store, and the backends
    map from it rather than to each other."""
    assert parse_secret_ref("creds#password@stage=PENDING").stage == "pending"
    assert parse_secret_ref("creds#password@stage=Previous").stage == "previous"


def test_a_qualifier_value_is_checked_rather_than_carried() -> None:
    """C14: both stores in scope have a fixed vocabulary of their own, so
    passing an unknown value through would buy nothing and move a typo to
    rotation time -- which invariant 4 says is the wrong time to find out."""
    with pytest.raises(ConfigError) as version:
        parse_secret_ref("creds#password@version=v3-beta")
    assert "not a whole number" in str(version.value)

    with pytest.raises(ConfigError) as stage:
        parse_secret_ref("creds#password@stage=whatever")
    assert "unknown stage 'whatever'" in str(stage.value)


def test_the_stages_oracle_has_but_the_tool_does_not_are_refused() -> None:
    """Three of OCI's five, deliberately: `LATEST` is an upload-ordering artefact
    with no counterpart in a payload of JSON fields, and `DEPRECATED` names a set
    of versions rather than selecting one."""
    for stage in ("LATEST", "DEPRECATED"):
        with pytest.raises(ConfigError) as caught:
            parse_secret_ref(f"creds#password@stage={stage}")

        assert "unknown stage" in str(caught.value)
        assert "current, pending, previous" in str(caught.value)


def test_version_zero_is_refused_rather_than_read_as_latest() -> None:
    """KV v2 reads version 0 as "the latest version" and OCI numbers from 1. A
    ref that meant two different things depending on where it resolved would be
    a rotation reading the wrong password."""
    with pytest.raises(ConfigError) as caught:
        parse_secret_ref("creds#password@version=0")

    assert "below the first version" in str(caught.value)
    assert "@stage=current" in str(caught.value)


def test_a_version_written_in_another_script_is_a_typo_not_a_preference() -> None:
    """`int()` would accept it. Nothing else in the toolchain would."""
    with pytest.raises(ConfigError):
        parse_secret_ref("creds#password@version=٧")


def test_a_padded_version_is_refused_rather_than_quietly_read_as_the_number() -> None:
    """`@version=007` is 7, and reading it as such would be a second thing that
    does not render back as it was written. Upper case has a source -- OCI spells
    its rotation states that way -- and padding has none."""
    with pytest.raises(ConfigError) as caught:
        parse_secret_ref("creds#password@version=007")

    assert "padded with leading zeros" in str(caught.value)
    assert "@version=7" in str(caught.value)


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
    assert ref.version == 2


def test_an_assignment_inside_the_path_is_not_a_second_qualifier() -> None:
    """A qualifier can only be at the end, so that is the only place looked at.
    Scanning the whole ref for `@...=...` would contradict the rule above and
    reject this, where `@foo=bar` is path text and only `@version=2` qualifies.
    """
    ref = parse_secret_ref("apps/user@foo=bar/db#password@version=2")

    assert ref.path == "apps/user@foo=bar/db"
    assert ref.field == "password"
    assert ref.version == 2


def test_two_real_qualifiers_are_still_refused() -> None:
    """The other side of the same rule: `@version=1@stage=pending` is two of
    them. Both values are legal, so this is the structural rule on its own."""
    with pytest.raises(ConfigError) as caught:
        parse_secret_ref("creds#password@version=1@stage=pending")

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
        "apps/orders/prod/db/creds#password@stage=pending",
        "vault-prod:tenants/beta#DB_CREDENTIALS/acme_web_user@version=3",
        "tenants/{tenant}#DB_CREDENTIALS/{account}",
    ],
)
def test_a_ref_renders_back_to_what_it_was_parsed_from(text: str) -> None:
    """Plan output and the audit trail name a secret by its ref. A rendered form
    that differed from the one in the config file would make the two impossible
    to line up by eye."""
    assert str(parse_secret_ref(text)) == text


def test_the_one_thing_that_does_not_round_trip_is_the_case_of_a_stage() -> None:
    """C14's price, and the whole of it: normalising means `config show` prints
    the canonical spelling rather than the file's. Worth it, because two refs
    that differ only in the case of a stage now compare equal."""
    written = "creds#password@stage=PENDING"

    assert str(parse_secret_ref(written)) == "creds#password@stage=pending"
    assert parse_secret_ref(written) == parse_secret_ref("creds#password@stage=pending")


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


@pytest.mark.parametrize("qualifier", ["@version={ver}", "@stage={stage}"])
def test_a_qualifier_may_not_hold_a_token(qualifier: str) -> None:
    """`secret_template` parses through the same function, so this has to be said
    rather than assumed: a version or stage that varied per target would have one
    rotation reading a different generation on each of them, which is the
    opposite of what UC-1 §3's ordering is for."""
    with pytest.raises(ConfigError) as caught:
        parse_secret_ref(f"tenants/{{tenant}}#DB_CREDENTIALS/{{account}}{qualifier}")

    assert "contains a token" in str(caught.value)


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
        ("creds#password@version=1@stage=pending", "more than one qualifier"),
        ("@version=7", "qualifier with nothing to qualify"),
        ("creds#password@version=v3-beta", "not a whole number"),
        ("creds#password@version=0", "below the first version"),
        ("creds#password@version=007", "padded with leading zeros"),
        ("creds#password@stage=staging", "unknown stage 'staging'"),
        ("creds#password@stage={stage}", "contains a token"),
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


# ------------------------------------------- characters a URL would read ---
#
# The HashiCorp backends put the path into the URL as written (#858).

UNSAFE = [
    pytest.param("apps/acme?x/db", "?", id="query"),
    pytest.param("apps/%2e%2e/secrets", "%", id="percent-encoded-traversal"),
    pytest.param("apps/acme%23x/db", "%", id="percent-encoded-hash"),
    pytest.param("apps\\acme/db", "\\", id="backslash"),
    pytest.param("apps/acme\x00/db", "\x00", id="nul"),
    pytest.param("apps/acme\r/db", "\r", id="carriage-return"),
    pytest.param("apps/acme\x1b]0;x\x07/db", "\x1b", id="escape"),
    pytest.param("apps/acme\x7f/db", "\x7f", id="delete"),
    pytest.param("apps/acme\x85/db", "\x85", id="c1"),
]


@pytest.mark.parametrize(("text", "character"), UNSAFE)
def test_a_character_that_changes_the_url_is_refused_with_its_location(
    text: str, character: str
) -> None:
    with pytest.raises(ConfigError) as caught:
        parse_secret_ref(f"{text}#password", at=ROOT.key("applications").index(0).key("secret"))

    message = str(caught.value)
    assert "applications[0].secret" in message
    assert f"contains {character!r}" in message, "the message must name the character"


def test_every_unsafe_character_is_named_once() -> None:
    with pytest.raises(ConfigError) as caught:
        parse_secret_ref("a?b?c%d")

    assert "contains '?', '%'" in str(caught.value)


def test_a_template_token_is_not_an_unsafe_character() -> None:
    assert parse_secret_ref("tenants/{tenant}/db#{account}").path == "tenants/{tenant}/db"

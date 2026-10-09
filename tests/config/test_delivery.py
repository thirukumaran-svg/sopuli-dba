"""The `delivery:` block — UC-2 §6.

Tier 0, pure: everything builds from a dict, so there is no filesystem and no I/O.
Fixtures use the fictional vocabulary the provenance note requires.

One accept and one reject per rule, and the rejects assert on the *message*: a rule
that fires without saying which key is wrong has not finished its job.

Which keys a method's sub-block takes is a fact about the service behind the
method, so only built methods have keys to test. `vault_wrapped:`'s have a
section of their own below; `vault_path:` (TODO(#447)), `one_time_link:`
(TODO(#445)) and `onepassword_share:` (TODO(#446)) are not read yet. What this
layer owes every method is the part common to all six: the method is one of the
six, and the selected one brought settings.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.delivery import (
    DEFAULT_METHOD,
    DELIVERY_METHODS,
    build_delivery,
    unserviceable,
)
from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config


def document(**block: Any) -> dict[str, Any]:
    return {"version": 1, "delivery": block}


def built(**block: Any) -> Any:
    section = build_delivery(document(**block))
    assert section is not None
    return section


# --------------------------------------------------------------- declaring ---


def test_a_section_that_is_absent_is_none_rather_than_the_default() -> None:
    """An estate that configured no delivery has not silently chosen one. A reset
    with nowhere to deliver is a refusal for the verb to make, and a default
    materialised here would make that estate indistinguishable from one that asked
    for `vault_wrapped` by name."""
    assert build_delivery({"version": 1}) is None


def test_the_method_is_read_and_its_sub_block_is_required() -> None:
    section = built(method="one_time_link", one_time_link={"backend": "yopass"})

    assert section.method == "one_time_link"
    assert not section.is_seen


def test_an_omitted_method_is_the_default() -> None:
    """§6.2: `vault_wrapped` works against a stock Vault, and every other unseen
    method needs infrastructure the tool does not create."""
    assert built(vault_wrapped={"ttl": "15m"}).method == DEFAULT_METHOD
    assert DEFAULT_METHOD == "vault_wrapped"


def test_manual_is_the_one_seen_method() -> None:
    """A path is seen because of what it does, not because a file said so."""
    assert built(method="manual", manual={"force_expire": True}).is_seen
    for method in DELIVERY_METHODS:
        if method != "manual":
            # Each method has its own required keys, so a sweep over the enum
            # has to carry them: `vault_wrapped` needs a `ttl`, and an empty
            # block is a config error rather than an unseen delivery.
            settings = {"ttl": "15m"} if method == "vault_wrapped" else {}
            assert not built(method=method, **{method: settings}).is_seen


def test_the_enum_includes_a_method_with_no_tracking_issue() -> None:
    """`smtp_encrypted` has no issue of its own and is in the enum anyway. An enum
    listing only what somebody had written a ticket for would be a contract shaped
    by project bookkeeping (UC-2 §6.2)."""
    assert "smtp_encrypted" in DELIVERY_METHODS
    assert len(DELIVERY_METHODS) == 6


@pytest.mark.parametrize(
    "method",
    [
        {"method": "manual", "manual": {"force_expire": True}},
        {"method": "vault_wrapped", "vault_wrapped": {"ttl": "15m"}},
    ],
    ids=["manual", "vault_wrapped"],
)
def test_a_notify_block_is_read_whichever_built_method_is_selected(
    method: dict[str, Any],
) -> None:
    """`tests/config/test_notify.py` holds the notify block's grammar; what
    belongs here is that `delivery:` reaches it, and that it does so for each
    method this build serves, the seen one and the unseen one."""
    section = built(
        **method,
        notify={
            "method": "webhook",
            "webhook": {
                "url": {"env": "SOPULI_NOTIFY"},
                "template": "{account} on {target} has a new password waiting",
            },
        },
    )

    assert section.notify is not None
    assert section.notify.webhook is not None
    assert section.notify.webhook.url.location == "SOPULI_NOTIFY"


def test_a_notify_block_is_read_on_the_seen_path_too() -> None:
    """A notification is a property of the delivery as a whole, not of a method --
    so unlike a method's own sub-block it is read whichever method is selected.
    The tool does not author the message, so an estate on `manual` writes one that
    is true of `manual`."""
    section = built(
        method="manual",
        manual={"force_expire": True},
        notify={
            "method": "webhook",
            "webhook": {"url": {"env": "SOPULI_NOTIFY"}, "template": "{account} was reset"},
        },
    )

    assert section.notify is not None


# ---------------------------------------------------------------- refusing ---


def test_an_unknown_method_is_refused_and_lists_the_known_ones() -> None:
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="carrier_pigeon", carrier_pigeon={}))
    message = str(raised.value)
    assert "delivery.method" in message
    assert "carrier_pigeon" in message
    assert "vault_wrapped" in message


def test_a_method_without_its_sub_block_is_refused_naming_the_method() -> None:
    """Half a configuration, and the half that was typed is the half that reads as
    done."""
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="one_time_link"))
    message = str(raised.value)
    assert "one_time_link" in message
    assert "delivery.one_time_link" in message


def test_the_default_method_needs_its_block_too() -> None:
    """An omitted `method:` is `vault_wrapped`, and a default is not an excuse to
    skip the settings it needs."""
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(notify={"method": "webhook"}))
    assert "vault_wrapped" in str(raised.value)


def test_a_sub_block_for_an_unselected_method_is_left_alone() -> None:
    """Keeping a configuration you are switching between is ordinary, and refusing
    it would make the file harder to edit without making a run safer -- nothing
    reads an unselected block. The opposite of §1's leftover `secret_template:`,
    where the stale key silently *governs*."""
    section = built(
        method="manual",
        manual={"force_expire": True},
        vault_wrapped={"ttl": "15m"},
    )

    assert section.method == "manual"


def test_an_unknown_key_in_the_block_is_refused() -> None:
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="manual", manual={}, retries=3))
    assert "retries" in str(raised.value)


def test_a_sub_block_that_is_not_a_mapping_is_refused() -> None:
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="manual", manual=["force_expire"]))
    assert "delivery.manual" in str(raised.value)


def test_a_notify_block_that_is_not_a_mapping_is_refused() -> None:
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="manual", manual={}, notify="webhook"))
    assert "delivery.notify" in str(raised.value)


def test_the_block_is_a_mapping_not_a_list() -> None:
    with pytest.raises(ConfigError) as raised:
        build_delivery({"version": 1, "delivery": [{"method": "manual"}]})
    assert "delivery" in str(raised.value)


# --------------------------------------------- a method this build lacks ---


def test_an_unimplemented_method_warns_that_nothing_serves_it() -> None:
    """A `delivery:` block that validates silently reads as delivery being
    configured, and the operator would find out otherwise at the moment a password
    had already been drawn."""
    # The test is about the warning, not about which method is missing, so it
    # uses one this build does not implement.
    notice = unserviceable(built(method="one_time_link", one_time_link={}))

    assert notice is not None
    assert "one_time_link" in notice
    assert "not implemented in this build" in notice


def test_an_implemented_method_warns_about_nothing() -> None:
    """`manual` is served, and the warning knows that: it would otherwise read
    *no delivery method is implemented* for every configured method, so an estate
    with a working seen path would be told nothing could hand a password over."""
    assert unserviceable(built(method="manual", manual={"force_expire": True})) is None


def test_no_block_means_nothing_to_warn_about() -> None:
    assert unserviceable(None) is None


# --------------------------------------------------------- through loading ---


def test_the_block_reaches_the_config() -> None:
    config = build_config(
        {
            "version": 1,
            "targets": [
                {
                    "name": "appdb-dev-alpha",
                    "type": "oracle",
                    "dsn": "db-dev.example.com:1521/ALPHA.pdb.example.com",
                }
            ],
            "delivery": {"method": "vault_wrapped", "vault_wrapped": {"ttl": "15m"}},
        }
    )

    assert config.delivery is not None
    assert config.delivery.method == "vault_wrapped"
    assert config.delivery.vault_wrapped is not None
    assert config.delivery.vault_wrapped.ttl == "15m"


def test_a_file_with_no_delivery_carries_none() -> None:
    assert build_config({"version": 1}).delivery is None


# ------------------------------------ the tool is never looser than the schema ---


def test_an_unselected_block_that_is_not_an_object_is_refused() -> None:
    """The published schema types all six method properties as objects, so
    `vault_wrapped: 15m` beside `method: manual` is refused by the schema.
    Accepting it here would invert §9b's claim that the schema is the incomplete
    check and the tool the complete one."""
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="manual", manual={}, vault_wrapped="15m"))
    assert "delivery.vault_wrapped" in str(raised.value)


def test_an_unselected_block_is_still_left_alone_in_the_senses_that_matter() -> None:
    """Only the grammar widened. Its presence is not refused and its keys are not
    judged -- `tt1` is still accepted, because which keys a method takes is that
    method's own issue."""
    section = built(
        method="manual",
        manual={"force_expire": True},
        vault_wrapped={"tt1": "15m"},
    )

    assert section.method == "manual"


def test_every_method_block_is_checked_not_only_the_selected_one() -> None:
    for name in DELIVERY_METHODS:
        if name == "manual":
            continue
        with pytest.raises(ConfigError, match=f"delivery.{name}"):
            build_delivery(document(method="manual", manual={}, **{name: "not-an-object"}))


# ----------------------------------------------- the warning reaches the run ---


def test_the_warning_reaches_config_warnings_rather_than_only_the_helper() -> None:
    """The wire, not the function. `_delivery_warnings` could be dropped from the
    loader's return and every other test here would still pass -- which is the
    failure `Setting.inert_reason`'s docstring lists four instances of: a complete
    implementation with the one wire missing, found by somebody reading the code
    rather than by a test."""
    config = build_config(
        {
            "version": 1,
            "delivery": {"method": "one_time_link", "one_time_link": {}},
        }
    )

    found = [warning for warning in config.warnings if "not implemented" in warning.message]
    assert len(found) == 1
    assert found[0].at == "delivery.method"
    assert found[0].hint is not None
    assert "nothing is wrong with the file" in found[0].hint


def test_a_file_with_no_delivery_carries_no_such_warning() -> None:
    config = build_config({"version": 1})

    assert not [w for w in config.warnings if "no delivery method" in w.message]


# ---------------------------------------------------- `vault_wrapped:`'s keys ---


def test_the_ttl_is_required_rather_than_defaulted() -> None:
    """The argument `force_expire` makes one method over: a wrapping token's whole
    safety story is that it stops working, so how soon is not a number to inherit
    from a tool's default. A default would be an unreviewed value standing between
    a password and whoever finds the token afterwards."""
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="vault_wrapped", vault_wrapped={}))

    assert "needs a `ttl`" in str(raised.value)
    assert "delivery.vault_wrapped.ttl" in str(raised.value)


def test_num_uses_is_refused_rather_than_ignored() -> None:
    """A response-wrapping token is single-use by construction, so the key can
    only describe a guarantee Vault is already making -- and accepting it
    silently would leave a file whose author believes the tool is enforcing
    something."""
    with pytest.raises(ConfigError) as raised:
        build_delivery(
            document(method="vault_wrapped", vault_wrapped={"ttl": "15m", "num_uses": 1})
        )

    assert "takes no `num_uses`" in str(raised.value)
    assert "single use by construction" in str(raised.value.hint or "")


@pytest.mark.parametrize("ttl", ["15", "15x", "0m", "-5m", "fifteen minutes", "15 m"])
def test_a_ttl_that_is_not_a_duration_is_refused_at_load(ttl: str) -> None:
    """Shape only, because Vault owns the grammar -- but shape *here*, so a typo
    is a config error rather than a 400 after a password has been drawn."""
    with pytest.raises(ConfigError, match="is not a duration"):
        build_delivery(document(method="vault_wrapped", vault_wrapped={"ttl": ttl}))


def test_an_empty_ttl_is_refused_by_the_field_before_the_shape() -> None:
    """Refused, and with the better message of the two: `must not be empty` says
    what to do, and `is not a duration` about an empty string would leave somebody
    looking for the unit they mistyped. Asserted so that tightening the pattern
    later does not quietly take the precise answer away."""
    with pytest.raises(ConfigError, match="must not be empty"):
        build_delivery(document(method="vault_wrapped", vault_wrapped={"ttl": ""}))


@pytest.mark.parametrize("ttl", ["15m", "900s", "1h", "90m"])
def test_the_durations_vault_actually_takes_are_accepted(ttl: str) -> None:
    section = built(method="vault_wrapped", vault_wrapped={"ttl": ttl})

    assert section.vault_wrapped is not None
    assert section.vault_wrapped.ttl == ttl


def test_the_store_is_optional_and_absence_means_the_chain() -> None:
    """Omitting `vault:` takes §3's chain -- the target's, then `defaults.vault` --
    which is the same resolution a secret ref walks. ``None`` rather than a
    materialised default, so a later layer can tell "not named here" from "named
    as this"."""
    section = built(method="vault_wrapped", vault_wrapped={"ttl": "15m"})

    assert section.vault_wrapped is not None
    assert section.vault_wrapped.vault is None


def test_the_store_can_be_named_on_the_method() -> None:
    """And it is not `reset_records.vault`. UC-2 §3.5 keeps the journal and the
    delivery target apart as two objects with two lifetimes, so an estate that
    wants them in one store says so twice rather than having one default to the
    other."""
    section = built(method="vault_wrapped", vault_wrapped={"ttl": "15m", "vault": "vault-handover"})

    assert section.vault_wrapped is not None
    assert section.vault_wrapped.vault == "vault-handover"


def test_an_unknown_key_in_the_wrapped_block_is_refused() -> None:
    """P3's "a typo in a credential tool must never be silently ignored", applied
    to the *selected* block now that it has keys of its own to typo -- which is
    the difference from the unselected one two tests down, whose keys stay
    unjudged on purpose."""
    with pytest.raises(ConfigError, match="delivery.vault_wrapped"):
        build_delivery(document(method="vault_wrapped", vault_wrapped={"ttl": "15m", "tt1": "x"}))


def test_the_block_is_not_read_when_another_method_is_selected() -> None:
    """`manual`'s rule, one method over: an unselected block is kept so somebody
    can switch between two configurations, and reading it either way would make a
    file start failing for a key the run never consults."""
    section = built(
        method="manual",
        manual={"force_expire": True},
        vault_wrapped={"num_uses": 1},
    )

    assert section.method == "manual"
    assert section.vault_wrapped is None


def test_vault_wrapped_is_served_by_this_build() -> None:
    """The warning that tells an estate nothing could deliver knows about
    `manual` and about this method, and `IMPLEMENTED` is one list so that
    `config validate` and the verb cannot disagree."""
    assert unserviceable(built(method="vault_wrapped", vault_wrapped={"ttl": "15m"})) is None

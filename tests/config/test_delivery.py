"""The `delivery:` block — UC-2 §6, built in #440.

Tier 0, pure: everything builds from a dict, so there is no filesystem and no I/O.
Fixtures use the fictional vocabulary the provenance note requires.

One accept and one reject per rule, and the rejects assert on the *message*: a rule
that fires without saying which key is wrong has not finished its job.

**What is deliberately not tested here** is anything *inside* a method's sub-block.
Which keys `vault_wrapped:` takes is #444's and `one_time_link:`'s is #445's,
because the answer is a fact about the service behind the method rather than about
this file. What this layer owes is the part common to all six: the method is one of
the six, and the selected one brought settings.
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
            assert not built(method=method, **{method: {}}).is_seen


def test_the_enum_is_the_whole_set_including_the_method_with_no_issue() -> None:
    """`smtp_encrypted` has no issue of its own and is in the enum anyway. An enum
    listing only what somebody had written a ticket for would be a contract shaped
    by project bookkeeping (UC-2 §6.2)."""
    assert "smtp_encrypted" in DELIVERY_METHODS
    assert len(DELIVERY_METHODS) == 6


def test_a_notify_block_is_accepted_and_left_to_its_own_issue() -> None:
    section = built(
        method="vault_wrapped",
        vault_wrapped={"ttl": "15m"},
        notify={"method": "webhook", "webhook": {"url": {"env": "SOPULI_NOTIFY"}}},
    )

    assert section.method == "vault_wrapped"


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


# ----------------------------------------------- nothing can deliver yet ---


def test_a_configured_method_warns_that_nothing_implements_it() -> None:
    """A `delivery:` block that validates silently reads as delivery being
    configured, and the operator would find out otherwise at the moment a password
    had already been drawn."""
    notice = unserviceable(built(method="manual", manual={"force_expire": True}))

    assert notice is not None
    assert "manual" in notice
    assert "no delivery method is implemented" in notice


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


def test_a_file_with_no_delivery_carries_none() -> None:
    assert build_config({"version": 1}).delivery is None


# ------------------------------------ the tool is never looser than the schema ---
#
# Both of these come from Copilot's review of #499.


def test_an_unselected_block_that_is_not_an_object_is_refused() -> None:
    """The published schema types all six method properties as objects, so
    `vault_wrapped: 15m` beside `method: manual` was refused by the schema and
    accepted here -- which inverts §9b's claim that the schema is the incomplete
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
            "delivery": {"method": "manual", "manual": {"force_expire": True}},
        }
    )

    found = [warning for warning in config.warnings if "no delivery method" in warning.message]
    assert len(found) == 1
    assert found[0].at == "delivery.method"
    assert found[0].hint is not None
    assert "nothing is wrong with the file" in found[0].hint


def test_a_file_with_no_delivery_carries_no_such_warning() -> None:
    config = build_config({"version": 1})

    assert not [w for w in config.warnings if "no delivery method" in w.message]

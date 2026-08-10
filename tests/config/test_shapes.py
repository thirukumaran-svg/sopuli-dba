"""The two config shapes, and the top-level key whitelist.

§1: the inline form is "exactly sugar for a single unnamed application entry".
This is where that claim is held to -- if the two shapes ever stop producing the
same object, every command downstream acquires a reason to care which one was
written, and §1 becomes a promise the code does not keep.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from sopuli.config.applications import build_applications
from sopuli.config.errors import ConfigError
from sopuli.config.loading import TOP_LEVEL_KEYS

TEMPLATE = "tenants/{tenant}#DB_CREDENTIALS/{account}"
ACCOUNTS = ["acme_web_user", "acme_api_user"]
OVERRIDES = [{"where": {"env": "dev"}, "secret_template": "tenants/_shared#DB/{account}"}]

INLINE = {
    "version": 1,
    "accounts": ACCOUNTS,
    "secret_template": TEMPLATE,
    "policy": "app-standard",
    "overrides": OVERRIDES,
}

EQUIVALENT = {
    "version": 1,
    "applications": [
        {
            "accounts": ACCOUNTS,
            "secret_template": TEMPLATE,
            "policy": "app-standard",
            "overrides": OVERRIDES,
            "name": "acme",
        }
    ],
}


def test_the_two_shapes_agree_on_everything_but_the_name() -> None:
    """The one documented difference: §3's field table says `name` is "required
    in the `applications:` form; absent in the inline form"."""
    (from_inline,) = build_applications(INLINE)
    (from_named,) = build_applications(EQUIVALENT)

    assert from_inline.name is None
    assert from_named.name == "acme"

    assert replace(from_inline, name="acme") == from_named


def test_the_inline_entry_knows_it_is_inline() -> None:
    (application,) = build_applications(INLINE)

    assert application.is_inline
    assert application.label == "the inline application"


def test_a_named_entry_is_labelled_by_its_name() -> None:
    (application,) = build_applications(EQUIVALENT)

    assert not application.is_inline
    assert application.label == "acme"


# ------------------------------------------------------- mutual exclusion ---


def test_both_shapes_at_once_is_an_error() -> None:
    """§1: "The two forms are mutually exclusive"."""
    document = {**INLINE, "applications": [{"name": "acme", "accounts": ACCOUNTS}]}

    with pytest.raises(ConfigError) as caught:
        build_applications(document)

    assert "either the inline form or `applications:`, not both" in str(caught.value)


@pytest.mark.parametrize(
    "leftover", ["accounts", "secret", "secret_template", "policy", "overrides"]
)
def test_any_leftover_inline_key_trips_the_exclusion(leftover: str) -> None:
    """Not just `accounts:`.

    A stray top-level `secret_template:` left behind when a file was converted to
    the `applications:` form would otherwise be silently ignored -- and §1 calls
    a wrong secret binding the mistake with the worst consequences. The message
    names which key it found, since that is the one to delete.
    """
    values: dict[str, Any] = {
        "accounts": ACCOUNTS,
        "secret": "ops/db#password",
        "secret_template": TEMPLATE,
        "policy": "app-standard",
        "overrides": OVERRIDES,
    }
    document = {
        "version": 1,
        leftover: values[leftover],
        "applications": [{"name": "acme", "accounts": ["acme_web_user"]}],
    }

    with pytest.raises(ConfigError) as caught:
        build_applications(document)

    assert f"`{leftover}:`" in str(caught.value)


def test_a_config_with_no_binding_at_all_is_allowed() -> None:
    """A file may describe only vaults and targets while an estate is written
    down. The commands that need a binding say so themselves."""
    assert build_applications({"version": 1, "targets": []}) == ()


# ------------------------------------------------ the inline key boundary ---


@pytest.mark.parametrize("key", ["targets", "vault", "oracle", "name"])
def test_application_only_keys_are_not_inline_keys(key: str) -> None:
    """`targets:` at the top level is the estate's target list, not a selector.

    That collision is why the inline form carries only the four keys §1's
    skeleton lists plus `secret`. A top-level `targets:` must therefore be left
    for the estate section to read -- not silently absorbed into the inline
    application, where it would quietly narrow what the tool acts on.
    """
    document = {"version": 1, "accounts": ["acme_web_user"], key: ["something"]}

    (application,) = build_applications(document)

    assert application.targets.is_everything
    assert application.vault is None
    assert application.oracle.container_clause is None
    assert application.name is None


# --------------------------------------------------- top-level whitelist ---


def test_every_section_in_the_reference_is_a_known_top_level_key() -> None:
    """The skeleton in §1 is the list this constant has to keep up with."""
    for section in ("version", "vaults", "targets", "target_sets", "groups", "policies"):
        assert section in TOP_LEVEL_KEYS
    for section in ("defaults", "profiles", "runtime", "applications"):
        assert section in TOP_LEVEL_KEYS


def test_the_inline_binding_keys_are_known_top_level_keys() -> None:
    for section in ("accounts", "secret", "secret_template", "policy", "overrides"):
        assert section in TOP_LEVEL_KEYS

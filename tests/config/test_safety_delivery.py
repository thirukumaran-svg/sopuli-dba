"""The `safety.delivery:` sub-block: what the file may say, and what it may not.

Tier 0 (04-testing.md §4) -- a dict in, a `Safety` out, no I/O.

The merge is `tests/settings/test_allowed_methods.py`'s. This is the half that
decides what can reach the merge at all, and the two rules worth having here are
the ones that keep the intersection honest: no layer can supply an allow-list of
methods that do not exist, and no layer can supply the empty set.
"""

from __future__ import annotations

import pytest

from sopuli.config.delivery import DELIVERY_METHODS
from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.safety import build_safety

AT = ROOT.key("defaults").key("safety")


def test_a_safety_block_may_declare_no_delivery_policy() -> None:
    """``None``, and it is the difference between permitting everything and
    permitting nothing -- see the setting's own test for why that matters."""
    safety = build_safety({"max_targets": 1}, at=AT)

    assert safety is not None
    assert safety.delivery is None


def test_the_allowed_methods_are_read_in_the_order_written() -> None:
    safety = build_safety(
        {"delivery": {"allowed_methods": ["vault_wrapped", "manual"]}},
        at=AT,
    )

    assert safety is not None
    assert safety.delivery is not None
    assert safety.delivery.allowed_methods == ("vault_wrapped", "manual")


def test_a_delivery_block_that_writes_nothing_imposes_no_constraint() -> None:
    """`delivery: {}` is a block with no key in it, which says nothing. Distinct
    from `allowed_methods: []`, which says *nothing is permitted* and is refused
    below."""
    safety = build_safety({"delivery": {}}, at=AT)

    assert safety is not None
    assert safety.delivery is not None
    assert safety.delivery.allowed_methods is None


def test_an_unknown_method_is_refused_with_the_known_set() -> None:
    """An allow-list is not free-form: a typo would silently permit one fewer
    method than it reads as permitting, which under an intersection is the
    difference between a slip and an estate that cannot deliver."""
    with pytest.raises(ConfigError) as caught:
        build_safety({"delivery": {"allowed_methods": ["carrier_pigeon"]}}, at=AT)

    assert "unknown delivery method 'carrier_pigeon'" in str(caught.value)
    assert str(caught.value.at) == "defaults.safety.delivery.allowed_methods[0]"


def test_every_real_method_is_accepted() -> None:
    """The enum and this key cannot drift: a method added to §6.2 is permissible
    in an allow-list on the day it is added."""
    safety = build_safety({"delivery": {"allowed_methods": list(DELIVERY_METHODS)}}, at=AT)

    assert safety is not None
    assert safety.delivery is not None
    assert safety.delivery.allowed_methods == DELIVERY_METHODS


def test_an_empty_allow_list_is_refused() -> None:
    """The set only ever narrows, so nothing could widen it again -- a layer
    permitting nothing is a layer under which no run could ever deliver."""
    with pytest.raises(ConfigError) as caught:
        build_safety({"delivery": {"allowed_methods": []}}, at=AT)

    assert "no delivery method would be permitted" in str(caught.value)
    assert "leave the key out" in (caught.value.hint or "")


def test_an_unknown_key_in_the_delivery_block_is_refused() -> None:
    """§10, and the one spelling that matters: there is no `forbidden_methods`,
    now or later, so a file that writes one is told rather than ignored."""
    with pytest.raises(ConfigError) as caught:
        build_safety({"delivery": {"forbidden_methods": ["manual"]}}, at=AT)

    assert "unknown key 'forbidden_methods'" in str(caught.value)


def test_the_delivery_block_must_be_a_mapping() -> None:
    with pytest.raises(ConfigError):
        build_safety({"delivery": ["manual"]}, at=AT)


def test_a_delivery_key_with_nothing_under_it_is_refused() -> None:
    """`delivery:` and nothing indented under it is `null`, and the published
    schema types the property as an object -- so accepting it would make the tool
    looser than its own schema, which is the one direction 9b forbids
    (Copilot's review of #500). Key *presence* decides, as it does for `readonly`.
    """
    with pytest.raises(ConfigError) as caught:
        build_safety({"delivery": None}, at=AT)

    assert "must be a mapping" in str(caught.value)


def test_an_allowed_methods_key_with_nothing_under_it_is_refused() -> None:
    """The same rule one level down, and the reading matters more here: a silently
    ignored `allowed_methods: null` is a layer that looks like it constrains
    delivery and does not."""
    with pytest.raises(ConfigError) as caught:
        build_safety({"delivery": {"allowed_methods": None}}, at=AT)

    assert "must be a list" in str(caught.value)

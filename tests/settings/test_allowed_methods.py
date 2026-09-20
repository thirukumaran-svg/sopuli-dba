"""`safety.delivery.allowed_methods` -- the fourth ratchet shape (H6, #453, #498).

Tier 0 (04-testing.md §4): every layer is a ``Contribution`` built here, and the
config half is a dict. Nothing opens a file or a socket.

`test_ratchet.py` already covers the invariant over every subset of every layer
crossed with every value, and it covers this setting from the moment its name
joined ``SAFETY_SETTINGS``. What that enumeration cannot say is *which* of the
four shapes ran: a union would satisfy "never less safe than a layer asked for"
in the cases where the sets nest, and only fail where they do not. So these are
the rules stated one at a time, named for what each refuses.
"""

from __future__ import annotations

import pytest

from sopuli.config.errors import ConfigError
from sopuli.settings import (
    Contribution,
    Layer,
    ListMerge,
    ratchet_note,
    resolve,
    setting,
)

NAME = "safety.delivery.allowed_methods"


def wrote(layer: Layer, *methods: str) -> Contribution:
    """One layer's allow-list, with the key path it would have been written at."""
    return Contribution(layer=layer, value=methods, detail=f"{layer}.safety.delivery")


def test_the_shape_is_declared_rather_than_read_off_the_type() -> None:
    """The whole reason for the fourth shape: two `tuple[str, ...]` settings that
    merge oppositely, so nothing about the values can decide."""
    assert setting(NAME).list_merge is ListMerge.INTERSECTION
    assert setting("safety.confirm_environments").list_merge is ListMerge.UNION
    assert setting(NAME).type is setting("safety.confirm_environments").type


def test_a_higher_layer_cannot_widen_what_a_lower_one_allowed() -> None:
    """Invariant 10 in the direction this setting exists for.

    The profile is layer 3 and `defaults:` is layer 5, so under `override` the
    profile would win outright and `manual` would be permitted.
    """
    answer = resolve(
        NAME,
        [
            wrote(Layer.PROFILE, "vault_wrapped", "manual"),
            wrote(Layer.DEFAULTS, "vault_wrapped"),
        ],
    )

    assert answer is not None
    assert answer.value == ("vault_wrapped",)


def test_a_higher_layer_may_narrow_what_a_lower_one_allowed() -> None:
    """The other direction, which is the one an estate uses: a profile for a CI
    runner permitting less than the file it inherits from."""
    answer = resolve(
        NAME,
        [
            wrote(Layer.PROFILE, "vault_wrapped"),
            wrote(Layer.DEFAULTS, "vault_wrapped", "manual"),
        ],
    )

    assert answer is not None
    assert answer.value == ("vault_wrapped",)


def test_an_unset_setting_imposes_no_constraint() -> None:
    """Rule 1, and the one whose failure would be silent and total.

    ``None`` rather than ``()``: a file that configures no delivery policy must
    not resolve to an estate that can deliver nothing, and under an intersection
    the empty set is exactly that -- unwidenable by any later layer.
    """
    assert resolve(NAME) is None


def test_two_layers_with_nothing_in_common_are_refused() -> None:
    """Rule 2. An empty intersection is a configuration nobody can have meant,
    and choosing a layer to honour would be choosing a guard to ignore."""
    with pytest.raises(ConfigError) as caught:
        resolve(
            NAME,
            [wrote(Layer.PROFILE, "manual"), wrote(Layer.DEFAULTS, "vault_wrapped")],
        )

    assert "resolves to nothing" in str(caught.value)


def test_the_refusal_names_both_layers_and_what_each_allowed() -> None:
    """Both, because an empty intersection is never one block's doing -- and a
    message naming one of them would send somebody to edit the wrong file."""
    with pytest.raises(ConfigError) as caught:
        resolve(
            NAME,
            [wrote(Layer.PROFILE, "manual"), wrote(Layer.DEFAULTS, "vault_wrapped")],
        )

    message = str(caught.value)
    assert "profile.safety.delivery allows manual" in message
    assert "defaults.safety.delivery allows vault_wrapped" in message


def test_the_refusal_covers_three_layers_that_are_pairwise_compatible() -> None:
    """The case a pairwise check would miss: every pair overlaps and the three
    together allow nothing."""
    with pytest.raises(ConfigError):
        resolve(
            NAME,
            [
                wrote(Layer.PROFILE, "manual", "vault_wrapped"),
                wrote(Layer.OBJECT, "vault_wrapped", "vault_path"),
                wrote(Layer.DEFAULTS, "vault_path", "manual"),
            ],
        )


def test_the_reported_layer_is_the_one_that_narrowed_the_set() -> None:
    """What `config show --explain` prints, and the key an operator edits to get
    a method back. The layer that wrote the wider list only permitted it."""
    answer = resolve(
        NAME,
        [
            wrote(Layer.PROFILE, "vault_wrapped", "manual"),
            wrote(Layer.DEFAULTS, "vault_wrapped"),
        ],
    )

    assert answer is not None
    assert answer.layer is Layer.DEFAULTS


def test_two_layers_that_narrow_jointly_are_both_contributors() -> None:
    """An intersection is often something no single layer wrote, so "the layer
    whose value equals the answer" would report nobody here. Ties resolve
    downward, so the reported one is still the lowest-authority contributor."""
    answer = resolve(
        NAME,
        [
            wrote(Layer.PROFILE, "vault_wrapped", "manual"),
            wrote(Layer.DEFAULTS, "vault_wrapped", "vault_path"),
        ],
    )

    assert answer is not None
    assert answer.value == ("vault_wrapped",)
    assert answer.layer is Layer.DEFAULTS


def test_identical_layers_report_the_lower_one() -> None:
    """The tie the integer shape already has, read for a list: two layers wrote
    the same list, both determined the answer, and the durable location wins."""
    answer = resolve(
        NAME,
        [wrote(Layer.PROFILE, "vault_wrapped"), wrote(Layer.DEFAULTS, "vault_wrapped")],
    )

    assert answer is not None
    assert answer.layer is Layer.DEFAULTS


def test_a_layer_that_only_permitted_the_answer_is_not_reported_as_the_source() -> None:
    """The same claim from the other end, because reporting the permissive layer
    would send the operator to a block whose edit changes nothing."""
    answer = resolve(
        NAME,
        [
            wrote(Layer.PROFILE, "vault_wrapped"),
            wrote(Layer.DEFAULTS, "vault_wrapped", "manual"),
        ],
    )

    assert answer is not None
    assert answer.layer is Layer.PROFILE


def test_a_layer_that_lost_a_method_is_reported_as_a_relaxation() -> None:
    """A union has no losers and an intersection does, which is what makes the
    ratchet note worth printing for this setting at all."""
    answer = resolve(
        NAME,
        [
            wrote(Layer.PROFILE, "vault_wrapped", "manual"),
            wrote(Layer.DEFAULTS, "vault_wrapped"),
        ],
    )

    assert answer is not None
    assert [one.layer for one in answer.relaxations] == [Layer.PROFILE]

    note = ratchet_note(answer)
    assert note is not None
    # The layer's list as that layer wrote it, rather than sorted: the note is
    # there to be found in a file, and it is the written order somebody reads.
    assert "asked for vault_wrapped, manual" in note
    assert "stays vault_wrapped" in note


def test_a_union_setting_still_has_no_losers() -> None:
    """The shape is per setting, so teaching the resolver about losers must not
    have given `confirm_environments` any."""
    answer = resolve(
        "safety.confirm_environments",
        [
            Contribution(layer=Layer.PROFILE, value=("prod",), detail="profiles.ci.safety"),
            Contribution(layer=Layer.DEFAULTS, value=("staging",), detail="defaults.safety"),
        ],
    )

    assert answer is not None
    assert answer.value == ("prod", "staging")
    assert answer.relaxations == ()
    assert ratchet_note(answer) is None

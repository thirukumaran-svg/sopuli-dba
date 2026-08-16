"""The two ``locking:`` keys, and the ratchet polarity one of them needed.

Tier 0, pure: a dict in, a model out, no vault anywhere. What is worth reading
here is not the parsing -- it is the same shape as every other section -- but the
three rules #83 decided that only exist as code once these keys do:

* a store gets a real lock unless somebody wrote down that it cannot;
* ``break_expired`` is permission rather than a guard, so the ratchet runs the
  other way and the layer saying ``false`` wins;
* the two may not be combined, because breaking a lock unattended is only safe
  while there is a fence to stop the run that was broken.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.defaults import build_defaults
from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.locking import LOCK_ADVISORY_ONLY, LOCK_REQUIRED
from sopuli.config.profiles import build_profiles
from sopuli.config.vaults import build_vaults
from sopuli.settings import Contribution, Layer, ratchet_note, resolve, setting

KV2: dict[str, Any] = {"type": "hashicorp", "addr": "https://vault.example.com", "kv_version": 2}
KV1: dict[str, Any] = {**KV2, "kv_version": 1, "locking": LOCK_ADVISORY_ONLY}


def document(**sections: Any) -> dict[str, Any]:
    return {"version": 1, **sections}


# ------------------------------------------------------- a store's locking ---


def test_a_store_holds_a_real_lock_unless_it_says_otherwise() -> None:
    """The default is the decision, not an omission: absent means `required`."""
    vault = build_vaults(document(vaults={"vault-prod": KV2}))[0]

    assert vault.locking == LOCK_REQUIRED


def test_a_store_may_be_excused_from_locking() -> None:
    vault = build_vaults(document(vaults={"legacy-kv": KV1}))[0]

    assert vault.locking == LOCK_ADVISORY_ONLY


def test_an_unknown_locking_mode_is_refused() -> None:
    """A free string here would be a store that silently locks nothing.

    `locking: none` is the plausible typo, and it reads like a stronger statement
    than `advisory-only` while being a value the tool has never heard of.
    """
    with pytest.raises(ConfigError) as caught:
        build_vaults(document(vaults={"legacy-kv": {**KV2, "locking": "none"}}))

    rendered = str(caught.value)
    assert "vaults.legacy-kv.locking" in rendered
    assert LOCK_ADVISORY_ONLY in rendered


# --------------------------------------------------------- the block itself ---


def test_defaults_may_permit_breaking_an_expired_lock() -> None:
    defaults = build_defaults(document(defaults={"locking": {"break_expired": True}}))

    assert defaults.locking is not None
    assert defaults.locking.break_expired is True


def test_a_profile_may_permit_it_too() -> None:
    """§5: unattended is a property of how a run was invoked, which is a profile."""
    profile = build_profiles(document(profiles={"ci": {"locking": {"break_expired": True}}}))[0]

    assert profile.locking is not None
    assert profile.locking.break_expired is True


def test_an_unwritten_block_stays_none_rather_than_false() -> None:
    """The distinction the ratchet needs: nobody asked is not the same as `false`.

    Same reason every `safety:` field is optional -- "safest of all layers" has to
    know which layers said nothing.
    """
    defaults = build_defaults(document(defaults={}))
    written = build_defaults(document(defaults={"locking": {"break_expired": False}}))

    assert defaults.locking is None
    assert written.locking is not None
    assert written.locking.break_expired is False


def test_an_unknown_key_in_the_block_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_defaults(document(defaults={"locking": {"break_expried": True}}))

    assert "unknown key 'break_expried'" in str(caught.value)


# ------------------------------------------------------------ the polarity ---


def test_one_layer_withholding_permission_is_enough() -> None:
    """The inverted ratchet, in the case that would have gone wrong.

    A profile that says `false` beats a `defaults` that says `true`, which is the
    opposite of how `readonly` merges and the same sentence read backwards: for a
    guard, one layer asking is enough; for permission, one layer refusing is.
    """
    answer = resolve(
        "locking.break_expired",
        [
            Contribution(Layer.PROFILE, False, "profiles.ci.locking.break_expired"),
            Contribution(Layer.DEFAULTS, True, "defaults.locking.break_expired"),
        ],
    )

    assert answer is not None
    assert answer.value is False


def test_permission_still_takes_effect_when_nobody_objects() -> None:
    """The other half: an inverted ratchet must not be a setting that never works."""
    answer = resolve(
        "locking.break_expired",
        [Contribution(Layer.DEFAULTS, True, "defaults.locking.break_expired")],
    )

    assert answer is not None
    assert answer.value is True


def test_the_defeated_request_is_reported_rather_than_swallowed() -> None:
    """`--explain`'s half of the ratchet, with the polarity the note has to follow.

    The loser here asked for `true`, which is the reverse of every other ratcheted
    boolean -- a note that named the `false` would send somebody to delete the
    line that is protecting them.
    """
    answer = resolve(
        "locking.break_expired",
        [
            Contribution(Layer.PROFILE, False, "profiles.ci.locking.break_expired"),
            Contribution(Layer.DEFAULTS, True, "defaults.locking.break_expired"),
        ],
    )

    assert answer is not None
    note = ratchet_note(answer)
    assert note is not None
    assert "defaults.locking.break_expired asked for true" in note
    assert "stays false" in note


def test_the_setting_declares_its_polarity() -> None:
    """Pinned as data, because everything above depends on the declaration.

    An entry that lost `safe_bool=False` in an edit would leave the merge rule
    correct and the setting inverted, with no other test able to tell.
    """
    assert setting("locking.break_expired").safe_bool is False
    assert setting("safety.readonly").safe_bool is True


# --------------------------------------------------- the two keys together ---


def test_breaking_an_expired_lock_is_refused_without_a_fence() -> None:
    """#83: no compare-and-set, no fence; no fence, no unattended takeover."""
    with pytest.raises(ConfigError) as caught:
        build_config(
            document(
                vaults={"vault-prod": KV2, "legacy-kv": KV1},
                defaults={"locking": {"break_expired": True}},
            )
        )

    rendered = str(caught.value)
    assert "defaults.locking.break_expired" in rendered
    assert "legacy-kv" in rendered
    assert LOCK_ADVISORY_ONLY in rendered


def test_the_refusal_names_every_offending_store() -> None:
    """Not just the first one read.

    Fixing the store the loader happened to name first would leave the file just
    as invalid, and the next run would name the next one -- an error message that
    asks somebody to play twenty questions with their own config.
    """
    with pytest.raises(ConfigError) as caught:
        build_config(
            document(
                vaults={"legacy-kv": KV1, "old-file": {"type": "file", "locking": "advisory-only"}},
                defaults={"locking": {"break_expired": True}},
            )
        )

    rendered = str(caught.value)
    assert "'legacy-kv'" in rendered
    assert "'old-file'" in rendered
    assert "vaults" in rendered


def test_the_refusal_names_the_profile_that_asked() -> None:
    """Either half is legitimate alone, so the message has to locate both ends."""
    with pytest.raises(ConfigError) as caught:
        build_config(
            document(
                vaults={"legacy-kv": KV1},
                profiles={"ci": {"locking": {"break_expired": True}}},
            )
        )

    assert "profiles.ci.locking.break_expired" in str(caught.value)


def test_either_key_alone_is_fine() -> None:
    build_config(document(vaults={"legacy-kv": KV1}))
    build_config(
        document(vaults={"vault-prod": KV2}, defaults={"locking": {"break_expired": True}})
    )


def test_an_explicit_false_beside_an_excused_store_is_not_a_refusal() -> None:
    """`break_expired: false` is a layer withholding permission, not asking for it.

    Worth its own case because the rule reads the block rather than the resolved
    setting, and a truth test over `Locking(break_expired=False)` would refuse a
    file that is doing exactly the right thing.
    """
    build_config(
        document(vaults={"legacy-kv": KV1}, defaults={"locking": {"break_expired": False}})
    )

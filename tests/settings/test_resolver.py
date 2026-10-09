"""Resolution and provenance: what wins, and what the answer says about itself.

Tier 0 (04-testing.md §4). Every layer arrives as a ``Contribution`` built here,
so there is nothing to mock and no environment to set.

The generic invariant -- *a ratcheted setting is never resolved to something
less safe than a contributing layer* -- lives in ``test_ratchet.py``. This file
covers the specific behaviours around it: which layer is reported, what stays
visible, and what is refused outright.
"""

from __future__ import annotations

import pytest

from sopuli.settings import (
    Contribution,
    Layer,
    ratchet_note,
    resolve,
    resolve_all,
)


def test_a_setting_no_layer_supplied_resolves_to_nothing() -> None:
    """``None``, not a ``Resolved`` holding ``None``.

    An unset ``max_targets`` is a guard nobody asked for, not a default the tool
    chose -- and ``invocation.options`` carries options that changed behaviour.
    """
    assert resolve("safety.max_targets") is None


def test_the_built_in_default_answers_when_nothing_else_does() -> None:
    answer = resolve("output")
    assert answer is not None
    assert answer.value == "text"
    assert answer.layer is Layer.BUILTIN
    assert answer.detail is None
    assert answer.location == "builtin"


def test_the_highest_layer_wins_an_override() -> None:
    answer = resolve(
        "output",
        [
            Contribution(Layer.PROFILE, "jsonl", "profiles.ci.output"),
            Contribution(Layer.ENV, "json", "SOPULI_OUTPUT"),
            Contribution(Layer.CLI, "text", "--output"),
        ],
    )
    assert answer is not None
    assert answer.value == "text"
    assert answer.layer is Layer.CLI
    assert answer.detail == "--output"


def test_the_loser_of_an_override_stays_visible() -> None:
    """``config show --explain`` shows the value that did not win.

    A setting that was requested and did not take effect is invisible in the
    result and obvious in that view, which is the whole reason the view exists.
    """
    answer = resolve(
        "output",
        [
            Contribution(Layer.PROFILE, "jsonl", "profiles.ci.output"),
            Contribution(Layer.CLI, "text", "--output"),
        ],
    )
    assert answer is not None
    assert [one.layer for one in answer.contributions] == [Layer.CLI, Layer.PROFILE]
    assert answer.contributions[1].value == "jsonl"


def test_the_built_in_default_drops_out_once_a_layer_speaks() -> None:
    """Layer 6 is a fallback, not a contributor.

    Under a ratchet the difference is load-bearing: a built-in that took part
    would be an unremovable floor rather than a default.
    """
    answer = resolve("output", [Contribution(Layer.PROFILE, "json", "profiles.ci.output")])
    assert answer is not None
    assert [one.layer for one in answer.contributions] == [Layer.PROFILE]


def test_a_flag_cannot_relax_a_config_file(capsys: pytest.CaptureFixture[str]) -> None:
    """Invariant 10, in the shape P3 states it: ``readonly: true`` holds.

    There is no ``--force`` yet, so the relaxation is written here as the profile
    layer asking for ``false``. The mechanism is the one a flag would meet.
    """
    answer = resolve(
        "safety.readonly",
        [
            Contribution(Layer.PROFILE, False, "profiles.ci.safety.readonly"),
            Contribution(Layer.DEFAULTS, True, "defaults.safety.readonly"),
        ],
    )
    assert answer is not None
    assert answer.value is True
    assert answer.layer is Layer.DEFAULTS
    assert answer.detail == "defaults.safety.readonly"


def test_the_reported_source_is_the_floor_not_the_top() -> None:
    """Ties resolve downward.

    Two layers say ``true``; the question "why did this refuse to write" is
    answered by the one that is still true after the other goes away.
    """
    answer = resolve(
        "safety.dry_run",
        [
            Contribution(Layer.CLI, True, "--dry-run"),
            Contribution(Layer.ENV, True, "SOPULI_DRY_RUN"),
        ],
    )
    assert answer is not None
    assert answer.value is True
    assert answer.layer is Layer.ENV
    assert answer.detail == "SOPULI_DRY_RUN"


def test_max_targets_ratchets_to_the_lowest() -> None:
    answer = resolve(
        "safety.max_targets",
        [
            Contribution(Layer.PROFILE, 200, "profiles.ci.safety.max_targets"),
            Contribution(Layer.DEFAULTS, 1, "defaults.safety.max_targets"),
        ],
    )
    assert answer is not None
    assert answer.value == 1
    assert answer.layer is Layer.DEFAULTS


def test_confirm_environments_ratchets_to_the_union() -> None:
    """§9: union, not last-one-wins -- and every layer's entries survive."""
    answer = resolve(
        "safety.confirm_environments",
        [
            Contribution(Layer.PROFILE, ("prod",), "profiles.ci.safety.confirm_environments"),
            Contribution(Layer.OBJECT, ("staging", "prod"), "groups.prod-pdbs.safety"),
        ],
    )
    assert answer is not None
    assert answer.value == ("prod", "staging")
    assert answer.relaxations == ()


def test_a_layer_that_named_nothing_does_not_own_the_union() -> None:
    """An empty list contributes nothing, so it cannot be the reported source."""
    answer = resolve(
        "safety.confirm_environments",
        [
            Contribution(Layer.PROFILE, ("prod",), "profiles.ci.safety.confirm_environments"),
            Contribution(Layer.DEFAULTS, (), "defaults.safety.confirm_environments"),
        ],
    )
    assert answer is not None
    assert answer.value == ("prod",)
    assert answer.layer is Layer.PROFILE


def test_several_contributions_from_one_layer_keep_the_callers_order() -> None:
    """A target's own ``safety:`` and its group's are both layer 4 (§9).

    The caller expresses which is nearer by the order it passes them, and an
    unstable sort would silently reorder that.
    """
    answer = resolve(
        "safety.max_targets",
        [
            Contribution(Layer.OBJECT, 5, "targets.acme-alpha.safety.max_targets"),
            Contribution(Layer.OBJECT, 5, "groups.prod-pdbs.safety.max_targets"),
        ],
    )
    assert answer is not None
    assert answer.detail == "groups.prod-pdbs.safety.max_targets"


def test_a_layer_the_setting_does_not_declare_is_a_programming_error() -> None:
    """``layers`` is enforced, not documentation.

    ``safety.max_targets`` has no environment variable in §6, and a resolver that
    quietly accepted one would make the precedence table a description of intent.
    """
    with pytest.raises(ValueError, match="declared layers"):
        resolve("safety.max_targets", [Contribution(Layer.ENV, 1, "SOPULI_MAX_TARGETS")])


def test_a_value_of_the_wrong_type_is_refused() -> None:
    with pytest.raises(TypeError, match="--output"):
        resolve("output", [Contribution(Layer.CLI, 1, "--output")])


def test_a_boolean_is_not_an_integer_here() -> None:
    """``isinstance(True, int)`` is true in Python, which this must not inherit."""
    with pytest.raises(TypeError, match="bool"):
        resolve(
            "safety.max_targets",
            [Contribution(Layer.DEFAULTS, True, "defaults.safety.max_targets")],
        )


def test_resolve_all_drops_the_unset_and_sorts_by_name() -> None:
    resolved = resolve_all(
        {
            "safety.max_targets": [],
            "safety.dry_run": [Contribution(Layer.CLI, True, "--dry-run")],
            "output": [Contribution(Layer.CLI, "json", "--output")],
        }
    )
    assert list(resolved) == ["output", "safety.dry_run"]


def test_the_ratchet_note_names_both_ends() -> None:
    answer = resolve(
        "safety.max_targets",
        [
            Contribution(Layer.PROFILE, 200, "profiles.ci.safety.max_targets"),
            Contribution(Layer.DEFAULTS, 1, "defaults.safety.max_targets"),
        ],
    )
    assert answer is not None
    note = ratchet_note(answer)
    assert note is not None
    assert "profiles.ci.safety.max_targets asked for 200" in note
    assert "stays 1 (defaults.safety.max_targets)" in note
    assert "ratchet toward safe" in note


def test_the_ratchet_note_writes_booleans_the_way_the_file_does() -> None:
    answer = resolve(
        "safety.readonly",
        [
            Contribution(Layer.PROFILE, False, "profiles.ci.safety.readonly"),
            Contribution(Layer.DEFAULTS, True, "defaults.safety.readonly"),
        ],
    )
    assert answer is not None
    note = ratchet_note(answer)
    assert note is not None
    assert "asked for false" in note
    assert "stays true" in note


def test_there_is_no_note_when_nothing_was_defeated() -> None:
    answer = resolve("safety.dry_run", [Contribution(Layer.CLI, True, "--dry-run")])
    assert answer is not None
    assert ratchet_note(answer) is None


def test_the_ratchet_note_is_ascii() -> None:
    """The tool's own prose stays ASCII -- see ``tests/test_cli_smoke.py``."""
    answer = resolve(
        "safety.max_targets",
        [
            Contribution(Layer.PROFILE, 200, "profiles.ci.safety.max_targets"),
            Contribution(Layer.DEFAULTS, 1, "defaults.safety.max_targets"),
        ],
    )
    assert answer is not None
    note = ratchet_note(answer)
    assert note is not None
    note.encode("ascii")


def test_an_override_never_reports_a_relaxation() -> None:
    """Only invariant 10 defeats anything. Being outranked is not being defeated."""
    answer = resolve(
        "output",
        [
            Contribution(Layer.CLI, "json", "--output"),
            Contribution(Layer.PROFILE, "text", "profiles.ci.output"),
        ],
    )
    assert answer is not None
    assert answer.relaxations == ()
    assert ratchet_note(answer) is None

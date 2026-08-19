"""``--explain``'s rendering, fed resolved settings directly (#53).

Tier 0 (04-testing.md §4): a pure function of a mapping, so there is no config
file, no environment and no command here.

**Why the view is tested at this boundary rather than only through the CLI.**
Two settings are wired today -- `output` and `safety.dry_run` -- so a run can
show a value from the command line, from the environment, and from a built-in
default, and nothing else. It cannot show a profile that tried to relax a ratchet
and lost, because no layer can supply a looser value yet; and it cannot show a
secret-valued setting, because none exists. Those are two of the three cases the
issue asks for, and both are properties of the *view*, which takes whatever the
resolver produced. Testing them here is what makes them true when the settings
that need them arrive, rather than a year from now when somebody notices.
"""

from __future__ import annotations

from sopuli.output.explain_view import BUILT_IN, ratchet_notes, render_settings, section
from sopuli.secrets import REDACTED, Secret
from sopuli.settings import Contribution, Layer, resolve
from sopuli.settings.resolver import Resolved


def resolved(name: str, *contributions: Contribution) -> dict[str, Resolved]:
    """One setting, resolved, as a mapping the view can render."""
    answer = resolve(name, contributions)
    assert answer is not None
    return {name: answer}


def rendered(*settings: dict[str, Resolved]) -> str:
    merged: dict[str, Resolved] = {}
    for one in settings:
        merged.update(one)
    return "\n".join(render_settings(merged))


# ------------------------------------------------------------ the plain rows ---


def test_nothing_resolved_renders_nothing() -> None:
    """So a caller can append the section unconditionally and get no empty
    heading over it."""
    assert render_settings({}) == []
    assert section({}) == []


def test_a_row_names_its_value_and_its_source() -> None:
    text = rendered(resolved("output", Contribution(Layer.CLI, "json", "--output (verb)")))

    assert "output" in text
    assert "= json" in text
    assert "[cli --output (verb)]" in text


def test_an_environment_variable_is_named_not_just_the_layer() -> None:
    """`env SOPULI_DRY_RUN`, never `env`.

    The point of the view is to send somebody to the thing they have to change,
    in their own environment. "env" alone answers which precedence rule applied,
    which is not the question anybody is asking at that moment.
    """
    text = rendered(resolved("safety.dry_run", Contribution(Layer.ENV, True, "SOPULI_DRY_RUN")))

    assert "[env SOPULI_DRY_RUN]" in text


def test_a_config_key_is_not_prefixed_with_its_own_section() -> None:
    """`defaults defaults.safety.readonly` says it twice."""
    text = rendered(
        resolved("safety.readonly", Contribution(Layer.DEFAULTS, True, "defaults.safety.readonly"))
    )

    assert "[defaults.safety.readonly]" in text


def test_a_built_in_default_says_so() -> None:
    """It has nowhere to point at, and P3's own wording reads as an answer rather
    than as a missing source: nothing else spoke."""
    text = rendered(resolved("output"))

    assert f"= text  [{BUILT_IN}]" in text


def test_booleans_are_written_the_way_the_file_writes_them() -> None:
    """A reader told `true` goes looking for `true` in their YAML."""
    text = rendered(resolved("safety.dry_run", Contribution(Layer.ENV, True, "SOPULI_DRY_RUN")))

    assert "= true" in text
    assert "True" not in text


def test_rows_are_ordered_by_name() -> None:
    """Two runs of one command produce comparable output, which is what makes
    the view usable in a bug report."""
    text = rendered(
        resolved("safety.dry_run", Contribution(Layer.ENV, True, "SOPULI_DRY_RUN")),
        resolved("output", Contribution(Layer.CLI, "json", "--output (verb)")),
    )

    assert text.index("output") < text.index("safety.dry_run")


def test_values_and_sources_line_up() -> None:
    """A column that wanders is a column nobody scans."""
    lines = render_settings(
        {
            **resolved("output", Contribution(Layer.CLI, "json", "--output (verb)")),
            **resolved("safety.dry_run", Contribution(Layer.ENV, True, "SOPULI_DRY_RUN")),
        }
    )

    assert len({line.index("=") for line in lines}) == 1
    assert len({line.index("[") for line in lines}) == 1


def test_the_table_is_ascii() -> None:
    """P3 draws the ratchet note with an arrow; the tool's own prose stays ASCII
    (``tests/test_cli_smoke.py``), so the note is a plain continuation line."""
    text = rendered(
        resolved(
            "safety.max_targets",
            Contribution(Layer.PROFILE, 200, "profiles.ci.safety.max_targets"),
            Contribution(Layer.DEFAULTS, 1, "defaults.safety.max_targets"),
        )
    )

    text.encode("ascii")


# --------------------------------------------------------- the loser, visible ---


def test_a_setting_at_two_layers_shows_the_winner() -> None:
    """The value is the winner's, and the row names the layer that produced it."""
    text = rendered(
        resolved(
            "output",
            Contribution(Layer.CLI, "json", "--output (verb)"),
            Contribution(Layer.ENV, "text", "SOPULI_OUTPUT"),
        )
    )

    assert "= json" in text
    assert "[cli --output (verb)]" in text


def test_a_defeated_relaxation_is_named_under_its_row() -> None:
    """The line P3 says is the one worth being able to see.

    A profile asked for 200 targets and got 1. Nothing in the result says so --
    the run simply has a lower limit -- which is the difference between "the
    ratchet works" as a claim and as something an operator can check.
    """
    lines = render_settings(
        resolved(
            "safety.max_targets",
            Contribution(Layer.PROFILE, 200, "profiles.ci.safety.max_targets"),
            Contribution(Layer.DEFAULTS, 1, "defaults.safety.max_targets"),
        )
    )

    assert len(lines) == 2
    assert "= 1" in lines[0]
    assert "[defaults.safety.max_targets]" in lines[0]
    assert "profiles.ci.safety.max_targets asked for 200" in lines[1]
    assert "ratchet toward safe" in lines[1]


def test_the_note_sits_under_the_row_it_explains() -> None:
    """Indented past the name, so it reads as a continuation rather than a row."""
    lines = render_settings(
        resolved(
            "safety.max_targets",
            Contribution(Layer.PROFILE, 200, "profiles.ci.safety.max_targets"),
            Contribution(Layer.DEFAULTS, 1, "defaults.safety.max_targets"),
        )
    )

    assert lines[1].startswith(" " * len("  safety.max_targets"))


def test_a_setting_nothing_defeated_gets_no_note() -> None:
    """A note that appears when nothing was refused is a line people learn to
    skip, which costs the case it exists for."""
    lines = render_settings(
        resolved("safety.dry_run", Contribution(Layer.ENV, True, "SOPULI_DRY_RUN"))
    )

    assert len(lines) == 1


# --------------------------------------------------------------- diagnostics ---


def test_a_defeated_relaxation_is_a_warning_diagnostic() -> None:
    """§`invocation.options`: it "appears in `diagnostics[]` as a warning naming
    both ends", so a consumer that never renders the text view still sees it.

    A warning rather than an error: nothing failed. Something was asked for and
    safely refused, and the run carried on.
    """
    [note] = ratchet_notes(
        resolved(
            "safety.max_targets",
            Contribution(Layer.PROFILE, 200, "profiles.ci.safety.max_targets"),
            Contribution(Layer.DEFAULTS, 1, "defaults.safety.max_targets"),
        )
    )

    assert note.level == "warning"
    assert "asked for 200" in note.message


def test_a_clean_run_has_no_ratchet_diagnostics() -> None:
    assert ratchet_notes(resolved("output")) == []


# -------------------------------------------------------------------- secrets ---


def test_a_secret_valued_setting_shows_its_layer_and_never_its_value() -> None:
    """Invariant 2, from the direction this view could have broken it.

    No setting is secret-valued today, and #145 makes that more than an accident:
    the command line names a token's *location* and never carries one, and §3a's
    chain is resolved outside the settings registry. Which is exactly why this is
    here now: the view renders whatever the resolver hands
    it, and the day one arrives, the redaction has to already be true. It is,
    because the value is rendered through `render_value`, which stringifies, and
    a `Secret` stringifies to `***`. There is no branch here that could be
    forgotten.

    The provenance is the useful half and is kept: *where* a token came from is
    what an operator needs, and the token itself is what they must not be shown.
    """
    answer = Resolved(
        setting="vault.token",
        value=Secret("hunter2"),
        layer=Layer.ENV,
        detail="SOPULI_VAULT_TOKEN",
    )

    text = "\n".join(render_settings({"vault.token": answer}))

    assert REDACTED in text
    assert "hunter2" not in text
    assert "[env SOPULI_VAULT_TOKEN]" in text

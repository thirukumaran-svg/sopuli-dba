"""§6's environment variables, as contributions. Tier 0, no ambient environment.

The mapping is passed in, so these run beside each other and beside everything
else -- the arrangement ``resolve_color`` and ``discover`` already use. What the
variables do once they reach a command is ``tests/test_cli_precedence.py``.
"""

from __future__ import annotations

from sopuli.settings import Layer
from sopuli.settings.sources import ENV_SETTINGS, env_contributions


def test_nothing_set_contributes_nothing() -> None:
    assert env_contributions({}) == {}


def test_a_variable_names_itself_and_not_its_value() -> None:
    """``source_detail`` is a location (03-json-output.md §invocation.options)."""
    [contribution] = env_contributions({"SOPULI_OUTPUT": "json"})["output"]
    assert contribution.layer is Layer.ENV
    assert contribution.value == "json"
    assert contribution.detail == "SOPULI_OUTPUT"


def test_an_empty_variable_says_nothing() -> None:
    """Set-but-empty is the ``NO_COLOR`` convention, and the only reading that
    lets a CI job clear an inherited variable without unsetting it."""
    assert env_contributions({"SOPULI_OUTPUT": "", "SOPULI_DRY_RUN": ""}) == {}


def test_a_safety_variable_is_true_whatever_it_says() -> None:
    """``SOPULI_DRY_RUN=0`` means dry-run.

    Under invariant 10 nothing can turn dry-run off, so a variable that parsed
    ``0`` would look like it disables a safety setting and could not. Set means
    asked for; there is no third answer available to give.
    """
    for value in ("1", "0", "false", "no"):
        [contribution] = env_contributions({"SOPULI_DRY_RUN": value})["safety.dry_run"]
        assert contribution.value is True, value


def test_an_unknown_value_is_not_rejected_here() -> None:
    """The layer reports what was set; what is *valid* belongs to the consumer.

    ``SOPULI_OUTPUT=jsonl`` is refused at the CLI boundary, where the message can
    say which formats this build has -- see ``invocation.check_output_mode``.
    """
    assert env_contributions({"SOPULI_OUTPUT": "jsonl"})["output"][0].value == "jsonl"


def test_every_mapped_variable_is_a_sopuli_one() -> None:
    """Layer 2 is ``SOPULI_*``. Third-party variables are layer 3 and rank below
    their equivalent, so they cannot be added to this table by mistake."""
    assert all(variable.startswith("SOPULI_") for variable in ENV_SETTINGS)

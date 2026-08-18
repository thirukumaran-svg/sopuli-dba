"""§6's environment variables, as contributions. Tier 0, no ambient environment.

The mapping is passed in, so these run beside each other and beside everything
else -- the arrangement ``resolve_color`` and ``discover`` already use. What the
variables do once they reach a command is ``tests/test_cli_precedence.py``.
"""

from __future__ import annotations

import pytest

from sopuli.config.errors import ConfigError
from sopuli.exit_codes import ExitCode
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


# ------------------------------------------------------ VAULT_SKIP_VERIFY ---
#
# §6's single exception: the one variable in the honoured-third-party list that
# this tool refuses rather than honours or ignores.


def test_vault_skip_verify_is_refused() -> None:
    """Honouring it would let an unranked environment variable turn off
    certificate verification from outside the config the ratchet governs, which
    is the direction invariant 10 exists to forbid. Ignoring it silently is
    worse than either: the operator set it and believes it took effect."""
    with pytest.raises(ConfigError) as caught:
        env_contributions({"VAULT_SKIP_VERIFY": "1"})

    message = str(caught.value)
    assert "VAULT_SKIP_VERIFY" in message
    assert "vaults.*.tls.verify" in message


def test_vault_skip_verify_is_refused_whatever_it_says() -> None:
    """Including the value that looks like it asks for nothing. Reading `false`
    as "not asked for" would make the refusal depend on parsing a variable we
    have just said we do not honour."""
    with pytest.raises(ConfigError):
        env_contributions({"VAULT_SKIP_VERIFY": "false"})


def test_vault_skip_verify_set_empty_is_unset() -> None:
    """§6's rule for the whole table, and the way out: a CI job can clear an
    inherited variable without unsetting it, and gets no error for doing so."""
    assert env_contributions({"VAULT_SKIP_VERIFY": ""}) == {}


def test_the_refusal_exits_nine_and_says_what_to_write_instead() -> None:
    """An error an operator can act on: it names the key that does the same job
    in the place where it is reviewable."""
    with pytest.raises(ConfigError) as caught:
        env_contributions({"VAULT_SKIP_VERIFY": "yes"})

    assert caught.value.exit_code == ExitCode.CONFIG_INVALID
    assert "verify: false" in (caught.value.hint or "")

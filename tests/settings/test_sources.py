"""§6's environment variables, as contributions. Tier 0, no ambient environment.

The mapping is passed in, so these run beside each other and beside everything
else -- the arrangement ``resolve_color`` and ``discover`` already use. What the
variables do once they reach a command is ``tests/test_cli_precedence.py``.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.exit_codes import ExitCode
from sopuli.settings import Layer, setting
from sopuli.settings.sources import ENV_SETTINGS, config_contributions, env_contributions


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


def test_sopuli_vault_supplies_the_default_store_name() -> None:
    """C13's row of §6's table: it names a **store**, not a setting of one, so it
    is a run setting like `profile` and not a per-store one. The variables that
    name a setting *of* a store are collected in `sopuli/config/vault_env.py`,
    and `tests/config/test_vault_env.py` is where they are asserted."""
    [contribution] = env_contributions({"SOPULI_VAULT": "vault-dev"})["vault"]

    assert contribution.layer is Layer.ENV
    assert contribution.value == "vault-dev"
    assert contribution.detail == "SOPULI_VAULT"


def test_no_token_variable_is_a_setting() -> None:
    """A token is auth material, resolved by `sopuli/material.py` (ADR-007). If
    one were ever mapped here it would be reported in `invocation.options`, which
    is the one place a credential must never reach."""
    for variable in ("SOPULI_VAULT_TOKEN", "VAULT_TOKEN"):
        assert variable not in ENV_SETTINGS
        assert env_contributions({variable: "s.a-real-token"}) == {}


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


# ------------------------------------------------- the file's own layers ---
#
# Layers 3 and 5. Same shape as the environment's half: a value object in,
# contributions out, no I/O -- so the ratchet across a profile and `defaults:` can
# be asserted without a file or a command line anywhere near it.


def contributions(profile: str | None = None, **sections: Any) -> dict[str, list[Any]]:
    return config_contributions(build_config({"version": 1, **sections}, profile=profile))


def test_a_file_that_says_nothing_contributes_nothing() -> None:
    assert contributions() == {}


def test_defaults_contributes_at_layer_five() -> None:
    supplied = contributions(defaults={"safety": {"readonly": True}})

    [one] = supplied["safety.readonly"]
    assert one.layer is Layer.DEFAULTS
    assert one.value is True
    assert one.detail == "defaults.safety.readonly"


def test_the_active_profile_contributes_at_layer_three() -> None:
    supplied = contributions(
        "ci", profiles={"ci": {"output": "json", "safety": {"max_targets": 200}}}
    )

    [output] = supplied["output"]
    assert output.layer is Layer.PROFILE
    assert output.detail == "profiles.ci.output"
    [targets] = supplied["safety.max_targets"]
    assert targets.layer is Layer.PROFILE
    assert targets.value == 200


def test_a_profile_nobody_selected_contributes_nothing() -> None:
    """§5 rule 1. The keys are parsed and validated either way; contributing
    them would be layer 3 arriving without anybody having asked for it."""
    assert contributions(profiles={"ci": {"output": "json"}}) == {}


def test_defaults_profile_is_reported_as_a_contribution_of_its_own() -> None:
    """So `--explain` can attribute the *choice* as well as what it supplied.

    Layer 5, because it is written in `defaults:` -- and `--profile` and
    `SOPULI_PROFILE` outrank it exactly as they outrank anything else there.
    """
    supplied = contributions("ci", profiles={"ci": {}}, defaults={"profile": "ci"})

    [one] = supplied["profile"]
    assert one.layer is Layer.DEFAULTS
    assert one.detail == "defaults.profile"


def test_defaults_vault_is_reported_as_the_run_s_default_store() -> None:
    """Layer 5 of the same setting `SOPULI_VAULT` supplies at layer 2. Which
    store a run defaults to is a property of the run, unlike a store's own
    settings -- which is why this one is here and `vaults.<name>.*` is not."""
    supplied = contributions(
        vaults={"vault-dev": {"type": "hashicorp"}}, defaults={"vault": "vault-dev"}
    )

    [one] = supplied["vault"]
    assert one.layer is Layer.DEFAULTS
    assert one.value == "vault-dev"
    assert one.detail == "defaults.vault"


def test_an_empty_confirm_environments_list_says_nothing() -> None:
    """`Safety` cannot tell a key nobody wrote from one written empty, and under
    a union ratchet the two mean the same thing. Reporting `defaults:` as the
    source of the empty answer would put a row in every run document."""
    supplied = contributions(defaults={"safety": {"confirm_environments": []}})

    assert "safety.confirm_environments" not in supplied


def test_locking_break_expired_reaches_the_resolver_from_both_layers() -> None:
    supplied = contributions(
        "ci",
        profiles={"ci": {"locking": {"break_expired": True}}},
        defaults={"locking": {"break_expired": False}},
    )

    layers = [one.layer for one in supplied["locking.break_expired"]]
    assert layers == [Layer.PROFILE, Layer.DEFAULTS]


def test_every_setting_the_file_supplies_declares_the_layer_it_arrives_on() -> None:
    """The registry enforces this at merge time; asserting it here is what makes
    a new key added to `config_contributions` fail in the module that produced
    it rather than three frames away in somebody else's run."""
    supplied = contributions(
        "ci",
        profiles={
            "ci": {
                "output": "json",
                "safety": {"readonly": True, "max_targets": 5, "confirm_environments": ["prod"]},
                "locking": {"break_expired": True},
            }
        },
        defaults={
            "profile": "ci",
            "safety": {"readonly": False, "max_targets": 9, "confirm_environments": ["dev"]},
            "locking": {"break_expired": False},
        },
    )

    for name, made in supplied.items():
        for one in made:
            assert one.layer in setting(name).layers, f"{name} from {one.layer}"

"""P3's layers as the command line actually meets them (#10).

Tier 0 (04-testing.md §4): ``CliRunner`` in-process, no containers. The
environment is set with ``monkeypatch.setenv`` where a test is *about* the
environment layer; everything below that boundary takes a mapping and is tested
without one (``tests/settings/``).

What this file is for, and ``tests/settings/`` is not: that the two click parser
positions and the ``SOPULI_*`` variables reach the one resolver, and that a
safety flag cannot arrive by a route with no merge policy behind it.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import click
import pytest
from click.testing import CliRunner

from sopuli import invocation
from sopuli.cli import cli
from sopuli.exit_codes import ExitCode
from sopuli.invocation import GLOBAL_PARAMS, INVOCATION_PARAM


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def show(config_file: Path) -> list[str]:
    return ["config", "show", "--config", str(config_file)]


@pytest.fixture(autouse=True)
def _no_ambient_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nobody's own ``SOPULI_OUTPUT`` decides the result of these tests."""
    for variable in ("SOPULI_OUTPUT", "SOPULI_DRY_RUN"):
        monkeypatch.delenv(variable, raising=False)


def options(result: Any) -> dict[str, Any]:
    """``invocation.options`` from a JSON run, or ``{}`` when it was omitted."""
    document: dict[str, Any] = json.loads(result.output)
    reported: dict[str, Any] = document["invocation"].get("options", {})
    return reported


# ------------------------------------------------------- the two positions ---


def test_both_positions_are_accepted(runner: CliRunner, config_file: Path) -> None:
    for argv in (
        ["--output", "json", "config", "show", "--config", str(config_file)],
        ["config", "show", "--config", str(config_file), "--output", "json"],
    ):
        result = runner.invoke(cli, argv)
        assert result.exit_code == ExitCode.SUCCESS, argv
        json.loads(result.output)


def test_the_verb_position_wins_when_both_are_given(runner: CliRunner, config_file: Path) -> None:
    """Most specific wins. Nothing is at stake for an inert option."""
    result = runner.invoke(
        cli,
        ["--output", "text", "config", "show", "--config", str(config_file), "--output", "json"],
    )
    assert result.exit_code == ExitCode.SUCCESS
    assert options(result)["output"]["value"] == "json"


def test_the_position_is_recorded_in_source_detail(runner: CliRunner, config_file: Path) -> None:
    """Q4: the flag as typed, with the position where a setting accepts both.

    One layer, so `source` cannot carry it -- and it is worth carrying, because
    "I passed --output and got something else" is answered by which of the two
    the tool used.
    """
    group = runner.invoke(cli, ["--output", "json", "config", "show", "--config", str(config_file)])
    assert options(group)["output"]["source_detail"] == "--output (group)"

    verb = runner.invoke(cli, ["config", "show", "--config", str(config_file), "--output", "json"])
    assert options(verb)["output"]["source_detail"] == "--output (verb)"


def test_both_positions_are_one_layer(runner: CliRunner, config_file: Path) -> None:
    """Q3: `source` is `cli` either way -- no `cli_group` / `cli_verb` split.

    A consumer branching on `source` would otherwise be reading an artefact of
    click's two-stage parser.
    """
    for argv in (
        ["--output", "json", "config", "show", "--config", str(config_file)],
        ["config", "show", "--config", str(config_file), "--output", "json"],
    ):
        assert options(runner.invoke(cli, argv))["output"]["source"] == "cli"


def test_config_layers_across_both_positions(
    runner: CliRunner, write_config: Any, tmp_path: Path
) -> None:
    """`--config` is a list, so both positions are kept rather than one winning.

    Group first, which is the order they were typed in -- the same left-to-right
    layering repeating the flag already gives (§9).
    """
    first = write_config("version: 1\n")
    second = tmp_path / "second.yaml"
    second.write_text("version: 1\n", encoding="utf-8")
    second.chmod(0o600)  # the fixture's own P4 permission rule, for a second file

    result = runner.invoke(
        cli,
        ["--config", str(first), "config", "show", "--config", str(second), "--output", "json"],
    )
    assert result.exit_code == ExitCode.SUCCESS
    document = json.loads(result.output)
    assert [Path(one).name for one in document["config"]["sources"]] == [
        first.name,
        second.name,
    ]


# --------------------------------------------------------- the safety trap ---


def test_a_safety_flag_before_the_subcommand_is_refused(runner: CliRunner) -> None:
    """Invariant 10 at the smallest layer: there is no second place to write it.

    Accepting `--dry-run` in both positions would need a merge policy inside
    layer 1, which is where it would be least visible in review. Refusing the
    group position removes the case rather than solving it.
    """
    result = runner.invoke(cli, ["--dry-run", "config", "show"])
    assert result.exit_code == ExitCode.USAGE
    assert "Traceback" not in result.output


def test_the_refusal_says_where_the_flag_goes(runner: CliRunner) -> None:
    """Better than the bare "no such option" this replaces."""
    result = runner.invoke(cli, ["--dry-run", "config", "show"])
    assert "--dry-run must be given after the subcommand" in result.output
    assert "sopuli <noun> <verb> --dry-run" in result.output


def test_the_trap_is_hidden_from_help(runner: CliRunner) -> None:
    """A flag listed in `--help` is a flag the help says you may use."""
    assert "--dry-run" not in runner.invoke(cli, ["--help"]).output


def test_the_trap_does_not_fire_when_the_flag_is_absent(runner: CliRunner, show: list[str]) -> None:
    assert runner.invoke(cli, show).exit_code == ExitCode.SUCCESS


def test_the_flag_still_works_in_the_trailing_position(runner: CliRunner, show: list[str]) -> None:
    result = runner.invoke(cli, [*show, "--dry-run", "--output", "json"])
    assert result.exit_code == ExitCode.SUCCESS
    assert json.loads(result.output)["invocation"]["dry_run"] is True


# ------------------------------------------------------- the environment ----


def test_an_environment_variable_reaches_a_real_command(
    runner: CliRunner, show: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOPULI_OUTPUT", "json")
    result = runner.invoke(cli, show)
    assert result.exit_code == ExitCode.SUCCESS
    assert options(result)["output"] == {
        "value": "json",
        "source": "env",
        "source_detail": "SOPULI_OUTPUT",
    }


def test_the_command_line_outranks_the_environment(
    runner: CliRunner, show: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """P3: the operator typing the command expresses the most specific intent."""
    monkeypatch.setenv("SOPULI_OUTPUT", "text")
    result = runner.invoke(cli, [*show, "--output", "json"])
    assert result.exit_code == ExitCode.SUCCESS
    assert options(result)["output"]["source"] == "cli"


def test_an_empty_variable_says_nothing(
    runner: CliRunner, show: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A CI job clearing an inherited variable should not have to unset it."""
    monkeypatch.setenv("SOPULI_OUTPUT", "")
    result = runner.invoke(cli, show)
    assert result.exit_code == ExitCode.SUCCESS
    # Text, so the empty value neither selected a format nor was refused as one.
    with pytest.raises(json.JSONDecodeError):
        json.loads(result.output)


def test_dry_run_from_the_environment_cannot_be_turned_off(
    runner: CliRunner, show: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`SOPULI_DRY_RUN=0` means dry-run, because nothing can mean the opposite.

    Under invariant 10 no layer can relax a safety setting, so a variable that
    parsed `0` would be one that looks like it disables dry-run and cannot.
    """
    monkeypatch.setenv("SOPULI_DRY_RUN", "0")
    result = runner.invoke(cli, [*show, "--output", "json"])
    assert result.exit_code == ExitCode.SUCCESS
    document = json.loads(result.output)
    assert document["invocation"]["dry_run"] is True
    assert options(result)["safety.dry_run"]["source_detail"] == "SOPULI_DRY_RUN"


def test_an_unknown_output_format_names_the_variable_it_came_from(
    runner: CliRunner, show: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`jsonl` is in §6's table and not implemented yet (#9), so this is real.

    click checks `--output`; nothing checks the variable, and a bare ValueError
    out of the enum names neither the value nor where it was set.
    """
    monkeypatch.setenv("SOPULI_OUTPUT", "jsonl")
    result = runner.invoke(cli, show)
    assert result.exit_code != ExitCode.SUCCESS
    assert isinstance(result.exception, Exception)
    message = str(result.exception)
    assert "SOPULI_OUTPUT" in message
    assert "jsonl" in message


def test_a_source_cannot_wire_a_setting_by_producing_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Which settings a run consults is a list, not whatever a source emits.

    Adding a variable to `ENV_SETTINGS` and forgetting `RESOLVED_SETTINGS` would
    otherwise resolve it and report it in `invocation.options` -- a run claiming
    it was influenced by something that influenced nothing. Refusing is the same
    rule the registry applies to a layer a setting does not declare.
    """
    monkeypatch.setattr(invocation, "RESOLVED_SETTINGS", ("safety.dry_run",))

    with pytest.raises(ValueError, match="RESOLVED_SETTINGS"):
        invocation.resolve_invocation(
            invocation.GlobalOptions(),
            invocation.GlobalOptions(),
            env={"SOPULI_OUTPUT": "json"},
        )


# ---------------------------------------------------- invocation.options ----


def test_a_setting_left_to_its_built_in_default_is_not_reported(
    runner: CliRunner, show: list[str]
) -> None:
    """A built-in default changed nothing, and the schema says "changed behaviour".

    `safety.dry_run` resolves on every run -- to `false`, from the built-in --
    and reporting that on every clean run would be noise in a document consumers
    diff. `--explain` (#53) shows those rows; JSON does not. `output` is here
    because asking for JSON at all is an override.
    """
    result = runner.invoke(cli, [*show, "--output", "json"])
    assert set(options(result)) == {"output"}


def test_every_reported_option_carries_its_layer(
    runner: CliRunner, show: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOPULI_DRY_RUN", "1")
    result = runner.invoke(cli, [*show, "--output", "json"])
    reported = options(result)
    assert set(reported) == {"output", "safety.dry_run"}
    for name, option in reported.items():
        assert option["source"] in {"cli", "env"}, name
        assert option["source_detail"], name


def test_source_detail_never_carries_a_value(
    runner: CliRunner, show: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """It is a location, so the thing it names is findable and never secret.

    No setting today is secret-valued; the rule is structural rather than
    situational, which is what makes it hold when one is.
    """
    monkeypatch.setenv("SOPULI_OUTPUT", "json")
    reported = options(runner.invoke(cli, show))
    assert reported["output"]["source_detail"] == "SOPULI_OUTPUT"
    assert reported["output"]["value"] == "json"


# ------------------------------------------------------------ completeness ---


def commands() -> Iterator[tuple[str, click.Command]]:
    """Every verb in the tree, by the path a user would type."""
    stack: list[tuple[str, click.Command]] = [("sopuli", cli)]
    while stack:
        path, command = stack.pop()
        if isinstance(command, click.Group):
            stack.extend((f"{path} {name}", child) for name, child in command.commands.items())
        else:
            yield path, command


def test_there_are_commands_to_check() -> None:
    """Guards the walk: an empty tree would make the test below vacuous."""
    assert len(list(commands())) >= 4


@pytest.mark.parametrize(("path", "command"), list(commands()), ids=lambda one: str(one))
def test_every_verb_takes_the_global_options(path: str, command: click.Command) -> None:
    """A verb that forgets the decorator silently loses `--output` and `--dry-run`.

    The completeness check the issue asked for, as a walk rather than a list --
    a hand-maintained list is one somebody forgets to extend.
    """
    names = {param.name for param in command.params}
    assert set(GLOBAL_PARAMS) <= names, path


@pytest.mark.parametrize(("path", "command"), list(commands()), ids=lambda one: str(one))
def test_every_verb_receives_the_resolved_invocation(path: str, command: click.Command) -> None:
    """Reading a flag off a click parameter is reading a value that skipped the
    resolver. The decorator removes the opportunity; this pins that it is applied."""
    assert command.callback is not None
    # `inspect.signature` follows `__wrapped__` through both decorators, so this
    # is the verb's own signature rather than click's wrapper.
    assert INVOCATION_PARAM in inspect.signature(command.callback).parameters, path

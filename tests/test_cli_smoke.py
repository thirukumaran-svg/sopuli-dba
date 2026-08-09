"""CLI routing, exit codes and the invariant-1 guard.

Tier 0 (04-testing.md §4): in-process, no containers, no I/O. ``CliRunner``
invokes commands directly, so asserting an exact exit code costs nothing.
"""

from __future__ import annotations

import json

import click
import pytest
from click.testing import CliRunner

from sopuli.cli import cli
from sopuli.exit_codes import ExitCode
from sopuli.version import get_version


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_version_prints_package_version(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == ExitCode.SUCCESS
    assert get_version() in result.output


def test_help_lists_the_config_noun(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == ExitCode.SUCCESS
    assert "config" in result.output


def test_config_show_succeeds_in_text_mode(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["config", "show"])
    assert result.exit_code == ExitCode.SUCCESS
    assert result.output.strip()


def test_human_output_is_ascii(runner: CliRunner) -> None:
    """P4: identical behaviour on every platform.

    On Windows, redirected stdout uses cp1252 rather than UTF-8 (an attached
    console is fine -- this is a redirection problem, and redirection is how
    scheduled runs are captured). Characters inside cp1252 reach a UTF-8 reader
    as mojibake; characters outside it raise UnicodeEncodeError and kill the
    command. So the tool's own prose stays ASCII until the stream encoding is
    handled.
    """
    result = runner.invoke(cli, ["config", "show"])
    result.output.encode("ascii")  # raises UnicodeEncodeError if it is not


def test_all_help_text_is_ascii(runner: CliRunner) -> None:
    """The same rule for every command's help, including ones added later.

    Command help comes from docstrings, where an em dash is easy to type
    without thinking about the stream it will be written to.
    """
    offenders = []
    for path in _command_paths(cli):
        output = runner.invoke(cli, [*path, "--help"]).output
        try:
            output.encode("ascii")
        except UnicodeEncodeError:
            offenders.append(" ".join(path) or "sopuli")
    assert not offenders, f"non-ASCII help text in: {offenders}"


def test_config_show_succeeds_in_json_mode(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["config", "show", "--output", "json"])
    assert result.exit_code == ExitCode.SUCCESS
    document = json.loads(result.output)
    assert document["command"] == "config.show"
    assert document["exit_code"] == ExitCode.SUCCESS


def test_json_mode_emits_only_the_document(runner: CliRunner) -> None:
    """Human text must not leak into the machine-readable stream."""
    result = runner.invoke(cli, ["config", "show", "--output", "json"])
    json.loads(result.output)  # raises if anything else was printed alongside


def test_global_flag_works_after_the_verb(runner: CliRunner) -> None:
    """The order a DBA actually types has to work.

    This is the reason common_options exists rather than options on the group:
    a group-level option is only accepted *before* the subcommand. Pinned so a
    later refactor cannot quietly move the flag back onto the group.
    """
    result = runner.invoke(cli, ["config", "show", "--output", "json"])
    assert result.exit_code == ExitCode.SUCCESS
    json.loads(result.output)


def test_global_flag_before_the_noun_is_a_clean_usage_error(runner: CliRunner) -> None:
    """The consequence of the choice above, recorded rather than discovered.

    ``sopuli --output json config show`` is not supported: the option lives on
    the verb. It must fail as a usage error with exit 2, never a traceback.
    """
    result = runner.invoke(cli, ["--output", "json", "config", "show"])
    assert result.exit_code == ExitCode.USAGE
    assert "Traceback" not in result.output


def test_dry_run_is_reflected_in_the_document(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["config", "show", "--dry-run", "--output", "json"])
    assert result.exit_code == ExitCode.SUCCESS
    assert json.loads(result.output)["invocation"]["dry_run"] is True


def test_unknown_noun_is_a_usage_error(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["bogus"])
    assert result.exit_code == ExitCode.USAGE
    assert "Traceback" not in result.output


def test_unknown_verb_is_a_usage_error(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["config", "bogus"])
    assert result.exit_code == ExitCode.USAGE
    assert "Traceback" not in result.output


def test_unknown_output_mode_is_a_usage_error(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["config", "show", "--output", "yaml"])
    assert result.exit_code == ExitCode.USAGE


# --------------------------------------------------------------- invariant 1 ---

SECRET_LIKE = ("password", "passwd", "secret", "token", "credential", "apikey", "api-key")


def _command_paths(command: click.Command, path: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    """Every invocable path in the tree, including the root."""
    paths = [path]
    if isinstance(command, click.Group):
        for name, sub in command.commands.items():
            paths.extend(_command_paths(sub, (*path, name)))
    return paths


def _walk(command: click.Command, path: tuple[str, ...] = ()) -> list[tuple[str, str]]:
    """Yield ``(command path, option name)`` for every option in the tree."""
    found: list[tuple[str, str]] = []
    for param in command.params:
        for opt in list(param.opts) + list(param.secondary_opts):
            found.append((" ".join(path) or "sopuli", opt))
    if isinstance(command, click.Group):
        for name, sub in command.commands.items():
            found.extend(_walk(sub, (*path, name)))
    return found


def test_no_command_accepts_a_secret_on_the_command_line() -> None:
    """Invariant 1: secrets never appear in argv — they are visible in ``ps``.

    This guards the whole tree, so a future command cannot add ``--password``
    without a test failing and someone having to think about it.
    """
    offenders = [
        (where, opt)
        for where, opt in _walk(cli)
        if any(token in opt.lower().lstrip("-") for token in SECRET_LIKE)
    ]
    assert not offenders, f"secret-like CLI options are forbidden: {offenders}"

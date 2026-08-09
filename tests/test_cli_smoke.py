"""CLI routing, exit codes and the invariant-1 guard.

Tier 0 (04-testing.md §4): in-process, no containers, no I/O. ``CliRunner``
invokes commands directly, so asserting an exact exit code costs nothing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from sopuli import cli as cli_module
from sopuli.cli import cli
from sopuli.config import ConfigError
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
    """The tool's own prose stays ASCII.

    This started as a workaround for the stream encoding bug and outlived it.
    The streams are UTF-8 now (``sopuli.output.stream``), so this is no longer
    about what can be written -- it is about decoration being opt-in and
    deliberate. Box drawing and status glyphs belong to the presentation layer,
    where the choice to use them is made once and can be turned off; an em dash
    that arrived in a message because it looked nice is not that choice.

    User-supplied text -- account names, ORA- messages -- is exempt: it passes
    through as it came, which is exactly what the encoding fix makes safe.
    """
    result = runner.invoke(cli, ["config", "show"])
    result.output.encode("ascii")  # raises UnicodeEncodeError if it is not


def test_all_help_text_is_ascii(runner: CliRunner) -> None:
    """The same rule for every command's help, including ones added later.

    Command help comes from docstrings, where an em dash is easy to type
    without thinking about it. This is the test that makes the convention hold
    as the command tree grows.
    """
    offenders = []
    for path in _command_paths(cli):
        output = runner.invoke(cli, [*path, "--help"]).output
        try:
            output.encode("ascii")
        except UnicodeEncodeError:
            offenders.append(" ".join(path) or "sopuli")
    assert not offenders, f"non-ASCII help text in: {offenders}"


def test_main_configures_the_streams_before_dispatching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The encoding fix has to run at the process boundary, not inside a verb.

    ``CliRunner`` invokes commands directly and never reaches ``main``, so
    without this the wiring could be deleted and every other test would stay
    green. Order matters as much as the call: click can write a usage error to
    stderr before any command body runs.
    """
    calls: list[str] = []
    monkeypatch.setattr(cli_module, "configure_streams", lambda: calls.append("streams"))
    monkeypatch.setattr(sys, "argv", ["sopuli", "config", "show"])

    with pytest.raises(SystemExit) as exit_info:
        cli_module.main()

    assert exit_info.value.code == ExitCode.SUCCESS
    assert calls == ["streams"]


def test_a_config_error_exits_two_and_keeps_its_location(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """P5 puts config validation on 2 with usage errors, not on 1 with failures.

    A scheduler branches on that: "fix your file" and "something broke" call for
    different people. The boundary is monkeypatched rather than driven through a
    real command because no command loads config yet -- what is under test is the
    mapping from exception to exit code, and that exists now.
    """

    def explode(**_: object) -> None:
        raise ConfigError(
            "unsupported config version 4",
            source=Path("sopuli.yaml"),
            line=1,
            hint="this build understands: 1",
        )

    monkeypatch.setattr(cli_module.cli, "main", explode)
    monkeypatch.setattr(sys, "argv", ["sopuli", "config", "show"])

    with pytest.raises(SystemExit) as exit_info:
        cli_module.main()

    assert exit_info.value.code == ExitCode.USAGE
    captured = capsys.readouterr()
    assert "sopuli.yaml:1: unsupported config version 4" in captured.err
    assert "hint: this build understands: 1" in captured.err
    assert "Traceback" not in captured.err


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


@pytest.mark.parametrize("choice", ["auto", "always", "never"])
def test_every_color_choice_is_accepted(runner: CliRunner, choice: str) -> None:
    result = runner.invoke(cli, ["config", "show", "--color", choice])
    assert result.exit_code == ExitCode.SUCCESS


def test_unknown_color_choice_is_a_usage_error(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["config", "show", "--color", "beige"])
    assert result.exit_code == ExitCode.USAGE


def test_color_always_does_not_reach_the_json_document(runner: CliRunner) -> None:
    """Invariant 12: the machine stream is a contract.

    ``CliRunner`` gives a non-TTY stream, so plain autodetection would pass this
    even if the rule were missing -- ``--color always`` is what makes it a real
    assertion. If an escape sequence ever leaks in, ``json.loads`` fails here
    rather than in someone's `jq` pipeline.
    """
    result = runner.invoke(cli, ["config", "show", "--output", "json", "--color", "always"])

    assert result.exit_code == ExitCode.SUCCESS
    assert "\x1b" not in result.output
    json.loads(result.output)


def test_text_output_is_not_coloured_when_piped(runner: CliRunner) -> None:
    """The default path for a scheduled run: redirected, so no decoration."""
    result = runner.invoke(cli, ["config", "show"])

    assert result.exit_code == ExitCode.SUCCESS
    assert "\x1b" not in result.output


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

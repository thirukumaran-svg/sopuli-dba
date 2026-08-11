"""CLI routing, exit codes and the invariant-1 guard.

Tier 0 (04-testing.md §4): in-process, no containers, no I/O. ``CliRunner``
invokes commands directly, so asserting an exact exit code costs nothing.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
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


@pytest.fixture
def show(config_file: Path) -> list[str]:
    """``config show`` against a config file that definitely exists.

    Every command discovers a config now, so a bare ``config show`` in a test
    would search the working directory and the user's config directory and
    answer differently on the machine of anyone who happens to have one. Naming
    the file is what keeps these tests about the CLI.
    """
    return ["config", "show", "--config", str(config_file)]


def test_version_prints_package_version(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == ExitCode.SUCCESS
    assert get_version() in result.output


def test_help_lists_the_config_noun(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == ExitCode.SUCCESS
    assert "config" in result.output


def test_config_show_succeeds_in_text_mode(runner: CliRunner, show: list[str]) -> None:
    result = runner.invoke(cli, show)
    assert result.exit_code == ExitCode.SUCCESS
    assert result.output.strip()


def test_human_output_is_ascii(runner: CliRunner, show: list[str], config_file: Path) -> None:
    """The tool's own prose stays ASCII.

    This started as a workaround for the stream encoding bug and outlived it.
    The streams are UTF-8 now (``sopuli.output.stream``), so this is no longer
    about what can be written -- it is about decoration being opt-in and
    deliberate. Box drawing and status glyphs belong to the presentation layer,
    where the choice to use them is made once and can be turned off; an em dash
    that arrived in a message because it looked nice is not that choice.

    User-supplied text -- account names, ORA- messages -- is exempt: it passes
    through as it came, which is exactly what the encoding fix makes safe. The
    config path is exactly that, and it is now printed: it comes from
    ``tmp_path``, so on a machine whose username is not ASCII this would fail on
    text the rule does not cover. Removing it first is what keeps the assertion
    about the prose around it.
    """
    result = runner.invoke(cli, show)

    prose = result.output.replace(str(config_file), "")
    prose.encode("ascii")  # raises UnicodeEncodeError if it is not


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
    monkeypatch: pytest.MonkeyPatch, show: list[str]
) -> None:
    """The encoding fix has to run at the process boundary, not inside a verb.

    ``CliRunner`` invokes commands directly and never reaches ``main``, so
    without this the wiring could be deleted and every other test would stay
    green. Order matters as much as the call: click can write a usage error to
    stderr before any command body runs.
    """
    calls: list[str] = []
    monkeypatch.setattr(cli_module, "configure_streams", lambda: calls.append("streams"))
    monkeypatch.setattr(sys, "argv", ["sopuli", *show])

    with pytest.raises(SystemExit) as exit_info:
        cli_module.main()

    assert exit_info.value.code == ExitCode.SUCCESS
    assert calls == ["streams"]


def test_a_config_error_exits_two_and_keeps_its_location(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    write_config: Callable[[str], Path],
) -> None:
    """P5 puts config validation on 2 with usage errors, not on 1 with failures.

    A scheduler branches on that: "fix your file" and "something broke" call for
    different people. Driven through a real command against a real bad file
    rather than a monkeypatched boundary, now that `config show` loads one: what
    matters is that a file the loader rejects reaches the user as a located
    message and exit 2, with no traceback anywhere in the path.
    """
    path = write_config("version: 4\n")
    monkeypatch.setattr(sys, "argv", ["sopuli", "config", "show", "--config", str(path)])

    with pytest.raises(SystemExit) as exit_info:
        cli_module.main()

    assert exit_info.value.code == ExitCode.USAGE
    captured = capsys.readouterr()
    assert f"{path}:" in captured.err
    assert "unsupported config version 4" in captured.err
    assert "hint: this build understands: 1" in captured.err
    assert "Traceback" not in captured.err


def test_config_show_succeeds_in_json_mode(runner: CliRunner, show: list[str]) -> None:
    result = runner.invoke(cli, [*show, "--output", "json"])
    assert result.exit_code == ExitCode.SUCCESS
    document = json.loads(result.output)
    assert document["command"] == "config.show"
    assert document["exit_code"] == ExitCode.SUCCESS


def test_json_mode_emits_only_the_document(runner: CliRunner, show: list[str]) -> None:
    """Human text must not leak into the machine-readable stream."""
    result = runner.invoke(cli, [*show, "--output", "json"])
    json.loads(result.output)  # raises if anything else was printed alongside


def test_global_flag_works_after_the_verb(runner: CliRunner, show: list[str]) -> None:
    """The order a DBA actually types has to work.

    This is the reason common_options exists rather than options on the group:
    a group-level option is only accepted *before* the subcommand. Pinned so a
    later refactor cannot quietly move the flag back onto the group.
    """
    result = runner.invoke(cli, [*show, "--output", "json"])
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


def test_dry_run_is_reflected_in_the_document(runner: CliRunner, show: list[str]) -> None:
    result = runner.invoke(cli, [*show, "--dry-run", "--output", "json"])
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


def test_unknown_output_mode_is_a_usage_error(runner: CliRunner, show: list[str]) -> None:
    result = runner.invoke(cli, [*show, "--output", "yaml"])
    assert result.exit_code == ExitCode.USAGE


@pytest.mark.parametrize("choice", ["auto", "always", "never"])
def test_every_color_choice_is_accepted(runner: CliRunner, choice: str, show: list[str]) -> None:
    result = runner.invoke(cli, [*show, "--color", choice])
    assert result.exit_code == ExitCode.SUCCESS


def test_unknown_color_choice_is_a_usage_error(runner: CliRunner, show: list[str]) -> None:
    result = runner.invoke(cli, [*show, "--color", "beige"])
    assert result.exit_code == ExitCode.USAGE


def test_color_always_does_not_reach_the_json_document(runner: CliRunner, show: list[str]) -> None:
    """Invariant 12: the machine stream is a contract.

    ``CliRunner`` gives a non-TTY stream, so plain autodetection would pass this
    even if the rule were missing -- ``--color always`` is what makes it a real
    assertion. If an escape sequence ever leaks in, ``json.loads`` fails here
    rather than in someone's `jq` pipeline.
    """
    result = runner.invoke(cli, [*show, "--output", "json", "--color", "always"])

    assert result.exit_code == ExitCode.SUCCESS
    assert "\x1b" not in result.output
    json.loads(result.output)


def test_text_output_is_not_coloured_when_piped(runner: CliRunner, show: list[str]) -> None:
    """The default path for a scheduled run: redirected, so no decoration."""
    result = runner.invoke(cli, show)

    assert result.exit_code == ExitCode.SUCCESS
    assert "\x1b" not in result.output


def test_colour_adds_decoration_and_never_information(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """`03-json-output.md` §1: the `NO_COLOR` path is lossless, not degraded.

    The strongest form of that promise, end to end: take the coloured output,
    strip the escapes, and it must equal the uncoloured output byte for byte. If
    anything were ever distinguishable *only* by colour, the two would differ.
    """
    path = str(write_config(ESTATE))
    command = ["config", "show", "--config", path, "--resolved"]

    coloured = runner.invoke(cli, [*command, "--color", "always"])
    plain = runner.invoke(cli, [*command, "--color", "never"])

    assert coloured.exit_code == ExitCode.SUCCESS
    assert "\x1b" in coloured.output, "--color always emitted nothing to strip"
    assert click.unstyle(coloured.output) == plain.output


@pytest.mark.parametrize("variable", ["NO_COLOR", "SOPULI_NO_COLOR"])
def test_the_no_color_variables_reach_a_real_command(
    runner: CliRunner, show: list[str], variable: str
) -> None:
    """Resolved in `output/color.py` and unit-tested there; asserted here through
    a command, because a control surface nothing consults is not one."""
    result = runner.invoke(cli, show, env={variable: "1"})

    assert result.exit_code == ExitCode.SUCCESS
    assert "\x1b" not in result.output


# ------------------------------------------------------------ config show ---

ESTATE = """
version: 1
vaults:
  vault-dev: { type: hashicorp, addr: "https://v.example.com" }
targets:
  - name: cdb-root-dev
    type: oracle
    dsn: db-dev.example.com:1521/CDBDEV.pdb.example.com
target_sets:
  appdb:
    type: oracle
    name: "appdb-{env}-{tenant}"
    dsn: "{host}:1521/{tenant}.pdb.example.com"
    environment: "{env}"
    for_each:
      env:
        dev:
          host: db-dev.example.com
          tenant: [alpha, beta]
"""


def test_config_show_names_the_file_it_read(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """The first question anybody asks of a tool that reads a config: which one?"""
    path = write_config(ESTATE)

    result = runner.invoke(cli, ["config", "show", "--config", str(path)])

    assert result.exit_code == ExitCode.SUCCESS
    assert f"config: {path}" in result.output


def test_a_non_ascii_config_path_reaches_the_output_intact(
    runner: CliRunner, tmp_path: Path
) -> None:
    """The other side of the ASCII rule, made real rather than assumed.

    The tool's own prose is ASCII; anything a user supplies passes through as it
    came, which is what the UTF-8 stream fix (#12) makes safe. A path is the
    first piece of user-supplied text any command prints, and "Muller" is a
    perfectly ordinary Windows username.
    """
    home = tmp_path / "Müller"
    home.mkdir()
    path = _write(home / "sopuli.yaml", "version: 1\n")

    result = runner.invoke(cli, ["config", "show", "--config", str(path)])

    assert result.exit_code == ExitCode.SUCCESS
    assert str(path) in result.output


def test_config_show_renders_the_file_as_loaded(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """The default view answers *did my YAML say what I think it says*, so it
    shows the sections as written -- the target set as a template, not as the
    targets it will become."""
    result = runner.invoke(cli, ["config", "show", "--config", str(write_config(ESTATE))])

    assert result.exit_code == ExitCode.SUCCESS
    assert "appdb-{env}-{tenant}" in result.output
    assert "appdb-dev-alpha" not in result.output


def test_config_show_resolved_renders_what_the_tool_would_act_on(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """And `--resolved` answers the other question. One explicit target plus a
    set over two tenants: the generated count is the number nobody can work out
    by reading the file."""
    path = write_config(ESTATE)

    result = runner.invoke(cli, ["config", "show", "--config", str(path), "--resolved"])

    assert result.exit_code == ExitCode.SUCCESS
    assert "appdb-dev-alpha" in result.output
    assert "3 targets (1 explicit, 2 generated)" in result.output


def test_config_show_prints_warnings_in_full(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """§10's warnings have nowhere else to go: they are the findings the loader
    decided were not worth refusing to run over, so a count alone would bury
    them."""
    path = write_config(f"{ESTATE}\nprofiles:\n  dev: {{ output: json }}\n")

    result = runner.invoke(cli, ["config", "show", "--config", str(path)])

    assert result.exit_code == ExitCode.SUCCESS
    assert "1 warning:" in result.output
    assert "named after an environment" in result.output


def test_repeated_config_options_are_layered_in_order(runner: CliRunner, tmp_path: Path) -> None:
    """§9: several `--config` files layer left to right, and the output has to
    say so -- an estate assembled from two files is otherwise indistinguishable
    from one file that says something surprising."""
    base = _write(tmp_path / "base.yaml", ESTATE)
    overlay = _write(tmp_path / "overlay.yaml", "version: 1\nvaults:\n  extra: { type: file }\n")

    result = runner.invoke(cli, ["config", "show", "--config", str(base), "--config", str(overlay)])

    assert result.exit_code == ExitCode.SUCCESS
    assert f"config: {base}" in result.output
    assert f"{overlay} (layered)" in result.output
    assert "vault-dev" in result.output
    assert "extra" in result.output


def test_a_named_config_that_does_not_exist_is_a_usage_error(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Never skipped in favour of the next candidate: a CI job whose path has a
    typo must not quietly run against the system config instead."""
    missing = tmp_path / "nope.yaml"

    result = runner.invoke(cli, ["config", "show", "--config", str(missing)], standalone_mode=False)

    assert isinstance(result.exception, ConfigError)
    assert "named by --config does not exist" in str(result.exception)
    assert result.exception.exit_code == ExitCode.USAGE


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    if sys.platform != "win32":
        path.chmod(0o600)
    return path


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

"""CLI routing, exit codes and the invariant-1 guard.

Tier 0 (04-testing.md §4): in-process, no containers, no I/O. ``CliRunner``
invokes commands directly, so asserting an exact exit code costs nothing.
"""

from __future__ import annotations

import json
import socket
import sys
from collections.abc import Callable
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from sopuli import cli as cli_module
from sopuli import invocation as invocation_module
from sopuli import material
from sopuli.cli import cli
from sopuli.config import ConfigError
from sopuli.exit_codes import ExitCode
from sopuli.output.document import Diagnostic
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


def test_a_config_error_exits_nine_and_keeps_its_location(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    write_config: Callable[[str], Path],
) -> None:
    """P5 gives a bad configuration its own code rather than folding it into 1.

    A scheduler branches on that: "fix your file" and "something broke" call for
    different people -- and since #8, so does "fix your command line", which is
    what exit 2 now means on its own. Driven through a real command against a
    real bad file rather than a monkeypatched boundary: what matters is that a
    file the loader rejects reaches the user as a located message and exit 9,
    with no traceback anywhere in the path.
    """
    path = write_config("version: 4\n")
    monkeypatch.setattr(sys, "argv", ["sopuli", "config", "show", "--config", str(path)])

    with pytest.raises(SystemExit) as exit_info:
        cli_module.main()

    assert exit_info.value.code == ExitCode.CONFIG_INVALID
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

    A click option declared on the group alone is only accepted *before* the
    subcommand, so every verb carries its own copy
    (:func:`~sopuli.invocation.global_options`). Pinned so a later refactor
    cannot quietly leave the flag on the group only.
    """
    result = runner.invoke(cli, [*show, "--output", "json"])
    assert result.exit_code == ExitCode.SUCCESS
    json.loads(result.output)


def test_global_flag_works_before_the_noun_too(runner: CliRunner, config_file: Path) -> None:
    """The other order, which used to be a usage error (#10).

    ``sopuli --output json config show`` and ``sopuli config show --output json``
    are the same person typing the same intent, so they resolve the same way.
    The precedence rules for the two positions live in
    ``tests/test_cli_precedence.py``; this is the routing.
    """
    result = runner.invoke(
        cli, ["--output", "json", "config", "show", "--config", str(config_file)]
    )
    assert result.exit_code == ExitCode.SUCCESS
    json.loads(result.output)


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


@pytest.mark.parametrize("view", [[], ["--resolved"]], ids=["declared", "resolved"])
def test_config_show_reports_warnings_as_diagnostics(
    runner: CliRunner, write_config: Callable[[str], Path], view: list[str]
) -> None:
    """The text view is not the contract. A warning that appears only there is
    invisible to the scheduler reading the document, which is the reader §10's
    findings most need to reach -- so both views carry them, like
    ``config validate`` does."""
    path = write_config(f"{ESTATE}\nprofiles:\n  dev: {{ output: json }}\n")

    result = runner.invoke(
        cli, ["config", "show", "--config", str(path), *view, "--output", "json"]
    )

    assert result.exit_code == ExitCode.SUCCESS
    document = json.loads(result.output)
    assert [entry["level"] for entry in document["diagnostics"]] == ["warning"]
    assert "named after an environment" in document["diagnostics"][0]["message"]


def test_config_show_emits_no_diagnostics_for_a_clean_file(
    runner: CliRunner, config_file: Path
) -> None:
    """A clean run carries no empty array, for the reason its `validate`
    counterpart gives: a field present in every document stops being read."""
    result = runner.invoke(
        cli, ["config", "show", "--config", str(config_file), "--output", "json"]
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert "diagnostics" not in json.loads(result.output)


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


def test_a_named_config_that_does_not_exist_is_a_config_error(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Never skipped in favour of the next candidate: a CI job whose path has a
    typo must not quietly run against the system config instead.

    A configuration error rather than a usage one, since #8: `--config` parsed
    perfectly and the run began, and it is the path it named that is not there.
    """
    missing = tmp_path / "nope.yaml"

    result = runner.invoke(cli, ["config", "show", "--config", str(missing)], standalone_mode=False)

    assert isinstance(result.exception, ConfigError)
    assert "named by --config does not exist" in str(result.exception)
    assert result.exception.exit_code == ExitCode.CONFIG_INVALID


# -------------------------------------------------------------- --explain ---
#
# The rendering itself is `tests/test_explain_view.py`, which can feed the view
# settings this tool cannot yet supply. These are about the flag: that it is
# wired, that it changes both output modes, and that it is not coupled to
# `--resolved`.


def test_explain_prints_where_each_setting_came_from(
    runner: CliRunner, show: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOPULI_DRY_RUN", "1")

    result = runner.invoke(cli, [*show, "--explain"])

    assert result.exit_code == ExitCode.SUCCESS
    assert "settings" in result.output
    assert "safety.dry_run" in result.output
    assert "[env SOPULI_DRY_RUN]" in result.output


def test_without_explain_the_output_is_unchanged(runner: CliRunner, show: list[str]) -> None:
    """The flag adds a section; it does not reshape the view it is asked of."""
    plain = runner.invoke(cli, show).output
    explained = runner.invoke(cli, [*show, "--explain"]).output

    assert explained.startswith(plain.rstrip("\n"))
    assert "settings" not in plain


def test_explain_does_not_require_resolved(
    runner: CliRunner, show: list[str], config_file: Path
) -> None:
    """Unlike `--select`, which has nothing to filter until the estate exists.

    Where a setting came from is the same answer in both views, so refusing it in
    one of them would be a rule a user meets and cannot explain (#53).
    """
    for argv in ([*show, "--explain"], [*show, "--explain", "--resolved"]):
        result = runner.invoke(cli, argv)
        assert result.exit_code == ExitCode.SUCCESS, argv
        assert "settings" in result.output, argv


def test_explain_widens_the_options_the_document_carries(
    runner: CliRunner, show: list[str]
) -> None:
    """One rule for both modes: `--explain` means "everything you consulted".

    Without it the document keeps §`invocation.options`' own filter -- what
    changed behaviour -- so a built-in default is absent. With it, the same
    producer is asked for all of them.
    """
    plain = json.loads(runner.invoke(cli, [*show, "--output", "json"]).output)
    explained = json.loads(runner.invoke(cli, [*show, "--output", "json", "--explain"]).output)

    assert "safety.dry_run" not in plain["invocation"]["options"]
    assert explained["invocation"]["options"]["safety.dry_run"] == {
        "value": False,
        "source": "builtin",
    }


def test_explain_changes_how_many_options_appear_and_nothing_else(
    runner: CliRunner, show: list[str]
) -> None:
    """The schema shape does not move, so neither does a consumer that reads it."""
    plain = json.loads(runner.invoke(cli, [*show, "--output", "json"]).output)
    explained = json.loads(runner.invoke(cli, [*show, "--output", "json", "--explain"]).output)

    assert plain["invocation"]["options"]["output"] == explained["invocation"]["options"]["output"]


def test_a_verb_adds_its_diagnostics_to_the_ones_already_there(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The document is open before a verb runs, and may already carry findings.

    A defeated ratchet becomes a warning when the invocation resolves, so a verb
    that *assigned* its config warnings would drop it -- silently, and in exactly
    the case invariant 10 exists to make visible. No layer can supply a looser
    value yet, so the note is injected here: the point is the accumulation, and
    the real producer arrives with the settings that can lose a ratchet.
    """
    monkeypatch.setattr(
        invocation_module,
        "ratchet_notes",
        lambda resolved: [Diagnostic(level="warning", message="a ratchet held")],
    )
    path = write_config(f"{ESTATE}\nprofiles:\n  dev: {{ output: json }}\n")

    result = runner.invoke(cli, ["config", "show", "--config", str(path), "--output", "json"])

    assert result.exit_code == ExitCode.SUCCESS
    messages = [entry["message"] for entry in json.loads(result.output)["diagnostics"]]
    assert "a ratchet held" in messages
    assert any("named after an environment" in message for message in messages)


# -------------------------------------------------------- config validate ---


def test_config_validate_accepts_a_good_file(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """P3 makes this a first-class command. What it reports on success is small
    on purpose -- the interesting output is the one it does not produce -- but
    the counts have to be there: a file that expands to no targets passes
    validation and manages nothing."""
    path = write_config(ESTATE)

    result = runner.invoke(cli, ["config", "validate", "--config", str(path)])

    assert result.exit_code == ExitCode.SUCCESS
    assert f"config: {path}" in result.output
    assert "ok: 3 targets" in result.output


def test_config_validate_exits_nine_on_an_unknown_key(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    write_config: Callable[[str], Path],
) -> None:
    """P3's own sentence: "exits non-zero on unknown keys -- a typo in a
    credential tool must never be silently ignored".

    Driven through ``main`` rather than the runner, because the exit code is the
    contract here and it is the boundary that maps a ConfigError onto it.

    Exit 9 since #8. This verb is the reason the code exists: reporting
    configuration problems is its entire purpose, so it is the one that must not
    share an exit code with "you typed the command wrong".
    """
    path = write_config("version: 1\ntargts: []\n")
    monkeypatch.setattr(sys, "argv", ["sopuli", "config", "validate", "--config", str(path)])

    with pytest.raises(SystemExit) as exit_info:
        cli_module.main()

    assert exit_info.value.code == ExitCode.CONFIG_INVALID
    captured = capsys.readouterr()
    assert "unknown key 'targts'" in captured.err
    assert "Traceback" not in captured.err


def test_config_validate_reports_warnings_both_ways(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """§10's warnings are findings the loader decided not to refuse to run over,
    so they must survive into both views -- in full in the text, and as run-level
    ``diagnostics`` in the document, which is the only path by which a scheduler
    ever sees one.

    Asserted by *presence* rather than by count, since #170: whether the estate's
    driver is installed is a property of the machine running the suite, so a
    count here would mean one thing under `sopuli-dba[all]` and another under a
    base install. `tests/driver/test_driver_registry.py` pins that warning
    deterministically instead."""
    path = write_config(f"{ESTATE}\nprofiles:\n  dev: {{ output: json }}\n")
    command = ["config", "validate", "--config", str(path)]

    text = runner.invoke(cli, command)
    emitted = runner.invoke(cli, [*command, "--output", "json"])

    assert text.exit_code == ExitCode.SUCCESS
    assert "warning" in text.output
    assert "named after an environment" in text.output
    assert emitted.exit_code == ExitCode.SUCCESS
    document = json.loads(emitted.output)
    assert {entry["level"] for entry in document["diagnostics"]} == {"warning"}
    assert any(
        "named after an environment" in entry["message"] for entry in document["diagnostics"]
    )


def test_config_validate_emits_no_diagnostics_for_a_clean_file(
    runner: CliRunner, config_file: Path
) -> None:
    """A clean run carries no empty array. The schema types `diagnostics` as an
    array, so an empty one would validate -- and would appear in every document
    a scheduler ever parses, which is how a field stops being read."""
    result = runner.invoke(
        cli, ["config", "validate", "--config", str(config_file), "--output", "json"]
    )

    assert result.exit_code == ExitCode.SUCCESS
    document = json.loads(result.output)
    assert document["command"] == "config.validate"
    assert "diagnostics" not in document


def test_config_validate_shows_nothing_of_the_file_itself(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """`validate` and `show` are different questions, and the JSON says so: only
    `show` carries a `config` section. Keeping validate's document empty of one
    is what lets CI consume it without deciding whether it wanted the estate."""
    path = write_config(ESTATE)

    result = runner.invoke(cli, ["config", "validate", "--config", str(path), "--output", "json"])

    assert result.exit_code == ExitCode.SUCCESS
    assert "config" not in json.loads(result.output)


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    if sys.platform != "win32":
        path.chmod(0o600)
    return path


# --------------------------------------------------------------- invariant 1 ---

SECRET_LIKE = ("password", "passwd", "secret", "token", "credential", "apikey", "api-key")

#: The two secret-like option names that are allowed, each with the reason it
#: carries no secret and a test below that holds it to that reason.
#:
#: Kept as a literal rather than as a rule over the names, so adding a third is a
#: line somebody has to write and defend. A suffix rule -- "anything ending
#: `-file` names a location" -- would let `--password-file` in silently, and
#: whether *that* is acceptable is UC-1's decision to make, not this list's.
SECRET_LIKE_EXCEPTIONS = {
    #: Takes a path (#145, ADR-007). `test_the_token_flag_takes_a_path` holds it.
    "--vault-token-file",
    #: Exists only to be refused. `test_the_bare_token_flag_is_refused` holds it.
    "--vault-token",
}


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
        if opt not in SECRET_LIKE_EXCEPTIONS
        and any(token in opt.lower().lstrip("-") for token in SECRET_LIKE)
    ]
    assert not offenders, f"secret-like CLI options are forbidden: {offenders}"


def test_every_secret_like_exception_is_actually_declared() -> None:
    """The allowlist may not outlive the options it excuses.

    An entry for an option nobody declares any more is an entry that would
    silently excuse a *future* option of the same name -- which is exactly the
    hole the guard above exists to close.
    """
    declared = {opt for _where, opt in _walk(cli)}

    assert declared >= SECRET_LIKE_EXCEPTIONS


def test_the_token_flag_takes_a_path(runner: CliRunner, show: list[str], tmp_path: Path) -> None:
    """`--vault-token-file` is the command line's position in §3a's token chain,
    and what it takes is a location. Accepted by a command that never reaches a
    store, because the flag is a location until something needs the value."""
    result = runner.invoke(cli, [*show, "--vault-token-file", str(tmp_path / "token")])

    assert result.exit_code == ExitCode.SUCCESS


@pytest.mark.parametrize(
    "written",
    [
        ["--vault-token"],
        ["--vault-token", "s.notatoken"],
        ["--vault-token=s.notatoken"],
    ],
    ids=["bare", "separate value", "attached value"],
)
def test_the_bare_token_flag_is_refused(
    runner: CliRunner, show: list[str], written: list[str]
) -> None:
    """#145: refused rather than absent, and refused rather than ignored.

    All three spellings, because the one somebody types is whichever Vault's own
    CLI taught them. A plain flag would answer the second with "unexpected extra
    argument" and a plain value option would answer the first with "requires an
    argument" -- click explaining its parser instead of the tool explaining
    invariant 1.

    `ArgumentError` rather than a `click.UsageError`, so the exit code is
    asserted on the exception: only the boundary in `main` maps one onto the
    process, which `tests/test_error_contract.py` drives for real.
    """
    result = runner.invoke(cli, [*show, *written])

    assert isinstance(result.exception, ConfigError)
    assert result.exception.exit_code == ExitCode.USAGE
    assert "--vault-token is not an option" in str(result.exception)


def test_the_refusal_names_every_source_that_does_work(runner: CliRunner, show: list[str]) -> None:
    """All four, not just the file form. A CI job where writing a token to disk
    is awkward is exactly the case that hits this, and `SOPULI_VAULT_TOKEN=...`
    already works -- a hint naming only the flag would hide that."""
    result = runner.invoke(cli, [*show, "--vault-token", "s.notatoken"])

    for source in material.TOKEN_SOURCES:
        assert source in str(result.exception)


def test_the_token_flag_is_refused_in_the_group_position_too(
    runner: CliRunner, config_file: Path
) -> None:
    """Both click parsers, one answer. The group's copy is where somebody who
    writes it the way Vault's CLI takes it will land."""
    result = runner.invoke(
        cli, ["--vault-token", "s.notatoken", "config", "show", "--config", str(config_file)]
    )

    assert isinstance(result.exception, ConfigError)
    assert result.exception.exit_code == ExitCode.USAGE


def test_the_refusal_survives_dry_run(runner: CliRunner, show: list[str]) -> None:
    """The property worth keeping from the plan-first mechanism: a rehearsal
    cannot come back clean while the flag silently did nothing."""
    result = runner.invoke(cli, [*show, "--dry-run", "--vault-token", "s.notatoken"])

    assert isinstance(result.exception, ConfigError)
    assert result.exception.exit_code == ExitCode.USAGE


def test_the_refusal_never_echoes_what_the_flag_carried(runner: CliRunner, show: list[str]) -> None:
    """Refusing is not a reason to print it. The value dies in the parser
    callback, so there is nothing in the invocation for a message -- or a
    traceback, or a `repr` -- to reach for."""
    result = runner.invoke(cli, [*show, "--vault-token", "s.notatoken"])

    assert "s.notatoken" not in str(result.exception)
    assert "s.notatoken" not in result.output


def test_the_refused_flag_is_hidden_from_help(runner: CliRunner) -> None:
    """Help must not advertise a flag whose only behaviour is to refuse.
    `--vault-token-file`, which works, is listed."""
    text = runner.invoke(cli, ["config", "show", "--help"]).output

    assert "--vault-token-file" in text
    assert "--vault-token " not in text.replace("--vault-token-file", "")


#: Two environments and an application, which `ESTATE` deliberately lacks: a
#: selector needs something to leave behind, and a binding needs to disappear
#: with its target.
SELECTABLE = """
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
    vault: vault-dev
    for_each:
      env:
        dev:
          host: db-dev.example.com
          tenant: [alpha, beta]
        qa:
          host: db-test.example.com
          tenant: [alpha, beta]
groups:
  app-pdbs: { match: { target_set: appdb } }
applications:
  - name: acme
    targets: { group: app-pdbs }
    accounts: [acme_web_user]
    secret_template: "tenants/{tenant}#DB_CREDENTIALS/{account}"
"""


def test_select_narrows_the_resolved_estate(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    path = write_config(SELECTABLE)

    result = runner.invoke(
        cli, ["config", "show", "--resolved", "--select", "env=qa", "--config", str(path)]
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert "appdb-qa-alpha" in result.output
    assert "appdb-dev-alpha" not in result.output
    assert "2 targets" in result.output


def test_select_says_what_it_filtered_by(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """Filtered output gets pasted into tickets. Two targets with no note of the
    selector reads as an estate of two."""
    path = write_config(SELECTABLE)

    result = runner.invoke(
        cli, ["config", "show", "--resolved", "--select", "env=qa", "--config", str(path)]
    )

    assert "select: env=qa" in result.output


def test_a_binding_leaves_with_its_target(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """A binding whose target was filtered out describes work on something this
    run cannot see."""
    path = write_config(SELECTABLE)

    result = runner.invoke(
        cli,
        [
            "config",
            "show",
            "--resolved",
            "--select",
            "env=qa,tenant=beta",
            "--config",
            str(path),
            "--output",
            "json",
        ],
    )

    assert result.exit_code == ExitCode.SUCCESS
    document = json.loads(result.output)
    assert [target["name"] for target in document["config"]["targets"]] == ["appdb-qa-beta"]
    assert [binding["target"] for binding in document["config"]["bindings"]] == ["appdb-qa-beta"]


def test_the_document_records_what_the_run_was_narrowed_to(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """Invariant 12 is a contract about meaning, not just shape: a consumer
    counting two targets cannot otherwise tell a small estate from a filtered
    one."""
    path = write_config(SELECTABLE)
    command = ["config", "show", "--resolved", "--config", str(path), "--output", "json"]

    filtered = runner.invoke(cli, [*command, "--select", "env=qa"])
    whole = runner.invoke(cli, command)

    assert filtered.exit_code == ExitCode.SUCCESS
    assert json.loads(filtered.output)["invocation"]["selection"] == {"select": {"env": "qa"}}
    assert whole.exit_code == ExitCode.SUCCESS
    assert "selection" not in json.loads(whole.output)["invocation"]


def test_a_selector_matching_nothing_is_not_an_error(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """Exit 0 with an answer, not exit 2. "None of them" is a legitimate reply
    to a legitimate question -- but it is said in words, because an empty table
    under a `targets` heading looks like an estate that expanded to nothing."""
    path = write_config(SELECTABLE)

    result = runner.invoke(
        cli, ["config", "show", "--resolved", "--select", "env=staging", "--config", str(path)]
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert "no targets carry env=staging" in result.output
    assert "NAME" not in result.output


def test_select_without_resolved_is_refused(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """Ignoring it would be the failure P3 refuses for unknown keys: the run
    looks like it did what was asked. The declared view shows the file, and the
    estate a selector narrows does not exist until `--resolved` builds it."""
    path = write_config(SELECTABLE)

    result = runner.invoke(
        cli,
        ["config", "show", "--select", "env=qa", "--config", str(path)],
        standalone_mode=False,
    )

    # A usage error rather than a config error: both options parsed, they simply
    # do not form a valid request, and no file is at fault (#8).
    assert isinstance(result.exception, click.UsageError)
    assert "nothing to filter without --resolved" in str(result.exception)
    assert result.exception.exit_code == ExitCode.USAGE


def test_a_malformed_selector_is_a_usage_error(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    path = write_config(SELECTABLE)

    result = runner.invoke(
        cli,
        ["config", "show", "--resolved", "--select", "env", "--config", str(path)],
        standalone_mode=False,
    )

    assert isinstance(result.exception, ConfigError)
    assert "not a label match" in str(result.exception)
    assert result.exception.exit_code == ExitCode.USAGE


def test_selecting_cannot_reach_a_target_the_file_does_not_declare(  # invariant 5
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """The config is the whitelist. A selector filters it and cannot extend it,
    so a label nothing carries selects nothing rather than conjuring a target."""
    path = write_config(SELECTABLE)

    result = runner.invoke(
        cli,
        [
            "config",
            "show",
            "--resolved",
            "--select",
            "tenant=omega",
            "--config",
            str(path),
            "--output",
            "json",
        ],
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert json.loads(result.output)["config"]["targets"] == []


# ------------------------------------------------------------ target list ---


def test_target_list_shows_the_expanded_estate(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    path = write_config(SELECTABLE)

    result = runner.invoke(cli, ["target", "list", "--config", str(path)])

    assert result.exit_code == ExitCode.SUCCESS
    assert "appdb-dev-alpha" in result.output
    assert "appdb-qa-beta" in result.output
    assert "5 targets (1 explicit, 4 generated)" in result.output


def test_target_list_takes_a_selector(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """§4's own example of this command is `target list --select env=qa`."""
    path = write_config(SELECTABLE)

    result = runner.invoke(cli, ["target", "list", "--select", "env=qa", "--config", str(path)])

    assert result.exit_code == ExitCode.SUCCESS
    assert "appdb-qa-alpha" in result.output
    assert "appdb-dev-alpha" not in result.output


def test_target_list_needs_no_resolved_flag(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """Always the expanded estate: a target set is a template, and the targets
    it generates are the whole subject of this command. `--resolved` here would
    be a flag to suppress the only thing it is for."""
    path = write_config(SELECTABLE)

    result = runner.invoke(cli, ["target", "list", "--resolved", "--config", str(path)])

    assert result.exit_code == ExitCode.USAGE
    assert "no such option" in result.output.lower()


def test_target_list_and_config_show_agree_on_the_count(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """Two commands over one file disagreeing about how many databases are in
    scope is the failure worth a test of its own."""
    path = write_config(SELECTABLE)

    listed = runner.invoke(cli, ["target", "list", "--config", str(path), "--output", "json"])
    shown = runner.invoke(
        cli, ["config", "show", "--resolved", "--config", str(path), "--output", "json"]
    )

    assert listed.exit_code == ExitCode.SUCCESS
    assert shown.exit_code == ExitCode.SUCCESS
    listed_names = [target["name"] for target in json.loads(listed.output)["config"]["targets"]]
    shown_names = [target["name"] for target in json.loads(shown.output)["config"]["targets"]]
    assert listed_names == shown_names
    assert json.loads(listed.output)["summary"]["total"] == len(shown_names)


def test_target_list_names_itself_in_the_document(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """`command` is a closed enum in the schema, so a new verb that forgot to
    add itself would fail validation rather than emit an unknown value."""
    path = write_config(SELECTABLE)

    result = runner.invoke(cli, ["target", "list", "--config", str(path), "--output", "json"])

    assert json.loads(result.output)["command"] == "target.list"


def test_target_list_opens_no_socket(
    runner: CliRunner, write_config: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """It says which targets exist, never which are reachable. Reachability is
    a different command with a different failure mode."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("target list opened a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    path = write_config(SELECTABLE)

    result = runner.invoke(cli, ["target", "list", "--config", str(path)])

    assert result.exit_code == ExitCode.SUCCESS

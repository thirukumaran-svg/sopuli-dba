"""Which exits produce a document, and which produce nothing (J7, issue #8).

Tier 0 (04-testing.md §4): in-process, no containers.

    A run document describes a run, and a run begins when the invocation
    resolves. No valid invocation, no document.

The consumer-facing half of that rule is what this file pins: **stdout is
byte-empty on exit 2**, and nothing else exits 2. J1's buffering happens to give
the first for free today, which is exactly why it is asserted rather than
inherited -- a guarantee consumers branch on should not depend on an unrelated
decision staying the way it is.

The other half -- that every *other* exit code emits a document -- arrives with
the exit handler that emits it. What is here now is the seam: the exit codes on
either side of it, and which errors land where.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from click.testing import CliRunner

from sopuli import cli as cli_module
from sopuli.cli import cli
from sopuli.exit_codes import ExitCode
from sopuli.output.document import SCHEMA_VERSION

SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

#: A file the loader rejects for a reason it can point at a line for.
BAD_CONFIG = "version: 1\ntargts: []\n"


@pytest.fixture
def runner() -> CliRunner:
    """Separate streams, so "stdout is empty" is a claim about stdout alone."""
    return CliRunner()


# ------------------------------------------------------- exit 2: no document ---

USAGE_CASES = {
    "unknown noun": ["bogus"],
    "unknown verb": ["config", "bogus"],
    "unknown option": ["config", "show", "--nope"],
    "bad option value": ["config", "show", "--output", "jsom"],
    "safety flag before the subcommand": ["--dry-run", "config", "show"],
}


@pytest.mark.parametrize(("why", "argv"), USAGE_CASES.items(), ids=list(USAGE_CASES))
def test_a_usage_error_exits_two_with_byte_empty_stdout(
    runner: CliRunner, why: str, argv: list[str]
) -> None:
    """The contract a consumer branches on, in both halves.

    "Empty stdout and exit 2 means the invocation never parsed" is only usable if
    both are true every time, so both are asserted -- and `--output json` is
    asked for in one of the cases to show that the request does not change the
    answer. The tool cannot honour a request for JSON that it failed to parse.
    """
    result = runner.invoke(cli, argv)

    assert result.exit_code == ExitCode.USAGE, why
    assert result.stdout == "", why
    assert result.stderr.strip(), f"{why}: the message has to go somewhere"


def test_asking_for_json_does_not_produce_one_on_a_usage_error(runner: CliRunner) -> None:
    """`--output json` parses here; the *verb* does not exist.

    The interesting half of the rule: the request for JSON was understood, and it
    still gets no document, because there is no run to describe.
    """
    result = runner.invoke(cli, ["--output", "json", "config", "bogus"])

    assert result.exit_code == ExitCode.USAGE
    assert result.stdout == ""


def test_two_flags_that_cannot_both_be_honoured_are_usage_errors(
    runner: CliRunner, config_file: Path
) -> None:
    """Both options parsed; together they are not a valid request.

    Reclassified in #8. They used to be `ConfigError`s and would have inherited
    exit 9, which would have made exit 9 mean "your file is wrong, or possibly
    your flags" -- and a consumer branching on it to say "fix your YAML"
    sometimes wrong.
    """
    selecting = runner.invoke(
        cli, ["config", "show", "--select", "env=qa", "--config", str(config_file)]
    )
    assert selecting.exit_code == ExitCode.USAGE
    assert selecting.stdout == ""
    assert "--resolved" in selecting.stderr

    revealing = runner.invoke(
        cli,
        ["policy", "sample", "--reveal", "--output", "json", "--config", str(config_file)],
    )
    assert revealing.exit_code == ExitCode.USAGE
    assert revealing.stdout == ""
    assert "--reveal" in revealing.stderr


def test_a_malformed_selector_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], config_file: Path
) -> None:
    """Found in the config layer, which cannot import click, so it raises
    `ArgumentError` -- a `ConfigError` that carries exit 2 instead of 9. The
    location is the tell: `--select`, not a key path.

    Through `main` rather than the runner because `ArgumentError` is not a click
    exception, so only the boundary turns it into an exit code. That is the same
    reason the exit-9 cases below go through `main`.
    """
    monkeypatch.setattr(
        sys,
        "argv",
        ["sopuli", "config", "show", "--select", "nonsense", "--config", str(config_file)],
    )

    with pytest.raises(SystemExit) as exit_info:
        cli_module.main()

    assert exit_info.value.code == ExitCode.USAGE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "--select" in captured.err


# ------------------------------------------------ exit 9: a run to describe ---


def test_a_bad_config_file_exits_nine(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    write_config: Callable[[str], Path],
) -> None:
    """Not 2. argv resolved and the run began; the file is what failed.

    Through `main` rather than the runner, because the exit code is the contract
    and `main` is what maps a `ConfigError` onto it.
    """
    path = write_config(BAD_CONFIG)
    monkeypatch.setattr(sys, "argv", ["sopuli", "config", "validate", "--config", str(path)])

    with pytest.raises(SystemExit) as exit_info:
        cli_module.main()

    assert exit_info.value.code == ExitCode.CONFIG_INVALID
    assert "unknown key 'targts'" in capsys.readouterr().err


def test_a_missing_named_config_exits_nine(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """`--config` parsed perfectly; the path it named is not there."""
    missing = tmp_path / "nope.yaml"
    monkeypatch.setattr(sys, "argv", ["sopuli", "config", "show", "--config", str(missing)])

    with pytest.raises(SystemExit) as exit_info:
        cli_module.main()

    assert exit_info.value.code == ExitCode.CONFIG_INVALID
    assert "does not exist" in capsys.readouterr().err


def test_an_undeclared_policy_name_exits_nine(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    write_config: Callable[[str], Path],
) -> None:
    """The boundary case #8 predicted would blur, pinned on purpose.

    The name came from the command line, so this *looks* like a usage error. It
    is not: argv resolved to a valid command with valid options, and the question
    "is there a policy called that" is answerable only by reading the file. The
    file is what the operator has to go and change, which is what exit 9 says.
    """
    path = write_config("version: 1\n")
    monkeypatch.setattr(
        sys, "argv", ["sopuli", "policy", "sample", "nosuch", "--config", str(path)]
    )

    with pytest.raises(SystemExit) as exit_info:
        cli_module.main()

    assert exit_info.value.code == ExitCode.CONFIG_INVALID
    assert "nosuch" in capsys.readouterr().err


# --------------------------------------------------------- the table itself ---


def test_every_exit_code_is_in_the_published_enum() -> None:
    """`exit_code` mirrors the process exit code, so the two vocabularies are one.

    Read from the committed schema rather than from a copy of its values, the way
    `tests/settings/test_registry.py` reads the `source` enum -- a code added to
    `ExitCode` without a schema bump has to fail somewhere, and this is where.
    """
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    published = schema["properties"]["exit_code"]["enum"]

    assert sorted(int(code) for code in ExitCode) == sorted(published)


def test_no_two_exit_codes_share_a_number() -> None:
    """The whole of #8, generalised past the pair it was about.

    ``ExitCode.USAGE`` and ``ExitCode.CONFIG_INVALID`` collapsing back into one
    value would take the consumer rule with them: "empty stdout and exit 2" stops
    distinguishing "your command line is wrong" from "your file is wrong", and
    one of the two would start carrying a document while the other did not. An
    ``IntEnum`` aliases duplicates silently rather than complaining, so the check
    is on the count.
    """
    assert len({int(code) for code in ExitCode}) == len(list(ExitCode))
    assert {"USAGE", "CONFIG_INVALID"} <= {code.name for code in ExitCode}

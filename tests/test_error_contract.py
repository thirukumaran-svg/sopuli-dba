"""Which exits produce a document, and which produce nothing (J7, issue #8).

Tier 0 (04-testing.md §4): in-process, no containers.

    A run document describes a run, and a run begins when the invocation
    resolves. No valid invocation, no document.

Both halves are pinned here. **Stdout is byte-empty on exit 2**, and J1's
buffering happens to give that for free today -- which is exactly why it is
asserted rather than inherited, since a guarantee consumers branch on should not
depend on an unrelated decision staying the way it is. And **every other exit
emits a document**, including the one nobody plans for: an exception from the
middle of a verb.

The failure documents are validated against the committed schema rather than
merely inspected. A document emitted only when something has already gone wrong
is the one nobody looks at until they need it.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import click
import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

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


@pytest.fixture
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))


def emitted(capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    """The run document a failed run wrote to stdout.

    Reads the captured streams once, so a caller can assert on the document and
    on stderr from the same run -- both happen, and which goes where is the
    contract.
    """
    document: dict[str, Any] = json.loads(capsys.readouterr().out)
    return document


def run_main(monkeypatch: pytest.MonkeyPatch, *argv: str) -> int:
    """Drive a real process boundary and return the exit code.

    Through ``main`` rather than ``CliRunner`` because the exit code is half of
    what is being asserted, and only the boundary maps a `ConfigError` onto one.
    """
    monkeypatch.setattr(sys, "argv", ["sopuli", *argv])
    with pytest.raises(SystemExit) as exit_info:
        cli_module.main()
    assert isinstance(exit_info.value.code, int)
    return exit_info.value.code


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


# --------------------------------------------- the document a failure emits ---


def test_a_config_error_emits_a_document_under_output_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    validator: Draft202012Validator,
    write_config: Callable[[str], Path],
) -> None:
    """`config validate` is the verb the whole decision was made for.

    Reporting configuration problems is its entire purpose, and until now
    `--output json` against a broken file produced an exit code and silence.
    """
    path = write_config(BAD_CONFIG)

    code = run_main(monkeypatch, "config", "validate", "--config", str(path), "--output", "json")
    document = emitted(capsys)

    assert code == ExitCode.CONFIG_INVALID
    assert list(validator.iter_errors(document)) == []
    assert document["exit_code"] == ExitCode.CONFIG_INVALID
    assert document["command"] == "config.validate"
    assert document["error"]["category"] == "config"
    assert "unknown key 'targts'" in document["error"]["message"]


def test_the_error_message_carries_the_location_and_the_hint_does_not(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    write_config: Callable[[str], Path],
) -> None:
    """`error` has a `hint` field and no location field, so the two split there.

    The file and key path are the most useful part of a config error and have
    nowhere else to go; the hint has its own field, so repeating it inside the
    message would hand a consumer the same sentence twice and a newline in the
    middle of a string it is about to put in a table.
    """
    path = write_config(BAD_CONFIG)

    run_main(monkeypatch, "config", "validate", "--config", str(path), "--output", "json")
    error = emitted(capsys)["error"]

    assert str(path) in error["message"]
    assert "\n" not in error["message"]
    assert "hint:" not in error["message"]
    assert error["hint"].startswith("known keys here")


def test_a_failure_says_so_on_both_streams(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    write_config: Callable[[str], Path],
) -> None:
    """The document is for the scheduler; the message is for whoever is watching.

    Both happen, and which goes where is the contract: a consumer parsing stdout
    must find only the document, and a human tailing a CI log must not have to
    parse JSON to see what went wrong.
    """
    path = write_config(BAD_CONFIG)

    run_main(monkeypatch, "config", "validate", "--config", str(path), "--output", "json")
    captured = capsys.readouterr()

    json.loads(captured.out)  # raises if anything else was printed alongside
    assert "unknown key 'targts'" in captured.err


def test_an_unexpected_exception_still_emits_a_valid_document(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    validator: Draft202012Validator,
    config_file: Path,
) -> None:
    """The case most likely to be missed, and the reason the document is opened
    early rather than assembled at the end.

    A verb that dies three lines in has no sections to report and still owes the
    consumer a document: the command it was running, the invocation, a zeroed
    summary, and the error. Assembling at the end would have produced nothing at
    all here -- which is exactly the shape a consumer cannot distinguish from a
    crashed process.
    """

    def explode(*args: object, **kwargs: object) -> None:
        raise RuntimeError("something went wrong")

    monkeypatch.setattr(cli_module, "load_layers", explode)

    code = run_main(monkeypatch, "config", "show", "--config", str(config_file), "--output", "json")
    document = emitted(capsys)

    assert code == ExitCode.FAILURE
    assert list(validator.iter_errors(document)) == []
    assert document["exit_code"] == ExitCode.FAILURE
    assert document["command"] == "config.show"
    assert document["summary"] == {"total": 0, "ok": 0, "changed": 0, "failed": 0}
    assert document["error"]["category"] == "internal"
    assert "something went wrong" in document["error"]["message"]


def test_an_abort_exits_eight_with_a_document(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    validator: Draft202012Validator,
    config_file: Path,
) -> None:
    """A run somebody stopped is still a run that happened.

    click's own handler would print "Aborted!" and exit 1; P5 puts "aborted by
    user / confirmation declined" on 8. Both halves matter: the document says 8
    and the process exits 8, because `exit_code` in the document is defined as
    equal to the process's.

    Nothing prompts yet, so the abort is injected -- but the path is the one a
    declined confirmation will take, and a Ctrl-C already takes today.
    """

    def abort(*args: object, **kwargs: object) -> None:
        raise click.Abort

    monkeypatch.setattr(cli_module, "load_layers", abort)

    code = run_main(monkeypatch, "config", "show", "--config", str(config_file), "--output", "json")
    document = emitted(capsys)

    assert code == ExitCode.ABORTED
    assert list(validator.iter_errors(document)) == []
    assert document["exit_code"] == ExitCode.ABORTED
    # No `error`: the category enum has no value for "the operator said no", and
    # `internal` would be a lie about what happened. The code says it, and a
    # diagnostic says it in words.
    assert "error" not in document
    assert document["diagnostics"] == [{"level": "info", "message": "aborted before completion"}]


def test_a_failed_run_still_reports_its_options(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    write_config: Callable[[str], Path],
) -> None:
    """The document is the *invocation's*, opened before the verb ran.

    "Why did the scheduled run fail and mine not" is answered by what each run
    was asked to do, which is the half a failure would otherwise drop.
    """
    path = write_config(BAD_CONFIG)
    monkeypatch.setenv("SOPULI_DRY_RUN", "1")

    run_main(monkeypatch, "config", "validate", "--config", str(path), "--output", "json")
    document = emitted(capsys)

    assert document["invocation"]["dry_run"] is True
    assert document["invocation"]["options"]["safety.dry_run"]["source"] == "env"


def test_text_output_gets_a_message_and_no_document(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    write_config: Callable[[str], Path],
) -> None:
    """A run document *is* the JSON output mode; text has no such thing.

    So the rule is about `--output json`, and the text path is unchanged: a
    located message on stderr and nothing on stdout.
    """
    path = write_config(BAD_CONFIG)

    code = run_main(monkeypatch, "config", "validate", "--config", str(path))
    captured = capsys.readouterr()

    assert code == ExitCode.CONFIG_INVALID
    assert captured.out == ""
    assert "unknown key 'targts'" in captured.err


def test_a_usage_error_emits_nothing_even_when_json_was_asked_for(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], config_file: Path
) -> None:
    """The seam, from the emitting side.

    `--select nonsense` is refused after the invocation would otherwise have
    resolved, so this is the case where the handler has a document in hand and
    must decline to emit it. Keyed on the exit code rather than on where the
    refusal happened, which is what makes the rule one line.
    """
    code = run_main(
        monkeypatch,
        "config",
        "show",
        "--select",
        "nonsense",
        "--config",
        str(config_file),
        "--output",
        "json",
    )
    captured = capsys.readouterr()

    assert code == ExitCode.USAGE
    assert captured.out == ""
    assert captured.err.strip()


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

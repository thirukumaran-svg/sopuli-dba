"""``policy sample`` — the command that shows what a policy produces.

Tier 0: in-process through ``CliRunner``, no containers, no I/O beyond the config
file the fixture writes.

The tests that matter most are the ones about *where the plaintext goes*. This is
the only command in the tool that prints a password on purpose — invariant 2's
third exception — and the whole argument for allowing it is that the exception is
narrow. Narrow is a property, so it is asserted rather than described:

* the default output contains no sample, and the assertion is against the values
  themselves rather than against a pattern, which the CSPRNG seam makes possible
* ``--output json`` carries none either, and cannot: the schema gives a sample no
  value property
* ``--reveal`` with ``--output json`` is refused rather than quietly downgraded
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import click
import pytest
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator

from sopuli import passwords
from sopuli.cli import cli
from sopuli.config import ConfigError
from sopuli.config.model import PasswordPolicy
from sopuli.exit_codes import ExitCode
from sopuli.output.document import SCHEMA_VERSION
from sopuli.passwords import check
from sopuli.secrets import Secret

RUN_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

#: §2's own policy, plus a second one so "declared policies:" has something to
#: list and `defaults.policy` has something to be.
POLICIES = """\
version: 1
defaults:
  policy: app-standard
policies:
  app-standard:
    password:
      length: 24
      charset: alnum_safe
      first_char: alpha
      require: { upper: 1, lower: 1, digit: 1, special: 1 }
  legacy:
    password:
      length: 30
      charset: alnum
"""

#: A policy with no `require:`, so a pinned CSPRNG can produce a known password
#: without tripping a composition rule.
PREDICTABLE = """\
version: 1
policies:
  simple:
    password:
      length: 6
      charset: custom
      allow: qwerty
"""

#: What that policy generates once every draw is the alphabet's first character.
PINNED = "qqqqqq"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def pin_csprng(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make generation deterministic, so a test can assert on the value itself.

    This is the seam ``tests/test_passwords.py`` uses to prove the CSPRNG is the
    real one; here it is what lets a leak test name the password it is looking for
    instead of guessing at a shape.
    """
    monkeypatch.setattr(passwords, "secure_choice", lambda alphabet: alphabet[0])


def sample(runner: CliRunner, path: Path, *args: str) -> Result:
    return runner.invoke(cli, ["policy", "sample", *args, "--config", str(path)])


def revealed(output: str) -> list[str]:
    """The passwords out of a `--reveal` table, and nothing else.

    Reads the region between the heading and the blank line under it rather than
    picking out lines that look like rows: the footer starts with a digit too, and
    a looser filter quietly counted it as a sixth password.
    """
    lines = output.splitlines()
    start = next(index for index, line in enumerate(lines) if line.startswith("#  CHARS"))
    body: list[str] = []
    for line in lines[start + 1 :]:
        if not line.strip():
            break
        body.append(line.split()[-1])
    return body


# ------------------------------------------------------------- the default ---


def test_it_reports_the_policy_and_one_row_per_sample(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    result = sample(runner, write_config(POLICIES), "app-standard", "--count", "3")

    assert result.exit_code == ExitCode.SUCCESS
    output = result.output
    assert "policy: app-standard" in output
    assert "length 24, alnum_safe, first_char alpha" in output
    assert "CHARS" in output
    assert "3 samples, all compliant" in output


def test_the_default_output_contains_no_sample(
    runner: CliRunner, write_config: Callable[[str], Path], pin_csprng: None
) -> None:
    """The whole reason `--reveal` is a flag rather than the behaviour.

    Asserted against the value the command actually produced -- with the CSPRNG
    pinned the test knows it is `qqqqqq` -- rather than against a pattern that a
    future format change could accidentally satisfy.
    """
    result = sample(runner, write_config(PREDICTABLE), "simple", "--count", "2")

    assert result.exit_code == ExitCode.SUCCESS
    assert PINNED not in result.output
    assert "pass --reveal to print them" in result.output


def test_the_byte_column_is_counted_in_the_named_encoding(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """§8 measures the limit in the database character set, so the same policy
    reports different byte counts against two databases."""
    path = write_config(
        "version: 1\npolicies:\n  wide:\n"
        "    password:\n      length: 4\n      charset: custom\n      allow: é\n"
    )

    in_utf8 = sample(runner, path, "wide", "--count", "1", "--max-bytes", "20")
    in_1252 = sample(
        runner, path, "wide", "--count", "1", "--max-bytes", "20", "--encoding", "cp1252"
    )

    assert "4      8" in in_utf8.output
    assert "4      4" in in_1252.output


def test_no_limit_leaves_the_byte_column_empty(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """Without `--max-bytes` there is no limit to measure against, and a number
    invented here would be the assumption UC-1 §4 step 2 warns about."""
    result = sample(runner, write_config(POLICIES), "app-standard", "--count", "1")

    assert "24     -" in result.output


# ---------------------------------------------------------------- --reveal ---


def test_reveal_prints_the_samples_and_says_not_to_use_them(
    runner: CliRunner, write_config: Callable[[str], Path], pin_csprng: None
) -> None:
    result = sample(runner, write_config(PREDICTABLE), "simple", "--count", "2", "--reveal")

    output = result.output
    assert output.count(PINNED) == 2
    assert "not for use" in output


def test_every_revealed_sample_satisfies_the_policy(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """The samples are the answer to "what will my passwords look like", so they
    have to be passwords the policy would accept -- read back out of the output
    and put through the same predicate the generator used."""
    declared = PasswordPolicy(
        length=24,
        charset="alnum_safe",
        first_char="alpha",
        require=(("digit", 1), ("lower", 1), ("special", 1), ("upper", 1)),
    )

    result = sample(runner, write_config(POLICIES), "app-standard", "--count", "5", "--reveal")

    passwords_ = revealed(result.output)

    assert len(passwords_) == 5
    for password in passwords_:
        assert check(Secret(password), declared, limit=None) == ()


def test_reveal_is_refused_with_json_output(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """JSON is what gets captured and shipped to log aggregation. Quietly dropping
    the flag would be the defect `select_option` describes; refusing is the
    `config show --select` precedent."""
    result = runner.invoke(
        cli,
        [
            "policy",
            "sample",
            "app-standard",
            "--reveal",
            "--output",
            "json",
            "--config",
            str(write_config(POLICIES)),
        ],
        standalone_mode=False,
    )

    # A usage error, not a config error: nothing is wrong with any file, two
    # flags simply cannot both be honoured. J7 puts that on exit 2, with no
    # run document -- which is the point here, since the document is the thing
    # `--output json` asked for and the sample must not appear in it either way.
    assert isinstance(result.exception, click.UsageError)
    assert "--reveal cannot be used with --output json" in str(result.exception)
    assert result.exception.exit_code == ExitCode.USAGE


# -------------------------------------------------------------------- json ---


def test_the_json_document_carries_the_policy_section_and_validates(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    result = runner.invoke(
        cli,
        [
            "policy",
            "sample",
            "legacy",
            "--count",
            "2",
            "--max-bytes",
            "30",
            "--output",
            "json",
            "--config",
            str(write_config(POLICIES)),
        ],
    )

    assert result.exit_code == ExitCode.SUCCESS
    document = json.loads(result.output)
    Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))).validate(document)

    assert document["command"] == "policy.sample"
    section = document["policy"]
    assert section["name"] == "legacy"
    assert section["length"] == 30
    assert section["limit"] == {"max_bytes": 30, "encoding": "utf-8"}
    assert len(section["samples"]) == 2
    assert all(one["characters"] == 30 for one in section["samples"])
    assert all(one["compliant"] for one in section["samples"])


def test_no_sample_object_has_anywhere_to_put_a_password(
    runner: CliRunner, write_config: Callable[[str], Path], pin_csprng: None
) -> None:
    """Invariant 2's third exception is text-only, and this is the assertion that
    keeps it that way: the value the command generated does not appear anywhere in
    the document, and the schema gives it no property to appear in."""
    result = runner.invoke(
        cli,
        [
            "policy",
            "sample",
            "simple",
            "--output",
            "json",
            "--config",
            str(write_config(PREDICTABLE)),
        ],
    )

    assert PINNED not in result.output
    schema = json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))
    properties = set(schema["$defs"]["sample"]["properties"])
    assert schema["$defs"]["sample"]["additionalProperties"] is False
    assert not properties & {"value", "password", "secret", "plaintext"}


# ---------------------------------------------------------- which policy ---


def test_no_name_uses_the_files_default_policy(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """`defaults.policy` is the chain the file itself describes (§3); the layers
    above it belong to the precedence resolver (decision #10)."""
    result = sample(runner, write_config(POLICIES), "--count", "1")

    assert result.exit_code == ExitCode.SUCCESS
    assert "policy: app-standard" in result.output


def test_an_undeclared_name_is_refused_and_lists_the_declared_ones(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """The same phrasing a name written *in* the file gets, because it is the same
    resolver -- a second wording for one failure is a second thing to learn."""
    result = runner.invoke(
        cli,
        ["policy", "sample", "app-standrd", "--config", str(write_config(POLICIES))],
        standalone_mode=False,
    )

    assert isinstance(result.exception, ConfigError)
    rendered = str(result.exception)
    assert "no policy named 'app-standrd' is declared" in rendered
    assert "declared policies: app-standard, legacy" in rendered


def test_no_name_and_no_default_is_refused(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    result = runner.invoke(
        cli,
        ["policy", "sample", "--config", str(write_config(PREDICTABLE))],
        standalone_mode=False,
    )

    assert isinstance(result.exception, ConfigError)
    assert "no policy to sample" in str(result.exception)
    assert "defaults.policy" in str(result.exception)


def test_a_dangling_defaults_policy_points_at_the_file(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """A name that came from the file has a line to blame; one typed on the command
    line does not, and gets no location rather than a made-up one."""
    path = write_config("version: 1\ndefaults:\n  policy: nope\npolicies:\n  real: {}\n")

    result = runner.invoke(cli, ["policy", "sample", "--config", str(path)], standalone_mode=False)

    assert isinstance(result.exception, ConfigError)
    assert "defaults.policy" in str(result.exception)


# -------------------------------------------- policies that cannot generate ---


def test_a_policy_with_no_length_is_refused_here(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """A policy declares its own length, and there is no built-in default (see
    `_required_length` in `sopuli/passwords.py`). This is the cheapest moment to
    meet that: a command that says so rather than a rotation that does."""
    path = write_config("version: 1\npolicies:\n  vague:\n    password:\n      charset: alnum\n")

    result = runner.invoke(
        cli, ["policy", "sample", "vague", "--config", str(path)], standalone_mode=False
    )

    assert isinstance(result.exception, ConfigError)
    assert "declares no password length" in str(result.exception)
    # The file is what has to change, so exit 9 rather than 2 (J7).
    assert result.exception.exit_code == ExitCode.CONFIG_INVALID


def test_a_length_the_target_cannot_hold_is_refused(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """The `--max-bytes` preview earning its place: this is the answer a DBA wants
    before pointing a 128-character policy at an 11.2 database."""
    result = runner.invoke(
        cli,
        [
            "policy",
            "sample",
            "legacy",
            "--max-bytes",
            "20",
            "--config",
            str(write_config(POLICIES)),
        ],
        standalone_mode=False,
    )

    assert isinstance(result.exception, ConfigError)
    assert "needs at least 30 bytes" in str(result.exception)
    assert "limit is 20" in str(result.exception)


# ------------------------------------------------------------------ bounds ---


@pytest.mark.parametrize("count", ["0", "101", "-1"])
def test_the_count_is_bounded(
    runner: CliRunner, write_config: Callable[[str], Path], count: str
) -> None:
    """Zero samples answers nothing, and a million is a way to fill a terminal."""
    result = sample(runner, write_config(POLICIES), "app-standard", "--count", count)

    assert result.exit_code == ExitCode.USAGE

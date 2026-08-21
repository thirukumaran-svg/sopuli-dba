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
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import click
import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

from sopuli import invocation
from sopuli.cli import cli
from sopuli.config import ArgumentError, ConfigError
from sopuli.exit_codes import ExitCode
from sopuli.invocation import GLOBAL_PARAMS, INVOCATION_PARAM
from sopuli.output.document import SCHEMA_VERSION

#: The same alias `tests/conftest.py` gives the fixture, spelled locally rather
#: than imported: the suite has no package for a relative import to reach.
WriteConfig = Callable[[str], Path]

SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def show(config_file: Path) -> list[str]:
    return ["config", "show", "--config", str(config_file)]


@pytest.fixture(autouse=True)
def _no_ambient_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nobody's own ``SOPULI_OUTPUT`` decides the result of these tests."""
    for variable in ("SOPULI_OUTPUT", "SOPULI_DRY_RUN", "SOPULI_PROFILE"):
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


def test_the_token_file_flag_takes_both_positions_and_the_verb_wins() -> None:
    """``--vault-token-file`` is not a setting, and still follows the same rule.

    §3a's token chain *is* its merge -- a config-written ``token:``, then this
    flag, then the variables, then ``~/.vault-token`` -- so registering half of
    it in ``sopuli/settings/`` would leave the tool with two resolvers for one
    question (#145). What it shares with every other inert global option is that
    both click parsers accept it and the more specific position wins.
    """
    group = invocation.GlobalOptions(vault_token_file=Path("group.token"))
    verb = invocation.GlobalOptions(vault_token_file=Path("verb.token"))

    assert invocation.resolve_invocation(group, verb, env={}).vault_token_file == Path("verb.token")
    assert invocation.resolve_invocation(
        group, invocation.GlobalOptions(), env={}
    ).vault_token_file == Path("group.token")
    assert (
        invocation.resolve_invocation(
            invocation.GlobalOptions(), invocation.GlobalOptions(), env={}
        ).vault_token_file
        is None
    )


def test_the_token_file_flag_is_not_a_reported_setting(
    runner: CliRunner, config_file: Path, tmp_path: Path
) -> None:
    """And therefore does not appear in ``invocation.options``.

    Reporting it there would claim the resolver settled it, which is the lie
    ``_wired`` exists to prevent for the other direction: the chain that settles
    it runs when a store is reached, not here.
    """
    result = runner.invoke(
        cli,
        [
            "config",
            "show",
            "--config",
            str(config_file),
            "--output",
            "json",
            "--vault-token-file",
            str(tmp_path / "token"),
        ],
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert "vault_token_file" not in json.dumps(options(result))


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


VAULT_CONFIG = """
version: 1
vaults:
  vault-dev:
    type: hashicorp
    addr: https://declared.example.com
defaults:
  vault: vault-dev
"""


@pytest.fixture
def vault_config(write_config: WriteConfig) -> list[str]:
    """`config show` over a file with one store, defaulted to."""
    return ["config", "show", "--config", str(write_config(VAULT_CONFIG))]


def test_a_named_vault_variable_reaches_the_store(
    runner: CliRunner, vault_config: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """§6's `__` addressing, end to end (#154). The merge itself is asserted in
    `tests/config/test_vault_env.py`; what this adds is that a real command reads
    a real environment and gets there."""
    monkeypatch.setenv("SOPULI_VAULT__VAULT_DEV__ADDR", "https://named.example.com")
    result = runner.invoke(cli, vault_config)

    assert result.exit_code == ExitCode.SUCCESS
    assert "https://named.example.com" in result.output
    assert "https://declared.example.com" not in result.output


def test_the_default_store_name_is_reported_with_its_layer(
    runner: CliRunner, vault_config: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`SOPULI_VAULT` is a setting of the *run* -- which store it defaults to --
    so unlike a store's own settings it appears in `invocation.options`."""
    monkeypatch.setenv("SOPULI_VAULT", "vault-dev")
    result = runner.invoke(cli, [*vault_config, "--output", "json"])

    assert options(result)["vault"] == {
        "value": "vault-dev",
        "source": "env",
        "source_detail": "SOPULI_VAULT",
    }


def test_a_third_party_variable_reaches_the_default_store(
    runner: CliRunner, vault_config: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """P3's first exception: `VAULT_ADDR` is honoured, one layer below
    `SOPULI_VAULT_ADDR` and still above everything the file can write."""
    monkeypatch.setenv("VAULT_ADDR", "https://third-party.example.com")
    result = runner.invoke(cli, vault_config)

    assert result.exit_code == ExitCode.SUCCESS
    assert "https://third-party.example.com" in result.output


def test_a_sopuli_variable_outranks_the_third_party_one(
    runner: CliRunner, vault_config: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VAULT_ADDR", "https://third-party.example.com")
    monkeypatch.setenv("SOPULI_VAULT_ADDR", "https://active.example.com")
    result = runner.invoke(cli, vault_config)

    assert result.exit_code == ExitCode.SUCCESS
    assert "https://active.example.com" in result.output


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


def test_a_profile_block_no_command_consults_yet_still_loads(
    runner: CliRunner, write_config: Any
) -> None:
    """The other direction from the test above, and the one that was missing.

    `profiles.*.db` is parsed, validated and schema-checked, and no command
    reads it yet -- so `sopuli/settings/sources.py` must not emit it. #176 made
    it emit, and the guard above did exactly what it exists to do: a previously
    valid config died with a raw `ValueError` and exit 1 on every command.

    Nothing caught it, because every fixture config in the suite happened to
    have no `db:` block. So this is not a test of the guard -- that one is
    above -- but of the far more ordinary thing the guard can break: a key the
    file is allowed to contain.
    """
    # `write_config` rather than a hand-written file: it sets 0600, which P4's
    # permission check requires on POSIX. Writing it by hand passed on Windows
    # and failed on every Linux runner -- which is what the OS matrix is for.
    config = write_config(
        "version: 1\n"
        "vaults:\n"
        "  vault-dev:\n"
        "    type: hashicorp\n"
        "    addr: https://vault.example.com:8200\n"
        "profiles:\n"
        "  ci:\n"
        "    db:\n"
        "      connect_timeout_s: 90\n"
        "      query_timeout_s: 600\n"
    )

    result = runner.invoke(cli, ["--profile", "ci", "config", "validate", "--config", str(config)])

    assert result.exit_code == ExitCode.SUCCESS, result.output


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
def test_every_verb_names_a_command_the_schema_allows(path: str, command: click.Command) -> None:
    """The document's `command` is derived from the tree, so the tree must fit it.

    `command_path` builds `config.show` out of the contexts rather than each verb
    repeating its own name, which removes a whole class of typo -- and moves the
    risk to a new verb whose path is not in the closed enum. That is this test:
    the verb exists, so its dotted name has to be a value a document may carry.
    """
    del command
    dotted = ".".join(path.split()[1:])
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    assert dotted in schema["properties"]["command"]["enum"], path


@pytest.mark.parametrize(("path", "command"), list(commands()), ids=lambda one: str(one))
def test_every_verb_receives_the_resolved_invocation(path: str, command: click.Command) -> None:
    """Reading a flag off a click parameter is reading a value that skipped the
    resolver. The decorator removes the opportunity; this pins that it is applied."""
    assert command.callback is not None
    # `inspect.signature` follows `__wrapped__` through both decorators, so this
    # is the verb's own signature rather than click's wrapper.
    assert INVOCATION_PARAM in inspect.signature(command.callback).parameters, path


# ------------------------------------------------ profile activation (#153) ---
#
# Layer 3 as a run actually meets it. What a profile *is* is `tests/config/`;
# what the merge rule *does* is `tests/settings/`. This is the seam: that
# `--profile`, `SOPULI_PROFILE` and `defaults.profile` reach the one resolver in
# that order, and that what the chosen profile wrote changes the run.

ESTATE = """\
version: 1
profiles:
  ci:
    output: json
    safety:
      readonly: false
      max_targets: 200
    locking:
      break_expired: true
  scheduled:
    output: json
  laptop:
    output: text
defaults:
  safety:
    readonly: true
    max_targets: 1
  locking:
    break_expired: false
"""


@pytest.fixture
def estate(write_config: WriteConfig) -> Path:
    return write_config(ESTATE)


def document_of(result: Any) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(result.output)
    return parsed


def test_a_run_with_no_profile_says_so_by_omission(runner: CliRunner, estate: Path) -> None:
    """`invocation.profile` is absent rather than null: a key with no name in it
    would read as "a profile was considered and found"."""
    result = runner.invoke(cli, ["config", "show", "--config", str(estate), "--output", "json"])

    assert result.exit_code == ExitCode.SUCCESS
    assert "profile" not in document_of(result)["invocation"]


def test_the_flag_selects_a_profile_and_the_document_names_it(
    runner: CliRunner, estate: Path
) -> None:
    result = runner.invoke(
        cli, ["config", "show", "--config", str(estate), "--profile", "ci", "--output", "json"]
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert document_of(result)["invocation"]["profile"] == "ci"


def test_the_environment_selects_a_profile(
    runner: CliRunner, estate: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§6's usual way a CI job or a scheduler picks one."""
    monkeypatch.setenv("SOPULI_PROFILE", "ci")

    result = runner.invoke(cli, ["config", "show", "--config", str(estate), "--output", "json"])

    assert result.exit_code == ExitCode.SUCCESS
    assert options(result)["profile"]["source"] == "env"
    assert options(result)["profile"]["source_detail"] == "SOPULI_PROFILE"


def test_the_flag_beats_the_environment(
    runner: CliRunner, estate: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOPULI_PROFILE", "scheduled")

    result = runner.invoke(
        cli, ["config", "show", "--config", str(estate), "--profile", "ci", "--output", "json"]
    )

    assert document_of(result)["invocation"]["profile"] == "ci"
    assert options(result)["profile"]["source"] == "cli"


def test_the_environment_beats_defaults_profile(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bottom two rungs of §5's chain, which the two tests above do not reach."""
    path = write_config(ESTATE.replace("defaults:\n", "defaults:\n  profile: scheduled\n"))
    monkeypatch.setenv("SOPULI_PROFILE", "ci")

    result = runner.invoke(cli, ["config", "show", "--config", str(path), "--output", "json"])

    assert document_of(result)["invocation"]["profile"] == "ci"
    assert options(result)["profile"]["source"] == "env"


def test_defaults_profile_answers_when_nothing_else_does(
    runner: CliRunner, write_config: WriteConfig
) -> None:
    path = write_config(ESTATE.replace("defaults:\n", "defaults:\n  profile: scheduled\n"))

    result = runner.invoke(cli, ["config", "show", "--config", str(path), "--output", "json"])

    assert document_of(result)["invocation"]["profile"] == "scheduled"
    assert options(result)["profile"]["source"] == "defaults"


def test_a_profile_that_does_not_exist_is_refused(runner: CliRunner, estate: Path) -> None:
    """§5 rule 6: never a silent fallback. Exit 9, because answering it needs the
    file -- the same code an undeclared `policy sample` name already gets."""
    result = runner.invoke(cli, ["config", "show", "--config", str(estate), "--profile", "nosuch"])

    # Exit 9 through `main`, which is what maps a `ConfigError` to a code; the
    # runner re-raises instead, so the code is asserted on the error itself.
    assert isinstance(result.exception, ConfigError)
    assert result.exception.exit_code == ExitCode.CONFIG_INVALID
    message = str(result.exception)
    assert "no profile named 'nosuch' is declared" in message
    assert "declared profiles: ci, laptop, scheduled" in message


def test_a_profile_supplies_output_and_the_run_emits_it(runner: CliRunner, estate: Path) -> None:
    """The reason the file is read before the verb runs: a profile's `output:`
    has to reach the emitter, and by the time a verb starts it is too late."""
    result = runner.invoke(cli, ["config", "show", "--config", str(estate), "--profile", "ci"])

    assert result.exit_code == ExitCode.SUCCESS
    assert options(result)["output"] == {
        "value": "json",
        "source": "profile",
        "source_detail": "profiles.ci.output",
    }


def test_a_flag_still_beats_the_profile_that_supplied_it(runner: CliRunner, estate: Path) -> None:
    """§9's own example, one layer down: the operator at the keyboard is the more
    specific intent, so `--output text` wins over `profiles.ci.output: json`."""
    result = runner.invoke(
        cli,
        ["config", "show", "--config", str(estate), "--profile", "ci", "--output", "text"],
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert not result.output.startswith("{")


def test_a_profile_cannot_relax_the_safety_block(runner: CliRunner, estate: Path) -> None:
    """Invariant 10 against the layer most likely to try it -- and the `defaults:`
    values are the ones that hold, in both of the ratchet's shapes."""
    result = runner.invoke(
        cli,
        ["config", "show", "--config", str(estate), "--profile", "ci", "--output", "json"],
    )

    reported = options(result)
    assert reported["safety.readonly"]["value"] is True
    assert reported["safety.readonly"]["source"] == "defaults"
    assert reported["safety.max_targets"]["value"] == 1
    assert reported["safety.max_targets"]["source"] == "defaults"


def test_break_expired_ratchets_the_other_way_round(runner: CliRunner, estate: Path) -> None:
    """The one ratcheted boolean whose safe value is `false` (#83): a profile
    asking for permission to break an expired lock is the defeated request, which
    is the opposite polarity to `readonly` one test up."""
    result = runner.invoke(
        cli,
        ["config", "show", "--config", str(estate), "--profile", "ci", "--output", "json"],
    )

    reported = options(result)
    assert reported["locking.break_expired"]["value"] is False
    assert reported["locking.break_expired"]["source"] == "defaults"


def test_every_defeated_request_is_reported_as_a_diagnostic(
    runner: CliRunner, estate: Path
) -> None:
    """A ratchet that holds silently is a surprise, which is what P3's `--explain`
    example is about -- and this reaches JSON on every run, not only under it."""
    result = runner.invoke(
        cli, ["config", "show", "--config", str(estate), "--profile", "ci", "--output", "json"]
    )

    messages = [one["message"] for one in document_of(result)["diagnostics"]]
    assert any("profiles.ci.safety.readonly asked for false" in one for one in messages)
    assert any("profiles.ci.safety.max_targets asked for 200" in one for one in messages)
    assert any("profiles.ci.locking.break_expired asked for true" in one for one in messages)


def test_explain_attributes_a_profile_supplied_value_to_layer_three(
    runner: CliRunner, estate: Path
) -> None:
    """P3's "making precedence debuggable", for the layer that until now could not
    produce a single row in that table."""
    result = runner.invoke(
        cli, ["config", "show", "--config", str(estate), "--profile", "laptop", "--explain"]
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert "[profiles.laptop.output]" in result.output
    # The key path rather than "[profile laptop]", which is how P3's sketch drew
    # it: `defaults.safety.readonly` already renders the same way, and naming the
    # key is what sends somebody to the line they have to edit (#53).
    assert "output" in result.output


def test_a_profile_key_with_no_consumer_reaches_no_setting(
    runner: CliRunner, write_config: WriteConfig
) -> None:
    """§5's list is longer than the registry's, deliberately. `verify.method` is
    parsed and validated and reaches nothing, because nothing verifies yet -- and
    a row in `invocation.options` for it would claim otherwise."""
    path = write_config("version: 1\nprofiles:\n  ci:\n    verify:\n      method: hash\n")

    result = runner.invoke(
        cli, ["config", "show", "--config", str(path), "--profile", "ci", "--output", "json"]
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert document_of(result)["invocation"]["profile"] == "ci"
    assert "verify.method" not in options(result)


def test_the_run_document_still_validates_with_a_profile(runner: CliRunner, estate: Path) -> None:
    validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
    result = runner.invoke(
        cli, ["config", "show", "--config", str(estate), "--profile", "ci", "--output", "json"]
    )

    assert list(validator.iter_errors(document_of(result))) == []


def test_an_output_format_this_build_lacks_is_refused_from_a_profile(
    runner: CliRunner, write_config: WriteConfig
) -> None:
    """`jsonl` is in §6's table and not implemented (#9), and a profile may write
    it -- so the refusal has to survive arriving from layer 3.

    Exit 2, like the same value from `SOPULI_OUTPUT`: what failed is not the file
    but the run's ability to say anything about itself, and a document is exactly
    what cannot be produced. The message still names the key.

    The regression this guards is the *second* exception. A profile-supplied
    value is refused inside the exit handler, which asks the invocation whether
    the run is JSON before deciding whether to emit a document -- and reading
    that through `OutputMode` raised `ValueError`, replacing a clean exit 2 with
    a traceback about an enum on exit 1.
    """
    path = write_config("version: 1\nprofiles:\n  ci:\n    output: jsonl\n")

    result = runner.invoke(cli, ["config", "show", "--config", str(path), "--profile", "ci"])

    assert isinstance(result.exception, ArgumentError)
    assert result.exception.exit_code == ExitCode.USAGE
    message = str(result.exception)
    assert "profiles.ci.output" in message
    assert "'jsonl' is not an output format" in message


def test_the_refusal_leaves_stdout_byte_empty(runner: CliRunner, write_config: WriteConfig) -> None:
    """J7's other half: exit 2 carries no run document, whichever layer wrote the
    format the tool could not read."""
    path = write_config("version: 1\nprofiles:\n  ci:\n    output: jsonl\n")

    result = runner.invoke(
        cli,
        ["config", "show", "--config", str(path), "--profile", "ci"],
        catch_exceptions=True,
    )

    assert result.stdout == ""

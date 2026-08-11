"""The ``sopuli`` command line.

Grammar is noun-verb (D2): ``sopuli <noun> <verb>``. Each noun is a
:class:`click.Group`, each verb a command inside it. Only ``config show`` exists
so far — it does no work, and is here so the shape is established once instead
of being improvised by whichever command lands first.

Two things about the structure are deliberate:

**Global options are a shared decorator, not group options.** A click option
declared on the group has to appear *before* the subcommand
(``sopuli --output json config show``), and DBAs type flags at the end of the
line. :func:`common_options` puts ``--output`` and ``--dry-run`` on every verb
so both orders work. Applying it is one line per command; retrofitting it across
twenty verbs would not be.

**Secrets never become options (invariant 1).** No command may take a password
as a command-line value — it is visible in ``ps`` and in the Windows process
list. Passwords arrive from stdin, a file, or a vault reference.
``tests/test_cli_smoke.py`` walks the command tree and fails if an option name
ever looks like a credential.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, TypeVar

import click

from sopuli.config import Config, ConfigError, discover, load_config_from
from sopuli.exit_codes import ExitCode
from sopuli.output.color import ColorChoice
from sopuli.output.document import RunDocument, Summary
from sopuli.output.emit import Emitter, OutputMode
from sopuli.output.stream import configure_streams
from sopuli.version import get_version

F = TypeVar("F", bound=Callable[..., Any])

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


def common_options(func: F) -> F:
    """Attach the options every verb accepts.

    ``--dry-run`` is here from the start because invariant 8 requires every
    mutating command to support it. Nothing mutates yet, so it only reaches the
    run document — but no future command has to remember to add the flag.

    ``--color`` is an *override*, not a ratchet: the command line simply wins
    over the environment (P3). ``--dry-run`` will need the opposite treatment
    when option precedence lands (#10), because invariant 10 says a safety
    setting may only move toward safe. The two are listed together here so that
    the difference is visible rather than assumed.
    """
    config = click.option(
        "--config",
        "config_paths",
        multiple=True,
        type=click.Path(path_type=Path),
        help="Config file. Repeat to layer files left to right.",
    )
    dry_run = click.option(
        "--dry-run",
        is_flag=True,
        default=False,
        help="Print the plan and make no changes.",
    )
    output = click.option(
        "--output",
        "output_mode",
        type=click.Choice([m.value for m in OutputMode]),
        default=OutputMode.TEXT.value,
        show_default=True,
        help="Output format. Scripts should consume json, never text.",
    )
    color = click.option(
        "--color",
        "color_choice",
        type=click.Choice([c.value for c in ColorChoice]),
        default=ColorChoice.AUTO.value,
        show_default=True,
        help="Colour in text output. auto follows the terminal; NO_COLOR disables it.",
    )
    return color(output(dry_run(config(func))))


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version=get_version(), prog_name="sopuli")
def cli() -> None:
    """Manage database account credentials with a vault as the master record."""


@cli.group("config")
def config_group() -> None:
    """Inspect and validate configuration."""


@config_group.command("show")
@common_options
def config_show(
    config_paths: tuple[Path, ...], output_mode: str, dry_run: bool, color_choice: str
) -> None:
    """Show the effective configuration.

    Offline in the strongest sense: it finds the file, validates it, and expands
    the estate, without opening a socket to a vault or a database. What it
    prints so far is a summary -- which files were read and what they declare.
    Rendering the sections themselves is the next change.

    A bad config file raises out of here rather than being caught and reported
    as a run: the boundary in :func:`main` already maps it to exit 2, and
    whether ``--output json`` should emit a run document for a usage error is
    an open question (J7, issue #8) that this command must not answer by
    accident.
    """
    emitter = Emitter(
        mode=OutputMode(output_mode),
        color_choice=ColorChoice(color_choice),
    )
    document = RunDocument.start("config.show", dry_run=dry_run)

    paths = discover(config_paths)
    config = load_config_from(paths)

    targets = len(config.expanded_targets)
    document.finish(
        ExitCode.SUCCESS,
        Summary(total=targets, ok=targets, changed=0, failed=0),
    )
    emitter.emit(document, describe_config(paths, config))


def describe_config(paths: Sequence[Path], config: Config) -> str:
    """The text summary: where the config came from, and what it declares.

    The tool's own prose stays ASCII by convention, even though the streams are
    UTF-8 now (``sopuli.output.stream``): decoration should be opt-in and
    deliberate, not an em dash that arrived in a docstring by accident. Anything
    a user supplies -- a target name, a warning's key path -- passes through
    unchanged.
    """
    lines = [f"config: {paths[0]}"]
    lines.extend(f"        {path} (layered)" for path in paths[1:])
    lines.append("")
    lines.extend(_estate_summary(config))
    lines.extend(_warning_summary(config))
    lines.append("")
    lines.append("This is a summary; the sections themselves are not rendered yet.")
    return "\n".join(lines)


def _estate_summary(config: Config) -> list[str]:
    """What the file declares, counted.

    The generated count is worth a line of its own because it is the number
    nobody can work out by reading: `01-configuration.md` §4 says generation is
    invisible until it goes wrong, and one target set is 35 targets or 34.
    """
    generated = sum(1 for target in config.expanded_targets if target.target_set is not None)
    explicit = len(config.expanded_targets) - generated

    targets = _count(len(config.expanded_targets), "target")
    if config.target_sets:
        sets = _count(len(config.target_sets), "target set")
        targets = f"{targets} ({explicit} explicit, {generated} from {sets})"

    declared = [
        _count(len(config.vaults), "vault"),
        _count(len(config.groups), "group"),
        _count(len(config.policies), "policy", "policies"),
        _count(len(config.profiles), "profile"),
        _count(len(config.applications), "application"),
    ]
    return [targets, ", ".join(declared)]


def _warning_summary(config: Config) -> list[str]:
    """§10's warnings, in full.

    A count alone would be worse than nothing: these are the findings the config
    layer decided were not worth refusing to run over, which makes this the only
    place anybody will read them.
    """
    if not config.warnings:
        return []
    return ["", f"{_count(len(config.warnings), 'warning')}:", *_indent(config.warnings)]


def _indent(warnings: Sequence[Any]) -> list[str]:
    return [f"  {line}" for warning in warnings for line in str(warning).splitlines()]


def _count(number: int, noun: str, plural: str | None = None) -> str:
    if number == 1:
        return f"1 {noun}"
    return f"{number} {plural if plural is not None else noun + 's'}"


def main() -> None:
    """Console-script entry point.

    click handles usage errors itself and exits 2, which is what the exit code
    table already specifies, so that path is left alone. This wrapper exists for
    the other one: an unexpected exception should reach the user as a message
    and exit 1, never as a traceback.

    Stream encoding is settled here rather than inside a command because it is a
    property of the process, not of any one verb: by the time a command runs,
    click may already have written a usage error to a cp1252 stderr. Tests that
    drive commands through ``CliRunner`` bypass this deliberately -- their
    streams are UTF-8 already, and ``tests/test_stream_encoding.py`` exercises
    the real thing through a real pipe.
    """
    configure_streams()
    try:
        cli.main(standalone_mode=True)
    except SystemExit:
        raise
    except ConfigError as exc:
        # A bad config file is a usage error, not a failure (P5): it exits 2
        # alongside "you typed the command wrong", so a scheduler can tell
        # "fix your file" from "something broke". The error already knows its
        # own location and hint -- printing it is all that is left to do.
        click.echo(f"sopuli: {exc}", err=True)
        raise SystemExit(exc.exit_code) from exc
    except Exception as exc:  # noqa: BLE001 - deliberate catch-all at the boundary
        # TODO(#4 follow-up): map driver and vault errors to their categories
        # here, carrying the vendor code and a hint (see CLAUDE.md, Style).
        click.echo(f"sopuli: {type(exc).__name__}: {exc}", err=True)
        raise SystemExit(ExitCode.FAILURE) from exc


if __name__ == "__main__":  # pragma: no cover
    main()

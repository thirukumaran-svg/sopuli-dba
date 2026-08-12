"""The ``sopuli`` command line.

Grammar is noun-verb (D2): ``sopuli <noun> <verb>``. Each noun is a
:class:`click.Group`, each verb a command inside it. Only the ``config`` verbs
and ``target list`` exist so far — none touches a vault or a database, and they
are here so the shape is established once instead of being improvised by
whichever command lands first.

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

from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

import click

from sopuli.config import (
    AT_SELECT,
    Config,
    ConfigError,
    as_dict,
    discover,
    filter_estate,
    load_layers,
    parse_selector,
)
from sopuli.exit_codes import ExitCode
from sopuli.output.color import ColorChoice
from sopuli.output.config_view import (
    build_section,
    render_target_list,
    render_text,
    render_validation,
)
from sopuli.output.document import Diagnostic, RunDocument, Summary
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


def select_option(func: F) -> F:
    """``--select``, for the commands that act on the estate.

    Deliberately not in :func:`common_options`. ``config validate`` answers
    "does this file parse", which no selector narrows, and an option that
    silently means nothing on some of the commands carrying it is the same
    defect as ignoring one that does.
    """
    return click.option(
        "--select",
        "selectors",
        multiple=True,
        metavar="K=V[,K=V]",
        help="Keep only targets carrying every label. Repeat to add more.",
    )(func)


def config_diagnostics(config: Config) -> list[Diagnostic]:
    """§10's warnings, as run-level diagnostics.

    Run-level rather than per-target because a config warning is not
    attributable to one target. Both config verbs report warnings the same way,
    in both views -- in full in the text, and here for the schedulers and CI
    jobs that read the document and never see the text at all.
    """
    return [Diagnostic(level="warning", message=str(warning)) for warning in config.warnings]


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version=get_version(), prog_name="sopuli")
def cli() -> None:
    """Manage database account credentials with a vault as the master record."""


@cli.group("config")
def config_group() -> None:
    """Inspect and validate configuration."""


@config_group.command("show")
@click.option(
    "--resolved",
    is_flag=True,
    default=False,
    help="Show what the tool would act on: expanded targets and their bindings.",
)
@select_option
@common_options
def config_show(
    resolved: bool,
    selectors: tuple[str, ...],
    config_paths: tuple[Path, ...],
    output_mode: str,
    dry_run: bool,
    color_choice: str,
) -> None:
    """Show the effective configuration.

    Two views of one file. Without ``--resolved`` it shows the configuration as
    loaded, which answers *did my YAML say what I think it says* after however
    many ``--config`` layers were merged. With it, target sets are expanded and
    every secret ref rendered per account, which answers *what will this act on*.

    Offline in the strongest sense: it opens no socket to a vault or a database,
    so it is safe to run against a production config from a laptop. A secret ref
    is an address and never a value.

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

    match = parse_selector(selectors)
    if match and not resolved:
        # Silently ignoring a filter is the failure P3 refuses for unknown keys,
        # for the same reason: the run looks like it did what was asked. There is
        # nothing to filter in the declared view -- it shows the file, and the
        # estate `--select` narrows does not exist until `--resolved` builds it.
        raise ConfigError(
            "--select has nothing to filter without --resolved",
            at=AT_SELECT,
            hint="the declared view shows the file; the estate it selects over is --resolved",
        )

    paths = discover(config_paths)
    declared, config = load_layers(paths)
    config = filter_estate(config, match)

    targets = len(config.expanded_targets)
    document.diagnostics = config_diagnostics(config)
    document.selection = as_dict(match) or None
    document.config = build_section(paths, config, declared, resolved=resolved)
    document.finish(
        ExitCode.SUCCESS,
        Summary(total=targets, ok=targets, changed=0, failed=0),
    )
    emitter.emit(document, render_text(paths, config, resolved=resolved, match=match))


@cli.group("target")
def target_group() -> None:
    """Inspect the estate."""


@target_group.command("list")
@select_option
@common_options
def target_list(
    selectors: tuple[str, ...],
    config_paths: tuple[Path, ...],
    output_mode: str,
    dry_run: bool,
    color_choice: str,
) -> None:
    """List the targets the configuration expands to.

    ``01-configuration.md`` section 4 makes this a command rather than a flag:
    "generation is invisible until it goes wrong", and the moment it matters is
    before a rotation, when the question is *how many databases is this about
    to touch* and the answer must not require reading a binding table to count.

    Always the expanded estate, so there is no ``--resolved`` here. A target
    set is a template; the targets it generates are the only thing this command
    is about, which is why ``config show`` keeps the other view rather than
    this one growing a flag to suppress its own subject.

    Offline, like the ``config`` verbs: nothing here opens a socket, so it is
    safe against a production config from a laptop. It says which targets
    *exist*, never which are reachable -- that is a different command with a
    different failure mode, and it must not arrive as a flag on this one.

    A bad config file raises out of here rather than being caught, for the
    reason ``config show`` gives: J7 (issue #8) is open, and no command should
    answer it by accident.
    """
    emitter = Emitter(
        mode=OutputMode(output_mode),
        color_choice=ColorChoice(color_choice),
    )
    document = RunDocument.start("target.list", dry_run=dry_run)

    match = parse_selector(selectors)
    paths = discover(config_paths)
    declared, config = load_layers(paths)
    config = filter_estate(config, match)

    targets = len(config.expanded_targets)
    document.diagnostics = config_diagnostics(config)
    document.selection = as_dict(match) or None
    # The same `config` section `config show --resolved` emits, deliberately.
    # It is one estate, and a second JSON shape for it would be two answers to
    # one question -- exactly what invariant 12 exists to prevent. The cost is
    # that `bindings` rides along where the text view has no column for it,
    # which is the cheaper of the two mistakes.
    document.config = build_section(paths, config, declared, resolved=True)
    document.finish(
        ExitCode.SUCCESS,
        Summary(total=targets, ok=targets, changed=0, failed=0),
    )
    emitter.emit(document, render_target_list(paths, config, match=match))


@config_group.command("validate")
@common_options
def config_validate(
    config_paths: tuple[Path, ...],
    output_mode: str,
    dry_run: bool,
    color_choice: str,
) -> None:
    """Check the configuration and say nothing else.

    P3 makes this a first-class command: it "exits non-zero on unknown keys -- a
    typo in a credential tool must never be silently ignored". Everything it does
    is what ``load_layers`` already does; what it adds is a command whose *only*
    job is that, so a file can be checked in CI without asking for output nobody
    reads.

    **Validated by the loader, not by the published schema.** The two are not
    equivalent, and the stricter one wins:
    ``docs/schemas/sopuli-config-1.0.schema.json`` is structural, deliberately
    leaves the cross-key rules out (``01-configuration.md`` section 9b), and
    ``jsonschema`` is a development dependency that must not become a runtime
    one. The schema is the editor's fast local check; this is the complete one.

    Offline, like ``config show``: no vault and no database is contacted, so it
    is safe to point at a production config from a laptop.

    A bad file raises out of here rather than being caught. The boundary in
    :func:`main` maps it to exit 2, and whether ``--output json`` should emit a
    run document for a usage error is an open question (J7, issue #8) that this
    command must not answer by accident -- the same reason ``config show`` gives.
    """
    emitter = Emitter(
        mode=OutputMode(output_mode),
        color_choice=ColorChoice(color_choice),
    )
    document = RunDocument.start("config.validate", dry_run=dry_run)

    paths = discover(config_paths)
    _, config = load_layers(paths)

    document.diagnostics = config_diagnostics(config)
    targets = len(config.expanded_targets)
    document.finish(
        ExitCode.SUCCESS,
        Summary(total=targets, ok=targets, changed=0, failed=0),
    )
    emitter.emit(document, render_validation(paths, config))


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

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

from collections.abc import Callable
from typing import Any, TypeVar

import click

from sopuli.exit_codes import ExitCode
from sopuli.output.document import RunDocument, Summary
from sopuli.output.emit import Emitter, OutputMode
from sopuli.version import get_version

F = TypeVar("F", bound=Callable[..., Any])

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


def common_options(func: F) -> F:
    """Attach the options every verb accepts.

    ``--dry-run`` is here from the start because invariant 8 requires every
    mutating command to support it. Nothing mutates yet, so it only reaches the
    run document — but no future command has to remember to add the flag.
    """
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
    return output(dry_run(func))


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version=get_version(), prog_name="sopuli")
def cli() -> None:
    """Manage database account credentials with a vault as the master record."""


@cli.group("config")
def config_group() -> None:
    """Inspect and validate configuration."""


@config_group.command("show")
@common_options
def config_show(output_mode: str, dry_run: bool) -> None:
    """Show the effective configuration.

    Placeholder: there is no configuration loader yet (01-configuration.md).
    It reports an empty run so that the routing, the exit code and both output
    modes are exercised end to end.
    """
    emitter = Emitter(mode=OutputMode(output_mode))
    document = RunDocument.start("config.show", dry_run=dry_run)
    document.finish(ExitCode.SUCCESS, Summary(total=0, ok=0, changed=0, failed=0))

    # Human output stays ASCII until the stream encoding is fixed. On Windows,
    # redirected stdout (`sopuli ... > run.log`, or any pipe) uses cp1252 rather
    # than UTF-8 -- an attached console is fine, this is a redirection problem.
    # Characters inside cp1252 survive as bytes a UTF-8 reader shows as mojibake;
    # characters outside it raise UnicodeEncodeError and kill the command.
    # click.echo does not protect against either. P4 requires the same behaviour
    # everywhere, so ASCII is the safe floor. The real fix is reconfiguring
    # stdout to UTF-8, which the text output contract needs anyway.
    # JSON is unaffected: json.dumps escapes non-ASCII by default.
    text = (
        "No configuration loaded.\n"
        "Config file discovery is not implemented yet - see "
        "docs/design/01-configuration.md."
    )
    emitter.emit(document, text)


def main() -> None:
    """Console-script entry point.

    click handles usage errors itself and exits 2, which is what the exit code
    table already specifies, so that path is left alone. This wrapper exists for
    the other one: an unexpected exception should reach the user as a message
    and exit 1, never as a traceback.
    """
    try:
        cli.main(standalone_mode=True)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - deliberate catch-all at the boundary
        # TODO(#4 follow-up): map driver and vault errors to their categories
        # here, carrying the vendor code and a hint (see CLAUDE.md, Style).
        click.echo(f"sopuli: {type(exc).__name__}: {exc}", err=True)
        raise SystemExit(ExitCode.FAILURE) from exc


if __name__ == "__main__":  # pragma: no cover
    main()

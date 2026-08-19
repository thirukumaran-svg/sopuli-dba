"""The ``sopuli`` command line.

Grammar is noun-verb (D2): ``sopuli <noun> <verb>``. Each noun is a
:class:`click.Group`, each verb a command inside it. The ``config`` verbs,
``target list`` and ``policy sample`` touch nothing outside the file; ``lock
status`` is the first verb that opens a socket, and the seam between the two is
worth keeping visible rather than letting it blur one command at a time.

Three things about the structure are deliberate:

**Global options are declared in both parser positions, and resolved in one.**
click's group parser and verb parser never see each other's options, so
``--output`` is attached to the group *and* to every verb; both are layer 1 and
:mod:`sopuli.invocation` merges them through the one precedence resolver. The
safety flags are the exception -- ``--dry-run`` is accepted after the subcommand
only, and the group's copy is a trap that says so. A verb receives the resolved
:class:`~sopuli.invocation.Invocation` rather than the raw flags, so no command
can read a value that skipped the layers beneath it.

**Secrets never become options (invariant 1).** No command may take a password
as a command-line value — it is visible in ``ps`` and in the Windows process
list. Passwords arrive from stdin, a file, or a vault reference.
``tests/test_cli_smoke.py`` walks the command tree and fails if an option name
ever looks like a credential.

**One command prints a password on purpose.** ``policy sample --reveal`` is
invariant 2's third exception, because a sample is not a credential: nothing
authenticates with it and it is never stored. What keeps that narrow lives in
:mod:`sopuli.output.policy_view`; what lives here is the refusal to combine it
with ``--output json``.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TypeVar

import click

from sopuli.config import (
    ROOT,
    Config,
    ConfigError,
    PasswordPolicy,
    as_dict,
    dangling,
    discover,
    filter_estate,
    load_layers,
    parse_selector,
)
from sopuli.diagnostics import backend_diagnostics
from sopuli.exit_codes import ExitCode
from sopuli.invocation import (
    GlobalOptions,
    Invocation,
    all_options,
    global_options,
    group_options,
)
from sopuli.lock.errors import LockDeniedError, LockError
from sopuli.lock.inspect import declared_locks, mode_of, survey
from sopuli.output.config_view import (
    build_section,
    render_target_list,
    render_text,
    render_validation,
)
from sopuli.output.document import Diagnostic, Summary
from sopuli.output.lock_view import build_status_section, render_status
from sopuli.output.policy_view import build_section as build_policy_section
from sopuli.output.policy_view import describe_all, render_samples
from sopuli.output.stream import configure_streams
from sopuli.passwords import ByteLimit, generate
from sopuli.store import SecretStore, connect
from sopuli.version import get_version

F = TypeVar("F", bound=Callable[..., Any])

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


def select_option(func: F) -> F:
    """``--select``, for the commands that act on the estate.

    Deliberately not in :func:`~sopuli.invocation.global_options`. ``config validate`` answers
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
    return [
        Diagnostic(level="warning", message=str(warning), code=warning.code)
        for warning in config.warnings
    ]


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version=get_version(), prog_name="sopuli")
@group_options
@click.pass_context
def cli(
    ctx: click.Context,
    config_paths: tuple[Path, ...],
    output_mode: str | None,
    color_choice: str | None,
) -> None:
    """Manage database account credentials with a vault as the master record."""
    # The group's copies of the global options are hidden and do nothing on their
    # own: they are stashed here for the verb, which resolves both positions
    # together (`sopuli.invocation`). A safety flag never arrives -- the group's
    # copy of it refuses before this runs. The explanation lives in a comment
    # rather than the docstring because the docstring is `sopuli --help`, and
    # naming a trap there would advertise a flag the help says you may not use.
    ctx.obj = GlobalOptions(
        config_paths=config_paths,
        output_mode=output_mode,
        color_choice=color_choice,
    )


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
@click.option(
    "--explain",
    is_flag=True,
    default=False,
    help="Show every effective setting and the layer it came from.",
)
@select_option
@global_options
def config_show(
    resolved: bool,
    explain: bool,
    selectors: tuple[str, ...],
    run: Invocation,
) -> str:
    """Show the effective configuration.

    Two views of one file. Without ``--resolved`` it shows the configuration as
    loaded, which answers *did my YAML say what I think it says* after however
    many ``--config`` layers were merged. With it, target sets are expanded and
    every secret ref rendered per account, which answers *what will this act on*.

    ``--explain`` answers a third question -- *where did each setting come from*
    -- and answers it the same way in both views, because provenance does not
    depend on target expansion. That is why it does not require ``--resolved``
    the way ``--select`` does: a selector has nothing to filter until the estate
    exists, and a setting has a source either way (P3, issue #53).

    Offline in the strongest sense: it opens no socket to a vault or a database,
    so it is safe to run against a production config from a laptop. A secret ref
    is an address and never a value.

    A bad config file raises out of here rather than being caught: the boundary
    in :func:`main` maps it to exit 9, which J7 (issue #8) settled as the code
    that *does* carry a run document -- the invocation resolved, and it is the
    file that turned out to be unusable. Emitting that document is the exit
    handler's job rather than this command's, so there is one place it happens
    instead of one per verb.
    """
    document = run.document

    match = parse_selector(selectors)
    if match and not resolved:
        # Silently ignoring a filter is the failure P3 refuses for unknown keys,
        # for the same reason: the run looks like it did what was asked. There is
        # nothing to filter in the declared view -- it shows the file, and the
        # estate `--select` narrows does not exist until `--resolved` builds it.
        #
        # A UsageError rather than a ConfigError, because nothing is wrong with
        # the configuration: two options that each parsed do not form a valid
        # request. That puts it on exit 2 with no document, which is J7's rule --
        # and keeps exit 9 meaning "your file is wrong" for a consumer that
        # branches on it (#8).
        raise click.UsageError(
            "--select has nothing to filter without --resolved\n"
            "       the declared view shows the file; the estate it selects over "
            "is --resolved"
        )

    paths = discover(run.config_paths)
    declared, config = load_layers(paths)
    config = filter_estate(config, match)

    targets = len(config.expanded_targets)
    document.diagnostics.extend(config_diagnostics(config))
    document.selection = as_dict(match) or None
    document.config = build_section(paths, config, declared, resolved=resolved)
    if explain:
        # The same data the JSON document already carries, widened: `--explain`
        # means "show everything you consulted", built-in defaults included.
        document.options = all_options(run)
    document.finish(
        ExitCode.SUCCESS,
        Summary(total=targets, ok=targets, changed=0, failed=0),
    )
    return render_text(
        paths, config, resolved=resolved, match=match, settings=run.resolved if explain else {}
    )


@cli.group("target")
def target_group() -> None:
    """Inspect the estate."""


@target_group.command("list")
@select_option
@global_options
def target_list(
    selectors: tuple[str, ...],
    run: Invocation,
) -> str:
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
    reason ``config show`` gives: exit 9 carries a document, and the boundary
    emits it (J7, issue #8).
    """
    document = run.document

    match = parse_selector(selectors)
    paths = discover(run.config_paths)
    declared, config = load_layers(paths)
    config = filter_estate(config, match)

    targets = len(config.expanded_targets)
    document.diagnostics.extend(config_diagnostics(config))
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
    return render_target_list(paths, config, match=match)


@cli.group("policy")
def policy_group() -> None:
    """Inspect password policies."""


@policy_group.command("sample")
@click.argument("name", required=False)
@click.option(
    "--count",
    type=click.IntRange(1, 100),
    default=3,
    show_default=True,
    help="How many samples to draw.",
)
@click.option(
    "--max-bytes",
    type=click.IntRange(1, 4096),
    help="Preview a target's byte limit (30 below 12.2, 128 from 12.2).",
)
@click.option(
    "--encoding",
    default="utf-8",
    show_default=True,
    help="The character set the byte limit is counted in.",
)
@click.option(
    "--reveal",
    is_flag=True,
    default=False,
    help="Print the sampled passwords. Text output only; they are never stored.",
)
@global_options
def policy_sample(
    name: str | None,
    count: int,
    max_bytes: int | None,
    encoding: str,
    reveal: bool,
    run: Invocation,
) -> str:
    """Show what a password policy produces, without touching anything.

    A policy is a handful of numbers and a charset name, and none of that answers
    the question somebody actually has: *what do the passwords look like*. This
    draws samples so they can answer it -- whether a `custom` charset renders what
    was meant, whether 24 characters fit a 30-byte target, whether the shape
    survives a `.env` file.

    Offline, and further than the other verbs: it opens no socket *and* writes
    nothing. Nothing generated here is stored, in a vault or anywhere else. With
    `--max-bytes` and `--encoding` it previews what a target would accept without
    connecting to one; reading the real limit needs a driver (P1) and will arrive
    as `--target`.

    `--reveal` prints the passwords themselves. That is the one place in the tool
    where plaintext reaches output on purpose (invariant 2's third exception): a
    sample is not a credential, because nothing authenticates with it and it is
    never stored. It is refused with `--output json`, which is what gets captured
    and shipped to log aggregation -- and the JSON section carries no value
    property at all, so the two halves cannot disagree about that.

    Named policies only: this samples what the file declares, so an undeclared
    name is refused the same way one written *in* the file would be. With no name
    it uses `defaults.policy`.
    """
    document = run.document

    if reveal and run.is_json:
        # Silently dropping the flag is the defect `select_option` describes; the
        # refusal is `config show --select`'s precedent. Which way round matters:
        # `--output json` is the safe one, so it wins and the *revealing* flag is
        # what has to go.
        #
        # A UsageError, for `config show --select`'s reason as well: two flags
        # that cannot both be honoured is a fact about argv, not about the file.
        raise click.UsageError(
            "--reveal cannot be used with --output json\n"
            "       json output is what gets captured and shipped to log "
            "aggregation, so a sample never\n"
            "       appears in it -- drop --reveal, or use the text output"
        )

    paths = discover(run.config_paths)
    _, config = load_layers(paths)
    chosen, policy = _policy_to_sample(config, name)

    limit = None if max_bytes is None else ByteLimit(max_bytes=max_bytes, encoding=encoding)
    samples = [generate(policy, limit=limit) for _ in range(count)]
    described = describe_all(samples, policy, limit=limit)

    document.diagnostics.extend(config_diagnostics(config))
    document.policy = build_policy_section(chosen, policy, described, limit=limit)
    document.finish(
        ExitCode.SUCCESS,
        Summary(total=count, ok=sum(1 for one in described if one.compliant), changed=0, failed=0),
    )
    return render_samples(paths, chosen, policy, samples, described, limit=limit, reveal=reveal)


def _policy_to_sample(config: Config, name: str | None) -> tuple[str, PasswordPolicy]:
    """The policy that was asked for, or the file's default.

    `defaults.policy` is read directly, as `bindings.py` already reads it: it is
    the chain the file itself describes (§3), and the `SOPULI_*` and command-line
    layers above it belong to the precedence resolver (#10) rather than here.

    **Both refusals below stay `ConfigError`, on exit 9, even though the name was
    typed on the command line.** This is the boundary J7 (#8) predicted would
    blur, and the test is not where the name came from but what is wrong: argv
    resolved to a valid command with valid options, the run began, and the
    configuration turned out not to declare what it asked for. `sopuli policy
    sample nosuch` is answerable only by reading the file, so it is the file the
    operator has to go and fix -- which is what exit 9 tells them. The two flag
    refusals above are the other case: nothing is wrong with any file.
    """
    chosen = name if name is not None else config.defaults.policy
    if chosen is None:
        raise ConfigError(
            "no policy to sample",
            hint=(
                "name one -- `sopuli policy sample NAME` -- or set `defaults.policy:` in the config"
            ),
        )
    dangling(
        chosen,
        {policy.name for policy in config.policies},
        noun="policy",
        section="policies",
        # A name typed on the command line has no place in the document to
        # point at; one that came from the file does, and naming it is what
        # sends the reader to the line to fix.
        at=ROOT.key("defaults").key("policy") if name is None else ROOT,
    )
    return chosen, next(policy for policy in config.policies if policy.name == chosen).password


@cli.group("lock")
def lock_group() -> None:
    """Inspect the advisory locks."""


@lock_group.command("status")
@select_option
@global_options
def lock_status(
    selectors: tuple[str, ...],
    run: Invocation,
) -> str:
    """Show which secret paths are locked, and by whom.

    The answer to exit 7. A mutating run that loses a lock prints the holder and
    stops; this is how anybody else finds out the same thing without racing for
    it -- what is held, by whom, since when, and whether the claim has lapsed.

    **It takes no lock itself.** #83 settled that for `check`, `status` and every
    `--dry-run`, and the reason is not politeness: an hourly survey that locked
    would block the rotations it exists to report on, and the concurrency gate
    would start failing for the wrong reason.

    **This is the first verb that opens a socket.** `config show`, `target list`
    and `policy sample` are offline by design and safe to point at a production
    config from a laptop; this one authenticates to every store its selection
    touches and reads from it. Nothing it reads is a secret -- a lock record
    carries an identity, a command and two timestamps, and never a value -- but
    the connection is real, and `--select` is how a survey is kept to the estate
    somebody meant.

    It reports the **declared** set: every secret path the configuration binds an
    account to, deduplicated through the same key the manager locks on, so two
    accounts sharing one document are one row here exactly as they are one lock
    during a rotation. A record left at a path the file no longer declares is
    invisible to this, and seeing one needs a store capability that does not
    exist yet (#150).

    Always exit 0 when it could look. A held lock is a finding, not a failure --
    exit 7 means *this run could not proceed*, and this run had nothing to
    proceed with.
    """
    document = run.document

    match = parse_selector(selectors)
    paths = discover(run.config_paths)
    _, config = load_layers(paths)
    config = filter_estate(config, match)

    keys = declared_locks(config)
    stores = _stores_for({key.store for key in keys}, config)
    states = survey(keys, stores=stores)
    mode = mode_of(stores)

    document.diagnostics.extend(config_diagnostics(config))
    document.selection = as_dict(match) or None
    document.lock = build_status_section(states, mode=mode)
    document.finish(
        ExitCode.SUCCESS,
        # `ok` is every path that was looked at, because looking succeeded. A
        # held lock is not a failed path -- `failed` here would put a red number
        # in front of a colleague doing their job.
        Summary(total=len(keys), ok=len(keys), changed=0, failed=0),
    )
    return render_status(paths, states, match=match, mode=mode)


def _stores_for(names: set[str], config: Config) -> Mapping[str, SecretStore]:
    """Open every store a survey needs, and only those.

    One connection per store rather than one per path: a store is a client, and
    an estate with forty paths in one vault should authenticate once.

    The names are resolved against `vaults:` with the same `dangling` message
    every other name in the file gets. `references.py` has already checked them,
    so this is unreachable through a config file -- and it is here anyway,
    because the alternative when it ever *is* reachable is a `KeyError` naming a
    dictionary.
    """
    declared = {vault.name: vault for vault in config.vaults}
    for name in sorted(names):
        dangling(name, set(declared), noun="vault", section="vaults", at=ROOT.key("vaults"))
    return {name: connect(declared[name], env=os.environ) for name in sorted(names)}


@config_group.command("validate")
@global_options
def config_validate(
    run: Invocation,
) -> str:
    """Check the configuration and say nothing else.

    P3 makes this a first-class command: it "exits non-zero on unknown keys -- a
    typo in a credential tool must never be silently ignored". Everything it does
    is what ``load_layers`` already does; what it adds is a command whose *only*
    job is that, so a file can be checked in CI without asking for output nobody
    reads.

    **Validated by the loader, not by the published schema.** The two are not
    equivalent, and the stricter one wins:
    ``docs/schemas/sopuli-config-1.2.schema.json`` is structural, deliberately
    leaves the cross-key rules out (``01-configuration.md`` section 9b), and
    ``jsonschema`` is a development dependency that must not become a runtime
    one. The schema is the editor's fast local check; this is the complete one.

    Offline, like ``config show``: no vault and no database is contacted, so it
    is safe to point at a production config from a laptop.

    A bad file raises out of here rather than being caught. The boundary in
    :func:`main` maps it to exit 9 and emits the run document, which matters more
    for this verb than for any other: reporting configuration problems is its
    entire purpose, and a validator that goes silent under ``--output json``
    exactly when it has something to say is not a validator. That argument is
    what settled J7 (issue #8).
    """
    document = run.document

    paths = discover(run.config_paths)
    _, config = load_layers(paths)

    # A configured-but-uninstalled backend warns here and **exits 0** (ADR-006,
    # E4): the config is valid, the install is incomplete, and the two are
    # different findings about different machines. It is the only warning in this
    # command that the config layer did not make, because making it means asking
    # what is importable and the config layer asks nothing outside the document.
    backends = backend_diagnostics(config.vaults)
    document.diagnostics.extend(config_diagnostics(config))
    document.diagnostics.extend(backends)
    targets = len(config.expanded_targets)
    document.finish(
        ExitCode.SUCCESS,
        Summary(total=targets, ok=targets, changed=0, failed=0),
    )
    return render_validation(paths, config, [warning.message for warning in backends])


def main() -> None:
    """Console-script entry point.

    click handles usage errors itself and exits 2, which is what the exit code
    table already specifies, so that path is left alone. This wrapper exists for
    the other one: an unexpected exception should reach the user as a message
    and exit 1, never as a traceback.

    **This is the boundary's text half.** The JSON half -- the run document, for
    every exit but 2 -- is emitted before the exception gets here, by the exit
    handler in :mod:`sopuli.invocation`, which is the only place that has the
    open document to attach an error to. What is left here is the message a human
    reads on stderr and the process exit code, both of which happen whatever
    ``--output`` said.

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
        # P5 gives a bad configuration its own exit code, so a scheduler can tell
        # "fix your file" from "you typed the command wrong" and from "something
        # broke". The error already knows its own location, hint and code --
        # printing it is all that is left to do. `ArgumentError` comes through
        # here too, carrying exit 2 (#8).
        click.echo(f"sopuli: {exc}", err=True)
        raise SystemExit(exc.exit_code) from exc
    except LockDeniedError as exc:
        # P5's exit 7, and the message carries the holder (#83) -- who is running
        # what, since a lock a colleague holds and a lock a dead process holds
        # need opposite responses. This arm and `_classify` in
        # `sopuli.invocation` have to agree: the document's `exit_code` is
        # defined as equal to the process's.
        click.echo(f"sopuli: {exc}", err=True)
        raise SystemExit(ExitCode.LOCK_HELD) from exc
    except LockError as exc:
        # Everything else about a lock, which today is `LockStolenError`, and
        # deliberately *not* 7. Exit 7 tells a scheduler nothing ran -- the
        # canonical recipe in `03-json-output.md` §6 pairs it with 6 under
        # "sopuli could not run" -- and a stolen lock is found at a fence check,
        # which may be the check before a run's *second* target. Saying "nothing
        # happened" there would be the one wrong answer.
        #
        # A command that knows what it applied reports exit 4 from its own
        # document and never reaches this handler. Reaching it means nobody could
        # say, and generic failure is what that is.
        click.echo(f"sopuli: {exc}", err=True)
        raise SystemExit(ExitCode.FAILURE) from exc
    except Exception as exc:  # noqa: BLE001 - deliberate catch-all at the boundary
        # TODO(#4 follow-up): map driver errors to their categories here,
        # carrying the vendor code and a hint (see CLAUDE.md, Style).
        click.echo(f"sopuli: {type(exc).__name__}: {exc}", err=True)
        raise SystemExit(ExitCode.FAILURE) from exc


if __name__ == "__main__":  # pragma: no cover
    main()

"""The ``sopuli`` command line.

Grammar is noun-verb (D2): ``sopuli <noun> <verb>``. Each noun is a
:class:`click.Group`, each verb a command inside it. The ``config`` verbs,
``target list`` and ``policy sample`` touch nothing outside the file; ``lock
status`` is the first verb that opens a socket and ``lock break`` the first that
writes through one, and both seams are worth keeping visible rather than letting
them blur one command at a time.

Five things about the structure are deliberate:

**The configuration is read by the boundary, not by the verbs.** A profile is
precedence layer 3 and can supply ``output``, so the file has to be read before a
run picks an emitter -- which is before any verb starts. :mod:`sopuli.invocation`
does it, and a verb asks ``run`` for the loaded config (#153). A verb that read
its own would be one that could disagree with the settings the run resolved.

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
ever looks like a credential — with two exceptions it checks rather than trusts:
``--vault-token-file`` carries a *path*, and ``--vault-token`` exists only to be
refused (#145, ADR-007).

**One command prints a password on purpose.** ``policy sample --reveal`` is
invariant 2's third exception, because a sample is not a credential: nothing
authenticates with it and it is never stored. What keeps that narrow lives in
:mod:`sopuli.output.policy_view`; what lives here is the refusal to combine it
with ``--output json``.

**One command mutates, and the gates it goes through are not its own** (#149).
``lock break`` asks :func:`sopuli.safety.refuse_if_readonly` before it opens a
store, :func:`sopuli.lock.takeover.check_fenceable` before it reads one, and
:func:`sopuli.lock.takeover.plan_break` before it writes -- three refusals in
three modules, each of which is a decision the command does not get to make
locally. What is left here is the order they happen in, the confirmation, and the
document. The verbs that mutate a database will inherit the same arrangement.
"""

from __future__ import annotations

import importlib
import os
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, TypeVar

import click

from sopuli import apply as apply_states
from sopuli import check as check_states
from sopuli import generate as staging
from sopuli import plan as plan_builder
from sopuli import strategy as strategies
from sopuli.admin import resolve as admin_resolve
from sopuli.apply import Source
from sopuli.clock import to_rfc3339, utc_now
from sopuli.config import (
    ROOT,
    ArgumentError,
    Binding,
    Config,
    ConfigError,
    ExpandedTarget,
    PasswordPolicy,
    as_dict,
    binding_stores,
    dangling,
    filter_estate,
    parse_selector,
)
from sopuli.diagnostics import (
    backend_diagnostics,
    driver_diagnostics,
    install_diagnostics,
    lock_broken,
    unlistable_stores,
    vault_diagnostics,
    wallet_diagnostics,
)
from sopuli.driver.oracle.client import (
    Timeouts,
    describes_unreachable_server,
    reach_floor,
)
from sopuli.driver.oracle.verification import DEFAULT_MARGIN
from sopuli.driver.oracle.wallet import survey as wallet_survey
from sopuli.driver.protocol import (
    FAIL,
    PASS,
    VERIFY_LOGIN,
    DriverError,
    UnsupportedCapabilityError,
    UserState,
)
from sopuli.driver.registry import DRIVERS
from sopuli.driver.registry import resolve as resolve_driver
from sopuli.exit_codes import ExitCode
from sopuli.generate import Candidate, DocumentWrite
from sopuli.install_shape import Component
from sopuli.install_shape import survey as install_survey
from sopuli.invocation import (
    GlobalOptions,
    Invocation,
    all_options,
    global_options,
    group_options,
)
from sopuli.lock.errors import LockDeniedError, LockError
from sopuli.lock.inspect import declared_locks, mode_of, survey
from sopuli.lock.inspect import discover as discover_locks
from sopuli.lock.keys import LockKey, acquisition_order, normalise_path, parse_lock_key
from sopuli.lock.manager import LockableStore, LockManager, describe_holder
from sopuli.lock.record import current_holder
from sopuli.lock.takeover import (
    Nothing,
    Outcome,
    Take,
    break_lock,
    check_fenceable,
    plan_break,
)
from sopuli.material import strip_one_newline
from sopuli.output.apply_view import build_result as build_apply_result
from sopuli.output.apply_view import render_apply, render_source_table
from sopuli.output.apply_view import summarise as summarise_apply
from sopuli.output.check_view import build_result, render_check, summarise
from sopuli.output.config_view import (
    build_section,
    render_target_list,
    render_text,
    render_validation,
)
from sopuli.output.doctor_view import build_target
from sopuli.output.doctor_view import render as render_doctor
from sopuli.output.document import Diagnostic, Error, Summary
from sopuli.output.generate_view import FAILED, STAGED, render_generate, render_write_table
from sopuli.output.generate_view import build_result as build_generate_result
from sopuli.output.generate_view import summarise as summarise_generate
from sopuli.output.install_view import build as build_install
from sopuli.output.install_view import render as render_install
from sopuli.output.lock_view import (
    build_break_section,
    build_denied_section,
    build_lock_section,
    build_status_section,
    render_break,
    render_status,
)
from sopuli.output.plan_view import render_plan
from sopuli.output.policy_view import build_section as build_policy_section
from sopuli.output.policy_view import describe_all, render_samples
from sopuli.output.stream import configure_streams
from sopuli.output.vault_view import build as build_vault
from sopuli.output.vault_view import render as render_vaults
from sopuli.output.wallet_view import build as build_wallet
from sopuli.output.wallet_view import render as render_wallet
from sopuli.passwords import ByteLimit, generate
from sopuli.payload import PENDING, PREVIOUS, stage_layout
from sopuli.safety import RefusedError, refuse_if_over_limit, refuse_if_readonly
from sopuli.secrets import Secret
from sopuli.store import SecretStore, StoreError, connect
from sopuli.store.credentials import StoredSecret, read_secret
from sopuli.store.credentials import apply_patch as write_credential
from sopuli.store.survey import VaultReport
from sopuli.store.survey import survey as vault_survey
from sopuli.strategy import STRATEGIES
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
    profile_name: str | None,
    vault_token_file: Path | None,
    vault_token_given: bool,
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
        profile_name=profile_name,
        vault_token_file=vault_token_file,
        vault_token_given=vault_token_given,
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

    The file is read before this runs, by the boundary (#153), and a bad one never
    reaches here at all: the exit handler in :mod:`sopuli.invocation` catches it,
    emits the run document and lets it out to exit 9 -- which J7 (issue #8)
    settled as the code that *does* carry a document, the invocation having
    resolved before the file turned out to be unusable. That is one place it
    happens rather than one per verb, and it is why this command asks ``run`` for
    a configuration instead of loading one.
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

    paths = run.sources
    config = filter_estate(run.config, match)

    targets = len(config.expanded_targets)
    document.diagnostics.extend(config_diagnostics(config))
    document.selection = as_dict(match) or None
    document.config = build_section(paths, config, run.declared, resolved=resolved)
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

    A bad config file never reaches here, for the reason ``config show`` gives:
    the boundary reads it, and its exit handler emits the document on exit 9
    (J7, issue #8).
    """
    document = run.document

    match = parse_selector(selectors)
    paths = run.sources
    config = filter_estate(run.config, match)

    targets = len(config.expanded_targets)
    document.diagnostics.extend(config_diagnostics(config))
    document.selection = as_dict(match) or None
    # The same `config` section `config show --resolved` emits, deliberately.
    # It is one estate, and a second JSON shape for it would be two answers to
    # one question -- exactly what invariant 12 exists to prevent. The cost is
    # that `bindings` rides along where the text view has no column for it,
    # which is the cheaper of the two mistakes.
    document.config = build_section(paths, config, run.declared, resolved=True)
    document.finish(
        ExitCode.SUCCESS,
        Summary(total=targets, ok=targets, changed=0, failed=0),
    )
    return render_target_list(paths, config, match=match)


@cli.command("doctor")
@select_option
@click.option(
    "--check-privileges",
    is_flag=True,
    help="Also report privileges the service account holds and does not need.",
)
@global_options
def doctor(
    selectors: tuple[str, ...],
    check_privileges: bool,
    run: Invocation,
) -> str:
    """Check that every target can be reached, and report what it is.

    The first command that connects, and it **mutates nothing** -- everything
    the `creds` verbs depend on either works here or is reported as the reason
    it does not. A `status`-shaped verb (P5): it takes no lock, so an hourly one
    never blocks a rotation.

    **A target that cannot be reached is a finding, not a crash.** The whole
    point is to survey an estate and say which parts of it are unwell, so one
    unreachable database must not end the run before the next target is tried.
    Each failure lands in its own ``targets[]`` entry with the vendor code and
    the server's own message, and the exit code reflects how many.

    **Install shape is reported on every run, not only when it is wrong**
    (ADR-006 E6). Which backends and drivers this build can serve, which the
    config asks for, and where the two disagree -- because this output is audit
    evidence as often as it is a diagnostic, and a section that appeared only on
    a mismatch could never be quoted as proof that there was none. A configured
    component this machine cannot serve fails the run, at exit 9; `config
    validate` warns over the same fact and exits 0, which is E4 and E6
    disagreeing on purpose.

    **The wallet is checked for estates that use ``auth: external``**, and only
    those (P4). A wallet that is missing or unreadable fails the connection as an
    Oracle *login* error, which sends somebody to the account and the password
    they do not have rather than to the file permissions they do. This says so
    first. It warns and never fails: what happens to the run is decided by each
    target's own reachability a moment later.

    Nothing here is a substitute for the guardrails. Reporting what a service
    account holds is not enforcing it; #173 is the refusal.

    **``--check-privileges`` warns and never fails** (P5, decided in #213). An
    over-granted account is somebody else's decision to fix, and a ``doctor``
    that exited non-zero over it would block the person who ran it, mid-incident,
    over a condition they did not create. A **missing** grant is reported the
    same way and for a different reason: it is a finding about readiness, and
    reporting it here is what stops it surfacing as six unrelated failures three
    commands later.

    It is behind a flag because it is not cheap -- three reads plus one probe per
    documented grant, per target -- and a survey of twenty databases should not
    pay for a question nobody asked.

    What it *cannot* see is reported beside what it found: a refused view, and
    the rows of the must-not-grant list that no view reachable from here carries.
    An audit that listed only its findings would read as complete whatever it
    managed to look at.

    Help text stays ASCII throughout, which is P4's rule and why the section
    numbers above are spelled out -- ``tests/test_cli_smoke.py`` fails the build
    on a section sign reaching a Windows console.
    """
    document = run.document

    match = parse_selector(selectors)
    config = filter_estate(run.config, match)
    document.selection = as_dict(match) or None
    document.diagnostics.extend(config_diagnostics(config))

    # Before anything connects, because it is the half of the answer that needs
    # no network -- and because a driver this machine does not have is the reason
    # every target below it is about to be unreachable.
    shape = install_survey(config)
    document.install = build_install(shape)
    # From the survey, never recomputed. "Missing" has to mean the same thing in
    # the section and in the diagnostics of one document, and two functions
    # working it out separately is how it stops meaning the same thing.
    document.diagnostics.extend(install_diagnostics(shape))

    # Before the connections, for the reason the install survey is: it is the
    # half of the answer that needs no network, and it explains the login error
    # the targets below are about to produce if the wallet is the reason.
    wallet = wallet_survey(config.expanded_targets, tns_admin=os.environ.get("TNS_ADMIN"))
    if wallet is not None:
        document.wallet = build_wallet(wallet)
        document.diagnostics.extend(wallet_diagnostics(wallet))

    # Over `config.vaults` and not the filtered estate: `--select` narrows which
    # *targets* are surveyed, and a store serving a target this run excluded is
    # still a store the configuration declares. `filter_estate` only ever removes
    # expanded targets and their bindings, so there is nothing here for it to
    # narrow anyway -- and reporting a store as absent because nobody selected a
    # target that happened to use it would be alarming and wrong.
    vaults = vault_survey(config.vaults, env=os.environ, token_file=run.vault_token_file)
    document.vaults = [build_vault(report, error=_vault_error(report)) for report in vaults]
    document.diagnostics.extend(vault_diagnostics(vaults))

    client = _client_report(config)
    entries = [
        _examine(target, run, config, privileges=check_privileges)
        for target in config.expanded_targets
    ]

    document.targets = entries
    reachable = sum(1 for entry in entries if entry["reachable"])
    failed = len(entries) - reachable
    unreachable_vaults = sum(1 for report in vaults if not report.reachable)
    document.finish(
        _doctor_exit(shape.missing, failed, unreachable_vaults),
        Summary(total=len(entries), ok=reachable, changed=0, failed=failed),
    )
    sections = [*render_install(shape)]
    if wallet is not None:
        sections.extend(render_wallet(wallet))
    sections.extend(render_vaults(list(vaults)))
    return "\n".join([*sections, render_doctor(entries, client=client)])


def _vault_error(report: VaultReport) -> Error | None:
    """A store that could not be opened, as the document's ``error`` object.

    ``None`` for a store that answered, however it answered. ``degraded`` is a
    status and not an error, and attaching one would make a sealed vault look
    like a failure of this run rather than a state of that vault.

    The exception's own ``category`` and ``code`` survive, which is the whole
    reason :class:`~sopuli.store.survey.VaultReport` carries the exception rather
    than a string: a missing backend is ``SOPULI-20001`` and a refused login is
    exit 6, and re-deriving either from a message is how they stop agreeing with
    the rest of the document.
    """
    if report.failure is None:
        return None
    return _as_error(report.failure)


def _doctor_exit(missing: Sequence[Component], failed: int, vaults_down: int = 0) -> ExitCode:
    """Which failure this run is, when it is several.

    **Install shape wins over everything else**, and the order is most of this
    function. A configured driver this machine does not have makes every target
    under it unreachable, so the two findings arrive together and only one of
    them names something the reader can go and fix. Reporting exit 1 there would
    point at twenty databases and away from the one `pip` line. A missing
    *backend* does the same to every store below it.

    **An unreachable vault fails the run, at exit 1, the same as an unreachable
    target** (#216). Not a softer verdict, and if anything it deserves a harder
    one: the vault is master and the direction is always vault to database
    (invariant 6), so a store nobody can reach is an estate on which no `creds`
    verb can do anything -- a wider outage than one dead database rather than a
    narrower one. It shares exit 1 rather than taking a number of its own
    because P5's set has none for it, and inventing one here would be answering
    a cross-cutting question as a side effect of a section.

    **A degraded vault does not, and neither does a skewed clock.** Something
    answered in both cases, and the run is not over: a sealed store is somebody
    to page, and a clock outside tolerance is a hazard this run did not create
    and cannot fix. Both are `SOPULI-W010` and `SOPULI-W009` in the diagnostics
    array, which is #213's answer for over-granted accounts applied to the same
    shape of question -- a `doctor` that exited non-zero over them would block
    the person who ran it, mid-incident, over a condition they did not cause.

    **Exit 9 and not 1**, which is E5's number rather than a new one: a missing
    backend is already ``config`` / exit 9 when a command resolves one, and P5's
    exit 9 already means *fix your configuration, not your command line*. Having
    `doctor` report the same condition with a different number would give the
    tool two answers to one question. The estate is not at fault and the config
    is valid -- what is incomplete is this machine, which is exactly the half of
    exit 9 the recipe in ``03-json-output.md`` §6 already routes to a human.

    ``summary`` is untouched by all of this and still counts **targets**. Neither
    an install-shape failure nor a dead vault is a target that failed, and
    inflating ``failed`` to make the exit code look derivable would put a number
    in the document that no entry in ``targets[]`` accounts for. So the exit code
    is deliberately not a function of the summary, and a consumer that wants to
    know why a run failed reads the sections rather than the arithmetic.
    """
    if missing:
        return ExitCode.CONFIG_INVALID
    return ExitCode.SUCCESS if failed == 0 and vaults_down == 0 else ExitCode.FAILURE


def _client_report(config: Config) -> dict[str, Any]:
    """What this machine can reach, before any target is tried.

    P4 wants this answered *without* a database: a 23.x client reaches 19c and
    later, so a configured 11.2 target is out of reach and saying so beats
    letting somebody wait for a connection that cannot succeed.

    A missing Instant Client is the ordinary case on a fresh machine and is
    reported rather than raised -- `doctor` exists to be run when things are
    wrong, so it is the one command that must survive its own subject being
    broken.
    """
    report: dict[str, Any] = {"tns_admin": os.environ.get("TNS_ADMIN") or "(unset)"}
    lib_dir = config.runtime.oracle.client_lib_dir
    if lib_dir:
        report["client_lib_dir"] = lib_dir

    try:
        # Through the registry's own entry rather than a second copy of the
        # module path: the whole value of resolving there is that one place
        # knows which module pulls the client in (#170).
        module = importlib.import_module(DRIVERS["oracle"].module)
        module.initialise(env=os.environ, lib_dir=lib_dir)
        version = module.client_version()
    except Exception as error:  # noqa: BLE001 -- a broken client is the finding
        report["instant_client"] = "not loaded"
        report["detail"] = str(error).splitlines()[0]
        return report

    report["instant_client"] = ".".join(str(part) for part in version)
    floor = reach_floor(version)
    report["reaches"] = f"{floor[0]}.{floor[1]} and later" if floor else "(no interoperability row)"
    return report


def _examine(
    target: ExpandedTarget, run: Invocation, config: Config, *, privileges: bool = False
) -> dict[str, Any]:
    """One target: connect, report what it is, and always close."""
    started = time.monotonic()
    session = None
    try:
        # Getting in, which is what `reachable` reports.
        try:
            session = _open_session(target, run, config)
        except Exception as error:  # noqa: BLE001 -- a per-target finding
            return build_target(
                target,
                connected=False,
                error=_as_error(error),
                duration_ms=_elapsed(started),
                warnings=_reach_warning(error),
            )

        # Finding out what it is, which can fail on a connection that is fine:
        # a dictionary view this account cannot read, or a probe that could not
        # be answered. Reporting that as unreachable would send somebody to the
        # listener over a grant, so the two are separate.
        warnings: tuple[str, ...] = ()
        audit = None
        try:
            scope = session.scope()
            if privileges:
                # Folded into the scope the entry already carries rather than
                # added beside it, because `scope.over_granted` is where the run
                # schema puts this, and two places for one fact are two things
                # that can disagree.
                audit = session.privileges()
                scope = replace(scope, over_granted=audit.over_granted)
                # The findings alone would be a report that reads as complete
                # whatever it managed to look at. `caveats()` is what stops
                # `over_granted: []` meaning both "nothing is over-granted" and
                # "the view that would have said so was refused".
                warnings = audit.caveats()
        except Exception as error:  # noqa: BLE001 -- also a per-target finding
            return build_target(
                target, connected=True, error=_as_error(error), duration_ms=_elapsed(started)
            )
    finally:
        if session is not None:
            with suppress(Exception):
                session.close()

    return build_target(
        target,
        connected=True,
        scope=scope,
        duration_ms=_elapsed(started),
        warnings=warnings,
        privileges=audit,
    )


def _timeouts(run: Invocation) -> Timeouts:
    """The run's own budgets, not the driver's defaults.

    `db.connect_timeout_s` is a documented setting with a whole precedence chain
    behind it, and a command that resolved it and then connected on the built-in
    anyway would be #176's review finding all over again: a key that looks
    configured and does nothing. `doctor` is also the command most likely to be
    pointed at something unreachable, which is exactly when the number matters.
    """
    resolved = run.resolved.get("db.connect_timeout_s")
    if resolved is None:
        return Timeouts()
    return Timeouts(connect_s=int(resolved.value))


def _elapsed(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _as_error(error: Exception) -> Error:
    """A failure as the document's ``error`` object, keeping the vendor code."""
    # First line only. A driver error's `message` keeps the server's own wording
    # (#172), and a client one carries whatever `oracledb` said -- which runs to
    # several lines including a documentation link. A survey puts one line per
    # target beside a table, so the rest belongs in the hint where it already is.
    message = getattr(error, "message", None) or str(error)
    # `"".splitlines()` is `[]`, so indexing it raises on an exception carrying no
    # message -- `Exception()`, or a vendor client raising a bare class. Reachable
    # from every target and, since #216, from every store as well. The class name
    # is the only information left, and it beats an empty string: that reads as
    # the tool having lost the reason rather than there never having been one.
    lines = message.splitlines()
    return Error(
        category=getattr(error, "category", "database"),
        message=lines[0] if lines else type(error).__name__,
        hint=getattr(error, "hint", None),
        code=getattr(error, "code", None),
    )


def _reach_warning(error: Exception) -> tuple[str, ...]:
    """The interoperability sentence, only where the code says it applies."""
    if describes_unreachable_server(getattr(error, "code", None)):
        return (
            "this looks like the Instant Client being newer than the server; "
            "see the client line above for what it reaches",
        )
    return ()


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

    paths = run.sources
    config = run.config
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
    """Inspect the advisory locks, and take one back."""


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
    during a rotation.

    **And then it looks beside it** (#150). Each store's lock prefix is listed,
    and a record at a path this configuration does not declare is reported with
    `declared: false` -- an application renamed or removed, or another config's
    estate sharing the mount. That is the record nobody could otherwise see, and
    a lock nobody can see is a lock nobody can clear. Invariant 5 is untouched:
    the config whitelists what the tool may *touch*, and this command touches
    nothing. A store with no `list` capability is named in a warning rather than
    refused, so a survey never becomes a command that works on some backends and
    not others.

    Always exit 0 when it could look. A held lock is a finding, not a failure --
    exit 7 means *this run could not proceed*, and this run had nothing to
    proceed with. A store that could not be *listed* is not a failure either: the
    warning says how much of the estate the answer covers.
    """
    document = run.document

    match = parse_selector(selectors)
    paths = run.sources
    config = run.config
    # Both estates: the filtered one decides what is surveyed and which stores
    # are opened, and the whole one decides what counts as *declared*. A path
    # `--select` excluded is still one this configuration declares, and reporting
    # it as a leftover because this run was not looking at it would be alarming
    # and wrong.
    everything = declared_locks(config)
    keys = declared_locks(filter_estate(config, match))

    stores = _stores_for({key.store for key in keys}, config, token_file=run.vault_token_file)
    leftovers = discover_locks(everything, stores=stores)
    states = survey(
        acquisition_order([*keys, *leftovers.keys]), stores=stores, declared=set(everything)
    )
    mode = mode_of(stores)

    document.diagnostics.extend(config_diagnostics(filter_estate(config, match)))
    document.diagnostics.extend(unlistable_stores(leftovers.unlistable))
    document.selection = as_dict(match) or None
    document.lock = build_status_section(states, mode=mode)
    document.finish(
        ExitCode.SUCCESS,
        # `ok` is every path that was looked at, because looking succeeded. A
        # held lock is not a failed path -- `failed` here would put a red number
        # in front of a colleague doing their job. Discovered paths count too:
        # they were examined, and `summary.total` is what was examined.
        Summary(total=len(states), ok=len(states), changed=0, failed=0),
    )
    return render_status(paths, states, match=match, mode=mode)


@lock_group.command("break")
@click.argument("lock", metavar="VAULT:PATH")
@click.option(
    "--confirm",
    is_flag=True,
    default=False,
    help="Proceed without asking. Required where nothing can be asked.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Break a lock that has not expired. Its holder is probably working.",
)
@global_options
def lock_break(
    lock: str,
    confirm: bool,
    force: bool,
    run: Invocation,
) -> str:
    """Take a lock from whoever holds it, and fence them.

    The remedy `lock status` names and exit 7 points at. A run that was killed
    leaves a held record behind; it expires, and until it does -- or if it never
    does, because something wrote a record with no readable expiry -- nothing else
    can rotate that credential. This is how a person clears it deliberately.

    The argument is spelled the way exit 7, the `lock.*` events and `lock
    status`'s first column already print it, so the invocation in a refusal is a
    paste rather than a translation.

    **It never deletes.** A `released` record is written over the held one, with
    `cas` set to the version that was read. A KV v2 delete leaves the metadata
    behind, after which a first acquisition can never compare-and-set against
    version 0 again -- and that monotonic version *is* the fence, so a delete
    would break every future lock on the path in order to clear one.

    **It fences whoever held it**, and that is what makes breaking a lock
    survivable rather than reckless: the write bumps the version, so the run that
    held it fails its next fence check and stops before its next `ALTER USER`.
    Which is also why a store that cannot fence is refused rather than served a
    weaker version of this, and why a store *declared* `locking: advisory-only`
    is refused whatever it supports -- there would be nothing to stop the run
    whose lock was taken, which is precisely the situation that ends with two
    runners applying different passwords to different targets.

    **An expired lock takes confirmation; a live one takes `--force` as well.**
    An expired holder is almost always a process that died. A live one is
    somebody working, and the answer is usually to talk to them -- so that
    refusal is exit 7, naming them, in the same words a rotation losing the same
    lock would use.

    **It is a mutation**, so `--dry-run` prints the plan and writes nothing, and
    `safety.readonly` refuses it outright. Nothing to break -- a path with no
    record, or one already released -- is exit 0 having changed nothing, which is
    what makes running this twice safe.

    It acts on the one lock named, whether or not this configuration declares a
    binding for it: the leftover at a path the file no longer names is exactly
    the record nobody else can clear (#150). The write still lands under the
    store's lock prefix, in a store `vaults:` declares, and never touches the
    secret the lock guards.
    """
    document = run.document

    try:
        key = parse_lock_key(lock)
    except ValueError as exc:
        # A malformed argument is exit 2 with no document (J7): argv did not
        # resolve to a valid request, and nothing about any file is wrong.
        raise click.UsageError(str(exc)) from exc

    refuse_if_readonly(run.resolved, action=f"breaking the lock on {key}")

    paths = run.sources
    config = run.config
    entry = _lockable_store(key, config, token_file=run.vault_token_file)
    # Invariant 4: the capability is asked about before the record is read, so a
    # store that can never serve this command says so rather than looking as
    # though this particular lock could not be taken.
    check_fenceable(key, entry)
    mode = mode_of({key.store: entry.store})

    document.diagnostics.extend(config_diagnostics(config))

    try:
        state = survey([key], stores={key.store: entry.store})[0]
        outcome = plan_break(state, force=force)

        if isinstance(outcome, Nothing) or run.dry_run:
            return _report_plan(run, outcome, paths=paths, mode=mode)

        _confirm_break(outcome, paths=paths, mode=mode, confirmed=confirm)
        new_version = break_lock(outcome, entry.store)
    except LockDeniedError as exc:
        # The same `denied` object a rotation would emit, for the same reason:
        # the question at exit 7 is who that is, and it must not depend on which
        # command was asking.
        document.lock = build_denied_section(exc, mode=mode)
        raise

    document.diagnostics.extend(
        lock_broken(outcome.key, outcome.record, expired=outcome.state.expired)
    )
    document.lock = build_break_section(outcome, mode=mode, applied=True, new_version=new_version)
    document.finish(ExitCode.SUCCESS, Summary(total=1, ok=1, changed=1, failed=0))
    return render_break(paths, outcome, mode=mode, applied=True, new_version=new_version)


def _report_plan(run: Invocation, outcome: Outcome, *, paths: Sequence[Path], mode: str) -> str:
    """Finish a run that wrote nothing — a dry run, or nothing to break.

    One function for both because the document is the same shape either way, and
    that is the point of `applied` living inside the entry: a consumer diffing a
    dry run against the run that followed compares like with like. What differs
    is `summary.changed`, which is 0 in both cases and for the same reason —
    nothing happened.

    Invariant 9 falls out here rather than being arranged: the second `lock
    break` on a path finds the record it wrote the first time, which is not a
    claim, and reports `changed: false` without writing again.
    """
    document = run.document
    if isinstance(outcome, Nothing):
        # The text says this on its last line; a consumer reading the document
        # gets an empty `broken` and would otherwise have to infer why.
        document.diagnostics.append(Diagnostic(level="info", message=_nothing_to_break(outcome)))
    document.lock = build_break_section(outcome, mode=mode, applied=False)
    document.finish(ExitCode.SUCCESS, Summary(total=1, ok=1, changed=0, failed=0))
    return render_break(paths, outcome, mode=mode, applied=False, dry_run=run.dry_run)


def _nothing_to_break(outcome: Nothing) -> str:
    return f"nothing to break at {outcome.key}: the path has no held record"


def _confirm_break(outcome: Take, *, paths: Sequence[Path], mode: str, confirmed: bool) -> None:
    """Print the plan and ask, unless somebody already answered.

    Invariant 8's "prints a plan first", and the plan goes to **stderr**: under
    `--output json` stdout carries the run document and nothing else may touch
    it, and a prompt that appeared only in text mode would be a confirmation
    somebody could skip by asking for JSON.

    **Where nothing can be asked, this refuses rather than proceeding.** That is
    the ratchet reading of P5's `--confirm`: the flag says *I have already
    decided*, and a closed stdin is not somebody deciding. Exit 8 with a message
    naming the flag is more use than a prompt that reads EOF and aborts, which is
    what click would otherwise do — the operator would learn that it stopped and
    not what to type instead.
    """
    if confirmed:
        return
    if not _can_prompt():
        raise RefusedError(
            "breaking a lock needs confirmation, and there is nobody here to ask",
            hint=(
                "pass --confirm to answer in advance, or --dry-run to see the plan "
                "without touching anything"
            ),
        )
    click.echo(render_break(paths, outcome, mode=mode, applied=False), err=True)
    click.confirm(
        f"take this lock from {describe_holder(outcome.record)}?",
        abort=True,
        err=True,
    )


def _can_prompt() -> bool:
    """Whether there is somebody at a terminal to answer.

    Not a flag and not a profile key — a run is unattended when nobody could have
    been asked, which is what `invocation.actor.unattended` already says in the
    document (`01-configuration.md` §5). A profile's `confirm:` is parsed and
    waiting for a consumer; wiring it into the resolver is its own change.
    """
    return sys.stdin is not None and sys.stdin.isatty()


def _lockable_store(
    key: LockKey, config: Config, *, token_file: Path | None = None
) -> LockableStore:
    """The one store this lock lives in, and whether a lock in it can be fenced.

    `locking` is carried alongside the client rather than re-read, for the reason
    :class:`~sopuli.lock.manager.LockableStore` gives: a command must not be able
    to disagree with what `config show` displayed about the same store.
    """
    store = _stores_for({key.store}, config, token_file=token_file)[key.store]
    locking = next(vault.locking for vault in config.vaults if vault.name == key.store)
    return LockableStore(store=store, locking=locking)


def _stores_for(
    names: set[str], config: Config, *, token_file: Path | None = None
) -> Mapping[str, SecretStore]:
    """Open every store a survey needs, and only those.

    One connection per store rather than one per path: a store is a client, and
    an estate with forty paths in one vault should authenticate once.

    ``token_file`` is ``--vault-token-file``'s path, forwarded as a location: it
    reaches ``method: token`` stores and is read there, on §3a's chain, so this
    is the first command line able to authenticate a store without a variable or
    a file in a fixed place (#145).

    The names are resolved against `vaults:` with the same `dangling` message
    every other name in the file gets. `references.py` has already checked them,
    so this is unreachable through a config file -- and it is here anyway,
    because the alternative when it ever *is* reachable is a `KeyError` naming a
    dictionary.
    """
    declared = {vault.name: vault for vault in config.vaults}
    for name in sorted(names):
        dangling(name, set(declared), noun="vault", section="vaults", at=ROOT.key("vaults"))
    return {
        name: connect(declared[name], env=os.environ, token_file=token_file)
        for name in sorted(names)
    }


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
    ``docs/schemas/sopuli-config-1.3.schema.json`` is structural, deliberately
    leaves the cross-key rules out (``01-configuration.md`` section 9b), and
    ``jsonschema`` is a development dependency that must not become a runtime
    one. The schema is the editor's fast local check; this is the complete one.

    Offline, like ``config show``: no vault and no database is contacted, so it
    is safe to point at a production config from a laptop.

    A bad file never reaches here: the boundary reads it, maps it to exit 9 and
    emits the run document. That matters more for this verb than for any other --
    reporting configuration problems is its entire purpose, and a validator that
    goes silent under ``--output json`` exactly when it has something to say is
    not a validator. That argument is what settled J7 (issue #8). Which is also
    why this verb reads as thin as it does: everything it checks has already
    happened by the time it is called, and what is left is saying so.
    """
    document = run.document

    paths = run.sources
    config = run.config

    # A configured-but-uninstalled backend warns here and **exits 0** (ADR-006,
    # E4): the config is valid, the install is incomplete, and the two are
    # different findings about different machines. It is the only warning in this
    # command that the config layer did not make, because making it means asking
    # what is importable and the config layer asks nothing outside the document.
    backends = backend_diagnostics(config.vaults) + driver_diagnostics(config.expanded_targets)
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
    except StoreError as exc:
        # A store carries its own exit code and category (#138) -- a login
        # failure is P5's exit 6, a store that cannot fence a lock is exit 5
        # (#149) -- and the run document already reports it from `_classify`.
        # Without this arm the process would exit 1 while its own document said
        # otherwise, and `exit_code` is defined as equal to the process's.
        click.echo(f"sopuli: {exc}", err=True)
        raise SystemExit(exc.exit_code) from exc
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
    except DriverError as exc:
        # A driver carries its own exit code and category, the way a store does
        # (#138) -- and here it is load-bearing rather than tidy:
        # `UnsupportedCapabilityError` is exit 5, and invariant 4 makes that a
        # promise. Without this arm the catch-all below would report it as
        # generic failure, and a command refusing a capability at plan time
        # would be indistinguishable from one that broke.
        #
        # `__str__` already renders the hint, so there is nothing to add here.
        click.echo(f"sopuli: {exc}", err=True)
        raise SystemExit(exc.exit_code) from exc
    except Exception as exc:  # noqa: BLE001 - deliberate catch-all at the boundary
        # TODO(#4 follow-up): map the driver errors that arrive *inside* a
        # per-account finding to their categories, carrying the vendor code and
        # a hint (see CLAUDE.md, Style). Ones that escape a command whole are
        # handled above.
        click.echo(f"sopuli: {type(exc).__name__}: {exc}", err=True)
        raise SystemExit(ExitCode.FAILURE) from exc


@cli.group("creds")
def creds_group() -> None:
    """Manage application database account credentials."""


@creds_group.command("check")
@select_option
@click.option(
    "--include-previous",
    is_flag=True,
    help="Also ask whether the vault's previous password is still accepted.",
)
@click.option(
    "--lockout-margin",
    type=click.IntRange(0, 100),
    default=DEFAULT_MARGIN,
    show_default=True,
    help="Refuse to attempt a login within this many tries of the lockout limit.",
)
@global_options
def creds_check(
    selectors: tuple[str, ...],
    include_previous: bool,
    lockout_margin: int,
    run: Invocation,
) -> str:
    """Check whether the vault's password works against each database.

    One question per account per target, and the command **mutates nothing**: no
    vault write, no DDL, and no lock at all -- P5 exempts `check` precisely so an
    hourly scheduled one never blocks a rotation.

    **Exit 3 for drift** is what makes this schedulable. A monitoring system
    alerts on 3 specifically, which is distinct from "the tool failed" -- so a
    target that could not be reached is exit 1 and never exit 3, or a broken
    check would page the same person as a real one.

    **Login is the only method, and there is no --method flag.** Q1 was decided
    in issue #86: `login`, unconditionally. Hash mode depends on reproducing
    Oracle's 12C verifier client-side, which is still unverified (issue #90) and
    may never ship, and a flag with one legal value would advertise a choice
    that does not exist.

    **Locking an account would be worse than the drift this detects**, so all of
    UC-1's runtime mitigations are in place. One attempt per account per run and
    no retry on a wrong password -- the driver's signature has no shape for a
    back-off loop. Where `SELECT ON SYS.USER$` was granted, the failed-login
    counter is read fresh immediately before the attempt and the login is
    refused within `--lockout-margin` of the profile's limit. That grant is
    optional and not part of the default install, so where it is absent the
    guard is *unavailable* rather than passing: the run says so in the row and
    goes ahead on the remaining mitigations.

    **Lock, expiry and a missing account are reported as themselves.** A login
    attempt alone conflates an expired password, an already-locked account and a
    genuinely wrong one behind one Oracle error, so the account's status is read
    separately -- from a view the baseline grant already covers -- and each gets
    its own state. Two of those three are not the vault's fault, and folding
    them into drift would send somebody to rotate a credential that is fine.

    Help text stays ASCII throughout, which is P4's rule.
    """
    document = run.document

    match = parse_selector(selectors)
    config = filter_estate(run.config, match)
    document.selection = as_dict(match) or None
    document.diagnostics.extend(config_diagnostics(config))

    # C15's plan-time half (#250), before anything is planned: a profile's
    # `vault:` and SOPULI_VAULT are not consulted while bindings are built, so
    # this is the first moment a binding's store can be complete. The refusal
    # follows immediately because reading a credential is the whole command --
    # invariant 4 wants it here and not partway through the estate.
    config = binding_stores.complete(config, env=os.environ)
    binding_stores.refuse_unresolved(config, action="checking credentials")

    plan = plan_builder.build(config, intent=["verify"])
    refuse_if_over_limit(run.resolved, plan.blast_radius, action="checking credentials")
    document.plan = plan.as_json()

    stores = _stores_for(
        {binding.vault for binding in config.bindings if binding.vault is not None},
        config,
        token_file=run.vault_token_file,
    )
    by_target = {expanded.name: expanded for expanded in config.expanded_targets}

    rows: list[tuple[Binding, check_states.Outcome]] = []
    results: list[dict[str, Any]] = []
    for target_name, bindings in _grouped(config.bindings).items():
        rows.extend(
            _check_target(
                by_target[target_name],
                bindings,
                run,
                config,
                stores=stores,
                margin=lockout_margin,
                previous=include_previous,
                results=results,
            )
        )

    document.results = results
    states = [outcome.state for _, outcome in rows]
    document.finish(check_states.exit_code_for(states), summarise(states))
    return "\n".join([render_plan(plan, noun="check"), "", render_check(rows)])


def _grouped(bindings: Sequence[Binding]) -> dict[str, list[Binding]]:
    """Bindings by target, in estate order.

    One connection per target rather than one per binding. A target with six
    accounts in it is one login for this tool, not six -- and six would be six
    entries in that database's audit trail for one scheduled check.
    """
    grouped: dict[str, list[Binding]] = {}
    for binding in bindings:
        grouped.setdefault(binding.target, []).append(binding)
    return grouped


def _check_target(
    target: ExpandedTarget,
    bindings: Sequence[Binding],
    run: Invocation,
    config: Config,
    *,
    stores: Mapping[str, SecretStore],
    margin: int,
    previous: bool,
    results: list[dict[str, Any]],
) -> list[tuple[Binding, check_states.Outcome]]:
    """Every account this run checks in one target, over one connection.

    **A target that cannot be reached is a finding, not a crash**, the same rule
    `doctor` follows: the point is to survey an estate and say which parts of it
    are unwell, so one dead listener must not end the run before the next target
    is tried. Every account bound to it gets an `ERROR` row carrying the vendor
    code and the server's own message, which is exit 1 rather than exit 3 --
    a broken check must not page whoever watches for drift.
    """
    started = time.monotonic()
    session = None
    try:
        try:
            module = resolve_driver(target.target)
            credential = admin_resolve(target, env=os.environ)
            driver = module.OracleDriver(
                env=os.environ,
                correlation_id=run.document.correlation_id,
                timeouts=_timeouts(run),
                client_lib_dir=config.runtime.oracle.client_lib_dir,
            )
            session = driver.connect(target, credential.credential)
        except Exception as error:  # noqa: BLE001 -- a per-target finding
            return _unreachable(bindings, error, results, duration=_elapsed(started))

        rows = []
        for binding in bindings:
            rows.append(
                _check_one(
                    binding,
                    session,
                    stores=stores,
                    margin=margin,
                    previous=previous,
                    out=results,
                )
            )
        return rows
    finally:
        if session is not None:
            with suppress(Exception):
                session.close()


def _unreachable(
    bindings: Sequence[Binding],
    error: Exception,
    results: list[dict[str, Any]],
    *,
    duration: int,
) -> list[tuple[Binding, check_states.Outcome]]:
    """One target's worth of `ERROR` rows, all carrying the same reason."""
    reported = _as_error(error)
    rows = []
    for binding in bindings:
        outcome = check_states.Outcome(check_states.ERROR, reported.message)
        results.append(build_result(binding, outcome, duration_ms=duration, error=reported))
        rows.append((binding, outcome))
    return rows


def _check_one(
    binding: Binding,
    session: Any,
    *,
    stores: Mapping[str, SecretStore],
    margin: int,
    previous: bool,
    out: list[dict[str, Any]],
) -> tuple[Binding, check_states.Outcome]:
    """One account in one target: read the vault, read the account, ask once.

    The account's state is read **before** the attempt and the attempt is made
    at most once. Both are UC-1 §7's mitigations rather than an ordering
    preference: the status read is what lets a locked account be reported as
    locked instead of as drift, and the driver re-reads the failed-login counter
    itself immediately before it tries, because a value carried from here would
    be a lockout guard computing on a number that has since moved.
    """
    started = time.monotonic()
    accepted: bool | None = None
    try:
        stored = _stored_credential(binding, stores)
        user = session.describe_user(binding.account)
        # Nothing to try, or nothing that should be tried. Written as a
        # disjunction rather than behind one predicate so that the two `None`
        # checks narrow for the branch below -- and read in the order they
        # matter: no account, no stored password, or an account whose status
        # already settles the answer.
        if user is None or stored is None or _settled_by_status(user):
            outcome = check_states.decide(user, None)
            if stored is None and user is not None and not _settled_by_status(user):
                outcome = check_states.Outcome(
                    check_states.UNVERIFIABLE, _nothing_to_compare(binding)
                )
        else:
            # `attempts` is the budget this run intends against this account, and
            # it is declared up front rather than counted afterwards: mitigation
            # 1 is one attempt per account per *run*, so `--include-previous`
            # must reserve both against the lockout guard before spending the
            # first. Asking per value checked would quietly double the spend on
            # the counter the guard exists to protect.
            budget = 2 if previous else 1
            verification = session.verify_password(
                user.name,
                stored.value,
                method=VERIFY_LOGIN,
                lockout_margin=margin,
                attempts=budget,
            )
            outcome = check_states.decide(user, verification, version=stored.version)
            if previous:
                accepted = _previous_accepted(
                    binding, user, session, stores=stores, margin=margin, budget=budget
                )
    except Exception as error:  # noqa: BLE001 -- a per-account finding
        reported = _as_error(error)
        outcome = check_states.Outcome(check_states.ERROR, reported.message)
        out.append(build_result(binding, outcome, duration_ms=_elapsed(started), error=reported))
        return binding, outcome

    out.append(
        build_result(
            binding,
            outcome,
            version=None if stored is None else stored.version,
            stage=None if stored is None else stored.stage,
            age_days=check_states.password_age_days(
                None if user is None else user.password_changed_at
            ),
            duration_ms=_elapsed(started),
            previous_accepted=accepted,
        )
    )
    return binding, outcome


def _previous_accepted(
    binding: Binding,
    user: UserState,
    session: Any,
    *,
    stores: Mapping[str, SecretStore],
    margin: int,
    budget: int,
) -> bool | None:
    """Whether the vault's *previous* password still authenticates.

    The question `--include-previous` exists for, and it is worth asking for two
    different reasons: during a rollover window the answer is expected to be yes
    and confirms the window is real, and outside one a yes means an old
    credential is still live -- which is a finding, because anything still
    holding it can still get in.

    ``None`` when there is no previous password to try, which is the ordinary
    state of a credential that has never been rotated. That is reported as null
    rather than false: "we asked and it was refused" and "there was nothing to
    ask about" are different answers, and the schema types the field nullable
    for exactly that reason.

    Does **not** change the state. A live previous password is information about
    the estate, not a disagreement between the vault and the database, and
    folding it into `DRIFT` would page somebody over a credential that is doing
    what a rollover window is supposed to make it do.
    """
    ref = binding.secret
    if ref is None or binding.vault is None:
        return None
    stored = read_secret(stores[binding.vault], replace(ref, stage=PREVIOUS))
    if stored is None:
        return None
    result = session.verify_password(
        user.name,
        stored.value,
        method=VERIFY_LOGIN,
        lockout_margin=margin,
        attempts=budget,
    )
    # A declined or unavailable attempt is not a "no": it is the absence of an
    # answer, and the guard that declined it has already been reported on the
    # first attempt's `lockout_margin_hit`.
    if result.result not in (PASS, FAIL):
        return None
    return bool(result.result == PASS)


def _nothing_to_compare(binding: Binding) -> str:
    """Why this account could not be checked, when the vault side came back empty.

    Three different situations reach one ``None`` from
    :func:`_stored_credential`, and they send an operator to three different
    places. Saying "the vault holds no password at this ref" for all of them
    would name a ref that, in two of the three, does not exist.

    A binding with no ref at all is not a fault: §3 makes ``secret`` optional,
    and an application that declares none is the ordinary shape of a config that
    only ever runs `doctor`.
    """
    if binding.secret is None:
        return "this account is declared with no secret ref, so there is nothing to compare"
    if binding.vault is None:
        return "no store is named for this ref, so there is nowhere to read it from"
    return f"the vault holds no password at {binding.secret}"


def _settled_by_status(user: UserState) -> bool:
    """Whether the account's own status already answers the question.

    A locked account and an expired password are both answered by the status
    rather than by the credential: a login would be refused by the lock, so it
    could not tell a right password from a wrong one, and it would spend a
    failed login finding that out. UC-1 §7's mitigation 6 reads status
    separately precisely so these are *reported* rather than *probed* -- and
    attempting anyway is the harm §7 exists to prevent, reached by a different
    route from the one it warns about.

    :func:`sopuli.check.decide` makes the same judgement about what to *report*.
    This is the half about what to *do*, and the two are deliberately apart: one
    is a pure decision over values, the other is the thing that stops a network
    call happening.
    """
    return user.locked or user.expired


def _stored_credential(binding: Binding, stores: Mapping[str, SecretStore]) -> StoredSecret | None:
    """The password this binding says to check, or ``None`` where there is none.

    A binding with no ref is not an error here -- §3 makes `secret` optional --
    and neither is a ref pointing at a document that does not exist yet. Both
    are "there is nothing to compare against", which the caller reports as
    `UNVERIFIABLE` with the reason rather than as a failure: a credential that
    has never been written is a real state of a new application, and it is not
    the same thing as a database that rejected a password.
    """
    if binding.secret is None or binding.vault is None:
        return None
    return read_secret(stores[binding.vault], binding.secret)


@creds_group.command("generate")
@select_option
@click.option("--policy", "policy_name", metavar="NAME", help="Override the policy to draw from.")
@click.option(
    "--from-stdin",
    is_flag=True,
    help="Read one password from stdin instead of generating. Applies to every selected account.",
)
@click.option(
    "--no-policy-check",
    is_flag=True,
    help="Accept a supplied password that violates the policy. Recorded in the audit event.",
)
@global_options
def creds_generate(
    selectors: tuple[str, ...],
    policy_name: str | None,
    from_stdin: bool,
    no_policy_check: bool,
    run: Invocation,
) -> str:
    """Draw a new password per the policy and stage it in the vault.

    **The database is never touched.** That is what lets this command take the
    advisory lock at all: the lock lives in the vault (Q2, issue #83), so a
    database-side lock could not have protected the write this makes.

    **Staging is deliberately separate from applying.** It lets an operator
    prepare a password, get a change window approved, and apply later -- and it
    makes each half independently retryable. Nothing is using the new password
    until `sopuli creds apply` puts it in the database and promotes it.

    **A second run replaces what was staged, and reports a change.** That is an
    explicit exemption from the idempotency invariant, decided in issue #254: the
    invariant governs commands that converge on a state, and drawing a fresh
    random secret has no state to converge on. The run warns that it replaced a
    staged password, because anything already holding the old one is now stale.

    **One document is one write.** Where several accounts share a secret -- the
    documented default since issue #85 -- their passwords go in a single
    compare-and-set write under a single lock, not one write each. Each account
    still gets its own password: sharing a document is a storage layout, not a
    shared credential.

    **A compare-and-set conflict is never retried.** This run holds the lock, so
    a conflict means somebody outside this tool wrote to the document, and
    re-reading to merge over them would rewrite fields belonging to accounts
    nobody selected.

    `--from-stdin` takes one password on stdin and applies it to every selected
    account, for migration and for systems that dictate the value. It is
    validated by the same predicate a generated one is drawn against, and reads
    the policy length as a minimum rather than an exact figure.

    Help text stays ASCII throughout, which is P4's rule.
    """
    document = run.document
    refuse_if_readonly(run.resolved, action="staging a password")

    match = parse_selector(selectors)
    config = filter_estate(run.config, match)
    document.selection = as_dict(match) or None
    document.diagnostics.extend(config_diagnostics(config))

    config = binding_stores.complete(config, env=os.environ)
    binding_stores.refuse_unresolved(config, action="staging a password")

    plan = plan_builder.build(config, intent=["generate", "vault_write_pending"])
    refuse_if_over_limit(run.resolved, plan.blast_radius, action="staging a password")
    document.plan = plan.as_json()

    bindings = [binding for binding in config.bindings if binding.secret is not None]
    if not bindings:
        document.finish(ExitCode.SUCCESS, Summary())
        return render_plan(plan, noun="generation") + "\n\nnothing to stage"

    supplied = _password_from_stdin() if from_stdin else None
    candidates = [
        _candidate(
            binding, config, name=policy_name, supplied=supplied, enforce=not no_policy_check
        )
        for binding in bindings
    ]
    writes = staging.group(candidates)
    names = {write.key.store for write in writes}

    header = "\n".join(
        [render_plan(plan, noun="generation"), "", *render_write_table(writes, stage=PENDING)]
    )
    if run.dry_run:
        # Invariant 8: print the plan, write nothing, take no lock. No `results`
        # either -- `plan` already says what would happen, at the same grain, and
        # a second vocabulary for "would have" would be a state nobody can act on.
        document.finish(ExitCode.SUCCESS, Summary(total=len(candidates)))
        return f"{header}\n\nnothing was written (--dry-run)"

    stores = _stores_for(names, config, token_file=run.vault_token_file)
    manager = LockManager(
        stores={name: _lockable(name, config, stores) for name in names},
        correlation_id=document.correlation_id,
        command="creds generate",
        selection=", ".join(f"{key}={value}" for key, value in match) or None,
    )

    results: list[dict[str, Any]] = []
    rows: list[tuple[Candidate, str, str]] = []
    try:
        with manager.holding([write.key for write in writes]):
            for write in writes:
                rows.extend(_stage(write, stores[write.key.store], out=results))
    except LockDeniedError as denied:
        document.lock = build_lock_section(manager, denied=denied)
        raise

    document.lock = build_lock_section(manager)
    document.results = results
    states = [state for _, state, _ in rows]
    document.finish(
        ExitCode.FAILURE if FAILED in states else ExitCode.SUCCESS,
        summarise_generate(states),
    )
    return f"{header}\n\n{render_generate(rows)}"


def _lockable(name: str, config: Config, stores: Mapping[str, SecretStore]) -> LockableStore:
    """One already-opened store, paired with the locking policy declared for it.

    Reuses the connection `_stores_for` made rather than dialling again: a store
    is a client, and a run that authenticated once to write should not
    authenticate a second time to lock the thing it is writing.

    `locking` travels beside the client rather than being re-read later, which is
    :class:`~sopuli.lock.manager.LockableStore`'s own rule -- a command must not
    be able to disagree with what `config show` displayed about the same store.
    """
    locking = next(vault.locking for vault in config.vaults if vault.name == name)
    return LockableStore(store=stores[name], locking=locking)


def _candidate(
    binding: Binding,
    config: Config,
    *,
    name: str | None,
    supplied: Secret | None,
    enforce: bool,
) -> Candidate:
    """One account's password, drawn or validated against its policy.

    Resolved per binding rather than once for the run, because a selection
    spanning two applications with different policies is the ordinary case. Only
    `--policy` is global, and it is applied by overriding the binding's own name
    before the file's chain is consulted -- so it wins over an application entry
    and still goes through the same dangling-name check every policy name gets.

    ``limit`` is `None`: the byte limit is a property of the *target database*
    and reading it means connecting, which UC-1 marks optional and #254 leaves
    out. The policy's declared length governs, which is §4's own fallback.
    """
    effective = binding if name is None else replace(binding, policy=name)
    chosen, policy = staging.policy_for(config, effective)
    return staging.candidate_for(
        binding, policy, name=chosen, limit=None, supplied=supplied, enforce=enforce
    )


def _password_from_stdin() -> Secret:
    """Read one password from stdin (invariant 1: never from an option value).

    One trailing newline is stripped and nothing else is --
    :func:`sopuli.material.strip_one_newline`, *called* rather than restated. A
    password may legitimately end in a space, and a pipe appends a newline that
    was never part of it; the shared function also handles ``\r\n``, which a
    local copy of the rule did not, and Windows is precisely where P4 asks for
    identical behaviour.
    """
    text = strip_one_newline(sys.stdin.read())
    if not text:
        raise ArgumentError(
            "--from-stdin was given and stdin was empty",
            hint="pipe the password in, and check nothing else has already consumed stdin",
        )
    return Secret(text)


def _stage(
    write: DocumentWrite, store: SecretStore, *, out: list[dict[str, Any]]
) -> list[tuple[Candidate, str, str]]:
    """Perform one document's write, and report it per account.

    Every account in the document shares the outcome, because they share the
    write: one compare-and-set either landed or it did not, and reporting one of
    three as staged when it failed would describe a state that never existed.

    ``cas`` is the version that was there, or ``0`` for a document that does not
    exist yet -- which is not a version but an assertion that there is nothing at
    the path, and the one case a merge patch cannot serve.
    """
    existing = store.read(write.key.path)
    cas = 0 if existing is None else existing.version
    replaced = _already_pending(existing, write)

    try:
        written = write_credential(store, write.key.path, write.patch(stage=PENDING), cas=cas)
    except Exception as error:  # noqa: BLE001 -- a per-document finding
        reported = _as_error(error)
        return _reported(write, FAILED, reported.message, out=out, error=reported)

    return _reported(
        write,
        STAGED,
        f"staged v{written.version}",
        out=out,
        version=written.version,
        replaced=replaced,
        mechanism=written.mechanism,
    )


def _reported(
    write: DocumentWrite,
    state: str,
    detail: str,
    *,
    out: list[dict[str, Any]],
    version: int | None = None,
    replaced: Mapping[str, int] | None = None,
    mechanism: str | None = None,
    error: Error | None = None,
) -> list[tuple[Candidate, str, str]]:
    """One document's outcome, recorded per account.

    The *write* is shared, so the state and the version are; **what was replaced
    is not**. In a shared document one account can have had a `pending` staged
    while its neighbours did not, and telling the neighbours their password was
    replaced sends somebody looking for a credential that never existed. So the
    warning and the detail suffix are looked up per account.
    """
    replaced = replaced or {}
    rows = []
    for candidate in write.candidates:
        was = replaced.get(candidate.binding.account)
        line = detail if was is None else f"{detail}, replaced the pending in v{was}"
        out.append(
            build_generate_result(
                candidate,
                state=state,
                stage=PENDING,
                version=version,
                replaced=was,
                mechanism=mechanism,
                changed=state == STAGED,
                detail=line,
                error=error,
            )
        )
        rows.append((candidate, state, line))
    return rows


def _already_pending(existing: Any, write: DocumentWrite) -> dict[str, int]:
    """Which accounts had a ``pending`` this write is about to replace.

    Per account rather than per document, which is the distinction that matters
    in a shared layout: "nothing was staged" and "something was staged and is now
    gone" are different things to tell an operator, and only the second means a
    password somebody may be holding has just become worthless. Reporting the
    document's answer for every account in it would attach that warning to
    accounts it was never true of.

    The version is the document's own -- there is one per document, and it is
    what an operator would go and read the old value back from.
    """
    if existing is None:
        return {}
    found: dict[str, int] = {}
    for candidate in write.candidates:
        ref = candidate.binding.secret
        if ref is not None and stage_layout(ref).read(existing.data, PENDING) is not None:
            found[candidate.binding.account] = int(existing.version)
    return found


@creds_group.command("apply")
@select_option
@click.option(
    "--strategy",
    type=click.Choice(STRATEGIES),
    default=None,
    help=(
        "Rollover regime. Default: rollover where the database and the account's "
        "profile allow it, staged otherwise. An explicit one the estate cannot "
        "honour is refused before anything is changed."
    ),
)
@click.option(
    "--lockout-margin",
    type=click.IntRange(0, 100),
    default=DEFAULT_MARGIN,
    show_default=True,
    help="Refuse to attempt a login within this many tries of the lockout limit.",
)
@global_options
def creds_apply(
    selectors: tuple[str, ...], strategy: str | None, lockout_margin: int, run: Invocation
) -> str:
    """Make each database hold what the vault holds, then promote what it staged.

    **The direction is always vault to database** (invariant 6). Nothing here
    reads a password out of a database, and there is no flag that would make it.

    **The database is asked before it is changed.** Invariant 9 names this the
    convergent verb -- the one that must report `changed: false` on a re-run --
    and with hash verification unavailable (issue #86, issue #90) the only way to
    know whether a change is needed is a login. So every account is verified
    first, under the same lockout mitigations `creds check` uses, and a password
    that already works is left alone. Two logins per account per run, budgeted up
    front rather than counted afterwards.

    **A locked account is not changed at all.** The statement would succeed and
    the verification could never pass, which would end the run holding a database
    whose password is in no vault stage -- the state the `pending` ordering exists
    to keep a run out of. An expired one *is* changed: setting a password clears
    the expiry, which is UC-1 section 6.4's own reading of ORA-28001.

    **The promotion is the commit, and it is per document.** The unit of work is
    the target and the unit of the commit is the secret document: `previous` takes
    what `current` held, `current` takes what `pending` held, and `pending` is
    cleared -- in one compare-and-set write, under the lock this run already
    holds, and only once **every** target for **every** account in that document
    has confirmed. A run touching two documents may promote one and not the
    other.

    **The rollover regime is chosen per account, and refused as a whole.** Where
    the database has gradual password rollover and the account's profile grants a
    window, that is the default -- both passwords authenticate until the window
    closes, so a partial apply causes no outage. `--strategy` names one instead,
    and an explicit one the estate cannot honour is refused before anything is
    changed rather than discovered halfway through. `--strategy staged` against a
    profile that grants a window is one of those refusals: Oracle opens the window
    because the profile says so, whatever this run asked for.

    **Nothing is promoted that was not confirmed** (invariant 7). Where some
    targets confirmed and others did not, the database is left changed where it
    changed, `pending` stays, the run exits 4, and the accounts involved carry a
    warning saying so -- because applications fetch `current`, and until the
    promotion lands they are fetching a password part of the estate no longer
    has. Re-running is the remedy and is safe.

    Help text stays ASCII throughout, which is P4's rule.
    """
    document = run.document
    refuse_if_readonly(run.resolved, action="applying a password")

    match = parse_selector(selectors)
    config = filter_estate(run.config, match)
    document.selection = as_dict(match) or None
    document.diagnostics.extend(config_diagnostics(config))

    config = binding_stores.complete(config, env=os.environ)
    binding_stores.refuse_unresolved(config, action="applying a password")

    plan = plan_builder.build(config, intent=["verify", "password_set", "vault_promote"])
    refuse_if_over_limit(run.resolved, plan.blast_radius, action="applying a password")
    document.plan = plan.as_json()

    bindings = [binding for binding in config.bindings if binding.secret is not None]
    if not bindings:
        document.finish(ExitCode.SUCCESS, Summary())
        return render_plan(plan, noun="apply") + "\n\nnothing to apply"

    keys = _document_keys(bindings)
    stores = _stores_for({key.store for key in keys}, config, token_file=run.vault_token_file)

    if run.dry_run:
        # Invariant 8: print the plan, take no lock, write nothing. The documents
        # are still *read*, because which stage an account would be applied from
        # is the thing worth reviewing and a read needs no lock -- `check` runs
        # its whole survey without one.
        sources = _sources(bindings, _read_documents(keys, stores))
        document.finish(ExitCode.SUCCESS, Summary(total=len(sources)))
        return f"{_header(plan, sources)}\n\nnothing was applied (--dry-run)"

    manager = LockManager(
        stores={name: _lockable(name, config, stores) for name in {key.store for key in keys}},
        correlation_id=document.correlation_id,
        command="creds apply",
        selection=", ".join(f"{key}={value}" for key, value in match) or None,
    )

    try:
        with manager.holding(keys):
            # Read under the lock, not before it. A document read first and locked
            # afterwards is one a concurrent `creds generate` may have staged into
            # in between -- and this run would then apply one password and promote
            # a different one.
            documents = _read_documents(keys, stores)
            sources = _sources(bindings, documents)
            _refuse_unhonourable_strategy(sources, run, config, strategy=strategy)
            applied = _apply_estate(sources, run, config, margin=lockout_margin, strategy=strategy)
            promotions = _promote_documents(applied, documents, stores)
    except LockDeniedError as denied:
        document.lock = build_lock_section(manager, denied=denied)
        raise

    document.lock = build_lock_section(manager)
    document.results = [_applied_json(record, promotions) for record in applied]
    states = [record.outcome.state for record in applied]
    changed = sum(1 for record in applied if record.changed)
    document.finish(
        apply_states.exit_code_for(
            states,
            # Both questions are asked of the documents that actually read a
            # `pending`. A repair -- a document whose accounts were applied from
            # `current` -- has nothing to promote, so counting it as unpromoted
            # would make a mixed run look like UC-1 §8 case 7 and exit 4 with
            # everything confirmed and nothing wrong.
            promoted=all(one.version is not None for one in promotions.values() if one.staged),
            staged=any(one.staged for one in promotions.values()),
        ),
        summarise_apply(states, changed=changed),
    )
    rows = [(record.binding, record.outcome, record.changed) for record in applied]
    promoted = sum(1 for one in promotions.values() if one.version is not None)
    return f"{_header(plan, sources)}\n\n{render_apply(rows, promoted=promoted)}"


@dataclass(frozen=True)
class _Applied:
    """One (account, target) after `creds apply` has finished with it.

    Held rather than reported immediately because a promotion is decided *after*
    every target has been visited, and its version belongs on the row of every
    account in the document it promoted. Building `results[]` as the run went
    would mean either omitting that version or rewriting entries already emitted.
    """

    binding: Binding
    source: Source | None
    outcome: check_states.Outcome
    changed: bool
    verified_before: Any | None = None
    version: int | None = None
    rollover: dict[str, Any] | None = None
    duration_ms: int | None = None
    error: Error | None = None


@dataclass(frozen=True)
class _Promotion:
    """What happened to one document once its targets were all in.

    ``version`` is ``None`` for a document that was not promoted, and ``reason``
    says which of the two cases that is: nothing needed promoting, or something
    did and the estate had not earned it.

    ``staged`` is what keeps those two apart for the exit code. A document whose
    accounts were applied from `current` is a repair: it has nothing to promote,
    and its ``version: None`` must not read as a promotion this run owed and did
    not make. Only the staged ones are asked about.
    """

    version: int | None
    reason: str
    staged: bool = False
    mechanism: str | None = None
    error: Error | None = None


def _document_keys(bindings: Sequence[Binding]) -> list[LockKey]:
    """Every secret document this run touches, in acquisition order.

    The same key `creds generate` writes under and `lock status` prints, through
    the same normaliser -- so a run that stages and a run that applies contend on
    exactly the paths they share. Sorted by
    :func:`~sopuli.lock.keys.acquisition_order`, where the ordering is a deadlock
    property rather than a presentation one.
    """
    found = {
        LockKey(store=binding.vault, path=normalise_path(binding.secret.path))
        for binding in bindings
        if binding.secret is not None and binding.vault is not None
    }
    return list(acquisition_order(found))


def _read_documents(
    keys: Sequence[LockKey], stores: Mapping[str, SecretStore]
) -> dict[LockKey, Any]:
    """Each document once, whole.

    Whole rather than per ref, and once rather than per account, for two reasons
    that both matter. A promotion needs what ``current`` held in order to write
    it into ``previous``, so the read has to see more than the value being
    applied; and a document shared by six accounts read six times could return
    six different versions, which is a compare-and-set nobody could reason about.
    """
    return {key: stores[key.store].read(key.path) for key in keys}


def _sources(
    bindings: Sequence[Binding], documents: Mapping[LockKey, Any]
) -> list[tuple[Binding, Source | None]]:
    """What each account would be applied from, in binding order.

    ``None`` where the vault holds neither stage. Kept in the list rather than
    filtered out, because an account the config declares and the vault has
    nothing for is a finding this command must report -- dropping it here would
    make it disappear from a run that was explicitly asked about it.
    """
    found = []
    for binding in bindings:
        stored = _stored_document(binding, documents)
        source = (
            None
            if binding.secret is None or stored is None
            else apply_states.source_for(stored.data, binding.secret)
        )
        found.append((binding, source))
    return found


def _stored_document(binding: Binding, documents: Mapping[LockKey, Any]) -> Any:
    if binding.secret is None or binding.vault is None:
        return None
    return documents.get(LockKey(store=binding.vault, path=normalise_path(binding.secret.path)))


def _header(plan: Any, sources: Sequence[tuple[Binding, Source | None]]) -> str:
    """The plan, and what would be applied from where."""
    rows = [(binding, source) for binding, source in sources if source is not None]
    if not rows:
        return render_plan(plan, noun="apply")
    return "\n".join([render_plan(plan, noun="apply"), "", *render_source_table(rows)])


def _apply_estate(
    sources: Sequence[tuple[Binding, Source | None]],
    run: Invocation,
    config: Config,
    *,
    margin: int,
    strategy: str | None,
) -> list[_Applied]:
    """Every account, target by target, one connection each.

    Grouped the way `check` groups and for the same reason: a target with six
    accounts in it is one login for this tool rather than six, and six would be
    six entries in that database's audit trail for one rotation.
    """
    by_target = {expanded.name: expanded for expanded in config.expanded_targets}
    grouped: dict[str, list[tuple[Binding, Source | None]]] = {}
    for binding, source in sources:
        grouped.setdefault(binding.target, []).append((binding, source))

    applied: list[_Applied] = []
    for name, work in grouped.items():
        applied.extend(
            _apply_target(by_target[name], work, run, config, margin=margin, strategy=strategy)
        )
    return applied


def _apply_target(
    target: ExpandedTarget,
    work: Sequence[tuple[Binding, Source | None]],
    run: Invocation,
    config: Config,
    *,
    margin: int,
    strategy: str | None,
) -> list[_Applied]:
    """One target's worth of accounts, over one connection.

    A target that cannot be reached is a finding rather than a crash, which is
    `check`'s rule and `doctor`'s -- but it means something stronger here: the
    accounts bound to it are `ERROR`, so the documents they belong to are not
    promoted, so a database that could not be reached cannot cause a password it
    does not have to be advertised to applications.
    """
    started = time.monotonic()
    session = None
    try:
        try:
            module = resolve_driver(target.target)
            credential = admin_resolve(target, env=os.environ)
            driver = module.OracleDriver(
                env=os.environ,
                correlation_id=run.document.correlation_id,
                timeouts=_timeouts(run),
                client_lib_dir=config.runtime.oracle.client_lib_dir,
            )
            session = driver.connect(target, credential.credential)
        except Exception as error:  # noqa: BLE001 -- a per-target finding
            reported = _as_error(error)
            elapsed = _elapsed(started)
            return [
                _Applied(
                    binding=binding,
                    source=source,
                    outcome=check_states.Outcome(check_states.ERROR, reported.message),
                    changed=False,
                    duration_ms=elapsed,
                    error=reported,
                )
                for binding, source in work
            ]

        return [
            _apply_one(binding, session, source=source, margin=margin, strategy=strategy)
            for binding, source in work
        ]
    finally:
        if session is not None:
            with suppress(Exception):
                session.close()


def _apply_one(
    binding: Binding,
    session: Any,
    *,
    source: Source | None,
    margin: int,
    strategy: str | None,
) -> _Applied:
    """One account in one target: ask, change if needed, ask again.

    UC-1 §5's flow with its two verifications, and the budget declared once:
    ``attempts=2`` says how many logins this run intends against this account, so
    the lockout guard reserves both before spending the first. Asking for one and
    then asking again would let a run spend two attempts on a counter the guard
    was protecting from spending two.

    ``strategy`` is ``None`` for the default, which is resolved **per account**:
    two accounts in one database can sit on different profiles, and only one of
    them may grant a rollover window. An explicit one has already been refused
    where it could not run (:func:`_refuse_unhonourable_strategy`), so by here it
    is a regime this account can honour.
    """
    started = time.monotonic()
    before = None
    try:
        user = session.describe_user(binding.account)
        settled = apply_states.settled_before_acting(user, source)
        if settled is not None:
            return _Applied(binding, source, settled, changed=False, duration_ms=_elapsed(started))
        if user is None or source is None:
            # Unreachable: `settled_before_acting` returns an outcome for both.
            # Restated rather than assumed, because a fall-through here would
            # decide a mutation on a value nobody checked.
            raise ValueError(f"nothing to apply for {binding.account!r} and no reason given")

        regime = strategy or strategies.default_for(session.scope(), user)
        before = session.verify_password(
            user.name, source.value, method=VERIFY_LOGIN, lockout_margin=margin, attempts=2
        )
        done = apply_states.already_applied(user, before, source=source)
        if done is not None:
            return _Applied(
                binding,
                source,
                done,
                changed=False,
                verified_before=before,
                rollover=_rollover_json(user),
                duration_ms=_elapsed(started),
            )

        session.set_password(user.name, source.value)
        # Re-read the account rather than reusing what was read before the change:
        # `EXPIRED` clears when a password is set, a rollover window opens, and a
        # lock may have arrived in between. The state reported has to be the one
        # that is true now.
        after_user = session.describe_user(binding.account) or user
        after = session.verify_password(
            after_user.name, source.value, method=VERIFY_LOGIN, lockout_margin=margin, attempts=2
        )
        outcome = apply_states.after_change(after_user, after)

        if strategies.closes_window(regime, after_user) and apply_states.is_confirmed(
            outcome.state
        ):
            # `--strategy direct`, and only now. Closing the window before the
            # change was confirmed would leave an account whose old password has
            # stopped working and whose new one is not known to work -- the one
            # state worse than the grace period `direct` exists to avoid.
            session.finish_rollover(after_user.name)
            after_user = session.describe_user(binding.account) or after_user
            outcome = apply_states.after_change(after_user, after)
    except Exception as error:  # noqa: BLE001 -- a per-account finding
        reported = _as_error(error)
        return _Applied(
            binding,
            source,
            check_states.Outcome(check_states.ERROR, reported.message),
            changed=False,
            verified_before=before,
            duration_ms=_elapsed(started),
            error=reported,
        )

    return _Applied(
        binding,
        source,
        _with_regime(outcome, regime, after_user),
        changed=True,
        verified_before=before,
        rollover=_rollover_json(after_user),
        duration_ms=_elapsed(started),
    )


def _with_regime(
    outcome: check_states.Outcome, regime: str, user: UserState
) -> check_states.Outcome:
    """The outcome, plus what the regime did that it does not already say.

    Only `direct` adds anything: `rollover` reaches `ROLLOVER_ACTIVE`, whose own
    sentence says the previous password still authenticates, and `staged` is an
    ordinary password change. Appending a clause for all three would put the same
    fact in the row twice for two of them.
    """
    extra = strategies.extra_detail(regime, user)
    if extra is None:
        return outcome
    return check_states.Outcome(outcome.state, f"{outcome.detail}; {extra}", outcome.verification)


def _rollover_json(user: UserState) -> dict[str, Any]:
    """``results[].rollover``: the window, and the profile that decides it.

    Emitted for every account this run acted on rather than only for the ones
    with an open window, because the *absence* of one is the answer to "did the
    old password stop working just now" -- and ``profile_rollover_time`` beside
    it says whether that was the regime asked for or the only one available.
    """
    found: dict[str, Any] = {
        "active": bool(user.rollover_active),
        "profile_rollover_time": user.rollover_time,
    }
    if user.rollover_ends_at is not None:
        # Omitted rather than null: the schema types `ends_at` as a timestamp and
        # not as a nullable one, and there is no deadline to report when no
        # window is open. `active: false` already says that.
        found["ends_at"] = to_rfc3339(user.rollover_ends_at)
    return found


def _open_session(target: ExpandedTarget, run: Invocation, config: Config) -> Any:
    """One connection to one target, with the admin credential P2 resolves.

    Extracted because two passes need it: the pre-flight that refuses a strategy
    the estate cannot honour, and the run that applies. Identical in both, which
    is the point -- a pre-flight that connected differently would be clearing a
    different thing from the one that runs.
    """
    module = resolve_driver(target.target)
    credential = admin_resolve(target, env=os.environ)
    driver = module.OracleDriver(
        env=os.environ,
        correlation_id=run.document.correlation_id,
        timeouts=_timeouts(run),
        client_lib_dir=config.runtime.oracle.client_lib_dir,
    )
    return driver.connect(target, credential.credential)


def _refuse_unhonourable_strategy(
    sources: Sequence[tuple[Binding, Source | None]],
    run: Invocation,
    config: Config,
    *,
    strategy: str | None,
) -> None:
    """Refuse an explicitly requested strategy the estate cannot honour (#262).

    **Nothing has been mutated when this raises**, which is what invariant 4 asks
    for and what costs a second connection per target. The cost is opt-in: with no
    ``--strategy`` there is nothing to refuse, because the regime is then chosen
    per account from what that account can actually do, so this returns
    immediately and the run pays nothing.

    That trade is the whole design. An operator who names a regime is asking for
    a property of the *estate* -- "no application will see a failed login
    tonight" -- and a run that honoured it on four PDBs and discovered on the
    fifth that it could not would already have broken the promise. One extra
    connection per target buys the promise being kept or refused, never
    half-kept.

    **A target that cannot be reached is skipped rather than refused.** It is a
    finding the run itself reports, per account and with the vendor code, and
    turning it into a plan-time refusal here would make an unreachable database
    look like a strategy problem.
    """
    if strategy is None:
        return

    by_target = {expanded.name: expanded for expanded in config.expanded_targets}
    grouped: dict[str, list[Binding]] = {}
    for binding, source in sources:
        if source is not None:
            grouped.setdefault(binding.target, []).append(binding)

    for name, bindings in grouped.items():
        try:
            session = _open_session(by_target[name], run, config)
        except Exception:  # noqa: BLE001 -- the run reports this per account
            continue
        try:
            _check_strategy(session, bindings, strategy=strategy, target=name)
        finally:
            with suppress(Exception):
                session.close()


def _check_strategy(
    session: Any, bindings: Sequence[Binding], *, strategy: str, target: str
) -> None:
    """Every account in one target, against one requested regime.

    Rollover goes through the driver's own ``require_rollover``, which owns both
    of its refusals and carries the exact ``ALTER PROFILE`` for the second
    (#181). The other two are :mod:`sopuli.strategy`'s, because they are about
    the regime the operator asked for rather than about anything the driver
    knows.

    An account the database does not have is skipped, for **every** regime:
    ``ACCOUNT_MISSING`` is a state the run reports per account, and refusing the
    whole estate over one would turn a per-account finding into a plan-time
    failure. The check is here rather than inside each branch because
    ``require_rollover`` raises for a missing account too -- it has no way to
    know this caller would rather skip it -- so a rollover pre-flight that asked
    it first would refuse an estate over an account the run was going to report
    on anyway.

    That means the rollover branch reads the account twice, once here and once
    inside ``require_rollover``. Deliberate: the driver owns that refusal
    (#181) and reads what it needs for it, and one extra query on a pre-flight
    that only runs under an explicit ``--strategy`` is a cheaper thing to spend
    than a second copy of the refusal.
    """
    for binding in bindings:
        user = session.describe_user(binding.account)
        if user is None:
            continue
        if strategy == strategies.ROLLOVER:
            session.require_rollover(binding.account)
            continue
        refusal = strategies.unhonourable(strategy, session.scope(), user)
        if refusal is None:
            continue
        if refusal.capability is not None:
            raise UnsupportedCapabilityError(refusal.capability, target=target, hint=refusal.hint)
        raise DriverError(
            f"--strategy {strategy} cannot run for {binding.account!r} in {target!r}: "
            f"{refusal.message}",
            hint=refusal.hint,
        )


def _promote_documents(
    applied: Sequence[_Applied],
    documents: Mapping[LockKey, Any],
    stores: Mapping[str, SecretStore],
) -> dict[LockKey, _Promotion]:
    """Promote every document whose targets all confirmed, and only those.

    Invariant 7's ordering, and the one place in this command where the two
    groupings meet: results arrive per (account, target) and the commit is per
    document, so the gate is *every pair belonging to the accounts in this
    document*.

    A document nobody staged into is not promoted and is not a failure -- a run
    that read `current` is a repair, and the vault already holds what it should.
    """
    promotions: dict[LockKey, _Promotion] = {}
    for key, records in _by_document(applied).items():
        staged = [
            record
            for record in records
            if record.source is not None and record.source.stage == PENDING
        ]
        if not staged:
            promotions[key] = _Promotion(None, "nothing was staged for this document")
            continue
        if not apply_states.summarise_document(record.outcome.state for record in records):
            promotions[key] = _Promotion(
                None, "not every target confirmed, so `pending` was left in place", staged=True
            )
            continue
        promotions[key] = _write_promotion(key, staged, documents[key], stores[key.store])
    return promotions


def _by_document(applied: Sequence[_Applied]) -> dict[LockKey, list[_Applied]]:
    """Results grouped by the document their account's credential lives in."""
    grouped: dict[LockKey, list[_Applied]] = {}
    for record in applied:
        binding = record.binding
        if binding.secret is None or binding.vault is None:
            continue
        key = LockKey(store=binding.vault, path=normalise_path(binding.secret.path))
        grouped.setdefault(key, []).append(record)
    return grouped


def _write_promotion(
    key: LockKey, staged: Sequence[_Applied], stored: Any, store: SecretStore
) -> _Promotion:
    """The one compare-and-set that makes a rotation visible to applications.

    ``cas`` is the version read at the start of this run, under the lock this run
    holds. A conflict therefore means a writer outside this tool, and it is never
    retried: re-reading to merge over them would rewrite fields belonging to
    accounts nobody selected.

    One account may be bound to several targets and so appear several times; the
    promotion is per account, so they are collapsed here rather than written
    once per target.
    """
    entries = []
    for record in _one_per_account(staged):
        source = record.source
        if source is None:  # pragma: no cover - `staged` is filtered on it
            continue
        entries.append(
            apply_states.Promotable(
                binding=record.binding,
                value=source.value,
                replaces=source.replaces,
                policy=record.binding.policy,
                targets=tuple(
                    one.binding.target
                    for one in staged
                    if one.binding.account == record.binding.account
                ),
            )
        )
    patch = apply_states.promotion_patch(entries, at=utc_now(), by=_rotated_by())
    try:
        written = write_credential(store, key.path, patch, cas=_version_of(stored))
    except Exception as error:  # noqa: BLE001 -- a per-document finding
        reported = _as_error(error)
        return _Promotion(None, reported.message, staged=True, error=reported)
    return _Promotion(
        written.version,
        f"promoted to v{written.version}",
        staged=True,
        mechanism=written.mechanism,
    )


def _one_per_account(records: Sequence[_Applied]) -> list[_Applied]:
    """The first record for each account, in the order they were applied."""
    seen: dict[str, _Applied] = {}
    for record in records:
        seen.setdefault(record.binding.account, record)
    return list(seen.values())


def _version_of(stored: Any) -> int:
    """The document's version, or ``0`` for one that does not exist yet.

    Zero is not a version but an assertion that there is nothing at the path,
    which is `creds generate`'s own reading of it -- and here it should never
    fire, because a promotion follows something having been staged.
    """
    return 0 if stored is None else int(stored.version)


def _rotated_by() -> str:
    """UC-1 §3's `rotated_by` stamp: who ran this.

    The same identity the advisory lock records about its holder
    (:func:`sopuli.lock.record.current_holder`), rather than a second notion of
    who is running -- a document saying one thing and the lock beside it saying
    another would be two answers to the question an audit asks first.
    """
    holder = current_holder()
    return f"{holder.os_user}@{holder.host}"


def _applied_json(record: _Applied, promotions: Mapping[LockKey, _Promotion]) -> dict[str, Any]:
    """One `results[]` entry, once the promotion for its document is known."""
    binding = record.binding
    promotion = None
    if binding.secret is not None and binding.vault is not None:
        promotion = promotions.get(
            LockKey(store=binding.vault, path=normalise_path(binding.secret.path))
        )
    return build_apply_result(
        binding,
        record.outcome,
        source=record.source,
        version=record.version,
        changed=record.changed,
        verified_before=record.verified_before,
        rollover=record.rollover,
        promoted_to=None if promotion is None else promotion.version,
        mechanism=None if promotion is None else promotion.mechanism,
        duration_ms=record.duration_ms,
        error=record.error,
    )


if __name__ == "__main__":  # pragma: no cover
    main()

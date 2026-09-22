"""The ``sopuli`` command line.

Grammar is noun-verb (D2): ``sopuli <noun> <verb>``. Each noun is a
:class:`click.Group`, each verb a command inside it. The ``config`` verbs,
``target list`` and ``policy sample`` touch nothing outside the file; ``lock
status`` is the first verb that opens a socket and ``lock break`` the first that
writes through one, and both seams are worth keeping visible rather than letting
them blur one command at a time.

Six things about the structure are deliberate:

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

**One command is not a run at all** (#413). ``about`` prints compiled-in text:
no options, no configuration, no settings, no estate, no socket, and no
``--output json`` form. So it is the one command in this file without
:func:`~sopuli.invocation.global_options`, the one that receives no
:class:`~sopuli.invocation.Invocation`, and the one absent from the JSON
contract's ``command`` enum. That is the footing ``--version`` and ``--help``
stand on; what makes it a verb rather than a flag is that ``--version`` has to
stay one greppable line, and that a bare top-level command is D2's grammar
rather than an exception to it -- ``doctor`` is already that shape.
``tests/test_cli_precedence.py`` names it in ``NOT_A_RUN`` and then holds the
whole shape, so it cannot half-rejoin the machinery by accident.

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
from contextlib import nullcontext, suppress
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, TypeVar

import click

from sopuli import account_list, preflight, reset, reset_record, suspend
from sopuli import apply as apply_states
from sopuli import check as check_states
from sopuli import constraints as constraint_source
from sopuli import finish_rollover as windows
from sopuli import generate as staging
from sopuli import plan as plan_builder
from sopuli import repair as repair_module
from sopuli import rotate as rotation
from sopuli import status as status_states
from sopuli import strategy as strategies
from sopuli.admin import AdminCredentialError, RefReader
from sopuli.admin import Resolved as AdminResolved
from sopuli.admin import resolve as admin_resolve
from sopuli.admin import store_name as admin_store_name
from sopuli.apply import SOURCES, Source
from sopuli.clock import as_utc, to_rfc3339, utc_now
from sopuli.config import (
    ROOT,
    ArgumentError,
    Binding,
    Config,
    ConfigError,
    ExpandedTarget,
    PasswordPolicy,
    Selection,
    binding_stores,
    dangling,
    filter_estate,
    filter_to_pairs,
    parse_selector,
    refuse_unknown,
)
from sopuli.config.expansion import declared_at
from sopuli.config.model import Delivery, PersonalAccountRule
from sopuli.config.secret_refs import SecretRef
from sopuli.config.vault_env import ADDR_FLAG, DEFAULT_STORE_VARIABLE
from sopuli.constraints import AccountConstraints, Constraints
from sopuli.diagnostics import (
    CONSTRAINTS_UNREAD,
    LOCK_LOST,
    LOCK_PATH_UNGUARDED,
    LOGIN_WARNING,
    LOW_ASSURANCE_ADMIN,
    PASSWORD_CHANGE_DATE_UNKNOWN,
    PASSWORD_GRACE_PERIOD,
    ROTATION_UNCONFIRMED,
    admin_diagnostics,
    constraint_diagnostics,
    guardrail_diagnostics,
    install_diagnostics,
    lock_broken,
    lock_diagnostics,
    no_reset_journal,
    no_reset_record,
    reset_record_unwritten,
    unlistable_stores,
    vault_diagnostics,
    wallet_diagnostics,
)
from sopuli.driver import guardrails
from sopuli.driver.oracle.client import (
    Timeouts,
    describes_unreachable_server,
    reach_floor,
)
from sopuli.driver.oracle.verification import DEFAULT_MARGIN
from sopuli.driver.oracle.wallet import survey as wallet_survey
from sopuli.driver.protocol import (
    ACCOUNT_UNLOCK,
    ATTRIBUTE_SET,
    FAIL,
    PASS,
    VERIFY_LOGIN,
    AccountAttributes,
    AttributeChange,
    DriverError,
    UnsupportedCapabilityError,
    UserState,
    VerifyResult,
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
    check_vault_token,
    global_options,
    group_options,
)
from sopuli.lock.errors import LockDeniedError, LockError, LockStolenError
from sopuli.lock.inspect import declared_locks, mode_of, resolvable_locks, survey
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
from sopuli.output.about_view import render as render_about
from sopuli.output.account_list_view import build_result as build_account_list_result
from sopuli.output.account_list_view import render_account_list
from sopuli.output.account_list_view import summarise as summarise_account_list
from sopuli.output.apply_view import build_result as build_apply_result
from sopuli.output.apply_view import render_apply, render_source_table, repair_invocation
from sopuli.output.apply_view import summarise as summarise_apply
from sopuli.output.check_view import build_result, render_check, summarise
from sopuli.output.color import ColorChoice
from sopuli.output.config_view import (
    build_section,
    render_target_list,
    render_text,
    render_validation,
)
from sopuli.output.constraints_view import build_constraints, render_constraints
from sopuli.output.doctor_view import build_target
from sopuli.output.doctor_view import render as render_doctor
from sopuli.output.document import Diagnostic, Error, RunDocument, Summary
from sopuli.output.emit import Emitter
from sopuli.output.finish_rollover_view import build_result as build_finish_result
from sopuli.output.finish_rollover_view import render_finish, render_window_table
from sopuli.output.finish_rollover_view import summarise as summarise_finish
from sopuli.output.generate_view import (
    FAILED,
    STAGED,
    VAULT_ONLY,
    WRITTEN,
    render_generate,
    render_promotion_table,
    render_write_table,
)
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
from sopuli.output.notices import render_notices
from sopuli.output.plan_view import render_plan
from sopuli.output.policy_view import build_section as build_policy_section
from sopuli.output.policy_view import describe_all, render_samples
from sopuli.output.preflight_view import render_preflight
from sopuli.output.reset_view import build_result as build_reset_result
from sopuli.output.reset_view import render as render_reset
from sopuli.output.reset_view import render_password
from sopuli.output.reset_view import summarise as summarise_reset
from sopuli.output.rotate_view import render_rotate, render_selection_table
from sopuli.output.status_view import build_result as build_status_result
from sopuli.output.status_view import render_status_table
from sopuli.output.status_view import summarise as summarise_status
from sopuli.output.stream import configure_streams
from sopuli.output.suspend_view import build_result as build_suspend_result
from sopuli.output.suspend_view import render as render_suspend
from sopuli.output.suspend_view import summarise as summarise_suspend
from sopuli.output.tty import is_a_terminal
from sopuli.output.vault_view import build as build_vault
from sopuli.output.vault_view import render as render_vaults
from sopuli.output.wallet_view import build as build_wallet
from sopuli.output.wallet_view import render as render_wallet
from sopuli.passwords import ByteLimit, generate
from sopuli.payload import CURRENT, ORIGIN, PENDING, PREVIOUS, stage_layout
from sopuli.personal import declared_on
from sopuli.preflight import Finding
from sopuli.safety import (
    RefusedError,
    confirmation_demanded,
    for_estate,
    refuse_disallowed_method,
    refuse_if_over_limit,
    refuse_if_readonly,
    refuse_unconfirmed,
)
from sopuli.secrets import Secret
from sopuli.status import Row
from sopuli.store import SecretStore, StoreError, connect
from sopuli.store.credentials import StoredSecret, read_secret, resolve
from sopuli.store.credentials import apply_patch as write_credential
from sopuli.store.survey import VaultReport
from sopuli.store.survey import survey as vault_survey
from sopuli.strategy import STRATEGIES
from sopuli.version import get_version

F = TypeVar("F", bound=Callable[..., Any])

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


def select_option(func: F) -> F:
    """The selectors, for the commands that act on the estate (#297).

    Deliberately not in :func:`~sopuli.invocation.global_options`. ``config validate`` answers
    "does this file parse", which no selector narrows, and an option that
    silently means nothing on some of the commands carrying it is the same
    defect as ignoring one that does.

    That rule is also why all five are one decorator rather than a target-shaped
    set and an account-shaped set. An account selector narrows *targets* too, by
    dropping the ones left with no bindings
    (:func:`~sopuli.config.selection.filter_estate`), so `--account` on
    ``target list`` means "the targets where this account lives" rather than
    nothing at all -- and every command carrying the flags is narrowed by every
    one of them.

    **Names are refused when they name nothing; labels are not.** `--select
    env=nosuch` is an empty run, because labels describe an estate that changes.
    `--target nosuch` is a typo, and the run that quietly did nothing and exited
    0 is how a scheduled rotation stops rotating without anybody noticing. See
    :func:`~sopuli.config.selection.refuse_unknown`.

    ``--app`` is an accepted alias for ``--application``, which
    ``01-configuration.md`` §3 has documented since before either existed.
    """
    for option in (
        click.option(
            "--application",
            "--app",
            "applications",
            multiple=True,
            metavar="NAME",
            help="Keep only this application entry's accounts. Repeat to add more.",
        ),
        click.option(
            "--group",
            "groups",
            multiple=True,
            metavar="NAME",
            help="Keep only targets in this group. Repeat to add more.",
        ),
        click.option(
            "--account",
            "accounts",
            multiple=True,
            metavar="NAME",
            help="Keep only this account, and the targets it lives on. Repeat to add more.",
        ),
        click.option(
            "--target",
            "targets",
            multiple=True,
            metavar="NAME",
            help="Keep only this target. Repeat to add more.",
        ),
        click.option(
            "--select",
            "selectors",
            multiple=True,
            metavar="K=V[,K=V]",
            help="Keep only targets carrying every label. Repeat to add more.",
        ),
    ):
        func = option(func)
    return func


def selected(
    selectors: tuple[str, ...],
    targets: tuple[str, ...],
    accounts: tuple[str, ...],
    groups: tuple[str, ...],
    applications: tuple[str, ...],
) -> Selection:
    """The five flags as one value, with the labels parsed.

    Every command that narrows an estate does it identically, so the assembly is
    here rather than repeated ten times -- and the run document reports the set
    as given, which is only true if there is one object that *is* what was given.
    """
    return Selection(
        select=parse_selector(selectors),
        targets=targets,
        accounts=accounts,
        groups=groups,
        applications=applications,
    )


def describe_selection(selection: Selection) -> str | None:
    """How a lock record spells what this run was narrowed to (#83).

    One line, in the flags the operator typed, because the record is printed at
    exit 7 to somebody deciding whether to wait for the holder or go and find
    them -- and "which part of the estate" is most of that decision. ``None``
    for an unnarrowed run, which the record then omits rather than carrying an
    empty string.

    Nothing in it is a value: label pairs and the names of things the
    configuration already declares.
    """
    parts = [f"{key}={value}" for key, value in selection.select]
    for flag, names in (
        ("target", selection.targets),
        ("account", selection.accounts),
        ("group", selection.groups),
        ("application", selection.applications),
    ):
        parts.extend(f"{flag}={name}" for name in names)
    return ", ".join(parts) or None


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
    vault_addr: str | None,
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
        vault_addr=vault_addr,
    )


def about_refusals(given: GlobalOptions) -> list[str]:
    """Which group-level options were written that ``about`` cannot honour.

    `about` takes no options of its own, but the group's parser accepts the
    global ones before any subcommand -- so they arrive on
    :class:`~sopuli.invocation.GlobalOptions` whether or not the command has any
    use for them. Dropping them would be the failure `config show` refuses for a
    selector it cannot apply, and for the same reason: the run looks like it did
    what was asked. So they are refused instead, by name.

    ``--color`` is absent because it is the one this command honours.
    ``--dry-run`` is absent because the group's copy refuses for itself
    (:func:`~sopuli.invocation.trailing_only`) before this runs, and
    ``--vault-token`` because :func:`~sopuli.invocation.check_vault_token` owns
    a better message for it than a list of flag names -- ADR-007's, naming every
    source that does work.
    """
    written = []
    if given.config_paths:
        written.append("--config")
    if given.output_mode is not None:
        written.append("--output")
    if given.profile_name is not None:
        written.append("--profile")
    if given.vault_token_file is not None:
        written.append("--vault-token-file")
    if given.vault_addr is not None:
        written.append(ADDR_FLAG)
    return written


@cli.command("about")
@click.pass_obj
def about(options: GlobalOptions | None) -> None:
    """Show the sopuli-dba banner, tagline, and project links.

    Static, compiled-in text and nothing else: the same output on every machine,
    on every run. It reads no configuration, opens no socket and reports nothing
    about the installation it is running from -- backends, drivers, versions and
    reachability are `doctor`'s, and two commands answering overlapping
    questions is how they come to disagree.

    `--color` is read from the position before the verb, which is the one this
    command's parser can see: `sopuli --color never about`. Every other global
    option is refused there rather than ignored, including `--output json`:
    there is no machine-readable form of this screen, and exiting 0 with human
    text after being asked for JSON is the silent-ignore this tool refuses
    everywhere else.
    """
    # Not a run, so not decorated with `global_options` and given no
    # `Invocation` (#413). It resolves no settings, has nothing to report and no
    # `--output json` form to be the machine half of -- the same footing
    # `--version` and `--help` stand on. `tests/test_cli_precedence.py` names it
    # there rather than exempting it silently.
    #
    # A verb rather than a flag, twice over. `--version` must stay one greppable
    # line a script can parse, so the banner could not go there; and a
    # root-level `--about` would be an exception to D2's noun-verb grammar for
    # no gain, where a bare top-level command is not one -- `doctor` is already
    # that shape.
    #
    # `--color` is read off the group's `GlobalOptions` rather than declared
    # here, because the verb takes no options at all. Ignoring it instead would
    # leave a documented flag silently inert on the one screen in the tool that
    # is mostly colour. `options` is `None` only for a caller that invoked this
    # command outside the group, which no real run does.
    given = options or GlobalOptions()
    # Invariant 1 does not stop being true because the command is trivial: the
    # token is in `argv` and visible in `ps` either way, and exiting 0 over it
    # would be ADR-007's worst case -- accepting the flag and doing nothing.
    # The group's position is the only one there is here, so the verb's is empty.
    check_vault_token(given, GlobalOptions())
    if written := about_refusals(given):
        raise click.UsageError(
            f"{', '.join(written)} cannot be honoured by `about`, which is not a run:\n"
            "       about prints compiled-in text: no configuration, no "
            "settings, no machine-readable form\n"
            "       --color is the one exception, and it is read in this same "
            "position"
        )
    choice = ColorChoice(given.color_choice or ColorChoice.AUTO)
    Emitter(color_choice=choice).emit_text(render_about())


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
    targets: tuple[str, ...],
    accounts: tuple[str, ...],
    groups: tuple[str, ...],
    applications: tuple[str, ...],
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

    selection = selected(selectors, targets, accounts, groups, applications)
    refuse_unknown(run.config, selection)
    if not selection.is_everything and not resolved:
        # Silently ignoring a filter is the failure P3 refuses for unknown keys,
        # for the same reason: the run looks like it did what was asked. There is
        # nothing to filter in the declared view -- it shows the file, and the
        # estate a selector narrows does not exist until `--resolved` builds it.
        #
        # A UsageError rather than a ConfigError, because nothing is wrong with
        # the configuration: two options that each parsed do not form a valid
        # request. That puts it on exit 2 with no document, which is J7's rule --
        # and keeps exit 9 meaning "your file is wrong" for a consumer that
        # branches on it (#8).
        raise click.UsageError(
            "a selector has nothing to filter without --resolved\n"
            "       the declared view shows the file; the estate a selector "
            "narrows is --resolved"
        )

    paths = run.sources
    config = filter_estate(run.config, selection)

    reached = len(config.expanded_targets)
    document.diagnostics.extend(config_diagnostics(config))
    document.selection = selection.as_json() or None
    document.config = build_section(paths, config, run.declared, resolved=resolved)
    if explain:
        # The same data the JSON document already carries, widened: `--explain`
        # means "show everything you consulted", built-in defaults included.
        document.options = all_options(run)
    document.finish(
        ExitCode.SUCCESS,
        Summary(total=reached, ok=reached, changed=0, failed=0),
    )
    return render_text(
        paths,
        config,
        resolved=resolved,
        match=selection.select,
        settings=run.resolved if explain else {},
    )


@cli.group("target")
def target_group() -> None:
    """Inspect the estate."""


@target_group.command("list")
@select_option
@global_options
def target_list(
    selectors: tuple[str, ...],
    targets: tuple[str, ...],
    accounts: tuple[str, ...],
    groups: tuple[str, ...],
    applications: tuple[str, ...],
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

    selection = selected(selectors, targets, accounts, groups, applications)
    refuse_unknown(run.config, selection)
    paths = run.sources
    config = filter_estate(run.config, selection)

    reached = len(config.expanded_targets)
    document.diagnostics.extend(config_diagnostics(config))
    document.selection = selection.as_json() or None
    # The same `config` section `config show --resolved` emits, deliberately.
    # It is one estate, and a second JSON shape for it would be two answers to
    # one question -- exactly what invariant 12 exists to prevent. The cost is
    # that `bindings` rides along where the text view has no column for it,
    # which is the cheaper of the two mistakes.
    document.config = build_section(paths, config, run.declared, resolved=True)
    document.finish(
        ExitCode.SUCCESS,
        Summary(total=reached, ok=reached, changed=0, failed=0),
    )
    return render_target_list(paths, config, match=selection.select)


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
    targets: tuple[str, ...],
    accounts: tuple[str, ...],
    groups: tuple[str, ...],
    applications: tuple[str, ...],
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

    selection = selected(selectors, targets, accounts, groups, applications)
    refuse_unknown(run.config, selection)
    config = filter_estate(run.config, selection)
    document.selection = selection.as_json() or None
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
    return "\n".join(
        [*sections, render_doctor(entries, client=client), *render_notices(_admin_notices(run))]
    )


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

    Both keys, which is the whole point of the function. Each is a documented
    setting with a precedence chain behind it, and a command that resolved one
    and then connected on the built-in anyway would be #176's review finding all
    over again: a key that looks configured and does nothing. `doctor` is also
    the command most likely to be pointed at something unreachable, which is
    exactly when `connect_timeout_s` matters.

    `db.query_timeout_s` was the key that did nothing (#360). It reached
    `Timeouts.query_s` -- which becomes `Connection.call_timeout` -- from
    nowhere, because this function read its sibling and passed no `query_s` at
    all, so a profile setting it changed exactly nothing.

    **Wiring it does not change what the tool imposes**, and that distinction is
    the reason it is safe to wire. The built-in stays `NO_QUERY_TIMEOUT`, for the
    reason stated where that constant lives: a call timeout cancels the round
    trip without undoing what the server did with it, `ALTER USER` is not
    transactional, and a rotation cut off at the wrong moment leaves a run that
    cannot say whether the password changed -- the one state invariant 7 has no
    answer for. What changes is that an operator can now *reach* that state on
    purpose, which `01-configuration.md` §5 has always said is theirs to choose.

    Absent means the built-in, for both, and `Timeouts` already holds those two
    numbers -- so an :class:`Invocation` built without resolution (a test, the
    preliminary one) gets the documented behaviour rather than a zero.
    """
    fallback = Timeouts()
    connect = run.resolved.get("db.connect_timeout_s")
    query = run.resolved.get("db.query_timeout_s")
    return Timeouts(
        connect_s=int(connect.value) if connect is not None else fallback.connect_s,
        query_s=int(query.value) if query is not None else fallback.query_s,
    )


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


@cli.group("account")
def account_group() -> None:
    """Act on an account a person owns, rather than one an application uses."""


@account_group.command("suspend")
@click.option(
    "--account",
    "account",
    required=True,
    metavar="NAME",
    help="The one account to suspend. Required: this verb acts on exactly one.",
)
@click.option(
    "--select",
    "selectors",
    multiple=True,
    metavar="KEY=VALUE",
    help="Limit to targets carrying this label. Repeatable.",
)
@click.option(
    "--target", "targets", multiple=True, metavar="NAME", help="Limit to this target. Repeatable."
)
@click.option(
    "--group", "groups", multiple=True, metavar="NAME", help="Limit to this group. Repeatable."
)
@click.option(
    "--confirm",
    is_flag=True,
    default=False,
    help="Proceed without asking. Required where `safety.confirm_environments` applies.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Waive guardrails 2 to 5. Never the whitelist, which nothing waives.",
)
@global_options
def account_suspend(
    account: str,
    selectors: tuple[str, ...],
    targets: tuple[str, ...],
    groups: tuple[str, ...],
    confirm: bool,
    force: bool,
    run: Invocation,
) -> str:
    """Lock a person's account -- the offboarding state a reset refuses to clear.

    `ALTER USER ... ACCOUNT LOCK`, against an account `personal_accounts:`
    declares. The state it produces is `LOCKED`, which is a different thing from
    the `LOCKED(TIMED)` a failed-login limit produces: that one expires on its
    own under `PASSWORD_LOCK_TIME`, and this one does not until somebody unlocks
    it.

    **One account, named on the command line.** `--account` is required and takes
    one name, because an offboarding is one person leaving and UC-2 section 2
    requires a mutating verb to name its account rather than resolve a set. The
    target selectors narrow where it is suspended, not who is.

    **A predicate does not widen this.** Where `personal_accounts:` declares by
    profile or role rather than by name, the rule is resolved against each target
    and the account is refused wherever the rule does not admit it -- so a
    declaration can never turn one named account into several.

    **The guardrails are the ones every mutating verb uses.** Suspending DBSNMP
    refuses exactly as rotating it would, and `--force` waives checks 2 to 5 and
    never the whitelist, which is invariant 5's own sentence.

    **Idempotent.** An account that is already locked reports no change and
    issues nothing -- the driver reads the state first, because Oracle accepts
    the statement against a locked account silently.

    **It changes no password and touches no store.** There is nothing here for
    the advisory lock to protect, and nothing that could emit a secret.

    Help text stays ASCII throughout, which is P4's rule.
    """
    document = run.document
    action = "suspending an account"
    refuse_if_readonly(run.resolved, action=action)

    selection = selected(selectors, targets, (), groups, ())
    refuse_unknown(run.config, selection)
    config = filter_estate(run.config, selection)
    document.selection = selection.as_json() or None
    document.diagnostics.extend(config_diagnostics(config))

    run = _with_estate_safety(run, config)
    refuse_if_readonly(run.resolved, action=action, estate=config)

    reached = config.expanded_targets
    plan = plan_builder.build_for_accounts(
        config, [(account, target.name) for target in reached], intent=["account_lock"]
    )
    refuse_if_over_limit(run.resolved, plan.blast_radius, action=action)
    document.plan = plan.as_json()
    _confirm_environments(plan, run, action=action, confirmed=confirm, noun="account")

    if not reached:
        document.finish(ExitCode.SUCCESS, Summary())
        return render_plan(plan, noun="account") + "\n\nnothing to suspend"

    found = _suspend_estate(reached, account, run, config, force=force, preview=run.dry_run)

    document.results = [record.as_json() for record in found]
    states = [record.state for record in found]
    changed = sum(1 for record in found if record.changed)
    document.finish(_suspend_exit(states), summarise_suspend(states, changed=changed))

    header = render_plan(plan, noun="account")
    body = render_suspend(
        [
            (record.account, record.target, record.state, record.status, record.detail)
            for record in found
        ],
        changed=changed,
        preview=run.dry_run,
        would_suspend=sum(1 for one in found if one.would_suspend) if run.dry_run else None,
    )
    return f"{header}\n\n{body}"


@dataclass(frozen=True)
class _Suspended:
    """One (account, target) after `account suspend` has looked at it."""

    account: str
    target: str
    state: str
    changed: bool
    detail: str | None = None
    #: ``ACCOUNT_STATUS`` as it was **read**, before anything was issued.
    status: str | None = None
    overridden: tuple[guardrails.Refusal, ...] = ()
    #: Under ``--dry-run``, whether this row cleared every gate and would have
    #: been suspended. Always ``False`` on a real run, where ``changed`` is the
    #: answer -- one field serving both would make "would have" and "did"
    #: indistinguishable in the one place it matters.
    would_suspend: bool = False
    duration_ms: int | None = None
    error: Error | None = None

    def as_json(self) -> dict[str, Any]:
        return build_suspend_result(
            self.account,
            self.target,
            state=self.state,
            changed=self.changed,
            detail=self.detail,
            status=self.status,
            overridden=self.overridden,
            duration_ms=self.duration_ms,
            error=self.error,
        )


def _suspend_exit(states: Sequence[str]) -> ExitCode:
    """Exit 4 where a target could not be reached, 0 otherwise.

    A refusal is not a failure: ``SKIPPED`` is the guardrails doing their job and
    ``ACCOUNT_MISSING`` is an ordinary fact about an estate where somebody has an
    account on four of nine targets. Neither is a reason for a scheduled caller to
    page anyone, and an exit code that said otherwise would make this verb
    unusable from a script.
    """
    failed = set(states) - {suspend.LOCKED, suspend.SKIPPED, suspend.ACCOUNT_MISSING}
    return ExitCode.PARTIAL if failed else ExitCode.SUCCESS


def _suspend_estate(
    targets: Sequence[ExpandedTarget],
    account: str,
    run: Invocation,
    config: Config,
    *,
    force: bool,
    preview: bool,
) -> list[_Suspended]:
    """The named account, target by target, one connection each."""
    return [
        _suspend_one(target, account, run, config, force=force, preview=preview)
        for target in targets
    ]


def _suspend_one(
    target: ExpandedTarget,
    account: str,
    run: Invocation,
    config: Config,
    *,
    force: bool,
    preview: bool,
) -> _Suspended:
    """One target: read the account, decide, and lock it or say why not.

    **The state is read before anything is decided**, because both gates need it:
    a predicate in ``personal_accounts:`` is resolved from the profile and the
    roles on it, and §4's guardrails run on the spelling the database gave back.

    Under ``--dry-run`` the read still happens and the statement does not. A
    preview that skipped the read would have nothing to preview -- which account
    is declared here, what state it is in, and which guardrail would stop it are
    the answers somebody runs one for.
    """
    started = time.monotonic()
    session = None
    try:
        try:
            session = _open_session(target, run, config)
            state = session.describe_user(account)
        except Exception as error:  # noqa: BLE001 -- a per-target finding
            reported = _as_error(error)
            return _Suspended(
                account=account,
                target=target.name,
                state=check_states.ERROR,
                changed=False,
                detail=reported.message,
                duration_ms=_elapsed(started),
                error=reported,
            )

        decision = suspend.decide(
            state, config=config, account=account, target=target.name, force=force
        )
        status = state.status if state is not None else None
        overridden = decision.review.overridden if decision.review is not None else ()
        if not decision.proceed:
            return _Suspended(
                account=account,
                target=target.name,
                state=decision.state,
                changed=False,
                detail=decision.detail,
                status=status,
                overridden=overridden,
                duration_ms=_elapsed(started),
            )

        if preview:
            return _Suspended(
                account=account,
                target=target.name,
                state=decision.state,
                changed=False,
                detail=f"{decision.detail}; would be suspended",
                status=status,
                overridden=overridden,
                would_suspend=True,
                duration_ms=_elapsed(started),
            )

        try:
            change = session.suspend_account(account)
        except Exception as error:  # noqa: BLE001 -- a per-target finding
            reported = _as_error(error)
            return _Suspended(
                account=account,
                target=target.name,
                state=check_states.ERROR,
                changed=False,
                detail=reported.message,
                status=status,
                duration_ms=_elapsed(started),
                error=reported,
            )

        return _Suspended(
            account=account,
            target=target.name,
            state=suspend.LOCKED,
            changed=change.changed,
            detail=change.detail,
            status=change.status,
            overridden=overridden,
            duration_ms=_elapsed(started),
        )
    finally:
        if session is not None:
            with suppress(Exception):
                session.close()


@account_group.command("reset-password")
@click.option(
    "--account",
    "account",
    required=True,
    metavar="NAME",
    help="The one account to reset. Required: this verb acts on exactly one.",
)
@click.option(
    "--select",
    "selectors",
    multiple=True,
    metavar="KEY=VALUE",
    help="Limit to targets carrying this label. Repeatable.",
)
@click.option(
    "--target", "targets", multiple=True, metavar="NAME", help="Limit to this target. Repeatable."
)
@click.option(
    "--group", "groups", multiple=True, metavar="NAME", help="Limit to this group. Repeatable."
)
@click.option(
    "--keep-rollover",
    is_flag=True,
    default=False,
    help="Leave an open rollover window open, so the old password keeps working.",
)
@click.option(
    "--confirm",
    is_flag=True,
    default=False,
    help="Proceed without asking. Refused with `delivery.method: manual`, which always asks.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Waive guardrails 2 to 5. Never the whitelist, and never a deliberate lock.",
)
@global_options
def account_reset_password(
    account: str,
    selectors: tuple[str, ...],
    targets: tuple[str, ...],
    groups: tuple[str, ...],
    keep_rollover: bool,
    confirm: bool,
    force: bool,
    run: Invocation,
) -> str:
    """Give a person's account a new password, and hand it over.

    UC-2's reason for existing: somebody cannot get into their own account,
    usually because the password expired and they no longer know it. This draws a
    new one, sets it, and delivers it by the method `delivery:` names.

    **Two paths, and the configuration chooses.** The unseen path -- the default
    -- puts the value where only the owner can fetch it and shows it to nobody;
    none of its methods is implemented yet (#444-#447), so a file naming one is
    refused here rather than after the password has changed. The seen path,
    `delivery.method: manual`, prints the password to your terminal and always
    expires the account, because expiry at first logon is what ends your sight of
    it.

    **`--confirm` cannot be used with `manual`.** That path asks every time and no
    flag may answer: the prompt exists to establish that somebody is watching, and
    a flag asserting it would be testifying to its own premise. If nobody can
    answer, nobody can receive the password either.

    **Running it twice draws a second password.** There is no convergence to be
    had -- a fresh random draw has nothing to compare against -- so this verb sits
    outside invariant 9 (#454) and says so in what it prints. Whoever holds the
    first password holds one that no longer works.

    **The rollover window is closed by default** (UC-2 4.3), so the old password
    stops working at once. `--keep-rollover` leaves it open, which is for the
    reset where the person still knows their old password -- and exactly wrong
    after a suspected disclosure, where somebody else knows it too.

    **One account, named on the command line.** The target selectors narrow where
    it is reset, not who is; each target holds a separate account with a separate
    password. A predicate in `personal_accounts:` narrows and never widens.

    Help text stays ASCII throughout, which is P4's rule.
    """
    document = run.document
    action = "resetting a password"
    refuse_if_readonly(run.resolved, action=action)

    # Both delivery gates run before a selector is judged and before anything
    # connects: a reset with nowhere to deliver, or one whose seen path cannot be
    # watched, must not reach a database at all. UC-2 6.4's ordering is about
    # which failure to prefer once a run is under way; this is about not starting.
    delivery = reset.deliverable(run.config.delivery)
    reset.refuse_seen_path(
        delivery,
        is_json=run.is_json,
        stdout_is_terminal=is_a_terminal(sys.stdout),
        confirm_given=confirm,
        preview=run.dry_run,
    )

    selection = selected(selectors, targets, (), groups, ())
    refuse_unknown(run.config, selection)
    config = filter_estate(run.config, selection)
    document.selection = selection.as_json() or None
    document.diagnostics.extend(config_diagnostics(config))

    run = _with_estate_safety(run, config)
    refuse_if_readonly(run.resolved, action=action, estate=config)
    # After the estate merge, because a target's or a group's `safety:` block is
    # layer 4 and cannot narrow the set until a selector has run (#424, #498).
    # `--force` is not passed and cannot be: this is a safety setting, and
    # invariant 10 is that no source relaxes one.
    refuse_disallowed_method(run.resolved, delivery.method)

    reached = config.expanded_targets
    plan = plan_builder.build_for_accounts(
        config,
        [(account, target.name) for target in reached],
        intent=_reset_intent(),
    )
    refuse_if_over_limit(run.resolved, plan.blast_radius, action=action)
    document.plan = plan.as_json()
    _confirm_environments(plan, run, action=action, confirmed=confirm, noun="account")

    # The record path is derived before anything connects, so a name it cannot
    # be built from is a plan-time refusal (invariant 4) rather than a failure
    # after the password has already changed.
    paths = _record_paths(config, account, reached)

    header = render_plan(plan, noun="account")
    if not reached:
        document.finish(ExitCode.SUCCESS, Summary())
        return header + "\n\nnothing to reset"

    # UC-2 3.4's first absence, after the empty-selection exit and before the
    # first connection: an operator who did not mean to run without a journal
    # can still stop, and a run that resets nothing has no record to be missing.
    notices: list[Diagnostic] = []
    if config.reset_records is None:
        unrecorded = no_reset_record()
        document.diagnostics.append(unrecorded)
        notices.append(unrecorded)

    if not run.dry_run and delivery.is_seen:
        # **The plan goes out before the first statement, and before the prompt**
        # (invariant 8; Copilot's review of #505). The verb returns its whole
        # output as a string, so without this the operator would be asked to
        # expose a password before seeing what the run was about to do -- and by
        # then the DDL has already run. On stderr, which is where
        # `_confirm_environments` puts the same thing for the same reason: stdout
        # carries the result.
        click.echo(header, err=True)

    # UC-2 §3.3's lock, keyed on the record's path -- the one location that
    # exists on the seen path and the unseen one alike, and the unit two
    # concurrent resets collide on. None under `--dry-run` (a preview takes no
    # lock, as `creds generate` does not) and none where no `reset_records:`
    # block declares a store, which is what `SOPULI-W024` above has already
    # said: where there is no store there is no lock.
    manager = _reset_lock_manager(run, config, selection)
    found: list[_Reset] = []
    stolen: LockStolenError | None = None
    try:
        keys = _reset_lock_keys(config, account, reached)
        with manager.holding(keys) if manager is not None else nullcontext():
            for target in reached:
                key = _reset_lock_key(config, account, target)
                if manager is not None and key is not None:
                    try:
                        # The fence, immediately before the statements rather
                        # than once for the run (UC-1 §8): what a stalled run
                        # holds is a memory of having held a lock.
                        manager.check(key)
                    except LockStolenError as lost:
                        stolen = lost
                        break
                found.append(
                    _reset_one(
                        target,
                        account,
                        run,
                        config,
                        delivery=delivery,
                        force=force,
                        keep_rollover=keep_rollover,
                        preview=run.dry_run,
                        record_at=paths.get(target.name),
                    )
                )
    except LockDeniedError as denied:
        # Exit 7, and nothing was issued: acquisition is all-or-nothing and
        # happens before the first connection, so a reset refused here is a
        # reset that did not start. Somebody else is resetting this account on
        # this target, which is the collision §3.3 keys the lock to prevent.
        if manager is not None:
            _record_locks(document, manager, denied=denied)
        raise
    except click.Abort:
        # The seen path's prompt, declined. `holding()` has already let the lock
        # go in its `finally`, so this records a lock that is released rather
        # than one that looks stuck -- and it records it at all for the reason
        # `_reset_one` records the row: a run abandoned half way is exactly when
        # somebody needs to know what it held and what it touched.
        if manager is not None:
            _record_locks(document, manager)
        raise

    if manager is not None:
        _record_locks(document, manager)

    document.results = [one.as_json() for one in found]
    states = [one.state for one in found]
    changed = sum(1 for one in found if one.changed)
    if stolen is not None:
        # `creds generate`'s split, for its reason: exit 7 asserts that nothing
        # happened, which is a lie once one target's password has been reset.
        # Printed as well as serialised, because on this verb the reader is by
        # definition at a terminal (§6.5) and the accounts *not* reached are the
        # thing they have to act on.
        fence = Diagnostic(level="error", message=stolen.message, code=LOCK_LOST)
        document.diagnostics.append(fence)
        notices.append(fence)
    # The second of §3.4's absences, raised here rather than inside `_reset_one`
    # so that the plan-time one above and this one are appended in the order
    # they happened. A row only carries a reason when a record was attempted and
    # failed; a row that wrote one, or never had a journal to write to, carries
    # none.
    for one in found:
        if one.record_error is not None:
            failed = reset_record_unwritten(one.record_error.path, one.record_error.reason)
            document.diagnostics.append(failed)
            notices.append(failed)
    document.finish(
        _reset_exit(states, stolen=stolen is not None, changed=changed),
        summarise_reset(states, changed=changed),
    )

    body = render_reset(
        [(one.account, one.target, one.state, one.status, one.detail) for one in found],
        changed=changed,
        preview=run.dry_run,
        would_reset=sum(1 for one in found if one.would_reset) if run.dry_run else None,
    )
    shown = "\n\n".join(one.shown for one in found if one.shown is not None)
    # Printed as well as serialised (#309): a warning nobody can see in the
    # default output is not surfaced, and these say the run kept no record of
    # itself -- which is what a terminal operator needs, and what
    # `diagnostics[]` alone tells only a JSON consumer.
    told = "\n".join(render_notices([one.message for one in notices]))
    return "\n\n".join(part for part in (header, body, told, shown) if part)


def _reset_lock_manager(
    run: Invocation, config: Config, selection: Selection
) -> LockManager | None:
    """The manager UC-2 §3.3's lock is taken with, or ``None`` for no lock.

    ``None`` in exactly two states, and neither is a failure: under
    ``--dry-run``, because a preview takes no lock any more than `creds
    generate`'s does, and where no `reset_records:` block declares a store,
    because **where there is no store there is no lock** -- the second half of
    the sentence `SOPULI-W024` already says out loud.

    **A store that is declared and cannot be reached is not one of the two.**
    Opening it here means such a run fails before it connects to a database and
    before anything is issued, which is where UC-1's lock stores already fail
    and the only honest answer: the estate asked for a lock, the lock cannot be
    taken, and nothing has happened yet. It is a different case from §3.4's
    absences, which are all about a store that went away *after* the password
    changed -- there the reset stands and a warning carries it.

    The store is opened through the run's own client cache, so the journal write
    that follows authenticates once rather than twice.
    """
    records = config.reset_records
    if run.dry_run or records is None:
        return None
    journal = _reset_journal(run, config)
    if journal is None:  # pragma: no cover -- `records` is not None, so neither is this
        return None
    return LockManager(
        stores={records.vault: _lockable(records.vault, config, {records.vault: journal})},
        correlation_id=run.document.correlation_id,
        command="account reset-password",
        selection=describe_selection(selection),
        break_expired=_break_expired(run),
    )


def _reset_lock_key(config: Config, account: str, target: ExpandedTarget) -> LockKey | None:
    """One (target, account)'s lock, which is its record's path.

    Never raises here although :func:`~sopuli.reset_record.record_lock_key`
    can: the same derivation ran at plan time in :func:`_record_paths`, and a
    name it refuses has already ended the run.
    """
    records = config.reset_records
    if records is None:
        return None
    return reset_record.record_lock_key(records, target=target.name, account=account)


def _reset_lock_keys(
    config: Config, account: str, reached: Sequence[ExpandedTarget]
) -> list[LockKey]:
    """Every lock this run needs, in acquisition order.

    Sorted for :func:`~sopuli.lock.keys.acquisition_order`'s reason rather than
    for presentation: taking locks in one order across every run is what makes
    deadlock structurally impossible. A reset of one person on nine PDBs takes
    nine locks, and two operators doing it at once must not each hold half.
    """
    found = {
        key
        for key in (_reset_lock_key(config, account, target) for target in reached)
        if key is not None
    }
    return list(acquisition_order(found))


def _record_paths(
    config: Config, account: str, reached: Sequence[ExpandedTarget]
) -> dict[str, str]:
    """Where each target's record will go, derived before anything connects.

    Empty where no `reset_records:` block is declared, which is the documented
    mode rather than a failure (UC-2 §3.4) -- so a caller reads "no path for this
    target" as "nothing to write" and needs no second flag to tell the two apart.

    **A name the path cannot be built from is refused here** (invariant 4).
    :func:`~sopuli.reset_record.record_path` raises :class:`ValueError` for a
    target or an account that is not one path segment -- a `/` in either derives
    the same record path as a *different* pair, which is one journal describing
    two accounts and, once #512 lands, one lock where there should be two.
    Deriving at plan time is what keeps that a refusal rather than a discovery
    made after the password has changed.

    A :class:`ConfigError` and exit 9, because the offending name is in the
    file: `targets[].name` or the account the operator typed, and neither is a
    capability the database lacks.
    """
    records = config.reset_records
    if records is None:
        return {}
    derived: dict[str, str] = {}
    for target in reached:
        try:
            derived[target.name] = reset_record.record_path(
                records, target=target.name, account=account
            )
        except ValueError as error:
            raise ConfigError(
                f"no reset record path for {account} on {target.name}: {error}",
                hint=(
                    "the record is one per (target, account) under "
                    f"`reset_records.prefix` ({records.prefix}), so each name has to be "
                    "a single path segment"
                ),
            ) from error
    return derived


@dataclass(frozen=True)
class _RecordFailure:
    """A record that could not be written, and where it was going to go."""

    path: str
    reason: str


def _write_reset_record(
    run: Invocation,
    config: Config,
    *,
    path: str,
    account: str,
    target: str,
    delivery: Delivery,
    expired: bool,
    secret: Secret,
) -> _RecordFailure | None:
    """Journal one reset, or say why it could not be (UC-2 §3.1, #511).

    **Called after the database has confirmed and after delivery** (§6.4). The
    record holds what happened, so writing it earlier would make it hold an
    intention -- which is also why §3.4 makes a failed write a warning on a
    *successful* run rather than a rollback: the password has already changed
    and the person still needs it.

    **On the seen path "after delivery" is as late as a function can be.** The
    password is displayed by this command returning a string, so the write
    happens once the value is composed and every guard has passed, a moment
    before Click echoes it. Restructuring the verb to echo first would put a
    store write after the one emission in this tool that must never be retried.

    **`seen` records the path rather than the operator's eyes.** It is `true` for
    a `manual` delivery even where the prompt was declined and nothing was
    printed: the field answers "was this the path that shows a DBA a working
    password", which is what makes the absent `delivery.to` unambiguous (§3.1),
    and a journal that understated an exposure would be wrong in the direction
    that matters. What the operator did about the prompt is in the run document.

    Never raises. Every failure is a :class:`_RecordFailure` the caller turns
    into `SOPULI-W025`, because there is no failure here worth ending a run that
    has already succeeded.
    """
    try:
        # **Opening is inside the guard, not beside it** (Copilot's review of
        # #513). `_stores_for` resolves a credential and builds a client, and
        # every one of those steps can fail -- an unreachable Vault, a token
        # that has expired since the run began, a backend whose extra is not
        # installed. Outside the guard that exception would escape a reset that
        # had already succeeded and turn it into a failed run, which is exactly
        # the false negative 3.4 rules out: the password has changed and the
        # person still needs it.
        journal = _reset_journal(run, config)
    except Exception as error:  # noqa: BLE001 -- never worth failing a done reset
        return _RecordFailure(path=path, reason=_as_error(error).message)
    if journal is None:
        # Unreachable while `path` comes from `_record_paths`, which derives
        # nothing without a block -- and cheaper to answer than to prove at every
        # call site. A store that could not be opened is a failure, not a silence.
        return _RecordFailure(path=path, reason="no store to write it to")
    record = reset_record.ResetRecord(
        account=account,
        target=target,
        reset_at=utc_now(),
        seen=delivery.is_seen,
        expired=expired,
        delivery=reset_record.Delivery(method=delivery.method),
        by=current_holder(),
        correlation_id=run.document.correlation_id,
    )
    document = record.to_dict()
    # Invariant 2 against the serialised document rather than against the
    # writer's intentions, which is what #468 built it for: the type has no
    # field a password could go in, and this is what holds when a later delivery
    # method puts its own reference in `delivery.to`. An `AssertionError` -- a
    # programming error, not a configuration one -- so it is deliberately not
    # caught below.
    reset_record.assert_no_secret(document, secret=secret)
    try:
        # Unguarded: serialising two concurrent resets is the advisory lock's
        # job (#512, UC-2 §3.3), and a compare-and-set here would buy nothing it
        # will not buy properly -- while failing forever on a path whose latest
        # version was deleted, which reads as `None` and is not version 0.
        journal.write(path, document, cas=None)
    except Exception as error:  # noqa: BLE001 -- never worth failing a done reset
        return _RecordFailure(path=path, reason=_as_error(error).message)
    return None


def _reset_intent() -> list[str]:
    """What the plan says this run will do, before it does any of it.

    **One word, and the expiry is not a second one.** The seen path always
    expires, but `PASSWORD EXPIRE` is a *suffix* on the statement that sets the
    password rather than a statement of its own (UC-2 4.1), so there is nothing
    separate to promise -- and inventing an `expire_password` intent would put a
    word in the contract that names no action the driver reports.

    The unlock and the window close are left out for the opposite reason: both
    are real statements, and both are conditional on state the plan has not read.
    A plan naming a statement that then does not run is what invariant 8 exists
    to prevent.
    """
    return ["password_set"]


def _reset_exit(states: Sequence[str], *, stolen: bool = False, changed: int = 0) -> ExitCode:
    """Exit 4 where a target could not be reached, 0 otherwise -- `suspend`'s rule.

    A refusal is not a failure: `SKIPPED` is the guardrails working and
    `ACCOUNT_MISSING` is an ordinary fact about an estate.

    **A lost fence splits the same way `creds generate` splits it** (#512). Exit
    7 asserts that nothing happened, so it is only right while nothing has: once
    one target's password has been reset and a later target's lock has been
    taken, the run is partial and says so with 4. Somebody holds a password the
    estate is no longer wholly consistent about, which is a worse thing to
    mislabel than a lock.
    """
    if stolen:
        return ExitCode.PARTIAL if changed else ExitCode.LOCK_HELD
    failed = set(states) - {reset.RESET, reset.SKIPPED, reset.ACCOUNT_MISSING}
    return ExitCode.PARTIAL if failed else ExitCode.SUCCESS


@dataclass(frozen=True)
class _Reset:
    """One (account, target) after `account reset-password` has looked at it."""

    account: str
    target: str
    state: str
    changed: bool
    detail: str | None = None
    #: ``ACCOUNT_STATUS`` as it was **read**, before anything was issued.
    status: str | None = None
    #: One entry per statement the driver considered: (kind, applied, detail).
    actions: tuple[tuple[str, bool, str | None], ...] = ()
    #: The delivery *method*, never a value and never a destination. `manual`'s
    #: destination is a person, by a route the tool did not carry (UC-2 3.1).
    delivered: str | None = None
    overridden: tuple[guardrails.Refusal, ...] = ()
    #: Under ``--dry-run``, whether this row cleared every gate.
    would_reset: bool = False
    duration_ms: int | None = None
    error: Error | None = None
    #: Why this reset's record could not be written, where one was attempted and
    #: failed (UC-2 3.4's second absence). **Never serialised as a result
    #: field**: the caller turns it into `SOPULI-W025` in ``diagnostics[]``,
    #: which is where a consumer already looks for what a run could not do.
    record_error: _RecordFailure | None = None
    #: The rendered password block, on the seen path only. **Never serialised**:
    #: `as_json` cannot reach it, and there is no field in the schema it could
    #: go in. It travels here because the caller prints it after the table, and
    #: the ordering of those two is a display decision rather than a safety one
    #: -- the safety is that the run never got this far unless every guard passed.
    shown: str | None = None

    def as_json(self) -> dict[str, Any]:
        return build_reset_result(
            self.account,
            self.target,
            state=self.state,
            changed=self.changed,
            actions=self.actions,
            status=self.status,
            delivered=self.delivered,
            overridden=self.overridden,
            duration_ms=self.duration_ms,
            error=self.error,
        )


def _reset_one(
    target: ExpandedTarget,
    account: str,
    run: Invocation,
    config: Config,
    *,
    delivery: Delivery,
    force: bool,
    keep_rollover: bool,
    preview: bool,
    record_at: str | None = None,
) -> _Reset:
    """One target: read the account, decide, draw, set, and hand it over.

    **The order is UC-2 6.4's, and on this path it is `ALTER USER` then print.**
    The irreversible step goes last, and what cannot be undone here is the
    printing: a password shown to a DBA has been shown, and one printed without
    having been set tells them something false, which they will then pass on. So
    the value on the screen is the account's password by the time anybody reads
    it. The unseen path prefers the other order, and gets it when a method that
    delivers elsewhere lands.

    **The password is drawn after the state is read**, not before: the byte limit
    the policy is validated against is a property of the target (#383), and a
    draw that ignored it would fail mid-statement on 21c and older.

    Under ``--dry-run`` the read still happens and nothing else does. A preview
    that skipped the read could not say which account is declared here, what
    state it is in, or which guardrail would stop it.
    """
    started = time.monotonic()
    session = None
    try:
        try:
            session = _open_session(target, run, config)
            state = session.describe_user(account)
        except Exception as error:  # noqa: BLE001 -- a per-target finding
            reported = _as_error(error)
            return _Reset(
                account=account,
                target=target.name,
                state=check_states.ERROR,
                changed=False,
                detail=reported.message,
                duration_ms=_elapsed(started),
                error=reported,
            )

        decision = reset.decide(
            state,
            config=config,
            account=account,
            target=target.name,
            delivery=delivery,
            force=force,
        )
        status = state.status if state is not None else None
        overridden = decision.review.overridden if decision.review is not None else ()
        if not decision.proceed:
            return _Reset(
                account=account,
                target=target.name,
                state=decision.state,
                changed=False,
                detail=decision.detail,
                status=status,
                overridden=overridden,
                duration_ms=_elapsed(started),
            )

        if preview:
            # **Nothing below this line may run under --dry-run** (invariant 8),
            # and the first draft of this function proved why the rule is written
            # as a hard stop rather than a habit: `preview` was threaded in and
            # never read, so a dry run drew a password, issued the DDL and then
            # aborted at the prompt -- leaving the account expired with a password
            # nobody had seen. Found by running it, in the one way a test of the
            # code as written could not have been.
            return _Reset(
                account=account,
                target=target.name,
                state=decision.state,
                changed=False,
                detail=f"{decision.detail}; would be reset",
                status=status,
                overridden=overridden,
                would_reset=True,
                duration_ms=_elapsed(started),
            )

        try:
            if decision.expire:
                # UC-2 4.3's refusal, asked here as well as inside the driver:
                # this is the last point before a password is drawn, and drawing
                # one for a reset that cannot run wastes nothing but says the
                # refusal arrived later than it had to.
                session.require_no_rollover_window(account)
            secret = generate(
                _reset_policy(config, account, target.name, state),
                limit=session.byte_limit(),
            )
            changes = session.reset_password(
                account,
                secret,
                expire=decision.expire,
                keep_rollover=keep_rollover,
            )
        except Exception as error:  # noqa: BLE001 -- a per-target finding
            reported = _as_error(error)
            return _Reset(
                account=account,
                target=target.name,
                state=check_states.ERROR,
                changed=False,
                detail=reported.message,
                status=status,
                duration_ms=_elapsed(started),
                error=reported,
            )

        # The row is built **before** the hand-over, and that is not style
        # (Copilot's review of #505). `_hand_over` prompts, and declining raises
        # `click.Abort` -- which used to propagate out of the caller's list
        # comprehension before `document.results` was ever assigned, so a run
        # that had changed and expired a password reported only "aborted before
        # completion". The boundary's own docstring names that case as the one a
        # document exists for: *a confirmation declined halfway through is
        # exactly when a scheduler wants to know which targets were touched.*
        row = _Reset(
            account=account,
            target=target.name,
            state=reset.RESET,
            changed=True,
            detail=decision.detail,
            status=status,
            actions=tuple((one.action, one.changed, one.detail) for one in changes),
            delivered=delivery.method,
            overridden=overridden,
            duration_ms=_elapsed(started),
        )

        def journalled(one: _Reset) -> _Reset:
            """The record, written after the database and after delivery (§6.4).

            Nothing to write where no `reset_records:` block was declared, which
            is the documented mode `SOPULI-W024` already announced at plan time.
            """
            if record_at is None:
                return one
            return replace(
                one,
                record_error=_write_reset_record(
                    run,
                    config,
                    path=record_at,
                    account=account,
                    target=target.name,
                    delivery=delivery,
                    expired=decision.expire,
                    secret=secret,
                ),
            )

        try:
            return journalled(
                replace(
                    row,
                    shown=_hand_over(
                        secret, account=account, target=target.name, delivery=delivery
                    ),
                )
            )
        except click.Abort:
            # Recorded, then re-raised. The row carries no password -- there is
            # no field for one -- so what survives is the fact of the mutation
            # and nothing that would make declining to look pointless.
            #
            # **Journalled too, and that is the point of doing it here.** The
            # password was set; a declined prompt changes what the operator saw
            # and not what the database holds, so a journal that skipped this
            # run would be missing the one reset that most needs explaining --
            # an account whose new password nobody received.
            run.document.results = [*(run.document.results or []), journalled(row).as_json()]
            raise
    finally:
        if session is not None:
            with suppress(Exception):
                session.close()


def _reset_policy(
    config: Config, account: str, target: str, state: UserState | None
) -> PasswordPolicy:
    """The policy this account's password is drawn from.

    The rule that admitted the account names it, and `defaults.policy` answers
    where the rule does not -- the same chain `bindings.py` reads for an
    application account, so a personal policy is configured the way every other
    policy is.
    """
    rule = (
        declared_on(config, state.name, target, profile=state.profile, roles=state.roles)
        if state is not None
        else None
    )
    named = (rule.policy if rule is not None else None) or config.defaults.policy
    if named is None:
        raise ConfigError(
            f"no password policy for {account}",
            hint=(
                "name one on the `personal_accounts:` entry that declares it, or set "
                "`defaults.policy:`"
            ),
        )
    dangling(named, {policy.name for policy in config.policies}, noun="policy", section="policies")
    return next(policy.password for policy in config.policies if policy.name == named)


def _hand_over(secret: Secret, *, account: str, target: str, delivery: Delivery) -> str | None:
    """Deliver the password, and return whatever the operator should see.

    **The one call into the seen path's reveal**, and the only place in `cli.py`
    that can reach it. Everything that makes it allowable was established before
    the run connected: the method is `manual`, the output is text, stdout is a
    terminal (`reset.refuse_seen_path`), and `force_expire: true` was written in
    the file (the config layer). What is left is the prompt.

    **The prompt is asked here, after the password is set**, which is 6.4's
    ordering: the value being shown is by then the account's real password. It is
    asked on stderr and answered from the terminal, and declining raises -- there
    is nothing to undo, and the operator has simply chosen not to look, which
    leaves the account holding a password nobody has seen. That is a lockout the
    next reset fixes, and it is what "aborted" has to mean here.

    ``None`` for an unseen method, which prints nobody anything.
    """
    if not delivery.is_seen:
        return None
    click.confirm(
        f"show the new password for {account} on {target} on this terminal?",
        abort=True,
        err=True,
    )
    return render_password(secret, account=account)


@account_group.command("list")
@click.option(
    "--select",
    "selectors",
    multiple=True,
    metavar="KEY=VALUE",
    help="Limit to targets carrying this label. Repeatable.",
)
@click.option(
    "--target", "targets", multiple=True, metavar="NAME", help="Limit to this target. Repeatable."
)
@click.option(
    "--group", "groups", multiple=True, metavar="NAME", help="Limit to this group. Repeatable."
)
@click.option(
    "--account",
    "account",
    metavar="NAME",
    help="Show only this account. Filters the resolved set; it cannot extend it.",
)
@global_options
def account_list_command(
    selectors: tuple[str, ...],
    targets: tuple[str, ...],
    groups: tuple[str, ...],
    account: str | None,
    run: Invocation,
) -> str:
    """Resolve `personal_accounts:` and show what it matched.

    Reads no password and writes nothing. It is the verb H1 (#449) owed: a
    personal account may be declared by a *predicate* over a database profile or
    role, and until this there was no way to read a whitelist you cannot
    enumerate. The declaration is resolved against each selected target, and each
    account is reported with the rule that admitted it and the state the database
    is in.

    Two date columns, not one. DB_PW_CHANGED is the database's own
    password-change date and RESET_AT is what the reset journal recorded, and
    UC-2 3.2 keeps them apart deliberately: they come off two clocks and answer
    two questions. A database date later than RESET_AT on the unseen path means
    somebody changed the password after the tool delivered it.

    Either can be empty and an empty one is never silent: SOPULI-W021 says why
    there is no database date, SOPULI-W023 that no journal is configured.

    A predicate naming a profile or role that does not exist is refused -- that
    is a misspelling. One that exists and matches no accounts is not an error,
    because that is a true answer about today's estate.

    Help text stays ASCII throughout, which is P4's rule.
    """
    document = run.document

    # The target selectors only. `--account` is **not** one of them here, and
    # that is the whole of H1's amendment showing up in the command line:
    # `refuse_unknown` compares an account name against what `applications:`
    # declares, so passing a personal account through it would refuse every name
    # this verb exists to report -- and a *predicate* name is not in the file at
    # all, so nothing in the config layer could validate it. It filters the
    # resolved set instead, after the database has said who is in it, which is
    # UC-2 2's rule for the flag: it narrows, it never widens.
    selection = selected(selectors, targets, (), groups, ())
    refuse_unknown(run.config, selection)
    config = filter_estate(run.config, selection)
    document.selection = selection.as_json() or None
    document.diagnostics.extend(config_diagnostics(config))

    reached = config.expanded_targets
    if not reached:
        document.finish(ExitCode.SUCCESS, Summary())
        return "no targets selected"

    if config.reset_records is None:
        document.diagnostics.extend(no_reset_journal())

    rows: list[account_list.Row] = []
    errors = 0
    for target in reached:
        found, failed = _list_one(target, run, config, wanted=account)
        rows.extend(found)
        errors += failed

    document.results = [build_account_list_result(row) for row in rows]
    document.finish(ExitCode.PARTIAL if errors else ExitCode.SUCCESS, summarise_account_list(rows))
    return render_account_list(rows)


def _list_one(
    target: ExpandedTarget,
    run: Invocation,
    config: Config,
    *,
    wanted: str | None,
) -> tuple[list[account_list.Row], int]:
    """One target: resolve every rule that applies, then describe what they named.

    **The predicates are resolved first and the accounts described second**, on
    one connection. Resolution is one query per rule and description is one per
    account, so an estate declaring four hundred developers by profile spends one
    query to learn who they are -- the arrangement the predicate exists for.

    A target that cannot be reached is one failed target and not a failed run: an
    estate of nine PDBs with one down should still report the other eight, which
    is the rule every other multi-target verb here follows.
    """
    session = None
    try:
        try:
            session = _open_session(target, run, config)
        except Exception as error:  # noqa: BLE001 -- a per-target finding
            return [_unreachable_row(target, _as_error(error))], 1

        names = _declared_names(session, config, target, wanted=wanted)
        journal = _reset_journal(run, config)
        return [_describe_row(session, name, target, config, journal=journal) for name in names], 0
    finally:
        if session is not None:
            with suppress(Exception):
                session.close()


def _declared_names(
    session: Any,
    config: Config,
    target: ExpandedTarget,
    *,
    wanted: str | None,
) -> list[str]:
    """Every account the declaration admits here, once each.

    **Deduplicated across rules, case-insensitively, and both halves were found
    by running it rather than by reasoning about it.** An account may be admitted
    by more than one rule -- UC-2 2 calls that ordinary -- and an enumerated rule
    yields the *file's* spelling while a predicate yields the *dictionary's*. So
    ``acme_dev_alice`` enumerated and ``ACME_DEV_ALICE`` carrying the profile are
    one person, and the first draft of this verb listed them as two rows. A
    listing that shows one account twice is worse than one that omits it: it
    misreports the size of the whitelist an operator is reviewing.

    First occurrence wins, so file order leads and predicates fill in behind it,
    which keeps a reviewer's listing aligned with the file they are reading it
    against.

    ``--account`` filters here, after resolution. UC-2 2's rule for the flag: it
    narrows the resolved set and never extends it.
    """
    seen: dict[str, str] = {}
    for rule in account_list.rules_on(config, target.name):
        for name in _resolve_rule(session, rule, target):
            seen.setdefault(name.casefold(), name)

    names = list(seen.values())
    if wanted is not None:
        folded = wanted.casefold()
        names = [name for name in names if name.casefold() == folded]
    return names


def _resolve_rule(
    session: Any, rule: PersonalAccountRule, target: ExpandedTarget
) -> tuple[str, ...]:
    """The names a rule admits on this target, refusing a predicate that misspells."""
    if not rule.is_predicate:
        return account_list.enumerated_names(rule)

    if rule.profile is not None:
        if session.resolve_profile(rule.profile) is None:
            raise _no_such_predicate(target, "profile", rule.profile)
        return tuple(session.accounts_matching(profile=rule.profile))

    assert rule.role is not None
    if session.resolve_role(rule.role) is None:
        raise _no_such_predicate(target, "role", rule.role)
    return tuple(session.accounts_matching(role=rule.role))


def _no_such_predicate(target: ExpandedTarget, noun: str, name: str) -> click.ClickException:
    """UC-2 2's refusing half, worded so the other half is visible in it.

    The message says both rules at once because an operator meeting this needs to
    know that the *other* empty answer is fine: a predicate matching nothing is a
    true answer about today's estate, and only a predicate naming nothing is a
    typo. Saying only the first would teach the wrong lesson about the second.
    """
    return click.ClickException(
        f"target {target.name!r} has no {noun} {name!r}, which `personal_accounts:` "
        f"declares a predicate over -- a predicate that matches no accounts is an "
        f"answer, and one that names nothing is a typo"
    )


def _reset_journal(run: Invocation, config: Config) -> SecretStore | None:
    """The store UC-2's reset records live in, or ``None`` where none is declared.

    Opened **once per target** rather than once per account, for
    :func:`_stores_for`'s own reason: a store is a client, and an estate with
    four hundred developers in one vault should authenticate once. The run's
    client cache makes it once per *run* in practice.

    ``None`` is the documented mode, not a failure (UC-2 3.4): a configuration
    with no `reset_records:` block keeps no journal, `SOPULI-W023` says so, and
    the listing still reports everything else.
    """
    records = config.reset_records
    if records is None:
        return None
    opened = _stores_for({records.vault}, config, token_file=run.vault_token_file, cache=run.stores)
    return opened.get(records.vault)


def _reset_at(journal: SecretStore | None, config: Config, target: str, account: str) -> str | None:
    """What the journal says about this account's last reset, if anything.

    **Three absences, one rendering, and only one of them is a finding.** No
    journal configured is `SOPULI-W023`, raised once for the run. A journal with
    no record for this account is not a finding at all -- nobody has reset them
    through this tool -- and gets no code. A journal that could not be read is
    reported on the row.

    Never raises. A listing verb that failed because a *metadata* store was
    unreachable would be refusing to describe an estate over its history, which
    is the priority inversion UC-2 3.4 rules out for the reset and which applies
    at least as strongly to a read.
    """
    records = config.reset_records
    if journal is None or records is None:
        return None
    try:
        stored = journal.read(reset_record.record_path(records, target=target, account=account))
    except Exception:  # noqa: BLE001 -- history is not worth failing a listing over
        return None
    if stored is None or not isinstance(stored.data, dict):
        return None
    moment = stored.data.get("reset_at")
    return moment if isinstance(moment, str) else None


def _describe_row(
    session: Any,
    name: str,
    target: ExpandedTarget,
    config: Config,
    *,
    journal: SecretStore | None = None,
) -> account_list.Row:
    """One account: its state, the rule that admitted it, and what is worth saying.

    The rule is resolved through :func:`sopuli.account_list.rule_for` rather than
    carried from whichever one produced the name, because an account may be
    admitted by more than one -- and because that is where the
    two-rules-two-policies refusal lives. A listing that showed the first match
    would be where an operator formed the belief the mutating verb then refuses.

    **The name reported is the one the database gave back**, where there is one.
    ``02-oracle-privileges.md`` 4's rule about spellings is about statements, and
    nothing here issues one -- but a listing that showed the file's spelling for
    an enumerated account and the dictionary's for a predicate account would be
    showing two vocabularies in one column, which is how the duplicate rows that
    :func:`_declared_names` now folds got there in the first place. Where the
    account does not exist, the file's spelling is all there is, and it is what
    the reader needs to go and look for.
    """
    state = session.describe_user(name)
    profile = state.profile if state is not None else None
    roles = tuple(state.roles) if state is not None and state.roles else ()
    admitted = account_list.rule_for(config, name, target.name, profile=profile, roles=roles)

    notices: list[str] = []
    # A predicate can admit an account a mutating verb would refuse, and the
    # commonest case is not hypothetical: creating a role grants it to the
    # creator, so `role: ACME_DEV_TEAM` admits whoever ran the CREATE ROLE --
    # measured on the tier-1 stack, where it turned out to be `SYSTEM`. Guardrail
    # 2 would refuse that at plan time, and a listing that showed it with nothing
    # said would be overstating the whitelist it exists to let somebody review.
    if state is not None and state.vendor_maintained:
        notices.append(
            "the database reports this account as its own, so a mutating verb refuses it "
            "at plan time (guardrail 2) -- a predicate can admit an account no reset will "
            "touch, and creating a role grants it to the creator"
        )
    owner = account_list.cross_declared(config, name)
    if owner is not None:
        notices.append(
            f"also declared by {owner}: the whitelist is ambiguous about which guarantee "
            f"applies, and only a predicate can reach this -- an enumerated name is "
            f"refused when the file loads"
        )

    return account_list.Row(
        account=state.name if state is not None else name,
        target=target.name,
        rule=admitted,
        state=state,
        reset_at=_reset_at(journal, config, target.name, name),
        notices=tuple(notices),
    )


def _unreachable_row(target: ExpandedTarget, error: Error) -> account_list.Row:
    """A target that could not be answered, reported as a row rather than a failure.

    **`ERROR`, never `ACCOUNT_MISSING`**, and the row carries the error object.
    The first draft left `state` to be inferred from "no `UserState`", which
    rendered a down or unauthenticated target as *this account does not exist* --
    a connectivity failure reported as a fact about an estate, with nothing in
    `results[]` to tell the two apart. `account suspend` already draws that
    distinction and this now matches it (Copilot's review of #493).
    """
    return account_list.Row(
        account=account_list.ABSENT,
        target=target.name,
        rule=None,
        state=None,
        unreachable=error,
    )


@cli.group("lock")
def lock_group() -> None:
    """Inspect the advisory locks, and take one back."""


@lock_group.command("status")
@select_option
@global_options
def lock_status(
    selectors: tuple[str, ...],
    targets: tuple[str, ...],
    accounts: tuple[str, ...],
    groups: tuple[str, ...],
    applications: tuple[str, ...],
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

    selection = selected(selectors, targets, accounts, groups, applications)
    refuse_unknown(run.config, selection)
    paths = run.sources
    config = run.config
    # Both estates: the filtered one decides what is surveyed and which stores
    # are opened, and the whole one decides what counts as *declared*. A path
    # `--select` excluded is still one this configuration declares, and reporting
    # it as a leftover because this run was not looking at it would be alarming
    # and wrong.
    #
    # `resolvable_locks` for the membership pass and `declared_locks` for the one
    # this command acts on (#349). The unfiltered pass is used only to decide
    # whether a discovered record is `declared: false`, and a binding whose store
    # is unknown can match no discovered path -- so refusing over one made
    # `--select` fail on an account in an application the run was never going to
    # survey.
    everything = resolvable_locks(config)
    keys = declared_locks(filter_estate(config, selection))

    stores = _stores_for(
        {key.store for key in keys}, config, token_file=run.vault_token_file, cache=run.stores
    )
    leftovers = discover_locks(everything, stores=stores)
    states = survey(
        acquisition_order([*keys, *leftovers.keys]), stores=stores, declared=set(everything)
    )
    mode = mode_of(stores)

    document.diagnostics.extend(config_diagnostics(filter_estate(config, selection)))
    document.diagnostics.extend(unlistable_stores(leftovers.unlistable))
    document.selection = selection.as_json() or None
    document.lock = build_status_section(states, mode=mode)
    document.finish(
        ExitCode.SUCCESS,
        # `ok` is every path that was looked at, because looking succeeded. A
        # held lock is not a failed path -- `failed` here would put a red number
        # in front of a colleague doing their job. Discovered paths count too:
        # they were examined, and `summary.total` is what was examined.
        Summary(total=len(states), ok=len(states), changed=0, failed=0),
    )
    return render_status(paths, states, match=selection.select, mode=mode)


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

    # No `estate=`, and that is a decision rather than the one verb that was
    # missed when layer 4 was wired up (#424, raised in review on #425).
    # `01-configuration.md` §3a records it; the short form is that this verb
    # addresses a **vault document** by path and takes no selector at all, so
    # there is no estate for a target's or a group's block to arrive from -- and
    # gating it here would guard nothing, because every verb that would use this
    # lock to change that target is already refused by the same block.
    # `defaults` and a profile still refuse it, as they always did.
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


def _confirm_environments(
    plan: Any, run: Invocation, *, action: str, confirmed: bool, noun: str
) -> None:
    """P5's environment gate: ask before mutating anything in a listed environment.

    ``safety.confirm_environments`` had been parsed, ratcheted as a union across
    layers, and read by nothing (#292) -- a config that looked like protection and
    was not, which is worse than the setting not existing. This is the consumer,
    and since #294 it is the only one: P5's other two triggers -- a built-in
    `prod`, and a blast radius over `max_targets` -- were **declined** rather than
    left for later. A target marked `environment: prod` that no layer listed is
    not prompted for, by design.

    **The flag satisfies the setting**, rather than being a separate gate that
    also has to pass. P5 says every mutating command supports ``--confirm``, and
    the setting says these environments are not entered *without an explicit yes*;
    ``--confirm`` is that yes given in advance. So what the setting configures is
    "make this verb need a yes here", which is coherent, cheap, and leaves a
    scheduler one flag to add rather than an environment list to keep in step with
    its config.

    **A `--dry-run` is never gated**, which is the opposite of what
    :func:`~sopuli.safety.refuse_if_readonly` does and is right for the opposite
    reason. `readonly` is about whether the verb is available at all; this is
    about assent, and a preview is how somebody decides what to assent *to*.
    Prompting before showing the plan would be asking for a yes to a question the
    operator is running the command to see.

    **`--force` does not satisfy it, and is not consulted here.**
    `00-principles.md` P3 settles that `--force` overrides the *account*
    guardrails of `02-oracle-privileges.md` §4 and never a safety setting -- it is
    not a setting, has no layer to arrive on, and so has nothing to relax
    (invariant 10).

    The plan goes to **stderr**, as `lock break`'s does: under ``--output json``
    stdout carries the run document and nothing else may touch it, and a prompt
    that appeared only in text mode would be a confirmation somebody could skip by
    asking for JSON.
    """
    if run.dry_run:
        return
    demand = confirmation_demanded(run.resolved, plan.blast_radius)
    if demand is None or confirmed:
        return
    if not _can_prompt():
        refuse_unconfirmed(demand, action=action, targets=plan.blast_radius.targets)
    click.echo(render_plan(plan, noun=noun), err=True)
    click.confirm(f"{action} in `{demand.named}`?", abort=True, err=True)


def _with_estate_safety(run: Invocation, config: Config) -> Invocation:
    """``run`` with the ``safety:`` blocks of the estate it selected merged in.

    P3's layer 4 for the safety settings, which until #424 was parsed and read by
    nothing: a ``readonly: true`` on a target refused no mutation, a
    ``max_targets`` on one bounded no run, and a ``confirm_environments`` on one
    asked nobody anything. :func:`~sopuli.safety.for_estate` is the merge and
    :mod:`sopuli.settings.sources` decides what contributes; this is only where
    the answer is put back so that every gate downstream reads it.

    Called once per verb, after every selector has narrowed ``config`` and before
    the plan is built -- which is invariant 4's requirement rather than a
    convenience. A readonly target discovered while the estate is being walked is
    exactly the generic mid-execution failure that invariant forbids.

    A new :class:`~sopuli.invocation.Invocation` rather than a mutation, because
    it is frozen, and it keeps the same run document: the object is shared, so
    everything a verb has already written to it stays written.
    """
    return replace(run, resolved=for_estate(run.resolved, config))


def _can_prompt() -> bool:
    """Whether there is somebody at a terminal to answer.

    Not a flag and not a profile key — a run is unattended when nobody could have
    been asked, which is what `invocation.actor.unattended` already says in the
    document (`01-configuration.md` §5). A profile's `confirm:` is parsed and
    waiting for a consumer; wiring it into the resolver is its own change.

    Asks :func:`~sopuli.output.tty.is_a_terminal` rather than `isatty()` directly
    (#419). The bare call raises `ValueError` on a closed or detached stdin, and
    that is exactly the run this question is being asked about: a scheduler or a
    service manager hands a command no stdin at all. Raising there replaced a
    clean refusal naming the environment with a traceback from inside the code
    that was trying to find out whether anyone was watching. Both answers refuse
    the unconfirmed run -- the difference is which one the operator can act on.
    """
    return is_a_terminal(sys.stdin)


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
    names: set[str],
    config: Config,
    *,
    token_file: Path | None = None,
    cache: dict[str, SecretStore] | None = None,
) -> Mapping[str, SecretStore]:
    """Open every store a survey needs, and only those.

    One connection per store rather than one per path: a store is a client, and
    an estate with forty paths in one vault should authenticate once.

    ``cache`` is the run's own client map (:attr:`Invocation.stores`), and it is
    what makes that sentence true **across** the calls as well as within one
    (#483, Copilot's review of #488). This function used to be called several
    times in a run -- for the lock stores, for the binding stores, and now for an
    admin credential's -- and each call opened its own clients, so a config whose
    admin ref and application documents live in one vault authenticated to it
    twice. Passed a cache, a name already opened is reused and only the rest are
    dialled.

    Every client here is built the same way, from the ``vaults:`` entry and the
    run's token file, so a same-named one is not merely similar but identical in
    construction -- which is what makes reuse safe rather than merely cheap.
    Nothing closes a store, so a shared client has no lifecycle to get wrong.

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
    # The name is checked above before the cache is consulted, so a dangling one
    # is refused whether or not some earlier call in this run happened to open a
    # store of that name -- the message is about the file, not about this cache.
    opened = {} if cache is None else cache
    for name in sorted(names):
        if name not in opened:
            opened[name] = connect(declared[name], env=os.environ, token_file=token_file)
    return {name: opened[name] for name in sorted(names)}


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
    ``docs/schemas/sopuli-config-1.7.schema.json`` is structural, deliberately
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

    # A backend or driver this machine cannot serve warns here and **exits 0**
    # (ADR-006, E4): the config is valid, the install is incomplete, and the two
    # are different findings about different machines. These are the only
    # warnings in this command that the config layer did not make, because
    # making them means asking what is importable and the config layer asks
    # nothing outside the document (`04-testing.md` §4).
    #
    # The same survey and the same function `doctor` uses, at a different level
    # (#238). `doctor` additionally *reports* the survey as a section, which is
    # E6 and its alone -- this command answers "is my file good", and a table of
    # every registry entry would bury the answer.
    warnings = install_diagnostics(install_survey(config), level="warning")
    document.diagnostics.extend(config_diagnostics(config))
    document.diagnostics.extend(warnings)
    targets = len(config.expanded_targets)
    document.finish(
        ExitCode.SUCCESS,
        Summary(total=targets, ok=targets, changed=0, failed=0),
    )
    return render_validation(paths, config, [warning.message for warning in warnings])


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
    targets: tuple[str, ...],
    accounts: tuple[str, ...],
    groups: tuple[str, ...],
    applications: tuple[str, ...],
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
    # The "still unverified (issue #90)" sentence above is a register entry
    # (unverified: t-verifier), and the marker sits here rather than in the
    # docstring because this docstring IS `creds check --help`. A marker is an
    # internal bookkeeping token; putting one in front of an operator would be
    # the same mistake as a debug string in a user-facing message. If hash mode
    # is ever settled, the help text three paragraphs up changes with it.
    document = run.document

    selection = selected(selectors, targets, accounts, groups, applications)
    refuse_unknown(run.config, selection)
    config = filter_estate(run.config, selection)
    document.selection = selection.as_json() or None
    document.diagnostics.extend(config_diagnostics(config))

    # C15's plan-time half (#250), before anything is planned: a profile's
    # `vault:` and SOPULI_VAULT are not consulted while bindings are built, so
    # this is the first moment a binding's store can be complete. The refusal
    # follows immediately because reading a credential is the whole command --
    # invariant 4 wants it here and not partway through the estate.
    config = binding_stores.complete(config, env=os.environ)
    binding_stores.refuse_unresolved(config, action="checking credentials")

    run = _with_estate_safety(run, config)
    plan = plan_builder.build(config, intent=["verify"])
    refuse_if_over_limit(run.resolved, plan.blast_radius, action="checking credentials")
    document.plan = plan.as_json()

    stores = _stores_for(
        {binding.vault for binding in config.bindings if binding.vault is not None},
        config,
        token_file=run.vault_token_file,
        cache=run.stores,
    )
    by_target = {expanded.name: expanded for expanded in config.expanded_targets}

    rows: list[tuple[Binding, check_states.Outcome]] = []
    results: list[dict[str, Any]] = []
    # Collected beside `results` and by the same out-parameter idiom: one is what
    # a consumer reads and the other is what a person does, and both are filled
    # from one `grace_warning` call so they cannot disagree (#309).
    notices: list[str] = []
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
                notices=notices,
            )
        )

    document.results = results
    states = [outcome.state for _, outcome in rows]
    document.finish(check_states.exit_code_for(states), summarise(states))
    return "\n".join([render_plan(plan, noun="check"), "", render_check(rows, notices=notices)])


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
    notices: list[str],
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
            credential = _admin_credential(target, run, config)
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
                    notices=notices,
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
    notices: list[str],
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
    # Bound up front because the branch below may never reach a login at all -- a
    # missing account, no stored password, or a status that already settles the
    # answer. `None` there is the same "nothing was attempted" the rest of this
    # function already means by it.
    verification: VerifyResult | None = None
    # Bound before the `try` for the error path's sake: an account read before a
    # later step failed is still an account that was read (#386).
    user: UserState | None = None
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
        # What the database said before the failure still stands. A login that
        # raised says nothing about the account's age or its grace period, and
        # dropping them would leave `password_age_days` missing with neither the
        # value nor W021's reason for its absence (#386, Copilot on #421).
        out.append(
            build_result(
                binding,
                outcome,
                age_days=check_states.password_age_days(
                    None if user is None else user.password_changed_at
                ),
                duration_ms=_elapsed(started),
                error=reported,
                warnings=_result_warnings(
                    check_states.grace_warning(user),
                    None,
                    None if user is None else user.password_changed_unknown,
                ),
            )
        )
        return binding, outcome

    # One call, two channels: `results[].warnings[]` for a consumer and a line
    # under the table for a person. Computing it twice is how they would come to
    # disagree about one window (#309).
    grace = check_states.grace_warning(user)
    if grace is not None:
        notices.append(_account_notice(binding, grace))

    # What the *server* said on a login that worked, which is a different source
    # from the status column above and is reported beside it rather than folded
    # into it (#322). On a grace-period account both fire, and that is the
    # intended shape: the second is the server's own words for the first.
    server = None if verification is None else verification.warning
    if server is not None:
        notices.append(_account_notice(binding, server))

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
            warnings=_result_warnings(
                grace, server, None if user is None else user.password_changed_unknown
            ),
        )
    )
    return binding, outcome


def _result_warnings(
    grace: str | None, server: str | None, changed_unknown: str | None = None
) -> tuple[tuple[str, str], ...]:
    """The coded entries for one account's ``results[].warnings[]``.

    Order is the order they were learned: the account's state is read before the
    login is attempted, and on a run where the lockout guard declined there is no
    server entry at all. ``changed_unknown`` is read with that state, so it sits
    beside the grace period rather than after the login (#386).
    """
    found = []
    if grace is not None:
        found.append((PASSWORD_GRACE_PERIOD, grace))
    if changed_unknown is not None:
        found.append((PASSWORD_CHANGE_DATE_UNKNOWN, changed_unknown))
    if server is not None:
        found.append((LOGIN_WARNING, server))
    return tuple(found)


def _account_notice(binding: Binding, message: str) -> str:
    """A finding about one account, addressed to a person rather than a consumer.

    Not named for any one of them: the grace period was the first (#309) and the
    server's own login warning is the second (#322), and both want the same line
    under the same table.

    The document keeps the account and target in fields of their own; a line
    under a table has to carry them itself, because it is read next to other
    accounts' lines and not next to its own row.
    """
    return f"{binding.account} on {binding.target}: {message}"


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
@click.option(
    "--offline",
    is_flag=True,
    default=False,
    help="Do not connect to any target to read password constraints. Draw from the policy alone.",
)
@click.option(
    "--promote",
    is_flag=True,
    default=False,
    help="Write straight to `current` instead of staging. Still asks no database anything.",
)
@click.option(
    "--overwrite-current",
    "overwrite",
    is_flag=True,
    default=False,
    help="Authorise replacing a `current` that already exists. Required wherever one does.",
)
@click.option(
    "--confirm",
    is_flag=True,
    default=False,
    help="Proceed without asking. Required where `safety.confirm_environments` applies.",
)
@global_options
def creds_generate(
    selectors: tuple[str, ...],
    targets: tuple[str, ...],
    accounts: tuple[str, ...],
    groups: tuple[str, ...],
    applications: tuple[str, ...],
    policy_name: str | None,
    from_stdin: bool,
    no_policy_check: bool,
    offline: bool,
    promote: bool,
    overwrite: bool,
    confirm: bool,
    run: Invocation,
) -> str:
    """Draw a new password per the policy and stage it in the vault.

    **The database is read and never written.** Step 2 of the use case asks one
    connection per selected target for the one constraint that can be known in
    advance -- how long a password may be, in that database's own character set
    -- and the strictest answer governs the draw (issue #317). Nothing is issued,
    and the argument for taking the advisory lock is untouched: the lock lives in
    the vault (Q2, issue #83) because this command makes no *change* a
    database-side lock could have protected, which was never the same claim as
    making no connection.

    A target that cannot be reached is not a failure. The policy's declared
    length governs instead, which is the documented fallback, and the run says
    which of the two happened rather than leaving a reader to assume the estate
    agreed. `--offline` declines to ask at all, for staging against an estate
    that is down on purpose.

    **Staging is deliberately separate from applying.** It lets an operator
    prepare a password, get a change window approved, and apply later -- and it
    makes each half independently retryable. Nothing is using the new password
    until `sopuli creds apply` puts it in the database and promotes it.

    **`--promote` writes `current` instead**, for first adoption of an account
    that already exists and whose password is not in the vault (use case section
    4). It is invariant 7's one exception and it is not a small one: what the
    invariant protects is a `current` applications are reading being replaced
    before any database can serve the new value. Where the account has no
    `current` there is no such window and the write is unremarkable; where it has
    one, `--overwrite-current` has to say so, and without it the run refuses at
    plan time naming the accounts. The value `current` held moves to `previous`
    in the same write, and any `pending` is cleared -- a staged password left
    behind is one the next `apply` would prefer to what was just promoted.

    **A second run replaces what was staged, and reports a change.** That is
    outside the idempotency invariant rather than excused from it, decided in
    issue #254 and placed by #454's scope rule: the invariant governs commands
    that converge on a state, and drawing a fresh random secret has no state to
    converge on. The run warns that it replaced a staged password, because
    anything already holding the old one is now stale.

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
    refuse_if_readonly(
        run.resolved, action="promoting a password" if promote else "staging a password"
    )

    selection = selected(selectors, targets, accounts, groups, applications)
    refuse_unknown(run.config, selection)
    config = filter_estate(run.config, selection)
    document.selection = selection.as_json() or None
    document.diagnostics.extend(config_diagnostics(config))

    config = binding_stores.complete(config, env=os.environ)
    binding_stores.refuse_unresolved(
        config, action="promoting a password" if promote else "staging a password"
    )

    action = "promoting a password" if promote else "staging a password"
    run = _with_estate_safety(run, config)
    refuse_if_readonly(run.resolved, action=action, estate=config)
    plan = plan_builder.build(
        config, intent=["generate", "vault_promote" if promote else "vault_write_pending"]
    )
    refuse_if_over_limit(run.resolved, plan.blast_radius, action=action)
    document.plan = plan.as_json()
    _confirm_environments(plan, run, action=action, confirmed=confirm, noun="generation")

    bindings = [binding for binding in config.bindings if binding.secret is not None]
    if not bindings:
        document.finish(ExitCode.SUCCESS, Summary())
        return render_plan(plan, noun="generation") + "\n\nnothing to stage"

    supplied = _password_from_stdin() if from_stdin else None
    limits = _constraints_for(bindings, run, config, offline=offline)
    document.constraints = build_constraints(limits)
    notices = constraint_diagnostics(limits, supplied=supplied is not None)
    document.diagnostics.extend(notices)
    candidates = [
        _candidate(
            binding,
            config,
            name=policy_name,
            supplied=supplied,
            enforce=not no_policy_check,
            limits=limits.limits,
        )
        for binding in bindings
    ]
    writes = staging.group(candidates)
    names = {write.key.store for write in writes}

    # **A promote reads before it plans**, which is why the stores open here
    # rather than after the `--dry-run` return. The refusal is a plan-time one
    # (invariant 4) and the plan itself has to say which accounts would be
    # seeded and which replaced, so both need the documents -- and a preview
    # that could not tell those apart would be a preview of the wrong question.
    # An ordinary `--dry-run` still opens nothing.
    stores = (
        _stores_for(names, config, token_file=run.vault_token_file, cache=run.stores)
        if promote or not run.dry_run
        else {}
    )
    held = _current_holders(writes, stores) if promote else {}
    if held and not overwrite and not run.dry_run:
        # Never under `--dry-run`: a preview is how somebody finds out they need
        # the flag, and refusing to show it would leave them guessing which
        # accounts it was about.
        _refuse_overwrite(held)

    # Between the plan and the write table, which is where they answer the
    # question the plan raises: it says which targets are in scope, and these say
    # what those targets said about a password. Both absent under `--offline`,
    # where nothing was asked -- and where there is nothing to ask about there is
    # nothing to be told, so the notes cannot appear without the line.
    #
    # **The notes are rendered rather than left in `diagnostics[]`.** A run-level
    # warning is invisible to somebody reading a terminal -- the emitter prints
    # the command's text, not the document -- and a verify function reported only
    # in JSON is reported to nobody who ran this by hand. The same block `check`
    # and `config validate` print, for #309's reason: a warning that cannot be
    # seen in the default output is not surfaced.
    read = render_constraints(limits)
    lines = [render_plan(plan, noun="generation"), ""]
    if read is not None:
        # `SOPULI-W015` is deliberately not among them: the line above already
        # says the estate was not read, in plainer words and in both of the
        # shapes that code covers. The code exists so a JSON consumer can branch
        # on it, and printing the sentence twice under a heading that says
        # "notes" would teach a reader that the block repeats itself.
        told = [one.message for one in notices if one.code != CONSTRAINTS_UNREAD]
        lines.extend([read, *render_notices(told), ""])
    table = (
        render_promotion_table(writes, held)
        if promote
        else render_write_table(writes, stage=PENDING)
    )
    header = "\n".join([*lines, *table])
    if run.dry_run:
        # Invariant 8: print the plan, write nothing, take no lock. No `results`
        # either -- `plan` already says what would happen, at the same grain, and
        # a second vocabulary for "would have" would be a state nobody can act on.
        document.finish(ExitCode.SUCCESS, Summary(total=len(candidates)))
        return f"{header}\n\nnothing was written (--dry-run)"

    manager = LockManager(
        stores={name: _lockable(name, config, stores) for name in names},
        correlation_id=document.correlation_id,
        command="creds generate",
        selection=describe_selection(selection),
        break_expired=_break_expired(run),
    )

    results: list[dict[str, Any]] = []
    rows: list[tuple[Candidate, str, str]] = []
    stolen: LockStolenError | None = None
    try:
        with manager.holding([write.key for write in writes]):
            for write in writes:
                # The fence, before the write rather than after the lock (UC-1
                # §8). The window it guards is small here -- acquire, read,
                # write -- but "small" is not a property the next change to this
                # loop preserves, and a staged password written under somebody
                # else's lock is one the run that holds it will promote.
                try:
                    manager.check(write.key)
                except LockStolenError as lost:
                    stolen = lost
                    break
                rows.extend(
                    _promote_document(
                        write, stores[write.key.store], authorised=overwrite, out=results
                    )
                    if promote
                    else _stage(write, stores[write.key.store], out=results)
                )
    except LockDeniedError as denied:
        _record_locks(document, manager, denied=denied)
        raise

    _record_locks(document, manager)
    document.results = results
    states = [state for _, state, _ in rows]
    if stolen is not None:
        # The same split `creds apply` makes, for the same reason: 7 asserts
        # nothing happened, which is a lie once a document has been staged.
        document.diagnostics.append(
            Diagnostic(level="error", message=stolen.message, code=LOCK_LOST)
        )
        document.finish(
            ExitCode.PARTIAL if rows else ExitCode.LOCK_HELD, summarise_generate(states)
        )
        body = f"{header}\n\n{render_generate(rows)}\n\n{stolen}"
        return "\n".join([body, *render_notices(_lock_notices(manager))])

    document.finish(
        ExitCode.FAILURE if FAILED in states else ExitCode.SUCCESS,
        summarise_generate(states),
    )
    return "\n".join(
        [f"{header}\n\n{render_generate(rows)}", *render_notices(_lock_notices(manager))]
    )


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
    limits: Sequence[ByteLimit] = (),
) -> Candidate:
    """One account's password, drawn or validated against its policy.

    Resolved per binding rather than once for the run, because a selection
    spanning two applications with different policies is the ordinary case. Only
    `--policy` is global, and it is applied by overriding the binding's own name
    before the file's chain is consulted -- so it wins over an application entry
    and still goes through the same dangling-name check every policy name gets.

    ``limits`` is every answered target's, resolved once for the run by
    :func:`_constraints_for` and passed in rather than read here: they are a
    property of the *targets*, not of the binding, and a function called once per
    account is the wrong place to open a connection. Empty is the documented
    fallback -- no target answered, or none was asked -- and the policy's declared
    length then governs, which is what
    :func:`sopuli.generate.candidate_for` already does with it.
    """
    effective = binding if name is None else replace(binding, policy=name)
    chosen, policy = staging.policy_for(config, effective)
    return staging.candidate_for(
        binding, policy, name=chosen, limits=limits, supplied=supplied, enforce=enforce
    )


def _constraints_for(
    bindings: Sequence[Binding],
    run: Invocation,
    config: Config,
    *,
    offline: bool,
) -> Constraints:
    """What the selected targets say a password may be (#317, UC-1 §4 step 2).

    **One connection per target, not per account.** §4 asks for "one
    representative target", which for a command whose unit of work is an account
    and whose selection routinely puts several accounts on one database means:
    ask each distinct target once, and let the strictest answer govern. Asking
    per account would multiply connections by a factor the config decides.

    **Every failure here is a caveat, not an error.** A target that will not
    answer costs the run nothing but strictness, and §4 says so plainly: fall back
    to the policy's declared limits and say so. That is why this catches broadly
    -- a listener that is down, a credential that is wrong, a driver that is not
    installed and a wallet that cannot be read are all the same thing to a
    command that is not going to write to a database either way.

    `--dry-run` still reads. The plan is a claim about what would be staged, and
    a preview that skipped the constraint would be previewing a different draw
    from the one the real run makes.
    """
    if offline:
        return Constraints(source=constraint_source.UNREAD)

    readings: list[tuple[str, ByteLimit]] = []
    accounts: list[tuple[str, AccountConstraints]] = []
    unreachable: list[str] = []
    for name in dict.fromkeys(binding.target for binding in bindings):
        session = None
        try:
            session = _open_session(_expanded(config, name), run, config)
            readings.append((name, session.byte_limit()))
            accounts.extend(_profile_readings(session, name, bindings))
        except Exception:  # noqa: BLE001 -- every failure is the same caveat
            unreachable.append(name)
        finally:
            if session is not None:
                with suppress(Exception):
                    session.close()
    return constraint_source.survey(readings, unreachable=unreachable, accounts=accounts)


def _profile_readings(
    session: Any, target: str, bindings: Sequence[Binding]
) -> list[tuple[str, AccountConstraints]]:
    """The reporting half of §4 step 2, on the connection already open (#317).

    A verify function, the reuse resources and the account's verifiers -- read
    per account because they are properties of an account's *profile*, and read
    over the session the byte limit came from because a second connection to the
    same database to ask a second question would be a connection per account by
    another name.

    **A failure here is silence, not a caveat.** The target answered: it gave the
    limit that governs the draw, and losing that because a profile could not be
    read would turn a report nobody asked for into a downgrade of the one thing
    this command needs. So it is caught per account, and an account that could
    not be read is simply absent from the section -- which is what the section
    means by absent.
    """
    found: list[tuple[str, AccountConstraints]] = []
    for account in dict.fromkeys(
        binding.account for binding in bindings if binding.target == target
    ):
        try:
            one = session.password_constraints(account)
        except Exception:  # noqa: BLE001 -- reporting only; see the docstring
            continue
        if one is not None:
            found.append((target, one))
    return found


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


def _current_holders(
    writes: Sequence[DocumentWrite], stores: Mapping[str, SecretStore]
) -> dict[LockKey, tuple[str, ...]]:
    """Which selected accounts already have a `current`, per document (#257).

    The input to both halves of `--promote`'s gate: the plan-time refusal, and
    the plan's own split between accounts that would be **seeded** and accounts
    whose `current` would be **replaced**. Those are different risks and an
    operator should not have to count them.

    **Read before the lock, and used for neither of the values written.** What
    comes back here is a classification and nothing else -- the password that
    becomes ``previous`` is read again inside the lock, by
    :func:`_promote_document`, because a value read before acquiring is a value
    another run may have replaced in between. Carrying it forward would write a
    `previous` that never was `current`.

    A document that cannot be read contributes nothing rather than raising. The
    write is about to fail on the same store and will say so per document with
    the store's own message; refusing here would report a vault outage as a
    refusal to overwrite, which is a different thing to go and fix.
    """
    found: dict[LockKey, tuple[str, ...]] = {}
    for write in writes:
        store = stores.get(write.key.store)
        if store is None:  # pragma: no cover - `names` is built from these keys
            continue
        try:
            document = store.read(write.key.path)
        except Exception:  # noqa: BLE001 -- see the docstring: the write reports it
            continue
        holders = tuple(
            candidate.binding.account
            for candidate in write.candidates
            if _holds_current(document, candidate)
        )
        if holders:
            found[write.key] = holders
    return found


def _holds_current(document: Any, candidate: Candidate) -> bool:
    """Whether this account's `current` is already there.

    A ref that will not resolve is **not** a holder. `resolve` raises on a
    document of the wrong shape -- a container where a password should be -- and
    that is a configuration problem the write will report; reading it as "there
    is a current here" would turn it into a refusal naming the wrong cause.
    """
    ref = candidate.binding.secret
    if ref is None:  # pragma: no cover - bindings without a ref never reach here
        return False
    try:
        return resolve(document.data if document is not None else None, ref) is not None
    except Exception:  # noqa: BLE001 -- see the docstring
        return False


def _refuse_overwrite(held: Mapping[LockKey, Sequence[str]]) -> None:
    """Stop a promote that would replace a `current` nobody authorised (#257).

    Invariant 7's exception is `--overwrite-current` and this is where the
    exception is enforced. **Exit 8**, which is "aborted, or confirmation
    declined": a required authorisation nobody gave is that, and the file is not
    wrong and the run is not broken.

    **Named accounts, not a count.** The operator's next move is to decide
    whether those particular passwords may be replaced, and a message saying
    "3 accounts" sends them to `--dry-run` to find out which -- which they can
    still do, and should not have to.
    """
    named = sorted(account for accounts in held.values() for account in accounts)
    listed = ", ".join(named)
    raise RefusedError(
        f"{len(named)} of the selected accounts already have a `current` in the vault "
        f"({listed}), and promoting would replace what applications are reading",
        hint=(
            "pass --overwrite-current to authorise replacing them, --dry-run to see "
            "which would be seeded and which replaced, or drop --promote to stage a "
            "`pending` instead"
        ),
    )


def _promote_document(
    write: DocumentWrite,
    store: SecretStore,
    *,
    authorised: bool,
    out: list[dict[str, Any]],
) -> list[tuple[Candidate, str, str]]:
    """Write one document's passwords straight to `current` (#257, UC-1 §4).

    The same shape as :func:`_stage` -- one read, one compare-and-set, one
    outcome shared by every account in the document -- and the same reason for
    sharing it: one write either landed or it did not.

    **The authorisation is checked again here**, against the document this run
    actually holds the lock on. The plan-time refusal reads before acquiring, so
    a `current` written in between would otherwise be replaced by a run that was
    told there was none. Where the flag was passed there is nothing left to
    check: the overwrite is authorised wherever it is found.

    **`previous` comes from this read**, not from the plan-time one. It is the
    value `current` held a moment ago under this lock, which is the only reading
    that can be true of the write it accompanies.

    Reuses :func:`sopuli.apply.promotion_patch` rather than spelling a second
    promotion. What that function does beyond `current` and `previous` is
    exactly what is wanted here: it clears `pending` and the `origin` describing
    it, and a staged password left beside a freshly promoted one is a password
    the next `apply` would prefer -- `--source` defaults to `pending` where there
    is one, so leaving it would let a later run undo this one.

    A seeded document therefore acquires an empty ``pending`` and ``origin``,
    which is the clearing meeting a document that had neither. Cosmetic and
    deliberately not special-cased: :meth:`~sopuli.payload.StageLayout.read`
    answers an empty container exactly as it answers an absent one, and one
    definition of what a promotion writes is worth more than a tidier first
    version.
    """
    existing = store.read(write.key.path)
    cas = 0 if existing is None else existing.version
    data = existing.data if existing is not None else None

    entries: list[apply_states.Promotable] = []
    replaced: list[str] = []
    for candidate in write.candidates:
        ref = candidate.binding.secret
        try:
            held = resolve(data, ref) if ref is not None else None
        except StoreError as error:
            # A document shaped the way this ref does not address -- the config
            # and the vault disagree about where a password lives. Reported per
            # document like a refused write, rather than raised: it is one
            # document's problem, and a run over twenty of them should write the
            # nineteen it can. The plan-time read reached the same document and
            # said nothing for the same reason (`_holds_current`), which is what
            # makes this the place the disagreement is named.
            reported = _as_error(error)
            return _reported(
                write, FAILED, reported.message, out=out, stage=CURRENT, error=reported
            )
        if held is not None:
            replaced.append(candidate.binding.account)
        entries.append(
            apply_states.Promotable(
                binding=candidate.binding,
                value=candidate.value,
                replaces=held,
                policy=candidate.policy,
                # Empty, and that is the whole of what `--promote` is: no target
                # confirmed this password, because none was asked. A stamp
                # naming targets would claim a confirmation that never happened.
                targets=(),
            )
        )

    if replaced and not authorised:
        return _reported(
            write,
            FAILED,
            f"a `current` appeared for {', '.join(replaced)} after the plan was made, "
            f"and replacing it was not authorised (--overwrite-current)",
            out=out,
            stage=CURRENT,
        )

    patch = apply_states.promotion_patch(entries, at=utc_now(), by=_rotated_by())
    try:
        written = write_credential(store, write.key.path, patch, cas=cas)
    except Exception as error:  # noqa: BLE001 -- a per-document finding
        reported = _as_error(error)
        return _reported(write, FAILED, reported.message, out=out, stage=CURRENT, error=reported)

    return _reported(
        write,
        VAULT_ONLY,
        f"promoted to v{written.version}",
        out=out,
        stage=CURRENT,
        version=written.version,
        overwritten=tuple(replaced),
        mechanism=written.mechanism,
    )


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
    stage: str = PENDING,
    version: int | None = None,
    replaced: Mapping[str, int] | None = None,
    overwritten: Sequence[str] = (),
    mechanism: str | None = None,
    error: Error | None = None,
) -> list[tuple[Candidate, str, str]]:
    """One document's outcome, recorded per account.

    The *write* is shared, so the state and the version are; **what was replaced
    is not**. In a shared document one account can have had a `pending` staged
    while its neighbours did not, and telling the neighbours their password was
    replaced sends somebody looking for a credential that never existed. So the
    warning and the detail suffix are looked up per account.

    ``overwritten`` is the same argument one stage along (#257): a `--promote`
    can seed one account and replace another's `current` in the same write, and
    replacing a `current` is the more consequential of the two to report to the
    wrong account.
    """
    replaced = replaced or {}
    rows = []
    for candidate in write.candidates:
        account = candidate.binding.account
        was = replaced.get(account)
        line = detail if was is None else f"{detail}, replaced the pending in v{was}"
        if account in overwritten:
            line = f"{line}, replaced the current"
        out.append(
            build_generate_result(
                candidate,
                state=state,
                stage=stage,
                version=version,
                replaced=was,
                overwritten=account in overwritten,
                mechanism=mechanism,
                changed=state in WRITTEN,
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
    "--source",
    "source_stage",
    type=click.Choice(SOURCES),
    default=None,
    help=(
        "Which vault stage to apply. Default: pending if one is staged, else "
        "current. `previous` is the rollback and needs --confirm."
    ),
)
@click.option(
    "--confirm",
    is_flag=True,
    default=False,
    help="Proceed without asking. Required for --source previous.",
)
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
    "--preflight",
    "preflight_all",
    is_flag=True,
    default=False,
    help=(
        "Survey every target before writing anything: reachable, the scope it "
        "claims, the accounts declared, the privileges needed. Refuses the run "
        "rather than discovering it half way through."
    ),
)
@click.option(
    "--lockout-margin",
    type=click.IntRange(0, 100),
    default=DEFAULT_MARGIN,
    show_default=True,
    help="Refuse to attempt a login within this many tries of the lockout limit.",
)
@click.option(
    "--repair",
    "repair_document",
    metavar="FILE",
    type=click.Path(path_type=Path),
    default=None,
    help=(
        "Act only on what a previous run left unconfirmed. Takes a run document "
        "-- an apply that exited 4, or a check that exited 3. Narrows the run; "
        "it cannot extend it."
    ),
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help=(
        "Waive the account guardrails of 02-oracle-privileges.md section 4, "
        "checks 2 to 5: vendor-maintained, password file, admin role, deny list. "
        "Never check 1 -- an account the config does not declare is refused "
        "whatever this says. Every waiver is recorded in the run document."
    ),
)
@global_options
def creds_apply(
    selectors: tuple[str, ...],
    targets: tuple[str, ...],
    accounts: tuple[str, ...],
    groups: tuple[str, ...],
    applications: tuple[str, ...],
    source_stage: str | None,
    confirm: bool,
    strategy: str | None,
    preflight_all: bool,
    lockout_margin: int,
    repair_document: Path | None,
    force: bool,
    run: Invocation,
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

    **`--source previous` is the rollback**, and it is the escape hatch UC-1
    section 8 describes: an application turns out to have hard-coded the old
    password somewhere, and the database has to go back. It puts `previous` on
    every selected target and then **swaps the vault**, so `current` holds what
    the database now has and `previous` holds what was just taken off it. That
    leaves the estate consistent rather than deliberately drifted, and it is not
    a breach of the vault-is-master rule: both values came out of the vault, and
    no database was ever read for one.

    Rollback is bounded to one generation, because that is all the stage
    vocabulary can address (Q3, issue #84). It needs `--confirm`, and it refuses
    where a password is staged -- rolling back under a rotation in flight leaves
    a `pending` that the next run would move the estate forward with.

    **The rollover regime is chosen per account, and refused as a whole.** Where
    the database has gradual password rollover and the account's profile grants a
    window, that is the default -- both passwords authenticate until the window
    closes, so a partial apply causes no outage. `--strategy` names one instead,
    and an explicit one the estate cannot honour is refused before anything is
    changed rather than discovered halfway through. `--strategy staged` against a
    profile that grants a window is one of those refusals: Oracle opens the window
    because the profile says so, whatever this run asked for.

    **`--preflight` asks the whole estate first** (UC-1 section 8 step 3). One
    connection per target, before anything is written: is it reachable, is it the
    container the config claims, is it open read-write, does it have the accounts
    declared, does the service account hold the privileges. Every problem found
    is reported and the run refuses, because the alternative is discovering on
    target nine that target ten was never going to work -- by which point nine
    databases hold a password the vault has not promoted. Off by default, since a
    repair of one target should not pay for a survey of twenty.

    **Nothing is promoted that was not confirmed** (invariant 7). Where some
    targets confirmed and others did not, the database is left changed where it
    changed, `pending` stays, the run exits 4, and the accounts involved carry a
    warning saying so -- because applications fetch `current`, and until the
    promotion lands they are fetching a password part of the estate no longer
    has. Re-running is the remedy and is safe.

    **`--repair FILE` narrows that re-run to what the last one left behind.**
    It reads a previous run's document -- an apply that exited 4, or a check
    that exited 3 -- and acts only on the (account, target) pairs it reported as
    not confirmed. What it buys is logins, not capability: an unnarrowed repair
    converges the estate correctly and expensively, at one login per account per
    target against the failed-login counter section 7 exists to protect.

    It **narrows and cannot extend** (invariant 5): a pair the document names
    and the config no longer declares is dropped, not acted on. It combines with
    the other selectors as *and*, like every one of them. A document produced
    over a different configuration is refused before a target is dialled, which
    is the one mistake the narrowing does not make harmless; a document merely
    *old* warns and proceeds, because a pair since repaired costs one login and
    reports no change.

    Help text stays ASCII throughout, which is P4's rule.
    """
    document = run.document
    refuse_if_readonly(run.resolved, action="applying a password")
    _confirm_rollback(source_stage, confirmed=confirm, previewing=run.dry_run)

    selection = selected(selectors, targets, accounts, groups, applications)
    refuse_unknown(run.config, selection)
    config = filter_estate(run.config, selection)
    # After the selectors, so the two compose as *and* the way every pair of
    # selectors does, and so `refuse_unknown` still judges names against the
    # unfiltered estate. Before the plan, because `max_targets` and
    # `confirm_environments` must answer about the work this run will actually
    # do -- a blast radius counting the whole estate on a two-pair repair would
    # ask for a confirmation the run does not warrant.
    repair_notes: list[str] = []
    if repair_document is not None:
        repair_set = repair_module.read(repair_document, sources=run.sources)
        config = filter_to_pairs(config, repair_set.pairs)
        stale = repair_module.staleness(repair_set)
        if stale is not None:
            document.diagnostics.append(stale)
            # Printed as well as serialised, on #309's rule: the emitter writes
            # the document or the text and never both, so a diagnostic alone is
            # invisible to the person who ran this by hand -- and they are
            # exactly who a staleness warning is for. Carried on every return
            # path below, including the two that do nothing: "nothing to apply"
            # from a stale document is the case most worth explaining.
            repair_notes.append(stale.message)
    document.selection = selection.as_json() or None
    document.diagnostics.extend(config_diagnostics(config))

    config = binding_stores.complete(config, env=os.environ)
    binding_stores.refuse_unresolved(config, action="applying a password")

    run = _with_estate_safety(run, config)
    refuse_if_readonly(run.resolved, action="applying a password", estate=config)
    plan = plan_builder.build(
        config, intent=[*_attribute_intent(config), "verify", "password_set", "vault_promote"]
    )
    refuse_if_over_limit(run.resolved, plan.blast_radius, action="applying a password")
    document.plan = plan.as_json()
    # `--confirm` already means "proceed without asking" here -- it is what
    # `--source previous` requires -- so the flag answers both gates. Two flags
    # for one word would be the sort of distinction only the implementation cares
    # about.
    _confirm_environments(plan, run, action="applying a password", confirmed=confirm, noun="apply")

    bindings = [binding for binding in config.bindings if binding.secret is not None]
    if not bindings:
        document.finish(ExitCode.SUCCESS, Summary())
        return "\n".join(
            [
                render_plan(plan, noun="apply") + "\n\nnothing to apply",
                *render_notices(repair_notes),
            ]
        )

    keys = _document_keys(bindings)
    stores = _stores_for(
        {key.store for key in keys}, config, token_file=run.vault_token_file, cache=run.stores
    )

    if run.dry_run:
        # Invariant 8: print the plan, take no lock, write nothing. The documents
        # are still *read*, because which stage an account would be applied from
        # is the thing worth reviewing and a read needs no lock -- `check` runs
        # its whole survey without one.
        sources = _sources(bindings, _read_documents(keys, stores, run=run), stage=source_stage)
        # The pre-flight runs here too, and it is the combination worth having:
        # `--dry-run --preflight` is "show me the plan, and tell me whether it
        # would work". Skipping it under a dry run would make the flag silently
        # mean nothing on the invocation somebody would reach for first. It
        # writes nothing and needs no lock, which is why it can.
        findings = _preflight(
            _surveyable(sources), run, config, strategy=strategy, full=preflight_all
        )
        document.diagnostics.extend(_preflight_diagnostics(findings))
        if preflight.refusal(findings) is not None:
            return _refuse_preflight(
                findings, document, header=_header(plan, sources), notes=repair_notes
            )
        document.finish(ExitCode.SUCCESS, Summary(total=len(sources)))
        return "\n".join(
            [
                f"{_header(plan, sources)}\n\nnothing was applied (--dry-run)",
                *render_notices(repair_notes),
            ]
        )

    manager = LockManager(
        stores={name: _lockable(name, config, stores) for name in {key.store for key in keys}},
        correlation_id=document.correlation_id,
        command="creds apply",
        selection=describe_selection(selection),
        break_expired=_break_expired(run),
    )

    try:
        with manager.holding(keys):
            # Read under the lock, not before it. A document read first and locked
            # afterwards is one a concurrent `creds generate` may have staged into
            # in between -- and this run would then apply one password and promote
            # a different one.
            documents = _read_documents(keys, stores, run=run)
            sources = _sources(bindings, documents, stage=source_stage)
            findings = _preflight(
                _surveyable(sources), run, config, strategy=strategy, full=preflight_all
            )
            document.diagnostics.extend(_preflight_diagnostics(findings))
            if preflight.refusal(findings) is not None:
                # Before the first mutation and inside the lock, so the estate
                # cannot change between the survey and the run it was surveying
                # for. Releasing happens on the way out of `holding`, as it does
                # on every other path.
                return _refuse_preflight(
                    findings, document, header=_header(plan, sources), notes=repair_notes
                )
            applied, stolen = _apply_estate(
                sources,
                run,
                config,
                manager=manager,
                margin=lockout_margin,
                strategy=strategy,
                selection=selection,
                force=force,
                requested=source_stage,
            )
            if stolen is None:
                # §6.4's redraw, between the estate pass and the promotion (#312).
                # After, because a refusal is only discoverable by issuing the
                # statement; before, because nothing may be promoted until the
                # password every target holds is the one `pending` carries.
                applied, stolen = _redraw_estate(
                    applied,
                    documents,
                    stores,
                    run,
                    config,
                    manager=manager,
                    margin=lockout_margin,
                    strategy=strategy,
                    selection=selection,
                    force=force,
                    requested=source_stage,
                    diagnostics=document.diagnostics,
                )
            promotions: dict[LockKey, _Promotion] = {}
            if stolen is None:
                # Nothing is promoted after a takeover, and not because the write
                # would fail -- the fence would catch it. It is that a promotion
                # asserts every target holds this password, and a run stopped part
                # way through has no standing to assert it.
                promotions, stolen = _promote_documents(applied, documents, stores, manager=manager)
    except LockDeniedError as denied:
        _record_locks(document, manager, denied=denied)
        raise

    _record_locks(document, manager)
    document.results = [_applied_json(record, promotions) for record in applied]
    unchecked = _guardrail_caveats(applied)
    document.diagnostics.extend(unchecked)
    states = [record.outcome.state for record in applied]
    # `mutated`, not `changed`: an account this run unlocked and did not need to
    # re-password changed, and a summary counting only the DDL would call a run
    # that touched the estate an unchanged one (#300).
    changed = sum(1 for record in applied if record.mutated)
    if stolen is not None:
        # `sopuli.lock.errors` leaves this split to the command, because only the
        # command knows what it had applied: 7 says nothing happened, which is
        # true of a run fenced out before its first change and a lie about one
        # fenced out after its ninth. The diagnostic is what separates this exit 4
        # from the ordinary one -- that one is repaired by running `apply` again
        # (#264), and this one must not be.
        document.diagnostics.append(
            Diagnostic(level="error", message=stolen.message, code=LOCK_LOST)
        )
        code = int(ExitCode.PARTIAL if changed else ExitCode.LOCK_HELD)
    else:
        code = apply_states.exit_code_for(
            states,
            # Both questions are asked of the documents that actually read a
            # `pending`. A repair -- a document whose accounts were applied from
            # `current` -- has nothing to promote, so counting it as unpromoted
            # would make a mixed run look like UC-1 §8 case 7 and exit 4 with
            # everything confirmed and nothing wrong.
            promoted=all(one.version is not None for one in promotions.values() if one.promotable),
            promotable=any(one.promotable for one in promotions.values()),
        )
    document.finish(code, summarise_apply(states, changed=changed))
    rows = [(record.binding, record.outcome, record.mutated) for record in applied]
    promoted = sum(1 for one in promotions.values() if one.version is not None)
    # Exit 4's whole purpose is to point at a remedy (P5, UC-1 §5), so the run
    # that earns it says what to type -- narrowed the way this run was narrowed,
    # because a repair that walks the whole estate spends every login the partial
    # run already spent. Decided here rather than in the renderer: the exit code
    # has one author, and a table offering a remedy on a run that code called
    # successful would be the two describing one run differently (#264).
    # No remedy is offered after a takeover, and the suppression is the point:
    # #264's line says "run this again", which is the one thing not to do while
    # somebody else holds this estate's lock. `stopped` says what happened
    # instead, and `render_apply` refuses to print both.
    repair = (
        repair_invocation(
            selectors=selectors,
            config_paths=[str(path) for path in run.config_paths],
            profile=run.profile,
            source=source_stage,
            strategy=strategy,
        )
        if code == ExitCode.PARTIAL and stolen is None
        else None
    )
    table = render_apply(
        rows,
        promoted=promoted,
        source=source_stage,
        repair=repair,
        stopped=None if stolen is None else str(stolen),
    )
    # Printed as well as put in `diagnostics[]`, which is `creds generate`'s rule
    # and #309's before it: the emitter prints the command's text and not the
    # document, so a run-level warning is invisible to somebody reading a
    # terminal -- and a guardrail that did not run, reported only in JSON, is
    # reported to nobody who ran this by hand.
    notes = render_notices(
        repair_notes + [one.message for one in unchecked] + _lock_notices(manager)
    )
    return "\n".join([f"{_header(plan, sources)}\n\n{table}", *notes])


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
    #: Whether this run issued the ``ALTER USER … IDENTIFIED BY``. Narrower than
    #: the document's ``results[].changed``, which is any mutation at all -- see
    #: :attr:`mutated`, and :func:`sopuli.output.apply_view.build_result`, which
    #: is where the two are reconciled.
    changed: bool
    verified_before: Any | None = None
    version: int | None = None
    rollover: dict[str, Any] | None = None
    #: UC-1 §5's opt-in attributes, one entry per attribute the policy declared
    #: (#300). Empty on every estate that declares none, which is every estate
    #: that has not opted in.
    attributes: tuple[AttributeChange, ...] = ()
    #: §4 guardrails `--force` waived for this account (#286). Empty on every
    #: ordinary run, which is the point: §4 requires the override to survive the
    #: waiving, so the row carries what was gone past rather than merely that the
    #: run was allowed to proceed.
    overridden: tuple[guardrails.Refusal, ...] = ()
    #: §4 checks that could not be run against this account (#296). Empty where
    #: every check had its input; on Oracle, non-empty for check 3 on any target
    #: that has not taken the optional `V$PWFILE_USERS` grant, which is most of
    #: them. Reported as a run-level warning rather than on the row, because what
    #: could not be read is a grant on the *target* and one entry per account
    #: would say the same thing forty times.
    caveats: tuple[guardrails.Caveat, ...] = ()
    duration_ms: int | None = None
    error: Error | None = None
    #: Whether the server refused the *password itself* -- the vendor-neutral
    #: :attr:`~sopuli.driver.protocol.DriverError.regenerate` (#312). Kept on the
    #: record rather than read back off :attr:`error`, which is the run
    #: document's ``Error`` and carries only what the contract emits: adding a
    #: field there to satisfy an internal question would put a decision this tool
    #: makes into a schema other people parse.
    refused: bool = False
    #: How many *extra* passwords this account was given, over the one the run
    #: arrived with (#312). Zero on every ordinary run.
    redraws: int = 0

    @property
    def mutated(self) -> bool:
        """Whether this run changed anything about this account at all.

        The run-level count's question, and not :attr:`changed`'s: an account
        that was unlocked and whose password was already correct changed, and a
        summary that counted only the DDL would report a run that mutated the
        estate as having done nothing.
        """
        return self.changed or any(change.changed for change in self.attributes)


@dataclass(frozen=True)
class _Promotion:
    """What happened to one document once its targets were all in.

    ``version`` is ``None`` for a document that was not promoted, and ``reason``
    says which of the two cases that is: nothing needed promoting, or something
    did and the estate had not earned it.

    ``promotable`` is what keeps those two apart for the exit code. A document
    whose accounts were applied from `current` is a repair: the vault already
    holds what went on the database, so its ``version: None`` must not read as a
    promotion this run owed and did not make. Only the ones that owed a write are
    asked about -- a ``pending`` promoted forward, or a ``previous`` rolled back
    (`apply.PROMOTES`).
    """

    version: int | None
    reason: str
    promotable: bool = False
    mechanism: str | None = None
    error: Error | None = None


def _confirm_rollback(stage: str | None, *, confirmed: bool, previewing: bool) -> None:
    """Ask before a rollback, or refuse where nobody can be asked.

    UC-1 section 8 puts `--confirm` on this operation and only this one, and the
    reason is worth saying: `--source previous` is the one invocation whose
    *success* makes an application's current credential stop working. Every other
    thing `apply` does converges the estate on what the vault already says.

    The shape is `lock break`'s, for its reasons (:func:`_confirm_break`): the
    prompt goes to **stderr**, so a confirmation cannot be skipped by asking for
    JSON, and a closed stdin is a refusal rather than a prompt that reads EOF --
    exit 8 naming the flag is more use than click aborting on nobody's behalf.

    `--dry-run` needs no confirmation. Nothing is changed, and a preview an
    operator has to authorise is a preview they will stop taking.
    """
    if stage != PREVIOUS or confirmed or previewing:
        return
    if not _can_prompt():
        raise RefusedError(
            "rolling back needs confirmation, and there is nobody here to ask",
            hint=(
                "pass --confirm to answer in advance, or --dry-run to see the plan "
                "without touching anything"
            ),
        )
    click.confirm(
        "put the vault's `previous` password back on every selected target?",
        abort=True,
        err=True,
    )


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


def _record_locks(
    document: RunDocument, manager: LockManager, *, denied: LockDeniedError | None = None
) -> None:
    """The lock section, and what the run should say about how it got its locks.

    Called **after** the lock has been let go, which is the other half of the
    rule and the half that was wrong: `release()` flips `HeldLock.released`, so a
    section built while the run still held its locks reports `released: false`
    for locks it gives back immediately afterwards. `creds rotate` did that on
    three early-return paths inside `manager.holding(...)` -- the document said
    `false` while the store record said `released`.

    One function because the two halves must not come apart, and they had (#348).
    `lock_diagnostics` was written, unit-tested in `tests/test_lock_view.py`, and
    called by nothing -- so a run that took over an expired lock said so nowhere,
    and neither did a run holding an `advisory-only` lock. Both are documented
    output: `01-configuration.md` §5.3 says `break_expired` and `sopuli lock
    break` "emit the same warning code, because it is the same event", and
    `03-json-output.md` lists `SOPULI-W001` for the second.

    That mattered less while `break_expired` reached no manager, because the
    takeover it reports could not happen. It matters now, and reporting is not
    decoration here: `_taken_over`'s own docstring says the evidence is gone from
    the path the moment the takeover write lands, so if this run does not report
    it, nothing ever does.
    """
    document.lock = build_lock_section(manager, denied=denied)
    document.diagnostics.extend(lock_diagnostics(manager))


def _lock_notices(manager: LockManager) -> list[str]:
    """Lock findings a person reading a terminal has to see (#390).

    #309's rule applied to the one lock diagnostic that asks the reader to go
    and do something: a warning that cannot be seen in the default output is not
    surfaced, and the emitter prints the command's text rather than the
    document. A path created without `cas_required` is a thing to fix in the
    vault, and a JSON-only report of it reaches nobody who ran this by hand.

    **Only that one.** `SOPULI-W001` and `SOPULI-W002` stay in `diagnostics[]`
    alone, which is a gap rather than a decision -- do not read this function's
    narrowness as an argument that they belong in JSON only.
    """
    return [one.message for one in lock_diagnostics(manager) if one.code == LOCK_PATH_UNGUARDED]


def _break_expired(run: Invocation) -> bool:
    """Whether this run may take over a lock whose holder's claim has lapsed.

    `locking.break_expired` (#83) was resolved, ratcheted, cross-checked against
    `locking: advisory-only` at load *and* in `LockManager.__post_init__`, and
    implemented in `decide()` -- and no `LockManager` was ever built with it, so
    it was always `False` (#348). An operator who set the key got exit 7 on an
    expired lock, was told by `_hint_for` to set the key they had already set,
    and had no way to see from the output that it was not consulted. This is the
    wire.

    Absent is not `false`: the setting has no built-in, because nobody having
    asked is a different statement from somebody having written `false`, and
    only the second appears in `invocation.options`. Both mean the same thing
    here, which is why this reads as a plain truth test.

    Nothing checks `advisory-only` at this point on purpose. `references.py`'s
    `_check_breaking_locks_without_a_fence` already refuses the combination for
    the whole file -- any vault, not only the ones a run selects -- and the two
    layers this setting may come from are both blocks in that file. A third
    check here would be a fourth place to disagree about one rule.
    """
    answer = run.resolved.get("locking.break_expired")
    return bool(answer is not None and answer.value)


def _lock_key(binding: Binding) -> LockKey:
    """The lock guarding the document this account's credential lives in.

    One spelling, used by everything that has to name a document: the keys a run
    acquires, the fence check before an `ALTER USER`, the grouping the promotion
    commits by. Three copies of the same two-line expression is three chances for
    one of them to address a different document from the lock being held over it.

    Raises on a binding with no ref rather than returning ``None`` for the caller
    to skip on. Every caller is about to mutate, and "there was no lock to check,
    so none was checked" is the failure the fence exists to prevent, reached
    politely.
    """
    if binding.secret is None or binding.vault is None:
        raise ValueError(f"{binding.account!r} names no secret ref, so it has no lock")
    return LockKey(store=binding.vault, path=normalise_path(binding.secret.path))


def _read_documents(
    keys: Sequence[LockKey], stores: Mapping[str, SecretStore], *, run: Invocation
) -> dict[LockKey, Any]:
    """Each document once, whole.

    Whole rather than per ref, and once rather than per account, for two reasons
    that both matter. A promotion needs what ``current`` held in order to write
    it into ``previous``, so the read has to see more than the value being
    applied; and a document shared by six accounts read six times could return
    six different versions, which is a compare-and-set nobody could reason about.

    **The tool's one spinner lives here (#419)**, and it is here rather than at
    `_stores_for` because that is what measuring said. `_stores_for` looked like
    the slow step and is not: with `auth: { method: token }` nothing on that path
    opens a socket at all -- `connect` reads the token and constructs an
    `httpx.Client`, which is local work. Against a vault at an unroutable address
    with `timeout_s: 8`, opening the store took 0.7s and *this* function took the
    remaining eight. The round trip is here, on every auth method rather than on
    some of them, which is also why one spinner here covers what two would have.

    One per document rather than one for the loop: they are sequential, and
    naming the path is the difference between "something is happening" and
    "*this* is what is not answering".

    Nothing on this path prompts or prints -- the store layer writes to no
    stream -- which is what keeps the spinner clear of `sopuli.output.spinner`'s
    rule about never being live across a prompt. A confirmation, where there is
    one, is already past by the time a verb reads a document.
    """
    emitter = run.emitter()
    documents: dict[LockKey, Any] = {}
    for key in keys:
        with emitter.spinner(f"Reading `{key.store}:{key.path}`"):
            documents[key] = stores[key.store].read(key.path)
    return documents


def _sources(
    bindings: Sequence[Binding], documents: Mapping[LockKey, Any], *, stage: str | None = None
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
            else apply_states.source_for(stored.data, binding.secret, stage=stage)
        )
        found.append((binding, source))
    return found


def _stored_document(binding: Binding, documents: Mapping[LockKey, Any]) -> Any:
    if binding.secret is None or binding.vault is None:
        return None
    return documents.get(_lock_key(binding))


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
    manager: LockManager,
    margin: int,
    strategy: str | None,
    selection: Selection,
    force: bool = False,
    requested: str | None = None,
) -> tuple[list[_Applied], LockStolenError | None]:
    """Every account, target by target, one connection each.

    Grouped the way `check` groups and for the same reason: a target with six
    accounts in it is one login for this tool rather than six, and six would be
    six entries in that database's audit trail for one rotation.

    **The lease is renewed at each target boundary** (UC-1 §8 step 5), which is
    where the default 15-minute TTL would otherwise run out on an estate large
    enough to need it. A renewal is a write and goes behind the fence like every
    other, so the boundary is also the check that catches a takeover between one
    target and the next -- before the next target's first `ALTER USER` rather
    than after it.

    **A stolen lock ends the run and is returned, not raised.** §8 is explicit
    that the run aborts and mutates nothing further, and what it had already
    applied *stands* -- so the results collected so far are the run's document
    and must not be lost with the exception. That is why ``out`` is an
    accumulator: a takeover found before the third account of a target leaves the
    first two in it. The caller decides the exit code, which is the split
    `sopuli.lock.errors` describes -- 7 when nothing had been applied, 4 when
    something had, and only a command that knows what it applied can say.
    """
    by_target = {expanded.name: expanded for expanded in config.expanded_targets}
    grouped: dict[str, list[tuple[Binding, Source | None]]] = {}
    for binding, source in sources:
        grouped.setdefault(binding.target, []).append((binding, source))

    declared = _declared_accounts(run)
    applied: list[_Applied] = []
    for position, (name, work) in enumerate(grouped.items()):
        try:
            if position:
                manager.renew()
            _apply_target(
                by_target[name],
                work,
                run,
                config,
                manager=manager,
                margin=margin,
                strategy=strategy,
                declared=declared,
                selection=selection,
                force=force,
                requested=requested,
                out=applied,
            )
        except LockStolenError as stolen:
            return applied, stolen
    return applied, None


def _apply_target(
    target: ExpandedTarget,
    work: Sequence[tuple[Binding, Source | None]],
    run: Invocation,
    config: Config,
    *,
    manager: LockManager,
    margin: int,
    strategy: str | None,
    declared: frozenset[str],
    selection: Selection,
    force: bool = False,
    requested: str | None = None,
    out: list[_Applied],
) -> None:
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
            credential = _admin_credential(target, run, config)
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
            out.extend(
                _Applied(
                    binding=binding,
                    source=source,
                    outcome=check_states.Outcome(check_states.ERROR, reported.message),
                    changed=False,
                    duration_ms=elapsed,
                    error=reported,
                )
                for binding, source in work
            )
            return

        # Appended one at a time rather than built as a list, so that a fence
        # check failing on the third account leaves the first two in the run's
        # results. `_apply_one` lets a lock error through on purpose.
        for binding, source in work:
            out.append(
                _apply_one(
                    binding,
                    session,
                    manager=manager,
                    source=source,
                    margin=margin,
                    strategy=strategy,
                    declared=declared,
                    selection=selection,
                    force=force,
                    requested=requested,
                    # Resolved per binding rather than per run: two accounts on
                    # one target can sit on different policies, and only one of
                    # them may have opted into an attribute (#300).
                    attributes=apply_states.attributes_for(config, binding),
                )
            )
    finally:
        if session is not None:
            with suppress(Exception):
                session.close()


def _apply_one(
    binding: Binding,
    session: Any,
    *,
    manager: LockManager,
    source: Source | None,
    margin: int,
    strategy: str | None,
    declared: frozenset[str],
    selection: Selection,
    attributes: AccountAttributes,
    force: bool = False,
    requested: str | None = None,
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

    **The fence is re-read immediately before every mutating call** (UC-1 §8),
    and narrowed to this account's own document: that is the lock the change is
    about to be made under, and checking the run's other twenty would be twenty
    store reads to establish nineteen facts nothing here is about to act on.
    *Every* is the word #347 cost -- the attribute pass and the rollover close
    are mutations too, and each carries its own check rather than resting on the
    distance to the one before `set_password`.

    *Call*, not *statement*: `apply_attributes` may issue both an
    `ACCOUNT UNLOCK` and a `PROFILE` change under one check. The check is per
    driver call because that is the granularity the fence can have -- a run
    cannot re-read a vault between two statements the driver sends -- and the
    guarantee is that no call begins on a lock this run has lost.

    **A lock error is never a per-account finding.** Everything else that goes
    wrong with one account is a row in the table and the run carries on, which is
    exactly the wrong answer to a takeover: it would turn "somebody else owns this
    estate now" into a footnote and apply to the next account anyway. So it is
    re-raised ahead of the catch-all, and the run ends.

    **UC-1 §5's attributes are enforced before the first login** (#300), and only
    where the policy declared one. Before, because an unlock is what makes the
    login worth attempting at all -- a locked account refuses every one of them --
    and after the guardrail review, because §4 decides whether this account may be
    touched and an unlock is touching it.

    **A guardrail refusal is a `SKIPPED` row and never an error** (§4, #286). It
    is the one case where the tool declining to act is the tool working: the run
    does the rest of its job and the account carries its reason. ``declared`` is
    the config's whitelist for check 1, and it is the **unfiltered** set on
    purpose -- a selector narrows what a run touches and cannot un-declare an
    account (invariant 5), so passing the filtered estate would let `--select`
    change the answer to "is this account allowed at all".
    """
    started = time.monotonic()
    before = None
    overridden: tuple[guardrails.Refusal, ...] = ()
    caveats: tuple[guardrails.Caveat, ...] = ()
    enforced: tuple[AttributeChange, ...] = ()
    try:
        user = session.describe_user(binding.account)
        settled = apply_states.settled_before_acting(
            user, source, requested=requested, unlock=attributes.unlock
        )
        if settled is not None:
            return _Applied(binding, source, settled, changed=False, duration_ms=_elapsed(started))
        if user is None or source is None:
            # Unreachable: `settled_before_acting` returns an outcome for both.
            # Restated rather than assumed, because a fall-through here would
            # decide a mutation on a value nobody checked.
            raise ValueError(f"nothing to apply for {binding.account!r} and no reason given")

        # §4's account guardrails, before the first login rather than before the
        # statement (#286). Two reasons for the position: a refused account must
        # cost no login attempt, and `describe_user` above has already read every
        # fact the checks need -- so this is free where the alternative would have
        # been another round trip.
        review = guardrails.review(user, declared=declared, force=force)
        if not review.permitted:
            # §4's two cases, and the only thing separating them is how the
            # account got into this run (#297). Named: the operator asked for
            # something the tool will not do, and a run that reported success
            # would be reporting it for work nobody did. Fell inside a broader
            # selection: skipped, and the run does the rest of its job.
            named = selection.names(binding.account)
            return _Applied(
                binding,
                source,
                check_states.Outcome(
                    apply_states.REFUSED if named else apply_states.SKIPPED,
                    guardrails_reason(review, named=named),
                ),
                changed=False,
                duration_ms=_elapsed(started),
            )
        overridden = review.overridden
        # §4's third answer, carried on the accounts this run went on to act on
        # (#296). Not on the refused ones above: an account the guardrails turned
        # away was not touched, so what an unread check might have said about it
        # changed nothing.
        caveats = review.caveats

        if attributes.requested():
            # Fenced like every other mutation (P5, #347). `apply_attributes`
            # issues `ALTER USER ... ACCOUNT UNLOCK` and `ALTER USER ... PROFILE`
            # -- a smaller blast radius than a password, and still a database
            # change this run must not make on a lock it no longer holds. Before
            # #347 the only check in this function ran forty-five lines later,
            # which left the first account of the run and every account after the
            # first within a target unfenced.
            manager.check(_lock_key(binding))
            # The driver decides what still needs doing and reports a row either
            # way, which is where invariant 9 lives for these: an account that is
            # already unlocked is `changed: false` rather than an absent action.
            enforced = session.apply_attributes(user.name, attributes)
            if any(change.changed for change in enforced):
                user = session.describe_user(binding.account) or user
            # Asked again, and this time with no permission to unlock. The first
            # call let the run *reach* the attribute pass; this one is about the
            # state that pass left behind, and an account still locked here is one
            # whose password must not be changed after all.
            blocked = apply_states.settled_before_acting(user, source, requested=requested)
            if blocked is not None:
                return _Applied(
                    binding,
                    source,
                    blocked,
                    changed=False,
                    attributes=enforced,
                    overridden=overridden,
                    caveats=caveats,
                    duration_ms=_elapsed(started),
                )

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
                attributes=enforced,
                # Reported on the no-op path too. The waiver was granted and the
                # tool went on to touch an account §4 would have refused -- that
                # it turned out to need no change is a fact about the estate, not
                # about what was overridden, and an audit trail that recorded the
                # override only when something happened would be missing exactly
                # the runs somebody skims looking for `--force`.
                overridden=overridden,
                caveats=caveats,
                duration_ms=_elapsed(started),
            )

        manager.check(_lock_key(binding))
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
            #
            # Checked again rather than resting on the check before
            # `set_password` (#347). A DDL, a `describe_user` and a login with
            # `attempts=2` sit between the two, so the window is real -- but the
            # reason is the rule rather than the size of the window: `creds
            # finish-rollover` fences this same call, and one operation cannot
            # encode two different rules about whether the fence applies to it.
            manager.check(_lock_key(binding))
            session.finish_rollover(after_user.name)
            after_user = session.describe_user(binding.account) or after_user
            outcome = apply_states.after_change(after_user, after)
    except LockError:
        # See the docstring: the run is over, and turning that into one account's
        # ERROR row would let the loop apply the next account under a lock this
        # run no longer holds -- the outcome the fence exists to prevent, reached
        # through the error handler instead of past the check.
        raise
    except Exception as error:  # noqa: BLE001 -- a per-account finding
        reported = _as_error(error)
        return _Applied(
            binding,
            source,
            check_states.Outcome(check_states.ERROR, reported.message),
            changed=False,
            verified_before=before,
            # Empty where the failure came before the review, which is why both
            # are initialised above rather than assigned only on the path that
            # runs. An attribute that was enforced before the failure stays on the
            # row: it happened, and a row that dropped it would leave a mutation
            # this run made in no document at all.
            overridden=overridden,
            caveats=caveats,
            attributes=enforced,
            duration_ms=_elapsed(started),
            error=reported,
            # Asked of the exception, which is the only place the answer exists:
            # `_as_error` builds the run document's `Error` and keeps what the
            # contract emits, and this is a question the tool asks itself (#312).
            refused=getattr(error, "regenerate", False),
        )

    return _Applied(
        binding,
        source,
        _with_regime(outcome, regime, after_user),
        changed=True,
        verified_before=before,
        rollover=_rollover_json(after_user),
        overridden=overridden,
        caveats=caveats,
        attributes=enforced,
        duration_ms=_elapsed(started),
    )


def _attribute_intent(config: Config) -> list[str]:
    """UC-1 §5's attributes this run may enforce, for the plan (#300).

    ``intent`` applies to every unit -- :func:`sopuli.plan.build` is explicit
    about that -- and an attribute is declared per policy, so what this adds is
    what the *run* may do rather than what it will do to each account. That is
    already what an intent is: `password_set` is listed by every apply and issued
    only where the database does not already hold the password.

    Emitted only where something declared it, so an estate that has opted into
    nothing produces exactly the plan it produced before. That is the half worth
    getting right: `--dry-run` on an estate that would unlock an account has to
    say so, and one that would not must not imply it might.
    """
    attributes = [apply_states.attributes_for(config, binding) for binding in config.bindings]
    intent = []
    if any(one.unlock for one in attributes):
        intent.append(ACCOUNT_UNLOCK)
    if any(one.profile is not None for one in attributes):
        # Whether it would *move* an account needs the database and this is built
        # before anything connects, so what the plan says is that the run may set
        # a profile -- which is what an intent is. `password_set` is listed by
        # every apply and issued only where the database does not already hold the
        # password, on the same reading.
        intent.append(ATTRIBUTE_SET)
    return intent


def _declared_accounts(run: Invocation) -> frozenset[str]:
    """Every account the configuration declares, before any selector narrowed it.

    §4 check 1 asks whether the config declares this account at all, and
    invariant 5 says selectors filter the declared set rather than extend it --
    so the question is about the *file*, not about this run's slice of it. Taking
    the filtered estate would make `--select` able to change the answer, which is
    the one thing a whitelist must not have.

    In practice check 1 cannot fire from a mutating verb today: the bindings a run
    acts on are built from the same file. It is run anyway rather than assumed,
    because "enforced by construction" is a property of today's call graph and
    not of the guardrail.
    """
    return frozenset(binding.account for binding in run.config.bindings)


def guardrails_reason(review: guardrails.Review, *, named: bool = False) -> str:
    """Why an account was refused, in one line, naming every check that objected.

    Every refusal rather than the first: an operator clearing these is going to
    have to deal with all of them, and a message that revealed them one run at a
    time would be three runs to learn one fact. The checks are already ordered by
    §4's numbering, which is the order they read in.

    ``named`` adds what to do about it, and only there. An account that fell
    inside a broad selection needs no advice -- the run carried on and the row is
    informational -- while an operator who typed `--account DBSNMP` asked for
    this specific thing and is owed the sentence that says how to get it.
    """
    reasons = "; ".join(refusal.reason for refusal in review.refusals)
    if not named:
        return reasons
    overridable = all(refusal.overridable for refusal in review.refusals)
    remedy = (
        "pass --force to override, which is recorded"
        if overridable
        # Check 1, the one no flag reaches. Saying "--force" here would send an
        # operator to a flag that is going to refuse them again.
        else "declare it in `accounts:` first; no flag extends the whitelist"
    )
    return f"{reasons} -- you named this account, so the run stopped short: {remedy}"


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
        # Through `as_utc`: `to_rfc3339` reads a naive value as the machine's
        # local time, and an Oracle `DATE` is naive.
        found["ends_at"] = to_rfc3339(as_utc(user.rollover_ends_at))
    return found


def _admin_reader(target: ExpandedTarget, run: Invocation, config: Config) -> RefReader:
    """Read a target's `method: vault` admin credential through its store (#483).

    `admin.resolve` has taken a `read_ref` supplier since #175 and no call site
    ever passed one, so `_read_ref`'s "no store was available here" -- the branch
    its own hint calls *a caller that supplied no reader* -- was the only
    reachable one, and `method: vault` failed on every run of every verb. This is
    the supplier. It is the same gap #476 fixed for `prompt`, in the source P2
    ranks highest of the three that need something from this machine.

    **Everything happens inside the closure, and that is the design.**
    :func:`sopuli.admin.resolve` calls this only on the ``vault`` branch, so a
    target authenticating by wallet, prompt or variable never resolves a store
    name and never opens a socket -- which is the first consequence that module's
    docstring claims for taking its sources as suppliers, and it would stop being
    true the moment this function did any work eagerly. ADR-006's "base opens no
    sockets" is the same property one layer down.

    **One client per store per run**, through :attr:`Invocation.stores`. An
    estate of thirty-four targets sharing one vault authenticates once, which is
    the rule :func:`_stores_for` states -- and thirty-four authentications would
    also be thirty-four entries in that vault's audit log for one scheduled run.

    That cache is the **run's**, not this function's, and the distinction is
    Copilot's correction on #488. A per-admin cache made the rule true within
    this reader and false across the run: a config keeping its admin credential
    and its application documents in one vault -- the ordinary arrangement --
    opened that vault twice, once here and once for the bindings. Sharing one map
    keyed on the store name is what makes the sentence above hold, and it is safe
    because every client is built identically from the ``vaults:`` entry and the
    run's token file.

    **Which store** is still resolved through the admin ref's own chain, and that
    is the half worth keeping separate: a run may authenticate to a database from
    one vault while mastering its accounts in another. What is shared is the
    client for a name, never the decision about which name.
    """

    def read(ref: SecretRef) -> Secret:
        name = admin_store_name(target, ref, config=config, env=os.environ)
        if name is None:
            raise AdminCredentialError(
                f"target {target.name!r} authenticates from a vault, and nothing says which one",
                at=declared_at(target, "admin").key("auth").key("secret"),
                # Every link of `admin.store_name`'s chain, including the
                # profile: an operator who supplies the store through `--profile`
                # is doing something the chain allows, and a hint that omitted it
                # would send them to change something else instead.
                hint=(
                    f"put a prefix on the ref (`{ref}` -> `vault-dev:{ref}`), or name a "
                    f"store on the target's `vault:`, or set `defaults.vault`, "
                    f"${DEFAULT_STORE_VARIABLE}, or the active profile's `vault:`"
                ),
            )
        store = _stores_for({name}, config, token_file=run.vault_token_file, cache=run.stores)[name]
        stored = read_secret(store, ref)
        if stored is None:
            # An empty path is the operator's mistake rather than a store
            # failure, so it is worded as one: the store answered, and what it
            # answered was that there is nothing there. `read_secret` returns
            # `None` for every way of finding nothing (#183) -- no document, no
            # field, no key -- and they have one remedy here, which is to go and
            # look at the path.
            raise AdminCredentialError(
                f"target {target.name!r} authenticates from {name!r}, and there is "
                f"nothing at {str(ref)!r}",
                at=declared_at(target, "admin").key("auth").key("secret"),
                hint=(
                    "the store answered and the path is empty -- check the ref's path, "
                    "its field, and that this run's token may read it"
                ),
            )
        return stored.value

    return read


def _admin_credential(target: ExpandedTarget, run: Invocation, config: Config) -> AdminResolved:
    """Resolve one target's admin credential, and record where it came from (#477).

    The one place either happens, so that the reporting cannot be forgotten at a
    call site -- which is invariant 2's structural argument applied to
    *provenance* rather than to the value. :class:`~sopuli.admin.Resolved`
    classifies and does not decide; this is the caller its docstring names, and
    there is one of it rather than three.

    **At most one entry per target per run.** A target can be resolved twice in
    one run -- ``creds apply --strategy`` pre-flights the estate and then applies
    to it, over two connections -- and the fact being reported is a property of
    the target's *configuration*, which did not change between them. Told twice,
    a reader would reasonably wonder what was different about the second time.

    Deduplicated against the document rather than by remembering here, because
    the document is what actually gets emitted: a cache on this function would
    have to be per run, and the run already has one thing that is per run and
    holds diagnostics.
    """
    credential = admin_resolve(
        target,
        env=os.environ,
        prompt=run.prompt,
        read_ref=_admin_reader(target, run, config),
    )
    already = {(one.code, one.target) for one in run.document.diagnostics if one.code is not None}
    run.document.diagnostics.extend(
        one
        for one in admin_diagnostics(target.name, credential)
        if (one.code, one.target) not in already
    )
    return credential


def _admin_notices(run: Invocation) -> list[str]:
    """The low-assurance flag, for somebody reading a terminal (#477).

    Read back off the document rather than collected alongside it, which is
    `_doctor_exit`'s rule about "missing" applied to this: the text and the JSON
    have to say the same thing, and two code paths working out what to say
    separately is how they stop doing so.

    **`doctor` prints it and the other verbs do not**, though all of them emit
    the diagnostic. P2 asks for the source to be flagged *in output* and text is
    the default output, so something has to print it -- but the thing being
    reported is a property of the *configuration*, identical on every run until
    somebody edits the file. Printed by `creds apply`, it would be a line under
    every rotation forever, which is the warning-a-reader-learns-to-filter
    failure that :data:`~sopuli.diagnostics.PASSWORD_REUSE_ENFORCED` and
    :func:`~sopuli.diagnostics.admin_diagnostics` are both written to avoid.

    That is the distinction the other printed notices already draw, rather than a
    new one. :data:`~sopuli.diagnostics.REPAIR_DOCUMENT_STALE` is printed because
    "the document *you* just passed is thirteen days old" is about this
    invocation, and :data:`~sopuli.diagnostics.GUARDRAIL_UNCHECKED` because a
    check that did not run is about this run's accounts. "Your file authenticates
    from a variable" is about neither, and `doctor` is the verb whose whole job
    is to report on the setup -- so it is where a person goes to be told, and
    ``diagnostics[]`` is where anything alerting reads it from on every command.
    """
    return [one.message for one in run.document.diagnostics if one.code == LOW_ASSURANCE_ADMIN]


def _open_session(target: ExpandedTarget, run: Invocation, config: Config) -> Any:
    """One connection to one target, with the admin credential P2 resolves.

    Extracted because two passes need it: the pre-flight that refuses a strategy
    the estate cannot honour, and the run that applies. Identical in both, which
    is the point -- a pre-flight that connected differently would be clearing a
    different thing from the one that runs.
    """
    module = resolve_driver(target.target)
    credential = _admin_credential(target, run, config)
    driver = module.OracleDriver(
        env=os.environ,
        correlation_id=run.document.correlation_id,
        timeouts=_timeouts(run),
        client_lib_dir=config.runtime.oracle.client_lib_dir,
    )
    return driver.connect(target, credential.credential)


def _surveyable(sources: Sequence[tuple[Binding, Source | None]]) -> list[Binding]:
    """The accounts `apply` asks a pre-flight about: the ones it has work for.

    An account whose vault stage is empty is one this run will not touch, so
    surveying the target on its behalf spends a connection to learn something
    about work that is not going to happen. `rotate` passes its own list instead
    -- see :func:`_preflight` for why the two differ.
    """
    return [binding for binding, source in sources if source is not None]


def _preflight(
    surveyed: Sequence[Binding],
    run: Invocation,
    config: Config,
    *,
    strategy: str | None,
    full: bool,
) -> list[Finding]:
    """UC-1 §8 step 3: ask the estate before anything is written (#262, #283).

    One connection per target, and it does both jobs on the one connection: the
    strategy refusal #262 added, and -- under ``--preflight`` -- the rest of §8's
    list. The two arrived separately and are one pass, because they want the same
    thing at the same moment and a second pass would double a cost that is
    already the interesting part of this function.

    **It costs nothing unless it was asked for.** With no ``--strategy`` and no
    ``--preflight`` there is nothing to survey and this returns immediately: the
    regime is then chosen per account from what that account can actually do, and
    an ordinary repair of one target should not pay for a survey of twenty.

    That trade is the whole design of both flags. An operator who names a regime,
    or asks for a pre-flight, is asking for a property of the *estate* -- "no
    application will see a failed login tonight", "this will not stop half way"
    -- and a run that honoured it on four PDBs and discovered on the fifth that
    it could not would already have broken the promise.

    **An unhonourable strategy raises where it is found**, before the survey has
    visited the rest of the estate, and that is deliberate. Invariant 4's
    capability refusal carries its own exit code and names the capability and the
    target; it is not a finding to be collected among others, and an operator who
    named a regime this estate cannot honour has one thing to fix before anything
    else is worth reporting.

    **An unreachable target is a finding only under ``--preflight``.** Without
    it, the run reports one per account with the vendor code and carries on, and
    turning that into a plan-time refusal here would make an unreachable database
    look like a strategy problem -- which is the rule #262 wrote and this keeps.
    With the flag, being unable to reach a target is exactly what was asked
    about.

    **The caller decides which accounts are surveyed**, and the two callers
    decide differently for a reason worth stating. `apply` passes the accounts
    that have something to apply -- an empty vault stage means the run will not
    touch that account, so surveying its target buys nothing. `rotate` passes
    everything it is about to rotate, because it has not staged yet: at step 3
    there is no `pending` anywhere, and a first-ever rotation has no `current`
    either, so filtering on what the vault already holds would skip the whole
    estate on exactly the run whose pre-flight matters most.
    """
    if strategy is None and not full:
        return []

    by_target = {expanded.name: expanded for expanded in config.expanded_targets}
    grouped: dict[str, list[Binding]] = {}
    for binding in surveyed:
        grouped.setdefault(binding.target, []).append(binding)

    findings: list[Finding] = []
    for name, bindings in grouped.items():
        try:
            session = _open_session(by_target[name], run, config)
        except Exception as error:  # noqa: BLE001 -- the run reports this per account
            if full:
                reported = _as_error(error)
                findings.append(
                    preflight.unreachable(name, message=reported.message, hint=reported.hint)
                )
            continue
        try:
            if strategy is not None:
                _check_strategy(session, bindings, strategy=strategy, target=name, config=config)
            if full:
                findings.extend(_preflight_target(session, by_target[name], bindings, config))
        finally:
            with suppress(Exception):
                session.close()
    return findings


def _preflight_target(
    session: Any, target: ExpandedTarget, bindings: Sequence[Binding], config: Config
) -> tuple[Finding, ...]:
    """One reachable target, against §8's remaining checks.

    Reading is here and deciding is in :mod:`sopuli.preflight`, which is the
    arrangement every other verb in this file has with its own decision module.

    **Every probe that fails is a finding rather than an exception**, and each is
    reported as the check it was answering rather than as unreachability --
    `doctor` draws the same line and for the same reason: a dictionary view this
    account cannot read would otherwise send somebody to the listener over a
    grant. The probes are separate for that reason too, since a service account
    can be perfectly able to describe its scope, unable to audit its own
    privileges, and unable to read the roles an account holds -- three grants,
    three answers.

    Letting any of them escape would abort the survey and take every finding
    gathered so far with it, which is precisely what a run asking "tell me
    everything before you start" did not ask for.
    """
    try:
        scope = session.scope()
    except Exception as error:  # noqa: BLE001 -- a finding, not a crash
        return (
            Finding(
                target=target.name,
                check=preflight.SCOPE,
                message=_as_error(error).message,
                hint="the connection worked; this is what it could not read",
            ),
        )

    try:
        missing_privileges = tuple(session.privileges().missing)
    except Exception as error:  # noqa: BLE001 -- likewise
        # Reported and **not** blocking. The audit establishes nothing either
        # way when it cannot be read, and refusing over it would mean an estate
        # that will not grant the view can never run a pre-flight -- while
        # staying silent would be the guard that is not running and does not say
        # so, which UC-1 §7 rules out for `check`'s LCOUNT guard by name.
        missing_privileges = ()
        privilege_finding: tuple[Finding, ...] = (
            Finding(
                target=target.name,
                check=preflight.PRIVILEGES,
                message=f"the privilege audit could not be read: {_as_error(error).message}",
                hint="nothing about this target's grants was established, either way",
                category="authorization",
                blocking=False,
            ),
        )
    else:
        privilege_finding = ()

    missing_accounts: list[str] = []
    missing_profiles: list[tuple[str, str]] = []
    unreadable: list[Finding] = []
    for binding in bindings:
        try:
            state = session.describe_user(binding.account)
        except Exception as error:  # noqa: BLE001 -- a finding about this account
            # `describe_user` raises where the account's *state* cannot be read
            # rather than where the account is absent -- `RolesUnreadableError`
            # is the one that exists, for a `DBA_ROLE_PRIVS` this service
            # account is not granted. Letting it escape would abort the survey
            # and take every finding gathered so far with it, which is the
            # opposite of what a run asking "tell me everything first" wants.
            #
            # Blocking, unlike the privilege audit above, and the asymmetry is
            # the point: that one establishes nothing either way, while this one
            # is the input guardrail 4 refuses on, and treating an unreadable
            # answer as "holds no admin role" is the silent success
            # `RolesUnreadableError` was raised to prevent.
            reported = _as_error(error)
            unreadable.append(
                Finding(
                    target=target.name,
                    check=preflight.ACCOUNT,
                    message=reported.message,
                    hint=reported.hint,
                    account=binding.account,
                    category=reported.category,
                )
            )
            continue
        if state is None:
            missing_accounts.append(binding.account)
            continue

        # §5's profile assignment, asked before anything is written (#301). Only
        # where the policy declares one and the account is not already on it: the
        # question is whether this run's *move* can land, and an account already
        # there is not moving.
        moving = strategies.moves_profile(state, apply_states.attributes_for(config, binding))
        if moving is None:
            continue
        try:
            found = session.resolve_profile(moving)
        except UnsupportedCapabilityError:
            # Invariant 4, and the one exception this survey lets past: the
            # target cannot read profiles at all, so the assignment this run
            # intends can never run here. That is a plan-time refusal with its
            # own exit code naming the capability, not a finding among others --
            # the same escape `_check_strategy` gives it.
            raise
        except Exception as error:  # noqa: BLE001 -- a finding about this account
            # Reported and **not** blocking, on the rule this function states and
            # the privilege audit above already follows: a dictionary read that
            # failed has established nothing either way, and refusing over it
            # would mean an estate that will not grant `DBA_PROFILES` can never
            # run a pre-flight. The run still cannot move an account onto a
            # profile that is not there -- the driver asks the same question
            # again before its own statement and refuses that account -- so what
            # is lost is the early warning, which is exactly what the finding
            # says.
            reported = _as_error(error)
            unreadable.append(
                Finding(
                    target=target.name,
                    check=preflight.PROFILE,
                    message=(
                        f"could not establish whether profile {moving!r} exists here: "
                        f"{reported.message}"
                    ),
                    hint="nothing about this account's profile was established, either way",
                    account=binding.account,
                    category=reported.category,
                    blocking=False,
                )
            )
            continue
        if found is None:
            missing_profiles.append((binding.account, moving))

    declared = target.target.oracle
    return (
        preflight.survey(
            target.name,
            scope=scope,
            declared_scope=declared.scope,
            declared_container=declared.container,
            missing_accounts=missing_accounts,
            missing_profiles=missing_profiles,
            missing_privileges=missing_privileges,
        )
        + tuple(unreadable)
        + privilege_finding
    )


def _preflight_diagnostics(findings: Sequence[Finding]) -> list[Diagnostic]:
    """Every finding as a run-level diagnostic, blocking or not.

    Emitted whether or not the run goes ahead, which is the half worth stating: a
    survey that found only caveats lets the run proceed, and those caveats are
    exactly what a document read afterwards needs in order to know how much the
    pre-flight actually established.

    ``level`` carries the distinction -- ``error`` for a finding that refused the
    run, ``warning`` for one that could not establish anything. No diagnostic
    *code* is allocated: #216's rule is that a code exists for what the exit code
    cannot tell you, and on a refusal the run-level `error.category` already says
    which kind of problem stopped it -- ``connectivity``, ``authorization`` or
    ``database``, which is the branch a consumer needs. A code would be a fourth
    spelling of `check`.
    """
    return [
        Diagnostic(
            level="error" if one.blocking else "warning",
            message=f"{one.check}: {one.message}",
            target=one.target,
            account=one.account,
        )
        for one in findings
    ]


def _refuse_preflight(
    findings: Sequence[Finding], document: Any, *, header: str, notes: Sequence[str] = ()
) -> str:
    """Report the refusal, and change nothing.

    Exit 1, which is what "nothing changed anywhere" already means for this verb
    (UC-1 §5). Not exit 9: the estate disagreeing with the file is not the same
    as a file that could not be read, and `config validate` would pass on every
    one of these. Not exit 5 either -- that is invariant 4's capability code, and
    the capability refusal never reaches here because it raises.

    ``notes`` carries the run-level notices the ordinary return paths render, so
    a refusal does not silently drop them (found in review on #391). A stale
    ``--repair`` document under ``--preflight`` was serialised into
    ``diagnostics[]`` and printed nowhere, which is exactly the invisibility
    #309's rule exists to prevent -- and a refusal is a worse place to lose a
    warning than a success, because it is where somebody is already reading.
    """
    first = preflight.refusal(findings)
    if first is None:  # pragma: no cover - the caller asks before calling
        raise ValueError("nothing in this pre-flight refuses the run")
    document.error = Error(
        category=first.category,
        message=preflight.summarise(findings),
        hint=first.hint,
    )
    blocking = sum(1 for one in findings if one.blocking)
    document.finish(ExitCode.FAILURE, Summary(total=len(findings), failed=blocking))
    return f"{header}\n\n{render_preflight(findings)}"


def _check_strategy(
    session: Any, bindings: Sequence[Binding], *, strategy: str, target: str, config: Config
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

        # #301, and it comes first because it says the question below cannot be
        # answered rather than answering it. A profile decides whether a rollover
        # window opens, so judging a named regime against the profile an account
        # is about to *leave* would clear `--strategy staged` on one profile and
        # then run it under another that opens a window.
        moving = strategies.moving_profile(
            strategy,
            user,
            strategies.moves_profile(user, apply_states.attributes_for(config, binding)),
        )
        if moving is not None:
            raise DriverError(
                f"--strategy {strategy} cannot be honoured for {binding.account!r} "
                f"in {target!r}: {moving.message}",
                hint=moving.hint,
            )

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


#: The diagnostic code for a password the server refused and this run replaced.
REDRAWN = "password_redrawn"

#: And for one it refused that this run was not allowed to replace.
NOT_REDRAWN = "password_not_redrawn"


def _redraw_estate(
    applied: list[_Applied],
    documents: dict[LockKey, Any],
    stores: Mapping[str, SecretStore],
    run: Invocation,
    config: Config,
    *,
    manager: LockManager,
    margin: int,
    strategy: str | None,
    selection: Selection,
    force: bool,
    requested: str | None,
    diagnostics: list[Diagnostic],
) -> tuple[list[_Applied], LockStolenError | None]:
    """Draw again for the accounts whose password the server itself refused (#312).

    UC-1 §6.4, deciding #268. ``ORA-28003`` and ``ORA-28007`` say the *value* was
    unacceptable, and neither can be known before the statement is issued -- a
    verify function is arbitrary PL/SQL that cannot be consulted (invariants 13
    and 14), and a reuse history is hashed. So this is the only place the answer
    can be found, and telling an operator to re-run `creds generate` and hope was
    the loop §6.4 was written about.

    **The unit is an account, not a document and not the estate.** Passwords are
    drawn per account even where accounts share a document (§4), so a refusal
    implicates exactly the account that met it. What is re-applied is that
    account's own bindings -- every target it is bound to, including ones this
    run has already visited -- because they share one password and have to end
    the run holding the same one.

    **Re-applying is** :func:`_apply_estate` **again, on a narrowed source
    list**, rather than a second loop that would have to re-derive the lease
    renewal, the fence and the per-target connection, and could come to disagree
    with the first about any of them.

    **The restage happens under the lock this run already holds**, before the
    re-apply. A crash between the two leaves a ``pending`` that some target may
    hold, which is the state UC-1 §3 designed ``pending`` to be recoverable from;
    the opposite ordering leaves a password that exists nowhere.

    **Nothing here is quiet.** Every draw is a warning naming the account and the
    server's own message, and so is every refusal to draw: three of
    :func:`sopuli.apply.may_redraw`'s four answers are the tool declining to act,
    and a run that silently declined is the behaviour this replaces.
    """
    reported: set[tuple[str, LockKey]] = set()
    # Bounded by the budget, which is what ends this loop in practice: every
    # round raises each account's `redraws` by one, so after `DRAW_LIMIT` of them
    # `may_redraw` refuses everything and the return below fires. The `range` is
    # the structural backstop -- an unbounded loop that mutates databases and
    # writes secrets should not depend for its termination on arithmetic done
    # three functions away.
    for _ in range(apply_states.DRAW_LIMIT):
        wanted, declined = _wants_redraw(applied, documents, config, reported=reported)
        diagnostics.extend(declined)
        if not wanted:
            return applied, None

        try:
            restaged = _restage(wanted, documents, stores, config, manager=manager)
        except LockStolenError as taken:
            # Named apart from `stolen` below: `except ... as` unbinds its target
            # at the end of the block, so reusing the name would leave the
            # assignment further down writing to a variable Python had deleted.
            return applied, taken
        diagnostics.extend(restaged.diagnostics)

        again, stolen = _apply_estate(
            _sources(_every_target_of(restaged.accounts, applied), documents, stage=requested),
            run,
            config,
            manager=manager,
            margin=margin,
            strategy=strategy,
            selection=selection,
            force=force,
            requested=requested,
        )
        applied = _splice(applied, again)
        if stolen is not None:
            return applied, stolen
    return applied, None


def _wants_redraw(
    applied: Sequence[_Applied],
    documents: Mapping[LockKey, Any],
    config: Config,
    *,
    reported: set[tuple[str, LockKey]],
) -> tuple[list[_Applied], list[Diagnostic]]:
    """The records to draw again for, and the diagnostics for those refused.

    The decision is :func:`sopuli.apply.may_redraw`, which owns it and knows
    nothing about Oracle. What this adds is the facts it needs and only the run
    has: the ``origin`` #311 staged beside the value, read out of the document
    this run holds the lock on, and how many draws this account has had.

    **One record per account, not per target.** An account refused on three
    targets is one redraw and three re-applications; treating it as three would
    draw three passwords for one account and leave two of them nowhere.

    **A refusal is reported once**, not once per round: ``reported`` carries the
    accounts already explained across the loop's iterations, because the same
    account declines again every time round and a run that said so three times
    would read as three separate refusals.

    **An account with no password policy declines here rather than raising.**
    Drawing needs a policy and §8 refuses to invent one, but this run was applying
    happily until the server refused a value -- turning that into a configuration
    error would replace a report of what the estate did with a complaint about
    the file, on a run where nothing about the file had changed.
    """
    wanted: list[_Applied] = []
    declined: list[Diagnostic] = []
    seen: set[tuple[str, LockKey]] = set()
    for record in applied:
        if not record.refused or record.binding.secret is None or record.binding.vault is None:
            continue
        key = _lock_key(record.binding)
        identity = (record.binding.account, key)
        if identity in seen:
            continue
        seen.add(identity)
        decision = apply_states.may_redraw(
            _RefusedPassword(record.refused),
            _origin_of(record.binding, documents.get(key)),
            drawn=record.redraws + 1,
        )
        reason = decision.reason if not decision.allowed else _no_policy_for(config, record.binding)
        if reason is None:
            wanted.append(record)
            continue
        if identity not in reported:
            reported.add(identity)
            declined.append(
                Diagnostic(
                    level="warning",
                    message=(f"the server refused this password and it was not replaced: {reason}"),
                    code=NOT_REDRAWN,
                    account=record.binding.account,
                )
            )
    return wanted, declined


def _no_policy_for(config: Config, binding: Binding) -> str | None:
    """Why this account cannot be drawn for, or ``None`` when it can.

    :func:`sopuli.generate.policy_for` is the same chain `creds generate` walks
    and it *raises* where there is nothing to draw against -- which is right for
    a command whose whole job is drawing, and wrong here, where the run is
    already part way through an estate. So the refusal is caught and becomes one
    more reason a password was not replaced.
    """
    try:
        staging.policy_for(config, binding)
    except ConfigError:
        return "this account has no password policy to draw from"
    return None


def _origin_of(binding: Binding, stored: Any) -> Any:
    """What the document says about where this account's ``pending`` came from.

    ``None`` for every way of not knowing -- no document, no ref, no key -- which
    is the answer :func:`sopuli.apply.may_redraw` treats as "do not redraw". A
    document staged before #311 and a document nobody has staged into are the
    same fact here, and both self-heal on the next `creds generate`.
    """
    if binding.secret is None or stored is None:
        return None
    return stage_layout(binding.secret).read(stored.data, ORIGIN)


@dataclass(frozen=True)
class _RefusedPassword:
    """:func:`sopuli.apply.may_redraw`'s input, rebuilt from the record.

    The decision asks an *error* whether the password was refused, because that
    is where the answer is when it is first asked. By here the exception is gone
    and its answer is on the record, so this carries it back in the shape the
    decision reads -- rather than the decision growing a second entry point that
    could come to disagree with the first.
    """

    regenerate: bool


@dataclass(frozen=True)
class _Restaged:
    """Which accounts one round of drawing staged a new password for."""

    accounts: tuple[tuple[str, LockKey], ...]
    diagnostics: tuple[Diagnostic, ...]


def _every_target_of(
    accounts: Sequence[tuple[str, LockKey]], applied: Sequence[_Applied]
) -> list[Binding]:
    """Every binding belonging to the accounts that were just redrawn.

    **This is the whole reason a redraw is not just a retry of the target that
    refused.** An account bound to three targets has one password, and staging a
    new one leaves the two that succeeded holding a value the vault no longer
    carries -- so a promotion would then advertise a password most of the estate
    does not have, which is the first of the two orderings UC-1 §3 rules out.

    Re-applying a target that already succeeded is another ``ALTER USER`` and
    nothing worse: `apply` is the convergent verb, and the account it meets on
    the second pass is one whose password it set itself.

    Taken from this run's own results rather than from the config, so the set is
    exactly what was applied -- an account a selector excluded was never in
    ``applied`` and must not be dragged in by a redraw of its neighbour
    (invariant 5).
    """
    wanted = set(accounts)
    return [
        record.binding
        for record in applied
        if record.binding.secret is not None
        and record.binding.vault is not None
        and (record.binding.account, _lock_key(record.binding)) in wanted
    ]


def _restage(
    wanted: Sequence[_Applied],
    documents: dict[LockKey, Any],
    stores: Mapping[str, SecretStore],
    config: Config,
    *,
    manager: LockManager,
) -> _Restaged:
    """Draw a password for each refused account and stage it, one write per document.

    :class:`sopuli.generate.DocumentWrite` builds the patch, which is what puts
    the ``origin`` beside the value without this function having to know that it
    must: a drawn candidate is ``generated``, and #311's rule that the two go in
    one write stays one implementation rather than two that can drift.

    ``documents`` is **updated in place** with what came back. A promotion writes
    against the version read at the start of the run and staging has moved it, so
    a stale entry would turn every redrawn document's promotion into a
    compare-and-set conflict with this run's own write.
    """
    drawn: list[tuple[str, LockKey]] = []
    notes: list[Diagnostic] = []
    for key, records in _redraws_by_document(wanted).items():
        candidates = tuple(
            _candidate(record.binding, config, name=None, supplied=None, enforce=True)
            for record in records
        )
        stored = documents.get(key)
        manager.check(key)
        written = write_credential(
            stores[key.store],
            key.path,
            staging.DocumentWrite(key=key, candidates=candidates).patch(stage=PENDING),
            cas=0 if stored is None else stored.version,
        )
        documents[key] = stores[key.store].read(key.path)
        for record in records:
            drawn.append((record.binding.account, key))
            notes.append(
                Diagnostic(
                    level="warning",
                    message=(
                        "the server refused this password, so another was drawn and staged as "
                        f"v{written.version}: {record.outcome.detail or 'no message was given'}"
                    ),
                    code=REDRAWN,
                    account=record.binding.account,
                )
            )
    return _Restaged(accounts=tuple(drawn), diagnostics=tuple(notes))


def _redraws_by_document(wanted: Sequence[_Applied]) -> dict[LockKey, list[_Applied]]:
    """Accounts to redraw, grouped into the write that will stage them.

    Two accounts of one application refused on the same run share a document, and
    #254's rule is that one document is one write however many accounts land in
    it -- three writes would be three versions, two of which describe a state
    nobody intended.
    """
    grouped: dict[LockKey, list[_Applied]] = {}
    for record in wanted:
        grouped.setdefault(_lock_key(record.binding), []).append(record)
    return grouped


def _splice(applied: Sequence[_Applied], again: Sequence[_Applied]) -> list[_Applied]:
    """This run's results with the re-applied accounts' rows replaced.

    Replaced rather than appended: a redrawn account was applied twice, and the
    row belonging in ``results[]`` is the second -- it carries the outcome of the
    password the estate ended up with. Appending would report one account on one
    target twice, the first row describing a password no longer staged anywhere.

    ``redraws`` accumulates across rounds, because :func:`_apply_estate` builds
    fresh records that have never heard of it. That is what stops the budget
    resetting every time round the loop.
    """
    replacements = {(record.binding.account, record.binding.target): record for record in again}
    spliced: list[_Applied] = []
    for record in applied:
        fresh = replacements.pop((record.binding.account, record.binding.target), None)
        spliced.append(record if fresh is None else replace(fresh, redraws=record.redraws + 1))
    # Anything left is an account that was not in the original pass, which cannot
    # happen -- a redraw narrows the estate rather than widening it -- and is
    # appended rather than dropped, because losing a row this run applied would
    # leave a mutation in no document at all.
    spliced.extend(replacements.values())
    return spliced


def _promote_documents(
    applied: Sequence[_Applied],
    documents: Mapping[LockKey, Any],
    stores: Mapping[str, SecretStore],
    *,
    manager: LockManager,
) -> tuple[dict[LockKey, _Promotion], LockStolenError | None]:
    """Promote every document whose targets all confirmed, and only those.

    Invariant 7's ordering, and the one place in this command where the two
    groupings meet: results arrive per (account, target) and the commit is per
    document, so the gate is *every pair belonging to the accounts in this
    document*.

    A document nobody staged into is not promoted and is not a failure -- a run
    that read `current` is a repair, and the vault already holds what it should.

    **The fence is re-read before each promotion**, which is the vault write UC-1
    §8 cares about most: it is the one that makes a password visible to
    applications. A takeover found here ends the run with the documents already
    promoted reported and the rest left alone -- the same abort
    :func:`_apply_estate` performs, at the other end of the run.
    """
    promotions: dict[LockKey, _Promotion] = {}
    for key, records in _by_document(applied).items():
        owing = [
            record
            for record in records
            if record.source is not None and apply_states.promotes(record.source.stage)
        ]
        if not owing:
            promotions[key] = _Promotion(None, "the vault already holds what was applied")
            continue
        if not apply_states.summarise_document(record.outcome.state for record in records):
            promotions[key] = _Promotion(
                None,
                "not every target confirmed, so the vault was left as it was",
                promotable=True,
            )
            continue
        try:
            manager.check(key)
        except LockStolenError as stolen:
            return promotions, stolen
        promotions[key] = _write_promotion(key, owing, documents[key], stores[key.store])
    return promotions, None


def _by_document(applied: Sequence[_Applied]) -> dict[LockKey, list[_Applied]]:
    """Results grouped by the document their account's credential lives in.

    **A guardrail-skipped account is dropped entirely** (#286), from the gate and
    from the promotion alike, which is the same principle the exit code applies:
    it left the run's scope rather than failing inside it.

    Both halves matter and they pull in opposite directions, which is why this is
    stated rather than left to fall out. Promoting a skipped account would move
    its `pending` to `current` while its database still holds the old password --
    advertising a credential nothing has, which is precisely what invariant 7
    exists to prevent. But letting it *gate* the document would mean one
    permanently guarded account -- a `DBA` grant somebody is not going to give up
    -- blocking promotion for every neighbour sharing the path, on every run,
    for ever. Dropping it does neither: its `pending` stays staged and its
    neighbours promote.
    """
    grouped: dict[LockKey, list[_Applied]] = {}
    for record in applied:
        binding = record.binding
        if binding.secret is None or binding.vault is None:
            continue
        if record.outcome.state == apply_states.SKIPPED:
            continue
        grouped.setdefault(_lock_key(binding), []).append(record)
    return grouped


def _write_promotion(
    key: LockKey, owing: Sequence[_Applied], stored: Any, store: SecretStore
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
    for record in _one_per_account(owing):
        source = record.source
        if source is None:  # pragma: no cover - `owing` is filtered on it
            continue
        entries.append(
            apply_states.Promotable(
                binding=record.binding,
                value=source.value,
                replaces=source.replaces,
                policy=record.binding.policy,
                targets=tuple(
                    one.binding.target
                    for one in owing
                    if one.binding.account == record.binding.account
                ),
            )
        )
    patch = apply_states.promotion_patch(entries, at=utc_now(), by=_rotated_by())
    try:
        written = write_credential(store, key.path, patch, cas=_version_of(stored))
    except Exception as error:  # noqa: BLE001 -- a per-document finding
        reported = _as_error(error)
        return _Promotion(None, reported.message, promotable=True, error=reported)
    return _Promotion(
        written.version,
        f"promoted to v{written.version}",
        promotable=True,
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


def _guardrail_caveats(applied: Sequence[_Applied]) -> list[Diagnostic]:
    """§4's checks that could not be run, as this run's warnings (#296).

    A run-level diagnostic rather than a ``results[].warnings`` entry, and the
    reason is what the reader is being told: the fact that could not be read is a
    grant on a *target*, not a property of an account, so the account list belongs
    inside one message and not spread over forty rows. `creds generate` already
    groups the constraints it cannot check the same way, for the same reason.

    Emitted by `apply` and by `rotate`, which are the two verbs that ask the
    guardrails anything. Grouping and wording are
    :func:`sopuli.diagnostics.guardrail_diagnostics`', because turning a domain
    object into something an operator reads is that module's job and the remedy it
    appends is a `GRANT` statement -- product knowledge the guardrails deliberately
    do not carry.
    """
    return guardrail_diagnostics(
        [(record.binding.target, caveat) for record in applied for caveat in record.caveats]
    )


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
        overridden=record.overridden,
        attributes=record.attributes,
        duration_ms=record.duration_ms,
        error=record.error,
        redraws=record.redraws,
    )


@creds_group.command("finish-rollover")
@select_option
@click.option(
    "--lockout-margin",
    type=click.IntRange(0, 100),
    default=DEFAULT_MARGIN,
    show_default=True,
    help="Refuse to attempt a login within this many tries of the lockout limit.",
)
@click.option(
    "--confirm",
    is_flag=True,
    default=False,
    help="Proceed without asking. Required where `safety.confirm_environments` applies.",
)
@global_options
def creds_finish_rollover(
    selectors: tuple[str, ...],
    targets: tuple[str, ...],
    accounts: tuple[str, ...],
    groups: tuple[str, ...],
    applications: tuple[str, ...],
    lockout_margin: int,
    confirm: bool,
    run: Invocation,
) -> str:
    """End an open password rollover window early.

    UC-1 section 6.3 step 4. While a window is open both the old and the new
    password authenticate, which is what makes zero-downtime rotation real; this
    ends it, so only the new one works from that moment. S2 runs it as a
    follow-up job once applications have had their grace period.

    **This is the one step whose purpose is to stop something working**, so most
    of what it does is decide which accounts to leave alone.

    **A staged `pending` is refused, without spending a login.** It means the
    rotation is unfinished, so the vault's `current` is still the *old* password
    and closing the window would strand every application that has not been given
    the new one. Run `sopuli creds apply` first.

    **An account whose vault password the database refuses keeps its window.**
    That is drift, exit 3, and closing there would leave nothing that
    authenticates -- neither the password applications fetch nor the one that is
    about to stop working.

    **What the login proves, and what it does not.** Under an open window a
    *pass* says less than usual, because both passwords authenticate: it cannot
    tell "the database has the vault's password" from "it has the previous one
    and accepts both". A *fail* is conclusive, and that is the case worth
    spending an attempt on. The gap is covered on the vault side by the `pending`
    rule above, which costs nothing and catches the case a pass would have got
    wrong.

    **No lock, and no vault write.** Nothing in any store changes, so there is
    nothing for the advisory lock to protect -- this is the second verb after
    `creds check` that leaves every document alone.

    **An account with no window open reports no change.** That is the ordinary
    result for a scheduled job, and invariant 9: issuing the statement anyway is
    accepted silently by Oracle and changes nothing, so a run that did would
    report a change every night.

    Help text stays ASCII throughout, which is P4's rule.
    """
    document = run.document
    refuse_if_readonly(run.resolved, action="ending a rollover window")

    selection = selected(selectors, targets, accounts, groups, applications)
    refuse_unknown(run.config, selection)
    config = filter_estate(run.config, selection)
    document.selection = selection.as_json() or None
    document.diagnostics.extend(config_diagnostics(config))

    config = binding_stores.complete(config, env=os.environ)
    binding_stores.refuse_unresolved(config, action="ending a rollover window")

    run = _with_estate_safety(run, config)
    refuse_if_readonly(run.resolved, action="ending a rollover window", estate=config)
    plan = plan_builder.build(config, intent=["verify", "rollover_finish"])
    refuse_if_over_limit(run.resolved, plan.blast_radius, action="ending a rollover window")
    document.plan = plan.as_json()
    # The one verb here whose purpose is to stop something working, so the gate
    # is if anything more apt: closing a window early is what takes the old
    # password away from whatever has not been given the new one.
    _confirm_environments(
        plan, run, action="ending a rollover window", confirmed=confirm, noun="window"
    )

    bindings = [binding for binding in config.bindings if binding.secret is not None]
    if not bindings:
        document.finish(ExitCode.SUCCESS, Summary())
        return render_plan(plan, noun="window") + "\n\nnothing to end"

    keys = _document_keys(bindings)
    stores = _stores_for(
        {key.store for key in keys}, config, token_file=run.vault_token_file, cache=run.stores
    )
    # No lock: this verb writes to no store. The documents are read for one
    # reason -- to know whether a `pending` is staged, and to have something to
    # verify with -- and a read has never needed one.
    sources = _sources(bindings, _read_documents(keys, stores, run=run))

    finished = _finish_estate(sources, run, config, margin=lockout_margin, preview=run.dry_run)

    document.results = [
        build_finish_result(
            record.binding,
            record.outcome,
            user=record.user,
            changed=record.changed,
            duration_ms=record.duration_ms,
            error=record.error,
        )
        for record in finished
    ]
    states = [record.outcome.state for record in finished]
    closed = sum(1 for record in finished if record.changed)
    document.finish(check_states.exit_code_for(states), summarise_finish(states, changed=closed))

    header = "\n".join(
        [
            render_plan(plan, noun="window"),
            "",
            *render_window_table(
                [(record.binding, record.user) for record in finished if record.user is not None]
            ),
        ]
    )
    # The rows are printed under `--dry-run` too. They are not decoration there:
    # a preview still reaches every database, so an unreachable target is a real
    # finding that sets the exit code, and a run exiting 1 with only a plan and a
    # window table on screen would be a non-zero exit nobody could explain. The
    # rows are also the half a preview is *for* -- which accounts would be closed
    # and which would be left open, per account and with the reason.
    rows = [(record.binding, record.outcome, record.changed) for record in finished]
    body = render_finish(
        rows, would_close=sum(1 for one in finished if one.would_close) if run.dry_run else None
    )
    return f"{header}\n\n{body}"


@dataclass(frozen=True)
class _Finished:
    """One (account, target) after `creds finish-rollover` has looked at it.

    ``user`` is the state as it was **read**, before anything was issued, which
    is what the window table prints. What the run left behind is derived from it
    and ``changed`` in the view, so the two cannot disagree about one account.
    """

    binding: Binding
    outcome: check_states.Outcome
    changed: bool
    user: UserState | None = None
    #: Under ``--dry-run``, whether this account cleared every gate and would
    #: have had its window closed. Always ``False`` on a real run, where
    #: ``changed`` is the answer -- the two are never both meaningful, and one
    #: field serving both would make "would have" and "did" indistinguishable in
    #: the one place it matters.
    would_close: bool = False
    duration_ms: int | None = None
    error: Error | None = None


def _finish_estate(
    sources: Sequence[tuple[Binding, Source | None]],
    run: Invocation,
    config: Config,
    *,
    margin: int,
    preview: bool,
    manager: LockManager | None = None,
) -> list[_Finished]:
    """Every account, target by target, one connection each. `check`'s grouping.

    ``manager`` is ``None`` for `creds finish-rollover`, which takes no lock at
    all -- it writes to no store, so there is nothing for the advisory lock to
    protect and an hourly job that blocked rotations would be the worse problem.

    `rotate` passes the one it is holding, because there the DDL below is a
    mutation inside a sequence somebody else can take over mid-run, and UC-1 §8
    is explicit that the fence is re-read before *every* mutating call. Optional
    rather than required so the standalone verb keeps behaving exactly as it did:
    the argument is the lock a caller holds, and a caller that holds none says so.
    """
    by_target = {expanded.name: expanded for expanded in config.expanded_targets}
    grouped: dict[str, list[tuple[Binding, Source | None]]] = {}
    for binding, source in sources:
        grouped.setdefault(binding.target, []).append((binding, source))

    found: list[_Finished] = []
    for name, work in grouped.items():
        found.extend(
            _finish_target(
                by_target[name], work, run, config, margin=margin, preview=preview, manager=manager
            )
        )
    return found


def _finish_target(
    target: ExpandedTarget,
    work: Sequence[tuple[Binding, Source | None]],
    run: Invocation,
    config: Config,
    *,
    margin: int,
    preview: bool,
    manager: LockManager | None = None,
) -> list[_Finished]:
    """One target's worth of accounts, over one connection.

    A target that cannot be reached is a finding rather than a crash -- and here
    it is the harmless direction: a window nobody closed elapses on its own.
    """
    started = time.monotonic()
    session = None
    try:
        try:
            session = _open_session(target, run, config)
        except Exception as error:  # noqa: BLE001 -- a per-target finding
            reported = _as_error(error)
            elapsed = _elapsed(started)
            return [
                _Finished(
                    binding=binding,
                    outcome=check_states.Outcome(check_states.ERROR, reported.message),
                    changed=False,
                    duration_ms=elapsed,
                    error=reported,
                )
                for binding, _ in work
            ]

        return [
            _finish_one(
                binding, session, source=source, margin=margin, preview=preview, manager=manager
            )
            for binding, source in work
        ]
    finally:
        if session is not None:
            with suppress(Exception):
                session.close()


def _finish_one(
    binding: Binding,
    session: Any,
    *,
    source: Source | None,
    margin: int,
    preview: bool,
    manager: LockManager | None = None,
) -> _Finished:
    """One account: read the window, decide, and close it or say why not.

    ``attempts=1`` is the whole budget. This verb makes one login per account per
    run and never a second -- UC-1 section 7 mitigation 1 -- and it is declared to
    the guard before it is spent.

    Under ``--dry-run`` the state is read and the login is **not** spent. The
    plan a preview shows is which windows are open and how much is left on them,
    and a login would be a real cost paid for a run that changes nothing.

    **The fence is re-read immediately before the statement**, where a caller
    holds a lock at all (UC-1 §8, #282, found in review on #284). Closing a window
    is a mutation, and it is the one whose direction cannot be undone: a window
    nobody closed elapses on its own, and one closed by a run that had already
    lost the estate cannot be reopened. Narrowed to this account's own document,
    which is §8's per-document rule and the same check :func:`_apply_one` makes.

    **A lock error is never a per-account finding**, for the reason it is not one
    in :func:`_apply_one`: the catch-all below would turn "somebody else owns this
    estate now" into a row in the table and carry on closing the next account's
    window. It is re-raised ahead of it, and the run ends.
    """
    started = time.monotonic()
    try:
        user = session.describe_user(binding.account)
        settled = windows.settled_before_closing(user, source, session.scope())
        if settled is not None:
            return _Finished(
                binding, settled, changed=False, user=user, duration_ms=_elapsed(started)
            )
        if user is None or source is None:
            # Unreachable: `settled_before_closing` answers both. Restated so a
            # fall-through cannot decide a mutation on a value nobody checked.
            raise ValueError(f"no window to end for {binding.account!r} and no reason given")

        if preview:
            return _Finished(
                binding,
                check_states.Outcome(
                    check_states.IN_SYNC,
                    f"would end this window, {windows.remaining(user) or 'time unknown'} early",
                ),
                changed=False,
                user=user,
                would_close=True,
                duration_ms=_elapsed(started),
            )

        verified = session.verify_password(
            user.name, source.value, method=VERIFY_LOGIN, lockout_margin=margin, attempts=1
        )
        refused = windows.decide(verified)
        if refused is not None:
            return _Finished(
                binding, refused, changed=False, user=user, duration_ms=_elapsed(started)
            )

        if manager is not None:
            manager.check(_lock_key(binding))
        result = session.finish_rollover(user.name)
        if not result.changed:
            # The window closed between the read and the statement -- it elapsed,
            # or another run got there first. Not a failure and not a change:
            # what this run wanted is true, and it is not what made it true.
            return _Finished(
                binding,
                check_states.Outcome(
                    check_states.IN_SYNC,
                    result.detail or "no rollover window is open",
                    verified,
                ),
                changed=False,
                user=user,
                duration_ms=_elapsed(started),
            )
        outcome = windows.closed(user, verified)
    except LockError:
        # Ahead of the catch-all on purpose -- see the docstring. The run ends;
        # it does not report a takeover as one account's bad luck.
        raise
    except Exception as error:  # noqa: BLE001 -- a per-account finding
        reported = _as_error(error)
        return _Finished(
            binding,
            check_states.Outcome(check_states.ERROR, reported.message),
            changed=False,
            duration_ms=_elapsed(started),
            error=reported,
        )

    return _Finished(binding, outcome, changed=True, user=user, duration_ms=_elapsed(started))


@creds_group.command("rotate")
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
    "--max-age-days",
    type=click.IntRange(1, 100000),
    default=None,
    help="Rotate only what the vault last rotated more than this many days ago.",
)
@click.option(
    "--finish-rollover",
    "finish_windows",
    is_flag=True,
    default=False,
    help=(
        "End every rollover window at the end of the run, once every target has "
        "been applied and verified. Not the same as --strategy direct."
    ),
)
@click.option(
    "--confirm",
    is_flag=True,
    default=False,
    help="Proceed without asking. Required where there is nobody to ask.",
)
@click.option(
    "--lockout-margin",
    type=click.IntRange(0, 100),
    default=DEFAULT_MARGIN,
    show_default=True,
    help="Refuse to attempt a login within this many tries of the lockout limit.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help=(
        "Waive the account guardrails of 02-oracle-privileges.md section 4, "
        "checks 2 to 5: vendor-maintained, password file, admin role, deny list. "
        "Never check 1 -- an account the config does not declare is refused "
        "whatever this says. Every waiver is recorded in the run document."
    ),
)
@global_options
def creds_rotate(
    selectors: tuple[str, ...],
    targets: tuple[str, ...],
    accounts: tuple[str, ...],
    groups: tuple[str, ...],
    applications: tuple[str, ...],
    strategy: str | None,
    max_age_days: int | None,
    finish_windows: bool,
    confirm: bool,
    lockout_margin: int,
    force: bool,
    run: Invocation,
) -> str:
    """Draw a new password, put it on every target, and promote it. UC-1 section 8.

    **This is not a wrapper around three verbs, and that is the whole point.**
    Calling `generate`, `apply` and `check` in sequence gives up the two
    properties the sequence is built on. Each of those verbs takes and releases
    its own lock, so between a `generate` that released and an `apply` that has
    not yet acquired, another run can stage a different `pending` -- and this run
    would then apply and promote a password it never generated. Here one
    acquisition spans the whole sequence, and the fence is re-read before every
    mutating call, so a run whose lease is taken over stops rather than applying
    a password the vault no longer advertises.

    **The pre-flight is unconditional here**, which is the one place it differs
    from `creds apply`. There it is `--preflight` and off by default, because a
    repair of one target should not pay for a survey of twenty. A rotation is the
    opposite case: it is about to change every target it was given, and
    discovering on target nine that target ten was never going to work leaves
    nine databases holding a password no application has been told about.

    **`--max-age-days` reads the vault and never the database** (Q9, issue #87).
    `rotated_at` lives on the secret path, one value however many targets share
    it, so there is nothing to aggregate across the PDBs of a CDB and no "oldest,
    newest or any" rule to invent. An account the vault has no stamp for is
    **not** selected: a freshly adopted estate has no stamps anywhere in it, and
    treating unknown as infinitely old would make this tool's first scheduled act
    against that estate a rotation of every credential it has.

    **The order is generate, apply, verify, promote, and it is a safety design**
    (invariant 7). Nothing is promoted until every target has confirmed, so the
    `current` that applications fetch is only ever a password the whole estate
    has already accepted. A run that gets part way leaves `pending` staged and
    the databases it reached changed -- which is recoverable, `creds apply` is
    the recovery, and under the rollover strategy there is no outage meanwhile.

    **A staging failure stops the run before any database is touched.** Section
    8's table says row 4 leaves nothing changed in the database, and a rotation
    that staged two documents, failed on a third and applied the two anyway would
    make that row untrue for the estate somebody has to reason about afterwards.

    **Step 8 reads the promotion back**, which is the one step no other verb has.
    A store that acknowledges a write and then serves something else is not a
    theoretical failure -- it is what a read replica behind its primary looks
    like -- and an application fetching `current` in that window gets the old
    password. The run says which accounts, carries `SOPULI-W012` and exits 4:
    nothing needs undoing, and the place to look is the vault, not a database.

    **`--finish-rollover` runs at the end of the run, not per target.** That is
    what makes it different from `--strategy direct`, which closes each window as
    it opens it. Here every window stays open until every target has been applied
    and verified, so an application that has not yet picked up the new password
    keeps authenticating with the old one for the whole run rather than losing it
    the moment its own database was reached.

    Help text stays ASCII throughout, which is P4's rule.
    """
    document = run.document
    refuse_if_readonly(run.resolved, action="rotating a password")

    selection = selected(selectors, targets, accounts, groups, applications)
    refuse_unknown(run.config, selection)
    config = filter_estate(run.config, selection)
    document.selection = selection.as_json() or None
    document.diagnostics.extend(config_diagnostics(config))

    config = binding_stores.complete(config, env=os.environ)
    binding_stores.refuse_unresolved(config, action="rotating a password")

    run = _with_estate_safety(run, config)
    refuse_if_readonly(run.resolved, action="rotating a password", estate=config)
    plan = plan_builder.build(
        config,
        intent=[
            "generate",
            "vault_write_pending",
            *_attribute_intent(config),
            "verify",
            "password_set",
            "vault_promote",
        ],
    )
    refuse_if_over_limit(run.resolved, plan.blast_radius, action="rotating a password")
    document.plan = plan.as_json()

    bindings = [binding for binding in config.bindings if binding.secret is not None]
    if not bindings:
        document.finish(ExitCode.SUCCESS, Summary())
        return render_plan(plan, noun="rotation") + "\n\nnothing to rotate"

    keys = _document_keys(bindings)
    stores = _stores_for(
        {key.store for key in keys}, config, token_file=run.vault_token_file, cache=run.stores
    )

    if run.dry_run:
        # Invariant 8: the plan, the survey, and nothing written anywhere. The
        # documents are read because `--max-age-days` is answered out of them and
        # a read has never needed a lock, and the pre-flight runs because "would
        # this work" is most of what somebody previewing a rotation is asking.
        return _preview_rotation(
            bindings,
            run,
            config,
            plan=plan,
            documents=_read_documents(keys, stores, run=run),
            strategy=strategy,
            max_age_days=max_age_days,
        )

    # Step 1, and it happens before the lock rather than under it: a prompt
    # waiting on a human while holding every lock in the estate would block the
    # scheduled runs nobody asked it about. What is confirmed is the plan -- the
    # blast radius somebody is authorising -- and `--max-age-days` can only
    # narrow that afterwards, which is the safe direction to be surprised in.
    #
    # `safety.confirm_environments` is deliberately *not* also asked here (#292).
    # This gate is unconditional, so the setting could only ever make it weaker,
    # and a second prompt on the runs the setting covers would ask the same
    # question twice for the same answer.
    _confirm_rotation(plan, confirmed=confirm)

    manager = LockManager(
        stores={name: _lockable(name, config, stores) for name in {key.store for key in keys}},
        correlation_id=document.correlation_id,
        command="creds rotate",
        selection=describe_selection(selection),
        break_expired=_break_expired(run),
    )

    sequence = _Rotation()
    # Bound before the `try` because every path out of it reads this, including
    # the one that returns a refusal from inside the lock.
    refusal: str | None = None
    try:
        # Step 2. One acquisition, held to the end of the sequence, released in
        # the `finally` inside `holding` on every path including this one's
        # early returns -- which is the property that makes this a command
        # rather than three in a row.
        with manager.holding(keys):
            refusal = _rotate_estate(
                bindings,
                run,
                config,
                plan=plan,
                stores=stores,
                keys=keys,
                manager=manager,
                margin=lockout_margin,
                strategy=strategy,
                max_age_days=max_age_days,
                finish_windows=finish_windows,
                force=force,
                selection=selection,
                into=sequence,
            )
    except LockDeniedError as denied:
        _record_locks(document, manager, denied=denied)
        raise

    # **After** `holding` has exited, on every path including the refusals
    # `_rotate_estate` returns from inside the lock. `release()` runs in that
    # `finally`, and it is what flips `HeldLock.released` -- so a section built
    # while the lock was still held reported `released: false` for locks this run
    # gave back a moment later. Measured on the `--max-age-days` no-op: the
    # document said `false` and the store record said `released` (#348, found in
    # review). One call, one place, and the ordering is now structural rather
    # than a property of where each early return happens to sit.
    _record_locks(document, manager)
    if refusal is not None:
        return refusal

    document.results = sequence.staged_json + [
        _applied_json(record, sequence.promotions) for record in sequence.applied
    ]
    unchecked = _guardrail_caveats(sequence.applied)
    document.diagnostics.extend(unchecked)
    states = [record.outcome.state for record in sequence.applied]
    changed = sum(1 for record in sequence.applied if record.mutated)

    if sequence.stolen is not None:
        # The split `sopuli.lock.errors` leaves to the command, and `rotate` has
        # one more way to have changed something than `apply` does: a staged
        # document is a mutation too, so a takeover found between two writes at
        # step 4 is exit 4 even though no database was reached. Exit 7 asserts
        # nothing happened, and a `pending` somebody has to clean up is
        # something happening.
        document.diagnostics.append(
            Diagnostic(level="error", message=sequence.stolen.message, code=LOCK_LOST)
        )
        code = int(ExitCode.PARTIAL if changed or sequence.documents else ExitCode.LOCK_HELD)
    else:
        if sequence.disagreed:
            document.diagnostics.append(_unconfirmed(sequence.disagreed))
        code = rotation.exit_code_for(
            staged_failures=sequence.failures,
            applied=states,
            promoted=all(
                one.version is not None for one in sequence.promotions.values() if one.promotable
            ),
            promotable=any(one.promotable for one in sequence.promotions.values()),
            disagreed=len(sequence.disagreed),
        )

    document.finish(code, summarise_apply(states, changed=changed))
    # #264's remedy, on the runs it is a remedy for. Withheld after a takeover
    # for the reason `render_apply` documents, and withheld after a read-back
    # disagreement for a different one: re-running `apply` there would converge
    # a database estate that is already converged, and the thing to go and look
    # at is the vault.
    repair = (
        repair_invocation(
            selectors=selectors,
            config_paths=[str(path) for path in run.config_paths],
            profile=run.profile,
            strategy=strategy,
        )
        if code == ExitCode.PARTIAL and sequence.stolen is None and not sequence.disagreed
        else None
    )
    table = render_rotate(
        [(record.binding, record.outcome, record.mutated) for record in sequence.applied],
        staged=sequence.documents,
        promoted=sum(1 for one in sequence.promotions.values() if one.version is not None),
        disagreed=sequence.disagreed,
        closed=sequence.closed,
        stopped=None if sequence.stolen is None else str(sequence.stolen),
        repair=repair,
    )
    header = _rotation_header(plan, sequence.selections, max_age_days)
    # See `apply`'s: a warning that cannot be seen in the default output is not
    # surfaced.
    notes = render_notices([one.message for one in unchecked] + _lock_notices(manager))
    return "\n".join([f"{header}\n\n{table}", *notes])


@dataclass
class _Rotation:
    """What the sequence accumulated, so the caller can report a run that stopped.

    Mutable and passed in, which is the same arrangement ``out`` has in
    :func:`_apply_estate` and for the same reason: a rotation can end at any of
    section 8's steps, and what it had done by then is the run's document. Losing
    it with the exception would leave an operator with an exit code and no record
    of which databases were changed.
    """

    selections: tuple[rotation.Selection, ...] = ()
    #: Documents written at step 4, counted the way the vault counted them -- one
    #: compare-and-set per secret path, not one per account sharing it.
    documents: int = 0
    failures: int = 0
    staged_json: list[dict[str, Any]] = field(default_factory=list)
    staged_rows: list[tuple[Candidate, str, str]] = field(default_factory=list)
    applied: list[_Applied] = field(default_factory=list)
    promotions: dict[LockKey, _Promotion] = field(default_factory=dict)
    disagreed: tuple[str, ...] = ()
    #: Windows closed by ``--finish-rollover``. ``None`` where it was not asked
    #: for, which is not the same fact as zero.
    closed: int | None = None
    stolen: LockStolenError | None = None


def _rotate_estate(
    bindings: Sequence[Binding],
    run: Invocation,
    config: Config,
    *,
    plan: Any,
    stores: Mapping[str, SecretStore],
    keys: Sequence[LockKey],
    manager: LockManager,
    margin: int,
    strategy: str | None,
    max_age_days: int | None,
    finish_windows: bool,
    force: bool,
    selection: Selection,
    into: _Rotation,
) -> str | None:
    """Section 8's steps 3 to 8, under a lock the caller already holds.

    Returns rendered text where the run is over before it began -- nothing due,
    a pre-flight refusal, a staging failure -- and ``None`` where the caller
    should report what ``into`` accumulated. The split is what keeps the two
    kinds of ending apart: one has no table to print because no database was
    touched, and the other has a table that *is* the report.

    Separate from :func:`creds_rotate` so the `with manager.holding(...)` block
    stays short enough to read. Everything here happens under that lock and none
    of it acquires one.
    """
    document = run.document
    documents = _read_documents(keys, stores, run=run)
    into.selections = rotation.select(
        [(binding, _document_data(binding, documents)) for binding in bindings],
        max_age_days=max_age_days,
    )
    rotating = rotation.due(into.selections)
    if not rotating:
        document.finish(ExitCode.SUCCESS, Summary(total=len(into.selections)))
        return _nothing_due(plan, into.selections, max_age_days)

    # Step 3, and unconditional. Every account about to be rotated, rather than
    # only those the vault already holds something for: there is no `pending`
    # yet, and a first rotation has no `current` either.
    findings = _preflight(rotating, run, config, strategy=strategy, full=True)
    document.diagnostics.extend(_preflight_diagnostics(findings))
    if preflight.refusal(findings) is not None:
        return _refuse_preflight(
            findings, document, header=_rotation_header(plan, into.selections, max_age_days)
        )

    # Step 4 -- `creds generate`'s write, behind the fence it uses.
    writes = staging.group(
        [
            _candidate(binding, config, name=None, supplied=None, enforce=True)
            for binding in rotating
        ]
    )
    for write in writes:
        try:
            manager.check(write.key)
        except LockStolenError as lost:
            into.stolen = lost
            return None
        rows = _stage(write, stores[write.key.store], out=into.staged_json)
        into.staged_rows.extend(rows)
        if any(state == FAILED for _, state, _ in rows):
            into.failures += 1
        else:
            into.documents += 1

    if into.failures:
        document.results = into.staged_json
        document.finish(
            ExitCode.FAILURE, summarise_generate([state for _, state, _ in into.staged_rows])
        )
        header = _rotation_header(plan, into.selections, max_age_days)
        body = render_generate(into.staged_rows)
        return f"{header}\n\n{body}\n\nnothing was applied to any database"

    # Re-read: staging bumped every version this run wrote, and the promotion at
    # step 7 compare-and-sets against the version it is promoting from.
    documents = _read_documents(keys, stores, run=run)
    sources = _sources(rotating, documents, stage=None)

    # Steps 5 and 6.
    into.applied, into.stolen = _apply_estate(
        sources,
        run,
        config,
        manager=manager,
        margin=margin,
        strategy=strategy,
        selection=selection,
        force=force,
    )
    if into.stolen is not None:
        return None

    # Step 7. Nothing is promoted that was not confirmed (invariant 7).
    into.promotions, into.stolen = _promote_documents(
        into.applied, documents, stores, manager=manager
    )
    if into.stolen is not None:
        return None

    # Step 8, on the documents this run actually promoted.
    promoted = _read_documents(keys, stores, run=run)
    into.disagreed = _read_back(into.applied, into.promotions, promoted)

    if finish_windows:
        try:
            into.closed = _close_windows(
                into.applied, run, config, documents=promoted, margin=margin, manager=manager
            )
        except LockStolenError as lost:
            # Every window this run had already closed stays closed, which is why
            # the count is not discarded -- `_close_windows` returns only on the
            # path that finished. What the run must not do is close another.
            into.stolen = lost
    return None


def _document_data(binding: Binding, documents: Mapping[LockKey, Any]) -> Any:
    """The raw body of this account's document, or ``None`` if there is none.

    :func:`rotation.select` reads a ``rotated_at`` out of it and nothing else, so
    a path that does not exist yet is an age of unknown rather than an error --
    which is the ordinary state of an estate before its first rotation.
    """
    stored = _stored_document(binding, documents)
    return None if stored is None else stored.data


def _read_back(
    applied: Sequence[_Applied],
    promotions: Mapping[LockKey, _Promotion],
    documents: Mapping[LockKey, Any],
) -> tuple[str, ...]:
    """Section 8 step 8: does the vault serve what this run just promoted?

    **Only the documents this run promoted are read back.** A document nobody
    staged into was not written, and one whose targets did not all confirm was
    deliberately left alone -- checking either would report a disagreement
    against a value the run never claimed to have put there.

    The comparison itself is in :func:`sopuli.rotate.disagreements`, which does
    it without revealing either value.
    """
    entries: list[tuple[Binding, Secret, Any]] = []
    for record in applied:
        if record.binding.secret is None or record.binding.vault is None:
            continue
        key = _lock_key(record.binding)
        promotion = promotions.get(key)
        if promotion is None or promotion.version is None or record.source is None:
            continue
        entries.append((record.binding, record.source.value, _data_at(key, documents)))
    return rotation.disagreements(entries)


def _data_at(key: LockKey, documents: Mapping[LockKey, Any]) -> Any:
    stored = documents.get(key)
    return None if stored is None else stored.data


def _close_windows(
    applied: Sequence[_Applied],
    run: Invocation,
    config: Config,
    *,
    documents: Mapping[LockKey, Any],
    margin: int,
    manager: LockManager,
) -> int:
    """`--finish-rollover`: end every window this run opened, once it is over.

    **At the end of the run rather than per target**, which is the difference
    between this and `--strategy direct`. Direct closes each window as it opens
    it, so an application whose database is reached first loses the old password
    while nine more targets are still being changed; this leaves every window
    open until the whole estate has been applied, verified and promoted.

    **Only accounts this run actually confirmed**, and the filter is why the
    sequencing is safe: an account whose apply failed still has applications
    authenticating with a password that only its open window is keeping alive,
    and closing it because its neighbours succeeded would turn a partial
    rotation into an outage.

    **The fence still applies here**, which is why the manager is handed down.
    This is the last mutation of the run and the furthest from step 2, so it is
    the one most likely to be issued after a lease has gone -- and a window closed
    by a run that no longer owns the estate cannot be reopened. A takeover found
    here raises, the same as one found at step 5.
    """
    confirmed = [
        record.binding
        for record in applied
        if apply_states.is_confirmed(record.outcome.state) and record.binding.secret is not None
    ]
    if not confirmed:
        return 0
    finished = _finish_estate(
        _sources(confirmed, documents),
        run,
        config,
        margin=margin,
        preview=False,
        manager=manager,
    )
    return sum(1 for record in finished if record.changed)


def _unconfirmed(accounts: Sequence[str]) -> Diagnostic:
    """Section 8 step 8's finding, as the diagnostic a scheduler reads.

    Named accounts rather than a count, for the reason the closing line gives:
    the exit code says 4 and so does a run with half its targets failed, and what
    separates them is which accounts and what to go and look at.
    """
    return Diagnostic(
        level="error",
        message=(
            "the vault read back a different password than this run applied, for: "
            + ", ".join(sorted(accounts))
        ),
        code=ROTATION_UNCONFIRMED,
    )


def _reach(radius: Any) -> str:
    """How much of the estate a run reaches, as a phrase an operator can read.

    This is what the confirmation prompt interpolates. It used to interpolate the
    :class:`~sopuli.plan.BlastRadius` itself, which is a frozen dataclass, so the
    question read `draw a new password for BlastRadius(targets=1, accounts=1,
    environments=('dev',)) account(s) and promote it?` -- a repr in the last
    sentence an operator sees before a whole estate's passwords change, with the
    word `account(s)` after an object that already said `accounts=1`. Found by
    running the verb rather than by a test, on 21c for #380, and not
    version-specific: every rotation has always asked it this way.

    Targets **and** accounts, because the two differ exactly where sharing
    happens and that difference is what the person answering needs: `1 account on
    11 targets` and `11 accounts on 1 target` are very different things to say
    yes to, and `BlastRadius` carries both for this reason. The environments come
    along because they are what `confirm_environments` is about.
    """
    accounts = f"{radius.accounts} account{'' if radius.accounts == 1 else 's'}"
    targets = f"{radius.targets} target{'' if radius.targets == 1 else 's'}"
    where = f"{accounts} on {targets}"
    if radius.environments:
        named = ", ".join(f"`{name}`" for name in radius.environments)
        where = f"{where} in {named}"
    return where


def _confirm_rotation(plan: Any, *, confirmed: bool) -> None:
    """Section 8 step 1: print the plan and ask, unless somebody already answered.

    The same shape `lock break` has, and for the reasons :func:`_confirm_break`
    gives: the plan goes to **stderr** so that `--output json` cannot be used to
    skip a confirmation, and a run with nobody to ask is refused rather than left
    to click's EOF abort -- which tells an operator that it stopped and not what
    to type instead.

    **`rotate` asks and `apply` does not**, which is a difference worth stating
    rather than leaving to be noticed. `apply` converges an estate on what the
    vault already holds; the value it puts on a database is one somebody has
    already staged and reviewed. `rotate` *invents* the value, replaces what
    every application is using, and does it across the whole selection in one
    pass -- so section 8 puts a confirmation in front of it and section 5 does
    not.

    The estate-wide `safety.confirm_environments` setting is a separate gate that
    nothing enforces yet (#292); this flag is not it, and neither one is a
    substitute for the other.
    """
    if confirmed:
        return
    if not _can_prompt():
        raise RefusedError(
            "rotating a password needs confirmation, and there is nobody here to ask",
            hint=(
                "pass --confirm to answer in advance, or --dry-run to see the plan "
                "without touching anything"
            ),
        )
    click.echo(render_plan(plan, noun="rotation"), err=True)
    click.confirm(
        f"draw a new password for {_reach(plan.blast_radius)} and promote it?",
        abort=True,
        err=True,
    )


def _preview_rotation(
    bindings: Sequence[Binding],
    run: Invocation,
    config: Config,
    *,
    plan: Any,
    documents: Mapping[LockKey, Any],
    strategy: str | None,
    max_age_days: int | None,
) -> str:
    """`--dry-run`: the plan, what is due, and whether the estate would take it.

    **The pre-flight runs**, which is what makes `--dry-run` worth typing here
    rather than only reading the plan. It writes nothing and takes no lock, and
    "show me what this would do, and tell me whether it would work" is the
    question somebody previewing a rotation is actually asking. A refusal under
    `--dry-run` is still a refusal: the estate would not have taken this.

    **No `results`.** The plan and the selection table already say what would
    happen, at the grain it would happen at, and a second vocabulary for "would
    have" is a state nobody can act on -- which is `creds generate`'s rule and
    the same one.
    """
    document = run.document
    selections = rotation.select(
        [(binding, _document_data(binding, documents)) for binding in bindings],
        max_age_days=max_age_days,
    )
    header = _rotation_header(plan, selections, max_age_days)
    rotating = rotation.due(selections)
    if not rotating:
        document.finish(ExitCode.SUCCESS, Summary(total=len(selections)))
        return _nothing_due(plan, selections, max_age_days)

    findings = _preflight(rotating, run, config, strategy=strategy, full=True)
    document.diagnostics.extend(_preflight_diagnostics(findings))
    if preflight.refusal(findings) is not None:
        return _refuse_preflight(findings, document, header=header)

    document.finish(ExitCode.SUCCESS, Summary(total=len(rotating)))
    return f"{header}\n\nnothing was rotated (--dry-run)"


def _rotation_header(
    plan: Any, selections: Sequence[rotation.Selection], max_age_days: int | None
) -> str:
    """The plan, and -- where `--max-age-days` narrowed it -- what it selected.

    The age table is printed only when the flag was given, for the reason
    :func:`~sopuli.output.rotate_view.render_selection_table` gives: without it
    every account is due and the table carries no information the plan above it
    does not already have.
    """
    if max_age_days is None or not selections:
        return render_plan(plan, noun="rotation")
    return "\n".join([render_plan(plan, noun="rotation"), "", *render_selection_table(selections)])


def _nothing_due(
    plan: Any, selections: Sequence[rotation.Selection], max_age_days: int | None
) -> str:
    """Exit 0, and why -- which is not the same message as an empty selection.

    "Nothing is old enough" is the ordinary, healthy result of a scheduled
    rotation and must not read like "your selector matched nothing". The table
    above it has already shown every account's age, so the line only has to name
    the threshold that filtered them.
    """
    header = _rotation_header(plan, selections, max_age_days)
    return f"{header}\n\nnothing is older than --max-age-days {max_age_days}; nothing was rotated"


@creds_group.command("status")
@select_option
@click.option(
    "--max-age-days",
    type=click.IntRange(1, 100000),
    default=None,
    help="Mark accounts the vault last rotated more than this many days ago.",
)
@global_options
def creds_status(
    selectors: tuple[str, ...],
    targets: tuple[str, ...],
    accounts: tuple[str, ...],
    groups: tuple[str, ...],
    applications: tuple[str, ...],
    max_age_days: int | None,
    run: Invocation,
) -> str:
    """Inventory the estate: ages, versions, lock state, rollover.

    **No login attempts, no lock, no mutation.** The safest verb in the tool --
    `creds check` at least tries a password, and this reads two dictionary views
    and a vault document. Safe to run anywhere, at any hour, against production.

    **AGE is the vault's, and it is the one that counts.** `--max-age-days`
    filters on the `rotated_at` stamp the vault holds (Q9, issue #87), never on
    the database's own `PASSWORD_CHANGE_DATE` -- one value per secret path
    however many targets share it, so there is nothing to aggregate and no
    "oldest, newest or any" rule to invent for an account spanning a CDB's PDBs.

    The database's date is displayed beside it and never acted on. The pair is
    the point: the same database history answers differently depending on which
    clock is asked, and a row where the two disagree wildly is a drift smell that
    costs no login attempt to notice.

    **It will not tell you whether a password works.** That is `creds check`,
    which spends a login to find out. A row here reads `UNVERIFIABLE` because
    nothing was asked -- reporting `IN_SYNC` from a command that never tried
    would be agreement nobody measured.

    **What it does say without asking**: an account the config declares and the
    database has not got, one that is locked or expired, a rotation somebody
    staged and never applied, and a rollover window standing open.

    Help text stays ASCII throughout, which is P4's rule.
    """
    document = run.document

    selection = selected(selectors, targets, accounts, groups, applications)
    refuse_unknown(run.config, selection)
    config = filter_estate(run.config, selection)
    document.selection = selection.as_json() or None
    document.diagnostics.extend(config_diagnostics(config))

    config = binding_stores.complete(config, env=os.environ)
    binding_stores.refuse_unresolved(config, action="taking an inventory")

    run = _with_estate_safety(run, config)
    plan = plan_builder.build(config, intent=["none"])
    refuse_if_over_limit(run.resolved, plan.blast_radius, action="taking an inventory")
    document.plan = plan.as_json()

    bindings = list(config.bindings)
    if not bindings:
        document.finish(ExitCode.SUCCESS, Summary())
        return render_plan(plan, noun="account") + "\n\nnothing to inventory"

    keys = _document_keys(bindings)
    stores = _stores_for(
        {key.store for key in keys}, config, token_file=run.vault_token_file, cache=run.stores
    )
    documents = _read_documents(keys, stores, run=run)

    rows: list[_Surveyed] = []
    for name, work in _grouped(bindings).items():
        rows.extend(
            _survey_target(
                _expanded(config, name),
                work,
                run,
                config,
                documents=documents,
                stores=stores,
                max_age_days=max_age_days,
            )
        )

    document.results = [
        build_status_result(one.row, duration_ms=one.duration_ms, error=one.error) for one in rows
    ]
    found = [one.row for one in rows]
    document.finish(
        # `check`'s codes, and for its reason: exit 3 is drift, which this verb
        # cannot observe, so it only ever exits 0 or 1. A target it could not
        # reach is exit 1 -- an inventory with a hole in it must not look
        # complete, which is the same argument `check` makes about a survey.
        check_states.exit_code_for([one.outcome.state for one in found]),
        summarise_status(found),
    )
    return f"{render_plan(plan, noun='account')}\n\n{render_status_table(found)}"


@dataclass(frozen=True)
class _Surveyed:
    """One row, with what it cost and what went wrong."""

    row: Row
    duration_ms: int | None = None
    error: Error | None = None


def _expanded(config: Config, name: str) -> ExpandedTarget:
    return next(one for one in config.expanded_targets if one.name == name)


def _survey_target(
    target: ExpandedTarget,
    bindings: Sequence[Binding],
    run: Invocation,
    config: Config,
    *,
    documents: Mapping[LockKey, Any],
    stores: Mapping[str, SecretStore],
    max_age_days: int | None,
) -> list[_Surveyed]:
    """One target's worth of accounts, over one connection.

    A target that cannot be reached is a row rather than a crash, which is
    `doctor`'s rule and `check`'s. The vault half of the row is still filled in:
    the version and the age came from a document that was read before any
    database was dialled, and an inventory that threw them away because a
    listener was down would be answering less than it knows.
    """
    started = time.monotonic()
    session = None
    try:
        try:
            session = _open_session(target, run, config)
        except Exception as error:  # noqa: BLE001 -- a per-target finding
            reported = _as_error(error)
            elapsed = _elapsed(started)
            return [
                _Surveyed(
                    _row(
                        binding,
                        user=None,
                        outcome=check_states.Outcome(check_states.ERROR, reported.message),
                        documents=documents,
                        stores=stores,
                        max_age_days=max_age_days,
                    ),
                    duration_ms=elapsed,
                    error=reported,
                )
                for binding in bindings
            ]

        return [
            _survey_one(
                binding,
                session,
                documents=documents,
                stores=stores,
                max_age_days=max_age_days,
            )
            for binding in bindings
        ]
    finally:
        if session is not None:
            with suppress(Exception):
                session.close()


def _survey_one(
    binding: Binding,
    session: Any,
    *,
    documents: Mapping[LockKey, Any],
    stores: Mapping[str, SecretStore],
    max_age_days: int | None,
) -> _Surveyed:
    """One account: read its state, read its document, conclude nothing about the
    password.

    There is no `verify_password` call in here and there is not meant to be. The
    one assertion `tests/test_cli_creds_status.py` makes about every case is that
    the session recorded no attempt.
    """
    started = time.monotonic()
    try:
        user = session.describe_user(binding.account)
    except Exception as error:  # noqa: BLE001 -- a per-account finding
        reported = _as_error(error)
        return _Surveyed(
            _row(
                binding,
                user=None,
                outcome=check_states.Outcome(check_states.ERROR, reported.message),
                documents=documents,
                stores=stores,
                max_age_days=max_age_days,
            ),
            duration_ms=_elapsed(started),
            error=reported,
        )
    return _Surveyed(
        _row(
            binding,
            user=user,
            outcome=None,
            documents=documents,
            stores=stores,
            max_age_days=max_age_days,
        ),
        duration_ms=_elapsed(started),
    )


def _row(
    binding: Binding,
    *,
    user: UserState | None,
    outcome: check_states.Outcome | None,
    documents: Mapping[LockKey, Any],
    stores: Mapping[str, SecretStore],
    max_age_days: int | None,
) -> Row:
    """Assemble one row from the vault half and the database half.

    ``outcome`` is passed in only where the database half failed and the state is
    already decided; otherwise :func:`sopuli.status.decide` reads it off the two
    halves. Both paths fill the vault columns, for the reason `_survey_target`
    gives.
    """
    stored = _stored_document(binding, documents)
    data = None if stored is None else stored.data
    credential = _quietly_read(binding, stores)
    age = status_states.age_days(status_states.rotated_at(data, binding))
    return Row(
        binding=binding,
        outcome=outcome or status_states.decide(user, credential, data, binding),
        version=None if stored is None else int(stored.version),
        age=age,
        user=user,
        over_age=status_states.exceeds(age, max_age_days),
    )


def _quietly_read(binding: Binding, stores: Mapping[str, SecretStore]) -> StoredSecret | None:
    """The account's credential, or ``None`` for any reason at all.

    Swallowing is right here and nowhere else in this file. A malformed document
    -- a ref landing on a map, a stage on a scalar -- is a real finding that
    `check` and `apply` refuse over, and it is *this* verb's job to render the
    row that shows the estate around it rather than to abort the survey. The
    state comes back `UNVERIFIABLE` saying the vault holds nothing readable,
    which is true and is what an inventory should say.
    """
    with suppress(Exception):
        return _stored_credential(binding, stores)
    return None


if __name__ == "__main__":  # pragma: no cover
    main()

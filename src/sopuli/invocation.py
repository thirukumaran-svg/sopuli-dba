"""What one run was asked to do -- the command line and the environment, resolved.

This is the binding layer: click parameters and ``SOPULI_*`` variables in,
:class:`~sopuli.settings.resolver.Resolved` values out, with the provenance the
JSON contract's ``invocation.options`` needs. The merge rules themselves are not
here; they are in :mod:`sopuli.settings`, and this module's whole job is to feed
that one resolver rather than grow a second one beside it (decision #10).

**click parses in two stages, and both are layer 1.** The group's parser consumes
what it knows until the first non-option token -- the subcommand -- and hands the
rest to the subcommand's parser. Neither sees the other's options, so an option is
only accepted in the section belonging to the parser that declared it. Global
options are therefore declared *twice*, once on the group and once on every verb,
and both positions resolve as ``cli``: it is the same person, in the same command
line, at the same moment, so there is no authority to rank (P3, "Layer 1 is one
layer"). Position is recorded in ``source_detail`` and nowhere else.

**Except for the safety set, which is trailing-only.** ``--dry-run`` is declared
on the group as a hidden *trap* that refuses rather than resolves, and the rule
is written for the set rather than for that one flag: ``--confirm`` and
``--force``, which decision P3 keeps, belong to it too and are declared on the
verbs that take them. ``--max-targets`` is not in that set, because there is no
such flag: ``safety.max_targets`` does not declare ``Layer.CLI``, and
``00-principles.md`` P5 says why it is a setting rather than a flag
(decision #392). ``--force`` belongs by *position* though not by merge policy:
it overrides account guardrails rather than ratcheting a safety setting
(``02-oracle-privileges.md`` §4), but group position and verb position express
the same intent for it as for the others, so there is nothing to merge there
either. Group position and verb position express identical intent for a safety
flag, so accepting both would buy typing tolerance and nothing else -- and it
would buy it at the price of a merge policy in the smallest, least visible layer
there is. :func:`trailing_only` gives the typing tolerance anyway, as a message
that says where the flag goes, and no group-position safety value ever reaches
the resolver. Invariant 10 cannot be violated here because there is nothing to
merge.

**One option is declared only to be refused.** ``--vault-token`` is not an
option this tool has: a token given as a command-line value is visible in ``ps``
and in the Windows process list, which is invariant 1 without qualification.
Vault's own CLI accepts ``-token=``, so somebody will type it, and *absent* would
answer them with "no such option" -- correct, and teaching nothing about why.
Worse would be accepting it and doing nothing, which is a run that looks like it
accounted for authentication and did not. So it is declared, hidden, in both
positions, and :func:`check_vault_token` refuses it before anything else in a run
happens (ADR-007). The value it carried dies in the parser callback: what
travels is a boolean saying the flag was written.

**Which position wins where both were given.** The verb's, for the inert options:
most specific wins, and nothing is at stake. ``--config`` is the exception in
shape rather than in rule -- it is a list that layers left to right (§9), so both
positions are *kept*, group first, exactly as repeating the flag would.

**The config file is read here, before the verb runs.** Profile activation is why:
a profile is layer 3, it can supply ``output``, and a run whose output format is
settled after the verb has started has already chosen an emitter. So the boundary
discovers the file, reads it with the profile the command line asked for, and
resolves all six layers -- and a verb receives the loaded config on its
:class:`Invocation` rather than loading one of its own. Every verb needs the
file; none of them decides *when* it is read.

It happens in two steps, and the order is J7's rather than convenience.
:func:`resolve_invocation` runs first over the command line and the environment
alone, which opens the run document -- so a file that turns out to be unreadable
has somewhere to report itself, on exit 9 with a document, instead of failing
before the run exists. Then :func:`load_config_layers` reads it and
:func:`resolve_invocation` runs again over all six layers, refreshing that same
document rather than opening a second one: one run, one correlation id.
"""

from __future__ import annotations

import functools
import getpass
import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO, TypeVar

import click

from sopuli.admin import PasswordPrompt, Prompter
from sopuli.config.discovery import discover
from sopuli.config.errors import ArgumentError, ConfigError
from sopuli.config.loading import load_layers
from sopuli.config.model import Config
from sopuli.config.vault_env import ADDR_FLAG
from sopuli.driver.protocol import DriverError
from sopuli.exit_codes import ExitCode
from sopuli.lock.errors import LockDeniedError, LockError
from sopuli.material import TOKEN_FLAG, TOKEN_SOURCES
from sopuli.output.color import ColorChoice
from sopuli.output.document import Diagnostic, Error, Option, RunDocument
from sopuli.output.emit import Emitter, OutputMode
from sopuli.output.explain_view import ratchet_notes
from sopuli.output.tty import is_a_terminal
from sopuli.settings import Contribution, Layer, Resolved, resolve_all
from sopuli.settings.sources import config_contributions, env_contributions
from sopuli.store.protocol import StoreError

if TYPE_CHECKING:  # a type only -- importing the registry here would widen the
    # boundary's import graph for a field that is otherwise just a dict.
    from sopuli.store.protocol import SecretStore

F = TypeVar("F", bound=Callable[..., Any])

#: The keyword every verb receives in place of the raw option values.
INVOCATION_PARAM = "run"

#: How ``source_detail`` names the two parser positions. Recorded only for
#: options that accept both -- ``--dry-run`` has one position, so saying which
#: would be noise rather than provenance.
VERB = "verb"
GROUP = "group"

#: The global options, as click parameter names. Popped from a verb's keyword
#: arguments before it is called, so a command cannot read one directly and miss
#: the layer beneath it.
GLOBAL_PARAMS = (
    "config_paths",
    "output_mode",
    "color_choice",
    "profile_name",
    "dry_run",
    "vault_token_file",
    "vault_token_given",
    "vault_addr",
)

#: The settings every run consults, whether or not any layer mentioned them.
#:
#: Resolution is per setting, and a setting nobody supplied still has an answer
#: when it has a built-in default -- ``output`` is ``text`` on a bare command
#: line. Listing them is what asks the resolver the question; a setting left off
#: this list is simply never asked, which is why it is short and explicit rather
#: than "everything in the registry". A setting joins it when something reads it.
#:
#: `verify.method` and `log_level` are absent. A profile may write them: they
#: are parsed and validated, but nothing reads them, which is the rule
#: `sopuli/settings/registry.py` states.
#:
#: **A setting with a reader must be listed here.** A name absent from this tuple
#: is never in `Invocation.resolved`, so a read of it returns `None` on every run
#: and the built-in is used whatever the profile said. That key looks wired from
#: both ends and is joined in the middle by nothing.
#: `tests/settings/test_settings_are_wired.py` refuses that shape.
#: `vaults.*` is absent for a different reason -- it is resolved inside the file,
#: by `sopuli/config/vault_layers.py`, because it describes a store rather than
#: a run. `vault` is the one next to it that *is* a run setting and so is here:
#: it names which store the run defaults to, which is what §6's unnamed
#: `SOPULI_VAULT_ADDR` and `VAULT_ADDR` need before they know what they address.
#: It is resolved twice per run for that reason -- here, so the document reports
#: where the name came from, and again in `sopuli/config/vault_env.py`, which
#: needs the answer while the file is still being built. Same two contributions,
#: same resolver, so there is nothing for them to disagree about.
RESOLVED_SETTINGS = (
    "confirm",
    "db.connect_timeout_s",
    "db.query_timeout_s",
    "locking.break_expired",
    "output",
    "profile",
    "safety.confirm_environments",
    "safety.delivery.allowed_methods",
    "safety.dry_run",
    "safety.max_targets",
    "safety.readonly",
    "vault",
)

#: What an :class:`Invocation` built without a command is called. Only reachable
#: from a test that constructs one directly -- every real run derives the name
#: from the command tree (:func:`command_path`) -- and it is a value from the
#: schema's enum rather than a placeholder, so such a document still validates.
NO_COMMAND = "config.show"


@dataclass(frozen=True)
class GlobalOptions:
    """One parser's view of the global options -- the group's, or a verb's.

    ``None`` means *not given*, which is why the defaults here are ``None`` and
    not each option's own default. Distinguishing "not given" from "given the
    documented default" is what makes a precedence layer expressible at all, and
    click supports it for flags as well as for values.
    """

    config_paths: tuple[Path, ...] = ()
    output_mode: str | None = None
    color_choice: str | None = None
    #: ``--profile``'s value. A profile *name*, never a selector -- §5's whole
    #: distinction, and the reason this is not beside ``--select``.
    profile_name: str | None = None
    dry_run: bool = False
    vault_token_file: Path | None = None
    #: ``--vault-addr``'s value, or ``None``. Layer 1 of
    #: ``vaults.*.addr``, and unlike every other global option it is consumed
    #: while the *file* is being built rather than at this boundary -- a store's
    #: settings belong to the store, so they are merged in
    #: :mod:`sopuli.config.vault_layers` and never reach ``RESOLVED_SETTINGS``.
    vault_addr: str | None = None
    #: Whether ``--vault-token`` was written, and **never what it carried**. The
    #: parser callback throws the value away, so there is no field on this class,
    #: on :class:`Invocation`, or anywhere between them that a token could sit in.
    vault_token_given: bool = False

    @classmethod
    def from_params(cls, params: Mapping[str, Any]) -> GlobalOptions:
        """Read whichever of :data:`GLOBAL_PARAMS` are present."""
        return cls(
            config_paths=tuple(params.get("config_paths") or ()),
            output_mode=params.get("output_mode"),
            color_choice=params.get("color_choice"),
            profile_name=params.get("profile_name"),
            dry_run=bool(params.get("dry_run", False)),
            vault_token_file=params.get("vault_token_file"),
            vault_addr=params.get("vault_addr"),
            vault_token_given=bool(params.get("vault_token_given", False)),
        )


@dataclass(frozen=True)
class LoadedConfig:
    """The configuration this run read, in both the forms a command needs.

    One object rather than three fields on :class:`Invocation`, because the three
    are one answer: they come from one read, and a command holding two of them
    from different reads would be describing a file that never existed.
    """

    #: What discovery settled on -- the files actually read, in layering order.
    #: Not the same as :attr:`Invocation.config_paths`, which is what ``--config``
    #: was given; with no flag at all that is empty and this is not.
    paths: tuple[Path, ...]
    #: The merged raw document. ``config show`` renders it as "the configuration
    #: as loaded", which after several ``--config`` layers is a thing no file on
    #: disk holds.
    declared: dict[str, Any]
    #: The validated file, with its own precedence layers already merged and the
    #: active profile chosen (:attr:`~sopuli.config.model.Config.active_profile`).
    config: Config


@dataclass(frozen=True)
class Invocation:
    """The resolved answer for one run.

    Handed to every verb in place of the raw click parameters. A verb that wants
    to know whether this is a dry run asks :attr:`dry_run`, and gets the
    resolver's answer -- ``SOPULI_DRY_RUN`` included.
    """

    config_paths: tuple[Path, ...] = ()
    color_choice: ColorChoice = ColorChoice.AUTO
    #: ``--vault-token-file``'s path, or ``None``. A **location**, like every
    #: other step of §3a's token chain -- the file is read when a run reaches a
    #: store, by :func:`sopuli.material.resolve_token`, so a command that opens
    #: no socket never reads it and no invocation ever holds a credential.
    vault_token_file: Path | None = None
    #: ``--vault-addr``'s value, or ``None``. Held rather than resolved
    #: here: it is a setting of a *store*, so it joins the merge inside the file
    #: (:func:`sopuli.config.vault_layers.apply_vault_layers`), which is why
    #: :func:`load_config_layers` is the one place that reads it.
    vault_addr: str | None = None
    resolved: Mapping[str, Resolved] = field(default_factory=dict)
    #: How ``auth: prompt`` asks, or ``None`` when nobody is at a terminal.
    #: Built once per run by :func:`_pass_invocation`, because
    #: :class:`~sopuli.admin.PasswordPrompt` caches its answers and one instance
    #: is what makes §3a's "one prompt covers every target that declares the
    #: same credential" true -- a second instance would ask again for a
    #: credential the first already has.
    #:
    #: **A value rather than a location**, unlike :attr:`vault_token_file`, and
    #: it holds no secret either way: what is stored is the *means* of asking,
    #: and nothing has been asked until a target that declares ``prompt`` is
    #: reached. A run that authenticates by wallet builds one and never calls it.
    #:
    #: ``None`` is the refusal P5 needs rather than an absent feature:
    #: :func:`sopuli.safety.refuse_if_nobody_to_ask` turns it into exit 8 on a
    #: verb that changes something, and the reason a prompter exists *only*
    #: under a terminal is that a terminal is not carrying a piped password --
    #: so ``--from-stdin`` and this can never be two readers of one stream.
    prompt: Prompter | None = None
    #: Every secret store this run has opened, by name.
    #:
    #: **The run's client cache**, filled by ``cli._stores_for`` -- so the lock
    #: stores, an application's binding stores and a target's ``method: vault``
    #: admin credential all share one client per name. That is the whole of what
    #: it is for: those are opened by different calls at different moments, and
    #: without somewhere per-run to put them a config keeping its admin
    #: credential and its application documents in one vault authenticated to it
    #: twice.
    #:
    #: A client per *name* is safe because every one is built the same way, from
    #: the ``vaults:`` entry and this run's token file, and nothing ever closes
    #: one. Empty on a run that opens no store at all.
    #:
    #: It holds no secret: a client knows how to fetch one, and what it fetches
    #: is wrapped on the way out.
    stores: dict[str, SecretStore] = field(default_factory=dict)
    #: The configuration, read by the boundary before the verb ran.
    #:
    #: ``None`` only where no file has been read: an :class:`Invocation` built
    #: directly in a test, or the preliminary one that exists between the command
    #: line resolving and the file being opened. Every verb receives a loaded one,
    #: and :attr:`config` says so rather than making each of them check.
    loaded: LoadedConfig | None = None
    #: The run document, **open from the moment the invocation resolves**. A verb
    #: fills in its sections and finishes it; it is serialised once, by
    #: :func:`_pass_invocation`. Building it here rather than at the end is what
    #: makes "every exit but 2 emits a document" true rather than aspirational --
    #: an exception three lines into a verb still has one to attach the error to.
    document: RunDocument = field(default_factory=lambda: RunDocument.start(NO_COMMAND))

    @property
    def output_mode(self) -> OutputMode:
        return OutputMode(self.value("output"))

    @property
    def dry_run(self) -> bool:
        return bool(self.value("safety.dry_run"))

    @property
    def is_json(self) -> bool:
        """Whether this run's output is a machine-readable contract -- ``json``
        or ``jsonl``.

        Both, because every caller is asking the contract's question rather than
        the framing's: may a password be printed, may the handover token go to
        stdout. A seen reset refused under ``json`` and allowed under ``jsonl``
        would be invariant 2's guard lost to an output mode added after it.

        Compared against the resolved value rather than through
        :attr:`output_mode`, so that a format this build does not have answers
        ``False`` instead of raising. A run can reach here holding one: a
        variable or a profile may carry any string,
        :func:`check_output_mode` refuses it, and the refusal travels out through
        the exit handler -- which asks this question on the way past. Raising
        there would replace a usage error naming ``profiles.ci.output`` with a
        ``ValueError`` about an enum, and ``False`` is the true answer in any
        case: a run that could not read its own ``--output`` emits no document.
        """
        return self.value("output") in (OutputMode.JSON, OutputMode.JSONL)

    @property
    def profile(self) -> str | None:
        """The active profile's name, or ``None`` (§5). What the JSON contract
        reports as ``invocation.profile``.

        Read off the loaded config rather than off ``resolved["profile"]``: the
        setting is what was *asked for*, and this is what the file resolved it to.
        The two agree whenever a profile is active, and differ in the case worth
        being exact about -- nobody asked, and ``defaults.profile`` did not
        either, so the answer is that there is no profile rather than a name.
        """
        if self.loaded is None or self.loaded.config.active_profile is None:
            return None
        return self.loaded.config.active_profile.name

    @property
    def config(self) -> Config:
        """The configuration this run read.

        Raises rather than returning ``None``: a verb runs only after the
        boundary has loaded the file, so an absent one here is a programming
        error -- a command invoked around :func:`_pass_invocation` -- and not a
        condition any command should be written to handle. Three accessors rather
        than one, because a command wants one of the three and should not have to
        reach through an object to say which.
        """
        return self._loaded().config

    @property
    def sources(self) -> tuple[Path, ...]:
        """The config files that were read, in layering order. See :attr:`config`."""
        return self._loaded().paths

    @property
    def declared(self) -> dict[str, Any]:
        """The merged raw document. See :attr:`config`."""
        return self._loaded().declared

    def _loaded(self) -> LoadedConfig:
        if self.loaded is None:
            raise RuntimeError(
                "no configuration has been loaded on this invocation; a verb "
                "receives one from `_pass_invocation`"
            )
        return self.loaded

    def value(self, name: str) -> Any:
        """The effective value of a setting, or ``None`` if no layer supplied one."""
        answer = self.resolved.get(name)
        return None if answer is None else answer.value

    def emitter(self) -> Emitter:
        """The one emitter for this run (see :class:`~sopuli.output.emit.Emitter`)."""
        return Emitter(mode=self.output_mode, color_choice=self.color_choice)


def open_document(command: str, invocation: Invocation) -> RunDocument:
    """A run document carrying this invocation's own settings.

    Opened as soon as the command line resolves, which is before the config file
    is read: a file that turns out to be unreadable reports itself *in* a run
    document on exit 9, and there has to be one for it to go in (J7).
    :func:`refresh_document` then fills in what the file changed.
    """
    return refresh_document(RunDocument.start(command), invocation)


def refresh_document(document: RunDocument, invocation: Invocation) -> RunDocument:
    """Re-state what this run was asked to do, after a layer joined.

    Called twice per run -- once when the document is opened over the command
    line and the environment, once when the config file's three layers arrive.
    The same document both times, so a run keeps one ``correlation_id``
    and one ``started_at`` however many layers it took to settle.

    ``options`` reports what *changed behaviour*, which is the schema's own
    wording: a setting answered by its built-in default changed nothing, and
    ``output: text [builtin]`` on every clean run would be noise in a document
    consumers diff. ``--explain`` lifts that filter (see :func:`all_options`) --
    the same producer, asked for everything.

    A defeated relaxation becomes a diagnostic here rather than under
    ``--explain``, because it is true of every run: something was asked for and
    safely refused, and a run that says nothing about it is the surprise
    invariant 10 exists to prevent. The notes are *replaced* rather than
    appended, because the second call resolves the same settings again and would
    otherwise say each one twice. Nothing else has written a diagnostic at this
    point: this runs before the verb does.

    ``config_files`` is filled on the second call and only then, which is
    what the two-call arrangement is for: the first happens before a file has
    been read, so there is nothing to name, and a run that never loads one keeps
    the field absent rather than empty.

    **Resolved, not as given.** ``discover`` keeps an
    explicit ``--config estate.yaml`` relative, and a relative path is only
    meaningful beside the working directory that produced it -- which no later
    reader has. `creds apply --repair` compares this list against its own run's
    to refuse a document from another estate, and two *different* files both
    called ``estate.yaml`` would have compared equal. Resolving here rather than
    there is what makes the comparison sound at all: the reader cannot recover a
    working directory the writer did not record.
    """
    document.dry_run = invocation.dry_run
    document.profile = invocation.profile
    if invocation.loaded is not None:
        document.config_files = tuple(str(path.resolve()) for path in invocation.sources)
    document.options = {
        name: option
        for name, option in all_options(invocation).items()
        if invocation.resolved[name].layer is not Layer.BUILTIN
    }
    document.diagnostics[:] = ratchet_notes(invocation.resolved)
    return document


def all_options(invocation: Invocation) -> dict[str, Option]:
    """Every setting the run consulted, built-in defaults included.

    What ``--explain`` reports, in both output modes. The shape is identical to
    the filtered form -- one producer, one schema -- so the flag changes how many
    entries appear and nothing about what an entry means.
    """
    return {
        name: Option(
            value=answer.value,
            source=str(answer.layer),
            source_detail=answer.detail,
        )
        for name, answer in invocation.resolved.items()
    }


def command_path(ctx: click.Context) -> str:
    """The verb's dotted path, as the schema's ``command`` enum spells it.

    Derived rather than passed in by each verb. The enum *is* D2's noun-verb
    grammar written with a dot -- ``config show`` is ``config.show``, and the
    top-level ``doctor`` is ``doctor`` -- so a verb repeating its own name would
    be a second spelling of one fact, and the one place a typo could put a run
    document under a command that does not exist.

    Built by walking up the context chain rather than by splitting
    ``ctx.command_path``, which begins with the program name -- and the program
    name is whatever click made of ``argv[0]``, which can be several words
    (``python -m sopuli``, and ``python -m pytest`` under the test suite). Every
    context except the root is a noun or a verb; the root is the program.
    """
    names = []
    node: click.Context | None = ctx
    while node is not None and node.parent is not None:
        if node.info_name is not None:
            names.append(node.info_name)
        node = node.parent
    return ".".join(reversed(names))


def global_options(func: F) -> F:
    """Attach the global options to a **verb**, and hand it an :class:`Invocation`.

    One line per command; retrofitting it across twenty verbs would not be, which
    is why it is a decorator rather than something each verb remembers to do.
    ``tests/test_cli_precedence.py`` walks the command tree and fails if a verb is
    missing it.

    ``--dry-run`` is here because invariant 8 requires every mutating command to
    support it. Putting it on every verb means no new command has to remember to
    add the flag. On a verb that mutates nothing, it only reaches the run
    document.
    """
    return _options(_pass_invocation(func), hidden=False)


def group_options(func: F) -> F:
    """Attach the same options to the **group**: the inert ones real, the safety
    ones as traps.

    Hidden, all of them. ``sopuli --help`` listing a second copy of every global
    option would suggest the two positions differ, and the point is that they do
    not.
    """
    return _options(func, hidden=True)


def trailing_only(ctx: click.Context, param: click.Parameter, value: bool) -> bool:
    """Refuse a safety flag written before the subcommand, and say where it goes.

    The alternative is what happens today: click reports "no such option" and
    exits 2, which is correct and unhelpful. This exits 2 with the fix in it.

    The message cannot name the subcommand the user actually typed. When a
    group-level option callback runs, click has not yet split the remaining
    tokens -- ``ctx.args`` is empty and the parser's state is not exposed -- and
    reading ``sys.argv`` instead would work in the process and not under
    ``CliRunner``, which is a worse trade than a message one word less specific.
    """
    del ctx
    if not value:
        return value
    flag = param.opts[0]
    raise click.UsageError(
        f"{flag} must be given after the subcommand, not before it:\n"
        f"       sopuli <noun> <verb> {flag}\n"
        f"       safety flags are accepted in the trailing position only"
    )


def token_given(ctx: click.Context, param: click.Parameter, value: str | None) -> bool:
    """Keep *that* ``--vault-token`` was written; drop what it carried.

    The one place the refused flag's value is ever in a variable, and it does not
    leave this function. Returning the value so that
    :func:`check_vault_token` could quote it would put a token on
    :class:`GlobalOptions`, in a traceback frame, and in every ``repr`` of an
    invocation -- for a message that must not print it anyway.

    Declared with ``flag_value`` and ``is_flag=False``, so click accepts all four
    ways somebody will write it -- ``--vault-token``, ``--vault-token X``,
    ``--vault-token=X`` -- and every one of them lands here. A plain flag would
    leave ``X`` behind as an unexpected argument, and a plain value option would
    answer the bare form with "requires an argument": both are click explaining
    its own parser instead of the tool explaining invariant 1.
    """
    del ctx, param
    return value is not None


def check_vault_token(group: GlobalOptions, verb: GlobalOptions) -> None:
    """Refuse ``--vault-token``, and name every source that does work.

    **Exit 2, and not a plan-time capability refusal.** P5 puts exit 2 at "argv
    did not resolve to a valid command and options", which is exactly this: the
    flag is not an option the tool has. J7 then makes exit 2 the one
    code that carries no run document, so this cannot be reported *in* a plan the
    way a missing capability is -- there is no run to describe. What it keeps
    from that mechanism is the part that matters: it fires before anything else a
    run does, ``--dry-run`` included, so a rehearsal cannot come back clean while
    the flag silently did nothing.

    The hint lists all four working sources rather than recommending the file
    form alone. A CI job where writing a token to disk is awkward is precisely
    the case that hits this, and it already has an answer: exporting
    ``SOPULI_VAULT_TOKEN`` for the run. A hint naming only ``--vault-token-file``
    would hide it.
    """
    if not (group.vault_token_given or verb.vault_token_given):
        return
    raise ArgumentError(
        "--vault-token is not an option: a token given on the command line is "
        "visible in `ps` and in the Windows process list (P5, invariant 1)",
        hint=(
            f"name where the token is instead of passing it. Any of: "
            f"{', '.join(TOKEN_SOURCES[:-1])}, or `vault login`, which writes "
            f"{TOKEN_SOURCES[-1]}"
        ),
    )


def resolve_invocation(
    group: GlobalOptions,
    verb: GlobalOptions,
    *,
    env: Mapping[str, str],
    command: str = NO_COMMAND,
    loaded: LoadedConfig | None = None,
    document: RunDocument | None = None,
) -> Invocation:
    """Merge both parser positions with the environment and the file, and resolve.

    Pure: the environment arrives as a mapping and the configuration arrives
    already read. The process supplies its own of each in
    :func:`_pass_invocation`, which is the only place either is fetched.

    ``loaded`` is ``None`` on the first pass, because the file cannot be read
    until the command line has said which one and under which profile. Called
    again with it -- and with the document the first pass opened -- the file's
    three layers join the same merge and the same document is refreshed. A caller
    with nothing to load, which is every test whose subject is the command line,
    simply never makes the second call.

    :func:`check_vault_token` is the first thing that happens either way: a
    refused flag means the invocation never resolved, so there is nothing yet to
    describe (J7).
    """
    check_vault_token(group, verb)

    contributions: dict[str, list[Contribution]] = {name: [] for name in RESOLVED_SETTINGS}
    if loaded is not None:
        # Lowest first, so the insertions below land in front of it. Order within
        # a layer is the caller's to express and only matters there; between
        # layers the resolver sorts for itself.
        for name, supplied in config_contributions(loaded.config).items():
            _wired(contributions, name).extend(supplied)
    for name, supplied in env_contributions(env).items():
        _wired(contributions, name)[:0] = supplied
    for name, contribution in _cli_contributions(group, verb):
        # The command line outranks the environment, and within one layer the
        # first contribution wins -- so the CLI's goes in front of whatever the
        # environment already put there.
        _wired(contributions, name).insert(0, contribution)

    invocation = Invocation(
        # Left to right, group first: both positions are kept, because repeating
        # `--config` layers files rather than replacing them (§9).
        config_paths=(*group.config_paths, *verb.config_paths),
        color_choice=ColorChoice(_first_given(verb.color_choice, group.color_choice)),
        vault_token_file=_first_path(verb.vault_token_file, group.vault_token_file),
        vault_addr=_first_written(verb.vault_addr, group.vault_addr),
        resolved=resolve_all(contributions),
        loaded=loaded,
    )
    if document is None:
        return replace(invocation, document=open_document(command, invocation))
    return replace(invocation, document=refresh_document(document, invocation))


def load_config_layers(invocation: Invocation, *, env: Mapping[str, str]) -> LoadedConfig:
    """Discover and read the configuration, under the profile that was asked for.

    The one place a command's file is opened. The profile *name* comes from the
    resolver rather than from ``--profile`` directly, so ``SOPULI_PROFILE`` is
    honoured here without this function knowing it exists; the file then supplies
    ``defaults.profile`` where neither spoke, and refuses a name nothing declares
    (:func:`sopuli.config.profiles.select_profile`).

    Reading the file is what makes layers 3 to 5 reachable, so it cannot be
    deferred to the verb -- see the module note.
    """
    paths = discover(invocation.config_paths, env=env)
    declared, config = load_layers(
        paths,
        profile=invocation.value("profile"),
        env=env,
        # Layer 1 of `vaults.*.addr`, and the one global option that has to arrive
        # here rather than at the resolver above: a store's settings are
        # merged inside the file, because they describe the store rather than the
        # run. `--profile` already reaches this function for its own version of
        # that reason, so this is the shape rather than a new one.
        vault_addr=invocation.vault_addr,
    )
    return LoadedConfig(paths=paths, declared=declared, config=config)


def terminal_prompter(stdin: TextIO | None) -> Prompter | None:
    """How ``auth: prompt`` asks, when there is somebody to ask.

    The half of ``sopuli/admin.py`` that lives out here, and it is out here for
    the reason that module's :data:`~sopuli.admin.Asker` note gives: naming
    :mod:`getpass` in the config layer would put a terminal read one import away
    from it, and **the decision whether there is a terminal already lives at this
    boundary**. So the supplier is built where the process's own streams are
    known, and everything below takes it as an argument.

    ``None`` when stdin cannot answer to being a terminal, which is a refusal and
    not a missing feature -- :func:`sopuli.safety.refuse_if_nobody_to_ask` and
    :func:`sopuli.admin._from_prompt` turn it into a refusal naming the three
    sources that need nobody. The condition is stdin and deliberately not
    stderr: what is being protected is P5's *one stream, one reader*, and the
    stream ``--from-stdin`` claims is stdin. A run with a piped password
    therefore builds no prompter at all, so the two can never both read the
    pipe.

    :func:`~sopuli.output.tty.is_a_terminal` rather than ``stdin.isatty()``,
    because ``isatty()`` can raise: under a scheduler or a service manager stdin is
    detached, and a detached stream raises on being asked. That is exactly the
    run whose answer must be "nobody is watching" rather than a traceback from
    inside the code that was finding out.

    **The question is never put on stdout**, and :mod:`getpass` is what makes
    that true rather than a rule kept here: it writes to the controlling terminal
    where there is one and to stderr otherwise. Stdout carries the run document
    under ``--output json`` (J1), and a prompt written there would corrupt it for
    every reader -- while writing the *answer* anywhere is invariant 1's problem
    and is why the echo is off.
    """
    if not is_a_terminal(stdin):
        return None
    return PasswordPrompt(ask=getpass.getpass)


def _wired(contributions: dict[str, list[Contribution]], name: str) -> list[Contribution]:
    """The contribution list for a setting this run actually consults.

    Enforced rather than assumed, for the reason
    :attr:`sopuli.settings.registry.Setting.layers` is: a source that starts
    producing a setting nothing reads would otherwise have it resolved and
    reported in ``invocation.options`` by ``setdefault``, which claims the run
    was influenced by something that influenced nothing. A lie in the contract is
    worse than a missing row, and this is the same argument that keeps `profile`
    out of :data:`RESOLVED_SETTINGS` until a profile does something.

    A programming error, so it raises rather than being reported: only code can
    add to :data:`~sopuli.settings.sources.ENV_SETTINGS`.
    """
    if name not in contributions:
        raise ValueError(
            f"{name!r} was supplied by a source but is not in RESOLVED_SETTINGS; "
            f"this run consults: {', '.join(RESOLVED_SETTINGS)}"
        )
    return contributions[name]


#: The verbs that accept ``--output jsonl``, by :func:`command_path`.
#:
#: A verb is here because it streams something the document would otherwise
#: carry only at exit -- `check`'s per-target results as each target finishes,
#: `apply`'s, `rotate`'s and `generate`'s locks, reads, writes, database changes
#: and promotions as they happen.
#: One that is not refuses the mode rather than accepting it and emitting
#: ``run.started`` and ``run.finished`` with its findings missing: ``jsonl`` and
#: ``json`` are promised to describe the same run (``03-json-output.md`` §1), and
#: the event schema has no home for a ``config`` section.
#: Adding a verb means giving it events, not only a line here.
STREAMING_COMMANDS: frozenset[str] = frozenset(
    {"creds.check", "creds.apply", "creds.rotate", "creds.generate", "account.reset-password"}
)


def check_output_mode(invocation: Invocation) -> None:
    """Refuse an output format the tool does not have, naming where it came from.

    ``--output`` is a ``click.Choice`` and click checks it; ``SOPULI_OUTPUT`` is
    checked by nothing, and an unknown value there would otherwise surface as a
    bare ``ValueError`` out of the enum three frames later. Naming the location is
    what makes it fixable -- the same variable can be inherited from a CI image
    nobody in the room chose.

    **And a format this verb does not have**: ``jsonl`` is refused by any
    verb outside :data:`STREAMING_COMMANDS`, for the same reason and on the same
    exit -- the request names a real mode, but not one this run can produce.

    An :class:`~sopuli.config.errors.ArgumentError`, so it exits 2 and emits no
    document, and this is the case ``03-json-output.md`` §6 names outright:
    ``--output json`` is itself a request that has to parse, and the tool cannot
    honour one it failed to read. It does not matter that the value arrived in a
    variable rather than in argv -- the invocation did not resolve either way.

    A profile is the third source, and gets the same answer for the same
    reason, exit 2 rather than a bad-configuration exit 9: what failed is not the
    file but the run's ability to say anything about itself, and a document is
    the thing that cannot be produced. The message names ``profiles.ci.output``,
    so the line to fix is still in it.
    """
    answer = invocation.resolved.get("output")
    if answer is None:
        return
    if answer.value not in {mode.value for mode in OutputMode}:
        raise ArgumentError(
            f"{answer.location}: {answer.value!r} is not an output format",
            hint=f"this build has: {', '.join(mode.value for mode in OutputMode)}",
        )
    command = invocation.document.command
    if answer.value == OutputMode.JSONL and command not in STREAMING_COMMANDS:
        # The same exit 2 and the same reason as an unknown format: this verb
        # cannot honour the request, so the invocation did not resolve, and
        # §6's rule for jsonl is zero events rather than a thin stream.
        raise ArgumentError(
            f"{answer.location}: `{command.replace('.', ' ')}` does not stream, "
            "so it has no jsonl output",
            hint=(
                "use --output json for the same run as one document; jsonl is "
                f"offered by: {', '.join(sorted(c.replace('.', ' ') for c in STREAMING_COMMANDS))}"
            ),
        )


# -------------------------------------------------------------- the wiring ---


def _options(func: F, *, hidden: bool) -> F:
    """The options themselves, in one place so the two positions cannot drift.

    An option accepted on the verb and forgotten on the group is the asymmetry
    this module exists to remove, so there is one list and a switch for what the
    safety flags do with it.
    """
    config = click.option(
        "--config",
        "config_paths",
        multiple=True,
        type=click.Path(path_type=Path),
        hidden=hidden,
        help="Config file. Repeat to layer files left to right.",
    )
    output = click.option(
        "--output",
        "output_mode",
        type=click.Choice([mode.value for mode in OutputMode]),
        default=None,
        hidden=hidden,
        help="Output format. Scripts should consume json, never text.  [default: text]",
    )
    color = click.option(
        "--color",
        "color_choice",
        type=click.Choice([choice.value for choice in ColorChoice]),
        default=None,
        hidden=hidden,
        help="Colour in text output. auto follows the terminal; NO_COLOR disables"
        " it.  [default: auto]",
    )
    profile = click.option(
        "--profile",
        "profile_name",
        metavar="NAME",
        default=None,
        hidden=hidden,
        help="Run under a profile declared in `profiles:`. Not a selector: it"
        " changes how the run behaves, never what it acts on.",
    )
    vault_addr = click.option(
        ADDR_FLAG,
        "vault_addr",
        metavar="URL",
        default=None,
        hidden=hidden,
        help="Address of the default vault -- whichever store `SOPULI_VAULT` or"
        " `defaults.vault` names. Refused when neither does.",
    )
    vault_token_file = click.option(
        TOKEN_FLAG,
        "vault_token_file",
        type=click.Path(path_type=Path),
        default=None,
        hidden=hidden,
        help="File holding the vault token. The command line's position in the"
        " token chain; the token itself is never an option value.",
    )
    # Always hidden, in both positions: the help must not advertise a flag whose
    # only behaviour is to refuse. Somebody arrives here by typing what Vault's
    # own CLI takes, not by reading `--help`.
    vault_token = click.option(
        "--vault-token",
        "vault_token_given",
        is_flag=False,
        flag_value="",
        default=None,
        hidden=True,
        callback=token_given,
    )
    dry_run = (
        click.option(
            "--dry-run",
            is_flag=True,
            default=False,
            hidden=True,
            expose_value=False,
            callback=trailing_only,
        )
        if hidden
        else click.option(
            "--dry-run",
            is_flag=True,
            default=False,
            help="Print the plan and make no changes.",
        )
    )
    return color(profile(output(vault_addr(vault_token(vault_token_file(dry_run(config(func))))))))


def _pass_invocation(func: F) -> F:
    """Resolve the run's settings, and give the verb them as ``run``.

    The verb declares ``run: Invocation`` and never sees ``output_mode``,
    ``dry_run`` or ``config_paths`` at all. That is the point: a value read
    straight off a click parameter is a value that skipped the resolver, and this
    removes the opportunity rather than the temptation.
    """

    def wrapper(ctx: click.Context, /, **kwargs: Any) -> Any:
        verb = GlobalOptions.from_params(kwargs)
        for name in GLOBAL_PARAMS:
            kwargs.pop(name, None)
        group = ctx.find_root().obj or GlobalOptions()
        command = command_path(ctx)
        invocation = resolve_invocation(group, verb, env=os.environ, command=command)
        check_output_mode(invocation)

        # Everything from here is the exit handler. It is one function applied to
        # every verb rather than a global, which is what "serialised once" means
        # in practice: a verb cannot forget it, and there is no ambient state
        # holding a half-built document.
        #
        # The config file is read *inside* it, and that is the point: a bad file
        # is exit 9 with a run document (J7), which needs the document above
        # to be open already and this handler to be watching. Rebinding
        # `invocation` is what the handler then reports against -- the resolved
        # one if the file was read, the command line's own if it was not.
        try:
            loaded = load_config_layers(invocation, env=os.environ)
            invocation = resolve_invocation(
                group,
                verb,
                env=os.environ,
                command=command,
                loaded=loaded,
                document=invocation.document,
            )
            # Again, because a profile may have supplied `output` -- and an
            # output format the tool does not have is still not a request it can
            # honour, wherever it was written.
            check_output_mode(invocation)
            # Built here and not in `resolve_invocation`, which is pure and is
            # called twice: a prompter made in there would be made twice, and the
            # second would arrive empty. One per run is the whole design of
            # `PasswordPrompt` -- the cache *is* the answer to "have we asked for
            # this one already" -- so it is attached once, after the last resolve.
            invocation = replace(invocation, prompt=terminal_prompter(sys.stdin))
            kwargs[INVOCATION_PARAM] = invocation
            text = ctx.invoke(func, **kwargs)
        except click.Abort as exc:
            # click would print "Aborted!" and exit 1. P5 puts "aborted by user /
            # confirmation declined" on 8, and an abort raised from inside a verb
            # is that: the invocation resolved, the run began, and somebody -- or
            # a Ctrl-C -- stopped it. Raising SystemExit here rather than
            # re-raising is what makes the process agree with the document, since
            # `exit_code` in the document always equals the process's.
            _abort(invocation)
            click.echo("sopuli: aborted", err=True)
            raise SystemExit(ExitCode.ABORTED) from exc
        except Exception as exc:  # noqa: BLE001 - deliberate: this is the handler
            _fail(invocation, exc)
            raise
        invocation.emitter().emit(invocation.document, text)
        if invocation.document.exit_code:
            # The document's `exit_code` always equals the process's: a verb that
            # finished non-zero would otherwise emit a document saying so and
            # exit 0 anyway.
            #
            # `doctor`'s failure is a *finding* rather than an exception -- an
            # unreachable target is what the command is for -- so it finishes
            # non-zero without raising. P5
            # exists so schedulers can branch on the number, and a survey that
            # always exits 0 is one nothing can alert on.
            raise SystemExit(invocation.document.exit_code)
        return text

    # `update_wrapper` rather than the `@functools.wraps` decorator, so that mypy
    # still sees `wrapper` as the plain function `click.pass_context` wants. The
    # effect is the same, and it is what carries the verb's docstring into
    # `--help` and its signature into `inspect.signature` -- which is how
    # `tests/test_cli_precedence.py` can check that a verb really takes `run`.
    functools.update_wrapper(wrapper, func)
    return click.pass_context(wrapper)  # type: ignore[return-value]


def _fail(invocation: Invocation, exc: BaseException) -> None:
    """Emit the run document for a failure, if this failure has one.

    J7's rule, and the only place it is applied: **exit 2 never produces a
    document**, everything else does. Keyed on the exit code rather than on the
    exception type, so a new error class cannot arrive on the wrong side of the
    seam by forgetting to be listed here.

    The exception is re-raised by the caller either way. In text output that is
    what reaches the boundary in :func:`sopuli.cli.main` and becomes a message on
    stderr -- a run document *is* the JSON output mode, and text has no such
    thing to withhold.
    """
    if not invocation.is_json:
        return

    code, error = _classify(exc)
    if code is ExitCode.USAGE:
        # The invocation never resolved -- or, for `ArgumentError`, resolved to
        # something that was not a valid request. Either way there is no run to
        # describe, stdout stays byte-empty, and the message goes to stderr.
        return

    document = invocation.document
    document.error = error
    document.finish(code)
    invocation.emitter().emit(document, "")


def _abort(invocation: Invocation) -> None:
    """Emit the run document for a run somebody stopped.

    An abort is a run that happened and did not finish, so it gets a document
    like every other exit but 2 -- withholding one would be the same defect as
    withholding it for a failure, and worse in the case it exists for: a
    confirmation declined halfway through a rotation is exactly when a scheduler
    wants to know which targets were already touched.

    No ``error`` object, because the schema's ``category`` enum has no value for
    "the operator said no" and ``internal`` would be a lie about what happened.
    The exit code says it, and a diagnostic says it in words -- the schema makes
    ``error`` optional precisely so a document can report an outcome that is not
    a failure.
    """
    if not invocation.is_json:
        return
    document = invocation.document
    document.diagnostics.append(Diagnostic(level="info", message="aborted before completion"))
    document.finish(ExitCode.ABORTED)
    invocation.emitter().emit(document, "")


def _classify(exc: BaseException) -> tuple[ExitCode, Error]:
    """An exception as an exit code and an ``error`` object.

    ``ConfigError`` carries its category, its exit code and -- where the
    condition has one -- its ``error.code`` itself, which is the point of
    :attr:`~sopuli.config.errors.ConfigError.category`: the boundary reports what
    the error says about itself rather than inferring it from a type, and the
    inference is what goes wrong first when a subclass is added. A missing
    backend (ADR-006) is the first subclass to carry a code, and it needed no
    change here beyond passing one along -- which is the arrangement working.

    A lock error carries its category the same way and **splits on which one it
    is**. Neither carries an exit code of its own, unlike ``ConfigError``,
    because the right code depends on what the run had already done:

    * :class:`~sopuli.lock.errors.LockDeniedError` is exit 7. It is raised while
      acquiring, before anything is touched, which is exactly what exit 7 asserts
      -- ``03-json-output.md`` §6's recipe pairs 7 with 6 under "sopuli could not
      run".
    * :class:`~sopuli.lock.errors.LockStolenError` is **not** exit 7. It is found
      at a fence check, and that may be the check before a run's *second* target.
      Reporting "nothing ran" there is the one answer that would mislead a
      scheduler into skipping the repair. A command that knows what it applied
      finishes its own document on exit 4 and never reaches here; reaching here
      means nobody could say, so it is generic failure.

    A driver error carries its own too. Without that, every one would fall into the
    catch-all below and be reported as ``internal`` on exit 1 -- including
    :class:`~sopuli.driver.protocol.UnsupportedCapabilityError`, whose *distinct
    exit code* (invariant 4) would be 1 like everything else, with the hint folded
    into the message instead of the field it has.

    Anything else is ``internal`` on exit 1. This catch-all repeats what the text
    boundary already prints to stderr, and no more.
    """
    if isinstance(exc, ConfigError):
        return (
            ExitCode(exc.exit_code),
            Error(category=exc.category, message=exc.located, hint=exc.hint, code=exc.code),
        )
    if isinstance(exc, StoreError):
        # Same arrangement as ConfigError above: the exception carries its
        # category and its exit code, so a login failure reaches exit 6 (P5) and
        # a sealed store reaches generic failure without this function knowing
        # which is which. Without this branch, a store failure would land in
        # the catch-all below and exit 1 as `internal`, which would be a lie about
        # a failure the tool understands perfectly well.
        return ExitCode(exc.exit_code), Error(
            category=exc.category, message=exc.message, hint=exc.hint
        )
    if isinstance(exc, LockError):
        code = ExitCode.LOCK_HELD if isinstance(exc, LockDeniedError) else ExitCode.FAILURE
        return code, Error(category=exc.category, message=exc.message, hint=exc.hint)
    if isinstance(exc, DriverError):
        return ExitCode(exc.exit_code), Error(
            category=exc.category,
            message=exc.message,
            hint=exc.hint,
            code=exc.code,
            # Only the capability category has one, which is the schema's rule
            # for the field rather than this function's -- so it is read off the
            # exception that defines it rather than switched on `category`.
            target_capability=getattr(exc, "capability", None),
        )
    if isinstance(exc, click.ClickException):
        # click's own errors carry their exit code, and every one of them today
        # is a usage error -- which the caller then declines to emit. Reading the
        # code off the exception rather than assuming 2 keeps that true if click
        # ever raises something else.
        return ExitCode(exc.exit_code), Error(category="internal", message=exc.format_message())
    return (
        ExitCode.FAILURE,
        Error(category="internal", message=f"{type(exc).__name__}: {exc}"),
    )


def _cli_contributions(group: GlobalOptions, verb: GlobalOptions) -> list[tuple[str, Contribution]]:
    """The command line's answers, whichever of the two parsers caught them."""
    contributions = []

    output = _positioned(verb.output_mode, group.output_mode, flag="--output")
    if output is not None:
        contributions.append(("output", output))

    profile = _positioned(verb.profile_name, group.profile_name, flag="--profile")
    if profile is not None:
        contributions.append(("profile", profile))

    if verb.dry_run:
        # Trailing-only, so there is no position worth recording -- and no group
        # value to merge, because `trailing_only` refused it before it got here.
        contributions.append(("safety.dry_run", Contribution(Layer.CLI, True, "--dry-run")))
    return contributions


def _positioned(verb: str | None, group: str | None, *, flag: str) -> Contribution | None:
    """The verb's value, else the group's, tagged with where it was written."""
    if verb is not None:
        return Contribution(Layer.CLI, verb, f"{flag} ({VERB})")
    if group is not None:
        return Contribution(Layer.CLI, group, f"{flag} ({GROUP})")
    return None


def _first_path(verb: Path | None, group: Path | None) -> Path | None:
    """The same rule again, for the one global option that carries a path.

    ``--vault-token-file`` is not a setting, so it does not go through the
    resolver: §3a's token chain *is* its merge, and registering half of that
    chain here would leave the tool with two of them. It still accepts both
    parser positions, and settles them the way everything else does.
    """
    for value in (verb, group):
        if value is not None:
            return value
    return None


def _first_written(verb: str | None, group: str | None) -> str | None:
    """The same rule once more, for the one global option that carries a URL.

    ``--vault-addr`` is a setting -- layer 1 of ``vaults.*.addr`` -- but not one
    *this* resolver merges: a store's settings belong to the store, so the merge
    happens inside the file (:mod:`sopuli.config.vault_layers`). What is settled
    here is only which parser position wrote it.

    Distinct from :func:`_first_given`, which is colour's and falls back to
    ``auto``. Reusing that one here made an unwritten flag arrive as the string
    ``"auto"``, which then refused every run that had no default store -- found
    by the suite rather than by reading, because the two signatures differ only
    in a return type mypy was happy with.
    """
    for value in (verb, group):
        if value is not None:
            return value
    return None


def _first_given(verb: str | None, group: str | None) -> str:
    """The same rule for an option that is not a resolved setting.

    ``--color`` is settled by :func:`sopuli.output.color.resolve_color`, which
    mixes in TTY detection and Windows VT mode -- neither of which is a precedence
    layer, which is why colour is not in the registry. It still accepts both
    positions, and it settles them with the rule the settings use rather than one
    of its own.
    """
    for value in (verb, group):
        if value is not None:
            return value
    return ColorChoice.AUTO.value

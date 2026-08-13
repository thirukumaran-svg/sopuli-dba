"""What one run was asked to do -- the command line and the environment, resolved.

This is the binding layer: click parameters and ``SOPULI_*`` variables in,
:class:`~sopuli.settings.resolver.Resolved` values out, with the provenance the
JSON contract's ``invocation.options`` needs. The merge rules themselves are not
here; they are in :mod:`sopuli.settings`, and this module's whole job is to feed
that one resolver rather than grow a second one beside it (#10).

**click parses in two stages, and both are layer 1.** The group's parser consumes
what it knows until the first non-option token -- the subcommand -- and hands the
rest to the subcommand's parser. Neither sees the other's options, so an option is
only accepted in the section belonging to the parser that declared it. Global
options are therefore declared *twice*, once on the group and once on every verb,
and both positions resolve as ``cli``: it is the same person, in the same command
line, at the same moment, so there is no authority to rank (P3, "Layer 1 is one
layer"). Position is recorded in ``source_detail`` and nowhere else.

**Except for the safety set, which is trailing-only.** ``--dry-run`` and the flags
that will follow it (``--confirm``, ``--max-targets``, ``--force`` if it ever
exists) are declared on the group as hidden *traps* that refuse rather than
resolve. Group position and verb position express identical intent for a safety
flag, so accepting both would buy typing tolerance and nothing else -- and it
would buy it at the price of a merge policy in the smallest, least visible layer
there is. :func:`trailing_only` gives the typing tolerance anyway, as a message
that says where the flag goes, and no group-position safety value ever reaches
the resolver. Invariant 10 cannot be violated here because there is nothing to
merge.

**Which position wins where both were given.** The verb's, for the inert options:
most specific wins, and nothing is at stake. ``--config`` is the exception in
shape rather than in rule -- it is a list that layers left to right (§9), so both
positions are *kept*, group first, exactly as repeating the flag would.
"""

from __future__ import annotations

import functools
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

import click

from sopuli.config.errors import ConfigError
from sopuli.output.color import ColorChoice
from sopuli.output.document import Option, RunDocument
from sopuli.output.emit import Emitter, OutputMode
from sopuli.settings import Contribution, Layer, Resolved, resolve_all
from sopuli.settings.sources import env_contributions

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
GLOBAL_PARAMS = ("config_paths", "output_mode", "color_choice", "dry_run")

#: The settings every run consults, whether or not any layer mentioned them.
#:
#: Resolution is per setting, and a setting nobody supplied still has an answer
#: when it has a built-in default -- ``output`` is ``text`` on a bare command
#: line. Listing them is what asks the resolver the question; a setting left off
#: this list is simply never asked, which is why it is short and explicit rather
#: than "everything in the registry". It grows as consumers arrive: the safety
#: block needs the config layer to reach it, and `profile` needs profile
#: activation to mean anything.
RESOLVED_SETTINGS = ("output", "safety.dry_run")


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
    dry_run: bool = False

    @classmethod
    def from_params(cls, params: Mapping[str, Any]) -> GlobalOptions:
        """Read whichever of :data:`GLOBAL_PARAMS` are present."""
        return cls(
            config_paths=tuple(params.get("config_paths") or ()),
            output_mode=params.get("output_mode"),
            color_choice=params.get("color_choice"),
            dry_run=bool(params.get("dry_run", False)),
        )


@dataclass(frozen=True)
class Invocation:
    """The resolved answer for one run.

    Handed to every verb in place of the raw click parameters. A verb that wants
    to know whether this is a dry run asks :attr:`dry_run`, and gets the
    resolver's answer -- ``SOPULI_DRY_RUN`` included.
    """

    config_paths: tuple[Path, ...] = ()
    color_choice: ColorChoice = ColorChoice.AUTO
    resolved: Mapping[str, Resolved] = field(default_factory=dict)

    @property
    def output_mode(self) -> OutputMode:
        return OutputMode(self.value("output"))

    @property
    def dry_run(self) -> bool:
        return bool(self.value("safety.dry_run"))

    def value(self, name: str) -> Any:
        """The effective value of a setting, or ``None`` if no layer supplied one."""
        answer = self.resolved.get(name)
        return None if answer is None else answer.value

    def emitter(self) -> Emitter:
        """The one emitter for this run (see :class:`~sopuli.output.emit.Emitter`)."""
        return Emitter(mode=self.output_mode, color_choice=self.color_choice)

    def start(self, command: str) -> RunDocument:
        """Open a run document carrying this invocation's own settings.

        ``options`` reports what *changed behaviour*, which is the schema's own
        wording: a setting answered by its built-in default changed nothing, and
        ``output: text [builtin]`` on every clean run would be noise in a
        document consumers diff. ``config show --explain`` (#53) shows those rows
        too -- a different view over the same resolver, not a second answer.
        """
        return RunDocument.start(
            command,
            dry_run=self.dry_run,
            options={
                name: Option(
                    value=answer.value,
                    source=str(answer.layer),
                    source_detail=answer.detail,
                )
                for name, answer in self.resolved.items()
                if answer.layer is not Layer.BUILTIN
            },
        )


def global_options(func: F) -> F:
    """Attach the global options to a **verb**, and hand it an :class:`Invocation`.

    One line per command; retrofitting it across twenty verbs would not be, which
    is why it is a decorator rather than something each verb remembers to do.
    ``tests/test_cli_precedence.py`` walks the command tree and fails if a verb is
    missing it.

    ``--dry-run`` is here from the start because invariant 8 requires every
    mutating command to support it. Nothing mutates yet, so it only reaches the
    run document -- but no future command has to remember to add the flag.
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


def resolve_invocation(
    group: GlobalOptions, verb: GlobalOptions, *, env: Mapping[str, str]
) -> Invocation:
    """Merge both parser positions with the environment, and resolve.

    Pure: the environment arrives as a mapping. The process supplies its own in
    :func:`_pass_invocation`, which is the only place it is read.
    """
    contributions: dict[str, list[Contribution]] = {name: [] for name in RESOLVED_SETTINGS}
    for name, supplied in env_contributions(env).items():
        _wired(contributions, name).extend(supplied)
    for name, contribution in _cli_contributions(group, verb):
        # The command line outranks the environment, and within one layer the
        # first contribution wins -- so the CLI's goes in front of whatever the
        # environment already put there.
        _wired(contributions, name).insert(0, contribution)

    return Invocation(
        # Left to right, group first: both positions are kept, because repeating
        # `--config` layers files rather than replacing them (§9).
        config_paths=(*group.config_paths, *verb.config_paths),
        color_choice=ColorChoice(_first_given(verb.color_choice, group.color_choice)),
        resolved=resolve_all(contributions),
    )


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


def check_output_mode(invocation: Invocation) -> None:
    """Refuse an output format the tool does not have, naming where it came from.

    ``--output`` is a ``click.Choice`` and click checks it; ``SOPULI_OUTPUT`` is
    checked by nothing, and an unknown value there would otherwise surface as a
    bare ``ValueError`` out of the enum three frames later. Naming the location is
    what makes it fixable -- the same variable can be inherited from a CI image
    nobody in the room chose. ``jsonl`` is the realistic case: it is in §6's table
    and not yet implemented (#9).
    """
    answer = invocation.resolved.get("output")
    if answer is None or answer.value in {mode.value for mode in OutputMode}:
        return
    raise ConfigError(
        f"{answer.location}: {answer.value!r} is not an output format",
        hint=f"this build has: {', '.join(mode.value for mode in OutputMode)}",
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
    return color(output(dry_run(config(func))))


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
        invocation = resolve_invocation(group, verb, env=os.environ)
        check_output_mode(invocation)
        kwargs[INVOCATION_PARAM] = invocation
        return ctx.invoke(func, **kwargs)

    # `update_wrapper` rather than the `@functools.wraps` decorator, so that mypy
    # still sees `wrapper` as the plain function `click.pass_context` wants. The
    # effect is the same, and it is what carries the verb's docstring into
    # `--help` and its signature into `inspect.signature` -- which is how
    # `tests/test_cli_precedence.py` can check that a verb really takes `run`.
    functools.update_wrapper(wrapper, func)
    return click.pass_context(wrapper)  # type: ignore[return-value]


def _cli_contributions(group: GlobalOptions, verb: GlobalOptions) -> list[tuple[str, Contribution]]:
    """The command line's answers, whichever of the two parsers caught them."""
    contributions = []

    output = _positioned(verb.output_mode, group.output_mode, flag="--output")
    if output is not None:
        contributions.append(("output", output))

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

"""What the safety settings refuse, and the exit code a refusal carries.

Invariant 10 says safety settings only ratchet toward safe, and
:mod:`sopuli.settings.registry` is what makes that true of *resolution*: no layer
can relax ``safety.readonly``, because the merge policy will not let it. What was
missing is the other half -- something that then acts on the resolved answer.
``sopuli lock break`` is the first mutating command, so it is the first consumer,
and the shape it settles here is the one every later one inherits.

**Exit 8, category ``policy``.** P5 reads exit 8 as "aborted by user /
confirmation declined", and ``readonly: true`` is the operator declining in
advance, in the file. The alternatives were both worse:

* Exit 9 says *your config file is wrong*, and this file is right. A scheduler
  branching on 9 to mean "go and fix the YAML" would be sent to look for a defect
  that is not there.
* Exit 5 says the target or the store cannot do what was asked, which is the
  refusal :class:`~sopuli.lock.errors.NoFenceError` makes. Folding the two
  together would lose the distinction between "this store cannot fence" and "you
  told me not to write", and those need opposite responses.

A :class:`~sopuli.config.errors.ConfigError` subclass, following
:class:`~sopuli.config.errors.ArgumentError`'s precedent: everything about the
reporting is already right -- the boundary exits with ``exc.exit_code`` and reads
``category`` off the exception rather than inferring one from its type -- and
what differs is exactly those two class attributes.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from sopuli.admin import UNATTENDED_SOURCES, NobodyToAskError, Prompter, auth_at, needs_prompt
from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.expansion import declared_at
from sopuli.config.model import Config, ExpandedTarget
from sopuli.config.selection import matches
from sopuli.exit_codes import ExitCode
from sopuli.plan import BlastRadius
from sopuli.settings.registry import Layer
from sopuli.settings.resolver import Contribution, Resolved, resolve
from sopuli.settings.sources import estate_contributions

#: The setting that refuses every mutation, wherever it was written.
READONLY = "safety.readonly"

#: The ceiling on how many targets one run may reach (P5).
MAX_TARGETS = "safety.max_targets"

#: The environments a mutation may not enter without an explicit yes (P5).
CONFIRM_ENVIRONMENTS = "safety.confirm_environments"

#: Which UC-2 delivery methods an estate permits (H6). Ratchets by
#: intersection, so a layer may only narrow the set.
ALLOWED_METHODS = "safety.delivery.allowed_methods"

#: How many readonly targets a refusal names before it stops listing them.
#:
#: A ceiling rather than a paragraph: the message exists so somebody can find the
#: key they have to edit, and the first few names do that as well as two hundred
#: would. The count is always exact, so nothing is hidden -- only abbreviated.
NAMED_TARGETS = 5


class RefusedError(ConfigError):
    """A safety setting stopped a mutating command before it did anything.

    Not a failure and not a bad file: the run did exactly what it was configured
    to do. The exit code is what says so, which is why this carries one of its
    own rather than letting the boundary guess from the type.
    """

    exit_code = ExitCode.ABORTED
    category = "policy"


@dataclass(frozen=True)
class ReadonlyTarget:
    """One target this run reaches whose ``safety:`` block refuses mutation."""

    #: The rendered target name -- what ``--target`` selects on.
    name: str
    #: The key that has to be edited, e.g. ``targets[0].safety.readonly``.
    location: str


def for_estate(resolved: Mapping[str, Resolved], config: Config) -> dict[str, Resolved]:
    """``resolved``, re-merged with the ``safety:`` blocks of the estate.

    Layer 4 of P3's table, asked at the only moment it can be answered. The
    invocation resolves at the boundary, before any selector has run, so a block
    on a target or a group cannot join it there. Without this re-merge,
    ``readonly`` on a target would parse, validate and appear in ``config show``
    and refuse nothing.

    ``config`` is the **already-selected** estate.
    :func:`~sopuli.settings.sources.estate_contributions` decides which of its
    targets count and why; this half is only the re-merge.

    **Through the same resolver, on the same contributions.** The prior layers
    are taken off :attr:`~sopuli.settings.resolver.Resolved.contributions` and
    handed back with the new ones, rather than the object layer being folded into
    an answer that has already been merged. Merging twice would report the winner
    of the first pass -- P3 says so about the ``vaults.*`` layers, in the same
    words, and it is the same mistake here: the location an operator has to go
    and edit is the lowest-authority contributor to the *final* value, which a
    two-stage merge cannot see.

    The built-in is dropped before re-merging because :func:`resolve` puts it
    back. Keeping it would make layer 6 a *contributor* rather than a fallback,
    which under a ratchet is the difference between a working one and a stuck one.

    A setting no layer supplied is absent from ``resolved`` and starts from
    nothing, and one no object wrote is returned untouched.
    """
    extra = estate_contributions(config)
    if not extra:
        return dict(resolved)
    merged = dict(resolved)
    for name, contributions in extra.items():
        prior = _prior(resolved.get(name))
        answer = resolve(name, [*prior, *contributions])
        if answer is not None:
            merged[name] = answer
    return merged


def _prior(answer: Resolved | None) -> tuple[Contribution, ...]:
    """The layers that already spoke, minus the built-in fallback."""
    if answer is None:
        return ()
    return tuple(one for one in answer.contributions if one.layer is not Layer.BUILTIN)


def readonly_targets(config: Config) -> tuple[ReadonlyTarget, ...]:
    """The targets in ``config`` that some ``safety:`` block marks ``readonly``.

    **Reported per target, whichever kind of block did the marking.** A group is
    a label match rather than a place a target is written, so a run refused by
    ``groups.prod-pdbs.safety.readonly`` has no key of its own to point at -- and
    pairing the target with the group's key is what makes the refusal actionable
    anyway: the operator learns both which database is protected and which line
    protects it. The alternative was a second message shape for the group case,
    which meant the same refusal read two ways depending on where somebody had
    written one word.

    **A target's own block wins where both mark it.** The two sit at the same
    layer, so §9's "ties resolve downward" has nothing to separate them; the
    target's is the more specific place and the one an operator looking at that
    target would find first.

    In estate order, so two runs over one file name them in the same order.
    """
    reached = {binding.target for binding in config.bindings}
    marked = []
    for expanded in config.expanded_targets:
        if expanded.name not in reached:
            continue
        location = _readonly_at(expanded, config)
        if location is not None:
            marked.append(ReadonlyTarget(name=expanded.name, location=location))
    return tuple(marked)


def _readonly_at(expanded: ExpandedTarget, config: Config) -> str | None:
    """The key that marks this target ``readonly``, or ``None`` if none does.

    The template's block is consulted **before** the flattened one, because a
    patch that tried to relax it lost the ratchet and the line that holds is the
    template's. Reading only the flattened value would
    drop the target out of the message entirely while the refusal still fired --
    the right refusal with a worse message, which is the failure that is hardest
    to notice.
    """
    if expanded.template_safety is not None and expanded.template_safety.readonly:
        return f"target_sets.{expanded.target_set}.safety.readonly"
    if expanded.target.safety is not None and expanded.target.safety.readonly:
        return str(declared_at(expanded, "safety").key("readonly"))
    for group in config.groups:
        if (
            group.safety is not None
            and group.safety.readonly
            and matches(expanded.target, group.match)
        ):
            return f"groups.{group.name}.safety.readonly"
    return None


def refuse_if_readonly(
    resolved: Mapping[str, Resolved], *, action: str, estate: Config | None = None
) -> None:
    """Stop a mutating command when any layer asked for ``readonly``.

    ``action`` is what would have happened, in words, because "refused by
    readonly" without it leaves the operator to work out which part of their
    command was the mutation.

    The message names **where the setting came from** rather than only that it is
    set. A ``readonly: true`` an operator did not know about is the whole reason
    this refusal is confusing when it arrives, and
    :attr:`~sopuli.settings.resolver.Resolved.location` is already the answer --
    the profile, the object, or ``defaults``.

    **This refuses a ``--dry-run`` too**, which is not obviously right and is
    deliberate. A dry run of a mutating verb writes nothing, so the strict reading
    would allow it; the rule that is worth having is the simple one -- under
    ``readonly`` the mutating verbs are unavailable, and the read-only verb is how
    you ask. For a lock that verb is ``sopuli lock status``, which answers the
    same question and takes no lock doing it.

    **``estate`` is the selected config, and giving it changes only the message**.
    Every verb asks this twice: once on the invocation, before a selector
    has been validated, and again on the estate the selection produced, against a
    ``resolved`` that :func:`for_estate` has re-merged. The second call is where a
    target's or a group's block can refuse at all, and the message it wants is a
    different one -- *these* targets, and the key on each. Asking twice rather
    than moving the gate is what keeps a ``defaults``-level ``readonly`` refusing
    before a bad ``--target`` is judged: exit 8 for a run that was never going to
    write, rather than exit 2 for a typo in it.

    **Refusing the whole run is the decision, not skipping the readonly targets**
    (decision #424). Skipping would make ``readonly`` mean two different things
    depending on where it was written -- a refusal under ``defaults``, a filter on
    a target -- and it does not generalise: there is no per-target reading of
    ``max_targets`` that skips its way under a ceiling, and a ``safety:`` block is
    resolved as a unit. So the run stops, and the message names a narrowing
    instead, because a selector is the mechanism the tool already has for
    "operate on less than this".
    """
    answer = resolved.get(READONLY)
    if answer is None or not answer.value:
        return
    marked = readonly_targets(estate) if estate is not None else ()
    if marked and estate is not None:
        reached = len({binding.target for binding in estate.bindings})
        raise RefusedError(
            _marked_message(marked, estate, action=action),
            hint=_marked_hint(marked, escapable=len(marked) < reached),
        )
    raise RefusedError(
        f"{action} is a mutation, and `{READONLY}` is set",
        hint=(
            f"set at {answer.location}; no layer can relax it (invariant 10) -- "
            f"`sopuli lock status` reads without writing"
        ),
    )


def _marked_message(marked: tuple[ReadonlyTarget, ...], estate: Config, *, action: str) -> str:
    """The first line of a refusal a target's own block caused.

    Says how much of the run is refused as well as that it is, because those are
    two different situations and the operator's next move differs: some of the
    plan is reachable by narrowing, and none of it is not.
    """
    reached = len({binding.target for binding in estate.bindings})
    if len(marked) < reached:
        scope = f"{len(marked)} of the {reached} targets it reaches"
    elif reached == 1:
        scope = "the target it reaches"
    else:
        scope = "every target it reaches"
    return f"{action} is a mutation, and `{READONLY}` is set on {scope}"


def _marked_hint(marked: tuple[ReadonlyTarget, ...], *, escapable: bool) -> str:
    """Where each readonly target was marked, and what to do about it.

    ``escapable`` is whether any of the plan survives a narrowing. Where it does,
    a selector is the answer and the message says which ones exist -- narrowing is
    the mechanism the tool already has for "operate on less than this", and the
    refusal (decision #424) is there so that the operator makes that
    call rather than the tool making it silently. Where it does not, saying
    "narrow the run" would be advice that cannot work, so the message says so and
    names the verbs that read instead.
    """
    named = _named([f"{one.name} ({one.location})" for one in marked])
    them = "it" if len(marked) == 1 else "them"
    reads = "read instead with `sopuli creds check` or `sopuli creds status`"
    escape = (
        f"narrow the run with --target, --group or --select so it does not reach {them}, or {reads}"
        if escapable
        else f"no narrowing of this run can avoid {them}, so {reads}"
    )
    return f"readonly: {named}; no layer can relax it (invariant 10) -- {escape}"


def _named(items: Sequence[str]) -> str:
    """``items`` joined, cut at :data:`NAMED_TARGETS` with a count of the rest."""
    named = ", ".join(items[:NAMED_TARGETS])
    if len(items) > NAMED_TARGETS:
        named += f", and {len(items) - NAMED_TARGETS} more"
    return named


def refuse_if_over_limit(
    resolved: Mapping[str, Resolved], radius: BlastRadius, *, action: str
) -> None:
    """Stop a run that reaches more targets than any layer allowed.

    This is the check behind P5's "prevents a wildcard from hitting 200 PDBs by
    accident".

    **There is no `--limit` or `--max-targets` flag.** ``Setting.layers`` does not
    include ``Layer.CLI`` for this setting, so the resolver would refuse the flag
    (decision #392).

    **Counts targets, not units.** :class:`~sopuli.plan.BlastRadius` says why: six
    accounts in one PDB is one target's worth of reach, and refusing it under
    `max_targets: 1` would refuse a run the setting was never aimed at. The name
    of the setting is also the name of the thing it counts, which is worth keeping
    true.

    **An unset `max_targets` is no ceiling**, not a ceiling of one. The registry
    gives it no built-in on purpose -- "an unset max_targets is no limit, which is
    not the same claim as a default limit the tool chose" -- and inventing one here
    would put that default somewhere a reviewer reading the registry would not find
    it.

    P5's struck-through "default 1" is about *confirmation*, not about this ceiling,
    and **C17 declined that trigger**: a threshold that prompted on every
    multi-target mutation would fire on estates that configured nothing, and a
    ceiling is not a confirmation threshold in the first place. So this function is
    the only consumer `max_targets` has and the only one it is going to get -- which
    is worth knowing before reading the absent built-in as an oversight.
    Confirmation is `confirm_environments` and nothing else
    (:func:`confirmation_demanded`).

    **Refuses a `--dry-run` too**, for :func:`refuse_if_readonly`'s reason and one
    more of its own: the plan is what the operator is being shown, and showing a
    200-target plan under a ceiling of 20 as though it were runnable is the
    surprise the ceiling exists to prevent.
    """
    answer = resolved.get(MAX_TARGETS)
    if answer is None or answer.value is None:
        return
    limit = int(answer.value)
    if radius.targets <= limit:
        return
    raise RefusedError(
        f"{action} would reach {radius.targets} targets, and `{MAX_TARGETS}` is {limit}",
        hint=(
            f"set at {answer.location}; no layer can raise it (invariant 10) -- "
            f"narrow the run with --select, --target or --group, or raise the "
            f"ceiling where it is written"
        ),
    )


def refuse_if_nobody_to_ask(
    targets: Sequence[ExpandedTarget], prompt: Prompter | None, *, action: str
) -> None:
    """Stop a mutating command that would ask for a password nobody can type.

    ``prompt`` is ``None`` when stdin is not a terminal
    (:func:`~sopuli.invocation.terminal_prompter`). A target with
    ``auth: prompt`` then cannot be reached, and every run that reaches it fails
    on it. Invariant 4 says such a run says so before it touches anything, so
    this asks :func:`~sopuli.admin.needs_prompt` over the selected targets
    first. Without it, a run would change the targets it can reach and then fail
    on the one it cannot, and a rollover left half applied is one that cannot be
    promoted (invariant 7).

    **Only the mutating verbs call this** (decision #481). A verb that only reads,
    such as ``doctor`` or ``creds check``, keeps going past a target it cannot
    reach and reports it, because one target nobody can reach must not hide what
    the others say.

    **``targets`` is every target the run may connect to**, judged from the
    config before any vault document is read, and the caller decides it. That
    is more than the run will always reach: a ``creds`` verb skips an account
    with nothing staged or nothing due, and only the vault says which those are.
    A run that needs a password on some days and not on others is not one a
    scheduler can rely on, so it is refused every time, and the operator narrows
    it.

    A ``--dry-run`` whose preview connects is refused like the real run, before
    the plan is printed, as the ``readonly`` and ``max_targets`` refusals are.
    ``creds apply --dry-run`` with no ``--preflight`` and no ``--strategy`` reads
    only the vault, so its caller passes no targets and it still prints its plan.

    The refusal points at each target's ``admin.auth`` key, because that is the
    line to edit for a run that has to go unattended. One target's key is the
    error's location; several are each named with theirs.
    """
    if prompt is not None:
        return
    asking = [target for target in targets if needs_prompt(target)]
    if not asking:
        return
    if len(asking) == 1:
        message = (
            f"{action} reaches target {asking[0].name!r}, which asks for its admin "
            f"password interactively, and there is nobody here to ask"
        )
        at = auth_at(asking[0])
    else:
        named = _named([f"{one.name} ({auth_at(one)})" for one in asking])
        message = (
            f"{action} reaches {len(asking)} targets that ask for their admin passwords "
            f"interactively, and there is nobody here to ask: {named}"
        )
        at = ROOT
    them = "it" if len(asking) == 1 else "them"
    narrow = f"narrow the run so it does not reach {them}, " if len(asking) < len(targets) else ""
    raise NobodyToAskError(
        message,
        at=at,
        hint=f"nothing was changed; run it from a terminal, {narrow}or {UNATTENDED_SOURCES}",
    )


@dataclass(frozen=True)
class Confirmation:
    """Why this run needs an explicit yes before it may mutate anything.

    Returned rather than acted on, because the acting is I/O: a prompt is a
    terminal, and this module is the one place a safety answer can be decided
    without one. :mod:`sopuli.cli` turns this into a question, a refusal, or
    nothing at all.
    """

    #: The listed environments this run actually reaches, in estate order. The
    #: intersection and not the setting: an operator who wrote ``[prod, staging]``
    #: and is touching only staging should be asked about staging, and a message
    #: naming both would be telling them their run reaches prod.
    environments: tuple[str, ...]
    #: Where the setting was written, for the same reason every other refusal
    #: here carries it.
    location: str

    @property
    def named(self) -> str:
        """The environments as a phrase, for a prompt or a refusal."""
        return ", ".join(self.environments)


def confirmation_demanded(
    resolved: Mapping[str, Resolved], radius: BlastRadius
) -> Confirmation | None:
    """Whether ``safety.confirm_environments`` covers anything this run reaches.

    P5 says every mutating command supports ``--confirm`` and that confirmation
    is required in some circumstances; this is **all** of the circumstances. The
    setting ratchets as a union, and this function is what reads it.

    **There is no other trigger.** P5 asked for two more -- a built-in
    `prod` and a blast radius over ``max_targets`` -- and C17 declined both: the
    first is an unremovable floor under ``01-configuration.md`` §9's union
    ratchet, and the second would prompt on every multi-target mutation for an
    estate that wrote no safety block. So a ``None`` from here means *this run
    needs no assent*, full stop, rather than *this gate had nothing to say and
    another might*.

    **Matched against the environments the run reaches, not the estate's.**
    :class:`~sopuli.plan.BlastRadius` already carries them for this purpose --
    its own docstring names this setting -- so a run narrowed to dev by a
    selector is not asked about prod merely because prod is declared elsewhere in
    the file. That is what makes the setting usable: one that asked on every run
    would be turned off within a week.

    **A target with no ``environment:`` matches nothing.** ``environment`` is
    optional, and a `confirm_environments` entry matching the empty string would
    be a rule nobody wrote -- which is the reading `BlastRadius` already takes by
    contributing nothing for such a target rather than an empty string.

    **Comparison is exact**, not case-folded. ``environment`` is a declared label
    the file controls and §6 already refuses to let the environment be relabelled
    from an override, so two spellings of prod in one estate is a config problem
    to see rather than one to paper over here.

    ``None`` where the setting is unset, where it is empty, or where nothing this
    run reaches is listed -- the three of which are one answer: nobody asked to be
    asked.
    """
    answer = resolved.get(CONFIRM_ENVIRONMENTS)
    if answer is None or not answer.value:
        return None
    listed = frozenset(answer.value)
    matched = tuple(name for name in radius.environments if name in listed)
    if not matched:
        return None
    return Confirmation(environments=matched, location=answer.location)


def refuse_disallowed_method(resolved: Mapping[str, Resolved], method: str) -> None:
    """Stop a run whose delivery method no layer permits (H6).

    This is the consumer of the resolved set. A setting that is resolved,
    ratcheted and reported by `config show --explain` but read by nothing is
    marked with ``inert_reason``.

    **Unset is no constraint**, which is the intersection's first rule: an estate
    that wrote nothing has not thereby forbidden everything. The resolver returns
    ``None`` for a setting no layer supplied, and that is the ordinary case.

    **`--force` has nothing to say about it.** That flag waives
    ``02-oracle-privileges.md`` §4's *account* guardrails; this is a safety
    setting, and invariant 10's whole point is that no source can relax one. So
    the refusal takes no override parameter -- there is nothing for a caller to
    pass, which is the same reason `--force` is not in the settings registry.

    Exit 8 and category ``policy``, like every other refusal here: the file is
    right and the answer is no. A method that does not *exist* is a different
    thing and exits 5 (:class:`sopuli.reset.DeliveryUnavailableError`); this one
    exists and is forbidden.
    """
    answer = resolved.get(ALLOWED_METHODS)
    if answer is None or not answer.value:
        return
    permitted = tuple(answer.value)
    if method in permitted:
        return
    raise RefusedError(
        f"`delivery.method: {method}` is not permitted here; "
        f"`{ALLOWED_METHODS}` allows {', '.join(permitted)}",
        hint=(
            f"set at {answer.location}; no layer can widen it (invariant 10), and "
            f"--force does not reach a safety setting -- deliver by one of the permitted "
            f"methods, or change the set where it is written"
        ),
    )


def refuse_unconfirmed(demand: Confirmation, *, action: str, targets: int) -> None:
    """Stop a run that needs an explicit yes and has nobody to give one.

    The unattended half of the gate, and it is a refusal rather than a prompt
    that reads EOF for the reason :func:`sopuli.cli._confirm_break` gives: click
    would abort on the closed stdin and the operator would learn that it stopped
    without learning what to type instead.

    **Exit 8, like every other refusal here.** The file is not wrong and the run
    is not broken -- somebody wrote down that this environment is not entered
    without an explicit yes, and there was no yes. That is P5's reading of exit 8
    exactly, and it is the same code an operator declining the prompt produces,
    which is the point: a scheduler cannot tell whether a human said no or was
    never there, and does not need to.
    """
    reach = "1 target" if targets == 1 else f"{targets} targets"
    raise RefusedError(
        f"{action} reaches {reach} in `{demand.named}`, and "
        f"`{CONFIRM_ENVIRONMENTS}` covers "
        + ("that environment" if len(demand.environments) == 1 else "those environments"),
        hint=(
            f"set at {demand.location}; no layer can relax it (invariant 10) -- "
            f"pass --confirm to answer in advance, or --dry-run to see the plan "
            f"without touching anything"
        ),
    )

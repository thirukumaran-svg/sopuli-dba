"""What the safety settings refuse, and the exit code a refusal carries (#149).

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

from collections.abc import Mapping
from dataclasses import dataclass

from sopuli.config.errors import ConfigError
from sopuli.exit_codes import ExitCode
from sopuli.plan import BlastRadius
from sopuli.settings.resolver import Resolved

#: The setting that refuses every mutation, wherever it was written.
READONLY = "safety.readonly"

#: The ceiling on how many targets one run may reach (P5, #247).
MAX_TARGETS = "safety.max_targets"

#: The environments a mutation may not enter without an explicit yes (P5, #292).
CONFIRM_ENVIRONMENTS = "safety.confirm_environments"


class RefusedError(ConfigError):
    """A safety setting stopped a mutating command before it did anything.

    Not a failure and not a bad file: the run did exactly what it was configured
    to do. The exit code is what says so, which is why this carries one of its
    own rather than letting the boundary guess from the type.
    """

    exit_code = ExitCode.ABORTED
    category = "policy"


def refuse_if_readonly(resolved: Mapping[str, Resolved], *, action: str) -> None:
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
    """
    answer = resolved.get(READONLY)
    if answer is None or not answer.value:
        return
    raise RefusedError(
        f"{action} is a mutation, and `{READONLY}` is set",
        hint=(
            f"set at {answer.location}; no layer can relax it (invariant 10) -- "
            f"`sopuli lock status` reads without writing"
        ),
    )


def refuse_if_over_limit(
    resolved: Mapping[str, Resolved], radius: BlastRadius, *, action: str
) -> None:
    """Stop a run that reaches more targets than any layer allowed.

    P5's "prevents a wildcard from hitting 200 PDBs by accident", finally asked of
    something. The setting has been parsed since the config model was written and
    ratcheted since the resolver was, and until now nothing read the answer.

    **The bullet used to say `--limit`/`--max-targets`** and this docstring quoted
    it. #392 struck the flag from P5: ``Setting.layers`` does not include
    ``Layer.CLI`` for this setting, so the flag would be refused by the resolver
    rather than merely missing. The quotation is trimmed to the half that is still
    true.

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

    P5 did say "default 1", about *confirmation* rather than about this ceiling.
    #247 excluded that reading from its scope and wrote the tension down here,
    where it sat as an open question until **#294 decided the trigger away**: a
    threshold that prompted on every multi-target mutation would fire on estates
    that configured nothing, and a ceiling is not a confirmation threshold in the
    first place. So this function is the only consumer `max_targets` has and the
    only one it is going to get -- which is worth knowing before reading the
    absent built-in as an oversight. Confirmation is `confirm_environments` and
    nothing else (:func:`confirmation_demanded`).

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
    setting had been parsed, ratcheted as a union and read by nothing since the
    config model was written (#292), and this is its consumer.

    **There is no second trigger to come.** P5 asked for two more -- a built-in
    `prod` and a blast radius over ``max_targets`` -- and #294 declined both: the
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

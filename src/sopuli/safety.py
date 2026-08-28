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

from sopuli.config.errors import ConfigError
from sopuli.exit_codes import ExitCode
from sopuli.plan import BlastRadius
from sopuli.settings.resolver import Resolved

#: The setting that refuses every mutation, wherever it was written.
READONLY = "safety.readonly"

#: The ceiling on how many targets one run may reach (P5, #247).
MAX_TARGETS = "safety.max_targets"


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

    P5's "`--limit`/`--max-targets` prevents a wildcard from hitting 200 PDBs by
    accident", finally asked of something. The setting has been parsed since the
    config model was written and ratcheted since the resolver was, and until now
    nothing read the answer.

    **Counts targets, not units.** :class:`~sopuli.plan.BlastRadius` says why: six
    accounts in one PDB is one target's worth of reach, and refusing it under
    `max_targets: 1` would refuse a run the setting was never aimed at. The name
    of the setting is also the name of the thing it counts, which is worth keeping
    true.

    **An unset `max_targets` is no ceiling**, not a ceiling of one. The registry
    gives it no built-in on purpose -- "an unset max_targets is no limit, which is
    not the same claim as a default limit the tool chose" -- and inventing one here
    would put that default somewhere a reviewer reading the registry would not find
    it. P5 does say "default 1", but it says it about *confirmation*, which is a
    different gate and is not this one; wiring that up is #247's excluded scope,
    waiting on a profile's `confirm:` reaching the resolver.

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

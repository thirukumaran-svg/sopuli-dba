"""Merging the layers, and remembering where the answer came from.

One resolver, because there are three consumers and they must not disagree: the
merge rule itself, ``invocation.options`` in the run document
(``03-json-output.md``), and ``config show --resolved --explain`` (#53). A value
that arrives without provenance can serve the first and neither of the others,
so provenance is part of the result rather than something reconstructed later.

Pure by construction (``04-testing.md`` §4): every layer arrives as a
:class:`Contribution` the caller built. Nothing here reads ``os.environ``, opens
a file, or knows what click is.

Four rules are decisions rather than transcription of P3:

**The built-in default is a fallback, not a contributor.** If any other layer
spoke, layer 6 drops out before merging. Under :attr:`~sopuli.settings.registry.
MergePolicy.OVERRIDE` this changes nothing; under ``RATCHET`` it is the
difference between a working ratchet and a stuck one. A built-in ``confirm:
true`` that took part in the ratchet would make ``profiles.ci.confirm: false``
unreachable forever, which is not what P3 describes -- and "built-in default" in
``--explain`` means precisely *nothing else spoke*.

**Ratchet is one policy with four shapes**, three of them taken from the
setting's declared type rather than from a third policy name: ``bool`` ratchets
toward its safe value, ``int`` to the minimum, and a list to the union. §9 of
``01-configuration.md`` names exactly those three -- "lowest ``max_targets``,
union of ``confirm_environments``, ``readonly: true`` if any layer sets it".

**The fourth is declared**, because the type could not give it (H6, #453).
``safety.delivery.allowed_methods`` is a list that must *intersect*: each layer
may only narrow which delivery methods an estate may use, and no
higher-authority layer can restore one a lower layer removed.
``safety.confirm_environments`` is a list of strings as well and must still
union, so the shape travels on
:attr:`~sopuli.settings.registry.Setting.list_merge` rather than on
``isinstance``. Three rules come with it and none has a counterpart in the
union: **unset means no constraint** -- a setting nothing supplied resolves to
``None`` here, which is the same answer it already gives for an unset
``max_targets``, and never to the empty intersection; **disjoint layers are a
refusal** rather than an empty answer, raised from :func:`_safest` naming every
layer that spoke, because a configuration nothing can deliver under is one
nobody can have meant and picking a layer to honour would be choosing which
guard to ignore; and **there is no ``forbidden_methods``**, now or later.

The boolean shape reads its direction from
:attr:`~sopuli.settings.registry.Setting.safe_bool` rather than assuming ``true``
is safe. It held for every ratcheted boolean until ``locking.break_expired``
(#83), which grants permission rather than withholding it -- and a ratchet that
merged it with ``any`` would have advertised a guardrail while doing the
opposite of one.

**Ties resolve downward.** Where several layers supply the effective value -- two
of them saying ``readonly: true``, or three contributing to a union -- the
reported source is the *lowest-authority* one. If config says ``readonly: true``
and ``--force`` was passed, the answer to "why did this refuse to write" is the
config key; reporting ``cli`` because the command line is layer 1 would be
precisely backwards. It is also the actionable answer: dropping the flag changes
nothing, editing the key does.

**A relaxation that lost is reported, not swallowed.** :func:`ratchet_note` says
so in words, which is what turns a silent surprise into a self-explaining one.
P3 makes the same point about its own ``--explain`` example: a setting that was
requested and did not win is invisible in the result and obvious in that view.

A consequence worth recording: a ratcheted setting can have several contributing
sources while the reported one is the floor rather than the top. The full chain
stays on :attr:`Resolved.contributions` for a view that wants it. If it is ever
wanted in JSON it is a new optional field, not a change to ``source`` -- see
``03-json-output.md``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sopuli.config.errors import ROOT, ConfigError
from sopuli.settings.registry import Layer, ListMerge, MergePolicy, Setting, setting


@dataclass(frozen=True)
class Contribution:
    """One layer's answer for one setting.

    ``detail`` is a **location, never a value**: the flag as typed
    (``--dry-run``, ``-o``), the variable name (``SOPULI_OUTPUT``), the config key
    (``profiles.ci.safety.max_targets``). It exists so somebody can find the thing
    in their own command line or CI job definition, which is the same reason the
    config layer points at a key path rather than saying "config".

    Keeping it a location is also what puts it inside ``03-json-output.md`` §4's
    redaction rule for free: there is nowhere here for a value, so no code path
    can put a credential in one. No setting is secret-valued today -- #145 settled
    that the command line names a token's *location* (``--vault-token-file``) and
    never carries one -- and this holds whether or not that stays true.
    """

    layer: Layer
    value: Any
    detail: str | None = None

    @property
    def location(self) -> str:
        """How to refer to this contribution in a message.

        The layer's own name where there is no more specific location -- a
        built-in default has nowhere to point at, and "builtin" is the honest
        answer rather than a missing one.
        """
        return self.detail if self.detail is not None else str(self.layer)


@dataclass(frozen=True)
class Resolved:
    """The effective value of one setting, and where it came from."""

    setting: str
    value: Any
    #: The layer that *determined* the value. For a ratcheted setting this is
    #: the floor, not the highest layer present. See the module note.
    layer: Layer
    #: The winning contribution's location, or ``None`` for a built-in default.
    detail: str | None
    #: Every contribution that was considered, in authority order. Kept so
    #: ``--explain`` can show the loser as well as the winner.
    contributions: tuple[Contribution, ...] = ()
    #: The setting's declared boolean polarity, copied from the registry by
    #: :func:`resolve` rather than looked up here. A resolved value is a value
    #: object: renderers hold one, tests build one, and neither should need the
    #: registry to be able to ask it what it means. Irrelevant for every
    #: non-boolean setting, where :func:`_is_looser_than` never consults it.
    safe_bool: bool = True
    #: The setting's declared list shape, copied from the registry alongside
    #: :attr:`safe_bool` and for the same reason. ``None`` for everything that is
    #: not a ratcheted list, where nothing consults it.
    list_merge: ListMerge | None = None

    @property
    def location(self) -> str:
        """Where to go and edit this. See :attr:`Contribution.location`."""
        return self.detail if self.detail is not None else str(self.layer)

    @property
    def relaxations(self) -> tuple[Contribution, ...]:
        """Contributions that asked for something less safe and did not get it.

        Empty for everything except a ratcheted setting that was actually held
        back. A union never produces one: every layer's environments end up in
        the result, so nothing was defeated. **An intersection does**, which is
        the difference between the two list shapes made visible: a layer that
        allowed ``manual`` where another layer did not ask for less than it got,
        and ``--explain`` says so rather than leaving the operator to compare two
        blocks by eye.
        """
        return tuple(
            one
            for one in self.contributions
            if _is_looser_than(one.value, self.value, self.safe_bool, self.list_merge)
        )


def resolve(name: str, contributions: Iterable[Contribution] = ()) -> Resolved | None:
    """The effective value of ``name``, or ``None`` when no layer supplied one.

    ``None`` rather than a :class:`Resolved` holding ``None``: an unset
    ``safety.max_targets`` is not "unlimited by default", it is a guard nobody
    asked for, and ``invocation.options`` carries "every effective option that
    changed behaviour" -- which that is not.
    """
    definition = setting(name)
    candidates = [_checked(one, definition) for one in contributions]
    if definition.builtin is not None:
        candidates.append(Contribution(layer=Layer.BUILTIN, value=definition.builtin))

    # Stable, so several contributions from one layer keep the order the caller
    # gave them -- which is how a caller expresses "the target's own `safety:`
    # before its group's".
    candidates.sort(key=lambda one: one.layer.authority)
    candidates = _without_fallback(candidates)
    if not candidates:
        return None

    if definition.policy is MergePolicy.OVERRIDE:
        # The highest-authority layer wins outright. Several contributions from
        # one layer keep the caller's order, so the first of those wins too.
        winner, value = candidates[0], candidates[0].value
    else:
        value = _safest(candidates, definition)
        winner = _ratchet_winner(candidates, value, definition)

    return Resolved(
        setting=name,
        value=value,
        layer=winner.layer,
        detail=winner.detail,
        contributions=tuple(candidates),
        safe_bool=definition.safe_bool,
        list_merge=definition.list_merge,
    )


def resolve_all(
    contributions: Mapping[str, Sequence[Contribution]],
) -> dict[str, Resolved]:
    """Resolve several settings, dropping the ones no layer supplied.

    Keyed by setting name and ordered by it, so ``--explain`` and
    ``invocation.options`` print the same rows in the same order every run.
    """
    resolved = {}
    for name in sorted(contributions):
        one = resolve(name, contributions[name])
        if one is not None:
            resolved[name] = one
    return resolved


def ratchet_note(resolved: Resolved) -> str | None:
    """Why a layer's request did not take effect, or ``None`` if none was defeated.

    One sentence, naming both ends: what asked for what, and where the value that
    held actually lives. Only locations and safety values appear, never a secret
    -- no safety setting is secret-valued, and ``detail`` is a location by
    contract (see :class:`Contribution`).
    """
    relaxations = resolved.relaxations
    if not relaxations:
        return None
    # The highest-authority loser: the most surprising one, and usually the thing
    # the operator typed a moment ago.
    loser = relaxations[0]
    return (
        f"{loser.location} asked for {render_value(loser.value)}; "
        f"{resolved.setting} stays {render_value(resolved.value)} ({resolved.location}) "
        f"-- safety settings only ratchet toward safe"
    )


# ------------------------------------------------------------- the merging ---


def _without_fallback(candidates: list[Contribution]) -> list[Contribution]:
    """Drop layer 6 unless it is all there is. See the module note."""
    spoken = [one for one in candidates if one.layer is not Layer.BUILTIN]
    return spoken or candidates


def _ratchet_winner(
    candidates: list[Contribution], effective: Any, definition: Setting
) -> Contribution:
    """The lowest-authority contribution that produced the effective value.

    ``candidates`` is in authority order, so this is the last contributor rather
    than the first. See "ties resolve downward" in the module note.

    **An intersection asks a different question of each layer**, which is why the
    declared shape reaches this far rather than stopping at :func:`_safest`.
    Under a union every layer that named anything is part of the answer; under an
    intersection a layer that named a superset merely *permitted* it, and the one
    worth reporting is the layer that narrowed it -- which is the key an operator
    has to edit to get a method back.

    Two ways to have narrowed it, and both are needed. A layer that wrote the
    answer exactly determined it, which is the tie case the integer shape already
    has -- two layers writing the same list are both contributors, and "ties
    resolve downward" then picks the lower. A layer that wrote something wider
    can still have narrowed it jointly with another, because an intersection is
    often smaller than anything any single layer wrote: ``[a, b]`` against
    ``[b, c]`` leaves ``[b]``, which neither of them contains as its whole value.
    So the second test is asked of the set -- taking this layer away would have
    left a wider answer -- and a layer that passes neither test is one that only
    permitted what somebody else decided.
    """
    if definition.list_merge is ListMerge.INTERSECTION:
        narrowers = [
            one for index, one in enumerate(candidates) if _narrows(candidates, index, effective)
        ]
        return narrowers[-1] if narrowers else candidates[-1]
    contributors = [one for one in candidates if _contributes(one.value, effective)]
    # A ratchet always has at least one contributor: the effective value came
    # from somewhere. The fallback keeps the failure legible if that ever stops
    # being true rather than raising IndexError three frames away.
    return contributors[-1] if contributors else candidates[-1]


def _narrows(candidates: list[Contribution], index: int, effective: Any) -> bool:
    """Whether the contribution at ``index`` is part of why the answer is that
    narrow. See :func:`_ratchet_winner` for the two ways it can be.

    Removal is by position rather than by value: two layers may write the same
    list, and dropping "the one equal to this" would drop both.
    """
    if set(candidates[index].value) == set(effective):
        # As a set, because a layer writes the methods in whatever order it likes
        # and the answer comes back sorted.
        return True
    others = [one.value for position, one in enumerate(candidates) if position != index]
    return bool(_intersection(others) != effective)


def _safest(candidates: Sequence[Contribution], definition: Setting) -> Any:
    """The safest of several contributions to one setting. §9's four shapes.

    Takes the contributions rather than their values because one shape needs the
    locations: an empty intersection is a refusal, and a refusal that cannot name
    the layers it came from leaves an operator to find two blocks in a file by
    reading the whole thing.

    A boolean consults the setting's declared polarity. Where ``true`` is the
    safe value this is ``any`` -- one layer asking for ``readonly`` is enough.
    Where ``false`` is (``locking.break_expired``, #83) it is ``all``, which is
    the same sentence read the other way round: one layer withholding permission
    is enough.
    """
    values = [one.value for one in candidates]
    first = values[0]
    if isinstance(first, bool):
        return any(values) if definition.safe_bool else all(values)
    if isinstance(first, tuple):
        if definition.list_merge is ListMerge.INTERSECTION:
            return _narrowed(candidates, definition)
        return tuple(sorted({item for value in values for item in value}))
    if isinstance(first, int):
        return min(values)
    # A string setting is never ratcheted -- the registry refuses it -- so there
    # is no "safest string" to invent. Reaching here is a programming error.
    raise TypeError(f"no ratchet rule for {type(first).__name__}")


def _intersection(values: Sequence[Any]) -> tuple[str, ...]:
    """What every one of ``values`` allows, sorted.

    An empty sequence gives the empty tuple, and that is never an *answer*: a
    setting no layer supplied does not reach here at all, since :func:`resolve`
    returns ``None`` for it. "Unset means no constraint" is therefore a property
    of the whole merge rather than of this function, which is where it belongs --
    ``max_targets`` already reads the same way. Here the empty sequence only ever
    means "with this layer removed there would be nothing left to constrain
    anything", which is what :func:`_ratchet_winner` asks it.
    """
    if not values:
        return ()
    kept = set(values[0]).intersection(*(set(value) for value in values[1:]))
    return tuple(sorted(kept))


def _narrowed(candidates: Sequence[Contribution], definition: Setting) -> tuple[str, ...]:
    """The intersection of every layer, or a refusal where it is empty.

    **A refusal rather than an empty answer**, and it lives here rather than in a
    verb for the same reason the merge does: every path that resolves this
    setting comes through one function, so the check cannot be the one a later
    consumer forgets to make. That covers :func:`sopuli.safety.for_estate` for
    free, where a target's or a group's ``safety:`` block can make two layers
    disjoint that were not disjoint at the boundary.

    **Exit 9 rather than the 8 the other safety refusals carry**
    (:class:`sopuli.safety.RefusedError`). Those stop a run that a correct file
    forbids -- the configuration is right and the answer is no. This is a set of
    layers that cannot all be honoured at once, under which no run could ever
    deliver anything, and *the file is wrong* is the honest report. It follows
    :data:`sopuli.settings.sources.REFUSED_VARIABLES`, the one other user-facing
    refusal this package makes.

    The message names every layer that spoke and what each allowed, because an
    empty intersection is never one block's doing.
    """
    kept = _intersection([one.value for one in candidates])
    if kept:
        return kept
    written = "; ".join(f"{one.location} allows {render_value(one.value)}" for one in candidates)
    raise ConfigError(
        f"`{definition.name}` resolves to nothing: {written}",
        at=ROOT,
        hint=(
            "these layers have no method in common, so nothing could be delivered under "
            "all of them -- widen one, or delete it; the setting only ever narrows, so a "
            "layer meant to impose nothing is a layer that should not be written"
        ),
    )


def _contributes(value: Any, effective: Any) -> bool:
    """Whether ``value`` is part of why the answer is ``effective``.

    Not asked of an intersection, which needs the whole set rather than one
    value -- see :func:`_ratchet_winner`.
    """
    if isinstance(effective, tuple):
        # Everything in a union contributes, except a layer that named nothing --
        # and if nobody named anything, they all agreed on the empty answer.
        return bool(value) or not effective
    return bool(value == effective)


def _is_looser_than(
    value: Any, effective: Any, safe_bool: bool, list_merge: ListMerge | None = None
) -> bool:
    """Whether ``value`` asked for something less safe than ``effective``.

    A union has no losers: every layer's entries are in the result. Booleans and
    integers do -- ``readonly: false`` against a ``true`` that held, or a profile
    asking for 200 targets where another layer said 1.

    **An intersection has losers too**, which is the one thing the two list
    shapes do not share. A layer allowing ``[manual, vault_wrapped]`` against one
    allowing ``[vault_wrapped]`` asked for a method it did not get, and that is
    exactly the row ``--explain`` exists to print. A proper superset of the
    answer is the test, so a layer that wrote the answer itself is not reported
    as defeated -- and nothing can write less than the answer, an intersection
    being a subset of every layer by construction.

    For a boolean the loser is whoever asked for the *unsafe* value and did not
    get it, which is the setting's polarity rather than "asked for false". With
    ``locking.break_expired`` the defeated request is a ``true``.
    """
    if isinstance(effective, bool):
        return value != effective and bool(value) is not safe_bool
    if isinstance(effective, tuple):
        return list_merge is ListMerge.INTERSECTION and set(value) > set(effective)
    if not isinstance(effective, int):
        return False
    return bool(value > effective)


def _checked(contribution: Contribution, definition: Setting) -> Contribution:
    """Refuse a contribution the registry does not allow.

    Both checks are programming errors rather than user errors, so they raise
    plain exceptions: a config file cannot express "supply ``output`` from a
    target", only code can.
    """
    if contribution.layer not in definition.layers:
        allowed = ", ".join(sorted(str(one) for one in definition.layers))
        raise ValueError(
            f"{definition.name!r} cannot be supplied by layer "
            f"{contribution.layer!r}; declared layers: {allowed}"
        )
    if not definition.accepts(contribution.value):
        raise TypeError(
            f"{definition.name!r} is {definition.type.__name__}, but "
            f"{contribution.location} supplied {type(contribution.value).__name__}"
        )
    return contribution


def render_value(value: Any) -> str:
    """A value as any view should show it.

    Lower-case booleans because that is how the config file writes them, and a
    reader told ``readonly: True`` would go looking for a capital letter in their
    own YAML.

    Public because ``config show --explain`` renders the same values in a table
    and a ratchet note can appear under one of its rows: two spellings of one
    value, three lines apart, would be a defect the reader has to resolve.

    A :class:`~sopuli.secrets.Secret` renders ``***`` here for free, since that
    is what its ``__str__`` does (invariant 2) -- this function does not know
    secrets exist, and that is what keeps it from forgetting one.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, tuple):
        return ", ".join(value) if value else "nothing"
    return str(value)

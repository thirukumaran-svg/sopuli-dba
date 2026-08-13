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

**Ratchet is one policy with three shapes**, taken from the setting's declared
type rather than from a third policy name: ``bool`` ratchets to true, ``int`` to
the minimum, and a list to the union. §9 of ``01-configuration.md`` names exactly
those three -- "lowest ``max_targets``, union of ``confirm_environments``,
``readonly: true`` if any layer sets it".

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

from sopuli.settings.registry import Layer, MergePolicy, Setting, setting


@dataclass(frozen=True)
class Contribution:
    """One layer's answer for one setting.

    ``detail`` is a **location, never a value**: the flag as typed
    (``--dry-run``, ``-o``), the variable name (``SOPULI_OUTPUT``), the config key
    (``profiles.ci.safety.max_targets``). It exists so somebody can find the thing
    in their own command line or CI job definition, which is the same reason the
    config layer points at a key path rather than saying "config".

    Keeping it a location is also what puts it inside ``03-json-output.md`` §4's
    redaction rule for free: ``--vault-token`` names the flag, and no code path
    puts a token here at all.
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

    @property
    def location(self) -> str:
        """Where to go and edit this. See :attr:`Contribution.location`."""
        return self.detail if self.detail is not None else str(self.layer)

    @property
    def relaxations(self) -> tuple[Contribution, ...]:
        """Contributions that asked for something less safe and did not get it.

        Empty for everything except a ratcheted setting that was actually held
        back. A union never produces one: every layer's environments end up in
        the result, so nothing was defeated.
        """
        return tuple(one for one in self.contributions if _is_looser_than(one.value, self.value))


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
        value = _safest([one.value for one in candidates])
        winner = _ratchet_winner(candidates, value)

    return Resolved(
        setting=name,
        value=value,
        layer=winner.layer,
        detail=winner.detail,
        contributions=tuple(candidates),
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


def _ratchet_winner(candidates: list[Contribution], effective: Any) -> Contribution:
    """The lowest-authority contribution that produced the effective value.

    ``candidates`` is in authority order, so this is the last contributor rather
    than the first. See "ties resolve downward" in the module note.
    """
    contributors = [one for one in candidates if _contributes(one.value, effective)]
    # A ratchet always has at least one contributor: the effective value came
    # from somewhere. The fallback keeps the failure legible if that ever stops
    # being true rather than raising IndexError three frames away.
    return contributors[-1] if contributors else candidates[-1]


def _safest(values: Sequence[Any]) -> Any:
    """The safest of several values of one type. §9's three shapes."""
    first = values[0]
    if isinstance(first, bool):
        return any(values)
    if isinstance(first, tuple):
        return tuple(sorted({item for value in values for item in value}))
    if isinstance(first, int):
        return min(values)
    # A string setting is never ratcheted -- the registry refuses it -- so there
    # is no "safest string" to invent. Reaching here is a programming error.
    raise TypeError(f"no ratchet rule for {type(first).__name__}")


def _contributes(value: Any, effective: Any) -> bool:
    """Whether ``value`` is part of why the answer is ``effective``."""
    if isinstance(effective, tuple):
        # Everything in a union contributes, except a layer that named nothing --
        # and if nobody named anything, they all agreed on the empty answer.
        return bool(value) or not effective
    return bool(value == effective)


def _is_looser_than(value: Any, effective: Any) -> bool:
    """Whether ``value`` asked for something less safe than ``effective``.

    A union has no losers: every layer's entries are in the result. Booleans and
    integers do -- ``readonly: false`` against a ``true`` that held, or a profile
    asking for 200 targets where another layer said 1.
    """
    if isinstance(effective, bool):
        return effective and not value
    if isinstance(effective, tuple) or not isinstance(effective, int):
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

"""What a setting is, and which of them exist.

P3 defines one precedence chain and invariant 10 says safety settings only
ratchet toward safe. Both rules are about *settings* rather than about command
line options, and the distinction is the whole reason this module exists.

`readonly` has no flag at all. `verify.method` arrives from a profile block.
`--dry-run` will eventually have a flag *and* an environment variable. A resolver
keyed on click options would leave half the things needing a merge policy with
nowhere to declare one. So the unit is a setting -- ``safety.dry_run``,
``output`` -- with an entry declaring its type, which layers may supply it, and
how colliding layers merge. Flags, ``SOPULI_*`` variables and config keys all
bind to setting *names*; the same registry is what ``invocation.options`` and
``config show --resolved --explain`` (#53) iterate over.

Three things here are decisions rather than transcription:

**:data:`SAFETY_SETTINGS` is a literal, and it is authoritative.** Invariant 10
wants one place a reviewer can look to see the whole ratcheted set, which a
comprehension over the registry would not be. :class:`Setting` still requires
``policy`` explicitly -- the failure mode is not a wrong policy, it is a new
setting silently inheriting ``override`` -- and :meth:`Setting.__post_init__`
refuses any disagreement between the two, in either direction. So the frozenset
cannot drift from the registry, and neither can be edited alone.

**Two policies, not three.** ``relax-but-bounded`` was considered for ``--force``
and is not needed, now that P3 has decided what the flag is (#89): it overrides
the *account* guardrails in ``02-oracle-privileges.md`` §4, never a safety
setting, so it is not a setting at all and has nothing here to merge. Because
``policy`` is a required declared field, adding a third policy later stays
additive rather than a migration.

**Ratcheted booleans carry a direction.** "Safest" meant ``any()`` while every
ratcheted boolean refused *more* when true. ``locking.break_expired`` (#83) is
the first that refuses *less*, and reading it with the same rule would have made
the setting unreachable and — worse — made it look like a guardrail while being
the opposite. So :attr:`Setting.safe_bool` says which value is the safe one, per
setting, declared rather than inferred from the name.

**:attr:`Setting.layers` is enforced.** A contribution from a layer a setting
does not declare raises rather than being merged. ``output`` has no meaning on a
target and ``safety.max_targets`` has no business arriving from an environment
variable; a resolver that silently accepted either would make the precedence
table a description of intent rather than of behaviour.

Two settings that look like they belong here and do not:

* ``--color`` -- :func:`sopuli.output.color.resolve_color` owns it, and mixes in
  TTY detection and Windows VT-mode probing, which are not precedence layers.
* ``--config`` -- P3's five-step first-match *file discovery* is a different
  chain, implemented in :mod:`sopuli.config.discovery`.
* ``--force`` -- decided in #89, and deliberately absent. It overrides the
  account guardrails of ``02-oracle-privileges.md`` §4 (checks 2--5), which are
  not settings and have no precedence chain: they are asked of one account at one
  moment. Keeping it out of the registry is what makes invariant 10 structural
  rather than remembered -- a flag that is not a setting cannot relax
  ``safety.readonly`` or ``safety.max_targets``, because there is no layer for it
  to arrive on. If it is ever added here, that argument is gone.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any


class Layer(StrEnum):
    """A precedence layer, in P3's order -- highest authority first.

    Declaration order *is* the authority order: :mod:`sopuli.settings.resolver`
    sorts by it rather than by a separate rank table that could disagree.

    The values are exactly the ``source`` enum published in
    ``docs/schemas/sopuli-run-1.8.schema.json``, so a resolved setting can be
    serialised into ``invocation.options`` without a translation step -- and
    ``tests/settings/test_registry.py`` reads the schema to keep it that way.

    There is deliberately no ``cli_group`` / ``cli_verb`` split. A precedence
    layer encodes authority: who expressed more specific or more current intent.
    Group position and verb position are the same person, in the same command
    line, at the same moment. Splitting them would push an artefact of click's
    two-stage parser into an interface that scripts branch on. Position is
    recorded in ``source_detail`` instead.
    """

    CLI = "cli"
    ENV = "env"
    ENV_THIRDPARTY = "env_thirdparty"
    PROFILE = "profile"
    OBJECT = "object"
    DEFAULTS = "defaults"
    BUILTIN = "builtin"

    @property
    def authority(self) -> int:
        """Position in the chain. Lower is higher authority."""
        return LAYER_ORDER[self]


#: Authority by layer, derived from declaration order so there is no second
#: ordering to keep in agreement with the first.
LAYER_ORDER = MappingProxyType({layer: rank for rank, layer in enumerate(Layer)})


class MergePolicy(StrEnum):
    """How a setting resolves when more than one layer supplies it."""

    OVERRIDE = "override"
    """The highest-authority layer wins. The ordinary case; nothing is at stake."""

    RATCHET = "ratchet"
    """The *safest* layer wins, whichever it is. Invariant 10."""


#: The settings invariant 10 governs. One glance, one list.
#:
#: A name here may only be declared :attr:`MergePolicy.RATCHET`, and a name not
#: here may only be declared :attr:`MergePolicy.OVERRIDE`. Adding ``--skip-verify``
#: next year means adding a line here, and the generic invariant test in
#: ``tests/settings/test_ratchet.py`` covers it from that moment without anyone
#: writing a test for it.
SAFETY_SETTINGS = frozenset(
    {
        "safety.dry_run",
        "safety.readonly",
        "safety.max_targets",
        "safety.confirm_environments",
        "locking.break_expired",
    }
)

#: The types a setting may hold, and what "safest" means for each. ``tuple`` is
#: the list shape -- ``confirm_environments`` -- kept immutable for the same
#: reason the config model is (see :mod:`sopuli.config.model`).
SETTING_TYPES = (bool, int, str, tuple)


@dataclass(frozen=True)
class Setting:
    """One resolvable setting.

    ``builtin`` is the layer-6 default and is *optional* in the sense that
    ``None`` means the tool has none: ``safety.max_targets`` unset is not
    "unlimited by default", it is a guard nobody asked for. Distinguishing the
    two is what lets ``config show --explain`` print "built-in default" for one
    and nothing at all for the other.
    """

    name: str
    type: type
    #: Which layers may supply this. Enforced -- see the module note.
    layers: frozenset[Layer]
    #: Required, with no default. A new setting must state its merge policy
    #: rather than inherit one by omission.
    policy: MergePolicy
    #: Layer 6, or ``None`` where the tool has no built-in answer.
    builtin: Any = None
    #: For a ratcheted **boolean**, which of the two values is the safe one.
    #:
    #: ``True`` for almost everything: ``readonly``, ``dry_run`` and a confirm
    #: flag all refuse *more* when set, so a layer asking for ``true`` may always
    #: have it. ``locking.break_expired`` (#83) is the first that inverts --
    #: permission to break a lock nobody is watching refuses *less* -- so there
    #: the layer saying ``false`` is the one that must win.
    #:
    #: Declared rather than inferred from the name. A ratchet that reads its
    #: direction out of a string is a ratchet that silently flips when somebody
    #: renames a setting, and the failure mode is a guardrail that stops holding
    #: while every test still passes.
    safe_bool: bool = True

    def __post_init__(self) -> None:
        if self.type not in SETTING_TYPES:
            raise ValueError(
                f"setting {self.name!r} has unsupported type {self.type.__name__}; "
                f"supported: {', '.join(one.__name__ for one in SETTING_TYPES)}"
            )
        if not self.layers:
            raise ValueError(f"setting {self.name!r} declares no layers; nothing could supply it")
        ratchet = self.policy is MergePolicy.RATCHET
        safety = self.name in SAFETY_SETTINGS
        if safety and not ratchet:
            raise ValueError(
                f"{self.name!r} is in SAFETY_SETTINGS and must be MergePolicy.RATCHET "
                f"(invariant 10: safety settings only ratchet toward safe)"
            )
        if ratchet and not safety:
            raise ValueError(
                f"{self.name!r} is declared MergePolicy.RATCHET but is not in "
                f"SAFETY_SETTINGS; add it there, so the ratcheted set stays readable "
                f"in one place"
            )
        if self.builtin is not None and not self.accepts(self.builtin):
            raise ValueError(
                f"built-in default for {self.name!r} is {type(self.builtin).__name__}, "
                f"not {self.type.__name__}"
            )
        if not self.safe_bool and not (ratchet and self.type is bool):
            # An inverted polarity on anything else is a statement with no
            # meaning: OVERRIDE never consults it, and "the safe int" is
            # `min` by §9 rather than a direction somebody may choose.
            raise ValueError(
                f"{self.name!r} declares safe_bool=False but is not a ratcheted bool; "
                f"polarity only means anything for a ratcheted boolean"
            )

    @property
    def is_safety(self) -> bool:
        """Whether invariant 10 governs this setting."""
        return self.name in SAFETY_SETTINGS

    def accepts(self, value: Any) -> bool:
        """Whether ``value`` is of this setting's declared type.

        ``isinstance`` with the bool/int trap closed: ``isinstance(True, int)``
        is true in Python, so an unguarded check would let ``max_targets: true``
        through and then ratchet a boolean against a number.

        One rule with two callers -- the built-in default above, and every
        contribution the resolver is handed. A second copy of it would be a
        second place for the trap to reopen, which is how the built-in check
        came to have it in the first place.
        """
        if self.type is tuple:
            # A list setting is a list *of strings*: the config layer only ever
            # produces those, and a tuple of anything else would union its way
            # into output nobody can render.
            return isinstance(value, tuple) and all(isinstance(item, str) for item in value)
        if self.type is int and isinstance(value, bool):
            return False
        return isinstance(value, self.type)


def _setting(
    name: str,
    *,
    type: type,  # noqa: A002 - the field is called `type`; shadowing it here is the honest name
    layers: tuple[Layer, ...],
    policy: MergePolicy,
    builtin: Any = None,
    safe_bool: bool = True,
) -> Setting:
    return Setting(
        name=name,
        type=type,
        layers=frozenset(layers),
        policy=policy,
        builtin=builtin,
        safe_bool=safe_bool,
    )


#: Every setting the resolver knows about.
#:
#: Deliberately only what has a producer today plus the safety block, which
#: :mod:`sopuli.config.safety` already parses and which is the reason the ratchet
#: exists at all. Entries for settings nothing reads yet -- ``vault.addr``,
#: ``verify.method``, the ``db`` timeouts -- would be a contract stated in a place
#: no test can mean anything about; they arrive with their consumers.
SETTINGS: MappingProxyType[str, Setting] = MappingProxyType(
    {
        setting.name: setting
        for setting in (
            _setting(
                "output",
                type=str,
                layers=(Layer.CLI, Layer.ENV, Layer.PROFILE, Layer.BUILTIN),
                policy=MergePolicy.OVERRIDE,
                builtin="text",
            ),
            _setting(
                # Which profile is active (§5). Not a selector, and layer 3 is
                # what it *supplies*, not where it is chosen from -- so it takes
                # `SOPULI_PROFILE` and `defaults.profile` and, when the flag
                # lands, the command line.
                "profile",
                type=str,
                layers=(Layer.CLI, Layer.ENV, Layer.DEFAULTS),
                policy=MergePolicy.OVERRIDE,
            ),
            _setting(
                "safety.dry_run",
                type=bool,
                layers=(Layer.CLI, Layer.ENV, Layer.BUILTIN),
                policy=MergePolicy.RATCHET,
                builtin=False,
            ),
            _setting(
                "safety.readonly",
                type=bool,
                layers=(Layer.PROFILE, Layer.OBJECT, Layer.DEFAULTS, Layer.BUILTIN),
                policy=MergePolicy.RATCHET,
                builtin=False,
            ),
            _setting(
                # No built-in: an unset max_targets is no limit, which is not the
                # same claim as a default limit the tool chose.
                "safety.max_targets",
                type=int,
                layers=(Layer.PROFILE, Layer.OBJECT, Layer.DEFAULTS),
                policy=MergePolicy.RATCHET,
            ),
            _setting(
                "safety.confirm_environments",
                type=tuple,
                layers=(Layer.PROFILE, Layer.OBJECT, Layer.DEFAULTS),
                policy=MergePolicy.RATCHET,
            ),
            _setting(
                # May an unattended runner take over a lock past its expiry
                # (#83)? Config-only -- `defaults.locking` and a profile's -- for
                # the reason the ratchet exists: a flag that unblocks a stuck run
                # is the one thing nobody would ever remove afterwards.
                #
                # No built-in, like `max_targets`: nobody having asked is not the
                # same statement as somebody having written `false`, and only the
                # second is worth reporting in `invocation.options`.
                "locking.break_expired",
                type=bool,
                layers=(Layer.PROFILE, Layer.DEFAULTS),
                policy=MergePolicy.RATCHET,
                safe_bool=False,
            ),
        )
    }
)


def setting(name: str) -> Setting:
    """The registry entry for ``name``.

    Raises :class:`KeyError` with the known names rather than a bare one: an
    unknown setting is a programming error, and the list is short enough that
    showing it turns a typo into a one-line fix.
    """
    try:
        return SETTINGS[name]
    except KeyError:
        raise KeyError(f"unknown setting {name!r}; known: {', '.join(sorted(SETTINGS))}") from None

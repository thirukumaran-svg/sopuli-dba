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

**And so do ratcheted lists**, one type over and for the same reason (H6, #453).
A list merged toward safety meant the union while there was one list setting.
``safety.delivery.allowed_methods`` is the second, and it must *intersect* --
each layer may only narrow which delivery methods an estate may use -- while
``safety.confirm_environments`` must still union. Both are ``tuple[str, ...]``,
so the type cannot say which is which and :attr:`Setting.list_merge` does,
required for a ratcheted list and refused for anything else.

**:attr:`Setting.layers` is enforced.** A contribution from a layer a setting
does not declare raises rather than being merged. ``output`` has no meaning on a
target and ``safety.max_targets`` has no business arriving from an environment
variable; a resolver that silently accepted either would make the precedence
table a description of intent rather than of behaviour.

**One entry can stand for many objects.** ``vaults.*.addr`` is *one* setting with
``*`` where a store name goes, not one setting per declared store (C13, #136).
Registering per store would mean building this mapping from a config file, and
the value of :data:`SAFETY_SETTINGS` being a literal is exactly that a reviewer
can read the ratcheted set without one. Which store a contribution came from is a
*location*, so it travels on :attr:`~sopuli.settings.resolver.Contribution.detail`
-- ``defaults.vaults.vault-dev.tls.verify`` -- where locations already live.
:mod:`sopuli.config.vault_layers` builds those names.

Two settings that look like they belong here and do not:

* ``--color`` -- :func:`sopuli.output.color.resolve_color` owns it, and mixes in
  TTY detection and Windows VT-mode probing, which are not precedence layers.
* ``--config`` -- P3's five-step first-match *file discovery* is a different
  chain, implemented in :mod:`sopuli.config.discovery`.
* ``--force`` -- decided in #89, and deliberately absent. It overrides the
  account guardrails of ``02-oracle-privileges.md`` §4 (checks 2--5) and, since
  #149, ``lock break``'s refusal of a lock that has not expired. Neither is a
  setting and neither has a precedence chain: both are asked of one thing at one
  moment -- this account, now; this lock, now. Keeping it out of the registry is
  what makes invariant 10 structural rather than remembered -- a flag that is not
  a setting cannot relax ``safety.readonly`` or ``safety.max_targets``, because
  there is no layer for it to arrive on. If it is ever added here, that argument
  is gone, and it is the argument that lets the catalogue grow safely: a second
  guardrail joined it without touching this file.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

#: How long to wait for a listener when nothing says otherwise (#176). Thirty
#: seconds crosses a slow WAN and still lets a scheduled run report a dead host
#: the same night.
#:
#: Safe to have a default at all because **nothing has been applied yet**: a
#: connection that times out changed nothing anywhere, which is exactly what
#: cannot be said of the one below.
DEFAULT_CONNECT_TIMEOUT_S = 30

#: No bound on a single round trip, unless an operator asks for one (#176).
#:
#: A call timeout cancels the round trip; it does not undo what the server did
#: with it. ``ALTER USER`` is not transactional, so a rotation cut off at the
#: wrong moment leaves a run that cannot say whether the password changed --
#: and invariant 7's ordering exists precisely so the vault is never promoted
#: ahead of a confirmed target. Turning a slow success into an unknown state is
#: the one failure this design has no recovery for, so the tool does not impose
#: one by default.
#:
#: **Here rather than beside the driver that means it**, which is where the
#: reasoning wants to live: this module imports nothing from ``sopuli`` on
#: purpose -- it sits below :mod:`sopuli.config`, which imports it -- and a
#: constant reaching up into the driver layer made a cycle out of a number. One
#: definition, and :mod:`sopuli.driver.oracle.client` reads it from here.
NO_QUERY_TIMEOUT = 0


class Layer(StrEnum):
    """A precedence layer, in P3's order -- highest authority first.

    Declaration order *is* the authority order: :mod:`sopuli.settings.resolver`
    sorts by it rather than by a separate rank table that could disagree.

    The values are exactly the ``source`` enum published in
    ``docs/schemas/sopuli-run-1.11.schema.json``, so a resolved setting can be
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


class ListMerge(StrEnum):
    """Which direction a ratcheted **list** setting merges (H6, #453).

    The fourth shape of one policy, and the first that the value's type could not
    give. Three are read off the type -- a boolean ratchets toward its safe value,
    an integer to the minimum, a list to the union -- and that held for as long as
    there was one list setting. ``safety.confirm_environments`` and
    ``safety.delivery.allowed_methods`` are both ``tuple[str, ...]`` and must
    merge oppositely, so the shape is declared per setting, exactly as
    :attr:`Setting.safe_bool` already is for the booleans whose polarity the type
    could not give either. That precedent is why this is a fourth shape rather
    than a second mechanism.
    """

    UNION = "union"
    """Every layer's entries are kept. One layer naming an environment is enough
    to have it confirmed, and no layer can remove another's."""

    INTERSECTION = "intersection"
    """Only what *every* layer allows survives. Each layer may narrow the set and
    none may restore what a lower one removed.

    Fail-closed on purpose, which is the whole reason for the extra shape: a
    delivery method a later release adds is unusable until an estate names it,
    where a ``forbidden_methods`` union would have permitted it everywhere on
    upgrade -- silently widening a guard that stands in front of putting a live
    credential on a wire (``00-principles.md`` P3). Three rules come with it and
    are the resolver's: unset means no constraint rather than the empty
    intersection, disjoint layers are a refusal rather than an empty answer, and
    there is no ``forbidden_methods`` key, now or later.
    """


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
        "safety.delivery.allowed_methods",
        "locking.break_expired",
        "vaults.*.tls.verify",
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
    #: For a ratcheted **list**, which direction it merges (H6, #453).
    #:
    #: Required there and refused everywhere else, for :attr:`safe_bool`'s reason
    #: read one type over: ``safety.confirm_environments`` and
    #: ``safety.delivery.allowed_methods`` are both ``tuple[str, ...]``, one must
    #: union and the other must intersect, and no property of the values says
    #: which. A new list setting therefore cannot inherit a shape by omission --
    #: the failure mode being a guard that merges the wrong way round while every
    #: test still passes, which is the same failure mode ``policy`` is required
    #: against.
    list_merge: ListMerge | None = None
    #: Why this setting is accepted and then ignored, or ``None`` where it is
    #: wired to something (#358).
    #:
    #: A key can be worth declaring before anything reads it -- the schema
    #: accepts it, `config show` prints it, and an estate can write it without
    #: the file being invalid. What that must not be is *accidental*, and four
    #: times it was: #292, #296, #348 and `lock_diagnostics` in #356 were each a
    #: complete implementation with the one wire missing, and each was found by
    #: somebody reading the code rather than by a test.
    #:
    #: So the claim moves out of prose and into the registry, where
    #: `tests/settings/test_settings_are_wired.py` holds it to **both**
    #: directions: a setting with no reason must have a consumer, and a setting
    #: with one must have none. The second is the half that stops the marking
    #: rotting -- wiring an inert key up fails the suite until somebody deletes
    #: the reason, which is the moment to ask whether the documents still say
    #: the right thing. `01-configuration.md` §5's paragraph about
    #: `db.query_timeout_s` had already gone stale exactly that way.
    inert_reason: str | None = None

    def __post_init__(self) -> None:
        if self.type not in SETTING_TYPES:
            raise ValueError(
                f"setting {self.name!r} has unsupported type {self.type.__name__}; "
                f"supported: {', '.join(one.__name__ for one in SETTING_TYPES)}"
            )
        if not self.layers:
            raise ValueError(f"setting {self.name!r} declares no layers; nothing could supply it")
        if self.inert_reason is not None and not self.inert_reason.strip():
            raise ValueError(
                f"setting {self.name!r} is marked inert with no reason; the reason is the "
                f"point -- it is what a reader needs in order to know whether the marking "
                f"is still true"
            )
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
        ratcheted_list = ratchet and self.type is tuple
        if ratcheted_list and self.list_merge is None:
            raise ValueError(
                f"{self.name!r} is a ratcheted list and declares no list_merge; "
                f"say which way it merges -- `confirm_environments` unions and "
                f"`delivery.allowed_methods` intersects, and the type cannot tell "
                f"them apart"
            )
        if self.list_merge is not None and not ratcheted_list:
            # The mirror of the `safe_bool` rule above: OVERRIDE never merges
            # anything, and a non-list has no union to have a direction in.
            raise ValueError(
                f"{self.name!r} declares list_merge={self.list_merge} but is not a "
                f"ratcheted list; a merge direction only means anything for one"
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
    list_merge: ListMerge | None = None,
    inert_reason: str | None = None,
) -> Setting:
    return Setting(
        name=name,
        type=type,
        layers=frozenset(layers),
        policy=policy,
        builtin=builtin,
        safe_bool=safe_bool,
        list_merge=list_merge,
        inert_reason=inert_reason,
    )


def _vault_setting(
    key: str,
    *,
    type: type,  # noqa: A002 - see `_setting`
    env: tuple[Layer, ...] = (),
    cli: bool = False,
) -> Setting:
    """One per-store vault key, at the three layers the file gives it and any the
    environment does.

    Every one of them is :attr:`MergePolicy.OVERRIDE`: an address or a mount has
    no safe direction, so the highest layer that wrote one wins. The exception --
    ``tls.verify`` -- is written out in full below rather than passed through
    here, because a ratcheted setting is worth reading beside its reason.

    ``env`` is the environment layers §6 gives *this* key, and it is per key
    rather than blanket (#154): the table names a variable for some of these and
    not for others, and declaring a layer nothing produces would advertise a
    variable that does not exist. :mod:`sopuli.config.vault_env` is the producer,
    and the enforcement in :func:`~sopuli.settings.resolver._checked` is what
    keeps the two in agreement.

    ``cli`` is layer 1, and it is per key for the same reason and true of exactly
    one of them (#422): ``--vault-addr`` is the only flag that hoists a store's
    setting onto the command line. There is deliberately no ``--vault-mount`` or
    ``--vault-namespace`` -- a flag per reach key would be six spellings of what
    ``vaults:`` already says once, and the case for this one is that an address is
    the thing an operator redirects for a single run.
    """
    return _setting(
        f"vaults.*.{key}",
        type=type,
        layers=(
            *((Layer.CLI,) if cli else ()),
            *env,
            Layer.PROFILE,
            Layer.OBJECT,
            Layer.DEFAULTS,
        ),
        policy=MergePolicy.OVERRIDE,
    )


#: Every setting the resolver knows about.
#:
#: Deliberately only what has a producer today plus the safety block, which
#: :mod:`sopuli.config.safety` already parses and which is the reason the ratchet
#: exists at all. Entries for settings nothing reads yet -- ``verify.method``, the
#: ``db`` timeouts -- would be a contract stated in a place no test can mean
#: anything about; they arrive with their consumers. Profile activation (#153)
#: did not change that: a profile may write ``verify.method``, the config layer
#: validates it, and it reaches no setting until something verifies.
#:
#: The ``vaults.*`` entries arrived with theirs (#136): a top-level ``vaults:``
#: declaration and a ``defaults.vaults:`` block are two layers of one setting, so
#: there is a merge to have an opinion about. Their :attr:`Layer.PROFILE` is
#: supplied as of #153, in the same single pass, which is what makes a profile
#: able to say "token from a laptop, AppRole from CI" about one store.
#:
#: :attr:`Layer.OBJECT` for the ``safety.*`` settings is supplied by
#: :func:`~sopuli.settings.sources.estate_contributions` rather than by
#: :func:`~sopuli.settings.sources.config_contributions`, and that split is the
#: point: a ``safety:`` block on a target or a group is not a property of the run,
#: so it can only be merged once a verb knows which targets it is about to reach.
#: :func:`sopuli.safety.for_estate` does that second merge, through this same
#: resolver and on the same contributions, so the ratchet stays one mechanism.
#:
#: **This comment used to say the merge happened elsewhere, and it did not**
#: (#424). For as long as it said so, ``readonly: true`` on a target parsed,
#: validated, appeared in ``config show`` and refused nothing -- a guard failing
#: in the one direction it must not fail in, described in a docstring as though
#: it worked. The enforcement in :func:`~sopuli.settings.resolver._checked` could
#: not catch it: it refuses a layer a setting does not declare, and never
#: requires one to arrive.
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
                # `--profile`, `SOPULI_PROFILE` and `defaults.profile`, in that
                # order, and never `Layer.PROFILE` itself. A profile naming the
                # profile would be §5 rule 2's inheritance graph arriving by the
                # back door.
                "profile",
                type=str,
                layers=(Layer.CLI, Layer.ENV, Layer.DEFAULTS),
                policy=MergePolicy.OVERRIDE,
            ),
            _setting(
                # Which store a run defaults to (§3a, C13). A store *name*, not
                # a setting of one -- `SOPULI_VAULT` is layer 2 of the same
                # setting `defaults.vault` writes, which is the row of §6's table
                # that makes the two spellings one thing.
                #
                # No `Layer.PROFILE`, and that is #118's decision rather than an
                # omission: a profile's `vault:` is deliberately outside the
                # chain that builds bindings, because which profile is active is
                # a property of a run and bindings are built once at load. What
                # this setting answers is narrower -- which store §6's unnamed
                # variables address (`sopuli/config/vault_env.py`) -- and
                # widening it to layer 3 would be answering C15 in a diff.
                "vault",
                type=str,
                layers=(Layer.ENV, Layer.DEFAULTS),
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
                list_merge=ListMerge.UNION,
            ),
            _setting(
                # Which UC-2 delivery methods an estate may use (H6, #453). The
                # fifth ratcheted setting and the first whose merge shape is
                # declared rather than read off its type -- see
                # :class:`ListMerge`, and `01-configuration.md` §9 for the three
                # rules an intersection needs that a union does not.
                #
                # No built-in, like `max_targets` and for the same reading: an
                # unset `allowed_methods` is *no constraint*, which is not the
                # same claim as the tool having chosen a set. A built-in here
                # would be worse than it is there, because it would take part in
                # the intersection and cap every estate at whatever this release
                # happened to know about.
                #
                # The same three layers as the rest of a `safety:` block. There
                # is deliberately no `Layer.CLI`: a flag that widened the set for
                # one run is the relaxation invariant 10 exists to forbid, and a
                # flag that narrowed it would be a second spelling of a guard the
                # file already writes.
                "safety.delivery.allowed_methods",
                type=tuple,
                layers=(Layer.PROFILE, Layer.OBJECT, Layer.DEFAULTS),
                policy=MergePolicy.RATCHET,
                # Inert until #441, which is the issue #498 named in advance as
                # "the first to land is what reads the resolved set". It landed,
                # so the reason is deleted rather than left to rot --
                # `tests/settings/test_settings_are_wired.py` fails either way
                # round, which is what sends somebody back to the documents.
                list_merge=ListMerge.INTERSECTION,
            ),
            # --- one store, several layers (C13, #136) -----------------------
            #
            # `*` is the store name; see the module note. `type`,
            # `non_production` and `locking` are deliberately absent and always
            # will be: a layer may not write them at all, so there is nothing to
            # merge and an entry here would advertise one.
            #
            # `auth:` is absent for a different reason -- it is a block, not a
            # scalar, and `SETTING_TYPES` has no shape for it. It is replaced
            # whole by the highest layer that wrote one, which needs no merge
            # rule; `sopuli/config/vault_layers.py` says why whole rather than
            # key by key.
            # The environment layers are §6's table, key by key (#154).
            # `addr` is the only one with a `SOPULI_*` variable of its own --
            # both the named form and the unnamed one are layer 2 -- while
            # `namespace` and `tls.ca_file` are reachable only through Vault's
            # own `VAULT_NAMESPACE` and `VAULT_CACERT`, which P3 ranks below it.
            _vault_setting("addr", type=str, env=(Layer.ENV, Layer.ENV_THIRDPARTY), cli=True),
            _vault_setting("mount", type=str),
            _vault_setting("kv_version", type=int),
            _vault_setting("namespace", type=str, env=(Layer.ENV_THIRDPARTY,)),
            _vault_setting("timeout_s", type=int),
            _vault_setting("tls.ca_file", type=str, env=(Layer.ENV_THIRDPARTY,)),
            _vault_setting("tls.ca_path", type=str),
            _vault_setting("tls.client_cert", type=str),
            _vault_setting("tls.client_key", type=str),
            _vault_setting("tls.server_name", type=str),
            _setting(
                # The one vault key invariant 10 governs, and the reason the
                # merge goes through this resolver at all. Certificate
                # verification is the safe value, so `true` wins wherever it is
                # written -- a layer that says `false` against a layer that said
                # `true` is refused, whichever of them is higher.
                #
                # No built-in, and that is not the same as defaulting to `false`:
                # an unwritten `verify` is read through `VaultTls.verified`,
                # which treats absent as verified. A built-in `true` here would
                # take part in the ratchet and make `verify: false` unreachable
                # from every layer at once -- which is a decision to remove the
                # key, not a default.
                "vaults.*.tls.verify",
                type=bool,
                layers=(Layer.PROFILE, Layer.OBJECT, Layer.DEFAULTS),
                policy=MergePolicy.RATCHET,
            ),
            _setting(
                # How long to wait for a listener (#176). Profile-only, because
                # §5's table puts it there and because it is a property of
                # *where a run is invoked from*: the same estate reached from a
                # CI runner across a WAN and from a DBA's laptop on the same
                # subnet wants two different numbers, and neither is a fact
                # about the target. See `DEFAULT_CONNECT_TIMEOUT_S` above.
                "db.connect_timeout_s",
                type=int,
                layers=(Layer.PROFILE, Layer.BUILTIN),
                policy=MergePolicy.OVERRIDE,
                builtin=DEFAULT_CONNECT_TIMEOUT_S,
            ),
            _setting(
                # How long to let one round trip run (#176). The built-in is
                # "no bound", which is a decision rather than an omission --
                # `NO_QUERY_TIMEOUT` above says why. An operator may still set
                # one: that is their call about their database, made once and in
                # writing, which is a different thing from a number the tool
                # picked for them.
                "db.query_timeout_s",
                type=int,
                layers=(Layer.PROFILE, Layer.BUILTIN),
                policy=MergePolicy.OVERRIDE,
                builtin=NO_QUERY_TIMEOUT,
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

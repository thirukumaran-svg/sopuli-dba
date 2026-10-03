"""Where contributions come from, for the sources that are not the command line.

The environment is layer 2 (P3), and §6 of ``01-configuration.md`` is the table
this implements. Pure, like everything else here: the mapping is passed in, the
process supplies its own at the boundary -- the same arrangement
:func:`sopuli.output.color.resolve_color` and :func:`sopuli.config.discovery.discover`
already use, and for the same reason. A test that has to set a real environment
variable to check a precedence rule is a test that cannot run beside another one.

Only the variables with a consumer are here. ``SOPULI_PROFILE`` arrived with one
(#153): it is the usual way a CI job or a scheduler selects a profile, and it is
layer 2, so ``--profile`` still beats it and it still beats ``defaults.profile``.
``SOPULI_VAULT`` arrived with #154, for the same shape of reason -- it names the
store a run defaults to, and §6's *other* vault variables need that answer before
they know which store they are talking about.

Three variables in §6 that are *not* settings, and stay where they are:

* ``SOPULI_CONFIG`` -- file discovery is a different chain
  (:mod:`sopuli.config.discovery`).
* ``SOPULI_NO_COLOR`` / ``NO_COLOR`` -- :func:`sopuli.output.color.resolve_color`
  owns colour, TTY detection included.
* ``SOPULI_VAULT_TOKEN`` / ``VAULT_TOKEN`` -- auth material, resolved by
  :mod:`sopuli.material` (ADR-007). A token is not a setting, and it must never
  reach ``invocation.options``.

:func:`config_contributions` is the file's half, and it is here rather than in
:mod:`sopuli.config` for the reason the environment's half is: collecting
contributions is one job with one shape, and splitting it across two packages
would mean two places to look when a layer stops arriving. It stays as pure as
the rest -- a :class:`~sopuli.config.model.Config` in, contributions out.

:func:`config_contributions` is **layers 3 and 5 only**, because layer 4 is
"target/vault-level setting" and a ``safety:`` block on a target or a group is
not a property of the *run*: which one applies depends on which targets a command
is about to reach, and at the boundary no selector has run yet. The per-store half
of layer 4 works the same way in :mod:`sopuli.config.vault_layers`, which resolves
``vaults.*`` inside the file rather than through the invocation.

:func:`estate_contributions` is that layer, and it is here rather than somewhere
of its own so that both halves of one merge are read together (#424). It is asked
later -- once a verb has selected its estate -- and the answer goes back through
the same resolver, which is what keeps the ratchet one mechanism instead of two
that have to agree. Until #424 nothing asked it at all: the keys parsed,
validated, appeared in ``config show`` and refused nothing, which is a config that
reads like protection and is not.
"""

from __future__ import annotations

from collections.abc import Mapping

from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.expansion import declared_at
from sopuli.config.model import Config, ExpandedTarget, Locking, ProfileDb, Safety
from sopuli.config.selection import matches
from sopuli.config.vault_env import DEFAULT_STORE_SETTING, DEFAULT_STORE_VARIABLE
from sopuli.settings.registry import Layer
from sopuli.settings.resolver import Contribution

#: §6's variables that supply a setting of the *run*, by the setting each
#: supplies. All layer 2.
#:
#: ``SOPULI_VAULT`` is here and its neighbours in §6's table are not, and the
#: difference is C13: this one names a **store**, while ``SOPULI_VAULT_ADDR`` and
#: ``SOPULI_VAULT__VAULT_DEV__ADDR`` name a *setting of* one. A store's settings
#: are merged inside the file, for the reason :func:`config_contributions` gives
#: about a profile's ``vaults:`` block, so §6's other vault variables are
#: collected in :mod:`sopuli.config.vault_env` and reach the same resolver from
#: there (#154). The third-party variables of layer 3 travel with them.
ENV_SETTINGS = {
    "SOPULI_OUTPUT": "output",
    "SOPULI_DRY_RUN": "safety.dry_run",
    "SOPULI_PROFILE": "profile",
    DEFAULT_STORE_VARIABLE: DEFAULT_STORE_SETTING,
}

#: Variables whose *presence* is the whole answer, whatever they are set to.
#:
#: ``SOPULI_DRY_RUN=0`` means dry-run, and that is deliberate rather than lazy.
#: Under invariant 10 nothing can turn dry-run *off*, so a variable that parsed
#: ``0`` / ``false`` / ``no`` would be one that looks like it can disable a safety
#: setting and cannot -- the worst of both readings. Set means asked for; unset or
#: empty means not asked for; there is no third answer available to give.
FLAG_VARIABLES = frozenset({"SOPULI_DRY_RUN"})

#: Variables that are read and **refused**, mapped to the setting they collide
#: with. One entry, and §6 calls it the single exception in the whole table.
#:
#: `VAULT_SKIP_VERIFY` is Vault's own CLI convention, so somebody will have it
#: set, and it names the same thing as `vaults.*.tls.verify` -- which is under
#: P3's safety ratchet. Honouring it would let an unranked environment variable
#: turn off verification from outside the config the ratchet governs, which is
#: the one direction invariant 10 exists to forbid. *Ignoring* it silently is
#: worse than either: the operator set it, believes it took effect, and is
#: running verified while thinking they are not -- or the reverse, next time the
#: reading changes. So it is an error, and the error says what to write instead.
REFUSED_VARIABLES = {"VAULT_SKIP_VERIFY": "vaults.*.tls.verify"}


def env_contributions(env: Mapping[str, str]) -> dict[str, list[Contribution]]:
    """What the environment asks for, as contributions keyed by setting name.

    Unset and empty are both "said nothing" -- the ``NO_COLOR`` convention this
    tool already follows, and the only reading that lets a CI job clear an
    inherited variable without unsetting it.

    The variable is named in ``detail`` and its value never is: ``source_detail``
    is a location (``03-json-output.md`` §``invocation.options``).
    """
    for variable, setting in REFUSED_VARIABLES.items():
        # Set-but-empty is "said nothing" here too, so clearing an inherited
        # variable is a way out rather than a second thing to explain.
        if env.get(variable):
            raise ConfigError(
                f"{variable} is set, and this tool does not honour it",
                at=ROOT,
                hint=(
                    f"it names the same setting as `{setting}`, which is under the safety "
                    f"ratchet -- write `verify: false` on the store instead, where it is "
                    f"reviewable and where a higher layer cannot weaken it further"
                ),
            )

    contributions: dict[str, list[Contribution]] = {}
    for variable, name in ENV_SETTINGS.items():
        raw = env.get(variable, "")
        if not raw:
            continue
        value: object = True if variable in FLAG_VARIABLES else raw
        contributions.setdefault(name, []).append(
            Contribution(layer=Layer.ENV, value=value, detail=variable)
        )
    return contributions


def config_contributions(config: Config) -> dict[str, list[Contribution]]:
    """What the file asks for, as contributions keyed by setting name.

    The active profile is layer 3 and ``defaults:`` is layer 5, in that order --
    which is only a convenience for the reader, since the resolver sorts by
    authority itself.

    Only the settings that have a consumer appear, which is the rule
    :mod:`sopuli.settings.registry` states and this is the other end of it. §5's
    list is longer -- ``verify.method``, ``confirm``, the ``db`` budgets -- and
    those keys are parsed, validated and waiting; they join here when something
    reads them, and a contribution for a setting nothing consults would be
    refused by :func:`sopuli.invocation._wired` anyway.

    **A profile's ``db:`` block is here now** (#360), which is the change the
    previous version of this paragraph described in advance: the two names
    "join ``RESOLVED_SETTINGS`` and this function together, in the change that
    gives them a consumer". They now have one -- :func:`sopuli.cli._timeouts`
    hands both to every driver the tool builds.

    #176's review is why they were held back, and the reasoning was right for its
    moment: emitting a contribution for a setting no command consults makes
    :func:`sopuli.invocation._wired` refuse it, and a run document reporting that
    ``profiles.ci.db.connect_timeout_s`` influenced a run it could not have
    influenced is the lie that guard exists to prevent. What went wrong is that
    ``_timeouts`` acquired a *reader* for ``connect_timeout_s`` without either
    half of this joining it -- so the read hit a mapping the name was never in,
    returned ``None`` on every run, and the built-in was used whatever the
    profile said. Half-wired reads as wired from both ends.

    ``vaults.<name>.*`` is deliberately absent. It is the one part of a profile
    that is applied inside the file (:mod:`sopuli.config.vault_layers`), because
    a store's settings belong to the store rather than to the run and the
    registry holds one ``vaults.*`` entry for all of them. ``defaults.vault`` is
    here rather than there for the mirror-image reason: it is a store *name*, not
    a setting of one, and which store a run defaults to is a property of the run.
    """
    found: list[tuple[str, object, str, Layer]] = []

    profile = config.active_profile
    if profile is not None:
        at = f"profiles.{profile.name}"
        found.append(("output", profile.output, f"{at}.output", Layer.PROFILE))
        found.append(("confirm", profile.confirm, f"{at}.confirm", Layer.PROFILE))
        found.extend(_safety(profile.safety, at=at, layer=Layer.PROFILE))
        found.extend(_locking(profile.locking, at=at, layer=Layer.PROFILE))
        found.extend(_db(profile.db, at=at, layer=Layer.PROFILE))

    found.append(("profile", config.defaults.profile, "defaults.profile", Layer.DEFAULTS))
    found.append((DEFAULT_STORE_SETTING, config.defaults.vault, "defaults.vault", Layer.DEFAULTS))
    found.extend(_safety(config.defaults.safety, at="defaults", layer=Layer.DEFAULTS))
    found.extend(_locking(config.defaults.locking, at="defaults", layer=Layer.DEFAULTS))

    return _collected(found)


def estate_contributions(config: Config) -> dict[str, list[Contribution]]:
    """Layer 4 of the ``safety:`` settings -- the blocks on the targets a run
    reaches, and on the groups that match them (#424).

    ``config`` is the **already-selected** estate: `filter_estate` has run, and
    what is left is what the verb is about to act on. That is what makes this
    answerable at all -- a `safety:` block on a target says nothing about a run
    that never reaches that target, so the question cannot be asked at the
    boundary where :func:`config_contributions` is.

    **The targets are the ones the plan names**, which is the ones bindings name
    rather than everything still in ``expanded_targets``. A declared target this
    run touches nothing on is not reached, and it has to be read that way:
    ``max_targets`` is compared against :class:`~sopuli.plan.BlastRadius`, which
    counts the same set. Two different answers to "which targets does this run
    reach" is the shape of bug that makes a ceiling fire on a run it was never
    aimed at.

    **A group contributes when it matches a target in the plan.** A group is a
    named label match (§4) and nothing has to select by it for its block to
    apply -- the file writes it as a `safety:` block over a population, and a
    population this run enters is a population this run is governed by.

    Several contributions arrive at one layer, which the resolver already allows
    and orders stably: each target's own block first, in estate order, then the
    groups in the order the file declares them. Under the ratchet the order
    decides nothing about the *value* -- only which location is reported when
    several layers tie -- and "ties resolve downward" (§9) makes the reported one
    the lowest-authority contributor in any case.
    """
    reached = {binding.target for binding in config.bindings}
    found: list[tuple[str, object, str, Layer]] = []
    for expanded in config.expanded_targets:
        if expanded.name not in reached:
            continue
        found.extend(target_safety(expanded))
    matched = [expanded.target for expanded in config.expanded_targets if expanded.name in reached]
    for group in config.groups:
        if group.safety is None or not any(matches(target, group.match) for target in matched):
            continue
        found.extend(
            safety_block(group.safety, at=f"groups.{group.name}.safety", layer=Layer.OBJECT)
        )
    return _collected(found)


def _db(db: ProfileDb, *, at: str, layer: Layer) -> list[tuple[str, object, str, Layer]]:
    """A profile's ``db:`` block, one entry per budget it wrote (#360).

    ``ProfileDb`` is never ``None`` -- ``Profile`` builds an empty one -- so this
    takes the block rather than an optional, and the ``None`` per *field* is what
    says a key went unwritten. The caller drops those, which is the same
    distinction every other block here keeps: a key nobody wrote is not a key
    written to the built-in.

    Profile only, because that is what the registry declares for both names. §5
    puts them there because they are a property of *where a run is invoked from*
    -- the same estate reached from a CI runner across a WAN and from a laptop on
    the same subnet wants two different numbers, and neither is a fact about the
    target.
    """
    return [
        ("db.connect_timeout_s", db.connect_timeout_s, f"{at}.db.connect_timeout_s", layer),
        ("db.query_timeout_s", db.query_timeout_s, f"{at}.db.query_timeout_s", layer),
    ]


def _safety(
    safety: Safety | None, *, at: str, layer: Layer
) -> list[tuple[str, object, str, Layer]]:
    """A ``safety:`` block, one entry per key it may have written.

    ``confirm_environments`` reports ``None`` when empty, and that is a reading
    rather than an optimisation: :class:`~sopuli.config.model.Safety` cannot tell
    a key nobody wrote from one written as an empty list, both being ``()``.
    Under a union ratchet the two mean the same thing -- neither adds an
    environment -- so the honest report is that the layer said nothing, rather
    than a row in every run document claiming ``defaults:`` supplied the empty
    answer.
    """
    if safety is None:
        return []
    return safety_block(safety, at=f"{at}.safety", layer=layer)


def target_safety(expanded: ExpandedTarget) -> list[tuple[str, object, str, Layer]]:
    """One target's ``safety:`` keys, and the line each was written on.

    Public because :mod:`sopuli.output.config_view` needs the identical answer
    (#426): a view that listed a generated target's keys by a rule of its own
    would report an ``overrides:`` entry as the source of keys it never wrote,
    which is the defect this function exists to avoid one layer down.

    Usually one block. **Two, where an ``overrides:`` entry patched it** (#424,
    found in review): `_patch_target` merges a patch into the template key by
    key, so a patch's ``readonly: false`` replaces a template's ``true`` and the
    safer of the two is gone before anything can ratchet them. A run narrowed to
    the patched target would then have nothing left to be safest *of*, and the
    override would simply win -- which invariant 10 forbids and which
    `_patch_target`'s own docstring has always said cannot happen.

    So both reach the resolver. The template's block goes first, and the patched
    one contributes **only the keys whose value it changed**: a key the patch did
    not write holds the template's answer, which is already contributed at the
    template's line, and repeating it here would do nothing but win the
    location tie and send the reader to a block that does not mention the key.
    """
    block = expanded.target.safety
    if expanded.template_safety is None:
        return (
            []
            if block is None
            else safety_block(block, at=str(declared_at(expanded, "safety")), layer=Layer.OBJECT)
        )
    template = safety_block(
        expanded.template_safety,
        at=f"target_sets.{expanded.target_set}.safety",
        layer=Layer.OBJECT,
    )
    written = {name: value for name, value, _, _ in template}
    patched = (
        []
        if block is None
        else safety_block(block, at=str(declared_at(expanded, "safety")), layer=Layer.OBJECT)
    )
    return [*template, *(row for row in patched if row[1] != written.get(row[0]))]


def safety_block(safety: Safety, *, at: str, layer: Layer) -> list[tuple[str, object, str, Layer]]:
    """The same four keys, given the path of the **block** rather than of what
    contains it.

    Split out for the one caller that cannot compute the first from the second
    (#424): a generated target's block may have been written in an ``overrides:``
    entry rather than in the template, and
    :func:`~sopuli.config.expansion.declared_at` is the function that knows which.
    Reporting an override against the template would point the reader at the one
    place the value is spelled the way they expected.
    """
    return [
        ("safety.readonly", safety.readonly, f"{at}.readonly", layer),
        ("safety.max_targets", safety.max_targets, f"{at}.max_targets", layer),
        (
            "safety.confirm_environments",
            safety.confirm_environments or None,
            f"{at}.confirm_environments",
            layer,
        ),
        (
            # `None` from two places that mean the same thing -- no `delivery:`
            # sub-block, and one that wrote no `allowed_methods` -- and the
            # caller drops both. Under the intersection that is the difference
            # between a layer imposing nothing and a layer permitting nothing,
            # which is why the empty list is refused at build time rather than
            # arriving here as `()`.
            "safety.delivery.allowed_methods",
            None if safety.delivery is None else safety.delivery.allowed_methods,
            f"{at}.delivery.allowed_methods",
            layer,
        ),
    ]


def _collected(
    found: list[tuple[str, object, str, Layer]],
) -> dict[str, list[Contribution]]:
    """Contributions by setting name, dropping the keys nobody wrote.

    A key the layer did not write says nothing, which is not the same as writing
    the built-in default -- the distinction the whole config model keeps so that
    "safest of all layers" can be computed at all.
    """
    contributions: dict[str, list[Contribution]] = {}
    for name, value, detail, layer in found:
        if value is None:
            continue
        contributions.setdefault(name, []).append(
            Contribution(layer=layer, value=value, detail=detail)
        )
    return contributions


def _locking(
    locking: Locking | None, *, at: str, layer: Layer
) -> list[tuple[str, object, str, Layer]]:
    """``locking.break_expired`` -- the one key of a ``locking:`` block that is a
    setting. ``mode`` is a property of a store, and a profile may not write it."""
    if locking is None:
        return []
    return [("locking.break_expired", locking.break_expired, f"{at}.locking.break_expired", layer)]

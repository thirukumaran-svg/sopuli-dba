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

Two variables in §6 that are *not* settings, and stay where they are:

* ``SOPULI_CONFIG`` -- file discovery is a different chain
  (:mod:`sopuli.config.discovery`).
* ``SOPULI_NO_COLOR`` / ``NO_COLOR`` -- :func:`sopuli.output.color.resolve_color`
  owns colour, TTY detection included.

:func:`config_contributions` is the file's half, and it is here rather than in
:mod:`sopuli.config` for the reason the environment's half is: collecting
contributions is one job with one shape, and splitting it across two packages
would mean two places to look when a layer stops arriving. It stays as pure as
the rest -- a :class:`~sopuli.config.model.Config` in, contributions out.

**Layers 3 and 5 only.** Layer 4 is "target/vault-level setting", and a
``safety:`` block on a target or a group is not a property of the *run*: which
one applies depends on which target is being worked on, so it is merged when a
command reaches one, against the answer resolved here. The per-store half of
layer 4 already works this way in :mod:`sopuli.config.vault_layers`, which
resolves ``vaults.*`` inside the file rather than through the invocation.
"""

from __future__ import annotations

from collections.abc import Mapping

from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.model import Config, Locking, Safety
from sopuli.settings.registry import Layer
from sopuli.settings.resolver import Contribution

#: §6's variables, by the setting each supplies. ``SOPULI_*`` is layer 2; the
#: third-party variables of layer 3 (``VAULT_ADDR`` and friends) arrive with the
#: settings they feed, which do not exist yet.
ENV_SETTINGS = {
    "SOPULI_OUTPUT": "output",
    "SOPULI_DRY_RUN": "safety.dry_run",
    "SOPULI_PROFILE": "profile",
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

    ``vaults.<name>.*`` is deliberately absent. It is the one part of a profile
    that is applied inside the file (:mod:`sopuli.config.vault_layers`), because
    a store's settings belong to the store rather than to the run and the
    registry holds one ``vaults.*`` entry for all of them.
    """
    found: list[tuple[str, object, str, Layer]] = []

    profile = config.active_profile
    if profile is not None:
        at = f"profiles.{profile.name}"
        found.append(("output", profile.output, f"{at}.output", Layer.PROFILE))
        found.extend(_safety(profile.safety, at=at, layer=Layer.PROFILE))
        found.extend(_locking(profile.locking, at=at, layer=Layer.PROFILE))

    found.append(("profile", config.defaults.profile, "defaults.profile", Layer.DEFAULTS))
    found.extend(_safety(config.defaults.safety, at="defaults", layer=Layer.DEFAULTS))
    found.extend(_locking(config.defaults.locking, at="defaults", layer=Layer.DEFAULTS))

    contributions: dict[str, list[Contribution]] = {}
    for name, value, detail, layer in found:
        # A key the layer did not write says nothing, which is not the same as
        # writing the built-in default -- the distinction the whole config model
        # keeps so that "safest of all layers" can be computed at all.
        if value is None:
            continue
        contributions.setdefault(name, []).append(
            Contribution(layer=layer, value=value, detail=detail)
        )
    return contributions


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
    return [
        ("safety.readonly", safety.readonly, f"{at}.safety.readonly", layer),
        ("safety.max_targets", safety.max_targets, f"{at}.safety.max_targets", layer),
        (
            "safety.confirm_environments",
            safety.confirm_environments or None,
            f"{at}.safety.confirm_environments",
            layer,
        ),
    ]


def _locking(
    locking: Locking | None, *, at: str, layer: Layer
) -> list[tuple[str, object, str, Layer]]:
    """``locking.break_expired`` -- the one key of a ``locking:`` block that is a
    setting. ``mode`` is a property of a store, and a profile may not write it."""
    if locking is None:
        return []
    return [("locking.break_expired", locking.break_expired, f"{at}.locking.break_expired", layer)]

"""Where contributions come from, for the sources that are not the command line.

The environment is layer 2 (P3), and §6 of ``01-configuration.md`` is the table
this implements. Pure, like everything else here: the mapping is passed in, the
process supplies its own at the boundary -- the same arrangement
:func:`sopuli.output.color.resolve_color` and :func:`sopuli.config.discovery.discover`
already use, and for the same reason. A test that has to set a real environment
variable to check a precedence rule is a test that cannot run beside another one.

Only the variables with a consumer are here. ``SOPULI_PROFILE`` is in §6 and is
deliberately absent: nothing activates a profile yet, and a variable that
appeared in ``invocation.options`` while changing nothing would be a lie in the
contract rather than a head start. It arrives with profile activation.

Two variables in §6 that are *not* settings, and stay where they are:

* ``SOPULI_CONFIG`` -- file discovery is a different chain
  (:mod:`sopuli.config.discovery`).
* ``SOPULI_NO_COLOR`` / ``NO_COLOR`` -- :func:`sopuli.output.color.resolve_color`
  owns colour, TTY detection included.
"""

from __future__ import annotations

from collections.abc import Mapping

from sopuli.settings.registry import Layer
from sopuli.settings.resolver import Contribution

#: §6's variables, by the setting each supplies. ``SOPULI_*`` is layer 2; the
#: third-party variables of layer 3 (``VAULT_ADDR`` and friends) arrive with the
#: settings they feed, which do not exist yet.
ENV_SETTINGS = {
    "SOPULI_OUTPUT": "output",
    "SOPULI_DRY_RUN": "safety.dry_run",
}

#: Variables whose *presence* is the whole answer, whatever they are set to.
#:
#: ``SOPULI_DRY_RUN=0`` means dry-run, and that is deliberate rather than lazy.
#: Under invariant 10 nothing can turn dry-run *off*, so a variable that parsed
#: ``0`` / ``false`` / ``no`` would be one that looks like it can disable a safety
#: setting and cannot -- the worst of both readings. Set means asked for; unset or
#: empty means not asked for; there is no third answer available to give.
FLAG_VARIABLES = frozenset({"SOPULI_DRY_RUN"})


def env_contributions(env: Mapping[str, str]) -> dict[str, list[Contribution]]:
    """What the environment asks for, as contributions keyed by setting name.

    Unset and empty are both "said nothing" -- the ``NO_COLOR`` convention this
    tool already follows, and the only reading that lets a CI job clear an
    inherited variable without unsetting it.

    The variable is named in ``detail`` and its value never is: ``source_detail``
    is a location (``03-json-output.md`` §``invocation.options``).
    """
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

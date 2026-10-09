"""Settings: P3's precedence chain and invariant 10's ratchet, in one place.

Two layers, deliberately separable:

* **The registry** -- :mod:`sopuli.settings.registry` declares what a setting
  *is*: its type, which of P3's six layers may supply it, and how colliding
  layers merge. :data:`~sopuli.settings.registry.SAFETY_SETTINGS` is the
  one-glance audit surface invariant 10 asks for.
* **The resolver** -- :mod:`sopuli.settings.resolver` merges the contributions a
  caller collected and reports *where the answer came from*, which is what
  ``invocation.options`` and ``config show --resolved --explain`` need and
  what a bare value cannot provide.

The unit is a setting rather than a command-line option, because half the things
needing a merge policy have no flag: ``readonly`` arrives from a config file,
``verify.method`` from a profile, ``safety.dry_run`` from either a flag or
``SOPULI_DRY_RUN``. Flags, ``SOPULI_*`` variables and config keys all bind to
setting names.

Nothing here reads the environment, opens a file, or imports click. Collecting
contributions is the caller's job -- the boundary knows what was typed and what
the file said; this knows what those two mean together.
"""

from sopuli.settings.registry import (
    LAYER_ORDER,
    SAFETY_SETTINGS,
    SETTINGS,
    Layer,
    ListMerge,
    MergePolicy,
    Setting,
    setting,
)
from sopuli.settings.resolver import (
    Contribution,
    Resolved,
    ratchet_note,
    render_value,
    resolve,
    resolve_all,
)

__all__ = [
    "LAYER_ORDER",
    "SAFETY_SETTINGS",
    "SETTINGS",
    "Contribution",
    "Layer",
    "ListMerge",
    "MergePolicy",
    "Resolved",
    "Setting",
    "ratchet_note",
    "render_value",
    "resolve",
    "resolve_all",
    "setting",
]

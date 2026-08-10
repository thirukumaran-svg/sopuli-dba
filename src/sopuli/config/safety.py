"""Building a ``safety:`` block.

§9 allows one under ``defaults``, a target, a group or a profile, and says they
are the one thing in the file that does *not* follow last-one-wins: the resolved
value is the safest of all layers -- the lowest ``max_targets``, the union of
``confirm_environments``, ``readonly`` if any layer sets it (P3, invariant 10).

That resolution is the precedence work and is not here. This reads one block, and
its only real job is to keep "unset" distinct from "set to the default" so the
resolver has something to be safest *of*.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.errors import ConfigError, KeyPath
from sopuli.config.fields import (
    mapping,
    optional_bool,
    optional_int,
    reject_unknown_keys,
    string_list,
)
from sopuli.config.model import Safety

SAFETY_KEYS = ("max_targets", "confirm_environments", "readonly")


def build_safety(raw: Any, *, at: KeyPath) -> Safety | None:
    """Read a ``safety:`` block, or ``None`` where there is none."""
    if raw is None:
        return None
    block = mapping(raw, at=at)
    reject_unknown_keys(block, allowed=SAFETY_KEYS, at=at)

    max_targets = optional_int(block, "max_targets", at=at)
    if max_targets is not None and max_targets < 1:
        # Zero would be a way of saying "touch nothing", but `readonly: true` is
        # that, and it says so. A max_targets of 0 or -1 is much more likely to
        # be a slip in a file that then blocks every run for a reason nobody can
        # find.
        raise ConfigError(
            f"max_targets must be at least 1, not {max_targets}",
            at=at.key("max_targets"),
            hint="use `readonly: true` to block changes entirely",
        )

    confirm = block.get("confirm_environments")
    return Safety(
        max_targets=max_targets,
        confirm_environments=(
            () if confirm is None else string_list(confirm, at=at.key("confirm_environments"))
        ),
        readonly=optional_bool(block, "readonly", at=at),
    )

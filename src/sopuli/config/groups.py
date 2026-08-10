"""Building the ``groups:`` section -- named label matches over the estate (§4).

A group is a name for a selection: ``prod-pdbs: { match: { target_set: appdb,
env: prod } }``. It is what ``--group`` and an application's
``targets: { group: NAME }`` refer to, and §9 allows it to carry a ``safety:``
block so a whole population can be marked ``readonly`` in one place.

Whether the labels a group matches on exist anywhere in the estate is not
checked here. That needs the target sets expanded, and a group matching nothing
today may match something the moment a tenant is added -- so it is a question for
the resolved view rather than for the file.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.fields import label_selector, mapping, reject_unknown_keys
from sopuli.config.model import Group
from sopuli.config.safety import build_safety

GROUP_KEYS = ("match", "safety")


def build_groups(document: dict[str, Any]) -> tuple[Group, ...]:
    """Read ``groups:`` into entries, in document order."""
    if "groups" not in document:
        return ()

    at = ROOT.key("groups")
    entries = mapping(document["groups"], at=at)
    return tuple(_build_group(name, entry, at=at.key(name)) for name, entry in entries.items())


def _build_group(name: str, raw: Any, *, at: KeyPath) -> Group:
    entry = mapping(raw, at=at)
    reject_unknown_keys(entry, allowed=GROUP_KEYS, at=at)

    if "match" not in entry:
        raise ConfigError(
            "a group must declare what it matches",
            at=at.key("match"),
            hint="`match: { env: prod }` -- a group is a name for a label selection",
        )

    return Group(
        name=name,
        match=label_selector(entry["match"], at=at.key("match")),
        safety=build_safety(entry.get("safety"), at=at.key("safety")),
    )

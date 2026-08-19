"""Building ``defaults:`` and ``runtime:`` -- the two small top-level sections.

They are together because neither is big enough to earn a file, and because they
are the two sections that describe *this installation* rather than the estate:
``defaults`` is precedence layer 5 (P3), the bottom of the config file, and
``runtime`` is where the Oracle client lives on this machine.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.errors import ROOT
from sopuli.config.fields import mapping, optional_string, reject_unknown_keys
from sopuli.config.locking import build_locking
from sopuli.config.model import Defaults, OracleRuntime, Runtime
from sopuli.config.safety import build_safety
from sopuli.config.vaults import build_vault_patches, vault_name

DEFAULTS_KEYS = ("vault", "vaults", "policy", "profile", "safety", "locking")

RUNTIME_KEYS = ("oracle",)

RUNTIME_ORACLE_KEYS = ("client_lib_dir",)


def build_defaults(document: dict[str, Any]) -> Defaults:
    """Read ``defaults:`` -- what everything else falls back to."""
    if "defaults" not in document:
        return Defaults()

    at = ROOT.key("defaults")
    entry = mapping(document["defaults"], at=at)
    reject_unknown_keys(entry, allowed=DEFAULTS_KEYS, at=at)

    return Defaults(
        vault=vault_name(entry, at=at),
        policy=optional_string(entry, "policy", at=at),
        profile=optional_string(entry, "profile", at=at),
        safety=build_safety(entry.get("safety"), at=at.key("safety")),
        locking=build_locking(entry.get("locking"), at=at.key("locking")),
        # `vault:` names a store and `vaults:` describes one -- C13, and the two
        # keys sit one line apart here on purpose. Layer 5, so these are
        # outranked by the declaration they patch (:mod:`sopuli.config.vault_layers`).
        vaults=build_vault_patches(entry, at=at),
    )


def build_runtime(document: dict[str, Any]) -> Runtime:
    """Read ``runtime:`` -- how this installation of the tool is set up."""
    if "runtime" not in document:
        return Runtime()

    at = ROOT.key("runtime")
    entry = mapping(document["runtime"], at=at)
    reject_unknown_keys(entry, allowed=RUNTIME_KEYS, at=at)

    oracle = entry.get("oracle")
    if oracle is None:
        return Runtime()

    block = mapping(oracle, at=at.key("oracle"))
    reject_unknown_keys(block, allowed=RUNTIME_ORACLE_KEYS, at=at.key("oracle"))
    return Runtime(
        oracle=OracleRuntime(
            client_lib_dir=optional_string(block, "client_lib_dir", at=at.key("oracle"))
        )
    )

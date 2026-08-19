"""Merging the layers of P3 that the config file itself can supply (C13, #136).

`00-principles.md` P3 puts one precedence chain over everything, and three of its
six layers are inside the file:

.. code-block::

    3. Profile block in config          profiles.ci.vaults.hcv-prod.addr
    4. Target/vault-level setting       vaults.hcv-prod.addr
    5. Top-level defaults in config     defaults.vaults.hcv-prod.addr

**The direction is the thing most likely to be got wrong.** A top-level
``vaults:`` entry *outranks* ``defaults.vaults:``, so the ``defaults:`` block
supplies keys the declaration did not write rather than replacing ones it did.
The word "patch" reads the other way and is right only for a profile, which is
layer 3 and above the declaration.

**All three layers are merged in one pass**, which is why the active profile has
to be known before this runs (#153). Resolving 4 against 5 first and folding 3 in
afterwards would give the right *value* for an overridden key and the wrong
*provenance* for it -- and for ``tls.verify``, whose ratchet is the reason this
goes through the resolver at all, it would report the winner of the first pass
rather than the layer somebody has to go and edit.

The active profile is chosen by :func:`sopuli.config.profiles.select_profile` and
reaches here on :attr:`~sopuli.config.model.Config.active_profile`. A profile
that is declared and not active contributes nothing: §5 rule 1 is that exactly
one profile is active, so the others are inert text in the file.

**Not a second resolver.** :mod:`sopuli.settings` owns the merge rule, and every
key here goes through it -- which is the whole reason ``vaults.*.tls.verify``
ratchets instead of being overwritten. A hand-rolled "highest layer wins" would
have been three lines and would have got that one key silently wrong, because it
is the one key where highest-layer-wins is not the rule.

Two shape decisions the merge has to make, and they differ:

**``auth:`` is replaced whole.** Its keys are only meaningful together with a
``method``, so a key-by-key merge produces credentials nobody wrote --
``method: approle`` carrying a leftover ``token:`` from the declaration
authenticates as nobody. The layer that wrote an ``auth:`` block wrote all of it.

**``tls:`` is merged key by key.** Its keys are independent facts about one
connection, and one of them is under the safety ratchet. Replacing the block
whole would let a layer mentioning only ``ca_file`` drop a ``verify: true`` it
never spoke about, which is exactly the relaxation invariant 10 exists to stop.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from sopuli.config.errors import ROOT, KeyPath
from sopuli.config.model import Config, ConfigWarning, Vault, VaultPatch, VaultTls
from sopuli.settings import Contribution, Layer, Resolved, ratchet_note, resolve

#: The scalar keys of a vault entry, and the order the merged object takes them.
#: ``auth`` is absent because it is not a scalar; ``tls`` because its members are
#: merged individually. See the module note.
REACH_KEYS = ("addr", "mount", "kv_version", "namespace", "timeout_s")

#: The members of ``tls:``, merged one at a time.
TLS_KEYS = ("ca_file", "ca_path", "client_cert", "client_key", "server_name", "verify")


def setting_name(key: str) -> str:
    """What a per-store setting is called in the registry.

    ``addr`` becomes ``vaults.*.addr``; ``tls.verify`` becomes
    ``vaults.*.tls.verify``. The ``*`` stands for the store, because a registry
    keyed by concrete store name would have to be built from a config -- and
    :data:`sopuli.settings.registry.SETTINGS` is a literal on purpose, so that the
    ratcheted set stays readable in one place without one.

    The concrete store is carried on the contribution's ``detail`` instead, which
    is where a location belongs anyway (``03-json-output.md``
    §``invocation.options``). ``sopuli/settings/sources.py`` already refers to
    ``vaults.*.tls.verify`` by exactly this spelling in the ``VAULT_SKIP_VERIFY``
    refusal, which is the same name arriving from the other end.
    """
    return f"vaults.*.{key}"


def apply_vault_layers(config: Config) -> tuple[tuple[Vault, ...], tuple[ConfigWarning, ...]]:
    """Every declared store with the file's layers merged in, and what was refused.

    A patch naming a store the file does not declare is **ignored here and
    refused elsewhere**: :mod:`sopuli.config.references` resolves every name in
    the file against what it declares, in one pass, with one message. Growing a
    second dangling-name error here would be a second thing to learn about the
    same mistake -- and nothing can proceed past that check either way.
    """
    by_name: dict[str, list[tuple[Layer, KeyPath, VaultPatch]]] = {}
    # Highest authority first, because `_highest` reads `auth:` off the front of
    # this list. The resolver sorts for itself; that one key does not go through
    # it, being replaced whole rather than merged.
    profile = config.active_profile
    if profile is not None:
        at = ROOT.key("profiles").key(profile.name).key("vaults")
        for patch in profile.vaults:
            by_name.setdefault(patch.name, []).append((Layer.PROFILE, at.key(patch.name), patch))
    for patch in config.defaults.vaults:
        by_name.setdefault(patch.name, []).append(
            (Layer.DEFAULTS, ROOT.key("defaults").key("vaults").key(patch.name), patch)
        )

    merged = []
    warnings: list[ConfigWarning] = []
    for vault in config.vaults:
        one, found = _merge(vault, by_name.get(vault.name, []))
        merged.append(one)
        warnings.extend(found)
    return tuple(merged), tuple(warnings)


def _merge(
    vault: Vault, patches: list[tuple[Layer, KeyPath, VaultPatch]]
) -> tuple[Vault, list[ConfigWarning]]:
    """One store, resolved key by key. Returns it and any defeated relaxation."""
    if not patches:
        # Nothing to merge, and skipping the resolver here is not an optimisation:
        # a single contribution resolves to itself, so the two paths agree. What
        # it avoids is inventing a `patched` provenance for a store nobody
        # patched.
        return vault, []

    values: dict[str, Any] = {}
    patched: list[str] = []
    warnings: list[ConfigWarning] = []

    for key in REACH_KEYS:
        answer = _resolve_key(key, vault, patches, at=ROOT.key("vaults").key(vault.name))
        if answer is None:
            continue
        values[key] = answer.value
        if answer.layer is not Layer.OBJECT:
            patched.append(key)

    tls, tls_patched, tls_warnings = _merge_tls(vault, patches)
    if tls is not None:
        values["tls"] = tls
    patched.extend(tls_patched)
    warnings.extend(tls_warnings)

    auth = _highest(patch.auth for _, _, patch in patches)
    if auth is not None:
        # Whole-block replacement, so there is nothing to merge and nothing to
        # keep from the declaration. `replace` leaves the declaration's own block
        # in place when no layer wrote one.
        values["auth"] = auth
        patched.append("auth")

    return replace(vault, patched=tuple(sorted(patched)), **values), warnings


def _merge_tls(
    vault: Vault, patches: list[tuple[Layer, KeyPath, VaultPatch]]
) -> tuple[VaultTls | None, list[str], list[ConfigWarning]]:
    """``tls:`` one member at a time, so ``verify`` can ratchet.

    ``None`` when no layer wrote a ``tls:`` block at all, which keeps "no block"
    distinct from "an empty block" -- the same distinction
    :class:`~sopuli.config.model.VaultTls` keeps between a missing ``verify`` and
    a written one.
    """
    if vault.tls is None and all(patch.tls is None for _, _, patch in patches):
        return None, [], []

    values: dict[str, Any] = {}
    patched: list[str] = []
    warnings: list[ConfigWarning] = []
    for key in TLS_KEYS:
        answer = _resolve_key(f"tls.{key}", vault, patches, at=ROOT.key("vaults").key(vault.name))
        if answer is None:
            continue
        values[key] = answer.value
        if answer.layer is not Layer.OBJECT:
            patched.append(f"tls.{key}")
        note = ratchet_note(answer)
        if note is not None:
            # A relaxation that lost is reported rather than swallowed
            # (`sopuli/settings/resolver.py`). Here it becomes a config warning
            # rather than a run diagnostic, because the merge happens while the
            # file is being read and `Config.warnings` is where a finding about
            # the file goes -- the boundary turns those into `diagnostics[]` for
            # every command that loads a config.
            warnings.append(
                ConfigWarning(
                    message=note,
                    # No `at`. Every other config warning needs one because its
                    # message describes a value; this one names *both* locations
                    # already -- the layer that asked and the one that held -- and
                    # a breadcrumb in front of it would repeat one of them a few
                    # words before the sentence says it again.
                    at="",
                    hint="invariant 10: a safety setting cannot be relaxed by any layer",
                )
            )
    return VaultTls(**values), patched, warnings


def _resolve_key(
    key: str, vault: Vault, patches: list[tuple[Layer, KeyPath, VaultPatch]], *, at: KeyPath
) -> Resolved | None:
    """One key across the layers that spoke, through the one resolver.

    The declaration contributes at :attr:`~sopuli.settings.registry.Layer.OBJECT`
    -- P3's layer 4, "target/vault-level setting" -- and a ``defaults:`` patch at
    layer 5. Which is higher is the resolver's business and not restated here.
    """
    contributions = []
    declared = _read(vault, key)
    if declared is not None:
        contributions.append(
            Contribution(layer=Layer.OBJECT, value=declared, detail=str(_at(at, key)))
        )
    for layer, where, patch in patches:
        value = _read(patch, key)
        if value is not None:
            contributions.append(
                Contribution(layer=layer, value=value, detail=str(_at(where, key)))
            )
    return resolve(setting_name(key), contributions)


def _read(entry: Vault | VaultPatch, key: str) -> Any:
    """The value of ``addr`` or of ``tls.verify`` on either shape."""
    if not key.startswith("tls."):
        return getattr(entry, key)
    return None if entry.tls is None else getattr(entry.tls, key.removeprefix("tls."))


def _at(base: KeyPath, key: str) -> KeyPath:
    for part in key.split("."):
        base = base.key(part)
    return base


def _highest(blocks: Any) -> Any:
    """The first non-``None`` block, in the order the caller supplied.

    ``auth:`` only, and only because it is replaced whole. ``patches`` is built
    highest-authority-first, so "first" is "wins" -- and there is exactly one
    layer in it today, which is why this is three lines rather than a sort.
    """
    for block in blocks:
        if block is not None:
            return block
    return None

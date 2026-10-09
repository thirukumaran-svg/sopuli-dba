"""Merging P3's layers for one store (C13).

`00-principles.md` P3 puts one precedence chain over everything, and five of its
six layers reach a store:

.. code-block::

    2. Environment variable             SOPULI_VAULT__HCV_PROD__ADDR
    3. Profile block in config          profiles.ci.vaults.hcv-prod.addr
    4. Target/vault-level setting       vaults.hcv-prod.addr
    5. Top-level defaults in config     defaults.vaults.hcv-prod.addr

The third-party variables -- ``VAULT_ADDR`` and friends -- are also layer 2, ranked
below their ``SOPULI_*`` equivalent, as P3 says. **Layer 1 is one key wide**
(decision #422): ``--vault-addr`` hoists ``vaults.*.addr`` onto the command
line and nothing else does, so there is no ``--vault-mount`` beside it.
:func:`sopuli.config.vault_env.vault_cli_contributions` places it, on purpose --
which store an unnamed setting addresses is §6's question and it has one answer.

**The environment is collected next door**, in :mod:`sopuli.config.vault_env`,
which owns §6's spellings and the question the unnamed variables raise -- which
store is "the active" one. What arrives here is contributions, already addressed
to a store and a key, so this function is the place where the layers meet.

**The direction is the thing most likely to be got wrong.** A top-level
``vaults:`` entry *outranks* ``defaults.vaults:``, so the ``defaults:`` block
supplies keys the declaration did not write rather than replacing ones it did.
The word "patch" reads the other way and is right only for a profile, which is
layer 3 and above the declaration.

**Every layer is merged in one pass**, which is why the active profile has to be
known before this runs. Resolving 4 against 5 first and folding 3 in
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

from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any

from sopuli.config.errors import ROOT, KeyPath
from sopuli.config.model import Config, ConfigWarning, Vault, VaultPatch, VaultTls
from sopuli.config.vault_env import (
    NO_ENV,
    default_store,
    vault_cli_contributions,
    vault_env_contributions,
)
from sopuli.settings import Contribution, Layer, Resolved, ratchet_note, resolve

#: One store's environment contributions, keyed by setting key -- what
#: :func:`~sopuli.config.vault_env.vault_env_contributions` produces for one
#: name. Empty for a store no variable mentioned, which is almost always all of
#: them.
EnvKeys = Mapping[str, Sequence[Contribution]]

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


def apply_vault_layers(
    config: Config, *, env: Mapping[str, str] = NO_ENV, vault_addr: str | None = None
) -> tuple[tuple[Vault, ...], tuple[ConfigWarning, ...]]:
    """Every declared store with its layers merged in, and what was refused.

    A patch naming a store the file does not declare is **ignored here and
    refused elsewhere**: :mod:`sopuli.config.references` resolves every name in
    the file against what it declares, in one pass, with one message. Growing a
    second dangling-name error here would be a second thing to learn about the
    same mistake -- and nothing can proceed past that check either way.

    ``env`` defaults to empty rather than to ``os.environ``: this layer does no
    I/O and reads no ambient state, so a caller that wants the process's own
    environment says so (``04-testing.md`` §4). ``vault_addr`` is
    ``--vault-addr``'s value and defaults to ``None`` for the same reason -- the
    command line is the caller's to supply, not this layer's to find.
    """
    stores = [vault.name for vault in config.vaults]
    active = default_store(env, config.defaults.vault)
    from_env, env_warnings = vault_env_contributions(env, stores=stores, active=active)
    from_cli = vault_cli_contributions(vault_addr, stores=stores, active=active)

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
    warnings: list[ConfigWarning] = list(env_warnings)
    for vault in config.vaults:
        # Layer 1 in front of layer 2, which is all the resolver needs: the two
        # are different layers, so it ranks them itself, and within a key the
        # list order only decides a tie that cannot happen between them.
        supplied = {
            key: [*from_cli.get(vault.name, {}).get(key, []), *contributions]
            for key, contributions in from_env.get(vault.name, {}).items()
        }
        for key, contributions in from_cli.get(vault.name, {}).items():
            supplied.setdefault(key, contributions)
        one, found = _merge(vault, by_name.get(vault.name, []), supplied)
        merged.append(one)
        warnings.extend(found)
    return tuple(merged), tuple(warnings)


def _merge(
    vault: Vault, patches: list[tuple[Layer, KeyPath, VaultPatch]], from_env: EnvKeys
) -> tuple[Vault, list[ConfigWarning]]:
    """One store, resolved key by key. Returns it and any defeated relaxation.

    **Every store goes through the resolver, including one nobody patched**
    (decision #428). A single contribution resolves to itself, so skipping the
    resolver for that store would give the same *value*. It would lose the
    provenance, and a store with no layers has provenance worth reporting:
    ``[vaults.vault-dev.addr]`` is the answer "the file wrote it, here", and it is
    only distinguishable from "nobody wrote it" because the pair exists.

    :attr:`~sopuli.config.model.Vault.patched` does not depend on this. It names
    the keys some *other* layer supplied, which is the ``layer is not OBJECT``
    test below.
    """
    values: dict[str, Any] = {}
    patched: list[str] = []
    settings: dict[str, Resolved] = {}
    warnings: list[ConfigWarning] = []

    for key in REACH_KEYS:
        answer = _resolve_key(key, vault, patches, from_env, at=ROOT.key("vaults").key(vault.name))
        if answer is None:
            continue
        values[key] = answer.value
        settings[key] = answer
        if answer.layer is not Layer.OBJECT:
            patched.append(key)

    tls, tls_patched, tls_settings, tls_warnings = _merge_tls(vault, patches, from_env)
    if tls is not None:
        values["tls"] = tls
    patched.extend(tls_patched)
    settings.update(tls_settings)
    warnings.extend(tls_warnings)

    auth = _highest(patch.auth for _, _, patch in patches)
    if auth is not None:
        # Whole-block replacement, so there is nothing to merge and nothing to
        # keep from the declaration. `replace` leaves the declaration's own block
        # in place when no layer wrote one.
        #
        # No `settings` entry, for the same reason: there is no `Resolved` to
        # report, one block having replaced another rather than a key having won.
        # `patched` names it, which is what the store's own table column reads.
        values["auth"] = auth
        patched.append("auth")

    return (
        replace(
            vault,
            patched=tuple(sorted(patched)),
            settings=tuple(sorted(settings.items())),
            **values,
        ),
        warnings,
    )


def _merge_tls(
    vault: Vault, patches: list[tuple[Layer, KeyPath, VaultPatch]], from_env: EnvKeys
) -> tuple[VaultTls | None, list[str], dict[str, Resolved], list[ConfigWarning]]:
    """``tls:`` one member at a time, so ``verify`` can ratchet.

    ``None`` when no layer wrote a ``tls:`` block at all, which keeps "no block"
    distinct from "an empty block" -- the same distinction
    :class:`~sopuli.config.model.VaultTls` keeps between a missing ``verify`` and
    a written one. ``VAULT_CACERT`` counts as a layer writing one: it supplies
    ``tls.ca_file``, and a store whose only ``tls:`` key came from the
    environment still has a block.
    """
    wrote_tls = any(key.startswith("tls.") for key in from_env)
    if vault.tls is None and not wrote_tls and all(patch.tls is None for _, _, patch in patches):
        return None, [], {}, []

    values: dict[str, Any] = {}
    patched: list[str] = []
    settings: dict[str, Resolved] = {}
    warnings: list[ConfigWarning] = []
    for key in TLS_KEYS:
        answer = _resolve_key(
            f"tls.{key}", vault, patches, from_env, at=ROOT.key("vaults").key(vault.name)
        )
        if answer is None:
            continue
        values[key] = answer.value
        settings[f"tls.{key}"] = answer
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
    return VaultTls(**values), patched, settings, warnings


def _resolve_key(
    key: str,
    vault: Vault,
    patches: list[tuple[Layer, KeyPath, VaultPatch]],
    from_env: EnvKeys,
    *,
    at: KeyPath,
) -> Resolved | None:
    """One key across the layers that spoke, through the one resolver.

    The declaration contributes at :attr:`~sopuli.settings.registry.Layer.OBJECT`
    -- P3's layer 4, "target/vault-level setting" -- and a ``defaults:`` patch at
    layer 5. The environment contributes at layer 2, already addressed to
    this store by :mod:`sopuli.config.vault_env`. Which is higher is the
    resolver's business and not restated here.

    **The answer is renamed to the concrete store on the way out**
    (decision #428). :func:`setting_name` is what the registry has to be asked
    with -- ``vaults.*.tls.verify``, for the reason its own docstring gives --
    and it is not what a reader can be told: the ``*`` stands for every store at once and is
    not a key anybody can edit. Two things quote the name back.
    :func:`~sopuli.settings.ratchet_note` puts it in the sentence a defeated
    ``tls.verify`` produces -- which reaches an operator twice, as a warning on
    every command that loads the file and as the continuation line under this
    store's row in ``config show --explain``. Without the rename, the text
    ``vaults.*.tls.verify stays true`` would sit directly beneath a row named
    ``vaults.vault-dev.tls.verify``.

    Renamed **here** rather than in either view, because there are two of them and
    they must not spell one sentence two ways -- the argument
    :func:`~sopuli.settings.render_value` makes about a value appearing in a table
    and in a note three lines below it. The registry lookup is unaffected; only
    the label the answer carries changes.
    """
    contributions = list(from_env.get(key, ()))
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
    answer = resolve(setting_name(key), contributions)
    return None if answer is None else replace(answer, setting=str(_at(at, key)))


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

"""§6's vault variables, as contributions to one store's settings.

The environment's half of C13. A store's settings belong to the store rather
than to the run, so ``vaults.<name>.*`` is merged **inside the file** rather than
through the invocation -- :mod:`sopuli.config.vault_layers` says why, and
:func:`sopuli.settings.sources.config_contributions` says the same thing from the
other end about a profile's block. This module is where layers 1 and 2 join that
merge, which is why it lives beside it rather than in
:mod:`sopuli.settings.sources` with the rest of §6's table.

Pure, like everything else in this package: the mapping is passed in and the
process supplies its own at the boundary.

Three shapes, and the difference between them is *which store they address*:

.. code-block::

    SOPULI_VAULT__VAULT_DEV__ADDR    one named store       layer 2
    SOPULI_VAULT_ADDR                the default store     layer 2
    VAULT_ADDR                       the default store     layer 2, below SOPULI_*

**The named form is the addressing C13 chose**, written the way §6 writes
nesting: ``SOPULI_`` plus an upper-snake path, ``__`` between the object and the
key. It is the same sentence as ``defaults.vaults.vault-dev.addr`` in the file,
and it is unambiguous by construction.

**"The default store" is the question the unnamed forms had to answer**, because
they name no store and a run touching two vaults has two active ones. It is the
store ``defaults.vault`` names -- with ``SOPULI_VAULT`` above it, being layer 2
of the same setting -- and where nothing names one the variable is **refused**
rather than quietly applied to whichever store a binding happened to reach. That
is C13's own argument: the rejected ``vault_settings:`` block was rejected for
following whichever store was active, which is how auth written for dev follows a
changed ``vault:`` into prod. A variable that did the same would be that block
with a different spelling.

The two halves of that answer are deliberately not symmetric:

* A ``SOPULI_*`` variable that cannot be placed is an **error**. It was set for
  this tool, by somebody who expects it to take effect, and §6's
  ``VAULT_SKIP_VERIFY`` note makes the case that silently doing nothing is worse
  than either honouring or refusing.
* A third-party variable that cannot be placed is a **warning**. ``VAULT_ADDR``
  is exported in every shell that has ever run ``vault``, and it was not set for
  this tool at all -- P3 honours it as a courtesy at the bottom of the chain.
  Failing a run over somebody else's variable would be this tool taking a
  position on an environment it does not own; saying so once, in
  ``diagnostics``, is the same information without the hostage-taking.

**The name-to-variable mapping has to refuse a collision.** ``-`` is not legal in
a variable name, so a store called ``vault-dev`` is addressed as ``VAULT_DEV`` --
and so is a store called ``vault_dev``. Where both are declared the variable is
ambiguous, and picking one of them silently is the failure this module is
arranged to avoid. It is refused when such a variable is actually **set**, rather
than at every load: two stores whose names differ only in punctuation are a legal
file, and the ambiguity is not real until something depends on it.

**An unrecognised variable under ``SOPULI_VAULT__`` is refused too**, naming the
stores that are declared and the keys that can be addressed. That prefix is this
tool's own namespace; a typo in it -- ``…__ADDRESS``, a renamed store -- would
otherwise be a variable somebody set, believes in, and never sees again. Only
``ADDR`` is addressable today, because §6's table lists no other, so the refusal
is also how the next key gets asked for.

``SOPULI_VAULT_TOKEN`` and ``VAULT_TOKEN`` are **not** here and will not be: they
are auth material, resolved by :mod:`sopuli.material` (ADR-007), and a token is
not a setting -- it must never reach ``invocation.options``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from types import MappingProxyType

from sopuli.config.codes import THIRD_PARTY_VARIABLE_UNAPPLIED
from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.model import ConfigWarning
from sopuli.settings import Contribution, Layer, Resolved, resolve

#: This tool's namespace for addressing one *named* store, and the separator §6
#: uses for nesting. Spelled once each, because the prefix is matched as well as
#: built -- see :func:`_named`.
PREFIX = "SOPULI_VAULT__"
SEPARATOR = "__"

#: The variable that names the default store, and the setting it supplies. It is
#: a store *name*, not a setting of one, which is C13 in one row of §6's table.
#: :mod:`sopuli.settings.sources` imports both rather than spelling them again:
#: the boundary resolves the same setting for ``invocation.options``, and two
#: spellings of one variable is one typo away from two behaviours.
DEFAULT_STORE_VARIABLE = "SOPULI_VAULT"
DEFAULT_STORE_SETTING = "vault"

#: The one flag that hoists a store's setting onto the command line, and layer 1
#: of ``vaults.*.addr`` (decision #422). Spelled once, here rather than in
#: :mod:`sopuli.cli`, because the string is both the option click parses and the
#: ``source_detail`` a refusal names -- and :data:`~sopuli.material.TOKEN_FLAG`
#: already set that precedent for the same reason.
#:
#: There is no ``--vault-mount`` beside it and no named ``--vault-addr NAME=URL``.
#: See :func:`vault_cli_contributions`.
ADDR_FLAG = "--vault-addr"

#: What the named form may address, as the variable spells it, mapped to the
#: setting key :mod:`sopuli.config.vault_layers` merges. One entry, matching §6's
#: table; a second one is a line here and a row there.
NAMED_KEYS: Mapping[str, str] = MappingProxyType({"ADDR": "addr"})

#: ``SOPULI_*`` variables that address the default store. Layer 2.
ACTIVE_VARIABLES: Mapping[str, str] = MappingProxyType({"SOPULI_VAULT_ADDR": "addr"})

#: Vault's own variables, honoured at layer 2 -- below their ``SOPULI_*``
#: equivalent where there is one (P3). ``VAULT_CACERT`` is a path to a
#: PEM-encoded CA certificate, which is ``tls.ca_file``; ``VAULT_CAPATH`` is
#: absent because §6's list is, and an unlisted variable is one nobody has asked
#: for yet.
#:
#: ``VAULT_SKIP_VERIFY`` is not here on purpose. It is read and **refused** by
#: :func:`sopuli.settings.sources.env_contributions`, because it names a setting
#: under the safety ratchet (§6, ADR-005).
THIRDPARTY_VARIABLES: Mapping[str, str] = MappingProxyType(
    {
        "VAULT_ADDR": "addr",
        "VAULT_NAMESPACE": "namespace",
        "VAULT_CACERT": "tls.ca_file",
    }
)

#: What a caller with no environment passes. Empty rather than ``os.environ``:
#: reading the process's own here would make every config test depend on the
#: shell it ran in (``04-testing.md`` §4).
NO_ENV: Mapping[str, str] = MappingProxyType({})


def variable_segment(store: str) -> str:
    """How a store's name is spelled inside a variable name.

    ``upper()`` with ``-`` written as ``_``, because a hyphen is not legal in an
    environment variable name on any platform this tool runs on. Not injective --
    see :func:`_refuse_collision`, which refuses the ambiguity rather than
    resolving it.
    """
    return store.upper().replace("-", "_")


def named_variable(store: str, key: str) -> str:
    """The variable addressing ``key`` of ``store`` -- ``SOPULI_VAULT__VAULT_DEV__ADDR``."""
    return f"{PREFIX}{variable_segment(store)}{SEPARATOR}{key}"


def default_store(env: Mapping[str, str], declared: str | None) -> Resolved | None:
    """Which store the unnamed variables address, and where that name came from.

    ``SOPULI_VAULT`` over ``defaults.vault``, through the one resolver rather
    than an ``or`` -- so the answer carries a location and the messages below can
    name the thing to go and edit.

    ``None`` when neither spoke, which is not an error by itself: a file naming a
    store on every target needs no default, and only a variable that depends on
    one makes the absence matter. The same goes for a name that resolves to no
    declared store -- it is refused by whoever *depends* on the answer, below,
    rather than here. ``defaults.vault`` already has such a caller in
    :func:`sopuli.config.references.check_references`; ``SOPULI_VAULT`` has
    one too (decision #250): :func:`sopuli.config.binding_stores.complete` reads
    the variable directly to fill a binding's store at plan time (C15). It
    resolves the name itself rather than calling this, because the two answer
    different questions -- this one is *which store §6's unnamed variables address*.

    The boundary resolves this same setting again for ``invocation.options``
    (:mod:`sopuli.settings.sources`). Both build the same two contributions and
    hand them to the same resolver, so they cannot disagree; what they cannot
    share is the *moment*, since ``defaults.vault`` is not known until the file
    has been read and the declared stores are not known before that either.
    """
    contributions = []
    asked = env.get(DEFAULT_STORE_VARIABLE, "")
    if asked:
        contributions.append(
            Contribution(layer=Layer.ENV, value=asked, detail=DEFAULT_STORE_VARIABLE)
        )
    if declared is not None:
        contributions.append(
            Contribution(layer=Layer.DEFAULTS, value=declared, detail="defaults.vault")
        )
    return resolve(DEFAULT_STORE_SETTING, contributions)


def vault_env_contributions(
    env: Mapping[str, str],
    *,
    stores: Sequence[str],
    active: Resolved | None,
) -> tuple[dict[str, dict[str, list[Contribution]]], tuple[ConfigWarning, ...]]:
    """§6's vault variables as contributions, keyed by store and then by setting key.

    ``stores`` is what the file declares, and it is the whitelist (invariant 5):
    a variable supplies a setting of a declared store and can never bring one
    into existence.

    ``active`` is :func:`default_store`'s answer, passed in rather than computed
    here so that one caller reads the file once.
    """
    found: dict[str, dict[str, list[Contribution]]] = {}
    for store, key, contribution in _named(env, stores):
        found.setdefault(store, {}).setdefault(key, []).append(contribution)
    unnamed, warnings = _unnamed(env, stores=stores, active=active)
    for store, key, contribution in unnamed:
        # After the named form, deliberately. Both are layer 2 and the resolver
        # keeps a caller's order within one layer, so
        # `SOPULI_VAULT__VAULT_DEV__ADDR` wins over `SOPULI_VAULT_ADDR` for a
        # store that is both named and default: the more specific request is the
        # one that was typed about *this* store.
        found.setdefault(store, {}).setdefault(key, []).append(contribution)
    return found, warnings


def _named(env: Mapping[str, str], stores: Sequence[str]) -> list[tuple[str, str, Contribution]]:
    """``SOPULI_VAULT__<NAME>__<KEY>``, matched by generating the names.

    Generated and looked up rather than parsed: a store name may itself contain
    ``_`` -- or, in a file somebody will eventually write, ``__`` -- and splitting
    a variable on the separator would have to guess where the name ends. Building
    the variable each declared store *would* answer to leaves nothing to guess,
    and it is also what makes a collision visible: two stores generate one name.
    """
    claims: dict[str, list[tuple[str, str]]] = {}
    for store in stores:
        for spelling, key in NAMED_KEYS.items():
            claims.setdefault(named_variable(store, spelling), []).append((store, key))

    found = []
    for variable, claimants in sorted(claims.items()):
        raw = env.get(variable, "")
        if not raw:
            continue
        if len(claimants) > 1:
            _refuse_collision(variable, [store for store, _ in claimants])
        store, key = claimants[0]
        found.append((store, key, Contribution(layer=Layer.ENV, value=raw, detail=variable)))

    _refuse_unrecognised(env, known=set(claims), stores=stores)
    return found


def _refuse_collision(variable: str, claimants: Sequence[str]) -> None:
    """Two declared stores, one variable spelling. Name both and stop.

    The whole reason :func:`variable_segment` is documented as not injective. A
    tool that picked one of them would be writing an address into whichever store
    sorted first, which is a coin toss between two vaults -- exactly the class of
    mistake "vault is master" exists to make impossible.
    """
    names = ", ".join(f"`{one}`" for one in sorted(claimants))
    raise ConfigError(
        f"{variable} is set, and {len(claimants)} declared stores answer to it: {names}",
        at=ROOT,
        hint=(
            "a store's name becomes a variable by upper-casing it and writing `-` as "
            "`_`, so these are one variable -- rename one of the stores, or write the "
            "setting under `vaults:` in the file, where the name is exact"
        ),
    )


def _refuse_unrecognised(env: Mapping[str, str], *, known: set[str], stores: Sequence[str]) -> None:
    """Anything under ``SOPULI_VAULT__`` that addresses nothing.

    A renamed store, a mistyped key, a store the file never declared. Every one
    of them is a variable somebody set on purpose, and ignoring it is the failure
    §6 spells out for ``VAULT_SKIP_VERIFY``: the operator believes it took effect.

    Deliberately the whole prefix rather than only the key part: a name that is
    wrong is as silent as a key that is wrong, and invariant 5 already says a
    variable cannot address a store the file does not declare.
    """
    for variable in sorted(env):
        if not variable.startswith(PREFIX) or not env[variable] or variable in known:
            continue
        declared = (
            ", ".join(f"`{one}` ({named_variable(one, 'ADDR')})" for one in sorted(stores))
            if stores
            else "none -- there is no `vaults:`"
        )
        raise ConfigError(
            f"{variable} addresses no setting of any declared store",
            at=ROOT,
            hint=(
                f"the form is {PREFIX}<STORE>{SEPARATOR}<KEY>, with `-` in a store name "
                f"written as `_`. Addressable keys: {', '.join(sorted(NAMED_KEYS))}. "
                f"Declared stores: {declared}"
            ),
        )


def vault_cli_contributions(
    addr: str | None, *, stores: Sequence[str], active: Resolved | None
) -> dict[str, dict[str, list[Contribution]]]:
    """``--vault-addr``, placed on the default store (decision #422). Layer 1.

    In this module rather than beside the flag, and that is the decision rather
    than convenience. §6 already answers "which store does an unnamed setting
    address" -- the one ``SOPULI_VAULT`` or ``defaults.vault`` names, refusing
    where neither does, never the store the current binding happened to resolve
    to (C13's rejected `vault_settings:`). A flag resolving that question
    its own way would be a *second definition of the default store*, one layer
    above the first, and the two would agree until the day they did not. So it
    goes through :func:`_place`, which is the same code the variables use.

    **There is no named form**, decided with the flag itself. The environment has
    ``SOPULI_VAULT__<NAME>__ADDR`` for a run that touches two stores, and adding
    ``--vault-addr NAME=URL`` would put a third ``K=V`` grammar on a command line
    that has one. The analogy that settled it is ``--vault-token-file``, which is
    unnamed for the same reason -- with one crack worth knowing about: a token is
    plausibly the same across the stores one run touches and an address is
    definitionally per-store, so the multi-store case here really does fall back
    to the environment rather than merely preferring it.

    Returns the same shape :func:`vault_env_contributions` does, and no warnings:
    a flag the operator typed is never quietly dropped.
    """
    if not addr:
        return {}
    placed, _ = _place([(ADDR_FLAG, "addr", Layer.CLI, addr)], stores=stores, active=active)
    found: dict[str, dict[str, list[Contribution]]] = {}
    for store, key, contribution in placed:
        found.setdefault(store, {}).setdefault(key, []).append(contribution)
    return found


def _unnamed(
    env: Mapping[str, str], *, stores: Sequence[str], active: Resolved | None
) -> tuple[list[tuple[str, str, Contribution]], tuple[ConfigWarning, ...]]:
    """The variables that name no store, placed on the default one.

    Sorted so that a run reports these in the same order whatever order the
    environment iterates in. ``SOPULI_*`` and third-party are different layers,
    so the resolver ranks them itself and this does not.
    """
    asked = sorted(
        [
            (variable, key, Layer.ENV, env[variable])
            for variable, key in ACTIVE_VARIABLES.items()
            if env.get(variable)
        ]
        + [
            (variable, key, Layer.ENV_THIRDPARTY, env[variable])
            for variable, key in THIRDPARTY_VARIABLES.items()
            if env.get(variable)
        ]
    )
    return _place(asked, stores=stores, active=active)


def _place(
    asked: Sequence[tuple[str, str, Layer, str]],
    *,
    stores: Sequence[str],
    active: Resolved | None,
) -> tuple[list[tuple[str, str, Contribution]], tuple[ConfigWarning, ...]]:
    """Put every source that names no store onto the default one, or say why not.

    One function for the variables and the flag (decision #422), so that
    "which store is the active one" has exactly one answer however it was asked.
    ``asked`` is ``(where it was written, setting key, layer, value)``.

    **Everything this tool owns refuses; only a third-party variable warns.** The
    split is §6's and it is about whose environment it is: ``SOPULI_VAULT_ADDR``
    and ``--vault-addr`` were written for this tool, so doing nothing silently is
    worse than either honouring or refusing, while ``VAULT_ADDR`` is exported in
    every shell that has run `vault` and failing a run over somebody else's
    variable would be taking a position on an environment the tool does not own.
    """
    if not asked:
        return [], ()

    store = None if active is None else str(active.value)
    if store is not None and store in stores:
        return [
            (store, key, Contribution(layer=layer, value=value, detail=where))
            for where, key, layer, value in asked
        ], ()

    warnings = []
    for where, _, layer, _value in asked:
        if layer is not Layer.ENV_THIRDPARTY:
            _refuse_unplaceable(where, store=store, active=active, stores=stores)
        if store is not None and active is not None and active.layer is not Layer.ENV:
            # A dangling `defaults.vault` is `check_references`' finding, and it
            # runs a few lines after this one with the message every other
            # dangling name in the file gets. Saying it here as well would be one
            # mistake reported twice, in two phrasings.
            continue
        warnings.append(_unplaceable_warning(where, store=store, active=active))
    return [], tuple(warnings)


def _refuse_unplaceable(
    where: str, *, store: str | None, active: Resolved | None, stores: Sequence[str]
) -> None:
    """A ``SOPULI_*`` variable or ``--vault-addr`` with no store to apply to.

    ``where`` is the variable name or the flag, which is what the operator has to
    go and change; the three fixes in the hint are the same either way.
    """
    if store is None:
        raise ConfigError(
            f"{where} names no store, and this run has no default one to apply it to",
            at=ROOT,
            hint=(
                f"it applies to the store `defaults.vault` names -- write one, export "
                f"{DEFAULT_STORE_VARIABLE}=<store>, or address a store directly with "
                f"{PREFIX}<STORE>{SEPARATOR}<KEY>"
            ),
        )
    known = ", ".join(f"`{one}`" for one in sorted(stores)) if stores else "none"
    # Not `where`: the two are different halves of the sentence -- what the
    # operator wrote, and what named the store it could not be placed on.
    named_by = "the environment" if active is None else active.location
    raise ConfigError(
        f"{where} applies to the default store {store!r}, which is not declared",
        at=ROOT,
        hint=f"{named_by} names it; declared vaults: {known}",
    )


def _unplaceable_warning(
    where: str, *, store: str | None, active: Resolved | None
) -> ConfigWarning:
    """A third-party variable this run had nowhere to put.

    A warning rather than an error, and rather than nothing at all -- see the
    module note. It fires only when the default store is missing or dangling, so
    a shell with ``VAULT_ADDR`` exported and a file that names a default store
    says nothing at all.
    """
    if store is None:
        return ConfigWarning(
            message=(
                f"{where} is set and was not applied: this run has no default store, "
                f"and a third-party variable names none"
            ),
            at="",
            hint=(
                f"P3 honours it as a setting of the store `defaults.vault` names, below "
                f"{DEFAULT_STORE_VARIABLE} -- write `defaults.vault`, or ignore this if "
                f"the variable belongs to something else on this machine"
            ),
            code=THIRD_PARTY_VARIABLE_UNAPPLIED,
        )
    named_by = "the environment" if active is None else active.location
    return ConfigWarning(
        message=(
            f"{where} is set and was not applied: the default store {store!r} "
            f"({named_by}) is not declared"
        ),
        at="",
        hint="declare it under `vaults:`, or correct the name",
        code=THIRD_PARTY_VARIABLE_UNAPPLIED,
    )

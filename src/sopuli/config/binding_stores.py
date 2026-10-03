"""Which store a binding uses, once the run is known (C15's plan-time half, #250).

A store can be named in **seven** places. `_vault_for` resolves five of them
while the file is being read -- the ref's own prefix, the application entry's
``vault:``, an ``overrides:`` patch's, the target's, and ``defaults.vault`` --
which is the same list ``bindings._check_has_somewhere_to_resolve_from`` recites
and the same one this module's refusal offers back. The other two are
deliberately **not** in that chain: a profile's ``vault:`` and ``SOPULI_VAULT``,
because both are properties of a *run* and bindings are built once, at load.

So a perfectly good file can finish loading with ``binding.vault is None``, and
#118 decided that is a real temporary state rather than an error: `config show
--resolved` renders it ``-``, and the command that actually needs a store is what
fails.

This module is the step that turns the temporary state into an answer, and the
refusal for when it cannot.

**Gap-filling, never overriding.** A binding that resolved a store at load keeps
it, whatever the environment says. That is what C15 means by "may still supply
one", and it is the only reading that is safe: a target naming its own store is a
statement about that database, and an exported ``SOPULI_VAULT`` -- which is a
property of the shell a run happened to start in -- must not silently redirect a
rotation to a different vault. The variable fills holes; it does not repoint
arrows.

**Not a registry setting, and that is #250's decision** (option 2 of two). The
tempting alternative was to widen ``vault`` in :mod:`sopuli.settings.registry` to
accept ``Layer.PROFILE`` and let the one resolver answer this. It was rejected
because that setting means something narrower than it looks: it answers *which
store §6's unnamed variables address* (:func:`sopuli.config.vault_env.default_store`),
and a binding's store is a different question wearing the same name. Merging the
two would make ``invocation.options`` report one number for two decisions, and
:attr:`sopuli.settings.registry.Setting.layers` would stop describing the setting
it is attached to. The chain here is two candidates long and written out; when it
grows a third, that is the moment to reconsider, not before.

**The precedence is still P3's**, hand-applied rather than reimplemented:
``SOPULI_VAULT`` is layer 2 and a profile is layer 3, so the variable wins. Both
sit above ``defaults.vault`` at layer 5, which the load-time chain already
consulted -- consistent, because this only runs where that chain found nothing.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace

from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.model import Binding, Config
from sopuli.config.vault_env import DEFAULT_STORE_VARIABLE, NO_ENV

__all__ = ["NoStoreError", "complete", "refuse_unresolved", "unresolved"]


class NoStoreError(ConfigError):
    """A binding names a secret, and after the run is known still has no store.

    Exit 9 and category ``config``, inherited: the remedy is to edit the file or
    to set a variable, which is the distinction :attr:`~sopuli.exit_codes.ExitCode.CONFIG_INVALID`
    draws against exit 2's "fix your command line". It is a subclass rather than
    a bare :class:`~sopuli.config.errors.ConfigError` so that a caller can tell
    this apart from the file being malformed -- the file may be entirely valid
    and merely invoked without the profile it was written for.
    """


@dataclass(frozen=True)
class _Candidate:
    """One place a run can name a store, and what to call it in a message."""

    name: str
    location: str


def complete(config: Config, *, env: Mapping[str, str] = NO_ENV) -> Config:
    """Fill in the store for bindings that reached load without one.

    Returns ``config`` itself when there is nothing to fill, so a caller can run
    this unconditionally: the overwhelmingly common case is a file that names its
    stores, and that case allocates nothing.

    The store name is validated against ``vaults:`` **at the point it is used**,
    not when it is read. A ``SOPULI_VAULT`` naming an undeclared store is only
    wrong for a run that needed it -- :func:`~sopuli.config.vault_env.default_store`
    defers the same check to "whoever depends on the answer", and this is that
    caller. Exported variables outlive the shell they were meant for, and
    refusing a run that never consulted one would be this tool taking a position
    on an environment it does not own.
    """
    candidate = _candidate(config, env=env)
    if candidate is None:
        return config
    if not any(_needs_store(binding) for binding in config.bindings):
        return config

    _refuse_dangling(candidate, config)
    return replace(
        config,
        bindings=tuple(
            replace(binding, vault=candidate.name) if _needs_store(binding) else binding
            for binding in config.bindings
        ),
    )


def unresolved(config: Config) -> tuple[Binding, ...]:
    """Bindings that name a secret and still have nowhere to read it from.

    Asked of the bindings rather than of a :class:`~sopuli.plan.Plan`, because a
    plan cannot answer it: `plan.units[].secret` is omitted both for a binding
    with no ref at all and for one whose store is unknown, and only the second is
    a problem. The distinction survives here and nowhere else.
    """
    return tuple(binding for binding in config.bindings if _needs_store(binding))


def refuse_unresolved(config: Config, *, action: str) -> None:
    """Stop a command that needs a store for a binding which has none.

    Invariant 4: fail at **plan time**, naming the thing and the target, rather
    than partway through with a generic error. This is the refusal C15 (#118)
    put in "the command that actually needs a store", and the reason it lives
    here rather than in :mod:`sopuli.plan` is that a plan is a pure function of
    the config while this depends on the environment the run started in.

    ``action`` is what the command was about to do, because "no store" without it
    leaves the operator to work out which half of their command needed one --
    `config show` over the same file is fine, and saying so implicitly is worth a
    word.

    The message names **one** binding rather than all of them. A file invoked
    without its profile produces this for every binding it declares, and a
    hundred identical lines differing only in an account name is a wall an
    operator scrolls past; the count says how many there are, and the first says
    what the problem looks like.
    """
    outstanding = unresolved(config)
    if not outstanding:
        return
    first = outstanding[0]
    others = "" if len(outstanding) == 1 else f" (and {len(outstanding) - 1} more of the same)"
    raise NoStoreError(
        f"{action} needs a store for {first.account!r} in {first.target!r}, "
        f"and nothing has named one{others}",
        hint=(
            f"name a store on the ref, the application entry, an override, the target, "
            f"or `defaults.vault` -- or, for this run only, "
            f"`--profile <one with vault:>` or {DEFAULT_STORE_VARIABLE}=<store>"
        ),
    )


def _needs_store(binding: Binding) -> bool:
    """Whether this binding has something to read and nowhere to read it from.

    A binding with no ref at all is **not** this. §3 makes ``secret`` optional and
    an application that declares no ref has nothing to resolve -- it is the
    ordinary shape of a config that only ever runs `doctor`, and refusing it
    would make a store mandatory for commands that never open one.
    """
    return binding.secret is not None and binding.vault is None


def _refuse_dangling(candidate: _Candidate, config: Config) -> None:
    """A run named a store, and the file declares no such store.

    Phrased here rather than through :func:`~sopuli.config.references.dangling`,
    which is the one place that phrasing normally lives. That helper reports
    against a :class:`~sopuli.config.errors.KeyPath` -- the line in the file that
    wrote the name -- and half the names that reach this function were never in
    the file at all. ``SOPULI_VAULT`` has no key path, and an error that dropped
    the attribution would leave an operator searching a file for a name their
    shell supplied.

    So this follows the neighbour that had the same problem:
    :func:`sopuli.config.vault_env._refuse_unplaceable` also reports a bad store
    name from the environment, also points ``at`` the document as a whole, and
    also carries *where the name came from* in the hint. Two functions with one
    shape rather than one function with two.

    **In practice only the environment can reach this.**
    :func:`~sopuli.config.references.check_references` resolves
    ``profiles.<name>.vault`` at load for *every declared* profile, not only the
    active one, so a profile's name has already been checked against ``vaults:``
    before a run gets here. The candidate is still checked rather than trusted:
    the guard costs one set lookup, and what makes the profile safe is a rule in
    another module that this one would otherwise be silently depending on.
    """
    declared = {vault.name for vault in config.vaults}
    if candidate.name in declared:
        return
    known = ", ".join(f"`{one}`" for one in sorted(declared)) if declared else "none"
    raise NoStoreError(
        f"the store {candidate.name!r} this run selected is not declared",
        at=ROOT,
        hint=f"{candidate.location} names it; declared vaults: {known}",
    )


def _candidate(config: Config, *, env: Mapping[str, str]) -> _Candidate | None:
    """The store a run can supply, in P3's order, or ``None``.

    Two layers, highest first. The location travels with the name because it is
    the whole content of the eventual error: a run redirected to the wrong vault
    by an exported variable is only debuggable if the message says the variable
    is what did it.
    """
    asked = env.get(DEFAULT_STORE_VARIABLE, "")
    if asked:
        return _Candidate(asked, DEFAULT_STORE_VARIABLE)
    profile = config.active_profile
    if profile is not None and profile.vault is not None:
        return _Candidate(profile.vault, f"profiles.{profile.name}.vault")
    return None

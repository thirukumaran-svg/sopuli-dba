"""Which module serves a ``vaults.*.type``, imported on first use (ADR-006).

[ADR-006](../../docs/decisions/adr-006-optional-dependencies.md) is the
specification, and this is rules 1 and 2 of it:

1. a vendor client is imported inside its backend module, never at package
   import time -- so this maps ``type:`` to a *module path* and imports it when
   something actually connects;
2. a missing backend is a diagnosable condition, not a traceback.

Rule 3 -- nothing in base opens a socket -- is what the two above are in service
of, and it is held by a test rather than by this module
(``tests/store/test_install_shape.py``).

**Not a plugin system.** The mapping below is a literal, in-tree, per D6 and
ADR-006's non-goals. Extras control which dependencies are installed, not which
modules exist; installing a package cannot register a backend.

Declaring a store is config and reaching one is not (``01-configuration.md``
§3a). Everything in this module is on the second side of that line: a config
naming many backends loads, validates and prints with none of them installed,
and nothing here runs until a command resolves a store to a client.
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

from sopuli.config.errors import ConfigError
from sopuli.config.model import Vault
from sopuli.extras import MISSING_CLIENT, MISSING_MODULE, install_command, missing_kind
from sopuli.extras import installed as extras_installed
from sopuli.store.protocol import SecretStore

#: ``error.code`` for a configured backend whose client is not installed
#: (``03-json-output.md`` §3). Carried so a consumer can branch on this case
#: without parsing the message.
BACKEND_NOT_INSTALLED = "SOPULI-20001"

#: ``error.code`` for a backend type this build has no module for. Its own code,
#: apart from :data:`sopuli.driver.registry.DRIVER_NOT_IMPLEMENTED`, for the
#: reason ``SOPULI-20001`` and ``SOPULI-20002`` are two: a store and a database
#: are different outages.
BACKEND_NOT_IMPLEMENTED = "SOPULI-20005"


@dataclass(frozen=True)
class Backend:
    """What is behind one ``vaults.*.type``.

    ``provides`` is the part that is easy to leave out and is the whole reason
    this is a dataclass rather than a string: it is the set of **top-level
    modules that installing** ``extra`` **adds**, which is what lets
    :func:`resolve` tell "the operator has not installed this" from "we have a
    typo in our own import". Both arrive as ``ModuleNotFoundError``.
    """

    #: Dotted path of the module implementing the backend.
    module: str
    #: The extra that installs its client, or ``None`` where there is nothing to
    #: install -- see :data:`BACKENDS`.
    extra: str | None = None
    #: Top-level module names ``pip install "sopuli-dba[<extra>]"`` makes importable.
    provides: frozenset[str] = frozenset()

    @property
    def install_command(self) -> str:
        """The line an operator can paste, for the message that names it.

        ``sopuli-dba``, not ``sopuli``. D1 splits the two -- the binary is
        ``sopuli`` and the distribution is ``sopuli-dba`` -- and this string is
        the one place the difference is load-bearing rather than cosmetic,
        because it is the half the operator pastes into `pip`.

        Spelled in :mod:`sopuli.extras`, so that the store and the driver cannot
        disagree about it.
        """
        assert self.extra is not None
        return install_command(self.extra)


#: Every ``type:`` :data:`~sopuli.config.vaults.VAULT_TYPES` allows, and what
#: serves it. The two lists are checked against each other by
#: ``tests/store/test_backend_registry.py``: a type the config layer accepts and this one
#: has never heard of would fail at connect time with a :class:`KeyError`, which
#: is precisely the traceback rule 2 exists to prevent.
#:
#: ``file`` and ``keyring`` have **no extra**, and that is not an oversight.
#: ADR-006's named gap: P2 does not say whether the file backend reaches age/gpg
#: as a Python library or as a subprocess, and the answer decides whether there
#: is an extra at all -- a library makes it ``sopuli-dba[file]``, a subprocess makes
#: it a runtime prerequisite like Instant Client. ``keyring`` is priority 4 and
#: appears in no extras table yet. Until either is settled, ``extra=None`` means
#: "there is nothing to tell you to install", and asking for one of them fails as
#: *not implemented in this build* rather than as a pip problem -- which is true,
#: and is the message that does not send somebody to `pip` for something `pip`
#: cannot fix.
BACKENDS: dict[str, Backend] = {
    "hashicorp": Backend(
        module="sopuli.store.hashicorp",
        extra="hashicorp",
        # ADR-005/E2: the client is `httpx` and there is no vendor SDK, which
        # changes nothing here -- rule 3 names the installed dependency set, and
        # a generic HTTP client in base is as visible to it as an SDK would be.
        provides=frozenset({"httpx"}),
    ),
    "oci": Backend(
        module="sopuli.store.oci",
        extra="oci",
        provides=frozenset({"oci"}),
    ),
    "file": Backend(module="sopuli.store.file"),
    "keyring": Backend(module="sopuli.store.keyring"),
}


class BackendNotInstalledError(ConfigError):
    """A configured backend's client is not installed on this machine.

    ``config`` and exit 9, not ``capability`` (ADR-006, E5). ``capability`` names
    something a *target* cannot do -- a property of the database at the far end
    that no local action changes. This is the opposite: it is fixed on this
    machine, by the person reading the message, with the command in the message.
    Exit 9 already means "fix your configuration, not your command line" (P5).
    """

    code = BACKEND_NOT_INSTALLED


class BackendNotImplementedError(ConfigError):
    """This build has no module for a backend the config file may legitimately
    name.

    A separate class from :class:`BackendNotInstalledError` because the two are
    the same ``ModuleNotFoundError`` and completely different problems. Nothing
    the operator installs fixes this one, so it must never carry an install line
    -- and it is reachable, because `01-configuration.md` §3a accepts backend
    types that :data:`BACKENDS` maps to a module this build does not have.

    It has a code because the configuration is right and there is nothing to
    install, so a consumer must tell it from the ``config`` errors that a change
    to either fixes (J3).
    """

    code = BACKEND_NOT_IMPLEMENTED


def installed(backend: Backend) -> bool:
    """Whether ``backend``'s client is importable, **without importing it**.

    :func:`sopuli.extras.installed` is the mechanism, shared with the driver
    registry. A backend with no extra is vacuously installed -- there is no
    client to look for -- which keeps ``config validate`` quiet about ``file``
    and ``keyring`` rather than warning that something unnamed is missing, and
    the roadmap gap surfaces at :func:`resolve` where it belongs.
    """
    return extras_installed(backend.provides)


def resolve(vault: Vault) -> ModuleType:
    """Import the module serving ``vault``'s ``type:``, or say why it cannot.

    **Fails closed**, the same rule ``sopuli/store/hashicorp/_errors.py`` uses
    for an unrecognised 400 (ADR-005): three different failures all arrive as
    ``ModuleNotFoundError`` and only one of them is "install the extra", so this
    matches the two it can name exactly and re-raises everything else.

    ============================================ ==================================
    What actually happened                       What the operator is told
    ============================================ ==================================
    the extra's client is not installed          :class:`BackendNotInstalledError`
    this build has no module for that backend    :class:`BackendNotImplementedError`
    a bad import *inside* a backend module       the traceback, unchanged
    ============================================ ==================================

    The third row is the one a bare ``except ImportError`` gets wrong, and it is
    the expensive mistake: it sends somebody to `pip` forever over a typo of
    ours. It re-raises here because a module that exists and cannot import
    itself is a bug in this project, and reporting it as anything else buys the
    user a wrong instruction and costs us the stack trace.

    Returns the module. What a backend module must expose is stated in
    :func:`connect`, not here.
    """
    backend = BACKENDS[vault.type]
    try:
        return importlib.import_module(backend.module)
    except ModuleNotFoundError as exc:
        kind = missing_kind(
            exc, module=backend.module, provides=backend.provides, extra=backend.extra
        )
        if kind == MISSING_CLIENT:
            raise BackendNotInstalledError(
                f'vault "{vault.name}" declares type "{vault.type}", '
                f"but that backend is not installed",
                # No `at=`: the message names the store already, and
                # `01-configuration.md` §3a quotes this line verbatim. A
                # `vaults.<name>:` breadcrumb in front of a sentence that opens
                # with the same name reads as a stutter.
                hint=f"install it with:  {backend.install_command}",
            ) from exc
        if kind == MISSING_MODULE:
            raise BackendNotImplementedError(
                f'vault "{vault.name}" declares type "{vault.type}", '
                f"but this build has no {vault.type} backend yet",
                hint="this is not something to install -- the backend is not written yet",
            ) from exc
        raise


def connect(vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None) -> SecretStore:
    """An authenticated store for ``vault``, whichever backend serves it.

    **This settles what a backend module must expose**, which :func:`resolve`
    deliberately left open until there was an implementation to hold the
    contract: a module named in :data:`BACKENDS` provides

    .. code-block:: python

        def connect(vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None)
            -> SecretStore

    and nothing else is required of it. :mod:`sopuli.store.hashicorp` defines it
    that way; this is the one line that says every backend must, rather than
    each caller learning the shape from whichever module it happened to import.

    ``env`` is passed rather than read, for the reason the rest of the tool
    passes it: half of §3a's auth material lives in the environment, and a
    function that reaches for :data:`os.environ` itself cannot be tested against
    a different one.

    ``token_file`` is ``--vault-token-file``'s path, forwarded because C16
    decided what the flag takes: a **path**, because a token as a command-line
    value is what invariant 1 forbids. It stays a location all the way down --
    the value is read on §3a's chain in :func:`sopuli.material.resolve_token` --
    so no signature between the CLI and the chain has a slot a credential could
    sit in. A caller that already holds a token goes to the backend directly,
    which is what :func:`sopuli.store.hashicorp.open_store` is for.

    Calling this is what makes a run *reach* a store, which is the line
    ``01-configuration.md`` §3a draws: declaring a store is config, and reaching
    one is not. Every failure below that line -- a missing client, a refused
    login, an unreachable host -- arrives from here rather than from the loader.
    """
    module = resolve(vault)
    # No `getattr` guard. A module in `BACKENDS` that does not define `connect`
    # is a bug in this project, and an `AttributeError` naming the module is a
    # better report of it than a message telling the operator to install
    # something -- the same reasoning as `resolve`'s third row.
    store: SecretStore = module.connect(vault, env=env, token_file=token_file)
    return store

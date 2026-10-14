"""Which module serves a ``targets.*.type``, imported on first use.

ADR-006 rules 1 and 2, applied to drivers exactly as they are applied to
stores. A vendor client is imported inside its own module when something
actually connects, and a target declaring a driver this machine has not
installed is a structured error naming the extra that supplies it:

.. code-block:: text

    $ sopuli creds check --application acme
    error: target "cdb1-pdb-orders" declares type "oracle", but that driver is not installed
           install it with:  pip install "sopuli-dba[oracle]"
    exit 9

**Why a driver is an extra at all** (D9, E1): ``python-oracledb`` exists only to
reach Oracle. Binding stores and not drivers would read as arbitrary, and D3
already makes reaching Oracle a per-site runtime condition, since Instant Client
has to be installed either way.

**Two registries, one mechanism.** :mod:`sopuli.extras` holds what this shares
with :mod:`sopuli.store.registry` -- looking a module up without importing it,
and the three-way reading of a ``ModuleNotFoundError``. What stays here is the
noun and the wording: a store is named by ``vaults:`` and a driver by a target's
``type:``, and a message that tried to serve both would name neither. The
subtlety is shared because it is subtle; the sentences are not shared because
they are not the same sentence.

**Not a plugin system** (D6). The mapping below is a literal, in-tree dict.
Extras control which dependencies are installed, not which modules exist, so
installing a package cannot register a driver.

Declaring a driver is config and reaching one is not. A file naming a target
loads, validates and prints with nothing installed; only connecting needs the
client.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from types import ModuleType

from sopuli.config.errors import ConfigError
from sopuli.config.model import Target
from sopuli.extras import MISSING_CLIENT, MISSING_MODULE, install_command, missing_kind
from sopuli.extras import installed as extras_installed

#: ``error.code`` for a configured driver whose client is not installed
#: (``03-json-output.md`` §3), so a consumer can branch on this case without
#: parsing the message.
#:
#: The next number after ``SOPULI-20001``, its store equivalent (J3).
DRIVER_NOT_INSTALLED = "SOPULI-20002"


@dataclass(frozen=True)
class DatabaseDriver:
    """What is behind one ``targets.*.type``.

    ``provides`` is the field that makes the difference between "the operator
    has not installed this" and "we have a typo in our own import", since both
    arrive as ``ModuleNotFoundError``.

    Named ``DatabaseDriver`` rather than ``Driver`` because
    :class:`sopuli.driver.protocol.Driver` already means the connecting thing.
    This is the registry entry that finds it -- a fact about packaging, not
    about databases.
    """

    #: Dotted path of the module implementing the driver.
    module: str
    #: The extra that installs its client.
    extra: str | None = None
    #: Top-level module names ``pip install "sopuli-dba[<extra>]"`` makes
    #: importable.
    provides: frozenset[str] = frozenset()

    @property
    def install_command(self) -> str:
        """The line an operator can paste."""
        assert self.extra is not None
        return install_command(self.extra)


#: Every ``type:`` :data:`~sopuli.config.targets.TARGET_TYPES` allows, and what
#: serves it. ``tests/driver/test_driver_registry.py`` checks the two against
#: each other: a type the config layer accepts and this one has never heard of
#: would fail at connect time with a ``KeyError``, which is precisely the
#: traceback rule 2 exists to prevent.
#:
#: One entry, and that is not a placeholder for a table that wants filling. D6
#: keeps drivers in-tree until there is a second one, and P1's intended order
#: after Oracle -- PostgreSQL, SQL Server, MySQL -- is a roadmap rather than a
#: promise this dict should pre-announce.
DRIVERS: dict[str, DatabaseDriver] = {
    "oracle": DatabaseDriver(
        # The module that *connects*, not the package above it. The whole
        # value of resolving through here is that a missing client arrives as
        # `DriverNotInstalledError` rather than a traceback, and that only works
        # if the import being caught is the one that pulls the client in. The
        # package deliberately does not: `statements.py` and `client.py` are
        # tier 0 and must stay importable on a machine with no Oracle client at
        # all, which is every tier-0 CI job.
        module="sopuli.driver.oracle.session",
        extra="oracle",
        # `oracledb`, not `python-oracledb`. Oracle calls the driver
        # python-oracledb everywhere it is written about, but the distribution
        # on PyPI and the module you import are both `oracledb`, and the other
        # name resolves to nothing at all.
        provides=frozenset({"oracledb"}),
    ),
}


class DriverNotInstalledError(ConfigError):
    """A configured driver's client is not installed on this machine.

    ``config`` and exit 9, not ``capability`` (ADR-006 E5). ``capability`` names
    something a *target* cannot do -- a property of the database at the far end
    that no local action changes. This is the opposite: it is fixed on this
    machine, by the person reading the message, with the command in the message.
    """

    code = DRIVER_NOT_INSTALLED


class DriverNotImplementedError(ConfigError):
    """This build has no module for a driver type the config named.

    A separate class from :class:`DriverNotInstalledError` because the two are
    the same ``ModuleNotFoundError`` and completely different problems. Nothing
    the operator installs fixes this one, so it must never carry an install
    line.

    Unreachable today, since ``oracle`` is the only type the config layer
    accepts and its module exists. It is written now because the moment it
    becomes reachable is the moment somebody adds ``postgresql`` to
    ``TARGET_TYPES`` -- and discovering then that the failure path is a
    ``KeyError`` is discovering it in the worst way.

    No ``error.code`` yet. J3 gives it one: the configuration is right and there
    is nothing to install, so a consumer must tell it from the ``config`` errors
    that a change to either fixes. #801 adds it.
    """


def installed(driver: DatabaseDriver) -> bool:
    """Whether ``driver``'s client is importable, **without importing it**.

    Safe to call from an offline command, which is the only kind that calls it:
    looking a module up does not run a vendor package's import side effects.
    """
    return extras_installed(driver.provides)


def resolve(target: Target) -> ModuleType:
    """Import the module serving ``target``'s ``type:``, or say why it cannot.

    Returns the module, which exposes ``connect(target, credential, *, env,
    correlation_id, timeouts)``.
    """
    driver = DRIVERS[target.type]
    try:
        return importlib.import_module(driver.module)
    except ModuleNotFoundError as exc:
        kind = missing_kind(exc, module=driver.module, provides=driver.provides, extra=driver.extra)
        if kind == MISSING_CLIENT:
            raise DriverNotInstalledError(
                f'target "{target.name}" declares type "{target.type}", '
                f"but that driver is not installed",
                hint=f"install it with:  {driver.install_command}",
            ) from exc
        if kind == MISSING_MODULE:
            raise DriverNotImplementedError(
                f'target "{target.name}" declares type "{target.type}", '
                f"but this build has no {target.type} driver yet",
                hint="this is not something to install -- the driver is not written yet",
            ) from exc
        raise

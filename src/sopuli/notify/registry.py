"""Which module serves a `notify.method`, imported on first use.

The same arrangement `sopuli/store/registry.py` and `sopuli/driver/registry.py`
already have, and for ADR-006's reasons rather than for symmetry: a channel that
opens a socket keeps its client inside its own module, a missing client is a
diagnosable condition rather than a traceback, and base opens no sockets.

**A third registry, and a fourth extra category** (E7). ADR-006's table named store
extras, driver extras and `all`; a notify channel is none of those, and folding it
into an existing one was the alternative considered and rejected: an
estate on OCI Vault installing `sopuli-dba[hashicorp]` in order to post a chat
message would make the extra's name stop meaning what it says, which is the whole
property that ADR makes real.

**`smtp` will add nothing here.** The standard library sends mail, so a future
`smtp` channel has no client to install and no extra to name — which is why
:attr:`Notifier.extra` is optional rather than required, exactly as
:attr:`sopuli.store.registry.Backend.extra` is.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from types import ModuleType

from sopuli.config.errors import ConfigError
from sopuli.extras import MISSING_CLIENT, install_command, installed, missing_kind

#: ``error.code`` for a configured channel whose client is not installed, so a
#: consumer can branch on this rather than parse a message (E5, and
#: ``03-json-output.md`` §3). Third in the series `SOPULI-20001` (a store's
#: backend) and `SOPULI-20002` (a driver's) started, because it is the same
#: condition a third time: a file names something this machine cannot serve, and
#: `pip` is the answer.
NOTIFIER_NOT_INSTALLED = "SOPULI-20003"


@dataclass(frozen=True)
class Notifier:
    """What is behind one `notify.method`.

    ``provides`` earns its place for :class:`sopuli.store.registry.Backend`'s
    reason: it is the set of top-level modules that installing ``extra`` adds,
    which is what lets a :class:`ModuleNotFoundError` be read as "the operator has
    not installed this" rather than as "we have a typo in our own import". Both
    arrive as the same exception and only one of them has an install line as its
    answer.
    """

    #: Dotted path of the module implementing the channel.
    module: str
    #: The extra that installs its client, or ``None`` where there is nothing to
    #: install -- a future `smtp` channel sends with the standard library.
    extra: str | None = None
    #: Top-level module names ``pip install "sopuli-dba[<extra>]"`` makes importable.
    provides: frozenset[str] = frozenset()

    @property
    def available(self) -> bool:
        """Whether this channel could send, **without importing anything**.

        Asked by `config validate` (E4), which must be able to report on a channel
        it cannot serve without loading the client it does not have.
        """
        return installed(self.provides)


#: Every channel `notify.method` may name, and what serves it.
NOTIFIERS: dict[str, Notifier] = {
    "webhook": Notifier(
        module="sopuli.notify.webhook",
        extra="notify",
        # `httpx` again, and the duplication with the HashiCorp backend is the
        # point rather than an oversight: rule 3 names the *installed dependency
        # set*, so an estate that has httpx for one reason has it for both, and an
        # estate that has it for neither is the case base install defends.
        provides=frozenset({"httpx"}),
    ),
}


class NotifierNotInstalledError(ConfigError):
    """The channel's client is not installed on this machine (E5).

    Exit 9 and ``category: config``, inherited, and that is E5's call rather than
    this class's: a configured channel this machine cannot serve is a mismatch
    between a file and an install, which is the operator's to fix with `pip` and
    not a capability the *tool* lacks.
    """

    code = NOTIFIER_NOT_INSTALLED


def resolve(method: str) -> ModuleType:
    """Import the module serving ``method``, or say what to install.

    Imported here rather than at package scope, which is ADR-006 rule 1: nothing
    is loaded until a run actually has a message to send, so `config validate` and
    every offline verb stay free of a third-party HTTP client.
    """
    notifier = NOTIFIERS[method]
    try:
        return importlib.import_module(notifier.module)
    except ModuleNotFoundError as exc:
        kind = missing_kind(
            exc, module=notifier.module, provides=notifier.provides, extra=notifier.extra
        )
        if kind == MISSING_CLIENT and notifier.extra is not None:
            raise NotifierNotInstalledError(
                f"notify method {method!r} needs a client this machine does not have",
                hint=(
                    f"{install_command(notifier.extra)} -- or take `delivery.notify` out of "
                    f"the file if nobody should be told. The reset is refused rather than run "
                    f"without the notification, because it is refused *before* the password "
                    f"changes and running it would leave somebody holding a credential nobody "
                    f"told them about"
                ),
            ) from exc
        raise

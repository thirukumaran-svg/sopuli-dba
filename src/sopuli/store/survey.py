"""Every configured store, and whether this run could use it (#216, P4).

The vault half of what `doctor` does, standing beside
:mod:`sopuli.driver.oracle.wallet` in the same relation: the subject's own layer
owns the probing, and :mod:`sopuli.output.vault_view` owns the shape it is
reported in.

**One store, three ways it can go, and all three are findings rather than
crashes.** `doctor` surveys an estate and says which parts of it are unwell, so a
vault that cannot be opened must not end the run before the next one is tried --
exactly the rule its ``targets[]`` already follows. The three:

* the backend's client is not installed, or this build has no module for it. Not
  a network condition at all, and already reported by the ``install`` section
  (ADR-006 E6) -- carried here too so the row in this table has a reason beside
  it rather than being unexplained red;
* the store could not be authenticated to. A login is a round trip that can fail
  on a store that is perfectly healthy, so this is its own outcome;
* the store answered, and :meth:`~sopuli.store.protocol.SecretStore.health` says
  what it said.

**The skew is computed here rather than in the view**, and that is where P4's
sentence turns into a number: the tolerance is
:data:`~sopuli.lock.record.CLOCK_SKEW`, the allowance the advisory lock already
makes when it decides whether a lease has expired (#83). Importing it here is
deliberate and the coupling is the point -- a report judged against any other
figure would be measuring an assumption nothing makes.

**Nothing here writes and nothing takes a lock** (P5). The whole survey is one
``sys/health`` and one token lookup per store.
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from sopuli.clock import Skew
from sopuli.config.model import Vault
from sopuli.lock.record import CLOCK_SKEW
from sopuli.store.protocol import UNREACHABLE, StoreHealth
from sopuli.store.registry import connect


@dataclass(frozen=True)
class VaultReport:
    """One configured store as this run found it."""

    #: The name under ``vaults:``, which is what a reader goes and edits.
    name: str
    #: The backend serving it, as ``vaults.*.type`` spells it.
    type: str
    #: What the store said about itself. Always present: a store that could not
    #: be opened gets a :data:`~sopuli.store.protocol.UNREACHABLE` one carrying
    #: the reason, rather than this being ``None`` and every reader having to
    #: handle a second absent case.
    health: StoreHealth
    #: The clock comparison, or ``None`` where the backend exposes no server
    #: time -- which is a different answer from "the clocks agree" and must stay
    #: distinguishable from it all the way to the output.
    skew: Skew | None = None
    #: What went wrong opening it, kept as the exception so the boundary can
    #: report the vendor code and category it carries (``03-json-output.md`` §2)
    #: rather than re-deriving them from a message.
    failure: Exception | None = None
    #: The whole interaction, end to end -- opening the store as well as asking
    #: it. Not :attr:`StoreHealth.round_trip`, which is the probe alone: what a
    #: reader wants beside a store's name is what the store cost them, and an
    #: authentication method with a login round trip of its own is most of that.
    duration_ms: int = 0

    @property
    def reachable(self) -> bool:
        return self.health.status != UNREACHABLE


def survey(
    vaults: Sequence[Vault],
    *,
    env: Mapping[str, str],
    token_file: Path | None = None,
    tolerance: timedelta = CLOCK_SKEW,
) -> tuple[VaultReport, ...]:
    """Ask every store in ``vaults`` how it is, in configuration order.

    Configuration order rather than sorted, matching ``targets[]``: the file is
    what the reader has open, and a survey that reordered it would make them
    search for the row they came for.

    ``token_file`` is ``--vault-token-file``'s path, forwarded as a *location*
    exactly as :func:`sopuli.cli._stores_for` forwards it -- ADR-007's rule is
    that the flag names a file and the value is read at the end of §3a's chain,
    so no signature between here and there has a slot a credential could sit in.

    ``tolerance`` is :data:`~sopuli.lock.record.CLOCK_SKEW` by default and is an
    argument so a test can state the boundary it is asserting rather than
    importing the same constant and comparing it with itself.
    """
    return tuple(
        _examine(vault, env=env, token_file=token_file, tolerance=tolerance) for vault in vaults
    )


def _examine(
    vault: Vault,
    *,
    env: Mapping[str, str],
    token_file: Path | None,
    tolerance: timedelta,
) -> VaultReport:
    """One store: open it, ask it, and never raise.

    The broad ``except`` is the point rather than a lapse. Opening a store can
    fail as a missing client (ADR-006), a refused login (#138), an unreadable
    token file, a TLS failure, or a configuration error caught late -- and
    `doctor` exists to be run when things are wrong, so it is the one command
    that must survive its own subject being broken. Each of those keeps its own
    category and exit code on the exception, which the boundary reads back out;
    nothing is flattened here.

    **The store is not closed**, and that is the existing arrangement rather
    than an oversight: :func:`sopuli.cli._stores_for` opens one per store for
    `lock status` and lets the run's exit reclaim them. There is no ``close`` on
    the interface to call -- adding one would be a demand on every
    implementation, which is the cost P2 weighs before any method goes on that
    protocol, and it is not a decision to make as a side effect of a survey. The
    holding is a connection pool per configured store for the seconds a `doctor`
    run lasts.
    """
    started = time.monotonic()
    try:
        health = connect(vault, env=env, token_file=token_file).health()
    except Exception as error:  # noqa: BLE001 -- a per-vault finding, never a crash
        return VaultReport(
            name=vault.name,
            type=vault.type,
            health=StoreHealth(status=UNREACHABLE, detail=_first_line(error)),
            failure=error,
            duration_ms=_elapsed(started),
        )

    return VaultReport(
        name=vault.name,
        type=vault.type,
        health=health,
        skew=health.skew(tolerance),
        duration_ms=_elapsed(started),
    )


def _first_line(error: Exception) -> str:
    """The failure in one line, keeping the store's own wording.

    A ``StoreError`` carries a ``hint`` on a second line and a client error can
    run to several including a documentation link. This is the sentence that
    goes beside a row in a table; the rest survives in the ``error`` object the
    boundary builds from :attr:`VaultReport.failure`.

    An exception with **no message at all** -- ``Exception()``, or a vendor
    client raising a bare class -- is why this does not simply index
    ``splitlines()``: that is ``[]`` for an empty string, and an ``IndexError``
    here would be raised by the one code path whose contract is never to raise.
    The class name is the only information left and beats an empty string, which
    reads as the tool having lost the reason rather than there never having been
    one.
    """
    message = getattr(error, "message", None) or str(error)
    lines = message.splitlines()
    return lines[0] if lines else type(error).__name__


def _elapsed(started: float) -> int:
    return int((time.monotonic() - started) * 1000)

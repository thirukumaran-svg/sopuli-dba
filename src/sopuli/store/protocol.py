"""The slice of P2's secret store the advisory lock needs (#83, #96).

P2 sketches the interface as ``read`` / ``write`` / ``list`` / ``supports`` /
``health``. The lock needs two things that sketch does not have, and both come
straight out of the decision on #83:

* **compare-and-set on write, returning the new version.** That version *is* the
  fencing token. A write that only said "ok" would leave the design with nothing
  to fence with.
* **a metadata read.** Pre-flight asserts that the lock path is not configured to
  accept writes without a CAS, because a guarantee the tool cannot check is a
  guarantee it should not claim.

Only that slice is here. The rest of P2's interface arrives with the first real
backend, along with the parts a lock has no opinion about -- listing, health, and
what a *secret* value looks like as opposed to a lock record.

Deliberately a :class:`~typing.Protocol` rather than a base class. A store
implementation should not have to import this to satisfy it: the HashiCorp
adapter will be written against Vault's API and checked against this by mypy,
which is the arrangement that keeps the interface a description of what the lock
needs rather than a place to put shared code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from sopuli.exit_codes import ExitCode

#: The store capability the lock requires, spelled as P2's table spells it.
CAS = "cas"


class StoreError(Exception):
    """A store could not do what was asked.

    ``category`` mirrors :class:`~sopuli.config.errors.ConfigError`'s: the
    exception says what kind of failure it is, so the boundary reports it rather
    than inferring one from the exception's type (``03-json-output.md`` §2).
    """

    category = "vault"

    #: What the process exits with, carried here for the same reason ``category``
    #: is: the boundary reports what the error says about itself rather than
    #: inferring it from a type. Generic failure by default -- a store that could
    #: not answer is not a configuration problem and not a usage one. Subclasses
    #: that mean something more specific say so, and
    #: :class:`~sopuli.store.hashicorp._auth.LoginFailedError` is exit 6.
    exit_code = ExitCode.FAILURE

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:
        if self.hint:
            return f"{self.message}\n  hint: {self.hint}"
        return self.message


class CasConflictError(StoreError):
    """A compare-and-set write was refused: the version had moved.

    The whole point of the primitive, and never a reason to retry. Somebody else
    wrote between this run's read and its write, so the state the write was
    computed from is gone -- retrying would recompute against a document that has
    changed for a reason this run knows nothing about.
    """


@dataclass(frozen=True)
class Stored:
    """A document read from a store, and the version it was read at."""

    data: Any
    version: int


@dataclass(frozen=True)
class PathMetadata:
    """What a store knows about a path apart from its contents.

    ``cas_required`` is the one that matters here: a KV v2 path can be configured
    to demand a compare-and-set on every write, which is what stops a *different*
    writer -- an operator with a vault CLI, a script -- from clobbering a lock
    without one. The tool always passes a CAS itself, so this is about everybody
    else.

    ``max_versions`` is carried because #83 names it, and is deliberately not a
    safety property: pruning old versions does not reset the version counter, so
    fencing survives any value of it. See
    :meth:`~sopuli.lock.manager.LockManager.preflight`.
    """

    cas_required: bool = False
    max_versions: int | None = None


@runtime_checkable
class SecretStore(Protocol):
    """What the lock manager needs a store to be able to do."""

    def supports(self) -> frozenset[str]:
        """Store capabilities, from P2's table. ``cas`` is the one asked about."""
        ...

    def read(self, path: str) -> Stored | None:
        """The document at ``path``, or ``None`` if there is nothing to read.

        **``None`` is not the same as "a ``cas: 0`` write will succeed here",**
        and conflating the two is the trap this interface exists to keep visible.
        Two states read as ``None``:

        * nothing was ever written -- version 0, and ``cas: 0`` succeeds;
        * the latest version was **deleted** -- there is no data, and the version
          counter stands, so ``cas: 0`` fails and will keep failing.

        That second state is why a lock is released by writing a ``released``
        record rather than by deleting one (#83): a delete would leave a path no
        first acquisition could ever take again. A caller that wants to know
        which state it is in finds out from the write.

        A path whose *contents* are unreadable is neither: it has a version, and
        the caller decides what to make of the payload.
        """
        ...

    def write(self, path: str, data: Any, *, cas: int | None) -> int:
        """Write ``data``, returning the new version.

        ``cas`` is the version the write is expected to replace, ``0`` for "there
        must be nothing here", or ``None`` for an unguarded write -- which only a
        store without the ``cas`` capability should ever be asked for, and which
        the lock manager only does under ``locking: advisory-only``.

        Raises :class:`CasConflictError` when the version has moved.
        """
        ...

    def metadata(self, path: str) -> PathMetadata | None:
        """What the store knows about ``path``, or ``None`` if it knows nothing.

        ``None`` for a path that has never been written *and* never had metadata
        configured. That is the ordinary state of a lock path before the first
        lock is taken, so it is not a failure.
        """
        ...

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

``list`` joined them in #150, and for a reason of the same kind: ``lock status``
reads the paths the *config* declares, so a record left behind by an application
that was renamed or removed is invisible to it -- and a lock nobody can see is a
lock nobody can clear. Listing is how the tool finds a path its own configuration
no longer names.

The rest of P2's interface arrives with the secret side: ``health``, and what a
*secret* value looks like as opposed to a lock record.

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

#: Reading a *named* version rather than the latest one, spelled as P2's table
#: spells it (#183).
#:
#: The capability :meth:`SecretStore.read`'s ``version`` argument needs, and the
#: reason that argument is not simply always honoured: KV v1 has no versions at
#: all, so ``@version=7`` there is not a read that returns nothing -- it is a
#: question the store cannot be asked. P2's rule is that a missing capability is
#: emulated in the payload where it can be, and this is one of the two that
#: cannot: a version somebody wants to read back is a version the store had to
#: have kept at the time, and nothing in a payload written afterwards can
#: manufacture one.
VERSIONING = "versioning"

#: Enumerating the paths below a prefix (#150), spelled the same way.
#:
#: Its own capability rather than an assumption, for the reason every entry in
#: P2's table is one: a store may genuinely not have it. Both HashiCorp mounts
#: do, and an OS keyring or a future backend over an object store with no prefix
#: query may not -- and the answer for a caller is then to say it could not look
#: further, never to report an empty listing as though it had looked.
LIST = "list"


def bounded_prefix(prefix: str) -> str:
    """``prefix`` with exactly one trailing separator, or ``""`` for everything.

    What :meth:`SecretStore.list`'s argument *means*, which is why it lives
    beside the interface rather than inside one implementation: every store has
    to answer the same question for the same string, and the question is asked on
    a **segment boundary**. ``locks``, ``locks/`` and ``/locks/`` are one prefix;
    ``locksmiths/db`` is not under any of them, though a bare string comparison
    would say it was.

    An empty prefix -- or one that is nothing but separators -- means the whole
    store, and returns ``""`` so that a prefix test against it is trivially true.
    """
    trimmed = prefix.strip("/")
    return f"{trimmed}/" if trimmed else ""


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

    def read(self, path: str, *, version: int | None = None) -> Stored | None:
        """The document at ``path``, or ``None`` if there is nothing to read.

        ``version`` pins the read to one version -- C14's ``@version=N``, which
        counts from 1 (``01-configuration.md`` §7). ``None`` is the latest, which
        is every caller the lock has and the default for that reason.

        **A pinned version is behind** :data:`VERSIONING`, and a store without it
        raises :class:`StoreError` rather than quietly answering with the latest.
        Substituting the latest for a version somebody asked for by number is the
        one failure worth being loud about here: the caller asked *because* it
        did not want whatever is current, and a rotation that read the wrong
        generation is a password written where nobody reads it.

        **A version that is gone reads as** ``None``, not as an error -- pruned
        by ``max_versions``, deleted, or never written at all. It is the same
        answer as an empty path for the same reason the next paragraph gives, and
        a caller that pinned a version finds out that it is unavailable rather
        than what became of it.

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

    def list(self, prefix: str) -> tuple[str, ...]:
        """Every path the store knows about below ``prefix``, sorted (#150).

        Five properties, each of which a caller is entitled to rely on and none
        of which is what a backend's own listing endpoint gives you unaided:

        **What comes back can be handed straight to** :meth:`read`. Each entry
        still carries ``prefix`` on the front of it -- ``list("locks")`` answers
        ``("locks/apps/acme/db", ...)``, not the bare tails a KV mount returns.
        ``prefix`` is a boundary and never an entry in its own right: a document
        written *at* ``locks`` is not below ``locks/`` and is not listed. A caller
        that had to reassemble these would be reimplementing the store's own
        addressing, and would get it wrong the first time a prefix did or did not
        end in a separator.

        **Recursive, and leaves only.** KV answers one level at a time and marks
        a subtree with a trailing separator; that is a detail of the endpoint, and
        a caller walking it would be walking it identically for every backend. No
        entry returned here ends in ``/``.

        **Knowing about a path is not the same as having something to read**, the
        same seam :meth:`read` already draws. A soft-deleted path and one that
        exists only because its metadata was configured are both *listed* and both
        read as ``None``. That is deliberate: for the case #150 exists for -- a
        leftover lock record -- the useful question is "what is out there", and a
        caller that wants contents reads and finds out.

        **Sorted**, so two surveys of one estate are the same survey. Store order
        is nobody's contract, and a report whose rows moved between runs is a
        report nobody can diff.

        **An empty prefix is the whole mount, and an empty answer is not an
        error.** A prefix with nothing under it returns ``()``; a store that
        cannot answer raises rather than returning ``()``, because "I looked and
        found nothing" and "I cannot look" are the two answers a caller must never
        confuse. Which is why this is behind :data:`LIST`: a store that does not
        declare the capability raises :class:`StoreError` when asked, and the
        caller is expected to have checked.
        """
        ...

"""The slice of P2's secret store the advisory lock needs (Q2).

P2 sketches the interface as ``read`` / ``write`` / ``list`` / ``supports`` /
``health``. The lock needs two things that sketch does not have, and both come
straight out of decision Q2:

* **compare-and-set on write, returning the new version.** That version *is* the
  fencing token. A write that only said "ok" would leave the design with nothing
  to fence with.
* **a metadata read.** Pre-flight asserts that the lock path is not configured to
  accept writes without a CAS, because a guarantee the tool cannot check is a
  guarantee it should not claim.

``list`` is here for a reason of the same kind: ``lock status`` reads the paths
the *config* declares, so a record left behind by an application that was
renamed or removed is invisible to it -- and a lock nobody can see is a lock
nobody can clear. Listing is how the tool finds a path its own configuration no
longer names.

``health`` completes P2's sketch. A method on this protocol is a demand on every
implementation, so it is declared only because something calls it
(``00-principles.md`` P2). `doctor`'s vault section is that caller, and it asks
the one question the rest of this interface cannot answer -- not *what is at
this path* but *is the store there at all, and does its clock agree with ours*.

Deliberately a :class:`~typing.Protocol` rather than a base class. A store
implementation should not have to import this to satisfy it: the HashiCorp
backend is written against Vault's HTTP API and checked against this by mypy,
which keeps the interface a description of what the commands need rather than a
place to put shared code.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol, runtime_checkable

from sopuli.clock import Skew, measure_skew
from sopuli.exit_codes import ExitCode

#: The store capability the lock requires, spelled as P2's table spells it.
CAS = "cas"

#: Reading a *named* version rather than the latest one, spelled as P2's table
#: spells it.
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

#: Applying an RFC 7396 merge patch server-side, rather than by reading the
#: document and writing it back.
#:
#: The capability that makes ``01-configuration.md`` §7's "must not clobber
#: siblings" a *structural* property instead of a careful one. Under a merge
#: patch the tool sends only the keys it changes, so a sibling account's password
#: is never read into this process and never written back; under the
#: read-modify-write fallback the whole document goes out, and not rewriting a
#: sibling wrongly is then something the code has to get right rather than
#: something it cannot get wrong.
#:
#: Both are safe against a *concurrent* writer, because both carry the same
#: compare-and-set. The difference is blast radius, not atomicity.
MERGE_PATCH = "merge_patch"

#: Enumerating the paths below a prefix, spelled the same way.
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


class PatchNotPermittedError(StoreError):
    """This store could apply a merge patch, and is not allowed to right now.

    **Not "this store cannot"** — that is a missing :data:`MERGE_PATCH`
    capability, answered by :meth:`SecretStore.supports` before anything is sent.
    This is the narrower case where the endpoint exists and *this caller* is
    refused it, which on Vault is a policy granting ``update`` and not ``patch``:
    ``patch`` is a capability of its own, newer than ``update``, so a perfectly
    ordinary policy produces it.

    Here rather than in the HashiCorp adapter because it is a signal to the layer
    above -- :func:`sopuli.store.credentials.apply_patch` catches it and falls
    back to a read-modify-write, and that module must not import a backend
    (ADR-006: base loads no vendor client). A backend raises it; nothing outside
    one ever does.

    ``authorization`` and exit 6, the same as any other refused token, because a
    caller with no fallback should treat it as exactly that. Where there *is* a
    fallback and the token was in fact bad, the fallback's own read fails with an
    ordinary refusal and the run stops there — one wasted round trip, and never a
    silent success.
    """

    category = "authorization"
    exit_code = ExitCode.AUTH_FAILURE


class MetadataNotPermittedError(StoreError):
    """This store could set path metadata, and is not allowed to right now.

    :meth:`SecretStore.require_cas`'s counterpart to
    :class:`PatchNotPermittedError`, and the same distinction: not "this store
    has no metadata" -- that is a store answering ``None`` from
    :meth:`SecretStore.metadata`, which KV v1 always does -- but "the endpoint is
    there and *this caller* is refused it".

    On Vault that is an ordinary policy. Writing a lock record needs
    ``create``/``update`` on ``<mount>/data/<path>``; setting ``cas_required``
    needs ``update`` on ``<mount>/metadata/<path>``, which is a separate rule a
    policy written for secrets alone will not carry. Measured against Vault
    2.0.4: a token holding ``create, update, read`` on ``kv/data/*`` and
    ``read, list`` on ``kv/metadata/*`` gets **403** from the metadata write and
    writes the record itself perfectly well.

    **The caller degrades rather than stopping**, which is why this is its own
    exception and not a bare refusal: an estate whose token cannot set the
    metadata is exactly as safe as it was before the tool tried, so failing the
    run would break installs that work today over a guarantee they never had. The
    run says so instead -- ``SOPULI-W019``.
    """

    category = "authorization"
    exit_code = ExitCode.AUTH_FAILURE


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

    ``max_versions`` is carried because it sits beside ``cas_required`` in the
    same metadata, and is deliberately not a safety property: pruning old
    versions does not reset the version counter, so fencing survives any value
    of it. See :meth:`~sopuli.lock.manager.LockManager.preflight`.
    """

    cas_required: bool = False
    max_versions: int | None = None


#: The store is there, answering, and able to serve this run.
OK = "ok"

#: Something answered and cannot do the whole job right now: sealed, standing
#: by, not yet initialised, or serving a token this run cannot authenticate
#: with. **A distinct answer from** :data:`UNREACHABLE`, and the distinction is
#: the point of having three words rather than a boolean: one sends somebody to
#: the network and the other sends them to the vault, and being sent to the
#: wrong one costs an outage's worth of time.
DEGRADED = "degraded"

#: Nothing that could be recognised as this store answered -- a refused
#: connection, a timeout, a TLS failure, or a reply this build cannot read.
#:
#: The last of those is deliberately in here rather than in :data:`DEGRADED`,
#: on :mod:`sopuli.store.hashicorp._errors`' fail-closed rule: an answer the tool
#: cannot interpret is not evidence that a store is well, and a proxy's 502 is exactly
#: what it would be mistaken for.
UNREACHABLE = "unreachable"


@dataclass(frozen=True)
class StoreHealth:
    """Whether a store is there, and what its clock says (P2).

    The three-word ``status`` is P2's own sketch -- ``ok | degraded |
    unreachable`` -- and everything else here exists to make one of those three
    words actionable rather than to widen the vocabulary.

    **The clock fields are the reason this is not a boolean.** `sopuli/lock/`
    compares a lease's ``expires_at`` against *this* machine's clock and allows
    :data:`~sopuli.lock.record.CLOCK_SKEW` for the two disagreeing. A host that
    is minutes out will take over locks that are still live, or refuse ones that
    are long dead, and the failure looks like a locking bug rather than an NTP
    problem. So the skew is not a health nicety: it is the assumption the lock
    rests on, measured against the only other clock in the system that matters.

    **A store that cannot report its own time reports** ``server_time: None``,
    never a substitute. There is no defensible fallback -- this host's clock is
    the very thing under test -- and a caller that got one back would compute a
    skew of zero and print it as a measurement.
    """

    #: :data:`OK`, :data:`DEGRADED` or :data:`UNREACHABLE`.
    status: str
    #: What the store says it is running, where it says so at all. Its own
    #: field rather than part of :attr:`detail`, because a consumer reads it as
    #: a value -- an estate audit asking which vaults are behind -- and a
    #: version recoverable only by parsing a human sentence is one that breaks
    #: the first time the sentence is reworded (``03-json-output.md`` §8: the
    #: wording around a contract is not the contract).
    version: str | None = None
    #: What the status is, in the store's own vocabulary: ``"sealed"``,
    #: ``"standby"``, the transport error, whatever the store can say. ``None``
    #: when there is nothing to add to :data:`status`, which is the ordinary
    #: :data:`OK` case.
    detail: str | None = None
    #: The store's own clock, when it exposes one at all. ``None`` is a real
    #: answer and not a failure -- see the class note.
    server_time: datetime | None = None
    #: How precisely the store reports :attr:`server_time`. HashiCorp answers in
    #: whole seconds, so a sub-second reading against one is noise, and a report
    #: that presented it as a measured difference would be inventing precision.
    time_resolution: timedelta = timedelta(0)
    #: This host's clock at the **midpoint** of the request that produced
    #: :attr:`server_time` -- the best single estimate of the instant the far end
    #: read its own. See :func:`sopuli.clock.measure_skew`.
    measured_at: datetime | None = None
    #: What the request cost, end to end. Both a thing to report -- P4 asks how
    #: long the store took -- and the width of what one round trip cannot pin
    #: down about :attr:`server_time`.
    round_trip: timedelta | None = None
    #: Whether the credential this store was opened with was accepted.
    #:
    #: ``None`` means *not asked*, which is a third state and not a shrug: a
    #: sealed store refuses every request including the one that would answer
    #: this, so reporting ``False`` there would blame a token for a seal. Absent
    #: and false are therefore different findings, exactly as they are on
    #: ``doctor``'s privilege report.
    authenticated: bool | None = None

    def skew(self, tolerance: timedelta, *, local: datetime | None = None) -> Skew | None:
        """The clock difference this reading implies, or ``None`` if it cannot say.

        ``None`` when the store exposes no server time -- the one case a caller
        must not paper over, since the alternative reading is a confident zero.

        ``local`` overrides :attr:`measured_at`, and exists so the comparison can
        be exercised against a **real** server reading with a deliberately
        offset host clock. A test that only ever sees the runner's own clock
        beside a container sharing it measures nothing: the difference is always
        zero, and a broken comparison passes.
        """
        if self.server_time is None:
            return None
        moment = local if local is not None else self.measured_at
        if moment is None:  # pragma: no cover -- set together, by every producer
            return None
        return measure_skew(
            server=self.server_time,
            local=moment,
            round_trip=self.round_trip or timedelta(0),
            tolerance=tolerance,
            resolution=self.time_resolution,
        )


@runtime_checkable
class SecretStore(Protocol):
    """What the lock manager needs a store to be able to do."""

    def supports(self) -> frozenset[str]:
        """Store capabilities, from P2's table. ``cas`` is the one asked about."""
        ...

    def health(self) -> StoreHealth:
        """Is the store there, is it able to serve, and what does its clock say.

        The only method here that is not about a path, and the only one that
        **never raises for an unreachable store**. Every other call on this
        interface treats "I could not reach it" as a failure, because every other
        caller wanted something done; this one is asked precisely in order to
        find out, so a store that is not there is the answer rather than an
        exception. `doctor` surveys a whole estate and one dead vault must not
        end the run before the next is tried -- the same rule its ``targets[]``
        already follows.

        It **must not write**, take a lock, or renew anything (P5: `doctor`
        mutates nothing). Establishing that a store is reachable by leaving a
        lease in it would be a health check that changes the thing it measures,
        and on a lock mount it would be one that a concurrent rotation notices.

        A store that cannot report its own time answers ``server_time: None``
        rather than substituting this host's -- see :class:`StoreHealth`.
        """
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
        record rather than by deleting one: a delete would leave a path no first
        acquisition could ever take again. A caller that wants to know which
        state it is in finds out from the write.

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

    def patch(self, path: str, changes: Any, *, cas: int | None) -> int:
        """Apply ``changes`` as an RFC 7396 merge patch, returning the new version.

        ``changes`` is a merge patch and not a document: a key it does not
        mention is left exactly as it was, and a key mapped to ``None`` is
        **deleted** -- which is how ``pending`` is cleared at promotion
        (:data:`sopuli.payload.REMOVE`). That is the whole reason this is not
        :meth:`write`: a write replaces, and replacing a shared document is how
        an account nobody selected loses its password.

        ``cas`` means what it means on :meth:`write`, and is carried for the same
        reason. A merge patch is not a substitute for it: the patch says which
        keys change, and the compare-and-set says which *version* they change,
        and §7 wants a foreign writer to abort the run rather than be merged over.

        Behind :data:`MERGE_PATCH`. A store without it raises
        :class:`StoreError`, and the caller's answer is
        :func:`sopuli.store.credentials.apply_patch`'s read-modify-write --
        which is a fallback rather than an equivalent, for the reason
        :data:`MERGE_PATCH` gives.

        Raises :class:`CasConflictError` when the version has moved, exactly as
        :meth:`write` does.
        """
        ...

    def metadata(self, path: str) -> PathMetadata | None:
        """What the store knows about ``path``, or ``None`` if it knows nothing.

        ``None`` for a path that has never been written *and* never had metadata
        configured. That is the ordinary state of a lock path before the first
        lock is taken, so it is not a failure.
        """
        ...

    def require_cas(self, path: str) -> None:
        """Make ``path`` refuse any write that carries no compare-and-set.

        The write half of :meth:`metadata`, and it exists for one caller: the
        lock's first acquisition of a path. That path has no metadata -- the
        ordinary state of a path nobody has locked -- and an acquisition left to
        create it would leave ``cas_required`` unset, so every later run would
        be refused until somebody set it by hand. So the lock's pre-flight
        arranges the guarantee rather than only reading it.

        **Creating metadata does not create a version**, which is what makes
        this safe to do before a first write. Measured against Vault 2.0.4:
        after setting ``cas_required`` on a path holding nothing,
        ``current_version`` is 0 and the version list is empty, and the
        ``cas: 0`` write a first acquisition makes still succeeds. Were it otherwise
        this would lock every new path out of its own first acquisition, exactly
        as deleting a lock record does (:mod:`sopuli.store.hashicorp.kv2`).

        Raises :class:`MetadataNotPermittedError` where the endpoint is there and
        this caller may not use it. A store with no metadata at all -- KV v1,
        whose :meth:`metadata` is always ``None`` -- raises
        :class:`StoreError`, and is never asked: it has no :data:`CAS` capability
        either, so the lock has already refused it or been configured
        ``advisory-only``.
        """
        ...

    def list(self, prefix: str) -> tuple[str, ...]:
        """Every path the store knows about below ``prefix``, sorted.

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

        **Knowing about a path is not the same as having something to read**,
        the same seam :meth:`read` already draws. A soft-deleted path and one
        that exists only because its metadata was configured are both *listed*
        and both read as ``None``. That is deliberate: for the case listing
        exists for -- a leftover lock record -- the useful question is "what is
        out there", and a caller that wants contents reads and finds out.

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

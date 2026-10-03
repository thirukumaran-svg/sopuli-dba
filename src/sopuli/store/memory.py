"""A KV v2 emulation that lives in a dictionary (#96).

Here rather than in ``tests/`` for two reasons. It is the **reference reading of
the semantics** :mod:`sopuli.store.protocol` demands -- when the HashiCorp
adapter arrives, "does it behave like this one" is the conformance question --
and the lock's whole design rests on details of those semantics that a looser
fake would paper over. It is not reachable from a config file: ``vaults.type``
is a closed set (``01-configuration.md`` §3a) and this is not in it.

What it gets right on purpose, because the lock depends on each:

* **versions increase and never repeat.** The version is the fencing token, so a
  fake that reused numbers would make a stolen lock undetectable.
* **``cas: 0`` succeeds only on a path with no history**, and a *deleted* path
  still has history. That is the trap that makes "release by writing a record,
  never by deleting" load-bearing rather than stylistic, and a fake without it
  would let the wrong implementation pass.
* **a stale CAS is refused**, which is the primitive itself.
* **a merge patch deletes a key mapped to ``None``** (#183) rather than storing
  one, which is RFC 7396 and is how ``pending`` is cleared at promotion. Shared
  with the read-modify-write fallback through
  :func:`~sopuli.payload.apply_patch`, so a store with the capability and one
  without cannot end up with two readings of the same RFC.
* **an older version is still readable by number**, and a soft delete removes
  the latest one only (#183). ``@version=N`` is a read of a generation that is
  no longer current, so a fake that kept only the newest document would answer
  every pinned read with ``None`` and let an adapter that did the same pass.
* **listing knows about paths that have nothing to read** (#150). A soft-deleted
  path and one that exists only because its metadata was configured are both
  listed here and both read as ``None``, because that is what a KV v2
  ``LIST metadata/`` answers -- metadata outlives the data. A fake that listed
  only readable paths would let an adapter pass with the easier semantics and
  then surprise ``lock status`` against a real Vault.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sopuli.clock import utc_now
from sopuli.payload import apply_patch
from sopuli.store.protocol import (
    CAS,
    LIST,
    MERGE_PATCH,
    OK,
    VERSIONING,
    CasConflictError,
    PathMetadata,
    Stored,
    StoreError,
    StoreHealth,
    bounded_prefix,
)


@dataclass
class _Path:
    """One path's history: every version ever written, by number.

    Kept in full rather than as a latest-plus-counter, because ``@version=N``
    (#183) is a read of an *older* generation and a store that had discarded it
    could only answer by pretending. ``deleted`` covers the latest version alone,
    which is what a KV v2 soft delete does -- the earlier versions stay readable
    by number, and that asymmetry is exactly the kind of thing a looser fake
    would paper over.
    """

    version: int = 0
    data: Any = None
    deleted: bool = False
    metadata: PathMetadata | None = None
    #: Every version written, by number. Never pruned: ``max_versions`` is
    #: reported by :class:`PathMetadata` and not enforced here, since the lock's
    #: pre-flight reads the setting and nothing in tier 0 depends on the pruning
    #: itself happening.
    history: dict[int, Any] = field(default_factory=dict)


@dataclass
class MemoryStore:
    """An in-memory store with KV v2's compare-and-set semantics.

    Not durable, not shared, and not a backend: two :class:`MemoryStore`
    instances know nothing about each other, which is exactly what makes it
    usable for the concurrency tests -- two "runs" contend by sharing *one*
    instance, and the test is then about the store's semantics rather than about
    Python threads.
    """

    paths: dict[str, _Path] = field(default_factory=dict)
    #: Capabilities this instance claims. Reducible, so the advisory-only path
    #: can be exercised against a store that genuinely has no ``cas`` rather than
    #: against one pretending not to -- and, since #150, so that a caller's
    #: handling of a store that cannot be listed is exercised the same way.
    capabilities: frozenset[str] = frozenset({CAS, LIST, MERGE_PATCH, VERSIONING})
    #: What this store answers :meth:`health` with, as its own clock (#216).
    #:
    #: Injectable for the reason :class:`~sopuli.lock.manager.LockManager`'s is:
    #: a skew of zero is what a fake sharing the caller's clock always reports,
    #: and a comparison exercised only against zero is a comparison that passes
    #: while broken. Handing this store a clock that is five minutes out is how
    #: the whole reporting path is tested without a container or a machine
    #: somebody has to misconfigure.
    clock: Callable[[], datetime] = utc_now

    def supports(self) -> frozenset[str]:
        return self.capabilities

    def health(self) -> StoreHealth:
        """Always reachable, and honest about why that proves nothing.

        There is no network here and nothing that can be down, so this is the one
        implementation for which :data:`~sopuli.store.protocol.OK` is a constant
        rather than a finding. What it *is* good for is the clock: :attr:`clock`
        is somebody else's, so the skew a caller computes from this is a real
        measurement of two clocks that genuinely disagree.

        **The store clock is bracketed exactly as the real adapter brackets it**
        -- host clock, store clock, host clock -- so ``measured_at`` is the
        midpoint of the interval the store's clock was read in and
        ``round_trip`` is that interval's real width. Which for a dictionary is
        microseconds and never worth reporting, and is the point anyway: this
        module is the *reference reading* of
        :mod:`sopuli.store.protocol`'s semantics, so a timing shape here that
        the protocol forbids is a fake that would let an adapter with the same
        fault pass the conformance suite. Reporting ``round_trip=0`` beside two
        readings taken at different instants was that fault, in the one place
        it is least affordable.

        For a skew assertion exact on *both* sides, a caller passes
        :meth:`~sopuli.store.protocol.StoreHealth.skew`'s ``local``, which pins
        the host half the same way :attr:`clock` pins the store's.
        """
        # The *store's* clock and this host's, read separately and never from
        # one source. Setting both from `clock` was the first version and was
        # useless: it makes the skew identically zero however far the injected
        # clock is moved, so the one thing this field exists to exercise cannot
        # be exercised through it.
        sent = utc_now()
        server_time = self.clock()
        received = utc_now()
        return StoreHealth(
            status=OK,
            server_time=server_time,
            measured_at=sent + (received - sent) / 2,
            round_trip=received - sent,
            # Nothing was asked of a credential, because there is none to ask
            # about. `None` is the protocol's "not asked", and reporting `True`
            # would be this store claiming to have checked something.
            authenticated=None,
        )

    def read(self, path: str, *, version: int | None = None) -> Stored | None:
        if version is not None and VERSIONING not in self.capabilities:
            raise StoreError(
                f"this store keeps no versions, and a read of {path!r} asked for version {version}",
                hint="drop the `@version=` qualifier, or point the ref at a store that versions",
            )
        entry = self.paths.get(path)
        if entry is None:
            return None
        if version is not None:
            # An older version outlives a soft delete, which removes the latest
            # one only -- so this deliberately does not consult `deleted`. Asking
            # for a version that was never written, or one above the latest,
            # answers `None` rather than raising: the protocol's rule is that a
            # version that is gone reads as nothing.
            if version not in entry.history:
                return None
            return Stored(data=copy.deepcopy(entry.history[version]), version=version)
        if entry.deleted or entry.version == 0:
            # Version 0 means the path exists only because its *metadata* was
            # configured -- `vault kv metadata put` before anything was ever
            # written. There is nothing to read, and a `cas: 0` write still
            # succeeds against it, which is what makes pre-flight's "configure
            # the path first" advice workable.
            return None
        # Copied on the way out: a caller that mutated what it read would be
        # editing the store's own state, which no real backend allows and which
        # would hide exactly the bugs this fake exists to expose.
        return Stored(data=copy.deepcopy(entry.data), version=entry.version)

    def write(self, path: str, data: Any, *, cas: int | None) -> int:
        entry = self.paths.setdefault(path, _Path())
        if cas is None and entry.metadata is not None and entry.metadata.cas_required:
            # What the setting is *for*: KV v2 refuses an unguarded write on a
            # path configured this way, whoever the writer is. A fake that
            # accepted one would let an implementation pass here and be rejected
            # by the real thing -- and the lock's pre-flight checks this exact
            # setting, so the emulation has to mean it.
            #
            # `StoreError` and **not** `CasConflictError`, which is what this
            # raised until the conformance suite ran it beside the real backend
            # (#104). Nothing raced: the write was refused because it carried no
            # version, not because the version moved. ADR-005 names the same
            # confusion from the other end -- Vault's message for this case opens
            # with the same words as the conflict's, and reporting it as a lost
            # race would have a run announce that somebody beat it to the path
            # when nobody was there at all.
            raise StoreError(f"{path!r} requires a compare-and-set and the write did not carry one")
        if cas is not None and cas != entry.version:
            raise CasConflictError(
                f"compare-and-set failed at {path!r}: expected version {cas}, found {entry.version}"
            )
        if cas == 0 and entry.version != 0:
            # Unreachable through the check above, and kept as the statement of
            # the rule: `cas: 0` means "there must be nothing here", and a path
            # that once held something is not nothing.
            raise CasConflictError(f"compare-and-set failed at {path!r}: the path has a history")
        entry.version += 1
        entry.data = copy.deepcopy(data)
        entry.history[entry.version] = entry.data
        entry.deleted = False
        if entry.metadata is None:
            # A write creates the path's metadata, with nothing set on it.
            # Measured against Vault 2.0.4 (#390): `vault kv metadata get` on a
            # path that has only ever been written answers `cas_required: false`,
            # where before the write it answers nothing at all.
            #
            # **The fake did not do this, and that is how #390 stayed invisible
            # in tier 0.** The lock's pre-flight reads "no metadata" as "new
            # path, nothing to check", so against this store every run on a path
            # looked like the first one and the whole bug -- second run refused,
            # for metadata the first run created -- could not happen here. A fake
            # that is wrong in the direction of *nothing going wrong* is the
            # expensive kind, which is the argument for this module living in
            # `src/` and being held to the conformance suite.
            entry.metadata = PathMetadata()
        return entry.version

    def patch(self, path: str, changes: Any, *, cas: int | None) -> int:
        """Apply a merge patch, which here is a read and a write with no gap.

        A dictionary makes this trivial and that is the trap worth naming: on a
        real store the whole value of a merge patch is that the tool never sends
        the keys it did not change, and nothing about *this* implementation can
        demonstrate that. What it can hold is the arithmetic -- RFC 7396's
        deletion in particular -- and it holds it by calling the same
        :func:`~sopuli.payload.apply_patch` the read-modify-write fallback does,
        so the two can never drift into two readings of one RFC.

        **A patch will not create a document**, and that refusal is the one thing
        here a dictionary would happily get wrong. Vault answers 404 to a patch
        of a path with nothing at it -- never written, metadata-only, or
        soft-deleted alike -- because a patch describes a change to something. A
        fake that created the document instead would let a caller patch a path it
        had never written, pass in tier 0, and fail against a real mount.
        """
        if MERGE_PATCH not in self.capabilities:
            raise StoreError(
                f"this store cannot apply a merge patch, and a write to {path!r} asked it to",
                hint="read the document, apply the patch locally, and write it back under a `cas`",
            )
        existing = self.read(path)
        if existing is None:
            raise StoreError(
                f"there is nothing at {path!r} to merge a patch into",
                hint="the first write to a path creates it; a merge patch changes one that exists",
            )
        return self.write(path, apply_patch(existing.data, changes), cas=cas)

    def metadata(self, path: str) -> PathMetadata | None:
        entry = self.paths.get(path)
        return None if entry is None else entry.metadata

    def require_cas(self, path: str) -> None:
        """Set ``cas_required`` on ``path``, creating its metadata if need be (#390).

        The property the lock depends on, and the one a looser fake would get
        wrong: **this does not create a version.** A path configured here and
        never written still has ``version == 0``, so the ``cas: 0`` write a first
        acquisition makes still succeeds -- which is what makes it safe to
        arrange the guarantee *before* taking the lock rather than after. Checked
        against Vault 2.0.4 before it was written here (#390), because a fake
        that quietly bumped the counter would have let an implementation pass
        that locks every new path out of its own first acquisition.

        Refusal is not modelled: this store has no policy, and the one refusal
        that matters -- :class:`~sopuli.store.protocol.MetadataNotPermittedError` --
        is a backend's to raise. A test that wants it raises it from a stub around
        this one.
        """
        entry = self.paths.setdefault(path, _Path())
        current = entry.metadata or PathMetadata()
        entry.metadata = PathMetadata(cas_required=True, max_versions=current.max_versions)

    def list(self, prefix: str) -> tuple[str, ...]:
        """Every known path under ``prefix``, sorted.

        Every *known* path, which is not every readable one: a deleted entry and
        a metadata-only entry both stay in :attr:`paths` and both appear here.
        See the module note -- KV v2 lists metadata, and metadata outlives data.

        The prefix goes through :func:`~sopuli.store.protocol.bounded_prefix`,
        which is the interface's own rule rather than this store's reading of it
        -- the fake and the adapters have to answer one question the same way, or
        the conformance suite is comparing two different questions.
        """
        if LIST not in self.capabilities:
            raise StoreError(
                "this store cannot list paths, and something asked it to",
                hint="a store without the `list` capability can only be read a path at a time",
            )
        under = bounded_prefix(prefix)
        return tuple(sorted(path for path in self.paths if path.startswith(under)))

    # ------------------------------------------------ test-facing helpers ---

    def configure(self, path: str, metadata: PathMetadata) -> None:
        """Set a path's metadata without writing to it, as ``vault kv metadata`` does."""
        self.paths.setdefault(path, _Path()).metadata = metadata

    def delete(self, path: str) -> None:
        """Delete the data and keep the history.

        The trap in full: after this, ``read`` says ``None`` -- there is nothing
        to read -- but the version counter stands, so a ``cas: 0`` write still
        fails. A lock released by deleting would leave a path that can never be
        acquired again, which is why release writes a record instead.
        """
        entry = self.paths.get(path)
        if entry is not None:
            entry.deleted = True
            entry.data = None

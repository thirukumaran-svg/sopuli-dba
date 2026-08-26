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
  one, which is RFC 7386 and is how ``pending`` is cleared at promotion. Shared
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
from dataclasses import dataclass, field
from typing import Any

from sopuli.payload import apply_patch
from sopuli.store.protocol import (
    CAS,
    LIST,
    MERGE_PATCH,
    VERSIONING,
    CasConflictError,
    PathMetadata,
    Stored,
    StoreError,
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

    def supports(self) -> frozenset[str]:
        return self.capabilities

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
        return entry.version

    def patch(self, path: str, changes: Any, *, cas: int | None) -> int:
        """Apply a merge patch, which here is a read and a write with no gap.

        A dictionary makes this trivial and that is the trap worth naming: on a
        real store the whole value of a merge patch is that the tool never sends
        the keys it did not change, and nothing about *this* implementation can
        demonstrate that. What it can hold is the arithmetic -- RFC 7386's
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

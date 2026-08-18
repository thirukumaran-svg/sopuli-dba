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
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from sopuli.store.protocol import CAS, CasConflictError, PathMetadata, Stored, StoreError


@dataclass
class _Path:
    """One path's history. ``versions`` is empty for a path that was deleted."""

    version: int = 0
    data: Any = None
    deleted: bool = False
    metadata: PathMetadata | None = None


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
    #: against one pretending not to.
    capabilities: frozenset[str] = frozenset({CAS})

    def supports(self) -> frozenset[str]:
        return self.capabilities

    def read(self, path: str) -> Stored | None:
        entry = self.paths.get(path)
        if entry is None or entry.deleted or entry.version == 0:
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
        entry.deleted = False
        return entry.version

    def metadata(self, path: str) -> PathMetadata | None:
        entry = self.paths.get(path)
        return None if entry is None else entry.metadata

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

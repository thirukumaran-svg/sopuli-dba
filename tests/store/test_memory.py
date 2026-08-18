"""The KV v2 emulation, tested as the thing the lock's correctness rests on.

A fake that is wrong in the store's favour makes every test above it meaningless,
and the three properties below are exactly the ones a looser fake would get
wrong -- most of all the last, which is the reason a lock is released by writing
a record rather than by deleting one.
"""

from __future__ import annotations

import pytest

from sopuli.store import CAS, CasConflictError, MemoryStore, PathMetadata, StoreError


def test_a_fresh_path_has_nothing_and_no_version() -> None:
    store = MemoryStore()

    assert store.read("locks/apps/acme") is None


def test_versions_start_at_one_and_increase() -> None:
    """The version is the fencing token, so it has to be monotonic."""
    store = MemoryStore()

    assert store.write("locks/a", {"n": 1}, cas=0) == 1
    assert store.write("locks/a", {"n": 2}, cas=1) == 2
    assert store.read("locks/a").version == 2  # type: ignore[union-attr]


def test_a_stale_compare_and_set_is_refused() -> None:
    """The primitive itself: somebody wrote between the read and the write."""
    store = MemoryStore()
    store.write("locks/a", {"n": 1}, cas=0)

    with pytest.raises(CasConflictError) as caught:
        store.write("locks/a", {"n": 2}, cas=0)

    assert "expected version 0" in str(caught.value)


def test_a_write_without_a_compare_and_set_always_lands() -> None:
    """What `advisory-only` does, and why it is a weaker guarantee."""
    store = MemoryStore()
    store.write("locks/a", {"n": 1}, cas=0)

    assert store.write("locks/a", {"n": 2}, cas=None) == 2


def test_a_path_that_requires_a_compare_and_set_refuses_a_write_without_one() -> None:
    """What `cas_required` is *for*, and the lock's pre-flight checks it.

    KV v2 refuses an unguarded write on a path configured this way, whoever the
    writer is -- which is what stops an operator with a vault CLI from replacing
    a lock record without one. A fake that accepted the write would let an
    implementation pass here and be rejected by the real thing.

    A `StoreError` and **not** a `CasConflictError`: nothing raced. This asserted
    the conflict until `tests/store/test_store_conformance.py` ran the same body
    against a real Vault (#104) and the two disagreed -- the fake was the one
    that was wrong, which is the divergence that suite exists to find.
    """
    store = MemoryStore()
    store.configure("locks/a", PathMetadata(cas_required=True))

    with pytest.raises(StoreError) as caught:
        store.write("locks/a", {"n": 1}, cas=None)

    assert "requires a compare-and-set" in str(caught.value)
    assert store.write("locks/a", {"n": 1}, cas=0) == 1


def test_a_deleted_path_keeps_its_history() -> None:
    """The trap that makes "release by writing" load-bearing rather than tidy.

    After a delete there is nothing to read -- and `cas: 0` still fails, because
    the version counter stands. A lock released by deleting would leave a path
    that can never be acquired again.
    """
    store = MemoryStore()
    store.write("locks/a", {"n": 1}, cas=0)

    store.delete("locks/a")

    assert store.read("locks/a") is None
    with pytest.raises(CasConflictError):
        store.write("locks/a", {"n": 2}, cas=0)


def test_what_is_read_is_a_copy() -> None:
    """A caller that mutated a read would be editing the store's own state.

    No real backend allows that, and a fake that did would hide exactly the bugs
    it exists to expose.
    """
    store = MemoryStore()
    store.write("locks/a", {"holder": {"pid": 1}}, cas=0)

    stored = store.read("locks/a")
    assert stored is not None
    stored.data["holder"]["pid"] = 999

    assert store.read("locks/a").data["holder"]["pid"] == 1  # type: ignore[union-attr]


def test_metadata_is_separate_from_content() -> None:
    """`vault kv metadata put` on a path that has never been written."""
    store = MemoryStore()

    store.configure("locks/a", PathMetadata(cas_required=True, max_versions=10))

    assert store.read("locks/a") is None
    metadata = store.metadata("locks/a")
    assert metadata is not None
    assert metadata.cas_required


def test_a_store_can_be_built_without_compare_and_set() -> None:
    """So the advisory-only path is exercised against a store that genuinely
    lacks the capability rather than one pretending to."""
    store = MemoryStore(capabilities=frozenset())

    assert CAS not in store.supports()

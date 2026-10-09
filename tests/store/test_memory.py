"""The KV v2 emulation, tested as the thing the lock's correctness rests on.

A fake that is wrong in the store's favour makes every test above it meaningless,
and the three properties below are exactly the ones a looser fake would get
wrong -- most of all the last, which is the reason a lock is released by writing
a record rather than by deleting one.
"""

from __future__ import annotations

import pytest

from sopuli.store import CAS, CasConflictError, MemoryStore, PathMetadata, StoreError
from sopuli.store.protocol import LIST


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

    A `StoreError` and **not** a `CasConflictError`: nothing raced.
    `tests/store/test_store_conformance.py` runs the same body against a real
    Vault, so a disagreement between the fake and the real store shows up there.
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


# -------------------------------------------------------------------- listing ---
#
# What the conformance suite cannot ask, because it asks both stores the same
# question and these are about states only the fake can be put into.


def test_a_store_can_be_built_without_listing() -> None:
    """The capability a future backend may genuinely lack -- an OS keyring, or a
    store over something with no prefix query. Reducible here for the same reason
    `cas` is: so a caller's handling of the absence is exercised against a store
    that really lacks it."""
    store = MemoryStore(capabilities=frozenset({CAS}))

    assert LIST not in store.supports()


def test_a_store_that_cannot_list_raises_rather_than_answering_nothing() -> None:
    """The distinction the whole capability exists for.

    `()` would mean "I looked and there is nothing there", which a caller acts on
    by concluding no leftover locks exist. "I cannot look" has to be a different
    answer, or the absence of the capability is indistinguishable from a clean
    estate.
    """
    store = MemoryStore(capabilities=frozenset({CAS}))
    store.write("locks/apps/acme/db", {"state": "held"}, cas=0)

    with pytest.raises(StoreError) as caught:
        store.list("locks")

    assert "cannot list" in str(caught.value)


def test_a_metadata_only_path_is_listed_though_it_reads_as_nothing() -> None:
    """The other half of "knowing about a path is not having something to read".

    The conformance suite covers the soft-deleted case against both stores; this
    is the one a real Vault reaches through `vault kv metadata put` on a path
    nobody has ever written, which pre-flight's own advice tells operators to do.
    """
    store = MemoryStore()
    store.configure("locks/apps/acme/db", PathMetadata(cas_required=True))

    assert store.list("locks") == ("locks/apps/acme/db",)
    assert store.read("locks/apps/acme/db") is None


def test_a_prefix_matches_on_a_segment_boundary() -> None:
    """`locks` must not return `locksmiths/db`.

    Two applications whose names share a first word are not one prefix, and a
    bare `startswith` on the raw string says they are.
    """
    store = MemoryStore()
    store.write("locks/db", {"n": 1}, cas=0)
    store.write("locksmiths/db", {"n": 1}, cas=0)

    assert store.list("locks") == ("locks/db",)


@pytest.mark.parametrize("prefix", ["locks", "locks/", "/locks/", "//locks//"])
def test_the_separators_around_a_prefix_do_not_change_the_question(prefix: str) -> None:
    """One rule, in `sopuli/store/protocol.py`, so every store answers the same
    string the same way -- otherwise the conformance suite compares two different
    questions and passes."""
    store = MemoryStore()
    store.write("locks/db", {"n": 1}, cas=0)

    assert store.list(prefix) == ("locks/db",)


def test_an_empty_prefix_is_the_whole_store() -> None:
    store = MemoryStore()
    store.write("locks/db", {"n": 1}, cas=0)
    store.write("apps/acme/db", {"n": 1}, cas=0)

    assert store.list("") == ("apps/acme/db", "locks/db")

"""One test body, two stores (#104).

`MemoryStore` is the reference reading of `sopuli/store/protocol.py`'s semantics
(#96) and the KV v2 adapter is the first real backend, so the useful question is
not "does each work" but **"do they agree"**. Every test below runs against
both: the fake in tier 0, and Vault in tier 1 where a container is available.

Any place they disagree is either a bug in the adapter or a fake that was lying,
and both are worth finding. The fake is the one nobody would suspect, and it is
the one every lock test in the suite rests on.

Three of these are the properties #83's design actually depends on:

* **``cas: 0`` succeeds only on a path with no history**, and a *deleted* path
  still has history. That is what makes "release by writing a record, never by
  deleting" load-bearing rather than stylistic.
* **a lost compare-and-set is a ``CasConflictError``**, and never anything else.
* **the version comes back from the write**, so there is something to fence with.

Listing (#150) joined them, and it is the one where the fake is most likely to
be the liar: a dictionary makes "every path under this prefix" trivial, while a
KV mount answers one level at a time, marks subtrees with a trailing separator,
and lists paths whose data has been deleted. Every one of those is somewhere an
adapter can quietly disagree with the reference reading.

The harness gives each store the same three operations the protocol does not
have but the tests need -- wipe, soft-delete and configure -- because they are
the operations an *operator* has, and the traps above are about what happens
when somebody else has used them.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Protocol

import pytest

from sopuli.config.model import Vault
from sopuli.secrets import Secret
from sopuli.store import MemoryStore
from sopuli.store.protocol import (
    CAS,
    LIST,
    CasConflictError,
    PathMetadata,
    SecretStore,
    StoreError,
)


class Admin(Protocol):
    """What an operator can do to a path, which the store interface cannot."""

    def wipe(self, path: str) -> None: ...
    def soft_delete(self, path: str) -> None: ...
    def require_cas(self, path: str) -> None: ...


#: Where the memory store writes. The Vault half uses the stack's own scratch
#: path, which is the same string -- kept on the harness rather than as a module
#: constant so neither store has to know the other's.
PATH = "apps/acme/conformance"


@dataclass
class Harness:
    store: SecretStore
    admin: Admin
    path: str
    name: str


class _MemoryAdmin:
    def __init__(self, store: MemoryStore) -> None:
        self._store = store

    def wipe(self, path: str) -> None:
        self._store.paths.pop(path, None)

    def soft_delete(self, path: str) -> None:
        self._store.delete(path)

    def require_cas(self, path: str) -> None:
        self._store.configure(path, PathMetadata(cas_required=True))


class _VaultAdmin:
    """The same three operations, as an operator would issue them.

    `vault kv metadata delete` for the wipe -- data *and* the version counter,
    which is the only way to make a path new again and is deliberately not
    something the tool itself ever does (#83).
    """

    def __init__(self, client: Any, mount: str) -> None:
        self._client = client
        self._mount = mount

    def wipe(self, path: str) -> None:
        self._client.delete(f"/v1/{self._mount}/metadata/{path}")

    def soft_delete(self, path: str) -> None:
        self._client.delete(f"/v1/{self._mount}/data/{path}")

    def require_cas(self, path: str) -> None:
        self._client.post(f"/v1/{self._mount}/metadata/{path}", json={"cas_required": True})


@pytest.fixture(params=["memory", "kv2"])
def harness(request: pytest.FixtureRequest) -> Iterator[Harness]:
    """The same tests, once per store.

    `kv2` skips when there is no container, per `04-testing.md` §3 -- never a
    failure, or a fork without Docker could not run the suite at all.
    """
    if request.param == "memory":
        memory = MemoryStore()
        yield Harness(store=memory, admin=_MemoryAdmin(memory), path=PATH, name="memory")
        return

    stack = request.getfixturevalue("vault_stack")
    # Imported here rather than at module scope: it pulls in `httpx`, and a base
    # install has to reach the skip above instead of failing at collection.
    from sopuli.store.hashicorp import open_store

    admin = _VaultAdmin(stack.client, stack.kv2_mount)
    admin.wipe(stack.scratch)
    store = open_store(
        Vault(
            name="vault-dev",
            type="hashicorp",
            addr=stack.addr,
            mount=stack.kv2_mount,
            kv_version=2,
        ),
        token=Secret(stack.token),
    )
    yield Harness(store=store, admin=admin, path=stack.scratch, name="kv2")
    admin.wipe(stack.scratch)


#: The three paths every listing test writes, relative to the prefix the
#: :func:`tree` fixture yields.
#:
#: ``nested/gamma`` is the one that matters: it is the entry a KV mount answers
#: as a subtree marker rather than a document, so an adapter that forwarded the
#: raw level would return ``nested/`` and never see ``gamma`` at all.
TREE = ("alpha", "beta", "nested/gamma")


@pytest.fixture
def tree(harness: Harness) -> Iterator[str]:
    """Three documents under a prefix of their own, cleaned up afterwards.

    A *sibling* of ``harness.path`` rather than a subtree of it, so that the two
    coexist -- which is what makes the segment-boundary test mean something,
    since ``…/conformance`` and ``…/conformance-tree`` share every character of
    the first and differ only after it.

    Wiped key by key: the harness's own teardown wipes one path, and on a real
    Vault ``metadata delete`` on a prefix removes nothing under it.
    """
    prefix = f"{harness.path}-tree"
    for leaf in TREE:
        harness.store.write(f"{prefix}/{leaf}", {"leaf": leaf}, cas=0)
    yield prefix
    for leaf in TREE:
        harness.admin.wipe(f"{prefix}/{leaf}")


def test_a_store_with_compare_and_set_says_so(harness: Harness) -> None:
    assert CAS in harness.store.supports()


def test_a_store_that_can_be_listed_says_so(harness: Harness) -> None:
    assert LIST in harness.store.supports()


def test_a_fresh_path_reads_as_nothing(harness: Harness) -> None:
    assert harness.store.read(harness.path) is None


def test_the_first_write_takes_the_path_and_returns_a_version(harness: Harness) -> None:
    version = harness.store.write(harness.path, {"holder": "one"}, cas=0)

    assert version == 1


def test_what_was_written_is_what_is_read(harness: Harness) -> None:
    harness.store.write(harness.path, {"holder": "one", "nested": {"n": 1}}, cas=0)

    stored = harness.store.read(harness.path)

    assert stored is not None
    assert stored.data == {"holder": "one", "nested": {"n": 1}}
    assert stored.version == 1


def test_versions_increase_and_never_repeat(harness: Harness) -> None:
    """The version is the fencing token, so a store that reused one would make a
    stolen lock undetectable."""
    assert harness.store.write(harness.path, {"n": 1}, cas=0) == 1
    assert harness.store.write(harness.path, {"n": 2}, cas=1) == 2
    assert harness.store.write(harness.path, {"n": 3}, cas=2) == 3


def test_a_stale_compare_and_set_is_refused(harness: Harness) -> None:
    """The primitive itself: somebody wrote between this run's read and write."""
    harness.store.write(harness.path, {"n": 1}, cas=0)

    with pytest.raises(CasConflictError):
        harness.store.write(harness.path, {"n": 2}, cas=0)


def test_a_conflict_leaves_the_stored_value_alone(harness: Harness) -> None:
    """A refused write must not be a partial one."""
    harness.store.write(harness.path, {"holder": "first"}, cas=0)

    with pytest.raises(CasConflictError):
        harness.store.write(harness.path, {"holder": "second"}, cas=0)

    stored = harness.store.read(harness.path)
    assert stored is not None
    assert stored.data == {"holder": "first"}


def test_a_deleted_path_reads_as_nothing_but_keeps_its_history(harness: Harness) -> None:
    """**The trap the whole release design turns on.**

    After a delete there is nothing to read -- so `read` says `None`, exactly as
    it does for a path that never existed -- but the version counter stands, so
    `cas: 0` fails and will keep failing forever. A lock released by deleting
    would leave a path no first acquisition could ever take again, which is why
    #83 releases by writing a `released` record instead.
    """
    harness.store.write(harness.path, {"holder": "one"}, cas=0)
    harness.admin.soft_delete(harness.path)

    assert harness.store.read(harness.path) is None
    with pytest.raises(CasConflictError):
        harness.store.write(harness.path, {"holder": "two"}, cas=0)


def test_metadata_is_absent_for_a_path_nobody_has_touched(harness: Harness) -> None:
    """The ordinary state of a lock path before the first lock, so not a
    failure: pre-flight asks whether `cas_required` is set, and "no metadata" is
    a perfectly good answer."""
    assert harness.store.metadata("apps/acme/never-written-at-all") is None


def test_cas_required_is_reported(harness: Harness) -> None:
    """What pre-flight actually reads. A guarantee the tool cannot check is one
    it should not claim, so this is the check behind that claim."""
    harness.admin.require_cas(harness.path)

    metadata = harness.store.metadata(harness.path)

    assert metadata is not None
    assert metadata.cas_required is True


def test_an_unguarded_write_is_refused_where_cas_is_required(harness: Harness) -> None:
    """What the setting is *for*: it stops a **different** writer -- an operator
    with a vault CLI, a script -- clobbering the path without a version. The tool
    always sends one, so this is about everybody else.

    Refused, and **not as a conflict**. Nothing raced: the write carried no
    version, rather than a version that had moved. This is the case ADR-005 warns
    about from the wire end -- Vault's message for it opens with the same words
    as the conflict's -- and it is where the two stores first disagreed: the fake
    called it a `CasConflictError` until this test ran them side by side.
    """
    harness.admin.require_cas(harness.path)

    with pytest.raises(StoreError) as caught:
        harness.store.write(harness.path, {"holder": "unguarded"}, cas=None)

    assert not isinstance(caught.value, CasConflictError)


# ------------------------------------------------------------- listing (#150) ---


def test_a_prefix_with_nothing_under_it_lists_as_empty(harness: Harness) -> None:
    """Not an error. The ordinary state of the lock prefix in a store nobody has
    locked anything in, which is most stores most of the time."""
    assert harness.store.list(f"{harness.path}-nothing-here") == ()


def test_listing_returns_full_paths_that_can_be_read(harness: Harness, tree: str) -> None:
    """The property the protocol promises, asserted the way a caller uses it.

    Not "the right number of entries": every path that comes back is handed
    straight to `read`, which is what a caller does with them and what an adapter
    returning KV's tails would fail.
    """
    listed = harness.store.list(tree)

    assert listed == tuple(sorted(f"{tree}/{leaf}" for leaf in TREE))
    for path in listed:
        stored = harness.store.read(path)
        assert stored is not None, f"{path} was listed and could not be read"


def test_listing_recurses_and_returns_no_subtree_markers(harness: Harness, tree: str) -> None:
    """KV answers one level and marks a subtree with a trailing separator.

    Walking that is the adapter's job (`sopuli/store/hashicorp/_listing.py`), so
    the caller never sees `nested/` -- it sees `nested/gamma`, which is a path it
    can read.
    """
    listed = harness.store.list(tree)

    assert f"{tree}/nested/gamma" in listed
    assert not [path for path in listed if path.endswith("/")]


def test_listing_is_sorted(harness: Harness, tree: str) -> None:
    """Store order is nobody's contract, and a report whose rows move between
    runs is a report nobody can diff."""
    listed = harness.store.list(tree)

    assert list(listed) == sorted(listed)


def test_a_prefix_stops_at_a_segment_boundary(harness: Harness, tree: str) -> None:
    """`…/conformance` must not return `…/conformance-tree/alpha`.

    The failure a bare string comparison gives you, and the reason
    `bounded_prefix` is in the protocol module rather than in one store: two
    applications whose names share a first word are not one prefix.

    The prefix is a boundary and never an entry in its own right, which the same
    setup asserts: a document written *at* `harness.path` is not below it.
    """
    harness.store.write(harness.path, {"holder": "one"}, cas=0)

    listed = harness.store.list(harness.path)

    assert not [path for path in listed if path.startswith(tree)]
    assert harness.path not in listed


def test_a_deleted_path_is_still_listed_though_it_reads_as_nothing(
    harness: Harness, tree: str
) -> None:
    """Metadata outlives data, so listing and reading answer different questions.

    The divergence a dictionary-backed fake would never produce on its own, and
    the one an adapter cannot avoid: KV v2 lists `metadata/`, and a soft-deleted
    path still has metadata. Written down here because `lock status` depends on
    the pair -- a leftover path is *found* by listing and then reported as
    carrying no record, which is a different row from one nobody listed.
    """
    victim = f"{tree}/alpha"
    harness.admin.soft_delete(victim)

    assert victim in harness.store.list(tree)
    assert harness.store.read(victim) is None


def test_a_read_does_not_hand_back_the_stores_own_state(harness: Harness) -> None:
    """A caller that mutated what it read must not be editing the store.

    No real backend allows it, and a fake that did would hide exactly the bugs
    the fake exists to expose -- which is the kind of divergence this whole file
    is here to catch.
    """
    harness.store.write(harness.path, {"holder": "one"}, cas=0)

    first = harness.store.read(harness.path)
    assert first is not None
    assert isinstance(first.data, dict)
    first.data["holder"] = "mutated"

    second = harness.store.read(harness.path)
    assert second is not None
    assert second.data == {"holder": "one"}

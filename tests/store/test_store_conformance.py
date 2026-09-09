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
from datetime import timedelta
from typing import Any, Protocol

import pytest

from sopuli.clock import utc_now
from sopuli.config.model import Vault
from sopuli.lock.record import CLOCK_SKEW
from sopuli.secrets import Secret
from sopuli.store import MemoryStore
from sopuli.store.protocol import (
    CAS,
    LIST,
    MERGE_PATCH,
    OK,
    VERSIONING,
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


def test_a_store_that_keeps_versions_says_so(harness: Harness) -> None:
    assert VERSIONING in harness.store.supports()


def test_an_older_version_is_readable_by_number(harness: Harness) -> None:
    """What ``@version=N`` is (#183), and the reason the fake had to grow a
    history: a store that kept only the newest document would answer every
    pinned read with `None` and let an adapter that did the same pass."""
    harness.store.write(harness.path, {"password": "first"}, cas=0)
    harness.store.write(harness.path, {"password": "second"}, cas=1)

    pinned = harness.store.read(harness.path, version=1)
    assert pinned is not None
    assert pinned.data == {"password": "first"}
    assert pinned.version == 1


def test_a_pinned_read_reports_the_version_it_read(harness: Harness) -> None:
    """Not the latest one. A caller records what it *found*, and a store that
    echoed the current version would put the wrong number in the audit trail."""
    harness.store.write(harness.path, {"n": 1}, cas=0)
    harness.store.write(harness.path, {"n": 2}, cas=1)
    harness.store.write(harness.path, {"n": 3}, cas=2)

    pinned = harness.store.read(harness.path, version=2)
    assert pinned is not None
    assert pinned.version == 2


def test_a_version_that_was_never_written_reads_as_nothing(harness: Harness) -> None:
    """Above the latest, and so gone in the only sense that matters. `None`
    rather than an error, which is the protocol's rule for a version that is not
    there -- pruned, deleted, or never reached."""
    harness.store.write(harness.path, {"n": 1}, cas=0)

    assert harness.store.read(harness.path, version=9) is None


def test_a_soft_delete_removes_the_latest_version_only(harness: Harness) -> None:
    """The asymmetry a looser fake would paper over.

    KV v2's delete acts on the latest version; the earlier ones stay readable by
    number. So the *unqualified* read says `None` -- there is nothing current --
    while `version=1` still answers, and the two are not in conflict.
    """
    harness.store.write(harness.path, {"password": "first"}, cas=0)
    harness.store.write(harness.path, {"password": "second"}, cas=1)
    harness.admin.soft_delete(harness.path)

    assert harness.store.read(harness.path) is None
    pinned = harness.store.read(harness.path, version=1)
    assert pinned is not None
    assert pinned.data == {"password": "first"}


def test_a_store_that_can_merge_patch_says_so(harness: Harness) -> None:
    assert MERGE_PATCH in harness.store.supports()


def test_a_merge_patch_changes_only_the_keys_it_names(harness: Harness) -> None:
    """01-configuration.md §7's central promise, against the real endpoint.

    A dictionary makes this trivial and Vault does not: the merge patch is
    selected by a content type rather than by the URL, so an adapter that sent an
    ordinary body would *replace* the document here and pass against the fake.
    """
    harness.store.write(harness.path, {"acme_web_user": "one", "acme_api_user": "two"}, cas=0)

    harness.store.patch(harness.path, {"acme_web_user": "rotated"}, cas=1)

    stored = harness.store.read(harness.path)
    assert stored is not None
    assert stored.data == {"acme_web_user": "rotated", "acme_api_user": "two"}


def test_a_merge_patch_deletes_a_key_mapped_to_null(harness: Harness) -> None:
    """RFC 7396's deletion, which is how `pending` is cleared at promotion. A
    store that stored a null instead would leave a `pending` that reads as staged
    with no value rather than as cleared."""
    harness.store.write(harness.path, {"password": "one", "pending": "two"}, cas=0)

    harness.store.patch(harness.path, {"pending": None}, cas=1)

    stored = harness.store.read(harness.path)
    assert stored is not None
    assert stored.data == {"password": "one"}


def test_a_merge_patch_returns_the_new_version(harness: Harness) -> None:
    """The fence, from the write that made it -- the same rule `write` follows
    and for the same reason: reading it back afterwards would reopen the window
    the fence exists to close."""
    harness.store.write(harness.path, {"password": "one"}, cas=0)

    assert harness.store.patch(harness.path, {"password": "two"}, cas=1) == 2


def test_a_merge_patch_will_not_create_a_document(harness: Harness) -> None:
    """A patch describes a change to something, and Vault answers 404 when there
    is nothing to change. The fake has to refuse it too: a dictionary would
    create the document quite happily, and a caller patching a path it had never
    written would then pass in tier 0 and fail against a real mount."""
    with pytest.raises(StoreError) as raised:
        harness.store.patch(harness.path, {"password": "one"}, cas=0)

    assert not isinstance(raised.value, CasConflictError)
    assert "nothing at" in str(raised.value)


def test_a_merge_patch_will_not_undelete(harness: Harness) -> None:
    """The same refusal for the state that reads identically but is not the same
    -- a soft-deleted path has a history, so `cas: 0` could never take it either.
    Both stores answer this on the read, which is why one rule covers both."""
    harness.store.write(harness.path, {"password": "one"}, cas=0)
    harness.admin.soft_delete(harness.path)

    with pytest.raises(StoreError) as raised:
        harness.store.patch(harness.path, {"password": "two"}, cas=1)

    # Not a lost race: the version never moved. Asserted because a conflict is
    # the other way this could fail, and it would be right for the wrong reason.
    assert not isinstance(raised.value, CasConflictError)
    assert "nothing at" in str(raised.value)


def test_a_stale_merge_patch_is_refused(harness: Harness) -> None:
    """A patch is not a substitute for a compare-and-set: it says which keys
    change, not which version they change. §7 wants a foreign writer to abort the
    run rather than be merged over."""
    harness.store.write(harness.path, {"password": "one"}, cas=0)
    harness.store.write(harness.path, {"password": "somebody-elses"}, cas=1)

    with pytest.raises(CasConflictError):
        harness.store.patch(harness.path, {"password": "mine"}, cas=1)


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


def test_a_store_can_require_a_compare_and_set_for_itself(harness: Harness) -> None:
    """The write half of the metadata pair (#390).

    Until then only an *operator* could set this -- `Admin.require_cas` above is
    exactly the `vault kv metadata put` a human runs -- so the lock could read
    the guarantee and never arrange one. Now the store does it, and both stores
    have to agree about what it leaves behind.
    """
    harness.store.require_cas(harness.path)

    metadata = harness.store.metadata(harness.path)

    assert metadata is not None
    assert metadata.cas_required is True


def test_requiring_a_compare_and_set_does_not_create_a_version(harness: Harness) -> None:
    """The property the lock's first acquisition rests on (#390).

    Metadata outlives data in KV v2 and, in the other direction, arrives without
    it: configuring a path leaves the version counter at zero, so the ``cas: 0``
    write a first acquisition makes still succeeds afterwards. Were it otherwise,
    arranging the guarantee would lock every new path out of its own first
    acquisition -- the same trap a deleted lock record sets, from the other end.

    Measured against Vault 2.0.4 before the code was written, and here so that
    the fake cannot quietly disagree: a store that bumped the counter would make
    every new lock unacquirable and would do it only in tier 1.
    """
    harness.store.require_cas(harness.path)

    assert harness.store.read(harness.path) is None
    version = harness.store.write(harness.path, {"state": "held"}, cas=0)

    assert version == 1


def test_a_store_that_required_it_then_refuses_an_unguarded_write(harness: Harness) -> None:
    """End to end, and the whole point of #390: the guarantee the store arranged
    for itself is the same one an operator's `vault kv metadata put` arranges.

    The test above this one asserts the setting is reported; this asserts it
    *bites*, through the store's own call rather than the admin helper -- which
    is the difference between the metadata being set and the metadata being set
    to something Vault enforces.
    """
    harness.store.require_cas(harness.path)
    harness.store.write(harness.path, {"state": "held"}, cas=0)

    with pytest.raises(StoreError) as caught:
        harness.store.write(harness.path, {"state": "clobbered"}, cas=None)

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


# ----------------------------------------------------------------- health ---
#
# The last of P2's sketch to arrive (#216), and the one where the fake is least
# able to stand in for the real thing: `MemoryStore` has no network and nothing
# that can be down, so `ok` is a constant for it rather than a finding. What is
# worth asserting jointly is the *shape* of the answer -- that both report the
# vocabulary, and that a store claiming a server time gives one a skew can
# actually be computed from.


def test_a_reachable_store_reports_ok(harness: Harness) -> None:
    assert harness.store.health().status == OK


def test_health_never_writes(harness: Harness) -> None:
    """P5: `doctor` mutates nothing, and `health` is the only store call it makes.

    Against a real Vault this is the case that matters, because the tempting
    implementation -- prove the store is writable by writing to it -- passes
    every other test in this file and leaves a document behind on a mount a
    rotation is using.
    """
    harness.admin.wipe(harness.path)

    harness.store.health()

    assert harness.store.read(harness.path) is None


def test_a_store_that_reports_a_clock_reports_an_aware_utc_one(harness: Harness) -> None:
    """`None` is allowed; a naive datetime is not.

    A timestamp without an offset compared against an aware one raises, so a
    backend answering with one would fail at the subtraction rather than here --
    several layers from the module that produced it.
    """
    server_time = harness.store.health().server_time

    if server_time is None:
        pytest.skip(f"{harness.name} exposes no server clock")
    assert server_time.tzinfo is not None
    assert server_time.utcoffset() == timedelta(0)


def test_a_store_that_reports_a_clock_can_be_asked_for_a_skew(harness: Harness) -> None:
    """The two halves arrive together or not at all.

    `server_time` without `measured_at` is a reading with nothing to compare it
    to, and would answer `None` from `skew()` while looking as though it had
    measured something.
    """
    report = harness.store.health()

    if report.server_time is None:
        pytest.skip(f"{harness.name} exposes no server clock")
    assert report.measured_at is not None
    assert report.skew(CLOCK_SKEW) is not None


def test_a_clock_five_minutes_out_is_beyond_what_the_lock_tolerates(harness: Harness) -> None:
    """The comparison, against a **real** server reading on the Vault half.

    The host clock is the injected half here, and deliberately so: a container
    shares the runner's clock, so a test taking both sides as it finds them only
    ever measures zero -- and a comparison exercised only against zero is one
    that passes while broken.
    """
    report = harness.store.health()

    if report.measured_at is None:
        pytest.skip(f"{harness.name} exposes no server clock")
    skew = report.skew(CLOCK_SKEW, local=report.measured_at + timedelta(minutes=5))

    assert skew is not None
    assert skew.beyond_tolerance


def test_a_reading_is_bracketed_by_this_host_s_clock(harness: Harness) -> None:
    """`measured_at` is a midpoint inside the call, and `round_trip` is its width.

    The shape `StoreHealth` promises, asserted from outside where it can be:
    a midpoint outside the window the call occupied is not a midpoint, and a
    round trip wider than the call is one the store invented -- and an invented
    one widens the uncertainty band, which is how a genuinely skewed clock stops
    being reported.

    It constrains the shape rather than reproducing any particular fault: for a
    store this fast the interval is microseconds, so a reading taken at one end
    rather than the middle is not distinguishable from out here. The bracket in
    each implementation is what makes it right; this is what stops it drifting.
    """
    before = utc_now()
    report = harness.store.health()
    after = utc_now()

    if report.measured_at is None:
        pytest.skip(f"{harness.name} exposes no server clock")
    assert before <= report.measured_at <= after
    assert report.round_trip is not None
    assert timedelta(0) <= report.round_trip <= after - before

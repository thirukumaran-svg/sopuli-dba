"""KV v1: a store with no compare-and-set, against the real mount (#104, #94).

`test/compose.yaml` mounts `kv1` beside `kv` precisely so this is testable — P2's
degradation path needs a backend that genuinely lacks the capability, and this is
**the first time "this store has no `cas`" is a fact rather than a constructor
argument**. `MemoryStore` can be built with the capability removed, which proves
the code branches; only a real v1 mount proves the branch matches reality.

Tier 1, so it skips without the container rather than failing (`04-testing.md`
§3). What it makes runnable is §5's row: "KV v1 degradation: no versioning,
staging emulated in payload, and the tool says so" — the store half of it.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from sopuli.config.model import Vault
from sopuli.secrets import Secret
from sopuli.store.protocol import CAS, LIST, SecretStore, StoreError

PATH = "apps/acme/kv1-degradation"


@pytest.fixture
def store(vault_stack: Any) -> Iterator[SecretStore]:
    # Imported here rather than at module scope: it pulls in `httpx`, and a base
    # install has to reach the skip in `vault_stack` instead of failing at
    # collection (ADR-006).
    from sopuli.store.hashicorp import open_store

    vault_stack.client.delete(f"/v1/{vault_stack.kv1_mount}/{PATH}")
    yield open_store(
        Vault(
            name="legacy-kv",
            type="hashicorp",
            addr=vault_stack.addr,
            mount=vault_stack.kv1_mount,
            kv_version=1,
        ),
        token=Secret(vault_stack.token),
    )
    vault_stack.client.delete(f"/v1/{vault_stack.kv1_mount}/{PATH}")


def test_a_v1_mount_has_no_compare_and_set(store: SecretStore) -> None:
    """The whole of the degradation, in one answer. P2 emulates a missing
    capability in the payload -- except `cas`, which cannot be emulated, because
    "not atomic" is precisely what it is for."""
    assert CAS not in store.supports()


def test_a_v1_mount_can_still_be_listed(store: SecretStore) -> None:
    """Capabilities are per capability, not a tier (#150).

    This used to assert an empty set, which read as "v1 is the degraded one" and
    was wrong about a capability v1 has: a v1 mount enumerates perfectly well.
    Reporting no `list` because the *interesting* capability is missing would
    deny `lock status` a leftover record it could have found.
    """
    assert store.supports() == frozenset({LIST})


def test_an_unguarded_write_works(store: SecretStore) -> None:
    """What `locking: advisory-only` accepts knowingly: the record is written,
    with nothing guarding it (#83, #94)."""
    store.write(PATH, {"holder": "one"}, cas=None)

    stored = store.read(PATH)
    assert stored is not None
    assert stored.data == {"holder": "one"}


def test_a_write_asking_for_a_compare_and_set_is_refused(store: SecretStore) -> None:
    """Refused rather than silently written.

    Sending it anyway and returning a number is the one answer that would be
    dangerous: the caller would hold what it believes is a fence, and two runs
    could hold it at once. The message names `enable-versioning` and
    `advisory-only`, which are the two ways out.
    """
    with pytest.raises(StoreError) as caught:
        store.write(PATH, {"holder": "one"}, cas=0)

    assert "compare-and-set" in str(caught.value)
    assert "advisory-only" in str(caught.value)


def test_a_second_write_overwrites_without_complaint(store: SecretStore) -> None:
    """No versioning: the thing a v2 mount would have refused, this one does
    quietly. Which is exactly why a store like this gets no lock rather than a
    weaker one."""
    store.write(PATH, {"holder": "one"}, cas=None)
    store.write(PATH, {"holder": "two"}, cas=None)

    stored = store.read(PATH)
    assert stored is not None
    assert stored.data == {"holder": "two"}


def test_the_version_it_reports_is_not_a_fence(store: SecretStore) -> None:
    """Zero, and it never moves. A number that climbed would be the lie that
    makes a stolen lock undetectable -- the lock manager keeps no fence for a
    store that cannot fence, and this is what it would be keeping."""
    store.write(PATH, {"holder": "one"}, cas=None)
    first = store.read(PATH)
    store.write(PATH, {"holder": "two"}, cas=None)
    second = store.read(PATH)

    assert first is not None
    assert second is not None
    assert first.version == second.version == 0


def test_a_missing_path_reads_as_nothing(store: SecretStore) -> None:
    assert store.read("apps/acme/never-written-on-v1") is None


#: Three documents under `TREE_PREFIX`, `nested/gamma` being the one that
#: matters: a v1 listing marks it as a subtree exactly as v2 does, so an adapter
#: that forwarded the raw level would return `nested/` and never reach it.
LEAVES = ("alpha", "beta", "nested/gamma")

#: A prefix of this test file's own, and not a shared parent like `apps/acme`.
#: The mount outlives the session, so listing a shared parent would survey
#: whatever every other test had left there -- an assertion that passes or fails
#: on test *ordering*, which is the one thing a store test must not depend on.
TREE_PREFIX = f"{PATH}-tree"


@pytest.fixture
def tree(store: SecretStore, vault_stack: Any) -> Iterator[str]:
    """`LEAVES` written under `TREE_PREFIX`, removed key by key afterwards.

    Key by key because a v1 mount has no metadata endpoint: deleting a prefix
    removes nothing under it, and there is no soft delete to undo either.
    """
    for leaf in LEAVES:
        store.write(f"{TREE_PREFIX}/{leaf}", {"leaf": leaf}, cas=None)
    yield TREE_PREFIX
    for leaf in LEAVES:
        vault_stack.client.delete(f"/v1/{vault_stack.kv1_mount}/{TREE_PREFIX}/{leaf}")


def test_listing_walks_a_v1_mount(store: SecretStore, tree: str) -> None:
    """The same walk as v2, one endpoint shorter -- against the real mount."""
    listed = store.list(tree)

    assert listed == tuple(sorted(f"{tree}/{leaf}" for leaf in LEAVES))
    assert not [path for path in listed if path.endswith("/")]


def test_everything_a_v1_mount_lists_can_be_read(store: SecretStore, tree: str) -> None:
    """v1's one advantage over v2 here: no soft delete, so listing and reading
    agree. On v2 a deleted path keeps its metadata and stays listed while reading
    as nothing -- there is no such state for a v1 mount to have."""
    for path in store.list(tree):
        assert store.read(path) is not None, f"{path} was listed and could not be read"


def test_a_prefix_with_nothing_under_it_lists_as_empty(store: SecretStore) -> None:
    """A 404 from the listing endpoint, which is not a failure."""
    assert store.list(f"{PATH}-nothing-here") == ()


def test_there_is_no_metadata_to_read(store: SecretStore) -> None:
    """`None` is honest here: a v1 mount has no metadata endpoint, so the store
    knows nothing about the path apart from its contents. What the lock does
    about a store that cannot promise `cas_required` is the capability check,
    not this."""
    store.write(PATH, {"holder": "one"}, cas=None)

    assert store.metadata(PATH) is None

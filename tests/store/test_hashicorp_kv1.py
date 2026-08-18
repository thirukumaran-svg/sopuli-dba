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
from sopuli.store.protocol import CAS, SecretStore, StoreError

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


def test_a_v1_mount_reports_no_capabilities(store: SecretStore) -> None:
    """The whole of the degradation, in one answer. P2 emulates a missing
    capability in the payload -- except `cas`, which cannot be emulated, because
    "not atomic" is precisely what it is for."""
    assert store.supports() == frozenset()
    assert CAS not in store.supports()


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


def test_there_is_no_metadata_to_read(store: SecretStore) -> None:
    """`None` is honest here: a v1 mount has no metadata endpoint, so the store
    knows nothing about the path apart from its contents. What the lock does
    about a store that cannot promise `cas_required` is the capability check,
    not this."""
    store.write(PATH, {"holder": "one"}, cas=None)

    assert store.metadata(PATH) is None

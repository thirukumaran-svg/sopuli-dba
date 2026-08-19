"""The walk that turns KV's one-level listing into a recursive one (#150).

Tier 0: the walk takes a fetch function, so every level here is a dictionary and
nothing opens a socket. The adapters' own endpoints are covered against a real
Vault by `test_store_conformance.py` and `test_hashicorp_kv1.py`; what is left
for this file is the two things a working store never produces.

**A malformed answer.** `keys_of` is strict on purpose -- a 200 without a `keys`
array has told the caller nothing, and returning `()` would report that as an
empty estate.

**An answer that is not a tree.** A level naming itself would loop forever
against a store that had gone wrong, which is the worst failure mode available:
it never ends and never allocates, so nothing times out and nothing crashes.
"""

from __future__ import annotations

import pytest

# Tier 0 by tier -- no container, no network -- but not by *install shape*:
# `_listing` reads a `Response`, which lives beside the `httpx` client the
# `hashicorp` extra installs. A skip rather than a collection error, so the rest
# of the suite still runs on a base+dev install (`04-testing.md` §3).
pytest.importorskip("httpx", reason="the hashicorp extra is not installed")

from sopuli.store.hashicorp._listing import keys_of, walk  # noqa: E402
from sopuli.store.hashicorp._transport import Response  # noqa: E402
from sopuli.store.protocol import StoreError  # noqa: E402

#: A three-level mount, as a fetch function's worth of answers. Keys ending in
#: `/` are subtrees, which is KV's own marking.
TREE: dict[str, tuple[str, ...]] = {
    "": ("locks/", "apps/"),
    "locks/": ("db", "nested/"),
    "locks/nested/": ("deep",),
    "apps/": ("acme",),
}


def fetch(prefix: str) -> tuple[str, ...] | None:
    return TREE.get(prefix)


def test_a_walk_returns_full_paths_with_the_prefix_still_on_them() -> None:
    """What the protocol promises: an entry can be handed straight to `read`."""
    assert walk(fetch, "locks") == ("locks/db", "locks/nested/deep")


def test_a_walk_descends_and_drops_the_subtree_markers() -> None:
    """`nested/` is an instruction to the walk, not a path anybody can read."""
    listed = walk(fetch, "locks")

    assert "locks/nested/" not in listed
    assert "locks/nested/deep" in listed


def test_a_walk_of_the_whole_mount_starts_at_the_empty_prefix() -> None:
    assert walk(fetch, "") == ("apps/acme", "locks/db", "locks/nested/deep")


def test_a_prefix_the_store_has_nothing_under_is_empty_rather_than_an_error() -> None:
    """The fetch answers `None` for a 404, and the walk ends there. Ordinary for
    the lock prefix in a store nobody has locked anything in."""
    assert walk(fetch, "nothing-here") == ()


def test_a_walk_terminates_on_a_level_that_names_itself() -> None:
    """A store that answered a listing of `locks/` with the key `locks/`.

    Impossible from a working Vault, and the reason `seen` is in the walk rather
    than an optimisation: without it this loops forever, allocating nothing, so
    no timeout and no memory limit ever ends it.
    """
    looping = {"locks/": ("locks/", "db")}

    assert walk(lambda prefix: looping.get(prefix), "locks") == ("locks/db",)


def test_an_empty_key_is_skipped_rather_than_re_walked() -> None:
    """`""` and `"/"` both resolve to the prefix itself, which is the same loop
    by another spelling."""
    odd = {"locks/": ("", "/", "db")}

    assert walk(lambda prefix: odd.get(prefix), "locks") == ("locks/db",)


@pytest.mark.parametrize(
    ("why", "body"),
    [
        ("no envelope", None),
        ("no data", {"lease_id": ""}),
        ("no keys", {"data": {}}),
        ("keys is not a list", {"data": {"keys": "db"}}),
        ("a key is not a string", {"data": {"keys": ["db", 7]}}),
    ],
)
def test_a_listing_without_a_list_of_keys_is_refused(why: str, body: object) -> None:
    """Every shape short of the real one, because `()` would be a lie.

    A caller acts on an empty listing by concluding there are no leftover locks.
    That conclusion has to be earned by an answer, not by a response nobody could
    parse.
    """
    with pytest.raises(StoreError) as caught:
        keys_of(Response(status=200, body=body), prefix="locks/")

    assert "without a list of keys" in str(caught.value), why


def test_a_well_formed_listing_comes_back_in_the_stores_own_order() -> None:
    """`keys_of` reads one level and sorts nothing: the ordering promise is the
    walk's, over the whole answer, and sorting twice would hide which one holds
    it."""
    response = Response(status=200, body={"data": {"keys": ["db", "apps/"]}})

    assert keys_of(response, prefix="locks/") == ("db", "apps/")

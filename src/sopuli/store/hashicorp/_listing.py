"""Turning KV's one-level listing into the protocol's recursive one (#150).

Both mounts answer a ``LIST`` the same shape -- ``{"data": {"keys": [...]}}``,
one level deep, with a trailing ``/`` marking a key that is a subtree rather than
a document -- and differ only in the endpoint it is asked of. So the walk lives
here once and each adapter supplies its own fetch, which is the same arrangement
:mod:`._errors` has with status mapping.

**The recursion is the adapter's job and not the caller's**, which is the whole
reason this module exists. ``sopuli/store/protocol.py`` promises full paths that
can be handed straight back to ``read``; a caller given Vault's tails and
subtree markers would reassemble them itself, identically, once per backend --
and would get the separator handling wrong the first time a prefix did not end
in one.
"""

from __future__ import annotations

from collections.abc import Callable

from sopuli.store.hashicorp._transport import Response
from sopuli.store.protocol import StoreError, bounded_prefix

#: One level of a listing: the raw keys at a prefix, or ``None`` for a prefix
#: the store has nothing under. ``None`` rather than ``()`` because the fetch is
#: what sees the 404, and "there is no such prefix" is a fact worth keeping
#: distinct from "the prefix exists and is empty" even though this module treats
#: them alike.
Level = Callable[[str], tuple[str, ...] | None]

#: What KV puts on the end of a key that is a subtree rather than a document.
SUBTREE = "/"


def keys_of(response: Response, *, prefix: str) -> tuple[str, ...]:
    """The ``keys`` array of one level, refused if that is not what came back.

    Both mounts answer ``{"data": {"keys": [...]}}``, so this is one function
    rather than one per adapter.

    Strict, for the reason :meth:`~sopuli.store.hashicorp.kv2.Kv2Store.read` is
    strict about a missing version: a store that answered 200 to a listing and
    could not say what was under the prefix has told the caller nothing, and
    returning ``()`` would report that as "there is nothing there" -- which is
    exactly the answer #150 makes load-bearing, since a caller acts on it by
    concluding that no leftover locks exist.
    """
    body = response.body
    payload = body.get("data") if isinstance(body, dict) else None
    keys = payload.get("keys") if isinstance(payload, dict) else None
    if not isinstance(keys, list) or not all(isinstance(key, str) for key in keys):
        raise StoreError(
            f"the store answered a listing of {prefix!r} without a list of keys",
            hint="is this a KV mount? A listing answers `data.keys`",
        )
    return tuple(keys)


def walk(fetch: Level, prefix: str) -> tuple[str, ...]:
    """Every document below ``prefix``, sorted, with the prefix still on the front.

    Iterative rather than recursive: a KV mount's depth is whatever an operator
    made it, and a deep estate should not be able to reach Python's recursion
    limit through a listing.

    ``seen`` is not an optimisation. A tree cannot contain a cycle, but nothing
    here has established that the answer *is* a tree -- a store that answered a
    listing of ``locks/`` with the key ``locks/`` would put this in a loop that
    never ends and never allocates, which is the worst failure mode available.
    Refusing to descend into a prefix twice makes the walk terminate on any
    answer at all.
    """
    root = bounded_prefix(prefix)
    found: set[str] = set()
    seen = {root}
    pending = [root]

    while pending:
        here = pending.pop()
        keys = fetch(here)
        if keys is None:
            continue
        for key in keys:
            if not key or key == SUBTREE:
                # A store that offered an empty name has nothing to address, and
                # descending into `here` again is the loop `seen` also guards.
                continue
            child = f"{here}{key}"
            if not key.endswith(SUBTREE):
                found.add(child)
            elif child not in seen:
                seen.add(child)
                pending.append(child)
    return tuple(sorted(found))

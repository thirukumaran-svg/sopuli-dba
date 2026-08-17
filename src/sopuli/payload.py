"""Where each of C14's three stages lives inside one secret document (Q7, #85).

Q7 made **one secret per application, a field per account** the documented
default, and left one secret per account fully supported. This module is the
reason that is a default rather than a fork: both layouts resolve through one
rule, so nothing above it has two code paths to keep in step.

    Every root-level key mirrors the shape of the current-stage container.

The *container* is whatever the configured ref addresses -- its field, and any
JSON pointer below it. Where that is a scalar, ``pending``, ``previous`` and the
rotation stamps are scalars beside it, which is UC-1 §3's original payload
unchanged. Where it is a map keyed by account, they are maps keyed the same way::

    apps/orders/db/creds#password           ->  container "password",       within ()
    tenants/beta#DB_CREDENTIALS/{account}   ->  container "DB_CREDENTIALS",
                                                within ("{account}",)

Three consequences are worth naming, because each is a thing this module does
*not* have to do:

**No new pointer syntax.** ``#pending/acme_web_user`` takes the same pointer
below a different root key, so ``@stage=pending`` is "the ``pending`` sibling,
same key" in both layouts and :meth:`StageLayout.location` is the whole mapping.

**No nesting of the triple.** The rejected shape was an object per account
holding its own ``password``/``pending``/``previous``. It would have made the ref
an application reads resolve to a document rather than to a password, which is a
change to every consumer to save this module a rule it needs anyway.

**No plaintext.** Values move through here as :class:`~sopuli.secrets.Secret` and
are never unwrapped: a patch built here carries the wrapper all the way to the
store, where the vault write is one of invariant 2's three permitted reveals.
There is deliberately no ``reveal()`` in this file.

What this module is not is the *write*. It computes locations and merge patches;
issuing them, and holding the lock while it happens, belongs to the store adapter
(#104) and the commands above it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.secret_refs import STAGES, SecretRef

CURRENT, PENDING, PREVIOUS = STAGES

#: UC-1 §3's rotation stamps. Per-account in a shared document for the same
#: reason the stages are: a single account can be rotated inside one, so a
#: root-level ``rotated_at`` would describe some of the document and not the
#: rest. ``username`` from §3's original payload has no counterpart here -- in
#: the shared layout the map key *is* the username, and a second copy of it is a
#: thing that can disagree with itself.
STAMPS = ("rotated_at", "rotated_by", "policy", "targets")

#: Root keys the mirror rule generates, and therefore names a container may not
#: take. ``current`` is absent on purpose: it is not a root key -- the container
#: *is* the current stage -- so a field genuinely called ``current`` collides
#: with nothing.
RESERVED = (PENDING, PREVIOUS, *STAMPS)

#: What a JSON merge patch (RFC 7386) uses to remove a key, which is how
#: ``pending`` is cleared at promotion. Named because ``None`` in a patch means
#: "delete this" and not "no value", and those read identically at a call site.
REMOVE = None

__all__ = [
    "CURRENT",
    "PENDING",
    "PREVIOUS",
    "REMOVE",
    "RESERVED",
    "STAMPS",
    "StageLayout",
    "merge",
    "stage_layout",
]


@dataclass(frozen=True)
class StageLayout:
    """One secret document, seen as the mirror rule sees it.

    Frozen and comparable, because two refs that address the same account in the
    same document have to *be* one layout rather than two that happen to agree --
    the same argument :class:`~sopuli.lock.keys.LockKey` makes about paths.
    """

    #: The root key holding the current stage: the ref's field.
    container: str
    #: The pointer segments below it, unescaped. Empty when the container holds
    #: the value itself, which is the one-secret-per-account layout.
    within: tuple[str, ...] = ()

    @property
    def is_addressed(self) -> bool:
        """Whether the document can hold more than this one credential.

        True when a pointer addresses *into* the container. It says the layout
        permits company, not that there is any: a per-application document with
        one account declared today is still shared in shape, and is the case
        ``plan.shared_secrets`` reports on only once a second account appears.
        """
        return bool(self.within)

    def location(self, key: str = CURRENT) -> tuple[str, ...]:
        """The path to ``key``'s value, as document keys from the root.

        ``key`` is a stage from C14's closed vocabulary or one of :data:`STAMPS`.
        The mapping is the mirror rule and nothing else: swap the root key, keep
        the pointer.
        """
        root = self.container if key == CURRENT else key
        return (root, *self.within)

    def read(self, document: Mapping[str, Any] | None, key: str = CURRENT) -> Any | None:
        """What ``document`` holds at ``key``, or ``None`` if it holds nothing.

        A missing key and a missing document are the same answer deliberately.
        The states this distinguishes -- no ``pending``, a ``pending`` for other
        accounts but not this one, no document at all -- are all "there is
        nothing staged here", and UC-1 §3's state model reads them that way.

        ``None`` is accepted for that reason rather than as tolerance.
        :meth:`~sopuli.store.protocol.SecretStore.read` returns ``None`` for a
        path with nothing at it, which is the very first rotation and not an
        error; requiring a mapping here would put ``or {}`` at every call site,
        and a call site that substitutes an empty document is a call site that
        can substitute the wrong one.
        """
        node: Any = document
        for segment in self.location(key):
            if not isinstance(node, Mapping) or segment not in node:
                return None
            node = node[segment]
        return node

    def accounts(self, document: Mapping[str, Any] | None, key: str = CURRENT) -> tuple[str, ...]:
        """Every key alongside this one in ``document``'s ``key`` container.

        The raw material for ``plan.shared_secrets[].accounts``: who else's
        credential a write to this document would sit next to. Empty for an
        unaddressed layout, where there is no container to look inside, and for
        a document that is not there yet -- same reasoning as :meth:`read`.

        Sorted, because it reaches a plan a human compares between runs, and
        insertion order in a document nobody controls is not an order.
        """
        if not self.is_addressed:
            return ()
        node: Any = document
        for segment in self.location(key)[:-1]:
            if not isinstance(node, Mapping) or segment not in node:
                return ()
            node = node[segment]
        if not isinstance(node, Mapping):
            return ()
        return tuple(sorted(str(name) for name in node))

    def patch(self, key: str, value: Any) -> dict[str, Any]:
        """A merge patch setting ``key`` to ``value``, and touching nothing else.

        This is the shape §7 of ``01-configuration.md`` requires: siblings in the
        container -- other accounts -- and sibling properties of the document
        alike are absent from the patch rather than rewritten with what was last
        read. Absent is the only version of "not touched" that survives a
        concurrent writer.

        Pass :data:`REMOVE` to delete, which is how ``pending`` is cleared once
        it has been promoted.
        """
        patch: Any = value
        for segment in reversed(self.location(key)):
            patch = {segment: patch}
        return dict(patch)


def stage_layout(ref: SecretRef, *, at: KeyPath = ROOT) -> StageLayout:
    """The layout ``ref`` describes, or why it describes none.

    Refused rather than guessed, in both cases, because §7 parses a ref when the
    file is read for exactly this reason: the failure at the far end of a
    malformed one is a password written where the application does not read it.
    """
    if ref.field is None:
        raise ConfigError(
            f"the secret ref {ref} names a whole secret, which has nowhere to stage into",
            at=at,
            hint=(
                "rotation needs a named field to put `pending` and `previous` beside -- "
                "add one, e.g. `#password`"
            ),
        )
    if ref.field in RESERVED:
        raise ConfigError(
            f"the secret ref {ref} uses the reserved field name `{ref.field}`",
            at=at,
            hint=(
                f"the rotation mechanism owns that key at the document root: {', '.join(RESERVED)}"
            ),
        )
    return StageLayout(container=ref.field, within=ref.pointer_segments)


def merge(*patches: Mapping[str, Any]) -> dict[str, Any]:
    """Combine merge patches into one, later arguments winning.

    A promotion is four changes to one document -- ``current`` takes what
    ``pending`` held, ``previous`` takes what ``current`` held, ``pending`` is
    removed, the stamps are refreshed -- and it must reach the store as **one**
    write. Four writes would be four versions, three of which describe a state
    that was never true, and any of which can be the one that fails.

    Merging is recursive over dictionaries so that patches sharing a root key do
    not overwrite each other: two accounts staged in one run both live under
    ``pending``, and a shallow update would file the second and lose the first.
    Anything that is not a dictionary replaces rather than merges, :data:`REMOVE`
    included -- deleting a key is a decision about the whole subtree.
    """
    merged: dict[str, Any] = {}
    for patch in patches:
        _merge_into(merged, patch)
    return merged


def _merge_into(target: dict[str, Any], patch: Mapping[str, Any]) -> None:
    for key, value in patch.items():
        existing = target.get(key)
        if isinstance(existing, dict) and isinstance(value, Mapping):
            _merge_into(existing, value)
        elif isinstance(value, Mapping):
            nested: dict[str, Any] = {}
            _merge_into(nested, value)
            target[key] = nested
        else:
            target[key] = value

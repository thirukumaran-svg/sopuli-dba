"""Which secrets more than one binding lands on (#110).

§7 is explicit that sharing is legal and often intended -- one account across
eleven PDBs, one document per application -- and equally explicit that it must
never be *invisible*. This is where it stops being something an operator has to
work out from a template by eye.

Two different questions get one answer here, because they are two properties of
one document:

* **``targets``** -- who receives this password. One secret backing three PDBs
  means rotating it changes what three databases' applications read, whether or
  not all three were selected. This is UC-1 §4's original case.
* **``accounts``** -- whose credentials share the document. Added by Q7 (#85),
  which made one secret per application the documented default: a write to
  ``acme_orders_user`` lands in the document ``acme_batch_user`` reads.

A consumer that knew only the first would report a blast radius of one account
for a write that touched six.

**Keyed on the document, not on the ref.** Every account in one document differs
only by the pointer below the field, and the document is what gets written, what
compare-and-set operates on, and what the advisory lock covers. So an entry here
is one entry per :class:`~sopuli.lock.keys.LockKey` -- and the path is normalised
through the same function, so that "shares a document" and "shares a lock" cannot
give two different answers. Keying on the full ref instead would emit six nearly
identical entries for one six-account document, each repeating the same five
neighbours.

That is also why the emitted ``secret`` carries a path and no field: it addresses
the document. It is the run schema's ``secret_document`` rather than its
``secret_ref``, which is a distinction with two halves. There is nothing here that
addresses part of a document, so there is no ``field`` or ``pointer`` to carry --
and the store is **nullable**, because this is read from the config, where one may
never have been named. ``secret_ref`` describes a ref after resolution, where C14
makes the store required because the run is about to talk to it; that is a
different moment, and ``config.bindings[].vault`` is nullable for the same reason
this is.

**Read from the config, never from the store.** The accounts in an entry are the
ones the file *declares* for that document, which is invariant 5's set -- the
config is the whitelist, so it is also the list of what a write may touch. Two
consequences, both deliberate:

* It is offline and deterministic. A plan is reviewable ahead of time only if it
  is a function of the config and the selection; ``03-json-output.md`` requires a
  real run to emit the plan it would have emitted under ``--dry-run``, and a list
  read from a live document would make two runs of one command disagree because
  somebody else edited the vault in between.
* It will not show an account that is in the document but not in the file. That
  is a real thing to know and it belongs to ``creds check``, whose job is what is
  actually out there; :meth:`sopuli.payload.StageLayout.accounts` is what reads
  it. It is drift, not plan.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sopuli.config.model import Binding
from sopuli.lock.keys import normalise_path

__all__ = ["SharedSecret", "shared_secrets"]


@dataclass(frozen=True)
class SharedSecret:
    """One secret document, and everything the config routes into it."""

    #: The store, or ``None`` where nothing named one.
    vault: str | None
    #: The document's path, normalised the way the lock key normalises it.
    path: str
    #: Every target bound to this document, in estate order.
    targets: tuple[str, ...]
    #: Every account whose credential the config puts in it, in declared order.
    accounts: tuple[str, ...]

    @property
    def is_shared(self) -> bool:
        """Whether this is worth reporting at all.

        One account in one target is the ordinary case and not a finding. Either
        axis alone is enough to make it one: six accounts in one document is
        worth saying even when each is bound to a single PDB, and one account in
        eleven PDBs is worth saying even though nothing shares its document.
        """
        return len(self.targets) > 1 or len(self.accounts) > 1

    def as_json(self) -> dict[str, Any]:
        """The run schema's ``shared_secrets[]`` item.

        ``accounts`` is omitted for a single account rather than emitted as a
        list of one, which is what the schema's ``minItems: 2`` says: the field
        reads as "the sharing you might not have intended", and a list of one is
        not sharing.
        """
        item: dict[str, Any] = {
            "secret": {"vault": self.vault, "path": self.path},
            "targets": list(self.targets),
        }
        if len(self.accounts) > 1:
            item["accounts"] = list(self.accounts)
        return item


def shared_secrets(bindings: Iterable[Binding]) -> tuple[SharedSecret, ...]:
    """Group ``bindings`` by the document they write, keeping the shared ones.

    Order is the order the bindings arrived in -- document order, since
    :func:`~sopuli.config.bindings.build_bindings` is ordered by application, then
    estate, then declared account. Deliberately not sorted: the operator reads
    this beside the estate table and the binding rows, and a third ordering would
    make the same set of names look like a different set.

    A binding with no ref contributes nothing. §3 makes ``secret`` optional and
    this layer does not invent one.
    """
    found: dict[tuple[str | None, str], _Group] = {}
    for binding in bindings:
        if binding.secret is None:
            continue
        key = (binding.vault, normalise_path(binding.secret.path))
        group = found.get(key)
        if group is None:
            group = found[key] = _Group()
        group.add(binding)

    return tuple(
        shared
        for (vault, path), group in found.items()
        if (shared := SharedSecret(vault, path, group.targets, group.accounts)).is_shared
    )


@dataclass
class _Group:
    """Distinct targets and accounts for one document, in first-seen order.

    ``dict`` rather than ``set`` because the order is the point (above), and
    because a binding repeats a target once per account and an account once per
    target -- so both need de-duplicating, not just collecting.
    """

    _targets: dict[str, None] = field(default_factory=dict)
    _accounts: dict[str, None] = field(default_factory=dict)

    def add(self, binding: Binding) -> None:
        self._targets[binding.target] = None
        self._accounts[binding.account] = None

    @property
    def targets(self) -> tuple[str, ...]:
        return tuple(self._targets)

    @property
    def accounts(self) -> tuple[str, ...]:
        return tuple(self._accounts)

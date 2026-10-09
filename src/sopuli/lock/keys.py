"""What a lock is keyed on, and the order several are taken in.

P5 said "account+target" until Q2 was answered, and neither half was right.
Per-target is meaningless: every target in a run receives the same value, so
``--select env=dev`` and ``--select env=prod`` would hold different locks while
racing on one secret. Per-account is too narrow: two accounts can share one
document, and an account-keyed lock does not see the collision.

The mutated resource is the **vault document**, and compare-and-set operates on
exactly that. So a lock is keyed on the store and the path, and the account
travels in the record as a label for whoever reads it.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from sopuli.config.secret_refs import SecretRef, normalise_path

#: ``normalise_path`` is re-exported deliberately, and is why this list exists.
#: It moved to :mod:`sopuli.config.secret_refs` with the rule it enforces,
#: and the lock layer is the place that *applies* it -- :func:`lock_key` and
#: :func:`parse_lock_key` both do -- so a caller building keys still reaches for
#: it here. Naming it keeps that a decision rather than an implicit re-export
#: mypy would refuse under ``--strict``.
__all__ = [
    "LockKey",
    "acquisition_order",
    "lock_key",
    "normalise_path",
    "parse_lock_key",
]


@dataclass(frozen=True, order=True)
class LockKey:
    """One store, one secret path -- the unit a lock is taken on.

    Ordered, because :func:`acquisition_order` sorts these and the ordering is a
    safety property rather than tidiness. Frozen and hashable for the same
    reason: two refs that address the same document have to *be* one key, not
    two that compare equal somewhere later.
    """

    store: str
    path: str

    def __str__(self) -> str:
        """``store:path`` -- what exit 7 and the lock events print."""
        return f"{self.store}:{self.path}"


#: What :meth:`LockKey.__str__` puts between the two halves, and therefore what
#: :func:`parse_lock_key` splits on.
SEPARATOR = ":"


def parse_lock_key(text: str) -> LockKey:
    """Read back what :meth:`LockKey.__str__` writes.

    ``sopuli lock break`` takes its argument in exactly the spelling exit 7, the
    ``lock.*`` events and ``lock status``'s first column already print, so the
    invocation in a refusal is a paste rather than a translation. That only holds
    if the two are one grammar, which is why this lives beside ``__str__`` rather
    than in the command that calls it.

    Split on the **first** separator rather than the last. A store name is a
    ``vaults:`` key and cannot contain one; a secret path is somebody else's
    namespace and might. Splitting from the right would address a different
    document on exactly the input where the two rules disagree, and do it
    silently.

    The path goes through :func:`normalise_path` for the reason :func:`lock_key`
    gives: a typed path and a configured one have to land on one key. Breaking a
    lock is a write, and a key that differed by a doubled separator would write
    *beside* the record instead of over it -- leaving the holder unfenced and the
    operator believing otherwise.

    Raises :class:`ValueError` rather than a ``ConfigError``: nothing is wrong
    with any file, and the caller is a command line boundary that turns this into
    click's own usage error -- exit 2, no run document (J7).
    """
    store, separator, path = text.partition(SEPARATOR)
    normalised = normalise_path(path)
    if not separator:
        raise ValueError(
            f"{text!r} is not a lock: write it as `<vault>{SEPARATOR}<path>`, "
            f"the way `sopuli lock status` and exit 7 print it"
        )
    if not store or not normalised:
        raise ValueError(
            f"{text!r} is not a lock: `<vault>{SEPARATOR}<path>` needs a vault name "
            f"and a secret path, and this has only one of them"
        )
    return LockKey(store=store, path=normalised)


def lock_key(ref: SecretRef, *, store: str) -> LockKey:
    """The lock a secret ref is mutated under.

    Five of a :class:`~sopuli.config.secret_refs.SecretRef`'s six parts are
    dropped, and dropping them is the point rather than a simplification:

    * ``field`` and the JSON pointer address a part *of* the document, and a
      write to one field is a write to the whole document. Two accounts in one
      shared document (§7) must contend, which is exactly what per-account
      locking missed.
    * ``@version=`` and ``@stage=`` select a version to read. A mutation writes
      the next one, so they say nothing about what is being locked.
    * ``vault`` is not read here even when the ref carries one. Which store a ref
      resolves to is a precedence question (P3), answered before this is called;
      taking a prefix that may be absent would make the key depend on how the ref
      happened to be written.

    The path is normalised -- surrounding and repeated separators removed --
    because the key is a string and the store's document is not. ``apps/acme/db``
    and ``apps//acme/db`` address one document, and two keys for it would be two
    locks that never contend. Normalising can only ever *merge* keys, which
    over-locks at worst; the failure in the other direction is two runs rotating
    one credential at once.

    Case is deliberately left alone: vault paths are case-sensitive, and folding
    them here would make two different documents share a lock.
    """
    return LockKey(store=store, path=normalise_path(ref.path))


def acquisition_order(keys: Iterable[LockKey]) -> tuple[LockKey, ...]:
    """Every distinct lock a run needs, in the order it must take them.

    Sorted and deduplicated, and both halves are load-bearing.

    **Sorted** makes deadlock structurally impossible rather than unlikely. Two
    runs whose selections overlap take the shared locks in the same order, so one
    of them fails to get the first contested lock and gives up -- instead of each
    holding half of what the other needs. Nothing here ever waits (UC-1 §8),
    which is the other half of that argument.

    **Deduplicated** because a run that touches one secret from several bindings
    -- the one-secret-many-targets case UC-1 §5 exists to handle -- would
    otherwise try to acquire the same lock twice. The second attempt would find
    the run's own held record and refuse it, which is a run deadlocking against
    itself and reporting that somebody else holds the lock.
    """
    return tuple(sorted(set(keys)))

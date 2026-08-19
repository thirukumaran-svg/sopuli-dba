"""Reading lock records the tool did not write (#105).

Everything else in this package is about a lock a run *holds*:
:mod:`sopuli.lock.manager` acquires, renews, fences and releases, and the whole
of it is written from the holder's point of view. ``sopuli lock status`` asks the
other question -- *what is at these paths, and who put it there* -- and that is a
different enough posture to be worth its own module rather than a read-only mode
on the manager.

Three things follow from asking it as an outsider.

**It takes no lock**, which #83 settled for ``check``, ``status`` and every
``--dry-run``: an hourly survey that locked would block the rotations it is meant
to report on. Nothing here writes.

**It reads the declared set.** The paths come from the config's own bindings, run
through the same :func:`sopuli.lock.keys.lock_key` the manager locks on, so
"shares a document" and "shares a lock" cannot give two different answers here
either. A record at a path the config no longer declares is invisible to this,
and that is still a real gap rather than a decision. Half of #150 has closed it:
:meth:`sopuli.store.protocol.SecretStore.list` exists and both KV mounts
implement it, so the paths *can* now be found. Reading them here, and marking
them in the report as records this configuration does not declare, is the other
half and is not done.

**Nothing is a refusal.** A path with no record is a state, not an error, and so
is a payload that does not parse as a lock:
:meth:`sopuli.lock.record.LockRecord.from_dict` always produces a record, which
is what makes an unreadable lock *reportable* rather than a lock nobody can
explain.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta

from sopuli.clock import utc_now
from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.model import Config
from sopuli.lock.keys import LockKey, acquisition_order, lock_key
from sopuli.lock.manager import MODE_CAS, MODE_NONE, lock_path
from sopuli.lock.record import CLOCK_SKEW, LockRecord
from sopuli.store.protocol import CAS, SecretStore, Stored


@dataclass(frozen=True)
class LockState:
    """One lock path, as somebody who does not hold it sees it.

    ``record`` is ``None`` for a path with nothing at it, which is the ordinary
    state of a path nobody has locked yet -- and, indistinguishably from here, of
    one whose record was deleted rather than released. The store tells those two
    apart only at the next write (see
    :meth:`sopuli.store.protocol.SecretStore.read`), so a survey does not claim
    to.

    ``version`` is the store's version of the record and is deliberately not
    called a fence. A fence is a claim -- *this version is mine* -- and nothing
    here holds one. It is carried because it is what a takeover has to
    compare-and-set against (#149), and because a version that jumps between two
    surveys is a lock somebody else has been renewing.

    It is ``None`` on a store with no compare-and-set, where the number exists
    and guarantees nothing -- the same reason
    :attr:`sopuli.lock.manager.HeldLock.fence` is null under ``mode: none``.
    Reporting KV v1's constant zero as a version would offer a takeover something
    to compare against that compares equal to everything.
    """

    key: LockKey
    record: LockRecord | None
    version: int | None
    expired: bool

    @property
    def is_held(self) -> bool:
        """Whether something stands in the way of taking this lock.

        A path with no record is free. Everything else follows
        :attr:`sopuli.lock.record.LockRecord.is_held`, which treats a state this
        build does not recognise as held -- the safe direction, and the same
        answer the manager would give when acquiring.
        """
        return self.record is not None and self.record.is_held


def declared_locks(config: Config) -> tuple[LockKey, ...]:
    """Every lock the configuration could ever take, in acquisition order.

    Invariant 5's set, seen from the lock's side: one key per (store, secret
    path) the file declares, deduplicated -- so six accounts sharing one document
    are one lock here exactly as they are one lock during a rotation.

    A binding with no secret ref contributes nothing: there is no document to
    lock. A binding whose ref names no *store* is the case
    :func:`sopuli.config.bindings._check_has_somewhere_to_resolve_from` leaves
    open on purpose -- a profile or ``SOPULI_VAULT`` may complete it once a run
    picks one -- and this is the command that needs the answer, so it refuses
    here rather than surveying a store it had to guess (invariant 4).
    """
    keys = []
    for binding in config.bindings:
        if binding.secret is None:
            continue
        if binding.vault is None:
            raise ConfigError(
                f"account {binding.account!r} on target {binding.target!r} names no store, "
                f"so there is no lock path to read",
                at=ROOT.key("vaults"),
                hint=(
                    "name one on the ref, the entry, an override, the target, or "
                    "`defaults.vault` -- a profile's `vault:` and SOPULI_VAULT do not "
                    "reach bindings yet (#136)"
                ),
            )
        keys.append(lock_key(binding.secret, store=binding.vault))
    return acquisition_order(keys)


def survey(
    keys: Iterable[LockKey],
    *,
    stores: Mapping[str, SecretStore],
    now: datetime | None = None,
    skew: timedelta = CLOCK_SKEW,
) -> tuple[LockState, ...]:
    """Read every key, in order, and say what is at it.

    One moment for the whole survey rather than one per read. Two paths read a
    second apart would otherwise be judged against two different clocks, and the
    one thing a reader compares between rows is which of them has expired.
    """
    moment = utc_now() if now is None else now
    return tuple(_state(key, stores[key.store], now=moment, skew=skew) for key in keys)


def _state(key: LockKey, store: SecretStore, *, now: datetime, skew: timedelta) -> LockState:
    stored: Stored | None = store.read(lock_path(key))
    if stored is None:
        return LockState(key=key, record=None, version=None, expired=False)
    record = LockRecord.from_dict(stored.data, now=now)
    return LockState(
        key=key,
        record=record,
        version=stored.version if CAS in store.supports() else None,
        # A released record cannot expire: it is not a claim, so there is nothing
        # to lapse. Reporting one as expired would put a red word beside the row
        # that means everything is fine.
        expired=record.is_held and record.is_expired(now=now, skew=skew),
    )


def mode_of(stores: Mapping[str, SecretStore]) -> str:
    """``cas`` or ``none`` for the stores a survey covered.

    The same rule :attr:`sopuli.lock.manager.LockManager.mode` applies, asked of
    stores rather than of a run: ``none`` if *any* of them cannot fence, because
    reporting the strongest of several guarantees is reporting one that does not
    hold. What it means here is one step removed -- no locks were taken, so this
    is the guarantee those stores can give rather than one in force -- and that
    is the same fact either way: whether a lock in this store would mean
    anything.
    """
    if stores and all(CAS in store.supports() for store in stores.values()):
        return MODE_CAS
    return MODE_NONE

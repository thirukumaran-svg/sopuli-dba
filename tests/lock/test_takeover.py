"""Taking a lock from its holder, as a function of what was read (#149).

Tier 0 in the strongest sense: every refusal, every no-op and the one write are
decided from a :class:`~sopuli.lock.inspect.LockState` and two booleans, so the
whole live/expired/nothing matrix is a comparison rather than a container and a
sleep (``04-testing.md`` §4). The only store here is a dictionary.

What this file is *not* about is whether a lock is declared. ``lock break`` acts
on one key an operator typed, and the leftover at a path the config no longer
names is precisely the record they need to be able to clear -- so the module
never asks, and neither does this.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from sopuli.config.locking import LOCK_ADVISORY_ONLY
from sopuli.exit_codes import ExitCode
from sopuli.lock.errors import LockDeniedError, NoFenceError
from sopuli.lock.inspect import LockState, survey
from sopuli.lock.keys import LockKey, parse_lock_key
from sopuli.lock.manager import LockableStore, lock_path
from sopuli.lock.record import DEFAULT_TTL, HELD, RELEASED, Holder, LockRecord
from sopuli.lock.takeover import (
    ABSENT,
    Nothing,
    Take,
    break_lock,
    check_fenceable,
    plan_break,
)
from sopuli.lock.takeover import RELEASED as RELEASED_REASON
from sopuli.store import CasConflictError, MemoryStore, SecretStore
from sopuli.store.protocol import CAS, OK, PathMetadata, Stored, StoreHealth

KEY = LockKey(store="vault-prod", path="apps/acme/appdb-beta")
HOLDER = Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli")
NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


def record(*, state: str = HELD, acquired: datetime = NOW) -> LockRecord:
    """A record as another run would have left it."""
    made = LockRecord.acquired(
        correlation_id="01JTHEIRS",
        command="creds rotate",
        holder=HOLDER,
        now=acquired,
    )
    return made if state == HELD else made.released()


def state_of(store: SecretStore, *, now: datetime) -> LockState:
    """Read one key the way the command does -- through the survey, so the clock
    is applied in exactly one place and this file never computes expiry itself."""
    return survey([KEY], stores={KEY.store: store}, now=now)[0]


def store_with(data: dict[str, Any] | None) -> MemoryStore:
    store = MemoryStore()
    if data is not None:
        store.write(lock_path(KEY), data, cas=0)
    return store


class Unfenced:
    """A store with no compare-and-set -- KV v1, or the file backend.

    Hand-written rather than a `MemoryStore` with a flag, because the point is a
    store that declares fewer capabilities, and a fake that lies about
    :meth:`supports` is the one thing that would make this test pass wrongly.
    """

    def supports(self) -> frozenset[str]:
        return frozenset()

    def read(
        self, path: str, *, version: int | None = None
    ) -> Stored | None:  # pragma: no cover - never reached
        raise AssertionError("a store that cannot fence must be refused before the read")

    def write(self, path: str, data: Any, *, cas: int | None) -> int:  # pragma: no cover
        raise AssertionError("a store that cannot fence must never be written to by `break`")

    def patch(self, path: str, changes: Any, *, cas: int | None) -> int:  # pragma: no cover
        raise AssertionError("a store that cannot fence must never be written to by `break`")

    def metadata(self, path: str) -> PathMetadata | None:  # pragma: no cover - not asked
        return None

    def list(self, prefix: str) -> tuple[str, ...]:  # pragma: no cover - not asked
        return ()

    def health(self) -> StoreHealth:  # pragma: no cover - not asked
        # `check_fenceable` never asks, and the method is here because a
        # `Protocol` demands it of every implementation -- which is the cost P2
        # weighs when it says a method nothing calls obliges every store to
        # write a body for a caller that does not exist (#216).
        return StoreHealth(status=OK)


# ------------------------------------------------------------ the argument ---


def test_the_argument_is_what_lock_status_prints() -> None:
    """The whole reason the grammar is shared: the invocation in an exit-7
    message has to be a paste, not a translation."""
    assert parse_lock_key(str(KEY)) == KEY


def test_a_path_is_normalised_the_way_a_configured_one_is() -> None:
    """A typed path and a configured one have to land on one key. Breaking a
    lock is a write, and a key that differed by a doubled separator would write
    beside the record rather than over it -- leaving the holder unfenced."""
    assert parse_lock_key("vault-prod:/apps//acme/appdb-beta/") == KEY


def test_a_path_containing_a_separator_keeps_all_of_it() -> None:
    """Split on the first separator, not the last. A store name comes from a
    `vaults:` key and cannot contain one; a secret path is somebody else's
    namespace and might."""
    assert parse_lock_key("vault-prod:apps/acme:beta/db") == LockKey(
        store="vault-prod", path="apps/acme:beta/db"
    )


@pytest.mark.parametrize("text", ["nocolon", ":apps/acme/db", "vault-prod:", "vault-prod:///"])
def test_something_that_is_not_a_lock_is_refused_by_name(text: str) -> None:
    """A `ValueError` and not a `ConfigError`: nothing is wrong with any file,
    and the command line boundary turns this into click's usage error."""
    with pytest.raises(ValueError, match="is not a lock"):
        parse_lock_key(text)


# --------------------------------------------------------- what may be broken ---


def test_a_store_that_cannot_fence_is_refused_before_anything_is_read() -> None:
    """Invariant 4: a command that needs an unavailable capability fails at plan
    time, with a distinct exit code. `Unfenced.read` asserts the "before" half --
    a takeover here would be deleting somebody's claim while they carry on."""
    with pytest.raises(NoFenceError) as caught:
        check_fenceable(KEY, LockableStore(store=Unfenced()))

    assert caught.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
    assert caught.value.category == "capability"
    assert "no compare-and-set" in caught.value.message


def test_advisory_only_is_refused_in_its_own_words() -> None:
    """The operator already conceded there is no fence here (#94), so the remedy
    is not "turn on versioning" -- it is that this is what that setting costs."""
    with pytest.raises(NoFenceError) as caught:
        check_fenceable(KEY, LockableStore(store=Unfenced(), locking=LOCK_ADVISORY_ONLY))

    assert LOCK_ADVISORY_ONLY in caught.value.message


def test_advisory_only_is_refused_even_where_the_store_could_fence() -> None:
    """The refusal is on the **declaration**, not on what the store turns out to
    support -- so a KV v2 mount somebody marked `advisory-only` is refused too.

    It is the case that reads as an exception and is not one.
    `LockManager.__post_init__` refuses `break_expired` on this key alone, and
    its comment names this verb as the thing it exists to constrain; #149 settled
    the pair in the same words. A guard that probed the store instead would
    behave differently on two configurations that read identically, and the
    operator cannot see which they have from the file.
    """
    fenceable = MemoryStore()
    assert CAS in fenceable.supports()

    with pytest.raises(NoFenceError) as caught:
        check_fenceable(KEY, LockableStore(store=fenceable, locking=LOCK_ADVISORY_ONLY))

    assert LOCK_ADVISORY_ONLY in caught.value.message


def test_a_store_that_can_fence_passes() -> None:
    """The ordinary KV v2 case, asserted so the refusals above are known to be
    about the capability rather than about the check being unconditional."""
    assert CAS in MemoryStore().supports()
    check_fenceable(KEY, LockableStore(store=MemoryStore()))


# ------------------------------------------------------------- the decision ---


def test_a_path_with_no_record_is_nothing_to_break() -> None:
    """Not a refusal. The operator asked for the path to be clear, and it is --
    which is what makes exit 0 the honest answer."""
    outcome = plan_break(state_of(store_with(None), now=NOW))

    assert outcome == Nothing(key=KEY, reason=ABSENT)


def test_an_already_released_record_is_nothing_to_break() -> None:
    """Invariant 9, and where it comes from: the second `lock break` finds the
    record the first one wrote, which is not a claim."""
    outcome = plan_break(state_of(store_with(record(state=RELEASED).to_dict()), now=NOW))

    assert outcome == Nothing(key=KEY, reason=RELEASED_REASON)


def test_an_expired_lock_is_taken_without_force() -> None:
    """The case the verb exists for: a run was killed and its claim has lapsed."""
    later = NOW + DEFAULT_TTL + timedelta(hours=1)
    outcome = plan_break(state_of(store_with(record().to_dict()), now=later))

    assert isinstance(outcome, Take)
    assert outcome.key == KEY
    assert outcome.state.expired is True
    assert outcome.version == 1


def test_a_live_lock_is_refused_and_names_its_holder() -> None:
    """Exit 7, in the same words a rotation losing the same lock would use --
    because it is the same question being answered to the same person."""
    with pytest.raises(LockDeniedError) as caught:
        plan_break(state_of(store_with(record().to_dict()), now=NOW + timedelta(minutes=1)))

    assert caught.value.key == KEY
    assert "svc_sopuli@ci-runner-3 pid 8821 running creds rotate" in caught.value.message
    assert caught.value.expired is False
    assert caught.value.reason == "held"
    assert "--force" in (caught.value.hint or "")


def test_force_takes_a_live_lock() -> None:
    """#89 settled `--force` as an audited override of a guardrail that is not a
    safety setting, and a live holder is exactly that kind of guardrail."""
    outcome = plan_break(
        state_of(store_with(record().to_dict()), now=NOW + timedelta(minutes=1)), force=True
    )

    assert isinstance(outcome, Take)
    assert outcome.state.expired is False


def test_a_record_this_build_cannot_read_is_still_breakable() -> None:
    """An unrecognised state is held -- the safe direction everywhere else -- and
    it has to be *breakable*, or one bad write leaves a path nobody can clear
    except with the store's own client."""
    store = store_with({"state": "quarantined", "acquired_at": "2026-08-16T12:00:00Z"})
    later = NOW + DEFAULT_TTL + timedelta(hours=1)

    outcome = plan_break(state_of(store, now=later))

    assert isinstance(outcome, Take)
    assert outcome.record.state == "quarantined"


def test_a_record_with_no_readable_expiry_is_breakable_after_the_skew() -> None:
    """`from_dict` falls back inwards, so such a record expired the moment it was
    taken. The other reading -- "no expiry means never" -- produces a path only a
    vault client can clear, from one bad write."""
    store = store_with({"state": HELD, "acquired_at": "2026-08-16T12:00:00Z"})

    assert isinstance(plan_break(state_of(store, now=NOW + timedelta(minutes=5))), Take)


# ----------------------------------------------------------------- the write ---


def test_breaking_writes_a_released_record_over_the_held_one() -> None:
    """Never a delete. A KV v2 delete leaves the metadata, after which a first
    acquisition can never compare-and-set against version 0 again -- and that
    version *is* the fence."""
    store = store_with(record().to_dict())
    later = NOW + DEFAULT_TTL + timedelta(hours=1)
    outcome = plan_break(state_of(store, now=later))
    assert isinstance(outcome, Take)

    new_version = break_lock(outcome, store)

    stored = store.read(lock_path(KEY))
    assert stored is not None
    assert stored.data["state"] == RELEASED
    assert stored.version == new_version == 2


def test_the_write_bumps_the_version_which_is_what_fences_the_holder() -> None:
    """The whole safety argument in one assertion: the holder's remembered fence
    is now stale, so their next check fails before their next mutation."""
    store = store_with(record().to_dict())
    their_fence = 1
    outcome = plan_break(state_of(store, now=NOW + DEFAULT_TTL + timedelta(hours=1)))
    assert isinstance(outcome, Take)

    assert break_lock(outcome, store) != their_fence


def test_the_holders_own_fields_survive_the_transition() -> None:
    """The released record is the holder's, transitioned -- including keys this
    build does not understand, which a newer sopuli may have written."""
    payload = record().to_dict() | {"reason": "a field from a later version"}
    store = store_with(payload)
    outcome = plan_break(state_of(store, now=NOW + DEFAULT_TTL + timedelta(hours=1)))
    assert isinstance(outcome, Take)

    break_lock(outcome, store)

    stored = store.read(lock_path(KEY))
    assert stored is not None
    assert stored.data["correlation_id"] == "01JTHEIRS"
    assert stored.data["reason"] == "a field from a later version"


def test_losing_the_compare_and_set_is_reported_as_a_race_and_not_retried() -> None:
    """The version moved between the read and the write, which means the holder
    renewed -- they are alive, the most useful thing the operator could learn --
    or somebody else broke it first. Either way the plan describes a path that no
    longer exists."""
    store = store_with(record().to_dict())
    outcome = plan_break(state_of(store, now=NOW + DEFAULT_TTL + timedelta(hours=1)))
    assert isinstance(outcome, Take)
    # Somebody renews between this run's read and its write.
    store.write(lock_path(KEY), record().to_dict(), cas=1)

    with pytest.raises(LockDeniedError) as caught:
        break_lock(outcome, store)

    assert caught.value.reason == "race"
    assert "nothing was written" in (caught.value.hint or "")


def test_a_lost_race_leaves_the_record_alone() -> None:
    """ "Nothing was written" is a claim the hint makes, so it is asserted rather
    than trusted."""
    store = store_with(record().to_dict())
    outcome = plan_break(state_of(store, now=NOW + DEFAULT_TTL + timedelta(hours=1)))
    assert isinstance(outcome, Take)
    store.write(lock_path(KEY), record().to_dict(), cas=1)

    with pytest.raises((LockDeniedError, CasConflictError)):
        break_lock(outcome, store)

    stored = store.read(lock_path(KEY))
    assert stored is not None
    assert stored.data["state"] == HELD
    assert stored.version == 2


def test_a_break_on_an_unfenced_store_would_be_invisible_to_its_holder() -> None:
    """Why the refusal above is absolute rather than a weaker guarantee.

    The released record is the holder's own, so it keeps their `correlation_id`.
    Where there is a fence, their next check fails on the version. Where there is
    not, `fence` is `None`, the version comparison is skipped, and `is_mine` still
    answers *yes* -- so the holder would carry on rotating having never been told.
    Not a quieter warning: no warning at all, which is what makes a break in such
    a store a thing the tool must refuse to do rather than do carefully.
    """
    broken = record().released()

    assert broken.is_mine("01JTHEIRS") is True

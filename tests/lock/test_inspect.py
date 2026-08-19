"""Reading lock records nobody in this process wrote (#105).

Tier 0: the config comes from a dict and the store is
:class:`~sopuli.store.MemoryStore`, so nothing here opens a socket. That is not
just convenience -- the survey has to give the same answers about a record it
cannot explain as about one it can, and a fake is the only place a half-written
record can be *put* deliberately.

Two properties carry the module. The declared set has to be the same set the
manager locks on, or `lock status` reports on paths a rotation would not touch;
and every readable record has to produce a state, because the alternative is a
lock the tool can neither describe nor break.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.lock.inspect import declared_locks, mode_of, survey
from sopuli.lock.keys import LockKey
from sopuli.lock.manager import MODE_CAS, MODE_NONE, lock_path
from sopuli.lock.record import DEFAULT_TTL, Holder, LockRecord
from sopuli.store import CAS, MemoryStore

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
HOLDER = Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli")

TARGETS: list[dict[str, Any]] = [
    {
        "name": "appdb-alpha",
        "type": "oracle",
        "dsn": "db-dev.example.com:1521/alpha.pdb.example.com",
        "environment": "dev",
        "labels": {"env": "dev"},
        "vault": "vault-dev",
    },
    {
        "name": "appdb-beta",
        "type": "oracle",
        "dsn": "db-dev.example.com:1521/beta.pdb.example.com",
        "environment": "prod",
        "labels": {"env": "prod"},
        "vault": "vault-prod",
    },
]

VAULTS: dict[str, Any] = {
    "vault-dev": {"type": "hashicorp"},
    "vault-prod": {"type": "hashicorp"},
}


def config(**sections: Any) -> Any:
    return build_config({"version": 1, "vaults": VAULTS, "targets": TARGETS, **sections})


def application(**entry: Any) -> dict[str, Any]:
    """One application entry, `secret:` unless the caller writes a template."""
    base: dict[str, Any] = {
        "name": "acme",
        "accounts": ["acme_web_user"],
        "targets": {"match": {"env": "dev"}},
        "secret": "apps/acme/db#password",
    }
    if "secret_template" in entry:
        del base["secret"]
    return {**base, **entry}


def record(
    *,
    state: str = "held",
    now: datetime = NOW,
    ttl: timedelta = DEFAULT_TTL,
    **fields: Any,
) -> dict[str, Any]:
    """A lock record as it sits in a store, so a test can bend one field."""
    written = LockRecord.acquired(
        correlation_id="01JTHEIRS",
        command="creds rotate",
        holder=HOLDER,
        now=now,
        ttl=ttl,
    ).to_dict()
    written["state"] = state
    return {**written, **fields}


# ------------------------------------------------------------ the declared set ---


def test_the_declared_set_is_every_bound_secret_path() -> None:
    keys = declared_locks(config(applications=[application()]))

    assert keys == (LockKey(store="vault-dev", path="apps/acme/db"),)


def test_two_accounts_in_one_document_are_one_lock() -> None:
    """The collision per-account locking missed (`keys.py`): one document, one
    compare-and-set, one lock -- so the survey must show one row, not two."""
    keys = declared_locks(
        config(
            applications=[
                application(
                    accounts=["acme_web_user", "acme_api_user"],
                    secret_template="apps/acme/db#DB_CREDENTIALS/{account}",
                )
            ]
        )
    )

    assert keys == (LockKey(store="vault-dev", path="apps/acme/db"),)


def test_the_same_path_in_two_stores_is_two_locks() -> None:
    """A lock is keyed on the store *and* the path. Two vaults holding the same
    path are two documents, and merging them would report one as the other."""
    keys = declared_locks(config(applications=[application(targets=None)]))

    assert keys == (
        LockKey(store="vault-dev", path="apps/acme/db"),
        LockKey(store="vault-prod", path="apps/acme/db"),
    )


def test_the_set_comes_back_in_acquisition_order() -> None:
    """Sorted, because a survey read in one order and a rotation acquiring in
    another would make the two hard to compare at exactly the moment somebody is
    comparing them."""
    keys = declared_locks(
        config(
            applications=[
                application(secret="vault-prod:apps/acme/zulu#password"),
                application(
                    name="acme-two",
                    accounts=["acme_api_user"],
                    secret="vault-prod:apps/acme/alpha#password",
                ),
            ]
        )
    )

    assert [key.path for key in keys] == ["apps/acme/alpha", "apps/acme/zulu"]


def test_a_binding_with_no_secret_contributes_no_lock() -> None:
    """There is no document to lock, so there is nothing to report."""
    assert declared_locks(config()) == ()


def test_a_binding_that_names_no_store_is_refused_by_name() -> None:
    """Invariant 4: the command that needs the answer is where the refusal
    belongs, and it has to name what could not be resolved.

    A real file rather than a doctored `Config`: nothing in the chain names a
    store -- no prefix, no entry, no target, no `defaults.vault` -- while
    `vaults:` still declares one for a profile or `SOPULI_VAULT` to select later,
    which is exactly the state `bindings.py` accepts on purpose. `config show
    --resolved` renders a dash for it; a survey cannot.
    """
    unbound = build_config(
        {
            "version": 1,
            "vaults": VAULTS,
            "targets": [{key: value for key, value in TARGETS[0].items() if key != "vault"}],
            "applications": [application()],
        }
    )

    with pytest.raises(ConfigError) as caught:
        declared_locks(unbound)

    rendered = str(caught.value)
    assert "acme_web_user" in rendered
    assert "appdb-alpha" in rendered
    assert "names no store" in rendered


# ------------------------------------------------------------------ the survey ---


def surveyed(data: dict[str, Any] | None, **kwargs: Any) -> Any:
    key = LockKey(store="vault-dev", path="apps/acme/db")
    store = MemoryStore()
    if data is not None:
        store.write(lock_path(key), data, cas=0)
    states = survey([key], stores={"vault-dev": store}, now=NOW, **kwargs)
    assert len(states) == 1
    return states[0]


def test_a_path_with_nothing_at_it_is_free_and_carries_no_record() -> None:
    state = surveyed(None)

    assert state.record is None
    assert state.version is None
    assert not state.is_held
    assert not state.expired


def test_a_live_record_is_held_and_not_expired() -> None:
    state = surveyed(record())

    assert state.is_held
    assert not state.expired
    assert state.version == 1
    assert state.record is not None
    assert state.record.holder == HOLDER
    assert state.record.command == "creds rotate"


def test_a_lapsed_record_is_held_and_expired() -> None:
    """Still held: expiry says the holder is probably gone, not that the path is
    free. Taking it is a deliberate act (#149), and until somebody performs one
    the record stands."""
    state = surveyed(record(now=NOW - DEFAULT_TTL - timedelta(minutes=2)))

    assert state.is_held
    assert state.expired


def test_the_skew_margin_is_the_boundary_it_says_it_is() -> None:
    """Strictly past `expires_at + skew`, so a lock is not expired *at* the
    margin. One second either way changes nothing operationally and everything
    about whether a test can sit on the rule."""
    at_the_margin = surveyed(
        record(now=NOW - DEFAULT_TTL - timedelta(seconds=60)), skew=timedelta(seconds=60)
    )
    one_past = surveyed(
        record(now=NOW - DEFAULT_TTL - timedelta(seconds=61)), skew=timedelta(seconds=60)
    )

    assert not at_the_margin.expired
    assert one_past.expired


def test_a_released_record_is_not_held_and_never_expires() -> None:
    """A released record is not a claim, so there is nothing to lapse -- and
    reporting one as expired would put a red word beside a row that is fine."""
    state = surveyed(record(state="released", now=NOW - timedelta(days=9)))

    assert not state.is_held
    assert not state.expired


def test_a_state_this_build_does_not_recognise_reads_as_held() -> None:
    """The safe direction, and the same answer the manager gives when acquiring:
    treating an unknown state as free is the one guess that ends with two runs
    rotating one credential."""
    state = surveyed(record(state="quiescing"))

    assert state.is_held
    assert state.record is not None
    assert state.record.state == "quiescing"


def test_an_unreadable_payload_is_still_a_reportable_lock() -> None:
    """`from_dict` never refuses, because the caller's next move on a refusal
    would be to write over a path something wrote. A lock nobody can explain must
    still be a lock somebody can see."""
    state = surveyed({"nonsense": True})

    assert state.is_held
    assert state.record is not None
    assert state.record.holder is None


def test_the_whole_survey_is_judged_against_one_moment() -> None:
    """Two paths read a second apart would be judged by two clocks, and which of
    them has expired is the one thing a reader compares between rows."""
    lapsed = record(now=NOW - DEFAULT_TTL - timedelta(minutes=2))
    store = MemoryStore()
    keys = [
        LockKey(store="vault-dev", path="apps/acme/alpha"),
        LockKey(store="vault-dev", path="apps/acme/beta"),
    ]
    for key in keys:
        store.write(lock_path(key), lapsed, cas=0)

    states = survey(keys, stores={"vault-dev": store}, now=NOW)

    assert [state.expired for state in states] == [True, True]


def test_a_store_with_no_compare_and_set_reports_no_version() -> None:
    """The number exists and guarantees nothing, so offering it as something to
    fence against would offer a takeover a comparison that always matches."""
    key = LockKey(store="vault-dev", path="apps/acme/db")
    store = MemoryStore(capabilities=frozenset())
    store.write(lock_path(key), record(), cas=None)

    states = survey([key], stores={"vault-dev": store}, now=NOW)

    assert states[0].is_held
    assert states[0].version is None


# -------------------------------------------------------------------- the mode ---


def test_the_mode_is_cas_when_every_store_can_fence() -> None:
    assert mode_of({"a": MemoryStore(), "b": MemoryStore()}) == MODE_CAS


def test_one_store_without_compare_and_set_drops_the_whole_mode() -> None:
    """Reporting the strongest of several guarantees is reporting one that does
    not hold -- the rule `LockManager.mode` already applies to a run."""
    stores = {"a": MemoryStore(), "b": MemoryStore(capabilities=frozenset())}

    assert mode_of(stores) == MODE_NONE
    assert CAS in stores["a"].supports()


def test_no_stores_at_all_is_no_guarantee() -> None:
    """A survey that contacted nothing has nothing to promise, and `cas` there
    would be a claim about stores that were never asked."""
    assert mode_of({}) == MODE_NONE

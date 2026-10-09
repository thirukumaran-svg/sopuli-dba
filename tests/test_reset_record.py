"""UC-2's reset record -- what it says, where it goes, and what it may never hold.

Tier 0, and the whole module stays there on purpose. The record reads no clock,
no store and no database: a moment arrives as an argument, which is what lets the
collision case below be a real contention test without a container (`04-testing.md`
§4). Two runs contend by sharing one :class:`~sopuli.store.MemoryStore`, exactly
as `tests/lock/test_manager.py` does.

Fixtures use the fictional vocabulary the provenance note requires -- tenants
``alpha``…``theta``, hosts under ``example.com``, and ``jdoe`` for a person, who
is a placeholder and not anybody.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from sopuli.config.locking import LOCK_REQUIRED
from sopuli.config.model import ResetRecords
from sopuli.lock import Holder, LockableStore, LockDeniedError, LockManager, lock_path
from sopuli.reset_record import (
    Delivery,
    ResetRecord,
    assert_no_secret,
    record_lock_key,
    record_path,
)
from sopuli.secrets import Secret
from sopuli.store import MemoryStore

RECORDS = ResetRecords(vault="kv", prefix="sopuli/personal-resets")
NOW = datetime(2026, 9, 17, 9, 14, 22, tzinfo=UTC)
HOLDER = Holder(host="dba-ws-4.example.com", pid=8821, os_user="dba01")


def record(**overrides: Any) -> ResetRecord:
    fields: dict[str, Any] = {
        "account": "jdoe",
        "target": "appdb-dev-alpha",
        "reset_at": NOW,
        "seen": False,
        "expired": False,
        "delivery": Delivery(method="vault_wrapped", to="cubbyhole/response"),
        "by": HOLDER,
        "correlation_id": "01JRESET",
    }
    return ResetRecord(**{**fields, **overrides})


# ------------------------------------------------------------ what it says ---


def test_the_document_is_the_one_the_use_case_specifies() -> None:
    """UC-2 §3.1's example, built rather than transcribed."""
    assert record().to_dict() == {
        "account": "jdoe",
        "target": "appdb-dev-alpha",
        "reset_at": "2026-09-17T09:14:22Z",
        "seen": False,
        "expired": False,
        "delivery": {"method": "vault_wrapped", "to": "cubbyhole/response"},
        "by": {"host": "dba-ws-4.example.com", "pid": 8821, "os_user": "dba01"},
        "correlation_id": "01JRESET",
    }


def test_the_seen_path_records_a_method_and_no_destination() -> None:
    """``to`` is omitted rather than written null. The seen path's destination is
    a person, by a route the tool did not carry, and inventing a value for stdout
    would make a reader think the tool knew where it went. What they are actually
    asking is answered by ``seen``."""
    written = record(seen=True, expired=True, delivery=Delivery(method="manual")).to_dict()

    assert written["delivery"] == {"method": "manual"}
    assert "to" not in written["delivery"]
    assert written["seen"] is True


def test_a_runner_that_could_not_be_described_has_no_by_key() -> None:
    written = record(by=None, correlation_id=None).to_dict()

    assert "by" not in written
    assert "correlation_id" not in written


def test_by_is_the_lock_records_holder_shape_rather_than_a_second_spelling() -> None:
    """Both answer "which runner did this", and a reader who has learned one
    should not have to learn the other."""
    assert record().to_dict()["by"] == HOLDER.to_dict()


def test_there_is_no_field_a_password_could_go_in() -> None:
    """The structural half of invariant 2, asserted on the type. The other half
    is :func:`assert_no_secret`, on the document."""
    fields = set(ResetRecord.__dataclass_fields__)

    assert fields == {
        "account",
        "target",
        "reset_at",
        "seen",
        "expired",
        "delivery",
        "by",
        "correlation_id",
    }


# ------------------------------------------------------------ where it goes ---


def test_the_path_is_one_record_per_target_and_account() -> None:
    assert record_path(RECORDS, target="appdb-dev-alpha", account="jdoe") == (
        "sopuli/personal-resets/appdb-dev-alpha/jdoe"
    )


def test_one_person_on_two_targets_is_two_records() -> None:
    """Two accounts with two passwords, which two DBAs may reset independently."""
    assert record_path(RECORDS, target="appdb-dev-alpha", account="jdoe") != record_path(
        RECORDS, target="appdb-qa-alpha", account="jdoe"
    )


@pytest.mark.parametrize("name", ["a/b", "..", ".", "", " jdoe"])
def test_a_name_that_is_not_one_path_segment_is_refused(name: str) -> None:
    """Nothing validates a `targets:` key or an `accounts:` entry against a path
    grammar -- both are "a non-empty string" -- so interpolating one is how two
    different pairs end up sharing a record. Target ``a/b`` with account ``jdoe``
    and target ``a`` with account ``b/jdoe`` would derive one path: one journal
    describing two accounts, and one lock where there should be two."""
    with pytest.raises(ValueError, match="record path component"):
        record_path(RECORDS, target=name, account="jdoe")
    with pytest.raises(ValueError, match="record path component"):
        record_path(RECORDS, target="appdb-dev-alpha", account=name)


def test_the_pair_that_would_have_collided_cannot_be_built() -> None:
    """The collision stated as the two calls that used to produce one path."""
    with pytest.raises(ValueError, match="same record path"):
        record_path(RECORDS, target="a/b", account="jdoe")
    with pytest.raises(ValueError, match="same record path"):
        record_path(RECORDS, target="a", account="b/jdoe")


def test_an_account_name_is_folded_and_a_target_name_is_not() -> None:
    """An Oracle account is matched case-insensitively everywhere else here, so a
    path that did not fold would let one account own two records that never find
    each other -- two concurrent resets not colliding. A target name is a
    `targets:` key, matched exactly, and folding it would merge two targets an
    operator declared as distinct."""
    assert record_path(RECORDS, target="appdb-dev-alpha", account="JDOE") == record_path(
        RECORDS, target="appdb-dev-alpha", account="jdoe"
    )
    assert record_path(RECORDS, target="APPDB-DEV-ALPHA", account="jdoe") != record_path(
        RECORDS, target="appdb-dev-alpha", account="jdoe"
    )


# ------------------------------------------------------------------ the lock ---


def manager(store: MemoryStore, *, correlation_id: str) -> LockManager:
    return LockManager(
        stores={RECORDS.vault: LockableStore(store=store, locking=LOCK_REQUIRED)},
        correlation_id=correlation_id,
        command="account reset-password",
        holder=HOLDER,
        break_expired=False,
        now=lambda: NOW,
    )


def key(*, target: str = "appdb-dev-alpha", account: str = "jdoe") -> Any:
    return record_lock_key(RECORDS, target=target, account=account)


def test_the_lock_is_keyed_on_the_records_own_path() -> None:
    """UC-2 §3.3's whole claim: the key is the only new thing, and the ``locks/``
    prefix that keeps lock writes off the record is Q2's."""
    assert key().store == "kv"
    assert key().path == "sopuli/personal-resets/appdb-dev-alpha/jdoe"
    assert lock_path(key()) == "locks/sopuli/personal-resets/appdb-dev-alpha/jdoe"


def test_two_resets_of_one_target_and_account_collide() -> None:
    """The collision H2 raised and had nothing to key on: two DBAs resetting the
    same person at once, the second password overwriting the first before the
    person has fetched either."""
    store = MemoryStore()
    manager(store, correlation_id="01JMINE").acquire([key()])

    with pytest.raises(LockDeniedError) as denied:
        manager(store, correlation_id="01JTHEIRS").acquire([key()])

    assert "dba01" in str(denied.value)


def test_the_same_account_on_two_targets_does_not_collide() -> None:
    """The other half, and the reason the key is not per-account: resetting one
    person on dev and on qa at the same time is two accounts with two passwords,
    and a lock that stopped it would be stopping ordinary work."""
    store = MemoryStore()
    manager(store, correlation_id="01JMINE").acquire([key(target="appdb-dev-alpha")])

    manager(store, correlation_id="01JTHEIRS").acquire([key(target="appdb-qa-alpha")])


def test_two_accounts_on_one_target_do_not_collide() -> None:
    """And the reason it is not per-target either. Every target in a UC-1 run
    receives one value, which is why that lock keys on the document; here the
    mutated resource is the account, and two people are two accounts."""
    store = MemoryStore()
    manager(store, correlation_id="01JMINE").acquire([key(account="jdoe")])

    manager(store, correlation_id="01JTHEIRS").acquire([key(account="asmith")])


# ------------------------------------------------- what it may never hold ---

#: Wrapped, because that is what :func:`assert_no_secret` takes: the comparison
#: goes through `Secret.__eq__`, so proving a document holds no password needs no
#: reveal. The documents below carry the *plaintext*, which is the thing
#: being looked for.
PLAINTEXT = "Xq7!tvBm2LsdPw9r"
PASSWORD = Secret(PLAINTEXT)


def test_the_password_in_a_key_the_record_does_declare_is_refused() -> None:
    """The value half, reached through a **permitted** key -- which is the case
    the closed shape cannot catch, and the reason both halves exist."""
    with pytest.raises(AssertionError) as raised:
        assert_no_secret({"account": PLAINTEXT}, secret=PASSWORD)
    assert "invariant 2" in str(raised.value)


def test_it_is_refused_at_any_depth_and_in_a_key() -> None:
    """A record has no field a password is a *part* of, so an occurrence anywhere
    is the failure -- including a document built by inverting a mapping."""
    with pytest.raises(AssertionError):
        assert_no_secret({"delivery": {"to": PLAINTEXT}}, secret=PASSWORD)
    with pytest.raises(AssertionError):
        assert_no_secret({"by": {"host": PLAINTEXT}}, secret=PASSWORD)
    with pytest.raises(AssertionError):
        assert_no_secret({PLAINTEXT: "jdoe"}, secret=PASSWORD)


def test_the_record_this_build_writes_passes_it() -> None:
    """The assertion wired to the type it guards: no writer here puts a password
    in, and this is what says so on every run rather than only in this test."""
    assert_no_secret(record().to_dict(), secret=PASSWORD)


def test_a_key_nothing_specified_is_refused_even_with_no_password_in_it() -> None:
    """The half a value comparison cannot do. A hash or a verifier is caught by
    having nowhere to live, which only works if "nowhere" is checked -- so the
    shape is closed, and a `verifier` key is refused on sight rather than on its
    contents."""
    document = record().to_dict()
    document["verifier"] = "T:9c1f2e..."

    with pytest.raises(AssertionError, match="verifier"):
        assert_no_secret(document, secret=PASSWORD)


def test_a_key_delivery_does_not_declare_is_refused() -> None:
    document = record().to_dict()
    document["delivery"]["password_hash"] = "sha512:..."

    with pytest.raises(AssertionError, match="password_hash"):
        assert_no_secret(document, secret=PASSWORD)


def test_a_document_that_is_not_an_object_is_refused() -> None:
    with pytest.raises(AssertionError, match="not an object"):
        assert_no_secret([record().to_dict()], secret=PASSWORD)


# -------------------------------------------------- and the token, which fetches it ---

#: What `vault_wrapped` hands the DBA. Not a password -- and UC-2 §6.1 covers it
#: anyway, because the rule is about reach rather than value.
TOKEN_TEXT = "hvs.EXAMPLE-not-a-real-token-AAAAAAAAAAAAAAAAAAAAAAAA"
TOKEN = Secret(TOKEN_TEXT)


def test_the_hand_over_token_in_delivery_to_is_refused() -> None:
    """The closed shape proves nothing about a delivery method that stuffs a
    value into `delivery.to`. `vault_wrapped` has two candidates for that field:
    the accessor, which names the hand-over, and the token, which performs it.
    A record is long-lived and readable by anyone who may know *that* a reset
    happened, so a token in one outlives the TTL that is the method's whole
    guarantee.
    """
    with pytest.raises(AssertionError) as raised:
        assert_no_secret({"delivery": {"to": TOKEN_TEXT}}, secret=PASSWORD, token=TOKEN)

    assert "hand-over token" in str(raised.value)
    assert "accessor" in str(raised.value)


def test_the_token_is_refused_at_any_depth_like_the_password() -> None:
    """Same walk, so a token reaching a permitted field by another route is caught
    by the same pass rather than by a second one that could disagree."""
    for document in ({"account": TOKEN_TEXT}, {"by": {"host": TOKEN_TEXT}}, {TOKEN_TEXT: "x"}):
        with pytest.raises(AssertionError):
            assert_no_secret(document, secret=PASSWORD, token=TOKEN)


def test_the_accessor_in_delivery_to_is_what_the_field_is_for() -> None:
    """The positive case, which is the point of distinguishing the two: an
    accessor names the hand-over in the store's own audit log and cannot perform
    it, so the record is allowed to carry it and stay readable by people who may
    know a reset happened without being able to use one."""
    assert_no_secret(
        {"delivery": {"method": "vault_wrapped", "to": "EXAMPLEaccessor000000000"}},
        secret=PASSWORD,
        token=TOKEN,
    )


def test_no_token_given_means_nothing_to_compare_against() -> None:
    """`None` rather than a sentinel, for the seen path and for any method that
    produces no token: such a method has nothing for this to look for, and an
    absent argument says that better than a value standing in for absence."""
    assert_no_secret({"delivery": {"to": TOKEN_TEXT}}, secret=PASSWORD)

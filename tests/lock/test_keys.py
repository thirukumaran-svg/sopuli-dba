"""What a lock is keyed on, and the order a run takes several in.

Two of these tests are about a failure that has no symptom until it matters. A
key that is too narrow -- per account, per target, or per spelling of a path --
does not error; it produces two locks where there should be one, and two runs
that never contend rotate the same credential at the same time. So the
assertions are mostly about refs that *differ* and must still collide.
"""

from __future__ import annotations

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.lock import LockKey, acquisition_order, lock_key, normalise_path
from sopuli.lock.keys import parse_lock_key

STORE = "vault-prod"


def key(text: str, *, store: str = STORE) -> LockKey:
    return lock_key(parse_secret_ref(text), store=store)


def test_a_key_is_the_store_and_the_path() -> None:
    assert key("apps/acme/db") == LockKey(store=STORE, path="apps/acme/db")


@pytest.mark.parametrize(
    "ref",
    [
        "apps/acme/db#WEB_USER",
        "apps/acme/db#DB_CREDENTIALS/acme_web_user",
        "apps/acme/db@version=7",
        "apps/acme/db@stage=pending",
    ],
    ids=["field", "pointer", "version", "stage"],
)
def test_everything_that_addresses_part_of_a_document_locks_the_whole_document(ref: str) -> None:
    """Q7's shared-document layout is the case this exists for.

    Two accounts in one document are two refs differing only in `#field`. A write
    to either rewrites the document, so they have to contend -- which is exactly
    what a per-account lock would have missed.
    """
    assert key(ref) == key("apps/acme/db")


def test_the_stores_are_part_of_the_key() -> None:
    """One path in two stores is two documents, and must be two locks."""
    assert key("apps/acme/db", store="vault-dev") != key("apps/acme/db")


def test_a_ref_that_names_its_own_store_does_not_get_to_choose() -> None:
    """Which store a ref resolves to is a precedence question, answered earlier.

    Reading the prefix here would make the key depend on whether somebody wrote
    the ref with one -- so `vault-dev:apps/acme/db` under a run resolved to
    `vault-prod` would take a lock nothing else contends for.
    """
    assert key("vault-dev:apps/acme/db") == key("apps/acme/db")


@pytest.mark.parametrize(
    "path",
    ["/apps/acme/db", "apps/acme/db/", "apps//acme/db", "//apps/acme//db//"],
)
def test_paths_that_address_one_document_are_one_key(path: str) -> None:
    assert key(path) == key("apps/acme/db")


def test_case_is_left_alone() -> None:
    """Vault paths are case-sensitive, so folding case would merge two documents.

    The opposite direction from the slash rule above, and deliberately: merging
    keys over-locks, which costs concurrency, while splitting them under-locks,
    which costs a credential. Only one of those is worth guessing at.
    """
    assert key("apps/ACME/db") != key("apps/acme/db")


def test_normalising_a_path_leaves_nothing_to_strip() -> None:
    assert normalise_path("//a//b//") == "a/b"
    assert normalise_path("a/b") == "a/b"
    assert normalise_path("") == ""


# ------------------------------------------------------- acquisition order ---


def test_locks_are_taken_in_one_deterministic_order() -> None:
    """Sorted is what makes deadlock impossible rather than unlikely.

    Two runs with overlapping selections take the shared locks in the same order,
    so one of them loses the first contested lock and gives up whole -- instead
    of each holding half of what the other needs.
    """
    keys = [key("apps/z"), key("apps/a"), key("apps/m")]

    assert acquisition_order(keys) == acquisition_order(reversed(keys))
    assert [one.path for one in acquisition_order(keys)] == ["apps/a", "apps/m", "apps/z"]


def test_one_secret_reached_from_several_bindings_is_one_lock() -> None:
    """UC-1 §5's one-secret-many-targets case, seen from the lock.

    Without the dedupe the run would try to take the same lock twice, find its
    own held record the second time, and refuse -- a run deadlocking against
    itself and reporting that somebody else holds the lock.
    """
    keys = [key("apps/acme/db"), key("apps/acme/db#WEB"), key("apps/acme/db#BATCH")]

    assert acquisition_order(keys) == (LockKey(store=STORE, path="apps/acme/db"),)


def test_the_order_is_stable_across_stores_too() -> None:
    """A run may span stores, so the sort has to be total rather than per store."""
    ordered = acquisition_order([key("apps/a", store="v-b"), key("apps/z", store="v-a")])

    assert [str(one) for one in ordered] == ["v-a:apps/z", "v-b:apps/a"]


def test_a_key_prints_as_store_and_path() -> None:
    """What exit 7 and the lock events show, so it is worth pinning."""
    assert str(key("apps/acme/db")) == "vault-prod:apps/acme/db"


# ------------------------------------------------ paths that address nothing ---
#
# `normalise_path` refuses `.` and `..` segments (decision #344). `lock_path()`
# prefixes `locks/`, and a `..` would walk straight back out of it. Without the
# refusal, `lock break 'kv:../secrets/acme/db'` would read the *credential*
# document as a lock record and CAS-write a `released` record onto it, with
# nothing written under `locks/` at all (measured against a real Vault).


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("../secrets/acme/db", id="leading"),
        pytest.param("apps/../secrets/acme/db", id="interior"),
        pytest.param("apps/acme/..", id="trailing"),
        pytest.param("apps/./acme/db", id="single-dot"),
        pytest.param("..", id="bare"),
        pytest.param("apps//../acme/db", id="after-an-empty-segment"),
    ],
)
def test_a_relative_segment_is_refused_rather_than_dropped(path: str) -> None:
    """Refused, and specifically not stripped.

    Stripping would silently rewrite what the operator typed, so `lock status`
    and `lock break` would report and act on different records -- which is the
    failure the normalisation exists to prevent, arrived at from the other side.
    """
    with pytest.raises(ValueError, match="cannot address a document"):
        normalise_path(path)


def test_the_empty_segment_rule_is_untouched() -> None:
    """The half that needs no refusal: normalising *merges* two spellings of one
    document, which over-locks at worst. A `..` does not merge, it redirects
    (decision #344)."""
    assert normalise_path("apps//acme/db") == "apps/acme/db"
    assert normalise_path("/apps/acme/db/") == "apps/acme/db"
    assert normalise_path("apps/acme/db") == "apps/acme/db"


def test_a_dot_inside_a_segment_is_still_an_ordinary_path() -> None:
    """Only a whole segment counts. Vault paths carry dots -- `acme.db`,
    `v1.2` -- and refusing those would refuse ordinary estates."""
    assert normalise_path("apps/acme.db/v1.2") == "apps/acme.db/v1.2"
    assert normalise_path("apps/..db/x") == "apps/..db/x"


def test_a_typed_lock_key_carrying_one_is_refused() -> None:
    """`lock break`'s argument. `cli.py` turns this `ValueError` into a
    `click.UsageError` -- exit 2, no run document, nothing wrong with any file."""
    with pytest.raises(ValueError, match="cannot address a document"):
        parse_lock_key("vault-prod:../apps/acme/db")


def test_a_ref_carrying_one_is_refused_by_the_config_layer_with_a_location() -> None:
    """The refusal an operator actually meets.

    `normalise_path` raises a `ValueError`, which is right for a command line and
    wrong for a file -- so the ref grammar refuses it first, with the key it was
    written at and a hint. The lock-side check stays as the backstop for a path
    that reached a key some other way.
    """
    with pytest.raises(ConfigError, match="as a path segment"):
        parse_secret_ref("apps/../acme/db#DB_CREDENTIALS/acme_web_user")


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("apps/acme?x/db", id="query"),
        pytest.param("apps/%2e%2e/secrets", id="percent"),
        pytest.param("apps\\acme", id="backslash"),
        pytest.param("apps/acme\n/db", id="control"),
    ],
)
def test_a_character_that_changes_the_url_is_refused_by_the_backstop(path: str) -> None:
    """`lock break` reaches `normalise_path` from the command line (#858)."""
    with pytest.raises(ValueError, match="may not hold"):
        normalise_path(path)

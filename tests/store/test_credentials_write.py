"""Writing a credential into a stored document (#183, write side).

Tier 0. `tests/test_payload.py` already asserts that a *patch* omits every
sibling account; what is asserted here is that the store agrees — that a patch
omitting a key leaves that key as it was rather than as absent, through both
mechanisms `01-configuration.md` §7 names:

* a **merge patch**, where the keys this run did not come for are never sent;
* a **read-modify-write** under the same compare-and-set, where the whole
  document goes out and not rewriting a sibling wrongly is something the code
  has to get right rather than something it cannot get wrong.

The second is where the interesting assertions live, for exactly that reason.

The other two properties with their own sections below are the ones a rotation
depends on and a fake would flatter: that RFC 7386's deletion **removes** a key
rather than storing a null — a `pending` of `null` reads as staged-with-no-value,
not as cleared — and that a foreign writer **aborts** the run instead of being
merged over.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.payload import CURRENT, PENDING, PREVIOUS, REMOVE, merge, stage_layout
from sopuli.secrets import Secret
from sopuli.store import MemoryStore
from sopuli.store.credentials import READ_MODIFY_WRITE, apply_patch, staged_patch
from sopuli.store.protocol import (
    CAS,
    LIST,
    MERGE_PATCH,
    VERSIONING,
    CasConflictError,
    PatchNotPermittedError,
)

PATH = "apps/acme/prod/db/creds"
SHARED = "tenants/beta"

PER_ACCOUNT: dict[str, Any] = {
    "password": "current-one",
    "pending": "candidate-one",
    "rotated_at": "2026-08-04T09:12:33Z",
}

#: Two accounts in one document. Every sibling assertion below is about
#: `acme_api_user`, which no test ever writes to.
PER_APPLICATION: dict[str, Any] = {
    "DB_CREDENTIALS": {"acme_web_user": "current-one", "acme_api_user": "current-two"},
    "pending": {"acme_web_user": "candidate-one"},
}

#: A store that has everything but the merge patch, which is KV v1's shape for
#: the purposes of this module and the way the fallback is exercised.
NO_PATCH = frozenset({CAS, LIST, VERSIONING})


def ref(text: str) -> Any:
    return parse_secret_ref(text)


def store_with(document: Any, *, path: str = PATH, capabilities: Any = None) -> MemoryStore:
    store = MemoryStore() if capabilities is None else MemoryStore(capabilities=capabilities)
    store.write(path, document, cas=0)
    return store


def data_at(store: MemoryStore, path: str) -> Any:
    stored = store.read(path)
    assert stored is not None
    return stored.data


# ------------------------------------------------------------- the patch ---


def test_a_staged_patch_names_one_account_in_one_stage() -> None:
    """The write-side mirror of `resolve`: same layout, same rule, one key."""
    patch = staged_patch(
        ref(f"{SHARED}#DB_CREDENTIALS/acme_web_user"), Secret("new"), stage=PENDING
    )

    assert patch == {"pending": {"acme_web_user": Secret("new")}}


def test_a_staged_patch_keeps_the_value_wrapped() -> None:
    """No `reveal()` between generation and the store call, which is what makes
    the single reveal inside `apply_patch` meaningful rather than decorative:
    everything above it is safe to log."""
    patch = staged_patch(ref(f"{PATH}#password"), Secret("new"))

    assert isinstance(patch["password"], Secret)
    assert "new" not in repr(patch)


def test_a_staged_patch_refuses_a_ref_with_nowhere_to_stage_into() -> None:
    """The other half of §7's sentence. The whole-secret form is legal for a ref
    that is only ever read — `admin.auth.secret` — and has nowhere to put
    `pending`, so it is refused the moment somebody tries to rotate through it."""
    with pytest.raises(ConfigError):
        staged_patch(ref(PATH), Secret("new"))


# ------------------------------------------------- what a write leaves alone ---


def test_a_write_leaves_a_sibling_account_untouched() -> None:
    """§7's central promise, asserted on the document rather than on the patch.

    `tests/test_payload.py` asserts the patch omits the sibling; this asserts a
    key the patch omits survives the write.
    """
    store = store_with(PER_APPLICATION, path=SHARED)

    apply_patch(
        store,
        SHARED,
        staged_patch(ref(f"{SHARED}#DB_CREDENTIALS/acme_web_user"), Secret("rotated")),
        cas=1,
    )

    assert data_at(store, SHARED)["DB_CREDENTIALS"] == {
        "acme_web_user": "rotated",
        "acme_api_user": "current-two",
    }


def test_the_fallback_leaves_a_sibling_untouched_too() -> None:
    """The same property on the path where it is a thing the code gets right
    rather than a thing it cannot get wrong: the whole document goes out, so a
    sibling survives only because the merge was correct."""
    store = store_with(PER_APPLICATION, path=SHARED, capabilities=NO_PATCH)

    apply_patch(
        store,
        SHARED,
        staged_patch(ref(f"{SHARED}#DB_CREDENTIALS/acme_web_user"), Secret("rotated")),
        cas=1,
    )

    assert data_at(store, SHARED)["DB_CREDENTIALS"]["acme_api_user"] == "current-two"


def test_a_write_leaves_unrecognised_keys_alone() -> None:
    """§7: "keys the tool does not recognise are preserved verbatim, never
    dropped and never rebuilt from config. A document is edited, not
    regenerated." Application settings share these documents."""
    store = store_with(
        {"password": "current-one", "app_setting": {"pool_size": 20}, "owner": "team-acme"}
    )

    apply_patch(store, PATH, staged_patch(ref(f"{PATH}#password"), Secret("rotated")), cas=1)

    assert data_at(store, PATH) == {
        "password": "rotated",
        "app_setting": {"pool_size": 20},
        "owner": "team-acme",
    }


def test_the_value_reaches_the_store_as_plaintext() -> None:
    """Invariant 2's permitted reveal, asserted where it happens. A `Secret` that
    reached the store still wrapped would be a document no backend could
    serialise and no application could read."""
    store = store_with(PER_ACCOUNT)

    apply_patch(store, PATH, staged_patch(ref(f"{PATH}#password"), Secret("rotated")), cas=1)

    assert data_at(store, PATH)["password"] == "rotated"


def test_a_first_write_creates_the_document() -> None:
    """`cas=0` asserts there is nothing at the path, so this is a write and never
    a merge patch — a patch describes a change to something, and Vault will not
    create a document by one."""
    store = MemoryStore()

    written = apply_patch(
        store, PATH, staged_patch(ref(f"{PATH}#password"), Secret("first")), cas=0
    )

    assert written.mechanism == READ_MODIFY_WRITE
    assert data_at(store, PATH) == {"password": "first"}


# ------------------------------------------------------------- promotion ---


def test_a_promotion_reaches_the_store_as_one_write() -> None:
    """UC-1 §3's four changes in a single version. Four writes would be four
    versions, three of which describe a state that was never true — and any of
    which can be the one that fails."""
    store = store_with(PER_ACCOUNT)
    at = stage_layout(ref(f"{PATH}#password"))

    written = apply_patch(
        store,
        PATH,
        merge(
            at.patch(CURRENT, Secret("candidate-one")),
            at.patch(PREVIOUS, Secret("current-one")),
            at.patch(PENDING, REMOVE),
            at.patch("rotated_by", "approle:sopuli-ci"),
        ),
        cas=1,
    )

    assert written.version == 2
    assert data_at(store, PATH) == {
        "password": "candidate-one",
        "previous": "current-one",
        "rotated_at": "2026-08-04T09:12:33Z",
        "rotated_by": "approle:sopuli-ci",
    }


def test_removing_a_stage_deletes_the_key_rather_than_storing_a_null() -> None:
    """RFC 7386's deletion, which is the whole difference between `merge` and
    `apply_patch` and the one a single shared helper would have got wrong for one
    of them. A `pending` of `null` reads as staged-with-no-value, not cleared."""
    store = store_with(PER_ACCOUNT)

    apply_patch(store, PATH, staged_patch(ref(f"{PATH}#password"), REMOVE, stage=PENDING), cas=1)

    assert "pending" not in data_at(store, PATH)


def test_clearing_a_stage_that_was_never_staged_is_not_an_error() -> None:
    """Invariant 9's shape at this layer: the second run reaches the same
    document rather than failing on a key that is already gone."""
    store = store_with({"password": "current-one"})

    apply_patch(store, PATH, staged_patch(ref(f"{PATH}#password"), REMOVE, stage=PENDING), cas=1)

    assert data_at(store, PATH) == {"password": "current-one"}


# ---------------------------------------------------------- which mechanism ---


def test_a_store_with_merge_patch_uses_one_and_says_so() -> None:
    """UC-1 §3 requires the run to report the mechanism, and the two are not
    equally narrow — so it is reported rather than inferred from the backend."""
    store = store_with(PER_APPLICATION, path=SHARED)

    written = apply_patch(
        store,
        SHARED,
        staged_patch(ref(f"{SHARED}#DB_CREDENTIALS/acme_web_user"), Secret("x")),
        cas=1,
    )

    assert written.mechanism == MERGE_PATCH
    assert written.version == 2


def test_a_store_without_merge_patch_falls_back_and_says_so() -> None:
    """`04-testing.md` §5's KV v1 degradation row: the fallback is used **and the
    tool says so**, rather than the run looking identical either way."""
    store = store_with(PER_APPLICATION, path=SHARED, capabilities=NO_PATCH)

    written = apply_patch(
        store,
        SHARED,
        staged_patch(ref(f"{SHARED}#DB_CREDENTIALS/acme_web_user"), Secret("x")),
        cas=1,
    )

    assert written.mechanism == READ_MODIFY_WRITE


def test_a_store_that_refuses_the_patch_falls_back_rather_than_failing() -> None:
    """A Vault policy granting `update` and not `patch` is an ordinary policy and
    not a broken token, and `patch` is a capability of the mount rather than of
    the token — so this cannot be negotiated in `supports()` and is discovered by
    asking. If the token really were bad, the fallback's own read fails with the
    refusal it deserves."""

    class Unpatchable(MemoryStore):
        def patch(self, path: str, changes: Any, *, cas: int | None) -> int:
            raise PatchNotPermittedError(f"the store refused a merge patch at {path!r}")

    store = Unpatchable()
    store.write(PATH, PER_ACCOUNT, cas=0)

    written = apply_patch(store, PATH, staged_patch(ref(f"{PATH}#password"), Secret("x")), cas=1)

    assert written.mechanism == READ_MODIFY_WRITE
    assert data_at(store, PATH)["password"] == "x"


# ------------------------------------------------------ a foreign writer ---


def test_a_concurrent_change_aborts_the_write() -> None:
    """§7, and the reason it is a rule rather than caution: this run holds the
    advisory lock on the path, so a conflict means a *foreign* writer. Re-reading
    and merging over them is the read-modify-write that rewrites fields belonging
    to accounts nobody selected, which invariant 5 exists to prevent."""
    store = store_with(PER_ACCOUNT)
    store.write(PATH, {**PER_ACCOUNT, "password": "somebody-elses"}, cas=1)

    with pytest.raises(CasConflictError):
        apply_patch(store, PATH, staged_patch(ref(f"{PATH}#password"), Secret("x")), cas=1)


def test_a_conflict_on_the_fallback_aborts_before_the_document_is_built() -> None:
    """The fallback's read and its write are two calls, so without a check the
    run would compute a whole document from a version it has already been told it
    is not writing against. The store's own compare-and-set still guards the
    write; this stops the wrong document being built at all."""
    store = store_with(PER_ACCOUNT, capabilities=NO_PATCH)
    store.write(PATH, {**PER_ACCOUNT, "password": "somebody-elses"}, cas=1)

    with pytest.raises(CasConflictError):
        apply_patch(store, PATH, staged_patch(ref(f"{PATH}#password"), Secret("x")), cas=1)

    assert data_at(store, PATH)["password"] == "somebody-elses"


def test_an_unguarded_write_is_possible_where_the_store_has_no_cas() -> None:
    """`locking: advisory-only` on a store with no compare-and-set: the write
    goes out without a guard, which is what that setting costs and what every run
    under it says (`SOPULI-W001`)."""
    store = store_with(PER_ACCOUNT, capabilities=frozenset({LIST}))

    written = apply_patch(store, PATH, staged_patch(ref(f"{PATH}#password"), Secret("x")), cas=None)

    assert written.mechanism == READ_MODIFY_WRITE
    assert data_at(store, PATH)["password"] == "x"

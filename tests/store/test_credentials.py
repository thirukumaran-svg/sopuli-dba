"""Resolving a §7 ref against a stored document (read side).

Tier 0 throughout. The addressing is pure -- a document in, a value out -- and
`04-testing.md` §4 wants it that way as an architecture property rather than a
test convenience: a rule about where a password lives inside a document is a
decision, and decisions are the layer that has to be testable without a
container.

Two shapes run through nearly every test, because Q7's whole claim is that they
are **one rule and not two**:

* one secret per account, `apps/acme/db/creds#password` -- the container holds
  the value, and `pending` is a scalar beside it;
* one secret per application, `tenants/beta#DB_CREDENTIALS/acme_web_user` -- the
  container is a map keyed by account, and `pending` is a map keyed the same way.

The interesting assertions are the refusals. A ref that lands on the container
rather than on the value inside it is the mistake this layer exists to catch,
and the failure it prevents is a `Secret` wrapping a dictionary on its way to
`ALTER USER`.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.exit_codes import ExitCode
from sopuli.payload import stage_layout
from sopuli.secrets import Secret
from sopuli.store import MemoryStore
from sopuli.store.credentials import (
    CannotPinVersionError,
    SecretShapeError,
    read_secret,
    resolve,
)
from sopuli.store.protocol import CAS, LIST

PATH = "apps/acme/prod/db/creds"
SHARED = "tenants/beta"

#: The one-secret-per-account layout, mid-rotation: a candidate is staged and the
#: generation before current is still there for a rollback.
PER_ACCOUNT: dict[str, Any] = {
    "username": "acme_web_user",
    "password": "current-one",
    "pending": "candidate-one",
    "previous": "older-one",
    "rotated_at": "2026-08-04T09:12:33Z",
}

#: The one-secret-per-application layout holding two accounts, one of which is
#: mid-rotation and one of which is not. The asymmetry is the point: `pending`
#: names one account and not the other, which is what a shared document looks
#: like when a single account is rotated inside it.
PER_APPLICATION: dict[str, Any] = {
    "DB_CREDENTIALS": {"acme_web_user": "current-one", "acme_api_user": "current-two"},
    "pending": {"acme_web_user": "candidate-one"},
    "rotated_at": {"acme_web_user": "2026-08-04T09:12:33Z"},
}


def ref(text: str) -> Any:
    return parse_secret_ref(text)


def revealed(value: Secret | None) -> str | None:
    """The plaintext, in the tests only.

    Invariant 2's exceptions do not include a test, and this is why that is
    survivable: comparing two `Secret`s works without revealing either, but a
    failing assertion would then print `*** != ***` and say nothing at all.
    """
    return None if value is None else value.reveal()


# --------------------------------------------------------- the two layouts ---


def test_a_field_resolves_to_the_value_it_names() -> None:
    assert revealed(resolve(PER_ACCOUNT, ref(f"{PATH}#password"))) == "current-one"


def test_a_pointer_resolves_to_one_account_inside_the_container() -> None:
    got = resolve(PER_APPLICATION, ref(f"{SHARED}#DB_CREDENTIALS/acme_web_user"))
    assert revealed(got) == "current-one"


def test_a_pointer_segment_is_unescaped_before_it_is_looked_up() -> None:
    """RFC 6901: `a~1b` is the single key `a/b`, not two levels.

    Worth a test of its own because the decoding lives in `SecretRef` and the
    lookup lives here, so nothing checks that they meet unless something does.
    """
    document = {"DB_CREDENTIALS": {"a/b": "odd-but-legal"}}
    assert revealed(resolve(document, ref(f"{SHARED}#DB_CREDENTIALS/a~1b"))) == "odd-but-legal"


def test_the_same_stage_rule_covers_both_layouts() -> None:
    """Q7's claim, asserted rather than described: `@stage=pending` is "the
    `pending` sibling, same pointer" in each, and one `location()` produces
    both."""
    scalar = resolve(PER_ACCOUNT, ref(f"{PATH}#password@stage=pending"))
    mapped = resolve(PER_APPLICATION, ref(f"{SHARED}#DB_CREDENTIALS/acme_web_user@stage=pending"))

    assert revealed(scalar) == "candidate-one"
    assert revealed(mapped) == "candidate-one"


def test_previous_is_reachable_the_same_way() -> None:
    assert revealed(resolve(PER_ACCOUNT, ref(f"{PATH}#password@stage=previous"))) == "older-one"


def test_no_qualifier_means_current() -> None:
    """`current` is not a root key -- the container *is* the current stage -- so
    this is the one stage that does not swap the root."""
    plain = resolve(PER_ACCOUNT, ref(f"{PATH}#password"))
    explicit = resolve(PER_ACCOUNT, ref(f"{PATH}#password@stage=current"))
    assert revealed(plain) == revealed(explicit) == "current-one"


# ------------------------------------------------- finding nothing is not an error ---


def test_a_stage_nobody_staged_resolves_to_nothing() -> None:
    """UC-1 §3's state model reads this as "there is nothing staged here", which
    is a state and not a failure -- the ordinary condition of a document between
    rotations."""
    assert (
        resolve(PER_APPLICATION, ref(f"{SHARED}#DB_CREDENTIALS/acme_api_user@stage=pending"))
        is None
    )


def test_an_account_that_is_not_in_the_document_resolves_to_nothing() -> None:
    assert resolve(PER_APPLICATION, ref(f"{SHARED}#DB_CREDENTIALS/acme_batch_user")) is None


def test_a_missing_document_resolves_to_nothing() -> None:
    """`None` is accepted rather than tolerated: a path with nothing at it is the
    very first rotation, and requiring a mapping here would put `or {}` at every
    call site."""
    assert resolve(None, ref(f"{PATH}#password")) is None


def test_a_staged_read_of_a_missing_document_resolves_to_nothing() -> None:
    """No document is not a document of the wrong shape.

    The two look alike from inside the staged branch -- neither is a map -- and
    conflating them refuses a path that is merely empty, which is the ordinary
    state before the first rotation. Reachable through a store as well as
    directly: KV v1 answers a body with no `data` key as `Stored(data=None)`.
    """
    assert resolve(None, ref(f"{PATH}#password@stage=pending")) is None
    assert resolve(None, ref(f"{SHARED}#DB_CREDENTIALS/acme_web_user@stage=previous")) is None


def test_a_staged_read_of_a_missing_document_resolves_to_nothing_through_a_store() -> None:
    """The same thing where it is actually reached: a store whose read answers a
    document of `None` rather than answering `None` itself."""
    store = MemoryStore()
    store.write(PATH, None, cas=0)

    assert read_secret(store, ref(f"{PATH}#password@stage=pending")) is None


def test_a_field_that_is_not_there_resolves_to_nothing() -> None:
    assert resolve({"other": "value"}, ref(f"{PATH}#password")) is None


# ------------------------------------------------------- the whole-secret form ---


def test_a_ref_with_no_field_reads_a_single_field_document() -> None:
    """§7's "whole secret (scalar or single-field)", which is what makes the form
    usable against KV at all -- a KV secret is always a map, so `vault kv put
    path password=…` gives a document of one key and a ref naming no field means
    that key. This is the shape `admin.auth.secret` uses."""
    assert revealed(resolve({"password": "admin-one"}, ref(PATH))) == "admin-one"


def test_a_ref_with_no_field_reads_a_scalar_document() -> None:
    assert revealed(resolve("admin-one", ref(PATH))) == "admin-one"


def test_a_ref_with_no_field_is_refused_where_there_is_more_than_one() -> None:
    """There is nothing for it to mean, and guessing would authenticate with
    whichever key happened to be first. The message lists the field names, which
    is safe -- they are keys, and the values are what this layer never shows."""
    with pytest.raises(SecretShapeError) as raised:
        resolve({"password": "one", "username": "acme_web_user"}, ref(PATH))

    assert "holds 2 of them" in str(raised.value)
    assert "password" in str(raised.value)
    assert "one" not in str(raised.value)


def test_a_whole_secret_ref_is_legal_here_though_rotation_refuses_it() -> None:
    """The two rules are consistent rather than in tension.

    `stage_layout` refuses a field-less ref because rotation needs somewhere to
    put `pending`; §7 says in the same breath that "none of this constrains a ref
    that is only ever read". So the same ref resolves here and is refused there,
    and this test is the statement of that.
    """
    assert revealed(resolve({"password": "admin-one"}, ref(PATH))) == "admin-one"
    with pytest.raises(ConfigError):
        stage_layout(ref(PATH))


# ------------------------------------------------------------ wrong shapes ---


def test_a_ref_that_stops_at_the_container_is_refused() -> None:
    """The mistake this layer exists to catch: one pointer segment short, so the
    ref lands on the map of accounts rather than on an account's password. What
    it prevents is a `Secret` wrapping a dictionary on its way to `ALTER USER`."""
    with pytest.raises(SecretShapeError) as raised:
        resolve(PER_APPLICATION, ref(f"{SHARED}#DB_CREDENTIALS"))

    assert "dict rather than a password" in str(raised.value)
    assert "DB_CREDENTIALS" in str(raised.value)


def test_a_refusal_about_the_shape_never_quotes_the_value() -> None:
    """Where a leak would be easiest, because the obvious way to say "that is not
    a password" is to show what it was instead."""
    with pytest.raises(SecretShapeError) as raised:
        resolve(
            {"DB_CREDENTIALS": {"acme_web_user": "current-one"}}, ref(f"{SHARED}#DB_CREDENTIALS")
        )

    assert "current-one" not in str(raised.value)


def test_a_value_that_is_not_a_string_is_refused() -> None:
    with pytest.raises(SecretShapeError) as raised:
        resolve({"password": 12345}, ref(f"{PATH}#password"))

    assert "int rather than a password" in str(raised.value)


def test_a_stage_of_a_scalar_document_is_refused() -> None:
    """A ref that can never resolve, rather than one that found nothing today:
    on a store that emulates the stages in payload fields there is nowhere for
    `pending` to be if the document is not a map."""
    with pytest.raises(SecretShapeError) as raised:
        resolve("just-a-password", ref(f"{PATH}#password@stage=pending"))

    assert "not a map" in str(raised.value)


# ------------------------------------------------------- reading via a store ---


def store_with(document: Any, *, path: str = PATH) -> MemoryStore:
    store = MemoryStore()
    store.write(path, document, cas=0)
    return store


def test_reading_through_a_store_carries_the_version_and_the_stage() -> None:
    """Both, because the run document's `secret_ref` types both and a caller that
    re-derived them would be re-deriving them from the ref -- which says what was
    asked for, not what was found."""
    store = store_with(PER_ACCOUNT)

    got = read_secret(store, ref(f"{PATH}#password"))

    assert got is not None
    assert revealed(got.value) == "current-one"
    assert got.version == 1
    assert got.stage == "current"


def test_a_stage_read_reports_the_stage_it_asked_for() -> None:
    got = read_secret(store_with(PER_ACCOUNT), ref(f"{PATH}#password@stage=pending"))

    assert got is not None
    assert revealed(got.value) == "candidate-one"
    assert got.stage == "pending"


def test_an_empty_path_reads_as_nothing() -> None:
    assert read_secret(MemoryStore(), ref(f"{PATH}#password")) is None


def test_a_pinned_version_reads_the_generation_it_names() -> None:
    """The point of `@version=`: an older document, not the current one. Read
    back through the same rule, so the stage resolution happens *inside* whichever
    version was selected."""
    store = store_with(PER_ACCOUNT)
    store.write(PATH, {**PER_ACCOUNT, "password": "current-two"}, cas=1)

    got = read_secret(store, ref(f"{PATH}#password@version=1"))

    assert got is not None
    assert revealed(got.value) == "current-one"
    assert got.version == 1


def test_a_pinned_version_that_is_gone_reads_as_nothing() -> None:
    assert read_secret(store_with(PER_ACCOUNT), ref(f"{PATH}#password@version=9")) is None


def test_a_pinned_version_against_a_store_that_keeps_none_is_refused() -> None:
    """Invariant 4's shape applied to a store capability: a distinct exit code
    and a message naming what is missing, rather than a generic failure further
    in. The message names the ref, which is the text somebody has to go and edit
    -- the store's own refusal names only a path, because a store has never heard
    of a ref."""
    store = MemoryStore(capabilities=frozenset({CAS, LIST}))
    store.write(PATH, PER_ACCOUNT, cas=0)

    with pytest.raises(CannotPinVersionError) as raised:
        read_secret(store, ref(f"{PATH}#password@version=1"))

    assert raised.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
    assert f"{PATH}#password@version=1" in str(raised.value)


def test_two_accounts_in_one_document_read_back_their_own_values() -> None:
    """The read-side half of the sibling rule. The write half -- a patch that
    omits every account it did not come for -- is tested in
    `test_credentials_write.py`, and this is the property it has to preserve:
    one document, two refs, two different passwords, and neither ref able to
    reach the other's."""
    store = store_with(PER_APPLICATION, path=SHARED)

    web = read_secret(store, ref(f"{SHARED}#DB_CREDENTIALS/acme_web_user"))
    api = read_secret(store, ref(f"{SHARED}#DB_CREDENTIALS/acme_api_user"))

    assert web is not None
    assert api is not None
    assert revealed(web.value) == "current-one"
    assert revealed(api.value) == "current-two"
    assert web.version == api.version == 1

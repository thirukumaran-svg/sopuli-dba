"""The run document's ``lock`` section, validated against the published schema.

Invariant 12: the schema is the test fixture, not documentation written
afterwards. Every section built here goes through
``sopuli-run-1.5.schema.json`` -- which is stricter than it looks, because #98's
review tightened it: every field of a `held` entry is required, and a `denied`
whose reason is `held` must describe the holder.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from sopuli.config.locking import LOCK_ADVISORY_ONLY, LOCK_REQUIRED
from sopuli.diagnostics import ADVISORY_LOCKING, LOCK_TAKEN_OVER, WARNINGS, lock_diagnostics
from sopuli.exit_codes import ExitCode
from sopuli.lock import (
    CLOCK_SKEW,
    DEFAULT_TTL,
    Holder,
    LockableStore,
    LockDeniedError,
    LockKey,
    LockManager,
    lock_path,
)
from sopuli.output.document import RunDocument, Summary
from sopuli.output.lock_view import build_section
from sopuli.store import MemoryStore

REPO_ROOT = Path(__file__).resolve().parents[1]
STORE = "vault-prod"
KEY = LockKey(store=STORE, path="apps/acme/db")
NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
HOLDER = Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli")


class Clock:
    def __init__(self, now: datetime = NOW) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


@pytest.fixture(scope="module")
def validator() -> Draft202012Validator:
    schema = REPO_ROOT / "docs" / "schemas" / "sopuli-run-1.5.schema.json"
    return Draft202012Validator(json.loads(schema.read_text(encoding="utf-8")))


def manager(
    store: MemoryStore,
    *,
    correlation_id: str = "01JMINE",
    clock: Clock | None = None,
    locking: str = LOCK_REQUIRED,
    break_expired: bool = False,
) -> LockManager:
    return LockManager(
        stores={STORE: LockableStore(store=store, locking=locking)},
        correlation_id=correlation_id,
        command="creds rotate",
        holder=HOLDER,
        break_expired=break_expired,
        now=clock or Clock(),
    )


def document_with(section: dict[str, Any] | None) -> dict[str, Any]:
    document = RunDocument.start("creds.rotate")
    document.lock = section
    return document.finish(ExitCode.SUCCESS, Summary()).to_dict()


# ------------------------------------------------------------------- held ---


def test_a_run_that_took_no_lock_has_no_section() -> None:
    """Absent *means* something: no lock was needed.

    Every `check`, `status` and `--dry-run` lands here, and an empty object would
    instead describe a run that wanted locks and holds none.
    """
    assert build_section(manager(MemoryStore())) is None
    assert "lock" not in document_with(None)


def test_a_held_lock_reports_its_fence_and_its_window(validator: Draft202012Validator) -> None:
    store = MemoryStore()
    run = manager(store)
    run.acquire([KEY])

    section = build_section(run)

    assert section == {
        "mode": "cas",
        "held": [
            {
                "vault": STORE,
                "path": "apps/acme/db",
                "fence": 1,
                "acquired_at": "2026-08-16T12:00:00Z",
                "expires_at": "2026-08-16T12:15:00Z",
                "released": False,
            }
        ],
    }
    assert not list(validator.iter_errors(document_with(section)))


def test_a_released_lock_says_so() -> None:
    """`released: false` on a finished run means the release write failed, which
    is a fact worth reporting rather than an error worth raising over."""
    store = MemoryStore()
    run = manager(store)
    run.acquire([KEY])
    run.release()

    section = build_section(run)
    assert section is not None
    assert section["held"][0]["released"]


def test_an_advisory_lock_reports_the_guarantee_it_actually_had(
    validator: Draft202012Validator,
) -> None:
    """`mode` names the guarantee rather than the mechanism, and `fence: null`
    says the same thing per lock -- a consumer never has to know what KV v1 is."""
    store = MemoryStore(capabilities=frozenset())
    run = manager(store, locking=LOCK_ADVISORY_ONLY)
    run.acquire([KEY])

    section = build_section(run)

    assert section is not None
    assert section["mode"] == "none"
    assert section["held"][0]["fence"] is None
    assert not list(validator.iter_errors(document_with(section)))


# ----------------------------------------------------------------- denied ---


def test_a_denial_by_a_live_holder_describes_them(validator: Draft202012Validator) -> None:
    store = MemoryStore()
    manager(store).acquire([KEY])
    loser = manager(store, correlation_id="01JTHEIRS")

    with pytest.raises(LockDeniedError) as caught:
        loser.acquire([KEY])
    section = build_section(loser, denied=caught.value)

    assert section is not None
    assert section["denied"] == {
        "vault": STORE,
        "path": "apps/acme/db",
        "reason": "held",
        "holder": {
            "host": "ci-runner-3",
            "pid": 8821,
            "os_user": "svc_sopuli",
            "correlation_id": "01JMINE",
            "command": "creds rotate",
        },
        "acquired_at": "2026-08-16T12:00:00Z",
        "expires_at": "2026-08-16T12:15:00Z",
        "expired": False,
    }
    assert not list(validator.iter_errors(document_with(section)))


def test_the_holder_is_flattened_from_a_record_that_nests_it_differently() -> None:
    """In the record the correlation id and command are the *run's* own fields,
    beside the holder. In the report the run being described is somebody else's,
    so "who is that and what are they doing" is one question."""
    store = MemoryStore()
    manager(store).acquire([KEY])

    with pytest.raises(LockDeniedError) as caught:
        manager(store, correlation_id="01JTHEIRS").acquire([KEY])

    record = caught.value.record
    assert record is not None
    assert record.correlation_id == "01JMINE"
    assert record.holder is not None


def test_an_expired_holder_is_reported_as_expired(validator: Draft202012Validator) -> None:
    """The two refusals need different words: coordinate, or break it."""
    store = MemoryStore()
    clock = Clock()
    manager(store, clock=clock).acquire([KEY])
    clock.advance(DEFAULT_TTL + CLOCK_SKEW + timedelta(seconds=1))
    loser = manager(store, correlation_id="01JTHEIRS", clock=clock)

    with pytest.raises(LockDeniedError) as caught:
        loser.acquire([KEY])
    section = build_section(loser, denied=caught.value)

    assert section is not None
    assert section["denied"]["expired"]
    assert not list(validator.iter_errors(document_with(section)))


def test_a_lost_race_reports_no_holder(validator: Draft202012Validator) -> None:
    """The winner's record was never read, so an all-null holder would be a
    fabrication a consumer cannot tell from a vault answering badly."""
    store = MemoryStore()
    run = manager(store)
    denied = LockDeniedError("lost the race", key=KEY)

    section = build_section(run, denied=denied)

    assert section is not None
    assert section["denied"] == {"vault": STORE, "path": "apps/acme/db", "reason": "race"}
    assert not list(validator.iter_errors(document_with(section)))


def test_a_denied_run_reports_what_it_had_already_taken(validator: Draft202012Validator) -> None:
    """Acquisition is all-or-nothing, so those locks were released -- and saying
    which ones were touched is the point of reporting them at all."""
    store = MemoryStore()
    other = LockKey(store=STORE, path="apps/beta/db")
    manager(store, correlation_id="01JTHEIRS").acquire([other])
    loser = manager(store)

    with pytest.raises(LockDeniedError) as caught:
        loser.acquire([KEY, other])
    section = build_section(loser, denied=caught.value)

    assert section is not None
    assert [one["path"] for one in section["held"]] == ["apps/acme/db"]
    assert section["held"][0]["released"]
    assert not list(validator.iter_errors(document_with(section)))


# ------------------------------------------------------------ diagnostics ---


def test_an_ordinary_run_warns_about_nothing() -> None:
    store = MemoryStore()
    run = manager(store)
    run.acquire([KEY])

    assert lock_diagnostics(run) == []


def test_an_advisory_store_warns_on_every_run() -> None:
    """#83: the weakening reaches each run's audit trail rather than only the
    config file, which is the only place it would otherwise be visible."""
    store = MemoryStore(capabilities=frozenset())
    run = manager(store, locking=LOCK_ADVISORY_ONLY)
    run.acquire([KEY])

    (warning,) = lock_diagnostics(run)

    assert warning.level == "warning"
    assert warning.code == ADVISORY_LOCKING
    assert STORE in warning.message


def test_an_advisory_store_warns_once_rather_than_once_per_lock() -> None:
    """The weakening is a property of the store. Eleven locks in it is still one
    thing that is true."""
    store = MemoryStore(capabilities=frozenset())
    run = manager(store, locking=LOCK_ADVISORY_ONLY)
    run.acquire([KEY, LockKey(store=STORE, path="apps/beta/db")])

    assert len(lock_diagnostics(run)) == 1


def test_taking_over_a_lock_says_so_and_says_whose() -> None:
    """The evidence is gone from the path the moment the takeover write lands.

    If the run that broke the lock does not report it, nothing ever does.
    """
    store = MemoryStore()
    clock = Clock()
    manager(store, clock=clock).acquire([KEY])
    clock.advance(DEFAULT_TTL + CLOCK_SKEW + timedelta(seconds=1))
    taker = manager(store, correlation_id="01JTHEIRS", clock=clock, break_expired=True)
    taker.acquire([KEY])

    (warning,) = lock_diagnostics(taker)

    assert warning.code == LOCK_TAKEN_OVER
    assert "svc_sopuli@ci-runner-3" in warning.message
    assert lock_path(KEY).endswith("apps/acme/db")


def test_every_code_that_can_be_emitted_is_in_the_registry() -> None:
    """A code is contract in the way an enum value is (§8), so it needs a
    documented meaning rather than only a message somebody may reword."""
    store = MemoryStore(capabilities=frozenset())
    run = manager(store, locking=LOCK_ADVISORY_ONLY)
    run.acquire([KEY])

    for diagnostic in lock_diagnostics(run):
        assert diagnostic.code in WARNINGS


def test_a_diagnostic_reaches_the_document_with_its_code(
    validator: Draft202012Validator,
) -> None:
    store = MemoryStore(capabilities=frozenset())
    run = manager(store, locking=LOCK_ADVISORY_ONLY)
    run.acquire([KEY])

    document = RunDocument.start("creds.rotate")
    document.lock = build_section(run)
    document.diagnostics.extend(lock_diagnostics(run))
    rendered = document.finish(ExitCode.SUCCESS, Summary()).to_dict()

    assert rendered["diagnostics"][0]["code"] == ADVISORY_LOCKING
    assert not list(validator.iter_errors(rendered))

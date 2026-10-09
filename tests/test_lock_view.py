"""The run document's ``lock`` section, validated against the published schema.

Invariant 12: the schema is the test fixture, not documentation written
afterwards. Every section built here goes through
``sopuli-run-1.8.schema.json`` -- which is stricter than it looks: every field
of a `held` entry is required, and a `denied` whose reason is `held` must
describe the holder.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from sopuli.config.locking import LOCK_ADVISORY_ONLY, LOCK_REQUIRED
from sopuli.diagnostics import (
    ADVISORY_LOCKING,
    LOCK_PATH_UNGUARDED,
    LOCK_TAKEN_OVER,
    WARNINGS,
    lock_diagnostics,
)
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
from sopuli.lock.inspect import survey
from sopuli.output.document import SCHEMA_VERSION, RunDocument, Summary
from sopuli.output.lock_view import build_lock_section, build_status_section, render_status
from sopuli.store import CAS, MemoryStore
from sopuli.store.protocol import MetadataNotPermittedError

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
    schema = REPO_ROOT / "docs" / "schemas" / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
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


def document_with(
    section: dict[str, Any] | None, *, command: str = "creds.rotate"
) -> dict[str, Any]:
    document = RunDocument.start(command)
    document.lock = section
    return document.finish(ExitCode.SUCCESS, Summary()).to_dict()


# ------------------------------------------------------------------- held ---


def test_a_run_that_took_no_lock_has_no_section() -> None:
    """Absent *means* something: no lock was needed.

    Every `check`, `status` and `--dry-run` lands here, and an empty object would
    instead describe a run that wanted locks and holds none.
    """
    assert build_lock_section(manager(MemoryStore())) is None
    assert "lock" not in document_with(None)


def test_a_held_lock_reports_its_fence_and_its_window(validator: Draft202012Validator) -> None:
    store = MemoryStore()
    run = manager(store)
    run.acquire([KEY])

    section = build_lock_section(run)

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

    section = build_lock_section(run)
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

    section = build_lock_section(run)

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
    section = build_lock_section(loser, denied=caught.value)

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
    section = build_lock_section(loser, denied=caught.value)

    assert section is not None
    assert section["denied"]["expired"]
    assert not list(validator.iter_errors(document_with(section)))


def test_a_lost_race_reports_no_holder(validator: Draft202012Validator) -> None:
    """The winner's record was never read, so an all-null holder would be a
    fabrication a consumer cannot tell from a vault answering badly."""
    store = MemoryStore()
    run = manager(store)
    denied = LockDeniedError("lost the race", key=KEY)

    section = build_lock_section(run, denied=denied)

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
    section = build_lock_section(loser, denied=caught.value)

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
    """The advisory-only weakening (Q2) reaches each run's audit trail rather
    than only the config file, which is the only place it would otherwise be
    visible."""
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


def test_a_path_the_store_would_not_guard_warns_with_its_own_code() -> None:
    """The run succeeded, its lock was written under a compare-and-set, and
    its fence held -- so nothing in the result is wrong and the exit code cannot
    say this. What is missing is the store refusing an un-CAS'd write from
    anybody else, on a path that will still be unguarded on the next run."""
    store = MemoryStore()

    def refuse(path: str) -> None:
        raise MetadataNotPermittedError(f"the store refused to set `cas_required` on {path!r}")

    store.require_cas = refuse  # type: ignore[method-assign]
    run = manager(store)
    run.acquire([KEY])

    (warning,) = lock_diagnostics(run)

    assert warning.level == "warning"
    assert warning.code == LOCK_PATH_UNGUARDED
    assert str(KEY) in warning.message


def test_an_unguarded_path_is_reported_once_per_path() -> None:
    """The opposite of the advisory case above, and deliberately so: that one is
    a property of the store and is one fact however many locks are held, while
    this is a property of a path and names the path to go and fix."""
    store = MemoryStore()

    def refuse(path: str) -> None:
        raise MetadataNotPermittedError("nope")

    store.require_cas = refuse  # type: ignore[method-assign]
    run = manager(store)
    run.acquire([KEY, LockKey(store=STORE, path="apps/beta/db")])

    assert len(lock_diagnostics(run)) == 2


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
    document.lock = build_lock_section(run)
    document.diagnostics.extend(lock_diagnostics(run))
    rendered = document.finish(ExitCode.SUCCESS, Summary()).to_dict()

    assert rendered["diagnostics"][0]["code"] == ADVISORY_LOCKING
    assert not list(validator.iter_errors(rendered))


# ------------------------------------------------------------------ found ---
#
# `lock status`: records read at paths this run does not hold. A separate
# array from `held`, and these are the tests that say why -- the two describe
# different relationships to a lock, and one shape for both would make `released`
# mean two things depending on `command`.


def status_of(state: str = "held", *, capabilities: frozenset[str] = frozenset({CAS})) -> Any:
    """Put a record at the key and survey it, as somebody who does not hold it."""
    store = MemoryStore(capabilities=capabilities)
    locking = LOCK_REQUIRED if CAS in capabilities else LOCK_ADVISORY_ONLY
    run = manager(store, locking=locking)
    run.acquire([KEY])
    if state != "held":
        stored = store.read(lock_path(KEY))
        assert stored is not None
        store.write(lock_path(KEY), {**stored.data, "state": state}, cas=stored.version)
    return survey([KEY], stores={STORE: store}, now=NOW)


def test_a_survey_reports_the_holder_the_way_a_denial_does(
    validator: Draft202012Validator,
) -> None:
    """The question at exit 7 and the question `lock status` answers are the same
    question, so the answer is the same shape -- which is what the shared
    `lock_holder` definition in the schema is for."""
    section = build_status_section(status_of(), mode="cas")

    assert section == {
        "mode": "cas",
        "found": [
            {
                "vault": STORE,
                "path": "apps/acme/db",
                "held": True,
                # `survey` was given no declared set, which means "every key here
                # is declared" -- the answer for a caller that did not go looking.
                # `lock status` passes one; this test is about the holder.
                # `declared_by` defaults the same way and for the same reason:
                # a caller that never asked describes what it found
                # correctly rather than marking the whole survey undeclared.
                "declared": True,
                "declared_by": "binding",
                "state": "held",
                "expired": False,
                "version": 1,
                "acquired_at": "2026-08-16T12:00:00Z",
                "expires_at": "2026-08-16T12:15:00Z",
                "holder": {
                    "host": "ci-runner-3",
                    "pid": 8821,
                    "os_user": "svc_sopuli",
                    "correlation_id": "01JMINE",
                    "command": "creds rotate",
                },
            }
        ],
    }
    assert not list(validator.iter_errors(document_with(section, command="lock.status")))


def test_a_released_record_is_reported_as_not_held() -> None:
    """`held: false` here means the path is free, which is emphatically not what
    `held[].released: true` means on a rotation -- there it means this run let go
    cleanly. Two meanings, two arrays."""
    section = build_status_section(status_of("released"), mode="cas")

    assert section["found"][0]["held"] is False
    assert section["found"][0]["state"] == "released"


def test_an_unrecognised_state_is_reported_as_written_and_treated_as_held() -> None:
    """`held` is the verdict and `state` is the evidence. Flattening the second
    into the first would hide a record written by a newer sopuli behind a
    perfectly ordinary-looking row."""
    section = build_status_section(status_of("quiescing"), mode="cas")

    assert section["found"][0]["held"] is True
    assert section["found"][0]["state"] == "quiescing"


def test_a_survey_of_a_store_that_cannot_fence_reports_no_version(
    validator: Draft202012Validator,
) -> None:
    """Null for the reason `held[].fence` is null under mode `none`: the number
    exists and guarantees nothing, and offering it to a takeover would offer a
    comparison that always matches."""
    section = build_status_section(status_of(capabilities=frozenset()), mode="none")

    assert section["found"][0]["version"] is None
    assert not list(validator.iter_errors(document_with(section, command="lock.status")))


def test_a_free_path_is_not_an_entry(validator: Draft202012Validator) -> None:
    """`found` is what was read. How many paths were examined is
    `summary.total`, and the difference between the two is how many are free --
    which keeps every member of an entry required."""
    states = survey([KEY], stores={STORE: MemoryStore()}, now=NOW)
    section = build_status_section(states, mode="cas")

    assert section == {"mode": "cas", "found": []}
    assert not list(validator.iter_errors(document_with(section, command="lock.status")))


def test_the_quiet_estate_still_emits_a_section() -> None:
    """The one place an empty `lock` section is right. Absent means *no lock was
    needed*; here an empty `found` is the finding, and omitting it would make a
    quiet estate indistinguishable from a command that did not look."""
    assert "lock" in document_with(build_status_section((), mode="cas"), command="lock.status")


# ----------------------------------------------------------- the text view ---


def test_the_text_view_leads_with_the_string_lock_break_will_take() -> None:
    """`store:path` in one cell, because that spelling is what exit 7 prints and
    what `lock break` accepts. Two columns would make the operator reassemble by
    hand the one string they are about to paste."""
    rendered = render_status([Path("sopuli.yaml")], status_of(), mode="cas")

    assert "vault-prod:apps/acme/db" in rendered
    assert "svc_sopuli@ci-runner-3" in rendered
    assert "1 of 1 declared lock paths held" in rendered


def test_the_text_view_marks_a_lapsed_claim() -> None:
    store = MemoryStore()
    clock = Clock()
    manager(store, clock=clock).acquire([KEY])
    later = NOW + DEFAULT_TTL + CLOCK_SKEW + timedelta(seconds=1)

    rendered = render_status(
        [Path("sopuli.yaml")],
        survey([KEY], stores={STORE: store}, now=later),
        mode="cas",
    )

    assert "expired" in rendered
    assert "1 past expiry" in rendered


def test_the_text_view_shows_no_table_when_nothing_is_locked() -> None:
    """A table of forty free paths so that nothing can hide in it is a table
    nobody scans. The count is the answer."""
    rendered = render_status(
        [Path("sopuli.yaml")],
        survey([KEY], stores={STORE: MemoryStore()}, now=NOW),
        mode="cas",
    )

    assert "LOCK" not in rendered
    assert "0 of 1 declared lock paths held" in rendered

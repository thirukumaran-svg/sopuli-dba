"""`creds check`'s `results[]` against the published schema, and its table (#248).

Invariant 12: the schema is the test fixture. `result` is strict about the shapes
below it -- `verification` and `secret_ref` both carry
`additionalProperties: false` -- so a field emitted in the wrong shape fails here
rather than in a consumer.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from sopuli import check
from sopuli.config.model import Binding
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.driver.protocol import (
    FAIL,
    PASS,
    SKIPPED,
    VERIFY_LOGIN,
    UserState,
    VerifyResult,
)
from sopuli.exit_codes import ExitCode
from sopuli.output.check_view import build_result, render_check, summarise
from sopuli.output.document import SCHEMA_VERSION, Error, RunDocument

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = REPO_ROOT / "docs" / "schemas" / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
    return Draft202012Validator(json.loads(schema.read_text(encoding="utf-8")))


def binding(
    *, ref: str | None = "apps/acme/db#password", vault: str | None = "vault-prod"
) -> Binding:
    return Binding(
        account="ACME_WEB_USER",
        target="cdb1-pdb-orders",
        application="acme",
        secret=None if ref is None else parse_secret_ref(ref),
        vault=vault,
    )


def document_with(results: list[dict[str, Any]], states: list[str]) -> dict[str, Any]:
    run = RunDocument.start("creds.check")
    run.results = results
    return run.finish(check.exit_code_for(states), summarise(states)).to_dict()


# -------------------------------------------------------------- the schema ---


def test_a_passing_result_validates(validator: Draft202012Validator) -> None:
    outcome = check.decide(
        UserState(name="ACME_WEB_USER", status="OPEN"),
        VerifyResult(method=VERIFY_LOGIN, result=PASS, latency_ms=12, failed_logins=0),
        version=7,
    )
    entry = build_result(binding(), outcome, version=7, stage="current", age_days=12.9)

    assert entry["state"] == check.IN_SYNC
    assert not list(validator.iter_errors(document_with([entry], [outcome.state])))


def test_a_drifting_result_validates_and_exits_three(validator: Draft202012Validator) -> None:
    outcome = check.Outcome(check.DRIFT, "vault v7 rejected (ORA-01017)")
    entry = build_result(binding(), outcome, version=7, stage="current")

    document = document_with([entry], [check.DRIFT])
    assert document["exit_code"] == ExitCode.DRIFT
    assert not list(validator.iter_errors(document))


def test_an_errored_result_validates(validator: Draft202012Validator) -> None:
    outcome = check.Outcome(check.ERROR, "ORA-12541: no listener")
    entry = build_result(
        binding(),
        outcome,
        error=Error(category="database", message="ORA-12541: no listener", code="ORA-12541"),
    )

    assert not list(validator.iter_errors(document_with([entry], [check.ERROR])))


def test_a_binding_with_no_store_emits_no_secret(validator: Draft202012Validator) -> None:
    """Same rule as `plan.units[].secret`: `vault` is a required string, so there
    is no shape for half an address."""
    entry = build_result(binding(vault=None), check.Outcome(check.UNVERIFIABLE, "no store"))

    assert "secret" not in entry
    assert not list(validator.iter_errors(document_with([entry], [check.UNVERIFIABLE])))


def test_the_observed_version_is_what_the_store_served() -> None:
    """The one thing this knows that a plan deliberately cannot: a plan is a
    function of the config, and an observed version is a fact about a moment."""
    entry = build_result(binding(), check.Outcome(check.IN_SYNC, "ok"), version=9, stage="current")

    assert entry["secret"]["version"] == 9
    assert entry["secret"]["stage"] == "current"


# ---------------------------------------------------------- what it records ---


def test_a_declined_login_records_that_it_did_not_happen() -> None:
    """`applied` is whether the login happened, not whether it passed.

    A decline carries a `VerifyResult` too -- saying it declined -- so reading
    "the object exists" as "we tried" collapses exactly the distinction
    mitigation 1 exists to make visible. Caught by Copilot on #253, where the
    code said `True` while the comment beside it said the opposite.
    """
    declined = VerifyResult(
        method=VERIFY_LOGIN, result=SKIPPED, lockout_margin_hit=True, detail="within margin"
    )
    entry = build_result(binding(), check.Outcome(check.UNVERIFIABLE, "within margin", declined))

    assert entry["actions"][0]["applied"] is False
    assert entry["verification"]["lockout_margin_hit"] is True


def test_a_rejected_password_did_happen() -> None:
    """The other side of it: `FAIL` is an answer the database gave, and it cost
    the attempt that `SKIPPED` deliberately did not spend."""
    rejected = VerifyResult(method=VERIFY_LOGIN, result=FAIL, detail="ORA-01017")
    entry = build_result(binding(), check.Outcome(check.DRIFT, "rejected", rejected))

    assert entry["actions"][0]["applied"] is True


def test_an_errored_run_counts_as_failed_not_unverifiable() -> None:
    """`summary.failed` and the exit code must agree about one run: a document
    exiting 1 while reporting `failed: 0` contradicts itself."""
    summary = summarise([check.ERROR, check.LOCKED, check.IN_SYNC]).to_dict()

    assert summary["failed"] == 1
    assert summary["unverifiable"] == 1
    assert check.exit_code_for([check.ERROR, check.LOCKED, check.IN_SYNC]) == ExitCode.FAILURE


def test_a_missing_lcount_is_null_rather_than_absent() -> None:
    """#86 made `SELECT ON SYS.USER$` optional, so "the guard was unavailable" is
    a thing a scheduled check must be able to report. Omitting the key would make
    an ungranted estate look like one where nothing looked."""
    failed = VerifyResult(method=VERIFY_LOGIN, result=FAIL, failed_logins=None)
    entry = build_result(binding(), check.Outcome(check.DRIFT, "rejected", failed))

    assert entry["verification"]["lcount"] is None
    assert entry["verification"]["failed_login_attempts_limit"] is None


def test_check_never_reports_a_change() -> None:
    """Invariant 9's shape for a read-only verb: `changed` answers *did this run
    do anything*, and the answer is structurally no."""
    entry = build_result(binding(), check.Outcome(check.DRIFT, "rejected"))

    assert entry["changed"] is False


# ------------------------------------------------------------- the summary ---


def test_a_rollover_window_is_not_counted_as_ok() -> None:
    """It is healthy and it has a deadline attached; folding it into `ok` would
    make "4 ok" mean two different situations."""
    summary = summarise([check.IN_SYNC, check.ROLLOVER_ACTIVE]).to_dict()

    assert summary["ok"] == 1
    assert summary["by_state"][check.ROLLOVER_ACTIVE] == 1


def test_the_inconclusive_states_count_together() -> None:
    """ "1 drift, 1 unverifiable" answers *go and fix something* and *go and look
    at something*, and a locked account belongs to the second."""
    summary = summarise([check.LOCKED, check.UNVERIFIABLE, check.DRIFT]).to_dict()

    assert summary["unverifiable"] == 2
    assert summary["drift"] == 1


# ---------------------------------------------------------------- the text ---


def test_the_table_carries_the_reason_beside_every_state() -> None:
    """A state alone is a word an operator has to interpret; `UNVERIFIABLE` says
    nothing about whether to act."""
    rendered = render_check(
        [
            (binding(), check.Outcome(check.IN_SYNC, "vault v7 verified by login")),
            (binding(), check.Outcome(check.DRIFT, "vault v7 rejected (ORA-01017)")),
        ]
    )

    assert "vault v7 verified by login" in rendered
    assert "ORA-01017" in rendered
    assert "1 drift" in rendered


def test_a_clean_run_says_so_in_one_line() -> None:
    rendered = render_check([(binding(), check.Outcome(check.IN_SYNC, "verified"))])

    assert "all 1 in sync" in rendered


def test_the_rendered_table_is_ascii() -> None:
    """P4: redirected stdout on Windows is cp1252 (#12)."""
    render_check([(binding(), check.Outcome(check.DRIFT, "vault v7 rejected"))]).encode("ascii")

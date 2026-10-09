"""Deciding whether an account may be suspended, and how the run reports it.

Tier 0, pure: :func:`sopuli.suspend.decide` takes the ``UserState`` a caller read
and returns a decision, so every refusal here is testable without a database. The
statement itself is `tests/driver/test_oracle_statements.py`; that it is
idempotent against a real server is `tests/driver/test_oracle_suspend.py`.

``jdoe`` is a placeholder for a person and not anybody.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from sopuli.config.loading import build_config
from sopuli.driver.protocol import UserState
from sopuli.output.document import SCHEMA_VERSION
from sopuli.output.suspend_view import build_result, render, summarise
from sopuli.suspend import ACCOUNT_MISSING, LOCKED, SKIPPED, decide

RUN_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

TARGET = {
    "name": "appdb-dev-alpha",
    "type": "oracle",
    "environment": "dev",
    "dsn": "db-dev.example.com:1521/alphadev.pdb.example.com",
    "admin": {"username": "C##SOPULI_SVC", "auth": "prompt"},
}


def config(*rules: dict[str, Any]) -> Any:
    return build_config({"version": 1, "targets": [TARGET], "personal_accounts": list(rules)})


def state(name: str = "JDOE", **keys: Any) -> UserState:
    return UserState(name=name, status=keys.pop("status", "OPEN"), **keys)


# -------------------------------------------------------------- deciding ---


def test_a_declared_account_is_suspended() -> None:
    decision = decide(
        state(), config=config({"accounts": ["jdoe"]}), account="jdoe", target="appdb-dev-alpha"
    )

    assert decision.proceed
    assert decision.state == LOCKED
    assert "accounts 'jdoe'" in decision.detail


def test_an_account_no_rule_declares_is_refused() -> None:
    """Invariant 5, reported in the vocabulary every other verb refuses in."""
    decision = decide(
        state(), config=config({"accounts": ["asmith"]}), account="jdoe", target="appdb-dev-alpha"
    )

    assert not decision.proceed
    assert decision.state == SKIPPED
    assert "does not declare this account" in decision.detail


def test_a_predicate_declares_from_the_state_that_was_read() -> None:
    decision = decide(
        state(profile="DEV_USERS"),
        config=config({"profile": "DEV_USERS"}),
        account="jdoe",
        target="appdb-dev-alpha",
    )

    assert decision.proceed
    assert "profile 'DEV_USERS'" in decision.detail


def test_a_predicate_that_does_not_admit_this_account_refuses_it() -> None:
    """The half of invariant 5 a predicate must never weaken."""
    decision = decide(
        state(profile="APP_PROF"),
        config=config({"profile": "DEV_USERS"}),
        account="jdoe",
        target="appdb-dev-alpha",
    )

    assert not decision.proceed
    assert decision.state == SKIPPED


def test_an_account_that_does_not_exist_is_a_finding_rather_than_an_error() -> None:
    """The tool creates nothing (Q8), and an account on four of nine targets is ordinary."""
    decision = decide(
        None, config=config({"accounts": ["jdoe"]}), account="jdoe", target="appdb-dev-alpha"
    )

    assert not decision.proceed
    assert decision.state == ACCOUNT_MISSING
    assert decision.review is None


def test_a_vendor_account_is_refused_even_where_it_is_declared() -> None:
    """Guardrail 2. Suspending DBSNMP refuses exactly as rotating it would."""
    decision = decide(
        state(name="DBSNMP", vendor_maintained=True),
        config=config({"accounts": ["dbsnmp"]}),
        account="dbsnmp",
        target="appdb-dev-alpha",
    )

    assert not decision.proceed
    assert "its own" in decision.detail


def test_force_waives_a_guardrail_and_records_it() -> None:
    decision = decide(
        state(name="DBSNMP", vendor_maintained=True),
        config=config({"accounts": ["dbsnmp"]}),
        account="dbsnmp",
        target="appdb-dev-alpha",
        force=True,
    )

    assert decision.proceed
    assert decision.review is not None
    assert decision.review.overridden


def test_force_does_not_waive_the_whitelist() -> None:
    """Invariant 5's own sentence: `--force` overrides other guardrails, never this."""
    decision = decide(
        state(),
        config=config({"accounts": ["asmith"]}),
        account="jdoe",
        target="appdb-dev-alpha",
        force=True,
    )

    assert not decision.proceed
    assert "does not declare this account" in decision.detail


# ------------------------------------------------------------- reporting ---


def test_a_result_carries_the_status_it_read() -> None:
    entry = build_result(
        "jdoe",
        "appdb-dev-alpha",
        state=LOCKED,
        changed=True,
        detail="account was open; locked",
        status="OPEN",
    )

    assert entry["account_status"] == "OPEN"
    assert entry["actions"] == [
        {"kind": "account_lock", "applied": True, "detail": "account was open; locked"}
    ]
    assert "secret" not in entry


def test_a_refused_row_still_reports_the_status() -> None:
    """ "I left it alone, and here is the state it is in" is the whole answer."""
    entry = build_result(
        "jdoe",
        "appdb-dev-alpha",
        state=SKIPPED,
        changed=False,
        detail="not declared",
        status="OPEN",
    )

    assert entry["account_status"] == "OPEN"
    assert entry["actions"][0]["applied"] is False


def test_a_refusal_is_not_a_failure() -> None:
    summary = summarise([LOCKED, SKIPPED, ACCOUNT_MISSING], changed=1)

    assert summary.failed == 0
    assert summary.changed == 1
    assert summary.total == 3


def test_an_error_is() -> None:
    assert summarise([LOCKED, "ERROR"], changed=1).failed == 1


def test_the_closing_line_counts_changes_and_not_states() -> None:
    """The bug that reached a real run: a second run said it had suspended an
    account it found already locked. A `LOCKED` row cannot say which it was."""
    rows = [("jdoe", "appdb-dev-alpha", LOCKED, "LOCKED", "the account is already locked")]

    assert "already locked" in render(rows, changed=0)
    assert "suspended jdoe on 1" in render(rows, changed=1)


def test_a_preview_says_what_would_happen() -> None:
    rows = [("jdoe", "appdb-dev-alpha", LOCKED, "OPEN", "declared; would be suspended")]

    line = render(rows, changed=0, preview=True, would_suspend=1)

    assert "would suspend jdoe on 1 of 1" in line


# ------------------------------------------------------ overridden guardrails ---


def test_an_overridden_guardrail_is_a_check_and_a_reason() -> None:
    """The schema requires both halves, and a list of strings fails validation.

    It also loses the half an operator actually reads. `apply` emits the pair,
    and this verb emits the same pair for a `--force` run.
    """
    decision = decide(
        state(name="DBSNMP", vendor_maintained=True),
        config=config({"accounts": ["dbsnmp"]}),
        account="dbsnmp",
        target="appdb-dev-alpha",
        force=True,
    )
    assert decision.review is not None

    entry = build_result(
        "dbsnmp",
        "appdb-dev-alpha",
        state=LOCKED,
        changed=True,
        detail="account was open; locked",
        status="OPEN",
        overridden=decision.review.overridden,
    )

    assert entry["overridden"] == [
        {"check": "vendor_maintained", "reason": "the database reports this account as its own"}
    ]


def test_a_forced_result_validates_against_the_published_schema() -> None:
    """`additionalProperties: false` here means a wrong item shape is a document
    nobody can consume."""
    schema = json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))
    result_schema = schema["$defs"]["result"]
    result_schema["$defs"] = schema["$defs"]

    decision = decide(
        state(name="DBSNMP", vendor_maintained=True),
        config=config({"accounts": ["dbsnmp"]}),
        account="dbsnmp",
        target="appdb-dev-alpha",
        force=True,
    )
    assert decision.review is not None
    entry = build_result(
        "dbsnmp",
        "appdb-dev-alpha",
        state=LOCKED,
        changed=True,
        detail="locked",
        status="OPEN",
        overridden=decision.review.overridden,
    )

    Draft202012Validator(result_schema).validate(entry)


def test_the_closing_line_names_a_target_it_could_not_reach() -> None:
    """A failure sets the exit code, so the line summarising the run must say so.

    Without this, `[LOCKED, ERROR]` read "already locked on 1 of 2" and never
    mentioned the target it could not reach -- true, and the half a reader would
    have acted on is the half it left out.
    """
    rows = [
        ("jdoe", "appdb-dev-alpha", LOCKED, "LOCKED", "the account is already locked"),
        ("jdoe", "appdb-dev-beta", "ERROR", None, "could not connect"),
    ]

    line = render(rows, changed=0)

    assert "already locked on 1 of 2" in line
    assert "1 failed" in line


def test_a_clean_run_says_nothing_about_failures() -> None:
    rows = [("jdoe", "appdb-dev-alpha", LOCKED, "OPEN", "account was open; locked")]

    assert "failed" not in render(rows, changed=1)

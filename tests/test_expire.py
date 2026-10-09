"""Deciding whether a password may be expired, and how the run reports it.

Tier 0, pure. The gates are :mod:`sopuli.suspend`'s and are tested there in full
(`tests/test_suspend.py`); what is pinned here is that `expire-password` asks
them and reports its own state word, and the report's two-action shape. The
statement is `tests/driver/test_oracle_statements.py`, and its behaviour against
a real server is `tests/driver/test_oracle_expire.py`.

``jdoe`` is a placeholder for a person and not anybody.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from sopuli.config.loading import build_config
from sopuli.driver.protocol import PASSWORD_EXPIRE, ROLLOVER_FINISH, UserState
from sopuli.expire import ACCOUNT_MISSING, EXPIRED, SKIPPED, decide
from sopuli.output.document import SCHEMA_VERSION
from sopuli.output.expire_view import build_result, render, summarise
from sopuli.plan import ACTION_KINDS

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

#: What the driver reports for an account found at `EXPIRED & IN ROLLOVER`:
#: the window closed, the expiry not reissued.
WINDOW_ONLY = (
    (ROLLOVER_FINISH, True, "rollover window closed; the old password no longer works"),
    (PASSWORD_EXPIRE, False, "the password is already expired"),
)


def config(*rules: dict[str, Any]) -> Any:
    return build_config({"version": 1, "targets": [TARGET], "personal_accounts": list(rules)})


def state(name: str = "JDOE", **keys: Any) -> UserState:
    return UserState(name=name, status=keys.pop("status", "OPEN"), **keys)


def result_validator() -> Draft202012Validator:
    schema = json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))
    result_schema = schema["$defs"]["result"]
    result_schema["$defs"] = schema["$defs"]
    return Draft202012Validator(result_schema)


# -------------------------------------------------------------- deciding ---


def test_a_declared_account_proceeds_as_expired() -> None:
    decision = decide(
        state(), config=config({"accounts": ["jdoe"]}), account="jdoe", target="appdb-dev-alpha"
    )

    assert decision.proceed
    assert decision.state == EXPIRED


def test_an_undeclared_account_is_refused_even_under_force() -> None:
    """Invariant 5: `--force` never waives the whitelist, on this verb either."""
    decision = decide(
        state(name="SYSTEM"),
        config=config({"accounts": ["jdoe"]}),
        account="system",
        target="appdb-dev-alpha",
        force=True,
    )

    assert not decision.proceed
    assert decision.state == SKIPPED


def test_a_missing_account_is_a_finding() -> None:
    decision = decide(
        None, config=config({"accounts": ["jdoe"]}), account="jdoe", target="appdb-dev-alpha"
    )

    assert decision.state == ACCOUNT_MISSING


def test_suspend_still_proceeds_as_locked() -> None:
    """The shared gate took a parameter; the verb that owned it must not notice."""
    from sopuli.suspend import LOCKED
    from sopuli.suspend import decide as decide_suspend

    decision = decide_suspend(
        state(), config=config({"accounts": ["jdoe"]}), account="jdoe", target="appdb-dev-alpha"
    )

    assert decision.state == LOCKED


# ------------------------------------------------------------- reporting ---


def test_a_row_carries_both_statements_in_order() -> None:
    entry = build_result(
        "jdoe",
        "appdb-dev-alpha",
        state=EXPIRED,
        changed=True,
        actions=WINDOW_ONLY,
        status="EXPIRED & IN ROLLOVER",
    )

    assert [action["kind"] for action in entry["actions"]] == [ROLLOVER_FINISH, PASSWORD_EXPIRE]
    assert [action["applied"] for action in entry["actions"]] == [True, False]
    assert entry["account_status"] == "EXPIRED & IN ROLLOVER"
    result_validator().validate(entry)


def test_a_row_that_never_reached_the_driver_carries_one_unapplied_expiry() -> None:
    entry = build_result(
        "jdoe", "appdb-dev-alpha", state=SKIPPED, changed=False, detail="not declared"
    )

    assert entry["actions"] == [
        {"kind": PASSWORD_EXPIRE, "applied": False, "detail": "not declared"}
    ]
    result_validator().validate(entry)


def test_the_new_kind_is_one_a_plan_may_carry() -> None:
    """`plan.ACTION_KINDS` is a literal copy of the schema's enum; they move together."""
    schema = json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))

    assert PASSWORD_EXPIRE in ACTION_KINDS
    assert PASSWORD_EXPIRE in schema["$defs"]["action_kind"]["enum"]


def test_nothing_in_a_row_could_hold_a_password() -> None:
    entry = build_result(
        "jdoe", "appdb-dev-alpha", state=EXPIRED, changed=True, actions=WINDOW_ONLY
    )

    assert not {"secret", "password", "delivered", "handover"} & set(entry)


def test_a_refusal_is_not_a_failure_and_an_error_is() -> None:
    assert summarise([EXPIRED, SKIPPED, ACCOUNT_MISSING], changed=1).failed == 0
    assert summarise([EXPIRED, "ERROR"], changed=1).failed == 1


def test_the_closing_line_counts_changes_and_not_states() -> None:
    """`account suspend`'s bug, not repeated: an `EXPIRED` row cannot say whether
    this run expired it or found it expired."""
    rows = [("jdoe", "appdb-dev-alpha", EXPIRED, "EXPIRED", "the password is already expired")]

    assert "already expired on 1 of 1" in render(rows, changed=0)
    assert "expired jdoe's password on 1 of 1" in render(rows, changed=1)


def test_a_preview_says_what_would_happen() -> None:
    rows = [("jdoe", "appdb-dev-alpha", EXPIRED, "OPEN", "declared; would be expired")]

    assert "would expire jdoe's password on 1 of 1" in render(rows, preview=True, would_expire=1)


def test_the_closing_line_names_a_target_it_could_not_reach() -> None:
    rows = [
        ("jdoe", "appdb-dev-alpha", EXPIRED, "EXPIRED", "the password is already expired"),
        ("jdoe", "appdb-dev-beta", "ERROR", None, "could not connect"),
    ]

    line = render(rows, changed=0)

    assert "already expired on 1 of 2" in line
    assert "1 failed" in line

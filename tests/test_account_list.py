"""`sopuli account list` — resolving a declaration and reporting what it matched.

Tier 0. The database work belongs to the session, so every rule here is exercised
against a stub that answers the two questions a predicate asks
(``resolve_profile``/``resolve_role`` and ``accounts_matching``) — which is the
arrangement :mod:`sopuli.account_list` exists to make possible.

Fixtures use the fictional vocabulary the provenance note requires: application
``acme``, accounts ``acme_*_user``, tenants ``alpha``…``theta``, and ``jdoe`` and
``asmith`` for people, who are placeholders and not anybody.

**Two of these tests exist because a real run found the bug, not because anybody
predicted it** — the duplicate row and the two spellings. They are marked where
they appear.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from sopuli.account_list import (
    ABSENT,
    DECLARED,
    Notice,
    Row,
    cross_declared,
    enumerated_names,
    rule_for,
    rules_on,
)
from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.diagnostics import ADMITTED_CROSS_DECLARED, ADMITTED_VENDOR_ACCOUNT
from sopuli.driver.protocol import UserState
from sopuli.output.account_list_view import (
    build_result,
    render_account_list,
    summarise,
)

TARGET = "appdb-dev-alpha"

DOCUMENT: dict[str, Any] = {
    "version": 1,
    "targets": [
        {"name": TARGET, "type": "oracle", "dsn": "db-dev.example.com:1521/ALPHA"},
        {"name": "appdb-qa-alpha", "type": "oracle", "dsn": "db-qa.example.com:1521/ALPHA"},
    ],
    "policies": {"personal-standard": {"password": {"length": 24}}},
    "personal_accounts": [
        {"accounts": ["jdoe", "asmith"], "policy": "personal-standard"},
        {"profile": "DEV_USERS", "policy": "personal-standard"},
    ],
}


def config(**overrides: Any) -> Any:
    return build_config({**DOCUMENT, **overrides})


def user(name: str, *, status: str = "OPEN", profile: str | None = None, **extra: Any) -> UserState:
    return UserState(name=name, status=status, profile=profile, **extra)


# ------------------------------------------------------------- resolution ---


def test_an_enumerated_rule_reports_its_names_in_file_order() -> None:
    """The file is the whitelist and a reviewer reads the listing against it.
    Sorting would be tidier and would make the two harder to compare."""
    rule = config().personal_accounts[0]

    assert enumerated_names(rule) == ("jdoe", "asmith")


def test_a_rule_applies_only_to_the_targets_it_selects() -> None:
    narrowed = config(personal_accounts=[{"accounts": ["jdoe"], "targets": ["appdb-qa-alpha"]}])

    assert rules_on(narrowed, TARGET) == ()
    assert len(rules_on(narrowed, "appdb-qa-alpha")) == 1


def test_a_predicate_credits_the_account_to_the_rule_that_admits_it() -> None:
    rule = rule_for(config(), "carol", TARGET, profile="DEV_USERS")

    assert rule is not None
    assert rule.label == "profile 'DEV_USERS'"


def test_an_account_no_rule_admits_is_credited_to_nothing() -> None:
    assert rule_for(config(), "nobody", TARGET, profile="OTHER_PROF") is None


def test_two_rules_naming_different_policies_are_refused_here_too() -> None:
    """The listing must refuse exactly where the mutating verb does, or it is
    where an operator forms the belief the reset then refuses."""
    colliding = config(
        personal_accounts=[
            {"accounts": ["jdoe"], "policy": "personal-standard"},
            {"profile": "DEV_USERS", "policy": "other-policy"},
        ],
        policies={
            "personal-standard": {"password": {"length": 24}},
            "other-policy": {"password": {"length": 20}},
        },
    )

    with pytest.raises(ConfigError, match="different policies"):
        rule_for(colliding, "jdoe", TARGET, profile="DEV_USERS")


# ----------------------------------------------- the collision a file cannot see ---


def test_an_account_a_predicate_and_an_application_both_declare_is_named() -> None:
    """`reject_cross_declaration` catches the enumerated form at load and says it
    cannot reach this one: an account a *predicate* admits and an application
    declares is a fact about a database. H1 said the resolving verb is where it
    has to be caught."""
    both = config(
        vaults={"vault-dev": {"type": "hashicorp", "addr": "https://v.example.com"}},
        applications=[
            {
                "name": "acme",
                "accounts": ["acme_web_user"],
                "secret": "vault-dev:acme/db#pw",
            }
        ],
        personal_accounts=[{"profile": "DEV_USERS"}],
    )

    assert cross_declared(both, "ACME_WEB_USER") == "acme"
    assert cross_declared(both, "jdoe") is None


def test_the_row_gives_each_notice_its_own_code() -> None:
    """`_describe_row` is where each notice gets its code, so a swap of the two
    codes, or a lost one, fails here rather than passing every view test."""
    from sopuli.cli import _describe_row

    both = config(
        vaults={"vault-dev": {"type": "hashicorp", "addr": "https://v.example.com"}},
        applications=[
            {
                "name": "acme",
                "accounts": ["acme_web_user"],
                "secret": "vault-dev:acme/db#pw",
            }
        ],
        personal_accounts=[{"profile": "DEV_USERS"}],
    )
    target = next(one for one in both.targets if one.name == TARGET)

    class Session:
        def describe_user(self, name: str) -> UserState:
            return user(name.upper(), profile="DEV_USERS", vendor_maintained=True)

    row = _describe_row(Session(), "acme_web_user", target, both)

    assert [notice.code for notice in row.notices] == [
        ADMITTED_VENDOR_ACCOUNT,
        ADMITTED_CROSS_DECLARED,
    ]
    assert "as its own" in row.notices[0].message
    assert "also declared by acme" in row.notices[1].message


# ------------------------------------------------------------------ rows ---


def test_a_row_that_exists_is_declared_and_one_that_does_not_is_missing() -> None:
    rule = config().personal_accounts[0]
    present = Row(account="JDOE", target=TARGET, rule=rule, state=user("JDOE"))
    absent = Row(account="ghost", target=TARGET, rule=None, state=None)

    assert build_result(present)["state"] == DECLARED
    assert build_result(absent)["state"] == "ACCOUNT_MISSING"
    assert present.exists
    assert not absent.exists


def test_every_row_is_unchanged_because_this_verb_cannot_mutate() -> None:
    rule = config().personal_accounts[0]
    entry = build_result(Row(account="JDOE", target=TARGET, rule=rule, state=user("JDOE")))

    assert entry["changed"] is False
    assert entry["actions"] == [
        {"kind": "none", "applied": False, "detail": "declared by accounts 'jdoe', 'asmith'"}
    ]


def test_the_document_says_which_rule_admitted_the_account() -> None:
    """Under a predicate this is the only place the answer appears at all: the
    configuration does not contain it, because membership is a grant."""
    predicate = config().personal_accounts[1]
    entry = build_result(Row(account="CAROL", target=TARGET, rule=predicate, state=user("CAROL")))

    assert entry["declared_by"] == "profile 'DEV_USERS'"


def test_a_missing_account_is_credited_to_no_rule_rather_than_guessed() -> None:
    entry = build_result(Row(account="ghost", target=TARGET, rule=None, state=None))

    assert entry["declared_by"] is None


def test_the_database_date_absence_carries_its_reason_per_result() -> None:
    """`SOPULI-W021` is per result and `SOPULI-W023` is per run, and the
    difference is real: one release and one grant, but a date that may be
    readable for one account and not another."""
    rule = config().personal_accounts[0]
    unknown = user("JDOE", password_changed_unknown="no PASSWORD_CHANGE_DATE on this release")
    entry = build_result(Row(account="JDOE", target=TARGET, rule=rule, state=unknown))

    assert [warning["code"] for warning in entry["warnings"]] == ["SOPULI-W021"]


def test_a_rows_notices_carry_their_codes() -> None:
    """Each notice is its own condition with its own code (J3), so a consumer
    can tell "the database owns this account" from "the whitelist is ambiguous"
    without reading the message."""
    rule = config().personal_accounts[0]
    notices = (
        Notice(ADMITTED_VENDOR_ACCOUNT, "the database reports this account as its own"),
        Notice(ADMITTED_CROSS_DECLARED, "also declared by acme"),
    )
    entry = build_result(
        Row(account="JDOE", target=TARGET, rule=rule, state=user("JDOE"), notices=notices)
    )

    assert [warning["code"] for warning in entry["warnings"]] == [
        ADMITTED_VENDOR_ACCOUNT,
        ADMITTED_CROSS_DECLARED,
    ]


def test_a_reset_at_is_emitted_only_when_there_is_one() -> None:
    rule = config().personal_accounts[0]
    without = build_result(Row(account="JDOE", target=TARGET, rule=rule, state=user("JDOE")))
    with_one = build_result(
        Row(
            account="JDOE",
            target=TARGET,
            rule=rule,
            state=user("JDOE"),
            reset_at="2026-09-17T09:14:22Z",
        )
    )

    assert "reset_at" not in without
    assert with_one["reset_at"] == "2026-09-17T09:14:22Z"


# ------------------------------------------------------------------ table ---


def rows() -> list[Row]:
    built = config()
    return [
        Row(account="JDOE", target=TARGET, rule=built.personal_accounts[0], state=user("JDOE")),
        Row(
            account="CAROL",
            target=TARGET,
            rule=built.personal_accounts[1],
            state=user(
                "CAROL",
                profile="DEV_USERS",
                password_changed_at=datetime(2026, 9, 1, 8, 30, tzinfo=UTC),
            ),
        ),
    ]


def test_the_table_shortens_an_enumerated_rule_and_keeps_a_predicate_whole() -> None:
    """A four-hundred-name rule would truncate to `accounts 'a...` on every row
    and say nothing; `names` is what `config show` already calls that case."""
    text = render_account_list(rows())

    assert "names" in text
    assert "profile 'DEV_USERS'" in text


def test_the_table_shows_both_dates_and_dashes_the_absent_one() -> None:
    text = render_account_list(rows())

    assert "DB_PW_CHANGED" in text
    assert "RESET_AT" in text
    assert "2026-09-01" in text
    assert ABSENT in text


def test_matching_nothing_reads_as_an_answer_rather_than_an_empty_table() -> None:
    """§2's asymmetry: a predicate that exists and admits no accounts is a fact
    about today's estate, and an empty table would read as a failure to look."""
    assert render_account_list([]) == "no declared personal accounts on the selected targets"


def test_the_count_says_how_many_are_not_present() -> None:
    built = config()
    with_missing = [
        *rows(),
        Row(account="ghost", target=TARGET, rule=built.personal_accounts[0], state=None),
    ]

    assert "(1 not present)" in render_account_list(with_missing)


def test_the_summary_counts_what_exists_and_changes_nothing() -> None:
    summary = summarise(rows())

    assert summary.total == 2
    assert summary.ok == 2
    assert summary.changed == 0
    assert summary.unchanged == 2


# ------------------------------------- a target that could not be answered ---
#
# Both of these pin that a down target is not reported as `ACCOUNT_MISSING`,
# which would state a connectivity failure as a fact about an estate, with
# nothing in `results[]` to tell the two apart.


def unreachable() -> Row:
    from sopuli.output.document import Error

    return Row(
        account=ABSENT,
        target=TARGET,
        rule=None,
        state=None,
        unreachable=Error(message="ORA-12541: TNS:no listener", category="database"),
    )


def test_a_target_that_could_not_be_answered_is_error_not_account_missing() -> None:
    """A run that could not open a session knows nothing about any account there,
    including whether it exists, so `ACCOUNT_MISSING` would assert what it never
    learned."""
    entry = build_result(unreachable())

    assert entry["state"] == "ERROR"
    assert entry["state"] != "ACCOUNT_MISSING"


def test_the_failure_reaches_the_document_as_an_error_object() -> None:
    """A consumer branches on `error`, not on prose in a detail string."""
    entry = build_result(unreachable())

    assert entry["error"]["message"] == "ORA-12541: TNS:no listener"
    assert entry["error"]["category"] == "database"


def test_a_failed_target_is_counted_as_failed_rather_than_unchanged() -> None:
    """The summary used to report zero failures on a run that exited PARTIAL, so
    the exit code and the document disagreed."""
    summary = summarise([*rows(), unreachable()])

    assert summary.failed == 1
    assert summary.unchanged == 2
    assert summary.total == 3


def test_a_failed_target_is_not_counted_as_a_declared_account() -> None:
    text = render_account_list([*rows(), unreachable()])

    assert "2 declared accounts" in text
    assert "1 target could not be answered" in text
    assert "not present" not in text, "an unanswered target is not a missing account"


# ------------------------------------------------------ reading the journal ---


def test_the_reset_at_column_is_read_from_the_journal() -> None:
    """`reset_at` is on the model and in the schema, so something must populate
    it. Otherwise a documented column would be permanently `-`, even where a
    journal existed and held a record."""
    from sopuli.cli import _reset_at
    from sopuli.store import MemoryStore

    journal = MemoryStore()
    journal.write(
        "sopuli/personal-resets/appdb-dev-alpha/jdoe",
        {"account": "jdoe", "target": TARGET, "reset_at": "2026-09-17T09:14:22Z"},
        cas=None,
    )
    built = config(
        reset_records={"vault": "vault-dev", "prefix": "sopuli/personal-resets"},
        vaults={"vault-dev": {"type": "hashicorp", "addr": "https://v.example.com"}},
    )

    assert _reset_at(journal, built, TARGET, "jdoe") == "2026-09-17T09:14:22Z"


def test_a_journal_with_no_record_for_this_account_is_not_a_finding() -> None:
    """Nobody has reset them through this tool. That is not an absence worth a
    code -- unlike a journal that is not configured at all, which is W023."""
    from sopuli.cli import _reset_at
    from sopuli.store import MemoryStore

    built = config(
        reset_records={"vault": "vault-dev", "prefix": "sopuli/personal-resets"},
        vaults={"vault-dev": {"type": "hashicorp", "addr": "https://v.example.com"}},
    )

    assert _reset_at(MemoryStore(), built, TARGET, "jdoe") is None


def test_a_journal_that_cannot_be_read_does_not_fail_the_listing() -> None:
    """A listing verb that failed because a *metadata* store was unreachable
    would be refusing to describe an estate over its history -- the priority
    inversion UC-2 §3.4 rules out for the reset, and it applies at least as
    strongly to a read."""
    from sopuli.cli import _reset_at
    from sopuli.store import MemoryStore

    class Broken(MemoryStore):
        def read(self, path: str, *, version: int | None = None) -> Any:
            raise RuntimeError("the metadata store is down")

    built = config(
        reset_records={"vault": "vault-dev", "prefix": "sopuli/personal-resets"},
        vaults={"vault-dev": {"type": "hashicorp", "addr": "https://v.example.com"}},
    )

    assert _reset_at(Broken(), built, TARGET, "jdoe") is None


def test_no_journal_configured_reads_as_no_date_rather_than_an_error() -> None:
    from sopuli.cli import _reset_at

    assert _reset_at(None, config(), TARGET, "jdoe") is None

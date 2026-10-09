"""`sopuli account list` as a document and as a table (UC-2 §2).

Same arrangement as the other verbs: the shape here, the resolution in
:mod:`sopuli.account_list`.

**This verb mutates nothing and reads no password.** Every ``results[]`` entry is
``changed: false`` by construction, with the ``none`` action `creds status`
established for a read-only verb — nothing was done, and the enum's own word for
that is better than inventing an ``inventory`` kind that describes an absence.

**Three columns can be empty, and an empty one is never silently empty.** §2
applies `SOPULI-W021`'s rule to the pair of date columns: a documented column that
vanishes with nothing saying why is a hole in the contract. So each absence is
rendered ``-`` *and* carries a diagnostic saying which absence it is — the release
or the grant for the database's date (`SOPULI-W021`, already allocated), and no
journal configured for the record's (`SOPULI-W023`, allocated here because this is
the verb that raises it).

**Both dates are shown rather than folded into one number**, which is UC-2 §3.2's
decision and not a layout preference. They come off two clocks and answer two
questions, and their disagreement is information: on the unseen path a database
date later than the record's ``reset_at`` means somebody changed the password after
the tool delivered it, so the copy the person was told to fetch no longer works.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sopuli.account_list import ABSENT, ACCOUNT_MISSING, DECLARED, ERROR, Row
from sopuli.diagnostics import PASSWORD_CHANGE_DATE_UNKNOWN
from sopuli.output.document import Diagnostic, Error, Summary
from sopuli.output.palette import Role, paint, state_cell
from sopuli.output.table import Cell, Column, render_table

#: Column widths, in the sibling views' units.
_ACCOUNT = 24
_TARGET = 28
_DECLARED_BY = 26
_STATUS = 22


def build_result(
    row: Row, *, duration_ms: int | None = None, error: Error | None = None
) -> dict[str, Any]:
    """One ``results[]`` entry.

    ``changed`` is always ``False`` and the schema requires it anyway, which is
    worth stating rather than leaving to be noticed: this verb cannot mutate
    anything, so a consumer diffing the array gets a run of ``false`` by
    construction. Invariant 9's shape for a read-only verb, as `check` and
    `status` have it.

    ``declared_by`` is the field this verb exists for. An audit trail saying an
    account is declared, without saying *by what*, is the kind of record nobody
    can check afterwards -- and under a predicate it is the only place the answer
    appears at all, because the file does not contain it.
    """
    entry: dict[str, Any] = {
        "account": row.account,
        "target": row.target,
        "state": _state(row),
        "changed": False,
        "actions": [{"kind": "none", "applied": False, "detail": _detail(row)}],
        "declared_by": row.rule.label if row.rule is not None else None,
    }
    if row.state is not None:
        entry["account_status"] = row.state.status
    if row.reset_at is not None:
        entry["reset_at"] = row.reset_at
    if duration_ms is not None:
        entry["duration_ms"] = duration_ms
    reported = error if error is not None else row.unreachable
    if reported is not None:
        entry["error"] = reported.to_dict()
    warnings = _warnings(row)
    if warnings:
        entry["warnings"] = warnings
    return entry


def _warnings(row: Row) -> list[dict[str, Any]]:
    """What this row wants somebody to notice.

    ``SOPULI-W021`` is **per result**, not per run, and that is the difference
    between it and ``SOPULI-W023`` beside it: a missing journal is a property of
    the configuration and identical on every row, while whether the database will
    say when *this* account's password changed can differ between two accounts on
    one target. `creds status` carries it the same way and takes the reason from
    the same field, so the two commands cannot describe one absence differently.
    """
    found = [
        Diagnostic(level="warning", message=notice, account=row.account, target=row.target)
        for notice in row.notices
    ]
    unknown = None if row.state is None else row.state.password_changed_unknown
    if unknown:
        found.append(
            Diagnostic(
                level="warning",
                code=PASSWORD_CHANGE_DATE_UNKNOWN,
                message=unknown,
                account=row.account,
                target=row.target,
            )
        )
    return [entry.to_dict() for entry in found]


def _state(row: Row) -> str:
    """``ERROR`` for a target that could not be answered, and never the other two.

    A run that could not open a session knows nothing about any account on that
    target -- including whether it exists -- so reporting ``ACCOUNT_MISSING``
    would be asserting a fact it did not learn.
    """
    if row.failed:
        return ERROR
    return DECLARED if row.exists else ACCOUNT_MISSING


def _detail(row: Row) -> str:
    if row.failed:
        return "this target could not be answered, so nothing here was resolved"
    if row.rule is None:
        return "declared here, and the database has no such account"
    return f"declared by {row.rule.label}"


def summarise(rows: Sequence[Row]) -> Summary:
    """Counts for the run document.

    ``changed`` is zero by construction. ``ok`` counts the accounts that exist,
    ``unchanged`` every row this verb looked at and left alone, and ``failed``
    the targets it could not answer. Counting them as zero on a run that exits
    ``PARTIAL`` would make the exit code and the summary disagree.
    """
    return Summary(
        total=len(rows),
        ok=sum(1 for row in rows if row.exists),
        changed=0,
        unchanged=sum(1 for row in rows if not row.failed),
        failed=sum(1 for row in rows if row.failed),
    )


def render_account_list(rows: Sequence[Row]) -> str:
    """The table, or a sentence where the declaration matched nothing.

    **Matching nothing is a true answer and reads like one.** §2's asymmetry says
    a predicate that exists and admits no accounts is a fact about today's estate,
    not an error -- so this says so plainly rather than rendering an empty table,
    which would read as a failure to look.
    """
    if not rows:
        return "no declared personal accounts on the selected targets"

    lines = render_table(
        [
            Column("ACCOUNT", _ACCOUNT),
            Column("TARGET", _TARGET),
            Column("DECLARED BY", _DECLARED_BY),
            Column("STATUS", _STATUS),
            Column("DB_PW_CHANGED"),
            Column("RESET_AT"),
        ],
        [
            [
                row.account,
                row.target,
                _declared_by(row),
                _status(row),
                _or_dash(_changed_at(row)),
                _or_dash(row.reset_at),
            ]
            for row in rows
        ],
    )
    return "\n".join([*lines, "", _count(rows)])


def _declared_by(row: Row) -> str:
    """The short form for the column; the full label goes in the document.

    An enumerated rule's :attr:`~sopuli.config.model.PersonalAccountRule.label`
    lists every name it declares, which is right in a refusal naming two colliding
    rules and useless in a column -- a four-hundred-name rule would truncate to
    `accounts 'a...` on every row and say nothing. ``names`` is what `config show`
    already calls that case, so the two commands agree. A predicate's label is
    already short and is the answer to the question this column asks.
    """
    if row.rule is None:
        return ABSENT
    return "names" if not row.rule.is_predicate else row.rule.label


def _status(row: Row) -> Cell | str:
    """``ACCOUNT_STATUS`` as read, or the missing-account word.

    Coloured by the same :func:`~sopuli.output.palette.state_cell` every other
    view uses, so ``LOCKED`` looks the same here as it does after `account
    suspend` -- one vocabulary, one colour.
    """
    if row.failed:
        return state_cell(ERROR)
    if row.state is None:
        return state_cell(ACCOUNT_MISSING)
    return state_cell(row.state.status)


def _changed_at(row: Row) -> str | None:
    """The database's own password-change date, as a plain day.

    A day rather than a timestamp, because the question is "how long ago" and the
    two clocks disagree at the second anyway (§3.2). `creds status` prints the
    same column the same way.
    """
    if row.state is None or row.state.password_changed_at is None:
        return None
    return row.state.password_changed_at.date().isoformat()


def _or_dash(value: str | None) -> str:
    return value if value else ABSENT


def _count(rows: Sequence[Row]) -> str:
    missing = sum(1 for row in rows if not row.exists and not row.failed)
    failed = sum(1 for row in rows if row.failed)
    accounts = len({row.account.casefold() for row in rows if not row.failed})
    noun = "account" if accounts == 1 else "accounts"
    line = f"{accounts} declared {noun}, {len(rows) - failed} on the selected targets"
    if missing:
        line += f" ({missing} not present)"
    if failed:
        line += f"; {failed} target{'' if failed == 1 else 's'} could not be answered"
    return paint(line, Role.NOTABLE) if missing or failed else line

"""Every closed decision has a record in `docs/decisions/log.md` (#616).

Tier 0: reads Markdown, imports nothing of the tool.

The reasons for a decision used to live only in its GitHub issue. A bare `#454`
says nothing in an IDE, a fork or a source distribution, so each decision now
has a short record in the repository. This module checks that:

* each record is a `## <ID>` section with the five fields, in order:
  Decided, Question, Decision, Why, Rejected;
* each ID is used once, and is a `decided` row in the register;
* a record's issue is the register row's issue, where the row has one;
* every `decided` register row has a record, except ADRs, which are their own
  record;
* every link to `log.md#…` in the docs names a record that exists.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from repo_files import requires_repo
from test_decision_register import register

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
LOG = DOCS / "decisions" / "log.md"

FIELDS = ("Decided", "Question", "Decision", "Why", "Rejected")

#: `Where` values whose rows are recorded by an ADR rather than in the log.
ADR_ROWS = {"ADR", "ADR-006"}

#: Decided rows whose records are not written yet. TODO(#616): the backfill
#: empties this set, and then it goes.
NOT_YET_RECORDED = {
    *(f"D{n}" for n in range(1, 11)),
    *(f"C{n}" for n in (1, 2, 3, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17)),
    *(f"J{n}" for n in (1, 2, 4, 6, 7)),
    *(f"T{n}" for n in (1, 2, 5)),
}

RECORD = re.compile(r"^## (\S+)\s*$")
FIELD = re.compile(r"^- \*\*(\w+):\*\*\s*(.*)$")
DECIDED = re.compile(r"^(\d{4}-\d{2}-\d{2})(?:, (#\d+))?$")
LINK = re.compile(r"log\.md#([\w-]+)")


@dataclass(frozen=True)
class Record:
    id: str
    fields: tuple[str, ...]
    decided: str
    line: int


def records() -> list[Record]:
    """The log's records, in order. The text before the first one is ignored."""
    found: list[Record] = []
    current: tuple[str, int] | None = None
    fields: list[str] = []
    decided = ""

    def close() -> None:
        if current is not None:
            found.append(Record(current[0], tuple(fields), decided, current[1]))

    for number, line in enumerate(LOG.read_text(encoding="utf-8").splitlines(), 1):
        if line.startswith("## "):
            close()
            match = RECORD.match(line)
            assert match, f"log.md:{number}: a record heading is `## <ID>` and nothing else"
            current, fields, decided = (match.group(1), number), [], ""
        elif current is not None and (match := FIELD.match(line)):
            fields.append(match.group(1))
            if match.group(1) == "Decided":
                decided = match.group(2).strip()
    close()
    return found


def test_each_record_has_the_five_fields_in_order() -> None:
    requires_repo(LOG)
    found = records()
    assert found, "log.md has no records"
    for record in found:
        assert record.fields == FIELDS, (
            f"log.md:{record.line}: {record.id} has fields {list(record.fields)}; "
            f"a record has {list(FIELDS)}, each once, in that order"
        )
        assert DECIDED.match(record.decided), (
            f"log.md:{record.line}: {record.id}'s Decided is {record.decided!r}; "
            "write the date as YYYY-MM-DD, then `, #N` for the issue if there is one"
        )


def test_each_record_is_a_decided_register_row_and_names_its_issue() -> None:
    requires_repo(LOG)
    rows = {entry.id: entry for entry in register()}
    seen: set[str] = set()
    for record in records():
        assert record.id not in seen, f"log.md:{record.line}: {record.id} is recorded twice"
        seen.add(record.id)
        entry = rows.get(record.id)
        assert entry is not None, (
            f"log.md:{record.line}: {record.id} is not in the decision register in docs/README.md"
        )
        assert entry.status == "decided", (
            f"log.md:{record.line}: {record.id} is `{entry.status}` in the register; "
            "only a decided question has a record"
        )
        match = DECIDED.match(record.decided)
        issue = match.group(2) if match else None
        if entry.issue:
            assert issue == entry.issue, (
                f"log.md:{record.line}: {record.id} names {issue}; the register names {entry.issue}"
            )


def test_every_decided_row_has_a_record() -> None:
    requires_repo(LOG)
    recorded = {record.id for record in records()}
    missing = [
        entry.id
        for entry in register()
        if entry.status == "decided"
        and entry.where not in ADR_ROWS
        and entry.id not in recorded
        and entry.id not in NOT_YET_RECORDED
    ]
    assert not missing, (
        f"decided with no record in docs/decisions/log.md: {missing}. "
        "The pull request that closes a decision adds its record."
    )
    stale = sorted(NOT_YET_RECORDED & recorded)
    assert not stale, f"recorded, so remove from NOT_YET_RECORDED: {stale}"


def test_every_link_into_the_log_names_a_record() -> None:
    requires_repo(LOG)
    anchors = {record.id.lower() for record in records()}
    broken = []
    for path in sorted(DOCS.rglob("*.md")):
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), 1):
            for anchor in LINK.findall(line):
                if anchor not in anchors:
                    broken.append(f"{path.relative_to(ROOT).as_posix()}:{number}: #{anchor}")
    assert not broken, "links to a record log.md does not have:\n" + "\n".join(broken)

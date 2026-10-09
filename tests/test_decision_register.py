"""The decision register is the one place a decision's status is written.

Tier 0, except the last two tests, which ask GitHub and run weekly.

The register in `docs/README.md` is the authority for a decision's status. The
`decision` label, a prose list and code comments do not state it, because copies
disagree. Each document keeps its own table, because the table carries the
question and the reasoning, and its status marks must match the register. This
module checks that they agree:

* every row in a document's table has a register row, and the other way round;
* a question struck through (`~~…~~`) in the document is `decided` in the
  register, and only then;
* a `deferred` row says "defer" in the document's answer, and no other unstruck row does;
* `00-principles.md`'s status column says the same as the register;
* every ADR is in the register as `decided` and says `Status: **accepted**`.

Two more checks need the network, so they are skipped unless
`SOPULI_CHECK_ISSUES` is set, and `.github/workflows/pending-work.yml` sets it
weekly:

* an `open` row's issue is open, and a `decided` row's issue is closed;
* every open issue labelled `decision` has a row.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from github_issues import needs_github, open_issues, state
from repo_files import requires_repo

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
README = DOCS / "README.md"
HEADING = "## Decision register"

STATUSES = {"open", "decided", "deferred"}

#: The register's `Where` column, as the file holding that document's table.
TABLES = {
    "00": DOCS / "design" / "00-principles.md",
    "01": DOCS / "design" / "01-configuration.md",
    "02": DOCS / "design" / "02-oracle-privileges.md",
    "03": DOCS / "design" / "03-json-output.md",
    "04": DOCS / "design" / "04-testing.md",
    "UC-1": DOCS / "use-cases" / "uc-01-app-credential-sync.md",
    "UC-2": DOCS / "use-cases" / "uc-02-personal-account-passwords.md",
}

#: `Where` values that have no table to check against.
UNTABLED = {"ADR", "ADR-006", "—"}

#: A decision row in a document's table: `| C4 | question | answer |`, with the
#: ID possibly struck through.
ROW = re.compile(r"^\|\s*(?:~~)?([A-Z]\d+)(?:~~)?\s*\|(.*)\|\s*$")
STRUCK = re.compile(r"^~~.+~~")
ISSUE = re.compile(r"^(?:#\d+)?$")


@dataclass(frozen=True)
class Entry:
    id: str
    where: str
    question: str
    status: str
    answer: str
    issue: str


@dataclass(frozen=True)
class TableRow:
    id: str
    cells: tuple[str, ...]
    line: int

    @property
    def question(self) -> str:
        return self.cells[0]

    @property
    def answer(self) -> str:
        return self.cells[1] if len(self.cells) > 1 else ""


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def register() -> list[Entry]:
    """The register's rows, in order."""
    text = README.read_text(encoding="utf-8")
    start = text.index(HEADING + "\n")
    end = text.find("\n## ", start + len(HEADING))
    section = text[start : end if end != -1 else len(text)]
    entries = []
    for line in section.splitlines():
        if not line.startswith("| ") or line.startswith("| ID ") or line.startswith("|---"):
            continue
        cells = _cells(line)
        assert len(cells) == 6, f"a register row has six cells: {line}"
        entries.append(Entry(*cells))
    return entries


def table(path: Path) -> list[TableRow]:
    """The decision rows of one document's table."""
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if match := ROW.match(line):
            rows.append(TableRow(match.group(1), tuple(_cells(match.group(2))), number))
    return rows


def _by_where(where: str) -> dict[str, Entry]:
    return {entry.id: entry for entry in register() if entry.where == where}


# ------------------------------------------------------------- the register ---


def test_the_register_is_well_formed() -> None:
    requires_repo(README)
    entries = register()
    assert entries, f"{README} has no {HEADING!r} table"

    problems = []
    # Global, not per document: the docs and the code refer to a decision by
    # its bare ID, so `D1` must mean one row.
    seen: set[str] = set()
    for entry in entries:
        if entry.id != "—" and entry.id in seen:
            problems.append(f"{entry.id} is listed twice")
        seen.add(entry.id)
        if entry.status not in STATUSES:
            problems.append(f"{entry.id}: status {entry.status!r} is not one of {sorted(STATUSES)}")
        if entry.where not in TABLES and entry.where not in UNTABLED:
            problems.append(f"{entry.id}: unknown Where {entry.where!r}")
        if not ISSUE.match(entry.issue):
            problems.append(f"{entry.id}: issue {entry.issue!r} is not one `#N`")
        if entry.id == "—" and not entry.issue:
            problems.append(f"a row with no ID names no issue: {entry.question}")

    assert not problems, "\n".join(problems)


# ------------------------------------------------------ the documents' tables ---


@pytest.mark.parametrize("where", sorted(TABLES))
def test_each_document_s_table_and_the_register_list_the_same_ids(where: str) -> None:
    path = TABLES[where]
    requires_repo(path)
    in_table = [row.id for row in table(path)]
    in_register = list(_by_where(where))

    assert sorted(in_table) == sorted(in_register), (
        f"{path.relative_to(ROOT).as_posix()} and the register disagree on which "
        f"decisions {where} raises. Only in the document: "
        f"{sorted(set(in_table) - set(in_register))}; only in the register: "
        f"{sorted(set(in_register) - set(in_table))}"
    )


@pytest.mark.parametrize("where", sorted(set(TABLES) - {"00"}))
def test_a_struck_question_is_decided_and_only_then(where: str) -> None:
    path = TABLES[where]
    requires_repo(path)
    entries = _by_where(where)
    wrong = []
    for row in table(path):
        entry = entries.get(row.id)
        if entry is None:
            continue
        struck = bool(STRUCK.match(row.question))
        if struck != (entry.status == "decided"):
            wrong.append(
                f"{path.name}:{row.line}: {row.id} is {entry.status} in the register, "
                f"and its question is {'struck' if struck else 'not struck'}"
            )

    assert not wrong, "\n".join(wrong)


@pytest.mark.parametrize("where", sorted(set(TABLES) - {"00"}))
def test_a_deferred_row_says_so_and_only_a_deferred_row(where: str) -> None:
    path = TABLES[where]
    requires_repo(path)
    entries = _by_where(where)
    wrong = []
    for row in table(path):
        entry = entries.get(row.id)
        if entry is None or STRUCK.match(row.question):
            continue
        says = "defer" in row.answer.lower()
        if says != (entry.status == "deferred"):
            wrong.append(
                f"{path.name}:{row.line}: {row.id} is {entry.status} in the register, and "
                f"its answer {'says' if says else 'does not say'} deferred"
            )

    assert not wrong, "\n".join(wrong)


def test_the_principles_status_column_matches() -> None:
    """`00-principles.md` writes a status in its last column rather than striking
    the question."""
    path = TABLES["00"]
    requires_repo(path)
    entries = _by_where("00")
    wrong = [
        f"{row.id}: {row.cells[-1]!r} there, {entries[row.id].status!r} in the register"
        for row in table(path)
        if row.id in entries and row.cells[-1] != entries[row.id].status
    ]

    assert not wrong, "\n".join(wrong)


# ------------------------------------------------------------------- the ADRs ---


def test_every_adr_is_in_the_register_and_accepted() -> None:
    requires_repo(DOCS / "decisions")
    files = sorted((DOCS / "decisions").glob("adr-*.md"))
    listed = {entry.id: entry for entry in register() if entry.where == "ADR"}
    problems = []

    for path in files:
        adr = "ADR-" + path.name.split("-")[1]
        entry = listed.pop(adr, None)
        if entry is None:
            problems.append(f"{adr} ({path.name}) is not in the register")
            continue
        if entry.status != "decided":
            problems.append(f"{adr}: the register says {entry.status}, not decided")
        if "Status: **accepted**" not in path.read_text(encoding="utf-8"):
            problems.append(f"{adr}: {path.name} does not say `Status: **accepted**`")
    problems += [f"{adr} is in the register and has no file" for adr in listed]

    assert not problems, "\n".join(problems)


# --------------------------------------------------- the checker still checks ---


def test_the_row_pattern_reads_both_forms() -> None:
    """The tests above passing proves nothing if the pattern stopped matching."""
    plain = ROW.match("| C4 | Per-account overrides | the `overrides:` mechanism |")
    struck = ROW.match("| ~~P2~~ | ~~Grant `SELECT ON SYS.USER$`?~~ | **decided: no** |")

    assert plain is not None
    assert plain.group(1) == "C4"
    assert struck is not None
    assert struck.group(1) == "P2"
    assert STRUCK.match(_cells(struck.group(2))[0])


# -------------------------------------------------------- needs the network ---


def _issue(entry: Entry) -> int | None:
    return int(entry.issue.lstrip("#")) if entry.issue else None


@needs_github
def test_each_row_s_status_matches_its_issue() -> None:
    """A `deferred` row may name an issue in either state: "not now" is an answer,
    and whether its issue stays open is a matter of taste."""
    wrong = []
    for entry in register():
        issue = _issue(entry)
        if issue is None or entry.status == "deferred":
            continue
        expected = "open" if entry.status == "open" else "closed"
        if state(issue) != expected:
            wrong.append(f"{entry.id} is {entry.status}, and #{issue} is {state(issue)}")

    assert not wrong, (
        "the register and the issues disagree. Update the register row and the "
        "document's table together:\n" + "\n".join(wrong)
    )


@needs_github
def test_every_open_decision_issue_has_a_row() -> None:
    """The `decision` label means a row in the register. An issue that is not a
    design decision does not carry it."""
    listed = {issue for entry in register() if (issue := _issue(entry)) is not None}
    missing = sorted(open_issues("decision") - listed)

    assert not missing, (
        "these open `decision` issues have no row in the register. Add one, or "
        "remove the label if the issue is not a decision: "
        + ", ".join(f"#{issue}" for issue in missing)
    )

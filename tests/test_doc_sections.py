"""Every section reference in the docs and the code resolves to a heading.

Tier 0: reads Markdown and Python source, imports nothing of the tool.

Sections get renumbered and text moves between them, and a reference into the
old place keeps reading as correct. This finds the references a heading no
longer answers. It cannot tell that a reference which resolves points at the
wrong text.

**What a reference is.** A `§` followed by a section number, such as `§3a` or
`§10.9`, and `Pn` for a principle. The document it points into is:

* the one named right before it: `01-configuration.md` §3a, a link to that file
  followed by `§3a`, `UC-2 §6.1`, or a file name followed by `section 2` (the
  ASCII spelling used in hints);
* the one named right after it: `§3a of 01-configuration.md`;
* otherwise, the last document named that way earlier in the same paragraph, so
  that `01-configuration.md` §1, §3a and §6 needs one name;
* otherwise, the document the reference is written in, for a file under `docs/`.

A reference whose document is not a file in `docs/` (a `.sql` script's own
sections, say) is not checked. Nor is a `§` in a Python file with no document
named before it in the same paragraph, because a docstring has no document of
its own to fall back to.

The rule for a writer follows from this: name the document at the first
reference to it in a paragraph, and name your own document again if a paragraph
has referred to another one first.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from repo_files import requires_repo

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

#: Where references are looked for. `CHANGELOG.md` is left out: it is history,
#: built from commit subjects, and a section renumbered since is not an error in
#: it.
SCANNED = ("docs", "src", "tests", "test", "examples")
ROOT_FILES = ("README.md", "CLAUDE.md", "CONTRIBUTING.md")

FENCE = re.compile(r"^\s*(```|~~~)")
SECTION = r"\d+[a-z]?(?:\.\d+[a-z]?)*"
HEADING = re.compile(rf"^#{{1,6}}\s+(?:§\s*)?(P?{SECTION})\b")

#: A line that ends a paragraph on its own: a table row or a heading.
STANDALONE = re.compile(r"^\s*(\||#)")

REFERENCE = re.compile(
    rf"(?P<doc>[\w-]+\.(?:md|sql|py))`?\]?(?:\([^)\s]*\))?\s*\(?\s*"
    rf"(?:section\s+(?P<word>{SECTION})|§§?\s*(?P<after_doc>{SECTION}))"
    rf"|(?P<uc>UC-\d+[a-z]?)(?:'s)?\s*§§?\s*(?P<after_uc>{SECTION})"
    rf"|§§?\s*(?P<bare>{SECTION})(?:\s+of\s+(?:the\s+)?`?(?P<trailing>[\w-]+\.md))?"
)

#: The far end of a range, `§1–2` or `§§3–12`, read from where a reference ends.
RANGE_END = re.compile(rf"\s*[–-]\s*§?\s*({SECTION})\b")

PRINCIPLE = re.compile(r"\bP(\d+)\b")

#: A decision row in a register table, such as `| P6 |` or `| ~~P7~~ |`.
DECISION_ROW = re.compile(r"^\|\s*(?:~~)?(P\d+)(?:~~)?\s*\|", re.MULTILINE)


@dataclass(frozen=True)
class Unresolved:
    file: str
    line: int
    reference: str
    problem: str

    def __str__(self) -> str:
        return f"{self.file}:{self.line}: {self.reference!r} {self.problem}"


def _headings(path: Path) -> set[str]:
    found: set[str] = set()
    inside = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if FENCE.match(line):
            inside = not inside
        elif not inside and (match := HEADING.match(line)):
            found.add(match.group(1))
    return found


def _documents() -> dict[str, list[Path]]:
    """The documents under `docs/`, by file name. Two share a name (`README.md`),
    so a name maps to every document that has it."""
    by_name: dict[str, list[Path]] = {}
    for path in sorted(DOCS.rglob("*.md")):
        by_name.setdefault(path.name, []).append(path)
    return by_name


def _sections(start: str, end: str | None) -> list[str]:
    """The sections a reference names. A range of whole numbers names every
    section in it; any other range names its two ends."""
    if end is None:
        return [start]
    if start.isdigit() and end.isdigit():
        return [str(number) for number in range(int(start), int(end) + 1)]
    return [start, end]


def _use_case(label: str, documents: dict[str, list[Path]]) -> str | None:
    """`UC-2` is `uc-02-*.md`. `UC-1b` and the later use cases have no document."""
    number = label.removeprefix("UC-")
    if not number.isdigit():
        return None
    prefix = f"uc-{int(number):02d}-"
    return next((name for name in documents if name.startswith(prefix)), None)


def _paragraphs(text: str) -> Iterator[tuple[int, str]]:
    """(first line number, text) for each paragraph outside fenced blocks."""
    lines: list[str] = []
    start = 0
    inside = False
    for number, line in enumerate(text.splitlines(), 1):
        if FENCE.match(line):
            inside = not inside
            if lines:
                yield start, " ".join(lines)
                lines = []
            continue
        if inside:
            continue
        if not line.strip() or STANDALONE.match(line):
            if lines:
                yield start, " ".join(lines)
                lines = []
            if line.strip():
                yield number, line
            continue
        if not lines:
            start = number
        lines.append(line.strip())
    if lines:
        yield start, " ".join(lines)


def _scanned_files() -> list[Path]:
    files = [ROOT / name for name in ROOT_FILES]
    for directory in SCANNED:
        files += sorted((ROOT / directory).rglob("*.md"))
        files += sorted((ROOT / directory).rglob("*.py"))
    return [path for path in files if path.is_file()]


def _unresolved_sections() -> list[Unresolved]:
    documents = _documents()
    headings = {path: _headings(path) for paths in documents.values() for path in paths}
    found: list[Unresolved] = []

    for path in _scanned_files():
        relative = path.relative_to(ROOT).as_posix()
        for line, paragraph in _paragraphs(path.read_text(encoding="utf-8")):
            # The document a bare `§` points into. Keyed by path, so that each
            # document checks its own references whatever its name.
            current: Path | None = path if path in headings else None
            for match in REFERENCE.finditer(paragraph):
                name = match.group("doc") or match.group("trailing")
                if match.group("uc"):
                    name = _use_case(match.group("uc"), documents)
                    if name is None:
                        found.append(Unresolved(relative, line, match.group(0), "has no document"))
                        continue
                if name is not None:
                    candidates = documents.get(name, [])
                    if len(candidates) > 1:
                        problem = f"is ambiguous: {len(candidates)} documents are named {name}"
                        found.append(Unresolved(relative, line, match.group(0), problem))
                        current = None
                        continue
                    current = candidates[0] if candidates else None
                if current is None:
                    continue

                start = (
                    match.group("word")
                    or match.group("after_doc")
                    or match.group("after_uc")
                    or match.group("bare")
                )
                end = RANGE_END.match(paragraph, match.end())
                reference = match.group(0) + (end.group(0) if end else "")
                for section in _sections(start.rstrip("."), end and end.group(1).rstrip(".")):
                    if section not in headings[current]:
                        where = current.relative_to(ROOT).as_posix()
                        problem = f"has no heading {section} in {where}"
                        found.append(Unresolved(relative, line, reference, problem))
    return found


def test_every_section_reference_resolves() -> None:
    requires_repo(DOCS)
    unresolved = _unresolved_sections()

    assert not unresolved, "\n".join(str(each) for each in unresolved)


def test_every_principle_reference_is_a_principle_or_a_decision() -> None:
    """`P1` to `P5` are the principles in `00-principles.md`. `P6` and up are
    open-decision rows in a register table, so a `Pn` must be one of the two."""
    requires_repo(DOCS)
    known = _headings(DOCS / "design" / "00-principles.md")
    for path in DOCS.rglob("*.md"):
        known |= set(DECISION_ROW.findall(path.read_text(encoding="utf-8")))

    unknown = sorted(
        f"{path.relative_to(ROOT).as_posix()}: P{number}"
        for path in _scanned_files()
        for number in set(PRINCIPLE.findall(path.read_text(encoding="utf-8")))
        if f"P{number}" not in known
    )
    assert not unknown


@pytest.mark.parametrize(
    ("text", "sections"),
    [("§1–2 here", ["1", "2"]), ("§§3–5 here", ["3", "4", "5"]), ("§3a-4 here", ["3a", "4"])],
)
def test_a_range_names_every_section_in_it(text: str, sections: list[str]) -> None:
    match = REFERENCE.search(text)
    assert match is not None
    end = RANGE_END.match(text, match.end())
    assert end is not None

    assert _sections(match.group("bare"), end.group(1)) == sections


def test_the_checker_finds_a_broken_reference() -> None:
    """The scan above passing proves nothing if the pattern stopped matching."""
    documents = _documents()
    # Assembled, so that this file's own scan does not report it.
    missing = "§" + "99"
    paragraph = f"See `01-configuration.md` §3a, {missing} and UC-2 §6.1."
    matches = [m.group(0) for m in REFERENCE.finditer(paragraph)]

    assert matches == ["01-configuration.md` §3a", missing, "UC-2 §6.1"]
    assert "99" not in _headings(documents["01-configuration.md"][0])
    assert _use_case("UC-2", documents) == "uc-02-personal-account-passwords.md"
    assert _use_case("UC-1b", documents) is None

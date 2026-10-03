"""Work that waits on an issue is marked, and the mark goes when the issue closes (#614).

Tier 0, except the last test, which needs the network and runs on a schedule.

Prose that waits on an issue stays in place after the issue closes. "Until #N
lands" reads as true for as long as nobody rereads it, and the pull request that
closes #N rarely touches the files that mention it. The drift audit in #627
found 59 such references to issues that had already closed.

**The marker.** Pending work names its issue in one fixed spelling:

* `TODO(#N)` in code: Python, SQL and the workflow files, comments and
  docstrings alike;
* `(open: #N)` in Markdown. Several issues share one marker as
  `(open: #N, #M)`.

**What this module checks.**

* No issue is referred to in the future tense without the marker: "until #N
  lands", "once #N lands", "#N is open", "#N will", "#N has yet to", "blocked on
  #N". Write what is true now and put the marker beside it, or, if the issue has
  closed, write what it did.
* Each medium uses its own spelling, and a `TODO` in code always names an issue.
* No marker names a closed issue. This one asks GitHub, so it is skipped unless
  `SOPULI_CHECK_ISSUES` is set. The `pending-work` workflow sets it weekly; it
  is kept out of pull request CI because it needs the network.

History is not pending work. "This said X until #N" describes the past and is not
matched here.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from github_issues import needs_github, state
from repo_files import requires_repo

ROOT = Path(__file__).resolve().parents[1]

#: Where references are looked for. `CHANGELOG.md` is left out: it is history,
#: built from commit subjects.
SCANNED = ("docs", "src", "tests", "test", "sql", "examples", ".github")
ROOT_FILES = ("README.md", "CLAUDE.md", "CONTRIBUTING.md")
SUFFIXES = {".md", ".py", ".sql", ".yml", ".yaml"}

#: One issue, or a list of them: `#441`, `#444-#447`, `#441 or #444`.
ISSUES = r"#\d+(?:\s*(?:[-–,]|\bor\b|\band\b)\s*#\d+)*"

#: The phrases that put an issue in the future tense. `\)?` admits the
#: parenthesised form, `Q4 (#88) is open`.
FUTURE = re.compile(
    rf"\b(?:until|once|when|after)\s+{ISSUES}\s+"
    rf"(?:lands?|merges?|ships?|decides?|classif(?:y|ies)"
    rf"|is\s+(?:merged|done|built|decided|resolved|fixed|closed))\b"
    rf"|{ISSUES}\)?\s+(?:is|are|remains?|stays?)\s+(?:still\s+)?open\b"
    rf"|{ISSUES}\)?\s+will\b"
    rf"|{ISSUES}\)?\s+(?:has|have)\s+yet\s+to\b"
    rf"|\b(?:blocked|waiting|waits?)\s+(?:on|for)\s+{ISSUES}",
    re.IGNORECASE,
)

CODE_MARKER = re.compile(r"\bTODO\(#(\d+)\)")
DOCS_MARKER = re.compile(r"\(open: (#\d+(?:, #\d+)*)\)")

#: A `TODO` in code that does not name exactly one issue. `TODO(#N)`, with a
#: letter, is the spelling being described rather than a marker.
LOOSE_TODO = re.compile(r"\bTODO\b(?!\(#(?:\d+|N)\))")
#: The other medium's spelling, with a real issue number.
CODE_SPELLING = re.compile(r"\bTODO\(#\d")
DOCS_SPELLING = re.compile(r"\(open:\s*#\d")
#: An `(open: ...)` in Markdown that `DOCS_MARKER` would not read, such as
#: `(open: #445 and #447)`: the weekly check would never see its issues.
#: `(open: #N)` and `(open: #N, #M)`, with letters, describe the spelling.
LOOSE_OPEN = re.compile(r"\(open:(?! (?:#\d+(?:, #\d+)*|#N(?:, #M)?)\))")

FENCE = re.compile(r"^\s*(```|~~~)")

#: The comment leader on a continuation line, so that a phrase wrapped across
#: two comment lines still reads as one phrase. `#` only when a space or the end
#: of the line follows, so that `#512` at the start of a line is kept.
LEADER = re.compile(r"^\s*(?:#:?(?=\s|$)|--(?=\s|$)|>|\*(?=\s))?\s*")


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    text: str

    def __str__(self) -> str:
        return f"{self.file}:{self.line}: {self.text!r}"


def _scanned_files() -> list[Path]:
    files = [ROOT / name for name in ROOT_FILES]
    for directory in SCANNED:
        files += sorted(path for path in (ROOT / directory).rglob("*") if path.suffix in SUFFIXES)
    # This module spells out both markers and the phrases it rejects.
    own = Path(__file__).resolve()
    return [path for path in files if path.is_file() and path.resolve() != own]


def _is_docs(path: Path) -> bool:
    return path.suffix == ".md"


def _lines(path: Path) -> Iterator[tuple[int, str]]:
    """Each line with its number. Fenced blocks in Markdown are left out: they
    show code and commands, not prose about the project's state."""
    inside = False
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if _is_docs(path) and FENCE.match(line):
            inside = not inside
            continue
        if not inside:
            yield number, line


def _future_tense(path: Path) -> list[Finding]:
    """The future-tense phrases in ``path``, read across line breaks.

    The text is joined into one string with each line's comment leader removed,
    and every match is reported at the line it starts on.
    """
    starts: list[tuple[int, int]] = []
    pieces: list[str] = []
    offset = 0
    for number, line in _lines(path):
        piece = LEADER.sub("", line) + " "
        starts.append((offset, number))
        pieces.append(piece)
        offset += len(piece)
    text = "".join(pieces)

    found = []
    for match in FUTURE.finditer(text):
        first = max(number for start, number in starts if start <= match.start())
        found.append(Finding(_relative(path), first, match.group(0)))
    return found


def _relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _misspelled(path: Path) -> list[Finding]:
    found = []
    for number, line in _lines(path):
        if _is_docs(path):
            wrong = CODE_SPELLING.search(line) or LOOSE_OPEN.search(line)
        else:
            wrong = DOCS_SPELLING.search(line) or LOOSE_TODO.search(line)
        if wrong:
            found.append(Finding(_relative(path), number, line.strip()))
    return found


def markers() -> dict[int, list[str]]:
    """Every marked issue number, and the places that mark it."""
    found: dict[int, list[str]] = {}
    for path in _scanned_files():
        for number, line in _lines(path):
            if _is_docs(path):
                issues = [
                    int(each.lstrip("#"))
                    for match in DOCS_MARKER.finditer(line)
                    for each in match.group(1).split(", ")
                ]
            else:
                issues = [int(each) for each in CODE_MARKER.findall(line)]
            for issue in issues:
                found.setdefault(issue, []).append(f"{_relative(path)}:{number}")
    return found


# ------------------------------------------------------------------ tier 0 ---


def test_no_issue_is_referred_to_in_the_future_tense() -> None:
    requires_repo(ROOT / "docs")
    found = [each for path in _scanned_files() for each in _future_tense(path)]

    assert not found, (
        "these refer to an issue in the future tense. Say what is true now and mark "
        "pending work `TODO(#N)` in code or `(open: #N)` in Markdown; if the issue "
        "has closed, say what it did:\n" + "\n".join(str(each) for each in found)
    )


def test_each_medium_uses_its_own_marker() -> None:
    requires_repo(ROOT / "docs")
    found = [each for path in _scanned_files() for each in _misspelled(path)]

    assert not found, (
        "a marker is `TODO(#N)` in code and `(open: #N)` in Markdown, and a TODO "
        "names its issue:\n" + "\n".join(str(each) for each in found)
    )


ISSUE = "#512"


@pytest.mark.parametrize(
    "text",
    [
        f"one lock where there should be two, once {ISSUE} lands.",
        f"refused until {ISSUE}-#447 land.",
        f"Q4 ({ISSUE}) is open with a leaning of no.",
        f"{ISSUE} has yet to decide whether",
        f"what {ISSUE} will accept",
        f"still blocked on {ISSUE} and #453",
    ],
)
def test_the_checker_finds_a_future_tense_reference(text: str) -> None:
    """The scan above passing proves nothing if the pattern stopped matching."""
    assert FUTURE.search(text)


@pytest.mark.parametrize(
    "text",
    [
        f"This said X until {ISSUE};",
        f"It was three rows until {ISSUE}.",
        f"until {ISSUE} built it",
        f"not built (open: {ISSUE})",
    ],
)
def test_history_is_not_pending_work(text: str) -> None:
    assert not FUTURE.search(text)


def test_a_phrase_wrapped_across_comment_lines_is_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "module.py"
    source.write_text(f"# one lock, once\n# {ISSUE} lands, where\n", encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)

    found = _future_tense(source)

    assert [(each.line, each.text) for each in found] == [(1, f"once {ISSUE} lands")]


@pytest.mark.parametrize(
    ("name", "line", "wrong"),
    [
        ("a.md", "Not built TODO(#445).", True),
        ("a.md", "The marker is `TODO(#N)` in code.", False),
        ("a.md", "Not built (open: #445, #447).", False),
        ("a.md", "The marker is `(open: #N, #M)`.", False),
        ("a.md", "Not built (open: #445 and #447).", True),
        ("a.md", "Not built (open: #445,#447).", True),
        ("a.md", "Not built (open:#445).", True),
        ("a.md", "Not built (open: 445).", True),
        ("b.py", "# Not built (open: #445).", True),
        ("b.py", "# TODO: map the rest", True),
        ("b.py", "# TODO(#4 follow-up): map the rest", True),
        ("b.py", "# TODO(#445): map the rest", False),
    ],
)
def test_a_marker_in_the_wrong_spelling_is_found(
    name: str, line: str, wrong: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / name
    source.write_text(line + "\n", encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)

    assert bool(_misspelled(source)) is wrong


def test_both_spellings_are_collected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text("Not built (open: #445, #446).\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "b.py").write_text("x = 1  # TODO(#447): y\n", encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)

    assert markers() == {445: ["docs/a.md:1"], 446: ["docs/a.md:1"], 447: ["src/b.py:1"]}


# --------------------------------------------------------- needs the network ---


@needs_github
def test_no_marker_names_a_closed_issue() -> None:
    """Run weekly by `.github/workflows/pending-work.yml`.

    A pull request number counts as an issue here, as it does on GitHub, so a
    marker naming a merged pull request is reported too.
    """
    marked = markers()
    closed = {issue: places for issue, places in marked.items() if state(issue) != "open"}

    assert not closed, (
        "these markers name a closed issue. Say what the issue did, and remove the "
        "marker:\n"
        + "\n".join(f"#{issue}: {', '.join(places)}" for issue, places in sorted(closed.items()))
    )

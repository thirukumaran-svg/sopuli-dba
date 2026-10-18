"""The `SOPULI-` codes are one series each, with no number used twice.

Tier 0: reads `src/` and `docs/design/03-json-output.md`, and opens no socket.

J3 (`03-json-output.md` §3) makes the warning codes one flat series,
`SOPULI-W001` upwards, and the tool's own error codes another, from
`SOPULI-20001`. A pull request takes the next free number. Two pull requests
written at the same time often take the same one, and nothing at merge time
says so: the second constant shadows nothing, and a dict literal with a repeated
key keeps the last value without a word. So this checks, for each series:

* no two constants in `src/` hold one code;
* the numbers run from the first with no gap;
* the document's table has each code once, and the same codes as `src/`;
* every code written anywhere in `src/` is in the table;
* the highest number is the one recorded, so a code is retired and never deleted.

It also checks J3's rule itself: every warning built in `src/` has a code.

The pull request that merges second then fails on its rebase, and takes the next
free number before it merges.

It is in `ci.yml`'s `docs` job as well as the main lanes, because
`03-json-output.md` is on the prose list: a pull request that changes only the
table would otherwise run no test that reads it.
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from pathlib import Path

import pytest

from repo_files import requires_repo
from sopuli.diagnostics import WARNINGS

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "sopuli"
DOC = ROOT / "docs" / "design" / "03-json-output.md"

#: Each series: its pattern, the shorthand that continues it (`SOPULI-W031/W032`),
#: its first number, and the heading of its table. `(?!\d)` keeps a code from
#: matching inside a longer number.
SERIES = {
    "warning": (
        re.compile(r"SOPULI-W(\d{3})(?!\d)"),
        re.compile(r"/W(\d{3})(?!\d)"),
        1,
        "### Diagnostic codes",
    ),
    "error": (
        re.compile(r"SOPULI-(2\d{4})(?!\d)"),
        re.compile(r"/(2\d{4})(?!\d)"),
        20001,
        "### Error codes",
    ),
}

#: What each series' shorthand leaves out: `SOPULI-W031/W032` is `SOPULI-W` + `032`.
PREFIX = {"warning": "SOPULI-W", "error": "SOPULI-"}

#: The highest number given so far in each series. A pull request that adds a
#: code raises it here. A number is never reused, so deleting the highest row and
#: its constant must fail, and without this the other checks would still pass.
HIGHEST = {"warning": 53, "error": 20006}


def _constants(pattern: re.Pattern[str]) -> dict[str, list[str]]:
    """Each code assigned to a name in `src/`, and every name it is assigned to.

    Assignments only, so an import that re-exports a code, as `diagnostics.py`
    does for `SOPULI-W004`, is not counted as a second constant.
    """
    found: dict[str, list[str]] = defaultdict(list)
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            else:
                continue
            if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
                continue
            if not pattern.fullmatch(value.value):
                continue
            for target in targets:
                if isinstance(target, ast.Name):
                    where = f"{path.relative_to(ROOT).as_posix()}:{node.lineno}"
                    found[value.value].append(f"{target.id} ({where})")
    return found


def _written(pattern: re.Pattern[str], shorthand: re.Pattern[str], prefix: str) -> dict[str, str]:
    """Every code written anywhere in `src/`, with the first place it appears.

    Shorthand counts: `SOPULI-W031/W032` writes two codes, and the second is as
    visible to a reader as the first. ``prefix`` is what the shorthand leaves out,
    such as ``SOPULI-W``.
    """
    found: dict[str, str] = {}
    for path in sorted(SRC.rglob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            where = f"{path.relative_to(ROOT).as_posix()}:{number}"
            for match in pattern.finditer(line):
                found.setdefault(match.group(0), where)
                end = match.end()
                while (more := shorthand.match(line, end)) is not None:
                    found.setdefault(prefix + more.group(1), where)
                    end = more.end()
    return found


def _table(heading: str, pattern: re.Pattern[str]) -> list[str]:
    """The codes in the first column of the table under ``heading``, in order."""
    requires_repo(DOC)
    lines = DOC.read_text(encoding="utf-8").splitlines()
    assert heading in lines, (
        f"no {heading!r} heading in {DOC.relative_to(ROOT).as_posix()}; if it was "
        "renamed, rename it in SERIES here too"
    )
    start = lines.index(heading)
    codes = []
    for line in lines[start + 1 :]:
        if line.startswith("#"):
            break
        cell = line.split("|")[1].strip() if line.startswith("|") else ""
        match = pattern.fullmatch(cell.strip("`"))
        if match:
            codes.append(match.group(0))
    return codes


def _number(code: str, pattern: re.Pattern[str]) -> int:
    match = pattern.fullmatch(code)
    assert match is not None, code
    return int(match.group(1))


@pytest.mark.parametrize("series", sorted(SERIES))
def test_no_two_constants_hold_one_code(series: str) -> None:
    pattern, _, _, _ = SERIES[series]
    shared = {code: names for code, names in _constants(pattern).items() if len(names) > 1}
    assert not shared, (
        "two constants hold one code; the pull request that merged second takes the "
        f"next free number: {shared}"
    )


@pytest.mark.parametrize("series", sorted(SERIES))
def test_the_numbers_have_no_gap(series: str) -> None:
    pattern, _, first, heading = SERIES[series]
    numbers = sorted(_number(code, pattern) for code in _table(heading, pattern))
    assert numbers == list(range(first, first + len(numbers))), numbers


@pytest.mark.parametrize("series", sorted(SERIES))
def test_the_highest_number_is_the_one_recorded(series: str) -> None:
    """A code is never deleted, only retired, so the highest number never falls.

    A pull request that adds a code raises :data:`HIGHEST`. One that deletes the
    highest row and its constant, instead of marking it retired, fails here.
    """
    pattern, _, _, heading = SERIES[series]
    highest = max(_number(code, pattern) for code in _table(heading, pattern))
    assert highest == HIGHEST[series], (
        f"the highest {series} code is {highest}, and HIGHEST records {HIGHEST[series]}. "
        "Raise HIGHEST when you add a code; a code is retired, never deleted"
    )


@pytest.mark.parametrize("series", sorted(SERIES))
def test_the_table_lists_each_code_once(series: str) -> None:
    pattern, _, _, heading = SERIES[series]
    codes = _table(heading, pattern)
    repeated = sorted({code for code in codes if codes.count(code) > 1})
    assert not repeated, f"rows repeated under {heading!r}: {repeated}"


@pytest.mark.parametrize("series", sorted(SERIES))
def test_the_table_and_the_source_hold_the_same_codes(series: str) -> None:
    pattern, _, _, heading = SERIES[series]
    table = set(_table(heading, pattern))
    defined = set(_constants(pattern))
    assert table - defined == set(), f"in the table, with no constant in src/: {table - defined}"
    assert defined - table == set(), f"a constant in src/, not in the table: {defined - table}"


@pytest.mark.parametrize("series", sorted(SERIES))
def test_every_code_in_the_source_is_in_the_table(series: str) -> None:
    """A code in a message or a comment is as visible to a reader as a constant."""
    pattern, shorthand, _, heading = SERIES[series]
    table = set(_table(heading, pattern))
    written = _written(pattern, shorthand, PREFIX[series])
    unknown = {code: where for code, where in written.items() if code not in table}
    assert not unknown, f"codes in src/ that the table does not have: {unknown}"


def test_shorthand_is_read_as_two_codes() -> None:
    """`SOPULI-W031/W032` names W032 too, so a renumbering that misses it fails."""
    pattern, shorthand, _, _ = SERIES["warning"]
    assert {"SOPULI-W031", "SOPULI-W032"} <= set(_written(pattern, shorthand, PREFIX["warning"]))


def test_a_code_does_not_match_inside_a_longer_number() -> None:
    pattern, _, _, _ = SERIES["warning"]
    assert pattern.search("SOPULI-W1000") is None


def test_the_registry_describes_every_warning_in_the_table() -> None:
    """`WARNINGS` is what a run uses to describe a code; the table is what a reader sees."""
    pattern, _, _, heading = SERIES["warning"]
    assert set(WARNINGS) == set(_table(heading, pattern))


def _is_warning_level(level: ast.expr | None) -> bool:
    """A level that is, or may be, ``warning``. A computed level counts."""
    return level is not None and not (isinstance(level, ast.Constant) and level.value != "warning")


def _uncoded_warnings() -> dict[str, int]:
    """Each place in `src/` that builds a warning with no code, and how many.

    Three shapes reach a run document as a warning: a ``ConfigWarning``, a
    ``Diagnostic`` whose level is ``warning`` or is computed, and a dict literal
    whose ``"level"`` is the literal ``"warning"``. A dict whose level is computed
    is the serialiser, not a warning, so it is not counted.
    """
    found: dict[str, int] = defaultdict(int)

    def visit(node: ast.AST, where: str, function: str) -> None:
        for child in ast.iter_child_nodes(node):
            inner = function
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                inner = child.name
            uncoded = False
            if isinstance(child, ast.Call):
                name = getattr(child.func, "id", getattr(child.func, "attr", None))
                keywords = {keyword.arg: keyword.value for keyword in child.keywords}
                if name == "ConfigWarning" and "code" not in keywords:
                    uncoded = True
                if (
                    name == "Diagnostic"
                    and "code" not in keywords
                    and _is_warning_level(keywords.get("level"))
                ):
                    uncoded = True
            if isinstance(child, ast.Dict):
                keys = {
                    key.value: value
                    for key, value in zip(child.keys, child.values, strict=True)
                    if isinstance(key, ast.Constant)
                }
                level = keys.get("level")
                if (
                    isinstance(level, ast.Constant)
                    and level.value == "warning"
                    and "code" not in keys
                ):
                    uncoded = True
            if uncoded:
                found[f"{where}::{inner}"] += 1
            visit(child, where, inner)

    for path in sorted(SRC.rglob("*.py")):
        visit(
            ast.parse(path.read_text(encoding="utf-8")),
            path.relative_to(SRC.parent).as_posix(),
            "<module>",
        )
    return dict(found)


def test_every_warning_has_a_code() -> None:
    """J3's rule: a warning that reaches a run document has a code."""
    found = _uncoded_warnings()
    assert not found, (
        f"warnings built with no code; give each a SOPULI-Wnnn code (03-json-output.md §3): {found}"
    )

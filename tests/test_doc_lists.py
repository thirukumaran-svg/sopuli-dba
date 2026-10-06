"""Lists in the docs that copy something the code defines are checked against it (#611).

Tier 0: reads Markdown, the current run schema and click's command tree.

A list in prose goes stale through a pull request that never opens the file. The
command list in `local-testing.md` said fourteen while the CLI had eighteen, and
the `state` enum in `03-json-output.md` stopped at eleven of thirteen.

A checked list is marked with an HTML comment on the line before it:

    <!-- checked-list: commands -->

The marker applies to the next block: a fenced block, or the lines up to the next
blank line. :data:`EXPECTED` pins where the markers are, so deleting one fails
too rather than switching its check off.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import click
import pytest

from repo_files import requires_repo
from sopuli.cli import cli
from sopuli.driver.protocol import Driver, Session
from sopuli.output.document import SCHEMA_VERSION
from sopuli.output.palette import Role, role_for_state
from sopuli.store.protocol import SecretStore

ROOT = Path(__file__).resolve().parents[1]
RUN_SCHEMA = ROOT / "docs" / "schemas" / f"sopuli-run-{SCHEMA_VERSION}.schema.json"

MARKER = re.compile(r"^<!-- checked-list: (.+?) -->$")
FENCE = re.compile(r"^\s*(```|~~~)")
TOKEN = re.compile(r"`([^`]+)`")

#: Every marker that must exist, as (file, kind).
EXPECTED = frozenset(
    {
        ("docs/local-testing.md", "commands"),
        ("docs/local-testing.md", "state-colours"),
        ("docs/design/03-json-output.md", "state-roles"),
        ("docs/design/03-json-output.md", "run-document"),
        ("docs/design/03-json-output.md", "enum state"),
        ("docs/design/03-json-output.md", "enum action_kind"),
        ("docs/design/00-principles.md", "driver-protocol"),
        ("docs/design/00-principles.md", "store-protocol"),
        ("docs/design/00-principles.md", "extras"),
    }
)

#: The colour words `local-testing.md` uses for the four state roles.
COLOURS = {
    "cyan": Role.GOOD,
    "yellow": Role.ATTENTION,
    "red, bold": Role.BAD,
    "dim": Role.INCONCLUSIVE,
}


def _schema() -> dict[str, Any]:
    schema: dict[str, Any] = json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))
    return schema


def _commands(group: click.Group, path: tuple[str, ...] = ()) -> Iterator[str]:
    """Every leaf command, as `creds rotate` or `doctor`."""
    for name, command in group.commands.items():
        if isinstance(command, click.Group):
            yield from _commands(command, (*path, name))
        else:
            yield " ".join((*path, name))


def _markdown_files() -> list[Path]:
    return [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]


def _block_after(lines: list[str], start: int) -> list[str]:
    """The block a marker on line ``start`` applies to."""
    i = start + 1
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i < len(lines) and FENCE.match(lines[i]):
        end = i + 1
        while end < len(lines) and not FENCE.match(lines[end]):
            end += 1
        return lines[i + 1 : end]
    block = []
    while i < len(lines) and lines[i].strip():
        block.append(lines[i])
        i += 1
    return block


def _marked() -> dict[tuple[str, str], list[str]]:
    found: dict[tuple[str, str], list[str]] = {}
    for path in _markdown_files():
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines):
            match = MARKER.match(line.strip())
            if match:
                key = (path.relative_to(ROOT).as_posix(), match.group(1))
                assert key not in found, f"{key} is marked twice"
                found[key] = _block_after(lines, number)
    return found


def _block(file: str, kind: str) -> list[str]:
    requires_repo(ROOT / file)
    block = _marked().get((file, kind))
    assert block, f"{file} has no `<!-- checked-list: {kind} -->` marker, or nothing after it"
    return block


def test_the_markers_are_where_they_should_be() -> None:
    requires_repo(ROOT / "docs")
    assert set(_marked()) == EXPECTED


def test_the_command_list_is_the_command_tree() -> None:
    text = "\n".join(_block("docs/local-testing.md", "commands"))
    documented = re.findall(r"\bsopuli((?: [a-z][a-z-]*)+)", text)

    assert sorted(word.strip() for word in documented) == sorted(_commands(cli))


@pytest.mark.parametrize("enum", ["state", "action_kind"])
def test_an_enum_list_is_the_schema_enum(enum: str) -> None:
    block = _block("docs/design/03-json-output.md", f"enum {enum}")
    # The first token is the bold field name the paragraph opens with.
    documented = TOKEN.findall(" ".join(block))[1:]

    assert sorted(documented) == sorted(_schema()["$defs"][enum]["enum"])


#: A state is written in capitals, which is how a row is told to be about states.
#: Not filtered through the schema: a value the schema lacks must reach the
#: comparison and fail it, not be dropped on the way.
STATE_WORD = re.compile(r"^[A-Z][A-Z_]*$")


def _state_rows(block: list[str]) -> Iterator[tuple[str, list[str]]]:
    """(first cell, states named in the last cell) for each table row naming a state."""
    for line in block:
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        named = [token for token in TOKEN.findall(cells[-1]) if STATE_WORD.match(token)]
        if named:
            yield cells[0].strip("`"), named


def test_a_state_the_schema_lacks_is_kept() -> None:
    rows = list(_state_rows(["| `attention` | text | `state` ∈ `RESET`, `NOT_A_STATE` |"]))

    assert rows == [("attention", ["RESET", "NOT_A_STATE"])]


@pytest.mark.parametrize(
    ("file", "kind", "role_of"),
    [
        ("docs/design/03-json-output.md", "state-roles", Role),
        ("docs/local-testing.md", "state-colours", COLOURS.__getitem__),
    ],
)
def test_a_state_table_matches_the_palette(file: str, kind: str, role_of: object) -> None:
    """Every state appears once, in the row of the role the palette gives it."""
    documented: dict[str, Role] = {}
    for label, states in _state_rows(_block(file, kind)):
        for state in states:
            assert state not in documented, f"{state} is in two rows"
            documented[state] = role_of(label)  # type: ignore[operator]

    expected = {state: role_for_state(state) for state in _schema()["$defs"]["state"]["enum"]}
    assert documented == expected


def _strip_brackets(text: str) -> str:
    """``text`` with every bracketed part removed, innermost first."""
    inner = re.compile(r"\{[^{}\[\]]*\}|\[[^{}\[\]]*\]")
    while True:
        stripped = inner.sub("", text)
        if stripped == text:
            return text
        text = stripped


def _keys(text: str) -> list[str]:
    return re.findall(r"[a-z_]+", _strip_brackets(text))


def test_the_run_document_sketch_has_every_top_level_key() -> None:
    text = "\n".join(_block("docs/design/03-json-output.md", "run-document"))
    body = text[text.index("{") + 1 : text.rindex("}")]

    assert _keys(body) == list(_schema()["properties"])


def test_the_run_document_sketch_has_every_result_property() -> None:
    text = "\n".join(_block("docs/design/03-json-output.md", "run-document"))
    match = re.search(r"\bresults\s*\[\s*\{", text)
    assert match is not None, "the sketch has no `results [ { ... } ]`"
    depth, end = 1, match.end()
    while depth:
        depth += {"{": 1, "}": -1}.get(text[end], 0)
        end += 1

    assert _keys(text[match.end() : end - 1]) == list(_schema()["$defs"]["result"]["properties"])


#: A method in a protocol sketch: a name at the start of an indented line, then `(`.
SKETCH_METHOD = re.compile(r"^\s+([a-z_]+)\(")


def _methods(*protocols: type) -> list[str]:
    return [
        name
        for protocol in protocols
        for name, value in vars(protocol).items()
        if callable(value) and not name.startswith("_")
    ]


def _sketch_methods(kind: str) -> list[str]:
    block = _block("docs/design/00-principles.md", kind)
    return [match.group(1) for line in block if (match := SKETCH_METHOD.match(line))]


def test_the_driver_sketch_is_the_driver_protocol() -> None:
    assert sorted(_sketch_methods("driver-protocol")) == sorted(_methods(Driver, Session))


def test_the_store_sketch_is_the_store_protocol() -> None:
    assert sorted(_sketch_methods("store-protocol")) == sorted(_methods(SecretStore))


def test_the_install_lines_are_the_extras() -> None:
    requires_repo(ROOT / "pyproject.toml")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    # `dev` is for contributors, not an install a site chooses.
    extras = set(project["optional-dependencies"]) - {"dev"}
    text = "\n".join(_block("docs/design/00-principles.md", "extras"))

    assert sorted(re.findall(r"sopuli-dba\[([a-z]+)\]", text)) == sorted(extras)

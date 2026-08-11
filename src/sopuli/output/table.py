"""Columns of text, laid out by hand (ADR-003).

No table library, and no terminal detection. The width of a column is decided by
what is in it and by a cap the caller sets, never by how wide the window happens
to be -- so the same estate renders the same bytes when piped, in CI, and in a
200-column terminal. ``03-json-output.md`` is explicit that scripts should
consume JSON rather than parse this, which is what makes fixed widths
affordable.

Truncation is visible: a cell that did not fit ends in ``...``, so nobody reads a
shortened DSN as the whole one. The full value is always in ``--output json``.

Colour is not decided here. :class:`~sopuli.output.emit.Emitter` owns whether a
run may emit ANSI and strips it when the answer is no; a renderer that styled its
own output would be a second authority on that question.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

#: What a truncated cell ends with. ASCII by the same convention as the rest of
#: the tool's prose -- this is decoration the tool adds, not text a user supplied.
ELLIPSIS = "..."

#: Spaces between columns. Two, because one reads as a single wide column when a
#: cell happens to end in a space-like character.
GAP = "  "


@dataclass(frozen=True)
class Column:
    """One column: its heading, and how wide it is allowed to get.

    ``width`` caps the *content*. A heading longer than the cap still fits,
    because a truncated heading is a table nobody can read.
    """

    heading: str
    width: int | None = None


def render_table(columns: Sequence[Column], rows: Sequence[Sequence[str]]) -> list[str]:
    """Lay out ``rows`` under ``columns``, one string per line.

    Returns lines rather than a block so a caller can indent them, put a count
    underneath, or drop the whole thing when there is nothing to show. An empty
    ``rows`` renders nothing at all -- a heading row over no data says only that
    the developer did not check.
    """
    if not rows:
        return []

    widths = [_width_of(column, index, rows) for index, column in enumerate(columns)]
    # Rows are squared off before anything is measured against them, so a caller
    # that built a row from optional fields gets a blank cell rather than a
    # traceback -- and every zip below can be strict.
    squared = [[_cell(row, index) for index in range(len(columns))] for row in rows]

    lines = [_line([column.heading for column in columns], widths)]
    lines.extend(
        _line([_fit(cell, width) for cell, width in zip(row, widths, strict=True)], widths)
        for row in squared
    )
    return lines


def _width_of(column: Column, index: int, rows: Sequence[Sequence[str]]) -> int:
    longest = max((len(_cell(row, index)) for row in rows), default=0)
    if column.width is not None:
        longest = min(longest, column.width)
    return max(longest, len(column.heading))


def _cell(row: Sequence[str], index: int) -> str:
    return row[index] if index < len(row) else ""


def _fit(text: str, width: int) -> str:
    """Truncate to ``width``, leaving room for the marker.

    A width too small to hold even the marker keeps the marker rather than a
    meaningless prefix: ``...`` says "there was something here" and ``d`` does
    not.
    """
    if len(text) <= width:
        return text
    if width <= len(ELLIPSIS):
        return ELLIPSIS[:width]
    return text[: width - len(ELLIPSIS)] + ELLIPSIS


def _line(cells: Sequence[str], widths: Sequence[int]) -> str:
    """Pad every cell but the last, which would otherwise trail whitespace."""
    if not cells:
        return ""
    padded = [cell.ljust(width) for cell, width in zip(cells[:-1], widths[:-1], strict=True)]
    padded.append(cells[-1])
    return GAP.join(padded).rstrip()

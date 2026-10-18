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

from sopuli.output.palette import Role, paint
from sopuli.output.printable import printable_cell

#: What a truncated cell ends with. ASCII by the same convention as the rest of
#: the tool's prose -- this is decoration the tool adds, not text a user supplied.
ELLIPSIS = "..."

#: Spaces between columns. Two, because one reads as a single wide column when a
#: cell happens to end in a space-like character.
GAP = "  "


@dataclass(frozen=True)
class Cell:
    """A value and what it is, for a column where only some rows are notable.

    A plain ``str`` is a cell with no role, so a caller only reaches for this
    where a row differs from its neighbours. Every width is computed from
    ``text``, never from the styled form: escape sequences have length, and a
    table measured with them in has columns that drift by row.
    """

    text: str
    role: Role | None = None


@dataclass(frozen=True)
class Column:
    """One column: its heading, and how wide it is allowed to get.

    ``width`` caps the *content*. A heading longer than the cap still fits,
    because a truncated heading is a table nobody can read.
    """

    heading: str
    width: int | None = None


def render_table(columns: Sequence[Column], rows: Sequence[Sequence[Cell | str]]) -> list[str]:
    """Lay out ``rows`` under ``columns``, one string per line.

    Returns lines rather than a block so a caller can indent them, put a count
    underneath, or drop the whole thing when there is nothing to show. An empty
    ``rows`` renders nothing at all -- a heading row over no data says only that
    the developer did not check.
    """
    if not rows:
        return []

    # Rows are squared off before anything is measured against them, so a caller
    # that built a row from optional fields gets a blank cell rather than a
    # traceback -- and every zip below can be strict.
    squared = [[_cell(row, index) for index in range(len(columns))] for row in rows]
    widths = [_width_of(column, index, squared) for index, column in enumerate(columns)]

    headings = [Cell(column.heading, Role.HEADING) for column in columns]
    return [_line(headings, widths), *(_line(row, widths) for row in squared)]


def _width_of(column: Column, index: int, rows: Sequence[Sequence[Cell]]) -> int:
    longest = max((len(row[index].text) for row in rows), default=0)
    if column.width is not None:
        longest = min(longest, column.width)
    return max(longest, len(column.heading))


def _cell(row: Sequence[Cell | str], index: int) -> Cell:
    """One cell, its text made printable before anything measures it (#859).

    Cells carry text from outside the tool -- an ORA- detail, a lock holder --
    and a control character in one would move the cursor or start a row the
    table never laid out.
    """
    value = row[index] if index < len(row) else ""
    cell = value if isinstance(value, Cell) else Cell(value)
    return Cell(printable_cell(cell.text), cell.role)


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


def _line(cells: Sequence[Cell], widths: Sequence[int]) -> str:
    """Fit, paint, then pad *outside* the paint.

    The order is the whole of the arithmetic. Widths are measured on the plain
    text, because escape sequences have length and a table measured with them in
    has columns that drift by row. Padding then goes outside the escapes rather
    than inside them, so a dim placeholder dims one character instead of a run of
    spaces -- invisible either way on most terminals, and not on all of them.

    The last cell is not padded: trailing whitespace is invisible until it lands
    in a diff or a ticket.
    """
    if not cells:
        return ""
    painted = [_pad(cell, width) for cell, width in zip(cells[:-1], widths[:-1], strict=True)]
    painted.append(paint(_fit(cells[-1].text, widths[-1]), cells[-1].role))
    return GAP.join(painted).rstrip()


def _pad(cell: Cell, width: int) -> str:
    """One cell, painted and then padded to ``width`` in plain spaces."""
    fitted = _fit(cell.text, width)
    return paint(fitted, cell.role) + " " * (width - len(fitted))

"""Columns of text, laid out by hand (ADR-003).

The property that matters most is not prettiness: the same rows must render to
the same bytes every time, whether piped, in CI, or in a wide terminal. No test
here sets a terminal width, because the renderer does not read one.
"""

from __future__ import annotations

from sopuli.output.table import ELLIPSIS, Column, render_table


def test_columns_are_as_wide_as_their_widest_cell() -> None:
    lines = render_table(
        [Column("NAME"), Column("ENV")],
        [["appdb-dev-alpha", "dev"], ["cdb", "prod"]],
    )

    assert lines == [
        "NAME             ENV",
        "appdb-dev-alpha  dev",
        "cdb              prod",
    ]


def test_a_heading_widens_a_column_of_narrow_cells() -> None:
    lines = render_table([Column("ENVIRONMENT"), Column("N")], [["dev", "1"]])

    assert lines == ["ENVIRONMENT  N", "dev          1"]


def test_no_rows_renders_nothing_at_all() -> None:
    """A heading row over no data says only that the developer did not check."""
    assert render_table([Column("NAME")], []) == []


def test_the_last_column_is_not_padded() -> None:
    """Trailing whitespace is invisible until it lands in a diff or a ticket."""
    lines = render_table([Column("A"), Column("B")], [["one", "x"], ["two", "yy"]])

    assert not any(line.endswith(" ") for line in lines)


def test_a_cell_over_its_cap_is_truncated_visibly() -> None:
    """A shortened DSN must not read as the whole one. The full value is always
    in `--output json`."""
    lines = render_table([Column("DSN", 12)], [["db.example.com:1521/service"]])

    assert lines[1] == "db.exampl" + ELLIPSIS
    assert len(lines[1]) == 12  # the marker counts against the cap, never past it


def test_a_cell_exactly_at_its_cap_is_left_alone() -> None:
    lines = render_table([Column("DSN", 8)], [["12345678"]])

    assert lines[1] == "12345678"


def test_a_cap_narrower_than_the_marker_keeps_the_marker() -> None:
    """`...` says "there was something here"; a one-character prefix does not."""
    lines = render_table([Column("X", 2)], [["abcdef"]])

    assert lines[1].strip() == ELLIPSIS[:2]


def test_a_cap_does_not_shrink_a_column_below_its_heading() -> None:
    """A truncated heading is a table nobody can read."""
    lines = render_table([Column("ENVIRONMENT", 3), Column("N")], [["dev", "1"]])

    assert lines[0].startswith("ENVIRONMENT")


def test_a_short_row_is_padded_rather_than_raising() -> None:
    """Rows are built by callers from optional fields; a missing trailing cell
    should not be a traceback."""
    lines = render_table([Column("A"), Column("B")], [["one"]])

    assert lines == ["A    B", "one"]


def test_rendering_is_deterministic() -> None:
    columns = [Column("NAME", 10), Column("DSN", 20)]
    rows = [["alpha", "db.example.com:1521/x"], ["beta", "db2.example.com:1521/y"]]

    assert render_table(columns, rows) == render_table(columns, rows)

"""Text from outside the tool, made safe to put on a terminal (#859).

Server messages, vault error bodies and lock holders can carry control
characters, and a terminal acts on them. These are the shapes that matter: an
OSC sequence that sets the window title, a lone carriage return that lets the
next text overwrite a row, and the C1 forms of both.
"""

from __future__ import annotations

import io
import json
from typing import TextIO, cast

import click
import pytest

from sopuli.output.color import ColorChoice
from sopuli.output.emit import Emitter, OutputMode
from sopuli.output.palette import Role, paint
from sopuli.output.printable import printable, printable_cell
from sopuli.output.table import Column, render_table

#: An ORA-20000 from a site-written verify function, carrying an OSC title
#: sequence and a carriage return that would overwrite the line with "ok".
HOSTILE = "ORA-20000: rejected\x1b]0;owned\x07\rSTATE ok"


@pytest.mark.parametrize("colour", [False, True])
def test_osc_and_carriage_return_are_shown_not_sent(colour: bool) -> None:
    shown = printable(HOSTILE, colour=colour)

    assert "\x1b" not in shown
    assert "\x07" not in shown
    assert "\r" not in shown
    assert shown == "ORA-20000: rejected\\x1b]0;owned\\x07\\rSTATE ok"


@pytest.mark.parametrize(
    ("character", "shown"),
    [
        ("\x08", "\\x08"),
        ("\x7f", "\\x7f"),
        ("\x9b", "\\x9b"),
        ("\x9d", "\\x9d"),
        ("\x00", "\\x00"),
        ("\N{LINE SEPARATOR}", "\\u2028"),
        ("\N{RIGHT-TO-LEFT OVERRIDE}", "\\u202e"),
        ("\N{ZERO WIDTH SPACE}", "\\u200b"),
        ("\N{LEFT-TO-RIGHT MARK}", "\\u200e"),
        ("\N{ARABIC LETTER MARK}", "\\u061c"),
        ("\N{WORD JOINER}", "\\u2060"),
        ("\N{SOFT HYPHEN}", "\\xad"),
    ],
    ids=[
        "backspace",
        "delete",
        "c1-csi",
        "c1-osc",
        "nul",
        "line-separator",
        "bidi-override",
        "zero-width",
        "ltr-mark",
        "arabic-mark",
        "word-joiner",
        "soft-hyphen",
    ],
)
def test_every_other_control_character_is_shown(character: str, shown: str) -> None:
    assert printable(f"a{character}b", colour=False) == f"a{shown}b"


def test_line_breaks_and_tabs_are_kept_in_free_text() -> None:
    """A multi-line hint or a traceback is still multi-line."""
    assert printable("first\n\tsecond", colour=False) == "first\n\tsecond"


def test_a_windows_line_end_is_a_line_end() -> None:
    """Text from a Windows host or an HTTP body would otherwise show a `\\r`
    on every line."""
    assert printable("one\r\ntwo", colour=False) == "one\ntwo"


def test_a_table_cell_shows_line_breaks_too() -> None:
    """A line break in a cell would start a row the table never laid out."""
    assert printable_cell("a\nb\rc\td") == "a\\nb\\rc\\td"


def test_the_palettes_colour_is_kept_only_where_colour_is_on() -> None:
    painted = paint("DRIFT", Role.BAD)

    assert printable(painted, colour=True) == painted
    assert printable(painted, colour=False) == "DRIFT"


@pytest.mark.parametrize("colour", [False, True])
def test_a_colour_sequence_from_outside_is_shown_either_way(colour: bool) -> None:
    """Conceal (`ESC [ 8 m`) would hide every row after it, and a cursor move
    would rewrite one. Only the palette's own sequences are written as escapes,
    and colour off does not hide one that came from outside."""
    shown = printable("ORA-20000: x\x1b[8m\x1b[1A", colour=colour)

    assert "\x1b" not in shown
    assert shown == "ORA-20000: x\\x1b[8m\\x1b[1A"


def test_colour_on_still_shows_every_other_escape_sequence() -> None:
    painted = paint("DRIFT", Role.BAD) + HOSTILE

    kept = printable(painted, colour=True)

    assert kept.startswith(paint("DRIFT", Role.BAD))
    assert "\x1b]" not in kept
    assert "\r" not in kept


def test_a_hostile_cell_cannot_forge_a_row() -> None:
    lines = render_table([Column("ACCOUNT"), Column("DETAIL")], [["acme_web_user", HOSTILE]])

    assert len(lines) == 2
    assert "\r" not in click.unstyle(lines[1])
    assert "\x1b]" not in lines[1]


@pytest.mark.parametrize("choice", [ColorChoice.NEVER, ColorChoice.ALWAYS])
def test_the_emitter_shows_control_characters_with_colour_on_or_off(
    choice: ColorChoice, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sopuli.output.color.enable_virtual_terminal", lambda _: True)
    written = io.StringIO()
    emitter = Emitter(mode=OutputMode.TEXT, stream=cast("TextIO", written), color_choice=choice)

    emitter.emit_text(HOSTILE)

    assert written.getvalue().strip() == "ORA-20000: rejected\\x1b]0;owned\\x07\\rSTATE ok"


def test_main_shows_the_control_characters_in_an_error_it_prints(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The run-level error line carries the exception's message, which is the
    server's or the vault's text, and it goes to stderr outside the emitter."""
    import sopuli.cli as cli_module

    def failing(**_: object) -> None:
        raise RuntimeError(HOSTILE)

    monkeypatch.setattr(cli_module, "configure_streams", lambda: None)
    monkeypatch.setattr(cli_module.cli, "main", failing)

    with pytest.raises(SystemExit):
        cli_module.main()

    printed = capsys.readouterr().err
    assert "\x1b" not in printed
    assert "\r" not in printed
    assert "\\x1b]0;owned\\x07\\rSTATE ok" in printed


def test_the_debug_formatter_shows_control_characters() -> None:
    import logging

    from sopuli.output.debug import DebugFormatter

    record = logging.LogRecord("sopuli.driver", logging.DEBUG, __file__, 1, HOSTILE, None, None)

    formatted = DebugFormatter(started=0.0).format(record)

    assert "\x1b" not in formatted
    assert "\x07" not in formatted
    assert "\r" not in formatted
    assert "rejected\\x1b]0;owned\\x07\\rSTATE ok" in formatted


def test_a_lock_holder_in_a_prompt_is_shown_not_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    """`lock break` asks "take this lock from <holder>?", and the holder is
    the vault's text. A `\\r` in it would overwrite the question."""
    import sopuli.cli as cli_module

    asked: list[str] = []

    def confirm(question: str, **_: object) -> bool:
        asked.append(question)
        return True

    monkeypatch.setattr(click, "confirm", confirm)

    cli_module._confirm("take this lock from svc\x1b]0;x\x07\ryes?", abort=True, err=True)

    assert asked == ["take this lock from svc\\x1b]0;x\\x07\\ryes?"]


@pytest.mark.parametrize("colour", [False, True])
def test_a_line_for_stderr_is_shown_not_sent(colour: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    """The plan before a prompt goes to stderr outside the emitter, and a lock
    holder reaches it from the vault. Asserted on what is handed to click, so
    the colour-on path is exercised whatever stderr is in the test."""
    from types import SimpleNamespace

    import sopuli.cli as cli_module

    echoed: list[tuple[str, object]] = []

    def echo(message: str, **options: object) -> None:
        echoed.append((message, options.get("color")))

    monkeypatch.setattr(click, "echo", echo)
    monkeypatch.setattr("sopuli.output.emit.resolve_color", lambda *_, **__: colour)
    run = SimpleNamespace(emitter=lambda: SimpleNamespace(color_choice=ColorChoice.AUTO))

    cli_module._echo_err(paint("plan", Role.HEADING) + f" held by {HOSTILE}", run=run)  # type: ignore[arg-type]

    ((message, passed),) = echoed
    assert passed is colour
    assert "\x1b]" not in message
    assert "\x07" not in message
    assert "\r" not in message
    assert message.startswith(paint("plan", Role.HEADING) if colour else "plan")
    assert "\\x1b]0;owned\\x07\\rSTATE ok" in message


def test_json_keeps_the_servers_text_exactly() -> None:
    """The JSON encoder escapes control characters itself, so the document
    carries the message as the server sent it."""
    assert json.loads(json.dumps({"message": HOSTILE}))["message"] == HOSTILE

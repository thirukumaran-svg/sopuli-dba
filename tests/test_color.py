"""The colour gate (``sopuli.output.color``, ``Emitter.use_color``).

Tier 0 (``04-testing.md`` §4): pure logic, no containers, no I/O. ``env`` is a
parameter of :func:`resolve_color` rather than a read of ``os.environ``, so
these are ordinary function calls with no process state to set up or restore.

The fake streams below answer ``isatty`` however a case needs. On Windows a real
TTY would also have to survive the VT probe, so the cases that expect colour
patch :func:`enable_virtual_terminal` -- what is under test there is the
precedence, not the console API.
"""

from __future__ import annotations

import io
import sys
from typing import TextIO, cast

import click
import pytest

from sopuli.exit_codes import ExitCode
from sopuli.output.color import (
    ColorChoice,
    enable_virtual_terminal,
    resolve_color,
)
from sopuli.output.document import RunDocument
from sopuli.output.emit import Emitter, OutputMode


def _finished_run() -> RunDocument:
    """A closed run document, since ``emit`` needs one even in text mode."""
    return RunDocument.start("config.show").finish(ExitCode.SUCCESS)


class FakeStream:
    """A stream that knows only whether it is a terminal."""

    def __init__(self, *, tty: bool) -> None:
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def terminal() -> TextIO:
    return cast("TextIO", FakeStream(tty=True))


def pipe() -> TextIO:
    return cast("TextIO", FakeStream(tty=False))


@pytest.fixture
def vt_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """Take the Windows console API out of the picture.

    ``enable_virtual_terminal`` is exercised on its own further down; here it
    would only mean that every "colour is on" case fails on Windows and passes
    on Linux, which is the kind of test that teaches nothing.
    """
    monkeypatch.setattr("sopuli.output.color.enable_virtual_terminal", lambda _: True)


# ------------------------------------------------------------------- auto ---


@pytest.mark.usefixtures("vt_available")
def test_auto_colours_an_interactive_terminal() -> None:
    assert resolve_color(ColorChoice.AUTO, stream=terminal(), env={}) is True


def test_auto_does_not_colour_a_pipe() -> None:
    """The common case: `sopuli creds check > nightly.log`, or any `| grep`."""
    assert resolve_color(ColorChoice.AUTO, stream=pipe(), env={}) is False


@pytest.mark.usefixtures("vt_available")
@pytest.mark.parametrize("variable", ["NO_COLOR", "SOPULI_NO_COLOR"])
def test_auto_honours_both_no_colour_variables(variable: str) -> None:
    env = {variable: "1"}
    assert resolve_color(ColorChoice.AUTO, stream=terminal(), env=env) is False


@pytest.mark.usefixtures("vt_available")
@pytest.mark.parametrize("value", ["1", "0", "false", "no", "anything at all"])
def test_any_non_empty_value_disables_colour(value: str) -> None:
    """no-color.org: set and not empty, *regardless of its value*.

    `NO_COLOR=0` therefore still disables colour. That reads wrong and is
    correct -- the variable's presence is the signal, and treating `0` as "yes
    please" would break every consumer that follows the convention.
    """
    env = {"NO_COLOR": value}
    assert resolve_color(ColorChoice.AUTO, stream=terminal(), env=env) is False


@pytest.mark.usefixtures("vt_available")
def test_an_empty_no_colour_variable_is_not_set() -> None:
    """The one exception the standard names, and the reason for a truthiness
    check rather than a membership test."""
    env = {"NO_COLOR": ""}
    assert resolve_color(ColorChoice.AUTO, stream=terminal(), env=env) is True


@pytest.mark.usefixtures("vt_available")
def test_auto_respects_a_dumb_terminal() -> None:
    env = {"TERM": "dumb"}
    assert resolve_color(ColorChoice.AUTO, stream=terminal(), env=env) is False


@pytest.mark.usefixtures("vt_available")
def test_a_normal_term_is_not_treated_as_dumb() -> None:
    env = {"TERM": "xterm-256color"}
    assert resolve_color(ColorChoice.AUTO, stream=terminal(), env=env) is True


# --------------------------------------------------------- explicit flags ---


def test_never_wins_over_a_terminal() -> None:
    assert resolve_color(ColorChoice.NEVER, stream=terminal(), env={}) is False


def test_always_wins_over_a_pipe() -> None:
    """The reason `always` exists.

    A CI job's log viewer renders ANSI, but the job has no TTY, so autodetection
    would strip exactly the output that was wanted.
    """
    assert resolve_color(ColorChoice.ALWAYS, stream=pipe(), env={}) is True


def test_always_wins_over_no_color() -> None:
    """P3: the command line outranks the environment.

    Deliberate, and the one place this departs from a naive reading of
    no-color.org. Invariant 10's ratchet does not apply -- it governs safety
    settings, and nothing becomes more dangerous because it is red.
    """
    env = {"NO_COLOR": "1", "SOPULI_NO_COLOR": "1"}
    assert resolve_color(ColorChoice.ALWAYS, stream=pipe(), env=env) is True


def test_never_wins_over_everything() -> None:
    env = {"TERM": "xterm-256color"}
    assert resolve_color(ColorChoice.NEVER, stream=terminal(), env=env) is False


# --------------------------------------------------- streams that cannot ----


@pytest.mark.parametrize("exception", [ValueError, OSError])
def test_a_stream_that_cannot_answer_isatty_gets_no_colour(
    exception: type[Exception],
) -> None:
    """Closed or detached. If we cannot establish that a human is watching,
    do not decorate."""

    class Raises:
        def isatty(self) -> bool:
            raise exception("I/O operation on closed file")

    assert resolve_color(ColorChoice.AUTO, stream=cast("TextIO", Raises()), env={}) is False


def test_a_stream_without_isatty_gets_no_colour() -> None:
    assert resolve_color(ColorChoice.AUTO, stream=cast("TextIO", object()), env={}) is False


def test_virtual_terminal_declines_a_stream_with_no_os_handle() -> None:
    """P4's "plain fallback": a Windows console with VT off would render escape
    sequences as literal garbage, so an unanswerable probe means no colour.

    On other platforms there is nothing to enable and the answer is yes.
    """
    result = enable_virtual_terminal(cast("TextIO", object()))

    assert result is (sys.platform != "win32")


# ------------------------------------------------------- the emitter gate ---


@pytest.mark.usefixtures("vt_available")
def test_json_output_is_never_coloured() -> None:
    """Invariant 12: the machine stream is a contract.

    A consumer must never have to strip escape sequences before parsing, so
    `--color always` does not reach the JSON document -- it is not a preference
    about JSON.
    """
    emitter = Emitter(
        mode=OutputMode.JSON,
        stream=terminal(),
        color_choice=ColorChoice.ALWAYS,
    )

    assert emitter.use_color() is False


@pytest.mark.usefixtures("vt_available")
def test_text_output_consults_the_choice() -> None:
    emitter = Emitter(mode=OutputMode.TEXT, stream=terminal(), color_choice=ColorChoice.ALWAYS)

    assert emitter.use_color() is True


def test_the_default_choice_is_auto() -> None:
    assert Emitter().color_choice is ColorChoice.AUTO


def test_escape_sequences_are_stripped_when_colour_is_off() -> None:
    """The NO_COLOR promise is kept at the serialiser, not by call sites.

    A renderer that forgets the gate, or an ORA- message that arrives already
    decorated, must not put escapes on a stream the user asked to keep clean.
    """
    written = io.StringIO()
    emitter = Emitter(
        mode=OutputMode.TEXT,
        stream=cast("TextIO", written),
        color_choice=ColorChoice.NEVER,
    )

    emitter.emit(_finished_run(), click.style("DRIFT", fg="red"))

    assert written.getvalue().strip() == "DRIFT"


def test_escape_sequences_survive_when_colour_is_on() -> None:
    """The other half: stripping must be the gate's doing, not unconditional."""
    written = io.StringIO()
    emitter = Emitter(
        mode=OutputMode.TEXT,
        stream=cast("TextIO", written),
        color_choice=ColorChoice.ALWAYS,
    )

    emitter.emit(_finished_run(), click.style("DRIFT", fg="red"))

    assert "\x1b" in written.getvalue()
    assert "DRIFT" in written.getvalue()


def test_the_answer_is_resolved_once_and_remembered() -> None:
    """One run gets one answer.

    Re-deciding per write would call isatty on every line, and could answer
    differently mid-run if the stream were swapped underneath it.
    """
    calls: list[int] = []

    class CountingStream:
        def isatty(self) -> bool:
            calls.append(1)
            return False

    emitter = Emitter(mode=OutputMode.TEXT, stream=cast("TextIO", CountingStream()))

    assert emitter.use_color() is False
    assert emitter.use_color() is False
    assert len(calls) == 1

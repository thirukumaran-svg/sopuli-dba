"""The spinner's gate, and the promise that it never reaches a machine (#419).

Tier 0 (``04-testing.md`` §4): no containers, no sockets, no real terminal.

**What these tests are really guarding is the test suite itself.** #416 measured
that ``CliRunner`` replaces ``sys.stderr`` with a stream whose ``isatty()`` is
``False``, so no spinner thread is ever created anywhere in this repository's
tests -- nothing to join, nothing to race an assertion, no timing workaround and
no mocking. That is a property worth asserting rather than a comment worth
writing, because the day it stops being true is the day this suite starts
failing intermittently for reasons nobody will connect to a spinner.

The animation itself is exercised by forcing it on against a ``StringIO``, which
is the only way to see the bytes without a terminal. That is not a substitute for
watching it spin -- ``docs/local-testing.md`` §10 carries the real run.
"""

from __future__ import annotations

import io
import os
import sys
import threading
import time

import click
import pytest
from click.testing import CliRunner

from sopuli.output import tty
from sopuli.output.emit import Emitter, OutputMode
from sopuli.output.spinner import FRAMES, Spinner, disabled, make
from sopuli.output.tty import is_a_terminal


class Terminal(io.StringIO):
    """A ``StringIO`` that claims to be a terminal, which ``StringIO`` does not."""

    def isatty(self) -> bool:
        return True


#: The message the one real call site produces, so the samples here and the
#: ones in ``docs/local-testing.md`` are the same string.
MESSAGE = "Reading `vault-dev:acme/dev/acme`"


def spun(stream: io.StringIO) -> str:
    """Everything a spinner wrote, once it has stopped."""
    return stream.getvalue()


# ------------------------------------------------------------- the probe ---


def test_a_stream_that_is_not_a_terminal_says_so() -> None:
    assert is_a_terminal(io.StringIO()) is False


def test_a_stream_that_claims_a_terminal_is_believed() -> None:
    assert is_a_terminal(Terminal()) is True


def test_no_stream_at_all_is_not_a_terminal() -> None:
    """``sys.stderr`` is ``None`` under ``pythonw.exe``. Not an error, an answer."""
    assert is_a_terminal(None) is False


def test_a_closed_stream_is_not_a_terminal() -> None:
    """The tolerant half of the probe, and the reason it moved to its own module.

    A closed stream raises ``ValueError`` from ``isatty()`` rather than
    answering. The old ``cli._can_prompt`` would have propagated it; the answer
    that was wanted all along is "nobody is watching".
    """
    stream = io.StringIO()
    stream.close()

    assert is_a_terminal(stream) is False


def test_an_object_with_no_isatty_is_not_a_terminal() -> None:
    assert is_a_terminal(object()) is False  # type: ignore[arg-type]


def test_the_null_device_is_not_a_terminal() -> None:
    """#549: Windows answers ``isatty()`` true for ``NUL``, a character device.

    A real open of the null device, not a double, because a double is exactly
    what cannot show the bug: it answers whatever it was told to. On POSIX
    ``/dev/null`` was never a TTY, so this holds there trivially; on Windows it
    is the ``GetConsoleMode`` check that makes it hold.
    """
    with open(os.devnull, encoding="utf-8") as null:
        assert is_a_terminal(null) is False


@pytest.mark.skipif(sys.platform != "win32", reason="CONOUT$ is a Windows device name")
def test_on_windows_a_real_console_is_a_terminal() -> None:
    """The half of #549 that must not regress: a console still counts.

    ``CONOUT$`` is the process's own console output buffer, so this is the one
    handle ``GetConsoleMode`` is supposed to succeed on. A process with no
    console attached cannot open it, and has nothing here to test.
    """
    try:
        with open("CONOUT$", "w", encoding="utf-8") as console:
            answer = is_a_terminal(console)
    except OSError as exc:
        pytest.skip(f"no console attached to this process: {exc}")

    assert answer is True


def test_on_windows_a_tty_that_is_not_a_console_is_not_a_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Windows branch, reached from any platform."""
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(tty, "_is_a_windows_console", lambda stream: False)

    assert is_a_terminal(Terminal()) is False


def test_on_windows_a_stream_with_no_os_handle_keeps_its_own_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A double has no device to be ``NUL``, so the console check defers to it.

    ``Terminal`` is a ``StringIO``, whose ``fileno()`` raises. The check returns
    before it touches ``msvcrt``, which is why this runs off Windows too.
    """
    monkeypatch.setattr(sys, "platform", "win32")

    assert is_a_terminal(Terminal()) is True


# -------------------------------------------------------------- the gate ---


def test_the_gate_is_shut_when_stderr_is_not_a_terminal() -> None:
    assert Emitter(err_stream=io.StringIO()).spinner("x")._enabled is False


def test_the_gate_is_open_on_a_terminal_in_text_mode() -> None:
    assert Emitter(err_stream=Terminal()).spinner("x")._enabled is True


def test_json_shuts_the_gate_even_on_a_terminal() -> None:
    """Invariant 12: the machine contract does not animate.

    The stream check would already refuse a pipe. This is the case it cannot
    cover -- a JSON run on a terminal, where a consumer capturing ``2>&1`` would
    otherwise find frames ahead of the document.
    """
    emitter = Emitter(mode=OutputMode.JSON, err_stream=Terminal())

    assert emitter.spinner("x")._enabled is False


def test_a_disabled_spinner_starts_no_thread_and_writes_nothing() -> None:
    stream = io.StringIO()
    before = threading.active_count()

    with disabled(MESSAGE):
        assert threading.active_count() == before

    assert spun(stream) == ""


def test_colour_is_not_consulted() -> None:
    """``NO_COLOR`` has nothing to say here, because there is no colour to say it about.

    Asserted rather than assumed: a future reader adding a colour gate would be
    adding a rule the emission cannot violate, and this says so.
    """
    emitter = Emitter(err_stream=Terminal(), env={"NO_COLOR": "1"})

    assert emitter.spinner("x")._enabled is True


# --------------------------------------------------- what it actually writes ---


def test_it_animates_and_clears_the_line() -> None:
    stream = Terminal()

    with make(MESSAGE, stream=stream):
        time.sleep(0.25)

    written = spun(stream)
    assert written.startswith("\r")
    assert any(f"\r{frame} {MESSAGE}" in written for frame in FRAMES)
    # The line is blanked on the way out, so whatever prints next starts clean.
    assert written.endswith("\r")
    assert written.rstrip("\r").endswith(" ")


def test_the_emission_is_ascii_and_carries_no_ansi() -> None:
    """``tests/test_cli_smoke.py``'s rule, for the one output it cannot see.

    The smoke tests read stdout; a spinner never goes there. So the ASCII rule is
    asserted here or nowhere.
    """
    stream = Terminal()

    with make(MESSAGE, stream=stream):
        time.sleep(0.15)

    written = spun(stream)
    written.encode("ascii")  # raises UnicodeEncodeError if it is not
    assert "\x1b" not in written
    assert set(written) - set(FRAMES) - set(MESSAGE + " ") == {"\r"}


def test_the_line_is_clear_before_an_exception_message_prints() -> None:
    """The ordering that matters most, since a failing call is when it is read.

    ``__exit__`` joins the thread, so the blanking is ordered ahead of whatever
    the caller writes next -- here, the shape ``cli.py`` uses for an ORA- error.
    """
    stream = Terminal()

    def fail() -> None:
        with make(MESSAGE, stream=stream):
            time.sleep(0.15)
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        fail()
    stream.write("sopuli: ORA-12541: Cannot connect. No listener\n")

    written = spun(stream)
    assert written[written.rfind("\r") :] == "\rsopuli: ORA-12541: Cannot connect. No listener\n"


def test_the_thread_is_joined_before_the_block_exits() -> None:
    """No daemon thread outlives its ``with``, so nothing races the next assertion."""
    before = threading.active_count()

    with make(MESSAGE, stream=Terminal()) as spinner:
        time.sleep(0.15)
        assert threading.active_count() == before + 1

    assert spinner._thread is None
    assert threading.active_count() == before


def test_a_stream_that_breaks_mid_spin_does_not_kill_the_run() -> None:
    """Decoration must not be able to fail a rotation.

    A reader that goes away closes the pipe under the spinner's thread. The
    animation stops; the block it was decorating runs to completion.
    """
    stream = Terminal()
    finished = False

    with make(MESSAGE, stream=stream):
        time.sleep(0.15)
        stream.close()
        time.sleep(0.15)
        finished = True

    assert finished


# --------------------------------------------- and none of this in the suite ---


def test_no_spinner_thread_is_ever_created_under_clirunner() -> None:
    """The property that keeps this suite from going flaky (#416).

    ``CliRunner`` replaces ``sys.stderr`` with a stream whose ``isatty()`` is
    ``False``. The same gate that makes the spinner correct in a log file makes
    it inert in every test in this repository -- one mechanism, not two. If this
    ever fails, every ``CliRunner`` test in the suite has just acquired a thread
    it does not know about.
    """
    seen: list[object] = []

    @click.command()
    def probe() -> None:
        seen.append(is_a_terminal(sys.stderr))
        before = threading.active_count()
        with Emitter().spinner(MESSAGE):
            time.sleep(0.15)
            seen.append(threading.active_count() == before)

    result = CliRunner().invoke(probe, catch_exceptions=False)

    assert result.exit_code == 0
    assert seen == [False, True]


def test_the_spinner_takes_no_flag_and_no_variable() -> None:
    """#416's non-goal, asserted so it cannot drift into being one.

    A ``--spinner`` flag would need a precedence rule, a settings-registry entry
    and a line in ``tests/test_cli_precedence.py``'s walk. There is no reader for
    whom forcing animation into a non-interactive stream is better than silence,
    so the absence is the design rather than an omission.
    """
    from sopuli.cli import cli
    from sopuli.settings.registry import SETTINGS

    assert not [name for name in SETTINGS if "spinner" in name]

    def params(command: click.Command) -> set[str]:
        found = {str(param.name) for param in command.params}
        if isinstance(command, click.Group):
            for child in command.commands.values():
                found |= params(child)
        return found

    assert not {name for name in params(cli) if "spinner" in name}


def test_a_spinner_resolves_its_stream_at_write_time() -> None:
    """Amendment 2 from #416: nothing captured in ``__init__``.

    A stream captured at construction and written from another thread could
    outlive the one the rest of the run is using. ``Emitter`` resolves its own
    stream at write time for the same reason and says so.
    """
    spinner = Spinner("x", enabled=False)

    assert spinner._out() is sys.stderr


# ----------------------------------- the probe's other caller, consolidated ---


def test_a_detached_stdin_answers_rather_than_raising() -> None:
    """``cli._can_prompt`` now asks the tolerant probe (#419).

    This is the one behaviour change in the wiring, and it is on the
    confirmation path, so it is asserted rather than left to be noticed. A
    scheduler or a service manager hands a command a stdin that is closed or
    absent; ``sys.stdin.isatty()`` raised ``ValueError`` on exactly that stream,
    turning "nobody is watching" into a traceback from inside the check for it.

    Both answers refuse the unconfirmed run. The difference is that one of them
    names the environment the operator has to change.
    """
    import sopuli.cli as cli_module

    closed = io.StringIO()
    closed.close()

    for stdin in (closed, None):
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(sys, "stdin", stdin)
            assert cli_module._can_prompt() is False


def test_a_terminal_stdin_can_still_prompt() -> None:
    """The other direction, so the consolidation cannot have simply broken it."""
    import sopuli.cli as cli_module

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(sys, "stdin", Terminal())
        assert cli_module._can_prompt() is True

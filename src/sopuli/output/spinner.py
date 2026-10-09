"""A stderr spinner, for the calls that are silent because they are waiting.

Four rules hold it, and none of them is a style preference.

**stderr only, and never under ``--output json``.** stdout carries the run
document and nothing else may touch it (invariant 12). stderr is not safe by
itself either: a consumer capturing ``2>&1`` would find ``\\r``-separated frames
ahead of the document, so the machine contract turns the animation off entirely
rather than relying on which stream it went to. :meth:`~sopuli.output.emit.Emitter.spinner` asks
:attr:`~sopuli.output.emit.Emitter.is_json` before it builds one.

**A TTY, or nothing.** Unlike ``--color always`` — which exists because a CI log
viewer with no TTY can still render ANSI — there is no reader for whom
``\\r``-driven animation in a log file is better than silence. So there is no
``--spinner`` flag, no ``SOPULI_SPINNER``, no precedence rule and nothing for
``tests/test_cli_precedence.py``'s walk to learn. At :data:`INTERVAL_S`, with a
message of about 37 characters, this is 400 characters a second, or about 12,000
over the 30-second default vault timeout — which is what a flag forcing it on
would put in somebody's log.

**ASCII, and no ANSI at all.** :data:`FRAMES` is four ASCII characters and the
only control character emitted is a carriage return. That is what makes
``NO_COLOR`` irrelevant here rather than a fifth rule: there is nothing to
strip, so a colour-free run and a colour-full one animate identically.

**Never live across anything else that writes to stderr.** This is the one that
is easy to get wrong, and the cost is concrete: a prompt written
while a spinner is running reaches the stream and is then overwritten by the
next frame, leaving the operator looking at a spinner while the process blocks
on a ``readline`` for a question no longer on screen. ``render_plan`` and
``click.confirm(..., err=True)`` are both on stderr deliberately, so a spinner
must wrap one slow call and stop. That is why this is a context manager used
explicitly at a call site rather than a decorator on a verb: which operations
are considered slow stays visible in the diff, and so does what each one spans.
"""

from __future__ import annotations

import itertools
import sys
import threading
from types import TracebackType
from typing import TextIO

from sopuli.output.tty import is_a_terminal

#: The animation. ASCII by the rule above, and four frames because a spinner is
#: a sign of life rather than a progress bar -- there is no percentage to show,
#: since neither Vault nor Oracle reports one.
FRAMES = "|/-\\"

#: Seconds between frames. Fast enough to read as motion, slow enough that a
#: 30-second wait is not thousands of writes.
INTERVAL_S = 0.1


class Spinner:
    """Animate ``message`` on stderr for as long as the ``with`` block runs.

    Built by :meth:`sopuli.output.emit.Emitter.spinner`, which is where the
    "may I decorate this stream" question is answered — the same place, and for
    the same reason, as :meth:`~sopuli.output.emit.Emitter.use_color`. A call
    site never works it out for itself, so no future call site can forget to.

    A disabled spinner is a working context manager that starts no thread and
    writes nothing, so a call site needs no branch of its own.
    """

    def __init__(self, message: str, *, enabled: bool, stream: TextIO | None = None) -> None:
        self.message = message
        self._stream = stream
        self._enabled = enabled
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _out(self) -> TextIO | None:
        """The stream to animate on, resolved **now** rather than at construction.

        :class:`~sopuli.output.emit.Emitter` resolves its own stream at write
        time and says why: "capturing ``sys.stdout`` early would break under test
        runners that replace it". The same hazard applies here and is worse,
        because the read happens on another thread — a stream captured in
        ``__init__`` could outlive the one the rest of the run is using.
        """
        return self._stream if self._stream is not None else sys.stderr

    def _spin(self) -> None:
        for frame in itertools.cycle(FRAMES):
            if self._stop.is_set():
                break
            self._write(f"\r{frame} {self.message}")
            if self._stop.wait(INTERVAL_S):
                break
        # Blank the line rather than leaving a final frame behind: whatever the
        # caller prints next -- a result, or an ORA- message from the call that
        # just failed -- starts at column zero on a clean line.
        self._write("\r" + " " * (len(self.message) + 2) + "\r")

    def _write(self, text: str) -> None:
        """Write a frame, and let a broken stream end the animation, not the run.

        A spinner is decoration. If stderr closes underneath it -- a piped reader
        that went away -- the command it is decorating may still have useful work
        to finish, and killing it from a daemon thread would turn a cosmetic
        failure into a failed rotation.
        """
        stream = self._out()
        if stream is None:
            return
        try:
            stream.write(text)
            stream.flush()
        except (ValueError, OSError):
            self._stop.set()

    def __enter__(self) -> Spinner:
        if self._enabled:
            # Daemon, so an abrupt exit is never held open by decoration. In
            # practice __exit__ joins it on every path a `with` block has --
            # including KeyboardInterrupt and click.Abort -- so this is the
            # belt on top of the braces.
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Stop, and do not return until the line is clear.

        The join is what orders the clearing *before* whatever the caller prints
        next. The ordering holds when an exception leaves the block, which is the
        path that matters most: the line is blanked, then
        ``sopuli: ORA-12541: ...`` prints at column zero.
        """
        if self._thread is None:
            return
        self._stop.set()
        self._thread.join()
        self._thread = None


#: A spinner that does nothing, for every run that is not an interactive text
#: one. Named rather than built inline so the disabled path is one object with
#: one meaning, and so ``Emitter.spinner`` reads as a decision rather than a
#: constructor call with a confusing argument.
def disabled(message: str = "") -> Spinner:
    """A :class:`Spinner` that starts no thread and writes nothing."""
    return Spinner(message, enabled=False)


def make(message: str, *, stream: TextIO | None = None) -> Spinner:
    """A :class:`Spinner` enabled if — and only if — ``stream`` is a terminal.

    The JSON half of the gate is not here: it belongs to
    :meth:`sopuli.output.emit.Emitter.spinner`, which is the only caller, for the
    reason :func:`~sopuli.output.color.resolve_color` gives for keeping the
    output mode out of *it* — a function that could be asked to animate a JSON
    run and answer yes is a foot-gun for the sake of symmetry.
    """
    target = stream if stream is not None else sys.stderr
    return Spinner(message, enabled=is_a_terminal(target), stream=stream)

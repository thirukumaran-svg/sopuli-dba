"""Standard stream encoding, fixed once at the process boundary.

On Windows, *redirected* stdout uses the locale encoding rather than UTF-8. An
attached console is fine -- Python opens it as UTF-8 -- so this is purely a
redirection problem, and redirection is exactly how a scheduled run gets
captured (``sopuli creds check > nightly.log``). Measured on Python 3.13 with
stdout piped: ``sys.stdout.encoding`` is ``cp1252``, and there are two distinct
failure modes.

Characters *inside* cp1252 -- an em dash, curly quotes -- encode to bytes that a
UTF-8 reader renders as mojibake. Ugly, and recoverable. Characters *outside* it
-- box drawing, check marks, arrows, anything a table or a status column would
want -- raise ``UnicodeEncodeError`` and kill the command mid-write. So a
nightly job does not merely produce an ugly log; it fails, and the failure looks
like the tool's own, not the terminal's. ``click.echo`` does not protect against
either: it strips ANSI, not unrepresentable characters.

Reconfiguring to UTF-8 removes both. It is a no-op wherever the stream is
already UTF-8, which is every POSIX system and every attached Windows console,
so the only behaviour that changes is the one that was broken.

Four things here are decisions rather than obvious lines of code:

**The guard is ``getattr``, not ``isinstance``.** ``sys.stdout`` is ``None``
under ``pythonw.exe`` and is replaced by something else entirely under a test
runner. Asking whether the object can do the thing is more honest than asserting
what it is -- click's ``CliRunner`` stream, for instance, is not
``io.TextIOWrapper`` but does support ``reconfigure``.

**``PYTHONIOENCODING`` is deliberately overridden.** Honouring it would mean
honouring a request to crash. The contract is that sopuli writes UTF-8; that it
is implemented in Python is not something a consumer of the output should have
to know.

**``errors`` is carried over explicitly.** ``reconfigure`` does not preserve it:
given an encoding and no ``errors``, it resets to ``strict``. That is not
harmless, because CPython does not use ``strict`` everywhere -- ``sys.stderr``
defaults to ``backslashreplace`` precisely so that the error path cannot die
inside itself. Silently resetting it would make this fix a regression on the
stream that matters most. So the current value is read off the stream and passed
back, and only the encoding changes.

**Failure is silent.** There is no logging subsystem yet, and the tool's own
prose is ASCII by convention (``tests/test_cli_smoke.py``), so a stream that
refuses to reconfigure still produces correct output. ``sopuli doctor`` can
report the state later by reading ``sys.stdout.encoding`` directly.
"""

from __future__ import annotations

import sys
from typing import TextIO

ENCODING = "utf-8"


def configure_streams() -> None:
    """Force UTF-8 on the standard streams. Call once, at the process boundary.

    Safe to call more than once and safe when a stream is missing, closed, or
    not reconfigurable.
    """
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        reconfigure_stream(stream)


def reconfigure_stream(stream: TextIO | None) -> bool:
    """Switch one stream to UTF-8. Returns whether it worked.

    stdin is included for the same reason as the output streams, in the opposite
    direction: a password read from a redirected stdin under cp1252 is decoded
    wrongly and *silently* -- it becomes a different password, and the failure
    surfaces later as an authentication error against the database. That is a
    worse outcome than the stdout crash, and stdin is one of the ways a password
    arrives (invariant 1: passwords arrive on stdin, a file, or a vault ref --
    never argv).
    """
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        return False

    # Without an explicit `errors`, reconfigure resets it to "strict" -- which
    # would quietly strip stderr of the "backslashreplace" CPython gives it.
    errors = getattr(stream, "errors", None)
    try:
        if errors:
            reconfigure(encoding=ENCODING, errors=errors)
        else:
            reconfigure(encoding=ENCODING)
    except (ValueError, OSError):
        # Detached, closed, or a stream that only pretends to be a text file.
        return False
    return True

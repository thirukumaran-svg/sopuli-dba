"""Whether somebody is watching — one probe, for every question that asks.

There were two before this module (#416's feasibility pass counted them), and
they disagreed on the case that matters:

* ``sopuli.output.color._is_a_terminal`` tolerated a stream that cannot answer —
  closed, detached, or a substitute with no ``isatty`` at all — and read the
  failure as "no".
* ``sopuli.cli._can_prompt`` asked ``sys.stdin.isatty()`` directly, and would
  raise ``ValueError`` on exactly those streams rather than answer.

Both were asking the same question, and the tolerant one is right. Not as a
style preference: **the streams that cannot answer are the ones this question is
being asked about.** A run under a scheduler, a service manager, or a test
harness is precisely where stdin is detached and stderr is a pipe, and it is
precisely where the answer must be "nobody is watching" rather than a traceback
from inside the code that was trying to find out.

A third copy would have been the worst of the available options, so the probe
moved here when the spinner became its third caller.

**It lives in its own module rather than in ``color.py``**, whose docstring is
emphatic that it answers one question — *is colour on?* — and "deliberately stops
there". A stderr spinner importing a TTY probe out of the colour module would
make that false: colour and animation are separate decisions that happen to share
one input, and sharing the input is not a reason to join the decisions.

**On Windows ``isatty()`` is not enough** (#549). It is true for any *character
device*, and ``NUL`` is one — so ``< NUL``, which is what a scheduled task or Git
Bash's ``< /dev/null`` hands a process, answered "somebody is here", and a
confirmation gate prompted, read EOF and aborted instead of refusing with the
message that names ``--confirm``. A Windows console is the handle
``GetConsoleMode`` succeeds on, so that is asked as well. The fix is here rather
than in the prompt gate because every caller asks the same question: colour, the
spinner, and invariant 2's guard 3 all get the stricter answer, and it can only
ever turn a "yes" into a "no".
"""

from __future__ import annotations

import sys
from typing import TextIO


def is_a_terminal(stream: TextIO | None) -> bool:
    """``stream.isatty()``, tolerating streams that cannot answer — and, on
    Windows, only when the stream is a console (#549).

    ``None`` is an answer rather than an error: ``sys.stdin`` and ``sys.stderr``
    are both ``None`` under ``pythonw.exe``, and "there is no stream" is a clear
    case of "nobody is watching".

    If we cannot establish that a human is there, the answer is no — do not
    decorate, do not animate, and do not ask a question nobody can answer.
    """
    if stream is None:
        return False
    isatty = getattr(stream, "isatty", None)
    if isatty is None:
        return False
    try:
        if not isatty():
            return False
    except (ValueError, OSError):
        return False
    return _is_a_windows_console(stream)


def _is_a_windows_console(stream: TextIO) -> bool:
    """Whether a stream that says it is a TTY is a console rather than ``NUL``.

    Only asked of a stream whose ``isatty()`` already said yes. A stream with no
    OS handle behind it — a test double, or a substitute that implements
    ``isatty`` itself — has no device to be ``NUL``, so its own answer stands;
    the check refines ``isatty()`` for real handles and does not replace it.

    Anywhere but Windows ``isatty()`` already means a terminal, so the answer is
    yes. The check sits here, first, rather than in the caller so that mypy
    narrows ``sys.platform`` and does not read the ``msvcrt`` and ``WinDLL``
    calls below on a Linux run -- ``color.enable_virtual_terminal``'s shape.
    """
    if sys.platform != "win32":
        return True
    try:
        fd = stream.fileno()
    except (AttributeError, ValueError, OSError):
        # io.UnsupportedOperation is both a ValueError and an OSError.
        return True

    import ctypes
    import msvcrt
    from ctypes import wintypes

    try:
        handle = msvcrt.get_osfhandle(fd)
    except OSError:
        return False

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # Without argtypes, ctypes would marshal the handle as a 32-bit int and
    # truncate it on 64-bit Windows.
    kernel32.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetConsoleMode.restype = wintypes.BOOL
    mode = wintypes.DWORD()
    return bool(kernel32.GetConsoleMode(handle, ctypes.byref(mode)))

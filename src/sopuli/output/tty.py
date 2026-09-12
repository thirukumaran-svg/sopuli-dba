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
"""

from __future__ import annotations

from typing import TextIO


def is_a_terminal(stream: TextIO | None) -> bool:
    """``stream.isatty()``, tolerating streams that cannot answer.

    ``None`` is an answer rather than an error: ``sys.stdin`` and ``sys.stderr``
    are both ``None`` under ``pythonw.exe``, and "there is no stream" is a clear
    case of "nobody is watching".

    If we cannot establish that a human is there, the answer is no — do not
    decorate, do not animate, and do not ask a question nobody can answer.
    """
    isatty = getattr(stream, "isatty", None)
    if isatty is None:
        return False
    try:
        return bool(isatty())
    except (ValueError, OSError):
        return False

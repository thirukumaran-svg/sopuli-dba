"""Whether output may be decorated at all.

This module answers one question — *is colour on?* — and deliberately stops
there. It does not style anything and owns no palette. What colour *means* is
fixed by the JSON contract's vocabulary (`state`, `by_state`, `drift`,
`unverifiable`, `failed`) and rendered by whichever library wins ADR-003; that
decision is open, and a helper here that wrapped one library's styling would
quietly settle it. The gate and the renderer are separable, so they are
separated.

The control surface is specified in three places already: P4 in
``00-principles.md`` ("ANSI colour, off when not a TTY or ``NO_COLOR``";
Windows "same, with VT mode enabled; plain fallback"), the environment table in
``01-configuration.md`` (``SOPULI_NO_COLOR`` / ``NO_COLOR``), and §1 of
``03-json-output.md`` ("colour when a TTY").

Two rules in :func:`resolve_color` are decisions rather than transcription:

**An explicit flag beats the environment.** ``--color always`` overrides
``NO_COLOR``, and ``--color never`` overrides everything. This follows P3, where
the command line outranks the environment. It does not contradict invariant 10:
that ratchet governs *safety* settings — ``readonly``, ``--dry-run``,
``max_targets``, ``confirm_environments`` — and colour is not one. Nothing
becomes more dangerous because it is red. The ``always`` direction is the point
of the flag: a CI job whose log viewer renders ANSI has no TTY, so autodetection
would strip exactly the output it wants.

**``--output json`` is not consulted here.** The machine stream must never carry
ANSI, but that is the emitter's rule to enforce, and it enforces it by never
asking (see :meth:`sopuli.output.emit.Emitter.use_color`). Passing the output
mode into this function would let a caller resolve colour for a JSON run and get
``True``, which is a foot-gun for the sake of symmetry.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from enum import StrEnum
from typing import TextIO

#: Either of these disables colour, with the meaning no-color.org gives the
#: informal standard: set *and not empty*, whatever the value. `SOPULI_NO_COLOR`
#: outranks the bare `NO_COLOR` under the 01-configuration.md rule that
#: third-party variables rank below their `SOPULI_` equivalents, but since both
#: can only ever disable, the ranking never has to be resolved.
NO_COLOR_VARIABLES = ("SOPULI_NO_COLOR", "NO_COLOR")

#: A terminal that has told us it cannot render escape sequences.
DUMB_TERMINAL = "dumb"

ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004


class ColorChoice(StrEnum):
    """``--color`` values."""

    AUTO = "auto"
    """Colour when the stream is an interactive terminal that can render it."""

    ALWAYS = "always"
    """Colour regardless of detection. For CI logs that render ANSI off-TTY."""

    NEVER = "never"
    """No colour, whatever anything else says."""


def resolve_color(
    choice: ColorChoice,
    *,
    stream: TextIO,
    env: Mapping[str, str],
) -> bool:
    """Decide whether ``stream`` may carry ANSI escape sequences.

    ``env`` is passed in rather than read from ``os.environ`` so this stays a
    pure function of its arguments — tier 0, testable without touching the
    process environment (``04-testing.md`` §4).
    """
    if choice is ColorChoice.NEVER:
        return False
    if choice is ColorChoice.ALWAYS:
        return True

    if any(env.get(name) for name in NO_COLOR_VARIABLES):
        return False
    if env.get("TERM") == DUMB_TERMINAL:
        return False
    if not _is_a_terminal(stream):
        return False
    return enable_virtual_terminal(stream)


def _is_a_terminal(stream: TextIO) -> bool:
    """``stream.isatty()``, tolerating streams that cannot answer.

    A closed or detached stream raises rather than returning ``False``, and a
    substitute stream may not implement the method at all. Either way the answer
    we want is "no": if we cannot establish that a human is watching, do not
    decorate.
    """
    isatty = getattr(stream, "isatty", None)
    if isatty is None:
        return False
    try:
        return bool(isatty())
    except (ValueError, OSError):
        return False


def enable_virtual_terminal(stream: TextIO) -> bool:
    """Turn on ANSI processing for a Windows console. Returns whether it is on.

    This is P4's "with VT mode enabled; plain fallback" — and the fallback is a
    real branch rather than a hope, which is why this returns a bool instead of
    being fire-and-forget. A Windows console with VT off renders escape
    sequences as literal garbage, which is worse than no colour at all.

    Non-Windows platforms have nothing to enable, so the answer is yes.

    No ``colorama``: it is the obvious dependency for this, and taking it would
    prejudge ADR-003 by putting a display library in the tree before the
    decision is made. Twenty lines of ``ctypes`` against two documented
    ``kernel32`` calls is the smaller commitment.
    """
    if sys.platform != "win32":
        return True

    import ctypes
    import msvcrt
    from ctypes import wintypes

    try:
        handle = msvcrt.get_osfhandle(stream.fileno())
    except (ValueError, OSError, AttributeError):
        # No underlying OS handle: a pipe replacement, or a closed stream.
        return False

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # Without argtypes, ctypes would marshal the handle as a 32-bit int and
    # truncate it on 64-bit Windows.
    kernel32.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetConsoleMode.restype = wintypes.BOOL
    kernel32.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.SetConsoleMode.restype = wintypes.BOOL

    mode = wintypes.DWORD()
    if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
        # Not a console -- a pipe or a file. Redirected output is not a TTY, so
        # this is normally unreachable; it stays as the honest answer if it is.
        return False
    if mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING:
        return True
    updated = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
    return bool(kernel32.SetConsoleMode(handle, updated))

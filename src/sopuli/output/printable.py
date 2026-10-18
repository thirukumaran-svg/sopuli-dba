"""Text from outside the tool, made safe to put on a terminal (#859).

ORA- messages, vault error bodies, lock holders and anything else the tool did
not write can carry control characters, and a terminal acts on them: an OSC
sequence (``ESC ] 0;title BEL``) sets the window title, a lone ``\\r`` returns
to the start of the line so the next text overwrites it, ``\\b`` deletes what
was printed, and a colour sequence such as conceal (``ESC [ 8 m``) hides what
follows.

Every one is shown rather than sent: ``\\x1b``, ``\\x07``, ``\\r``. The
operator sees that the text had one, and nothing is acted on. The only escape
sequences written as escapes are the ones the tool's own palette produces
(:func:`ours`), and only when colour is on. With colour off they are removed,
which is what colour off means.

Also shown, as ``\\uXXXX``: the Unicode line and paragraph separators, which
``str.splitlines`` splits on; the bidirectional marks, overrides and isolates,
which reorder what is displayed; and the zero-width and invisible characters,
which make two names look alike.

Pure, and tier 0. JSON output does not pass through here: the encoder escapes
control characters itself, and the document carries the server's text exactly.
"""

from __future__ import annotations

import re
from functools import cache

__all__ = ["ours", "printable", "printable_cell"]

#: A colour sequence (SGR, ``ESC [ ... m``).
_SGR = r"\x1b\[[0-9;]*m"

#: The Unicode characters shown as well as the control ones, named so that the
#: source shows which they are: the soft hyphen (U+00AD), the Arabic letter mark
#: (U+061C), the zero-width characters and the left-to-right and right-to-left
#: marks (U+200B-U+200F), the line and paragraph separators and the
#: bidirectional embeddings and overrides (U+2028-U+202E), the invisible
#: operators (U+2060-U+2064), the bidirectional isolates (U+2066-U+2069), and
#: the byte-order mark (U+FEFF).
_UNICODE = (
    r"\N{SOFT HYPHEN}"
    r"\N{ARABIC LETTER MARK}"
    r"\N{ZERO WIDTH SPACE}-\N{RIGHT-TO-LEFT MARK}"
    r"\N{LINE SEPARATOR}-\N{RIGHT-TO-LEFT OVERRIDE}"
    r"\N{WORD JOINER}-\N{INVISIBLE PLUS}"
    r"\N{LEFT-TO-RIGHT ISOLATE}-\N{POP DIRECTIONAL ISOLATE}"
    r"\N{ZERO WIDTH NO-BREAK SPACE}"
)

#: C0 except the line break and the tab, DEL, C1 (which includes the
#: single-byte CSI ``\x9b`` and OSC ``\x9d``), and :data:`_UNICODE`.
_TEXT = re.compile(rf"{_SGR}|\r\n|[\x00-\x08\x0b-\x1f\x7f-\x9f{_UNICODE}]")

#: The same for a table cell, where the line break and the tab are shown too.
_CELL = re.compile(rf"[\x00-\x1f\x7f-\x9f{_UNICODE}]")


@cache
def ours() -> frozenset[str]:
    """Every escape sequence the tool's own palette writes.

    Computed from the palette rather than listed, so a new role cannot be shown
    as an escape. Imported here, on first use, because the palette imports the
    command modules for their states, and this module is imported by the debug
    logger, which everything imports.
    """
    from sopuli.output.palette import Role, paint

    return frozenset(re.findall(_SGR, "".join(paint("x", role) for role in Role)))


_NAMED = {"\r": "\\r", "\n": "\\n", "\t": "\\t"}


def _shown(character: str) -> str:
    if character in _NAMED:
        return _NAMED[character]
    if ord(character) > 0xFF:
        return f"\\u{ord(character):04x}"
    return f"\\x{ord(character):02x}"


def printable(text: str, *, colour: bool) -> str:
    """``text`` with every control character shown and line breaks kept.

    ``colour`` is whether the stream may carry colour. The palette's own
    sequences (:func:`ours`) are kept where it may and removed where it may not;
    any other escape sequence is shown either way. A ``\\r\\n`` line end becomes
    ``\\n``, so text from a Windows host or an HTTP body does not show a ``\\r``
    on every line.

    **What this cannot tell apart.** By the time text reaches the serialiser,
    the tool's colour and a server's are one string. A server message that uses
    one of the palette's own sequences is therefore treated as the tool's: it
    is written with colour on and removed with it off. Those sequences only set
    a colour, bold or dim, and reset. None of them hides text, moves the cursor
    or sets a title, so the most such a message can do is colour itself.

    **Backslashes are not escaped.** Paths and DSNs carry them, and doubling
    every one would make the common case wrong. So a message containing the
    literal text ``\\x1b`` prints the same as one containing ESC. What this
    guarantees is that no character acts on the terminal, not that the text
    can be decoded back. The JSON document carries the exact text.
    """

    def replace(match: re.Match[str]) -> str:
        token = match.group()
        if token == "\r\n":
            return "\n"
        if len(token) > 1:
            if token in ours():
                return token if colour else ""
            return "\\x1b" + token[1:]
        return _shown(token)

    return _TEXT.sub(replace, text)


def printable_cell(text: str) -> str:
    """``text`` for one table cell: every control character shown, line breaks too.

    A line break or a ``\\r`` in a cell would start a row the table never laid
    out, so a server message could print a row that reads ``ok``. A cell is
    painted after this, so no escape in it is the tool's own.
    """
    return _CELL.sub(lambda match: _shown(match.group()), text)

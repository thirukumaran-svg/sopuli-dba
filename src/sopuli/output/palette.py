"""What colour is allowed to mean (``03-json-output.md`` §1).

:mod:`sopuli.output.color` answers *is colour on*. This answers *what may be
coloured*, and the two are separate on purpose: the gate is a property of the
run, the palette is a property of the thing being rendered.

Two rules from §1 bind everything here, and both are structural rather than
aspirational:

**Colour never carries meaning alone.** Every role below decorates a word that
is already there -- ``prod``, ``override``, ``non-production``, ``-``. Nothing is
distinguishable only by being coloured, so the ``NO_COLOR`` path is lossless by
construction rather than by care, and ``tests/test_palette.py`` asserts exactly
that: strip the escapes and the output is the plain output, byte for byte.

**The palette maps onto what the machine view emits.** §1 wrote that rule
against the result vocabulary (``state``, ``by_state``, ``drift``), because
results were the only text output anticipated. ``config show`` came first and
has no states at all, so these roles map onto the fields its ``config`` section
*does* emit -- ``overridden``, ``environment``, ``non_production``, and absence.
Same vocabulary, reinforced; not a second one that could disagree with it.

The result palette is deliberately absent. Nothing emits a ``state`` yet, and a
mapping written before there is anything to map is the renderer-against-guesses
that ADR-003 and #12 both warn about. It arrives with ``creds check``.

Styling goes through :func:`paint` rather than ``click.style`` at call sites, so
the set of things a role can do stays visible in one file -- and so a renderer
cannot invent a colour that means nothing to anyone else.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

import click


class Role(StrEnum):
    """What a piece of text *is*, never what colour it should be.

    A renderer names the role; this file decides how it looks. That is what
    keeps "yellow" from meaning three different things in three views.
    """

    HEADING = "heading"
    """A section name or a column heading. Structure, not data."""

    MUTED = "muted"
    """A value that is not there. The placeholder is already visible; this stops
    a column of them from competing with the values around it."""

    NOTABLE = "notable"
    """Something that departs from the norm around it and is worth a second
    look: a target an override rewrote, a store marked non-production, a
    warning. Not a problem -- problems get an exit code, not a colour."""

    PRODUCTION = "production"
    """The `prod` environment, wherever it appears. The one distinction on a
    `config show` screen worth finding without reading: `01-configuration.md` §9
    keys `confirm_environments` on it, and it is what `--select env=prod` is
    about to touch."""


#: Role to ``click.style`` keywords. Kept small and conventional on purpose --
#: a palette a reader has to learn is a palette that has stopped helping.
_STYLES: dict[Role, dict[str, Any]] = {
    Role.HEADING: {"bold": True},
    Role.MUTED: {"dim": True},
    Role.NOTABLE: {"fg": "yellow"},
    Role.PRODUCTION: {"fg": "red", "bold": True},
}


def paint(text: str, role: Role | None = None) -> str:
    """Style ``text`` for ``role``, or return it unchanged.

    Never asks whether colour is on. :class:`~sopuli.output.emit.Emitter` owns
    that and strips escapes when the answer is no -- the same shape as redaction,
    where a guarantee held in one place cannot be lost by a call site that
    forgot. A renderer that checked for itself would be a second authority, and
    the two would eventually disagree.

    Empty text is left alone so that a blank cell does not become two escape
    sequences wrapped around nothing.
    """
    if role is None or not text:
        return text
    return click.style(text, **_STYLES[role])

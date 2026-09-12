"""Serialisers — the one place objects become output a user can see.

Two rules are enforced structurally here rather than by convention:

* **Redaction (invariant 2).** :class:`RedactingJSONEncoder` turns any
  :class:`~sopuli.secrets.Secret` into ``***``. A secret cannot reach stdout
  through this path even if a call site forgets it is holding one.
* **Buffering (J1).** ``--output json`` writes one document when the run
  completes. A truncated JSON document is worse than none; streaming is what
  ``jsonl`` is for.
* **Colour is asked for, not decided.** :meth:`Emitter.use_color` is the single
  answer for a run, so no command works out for itself whether ``NO_COLOR`` is
  set, and the machine-readable stream cannot acquire escape sequences. When the
  answer is no, :meth:`Emitter.emit_text` strips ANSI rather than trusting
  callers to have avoided it -- for a run's text half and for ``sopuli about``,
  which is not a run at all (#413).

``jsonl`` is deliberately not offered yet: no command streams anything, and an
output mode that silently behaves like ``json`` would be a lie in the contract.
It arrives with the first command that has per-target events to emit.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, StrEnum
from typing import TYPE_CHECKING, Any, TextIO

import click

from sopuli.output.color import ColorChoice, resolve_color
from sopuli.output.document import to_rfc3339
from sopuli.output.spinner import Spinner
from sopuli.output.spinner import disabled as spinner_disabled
from sopuli.output.spinner import make as make_spinner
from sopuli.secrets import REDACTED, Secret

if TYPE_CHECKING:
    from sopuli.output.document import RunDocument


class OutputMode(StrEnum):
    """``--output`` values. See ``docs/design/03-json-output.md`` section 1."""

    TEXT = "text"
    JSON = "json"


class RedactingJSONEncoder(json.JSONEncoder):
    """JSON encoder that cannot emit a secret in plaintext."""

    def default(self, o: Any) -> Any:
        if isinstance(o, Secret):
            return REDACTED
        if isinstance(o, datetime):
            return to_rfc3339(o)
        if isinstance(o, Enum):
            return o.value
        return super().default(o)


def render_json(document: RunDocument) -> str:
    """Render a run document as the ``--output json`` contract document."""
    return json.dumps(document.to_dict(), cls=RedactingJSONEncoder, indent=2)


@dataclass
class Emitter:
    """Holds the resolved output mode and colour choice for a run.

    The stream and the environment are both resolved at write time rather than
    at construction, and default to the process's own. Capturing ``sys.stdout``
    early would break under test runners that replace it; ``env`` is here for
    the reason :func:`~sopuli.output.color.resolve_color` takes one — it is a
    pure function of its arguments so that colour resolution can be tested
    without the ambient environment deciding the answer. Reading
    ``os.environ`` here would have undone that one layer further out.

    Colour lives here rather than at the call sites for the same reason
    redaction does. A command asks the emitter whether it may decorate; it never
    works that out itself, so there is no code path where a new command forgets
    to check ``NO_COLOR``.
    """

    mode: OutputMode = OutputMode.TEXT
    stream: TextIO | None = None
    #: Where a spinner animates (#419). Separate from :attr:`stream` because the
    #: two are not interchangeable: stdout is the contract and stderr is the
    #: side channel, and a test that redirects one must not silently move the
    #: other. ``None`` means the process's own, resolved at write time like
    #: :attr:`stream`.
    err_stream: TextIO | None = None
    color_choice: ColorChoice = ColorChoice.AUTO
    env: Mapping[str, str] | None = None
    _color: bool | None = field(default=None, init=False, repr=False)

    def _out(self) -> TextIO:
        return self.stream if self.stream is not None else sys.stdout

    def _env(self) -> Mapping[str, str]:
        return self.env if self.env is not None else os.environ

    @property
    def is_json(self) -> bool:
        return self.mode is OutputMode.JSON

    def use_color(self) -> bool:
        """Whether this run's output may carry ANSI escape sequences.

        Resolved once and remembered. Deciding per write would call ``isatty``
        on every line, and — worse — could answer differently within one run if
        the stream were swapped underneath it.

        ``--output json`` is forced off here rather than inside
        :func:`~sopuli.output.color.resolve_color`: the machine stream is a
        contract (invariant 12) and a consumer parsing it must never have to
        strip escape sequences first. ``--color always`` does not override this,
        because it is not a preference about JSON.
        """
        if self._color is not None:
            return self._color
        if self.is_json:
            self._color = False
        else:
            self._color = resolve_color(self.color_choice, stream=self._out(), env=self._env())
        return self._color

    def spinner(self, message: str) -> Spinner:
        """A spinner for one slow call, already gated (#419).

        The gate lives here for the reason :meth:`use_color` does, and the
        docstring there is the whole argument: a command asks the emitter
        whether it may decorate, and never works it out for itself, so there is
        no code path where a new call site forgets to check. A free-standing
        helper that read the output mode and probed the stream at each call site
        would rebuild exactly the decision this class exists to centralise.

        ``--output json`` is refused outright rather than left to the stream
        check. stdout is the contract (invariant 12), and although a spinner
        never writes there, a consumer capturing ``2>&1`` would still find
        frames ahead of the document -- so the machine contract turns the
        animation off rather than relying on which stream it went to. Unlike
        colour, this is not something ``--color always``'s equivalent could
        override, because no such flag exists and #416's non-goals say why.

        Returns a working context manager either way: a disabled spinner starts
        no thread and writes nothing, so no call site needs a branch.
        """
        if self.is_json:
            return spinner_disabled(message)
        return make_spinner(message, stream=self.err_stream)

    def emit(self, document: RunDocument, text: str) -> None:
        """Write the run: the JSON document, or the human text, never both.

        The text half goes through :meth:`emit_text`, which is where colour is
        stripped when it is off -- rather than avoided upstream. That is the same
        shape as redaction: a guarantee held at the serialiser cannot be lost by
        a call site that forgot. ``NO_COLOR`` promises that no ANSI reaches the
        stream, and that is what makes the promise true of anything the renderer
        produces -- and of a vendor message that arrives already decorated.
        """
        if self.is_json:
            print(render_json(document), file=self._out())
            return
        self.emit_text(text)

    def emit_text(self, text: str) -> None:
        """Write human text through the colour gate, with no document behind it.

        :meth:`emit` is the whole of a run: a document, or the text that stands
        in for it. ``sopuli about`` is the one command that is not a run at all
        (#413) -- it takes no options, reads nothing, resolves no settings and
        has no ``--output json`` form to be the machine half of. It still must
        not put escape sequences on a stream that ``NO_COLOR`` has spoken for,
        and that promise is kept here rather than by a second ``unstyle`` call in
        a command body.

        Splitting this out rather than handing `about` a document is what keeps
        the document honest: every ``RunDocument`` describes something the tool
        did to an estate, and one carrying a `command` that acts on nothing would
        be a JSON contract entry for a screen that has no JSON form.

        Stripping only ever removes, so it commits to nothing that ADR-003 has
        to decide. ``click.unstyle`` is the existing CLI dependency's own
        function for it, not a display-library choice.
        """
        if not self.use_color():
            text = click.unstyle(text)
        print(text.rstrip("\n"), file=self._out())

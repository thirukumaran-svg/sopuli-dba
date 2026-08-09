"""Serialisers — the one place objects become output a user can see.

Two rules are enforced structurally here rather than by convention:

* **Redaction (invariant 2).** :class:`RedactingJSONEncoder` turns any
  :class:`~sopuli.secrets.Secret` into ``***``. A secret cannot reach stdout
  through this path even if a call site forgets it is holding one.
* **Buffering (J1).** ``--output json`` writes one document when the run
  completes. A truncated JSON document is worse than none; streaming is what
  ``jsonl`` is for.

``jsonl`` is deliberately not offered yet: no command streams anything, and an
output mode that silently behaves like ``json`` would be a lie in the contract.
It arrives with the first command that has per-target events to emit.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, StrEnum
from typing import TYPE_CHECKING, Any, TextIO

from sopuli.output.document import to_rfc3339
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
    """Holds the resolved output mode for a run.

    The stream is resolved at write time, not at construction: capturing
    ``sys.stdout`` early would break under test runners that replace it.
    """

    mode: OutputMode = OutputMode.TEXT
    stream: TextIO | None = None

    def _out(self) -> TextIO:
        return self.stream if self.stream is not None else sys.stdout

    @property
    def is_json(self) -> bool:
        return self.mode is OutputMode.JSON

    def emit(self, document: RunDocument, text: str) -> None:
        """Write the run: the JSON document, or the human text, never both."""
        if self.is_json:
            print(render_json(document), file=self._out())
        else:
            print(text.rstrip("\n"), file=self._out())

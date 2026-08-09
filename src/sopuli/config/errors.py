"""Configuration errors, and the breadcrumb that makes them locatable.

A config file for this tool is long -- the worked example in
``01-configuration.md`` §2 is ~130 lines before anyone adds a second
application -- and the thing that has gone wrong is usually one key deep inside
it. "invalid config" is not an error message; it is an invitation to read the
whole file.

So every error carries a location, and there are two independent sources of one:

* **Parse errors** know a line and column, because PyYAML's marks say so.
* **Validation errors** know a :class:`KeyPath` -- ``applications[1].policy`` --
  because validation built one on the way down.

Both render through the same message shape, so a user never has to learn two.

``ConfigError`` is a plain exception rather than a ``ClickException``. The
loader is meant to stay usable without the CLI around it, and tier 0 keeps these
layers free of anything they do not need (``04-testing.md`` §4). The mapping to
a process exit code happens once, at the CLI boundary in ``sopuli.cli.main``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from sopuli.exit_codes import ExitCode

if TYPE_CHECKING:
    from yaml.error import Mark


@dataclass(frozen=True)
class KeyPath:
    """Where in the document we are, written the way a user would say it.

    Immutable and built by descent -- ``ROOT.key("applications").index(1)`` --
    so a validator can pass its own position down without any caller having to
    remember to undo it afterwards.
    """

    parts: tuple[str | int, ...] = ()

    def key(self, name: str) -> KeyPath:
        """Descend into a mapping key."""
        return KeyPath((*self.parts, name))

    def index(self, position: int) -> KeyPath:
        """Descend into a sequence element."""
        return KeyPath((*self.parts, position))

    def __bool__(self) -> bool:
        return bool(self.parts)

    def __str__(self) -> str:
        rendered = ""
        for part in self.parts:
            if isinstance(part, int):
                rendered += f"[{part}]"
            elif rendered:
                rendered += f".{part}"
            else:
                rendered = part
        return rendered


#: The document itself. Errors about the file as a whole point here.
ROOT = KeyPath()


class ConfigError(Exception):
    """A config file is unusable, with enough detail to go and fix it.

    Carries its own ``exit_code`` because P5 puts config validation on 2 with
    usage errors, not on 1 with generic failures -- a scheduler distinguishes
    "you typed it wrong" from "it broke".
    """

    exit_code = ExitCode.USAGE

    def __init__(
        self,
        message: str,
        *,
        source: Path | None = None,
        at: KeyPath = ROOT,
        line: int | None = None,
        column: int | None = None,
        hint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.source = source
        self.at = at
        self.line = line
        self.column = column
        self.hint = hint

    def __str__(self) -> str:
        """Render as ``file:line:col: key.path: message``, hint on its own line.

        Every part is optional except the message, and each is omitted rather
        than filled with a placeholder -- ``sopuli.yaml:?:?:`` tells a reader
        nothing except that the tool did not know.
        """
        prefix = []
        if self.source is not None:
            location = str(self.source)
            if self.line is not None:
                location += f":{self.line}"
                if self.column is not None:
                    location += f":{self.column}"
            prefix.append(location)
        elif self.line is not None:
            # No file to name -- parsing a string, which is how the tests and any
            # future `--config -` would come through. The location is still the
            # useful part, so it is spelled out rather than dropped.
            location = f"line {self.line}"
            if self.column is not None:
                location += f" column {self.column}"
            prefix.append(location)
        if self.at:
            prefix.append(str(self.at))

        rendered = ": ".join([*prefix, self.message])
        if self.hint:
            rendered += f"\n  hint: {self.hint}"
        return rendered


def location_of(mark: Mark | None) -> tuple[int | None, int | None]:
    """Turn a PyYAML mark into a line and column a human would recognise.

    PyYAML counts from zero. Editors count from one, and the point of the
    number is to be typed into one.
    """
    if mark is None:
        return None, None
    return mark.line + 1, mark.column + 1

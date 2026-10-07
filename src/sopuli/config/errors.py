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

    Carries its own ``exit_code`` because P5 gives a bad configuration a code of
    its own rather than folding it into generic failure -- a scheduler
    distinguishes "fix your file" from "it broke", and the first is the failure
    an operator can act on.

    Not exit 2. That is the *pre-invocation* code, and a config error is the
    opposite case: argv resolved, the run began, and then the file it was told to
    read turned out to be unusable. J7 puts the seam exactly there, so that this
    can carry a run document while a usage error cannot.
    """

    exit_code = ExitCode.CONFIG_INVALID

    #: ``error.category`` in the run document, from the schema's closed enum.
    #: Carried by the exception so the boundary reports what was wrong rather
    #: than inferring it from the exception's type -- which is the mapping that
    #: goes wrong first when a subclass is added.
    category = "config"

    #: ``error.code`` in the run document, where this condition has one from the
    #: registry in ``03-json-output.md`` §3. ``None`` for the ordinary case: most
    #: config errors are "this key is wrong", which a consumer handles by showing
    #: the message rather than by branching. A subclass sets it when the
    #: condition is specific enough that a scheduler would want to act on *that*
    #: failure and not on config errors generally -- see
    #: :class:`~sopuli.store.registry.BackendNotInstalledError`.
    code: str | None = None

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

    @property
    def located(self) -> str:
        """``file:line:col: key.path: message`` -- everything but the hint.

        Split out of :meth:`__str__` because the JSON contract's ``error`` object
        has a ``hint`` field of its own and **no location field at all**
        (``03-json-output.md`` §4). So the location has to travel inside the
        message there, and the hint must not -- otherwise a consumer gets the
        hint twice and a newline in the middle of a string it is going to render
        in a table. Same rendering either way, which is what keeps the message a
        reader sees on stderr and the one a scheduler parses from being two
        different descriptions of one problem.
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

        return ": ".join([*prefix, self.message])

    def __str__(self) -> str:
        """The located message, with the hint on its own line.

        Every part is optional except the message, and each is omitted rather
        than filled with a placeholder -- ``sopuli.yaml:?:?:`` tells a reader
        nothing except that the tool did not know.
        """
        if self.hint:
            return f"{self.located}\n  hint: {self.hint}"
        return self.located


class ArgumentError(ConfigError):
    """Something on the *command line* is unusable, not something in a file.

    A ``--select`` value that is not ``key=value`` is the case that needs this:
    it is parsed in the config layer, which must not import click
    (``04-testing.md`` §4 keeps tier 0 free of I/O and of the CLI), so
    ``click.UsageError`` is not available where the problem is found.

    Everything about it is a :class:`ConfigError` except the exit code, and that
    is the whole point. J7 puts the seam at "did the invocation resolve": a
    malformed selector means it did not, so this exits 2 and carries no run
    document, while its parent exits 9 and does. The boundary needs no special
    case -- it already exits with ``exc.exit_code``.

    Refusals found *in* the CLI raise ``click.UsageError`` directly. This exists
    for the layers that cannot.
    """

    exit_code = ExitCode.USAGE


def location_of(mark: Mark | None) -> tuple[int | None, int | None]:
    """Turn a PyYAML mark into a line and column a human would recognise.

    PyYAML counts from zero. Editors count from one, and the point of the
    number is to be typed into one.
    """
    if mark is None:
        return None, None
    return mark.line + 1, mark.column + 1

"""Reading typed values out of raw YAML, with the key path attached.

Every section of the config has the same handful of needs: *this key must be a
string*, *this one a list of strings*, *no key here may be one I do not know*.
Written per section, that becomes a dozen slightly different phrasings of the
same error, and a user learns each one separately.

So they live here once, and each takes the :class:`KeyPath` of the thing it is
reading. That path is the whole point — "invalid config" is not an error message
for a file this long, and threading a breadcrumb down through the builders is
what turns it into ``applications[1].secret_template``.

Two conventions worth stating, because they shape every caller:

**Absent and wrong are different failures.** A missing optional key returns
``None``; a key that is present with the wrong type raises. Callers never have to
tell those apart from a single return value.

**Types are named the way a YAML author thinks of them** — "a mapping", "a list",
"a string" — not as Python type names. Someone editing a config file has never
heard of ``dict``.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sopuli.config.errors import ConfigError, KeyPath

#: How each Python type reads in an error message. `bool` is listed before `int`
#: because it is a subclass of it and would otherwise be described as a number.
_TYPE_NAMES: tuple[tuple[type, str], ...] = (
    (dict, "a mapping"),
    (list, "a list"),
    (str, "a string"),
    (bool, "a boolean"),
    (int, "a number"),
    (float, "a number"),
    (type(None), "nothing"),
)


def describe(value: Any) -> str:
    """Name a value's type the way a YAML author thinks of it."""
    for candidate, name in _TYPE_NAMES:
        if isinstance(value, candidate):
            return name
    return type(value).__name__


def mapping(value: Any, *, at: KeyPath) -> dict[str, Any]:
    """Require a mapping with string keys."""
    if not isinstance(value, dict):
        raise ConfigError(f"must be a mapping, not {describe(value)}", at=at)
    for key in value:
        if not isinstance(key, str):
            raise ConfigError(f"key {key!r} must be a string, not {describe(key)}", at=at)
    return value


def sequence(value: Any, *, at: KeyPath) -> list[Any]:
    """Require a list."""
    if not isinstance(value, list):
        raise ConfigError(f"must be a list, not {describe(value)}", at=at)
    return value


def string(value: Any, *, at: KeyPath) -> str:
    """Require a non-empty string.

    Empty is rejected along with the wrong type because an empty string in this
    file is never meaningful -- ``policy: ""`` names no policy, and silently
    treating it as absent would hide a half-finished edit.
    """
    if not isinstance(value, str):
        raise ConfigError(f"must be a string, not {describe(value)}", at=at)
    if not value.strip():
        raise ConfigError("must not be empty", at=at)
    return value


def optional_string(container: dict[str, Any], key: str, *, at: KeyPath) -> str | None:
    """A string if the key is present, ``None`` if it is not."""
    if key not in container:
        return None
    return string(container[key], at=at.key(key))


def string_list(value: Any, *, at: KeyPath) -> tuple[str, ...]:
    """Require a list of non-empty strings, reporting the offending element.

    The index matters: ``accounts[3]`` sends someone to the right line, where
    "accounts must be a list of strings" sends them to re-read all six.
    """
    items = sequence(value, at=at)
    return tuple(string(item, at=at.index(index)) for index, item in enumerate(items))


def reject_unknown_keys(container: dict[str, Any], *, allowed: Iterable[str], at: KeyPath) -> None:
    """§9: unknown keys are an error, not a warning.

    A typo in a credential tool must never be silently ignored (P3). ``secret_tmplate``
    that is quietly dropped means the tool falls back to some other secret, which
    is the failure mode with the worst consequences.

    The message lists what *was* allowed, sorted. A rejection that does not say
    what the alternatives were leaves someone guessing at spelling.
    """
    permitted = set(allowed)
    unknown = sorted(key for key in container if key not in permitted)
    if not unknown:
        return
    named = ", ".join(repr(key) for key in unknown)
    raise ConfigError(
        f"unknown {'keys' if len(unknown) > 1 else 'key'} {named}",
        at=at,
        hint=f"known keys here: {', '.join(sorted(permitted))}",
    )

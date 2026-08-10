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
from sopuli.config.model import Pairs

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


def required_string(
    container: dict[str, Any], key: str, *, at: KeyPath, hint: str | None = None
) -> str:
    """A string that has to be there."""
    if key not in container:
        raise ConfigError("must be given", at=at.key(key), hint=hint)
    return string(container[key], at=at.key(key))


def choice(value: Any, *, allowed: Iterable[str], at: KeyPath, noun: str) -> str:
    """A string from a closed set.

    Closed rather than free-form wherever the value selects behaviour -- a
    driver, a scope, an auth method. A free string means ``scope: cdb-root``
    loads happily and the tool then connects somewhere other than where the
    author meant, which is the class of failure invariant 5 and §9 exist to stop.
    Widening a set is a one-line change once the reference names the new value.
    """
    text = string(value, at=at)
    permitted = tuple(allowed)
    if text not in permitted:
        raise ConfigError(
            f"unknown {noun} {text!r}",
            at=at,
            hint=f"known: {', '.join(permitted)}",
        )
    return text


def optional_bool(container: dict[str, Any], key: str, *, at: KeyPath) -> bool | None:
    """A boolean if the key is present, ``None`` if it is not.

    Only a real boolean is accepted. ``readonly: "true"`` is a string, and
    treating a non-empty string as truthy would mean ``readonly: "false"``
    silently turning writes off -- or, worse, some future flag silently turning a
    guard off.
    """
    if key not in container:
        return None
    value = container[key]
    if not isinstance(value, bool):
        raise ConfigError(
            f"must be true or false, not {describe(value)}",
            at=at.key(key),
            hint="unquoted `true` or `false`; the hardened loader keeps `yes`/`no` as strings",
        )
    return value


def optional_int(container: dict[str, Any], key: str, *, at: KeyPath) -> int | None:
    """An integer if the key is present, ``None`` if it is not.

    ``bool`` is rejected explicitly because it is a subclass of ``int``:
    ``kv_version: true`` would otherwise be read as version 1.
    """
    if key not in container:
        return None
    value = container[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"must be a number, not {describe(value)}", at=at.key(key))
    return value


def pairs(value: Any, *, at: KeyPath) -> Pairs:
    """A mapping of names to string values, sorted for determinism.

    Labels and label matches are both this shape. Sorting is what makes error
    messages and plan output depend on the estate rather than on YAML key order.
    """
    labels = mapping(value, at=at)
    return tuple(sorted((key, string(item, at=at.key(key))) for key, item in labels.items()))


def label_selector(value: Any, *, at: KeyPath) -> Pairs:
    """A label match that has to select *something*.

    The same shape as a target's ``labels:``, with one rule added: it may not be
    empty. A group or an override whose match is ``{}`` applies to every target
    in the estate, which is never what was meant by writing an exception.
    """
    selected = pairs(value, at=at)
    if not selected:
        raise ConfigError("must name at least one label", at=at)
    return selected


def string_list(value: Any, *, at: KeyPath) -> tuple[str, ...]:
    """Require a list of non-empty strings, reporting the offending element.

    The index matters: ``accounts[3]`` sends someone to the right line, where
    "accounts must be a list of strings" sends them to re-read all six.
    """
    items = sequence(value, at=at)
    return tuple(string(item, at=at.index(index)) for index, item in enumerate(items))


def reject_unknown_keys(
    container: dict[str, Any], *, allowed: Iterable[str], at: KeyPath, hint: str | None = None
) -> None:
    """§9: unknown keys are an error, not a warning.

    A typo in a credential tool must never be silently ignored (P3). ``secret_tmplate``
    that is quietly dropped means the tool falls back to some other secret, which
    is the failure mode with the worst consequences.

    The message lists what *was* allowed, sorted. A rejection that does not say
    what the alternatives were leaves someone guessing at spelling. Pass ``hint``
    where the key is not a typo but something the reference has not specified
    yet, and listing the known keys would answer the wrong question.
    """
    permitted = set(allowed)
    unknown = sorted(key for key in container if key not in permitted)
    if not unknown:
        return
    named = ", ".join(repr(key) for key in unknown)
    raise ConfigError(
        f"unknown {'keys' if len(unknown) > 1 else 'key'} {named}",
        at=at,
        hint=hint if hint is not None else f"known keys here: {', '.join(sorted(permitted))}",
    )

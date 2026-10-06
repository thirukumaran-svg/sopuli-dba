"""§8's charsets, as characters rather than as prose.

Two things need the charsets as data: :mod:`sopuli.passwords`, which draws
from them, and :mod:`sopuli.config.policies`, which has to answer whether a
``require:`` block is satisfiable by the alphabet the policy actually chose.

**Character classes are defined here too**, because "is this a special
character" is the same question in both places. A class is upper, lower or
digit; ``special`` is *everything else in the alphabet*. That definition is what
makes ``require: { special: 1 }`` answerable for ``charset: custom``, where the
alphabet is whatever somebody typed.

**Why this lives in the config layer.** ``config/policies.py`` validates a
policy against it, and the config layer does no I/O. A leaf module inside the
layer keeps validation free of the generator: nothing here imports it.

One deliberate difference from a plain reading of "printable ASCII":
``printable_ascii`` is printable ASCII except space **and except** ``"``.
Invariant 11 rejects a password containing ``"`` rather than escaping it -- Oracle
quoted identifiers have no escape for it -- so an alphabet containing one could
only ever produce candidates that are thrown away.
"""

from __future__ import annotations

import string
import unicodedata
from collections.abc import Mapping
from types import MappingProxyType

from sopuli.config.errors import ConfigError
from sopuli.config.model import PasswordPolicy

#: The character §8 excludes from every password, whatever the charset
#: (invariant 11, ``02-oracle-privileges.md`` §4).
FORBIDDEN = '"'

UPPER = string.ascii_uppercase
LOWER = string.ascii_lowercase
DIGIT = string.digits

#: §8's nine additions to ``alnum``: they avoid shell, connection-string and
#: SQL-quoting hazards.
SAFE_SPECIALS = "_#$-.+=~^"

#: The same nine as §8 and §2 write them in prose, for an error message.
SAFE_SPECIALS_SPACED = " ".join(SAFE_SPECIALS)

#: Printable ASCII without space -- ``0x21`` to ``0x7E`` inclusive.
PRINTABLE_ASCII = "".join(chr(point) for point in range(0x21, 0x7F))

#: The classes ``require:`` counts, in the order §8 lists them. ``policies.py``
#: takes its ``REQUIRE_KEYS`` from this, so the two cannot drift -- the published
#: schema generates its ``require`` properties from that same tuple.
CLASS_NAMES = ("upper", "lower", "digit", "special")

#: The three classes with a fixed membership. Anything else in an alphabet is
#: ``special``, which is why that one is absent from this table.
CLASSES = {"upper": UPPER, "lower": LOWER, "digit": DIGIT}

SPECIAL = "special"

CUSTOM = "custom"

#: The one value §8 documents for ``first_char``. Named here because the rule it
#: states -- start with a letter -- is about these classes.
ALPHA = "alpha"

#: §8 names ``alnum_safe`` the default charset. Unlike ``length``, which §8 gives
#: no default for and :func:`sopuli.passwords.generate` therefore refuses to
#: invent, this default is written down -- so resolving it is following the
#: reference rather than choosing entropy on somebody's behalf.
DEFAULT_CHARSET = "alnum_safe"


def _usable(characters: str) -> str:
    """An alphabet with the forbidden character removed, order preserved."""
    return "".join(character for character in characters if character != FORBIDDEN)


#: §8's table. Already free of ``"``: an alphabet that contained it would only
#: produce candidates the same module then rejects.
#:
#: Read-only, like every other constant in this layer is a tuple. The alphabet a
#: password is drawn from is not something a later import should be able to widen.
ALPHABETS: Mapping[str, str] = MappingProxyType(
    {
        "alnum": UPPER + LOWER + DIGIT,
        "alnum_safe": UPPER + LOWER + DIGIT + SAFE_SPECIALS,
        "printable_ascii": _usable(PRINTABLE_ASCII),
    }
)


def alphabet(policy: PasswordPolicy) -> str:
    """The characters this policy's passwords may be built from.

    ``charset: custom`` uses its own ``allow:``; anything else uses §8's table,
    defaulting to ``alnum_safe``. ``"`` is removed either way -- ``policies.py``
    already refuses it in an ``allow:``, and doing it here as well means no caller
    can be handed an alphabet that produces unusable passwords.

    **The gate for whether a policy has an alphabet at all.** A policy read from a
    file cannot fail here: :mod:`sopuli.config.policies` validates the charset
    against a closed set and pairs ``allow:`` with ``custom`` before anything asks
    for an alphabet, and its errors carry a key path this function has no way to
    know. But :class:`~sopuli.config.model.PasswordPolicy` is an ordinary frozen
    dataclass that a command or a test may build directly, and for those three
    shapes the alternative is worse than an error:

    * an unknown charset would be a bare ``KeyError`` out of a dict lookup
    * ``allow:`` beside a named charset would be *silently ignored*, so the caller
      would get passwords from an alphabet other than the one it asked for
    * ``charset: custom`` with nothing allowed would be an empty alphabet, which
      reads as "no characters are permitted" rather than as the unfinished policy
      it is

    So they are refused here, once, where the alphabet is resolved -- rather than
    at each of the two entry points in :mod:`sopuli.passwords`, which would be the
    same rule written twice.
    """
    if policy.charset == CUSTOM:
        if not policy.allow:
            raise ConfigError(
                f"`charset: {CUSTOM}` must say what it allows",
                hint="give `allow:` the characters a password may be built from",
            )
        return _usable(policy.allow)

    if policy.allow is not None:
        named = "no charset" if policy.charset is None else f"`charset: {policy.charset}`"
        raise ConfigError(
            f"`allow:` only applies to `charset: {CUSTOM}`, but this policy sets {named}",
            hint=f"the named charsets are fixed (§8): {_known()}",
        )

    name = policy.charset if policy.charset is not None else DEFAULT_CHARSET
    if name not in ALPHABETS:
        raise ConfigError(f"unknown charset {name!r}", hint=f"known: {_known()}")
    return ALPHABETS[name]


def _known() -> str:
    """§8's charset names, for an error message."""
    return ", ".join((*ALPHABETS, CUSTOM))


def class_of(character: str) -> str:
    """Which ``require:`` class a character counts towards."""
    for name, members in CLASSES.items():
        if character in members:
            return name
    return SPECIAL


def counts(text: str) -> dict[str, int]:
    """How many characters of each class ``text`` holds.

    Every class is present in the result, zero included, so a caller comparing
    against a ``require:`` block never has to distinguish "none" from "not
    counted".
    """
    tally = dict.fromkeys(CLASS_NAMES, 0)
    for character in text:
        tally[class_of(character)] += 1
    return tally


def classes_present(characters: str) -> frozenset[str]:
    """Which classes an alphabet can produce at all.

    The question behind every "no password could satisfy this" rule: asking for a
    special character from an alphabet that has none is not strictness, it is a
    policy that can never be met.
    """
    return frozenset(class_of(character) for character in characters)


def has_letters(characters: str) -> bool:
    """Whether ``first_char: alpha`` is satisfiable from this alphabet."""
    return any(character in UPPER or character in LOWER for character in characters)


def is_control(character: str) -> bool:
    """Whether a character is a control character, ``CHR(0)`` included.

    ``02-oracle-privileges.md`` §4 rejects these in a password: the statement is
    built as a quoted literal, and a control character in one is at best
    unusable and at worst something else entirely. Read from the Unicode category
    rather than a range, so the C1 block (``0x80``--``0x9F``) counts too.
    """
    return unicodedata.category(character) == "Cc"

"""Building the ``policies:`` section -- password rules, rotation, verification.

Most of this is reading closed sets and range-checking numbers. Three rules earn
their place by catching a config that looks fine and cannot work:

* **invariant 11 and the rest of what cannot be in a password** -- a `"` in a
  custom charset, because Oracle quoted identifiers have no escape for it, and a
  control character, because the same section rejects those too
  (``02-oracle-privileges.md`` §4). The generator enforces that on what it
  produces; here the same rules are applied to the alphabet it produces *from*,
  which is the only place a config file can name such a character at all.
* **`require` cannot exceed `length`** -- ask for 30 characters of each class in
  a 24-character password and generation never terminates.
* **`require:` asking for a class the alphabet does not have** -- the same
  impossibility, one step less obvious. Answered against the *real* alphabet
  (:mod:`sopuli.config.charsets`), so it holds for `charset: custom` as well as
  for the named sets, and covers `first_char: alpha` against an alphabet with no
  letters.

All are the same kind of failure: a file nobody could look at and see was wrong,
which would surface as a hung or looping rotation rather than as an error.
"""

from __future__ import annotations

from typing import Any

from sopuli.config import charsets
from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.fields import (
    choice,
    mapping,
    optional_bool,
    optional_int,
    optional_string,
    reject_unknown_keys,
)
from sopuli.config.model import (
    AccountPolicy,
    PasswordPolicy,
    Policy,
    RotationPolicy,
    VerifyPolicy,
)

POLICY_KEYS = ("password", "rotation", "verify", "account")

PASSWORD_KEYS = ("length", "charset", "allow", "first_char", "require")

#: §8's table. `custom` is the only one that reads `allow:`; the others are the
#: named alphabets in :mod:`sopuli.config.charsets`, which is where §8's table
#: exists as characters.
CHARSETS = (*charsets.ALPHABETS, charsets.CUSTOM)

#: §8 documents one value. Omitting the key means no constraint, so there is no
#: need for an "any" spelling and no reason to invent one.
FIRST_CHARS = (charsets.ALPHA,)

#: The classes `require:` counts. Taken from the charset module rather than
#: written again, so the alphabet's idea of a class and the config key that
#: demands one cannot drift -- the published schema generates from this too.
REQUIRE_KEYS = charsets.CLASS_NAMES

ROTATION_KEYS = ("strategy", "rollover_hours", "keep_previous", "max_age_days")

#: UC-1 §6: rollover where the capability exists, staged where it does not,
#: direct when a leak means the old password must die immediately.
ROTATION_STRATEGIES = ("rollover", "staged", "direct")

VERIFY_KEYS = ("method", "lockout_margin")

VERIFY_METHODS = ("login", "hash", "both", "none")

ACCOUNT_KEYS = ("unlock_if_locked", "profile")


def build_policies(document: dict[str, Any]) -> tuple[Policy, ...]:
    """Read ``policies:`` into entries, in document order."""
    if "policies" not in document:
        return ()

    at = ROOT.key("policies")
    entries = mapping(document["policies"], at=at)
    return tuple(_build_policy(name, entry, at=at.key(name)) for name, entry in entries.items())


def _build_policy(name: str, raw: Any, *, at: KeyPath) -> Policy:
    entry = mapping(raw, at=at)
    reject_unknown_keys(entry, allowed=POLICY_KEYS, at=at)

    return Policy(
        name=name,
        password=_build_password(entry.get("password"), at=at.key("password")),
        rotation=_build_rotation(entry.get("rotation"), at=at.key("rotation")),
        verify=build_verify(entry.get("verify"), at=at.key("verify")),
        account=_build_account(entry.get("account"), at=at.key("account")),
    )


# ------------------------------------------------------------- password ---


def _build_password(raw: Any, *, at: KeyPath) -> PasswordPolicy:
    if raw is None:
        return PasswordPolicy()
    block = mapping(raw, at=at)
    reject_unknown_keys(block, allowed=PASSWORD_KEYS, at=at)

    charset = block.get("charset")
    policy = PasswordPolicy(
        length=_positive(block, "length", at=at),
        charset=(
            None
            if charset is None
            else choice(charset, allowed=CHARSETS, at=at.key("charset"), noun="charset")
        ),
        allow=optional_string(block, "allow", at=at),
        first_char=_build_first_char(block, at=at),
        require=_build_require(block.get("require"), at=at.key("require")),
    )

    _require_allow_matches_charset(policy, at=at)
    _reject_unusable_characters(policy, at=at)
    _require_satisfiable(policy, at=at)
    return policy


def _build_first_char(block: dict[str, Any], *, at: KeyPath) -> str | None:
    first_char = block.get("first_char")
    if first_char is None:
        return None
    return choice(first_char, allowed=FIRST_CHARS, at=at.key("first_char"), noun="first_char rule")


def _build_require(raw: Any, *, at: KeyPath) -> tuple[tuple[str, int], ...]:
    if raw is None:
        return ()
    block = mapping(raw, at=at)
    reject_unknown_keys(block, allowed=REQUIRE_KEYS, at=at)

    # Iterating the known keys rather than the block's own: unknown ones are
    # already rejected, and this way the reader never has to hold a `None` that
    # cannot happen.
    counts: list[tuple[str, int]] = []
    for key in REQUIRE_KEYS:
        count = optional_int(block, key, at=at)
        if count is None:
            continue
        if count < 0:
            raise ConfigError(f"cannot require {count} characters", at=at.key(key))
        counts.append((key, count))
    return tuple(sorted(counts))


def _require_allow_matches_charset(policy: PasswordPolicy, *, at: KeyPath) -> None:
    """``allow:`` belongs to ``charset: custom`` and to nothing else."""
    if policy.charset == "custom" and policy.allow is None:
        raise ConfigError(
            "`charset: custom` must say what it allows",
            at=at.key("allow"),
            hint="give `allow:` the characters a password may be built from",
        )
    if policy.allow is not None and policy.charset != "custom":
        named = "no charset" if policy.charset is None else f"`charset: {policy.charset}`"
        raise ConfigError(
            f"`allow:` only applies to `charset: custom`, but this policy sets {named}",
            at=at.key("allow"),
            hint="the named charsets are fixed (§8); delete `allow:` or switch to `custom`",
        )


def _reject_unusable_characters(policy: PasswordPolicy, *, at: KeyPath) -> None:
    """What a password may not contain, at the only place a file can name it.

    Rejected rather than quietly dropped from the alphabet: a charset that
    silently differs from what the file says is how somebody ends up believing
    their passwords have a character class they do not have.

    Both rules come from ``02-oracle-privileges.md`` §4, which builds
    ``ALTER USER ... IDENTIFIED BY "<password>"`` as a quoted literal. A `"` has
    no escape in one (invariant 11), and a control character in one is at best
    unusable.
    """
    if policy.allow is None:
        return
    if charsets.FORBIDDEN in policy.allow:
        raise ConfigError(
            'a custom charset may not contain `"`',
            at=at.key("allow"),
            hint=(
                "Oracle quoted identifiers have no escape for it, so such a password "
                "could not be set at all (02-oracle-privileges.md §4)"
            ),
        )
    controls = sum(1 for character in policy.allow if charsets.is_control(character))
    if controls:
        raise ConfigError(
            f"a custom charset may not contain control characters, and this one has {controls}",
            at=at.key("allow"),
            hint=(
                "02-oracle-privileges.md §4 rejects them in a password, CHR(0) included, "
                "so they could only ever produce candidates the generator throws away"
            ),
        )


def _require_satisfiable(policy: PasswordPolicy, *, at: KeyPath) -> None:
    """A policy no password of this length and charset can meet.

    Every case below is generation looping or failing forever, reported instead
    while somebody is looking at the file. They are answered against the alphabet
    the policy actually chose (:mod:`sopuli.config.charsets`), so a hand-written
    ``allow:`` is held to the same standard as a named charset -- it is the one
    more likely to be missing a class, since nobody checks a string of punctuation
    by eye.
    """
    demanded = sum(count for _, count in policy.require)
    if policy.length is not None and demanded > policy.length:
        raise ConfigError(
            f"`require:` asks for {demanded} characters but `length:` is {policy.length}",
            at=at.key("require"),
            hint="no password can satisfy this, so generation would never succeed",
        )

    alphabet = charsets.alphabet(policy)
    present = charsets.classes_present(alphabet)
    for name, count in policy.require:
        if count and name not in present:
            raise ConfigError(
                f"{_names(policy)} has no {name} characters, but `require:` asks for {count}",
                at=at.key("require").key(name),
                hint=_widen(policy, name),
            )

    if policy.first_char == charsets.ALPHA and not charsets.has_letters(alphabet):
        raise ConfigError(
            f"`first_char: {charsets.ALPHA}` needs a letter, but {_names(policy)} has none",
            at=at.key("first_char"),
            hint="no password can satisfy this, so generation would never succeed",
        )


def _names(policy: PasswordPolicy) -> str:
    """How to refer to this policy's alphabet in a message.

    A named charset is named; a custom one is the key that holds it, because
    quoting the characters back would be quoting the line the reader is looking at.
    """
    if policy.charset == charsets.CUSTOM:
        return "`allow:`"
    return f"`charset: {policy.charset or charsets.DEFAULT_CHARSET}`"


def _widen(policy: PasswordPolicy, name: str) -> str:
    """What to do about a class the alphabet cannot produce.

    The named charsets all hold every class but ``special``, so for them there is
    exactly one remedy and §8's table has it one row down. A custom alphabet is
    whatever was typed, so the remedy is to type more of it.
    """
    if policy.charset == charsets.CUSTOM:
        return f"add {name} characters to `allow:`, or use a named charset from §8"
    return f"use `alnum_safe`, which adds {charsets.SAFE_SPECIALS_SPACED} (§8)"


# ------------------------------------------------- rotation and the rest ---


def _build_rotation(raw: Any, *, at: KeyPath) -> RotationPolicy:
    if raw is None:
        return RotationPolicy()
    block = mapping(raw, at=at)
    reject_unknown_keys(block, allowed=ROTATION_KEYS, at=at)

    strategy = block.get("strategy")
    return RotationPolicy(
        strategy=(
            None
            if strategy is None
            else choice(
                strategy, allowed=ROTATION_STRATEGIES, at=at.key("strategy"), noun="strategy"
            )
        ),
        rollover_hours=_positive(block, "rollover_hours", at=at),
        keep_previous=optional_bool(block, "keep_previous", at=at),
        max_age_days=_positive(block, "max_age_days", at=at),
    )


def build_verify(raw: Any, *, at: KeyPath) -> VerifyPolicy:
    """``verify:`` -- shared with profiles, which is the whole point of §5."""
    if raw is None:
        return VerifyPolicy()
    block = mapping(raw, at=at)
    reject_unknown_keys(block, allowed=VERIFY_KEYS, at=at)

    method = block.get("method")
    margin = optional_int(block, "lockout_margin", at=at)
    if margin is not None and margin < 0:
        raise ConfigError(f"lockout_margin cannot be {margin}", at=at.key("lockout_margin"))

    return VerifyPolicy(
        method=(
            None
            if method is None
            else choice(method, allowed=VERIFY_METHODS, at=at.key("method"), noun="verify method")
        ),
        lockout_margin=margin,
    )


def _build_account(raw: Any, *, at: KeyPath) -> AccountPolicy:
    if raw is None:
        return AccountPolicy()
    block = mapping(raw, at=at)
    reject_unknown_keys(block, allowed=ACCOUNT_KEYS, at=at)
    return AccountPolicy(
        unlock_if_locked=optional_bool(block, "unlock_if_locked", at=at),
        profile=optional_string(block, "profile", at=at),
    )


def _positive(block: dict[str, Any], key: str, *, at: KeyPath) -> int | None:
    value = optional_int(block, key, at=at)
    if value is not None and value < 1:
        raise ConfigError(f"{key} must be at least 1, not {value}", at=at.key(key))
    return value

"""Generating a password from a policy, and deciding whether one complies (§8).

Tier 0: pure logic, no database, no vault, no filesystem (``04-testing.md`` §4).
Everything the generator needs to know about the *target* -- its maximum password
length and the character set that length is measured in -- arrives as an argument,
because discovering it is a connection and belongs to the command (UC-1 §4 step 2).

Two entry points, and it matters that there are exactly two:

* :func:`generate` draws candidates from a CSPRNG and keeps the first compliant
  one (UC-1 §4 step 3).
* :func:`check` says whether a password complies, for ``creds apply --from-stdin``,
  which "validates against policy and refuses on violation".

They share one predicate on purpose. Two notions of *compliant* would drift, and
the drift would show up as a supplied password being refused for a rule the
generator quietly ignores -- or, worse, accepted for one it enforces.

**A password is a :class:`~sopuli.secrets.Secret` from the moment it exists**, so
nothing downstream has to remember to wrap it (invariant 2). That extends to the
failures: a :class:`Violation` says *how many* characters broke a rule and never
which, so a violation can be logged or put in an audit event without leaking part
of a credential somebody typed.

**Length is characters; the limit is bytes.** §8 is explicit that the maximum is
computed in the database character set, so the two are separate and a
:class:`ByteLimit` carries the encoding it counted in. Where no target could be
reached there is no limit to apply, and the command says so rather than assuming
one (UC-1 §4 step 2).
"""

from __future__ import annotations

import secrets as csprng  # the standard library's, not `sopuli.secrets` beside it
from dataclasses import dataclass

from sopuli.config import charsets
from sopuli.config.errors import ConfigError
from sopuli.config.model import PasswordPolicy
from sopuli.secrets import Secret

#: The only source of randomness this module uses -- P5 and UC-1 §4 step 3 both
#: require a CSPRNG, and `random` would produce passwords that look exactly as good
#: and are predictable from each other. Bound to a module-level name on purpose: it
#: is the one seam a test can monkeypatch to prove that generation really goes
#: through it, which output alone cannot show.
secure_choice = csprng.choice

#: How many candidates to draw before giving up. Generous on purpose: a draw costs
#: microseconds, and every realistic policy succeeds within a handful, so
#: exhausting this bound means the policy is *infeasible* rather than unlucky --
#: which is what the error is then allowed to say.
MAX_ATTEMPTS = 1000

#: The rules :func:`check` reports against. Slugs rather than prose so a command
#: can group them, and internal for now: whether they become codes in the JSON
#: contract is J3 (the warning code registry), which this must not answer by
#: accident.
CHARSET = "charset"
FORBIDDEN = "forbidden"
CONTROL = "control"
FIRST_CHAR = "first_char"
REQUIRE = "require"
LENGTH = "length"
BYTE_LENGTH = "byte_length"
ENCODING = "encoding"


class PasswordPolicyError(ConfigError):
    """This policy cannot produce a password.

    A :class:`~sopuli.config.errors.ConfigError` because that is what it is: the
    fix is a line in a config file, so P5 puts it on exit 2 with "you typed it
    wrong" rather than on 1 with "something broke". It also means the CLI boundary
    already prints it with its hint.

    Distinct from a :class:`Violation`, which is a *password* failing a policy.
    This is the policy failing on its own terms.
    """


@dataclass(frozen=True)
class ByteLimit:
    """The target's maximum password length, and the encoding it is counted in.

    One object rather than two arguments because a byte count without its encoding
    is meaningless -- 30 bytes is 30 characters in ``cp1252`` and as few as 7 in
    ``utf-8``. §8 says the maximum is computed in the *database* character set, and
    pairing them is how that stops being a comment.

    ``encoding`` is a Python codec name. Mapping an Oracle character set
    (``AL32UTF8``, ``WE8MSWIN1252``) onto one is the driver's knowledge, not this
    layer's.
    """

    max_bytes: int
    encoding: str

    def width(self, text: str) -> int:
        """How many bytes ``text`` occupies in this encoding."""
        return len(text.encode(self.encoding))

    def encodable(self, text: str) -> bool:
        """Whether this encoding can represent ``text`` at all."""
        try:
            text.encode(self.encoding)
        except UnicodeEncodeError:
            return False
        return True


@dataclass(frozen=True)
class Violation:
    """One way a password fails its policy.

    ``detail`` is deliberately about *counts and classes* and never about
    characters or positions. "3 characters outside the charset" is actionable for
    whoever supplied the password; naming them would put part of a credential into
    whatever reads this, which is the failure invariant 2 exists to prevent.
    """

    rule: str
    detail: str


def check(
    candidate: Secret, policy: PasswordPolicy, *, limit: ByteLimit | None
) -> tuple[Violation, ...]:
    """Every way ``candidate`` fails ``policy``, in a stable order.

    Empty means compliant. A tuple rather than a boolean because the caller has to
    say what was wrong: UC-1 §4 lets ``--from-stdin`` proceed under
    ``--no-policy-check``, and what it records in the audit event is this list.

    ``length`` is read as a **minimum** here, where :func:`generate` produces
    exactly it. A password an external system dictated is not weaker for being
    longer, and refusing it would block the migration case ``--from-stdin`` exists
    for; too *short* is a violation.
    """
    text = candidate.reveal()
    allowed = charsets.alphabet(policy)
    found: list[Violation] = []

    outside = sum(1 for character in text if character not in allowed)
    if outside:
        found.append(
            Violation(CHARSET, f"{outside} of {len(text)} characters are outside the charset")
        )
    if charsets.FORBIDDEN in text:
        found.append(
            Violation(FORBIDDEN, 'contains `"`, which an Oracle quoted identifier cannot escape')
        )
    controls = sum(1 for character in text if charsets.is_control(character))
    if controls:
        found.append(Violation(CONTROL, f"contains {controls} control characters"))

    if policy.first_char == charsets.ALPHA and not _starts_with_a_letter(text):
        found.append(Violation(FIRST_CHAR, "does not start with a letter"))

    tally = charsets.counts(text)
    for name, demanded in policy.require:
        if tally[name] < demanded:
            found.append(
                Violation(REQUIRE, f"needs {demanded} {name}, has {tally[name]}"),
            )

    if policy.length is not None and len(text) < policy.length:
        found.append(
            Violation(
                LENGTH,
                f"is {len(text)} characters, policy asks for at least {policy.length}",
            )
        )

    found.extend(_byte_violations(text, limit))
    return tuple(found)


def _starts_with_a_letter(text: str) -> bool:
    """An empty password starts with nothing, which is not a letter."""
    return bool(text) and charsets.class_of(text[0]) in ("upper", "lower")


def _byte_violations(text: str, limit: ByteLimit | None) -> list[Violation]:
    """The two ways a target's byte limit refuses a password.

    Unrepresentable comes first and is not a length problem at all: a password
    holding a character the database character set has no encoding for cannot be
    set whatever its length. Reported rather than raised, because a supplied
    password reaching that state is a policy answer, not a crash.
    """
    if limit is None:
        return []
    if not limit.encodable(text):
        return [Violation(ENCODING, f"cannot be represented in {limit.encoding}")]
    width = limit.width(text)
    if width > limit.max_bytes:
        return [
            Violation(
                BYTE_LENGTH,
                f"is {width} bytes in {limit.encoding}, the target's limit is {limit.max_bytes}",
            )
        ]
    return []


def generate(
    policy: PasswordPolicy, *, limit: ByteLimit | None, attempts: int = MAX_ATTEMPTS
) -> Secret:
    """A compliant password, drawn from a CSPRNG (UC-1 §4 step 3).

    Rejection sampling: draw ``length`` characters, keep the candidate if
    :func:`check` finds nothing, otherwise draw again. Doing it this way rather
    than by placing required characters deliberately is what keeps one definition
    of compliant -- a constructive generator would encode the rules a second time,
    and the second copy is the one that would drift.

    Every impossibility is refused *before* the loop, so an unsatisfiable policy
    produces an error naming the reason rather than a thousand wasted draws and a
    timeout (invariant 4: fail at plan time, naming what is wrong).

    Raises :class:`PasswordPolicyError` where a valid policy cannot produce a
    password, and a plain :class:`~sopuli.config.errors.ConfigError` -- its base --
    where the policy is not a valid one at all, which only a policy built in code
    can be (:func:`sopuli.config.charsets.alphabet`). ``except ConfigError`` covers
    both, and both exit 2.
    """
    length = _required_length(policy)
    allowed = _usable_alphabet(policy, limit)
    _reject_impossible(policy, allowed, length, limit)

    last: tuple[Violation, ...] = ()
    for _ in range(attempts):
        candidate = Secret("".join(secure_choice(allowed) for _ in range(length)))
        last = check(candidate, policy, limit=limit)
        if not last:
            return candidate

    raise PasswordPolicyError(
        f"gave up generating a password after {attempts} attempts",
        hint=(
            "the policy is infeasible rather than unlucky at this point -- the last "
            f"candidate failed: {_describe(last)}"
        ),
    )


def _required_length(policy: PasswordPolicy) -> int:
    """``length`` is not defaulted, and that is a decision rather than an omission.

    §8 names a default *charset* and no default length, so there is nothing to
    follow -- and the value decides how much entropy every credential in the estate
    gets. A tool picking that quietly is the opposite of a reviewed config line.
    A built-in default belongs to P3's layer 6 if it is ever wanted (#10).
    """
    if policy.length is None:
        raise PasswordPolicyError(
            "this policy declares no password length",
            hint=(
                "add `password.length:` to it -- there is no built-in default, because "
                "how much entropy a credential gets should be a reviewed line in the file"
            ),
        )
    return policy.length


def _usable_alphabet(policy: PasswordPolicy, limit: ByteLimit | None) -> str:
    """The alphabet, refused up front if it cannot produce anything usable."""
    allowed = charsets.alphabet(policy)
    if not allowed:
        raise PasswordPolicyError(
            "this policy's charset has no characters to draw from",
            hint=(
                "`charset: custom` needs an `allow:` with something in it; the named "
                'charsets always do, minus `"` (invariant 11)'
            ),
        )
    if limit is not None:
        unusable = sum(1 for character in allowed if not limit.encodable(character))
        if unusable:
            raise PasswordPolicyError(
                f"{unusable} of this charset's {len(allowed)} characters cannot be "
                f"represented in {limit.encoding}",
                hint=(
                    "the target's character set cannot store passwords built from this "
                    "alphabet -- narrow `allow:`, or use a named charset, which is ASCII"
                ),
            )
    return allowed


def _reject_impossible(
    policy: PasswordPolicy, allowed: str, length: int, limit: ByteLimit | None
) -> None:
    """The redraws that could never succeed, refused before any of them happen.

    ``policies.py`` catches the composition cases when the file is read, which is
    where somebody can act on them. They are repeated here because this function
    is also reachable with a :class:`~sopuli.config.model.PasswordPolicy` built in
    code, and a loop that cannot terminate is a worse answer than an error either
    way.
    """
    demanded_in_all = sum(count for _, count in policy.require)
    if demanded_in_all > length:
        raise PasswordPolicyError(
            f"`require:` asks for {demanded_in_all} characters but the length is {length}",
            hint="no candidate could ever satisfy this, so generation would never finish",
        )

    present = charsets.classes_present(allowed)
    for name, demanded in policy.require:
        if demanded and name not in present:
            raise PasswordPolicyError(
                f"the charset has no {name} characters, but `require:` asks for {demanded}",
                hint="no candidate could ever satisfy this, so generation would never finish",
            )
    if policy.first_char == charsets.ALPHA and not charsets.has_letters(allowed):
        raise PasswordPolicyError(
            "the charset has no letters, but `first_char: alpha` requires one",
            hint="no candidate could ever satisfy this, so generation would never finish",
        )

    if limit is None:
        return
    # Every character costs at least this much, so this many characters cost at
    # least this many bytes. For the ASCII charsets that is one byte each and the
    # comparison is exact; a custom alphabet with wider characters only makes the
    # true cost higher, never lower.
    narrowest = min(limit.width(character) for character in allowed)
    if length * narrowest > limit.max_bytes:
        raise PasswordPolicyError(
            f"a {length}-character password needs at least {length * narrowest} bytes in "
            f"{limit.encoding}, but the target's limit is {limit.max_bytes}",
            hint=(
                "§8 measures the limit in bytes and `length:` in characters -- lower "
                "`length:` for this target, or narrow the estate this policy covers"
            ),
        )


def _describe(violations: tuple[Violation, ...]) -> str:
    """Violations as one line, for an error message. Counts only, never content."""
    if not violations:  # pragma: no cover - only reachable if attempts is 0
        return "nothing, which should not happen"
    return "; ".join(f"{violation.rule} ({violation.detail})" for violation in violations)

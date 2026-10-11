"""Password generation and validation (§8, UC-1 §4 step 3).

Tier 0: no database, no vault, nothing to start. Every rule §8 states is checked
here, and three things that output alone cannot show are pinned deliberately:

* **the source of randomness.** A generator using ``random`` looks identical from
  the outside, so the CSPRNG is asserted as an identity and exercised through a
  monkeypatch rather than inferred from statistics.
* **composition on every draw, not on average.** ``require:`` being satisfied
  usually is the same as not being satisfied, for a rule whose whole purpose is
  that the password the tool just wrote will be accepted.
* **that nothing leaks.** A candidate must not reach a message, a ``repr`` or a
  JSON rendering -- including the messages about *rejected* candidates.

Draw counts are chosen so that a broken rule fails essentially every time rather
than flaking: 200 passwords of the shapes §2's own policy uses.
"""

from __future__ import annotations

import json
import secrets
from typing import Any

import pytest

from sopuli import passwords
from sopuli.config import charsets
from sopuli.config.errors import ConfigError
from sopuli.config.model import PasswordPolicy
from sopuli.exit_codes import ExitCode
from sopuli.output.emit import RedactingJSONEncoder
from sopuli.passwords import ByteLimit, PasswordPolicyError, check, generate
from sopuli.secrets import REDACTED, Secret

#: Enough draws that a rule broken one time in ten would fail this suite every
#: run, and few enough to stay inside tier 0's minute.
DRAWS = 200

#: §2's own policy, which is the shape a real estate uses.
WORKED_EXAMPLE = PasswordPolicy(
    length=24,
    charset="alnum_safe",
    first_char="alpha",
    require=(("digit", 1), ("lower", 1), ("special", 1), ("upper", 1)),
)

UTF8 = ByteLimit(max_bytes=128, encoding="utf-8")


def policy(**keys: Any) -> PasswordPolicy:
    return PasswordPolicy(**keys)


def drawn(
    policy_: PasswordPolicy, *, limit: ByteLimit | None = UTF8, draws: int = DRAWS
) -> list[str]:
    """``draws`` generated passwords, revealed for inspection.

    Revealing is what a test has to do and nothing else does: the assertions are
    about the characters, and the point of :class:`Secret` is that only an audited
    caller can see them.
    """
    return [generate(policy_, limit=limit).reveal() for _ in range(draws)]


# ------------------------------------------------------------- the charsets ---


@pytest.mark.parametrize("name", list(charsets.ALPHABETS))
def test_every_charset_produces_only_its_own_characters(name: str) -> None:
    alphabet = set(charsets.ALPHABETS[name])

    for password in drawn(policy(length=16, charset=name)):
        assert set(password) <= alphabet


def test_a_custom_charset_produces_only_what_it_allows() -> None:
    for password in drawn(policy(length=12, charset="custom", allow="abc123")):
        assert set(password) <= set("abc123")


@pytest.mark.parametrize("name", [*charsets.ALPHABETS, "custom"])
def test_a_generated_password_never_contains_a_double_quote(name: str) -> None:
    """Invariant 11, including under `printable_ascii`, which is the charset that
    would contain it if §8's row were read as prose rather than as characters."""
    allow = 'abc"123' if name == "custom" else None

    for password in drawn(policy(length=20, charset=name, allow=allow)):
        assert '"' not in password


def test_the_default_charset_is_used_when_none_is_declared() -> None:
    """§8 names `alnum_safe` the default, so a policy that only sets a length is
    complete enough to generate from."""
    for password in drawn(policy(length=16), draws=20):
        assert set(password) <= set(charsets.ALPHABETS["alnum_safe"])


# ---------------------------------------------------------------- the rules ---


def test_the_length_is_exact() -> None:
    assert {len(password) for password in drawn(policy(length=17))} == {17}


def test_first_char_alpha_holds_on_every_draw() -> None:
    """A policy demanding a digit first is refused at load, so only this direction
    has to hold -- but it has to hold every time, not almost every time."""
    for password in drawn(policy(length=12, first_char="alpha")):
        assert password[0].isalpha()


def test_every_required_class_is_present_on_every_draw() -> None:
    """§2's `require:` block, satisfied 200 times out of 200. "Usually" is the
    same as "no" for a rule whose purpose is that the database accepts the
    password the tool just wrote."""
    for password in drawn(WORKED_EXAMPLE):
        tally = charsets.counts(password)
        assert tally["upper"] >= 1
        assert tally["lower"] >= 1
        assert tally["digit"] >= 1
        assert tally["special"] >= 1


def test_a_heavier_requirement_is_still_satisfied_every_time() -> None:
    """Four specials out of ten characters is where naive rejection sampling
    starts needing real numbers of draws. It still must not return a candidate
    that misses.

    Ten, not eight: with `alnum_safe`'s seven specials, one draw in 75 meets this
    at ten characters and one in 190 at eight. At eight, the 1000 attempts give
    up on about one password in 200, and this test, which draws 50, would fail
    about one run in five."""
    demanding = policy(length=10, charset="alnum_safe", require=(("special", 4),))

    for password in drawn(demanding, draws=50):
        assert charsets.counts(password)["special"] >= 4


def test_a_generated_password_satisfies_its_own_policy() -> None:
    """The property that makes one predicate worth having: what `generate` returns
    is what `check` accepts, so `--from-stdin` and generation cannot disagree."""
    for _ in range(50):
        candidate = generate(WORKED_EXAMPLE, limit=UTF8)
        assert check(candidate, WORKED_EXAMPLE, limit=UTF8) == ()


# ------------------------------------------------------- length in bytes ---


def test_the_byte_limit_is_counted_in_the_targets_encoding() -> None:
    """§8's "not in characters", made concrete. The same 4-character alphabet is
    5 bytes in UTF-8 and 4 in cp1252, so the same policy behaves differently
    against two databases -- which is why the encoding travels with the limit.
    """
    multibyte = policy(length=10, charset="custom", allow="abcé")

    for password in drawn(multibyte, limit=ByteLimit(max_bytes=10, encoding="utf-8")):
        assert len(password) == 10
        assert len(password.encode("utf-8")) <= 10
        # 10 characters in 10 bytes leaves no room for the two-byte one at all.
        assert "é" not in password

    # The same policy against a single-byte database has room for it, and over
    # this many draws will certainly have used it.
    relaxed = drawn(multibyte, limit=ByteLimit(max_bytes=10, encoding="cp1252"))
    assert any("é" in password for password in relaxed)


def test_a_password_may_be_shorter_in_characters_than_in_bytes() -> None:
    """The redraw path, rather than the up-front refusal: 8 characters fit in 12
    UTF-8 bytes only if at most four of them are the two-byte one."""
    for password in drawn(
        policy(length=8, charset="custom", allow="abcé"),
        limit=ByteLimit(max_bytes=12, encoding="utf-8"),
    ):
        assert len(password.encode("utf-8")) <= 12


def test_no_limit_means_no_byte_check() -> None:
    """UC-1 §4 step 2: where no target was reachable there is no limit to apply,
    and inventing one would be the assumption that wording exists to prevent."""
    passwords_ = drawn(policy(length=40, charset="custom", allow="é"), limit=None, draws=5)

    assert {len(password) for password in passwords_} == {40}
    assert {len(password.encode("utf-8")) for password in passwords_} == {80}


# ------------------------------------------------- refusals before the loop ---


def test_a_policy_with_no_length_is_refused_rather_than_defaulted() -> None:
    """§8 names a default charset and no default length, so there is nothing to
    follow -- and how much entropy every credential in the estate gets should be
    a reviewed line in a file."""
    with pytest.raises(PasswordPolicyError) as caught:
        generate(policy(charset="alnum_safe"), limit=UTF8)

    rendered = str(caught.value)
    assert "declares no password length" in rendered
    assert "password.length" in rendered
    assert "no built-in default" in rendered


def test_a_policy_error_is_a_config_error_and_exits_nine() -> None:
    """P5 gives "fix your file" a code of its own, and the CLI boundary already
    prints a `ConfigError` with its hint.

    Exit 9 rather than 2: a policy the file could not hold is found *after* the
    invocation resolved, so it is the one that carries a run document. Exit 2
    is reserved for argv that never parsed.
    """
    error = PasswordPolicyError("nope")

    assert isinstance(error, ConfigError)
    assert error.exit_code == ExitCode.CONFIG_INVALID


@pytest.mark.parametrize(
    ("why", "keys"),
    [
        ("an unknown charset", {"charset": "alnumm"}),
        ("`allow:` beside a named charset", {"charset": "alnum", "allow": "abc"}),
        ("`charset: custom` allowing nothing", {"charset": "custom"}),
    ],
    ids=lambda value: str(value)[:32],
)
def test_a_policy_a_config_file_could_not_hold_is_an_error_at_both_entry_points(
    why: str, keys: dict[str, Any]
) -> None:
    """This module says a `PasswordPolicy` built in code is supported, so it has to
    behave for one the loader would have refused.

    Without the gate in `charsets.alphabet` the three shapes are, in order: a bare
    `KeyError` out of a dict lookup, an `allow:` silently ignored so the caller gets
    a different alphabet than it asked for, and an empty alphabet that reads as "no
    characters are permitted". All three are `ConfigError`, so they exit 2 like any
    other bad policy -- `PasswordPolicyError` is for a *valid* policy that cannot
    produce a password, which these are not.
    """
    built = policy(length=8, **keys)

    with pytest.raises(ConfigError) as generating:
        generate(built, limit=UTF8)
    with pytest.raises(ConfigError) as checking:
        check(Secret("Abcdef1#"), built, limit=UTF8)

    assert generating.value.exit_code == ExitCode.CONFIG_INVALID
    assert str(generating.value) == str(checking.value), "the two entry points must agree"


def test_an_empty_custom_alphabet_is_refused() -> None:
    with pytest.raises(PasswordPolicyError) as caught:
        generate(policy(length=8, charset="custom", allow='"'), limit=UTF8)

    assert "no characters to draw from" in str(caught.value)


def test_a_length_that_cannot_fit_the_targets_bytes_is_refused_at_plan_time() -> None:
    """Invariant 4 applied here: a 128-character policy against an 11.2 target
    fails immediately, naming both numbers, rather than after a thousand draws."""
    with pytest.raises(PasswordPolicyError) as caught:
        generate(policy(length=128), limit=ByteLimit(max_bytes=30, encoding="utf-8"))

    rendered = str(caught.value)
    assert "needs at least 128 bytes" in rendered
    assert "limit is 30" in rendered
    assert "`length:`" in rendered


def test_a_byte_limit_refusal_names_its_target_where_one_is_given() -> None:
    """The caller knows which target the limit came from, and the message says
    so. Without one -- `policy sample --max-bytes` -- it stays generic."""
    with pytest.raises(PasswordPolicyError) as caught:
        generate(
            policy(length=40),
            limit=ByteLimit(max_bytes=30, encoding="utf-8"),
            target="xe21-pdb",
        )

    assert "but the limit on 'xe21-pdb' is 30" in str(caught.value)
    assert "lower `length:` for 'xe21-pdb'" in (caught.value.hint or "")


@pytest.mark.parametrize(
    ("candidate", "limit"),
    [
        (policy(length=40), ByteLimit(max_bytes=30, encoding="utf-8")),
        (policy(length=8, charset="custom", allow="é"), ByteLimit(max_bytes=30, encoding="ascii")),
        (policy(length=8, charset="custom", allow='"'), None),
    ],
)
def test_require_feasible_refuses_what_generate_refuses_with_the_same_message(
    candidate: PasswordPolicy, limit: ByteLimit | None
) -> None:
    """#671: a `--dry-run` asks this instead of drawing, so its message must be the
    one the real run's draw would give."""
    with pytest.raises(PasswordPolicyError) as asked:
        passwords.require_feasible(candidate, limit=limit, target="xe21-pdb")
    with pytest.raises(PasswordPolicyError) as drawn:
        generate(candidate, limit=limit, target="xe21-pdb")

    assert str(asked.value) == str(drawn.value)


def test_require_feasible_says_nothing_about_a_policy_that_fits() -> None:
    passwords.require_feasible(policy(length=20), limit=UTF8)


def test_an_alphabet_the_target_cannot_store_is_refused() -> None:
    """A US7ASCII database cannot hold `é` at all, so no candidate drawn from this
    alphabet could ever be set."""
    with pytest.raises(PasswordPolicyError) as caught:
        generate(
            policy(length=8, charset="custom", allow="abcé"),
            limit=ByteLimit(max_bytes=30, encoding="ascii"),
        )

    rendered = str(caught.value)
    assert "cannot be represented in ascii" in rendered
    assert "1 of this charset's 4 characters" in rendered


def test_requiring_a_class_the_alphabet_lacks_is_refused_before_drawing() -> None:
    """`policies.py` catches this when the file is read. It is caught here too,
    because this function is reachable with a policy built in code, and a loop
    that cannot terminate is the worse answer either way."""
    with pytest.raises(PasswordPolicyError) as caught:
        generate(
            policy(length=8, charset="custom", allow="abc", require=(("digit", 1),)), limit=UTF8
        )

    rendered = str(caught.value)
    assert "no digit characters" in rendered
    assert "never finish" in rendered


def test_requiring_more_characters_than_the_length_is_refused_before_drawing() -> None:
    """`policies.py`'s first satisfiability rule, repeated where a policy built in
    code can also reach it."""
    with pytest.raises(PasswordPolicyError) as caught:
        generate(policy(length=4, require=(("special", 3), ("upper", 3))), limit=UTF8)

    rendered = str(caught.value)
    assert "asks for 6 characters but the length is 4" in rendered
    assert "never finish" in rendered


def test_first_char_alpha_without_letters_is_refused_before_drawing() -> None:
    with pytest.raises(PasswordPolicyError) as caught:
        generate(policy(length=8, charset="custom", allow="0123", first_char="alpha"), limit=UTF8)

    assert "no letters" in str(caught.value)


def test_exhausting_the_retries_says_the_policy_is_the_problem() -> None:
    """The safety net under the up-front checks: a policy that is *statistically*
    infeasible rather than provably so. One attempt is enough to reach it, and the
    message has to say what the last candidate failed rather than shrug.
    """
    demanding = policy(length=8, charset="alnum_safe", require=(("special", 8),))

    with pytest.raises(PasswordPolicyError) as caught:
        generate(demanding, limit=UTF8, attempts=1)

    rendered = str(caught.value)
    assert "gave up generating a password after 1 attempts" in rendered
    assert "infeasible rather than unlucky" in rendered
    assert "require" in rendered


# ------------------------------------------------------------------- check ---


def test_a_compliant_password_has_no_violations() -> None:
    assert check(Secret("Abcdef1#Abcdef1#Abcdef1#"), WORKED_EXAMPLE, limit=UTF8) == ()


def rules(candidate: str, policy_: PasswordPolicy, *, limit: ByteLimit | None = UTF8) -> set[str]:
    return {violation.rule for violation in check(Secret(candidate), policy_, limit=limit)}


def test_every_rule_is_reported_by_name() -> None:
    assert rules("abc", policy(length=8)) == {passwords.LENGTH}
    assert rules("abcdefgh", policy(length=8, charset="alnum")) == set()
    assert rules("abcdefg#", policy(length=8, charset="alnum")) == {passwords.CHARSET}
    assert rules("1bcdefgh", policy(length=8, first_char="alpha")) == {passwords.FIRST_CHAR}
    assert rules("abcdefgh", policy(length=8, require=(("digit", 1),))) == {passwords.REQUIRE}


def test_a_forbidden_or_control_character_is_reported_twice_over() -> None:
    """Both are outside every alphabet, so `charset` fires as well -- and that is
    the point rather than noise. The count says *how much* of the password is
    unusable; the second violation says *why* a reader cannot fix it by widening
    the charset, because no charset may contain these.
    """
    assert rules('abcdef"#', policy(length=8, charset="printable_ascii")) == {
        passwords.CHARSET,
        passwords.FORBIDDEN,
    }
    assert rules("abcdef\x00", policy(length=7, charset="printable_ascii")) == {
        passwords.CHARSET,
        passwords.CONTROL,
    }
    assert rules("1bcdefgh", policy(length=8, first_char="alpha")) == {passwords.FIRST_CHAR}
    assert rules("abcdefgh", policy(length=8, require=(("digit", 1),))) == {passwords.REQUIRE}


def test_a_longer_supplied_password_is_compliant_but_a_shorter_one_is_not() -> None:
    """`length` is exact for generation and a minimum for validation. An
    external system dictating a longer password is not weaker, and refusing it
    would block the migration case `--from-stdin` exists for."""
    declared = policy(length=8, charset="alnum")

    assert rules("abcdefghijkl", declared) == set()
    assert rules("abcdefg", declared) == {passwords.LENGTH}


def test_the_byte_rules_are_reported_separately_from_the_character_count() -> None:
    tight = ByteLimit(max_bytes=8, encoding="utf-8")

    assert rules("abcdéfgh", policy(length=8, charset="custom", allow="abcdéfgh"), limit=tight) == {
        passwords.BYTE_LENGTH
    }
    assert rules(
        "abcdéfgh",
        policy(length=8, charset="custom", allow="abcdéfgh"),
        limit=ByteLimit(max_bytes=30, encoding="ascii"),
    ) == {passwords.ENCODING}


def test_an_empty_password_does_not_start_with_a_letter() -> None:
    """The edge that would otherwise be an IndexError on a supplied empty line."""
    assert passwords.FIRST_CHAR in rules("", policy(length=8, first_char="alpha"))


# --------------------------------------------------------------- the CSPRNG ---


def test_the_generator_draws_from_the_csprng_and_not_from_random() -> None:
    """P5 and UC-1 §4 step 3 both say a CSPRNG, and the difference is invisible in
    the output -- `random` would produce passwords that look exactly as good and
    are predictable from each other. So the source is pinned as an identity."""
    assert passwords.secure_choice is secrets.choice


def test_generation_actually_goes_through_that_function(monkeypatch: pytest.MonkeyPatch) -> None:
    """The other half, and the one that fails if somebody swaps the import for
    `random.choice`: patch the CSPRNG and the output must change with it."""
    monkeypatch.setattr(passwords, "secure_choice", lambda alphabet: alphabet[0])

    generated = generate(policy(length=6, charset="custom", allow="qwerty"), limit=UTF8)

    assert generated.reveal() == "qqqqqq"


# ------------------------------------------------------------- redaction ---


def test_a_generated_password_is_a_secret_from_the_moment_it_exists() -> None:
    """Invariant 2: nothing downstream has to remember to wrap it."""
    generated = generate(WORKED_EXAMPLE, limit=UTF8)

    assert isinstance(generated, Secret)
    assert str(generated) == REDACTED
    assert repr(generated) == REDACTED
    assert generated.reveal() not in json.dumps({"password": generated}, cls=RedactingJSONEncoder)


def test_no_violation_repeats_the_password_it_rejected() -> None:
    """A violation may be logged or put in an audit event, so it says how many
    characters broke a rule and never which. This is the assertion that keeps the
    messages honest as they are edited."""
    supplied = 'Sup3rSecret!"\x00'
    violations = check(Secret(supplied), policy(length=32, charset="alnum"), limit=UTF8)

    assert violations
    for violation in violations:
        assert supplied not in violation.detail
        for fragment in ("Sup3r", "Secret", "ecre"):
            assert fragment not in violation.detail


def test_the_retry_error_does_not_repeat_the_candidate_either(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one message built from a *rejected* candidate, which is the easiest
    place to leak one by accident.

    The CSPRNG is pinned to a known character so the test knows exactly what the
    discarded candidate was and can assert its absence.
    """
    monkeypatch.setattr(passwords, "secure_choice", lambda alphabet: "Z")

    with pytest.raises(PasswordPolicyError) as caught:
        generate(
            policy(length=8, charset="alnum_safe", require=(("special", 8),)),
            limit=UTF8,
            attempts=2,
        )

    rendered = str(caught.value)
    assert "ZZZZZZZZ" not in rendered
    assert "needs 8 special, has 0" in rendered

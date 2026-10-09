"""How long a password may be, and in what character set. Tier 0.

A `ByteLimit` is a required argument so that a statement cannot be built by
somebody who never found out; these are the tests for the finding out.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.oracle.limits import (
    CHARSET_QUERY,
    CODECS,
    FALLBACK,
    LEGACY_MAX_BYTES,
    MODERN_MAX_BYTES,
    character_set,
    max_bytes,
    resolve,
)
from sopuli.driver.oracle.statements import PasswordNotAdmissibleError, admissible
from sopuli.secrets import Secret


class _Cursor:
    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.sql = ""

    def execute(self, sql: str, parameters: Any = None, /) -> _Cursor:
        self.sql = sql
        return self

    def fetchone(self) -> Any:
        answer = self.answers.get(self.sql)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def fetchall(self) -> Any:
        return []


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("11.2.0.4.0", LEGACY_MAX_BYTES),
        ("12.1.0.2.0", LEGACY_MAX_BYTES),
        ("12.2.0.1.0", LEGACY_MAX_BYTES),
        ("18.0.0.0.0", LEGACY_MAX_BYTES),
        ("19.0.0.0.0", LEGACY_MAX_BYTES),
        ("21.0.0.0.0", LEGACY_MAX_BYTES),
        ("23.0.0.0.0", MODERN_MAX_BYTES),
    ],
)
def test_the_limit_follows_the_probed_version(version: str, expected: int) -> None:
    """30 below 23, 128 from it.

    The 18c-and-later rows read ``x.0.0.0.0`` because that is what
    ``V$INSTANCE.VERSION`` reports there: the base release, not the RU. 12.2,
    18c, 19c and 21c are all measured to refuse a 31st byte, which is why the
    floor is not 12.2 -- that is where *identifiers* grew, not passwords.

    Not a violation of invariant 3: the rule forbids branching on a version from
    *config*, and no dictionary view states this limit — so the version the
    database itself reported on connect is the only place it can come from.
    """
    assert max_bytes(version) == expected


@pytest.mark.parametrize("version", [None, "", "garbage", "23"])
def test_an_unreadable_version_gets_the_modern_limit(version: str | None) -> None:
    """Unknown reads as modern, not as legacy.

    Capping every password at 30 bytes because the version could not be read
    would silently weaken credentials on a database that accepts 128. The server
    refuses an over-long password anyway, so being wrong the other way produces
    an error rather than a weaker secret.
    """
    assert max_bytes(version) == MODERN_MAX_BYTES


def test_the_database_character_set_is_read_rather_than_the_session_one() -> None:
    """§8 counts the limit in the character set the *server* stores the password
    in, not the one this client happens to be speaking."""
    assert "nls_database_parameters" in CHARSET_QUERY
    assert "v$nls" not in CHARSET_QUERY

    assert character_set(_Cursor({CHARSET_QUERY: ("AL32UTF8",)})) == "AL32UTF8"


def test_a_known_character_set_maps_to_its_codec() -> None:
    limit = resolve(_Cursor({CHARSET_QUERY: ("WE8MSWIN1252",)}), "23.0.0.0.0")

    assert limit.encoding == "cp1252"
    assert limit.charset == "WE8MSWIN1252"
    assert limit.max_bytes == MODERN_MAX_BYTES


def test_an_unmapped_character_set_falls_back_to_ascii() -> None:
    """A refusal to guess rather than a guess.

    Under `ascii` every password §8's alphabets can produce measures exactly, and
    anything outside ASCII is refused with a message. Assuming UTF-8 instead would
    *under*-count on Oracle's `UTF8` (CESU-8) for supplementary characters, and
    build a statement the server rejects.
    """
    limit = resolve(_Cursor({CHARSET_QUERY: ("JA16SJIS",)}), "19.3.0.0.0")

    assert limit.encoding == FALLBACK
    assert limit.charset == "JA16SJIS"


def test_an_ascii_password_is_admissible_under_an_unmapped_character_set() -> None:
    """The fallback must not break the ordinary case: every charset §8 offers is
    ASCII, so a generated password measures the same under any of them."""
    limit = resolve(_Cursor({CHARSET_QUERY: ("JA16SJIS",)}), "19.3.0.0.0")

    admissible(Secret("Str0ng-Pa55-quiXa"), limit)


def test_a_message_names_the_database_s_own_word_for_the_character_set() -> None:
    """`ascii` is accurate about the codec and useless about the estate. The
    operator has to be able to recognise what their database is called."""
    limit = resolve(_Cursor({CHARSET_QUERY: ("JA16SJIS",)}), "19.3.0.0.0")

    with pytest.raises(PasswordNotAdmissibleError) as raised:
        admissible(Secret("pässwörd-with-non-ascii"), limit)

    assert "JA16SJIS" in str(raised.value)


def test_an_unreadable_character_set_still_produces_a_limit() -> None:
    """`NLS_DATABASE_PARAMETERS` needs no grant, but a target that cannot answer
    still has to get a usable limit rather than an exception: the fallback is
    ASCII and the statement builder does the refusing."""
    limit = resolve(_Cursor({CHARSET_QUERY: None}), "19.3.0.0.0")

    assert limit.encoding == FALLBACK
    assert limit.charset is None
    assert limit.described == FALLBACK


@pytest.mark.parametrize("version", ["11.2.0.4.0", "19.0.0.0.0", "21.0.0.0.0"])
def test_the_limit_is_enforced_at_the_measured_boundary(version: str) -> None:
    """19c and 21c included: they refuse a 31st byte exactly as 11.2 does, and
    a floor at 12.2 would tell them they accept 128."""
    limit = resolve(_Cursor({CHARSET_QUERY: ("AL32UTF8",)}), version)

    admissible(Secret("a" * LEGACY_MAX_BYTES), limit)

    with pytest.raises(PasswordNotAdmissibleError, match="31 bytes"):
        admissible(Secret("a" * (LEGACY_MAX_BYTES + 1)), limit)


def test_oracle_utf8_is_not_mapped_to_python_utf8() -> None:
    """Its absence from `CODECS` is the point, not a gap somebody should fill.

    Oracle's `UTF8` is CESU-8. The two agree across the Basic Multilingual Plane
    and diverge above it, where UTF-8 spends four bytes on a supplementary
    character and CESU-8 spends six on a surrogate pair — so mapping it to
    `utf-8` under-counts by two bytes each, accepting a password the server then
    refuses. In the one code path whose job is to know the limit *before* the
    statement is built, that is the wrong direction to be wrong in.
    """
    assert "UTF8" not in CODECS, "see the module docstring: this omission is deliberate"
    assert "AL32UTF8" in CODECS, "which is real UTF-8 and is mapped"

    limit = resolve(_Cursor({CHARSET_QUERY: ("UTF8",)}), "19.3.0.0.0")

    assert limit.encoding == FALLBACK
    assert limit.charset == "UTF8", "and the message still names what the database calls it"


def test_a_supplementary_character_is_where_the_two_would_disagree() -> None:
    """The measurement behind the omission, as arithmetic rather than prose."""
    supplementary = "😀"

    assert len(supplementary.encode("utf-8")) == 4
    # CESU-8 spends 3 bytes on each half of the surrogate pair.
    assert len(supplementary.encode("utf-16-be")) // 2 * 3 == 6

"""How long a password may be here, and in what character set (#179).

`#171 <https://github.com/villebase/sopuli-dba/issues/171>`_ made a
:class:`~sopuli.passwords.ByteLimit` a required argument to
:func:`~sopuli.driver.oracle.statements.alter_user_password`, precisely so a
statement cannot be built by somebody who never found out. This is where the
answer comes from.

**The maximum is derived from the probed version, and that is not a violation of
invariant 3.** The rule is that the tool never branches on a version *from
config*; no dictionary view states the password limit, so the only place it can
come from is the version the database itself reported when the session opened.
The distinction matters: `04-testing.md` §3 makes the same point about the
harness, and the version here is :attr:`~sopuli.driver.protocol.Scope.db_version`, read on connect.

**The character set needs no grant.** ``NLS_DATABASE_PARAMETERS`` answered
``AL32UTF8`` to a service account holding exactly `02-oracle-privileges.md` §2's
grants and nothing else -- measured, because a probe requiring a grant nobody
made is the failure #178 already found once. It is the *database* character set
rather than the session's, which is what §8 specifies: the limit is counted in
the character set the server stores the password in, not the one this client
happens to be speaking.

**An unmapped character set falls back to ASCII, deliberately.** Oracle has a
long tail of character sets and this table will never be complete. The fallback
is not a guess about byte widths -- it is a refusal to make one: under ``ascii``
every generated password (§8's alphabets are ASCII) measures exactly, and
anything outside ASCII is refused by
:func:`~sopuli.driver.oracle.statements.admissible` with a message naming the
database's own word for the character set.

**Oracle's ``UTF8`` is one of the unmapped ones, and its absence from
:data:`CODECS` is the point rather than an oversight.** It is CESU-8, not UTF-8:
the two agree for every character in the Basic Multilingual Plane and diverge
above it, where UTF-8 spends four bytes and CESU-8 spends six on a surrogate
pair. Mapping it to ``utf-8`` would *under*-count by two bytes per supplementary
character -- accepting a password the server then refuses, in the one code path
whose whole job is to know the limit before the statement is built. Python has no
CESU-8 codec, so the choice is between measuring it wrongly and not claiming to
measure it, and this module does the second. A database still on ``UTF8``
(Oracle deprecated it in favour of ``AL32UTF8``) therefore accepts ASCII
passwords, which is every password §8 can generate, and refuses the rest with a
message rather than a surprise.
"""

from __future__ import annotations

from sopuli.driver.oracle.capabilities import Cursor, read
from sopuli.passwords import ByteLimit

#: The *database* character set (§8), not the session's.
CHARSET_QUERY = "select value from nls_database_parameters where parameter = 'NLS_CHARACTERSET'"

#: 128 bytes from 23, 30 below it (#383, #595).
#:
#: **Not 12.2**, which is where this floor used to be and why it was called
#: ``LONG_IDENTIFIER_FLOOR``: 12.2 raised *identifiers* from 30 bytes to 128, and
#: passwords did not move with them. A 31st byte is ``ORA-00972`` on 11.2, 12.2,
#: 18.4, 19.3 and 21.3, and 19.32 refuses 128; 26ai 23.26 accepts 128. So the
#: floor is somewhere in (21.3, 23.26], and ``23`` is the only one this module can
#: express: the version it is compared against is ``V$INSTANCE.VERSION``, which is
#: the *base* release on 18c and later, so every 23ai and 26ai reads
#: ``23.0.0.0.0``. A 23ai before 23.26 is unmeasured and indistinguishable here.
MODERN_MAX_BYTES = 128
LEGACY_MAX_BYTES = 30
LONG_PASSWORD_FLOOR = (23, 0)

#: Oracle's character sets, as Python codecs. Deliberately short: these are the
#: ones a supported release is actually installed with, and an entry is cheap to
#: add for a site that needs it. Anything absent lands on :data:`FALLBACK`.
CODECS: dict[str, str] = {
    "AL32UTF8": "utf-8",
    "US7ASCII": "ascii",
    "WE8MSWIN1252": "cp1252",
    "WE8ISO8859P1": "latin-1",
    "WE8ISO8859P15": "iso8859-15",
    "EE8MSWIN1250": "cp1250",
    "CL8MSWIN1251": "cp1251",
}

#: What an unmapped character set gets. See the module docstring: this refuses to
#: guess rather than guessing conservatively.
FALLBACK = "ascii"


def max_bytes(db_version: str | None) -> int:
    """Oracle's maximum password length for this release.

    Unknown reads as **modern**, not as legacy. A tool that could not read the
    version and therefore capped every password at 30 bytes would be silently
    weakening passwords on a database that accepts 128 -- and the server refuses
    an over-long one anyway, so the cost of being wrong the other way is an
    error rather than a weaker credential.
    """
    return LEGACY_MAX_BYTES if _below(db_version, LONG_PASSWORD_FLOOR) else MODERN_MAX_BYTES


def describe_max_bytes() -> str:
    """The rule :func:`max_bytes` applies, in words, for help text (#612).

    Built from the constants so that moving the floor moves the help with it.
    """
    major, minor = LONG_PASSWORD_FLOOR
    floor = str(major) if minor == 0 else f"{major}.{minor}"
    return f"{LEGACY_MAX_BYTES} below {floor}, {MODERN_MAX_BYTES} from {floor}"


def _below(version: str | None, floor: tuple[int, int]) -> bool:
    if not version:
        return False
    parts = version.split(".")
    try:
        return (int(parts[0]), int(parts[1])) < floor
    except (IndexError, ValueError):
        return False


def character_set(cursor: Cursor) -> str | None:
    """The database character set, or ``None`` where it could not be read."""
    row = read(cursor, CHARSET_QUERY)
    return str(row[0]).upper() if row and row[0] else None


def resolve(cursor: Cursor, db_version: str | None) -> ByteLimit:
    """This target's password limit, counted in its own character set."""
    charset = character_set(cursor)
    return ByteLimit(
        max_bytes=max_bytes(db_version),
        encoding=CODECS.get(charset or "", FALLBACK),
        charset=charset,
    )

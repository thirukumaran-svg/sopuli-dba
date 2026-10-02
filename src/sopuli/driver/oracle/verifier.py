"""Comparing a password with an account's stored 12C verifier, client-side (#437).

What `check --method hash` runs instead of a login: read ``SYS.USER$.SPARE4``,
regenerate the 12C digest from the vault's password and the verifier's own salt,
and compare. **No authentication attempt**, so no failed-login counter moves and
no account is locked by checking it -- UC-1 §7's lockout problem does not arise,
and a locked account can be compared as readily as an open one.

The derivation is ported from ``sql/oracle/06_verifier_reproduce.py``, the
evidence behind ``02-oracle-privileges.md`` §2, and nothing about it is guessed.
It reproduced byte-for-byte on 26ai, 21c, 18c (#432), 19.3.0.0.0 (#548),
12.2.0.1.0 (#572) and 19.32.0.0.0 (#581). 12.1 is unread::

    salt   = the last 16 bytes of the T: blob (its 32 trailing hex characters)
    inter  = PBKDF2-HMAC-SHA512(password_utf8, salt || b"AUTH_PBKDF2_SPEEDY_KEY", 4096, 64)
    digest = SHA-512(inter || salt)            # the 64-byte head of the blob

**The 12C verifier and only it.** ``S:`` (11G, SHA-1) and the 10G DES hash are
weaker than a login, so comparing either would report a check stronger than the
one performed. They are never a fallback, and an account with no 12C verifier
is :data:`NO_VERIFIER` rather than a comparison against something else (#433).

**Two 12C verifiers mean a rollover window.** During one, ``SPARE4`` carries
``T:`` for the *previous* password and ``t:`` for the *current* one, sharing a
salt (#432; on a real 19.12+ by 19.32, #581). Outside a window there is one,
``T:``, and it is current. :func:`compare` says which one the password
reproduced, because that is the thing a login cannot tell: during a window both
passwords authenticate.

**Pure, deliberately**: everything here is a function of a string the driver
read and a password the vault gave, so it is tier 0. The read itself is
``accounts.SPARE4_QUERY``, and it binds the account *name* and nothing else.
Invariant 14 is the reason the comparison is here at all rather than in SQL: a
verifier or password sent as a bind is kept in clear by ``V$SQL_BIND_CAPTURE``.
"""

from __future__ import annotations

import hashlib
import hmac

from sopuli.passwords import ByteLimit
from sopuli.secrets import Secret

__all__ = [
    "CURRENT",
    "NO_MATCH",
    "NO_VERIFIER",
    "PREVIOUS",
    "Malformed12cVerifierError",
    "NotComparableError",
    "compare",
    "derive",
    "twelve_c",
]

#: The fixed suffix Oracle appends to the salt before the PBKDF2 pass. Part of the
#: protocol rather than a secret -- the same constant hashcat's mode 12300 uses.
SPEEDY_KEY = b"AUTH_PBKDF2_SPEEDY_KEY"

#: The count Oracle generates the stored verifier with. **Not stored in
#: ``SPARE4``**: the server sends it at logon as ``AUTH_PBKDF2_VGEN_COUNT``, read
#: as 4096 on every release whose wire could be read (#431), and shown by the
#: reproduction on 19.32, whose NNE hid the wire (#581). A release that used
#: another would make every comparison a mismatch, which is why the releases are
#: listed in the module docstring rather than assumed.
ITERATIONS = 4096

#: A well-formed 12C blob: a 64-byte digest then a 16-byte salt, in hex.
DIGEST_HEX = 128
SALT_HEX = 32
BLOB_HEX = DIGEST_HEX + SALT_HEX

#: The previous password's verifier during a rollover window, and the only one
#: outside it. Case-sensitive: ``t:`` is a different verifier.
OLDER = "T:"
#: The current password's verifier during a rollover window.
NEWER = "t:"

#: What :func:`compare` answers.
CURRENT = "current"
PREVIOUS = "previous"
NO_MATCH = "no_match"
NO_VERIFIER = "no_verifier"


class Malformed12cVerifierError(ValueError):
    """A ``T:``/``t:`` token that is not 160 hex characters.

    Raised rather than skipped, which is the spike's rule carried over: a token
    filtered out would report "no verifier", and a changed format is exactly what
    the release list in the module docstring cannot vouch for. The message names
    the length, never the token.
    """


class NotComparableError(ValueError):
    """The password cannot be compared here, because the server did not hash it.

    Oracle derives the verifier from the password *as the database holds it*,
    after conversion to the database character set (#572: on WE8DEC, ``Ω``
    became ``¿`` and the verifier reproduced from that). Where the character set
    holds the password exactly, the conversion changes nothing and its UTF-8 is
    what was hashed. Where it cannot, the stored password is a lossy substitute
    this code cannot reproduce, and comparing anyway would report a mismatch for
    a password that logs in -- false drift, and drift starts rotations. So it is
    refused. The message names the character set, never a character.
    """


def derive(password: bytes, salt: bytes) -> bytes:
    """The 64-byte 12C digest for ``password`` under ``salt``."""
    inter = hashlib.pbkdf2_hmac("sha512", password, salt + SPEEDY_KEY, ITERATIONS, 64)
    return hashlib.sha512(inter + salt).digest()


def twelve_c(spare4: str | None) -> dict[str, str]:
    """The 12C verifiers in ``spare4``, keyed by prefix.

    ``S:`` (11G) and the rollover marker ``V:`` are not 12C verifiers and are left
    out. Every ``T:``/``t:`` token is checked for shape here, so a caller never
    holds one it cannot use.
    """
    found: dict[str, str] = {}
    for part in (spare4 or "").split(";"):
        prefix, value = part[:2], part[2:].strip()
        if prefix not in (OLDER, NEWER):
            continue
        if len(value) != BLOB_HEX or not _is_hex(value):
            raise Malformed12cVerifierError(
                f"a {prefix} verifier of {len(value)} characters, where 12C is {BLOB_HEX} hex"
            )
        found[prefix] = value
    return found


def compare(secret: Secret, spare4: str | None, *, limit: ByteLimit) -> str:
    """Which of this account's 12C verifiers ``secret`` reproduces.

    :data:`CURRENT`, :data:`PREVIOUS`, :data:`NO_MATCH`, or :data:`NO_VERIFIER`
    where the account has no 12C verifier to compare with. The caller turns the
    last into a refusal; it is never a mismatch, because nothing was compared.

    The password is fed as its UTF-8 bytes with no case folding or normalisation,
    which is what reproduced on every release read -- **provided the database
    character set holds it exactly**, which ``limit`` says. It is required for the
    reason it is required by the statement builder: a comparison cannot be made
    by somebody who never asked the database. Where the set cannot hold the
    password, :class:`NotComparableError`. A password this tool set never gets
    there, since ``admissible`` refused it first; a value checked against an
    account somebody else set can.
    """
    verifiers = twelve_c(spare4)
    if not verifiers:
        return NO_VERIFIER

    text = secret.reveal()
    if not limit.encodable(text):
        raise NotComparableError(
            f"the password has characters {limit.described} cannot hold, so the server "
            "hashed a converted copy this comparison cannot reproduce"
        )

    current = NEWER if NEWER in verifiers else OLDER
    password = text.encode("utf-8")
    for prefix, answer in ((current, CURRENT), (OLDER, PREVIOUS)):
        if prefix not in verifiers or (answer == PREVIOUS and prefix == current):
            continue
        blob = verifiers[prefix]
        digest, salt = bytes.fromhex(blob[:DIGEST_HEX]), bytes.fromhex(blob[DIGEST_HEX:])
        if hmac.compare_digest(derive(password, salt), digest):
            return answer
    return NO_MATCH


def _is_hex(value: str) -> bool:
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True

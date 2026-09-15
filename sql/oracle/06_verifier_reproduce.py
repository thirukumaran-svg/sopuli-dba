"""sopuli-dba : client-side reproduction of the 12C (T:) verifier   (#432)

Part 2 of #90's spike. Reads the output of ``06_verifier_reproduce.sql`` and,
for every stored ``T:``/``t:`` verifier, regenerates the digest from the
password with :func:`derive_12c` and compares it byte-for-byte. It derives
nothing secret: the input is a password the harness set on a throwaway account
and the verifier that account already stored, both emitted by the SQL probe.
This is the algorithm ``creds check --method hash`` would run against a vault
value and the account's own verifier.

Not product code and not a test -- a spike, run by hand against the tier-2
stack and left in the tree as the evidence behind the finding in
``docs/design/02-oracle-privileges.md`` §2. When ``--method hash`` is
implemented, :func:`derive_12c` is the reference to port, not this I/O.

THE DERIVATION (measured; parameters confirmed in #431):

    salt   = the last 16 bytes of the verifier (32 trailing hex characters)
    inter  = PBKDF2-HMAC-SHA512(password_utf8, salt || b"AUTH_PBKDF2_SPEEDY_KEY",
                                iterations=4096, dklen=64)
    digest = SHA-512(inter || salt)            # the first 64 bytes of the blob

  - The password is fed as its raw UTF-8 bytes, with no case folding and no
    Unicode normalisation -- the non-ASCII case reproduces on exactly the bytes
    the client sent (#431 measured those bytes as UTF-8 under an AL32UTF8
    database). No password containing ``"`` reaches here: invariant 11 rejects
    it before a driver would.
  - 4096 is the iteration count Oracle sends at logon as
    ``AUTH_PBKDF2_VGEN_COUNT`` on 26ai, 21c and 18c (#431). It is *not* stored
    in ``SPARE4``; a release that sent a different count would not reproduce
    here, which is why #431 read it from the wire rather than assuming it.

HOW TO RUN (from the repo root, against the tier-2 stack):

    set -o pipefail   # so a failed sqlplus is not hidden by the pipe
    docker exec -i -e NLS_LANG=AMERICAN_AMERICA.AL32UTF8 \
      sopuli-test-oracle-free-1 sqlplus -s / as sysdba \
      < sql/oracle/06_verifier_reproduce.sql \
      | python sql/oracle/06_verifier_reproduce.py

Exit status is 0 only if every verifier reproduced AND every label and rollover
phase the probe always emits was present -- an empty or truncated pipe is a
failure, not a silent pass. ``pipefail`` catches a non-zero sqlplus; this catches
a sqlplus that exits 0 having printed only some rows.
"""

from __future__ import annotations

import hashlib
import sys

#: The fixed suffix Oracle appends to the salt before the PBKDF2 pass. Not a
#: secret and not configurable -- it is part of the protocol, the same constant
#: hashcat's mode 12300 uses. Named here so the one magic string in the
#: derivation is spelled out once.
SPEEDY_KEY = b"AUTH_PBKDF2_SPEEDY_KEY"

#: Iterations Oracle uses to generate the stored verifier (#431). The session
#: key derivation count (AUTH_PBKDF2_SDER_COUNT = 3) is a different number for a
#: different purpose and is not used here.
ITERATIONS = 4096


def derive_12c(password: bytes, salt: bytes) -> bytes:
    """Regenerate the 64-byte 12C digest from a password and its 16-byte salt."""
    inter = hashlib.pbkdf2_hmac("sha512", password, salt + SPEEDY_KEY, ITERATIONS, 64)
    return hashlib.sha512(inter + salt).digest()


#: The static labels the SQL probe always emits, on every release. Checked for
#: presence before success is declared: an empty or truncated pipe (a failed
#: sqlplus, a dropped connection) would otherwise leave both collections empty
#: and print ALL REPRODUCED over nothing. `set -o pipefail` in the shell catches
#: the process exit; this catches the case where sqlplus exits 0 having printed
#: only some rows.
EXPECTED_STATIC = frozenset({"ascii", "symbols", "nonascii", "len30", "len128"})
EXPECTED_PHASES = frozenset({"BEFORE", "DURING", "AFTER"})


def twelve_c_verifiers(spare4: str) -> list[tuple[str, str]]:
    """Every ``T:``/``t:`` token in a ``SPARE4`` string, as ``(prefix, value)``.

    The prefix is case-sensitive: a rollover window carries ``T:`` (the previous
    password) and ``t:`` (the current one), and telling them apart is the whole
    of question 2. ``S:`` (11G), ``H:`` (10G) and ``V:`` (the rollover marker)
    are not 12C verifiers and are skipped.

    **A ``T:``/``t:`` token of any length is returned, not only the 160-hex one
    this release uses.** Surfacing a changed format is the point of the spike, so
    a malformed token has to reach the caller as a token it must reject, never be
    filtered out and reported as "no verifier". A well-formed 12C blob is 160 hex
    characters: a 128-hex (64-byte) digest then a 32-hex (16-byte) salt.
    """
    return [(part[:2], part[2:]) for part in spare4.split(";") if part[:2] in ("T:", "t:")]


def check_verifier(prefix: str, value: str, candidates: dict[str, bytes]) -> tuple[str, bool]:
    """Match one verifier against candidate passwords: ``(which, well_formed)``.

    ``which`` is the candidate label whose derivation reproduces the stored
    digest, ``"none"`` if none does, or ``"MALFORMED"`` if the token is not
    160 hex characters -- the last counting as a failure, not a miss.
    """
    if len(value) != 160:
        return "MALFORMED", False
    digest_hex, salt = value[:128], bytes.fromhex(value[128:160])
    for label, password in candidates.items():
        if derive_12c(password, salt).hex().upper() == digest_hex.upper():
            return label, True
    return "none", True


def main() -> int:
    static: list[tuple[str, bool, bytes, str]] = []
    rollover_pw: dict[str, bytes] = {}
    rollover: list[tuple[str, str]] = []

    for raw in sys.stdin:
        line = raw.strip()
        if line.startswith("RESULT|"):
            _, label, applied, pwhex, spare4 = line.split("|", 4)
            static.append((label, applied == "1", bytes.fromhex(pwhex), spare4))
        elif line.startswith("ROLLPW|"):
            _, which, pwhex = line.split("|", 2)
            rollover_pw[which] = bytes.fromhex(pwhex)
        elif line.startswith("ROLL|"):
            _, phase, spare4 = line.split("|", 2)
            rollover.append((phase, spare4))

    problems: list[str] = []
    compared = 0

    print("== static passwords: does the stored T: reproduce byte-for-byte?")
    print(f"   {'label':<10} {'pw bytes':>8}  {'verifiers':>9}  result")
    for label, applied, password, spare4 in static:
        nbytes = len(password)
        if not applied:
            print(f"   {label:<10} {nbytes:>8}  {'-':>9}  rejected by server (length not accepted)")
            continue
        verifiers = twelve_c_verifiers(spare4)
        if not verifiers:
            problems.append(f"{label}: applied but no 12C verifier stored (not a 12.2+ target?)")
            print(f"   {label:<10} {nbytes:>8}  {'0':>9}  NO 12C VERIFIER")
            continue
        results = [check_verifier(prefix, value, {"pw": password}) for prefix, value in verifiers]
        compared += sum(1 for _which, well_formed in results if well_formed)
        ok = all(which == "pw" for which, _wf in results)
        if not ok:
            malformed = any(not wf for _which, wf in results)
            problems.append(f"{label}: {'malformed token' if malformed else 'did not reproduce'}")
        print(f"   {label:<10} {nbytes:>8}  {len(verifiers):>9}  {'MATCH' if ok else 'MISMATCH'}")

    if rollover:
        print("\n== rollover window: which verifier is current, which is previous?")
        print("   the probe rotated the account from ROLLPW|old to ROLLPW|new")
        for phase, spare4 in rollover:
            verifiers = twelve_c_verifiers(spare4)
            labelled = []
            for prefix, value in verifiers:
                which, well_formed = check_verifier(prefix, value, rollover_pw)
                compared += 1 if well_formed else 0
                if which in ("none", "MALFORMED"):
                    problems.append(f"rollover {phase} {prefix}: {which}")
                labelled.append(f"{prefix} = {which}")
            print(f"   {phase:<7} {len(verifiers)} verifier(s): {', '.join(labelled) or '(none)'}")

    missing_static = EXPECTED_STATIC - {label for label, *_ in static}
    if missing_static:
        problems.append(f"static labels missing (truncated run?): {sorted(missing_static)}")
    missing_phases = EXPECTED_PHASES - {phase for phase, _ in rollover}
    if missing_phases:
        problems.append(f"rollover phases missing: {sorted(missing_phases)}")
    if {"old", "new"} - set(rollover_pw):
        problems.append("rollover passwords missing (ROLLPW old/new)")
    if compared == 0:
        problems.append("no 12C verifiers were compared at all -- nothing was proven")

    if problems:
        print("\nNOT REPRODUCED:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("\nALL REPRODUCED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

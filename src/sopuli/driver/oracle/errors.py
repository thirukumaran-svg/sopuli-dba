"""What an ORA- code means, and what the tool should do about it (UC-1 §6.4).

CLAUDE.md's rule is the requirement: *never swallow an ORA- code -- map it, and
preserve the server's own message*. So this module turns a code into a
:class:`Diagnosis` carrying a category, an exit code, a hint, and the server's
message untouched.

**It classifies; it does not decide.** Nothing here raises, and that is the
central design point rather than a stylistic one: `ORA-01017` means two
completely different things depending on whose credential was refused. Reaching
the database as the *admin* account is an authentication failure and exit 6;
the same code from a *verification* login is `DRIFT`, exit 3, and the whole
reason `creds check` is schedulable. A mapping that raised would have to guess
which, and it would guess wrong half the time. So it returns a value and the
caller -- which knows what it was doing -- decides whether that value is an
exception, a state, or a reason to draw another password.

**Tier 0, and no ``oracledb`` anywhere.** A code and a message are two strings.
:func:`from_error` reads them off a vendor exception structurally, without
importing the client, so the extraction is testable in the same suite as the
table it feeds -- and so this module stays importable in a base install
(ADR-006 rule 3).

### Three rules that decide the rows

**Never retry the same password.** `ORA-28003` and `ORA-28007` mean *draw
another one*, which is UC-1 §4 step 3's bounded loop, and they never mean *send
that one again*. :attr:`Diagnosis.regenerate` is how a caller tells those two
apart from everything else, and no row sets both it and ``retryable``.

**``retryable`` is a report, not an instruction.** It is the run document's
``error.retryable``, and it says whether the same call could plausibly succeed
later -- a listener that is down may come up. It is not permission for this tool
to loop, and nothing in sopuli retries on it today.

**Exit codes come from P5's published table and are not invented here.** Two
families have no number of their own and deliberately do not get one:
connectivity and authorization exit 1 with their own *category*. A distinct exit
path in UC-1 §6.4 means a distinct thing the operator reads, and adding a number
to P5's table is a change to a contract schedulers branch on -- an argument to
have in the open, not a default this module sets on the way past.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sopuli.driver.protocol import AuthenticationError, DriverError
from sopuli.exit_codes import ExitCode

# ------------------------------------------------------------------- kinds ---
#
# What happened, as something a caller can branch on without matching a number.
# The code stays on the Diagnosis for the audit trail; these are for the code
# path.

PASSWORD_REJECTED = "password_rejected"
PASSWORD_REUSED = "password_reused"
INVALID_CREDENTIALS = "invalid_credentials"
ACCOUNT_LOCKED = "account_locked"
PASSWORD_EXPIRED = "password_expired"
PASSWORD_IN_GRACE = "password_in_grace"
INSUFFICIENT_PRIVILEGE = "insufficient_privilege"
CONTAINER_MISUSE = "container_misuse"
UNREACHABLE = "unreachable"
VERIFIER_MISMATCH = "verifier_mismatch"
CLIENT_LIBRARY = "client_library"
UNKNOWN = "unknown"

#: Run-document states a code implies on its own. Spelled here as strings and
#: checked against the schema's ``state`` enum by the tests, for the reason every
#: vocabulary in this package is: the word the driver produces and the word the
#: document prints have to be the same word.
LOCKED = "LOCKED"
EXPIRED = "EXPIRED"

#: Oracle's Net/TNS error range. A range rather than a list because the family is
#: large and only a few members are worth naming: a code in here that nothing has
#: named is still a *connectivity* problem, and landing it in ``database`` would
#: send the operator to look at the wrong thing entirely.
NET_RANGE = range(12150, 12700)

_ORA = re.compile(r"^ORA-(\d+)")

#: A code at the *start* of a message, which is where Oracle puts the primary
#: one. Anchored deliberately: an ``ORA-28003`` commonly carries an ``ORA-20000``
#: from the verify function further along, and the leading code is the one that
#: says what happened.
_LEADING_CODE = re.compile(r"^(?:ORA|DPI|DPY)-\d+")


@dataclass(frozen=True)
class _Rule:
    kind: str
    category: str
    exit_code: ExitCode = ExitCode.FAILURE
    hint: str | None = None
    retryable: bool = False
    state: str | None = None


#: UC-1 §6.4's table, as data. Each hint says what to do next rather than
#: restating what went wrong -- the server's own message already does that, and
#: it is preserved verbatim beside it.
RULES: dict[str, _Rule] = {
    "ORA-28003": _Rule(
        PASSWORD_REJECTED,
        "policy",
        hint=(
            "the profile's password verify function refused this candidate; draw another. "
            "The server message usually carries an ORA-20000 saying which rule was broken"
        ),
    ),
    "ORA-28007": _Rule(
        PASSWORD_REUSED,
        "policy",
        hint=(
            "PASSWORD_REUSE_TIME/MAX refused this value; draw another. "
            "Never send the same one again"
        ),
    ),
    "ORA-01017": _Rule(
        INVALID_CREDENTIALS,
        "authentication",
        exit_code=ExitCode.AUTH_FAILURE,
        hint="the password this run used is not the one the database holds",
    ),
    "ORA-28000": _Rule(
        ACCOUNT_LOCKED,
        "database",
        state=LOCKED,
        hint=(
            "the account is locked; sopuli does not unlock one unless the policy says to. "
            "ACCOUNT_STATUS says whether it was locked by an operator or by FAILED_LOGIN_ATTEMPTS"
        ),
    ),
    "ORA-28001": _Rule(
        PASSWORD_EXPIRED,
        "database",
        state=EXPIRED,
        hint="the password has expired rather than drifted; `creds apply` resolves it",
    ),
    "ORA-28002": _Rule(
        PASSWORD_IN_GRACE,
        "database",
        hint="the password is in its grace period; rotate before the profile expires it",
    ),
    "ORA-01031": _Rule(
        INSUFFICIENT_PRIVILEGE,
        "authorization",
        hint=(
            "the service account is missing a grant -- ALTER USER for a rotation, "
            "SELECT on DBA_USERS/DBA_PROFILES for a read. See sql/oracle/00_install.sql"
        ),
    ),
    "ORA-65040": _Rule(
        CONTAINER_MISUSE,
        "config",
        exit_code=ExitCode.CONFIG_INVALID,
        hint=(
            "the statement's container clause does not suit the container the session is in; "
            "check the target's scope"
        ),
    ),
    "ORA-65066": _Rule(
        CONTAINER_MISUSE,
        "config",
        exit_code=ExitCode.CONFIG_INVALID,
        hint=(
            "this account is common to its application container, so it cannot be altered "
            "from inside one member of it. Its application root is the only place that can, "
            "and this tool refuses that scope -- rotate it there by hand, or point the "
            "target at an account local to this container"
        ),
    ),
    "ORA-65048": _Rule(
        CONTAINER_MISUSE,
        "config",
        exit_code=ExitCode.CONFIG_INVALID,
        hint=(
            "the statement succeeded in the root and failed in a PDB, so containers now "
            "disagree about this account; the server message names the PDB"
        ),
    ),
    "ORA-12154": _Rule(
        UNREACHABLE,
        "connectivity",
        hint="the connect identifier did not resolve; check the dsn and TNS_ADMIN",
    ),
    "ORA-12541": _Rule(
        UNREACHABLE,
        "connectivity",
        retryable=True,
        hint="no listener at that address; it may be down rather than wrong",
    ),
    "ORA-28040": _Rule(
        VERIFIER_MISMATCH,
        "authentication",
        exit_code=ExitCode.AUTH_FAILURE,
        hint=(
            "client and server cannot agree a logon protocol. The account's PASSWORD_VERSIONS "
            "and the server's SQLNET.ALLOWED_LOGON_VERSION_SERVER are the pair to compare -- "
            "a password over 30 bytes silently drops clients still on the 10G/11G verifiers"
        ),
    ),
    # The driver's own, not the server's. Both are fixed on this machine by the
    # person reading the message, which is what `config` and exit 9 already mean
    # for a backend that is configured and not installed (ADR-006 E5).
    "DPI-1047": _Rule(
        CLIENT_LIBRARY,
        "config",
        exit_code=ExitCode.CONFIG_INVALID,
        hint=(
            "Oracle Instant Client is not on the library path. It is a runtime prerequisite "
            "on every platform (D3): LD_LIBRARY_PATH on Linux, PATH plus the VC++ "
            "redistributable on Windows"
        ),
    ),
    "DPY-3001": _Rule(
        CLIENT_LIBRARY,
        "config",
        exit_code=ExitCode.CONFIG_INVALID,
        hint=(
            "this ran in thin mode, which sopuli never uses deliberately (D3): thin mode "
            "has no Native Network Encryption, cannot reach a database older than 12.1, "
            "and cannot log on through an external password store. "
            "Instant Client is missing or thick-mode initialisation did not happen"
        ),
    ),
}


@dataclass(frozen=True)
class Diagnosis:
    """One failure, classified. Never raised by this module -- see the note above.

    ``message`` is the server's own, preserved rather than replaced. A DBA
    reading a sopuli failure and a DBA reading the same failure in SQL\\*Plus
    should recognise it as the same event, and the hint is added *beside* it
    rather than over it.
    """

    code: str
    kind: str
    category: str
    exit_code: ExitCode
    message: str
    hint: str | None = None
    retryable: bool = False
    #: The run-document state this code implies on its own, where it implies one.
    #: ``LOCKED`` and ``EXPIRED`` exist so that `check` reports them rather than
    #: folding them into ``DRIFT`` -- one ``ORA-01017`` otherwise hides an expired
    #: password, a locked account and a genuinely wrong one behind one word
    #: (UC-1 §7 mitigation 6).
    state: str | None = None

    @property
    def regenerate(self) -> bool:
        """Whether the *password* was refused and another should be drawn.

        The signal UC-1 §4 step 3's bounded loop runs on. Deliberately distinct
        from :attr:`retryable`: this one means *the value was bad*, and sending
        it again is the one thing that certainly will not work.
        """
        return self.kind in (PASSWORD_REJECTED, PASSWORD_REUSED)

    def as_error(self) -> DriverError:
        """This diagnosis as something to raise, when the caller decides it is.

        An authentication failure comes back as
        :class:`~sopuli.driver.protocol.AuthenticationError` so that a caller
        which wants ``except AuthenticationError`` has one; everything else is a
        :class:`MappedError` carrying this row's own category and exit code.
        """
        if self.category == AuthenticationError.category:
            return AuthenticationError(self.message, hint=self.hint, code=self.code)
        return MappedError(self)


class MappedError(DriverError):
    """A :class:`Diagnosis` that a caller decided to raise.

    ``category`` and ``exit_code`` are set on the *instance*, shadowing the class
    attributes :class:`~sopuli.driver.protocol.DriverError` declares. The class
    ones are the default for a driver failure nobody classified; these are what
    the code actually means, and the boundary reads the same attribute either
    way.
    """

    def __init__(self, diagnosis: Diagnosis) -> None:
        super().__init__(diagnosis.message, hint=diagnosis.hint, code=diagnosis.code)
        self.category = diagnosis.category
        self.exit_code = diagnosis.exit_code
        # The one thing above the driver that needs this answer cannot ask a
        # `Diagnosis` for it: `sopuli.apply` is vendor-neutral and does not import
        # this module (#312). Carried onto the instance, where `DriverError`
        # declares it, so the boundary reads one attribute whoever raised it.
        self.regenerate = diagnosis.regenerate
        self.diagnosis = diagnosis


def classify(code: str, message: str) -> Diagnosis:
    """What ``code`` means, with ``message`` carried through untouched.

    Three layers, in order. The named rows in :data:`RULES`; then Oracle's
    Net/TNS range, so an unnamed member of a family lands with its family; then
    a default per prefix.

    **An unmapped code is terminal**, and that is the decision this function
    makes rather than the absence of one. A code nobody has classified might be
    transient and might be a password the server will refuse forever, and of the
    two ways to be wrong, looping on the second is the one that locks accounts
    and burns rotations. Nothing sets ``regenerate`` either: drawing a new
    password because of an error nobody understood would change the vault's
    state on the strength of a guess.
    """
    rule = RULES.get(code)
    if rule is None:
        rule = _by_family(code)

    return Diagnosis(
        code=code,
        kind=rule.kind,
        category=rule.category,
        exit_code=rule.exit_code,
        message=message,
        hint=rule.hint,
        retryable=rule.retryable,
        state=rule.state,
    )


def _by_family(code: str) -> _Rule:
    """The fallback, which is about where a code *came from* rather than what it
    says. Unknown, but not unplaced."""
    matched = _ORA.match(code)
    if matched and int(matched.group(1)) in NET_RANGE:
        return _Rule(UNREACHABLE, "connectivity")
    if code.startswith(("DPI-", "DPY-")):
        # The client library's own numbering. Whatever it is, it happened on this
        # side of the wire, so it is not something the database did.
        return _Rule(UNKNOWN, "connectivity")
    return _Rule(UNKNOWN, "database")


def from_error(exc: Any) -> Diagnosis:
    """Classify a ``oracledb`` exception without importing ``oracledb``.

    The client wraps its detail in ``exc.args[0]``, an object carrying
    ``full_code`` (``"ORA-01017"``), ``code`` (the integer) and ``message``.
    Reading those structurally keeps this module in tier 0 and keeps the
    extraction in one place -- otherwise every call site writes the same three
    lines of attribute-poking and one of them gets it wrong on the day the
    exception has no detail object at all.

    An exception that carries nothing recognisable still produces a
    :class:`Diagnosis`, because "the driver raised something we cannot read" is
    a failure the operator has to be told about in the same shape as every
    other.

    **Where there is no detail object, the code is read off the front of the
    message.** An exception whose ``args[0]`` is a plain string is the case:
    without this it classifies as ``unknown`` and ``database``, so an
    ``ORA-12154`` that arrived in the shape nobody expected would be reported as
    a database failure and send the operator to the wrong machine — the exact
    misclassification :data:`NET_RANGE` exists to prevent. The message itself is
    never rewritten; only the code is recovered from it.
    """
    detail = exc.args[0] if getattr(exc, "args", None) else None
    message = str(getattr(detail, "message", "") or "") or str(exc)
    code = _normalise(str(getattr(detail, "full_code", "") or ""))

    return classify(code or _leading_code(message), message)


def _normalise(code: str) -> str:
    """``"ORA-01017:"`` and ``" ORA-01017 "`` are the same key as ``"ORA-01017"``.

    Trivial, and worth doing rather than trusting: a row that fails to match
    because of a trailing colon does not fail loudly -- it silently becomes
    ``unknown``, which is the one outcome that looks like an ordinary result.
    """
    return code.strip().rstrip(":")


def _leading_code(message: str) -> str:
    return matched.group(0) if (matched := _LEADING_CODE.match(message.strip())) else ""

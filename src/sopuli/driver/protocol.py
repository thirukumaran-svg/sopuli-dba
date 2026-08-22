"""The driver interface (P1), as far as UC-1 needs it.

P1's rule is that every operation touching a database goes through this
interface, no command contains vendor SQL, and Oracle's shape does not leak
into what is written here. This module is that interface; nothing in it imports
a database client, and it is imported on every run including the ones that never
connect.

Deliberately a :class:`~typing.Protocol` rather than a base class, for the reason
:mod:`sopuli.store.protocol` gives: an implementation should not have to import
this in order to satisfy it. The Oracle driver will be written against
``oracledb`` and checked against this by mypy, which keeps the interface a
description of what the commands need rather than a place to put shared code.

**Four things changed shape between P1's sketch and this file**, and each is a
refinement rather than a disagreement -- the same way P2's ``write`` grew a
compare-and-set when the lock made it real (#83). ``00-principles.md`` P1 carries
them too, because the sketch there is the specification and this is the code.

*The session carries the operations.* P1 threads a session through every call,
which is C. Two things push the other way: capabilities are cached **per
session** (invariant 3), so a flat interface would need a cache keyed on a
connection -- which is this object with extra steps -- and ``capabilities()``
in the sketch takes no argument at all, which cannot be right for an estate
where twenty-one PDBs answer differently.

*``capabilities()`` folded into* :meth:`Session.scope`. Both are observed at one
moment, from one connection, and cached together; the run document already
prints them as one ``scope`` object. Two calls would mean two caches and a merge
at the output layer.

*``user_exists`` is* ``describe_user(...) is not None``. A caller that asks
whether an account exists asks what it is in the next breath, and UC-1 §5 step 3
is one step, not two. Keeping both would be one round trip spent on a question
the second call answers anyway.

*``opts`` has no members yet, so it has no type yet.* The sketch's
``set_password(..., opts)`` is where UC-1 §5's opt-in attributes will go --
profile assignment, unlock, expiry handling. An untyped bag now would accept a
misspelled ``container_clase: ALL`` and silently do nothing, which is the
failure ``01-configuration.md`` §10 exists to prevent.

``apply_attributes`` goes with it, and is **deliberately absent from**
:class:`Session` rather than declared and unimplemented -- the same seam P2
draws when it says ``health`` arrives with the secret side. A method on a
:class:`~typing.Protocol` is a demand on every implementation that satisfies it,
so declaring one nothing calls would oblige the Oracle driver to write a body
for a caller that does not exist. It stays in P1's sketch, which describes the
interface, and arrives here when `creds apply` grows attributes.

What is **not** deferred, and is worth saying because it looks like an omission:
there is no ``offline_verify`` path in :meth:`Session.verify_password` beyond a
method name. Whether the ``T:`` verifier in ``SYS.USER$.SPARE4`` can be
reproduced client-side is #90, unanswered, and if it cannot then ``--method
hash`` is dropped from the CLI entirely. So the vocabulary is representable --
it is the run document's, and the document was written before the doubt -- while
:data:`OFFLINE_VERIFY` exists in this build to gate UC-1 §7's ``LCOUNT`` guard
and nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from sopuli.config.model import ExpandedTarget
from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret

# ------------------------------------------------------------- capabilities ---
#
# P1's table, spelled once. A driver reports what it found; a command that needs
# an absent one refuses at plan time naming the capability and the target
# (invariant 4), which is what `require_capability` below is for.
#
# These are strings rather than an enum because they cross two boundaries that
# are already strings: the run document's `scope.capabilities`, and a test that
# declares what it needs (`04-testing.md` §3). A name is the contract.

#: The session holds ``ALTER USER`` **granted commonly**, which is what altering
#: a ``C##`` user with ``CONTAINER=ALL`` requires.
#:
#: A privilege, not a place. Where the session is standing is :attr:`Scope.type`,
#: and keeping the two apart is #195: the pair used to share one probe on the
#: reasoning that a common user is a thing which exists only in a CDB, and the
#: first real measurement showed the shared question was not answering either of
#: them. Oracle distinguishes the two failures itself -- ``ORA-01031`` for a
#: session that lacks the common grant, ``ORA-65040`` for one that holds it and
#: is in a PDB.
COMMON_USERS = "common_users"

#: Two passwords valid during a grace window. Oracle: 19.12+ / 21c+.
PASSWORD_ROLLOVER = "password_rollover"

#: A password can be verified against a stored hash without a login attempt.
#: Oracle: needs the optional ``SELECT ON SYS.USER$`` grant, which #86 decided is
#: **not** part of the default install. In this build it gates UC-1 §7's
#: ``LCOUNT`` guard; whether it ever gates ``--method hash`` is #90.
OFFLINE_VERIFY = "offline_verify"

#: The tool can read password profile parameters. Note *read*: altering a
#: profile is Q4 (#88), open, and the documented leaning is that the tool reports
#: the DDL rather than issuing it.
PROFILE_MANAGEMENT = "profile_management"

#: The server may reject a generated password -- Oracle's ``PASSWORD_REUSE_*``
#: and verify function. What makes UC-1 §4's bounded regeneration necessary.
PASSWORD_REUSE_POLICY = "password_reuse_policy"

#: Force expiry, or end a rollover window early.
EXPIRE_PASSWORD = "expire_password"

#: Lock state can be read and set.
ACCOUNT_LOCK_STATE = "account_lock_state"

#: Every capability P1 names. ``tests/driver/test_protocol.py`` checks this
#: against the table in ``00-principles.md`` itself, so a capability added to the
#: document and not to the code -- or the reverse -- fails rather than drifts.
CAPABILITIES = frozenset(
    {
        COMMON_USERS,
        PASSWORD_ROLLOVER,
        OFFLINE_VERIFY,
        PROFILE_MANAGEMENT,
        PASSWORD_REUSE_POLICY,
        EXPIRE_PASSWORD,
        ACCOUNT_LOCK_STATE,
    }
)


# ------------------------------------------------------------------ scopes ---

#: What the driver found the connection to be. The run document has typed this
#: since it was written, and ``config/targets.py`` accepts the same words minus
#: :data:`UNKNOWN` -- so the word a file *asserts* and the word the tool
#: *reports* are the same word, and a mismatch between them needs no translation
#: to explain (``01-configuration.md`` §3a).
SCOPE_TYPES = ("non_cdb", "cdb_root", "pdb", "app_root", "app_pdb", "unknown")

#: Observation-only, and the one scope a config file may never claim. A driver
#: that cannot tell says so; a file that said so would be asserting nothing.
UNKNOWN = "unknown"


# ------------------------------------------------------------ verification ---

VERIFY_LOGIN = "login"
VERIFY_HASH = "hash"
VERIFY_BOTH = "both"
VERIFY_NONE = "none"

#: The run document's ``verification.method``. ``login`` is what `check` defaults
#: to, unconditionally (Q1, #86); the other two exist in the vocabulary and are
#: refused by a driver that cannot honour them, which is #90's outcome either
#: way.
VERIFY_METHODS = (VERIFY_LOGIN, VERIFY_HASH, VERIFY_BOTH, VERIFY_NONE)

PASS = "pass"
FAIL = "fail"
SKIPPED = "skipped"
UNAVAILABLE = "unavailable"

#: The run document's ``verification.result``. ``skipped`` and ``unavailable``
#: are not the same answer and the difference matters at 03:00: *we chose not to
#: try* (the lockout margin, UC-1 §7 mitigation 2) versus *we could not*.
VERIFY_RESULTS = (PASS, FAIL, SKIPPED, UNAVAILABLE)


# ------------------------------------------------------------------ errors ---


class DriverError(Exception):
    """A driver could not do what was asked.

    ``category``, ``exit_code`` and ``code`` are on the class for the reason
    :class:`~sopuli.store.protocol.StoreError` puts the first two there: the
    boundary reports what the error says about itself rather than inferring it
    from an exception type. ``category`` is one of the run document's, and
    ``database`` is the default because a statement the server refused is
    neither a configuration problem nor a usage one.

    ``code`` carries the **vendor** code where there is one -- ``ORA-01017`` --
    because CLAUDE.md's rule is that an ORA- code is never swallowed. Mapping
    the families that deserve their own category and hint is #172; what this
    class provides is somewhere for the answer to live.
    """

    category = "database"
    exit_code = ExitCode.FAILURE

    def __init__(self, message: str, *, hint: str | None = None, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint
        self.code = code

    def __str__(self) -> str:
        if self.hint:
            return f"{self.message}\n  hint: {self.hint}"
        return self.message


class UnsupportedCapabilityError(DriverError):
    """The target cannot do what the command needs (invariant 4, P1).

    Exit 5, and the message names **the capability and the target** -- never a
    generic error, and never discovered halfway through a run. The name is kept
    on the exception as well as in the message because the run document has a
    field for it: ``error.target_capability``, which is what a consumer branches
    on instead of parsing prose.
    """

    category = "capability"
    exit_code = ExitCode.UNSUPPORTED_CAPABILITY

    def __init__(self, capability: str, *, target: str, hint: str | None = None) -> None:
        super().__init__(
            f'target "{target}" does not support {capability}',
            hint=hint,
        )
        self.capability = capability
        self.target = target


class AuthenticationError(DriverError):
    """The database refused the credential the tool connected with.

    Exit 6, the same code the vault side uses for the same failure, because a
    scheduler branching on "something could not authenticate" should not have to
    know which half of the run it was.

    Not to be confused with a *verification* login failing: that is drift, exit
    3, and it is a :class:`VerifyResult` rather than an exception. One
    ``ORA-01017`` means two entirely different things depending on whose
    credential it was, which is why #172 classifies rather than guesses.
    """

    category = "authentication"
    exit_code = ExitCode.AUTH_FAILURE


# ------------------------------------------------------------------- types ---


@dataclass(frozen=True)
class Credential:
    """What a driver needs in order to connect, once P2's bootstrap has run.

    Resolving one is #175's job -- ``external`` / ``vault`` / ``prompt`` /
    ``env``, in P2's order of preference. What arrives here is the outcome, and
    it is deliberately narrow: a username, a secret, or neither.

    ``external`` is the case with neither. A wallet or Kerberos supplies both
    identity and proof, the connection is made as ``/@alias``, and
    ``01-configuration.md`` §3a **refuses** a ``username:`` beside it rather
    than ignoring one -- a file that appears to name the connecting account
    while the wallet names another is worth stopping for, since "who" is half of
    every audit record.
    """

    username: str | None = None
    secret: Secret | None = None
    external: bool = False


@dataclass(frozen=True)
class Scope:
    """What the driver found when it connected -- observed, never configured.

    This is the run document's ``scope`` object minus ``labels``, which are the
    *config's* and are added by the view: a driver has no idea what a target set
    called this database, and inventing a field for it here would be a second
    place for labels to disagree with the estate.

    ``type`` and ``container`` are the two a target may *assert*
    (``01-configuration.md`` §3a). The driver reports what is true; comparing
    the two, and erroring with both values named, is #177's -- and it is the
    check that catches a ``dsn:`` edit which silently repointed a target at a
    different container.

    ``read_write`` is the one worth reading before the DDL. On a physical
    standby the answer is false, and P1 requires the refusal **up front** rather
    than a failure halfway through a statement.

    The document's ``offline_verify_available`` has no field here: it is
    ``supports(OFFLINE_VERIFY)``. One fact, reported twice in the schema because
    a consumer asks it directly, stored once here because two copies are two
    things that can disagree.
    """

    type: str = UNKNOWN
    container: str | None = None
    db_unique_name: str | None = None
    db_version: str | None = None
    open_mode: str | None = None
    read_write: bool | None = None
    capabilities: frozenset[str] = frozenset()
    #: How the tool is privileged here -- ``direct``, ``self`` or ``package``.
    #: Only ``direct`` is real (ADR-001); the others are the run schema's, kept
    #: so `doctor` (#182) has somewhere to put what it finds.
    privilege_model: str | None = None
    #: Privileges the service account holds and the tool does not need. A
    #: warning, never fatal: over-granting is what happens when somebody is
    #: debugging a permissions problem at 17:00 on a Friday, and the tool should
    #: notice rather than quietly benefit.
    over_granted: tuple[str, ...] = ()

    def supports(self, capability: str) -> bool:
        """Whether this connection reported ``capability``."""
        return capability in self.capabilities


@dataclass(frozen=True)
class UserState:
    """One account as the database describes it (UC-1 §3's ``DbState``).

    Three separate things read this: UC-1 §5's pre-flight, the client-side
    guardrails (#173), and `creds status`. It is product-neutral on purpose --
    P1 says Oracle's shape must not leak into the interface -- so the fields are
    named for what they *mean* and the Oracle driver maps its dictionary onto
    them:

    ================================  ==========================================
    field                             Oracle
    ================================  ==========================================
    ``status``                        ``DBA_USERS.ACCOUNT_STATUS``
    ``vendor_maintained``             ``DBA_USERS.ORACLE_MAINTAINED``
    ``password_file_member``          ``V$PWFILE_USERS``
    ``failed_logins``                 ``SYS.USER$.LCOUNT``
    ``failed_login_limit``            the profile's ``FAILED_LOGIN_ATTEMPTS``
    ``password_changed_at``           ``DBA_USERS.PASSWORD_CHANGE_DATE``
    ================================  ==========================================

    **``name`` is the spelling the database gave back**, and it is the only
    spelling that may reach a statement (``02-oracle-privileges.md`` §4). Never
    the raw string from the config file.

    Three fields are ``None``-when-unknown rather than defaulted, and the
    distinction is load-bearing in each case:

    * ``password_changed_at`` -- its source is version-dependent and
      **unconfirmed** (#87): absent from ``DBA_USERS`` on 11.2, where the same
      value means reading ``SYS.USER$.PTIME`` behind the optional grant. Nothing
      gates on it (Q9 made `--max-age-days` read the vault's ``rotated_at`` and
      only that), so reporting nothing costs nothing and guessing would be all
      cost.
    * ``failed_logins`` -- ``None`` where ``SELECT ON SYS.USER$`` was not
      granted, which is the default (#86). The ``LCOUNT`` guard is then
      unavailable and `check` must say so plainly rather than run a weaker
      version of it silently.
    * ``vendor_maintained`` -- ``None`` on 11.2, where the column does not
      exist. That is precisely the case the guardrails' literal deny list covers
      (``02-oracle-privileges.md`` §4 check 5), so it must not read as "no".
    """

    name: str
    status: str
    locked: bool = False
    expired: bool = False
    profile: str | None = None
    #: The profile's **effective** password limits, each as the database spells
    #: the value -- a number, ``UNLIMITED``, or a vendor word. Never ``DEFAULT``:
    #: Oracle reports that string for a resource the profile does not set, and
    #: resolving it against the ``DEFAULT`` profile happens in the driver so a
    #: caller cannot mistake the word for a threshold (#178).
    #:
    #: Separate fields rather than one bag, on ``01-configuration.md`` §10's
    #: argument: a mapping keyed by vendor resource names would accept a
    #: misspelled key and answer ``None`` to the caller that needed it.
    failed_login_limit: str | None = None
    #: ``PASSWORD_ROLLOVER_TIME``, which #181 reads at plan time to decide
    #: whether a rollover strategy can run here at all.
    rollover_time: str | None = None
    password_reuse_max: str | None = None
    password_reuse_time: str | None = None
    password_versions: tuple[str, ...] = ()
    password_changed_at: datetime | None = None
    failed_logins: int | None = None
    rollover_active: bool | None = None
    rollover_ends_at: datetime | None = None
    vendor_maintained: bool | None = None
    password_file_member: bool | None = None
    #: Roles held, upper-cased. Read by guardrail 4, which refuses an account
    #: holding ``DBA``, ``PDB_DBA``, ``CDB_DBA`` or ``AUDIT_ADMIN``.
    roles: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ChangeResult:
    """What one mutating call did.

    ``changed`` is the run document's ``results[].changed``, and it is
    deliberately not the same question as ``state``: one is *whether this run did
    anything*, the other is *what is true now*. An idempotent re-run reports
    ``changed: false`` and a perfectly healthy state, and collapsing the two
    would break one of the two consumers (``03-json-output.md`` §2).
    """

    changed: bool
    detail: str | None = None


@dataclass(frozen=True)
class VerifyResult:
    """The answer to "does this password work here", and how hard it was asked.

    Mirrors the run document's ``verification``. ``result`` is never an
    exception: a wrong password is drift (exit 3), which is what makes `check`
    schedulable, and an exception here would make a scheduled check
    indistinguishable from a broken one.

    ``lockout_margin_hit`` is the field that says the tool **declined to try**.
    UC-1 §7's whole point is that a naive check locks production accounts, so
    "we did not attempt this" has to be reportable as its own outcome rather
    than folded into a failure.
    """

    method: str
    result: str
    latency_ms: int | None = None
    failed_logins: int | None = None
    failed_login_limit: str | None = None
    lockout_margin_hit: bool = False
    detail: str | None = None


# --------------------------------------------------------------- interface ---


@runtime_checkable
class Session(Protocol):
    """A live connection to one target, and everything done through it.

    Every method here is scoped to the target this session reached. That is the
    reason the operations live on the session rather than on the driver: the
    same driver reaches twenty-one PDBs with twenty-one different capability
    sets, and invariant 3 caches the answer per session.
    """

    def scope(self) -> Scope:
        """What this connection is, and what it can do.

        Probed on first use and **cached for the life of the session**
        (invariant 3). Never derived from a version number in the config file --
        that is the rule this method exists to make unavoidable.
        """
        ...

    def describe_user(self, account: str) -> UserState | None:
        """The account's state, or ``None`` if there is no such account.

        ``None`` is UC-1's ``ACCOUNT_MISSING``, and it is not an error: the tool
        does not create accounts (Q8 -- provisioning belongs to its own use
        case), so a missing one is a state to report, not a failure to recover
        from.
        """
        ...

    def set_password(self, account: str, secret: Secret) -> ChangeResult:
        """Set ``account``'s password to ``secret``.

        The one call in this interface that reveals a secret, which is one of
        invariant 2's three permitted reveals.

        Implementations are bound by invariants 11, 13 and 14: a password
        containing ``"`` is refused rather than escaped, the statement is never
        wrapped in a PL/SQL block, and the password is never bound. #171 is the
        statement builder those apply to; this is the call that issues what it
        built.
        """
        ...

    def verify_password(
        self, account: str, secret: Secret, *, method: str = VERIFY_LOGIN
    ) -> VerifyResult:
        """Whether ``secret`` authenticates as ``account``.

        ``method`` is one of :data:`VERIFY_METHODS`; ``login`` is the default
        unconditionally (Q1, #86). A driver that cannot honour a method raises
        :class:`UnsupportedCapabilityError` rather than quietly doing a
        different one -- the distinction between "verified by hash" and
        "verified by logging in" is the difference between no lockout risk and
        some.

        **One attempt, and no retry** (UC-1 §7 mitigation 1). This signature
        takes one secret and returns one result for that reason: there is no
        shape here for a back-off loop to hide in.
        """
        ...

    def close(self) -> None:
        """Release the connection. Called on every path, including failure."""
        ...


@runtime_checkable
class Driver(Protocol):
    """What opens sessions for one product.

    Small on purpose. Everything a command does happens through a
    :class:`Session`, so this is a factory and a place for the registry (#170)
    to land after it imports a vendor client on first use.
    """

    def connect(self, target: ExpandedTarget, credential: Credential) -> Session:
        """Connect to ``target``.

        Raises :class:`AuthenticationError` when the credential is refused, and
        :class:`DriverError` for anything else that stopped the connection.
        """
        ...


def require_capability(scope: Scope, capability: str, *, target: str) -> None:
    """Refuse unless ``scope`` reported ``capability`` (invariant 4).

    Called at **plan time**, before anything is written anywhere. The whole
    value of the capability model is that `--strategy rollover` against 18c
    fails while the plan is being printed rather than after two of five targets
    already have a new password.
    """
    if not scope.supports(capability):
        raise UnsupportedCapabilityError(capability, target=target)

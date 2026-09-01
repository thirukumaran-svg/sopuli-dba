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

*``opts`` is* :class:`AccountAttributes`, *and it is an argument of its own.*
The sketch's ``set_password(..., opts)`` is where UC-1 §5's opt-in attributes
were to go, and they arrived beside it rather than inside it (#300): §5 requires
each attribute to be *reported as a separate change*, and a password set that
also unlocked would be one ``ChangeResult`` describing two mutations. What the
sketch's warning was really about is the shape, and that is kept whole -- one
typed field per attribute, never a bag, because an untyped one would accept a
misspelled ``container_clase: ALL`` and silently do nothing, which is the failure
``01-configuration.md`` §10 exists to prevent.

``apply_attributes`` **arrived with the caller that needed it** (#300, the first
of #267's four attributes), which is the seam this file described until then and
the same one P2 drew around ``health``: a method on a
:class:`~typing.Protocol` is a demand on every implementation that satisfies it,
so one that nothing calls would oblige the Oracle driver to write a body for a
caller that does not exist. Three attributes are still to come -- profile
assignment (#301), expiry (#302), tablespaces (#303) -- and each is a field on
:class:`AccountAttributes` rather than a method here.

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


# -------------------------------------------------------------- attributes ---

#: Unlock an account that is locked (UC-1 §5, #300).
#:
#: **The run document's own ``action_kind`` word**, and deliberately not a second
#: vocabulary translated into it at the output layer. The verification results
#: above set the precedent: what a driver reports about a step is what the
#: document calls that step, so a driver adding an attribute cannot forget to
#: teach a renderer about it. `03-json-output.md` §9 has the enum.
ACCOUNT_UNLOCK = "account_unlock"

#: Every attribute :class:`AccountAttributes` can carry, in the order
#: :meth:`Session.apply_attributes` enforces them. One entry today; #301, #302
#: and #303 are the other three UC-1 §5 names.
ATTRIBUTES = (ACCOUNT_UNLOCK,)


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
class PrivilegeAudit:
    """What a service account is granted, on both sides, and what was not checked.

    A driver's answer to "is this account fit to run the tool" (#213, #225), and
    that is **two independent questions** rather than one: what it holds and
    should not (``over_granted``), and what it needs and may not have
    (``held``/``missing``). An account can be in both states at once, which is
    what a half-finished debugging session leaves behind, so neither answer
    implies anything about the other.

    A third thing is carried and is not a finding: **what was not looked at**.
    ``unaudited`` and ``unreadable`` are the difference between "I looked and
    found nothing" and "I could not look", and a report that merged them would
    have its most reassuring output be its least trustworthy.

    Here rather than in a driver package for the reason :class:`Scope` is here:
    the output layer renders it, and one that imported a vendor module would make
    ``sopuli.output`` depend on which database a site happens to run. What is
    vendor-specific is *which* privileges these are and how they are discovered
    -- for Oracle, :mod:`sopuli.driver.oracle.privileges` -- and none of that
    appears in the shape.

    Sorted throughout, because this reaches a report a human compares between
    runs and dictionary order is nobody's contract.
    """

    #: §3 entries this account holds. What ``scope.over_granted`` carries.
    over_granted: tuple[str, ...] = ()
    #: §2 grants this account has. The positive side (#225): a half-installed
    #: account is visible *here* rather than as six unrelated failures three
    #: commands later.
    held: tuple[str, ...] = ()
    #: §2 grants it does not have, spelled as the ``GRANT`` to issue. Empty is
    #: the answer a correct install gives, and the reason this section is emitted
    #: whether or not it is empty: a section that appeared only on a problem
    #: could not be quoted as evidence that there was none (E6).
    missing: tuple[str, ...] = ()
    #: Every role held, traversed. Reported whole rather than only where it
    #: matched, so a reader can see *how* an over-grant arrived -- a site role
    #: two levels up is the case #178 measured and the one nobody guesses.
    roles: tuple[str, ...] = ()
    #: Direct system privileges granted commonly (``USER_SYS_PRIVS.COMMON``),
    #: which for a ``C##`` account is the difference between a grant that reaches
    #: every PDB and one that reaches this one.
    common: tuple[str, ...] = ()
    #: §3 entries that were not checked, and why. :data:`UNAUDITABLE` always,
    #: plus anything a refused view took with it.
    unaudited: tuple[str, ...] = ()
    #: Views that raised. Empty is the ordinary case; non-empty means the audit
    #: is partial and the report has to say so rather than read as clean.
    unreadable: tuple[str, ...] = ()

    def caveats(self) -> tuple[str, ...]:
        """What a reader has to know before trusting ``over_granted``.

        Both lines, and the always-true one is deliberate. E6's argument for
        `doctor`'s install shape applies here word for word: a caveat that
        appears only when something is wrong cannot be quoted as evidence that
        nothing was. Somebody handing this run to an auditor needs "SYSDBA was
        not among the things checked" written down, not inferred from its
        absence.
        """
        lines = []
        if self.unreadable:
            lines.append("this audit is partial -- could not read " + ", ".join(self.unreadable))
        if self.unaudited:
            lines.append("not checked, and not visible from here: " + ", ".join(self.unaudited))
        return tuple(lines)

    @property
    def complete(self) -> bool:
        """Whether every row of §3's list actually got looked at.

        Never true today -- :data:`UNAUDITABLE` is always in ``unaudited`` -- and
        it is a property rather than a constant because that is a fact about
        §2's grant set rather than about this code, and the grant set can change.
        """
        return not self.unaudited and not self.unreadable


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
    #: Whether the account's **profile** grants a rollover window at all, which
    #: is a different question from :attr:`rollover_active` -- that is whether one
    #: is open *now*. Read by :mod:`sopuli.strategy` (#262) to decide which regime
    #: a change will run under, and computed here rather than there because
    #: ``rollover_time`` is a string in whatever the database spells and parsing
    #: it is vendor work. ``None`` where nothing was read -- which
    #: :func:`sopuli.strategy.opens_window` takes as *no*, the direction that
    #: cannot surprise anybody.
    rollover_enabled: bool | None = None
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


@dataclass(frozen=True)
class AccountAttributes:
    """The non-password attributes a run may enforce on an account (UC-1 §5).

    P1's ``opts``, typed. **One field per attribute and never a mapping**, which
    is ``01-configuration.md`` §10's rule and the reason this type exists at all:
    a bag would accept a misspelled key, do nothing, and report that it had done
    nothing wrong. Three more fields are coming -- profile assignment (#301),
    expiry (#302), tablespaces (#303) -- and each arrives with the config field
    that declares it.

    **Every attribute is opt-in and defaults to off.** UC-1 §5's rule, and the
    reason it is not merely a default: a tool that unlocked an account because it
    found one locked, or moved it to a profile because a policy named one, would
    be making a change nobody asked for during a credential rotation -- which is
    the worst moment in the estate for a surprise.
    """

    #: Unlock a locked account before the password is set. Declared by
    #: ``policies.<name>.account.unlock_if_locked``.
    unlock: bool = False

    def requested(self) -> bool:
        """Whether anything at all was declared.

        The caller's reason to skip :meth:`Session.apply_attributes` entirely:
        an estate that declares no attributes pays no round trip for the ones it
        did not ask for.
        """
        return self.unlock


@dataclass(frozen=True)
class AttributeChange:
    """What enforcing **one** attribute did.

    A :class:`ChangeResult` with the attribute's name on it, rather than the one
    result P1's sketch returned for the whole call. UC-1 §5 asks for each
    attribute to be *reported as a separate change so the diff stays readable*,
    and a single result for four attributes could not say which of them moved.

    ``changed`` is the same question it is everywhere else -- *did this run do
    it* -- so an account that was already unlocked comes back ``False`` with a
    detail saying so, and invariant 9 is satisfied by the driver rather than by a
    caller remembering to ask first.
    """

    #: One of :data:`ATTRIBUTES`, which is the document's ``action_kind`` word.
    attribute: str
    changed: bool
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

    def apply_attributes(
        self, account: str, attributes: AccountAttributes
    ) -> tuple[AttributeChange, ...]:
        """Enforce the non-password attributes ``attributes`` declares (UC-1 §5).

        **One entry per attribute that was declared**, in :data:`ATTRIBUTES`
        order, whether or not it turned out to need doing -- an account that is
        already unlocked is ``changed: False`` and a row saying so, not an absent
        row. §5 wants each attribute reported as its own change, and a consumer
        that had to infer "not declared" from "not present" would be reading the
        policy out of the results.

        **Nothing is inferred.** An attribute the caller did not set is not
        enforced, so a run against an estate declaring none of them returns an
        empty tuple and issues nothing.

        **Idempotent, and the driver is what makes it so** (invariant 9): the
        implementation reads the account's state and issues nothing where the
        attribute already holds. That is the opposite of :meth:`set_password`,
        which cannot ask a database whether a password is already a given value
        -- here the state is readable, so a second run reports ``changed: False``
        without the command having to remember to check.

        Raises :class:`UnsupportedCapabilityError` where the target cannot do
        what was asked, naming the capability (invariant 4).
        """
        ...

    def verify_password(
        self,
        account: str,
        secret: Secret,
        *,
        method: str = VERIFY_LOGIN,
        lockout_margin: int = 2,
        attempts: int = 1,
    ) -> VerifyResult:
        """Whether ``secret`` authenticates as ``account``.

        ``lockout_margin`` is UC-1 §7 mitigation 2's headroom -- how many failed
        logins the driver must leave unspent -- and it is **on the interface
        rather than only on the driver** because `check --lockout-margin` is a
        flag: a command calls this protocol, so a margin that lived on the Oracle
        implementation alone would be configurable in the CLI and silently 2 by
        the time it reached a database.

        ``attempts`` is how many logins the run intends against this account, so
        that a second value checked (`--include-previous`) is budgeted before it
        is spent rather than doubling the spend on the counter the margin
        protects.

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

    def require_rollover(self, account: str) -> None:
        """Refuse ``--strategy rollover`` for ``account`` here, or say nothing.

        Two conditions, failing differently, which is why this is one call rather
        than a capability check somebody has to remember to pair with a profile
        read (#181):

        * **the release has no such feature** --
          :class:`UnsupportedCapabilityError`, exit 5, naming the capability and
          the target (invariant 4);
        * **the account's profile grants no window** -- a
          :class:`DriverError` whose hint carries the exact ``ALTER PROFILE`` an
          operator would run. The tool never issues it: profiles are shared, so
          changing one affects accounts nobody selected, and Q4 (#88) is open with
          a documented leaning of no.

        On the protocol as of #262, which is when it acquired a caller.
        :mod:`sopuli.strategy` deliberately does not restate either refusal -- the
        second is that product's SQL, and a hint is a thing operators paste into a
        terminal.
        """
        ...

    def finish_rollover(self, account: str) -> ChangeResult:
        """End ``account``'s open rollover window now, or report there was none.

        ``changed: false`` where no window is open, which is invariant 9 and not
        caution: measured on 26ai, issuing the statement with no window open is
        accepted silently and changes nothing, so a driver that just issued it
        would report a change for every run that did nothing.

        Called by ``creds apply --strategy direct`` **after** the change has been
        verified. Closing a window on a change nobody confirmed would leave an
        account whose old password has stopped working and whose new one is not
        known to work.
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

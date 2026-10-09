"""The driver interface (P1), as far as UC-1 needs it.

P1's rule is that every operation touching a database goes through this
interface, no command contains vendor SQL, and Oracle's shape does not leak
into what is written here. This module is that interface; nothing in it imports
a database client, and it is imported on every run including the ones that never
connect.

Deliberately a :class:`~typing.Protocol` rather than a base class, for the reason
:mod:`sopuli.store.protocol` gives: an implementation should not have to import
this in order to satisfy it. The Oracle driver is written against ``oracledb``
and checked against this by mypy, which keeps the interface a description of
what the commands need rather than a place to put shared code.

**This file refines P1's sketch in the ways below.** Each is a refinement, not
a disagreement. ``00-principles.md`` P1 records them too, because the sketch
there is the specification and this is the code.

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
would go. They are a separate call, :meth:`Session.apply_attributes`, because
§5 requires each attribute to be *reported as a separate change*: a password set
that also unlocked would be one ``ChangeResult`` describing two mutations. The
sketch's warning was about the shape, and that is kept: one typed field per
attribute, never a bag. An untyped bag would accept a misspelled
``container_clase: ALL`` and silently do nothing, which is the failure
``01-configuration.md`` §10 exists to prevent.

**UC-1 §5's attribute list is closed**: unlock and profile assignment.
``PASSWORD_EXPIRE`` handling and tablespaces belong to other use cases
(decisions #302 and #303). The first is not an operation this use case has. The
second is provisioning's, since assigning a tablespace moves no existing segment.
A new field on :class:`AccountAttributes` is a decision, not an implementation
detail.

:meth:`Session.verify_password` takes a ``method``. ``login`` logs in. ``hash``
reproduces the ``T:`` verifier in ``SYS.USER$.SPARE4`` client-side and compares
it, with no login attempt. ``both`` does the comparison and then logs in. The
releases on which the verifier reproduces are the ``06_verifier_reproduce.sql``
rows of ``docs/measurements.md``. Only
the ``12C`` verifier is compared: an account without one fails at plan time
(invariant 4) rather than falling back to a weaker verifier.
:data:`OFFLINE_VERIFY` gates ``hash`` and ``both``, UC-1 §7's ``LCOUNT`` guard,
and the ``PTIME`` fallback for :attr:`UserState.password_changed_at`, because all
of them read ``SYS.USER$``.
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
#: A privilege, not a place. Where the session is standing is :attr:`Scope.type`.
#: The two are separate questions (decision #195): one probe cannot answer both.
#: Oracle distinguishes the two failures itself -- ``ORA-01031`` for a session
#: that lacks the common grant, ``ORA-65040`` for one that holds it and is in a
#: PDB.
COMMON_USERS = "common_users"

#: Two passwords valid during a grace window. Oracle: 19.12+ / 21c+.
PASSWORD_ROLLOVER = "password_rollover"

#: A password can be verified against a stored hash without a login attempt.
#: Oracle: needs the optional ``SELECT ON SYS.USER$`` grant, which is **not**
#: part of the default install (decision P2). It gates ``--method hash`` and ``both``,
#: UC-1 §7's ``LCOUNT`` guard, and the ``PTIME`` fallback.
OFFLINE_VERIFY = "offline_verify"

#: The tool can read password profile parameters. Note *read*: the tool never
#: alters a profile (Q4). It reports the DDL for an operator to run.
PROFILE_MANAGEMENT = "profile_management"

#: The server may reject a generated password -- Oracle's ``PASSWORD_REUSE_*``
#: and verify function. What makes UC-1 §4's bounded regeneration necessary.
PASSWORD_REUSE_POLICY = "password_reuse_policy"

#: Force expiry, or end a rollover window early.
EXPIRE_PASSWORD = "expire_password"

#: Lock state can be read and set.
ACCOUNT_LOCK_STATE = "account_lock_state"

#: Which roles exist can be read, which is what tells a misspelled ``role:``
#: predicate from one that matches nobody (UC-2 §2). Oracle: ``SELECT ON
#: SYS.DBA_ROLES``, in §2's grant set. A service account without that grant
#: reports it absent, and `account list` refuses a role predicate there at plan
#: time rather than calling a real role misspelled.
ROLE_LOOKUP = "role_lookup"

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
        ROLE_LOOKUP,
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
#: to, unconditionally (Q1). The Oracle driver honours ``hash`` by comparing the
#: stored 12C verifier, and ``both`` by comparing first and logging in only if
#: that passed. A driver that cannot honour a method refuses it rather than
#: doing another.
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

#: Unlock an account that is locked (UC-1 §5).
#:
#: **The run document's own ``action_kind`` word**, and deliberately not a second
#: vocabulary translated into it at the output layer. The verification results
#: above set the precedent: what a driver reports about a step is what the
#: document calls that step, so a driver adding an attribute cannot forget to
#: teach a renderer about it. `03-json-output.md` §9 has the enum.
ACCOUNT_UNLOCK = "account_unlock"

#: Assign the account to the profile the policy names (UC-1 §5).
#:
#: **The generic kind, and deliberately so.** ``account_unlock`` has a kind of
#: its own because unlocking is a distinct *operation* a reader looks for.
#: Assigning a profile is exactly *an attribute was set*, which is what this enum
#: value means. The detail names the attribute and both profiles, so attributes
#: that share this kind stay as readable as §5 asks. A kind per attribute would
#: cost a schema bump each time, on a contract consumers branch on.
ATTRIBUTE_SET = "attribute_set"

#: Suspend an account: ``ALTER USER … ACCOUNT LOCK`` (UC-2).
#:
#: **Not one of** :data:`ATTRIBUTE_KINDS`, and the absence is deliberate. Those
#: are the attributes a *policy* declares and `creds apply` enforces on its way
#: past; this is a verb an operator types, about a person who has left. So it
#: reports as an :class:`AccountChange` rather than an
#: :class:`AttributeChange` -- a value outside ``ATTRIBUTE_KINDS`` carried in a
#: field documented as one of them would be a contract saying two things.
#:
#: The run schema's ``action_kind`` enum lists it, because ``account suspend``
#: reports it.
ACCOUNT_LOCK = "account_lock"

#: Set an account's password: ``ALTER USER … IDENTIFIED BY`` (UC-2 §4.1).
#:
#: The same word UC-1's `creds apply` emits, so a personal reset and an
#: application rotation report a password change alike. :data:`ACCOUNT_UNLOCK`
#: above sets the rule: what a driver calls a step is what the document calls it,
#: not a second vocabulary translated at the output layer.
#:
#: `output/apply_view.py` and `output/finish_rollover_view.py` spell this and
#: :data:`ROLLOVER_FINISH` as literals. A driver uses these constants and never a
#: spelling of its own.
PASSWORD_SET = "password_set"

#: End an open password rollover window: ``ALTER USER … EXPIRE PASSWORD ROLLOVER
#: PERIOD`` (UC-1 §6.3, UC-2 §4.3).
ROLLOVER_FINISH = "rollover_finish"

#: Expire an account's password without setting one: the bare
#: ``ALTER USER … PASSWORD EXPIRE`` (UC-2 §2).
#:
#: Its own kind rather than :data:`PASSWORD_SET`, because no password is set.
#: The seen reset's ``IDENTIFIED BY … PASSWORD EXPIRE`` sets one and reports as
#: that. A reader who met ``password_set`` on a verb that draws nothing would be
#: told something false.
PASSWORD_EXPIRE = "password_expire"

#: What an account verb reports as, and the tuple exists for the reason
#: :data:`ATTRIBUTE_KINDS` does -- so a verb cannot report a kind without a
#: renderer noticing.
#:
#: A verb that issues several statements as one operation reports each as its
#: own row: the reset issues up to three (UC-2 §4.1), and `expire-password` two.
#: That is `apply_attributes`' rule read for a verb: a row per statement the
#: operation *considered*, so an account that was not locked says so rather than
#: being absent from the answer.
ACCOUNT_ACTIONS = (ACCOUNT_LOCK, ACCOUNT_UNLOCK, PASSWORD_SET, ROLLOVER_FINISH, PASSWORD_EXPIRE)

#: The kinds an :class:`AttributeChange` reports as, in the order
#: :meth:`Session.apply_attributes` enforces them.
#:
#: Kinds rather than attributes, and the two are not one-to-one: a kind may serve
#: several attributes, which is what :data:`ATTRIBUTE_SET` is for. What
#: distinguishes them on the row is the detail, which is why every implementation
#: writes one.
ATTRIBUTE_KINDS = (ACCOUNT_UNLOCK, ATTRIBUTE_SET)


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
    because CLAUDE.md's rule is that an ORA- code is never swallowed. A driver
    maps the code families that deserve their own category and hint; this class
    is where the answer lives.
    """

    category = "database"
    exit_code = ExitCode.FAILURE

    #: Whether the *password* was refused, and another should be drawn.
    #:
    #: On the class, and ``False``, for the same reason ``category`` and
    #: ``exit_code`` are: the boundary reports what an error says about itself
    #: rather than inferring it from an exception type. A driver that classifies
    #: its vendor codes sets it on the instance -- Oracle's does, from the
    #: ``regenerate`` that its own ``Diagnosis`` already computed -- and one that
    #: does not gets the safe answer without having to know the question.
    #:
    #: **``False`` is the answer that cannot loop**, which is why it is the
    #: default rather than something a driver must remember to deny. An unmapped
    #: code might be transient and might be a value the server will refuse
    #: forever; of the two ways to be wrong, drawing again is the one that burns
    #: rotations and locks accounts.
    #:
    #: Vendor-neutral on purpose. `sopuli.apply` is above the driver and must not
    #: import an Oracle module to find out that Oracle refused a password.
    regenerate = False

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
    credential it was, which is why the driver classifies rather than guesses.
    """

    category = "authentication"
    exit_code = ExitCode.AUTH_FAILURE


# ------------------------------------------------------------------- types ---


@dataclass(frozen=True)
class Credential:
    """What a driver needs in order to connect, once P2's bootstrap has run.

    The bootstrap resolves one from ``external`` / ``vault`` / ``prompt`` /
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

    A driver's answer to "is this account fit to run the tool", and that is
    **two independent questions** rather than one: what it holds and should not
    (``over_granted``), and what it needs and may not have (``held``/``missing``).
    An account can be in both states at once, which is what a half-finished
    debugging session leaves behind, so neither answer implies anything about the
    other.

    A third thing is carried and is not a finding: **what was not looked at**.
    ``unaudited`` and ``unreadable`` are the difference between "I looked and
    found nothing" and "I could not look", and a report that merged them would
    have its most reassuring output be its least trustworthy. ``remedies`` is the
    part of that a site can do something about.

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
    #: §2 grants this account has. The positive side: a half-installed
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
    #: two levels up is a real case, and the one nobody guesses.
    roles: tuple[str, ...] = ()
    #: Direct system privileges granted commonly (``USER_SYS_PRIVS.COMMON``),
    #: which for a ``C##`` account is the difference between a grant that reaches
    #: every PDB and one that reaches this one.
    common: tuple[str, ...] = ()
    #: §3 entries that were not checked: the rows no view carries, plus whatever
    #: a refused or ungranted one took with it. Never empty on Oracle, where one
    #: row has no view to read at all.
    unaudited: tuple[str, ...] = ()
    #: Views that raised. Empty is the ordinary case; non-empty means the audit
    #: is partial and the report has to say so rather than read as clean.
    #:
    #: **A grant the product documents as optional does not belong here**: an
    #: estate that declined it is installed as documented, and a report that
    #: called every correct install partial would teach a reader to skip the
    #: line. Those rows go to ``unaudited`` and bring a ``remedies`` entry.
    unreadable: tuple[str, ...] = ()
    #: What a site could do to shrink ``unaudited``, in the product's own words.
    #:
    #: Empty where nothing would help, which is the ordinary meaning of a row
    #: being unauditable. The strings are the driver's because a ``GRANT``
    #: statement is a fact about one product, and this class is deliberately free
    #: of any -- the same seam
    #: :data:`~sopuli.diagnostics.GUARDRAIL_REMEDIES` sits on. Rendered as a
    #: caveat rather than emitted in the run document, so no consumer parses it.
    #:
    #: **The one field here that is not sorted**, and the exception is the class
    #: docstring's own reason read the other way: sorting exists because
    #: dictionary order is nobody's contract, and every other field holds names
    #: that arrive from a query or a set. These are sentences, produced by a
    #: driver in a fixed sequence, and alphabetising prose orders it by whichever
    #: word happens to start it. :meth:`caveats` already orders by meaning rather
    #: than by spelling -- the partial-audit line first, because it changes how
    #: the rest is read -- and this follows that.
    remedies: tuple[str, ...] = ()

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
        # Last, and separate lines rather than a clause on the one above: the
        # caveat is what an auditor quotes and the remedy is what an operator
        # acts on, and only some of the rows above have one.
        lines.extend(self.remedies)
        return tuple(lines)

    @property
    def complete(self) -> bool:
        """Whether every row of §3's list actually got looked at.

        Never true on Oracle, and it is a property rather than a constant
        because that is a fact about §2's grant set rather than about this code,
        and the grant set can change. On Oracle one row is an object privilege
        with no view to read, which is a design question rather than a grant.
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
    the two, and erroring with both values named, is
    :func:`sopuli.driver.oracle.capabilities.assert_scope`'s job. That check
    catches a ``dsn:`` edit which silently repointed a target at a
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
    #: so `doctor` has somewhere to put what it finds.
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
    guardrails, and `creds status`. It is product-neutral on purpose --
    P1 says Oracle's shape must not leak into the interface -- so the fields are
    named for what they *mean* and the Oracle driver maps its dictionary onto
    them:

    ================================  ==========================================
    field                             Oracle
    ================================  ==========================================
    ``status``                        ``DBA_USERS.ACCOUNT_STATUS``
    ``password_expires_at``           ``DBA_USERS.EXPIRY_DATE``
    ``vendor_maintained``             ``DBA_USERS.ORACLE_MAINTAINED``
    ``password_file_member``          ``V$PWFILE_USERS``
    ``failed_logins``                 ``SYS.USER$.LCOUNT``
    ``failed_login_limit``            the profile's ``FAILED_LOGIN_ATTEMPTS``
    ``password_changed_at``           ``DBA_USERS.PASSWORD_CHANGE_DATE``, or
                                      ``SYS.USER$.PTIME`` where that column
                                      does not exist
    ================================  ==========================================

    **``name`` is the spelling the database gave back**, and it is the only
    spelling that may reach a statement (``02-oracle-privileges.md`` §4). Never
    the raw string from the config file.

    Three fields are ``None``-when-unknown rather than defaulted, and the
    distinction is load-bearing in each case:

    * ``password_changed_at`` -- its source depends on the release (decision #386).
      Where ``DBA_USERS`` has no ``PASSWORD_CHANGE_DATE`` column the value is
      ``SYS.USER$.PTIME``, behind the optional grant, and ``None`` without it. Which
      releases have the column is in ``docs/measurements.md``; 12.1 is unmeasured
      (unverified: pw-changed-source). Nothing gates on it (Q9: `--max-age-days`
      reads the vault's ``rotated_at`` and only that), so reporting nothing costs
      nothing and guessing would be all cost. Saying *why* there is nothing is
      :attr:`password_changed_unknown`.
    * ``failed_logins`` -- ``None`` where ``SELECT ON SYS.USER$`` was not
      granted, which is the default (decision P2). The ``LCOUNT`` guard is then
      unavailable and `check` must say so plainly rather than run a weaker
      version of it silently.
    * ``vendor_maintained`` -- ``None`` on 11.2, where the column does not
      exist. That is precisely the case the guardrails' literal deny list covers
      (``02-oracle-privileges.md`` §4 check 5), so it must not read as "no".
    """

    name: str
    status: str
    locked: bool = False
    #: The password has **stopped working**. Deliberately not true of an account
    #: in its grace period, which is :attr:`in_grace` -- Oracle spells that
    #: ``EXPIRED(GRACE)``, and the token ``EXPIRED`` is inside it. Reading the two
    #: as one would make `check` report a working account as expired and skip the
    #: login that would prove it.
    expired: bool = False
    #: The password still works and is on notice: past its ``PASSWORD_LIFE_TIME``
    #: and inside the window ``PASSWORD_GRACE_TIME`` grants. Mutually exclusive
    #: with :attr:`expired` -- one is a credential that has stopped working and
    #: the other is one that has not.
    in_grace: bool = False
    profile: str | None = None
    #: The profile's **effective** password limits, each as the database spells
    #: the value -- a number, ``UNLIMITED``, or a vendor word. Never ``DEFAULT``:
    #: Oracle reports that string for a resource the profile does not set, and
    #: resolving it against the ``DEFAULT`` profile happens in the driver so a
    #: caller cannot mistake the word for a threshold.
    #:
    #: Separate fields rather than one bag, on ``01-configuration.md`` §10's
    #: argument: a mapping keyed by vendor resource names would accept a
    #: misspelled key and answer ``None`` to the caller that needed it.
    failed_login_limit: str | None = None
    #: ``PASSWORD_ROLLOVER_TIME``, which :meth:`Session.require_rollover` reads
    #: at plan time to decide whether a rollover strategy can run here at all.
    rollover_time: str | None = None
    password_reuse_max: str | None = None
    password_reuse_time: str | None = None
    password_versions: tuple[str, ...] = ()
    password_changed_at: datetime | None = None
    #: Why :attr:`password_changed_at` is ``None``, in the driver's words, and
    #: ``None`` whenever it is not. A sentence rather than an enum because the
    #: useful part is product-specific -- *which* view is missing and *which*
    #: grant supplies the value -- and this object is not allowed to know that.
    #:
    #: Without it the absence would look the same whatever caused it: ``-`` in
    #: `creds status`, and no ``password_age_days`` in the run document, whether
    #: the release has no such column or something could not be read. Only one
    #: of those is worth investigating.
    password_changed_unknown: str | None = None
    #: When the password stops working, from ``DBA_USERS.EXPIRY_DATE``. During a
    #: grace period this is the **end of the grace window**, which is what makes
    #: it the deadline worth reporting: in "in sync, and expiring on Friday",
    #: *when* is most of the sentence.
    #:
    #: ``None`` where the profile expires nothing, which is the ordinary state of
    #: an account on a profile with ``PASSWORD_LIFE_TIME UNLIMITED``. Never
    #: substituted for: no date and a date in the far future are different
    #: answers, and only one of them is true.
    password_expires_at: datetime | None = None
    failed_logins: int | None = None
    rollover_active: bool | None = None
    rollover_ends_at: datetime | None = None
    #: Whether the account's **profile** grants a rollover window at all, which
    #: is a different question from :attr:`rollover_active` -- that is whether one
    #: is open *now*. Read by :mod:`sopuli.strategy` to decide which regime
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
    #: What the server said on a login that **succeeded**, in its own words and
    #: carrying its vendor code.
    #:
    #: Separate from :attr:`detail` rather than folded into it, and the separation
    #: is the point: ``detail`` explains the ``result`` -- why this is a pass, a
    #: fail or an unavailable -- while this is a diagnostic that came *with* a
    #: pass and explains nothing about it. A consumer alerting on "the server had
    #: something to say" would otherwise have to parse the sentence that says why
    #: verification succeeded.
    #:
    #: ``None`` on every ordinary login, which is almost all of them.
    warning: str | None = None


@dataclass(frozen=True)
class AccountAttributes:
    """The non-password attributes a run may enforce on an account (UC-1 §5).

    P1's ``opts``, typed. **One field per attribute and never a mapping**, which
    is ``01-configuration.md`` §10's rule and the reason this type exists at all:
    a bag would accept a misspelled key, do nothing, and report that it had done
    nothing wrong. **UC-1 §5's list is closed**, and its other names belong to
    other use cases (decisions #302 and #303), so a new field here is a decision
    rather than an implementation detail.

    **Every attribute is opt-in and defaults to off.** UC-1 §5's rule, and the
    reason it is not merely a default: a tool that unlocked an account because it
    found one locked, or moved it to a profile because a policy named one, would
    be making a change nobody asked for during a credential rotation -- which is
    the worst moment in the estate for a surprise.
    """

    #: Unlock a locked account before the password is set. Declared by
    #: ``policies.<name>.account.unlock_if_locked``.
    unlock: bool = False
    #: The profile the account is to sit on, or ``None`` where none was declared.
    #: ``policies.<name>.account.profile``.
    #:
    #: **A name out of a file, so it is not the spelling that reaches a
    #: statement.** Which profiles exist is a property of each target, and
    #: ``02-oracle-privileges.md`` §4's rule about account names applies here
    #: unchanged: the driver resolves it against the dictionary and uses what came
    #: back. :meth:`Session.resolve_profile` is that resolution, exposed because
    #: the pre-flight wants the same answer before anything is written.
    profile: str | None = None

    def requested(self) -> bool:
        """Whether anything at all was declared.

        The caller's reason to skip :meth:`Session.apply_attributes` entirely:
        an estate that declares no attributes pays no round trip for the ones it
        did not ask for.
        """
        return self.unlock or self.profile is not None


@dataclass(frozen=True)
class AttributeChange:
    """What enforcing **one** attribute did.

    A :class:`ChangeResult` with the attribute's name on it, rather than the one
    result P1's sketch returned for the whole call. UC-1 §5 asks for each
    attribute to be *reported as a separate change so the diff stays readable*,
    and a single result for several attributes could not say which of them moved.

    ``changed`` is the same question it is everywhere else -- *did this run do
    it* -- so an account that was already unlocked comes back ``False`` with a
    detail saying so, and invariant 9 is satisfied by the driver rather than by a
    caller remembering to ask first.
    """

    #: One of :data:`ATTRIBUTE_KINDS`, which is the document's ``action_kind``
    #: word. Where a kind serves more than one attribute -- :data:`ATTRIBUTE_SET`
    #: does -- the detail is what says which.
    attribute: str
    changed: bool
    detail: str | None = None


@dataclass(frozen=True)
class AccountChange:
    """What one **account verb** did to one account (UC-2).

    Distinct from :class:`AttributeChange`, which reports enforcing an attribute
    a *policy* declared on `creds apply`'s way past. An account verb is something
    an operator typed, so the two are different events even where the DDL is
    similar, and one type carrying both would have an ``attribute`` field naming
    something no policy can declare.

    ``status`` is ``ACCOUNT_STATUS`` **as it was read**, before anything was
    issued. It is on the result rather than left to the caller for the reason
    UC-2 §5 gives: every one of these verbs reports the state it found, and a
    caller that had to read it again could report a state a different run had
    since changed.
    """

    #: One of :data:`ACCOUNT_ACTIONS`.
    action: str
    changed: bool
    status: str
    detail: str | None = None


class PartialAccountChangeError(DriverError):
    """A multi-statement account verb failed **after** changing something.

    Raised where an earlier statement committed and a later one did not. DDL
    commits as it goes, so there is no rolling the first back. Without this the
    caller could only see an exception, and would report the account untouched
    when it was not.

    ``completed`` is the :class:`AccountChange` rows for the statements that
    ran, in order. ``cause`` is the failure itself, whose category, exit code,
    vendor code and hint this error carries unchanged, so a caller that reports
    it as an ordinary failure still reports the server's own words.
    """

    def __init__(self, cause: DriverError, *, completed: tuple[AccountChange, ...]) -> None:
        super().__init__(cause.message, hint=cause.hint, code=cause.code)
        self.category = cause.category
        self.exit_code = cause.exit_code
        self.cause = cause
        self.completed = completed


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
        wrapped in a PL/SQL block, and the password is never bound. The
        driver's statement builder applies them; this is the call that issues
        what it built.
        """
        ...

    def suspend_account(self, account: str) -> AccountChange:
        """Lock ``account`` deliberately -- the offboarding state (UC-2).

        **Idempotent, and the driver is what makes it so** (invariant 9), as
        :meth:`apply_attributes` is: the implementation reads the state first and
        issues nothing where the account is already locked. Oracle accepts
        ``ACCOUNT LOCK`` against a locked account silently, so an implementation
        that issued unconditionally would report a change every time.

        **A `LOCKED(TIMED)` account is not already suspended**, and an
        implementation must not treat it as one. The timed lock is what a
        failed-login limit produced and `PASSWORD_LOCK_TIME` clears on its own;
        this is somebody's decision, and it does not expire. Reporting
        ``changed: False`` there would say an offboarding had already happened
        when what is true is that a person mistyped their password.

        Returns an :class:`AccountChange` whether or not anything was issued,
        carrying the status it read and a detail naming it.

        **Refused on a read-only target before anything is issued**, like every
        other mutating call here: a physical standby would otherwise take the
        statement as far as the cursor and fail there.
        """
        ...

    def reset_password(
        self, account: str, secret: Secret, *, expire: bool, keep_rollover: bool = False
    ) -> tuple[AccountChange, ...]:
        """Hand ``account`` a new password -- UC-2 §4.1's whole operation.

        Distinct from :meth:`set_password`, which is UC-1's one statement against
        an application account. A personal reset is **up to three** statements
        issued as one operation, each conditional on the state the driver reads
        first, and they belong together rather than in a caller that would have
        to re-derive the conditions and get the order right:

        1. ``ACCOUNT UNLOCK``, only where the account is locked by a failed-login
           limit;
        2. the password itself, with ``PASSWORD EXPIRE`` where ``expire``;
        3. ``EXPIRE PASSWORD ROLLOVER PERIOD``, unless ``keep_rollover``.

        Returns one :class:`AccountChange` per statement the operation
        *considered*, in that order, whether or not it was issued --
        :meth:`apply_attributes`' rule, and for its reason: an account that was
        not locked is a row saying so, not an absent row a caller has to read as
        an answer.

        **A deliberately locked account is refused, and a timed lock is not**
        (H4). The first is an offboarding somebody performed, and handing
        that person a working password would undo it silently; the second is what
        a mistyped password produces, and clearing it is the reset's job.
        :meth:`suspend_account` is the verb that sets the first, so the two calls
        agree on what the state means.

        **``expire`` is the seen path and never a default.** UC-2 §1: the seen
        path always expires, because expiry is what ends the DBA's exposure, and
        the unseen path never does, because nobody but the owner is meant to know
        the value. There is no third reading, so the argument is required rather
        than defaulted -- a caller that has not decided which path it is on has
        not decided what it is doing.

        **The window is closed by default** (§4.3), which is the one place UC-2
        defaults the opposite way to UC-1: there the old password's holders are
        applications nobody can enumerate, and here the only holder is the person
        being reset, whose not having it is the premise. ``keep_rollover`` is for
        the reset where they *do* still know it.

        **Callers must ask :meth:`require_no_rollover_window` first** where
        ``expire`` is true. The refusal belongs at plan time, before a password
        has been drawn or delivered, and this call raises it too rather than
        trusting that they did.

        **A failure after a statement committed raises
        :class:`PartialAccountChangeError`**, carrying the rows that ran.
        Two cases, and the caller treats them differently: an unlock followed by
        a failed set leaves the password unchanged and the account open, and a
        set followed by a failed close leaves the new password live and the old
        one working until the window ends. A failure with nothing committed
        before it is raised as it came.
        """
        ...

    def expire_password(self, account: str) -> tuple[AccountChange, ...]:
        """Force ``account`` to change its password at next logon (UC-2 §2).

        Two statements, each conditional on the one state the driver reads first,
        and returned as one :class:`AccountChange` per statement *considered*, in
        this order -- :meth:`reset_password`'s rule:

        1. **end an open rollover window** (:data:`ROLLOVER_FINISH`), only where
           one is open;
        2. **expire the password** (:data:`PASSWORD_EXPIRE`), only where it is
           not already expired.

        **The window is closed because expiring does not close it** (decision #525).
        Measured on 26ai Free 23.26.2.0.0: expiring an account with an open window
        leaves ``EXPIRED & IN ROLLOVER``, and the *old* password still answers
        ``ORA-28001`` -- it authenticates, and it is itself a way to set the next one.
        Closing first kills it (``ORA-01017``). It is the reset's default (H4) for the
        reason given there: the only holder of the old password is the person whose
        account this is.

        **Close first, then expire, and the order is about failure.** Both orders
        reach plain ``EXPIRED`` (measured). If the second statement fails, close
        then expire leaves ``OPEN`` with the old password already dead, while
        expire then close would leave the old password alive by accident.

        **Only an open window is closed, not a profile that grants one.** The
        bare expiry sets no password and so opens no window -- measured: on a
        rollover profile with none open it leaves plain ``EXPIRED``. That is where
        this differs from the reset, whose own ``IDENTIFIED BY`` opens one.

        **Idempotent** (invariant 9). The converged state is expired with no
        window open. Oracle accepts a second ``PASSWORD EXPIRE`` silently
        (measured), so the driver issues nothing where the account is already
        there. ``EXPIRED(GRACE)`` is **not** already expired: the password still
        logs in, and expiring it is a real change (measured).

        **A lock is left alone, either kind.** Expiry and a lock are independent
        components of the status (measured: ``LOCKED`` becomes
        ``EXPIRED & LOCKED``), and this verb unlocks nothing -- the reset is
        what does that.

        **Refused on a read-only target before anything is issued**, like every
        other mutating call here.

        **A failure after the window closed raises
        :class:`PartialAccountChangeError`**, carrying the close. By then the old
        password is already dead and cannot be revived, and a caller that saw only
        an exception would report the account as untouched.
        """
        ...

    def require_no_rollover_window(self, account: str) -> None:
        """Refuse an **expiring** reset of ``account`` where its profile grants a
        password rollover window (UC-2 §4.3), or say nothing.

        :meth:`require_rollover`'s mirror, and the names are opposites because the
        conditions are: that one refuses where no window can be opened, this one
        refuses where one would be. Both are plan-time refusals that raise rather
        than return, so neither can be called and ignored.

        The reason is measured rather than assumed (Q7, on 26ai 23.26.2.0.0 and
        21c 21.3.0.0.0, identically): ``IDENTIFIED BY … PASSWORD EXPIRE`` is
        *accepted* on a rollover profile, the resulting status is ``EXPIRED & IN ROLLOVER``, and
        the old password still authenticates -- it answers ``ORA-28001`` rather
        than ``ORA-01017``, so it is not merely alive but is itself a way to set
        the new one. The expiry that is supposed to end the DBA's exposure would
        leave a second live password behind it for the length of the window.

        **Refused rather than worked around.** From an ``EXPIRED`` start the same
        statement leaves no second password. Whether the refusal narrows to
        accounts whose old password still authenticates is an open decision, and
        not something to loosen here. TODO(#541). 19c is unmeasured. The unseen
        path remains available for the same account, and the message says so.
        """
        ...

    def apply_attributes(
        self, account: str, attributes: AccountAttributes
    ) -> tuple[AttributeChange, ...]:
        """Enforce the non-password attributes ``attributes`` declares (UC-1 §5).

        **One entry per attribute that was declared**, in
        :class:`AccountAttributes` field order, whether or not it turned out to need
        doing -- an account that is already unlocked is ``changed: False`` and a row
        saying so, not an absent row. §5 wants each attribute reported as its own
        change, and a consumer that had to infer "not declared" from "not present"
        would be reading the policy out of the results.

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

    def resolve_profile(self, profile: str) -> str | None:
        """The profile as this database spells it, or ``None`` if it has none.

        ``None`` is the same kind of answer :meth:`describe_user` gives for a
        missing account: a fact about this target, not a failure. Which profiles
        exist varies from database to database, and an estate that names one that
        exists on nineteen PDBs and not the twentieth is the ordinary case rather
        than a broken config -- so the caller decides what it means. UC-1 §8's
        pre-flight makes it a finding and refuses before anything is written;
        :meth:`apply_attributes` makes it an error for that one account.

        The **spelling** is the return value rather than a boolean for
        ``02-oracle-privileges.md`` §4's reason about account names: a quoted
        identifier is case-sensitive, so the only spelling that may reach a
        statement is the one the dictionary gave back. A caller that only wanted
        to know whether it exists gets that from ``is not None``.
        """
        ...

    def resolve_role(self, role: str) -> str | None:
        """The role as this database spells it, or ``None`` if it has none.

        :meth:`resolve_profile`'s argument for the other predicate kind, and it
        exists because UC-2 §2 draws a distinction that an account list cannot:
        a `role:` predicate naming a role that **does not exist** is a
        misspelling and is refused, while one that exists and matches **no
        accounts** is a true answer about today's estate. Both are an empty
        result from :meth:`accounts_matching`, so something has to ask separately.
        """
        ...

    def accounts_matching(
        self, *, profile: str | None = None, role: str | None = None
    ) -> tuple[str, ...]:
        """Every account a predicate admits, as the dictionary spells them.

        The resolution half of H1's predicate. :func:`sopuli.personal.admits`
        answers "does this rule admit that account" for a verb acting on one
        name; this answers "which accounts does this rule admit", for the verb
        that lists them.

        **An implementation must resolve a role transitively**, including
        accounts that hold it through another role. `admits` decides membership
        against the traversed set, so an enumeration reading only direct grants
        would show an operator *fewer* accounts than a reset would accept — and a
        listing that under-reports what a predicate admits is worse than none,
        because it will be read as the whole set.

        **Empty is an answer, not an error** (UC-2 §2). Whether the profile or
        role exists is :meth:`resolve_profile`/:meth:`resolve_role`'s question,
        asked first by the caller that needs to tell a misspelling from an empty
        estate.

        Exactly one of ``profile`` and ``role`` is given; neither and both are
        programming errors.

        **This returns names, and it does not widen anything.** Invariant 5's
        second sentence is untouched: a mutating verb still requires the account
        named on the command line and refuses any name the predicate does not
        admit. What this feeds is a listing.
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
        unconditionally (Q1). ``hash`` compares a stored verifier and makes
        no attempt, so ``lockout_margin`` and ``attempts`` do not apply to it, and
        a driver refuses it -- naming the target -- where it has nothing to
        compare rather than comparing something weaker. A driver
        that cannot honour a method raises
        :class:`UnsupportedCapabilityError` rather than quietly doing a
        different one -- the distinction between "verified by hash" and
        "verified by logging in" is the difference between no lockout risk and
        some.

        **One attempt, and no retry** (UC-1 §7 mitigation 1). This signature
        takes one secret and returns one result for that reason: there is no
        shape here for a back-off loop to hide in.
        """
        ...

    def require_verifier(self, account: str, secret: Secret) -> None:
        """Refuse ``check --method hash`` or ``both`` for ``account``, or say nothing.

        Asked at plan time, before any account is checked, so an explicit method
        a target cannot honour fails as :class:`UnsupportedCapabilityError`,
        exit 5, naming the target (invariant 4) rather than as a row partway
        through a run. ``secret`` is the value about to be compared, because one
        refusal is about it rather than about the account: a database character
        set that cannot hold it means the server hashed a converted copy.

        A missing account says nothing; the run reports it per account.
        """
        ...

    def require_rollover(self, account: str) -> None:
        """Refuse ``--strategy rollover`` for ``account`` here, or say nothing.

        Two conditions, failing differently, which is why this is one call rather
        than a capability check somebody has to remember to pair with a profile
        read:

        * **the release has no such feature** --
          :class:`UnsupportedCapabilityError`, exit 5, naming the capability and
          the target (invariant 4);
        * **the account's profile grants no window** -- a
          :class:`DriverError` whose hint carries the exact ``ALTER PROFILE`` an
          operator would run. The tool never issues it: profiles are shared, so
          changing one affects accounts nobody selected, and Q4 decided that
          the tool never alters one.

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
    :class:`Session`, so this is a factory, and what the registry returns after
    it imports a vendor client on first use.
    """

    def connect(self, target: ExpandedTarget, credential: Credential) -> Session:
        """Connect to ``target``.

        Raises :class:`AuthenticationError` when the credential is refused, and
        :class:`DriverError` for anything else that stopped the connection.
        """
        ...


def require_capability(
    scope: Scope, capability: str, *, target: str, hint: str | None = None
) -> None:
    """Refuse unless ``scope`` reported ``capability`` (invariant 4).

    Called at **plan time**, before anything is written anywhere. The whole
    value of the capability model is that `--strategy rollover` against 18c
    fails while the plan is being printed rather than after two of five targets
    already have a new password. On 18c XE that run exits 5, with
    `error.category` ``capability``, `error.target_capability`
    ``password_rollover``, and the plan emitted with nothing done.

    ``hint`` is the caller's, because this function cannot write one. What to do
    instead of an absent capability depends entirely on which capability it was,
    and a generic "this target cannot do that" adds nothing an operator can act
    on -- which is what the style rule about hints is for. A caller with nothing
    useful to say passes nothing.
    """
    if not scope.supports(capability):
        raise UnsupportedCapabilityError(capability, target=target, hint=hint)

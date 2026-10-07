"""Opening a connection, and putting the run's id on it.

The first code in this project that opens a socket to a database, and the module
:data:`sopuli.driver.registry.DRIVERS` imports for ``type: oracle``. It imports
``oracledb`` at module scope on purpose: that is what makes
:func:`sopuli.driver.registry.resolve` able to answer "the driver is not
installed" as a structured error instead of a traceback (ADR-006 rule 1). The
package above it stays clean, so :mod:`.statements` and :mod:`.client` remain
importable -- and testable -- with no client on the machine.

Two decisions, made here and stated rather than implied.

**Thick-mode initialisation happens lazily, on the first connect.**
``init_oracle_client`` is process-global and effectively one-shot, so the choice
is between doing it at startup, where the failure is earliest and the message
best, and doing it when something actually connects. Lazy wins, because ADR-006
rule 3 says a base install opens no sockets and loads no vendor client: an
offline ``config validate`` that initialised Instant Client would be doing work
for a database it will never contact, and would *fail* on a machine where that
command is perfectly valid. The cost is that the error arrives a little later,
and it is a good error -- see :func:`sopuli.driver.oracle.client.missing_client`.

**One connection per target, never a shared session with ``SET CONTAINER``.**
A CDB root and its PDBs are separate services and are connected to separately.
The alternative needs the ``SET CONTAINER`` privilege, which
``02-oracle-privileges.md`` §2 leaves out of the grant set. Without it the grant
set stays minimal, and a run that cannot reach a PDB fails for that PDB rather
than poisoning a session shared with others.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field, replace
from typing import Any

import oracledb

from sopuli.config.model import ExpandedTarget
from sopuli.constraints import AccountConstraints
from sopuli.driver.oracle.accounts import (
    accounts_with_profile,
    accounts_with_role,
    deliberately_locked,
    describe,
    failed_logins,
    login_state,
    password_constraints,
    resolve_name,
    resolve_profile,
    resolve_role,
    stored_verifiers,
)
from sopuli.driver.oracle.capabilities import (
    assert_scope,
    cloud_service_of,
    observe,
    require_read_write,
)
from sopuli.driver.oracle.client import (
    CLIENT_LIB_DIR_ENV,
    NO_CLIENT,
    Timeouts,
    connect_arguments,
    missing_client,
)
from sopuli.driver.oracle.errors import INSTALL_SCRIPT, from_error
from sopuli.driver.oracle.limits import resolve as resolve_limit
from sopuli.driver.oracle.privileges import audit
from sopuli.driver.oracle.rollover import alter_profile_ddl, is_enabled
from sopuli.driver.oracle.statements import (
    Identifier,
    Statement,
    alter_user_password,
    alter_user_profile,
    expire_password,
    finish_rollover,
    lock_account,
    unlock_account,
)
from sopuli.driver.oracle.verification import (
    DEFAULT_MARGIN,
    is_verification_outcome,
    margin_reason,
    result_for,
    skipped_detail,
    warning_detail,
)
from sopuli.driver.oracle.verifier import (
    CURRENT,
    NO_MATCH,
    NO_VERIFIER,
    PREVIOUS,
    Malformed12cVerifierError,
    NotComparableError,
    compare,
)
from sopuli.driver.protocol import (
    ACCOUNT_LOCK,
    ACCOUNT_LOCK_STATE,
    ACCOUNT_UNLOCK,
    ATTRIBUTE_SET,
    EXPIRE_PASSWORD,
    FAIL,
    OFFLINE_VERIFY,
    PASS,
    PASSWORD_EXPIRE,
    PASSWORD_ROLLOVER,
    PASSWORD_SET,
    PROFILE_MANAGEMENT,
    ROLE_LOOKUP,
    ROLLOVER_FINISH,
    SKIPPED,
    UNAVAILABLE,
    VERIFY_BOTH,
    VERIFY_HASH,
    VERIFY_LOGIN,
    AccountAttributes,
    AccountChange,
    AttributeChange,
    ChangeResult,
    Credential,
    DriverError,
    PartialAccountChangeError,
    PrivilegeAudit,
    Scope,
    UnsupportedCapabilityError,
    UserState,
    VerifyResult,
    require_capability,
)
from sopuli.passwords import ByteLimit
from sopuli.secrets import Secret

#: Guards :func:`initialise`. ``init_oracle_client`` mutates process-global
#: state, and nothing in this codebase promises a connection is only ever opened
#: from one thread -- ``tests/lock/test_manager.py`` already runs a manager from
#: two. Cheap insurance against a failure that would be unreproducible.
_INITIALISING = threading.Lock()

#: What ``error.target_capability`` carries when a comparison cannot run, beside
#: ``offline_verify`` for an unreadable ``SYS.USER$``. Names rather than sentences,
#: because the field is what a consumer branches on (03-json-output §4); the
#: account they concern is in the hint. All three are per account rather than
#: per target, which is why none of them is in the capability probe.
VERIFIER_12C = "verifier_12c"
VERIFIER_FORMAT = "verifier_12c_format"
VERIFIER_CHARSET = "verifier_charset"

#: What a ``hash`` comparison reports, by which verifier the password reproduced.
#: Every one says no login was attempted, because that is the difference between
#: this result and a ``login`` one with the same word in ``result``.
_HASH_DETAIL = {
    CURRENT: "matches the account's current 12C verifier, with no login attempted",
    PREVIOUS: (
        "matches the previous password's 12C verifier, with no login attempted: a "
        "rollover window is open, and that password works until it closes"
    ),
    NO_MATCH: "matches none of the account's 12C verifiers, with no login attempted",
}

#: Whether thick mode is up. python-oracledb tolerates a second
#: ``init_oracle_client`` with identical arguments and raises on a differing
#: one, so this is not merely an optimisation: it is what stops a second call
#: with a different ``lib_dir`` from turning a working process into a broken one.
_initialised = False


def initialise(
    *,
    env: Mapping[str, str],
    lib_dir: str | None = None,
    platform: str | None = None,
) -> None:
    """Start thick mode, once per process.

    Where the client is, in P3's order: §6's
    :data:`~sopuli.driver.oracle.client.CLIENT_LIB_DIR_ENV` first, then
    ``runtime.oracle.client_lib_dir`` from the file, then nothing -- which leaves
    it to the platform's own loader, and P4's table is the specification for
    where that looks. An unset variable and an unwritten key are not an error
    between them: the ordinary Linux install puts the client on
    ``LD_LIBRARY_PATH`` and needs neither.

    **The config key is a parameter rather than something read here**, for the
    reason the whole driver layer is arranged that way: this module must not
    reach for a :class:`~sopuli.config.model.Config`. A documented key that
    silently did nothing is worse than one that does not exist, so
    :class:`OracleDriver` carries it: that is where a run-scoped fact belongs.
    """
    global _initialised
    with _INITIALISING:
        if _initialised:
            return
        try:
            oracledb.init_oracle_client(lib_dir=env.get(CLIENT_LIB_DIR_ENV) or lib_dir or None)
        except oracledb.Error as error:
            if NO_CLIENT in str(error):
                raise missing_client(str(error), platform=platform) from error
            # Anything else the client raised on the way up. Mapped rather than
            # re-raised, because `connect` promises that every failure arrives
            # classified -- an unmapped vendor exception escaping from *here*
            # would be the one place the promise did not hold, and the
            # classifier's fallback preserves the vendor code and message for a
            # code it has no specific rule for.
            raise from_error(error).as_error() from error
        _initialised = True


@dataclass
class OracleSession:
    """One open connection, and everything done through it.

    **A** :class:`sopuli.driver.protocol.Session`. The protocol is structural, so
    this class satisfies it by having the methods, not by declaring anything.
    ``tests/driver/test_oracle_verify.py`` asserts the ``isinstance``, so the
    claim is checked rather than asserted in prose.
    """

    connection: Any
    target: ExpandedTarget
    correlation_id: str
    #: Carried so a verification can open its own connection with the run's own
    #: budgets rather than the client's defaults. `verify_password` is the only
    #: caller, and it is the one call that must not wait forever.
    timeouts: Timeouts = field(default_factory=Timeouts)
    #: Invariant 3's cache. Private, and not a constructor argument: a scope
    #: handed in from outside would be a scope that came from somewhere other
    #: than this connection, which is the single thing the invariant forbids.
    _scope: Scope | None = field(default=None, init=False, repr=False)
    #: Cached beside the scope and for the same reason: it is one more thing this
    #: connection is, and asking twice is two chances to disagree.
    _limit: ByteLimit | None = field(default=None, init=False, repr=False)

    def scope(self) -> Scope:
        """What this connection is, and what it can do.

        Probed on first call and **cached for the life of the session**
        (invariant 3). Twenty-one PDBs answer differently, so the cache is per
        session and never per driver, and the answer is never derived from a
        version in a file.

        **On first call, not during** :meth:`OracleDriver.connect`. P1's "on
        connect" means *from the connection rather than from a config file*, not
        *eagerly*. Three reasons, in ascending order of how much they would cost
        to get wrong:

        * ``connect`` promises what connecting is. Probing inside it would make
          an ``ORA-`` from a dictionary read arrive as a connection failure,
          which sends the reader to the listener and the credential for a
          problem that is neither.
        * The probe is several round trips, and not every session wants them.
        * **It would break verification.** Verification logs in on a fresh
          connection as the account *being verified*, and that session
          holds none of §2's grants, so a probe on every connection would fail
          there.

        What P1 does require is that a read-only standby is refused **up front**
        rather than mid-statement. That is a property of when the *plan* asks —
        which it does, before anything mutates — and not of when the session
        volunteers.

        The probe raises rather than degrades. A capability that is absent is an
        ordinary result and comes back as a smaller set; a probe that could not
        be *answered* is :class:`~sopuli.driver.oracle.capabilities.ProbeError`,
        because a run where those two share a word reports a failed probe as an absent
        capability (decision #195).
        """
        if self._scope is None:
            with self.connection.cursor() as cursor:
                self._scope = observe(cursor)
        return self._scope

    def privileges(self) -> PrivilegeAudit:
        """What this session holds that §3 says it should not.

        **Not folded into** :meth:`scope`, unlike the capability probe, and the
        difference is who asks. Every command calls ``scope()``; only
        ``doctor --check-privileges`` wants this, and it is not cheap: three
        reads plus one probe per grant §2 documents. Paying that on every
        connection to answer a question nobody asked is the cost the flag exists
        to avoid. Uncached for the same reason: it is asked once per run.

        Reporting is not enforcing, and this never refuses. P5 is decided
        — over-granting **warns**.
        """
        with self.connection.cursor() as cursor:
            # The scope decides whether `V_$PDBS` is expected: §2 grants it in
            # the root only, and calling a PDB half-installed for lacking a grant
            # it was never given would be wrong in the direction that costs the
            # most trust. Cached, so this is not another round trip.
            return audit(cursor, scope_type=self.scope().type)

    def describe_user(self, account: str) -> UserState | None:
        """The account's state, or ``None`` if there is no such account.

        ``None`` is UC-1's ``ACCOUNT_MISSING`` and not an error -- the tool does
        not create accounts (Q8). The reads are all on the baseline grant set,
        so `check` needs no site-specific privilege to run (decisions P2 and Q1).

        One read goes further where the optional grant was made: on a release
        with no ``DBA_USERS.PASSWORD_CHANGE_DATE``, the date comes from
        ``SYS.USER$.PTIME`` (decision #386). Asked of the capability probe, which is
        cached, so a session without the grant never issues the read at all.
        """
        with self.connection.cursor() as cursor:
            return describe(cursor, account, user_dollar=self.scope().supports(OFFLINE_VERIFY))

    def password_constraints(self, account: str) -> AccountConstraints | None:
        """What this target says about a password for one account.

        The reporting half of UC-1 §4 step 2 -- a verify function, the reuse
        resources and the verifiers the account holds. **Nothing gates on any of
        it**: none of the three can be evaluated before the statement is issued,
        which is why they are read to be said rather than to be acted on.

        Not cached, unlike :meth:`byte_limit`. That one is a property of the
        database and this is a property of an account's profile, which a run
        reads once per account and which a concurrent ``ALTER PROFILE`` can move
        under it -- a cache keyed by account would save nothing and would be a
        second place for the answer to age.
        """
        with self.connection.cursor() as cursor:
            return password_constraints(cursor, account)

    def byte_limit(self) -> ByteLimit:
        """How long a password may be here, in this database's character set.

        Cached per session. The statement builder takes the limit as a required
        argument so that nobody can build a statement without having found it
        out, and this is the finding out.
        """
        if self._limit is None:
            with self.connection.cursor() as cursor:
                self._limit = resolve_limit(cursor, self.scope().db_version)
        return self._limit

    def set_password(self, account: str, secret: Secret) -> ChangeResult:
        """Issue the ``ALTER USER``, and let a rejection be a rejection.

        **The driver does not regenerate.** UC-1 §4's bounded loop does not live
        here: a driver that drew another password on
        `ORA-28003` would be putting a value into the database that the vault has
        never seen, which is the ordering UC-1 §3 exists to prevent. So a
        rejection is reported -- classified by the error mapper as ``password_rejected`` or
        ``password_reused``, category ``policy`` -- and the command that owns
        both the generator and the vault write owns the loop.

        **``changed`` is always ``True`` when the statement succeeded**, and
        that is not a shortcut. Invariant 9 wants ``changed: false`` on a second
        run, and "the password is already this value" is not a question a
        database can answer about a password -- there is nothing to compare. So
        idempotency for this verb is defined by the *vault's* state: the command
        does not call this when the vault says the target is already at
        ``current``. A driver reporting ``changed: false`` here could only do it
        by guessing.

        The name in the statement is the spelling the dictionary gave back, not
        the caller's, because an Oracle quoted identifier is case-sensitive.

        **A read-only target is refused here, before anything is built.** The
        mutating callers call
        :func:`~sopuli.driver.oracle.capabilities.require_read_write`, rather than
        ``assert_scope`` doing it, so that `creds check` keeps working against a
        physical standby. This is a mutating caller. P1 asks for the refusal *up
        front*, so that it does not arrive as a failed ``ALTER USER`` half way
        through a run.
        """
        require_read_write(self.scope(), target=self.target.name)

        with self.connection.cursor() as cursor:
            spelling = resolve_name(cursor, account)
            if spelling is None:
                raise DriverError(
                    f'account "{account}" does not exist on this target',
                    hint=(
                        "the tool does not create accounts (Q8); `creds check` reports this "
                        "as ACCOUNT_MISSING rather than failing"
                    ),
                )

            statement = alter_user_password(
                Identifier(spelling),
                secret,
                scope=self.scope(),
                limit=self.byte_limit(),
            )

            try:
                # `reveal()` here is one of invariant 2's three permitted
                # reveals. Nothing between this line and the wire may log it,
                # and `Statement.__str__` is the redacted form precisely so an
                # accidental interpolation elsewhere cannot leak it.
                cursor.execute(statement.reveal())
            except Exception as error:  # noqa: BLE001 -- classified, never swallowed
                raise from_error(error).as_error() from error

        return ChangeResult(changed=True, detail="password set")

    def apply_attributes(
        self, account: str, attributes: AccountAttributes
    ) -> tuple[AttributeChange, ...]:
        """Enforce UC-1 §5's opt-in account attributes.

        One entry per attribute the caller declared, whether or not it needed
        doing. Nothing is inferred: an ``AccountAttributes`` with nothing set
        returns an empty tuple and reads nothing, so an estate that declares no
        attributes pays no round trip for them.

        **Read-write is refused here as it is in** :meth:`set_password`, and for
        the same reason: this is a mutating caller, and the mutating callers
        make the check so that `creds check` keeps working against a physical
        standby.
        """
        if not attributes.requested():
            return ()

        require_read_write(self.scope(), target=self.target.name)

        changes: list[AttributeChange] = []
        if attributes.unlock:
            changes.append(self._unlock(account))
        if attributes.profile is not None:
            changes.append(self._assign_profile(account, attributes.profile))
        return tuple(changes)

    def resolve_profile(self, profile: str) -> str | None:
        """How this database spells ``profile``, or ``None`` if it has no such one.

        The capability is checked because reading ``DBA_PROFILES`` is what
        :data:`~sopuli.driver.protocol.PROFILE_MANAGEMENT` means -- *read*, and
        only read: altering a profile is Q4 and this driver builds no
        statement that would.
        """
        require_capability(self.scope(), PROFILE_MANAGEMENT, target=self.target.name)

        with self.connection.cursor() as cursor:
            return resolve_profile(cursor, profile)

    def resolve_role(self, role: str) -> str | None:
        """How this database spells ``role``, or ``None`` if it has no such one.

        **Gated on** :data:`~sopuli.driver.protocol.ROLE_LOOKUP`, its own
        capability rather than ``profile_management``: nothing here is a profile
        operation, and a target whose only shortcoming is about profiles must
        not refuse a role predicate.

        ``DBA_ROLES`` is in ``02-oracle-privileges.md`` §2's grant set (decision
        #531). Without the grant the read is ``ORA-00942``, which would read as
        "no such role" and refuse every ``role:`` predicate in `account list` as
        a misspelling. A service account that lacks it is refused here, at plan
        time, naming the grant.
        """
        require_capability(
            self.scope(),
            ROLE_LOOKUP,
            target=self.target.name,
            hint=(
                "the service account cannot read DBA_ROLES, so a role that matches nobody "
                "cannot be told from one that does not exist: GRANT SELECT ON SYS.DBA_ROLES "
                f"to it (02-oracle-privileges.md section 2, or {INSTALL_SCRIPT})"
            ),
        )
        with self.connection.cursor() as cursor:
            return resolve_role(cursor, role)

    def accounts_matching(
        self, *, profile: str | None = None, role: str | None = None
    ) -> tuple[str, ...]:
        """Every account a predicate admits, as the dictionary spells them.

        One method for the two predicate kinds rather than two, because the
        caller has one rule with one of them set and would otherwise branch to
        choose a method and branch again on the result. Exactly one is given;
        neither and both are programming errors and say so.
        """
        if (profile is None) == (role is None):
            raise ValueError("accounts_matching takes exactly one of `profile` and `role`")

        with self.connection.cursor() as cursor:
            if profile is not None:
                require_capability(self.scope(), PROFILE_MANAGEMENT, target=self.target.name)
                return accounts_with_profile(cursor, profile)
            assert role is not None
            return accounts_with_role(cursor, role)

    def _assign_profile(self, account: str, profile: str) -> AttributeChange:
        """``ALTER USER … PROFILE …``, or report that the account is already on it.

        **Never ``ALTER PROFILE``** (Q4). What moves is one account the config
        whitelists; the profile itself is left exactly as its owner wrote it. The
        :mod:`sopuli.driver.oracle.rollover` check reports the ``ALTER PROFILE`` an
        operator would run and never issues it, and this method never has cause to.

        **The state is read first**, which is invariant 9 here as everywhere in
        this method's neighbours: an account already on the profile is a
        ``changed: False`` row, so the second run of an estate that declares the
        attribute issues nothing.

        A profile the database does not have is a :class:`DriverError` naming it
        and the target, rather than the ``ORA-02380`` the server would give.
        Which profiles exist varies per database, so this is the ordinary shape
        of a misconfigured estate rather than an exotic one -- and UC-1 §8's
        pre-flight asks the same question through :meth:`resolve_profile` before
        anything at all is written.
        """
        state = self.describe_user(account)
        if state is None:
            raise DriverError(
                f'account "{account}" does not exist on this target',
                hint=(
                    "the tool does not create accounts (Q8); `creds check` reports this "
                    "as ACCOUNT_MISSING rather than failing"
                ),
            )

        spelling = self.resolve_profile(profile)
        if spelling is None:
            raise DriverError(
                f'profile "{profile}" does not exist on this target',
                hint=(
                    "create it on this database, or name one that exists -- sopuli does not "
                    "create or alter a profile, because a profile is shared and changing one "
                    "affects accounts nobody selected (Q4)"
                ),
            )

        if state.profile is not None and state.profile.upper() == spelling.upper():
            return AttributeChange(
                ATTRIBUTE_SET, changed=False, detail=f"profile is already {spelling}"
            )

        was = state.profile or "unknown"
        statement = alter_user_profile(
            Identifier(state.name), Identifier(spelling), scope=self.scope()
        )
        with self.connection.cursor() as cursor:
            try:
                cursor.execute(statement.reveal())
            except Exception as error:  # noqa: BLE001 -- classified, never swallowed
                raise from_error(error).as_error() from error

        return AttributeChange(ATTRIBUTE_SET, changed=True, detail=f"profile {was} -> {spelling}")

    def suspend_account(self, account: str) -> AccountChange:
        """``ALTER USER … ACCOUNT LOCK``, or report that it was already locked.

        **The state is read first** (invariant 9), for :meth:`_unlock`'s reason
        in the other direction: measured on 26ai Free 23.26.2.0.0, a second
        ``ACCOUNT LOCK`` against an already-``LOCKED`` account is accepted
        silently and leaves it ``LOCKED``, so a driver that issued
        unconditionally would report a change every run.

        **`LOCKED(TIMED)` is not already suspended, and the transition is real.**
        Measured on the same release, twice: an account locked by a failed-login
        limit reads ``LOCKED(TIMED)``, and ``ACCOUNT LOCK`` takes it to
        ``LOCKED``. That is a change worth reporting rather than a no-op on a
        technicality -- the timed lock expires on its own under
        ``PASSWORD_LOCK_TIME`` and this one does not, and a personal reset
        refuses a deliberate ``LOCKED`` (H4) while it clears a timed one.
        So the two states differ in exactly what this verb is for.

        The capability is checked for the reason :meth:`_unlock` gives: it is
        structural on Oracle, and what makes it structural is a fact recorded in
        one place rather than something a caller should have to know.

        **The read-only check comes first**, as it does in :meth:`set_password`
        and :meth:`apply_attributes`: a physical standby answers
        :meth:`describe_user` perfectly well, so without it the refusal would
        arrive from the cursor after the run had already decided to mutate.
        """
        require_read_write(self.scope(), target=self.target.name)
        require_capability(self.scope(), ACCOUNT_LOCK_STATE, target=self.target.name)
        state = self.describe_user(account)
        if state is None:
            raise DriverError(
                f'account "{account}" does not exist on this target',
                hint=(
                    "the tool does not create accounts (Q8); nothing is suspended, and "
                    "the account name is worth checking against the estate"
                ),
            )
        if deliberately_locked(state.status):
            return AccountChange(
                ACCOUNT_LOCK,
                changed=False,
                status=state.status,
                detail="the account is already locked",
            )

        was = state.status.lower()
        statement = lock_account(Identifier(state.name), scope=self.scope())
        with self.connection.cursor() as cursor:
            try:
                cursor.execute(statement.reveal())
            except Exception as error:  # noqa: BLE001 -- classified, never swallowed
                raise from_error(error).as_error() from error

        return AccountChange(
            ACCOUNT_LOCK, changed=True, status=state.status, detail=f"account was {was}; locked"
        )

    def reset_password(
        self, account: str, secret: Secret, *, expire: bool, keep_rollover: bool = False
    ) -> tuple[AccountChange, ...]:
        """UC-2 §4.1's reset: up to three statements, one session, one read.

        **One `describe_user` for all three decisions**, rather than a read per
        statement. The alternative is not merely slower: three reads is three
        chances to see three different states, and an operation that unlocked an
        account on the strength of a status it no longer had would be reporting
        somebody else's run.

        **Refusals come before anything is issued**, in the order that costs
        least to be wrong about: read-only, then capability, then the account's
        existence, then §4.3's rollover refusal, then a deliberate lock. Each is
        invariant 4's plan-time rule inside one call -- by the time the first
        statement goes out, nothing left can refuse.

        The per-statement conditions and their measurements are
        :meth:`~sopuli.driver.protocol.Session.reset_password`'s; this issues
        what they decided.
        """
        require_read_write(self.scope(), target=self.target.name)
        require_capability(self.scope(), ACCOUNT_LOCK_STATE, target=self.target.name)

        state = self.describe_user(account)
        if state is None:
            raise DriverError(
                f'account "{account}" does not exist on this target',
                hint=(
                    "the tool does not create accounts (Q8); nothing was reset, and the "
                    "account name is worth checking against the estate"
                ),
            )
        if expire:
            # Asked again here although the caller is required to have asked at
            # plan time: this is the last point at which refusing costs nothing,
            # and a caller that forgot would otherwise expire a password whose
            # predecessor keeps working (§4.3).
            self._refuse_rollover_window(state)
        if deliberately_locked(state.status):
            raise DriverError(
                f'account "{state.name}" is locked, and a reset does not unlock it',
                hint=(
                    "`LOCKED` without `(TIMED)` is somebody's decision -- an offboarding, "
                    "usually -- and handing the account a working password would undo it "
                    "silently. Unlock it deliberately first if that is what you mean "
                    "(H4)"
                ),
            )

        # Built before the first statement is issued, never between them.
        # `alter_user_password` validates: invariant
        # 11 refuses a password containing `"`, and `admissible` refuses one over
        # the target's byte limit. Building it inside the sequence would let that
        # refusal arrive *after* `ACCOUNT UNLOCK` had already run, leaving a
        # timed-locked account open on behalf of a reset that never happened --
        # a state change from a failed operation, which is the one outcome
        # invariant 4's plan-time rule exists to prevent. `byte_limit()` is
        # resolved by the same call and can fail the same way.
        statement = alter_user_password(
            Identifier(state.name),
            secret,
            scope=self.scope(),
            limit=self.byte_limit(),
            expire=expire,
        )

        # **What committed travels with the failure.** DDL commits as it
        # goes, so a statement that fails after an earlier one ran cannot take the
        # earlier one back -- a timed lock already cleared, or a password already
        # live -- and an exception alone would let the caller report the account
        # as untouched. `done` is the rows so far; a failure with nothing in it
        # that changed anything is an ordinary failure and is raised as one.
        done: tuple[AccountChange, ...] = ()
        try:
            done = (self._reset_unlock(state),)
            done = (*done, self._reset_set(state, statement, expire=expire))
            return (*done, self._reset_close_window(state, keep=keep_rollover))
        except DriverError as error:
            if any(one.changed for one in done):
                raise PartialAccountChangeError(error, completed=done) from error
            raise

    def _reset_unlock(self, state: UserState) -> AccountChange:
        """§4.1 statement 1 -- the timed lock only.

        A deliberate lock never reaches here: :meth:`reset_password` refuses it
        above, so ``locked`` at this point can only be ``LOCKED(TIMED)``. Stated
        rather than re-tested, because a second test would read as though the
        refusal might not have happened.
        """
        if not state.locked:
            return AccountChange(
                ACCOUNT_UNLOCK,
                changed=False,
                status=state.status,
                detail="the account is not locked",
            )
        self._issue(unlock_account(Identifier(state.name), scope=self.scope()))
        return AccountChange(
            ACCOUNT_UNLOCK,
            changed=True,
            status=state.status,
            detail=f"account was {state.status.lower()}; unlocked",
        )

    def _reset_set(self, state: UserState, statement: Statement, *, expire: bool) -> AccountChange:
        """§4.1 statement 2 -- the reset itself, always issued.

        Takes the **built** statement rather than the secret, which is what keeps
        every refusal ahead of the first `ACCOUNT UNLOCK`: this method can no
        longer be the one that discovers a password is inadmissible, because by
        the time it runs that question has been answered.

        ``changed`` is always ``True``, for :meth:`set_password`'s reason: *is
        the password already this value* is not a question a database can answer,
        so there is nothing to converge on. Invariant 9 does not govern this verb
        at all -- a fresh draw has no fixed point -- and a row claiming
        ``changed: false`` here could only be a guess.
        """
        self._issue(statement)
        return AccountChange(
            PASSWORD_SET,
            changed=True,
            status=state.status,
            detail="password set, expired for first logon" if expire else "password set",
        )

    def _reset_close_window(self, state: UserState, *, keep: bool) -> AccountChange:
        """§4.3 statement 3 -- end the rollover window unless asked to keep it.

        **The window is read from the state taken before the reset**, not after.
        That is correct rather than convenient: ``IDENTIFIED BY`` on a profile
        with a non-zero ``PASSWORD_ROLLOVER_TIME`` *opens* a window, so a state
        read afterwards would say a window is open on every such account and the
        row would stop distinguishing the profile that grants one from the
        account that just got one. What this row answers is whether the reset
        left the old password able to authenticate.

        Issued with no window open it is accepted silently and changes nothing
        (measured on 26ai, §4.3), so an account whose profile grants none costs
        one statement and nothing else -- but reporting ``changed: true`` for it
        would be the same lie :meth:`finish_rollover` reads its state to avoid.

        **Two conditions, not one.** The profile granting a window says the reset
        is about to open one; a window already being open says something about
        the account right now. They come apart: setting a profile's
        ``PASSWORD_ROLLOVER_TIME`` to zero leaves an already-open window reading
        ``OPEN & IN ROLLOVER``, so ``rollover_time`` says no and
        ``rollover_active`` says yes.

        **What that state does is not what it looks like.** Measured on 26ai Free
        23.26.2.0.0: the profile change kills the old password immediately
        (``ORA-01017``), and only the *status* is stale. Closing is still right,
        for two reasons. The status is what an operator reads and what `creds
        status` reports, and the statement makes it true again (the account goes
        to ``OPEN``). And the measurement covers one release; a release where the
        old password *does* outlive the profile change would need the close for
        its own sake.

        So the wider condition is safe under both readings and costs one
        silently-accepted statement under the one that holds here.
        :meth:`finish_rollover` already keys on ``rollover_active`` for its own
        half of the same question.
        """
        grants = is_enabled(state.rollover_time)
        open_now = bool(state.rollover_active)
        if keep:
            return AccountChange(
                ROLLOVER_FINISH,
                changed=False,
                status=state.status,
                detail=(
                    "rollover window kept, as asked"
                    if grants or open_now
                    else "no rollover window to keep; this profile grants none"
                ),
            )
        if not grants and not open_now:
            return AccountChange(
                ROLLOVER_FINISH,
                changed=False,
                status=state.status,
                detail="this profile grants no rollover window",
            )
        self._issue(finish_rollover(Identifier(state.name), scope=self.scope()))
        return AccountChange(
            ROLLOVER_FINISH,
            changed=True,
            status=state.status,
            detail="rollover window closed; the old password no longer works",
        )

    def expire_password(self, account: str) -> tuple[AccountChange, ...]:
        """Close an open window, then expire: two statements, one read.

        **One `describe_user` for both decisions**, for :meth:`reset_password`'s
        reason: two reads are two chances to see two different states.

        The conditions and the measurements behind them are
        :meth:`~sopuli.driver.protocol.Session.expire_password`'s. What is here
        is the order of refusals -- read-only, capability, existence -- and every
        one of them lands before the first statement is issued.

        ``state.expired`` already excludes ``EXPIRED(GRACE)``, which is
        exactly the reading this needs: a grace-period password still logs in,
        so expiring it is a change rather than a no-op.
        """
        require_read_write(self.scope(), target=self.target.name)
        require_capability(self.scope(), EXPIRE_PASSWORD, target=self.target.name)

        state = self.describe_user(account)
        if state is None:
            raise DriverError(
                f'account "{account}" does not exist on this target',
                hint=(
                    "the tool does not create accounts (Q8); nothing was expired, and the "
                    "account name is worth checking against the estate"
                ),
            )

        closed = self._expire_close_window(state)
        try:
            expired = self._expire(state)
        except DriverError as error:
            # The close has committed, and it is the half that matters: the old
            # password is already dead. Reporting the account as untouched would
            # hide that, so the failure carries what already happened.
            if closed.changed:
                raise PartialAccountChangeError(error, completed=(closed,)) from error
            raise
        return (closed, expired)

    def _expire_close_window(self, state: UserState) -> AccountChange:
        """Statement 1 -- end the window, only where one is open now.

        Keyed on ``rollover_active`` alone, unlike :meth:`_reset_close_window`,
        which also closes where the profile merely grants a window. The reset
        needs the wider test because its own ``IDENTIFIED BY`` opens a window; a
        bare ``PASSWORD EXPIRE`` opens none (measured; decision #525), so a profile
        that grants one with none open has nothing to close.

        ``rollover_active`` is read from the status, so it also catches the
        stale-window case :meth:`_reset_close_window` documents -- a window that
        outlived its profile's grant still reads ``IN ROLLOVER``.
        """
        if not state.rollover_active:
            return AccountChange(
                ROLLOVER_FINISH,
                changed=False,
                status=state.status,
                detail="no rollover window is open",
            )
        self._issue(finish_rollover(Identifier(state.name), scope=self.scope()))
        return AccountChange(
            ROLLOVER_FINISH,
            changed=True,
            status=state.status,
            detail="rollover window closed; the old password no longer works",
        )

    def _expire(self, state: UserState) -> AccountChange:
        """Statement 2 -- the expiry, unless the password is already expired.

        Read from the state taken before statement 1, which is safe: closing a
        window changes the ``IN ROLLOVER`` component and never the ``EXPIRED``
        one (measured; decision #525).
        """
        if state.expired:
            return AccountChange(
                PASSWORD_EXPIRE,
                changed=False,
                status=state.status,
                detail="the password is already expired",
            )
        self._issue(expire_password(Identifier(state.name), scope=self.scope()))
        was = state.status.lower()
        return AccountChange(
            PASSWORD_EXPIRE,
            changed=True,
            status=state.status,
            detail=f"account was {was}; password expired",
        )

    def require_no_rollover_window(self, account: str) -> None:
        """§4.3's plan-time refusal. See the protocol for the measurement."""
        state = self.describe_user(account)
        if state is None:
            raise DriverError(f'account "{account}" does not exist on this target')
        self._refuse_rollover_window(state)

    def _refuse_rollover_window(self, state: UserState) -> None:
        """The refusal itself, shared by the plan-time call and the reset.

        One implementation rather than two, because the two would drift and the
        one that drifted would be the one nobody runs until a password has
        already been drawn.
        """
        if not is_enabled(state.rollover_time):
            return
        profile = state.profile or "its profile"
        raise DriverError(
            f'account "{state.name}" is on profile {profile}, which grants a password '
            f"rollover window, and an expiring reset would leave the old password working",
            hint=(
                "measured on 26ai: the account goes to `EXPIRED & IN ROLLOVER`, and the old "
                "password answers ORA-28001 rather than ORA-01017 -- it still authenticates, "
                "and it is itself a way to set the new one. Use the unseen delivery path for "
                "this account, or reset one whose profile grants no window (UC-2 §4.3)"
            ),
        )

    def _issue(self, statement: Statement) -> None:
        """Execute one built statement, classifying whatever the server says.

        The ``reveal()`` is invariant 2's permitted one, as in
        :meth:`set_password`: nothing between this line and the wire may log it,
        and ``Statement.__str__`` is the redacted form so an accidental
        interpolation elsewhere cannot leak it. A cursor per statement, because
        §4.1's three are separate statements rather than one script.
        """
        with self.connection.cursor() as cursor:
            try:
                cursor.execute(statement.reveal())
            except Exception as error:  # noqa: BLE001 -- classified, never swallowed
                raise from_error(error).as_error() from error

    def _unlock(self, account: str) -> AttributeChange:
        """``ALTER USER … ACCOUNT UNLOCK``, or report that there was no lock.

        **The state is read first, and that is invariant 9** -- the same argument
        :meth:`finish_rollover` makes: Oracle accepts the statement against an
        already-open account silently, so a driver that just issued it would
        report a change on every run of an estate that declares the attribute.

        The capability is checked even though it is structural on Oracle
        (``ACCOUNT_STATUS`` and ``ALTER USER … ACCOUNT LOCK`` exist on every
        supported release), because what makes it structural is a fact about this
        product recorded in one place, and a caller reading this method should
        not have to know which of the two kinds of capability it is.
        """
        require_capability(self.scope(), ACCOUNT_LOCK_STATE, target=self.target.name)

        state = self.describe_user(account)
        if state is None:
            raise DriverError(
                f'account "{account}" does not exist on this target',
                hint=(
                    "the tool does not create accounts (Q8); `creds check` reports this "
                    "as ACCOUNT_MISSING rather than failing"
                ),
            )
        if not state.locked:
            return AttributeChange(
                ACCOUNT_UNLOCK, changed=False, detail="the account is not locked"
            )

        # `status` is carried into the detail because the two locks an operator
        # cares about are different events: `LOCKED` is somebody's decision and
        # `LOCKED(TIMED)` is the failed-login limit, which says the password in
        # the vault had already stopped working somewhere.
        was = state.status.lower()
        statement = unlock_account(Identifier(state.name), scope=self.scope())
        with self.connection.cursor() as cursor:
            try:
                cursor.execute(statement.reveal())
            except Exception as error:  # noqa: BLE001 -- classified, never swallowed
                raise from_error(error).as_error() from error

        return AttributeChange(ACCOUNT_UNLOCK, changed=True, detail=f"account was {was}; unlocked")

    def verify_password(
        self,
        account: str,
        secret: Secret,
        *,
        method: str = VERIFY_LOGIN,
        lockout_margin: int = DEFAULT_MARGIN,
        attempts: int = 1,
    ) -> VerifyResult:
        """Does this password work here -- asked at most once, or not at all.

        **One attempt, and no retry** (UC-1 §7 mitigation 1). The signature takes
        one secret and returns one result precisely so there is no shape for a
        back-off loop to hide in, and a wrong password is
        :data:`~sopuli.driver.protocol.FAIL` rather than an exception, because
        drift is exit 3 and that is what makes `check` schedulable.

        **The counter is read fresh, immediately before the attempt.** It is not
        taken from a :class:`UserState` the caller happens to be holding: every
        failed login moves it, including ones this tool did not make, so a value
        carried from earlier in the run is a lockout guard computing on a number
        that has moved. That is also why the state read here is
        :func:`~sopuli.driver.oracle.accounts.login_state` rather than
        ``describe`` -- `check` needs no site-specific grant (decisions P2 and Q1), and
        roles are a guardrail input for mutations, not for reading.

        Where ``SELECT ON SYS.USER$`` was never granted the guard is
        **unavailable**, the attempt still goes ahead, and the result says
        so in ``detail`` rather than letting an absent guard read like a
        satisfied one.
        """
        if method == VERIFY_HASH:
            return self._compare_verifier(account, secret)
        if method == VERIFY_BOTH:
            return self._compare_then_login(
                account, secret, lockout_margin=lockout_margin, attempts=attempts
            )
        if method != VERIFY_LOGIN:
            raise UnsupportedCapabilityError(
                f"verification method {method!r}",
                target=self.target.name,
                hint="this driver verifies by `login`, `hash` or `both`",
            )
        return self._login(
            account, secret, method=VERIFY_LOGIN, lockout_margin=lockout_margin, attempts=attempts
        )

    def _login(
        self,
        account: str,
        secret: Secret,
        *,
        method: str,
        lockout_margin: int,
        attempts: int,
    ) -> VerifyResult:
        """``method="login"``, and the second half of ``both``: one guarded attempt.

        Everything :meth:`verify_password` says about the attempt is this method's.
        ``method`` is only what the result is labelled with, so a ``both`` reports
        itself as ``both`` from either half.
        """
        with self.connection.cursor() as cursor:
            state = login_state(cursor, account)
            if state is None:
                return VerifyResult(
                    method=method,
                    result=UNAVAILABLE,
                    detail=f'there is no account "{account}" on this target',
                )
            guarded = self.scope().supports(OFFLINE_VERIFY)
            counter = failed_logins(cursor, state.name) if guarded else None

        if state.locked:
            # **Before the margin, not after.** A lock caused by earlier failures
            # usually leaves the counter at the threshold, so the margin check
            # would win and report `skipped` -- and the same locked account would
            # then describe itself differently depending on whether the counter
            # could be read. It is locked either way, and saying so is both
            # consistent and more useful than "we did not try".
            return VerifyResult(
                method=method,
                result=UNAVAILABLE,
                failed_logins=counter,
                failed_login_limit=state.failed_login_limit,
                detail=f"the account is locked ({state.status}); no login was attempted",
            )

        reason = margin_reason(
            counter, state.failed_login_limit, margin=lockout_margin, attempts=attempts
        )
        if reason is not None:
            return VerifyResult(
                method=method,
                result=SKIPPED,
                failed_logins=counter,
                failed_login_limit=state.failed_login_limit,
                lockout_margin_hit=True,
                detail=skipped_detail(reason),
            )

        outcome, detail, warning = self._attempt(state.name, secret)
        if not guarded:
            detail = "; ".join(
                part
                for part in (
                    detail,
                    "the lockout guard is unavailable: SELECT ON SYS.USER$ is not granted",
                )
                if part
            )

        return VerifyResult(
            method=method,
            result=outcome,
            failed_logins=counter,
            failed_login_limit=state.failed_login_limit,
            detail=detail or None,
            warning=warning,
        )

    def require_verifier(self, account: str, secret: Secret) -> None:
        """Refuse ``hash`` or ``both`` for ``account`` at **plan time**, or say nothing.

        Every refusal :meth:`_compare_verifier` can make, made before any account
        is checked, which is invariant 4: an explicit ``--method hash`` against a
        target that cannot compare fails with exit 5 naming the target, never as
        a row partway through a run. It takes the password because one refusal is
        about the value -- a character set that cannot hold it -- and the caller
        has it anyway.

        **A missing account says nothing**, for ``require_rollover``'s caller's
        reason: ``ACCOUNT_MISSING`` is a state the run reports per account, and
        refusing the estate over one would turn that finding into a failure.
        """
        self._verifier_answer(account, secret)

    def _compare_verifier(self, account: str, secret: Secret) -> VerifyResult:
        """``method="hash"``: compare with the stored 12C verifier, and log in as nobody.

        **No authentication attempt**, so none of ``login``'s guards apply: no
        counter moves, nothing is spent, and the lockout margin has nothing to
        protect. A locked account is compared like any other -- UC-1 §7 names that
        as hash mode's point -- and its lock is still reported, by ``check``
        from the account's status, where it has always come from.

        **Four refusals, each an** :class:`UnsupportedCapabilityError` **naming
        the target**, and none falls back to anything (invariant 4):

        * the session cannot read ``SYS.USER$``, so there is no verifier to read;
        * the account has no 12C verifier -- 11g, or ``PASSWORD_VERSIONS``
          without ``12C`` -- and comparing ``S:`` or 10G instead would report a
          check stronger than the one made;
        * a ``T:``/``t:`` token is not the 160 hex characters every release read
          has stored, so the format is one the comparison was never measured on;
        * the database character set cannot hold the password exactly, so the
          server hashed a converted copy that cannot be reproduced.

        A pass says which verifier the password reproduced, because during a
        rollover window that is the one thing a login cannot tell: both passwords
        authenticate, and only ``t:`` is the current one.
        """
        found = self._verifier_answer(account, secret)
        if found is None:
            return VerifyResult(
                method=VERIFY_HASH,
                result=UNAVAILABLE,
                detail=f'there is no account "{account}" on this target',
            )
        state, counter, answer = found
        return VerifyResult(
            method=VERIFY_HASH,
            result=FAIL if answer == NO_MATCH else PASS,
            failed_logins=counter,
            failed_login_limit=state.failed_login_limit,
            detail=_HASH_DETAIL[answer],
        )

    def _compare_then_login(
        self, account: str, secret: Secret, *, lockout_margin: int, attempts: int
    ) -> VerifyResult:
        """``method="both"``: the comparison, and then a login only if it passed.

        **The order is the decision**: the comparison costs
        nothing, so it goes first, and a mismatch is reported as ``fail`` without
        spending a login on a value already shown to be wrong. Lockout budget is
        what UC-1 §7 exists to protect, and a login that cannot change the answer
        is budget spent for nothing. A login is made only when the comparison
        passed, and then it is the ordinary guarded one, so the margin and the
        lock still decline it.

        The detail always says which half answered, because a ``both`` that
        reports ``fail`` from the comparison alone has made a weaker claim than
        one that also logged in.
        """
        compared = self._compare_verifier(account, secret)
        if compared.result == FAIL:
            return replace(
                compared,
                method=VERIFY_BOTH,
                detail=(
                    "matches none of the account's 12C verifiers, so the login half was not spent"
                ),
            )
        if compared.result != PASS:
            return replace(compared, method=VERIFY_BOTH)
        logged = self._login(
            account,
            secret,
            method=VERIFY_BOTH,
            lockout_margin=lockout_margin,
            attempts=attempts,
        )
        matched = (
            "matches the account's 12C verifier and logs in"
            if logged.result == PASS
            else "matches the account's 12C verifier"
        )
        return replace(logged, detail="; ".join(part for part in (matched, logged.detail) if part))

    def _verifier_answer(
        self, account: str, secret: Secret
    ) -> tuple[UserState, int | None, str] | None:
        """Read the verifiers and compare, raising every refusal; ``None`` if no account."""
        if not self.scope().supports(OFFLINE_VERIFY):
            raise UnsupportedCapabilityError(
                OFFLINE_VERIFY,
                target=self.target.name,
                hint=self._unreadable_verifier_hint(),
            )

        with self.connection.cursor() as cursor:
            state = login_state(cursor, account)
            if state is None:
                return None
            spare4 = stored_verifiers(cursor, state.name)
            counter = failed_logins(cursor, state.name)

        try:
            answer = compare(secret, spare4, limit=self.byte_limit())
        except NotComparableError as error:
            raise UnsupportedCapabilityError(
                VERIFIER_CHARSET,
                target=self.target.name,
                hint=(
                    f"{state.name}: {error}; verify by `login`, which the server "
                    "converts for itself"
                ),
            ) from error
        except Malformed12cVerifierError as error:
            raise UnsupportedCapabilityError(
                VERIFIER_FORMAT,
                target=self.target.name,
                hint=(
                    f"{state.name}: {error} -- this release stores a format the comparison "
                    "was never measured against, so it refuses rather than guess; verify "
                    "by `login`"
                ),
            ) from error
        if answer == NO_VERIFIER:
            raise UnsupportedCapabilityError(
                VERIFIER_12C,
                target=self.target.name,
                hint=(
                    f"{state.name} has no 12C verifier (PASSWORD_VERSIONS "
                    f"{' '.join(state.password_versions) or 'unknown'}), and the comparison "
                    "uses 12C and only 12C -- the older ones are weaker than a login, so "
                    "they are never a fallback; verify by `login`, or reset the "
                    "password where 12C is allowed so the account gets one"
                ),
            )

        return state, counter, answer

    def _unreadable_verifier_hint(self) -> str:
        """Why ``SYS.USER$`` cannot be read here, in the words that fit this target.

        **Two different situations, decided separately.** On an
        ordinary database the grant is optional and absent, and granting it is the
        remedy. On Autonomous Database no account can read ``SYS.USER$``, ``ADMIN``
        included, so the same advice would send an operator after a grant
        that does not exist. The capability probe cannot tell the two apart -- both
        answer ``ORA-00942`` -- so this asks ``CLOUD_SERVICE``, and only here.
        """
        with self.connection.cursor() as cursor:
            service = cloud_service_of(cursor)
        if service is not None:
            return (
                f"this is Autonomous Database ({service}), where no account can read "
                "SYS.USER$ -- not even ADMIN -- so `hash` cannot run here; verify by `login`"
            )
        return (
            "`hash` compares the account's stored verifier, which is in SYS.USER$ "
            "and needs the optional `GRANT SELECT ON SYS.USER$` "
            "(02-oracle-privileges.md §2) -- grant it, or verify by `login`"
        )

    def _attempt(self, name: str, secret: Secret) -> tuple[str, str | None, str | None]:
        """One login as ``name``, on a connection of its own.

        Returns the outcome, the detail explaining it, and -- on a login that
        succeeded while the server had something to say -- that warning.
        The third is ``None`` on every other path, including every failure: a
        connection that raised has no ``warning`` attribute to read, and the
        diagnostic it did carry is already in the detail.

        A **fresh connection as that user** is what UC-1 §5 step 6 asks for --
        the admin session proves nothing about this account's password. The
        connection is closed in a ``finally``, and a failure to close it is **not** allowed to
        change the answer. The login already happened; reporting a verification
        failure because the socket did not shut politely would turn a tidy-up
        problem into drift, and drift starts rotations.
        """
        connection = None
        try:
            connection = oracledb.connect(
                **connect_arguments(
                    self.target,
                    Credential(username=name, secret=secret),
                    timeouts=self.timeouts,
                )
            )
        except oracledb.Error as error:
            diagnosis = from_error(error)
            if not is_verification_outcome(diagnosis.code or None):
                # Not an answer about the password. A DSN that does not resolve,
                # a listener that is down, a logon protocol nobody can agree --
                # the error mapper classifies each into its own category and exit
                # path, and folding them into `unavailable` would let an unreachable
                # target look like an account-level finding.
                raise diagnosis.as_error() from error
            outcome, detail = result_for(diagnosis.code or None, diagnosis.message)
            return outcome, detail, None
        else:
            # Labelled like every other connection (§5). A failed login is the
            # most audited thing this tool does, so a verification session that
            # reaches UNIFIED_AUDIT_TRAIL without the run's id is the one an
            # operator cannot account for afterwards.
            #
            # A labelling failure is **not** allowed to change the answer, which
            # is the opposite of `connect`'s rule and deliberately so: there the
            # session had done nothing yet, and here the login has already
            # happened and answered the question. Reporting drift because a
            # `DBMS_SESSION` call was refused would start a rotation over an
            # audit-hygiene problem.
            with suppress(Exception):
                set_identifier(connection, self.correlation_id)
            # Read **before** the `finally` closes the connection, and defensively:
            # `warning` exists from python-oracledb 2.0 and is absent on older
            # clients, so `getattr` is what keeps this from turning a working
            # verification into an AttributeError on a machine with an older
            # driver.
            outcome, detail = result_for(None)
            return outcome, detail, self._connection_warning(connection)
        finally:
            if connection is not None:
                with suppress(Exception):
                    connection.close()

    @staticmethod
    def _connection_warning(connection: Any) -> str | None:
        """The diagnostic a successful connection is carrying, or ``None``.

        ``Connection.warning`` exists from python-oracledb 2.0 and is ``None`` on
        an ordinary login. Read through :func:`getattr` because an older client is
        a machine this tool still has to verify on, and an ``AttributeError`` here
        would turn a working verification into a crash over a diagnostic nobody
        asked for -- the opposite trade from the one that made this worth reading.

        Anything raised while reading it is swallowed for the same reason
        ``set_identifier`` above is: the login has already happened and answered
        the question, and a report about the answer must not change it.
        """
        try:
            warning = getattr(connection, "warning", None)
        except Exception:  # noqa: BLE001 -- a diagnostic, never the verdict
            return None
        if warning is None:
            return None
        code = getattr(warning, "full_code", None) or getattr(warning, "code", None)
        message = getattr(warning, "message", None) or str(warning)
        # Both shapes go through one formatter, including the codeless one: it is
        # what keeps the one-line rule in a single place rather than in two that
        # can drift apart.
        return warning_detail(None if code is None else str(code), message)

    def require_rollover(self, account: str) -> None:
        """Refuse ``--strategy rollover`` here, at **plan time**, or say nothing.

        Two separate things have to be true and they fail differently, which is
        the whole reason this is one call rather than a capability check
        somebody remembers to pair with a profile read:

        * **the release has the feature** -- absent on 18c and 11g, and that is
          :class:`~sopuli.driver.protocol.UnsupportedCapabilityError`, exit 5,
          naming the capability and the target (invariant 4);
        * **this account's profile grants a window** -- ``PASSWORD_ROLLOVER_TIME``
          greater than zero. That is a configuration rather than a limitation,
          so the message carries the exact ``ALTER PROFILE`` an operator would
          run.

        **The tool never issues that DDL.** Profiles are shared, so changing one
        affects accounts nobody selected, and `02-oracle-privileges.md` §3 keeps
        ``ALTER PROFILE`` off the service account deliberately. Q4 decides
        that the tool never alters a profile, so it reports the statement
        instead.
        """
        # The hint matters more here than on most refusals, because the two
        # halves of this method fail for opposite reasons and an operator meeting
        # the first one has no local remedy: no `ALTER PROFILE` reaches it, and
        # the version is the answer. So it says which strategies remain rather
        # than leaving the reader to find `--strategy` in `--help` and guess
        # which of its three values this release can serve.
        require_capability(
            self.scope(),
            PASSWORD_ROLLOVER,
            target=self.target.name,
            hint=(
                "gradual password rollover needs Oracle 19.12 or later; this release "
                "has no such feature and no profile setting adds it -- use "
                "`--strategy staged`, or omit `--strategy` and let the target decide"
            ),
        )

        state = self.describe_user(account)
        if state is None:
            raise DriverError(f'account "{account}" does not exist on this target')
        if not is_enabled(state.rollover_time):
            if state.profile is None:
                # No name, so no statement worth printing. A hint reading
                # `ALTER PROFILE the account's profile LIMIT ...` is not SQL, and
                # a hint is a thing operators paste into a terminal.
                raise DriverError(
                    f'account "{state.name}" grants no rollover window, and the '
                    "database did not report which profile it uses",
                    hint=(
                        "check DBA_USERS.PROFILE for this account; a rollover window "
                        "comes from the profile's PASSWORD_ROLLOVER_TIME"
                    ),
                )
            raise DriverError(
                f"profile {state.profile} grants no rollover window "
                f"(PASSWORD_ROLLOVER_TIME is {state.rollover_time or 'unset'})",
                hint=(
                    "sopuli does not alter a profile, because profiles are shared and "
                    "changing one affects accounts nobody selected. Run this yourself if "
                    "it is what you want: " + alter_profile_ddl(state.profile)
                ),
            )

    def finish_rollover(self, account: str) -> ChangeResult:
        """End an open rollover window now, or report that there was none.

        **The state is read first, and that is invariant 9 rather than
        caution.** Measured on 26ai: issuing the statement when no window is
        open is accepted silently, with no error and nothing changed -- so a
        driver that just issued it would report ``changed: true`` for a run that
        did nothing, every time.

        **Whose window it is, is not decided here.** The question "whose window is
        this?" has `lock break`'s shape, but the shapes diverge where it matters: a lock carries a
        record naming its holder, and a rollover window carries nothing at all --
        the database cannot say which run opened one. So the driver is the
        mechanism and reports the facts a caller needs (``rollover_active``, and
        the derived ``rollover_ends_at``), and the
        decision belongs to the command, which has the vault's view of whether
        the applications have moved on. Putting an ownership guard here would be
        a guard built on a fact this layer cannot observe.

        **A read-only target is refused first**, as every other mutating
        method here is. `creds finish-rollover` refuses a standby before it
        spends a login (:func:`sopuli.finish_rollover.settled_before_closing`);
        this is the driver's own guard, so no caller reaches the DDL without it.
        """
        require_read_write(self.scope(), target=self.target.name)
        state = self.describe_user(account)
        if state is None:
            raise DriverError(f'account "{account}" does not exist on this target')
        if not state.rollover_active:
            return ChangeResult(changed=False, detail="no rollover window is open")

        statement = finish_rollover(Identifier(state.name), scope=self.scope())
        with self.connection.cursor() as cursor:
            try:
                cursor.execute(statement.reveal())
            except Exception as error:  # noqa: BLE001 -- classified, never swallowed
                raise from_error(error).as_error() from error

        return ChangeResult(changed=True, detail="rollover window ended")

    def check_assertions(self) -> Scope:
        """Refuse unless the target's claims match what this connection is.

        UC-1 §5's pre-flight step 2, wired to the target this session was opened
        for. Returns the scope it checked against, because every caller wants it
        next and probing is cached anyway -- a caller that had to call
        :meth:`scope` again would look like it was asking twice.

        Read-write is **not** checked here. `creds check` reads and must keep
        working against a standby, so
        :func:`~sopuli.driver.oracle.capabilities.require_read_write` is the
        mutating commands' call to make.
        """
        scope = self.scope()
        assert_scope(scope, self.target.target.oracle, target=self.target.name)
        return scope

    def close(self) -> None:
        """Let the connection go. Safe twice, because a caller unwinding from
        an error should not have to know whether it already did."""
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def __enter__(self) -> OracleSession:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


@dataclass(frozen=True)
class OracleDriver:
    """P1's :class:`~sopuli.driver.protocol.Driver`, for Oracle.

    **A class rather than a module-level function.** P1 says ``connect(target, credential) ->
    Session``, and a function needing four more keyword arguments is not that
    interface -- a caller written against the protocol would get a ``TypeError``,
    which is the drift the protocol exists to prevent.

    The split falls out naturally once the shape is right: everything here is a
    property of the **run** -- which environment, which correlation id, which
    budgets, where the client lives -- and everything ``connect`` takes is a
    property of the **target**. Nothing run-scoped has to be repeated per target,
    and nothing target-scoped can be set once and silently reused.
    """

    env: Mapping[str, str]
    correlation_id: str
    timeouts: Timeouts = field(default_factory=Timeouts)
    #: ``runtime.oracle.client_lib_dir`` from the file, outranked by §6's
    #: variable. Resolved by the caller, which is the one holding a `Config`.
    client_lib_dir: str | None = None

    def connect(self, target: ExpandedTarget, credential: Credential) -> OracleSession:
        """Reach ``target`` as ``credential``, with the run's id on the session.

        Every failure comes back through :mod:`sopuli.driver.oracle.errors`, so
        an ``ORA-`` code keeps its number, its category and the server's own
        wording -- CLAUDE.md's rule that a vendor code is mapped and never
        swallowed.

        **The target is not added to the message here**, by design rather
        than omission: the server's wording is preserved rather
        than rewritten, and the command knows which target it asked for while
        this layer only knows the one it was handed. A caller reporting across an
        estate has the name already.
        """
        initialise(env=self.env, lib_dir=self.client_lib_dir)
        arguments = connect_arguments(target, credential, timeouts=self.timeouts)

        try:
            connection = oracledb.connect(**arguments)
        except oracledb.Error as error:
            raise from_error(error).as_error() from error

        try:
            # Set before anything else happens on this session, so there is no
            # window in which a statement could be audited without the id.
            connection.call_timeout = self.timeouts.call_timeout_ms
            set_identifier(connection, self.correlation_id)
        except oracledb.Error as error:
            # A session we cannot label is a session whose work cannot be traced
            # back to this run, which `02-oracle-privileges.md` §5 makes the
            # compensating control for having no audit table of our own. Closing
            # it is the honest outcome -- carrying on would silently give up the
            # join between the tool's output, the database trail and the vault.
            connection.close()
            raise from_error(error).as_error() from error

        return OracleSession(
            connection=connection,
            target=target,
            correlation_id=self.correlation_id,
            timeouts=self.timeouts,
        )


def set_identifier(connection: Any, correlation_id: str) -> None:
    """``DBMS_SESSION.SET_IDENTIFIER`` -- the join, in one call (§5).

    The run's UUID lands in ``UNIFIED_AUDIT_TRAIL.CLIENT_ID``, which is what
    makes the tool's JSON output, the database's own trail and the vault's
    secret metadata line up afterwards. It is the property the rejected
    definer-rights package's local audit table would have provided (ADR-001),
    kept without the table -- and it is worth doing on *every* connection,
    including ones that turn out to read nothing, because a session that
    appears in the trail unlabelled is the one somebody has to explain.

    **Bound, not interpolated.** Invariant 14 forbids binding a *password*,
    because ``V$SQL_BIND_CAPTURE`` keeps bind values in clear -- which is exactly
    why a correlation id is safe to bind and a good thing to have captured. The
    inverse mistake is the dangerous one: building this string by concatenation
    would be the habit that later writes a password into SQL text.
    """
    with connection.cursor() as cursor:
        cursor.callproc("dbms_session.set_identifier", [correlation_id])


def client_version() -> tuple[int, ...]:
    """The Instant Client's version, for ``sopuli doctor``.

    Needs thick mode up but **not** a database, which is the property the doctor
    wants: P4 requires the doctor report whether a target is out of the client's reach
    -- a 23.x client reaches 19c and later, so an 11.2 target cannot be reached
    from Apple Silicon at all -- and that is an answer worth giving before
    anybody waits on a connection that cannot succeed.
    """
    return tuple(oracledb.clientversion())

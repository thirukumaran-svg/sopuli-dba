"""Opening a connection, and putting the run's id on it (#176).

The first code in this project that opens a socket to a database, and the module
:data:`sopuli.driver.registry.DRIVERS` imports for ``type: oracle``. It imports
``oracledb`` at module scope on purpose: that is what makes
:func:`sopuli.driver.registry.resolve` able to answer "the driver is not
installed" as a structured error instead of a traceback (ADR-006 rule 1). The
package above it stays clean, so :mod:`.statements` and :mod:`.client` remain
importable -- and testable -- with no client on the machine.

Two decisions the issue asked for, made here and stated rather than implied.

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
The alternative needs ``ALTER SESSION SET CONTAINER``, which
``02-oracle-privileges.md`` §2 lists as optional and which the document's whole
position is to avoid needing: the grant set stays minimal, and a run that cannot
reach a PDB fails for that PDB rather than poisoning a session shared with
others.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
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
)
from sopuli.driver.oracle.capabilities import assert_scope, observe, require_read_write
from sopuli.driver.oracle.client import (
    CLIENT_LIB_DIR_ENV,
    NO_CLIENT,
    Timeouts,
    connect_arguments,
    missing_client,
)
from sopuli.driver.oracle.errors import from_error
from sopuli.driver.oracle.limits import resolve as resolve_limit
from sopuli.driver.oracle.privileges import audit
from sopuli.driver.oracle.rollover import alter_profile_ddl, is_enabled
from sopuli.driver.oracle.statements import (
    Identifier,
    alter_user_password,
    alter_user_profile,
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
from sopuli.driver.protocol import (
    ACCOUNT_LOCK,
    ACCOUNT_LOCK_STATE,
    ACCOUNT_UNLOCK,
    ATTRIBUTE_SET,
    OFFLINE_VERIFY,
    PASSWORD_ROLLOVER,
    PROFILE_MANAGEMENT,
    SKIPPED,
    UNAVAILABLE,
    VERIFY_LOGIN,
    AccountAttributes,
    AccountChange,
    AttributeChange,
    ChangeResult,
    Credential,
    DriverError,
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
    reach for a :class:`~sopuli.config.model.Config`. #176's review found it
    ignored outright -- a documented key that silently did nothing, which is
    worse than one that does not exist -- and threading it through
    :class:`OracleDriver` is where a run-scoped fact belongs.
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
            # would be the one place the promise did not hold, and #172's
            # fallback already preserves the vendor code and message for a code
            # it has no specific rule for.
            raise from_error(error).as_error() from error
        _initialised = True


@dataclass
class OracleSession:
    """One open connection, and everything done through it.

    **Now a** :class:`sopuli.driver.protocol.Session`, which it was deliberately
    not until #180. The protocol is structural, so this became one by acquiring
    the last of its methods rather than by declaring anything -- ``scope`` (#177),
    ``describe_user`` (#178), ``set_password`` (#179) and ``verify_password``
    (#180). ``tests/driver/test_oracle_verify.py`` asserts the ``isinstance``,
    so the claim is checked rather than asserted in prose.

    ``apply_attributes`` arrived with #300, which gave it its first caller --
    `creds apply` enforcing UC-1 §5's account unlock. It was absent until then on
    the rule that a method on a Protocol is a demand on every implementation.
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
        """What this connection is, and what it can do (#177).

        Probed on first call and **cached for the life of the session**
        (invariant 3). Twenty-one PDBs answer differently, so the cache is per
        session and never per driver, and the answer is never derived from a
        version in a file.

        **On first call, not during** :meth:`OracleDriver.connect`, and #177's
        "on connect" means *from the connection rather than from a config file*
        rather than *eagerly*. Three reasons, in ascending order of how much they
        would cost to get wrong:

        * ``connect`` promises what connecting is. Probing inside it would make
          an ``ORA-`` from a dictionary read arrive as a connection failure,
          which sends the reader to the listener and the credential for a
          problem that is neither.
        * The probe is several round trips, and not every session wants them.
        * **It would pre-answer an open decision.** #180 has yet to decide
          whether verification opens its own connection or reuses the admin
          session; a session opened as the account *being verified* holds none of
          §2's grants, so probing every connection would make one of those two
          options quietly unworkable. Laziness leaves the choice where it belongs.

        What P1 does require is that a read-only standby is refused **up front**
        rather than mid-statement. That is a property of when the *plan* asks —
        which it does, before anything mutates — and not of when the session
        volunteers.

        The probe raises rather than degrades. A capability that is absent is an
        ordinary result and comes back as a smaller set; a probe that could not
        be *answered* is :class:`~sopuli.driver.oracle.capabilities.ProbeError`,
        because #195 is what a run looks like when those two share a word.
        """
        if self._scope is None:
            with self.connection.cursor() as cursor:
                self._scope = observe(cursor)
        return self._scope

    def privileges(self) -> PrivilegeAudit:
        """What this session holds that §3 says it should not (#213).

        **Not folded into** :meth:`scope`, unlike the capability probe, and the
        difference is who asks. Every command calls ``scope()``; only
        ``doctor --check-privileges`` wants this, and it is not cheap: three
        reads plus one probe per grant §2 documents. Paying that on every
        connection to answer a question nobody asked is the cost the flag exists
        to avoid. Uncached for the same reason: it is asked once per run.

        Reporting is not enforcing (#173), and this never refuses. P5 is decided
        — over-granting **warns**.
        """
        with self.connection.cursor() as cursor:
            # The scope decides whether `V_$PDBS` is expected: §2 grants it in
            # the root only, and calling a PDB half-installed for lacking a grant
            # it was never given would be wrong in the direction that costs the
            # most trust. Cached, so this is not another round trip.
            return audit(cursor, scope_type=self.scope().type)

    def describe_user(self, account: str) -> UserState | None:
        """The account's state, or ``None`` if there is no such account (#178).

        ``None`` is UC-1's ``ACCOUNT_MISSING`` and not an error -- the tool does
        not create accounts (Q8). The reads are all on the baseline grant set,
        so `check` needs no site-specific privilege to run (#86).

        One read goes further where the optional grant was made: on a release
        with no ``DBA_USERS.PASSWORD_CHANGE_DATE``, the date comes from
        ``SYS.USER$.PTIME`` (#386). Asked of the capability probe, which is
        cached, so a session without the grant never issues the read at all.
        """
        with self.connection.cursor() as cursor:
            return describe(cursor, account, user_dollar=self.scope().supports(OFFLINE_VERIFY))

    def password_constraints(self, account: str) -> AccountConstraints | None:
        """What this target says about a password for one account (#317).

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

        Cached per session. #171 makes this a required argument to the statement
        builder so that nobody can build one without having found out, and this
        is the finding out.
        """
        if self._limit is None:
            with self.connection.cursor() as cursor:
                self._limit = resolve_limit(cursor, self.scope().db_version)
        return self._limit

    def set_password(self, account: str, secret: Secret) -> ChangeResult:
        """Issue the ``ALTER USER`` (#179), and let a rejection be a rejection.

        **The driver does not regenerate.** #179 asks where UC-1 §4's bounded
        loop lives, and it is not here: a driver that drew another password on
        `ORA-28003` would be putting a value into the database that the vault has
        never seen, which is the ordering UC-1 §3 exists to prevent. So a
        rejection is reported -- classified by #172 as ``password_rejected`` or
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

        **A read-only target is refused here, before anything is built.** #177
        put :func:`~sopuli.driver.oracle.capabilities.require_read_write` in the
        mutating callers' hands rather than in ``assert_scope``, so that `creds
        check` keeps working against a physical standby -- and this is the
        mutating caller. Leaving it to a command that does not exist yet would
        have been a refusal that cannot fire, which P1 asks for *up front*
        precisely so it does not arrive as a failed ``ALTER USER`` half way
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
        """Enforce UC-1 §5's opt-in account attributes (#300).

        One entry per attribute the caller declared, whether or not it needed
        doing. Nothing is inferred: an ``AccountAttributes`` with nothing set
        returns an empty tuple and reads nothing, so an estate that declares no
        attributes pays no round trip for them.

        **Read-write is refused here as it is in** :meth:`set_password`, and for
        the same reason: this is a mutating caller, and #177 put the check in the
        mutating callers' hands so that `creds check` keeps working against a
        physical standby.
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
        only read: altering a profile is Q4 (#88) and this driver builds no
        statement that would.
        """
        require_capability(self.scope(), PROFILE_MANAGEMENT, target=self.target.name)

        with self.connection.cursor() as cursor:
            return resolve_profile(cursor, profile)

    def resolve_role(self, role: str) -> str | None:
        """How this database spells ``role``, or ``None`` if it has no such one.

        **No capability gate**, unlike :meth:`resolve_profile`. ``DBA_ROLES`` is
        in ``02-oracle-privileges.md`` §2's grant set unconditionally, and
        nothing here is a *profile* operation -- gating it on
        ``profile_management`` would refuse a role predicate on a target whose
        only shortcoming is about profiles.
        """
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

        **Never ``ALTER PROFILE``** (Q4, #88). What moves is one account the
        config whitelists; the profile itself is left exactly as its owner wrote
        it, which is the half of #181's position this shares -- that one reports
        the ``ALTER PROFILE`` an operator would run and never issues it, and this
        one never has cause to.

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
        refuses a deliberate ``LOCKED`` (H4, #455) while it clears a timed one.
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
        """Does this password work here (#180) -- asked at most once, or not at all.

        **One attempt, and no retry** (UC-1 §7 mitigation 1). The signature takes
        one secret and returns one result precisely so there is no shape for a
        back-off loop to hide in, and a wrong password is
        :data:`~sopuli.driver.protocol.FAIL` rather than an exception, because
        drift is exit 3 and that is what makes `check` schedulable.

        **The counter is read fresh, immediately before the attempt.** It is not
        taken from a :class:`UserState` the caller happens to be holding: every
        failed login moves it, including ones this tool did not make, so a value
        carried from earlier in the run is a lockout guard computing on a number
        that has since moved. That is also why the state read here is
        :func:`~sopuli.driver.oracle.accounts.login_state` rather than
        ``describe`` -- #86 decided `check` needs no site-specific grant, and
        roles are a guardrail input for mutations, not for reading.

        Where ``SELECT ON SYS.USER$`` was never granted the guard is
        **unavailable**, the attempt still goes ahead (#86), and the result says
        so in ``detail`` rather than letting an absent guard read like a
        satisfied one.
        """
        if method != VERIFY_LOGIN:
            raise UnsupportedCapabilityError(
                f"verification method {method!r}",
                target=self.target.name,
                hint=(
                    "only `login` exists in this build; whether `hash` ever ships depends "
                    "on #90, which is open"
                ),
            )

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

    def _attempt(self, name: str, secret: Secret) -> tuple[str, str | None, str | None]:
        """One login as ``name``, on a connection of its own.

        Returns the outcome, the detail explaining it, and -- on a login that
        succeeded while the server had something to say -- that warning (#322).
        The third is ``None`` on every other path, including every failure: a
        connection that raised has no ``warning`` attribute to read, and the
        diagnostic it did carry is already in the detail.

        A **fresh connection as that user** is what UC-1 §5 step 6 asks for --
        the admin session proves nothing about this account's password. #180
        leaves the hygiene to be decided here, and it is: the connection is
        closed in a ``finally``, and a failure to close it is **not** allowed to
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
                # #172 has classified each into its own category and exit path,
                # and folding them into `unavailable` would let an unreachable
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
            # `warning` arrived in python-oracledb 2.0 and is absent on older
            # clients, so `getattr` is what keeps this from turning a working
            # verification into an AttributeError on a machine with an older
            # driver (#322).
            outcome, detail = result_for(None)
            return outcome, detail, self._connection_warning(connection)
        finally:
            if connection is not None:
                with suppress(Exception):
                    connection.close()

    @staticmethod
    def _connection_warning(connection: Any) -> str | None:
        """The diagnostic a successful connection is carrying, or ``None``.

        ``Connection.warning`` arrived in python-oracledb 2.0 and is ``None`` on
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
        ``ALTER PROFILE`` off the service account deliberately. Q4 (#88) is open
        with a documented leaning of no; reporting the statement is that leaning,
        and it is the half that can be reversed if #88 ever says otherwise.
        """
        # The hint matters more here than on most refusals, because the two
        # halves of this method fail for opposite reasons and an operator meeting
        # the first one has no local remedy: no `ALTER PROFILE` reaches it, and
        # the version is the answer. So it says which strategies remain rather
        # than leaving the reader to find `--strategy` in `--help` and guess
        # which of its three values this release can serve (#381).
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

        **Whose window it is, is not decided here.** #181 asks the question and
        it has `lock break`'s shape, but the shapes diverge where it matters: a
        lock carries a record naming its holder, and a rollover window carries
        nothing at all -- the database cannot say which run opened one. So the
        driver is the mechanism and reports the facts a caller needs
        (``rollover_active``, and the derived ``rollover_ends_at``), and the
        decision belongs to the command, which has the vault's view of whether
        the applications have moved on. Putting an ownership guard here would be
        a guard built on a fact this layer cannot observe.
        """
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

    **A class rather than a module-level function**, which is #176's review
    correcting the first draft. P1 says ``connect(target, credential) ->
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
        wording (#172) -- CLAUDE.md's rule that a vendor code is mapped and never
        swallowed.

        **The target is not added to the message here**, and that is #172's
        design rather than an omission: the server's wording is preserved rather
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
    """The Instant Client's version, for ``sopuli doctor`` (#182).

    Needs thick mode up but **not** a database, which is the property #182 wants:
    P4 requires the doctor report whether a target is out of the client's reach
    -- a 23.x client reaches 19c and later, so an 11.2 target cannot be reached
    from Apple Silicon at all -- and that is an answer worth giving before
    anybody waits on a connection that cannot succeed.
    """
    return tuple(oracledb.clientversion())

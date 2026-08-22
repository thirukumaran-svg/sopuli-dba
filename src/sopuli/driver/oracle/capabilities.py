"""What a connection turned out to be, and what it can do (#177).

Invariant 3, made real: **ask the database, cache per session, branch on the
capability.** Nothing here reads a version from a file, and nothing here is
reachable from a command that has not connected.

Two things about this module are decisions rather than mechanics, and both were
bought with a measurement (#195).

**A probe that fails is not automatically a "no".** The first version of this
idea lived in ``tests/oracle_harness.py`` and read *any* exception as absent, on
the reasonable-sounding grounds that a missing view, a missing column and a
missing grant all mean the same thing to a caller. They do. What that rule also
swallowed was ``ORA-02003: invalid USERENV attribute`` -- a probe asking a
question Oracle does not have -- which then reported ``container_scope`` absent
on every database the tool ever touched, including the ones where it was plainly
present, and looked exactly like a measurement while doing it. So the negative
answers are enumerated (:data:`ABSENT_CODES`) and everything else is
:class:`ProbeError`. The tool refuses rather than guesses, which is CLAUDE.md's
rule, and the failure that hid for a release cycle would now arrive on the first
run.

**One question per capability, several round trips.** #177 asks whether the probe
set should be one statement or many. Many, and not reluctantly: each answer is
attributable to the question that produced it, a probe that fails names itself,
and the alternative is a single ``select`` whose seventh column silently becomes
``null`` on the release nobody tested. A session opens once and answers eight
short questions against ``dual`` and two dictionary views; the cost is not
measurable next to the connection itself.

**Nothing here imports ``oracledb``.** The SQL, the reading of an answer and the
mapping onto a :class:`~sopuli.driver.protocol.Scope` are pure, so they are
tier 0 and the tier-1 lane exercises the same code it tests. It is also what lets
``tests/oracle_harness.py`` import :data:`PROBES` rather than keep a second copy:
§3's claim that the suite validates the capability model only holds while the
harness and the driver are asking the same questions, and #195 is what it looks
like when they are not.
"""

from __future__ import annotations

from typing import Any, Protocol

from sopuli.config.model import TargetOracle
from sopuli.driver.oracle.errors import from_error
from sopuli.driver.protocol import (
    ACCOUNT_LOCK_STATE,
    CAPABILITIES,
    COMMON_USERS,
    EXPIRE_PASSWORD,
    OFFLINE_VERIFY,
    PASSWORD_REUSE_POLICY,
    PASSWORD_ROLLOVER,
    PROFILE_MANAGEMENT,
    UNKNOWN,
    DriverError,
    Scope,
)
from sopuli.exit_codes import ExitCode


class Cursor(Protocol):
    """The one shape this module needs from a database cursor.

    Structural, so a tier-0 test hands it a fake and the tier-1 lane hands it
    ``oracledb``'s, and neither has to know about the other.
    """

    def execute(self, statement: str, parameters: Any = None, /) -> Any: ...

    def fetchone(self) -> Any: ...

    def fetchall(self) -> Any: ...


class ProbeError(DriverError):
    """A probe failed for a reason that is not an answer.

    Distinct from a capability being absent, which is an ordinary outcome and
    not an exception at all. This is *the tool asked something it should not
    have asked*, or *the database broke while answering* -- and #195 is the
    argument for the two never sharing a word again.
    """

    category = "database"


# ------------------------------------------------------------------ probes ---

#: Codes that mean **no**, and nothing else does.
#:
#: * ``ORA-00942`` -- the view or table is not there, or the grant is not there.
#:   Indistinguishable from Oracle and identical in consequence.
#: * ``ORA-00904`` -- the column is not there, which is how a feature added in a
#:   later release announces itself to a query written for it.
#: * ``ORA-01031`` -- the privilege is not held. `offline_verify` is the case
#:   this exists for: #86 made ``SELECT ON SYS.USER$`` an optional grant, so its
#:   absence is the ordinary configuration rather than a fault.
#: * ``ORA-41900`` -- the ``READ`` privilege is not held, which is what a modern
#:   release says instead of ``ORA-00942`` when the asker is privileged enough to
#:   be told the object exists.
#:
#: **The last one was measured, not reasoned about** (26ai 23.26.2.0.0). The same
#: ungranted ``SYS.USER$`` answers ``ORA-41900`` to ``SYSTEM`` and ``ORA-00942``
#: to an account with no privileges at all -- Oracle declines to admit the table
#: exists to the second one. Both mean the grant is absent, and only one of them
#: is the code anybody would have predicted. Which is the argument for this list
#: being a list of things somebody ran rather than a list of things that sound
#: right: a code missing from here does not degrade, it raises.
ABSENT_CODES = frozenset({"ORA-00942", "ORA-00904", "ORA-01031", "ORA-41900"})

#: One question per capability, each answering with a truthy first column.
#:
#: ``common_users`` is the one worth reading twice, because it asks about a
#: **privilege** and not about a place. Measured on 26ai (#195): an account
#: holding ``ALTER USER`` commonly reads 1 here and successfully alters a common
#: user from the root; an account holding the identical privilege *locally* reads
#: 0 and gets ``ORA-01031`` for the same statement. Where the session is standing
#: is :attr:`~sopuli.driver.protocol.Scope.type`'s answer, not this one -- a root
#: session that lacks the grant and a PDB session that holds it are different
#: failures, and they come back from Oracle as different codes.
#:
#: ``USER_SYS_PRIVS`` rather than ``DBA_SYS_PRIVS``, which the documented grant
#: set cannot read (``ORA-00942``), and rather than ``SESSION_PRIVS``, which sees
#: role-derived privileges but has no ``COMMON`` column and so calls a local
#: grant a pass. Both alternatives were measured before this one was chosen.
PROBES: dict[str, str] = {
    COMMON_USERS: (
        "select count(*) from user_sys_privs where privilege = 'ALTER USER' and common = 'YES'"
    ),
    PASSWORD_ROLLOVER: (
        "select count(*) from dba_profiles where resource_name = 'PASSWORD_ROLLOVER_TIME'"
    ),
    OFFLINE_VERIFY: "select count(*) from sys.user$ where rownum = 1",
    PROFILE_MANAGEMENT: "select count(*) from dba_profiles where rownum = 1",
    PASSWORD_REUSE_POLICY: (
        "select count(*) from dba_profiles where resource_name = 'PASSWORD_REUSE_MAX'"
    ),
}

#: Capabilities with nothing to ask, and why.
#:
#: Kept as data rather than folded into whatever a probe returned, so a reader
#: can tell "we asked and it said yes" from "there was nothing to ask". Writing
#: ``select 1 from dual`` for these would look like a probe and measure nothing,
#: which is worse than saying so.
STRUCTURAL: dict[str, str] = {
    EXPIRE_PASSWORD: "ALTER USER ... PASSWORD EXPIRE exists on every supported release",
    ACCOUNT_LOCK_STATE: "ACCOUNT_STATUS and ALTER USER ... ACCOUNT LOCK likewise",
}


# ---------------------------------------------------------- scope questions ---

#: Where this session is standing. Needs **no grant at all**, which is why the
#: scope is resolved from it rather than from ``V$PDBS`` or ``CDB_PDBS``: a
#: half-installed service account must still be able to find out what it is
#: connected to, or the diagnosis of its own missing grants is unreadable.
CONTAINER_NAME = "select sys_context('userenv','con_name') from dual"

#: ``ORA-02003`` from :data:`CONTAINER_NAME` is not a failure and not an absent
#: capability. It is 11.2 saying it has never heard of containers, which is the
#: single question in this module where that code carries information.
#:
#: Enumerated here rather than caught loosely, because the whole argument of
#: :data:`ABSENT_CODES` is that a code meaning something in one place must not be
#: allowed to mean anything anywhere else.
NO_CONTAINERS = "ORA-02003"

#: The root's own name. A session here can alter a common user; anywhere else
#: cannot, and Oracle says so with ``ORA-65040`` rather than a privilege error.
ROOT_CONTAINER = "CDB$ROOT"

DATABASE_FACTS = "select db_unique_name, open_mode from v$database"

VERSION = "select version from v$instance"


def read(cursor: Cursor, statement: str, **binds: Any) -> Any:
    """Run one question. An expected negative is ``None``; anything else raises.

    The rule :data:`ABSENT_CODES` describes, in the one place that applies it --
    which is why a caller with a bind variable comes here rather than reaching
    for the cursor directly. #178's 11.2 fallback depends on it: ``ORA-00904``
    *is* the answer to "does this release have ``PASSWORD_CHANGE_DATE``", and it
    only reads as an answer where this rule is applied.

    **Binds are values, never identifiers**, and never a password (invariant 14):
    ``V$SQL_BIND_CAPTURE`` samples bind values at hard parse and keeps them in
    clear, which is what makes an account name safe to bind and a secret not.
    """
    try:
        cursor.execute(statement, binds or None)
        return cursor.fetchone()
    except Exception as error:  # noqa: BLE001 -- classified on the next line
        diagnosis = from_error(error)
        if diagnosis.code in ABSENT_CODES:
            return None
        raise ProbeError(
            f"a capability probe failed with {diagnosis.code or 'no code'}: {diagnosis.message}",
            code=diagnosis.code or None,
            hint=(
                "this is not the same as the capability being absent -- the probe itself "
                "could not be answered. The statement was: " + statement
            ),
        ) from error


def probe(cursor: Cursor) -> frozenset[str]:
    """Every capability this connection reports, asked one question at a time."""
    found = {name for name, sql in PROBES.items() if _truthy(read(cursor, sql))}
    return frozenset(found | set(STRUCTURAL))


def _truthy(row: Any) -> bool:
    return bool(row and row[0])


# -------------------------------------------------------------------- scope ---


def container_of(cursor: Cursor) -> str | None:
    """The container this session is in, or ``None`` where there are none.

    ``None`` is 11.2 and a 12.1 non-CDB: no containers exist, so there is no name
    to report, and that is a fact rather than a gap.
    """
    try:
        cursor.execute(CONTAINER_NAME)
        row = cursor.fetchone()
    except Exception as error:  # noqa: BLE001 -- classified on the next line
        if from_error(error).code == NO_CONTAINERS:
            return None
        raise
    return str(row[0]) if row and row[0] else None


def scope_type(container: str | None) -> str:
    """Which of P1's scopes a container name implies.

    Three of the five, and the two that are missing are missing on purpose.
    ``app_root`` and ``app_pdb`` need ``DBA_PDBS``/``V$PDBS``, which
    ``02-oracle-privileges.md`` §2 does not grant, and no application container
    has ever been run against this code -- so an application PDB reads as ``pdb``
    here. That is a known limit rather than a claim: what depends on it is
    :func:`~sopuli.driver.oracle.statements.container_clause`, which refuses an
    application container outright, and its refusal simply will not fire on a
    scope this cannot yet detect. Verifying it needs a real application
    container, which puts it in the same class as the other "verify before
    implementing" questions rather than in this change.
    """
    if container is None:
        return "non_cdb"
    if container.upper() == ROOT_CONTAINER:
        return "cdb_root"
    return "pdb"


def observe(cursor: Cursor) -> Scope:
    """Everything the driver knows about this connection, in one object.

    P1's ``capabilities()`` folded into ``scope()``, as
    :mod:`sopuli.driver.protocol` explains: both are observed at one moment from
    one connection, the run document prints them as one object, and two calls
    would mean two caches and a merge at the output layer.

    ``read_write`` is the one worth having before any DDL is built. A physical
    standby opens ``READ ONLY``, and P1 requires the refusal up front rather than
    halfway through a statement.
    """
    container = container_of(cursor)
    facts = read(cursor, DATABASE_FACTS)
    version = read(cursor, VERSION)
    open_mode = str(facts[1]) if facts and facts[1] else None

    return Scope(
        type=scope_type(container),
        container=container,
        db_unique_name=str(facts[0]) if facts and facts[0] else None,
        db_version=str(version[0]) if version and version[0] else None,
        open_mode=open_mode,
        read_write=None if open_mode is None else open_mode.upper().startswith("READ WRITE"),
        capabilities=probe(cursor),
    )


# --------------------------------------------------------------- assertions ---


class ScopeAssertionError(DriverError):
    """A target claimed a scope or a container, and the connection is elsewhere.

    ``config`` and exit 9, because whichever half is wrong the operator's next
    action is to reconcile the file with reality -- exit 9 means *fix your config
    file*, which is the right instruction even when what actually changed was the
    database. Generic failure would discard the most actionable distinction the
    tool has.

    **The message names both values.** An error saying only that the scope was
    wrong sends the reader to the file to look up what they already wrote; what
    they need is the other half, which is the half they cannot see.
    """

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID


class ReadOnlyTargetError(DriverError):
    """A mutation was planned against a target that is not open read-write.

    P1 requires this **up front** rather than halfway through a statement: a
    physical standby opens ``READ ONLY``, and finding out at the ``ALTER USER``
    means finding out after the run already decided this target was fine.

    Exit 1 with its own category, which is P5's established shape for a condition
    that has no number of its own -- connectivity and authorization are the
    precedent. Adding a number to P5's table is a change to a contract schedulers
    branch on, and a standby does not warrant one.

    Deliberately **not** raised by :func:`assert_scope`. `creds check` reads and
    must keep working against a standby, so refusing one is the mutating
    commands' call and not a property of having connected.
    """

    category = "database"


def assert_scope(scope: Scope, declared: TargetOracle | None, *, target: str) -> None:
    """Refuse unless what the file claims is what the connection found.

    UC-1 §5's pre-flight step 2, and `01-configuration.md` §3a's whole reason for
    calling these assertions rather than settings: the driver detects the real
    scope and container, so what the file writes is a claim to be checked rather
    than a value to be applied. It catches the two things no amount of load-time
    validation can see -- a ``dsn:`` edit that silently repointed a target at a
    different container, and a PDB whose role changed under an estate that still
    describes the old one.

    **A target that asserts nothing is not incompletely configured.** It makes no
    claim, and the driver reports what it found; both keys are optional and
    neither constrains the other.

    Containers compare case-insensitively, which is the same rule
    :attr:`~sopuli.driver.oracle.statements.Identifier.is_common` already applies
    to ``C##``: Oracle upper-cases an unquoted identifier, so ``freepdb1`` in a
    file and ``FREEPDB1`` from ``con_name`` are one container and a check that
    said otherwise would fail on a correct estate. A PDB created with a quoted
    lower-case name would defeat that, and is exotic enough to be worth the trade
    in this direction -- the alternative rejects the ordinary spelling every time.
    """
    if declared is None:
        return

    if declared.scope is not None:
        if scope.type == UNKNOWN:
            raise ScopeAssertionError(
                f'target "{target}" declares oracle.scope: {declared.scope}, '
                "and the driver could not determine what this connection is",
                hint=(
                    "an unresolved scope is not a confirmed one, and a claim that cannot be "
                    "checked is not a claim that passed; `sopuli doctor` reports what the "
                    "connection looks like"
                ),
            )
        if declared.scope != scope.type:
            raise ScopeAssertionError(
                f'target "{target}" declares oracle.scope: {declared.scope}, '
                f"but this connection is {scope.type}",
                hint=(
                    "the dsn may have been repointed at a different container, or this "
                    "database's role changed under an estate that still describes the old one"
                ),
            )

    if declared.container is not None:
        if scope.container is None:
            raise ScopeAssertionError(
                f'target "{target}" declares oracle.container: {declared.container}, '
                "but this database has no containers",
                hint=(
                    "the connection reached a non-CDB, where there is no container to name; "
                    "check the dsn"
                ),
            )
        if declared.container.upper() != scope.container.upper():
            raise ScopeAssertionError(
                f'target "{target}" declares oracle.container: {declared.container}, '
                f"but this connection is in {scope.container}",
                hint=(
                    "the dsn may have been repointed at a different container, or this "
                    "database's role changed under an estate that still describes the old one"
                ),
            )


def require_read_write(scope: Scope, *, target: str) -> None:
    """Refuse a mutation against a target that is not open read-write (P1).

    Called by the commands that write, at plan time, and by nothing else --
    see :class:`ReadOnlyTargetError` for why this is not folded into
    :func:`assert_scope`.

    An **unknown** open mode is not a refusal. ``V$DATABASE`` is in the
    documented grant set but a half-installed account cannot read it, and
    refusing every such target would turn a missing grant into "this database is
    a standby", which is a worse diagnosis than the one the missing grant already
    produces. The server refuses a write to a standby on its own; this exists to
    make the refusal early and legible, not to be the only thing standing there.
    """
    if scope.read_write is False:
        raise ReadOnlyTargetError(
            f'target "{target}" is open {scope.open_mode or "read-only"} and cannot be written to',
            hint=(
                "this looks like a physical standby; point the target at the primary, "
                "or drop it from the selection"
            ),
        )


#: Asserted by ``tests/driver/test_capabilities.py`` against P1's own table, so a
#: capability added to the document and not to the code -- or the reverse -- fails
#: rather than drifts. Every capability has to choose a side deliberately.
PROBED_OR_STRUCTURAL = frozenset(PROBES) | frozenset(STRUCTURAL)

__all__ = [
    "ABSENT_CODES",
    "CAPABILITIES",
    "CONTAINER_NAME",
    "DATABASE_FACTS",
    "NO_CONTAINERS",
    "PROBED_OR_STRUCTURAL",
    "PROBES",
    "ROOT_CONTAINER",
    "STRUCTURAL",
    "UNKNOWN",
    "VERSION",
    "Cursor",
    "ProbeError",
    "ReadOnlyTargetError",
    "ScopeAssertionError",
    "assert_scope",
    "container_of",
    "observe",
    "probe",
    "read",
    "require_read_write",
    "scope_type",
]

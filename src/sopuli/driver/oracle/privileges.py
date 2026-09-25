"""What the service account holds that it should not (#213, §3).

``02-oracle-privileges.md`` §3 lists what the tool must **not** be granted, and
says why the list is worth checking rather than assuming: over-granting is what
happens when somebody is debugging a permissions problem at 17:00 on a Friday,
and the tool should notice rather than quietly benefit from it.

**This reports; it does not enforce.** #173 is the refusal, §4 is the guardrail
set, and neither is here. P5 is now decided — ``doctor`` **warns** and does not
fail — for the reason the leaning gave: failing would block somebody mid-incident
over a condition they did not create and cannot fix from this side.

## It is self-inspection, and that is what makes it possible

The obvious implementation reads ``DBA_SYS_PRIVS`` for this grantee, and it does
not work: an account holding exactly §2's grants gets ``ORA-00942`` from it,
measured on 26ai in #178. A correctly installed tool would report nothing at all,
which is the same failure #178 found for ``DBA_ROLE_PRIVS`` and #195 for a
capability probe — the answer that looks like good news and means "I could not
look".

So the audit asks about *itself*, from views that need no grant:

======================= =========================================================
``SESSION_PRIVS``       every system privilege in force **including the ones held
                        through a role**, which is the set that matters for "what
                        can this account actually do"
``USER_SYS_PRIVS``      the same account's *direct* grants, with ``COMMON`` — the
                        column ``SESSION_PRIVS`` does not have
``DBA_ROLE_PRIVS``      granted roles, traversed. In §2's grant set since #207,
                        and the one view here that can be refused
======================= =========================================================

**Roles are read granted rather than enabled**, which is deliberate and is why
``SESSION_ROLES`` — free of any grant — is not used. It shows what is *enabled*
in this session, and a non-default ``DBA`` grant is enabled by one
``SET ROLE``. For a guardrail that would be splitting hairs; for an audit whose
question is "what could this account become", a privilege one statement away is
held.

## What cannot be audited, and says so

``EXECUTE ON DBMS_LOCK`` is on §3's list and is **not visible from here**: it is
an object privilege, and the three views above carry system privileges and roles.
Reported as :data:`UNAUDITABLE` rather than omitted, because a list that quietly
dropped one of its rows would read as a clean audit. The same applies to a view
that raises: "I looked and found nothing" and "I could not look" are answers a
report must never merge.

``SYSDBA`` and ``SYSOPER`` were the other two, and since #341 they are answered
wherever the estate lets them be. They live in ``V$PWFILE_USERS``, which §2 makes
an **optional** grant (#296, §2) rather than one it never gives — so the question
is asked, and the rows join :data:`UNAUDITABLE` only where the answer came back
absent. That was the merge this module exists to refuse, arrived at from the
other side: on an estate that had taken the grant, the report said *I could not
look* about something it could have read.
"""

from __future__ import annotations

from typing import Any

from sopuli.driver.oracle.capabilities import read
from sopuli.driver.oracle.errors import from_error
from sopuli.driver.protocol import PrivilegeAudit

#: The one scope §2 grants ``V_$PDBS`` in, from
#: :data:`~sopuli.driver.protocol.SCOPE_TYPES`' closed vocabulary. Named here
#: rather than compared inline, because a string that never matches produces a
#: report that is wrong and does not look it.
CDB_ROOT = "cdb_root"

#: §3's must-not-grant list, as **system privileges**. Spelled the way Oracle
#: spells them in ``SESSION_PRIVS``, which is upper case and space-separated.
FORBIDDEN_PRIVILEGES = (
    "SELECT ANY DICTIONARY",
    "ALTER PROFILE",
    "CREATE USER",
    "DROP USER",
    "ALTER SYSTEM",
    "BECOME USER",
)

#: The same list's ``GRANT ANY *`` row, which is a family rather than a name --
#: ``GRANT ANY PRIVILEGE``, ``GRANT ANY ROLE``, ``GRANT ANY OBJECT PRIVILEGE``.
#: Matched by prefix so a release that adds a fourth is caught by the rule rather
#: than by somebody remembering to extend a list.
FORBIDDEN_PREFIX = "GRANT ANY"

#: §3's must-not-grant list, as **roles**. Held through another role counts,
#: which is what the traversal is for.
FORBIDDEN_ROLES = ("DBA", "PDB_DBA", "CDB_DBA")

#: On §3's list and not visible from any read here, on any estate. Reported as
#: unaudited rather than dropped, because a list missing one of its rows reads as
#: a clean audit.
#:
#: ``EXECUTE ON DBMS_LOCK`` is an **object** privilege, and the three views above
#: carry system privileges and roles. Auditing it means ``USER_TAB_PRIVS`` for
#: the direct grant and ``ROLE_TAB_PRIVS`` for the role-derived one, and the
#: second does not compose with the nested-role traversal the way the system
#: privileges do -- which is a design question rather than a query, so the row is
#: named as unaudited here rather than half-answered.
#:
#: It was three rows until #341. ``SYSDBA`` and ``SYSOPER`` left because their
#: view became askable (:data:`PASSWORD_FILE_PRIVILEGES`); this one has no view
#: to ask, which is why "make the audit complete" is not what that change did.
UNAUDITABLE = ("EXECUTE ON DBMS_LOCK",)

#: §3's remaining two rows, which live in ``V$PWFILE_USERS`` -- **askable on the
#: estates that took §2's optional grant, and unaudited on the rest** (#341).
#:
#: In this order, because :data:`PWFILE_QUERY` answers them in it. The two are
#: kept apart rather than collapsed into one "in the password file" answer for
#: the reason the view itself gives: it carries a column each, so reporting
#: ``SYSOPER`` on the strength of a ``SYSDBA`` row would be inventing a finding
#: the server did not make. Measured on 26ai 23.26.2.0.0 with the grants issued
#: and revoked one at a time -- all four combinations read back as themselves.
#:
#: Distinct from guardrail 3, which asks the same view about a *target account*
#: and only whether it is a member at all
#: (:func:`~sopuli.driver.oracle.accounts.password_file_member`). This asks about
#: the session's own user, and §3 lists the two privileges separately.
PASSWORD_FILE_PRIVILEGES = ("SYSDBA", "SYSOPER")

#: What the two columns say when the privilege is held. Oracle's own spelling,
#: and a string rather than a flag -- ``VARCHAR2(5)``, ``TRUE``/``FALSE``,
#: measured rather than assumed.
PWFILE_HELD = "TRUE"

#: :data:`PASSWORD_FILE_PRIVILEGES`, asked of the session's own user.
#:
#: **Aggregated rather than selected**, and that is the whole of why it is a
#: separate query text from
#: :data:`~sopuli.driver.oracle.accounts.PWFILE_QUERY`'s ``count(*)``. An
#: unaggregated ``select`` over a non-member returns **no row at all**, and
#: :func:`~sopuli.driver.oracle.capabilities.read` answers ``None`` for a
#: refused view -- so the two would arrive here as the same value, which is the
#: merge this module exists to refuse. A ``count`` per column is one row always,
#: never null, and zero means *asked and not held*.
#:
#: ``user`` rather than a bind, because the grantee **is** the session -- the
#: same reason :data:`SELF_ROLES_QUERY` gives.
#:
#: Counting over the rows rather than reading one is also what makes a PDB-local
#: grant visible: an account granted ``SYSDBA`` inside a PDB appears with its own
#: ``CON_ID`` (§2), so a session that can see more than one container sees more
#: than one row, and holding the privilege in any of them is holding it.
PWFILE_QUERY = (
    "select "
    f"count(case when sysdba = '{PWFILE_HELD}' then 1 end), "
    f"count(case when sysoper = '{PWFILE_HELD}' then 1 end) "
    "from v$pwfile_users where username = user"
)

#: What a site can do about :data:`PASSWORD_FILE_PRIVILEGES` going unaudited.
#:
#: Here rather than on :class:`~sopuli.driver.protocol.PrivilegeAudit`, for the
#: reason :data:`~sopuli.diagnostics.GUARDRAIL_REMEDIES` gives about the same
#: grant: the audit's shape is product-neutral and a ``GRANT`` statement is a
#: fact about Oracle. Carried at all because since #296 the reason these two rows
#: go unaudited is "you may enable this" rather than "this cannot be known", and
#: only one of those has a next action.
PASSWORD_FILE_REMEDY = (
    "SYSDBA and SYSOPER need SELECT on V$PWFILE_USERS, which "
    "02-oracle-privileges.md §2 leaves optional: "
    "GRANT SELECT ON SYS.V_$PWFILE_USERS to the service account to audit them"
)

#: §2's system privileges: what the tool needs to exist and to work.
#:
#: Read from ``SESSION_PRIVS`` like everything else, so a grant arriving through
#: a role counts. §2 grants them directly and a site may not have.
REQUIRED_PRIVILEGES = ("CREATE SESSION", "ALTER USER")

#: §2's dictionary grants, **asked by reading the view rather than by reading a
#: grant table** (#225).
#:
#: The alternative was ``USER_TAB_PRIVS`` plus ``ROLE_TAB_PRIVS``, and #225 filed
#: the composition of those two as the design question this had to answer. It
#: does not have to: probing dissolves it. Three reasons, in ascending order of
#: how much they would have cost.
#:
#: * **A role-derived grant needs no special handling**, because a view you can
#:   read is a view you can read however the grant arrived. That *is* the
#:   composition question, and it stops existing.
#: * **A grant row is not access.** ``USER_TAB_PRIVS`` can carry a row for a view
#:   that has since been dropped, or that a later release renamed -- and the
#:   answer a caller wants is "will my next query work", which only the query
#:   answers.
#: * **The mechanism is already here and already measured.**
#:   :func:`~sopuli.driver.oracle.capabilities.read` treats ``ORA-00942``,
#:   ``ORA-01031`` and ``ORA-41900`` as "no", each of which was measured rather
#:   than predicted -- ``ORA-41900`` in particular, which the same ungranted
#:   object returns to a privileged asker where an unprivileged one gets
#:   ``ORA-00942``. A second implementation of that rule is a second thing to get
#:   wrong.
#:
#: Spelled as the grant rather than as the view, because the point of a missing
#: entry is that somebody has to go and issue it.
REQUIRED_READS = {
    "SELECT ON DBA_USERS": "select count(*) from dba_users where rownum = 1",
    "SELECT ON DBA_PROFILES": "select count(*) from dba_profiles where rownum = 1",
    "SELECT ON DBA_ROLE_PRIVS": "select count(*) from dba_role_privs where rownum = 1",
    "SELECT ON V_$DATABASE": "select count(*) from v$database where rownum = 1",
    "SELECT ON V_$INSTANCE": "select count(*) from v$instance where rownum = 1",
}

#: §2 grants these, and **no pre-flight requires them** (#531). ``DBA_ROLES`` is
#: read only to resolve a ``role:`` predicate in `account list`, which is gated on
#: the ``role_lookup`` capability instead. Kept out of :data:`REQUIRED_READS`
#: because `creds apply` and `rotate` refuse on a missing required read, and an
#: estate installed before #531 must keep rotating without a grant only a UC-2
#: listing uses.
PREDICATE_READS = {"SELECT ON DBA_ROLES": "select count(*) from dba_roles where rownum = 1"}

#: §2 grants this one **in the root only**, so its absence in a PDB is the
#: documented install and not a finding. Kept apart from :data:`REQUIRED_READS`
#: rather than filtered out of it at the call site, because "not required here"
#: and "required and missing" are the two answers this report exists to separate.
ROOT_ONLY_READS = {"SELECT ON V_$PDBS": "select count(*) from v$pdbs where rownum = 1"}

#: Every system privilege in force, role-derived included. Granted to PUBLIC, so
#: this is the one query here that cannot be refused.
SESSION_PRIVS_QUERY = "select privilege from session_privs"

#: The same account's direct grants, and whether each is common. ``USER_*`` views
#: answer for the session's own user and need no grant.
USER_SYS_PRIVS_QUERY = "select privilege, common from user_sys_privs"

#: The role traversal, scoped to this session rather than to a named grantee.
#:
#: :data:`~sopuli.driver.oracle.accounts.ROLES_QUERY` is the same ``CONNECT BY``
#: over ``DBA_ROLE_PRIVS`` and takes a ``:name``, because guardrail 4 asks about
#: an account that is not this one. Here the grantee **is** the session, and
#: ``USER`` is a SQL function -- so this asks in one round trip what a bind would
#: have taken two, which is worth a second query text for a command that is
#: already three reads per target.
SELF_ROLES_QUERY = (
    "select granted_role from dba_role_privs "
    "start with grantee = user "
    "connect by nocycle prior granted_role = grantee"
)


def classify(
    session_privileges: frozenset[str],
    roles: frozenset[str],
    common: frozenset[str],
    *,
    readable: frozenset[str] = frozenset(),
    expected_reads: tuple[str, ...] = (),
    unreadable: tuple[str, ...] = (),
    password_file: tuple[str, ...] | None = None,
) -> PrivilegeAudit:
    """§2's and §3's lists against what was found. Pure, and the whole judgement.

    Separate from the queries because ``04-testing.md`` §4 wants the layer that
    *decides* testable without a database, and both "which privileges are too
    many" and "which are too few" are decisions. Everything above it is three
    ``SELECT``s and a probe per documented grant.

    ``expected_reads`` is passed in rather than taken from :data:`REQUIRED_READS`
    because §2 grants ``V_$PDBS`` **in the root only**, so what is required
    depends on where the session is standing -- and a report that called a PDB
    half-installed for not holding a grant §2 never gives it there would be
    wrong in the direction that costs the most trust.

    ``unreadable`` is threaded through rather than raised: a view that could not
    be read makes the audit partial, and a partial audit is a finding to report
    rather than a reason to abandon a ``doctor`` run with twenty targets left.

    ``password_file`` is three-valued in the shape the answer actually has
    (#341): which of :data:`PASSWORD_FILE_PRIVILEGES` came back held, or ``None``
    where the optional grant was not taken and nobody could look. The empty tuple
    is therefore a *reading* -- asked, holds neither -- and is the case a
    two-valued parameter would have merged with the third.

    **An absent answer makes the two rows unaudited and does not make the audit
    partial.** ``unreadable`` says the report cannot be trusted at face value;
    §2 leaves this grant optional, so the estate that cannot answer is the
    documented install and not a damaged one. Putting it there would print "this
    audit is partial" on every correct install, which is how a caveat stops being
    read.
    """
    found = sorted(
        {privilege for privilege in session_privileges if _forbidden(privilege)}
        | {role for role in roles if role in FORBIDDEN_ROLES}
        # §3's own rows, and the audit's first finding that is neither a system
        # privilege nor a role. They belong here rather than in a section of
        # their own because `over_granted` is the must-not-grant list's answer
        # and these are two of its rows -- a reader looking for what this account
        # holds and should not must not have to know where each row came from.
        | set(password_file or ())
    )
    required = (*REQUIRED_PRIVILEGES, *expected_reads)
    have = session_privileges | readable
    unaudited = list(UNAUDITABLE)
    remedies: list[str] = []
    if password_file is None:
        unaudited.extend(PASSWORD_FILE_PRIVILEGES)
        remedies.append(PASSWORD_FILE_REMEDY)
    if unreadable:
        # A refused `DBA_ROLE_PRIVS` takes the role rows with it. Naming them
        # keeps `over_granted` honest: without this, an account holding `DBA`
        # through a role nobody could read would report as holding nothing.
        unaudited.extend(FORBIDDEN_ROLES)
    return PrivilegeAudit(
        over_granted=tuple(found),
        held=tuple(sorted(name for name in required if name in have)),
        missing=tuple(sorted(name for name in required if name not in have)),
        roles=tuple(sorted(roles)),
        common=tuple(sorted(common)),
        unaudited=tuple(sorted(set(unaudited))),
        unreadable=tuple(sorted(set(unreadable))),
        remedies=tuple(remedies),
    )


def audit(cursor: Any, *, scope_type: str = "") -> PrivilegeAudit:
    """Run the reads, probe each documented grant, and classify what comes back.

    Three ``SELECT``s, one probe per grant §2 documents, and one for the password
    file. More round trips than a grant-table read would be, and the trade is
    stated in :data:`REQUIRED_READS`: what a caller wants to know is whether its
    next query will work, and only the query answers that.

    Only the role read can fail *softly* -- `doctor` exists to be run when things
    are wrong, so a view this account cannot read is one more thing to report
    rather than the end of the survey. ``SESSION_PRIVS`` and ``USER_SYS_PRIVS``
    are left to raise, because a session that cannot read views granted to PUBLIC
    has something wrong with it this module should not be papering over. The
    probes never raise for an absent grant at all: that is
    :data:`~sopuli.driver.oracle.capabilities.ABSENT_CODES`, and it is the answer
    rather than a failure.

    ``scope_type`` decides whether ``V_$PDBS`` is expected, since §2 grants it in
    the root only. Defaulted to ``""`` rather than to a scope, so a caller that
    does not know says so instead of asserting the commonest case -- the report
    then omits the row rather than inventing a finding about it.

    The password-file probe is one more of the same kind, added by #341: §2's
    optional grant makes ``V$PWFILE_USERS`` readable on the estates that took it,
    and :data:`~sopuli.driver.oracle.capabilities.ABSENT_CODES` makes its absence
    an enumerated negative rather than a failure. Run unconditionally, because
    the only way to find out which estate this is, is to ask.
    """
    session_privileges = frozenset(
        str(row[0]).upper() for row in _rows(cursor, SESSION_PRIVS_QUERY)
    )
    common = _common_privileges(cursor)

    try:
        roles = frozenset(str(row[0]).upper() for row in _rows(cursor, SELF_ROLES_QUERY))
        unreadable: tuple[str, ...] = ()
    except Exception:  # noqa: BLE001 -- a refused view is a finding, not a crash
        roles, unreadable = frozenset(), ("DBA_ROLE_PRIVS",)

    expected = dict(REQUIRED_READS)
    if scope_type == CDB_ROOT:
        expected.update(ROOT_ONLY_READS)
    readable = frozenset(
        grant for grant, statement in expected.items() if read(cursor, statement) is not None
    )

    return classify(
        session_privileges,
        roles,
        common,
        readable=readable,
        expected_reads=tuple(expected),
        unreadable=unreadable,
        password_file=_password_file(cursor),
    )


def _password_file(cursor: Any) -> tuple[str, ...] | None:
    """Which of :data:`PASSWORD_FILE_PRIVILEGES` the session's own user holds.

    ``None`` where the optional grant was not taken, which is
    :func:`~sopuli.driver.oracle.capabilities.read`'s answer for an enumerated
    negative and is a different fact from the empty tuple this returns for an
    account that was asked about and is in no row.

    The columns are read **by position against the constant**, in the order
    :data:`PWFILE_QUERY` selects them; ``strict`` is what turns a query edited
    out of step with the constant into a failure here rather than into a report
    that names the wrong privilege.
    """
    row = read(cursor, PWFILE_QUERY)
    if row is None:
        return None
    return tuple(
        privilege for privilege, held in zip(PASSWORD_FILE_PRIVILEGES, row, strict=True) if held
    )


def _forbidden(privilege: str) -> bool:
    """Whether one system privilege is on §3's list.

    The prefix test is the ``GRANT ANY *`` row, and it is a *prefix* rather than
    three names so that a release adding a fourth member of the family is caught
    by the rule. ``GRANT ANY`` is not itself a privilege, so nothing legitimate
    starts with it.
    """
    return privilege in FORBIDDEN_PRIVILEGES or privilege.startswith(FORBIDDEN_PREFIX)


def _rows(cursor: Any, query: str, parameters: dict[str, Any] | None = None) -> list[Any]:
    cursor.execute(query, parameters or {})
    return list(cursor.fetchall())


#: What 11.2 says when asked whether a privilege is *common*: there is no such
#: column, because there are no containers.
#:
#: One code, not :data:`~sopuli.driver.oracle.capabilities.ABSENT_CODES`. The
#: argument that list makes is that a code meaning something in one place must
#: not be allowed to mean anything anywhere else, and here only ``ORA-00904``
#: carries information. ``ORA-01031`` from this query would mean the read was
#: *refused*, which is not the same as "nothing is common" and must not be
#: reported as it -- and ``USER_SYS_PRIVS`` is granted to PUBLIC, so a refusal
#: would be a finding worth raising rather than swallowing.
NO_COMMON_COLUMN = "ORA-00904"


def _common_privileges(cursor: Any) -> frozenset[str]:
    """Which of this session's direct grants are *common*.

    Empty on a release with no such concept, and that is a reading rather than a
    shrug: a database with no containers has no common privileges, so "none are
    common" is the true answer. :func:`classify` then treats it exactly as it
    treats a PDB whose grants are all local.

    ``USER_SYS_PRIVS.COMMON`` arrived with multitenant in 12.1. On 11.2 the
    column does not exist and this query is ``ORA-00904`` -- measured on 11g XE
    11.2.0.2.0 (#382), where it took the whole of `doctor --check-privileges`
    down with it: the target reported ``-`` for scope, ``0`` capabilities and a
    bare ORA- code, **while still exiting 0**. The audit is three reads per
    target and this was the only one with no answer for a release that cannot
    take the question.
    """
    try:
        rows = _rows(cursor, USER_SYS_PRIVS_QUERY)
    except Exception as error:  # noqa: BLE001 -- classified on the next line
        if from_error(error).code != NO_COMMON_COLUMN:
            raise
        return frozenset()
    return frozenset(str(row[0]).upper() for row in rows if _yes(row[1]))


def _yes(value: Any) -> bool:
    """Oracle's ``YES``/``NO`` columns, which are strings and not booleans."""
    return str(value).strip().upper() == "YES"

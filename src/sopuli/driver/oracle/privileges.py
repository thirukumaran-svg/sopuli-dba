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

``SYSDBA`` and ``SYSOPER`` are on §3's list and are **not visible from here**:
they live in ``V$PWFILE_USERS``, which §2 does not grant, and an account that had
them would not be exercising them on this connection anyway. Reported as
:data:`UNAUDITABLE` rather than omitted, because a list that quietly dropped two
of its rows would read as a clean audit. The same applies to a view that raises:
"I looked and found nothing" and "I could not look" are answers a report must
never merge.
"""

from __future__ import annotations

from typing import Any

from sopuli.driver.oracle.capabilities import read
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

#: On §3's list and not visible from the three reads below. Reported as
#: unaudited rather than dropped, because a list missing some of its rows reads
#: as a clean audit.
#:
#: ``SYSDBA``/``SYSOPER`` live in ``V$PWFILE_USERS``, which §2 does not grant --
#: and an account that had them would not be exercising them on this connection
#: anyway.
#:
#: ``EXECUTE ON DBMS_LOCK`` is an **object** privilege, and these three views
#: carry system privileges and roles. Auditing it means ``USER_TAB_PRIVS`` for
#: the direct grant and ``ROLE_TAB_PRIVS`` for the role-derived one, and the
#: second does not compose with the nested-role traversal the way the system
#: privileges do -- which is a design question rather than a query, so the row is
#: named as unaudited here rather than half-answered.
UNAUDITABLE = ("SYSDBA", "SYSOPER", "EXECUTE ON DBMS_LOCK")

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
    """
    found = sorted(
        {privilege for privilege in session_privileges if _forbidden(privilege)}
        | {role for role in roles if role in FORBIDDEN_ROLES}
    )
    required = (*REQUIRED_PRIVILEGES, *expected_reads)
    have = session_privileges | readable
    unaudited = list(UNAUDITABLE)
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
    )


def audit(cursor: Any, *, scope_type: str = "") -> PrivilegeAudit:
    """Run the reads, probe each documented grant, and classify what comes back.

    Three ``SELECT``s plus one probe per grant §2 documents. More round trips
    than a grant-table read would be, and the trade is stated in
    :data:`REQUIRED_READS`: what a caller wants to know is whether its next query
    will work, and only the query answers that.

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
    """
    session_privileges = frozenset(
        str(row[0]).upper() for row in _rows(cursor, SESSION_PRIVS_QUERY)
    )
    common = frozenset(
        str(row[0]).upper() for row in _rows(cursor, USER_SYS_PRIVS_QUERY) if _yes(row[1])
    )

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


def _yes(value: Any) -> bool:
    """Oracle's ``YES``/``NO`` columns, which are strings and not booleans."""
    return str(value).strip().upper() == "YES"

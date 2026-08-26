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

from dataclasses import dataclass
from typing import Any

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


@dataclass(frozen=True)
class PrivilegeAudit:
    """What §3's list found, and what it could not look at.

    Sorted throughout, because this reaches a report a human compares between
    runs and dictionary order is nobody's contract.
    """

    #: §3 entries this account holds. What ``scope.over_granted`` carries.
    over_granted: tuple[str, ...] = ()
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


def classify(
    session_privileges: frozenset[str],
    roles: frozenset[str],
    common: frozenset[str],
    *,
    unreadable: tuple[str, ...] = (),
) -> PrivilegeAudit:
    """§3's list against what was found. Pure, and the whole of the judgement.

    Separate from the queries because ``04-testing.md`` §4 wants the layer that
    *decides* testable without a database, and which privileges are too many is a
    decision. Everything above it is three ``SELECT``s.

    ``unreadable`` is threaded through rather than raised: a view that could not
    be read makes the audit partial, and a partial audit is a finding to report
    rather than a reason to abandon a ``doctor`` run that has twenty more targets
    to survey.
    """
    found = sorted(
        {privilege for privilege in session_privileges if _forbidden(privilege)}
        | {role for role in roles if role in FORBIDDEN_ROLES}
    )
    unaudited = list(UNAUDITABLE)
    if unreadable:
        # A refused `DBA_ROLE_PRIVS` takes the role rows with it. Naming them
        # keeps `over_granted` honest: without this, an account holding `DBA`
        # through a role nobody could read would report as holding nothing.
        unaudited.extend(FORBIDDEN_ROLES)
    return PrivilegeAudit(
        over_granted=tuple(found),
        roles=tuple(sorted(roles)),
        common=tuple(sorted(common)),
        unaudited=tuple(sorted(set(unaudited))),
        unreadable=tuple(sorted(set(unreadable))),
    )


def audit(cursor: Any) -> PrivilegeAudit:
    """Run the three reads and classify what comes back.

    Only the role read can fail, and it fails *softly*: `doctor` exists to be run
    when things are wrong, so a view this account cannot read is one more thing
    to report rather than the end of the survey. The privilege reads are on views
    granted to PUBLIC and are left to raise, because a session that cannot read
    ``SESSION_PRIVS`` has something wrong with it that this module should not be
    papering over.
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

    return classify(session_privileges, roles, common, unreadable=unreadable)


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

"""Reading an account's state from the dictionary (#178).

`DBA_USERS`, `DBA_PROFILES` and `DBA_ROLE_PRIVS` — all reads, no `SYS.USER$`,
which #86 made an optional grant and which nothing here touches. Three consumers
want this object: UC-1 §5's pre-flight step 3, the client-side guardrails (#173),
and `creds status`'s inventory.

Four things here were measured on 26ai Free 23.26.2.0.0 rather than reasoned
about, and each would have been got wrong by reasoning.

**Rollover state is in ``ACCOUNT_STATUS``, and nowhere else.** No column in any
`DBA_*` view mentions rollover — the dictionary was searched, not assumed. What
the status does instead is compound, joined with ``&``:

    OPEN                              EXPIRED & IN ROLLOVER
    OPEN & IN ROLLOVER                EXPIRED & LOCKED & IN ROLLOVER
    LOCKED & IN ROLLOVER              LOCKED(TIMED)

So the three flags are read as **tokens within** the status rather than by
comparing it to a value. A rotation opens the window and the status says so
immediately; equality against ``"OPEN"`` would have reported a healthy account as
neither open nor anything else.

**An unset profile resource reads as the string ``DEFAULT``**, meaning *inherit
from the ``DEFAULT`` profile*, not *this is the default value*. A profile created
with one limit set reports ``DEFAULT`` for the other eight, so a caller reading
``FAILED_LOGIN_ATTEMPTS`` off a custom profile gets a word where it wanted a
number. :data:`PROFILE_QUERY` resolves it in the database, and what reaches
:class:`~sopuli.driver.protocol.UserState` is always the **effective** limit.

**``PASSWORD_VERIFY_FUNCTION`` reads as ``FROM ROOT`` inside a PDB**, and the
numeric limits do not. #178 asked whether that phenomenon — already seen for the
verify function — applied to the other resources, because it decides whether
#181's profile check can trust the dictionary at all. Measured on a common
profile with `CONTAINER=ALL`, read from `CDB$ROOT` and from `FREEPDB1`:

    resource                    root                             pdb
    FAILED_LOGIN_ATTEMPTS       4                                4
    PASSWORD_ROLLOVER_TIME      1                                1
    PASSWORD_VERIFY_FUNCTION    ORA12C_STRONG_VERIFY_FUNCTION    FROM ROOT

So the limits this module reads are trustworthy from a PDB and the verify
function is not. Nothing here reads the verify function; #181 is where that
matters, and it now knows it must read it in the root or treat it as unreadable.

**``PASSWORD_CHANGE_DATE`` does track a rotation** on this release — two
rotations two minutes apart moved it — which is worth stating because #87 is open
about *where the value comes from on 11.2*, not about whether it means anything
here. Where the column is absent the answer is ``None`` and never a substitute:
nothing gates on it (Q9 put `--max-age-days` on the vault's ``rotated_at`` and
only that), so guessing would be all cost.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Any

from sopuli.driver.oracle.capabilities import Cursor, read
from sopuli.driver.oracle.rollover import is_enabled, window_end
from sopuli.driver.protocol import DriverError, UserState

#: The account, as the database spells it. ``PASSWORD_CHANGE_DATE`` is selected
#: unconditionally: it exists from 12.1, and on 11.2 the query fails with
#: ``ORA-00904`` — which :func:`~sopuli.driver.oracle.capabilities.read` already
#: treats as an enumerated negative, so the fallback is a query rather than a
#: guess. See :data:`USER_QUERY_NO_CHANGE_DATE`.
#:
#: **Bound, never interpolated.** The account name is not a secret, so invariant
#: 14 does not forbid binding it — and it is exactly the kind of value that must
#: not be pasted into SQL text.
USER_QUERY = (
    "select username, account_status, profile, password_versions, "
    "oracle_maintained, password_change_date "
    "from dba_users where username = :name"
)

#: 11.2's version of the same question. ``ORACLE_MAINTAINED`` arrived in 12.1 too,
#: so both columns go together and one fallback covers both -- and the ``None``
#: this produces for ``vendor_maintained`` is what makes the guardrails fall back
#: to their literal deny list (``02-oracle-privileges.md`` §4 check 5) rather than
#: reading a missing column as "no".
USER_QUERY_NO_CHANGE_DATE = (
    "select username, account_status, profile, password_versions "
    "from dba_users where username = :name"
)

#: The profile's password limits, with ``DEFAULT`` already resolved.
#:
#: The join is the whole point: ``DBA_PROFILES`` reports the string ``DEFAULT``
#: for every resource the profile does not set, and a caller that took it at face
#: value would read the word ``DEFAULT`` as a lockout threshold.
PROFILE_QUERY = (
    "select p.resource_name, "
    "case when p.limit = 'DEFAULT' then d.limit else p.limit end "
    "from dba_profiles p "
    "join dba_profiles d on d.profile = 'DEFAULT' and d.resource_name = p.resource_name "
    "where p.profile = :profile and p.resource_type = 'PASSWORD'"
)

#: Every role the account holds, **including the ones it holds through another
#: role**. Guardrail 4 refuses ``DBA``, ``PDB_DBA``, ``CDB_DBA`` and
#: ``AUDIT_ADMIN``, and a flat read of ``DBA_ROLE_PRIVS`` sees only direct
#: grants -- so an account granted a site role that itself holds ``DBA`` would
#: have been reported as holding nothing the guardrail cares about, and passed.
#:
#: Measured on 26ai, which is how the hole was confirmed rather than argued:
#: ``ACME_APP_ADMIN`` granted ``DBA``, then granted to an account, reads as
#: ``ACME_APP_ADMIN`` alone flat and as ``ACME_APP_ADMIN, DBA, …`` traversed.
#:
#: ``NOCYCLE`` is **defensive rather than load-bearing**, and the distinction is
#: worth writing down because the obvious justification for it is false. Oracle
#: refuses to build a cycle in the first place: ``grant a to b`` followed by
#: ``grant b to a`` fails with ``ORA-01934: circular role grant detected``, so
#: the role graph is acyclic by construction and ``CONNECT BY`` cannot loop on
#: it. It is kept because it costs nothing and the alternative failure --
#: ``ORA-01436`` at a site whose role graph reached a shape this reasoning did
#: not anticipate -- would be a tool that cannot describe any account there.
ROLES_QUERY = (
    "select granted_role from dba_role_privs "
    "start with grantee = :name "
    "connect by nocycle prior granted_role = grantee"
)

#: Just the spelling, for the one caller that needs the name and nothing else.
#:
#: Separate from :data:`USER_QUERY` rather than reusing :func:`describe`, because
#: the two questions have different costs and different failure modes: a
#: mutation needs to know how the database spells the account, and does not need
#: the roles read -- whose absent grant is a refusal (:class:`RolesUnreadableError`)
#: that would then be raised by `set_password` for a reason unrelated to setting
#: a password.
#:
#: It exists at all because an Oracle quoted identifier is **case-sensitive**.
#: `"acme_orders_user"` and `"ACME_ORDERS_USER"` are different accounts to the
#: server, so a statement built from the config's spelling would get
#: `ORA-01918: user does not exist` against a database that plainly has it.
NAME_QUERY = "select username from dba_users where username = :name"

#: A profile's own spelling, and by the same token whether it exists at all
#: (#301).
#:
#: :data:`NAME_QUERY`'s argument, one object along: an Oracle quoted identifier is
#: case-sensitive, so ``PROFILE "acme_app_prof"`` and ``PROFILE
#: "ACME_APP_PROF"`` are different requests and only one of them names a profile
#: the database has. A config file writes whichever it likes, so the spelling
#: that reaches the statement is read back out of the dictionary first.
#:
#: ``DISTINCT`` because ``DBA_PROFILES`` holds one row per resource, so a profile
#: is a dozen rows and the question here is about the name.
PROFILE_NAME_QUERY = "select distinct profile from dba_profiles where profile = :profile"

#: Consecutive failed logins, behind the optional ``SELECT ON SYS.USER$`` grant
#: (#86). Gated on the ``offline_verify`` capability, and the *only* thing that
#: capability gates in this build.
#:
#: Read immediately before an attempt and never cached: it changes with every
#: failed login, including ones this tool did not make, so a value carried from
#: earlier in the run would be a lockout guard computing on a number that has
#: since moved.
LCOUNT_QUERY = "select lcount from sys.user$ where name = :name"

FAILED_LOGIN_ATTEMPTS = "FAILED_LOGIN_ATTEMPTS"
PASSWORD_ROLLOVER_TIME = "PASSWORD_ROLLOVER_TIME"
PASSWORD_REUSE_MAX = "PASSWORD_REUSE_MAX"
PASSWORD_REUSE_TIME = "PASSWORD_REUSE_TIME"

#: The token the status carries during a gradual rollover window.
IN_ROLLOVER = "IN ROLLOVER"
LOCKED = "LOCKED"
EXPIRED = "EXPIRED"


class RolesUnreadableError(DriverError):
    """``DBA_ROLE_PRIVS`` could not be read, so guardrail 4 has no input.

    **Raised rather than reported as "no roles"**, which is the entire reason
    this class exists. Guardrail 4 refuses an account holding ``DBA``,
    ``PDB_DBA``, ``CDB_DBA`` or ``AUDIT_ADMIN``; an empty set means *this account
    holds none of them* and reads as a pass. A missing grant would therefore turn
    a safety check into a silent success, which is the same failure shape as a
    capability probe that could not be answered reporting absent (#195) — and the
    reason `02-oracle-privileges.md` §2 now grants the view.
    """

    category = "authorization"


def describe(cursor: Cursor, account: str) -> UserState | None:
    """One account as the database describes it, or ``None`` if there is none.

    ``None`` is UC-1's ``ACCOUNT_MISSING`` and is **not** an error: the tool does
    not create accounts (Q8 — provisioning is its own use case), so a missing one
    is a state to report rather than a failure to recover from.

    Three queries, and roles are one of them rather than something a caller opts
    into. #178 raised the alternative — role membership is consulted only before
    a mutation, and `creds status` reads this object for every account in an
    estate, so a lazy read would save two thirds of the work on the command that
    does the most of it. It is refused because of what it would cost when it went
    wrong: a caller that forgot to ask for roles would get a
    :class:`~sopuli.driver.protocol.UserState` whose empty ``roles`` reads exactly
    like an account holding none, and guardrail 4 would pass. A safety check must
    not depend on a caller remembering to enable its input.
    """
    state = login_state(cursor, account)
    if state is None:
        return None
    return replace(state, roles=_roles(cursor, state.name))


def login_state(cursor: Cursor, account: str) -> UserState | None:
    """The account without its roles, for the callers that must not need them.

    `creds check` is the caller. #86 decided it needs no site-specific grant to
    run, and reading roles is a *guardrail* input consulted before a mutation --
    so making a read-only command depend on `DBA_ROLE_PRIVS` would widen what
    `check` requires for a reason that has nothing to do with checking.

    :func:`describe` is this plus roles, and it is what a mutation uses.
    """
    row = _user_row(cursor, account)
    if row is None:
        return None

    name = str(row[0])
    status = str(row[1] or "")
    profile = str(row[2]) if row[2] else None
    limits = _limits(cursor, profile) if profile else {}

    return UserState(
        name=name,
        status=status,
        locked=LOCKED in status,
        expired=EXPIRED in status,
        profile=profile,
        password_versions=_versions(row[3]),
        password_changed_at=_changed_at(row),
        failed_login_limit=limits.get(FAILED_LOGIN_ATTEMPTS),
        # Carried rather than discarded, because one query already resolved
        # them: #181 reads the rollover time at plan time, and UC-1 §4's bounded
        # regeneration exists because of the reuse policy. Reading them again
        # from a second, uncoordinated query would be a second chance to
        # disagree about the same profile.
        rollover_time=limits.get(PASSWORD_ROLLOVER_TIME),
        password_reuse_max=limits.get(PASSWORD_REUSE_MAX),
        password_reuse_time=limits.get(PASSWORD_REUSE_TIME),
        rollover_active=IN_ROLLOVER in status,
        # Whether the profile grants a window at all, as opposed to whether one
        # is open. Parsed here because `rollover_time` is Oracle's own spelling
        # and `sopuli.strategy` (#262), which reads this, is above the driver.
        rollover_enabled=is_enabled(limits.get(PASSWORD_ROLLOVER_TIME)),
        # **Derived, and only while a window is open** (#181). #178 left this
        # null on the grounds that computing it would present an inference as a
        # reading, which was the right instinct and the wrong call: no
        # dictionary column exposes the end -- searched, not assumed -- so the
        # choice is between Oracle's own documented arithmetic over two measured
        # values and telling an operator nothing about their deadline.
        # `rollover.window_end` carries the reasoning and the limits.
        rollover_ends_at=(
            window_end(_changed_at(row), limits.get(PASSWORD_ROLLOVER_TIME))
            if IN_ROLLOVER in status
            else None
        ),
        vendor_maintained=_maintained(row),
    )


def resolve_profile(cursor: Cursor, profile: str) -> str | None:
    """The profile as the dictionary spells it, or ``None`` if there is no such one.

    Two questions with one query, which is deliberate rather than thrifty: *does
    this profile exist here* and *how is it spelled* have the same answer, and a
    caller that asked them separately could act on a name between the two reads.

    Upper-cased on the way in for :func:`_user_row`'s reason -- Oracle stores an
    unquoted identifier upper-cased, and a config file writing ``acme_app_prof``
    means the profile the database calls ``ACME_APP_PROF``. A site that created a
    genuinely lower-case profile with quotes gets ``None`` here and a refusal
    naming what it looked for, which is the honest outcome: guessing at a second
    spelling would be the tool deciding which of two profiles the file meant.
    """
    row = read(cursor, PROFILE_NAME_QUERY, profile=profile.upper())
    return None if row is None else str(row[0])


def _user_row(cursor: Cursor, account: str) -> Any:
    """``DBA_USERS``, falling back to 11.2's shorter column list.

    The fallback is driven by the server refusing the column rather than by a
    version test, which is invariant 3 in the small: `ORA-00904` *is* the answer
    to "does this release have `PASSWORD_CHANGE_DATE`", and it needs no capability
    of its own because the query itself is the probe.
    """
    row = read(cursor, USER_QUERY, name=account.upper())
    if row is not None:
        return row
    return read(cursor, USER_QUERY_NO_CHANGE_DATE, name=account.upper())


def _limits(cursor: Cursor, profile: str) -> dict[str, str]:
    cursor.execute(PROFILE_QUERY, {"profile": profile})
    return {str(name): str(limit) for name, limit in cursor.fetchall() if limit is not None}


def _roles(cursor: Cursor, name: str) -> frozenset[str]:
    try:
        cursor.execute(ROLES_QUERY, {"name": name})
        return frozenset(str(role[0]).upper() for role in cursor.fetchall())
    except Exception as error:  # noqa: BLE001 -- re-raised as a diagnosable one
        raise RolesUnreadableError(
            f'could not read the roles held by "{name}"',
            hint=(
                "guardrail 4 refuses an account holding DBA, PDB_DBA, CDB_DBA or "
                "AUDIT_ADMIN, and cannot tell an account with none from a view it "
                "cannot read: GRANT SELECT ON SYS.DBA_ROLE_PRIVS to the service account"
            ),
        ) from error


def _versions(value: Any) -> tuple[str, ...]:
    """``PASSWORD_VERSIONS`` is a space-separated list -- ``"11G 12C"``."""
    return tuple(str(value).split()) if value else ()


def _changed_at(row: Any) -> datetime | None:
    """``PASSWORD_CHANGE_DATE``, where the release has it.

    The 11.2 row is shorter, so its absence is a length rather than a null, and
    both mean the same thing to a caller: no date, and nothing substituted for
    one (#87).
    """
    if len(row) < 6:
        return None
    return row[5] if isinstance(row[5], datetime) else None


def _maintained(row: Any) -> bool | None:
    """``ORACLE_MAINTAINED``, which is ``None`` rather than ``False`` on 11.2.

    The distinction is load-bearing: guardrail check 5's literal deny list is
    consulted **only** where check 2 could not answer, so a missing column
    reading as "not vendor-maintained" would quietly switch off the fallback that
    exists for exactly that release.
    """
    if len(row) < 5:
        return None
    return str(row[4]).upper() == "Y" if row[4] is not None else None


def resolve_name(cursor: Cursor, account: str) -> str | None:
    """How the database spells ``account``, or ``None`` if it has no such user.

    ``02-oracle-privileges.md`` §4: the name that reaches a statement is the one
    read back from the dictionary, never the raw string from a config file.
    """
    row = read(cursor, NAME_QUERY, name=account.upper())
    return str(row[0]) if row else None


def failed_logins(cursor: Cursor, name: str) -> int | None:
    """``SYS.USER$.LCOUNT``, or ``None`` where the grant was never made.

    Measured on 26ai: a failed login takes it 0 -> 1 -> 2, and a **successful**
    login puts it back to 0. That last part is UC-1 §7 mitigation 3 and it needs
    no code -- the database does it -- which is what makes the happy path
    self-cleaning.
    """
    # Bound **unchanged**. ``name`` is already the spelling `DBA_USERS` gave
    # back, and ``SYS.USER$.NAME`` preserves it -- so upper-casing here would
    # miss a quoted lower-case account, return no row, and be indistinguishable
    # from "the grant was never made". That failure is silent and it is the
    # dangerous direction: an absent counter reads as an unavailable guard, and
    # the login goes ahead spending lockout budget the guard was there to
    # protect.
    row = read(cursor, LCOUNT_QUERY, name=name)
    return int(row[0]) if row and row[0] is not None else None

"""Reading an account's state from the dictionary (#178).

`DBA_USERS`, `DBA_PROFILES`, `DBA_ROLE_PRIVS` and -- opportunistically --
`V$PWFILE_USERS`: all reads, no `SYS.USER$`, which #86 made an optional grant and
which nothing here touches. Three consumers want this object: UC-1 §5's pre-flight
step 3, the client-side guardrails (#173), and `creds status`'s inventory.

The last of the four is the one that is **expected to fail on a correct install**
(#296). `V$PWFILE_USERS` is not in §2's grant set and #296 decided not to put it
there, so :func:`password_file_member` answers `None` where nobody could look --
and the guardrail turns that into a caveat rather than into a pass.

Five things here were measured on 26ai Free 23.26.2.0.0 rather than reasoned
about, and each would have been got wrong by reasoning. The fifth arrived later
than the others, with #309.

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
function is not. #181 is where that mattered first; :func:`password_constraints`
reads it now, and reports the not-knowing rather than an absence.

**``FROM ROOT`` is narrower than that reading left it looking**, measured
2026-09-04 for #317. Three profiles read from inside ``FREEPDB1``:

    profile             created                      PASSWORD_VERIFY_FUNCTION
    ACME_COMMON_PROF    in the root, CONTAINER=ALL   FROM ROOT
    ACME_LOCAL_PROF     in the PDB                   ORA12C_STRONG_VERIFY_FUNCTION
    DEFAULT             Oracle's own                 NULL

So the unreadable case is a **user-created common profile seen from a PDB**, and
not "a PDB" -- a local profile answers with its function's name, and even
``DEFAULT``, which is common, answers ``NULL`` rather than deferring. An
implementation that treated every PDB as unknowable would refuse to report the
ordinary case, and one that treated the reading as absent would tell an operator
that nothing will judge their password when something will.

Two values that a caller must not mistake for data came out of the same run:
``PASSWORD_VERIFY_FUNCTION`` is the string ``NULL`` where a profile names none
(:data:`NO_FUNCTION`), and ``PASSWORD_REUSE_MAX``/``PASSWORD_REUSE_TIME`` are
``UNLIMITED`` on the ``DEFAULT`` profile -- vendor words in a column a reader
expects numbers in, resolved through :data:`PROFILE_QUERY`'s ``DEFAULT`` join
like every other resource.

**``PASSWORD_CHANGE_DATE`` does track a rotation** on this release — two
rotations two minutes apart moved it. On 18c and 11.2 the column does not exist,
and on 19c it does (19.24.0.0.0, measured 2026-09-17) — though the server's
``ORA-00904`` is what decides, not a version — and
#386 decided the value comes from ``SYS.USER$.PTIME`` there, behind the optional
grant, rather than going missing. That is a second source for one field, and it
is admitted only because it is **the same clock** rather than an estimate of it —
measured 2026-09-08 on 26ai, 21c, 18c and 11.2: ``PTIME`` equals
``PASSWORD_CHANGE_DATE`` to the second where both exist, moves on ``ALTER USER
... IDENTIFIED BY`` where only it exists, and ``CTIME`` beside it does not move.
See :data:`PTIME_QUERY` for the rules that keep the two from disagreeing, and
:func:`_password_changed` for what is reported when neither answers. 12.1 and
12.2 would take the fallback too and are unmeasured (unverified:
pw-changed-source).

**``EXPIRED(GRACE)`` is a value of ``ACCOUNT_STATUS``, and it contains the token
``EXPIRED``.** Measured 2026-09-02, later than the four above, because #309 turned
on it. The grace state compounds like the rest, and the hard expiry was measured
alongside it as a control — it is the fourth value below:

    EXPIRED(GRACE)                    EXPIRED(GRACE) & LOCKED
    EXPIRED(GRACE) & LOCKED(TIMED)    EXPIRED

So the token reading below makes :attr:`~sopuli.driver.protocol.UserState.expired`
``True`` for an account whose password still works — which is #309 and is **not
fixed here**, because what `check` should report instead is an open decision.
What the measurement settles is that the fix is safe to make: every locked form
carries ``LOCKED`` and therefore parses ``locked=True``, and every caller tests
``locked`` before ``expired``. Excluding ``(GRACE)`` from ``expired`` cannot make
a locked account read as open.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Any

from sopuli.constraints import AccountConstraints
from sopuli.driver.oracle.capabilities import Cursor, read
from sopuli.driver.oracle.rollover import is_enabled, window_end
from sopuli.driver.protocol import DriverError, UserState

#: The account, as the database spells it. ``PASSWORD_CHANGE_DATE`` is selected
#: unconditionally: it exists on 21c and 26ai, and on 18c and 11.2 the query fails with
#: ``ORA-00904`` — which :func:`~sopuli.driver.oracle.capabilities.read` already
#: treats as an enumerated negative, so the fallback is a query rather than a
#: guess. See :data:`USER_QUERY_NO_CHANGE_DATE`, and :data:`PTIME_QUERY` for where
#: the date comes from instead.
#:
#: **Bound, never interpolated.** The account name is not a secret, so invariant
#: 14 does not forbid binding it — and it is exactly the kind of value that must
#: not be pasted into SQL text.
#: ``EXPIRY_DATE`` is **appended** rather than slotted in beside
#: ``ACCOUNT_STATUS`` where it reads most naturally, and that is deliberate:
#: :func:`_maintained` and :func:`_password_changed` read fixed positions, so a column
#: inserted in the middle would move two fields that nothing would fail loudly
#: about -- ``ORACLE_MAINTAINED`` would come back as a date and read as *not
#: vendor-maintained*, which is guardrail check 5's input (#309).
USER_QUERY = (
    "select username, account_status, profile, password_versions, "
    "oracle_maintained, password_change_date, expiry_date "
    "from dba_users where username = :name"
)

#: The same seven columns for a release that has no ``PASSWORD_CHANGE_DATE``.
#:
#: **The two columns do not travel together, and assuming they did cost 18c its
#: guardrails.** This constant used to select five columns and say
#: "``ORACLE_MAINTAINED`` arrived in 12.1 too, so both columns go together and
#: one fallback covers both". Measured 2026-09-08 (#381):
#:
#: ===============  =====================  ======================
#: release          ``ORACLE_MAINTAINED``  ``PASSWORD_CHANGE_DATE``
#: ===============  =====================  ======================
#: 26ai 23.26       present                present
#: 21c 21.3         present                present
#: **18c 18.4**     **present**            **ORA-00904**
#: 11g 11.2         ORA-00904              ORA-00904
#: ===============  =====================  ======================
#:
#: So on 18c the full query failed, the short one answered, and
#: ``vendor_maintained`` came back ``None`` from a column sitting right there and
#: readable -- which switched guardrail check 2 off and dropped it to check 5's
#: literal deny list, on a release that can answer properly.
#:
#: Both queries now project the **same seven columns in the same order**, with
#: ``NULL`` where the release has nothing to put. That removes the length test
#: :func:`_maintained` used to make, and with it the fragility the comment on
#: :data:`USER_QUERY` worries about: there is one shape, so a column can no
#: longer move under a fixed index.
USER_QUERY_NO_CHANGE_DATE = (
    "select username, account_status, profile, password_versions, "
    "oracle_maintained, cast(null as date), expiry_date "
    "from dba_users where username = :name"
)

#: 11.2, which has neither column. Same seven, two of them ``NULL``.
#:
#: ``ORACLE_MAINTAINED`` being absent here is what the ``None`` in
#: :func:`_maintained` is *for*: the guardrails fall back to their literal deny
#: list (``02-oracle-privileges.md`` §4 check 5) rather than reading a missing
#: column as "no". On 18c that fallback was firing by accident; here it is the
#: intended behaviour.
USER_QUERY_LEGACY = (
    "select username, account_status, profile, password_versions, "
    "cast(null as varchar2(1)), cast(null as date), expiry_date "
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

#: Whether the account is in the password file -- guardrail 3's only input, and
#: the one dictionary read here that a correctly installed service account is
#: **expected to be refused** (#296).
#:
#: ``V$PWFILE_USERS`` is not in ``02-oracle-privileges.md`` §2's grant set, and
#: that is a decision rather than an omission: the accounts check 3 catches are
#: largely caught by checks 2 and 4 as well, and widening what every service
#: account needs for the remainder is a poor trade. So the grant is **optional**,
#: the way ``SELECT ON SYS.USER$`` is (#86), and the answer here is three-valued:
#: a member, not a member, or *nobody looked*.
#:
#: ``count(*)`` rather than selecting the row, because the question is membership
#: and a count answers it in one column that is never null. What distinguishes
#: "not a member" from "could not look" is therefore whether there is a row at
#: all, which is exactly the distinction :func:`~sopuli.driver.oracle.capabilities.read`
#: draws: an enumerated negative (``ORA-00942`` for the ungranted view,
#: ``ORA-41900`` where the asker is privileged enough to be told it exists) is
#: ``None``, and anything else raises.
PWFILE_QUERY = "select count(*) from v$pwfile_users where username = :name"

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

#: A role's own spelling, and whether it exists -- :data:`PROFILE_NAME_QUERY`'s
#: argument again, for the other kind of predicate (`account list`, #490).
#:
#: It exists because UC-2 §2 draws an asymmetry that cannot be drawn without it:
#: a `role:` predicate naming a role that **does not exist** is a misspelling and
#: is refused, while one that exists and matches **no accounts** is a true answer
#: about today's estate and is not an error. Both produce an empty account list,
#: so the empty list cannot tell them apart and something has to ask.
ROLE_NAME_QUERY = "select role from dba_roles where role = :role"

#: Every account carrying a profile -- a `profile:` predicate resolved the other
#: way round (H1, #449; the listing verb is #490).
#:
#: ``DBA_USERS`` rather than ``SYS.USER$``, so this needs no grant beyond the one
#: :data:`USER_QUERY` already has. The order is the dictionary's own so that two
#: runs list an estate identically -- an unordered listing that shuffles between
#: runs is one nobody can diff.
ACCOUNTS_WITH_PROFILE_QUERY = (
    "select username from dba_users where profile = :profile order by username"
)

#: Every account holding a role, **including through another role**.
#:
#: :data:`ROLES_QUERY` walked **up** from an account to the roles it holds; this
#: walks **down** from a role to the accounts that hold it, and it has to, or the
#: two disagree. ``admits()`` decides membership from the traversed set, so a
#: flat ``where granted_role = :role`` here would list *fewer* accounts than a
#: reset would accept -- an operator reviewing what a predicate admits would be
#: shown a shorter estate than the one the verb acts on, which is the one wrong
#: answer a listing verb must not give.
#:
#: The ``join`` is what keeps roles out of the answer. A role granted to another
#: role is a grantee like any other, so the traversal returns both accounts and
#: roles, and only the ones ``DBA_USERS`` knows are accounts. Filtering here
#: rather than in Python because the dictionary is what decides what an account
#: is.
#:
#: ``NOCYCLE`` for :data:`ROLES_QUERY`'s reason, and the same caveat: Oracle
#: refuses a circular grant (``ORA-01934``), so it is defensive rather than
#: load-bearing.
ACCOUNTS_WITH_ROLE_QUERY = (
    "select distinct u.username from dba_users u "
    "join (select grantee from dba_role_privs "
    "start with granted_role = :role "
    "connect by nocycle prior grantee = granted_role) g "
    "on g.grantee = u.username "
    "order by u.username"
)

#: Consecutive failed logins, behind the optional ``SELECT ON SYS.USER$`` grant
#: (#86). Gated on the ``offline_verify`` capability, which gates this and
#: :data:`PTIME_QUERY` in this build and nothing else.
#:
#: Read immediately before an attempt and never cached: it changes with every
#: failed login, including ones this tool did not make, so a value carried from
#: earlier in the run would be a lockout guard computing on a number that has
#: since moved.
LCOUNT_QUERY = "select lcount from sys.user$ where name = :name"

#: When the password was last set, on a release with no
#: ``DBA_USERS.PASSWORD_CHANGE_DATE`` (#386). Behind the same optional grant as
#: :data:`LCOUNT_QUERY`, and gated on the same capability.
#:
#: **A second source for one field, and three rules keep it from becoming a
#: second opinion** -- which is the failure ``limits.py`` is the standing warning
#: about (#383), where a version-dependent fact was derived from the wrong place
#: and reported confidently:
#:
#: * **It is never consulted where the column exists.** The column answering is
#:   what selects the source, so no release ever has two, and a ``NULL`` in the
#:   column is reported as a ``NULL`` rather than retried here.
#: * **It is not a version test.** ``ORA-00904`` on the column is what sends the
#:   read here, exactly as it narrows :func:`_user_row`.
#: * **It was measured as the same clock, not an approximation of it.** Equal to
#:   ``PASSWORD_CHANGE_DATE`` to the second on 26ai and 21c; moved by ``ALTER
#:   USER ... IDENTIFIED BY`` on 18c and 11.2, with ``CTIME`` unmoved beside it
#:   (2026-09-08). ``tests/driver/test_oracle_accounts.py`` pins the equality on
#:   every release that has both, so a future one where they part fails there.
#:
#: Bound unchanged, for :func:`failed_logins`' reason: ``name`` is already the
#: spelling ``DBA_USERS`` gave back.
PTIME_QUERY = "select ptime from sys.user$ where name = :name"

FAILED_LOGIN_ATTEMPTS = "FAILED_LOGIN_ATTEMPTS"
PASSWORD_ROLLOVER_TIME = "PASSWORD_ROLLOVER_TIME"
PASSWORD_REUSE_MAX = "PASSWORD_REUSE_MAX"
PASSWORD_REUSE_TIME = "PASSWORD_REUSE_TIME"
PASSWORD_VERIFY_FUNCTION = "PASSWORD_VERIFY_FUNCTION"

#: What ``DBA_PROFILES`` reports for a profile that names no verify function --
#: **the four characters, not a SQL null**. Measured on 26ai: the ``DEFAULT``
#: profile carries it, in the root and in a PDB alike. A caller that read the
#: column without knowing this would report every default-profile account as
#: having a verify function called ``NULL``.
NO_FUNCTION = "NULL"

#: What a **common** profile's verify function reads as from inside a PDB, and
#: the reason :attr:`~sopuli.constraints.AccountConstraints.verify_function_known`
#: exists. Measured on 26ai, alongside the two readings that bound it (see the
#: module docstring): it is narrower than #178 left it looking.
FROM_ROOT = "FROM ROOT"

#: The token the status carries during a gradual rollover window.
IN_ROLLOVER = "IN ROLLOVER"
LOCKED = "LOCKED"
EXPIRED = "EXPIRED"

#: What a password in its grace period reads as -- and the reason :data:`EXPIRED`
#: is not enough on its own. The whole string is matched rather than the bare word
#: ``GRACE``, because the point is that this **contains** :data:`EXPIRED`: an
#: account here still authenticates, and a substring test for the shorter token
#: reported it as a hard expiry (#309). Measured, with every compound form, in the
#: module docstring above.
EXPIRED_GRACE = "EXPIRED(GRACE)"


#: What a **failed-login limit** produced, which is not the same event as a lock
#: somebody chose. ``PASSWORD_LOCK_TIME`` clears this one on its own.
LOCKED_TIMED = "LOCKED(TIMED)"

#: How Oracle joins the components of a compound ``ACCOUNT_STATUS``.
STATUS_SEPARATOR = " & "


def deliberately_locked(status: str) -> bool:
    """Whether ``status`` says a **person** locked this account (#463).

    Not the same question as :attr:`~sopuli.driver.protocol.UserState.locked`,
    which is true of every locked form, and the difference is what UC-2 turns on:
    a reset clears ``LOCKED(TIMED)`` by default and refuses a deliberate
    ``LOCKED`` (H4, #455), and `account suspend` is the verb that sets the second
    one.

    **Parsed by component rather than by substring**, and that is the whole
    reason this is a function. ``LOCKED(TIMED)`` *contains* ``LOCKED``, so
    ``LOCKED in status`` is true of a timed lock, and equality against the whole
    string is wrong the other way -- the status compounds, so a deliberately
    locked account can read ``EXPIRED & LOCKED``, ``LOCKED & IN ROLLOVER`` or
    ``EXPIRED & LOCKED & IN ROLLOVER``. Splitting on the separator answers both,
    which is #309's lesson applied before it had a chance to cost anything: that
    bug was ``EXPIRED(GRACE)`` read as a hard expiry by a substring test.
    """
    return LOCKED in {part.strip().upper() for part in status.split(STATUS_SEPARATOR)}


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


def describe(cursor: Cursor, account: str, *, user_dollar: bool = False) -> UserState | None:
    """One account as the database describes it, or ``None`` if there is none.

    ``None`` is UC-1's ``ACCOUNT_MISSING`` and is **not** an error: the tool does
    not create accounts (Q8 — provisioning is its own use case), so a missing one
    is a state to report rather than a failure to recover from.

    Four queries, and roles are one of them rather than something a caller opts
    into. #178 raised the alternative — role membership is consulted only before
    a mutation, and `creds status` reads this object for every account in an
    estate, so a lazy read would save two thirds of the work on the command that
    does the most of it. It is refused because of what it would cost when it went
    wrong: a caller that forgot to ask for roles would get a
    :class:`~sopuli.driver.protocol.UserState` whose empty ``roles`` reads exactly
    like an account holding none, and guardrail 4 would pass. A safety check must
    not depend on a caller remembering to enable its input.

    **The fourth is the password file** (#296), and it is here rather than in
    :func:`login_state` for the same reason roles are: it is a guardrail input, so
    it belongs on the object a mutation reads and not on the one `creds check`
    reads. Unlike roles it is allowed to fail — the grant is optional — and the
    ``None`` it then carries is the whole of what #296 fixed: guardrail 3 has been
    reading "nobody looked" as "not a member" since it was written, because
    nothing looked.

    ``user_dollar`` is whether the session may read ``SYS.USER$``, and it is the
    caller's to say because it is a capability the session probed once
    (:data:`PTIME_QUERY`).
    """
    state = login_state(cursor, account, user_dollar=user_dollar)
    if state is None:
        return None
    return replace(
        state,
        roles=_roles(cursor, state.name),
        password_file_member=password_file_member(cursor, state.name),
    )


def login_state(cursor: Cursor, account: str, *, user_dollar: bool = False) -> UserState | None:
    """The account without its roles, for the callers that must not need them.

    `creds check` is the caller. #86 decided it needs no site-specific grant to
    run, and reading roles is a *guardrail* input consulted before a mutation --
    so making a read-only command depend on `DBA_ROLE_PRIVS` would widen what
    `check` requires for a reason that has nothing to do with checking.

    :func:`describe` is this plus roles, and it is what a mutation uses.

    ``user_dollar`` defaults to ``False`` so that a caller which never asked
    whether the grant exists issues no ``SYS.USER$`` read: a refused one is an
    audit record on a site that audits failed selects, per account.
    """
    found = _user_row(cursor, account)
    if found is None:
        return None
    query, row = found

    name = str(row[0])
    status = str(row[1] or "")
    profile = str(row[2]) if row[2] else None
    limits = _limits(cursor, profile) if profile else {}
    changed_at, changed_unknown = _password_changed(
        cursor, name, row, has_column=query == USER_QUERY, user_dollar=user_dollar
    )

    return UserState(
        name=name,
        status=status,
        locked=LOCKED in status,
        # `EXPIRED(GRACE)` carries the token `EXPIRED`, so the two are read
        # together or the grace period comes out as a hard expiry. Every caller
        # tests `locked` before either, and every locked form carries `LOCKED`,
        # so an account that is both stays locked to all of them (#309).
        expired=EXPIRED in status and EXPIRED_GRACE not in status,
        in_grace=EXPIRED_GRACE in status,
        profile=profile,
        password_versions=_versions(row[3]),
        password_changed_at=changed_at,
        password_changed_unknown=changed_unknown,
        password_expires_at=_expires_at(row),
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
            window_end(changed_at, limits.get(PASSWORD_ROLLOVER_TIME))
            if IN_ROLLOVER in status
            else None
        ),
        vendor_maintained=_maintained(row),
    )


def password_constraints(cursor: Cursor, account: str) -> AccountConstraints | None:
    """What this target says about a password for one account (#317, UC-1 §4 step 2).

    ``None`` where the target has no such account, which is
    :func:`login_state`'s answer and means the same thing here: `creds generate`
    stages into a vault and does not need the account to exist yet, so this is a
    thing not reported rather than a failure.

    **Deliberately not a :class:`~sopuli.driver.protocol.UserState`.** The
    obvious implementation is to call :func:`login_state` and let the caller take
    the four fields it wants, and it is refused for the reason :func:`describe`
    gives for reading roles eagerly: a ``UserState`` with no ``roles`` reads
    exactly like an account holding none, and guardrail 4 would pass on it. A
    reporting path must not be able to hand that object to a safety check, so it
    returns a type that has no such field to misread.

    Two queries, both on the baseline grant set (``02-oracle-privileges.md`` §2),
    so reading them costs `creds generate` no privilege it did not already need
    -- and no third: the roles :func:`describe` reads are a guardrail input and a
    staging command has nothing to guard.
    """
    found = _user_row(cursor, account)
    if found is None:
        return None
    _, row = found

    profile = str(row[2]) if row[2] else None
    limits = _limits(cursor, profile) if profile else {}
    verify = limits.get(PASSWORD_VERIFY_FUNCTION)
    return AccountConstraints(
        account=str(row[0]),
        profile=profile,
        # `NULL` is the profile naming none, `FROM ROOT` is the dictionary
        # declining to say, and both are the string in the column rather than a
        # SQL null. They land on the same `verify_function` and are told apart by
        # `verify_function_known`, which is the distinction #317 asks for: not
        # knowing is not a finding, and it is not an absence either.
        verify_function=None if verify in (None, NO_FUNCTION, FROM_ROOT) else verify,
        verify_function_known=verify is not None and verify != FROM_ROOT,
        reuse_max=limits.get(PASSWORD_REUSE_MAX),
        reuse_time=limits.get(PASSWORD_REUSE_TIME),
        versions=_versions(row[3]),
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


def resolve_role(cursor: Cursor, role: str) -> str | None:
    """The role as the dictionary spells it, or ``None`` if there is no such one.

    :func:`resolve_profile`'s argument for the other predicate, and it exists for
    a reason that is not symmetry: UC-2 §2 refuses a predicate naming a role that
    does not exist and accepts one that matches nothing, and both of those look
    like an empty list from :func:`accounts_with_role`. Only asking separately
    tells them apart.

    Upper-cased on the way in, as :func:`resolve_profile` is, and the same
    consequence follows for a genuinely lower-case quoted role: ``None``, and a
    refusal naming what was looked for, rather than the tool guessing at a second
    spelling.
    """
    row = read(cursor, ROLE_NAME_QUERY, role=role.upper())
    return None if row is None else str(row[0])


def accounts_with_profile(cursor: Cursor, profile: str) -> tuple[str, ...]:
    """Every account carrying ``profile``, in the dictionary's own order.

    The **resolution** half of a `profile:` predicate: :func:`sopuli.personal.admits`
    answers "does this rule admit that account" for a verb acting on one name,
    and this answers "which accounts does this rule admit" for the verb that
    lists them.

    An empty tuple is a true answer about today's estate and not an error (UC-2
    §2). Whether the profile *exists* is :func:`resolve_profile`'s question, and
    the caller asks it first -- a misspelling and an empty profile are the same
    empty tuple here.
    """
    return _names(cursor, ACCOUNTS_WITH_PROFILE_QUERY, profile=profile.upper())


def accounts_with_role(cursor: Cursor, role: str) -> tuple[str, ...]:
    """Every account holding ``role``, directly or through another role.

    **Transitive, and that is a correctness requirement rather than a courtesy.**
    :func:`sopuli.personal.admits` decides membership against the set
    :data:`ROLES_QUERY` traverses, so an enumeration that read only direct grants
    would show an operator fewer accounts than a reset would accept. A listing
    verb that under-reports what a predicate admits is worse than no listing
    verb, because it would be read as the whole set.

    Empty is a true answer; existence is :func:`resolve_role`'s question.
    """
    return _names(cursor, ACCOUNTS_WITH_ROLE_QUERY, role=role.upper())


def _names(cursor: Cursor, statement: str, **binds: Any) -> tuple[str, ...]:
    """Every first column of a multi-row read, as the dictionary spelled it.

    Not :func:`~sopuli.driver.oracle.capabilities.read`, which fetches one row.
    The :data:`ABSENT_CODES` rule does not apply either: these two views are the
    ones ``02-oracle-privileges.md`` §2 already grants, so a failure to read one
    is a broken installation rather than an absent capability, and turning it
    into an empty list would report an estate with nobody in it.
    """
    cursor.execute(statement, binds or None)
    return tuple(str(row[0]) for row in cursor.fetchall())


def _user_row(cursor: Cursor, account: str) -> tuple[str, Any] | None:
    """``DBA_USERS``, narrowing one column at a time until the server answers.

    Returns the query that answered beside its row, because *which* one answered
    is itself a reading: :func:`_password_changed` needs to know whether the
    release has ``PASSWORD_CHANGE_DATE`` at all, and a ``NULL`` in position 5
    cannot say -- the narrower shapes select one there too.

    Each fallback is driven by the server refusing a column rather than by a
    version test, which is invariant 3 in the small: `ORA-00904` *is* the answer
    to "does this release have `PASSWORD_CHANGE_DATE`", and it needs no capability
    of its own because the query itself is the probe.

    **Three shapes, not two, and they are tried in that order for a reason.**
    18c has `ORACLE_MAINTAINED` and not `PASSWORD_CHANGE_DATE`; 11.2 has neither
    (measured -- see :data:`USER_QUERY_NO_CHANGE_DATE`). Dropping both together
    made 18c answer as 11.2 and gave up a guardrail input it could have read.
    Every shape projects the same seven columns, so a caller reads fixed
    positions whichever one answered.
    """
    for query in (USER_QUERY, USER_QUERY_NO_CHANGE_DATE, USER_QUERY_LEGACY):
        row = read(cursor, query, name=account.upper())
        if row is not None:
            return query, row
    return None


def _limits(cursor: Cursor, profile: str) -> dict[str, str]:
    cursor.execute(PROFILE_QUERY, {"profile": profile})
    return {str(name): str(limit) for name, limit in cursor.fetchall() if limit is not None}


def password_file_member(cursor: Cursor, name: str) -> bool | None:
    """Whether ``name`` is in the password file, or ``None`` if nobody could look.

    Guardrail 3's input (``02-oracle-privileges.md`` §4), and the **only**
    guardrail input that is allowed to come back unknown. The contrast with
    :func:`_roles` is the decision worth stating, because the two look like the
    same situation and are not:

    * ``DBA_ROLE_PRIVS`` is granted by §2, so a service account that cannot read
      it is **misinstalled**, and an empty role set would read as a pass on a
      check whose whole job is to refuse. That one raises
      (:class:`RolesUnreadableError`).
    * ``V$PWFILE_USERS`` is **not** granted by §2, and #296 decided not to add it:
      the accounts check 3 catches are largely caught by checks 2 and 4 as well,
      and widening the baseline install for the remainder is a poor trade. So the
      ordinary, correct estate cannot answer this, and raising would refuse every
      mutation on every correctly installed target.

    What must not happen either way is the merge :mod:`sopuli.driver.oracle.privileges`
    refuses one layer up — "I looked and found nothing" reported as the same thing
    as "I could not look". So the answer is three-valued, the guardrail turns the
    third into a caveat rather than a pass, and the command reports it.

    ``name`` is bound **unchanged**, for the reason :func:`failed_logins` gives:
    it is already the spelling ``DBA_USERS`` gave back, ``V$PWFILE_USERS.USERNAME``
    carries the same one, and upper-casing here would miss a quoted lower-case
    account and return a zero count -- which reads as *not a member* and is the
    one wrong answer that is silent.
    """
    row = read(cursor, PWFILE_QUERY, name=name)
    return None if row is None else bool(row[0])


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


def _password_changed(
    cursor: Cursor, name: str, row: Any, *, has_column: bool, user_dollar: bool
) -> tuple[datetime | None, str | None]:
    """When the password was last set, and -- where that is unknown -- why (#386).

    **Exactly one source per release**, chosen by what the server answered and
    never by a version: ``DBA_USERS.PASSWORD_CHANGE_DATE`` where the column
    exists, and ``SYS.USER$.PTIME`` where it does not and the session may read
    it. A column that exists and is empty is reported as empty rather than
    retried against ``PTIME``, because that is the one path by which a release
    would acquire two sources and the chance to disagree between them.

    The second value is the reason, and it is ``None`` exactly when the first is
    not. It exists because ``-`` in `creds status` and an omitted
    ``password_age_days`` in the run document used to mean both *this release
    has no such column* and *something could not be read*, and only one of
    those is worth anybody's time. It is a sentence in the driver's words, which
    keeps Oracle's vocabulary out of :class:`~sopuli.driver.protocol.UserState`
    while still naming the grant that fixes it.
    """
    if has_column:
        if isinstance(row[5], datetime):
            return row[5], None
        return None, "DBA_USERS.PASSWORD_CHANGE_DATE is empty for this account"
    if not user_dollar:
        return None, (
            "this release has no DBA_USERS.PASSWORD_CHANGE_DATE; GRANT SELECT ON "
            "SYS.USER$ to the service account to read the same date from SYS.USER$.PTIME"
        )
    found = read(cursor, PTIME_QUERY, name=name)
    if found is None:
        return None, (
            "this release has no DBA_USERS.PASSWORD_CHANGE_DATE, and SYS.USER$ could "
            "not be read for this account"
        )
    if isinstance(found[0], datetime):
        return found[0], None
    return None, (
        "this release has no DBA_USERS.PASSWORD_CHANGE_DATE, and SYS.USER$.PTIME is "
        "empty for this account"
    )


def _expires_at(row: Any) -> datetime | None:
    """``EXPIRY_DATE``, which every query selects and every one selects **last**.

    ``row[-1]`` rather than a number because it read the same in every shape back
    when the shapes had different lengths. Since #381 they do not -- all three
    project the same seven columns -- so this is now simply the last of seven and
    `row[6]` would be as correct. Left as written: it is the one index that
    cannot go wrong if a fourth shape is ever added with a column dropped from
    the middle, and that is the mistake this module has already made once.

    ``None`` where the profile expires nothing. A caller must not read that as
    *not expiring soon* and then as *expiring never*: it is the same answer either
    way here, and #309's warning simply has nothing to say about such an account.
    """
    return row[-1] if isinstance(row[-1], datetime) else None


def _maintained(row: Any) -> bool | None:
    """``ORACLE_MAINTAINED``, which is ``None`` rather than ``False`` on 11.2.

    The distinction is load-bearing: guardrail check 5's literal deny list is
    consulted **only** where check 2 could not answer, so a missing column
    reading as "not vendor-maintained" would quietly switch off the fallback that
    exists for exactly that release.

    **No length test any more** (#381). Every query in :func:`_user_row` projects
    the same seven columns, selecting ``NULL`` where the release has nothing to
    put, so this reads one fixed position on every version and a ``None`` here
    means the column said nothing rather than that the row was short. The old
    ``len(row) < 6`` test was correct for the two shapes that existed and was the
    thing that made 18c -- which *has* ``ORACLE_MAINTAINED`` -- report ``None``.
    """
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

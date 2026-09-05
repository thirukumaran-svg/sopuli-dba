"""The account the tool is actually meant to run as (#226). Tier 1.

Every other tier-1 test in this suite connects as `system`, which holds most of
`02-oracle-privileges.md` §3's must-not-grant list. That is convenient — #224's
over-grant test gets a genuinely over-granted account for free — and it means
**nothing has ever exercised the account §2 describes.**

Three things only this account can establish, and all three are load-bearing:

* **`--check-privileges` stays quiet on a correct install.** Tier 0 asserts the
  judgement against a hand-written set, which proves the classifier and nothing
  about what a real §2 install reports. A check that cries wolf on a healthy
  install is a check people learn to run with their eyes shut.
* **`DBA_SYS_PRIVS` is still unreadable under §2's grants.** #178 measured that on
  26ai and the whole audit is built on it: it is *why* the audit is
  self-inspection rather than a dictionary query. Nothing re-checked it, and a
  release that widened it would silently invalidate the reasoning — with a
  failure mode of a tool that reports nothing and looks healthy.
* **`DBA_ROLE_PRIVS` is still readable**, which is the control. Without it, a
  release that removed dictionary access from this account *entirely* would look
  exactly like the pass above. §8's P7 row makes the same argument for keeping
  its `ORA-00990` assertion after the question was answered.

The grants come from `sopuli/driver/oracle/privileges.py` rather than from a list
written here, so this account is by construction the one the tool asks for; that
those constants match `sql/oracle/00_install.sql` is `tests/test_install_sql.py`,
tier 0. The script itself is still not executed — it is SQL*Plus, not SQL.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from typing import Any

import pytest

from oracle_harness import Environment
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target
from sopuli.driver.oracle.privileges import (
    REQUIRED_PRIVILEGES,
    REQUIRED_READS,
    audit,
)
from sopuli.driver.protocol import Credential
from sopuli.secrets import Secret

ADMIN_PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")

#: **`SYS AS SYSDBA`, and not `SYSTEM`** -- which is §2's own instruction and was
#: measured before it was written: "every `GRANT SELECT ON SYS.…` above fails with
#: `ORA-01031: insufficient privileges` when the granting session is `SYSTEM`,
#: while the `CREATE USER` and the two system privileges succeed."
#:
#: The first draft of this module granted as `SYSTEM`, because that is what every
#: other tier-1 fixture connects as, and CI produced exactly that `ORA-01031`.
#: Worth recording rather than quietly fixing: the documented warning is real,
#: the failure it warns about is *partial* -- the account is created and can
#: rotate, and only the dictionary reads are missing -- and a fixture that had
#: swallowed the error would have built the half-granted account §2 describes as
#: the trap, then asserted the tool was happy with it.
ADMIN_USER = "sys"

CORRELATION_ID = "9f1c4e02-77ab-4d51-9c6e-3b8a5d2f0e14"

#: Fictional, per CLAUDE.md's provenance rule, and deliberately not `SOPULI_SVC`
#: -- the name the install script defaults to -- so that running the real script
#: against the same database later cannot collide with this.
ACCOUNT = "acme_svc_user"
ACCOUNT_PASSWORD = "Service-Account-9z"


def _run(session: Any, *statements: str) -> None:
    """Statements through a driver session."""
    _execute(session.connection, *statements)


def _execute(connection: Any, *statements: str) -> None:
    with connection.cursor() as cursor:
        for statement in statements:
            cursor.execute(statement)


def _container(connection: Any) -> str:
    with connection.cursor() as cursor:
        cursor.execute("select sys_context('userenv','con_name') from dual")
        return str(cursor.fetchone()[0])


def _grants() -> tuple[str, ...]:
    """§2's grant set as `GRANT` statements, derived rather than restated.

    The one transformation is the `SYS.` qualifier: a grant names the owner and
    the tool names the synonym it reads through. Writing the list out again here
    would make this fixture agree with `privileges.py` only until somebody edited
    one of them -- and the account would then be right about the wrong thing,
    which is the failure the whole module exists to catch.
    """
    return (
        *(f"grant {privilege} to {ACCOUNT}" for privilege in REQUIRED_PRIVILEGES),
        *(f"grant {grant.replace('ON ', 'ON SYS.')} to {ACCOUNT}" for grant in REQUIRED_READS),
    )


@pytest.fixture
def admin(live_oracle: Environment) -> Iterator[Any]:
    """A `SYS AS SYSDBA` connection, which is what can issue §2's grants.

    Raw `oracledb` rather than the tool's own driver, and that is not a shortcut:
    :meth:`OracleDriver.connect` has no `SYSDBA` mode and should not grow one.
    P2's bootstrap list is about the credential the *tool* authenticates with,
    and the tool has no operation that requires `SYSDBA` -- §3 puts it on the
    must-not-grant list. Installing the account is an operator's job that happens
    before the tool exists, so the fixture does it the way an operator does.
    """
    oracledb = pytest.importorskip("oracledb")
    session_module = pytest.importorskip("sopuli.driver.oracle.session")
    session_module.initialise(env=os.environ)

    connection = oracledb.connect(
        user=ADMIN_USER,
        password=ADMIN_PASSWORD,
        dsn=live_oracle.dsn,
        mode=oracledb.AUTH_MODE_SYSDBA,
    )
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture
def service_account(admin: Any, live_oracle: Environment) -> Iterator[Any]:
    """An account holding exactly §2's grants, connected **as itself**.

    Connected as itself is the whole point: `USER_SYS_PRIVS`, `SESSION_PRIVS` and
    the `ORA-00942` this module pins are all facts about the *session's own*
    user, and a test that asked them from `system` would be asking a different
    question and getting a reassuring answer.
    """
    session_module = pytest.importorskip("sopuli.driver.oracle.session")
    if _container(admin) == "CDB$ROOT":
        # A local account cannot be created in the root -- ORA-65096 -- and a
        # common one is the install script's COMMON mode, which grants
        # `CONTAINER=ALL` and adds `V_$PDBS`. That is a different account with a
        # different expected set, so it is a skip with a reason rather than a
        # prefix bolted on here: the two modes deserve separate coverage and
        # pretending one is the other would assert the wrong thing quietly.
        pytest.skip("this container answers as CDB$ROOT; a local service account needs a PDB")
    _drop(admin)
    # Everything from here to `yield` can fail and leave an account behind, and
    # on this module's first CI run it did: `CREATE USER` succeeded and the
    # grants raised `ORA-01031`, so a half-granted `acme_svc_user` outlived the
    # run. The `_drop` above means the *next* test still gets a clean account
    # rather than "user already exists" -- but a fixture whose recovery is "the
    # next one will tidy up" leaves the database dirty at the end of the session,
    # which on a developer's own instance is litter and on a shared one is worse.
    try:
        _execute(admin, f'create user {ACCOUNT} identified by "{ACCOUNT_PASSWORD}"', *_grants())

        driver = session_module.OracleDriver(env=os.environ, correlation_id=CORRELATION_ID)
        opened = driver.connect(
            ExpandedTarget(
                target=Target(
                    name="tier1-service",
                    type="oracle",
                    dsn=live_oracle.dsn,
                    admin=AdminCredential(username=ACCOUNT, auth=AdminAuth(method="env")),
                ),
                index=0,
            ),
            Credential(username=ACCOUNT, secret=Secret(ACCOUNT_PASSWORD)),
        )
    except Exception:
        # Dropped and re-raised, never swallowed: a setup failure here is the
        # finding -- a grant §2 documents that this release will not issue is
        # exactly what this module exists to notice.
        _drop(admin)
        raise

    try:
        yield opened
    finally:
        opened.close()
        _drop(admin)


def _drop(admin: Any) -> None:
    """Absent is the desired state, so "it was not there" is a success."""
    with contextlib.suppress(Exception):
        _execute(admin, f"drop user {ACCOUNT} cascade")


def _audit(session: Any) -> Any:
    with session.connection.cursor() as cursor:
        return audit(cursor, scope_type=session.scope().type)


# ------------------------------------------------------------- staying quiet ---


def test_a_correct_install_is_short_of_nothing(service_account: Any) -> None:
    """The assertion #213 asked for and could not make: `missing` is empty for an
    account granted exactly what §2 documents, measured rather than reasoned.

    This is where a wrong view name or a `V$` that should have been `V_$` shows
    up. Tier 0 cannot catch either, because it is handed the answer.
    """
    assert _audit(service_account).missing == ()


def test_a_correct_install_is_over_granted_nothing(service_account: Any) -> None:
    """The other half, and the one that decides whether anybody keeps the flag
    switched on. §2's grant set is the whole of what the tool needs, so a correct
    install has nothing on §3's list."""
    assert _audit(service_account).over_granted == ()


def test_a_correct_install_holds_every_documented_grant(service_account: Any) -> None:
    """`missing == ()` would also be true of an audit that checked nothing, so
    the positive form is asserted beside it."""
    held = set(_audit(service_account).held)

    assert set(REQUIRED_PRIVILEGES) <= held
    assert set(REQUIRED_READS) <= held


def test_the_audit_is_readable_and_says_so(service_account: Any) -> None:
    """`DBA_ROLE_PRIVS` is in the grant set, so the traversal succeeds and the
    audit is partial for no reason. An `unreadable` here would mean §2 and the
    audit had come apart."""
    assert _audit(service_account).unreadable == ()


# ---------------------------------------------- the measurements, re-measured ---


def test_dba_sys_privs_is_still_unreadable_under_the_documented_grants(
    service_account: Any,
) -> None:
    """#178's measurement, as a regression test on somebody else's product.

    The whole audit rests on this: if `DBA_SYS_PRIVS` were readable, the obvious
    implementation would work and the self-inspection design would be
    unnecessary. A release that widened it would not break anything visibly --
    the tool would keep working -- so nothing else would ever catch it.
    """
    with pytest.raises(Exception, match="ORA-00942") as raised:
        _run(service_account, "select count(*) from dba_sys_privs")

    # Asserted again on the value rather than only through `match`, because
    # `match` searches the *representation* and a driver that reworded its
    # exception could keep the code out of it. The code is the finding.
    assert "ORA-00942" in str(raised.value)


def test_dba_role_privs_is_still_readable_and_is_the_control(
    service_account: Any,
) -> None:
    """Without this, a release that removed dictionary access from this account
    entirely would look exactly like the test above passing.

    The same argument §8's P7 row makes for keeping its `ORA-00990` assertion
    after the question was settled: an assertion about a refusal needs a
    succeeding control beside it, or it stops measuring what it claims to.
    """
    _run(service_account, "select count(*) from dba_role_privs")


def test_the_self_inspection_views_need_no_grant(service_account: Any) -> None:
    """`SESSION_PRIVS` and `USER_SYS_PRIVS` are granted to PUBLIC, which is what
    makes the audit possible at all -- and is a fact about Oracle rather than
    about this install, so it is worth pinning where a release could change it."""
    _run(
        service_account,
        "select count(*) from session_privs",
        "select count(*) from user_sys_privs",
    )


# --------------------------------------------- the check that cannot look (#296) ---


def test_the_password_file_is_not_readable_under_the_documented_grants(
    service_account: Any,
) -> None:
    """§4 check 3's input, refused to the account §2 describes.

    Measured, and it is the measurement the whole of #296 turns on:
    `ORA-00942: table or view "SYS"."V_$PWFILE_USERS" does not exist`, from an
    account holding exactly the documented set. That code is in
    :data:`~sopuli.driver.oracle.capabilities.ABSENT_CODES`, so the driver reads
    it as an enumerated negative and answers `None` -- *nobody looked* -- rather
    than `False`, which would read as *not a member* and pass the guardrail.

    Asserted here rather than only in tier 0 because tier 0 is handed the
    exception. What only a server can say is that the correct install really is
    the one that cannot answer, which is why #296 made the check a caveat instead
    of a refusal.
    """
    with pytest.raises(Exception, match="ORA-00942") as raised:
        _run(service_account, "select count(*) from v$pwfile_users")

    assert "ORA-00942" in str(raised.value)


def test_an_account_is_still_described_with_the_password_file_unreadable(
    service_account: Any,
) -> None:
    """The consequence, end to end: `describe_user` succeeds and the field is
    `None`.

    The contrast with `DBA_ROLE_PRIVS` is the design. That one is granted, so an
    account that cannot read it is misinstalled and the driver refuses to
    describe anything (`RolesUnreadableError`); this one is deliberately not, so
    refusing would mean a correctly installed tool could mutate nothing anywhere.
    The account described here is the service account itself, which is the only
    one this fixture is sure exists.

    **Returning at all is the control**, and the first draft of this test got
    that wrong: it asserted `state.roles` was non-empty, on the assumption that
    an account reachable through `DBA_ROLE_PRIVS` must hold something. §2 grants
    privileges directly and no roles, so this account holds none and the
    assertion failed against a database that was behaving exactly as documented.
    What proves the roles view was read is that `describe_user` did not raise --
    an empty set and an unreadable view are precisely the two things
    `RolesUnreadableError` exists to keep apart.
    """
    state = service_account.describe_user(ACCOUNT)

    assert state is not None
    assert state.password_file_member is None
    assert state.roles == frozenset(), "§2 grants privileges directly and no roles"
    assert state.vendor_maintained is False, "the control: DBA_USERS was read"

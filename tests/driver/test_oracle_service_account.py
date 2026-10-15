"""The account the tool is actually meant to run as. Tier 1.

Every other tier-1 test in this suite connects as `system`, which holds most of
`02-oracle-privileges.md` §3's must-not-grant list. That is convenient — the
over-grant test gets a genuinely over-granted account for free — and it means
**nothing has ever exercised the account §2 describes.**

Three things only this account can establish, and all three are load-bearing:

* **`--check-privileges` stays quiet on a correct install.** Tier 0 asserts the
  judgement against a hand-written set, which proves the classifier and nothing
  about what a real §2 install reports. A check that cries wolf on a healthy
  install is a check people learn to run with their eyes shut.
* **`DBA_SYS_PRIVS` is still unreadable under §2's grants.** That was measured
  on 26ai Free 23.26.2.0.0 and the whole audit is built on it: it is *why* the
  audit is self-inspection rather than a dictionary query. A release that
  widened it would silently invalidate the reasoning — with a failure mode of a
  tool that reports nothing and looks healthy.
* **`DBA_ROLE_PRIVS` is still readable**, which is the control. Without it, a
  release that removed dictionary access from this account *entirely* would look
  exactly like the pass above. §8's P7 row makes the same argument for keeping
  its `ORA-00990` assertion after the question was answered.

A fourth needs a *second* account: §2's optional
`V$PWFILE_USERS` grant, taken. What the pair proves is that the audit's answer
about `SYSDBA` and `SYSOPER` follows the estate rather than a constant — one
account reports them unchecked and the other reports them, and a suite that only
ever built the first would pass with the answer hard-coded.

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

from oracle_harness import Environment, current_container, execute, service_account_grants
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target
from sopuli.driver.oracle.privileges import (
    PASSWORD_FILE_PRIVILEGES,
    REQUIRED_PRIVILEGES,
    REQUIRED_READS,
    audit,
)
from sopuli.driver.protocol import ROLE_LOOKUP, Credential, UnsupportedCapabilityError
from sopuli.secrets import Secret

CORRELATION_ID = "9f1c4e02-77ab-4d51-9c6e-3b8a5d2f0e14"

#: Fictional, per CLAUDE.md's provenance rule, and deliberately not `SOPULI_SVC`
#: -- the name the install script defaults to -- so that running the real script
#: against the same database later cannot collide with this.
ACCOUNT = "acme_svc_user"
ACCOUNT_PASSWORD = "Service-Account-9z"

#: §2's optional grant, spelled the way :func:`_grants` spells the rest of the
#: set -- lower-case keywords around the object name §2 and `00_install.sql` use,
#: so a grep for `V_$PWFILE_USERS` across the docs, the script and this file finds
#: all three. Not in :func:`_grants`, because it is the thing whose presence and
#: absence this module has to be able to tell apart.
PASSWORD_FILE_GRANT = f"grant SELECT ON SYS.V_$PWFILE_USERS to {ACCOUNT}"


def _run(session: Any, *statements: str) -> None:
    """Statements through a driver session."""
    execute(session.connection, *statements)


def _grants() -> tuple[str, ...]:
    """§2's grant set as `GRANT` statements, derived rather than restated.

    Writing the list out again here would make this fixture agree with
    `privileges.py` only until somebody edited one of them -- and the account
    would then be right about the wrong thing, which is the failure the whole
    module exists to catch. :func:`oracle_harness.service_account_grants` does
    the derivation.
    """
    return service_account_grants(ACCOUNT)


@contextlib.contextmanager
def _installed(sysdba: Any, live_oracle: Environment, *extra: str) -> Iterator[Any]:
    """§2's account, created and connected **as itself**, then dropped.

    Connected as itself is the whole point: `USER_SYS_PRIVS`, `SESSION_PRIVS` and
    the `ORA-00942` this module pins are all facts about the *session's own*
    user, and a test that asked them from `system` would be asking a different
    question and getting a reassuring answer.

    ``extra`` is what §2 documents as optional, issued **before the session
    opens** rather than into an open one. That is the order an operator installs
    in, and it means no test here depends on when a fresh grant becomes visible
    to a session that predates it -- a question this module has not measured and
    does not need to.
    """
    session_module = pytest.importorskip("sopuli.driver.oracle.session")
    if current_container(sysdba) == "CDB$ROOT":
        # A local account cannot be created in the root -- ORA-65096 -- and a
        # common one is the install script's COMMON mode, which grants
        # `CONTAINER=ALL` and adds `V_$PDBS`. That is a different account with a
        # different expected set, so it is a skip with a reason rather than a
        # prefix bolted on here: the two modes deserve separate coverage and
        # pretending one is the other would assert the wrong thing quietly.
        pytest.skip("this container answers as CDB$ROOT; a local service account needs a PDB")
    _drop(sysdba)
    # Everything from here to `yield` can fail and leave an account behind, and
    # on this module's first CI run it did: `CREATE USER` succeeded and the
    # grants raised `ORA-01031`, so a half-granted `acme_svc_user` outlived the
    # run. The `_drop` above means the *next* test still gets a clean account
    # rather than "user already exists" -- but a fixture whose recovery is "the
    # next one will tidy up" leaves the database dirty at the end of the session,
    # which on a developer's own instance is litter and on a shared one is worse.
    try:
        execute(
            sysdba,
            f'create user {ACCOUNT} identified by "{ACCOUNT_PASSWORD}"',
            *_grants(),
            *extra,
        )

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
        _drop(sysdba)
        raise

    try:
        yield opened
    finally:
        opened.close()
        _drop(sysdba)


@pytest.fixture
def service_account(sysdba: Any, live_oracle: Environment) -> Iterator[Any]:
    """The default install: §2's grants and neither of its optional ones."""
    with _installed(sysdba, live_oracle) as opened:
        yield opened


@pytest.fixture
def password_file_reader(sysdba: Any, live_oracle: Environment) -> Iterator[Any]:
    """The same account with §2's optional `V$PWFILE_USERS` grant taken.

    The estate that opted in, and it is a *second* account rather than a flag on
    the first because what the two prove is the pair: the same code has to report
    two of §3's rows as unaudited on one and audited on the other, and a test
    that only ever saw one of them would pass on a constant.
    """
    with _installed(sysdba, live_oracle, PASSWORD_FILE_GRANT) as opened:
        yield opened


def _drop(sysdba: Any) -> None:
    """Absent is the desired state, so "it was not there" is a success."""
    with contextlib.suppress(Exception):
        execute(sysdba, f"drop user {ACCOUNT} cascade")


def _audit(session: Any) -> Any:
    with session.connection.cursor() as cursor:
        return audit(cursor, scope_type=session.scope().type)


#: An estate whose grants lack ``SELECT ON SYS.DBA_ROLES``, so it has no
#: `role_lookup` capability (decision #531). Revoked rather than never granted so
#: :func:`_grants` stays the one list.
WITHOUT_ROLE_LOOKUP = f"revoke SELECT ON SYS.DBA_ROLES from {ACCOUNT}"


@pytest.fixture
def installed_without_role_lookup(sysdba: Any, live_oracle: Environment) -> Iterator[Any]:
    """§2's account without the `DBA_ROLES` grant."""
    with _installed(sysdba, live_oracle, WITHOUT_ROLE_LOOKUP) as opened:
        yield opened


# ------------------------------------------------------------- staying quiet ---


def test_a_correct_install_is_short_of_nothing(service_account: Any) -> None:
    """`missing` is empty for an account granted exactly what §2 documents,
    measured rather than reasoned.

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
    """The measurement, as a regression test on somebody else's product.

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


# ---------------------------------------------------- the check that cannot look ---


def test_the_password_file_is_not_readable_under_the_documented_grants(
    service_account: Any,
) -> None:
    """§4 check 3's input, refused to the account §2 describes.

    Measured, and it is the measurement the whole check turns on:
    `ORA-00942: table or view "SYS"."V_$PWFILE_USERS" does not exist`, from an
    account holding exactly the documented set. That code is in
    :data:`~sopuli.driver.oracle.capabilities.ABSENT_CODES`, so the driver reads
    it as an enumerated negative and answers `None` -- *nobody looked* -- rather
    than `False`, which would read as *not a member* and pass the guardrail.

    Asserted here rather than only in tier 0 because tier 0 is handed the
    exception. What only a server can say is that the correct install really is
    the one that cannot answer, which is why the check is a caveat instead of
    a refusal.
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

    **Returning at all is the control**, not a non-empty `state.roles`. An
    account reachable through `DBA_ROLE_PRIVS` need not hold anything: §2 grants
    privileges directly and no roles, so this account holds none, and asserting
    otherwise would fail against a database behaving exactly as documented.
    What proves the roles view was read is that `describe_user` did not raise --
    an empty set and an unreadable view are precisely the two things
    `RolesUnreadableError` exists to keep apart.
    """
    state = service_account.describe_user(ACCOUNT)

    assert state is not None
    assert state.password_file_member is None
    assert state.roles == frozenset(), "§2 grants privileges directly and no roles"
    # The control -- `DBA_USERS` was read -- on a field every release supplies.
    # `vendor_maintained` is not the control: `ORACLE_MAINTAINED` does not exist
    # on 11.2, so it is `None` there for a reason that has nothing to do with
    # whether the view was readable, and a control that cannot tell those two
    # apart is not one. `name` comes from the same row and the same query.
    assert state.name == ACCOUNT.upper(), "the control: DBA_USERS was read"


def test_the_audit_reports_the_password_file_rows_as_unaudited(service_account: Any) -> None:
    """The default estate, where nobody can look.

    Nobody can look, so §3's two password-file rows are named as unchecked --
    and the remedy names the grant, because the reason is "you may enable this"
    rather than "this cannot be known".
    """
    found = _audit(service_account)

    assert set(PASSWORD_FILE_PRIVILEGES) <= set(found.unaudited)
    assert found.over_granted == ()
    assert found.unreadable == (), "an optional grant declined is not a partial audit"
    assert any("V_$PWFILE_USERS" in line.upper() for line in found.remedies)


# ---------------------------------------------------- the estate that opted in ---


def test_the_optional_grant_makes_the_password_file_rows_auditable(
    password_file_reader: Any,
) -> None:
    """The other half: the audit must not say *I could not look* here from a
    constant, on a session that could.

    The account holds neither privilege, so this is the answer that has to stay
    quiet -- and the assertion that matters is not `over_granted == ()`, which
    was already true, but that the two rows are gone from `unaudited`. With
    nothing left to enable, there is no remedy either.
    """
    found = _audit(password_file_reader)

    assert not set(PASSWORD_FILE_PRIVILEGES) & set(found.unaudited)
    assert found.unaudited == ("EXECUTE ON DBMS_LOCK",), "the row no grant can answer"
    assert found.over_granted == ()
    assert found.remedies == ()


def test_a_granted_sysdba_is_found_and_sysoper_is_not(
    sysdba: Any, password_file_reader: Any
) -> None:
    """§3's row, reported for the first time -- and reported as one row.

    `V$PWFILE_USERS` carries a column per privilege, so the two are answered
    independently; collapsing them would report `SYSOPER` on the strength of a
    `SYSDBA` row. Granted here and revoked in the same test rather than left to
    the fixture, because what is being measured is the difference the grant makes
    to one session's answer.

    An account granted `SYSDBA` inside a PDB appears in the view with its own
    `CON_ID` (§2), which is why this works from a PDB-local service account at
    all.
    """
    before = _audit(password_file_reader)
    execute(sysdba, f"grant sysdba to {ACCOUNT}")
    try:
        after = _audit(password_file_reader)
    finally:
        execute(sysdba, f"revoke sysdba from {ACCOUNT}")

    assert before.over_granted == ()
    assert after.over_granted == ("SYSDBA",)
    assert "SYSOPER" not in after.over_granted
    assert _audit(password_file_reader).over_granted == (), "the control: the revoke took"


def test_taking_the_optional_grant_is_not_itself_an_over_grant(
    password_file_reader: Any,
) -> None:
    """The optional grant must not be reported as over-granted.

    `over_granted` reads system privileges and roles; this is an object
    privilege, so a site that takes the grant §2 recommends must not then be told
    `doctor` disapproves of it.
    """
    assert _audit(password_file_reader).over_granted == ()
    assert _audit(password_file_reader).missing == ()


# ------------------------------------------------------------ role predicates ---


def test_a_correct_install_can_tell_a_role_from_a_misspelling(service_account: Any) -> None:
    """Every other role test runs as `system`, which reads `DBA_ROLES` whatever
    §2 says -- so without this test a correctly installed service account could
    refuse every `role:` predicate as a misspelling unnoticed (decision #531).

    `CONNECT` is Oracle's own and exists on every release, so the control needs
    no fixture of its own."""
    assert service_account.scope().supports(ROLE_LOOKUP)
    assert service_account.resolve_role("connect") == "CONNECT"
    assert service_account.resolve_role("acme_no_such_role_at_all") is None


def test_an_install_without_the_grant_is_refused_naming_it(
    installed_without_role_lookup: Any,
) -> None:
    """The gate: an estate without the `DBA_ROLES` grant is told what to grant,
    at plan time and with the capability named (invariant 4), rather than told
    that a role it can see in SQL*Plus does not exist."""
    assert not installed_without_role_lookup.scope().supports(ROLE_LOOKUP)

    with pytest.raises(UnsupportedCapabilityError) as raised:
        installed_without_role_lookup.resolve_role("connect")

    assert raised.value.capability == ROLE_LOOKUP
    assert "GRANT SELECT ON SYS.DBA_ROLES" in (raised.value.hint or "")


def test_an_install_without_the_grant_still_describes_accounts(
    installed_without_role_lookup: Any,
) -> None:
    """The reason the grant is a capability and not a required read: UC-1 reads
    nothing from `DBA_ROLES`, so an older install keeps working for everything
    but a role predicate -- and its privilege audit is short of nothing."""
    assert installed_without_role_lookup.describe_user(ACCOUNT) is not None
    assert _audit(installed_without_role_lookup).missing == ()


# --------------------------------------------- whether a reset is audited ---
#
# H10. `02-oracle-privileges.md` §2's optional grant and §5's three answers,
# asked as the service account, because the grant is the account's.

#: §2's optional grant for the audit check: `READ` on the two policy views.
AUDIT_GRANTS = (
    f"grant READ ON SYS.AUDIT_UNIFIED_ENABLED_POLICIES to {ACCOUNT}",
    f"grant READ ON SYS.AUDIT_UNIFIED_POLICIES to {ACCOUNT}",
)

#: The person whose reset would be checked. The policies here are enabled for
#: every user, so the name only has to be one.
PERSON = "ACME_DEV_ALICE"

#: Not `AC_`, which `sql/oracle/13_audit_coverage_probe.sql` cleans up, and not
#: `SOPULI_`, which `01_audit_policy.sql` creates.
POLICY = "acme_route_pol"


@pytest.fixture
def audit_reader(sysdba: Any, live_oracle: Environment) -> Iterator[Any]:
    """§2's account with the optional grant for the audit check taken."""
    with _installed(sysdba, live_oracle, *AUDIT_GRANTS) as opened:
        yield opened


@contextlib.contextmanager
def _policy(sysdba: Any, actions: str) -> Iterator[None]:
    """An audit policy enabled for every user, then disabled and dropped."""
    with contextlib.suppress(Exception):
        execute(sysdba, f"noaudit policy {POLICY}")
    with contextlib.suppress(Exception):
        execute(sysdba, f"drop audit policy {POLICY}")
    execute(sysdba, f"create audit policy {POLICY} actions {actions}", f"audit policy {POLICY}")
    try:
        yield
    finally:
        execute(sysdba, f"noaudit policy {POLICY}", f"drop audit policy {POLICY}")


def test_without_the_grant_the_answer_is_unknown_and_names_it(service_account: Any) -> None:
    """The default install cannot read the policy views (`ORA-00942`, measured),
    and that is never `false`: the answer names the grant that would let it tell."""
    found = service_account.audit_coverage(PERSON)

    assert found.audited is None
    assert "GRANT READ ON SYS.AUDIT_UNIFIED_ENABLED_POLICIES" in found.detail


def test_a_policy_recording_both_routes_for_every_user_is_true(
    audit_reader: Any, sysdba: Any
) -> None:
    """The positive case, with the grant: the answer names the policy for both
    actions."""
    with _policy(sysdba, "logon, alter user"):
        found = audit_reader.audit_coverage(PERSON)

    assert found.audited is True, found.detail
    assert f"LOGON by {POLICY.upper()}" in found.detail
    assert f"ALTER USER by {POLICY.upper()}" in found.detail


def test_nothing_recording_logons_is_false_on_a_unified_only_database(
    audit_reader: Any, sysdba: Any
) -> None:
    """`false` needs both facts §5 names: unified auditing only, and no enabled
    policy that covers or might cover `LOGON`. This database's own policies and
    mode decide both, so the test asks the check first, before adding its own
    policy, and skips with the check's own reason where the answer is not
    `false` already. A precondition written as a separate query would have to
    repeat §5's rules, and would drift from them."""
    before = audit_reader.audit_coverage(PERSON)
    if before.audited is not False:
        pytest.skip(f"this database's own audit state is not false: {before.detail}")

    with _policy(sysdba, "alter user"):
        found = audit_reader.audit_coverage(PERSON)

    assert found.audited is False, found.detail
    assert found.detail == f"no enabled policy records LOGON for {PERSON}"

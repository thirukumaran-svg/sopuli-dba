"""§3's must-not-grant list, as a judgement over three result sets (#213).

Tier 0. `classify` takes what the three views returned and decides; the queries
themselves are `audit`'s and are tier 1. `04-testing.md` §4 wants it that way —
which privileges are too many is a decision, and decisions are the layer that has
to be testable without a database.

The assertions that matter are the two kinds of *quiet*:

* a correctly installed account holding exactly §2's grants reports **nothing**,
  because a check that cries wolf on every healthy install is a check people
  learn to run with their eyes shut;
* a view that could not be read reports **something**, because "I looked and
  found nothing" and "I could not look" are the two answers a report must never
  merge — which is the failure #178 found in `DBA_SYS_PRIVS` and #195 in a
  capability probe.

P5 is decided and is not tested here because it is not this module's: `classify`
returns findings and never an exit code. That `doctor` warns rather than fails on
them is asserted in `tests/driver/test_oracle_doctor.py`, against a real
database.
"""

from __future__ import annotations

import pytest

from sopuli.driver.oracle.privileges import (
    FORBIDDEN_ROLES,
    UNAUDITABLE,
    PrivilegeAudit,
    classify,
)

#: What §2 actually grants, as `SESSION_PRIVS` reports it. The healthy case, and
#: the one that has to stay silent.
INSTALLED = frozenset({"CREATE SESSION", "ALTER USER"})


def audit_of(
    privileges: frozenset[str] = INSTALLED,
    roles: frozenset[str] = frozenset(),
    common: frozenset[str] = frozenset(),
    unreadable: tuple[str, ...] = (),
) -> PrivilegeAudit:
    return classify(privileges, roles, common, unreadable=unreadable)


# ------------------------------------------------------------- staying quiet ---


def test_an_account_with_exactly_the_documented_grants_reports_nothing() -> None:
    """The case the feature must not fire on. §2's grant set is the whole of what
    the tool needs, so a correct install has nothing over-granted."""
    assert audit_of().over_granted == ()


def test_an_ordinary_role_is_not_a_finding() -> None:
    """Sites grant roles. Only §3's three are a finding, and reporting the rest
    as one would make the report unreadable at any real site."""
    assert audit_of(roles=frozenset({"CONNECT", "RESOURCE", "ACME_APP_READER"})).over_granted == ()


def test_a_privilege_that_merely_starts_with_a_forbidden_word_is_not_a_finding() -> None:
    """`CREATE USER` is on the list and `CREATE SESSION` is what §2 grants. The
    match is on the whole privilege and never a prefix — except `GRANT ANY`,
    which is a family and says so."""
    assert audit_of(frozenset({"CREATE SESSION", "CREATE TABLE"})).over_granted == ()


# ---------------------------------------------------------------- finding it ---


@pytest.mark.parametrize(
    "privilege",
    ["SELECT ANY DICTIONARY", "ALTER PROFILE", "CREATE USER", "DROP USER", "ALTER SYSTEM"],
)
def test_each_forbidden_privilege_is_found(privilege: str) -> None:
    assert audit_of(INSTALLED | {privilege}).over_granted == (privilege,)


@pytest.mark.parametrize(
    "privilege", ["GRANT ANY PRIVILEGE", "GRANT ANY ROLE", "GRANT ANY OBJECT PRIVILEGE"]
)
def test_the_grant_any_family_is_matched_by_prefix(privilege: str) -> None:
    """§3 writes the row as `GRANT ANY *` because it is a family rather than a
    name. Matched by prefix so a release adding a fourth is caught by the rule
    and not by somebody remembering to extend a list."""
    assert audit_of(INSTALLED | {privilege}).over_granted == (privilege,)


@pytest.mark.parametrize("role", FORBIDDEN_ROLES)
def test_each_forbidden_role_is_found(role: str) -> None:
    assert audit_of(roles=frozenset({role})).over_granted == (role,)


def test_a_role_held_through_another_role_is_found() -> None:
    """#178 measured this: `ACME_APP_ADMIN` granted `DBA`, then granted to the
    account, reads as `ACME_APP_ADMIN` alone flat and as both traversed. The
    traversal is the query's; what this asserts is that the classifier does not
    care how the role arrived."""
    audit = audit_of(roles=frozenset({"ACME_APP_ADMIN", "DBA", "SELECT_CATALOG_ROLE"}))

    assert audit.over_granted == ("DBA",)


def test_the_whole_role_set_is_reported_not_just_the_matches() -> None:
    """So a reader can see *how* an over-grant arrived. A site role two levels up
    is the case #178 measured and the one nobody guesses from `DBA` alone."""
    audit = audit_of(roles=frozenset({"ACME_APP_ADMIN", "DBA"}))

    assert audit.roles == ("ACME_APP_ADMIN", "DBA")


def test_findings_are_sorted() -> None:
    """This reaches a report a human compares between runs, and dictionary order
    is nobody's contract."""
    audit = audit_of(INSTALLED | {"DROP USER", "ALTER SYSTEM"}, roles=frozenset({"DBA"}))

    assert audit.over_granted == ("ALTER SYSTEM", "DBA", "DROP USER")


# --------------------------------------------------- what it could not look at ---


def test_sysdba_is_reported_as_unaudited_rather_than_absent() -> None:
    """It is on §3's list and lives in `V$PWFILE_USERS`, which §2 does not grant.
    A list that quietly dropped two of its rows would read as a clean audit."""
    audit = audit_of()

    assert set(UNAUDITABLE) <= set(audit.unaudited)
    assert audit.over_granted == ()


def test_a_refused_role_view_takes_the_role_rows_with_it() -> None:
    """The finding that would otherwise be invisible: without this, an account
    holding `DBA` through a role nobody could read reports as holding nothing at
    all, which is the answer that looks like good news."""
    audit = audit_of(unreadable=("DBA_ROLE_PRIVS",))

    assert audit.unreadable == ("DBA_ROLE_PRIVS",)
    assert set(FORBIDDEN_ROLES) <= set(audit.unaudited)


def test_an_audit_is_never_complete_while_sysdba_cannot_be_seen() -> None:
    """A property rather than a constant, because it is a fact about §2's grant
    set and that can change."""
    assert audit_of().complete is False


def test_a_readable_run_still_reports_the_privileges_it_did_see() -> None:
    """A partial audit is partial, not useless: the roles were unreadable and the
    system privileges were not, and the finding from the second still stands."""
    audit = audit_of(INSTALLED | {"SELECT ANY DICTIONARY"}, unreadable=("DBA_ROLE_PRIVS",))

    assert audit.over_granted == ("SELECT ANY DICTIONARY",)


# --------------------------------------------------------------- common grants ---


def test_common_grants_are_reported_separately() -> None:
    """For a `C##` account the difference between a grant that reaches every PDB
    and one that reaches this one, which `SESSION_PRIVS` has no column for."""
    audit = audit_of(common=frozenset({"ALTER USER", "CREATE SESSION"}))

    assert audit.common == ("ALTER USER", "CREATE SESSION")


# ------------------------------------------------------------------ caveats ---


def test_a_clean_audit_still_states_what_it_did_not_check() -> None:
    """E6's argument, applied here: a caveat that appears only when something is
    wrong cannot be quoted as evidence that nothing was. Somebody handing this
    run to an auditor needs "SYSDBA was not among the things checked" written
    down rather than inferred from its absence."""
    caveats = audit_of().caveats()

    assert len(caveats) == 1
    assert "SYSDBA" in caveats[0]
    assert "DBMS_LOCK" in caveats[0]


def test_a_partial_audit_says_so_before_anything_else() -> None:
    """The line that changes how `over_granted` is read. Without it an empty
    finding list means both "nothing is over-granted" and "the view that would
    have said so was refused"."""
    caveats = audit_of(unreadable=("DBA_ROLE_PRIVS",)).caveats()

    assert len(caveats) == 2
    assert "partial" in caveats[0]
    assert "DBA_ROLE_PRIVS" in caveats[0]


def test_the_object_privilege_row_is_named_rather_than_dropped() -> None:
    """`EXECUTE ON DBMS_LOCK` is on the must-not-grant list and is an *object*
    privilege, which none of the three views here carries. Auditing it properly
    is a design question about role-derived object grants, so the row is named as
    unchecked rather than half-answered."""
    assert "EXECUTE ON DBMS_LOCK" in audit_of().unaudited

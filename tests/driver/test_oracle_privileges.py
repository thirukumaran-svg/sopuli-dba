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
    PASSWORD_FILE_PRIVILEGES,
    PWFILE_HELD,
    PWFILE_QUERY,
    REQUIRED_PRIVILEGES,
    REQUIRED_READS,
    ROOT_ONLY_READS,
    UNAUDITABLE,
    classify,
)
from sopuli.driver.protocol import PrivilegeAudit

#: What §2 actually grants, as `SESSION_PRIVS` reports it. The healthy case, and
#: the one that has to stay silent.
INSTALLED = frozenset({"CREATE SESSION", "ALTER USER"})

#: The default estate: §2's optional `V$PWFILE_USERS` grant not taken, so nobody
#: could look. `None` rather than `()` throughout this module for that reason —
#: the empty tuple is the *other* answer, and #341 is about not merging them.
UNGRANTED: tuple[str, ...] | None = None


def audit_of(
    privileges: frozenset[str] = INSTALLED,
    roles: frozenset[str] = frozenset(),
    common: frozenset[str] = frozenset(),
    unreadable: tuple[str, ...] = (),
    password_file: tuple[str, ...] | None = UNGRANTED,
) -> PrivilegeAudit:
    return classify(privileges, roles, common, unreadable=unreadable, password_file=password_file)


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


def test_the_rows_no_view_carries_are_reported_as_unaudited_rather_than_absent() -> None:
    """On §3's list and readable from nowhere here. A list that quietly dropped
    one of its rows would read as a clean audit."""
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


def test_an_audit_is_not_complete_while_an_object_privilege_has_no_view() -> None:
    """A property rather than a constant, because it is a fact about §2's grant
    set and that can change. It changed: #341 answers two of the three rows this
    used to fail on. `EXECUTE ON DBMS_LOCK` is the one left, and it is left for a
    reason no grant fixes."""
    assert audit_of(password_file=()).complete is False
    assert audit_of(password_file=()).unaudited == ("EXECUTE ON DBMS_LOCK",)


def test_a_readable_run_still_reports_the_privileges_it_did_see() -> None:
    """A partial audit is partial, not useless: the roles were unreadable and the
    system privileges were not, and the finding from the second still stands."""
    audit = audit_of(INSTALLED | {"SELECT ANY DICTIONARY"}, unreadable=("DBA_ROLE_PRIVS",))

    assert audit.over_granted == ("SELECT ANY DICTIONARY",)


# ------------------------------------------------------- the password file (#341) ---
#
# §3's two remaining rows, which `V$PWFILE_USERS` carries and §2 makes an
# optional grant. Three answers rather than two, and the whole of this section is
# about not merging them: held, asked-and-not-held, and nobody-could-look.


@pytest.mark.parametrize("privilege", PASSWORD_FILE_PRIVILEGES)
def test_a_password_file_privilege_is_an_over_grant_like_any_other(privilege: str) -> None:
    """The audit's first finding that is neither a system privilege nor a role,
    and it lands where the other findings do. §3's must-not-grant list is one
    list, and a reader looking for what this account holds and should not must
    not have to know which view each row came from."""
    audit = audit_of(password_file=(privilege,))

    assert audit.over_granted == (privilege,)
    assert privilege not in audit.unaudited


def test_the_two_rows_are_answered_separately() -> None:
    """The view carries a column each, so collapsing them would report `SYSOPER`
    on the strength of a `SYSDBA` row. Measured both ways round on 26ai
    23.26.2.0.0 -- granted one at a time, each reads back as itself."""
    assert audit_of(password_file=("SYSDBA",)).over_granted == ("SYSDBA",)
    assert audit_of(password_file=("SYSOPER",)).over_granted == ("SYSOPER",)


def test_asked_and_not_held_is_not_the_same_as_nobody_looked() -> None:
    """The distinction #341 is. An estate that took the grant and holds neither
    privilege has been *audited*, and saying otherwise is the merge this module
    exists to refuse -- arrived at from the side that under-reports."""
    asked = audit_of(password_file=())
    unasked = audit_of(password_file=UNGRANTED)

    assert asked.over_granted == ()
    assert not set(PASSWORD_FILE_PRIVILEGES) & set(asked.unaudited)
    assert set(PASSWORD_FILE_PRIVILEGES) <= set(unasked.unaudited)


def test_an_ungranted_view_does_not_make_the_audit_partial() -> None:
    """`unreadable` says the report cannot be taken at face value. §2 leaves this
    grant optional, so an estate that declined it is installed as documented --
    and a run that called every correct install partial would teach a reader to
    skip the line that matters when a view really was refused."""
    audit = audit_of(password_file=UNGRANTED)

    assert audit.unreadable == ()
    assert "V$PWFILE_USERS" not in " ".join(audit.unreadable)


def test_the_unaudited_rows_come_with_something_to_do_about_them() -> None:
    """Question 3 of #341. The rows read the same as they did before the grant
    existed; the *reason* does not, and only "you may enable this" has a next
    action. The `GRANT` is the driver's words because it is a fact about one
    product -- the audit's own shape names no database."""
    caveats = audit_of(password_file=UNGRANTED).caveats()

    assert any("V$PWFILE_USERS" in line for line in caveats)
    assert any("GRANT SELECT" in line for line in caveats)


def test_an_estate_that_took_the_grant_is_offered_no_remedy() -> None:
    """Nothing to fix, so nothing to say. A remedy printed on a run that already
    took it is the advice people learn to stop reading."""
    assert audit_of(password_file=()).remedies == ()
    assert audit_of(password_file=("SYSDBA",)).remedies == ()


def test_the_query_answers_the_constants_in_the_order_they_are_written() -> None:
    """`_password_file` reads the columns by position against
    `PASSWORD_FILE_PRIVILEGES`, so the query and the constant have to agree. They
    are two lines apart and would still drift; this is what notices."""
    columns = PWFILE_QUERY.split(" from ")[0]

    assert [
        privilege
        for privilege in PASSWORD_FILE_PRIVILEGES
        if f"{privilege.lower()} = '{PWFILE_HELD}'" in columns
    ] == list(PASSWORD_FILE_PRIVILEGES)
    assert columns.index("sysdba") < columns.index("sysoper")


def test_the_probe_asks_about_the_session_and_binds_nothing() -> None:
    """The grantee *is* the session, which is `SELF_ROLES_QUERY`'s reasoning: a
    bind would cost a round trip to say what `user` already says. It also means
    there is no account name here to get the spelling of wrong."""
    assert " user" in PWFILE_QUERY
    assert ":" not in PWFILE_QUERY


def test_the_probe_aggregates_so_a_non_member_still_returns_a_row() -> None:
    """The reason this is not `accounts.PWFILE_QUERY` with `user` bound. An
    unaggregated select over a non-member returns no row, `read` answers `None`
    for a refused view, and the two would arrive here as the same value."""
    assert PWFILE_QUERY.count("count(") == len(PASSWORD_FILE_PRIVILEGES)


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

    assert "SYSDBA" in caveats[0]
    assert "DBMS_LOCK" in caveats[0]


def test_an_estate_that_took_the_optional_grant_still_names_the_row_left() -> None:
    """The caveat shrinks and does not go away. `EXECUTE ON DBMS_LOCK` is still
    unchecked, and the line that says so is still the one an auditor quotes."""
    caveats = audit_of(password_file=()).caveats()

    assert len(caveats) == 1
    assert "DBMS_LOCK" in caveats[0]
    assert "SYSDBA" not in caveats[0]


def test_a_partial_audit_says_so_before_anything_else() -> None:
    """The line that changes how `over_granted` is read. Without it an empty
    finding list means both "nothing is over-granted" and "the view that would
    have said so was refused"."""
    caveats = audit_of(unreadable=("DBA_ROLE_PRIVS",)).caveats()

    assert "partial" in caveats[0]
    assert "DBA_ROLE_PRIVS" in caveats[0]


def test_the_object_privilege_row_is_named_rather_than_dropped() -> None:
    """`EXECUTE ON DBMS_LOCK` is on the must-not-grant list and is an *object*
    privilege, which none of the three views here carries. Auditing it properly
    is a design question about role-derived object grants, so the row is named as
    unchecked rather than half-answered."""
    assert "EXECUTE ON DBMS_LOCK" in audit_of().unaudited


# ---------------------------------------------------------- the positive side ---
#
# §2's grants, checked as present or absent (#225). The point is that a
# half-installed account is visible *here* rather than as unrelated failures
# three commands later: a missing `SELECT ON DBA_PROFILES` otherwise surfaces as
# a limit resolution that could not answer, and nobody connects the two.


def readable_of(*grants: str) -> frozenset[str]:
    return frozenset(grants)


ALL_READS = tuple(REQUIRED_READS)


def complete_of() -> PrivilegeAudit:
    """An account holding everything §2 grants outside the root."""
    return classify(
        INSTALLED,
        frozenset(),
        frozenset(),
        readable=readable_of(*ALL_READS),
        expected_reads=ALL_READS,
    )


def test_a_complete_install_reports_everything_held_and_nothing_missing() -> None:
    audit = complete_of()

    assert audit.missing == ()
    assert set(REQUIRED_PRIVILEGES) <= set(audit.held)
    assert set(ALL_READS) <= set(audit.held)


def test_a_missing_dictionary_grant_is_named_as_the_grant_to_issue() -> None:
    """Spelled as the `GRANT`, because the point of a missing entry is that
    somebody has to go and issue it — not that a view was unreadable."""
    audit = classify(
        INSTALLED,
        frozenset(),
        frozenset(),
        readable=readable_of(*[g for g in ALL_READS if g != "SELECT ON DBA_PROFILES"]),
        expected_reads=ALL_READS,
    )

    assert audit.missing == ("SELECT ON DBA_PROFILES",)
    assert "SELECT ON DBA_PROFILES" not in audit.held


def test_a_missing_system_privilege_is_a_finding_too() -> None:
    """`ALTER USER` is the one the tool cannot work without, and an account that
    connects perfectly well may not hold it."""
    audit = classify(
        frozenset({"CREATE SESSION"}),
        frozenset(),
        frozenset(),
        readable=readable_of(*ALL_READS),
        expected_reads=ALL_READS,
    )

    assert audit.missing == ("ALTER USER",)


def test_a_privilege_held_through_a_role_counts_as_held() -> None:
    """`SESSION_PRIVS` includes role-derived privileges, which is why it is what
    this reads. §2 grants directly and a site may not have."""
    audit = classify(
        frozenset({"CREATE SESSION", "ALTER USER"}),
        frozenset({"ACME_APP_ADMIN"}),
        frozenset(),
        readable=readable_of(*ALL_READS),
        expected_reads=ALL_READS,
    )

    assert audit.missing == ()


def test_v_dollar_pdbs_is_not_expected_outside_the_root() -> None:
    """§2 grants it in the root only, so its absence in a PDB is the documented
    install. Calling a PDB half-installed for lacking a grant it was never given
    would be wrong in the direction that costs the most trust."""
    audit = complete_of()

    assert "SELECT ON V_$PDBS" not in audit.missing
    assert "SELECT ON V_$PDBS" not in audit.held


def test_v_dollar_pdbs_is_expected_in_the_root_and_missing_when_absent() -> None:
    """The other half, and the reason the two lists are separate constants rather
    than one filtered at the call site: "not required here" and "required and
    missing" are the answers this report exists to keep apart."""
    expected = (*ALL_READS, *ROOT_ONLY_READS)
    audit = classify(
        INSTALLED,
        frozenset(),
        frozenset(),
        readable=readable_of(*ALL_READS),
        expected_reads=expected,
    )

    assert audit.missing == ("SELECT ON V_$PDBS",)


def test_the_two_sides_are_independent() -> None:
    """An account can be both short of what it needs and holding what it must
    not, which is the state a half-finished 17:00-on-a-Friday debugging session
    actually leaves behind."""
    audit = classify(
        frozenset({"CREATE SESSION", "SELECT ANY DICTIONARY"}),
        frozenset(),
        frozenset(),
        readable=readable_of(*ALL_READS),
        expected_reads=ALL_READS,
    )

    assert audit.missing == ("ALTER USER",)
    assert audit.over_granted == ("SELECT ANY DICTIONARY",)


def test_nothing_expected_means_nothing_reported_either_way() -> None:
    """A caller that does not know the scope passes no expectations, and the
    report omits the rows rather than inventing findings about them."""
    audit = classify(INSTALLED, frozenset(), frozenset())

    assert audit.held == ("ALTER USER", "CREATE SESSION")
    assert audit.missing == ()

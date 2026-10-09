"""Probing, and the difference between "no" and "I could not tell".

Tier 0: what to ask, how to read an answer and what it means are pure, so they
are tested here rather than only on a machine with containers running — which is
the machine least likely to notice they were wrong. Decision #195 is the case in
point: a probe that was invalid on every release looked like a clean negative
for a full release cycle, on hardware that never ran it.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.model import TargetOracle
from sopuli.driver.oracle.capabilities import (
    ABSENT_CODES,
    APPLICATION_PDB,
    APPLICATION_ROOT,
    CONTAINER_NAME,
    PROBED_OR_STRUCTURAL,
    PROBES,
    STRUCTURAL,
    ProbeError,
    ReadOnlyTargetError,
    ScopeAssertionError,
    application_of,
    assert_scope,
    container_of,
    observe,
    probe,
    read,
    require_read_write,
    scope_type,
)
from sopuli.driver.protocol import (
    CAPABILITIES,
    COMMON_USERS,
    OFFLINE_VERIFY,
    PASSWORD_ROLLOVER,
    UNKNOWN,
    Scope,
)
from sopuli.exit_codes import ExitCode


class _Cursor:
    """A cursor that answers, or refuses, per statement.

    ``answers`` maps a statement to the first column of its single row, or to an
    exception to raise. Anything unasked-for answers ``0``, which is *absent* —
    the same default the real thing produces for a ``count(*)`` that matched
    nothing.
    """

    def __init__(self, answers: dict[str, Any] | None = None) -> None:
        self.answers = answers or {}
        self.asked: list[str] = []
        self.sql = ""
        self.parameters: Any = None

    def execute(self, sql: str, parameters: Any = None, /) -> _Cursor:
        self.asked.append(sql)
        self.sql = sql
        self.parameters = parameters
        return self

    def fetchone(self) -> tuple[Any, ...] | None:
        answer = self.answers.get(self.sql, 0)
        if isinstance(answer, Exception):
            raise answer
        return answer if isinstance(answer, tuple) else (answer,)

    def fetchall(self) -> list[tuple[Any, ...]]:
        row = self.fetchone()
        return [row] if row is not None else []


def _ora(code: str, message: str = "") -> RuntimeError:
    """An exception shaped the way a bare ``ORA-`` failure reaches us."""
    return RuntimeError(f"{code}: {message or 'something the server said'}")


# ------------------------------------------------------------ the vocabulary ---


def test_every_capability_is_either_probed_or_declared_structural() -> None:
    """P1's table and the code answer the same list.

    A capability added to the document and not here — or the reverse — fails
    rather than drifts, and a new one has to choose a side deliberately.
    """
    assert PROBED_OR_STRUCTURAL == CAPABILITIES


def test_nothing_is_both_probed_and_assumed() -> None:
    """A capability in both lists would be asked about and then granted anyway,
    which is a probe whose answer cannot matter."""
    assert not set(PROBES) & set(STRUCTURAL)


def test_every_structural_capability_says_why_it_is_not_probed() -> None:
    """Kept as data with a reason attached, so "we assumed this" stays visible
    rather than indistinguishable from "we measured it"."""
    assert all(reason for reason in STRUCTURAL.values())


def test_no_two_capabilities_share_a_question() -> None:
    """Each capability has its own probe (decision #195).

    A common user exists only in a CDB, so one probe can look like enough for
    `container_scope` and `common_users` both. It is not: holding the privilege
    to manage a common user is a separate question from being in a CDB, and a
    probe shared between them was measured reporting both absent everywhere.
    Two capabilities are two questions.
    """
    assert len(set(PROBES.values())) == len(PROBES)


def test_the_invalid_userenv_attribute_does_not_come_back() -> None:
    """The literal probe that decision #195 records.

    ``sys_context('userenv','cdb')`` is not a valid attribute — ``ORA-02003``, in
    a PDB and in the CDB root alike, measured on 26ai 23.26.2.0.0. It is an easy
    thing to reach for again, because it reads exactly like the question anybody
    would ask, so the regression is pinned on the text rather than on the outcome.
    """
    assert not any("'cdb'" in sql.replace(" ", "") for sql in PROBES.values())


def test_common_users_asks_about_a_privilege_not_a_place() -> None:
    """The probe for `common_users`, and what it asks.

    Measured: an account holding ``ALTER USER`` commonly reads 1 and can alter a
    common user from the root; one holding the identical privilege locally reads
    0 and gets ``ORA-01031`` for the same statement. Where the session stands is
    :attr:`Scope.type`'s answer, and asking that here is the mistake that
    decision #195 records.
    """
    sql = PROBES[COMMON_USERS]

    assert "user_sys_privs" in sql
    assert "common = 'YES'" in sql
    # DBA_SYS_PRIVS is unreadable under the documented grant set, and
    # SESSION_PRIVS has no COMMON column and so calls a local grant a pass.
    assert "dba_sys_privs" not in sql
    assert "session_privs" not in sql


# ----------------------------------------------------------- reading answers ---


@pytest.mark.parametrize("code", sorted(ABSENT_CODES))
def test_an_enumerated_negative_reads_as_absent(code: str) -> None:
    """A missing view, a missing column and a grant that was never made all mean
    the same thing to a caller: *you cannot do this here*."""
    assert read(_Cursor({"select 1": _ora(code)}), "select 1") is None


def test_an_unenumerated_failure_is_not_an_answer() -> None:
    """The finding of decision #195, as a test.

    ``ORA-02003`` means the tool asked something Oracle does not have. Reading
    that as *absent* is what let a broken probe report a plausible negative on
    every database for a release cycle, so it raises.
    """
    with pytest.raises(ProbeError) as raised:
        read(_Cursor({"select 1": _ora("ORA-02003", "invalid USERENV attribute")}), "select 1")

    assert raised.value.code == "ORA-02003"


def test_a_failed_probe_names_the_statement_that_failed() -> None:
    """The hint carries the SQL, because "a capability probe failed" without it
    sends the reader to grep for which one."""
    with pytest.raises(ProbeError) as raised:
        read(
            _Cursor({"select banana": _ora("ORA-00933", "SQL command not properly ended")}),
            "select banana",
        )

    assert raised.value.hint is not None
    assert "select banana" in raised.value.hint


def test_a_failed_probe_is_not_confused_with_an_absent_capability() -> None:
    """`ProbeError` is a `DriverError` and reaches the operator as one, rather
    than shrinking the capability set and being discovered three steps later."""
    cursor = _Cursor({PROBES[PASSWORD_ROLLOVER]: _ora("ORA-03113", "end-of-file on channel")})

    with pytest.raises(ProbeError):
        probe(cursor)


def test_a_probe_answering_zero_means_absent() -> None:
    assert read(_Cursor({"select 1": 0}), "select 1") == (0,)
    assert probe(_Cursor()) == frozenset(STRUCTURAL)


def test_probing_grants_the_structural_capabilities_without_asking() -> None:
    cursor = _Cursor(dict.fromkeys(PROBES.values(), 0))

    assert probe(cursor) == frozenset(STRUCTURAL)
    assert len(cursor.asked) == len(PROBES)


@pytest.mark.parametrize("code", ["ORA-00942", "ORA-41900"])
def test_an_ungranted_sys_user_dollar_reads_as_no_offline_verify(code: str) -> None:
    """The grant is optional (decision P2), so its absence is ordinary rather
    than an error — and the `LCOUNT` guard being unavailable is exactly what
    `check` has to report plainly.

    Measured on 26ai Free 23.26.2.0.0, where `SYSTEM` does not hold it either.

    Parametrised over both codes because the same ungranted table answers
    differently depending on who asks: ``ORA-41900`` to `SYSTEM`, which is
    privileged enough to be told the object exists, and ``ORA-00942`` to an
    account that is not. Measured on 26ai 23.26.2.0.0, and the second code is the
    one nobody would have guessed.
    """
    answers: dict[str, Any] = dict.fromkeys(PROBES.values(), 1)
    answers[PROBES[OFFLINE_VERIFY]] = _ora(code)

    assert OFFLINE_VERIFY not in probe(_Cursor(answers))


# ------------------------------------------------------------------- scope ---


def test_a_database_without_containers_reports_no_container() -> None:
    """11.2 has never heard of ``con_name`` and says so with ``ORA-02003``.

    The one question in the driver where that code carries information, and it is
    read here and nowhere else — the argument for enumerating negatives is that a
    code meaning something in one place must not mean anything anywhere else.
    """
    cursor = _Cursor({CONTAINER_NAME: _ora("ORA-02003", "invalid USERENV attribute")})

    assert container_of(cursor) is None


def test_a_container_name_is_reported_as_the_database_gave_it() -> None:
    assert container_of(_Cursor({CONTAINER_NAME: "FREEPDB1"})) == "FREEPDB1"


def test_a_failure_resolving_the_container_is_not_read_as_non_cdb() -> None:
    """Anything but ``ORA-02003`` propagates. Reporting ``non_cdb`` because the
    question could not be asked would be the same mistake in a new place, and
    `non_cdb` is the scope from which a common user cannot be reached at all."""
    with pytest.raises(RuntimeError):
        container_of(_Cursor({CONTAINER_NAME: _ora("ORA-01031")}))


@pytest.mark.parametrize(
    ("container", "expected"),
    [
        (None, "non_cdb"),
        ("CDB$ROOT", "cdb_root"),
        ("cdb$root", "cdb_root"),
        ("FREEPDB1", "pdb"),
    ],
)
def test_scope_type_follows_the_container_name(container: str | None, expected: str) -> None:
    """Measured on 26ai: `CDB$ROOT` in the root, `FREEPDB1` in the PDB, and
    ``con_id`` 1 and 3 beside them."""
    assert scope_type(container) == expected


@pytest.mark.parametrize(
    ("application", "expected"),
    [("root", "app_root"), ("pdb", "app_pdb"), (None, "pdb")],
)
def test_an_application_container_refines_the_pdb_answer(
    application: str | None, expected: str
) -> None:
    """The container name alone cannot tell these apart.

    ``ACME_ROOT`` and ``ACME_ALPHA`` are ordinary container names, so the two
    scopes P1 names beyond ``pdb`` are a refinement of that answer and never of
    the other two.
    """
    assert scope_type("ACME_ALPHA", application) == expected


@pytest.mark.parametrize("container", [None, "CDB$ROOT"])
def test_an_application_answer_cannot_override_the_container_name(container: str | None) -> None:
    """A non-CDB and the CDB root are settled before the question is reached.

    :func:`observe` does not ask it there at all, and this is the half of that
    which does not depend on remembering to: even handed the answer, the mapping
    keeps the scope the container name established.
    """
    assert scope_type(container, "root") in ("non_cdb", "cdb_root")


def test_an_application_root_is_read_from_userenv() -> None:
    """Measured on 26ai 23.26.2.0.0: ``YES``/``NO`` strings, not a flag."""
    cursor = _Cursor({APPLICATION_ROOT: "YES"})

    assert application_of(cursor) == "root"


def test_an_application_pdb_is_read_from_userenv() -> None:
    cursor = _Cursor({APPLICATION_ROOT: "NO", APPLICATION_PDB: "YES"})

    assert application_of(cursor) == "pdb"


def test_an_ordinary_pdb_is_neither() -> None:
    cursor = _Cursor({APPLICATION_ROOT: "NO", APPLICATION_PDB: "NO"})

    assert application_of(cursor) is None


def test_the_second_question_is_not_asked_once_the_first_says_yes() -> None:
    """A container cannot be both, so the second probe has nothing left to add."""
    cursor = _Cursor({APPLICATION_ROOT: "YES"})

    application_of(cursor)

    assert APPLICATION_PDB not in cursor.asked


def test_a_release_without_application_containers_is_not_one() -> None:
    """``ORA-02003`` again, carrying its second fact.

    From ``con_name`` it is 11.2 saying there are no containers; from these two it
    is a release before 12.2 saying there are no *application* containers. One
    code, two facts, and the same conclusion -- which is why it is read in exactly
    one function rather than caught wherever it turns up.
    """
    cursor = _Cursor({APPLICATION_ROOT: _ora("ORA-02003", "invalid USERENV attribute")})

    assert application_of(cursor) is None


def test_the_second_question_is_not_asked_where_the_attribute_is_absent() -> None:
    """A release before 12.2 says so once, not twice.

    ``ORA-02003`` from the first probe is the release answering for both, so
    asking the second would spend a round trip and an exception parse to be told
    the same thing again.
    """
    cursor = _Cursor({APPLICATION_ROOT: _ora("ORA-02003", "invalid USERENV attribute")})

    assert application_of(cursor) is None
    assert APPLICATION_PDB not in cursor.asked


def test_a_failure_asking_about_application_containers_is_not_read_as_no() -> None:
    """Anything but ``ORA-02003`` propagates, for :func:`container_of`'s reason:
    reporting "not an application container" because the question could not be
    asked is how the application-container refusal would go quiet again."""
    with pytest.raises(RuntimeError):
        application_of(_Cursor({APPLICATION_ROOT: _ora("ORA-01031")}))


def test_a_root_session_is_not_asked_about_application_containers() -> None:
    """The cost argument in :func:`application_of`, asserted rather than claimed."""
    cursor = _Cursor(
        {
            CONTAINER_NAME: "CDB$ROOT",
            "select db_unique_name, open_mode from v$database": ("FREE", "READ WRITE"),
        }
    )

    observe(cursor)

    assert APPLICATION_ROOT not in cursor.asked
    assert APPLICATION_PDB not in cursor.asked


def test_observe_reports_an_application_pdb() -> None:
    """End to end through the mapping, on the application container names."""
    cursor = _Cursor(
        {
            CONTAINER_NAME: "ACME_ALPHA",
            APPLICATION_ROOT: "NO",
            APPLICATION_PDB: "YES",
            "select db_unique_name, open_mode from v$database": ("FREE", "READ WRITE"),
        }
    )

    found = observe(cursor)

    assert found.type == "app_pdb"
    assert found.container == "ACME_ALPHA"


def test_observe_reports_what_it_found() -> None:
    cursor = _Cursor(
        {
            CONTAINER_NAME: "CDB$ROOT",
            "select db_unique_name, open_mode from v$database": ("FREE", "READ WRITE"),
            "select version from v$instance": "23.0.0.0.0",
            PROBES[COMMON_USERS]: 1,
        }
    )

    found = observe(cursor)

    assert found.type == "cdb_root"
    assert found.container == "CDB$ROOT"
    assert found.db_unique_name == "FREE"
    assert found.db_version == "23.0.0.0.0"
    assert found.read_write is True
    assert found.supports(COMMON_USERS)


def test_a_standby_is_reported_read_only() -> None:
    """P1 requires the refusal up front rather than halfway through a statement,
    and this is the fact it refuses on."""
    cursor = _Cursor(
        {
            CONTAINER_NAME: "CDB$ROOT",
            "select db_unique_name, open_mode from v$database": ("FREE_DR", "READ ONLY"),
        }
    )

    assert observe(cursor).read_write is False


def test_an_unreadable_v_dollar_database_leaves_the_facts_unknown() -> None:
    """`SELECT ON SYS.V_$DATABASE` is in the documented grant set, but a
    half-installed account is exactly the case that has to stay diagnosable: the
    scope still resolves, because it comes from `sys_context` and needs no grant
    at all."""
    cursor = _Cursor(
        {
            CONTAINER_NAME: "FREEPDB1",
            "select db_unique_name, open_mode from v$database": _ora("ORA-00942"),
        }
    )

    found = observe(cursor)

    assert found.type == "pdb"
    assert found.db_unique_name is None
    assert found.read_write is None


# -------------------------------------------------------------- assertions ---


def _declared(scope: str | None = None, container: str | None = None) -> TargetOracle:
    return TargetOracle(scope=scope, container=container)


def test_a_target_that_asserts_nothing_is_not_incompletely_configured() -> None:
    """`01-configuration.md` §3a: both keys are optional, because an assertion
    nobody makes is not a gap. The driver reports what it found."""
    found = Scope(type="pdb", container="FREEPDB1")

    assert_scope(found, None, target="t")
    assert_scope(found, _declared(), target="t")


def test_a_matching_assertion_passes() -> None:
    found = Scope(type="pdb", container="FREEPDB1")

    assert_scope(found, _declared(scope="pdb", container="FREEPDB1"), target="t")


def test_a_mismatched_scope_names_both_values() -> None:
    """The whole point of the message. Naming only the declared half sends the
    reader to the file to look up what they already wrote; the half they cannot
    see is the one the connection found."""
    with pytest.raises(ScopeAssertionError) as raised:
        assert_scope(Scope(type="cdb_root"), _declared(scope="pdb"), target="orders-pdb")

    message = str(raised.value)
    assert "pdb" in message
    assert "cdb_root" in message
    assert "orders-pdb" in message


def test_a_mismatched_container_names_both_values() -> None:
    """UC-1 §5 step 2's reason for existing: a `dsn:` edit that silently
    repointed a target at a different container."""
    found = Scope(type="pdb", container="BILLING")

    with pytest.raises(ScopeAssertionError) as raised:
        assert_scope(found, _declared(container="ORDERS"), target="orders-pdb")

    message = str(raised.value)
    assert "ORDERS" in message
    assert "BILLING" in message


def test_a_container_is_compared_case_insensitively() -> None:
    """Oracle upper-cases an unquoted identifier, so `freepdb1` in a file and
    `FREEPDB1` from `con_name` are one container — the same rule
    `Identifier.is_common` already applies to `C##`. A check that said otherwise
    would fail on a correct estate every time."""
    found = Scope(type="pdb", container="FREEPDB1")

    assert_scope(found, _declared(container="freepdb1"), target="t")


def test_a_container_declared_against_a_non_cdb_is_a_mismatch() -> None:
    """There is no container to name, which is a claim that cannot hold rather
    than one that happens not to match."""
    with pytest.raises(ScopeAssertionError) as raised:
        assert_scope(Scope(type="non_cdb"), _declared(container="ORDERS"), target="t")

    assert "no containers" in str(raised.value)


def test_an_unresolved_scope_does_not_satisfy_an_assertion() -> None:
    """A claim that could not be checked is not a claim that passed.

    `unknown` is a scope the driver may report and a file may never claim, so
    the two can never match — and treating "we could not tell" as agreement
    would be the mistake decision #195 records, in a new place.
    """
    with pytest.raises(ScopeAssertionError) as raised:
        assert_scope(Scope(type=UNKNOWN), _declared(scope="pdb"), target="t")

    assert "could not determine" in str(raised.value)


def test_the_assertion_check_carries_the_config_exit_code() -> None:
    """Exit 9 means *fix your config file*, which is the operator's next action
    whichever half moved."""
    with pytest.raises(ScopeAssertionError) as raised:
        assert_scope(Scope(type="cdb_root"), _declared(scope="pdb"), target="t")

    assert raised.value.exit_code == ExitCode.CONFIG_INVALID
    assert raised.value.category == "config"


# ------------------------------------------------------------- read / write ---


def test_a_standby_is_refused_before_anything_is_written() -> None:
    """P1 wants this up front rather than halfway through a statement."""
    with pytest.raises(ReadOnlyTargetError) as raised:
        require_read_write(
            Scope(type="pdb", open_mode="READ ONLY", read_write=False), target="orders-dr"
        )

    assert "orders-dr" in str(raised.value)
    assert "READ ONLY" in str(raised.value)


def test_a_read_write_target_is_not_refused() -> None:
    require_read_write(Scope(type="pdb", open_mode="READ WRITE", read_write=True), target="t")


def test_an_unknown_open_mode_is_not_treated_as_a_standby() -> None:
    """`V$DATABASE` is in the documented grant set, but a half-installed account
    cannot read it — and turning a missing grant into "this is a standby" is a
    worse diagnosis than the one the missing grant already produces."""
    require_read_write(Scope(type="pdb"), target="t")


def test_the_standby_refusal_is_not_folded_into_the_assertion_check() -> None:
    """`creds check` reads and must keep working against a standby, so refusing
    one is the mutating commands' call rather than a property of connecting."""
    assert_scope(Scope(type="pdb", read_write=False), _declared(scope="pdb"), target="t")

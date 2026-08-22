"""Probing, and the difference between "no" and "I could not tell" (#177).

Tier 0: what to ask, how to read an answer and what it means are pure, so they
are tested here rather than only on a machine with containers running — which is
the machine least likely to notice they were wrong. #195 is the case in point:
a probe that was invalid on every release looked like a clean negative for a full
release cycle, on hardware that never ran it.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.oracle.capabilities import (
    ABSENT_CODES,
    CONTAINER_NAME,
    PROBED_OR_STRUCTURAL,
    PROBES,
    STRUCTURAL,
    ProbeError,
    container_of,
    observe,
    probe,
    read,
    scope_type,
)
from sopuli.driver.protocol import (
    CAPABILITIES,
    COMMON_USERS,
    OFFLINE_VERIFY,
    PASSWORD_ROLLOVER,
)


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

    def execute(self, sql: str, /) -> _Cursor:
        self.asked.append(sql)
        self.sql = sql
        return self

    def fetchone(self) -> tuple[Any, ...] | None:
        answer = self.answers.get(self.sql, 0)
        if isinstance(answer, Exception):
            raise answer
        return answer if isinstance(answer, tuple) else (answer,)


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
    """#195, inverted.

    `container_scope` and `common_users` used to share one probe, on the
    reasoning that a common user is a thing which exists only in a CDB — so two
    separately-worded probes would agree by construction and give a future editor
    two places to make them disagree. The first real measurement contradicted the
    reasoning while agreeing with the answer, which is the specific way that
    argument fails. Two capabilities are two questions.
    """
    assert len(set(PROBES.values())) == len(PROBES)


def test_the_invalid_userenv_attribute_does_not_come_back() -> None:
    """The literal probe that caused #195.

    ``sys_context('userenv','cdb')`` is not a valid attribute — ``ORA-02003``, in
    a PDB and in the CDB root alike, measured on 26ai 23.26.2.0.0. It is an easy
    thing to reach for again, because it reads exactly like the question anybody
    would ask, so the regression is pinned on the text rather than on the outcome.
    """
    assert not any("'cdb'" in sql.replace(" ", "") for sql in PROBES.values())


def test_common_users_asks_about_a_privilege_not_a_place() -> None:
    """What replaced the shared probe.

    Measured: an account holding ``ALTER USER`` commonly reads 1 and can alter a
    common user from the root; one holding the identical privilege locally reads
    0 and gets ``ORA-01031`` for the same statement. Where the session stands is
    :attr:`Scope.type`'s answer, and asking that here is what #195 was about.
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
    """#195's whole finding, as a test.

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
    """#86 made the grant optional, so its absence is ordinary rather than an
    error — and the `LCOUNT` guard being unavailable is exactly what `check` has
    to report plainly.

    Measured on 23ai Free, where `SYSTEM` does not hold it either (#195).

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

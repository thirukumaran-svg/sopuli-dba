"""The harness's own logic, which is tier 0 because most of it is not I/O.

What to ask, how to read an answer, what to skip and how to report are decisions
that need no database — and they are the parts that would otherwise only be
exercised on a machine with containers running, which is the machine least
likely to notice they were wrong.
"""

from __future__ import annotations

from typing import Any

import pytest

from oracle_harness import (
    PROBES,
    STRUCTURAL,
    Environment,
    below,
    decide_skip,
    dsn_host,
    probe,
    read,
    render_matrix,
)
from sopuli.driver.protocol import (
    CAPABILITIES,
    OFFLINE_VERIFY,
    PASSWORD_ROLLOVER,
)


class _Cursor:
    """A cursor that answers, or refuses, per statement."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.asked: list[str] = []

    def execute(self, sql: str) -> _Cursor:
        self.asked.append(sql)
        self.sql = sql
        return self

    def fetchone(self) -> tuple[Any, ...] | None:
        answer = self.answers.get(self.sql, 0)
        if isinstance(answer, Exception):
            raise answer
        return (answer,)


def environment(**kwargs: Any) -> Environment:
    return Environment(
        name=kwargs.pop("name", "23ai Free"), dsn="localhost:1521/FREEPDB1", **kwargs
    )


# ------------------------------------------------------------ the vocabulary ---


def test_every_capability_is_either_probed_or_declared_structural() -> None:
    """The assertion the whole harness rests on.

    §3's claim is that the suite validates the capability model rather than
    duplicating its assumptions, and that only holds if the harness asks about
    the same list the driver reports. The sketch in `test/capabilities.py` did
    not: it probed three things no driver reports and missed three that are
    capabilities. A new capability now has to choose a side deliberately.
    """
    assert set(PROBES) | set(STRUCTURAL) == CAPABILITIES


def test_nothing_is_both_probed_and_assumed() -> None:
    """A capability in both lists would be asked about and then granted anyway,
    which is a probe whose answer cannot matter."""
    assert not set(PROBES) & set(STRUCTURAL)


def test_every_structural_capability_says_why_it_is_not_probed() -> None:
    """Kept as data with a reason attached, so that "we assumed this" is visible
    rather than indistinguishable from "we measured it"."""
    assert all(reason for reason in STRUCTURAL.values())


# ------------------------------------------------------------- reading answers ---


def test_a_probe_that_raises_means_absent() -> None:
    """A missing view, a missing column, a grant that was never made: all arrive
    as an exception and all mean the same thing to a caller."""
    cursor = _Cursor({"select 1": RuntimeError("ORA-00942: table or view does not exist")})

    assert not read(cursor, "select 1")


def test_a_probe_answering_zero_means_absent() -> None:
    assert not read(_Cursor({"select 1": 0}), "select 1")
    assert read(_Cursor({"select 1": 1}), "select 1")


def test_probing_grants_the_structural_capabilities_without_asking() -> None:
    cursor = _Cursor(dict.fromkeys(PROBES.values(), 0))
    found = probe(cursor)

    assert found == set(STRUCTURAL)
    assert len(cursor.asked) == len(PROBES)


def test_two_capabilities_may_share_one_question() -> None:
    """`container_scope` and `common_users` ask the same thing because the
    answer is the same fact: a common user is a thing that exists only in a CDB.

    Two separately-worded probes would agree by construction and give a future
    editor two places to make them disagree. Asserted rather than left to the
    comment, since the count above would otherwise look like an off-by-one.
    """
    from sopuli.driver.protocol import COMMON_USERS, CONTAINER_SCOPE

    assert PROBES[CONTAINER_SCOPE] == PROBES[COMMON_USERS]
    assert len(set(PROBES.values())) == len(PROBES) - 1


def test_an_ungranted_sys_user_dollar_reads_as_no_offline_verify() -> None:
    """#86 made the grant optional, so its absence is ordinary rather than an
    error -- and the `LCOUNT` guard being unavailable is exactly what `check`
    has to report plainly."""
    answers: dict[str, Any] = dict.fromkeys(PROBES.values(), 1)
    answers[PROBES[OFFLINE_VERIFY]] = RuntimeError("ORA-00942")

    assert OFFLINE_VERIFY not in probe(_Cursor(answers))


# ------------------------------------------------------------------ skipping ---


def test_a_missing_environment_and_a_missing_capability_are_different_skips() -> None:
    """§3: capability skips are correct, missing environments are a coverage
    gap. The wording differs so the two can be counted apart."""
    absent = decide_skip(environment(unreachable_reason="no container"))
    lacking = decide_skip(environment(capabilities=set()), required=[PASSWORD_ROLLOVER])

    assert absent is not None
    assert absent.startswith("environment unavailable")
    assert lacking is not None
    assert lacking.startswith("capability absent")
    assert PASSWORD_ROLLOVER in lacking


def test_a_capability_that_is_present_runs() -> None:
    assert (
        decide_skip(environment(capabilities={PASSWORD_ROLLOVER}), required=[PASSWORD_ROLLOVER])
        is None
    )


def test_requires_no_capability_is_the_negative_case_and_matters() -> None:
    """ "Rollover unavailable, so `--strategy rollover` fails at plan time" needs
    an environment that genuinely lacks it. Without this form the degradation
    paths are never exercised anywhere."""
    assert decide_skip(environment(capabilities=set()), forbidden=[PASSWORD_ROLLOVER]) is None

    blocked = decide_skip(
        environment(capabilities={PASSWORD_ROLLOVER}), forbidden=[PASSWORD_ROLLOVER]
    )
    assert blocked is not None
    assert "needs it absent" in blocked


def test_no_environment_at_all_is_an_environment_skip() -> None:
    reason = decide_skip(None, required=[PASSWORD_ROLLOVER])

    assert reason is not None
    assert reason.startswith("environment unavailable")


# -------------------------------------------------------------- the version ---


@pytest.mark.parametrize(
    ("version", "expected"),
    [("11.2.0.2.0", 30), ("12.1.0.2.0", 30), ("12.2.0.1.0", 128), ("23.26.2.0.0", 128)],
)
def test_the_byte_limit_follows_the_version(version: str, expected: int) -> None:
    """30 below 12.2, 128 from 12.2. No dictionary view states it, and #171
    makes it a required argument -- so a tier-1 test cannot build a statement
    without knowing it."""
    assert environment(version=version).max_password_bytes == expected


def test_an_unknown_version_does_not_pretend_to_be_old() -> None:
    """`below` answers false when it cannot tell, so an unreadable version gets
    the modern limit rather than silently capping every password at 30 bytes."""
    assert not below(None, (12, 2))
    assert not below("garbage", (12, 2))


# ------------------------------------------------------------------ the report ---


def test_the_matrix_reports_what_was_exercised() -> None:
    rendered = render_matrix([environment(capabilities={PASSWORD_ROLLOVER})], capability_skips=23)

    assert "capabilities exercised" in rendered
    assert "23ai Free" in rendered
    assert "23 tests skipped (capability absent), 0 skipped (environment unavailable)" in rendered


def test_the_matrix_is_ascii_so_a_redirected_run_survives() -> None:
    """P4's cp1252 story is about exactly this: a redirected stream on Windows
    takes the locale codepage, and a box-drawing character kills the writer
    mid-line. Our own report must not be the thing that dies."""
    rendered = render_matrix(
        [environment(capabilities=set(CAPABILITIES)), environment(name="11g XE")]
    )

    rendered.encode("cp1252")
    assert rendered.isascii()


def test_an_unavailable_environment_says_so_rather_than_reading_as_absent() -> None:
    """A column of dashes would say the database answered "no" to everything.
    It never answered at all, and the reason is the finding."""
    rendered = render_matrix([environment(unreachable_reason="no container")])

    assert "?" in rendered
    assert "no container" in rendered


def test_a_run_with_no_environment_still_renders_something_true() -> None:
    assert "no environment was configured" in render_matrix([])


# ------------------------------------------------------------- the wiring ---


@pytest.mark.requires_capability(PASSWORD_ROLLOVER)
def test_a_marked_test_reaches_the_environment_or_skips_saying_why(
    oracle_target: Environment,
) -> None:
    """The only test here that asks for a database, and it exists to prove the
    wiring rather than any behaviour.

    Without it the markers are pure logic that nothing has ever applied: the
    autouse gate, the session fixture and `decide_skip` are each tested apart,
    and "the mark actually skips instead of erroring" is the one claim only an
    end-to-end run can make. On a laptop with nothing up it skips with a reason,
    which is `04-testing.md` §1's rule working rather than a gap.
    """
    assert oracle_target.available
    assert PASSWORD_ROLLOVER in oracle_target.capabilities


# --------------------------------------------------------------- the dsn ---


@pytest.mark.parametrize(
    ("dsn", "host"),
    [
        ("localhost:1521/FREEPDB1", "localhost"),
        ("//localhost:1521/FREEPDB1", "localhost"),
        ("tcps://db.example.com:2484/svc", "db.example.com"),
        ("[::1]:1521/FREEPDB1", "[::1]"),
        ("localhost/FREEPDB1", "localhost"),
        ("CDBPROD", "CDBPROD"),
    ],
)
def test_the_host_comes_out_of_every_shape_a_dsn_is_written_in(dsn: str, host: str) -> None:
    """`//host:port/service` is what most Easy Connect documentation shows, and
    taking everything before the first `/` gets exactly that case backwards --
    returning nothing, which reads as *not loopback* and skips the tier-1 suite
    on the machine most likely to be running it.

    A TNS alias comes back as itself and is therefore treated as remote, which is
    the conservative reading: it resolves through `TNS_ADMIN` to somewhere this
    cannot see.
    """
    assert dsn_host(dsn) == host

"""The harness's own logic, which is tier 0 because most of it is not I/O.

Which environment, what to skip and how to report are decisions that need no
database — and they are the parts that would otherwise only be exercised on a
machine with containers running, which is the machine least likely to notice they
were wrong.

**What to ask is not here.** The probe set and the reading of an answer belong
to the driver and are tested beside it in `test_capabilities.py`; the harness
imports them rather than keeping a copy, so the two cannot disagree.
"""

from __future__ import annotations

from typing import Any

import pytest

from oracle_harness import (
    Environment,
    below,
    decide_skip,
    dsn_host,
    render_matrix,
)
from sopuli.driver.protocol import CAPABILITIES, PASSWORD_ROLLOVER


def environment(**kwargs: Any) -> Environment:
    return Environment(
        name=kwargs.pop("name", "23ai Free"), dsn="localhost:1521/FREEPDB1", **kwargs
    )


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
    [
        ("11.2.0.2.0", 30),
        ("12.2.0.1.0", 30),
        ("19.32.0.0.0", 30),
        ("21.3.0.0.0", 30),
        ("23.26.2.0.0", 128),
    ],
)
def test_the_byte_limit_follows_the_version(version: str, expected: int) -> None:
    """30 below 23, 128 from 23. No dictionary view states it, and the statement
    builder takes it as a required argument -- so a tier-1 test cannot build a
    statement without knowing it."""
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

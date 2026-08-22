"""Probing a real database (#177). Tier 1.

What to ask and how to read an answer is tier 0 (`test_capabilities.py`). What
is left is the half only a server can answer, and #195 is the argument for
writing it down: every probe in this module was *syntactically* fine, passed
every tier-0 test, and asked Oracle a question it does not have. Nothing but a
database catches that.

So the test that matters most here is the dullest one —
:func:`test_every_probe_is_a_question_oracle_can_answer`. It asserts no
capability, makes no claim about this release, and would have failed on the day
the broken probe was written.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from oracle_harness import Environment
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target, TargetOracle
from sopuli.driver.oracle.capabilities import PROBES, ProbeError, ScopeAssertionError, read
from sopuli.driver.protocol import SCOPE_TYPES, UNKNOWN, Credential
from sopuli.secrets import Secret

USER = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")

CORRELATION_ID = "3b8e1d05-6c47-4f92-b1ae-7d2c9f0a4e18"


@pytest.fixture
def session_module() -> Any:
    """`sopuli.driver.oracle.session`, imported only where there is a client."""
    return pytest.importorskip("sopuli.driver.oracle.session")


def _session(session_module: Any, dsn: str, oracle: TargetOracle | None = None) -> Any:
    driver = session_module.OracleDriver(env=os.environ, correlation_id=CORRELATION_ID)
    return driver.connect(
        ExpandedTarget(
            target=Target(
                name="tier1-oracle",
                type="oracle",
                dsn=dsn,
                admin=AdminCredential(username=USER, auth=AdminAuth(method="env")),
                oracle=oracle or TargetOracle(),
            ),
            index=0,
        ),
        Credential(username=USER, secret=Secret(PASSWORD)),
    )


def test_every_probe_is_a_question_oracle_can_answer(
    live_oracle: Environment, session_module: Any
) -> None:
    """#195, as the test that would have caught it.

    Each probe is run for its own sake. The answer is not asserted — a capability
    may legitimately be absent here, and pinning which ones would make this a
    test of the container rather than of the probes. What is asserted is that
    Oracle *understood the question*: an enumerated negative comes back as
    ``None``, and anything else raises
    :class:`~sopuli.driver.oracle.capabilities.ProbeError`.
    """
    with (
        _session(session_module, live_oracle.dsn) as session,
        session.connection.cursor() as cursor,
    ):
        for capability, statement in PROBES.items():
            try:
                read(cursor, statement)
            except ProbeError as failed:  # pragma: no cover - the failure path
                pytest.fail(f"the {capability} probe is not a valid question: {failed}")


def test_the_scope_is_what_the_database_says_it_is(
    live_oracle: Environment, session_module: Any
) -> None:
    """Observed, never configured — and nothing here consults a version."""
    with _session(session_module, live_oracle.dsn) as session:
        scope = session.scope()

        assert scope.type in SCOPE_TYPES
        assert scope.type != UNKNOWN, "a reachable database should resolve to a real scope"
        assert scope.db_version, "V$INSTANCE is in the documented grant set"
        assert scope.read_write is True, "the tier-1 container is not a standby"


def test_the_container_and_the_scope_agree(live_oracle: Environment, session_module: Any) -> None:
    """The two halves of one observation, which must not be able to disagree.

    Measured on 26ai: ``CDB$ROOT`` in the root and ``FREEPDB1`` in the PDB, with
    ``con_id`` 1 and 3 beside them. Asserted as a relationship rather than as a
    literal, so the test says something true of any target the lane is pointed
    at rather than only of the default one.
    """
    with _session(session_module, live_oracle.dsn) as session:
        scope = session.scope()

        if scope.container is None:
            assert scope.type == "non_cdb"
        elif scope.container.upper() == "CDB$ROOT":
            assert scope.type == "cdb_root"
        else:
            assert scope.type == "pdb"


def test_the_scope_is_probed_once_and_cached(live_oracle: Environment, session_module: Any) -> None:
    """Invariant 3's cache, asserted on identity.

    Equality would pass against a session that re-probed on every call and
    happened to get the same answer, which is the thing being ruled out: twenty-
    one PDBs answering separately is the reason the cache is per session, and a
    silent re-probe per call is eight extra round trips nobody asked for.
    """
    with _session(session_module, live_oracle.dsn) as session:
        assert session.scope() is session.scope()


# -------------------------------------------------------------- assertions ---


def test_a_wrong_container_is_caught_against_a_real_database(
    live_oracle: Environment, session_module: Any
) -> None:
    """#177's assertion check, on the estate mistake it exists for.

    A `dsn:` edit that repointed a target at a different container leaves a file
    that loads perfectly and connects perfectly, and nothing but the connection
    itself can notice. The declared name here is deliberately one no container in
    the lane can be called.
    """
    declared = TargetOracle(container="ACME_NO_SUCH_CONTAINER")

    with _session(session_module, live_oracle.dsn, declared) as session:
        with pytest.raises(ScopeAssertionError) as raised:
            session.check_assertions()

        message = str(raised.value)
        assert "ACME_NO_SUCH_CONTAINER" in message, "the declared value has to be named"
        found = session.scope().container
        assert found is not None
        assert found in message, "and so does the one the connection actually found"


def test_the_container_the_database_reports_satisfies_its_own_assertion(
    live_oracle: Environment, session_module: Any
) -> None:
    """The other direction, and the one that would catch a check that refuses
    everything: feeding back what the driver just found must pass."""
    with _session(session_module, live_oracle.dsn) as session:
        found = session.scope()
        declared = TargetOracle(scope=found.type, container=found.container)

    with _session(session_module, live_oracle.dsn, declared) as session:
        assert session.check_assertions() == found


def test_a_target_asserting_nothing_passes_against_a_real_database(
    live_oracle: Environment, session_module: Any
) -> None:
    """A target that makes no claim is not incompletely configured."""
    with _session(session_module, live_oracle.dsn) as session:
        assert session.check_assertions().type in SCOPE_TYPES

"""Connecting, against a real Oracle. Tier 1.

The first tests in this project that open a socket to a database. Everything
about *what* to send is tier 0 (`test_oracle_client.py`); what is left is the
half only a real server can answer:

* thick mode actually initialises against the installed Instant Client;
* the resolved credential actually authenticates;
* `DBMS_SESSION.SET_IDENTIFIER` actually lands where §5 says it does. That one
  is the reason this file exists rather than a mock: the whole value of the call
  is that a *third party* — the audit trail — can see it, and nothing but the
  database can confirm that.

The last group needs the client but no server, and drives a fake connection.
They live here rather than beside the tier-0 tests because they import
`sopuli.driver.oracle.session`, which imports `oracledb`; the module skips
rather than failing where it is absent.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from oracle_harness import Environment
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target
from sopuli.driver.protocol import AuthenticationError, Credential, Driver, DriverError
from sopuli.secrets import Secret

USER = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")

#: Who the *failed* login is attempted as, and deliberately **not** `USER`.
#:
#: Oracle counts failed logins per account and locks at the profile's
#: `FAILED_LOGIN_ATTEMPTS`, so a test that authenticates badly as `system` walks
#: the shared account toward a lockout every time it runs — and the tenth run
#: takes the tier-1 environment down for everything else. It is the same hazard
#: `04-testing.md` §5 makes a release gate of:
#: *a tool that locks production accounts while checking them is worse than no
#: tool*, which applies to the suite before it applies to the tool.
#:
#: An account that does not exist has no counter to increment and still answers
#: ORA-01017 — Oracle deliberately does not distinguish the two, which is the
#: property being relied on here.
NOBODY = "acme_no_such_user"

#: Shaped like the real thing (a UUID), because that is what goes into
#: `CLIENT_ID`, and the column is only 64 characters wide.
CORRELATION_ID = "9f1c2e7a-4d3b-4a51-9d2c-0b7f8e6a1234"


def target(dsn: str, *, name: str = "tier1-oracle") -> ExpandedTarget:
    return ExpandedTarget(
        target=Target(
            name=name,
            type="oracle",
            dsn=dsn,
            admin=AdminCredential(username=USER, auth=AdminAuth(method="env")),
        ),
        index=0,
    )


def credential(user: str = USER, password: str = PASSWORD) -> Credential:
    return Credential(username=user, secret=Secret(password))


def driver(session_module: Any, **kwargs: Any) -> Any:
    return session_module.OracleDriver(env=os.environ, correlation_id=CORRELATION_ID, **kwargs)


# ------------------------------------------------------- against a database ---


def test_a_connection_opens_and_closes(live_oracle: Environment, session_module: Any) -> None:
    """The whole of D3 in one assertion: thick mode initialises against the
    installed client and the credential authenticates."""
    with driver(session_module).connect(target(live_oracle.dsn), credential()) as session:
        assert session.connection is not None
        assert session.correlation_id == CORRELATION_ID

        with session.connection.cursor() as cursor:
            [answer] = cursor.execute("select 1 from dual").fetchone()

    assert answer == 1
    assert session.connection is None, "the context manager closes it"


def test_the_correlation_id_is_on_the_session(
    live_oracle: Environment, session_module: Any
) -> None:
    """§5's join, confirmed from the database's own side.

    `SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER')` is what
    `UNIFIED_AUDIT_TRAIL.CLIENT_ID` is populated from, so asserting it here
    asserts the property without needing an audit policy enabled on the test
    container — which §5 requires of a production database and which a fresh
    Free image does not have.

    This is what replaced the rejected package's local audit table (ADR-001):
    the run's id in the tool's JSON, in the database's trail and against the
    vault's metadata is what makes the three line up afterwards.
    """
    session = driver(session_module).connect(target(live_oracle.dsn), credential())
    try:
        with session.connection.cursor() as cursor:
            [found] = cursor.execute(
                "select sys_context('userenv', 'client_identifier') from dual"
            ).fetchone()
    finally:
        session.close()

    assert found == CORRELATION_ID


def test_a_wrong_password_is_an_authentication_failure_and_not_a_traceback(
    live_oracle: Environment, session_module: Any
) -> None:
    """ORA-01017, mapped rather than swallowed: the code survives, the
    server's own wording survives, and the exit code is 6 — the same one the
    vault side uses, so a scheduler need not know which half of the run could
    not authenticate.

    Attempted as `NOBODY` rather than as the real account, for the reason that
    constant gives at length: authenticating badly as a shared account is how a
    test suite locks the environment it needs.
    """
    with pytest.raises(AuthenticationError) as refused:
        driver(session_module).connect(
            target(live_oracle.dsn), credential(NOBODY, "definitely-not-the-password")
        )

    assert refused.value.code == "ORA-01017"


# ------------------------------------ the client, with nothing at the far end ---


def test_the_client_version_is_available_without_a_database(
    oracle_client: None, session_module: Any
) -> None:
    """A 23.x client reaches 19c and later (P4), so `doctor` can say a target is
    out of reach *before* anybody waits on a connection that cannot succeed.

    Takes `oracle_client`, which initialises thick mode and nothing else. Taking
    `live_oracle` — which connects — would mean a test named "without a
    database" needed one, and could not tell you whether the offline path
    worked at all.
    """
    version = session_module.client_version()

    assert version
    assert all(isinstance(part, int) for part in version)


def test_the_oracle_driver_is_p1s_driver(session_module: Any) -> None:
    """The protocol is structural, so this is what keeps
    `sopuli/driver/protocol.py` and the implementation one interface. A
    `connect` needing extra keyword arguments fails it — which is what the first
    draft had, and what review caught."""
    assert isinstance(driver(session_module), Driver)


# --------------------------------------------- the paths a server cannot show ---


class FakeCursor:
    """Records what it was asked, and refuses if told to."""

    def __init__(self, refuse: Exception | None = None) -> None:
        self.refuse = refuse
        self.calls: list[tuple[str, list[Any]]] = []

    def callproc(self, name: str, args: list[Any]) -> None:
        self.calls.append((name, args))
        if self.refuse is not None:
            raise self.refuse

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *_: object) -> None:
        return None


class FakeConnection:
    """The smallest thing `connect` configures after opening one."""

    def __init__(self, refuse: Exception | None = None) -> None:
        self.call_timeout = -1
        self.closed = False
        self.opened_cursor = FakeCursor(refuse)

    def cursor(self) -> FakeCursor:
        return self.opened_cursor

    def close(self) -> None:
        self.closed = True


def connected(session_module: Any, monkeypatch: pytest.MonkeyPatch, connection: Any) -> Any:
    """Drive `OracleDriver.connect` against ``connection`` instead of a server."""
    import oracledb

    monkeypatch.setattr(oracledb, "connect", lambda **_: connection)
    return driver(session_module, **{})


def test_the_resolved_query_timeout_reaches_the_connection(
    oracle_client: None, session_module: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Resolved, converted **and assigned**.

    Tier 0 checks the arithmetic and the live tests use the default, so a
    regression that stopped assigning `call_timeout` altogether would have
    passed everything — which is what review pointed out.
    """
    from sopuli.driver.oracle.client import Timeouts

    connection = FakeConnection()
    driving = connected(session_module, monkeypatch, connection)

    session = session_module.OracleDriver(
        env=driving.env, correlation_id=CORRELATION_ID, timeouts=Timeouts(query_s=90)
    ).connect(target("localhost:1521/NOWHERE"), credential())

    assert connection.call_timeout == 90_000
    assert session.connection is connection


def test_a_session_that_cannot_be_labelled_is_closed(
    oracle_client: None, session_module: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The audit control, exercised on the path that trips it.

    §5 makes `SET_IDENTIFIER` the compensating control for having no audit table
    of our own, so a session that cannot carry the run's id is worse than no
    session: its work would appear in the trail with nothing to join it back to.
    Closing it is the honest outcome, and until review pointed it out only the
    *successful* path had a test — the wrong half to cover.
    """
    import oracledb

    refusal = oracledb.DatabaseError("ORA-00942: table or view does not exist")
    connection = FakeConnection(refuse=refusal)
    driving = connected(session_module, monkeypatch, connection)

    with pytest.raises(DriverError) as raised:
        driving.connect(target("localhost:1521/NOWHERE"), credential())

    assert connection.closed, "a session that cannot be labelled must not be handed back"
    # A `DriverError` rather than the vendor exception: the driver maps it, keeping
    # the ORA- code and the server's wording, so a caller sees the same shape here
    # as for every other database failure.
    assert raised.value.code == "ORA-00942"


def test_the_identifier_is_bound_and_never_interpolated(
    oracle_client: None, session_module: Any
) -> None:
    """Invariant 14, from the other side.

    `V$SQL_BIND_CAPTURE` keeps bind values in clear, which is why a password must
    never be bound — and precisely why a correlation id is safe to bind and worth
    having captured. The dangerous habit is the inverse: a `SET_IDENTIFIER`
    assembled by string concatenation is the pattern that later writes a password
    into SQL text, so the id is asserted to travel as an *argument*.
    """
    connection = FakeConnection()

    session_module.set_identifier(connection, CORRELATION_ID)

    [(procedure, arguments)] = connection.opened_cursor.calls
    assert procedure == "dbms_session.set_identifier"
    assert arguments == [CORRELATION_ID]

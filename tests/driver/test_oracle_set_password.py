"""Issuing the ``ALTER USER`` against a real Oracle. Tier 1.

The statement's *shape* is tier 0 and so are invariants 13 and 14. What
only a server can answer is whether it is accepted — and, more usefully, what
happens when it is not. Both refusal paths were measured on 26ai Free
23.26.2.0.0 before this was written:

    a weak password against `ora12c_strong_verify_function`  ->  ORA-28003
    the account's current password, with PASSWORD_REUSE_MAX  ->  ORA-28007

The error mapper maps both to `policy`, so what this file pins is that they arrive
as those and not as a generic failure — because UC-1 §4's bounded regeneration
is the only correct response to either, and a run that mistook one for a
connection problem would stop instead of drawing another password.

The verify-function case is asserted **on the error, never on `DBA_PROFILES`**:
in a PDB the `PASSWORD_VERIFY_FUNCTION` limit reads `FROM ROOT` while the
function is in fact enforcing (measured on 26ai Free 23.26.2.0.0), so the
dictionary is the one witness that cannot be trusted here.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from typing import Any

import pytest

from oracle_harness import Environment
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target
from sopuli.driver.oracle.limits import (
    CODECS,
    FALLBACK,
    LEGACY_MAX_BYTES,
    MODERN_MAX_BYTES,
    max_bytes,
)
from sopuli.driver.protocol import Credential, DriverError
from sopuli.secrets import Secret

USER = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")

CORRELATION_ID = "7d41f8b2-3a6e-4c19-95d0-8b2e1f7a6c04"

ACCOUNT = "acme_billing_user"
STRICT_PROFILE = "acme_strict_prof"

#: Satisfies `ora12c_strong_verify_function`, which wants 9+ characters and two
#: or more digits — measured, by watching it refuse a password with one.
COMPLIANT = "Str0ng-Pa55-quiXa"
ROTATED = "N3wer-Pa66-zoRba"
WEAK = "short"


@pytest.fixture
def session_module() -> Any:
    return pytest.importorskip("sopuli.driver.oracle.session")


@pytest.fixture
def session(live_oracle: Environment, session_module: Any) -> Iterator[Any]:
    driver = session_module.OracleDriver(env=os.environ, correlation_id=CORRELATION_ID)
    opened = driver.connect(
        ExpandedTarget(
            target=Target(
                name="tier1-oracle",
                type="oracle",
                dsn=live_oracle.dsn,
                admin=AdminCredential(username=USER, auth=AdminAuth(method="env")),
            ),
            index=0,
        ),
        Credential(username=USER, secret=Secret(PASSWORD)),
    )
    try:
        yield opened
    finally:
        opened.close()


def _run(session: Any, *statements: str) -> None:
    with session.connection.cursor() as cursor:
        for statement in statements:
            cursor.execute(statement)


def _drop(session: Any) -> None:
    for statement in (f"drop user {ACCOUNT} cascade", f"drop profile {STRICT_PROFILE} cascade"):
        with contextlib.suppress(Exception):
            _run(session, statement)


@pytest.fixture
def account(session: Any) -> Iterator[Any]:
    """An ordinary account on the DEFAULT profile."""
    _drop(session)
    _run(session, f'create user {ACCOUNT} identified by "{COMPLIANT}"')
    try:
        yield session
    finally:
        _drop(session)


@pytest.fixture
def strict_account(session: Any) -> Iterator[Any]:
    """An account whose profile enforces complexity and forbids reuse.

    Skipped where `ora12c_strong_verify_function` does not exist, on the server's
    own answer rather than on a version: `ORA-07443: function
    ORA12C_STRONG_VERIFY_FUNCTION not found`, measured on 11g XE 11.2.0.2.0,
    where the 11g equivalent is `verify_function_11G` and enforces
    different rules. `test/oracle-init/01_test_profiles.sql` already skips
    `SOPULI_STRONG` there for the same reason and says so rather than aborting.

    Not a coverage gap, and not worth an 11g branch either: what these tests
    assert is that the *server's* refusal arrives as a policy error rather than a
    crash, and pairing that with a second function's rules would be asserting
    Oracle's password rules rather than the tool's handling of them.
    """
    _drop(session)
    try:
        _run(
            session,
            f"create profile {STRICT_PROFILE} limit "
            f"password_verify_function ora12c_strong_verify_function password_reuse_max 3",
        )
    except Exception as exc:  # noqa: BLE001 -- classified on the next line
        if "ORA-07443" not in str(exc):
            raise
        pytest.skip("this release has no ora12c_strong_verify_function")
    _run(
        session,
        f'create user {ACCOUNT} identified by "{COMPLIANT}" profile {STRICT_PROFILE}',
    )
    try:
        yield session
    finally:
        _drop(session)


def test_the_password_is_set_and_the_result_says_so(account: Any) -> None:
    result = account.set_password(ACCOUNT, Secret(ROTATED))

    assert result.changed is True


def test_the_new_password_actually_authenticates(
    account: Any, session_module: Any, live_oracle: Environment
) -> None:
    """The only assertion that proves the statement did what it claimed. A
    `ChangeResult` is the tool's word for it; a login is the database's."""
    _run(account, f"grant create session to {ACCOUNT}")
    account.set_password(ACCOUNT, Secret(ROTATED))

    driver = session_module.OracleDriver(env=os.environ, correlation_id=CORRELATION_ID)
    opened = driver.connect(
        ExpandedTarget(
            target=Target(
                name="as-the-account",
                type="oracle",
                dsn=live_oracle.dsn,
                admin=AdminCredential(username=ACCOUNT, auth=AdminAuth(method="env")),
            ),
            index=0,
        ),
        Credential(username=ACCOUNT, secret=Secret(ROTATED)),
    )
    opened.close()


def test_the_name_in_the_statement_is_the_database_s_spelling(account: Any) -> None:
    """An Oracle quoted identifier is case-sensitive, so a statement built from
    the config's spelling would get `ORA-01918` against a database that plainly
    has the account. The caller here passes lower case and the account is
    `ACME_BILLING_USER`."""
    result = account.set_password(ACCOUNT.lower(), Secret(ROTATED))

    assert result.changed is True


def test_a_missing_account_is_refused_before_any_statement(session: Any) -> None:
    _drop(session)

    with pytest.raises(DriverError, match="does not exist"):
        session.set_password("acme_no_such_user", Secret(ROTATED))


def test_a_password_the_verify_function_refuses_arrives_as_policy(strict_account: Any) -> None:
    """`ORA-28003`, and it must stay `policy`: UC-1 §4's bounded regeneration is
    the only correct response, and a run that read this as a connection problem
    would stop instead of drawing another password.

    Asserted on the error rather than on `DBA_PROFILES`, because in a PDB the
    `PASSWORD_VERIFY_FUNCTION` limit reads `FROM ROOT` while the function is
    enforcing.
    """
    with pytest.raises(DriverError) as raised:
        strict_account.set_password(ACCOUNT, Secret(WEAK))

    assert raised.value.code == "ORA-28003"
    assert raised.value.category == "policy"


def test_reusing_the_current_password_arrives_as_policy(strict_account: Any) -> None:
    """`ORA-28007`. The same value must never be sent again — the error mapper's
    rule is that an unmapped code is terminal and never regenerates, and this
    one regenerates with a *different* value or not at all."""
    with pytest.raises(DriverError) as raised:
        strict_account.set_password(ACCOUNT, Secret(COMPLIANT))

    assert raised.value.code == "ORA-28007"
    assert raised.value.category == "policy"


def test_the_byte_limit_is_this_database_s_own(session: Any) -> None:
    """Resolved from the target rather than hard-coded, which is the test's name.

    **The character set is asserted against what the database says, not against
    a constant.** It is `AL32UTF8` on 23.26.2.0.0, 21.3.0.0.0, 18.4.0.0.0 and
    11.2.0.2.0, but 12.2.0.1.0's registry image is `WE8DEC` in both the root and
    the PDB -- a character set :data:`CODECS` does not map, so the tool measures
    in ASCII there, which is `limits.py`'s deliberate fallback rather than a
    fault. A constant would be a fact about the images, not about the tool; what
    this test is named for is that the limit comes from the target.

    **`max_bytes` is asserted against the tool's own rule**, not against what the
    server enforces -- this test sends no over-long password, so it cannot show
    the two agree. The rule is 30 bytes below 23 and 128 from it. What this test
    is named for is the narrow thing: the limit comes from *this session's*
    reported version.
    """
    limit = session.byte_limit()
    with session.connection.cursor() as cursor:
        cursor.execute(
            "select value from nls_database_parameters where parameter = 'NLS_CHARACTERSET'"
        )
        (reported,) = cursor.fetchone()

    assert limit.charset == reported
    assert limit.encoding == CODECS.get(reported, FALLBACK)
    assert limit.max_bytes == max_bytes(session.scope().db_version)
    assert limit.max_bytes in (LEGACY_MAX_BYTES, MODERN_MAX_BYTES)


def test_the_byte_limit_is_resolved_once_and_cached(session: Any) -> None:
    assert session.byte_limit() is session.byte_limit()


def test_an_over_long_password_is_refused_before_the_wire(account: Any) -> None:
    """The client-side refusal is what produces a message naming the limit; the
    server's own answer to this is `ORA-28003`, which says only that some rule
    was broken."""
    with pytest.raises(DriverError, match="bytes"):
        account.set_password(ACCOUNT, Secret("Aa11-" + "x" * 200))


# ------------------------------------------- the client, but no server ------


class _Cursor:
    """A cursor that records, so a test can prove nothing was sent."""

    def __init__(self) -> None:
        self.executed: list[str] = []

    def execute(self, sql: str, parameters: Any = None, /) -> None:
        self.executed.append(sql)

    def fetchone(self) -> Any:
        return None

    def fetchall(self) -> Any:
        return []

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *_: object) -> None:
        return None


class _Connection:
    def __init__(self) -> None:
        self.opened = _Cursor()

    def cursor(self) -> _Cursor:
        return self.opened

    def close(self) -> None:
        return None


def test_a_read_only_target_is_refused_before_any_statement(session_module: Any) -> None:
    """P1 wants a standby refused **up front**, not as a failed `ALTER USER` half
    way through a run.

    `assert_scope` deliberately leaves out `require_read_write`, so that
    `creds check` keeps working against a physical standby — which makes calling
    it the mutating caller's job, and this is the mutating caller. Left to a
    command that does not exist yet it would be a refusal that cannot fire.

    Driven against a fake connection because a standby is not something the
    tier-1 lane can stand up, and the assertion that matters is that **nothing
    reached the cursor**.
    """
    from sopuli.driver.oracle.capabilities import ReadOnlyTargetError
    from sopuli.driver.protocol import Scope

    connection = _Connection()
    session = session_module.OracleSession(
        connection=connection,
        target=ExpandedTarget(
            target=Target(name="orders-dr", type="oracle", dsn="dr.example.com:1521/orders"),
            index=0,
        ),
        correlation_id=CORRELATION_ID,
    )
    session._scope = Scope(type="pdb", open_mode="READ ONLY", read_write=False)

    with pytest.raises(ReadOnlyTargetError) as raised:
        session.set_password(ACCOUNT, Secret(ROTATED))

    assert "orders-dr" in str(raised.value)
    assert connection.opened.executed == [], "nothing may reach the wire"


def test_finishing_a_rollover_on_a_read_only_target_is_refused_before_any_statement(
    session_module: Any,
) -> None:
    """Without the guard, a standby would reach `ALTER USER ... EXPIRE PASSWORD
    ROLLOVER PERIOD` and fail there, so `finish_rollover` refuses before the
    state is even read, as `set_password` does."""
    from sopuli.driver.oracle.capabilities import ReadOnlyTargetError
    from sopuli.driver.protocol import Scope

    connection = _Connection()
    session = session_module.OracleSession(
        connection=connection,
        target=ExpandedTarget(
            target=Target(name="orders-dr", type="oracle", dsn="dr.example.com:1521/orders"),
            index=0,
        ),
        correlation_id=CORRELATION_ID,
    )
    session._scope = Scope(type="pdb", open_mode="READ ONLY", read_write=False)

    with pytest.raises(ReadOnlyTargetError) as raised:
        session.finish_rollover(ACCOUNT)

    assert "orders-dr" in str(raised.value)
    assert connection.opened.executed == [], "nothing may reach the wire"

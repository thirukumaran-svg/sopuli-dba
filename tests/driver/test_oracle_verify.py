"""Verifying a password against a real Oracle (#180). Tier 1.

The arithmetic is tier 0 (`test_verification.py`). What only a server can answer
is whether the codes mean what this code believes, and whether the guard actually
holds — which is **release gate 4**:

    a profile with FAILED_LOGIN_ATTEMPTS 3, check a deliberately drifted account
    five times, and the account never locks.

`04-testing.md` §5 makes that a gate because a tool that locks production
accounts while checking them is worse than no tool. It is the one test in this
repository whose failure means "do not ship", so it is written to fail loudly
rather than skip quietly: the profile comes from the container init script, and
so does the `SELECT ON SYS.USER$` grant the guard needs.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from typing import Any

import pytest

from oracle_harness import Environment
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target
from sopuli.driver.protocol import (
    FAIL,
    OFFLINE_VERIFY,
    PASS,
    PASSWORD_ROLLOVER,
    SKIPPED,
    UNAVAILABLE,
    Credential,
    DriverError,
    Session,
    UnsupportedCapabilityError,
)
from sopuli.secrets import Secret

USER = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")

CORRELATION_ID = "2f6c8a90-1b47-4e35-8d92-6a0f3c5b7e21"

ACCOUNT = "acme_check_user"
LOCKOUT_PROFILE = "sopuli_lockout"
ROLLOVER_PROFILE = "sopuli_rollover"

CORRECT = "Corr3ct-Pa55-word"
WRONG = "Wr0ng-Pa55-word"


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


def _status(session: Any) -> str:
    state = session.describe_user(ACCOUNT)
    assert state is not None
    return str(state.status)


def _drop(session: Any) -> None:
    with contextlib.suppress(Exception):
        _run(session, f"drop user {ACCOUNT} cascade")


@pytest.fixture
def account(session: Any) -> Iterator[Any]:
    """An account on the DEFAULT profile — no lockout to trip over."""
    _drop(session)
    _run(
        session,
        f'create user {ACCOUNT} identified by "{CORRECT}"',
        f"grant create session to {ACCOUNT}",
    )
    try:
        yield session
    finally:
        _drop(session)


@pytest.fixture
def guarded_account(session: Any) -> Iterator[Any]:
    """An account on `SOPULI_LOCKOUT`, which the init script creates with
    `FAILED_LOGIN_ATTEMPTS 3`."""
    _drop(session)
    _run(
        session,
        f'create user {ACCOUNT} identified by "{CORRECT}" profile {LOCKOUT_PROFILE}',
        f"grant create session to {ACCOUNT}",
    )
    try:
        yield session
    finally:
        _drop(session)


# ------------------------------------------------------------- the outcomes ---


def test_the_session_is_now_a_driver_session(session: Any) -> None:
    """#177 through #180, arrived. The protocol is structural, so this became
    true by acquiring the last method rather than by declaring anything — and it
    is worth asserting, because a signature drifting out of shape would otherwise
    be invisible until a command was written against the protocol."""
    assert isinstance(session, Session)


def test_the_right_password_passes(account: Any) -> None:
    result = account.verify_password(ACCOUNT, Secret(CORRECT))

    assert result.result == PASS
    assert result.method == "login"


def test_the_wrong_password_is_drift_and_not_an_exception(account: Any) -> None:
    """Exit 3 rather than a crash is what makes `check` schedulable — a wrong
    password is a finding, not a failure of the tool."""
    result = account.verify_password(ACCOUNT, Secret(WRONG))

    assert result.result == FAIL


def test_a_locked_account_is_unverifiable_rather_than_drifted(account: Any) -> None:
    """Measured: a locked account answers `ORA-28000` whether the password is
    right or wrong, so nothing was learned about the password. Calling it drift
    would start a rotation for an account whose password is fine."""
    _run(account, f"alter user {ACCOUNT} account lock")

    result = account.verify_password(ACCOUNT, Secret(CORRECT))

    assert result.result == UNAVAILABLE
    assert result.detail is not None
    assert "locked" in result.detail
    assert "LOCKED" in _status(account), "and the status is reported either way"


def test_an_expired_password_still_passes(account: Any) -> None:
    """The one that reads backwards, against the real server.

    `ORA-28001` comes back only when the password is **correct**; a wrong one
    against the same expired account still answers `ORA-01017`. Both halves are
    asserted, because it is the pair that makes the point.
    """
    _run(account, f"alter user {ACCOUNT} password expire")

    assert account.verify_password(ACCOUNT, Secret(CORRECT)).result == PASS
    assert account.verify_password(ACCOUNT, Secret(WRONG)).result == FAIL


def test_a_missing_account_is_unavailable(session: Any) -> None:
    _drop(session)

    result = session.verify_password(ACCOUNT, Secret(CORRECT))

    assert result.result == UNAVAILABLE
    assert result.detail is not None
    assert "no account" in result.detail


# --------------------------------------------------------- method="hash" ---
#
# #437: compare with the stored 12C verifier instead of logging in. Every test
# here asserts on the *account* as well as on the result, because the claim being
# tested is that nothing happened to it.
#
# Whether the account *has* a 12C verifier is read from the account, never from
# the release (invariant 3): 11g's accounts are `10G 11G`, and a 12.1+ server can
# hold one without `12C` too. The comparison tests skip where it is absent, and
# the refusal test is the one that runs there instead.


def _needs_12c(session: Any) -> None:
    state = session.describe_user(ACCOUNT)
    assert state is not None
    if "12C" not in state.password_versions:
        pytest.skip(
            f"{ACCOUNT} has no 12C verifier here (PASSWORD_VERSIONS "
            f"{' '.join(state.password_versions)}); the refusal test runs instead"
        )


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_hash_passes_on_the_right_password_without_a_login(account: Any) -> None:
    _needs_12c(account)
    result = account.verify_password(ACCOUNT, Secret(CORRECT), method="hash")

    assert result.method == "hash"
    assert result.result == PASS
    assert result.detail is not None
    assert "current 12C verifier" in result.detail
    assert "no login was attempted" in result.detail


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_hash_fails_on_the_wrong_password(account: Any) -> None:
    _needs_12c(account)
    result = account.verify_password(ACCOUNT, Secret(WRONG), method="hash")

    assert result.result == FAIL


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_hash_spends_nothing_against_the_lockout_counter(guarded_account: Any) -> None:
    """Release gate 4's scenario, through the method that makes it moot.

    Five wrong comparisons against `FAILED_LOGIN_ATTEMPTS 3`: under `login` the
    second to fifth are refused by the guard; under `hash` all five are answered,
    because none of them costs anything, and `LCOUNT` stays at zero.
    """
    _needs_12c(guarded_account)
    results = [
        guarded_account.verify_password(ACCOUNT, Secret(WRONG), method="hash") for _ in range(5)
    ]

    assert all(r.result == FAIL for r in results), "every one answered, none skipped"
    assert not any(r.lockout_margin_hit for r in results)
    assert results[-1].failed_logins == 0, "no attempt was made, so nothing was counted"
    assert "LOCKED" not in _status(guarded_account)


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_hash_compares_a_locked_account(account: Any) -> None:
    """The thing a login cannot do: a locked account answers `ORA-28000` to the
    right password and the wrong one alike. Its lock is still `check`'s to report,
    from the status; the comparison only says whether the vault has its password."""
    _needs_12c(account)
    _run(account, f"alter user {ACCOUNT} account lock")

    assert account.verify_password(ACCOUNT, Secret(CORRECT), method="hash").result == PASS
    assert account.verify_password(ACCOUNT, Secret(WRONG), method="hash").result == FAIL


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_hash_on_a_missing_account_is_unavailable(session: Any) -> None:
    _drop(session)

    result = session.verify_password(ACCOUNT, Secret(CORRECT), method="hash")

    assert result.result == UNAVAILABLE


@pytest.mark.requires_capability(OFFLINE_VERIFY)
@pytest.mark.requires_capability(PASSWORD_ROLLOVER)
def test_hash_tells_the_two_passwords_of_a_rollover_window_apart(session: Any) -> None:
    """Both authenticate during a window, so a login cannot say which the vault
    holds. `T:` is the previous password and `t:` the current (#432)."""
    _drop(session)
    _run(
        session,
        f'create user {ACCOUNT} identified by "{WRONG}" profile {ROLLOVER_PROFILE}',
        f'alter user {ACCOUNT} identified by "{CORRECT}"',
    )
    try:
        current = session.verify_password(ACCOUNT, Secret(CORRECT), method="hash")
        previous = session.verify_password(ACCOUNT, Secret(WRONG), method="hash")
        neither = session.verify_password(ACCOUNT, Secret("N31ther-Pa55-word"), method="hash")
    finally:
        _drop(session)

    assert current.result == PASS
    assert "current" in (current.detail or "")
    assert previous.result == PASS, "it authenticates until the window closes"
    assert "previous" in (previous.detail or "")
    assert neither.result == FAIL


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_hash_refuses_an_account_with_no_12c_verifier(account: Any) -> None:
    """11g, or any account whose PASSWORD_VERSIONS lacks 12C: nothing to compare,
    and `S:` or 10G are never a fallback because both are weaker than a login
    (#433). A refusal naming the target, which is invariant 4's shape."""
    state = account.describe_user(ACCOUNT)
    assert state is not None
    if "12C" in state.password_versions:
        pytest.skip(f"{ACCOUNT} has a 12C verifier here; the comparison tests cover it")

    with pytest.raises(UnsupportedCapabilityError) as refused:
        account.verify_password(ACCOUNT, Secret(CORRECT), method="hash")

    assert "12C verifier" in refused.value.capability
    assert refused.value.target == "tier1-oracle"


def _offline_session(session_module: Any, capabilities: frozenset[str]) -> Any:
    """A session with a scope and nothing behind it: the refusals below happen
    before anything would reach a server."""
    from sopuli.driver.protocol import Scope

    offline = session_module.OracleSession(
        connection=object(),
        target=ExpandedTarget(
            target=Target(name="orders-pdb", type="oracle", dsn="db.example.com:1521/orders"),
            index=0,
        ),
        correlation_id=CORRELATION_ID,
    )
    offline._scope = Scope(type="pdb", capabilities=capabilities)
    return offline


def test_hash_without_the_sys_user_grant_is_refused_naming_the_target(
    session_module: Any,
) -> None:
    """The branch every live test above skips: without `SELECT ON SYS.USER$`
    there is no verifier to read, and `login` is not substituted for it."""
    offline = _offline_session(session_module, frozenset())

    with pytest.raises(UnsupportedCapabilityError) as refused:
        offline.verify_password(ACCOUNT, Secret(CORRECT), method="hash")

    assert refused.value.capability == OFFLINE_VERIFY
    assert refused.value.target == "orders-pdb"
    assert "GRANT SELECT ON SYS.USER$" in (refused.value.hint or "")


def test_hash_of_a_password_the_character_set_cannot_hold_is_refused(
    session_module: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#572's WE8DEC case at the session: a refusal naming the target and the
    set, rather than a `fail` that would report drift on a password that logs in.
    No live database in the stack has a non-Unicode set but 12.2's, which is
    maintainer-only, so the dictionary reads are stubbed."""
    from sopuli.driver.protocol import UserState
    from sopuli.passwords import ByteLimit

    offline = _offline_session(session_module, frozenset({OFFLINE_VERIFY}))
    offline._limit = ByteLimit(max_bytes=30, encoding="ascii", charset="WE8DEC")

    class _Cursor:
        def __enter__(self) -> Any:
            return self

        def __exit__(self, *_: object) -> None:
            return None

    offline.connection = type("_Connection", (), {"cursor": lambda self: _Cursor()})()
    monkeypatch.setattr(
        session_module,
        "login_state",
        lambda _cursor, _account: UserState(name="ACME_CHECK_USER", status="OPEN"),
    )
    monkeypatch.setattr(session_module, "failed_logins", lambda _cursor, _name: 0)
    spare4 = "S:" + "0" * 60 + ";T:" + "A" * 160
    monkeypatch.setattr(session_module, "stored_verifiers", lambda _cursor, _name: spare4)

    with pytest.raises(UnsupportedCapabilityError) as refused:
        offline.verify_password(ACCOUNT, Secret("Corr3ct-Pa55-wΩrd"), method="hash")

    assert refused.value.target == "orders-pdb"
    assert "WE8DEC" in (refused.value.hint or "")
    assert "Ω" not in str(refused.value) + (refused.value.hint or "")


def test_both_is_still_refused_rather_than_faked(account: Any) -> None:
    """`both` is login plus the comparison, and arrives with `check --method`. A
    driver that quietly did one of the two would report a check it did not make."""
    with pytest.raises(UnsupportedCapabilityError):
        account.verify_password(ACCOUNT, Secret(CORRECT), method="both")


# ---------------------------------------------------------- release gate 4 ---


def test_release_gate_4_checking_a_drifted_account_never_locks_it(
    guarded_account: Any, oracle_target: Environment
) -> None:
    """**The gate.** `04-testing.md` §5, and §6's rule that a gate does not skip.

    `FAILED_LOGIN_ATTEMPTS 3`, a password that is wrong, and five checks. Without
    the guard the account locks on the third; with it, exactly one attempt is
    spent and the remaining four are refused before they reach the server.

    The assertion is on the *account*, not on the tool: whatever the results say,
    `ACCOUNT_STATUS` must never contain `LOCKED`. That is the property that
    matters at 03:00 on a production estate.

    **No `requires_capability` marker, deliberately.** §6 opens with "not tests
    that can be skipped", and routing this through the generic capability gate
    would mean a missing `SELECT ON SYS.USER$` grant reports a tidy skip while
    the safety property goes unverified — a broken setup looking green, which is
    the one outcome a release gate must not have. So the guard's absence fails
    here, with a message saying what to grant.
    """
    if OFFLINE_VERIFY not in oracle_target.capabilities:
        pytest.fail(
            "release gate 4 cannot run without the LCOUNT guard, and a gate does not skip "
            "(04-testing.md §6). Grant SELECT ON SYS.USER$ to the test account -- "
            "test/oracle-init/01_test_profiles.sql does it, and it needs CONTAINER=ALL "
            "because the init script runs in CDB$ROOT while the suite connects to a PDB"
        )

    results = [guarded_account.verify_password(ACCOUNT, Secret(WRONG)) for _ in range(5)]

    assert "LOCKED" not in _status(guarded_account), (
        "the guard failed and the account is locked — this is the release gate"
    )

    assert results[0].result == FAIL, "the first attempt is spent, and it is drift"
    assert all(r.result == SKIPPED for r in results[1:]), "the rest are refused, not attempted"
    assert all(r.lockout_margin_hit for r in results[1:])
    assert results[1].detail is not None
    assert "margin" in results[1].detail


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_the_guard_does_not_make_an_exception_for_a_password_it_cannot_know_is_right(
    guarded_account: Any,
) -> None:
    """The guard is **sticky**, and that is a real operational property.

    Once the margin is breached, *every* further attempt is refused — including
    one carrying the correct password. It has to be: the guard cannot know the
    password is right without spending an attempt to find out, and spending the
    last of the margin on a guess is exactly what it exists to prevent.

    The consequence, on a profile as tight as this one (`FAILED_LOGIN_ATTEMPTS
    3`, default margin 2), is that a single drift makes the account
    unverifiable by this tool until something *else* clears `LCOUNT` — the
    application logging in successfully, or an operator widening the margin
    deliberately. `check` reports `skipped` with the reason rather than a
    verdict, which is the honest answer and not a failure.

    Written down here because it surfaced as a failing test that looked like a
    bug and is not one.
    """
    assert guarded_account.verify_password(ACCOUNT, Secret(WRONG)).result == FAIL

    blocked = guarded_account.verify_password(ACCOUNT, Secret(CORRECT))

    assert blocked.result == SKIPPED, "the right password is refused too"
    assert blocked.lockout_margin_hit


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_a_successful_check_clears_the_counter(guarded_account: Any) -> None:
    """Mitigation 3, and it is the database's doing rather than ours.

    Reaching the success at all needs the margin widened, which is the test
    above's finding turned into a fixture: `lockout_margin=0` spends the
    remaining budget deliberately, the login succeeds, and Oracle puts `LCOUNT`
    back to zero — after which an ordinary check is allowed again with no
    special pleading.
    """
    assert guarded_account.verify_password(ACCOUNT, Secret(WRONG)).result == FAIL
    assert guarded_account.verify_password(ACCOUNT, Secret(WRONG)).result == SKIPPED

    recovered = guarded_account.verify_password(ACCOUNT, Secret(CORRECT), lockout_margin=0)
    assert recovered.result == PASS

    again = guarded_account.verify_password(ACCOUNT, Secret(WRONG))
    assert again.result == FAIL, "the counter was reset, so there is budget again"


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_the_counter_is_reported_with_the_result(guarded_account: Any) -> None:
    """`failed_logins` and `failed_login_limit` travel with the answer, so a
    report can show how close the account is without a second query."""
    guarded_account.verify_password(ACCOUNT, Secret(WRONG))
    result = guarded_account.verify_password(ACCOUNT, Secret(WRONG))

    assert result.failed_logins == 1
    assert result.failed_login_limit == "3"


# ------------------------------------------- the client, but no server ------


def test_an_unreachable_target_raises_rather_than_reporting_a_finding(
    account: Any, session_module: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A target nobody can reach is not an account whose password failed.

    Driven by making the *verification* connection fail while the admin session
    stays up, which is the shape that matters: `_attempt` opens its own
    connection, and a listener that has gone away between the two is exactly how
    this arises in an estate.
    """
    import oracledb

    def unreachable(**_: Any) -> Any:
        raise oracledb.DatabaseError("ORA-12541: TNS:no listener")

    monkeypatch.setattr(session_module.oracledb, "connect", unreachable)

    with pytest.raises(DriverError) as raised:
        account.verify_password(ACCOUNT, Secret(CORRECT))

    assert raised.value.category == "connectivity"

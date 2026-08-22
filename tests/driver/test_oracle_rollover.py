"""Rollover against a real Oracle (#181). Tier 1.

The arithmetic is tier 0 (`test_rollover.py`). What only a server can answer is
the property the whole strategy rests on — **both passwords authenticate during
the window** — and that the finish statement really ends it.

Measured before any of this was written, on 26ai Free 23.26.2.0.0 with
`PASSWORD_ROLLOVER_TIME 1/24`: an account rotated old → new accepted both
logins; after `ALTER USER … EXPIRE PASSWORD ROLLOVER PERIOD` the old one
answered `ORA-01017` and the new one still worked.
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
    PASS,
    PASSWORD_ROLLOVER,
    Credential,
    DriverError,
    UnsupportedCapabilityError,
)
from sopuli.secrets import Secret

USER = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")

CORRELATION_ID = "8a3f2d61-7c05-4b9e-a2d8-4f1b6e0c9375"

ACCOUNT = "acme_rollover_user"
ROLLOVER_PROFILE = "sopuli_rollover"
PLAIN_PROFILE = "sopuli_lockout"

OLD = "Old-Pa55-word1"
NEW = "New-Pa55-word2"


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
    with contextlib.suppress(Exception):
        _run(session, f"drop user {ACCOUNT} cascade")


def _make(session: Any, profile: str) -> None:
    _drop(session)
    _run(
        session,
        f'create user {ACCOUNT} identified by "{OLD}" profile {profile}',
        f"grant create session to {ACCOUNT}",
    )


@pytest.fixture
def rollover_account(session: Any) -> Iterator[Any]:
    """On `SOPULI_ROLLOVER`, which the init script creates with
    `PASSWORD_ROLLOVER_TIME 1/24`."""
    _make(session, ROLLOVER_PROFILE)
    try:
        yield session
    finally:
        _drop(session)


@pytest.fixture
def plain_account(session: Any) -> Iterator[Any]:
    """On a profile with no rollover window at all."""
    _make(session, PLAIN_PROFILE)
    try:
        yield session
    finally:
        _drop(session)


def _logs_in(session: Any, password: str) -> bool:
    """Whether ``password`` authenticates, via the driver's own verification."""
    result = session.verify_password(ACCOUNT, Secret(password), lockout_margin=0)
    assert result.result in {PASS, FAIL}, result.detail
    return bool(result.result == PASS)


# ------------------------------------------------------------- the window ---


@pytest.mark.requires_capability(PASSWORD_ROLLOVER)
def test_both_passwords_work_during_the_window(rollover_account: Any) -> None:
    """The property the whole strategy rests on.

    It is why a partial apply across several PDBs causes no outage under this
    strategy, and therefore why it is the default where the capability exists
    (UC-1 §6.3). Asserted through `verify_password`, so what is checked is what
    the tool would report rather than what a test harness can see.
    """
    assert _logs_in(rollover_account, OLD)

    rollover_account.set_password(ACCOUNT, Secret(NEW))

    state = rollover_account.describe_user(ACCOUNT)
    assert state is not None
    assert state.rollover_active is True
    assert _logs_in(rollover_account, NEW), "the new password works"
    assert _logs_in(rollover_account, OLD), "and so does the old one, which is the point"


@pytest.mark.requires_capability(PASSWORD_ROLLOVER)
def test_finishing_the_window_retires_the_old_password(rollover_account: Any) -> None:
    rollover_account.set_password(ACCOUNT, Secret(NEW))

    result = rollover_account.finish_rollover(ACCOUNT)

    assert result.changed is True
    state = rollover_account.describe_user(ACCOUNT)
    assert state is not None
    assert state.rollover_active is False
    assert state.rollover_ends_at is None, "a closed window has no end to report"
    assert _logs_in(rollover_account, NEW)
    assert not _logs_in(rollover_account, OLD), "the old password is retired"


@pytest.mark.requires_capability(PASSWORD_ROLLOVER)
def test_finishing_twice_reports_no_change(rollover_account: Any) -> None:
    """Invariant 9, and it is **the tool's** job rather than the server's.

    Measured: issuing `EXPIRE PASSWORD ROLLOVER PERIOD` when no window is open
    is accepted silently, with no error. A driver that just issued it would
    report `changed: true` for a run that did nothing, every time.
    """
    rollover_account.set_password(ACCOUNT, Secret(NEW))
    assert rollover_account.finish_rollover(ACCOUNT).changed is True

    again = rollover_account.finish_rollover(ACCOUNT)

    assert again.changed is False
    assert again.detail is not None
    assert "no rollover window" in again.detail


@pytest.mark.requires_capability(PASSWORD_ROLLOVER)
def test_an_untouched_account_has_no_window_to_finish(rollover_account: Any) -> None:
    result = rollover_account.finish_rollover(ACCOUNT)

    assert result.changed is False


@pytest.mark.requires_capability(PASSWORD_ROLLOVER)
def test_an_open_window_reports_when_it_ends(rollover_account: Any) -> None:
    """Derived rather than read — no dictionary column exposes it — but it must
    still be there, and it must be after the change that opened the window."""
    rollover_account.set_password(ACCOUNT, Secret(NEW))

    state = rollover_account.describe_user(ACCOUNT)

    assert state is not None
    assert state.rollover_ends_at is not None
    assert state.password_changed_at is not None
    assert state.rollover_ends_at > state.password_changed_at


# ------------------------------------------------------- the plan-time no ---


@pytest.mark.requires_capability(PASSWORD_ROLLOVER)
def test_a_profile_without_a_window_is_refused_with_the_ddl_to_fix_it(
    plain_account: Any,
) -> None:
    """The release has the feature and this profile does not use it, which is a
    configuration rather than a limitation — so the refusal carries the exact
    `ALTER PROFILE` an operator would run, and the tool does not run it.

    Profiles are shared: changing one affects accounts nobody selected, and §3
    keeps `ALTER PROFILE` off the service account deliberately (Q4/#88).
    """
    with pytest.raises(DriverError) as raised:
        plain_account.require_rollover(ACCOUNT)

    assert not isinstance(raised.value, UnsupportedCapabilityError), (
        "the capability is present; it is the profile that is not configured"
    )
    assert raised.value.hint is not None
    assert "ALTER PROFILE" in raised.value.hint
    assert "PASSWORD_ROLLOVER_TIME" in raised.value.hint


@pytest.mark.requires_capability(PASSWORD_ROLLOVER)
def test_a_configured_profile_passes_the_plan_time_check(rollover_account: Any) -> None:
    rollover_account.require_rollover(ACCOUNT)


@pytest.mark.requires_no_capability(PASSWORD_ROLLOVER)
def test_a_release_without_rollover_refuses_at_plan_time(plain_account: Any) -> None:
    """18c and 11g. Exit 5, naming the capability and the target (invariant 4),
    and **at plan time** — not as an execution error two targets into a run."""
    with pytest.raises(UnsupportedCapabilityError) as raised:
        plain_account.require_rollover(ACCOUNT)

    assert raised.value.capability == PASSWORD_ROLLOVER
    assert raised.value.target == "tier1-oracle"

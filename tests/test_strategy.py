"""Which rollover regime applies, and which requests cannot be honoured (#262).

UC-1 §6.3 makes rollover the default where it exists. The interesting half is not
the default -- it is the requests the database will quietly not honour, and the
one that catches people is `--strategy staged` against a profile that grants a
window: Oracle opens one because the profile says so, whatever this run asked
for.

Pure, so the whole feasibility table is written down here rather than reproduced
against three Oracle releases.
"""

from __future__ import annotations

import pytest

from sopuli import strategy
from sopuli.driver.protocol import (
    EXPIRE_PASSWORD,
    PASSWORD_ROLLOVER,
    Scope,
    UserState,
)


def scope(*capabilities: str) -> Scope:
    return Scope(type="pdb", container="ALPHA", capabilities=frozenset(capabilities))


def user(**fields: object) -> UserState:
    base: dict[str, object] = {"name": "ACME_WEB_USER", "status": "OPEN", "profile": "APP_PROFILE"}
    return UserState(**{**base, **fields})  # type: ignore[arg-type]


def enabled(**fields: object) -> UserState:
    """An account whose profile grants a window."""
    return user(rollover_enabled=True, rollover_time="1", **fields)


ALL = scope(PASSWORD_ROLLOVER, EXPIRE_PASSWORD)


# ---------------------------------------------------------------- the window ---


def test_the_profile_decides_whether_a_window_opens() -> None:
    """Not the request. Oracle opens one because `PASSWORD_ROLLOVER_TIME` is
    greater than zero, and this tool has no say in it."""
    assert strategy.opens_window(enabled()) is True
    assert strategy.opens_window(user(rollover_enabled=False)) is False


def test_an_unknown_profile_reads_as_no_window() -> None:
    """The direction that cannot surprise anybody: a run that expected no window
    and got one is a grace period nobody was told about."""
    assert strategy.opens_window(user()) is False


# --------------------------------------------------------------- the default ---


def test_rollover_is_the_default_where_it_can_run() -> None:
    """§6.3, and the reason zero-downtime rotation is real."""
    assert strategy.default_for(ALL, enabled()) == strategy.ROLLOVER


def test_staged_is_the_default_without_the_capability() -> None:
    assert strategy.default_for(scope(), enabled()) == strategy.STAGED


def test_staged_is_the_default_where_the_profile_grants_no_window() -> None:
    """The capability is a property of the release and the window is a property
    of the profile. Both have to hold."""
    assert strategy.default_for(ALL, user(rollover_enabled=False)) == strategy.STAGED


def test_direct_is_never_a_default() -> None:
    """Ending a grace window early is destructive to whoever still holds the old
    password, and a default that did it would make that decision for an operator
    who did not know there was one."""
    for scoped in (ALL, scope(), scope(EXPIRE_PASSWORD)):
        for state in (enabled(), user(rollover_enabled=False)):
            assert strategy.default_for(scoped, state) != strategy.DIRECT


# ------------------------------------------------------------ the follow-up ---


def test_only_direct_closes_a_window() -> None:
    assert strategy.closes_window(strategy.DIRECT, enabled()) is True
    assert strategy.closes_window(strategy.ROLLOVER, enabled()) is False
    assert strategy.closes_window(strategy.STAGED, enabled()) is False


def test_direct_where_no_window_opens_closes_nothing() -> None:
    """The change was already immediate, which is what was asked for. Issuing
    `EXPIRE PASSWORD ROLLOVER PERIOD` to prove it would be a statement with no
    work in it."""
    assert strategy.closes_window(strategy.DIRECT, user(rollover_enabled=False)) is False


# ------------------------------------------------------------- the refusals ---


def test_staged_against_a_rollover_profile_is_refused() -> None:
    """The refusal worth reading twice. It looks like the safe, unambitious
    option and it is the one request Oracle will quietly ignore -- so a run
    reporting `staged` would tell an application team the old password had
    stopped working when it had not."""
    refusal = strategy.unhonourable(strategy.STAGED, ALL, enabled())

    assert refusal is not None
    assert "APP_PROFILE" in refusal.message
    assert "opens whatever" in refusal.message
    assert "--strategy direct" in refusal.hint


def test_that_refusal_is_a_configuration_and_not_a_limitation() -> None:
    """No capability is missing, so it is not exit 5's kind of answer. Somebody
    can change the profile; nobody can change the release."""
    refusal = strategy.unhonourable(strategy.STAGED, ALL, enabled())

    assert refusal is not None
    assert refusal.capability is None


def test_staged_where_no_window_opens_is_fine() -> None:
    assert strategy.unhonourable(strategy.STAGED, ALL, user(rollover_enabled=False)) is None


def test_direct_needs_the_capability_where_a_window_opens() -> None:
    """Without it the run would open a grace window the operator explicitly asked
    not to have."""
    refusal = strategy.unhonourable(strategy.DIRECT, scope(PASSWORD_ROLLOVER), enabled())

    assert refusal is not None
    assert refusal.capability == EXPIRE_PASSWORD


def test_direct_where_no_window_opens_needs_nothing() -> None:
    """Nothing to close, so nothing to be capable of."""
    assert strategy.unhonourable(strategy.DIRECT, scope(), user(rollover_enabled=False)) is None


def test_rollover_is_left_to_the_driver() -> None:
    """`Session.require_rollover` owns both of its refusals (#181) and carries
    the exact `ALTER PROFILE` for the second. A second phrasing here would be one
    message with two versions, and this module -- above the driver -- would write
    the worse one, because that hint is Oracle's own SQL."""
    assert strategy.unhonourable(strategy.ROLLOVER, scope(), user(rollover_enabled=False)) is None


# ---------------------------------------------------------------- the report ---


def test_only_direct_has_something_extra_to_say() -> None:
    """`rollover` reaches `ROLLOVER_ACTIVE`, whose own sentence says the previous
    password still authenticates, and `staged` is an ordinary password change.
    A clause for all three would put the same fact in the row twice."""
    assert strategy.extra_detail(strategy.ROLLOVER, enabled()) is None
    assert strategy.extra_detail(strategy.STAGED, user(rollover_enabled=False)) is None

    said = strategy.extra_detail(strategy.DIRECT, enabled())
    assert said is not None
    assert "no longer works" in said


def test_the_vocabulary_is_closed() -> None:
    """`--strategy` is a `click.Choice` over exactly this, so a value added here
    and not to UC-1 §5 -- or the reverse -- is worth noticing."""
    assert strategy.STRATEGIES == ("rollover", "staged", "direct")


@pytest.mark.parametrize("name", strategy.STRATEGIES)
def test_every_strategy_is_answerable_for_every_account(name: str) -> None:
    """No combination raises or returns something the caller has to special-case:
    a refusal or `None`, for all three regimes against both profiles."""
    for state in (enabled(), user(rollover_enabled=False)):
        for scoped in (ALL, scope()):
            answer = strategy.unhonourable(name, scoped, state)
            assert answer is None or isinstance(answer, strategy.Unhonourable)

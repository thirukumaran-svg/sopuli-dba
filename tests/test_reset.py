"""Deciding a personal password reset, and #439's five guards (#441). Tier 0.

A value object in, a decision or a refusal out. What the DDL then does is
`tests/driver/test_oracle_reset.py`'s, and what an operator sees is
`tests/test_cli_reset_password.py`'s.

The guards are the reason this module is pure. Three of the five are properties
of a *run* -- the output format, whether stdout is a terminal, whether
``--confirm`` was typed -- and the obvious place to check them is the CLI, where
testing them means owning a terminal. Passing them in as arguments makes each one
a test that runs in milliseconds and cannot be skipped on a machine without a
console, which is the difference between a guard that is checked on every commit
and one checked by hand in 2026.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ArgumentError
from sopuli.config.loading import build_config
from sopuli.config.model import Config, Delivery, ManualDelivery
from sopuli.driver.protocol import UserState
from sopuli.exit_codes import ExitCode
from sopuli.reset import (
    ACCOUNT_MISSING,
    RESET,
    SKIPPED,
    DeliveryUnavailableError,
    decide,
    deliverable,
    refuse_seen_path,
)
from sopuli.safety import RefusedError

SEEN = Delivery(method="manual", manual=ManualDelivery(force_expire=True))
UNSEEN = Delivery(method="vault_wrapped")

TARGET = {
    "type": "oracle",
    "name": "alpha-0",
    "dsn": "192.0.2.10:1521/ALPHA",
    "environment": "dev",
    "admin": {"username": "SOPULI_SVC", "auth": {"method": "env"}},
}


def config(**rest: Any) -> Config:
    return build_config(
        {
            "version": 1,
            "targets": [TARGET],
            "personal_accounts": [{"accounts": ["acme_dev_alice"]}],
            **rest,
        }
    )


def state(status: str = "OPEN", name: str = "ACME_DEV_ALICE", **rest: Any) -> UserState:
    return UserState(name=name, status=status, **rest)


#: So `decision(None)` can mean *the account is not there* rather than *use the
#: default*, which is the one value this helper must be able to pass through.
MISSING = object()


def decision(
    user: Any = MISSING,
    *,
    delivery: Delivery = UNSEEN,
    force: bool = False,
    declared: bool = True,
) -> Any:
    return decide(
        state() if user is MISSING else user,
        config=config() if declared else config(personal_accounts=[{"accounts": ["someone_else"]}]),
        account="acme_dev_alice",
        target="alpha-0",
        delivery=delivery,
        force=force,
    )


# ------------------------------------------------------- somewhere to deliver ---


def test_a_reset_with_no_delivery_configured_is_refused() -> None:
    """The first gate, and the cheapest: it needs no connection to answer, and a
    reset that reached a database before finding this out would have changed a
    password nobody can be told."""
    with pytest.raises(RefusedError) as caught:
        deliverable(None)

    assert "nowhere to go" in str(caught.value)
    assert caught.value.exit_code is ExitCode.ABORTED


def test_an_unimplemented_method_is_refused_on_the_capability_code() -> None:
    """Exit 5 rather than 9: the file is not wrong. It names a method UC-2 §6.2
    defines and this build cannot serve, which is what exit 5 has meant since
    P1."""
    with pytest.raises(DeliveryUnavailableError) as caught:
        deliverable(UNSEEN)

    assert "not implemented in this build" in str(caught.value)
    assert caught.value.exit_code is ExitCode.UNSUPPORTED_CAPABILITY
    assert caught.value.category == "capability"


def test_the_implemented_method_comes_back() -> None:
    """It returns the block rather than checking and discarding it, so a caller
    cannot hold an optional it has already proved is not ``None``."""
    assert deliverable(SEEN) is SEEN


# ------------------------------------------------------- #439's five guards ---


def test_guard_2_refuses_the_seen_path_with_json_output() -> None:
    """`policy sample --reveal`'s refusal, one verb over, and the same way round:
    the machine-readable format is the safe one, so it wins."""
    with pytest.raises(ArgumentError) as caught:
        refuse_seen_path(SEEN, is_json=True, stdout_is_terminal=True, confirm_given=False)

    assert "cannot be used with --output json" in str(caught.value)
    assert caught.value.exit_code is ExitCode.USAGE


def test_guard_3_refuses_the_seen_path_when_stdout_is_not_a_terminal() -> None:
    """The guard the whole argument rests on, and the one `--reveal` has no
    counterpart for: a value in a log outlives the single logon it is good for,
    and expiry does not unpublish it."""
    with pytest.raises(RefusedError) as caught:
        refuse_seen_path(SEEN, is_json=False, stdout_is_terminal=False, confirm_given=False)

    assert "not a terminal" in str(caught.value)
    assert caught.value.exit_code is ExitCode.ABORTED


def test_guard_3_has_no_escape_flag_on_the_command() -> None:
    """A decision rather than an omission, so it is asserted against the command
    itself rather than against a message.

    There must be no way to defeat the terminal check from the command line: a
    flag that exists to weaken a guard ends up in scripts, which is the exact
    place this value must never reach. `| clip` not working is the accepted cost
    (#439, #441). Checked by looking at every option the verb declares, so adding
    one called `--no-tty-check` fails here rather than in review.
    """
    from sopuli.cli import account_reset_password

    declared = {
        opt for param in account_reset_password.params for opt in getattr(param, "opts", ())
    }
    suspicious = {
        opt
        for opt in declared
        if any(word in opt for word in ("tty", "terminal", "reveal", "print", "show", "force-show"))
    }

    assert not suspicious, f"the verb declares what looks like a bypass: {suspicious}"


def test_guard_4_refuses_confirm_given_in_advance() -> None:
    """The one gate in the tool a yes cannot be given to ahead of time (P5, #439).
    A flag cannot testify to its own premise."""
    with pytest.raises(ArgumentError) as caught:
        refuse_seen_path(SEEN, is_json=False, stdout_is_terminal=True, confirm_given=True)

    assert "--confirm cannot answer" in str(caught.value)
    assert caught.value.exit_code is ExitCode.USAGE


def test_the_usage_errors_are_asked_before_the_environment_one() -> None:
    """Found by running it: a redirected run with `--confirm` used to be told
    about the terminal, which left guard 4 unreachable from anything but a real
    console. A script passing `--confirm` has made a mistake in its command line,
    and that is what it should hear about."""
    with pytest.raises(ArgumentError):
        refuse_seen_path(SEEN, is_json=False, stdout_is_terminal=False, confirm_given=True)


def test_no_guard_fires_on_an_unseen_delivery() -> None:
    """None of the three is true of a method that prints nobody anything.
    Refusing one for want of a terminal would be a guard firing on a path it was
    not written about."""
    refuse_seen_path(UNSEEN, is_json=True, stdout_is_terminal=False, confirm_given=True)


def test_no_guard_fires_on_a_dry_run() -> None:
    """A preview prints a plan and never a password (UC-2 §2, invariant 8), so
    there is no emission for any of these to guard -- and refusing one would make
    *show me what this would do* impossible from the CI job that most wants it."""
    refuse_seen_path(SEEN, is_json=True, stdout_is_terminal=False, confirm_given=True, preview=True)


# --------------------------------------------------------------- the decision ---


def test_an_account_that_does_not_exist_is_reported_not_failed() -> None:
    """The tool creates nothing (Q8); somebody with an account on four of nine
    targets is an ordinary estate."""
    answer = decision(None)

    assert answer.proceed is False
    assert answer.state == ACCOUNT_MISSING


def test_an_undeclared_account_is_refused() -> None:
    """Invariant 5: the config is the whitelist, and a reset touches nothing it
    does not declare."""
    answer = decision(declared=False)

    assert answer.proceed is False
    assert answer.state == SKIPPED


def test_a_deliberately_locked_account_is_refused() -> None:
    """H4 (#455): `LOCKED` without `(TIMED)` is somebody's offboarding decision,
    and handing the account a working password would undo it silently."""
    answer = decision(state(status="LOCKED", locked=True))

    assert answer.proceed is False
    assert answer.state == SKIPPED
    assert "does not unlock a deliberate lock" in answer.detail


def test_force_does_not_waive_a_deliberate_lock() -> None:
    """`--force` overrides §4's *account guardrails*, and this is not one of
    them. The flag has nothing to say about an offboarding."""
    answer = decision(state(status="LOCKED", locked=True), force=True)

    assert answer.proceed is False
    assert answer.state == SKIPPED


def test_a_timed_lock_is_not_refused() -> None:
    """The other half of H4, and the case the substring test gets wrong:
    `LOCKED(TIMED)` contains `LOCKED`, and clearing it is the reset's job."""
    answer = decision(state(status="LOCKED(TIMED)", locked=True))

    assert answer.proceed is True
    assert answer.state == RESET


def test_a_compound_status_carrying_a_deliberate_lock_is_still_refused() -> None:
    """`EXPIRED & LOCKED` is a real value, so equality against the whole string
    would call a deliberately locked account open -- #309's lesson, applied."""
    answer = decision(state(status="EXPIRED & LOCKED", locked=True, expired=True))

    assert answer.proceed is False


def test_the_seen_path_expires_and_the_unseen_one_does_not() -> None:
    """UC-2 §1's table, carried on the decision rather than re-derived by the
    caller, so one answer reaches the plan, the driver and the view."""
    assert decision(delivery=SEEN).expire is True
    assert decision(delivery=UNSEEN).expire is False


# ------------------------------------------- the ratchet #498 left a consumer for ---


def resolved_allowing(*methods: str) -> dict[str, Any]:
    """`safety.delivery.allowed_methods` as one layer would resolve it."""
    from sopuli.safety import ALLOWED_METHODS
    from sopuli.settings import Contribution, Layer, resolve

    answer = resolve(
        ALLOWED_METHODS,
        [Contribution(layer=Layer.DEFAULTS, value=methods, detail="defaults.safety.delivery")],
    )
    assert answer is not None
    return {ALLOWED_METHODS: answer}


def test_a_method_no_layer_permits_is_refused() -> None:
    """H6's consumer, which #498 said would arrive with the first delivery method
    and did (#441). Until this the set was resolved, ratcheted, reported by
    `config show --explain` and read by nothing."""
    from sopuli.safety import refuse_disallowed_method

    with pytest.raises(RefusedError) as caught:
        refuse_disallowed_method(resolved_allowing("vault_wrapped"), "manual")

    assert "is not permitted here" in str(caught.value)
    assert caught.value.exit_code is ExitCode.ABORTED


def test_a_permitted_method_passes() -> None:
    from sopuli.safety import refuse_disallowed_method

    refuse_disallowed_method(resolved_allowing("manual", "vault_wrapped"), "manual")


def test_an_unset_allow_list_permits_everything() -> None:
    """The intersection's first rule: an estate that wrote nothing has not
    thereby forbidden everything (§9, H6)."""
    from sopuli.safety import refuse_disallowed_method

    refuse_disallowed_method({}, "manual")


def test_the_refusal_names_where_the_set_was_written() -> None:
    """Every refusal in `sopuli/safety.py` carries the location, because a
    setting an operator did not know about is the whole reason one is confusing
    when it arrives."""
    from sopuli.safety import refuse_disallowed_method

    with pytest.raises(RefusedError) as caught:
        refuse_disallowed_method(resolved_allowing("vault_wrapped"), "manual")

    assert "defaults.safety.delivery" in (caught.value.hint or "")
    assert "--force does not reach a safety setting" in (caught.value.hint or "")


def test_the_setting_is_no_longer_declared_inert() -> None:
    """The other half of #498's bargain. `inert_reason` claims *nothing reads
    this*, and `tests/settings/test_settings_are_wired.py` fails in both
    directions -- so the marking had to go when the consumer arrived, which is
    the moment somebody checks whether the documents still say the right thing.
    """
    from sopuli.settings import setting

    assert setting("safety.delivery.allowed_methods").inert_reason is None

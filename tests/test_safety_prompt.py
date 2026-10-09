"""`auth: prompt` with no terminal, refused before a mutating verb connects.

Decision #481: a verb that changes something asks
:func:`~sopuli.admin.needs_prompt` over the selected targets first, and refuses
the run at exit 8 if any of them would ask for a password nobody can type.
These tests cover the decision itself. The wiring into each verb is in
`tests/test_cli_admin_prompt.py`.
"""

from __future__ import annotations

import pytest

from sopuli.admin import NobodyToAskError
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target
from sopuli.exit_codes import ExitCode
from sopuli.safety import NAMED_TARGETS, refuse_if_nobody_to_ask
from sopuli.secrets import Secret


def target(name: str, method: str | None) -> ExpandedTarget:
    admin = None
    if method is not None:
        admin = AdminCredential(username="C##SOPULI_SVC", auth=AdminAuth(method=method))
    return ExpandedTarget(
        target=Target(name=name, type="oracle", dsn="db.example.com:1521/orders", admin=admin),
        index=0,
        target_set=None,
    )


def answer(_: ExpandedTarget, __: str | None) -> Secret:
    return Secret("Correct-Horse-Battery-9")


def test_a_terminal_lets_every_target_through() -> None:
    """With somebody to ask, the prompt is how the run authenticates."""
    refuse_if_nobody_to_ask([target("orders-pdb", "prompt")], answer, action="applying a password")


def test_no_terminal_and_no_prompt_target_lets_the_run_through() -> None:
    """The refusal is about the prompt, not about the missing terminal."""
    refuse_if_nobody_to_ask(
        [target("orders-pdb", "env"), target("billing-pdb", "external"), target("hr-pdb", None)],
        None,
        action="applying a password",
    )


def test_no_terminal_and_a_prompt_target_refuses_at_exit_8() -> None:
    with pytest.raises(NobodyToAskError) as caught:
        refuse_if_nobody_to_ask(
            [target("orders-pdb", "env"), target("billing-pdb", "prompt")],
            None,
            action="applying a password",
        )

    assert caught.value.exit_code == ExitCode.ABORTED
    assert caught.value.category == "policy"
    message = str(caught.value)
    assert "applying a password reaches target 'billing-pdb', which asks" in message
    assert "orders-pdb" not in message
    assert "nothing was changed" in message
    assert str(caught.value.at) == "targets[0].admin.auth"


def test_the_hint_offers_narrowing_only_when_it_can_help() -> None:
    """A run whose every target prompts cannot be narrowed out of the refusal."""
    with pytest.raises(NobodyToAskError) as some:
        refuse_if_nobody_to_ask(
            [target("orders-pdb", "env"), target("billing-pdb", "prompt")],
            None,
            action="applying a password",
        )
    with pytest.raises(NobodyToAskError) as every:
        refuse_if_nobody_to_ask(
            [target("billing-pdb", "prompt")], None, action="applying a password"
        )

    assert "narrow the run so it does not reach it" in str(some.value)
    assert "narrow" not in str(every.value)


def test_every_prompt_target_is_named_up_to_the_ceiling() -> None:
    """The operator fixes them all at once, so the message names them all."""
    names = [f"appdb-{n}" for n in range(NAMED_TARGETS + 2)]

    with pytest.raises(NobodyToAskError) as caught:
        refuse_if_nobody_to_ask(
            [target(name, "prompt") for name in names], None, action="rotating a password"
        )

    message = str(caught.value)
    assert f"{NAMED_TARGETS + 2} targets that ask for their admin passwords" in message
    assert all(f"{name} (targets[0].admin.auth)" in message for name in names[:NAMED_TARGETS])
    assert names[NAMED_TARGETS] not in message
    assert "and 2 more" in message

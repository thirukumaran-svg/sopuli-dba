"""Rendering a notification, with no socket anywhere near it (#442). Tier 0.

The message is composed here and sent in #442's second part, and keeping the two
apart is what lets UC-2 §6.1's rule be proved without a network.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sopuli.config.errors import ROOT
from sopuli.config.notify import build_notify
from sopuli.notify import PLACEHOLDERS, Facts, render

AT = ROOT.key("delivery").key("notify")
WHEN = datetime(2026, 9, 22, 10, 21, 0, tzinfo=UTC)


def notify(template: str) -> object:
    return build_notify(
        {
            "method": "webhook",
            "webhook": {"url": {"env": "SOPULI_NOTIFY_WEBHOOK"}, "template": template},
        },
        at=AT,
    )


def test_the_estate_s_own_sentence_comes_back_filled() -> None:
    """The tool does not author the message: what is true of a hand-over differs
    by path, so a sentence the tool wrote would be wrong on one of them."""
    message = render(
        notify("{account} on {target} has a new password waiting"),  # type: ignore[arg-type]
        Facts(account="acme_dev_alice", target="free-pdb"),
    )

    assert message == "acme_dev_alice on free-pdb has a new password waiting"


def test_the_expiry_renders_the_way_the_run_document_does() -> None:
    """Formatted by `Facts` rather than by the template, so every channel agrees
    with the document about what a timestamp looks like -- and so an estate cannot
    ask for a format spec that raises at send time."""
    message = render(
        notify("fetch it before {expires_at}"),  # type: ignore[arg-type]
        Facts(account="a", target="t", expires_at=WHEN),
    )

    assert message == "fetch it before 2026-09-22T10:21:00Z"


def test_a_method_with_no_expiry_renders_empty_rather_than_none() -> None:
    """`manual` has no clock to expire and neither will #447's path. "expires at
    None" is worse than a sentence whose estate chose to mention an expiry that
    does not exist -- and the estate can see which it gets, because it wrote the
    template."""
    message = render(
        notify("before {expires_at}"),  # type: ignore[arg-type]
        Facts(account="a", target="t"),
    )

    assert message == "before "


def test_a_literal_brace_survives_rendering() -> None:
    message = render(
        notify("{{ok}} for {account}"),  # type: ignore[arg-type]
        Facts(account="acme_dev_alice", target="t"),
    )

    assert message == "{ok} for acme_dev_alice"


# ---------------------------------------------------- §6.1, made structural ---


def test_facts_has_a_field_for_every_placeholder_and_no_others() -> None:
    """**The assertion that keeps the closed set honest.** `PLACEHOLDERS` is what
    the config layer refuses against and `Facts` is what a render can reach; if
    they drift, either a template validates and cannot render, or a field exists
    that nothing will ever fill. `render` asserts it at run time too, so the
    failure is a test failure rather than a hole in a message."""
    assert set(Facts(account="a", target="t").as_fields()) == set(PLACEHOLDERS)


def test_there_is_nowhere_in_facts_to_put_a_password_or_a_token() -> None:
    """§6.1 made structural rather than checked. A renderer is handed exactly this
    and nothing else, so the channel cannot carry what the type has no room for --
    which is a stronger guarantee than looking for the words, and the reason the
    config layer's `NAMED_SECRETS` list is only a better error message."""
    fields = set(Facts.__dataclass_fields__)

    assert not any(
        word in name
        for name in fields
        for word in ("password", "secret", "token", "link", "credential", "url")
    )
    assert fields == {"account", "target", "expires_at"}


def test_a_renderer_cannot_be_handed_a_secret_at_all() -> None:
    """The other half of the same claim, from the signature: `render` takes the
    configuration and the facts, and there is no third parameter through which a
    caller could pass the thing being delivered."""
    from inspect import signature

    assert set(signature(render).parameters) == {"notify", "facts"}


def test_the_placeholder_set_cannot_drift_from_the_type() -> None:
    """**Derived, not asserted.** `PLACEHOLDERS` is built from `Facts`'s fields, so
    a fourth placeholder is a fourth field and there is no pair to keep in step --
    the same move #519's `Handover` made, letting the type carry the guarantee.
    This test is what says the derivation is the mechanism rather than a
    coincidence."""
    assert tuple(Facts.__dataclass_fields__) == PLACEHOLDERS


def test_a_field_that_as_fields_forgot_fails_loudly() -> None:
    """What is left to check after the derivation: a new field needs a line in
    `as_fields`, and forgetting one would render a hole rather than raise."""
    broken = Facts(account="a", target="t")
    object.__setattr__(broken, "as_fields", lambda: {"account": "a"})

    with pytest.raises(AssertionError, match="does not cover"):
        render(notify("{account}"), broken)  # type: ignore[arg-type]

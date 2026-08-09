"""Invariant 2: redaction is a property of the type and of the serialiser.

These tests exist before anything holds a real secret, on purpose. The seam is
cheap to build empty and expensive to retrofit, and a test that fails the moment
someone makes Secret printable is worth more than a comment asking them not to.
"""

from __future__ import annotations

import json

import pytest

from sopuli.output.emit import RedactingJSONEncoder
from sopuli.secrets import REDACTED, Secret

PLAINTEXT = "correct horse battery staple"


@pytest.fixture
def secret() -> Secret:
    return Secret(PLAINTEXT)


def test_str_is_redacted(secret: Secret) -> None:
    assert str(secret) == REDACTED


def test_repr_is_redacted(secret: Secret) -> None:
    assert repr(secret) == REDACTED


def test_fstring_is_redacted(secret: Secret) -> None:
    assert f"{secret}" == REDACTED


def test_format_spec_is_redacted(secret: Secret) -> None:
    """``f"{s:>10}"`` must redact rather than raise — a padded *** is fine."""
    assert PLAINTEXT not in f"{secret:>20}"


def test_reveal_is_the_only_way_out(secret: Secret) -> None:
    assert secret.reveal() == PLAINTEXT


def test_json_serialisation_is_redacted(secret: Secret) -> None:
    payload = json.dumps({"password": secret}, cls=RedactingJSONEncoder)
    assert PLAINTEXT not in payload
    assert REDACTED in payload


def test_nested_json_serialisation_is_redacted(secret: Secret) -> None:
    """Depth must not matter — the encoder is the boundary, not the call site."""
    payload = json.dumps({"results": [{"account": {"secret": secret}}]}, cls=RedactingJSONEncoder)
    assert PLAINTEXT not in payload


def test_plain_json_dumps_refuses_rather_than_leaking(secret: Secret) -> None:
    """Without the encoder, serialising must fail loudly instead of leaking.

    Secret is not a str subclass precisely so that a forgotten encoder is a
    TypeError, not a plaintext password in someone's log aggregator.
    """
    with pytest.raises(TypeError):
        json.dumps({"password": secret})


def test_equality_does_not_leak_via_error_messages(secret: Secret) -> None:
    assert secret == Secret(PLAINTEXT)
    assert secret != Secret("something else")

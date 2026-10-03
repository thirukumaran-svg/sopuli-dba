"""`vault_wrapped` delivery, without a Vault (#444). Tier 0.

What is here is the reading of Vault's answer and the refusals around it — all of
which are decisions this module makes about a response, and none of which need a
server to exercise. The socket is `tests/test_cli_reset_password.py`'s
(`test_the_token_unwraps_exactly_once`), against the real container, and the one
thing only that can tell us is whether the cubbyhole behaves the way UC-2 §6.6
claims: that the second unwrap fails.

The seam is the transport, handed in rather than patched: :class:`VaultWrapped`
takes one, which is what makes it testable with a stub that records what it was
asked for.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import pytest

from sopuli.delivery import Receipt
from sopuli.delivery.vault_wrapped import (
    METHOD,
    WRAP_PATH,
    WRAP_TTL_HEADER,
    NotWrappableError,
    VaultWrapped,
    for_store,
)
from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret
from sopuli.store import MemoryStore, StoreError
from sopuli.store.hashicorp._transport import Response

PASSWORD = "Correct#Horse9Battery"

#: What Vault actually answers: the *shape* is from a real wrap against the tier-1
#: container rather than from the documentation, which is what makes it worth
#: having. **The token and the accessor are synthetic**, and deliberately look it.
#: A response-wrapping token is a credential that retrieves a password (UC-2 §6.1)
#: and a real one has no business in a repository -- and a fixture only needs to be
#: a plausible string, because nothing here unwraps it.
WRAPPED = {
    "request_id": "e4f3753a-3e93-fe57-f164-e506470b38fc",
    "wrap_info": {
        "token": "hvs.EXAMPLE-not-a-real-token-AAAAAAAAAAAAAAAAAAAAAAAA",
        "accessor": "EXAMPLEaccessor000000000",
        "ttl": 900,
        "creation_time": "2026-09-22T10:06:50.837130Z",
        "creation_path": "sys/wrapping/wrap",
    },
}


class Recorder:
    """A transport that answers whatever it is told to, and remembers the call."""

    def __init__(self, response: Response) -> None:
        self.response = response
        self.calls: list[tuple[str, str, Any, Mapping[str, str] | None]] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Response:
        self.calls.append((method, path, json, headers))
        return self.response


def backend(response: Response, *, ttl: str = "15m") -> tuple[VaultWrapped, Recorder]:
    recorder = Recorder(response)
    return VaultWrapped(transport=recorder, ttl=ttl), recorder  # type: ignore[arg-type]


def deliver(body: Any, *, status: int = 200, ttl: str = "15m") -> Receipt:
    wrapper, _ = backend(Response(status=status, body=body), ttl=ttl)
    return wrapper.deliver(Secret(PASSWORD), account="acme_dev_alice", target="free-pdb")


# ------------------------------------------------------------- the wrap call ---


def test_the_password_is_wrapped_at_the_sys_endpoint_with_the_ttl_header() -> None:
    """The TTL travels as a header rather than in the body, which is Vault's own
    interface -- and the value is passed through rather than parsed, so what the
    server receives is exactly what the file said."""
    wrapper, recorder = backend(Response(status=200, body=WRAPPED), ttl="15m")

    wrapper.deliver(Secret(PASSWORD), account="acme_dev_alice", target="free-pdb")

    method, path, body, headers = recorder.calls[0]
    assert (method, path) == ("POST", WRAP_PATH)
    assert headers == {WRAP_TTL_HEADER: "15m"}
    assert body["password"] == PASSWORD


def test_the_cubbyhole_says_which_account_the_password_is_for() -> None:
    """A cubbyhole holding a bare string would make somebody who was sent two
    tokens guess which was which."""
    _, recorder = backend(Response(status=200, body=WRAPPED))
    VaultWrapped(transport=recorder, ttl="15m").deliver(  # type: ignore[arg-type]
        Secret(PASSWORD), account="acme_dev_alice", target="free-pdb"
    )

    _, _, body, _ = recorder.calls[0]
    assert body["account"] == "acme_dev_alice"
    assert body["target"] == "free-pdb"


def test_nothing_in_the_cubbyhole_identifies_the_dba() -> None:
    """A cubbyhole is read by the owner, and who reset it is the journal's
    business (UC-2 §3.1). Asserted as a closed set, so a field added later has to
    be argued for here."""
    _, recorder = backend(Response(status=200, body=WRAPPED))
    VaultWrapped(transport=recorder, ttl="15m").deliver(  # type: ignore[arg-type]
        Secret(PASSWORD), account="acme_dev_alice", target="free-pdb"
    )

    _, _, body, _ = recorder.calls[0]
    assert set(body) == {"password", "account", "target"}


# ---------------------------------------------------------------- the receipt ---


def test_the_receipt_carries_the_token_as_a_secret() -> None:
    """UC-2 §6.1 is about reach rather than value, so a wrapping token is
    secret-bearing -- and typing it as one means the default everywhere is `***`
    and emitting it takes a `reveal()` the tripwire test holds."""
    receipt = deliver(WRAPPED)

    assert receipt.method == METHOD
    assert receipt.token is not None
    assert str(receipt.token) == "***"
    assert receipt.token.reveal() == WRAPPED["wrap_info"]["token"]  # type: ignore[index]


def test_the_receipt_carries_the_accessor_which_names_without_using() -> None:
    """The one field the run document may carry: it identifies the handover and
    cannot fetch it, which is what lets a document describe a delivery without
    becoming the thing that leaks it."""
    assert deliver(WRAPPED).accessor == "EXAMPLEaccessor000000000"


def test_expiry_comes_from_the_answer_rather_than_from_the_configured_ttl() -> None:
    """A mount's `max_ttl` caps a wrap silently, so reporting the request back as
    though it were the outcome would tell an operator the handover lasts longer
    than it does. Asserted with a `ttl` the config did not ask for."""
    receipt = deliver({"wrap_info": {**WRAPPED["wrap_info"], "ttl": 60}}, ttl="15m")  # type: ignore[dict-item]

    assert receipt.expires_at == datetime(2026, 9, 22, 10, 7, 50, 837130, tzinfo=UTC)


def test_expiry_is_the_server_s_creation_time_plus_the_server_s_ttl() -> None:
    """Both numbers from the answer, which is what the docstring claimed and the
    first draft did not do (Copilot's review of #518): it added the server's TTL to
    the *client's* clock, wrong by the clock difference plus the round trip. Pinned
    to an exact value, because "about right" is what the bug looked like."""
    receipt = deliver(WRAPPED)

    assert receipt.expires_at == datetime(2026, 9, 22, 10, 21, 50, 837130, tzinfo=UTC)


@pytest.mark.parametrize("created", ["not a timestamp", "", 12, None, {"t": 1}])
def test_a_malformed_creation_time_falls_back_to_the_client_clock(created: Any) -> None:
    """Rather than to an unknown expiry, which is where this departs from the
    review's suggested fix. The TTL is the number that matters and it parsed;
    dropping it would replace a figure wrong by milliseconds with no figure at all,
    in the one line that tells somebody how long they have."""
    before = datetime.now(UTC)

    receipt = deliver({"wrap_info": {**WRAPPED["wrap_info"], "creation_time": created}})  # type: ignore[dict-item]

    assert receipt.expires_at is not None
    assert 890 <= (receipt.expires_at - before).total_seconds() <= 910


@pytest.mark.parametrize("ttl", [0, -1, "900", None, True])
def test_an_unusable_ttl_leaves_the_expiry_unknown(ttl: Any) -> None:
    """A receipt that admits to not knowing beats one carrying a number this
    module made up. `True` is in the list because `isinstance(True, int)` is the
    trap that would otherwise turn a boolean into one second."""
    assert deliver({"wrap_info": {**WRAPPED["wrap_info"], "ttl": ttl}}).expires_at is None  # type: ignore[dict-item]


# --------------------------------------------------------------- the refusals ---


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"wrap_info": None},
        {"wrap_info": {}},
        {"wrap_info": {"token": ""}},
        {"wrap_info": {"token": 12}},
        "not a mapping at all",
    ],
)
def test_an_answer_with_no_usable_token_fails_rather_than_returning_an_empty_receipt(
    body: Any,
) -> None:
    """The failure that matters most, and the reason it cannot be a soft one: a
    receipt with `token=None` would let the caller go on to issue the DDL, leaving
    an account whose password nobody holds -- which is exactly what UC-2 §6.4
    orders the two steps to prevent."""
    with pytest.raises(StoreError) as caught:
        deliver(body)

    assert "no token" in str(caught.value)
    assert caught.value.hint is not None
    assert WRAP_TTL_HEADER in caught.value.hint


def test_a_non_2xx_answer_is_reported_as_the_store_error_it_is() -> None:
    """Vault's own message survives, because a 403 here means a policy problem an
    operator fixes and a generic failure would send them looking at the tool."""
    with pytest.raises(StoreError) as caught:
        deliver({"errors": ["permission denied"]}, status=403)

    assert "permission denied" in str(caught.value)


def test_a_store_that_cannot_wrap_is_refused_by_name() -> None:
    """Invariant 4: the capability is named with the store, at plan time. An OCI
    vault has no cubbyhole and no equivalent, so there is nothing to degrade to
    and guessing would be worse than stopping."""
    with pytest.raises(NotWrappableError) as caught:
        for_store(MemoryStore(), vault="vault-oci", ttl="15m")

    assert "vault-oci" in str(caught.value)
    assert "HashiCorp" in str(caught.value)
    assert caught.value.exit_code is ExitCode.UNSUPPORTED_CAPABILITY
    assert caught.value.category == "capability"

"""Getting a token, per §3a.

Two halves. The dispatch — which endpoint, which body, which mount, and what
happens for a method this build does not perform — is decided before any packet
leaves, so it is tier 0 against a fake transport. The logins themselves are tier
1: they need a Vault with the auth mounts enabled, which the tests enable
themselves rather than asking `compose.yaml` to, because an auth mount that
exists only because the test stack created it is a mount no reader would expect
to find.

What is being protected is mostly *not* the happy path. A login is one POST and
it either works or it does not; the failures are where an operator loses an
afternoon — a 403 that means the mount is missing rather than the credential
being refused, a method that is deferred rather than unsupported, and a token
that must never reach a message.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

pytest.importorskip("httpx", reason="the hashicorp extra is not installed")

from sopuli.config.model import MaterialRef, Vault, VaultAuth  # noqa: E402
from sopuli.exit_codes import ExitCode  # noqa: E402
from sopuli.material import MaterialError  # noqa: E402
from sopuli.secrets import Secret  # noqa: E402
from sopuli.store.hashicorp import _auth  # noqa: E402
from sopuli.store.hashicorp._auth import (  # noqa: E402
    LoginFailedError,
    MethodNotImplementedError,
    authenticate,
)
from sopuli.store.hashicorp._transport import Response  # noqa: E402
from sopuli.store.protocol import CAS, LIST, StoreError  # noqa: E402

ADDR = "https://vault.example.com"


def vault(auth: VaultAuth | None, **overrides: Any) -> Vault:
    fields: dict[str, Any] = {"name": "vault-prod", "type": "hashicorp", "addr": ADDR}
    fields.update(overrides)
    return Vault(auth=auth, **fields)


@dataclass
class _Recorded:
    method: str
    path: str
    json: Any


class _FakeTransport:
    """Records one request and answers with whatever the test supplies."""

    def __init__(self, response: Response) -> None:
        self.response = response
        self.sent: _Recorded | None = None
        self.closed = False

    def request(self, method: str, path: str, *, json: Any = None) -> Response:
        self.sent = _Recorded(method=method, path=path, json=json)
        return self.response

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def transport(monkeypatch: pytest.MonkeyPatch) -> _FakeTransport:
    """Stand in for the login client, and remember how it was built.

    Patched at `_auth`'s own reference so the real `build_transport` -- which
    would open a socket to `vault.example.com` -- is never reached.
    """
    fake = _FakeTransport(Response(status=200, body={"auth": {"client_token": "s.issued"}}))
    captured: dict[str, Any] = {}

    def build(vault_entry: Vault, *, token: Secret | None) -> _FakeTransport:
        captured["token"] = token
        return fake

    monkeypatch.setattr(_auth, "build_transport", build)
    fake.built_with = captured  # type: ignore[attr-defined]
    return fake


# ------------------------------------------------------- method: token ---


def test_no_auth_block_at_all_means_the_token_method() -> None:
    """What makes a two-line config work on a laptop: §3a gives `token` no
    required keys, so an entry that says nothing about auth still authenticates
    from the chain."""
    secret = authenticate(vault(None), env={"VAULT_TOKEN": "s.from-env"})

    assert secret.reveal() == "s.from-env"


def test_the_token_method_reads_its_chain() -> None:
    secret = authenticate(vault(VaultAuth(method="token")), env={"SOPULI_VAULT_TOKEN": "s.sopuli"})

    assert secret.reveal() == "s.sopuli"


def test_a_written_token_ref_is_used(tmp_path: Any) -> None:
    path = tmp_path / "token"
    path.write_bytes(b"s.from-file\n")
    auth = VaultAuth(method="token", token=MaterialRef(kind="file", location=str(path)))

    assert authenticate(vault(auth), env={}).reveal() == "s.from-file"


def test_the_token_method_makes_no_call(transport: _FakeTransport) -> None:
    """`token` is a header, not a request. A login round-trip here would be a
    call nobody asked for, against an address that may not even be reachable."""
    authenticate(vault(VaultAuth(method="token")), env={"VAULT_TOKEN": "s.x"})

    assert transport.sent is None


# ----------------------------------------------------- method: approle ---


def test_approle_posts_both_halves_to_the_login_endpoint(transport: _FakeTransport) -> None:
    auth = VaultAuth(
        method="approle",
        role_id=MaterialRef(kind="env", location="ROLE_ID"),
        secret_id=MaterialRef(kind="env", location="SECRET_ID"),
    )

    secret = authenticate(vault(auth), env={"ROLE_ID": "r-1", "SECRET_ID": "s-1"})

    assert transport.sent is not None
    assert transport.sent.method == "POST"
    assert transport.sent.path == "auth/approle/login"
    assert transport.sent.json == {"role_id": "r-1", "secret_id": "s-1"}
    assert secret.reveal() == "s.issued"


def test_the_login_carries_no_token(transport: _FakeTransport) -> None:
    """**The one deliberately unauthenticated request in the tool**, and the
    probe confirmed Vault wants it that way: this call is what produces the
    authentication, so there is nothing to send."""
    auth = VaultAuth(
        method="approle",
        role_id=MaterialRef(kind="env", location="ROLE_ID"),
        secret_id=MaterialRef(kind="env", location="SECRET_ID"),
    )

    authenticate(vault(auth), env={"ROLE_ID": "r", "SECRET_ID": "s"})

    assert transport.built_with["token"] is None  # type: ignore[attr-defined]


def test_the_login_client_is_closed(transport: _FakeTransport) -> None:
    """It is not the client the store will use -- that one carries the token this
    call produced -- so leaving it open is a socket outliving its one request."""
    auth = VaultAuth(
        method="approle",
        role_id=MaterialRef(kind="env", location="R"),
        secret_id=MaterialRef(kind="env", location="S"),
    )

    authenticate(vault(auth), env={"R": "r", "S": "s"})

    assert transport.closed


def test_a_custom_auth_mount_is_used(transport: _FakeTransport) -> None:
    """`mount:` here is the *auth* mount, not the KV mount on the vault."""
    auth = VaultAuth(
        method="approle",
        mount="approle-ci",
        role_id=MaterialRef(kind="env", location="R"),
        secret_id=MaterialRef(kind="env", location="S"),
    )

    authenticate(vault(auth), env={"R": "r", "S": "s"})

    assert transport.sent is not None
    assert transport.sent.path == "auth/approle-ci/login"


def test_missing_material_fails_before_any_request(transport: _FakeTransport) -> None:
    """Exit 9, not 6: there was nothing to send, so nothing was refused. The
    distinction is the difference between fixing a vault role and fixing this
    machine."""
    auth = VaultAuth(
        method="approle",
        role_id=MaterialRef(kind="env", location="ROLE_ID"),
        secret_id=MaterialRef(kind="env", location="SECRET_ID"),
    )

    with pytest.raises(MaterialError) as caught:
        authenticate(vault(auth), env={"ROLE_ID": "r-1"})

    assert caught.value.exit_code == ExitCode.CONFIG_INVALID
    assert transport.sent is None


# ---------------------------------------------- kubernetes and userpass ---


def test_kubernetes_posts_the_role_and_the_jwt(transport: _FakeTransport, tmp_path: Any) -> None:
    """The file read is the work: a projected service-account token is a
    MaterialRef like any other, which is why this method is three lines."""
    token_file = tmp_path / "token"
    token_file.write_bytes(b"header.payload.signature\n")
    auth = VaultAuth(
        method="kubernetes",
        role="acme-rotator",
        jwt=MaterialRef(kind="file", location=str(token_file)),
    )

    authenticate(vault(auth), env={})

    assert transport.sent is not None
    assert transport.sent.path == "auth/kubernetes/login"
    assert transport.sent.json == {"role": "acme-rotator", "jwt": "header.payload.signature"}


def test_userpass_puts_the_username_in_the_path(transport: _FakeTransport) -> None:
    """The one endpoint here that is not `…/login`. Getting it wrong fails with a
    404 rather than a 403, which is a confusing symptom for something that looks
    like a credential problem."""
    auth = VaultAuth(
        method="userpass",
        username="acme_ci",
        password=MaterialRef(kind="env", location="PASSWORD"),
    )

    authenticate(vault(auth), env={"PASSWORD": "p"})

    assert transport.sent is not None
    assert transport.sent.path == "auth/userpass/login/acme_ci"
    assert transport.sent.json == {"password": "p"}


# ------------------------------------------------------------ failures ---


def test_a_refused_credential_is_exit_six(transport: _FakeTransport) -> None:
    transport.response = Response(status=400, body={"errors": ["invalid role or secret ID"]})
    auth = VaultAuth(
        method="approle",
        role_id=MaterialRef(kind="env", location="R"),
        secret_id=MaterialRef(kind="env", location="S"),
    )

    with pytest.raises(LoginFailedError) as caught:
        authenticate(vault(auth), env={"R": "r", "S": "wrong"})

    assert caught.value.exit_code == ExitCode.AUTH_FAILURE
    assert caught.value.category == "authentication"
    # The server's own words survive the mapping.
    assert "invalid role or secret ID" in str(caught.value)


def test_the_credential_never_reaches_the_message(transport: _FakeTransport) -> None:
    """A login body carries the one thing that must not be logged."""
    transport.response = Response(status=400, body={"errors": ["invalid role or secret ID"]})
    auth = VaultAuth(
        method="approle",
        role_id=MaterialRef(kind="env", location="R"),
        secret_id=MaterialRef(kind="env", location="S"),
    )

    with pytest.raises(LoginFailedError) as caught:
        authenticate(vault(auth), env={"R": "r-1", "S": "sup3rs3cr3t"})

    rendered = f"{caught.value} {caught.value.hint}"
    assert "sup3rs3cr3t" not in rendered


def test_a_403_says_the_mount_is_probably_missing(transport: _FakeTransport) -> None:
    """The failure that looks like exactly what it is not.

    Measured: a login against a mount that was never enabled answers **403
    permission denied**, not 404. A login endpoint is unauthenticated -- there is
    no identity yet, so there is nothing to deny -- and 403 is what Vault returns
    for a path that does not route. So the one status that reads as "your
    credential was rejected" is the one where it was never examined, and a hint
    saying "check the credential" would cost somebody an afternoon rotating a
    `secret_id` that was fine.
    """
    transport.response = Response(status=403, body={"errors": ["permission denied"]})
    auth = VaultAuth(
        method="userpass", username="acme", password=MaterialRef(kind="env", location="P")
    )

    with pytest.raises(LoginFailedError) as caught:
        authenticate(vault(auth), env={"P": "p"})

    assert "mount" in (caught.value.hint or "")


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (503, "StoreUnavailableError"),
        (429, "StoreUnavailableError"),
        (473, "StoreUnavailableError"),
    ],
)
def test_a_store_that_cannot_answer_is_not_a_refused_credential(
    transport: _FakeTransport, status: int, expected: str
) -> None:
    """Sealed is 503 and a standby is 429 or 473, and none of them looked at the
    credential.

    Reporting them as exit 6 would tell a scheduler to stop and fix the
    credential, which is the one action that cannot help -- the store is not
    refusing, it is unable to answer. Delegated to the general mapper, which
    already tells these apart.
    """
    transport.response = Response(status=status, body={"errors": ["Vault is sealed"]})
    auth = VaultAuth(
        method="approle",
        role_id=MaterialRef(kind="env", location="R"),
        secret_id=MaterialRef(kind="env", location="S"),
    )

    with pytest.raises(StoreError) as caught:
        authenticate(vault(auth), env={"R": "r", "S": "s"})

    assert type(caught.value).__name__ == expected
    assert not isinstance(caught.value, LoginFailedError)
    assert caught.value.exit_code != ExitCode.AUTH_FAILURE


def test_an_unrecognised_status_is_not_a_refused_credential(transport: _FakeTransport) -> None:
    """Fail closed, the same rule `_errors.py` uses: a 500 is not evidence about
    a credential."""
    transport.response = Response(status=500, body={"errors": ["internal error"]})
    auth = VaultAuth(
        method="approle",
        role_id=MaterialRef(kind="env", location="R"),
        secret_id=MaterialRef(kind="env", location="S"),
    )

    with pytest.raises(StoreError) as caught:
        authenticate(vault(auth), env={"R": "r", "S": "s"})

    assert not isinstance(caught.value, LoginFailedError)


def test_a_username_is_encoded_as_one_path_segment(transport: _FakeTransport) -> None:
    """A username holding a slash would otherwise rewrite the request path and
    come back as a 403 -- which this backend reads as "the auth mount is
    missing", so the diagnosis would be wrong twice over.

    Deliberately unlike a secret path, which is hierarchical and whose slashes
    are meant to survive.
    """
    auth = VaultAuth(
        method="userpass",
        username="acme/ci user",
        password=MaterialRef(kind="env", location="P"),
    )

    authenticate(vault(auth), env={"P": "p"})

    assert transport.sent is not None
    assert transport.sent.path == "auth/userpass/login/acme%2Fci%20user"


def test_an_accepted_login_with_no_token_is_a_failure(transport: _FakeTransport) -> None:
    transport.response = Response(status=200, body={"auth": None})
    auth = VaultAuth(
        method="approle",
        role_id=MaterialRef(kind="env", location="R"),
        secret_id=MaterialRef(kind="env", location="S"),
    )

    with pytest.raises(LoginFailedError):
        authenticate(vault(auth), env={"R": "r", "S": "s"})


def test_oidc_is_deferred_rather_than_unsupported() -> None:
    """Not yet, and the message says what it would take. ADR-005 is explicit
    that the hard part is the browser launch and the callback listener, which no
    Python client provides -- `hvac` included -- so deferring it costs nothing
    that choosing a client library would have bought."""
    with pytest.raises(MethodNotImplementedError) as caught:
        authenticate(vault(VaultAuth(method="oidc")), env={})

    message = str(caught.value)
    assert "not implemented in this build yet" in message
    assert "browser" in message
    assert caught.value.exit_code == ExitCode.CONFIG_INVALID


@pytest.mark.parametrize("method", _auth.FOREIGN)
def test_an_oci_method_on_a_hashicorp_store_says_so(method: str) -> None:
    """§3a's table is one grammar with two vocabularies, so these parse. They
    authenticate to a different vendor, which is a more useful thing to be told
    than "unknown method"."""
    with pytest.raises(MethodNotImplementedError) as caught:
        authenticate(vault(VaultAuth(method=method)), env={})

    assert "OCI" in str(caught.value)


# ------------------------------------------------------ tier 1: for real ---


@pytest.fixture
def approle(vault_stack: Any) -> dict[str, str]:
    """Enable AppRole, make a role, and hand back both halves.

    Enabled by the test rather than by `compose.yaml`: an auth mount that exists
    only because the test stack created it is one no reader of that file would
    expect, and the setup is three calls.
    """
    client = vault_stack.client
    client.post("/v1/sys/auth/approle", json={"type": "approle"})
    client.post("/v1/auth/approle/role/sopuli-test", json={"token_policies": "default"})
    role_id = client.get("/v1/auth/approle/role/sopuli-test/role-id").json()["data"]["role_id"]
    secret_id = client.post("/v1/auth/approle/role/sopuli-test/secret-id").json()["data"][
        "secret_id"
    ]
    return {"role_id": role_id, "secret_id": secret_id}


def test_approle_authenticates_against_a_real_vault(
    vault_stack: Any, approle: dict[str, str]
) -> None:
    """Two calls, no auth header, a `client_token` straight back -- and the token
    is then used for something, because a login that returns a string nothing
    can read with is not a login that worked."""
    auth = VaultAuth(
        method="approle",
        role_id=MaterialRef(kind="env", location="ROLE_ID"),
        secret_id=MaterialRef(kind="env", location="SECRET_ID"),
    )
    entry = Vault(name="vault-dev", type="hashicorp", addr=vault_stack.addr, auth=auth)

    token = authenticate(
        entry, env={"ROLE_ID": approle["role_id"], "SECRET_ID": approle["secret_id"]}
    )

    assert token.reveal().startswith("hvs.")
    lookup = vault_stack.client.get(
        "/v1/auth/token/lookup-self", headers={"X-Vault-Token": token.reveal()}
    )
    assert lookup.status_code == 200


def test_a_wrong_secret_id_is_exit_six_against_a_real_vault(
    vault_stack: Any, approle: dict[str, str]
) -> None:
    """The mapping, against the wording Vault actually sends rather than the
    wording this test made up."""
    auth = VaultAuth(
        method="approle",
        role_id=MaterialRef(kind="env", location="ROLE_ID"),
        secret_id=MaterialRef(kind="env", location="SECRET_ID"),
    )
    entry = Vault(name="vault-dev", type="hashicorp", addr=vault_stack.addr, auth=auth)

    with pytest.raises(LoginFailedError) as caught:
        authenticate(
            entry,
            env={
                "ROLE_ID": approle["role_id"],
                "SECRET_ID": "00000000-0000-0000-0000-000000000000",
            },
        )

    assert caught.value.exit_code == ExitCode.AUTH_FAILURE


def test_userpass_authenticates_against_a_real_vault(vault_stack: Any) -> None:
    client = vault_stack.client
    client.post("/v1/sys/auth/userpass", json={"type": "userpass"})
    client.post(
        "/v1/auth/userpass/users/acme_ci",
        json={"password": "acme-test-password", "token_policies": "default"},
    )
    auth = VaultAuth(
        method="userpass",
        username="acme_ci",
        password=MaterialRef(kind="env", location="PASSWORD"),
    )
    entry = Vault(name="vault-dev", type="hashicorp", addr=vault_stack.addr, auth=auth)

    token = authenticate(entry, env={"PASSWORD": "acme-test-password"})

    assert token.reveal().startswith("hvs.")


def test_a_login_against_a_mount_that_does_not_exist_is_a_403(vault_stack: Any) -> None:
    """Where the 403 reading came from. This test asserted a 404 first, on the
    strength of what the status *ought* to be, and the real Vault said
    otherwise -- which is the whole reason the tier-1 half exists."""
    auth = VaultAuth(
        method="userpass",
        mount="userpass-not-enabled",
        username="acme_ci",
        password=MaterialRef(kind="env", location="P"),
    )
    entry = Vault(name="vault-dev", type="hashicorp", addr=vault_stack.addr, auth=auth)

    with pytest.raises(LoginFailedError) as caught:
        authenticate(entry, env={"P": "whatever"})

    assert "mount" in (caught.value.hint or "")


def test_connect_reaches_a_store_from_a_config_entry(
    vault_stack: Any, approle: dict[str, str]
) -> None:
    """**The whole chain, in one call.** The entry describes the transport,
    the registry finds the module, the resolver turns `auth:` into a credential,
    the method turns that into a token, and the adapter reads with it. This test
    runs them together."""
    from sopuli.store.hashicorp import connect

    auth = VaultAuth(
        method="approle",
        role_id=MaterialRef(kind="env", location="ROLE_ID"),
        secret_id=MaterialRef(kind="env", location="SECRET_ID"),
    )
    entry = Vault(
        name="vault-dev",
        type="hashicorp",
        addr=vault_stack.addr,
        mount=vault_stack.kv2_mount,
        kv_version=2,
        auth=auth,
    )

    store = connect(entry, env={"ROLE_ID": approle["role_id"], "SECRET_ID": approle["secret_id"]})

    # A path this token's policy cannot read is still an answer from the store,
    # so `supports()` is what proves the store is live without needing a policy.
    # Asserted by containment rather than by equality: what this test is about is
    # that `connect` handed back a live KV v2 store, and pinning the exact set
    # makes it fail every time the interface grows a capability somewhere else,
    # such as `versioning`.
    assert {CAS, LIST} <= store.supports()

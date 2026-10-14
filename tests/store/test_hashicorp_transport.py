"""The transport and the error mapping, without a Vault (ADR-005).

Tier 0: every case here is a decision the adapter makes *before* or *after* the
network, so none of it needs a container. What it covers is the half that is
hardest to see in a live test — a client built with the wrong verification
setting still works against a store whose certificate is fine, and a status
misclassified as a lost race looks like an ordinary retry until the day it is a
wall.
"""

from __future__ import annotations

import socket
import ssl
from pathlib import Path

import pytest

# Tier 0 by tier -- no container, no network -- but not by *install shape*: the
# subject is the client `sopuli[hashicorp]` installs, so there is nothing to
# assert without it. A skip rather than a collection error, so the rest of the
# suite still runs on a base+dev install (`04-testing.md` §3).
httpx = pytest.importorskip("httpx", reason="the hashicorp extra is not installed")

from sopuli.config.model import Vault, VaultTls  # noqa: E402
from sopuli.secrets import Secret  # noqa: E402
from sopuli.store.hashicorp._errors import (  # noqa: E402
    StoreAuthError,
    StoreUnavailableError,
    messages,
    raise_for,
)
from sopuli.store.hashicorp._transport import (  # noqa: E402
    DEFAULT_TIMEOUT_S,
    Transport,
    build_ssl_context,
    build_transport,
)
from sopuli.store.protocol import CasConflictError, StoreError  # noqa: E402

PATH = "apps/acme/lock"


def vault(**overrides: object) -> Vault:
    fields: dict[str, object] = {
        "name": "vault-prod",
        "type": "hashicorp",
        "addr": "https://vault.example.com",
    }
    fields.update(overrides)
    return Vault(**fields)  # type: ignore[arg-type]


# ------------------------------------------------------------ error mapping ---
#
# The three 400s Vault answers, all mentioning the check-and-set parameter, and
# only one of them a lost race. Measured against hashicorp/vault:2.0.4.


def test_a_lost_race_is_a_conflict() -> None:
    body = {"errors": ["check-and-set parameter did not match the current version"]}

    with pytest.raises(CasConflictError) as caught:
        raise_for(400, body, path=PATH)

    assert PATH in str(caught.value)
    # The server's own words survive the mapping (CLAUDE.md, Style).
    assert "did not match the current version" in str(caught.value)


def test_a_missing_cas_where_one_is_required_is_not_a_conflict() -> None:
    """The trap ADR-005 names: this message opens with the same words as the
    conflict's, and the lock paths set `cas_required: true`, so it is
    reachable by design. Reported as a race, a run would announce that somebody
    beat it to the path when nobody was there."""
    body = {"errors": ["check-and-set parameter required for this call"]}

    with pytest.raises(StoreError) as caught:
        raise_for(400, body, path=PATH)

    assert not isinstance(caught.value, CasConflictError)


def test_a_malformed_cas_is_not_a_conflict() -> None:
    body = {"errors": ["error parsing check-and-set parameter"]}

    with pytest.raises(StoreError) as caught:
        raise_for(400, body, path=PATH)

    assert not isinstance(caught.value, CasConflictError)


def test_an_unrecognised_400_fails_closed() -> None:
    """The rule that decides the whole module. Misclassifying a real conflict
    costs one retry; misclassifying a hard error as a lost race retries into a
    wall."""
    with pytest.raises(StoreError) as caught:
        raise_for(400, {"errors": ["something nobody has seen before"]}, path=PATH)

    assert not isinstance(caught.value, CasConflictError)


@pytest.mark.parametrize("status", [401, 403])
def test_a_refused_token_is_an_authorization_failure(status: int) -> None:
    """`authorization`, not `vault`: what an operator does next is look at a
    policy or a token, not at the store."""
    with pytest.raises(StoreAuthError) as caught:
        raise_for(status, {"errors": ["permission denied"]}, path=PATH)

    assert caught.value.category == "authorization"


@pytest.mark.parametrize("status", [429, 472, 473, 503])
def test_sealed_and_standby_are_told_apart_from_ordinary_failure(status: int) -> None:
    """Worth retrying, and worth naming: "the vault is sealed" is something an
    operator can act on in a way that "500" is not."""
    with pytest.raises(StoreUnavailableError):
        raise_for(status, {"errors": []}, path=PATH)


def test_a_body_that_is_not_vaults_own_still_produces_an_error() -> None:
    """A proxy in front of the store answers HTML, and the status is still the
    fact worth reporting."""
    with pytest.raises(StoreError) as caught:
        raise_for(502, "<html>Bad Gateway</html>", path=PATH)

    assert "502" in str(caught.value)


def test_messages_reads_vaults_error_list_and_nothing_else() -> None:
    assert messages({"errors": ["a", "b"]}) == ["a", "b"]
    assert messages({"errors": []}) == []
    assert messages({"data": {}}) == []
    assert messages(None) == []


# ---------------------------------------------------------------- transport ---


def test_the_token_travels_as_a_header_and_never_in_the_url() -> None:
    transport = build_transport(vault(), token=Secret("s.aaaa"))

    assert transport._client.headers["X-Vault-Token"] == "s.aaaa"  # noqa: SLF001


def test_a_namespace_is_sent_only_when_configured() -> None:
    """Absent means the header is not sent, which is a different request from
    sending it empty: an empty namespace addresses the root one."""
    without = build_transport(vault(), token=Secret("t"))
    with_one = build_transport(vault(namespace="acme/platform"), token=Secret("t"))

    assert "X-Vault-Namespace" not in without._client.headers  # noqa: SLF001
    assert with_one._client.headers["X-Vault-Namespace"] == "acme/platform"  # noqa: SLF001


def test_a_store_without_a_timeout_still_gets_one() -> None:
    """`httpx` has no default and the advisory lock is held while a request is
    outstanding, so "unset" cannot mean "wait forever"."""
    transport = build_transport(vault(), token=Secret("t"))

    assert transport._client.timeout.read == DEFAULT_TIMEOUT_S  # noqa: SLF001


def test_a_configured_timeout_wins() -> None:
    transport = build_transport(vault(timeout_s=3), token=Secret("t"))

    assert transport._client.timeout.read == 3  # noqa: SLF001


def test_a_store_with_no_address_is_refused_before_any_request() -> None:
    with pytest.raises(StoreError) as caught:
        build_transport(vault(addr=None), token=Secret("t"))

    assert "addr" in str(caught.value)


def test_a_token_httpx_cannot_send_is_refused_without_quoting_it() -> None:
    """httpx encodes a header as ASCII, and its error quotes the character it
    could not encode, which is part of the token (#785)."""
    with pytest.raises(StoreError) as caught:
        build_transport(vault(), token=Secret("hvs.EXAMPLEéTOKEN"))

    assert caught.value.message == (
        "vault 'vault-prod': the client could not be built: UnicodeEncodeError"
    )


def test_a_body_httpx_cannot_encode_is_reported_by_its_error_type() -> None:
    """A body holds a secret on a write and on a login, and an encoding error
    quotes a character of it and its position (#785)."""
    transport = Transport(
        httpx.Client(
            base_url="https://vault.example.com",
            transport=httpx.MockTransport(lambda _: httpx.Response(204)),
        )
    )

    with pytest.raises(StoreError) as caught:
        transport.request("POST", "kv/data/acme", json={"password": "EXAMPLE\udce9SECRET"})

    assert caught.value.message == "the request to the store failed: UnicodeEncodeError"
    assert "EXAMPLE" not in str(caught.value)


def test_redirects_are_not_followed() -> None:
    """Vault redirects to the active node, and following it silently would send
    this token somewhere the config never named."""
    transport = build_transport(vault(), token=Secret("t"))

    assert transport._client.follow_redirects is False  # noqa: SLF001


# --------------------------------------------------------------- TLS context ---


def test_no_tls_block_verifies_with_the_default_trust_store() -> None:
    """`True` rather than a hand-built context: an empty one would trust nothing
    and fail against every public CA."""
    assert build_ssl_context(None) is True


def test_verify_false_is_the_whole_of_verify_false() -> None:
    assert build_ssl_context(VaultTls(verify=False)) is False


def test_an_unwritten_verify_still_verifies() -> None:
    """`verify` stays None when unwritten so the ratchet can tell "nobody said"
    from "somebody agreed"; the effective reading is unchanged."""
    assert build_ssl_context(VaultTls(server_name="vault.example.com")) is True


def test_a_ca_file_produces_a_context_that_loaded_it(tmp_path: Path) -> None:
    """The reason ADR-005 wanted a client taking a real SSLContext: a boolean
    could express `verify: false` and nothing else.

    A real bundle, copied rather than pointed at, so the assertion is about this
    file and not about whatever the machine's default trust store happens to be
    -- which on Windows is often no file at all.
    """
    import certifi

    bundle = tmp_path / "acme-ca.pem"
    bundle.write_bytes(Path(certifi.where()).read_bytes())

    context = build_ssl_context(VaultTls(ca_file=str(bundle)))

    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.get_ca_certs(), "the bundle should have been loaded, not merely accepted"


def test_a_ca_file_that_does_not_exist_is_a_store_error(tmp_path: Path) -> None:
    """A `StoreError` with a hint, not a traceback.

    Better found here than at the first handshake -- a store that silently fell
    back to the system trust store would verify against a CA the config never
    named, which is the opposite of what writing `ca_file` asks for. But this
    path is *valid config*, so reaching the store is the first
    moment anybody can find out, and a stack trace is not how to say that a
    filename is wrong.
    """
    missing = tmp_path / "not-there.pem"

    with pytest.raises(StoreError) as caught:
        build_ssl_context(VaultTls(ca_file=str(missing)))

    assert "ca_file" in str(caught.value)
    assert str(missing) in str(caught.value)


def test_a_ca_file_that_is_not_a_certificate_is_a_store_error(tmp_path: Path) -> None:
    """The other way it goes wrong, and the one a file-exists check would miss:
    the path resolves and holds something that is not a PEM."""
    junk = tmp_path / "acme-ca.pem"
    junk.write_text("this is not a certificate", encoding="utf-8")

    with pytest.raises(StoreError) as caught:
        build_ssl_context(VaultTls(ca_file=str(junk)))

    assert "ca_file" in str(caught.value)


def test_a_client_certificate_that_does_not_exist_is_a_store_error(tmp_path: Path) -> None:
    """Named separately from the CA material, because the fix is a different
    file: the hint says which of the two keys it was reading."""
    import certifi

    bundle = tmp_path / "acme-ca.pem"
    bundle.write_bytes(Path(certifi.where()).read_bytes())

    with pytest.raises(StoreError) as caught:
        build_ssl_context(VaultTls(ca_file=str(bundle), client_cert=str(tmp_path / "no-cert.pem")))

    assert "client_cert" in str(caught.value)
    assert "ca_file" not in str(caught.value)


def test_a_token_with_a_line_break_is_refused_without_quoting_it() -> None:
    """h11 refuses the header before anything is sent, and its message quotes
    the whole value, which is the token (#785). It checks the header after it
    connects, so a socket listens here and is never answered."""
    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = listener.getsockname()[1]
        transport = build_transport(
            vault(addr=f"http://127.0.0.1:{port}"), token=Secret("hvs.EXAMPLETOKEN\r")
        )

        with pytest.raises(StoreError) as caught:
            transport.request("GET", "sys/health")

    assert caught.value.message == (
        "the request to the store could not be sent: LocalProtocolError"
    )
    assert "EXAMPLETOKEN" not in str(caught.value)


def test_a_fault_in_the_tool_is_not_reported_as_the_store() -> None:
    """A value JSON cannot encode is a bug, not a store that is down."""
    transport = Transport(
        httpx.Client(
            base_url="https://vault.example.com",
            transport=httpx.MockTransport(lambda _: httpx.Response(204)),
        )
    )

    with pytest.raises(TypeError):
        transport.request("POST", "kv/data/acme", json={"value": object()})

"""The HTTP client a HashiCorp store speaks through (#104, ADR-005).

`httpx` is imported here and nowhere above: ADR-006 rule 1 puts a vendor client
inside its backend module so that ``pip install sopuli-dba`` installs neither it
nor a socket. ``tests/store/test_install_shape.py`` is what holds that.

Everything ADR-005 chose `httpx` *for* is in this module, which is the argument
for the choice written as code:

* **an explicit deadline on every request.** `httpx` has no default timeout, and
  P5's advisory lock is held while a request is outstanding -- a hung read is a
  lock nobody can take and a rotation nobody can finish.
* **a real** :class:`ssl.SSLContext`, which is what makes ``tls.ca_path`` and
  mutual TLS expressible at all. A client that took a boolean could express
  `verify: false` and nothing else.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from typing import Any

import httpx

from sopuli.config.model import Vault, VaultTls
from sopuli.secrets import Secret
from sopuli.store.protocol import StoreError

#: What a store gets when the config names no ``timeout_s``.
#:
#: There has to be one, and it cannot be "wait forever". `01-configuration.md`
#: §10 refuses `timeout_s: 0` on the grounds that omitting the key is how you ask
#: for the backend's default -- so the backend owes a default, and this is it.
#: Long enough that a slow-but-working vault is not cut off mid-rotation, short
#: enough that a black hole is not mistaken for one.
DEFAULT_TIMEOUT_S = 30


@dataclass(frozen=True)
class Response:
    """One answer, reduced to what the store layer above cares about."""

    status: int
    body: Any

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


class Transport:
    """A configured connection to one store.

    Holds the client rather than making one per call: a new client per request
    would throw away the connection pool and the TLS handshake, which for a
    rotation across twenty targets is twenty avoidable handshakes against the
    same vault.
    """

    def __init__(self, client: httpx.Client, *, sni_hostname: str | None = None) -> None:
        self._client = client
        self._sni_hostname = sni_hostname

    def request(self, method: str, path: str, *, json: Any = None) -> Response:
        """Call ``/v1/<path>``, and never raise for a status.

        **Non-2xx is data here, not an exception.** ``sys/health`` answers 429
        for a standby, 473 for a performance standby, 501 for uninitialised and
        503 for sealed, all by design (ADR-005) -- a client that raised on
        non-2xx would report a healthy cluster as broken. Which statuses are
        failures is :mod:`._errors`' judgement, and it needs the body to make it.
        """
        # SNI is a per-request extension rather than a client setting: httpx
        # passes `sni_hostname` down to the connection, which is what lets
        # `tls.server_name` work for a store reached by an address that does not
        # match its certificate -- a tunnel, or a load balancer by IP.
        extensions = {"sni_hostname": self._sni_hostname} if self._sni_hostname else {}
        try:
            response = self._client.request(method, f"/v1/{path}", json=json, extensions=extensions)
        except httpx.TimeoutException as error:
            raise StoreError(
                f"the store did not answer within the timeout: {error}",
                hint="raise `timeout_s` on the store, or check that `addr` reaches it",
            ) from error
        except httpx.TransportError as error:
            # Includes the TLS failures, which is the one class of connectivity
            # error worth a hint of its own: it is what `tls:` exists to fix and
            # what `verify: false` exists to paper over.
            raise StoreError(
                f"could not reach the store: {error}",
                hint="check `addr`, and `tls.ca_file` if the certificate is your own CA",
            ) from error

        return Response(status=response.status_code, body=_decode(response))

    def close(self) -> None:
        self._client.close()


def _decode(response: httpx.Response) -> Any:
    """The JSON body, or ``None``.

    A 204 has no body at all -- a KV v1 write answers with one -- and an error
    from a proxy rather than from Vault may not be JSON either. Neither is worth
    an exception here: :mod:`._errors` reports the status, and a body it cannot
    read simply contributes no detail to the message.
    """
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def build_transport(vault: Vault, *, token: Secret | None) -> Transport:
    """The client for ``vault``, carrying ``token`` if there is one.

    ``None`` is not a convenience: an auth-method login is the one request in
    the tool that must go out *without* a token, because it is the request that
    produces one (:mod:`._auth`). Sending an empty header instead would be a
    request claiming an identity it does not have.
    """
    headers = {} if token is None else {"X-Vault-Token": token.reveal()}
    if vault.namespace is not None:
        # Absent means the header is not sent, which is a different request from
        # sending it empty: an empty namespace addresses the root one.
        headers["X-Vault-Namespace"] = vault.namespace

    if vault.addr is None:
        raise StoreError(
            f"vault {vault.name!r} has no `addr`, and a HashiCorp store needs one",
            hint="add `addr: https://…` to the entry under `vaults:`",
        )

    client = httpx.Client(
        base_url=vault.addr,
        headers=headers,
        timeout=vault.timeout_s if vault.timeout_s is not None else DEFAULT_TIMEOUT_S,
        verify=build_ssl_context(vault.tls),
        # Vault answers a moved mount with a redirect to the active node, and
        # following it silently would send this token somewhere the config never
        # named. Failing instead makes the operator point `addr` at the right
        # place, which is the one that ends up in the audit trail.
        follow_redirects=False,
    )
    return Transport(client, sni_hostname=vault.tls.server_name if vault.tls else None)


def build_ssl_context(tls: VaultTls | None) -> ssl.SSLContext | bool:
    """A context from ``tls:``, or ``True`` for the ordinary verified case.

    ``True`` rather than a context built by hand when nothing is configured, so
    an unconfigured store gets `httpx`'s own certifi bundle -- building an empty
    context here would silently trust nothing and fail against every public CA.

    ``False`` is the whole of ``verify: false``: no context, no verification.
    The config layer has already warned about it (`SOPULI-W004`), so this does
    not warn again -- it is one weakening, and saying it twice trains people to
    read neither.

    **A path that does not resolve is a** :class:`StoreError`, **not a
    traceback.** These are the one part of ``tls:`` the config layer deliberately
    does not check -- #135 settled that a block naming a CA file which does not
    exist is *valid* config, because declaring a store is config and reaching one
    is not (§3a). Which makes this the first moment anybody can find out, and a
    stack trace is not how an operator should be told that a filename is wrong.
    """
    if tls is None:
        return True
    if not tls.verified:
        return False
    if tls.ca_file is None and tls.ca_path is None and tls.client_cert is None:
        return True

    try:
        context = ssl.create_default_context(cafile=tls.ca_file, capath=tls.ca_path)
    except (OSError, ssl.SSLError) as error:
        raise StoreError(
            f"could not load the CA material this store's `tls:` names: {error}",
            hint=_tls_hint(("ca_file", tls.ca_file), ("ca_path", tls.ca_path)),
        ) from error

    if tls.client_cert is not None:
        # `client_key` may be absent: a combined PEM holds both halves, which is
        # why §10 refuses only the other direction.
        try:
            context.load_cert_chain(certfile=tls.client_cert, keyfile=tls.client_key)
        except (OSError, ssl.SSLError) as error:
            raise StoreError(
                f"could not load the client certificate this store's `tls:` names: {error}",
                hint=_tls_hint(("client_cert", tls.client_cert), ("client_key", tls.client_key)),
            ) from error
    return context


def _tls_hint(*keys: tuple[str, str | None]) -> str:
    """Name the keys and the paths, because the message cannot.

    The underlying error says "No such file or directory" and, depending on the
    platform, may not include the filename at all -- and it never says which of
    two keys the file came from. That is the whole of what makes this actionable.
    """
    written = [f"{key}: {value}" for key, value in keys if value is not None]
    return (
        "checked " + ", ".join(written) + " -- the path is read from where the tool runs, "
        "which is not where the config file lives if you passed `--config`"
    )

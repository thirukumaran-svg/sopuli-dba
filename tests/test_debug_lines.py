"""The debug lines in the Oracle driver, the vault transport and the webhook (#782).

Tier 0 for each line's shape and for what it leaves out: a password, a bind
value, a request body, a token, a webhook URL's path. Tier 1 for a whole
`creds rotate --debug` against Oracle and Vault, because only a real run shows
every line a rotation writes. `account reset-password --debug` is in
`tests/test_cli_reset_password.py`, beside the seen path's other tests.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from fault_harness import ACCOUNT, OLD, SECRET, Estate
from sopuli.cli import _as_error, _finding
from sopuli.driver.oracle.statements import Statement
from sopuli.driver.oracle.trace import TracedCursor, traced_cursor
from sopuli.driver.protocol import Credential
from sopuli.exit_codes import ExitCode
from sopuli.notify import webhook
from sopuli.output.debug import PREFIX, debugging
from sopuli.secrets import REDACTED, Secret
from sopuli.store.hashicorp._transport import Transport
from sopuli.store.protocol import StoreError

PASSWORD = "Tr0ub4dor_3"
TOKEN = "hvs.EXAMPLEEXAMPLEEXAMPLE"


@pytest.fixture
def debug() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    with debugging(True, stream=stream):
        yield stream


class FakeCursor:
    """Records each call, and raises when a test sets ``error``."""

    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[tuple[Any, ...]] = []

    def execute(self, *args: Any) -> None:
        self.calls.append(args)
        if self.error is not None:
            raise self.error

    def callproc(self, name: str, parameters: Any = None) -> None:
        self.calls.append((name, parameters))

    def fetchone(self) -> Any:
        return ("row",)

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *_: object) -> None:
        pass


class OracleError(Exception):
    """An exception in the shape `oracledb` raises: a detail object in ``args[0]``."""

    def __init__(self, full_code: str, message: str) -> None:
        detail = type("Detail", (), {"full_code": full_code, "message": message})()
        super().__init__(detail)


# ------------------------------------------------------------------ Oracle ---


def test_a_statement_with_a_password_is_logged_redacted_and_sent_in_full(
    debug: io.StringIO,
) -> None:
    cursor = FakeCursor()
    statement = Statement(
        f'ALTER USER "ACME_APP_USER" IDENTIFIED BY "{PASSWORD}"',
        redacted=f'ALTER USER "ACME_APP_USER" IDENTIFIED BY {REDACTED}',
    )

    TracedCursor(cursor).execute(statement)

    assert cursor.calls == [(f'ALTER USER "ACME_APP_USER" IDENTIFIED BY "{PASSWORD}"',)]
    written = debug.getvalue()
    assert PASSWORD not in written
    assert f'oracle: ALTER USER "ACME_APP_USER" IDENTIFIED BY {REDACTED} in ' in written


def test_a_query_is_logged_on_one_line_with_its_bind_names_and_not_their_values(
    debug: io.StringIO,
) -> None:
    cursor = FakeCursor()

    TracedCursor(cursor).execute(
        "SELECT account_status\n  FROM dba_users\n WHERE username = :name",
        {"name": "ACME_APP_USER"},
    )

    (line,) = debug.getvalue().splitlines()
    assert line.startswith(PREFIX)
    assert (
        "oracle: SELECT account_status FROM dba_users WHERE username = :name (binds :name) in "
        in line
    )
    assert "ACME_APP_USER" not in line


def test_a_string_with_a_password_clause_is_cut_off_after_it(debug: io.StringIO) -> None:
    """The backstop: only a `Statement` should carry a password, and a string
    that carries one by mistake still writes none here."""
    cursor = FakeCursor()
    sql = f'ALTER USER "ACME_APP_USER" IDENTIFIED BY "{PASSWORD}" ACCOUNT UNLOCK'

    TracedCursor(cursor).execute(sql)

    assert cursor.calls == [(sql,)]
    written = debug.getvalue()
    assert PASSWORD not in written
    assert 'oracle: ALTER USER "ACME_APP_USER" IDENTIFIED BY *** in ' in written


def test_parameters_reach_the_client_as_the_caller_passed_them() -> None:
    """``execute(sql)`` and ``execute(sql, None)`` are two calls, and a fake
    that told them apart would break if the cursor merged them."""
    cursor = FakeCursor()

    TracedCursor(cursor).execute("SELECT 1 FROM dual")
    TracedCursor(cursor).execute("SELECT 1 FROM dual", None)

    assert cursor.calls == [("SELECT 1 FROM dual",), ("SELECT 1 FROM dual", None)]


def test_an_error_is_logged_as_the_server_s_answer_and_raised(debug: io.StringIO) -> None:
    """Not "failed": a probe reads ORA-00942 as an absent capability."""
    cursor = FakeCursor(error=OracleError("ORA-01031", "insufficient privileges"))

    with pytest.raises(OracleError):
        TracedCursor(cursor).execute("SELECT 1 FROM dual")

    written = debug.getvalue()
    assert "oracle: SELECT 1 FROM dual answered ORA-01031 in " in written
    assert "insufficient privileges" not in written


def test_a_procedure_call_is_logged_by_name_and_never_its_arguments(
    debug: io.StringIO,
) -> None:
    cursor = FakeCursor()
    connection = type("Connection", (), {"cursor": lambda self: cursor})()

    with traced_cursor(connection) as traced:
        traced.callproc("dbms_session.set_identifier", ["run-id-123"])

    written = debug.getvalue()
    assert "oracle: call dbms_session.set_identifier in " in written
    assert "run-id-123" not in written


# ------------------------------------------------------------------- vault ---


def test_a_vault_request_is_logged_without_its_body_or_token(debug: io.StringIO) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(204)

    client = httpx.Client(
        base_url="https://vault.example.com",
        headers={"X-Vault-Token": TOKEN},
        transport=httpx.MockTransport(handle),
    )

    Transport(client).request(
        "POST", "secret/data/acme/dev/acme", json={"data": {"password": PASSWORD}}
    )

    written = debug.getvalue()
    assert "vault: POST /v1/secret/data/acme/dev/acme: 204 in " in written
    assert PASSWORD not in written
    assert TOKEN not in written


def test_a_vault_request_that_fails_is_logged_by_its_error_type(debug: io.StringIO) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client = httpx.Client(
        base_url="https://vault.example.com", transport=httpx.MockTransport(handle)
    )

    with pytest.raises(Exception, match="could not reach the store"):
        Transport(client).request("GET", "sys/health")

    assert "vault: GET /v1/sys/health: ConnectError in " in debug.getvalue()


def test_any_other_vault_request_error_is_logged(debug: io.StringIO) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        raise httpx.TooManyRedirects("loop", request=request)

    client = httpx.Client(
        base_url="https://vault.example.com", transport=httpx.MockTransport(handle)
    )

    with pytest.raises(StoreError, match="the request to the store failed: TooManyRedirects"):
        Transport(client).request("GET", "sys/health")

    assert "vault: GET /v1/sys/health: TooManyRedirects in " in debug.getvalue()


# ----------------------------------------------------------------- webhook ---


def test_a_webhook_is_logged_by_its_host_only(
    debug: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The path of a chat webhook URL is its token (C9)."""
    url = "https://chat.example.com/hooks/T00000/B00000/EXAMPLEEXAMPLEEXAMPLE"
    monkeypatch.setattr("sopuli.notify.webhook.httpx.post", lambda *_, **__: httpx.Response(204))

    webhook.send(Secret(url), "a password is waiting")

    written = debug.getvalue()
    assert "webhook: POST to chat.example.com: 204 in " in written
    assert "EXAMPLEEXAMPLEEXAMPLE" not in written
    assert "/hooks/" not in written


def test_a_webhook_with_no_host_says_so(
    debug: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(address: str, **_: Any) -> httpx.Response:
        raise httpx.UnsupportedProtocol("no scheme")

    monkeypatch.setattr("sopuli.notify.webhook.httpx.post", refuse)

    with pytest.raises(Exception, match="could not be reached"):
        webhook.send(Secret("hooks.example.com/services/T/B/X"), "a password is waiting")

    written = debug.getvalue()
    assert "webhook: POST to an address with no host: UnsupportedProtocol in " in written
    assert "/services/" not in written


# ---------------------------------------------------------------- findings ---


def test_a_finding_carries_its_traceback(debug: io.StringIO) -> None:
    """A per-target error does not end the run, so the run's own traceback
    never covers it. The finding writes one where it is made."""

    def connect() -> None:
        raise ConnectionError("target down")

    try:
        connect()
    except ConnectionError as error:
        _finding(error)

    written = debug.getvalue()
    assert "finding: finding from ConnectionError" in written
    assert "Traceback (most recent call last):" in written
    assert "in connect" in written


def test_an_error_converted_for_its_message_writes_no_traceback(debug: io.StringIO) -> None:
    """`_as_error` alone is not a finding. Some callers read only its message,
    and some raise the error afterwards, when the run's own traceback covers it."""
    try:
        raise ConnectionError("target down")
    except ConnectionError as error:
        _as_error(error)

    assert debug.getvalue() == ""


# ---------------------------------------------------------- failure paths ---


def test_a_webhook_that_cannot_be_reached_is_logged_by_its_host_and_error_type(
    debug: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    """httpx puts the URL in its error messages, and the URL is the credential."""
    url = "https://chat.example.com/hooks/T00000/B00000/EXAMPLEEXAMPLEEXAMPLE"

    def refuse(address: str, **_: Any) -> httpx.Response:
        raise httpx.ConnectError(f"cannot reach {address}")

    monkeypatch.setattr("sopuli.notify.webhook.httpx.post", refuse)

    with pytest.raises(Exception, match="could not be reached"):
        webhook.send(Secret(url), "a password is waiting")

    written = debug.getvalue()
    assert "webhook: POST to chat.example.com: ConnectError in " in written
    assert "EXAMPLEEXAMPLEEXAMPLE" not in written


def test_a_webhook_url_httpx_cannot_parse_is_reported_by_error_type(
    debug: io.StringIO,
) -> None:
    """`httpx.InvalidURL` is not an `HTTPError`, and its message quotes part of the URL (#785)."""
    url = "https://chat.example.com:EXAMPLEPORT/hooks/T00000/B00000/EXAMPLE"

    with pytest.raises(StoreError) as raised:
        webhook.send(Secret(url), "a password is waiting")

    assert raised.value.message == "the webhook URL could not be used: InvalidURL"
    written = debug.getvalue()
    assert "webhook: POST to an address httpx could not parse: InvalidURL in " in written
    assert "EXAMPLEPORT" not in written


def test_a_vault_request_that_times_out_is_logged(debug: io.StringIO) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    client = httpx.Client(
        base_url="https://vault.example.com", transport=httpx.MockTransport(handle)
    )

    with pytest.raises(Exception, match="did not answer within the timeout"):
        Transport(client).request("GET", "kv/data/acme/dev/acme")

    assert "vault: GET /v1/kv/data/acme/dev/acme: timed out in " in debug.getvalue()


def test_a_connect_that_fails_is_logged_by_its_code(
    debug: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    """And an `auth: external` credential, which has no username, is named as such."""
    oracledb = pytest.importorskip("oracledb")
    from sopuli.driver.oracle import session as session_module

    def refuse(**_: Any) -> Any:
        raise oracledb.DatabaseError("ORA-12541: Cannot connect. No listener at host 192.0.2.10")

    monkeypatch.setattr(session_module, "initialise", lambda **_: None)
    monkeypatch.setattr(session_module, "connect_arguments", lambda *_, **__: {})
    monkeypatch.setattr(oracledb, "connect", refuse)
    driver = session_module.OracleDriver(env={}, correlation_id="run-id")

    with pytest.raises(Exception, match="ORA-12541"):
        driver.connect(SimpleNamespace(name="alpha-pdb"), Credential())  # type: ignore[arg-type]

    written = debug.getvalue()
    assert (
        "oracle: connect to alpha-pdb as the external credential failed with ORA-12541" in written
    )


# ---------------------------------------------------------- tier 1: rotate ---


def test_a_rotation_with_debug_logs_its_statements_and_never_a_password(
    fault_estate: Estate, vault_stack: Any
) -> None:
    """A real `creds rotate --debug`, end to end.

    The new password is read from the vault afterwards, and neither it nor the
    old one may appear on stderr. The redacted `ALTER USER` and the vault
    requests must, or the test proves nothing about the lines it means to check.
    """
    result = fault_estate.sopuli(
        fault_estate.config(vault_stack.addr), "creds", "rotate", "--confirm", "--debug"
    )

    assert result.returncode == ExitCode.SUCCESS, result.stderr
    document, _ = fault_estate.read(SECRET)
    new = document["DB_CREDENTIALS"][ACCOUNT]
    assert fault_estate.login(new)
    assert new not in result.stderr
    assert OLD not in result.stderr
    assert new not in result.stdout
    assert vault_stack.token not in result.stderr
    assert f"IDENTIFIED BY {REDACTED}" in result.stderr
    assert f"/v1/{fault_estate.mount}/data/{SECRET}: 200 in " in result.stderr
    assert "capabilities " in result.stderr
    json.loads(result.stdout)  # stdout is still one document

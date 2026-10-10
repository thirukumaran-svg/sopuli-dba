"""Whether a connection is encrypted, read from what the session reports.

Tier 0. The banner rows below are copied from
``sql/oracle/12_connection_encryption_probe.sql``'s runs, one per release, so
the classifier is tested against what the server sent rather than against what
the documentation says it sends.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.oracle.capabilities import (
    CONNECT_INFO,
    NETWORK_PROTOCOL,
    UNREADABLE_HINT,
    classify_encryption,
    encryption_of,
)
from sopuli.driver.protocol import (
    ENCRYPTION_NATIVE,
    ENCRYPTION_NONE,
    ENCRYPTION_TLS,
    UNKNOWN,
    Encryption,
    Scope,
)

PLAIN_23 = [
    "TCP/IP NT Protocol Adapter for Linux: Version 23.26.2.0.0 - Production",
    "Encryption service for Linux: Version 23.26.2.0.0 - Production",
    "Crypto-checksumming service for Linux: Version 23.26.2.0.0 - Production",
]
NNE_23 = [
    "TCP/IP NT Protocol Adapter for Linux: Version 23.26.2.0.0 - Production",
    "Encryption service for Linux: Version 23.26.2.0.0 - Production",
    "AES256 Encryption service adapter for Linux: Version 23.26.2.0.0 - Production",
    "Crypto-checksumming service for Linux: Version 23.26.2.0.0 - Production",
]
PLAIN_11 = [
    "TCP/IP NT Protocol Adapter for Linux: Version 11.2.0.2.0 - Production",
    "Oracle Advanced Security: encryption service for Linux: Version 11.2.0.2.0 - Production",
    "Oracle Advanced Security: crypto-checksumming service for Linux: "
    "Version 11.2.0.2.0 - Production",
]
NNE_11 = [
    "TCP/IP NT Protocol Adapter for Linux: Version 11.2.0.2.0 - Production",
    "Oracle Advanced Security: encryption service for Linux: Version 11.2.0.2.0 - Production",
    "Oracle Advanced Security: AES256 encryption service adapter for Linux: "
    "Version 11.2.0.2.0 - Production",
    "Oracle Advanced Security: crypto-checksumming service for Linux: "
    "Version 11.2.0.2.0 - Production",
]


@pytest.mark.parametrize("banners", [PLAIN_23, PLAIN_11], ids=["23.26", "11.2"])
def test_a_plain_tcp_connection_is_not_encrypted(banners: list[str]) -> None:
    """The ``Encryption service for Linux`` row is on every connection.

    It names the service, not an algorithm in use, so it must not be read as
    NNE. Matching on "encryption service" alone would call every connection
    encrypted.
    """
    found = classify_encryption("tcp", lambda: banners)
    assert found.method == ENCRYPTION_NONE
    assert found.algorithm is None
    assert found.hint is not None


@pytest.mark.parametrize("banners", [NNE_23, NNE_11], ids=["23.26", "11.2"])
def test_the_adapter_row_means_nne_and_names_the_algorithm(banners: list[str]) -> None:
    """11.2 writes the row in lower case after a prefix; later releases do not."""
    found = classify_encryption("tcp", lambda: banners)
    assert found == Encryption(method=ENCRYPTION_NATIVE, algorithm="AES256", protocol="tcp")


def _never() -> list[str]:
    raise AssertionError("the banners were read where they decide nothing")


def test_tcps_is_tls_without_reading_the_banners() -> None:
    assert classify_encryption("tcps", _never).method == ENCRYPTION_TLS
    assert classify_encryption("TCPS", _never).method == ENCRYPTION_TLS


def test_an_unreadable_view_is_unknown_not_unencrypted() -> None:
    """Could not look is not the same answer as looked and found nothing."""
    found = classify_encryption("tcp", lambda: None)
    assert found.method == UNKNOWN
    assert found.hint is not None
    assert "V_$SESSION_CONNECT_INFO" in found.hint


@pytest.mark.parametrize("protocol", ["ipc", "beq", None])
def test_an_unmeasured_transport_is_unknown(protocol: str | None) -> None:
    """Only TCP and TCPS were measured. Anything else is not guessed at."""
    found = classify_encryption(protocol, _never)
    assert found.method == UNKNOWN
    assert found.protocol == protocol


class _Cursor:
    """Answers each statement with rows, or raises the exception it maps to."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.asked: list[str] = []
        self.sql = ""

    def execute(self, sql: str, parameters: Any = None, /) -> _Cursor:
        self.asked.append(sql)
        self.sql = sql
        answer = self.answers.get(sql, [(0,)])
        if isinstance(answer, Exception):
            raise answer
        return self

    def fetchone(self) -> Any:
        rows = self.answers.get(self.sql, [(0,)])
        return rows[0] if rows else None

    def fetchall(self) -> Any:
        return self.answers.get(self.sql, [(0,)])


def _ora(code: str) -> RuntimeError:
    return RuntimeError(f"{code}: something the server said")


def test_the_session_is_asked_for_its_protocol_and_its_banners() -> None:
    cursor = _Cursor({NETWORK_PROTOCOL: [("tcp",)], CONNECT_INFO: [(banner,) for banner in NNE_23]})
    assert encryption_of(cursor).method == ENCRYPTION_NATIVE
    assert cursor.asked == [NETWORK_PROTOCOL, CONNECT_INFO]


def test_a_tls_session_does_not_read_the_view() -> None:
    cursor = _Cursor({NETWORK_PROTOCOL: [("tcps",)]})
    assert encryption_of(cursor).method == ENCRYPTION_TLS
    assert cursor.asked == [NETWORK_PROTOCOL]


@pytest.mark.parametrize("code", ["ORA-00942", "ORA-41900", "ORA-01031"])
def test_a_revoked_view_reads_as_unknown_and_names_the_grant(code: str) -> None:
    cursor = _Cursor({NETWORK_PROTOCOL: [("tcp",)], CONNECT_INFO: _ora(code)})
    found = encryption_of(cursor)
    assert found.method == UNKNOWN
    assert found.hint == UNREADABLE_HINT


def test_a_missing_column_is_not_blamed_on_a_grant() -> None:
    """``ORA-00904`` is in ``ABSENT_CODES`` for the probes, but no grant fixes a
    missing column, so the server's own message is reported instead."""
    cursor = _Cursor({NETWORK_PROTOCOL: [("tcp",)], CONNECT_INFO: _ora("ORA-00904")})
    found = encryption_of(cursor)
    assert found.method == UNKNOWN
    assert found.hint is not None
    assert "ORA-00904" in found.hint
    assert found.hint != UNREADABLE_HINT


def test_no_rows_for_the_session_is_unknown_not_unencrypted() -> None:
    """Every connection measured has at least one row. None at all means the
    session could not see its own, and "in clear" would be a false finding."""
    found = classify_encryption("tcp", lambda: [])
    assert found.method == UNKNOWN
    assert found.hint is not None


def test_a_scope_without_an_answer_says_why() -> None:
    """A driver that does not read encryption still gives ``unknown`` a hint."""
    assert Scope().encryption.method == UNKNOWN
    assert Scope().encryption.hint is not None


def test_an_unexpected_failure_is_unknown_and_keeps_the_code() -> None:
    """A rotation must not stop over a fact it only reports.

    The capability probes raise on a code outside ``ABSENT_CODES``, because a
    command branches on their answer. Nothing branches on this one, so the
    failure becomes ``unknown`` and the server's code stays in the hint.
    """
    cursor = _Cursor({NETWORK_PROTOCOL: [("tcp",)], CONNECT_INFO: _ora("ORA-03113")})
    found = encryption_of(cursor)
    assert found.method == UNKNOWN
    assert found.protocol == "tcp"
    assert found.hint is not None
    assert "ORA-03113" in found.hint


@pytest.mark.parametrize("code", ["ORA-01031", "ORA-03113"])
def test_an_unreadable_protocol_is_named_as_such(code: str) -> None:
    """Not blamed on the transport: the read failed, so say that."""
    found = encryption_of(_Cursor({NETWORK_PROTOCOL: _ora(code)}))
    assert found.method == UNKNOWN
    assert found.hint is not None
    assert "TCP and TCPS" not in found.hint


def test_the_statement_filters_on_the_session_s_own_sid() -> None:
    """On every release measured but 26ai the view showed other sessions, so a
    read without the filter would report somebody else's connection."""
    assert "sys_context('userenv','sid')" in CONNECT_INFO

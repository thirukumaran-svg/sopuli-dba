"""SOPULI-W031 and W032: a password sent over a connection in clear, or unknown. Tier 0."""

from __future__ import annotations

from sopuli.diagnostics import (
    CONNECTION_ENCRYPTION_UNKNOWN,
    CONNECTION_UNENCRYPTED,
    WARNINGS,
    encryption_diagnostics,
    worse_encryption,
)
from sopuli.driver.protocol import Encryption

CLEAR = Encryption(method="none", protocol="tcp", hint="require NNE or TLS")
UNKNOWN = Encryption(method="unknown", protocol="tcp", hint="grant the view")
TLS = Encryption(method="tls", protocol="tcps")
NNE = Encryption(method="native", algorithm="AES256", protocol="tcp")


def test_both_codes_are_registered() -> None:
    assert CONNECTION_UNENCRYPTED in WARNINGS
    assert CONNECTION_ENCRYPTION_UNKNOWN in WARNINGS


def test_an_encrypted_connection_is_not_a_finding() -> None:
    assert encryption_diagnostics([("appdb-alpha", TLS), ("appdb-beta", NNE)]) == []


def test_one_warning_per_target_however_many_accounts() -> None:
    """Encryption is a property of the connection, not of an account."""
    found = encryption_diagnostics([("appdb-alpha", CLEAR)] * 3 + [("appdb-beta", UNKNOWN)])

    assert [(one.target, one.code) for one in found] == [
        ("appdb-alpha", CONNECTION_UNENCRYPTED),
        ("appdb-beta", CONNECTION_ENCRYPTION_UNKNOWN),
    ]


def test_the_message_carries_the_driver_s_hint() -> None:
    (found,) = encryption_diagnostics([("appdb-alpha", CLEAR)])

    assert found.level == "warning"
    assert found.message.startswith("appdb-alpha: ")
    assert found.message.endswith(": require NNE or TLS")


def test_the_worst_answer_for_a_target_is_kept() -> None:
    """A redraw reconnects, so one target can bring two answers."""
    found = encryption_diagnostics(
        [
            ("appdb-alpha", UNKNOWN),
            ("appdb-alpha", CLEAR),
            ("appdb-beta", TLS),
            ("appdb-beta", UNKNOWN),
        ]
    )

    assert [(one.target, one.code) for one in found] == [
        ("appdb-alpha", CONNECTION_UNENCRYPTED),
        ("appdb-beta", CONNECTION_ENCRYPTION_UNKNOWN),
    ]


def test_the_worse_answer_is_none_then_unknown() -> None:
    assert worse_encryption(TLS, CLEAR) is CLEAR
    assert worse_encryption(CLEAR, UNKNOWN) is CLEAR
    assert worse_encryption(TLS, UNKNOWN) is UNKNOWN
    assert worse_encryption(NNE, TLS) is NNE, "two encrypted answers keep the first"


def test_a_pass_that_sent_nothing_loses_to_any_answer() -> None:
    """A redraw pass that sent nothing does not erase what an earlier one sent."""
    assert worse_encryption(CLEAR, None) is CLEAR
    assert worse_encryption(None, CLEAR) is CLEAR
    assert worse_encryption(None, None) is None

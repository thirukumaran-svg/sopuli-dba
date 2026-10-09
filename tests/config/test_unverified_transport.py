"""`tls.verify: false` says so on every run (ADR-005, §3a).

The weakening is written once, in a file somebody may have edited a year ago,
and it applies to every rotation afterwards. A key visible in the YAML is not
the same reach as a warning in each run's audit trail, which is why ADR-005
asked for a diagnostic rather than being satisfied that the config is readable.

A warning and never an error: an internal CA nobody has distributed yet is a
real situation, and a tool that refused to run would be unusable exactly where
an operator most needs it to say what it is doing.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from click.testing import CliRunner

from sopuli.cli import cli
from sopuli.config.loading import build_config
from sopuli.config.references import UNVERIFIED_TRANSPORT
from sopuli.diagnostics import WARNINGS
from sopuli.exit_codes import ExitCode

WriteConfig = Callable[[str], Path]

UNVERIFIED = """version: 1
vaults:
  vault-dev:
    type: hashicorp
    addr: https://192.0.2.14:8200
    tls: { verify: false }
"""

VERIFIED = """version: 1
vaults:
  vault-prod:
    type: hashicorp
    addr: https://vault.example.com
    tls:
      ca_file: /etc/ssl/acme-ca.pem
"""


def _warnings(document: dict[str, Any]) -> list[dict[str, str]]:
    diagnostics: list[dict[str, str]] = document.get("diagnostics", [])
    return [entry for entry in diagnostics if entry.get("code") == UNVERIFIED_TRANSPORT]


def _validate_json(path: Path) -> dict[str, Any]:
    result = CliRunner().invoke(
        cli, ["--config", str(path), "--output", "json", "config", "validate"]
    )
    return dict(json.loads(result.output))


def test_a_store_that_does_not_verify_produces_a_warning() -> None:
    config = build_config(
        {
            "version": 1,
            "vaults": {"vault-dev": {"type": "hashicorp", "tls": {"verify": False}}},
        }
    )

    [warning] = [entry for entry in config.warnings if entry.code == UNVERIFIED_TRANSPORT]
    assert "vault-dev" in warning.message
    assert warning.at == "vaults.vault-dev.tls.verify"


def test_a_store_that_verifies_produces_none() -> None:
    """The control. A warning that fired for every store would look exactly like
    this suite passing, and would train everyone to ignore it."""
    config = build_config(
        {
            "version": 1,
            "vaults": {
                "a": {"type": "hashicorp", "tls": {"ca_file": "/etc/ssl/ca.pem"}},
                "b": {"type": "hashicorp"},
            },
        }
    )

    assert [entry for entry in config.warnings if entry.code == UNVERIFIED_TRANSPORT] == []


def test_one_warning_per_store() -> None:
    config = build_config(
        {
            "version": 1,
            "vaults": {
                "one": {"type": "hashicorp", "tls": {"verify": False}},
                "two": {"type": "hashicorp", "tls": {"verify": False}},
                "three": {"type": "hashicorp"},
            },
        }
    )

    found = [entry for entry in config.warnings if entry.code == UNVERIFIED_TRANSPORT]
    assert len(found) == 2


def test_it_reaches_the_run_document_with_its_code(write_config: WriteConfig) -> None:
    """The reason the code exists: "did any run this month talk to a vault
    unverified" is answerable from the code and not from prose."""
    document = _validate_json(write_config(UNVERIFIED))

    [warning] = _warnings(document)
    assert warning["level"] == "warning"
    assert warning["code"] == UNVERIFIED_TRANSPORT


def test_it_is_a_warning_and_the_run_still_succeeds(write_config: WriteConfig) -> None:
    path = write_config(UNVERIFIED)

    result = CliRunner().invoke(cli, ["--config", str(path), "config", "validate"])

    assert result.exit_code == ExitCode.SUCCESS
    assert "does not verify its certificate" in result.output


def test_a_verified_config_says_nothing_about_it(write_config: WriteConfig) -> None:
    assert _warnings(_validate_json(write_config(VERIFIED))) == []


def test_the_code_is_in_the_registry() -> None:
    """`03-json-output.md` §3: a code is contract, and the registry says what it
    means. `tests/test_lock_view.py` asserts nothing emits one the registry does
    not describe; this asserts it is there to be found."""
    assert UNVERIFIED_TRANSPORT in WARNINGS
    assert "verify" in WARNINGS[UNVERIFIED_TRANSPORT]

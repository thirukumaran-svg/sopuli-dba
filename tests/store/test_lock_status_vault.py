"""``lock status`` against a real Vault (#105).

Tier 1. `tests/test_cli_lock_status.py` covers the command with the store handed
in, which is where the wiring belongs; the one thing a fake cannot tell us is
whether the chain a config file starts actually completes — entry, backend,
token, read — and that is all this file asserts.

It is worth its own module rather than a case in the tier-0 file for the reason
`04-testing.md` §1 gives: this skips when there is no Vault, and a skip that
takes the wiring tests with it would leave the command untested on a machine with
no containers.

The record is written **through the Vault API directly**, not through the tool.
The subject is reading somebody else's lock, and a record this process wrote with
the tool's own manager would be a record the tool already understood by
construction.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from sopuli.cli import cli
from sopuli.exit_codes import ExitCode
from sopuli.material import MaterialError

pytest.importorskip("httpx")

#: The **secret** path. The record lands under `locks/`, which the manager adds
#: and this test therefore has to add for itself when writing one by hand.
SECRET_PATH = "apps/acme/status"
LOCK_PATH = f"locks/{SECRET_PATH}"

#: Fixed rather than `now`, because nothing here is about expiry: a claim from
#: 2026 is as readable as one from this second, and a frozen record makes the
#: assertion about the reading rather than about the clock.
ACQUIRED_AT = "2026-08-16T12:00:00Z"
EXPIRES_AT = "2026-08-16T12:15:00Z"

RECORD = {
    "state": "held",
    "correlation_id": "01JTHEIRS",
    "command": "creds rotate",
    "holder": {"host": "ci-runner-3", "pid": 8821, "os_user": "svc_sopuli"},
    "acquired_at": ACQUIRED_AT,
    "expires_at": EXPIRES_AT,
    "selection": "env=prod",
}

CONFIG = """\
version: 1
vaults:
  vault-dev:
    type: hashicorp
    addr: {addr}
    mount: {mount}
    kv_version: 2
    auth:
      method: token
targets:
  - name: appdb-alpha
    type: oracle
    dsn: db-dev.example.com:1521/alpha.pdb.example.com
    environment: dev
    vault: vault-dev
applications:
  - name: acme
    accounts: [acme_web_user]
    secret: "{secret}#password"
"""


@pytest.fixture
def config_path(vault_stack: Any, tmp_path: Path) -> Path:
    path = tmp_path / "sopuli.yaml"
    path.write_text(
        CONFIG.format(addr=vault_stack.addr, mount=vault_stack.kv2_mount, secret=SECRET_PATH),
        encoding="utf-8",
    )
    if sys.platform != "win32":
        path.chmod(0o600)
    return path


@pytest.fixture
def their_lock(vault_stack: Any) -> Iterator[None]:
    """Somebody else's held record, written straight to the API.

    Cleaned up with a metadata delete, which wipes the version counter as well as
    the data -- something the tool itself never does (#83) and exactly what a
    test needs between runs.
    """
    mount = vault_stack.kv2_mount
    vault_stack.client.delete(f"/v1/{mount}/metadata/{LOCK_PATH}")
    vault_stack.client.post(f"/v1/{mount}/data/{LOCK_PATH}", json={"data": RECORD})
    yield
    vault_stack.client.delete(f"/v1/{mount}/metadata/{LOCK_PATH}")


@pytest.fixture
def token_in_env(vault_stack: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """`method: token` with nothing written down falls through to the
    environment (§3a), which is the chain a production run uses. Invariant 1
    rules out the other way of getting it here."""
    monkeypatch.setenv("VAULT_TOKEN", vault_stack.token)
    monkeypatch.delenv("SOPULI_VAULT_TOKEN", raising=False)


def invoke(config_path: Path, *args: str) -> Any:
    return CliRunner().invoke(cli, ["lock", "status", "--config", str(config_path), *args])


@pytest.mark.usefixtures("their_lock", "token_in_env")
def test_a_config_entry_reaches_a_real_vault_and_reads_somebody_elses_lock(
    config_path: Path,
) -> None:
    """The whole chain in one assertion: the entry describes the transport, the
    registry finds the backend, the material resolver produces a token, and the
    adapter reads a record this process did not write."""
    result = invoke(config_path, "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    found = json.loads(result.output)["lock"]["found"]
    assert len(found) == 1
    assert found[0]["path"] == SECRET_PATH
    assert found[0]["held"] is True
    assert found[0]["acquired_at"] == ACQUIRED_AT
    assert found[0]["holder"] == {
        "host": "ci-runner-3",
        "pid": 8821,
        "os_user": "svc_sopuli",
        "correlation_id": "01JTHEIRS",
        "command": "creds rotate",
    }


@pytest.mark.usefixtures("their_lock", "token_in_env")
def test_the_version_reported_is_the_store_s_own(config_path: Path, vault_stack: Any) -> None:
    """It is what a takeover will have to compare-and-set against (#149), so a
    number that does not match the store's is worse than no number at all."""
    mount = vault_stack.kv2_mount
    vault_stack.client.post(
        f"/v1/{mount}/data/{LOCK_PATH}", json={"data": RECORD, "options": {"cas": 1}}
    )

    found = json.loads(invoke(config_path, "--output", "json").output)["lock"]["found"]

    assert found[0]["version"] == 2


@pytest.mark.usefixtures("token_in_env")
def test_a_path_with_no_record_is_surveyed_and_reported_free(
    config_path: Path, vault_stack: Any
) -> None:
    """A 404 from KV v2 is a state, not a failure. The command that treated it as
    one would report every quiet estate as broken."""
    vault_stack.client.delete(f"/v1/{vault_stack.kv2_mount}/metadata/{LOCK_PATH}")

    result = invoke(config_path, "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert json.loads(result.output)["lock"] == {"mode": "cas", "found": []}


@pytest.mark.usefixtures("their_lock")
def test_no_token_anywhere_is_reported_as_an_incomplete_machine(
    config_path: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Exit 9, not 6, and the distinction is the one `MaterialError` exists to
    draw: nothing was refused, there was nothing to send. Exit 6 would tell a
    scheduler the store rejected a credential that was never presented.

    It is asserted here rather than in the tier-0 file because the point is that
    a *reachable* Vault is not enough -- the run fails before the first request,
    which is the only place that distinction is observable."""
    for name in ("VAULT_TOKEN", "SOPULI_VAULT_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    # `~/.vault-token` is the last step of the fall-through and belongs to
    # whoever is running the suite; pointing HOME at an empty directory is what
    # makes the assertion about the tool rather than about the machine.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("VAULT_ADDR", raising=False)

    result = invoke(config_path)

    # `CliRunner` drives the group rather than `main()`, so the exception is
    # what the command decided and the exit code is what the boundary would
    # make of it -- which is the half worth asserting here.
    assert isinstance(result.exception, MaterialError)
    assert result.exception.exit_code == ExitCode.CONFIG_INVALID
    assert "no token" in str(result.exception)


@pytest.mark.usefixtures("their_lock", "token_in_env")
def test_the_survey_writes_nothing(config_path: Path, vault_stack: Any) -> None:
    """#83: `check`, `status` and every `--dry-run` take no lock. Asserted
    against the store's version counter, because a write is what a lock is --
    and against a *real* store, where an accidental write would persist."""
    mount = vault_stack.kv2_mount
    before = vault_stack.client.get(f"/v1/{mount}/metadata/{LOCK_PATH}").json()

    invoke(config_path, "--output", "json")

    after = vault_stack.client.get(f"/v1/{mount}/metadata/{LOCK_PATH}").json()
    assert after["data"]["current_version"] == before["data"]["current_version"]

"""``lock break`` against a real Vault, and the fence it leaves behind (#149).

Tier 1. `tests/test_cli_lock_break.py` covers the command with the store handed
in, which is where the refusals and the document belong. Two things here need a
real store and are the whole reason this file exists:

**The write is a compare-and-set against a version Vault issued.** A fake that
counts integers agrees with the tool by construction; KV v2 is the thing that has
to agree.

**The previous holder is actually fenced.** That is the entire safety argument
for having this verb at all, and it can only be shown by taking a lock away from
a :class:`~sopuli.lock.manager.LockManager` that is holding it and watching its
next check fail. Everything else about breaking a lock is a decision; this is a
property, and a property is worth a container.

The record the break takes is written **through the Vault API directly**, the way
``test_lock_status_vault.py`` writes one: the subject is somebody else's lock, and
a record this process made with the tool's own manager would be one the tool
already understood by construction. The fencing test is the exception and says so
-- there the point is a manager that believes it still holds something.
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
from sopuli.lock.errors import LockStolenError
from sopuli.lock.keys import LockKey
from sopuli.lock.manager import LockableStore, LockManager
from sopuli.lock.record import RELEASED
from sopuli.store import connect

pytest.importorskip("httpx")

#: The **secret** path. The record lands under `locks/`, which the manager adds
#: and this test therefore has to add for itself when writing one by hand.
SECRET_PATH = "apps/acme/break"
LOCK_PATH = f"locks/{SECRET_PATH}"

#: Fixed and long past, so the record is expired without anything here having to
#: wait for a clock: `break` takes an expired lock on confirmation alone, and
#: `--force` has its own case in the tier-0 file.
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
    """Somebody else's expired record, written straight to the API.

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
    environment (§3a), which is the chain a production run uses."""
    monkeypatch.setenv("VAULT_TOKEN", vault_stack.token)
    monkeypatch.delenv("SOPULI_VAULT_TOKEN", raising=False)


def invoke(config_path: Path, *args: str) -> Any:
    return CliRunner().invoke(cli, ["lock", "break", "--config", str(config_path), *args])


KEY = LockKey(store="vault-dev", path=SECRET_PATH)


@pytest.mark.usefixtures("their_lock", "token_in_env")
def test_a_config_entry_reaches_a_real_vault_and_takes_somebody_elses_lock(
    config_path: Path, vault_stack: Any
) -> None:
    """The whole chain, ending in a write: the entry describes the transport, the
    registry finds the backend, the material resolver produces a token, and KV v2
    accepts a compare-and-set against the version the read reported."""
    result = invoke(config_path, str(KEY), "--confirm", "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    broken = json.loads(result.output)["lock"]["broken"]
    assert len(broken) == 1
    assert broken[0]["applied"] is True
    assert broken[0]["version"] == 1
    assert broken[0]["new_version"] == 2
    assert broken[0]["holder"]["os_user"] == "svc_sopuli"

    mount = vault_stack.kv2_mount
    stored = vault_stack.client.get(f"/v1/{mount}/data/{LOCK_PATH}").json()
    assert stored["data"]["data"]["state"] == RELEASED
    # Never a delete: the path still answers, and its version counter is intact.
    assert stored["data"]["metadata"]["version"] == 2


@pytest.mark.usefixtures("their_lock", "token_in_env")
def test_the_break_fences_the_run_that_held_it(config_path: Path, vault_stack: Any) -> None:
    """The property the verb exists to have, and the only test that can show it.

    A manager holding a lock is taken from behind its back, and its next fence
    check -- the one it makes before every mutation -- refuses. That is what makes
    breaking a lock survivable rather than reckless: the run whose lock was taken
    stops before its next `ALTER USER` instead of applying a password the vault no
    longer advertises.
    """
    entry = next(vault for vault in _config_of(config_path).vaults if vault.name == "vault-dev")
    store = connect(entry, env={"VAULT_TOKEN": vault_stack.token})
    mount = vault_stack.kv2_mount
    vault_stack.client.delete(f"/v1/{mount}/metadata/{LOCK_PATH}")

    holder = LockManager(
        stores={"vault-dev": LockableStore(store=store)},
        correlation_id="01JMINE",
        command="creds rotate",
    )
    holder.acquire([KEY])
    holder.check()  # still theirs, before anybody interferes

    broken = invoke(config_path, str(KEY), "--confirm", "--force")
    assert broken.exit_code == ExitCode.SUCCESS, broken.output

    with pytest.raises(LockStolenError) as caught:
        holder.check()
    assert "taken over" in str(caught.value) or "held by" in str(caught.value)


@pytest.mark.usefixtures("token_in_env")
def test_a_free_path_is_reported_and_nothing_is_written(
    config_path: Path, vault_stack: Any
) -> None:
    """A 404 from KV v2 is a state, not a failure -- and a `break` that wrote a
    released record over nothing would create the version history that stops the
    *next* first acquisition from ever succeeding."""
    mount = vault_stack.kv2_mount
    vault_stack.client.delete(f"/v1/{mount}/metadata/{LOCK_PATH}")

    result = invoke(config_path, str(KEY), "--confirm", "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert json.loads(result.output)["lock"] == {"mode": "cas", "broken": []}
    assert vault_stack.client.get(f"/v1/{mount}/metadata/{LOCK_PATH}").status_code == 404


@pytest.mark.usefixtures("their_lock", "token_in_env")
def test_a_dry_run_leaves_the_version_counter_where_it_found_it(
    config_path: Path, vault_stack: Any
) -> None:
    """Invariant 8, asserted against a real store, where an accidental write
    would persist and would also have fenced somebody for nothing."""
    mount = vault_stack.kv2_mount
    before = vault_stack.client.get(f"/v1/{mount}/metadata/{LOCK_PATH}").json()

    result = invoke(config_path, str(KEY), "--dry-run")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    after = vault_stack.client.get(f"/v1/{mount}/metadata/{LOCK_PATH}").json()
    assert after["data"]["current_version"] == before["data"]["current_version"]


def _config_of(path: Path) -> Any:
    """The parsed configuration, for the one test that needs a store of its own.

    Through the loader rather than by hand, so the manager in that test reaches
    the same Vault, on the same mount, that the command under test does.
    """
    from sopuli.config.loading import load_layers

    _declared, config = load_layers([path])
    return config

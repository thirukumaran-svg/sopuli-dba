"""Fault injection: a run killed part way through (`04-testing.md` §5).

Two rows of §5's table, each asserting the documented recovery and not only
that nothing crashed:

* a run killed between ``password_set`` and ``vault_promote``. ``pending``
  still holds the new password, ``status`` reports ``PENDING_APPLY``, and a
  second ``creds apply`` completes the promotion;
* a run killed while it holds a lock. Once the lock has expired, the next run
  refuses with exit 7 and names the holder. Under ``locking.break_expired`` it
  takes the lock over with a write that bumps the version.

Each kill is real: ``sopuli`` runs as its own process and is killed without a
chance to clean up. :mod:`fault_harness` says why a proxy holds the promotion
write first.

These need only the tier-1 services, Oracle Free and Vault, and skip without
them.
"""

from __future__ import annotations

import contextlib
import itertools
import json
import os
import subprocess
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from fault_harness import TIMEOUT, CliRun, VaultGate, sopuli_command
from oracle_harness import Environment
from sopuli.config.targets import ADMIN_PASSWORD_ENV
from sopuli.exit_codes import ExitCode

ACCOUNT = "acme_fault_user"
OLD = "Old-Pa55word-Fault1"

#: The secret path the template below produces, and the lock path beside it.
SECRET = "acme/dev/acme"
LOCK = f"locks/{SECRET}"

CONFIG = """version: 1

defaults:
  policy: standard
  vault: vault-dev
{locking}
vaults:
  vault-dev:
    type: hashicorp
    addr: {addr}
    mount: {mount}
    kv_version: 2
    auth: {{ method: token }}

targets:
  - name: free-pdb
    type: oracle
    environment: dev
    vault: vault-dev
    dsn: "{dsn}"
    admin: {{ username: {user}, auth: {{ method: env }} }}

policies:
  standard:
    password:
      length: 24
      charset: alnum_safe
      first_char: alpha
      require: {{ upper: 1, lower: 1, digit: 1, special: 1 }}

applications:
  - name: acme
    accounts: [{account}]
    secret_template: "vault-dev:acme/{{env}}/{{application}}#DB_CREDENTIALS/{{account}}"
"""

BREAK_EXPIRED = """  locking:
    break_expired: true
"""


@dataclass
class Estate:
    """One account, one private mount, and the means to run sopuli against them."""

    tmp_path: Path
    vault: Any
    mount: str
    dsn: str
    env: dict[str, str]
    login: Callable[[str], bool]
    _configs: itertools.count[int] = field(default_factory=itertools.count)

    def config(self, addr: str, *, break_expired: bool = False) -> Path:
        """A config whose vault is at ``addr``: Vault itself, or a gate in front of it."""
        path = self.tmp_path / f"sopuli-{next(self._configs)}.yaml"
        path.write_text(
            CONFIG.format(
                locking=BREAK_EXPIRED if break_expired else "",
                addr=addr,
                mount=self.mount,
                dsn=self.dsn,
                user=os.environ.get("SOPULI_TEST_ORACLE_USER", "system"),
                account=ACCOUNT,
            ),
            encoding="utf-8",
        )
        if sys.platform != "win32":
            path.chmod(0o600)
        return path

    def sopuli(self, config: Path, *args: str) -> subprocess.CompletedProcess[str]:
        """Run sopuli to the end. ``--output json``, so stdout is one document."""
        return subprocess.run(
            sopuli_command(config, "json", list(args)),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env={**os.environ, **self.env},
            timeout=TIMEOUT,
            check=False,
        )

    def read(self, path: str) -> tuple[dict[str, Any], int]:
        """The data at ``path`` on the private mount, and its version."""
        reply = self.vault.get(f"/v1/{self.mount}/data/{path}")
        assert reply.status_code == 200, reply.text
        body = reply.json()["data"]
        return body["data"], body["metadata"]["version"]


@pytest.fixture
def estate(
    live_oracle: Environment, vault_stack: Any, private_mount: str, tmp_path: Path
) -> Iterator[Estate]:
    """A real account with a known password, and a vault mount of its own."""
    oracledb = pytest.importorskip("oracledb")
    user = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
    password = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")
    connection = oracledb.connect(user=user, password=password, dsn=live_oracle.dsn)

    def sql(statement: str) -> None:
        with connection.cursor() as cursor:
            cursor.execute(statement)

    def login(candidate: str) -> bool:
        try:
            oracledb.connect(user=ACCOUNT, password=candidate, dsn=live_oracle.dsn).close()
        except oracledb.DatabaseError:
            return False
        return True

    with contextlib.suppress(Exception):  # absent is the ordinary case
        sql(f"drop user {ACCOUNT} cascade")
    sql(f'create user {ACCOUNT} identified by "{OLD}"')
    sql(f"grant create session to {ACCOUNT}")
    try:
        yield Estate(
            tmp_path=tmp_path,
            vault=vault_stack.client,
            mount=private_mount,
            dsn=live_oracle.dsn,
            env={"VAULT_TOKEN": vault_stack.token, ADMIN_PASSWORD_ENV: password},
            login=login,
        )
    finally:
        try:
            sql(f"drop user {ACCOUNT} cascade")
        finally:
            connection.close()


@dataclass
class Killed:
    """What a run killed before its promotion left behind."""

    current: str
    new: str
    pid: int


@pytest.fixture
def killed(estate: Estate, vault_stack: Any) -> Killed:
    """Rotate once, then kill the `creds apply` that is promoting a second password.

    The first rotation runs to the end, so the vault has a ``current`` that the
    database accepts. That is the estate a scheduled rotation meets. The second
    run is killed after it printed ``password.applied`` and while the gate holds
    its promotion write, so the database has the new password and the vault was
    never told.
    """
    direct = estate.config(vault_stack.addr)
    for args in (("creds", "generate"), ("creds", "apply", "--confirm"), ("creds", "generate")):
        result = estate.sopuli(direct, *args)
        assert result.returncode == ExitCode.SUCCESS, result.stderr
    staged, _ = estate.read(SECRET)
    current, new = staged["DB_CREDENTIALS"][ACCOUNT], staged["pending"][ACCOUNT]

    gate = VaultGate(vault_stack.addr, hold_path=f"/v1/{estate.mount}/data/{SECRET}")
    run = CliRun(estate.config(gate.addr), ["creds", "apply", "--confirm"], estate.env)
    try:
        run.wait_for("password.applied")
        assert gate.held.wait(TIMEOUT), "the run never reached its promotion write"
    finally:
        run.kill()
        gate.close()

    assert "vault.promote" not in [event["event"] for event in run.events]
    # Still held, so the run never reached its release. The pid is the run's
    # own, which Popen's is not always (see fault_harness).
    record, _ = estate.read(LOCK)
    assert record["state"] == "held", "the run outlived the kill"
    return Killed(current=current, new=new, pid=record["holder"]["pid"])


def test_a_run_killed_before_promotion_leaves_the_password_pending(
    estate: Estate, killed: Killed
) -> None:
    """The database has the new password, and the vault still calls it pending.

    The vault is the master copy, and an application reads ``current``. A
    ``current`` that named the new password here would be the promotion that
    invariant 7 forbids: not every target confirmed it.
    """
    document, _ = estate.read(SECRET)

    assert document["pending"][ACCOUNT] == killed.new
    assert document["DB_CREDENTIALS"][ACCOUNT] == killed.current
    assert estate.login(killed.new), "the database does not have the new password"
    assert not estate.login(killed.current)


def test_status_reports_the_killed_runs_password_as_pending(
    estate: Estate, vault_stack: Any, killed: Killed
) -> None:
    """`status` reads ``PENDING_APPLY`` from the vault alone (UC-1 §9).

    It takes no lock, so the dead run's lock does not stop it.
    """
    result = estate.sopuli(estate.config(vault_stack.addr), "creds", "status")

    document = json.loads(result.stdout)
    states = {row["account"]: row["state"] for row in document["results"]}
    assert states == {ACCOUNT: "PENDING_APPLY"}, result.stdout


def test_a_second_apply_completes_the_promotion(
    estate: Estate, vault_stack: Any, killed: Killed
) -> None:
    """The recovery UC-1 §8 names: break the dead run's lock, then apply again.

    The lock is still live, because the killed run never released it. An
    operator who knows the run is dead breaks it with ``--force``, which is the
    attended way out. Then ``apply`` finds the password already on the
    database and promotes it.
    """
    config = estate.config(vault_stack.addr)
    broken = estate.sopuli(config, "lock", "break", f"vault-dev:{SECRET}", "--force", "--confirm")
    assert broken.returncode == ExitCode.SUCCESS, broken.stderr

    applied = estate.sopuli(config, "creds", "apply", "--confirm")

    assert applied.returncode == ExitCode.SUCCESS, applied.stderr
    document, _ = estate.read(SECRET)
    assert document["DB_CREDENTIALS"][ACCOUNT] == killed.new
    assert ACCOUNT not in document.get("pending", {})
    assert estate.login(killed.new)


def _expire(estate: Estate) -> int:
    """Move the dead run's lock past its expiry, as fifteen minutes would.

    The lease is a fixed fifteen minutes (``DEFAULT_TTL``), too long to wait in
    a test. The record is rewritten with ``expires_at`` beyond the clock-skew
    margin, and everything else as the dead run left it. Returns the version
    the rewrite produced.
    """
    record, version = estate.read(LOCK)
    assert record["state"] == "held"
    past = datetime.now(UTC) - timedelta(minutes=5)
    record["expires_at"] = past.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    reply = estate.vault.post(
        f"/v1/{estate.mount}/data/{LOCK}", json={"options": {"cas": version}, "data": record}
    )
    assert reply.status_code == 200, reply.text
    return int(reply.json()["data"]["version"])


def test_an_expired_lock_of_a_killed_run_is_refused_by_default(
    estate: Estate, vault_stack: Any, killed: Killed
) -> None:
    """Breaking a lock is not self-service, even when the holder looks dead.

    The next run exits 7 and says who held the lock and that it has expired, so
    the person reading it knows what `lock break` would do.
    """
    _expire(estate)

    result = estate.sopuli(estate.config(vault_stack.addr), "creds", "apply", "--confirm")

    assert result.returncode == ExitCode.LOCK_HELD, result.stderr
    assert f"pid {killed.pid}" in result.stderr
    assert "expired" in result.stderr
    document, _ = estate.read(SECRET)
    assert document["DB_CREDENTIALS"][ACCOUNT] == killed.current, "promoted under a held lock"


def test_break_expired_takes_over_the_lock_of_a_killed_run(
    estate: Estate, vault_stack: Any, killed: Killed
) -> None:
    """Under ``locking.break_expired`` the next run takes the lock and finishes.

    The takeover is a compare-and-set write, so the version goes up. That
    version is the fence: had the killed run been only paused, its next check
    would find it and stop.
    """
    expired_at = _expire(estate)

    config = estate.config(vault_stack.addr, break_expired=True)
    result = estate.sopuli(config, "creds", "apply", "--confirm")

    assert result.returncode == ExitCode.SUCCESS, result.stderr
    record, version = estate.read(LOCK)
    assert version > expired_at
    assert record["state"] == "released"
    assert record["holder"]["pid"] != killed.pid
    document, _ = estate.read(SECRET)
    assert document["DB_CREDENTIALS"][ACCOUNT] == killed.new

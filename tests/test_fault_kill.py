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

import json
from dataclasses import dataclass
from typing import Any

import pytest

from fault_harness import ACCOUNT, LOCK, SECRET, TIMEOUT, CliRun, Estate, Fault, VaultGate
from sopuli.exit_codes import ExitCode


@dataclass
class Killed:
    """What a run killed before its promotion left behind."""

    current: str
    new: str
    pid: int


@pytest.fixture
def killed(fault_estate: Estate, vault_stack: Any) -> Killed:
    """Rotate once, then kill the `creds apply` that is promoting a second password.

    The first rotation runs to the end, so the vault has a ``current`` that the
    database accepts. That is the estate a scheduled rotation meets. The second
    run is killed after it printed ``password.applied`` and while the gate holds
    its promotion write, so the database has the new password and the vault was
    never told.
    """
    direct = fault_estate.config(vault_stack.addr)
    for args in (("creds", "generate"), ("creds", "apply", "--confirm"), ("creds", "generate")):
        result = fault_estate.sopuli(direct, *args)
        assert result.returncode == ExitCode.SUCCESS, result.stderr
    staged, _ = fault_estate.read(SECRET)
    current, new = staged["DB_CREDENTIALS"][ACCOUNT], staged["pending"][ACCOUNT]

    gate = VaultGate(vault_stack.addr, f"/v1/{fault_estate.mount}/data/{SECRET}", Fault.HOLD_WRITE)
    run = CliRun(fault_estate.config(gate.addr), ["creds", "apply", "--confirm"], fault_estate.env)
    try:
        run.wait_for("password.applied")
        assert gate.tripped.wait(TIMEOUT), "the run never reached its promotion write"
    finally:
        run.kill()
        gate.close()

    assert "vault.promote" not in [event["event"] for event in run.events]
    # Still held, so the run never reached its release. The pid is the run's
    # own, which Popen's is not always (see fault_harness).
    record, _ = fault_estate.read(LOCK)
    assert record["state"] == "held", "the run outlived the kill"
    return Killed(current=current, new=new, pid=record["holder"]["pid"])


def test_a_run_killed_before_promotion_leaves_the_password_pending(
    fault_estate: Estate, killed: Killed
) -> None:
    """The database has the new password, and the vault still calls it pending.

    The vault is the master copy, and an application reads ``current``. A
    ``current`` that named the new password here would be the promotion that
    invariant 7 forbids: not every target confirmed it.
    """
    document, _ = fault_estate.read(SECRET)

    assert document["pending"][ACCOUNT] == killed.new
    assert document["DB_CREDENTIALS"][ACCOUNT] == killed.current
    assert fault_estate.login(killed.new), "the database does not have the new password"
    assert not fault_estate.login(killed.current)


def test_status_reports_the_killed_runs_password_as_pending(
    fault_estate: Estate, vault_stack: Any, killed: Killed
) -> None:
    """`status` reads ``PENDING_APPLY`` from the vault alone (UC-1 §9).

    It takes no lock, so the dead run's lock does not stop it.
    """
    result = fault_estate.sopuli(fault_estate.config(vault_stack.addr), "creds", "status")

    document = json.loads(result.stdout)
    states = {row["account"]: row["state"] for row in document["results"]}
    assert states == {ACCOUNT: "PENDING_APPLY"}, result.stdout


def test_a_second_apply_completes_the_promotion(
    fault_estate: Estate, vault_stack: Any, killed: Killed
) -> None:
    """The recovery UC-1 §8 names: break the dead run's lock, then apply again.

    The lock is still live, because the killed run never released it. An
    operator who knows the run is dead breaks it with ``--force``, which is the
    attended way out. Then ``apply`` finds the password already on the
    database and promotes it.
    """
    config = fault_estate.config(vault_stack.addr)
    fault_estate.break_lock(config)

    applied = fault_estate.sopuli(config, "creds", "apply", "--confirm")

    assert applied.returncode == ExitCode.SUCCESS, applied.stderr
    document, _ = fault_estate.read(SECRET)
    assert document["DB_CREDENTIALS"][ACCOUNT] == killed.new
    assert ACCOUNT not in document.get("pending", {})
    assert fault_estate.login(killed.new)


def test_an_expired_lock_of_a_killed_run_is_refused_by_default(
    fault_estate: Estate, vault_stack: Any, killed: Killed
) -> None:
    """Breaking a lock is not self-service, even when the holder looks dead.

    The next run exits 7 and says who held the lock and that it has expired, so
    the person reading it knows what `lock break` would do.
    """
    fault_estate.expire_lock()

    result = fault_estate.sopuli(
        fault_estate.config(vault_stack.addr), "creds", "apply", "--confirm"
    )

    assert result.returncode == ExitCode.LOCK_HELD, result.stderr
    assert f"pid {killed.pid}" in result.stderr
    assert "expired" in result.stderr
    document, _ = fault_estate.read(SECRET)
    assert document["DB_CREDENTIALS"][ACCOUNT] == killed.current, "promoted under a held lock"


def test_break_expired_takes_over_the_lock_of_a_killed_run(
    fault_estate: Estate, vault_stack: Any, killed: Killed
) -> None:
    """Under ``locking.break_expired`` the next run takes the lock and finishes.

    The takeover is a compare-and-set write, so the version goes up. That
    version is the fence: had the killed run been only paused, its next check
    would find it and stop.
    """
    expired_at = fault_estate.expire_lock()

    config = fault_estate.config(vault_stack.addr, break_expired=True)
    result = fault_estate.sopuli(config, "creds", "apply", "--confirm")

    assert result.returncode == ExitCode.SUCCESS, result.stderr
    record, version = fault_estate.read(LOCK)
    assert version > expired_at
    assert record["state"] == "released"
    assert record["holder"]["pid"] != killed.pid
    document, _ = fault_estate.read(SECRET)
    assert document["DB_CREDENTIALS"][ACCOUNT] == killed.new

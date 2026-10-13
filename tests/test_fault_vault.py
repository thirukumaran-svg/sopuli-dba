"""Fault injection: the vault fails part way through a rotation (`04-testing.md` §5).

Two rows of §5's table, asserted against UC-1 §8's *Failure at each step*:

* the vault becomes unreachable mid-run. At step 4, the staging write, nothing
  is applied. At step 7, the promotion, the password is applied and not
  promoted, and ``creds apply`` completes it. Where Vault commits the
  promotion and its reply is lost, the run does not report success. None is
  promoted silently;
* the vault serves a stale read after the promotion. Step 8's read-back
  catches it, and the run exits 4 with ``SOPULI-W012``.

Each fault comes from :class:`fault_harness.VaultGate`, at one request to the
secret's path. ``rotate`` writes that path twice: write 1 stages ``pending``,
and write 2 promotes it.

These need only the tier-1 services, Oracle Free and Vault, and skip without
them.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import pytest

from fault_harness import ACCOUNT, SECRET, Estate, Fault, HarnessError, VaultGate
from sopuli.exit_codes import ExitCode

#: ``rotate``'s writes to the secret's path, counted from 1.
STAGING, PROMOTION = 1, 2


@dataclass
class Faulted:
    """A rotation that ran into a vault fault, and what was true before it."""

    result: subprocess.CompletedProcess[str]
    document: dict[str, Any]
    current: str
    version: int

    @property
    def diagnostics(self) -> list[str]:
        return [one.get("code") for one in self.document.get("diagnostics", [])]

    @property
    def rows(self) -> list[dict[str, Any]]:
        """The applied rows. ``rotate`` lists its staging rows first."""
        return [row for row in self.document.get("results", []) if row["state"] != "PENDING_APPLY"]

    @property
    def states(self) -> dict[str, str]:
        return {row["account"]: row["state"] for row in self.rows}


#: Rotate through a gate with this fault at this write.
Rotate = Callable[[Fault, int], Faulted]


@pytest.fixture
def rotate(fault_estate: Estate, vault_stack: Any) -> Iterator[Rotate]:
    """Rotate once to the end, then return a function that rotates through a gate.

    The first rotation gives the vault a ``current`` the database accepts, which
    is the estate a scheduled rotation meets.
    """
    first = fault_estate.sopuli(
        fault_estate.config(vault_stack.addr), "creds", "rotate", "--confirm"
    )
    assert first.returncode == ExitCode.SUCCESS, first.stderr
    gates: list[VaultGate] = []

    def through(fault: Fault, writes: int) -> Faulted:
        before, version = fault_estate.read(SECRET)
        gate = VaultGate(
            vault_stack.addr, f"/v1/{fault_estate.mount}/data/{SECRET}", fault, writes=writes
        )
        gates.append(gate)
        result = fault_estate.sopuli(fault_estate.config(gate.addr), "creds", "rotate", "--confirm")
        if not gate.tripped.is_set():
            raise HarnessError(f"the fault never fired; the gate saw {gate.seen}")
        return Faulted(
            result=result,
            document=json.loads(result.stdout),
            current=before["DB_CREDENTIALS"][ACCOUNT],
            version=version,
        )

    yield through
    for gate in gates:
        gate.close()


def test_the_vault_lost_at_staging_changes_nothing(fault_estate: Estate, rotate: Rotate) -> None:
    """Step 4: nothing changed in the database, and the vault has no new version.

    The dropped write never reached Vault, so ``pending`` was never staged. Exit
    1, not 4, because no target was attempted (``rotate.exit_code_for``), and
    the account's row says why.
    """
    faulted = rotate(Fault.DOWN_AT_WRITE, STAGING)

    assert faulted.result.returncode == ExitCode.FAILURE, faulted.result.stderr
    assert faulted.states == {ACCOUNT: "ERROR"}
    document, version = fault_estate.read(SECRET)
    assert version == faulted.version
    assert ACCOUNT not in document.get("pending", {})
    assert fault_estate.login(faulted.current), "the database was changed"


def test_the_vault_lost_at_promotion_leaves_the_password_applied_and_unpromoted(
    fault_estate: Estate, rotate: Rotate
) -> None:
    """Step 7: the database has the new password, and ``current`` is still old.

    ``pending`` still holds the right value, so ``creds apply`` can finish the
    job (the next test).
    """
    faulted = rotate(Fault.DOWN_AT_WRITE, PROMOTION)

    assert faulted.result.returncode == ExitCode.PARTIAL, faulted.result.stderr
    document, _ = fault_estate.read(SECRET)
    assert document["DB_CREDENTIALS"][ACCOUNT] == faulted.current
    new = document["pending"][ACCOUNT]
    assert fault_estate.login(new), "the database does not have the staged password"
    assert not fault_estate.login(faulted.current)


def test_the_vault_lost_at_promotion_is_reported_as_partial(rotate: Rotate) -> None:
    """Step 7 is not silent: exit 4, and the row says the database changed.

    ``apply_states.exit_code_for`` makes a run that confirmed every target and
    could not promote exit 4. A document that reports ``changed: 0`` would hide
    UC-1 §8's most severe case from whoever reads it.
    """
    faulted = rotate(Fault.DOWN_AT_WRITE, PROMOTION)

    assert faulted.result.returncode == ExitCode.PARTIAL, faulted.result.stderr
    assert faulted.document["summary"]["changed"] == 1
    assert [row["changed"] for row in faulted.rows] == [True]


def test_apply_completes_a_promotion_the_vault_lost(
    fault_estate: Estate, vault_stack: Any, rotate: Rotate
) -> None:
    """UC-1 §8's recovery for step 7: ``creds apply`` verifies and promotes.

    The run could not release its lock either, because the vault was gone. So
    the lock is broken first, as for a run that died.
    """
    rotate(Fault.DOWN_AT_WRITE, PROMOTION)
    staged, _ = fault_estate.read(SECRET)
    config = fault_estate.config(vault_stack.addr)
    fault_estate.break_lock(config)

    applied = fault_estate.sopuli(config, "creds", "apply", "--confirm")

    assert applied.returncode == ExitCode.SUCCESS, applied.stderr
    document, _ = fault_estate.read(SECRET)
    assert document["DB_CREDENTIALS"][ACCOUNT] == staged["pending"][ACCOUNT]
    assert ACCOUNT not in document.get("pending", {})


def test_a_promotion_vault_kept_but_never_answered_is_not_success(
    fault_estate: Estate, rotate: Rotate
) -> None:
    """Vault commits the promotion, and the reply is lost on the way back.

    The vault is right, and the run cannot know it. Reporting success would
    claim a promotion the run never saw confirmed, so it must not.
    """
    faulted = rotate(Fault.DOWN_AFTER_WRITE, PROMOTION)

    assert faulted.result.returncode == ExitCode.PARTIAL, faulted.result.stderr
    document, _ = fault_estate.read(SECRET)
    new = document["DB_CREDENTIALS"][ACCOUNT]
    assert new != faulted.current, "Vault did not keep the promotion"
    assert fault_estate.login(new)


def test_a_stale_read_after_promotion_is_exit_four_with_its_own_code(
    fault_estate: Estate, rotate: Rotate
) -> None:
    """Step 8: the read-back disagrees with what was promoted.

    Vault holds the promotion, and the database has the new password, so
    nothing needs undoing. The run says so with ``SOPULI-W012`` rather than
    reporting success.
    """
    faulted = rotate(Fault.STALE_AFTER_WRITES, PROMOTION)

    assert faulted.result.returncode == ExitCode.PARTIAL, faulted.result.stderr
    assert "SOPULI-W012" in faulted.diagnostics
    document, _ = fault_estate.read(SECRET)
    new = document["DB_CREDENTIALS"][ACCOUNT]
    assert new != faulted.current
    assert fault_estate.login(new)

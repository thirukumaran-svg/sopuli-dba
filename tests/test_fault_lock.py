"""Fault injection: two runs contend for one lock (`04-testing.md` §5).

Three rows of §5's table, through ``sopuli creds rotate`` against a real
database:

* two rotations of one account at once. One loses the lock and exits 7, having
  changed nothing, and the other finishes. The vault and the database agree
  afterwards;
* a lock taken over mid-run. The first run's lock expires, a second run takes
  it over, and the first run's next fence check finds it. The first run stops
  before its ``ALTER USER``, exits 4 with ``SOPULI-W011``, and promotes
  nothing;
* a ``pending`` already staged (#769). A rotation that reads one refuses, and
  one whose lock is taken over by a run that stages one loses its staging
  write's compare-and-set. Neither stages over it.

``tests/store/test_lock_concurrency.py`` makes the same claims about the lock
manager alone. These make them about the command: its exit codes, its
diagnostic, and what the database and the vault hold afterwards.

The first run is held inside its lock by :class:`fault_harness.VaultGate`,
which pauses its staging write. Step 4 checks the fence before that write, so
the next check is the one before step 5's ``ALTER USER``.

These need only the tier-1 services, Oracle Free and Vault, and skip without
them.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

import pytest

from fault_harness import (
    ACCOUNT,
    LOCK,
    OLD,
    SECRET,
    STAGING,
    TIMEOUT,
    Estate,
    Fault,
    HarnessError,
    VaultGate,
    start_paused,
)
from sopuli.diagnostics import LOCK_LOST
from sopuli.exit_codes import ExitCode


@dataclass
class Paused:
    """A rotation that holds its lock, paused at its staging write."""

    gate: VaultGate
    run: Future[subprocess.CompletedProcess[str]]
    #: The run's own pid, from its lock record. See ``fault_harness`` for why
    #: ``Popen.pid`` is not always it.
    pid: int

    def finish(self) -> subprocess.CompletedProcess[str]:
        """Let the staging write through, and wait for the run to end."""
        self.gate.release()
        return self.run.result(timeout=TIMEOUT)


#: Start a rotation through a gate, and return once it holds the lock.
Pause = Callable[[], Paused]


@pytest.fixture
def pause(fault_estate: Estate, vault_stack: Any) -> Iterator[Pause]:
    """Start ``creds rotate`` through a gate, when the test is ready for it.

    A factory and not a plain fixture, so that a test that must rotate first
    says so in its own body. Fixture order would otherwise decide it.
    """
    gates: list[VaultGate] = []
    # A worker per paused run, so a second `pause()` does not queue behind the first.
    with ThreadPoolExecutor() as pool:

        def start() -> Paused:
            gate = VaultGate(
                vault_stack.addr,
                f"/v1/{fault_estate.mount}/data/{SECRET}",
                Fault.PAUSE_WRITE,
                writes=STAGING,
            )
            gates.append(gate)
            run = start_paused(pool, fault_estate, gate, "creds", "rotate", "--confirm")
            record, _ = fault_estate.read(LOCK)
            if record["state"] != "held":
                raise HarnessError(f"the paused run does not hold its lock: {record}")
            return Paused(gate=gate, run=run, pid=record["holder"]["pid"])

        # Closed inside the pool, so a run still paused at a gate is let go
        # before the pool waits for it.
        try:
            yield start
        finally:
            for gate in gates:
                gate.close()


def _names(text: str, pid: int, command: str) -> bool:
    """Whether a lock message names this holder: its pid and its command.

    The space after the pid stops pid 605 from matching pid 6052.
    """
    return f"pid {pid} running {command}" in text


def test_two_rotations_at_once_one_exits_7_and_the_other_finishes(
    fault_estate: Estate, vault_stack: Any, pause: Pause
) -> None:
    """The second run is refused at its acquire, before it writes anything.

    The first run then rotates as if the second had never started: the vault
    promotes the password the database has, and stages nothing more.
    """
    paused = pause()

    second = fault_estate.sopuli(
        fault_estate.config(vault_stack.addr), "creds", "rotate", "--confirm"
    )

    assert second.returncode == ExitCode.LOCK_HELD, second.stderr
    assert _names(second.stderr, paused.pid, "creds rotate"), second.stderr
    secret = fault_estate.vault.get(f"/v1/{fault_estate.mount}/data/{SECRET}")
    assert secret.status_code == 404, "the refused run wrote the secret document"
    assert fault_estate.login(OLD), "the refused run changed the password"

    first = paused.finish()

    assert first.returncode == ExitCode.SUCCESS, first.stderr
    document, _ = fault_estate.read(SECRET)
    new = document["DB_CREDENTIALS"][ACCOUNT]
    assert new != OLD
    assert ACCOUNT not in document.get("pending", {})
    assert fault_estate.login(new), "the vault promoted a password the database does not have"
    record, _ = fault_estate.read(LOCK)
    assert record["state"] == "released"
    assert record["holder"]["pid"] == paused.pid


def test_a_run_whose_lock_is_taken_over_stops_before_its_alter_user(
    fault_estate: Estate, vault_stack: Any, pause: Pause
) -> None:
    """The fence: a stalled run's plan is no longer true, so it applies none of it.

    A first rotation runs to the end, so the vault has a ``current`` the
    database accepts. Then a second rotation stalls inside its lock until the
    lock expires. Another run under ``locking.break_expired`` takes the lock
    over and finishes. It writes no secret document: the estate is converged,
    so ``apply`` has nothing to do. The stalled run then stages its
    ``pending``, and its fence check before ``ALTER USER`` finds the takeover.
    It stops there.

    The harness's own expiry rewrite bumps the version too, so a bumped version
    alone does not show the takeover. The fenced run's message must name the
    version and the holder the takeover left.

    A staged document is a change, so the run exits 4 and not 7. ``SOPULI-W011``
    says why, which the exit code cannot: a run whose targets failed also exits
    4, and that one is repaired by running ``apply`` again.
    """
    direct = fault_estate.config(vault_stack.addr)
    rotated = fault_estate.sopuli(direct, "creds", "rotate", "--confirm")
    assert rotated.returncode == ExitCode.SUCCESS, rotated.stderr
    before, _ = fault_estate.read(SECRET)
    current = before["DB_CREDENTIALS"][ACCOUNT]
    paused = pause()

    expired = fault_estate.expire_lock()
    takeover = fault_estate.sopuli(
        fault_estate.config(vault_stack.addr, break_expired=True), "creds", "apply", "--confirm"
    )
    assert takeover.returncode == ExitCode.SUCCESS, takeover.stderr
    taken, version = fault_estate.read(LOCK)
    assert version > expired
    assert taken["state"] == "released"
    assert taken["command"] == "creds apply"
    taker = taken["holder"]["pid"]
    assert taker != paused.pid, "the second run did not take the lock over"

    first = paused.finish()

    assert first.returncode == ExitCode.PARTIAL, first.stderr
    document = json.loads(first.stdout)
    lost = [one for one in document["diagnostics"] if one.get("code") == LOCK_LOST]
    assert len(lost) == 1, first.stdout
    assert f"found {version} held by" in lost[0]["message"]
    assert _names(lost[0]["message"], taker, "creds apply"), (
        "the message does not name the run that took over"
    )
    assert [held["released"] for held in document["lock"]["held"]] == [False]
    staged, _ = fault_estate.read(SECRET)
    assert staged["DB_CREDENTIALS"][ACCOUNT] == current, "promoted after a takeover"
    assert fault_estate.login(current)
    assert not fault_estate.login(staged["pending"][ACCOUNT]), (
        "the run reached ALTER USER after its lock was taken"
    )
    # The fenced-out run wrote nothing to a lock it no longer held.
    assert fault_estate.read(LOCK) == (taken, version)

    # The recovery UC-1 §8 gives for step 4: ``pending`` is a password nobody
    # has yet, and the next run to hold the lock applies and promotes it.
    recovered = fault_estate.sopuli(direct, "creds", "apply", "--confirm")
    assert recovered.returncode == ExitCode.SUCCESS, recovered.stderr
    promoted, _ = fault_estate.read(SECRET)
    assert promoted["DB_CREDENTIALS"][ACCOUNT] == staged["pending"][ACCOUNT]
    assert ACCOUNT not in promoted.get("pending", {})
    assert fault_estate.login(staged["pending"][ACCOUNT])


def test_a_rotation_over_a_staged_pending_refuses_and_apply_finishes_it(
    fault_estate: Estate, vault_stack: Any
) -> None:
    """#769's case at its first step: a `pending` is staged when the rotation
    reads the document, so the rotation refuses and stages nothing.

    The lost password in #769 needed a stalled `rotate` to stage over a `pending`
    that a takeover `apply` had just set on the database. The refusal stops
    that `rotate` at its plan, before its write, so the write is never sent.
    """
    direct = fault_estate.config(vault_stack.addr)
    rotated = fault_estate.sopuli(direct, "creds", "rotate", "--confirm")
    assert rotated.returncode == ExitCode.SUCCESS, rotated.stderr
    current = fault_estate.read(SECRET)[0]["DB_CREDENTIALS"][ACCOUNT]
    generated = fault_estate.sopuli(direct, "creds", "generate", "--offline")
    assert generated.returncode == ExitCode.SUCCESS, generated.stderr
    staged, version = fault_estate.read(SECRET)
    pending = staged["pending"][ACCOUNT]

    refused = fault_estate.sopuli(direct, "creds", "rotate", "--confirm")

    assert refused.returncode == ExitCode.ABORTED, refused.stderr
    assert f"{ACCOUNT} already has a `pending` staged" in refused.stderr
    assert "sopuli creds apply" in refused.stderr
    assert fault_estate.read(SECRET) == (staged, version), "the refused run wrote the document"
    assert fault_estate.login(current)
    record, _ = fault_estate.read(LOCK)
    assert record["state"] == "released"

    finished = fault_estate.sopuli(direct, "creds", "apply", "--confirm")
    assert finished.returncode == ExitCode.SUCCESS, finished.stderr
    assert fault_estate.read(SECRET)[0]["DB_CREDENTIALS"][ACCOUNT] == pending
    assert fault_estate.login(pending)


def test_a_pending_staged_by_a_takeover_fails_the_stalled_rotation_s_write(
    fault_estate: Estate, vault_stack: Any, pause: Pause
) -> None:
    """#769's case where the stall comes after the plan. The rotation read no
    `pending`, so it did not refuse. Then its lock expired and a `generate`
    took it over and staged one.

    The stalled write carries the version the rotation read, so the store
    refuses it. The rotation stops as a staging failure and applies nothing,
    and the takeover's `pending` survives for `apply` to finish.
    """
    direct = fault_estate.config(vault_stack.addr)
    rotated = fault_estate.sopuli(direct, "creds", "rotate", "--confirm")
    assert rotated.returncode == ExitCode.SUCCESS, rotated.stderr
    current = fault_estate.read(SECRET)[0]["DB_CREDENTIALS"][ACCOUNT]
    paused = pause()

    fault_estate.expire_lock()
    takeover = fault_estate.sopuli(
        fault_estate.config(vault_stack.addr, break_expired=True),
        "creds",
        "generate",
        "--offline",
    )
    assert takeover.returncode == ExitCode.SUCCESS, takeover.stderr
    staged, version = fault_estate.read(SECRET)
    pending = staged["pending"][ACCOUNT]

    first = paused.finish()

    assert first.returncode == ExitCode.FAILURE, first.stderr
    rows = json.loads(first.stdout)["results"]
    assert [row["state"] for row in rows] == ["ERROR"]
    assert fault_estate.read(SECRET) == (staged, version), "the stalled write landed"
    assert fault_estate.login(current), "the stalled run reached ALTER USER"

    finished = fault_estate.sopuli(direct, "creds", "apply", "--confirm")
    assert finished.returncode == ExitCode.SUCCESS, finished.stderr
    assert fault_estate.read(SECRET)[0]["DB_CREDENTIALS"][ACCOUNT] == pending
    assert fault_estate.login(pending)

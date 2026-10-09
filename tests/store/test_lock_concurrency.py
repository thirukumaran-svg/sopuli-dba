"""Release gate: the lock holds under contention.

`04-testing.md` §5 and UC-1 §11 both list the concurrency case and the fencing
one. Both are covered in tier 0 already — two managers over one
dictionary with an injected clock (`tests/lock/test_manager.py`) — and that is
not the same claim. Tier 0 forces the race by driving the store in a chosen
order, so it proves the *manager* reacts correctly to a lost compare-and-set. It
never lets two runs actually start together, so it cannot prove that they
produce exactly one winner.

This does, with two real processes against a real Vault
(`tests/store/lock_race_driver.py`).

**Why it is a release gate.** A tool that lets two runs rotate one credential at
once is worse than a tool with no locking at all, because the second at least
does not claim otherwise. Everything else in the vault layer assumes these
two properties.

The split above cuts both ways. A claim
about an *interleaving* -- two runs both reading before either writes -- cannot
be made here, for the same reason tier 0 cannot make the claim about two runs
starting at once: the window is inside `acquire`, no handshake reaches into it,
and two processes released together land in it only sometimes. Asserting an
interleaving from this side is asserting a coin flip. What belongs here is what
holds on every run whatever the scheduler did.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from sopuli.lock import Holder, LockRecord

DRIVER = Path(__file__).with_name("lock_race_driver.py")

#: The **secret** path, in CLAUDE.md's fixture vocabulary. The record lands at
#: `locks/apps/acme/alpha`: locks live under a prefix of their own, which
#: the manager adds, so writing it here too would nest one inside the other.
SECRET_PATH = "apps/acme/alpha"

#: Where the record actually goes, which is what the test has to configure and
#: clean up.
LOCK_PATH = f"locks/{SECRET_PATH}"

#: How long to wait for a racer to say it is ready before giving up on it.
#: Generous: this is startup, not the thing being measured. Enforced in
#: :func:`_await_ready` -- it was documented here and enforced nowhere until
#: review pointed out that the gate could hang rather than fail.
READY_TIMEOUT = 60

#: How long a racer holds the lock once it has it.
#:
#: **Without this the race is unobservable**, and the handshake is not enough on
#: its own: a winner that releases immediately holds the lock for the two
#: loopback round trips its acquire and release take -- a couple of milliseconds
#: -- so a loser delayed by an ordinary scheduling hiccup finds the path
#: *released* and legitimately acquires it. Both runs then report success and
#: the gate fails for a reason that is not about locking.
#:
#: Holding is also what a real run does: the lock exists to be held across the
#: work, not across the acquire. One second is far longer than the loser needs
#: and short enough not to pad the suite.
CONTENTION_SECONDS = 1


def run_driver(stack: Any, **options: Any) -> dict[str, Any]:
    """Start one racer and wait for its answer."""
    return dict(json.loads(_finish(_start(stack, **options))))


def _start(stack: Any, **options: Any) -> subprocess.Popen[str]:
    """One racer, with the token in its environment and never in its argv.

    Invariant 1: a secret on a command line is visible in `ps` and in the Windows
    process list. This is a dev-mode root token against a loopback Vault, so the
    exposure is nil -- but the invariant is unconditional, and a harness is the
    worst place to demonstrate the pattern, because harnesses get copied.

    It also makes the driver exercise the real chain: `VAULT_TOKEN` is a step in
    `method: token`'s fall-through (§3a), so the racers authenticate the way a
    production run does rather than by being handed a `Secret`.
    """
    argv = [sys.executable, str(DRIVER), "--addr", stack.addr]
    for key, value in options.items():
        flag = f"--{key.replace('_', '-')}"
        argv += [flag] if value is True else [flag, str(value)]
    return subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "VAULT_TOKEN": stack.token},
    )


def _race(stack: Any, count: int = 2, **options: Any) -> list[dict[str, Any]]:
    """Start ``count`` racers, hold them at the line, and release them together.

    The handshake is what makes this a race rather than a coincidence. Each
    racer says `ready` once everything expensive is behind it -- imports, client,
    token -- so the only thing left when `go` arrives is the acquiring write.

    Aligning on a wall-clock instant instead, which this did first, is a guess
    about process startup time. It was wrong often enough under a loaded machine
    to make the gate flaky: a late racer found the other had already acquired
    *and released*, so both legitimately acquired. A guess cannot be tightened
    into a guarantee, so it is gone rather than longer.

    The racers also **hold** what they take (:data:`CONTENTION_SECONDS`), which
    the handshake does not make unnecessary: a winner that released immediately
    would hold the lock for about as long as two loopback round trips, and a
    loser delayed by an ordinary scheduling hiccup would find the path released
    and take it honestly. Holding is what a real run does anyway -- the lock
    exists to cover the work, not the acquire.
    """
    racers = [
        _start(
            stack,
            handshake=True,
            hold_seconds=CONTENTION_SECONDS,
            correlation_id=f"run-{index}",
            **options,
        )
        for index in range(count)
    ]
    try:
        for racer in racers:
            _await_ready(racer)
        for racer in racers:
            assert racer.stdin is not None
            racer.stdin.write("go\n")
            racer.stdin.flush()
        return [json.loads(_finish(racer)) for racer in racers]
    except BaseException as error:
        # Whatever went wrong, no racer is left running: one still holding the
        # lock would fail the *next* test rather than this one, and a hung
        # handshake would otherwise sit here until the suite timed out.
        raise AssertionError(_after_killing(racers, error)) from error


def _await_ready(racer: subprocess.Popen[str]) -> None:
    """Wait for one racer to reach the line, bounded.

    A plain `readline()` has two bad endings and no bound at all: a racer that
    hangs blocks here until something kills the suite, and one that dies during
    import returns EOF, which surfaces as a JSON error about an empty string
    rather than as "it never started".

    A thread, because a timed read on a pipe is not portable -- `select` does not
    take pipes on Windows, and P4 wants both platforms behaving the same. The
    reader is a daemon and the caller kills the process, so nothing is left
    behind either way.
    """
    line: list[str] = []

    def read() -> None:
        assert racer.stdout is not None
        line.append(racer.stdout.readline())

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    reader.join(READY_TIMEOUT)

    if reader.is_alive():
        raise AssertionError(f"a racer did not reach the line within {READY_TIMEOUT}s")
    if not line or not line[0].strip():
        raise AssertionError("a racer exited before saying it was ready")
    ready = json.loads(line[0])
    assert ready == {"ready": True}, ready


def _after_killing(racers: list[subprocess.Popen[str]], error: BaseException) -> str:
    """Stop every racer and gather what they had to say.

    Their stderr is most of the diagnosis: a racer that never said `ready`
    failed at import, at the token, or at reaching the store, and the traceback
    for that is in the child rather than here.
    """
    said = []
    for racer in racers:
        racer.kill()
        try:
            _, err = racer.communicate(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover -- it was killed
            err = ""
        if err.strip():
            said.append(err.strip())
    reported = "\n".join(said) or "(the racers said nothing on stderr)"
    return f"{error}\n--- racer stderr ---\n{reported}"


def _finish(process: subprocess.Popen[str]) -> str:
    out, err = process.communicate(timeout=60)
    assert process.returncode == 0, f"driver failed: {err}"
    return out.strip().splitlines()[-1]


@pytest.fixture
def lock_path(vault_stack: Any) -> Iterator[str]:
    """A lock path with no history, configured the way pre-flight demands.

    Two things, and the second is the more interesting.

    A full metadata delete, which wipes the version counter as well as the data.
    That is deliberately something the *tool* never does (UC-1 §8: release writes a
    `released` record, because a delete would leave a path no first acquisition
    could ever take again) and exactly what a test needs between runs.

    Then `cas_required: true` on the path, because **pre-flight checks it** -- a
    lock on a path that accepts unguarded writes is one another writer can
    replace, so the manager will not claim to hold it. On a path with no metadata
    at all, pre-flight sets it itself (UC-1 §8); setting it here keeps the race
    from depending on that step, so each test measures only the lock.
    """
    mount = vault_stack.kv2_mount
    vault_stack.client.delete(f"/v1/{mount}/metadata/{LOCK_PATH}")
    vault_stack.client.post(f"/v1/{mount}/metadata/{LOCK_PATH}", json={"cas_required": True})
    yield SECRET_PATH
    vault_stack.client.delete(f"/v1/{mount}/metadata/{LOCK_PATH}")


# ------------------------------------------------- gate 1: one lock, two runs ---


def test_exactly_one_of_two_concurrent_runs_takes_the_lock(
    vault_stack: Any, lock_path: str
) -> None:
    """The gate. Two processes, one instant, one winner.

    The loser is asserted on three counts, because "it failed" is not the
    property: it must exit **7** specifically, it must say who holds the lock or
    that it lost the race, and -- most importantly -- it must have touched
    nothing, which is what `acquire` releasing on the way out buys.
    """
    results = _race(vault_stack, mount=vault_stack.kv2_mount, path=lock_path)

    outcomes = sorted(result["outcome"] for result in results)
    assert outcomes == ["acquired", "denied"], f"both runs took the lock: {results}"

    [winner] = [result for result in results if result["outcome"] == "acquired"]
    [loser] = [result for result in results if result["outcome"] == "denied"]

    assert winner["fence"] == 1, "the winning write is the path's first version"
    assert loser["exit_code"] == 7
    assert loser["category"] == "lock"


def test_the_path_holds_one_record_after_a_race(vault_stack: Any, lock_path: str) -> None:
    """Not two writes, one of which happened to be last.

    The version is the evidence: a path at version 1 after the race was written
    once. Two runs that both wrote would leave version 2 with the loser's record
    on top -- which is precisely the outcome the fence exists to prevent, and it
    would be invisible from the winner's side.
    """
    results = _race(vault_stack, mount=vault_stack.kv2_mount, path=lock_path)
    [winner] = [result for result in results if result["outcome"] == "acquired"]

    read = vault_stack.client.get(f"/v1/{vault_stack.kv2_mount}/data/{LOCK_PATH}")
    body = read.json()["data"]

    # Released on the way out, so the record is the winner's `released` one --
    # written, never deleted. Version 2: the acquire, then the release.
    assert body["metadata"]["version"] == 2
    assert body["data"]["correlation_id"] == winner["correlation_id"]


# ----------------------------------------------------- gate 2: a stolen lock ---


def test_a_stolen_lock_stops_the_run_that_lost_it(vault_stack: Any, lock_path: str) -> None:
    """The fence, against a real store.

    The holder is mid-run and about to mutate something. Somebody else takes the
    path -- here by writing over it with the version the holder is standing on,
    which is exactly what a `lock break` or a second run under `break_expired`
    would do. The holder's next check must fail.

    This is the property that made a vault-side lock worth choosing over
    `DBMS_LOCK`: a stalled run's database session is still alive and still holds
    a `DBMS_LOCK`, so it would prevent nothing here.
    """
    holder = _start(
        vault_stack,
        mount=vault_stack.kv2_mount,
        path=lock_path,
        correlation_id="the-holder",
        hold_seconds=4,
    )
    # Wait for the acquiring write to land, then take the path from under it.
    stolen = _steal(vault_stack, LOCK_PATH)
    assert stolen, "the holder never wrote its lock record"

    result = json.loads(_finish(holder))

    assert result["outcome"] == "acquired"
    assert result["fence_check"] == "stolen"
    assert "the-holder" not in result["message"] or "taken over" in result["message"]


def _steal(stack: Any, path: str, *, attempts: int = 40) -> bool:
    """Overwrite the lock record the way a takeover would: with a real CAS."""
    mount = stack.kv2_mount
    for _ in range(attempts):
        read = stack.client.get(f"/v1/{mount}/data/{path}")
        if read.status_code == 200:
            version = read.json()["data"]["metadata"]["version"]
            written = stack.client.post(
                f"/v1/{mount}/data/{path}",
                json={
                    "data": {"correlation_id": "the-thief", "holder": {"os_user": "someone"}},
                    "options": {"cas": version},
                },
            )
            return bool(written.status_code == 200)
        time.sleep(0.1)
    return False


# ------------------------------------- what only a real store can be asked ---


def test_a_deleted_lock_path_can_never_be_acquired_again(vault_stack: Any, lock_path: str) -> None:
    """The fact behind "release writes a record, never deletes one" (UC-1 §8).

    Vault keeps a soft-deleted path's version counter, so `cas: 0` fails there
    forever. A lock released by deleting would leave a path no first acquisition
    could ever take -- a rotation that stops working, permanently, for a reason
    nobody would look for.

    Asserted against Vault rather than against `MemoryStore` because it is
    *Vault's* semantics that the design rests on. If a future release ever
    stopped behaving this way, the design would want to know.
    """
    mount = vault_stack.kv2_mount
    vault_stack.client.post(
        f"/v1/{mount}/data/{LOCK_PATH}", json={"data": {"x": 1}, "options": {"cas": 0}}
    )
    vault_stack.client.delete(f"/v1/{mount}/data/{LOCK_PATH}")

    result = run_driver(vault_stack, mount=mount, path=lock_path, correlation_id="after-delete")

    assert result["outcome"] == "denied"
    assert result["exit_code"] == 7


#: The wording `_write` uses when a compare-and-set is *lost*, as opposed to
#: when the read found a holder. The two denials are indistinguishable by exit
#: code -- both are 7 -- and the difference is the whole subject below, so it is
#: matched on the message rather than inferred.
LOST_A_RACE = "while this one was acquiring it"


def test_advisory_only_claims_no_fence_and_never_loses_a_race(vault_stack: Any) -> None:
    """What a mount with no compare-and-set can be *asked*, on a real Vault.

    `locking: advisory-only` is the operator conceding that a lock here
    guarantees nothing, and the concession has a shape that is observable
    every time rather than only when the timing cooperates:

    * nobody is handed a fence -- a version somebody could compare would be a
      guarantee this store cannot give;
    * every run reports `mode: none`, so a consumer is told which guarantee it
      got. A run reporting `cas` here would be claiming one it does not have,
      and *that* is the failure worth catching;
    * a denial, where one happens, is **never a lost compare-and-set**. There is
      none to lose: `_write` passes `cas=None` on a store that cannot fence, so
      the only way to be refused here is the read having seen a holder. That is
      the property that separates this mount from the `kv2` one above, and it is
      the half only a real store can be asked.

    **What is deliberately not asserted is the outcome pair.** Demanding
    `["acquired", "acquired"]` is not sound: `acquire` reads the path before it
    writes, on `advisory-only` exactly as on `required`, so a racer whose read
    lands after the other's write is *correctly* denied. Both pairs are legal
    here and which one appears is a fact about process scheduling, not about the
    store. The claim that two runs *can* hold one advisory lock at once is
    tested in `tests/lock/test_manager.py`, where the window between the
    read and the write can be forced open instead of waited for.
    """
    secret_path = "apps/acme/beta"
    record = f"locks/{secret_path}"
    vault_stack.client.delete(f"/v1/{vault_stack.kv1_mount}/{record}")
    results = _race(
        vault_stack,
        mount=vault_stack.kv1_mount,
        kv_version=1,
        locking="advisory-only",
        path=secret_path,
    )
    vault_stack.client.delete(f"/v1/{vault_stack.kv1_mount}/{record}")

    assert "acquired" in [result["outcome"] for result in results], (
        f"neither run took a lock nobody was holding: {results}"
    )
    assert {result["mode"] for result in results} == {"none"}

    for result in results:
        if result["outcome"] == "acquired":
            assert result["fence"] is None, (
                "a store that cannot fence must hand back no fence, rather than a "
                "number nothing can compare"
            )
        else:
            assert LOST_A_RACE not in result["message"], (
                f"there is no compare-and-set on this mount to lose: {result}"
            )


def test_a_denial_without_compare_and_set_is_the_read_and_not_a_lost_race(
    vault_stack: Any,
) -> None:
    """The denial branch above, reached on purpose instead of by luck.

    Whether the race produces a denial at all depends on the machine -- on an
    idle laptop both runs acquire every time, which is why the flake only ever
    appeared in CI. So the shape of a denial is asserted here, where it is
    forced: a record is planted, one run is started, and it is refused.

    The distinction being drawn is invisible from the exit code, since both
    denials are 7. `acquire` refuses in two places -- the read finding a holder,
    and the acquiring write losing a compare-and-set -- and on a mount with no
    `cas` the second cannot happen, because `_write` passes `cas=None` there.
    A denial here that claimed a lost race would mean the manager had asked this
    store for a guarantee it does not have.
    """
    secret_path = "apps/acme/gamma"
    record = f"locks/{secret_path}"
    held = LockRecord.acquired(
        correlation_id="01JSOMEBODYELSE",
        command="creds rotate",
        holder=Holder(host="another-runner", pid=4242, os_user="svc_sopuli"),
        now=datetime.now(UTC),
    )
    # kv1 writes the document at the path itself -- there is no `data/` prefix
    # and no `options`, which is the whole of what "no versioning" means here.
    vault_stack.client.post(f"/v1/{vault_stack.kv1_mount}/{record}", json=held.to_dict())
    try:
        result = run_driver(
            vault_stack,
            mount=vault_stack.kv1_mount,
            kv_version=1,
            locking="advisory-only",
            path=secret_path,
            correlation_id="run-late",
        )
    finally:
        vault_stack.client.delete(f"/v1/{vault_stack.kv1_mount}/{record}")

    assert result["outcome"] == "denied"
    assert result["exit_code"] == 7
    assert LOST_A_RACE not in result["message"], (
        f"there is no compare-and-set on this mount to lose: {result}"
    )
    # It says who, which is the half that makes exit 7 actionable -- and is also
    # the evidence that this denial came from the read.
    assert "another-runner" in result["message"]

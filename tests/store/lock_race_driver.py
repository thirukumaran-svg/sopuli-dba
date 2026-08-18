"""One run, taking one lock against a real Vault, as a separate process (#106).

Not collected as a test -- no ``test_`` prefix -- because it *is* the run under
test. ``tests/store/test_lock_concurrency.py`` starts two of these and reads
their JSON back.

**Two processes rather than two managers over one dictionary**, which is what
tier 0 already does (`tests/lock/test_manager.py`). The difference is the whole
point of this gate: tier 0 forces the race by driving the store in a chosen
order, so it proves the manager reacts correctly to a lost compare-and-set. It
cannot prove that two runs which genuinely start at the same instant produce
exactly one winner, because it never lets them. That is a property of Vault and
of the acquiring write, and it is only observable when nobody is holding the
stopwatch.

The processes align on a wall-clock instant passed in by the parent rather than
on a barrier file, because a barrier is a write and a read against the same disk
the test is already using -- the alignment would be as coarse as the thing being
measured.

**The token arrives in the environment and never in argv** (invariant 1, P5:
secrets are visible in ``ps`` and in the Windows process list). It is a dev-mode
root token against a loopback Vault, so the exposure is nil -- but the invariant
is unconditional, and a harness is the worst place to demonstrate the pattern,
because harnesses get copied. Reading it from ``VAULT_TOKEN`` also makes this
driver exercise the real chain rather than a shortcut: ``connect`` runs
``method: token`` through :func:`sopuli.material.resolve_token`, which is what a
production run does.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any

from sopuli.config.model import Vault, VaultAuth
from sopuli.invocation import _classify
from sopuli.lock.errors import LockError, LockStolenError
from sopuli.lock.keys import LockKey
from sopuli.lock.manager import LockableStore, LockManager
from sopuli.store.hashicorp import connect


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--addr", required=True)
    parser.add_argument("--mount", required=True)
    parser.add_argument("--kv-version", type=int, default=2)
    parser.add_argument("--path", required=True)
    parser.add_argument("--store-name", default="vault-dev")
    parser.add_argument("--locking", default="required")
    parser.add_argument("--correlation-id", required=True)
    #: Wall-clock instant, as epoch seconds, at which to attempt the write.
    parser.add_argument("--start-at", type=float, default=0.0)
    #: Hold the lock this long before checking the fence, so the parent has a
    #: window in which to steal it.
    parser.add_argument("--hold-seconds", type=float, default=0.0)
    args = parser.parse_args(argv)

    # `connect` rather than `open_store`: the token comes from `VAULT_TOKEN` in
    # this process's environment, through the same `method: token` chain a real
    # run uses, so nothing here holds a credential and nothing put one in argv.
    store = connect(
        Vault(
            name=args.store_name,
            type="hashicorp",
            addr=args.addr,
            mount=args.mount,
            kv_version=args.kv_version,
            auth=VaultAuth(method="token"),
        ),
        env=os.environ,
    )
    manager = LockManager(
        stores={args.store_name: LockableStore(store=store, locking=args.locking)},
        correlation_id=args.correlation_id,
        command="creds rotate",
    )
    key = LockKey(store=args.store_name, path=args.path)

    remaining = args.start_at - time.time()
    if remaining > 0:
        time.sleep(remaining)

    result: dict[str, Any] = {"correlation_id": args.correlation_id, "mode": manager.mode}
    try:
        manager.acquire([key])
    except LockError as error:
        # Includes the lost race. `acquire` releases whatever it had already
        # taken before raising, so a loser is a run that touched nothing.
        #
        # The exit code comes from the boundary's own mapping rather than from a
        # constant here. A lock error carries no code of its own -- what it means
        # depends on whether anything had been applied yet -- so a driver that
        # hard-coded 7 would assert its own opinion instead of the tool's, and
        # would keep passing if the mapping ever changed.
        exit_code, reported = _classify(error)
        result |= {
            "outcome": "denied",
            "exit_code": int(exit_code),
            "category": reported.category,
            "message": str(error),
        }
        print(json.dumps(result))
        return 0

    result |= {"outcome": "acquired", "fence": manager.held[0].fence}

    if args.hold_seconds:
        time.sleep(args.hold_seconds)
        try:
            manager.check()
            result["fence_check"] = "held"
        except LockStolenError as error:
            # The property this gate exists for: the run discovers at its next
            # boundary that the lock is no longer its own, and stops before
            # whatever it was about to change.
            result["fence_check"] = "stolen"
            result["message"] = str(error)

    manager.release()
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())

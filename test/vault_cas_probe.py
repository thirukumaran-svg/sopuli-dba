"""Probe: what does a real Vault KV v2 compare-and-set conflict actually look
like on the wire, and is it distinguishable from every other 400?

Written for issue #103 (which HashiCorp client) and #104 (the KV v2 adapter).
Both options on #103 need the answer: :mod:`sopuli.store.protocol`'s
``CasConflictError`` has to be raised for a lost compare-and-set and *only*
for that, never for an unrelated bad request -- see
``sopuli/store/memory.py``, the reference reading of these semantics. Talks to
Vault over stdlib ``urllib`` rather than ``hvac`` or ``requests`` on purpose:
neither is a project dependency yet (#103 is what would add one), and the
question this asks is about Vault's own HTTP contract, which holds regardless
of which client eventually wraps it.

Not a pytest test. A spike, run by hand against the tier0/tier1 dev-mode
Vault from ``test/compose.yaml`` (``docker compose --profile tier0 up -d``),
the same relationship ``sql/oracle/02_password_leak_probe.sql`` has to the
Oracle side. Idempotent: it wipes its own path's metadata first, so re-running
it does not depend on the previous run's state -- dev-mode Vault is ``inmem``
and outlives the script.

The regression this found -- that ``CAS_MESSAGE_FRAGMENT`` below is the one
string every shape of conflict shares -- is a real dependency on Vault's own
error text now, not just a fact this script measured once. That half is
promoted to ``tests/store/test_hashicorp_cas_conflict.py``, which runs (and
skips cleanly when Vault is unreachable) as part of the ordinary suite. This
script stays as the wider, exploratory investigation -- it also covers the
``read()`` 404-ambiguity question and the malformed-cas contrast, which are
worth keeping legible but are not string dependencies the way the conflict
message is.

    python test/vault_cas_probe.py
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "sopuli-test-root")
MOUNT = "kv"  # the v2 mount test/compose.yaml's vault-init creates
# CLAUDE.md's fixture vocabulary (application `acme`) rather than the tool's
# own name -- this is scratch space, not a real secret, but it is still an
# example in the codebase.
PATH = "apps/acme/probe/cas-conflict"

# The exact string #83/#96 need `CasConflictError` to key on. A hope, not yet
# a fact -- this script exists to find out whether it holds across every shape
# of conflict, or only the obvious one.
CAS_MESSAGE_FRAGMENT = "check-and-set parameter did not match"


@dataclass
class Response:
    status: int
    body: Any

    @property
    def errors(self) -> list[str]:
        if isinstance(self.body, dict) and isinstance(self.body.get("errors"), list):
            return self.body["errors"]
        return []


def call(method: str, path: str, *, json_body: dict[str, Any] | None = None) -> Response:
    url = f"{VAULT_ADDR}/v1/{path}"
    data = json.dumps(json_body).encode("utf-8") if json_body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("X-Vault-Token", VAULT_TOKEN)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read()
            body = json.loads(raw) if raw else None
            return Response(status=response.status, body=body)
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            body = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            body = raw.decode("utf-8", errors="replace")
        return Response(status=error.code, body=body)


def write(cas: int | None) -> Response:
    payload: dict[str, Any] = {"data": {"holder": "vault_cas_probe"}}
    if cas is not None:
        payload["options"] = {"cas": cas}
    return call("POST", f"{MOUNT}/data/{PATH}", json_body=payload)


def read() -> Response:
    return call("GET", f"{MOUNT}/data/{PATH}")


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def show(label: str, response: Response) -> None:
    print(f"  {label}: HTTP {response.status}")
    print(f"    body: {json.dumps(response.body)}")


def expect(condition: bool, description: str) -> None:
    mark = "OK" if condition else "FAIL"
    print(f"  [{mark}] {description}")
    if not condition:
        FAILURES.append(description)


FAILURES: list[str] = []


def main() -> int:
    section("setup")
    # Full metadata delete: wipes data *and* the version counter, so the probe
    # is rerunnable. This is the destructive teardown release writes a record
    # instead of using (#83) -- fine here because this path is the probe's own
    # scratch space, not a lock.
    wipe = call("DELETE", f"{MOUNT}/metadata/{PATH}")
    print(f"  wiped {PATH!r} (or it did not exist): HTTP {wipe.status}")

    section("1. cas=0 against a path with no history -- baseline")
    first = write(cas=0)
    show("write cas=0", first)
    expect(first.status == 200, "fresh path accepts cas=0")
    version1 = (first.body or {}).get("data", {}).get("version")
    expect(version1 == 1, f"version is 1 after the first write (got {version1!r})")

    section("2. cas=0 again -- the ordinary conflict: version has moved")
    stale_zero = write(cas=0)
    show("write cas=0 (stale)", stale_zero)
    expect(stale_zero.status == 400, "a stale cas=0 is refused with 400")
    message_stale_zero = " | ".join(stale_zero.errors)
    print(f"    message: {message_stale_zero!r}")
    expect(
        CAS_MESSAGE_FRAGMENT in message_stale_zero,
        f"message contains {CAS_MESSAGE_FRAGMENT!r}",
    )

    section("3. cas=<current version> -- the write that should succeed")
    correct = write(cas=version1)
    show("write cas=1", correct)
    expect(correct.status == 200, "the correct cas is accepted")
    version2 = (correct.body or {}).get("data", {}).get("version")
    expect(version2 == 2, f"version is 2 after the second write (got {version2!r})")

    section("4. cas=<stale nonzero> -- conflict with a real but old version")
    stale_nonzero = write(cas=version1)  # 1 again, but current is now 2
    show("write cas=1 (stale)", stale_nonzero)
    expect(stale_nonzero.status == 400, "a stale nonzero cas is refused with 400")
    message_stale_nonzero = " | ".join(stale_nonzero.errors)
    print(f"    message: {message_stale_nonzero!r}")
    expect(
        message_stale_nonzero == message_stale_zero,
        "message text is identical to the stale-zero case (one string to match on)",
    )

    section("5. soft-delete the latest version, then read it")
    deleted = call("DELETE", f"{MOUNT}/data/{PATH}")
    print(f"  soft-delete: HTTP {deleted.status}")
    after_delete = read()
    show("read after soft-delete", after_delete)
    expect(after_delete.status == 404, "reading a soft-deleted path is a 404")

    section("6. cas=0 against a soft-deleted path -- history exists, data does not")
    # This is the trap `sopuli/store/protocol.py`'s `read()` docstring names:
    # `None` from a read is not the same as "cas=0 will succeed here."
    zero_after_delete = write(cas=0)
    show("write cas=0 (after soft-delete)", zero_after_delete)
    expect(
        zero_after_delete.status == 400,
        "cas=0 is still refused: the version counter survived the delete",
    )
    message_after_delete = " | ".join(zero_after_delete.errors)
    print(f"    message: {message_after_delete!r}")
    expect(
        message_after_delete == message_stale_zero,
        "same message as an ordinary stale cas=0 -- read()'s None does not distinguish "
        "the two cases, and the write-time error does not either",
    )

    section("7. never-existed path -- read, for contrast with case 5")
    never = call("GET", f"{MOUNT}/data/apps/acme/probe/never-written")
    show("read a path that was never written", never)
    expect(never.status == 404, "also a 404")
    # Same status code, but NOT the same body: a soft-deleted path's 404 still
    # carries a `data` envelope with metadata (deletion_time, version); a
    # never-written path's 404 is bare -- just an empty `errors` list. So the
    # two states protocol.py's `read()` docstring says both collapse to `None`
    # are not actually indistinguishable on the wire -- `read()` *chooses* not
    # to look, because nothing that calls it needs the distinction. Worth
    # knowing for #104 regardless: the information is there if some future
    # caller ever does.
    never_has_data = (
        isinstance(never.body, dict) and "data" in never.body and never.body["data"] is not None
    )
    deleted_has_data = (
        isinstance(after_delete.body, dict)
        and "data" in after_delete.body
        and after_delete.body["data"] is not None
    )
    expect(
        not never_has_data and deleted_has_data,
        "status code alone (404/404) does not distinguish them, but the body does: "
        f"never-written has no `data` envelope ({never_has_data=}), "
        f"soft-deleted still has one, with metadata ({deleted_has_data=})",
    )

    section("8. a 400 that is NOT a cas conflict -- must not be mistaken for one")
    # `options.cas` is documented as an integer. A string in its place is a
    # malformed request, not a lost race, and the two must not share wording.
    malformed = call(
        "POST",
        f"{MOUNT}/data/{PATH}",
        json_body={"data": {"holder": "x"}, "options": {"cas": "not-a-number"}},
    )
    show("write with a non-integer cas", malformed)
    expect(malformed.status == 400, "still a 400 -- same status code as a real conflict")
    message_malformed = " | ".join(malformed.errors)
    print(f"    message: {message_malformed!r}")
    expect(
        CAS_MESSAGE_FRAGMENT not in message_malformed,
        f"message does not contain {CAS_MESSAGE_FRAGMENT!r} -- distinct from a real conflict",
    )

    section("teardown")
    call("DELETE", f"{MOUNT}/metadata/{PATH}")
    call("DELETE", f"{MOUNT}/metadata/apps/acme/probe/never-written")
    print("  wiped probe paths")

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) failed:")
        for description in FAILURES:
            print(f"  - {description}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

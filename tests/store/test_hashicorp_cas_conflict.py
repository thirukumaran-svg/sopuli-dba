"""A real Vault's compare-and-set conflict, pinned as a regression (#103, #104).

:class:`~sopuli.store.protocol.CasConflictError` has to be raised for a lost
compare-and-set and *only* for that (``sopuli/store/memory.py`` is the
reference reading of the semantics). Once the HashiCorp adapter exists, that
mapping will key on matching text in Vault's own error response -- a
dependency on someone else's wording, which is exactly the kind of thing that
drifts silently across a Vault upgrade unless something asserts on it. This
is that assertion, run against the real thing rather than trusted from a
one-time reading.

Promoted from ``test/vault_cas_probe.py`` (the exploratory spike, kept for
the wider investigation -- also covers the ``read()`` 404-ambiguity question
and the malformed-cas contrast, neither of which is a string dependency the
way the conflict message is).

Needs a reachable Vault -- ``docker compose --profile tier0 up -d`` from
``test/`` -- and skips cleanly without one, per ``04-testing.md`` §1: the
public suite must stay green using only freely pullable images, and Vault dev
mode is one of them. No project dependency on ``hvac``/``requests`` exists
yet, and this asks a question about Vault's own contract, so it talks HTTP
directly over stdlib ``urllib`` -- same reasoning as the spike it was
promoted from.
"""

from __future__ import annotations

import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from typing import Any

import pytest

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "sopuli-test-root")
MOUNT = "kv"  # the v2 mount test/compose.yaml's vault-init creates

#: Set to opt into running against a non-loopback `VAULT_ADDR`. Off by
#: default: this test deletes and rewrites a fixed path, and inheriting
#: `VAULT_ADDR`/`VAULT_TOKEN` from an unrelated shell session pointed at a
#: real store is exactly the kind of accident invariant 5 exists to prevent
#: elsewhere in this project -- a test has no config file whitelisting what
#: it may touch, so the loopback check does that job here instead.
_ALLOW_REMOTE_ENV = "SOPULI_TEST_ALLOW_REMOTE_VAULT"

#: CLAUDE.md's fixture vocabulary (application `acme`) rather than the
#: tool's own name -- scratch space, but still an example in the codebase.
PATH = "apps/acme/probe/cas-conflict"

#: The fact under test. Duplicated from `test/vault_cas_probe.py` rather than
#: imported -- there is no `sopuli.store.hashicorp` yet for either of them to
#: share it with (#104); once it exists, both this constant and the mapping
#: it documents belong there, and this test should import it instead.
CAS_MESSAGE_FRAGMENT = "check-and-set parameter did not match"


def _call(method: str, path: str, *, json_body: dict[str, Any] | None = None) -> tuple[int, Any]:
    url = f"{VAULT_ADDR}/v1/{path}"
    data = json.dumps(json_body).encode("utf-8") if json_body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("X-Vault-Token", VAULT_TOKEN)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, (json.loads(raw) if raw else None)
        except json.JSONDecodeError:
            return error.code, raw.decode("utf-8", errors="replace")


def _errors(body: Any) -> list[str]:
    if isinstance(body, dict):
        errors = body.get("errors")
        if isinstance(errors, list):
            return [str(item) for item in errors]
    return []


def _write(cas: int) -> tuple[int, Any]:
    return _call(
        "POST",
        f"{MOUNT}/data/{PATH}",
        json_body={"data": {"holder": "test_hashicorp_cas_conflict"}, "options": {"cas": cas}},
    )


def _is_loopback(addr: str) -> bool:
    hostname = urllib.parse.urlparse(addr).hostname
    if hostname is None:
        return False
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False  # a DNS name -- never assumed local


@pytest.fixture(scope="module")
def _vault_reachable() -> None:
    """Skip the whole module, not each test, so the reason is reported once.

    Two things have to hold before any mutating call runs, not just
    connectivity: `VAULT_ADDR` has to be loopback (or the override has to be
    set explicitly), and `VAULT_TOKEN` has to actually authenticate. Neither
    failure is this test's fault -- both mean "not configured for this
    suite" -- so both skip rather than fail, same as an unreachable address.
    """
    if not _is_loopback(VAULT_ADDR) and os.environ.get(_ALLOW_REMOTE_ENV) not in (
        "1",
        "true",
        "yes",
    ):
        pytest.skip(
            f"VAULT_ADDR={VAULT_ADDR!r} is not loopback, and this test writes to a "
            f"fixed scratch path -- set {_ALLOW_REMOTE_ENV}=1 to opt in deliberately"
        )

    try:
        status, _ = _call("GET", "sys/health")
    except (urllib.error.URLError, OSError) as error:
        pytest.skip(f"Vault not reachable at {VAULT_ADDR}: {error}")
    if status not in (200, 429, 472, 473, 501, 503):
        # Any of these means "a Vault answered" (sys/health's own status
        # vocabulary); anything else is a proxy or an unrelated server.
        pytest.skip(f"Vault at {VAULT_ADDR} answered unexpectedly: HTTP {status}")

    # sys/health takes no token, so a bad VAULT_TOKEN survives it undetected
    # and would otherwise fail the first real test with a 403 -- a skip
    # reported once here is more useful than that same 403 four times over.
    auth_status, auth_body = _call("GET", "auth/token/lookup-self")
    if auth_status != 200:
        pytest.skip(
            f"VAULT_TOKEN does not authenticate against {VAULT_ADDR}: "
            f"HTTP {auth_status} {auth_body!r}"
        )


@pytest.fixture
def path(_vault_reachable: None) -> Iterator[str]:
    """A wiped scratch path, cleaned up on the way out too.

    Full metadata delete -- wipes data *and* the version counter -- which is
    fine here because this path is the test's own scratch space, never a
    lock (#83 is the reason release writes a record instead of using this).
    """
    _call("DELETE", f"{MOUNT}/metadata/{PATH}")
    yield PATH
    _call("DELETE", f"{MOUNT}/metadata/{PATH}")


def test_a_stale_cas_zero_is_the_documented_conflict_message(path: str) -> None:
    _write(cas=0)  # version 1 now exists

    status, body = _write(cas=0)

    assert status == 400
    assert CAS_MESSAGE_FRAGMENT in " | ".join(_errors(body))


def test_a_stale_nonzero_cas_has_the_same_message(path: str) -> None:
    _write(cas=0)  # version 1
    _write(cas=1)  # version 2 -- cas=1 is now stale

    status, body = _write(cas=1)

    assert status == 400
    assert CAS_MESSAGE_FRAGMENT in " | ".join(_errors(body))


def test_a_conflict_after_soft_delete_has_the_same_message(path: str) -> None:
    """The trap `sopuli/store/protocol.py`'s `read()` docstring names: a
    soft-deleted path has no data, but its version counter survived, so
    `cas=0` fails exactly like an ordinary stale write -- not differently,
    and not silently succeeding."""
    _write(cas=0)  # version 1
    _call("DELETE", f"{MOUNT}/data/{PATH}")  # soft-delete: data gone, history kept

    status, body = _write(cas=0)

    assert status == 400
    assert CAS_MESSAGE_FRAGMENT in " | ".join(_errors(body))


def test_a_malformed_cas_is_not_mistaken_for_a_conflict(path: str) -> None:
    """A different kind of bad request must not share the conflict's wording,
    or a client matching on it would report a race that never happened."""
    status, body = _call(
        "POST",
        f"{MOUNT}/data/{PATH}",
        json_body={"data": {"holder": "x"}, "options": {"cas": "not-a-number"}},
    )

    assert status == 400
    assert CAS_MESSAGE_FRAGMENT not in " | ".join(_errors(body))

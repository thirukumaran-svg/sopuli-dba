"""Fixtures shared by the whole suite.

`write_config` lives here rather than under `tests/config/` because the CLI
tests need it too: every command now discovers and loads a config file, so a
test that does not supply one is at the mercy of whatever `./sopuli.yaml` or
`~/.config/sopuli/config.yaml` happens to exist on the machine running it.
Passing `--config` at an explicit path is what keeps the suite deterministic.
"""

from __future__ import annotations

import ipaddress
import os
import sys
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest

from sopuli.store.registry import BACKENDS

#: Writes a config file and returns its path.
WriteConfig = Callable[[str], Path]

#: The smallest file the loader accepts. Enough for any test whose subject is
#: the command rather than the configuration.
MINIMAL_CONFIG = "version: 1\n"


@pytest.fixture
def write_config(tmp_path: Path) -> WriteConfig:
    """Write a config file that the P4 permission check will accept.

    On POSIX that means 0600 explicitly: pytest's tmp_path is 0700, but the file
    inside it inherits the process umask and can easily end up group-readable on
    a CI runner -- which would make every test using this fail on the permission
    check rather than on what it says it tests. On Windows the default temp ACL
    already passes, and is covered directly in test_permissions.py.
    """

    def write(text: str) -> Path:
        path = tmp_path / "sopuli.yaml"
        path.write_text(text, encoding="utf-8")
        if sys.platform != "win32":
            path.chmod(0o600)
        return path

    return write


@pytest.fixture
def config_file(write_config: WriteConfig) -> Path:
    """A valid config file, for tests that need one to exist but do not care."""
    return write_config(MINIMAL_CONFIG)


#: The environment variables that now reach a store's settings (#154, §6). A
#: developer running the tier-1 suite has ``VAULT_ADDR`` exported by definition --
#: `vault_stack` below reads it -- and from #154 onward that variable *is* a
#: precedence layer, so without this every CLI test that loads a file with a
#: `defaults.vault` would resolve a different address on their machine than on
#: CI. Cleared per test rather than at import, because the module constants above
#: are read once and the tier-1 fixtures carry their own copy.
VAULT_ENV = ("SOPULI_VAULT", "SOPULI_VAULT_ADDR", "VAULT_ADDR", "VAULT_NAMESPACE", "VAULT_CACERT")


@pytest.fixture(autouse=True)
def no_ambient_vault_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nobody's own ``VAULT_ADDR`` decides what a store resolves to here.

    A test whose subject *is* one of these sets it back with ``setenv``; below the
    CLI boundary nothing reads a real environment at all, since every layer takes
    a mapping (``04-testing.md`` §4).
    """
    for variable in VAULT_ENV:
        monkeypatch.delenv(variable, raising=False)
    for variable in [one for one in os.environ if one.startswith("SOPULI_VAULT__")]:
        monkeypatch.delenv(variable, raising=False)


@pytest.fixture(autouse=True)
def backends_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every backend counts as installed, unless a test says otherwise.

    Install shape is a *dimension of the matrix* (``04-testing.md`` §3), not an
    ambient property of whoever is running the suite. Without this, the output of
    every command that reads a config naming a vault would depend on whether the
    machine happens to have `httpx` -- CI installs `[dev]` and a developer is
    meant to have `[all]`, so the two would disagree about how many warnings
    `config validate` prints, and the test that noticed would be an unrelated
    one.

    So the default is fixed here, and the tests whose subject *is* a missing
    backend opt out by naming the absent client themselves
    (``tests/store/test_missing_backend.py``). Emptying ``provides`` rather than
    faking an import: :func:`~sopuli.store.registry.installed` reports a backend
    with nothing to look for as installed, which is the same path `file` and
    `keyring` take in production.
    """
    for name, backend in list(BACKENDS.items()):
        monkeypatch.setitem(BACKENDS, name, replace(backend, provides=frozenset()))


# --------------------------------------------------------------- tier 1: Vault ---
#
# `04-testing.md` §1: the public suite stays green using only freely pullable
# images, so a missing container is a **skip with a reason** and never a failure.
# Vault dev mode is one of those images -- `docker compose --profile tier0 up -d`
# from `test/` -- so these are ordinarily runnable by anyone.

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "sopuli-test-root")

#: Opt in to running against a non-loopback `VAULT_ADDR`.
#:
#: These tests write to fixed paths and delete metadata, and a test has no config
#: file whitelisting what it may touch -- invariant 5's protection does not reach
#: here. Inheriting `VAULT_ADDR` from a shell pointed at a real store is exactly
#: the accident that would matter, so this check does that job instead.
ALLOW_REMOTE_VAULT = "SOPULI_TEST_ALLOW_REMOTE_VAULT"


@dataclass(frozen=True)
class VaultStack:
    """The running tier-1 Vault, and what a test needs to reach it.

    Carries its own constants rather than exporting them, so no test module has
    to import from this file: `tests/` has no `__init__.py` -- which is why two
    modules may not share a basename -- and a cross-module import here would be
    the same trap one level up.
    """

    addr: str
    token: str
    client: Any
    #: The two mounts `test/compose.yaml`'s vault-init creates.
    kv2_mount: str = "kv"
    kv1_mount: str = "kv1"
    #: CLAUDE.md's fixture vocabulary. Scratch space, but still an example in the
    #: codebase, so `acme` and never anything real.
    scratch: str = "apps/acme/conformance"


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


@pytest.fixture(scope="session")
def vault_stack() -> Iterator[VaultStack]:
    """A reachable Vault, or a skip saying which part was missing.

    Session-scoped so the reason is reported once rather than once per test.
    `httpx` is imported inside the fixture: it is an extra (ADR-006), and a base
    install collecting these files must reach the skip rather than an ImportError.
    """
    opted_in = os.environ.get(ALLOW_REMOTE_VAULT) in ("1", "true", "yes")
    if not _is_loopback(VAULT_ADDR) and not opted_in:
        pytest.skip(
            f"VAULT_ADDR={VAULT_ADDR!r} is not loopback, and these tests write to fixed "
            f"scratch paths -- set {ALLOW_REMOTE_VAULT}=1 to opt in deliberately"
        )

    try:
        import httpx
    except ImportError:  # pragma: no cover -- reached only in a base install
        pytest.skip("httpx is not installed; `pip install -e '.[hashicorp]'`")

    client = httpx.Client(base_url=VAULT_ADDR, headers={"X-Vault-Token": VAULT_TOKEN}, timeout=5)
    try:
        health = client.get("/v1/sys/health")
    except httpx.TransportError as error:
        client.close()
        pytest.skip(f"Vault not reachable at {VAULT_ADDR}: {error}")

    # sys/health's own status vocabulary: any of these means "a Vault answered".
    if health.status_code not in (200, 429, 472, 473, 501, 503):
        client.close()
        pytest.skip(f"Vault at {VAULT_ADDR} answered unexpectedly: HTTP {health.status_code}")

    # sys/health takes no token, so a bad one survives it undetected and would
    # fail the first real test with a 403 instead. One skip beats N failures.
    if client.get("/v1/auth/token/lookup-self").status_code != 200:
        client.close()
        pytest.skip(f"VAULT_TOKEN does not authenticate against {VAULT_ADDR}")

    yield VaultStack(addr=VAULT_ADDR, token=VAULT_TOKEN, client=client)
    client.close()

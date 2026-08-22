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
from typing import Any, NoReturn

import pytest

from oracle_harness import Environment, decide_skip, dsn_host, probe, render_matrix
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


#: Set to ``required`` where a tier-1 environment is supposed to be present --
#: which is the CI lane and nowhere else (#184).
#:
#: A skipped tier-1 test is the correct outcome on a laptop with nothing running
#: and a **silent hole** in a job that exists to run it. `04-testing.md` §3 draws
#: the same line for its two skip counts: a capability skip is correct, a missing
#: environment is a coverage gap. So this turns the second into a failure and
#: leaves the first alone -- a lane that reported green while skipping everything
#: would be worse than no lane, because it would be quoted as evidence.
TIER1 = "SOPULI_TEST_TIER1"


def _missing_environment(reason: str) -> NoReturn:
    """Skip, or fail if this run was supposed to have an environment."""
    if os.environ.get(TIER1) == "required":
        pytest.fail(f"tier 1 required, but the environment was not there: {reason}", pytrace=False)
    pytest.skip(reason)


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
        _missing_environment(
            f"VAULT_ADDR={VAULT_ADDR!r} is not loopback, and these tests write to fixed "
            f"scratch paths -- set {ALLOW_REMOTE_VAULT}=1 to opt in deliberately"
        )

    try:
        import httpx
    except ImportError:  # pragma: no cover -- reached only in a base install
        _missing_environment("httpx is not installed; `pip install -e '.[hashicorp]'`")

    client = httpx.Client(base_url=VAULT_ADDR, headers={"X-Vault-Token": VAULT_TOKEN}, timeout=5)
    try:
        health = client.get("/v1/sys/health")
    except httpx.TransportError as error:
        client.close()
        _missing_environment(f"Vault not reachable at {VAULT_ADDR}: {error}")

    # sys/health's own status vocabulary: any of these means "a Vault answered".
    if health.status_code not in (200, 429, 472, 473, 501, 503):
        client.close()
        _missing_environment(
            f"Vault at {VAULT_ADDR} answered unexpectedly: HTTP {health.status_code}"
        )

    # sys/health takes no token, so a bad one survives it undetected and would
    # fail the first real test with a 403 instead. One skip beats N failures.
    if client.get("/v1/auth/token/lookup-self").status_code != 200:
        client.close()
        _missing_environment(f"VAULT_TOKEN does not authenticate against {VAULT_ADDR}")

    yield VaultStack(addr=VAULT_ADDR, token=VAULT_TOKEN, client=client)
    client.close()


# ---------------------------------------------------------- tier 1: Oracle ---
#
# The tier-1 Oracle fixture, and the markers that gate tests on capabilities.
#
# Everything that opens a socket is here; everything that can be decided without
# one is in :mod:`oracle_harness` beside it, so the interesting half is tier 0.
#
# **A missing environment is a skip with a reason, never a failure** (§1). The
# public suite has to be green on freely pullable images alone, and greener still
# on a laptop with nothing running: `docker compose --profile tier1 up -d` from
# `test/` is what turns these on. The skip says which part was missing, because
# "skipped" without a reason is indistinguishable from a test nobody wrote.
#
# Three things can be absent and they are three different findings, so they get
# three different messages:
#
# * ``oracledb`` is not installed — the extra was never asked for (ADR-006);
# * **Instant Client** is not installed — thick mode cannot start, which is D3's
#   runtime prerequisite and the thing that bites a new contributor first;
# * the database is not reachable — no container, or the wrong DSN.
#
# Only the third is what most people mean by "no test environment", and reporting
# the other two as that would send somebody to `docker` for a `pip` problem.


#: Where the tier-1 database is. The default is `test/compose.yaml`'s
#: `oracle-free` service, so a contributor who brought the stack up needs no
#: environment variables at all.
DSN = os.environ.get("SOPULI_TEST_ORACLE_DSN", "localhost:1521/FREEPDB1")
USER = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")

#: Opt in to running against a non-loopback DSN.
#:
#: The same guard `vault_stack` has, and the argument is stronger here: these
#: tests create and drop accounts, and a test has no config file whitelisting
#: what it may touch, so invariant 5's protection does not reach them.
#: Inheriting a DSN from a shell pointed at a real database is exactly the
#: accident worth preventing.
ALLOW_REMOTE = "SOPULI_TEST_ALLOW_REMOTE_ORACLE"

#: How the environment is named in the matrix. One column today; the report
#: takes a sequence so a second is data rather than code (`04-testing.md` §3).
ENVIRONMENT_NAME = os.environ.get("SOPULI_TEST_ORACLE_NAME", "oracle")

#: Filled by the fixture and read by the summary hook. Module state because a
#: terminal hook has no access to fixtures, and the alternative -- stashing it on
#: the session -- is the same thing with more ceremony.
_ENVIRONMENTS: list[Environment] = []
_SKIPS = {"capability": 0, "environment": 0}


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "requires_capability(*names): run only where the target reports every one",
    )
    config.addinivalue_line(
        "markers",
        "requires_no_capability(*names): run only where the target reports none of them",
    )


def _dsn_is_loopback(dsn: str) -> bool:
    """The same question as :func:`_is_loopback`, asked of an Oracle DSN.

    A DSN is not a URL, so the host is pulled out by
    :func:`~oracle_harness.dsn_host` -- which is in the harness because that
    parsing is the part with edge cases worth testing -- and then reshaped into
    one. Delegating rather than growing a second notion of "loopback" is what
    stops this recognising `127.0.0.1` and missing `127.0.0.2`.
    """
    return _is_loopback(f"//{dsn_host(dsn)}")


@pytest.fixture(scope="session")
def oracle_target() -> Iterator[Environment]:
    """A probed Oracle, or an :class:`Environment` saying why there is not one.

    Session-scoped, and deliberately: most Oracle containers take minutes to
    start, so §4's rule is one long-running container per version per session
    and state reset by dropping and recreating accounts — never by recreating
    the container.

    Yields rather than skips, so that the summary can report the gap. A test
    that cannot run gets its skip from :func:`decide_skip` through the gate
    below, which is also what keeps the two skip counts apart.
    """
    environment = Environment(name=ENVIRONMENT_NAME, dsn=DSN)

    if not _dsn_is_loopback(DSN) and not os.environ.get(ALLOW_REMOTE):
        environment.unreachable_reason = (
            f"{DSN} is not loopback, and these tests create and drop accounts; "
            f"set {ALLOW_REMOTE}=1 to allow it"
        )
        _ENVIRONMENTS.append(environment)
        yield environment
        return

    try:
        import oracledb
    except ImportError:
        environment.unreachable_reason = "oracledb is not installed; `pip install -e '.[oracle]'`"
        _ENVIRONMENTS.append(environment)
        yield environment
        return

    connection = None
    try:
        # Thick mode, always (D3): thin mode has no Native Network Encryption,
        # so a harness that quietly used it would be exercising a configuration
        # the tool cannot run in.
        #
        # **The tool's own initialisation, not a second copy** (#176). This was
        # a bare `init_oracle_client()` until `session.initialise` existed, and
        # the difference is not cosmetic: the tool honours §6's
        # `SOPULI_ORACLE_CLIENT_LIB_DIR` and the bare call does not, so a
        # contributor whose Instant Client is anywhere the loader does not
        # already look could point the tool at it and still watch every tier-1
        # test skip. Two initialisations mean two answers to "where is the
        # client", and only one of them was the documented one.
        from sopuli.driver.oracle import session as oracle_session

        oracle_session.initialise(env=os.environ)
        connection = oracledb.connect(user=USER, password=PASSWORD, dsn=DSN)
        cursor = connection.cursor()
        row = cursor.execute("select version_full from v$instance").fetchone()
        environment.version = row[0] if row else None
        environment.capabilities = set(probe(cursor))
    except Exception as exc:  # noqa: BLE001 -- any failure means "not available"
        environment.unreachable_reason = _why(exc)

    _ENVIRONMENTS.append(environment)
    try:
        yield environment
    finally:
        if connection is not None:
            connection.close()


def _why(exc: BaseException) -> str:
    """A skip reason in the tool's own vocabulary.

    Uses the driver's error mapping (#172) rather than a bare `str(exc)`, so
    that "Instant Client is missing" reads as itself instead of as `DPI-1047`
    — the failure a contributor hits first, and the one most likely to be
    mistaken for a missing container.
    """
    from sopuli.driver.oracle.client import ClientError
    from sopuli.driver.oracle.errors import CLIENT_LIBRARY, from_error

    if isinstance(exc, ClientError):
        # Already worded for exactly this reader (#176): it names DPI-1047, keeps
        # the driver's own detail about which library failed, and carries the
        # per-platform remediation. Running it back through `from_error` would
        # classify our own exception as an unreadable driver failure.
        #
        # `str`, not `.message`: the remediation lives in `hint`, and `__str__`
        # is what renders the two together. Returning the message alone dropped
        # exactly the LD_LIBRARY_PATH / PATH / VC++ guidance this branch exists
        # to preserve -- caught in #176's review, having been claimed in this
        # very comment.
        return str(exc)

    diagnosis = from_error(exc)
    if diagnosis.kind == CLIENT_LIBRARY:
        # Ours *and* the driver's, not ours instead of it. DPI-1047 names the
        # library it could not load -- and on Ubuntu 24.04 that is `libaio.so.1`,
        # which is present under a different name, so "Instant Client is not
        # installed" is true-sounding and useless on its own. This message is
        # read by somebody who cannot see the machine.
        return f"{diagnosis.code}: thick mode could not start (D3) -- {diagnosis.message}"
    return f"{diagnosis.code or type(exc).__name__}: {diagnosis.message}".strip()


@pytest.fixture
def live_oracle(oracle_target: Environment) -> Environment:
    """An Oracle that is actually there, or the right kind of skip (#176).

    :func:`oracle_target` yields whatever it found, including a reason it found
    nothing, because the summary reports the gap rather than hiding it. The
    autouse gate below turns that into a skip — but only for a test carrying a
    capability marker, and a test that needs *a database* and no particular
    capability has none to carry.

    Connecting is the first thing in that shape and will not be the last, so
    this is a fixture rather than three lines in one module. It counts the skip
    where :func:`decide_skip` would have, and goes through
    :func:`_missing_environment`, so a lane running with
    ``SOPULI_TEST_TIER1=required`` still fails rather than reporting green over
    an absent database.
    """
    reason = decide_skip(oracle_target)
    if reason is not None:
        _SKIPS["environment"] += 1
        _missing_environment(reason)
    return oracle_target


@pytest.fixture
def oracle_client() -> None:
    """Instant Client, up -- and **no database** (#176).

    A narrower prerequisite than :func:`live_oracle`, for the tests that need
    thick mode and nothing at the other end: the client's version, and anything
    else `doctor` will want to answer before it makes anybody wait on a
    connection that cannot succeed (#182).

    Separate because the alternative is a test named "without a database" that
    takes a fixture which connects to one -- true of the first draft, and
    pointed out in review. It would skip for the wrong reason on a machine with
    a client and no container, and it could not tell whether it was exercising
    the offline path at all.
    """
    session = pytest.importorskip("sopuli.driver.oracle.session")
    from sopuli.driver.oracle.client import ClientError

    try:
        session.initialise(env=os.environ)
    except ClientError as error:
        _SKIPS["environment"] += 1
        _missing_environment(f"environment unavailable: {error}")


@pytest.fixture(autouse=True)
def _capability_gate(request: pytest.FixtureRequest) -> None:
    """Apply `requires_capability` / `requires_no_capability`.

    Autouse so a test declares what it needs and nothing else: no fixture to
    remember to request, and no way to mark a test and have the mark do nothing.
    A test with neither marker never asks for the environment, which is what
    keeps the tier-0 tests in this directory free of it.
    """
    required = _names(request.node, "requires_capability")
    forbidden = _names(request.node, "requires_no_capability")
    if not required and not forbidden:
        return

    environment = request.getfixturevalue("oracle_target")
    reason = decide_skip(environment, required=required, forbidden=forbidden)
    if reason is None:
        return

    if reason.startswith("environment"):
        _SKIPS["environment"] += 1
        _missing_environment(reason)

    # A capability skip stays a skip even under `required`: 18c genuinely has no
    # rollover, and a lane that failed over that would be asserting the model is
    # wrong (§3).
    _SKIPS["capability"] += 1
    pytest.skip(reason)


def _names(node: pytest.Item, marker: str) -> tuple[str, ...]:
    found = node.get_closest_marker(marker)
    return tuple(found.args) if found else ()


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    """§3's matrix, so that "green" is never ambiguous.

    Printed only when something asked for an environment. A tier-0-only run --
    which is every run on a laptop with no containers up -- says nothing, because
    a report about a database nobody wanted is noise.
    """
    if not _ENVIRONMENTS:
        return

    terminalreporter.write_line("")
    terminalreporter.write_line(
        render_matrix(
            _ENVIRONMENTS,
            capability_skips=_SKIPS["capability"],
            environment_skips=_SKIPS["environment"],
        )
    )

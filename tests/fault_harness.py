"""The fault-injection harness for `04-testing.md` §5 *Fault injection*.

Two parts:

* :class:`CliRun` starts ``sopuli`` as a real process with ``--output jsonl``
  and reads its events as they arrive. A test waits for an event, then kills the
  process. ``Popen.kill`` is ``SIGKILL`` on POSIX and ``TerminateProcess`` on
  Windows, so neither gives the run a chance to clean up.
* :class:`VaultGate` is an HTTP proxy between the run and Vault. It forwards
  every request, and injects one fault at one request to the secret's path:
  it holds a write, drops it and goes down, or serves an old read. It can also
  pause a write while the test changes the database, then forward it.

**Why the gate, and not a TCP proxy.** A fault sent when the test reads an
event is a race. The run carries on after it prints ``password.applied``: it
verifies, then promotes. A kill or a cut sent then lands before the promotion
on most runs, not on all, and a fault test that passes on most runs measures
nothing. A TCP proxy such as toxiproxy cannot tell one HTTP request from the
next, so it has the same race. The gate acts on the request itself. It watches
only the secret's own path. Lock records live under ``locks/``, so their reads
and writes pass.

**Popen's pid is not always the run's.** On Windows in a virtual environment,
``sys.executable`` is a launcher that starts the real interpreter as a child, so
``Popen.pid`` names the launcher. The launcher's job object takes the child
down when it is killed. A test that needs the run's own pid reads it from what
the run wrote, such as its lock record.

Nothing here imports ``httpx`` at module scope. It is an extra (ADR-006), and a
base install must reach the fixture's skip, not an ImportError.
"""

from __future__ import annotations

import itertools
import json
import os
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping
from concurrent.futures import Executor, Future
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

#: How long to wait for an event, or for the gate to catch a write. Long enough
#: for a thick-mode connect and a login on a slow runner.
TIMEOUT = 60.0

#: Methods that write. Vault's KV v2 API takes a write as POST or PUT, and a
#: merge patch as PATCH.
WRITES = ("POST", "PUT", "PATCH")


class Fault(Enum):
    """The faults :class:`VaultGate` injects at its path.

    ``writes`` counts the writes to that path as they arrive, from 1, whatever
    Vault answers them. Down means the listening
    socket is closed, so the run's next connection is refused.
    """

    #: Hold write ``writes`` and never forward it. The run waits there until the
    #: test kills it.
    HOLD_WRITE = "hold write"
    #: Drop write ``writes`` unanswered, and go down. Vault never sees it.
    DOWN_AT_WRITE = "down at write"
    #: Forward write ``writes``, then go down without answering it. Vault commits
    #: the write, and the run cannot know that it did.
    DOWN_AFTER_WRITE = "down after write"
    #: Forward write ``writes``. After it, answer every read with the reply to
    #: the last read before it, as a replica behind its primary would.
    STALE_AFTER_WRITES = "stale after writes"
    #: Hold write ``writes`` until the test calls :meth:`VaultGate.release`,
    #: then forward it. The test changes the database in between.
    PAUSE_WRITE = "pause write"


class HarnessError(RuntimeError):
    """The harness failed, not the run under test.

    Not an ``AssertionError``, so a test marked ``xfail(raises=AssertionError)``
    fails when its harness breaks instead of counting it as the expected
    failure.
    """


#: One upstream reply, kept so that it can be sent again: status, headers, body.
Answer = tuple[int, list[tuple[str, str]], bytes]


class VaultGate:
    """A proxy to Vault that injects one fault at one path.

    ``tripped`` is set when the fault takes effect. ``seen`` lists every request
    that reached the gate, as ``"METHOD path"``, so a test can show what Vault
    was and was not asked.

    The handlers run on threads of their own, so the counters change under
    ``_lock``. A run sends one request at a time, but the fault must land on the
    write it names even if that ever changes.
    """

    def __init__(self, upstream: str, path: str, fault: Fault, *, writes: int = 1) -> None:
        import httpx

        self.upstream = httpx.Client(base_url=upstream, timeout=TIMEOUT)
        self.path = path
        self.fault = fault
        self.writes = writes
        self.tripped = threading.Event()
        self.seen: list[str] = []
        self._release = threading.Event()
        self._closing = False
        self._lock = threading.Lock()
        self._arrived = 0
        self._last_read: Answer | None = None
        self._stale: Answer | None = None
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def addr(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host!s}:{port}"

    def release(self) -> None:
        """Let a paused write through."""
        self._release.set()

    def close(self) -> None:
        # Wakes a held or paused write without forwarding it. A paused write
        # released here belongs to a test that has already ended.
        self._closing = True
        self._release.set()
        self._go_down()
        self.upstream.close()

    def _go_down(self) -> None:
        """Stop accepting connections. Safe to call more than once."""
        self._server.shutdown()
        self._server.server_close()

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        gate = self

        class Handler(BaseHTTPRequestHandler):
            def _forward(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                ours = self.path.split("?")[0] == gate.path
                read, write = self.command == "GET", self.command in WRITES
                with gate._lock:
                    gate.seen.append(f"{self.command} {self.path}")
                    if ours and write:
                        gate._arrived += 1
                    faulted = ours and write and gate._arrived == gate.writes
                    stale = gate._stale if ours and read else None

                if faulted and gate.fault is Fault.HOLD_WRITE:
                    gate.tripped.set()
                    gate._release.wait(TIMEOUT)
                    return
                if faulted and gate.fault is Fault.PAUSE_WRITE:
                    gate.tripped.set()
                    if not gate._release.wait(TIMEOUT) or gate._closing:
                        return
                if faulted and gate.fault is Fault.DOWN_AT_WRITE:
                    gate.tripped.set()
                    gate._go_down()
                    return
                if stale is not None:
                    gate.tripped.set()
                    self._reply(stale)
                    return

                answer = self._upstream(body)
                with gate._lock:
                    if ours and read:
                        gate._last_read = answer
                    if faulted and gate.fault is Fault.STALE_AFTER_WRITES:
                        gate._stale = gate._last_read
                if faulted and gate.fault is Fault.DOWN_AFTER_WRITE:
                    gate.tripped.set()
                    gate._go_down()
                    return
                self._reply(answer)

            def _upstream(self, body: bytes) -> Answer:
                # No Accept-Encoding: ``reply.content`` is decoded, so the reply
                # goes back uncompressed whatever Vault would have sent.
                headers = {
                    name: value
                    for name, value in self.headers.items()
                    if name.lower()
                    not in ("host", "content-length", "connection", "accept-encoding")
                }
                reply = gate.upstream.request(
                    self.command, self.path, content=body, headers=headers
                )
                kept = [
                    (name, value)
                    for name, value in reply.headers.items()
                    if name.lower()
                    not in ("content-length", "content-encoding", "transfer-encoding", "connection")
                ]
                return reply.status_code, kept, reply.content

            def _reply(self, answer: Answer) -> None:
                status, headers, content = answer
                self.send_response(status)
                for name, value in headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)

            # http.server dispatches on these names, so they cannot be snake_case.
            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_LIST = _forward  # noqa: N815

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

        return Handler


def sopuli_command(config: Path, output: str, args: list[str]) -> list[str]:
    """The command line that runs ``sopuli`` with this interpreter."""
    return [
        sys.executable,
        "-c",
        "from sopuli.cli import main; main()",
        "--config",
        str(config),
        "--output",
        output,
        *args,
    ]


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
{targets}
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

TARGET = """  - name: {name}
    type: oracle
    environment: dev
    vault: vault-dev
    dsn: "{dsn}"
    admin: {{ username: {user}, auth: {{ method: env }} }}
"""

BREAK_EXPIRED = """  locking:
    break_expired: true
"""


@dataclass
class Estate:
    """One account, one private mount, and the means to run sopuli against them.

    The account is on one target, ``free-pdb`` at ``dsn``. A test that needs
    more targets names them in ``more_targets``, as ``(name, dsn)``, and creates
    the account on each.
    """

    tmp_path: Path
    vault: Any
    mount: str
    dsn: str
    env: dict[str, str]
    login: Callable[[str], bool]
    #: The admin user the config names. Its password is in ``env``.
    user: str
    more_targets: tuple[tuple[str, str], ...] = ()
    _configs: itertools.count[int] = field(default_factory=itertools.count)

    def config(self, addr: str, *, break_expired: bool = False) -> Path:
        """A config whose vault is at ``addr``: Vault itself, or a gate in front of it."""
        path = self.tmp_path / f"sopuli-{next(self._configs)}.yaml"
        targets = "".join(
            TARGET.format(name=name, dsn=dsn, user=self.user)
            for name, dsn in (("free-pdb", self.dsn), *self.more_targets)
        )
        path.write_text(
            CONFIG.format(
                locking=BREAK_EXPIRED if break_expired else "",
                addr=addr,
                mount=self.mount,
                targets=targets,
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

    def break_lock(self, config: Path) -> None:
        """Break the secret's lock with ``--force``, as an operator would for a dead run."""
        broken = self.sopuli(config, "lock", "break", f"vault-dev:{SECRET}", "--force", "--confirm")
        assert broken.returncode == 0, broken.stderr

    def expire_lock(self) -> int:
        """Move the held lock past its expiry, as fifteen minutes would.

        The lease is a fixed fifteen minutes (``DEFAULT_TTL``), too long to wait
        in a test. The record is rewritten with ``expires_at`` beyond the
        clock-skew margin, and everything else as its holder left it. Returns
        the version the rewrite produced.
        """
        record, version = self.read(LOCK)
        if record["state"] != "held":
            raise HarnessError(f"no held lock to expire: the record is {record['state']!r}")
        past = datetime.now(UTC) - timedelta(minutes=5)
        record["expires_at"] = past.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        reply = self.vault.post(
            f"/v1/{self.mount}/data/{LOCK}", json={"options": {"cas": version}, "data": record}
        )
        if reply.status_code != 200:
            raise HarnessError(f"could not rewrite {LOCK}: HTTP {reply.status_code} {reply.text}")
        return int(reply.json()["data"]["version"])

    def read(self, path: str) -> tuple[dict[str, Any], int]:
        """The data at ``path`` on the private mount, and its version."""
        reply = self.vault.get(f"/v1/{self.mount}/data/{path}")
        if reply.status_code != 200:
            raise HarnessError(f"could not read {path}: HTTP {reply.status_code} {reply.text}")
        body = reply.json()["data"]
        return body["data"], body["metadata"]["version"]


class CliRun:
    """One ``sopuli`` process, with its ``jsonl`` events read as they arrive."""

    def __init__(self, config: Path, args: list[str], env: Mapping[str, str]) -> None:
        self.process = subprocess.Popen(
            sopuli_command(config, "jsonl", args),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, **env},
            text=True,
            encoding="utf-8",
        )
        self.events: list[dict[str, Any]] = []
        self.stderr = ""
        self._arrived: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._readers = [
            threading.Thread(target=self._read_events, daemon=True),
            threading.Thread(target=self._read_stderr, daemon=True),
        ]
        for reader in self._readers:
            reader.start()

    def wait_for(self, name: str) -> dict[str, Any]:
        """Return the first event called ``name``, or fail if the run ends first."""
        while True:
            try:
                event = self._arrived.get(timeout=TIMEOUT)
            except queue.Empty:
                self.kill()
                raise AssertionError(f"no {name!r} event within {TIMEOUT}s") from None
            if event is None:
                self.process.wait(timeout=TIMEOUT)
                raise AssertionError(
                    f"the run ended with exit {self.process.returncode} before {name!r}; "
                    f"events: {[seen['event'] for seen in self.events]}; stderr: {self.stderr}"
                )
            if event["event"] == name:
                return event

    def kill(self) -> None:
        """Kill the run, if it is still running, and wait for it."""
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=TIMEOUT)
        for reader in self._readers:
            reader.join(timeout=TIMEOUT)

    def _read_events(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            if line.strip():
                event = json.loads(line)
                self.events.append(event)
                self._arrived.put(event)
        self._arrived.put(None)

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        self.stderr = self.process.stderr.read()


#: ``rotate``'s first write to the secret's path stages ``pending``.
STAGING = 1


def start_paused(
    pool: Executor, estate: Estate, gate: VaultGate, *args: str
) -> Future[subprocess.CompletedProcess[str]]:
    """Run sopuli through ``gate``, and return once the gate holds its write.

    The run can end before the write, such as on a pre-flight refusal. Then its
    own output says why, so the error reports it.
    """
    run = pool.submit(estate.sopuli, estate.config(gate.addr), *args)
    deadline = time.monotonic() + TIMEOUT
    while not gate.tripped.wait(0.5):
        if run.done() or time.monotonic() > deadline:
            raise HarnessError(
                f"the run never reached the gate; the gate saw {gate.seen}{_ended(run)}"
            )
    return run


def _ended(run: Future[subprocess.CompletedProcess[str]]) -> str:
    if not run.done():
        return ""
    error = run.exception()
    if error is not None:
        return f"; the run raised {error!r}"
    ended = run.result()
    return f"; exit {ended.returncode}, stderr: {ended.stderr}"

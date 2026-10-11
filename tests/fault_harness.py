"""The fault-injection harness for `04-testing.md` §5 *Fault injection*.

Two parts, both used by the tests that kill a run part way through:

* :class:`CliRun` starts ``sopuli`` as a real process with ``--output jsonl``
  and reads its events as they arrive. A test waits for an event, then kills the
  process. ``Popen.kill`` is ``SIGKILL`` on POSIX and ``TerminateProcess`` on
  Windows, so neither gives the run a chance to clean up.
* :class:`VaultGate` is an HTTP proxy between the run and Vault. It forwards
  every request, except a write to one chosen path, which it holds and never
  forwards.

**Why the gate.** Killing at an event alone is a race. The run carries on after
it prints ``password.applied``: it verifies, then promotes. A kill sent when the
test reads the event lands before the promotion on most runs, not on all, and a
fault test that passes on most runs measures nothing. With the gate, the run
stops at the promotion write and waits there, so the kill always comes first.
The gate holds only the secret's own path. Lock writes go to ``locks/``, so
they pass.

**Popen's pid is not always the run's.** On Windows in a virtual environment,
``sys.executable`` is a launcher that starts the real interpreter as a child, so
``Popen.pid`` names the launcher. The launcher's job object takes the child
down when it is killed. A test that needs the run's own pid reads it from what
the run wrote, such as its lock record.

Nothing here imports ``httpx`` at module scope. It is an extra (ADR-006), and a
base install must reach the fixture's skip, not an ImportError.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

#: How long to wait for an event, or for the gate to catch a write. Long enough
#: for a thick-mode connect and a login on a slow runner.
TIMEOUT = 60.0

#: Methods that write. Vault's KV v2 API takes a write as POST or PUT, and a
#: merge patch as PATCH.
WRITES = ("POST", "PUT", "PATCH")


class VaultGate:
    """A proxy to Vault that holds every write to one path.

    ``held`` is set when the first such write arrives. The held request is never
    forwarded: Vault never sees it. :meth:`close` lets the handler thread finish,
    and the run that sent the request gets no answer, because by then it is dead.
    """

    def __init__(self, upstream: str, hold_path: str) -> None:
        import httpx

        self.upstream = httpx.Client(base_url=upstream, timeout=TIMEOUT)
        self.hold_path = hold_path
        self.held = threading.Event()
        self._release = threading.Event()
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def addr(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host!s}:{port}"

    def close(self) -> None:
        self._release.set()
        self._server.shutdown()
        self._server.server_close()
        self.upstream.close()

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        gate = self

        class Handler(BaseHTTPRequestHandler):
            def _forward(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                if self.command in WRITES and self.path.split("?")[0] == gate.hold_path:
                    gate.held.set()
                    gate._release.wait(TIMEOUT)
                    return
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
                self.send_response(reply.status_code)
                for name, value in reply.headers.items():
                    if name.lower() not in (
                        "content-length",
                        "content-encoding",
                        "transfer-encoding",
                        "connection",
                    ):
                        self.send_header(name, value)
                self.send_header("Content-Length", str(len(reply.content)))
                self.end_headers()
                self.wfile.write(reply.content)

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

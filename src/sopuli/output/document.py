"""The run document (``docs/design/03-json-output.md`` §2).

There is no such thing as a placeholder run document. ``sopuli-run-1.0.schema.json``
sets ``additionalProperties: false`` at the root and requires six top-level
fields, two of which have required members of their own, so the smallest thing
that validates is a complete document. Building it properly now is cheaper than
discovering the shape later, and it makes the schema check in CI real from the
first command (invariant 12).

Optional sections (``plan``, ``results``, ``diagnostics``) are omitted entirely
rather than emitted as ``null`` — the schema types them as object/array, so a
null would fail validation.
"""

from __future__ import annotations

import getpass
import socket
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

SCHEMA_VERSION = "1.0"
TOOL_NAME = "sopuli"  # schema pins this to the binary name (D1), not the distribution


def utc_now() -> datetime:
    """Current time as an aware UTC datetime."""
    return datetime.now(UTC)


def to_rfc3339(moment: datetime) -> str:
    """RFC 3339 with a trailing ``Z``, as the schema's timestamp type requires."""
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def current_actor() -> Actor:
    """Describe who is running the tool, degrading rather than raising."""
    try:
        os_user = getpass.getuser()
    except Exception:  # noqa: BLE001 - no controlling terminal, no passwd entry, etc.
        os_user = "unknown"
    return Actor(os_user=os_user, host=socket.gethostname())


@dataclass(frozen=True)
class Actor:
    """``invocation.actor``. Never carries a token — only an identity name."""

    os_user: str
    host: str
    vault_identity: str | None = None
    scheduled: bool = False

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"os_user": self.os_user, "host": self.host}
        if self.vault_identity is not None:
            data["vault_identity"] = self.vault_identity
        if self.scheduled:
            data["scheduled"] = self.scheduled
        return data


@dataclass(frozen=True)
class Summary:
    """``summary``. Only the four required counters are populated so far."""

    total: int = 0
    ok: int = 0
    changed: int = 0
    failed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "ok": self.ok,
            "changed": self.changed,
            "failed": self.failed,
        }


@dataclass
class RunDocument:
    """One run, serialisable to the ``--output json`` contract.

    Construct with :meth:`start`, then :meth:`finish` once the exit code is
    known — the schema requires both timestamps and the duration, so the
    document cannot be built in a single step.
    """

    command: str
    correlation_id: str
    started_at: datetime
    actor: Actor
    dry_run: bool = False
    finished_at: datetime | None = None
    summary: Summary = field(default_factory=Summary)
    exit_code: int = 0

    @classmethod
    def start(cls, command: str, *, dry_run: bool = False) -> RunDocument:
        """Open a run document. ``command`` must be a value from the schema enum."""
        return cls(
            command=command,
            correlation_id=str(uuid.uuid4()),
            started_at=utc_now(),
            actor=current_actor(),
            dry_run=dry_run,
        )

    def finish(self, exit_code: int, summary: Summary | None = None) -> RunDocument:
        """Close the run. Returns self so callers can chain into an emitter."""
        self.finished_at = utc_now()
        self.exit_code = int(exit_code)
        if summary is not None:
            self.summary = summary
        return self

    def to_dict(self) -> dict[str, Any]:
        """Render to the shape ``sopuli-run-1.0.schema.json`` describes."""
        finished_at = self.finished_at or utc_now()
        duration_ms = int((finished_at - self.started_at).total_seconds() * 1000)
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": TOOL_NAME, "version": _tool_version()},
            "command": self.command,
            "invocation": {
                "correlation_id": self.correlation_id,
                "started_at": to_rfc3339(self.started_at),
                "finished_at": to_rfc3339(finished_at),
                "duration_ms": duration_ms,
                "actor": self.actor.to_dict(),
                "dry_run": self.dry_run,
            },
            "summary": self.summary.to_dict(),
            "exit_code": self.exit_code,
        }


def _tool_version() -> str:
    # Imported lazily so that document.py stays importable in isolation.
    from sopuli.version import get_version

    return get_version()

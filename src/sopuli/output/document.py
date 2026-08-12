"""The run document (``docs/design/03-json-output.md`` §2).

There is no such thing as a placeholder run document. ``sopuli-run-1.3.schema.json``
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

SCHEMA_VERSION = "1.3"
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
    #: Whether the run could have prompted, not which flag was passed. There was
    #: a `--scheduled` flag and an `actor.scheduled` to match it; both are gone.
    #: `01-configuration.md` §5 puts run context in a profile, and the thing a
    #: reader of the output actually wants to know is whether anybody could have
    #: been asked -- which stays true when a run is unattended for some other
    #: reason, such as a closed stdin.
    unattended: bool = False

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"os_user": self.os_user, "host": self.host}
        if self.vault_identity is not None:
            data["vault_identity"] = self.vault_identity
        if self.unattended:
            data["unattended"] = self.unattended
        return data


@dataclass(frozen=True)
class Diagnostic:
    """One entry in ``diagnostics`` — a run-level message with no single result
    to hang it on.

    Where a config warning goes in ``--output json``. The config layer does no
    I/O (``04-testing.md`` §4), so its findings cannot be printed where they are
    made; they travel on the :class:`~sopuli.config.model.Config` and become
    these at the boundary.

    ``code``, ``target`` and ``account`` are omitted rather than nulled when
    absent. The schema types them as nullable, so either would validate — but a
    consumer testing ``"target" in diagnostic`` and a consumer testing
    ``diagnostic["target"] is not None`` should not disagree, and omission is
    what the rest of this module already does.
    """

    level: str
    message: str
    code: str | None = None
    target: str | None = None
    account: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"level": self.level, "message": self.message}
        for key, value in (("code", self.code), ("target", self.target), ("account", self.account)):
            if value is not None:
                data[key] = value
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
    #: Run-level messages, in the order they were made. Emitted only when there
    #: are any: the schema types it as an array, so an empty one would be noise
    #: in every clean run and a null would fail validation.
    diagnostics: list[Diagnostic] = field(default_factory=list)
    #: ``invocation.selection.select`` -- the label filters as given. A run over
    #: part of the estate must say so: a consumer counting 3 targets cannot
    #: otherwise tell a small estate from a filtered one, and "3 rotated" means
    #: different things in each. Absent when the whole estate was in scope.
    #:
    #: The schema has carried ``selection`` since it was written, with slots for
    #: the selectors that do not exist yet: ``applications``, ``accounts``,
    #: ``targets``, ``groups``, ``all`` and ``limit``. Only ``select`` is
    #: populated, and the others are omitted rather than sent empty -- an empty
    #: array would claim the tool considered a selector it has not implemented.
    selection: dict[str, str] | None = None
    #: The ``config`` section, when the command produces one. Its shape belongs
    #: to the command that builds it (:mod:`sopuli.output.config_view`) rather
    #: than here, and is pinned by the schema and by
    #: ``tests/test_run_document.py`` -- this only decides that it is optional
    #: and omitted rather than nulled when absent.
    config: dict[str, Any] | None = None
    #: The ``policy`` section, emitted by ``policy sample``. Same arrangement as
    #: ``config``: :mod:`sopuli.output.policy_view` owns the shape. It describes
    #: the passwords a policy produces and never carries one -- the schema gives a
    #: sample no value property at all, which is what keeps ``--reveal`` a
    #: text-only affair.
    policy: dict[str, Any] | None = None

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
        """Render to the shape ``sopuli-run-1.3.schema.json`` describes."""
        finished_at = self.finished_at or utc_now()
        duration_ms = int((finished_at - self.started_at).total_seconds() * 1000)
        invocation: dict[str, Any] = {
            "correlation_id": self.correlation_id,
            "started_at": to_rfc3339(self.started_at),
            "finished_at": to_rfc3339(finished_at),
            "duration_ms": duration_ms,
            "actor": self.actor.to_dict(),
            "dry_run": self.dry_run,
        }
        if self.selection is not None:
            invocation["selection"] = {"select": self.selection}
        document: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": TOOL_NAME, "version": _tool_version()},
            "command": self.command,
            "invocation": invocation,
            "summary": self.summary.to_dict(),
            "exit_code": self.exit_code,
        }
        if self.diagnostics:
            document["diagnostics"] = [diagnostic.to_dict() for diagnostic in self.diagnostics]
        if self.config is not None:
            document["config"] = self.config
        if self.policy is not None:
            document["policy"] = self.policy
        return document


def _tool_version() -> str:
    # Imported lazily so that document.py stays importable in isolation.
    from sopuli.version import get_version

    return get_version()

"""The run document (``docs/design/03-json-output.md`` §2).

There is no such thing as a placeholder run document. ``sopuli-run-1.12.schema.json``
sets ``additionalProperties: false`` at the root and requires six top-level
fields, two of which have required members of their own, so the smallest thing
that validates is a complete document. Building it properly now is cheaper than
discovering the shape later, and it makes the schema check in CI real from the
first command (invariant 12).

Optional sections (``plan``, ``lock``, ``results``, ``diagnostics``) are omitted
entirely rather than emitted as ``null`` — the schema types them as object/array,
so a null would fail validation. For ``lock`` the omission also *means* something
(``03-json-output.md`` §2): absent says the run needed no lock, which is every
``check``, ``status`` and ``--dry-run``.
"""

from __future__ import annotations

import getpass
import socket
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Re-exported: these were defined here until a lock record needed the same
# format (#83), and `sopuli.output.emit` and the tests import them from here.
from sopuli.clock import to_rfc3339, utc_now

SCHEMA_VERSION = "1.12"
TOOL_NAME = "sopuli"  # schema pins this to the binary name (D1), not the distribution


__all__ = [
    "SCHEMA_VERSION",
    "TOOL_NAME",
    "Actor",
    "Diagnostic",
    "Error",
    "Option",
    "RunDocument",
    "Summary",
    "current_actor",
    "to_rfc3339",
    "utc_now",
]


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
class Error:
    """``error`` -- why the run as a whole failed.

    Distinct from ``results[].error``, which is one target failing inside a run
    that otherwise worked. This one is present when there is no per-target work
    to report at all: the configuration could not be read, or something went
    wrong before the first target was touched.

    ``category`` comes from the schema's closed enum, and the exception carries
    it (:attr:`sopuli.config.errors.ConfigError.category`) rather than the
    boundary guessing from the exception type.

    ``code`` arrived with the first error that has one: a configured backend
    whose client is not installed is ``SOPULI-20001`` (ADR-006, E5). It stays
    optional and omitted-when-absent, because most failures have no code and a
    ``null`` would invite a consumer to branch on a field that is empty almost
    always. ``retryable`` and ``target_capability`` are still absent for the
    original reason -- a vendor code needs a driver, and ``target_capability``
    belongs to the capability category -- and arrive with the errors that have
    them.

    ``message`` is documented as redacted (``03-json-output.md`` §4). What makes
    that true here is the same thing that makes it true everywhere: a
    :class:`~sopuli.secrets.Secret` serialises as ``***``, so an exception that
    interpolated one carries no plaintext into this field.
    """

    category: str
    message: str
    hint: str | None = None
    code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"category": self.category, "message": self.message}
        if self.code is not None:
            data["code"] = self.code
        if self.hint is not None:
            data["hint"] = self.hint
        return data


@dataclass(frozen=True)
class Option:
    """One entry in ``invocation.options`` -- an effective setting and its layer.

    ``source`` is a value from the schema's own enum, which is
    :class:`sopuli.settings.registry.Layer` serialised; ``source_detail`` is a
    **location** and never a value (``03-json-output.md``
    §``invocation.options``). There is no field for a value's origin *and* its
    content, so an entry is safe to emit whatever it describes: the location is
    named, and a credential has nowhere to sit. §3a's token chain does not appear
    here at all -- it is its own merge, resolved when a run reaches a store, and
    ``--vault-token-file`` is not a registered setting (#145).

    Kept deliberately dumb -- no import of the resolver -- so the run document
    stays a description of output rather than a second consumer of the
    precedence rules. The three-line conversion lives at the CLI boundary.
    """

    value: Any
    source: str
    source_detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        # A tuple-valued setting (`confirm_environments`) has to reach JSON as an
        # array; nothing else here needs converting.
        value = list(self.value) if isinstance(self.value, tuple) else self.value
        data: dict[str, Any] = {"value": value, "source": self.source}
        if self.source_detail is not None:
            data["source_detail"] = self.source_detail
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
    #: ``invocation.profile`` -- the active profile's name, or ``None`` (§5, #153).
    #:
    #: Reported whether or not the profile changed anything, unlike ``options``:
    #: *which* profile a scheduled run was invoked under is the first thing
    #: somebody asks when two runs over one config behaved differently, and
    #: answering it only when a key happened to differ would be answering a
    #: different question. Omitted when there is none -- the schema allows null,
    #: and a document that carries the key with no name in it says the run
    #: considered a profile and found one.
    profile: str | None = None
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
    #: The ``lock`` section, on a run that took locks (#83). Same arrangement as
    #: ``config`` and ``policy``: :mod:`sopuli.output.lock_view` owns the shape.
    #: Absent *means* something here rather than merely omitting something --
    #: no lock was needed, which is every ``check``, ``status`` and
    #: ``--dry-run``.
    lock: dict[str, Any] | None = None
    #: ``invocation.options`` -- the settings that changed behaviour, each with
    #: the layer it came from. Emitted only when there are any: on a run with no
    #: flags and no ``SOPULI_*`` variables the answer is "nothing overrode
    #: anything", and an empty object would say that once per run in a document
    #: consumers diff.
    options: dict[str, Option] = field(default_factory=dict)
    #: The ``targets`` section, emitted by ``doctor`` (#182). One entry per
    #: target, and **not** ``results[]``: that array is per (account, target)
    #: and its ``state`` vocabulary is about credential sync -- ``IN_SYNC``,
    #: ``DRIFT``, ``ACCOUNT_MISSING`` -- while ``doctor`` manages no credential
    #: and reports on the target itself. Added in 1.11 rather than widening
    #: ``result``, which would have meant making ``account`` optional and
    #: breaking every consumer that reads it unconditionally.
    #:
    #: Same arrangement as ``config`` and ``lock``:
    #: :mod:`sopuli.output.doctor_view` owns the shape, and this only decides
    #: that it is optional and omitted rather than nulled when absent.
    targets: list[dict[str, Any]] | None = None
    #: Why the run failed as a whole. Absent on success, and absent on exit 2 --
    #: which never produces a document at all (J7, ``03-json-output.md`` §6).
    error: Error | None = None

    @classmethod
    def start(
        cls,
        command: str,
        *,
        dry_run: bool = False,
        options: dict[str, Option] | None = None,
    ) -> RunDocument:
        """Open a run document. ``command`` must be a value from the schema enum."""
        return cls(
            command=command,
            correlation_id=str(uuid.uuid4()),
            started_at=utc_now(),
            actor=current_actor(),
            dry_run=dry_run,
            options=options or {},
        )

    def finish(self, exit_code: int, summary: Summary | None = None) -> RunDocument:
        """Close the run. Returns self so callers can chain into an emitter."""
        self.finished_at = utc_now()
        self.exit_code = int(exit_code)
        if summary is not None:
            self.summary = summary
        return self

    def to_dict(self) -> dict[str, Any]:
        """Render to the shape ``sopuli-run-1.12.schema.json`` describes."""
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
        if self.profile is not None:
            invocation["profile"] = self.profile
        if self.selection is not None:
            invocation["selection"] = {"select": self.selection}
        if self.options:
            invocation["options"] = {
                name: option.to_dict() for name, option in sorted(self.options.items())
            }
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
        if self.lock is not None:
            document["lock"] = self.lock
        if self.targets is not None:
            document["targets"] = self.targets
        if self.error is not None:
            document["error"] = self.error.to_dict()
        return document


def _tool_version() -> str:
    # Imported lazily so that document.py stays importable in isolation.
    from sopuli.version import get_version

    return get_version()

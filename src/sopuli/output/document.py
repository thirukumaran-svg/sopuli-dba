"""The run document (``docs/design/03-json-output.md`` §2).

There is no such thing as a placeholder run document. ``sopuli-run-1.16.schema.json``
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
from typing import Any, Literal

# Re-exported: these were defined here until a lock record needed the same
# format (#83), and `sopuli.output.emit` and the tests import them from here.
from sopuli.clock import to_rfc3339, utc_now

SCHEMA_VERSION = "1.18"
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


#: What a ``diagnostics[]`` entry can be, closed exactly as ``03-json-output.md``
#: §2 closes it and the run schema's ``diagnostic.level`` enum repeats it. Spelled
#: as a type so the three lists cannot drift: a fourth level is a schema change,
#: which is a version bump under invariant 12, and it should be impossible to
#: introduce one by writing a string.
DiagnosticLevel = Literal["info", "warning", "error"]


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

    ``level`` is a :data:`DiagnosticLevel` rather than a ``str``, so a typo is a
    type error at the call site rather than a schema-invalid document at the far
    end of a run. Nothing validates it at runtime and nothing should: the value
    is a literal at every one of these call sites, `mypy` runs on the whole
    matrix in CI, and a check here would only be reached by a mistake the type
    already made unwritable.
    """

    level: DiagnosticLevel
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
    always.

    ``target_capability`` arrived when the error that has one first reached this
    object (#287): a driver refusal used to fall into the boundary's catch-all
    and be reported as ``internal``, so
    :class:`~sopuli.driver.protocol.UnsupportedCapabilityError` never got here to
    fill it in. It is set only for ``category: "capability"``, which is the
    schema's own rule for it, and is what a consumer branches on instead of
    parsing the capability's name back out of the message. ``retryable`` is still
    absent for the original reason: nothing yet knows whether it is true.

    ``message`` is documented as redacted (``03-json-output.md`` §4). What makes
    that true here is the same thing that makes it true everywhere: a
    :class:`~sopuli.secrets.Secret` serialises as ``***``, so an exception that
    interpolated one carries no plaintext into this field.
    """

    category: str
    message: str
    hint: str | None = None
    code: str | None = None
    target_capability: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"category": self.category, "message": self.message}
        if self.code is not None:
            data["code"] = self.code
        if self.hint is not None:
            data["hint"] = self.hint
        if self.target_capability is not None:
            data["target_capability"] = self.target_capability
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
    """``summary``. The four required counters, and the optional ones a verb has.

    The optional counters are ``None``-when-absent rather than zero, because the
    schema makes them optional and zero is a claim: ``drift: 0`` from `doctor`
    would say that command looked for drift and found none, and it never looked.
    A verb that counts a thing reports it; one that does not, omits it.
    """

    total: int = 0
    ok: int = 0
    changed: int = 0
    failed: int = 0
    unchanged: int | None = None
    drift: int | None = None
    unverifiable: int | None = None
    skipped: int | None = None
    #: ``summary.by_state``: how many results carried each state, omitting the
    #: states with none. An open object in the schema, so a verb with no state
    #: vocabulary simply has nothing to put here.
    by_state: dict[str, int] | None = None

    def to_dict(self) -> dict[str, Any]:
        summary: dict[str, Any] = {
            "total": self.total,
            "ok": self.ok,
            "changed": self.changed,
            "failed": self.failed,
        }
        for name in ("unchanged", "drift", "unverifiable", "skipped"):
            value = getattr(self, name)
            if value is not None:
                summary[name] = value
        if self.by_state is not None:
            summary["by_state"] = dict(self.by_state)
        return summary


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
    #: ``invocation.selection`` -- the selectors as given, before resolution. A
    #: run over part of the estate must say so: a consumer counting 3 targets
    #: cannot otherwise tell a small estate from a filtered one, and "3 rotated"
    #: means different things in each. Absent when the whole estate was in scope.
    #:
    #: The schema has carried this object since it was written, and until #297
    #: only ``select`` was ever populated. ``applications``, ``accounts``,
    #: ``targets`` and ``groups`` now are; ``all`` and ``limit`` are still slots
    #: for flags that do not exist, and stay omitted rather than sent empty -- an
    #: empty array would claim the tool considered a selector it has not got.
    #:
    #: Built by :meth:`sopuli.config.Selection.as_json`, so what the document
    #: reports and what the run filtered on are the same object rather than two
    #: descriptions of it.
    selection: dict[str, Any] | None = None
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
    #: The ``plan`` section: what the run intended, before it did any of it
    #: (#247). :mod:`sopuli.plan` owns the shape; this only decides that it is
    #: optional and omitted rather than nulled.
    #:
    #: **Not dry-run-only.** ``03-json-output.md`` requires a real run to emit the
    #: identical structure it would have emitted under ``--dry-run``, so that a
    #: diff between the plan and ``results`` is mechanical. Absent means the
    #: command plans nothing -- ``config show``, ``doctor``, ``lock status`` --
    #: rather than that a planning command declined to say.
    plan: dict[str, Any] | None = None
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
    #: The ``results`` section: one entry per (account, target) the run acted on
    #: or concluded something about (#248). :mod:`sopuli.output.check_view` owns
    #: the shape.
    #:
    #: **Per credential, where ``targets`` is per target.** `doctor` manages no
    #: credential and reports on the database; the `creds` verbs report on a
    #: password in a database, and the ``state`` vocabulary here -- ``IN_SYNC``,
    #: ``DRIFT``, ``LOCKED`` -- is about that. #182 added ``targets`` rather than
    #: widening this for exactly that reason, and the two stay apart.
    #:
    #: Meant to be read beside ``plan``: same grain, same order, so a diff
    #: between what the run said it would do and what it did is mechanical
    #: (``03-json-output.md``).
    results: list[dict[str, Any]] | None = None
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
    #: The ``install`` section, emitted by ``doctor`` (#214). Which backends and
    #: drivers this build can serve, which the config asks for, and where the two
    #: disagree -- **on every run, not only on a mismatch** (ADR-006 E6). Its
    #: output is audit evidence as often as it is a diagnostic, and a section that
    #: appeared only when something was wrong could not be quoted as proof that
    #: nothing was.
    #:
    #: Neither per-target nor per-vault: it is a property of the machine, and no
    #: existing section is shaped like that -- so 1.13 adds one rather than
    #: repeating a machine fact once per target. Same arrangement as ``config``,
    #: ``lock`` and ``targets``: :mod:`sopuli.output.install_view` owns the shape,
    #: and this only decides that it is optional and omitted rather than nulled.
    install: dict[str, Any] | None = None
    #: The ``wallet`` section, emitted by ``doctor`` (#215). Whether this machine
    #: has an Oracle wallet the run can authenticate with, for the estates that
    #: use ``auth: external``.
    #:
    #: **Absent when nothing does**, which is the opposite of ``install``'s rule
    #: and right for the opposite reason: install shape is a fact about the
    #: machine that is always true of it, and this is a fact about a
    #: configuration option most files never use. A section warning about a
    #: missing wallet in every document that never needed one is noise.
    #: :mod:`sopuli.output.wallet_view` owns the shape.
    wallet: dict[str, Any] | None = None
    #: The ``vaults`` section, emitted by ``doctor`` (#216). Every store the
    #: configuration declares: whether it answered, whether this run's
    #: credential was accepted, and how far its clock is from this machine's.
    #:
    #: **Present on every ``doctor`` run**, which is ``install``'s rule rather
    #: than ``wallet``'s. A wallet matters only to an estate using ``auth:
    #: external``; stores matter to every estate that does anything, so an empty
    #: array is a real answer here and absence would not be.
    #:
    #: Its own section because a vault is neither a target nor an account -- the
    #: same shape #214 found for ``install``.
    #: :mod:`sopuli.output.vault_view` owns the shape.
    vaults: list[dict[str, Any]] | None = None
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
        """Render to the shape ``sopuli-run-1.16.schema.json`` describes."""
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
        if self.selection:
            invocation["selection"] = self.selection
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
        if self.plan is not None:
            document["plan"] = self.plan
        if self.lock is not None:
            document["lock"] = self.lock
        if self.results is not None:
            document["results"] = self.results
        if self.targets is not None:
            document["targets"] = self.targets
        if self.install is not None:
            document["install"] = self.install
        if self.wallet is not None:
            document["wallet"] = self.wallet
        if self.vaults is not None:
            document["vaults"] = self.vaults
        if self.error is not None:
            document["error"] = self.error.to_dict()
        return document


def _tool_version() -> str:
    # Imported lazily so that document.py stays importable in isolation.
    from sopuli.version import get_version

    return get_version()

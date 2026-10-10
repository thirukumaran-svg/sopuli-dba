"""The run document's ``targets`` section, and what ``doctor`` prints.

`doctor` is the first consumer of the driver layer, and the only one that
connects to every target and **mutates nothing**. Everything the `creds` verbs
will depend on — the client, the credential, the connection, the scope
assertion, the capability set — either works here or is reported as the reason
it does not.

**Its findings are ``targets[]`` and not ``results[]``**, which is a schema
decision rather than a stylistic one. `result` is per (account, target) and
requires an ``account`` and a ``state`` from a vocabulary that is entirely about
credential sync — ``IN_SYNC``, ``DRIFT``, ``ACCOUNT_MISSING``. `doctor` manages
no credential and touches no account, so every one of those would have been a
word that means something else. Widening `result` instead would have meant
making ``account`` optional, which breaks any consumer reading it
unconditionally; adding a section is additive, so it is a minor bump and no
existing consumer sees it.

**A target that asserts nothing gets no ``asserted`` object at all**, rather
than one reporting ``matches: true``. `01-configuration.md` §3a is explicit that
an assertion nobody makes is not a gap, and a section claiming a match would be
reporting agreement with a claim that was never made.

**Reachability is the first fact and never inferred from the others.** A target
that could not be reached has no scope, no capabilities and no assertion result
— so ``reachable`` is what a reader branches on, and everything else is absent
rather than empty. An empty capability list on an unreachable target would read
as a database that supports nothing.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.model import ExpandedTarget
from sopuli.driver.protocol import (
    ENCRYPTION_NATIVE,
    ENCRYPTION_NONE,
    UNKNOWN,
    Encryption,
    PrivilegeAudit,
    Scope,
)
from sopuli.output.document import Error
from sopuli.output.palette import Role, absent_cell
from sopuli.output.table import Cell, Column, render_table
from sopuli.preflight import assertion_holds


def build_target(
    target: ExpandedTarget,
    *,
    connected: bool,
    scope: Scope | None = None,
    error: Error | None = None,
    duration_ms: int | None = None,
    warnings: tuple[str, ...] = (),
    privileges: PrivilegeAudit | None = None,
) -> dict[str, Any]:
    """One entry in ``targets[]``.

    ``connected`` is passed rather than inferred from ``scope``, and the
    distinction is the whole point of the field. ``reachable`` means *a session
    was opened*, which is not the same as *everything after that worked*: a
    probe can fail on a connection that is perfectly fine -- a dictionary view
    the service account cannot read, or a question this build should not have
    asked (:class:`~sopuli.driver.oracle.capabilities.ProbeError`). Deriving
    ``reachable`` from ``scope is not None`` reported those as connectivity
    failures, which sends somebody to the listener over a grant.

    So there are three shapes and not two:

    * **not connected** -- no scope, and ``error`` says why;
    * **connected, not described** -- ``reachable: true``, no scope, and
      ``error`` says what failed after the session opened;
    * **connected and described** -- ``reachable: true`` and a scope.

    ``privileges`` is ``None`` unless ``--check-privileges`` asked, and the
    section is then emitted **whole**, empty arrays included. That is E6's
    argument applied to an audit: a section that appeared only when something was
    wrong could not be quoted as evidence that nothing was. Absent and empty
    therefore mean different things -- *not asked* and *asked, nothing found* --
    which is a distinction a consumer needs and a falsy check would destroy.
    """
    entry: dict[str, Any] = {"target": target.name, "reachable": connected}

    if scope is not None:
        entry["scope"] = _scope(scope, target)
        asserted = _asserted(target, scope)
        if asserted is not None:
            entry["asserted"] = asserted
    if duration_ms is not None:
        entry["duration_ms"] = duration_ms
    if error is not None:
        entry["error"] = error.to_dict()
    if warnings:
        entry["warnings"] = list(warnings)
    if privileges is not None:
        entry["privileges"] = _privileges(privileges)
    return entry


def _privileges(audit: PrivilegeAudit) -> dict[str, Any]:
    """The schema's ``privilege_report``, which is the audit minus one field.

    ``over_granted`` is deliberately not repeated here: it lives on ``scope``,
    and two copies of one finding are two things that can disagree. A consumer
    reads the findings from ``scope`` and the coverage from here.
    """
    return {
        "held": list(audit.held),
        "missing": list(audit.missing),
        "common": list(audit.common),
        "roles": list(audit.roles),
        "unaudited": list(audit.unaudited),
        "unreadable": list(audit.unreadable),
    }


def _scope(scope: Scope, target: ExpandedTarget) -> dict[str, Any]:
    """The schema's ``scope`` object, which the driver produces minus ``labels``.

    The labels are the *config's* — a driver has no idea what a target set called
    this database — so they are added here, which is the seam
    :class:`~sopuli.driver.protocol.Scope` names in its own docstring.
    """
    found: dict[str, Any] = {
        "type": scope.type,
        "container": scope.container,
        "db_unique_name": scope.db_unique_name,
        "db_version": scope.db_version,
        "open_mode": scope.open_mode,
        "read_write": scope.read_write,
        "capabilities": sorted(scope.capabilities),
        # One fact, reported twice in the schema because a consumer asks it
        # directly, and stored once on `Scope` because two copies are two things
        # that can disagree.
        "offline_verify_available": scope.supports("offline_verify"),
        "encryption": _encryption(scope.encryption),
    }
    labels = dict(target.target.labels)
    if target.target_set is not None:
        labels = {"target_set": target.target_set, **labels}
    if labels:
        found["labels"] = labels
    if scope.privilege_model is not None:
        found["privilege_model"] = scope.privilege_model
    if scope.over_granted:
        found["over_granted"] = list(scope.over_granted)
    return found


def _encryption(found: Encryption) -> dict[str, Any]:
    """The schema's ``encryption`` object. ``algorithm`` and ``hint`` only where set."""
    entry: dict[str, Any] = {"method": found.method, "protocol": found.protocol}
    if found.algorithm is not None:
        entry["algorithm"] = found.algorithm
    if found.hint is not None:
        entry["hint"] = found.hint
    return entry


def _encryption_cell(encryption: dict[str, Any] | None) -> Cell | str:
    """``none`` is coloured as bad and ``unknown`` as inconclusive; an encrypted
    connection is not coloured, like ``yes`` in the reachable column."""
    if not encryption:
        return absent_cell("")
    method = str(encryption["method"])
    if method == ENCRYPTION_NONE:
        return Cell(method, Role.BAD)
    if method == UNKNOWN:
        return Cell(method, Role.INCONCLUSIVE)
    if method == ENCRYPTION_NATIVE and encryption.get("algorithm"):
        return f"{method} {encryption['algorithm']}"
    return method


def _encryption_note(target: str, encryption: dict[str, Any] | None) -> str | None:
    """A line under the table for a connection that is not encrypted, or unknown.

    The driver's ``hint`` says what to do, in the product's own words.
    """
    if not encryption:
        return None
    if encryption["method"] == ENCRYPTION_NONE:
        headline = (
            "the connection is not encrypted, so a password the tool sets crosses it in clear"
        )
    elif encryption["method"] == UNKNOWN:
        headline = "could not tell whether the connection is encrypted"
    else:
        return None
    hint = encryption.get("hint")
    return f"  {target}: {headline}" + (f": {hint}" if hint else "")


def _asserted(target: ExpandedTarget, scope: Scope) -> dict[str, Any] | None:
    """What the file claims, and whether it held. ``None`` when it claims nothing."""
    declared = target.target.oracle
    if declared.scope is None and declared.container is None:
        return None

    # The comparison itself lives in `sopuli.preflight`, because the pre-flight
    # (UC-1 §8 step 3) needs the same answer as a *decision* and not only as a
    # field to render. Two copies of it would be two readings of what a `dsn:`
    # edit did, and the one that refuses a run is not the one anybody would
    # notice going stale.
    return {
        "scope": declared.scope,
        "container": declared.container,
        "matches": assertion_holds(
            declared_scope=declared.scope,
            declared_container=declared.container,
            scope=scope,
        ),
    }


def _reachable(reachable: bool) -> Cell | str:
    """``no`` is coloured and ``yes`` is not, which is the rule this table wants.

    Not the rule :func:`~sopuli.output.palette.state_cell` follows, and the
    difference is worth stating because both are right. A result state is one of
    eleven and has no norm, so ``IN_SYNC`` earns a colour saying *this row is
    done*. Reachability has two values and an overwhelming norm: colouring
    ``yes`` would paint the whole column on a healthy estate and make the one
    ``no`` ordinary again -- which is `config show`'s argument for painting
    ``prod`` and no other environment, one screen over.
    """
    return "yes" if reachable else Cell("no", Role.BAD)


def render(entries: list[dict[str, Any]], *, client: dict[str, Any]) -> str:
    """The text report: the client once, then a row per target.

    Two sections rather than one table, because they answer different questions
    and only the first can be answered without a network: *is this machine able
    to reach an Oracle at all*, and then *what did each target turn out to be*.
    """
    lines = ["client"]
    for key, value in client.items():
        lines.append(f"  {key:<18}{value}")
    lines.append("")

    columns = [
        Column("TARGET"),
        Column("REACHABLE"),
        Column("SCOPE"),
        Column("CONTAINER"),
        Column("OPEN MODE"),
        Column("CAPABILITIES"),
        Column("ENCRYPTION"),
    ]
    rows: list[list[Cell | str]] = []
    for entry in entries:
        scope = entry.get("scope") or {}
        rows.append(
            [
                entry["target"],
                _reachable(bool(entry["reachable"])),
                absent_cell(str(scope.get("type") or "")),
                absent_cell(str(scope.get("container") or "")),
                absent_cell(str(scope.get("open_mode") or "")),
                absent_cell(str(len(scope.get("capabilities", []))) if entry["reachable"] else ""),
                _encryption_cell(scope.get("encryption")),
            ]
        )
    lines.extend(render_table(columns, rows))

    for entry in entries:
        if entry.get("error"):
            lines.append(f"  {entry['target']}: {entry['error'].get('message', '')}")
        asserted = entry.get("asserted")
        if asserted is not None and not asserted["matches"]:
            scope = entry.get("scope") or {}
            lines.append(
                f"  {entry['target']}: declares "
                f"scope={asserted['scope']!r} container={asserted['container']!r}, "
                f"found scope={scope.get('type')!r} container={scope.get('container')!r}"
            )
        note = _encryption_note(entry["target"], (entry.get("scope") or {}).get("encryption"))
        if note is not None:
            lines.append(note)
        for warning in entry.get("warnings", ()):
            lines.append(f"  {entry['target']}: {warning}")
        missing = (entry.get("privileges") or {}).get("missing")
        if missing:
            # Before the over-grant line, because it is the one that stops the
            # tool working. An account short a grant fails at the verb that needs
            # it, several commands from here, with an error about the view rather
            # than about the install -- which is the whole reason this is
            # reported at connect time.
            lines.append(
                f"  {entry['target']}: not granted, and the tool needs it: " + ", ".join(missing)
            )
        over_granted = (entry.get("scope") or {}).get("over_granted")
        if over_granted:
            # A line rather than a column: it appears only under
            # `--check-privileges`, and a column that is empty on every ordinary
            # run is a column that teaches people to stop reading it. Named in
            # full because the remedy is a `REVOKE` and the reader needs the
            # spelling (P5: this warns and never fails).
            lines.append(
                f"  {entry['target']}: over-granted, and the tool needs none of it: "
                + ", ".join(over_granted)
            )

    return "\n".join(lines)

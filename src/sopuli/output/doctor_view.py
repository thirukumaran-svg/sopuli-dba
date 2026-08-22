"""The run document's ``targets`` section, and what ``doctor`` prints (#182).

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
unconditionally; adding a section is additive, so 1.11 is a minor bump and no
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
from sopuli.driver.protocol import Scope
from sopuli.output.document import Error
from sopuli.output.table import Column, render_table


def build_target(
    target: ExpandedTarget,
    *,
    connected: bool,
    scope: Scope | None = None,
    error: Error | None = None,
    duration_ms: int | None = None,
    warnings: tuple[str, ...] = (),
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
    return entry


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


def _asserted(target: ExpandedTarget, scope: Scope) -> dict[str, Any] | None:
    """What the file claims, and whether it held. ``None`` when it claims nothing."""
    declared = target.target.oracle
    if declared.scope is None and declared.container is None:
        return None

    matches = True
    if declared.scope is not None and declared.scope != scope.type:
        matches = False
    if declared.container is not None:
        found = (scope.container or "").upper()
        matches = matches and declared.container.upper() == found

    return {"scope": declared.scope, "container": declared.container, "matches": matches}


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
    ]
    rows = []
    for entry in entries:
        scope = entry.get("scope") or {}
        rows.append(
            [
                entry["target"],
                "yes" if entry["reachable"] else "no",
                str(scope.get("type", "-")),
                str(scope.get("container") or "-"),
                str(scope.get("open_mode") or "-"),
                str(len(scope.get("capabilities", []))) if entry["reachable"] else "-",
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
        for warning in entry.get("warnings", ()):
            lines.append(f"  {entry['target']}: {warning}")

    return "\n".join(lines)

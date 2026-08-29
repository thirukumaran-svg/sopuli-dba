"""`creds generate` as a document and as a table (#254).

The `results[]` entries for a staging run, and the text an operator reads. Same
arrangement as :mod:`sopuli.output.check_view`: the shape here, the decision in
:mod:`sopuli.generate`.

**Nothing in this module can emit a password.** It receives
:class:`~sopuli.generate.Candidate` objects whose value is a
:class:`~sopuli.secrets.Secret` and never unwraps one -- the single permitted
reveal on this path is inside
:func:`sopuli.store.credentials.apply_patch`, immediately before the call that
sends it. There is deliberately no ``--reveal`` here: `policy sample` has one
because a sample is not a credential, and this is the opposite case.

**The version is the whole result.** What an operator needs after staging is
which version to expect at `apply` time and which one it replaced, because that
pair is what a partial rotation is diagnosed from later.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sopuli.generate import Candidate, DocumentWrite
from sopuli.output.document import Error, Summary
from sopuli.output.palette import Role
from sopuli.output.table import Cell, Column, render_table
from sopuli.payload import PENDING

__all__ = ["build_result", "render_generate", "render_write_table", "summarise"]

#: The state a successfully staged account reports.
#:
#: **From the schema's own enum, not a new value.** UC-1 §3 put `PENDING_APPLY`
#: in `SyncState` for exactly this situation -- the vault holds a password the
#: database has not been given -- and inventing a `STAGED` beside it would be a
#: second name for one state and a contract change to carry it. Invariant 12
#: makes the enum a published interface; a verb that needed a new value would be
#: saying the vocabulary was wrong, which this one is not.
STAGED = "PENDING_APPLY"

#: A write that did not happen. `results[].error` carries the reason.
FAILED = "ERROR"

_ACCOUNT = 24
_SECRET = 40


def build_result(
    candidate: Candidate,
    *,
    state: str,
    stage: str,
    version: int | None = None,
    replaced: int | None = None,
    mechanism: str | None = None,
    changed: bool,
    detail: str,
    error: Error | None = None,
) -> dict[str, Any]:
    """One ``results[]`` entry for a staged account.

    ``changed`` is ``True`` on every successful write, including a second run
    over an account that already had a ``pending`` staged. That is #254's
    decision and an explicit exemption from invariant 9: a fresh draw has no
    fixed point to converge on, so "nothing changed" would be false. The
    invariant governs the convergent verbs, and `apply` is the one that will
    report ``changed: false`` on a re-run.

    **A ``--dry-run`` produces no entry at all.** It emits `plan` and stops --
    which is what invariant 8 asks for, and it avoids inventing a state for
    "would have been written". `plan` already says that, at the same grain, in
    the section built for it.
    """
    binding = candidate.binding
    entry: dict[str, Any] = {
        "account": binding.account,
        "target": binding.target,
        "state": state,
        "changed": changed,
    }
    secret = _secret(candidate, stage=stage, version=version)
    if secret is not None:
        entry["secret"] = secret
    entry["actions"] = [
        {
            # `vault_write_pending` from the schema's `action_kind` enum. The
            # stage is a parameter because `--promote` will add, and the
            # action it performs is a different one -- naming it here keeps that
            # a one-line change rather than a rediscovery.
            "kind": "vault_write_pending" if stage == PENDING else "vault_promote",
            "applied": state == STAGED,
            "detail": detail,
        }
    ]
    warnings = _warnings(candidate, replaced=replaced, mechanism=mechanism)
    if warnings:
        entry["warnings"] = warnings
    if error is not None:
        entry["error"] = error.to_dict()
    return entry


def _secret(candidate: Candidate, *, stage: str, version: int | None) -> dict[str, Any] | None:
    """Where the password went, as ``secret_ref`` -- an address and never a value."""
    binding = candidate.binding
    ref = binding.secret
    if ref is None or binding.vault is None:
        return None
    item: dict[str, Any] = {"vault": binding.vault, "path": ref.path, "stage": stage}
    if ref.field is not None:
        item["field"] = ref.field
    if ref.pointer is not None:
        item["pointer"] = ref.pointer
    if version is not None:
        item["version"] = version
    return item


def _warnings(
    candidate: Candidate, *, replaced: int | None, mechanism: str | None
) -> list[dict[str, Any]]:
    """What this run did that somebody should know about.

    Two things qualify, and both are consequences an operator did not type:

    * **a replaced ``pending``** -- the previous staged password is gone, and if
      it had been handed to anybody it is now worthless. Safe, per UC-1 §4, and
      not silent;
    * **an accepted policy violation** -- ``--no-policy-check`` let something
      through, and §4 requires the audit event to say *what*. The rule names and
      counts go in; never the characters (:class:`~sopuli.passwords.Violation`).

    The write ``mechanism`` rides here too when it was the wider one: under a
    read-modify-write the whole document left this process, which is a different
    exposure from a merge patch and UC-1 §3 asks for it to be reported.
    """
    found: list[dict[str, Any]] = []
    binding = candidate.binding
    if replaced is not None:
        found.append(
            {
                "level": "warning",
                "message": (
                    f"replaced a pending password that was already staged "
                    f"(document version {replaced}); anything holding it is now stale"
                ),
                "account": binding.account,
            }
        )
    for violation in candidate.accepted_violations:
        found.append(
            {
                "level": "warning",
                "message": (
                    f"--no-policy-check accepted a password that violates "
                    f"{violation.rule}: {violation.detail}"
                ),
                "account": binding.account,
            }
        )
    if mechanism == "read_modify_write":
        found.append(
            {
                "level": "info",
                "message": (
                    "written by read-modify-write rather than a merge patch, so the "
                    "whole document was sent; the store or its policy has no patch"
                ),
                "account": binding.account,
            }
        )
    return found


def summarise(states: Sequence[str]) -> Summary:
    """The counters a staging run carries.

    ``ok`` and ``changed`` are the same number here and that is not redundancy:
    they answer different questions everywhere else, and a verb whose every
    success is a mutation is exactly where they coincide. ``unchanged`` is what
    did *not* get written, which under #254's decision is only ever failures.
    """
    staged = sum(1 for state in states if state == STAGED)
    failed = sum(1 for state in states if state == FAILED)
    return Summary(
        total=len(states),
        ok=staged,
        changed=staged,
        failed=failed,
        unchanged=len(states) - staged,
        by_state=dict(sorted({state: states.count(state) for state in set(states)}.items())),
    )


def render_write_table(writes: Sequence[DocumentWrite], *, stage: str) -> list[str]:
    """What is about to be written, grouped the way it will actually be written.

    One row per document rather than per account, because the document is the
    unit of the write, the compare-and-set and the lock -- and an operator about
    to authorise a mutation should see the three accounts that share one write as
    one line, not as three that look independent.
    """
    return list(
        render_table(
            [
                Column("SECRET", _SECRET),
                Column("STAGE"),
                Column("ACCOUNTS"),
            ],
            [[str(write.key), stage, ", ".join(write.accounts)] for write in writes],
        )
    )


def render_generate(rows: Sequence[tuple[Candidate, str, str]]) -> str:
    """The result table, and the closing line.

    ``rows`` is (candidate, state, detail). The password is not among them and
    there is no column for one.
    """
    table = render_table(
        [
            Column("ACCOUNT", _ACCOUNT),
            Column("SECRET", _SECRET),
            Column("RESULT"),
        ],
        [
            [
                candidate.binding.account,
                _address(candidate),
                _result(state, detail),
            ]
            for candidate, state, detail in rows
        ],
    )
    return "\n".join([*table, "", _verdict([state for _, state, _ in rows])])


def _address(candidate: Candidate) -> Cell | str:
    binding = candidate.binding
    if binding.secret is None or binding.vault is None:
        return Cell("-", Role.MUTED)
    return f"{binding.vault}:{binding.secret.path}"


def _result(state: str, detail: str) -> Cell | str:
    if state == FAILED:
        return Cell(detail, Role.NOTABLE)
    return detail


def _verdict(states: Sequence[str]) -> str:
    staged = sum(1 for state in states if state == STAGED)
    failed = sum(1 for state in states if state == FAILED)
    parts = [f"{staged} staged"]
    if failed:
        parts.append(f"{failed} failed")
    line = ", ".join(parts)
    if staged and not failed:
        # The sentence that matters after a successful stage: the database has
        # not changed, and nothing is using this password yet.
        return f"{line}; no database was touched -- run `sopuli creds apply` to use them"
    return line

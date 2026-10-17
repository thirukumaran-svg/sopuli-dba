"""`creds generate` as a document and as a table.

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

from collections.abc import Mapping, Sequence
from typing import Any

from sopuli.diagnostics import CURRENT_REPLACED, PENDING_REPLACED, POLICY_VIOLATION_ACCEPTED
from sopuli.generate import VAULT_ONLY, Candidate, DocumentWrite, password_key
from sopuli.lock.keys import LockKey
from sopuli.output.document import Error, Summary
from sopuli.output.palette import Role
from sopuli.output.table import Cell, Column, render_table
from sopuli.payload import PENDING

__all__ = [
    "VAULT_ONLY",
    "WRITTEN",
    "build_result",
    "render_generate",
    "render_promotion_table",
    "render_write_table",
    "summarise",
]

#: The state a successfully staged account reports.
#:
#: **From the schema's own enum, not a new value.** UC-1 §3 put `PENDING_APPLY`
#: in `SyncState` for exactly this situation -- the vault holds a password the
#: database has not been given -- and inventing a `STAGED` beside it would be a
#: second name for one state and a contract change to carry it. Invariant 12
#: makes the enum a published interface; a verb that needed a new value would be
#: saying the vocabulary was wrong, which this one is not.
STAGED = "PENDING_APPLY"

#: ``VAULT_ONLY`` is declared in :mod:`sopuli.generate` and re-exported here,
#: imported above: every other state in the schema's enum is declared in a
#: domain module, and the palette cannot import a view. Kept in this module's
#: namespace because `cli` and the tests import it from here.

#: A write that did not happen. `results[].error` carries the reason.
FAILED = "ERROR"

#: The states a write actually happened in. `changed` is true of both, and both
#: sit outside invariant 9 for the same reason -- a fresh draw has no fixed point
#: to converge on, whichever stage it lands in (decision #254, and H7 for the
#: rule).
WRITTEN = (STAGED, VAULT_ONLY)

_ACCOUNT = 24
_SECRET = 40


def build_result(
    candidate: Candidate,
    *,
    state: str,
    stage: str,
    version: int | None = None,
    replaced: int | None = None,
    overwritten: bool = False,
    mechanism: str | None = None,
    changed: bool,
    detail: str,
    error: Error | None = None,
) -> dict[str, Any]:
    """One ``results[]`` entry for a staged account.

    ``changed`` is ``True`` on every successful write, including a second run
    over an account that already had a ``pending`` staged. The verb is outside
    invariant 9 rather than excused from it (decision #254, and the scope rule
    of H7): a fresh draw has no fixed point to converge on, and "nothing
    changed" would simply be false. The invariant governs the convergent verbs,
    and `apply` is the one that will report ``changed: false`` on a re-run.

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
            # `vault_write_pending` and `vault_promote`, both from the schema's
            # `action_kind` enum. The stage is a parameter, so one line serves
            # the staging run and `--promote`.
            "kind": "vault_write_pending" if stage == PENDING else "vault_promote",
            # Either write is an action that happened. Testing `== STAGED` would
            # have reported every promotion as an action that did not apply.
            "applied": state in WRITTEN,
            "detail": detail,
        }
    ]
    warnings = _warnings(candidate, replaced=replaced, overwritten=overwritten, mechanism=mechanism)
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
    candidate: Candidate, *, replaced: int | None, overwritten: bool, mechanism: str | None
) -> list[dict[str, Any]]:
    """What this run did that somebody should know about.

    Three things qualify, and each is a consequence an operator did not type:

    * **a replaced ``pending``** -- the previous staged password is gone, and if
      it had been handed to anybody it is now worthless. Authorised by
      `--overwrite-pending` (UC-1 §4), on a staging run or a `--promote`, and
      not silent;
    * **a replaced ``current``** -- `--promote` wrote over the field applications
      read (decision #257). Authorised, since `--overwrite-current` is what let
      it happen, and reported anyway: what the vault now advertises is a
      password no database has been given, and the run that did it is the last
      place anybody will look for that fact. It is a **warning** and not an
      error for the same reason the flag exists -- the operator asked for
      exactly this;
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
                "code": PENDING_REPLACED,
                "message": (
                    f"replaced a pending password that was already staged "
                    f"(document version {replaced}); anything holding it is now stale"
                ),
                "account": binding.account,
            }
        )
    if overwritten:
        found.append(
            {
                "level": "warning",
                "code": CURRENT_REPLACED,
                "message": (
                    "replaced the `current` password; the vault now advertises one no "
                    "database has been given -- run `sopuli creds apply` to converge them"
                ),
                "account": binding.account,
            }
        )
    for violation in candidate.accepted_violations:
        found.append(
            {
                "level": "warning",
                "code": POLICY_VIOLATION_ACCEPTED,
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
    did *not* get written, which under decision #254 is only ever failures.
    """
    staged = sum(1 for state in states if state in WRITTEN)
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


def render_promotion_table(
    writes: Sequence[DocumentWrite], held: Mapping[LockKey, Sequence[str]]
) -> list[str]:
    """What `--promote` is about to write, split by what it would replace.

    Two columns rather than one, because seeding an account that has no `current`
    and replacing one that has are different risks (decision #257) and the
    operator is the one who has to weigh them. A single ACCOUNTS column would
    make the run look uniform and leave the count of destructive writes to be
    worked out from a refusal message.

    One row per document, as :func:`render_write_table` has: the document is the
    unit of the write, the compare-and-set and the lock.

    ``held`` is what the plan-time read found. Under ``--overwrite-current`` the
    REPLACED column is the authorisation being spent; without it, on a
    ``--dry-run``, it is the list of accounts the run would refuse over -- and
    the same table answers both, which is why a preview is never gated.
    """
    rows = []
    for write in writes:
        replacing = set(held.get(write.key, ()))
        seeded = [account for account in write.accounts if account not in replacing]
        replaced = [account for account in write.accounts if account in replacing]
        rows.append(
            [
                str(write.key),
                ", ".join(seeded) or Cell("-", Role.MUTED),
                Cell(", ".join(replaced), Role.NOTABLE) if replaced else Cell("-", Role.MUTED),
            ]
        )
    return list(
        render_table(
            # Neither account column is capped: both hold a list, and a run that
            # truncated one would hide exactly the account somebody is looking
            # for -- the REPLACED column especially, which is the destructive
            # half. `render_write_table` leaves its ACCOUNTS column uncapped for
            # the same reason.
            [Column("SECRET", _SECRET), Column("SEEDED"), Column("REPLACED")],
            rows,
        )
    )


def render_generate(rows: Sequence[tuple[Candidate, str, str]]) -> str:
    """The result table, and the closing line.

    ``rows`` is (candidate, state, detail), one per binding. The password is not
    among them and there is no column for one.

    **One table row per password, not per binding.** An account on several
    targets that share its ref has one password and one row, and the row's
    result names the targets. The closing line counts passwords, so one shared
    password is "1 staged", as `creds check` counts it as one secret.
    `results[]` keeps one entry per binding (`03-json-output.md`).
    """
    grouped: dict[object, tuple[Candidate, str, str, list[str]]] = {}
    for candidate, state, detail in rows:
        key = password_key(candidate.binding) or id(candidate)
        found = grouped.setdefault(key, (candidate, state, detail, []))
        found[3].append(candidate.binding.target)
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
                _result(state, _for_targets(detail, targets)),
            ]
            for candidate, state, detail, targets in grouped.values()
        ],
    )
    states = [state for _, state, _, _ in grouped.values()]
    return "\n".join([*table, "", _verdict(states)])


def _for_targets(detail: str, targets: Sequence[str]) -> str:
    """``detail``, naming the targets where one password serves more than one."""
    if len(targets) < 2:
        return detail
    return f"{detail}, for {', '.join(targets)}"


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
    promoted = sum(1 for state in states if state == VAULT_ONLY)
    failed = sum(1 for state in states if state == FAILED)
    parts = [f"{staged} staged"] if staged else []
    if promoted:
        # "promoted" rather than "staged", because the two leave the document in
        # different states and the sentence below is the same advice for both:
        # `apply` is what makes a database match either of them.
        parts.append(f"{promoted} promoted to current")
    if failed:
        parts.append(f"{failed} failed")
    line = ", ".join(parts) or "nothing written"
    if (staged or promoted) and not failed:
        # The sentence that matters after a successful stage: the database has
        # not changed, and nothing is using this password yet.
        #
        # "changed" rather than "touched". A target may well have been *read*
        # -- step 2 asks each one how long a password may be -- so a line
        # claiming nothing was touched would be false. The reassurance a reader
        # wants here is about writes, and that one is true.
        return f"{line}; no database was changed -- run `sopuli creds apply` to use them"
    return line

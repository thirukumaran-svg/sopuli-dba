"""`creds apply` as a document and as a table (#259).

Same arrangement as :mod:`sopuli.output.check_view` and
:mod:`sopuli.output.generate_view`: the shape here, the decision in
:mod:`sopuli.apply`.

**Two things are reported that `check` has no counterpart for**, and both are
consequences of `apply` being the verb that commits:

* ``actions[]`` carries up to three entries per account -- the verification
  before, the ``password_set``, and the verification after -- because UC-1 §5's
  flow is a sequence and an operator diagnosing a partial rotation needs to know
  which step of it stopped. A single entry would make "we did not need to change
  it" and "we changed it and could not confirm it" the same row.
* a promotion is reported on **every account in the document it promoted**, with
  the version it produced. That version is what a later `check` or a resumed
  rotation is diagnosed from, and one account's row is not the place to hide it.

**Nothing here can emit a password.** Values reach this module as
:class:`~sopuli.secrets.Secret` inside a :class:`~sopuli.apply.Source` and are
never unwrapped; the one permitted reveal on this path is inside
:func:`sopuli.store.credentials.apply_patch`, immediately before the call that
sends it.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sopuli.apply import CONFIRMED, Source, counts, is_confirmed, is_failure, is_inconclusive
from sopuli.check import ACCOUNT_MISSING, ERROR, ROLLOVER_ACTIVE, Outcome
from sopuli.config.model import Binding
from sopuli.driver.protocol import FAIL, PASS, VerifyResult
from sopuli.output.document import Error, Summary
from sopuli.output.palette import Role, paint
from sopuli.output.table import Cell, Column, render_table
from sopuli.payload import CURRENT

__all__ = ["build_result", "render_apply", "render_source_table", "summarise"]

_ACCOUNT = 24
_TARGET = 28
_STATE = 16
_SECRET = 40


def build_result(
    binding: Binding,
    outcome: Outcome,
    *,
    source: Source | None = None,
    version: int | None = None,
    changed: bool,
    verified_before: VerifyResult | None = None,
    promoted_to: int | None = None,
    mechanism: str | None = None,
    duration_ms: int | None = None,
    error: Error | None = None,
) -> dict[str, Any]:
    """One ``results[]`` entry for an account this run acted on.

    ``changed`` is *did this run issue the DDL*, and it is passed in rather than
    derived from the state: ``IN_SYNC`` is reached both by changing the password
    and by finding it already correct, and those are the two answers invariant 9
    exists to keep apart. `apply` is the convergent verb, so the second run of a
    successful rotation reports ``IN_SYNC`` with ``changed: false``.

    ``promoted_to`` is the document version the promotion produced, and it is
    written on **every** account in that document -- they shared one
    compare-and-set, so they share its version. ``None`` where nothing was
    promoted, which is both a run that read ``current`` and a run whose targets
    did not all confirm; the two are distinguished by the state and the detail,
    not by this field.
    """
    entry: dict[str, Any] = {
        "account": binding.account,
        "target": binding.target,
        "state": outcome.state,
        "changed": changed,
    }
    secret = _secret(binding, source=source, version=version, promoted_to=promoted_to)
    if secret is not None:
        entry["secret"] = secret
    entry["actions"] = _actions(
        outcome,
        changed=changed,
        verified_before=verified_before,
        promoted_to=promoted_to,
    )
    if outcome.verification is not None:
        entry["verification"] = _verification(outcome.verification)
    if outcome.state == ROLLOVER_ACTIVE:
        entry["rollover"] = {"active": True}
    if duration_ms is not None:
        entry["duration_ms"] = duration_ms
    if error is not None:
        entry["error"] = error.to_dict()
    warnings = _warnings(binding, outcome, changed=changed, mechanism=mechanism)
    if warnings:
        entry["warnings"] = warnings
    return entry


def _actions(
    outcome: Outcome,
    *,
    changed: bool,
    verified_before: VerifyResult | None,
    promoted_to: int | None,
) -> list[dict[str, Any]]:
    """UC-1 §5's flow, as the steps that actually ran.

    In the order they happened, which is the order somebody reads them in when a
    rotation stopped halfway. ``applied`` is whether the step *ran*, never
    whether it succeeded -- the same rule `check` states about a login the
    lockout guard declined, and the reason a `verify` with ``applied: false`` is
    a meaningful row rather than a contradiction.
    """
    actions: list[dict[str, Any]] = []
    if verified_before is None and not changed:
        # Nothing ran: a locked account, a missing one, an empty vault, a target
        # that could not be reached. `none` is in the schema's `action_kind` enum
        # for exactly this, and it is the honest entry -- a `password_set` with
        # `applied: false` would say the run got as far as considering the
        # statement, and it did not.
        return [{"kind": "none", "applied": False, "detail": outcome.detail}]
    if verified_before is not None:
        actions.append(
            {
                "kind": "verify",
                "applied": _attempted(verified_before),
                "detail": "checked whether the database already has this password",
            }
        )
    actions.append(
        {
            "kind": "password_set",
            "applied": changed,
            "detail": outcome.detail,
        }
    )
    if outcome.verification is not None and outcome.verification is not verified_before:
        actions.append(
            {
                "kind": "verify",
                "applied": _attempted(outcome.verification),
                "detail": outcome.detail,
            }
        )
    if promoted_to is not None:
        actions.append(
            {
                "kind": "vault_promote",
                "applied": True,
                "detail": f"promoted `pending` to `current` in v{promoted_to}",
            }
        )
    return actions


def _attempted(result: VerifyResult | None) -> bool:
    """Whether a login was actually made. `check_view`'s rule, unchanged."""
    if result is None:
        return False
    return result.result in (PASS, FAIL)


def _secret(
    binding: Binding, *, source: Source | None, version: int | None, promoted_to: int | None
) -> dict[str, Any] | None:
    """Where the password came from, as ``secret_ref`` -- an address, never a value.

    ``stage`` is the stage this run **read**, which is the question an operator
    has after a partial rotation: a row saying ``pending`` is one whose password
    is not yet what applications fetch. After a promotion the same account's row
    carries the version the promote produced, so the pair reads as "was staged,
    now current at v9".
    """
    ref = binding.secret
    if ref is None or binding.vault is None:
        return None
    item: dict[str, Any] = {"vault": binding.vault, "path": ref.path}
    if ref.field is not None:
        item["field"] = ref.field
    if ref.pointer is not None:
        item["pointer"] = ref.pointer
    if promoted_to is not None:
        item["version"] = promoted_to
    elif version is not None:
        item["version"] = version
    if source is not None:
        item["stage"] = CURRENT if promoted_to is not None else source.stage
    return item


def _verification(result: VerifyResult) -> dict[str, Any]:
    """The ``verification`` object, as `check` emits it.

    The **post-change** attempt, where there was one: it is the one UC-1 §5 step
    6 requires and the one a promotion was gated on. The pre-flight attempt is in
    ``actions[]`` and deliberately not here -- the schema has one verification
    per result, and the one worth keeping is the one that decided something.
    """
    return {
        "method": result.method,
        "result": result.result,
        "latency_ms": result.latency_ms,
        "lcount": result.failed_logins,
        "failed_login_attempts_limit": result.failed_login_limit,
        "lockout_margin_hit": result.lockout_margin_hit,
        "previous_password_accepted": None,
    }


def _warnings(
    binding: Binding, outcome: Outcome, *, changed: bool, mechanism: str | None
) -> list[dict[str, Any]]:
    """What this run did that somebody should know about.

    The one that matters is a **changed database whose vault was not promoted**:
    UC-1 §8 calls it the highest-severity row in its table, because applications
    fetch ``current`` and are now fetching a password the database no longer has.
    It is a warning on the account rather than a run-level diagnostic so that it
    survives into whatever a consumer filters `results[]` down to.

    The write ``mechanism`` rides here too when it was the wider one, which is
    the reporting UC-1 §3 requires: under a read-modify-write the whole document
    left this process.
    """
    found: list[dict[str, Any]] = []
    if changed and outcome.state not in CONFIRMED:
        found.append(
            {
                "level": "warning",
                "message": (
                    "the database was changed and the vault was not promoted, so "
                    "`current` still holds the old password -- re-run `sopuli creds apply` "
                    "once this target is well"
                ),
                "account": binding.account,
                "target": binding.target,
            }
        )
    if mechanism == "read_modify_write":
        found.append(
            {
                "level": "info",
                "message": (
                    "the promotion was written by read-modify-write rather than a merge "
                    "patch, so the whole document was sent; the store or its policy has "
                    "no patch"
                ),
                "account": binding.account,
                "target": binding.target,
            }
        )
    return found


def summarise(states: Sequence[str], *, changed: int) -> Summary:
    """The counters an apply run carries.

    ``ok`` and ``changed`` come apart here, which is the whole point of having
    both: a converged estate is ``ok`` whether this run converged it or found it
    that way. ``unchanged`` is the complement of ``changed`` rather than of
    ``ok`` -- it answers *how much did this run leave alone*, which is what a
    second run of a successful rotation should report as everything.

    ``ok`` counts :data:`~sopuli.apply.CONFIRMED`, so an open rollover window is
    counted as well. That differs from `check`, deliberately: there, the window
    is a caveat on a survey, and here it is a target that accepted the password
    and can be promoted on.
    """
    return Summary(
        total=len(states),
        ok=sum(1 for state in states if is_confirmed(state)),
        changed=changed,
        failed=sum(1 for state in states if is_failure(state)),
        unchanged=len(states) - changed,
        unverifiable=sum(1 for state in states if is_inconclusive(state)),
        by_state=counts(states),
    )


def render_source_table(rows: Sequence[tuple[Binding, Source]]) -> list[str]:
    """What is about to be applied, and from which stage.

    Printed before anything is issued, and under ``--dry-run`` it is the whole
    output beside the plan. The stage column is the one that carries the
    information: a ``pending`` row is a rotation about to be completed, and a
    ``current`` row is a repair -- the same command, and two very different
    things to be authorising.
    """
    return list(
        render_table(
            [
                Column("ACCOUNT", _ACCOUNT),
                Column("TARGET", _TARGET),
                Column("SECRET", _SECRET),
                Column("SOURCE"),
            ],
            [
                [binding.account, binding.target, _address(binding), source.stage]
                for binding, source in rows
            ],
        )
    )


def render_apply(rows: Sequence[tuple[Binding, Outcome, bool]], *, promoted: int = 0) -> str:
    """The result table and the closing line. ``rows`` is (binding, outcome, changed)."""
    table = render_table(
        [
            Column("ACCOUNT", _ACCOUNT),
            Column("TARGET", _TARGET),
            Column("STATE", _STATE),
            Column("DETAIL"),
        ],
        [
            [binding.account, binding.target, _state(outcome.state), outcome.detail]
            for binding, outcome, _ in rows
        ],
    )
    return "\n".join(
        [
            *table,
            "",
            _verdict(
                [outcome.state for _, outcome, _ in rows],
                changed=sum(1 for _, _, changed in rows if changed),
                promoted=promoted,
            ),
        ]
    )


def _address(binding: Binding) -> Cell | str:
    if binding.secret is None or binding.vault is None:
        return Cell("-", Role.MUTED)
    return f"{binding.vault}:{binding.secret.path}"


def _state(state: str) -> Cell | str:
    """The state cell, with the two that need acting on picked out.

    ``ERROR`` is the run that did not work and ``ACCOUNT_MISSING`` is the estate
    disagreeing with the file. `check` paints only ``DRIFT``, which this command
    never reports: by the time a row is written the drift has either been fixed
    or has become one of these.
    """
    return Cell(state, Role.NOTABLE) if state in (ERROR, ACCOUNT_MISSING) else state


def _verdict(states: Sequence[str], *, changed: int, promoted: int) -> str:
    """The closing line: what happened, then what still needs attention.

    Says the two halves separately because they fail separately. "3 changed" and
    "2 documents promoted" are the database and the vault, and the whole design
    of UC-1 §3 is that the second only follows the first once every target has
    confirmed -- so a line reporting changes with no promotion is exactly the
    state an operator has to notice.
    """
    parts = [f"{changed} changed"] if changed else ["nothing changed"]
    if promoted:
        parts.append(f"{promoted} promoted to `current`")
    unconfirmed = sum(1 for state in states if state not in CONFIRMED)
    if not unconfirmed:
        line = ", ".join(parts)
        if changed and not promoted:
            return line
        return paint(line, Role.HEADING)
    parts.append(f"{unconfirmed} not confirmed")
    return ", ".join(parts)

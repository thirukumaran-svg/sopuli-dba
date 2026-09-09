"""`creds check` as a document and as a table (#248).

The `results[]` array and the text UC-1 §7 shows. Same arrangement as
:mod:`sopuli.output.doctor_view`: the shape lives here, the decision lives in
:mod:`sopuli.check`, and :class:`~sopuli.output.document.RunDocument` only knows
the section is optional.

**`results[]` is per (account, target), and `targets[]` is not.** `doctor` reports
on a target and manages no credential; this reports on a credential in a target.
The two arrays coexist for that reason and #182 added the second rather than
widening the first.

**The detail column is the point of the text view.** A state on its own is a word
an operator has to interpret -- `UNVERIFIABLE` says nothing about whether to act
-- and §7's worked output puts the reason beside every row for that reason. It is
the same sentence the JSON carries in ``actions[].detail``, so the two views
cannot drift.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sopuli.check import DRIFT, IN_SYNC, Outcome, counts, is_failure, is_inconclusive
from sopuli.config.model import Binding
from sopuli.driver.protocol import FAIL, PASS, VerifyResult
from sopuli.output.document import Diagnostic, Error, Summary
from sopuli.output.notices import render_notices
from sopuli.output.palette import Role, paint, state_cell
from sopuli.output.table import Cell, Column, render_table

__all__ = ["build_result", "render_check", "summarise"]

#: Column caps, matching the widths the estate is already printed at elsewhere.
_ACCOUNT = 24
_TARGET = 28
_STATE = 16


def build_result(
    binding: Binding,
    outcome: Outcome,
    *,
    version: int | None = None,
    stage: str | None = None,
    age_days: float | None = None,
    duration_ms: int | None = None,
    previous_accepted: bool | None = None,
    error: Error | None = None,
    warnings: Sequence[tuple[str, str]] = (),
) -> dict[str, Any]:
    """One ``results[]`` entry.

    ``changed`` is always ``False`` and is required by the schema anyway, which
    is worth saying rather than hiding: `check` is a read-only verb, and
    ``changed`` answers *did this run do anything* rather than *is anything
    wrong*. A consumer diffing the two arrays gets a run of ``false`` from this
    command by construction, and that is invariant 9's shape rather than an
    omission.

    ``warnings`` is ``(code, message)`` pairs rather than bare strings, because a
    warning without a code is one a consumer has to grep for (``03-json-output.md``
    §3). It carries findings that sit *beside* the state rather than replacing it
    -- the grace period is the first (#309), and the shape is deliberately general
    because it will not be the last.
    """
    entry: dict[str, Any] = {
        "account": binding.account,
        "target": binding.target,
        "state": outcome.state,
        "changed": False,
    }
    secret = _secret(binding, version=version, stage=stage)
    if secret is not None:
        entry["secret"] = secret
    entry["actions"] = [
        {
            "kind": "verify",
            # `applied` is whether the login actually happened, not whether it
            # passed. A rejected password is an action that happened; a login
            # the lockout guard declined is one that did not, and neither is a
            # `VerifyResult` being present -- a decline produces one too, saying
            # so. Reading "the object exists" as "we tried" collapses exactly
            # the distinction UC-1 §7's mitigation 1 exists to make visible.
            "applied": _attempted(outcome.verification),
            "detail": outcome.detail,
        }
    ]
    if outcome.verification is not None:
        entry["verification"] = _verification(
            outcome.verification, previous_accepted=previous_accepted
        )
    if age_days is not None:
        entry["password_age_days"] = age_days
    if duration_ms is not None:
        entry["duration_ms"] = duration_ms
    if error is not None:
        entry["error"] = error.to_dict()
    if warnings:
        # Built through `Diagnostic` rather than by hand, so a `results[].warnings[]`
        # entry and a top-level `diagnostics[]` one cannot drift into two shapes of
        # the same object -- and so the code travels with the message. A consumer
        # branches on `SOPULI-W013`; the prose carries a date and is not a key.
        entry["warnings"] = [
            Diagnostic(level="warning", code=code, message=text, target=binding.target).to_dict()
            for code, text in warnings
        ]
    return entry


def _attempted(result: VerifyResult | None) -> bool:
    """Whether a login was actually made.

    ``SKIPPED`` is the guard declining and ``UNAVAILABLE`` is the method not
    existing here; both carry a result object and neither spent an attempt. Only
    ``PASS`` and ``FAIL`` are answers the database gave.
    """
    if result is None:
        return False
    return result.result in (PASS, FAIL)


def _secret(binding: Binding, *, version: int | None, stage: str | None) -> dict[str, Any] | None:
    """The document this credential was read from, as ``secret_ref``.

    Carries the version the store actually served, which is the one thing this
    knows that `plan.units[].secret` deliberately cannot: a plan is a function of
    the config, and an observed version is a fact about the store at a moment.
    That is the whole reason both sections exist.

    ``None`` when the binding has no ref, or no store even after
    :func:`sopuli.config.binding_stores.complete` -- the schema requires ``vault``
    as a string, so there is no shape for half an address.
    """
    ref = binding.secret
    if ref is None or binding.vault is None:
        return None
    item: dict[str, Any] = {"vault": binding.vault, "path": ref.path}
    if ref.field is not None:
        item["field"] = ref.field
    if ref.pointer is not None:
        item["pointer"] = ref.pointer
    if version is not None:
        item["version"] = version
    if stage is not None:
        item["stage"] = stage
    return item


def _verification(result: VerifyResult, *, previous_accepted: bool | None = None) -> dict[str, Any]:
    """The ``verification`` object.

    ``lcount`` and ``failed_login_attempts_limit`` are emitted as ``null`` rather
    than omitted when the grant is absent, because null here is a real answer:
    #86 made ``SELECT ON SYS.USER$`` optional, so "the guard was unavailable" is
    a thing a scheduled check must be able to report. Omitting the keys would
    make an ungranted estate indistinguishable from one where nothing looked.
    """
    return {
        "method": result.method,
        "result": result.result,
        "latency_ms": result.latency_ms,
        "lcount": result.failed_logins,
        "failed_login_attempts_limit": result.failed_login_limit,
        "lockout_margin_hit": result.lockout_margin_hit,
        # Populated only with `--include-previous`, per the schema. Null covers
        # both "we did not ask" and "there was no previous password to ask
        # about" -- the second is the ordinary state of a credential that has
        # never been rotated, and neither is a `false`.
        "previous_password_accepted": previous_accepted,
    }


def summarise(states: Sequence[str]) -> Summary:
    """The whole ``summary`` object, in the vocabulary UC-1 §7's last line uses.

    Returns the object rather than a mapping to splat into it: `Summary` is
    frozen, and building it here means the optional counters this command has --
    and the ones it deliberately does not -- are decided in one place.

    ``ok`` is ``IN_SYNC`` and ``ROLLOVER_ACTIVE`` is **not** counted in it. The
    window is a healthy state and an operator should still know it is open --
    folding it into `ok` would make "4 ok" mean two different situations, one of
    which has a deadline attached.

    ``changed`` is zero and ``unchanged`` is everything, which is invariant 9's
    shape for a read-only verb rather than an oversight: nothing here mutates, so
    a second run reports exactly what the first did.

    ``failed`` counts `ERROR` and nothing else -- the same condition
    :func:`sopuli.check.exit_code_for` turns into exit 1, so the counter and the
    exit code in one document cannot disagree. It is deliberately not folded into
    ``unverifiable``: a target that could not be reached needs the *tool* looked
    at, and a locked account needs the estate looked at.
    """
    return Summary(
        total=len(states),
        ok=sum(1 for state in states if state == IN_SYNC),
        changed=0,
        failed=sum(1 for state in states if is_failure(state)),
        unchanged=len(states),
        drift=sum(1 for state in states if state == DRIFT),
        unverifiable=sum(1 for state in states if is_inconclusive(state)),
        by_state=counts(states),
    )


def render_check(rows: Sequence[tuple[Binding, Outcome]], *, notices: Sequence[str] = ()) -> str:
    """The table, and the one-line verdict UC-1 §7 ends with.

    The verdict counts only what is worth acting on. A run where everything is
    in sync says so in one line rather than repeating the table's own arithmetic
    -- and a run with findings names them in the order somebody would deal with
    them: drift first, because it is the thing that is actually wrong.

    ``notices`` are the row-level findings that do not fit in a column -- a grace
    period and the date it ends (#309). They go **under the verdict** rather than
    into ``DETAIL``, because a sentence carrying a timestamp would push the
    column past a terminal and because the verdict is the line somebody reads
    first. Below it, they are what they read next.
    """
    table = render_table(
        [
            Column("ACCOUNT", _ACCOUNT),
            Column("TARGET", _TARGET),
            Column("STATE", _STATE),
            Column("DETAIL"),
        ],
        [
            [binding.account, binding.target, _state(outcome.state), outcome.detail]
            for binding, outcome in rows
        ],
    )
    return "\n".join(
        [
            *table,
            "",
            _verdict([outcome.state for _, outcome in rows]),
            *render_notices(notices),
        ]
    )


def _state(state: str) -> Cell | str:
    """The state cell, coloured by :func:`~sopuli.output.palette.role_for_state`.

    This used to paint ``DRIFT`` alone, on the argument that colouring the
    inconclusive states too would make four of the eight shout at once. That
    argument is answered rather than overruled (#395): they are **dim**, not
    coloured, so a row nothing could be concluded about recedes instead of
    competing. Nothing shouts that did not shout before, and ``IN_SYNC`` --
    which is most rows on a healthy estate -- is now visibly not one of them.

    The word is on the line either way, so `NO_COLOR` still loses nothing.
    """
    return state_cell(state)


def _verdict(states: Sequence[str]) -> str:
    """The closing line, naming findings in the order somebody deals with them.

    Drift first, because it is the thing that is actually wrong. `failed` last
    and separate from `unverifiable`, because it is the count that says *this run
    did not finish looking* -- an operator who reads "2 unverifiable" and does
    not notice one of them was an unreachable database has been told the estate
    is odd when the answer is that the survey is incomplete.
    """
    drift = sum(1 for state in states if state == DRIFT)
    unverifiable = sum(1 for state in states if is_inconclusive(state))
    failed = sum(1 for state in states if is_failure(state))
    if not drift and not unverifiable and not failed:
        return paint(f"all {len(states)} in sync", Role.HEADING)
    findings = []
    if drift:
        findings.append(f"{drift} drift")
    if unverifiable:
        findings.append(f"{unverifiable} unverifiable")
    if failed:
        findings.append(f"{failed} failed")
    return ", ".join(findings)

"""`creds apply` as a document and as a table.

Same arrangement as :mod:`sopuli.output.check_view` and
:mod:`sopuli.output.generate_view`: the shape here, the decision in
:mod:`sopuli.apply`.

**Two things are reported that `check` has no counterpart for**, and both are
consequences of `apply` being the verb that commits:

* ``actions[]`` carries one entry per step that ran -- any §5 attribute the
  policy declared, the verification before, the ``password_set``, and the
  verification after -- because UC-1 §5's flow is a sequence and an operator
  diagnosing a partial rotation needs to know which step of it stopped. A single
  entry would make "we did not need to change it" and "we changed it and could
  not confirm it" the same row, and §5 asks for each attribute to be *reported as
  a separate change so the diff stays readable*.
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
from sopuli.check import ROLLOVER_ACTIVE, Outcome
from sopuli.config.model import Binding
from sopuli.diagnostics import CHANGED_NOT_PROMOTED, PROMOTION_SKIPPED, PROMOTION_WITHHELD
from sopuli.driver.guardrails import Refusal
from sopuli.driver.protocol import FAIL, PASS, AttributeChange, VerifyResult
from sopuli.output.document import Error, Summary
from sopuli.output.palette import Role, paint, state_cell
from sopuli.output.table import Cell, Column, render_table
from sopuli.payload import CURRENT, PREVIOUS

__all__ = [
    "HELD_NARROWED",
    "HELD_SKIPPED",
    "HELD_UNCONFIRMED",
    "build_result",
    "render_apply",
    "render_source_table",
    "repair_invocation",
    "summarise",
]

#: Why a document that owed a promotion was held back without a write (#873):
#: the run was narrowed past pairs the promotion needs (``SOPULI-W027``), a
#: guardrail skipped a target the password is for (``SOPULI-W050``), or a
#: target did not confirm.
HELD_NARROWED = "narrowed"
HELD_SKIPPED = "skipped"
HELD_UNCONFIRMED = "unconfirmed"

#: The `SOPULI-W049` message for a confirmed row in a held-back document, by
#: cause. Each points at what the run says about the cause, because the remedy
#: is there and one row cannot see it.
_HELD_MESSAGES = {
    HELD_NARROWED: (
        f"this database has the new password and the vault was not promoted, so `current` "
        f"still holds the old one -- {PROMOTION_WITHHELD} names the wider run that finishes it"
    ),
    HELD_SKIPPED: (
        f"this database has the new password and the vault was not promoted, so `current` "
        f"still holds the old one -- {PROMOTION_SKIPPED} names the target a guardrail skipped"
    ),
    HELD_UNCONFIRMED: (
        "this database has the new password and the vault was not promoted, because another "
        "row of this document did not confirm, so `current` still holds the old one -- "
        "that row says why, and the same command again finishes it once that is fixed"
    ),
}

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
    rollover: dict[str, Any] | None = None,
    promoted_to: int | None = None,
    promotion_error: Error | None = None,
    held_back: str | None = None,
    mechanism: str | None = None,
    overridden: Sequence[Refusal] = (),
    attributes: Sequence[AttributeChange] = (),
    duration_ms: int | None = None,
    error: Error | None = None,
    redraws: int = 0,
) -> dict[str, Any]:
    """One ``results[]`` entry for an account this run acted on.

    ``changed`` is *did this run issue the DDL*, and it is passed in rather than
    derived from the state: ``IN_SYNC`` is reached both by changing the password
    and by finding it already correct, and those are the two answers invariant 9
    exists to keep apart. `apply` is the convergent verb, so the second run of a
    successful rotation reports ``IN_SYNC`` with ``changed: false``.

    ``attributes`` is what UC-1 §5's opt-in attributes did, one entry each, and
    the emitted ``changed`` is **the union of it and the DDL**: the argument
    is about the password and the field is about the run, so an account that was
    unlocked and needed no new password reports ``changed: true`` with no
    ``password_set`` that applied. Keeping the argument narrow is what stops the
    action list from claiming a statement that was never issued.

    ``promoted_to`` is the document version the promotion produced, and it is
    written on **every** account in that document -- they shared one
    compare-and-set, so they share its version. ``None`` where nothing was
    promoted, which is both a run that read ``current`` and a run whose targets
    did not all confirm; the two are distinguished by the state and the detail,
    not by this field.

    ``promotion_error`` is the store's error where the promotion write was made
    and failed (UC-1 §8 row 7, #805). The caller passes it only for a row the
    write was made for (`cli._failed_promotion`): a sibling applied from
    `current` owed nothing, and its `current` is right. The row then gets a
    ``vault_promote`` action with ``applied: true``, since the write ran, this
    error as its ``error``, and the warning that ``current`` was not promoted.
    Without them a row that is ``IN_SYNC`` would read as a finished rotation.

    ``held_back`` is the same row's other way of not finishing (#873): it
    confirmed and owed the promotion, and its document was held back without a
    write, for one of the ``HELD_*`` causes. It gets the warning too.

    ``redraws`` is how many *extra* passwords this account was given because the
    server refused the value itself (§6.4) -- over the one the run arrived
    with, so a row that carries it was applied more than once and reports the last
    attempt. **Emitted only when at least one was drawn**, on the same reasoning
    as ``overridden`` below: the field records redraws, not the budget for them,
    and a ``0`` on every ordinary row would make the ones that mattered harder to
    find.

    ``overridden`` is what ``--force`` waived (§4), and it is the reason
    the flag returns a value rather than a boolean: §4 requires the waiver to
    survive the waiving, so a run that rotated `DBSNMP` on purpose says which
    checks it went past and what each observed. **Emitted only when something was
    actually waived** -- a `--force` that met a clean account omits the key,
    because the field records overrides and not intent, and a document carrying an
    empty array on every forced run would make the ones that mattered harder to
    find.
    """
    entry: dict[str, Any] = {
        "account": binding.account,
        "target": binding.target,
        "state": outcome.state,
        "changed": changed or any(change.changed for change in attributes),
    }
    if redraws:
        entry["redraws"] = redraws
    secret = _secret(binding, source=source, version=version, promoted_to=promoted_to)
    if secret is not None:
        entry["secret"] = secret
    entry["actions"] = _actions(
        outcome,
        changed=changed,
        verified_before=verified_before,
        promoted_to=promoted_to,
        promotion_error=promotion_error,
        attributes=attributes,
    )
    if outcome.verification is not None:
        entry["verification"] = verification_json(outcome.verification)
    if rollover is not None:
        # Emitted for every account whose password this run *looked at* on the
        # database -- not only the ones with an open window. The absence of a
        # window is the answer to "did the old password stop working just now",
        # and `profile_rollover_time` beside it says whether that was the regime
        # asked for or the only one available. A `ROLLOVER_ACTIVE` state
        # with no object beside it would leave a consumer inferring the deadline
        # from a word.
        #
        # **Omitted, never null, where the run never got that far** -- a missing
        # account, a locked one, an empty vault, an unreachable target. There is
        # no rollover fact to report about an account nothing was issued
        # against, and an absent optional object is how this document says that
        # everywhere else (`secret`, `verification`, `error`). A `null` would be
        # a third spelling of the same thing.
        entry["rollover"] = rollover
    elif outcome.state == ROLLOVER_ACTIVE:
        entry["rollover"] = {"active": True}
    if overridden:
        entry["overridden"] = [
            {"check": refusal.check, "reason": refusal.reason} for refusal in overridden
        ]
    if duration_ms is not None:
        entry["duration_ms"] = duration_ms
    if error is None:
        error = promotion_error
    if error is not None:
        entry["error"] = error.to_dict()
    warnings = _warnings(
        binding,
        outcome,
        changed=changed,
        mechanism=mechanism,
        promotion_failed=promotion_error is not None,
        held_back=held_back,
    )
    if warnings:
        entry["warnings"] = warnings
    return entry


def _actions(
    outcome: Outcome,
    *,
    changed: bool,
    verified_before: VerifyResult | None,
    promoted_to: int | None,
    promotion_error: Error | None = None,
    attributes: Sequence[AttributeChange] = (),
) -> list[dict[str, Any]]:
    """UC-1 §5's flow, as the steps that actually ran.

    In the order they happened, which is the order somebody reads them in when a
    rotation stopped halfway. ``applied`` is whether the step *ran*, never
    whether it succeeded -- the same rule `check` states about a login the
    lockout guard declined, and the reason a `verify` with ``applied: false`` is
    a meaningful row rather than a contradiction.

    **Attributes come first**, because that is when they happen: an unlock is
    what makes the pre-flight login worth attempting. Each carries the driver's
    own word for it, which is the document's ``action_kind`` -- the protocol
    spells them that way so that adding one cannot mean teaching this function
    about it.
    """
    actions: list[dict[str, Any]] = [
        {"kind": change.attribute, "applied": change.changed, "detail": change.detail}
        for change in attributes
    ]
    if verified_before is None and not changed:
        # Nothing further ran: a locked account, a missing one, an empty vault, a
        # target that could not be reached. `none` is in the schema's
        # `action_kind` enum for exactly this, and it is the honest entry -- a
        # `password_set` with `applied: false` would say the run got as far as
        # considering the statement, and it did not.
        #
        # Appended rather than returned alone, because an attribute above it did
        # run: the row says why nothing *else* did, which is what the reader of a
        # `LOCKED` row that also unlocked something needs.
        actions.append({"kind": "none", "applied": False, "detail": outcome.detail})
        return actions
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
    elif promotion_error is not None:
        actions.append(
            {
                "kind": "vault_promote",
                "applied": True,
                "detail": f"the promotion to `current` failed: {promotion_error.message}",
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


def verification_json(result: VerifyResult) -> dict[str, Any]:
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
    binding: Binding,
    outcome: Outcome,
    *,
    changed: bool,
    mechanism: str | None,
    promotion_failed: bool = False,
    held_back: str | None = None,
) -> list[dict[str, Any]]:
    """What this run did that somebody should know about.

    The one that matters is a **database whose password the vault did not
    promote**: UC-1 §8 calls it the highest-severity row in its table, because
    applications fetch ``current`` and are now fetching a password the database no
    longer has. It covers a changed row that did not confirm, any row whose
    promotion write failed (#805), and any confirmed row whose document was held
    back without a write (#873), changed by this run or by an earlier one. It is
    a warning on the account as well as any run-level diagnostic, so that it
    survives into whatever a consumer filters `results[]` down to.

    The write ``mechanism`` rides here too when it was the wider one, which is
    the reporting UC-1 §3 requires: under a read-modify-write the whole document
    left this process.
    """
    found: list[dict[str, Any]] = []
    if held_back is not None:
        found.append(
            {
                "level": "warning",
                "code": CHANGED_NOT_PROMOTED,
                "message": _HELD_MESSAGES[held_back],
                "account": binding.account,
                "target": binding.target,
            }
        )
    elif (changed and outcome.state not in CONFIRMED) or promotion_failed:
        # A failed promotion write (#805) is reported whether or not this run
        # changed the database: an earlier run may have put the password there.
        # Its remedy depends on the run (a conflict, a lost lock, a rollback, the
        # selectors), which one account's row cannot see, so it points at the
        # run-level diagnostic that names it.
        message = (
            "the promotion to `current` failed, so `current` may not hold the password this "
            "database has -- SOPULI-W033 says what to do next"
            if promotion_failed
            else (
                "the database was changed and the vault was not promoted, so "
                "`current` still holds the old password -- re-run `sopuli creds apply` "
                "once this target is well"
            )
        )
        found.append(
            {
                "level": "warning",
                # One code for both messages: either way `current` may not hold
                # the password this database has.
                "code": CHANGED_NOT_PROMOTED,
                "message": message,
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


def summarise(states: Sequence[str], *, changed: int, unpromoted: int = 0) -> Summary:
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

    ``unpromoted`` is the confirmed rows a promotion was for whose document
    `current` was not moved to: its write failed (#805), or it was held back
    without a write (#873). They move from ``ok`` to ``failed``: the database
    took the password and `current` still holds the old one, so the run did not
    finish its work on them. ``by_state`` still counts their state, which is
    what is true of the database.
    """
    return Summary(
        total=len(states),
        ok=sum(1 for state in states if is_confirmed(state)) - unpromoted,
        changed=changed,
        failed=sum(1 for state in states if is_failure(state)) + unpromoted,
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


def repair_invocation(
    *,
    selectors: Sequence[str] = (),
    config_paths: Sequence[str] = (),
    profile: str | None = None,
    source: str | None = None,
    strategy: str | None = None,
) -> str:
    """The command line that repairs a partial run, spelled exactly.

    Printed by :func:`render_apply` on the runs that exit 4, because that exit
    code's whole purpose is to point at a remedy and "run it again" is not one.
    A run narrowed to one tenant has to be narrowed the same way to repair it,
    or the repair walks the estate the partial run already walked -- which is a
    login per account per target, against the failed-login counter UC-1 §7
    exists to protect.

    So this echoes back the options that decide **what would be applied** -- the
    selectors, the stage, the regime -- and the two that decide **how the file
    resolves**, ``--config`` and ``--profile``. A scheduled run repaired without
    its profile resolves its settings from different layers and is a different
    run (`01-configuration.md` §5), which is the failure that looks like the
    tool behaving inconsistently.

    Options that tune a guard rather than the work are left out on purpose.
    ``--lockout-margin`` changes how cautious the pre-flight is and nothing about
    which accounts are acted on, and a remedy line long enough to wrap is one
    nobody pastes.

    ``--source previous`` carries ``--confirm`` with it, because the repair of a
    partial rollback is another rollback and UC-1 §8 refuses an unauthorised one.
    No other stage gets it: `--confirm` being on that operation alone is the
    point of having it.

    **This line is the plain re-run, although ``--repair FILE`` exists.**
    :meth:`~sopuli.output.emit.Emitter.emit` writes "the JSON document, or the
    human text, never both" -- so this line is only ever read by somebody in
    **text** mode, and a text-mode run leaves no document on disk for
    ``--repair`` to be pointed at. Replacing the line would hand a half-applied
    estate an invocation that cannot run.

    The flag is named on a separate line instead, and that line promises
    nothing: it says what the flag needs. A JSON consumer needs no line at
    all -- it has ``results[]``, and ``03-json-output.md`` §7's recipe is the
    same filter this flag applies.
    """
    words = ["sopuli", "creds", "apply"]
    for path in config_paths:
        words += ["--config", _word(path)]
    if profile is not None:
        words += ["--profile", _word(profile)]
    for selector in selectors:
        words += ["--select", _word(selector)]
    if source is not None:
        words += ["--source", source]
        if source == PREVIOUS:
            words.append("--confirm")
    if strategy is not None:
        words += ["--strategy", strategy]
    return " ".join(words)


def _word(value: str) -> str:
    """One argument, quoted where it carries whitespace.

    **Not a general shell quoter**, and it should not become one. What is
    composed here is config paths, a profile name and `k=v` label selectors, and
    whitespace is the character among those that arises -- ``C:/Program
    Files/estate.yaml`` is the ordinary case on Windows. Nothing here escapes
    ``&``, ``$`` or a glob, and a value carrying one would need a different
    answer per shell rather than this one.

    Double quotes rather than single, because the line is meant to be pasted on
    Windows as well (P4): ``cmd`` does not treat a single quote as quoting at
    all, while a double-quoted argument works in ``cmd``, in PowerShell and in
    every POSIX shell.
    """
    return f'"{value}"' if any(char.isspace() for char in value) else value


def render_apply(
    rows: Sequence[tuple[Binding, Outcome, bool]],
    *,
    promoted: int = 0,
    source: str | None = None,
    repair: str | None = None,
    stopped: str | None = None,
) -> str:
    """The result table and the closing line. ``rows`` is (binding, outcome, changed).

    ``source`` is the stage the operator named, and it changes only one word:
    a rollback says "rolled back" rather than "changed". Worth the parameter,
    because the two runs are indistinguishable otherwise and one of them moved
    an estate backwards on purpose.

    ``repair`` is the invocation that repairs this run, from
    :func:`repair_invocation`, and is passed **only on the runs that exit 4**.
    Deciding that here would mean re-deriving the exit code from the states,
    and the one place it is decided is `apply.exit_code_for`: a table
    that offered a remedy on a run the exit code called successful would be the
    two disagreeing about the same run.

    ``stopped`` is why the run ended early -- today, that its lock was taken
    over. It **suppresses** ``repair``, and that is not tidiness: the repair
    line says *run this again*, and running again is the one thing not to do
    while somebody else holds this estate's lock. Two callers passing both would
    print contradictory advice, so the renderer settles it rather than trusting
    each one to.
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
                source=source,
                repair=repair,
                stopped=stopped,
            ),
        ]
    )


def _address(binding: Binding) -> Cell | str:
    if binding.secret is None or binding.vault is None:
        return Cell("-", Role.MUTED)
    return f"{binding.vault}:{binding.secret.path}"


def _state(state: str) -> Cell | str:
    """The state cell, coloured by :func:`~sopuli.output.palette.role_for_state`.

    One function decides the role for every verb (decision #395), so a state is
    emphasised the same way whichever verb printed the row. This is the wrapper
    the table needs and holds no policy of its own.
    """
    return state_cell(state)


def _verdict(
    states: Sequence[str],
    *,
    changed: int,
    promoted: int,
    source: str | None = None,
    repair: str | None = None,
    stopped: str | None = None,
) -> str:
    """The closing line: what happened, then what still needs attention.

    Says the two halves separately because they fail separately. "3 changed" and
    "2 documents promoted" are the database and the vault, and the whole design
    of UC-1 §3 is that the second only follows the first once every target has
    confirmed -- so a line reporting changes with no promotion is exactly the
    state an operator has to notice.

    ``repair`` adds a second line naming the invocation that fixes it. It is
    printed on both shapes of exit 4 and that is deliberate: targets that did
    not confirm, and a whole estate that confirmed while its vault was not
    promoted. The second is UC-1 §8 case 7 -- the estate has the new password
    and applications are still fetching the old one -- and it is the row on that
    table where knowing what to type next matters most.

    **Text only, and no diagnostic code.** A code exists for what the exit code
    cannot tell you; here exit 4 says that the run is partial, and `results[]`
    carries the states a consumer would filter on (`03-json-output.md` §7). What
    exit 4 cannot say is *why* a confirmed estate was not promoted, so a failed
    promotion write has its own code, ``SOPULI-W033``, raised by the command and
    printed as a note under this line, not by it.

    ``stopped`` is the exception, and it *does* carry a code (``SOPULI-W011``):
    a run fenced out mid-estate exits 4 exactly like a run whose targets failed,
    and the two want opposite responses. Here it replaces the remedy rather than
    joining it -- see :func:`render_apply`.
    """
    verb = "rolled back" if source == PREVIOUS else "changed"
    parts = [f"{changed} {verb}"] if changed else [f"nothing {verb}"]
    if promoted:
        parts.append(f"{promoted} promoted to `current`")
    unconfirmed = sum(1 for state in states if state not in CONFIRMED)
    if not unconfirmed:
        line = ", ".join(parts)
        if not (changed and not promoted):
            line = paint(line, Role.HEADING)
        return _with_remedy(line, repair, stopped, flag=False)
    parts.append(f"{unconfirmed} not confirmed")
    return _with_remedy(", ".join(parts), repair, stopped, flag=True)


def _with_remedy(
    line: str, repair: str | None, stopped: str | None = None, *, flag: bool = False
) -> str:
    """The verdict, and under it either why the run stopped or what to type next.

    Never both, and ``stopped`` wins. A run whose lock was taken over has an
    exit code that also means "some targets failed", and the advice for that one
    -- run it again -- is the advice to withhold from this one.

    **The lines under the verdict are unpainted**, unlike the verdict itself,
    which the caller may have painted as a heading already. Colour maps onto the
    JSON vocabulary and nothing else (`03-json-output.md` §1), and neither a
    remedy nor a reason is a field the document carries. The remedy is also the
    line somebody copies, which is a second reason to keep escape sequences out
    of it.

    ``--repair`` gets the third line and the conditional wording, because this
    text is only ever read in text mode and a text-mode run captured no document
    (see :func:`repair_invocation`). It is worth saying anyway: an operator
    meeting exit 4 twice is exactly who should know the cheaper route exists,
    and *what it costs to have one* is the part they can act on before the next
    run rather than after it.

    ``flag`` is that third line's own condition, and it is not the same as
    ``repair``'s. Exit 4 has two shapes and the plain re-run fixes both, but
    ``--repair`` only fixes one: on UC-1 §8 case 7 -- every target confirmed and
    the vault not promoted -- there is no unconfirmed row for a repair set to be
    built from, so the flag would filter the estate to nothing and report
    ``nothing to apply``. Advertising it there sends the reader to a command
    that does nothing about the case they are in.
    """
    if stopped is not None:
        return f"{line}\n{stopped}"
    if repair is None:
        return line
    remedy = f"{line}\nrepair with: {repair}"
    if not flag:
        return remedy
    return f"{remedy}\n         or: --repair FILE, if you captured this run with --output json"

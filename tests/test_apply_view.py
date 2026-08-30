"""`creds apply`'s document and table shape (#259).

The decision is `tests/test_apply.py`. This is what a consumer sees: which
counters a run carries, which of UC-1 §5's steps end up in ``actions[]``, and the
two things the text view has to make impossible to miss -- a database that was
changed, and a vault that was not promoted.
"""

from __future__ import annotations

from typing import Any

from sopuli import apply, check
from sopuli.config.model import Binding
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.driver.protocol import FAIL, PASS, SKIPPED, VERIFY_LOGIN, VerifyResult
from sopuli.output import apply_view
from sopuli.payload import CURRENT, PENDING, PREVIOUS
from sopuli.secrets import Secret


def binding(account: str = "acme_web_user") -> Binding:
    return Binding(
        account=account,
        target="appdb-dev-alpha",
        secret=parse_secret_ref(f"apps/acme/db#DB_CREDENTIALS/{account}"),
        vault="vault-dev",
    )


def source(stage: str = PENDING) -> apply.Source:
    return apply.Source(stage=stage, value=Secret("new"), replaces=Secret("old"))


def attempt(result: str = PASS, **fields: Any) -> VerifyResult:
    return VerifyResult(method=VERIFY_LOGIN, result=result, **fields)


def outcome(state: str = check.IN_SYNC, detail: str = "changed and verified by login") -> Any:
    return check.Outcome(state, detail, attempt())


# ------------------------------------------------------------- the actions ---


def test_the_flow_is_reported_as_the_steps_that_ran() -> None:
    """UC-1 §5 is a sequence, and an operator diagnosing a partial rotation needs
    to know which step of it stopped."""
    entry = apply_view.build_result(
        binding(),
        outcome(),
        source=source(),
        changed=True,
        verified_before=attempt(FAIL),
        promoted_to=9,
    )

    assert [action["kind"] for action in entry["actions"]] == [
        "verify",
        "password_set",
        "verify",
        "vault_promote",
    ]


def test_a_run_that_changed_nothing_says_the_step_did_not_run() -> None:
    """`applied` is whether the step ran, never whether it succeeded -- so a
    `password_set` with `applied: false` is how "it was already right" reads."""
    entry = apply_view.build_result(
        binding(), outcome(), source=source(CURRENT), changed=False, verified_before=attempt()
    )

    steps = {action["kind"]: action["applied"] for action in entry["actions"]}
    assert steps["password_set"] is False


def test_a_declined_login_is_an_action_that_did_not_happen() -> None:
    """The distinction UC-1 §7 mitigation 1 exists to make visible: a decline
    produces a result object and spends no attempt."""
    entry = apply_view.build_result(
        binding(),
        check.Outcome(check.UNVERIFIABLE, "within 2 of the limit", attempt(SKIPPED)),
        source=source(),
        changed=True,
    )

    assert [action["applied"] for action in entry["actions"] if action["kind"] == "verify"] == [
        False
    ]


def test_an_account_nothing_ran_against_reports_no_action() -> None:
    """A locked account, a missing one, an empty vault, an unreachable target.
    `none` is in the schema's own `action_kind` enum for this, and a
    `password_set` with `applied: false` would say the run got as far as
    considering the statement."""
    entry = apply_view.build_result(
        binding(),
        check.Outcome(check.LOCKED, "account is locked; the password was not changed"),
        source=source(),
        changed=False,
    )

    assert entry["actions"] == [
        {
            "kind": "none",
            "applied": False,
            "detail": "account is locked; the password was not changed",
        }
    ]


# -------------------------------------------------------------- the secret ---


def test_the_stage_reported_is_the_one_that_was_read() -> None:
    """A row saying `pending` is one whose password is not yet what applications
    fetch."""
    entry = apply_view.build_result(binding(), outcome(), source=source(), changed=True)

    assert entry["secret"]["stage"] == PENDING


def test_a_promoted_account_reports_current_and_the_new_version() -> None:
    """The pair reads as "was staged, now current at v9", which is what a later
    `check` or a resumed rotation is diagnosed from."""
    entry = apply_view.build_result(
        binding(), outcome(), source=source(), changed=True, promoted_to=9
    )

    assert entry["secret"]["stage"] == CURRENT
    assert entry["secret"]["version"] == 9


def test_a_binding_with_no_store_emits_no_secret() -> None:
    """The schema requires `vault` as a string, so there is no shape for half an
    address."""
    orphan = Binding(account="a", target="t", secret=None, vault=None)

    assert "secret" not in apply_view.build_result(orphan, outcome(), changed=False)


# ------------------------------------------------------------ the warnings ---


def test_a_changed_database_with_no_promotion_is_a_warning() -> None:
    """UC-1 §8's highest-severity row. On the account rather than run-level, so
    it survives whatever a consumer filters `results[]` down to."""
    entry = apply_view.build_result(
        binding(),
        check.Outcome(check.UNVERIFIABLE, "could not confirm", attempt(SKIPPED)),
        source=source(),
        changed=True,
    )

    assert any("was not promoted" in one["message"] for one in entry["warnings"])


def test_a_confirmed_change_carries_no_such_warning() -> None:
    entry = apply_view.build_result(binding(), outcome(), source=source(), changed=True)

    assert "warnings" not in entry


def test_a_wider_write_mechanism_is_reported() -> None:
    """UC-1 §3 requires it, and the two are not equally narrow: under the
    fallback the whole document left this process."""
    entry = apply_view.build_result(
        binding(),
        outcome(),
        source=source(),
        changed=True,
        promoted_to=9,
        mechanism="read_modify_write",
    )

    assert any("read-modify-write" in one["message"] for one in entry["warnings"])


# ------------------------------------------------------------- the summary ---


def test_ok_and_changed_answer_different_questions() -> None:
    """A converged estate is `ok` whether this run converged it or found it that
    way -- which is the whole reason both counters exist."""
    summary = apply_view.summarise([check.IN_SYNC, check.IN_SYNC], changed=1)

    assert summary.ok == 2
    assert summary.changed == 1
    assert summary.unchanged == 1


def test_an_open_rollover_window_counts_as_ok() -> None:
    """Unlike `check`, where the window is a caveat on a survey. Here it is a
    target that accepted the password and can be promoted on."""
    summary = apply_view.summarise([check.ROLLOVER_ACTIVE], changed=1)

    assert summary.ok == 1


def test_failed_counts_error_and_nothing_else() -> None:
    """The same condition `exit_code_for` reads, so a document's counter and its
    exit code cannot disagree about one run."""
    summary = apply_view.summarise([check.ERROR, check.LOCKED], changed=0)

    assert summary.failed == 1
    assert summary.unverifiable == 1


# ---------------------------------------------------------------- the text ---


def test_the_verdict_reports_the_database_and_the_vault_separately() -> None:
    """They fail separately, and a line reporting changes with no promotion is
    exactly the state an operator has to notice."""
    rows = [(binding(), outcome(), True)]

    assert "1 changed, 1 promoted to `current`" in apply_view.render_apply(rows, promoted=1)


def test_a_run_that_changed_nothing_says_so_plainly() -> None:
    rows = [(binding(), outcome(check.IN_SYNC, "already accepted"), False)]

    assert "nothing changed" in apply_view.render_apply(rows)


def test_unconfirmed_rows_are_counted_in_the_verdict() -> None:
    rows = [
        (binding(), outcome(), True),
        (binding("acme_batch_user"), outcome(check.ERROR, "ORA-01017"), True),
    ]

    assert "1 not confirmed" in apply_view.render_apply(rows)


def test_the_source_table_names_the_stage_per_row() -> None:
    """A `pending` row is a rotation about to be completed and a `current` row is
    a repair: the same command, two very different things to authorise."""
    lines = apply_view.render_source_table(
        [(binding(), source()), (binding("acme_batch_user"), source(CURRENT))]
    )

    assert any(row.endswith(PENDING) for row in lines)
    assert any(row.endswith(CURRENT) for row in lines)


def test_the_table_is_ascii() -> None:
    """P4: identical output on every platform, and cp1252 cannot hold the rest."""
    rows = [(binding(), outcome(), True)]

    apply_view.render_apply(rows, promoted=1).encode("ascii")
    "\n".join(apply_view.render_source_table([(binding(), source())])).encode("ascii")


# -------------------------------------------------------------- the remedy ---


def test_the_repair_invocation_echoes_what_narrowed_the_run() -> None:
    """#264: exit 4 points at a remedy, and an unnarrowed one walks the estate the
    partial run already walked -- a login per account per target, against the
    counter UC-1 §7 exists to protect."""
    line = apply_view.repair_invocation(selectors=("env=prod", "tenant=alpha"))

    assert line == "sopuli creds apply --select env=prod --select tenant=alpha"


def test_the_repair_invocation_carries_the_layers_the_run_resolved_under() -> None:
    """A scheduled run repaired without its profile resolves its settings from
    different layers and is a different run (`01-configuration.md` §5)."""
    line = apply_view.repair_invocation(config_paths=("estate.yaml",), profile="scheduled")

    assert line == "sopuli creds apply --config estate.yaml --profile scheduled"


def test_the_repair_invocation_carries_an_explicit_regime() -> None:
    """`--strategy` decides what is issued, so a repair without it may honour a
    different regime from the run it is repairing (UC-1 §6.3)."""
    assert apply_view.repair_invocation(strategy="direct").endswith("--strategy direct")


def test_a_partial_rollback_is_repaired_by_another_authorised_rollback() -> None:
    """UC-1 §8 puts `--confirm` on this operation and only this one, so a remedy
    line that left it out would be a paste that stops at a refusal."""
    assert apply_view.repair_invocation(source=PREVIOUS).endswith("--source previous --confirm")


def test_no_other_stage_is_offered_a_confirmation() -> None:
    assert "--confirm" not in apply_view.repair_invocation(source=CURRENT)


def test_an_argument_with_a_space_is_quoted_for_both_shells() -> None:
    """P4: the line is meant to be pasted, on Windows as well. `cmd` does not
    treat a single quote as quoting at all, while a double-quoted argument works
    in `cmd`, in PowerShell and in every POSIX shell."""
    line = apply_view.repair_invocation(config_paths=("C:/Program Files/estate.yaml",))

    assert line.endswith('--config "C:/Program Files/estate.yaml"')


def test_the_verdict_names_the_repair_where_targets_did_not_confirm() -> None:
    rows = [
        (binding(), outcome(), True),
        (binding("acme_batch_user"), outcome(check.ERROR, "ORA-01017"), True),
    ]

    rendered = apply_view.render_apply(rows, repair="sopuli creds apply --select env=prod")

    assert "1 not confirmed" in rendered
    assert "repair with: sopuli creds apply --select env=prod" in rendered


def test_the_verdict_names_the_repair_where_the_vault_was_not_promoted() -> None:
    """Exit 4's other shape, and UC-1 §8's highest-severity row: every target
    confirmed, and applications are still fetching a password the estate no
    longer has. Knowing what to type next matters most here."""
    rows = [(binding(), outcome(), True)]

    rendered = apply_view.render_apply(rows, promoted=0, repair="sopuli creds apply")

    assert "repair with: sopuli creds apply" in rendered


def test_a_run_that_did_not_exit_four_offers_no_remedy() -> None:
    """The renderer never decides this. Offering a remedy on a run the exit code
    called successful would be the two describing one run differently."""
    rows = [(binding(), outcome(), True)]

    assert "repair with:" not in apply_view.render_apply(rows, promoted=1)


def test_a_stopped_run_says_why_instead_of_offering_a_remedy() -> None:
    """#282: a run fenced out mid-estate exits 4 exactly like one whose targets
    failed, and #264's line -- *run this again* -- is the advice to withhold from
    it. The renderer settles that rather than trusting each caller to."""
    rows = [(binding(), outcome(), True)]

    rendered = apply_view.render_apply(
        rows,
        repair="sopuli creds apply --select env=prod",
        stopped="vault-prod:apps/acme/db was taken over: expected version 41, found 42",
    )

    assert "was taken over" in rendered
    assert "repair with:" not in rendered


def test_the_reason_a_run_stopped_is_printed_under_the_verdict() -> None:
    rows = [(binding(), outcome(), True)]

    rendered = apply_view.render_apply(rows, stopped="taken over")

    assert rendered.splitlines()[-1] == "taken over"

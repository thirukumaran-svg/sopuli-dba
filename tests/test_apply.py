"""The decision table behind `creds apply` (#259).

UC-1 §5 is a sequence, and the interesting half of it is where the sequence
*stops*: an account nothing should be issued against, a password the database
already has, a change that could not be confirmed. Pure, so each of those is a
line here rather than a fixture against a container.

The property carrying most of this file is that **nothing is promoted that was
not confirmed** (invariant 7). Everything about the promotion is a function of
states this module produced, so the ordering can be argued about without a vault.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sopuli import apply, check
from sopuli.config.model import Binding
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.driver.protocol import (
    FAIL,
    PASS,
    SKIPPED,
    UNAVAILABLE,
    VERIFY_LOGIN,
    UserState,
    VerifyResult,
)
from sopuli.exit_codes import ExitCode
from sopuli.payload import CURRENT, PENDING, PREVIOUS
from sopuli.secrets import Secret

NOW = datetime(2026, 8, 29, 9, 30, tzinfo=UTC)

SHARED = "apps/acme/db#DB_CREDENTIALS/{account}"


def user(**fields: object) -> UserState:
    base: dict[str, object] = {"name": "ACME_WEB_USER", "status": "OPEN"}
    return UserState(**{**base, **fields})  # type: ignore[arg-type]


def attempt(result: str, **fields: object) -> VerifyResult:
    return VerifyResult(method=VERIFY_LOGIN, result=result, **fields)  # type: ignore[arg-type]


def binding(account: str = "acme_web_user", *, ref: str = SHARED, **fields: object) -> Binding:
    base: dict[str, object] = {"target": "appdb-dev-alpha", "vault": "vault-dev"}
    return Binding(
        account=account,
        secret=parse_secret_ref(ref.replace("{account}", account)),
        **{**base, **fields},  # type: ignore[arg-type]
    )


def source(
    stage: str = PENDING, *, value: str = "new", replaces: str | None = "old"
) -> apply.Source:
    return apply.Source(
        stage=stage,
        value=Secret(value),
        replaces=None if replaces is None else Secret(replaces),
    )


# -------------------------------------------------------------- the source ---


def test_a_staged_password_wins_over_the_current_one() -> None:
    """UC-1 §5's `--source` default: a `pending` exists precisely because it has
    not been applied yet."""
    document = {"DB_CREDENTIALS": {"acme_web_user": "old"}, "pending": {"acme_web_user": "new"}}

    found = apply.source_for(
        document, parse_secret_ref("apps/acme/db#DB_CREDENTIALS/acme_web_user")
    )

    assert found is not None
    assert found.stage == PENDING
    assert found.value.reveal() == "new"


def test_the_current_password_is_carried_so_previous_can_take_it() -> None:
    """A promotion moves `current` into `previous`, and the document is read once
    -- so what `current` held has to travel with the source rather than be read
    again from a document somebody else may have changed."""
    document = {"DB_CREDENTIALS": {"acme_web_user": "old"}, "pending": {"acme_web_user": "new"}}

    found = apply.source_for(
        document, parse_secret_ref("apps/acme/db#DB_CREDENTIALS/acme_web_user")
    )

    assert found is not None
    assert found.replaces is not None
    assert found.replaces.reveal() == "old"


def test_with_nothing_staged_the_current_password_is_applied() -> None:
    """The repair case: the vault already holds what it should and a database
    has drifted away from it."""
    document = {"DB_CREDENTIALS": {"acme_web_user": "live"}}

    found = apply.source_for(
        document, parse_secret_ref("apps/acme/db#DB_CREDENTIALS/acme_web_user")
    )

    assert found is not None
    assert found.stage == CURRENT
    assert found.replaces is None


def test_a_repair_has_nothing_to_move_into_previous() -> None:
    """`previous` means "the one before current", and a run that applied
    `current` has not made a new one."""
    document = {"DB_CREDENTIALS": {"acme_web_user": "live"}}
    ref = parse_secret_ref("apps/acme/db#DB_CREDENTIALS/acme_web_user")

    assert apply.source_for(document, ref) == apply.Source(CURRENT, Secret("live"), None)


def test_an_empty_document_yields_no_source() -> None:
    ref = parse_secret_ref("apps/acme/db#DB_CREDENTIALS/acme_web_user")

    assert apply.source_for(None, ref) is None
    assert apply.source_for({}, ref) is None


def test_a_sibling_account_s_password_is_not_this_account_s() -> None:
    """The shared layout, read the way the mirror rule addresses it."""
    document = {"DB_CREDENTIALS": {"acme_batch_user": "theirs"}}
    ref = parse_secret_ref("apps/acme/db#DB_CREDENTIALS/acme_web_user")

    assert apply.source_for(document, ref) is None


# ------------------------------------------------------ the chosen stage ---


def test_an_explicit_stage_is_read_and_never_fallen_back_from() -> None:
    """The fallback is the thing somebody passing the flag was trying to avoid.
    Silently applying `current` to an operator who asked for `previous` is a
    rollback that did not happen and said it did."""
    document = {"DB_CREDENTIALS": {"acme_web_user": "live"}}
    ref = parse_secret_ref("apps/acme/db#DB_CREDENTIALS/acme_web_user")

    assert apply.source_for(document, ref, stage=PREVIOUS) is None
    assert apply.source_for(document, ref, stage=PENDING) is None


def test_the_rollback_reads_previous_and_keeps_current_to_swap_with() -> None:
    """`replaces` is the password being taken *off* the database, which is
    exactly what `previous` should hold afterwards -- so the promotion patch
    needs no rollback-shaped variant."""
    document = {
        "DB_CREDENTIALS": {"acme_web_user": "live"},
        "previous": {"acme_web_user": "old"},
    }
    ref = parse_secret_ref("apps/acme/db#DB_CREDENTIALS/acme_web_user")

    found = apply.source_for(document, ref, stage=PREVIOUS)

    assert found is not None
    assert found.value.reveal() == "old"
    assert found.replaces is not None
    assert found.replaces.reveal() == "live"


def test_an_explicit_current_owes_the_vault_nothing() -> None:
    """`--source current` is a repair: the vault already holds what went on the
    database."""
    document = {
        "DB_CREDENTIALS": {"acme_web_user": "live"},
        "pending": {"acme_web_user": "new"},
    }
    ref = parse_secret_ref("apps/acme/db#DB_CREDENTIALS/acme_web_user")

    found = apply.source_for(document, ref, stage=CURRENT)

    assert found is not None
    assert found.stage == CURRENT
    assert found.replaces is None


def test_a_staged_pending_is_noted_whichever_stage_was_read() -> None:
    """Only the rollback acts on it, and it has to know."""
    document = {
        "DB_CREDENTIALS": {"acme_web_user": "live"},
        "pending": {"acme_web_user": "new"},
        "previous": {"acme_web_user": "old"},
    }
    ref = parse_secret_ref("apps/acme/db#DB_CREDENTIALS/acme_web_user")

    for stage in (None, CURRENT, PREVIOUS):
        found = apply.source_for(document, ref, stage=stage)
        assert found is not None
        assert found.pending_staged is True


def test_only_the_two_neighbours_owe_the_vault_a_write() -> None:
    """A rollback *is* a promotion, of the other neighbour -- which is why one
    patch serves both."""
    assert apply.promotes(PENDING) is True
    assert apply.promotes(PREVIOUS) is True
    assert apply.promotes(CURRENT) is False


# ------------------------------------------------- what is not acted on ---


def test_an_empty_vault_is_a_failure_and_not_a_quiet_no_op() -> None:
    """`check` calls this `UNVERIFIABLE` because its survey has a gap. `apply`
    cannot do the thing it was run to do, and a mutating verb that exits 0 having
    converged nothing is the silent failure worth being loud about."""
    outcome = apply.settled_before_acting(user(), None)

    assert outcome is not None
    assert outcome.state == check.ERROR
    assert "creds generate" in outcome.detail


def test_a_rollback_under_a_rotation_in_flight_is_refused() -> None:
    """The `pending` would survive this run, and the next `apply` would move the
    estate forward with it -- undoing the undo, unattended."""
    outcome = apply.settled_before_acting(
        user(), apply.Source(PREVIOUS, Secret("old"), Secret("live"), pending_staged=True)
    )

    assert outcome is not None
    assert outcome.state == apply.PENDING_APPLY
    assert "undone by the next" in outcome.detail


def test_a_missing_account_outranks_the_rollback_gate() -> None:
    """Telling somebody to deal with a `pending` first, about an account the
    database does not have, answers a question they had not reached. What the
    database says about the account is the cause of everything downstream of
    it."""
    outcome = apply.settled_before_acting(
        None, apply.Source(PREVIOUS, Secret("old"), Secret("live"), pending_staged=True)
    )

    assert outcome is not None
    assert outcome.state == check.ACCOUNT_MISSING


def test_a_locked_account_outranks_the_rollback_gate() -> None:
    """Same argument one step down: nothing was going to be rolled back onto a
    locked account either."""
    outcome = apply.settled_before_acting(
        user(status="LOCKED", locked=True),
        apply.Source(PREVIOUS, Secret("old"), Secret("live"), pending_staged=True),
    )

    assert outcome is not None
    assert outcome.state == check.LOCKED


def test_a_forward_apply_under_a_staged_pending_is_not_refused() -> None:
    """That is the ordinary rotation, and the `pending` is the point of it."""
    assert (
        apply.settled_before_acting(
            user(), apply.Source(PENDING, Secret("new"), Secret("live"), pending_staged=True)
        )
        is None
    )


def test_a_missing_stage_names_the_one_that_was_asked_for() -> None:
    """ "No `previous` to roll back to" and "nothing staged at all" send somebody
    to different places, and only one of them is `creds generate`."""
    rollback = apply.settled_before_acting(user(), None, requested=PREVIOUS)
    staging = apply.settled_before_acting(user(), None, requested=PENDING)
    unasked = apply.settled_before_acting(user(), None)

    assert rollback is not None
    assert "nothing to roll back to" in rollback.detail
    assert staging is not None
    assert "creds generate" in staging.detail
    assert unasked is not None
    assert "either stage" in unasked.detail


def test_a_missing_account_is_reported_and_not_created() -> None:
    """Q8 puts provisioning in its own use case."""
    outcome = apply.settled_before_acting(None, source())

    assert outcome is not None
    assert outcome.state == check.ACCOUNT_MISSING


def test_a_locked_account_is_not_changed() -> None:
    """The change would succeed and could never be confirmed, which would leave a
    database holding a password that is in no vault stage."""
    outcome = apply.settled_before_acting(user(status="LOCKED", locked=True), source())

    assert outcome is not None
    assert outcome.state == check.LOCKED
    assert "not changed" in outcome.detail


def test_an_expired_password_is_applied_rather_than_refused() -> None:
    """UC-1 §6.4 lists ORA-28001 as resolvable *by* apply: setting a password
    clears the expiry, so an expired account is one this command fixes."""
    assert apply.settled_before_acting(user(status="EXPIRED", expired=True), source()) is None


def test_no_source_outranks_a_missing_account() -> None:
    """Both are true and only one is actionable: there is nothing to apply, which
    is the operator's own next step regardless of what the database has."""
    outcome = apply.settled_before_acting(None, None)

    assert outcome is not None
    assert outcome.state == check.ERROR


# ------------------------------------------------------- the pre-flight ask ---


def test_a_password_that_already_works_is_left_alone() -> None:
    """Invariant 9's requirement on this verb, met without a special case for
    it: the second run of a successful rotation reads `current`, is accepted, and
    issues nothing."""
    outcome = apply.already_applied(user(), attempt(PASS), source=source(CURRENT))

    assert outcome is not None
    assert outcome.state == check.IN_SYNC


def test_a_rejected_password_is_applied_and_reports_no_transient_state() -> None:
    """What `check` would have called DRIFT. No state is produced for it, because
    the run is about to change the thing that made it drift."""
    assert apply.already_applied(user(), attempt(FAIL), source=source()) is None


def test_a_declined_login_still_applies() -> None:
    """The lockout guard declining means the run cannot tell whether a change is
    needed. Applying converges either way and costs the counter nothing --
    `ALTER USER` is not a login."""
    assert apply.already_applied(user(), attempt(SKIPPED), source=source()) is None
    assert apply.already_applied(user(), attempt(UNAVAILABLE), source=source()) is None


def test_a_pass_during_a_rollover_window_still_means_do_not_act() -> None:
    """The window makes a `pass` mean less -- the previous password authenticates
    too -- and re-applying would restart the window and report a change nobody
    asked for."""
    outcome = apply.already_applied(user(rollover_active=True), attempt(PASS), source=source())

    assert outcome is not None
    assert outcome.state == check.ROLLOVER_ACTIVE
    assert "previous password" in outcome.detail


def test_the_pre_flight_says_which_stage_it_was_asking_about() -> None:
    """A `pending` already accepted is an interrupted rotation to finish, and a
    `current` already accepted is nothing to do at all."""
    staged = apply.already_applied(user(), attempt(PASS), source=source(PENDING))
    live = apply.already_applied(user(), attempt(PASS), source=source(CURRENT))

    assert staged is not None
    assert live is not None
    assert "pending" in staged.detail
    assert "pending" not in live.detail


# ------------------------------------------------------ after the change ---


def test_a_change_that_verifies_is_in_sync() -> None:
    outcome = apply.after_change(user(), attempt(PASS))

    assert outcome.state == check.IN_SYNC
    assert "verified" in outcome.detail


def test_a_change_that_is_then_refused_is_an_error_not_drift() -> None:
    """§8 case 6. `DRIFT` is a statement about an estate somebody should go and
    fix; this is a statement about a run that did not work."""
    outcome = apply.after_change(user(), attempt(FAIL, detail="ORA-01017: invalid credential"))

    assert outcome.state == check.ERROR
    assert "ORA-01017" in outcome.detail


def test_a_change_that_could_not_be_verified_is_unverifiable() -> None:
    """The database was changed and the tool cannot say the change took. Not a
    failure of the estate, and not a success either."""
    outcome = apply.after_change(user(), attempt(SKIPPED, detail="within 2 of the limit"))

    assert outcome.state == check.UNVERIFIABLE
    assert "within 2" in outcome.detail


def test_a_lock_that_arrived_during_the_run_is_reported_as_the_lock() -> None:
    """`check`'s rule about the cause outranking the symptom, on the other side
    of the change."""
    outcome = apply.after_change(user(status="LOCKED", locked=True), attempt(FAIL))

    assert outcome.state == check.LOCKED
    assert "was changed" in outcome.detail


def test_a_change_under_an_open_rollover_window_says_so() -> None:
    outcome = apply.after_change(user(rollover_active=True), attempt(PASS))

    assert outcome.state == check.ROLLOVER_ACTIVE
    assert "until it closes" in outcome.detail


def test_a_verification_result_outside_the_vocabulary_is_refused() -> None:
    """Guessing which state an unknown result means is how an unconfirmed change
    becomes a promotion."""
    with pytest.raises(ValueError, match="not a verification result"):
        apply.after_change(user(), attempt("perhaps"))


def test_a_multi_line_driver_message_is_trimmed_to_one() -> None:
    """`oracledb` appends a documentation URL on its own line, and a table row
    holds one."""
    outcome = apply.after_change(user(), attempt(FAIL, detail="ORA-01017\nHelp: https://…"))

    assert "\n" not in outcome.detail


# ---------------------------------------------------------- the promotion ---


def test_a_document_promotes_only_when_every_pair_confirmed() -> None:
    """Invariant 7, stated as the gate. Some targets failing means `pending`
    stays, because promoting would advertise a password part of the estate does
    not have."""
    assert apply.summarise_document([check.IN_SYNC, check.IN_SYNC]) is True
    assert apply.summarise_document([check.IN_SYNC, check.ERROR]) is False
    assert apply.summarise_document([check.IN_SYNC, check.UNVERIFIABLE]) is False


def test_an_open_rollover_window_does_not_block_a_promotion() -> None:
    """The window means the previous password also authenticates; what a
    promotion asserts is that this database will serve the vault's value, which
    the window does not put in doubt. Refusing here would leave `pending` staged
    on every run of the default strategy."""
    assert apply.summarise_document([check.ROLLOVER_ACTIVE, check.IN_SYNC]) is True


def test_nothing_attempted_is_not_a_promotion() -> None:
    """ "No failures" is not the same fact as "every target confirmed"."""
    assert apply.summarise_document([]) is False


def test_the_promotion_is_one_patch_doing_four_things() -> None:
    """Four writes would be four versions, three of which describe a state that
    was never true."""
    entry = apply.Promotable(
        binding=binding(),
        value=Secret("new"),
        replaces=Secret("old"),
        policy="app-standard",
        targets=("appdb-dev-alpha",),
    )

    patch = apply.promotion_patch([entry], at=NOW, by="svc@host")

    assert patch["DB_CREDENTIALS"]["acme_web_user"].reveal() == "new"
    assert patch["previous"]["acme_web_user"].reveal() == "old"
    assert patch["pending"]["acme_web_user"] is None
    assert patch["rotated_at"]["acme_web_user"] == "2026-08-29T09:30:00Z"
    assert patch["rotated_by"]["acme_web_user"] == "svc@host"


def test_the_patch_never_reveals_a_password() -> None:
    """Values stay `Secret` until `apply_patch`, which holds the one permitted
    unwrapping on this path (invariant 2)."""
    entry = apply.Promotable(binding(), Secret("new"), Secret("old"), "app-standard", ("t",))

    assert "***" in repr(apply.promotion_patch([entry], at=NOW, by="svc@host"))


def test_a_first_rotation_writes_no_previous() -> None:
    """There is nothing to roll back to, and a `previous` holding nothing is a
    key that reads as a password somebody could try."""
    entry = apply.Promotable(binding(), Secret("new"), None, None, ())

    assert "previous" not in apply.promotion_patch([entry], at=NOW, by="svc@host")


def test_two_accounts_sharing_a_document_promote_in_one_patch() -> None:
    """Q7's default layout. Each account's stamps sit beside its own value, and
    every sibling is absent rather than rewritten."""
    entries = [
        apply.Promotable(binding(account), Secret(f"{account}-new"), None, "app-standard", ("t",))
        for account in ("acme_web_user", "acme_batch_user")
    ]

    patch = apply.promotion_patch(entries, at=NOW, by="svc@host")

    assert set(patch["DB_CREDENTIALS"]) == {"acme_web_user", "acme_batch_user"}
    assert set(patch["pending"]) == {"acme_web_user", "acme_batch_user"}


def test_a_binding_with_no_ref_cannot_be_promoted() -> None:
    """Silently promoting into nowhere is the failure mode worth being loud
    about."""
    entry = apply.Promotable(
        Binding(account="a", target="t", secret=None, vault="v"), Secret("x"), None, None, ()
    )

    with pytest.raises(ValueError, match="names no secret ref"):
        apply.promotion_patch([entry], at=NOW, by="svc@host")


# ---------------------------------------------------------- the exit code ---


def test_a_rollback_owes_the_vault_a_write_too() -> None:
    """`current` takes the rolled-back value and `previous` takes the one just
    removed from the database. Same patch, other direction."""
    entry = apply.Promotable(
        binding=binding(),
        value=Secret("old"),
        replaces=Secret("live"),
        policy="app-standard",
        targets=("appdb-dev-alpha",),
    )

    patch = apply.promotion_patch([entry], at=NOW, by="svc@host")

    assert patch["DB_CREDENTIALS"]["acme_web_user"].reveal() == "old"
    assert patch["previous"]["acme_web_user"].reveal() == "live"


def test_everything_confirmed_and_promoted_is_success() -> None:
    code = apply.exit_code_for([check.IN_SYNC, check.IN_SYNC], promoted=True, promotable=True)

    assert code == ExitCode.SUCCESS


def test_some_targets_confirmed_is_partial() -> None:
    """P5's exit 4, and the code that says `apply --repair` is the remedy: the
    estate is in a mixed state and re-running is not free."""
    code = apply.exit_code_for([check.IN_SYNC, check.ERROR], promoted=False, promotable=True)

    assert code == ExitCode.PARTIAL


def test_nothing_confirmed_is_failure() -> None:
    """Exit 1 means nothing changed anywhere and re-running costs nothing."""
    code = apply.exit_code_for(
        [check.ERROR, check.ACCOUNT_MISSING], promoted=False, promotable=True
    )

    assert code == ExitCode.FAILURE


def test_every_target_confirmed_and_nothing_promoted_is_still_partial() -> None:
    """UC-1 §8 case 7, the highest-severity row in its table: the database has the
    new password and the vault still advertises the old one. It must not exit 0
    just because every login passed."""
    code = apply.exit_code_for([check.IN_SYNC], promoted=False, promotable=True)

    assert code == ExitCode.PARTIAL


def test_a_repair_that_confirmed_needs_no_promotion_to_succeed() -> None:
    """Nothing was staged, so the vault already holds what it should."""
    code = apply.exit_code_for([check.IN_SYNC], promoted=False, promotable=False)

    assert code == ExitCode.SUCCESS


def test_an_empty_run_is_success() -> None:
    assert apply.exit_code_for([], promoted=True, promotable=False) == ExitCode.SUCCESS


# ------------------------------------------------- guardrail skips (#286) ---


def test_a_skipped_account_does_not_make_a_clean_run_partial() -> None:
    """§4's guardrails leave a `SKIPPED` row, and it is neither a success nor a
    failure -- it is an account this run was never going to act on.

    Counting it as unconfirmed would exit 4, which says "some of it worked, run
    `apply --repair`" about a run where everything the tool was willing to do
    succeeded and the repair would skip the same account again, every night.
    """
    code = apply.exit_code_for([check.IN_SYNC, apply.SKIPPED], promoted=True, promotable=True)

    assert code == ExitCode.SUCCESS


def test_a_run_of_nothing_but_skips_is_success() -> None:
    """The same answer an empty selection gives: nothing was eligible."""
    code = apply.exit_code_for([apply.SKIPPED, apply.SKIPPED], promoted=False, promotable=False)

    assert code == ExitCode.SUCCESS


def test_a_skip_does_not_rescue_a_run_that_failed() -> None:
    """Excluded from the denominator, not counted as a success. A run whose only
    real target errored still exits 1 -- being allowed to skip an account it was
    never going to touch does not make the failure partial."""
    code = apply.exit_code_for([check.ERROR, apply.SKIPPED], promoted=False, promotable=False)

    assert code == ExitCode.FAILURE


def test_a_skip_beside_a_failure_and_a_success_is_still_partial() -> None:
    code = apply.exit_code_for(
        [check.IN_SYNC, check.ERROR, apply.SKIPPED], promoted=False, promotable=True
    )

    assert code == ExitCode.PARTIAL


def test_the_states_are_counted_the_way_check_counts_them() -> None:
    """Two commands describing one estate must not count it two ways."""
    states = [check.IN_SYNC, check.IN_SYNC, check.ERROR]

    assert apply.counts(states) == {check.ERROR: 1, check.IN_SYNC: 2}
    assert apply.is_failure(check.ERROR) is True
    assert apply.is_inconclusive(check.LOCKED) is True

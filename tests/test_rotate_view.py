"""What a rotation prints (#284).

:mod:`sopuli.output.rotate_view` deliberately owns very little -- the result
table is `apply`'s, called rather than reimplemented -- so this file is about the
two things it does own: the selection table `--max-age-days` produces, and the
closing line that says how far the sequence got.

The closing line carries most of it, because it is the only part of the output
that describes the *sequence* rather than the accounts, and it is what somebody
scrolling a scheduled run's log reads first.
"""

from __future__ import annotations

from sopuli.check import ERROR, IN_SYNC, Outcome
from sopuli.config import Binding
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.output.rotate_view import render_rotate, render_selection_table
from sopuli.rotate import Selection


def binding(account: str = "acme_web_user", target: str = "appdb-alpha") -> Binding:
    return Binding(
        application="acme",
        account=account,
        target=target,
        vault="vault-prod",
        secret=parse_secret_ref(f"vault-prod:apps/acme/db#DB_CREDENTIALS/{account}"),
    )


def rows(state: str = IN_SYNC) -> list[tuple[Binding, Outcome, bool]]:
    return [(binding(), Outcome(state, "changed and verified"), True)]


class TestSelectionTable:
    def test_a_due_account_says_yes(self) -> None:
        table = render_selection_table([Selection(binding(), 120.0, due=True)])
        assert "yes" in "\n".join(table)
        assert "120.0d" in "\n".join(table)

    def test_a_skipped_account_carries_its_reason(self) -> None:
        """The alternative reading of a three-row run is that the selector was
        wrong, and those two have very different next actions."""
        table = render_selection_table(
            [Selection(binding(), 3.0, due=False, reason="rotated 3.0d ago, inside 90")]
        )
        assert "rotated 3.0d ago, inside 90" in "\n".join(table)

    def test_an_unknown_age_is_a_dash_and_not_a_number(self) -> None:
        """A number here could be misread as young, beside a decision that turned
        on the value being absent."""
        table = render_selection_table([Selection(binding(), None, due=False, reason="unknown")])
        assert "-" in "\n".join(table)
        assert "0d" not in "\n".join(table)


class TestClosingLine:
    def test_it_counts_documents_rather_than_accounts(self) -> None:
        """The grain both steps operate at, and the number an operator comparing
        this against a vault audit log is trying to match."""
        text = render_rotate(rows(), staged=2, promoted=2)
        assert "staged 2 documents, promoted 2 documents" in text

    def test_one_document_is_singular(self) -> None:
        text = render_rotate(rows(), staged=1, promoted=1)
        assert "staged 1 document, promoted 1 document" in text

    def test_the_window_clause_is_absent_when_it_was_not_asked_for(self) -> None:
        """``None`` and ``0`` are different facts: a run told to close windows and
        finding none is not the run that was never told to."""
        assert "closed" not in render_rotate(rows(), staged=1, promoted=1)

    def test_zero_windows_is_still_reported_when_it_was_asked_for(self) -> None:
        text = render_rotate(rows(), staged=1, promoted=1, closed=0)
        assert "closed 0 rollover windows" in text

    def test_one_window_is_singular(self) -> None:
        text = render_rotate(rows(), staged=1, promoted=1, closed=1)
        assert "closed 1 rollover window" in text

    def test_a_disagreement_names_the_accounts(self) -> None:
        """ "The vault disagreed" with no subject sends somebody to read three
        documents."""
        text = render_rotate(
            rows(), staged=1, promoted=1, disagreed=["acme_batch_user", "acme_web_user"]
        )
        assert "acme_batch_user, acme_web_user" in text

    def test_a_disagreement_is_the_last_clause(self) -> None:
        """It describes something still wrong after a table that may be entirely
        green, so it must not be buried mid-line."""
        text = render_rotate(rows(), staged=1, promoted=1, disagreed=["acme_web_user"])
        assert text.index("promoted 1 document") < text.index("read back a different")


class TestDelegation:
    def test_the_result_table_is_apply_s(self) -> None:
        """Not reimplemented: the middle of a rotation *is* an apply, and a table
        that differed would be two renderings of one operation."""
        text = render_rotate(rows(), staged=1, promoted=1)
        assert "ACCOUNT" in text
        assert "STATE" in text
        assert "acme_web_user" in text

    def test_stopped_suppresses_the_repair(self) -> None:
        """`render_apply` settles this, and passing both through is how it stays
        settled in one place rather than two."""
        text = render_rotate(
            rows(ERROR),
            staged=1,
            promoted=0,
            stopped="the lock was taken over",
            repair="sopuli creds apply --repair",
        )
        assert "the lock was taken over" in text
        assert "repair with:" not in text

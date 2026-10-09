"""What :mod:`sopuli.rotate` decides, with nothing plugged in (tier 0).

Three decisions live in that module and each has a case here that would be
expensive to reach through the command: which accounts ``--max-age-days``
selects, whether the vault agreed with what was applied, and which of UC-1 §8's
steps the exit code is describing.

The age cases carry most of the file, and the one worth reading first is
:meth:`TestSelect.test_unknown_age_is_never_due` -- it is the branch that decides what this
tool does the first night it is pointed at somebody else's estate.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from sopuli import rotate as rotation
from sopuli.check import ERROR, IN_SYNC
from sopuli.clock import to_rfc3339, utc_now
from sopuli.config import Binding
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret

NEW = Secret("Vertical-Anchor-Marble-4")
OLD = Secret("Correct-Horse-Battery-9")


def binding(account: str = "acme_web_user", target: str = "appdb-alpha") -> Binding:
    """One declared account, with the documented shared-document layout (Q7)."""
    return Binding(
        application="acme",
        account=account,
        target=target,
        vault="vault-prod",
        secret=parse_secret_ref(f"vault-prod:apps/acme/db#DB_CREDENTIALS/{account}"),
    )


def document(
    *, account: str = "acme_web_user", days: float | None = None, value: Secret = OLD
) -> dict[str, Any]:
    """One document in the mirror layout §7 describes, stamped ``days`` ago.

    ``current`` lives under the ref's field and every other stage and stamp under
    a root key of its own name -- so a stamp is ``rotated_at/<account>`` and not
    a property beside the value. Written out here rather than borrowed from the
    command's tests, because getting this shape wrong is exactly the bug
    :class:`~sopuli.payload.StageLayout` exists to prevent.

    ``days=None`` writes no stamp at all, which is the estate this tool has never
    rotated -- seeded by hand, or written by whatever came before it.
    """
    body: dict[str, Any] = {"DB_CREDENTIALS": {account: value.reveal()}}
    if days is not None:
        body["rotated_at"] = {account: to_rfc3339(utc_now() - timedelta(days=days))}
    return body


class TestSelect:
    """``--max-age-days`` reads the vault's ``rotated_at`` and only that (Q9)."""

    def test_no_limit_selects_everything(self) -> None:
        selections = rotation.select([(binding(), document(days=3))], max_age_days=None)
        assert [one.due for one in selections] == [True]
        assert selections[0].reason == ""

    def test_no_limit_still_reports_the_age(self) -> None:
        """The age is printed beside every row whether or not it filtered."""
        selections = rotation.select([(binding(), document(days=12))], max_age_days=None)
        assert selections[0].age == pytest.approx(12.0, abs=0.1)

    def test_older_than_the_limit_is_due(self) -> None:
        selections = rotation.select([(binding(), document(days=91))], max_age_days=90)
        assert selections[0].due is True

    def test_younger_than_the_limit_is_not(self) -> None:
        selections = rotation.select([(binding(), document(days=30))], max_age_days=90)
        assert selections[0].due is False
        assert "--max-age-days 90" in selections[0].reason

    def test_exactly_the_limit_is_not_due(self) -> None:
        """``exceeds`` is strict, and a rotation that ran 90 days ago to the
        second has not yet been overtaken by a 90-day schedule."""
        selections = rotation.select([(binding(), document(days=90))], max_age_days=90)
        assert selections[0].due is False

    def test_unknown_age_is_never_due(self) -> None:
        """The branch that decides what this tool does to a freshly adopted estate.

        No ``rotated_at`` anywhere is the ordinary state of a vault somebody else
        filled in. Treating unknown as infinitely old would make the first
        scheduled run rotate every credential in it, so unknown is *not*
        selected -- and the reason says so rather than leaving a blank row.
        """
        selections = rotation.select([(binding(), document(days=None))], max_age_days=90)
        assert selections[0].due is False
        assert selections[0].age is None
        assert selections[0].reason == rotation.NEVER_ROTATED

    def test_a_missing_document_is_unknown_rather_than_ancient(self) -> None:
        """A path with nothing at it is the same answer as a path with no stamp."""
        selections = rotation.select([(binding(), None)], max_age_days=90)
        assert selections[0].due is False
        assert selections[0].age is None

    def test_a_missing_document_is_due_when_nothing_filters(self) -> None:
        """A first-ever rotation: no document, no stamp, and every reason to run."""
        selections = rotation.select([(binding(), None)], max_age_days=None)
        assert selections[0].due is True

    def test_each_account_in_a_shared_document_answers_for_itself(self) -> None:
        """Per account, not per path -- one account can be rotated inside a
        document its neighbours were not (UC-1 §3)."""
        body = {
            "DB_CREDENTIALS": {"acme_web_user": OLD.reveal(), "acme_batch_user": OLD.reveal()},
            "rotated_at": {
                "acme_web_user": to_rfc3339(utc_now() - timedelta(days=120)),
                "acme_batch_user": to_rfc3339(utc_now() - timedelta(days=2)),
            },
        }
        selections = rotation.select(
            [(binding("acme_web_user"), body), (binding("acme_batch_user"), body)],
            max_age_days=90,
        )
        assert [one.due for one in selections] == [True, False]

    def test_due_keeps_the_order_it_was_given(self) -> None:
        pairs = [
            (binding(target="appdb-alpha"), document(days=100)),
            (binding(target="appdb-beta"), document(days=1)),
            (binding(target="appdb-gamma"), document(days=100)),
        ]
        due = rotation.due(rotation.select(pairs, max_age_days=90))
        assert [one.target for one in due] == ["appdb-alpha", "appdb-gamma"]

    def test_an_unparseable_stamp_is_unknown(self) -> None:
        """Somebody else's string in somebody else's document. Unknown, not zero."""
        body = {
            "DB_CREDENTIALS": {"acme_web_user": OLD.reveal()},
            "rotated_at": {"acme_web_user": "last Tuesday"},
        }
        selections = rotation.select([(binding(), body)], max_age_days=90)
        assert selections[0].age is None
        assert selections[0].due is False


class TestDisagreements:
    """§8 step 8: did the vault serve back what the run promoted?"""

    def test_agreement_is_silent(self) -> None:
        found = rotation.disagreements([(binding(), NEW, document(value=NEW))])
        assert found == ()

    def test_a_different_value_is_named(self) -> None:
        """A replica behind its primary: acknowledged the write, serving the old one."""
        found = rotation.disagreements([(binding(), NEW, document(value=OLD))])
        assert found == ("acme_web_user",)

    def test_a_missing_stage_counts_as_disagreement(self) -> None:
        """ "The vault has not got it" and "the vault has the wrong one" are the
        same fact to the application about to fetch it."""
        found = rotation.disagreements([(binding(), NEW, {"DB_CREDENTIALS": {}})])
        assert found == ("acme_web_user",)

    def test_a_missing_document_counts_as_disagreement(self) -> None:
        assert rotation.disagreements([(binding(), NEW, None)]) == ("acme_web_user",)

    def test_only_the_disagreeing_accounts_are_named(self) -> None:
        body = {"DB_CREDENTIALS": {"acme_web_user": NEW.reveal(), "acme_batch_user": OLD.reveal()}}
        found = rotation.disagreements(
            [(binding("acme_web_user"), NEW, body), (binding("acme_batch_user"), NEW, body)]
        )
        assert found == ("acme_batch_user",)

    def test_an_account_with_no_ref_is_skipped(self) -> None:
        """Nothing declared a secret for it, so there is nothing to have promoted."""
        bare = Binding(application="acme", account="acme_web_user", target="appdb-alpha")
        assert rotation.disagreements([(bare, NEW, None)]) == ()

    def test_the_module_reveals_nothing(self) -> None:
        """Invariant 2, asserted structurally rather than by reading the code.

        :class:`~sopuli.secrets.Secret` compares by value, so the comparison this
        module makes needs no ``reveal()`` -- and the file having none is what
        keeps it that way through the next edit.
        """
        source = (rotation.__file__ or "").replace("\\", "/")
        assert source.endswith("sopuli/rotate.py")
        with open(source, encoding="utf-8") as handle:
            # The dot is the point: the module's own prose says ``reveal()``
            # while having no call to it, and a bare substring would fail on the
            # sentence explaining why there is none.
            assert ".reveal()" not in handle.read()


class TestExitCode:
    """§8's failure table, in the order the run goes through it."""

    def test_a_clean_rotation_is_zero(self) -> None:
        code = rotation.exit_code_for(
            staged_failures=0, applied=[IN_SYNC], promoted=True, promotable=True, disagreed=0
        )
        assert code == ExitCode.SUCCESS

    def test_a_staging_failure_is_one_not_four(self) -> None:
        """Row 4: nothing changed in any database, so "some targets failed" would
        be describing targets this run never attempted."""
        code = rotation.exit_code_for(
            staged_failures=1, applied=[], promoted=False, promotable=False, disagreed=0
        )
        assert code == ExitCode.FAILURE

    def test_a_staging_failure_outranks_everything_after_it(self) -> None:
        code = rotation.exit_code_for(
            staged_failures=1, applied=[IN_SYNC], promoted=True, promotable=True, disagreed=2
        )
        assert code == ExitCode.FAILURE

    def test_a_read_back_disagreement_is_four(self) -> None:
        """Row 8. Every database took it and the promotion was acknowledged, so
        the estate is converged -- and the run cannot assert that applications
        will fetch what it applied."""
        code = rotation.exit_code_for(
            staged_failures=0, applied=[IN_SYNC], promoted=True, promotable=True, disagreed=1
        )
        assert code == ExitCode.PARTIAL

    def test_everything_else_is_apply_s_own_answer(self) -> None:
        """Steps 5 to 7 are `apply` doing what `apply` does, and a rotation that
        exited differently would be two commands describing one outcome twice."""
        code = rotation.exit_code_for(
            staged_failures=0,
            applied=[IN_SYNC, ERROR],
            promoted=False,
            promotable=True,
            disagreed=0,
        )
        assert code == ExitCode.PARTIAL

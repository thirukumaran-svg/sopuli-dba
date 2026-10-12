"""Reading a previous run's document back in (`creds apply --repair`).

Tier 0: a document is a JSON file and this module is pure logic over one, so
none of this needs a container. The one thing it does touch is the filesystem,
which is what `tmp_path` is for -- a run document arrives as a *path* from an
operator, and the failures worth covering are the ones a path has.

The refusals carry more weight here than the happy path. `--repair` narrows,
and invariant 5 plus `apply`'s idempotency make a stale or partly-wrong document
wasteful rather than dangerous -- so the only thing that must not get through is
a document describing a *different estate*, and the tests below spend most of
their length on that and on the shapes that are not run documents at all.
"""

from __future__ import annotations

import json
import re
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from sopuli.clock import to_rfc3339, utc_now
from sopuli.config.errors import ArgumentError
from sopuli.diagnostics import REPAIR_DOCUMENT_STALE
from sopuli.exit_codes import ExitCode
from sopuli.repair import STALE_AFTER, read, staleness

ESTATE = "/etc/sopuli/estate.yaml"


def document(
    *,
    command: str = "creds.apply",
    results: list[dict[str, Any]] | None = None,
    config_files: list[str] | None = None,
    estate: bool = True,
    finished: str | None = None,
) -> dict[str, Any]:
    """A run document with only what this flag reads.

    Deliberately not a full one: everything below has to keep working against a
    document from an older minor version, so a fixture carrying every property
    the current schema allows would hide a dependency on a new one.
    """
    invocation: dict[str, Any] = {"correlation_id": "x", "dry_run": False}
    if config_files is not None:
        invocation["config_files"] = config_files
    elif estate:
        invocation["config_files"] = [ESTATE]
    if finished is not None:
        invocation["finished_at"] = finished
    return {
        "schema_version": "1.20",
        "command": command,
        "invocation": invocation,
        "results": results if results is not None else [],
        "exit_code": 4,
    }


def written(tmp_path: Path, body: Any, name: str = "run.json") -> Path:
    path = tmp_path / name
    path.write_text(body if isinstance(body, str) else json.dumps(body), encoding="utf-8")
    return path


def row(account: str, target: str, state: str) -> dict[str, Any]:
    return {"account": account, "target": target, "state": state, "changed": False}


# ------------------------------------------------------- the repair set ---


def test_the_set_is_what_did_not_confirm(tmp_path: Path) -> None:
    path = written(
        tmp_path,
        document(
            results=[
                row("acme_web_user", "appdb-dev-alpha", "IN_SYNC"),
                row("acme_batch_user", "appdb-dev-alpha", "DRIFT"),
                row("acme_web_user", "appdb-dev-beta", "LOCKED"),
            ]
        ),
    )

    found = read(path, sources=[Path(ESTATE)])

    assert found.pairs == (
        ("acme_batch_user", "appdb-dev-alpha"),
        ("acme_web_user", "appdb-dev-beta"),
    )


def test_a_rollover_window_counts_as_confirmed(tmp_path: Path) -> None:
    """The target took the new password and both authenticate, so what remains
    is `creds finish-rollover` rather than an apply. Repairing it would spend a
    login to discover nothing was wrong."""
    path = written(tmp_path, document(results=[row("a", "t", "ROLLOVER_ACTIVE")]))

    assert read(path, sources=[Path(ESTATE)]).pairs == ()


def test_a_document_with_nothing_unconfirmed_yields_an_empty_set(tmp_path: Path) -> None:
    """Valid to hand over, and the run it produces does nothing and says so.
    Refusing would make "did my repair already happen" un-askable."""
    path = written(tmp_path, document(results=[row("a", "t", "IN_SYNC")]))

    assert read(path, sources=[Path(ESTATE)]).pairs == ()


def test_a_row_missing_a_name_is_skipped_not_refused(tmp_path: Path) -> None:
    """Both are schema-required, so a document without them is malformed in a
    way this flag has no better answer to than acting on the whole rows."""
    path = written(
        tmp_path,
        document(results=[{"state": "DRIFT"}, row("a", "t", "DRIFT")]),
    )

    assert read(path, sources=[Path(ESTATE)]).pairs == (("a", "t"),)


def staged(account: str, target: str, state: str = "PENDING_APPLY") -> dict[str, Any]:
    """A `rotate` document's staging row: `generate`'s entry, with its action."""
    entry = row(account, target, state)
    entry["changed"] = state == "PENDING_APPLY"
    entry["actions"] = [{"kind": "vault_write_pending", "applied": entry["changed"]}]
    return entry


class TestRotateDocument:
    """UC-1 §8 row 5: `apply --repair` finishes a rotation some targets missed."""

    def test_the_staging_rows_are_skipped(self, tmp_path: Path) -> None:
        """Each staging row is `PENDING_APPLY`, which is not confirmed. Counted, it
        would put the target that took the password in the set as well."""
        path = written(
            tmp_path,
            document(
                command="creds.rotate",
                results=[
                    staged("acme_web_user", "appdb-dev-alpha"),
                    staged("acme_web_user", "appdb-dev-beta"),
                    row("acme_web_user", "appdb-dev-alpha", "IN_SYNC"),
                    row("acme_web_user", "appdb-dev-beta", "ERROR"),
                ],
            ),
        )

        found = read(path, sources=[Path(ESTATE)])

        assert found.pairs == (("acme_web_user", "appdb-dev-beta"),)
        assert found.command == "creds.rotate"

    def test_a_rotation_that_stopped_at_staging_is_refused(self, tmp_path: Path) -> None:
        """No database was changed, so the set would be empty and the run would
        report `nothing to apply`. §8 row 4's recovery is another rotation."""
        path = written(
            tmp_path,
            document(
                command="creds.rotate",
                results=[staged("a", "t"), staged("b", "t", state="ERROR")],
            ),
        )

        with pytest.raises(ArgumentError) as caught:
            read(path, sources=[Path(ESTATE)])

        assert "stopped at staging" in str(caught.value)
        assert "creds rotate" in (caught.value.hint or "")

    def test_a_rotation_with_nothing_due_yields_an_empty_set(self, tmp_path: Path) -> None:
        """No rows at all is not a run that stopped at staging."""
        path = written(tmp_path, document(command="creds.rotate", results=[]))

        assert read(path, sources=[Path(ESTATE)]).pairs == ()

    def test_a_rotation_that_lost_its_lock_is_refused(self, tmp_path: Path) -> None:
        """UC-1 §8: the run holding the lock fixes it, not a re-run of this one.
        The pairs this run never reached have no apply row, so its set would
        leave them out."""
        body = document(
            command="creds.rotate",
            results=[
                staged("a", "alpha"),
                staged("a", "beta"),
                row("a", "alpha", "IN_SYNC"),
            ],
        )
        body["diagnostics"] = [{"level": "warning", "code": "SOPULI-W011", "message": "x"}]

        with pytest.raises(ArgumentError) as caught:
            read(written(tmp_path, body), sources=[Path(ESTATE)])

        assert "lost its lock" in str(caught.value)

    def test_an_apply_that_lost_its_lock_is_refused(self, tmp_path: Path) -> None:
        body = document(results=[row("a", "t", "ERROR")])
        body["diagnostics"] = [{"level": "warning", "code": "SOPULI-W011", "message": "x"}]

        with pytest.raises(ArgumentError):
            read(written(tmp_path, body), sources=[Path(ESTATE)])

    def test_diagnostics_that_are_not_a_list_are_ignored(self, tmp_path: Path) -> None:
        body = document(results=[row("a", "t", "DRIFT")])
        body["diagnostics"] = 7

        assert read(written(tmp_path, body), sources=[Path(ESTATE)]).pairs == (("a", "t"),)

    def test_pending_apply_without_the_staging_action_is_a_pair(self, tmp_path: Path) -> None:
        """`apply` reports `PENDING_APPLY` for a rollback it refused, and that row
        is a pair to repair. The staging row is told apart by its action."""
        path = written(tmp_path, document(results=[row("a", "t", "PENDING_APPLY")]))

        assert read(path, sources=[Path(ESTATE)]).pairs == (("a", "t"),)


def test_a_document_from_an_older_minor_version_is_still_readable(tmp_path: Path) -> None:
    """`03-json-output.md` §8's compatibility rule, which cuts both ways.

    Nothing here may require a property the schema marks optional, so a document
    carrying only the minimum still resolves to a repair set.
    """
    path = written(
        tmp_path,
        {
            "schema_version": "1.10",
            "command": "creds.check",
            "invocation": {"config_files": [ESTATE]},
            "results": [row("a", "t", "DRIFT")],
        },
    )

    found = read(path, sources=[Path(ESTATE)])

    assert found.pairs == (("a", "t"),)
    assert found.age is None


# ----------------------------------------------------------- refusals ---


class TestRefusals:
    """All of them exit 2, because `--repair` feeds a filter and a filter that
    does not resolve is an invocation that did not resolve (J7)."""

    def test_a_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ArgumentError) as caught:
            read(tmp_path / "nosuch.json", sources=[Path(ESTATE)])

        assert caught.value.exit_code == ExitCode.USAGE
        assert "cannot be read" in str(caught.value)

    def test_a_file_that_is_not_json(self, tmp_path: Path) -> None:
        with pytest.raises(ArgumentError) as caught:
            read(written(tmp_path, "not json at all"), sources=[Path(ESTATE)])

        assert "is not JSON" in str(caught.value)

    def test_json_that_is_not_a_run_document(self, tmp_path: Path) -> None:
        with pytest.raises(ArgumentError) as caught:
            read(written(tmp_path, {"hello": "world"}), sources=[Path(ESTATE)])

        assert "not a run document" in str(caught.value)

    def test_a_json_array(self, tmp_path: Path) -> None:
        """A list parses and has no `command`, so the type check has to come
        before the lookup rather than after it."""
        with pytest.raises(ArgumentError):
            read(written(tmp_path, [1, 2, 3]), sources=[Path(ESTATE)])

    def test_a_command_that_reports_no_repair_set(self, tmp_path: Path) -> None:
        """`creds generate` names accounts and asked no database anything, so
        every row would be unconfirmed -- which is not the same claim."""
        path = written(tmp_path, document(command="creds.generate"))

        with pytest.raises(ArgumentError) as caught:
            read(path, sources=[Path(ESTATE)])

        assert "reports no repair set" in str(caught.value)

    def test_a_document_from_a_different_estate(self, tmp_path: Path) -> None:
        """The one failure narrowing does not make harmless: the pairs may well
        exist in this estate too, and would then be acted on."""
        path = written(tmp_path, document(config_files=["/etc/sopuli/other.yaml"]))

        with pytest.raises(ArgumentError) as caught:
            read(path, sources=[Path(ESTATE)])

        assert "different configuration" in str(caught.value)
        assert "other.yaml" in str(caught.value)

    def test_a_document_naming_no_config_files(self, tmp_path: Path) -> None:
        """A document with no `invocation.config_files` is in this position.
        Refused rather than trusted: the estate check cannot be performed, and
        the check is on whether the field is there rather than on a version."""
        path = written(tmp_path, document(estate=False))

        with pytest.raises(ArgumentError) as caught:
            read(path, sources=[Path(ESTATE)])

        assert "names no usable config files" in str(caught.value)
        hint = caught.value.hint or ""
        assert "invocation.config_files" in hint
        assert "re-run" in hint
        assert not re.search(r"#\d", hint)

    def test_the_same_files_in_a_different_order_are_a_different_estate(
        self, tmp_path: Path
    ) -> None:
        """Order is the layering order (`01-configuration.md` §5), so two runs
        over the same files in the opposite order resolved different settings."""
        path = written(tmp_path, document(config_files=["/a.yaml", "/b.yaml"]))

        with pytest.raises(ArgumentError):
            read(path, sources=[Path("/b.yaml"), Path("/a.yaml")])

    def test_the_same_file_spelled_differently_is_the_same_estate(self, tmp_path: Path) -> None:
        """A scheduled run and a hand-typed repair may disagree about the
        working directory without disagreeing about the file."""
        real = tmp_path / "estate.yaml"
        real.write_text("version: 1\n", encoding="utf-8")
        path = written(tmp_path, document(config_files=[str(real)]))

        found = read(path, sources=[Path(str(real).replace("\\", "/"))])

        assert found.command == "creds.apply"

    def test_a_relative_path_in_the_document_is_not_normalised_into_a_match(
        self, tmp_path: Path
    ) -> None:
        """The estate check's whole job.

        `abspath` runs during the *repair*, so it resolves against the repairing
        run's working directory and tells you nothing about the writing run's.
        A document written in one directory with `--config estate.yaml` and
        repaired in another against a different `estate.yaml` would compare equal
        and be accepted. The producer resolves paths before writing, so a
        relative entry can only come from an older document -- and must not be
        rescued by normalising it here.
        """
        path = written(tmp_path, document(config_files=["estate.yaml"]))

        with pytest.raises(ArgumentError) as caught:
            read(path, sources=[tmp_path / "estate.yaml"])

        assert "different configuration" in str(caught.value)


class TestMalformedShapes:
    """A file this reader cannot use is exit 2 with a message, never a
    traceback. The shape check is one place, so none of these reaches an
    internal error."""

    def test_an_invocation_that_is_not_an_object(self, tmp_path: Path) -> None:
        path = written(tmp_path, {"command": "creds.apply", "invocation": "nope"})

        with pytest.raises(ArgumentError) as caught:
            read(path, sources=[Path(ESTATE)])

        assert caught.value.exit_code == ExitCode.USAGE

    def test_results_that_are_not_a_list(self, tmp_path: Path) -> None:
        path = written(
            tmp_path,
            {
                "command": "creds.apply",
                "invocation": {"config_files": [ESTATE]},
                "results": "nope",
            },
        )

        with pytest.raises(ArgumentError):
            read(path, sources=[Path(ESTATE)])

    def test_config_files_holding_something_other_than_paths(self, tmp_path: Path) -> None:
        """Reached `os.path.abspath` and raised `TypeError` before the check
        looked at the entries rather than only at the list."""
        path = written(tmp_path, document(config_files=[1, 2]))  # type: ignore[list-item]

        with pytest.raises(ArgumentError):
            read(path, sources=[Path(ESTATE)])

    def test_config_files_that_is_not_a_list(self, tmp_path: Path) -> None:
        path = written(tmp_path, document(config_files="/etc/sopuli/estate.yaml"))  # type: ignore[arg-type]

        with pytest.raises(ArgumentError):
            read(path, sources=[Path(ESTATE)])

    def test_a_non_string_command(self, tmp_path: Path) -> None:
        """This one already refused correctly -- a tuple membership test does
        not raise on a non-string -- and is kept so the shape check cannot
        regress it into one."""
        with pytest.raises(ArgumentError):
            read(written(tmp_path, {"command": 123}), sources=[Path(ESTATE)])


# --------------------------------------------- the exit code is not a filter ---


class TestExitCodeIsNotAFilter:
    """The exit code of the run that wrote a document is not a reason to refuse it.

    Refusing a producer by exit code would refuse the documents most worth
    repairing from. `apply` verifies every pair before touching it and
    invariant 5 bounds what it can reach, so accepting them costs nothing.
    """

    def test_an_apply_that_failed_everywhere_is_repairable(self, tmp_path: Path) -> None:
        """Exit 1 for `apply` is "nothing changed anywhere" (UC-1 §5) -- every
        row unconfirmed, which is precisely a repair set."""
        body = document(command="creds.apply", results=[row("a", "t", "ERROR")])
        body["exit_code"] = 1

        assert read(written(tmp_path, body), sources=[Path(ESTATE)]).pairs == (("a", "t"),)

    def test_a_check_that_could_not_reach_a_target_is_repairable(self, tmp_path: Path) -> None:
        """`check.exit_code_for` reserves 1 for a run that produced no answer
        somewhere. Retrying that pair is the remedy, not a hazard."""
        body = document(command="creds.check", results=[row("a", "t", "ERROR")])
        body["exit_code"] = 1

        assert read(written(tmp_path, body), sources=[Path(ESTATE)]).pairs == (("a", "t"),)


# ---------------------------------------------------------- staleness ---


class TestStaleness:
    """A warning and never a gate: a threshold that refused would have to be
    wrong for somebody, and the run it stopped would have been safe."""

    def _read(self, tmp_path: Path, ago: timedelta) -> Any:
        stamp = to_rfc3339(utc_now() - ago)
        return read(
            written(tmp_path, document(finished=stamp)),
            sources=[Path(ESTATE)],
        )

    def test_a_recent_document_warns_about_nothing(self, tmp_path: Path) -> None:
        assert staleness(self._read(tmp_path, timedelta(minutes=5))) is None

    def test_an_old_one_warns_and_names_its_age(self, tmp_path: Path) -> None:
        found = staleness(self._read(tmp_path, timedelta(days=11)))

        assert found is not None
        assert found.code == REPAIR_DOCUMENT_STALE
        assert found.level == "warning"
        assert "11 days" in found.message

    def test_the_boundary_does_not_warn(self, tmp_path: Path) -> None:
        assert staleness(self._read(tmp_path, STALE_AFTER - timedelta(minutes=1))) is None

    def test_hours_are_used_below_a_day(self, tmp_path: Path) -> None:
        found = staleness(self._read(tmp_path, timedelta(hours=20)))

        assert found is not None
        assert "20 hours" in found.message

    def test_a_document_with_no_timestamp_reports_no_age(self, tmp_path: Path) -> None:
        """`None` rather than zero, so "nothing to report" cannot be read as
        "fresh" by whatever asks next."""
        found = read(written(tmp_path, document()), sources=[Path(ESTATE)])

        assert found.age is None
        assert staleness(found) is None

    def test_an_unparseable_timestamp_reports_no_age(self, tmp_path: Path) -> None:
        path = written(tmp_path, document(finished="the day before yesterday"))

        assert read(path, sources=[Path(ESTATE)]).age is None

"""``--output jsonl`` at the emitter: the event stream as a contract (#9).

What a real verb streams is in ``tests/test_cli_creds_check.py``; this file is
about the stream itself -- framing, ``seq``, the two events written for the
caller, redaction, and the promise that ``run.finished`` says what the ``json``
document says. Every line is validated against the published event schema,
found from the producer's own constant for the reason ``test_run_document.py``
finds the run schema that way.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from repo_files import requires_repo
from sopuli.output.document import Diagnostic, Error, RunDocument, Summary
from sopuli.output.emit import EVENT_SCHEMA_VERSION, Emitter, OutputMode
from sopuli.secrets import Secret

EVENT_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-event-{EVENT_SCHEMA_VERSION}.schema.json"
)


@pytest.fixture(scope="module")
def validator() -> Draft202012Validator:
    schema = json.loads(EVENT_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


class FlushCountingStream(io.StringIO):
    """Counts flushes, because a stream nobody flushes is a document in pieces."""

    def __init__(self) -> None:
        super().__init__()
        self.flushes = 0

    def flush(self) -> None:
        self.flushes += 1
        super().flush()


def events(stream: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def valid(validator: Draft202012Validator, stream: io.StringIO) -> list[dict[str, Any]]:
    lines = events(stream)
    for line in lines:
        assert [error.message for error in validator.iter_errors(line)] == [], line
    return lines


def jsonl(stream: io.StringIO) -> Emitter:
    return Emitter(mode=OutputMode.JSONL, stream=stream)


def test_the_published_schema_is_the_one_this_build_emits() -> None:
    requires_repo(EVENT_SCHEMA)
    assert EVENT_SCHEMA.is_file()


@pytest.mark.parametrize("mode", [OutputMode.TEXT, OutputMode.JSON])
def test_an_event_is_a_no_op_outside_jsonl(mode: OutputMode) -> None:
    """So a verb calls it unconditionally, and cannot branch on the mode wrongly."""
    stream = io.StringIO()
    document = RunDocument.start("creds.check")

    Emitter(mode=mode, stream=stream).event(document, "target.started", target="appdb-alpha")

    assert stream.getvalue() == ""
    assert document.stream.seq == 0


def test_the_stream_opens_with_run_started_whatever_came_first(
    validator: Draft202012Validator,
) -> None:
    stream = io.StringIO()
    document = RunDocument.start("creds.check", dry_run=True)

    jsonl(stream).event(document, "target.started", target="appdb-alpha")

    first, second = valid(validator, stream)
    assert first["event"] == "run.started"
    assert first["data"] == {"command": "creds.check", "dry_run": True}
    assert second["event"] == "target.started"
    assert [first["seq"], second["seq"]] == [0, 1]
    assert first["correlation_id"] == second["correlation_id"] == document.correlation_id
    assert first["schema_version"] == EVENT_SCHEMA_VERSION


def test_seq_survives_a_new_emitter(validator: Draft202012Validator) -> None:
    """An emitter is built per call (`Invocation.emitter()`), so the counter
    cannot live on one -- a `seq` that restarted would read as truncation."""
    stream = io.StringIO()
    document = RunDocument.start("creds.check")

    for target in ("appdb-alpha", "appdb-beta"):
        jsonl(stream).event(document, "target.started", target=target)

    assert [line["seq"] for line in valid(validator, stream)] == [0, 1, 2]


def test_diagnostics_go_out_ahead_of_the_event_that_followed_them(
    validator: Draft202012Validator,
) -> None:
    stream = io.StringIO()
    document = RunDocument.start("creds.check")
    emitter = jsonl(stream)
    document.diagnostics.append(Diagnostic(level="warning", message="first", code="SOPULI-W001"))
    emitter.event(document, "plan.resolved", data={"intent": ["verify"]})
    document.diagnostics.append(
        Diagnostic(level="info", message="second", target="appdb-alpha", account="ACME_WEB_USER")
    )
    emitter.event(document, "target.started", target="appdb-alpha")

    lines = valid(validator, stream)
    assert [line["event"] for line in lines] == [
        "run.started",
        "diagnostic",
        "plan.resolved",
        "diagnostic",
        "target.started",
    ]
    assert lines[1]["level"] == "warning"
    assert lines[1]["message"] == "first"
    assert lines[1]["data"] == {"code": "SOPULI-W001"}
    assert "data" not in lines[3]
    assert lines[3]["target"] == "appdb-alpha"
    assert lines[3]["account"] == "ACME_WEB_USER"


def test_run_finished_says_what_the_document_says(validator: Draft202012Validator) -> None:
    """§1's promise, and why `_finished` reads the document's own serialisers."""
    stream = io.StringIO()
    document = RunDocument.start("creds.check")
    document.finish(3, Summary(total=2, ok=1, changed=0, failed=0, drift=1))

    jsonl(stream).emit(document, "text that jsonl never prints")

    last = valid(validator, stream)[-1]
    assert last["event"] == "run.finished"
    rendered = document.to_dict()
    assert last["data"] == {"summary": rendered["summary"], "exit_code": rendered["exit_code"]}
    assert "text that jsonl never prints" not in stream.getvalue()


def test_a_failed_run_says_why_in_run_finished(validator: Draft202012Validator) -> None:
    stream = io.StringIO()
    document = RunDocument.start("creds.check")
    document.error = Error(category="config", message="no such file", hint="check --config")
    document.finish(9)

    jsonl(stream).emit(document, "")

    started, finished = valid(validator, stream)
    assert started["event"] == "run.started"
    assert finished["data"]["exit_code"] == 9
    assert finished["data"]["error"] == document.error.to_dict()


def test_every_line_is_flushed_and_compact() -> None:
    stream = FlushCountingStream()
    document = RunDocument.start("creds.check")

    jsonl(stream).event(document, "target.started", target="appdb-alpha")

    raw = stream.getvalue().splitlines()
    assert len(raw) == 2
    assert stream.flushes >= 2
    assert all(": " not in line and "\n" not in line for line in raw)


def test_a_secret_in_a_payload_is_redacted(validator: Draft202012Validator) -> None:
    """Invariant 2 at the serialiser: the stream shares the document's encoder."""
    stream = io.StringIO()
    document = RunDocument.start("creds.check")

    jsonl(stream).event(
        document,
        "target.finished",
        account="ACME_WEB_USER",
        target="appdb-alpha",
        data={"leaked": Secret("Correct-Horse-Battery-9")},
    )

    assert "Correct-Horse-Battery-9" not in stream.getvalue()
    assert valid(validator, stream)[-1]["data"] == {"leaked": "***"}


def test_jsonl_is_a_machine_contract() -> None:
    """No colour and no spinner, whatever the terminal says -- the same answers
    `json` gets, because a consumer parses each line."""
    emitter = Emitter(mode=OutputMode.JSONL, stream=io.StringIO())

    assert emitter.is_json
    assert emitter.use_color() is False

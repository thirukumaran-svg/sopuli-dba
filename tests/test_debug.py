"""Debug output: ``--debug``, the ``sopuli`` logger, and what it must not print.

Tier 0 (``04-testing.md`` §4): in-process, no containers, no sockets.
"""

from __future__ import annotations

import io
import json
import logging
from pathlib import Path

import pytest
from click.testing import CliRunner

from sopuli.cli import cli
from sopuli.exit_codes import ExitCode
from sopuli.output.debug import PREFIX, debugging, logger
from sopuli.secrets import Secret

PASSWORD = "Tr0ub4dor_3"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def show(config_file: Path) -> list[str]:
    return ["config", "show", "--config", str(config_file)]


def debug_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith(PREFIX)]


# ------------------------------------------------------------ the logger ---


def test_a_secret_renders_as_stars_however_it_is_passed() -> None:
    """Invariant 2: the formatter is a serialiser, and a `Secret` redacts itself."""
    stream = io.StringIO()
    secret = Secret(PASSWORD)

    with debugging(True, stream=stream):
        logger("test").debug("as %s", secret)
        logger("test").debug("as %r", secret)
        logger("test").debug(f"as {secret}")

    written = stream.getvalue()
    assert PASSWORD not in written
    assert written.count("as ***") == 3


def test_a_line_names_its_area_and_indents_what_follows() -> None:
    stream = io.StringIO()

    with debugging(True, stream=stream):
        logger("oracle").debug("first\nsecond")

    first, second = stream.getvalue().splitlines()
    assert first.startswith(PREFIX)
    assert first.endswith(" oracle: first")
    assert second == "    second"


def test_without_debug_nothing_is_written(capsys: pytest.CaptureFixture[str]) -> None:
    """Not even a warning, which `logging.lastResort` would print to stderr."""
    logger("test").debug("quiet")
    logger("test").warning("still quiet")

    assert capsys.readouterr() == ("", "")


def test_the_handler_is_removed_when_the_block_ends() -> None:
    stream = io.StringIO()

    with debugging(True, stream=stream):
        pass
    logger("test").debug("after")

    assert stream.getvalue() == ""
    assert logging.getLogger("sopuli").level == logging.WARNING


def test_another_library_s_records_are_not_printed() -> None:
    """httpx logs the full request URL at INFO, and a webhook URL can hold a token.

    The handler is on the `sopuli` logger only, so a record from any other
    logger is not printed, whatever its level.
    """
    stream = io.StringIO()

    with debugging(True, stream=stream):
        logging.getLogger("httpx").warning("HTTP Request: POST https://hooks.example.com/T0KEN")
        logging.getLogger("httpcore").warning("send_request_headers.started")

    assert stream.getvalue() == ""


# --------------------------------------------------------------- the flag ---


@pytest.mark.parametrize("position", ["verb", "group"])
def test_debug_writes_to_stderr_in_either_position(
    runner: CliRunner, show: list[str], position: str
) -> None:
    argv = [*show, "--debug"] if position == "verb" else ["--debug", *show]

    result = runner.invoke(cli, argv)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    lines = debug_lines(result.stderr)
    assert any(" run: command config.show" in line for line in lines)
    assert any(" run: config " in line for line in lines)
    assert not debug_lines(result.stdout)


def test_without_debug_stderr_has_no_debug_line(runner: CliRunner, show: list[str]) -> None:
    result = runner.invoke(cli, show)

    assert result.exit_code == ExitCode.SUCCESS
    assert not debug_lines(result.stderr)


def test_the_json_document_is_unchanged_on_stdout(runner: CliRunner, show: list[str]) -> None:
    """Debug output is stderr's. stdout is still one document (invariant 12)."""
    result = runner.invoke(cli, [*show, "--debug", "--output", "json"])

    assert result.exit_code == ExitCode.SUCCESS
    assert json.loads(result.stdout)["command"] == "config.show"
    assert any(
        " run: setting output = 'json' from --output" in line for line in debug_lines(result.stderr)
    )


def test_a_failure_carries_its_traceback(runner: CliRunner, tmp_path: Path) -> None:
    """The message on stderr has no traceback. The debug output has one."""
    result = runner.invoke(
        cli, ["config", "show", "--debug", "--config", str(tmp_path / "nope.yaml")]
    )

    assert result.exit_code != ExitCode.SUCCESS
    assert "run: the run raised ConfigError" in result.stderr
    assert "    Traceback (most recent call last):" in result.stderr


def test_a_record_does_not_reach_the_root_logger() -> None:
    """`propagate` is off, so a handler that something else put on the root
    logger never sees a debug line.

    A handler of its own rather than `caplog`: pytest also attaches its capture
    handler to a logger that does not propagate, so `caplog` sees the record
    whatever this module does.
    """
    seen: list[logging.LogRecord] = []

    class Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record)

    handler = Keep()
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        with debugging(True, stream=io.StringIO()):
            logger("test").debug("only here")
    finally:
        root.removeHandler(handler)

    assert not seen


def test_debug_is_not_a_setting() -> None:
    """A plain flag, like `--color`: no variable, no config key (#629)."""
    from sopuli.settings.registry import SETTINGS

    assert not [name for name in SETTINGS if "debug" in name or "log" in name]


def test_a_cause_is_named_by_its_type_and_never_by_its_message() -> None:
    """A cause's message may hold a secret: an httpx error's holds the webhook
    URL, which `sopuli.notify.webhook` leaves out of its own message."""
    stream = io.StringIO()
    url = "https://hooks.example.com/services/T0KEN"

    with debugging(True, stream=stream):
        try:
            try:
                raise ValueError(f"cannot reach {url}")
            except ValueError as error:
                raise RuntimeError("the webhook failed") from error
        except RuntimeError:
            logger("test").debug("raised", exc_info=True)

    written = stream.getvalue()
    assert "T0KEN" not in written
    assert "RuntimeError: the webhook failed" in written
    assert "caused by builtins.ValueError" in written


def test_escape_sequences_are_removed() -> None:
    stream = io.StringIO()

    with debugging(True, stream=stream):
        logger("test").debug("\x1b[31mORA-01017\x1b[0m")

    assert "\x1b" not in stream.getvalue()
    assert stream.getvalue().rstrip().endswith("test: ORA-01017")


def test_without_debug_the_platform_is_not_asked(
    runner: CliRunner, show: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`platform.platform()` takes about 100 ms on Windows, so a run without
    `--debug` must not pay for a line it does not print."""

    def refuse() -> str:
        raise AssertionError("platform.platform() called without --debug")

    monkeypatch.setattr("platform.platform", refuse)

    result = runner.invoke(cli, show)

    assert result.exit_code == ExitCode.SUCCESS, result.output


def test_a_refusal_before_the_config_is_read_carries_its_traceback(
    runner: CliRunner, show: list[str]
) -> None:
    """`config show` does not stream, so `--output jsonl` is refused while the
    command line resolves, before the config file is read."""
    result = runner.invoke(cli, [*show, "--debug", "--output", "jsonl"])

    # `main` maps the error to exit 2; `CliRunner` stops before it.
    assert type(result.exception).__name__ == "ArgumentError"
    assert "run: the run raised ArgumentError" in result.stderr


def test_the_settings_printed_hold_no_secret() -> None:
    """Debug output prints each setting a layer supplied, with `%r`. That is
    safe for these settings, and this list is where a new one is reviewed: a
    setting that can hold a secret must not be printed as it is."""
    from sopuli.invocation import RESOLVED_SETTINGS

    assert set(RESOLVED_SETTINGS) == {
        "confirm",
        "db.connect_timeout_s",
        "db.query_timeout_s",
        "locking.break_expired",
        "output",
        "profile",
        "safety.confirm_environments",
        "safety.delivery.allowed_methods",
        "safety.dry_run",
        "safety.max_targets",
        "safety.readonly",
        "vault",
    }


def test_a_cause_keeps_its_frames() -> None:
    """The frames show where the failure happened. They are source lines, not
    values, so they are printed even where the message is not."""
    stream = io.StringIO()

    # A variable, because a frame prints its source line, and a literal there
    # would be the source line and not the message.
    message = "-".join(["secret", "bearing"])

    def deep() -> None:
        raise ValueError(message)

    with debugging(True, stream=stream):
        try:
            try:
                deep()
            except ValueError as error:
                raise RuntimeError("wrapped") from error
        except RuntimeError:
            logger("test").debug("raised", exc_info=True)

    written = stream.getvalue()
    assert "in deep" in written
    assert "secret-bearing" not in written


def test_a_suppressed_context_is_not_a_cause() -> None:
    """`raise ... from None` says the context is not the cause, as Python
    prints it."""
    stream = io.StringIO()

    with debugging(True, stream=stream):
        try:
            try:
                raise ValueError("first")
            except ValueError:
                raise RuntimeError("second") from None
        except RuntimeError:
            logger("test").debug("raised", exc_info=True)

    assert "caused by" not in stream.getvalue()


def test_a_cycle_in_the_chain_ends_the_walk() -> None:
    stream = io.StringIO()
    first = ValueError("first")
    second = RuntimeError("second")
    second.__cause__ = first
    first.__cause__ = second

    with debugging(True, stream=stream):
        logger("test").debug("raised", exc_info=(RuntimeError, second, None))

    assert stream.getvalue().count("caused by builtins.ValueError") == 1


def test_a_root_logger_at_debug_does_not_turn_it_on() -> None:
    """An embedding process or a test runner may set the root logger to DEBUG.
    The `sopuli` logger has a level of its own, so debug stays off."""
    root = logging.getLogger()
    level = root.level
    root.setLevel(logging.DEBUG)
    try:
        assert not logger("run").isEnabledFor(logging.DEBUG)
    finally:
        root.setLevel(level)

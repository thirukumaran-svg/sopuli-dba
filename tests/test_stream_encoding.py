"""Stream encoding (``sopuli.output.stream``).

Tier 0 (``04-testing.md`` §4): no containers, no database. Five of these tests
do spawn a Python subprocess, which is a deliberate exception and the only way
to get at the bug -- it needs a *real* pipe with a *real* locale encoding, and
an in-process fake cannot produce one. Each child is a one-line ``python -c``
and the whole file runs in well under a second.

``PYTHONIOENCODING=cp1252`` is what makes these portable. On Windows it is
already what a redirected stream does; on a Linux CI runner, where a pipe is
UTF-8 anyway, forcing it recreates the Windows condition rather than skipping.
It doubles as the pin on the decision to override that variable.
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import TextIO, cast

import pytest

from sopuli.output.stream import ENCODING, configure_streams, reconfigure_stream

# Inside cp1252 (an em dash) and outside it (box drawing, a check mark). The
# first only corrupts; the second is what actually kills the command. This is a
# fixture, not the tool's own prose, so the ASCII convention does not apply --
# but `!a` below still renders it as escapes when it is handed to the child, so
# no non-ASCII ever reaches a command line.
SAMPLE = "box: ┌─┐ dash — check ✓"

FIX = "from sopuli.output.stream import configure_streams; configure_streams(); "


def _run(code: str, stdin: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    """Run ``code`` in a child whose streams default to a legacy codepage."""
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "cp1252"
    env.pop("PYTHONUTF8", None)  # UTF-8 mode would defeat the point
    return subprocess.run(
        [sys.executable, "-c", code],
        input=stdin,
        capture_output=True,
        env=env,
        check=False,
    )


def test_utf8_survives_a_pipe_under_a_legacy_locale() -> None:
    """The bug, fixed: characters outside cp1252 reach the pipe intact."""
    result = _run(FIX + f"print({SAMPLE!a})")

    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert result.stdout.decode("utf-8").strip() == SAMPLE


def test_the_same_write_fails_without_the_fix() -> None:
    """The bug, unfixed.

    Without this, the test above would keep passing if ``configure_streams``
    were quietly reduced to a no-op -- on a UTF-8 runner it would prove nothing.
    The child here is identical except for the missing call, so the pair
    isolates exactly what the fix does.
    """
    result = _run(f"print({SAMPLE!a})")

    assert result.returncode != 0
    assert b"UnicodeEncodeError" in result.stderr


def test_stderr_is_reconfigured_too() -> None:
    """Errors carry ORA- codes and hints, and they go to stderr.

    A message that cannot be written is worse than one that is hard to read: the
    process would die inside its own error path.
    """
    result = _run(FIX + f"import sys; print({SAMPLE!a}, file=sys.stderr)")

    assert result.returncode == 0
    assert result.stderr.decode("utf-8").strip() == SAMPLE


def test_stdin_is_reconfigured_too() -> None:
    """Passwords arrive on stdin (invariant 1), where a mis-decode is silent.

    A cp1252 read turns a non-ASCII password into a *different* password with no
    error at all. It surfaces later as an authentication failure against the
    database, which is a long way from the cause.
    """
    result = _run(
        FIX + "import sys; print(sys.stdin.encoding); print(sys.stdin.read())",
        stdin=SAMPLE.encode("utf-8"),
    )

    assert result.returncode == 0
    encoding, value = result.stdout.decode("utf-8").splitlines()[:2]
    assert encoding.lower().replace("-", "") == "utf8"
    assert value == SAMPLE


def test_configure_streams_is_idempotent() -> None:
    """It is a boundary call; calling it twice must not raise."""
    configure_streams()
    configure_streams()


def test_a_stream_without_reconfigure_is_skipped() -> None:
    """``pythonw.exe`` has no stdout; a test runner may substitute anything."""
    assert reconfigure_stream(None) is False
    assert reconfigure_stream(cast("TextIO", object())) is False


def test_a_stream_that_accepts_reports_success() -> None:
    seen: dict[str, object] = {}

    class Accepts:
        errors = "backslashreplace"

        def reconfigure(self, **kwargs: object) -> None:
            seen.update(kwargs)

    assert reconfigure_stream(cast("TextIO", Accepts())) is True
    assert seen == {"encoding": ENCODING, "errors": "backslashreplace"}


def test_a_stream_with_no_errors_setting_is_reconfigured_anyway() -> None:
    seen: dict[str, object] = {}

    class NoErrors:
        def reconfigure(self, **kwargs: object) -> None:
            seen.update(kwargs)

    assert reconfigure_stream(cast("TextIO", NoErrors())) is True
    assert seen == {"encoding": ENCODING}


def test_the_error_handler_is_not_silently_reset() -> None:
    """``reconfigure`` resets ``errors`` to ``strict`` unless it is passed back.

    CPython gives ``sys.stderr`` ``backslashreplace`` so that writing an error
    cannot itself raise. Tightening that to ``strict`` while fixing an encoding
    crash would be an own goal, so the value is carried over -- checked here
    through a real process, since it is a property of the real streams.
    """
    result = _run(
        FIX + "import sys; print(sys.stdout.errors, sys.stderr.errors)",
    )

    assert result.returncode == 0
    stdout_errors, stderr_errors = result.stdout.decode("utf-8").split()
    assert stdout_errors == "strict"
    assert stderr_errors == "backslashreplace"


@pytest.mark.parametrize("exception", [OSError, ValueError])
def test_a_stream_that_refuses_is_skipped_rather_than_fatal(
    exception: type[Exception],
) -> None:
    """A closed or detached stream must not take the command down with it.

    ``ValueError`` is what a detached ``TextIOWrapper`` raises; ``OSError``
    covers the console handle cases.
    """

    class Refuses:
        def reconfigure(self, **_: object) -> None:
            raise exception("underlying buffer has been detached")

    assert reconfigure_stream(cast("TextIO", Refuses())) is False

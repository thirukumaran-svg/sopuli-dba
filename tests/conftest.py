"""Fixtures shared by the whole suite.

`write_config` lives here rather than under `tests/config/` because the CLI
tests need it too: every command now discovers and loads a config file, so a
test that does not supply one is at the mercy of whatever `./sopuli.yaml` or
`~/.config/sopuli/config.yaml` happens to exist on the machine running it.
Passing `--config` at an explicit path is what keeps the suite deterministic.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import pytest

#: Writes a config file and returns its path.
WriteConfig = Callable[[str], Path]

#: The smallest file the loader accepts. Enough for any test whose subject is
#: the command rather than the configuration.
MINIMAL_CONFIG = "version: 1\n"


@pytest.fixture
def write_config(tmp_path: Path) -> WriteConfig:
    """Write a config file that the P4 permission check will accept.

    On POSIX that means 0600 explicitly: pytest's tmp_path is 0700, but the file
    inside it inherits the process umask and can easily end up group-readable on
    a CI runner -- which would make every test using this fail on the permission
    check rather than on what it says it tests. On Windows the default temp ACL
    already passes, and is covered directly in test_permissions.py.
    """

    def write(text: str) -> Path:
        path = tmp_path / "sopuli.yaml"
        path.write_text(text, encoding="utf-8")
        if sys.platform != "win32":
            path.chmod(0o600)
        return path

    return write


@pytest.fixture
def config_file(write_config: WriteConfig) -> Path:
    """A valid config file, for tests that need one to exist but do not care."""
    return write_config(MINIMAL_CONFIG)

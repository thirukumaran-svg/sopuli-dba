"""Shared fixtures for the config tests."""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import pytest

#: Writes a config file and returns its path.
WriteConfig = Callable[[str], Path]


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

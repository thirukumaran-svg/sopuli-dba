"""Whether this suite is running from the sdist, and what that leaves out.

The sdist ships ``src/sopuli`` and ``tests`` and none of the repository's data:
``docs/schemas``, the design documents, ``examples/``, ``sql/``, the workflows. A
downstream packager runs the suite from it, and a test that reads one of those
files is out of reach there, not failing. So in an extracted sdist a test that
needs one skips and names the file.

**Only there.** ``PKG-INFO`` exists at the root of an sdist and never in a
checkout, so in the repository a missing file still fails exactly as it always
did. Two routes lead here: ``conftest.py`` turns a ``FileNotFoundError`` for one
of these paths into a skip, and :func:`requires_repo` covers the tests that
never open the file. Those are the guards that assert a glob found something,
or that a path exists, and they would otherwise fail on an absence that is the
sdist's design rather than a regression.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FROM_SDIST = (ROOT / "PKG-INFO").is_file()

#: The top-level paths the sdist leaves out and the suite reads.
REPO_ONLY = frozenset({"docs", "examples", "sql", "test", ".github", "CLAUDE.md"})


def repo_relative(path: str | Path) -> str | None:
    """``path`` relative to the repository root, if it is one the sdist leaves
    out; otherwise ``None``."""
    try:
        relative = Path(path).resolve().relative_to(ROOT)
    except ValueError:
        return None
    if not relative.parts or relative.parts[0] not in REPO_ONLY:
        return None
    return relative.as_posix()


def reason(relative: str) -> str:
    return f"{relative} is in the repository, not the sdist"


def requires_repo(path: Path) -> None:
    """Skip, in an sdist only, a test whose subject is ``path``."""
    if not FROM_SDIST:
        return
    relative = repo_relative(path)
    if relative is not None and not path.exists():
        pytest.skip(reason(relative))

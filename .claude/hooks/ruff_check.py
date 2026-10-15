"""PostToolUse hook: run `ruff check` on a Python file Claude has just edited.

It reports and changes nothing. `--fix` would delete an import added by one
edit before the edit that uses it, and would rewrite the file behind the
editor's back. A finding exits 2, which Claude Code shows to the model; the
edit itself has already happened.

ruff is taken from the clone's own `.venv`, then from PATH. Without either the
hook does nothing: a missing linter is not an edit's fault.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def ruff(root: Path) -> str | None:
    """The ruff to run: the clone's own first, then whatever PATH has."""
    for candidate in (root / ".venv" / "Scripts" / "ruff.exe", root / ".venv" / "bin" / "ruff"):
        if candidate.is_file():
            return str(candidate)
    return shutil.which("ruff")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return 0
    path = (payload.get("tool_input") or {}).get("file_path") or ""
    if not path.endswith(".py") or not Path(path).is_file():
        return 0
    root = Path(os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or ".").resolve()
    if not Path(path).resolve().is_relative_to(root):
        # A scratch script outside the clone is not this project's code.
        return 0
    exe = ruff(root)
    if exe is None:
        return 0
    result = subprocess.run(
        [exe, "check", "--no-fix", "--output-format", "concise", path],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return 0
    print(f"ruff check found problems in {path}:", file=sys.stderr)
    print((result.stdout or result.stderr).strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

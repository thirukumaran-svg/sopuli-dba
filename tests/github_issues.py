"""Issue states from GitHub, for the checks that run weekly rather than per pull request.

These need the network and a `gh` that is logged in, so every test using them is
skipped unless `SOPULI_CHECK_ISSUES` is set. `.github/workflows/pending-work.yml`
sets it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from functools import cache
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

needs_github = pytest.mark.skipif(
    not os.environ.get("SOPULI_CHECK_ISSUES"),
    reason="asks GitHub for issue states; set SOPULI_CHECK_ISSUES to run it",
)


def _gh(*args: str) -> str:
    if shutil.which("gh") is None:
        pytest.fail("SOPULI_CHECK_ISSUES is set and `gh` is not on PATH")
    result = subprocess.run(
        ["gh", *args], capture_output=True, text=True, encoding="utf-8", check=True, cwd=ROOT
    )
    return result.stdout


@cache
def state(issue: int) -> str:
    """`open` or `closed`. A pull request number works too, as it does on GitHub."""
    return str(json.loads(_gh("api", f"repos/{{owner}}/{{repo}}/issues/{issue}"))["state"])


def open_issues(label: str) -> set[int]:
    """The open issues that carry ``label``."""
    listed = _gh(
        "issue", "list", "--label", label, "--state", "open", "--limit", "1000", "--json", "number"
    )
    found = json.loads(listed)
    return {int(each["number"]) for each in found}

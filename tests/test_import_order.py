"""Every module can be the *first* one imported (#357).

`python -c "import sopuli.lock"` failed outright, and had since #117:
`sopuli.lock.keys` imported `SecretRef` from `sopuli.config.secret_refs`, while
`sopuli.config.sharing` imported `normalise_path` back out of `sopuli.lock.keys`.
Whichever package was entered first found the other half-built. Ten modules could
not be imported first, `sopuli.lock` among them.

**Nothing caught it, and no ordinary test could.** `sopuli.cli` imports
`sopuli.config` long before `sopuli.lock`, and so does `tests/conftest.py`, so
every run in this repository entered the cycle from the side that happens to
work. A cycle is only visible on the *first* import, which is why this file
spends a subprocess: within one interpreter the first import has already
happened by the time any assertion runs.

Who it costs is anyone outside the tool's own entry point -- a fixture, a script,
a REPL, a future consumer importing `sopuli.lock` as a library. It was found by
writing a tier-1 fixture that reached for the lock package first.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"

#: Cycles that are still here, and the issue that tracks each. **Empty** since
#: #363, which was the last one.
#:
#: Asserted **exactly** rather than as a floor, which is the half that matters:
#: fixing one fails this test until its entry is deleted, so the list cannot
#: quietly describe a repository that has moved on. It did its job once already
#: -- `sopuli.payload` sat here between #357 and #363, and deleting the entry was
#: part of closing the second. The same discipline
#: `tests/settings/test_settings_are_wired.py` uses for `inert_reason`.
KNOWN_CYCLES: dict[str, str] = {}

PROBE = """
import importlib, json, pathlib, sys

root = pathlib.Path(sys.argv[1]) / "sopuli"
names = []
for path in sorted(root.rglob("*.py")):
    parts = path.relative_to(root.parent).with_suffix("").parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    names.append(".".join(parts))

broken = {}
for name in names:
    # A clean slate, so each name is genuinely the *first* sopuli module
    # imported. Cheaper than a subprocess each and reproduces the same failure:
    # what a cycle breaks is the order modules initialise in, not the process.
    for loaded in [one for one in sys.modules if one == "sopuli" or one.startswith("sopuli.")]:
        del sys.modules[loaded]
    try:
        importlib.import_module(name)
    except Exception as error:
        broken[name] = f"{type(error).__name__}: {error}"

print(json.dumps({"checked": len(names), "broken": broken}))
"""


def _first_import_report() -> tuple[int, dict[str, str]]:
    """Import every module first, in a subprocess, and report what broke.

    A subprocess because the probe deletes `sopuli` out of `sys.modules` 123
    times, and doing that inside the test session would leave every module
    object in this suite stale -- fixtures holding classes that are no longer the
    classes anything else imports.
    """
    result = subprocess.run(
        [sys.executable, "-c", PROBE, str(SRC)],
        capture_output=True,
        text=True,
        check=False,
        env=_probe_env(),
    )
    assert result.returncode == 0, f"the probe itself failed:\n{result.stderr}"
    report = json.loads(result.stdout)
    return int(report["checked"]), dict(report["broken"])


def test_every_module_can_be_imported_first() -> None:
    """The property `python -c "import sopuli.lock"` was failing."""
    checked, broken = _first_import_report()

    assert checked > 100, "the probe found almost nothing; check the path it walks"
    assert set(broken) == set(KNOWN_CYCLES), (
        f"import cycles changed.\nbroken now: {broken}\n"
        f"known: {sorted(KNOWN_CYCLES)}\n"
        f"If you fixed one, delete its entry. If you added one, the module cannot be "
        f"imported before the package it cycles with -- which nothing in this repository "
        f"will notice, because `sopuli.cli` imports `sopuli.config` first on every run"
    )


def test_the_lock_package_imports_on_its_own() -> None:
    """#357 by name, because it is the one somebody will try again.

    Separate from the sweep above so the failure says *which* import broke rather
    than handing back a dict, and because this is the line from the issue: it is
    what a fixture, a script or a REPL does.
    """
    result = subprocess.run(
        [sys.executable, "-c", "import sopuli.lock; print(sopuli.lock.LockKey.__name__)"],
        capture_output=True,
        text=True,
        check=False,
        env=_probe_env(),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "LockKey"


def _probe_env() -> dict[str, str]:
    """The parent's environment, with ``PYTHONPATH`` pointed at this checkout.

    Explicit rather than inherited, for a reason particular to this file: the
    probe enumerates modules by walking ``src/sopuli`` and then imports them *by
    name*. Under the editable install this repository uses those are the same
    files, so today it would pass either way -- but under a plain
    ``pip install .`` the walk would describe the checkout while the imports
    resolved to site-packages, and a test whose whole subject is which module
    initialises first would be answering about a different copy without saying so.

    Written in this order because the opposite is a bug I had here: with
    ``{"PYTHONPATH": ..., **os.environ}`` a ``PYTHONPATH`` already set in the
    parent wins and the explicit value is silently discarded.
    """
    import os

    return {**os.environ, "PYTHONPATH": str(SRC)}

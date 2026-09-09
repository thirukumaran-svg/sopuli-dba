"""Rule 3: nothing in base opens a socket (ADR-006, ``04-testing.md`` §3).

**This is the only test in the suite that can see the boundary break.** The
developer environment is `sopuli-dba[all]`, so every other test passes whether or
not base is clean -- which is exactly how a convenient module-level ``import
httpx`` gets in and is discovered by a user rather than by CI.

What is asserted is ADR-006's own testable form of the property: in a base
install none of the clients the backends reach with is importable. Rather than
depending on how this machine happens to be installed, the clients are **blocked
at the import system** and every sopuli module outside a backend is imported
against that. The result is the same statement and it holds in either
environment.

The standard library's ``urllib`` and ``http.client`` are deliberately not
blocked. They are importable in every Python and no packaging rule changes that,
so the rule covers them by intent rather than by assertion: base code does not
reach the network, whatever it would reach it with.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

#: What ``sopuli-dba[oracle]``, ``sopuli-dba[hashicorp]`` and ``sopuli-dba[oci]`` install.
#: The list is the one ADR-006 names, kept here as a literal rather than derived
#: from ``BACKENDS`` on purpose: this test is the check *on* that table, and a
#: check that reads its expectation out of the thing it is checking would pass an
#: empty table.
CLIENTS = ("httpx", "oci", "oracledb")

#: A store the tool cannot reach from this interpreter, declared anyway. §3a's
#: promise in four lines: the file means the same thing on a machine that has the
#: backend and on one that does not.
CONFIG_NAMING_A_BACKEND = """version: 1
vaults:
  vault-prod:
    type: hashicorp
    mount: secret
"""

#: Run in a subprocess because the assertion is about what importing does from a
#: clean interpreter. This one is already several hundred sopuli modules deep by
#: the time it runs, so `sys.modules` here answers a different question.
PROBE = '''
import importlib
import json
import pkgutil
import sys

BLOCKED = {blocked!r}


class Blocker:
    """Refuse the vendor clients the way a base install refuses them."""

    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in BLOCKED:
            raise ModuleNotFoundError(f"blocked by the install-shape test: {{fullname}}",
                                      name=fullname)
        return None


for name in list(sys.modules):
    if name.split(".")[0] in BLOCKED:
        del sys.modules[name]
sys.meta_path.insert(0, Blocker())

import sopuli
from sopuli.driver.registry import DRIVERS
from sopuli.store.registry import BACKENDS

backends = tuple(backend.module for backend in BACKENDS.values()) + tuple(
    driver.module for driver in DRIVERS.values()
)
imported = []
for found in pkgutil.walk_packages(sopuli.__path__, "sopuli."):
    # Rule 1 puts the client import *inside* the backend module, so a backend is
    # the one place importing a client is correct. Everything else must not.
    # Drivers are backends for this purpose (#170): `sopuli.driver.oracle` is
    # where `oracledb` may be imported, and nowhere above it. Listed from the
    # registry rather than by hand, so a second driver inherits the exemption
    # instead of failing this on the day it is added.
    if any(found.name == module or found.name.startswith(module + ".") for module in backends):
        continue
    importlib.import_module(found.name)
    imported.append(found.name)

# What the *walk* pulled in, before the command runs. `walk_packages` imports a
# package in order to enumerate it, so a backend whose client import survives the
# blocker lands in sys.modules here -- which says nothing about the command. Store
# backends never showed up only because httpx is blocked and their import fails;
# a driver package with no vendor import at module scope imports perfectly well.
# The question this test asks is what the *command* loaded, so the baseline is
# subtracted rather than assumed empty.
preloaded = {{name for name in sys.modules if name in backends}}

from click.testing import CliRunner

from sopuli.cli import cli

result = CliRunner().invoke(cli, ["--config", {config!r}, "config", "validate"])
print(json.dumps({{
    "modules": len(imported),
    "exit_code": result.exit_code,
    "output": result.output,
    "loaded_backends": [
        name for name in sys.modules if name in backends and name not in preloaded
    ],
}}))
'''


def _probe(tmp_path: Path, config: str) -> dict[str, object]:
    path = tmp_path / "sopuli.yaml"
    path.write_text(config, encoding="utf-8")
    if sys.platform != "win32":
        path.chmod(0o600)

    script = PROBE.format(blocked=set(CLIENTS), config=str(path))
    finished = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=False,
    )
    assert finished.returncode == 0, finished.stderr
    return dict(json.loads(finished.stdout.strip().splitlines()[-1]))


def test_base_imports_none_of_the_backend_clients(tmp_path: Path) -> None:
    """Every sopuli module outside a backend imports with the clients blocked.

    A module-level ``import httpx`` anywhere else fails this with the name of
    the module that did it, which is the diagnosis as well as the failure.
    """
    result = _probe(tmp_path, "version: 1\n")

    assert int(str(result["modules"])) > 20  # the walk found the package, not nothing


def test_the_offline_commands_still_work_with_no_client_installed(tmp_path: Path) -> None:
    """The half of the boundary that makes it honest rather than a trick.

    A config naming a backend validates with that backend uninstalled, because
    declaring a store is config and reaching one is not (§3a). This is the
    promise ADR-006 makes about what `pip install sopuli-dba` still does.
    """
    result = _probe(tmp_path, CONFIG_NAMING_A_BACKEND)

    assert result["exit_code"] == 0
    assert "0 targets" in str(result["output"])


def test_no_backend_module_is_loaded_by_an_offline_command(tmp_path: Path) -> None:
    """Rule 1 from the other side: the registry maps to module paths and imports
    on first use, so running a command that never connects must leave every
    backend module unimported."""
    result = _probe(tmp_path, CONFIG_NAMING_A_BACKEND)

    assert result["loaded_backends"] == []


# ------------------------------------------------------------- colour (#395) ---


def test_an_unimplemented_backend_nobody_configured_is_dimmed() -> None:
    """`file`, `keyring` and `oci` are unimplemented on every run of this build.

    Colouring them would make every `doctor` look broken to somebody who
    configured none of them, which is the opposite of what the column is for.
    """
    from sopuli.install_shape import NOT_IMPLEMENTED, Component
    from sopuli.output.install_view import _status
    from sopuli.output.palette import Role
    from sopuli.output.table import Cell

    idle = Component(name="oci", status=NOT_IMPLEMENTED, configured=())

    assert _status(idle) == Cell(NOT_IMPLEMENTED, Role.MUTED)


def test_an_unimplemented_backend_somebody_configured_is_not() -> None:
    """The same status, and the run's actual failure -- exit 9, and nothing
    anybody installs will fix it. The only place in this palette where a
    status's role depends on another column, and this is what it buys."""
    from sopuli.install_shape import NOT_IMPLEMENTED, Component
    from sopuli.output.install_view import _status
    from sopuli.output.palette import Role
    from sopuli.output.table import Cell

    asked_for = Component(name="oci", status=NOT_IMPLEMENTED, configured=("vault-x",))

    assert _status(asked_for) == Cell(NOT_IMPLEMENTED, Role.BAD)

"""ADR-006 rules 1 and 2 for drivers, and the mechanism they share with stores.

The absent-driver path is what `04-testing.md` §5 asks for per backend: *resolve
a store whose extra is uninstalled and assert the whole contract -- the message
names the correct extra, the category, the code, and the exit code.* Without it
the clean error rots into a traceback the first time a module is renamed, which
no other test can see, because every other test imports the module successfully.

Nothing here depends on whether ``oracledb`` is installed on the machine running
it. That is deliberate: the developer environment is ``sopuli-dba[all]`` and CI
runs a base cell, so a test that read the real answer would assert different
things in the two places.
"""

from __future__ import annotations

import builtins
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn

import pytest

from sopuli.config.model import Config, ExpandedTarget, Target
from sopuli.config.targets import TARGET_TYPES
from sopuli.diagnostics import MISSING_DRIVER, WARNINGS, install_diagnostics
from sopuli.driver.registry import (
    DRIVER_NOT_INSTALLED,
    DRIVERS,
    DatabaseDriver,
    DriverNotImplementedError,
    DriverNotInstalledError,
    installed,
    resolve,
)
from sopuli.exit_codes import ExitCode
from sopuli.extras import MISSING_CLIENT, MISSING_MODULE, missing_kind
from sopuli.install_shape import survey
from sopuli.output.document import Diagnostic

ORACLE = DRIVERS["oracle"]


def target(name: str = "cdb1-pdb-orders", type_name: str = "oracle") -> Target:
    return Target(name=name, type=type_name, dsn="db.example.com:1521/PDB1")


def generated(name: str, *, target_set: str = "appdb") -> ExpandedTarget:
    """A target that exists because a ``target_sets:`` entry made it.

    Which is most of them: §2's own worked example writes one set and gets
    twenty-one PDBs. The warning is asserted against these rather than against
    explicit entries because that is the estate an operator actually has.
    """
    return ExpandedTarget(target=target(name), target_set=target_set)


#: A driver whose module and client are both here -- the healthy row.
#:
#: ``provides`` is ``json``, a stdlib module, and that is the whole trick: it
#: makes this constant mean *the client is present* on every machine, rather than
#: meaning whatever `oracledb`'s install state happens to be. Naming `oracledb`
#: here would make the tests below assert one thing in the developer environment,
#: which is `sopuli-dba[all]`, and another in CI's base cell -- which is the rule
#: this module's docstring already sets.
PRESENT = DatabaseDriver(
    module="sopuli.driver.oracle.session", extra="oracle", provides=frozenset({"json"})
)

#: The module is here and the client is not: `pip` fixes it, and the message says
#: so. What every one of these warnings looked like before #238.
CLIENT_MISSING = DatabaseDriver(
    module="sopuli.driver.oracle.session", extra="oracle", provides=frozenset({"no_such_client"})
)

#: No module in this build, and an extra all the same. Unreachable from the real
#: table -- ``DRIVERS`` has one entry and its module exists -- and the state the
#: day somebody adds a type to ``TARGET_TYPES`` before writing its driver.
NO_MODULE = DatabaseDriver(
    module="sopuli.driver.nowhere", extra="oracle", provides=frozenset({"no_such_client"})
)


def warnings(driver: DatabaseDriver, targets: int = 1) -> list[Diagnostic]:
    """What `config validate` says about ``targets`` targets served by ``driver``.

    Through the survey and :func:`install_diagnostics`, which since #238 is the
    only thing that answers "can this machine serve it" -- `doctor` reads the
    same function at ``level="error"``. The registries are injected for the
    reason :func:`~sopuli.install_shape.survey` takes them at all: the states
    that matter are unreachable from the real tables on any one machine.
    """
    config = Config(
        version=1,
        expanded_targets=tuple(generated(f"pdb-{index}") for index in range(targets)),
    )
    return install_diagnostics(
        survey(config, backends={}, drivers={"oracle": driver}), level="warning"
    )


# ----------------------------------------------------------- the two lists ---


def test_every_type_the_config_accepts_has_a_driver() -> None:
    """A type the config layer accepts and this one has never heard of would
    fail at connect time with a ``KeyError`` -- precisely the traceback rule 2
    exists to prevent, arriving after the plan was printed."""
    assert set(TARGET_TYPES) == set(DRIVERS)


def test_the_oracle_entry_names_the_module_that_pip_installs() -> None:
    """`oracledb`, not `python-oracledb`: Oracle calls it the second everywhere
    it is written about, and the second resolves to nothing at all."""
    assert ORACLE.provides == frozenset({"oracledb"})
    assert ORACLE.install_command == 'pip install "sopuli-dba[oracle]"'


# --------------------------------------------------------- the absent driver ---


def test_an_uninstalled_driver_is_the_whole_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    """The message names the extra, and the error carries the category, the code
    and the exit code a consumer branches on."""
    monkeypatch.setitem(sys.modules, "sopuli.driver.oracle", None)
    monkeypatch.setattr(
        "sopuli.driver.registry.importlib.import_module",
        _raising(ModuleNotFoundError("No module named 'oracledb'", name="oracledb")),
    )

    with pytest.raises(DriverNotInstalledError) as refused:
        resolve(target())

    rendered = str(refused.value)
    assert 'target "cdb1-pdb-orders"' in rendered
    assert 'pip install "sopuli-dba[oracle]"' in rendered
    assert refused.value.category == "config"
    assert refused.value.code == DRIVER_NOT_INSTALLED
    assert refused.value.exit_code == ExitCode.CONFIG_INVALID


def test_a_driver_this_build_does_not_have_never_says_pip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nothing the operator installs fixes it, so the message must not carry an
    install line. Unreachable today and written now, because the moment it
    becomes reachable is the moment somebody adds a type to ``TARGET_TYPES``."""
    monkeypatch.setitem(DRIVERS, "postgresql", DatabaseDriver(module="sopuli.driver.postgresql"))

    with pytest.raises(DriverNotImplementedError) as refused:
        resolve(target(type_name="postgresql"))

    assert "pip install" not in str(refused.value)
    assert refused.value.code is None


def test_a_bad_import_inside_the_driver_is_ours_and_is_re_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The expensive mistake a bare ``except ImportError`` makes: it sends
    somebody to `pip` forever over a typo of ours, and costs us the stack
    trace."""
    monkeypatch.setattr(
        "sopuli.driver.registry.importlib.import_module",
        _raising(
            ModuleNotFoundError(
                "No module named 'sopuli.driver.oracle.typo'", name="sopuli.driver.oracle.typo"
            )
        ),
    )

    with pytest.raises(ModuleNotFoundError):
        resolve(target())


def test_the_three_way_reading_is_the_one_the_stores_use() -> None:
    """The mechanism is shared (`sopuli/extras.py`) precisely because it is
    subtle: three different failures arrive as one exception and only one of
    them is "install the extra"."""

    def reading(missing: str) -> str | None:
        return missing_kind(
            ModuleNotFoundError(name=missing),
            module=ORACLE.module,
            provides=ORACLE.provides,
            extra=ORACLE.extra,
        )

    assert reading("oracledb") == MISSING_CLIENT
    assert reading(ORACLE.module) == MISSING_MODULE
    assert reading("something.else") is None


# ------------------------------------------------------------- the warning ---


def test_config_validate_warns_once_per_type_however_many_targets() -> None:
    """Where this parts company with the store version, and why.

    An estate generates targets by the dozen from one ``target_sets:`` entry, so
    twenty-one PDBs missing ``oracledb`` would be twenty-one identical lines
    saying to run one command. A store is written out by hand and its name is
    the thing to go and look at; a target may not appear in the file at all.
    """
    (found,) = warnings(CLIENT_MISSING, targets=3)

    assert found.code == MISSING_DRIVER
    assert found.level == "warning"
    assert "3 targets" in found.message
    assert "pdb-0" in found.message
    assert 'pip install "sopuli-dba[oracle]"' in found.message


def test_the_verb_agrees_with_the_count() -> None:
    """A warning is read by somebody already having a bad morning; it should at
    least be a sentence."""
    one = warnings(CLIENT_MISSING, targets=1)[0].message
    many = warnings(CLIENT_MISSING, targets=2)[0].message

    assert "declares type" in one
    assert "declare type" in many
    assert "declares type" not in many


def test_one_target_is_named_rather_than_counted() -> None:
    (found,) = warnings(CLIENT_MISSING, targets=1)

    assert '"pdb-0"' in found.message
    assert "1 targets" not in found.message


def test_an_unwritten_driver_is_not_sent_to_pip() -> None:
    """The store side's #238 defect, on the driver side before it can happen.

    Unreachable from the real table -- ``DRIVERS`` has one entry and its module
    exists -- and asserted anyway, because the day somebody adds ``postgresql``
    to ``TARGET_TYPES`` before writing the driver is the day this would otherwise
    start telling them to `pip install` a driver that is not written.
    """
    (found,) = warnings(NO_MODULE)

    assert found.level == "warning"
    assert found.code == MISSING_DRIVER
    assert "pip install" not in found.message
    assert "this build has no oracle driver yet" in found.message


def test_the_warning_is_a_warning_here_and_an_error_in_doctor() -> None:
    """One fact, two judgements of what it is worth (#238).

    `config validate` says the file is fine and this machine is not; `doctor`
    says it cannot reach the estate and exits 9. Both read the same survey
    through the same function, so the sentence cannot drift between them --
    which is the whole point of deleting the pair that used to compute it
    separately.
    """
    config = Config(version=1, expanded_targets=(generated("pdb-0"),))
    shape = survey(config, backends={}, drivers={"oracle": NO_MODULE})

    (as_warning,) = install_diagnostics(shape, level="warning")
    (as_error,) = install_diagnostics(shape)

    assert (as_warning.level, as_error.level) == ("warning", "error")
    assert as_warning.code == as_error.code
    assert as_warning.message == as_error.message


def test_an_installed_driver_warns_about_nothing() -> None:
    assert warnings(PRESENT) == []


def test_the_warning_is_its_own_code_and_is_registered() -> None:
    """Not a widening of ``SOPULI-W003``, whose registered description names a
    ``vaults:`` entry. One code meaning "some backend or other is missing" would
    leave a consumer unable to tell a store it cannot reach from a database it
    cannot reach, which are different outages."""
    assert MISSING_DRIVER in WARNINGS
    assert "SOPULI-20002" in WARNINGS[MISSING_DRIVER]
    assert MISSING_DRIVER != "SOPULI-W003"


# ------------------------------------------------------- asking, not importing ---

#: A vendor package whose import is *observable* -- it writes a file and says so.
#:
#: ADR-006 rule 3 is about the side effects of an import, which for an SDK can
#: mean reading a config file or reaching a metadata service. A stub is how this
#: suite gets to watch one happen: the real `oracledb` imports quietly, and on a
#: base cell it is not there to import at all.
STUB_CLIENT = """import os, pathlib

pathlib.Path(os.environ["SOPULI_IMPORT_MARKER"]).write_text("imported", encoding="utf-8")
"""

#: Run in a subprocess because the claim is about a *process* (#506). Asserting
#: ``"oracledb" not in sys.modules`` inside this session asserted it about a
#: session that has already imported whatever the tests before it imported --
#: and `pytest-randomly` decides what those were. The suite was green because
#: ``test_driver_registry`` sorts before ``test_oracle_*``, and any seed that
#: moved one Oracle module earlier reddened it: the driver fixtures
#: ``importorskip`` ``sopuli.driver.oracle.session``, which imports `oracledb` at
#: module scope on purpose (rule 1). One subprocess, and the guard is true rather
#: than order-dependent.
PROBE = """
import json
import sys

from sopuli.driver.registry import DRIVERS, installed

answer = installed(DRIVERS["oracle"])
print(json.dumps({
    "answer": answer,
    "loaded": sorted(name for name in sys.modules if name.split(".")[0] == "oracledb"),
}))
"""


def _ask_in_a_clean_interpreter(tmp_path: Path) -> tuple[dict[str, object], Path]:
    """Ask ``installed`` the question once, in a process that has imported nothing.

    The stub goes on ``PYTHONPATH``, which precedes site-packages, so it is the
    `oracledb` the probe finds whether or not the real one is installed. That is
    what keeps this module's promise -- nothing here depends on how this machine
    happens to be installed -- while still measuring the property on a base cell,
    where there would otherwise be no client to refrain from importing.
    """
    (tmp_path / "oracledb.py").write_text(STUB_CLIENT, encoding="utf-8")
    marker = tmp_path / "import-happened"
    # Prepended rather than assigned: a `PYTHONPATH` the parent set is how a
    # checkout that is not installed finds `sopuli` at all, and discarding it
    # would make this pass or fail on how the machine was set up.
    path = os.pathsep.join(filter(None, (str(tmp_path), os.environ.get("PYTHONPATH"))))

    finished = subprocess.run(
        [sys.executable, "-c", PROBE],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PYTHONPATH": path, "SOPULI_IMPORT_MARKER": str(marker)},
    )

    assert finished.returncode == 0, f"the probe itself failed:\n{finished.stderr}"
    return dict(json.loads(finished.stdout.strip().splitlines()[-1])), marker


def test_installed_answers_without_importing(tmp_path: Path) -> None:
    """ADR-006 rule 3: asking must not run a vendor package's import side
    effects, which for an SDK can mean reading a config file or reaching a
    metadata service."""
    report, marker = _ask_in_a_clean_interpreter(tmp_path)

    assert report["loaded"] == [], "asking imported the client"
    assert not marker.exists(), "asking ran the client's import side effects"


def test_the_probe_is_looking_at_a_client_it_could_have_imported(tmp_path: Path) -> None:
    """The half that keeps the test above from passing for the wrong reason.

    A probe that found no `oracledb` at all would assert that nothing was
    imported and mean nothing by it -- which is what the old in-session version
    did on a base cell, and what it did in this one on any seed that had already
    imported the real client. ``answer`` is the stub being found: `installed`
    says yes, having looked and not imported.
    """
    report, _ = _ask_in_a_clean_interpreter(tmp_path)

    assert report["answer"] is True


def test_asking_never_reaches_the_import_machinery(monkeypatch: pytest.MonkeyPatch) -> None:
    """The same rule as a property of the call, asserted in-session (#506).

    Weaker than the subprocess -- it says *this function* does not import, not
    that nothing did -- and it is here because it is the one that fails
    legibly. A rewrite of :func:`installed` that reaches for an import names
    itself here, where the subprocess reports a process state and leaves the
    reader to find out which call produced it.
    """
    real_import = builtins.__import__

    def refuse_the_client(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.split(".")[0] in ORACLE.provides:
            raise AssertionError(f"installed() imported {name!r}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse_the_client)
    monkeypatch.setattr(
        "importlib.import_module",
        _raising(AssertionError("installed() reached importlib.import_module")),
    )

    installed(ORACLE)


def _raising(exc: BaseException) -> Callable[..., NoReturn]:
    """An ``import_module`` that fails in a chosen way.

    Patching the import rather than uninstalling a package is what keeps these
    assertions the same on every machine -- the developer environment is
    ``sopuli-dba[all]`` and CI runs a base cell, so reading the real answer
    would assert different things in the two places.
    """

    def raise_it(*_args: object, **_kwargs: object) -> NoReturn:
        raise exc

    return raise_it

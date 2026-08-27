"""The ``install`` section: what this machine can serve (ADR-006 E6, #214). Tier 0.

Everything here is `find_spec` and dataclasses -- no container, no client, no
socket -- which is the property the section itself reports on and would be
embarrassing to break while testing it.

**The registries are injected, and that is the point of the parameters.** The
developer environment is `sopuli-dba[all]` and three of the four backends are
unwritten, so the two states that matter most -- configured and not installed,
installed and not configured -- cannot be produced from the real tables on the
machine this is developed on. A survey exercised only in its healthy shape is a
survey nobody has checked, which is the same trap
``tests/store/test_install_shape.py`` blocks the clients at the import system to
avoid.

The module names below are deliberately absent from this build: ``no_such_``
prefixes name a client `pip` has never heard of, and ``sopuli.store.nowhere``
names a module that does not exist. Both are answered by
:func:`importlib.util.find_spec` without importing anything, so an absent name
costs nothing and cannot accidentally succeed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

from conftest import WriteConfig
from sopuli.cli import cli
from sopuli.config.model import Config, ExpandedTarget, Target, Vault
from sopuli.diagnostics import MISSING_BACKEND, MISSING_DRIVER, install_diagnostics
from sopuli.driver.registry import DRIVERS, DatabaseDriver
from sopuli.exit_codes import ExitCode
from sopuli.install_shape import (
    INSTALLED,
    NOT_IMPLEMENTED,
    NOT_INSTALLED,
    STATUSES,
    survey,
)
from sopuli.output.document import SCHEMA_VERSION
from sopuli.output.install_view import build, render
from sopuli.store.registry import BACKENDS, Backend

SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

#: A backend this build has a module for, whose client is here. `hashicorp` is
#: the only one that is genuinely all three today.
PRESENT = Backend(module="sopuli.store.hashicorp", extra="hashicorp", provides=frozenset({"json"}))

#: The module is here and the client is not: `pip` fixes it.
CLIENT_MISSING = Backend(
    module="sopuli.store.hashicorp", extra="hashicorp", provides=frozenset({"no_such_client"})
)

#: No module in this build, and an extra all the same -- which is exactly `oci`
#: today, and the row where an install line would be a lie.
NO_MODULE = Backend(
    module="sopuli.store.nowhere", extra="oci", provides=frozenset({"no_such_client"})
)

ORACLE = DatabaseDriver(
    module="sopuli.driver.oracle.session", extra="oracle", provides=frozenset({"json"})
)


def _config(*, vaults: tuple[str, ...] = (), targets: int = 0) -> Config:
    """A config declaring `vaults` by type and `targets` oracle targets."""
    return Config(
        version=1,
        vaults=tuple(
            Vault(name=f"vault-{index}", type=type_name) for index, type_name in enumerate(vaults)
        ),
        expanded_targets=tuple(
            ExpandedTarget(
                target=Target(name=f"pdb-{index}", type="oracle", dsn="db.example.com:1521/orders"),
                target_set="appdb",
                index=index,
            )
            for index in range(targets)
        ),
    )


def _row(section: dict[str, Any], kind: str, name: str) -> dict[str, Any]:
    return next(one for one in section[kind] if one["name"] == name)


def test_every_registry_entry_gets_a_row_configured_or_not() -> None:
    """E6's whole shape: listed every run, not only on mismatch.

    A survey that reported only the disagreements would be indistinguishable, on
    a healthy machine, from a survey that did not run -- and `doctor`'s output is
    audit evidence as often as it is a diagnostic.
    """
    shape = survey(
        _config(),
        backends={"hashicorp": PRESENT, "oci": NO_MODULE},
        drivers={"oracle": ORACLE},
    )

    assert [one.name for one in shape.backends] == ["hashicorp", "oci"]
    assert [one.name for one in shape.drivers] == ["oracle"]


def test_installed_and_not_configured_is_reported() -> None:
    """The direction nothing else in the tool looks at.

    The gap between what a machine can do and what it was asked to do is worth
    seeing *before* somebody is troubleshooting inside it, which is why this is
    a row rather than an omission.
    """
    shape = survey(_config(), backends={"hashicorp": PRESENT}, drivers={"oracle": ORACLE})

    (backend,) = shape.backends
    assert backend.status == INSTALLED
    assert backend.configured == ()
    assert shape.missing == ()


def test_a_configured_backend_with_no_client_is_not_installed_and_says_what_to_run() -> None:
    shape = survey(
        _config(vaults=("hashicorp",)),
        backends={"hashicorp": CLIENT_MISSING},
        drivers={},
    )

    (backend,) = shape.backends
    assert backend.status == NOT_INSTALLED
    assert backend.configured == ("vault-0",)
    assert backend.install_command == 'pip install "sopuli-dba[hashicorp]"'
    assert shape.missing == (backend,)


def test_a_backend_this_build_has_no_module_for_carries_no_install_line() -> None:
    """The distinction that is expensive to get wrong in this direction.

    ``oci`` has an extra and no module, so asking only whether the client is
    installed would report it installable on a developer machine that has the
    SDK -- and send somebody to `pip` for something `pip` cannot supply. The
    absent ``install_command`` is the assertion: a row `pip` cannot help with
    must not carry a line that says it can.
    """
    shape = survey(_config(vaults=("oci",)), backends={"oci": NO_MODULE}, drivers={})

    (backend,) = shape.backends
    assert backend.status == NOT_IMPLEMENTED
    assert backend.install_command is None
    assert shape.missing == (backend,)


def test_an_unconfigured_backend_that_is_missing_is_not_a_failure() -> None:
    """`missing` is about the estate, not about the machine's completeness.

    Three of the four backends are unwritten in this build and nobody's config
    mentions them. A survey that counted those would fail every `doctor` run
    everywhere, which is the fastest way to teach people to ignore an exit code.
    """
    shape = survey(_config(), backends={"oci": NO_MODULE, "hashicorp": PRESENT}, drivers={})

    assert shape.missing == ()


def test_the_real_registries_answer_without_importing_a_client() -> None:
    """The defaults are wired up, and every status is one the schema allows.

    Deliberately not asserting *which* status each real entry has: that changes
    when a backend is written, and a test that had to be edited for it would be
    pinning the roadmap rather than the survey.
    """
    shape = survey(_config(vaults=("hashicorp",), targets=3))

    assert {one.name for one in shape.backends} == set(BACKENDS)
    assert {one.name for one in shape.drivers} == set(DRIVERS)
    assert all(one.status in STATUSES for one in (*shape.backends, *shape.drivers))


def test_drivers_count_their_targets_and_backends_name_their_vaults() -> None:
    """The one asymmetry in the section, and the reason for it.

    A store is written out by hand and its name is where to go and look. Targets
    are generated by the dozen from one ``target_sets:`` entry and every one of
    them is already in ``targets[]``, so naming them here would be a second copy
    of a fact the same document carries.
    """
    section = build(
        survey(
            _config(vaults=("hashicorp",), targets=21),
            backends={"hashicorp": PRESENT},
            drivers={"oracle": ORACLE},
        )
    )

    assert _row(section, "backends", "hashicorp")["vaults"] == ["vault-0"]
    assert _row(section, "drivers", "oracle")["targets"] == 21


@pytest.mark.parametrize(("count", "expected"), [(0, "-"), (1, "1 target"), (21, "21 targets")])
def test_the_target_count_reads_as_a_quantity(count: int, expected: str) -> None:
    """A bare number in a column shared with store names reads as an identifier.

    The singular is not pedantry here: "1 targets" beside a row saying
    `not_installed` is the kind of seam that makes a reader doubt the rest of the
    report.
    """
    text = "\n".join(
        render(survey(_config(targets=count), backends={}, drivers={"oracle": ORACLE}))
    )

    assert expected in text


def test_the_section_validates_against_the_schema() -> None:
    """Invariant 12, on the one shape 1.13 added."""
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator({**schema["$defs"]["install_shape"], "$defs": schema["$defs"]})
    section = build(
        survey(
            _config(vaults=("hashicorp", "oci"), targets=2),
            backends={"hashicorp": CLIENT_MISSING, "oci": NO_MODULE},
            drivers={"oracle": ORACLE},
        )
    )

    assert [f"{list(e.path)}: {e.message}" for e in validator.iter_errors(section)] == []


def test_the_text_report_shows_every_row_and_the_line_to_paste() -> None:
    lines = render(
        survey(
            _config(vaults=("hashicorp",)),
            backends={"hashicorp": CLIENT_MISSING, "oci": NO_MODULE},
            drivers={"oracle": ORACLE},
        )
    )
    text = "\n".join(lines)

    assert "install" in text
    # The unconfigured one is present too -- that is the half a healthy run
    # needs in order to be quotable as evidence.
    assert "oci" in text
    assert 'pip install "sopuli-dba[hashicorp]"' in text


def test_the_install_line_is_only_printed_for_something_the_config_asked_for() -> None:
    """A survey is not a shopping list.

    Every uninstalled extra carries a command; printing all of them would tell an
    operator to install backends their estate does not use.
    """
    text = "\n".join(render(survey(_config(), backends={"hashicorp": CLIENT_MISSING}, drivers={})))

    assert 'pip install "sopuli-dba[hashicorp]"' not in text


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _doctor(runner: CliRunner, config: Path) -> Any:
    return runner.invoke(cli, ["--config", str(config), "--output", "json", "doctor"])


def test_doctor_emits_the_section_on_a_run_with_nothing_wrong(
    runner: CliRunner, write_config: WriteConfig
) -> None:
    """The case E6 exists for: nothing is wrong and the run still says so."""
    config = write_config("version: 1\n")

    result = _doctor(runner, config)

    assert result.exit_code == ExitCode.SUCCESS
    document = json.loads(result.output)
    assert {one["name"] for one in document["install"]["backends"]} == set(BACKENDS)
    assert {one["name"] for one in document["install"]["drivers"]} == set(DRIVERS)


def test_doctor_fails_over_a_configured_backend_it_cannot_serve(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """E6: a configured-but-uninstalled backend is a `doctor` failure.

    Exit 9 rather than 1, which is E5's number for the same condition when a
    command resolves one. `doctor` reporting it with a different number would
    give the tool two answers to one question -- and 9 is the code that already
    means *fix your configuration, not your command line*, which is the actual
    remedy here.

    The registry entry is patched rather than the survey, so what runs is the
    real code path over a table that says the client is a module this
    interpreter does not have.
    """
    monkeypatch.setitem(BACKENDS, "hashicorp", CLIENT_MISSING)
    config = write_config(
        "version: 1\nvaults:\n  vault-prod:\n    type: hashicorp\n    mount: secret\n"
    )

    result = _doctor(runner, config)

    assert result.exit_code == ExitCode.CONFIG_INVALID
    document = json.loads(result.output)
    assert _row(document["install"], "backends", "hashicorp")["status"] == NOT_INSTALLED


def test_the_failure_is_not_a_warning_in_the_document(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run that exits 9 must not describe the reason as a warning.

    `config validate` warns over exactly this and exits 0 (E4); `doctor` fails.
    The two commands answer different questions and it is deliberate that they
    disagree -- but a document exiting 9 over an entry that calls itself a
    warning would be the tool disagreeing with itself.
    """
    monkeypatch.setitem(BACKENDS, "hashicorp", CLIENT_MISSING)
    config = write_config(
        "version: 1\nvaults:\n  vault-prod:\n    type: hashicorp\n    mount: secret\n"
    )

    document = json.loads(_doctor(runner, config).output)

    levels = {one["level"] for one in document["diagnostics"] if one.get("code") == "SOPULI-W003"}
    assert levels == {"error"}


def test_config_validate_still_warns_and_exits_zero(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other half of the deliberate disagreement, guarded against drift.

    Giving the two diagnostics a ``level`` is what lets `doctor` weigh this
    harder; it must not have moved `config validate` with it.
    """
    monkeypatch.setitem(BACKENDS, "hashicorp", CLIENT_MISSING)
    config = write_config(
        "version: 1\nvaults:\n  vault-prod:\n    type: hashicorp\n    mount: secret\n"
    )

    result = runner.invoke(cli, ["--config", str(config), "--output", "json", "config", "validate"])

    assert result.exit_code == ExitCode.SUCCESS
    document = json.loads(result.output)
    levels = {one["level"] for one in document["diagnostics"] if one.get("code") == "SOPULI-W003"}
    assert levels == {"warning"}
    assert "install" not in document


def test_a_component_with_no_module_is_never_told_to_run_pip() -> None:
    """The bug the first cut of this had, in the direction that misleads.

    With the `oci` SDK absent, the older `backend_diagnostics` reported
    `not installed; install it with: pip install "sopuli-dba[oci]"` -- while the
    section beside it in the same document said `not_implemented`. One document,
    two answers, and the one a reader would act on is the one that fixes nothing.
    """
    shape = survey(_config(vaults=("oci",)), backends={"oci": NO_MODULE}, drivers={})

    (found,) = install_diagnostics(shape)
    assert found.code == MISSING_BACKEND
    assert "no oci backend yet" in found.message
    assert "pip install" not in found.message


def test_a_component_with_no_module_is_still_reported_when_its_client_is_present() -> None:
    """The other half, and the one that failed silently.

    `pip install "sopuli-dba[oci]"` puts the SDK on the machine and does not add
    the backend module, because nobody has written it. The client check alone
    then says "installed", the survey says `not_implemented`, and the run exited
    9 with an empty `diagnostics` array -- a failure with no words anywhere in
    the document.

    ``provides`` names a module that is genuinely importable here, which is what
    reproduces "the client is present" without installing anything.
    """
    present_client = Backend(
        module="sopuli.store.nowhere", extra="oci", provides=frozenset({"json"})
    )
    shape = survey(_config(vaults=("oci",)), backends={"oci": present_client}, drivers={})

    assert shape.backends[0].status == NOT_IMPLEMENTED
    (found,) = install_diagnostics(shape)
    assert found.level == "error"
    assert "no oci backend yet" in found.message


def test_the_diagnostics_and_the_section_cannot_disagree() -> None:
    """One survey feeds both, which is the structural half of the fix.

    Every component the section reports as unserviceable and configured gets a
    diagnostic, and nothing else does. Asserting the correspondence rather than
    the messages is what keeps this true when the wording improves.
    """
    shape = survey(
        _config(vaults=("hashicorp", "oci"), targets=3),
        backends={"hashicorp": CLIENT_MISSING, "oci": NO_MODULE},
        drivers={"oracle": ORACLE},
    )

    found = install_diagnostics(shape)
    assert {one.code for one in found} == {MISSING_BACKEND}
    assert len(found) == len(shape.missing)
    assert all(one.level == "error" for one in found)


def test_a_missing_driver_is_counted_once_and_not_once_per_target() -> None:
    """The same reasoning `driver_diagnostics` uses, carried over.

    Twenty-one PDBs generated from one ``target_sets:`` entry would otherwise be
    twenty-one identical lines telling somebody to run one command.
    """
    absent = DatabaseDriver(
        module="sopuli.driver.oracle.session", extra="oracle", provides=frozenset({"no_such"})
    )
    shape = survey(_config(targets=21), backends={}, drivers={"oracle": absent})

    (found,) = install_diagnostics(shape)
    assert found.code == MISSING_DRIVER
    assert "21 targets" in found.message
    assert 'pip install "sopuli-dba[oracle]"' in found.message


def test_nothing_is_said_about_a_component_nobody_configured() -> None:
    shape = survey(_config(), backends={"oci": NO_MODULE}, drivers={})

    assert install_diagnostics(shape) == []

"""`sopuli doctor` against a real Oracle (#182). Tier 1.

The view is tier 0 (`test_doctor_view.py`) and the connection is tier 1 in the
driver's own tests. What is left — and what nothing else covers — is the *wiring*
between them: a config file goes in, a client is loaded, a credential is
resolved, a session is opened, and a document comes out.

That chain has one property worth a test of its own: **every part of it can fail
in a way that is the command's subject rather than its crash.** A survey exists
to be run when things are wrong, so the failure paths are asserted here beside
the working one.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from oracle_harness import Environment
from sopuli.cli import cli
from sopuli.driver.oracle.privileges import (
    FORBIDDEN_PREFIX,
    FORBIDDEN_PRIVILEGES,
    FORBIDDEN_ROLES,
)

USER = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")

PASSWORD_ENV = "SOPULI_TEST_DOCTOR_PASSWORD"


def _config(path: Path, dsn: str, *, asserted: str = "") -> Path:
    """A config file P4's permission check will accept.

    The same 0600 rule as `conftest.write_config`, applied here rather than by
    using that fixture, because it writes one fixed filename and
    `test_a_matching_assertion_is_reported_as_matching` needs two configs in one
    test. Without the chmod the file inherits the runner's umask, lands 0644, and
    every test in this module fails on "config file is accessible to others"
    rather than on what it says it tests -- which is exactly what CI showed.
    """
    path.write_text(
        f"""
version: 1
vaults:
  main:
    type: hashicorp
    addr: https://vault.example.com
    auth: {{ method: token }}
targets:
  - name: tier1-oracle
    type: oracle
    dsn: {dsn}
    environment: dev
    vault: main
    admin:
      username: {USER}
      auth: {{ method: env, password_env: {PASSWORD_ENV} }}
{asserted}
""".lstrip(),
        encoding="utf-8",
    )
    if sys.platform != "win32":
        path.chmod(0o600)
    return path


@pytest.fixture
def runner(live_oracle: Environment) -> Iterator[CliRunner]:
    """A CLI runner with the admin password where the config says to look.

    The password reaches the tool through the environment, never through argv --
    invariant 1, and `tests/test_cli_smoke.py` already fails the build if an
    option name suggests otherwise.
    """
    pytest.importorskip("oracledb")
    previous = os.environ.get(PASSWORD_ENV)
    os.environ[PASSWORD_ENV] = PASSWORD
    try:
        yield CliRunner()
    finally:
        if previous is None:
            os.environ.pop(PASSWORD_ENV, None)
        else:
            os.environ[PASSWORD_ENV] = previous


def _run(runner: CliRunner, config: Path, *extra: str) -> Any:
    return runner.invoke(cli, ["--config", str(config), *extra, "doctor"])


def _document(result: Any) -> dict[str, Any]:
    return json.loads(result.stdout)  # type: ignore[no-any-return]


def test_doctor_reaches_the_target_and_reports_what_it_is(
    runner: CliRunner, live_oracle: Environment, tmp_path: Path
) -> None:
    """The whole chain, end to end, exiting 0 because everything worked."""
    config = _config(tmp_path / "doctor.yaml", live_oracle.dsn)

    result = _run(runner, config, "--output", "json")

    assert result.exit_code == 0, result.output
    document = _document(result)
    assert document["command"] == "doctor"

    entry = document["targets"][0]
    assert entry["reachable"] is True
    assert entry["scope"]["type"] in {"pdb", "cdb_root", "non_cdb"}
    assert entry["scope"]["db_version"], "the version the database reported"
    assert entry["scope"]["read_write"] is True
    assert entry["scope"]["capabilities"], "a reachable database reports some"
    assert "asserted" not in entry, "this config claims nothing"


def test_doctor_mutates_nothing(
    runner: CliRunner, live_oracle: Environment, tmp_path: Path
) -> None:
    """The property the whole command rests on.

    Asserted through the document rather than by watching the database, because
    the claim is about what the *tool* did: a run reporting a change would be the
    bug, and `changed` is where it would show.
    """
    config = _config(tmp_path / "doctor.yaml", live_oracle.dsn)

    document = _document(_run(runner, config, "--output", "json"))

    assert document["summary"]["changed"] == 0
    assert document.get("lock") is None, "a status-shaped verb takes no lock (P5)"


def test_a_matching_assertion_is_reported_as_matching(
    runner: CliRunner, live_oracle: Environment, tmp_path: Path
) -> None:
    """Fed back what the driver itself found, so this passes on whichever
    container the lane is pointed at rather than only the default one."""
    first = _document(
        _run(runner, _config(tmp_path / "a.yaml", live_oracle.dsn), "--output", "json")
    )
    found = first["targets"][0]["scope"]

    asserted = f"    oracle: {{ scope: {found['type']}, container: {found['container']} }}"
    config = _config(tmp_path / "b.yaml", live_oracle.dsn, asserted=asserted)

    document = _document(_run(runner, config, "--output", "json"))

    assert document["targets"][0]["asserted"]["matches"] is True
    assert document["exit_code"] == 0


def test_a_wrong_assertion_is_reported_without_failing_the_connection(
    runner: CliRunner, live_oracle: Environment, tmp_path: Path
) -> None:
    """`doctor` surveys; it does not refuse.

    The connection succeeded and the claim did not hold, and both are true at
    once — so `reachable` stays true and the mismatch is reported beside it.
    Refusing here would make the command unable to describe the very estate
    problem it exists to find.
    """
    config = _config(
        tmp_path / "doctor.yaml",
        live_oracle.dsn,
        asserted="    oracle: { container: ACME_NO_SUCH_CONTAINER }",
    )

    document = _document(_run(runner, config, "--output", "json"))

    entry = document["targets"][0]
    assert entry["reachable"] is True
    assert entry["asserted"]["matches"] is False
    assert entry["asserted"]["container"] == "ACME_NO_SUCH_CONTAINER"


def test_an_unreachable_target_is_a_finding_and_the_exit_code_says_so(
    runner: CliRunner, tmp_path: Path
) -> None:
    """One dead target must not end the run, and must not exit 0 either.

    P5 exists so a scheduler can branch on the number; a survey that always
    exits 0 is one nothing can alert on.

    Loopback port 1 rather than a documentation address: a blackholed IP would
    hang for the full connect timeout, and a refused connection fails in
    milliseconds while producing the same finding.
    """
    config = _config(tmp_path / "doctor.yaml", "127.0.0.1:1/nothing")

    result = _run(runner, config, "--output", "json")

    assert result.exit_code == 1
    entry = _document(result)["targets"][0]
    assert entry["reachable"] is False
    assert entry["error"]["message"], "and it says why"


def test_the_report_is_readable_without_json(
    runner: CliRunner, live_oracle: Environment, tmp_path: Path
) -> None:
    config = _config(tmp_path / "doctor.yaml", live_oracle.dsn)

    result = _run(runner, config)

    assert result.exit_code == 0, result.output
    assert result.output.splitlines()[0] == "client"
    assert "tier1-oracle" in result.output


def _run_with_flags(runner: CliRunner, config: Path, *flags: str) -> Any:
    """`doctor` with options of its own, which `_run` cannot express.

    `_run` puts everything before the subcommand, where click reads it as a
    global option. `--check-privileges` belongs to the command.
    """
    return runner.invoke(cli, ["--config", str(config), "--output", "json", "doctor", *flags])


def test_check_privileges_finds_an_over_granted_account(
    runner: CliRunner, live_oracle: Environment, tmp_path: Path
) -> None:
    """The case the feature exists for, and the harness hands it over for free:
    these tests connect as `system`, which holds most of §3's list.

    Asserted loosely — that *something* was found and that it is a subset of the
    list — rather than on an exact set, because which privileges `system` holds
    is Oracle's business and varies by release. Pinning it would make this a test
    of the container image.
    """
    config = _config(tmp_path / "doctor.yaml", live_oracle.dsn)

    result = _run_with_flags(runner, config, "--check-privileges")

    assert result.exit_code == 0, result.output
    over_granted = _document(result)["targets"][0]["scope"]["over_granted"]
    assert over_granted, "`system` holds a great deal the tool does not need"
    assert set(over_granted) <= set(FORBIDDEN_PRIVILEGES) | set(FORBIDDEN_ROLES) | {
        privilege for privilege in over_granted if privilege.startswith(FORBIDDEN_PREFIX)
    }


def test_an_over_granted_account_warns_and_does_not_fail(
    runner: CliRunner, live_oracle: Environment, tmp_path: Path
) -> None:
    """**P5, decided in #213: warn.**

    The whole of the decision, asserted where it can regress. Failing would block
    somebody mid-incident over a condition they did not create and cannot fix
    from this side, so an over-granted account leaves the exit code alone — while
    still being impossible to miss in the text report.
    """
    config = _config(tmp_path / "doctor.yaml", live_oracle.dsn)

    result = runner.invoke(cli, ["--config", str(config), "doctor", "--check-privileges"])

    assert result.exit_code == 0, result.output
    assert "over-granted" in result.output


def test_the_audit_costs_nothing_when_it_is_not_asked_for(
    runner: CliRunner, live_oracle: Environment, tmp_path: Path
) -> None:
    """Behind a flag because it is three more round trips per target. A survey of
    twenty databases should not pay for a question nobody asked, and the field is
    absent rather than empty so a consumer can tell "not asked" from "nothing
    found"."""
    config = _config(tmp_path / "doctor.yaml", live_oracle.dsn)

    result = _run(runner, config, "--output", "json")

    assert result.exit_code == 0, result.output
    assert "over_granted" not in _document(result)["targets"][0]["scope"]

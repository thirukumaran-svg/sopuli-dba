"""The `env` admin source is flagged where it is reported. Tier 0.

P2 says the `env` source is "supported, and flagged low-assurance in output",
and §3a repeats it twice. Computing `Resolved.low_assurance` is not enough,
because the property is true of the source and the claim has to be true of every
run.

Two levels, because the claim can fail between them:

* `admin_diagnostics` decides *what a flagged source looks like in a document*,
  and is asked here without a command-line runner;
* the commands have to actually ask it. A unit test of the property cannot see
  that half, so covering the property well does not help.

The estates below use a fake driver: what is under test is what the run *says*
about a credential, which does not require a database to have accepted one.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result

from sopuli.admin import ENV, LOW_ASSURANCE, PROMPT, VAULT, Resolved
from sopuli.cli import cli
from sopuli.config.targets import ADMIN_PASSWORD_ENV, EXTERNAL
from sopuli.diagnostics import LOW_ASSURANCE_ADMIN, WARNINGS, admin_diagnostics
from sopuli.driver.protocol import Credential, PrivilegeAudit, Scope
from sopuli.secrets import Secret

WriteConfig = Callable[[str], Path]

PASSWORD = "Correct-Horse-Battery-9"

ENV_TARGET = """version: 1
targets:
  - name: orders-pdb
    type: oracle
    dsn: "db.example.com:1521/orders"
    admin: { username: C##SOPULI_SVC, auth: { method: env } }
"""

WALLET_TARGET = """version: 1
targets:
  - name: orders-pdb
    type: oracle
    dsn: ORDERS_DEV
    admin: { auth: external }
"""

#: Two targets, both reading the *same* variable. Two entries rather than one:
#: the fact is per target, and an operator fixing it fixes it per target.
TWO_ENV_TARGETS = (
    ENV_TARGET
    + """  - name: billing-pdb
    type: oracle
    dsn: "db.example.com:1521/billing"
    admin: { username: C##SOPULI_SVC, auth: { method: env } }
"""
)


def resolved(method: str) -> Resolved:
    """One `Resolved` per method, with the source string that method produces."""
    sources = {
        ENV: f"the environment variable {ADMIN_PASSWORD_ENV}",
        VAULT: "vault ref ops/dba#password",
        PROMPT: "an interactive prompt",
        EXTERNAL: "an external password store",
    }
    credential = (
        Credential(external=True)
        if method == EXTERNAL
        else Credential(username="C##SOPULI_SVC", secret=Secret(PASSWORD))
    )
    return Resolved(credential=credential, method=method, source=sources[method])


# ------------------------------------------------ what a flagged source is ---


def test_the_environment_source_is_flagged() -> None:
    notices = admin_diagnostics("orders-pdb", resolved(ENV))

    assert [one.code for one in notices] == [LOW_ASSURANCE_ADMIN]
    assert notices[0].target == "orders-pdb"
    assert notices[0].level == "warning"


def test_the_message_names_the_variable_and_not_the_method() -> None:
    """`Resolved.source` is the half an operator acts on.

    "the env method" sends nobody anywhere. The variable's name is what they
    grep their CI definitions for.
    """
    message = admin_diagnostics("orders-pdb", resolved(ENV))[0].message

    assert ADMIN_PASSWORD_ENV in message
    assert "orders-pdb" in message


@pytest.mark.parametrize("method", [VAULT, PROMPT, EXTERNAL])
def test_the_sources_p2_prefers_are_silent(method: str) -> None:
    """A warning on every source is one a reader learns to filter past."""
    assert admin_diagnostics("orders-pdb", resolved(method)) == []


def test_the_flag_follows_assurance_rather_than_the_method_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The set is the contract, so a second such source needs no new call site.

    **A synthetic second member, because there is only one.** With
    `LOW_ASSURANCE == {ENV}` every assertion about `env` is also an assertion
    about the string "env", so an implementation asking `method == ENV` passes
    the whole of the rest of this file. Asserting the set's contents and then
    looping over it would prove nothing at all.

    Putting an imaginary method in the set and asserting it is *reported* is the
    only form that fails for the coupling being wrong, because no implementation
    hard-coding `env` can flag a method it has never heard of.
    """
    assert frozenset({ENV}) == LOW_ASSURANCE, "if this changed, the synthetic below is stale"

    monkeypatch.setattr("sopuli.admin.LOW_ASSURANCE", frozenset({ENV, "carrier-pigeon"}))
    invented = Resolved(
        credential=Credential(username="C##SOPULI_SVC", secret=Secret(PASSWORD)),
        method="carrier-pigeon",
        source="a carrier pigeon",
    )

    assert [one.code for one in admin_diagnostics("orders-pdb", invented)] == [LOW_ASSURANCE_ADMIN]
    # And joining the set is all it took: nothing else moved, and the sources
    # outside it are still silent.
    assert admin_diagnostics("orders-pdb", resolved(ENV)) != []
    assert admin_diagnostics("orders-pdb", resolved(VAULT)) == []


def test_the_code_is_in_the_registry() -> None:
    """J3: nothing emits a code the registry does not describe."""
    assert LOW_ASSURANCE_ADMIN in WARNINGS


# --------------------------------------------- and the commands that report ---


class FakeSession:
    def scope(self) -> Scope:
        return Scope(type="pdb", container="ORDERS", read_write=True, capabilities=frozenset())

    def privileges(self) -> PrivilegeAudit:
        return PrivilegeAudit()

    def close(self) -> None:
        return None


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Callable[[], None]:
    def install() -> None:
        class FakeDriver:
            def __init__(self, **_: Any) -> None:
                pass

            def connect(self, target: Any, credential: Credential) -> FakeSession:
                return FakeSession()

        class FakeModule:
            OracleDriver = FakeDriver

        monkeypatch.setattr("sopuli.cli.resolve_driver", lambda target: FakeModule)

    return install


@pytest.fixture(autouse=True)
def password(monkeypatch: pytest.MonkeyPatch) -> None:
    """The variable the `env` source reads, so these runs resolve one."""
    monkeypatch.setenv(ADMIN_PASSWORD_ENV, PASSWORD)


def _doctor(runner: CliRunner, config: Path, *args: str) -> Result:
    return runner.invoke(cli, ["--config", str(config), *args, "doctor"])


def _diagnostics(result: Result) -> list[dict[str, Any]]:
    """`diagnostics` is omitted rather than emitted empty, so default to none."""
    return list(json.loads(result.output).get("diagnostics", []))


def test_doctor_reports_it_in_the_document(
    runner: CliRunner, write_config: WriteConfig, estate: Callable[[], None]
) -> None:
    """The target connected, and the document must still flag the source."""
    estate()
    config = write_config(ENV_TARGET)

    result = _doctor(runner, config, "--output", "json")
    flagged = [one for one in _diagnostics(result) if one["code"] == LOW_ASSURANCE_ADMIN]

    assert len(flagged) == 1
    assert flagged[0]["target"] == "orders-pdb"
    assert ADMIN_PASSWORD_ENV in flagged[0]["message"]
    # A flag and never a verdict: P2 supports this source.
    assert json.loads(result.output)["targets"][0]["reachable"] is True
    assert result.exit_code == 0


def test_doctor_prints_it_too(
    runner: CliRunner, write_config: WriteConfig, estate: Callable[[], None]
) -> None:
    """P2 asks for it *in output*, and text is the default output.

    A warning that exists only under `--output json` is reported to nobody who
    ran the command by hand, which is most of the people this one is for.
    """
    estate()
    config = write_config(ENV_TARGET)

    result = _doctor(runner, config)

    assert ADMIN_PASSWORD_ENV in result.output
    assert "low assurance" in result.output


def test_a_wallet_estate_is_not_flagged(
    runner: CliRunner, write_config: WriteConfig, estate: Callable[[], None]
) -> None:
    estate()
    config = write_config(WALLET_TARGET)

    result = _doctor(runner, config, "--output", "json")

    assert [one for one in _diagnostics(result) if one["code"] == LOW_ASSURANCE_ADMIN] == []


def test_one_entry_per_target(
    runner: CliRunner, write_config: WriteConfig, estate: Callable[[], None]
) -> None:
    """Two targets reading one variable are two findings, not one.

    The dedupe is per (code, target) and this is what stops it becoming per code:
    an operator fixes this target by target, and a single entry naming one of
    them would leave the other looking clean.
    """
    estate()
    config = write_config(TWO_ENV_TARGETS)

    result = _doctor(runner, config, "--output", "json")
    flagged = [one for one in _diagnostics(result) if one["code"] == LOW_ASSURANCE_ADMIN]

    assert sorted(one["target"] for one in flagged) == ["billing-pdb", "orders-pdb"]

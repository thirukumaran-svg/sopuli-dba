"""`safety.confirm_environments` asked of every mutating verb (#292).

The tier-0 half is `tests/test_safety_confirm.py`, which is about what the
setting *means*. This file is about the thing the issue was actually filed over:
the setting was decided, resolved and then never consulted, so what matters is
that **each verb consults it** — and that adding it to one verb has not left the
others behind, which is the failure #292 exists to prevent.

Two properties carry the file:

* **a refused run mutates nothing**, asserted on the store and the recorded
  statements rather than on the exit code;
* **the gate is the same gate everywhere** — one parametrised case per verb, so a
  verb added later without the gate fails here rather than shipping unguarded.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result

from sopuli.cli import cli
from sopuli.config.model import Vault
from sopuli.driver.protocol import (
    EXPIRE_PASSWORD,
    PASS,
    PASSWORD_ROLLOVER,
    ChangeResult,
    PrivilegeAudit,
    Scope,
    UserState,
    VerifyResult,
)
from sopuli.exit_codes import ExitCode
from sopuli.safety import RefusedError
from sopuli.secrets import Secret
from sopuli.store import MemoryStore, SecretStore

LIVE = "Correct-Horse-Battery-9"
STAGED = "Vertical-Anchor-Marble-4"

#: Two targets in two environments, so a selector can narrow a run *out* of the
#: listed one -- which is the case that separates "asks about the run" from
#: "asks about the estate".
CONFIG = """\
version: 1
defaults:
  policy: app-standard
  safety:
    confirm_environments: [prod]
policies:
  app-standard:
    password: { length: 24, charset: alnum, first_char: alpha }
vaults:
  vault-prod:
    type: hashicorp
    addr: https://vault-prod.example.com:8200
targets:
  - name: appdb-alpha
    type: oracle
    dsn: db-prod.example.com:1521/alpha.pdb.example.com
    environment: prod
    labels: { env: prod, tenant: alpha }
    vault: vault-prod
  - name: appdb-beta
    type: oracle
    dsn: db-dev.example.com:1521/beta.pdb.example.com
    environment: dev
    labels: { env: dev, tenant: beta }
    vault: vault-prod
applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "apps/acme/{target}#DB_CREDENTIALS/{account}"
"""

#: The same estate with nobody asking to be asked, which is what every other
#: suite in this repository is implicitly running under.
UNGUARDED = CONFIG.replace("  safety:\n    confirm_environments: [prod]\n", "")


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class FakeSession:
    def __init__(self, *, rollover: bool = False) -> None:
        self.rollover = rollover
        self.changed: list[tuple[str, str]] = []
        self.finished: list[str] = []

    def scope(self) -> Scope:
        capabilities = (
            frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}) if self.rollover else frozenset()
        )
        return Scope(type="pdb", container="ALPHA", read_write=True, capabilities=capabilities)

    def privileges(self) -> PrivilegeAudit:
        return PrivilegeAudit()

    def describe_user(self, account: str) -> UserState | None:
        return UserState(
            name=account.upper(),
            status="OPEN",
            rollover_enabled=self.rollover,
            rollover_active=self.rollover and bool(self.changed),
        )

    def require_rollover(self, account: str) -> None:
        return None

    def finish_rollover(self, account: str) -> ChangeResult:
        self.finished.append(account.upper())
        return ChangeResult(changed=True, detail="rollover window ended")

    def verify_password(self, account: str, secret: Secret, **_: Any) -> VerifyResult:
        return VerifyResult("login", PASS, latency_ms=9)

    def set_password(self, account: str, secret: Secret) -> ChangeResult:
        self.changed.append((account.upper(), secret.reveal()))
        return ChangeResult(changed=True)

    def close(self) -> None:
        return None


Harness = Callable[..., dict[str, Any]]


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Harness:
    def install(*, rollover: bool = False) -> dict[str, Any]:
        store = MemoryStore()
        for target in ("appdb-alpha", "appdb-beta"):
            store.write(
                f"apps/acme/{target}",
                {"DB_CREDENTIALS": {"acme_web_user": LIVE}, "pending": {"acme_web_user": STAGED}},
                cas=0,
            )
        sessions: list[FakeSession] = []

        def fake_connect(
            vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
        ) -> SecretStore:
            return store

        class FakeDriver:
            def __init__(self, **_: Any) -> None:
                pass

            def connect(self, target: Any, credential: Any) -> FakeSession:
                session = FakeSession(rollover=rollover)
                sessions.append(session)
                return session

        class FakeModule:
            OracleDriver = FakeDriver

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        monkeypatch.setattr("sopuli.cli.resolve_driver", lambda target: FakeModule)
        monkeypatch.setattr("sopuli.cli.admin_resolve", lambda target, **_: _credential())
        return {"store": store, "sessions": sessions}

    return install


def _credential() -> Any:
    class Resolved:
        credential = object()

    return Resolved()


def versions(harness: dict[str, Any]) -> dict[str, int]:
    """Every document's version, so "nothing was written" is one comparison."""
    return {
        path: harness["store"].read(path).version
        for path in ("apps/acme/appdb-alpha", "apps/acme/appdb-beta")
    }


def issued(harness: dict[str, Any]) -> list[tuple[str, str]]:
    return [one for session in harness["sessions"] for one in session.changed]


def radius(result: Result) -> int:
    """How many targets the run resolved to, from its own plan.

    #294's declined `max_targets` trigger is about the *radius*, so a test for it
    has to establish the radius rather than infer it from an estate that happened
    to be written to twice.
    """
    return int(json.loads(result.output)["plan"]["blast_radius"]["targets"])


def reached(result: Result) -> list[str]:
    """The environments the run resolved to, likewise."""
    return list(json.loads(result.output)["plan"]["blast_radius"]["environments"])


#: Every verb the setting governs, and the argv that reaches its mutation.
#: `creds rotate` is absent on purpose -- it asks unconditionally (UC-1 §8 step
#: 1), so the setting can only ever make its gate weaker. Its own suite covers
#: that, and a case here would assert the wrong reason for the right outcome.
VERBS = [
    pytest.param(["creds", "generate"], id="generate"),
    pytest.param(["creds", "apply"], id="apply"),
    pytest.param(["creds", "finish-rollover"], id="finish-rollover"),
]


def run(runner: CliRunner, argv: list[str], config: Path, *args: str) -> Result:
    return runner.invoke(cli, [*argv, "--config", str(config), *args])


# ------------------------------------------------------- every verb consults it ---


@pytest.mark.parametrize("argv", VERBS)
def test_an_unattended_run_into_a_listed_environment_is_refused(
    argv: list[str], runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The whole point of #292: a config that looked like protection and was not.

    `CliRunner` has no terminal, which is the scheduler's situation exactly.
    """
    harness = estate()
    before = versions(harness)
    result = run(runner, argv, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code != ExitCode.SUCCESS
    assert versions(harness) == before
    assert issued(harness) == []


@pytest.mark.parametrize("argv", VERBS)
def test_confirm_satisfies_the_setting(
    argv: list[str], runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """P5 says every mutating command supports `--confirm`, and the setting says
    these environments are not entered without an explicit yes. The flag is that
    yes given in advance -- so it satisfies the gate rather than being a second
    one that also has to pass."""
    estate()
    result = run(runner, argv, write_config(CONFIG), "--select", "tenant=alpha", "--confirm")

    assert result.exit_code == ExitCode.SUCCESS


@pytest.mark.parametrize("argv", VERBS)
def test_a_run_narrowed_out_of_the_listed_environment_is_not_gated(
    argv: list[str], runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Matched against the run, not the estate. An implementation reading the
    config rather than the blast radius would stop this, and a gate that asks
    every time is one that gets turned off."""
    estate()
    result = run(runner, argv, write_config(CONFIG), "--select", "tenant=beta")

    assert result.exit_code == ExitCode.SUCCESS


@pytest.mark.parametrize("argv", VERBS)
def test_an_unguarded_config_is_unaffected(
    argv: list[str], runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """No built-in, so an estate that never wrote the key keeps behaving exactly
    as it did -- which is every other suite in this repository."""
    estate()
    result = run(runner, argv, write_config(UNGUARDED), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.SUCCESS


@pytest.mark.parametrize("argv", VERBS)
def test_a_dry_run_is_never_gated(
    argv: list[str], runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The opposite of what `readonly` does, for the opposite reason. `readonly`
    is about whether the verb is available; this is about assent, and a preview
    is how somebody decides what to assent to. Prompting before showing the plan
    would ask for a yes to the question they ran the command to see."""
    harness = estate()
    before = versions(harness)
    result = run(runner, argv, write_config(CONFIG), "--select", "tenant=alpha", "--dry-run")

    assert result.exit_code == ExitCode.SUCCESS
    assert versions(harness) == before


# ------------------------------------------ the triggers that were declined (#294) ---
#
# P5 asked for three confirmation triggers and #294 kept one. The other two are
# **declined, not deferred**, which is a thing tests can say and prose cannot: if
# somebody later reads the absent behaviour as a gap and builds it, these fail.
#
# Both run unattended -- `CliRunner` has no terminal -- so a gate that fired would
# refuse (exit 8) rather than block on a prompt. What is asserted is the exit code
# plus the **plan**: that the run really did resolve to a prod target, or to two
# targets, so a case that quietly narrowed to nothing cannot pass by having
# nothing to be gated about. Deliberately not "the estate was written to":
# `creds finish-rollover` legitimately writes nothing when no window is open, and
# an assertion it cannot satisfy is one that gets deleted rather than fixed.


@pytest.mark.parametrize("argv", VERBS)
def test_a_prod_target_nobody_listed_is_not_prompted_for(
    argv: list[str], runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """P5's second trigger, declined: `environment: prod` is a label like any other.

    A built-in `confirm_environments: [prod]` is what that trigger amounts to, and
    `01-configuration.md` §9 forbids a built-in that joins a union ratchet — no
    layer could remove `prod` again, and §9 uses `confirm` itself as the worked
    example of that trap. So the estate below marks a target `prod`, lists
    nothing, and is not asked.

    `tenant=alpha` **is** the prod target, which is what makes this the trigger's
    case rather than a general smoke test -- and it is asserted from the plan
    rather than from a write, because `creds finish-rollover` legitimately writes
    nothing when no window is open and would pass a "the estate changed" check
    vacuously.
    """
    estate()
    result = run(
        runner, argv, write_config(UNGUARDED), "--select", "tenant=alpha", "--output", "json"
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert reached(result) == ["prod"]


@pytest.mark.parametrize("argv", VERBS)
def test_a_multi_target_run_is_not_prompted_for(
    argv: list[str], runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """P5's third trigger, declined: blast radius is not a confirmation threshold.

    "Confirmation is required when blast radius exceeds `max_targets` (default 1)"
    would make **every** multi-target mutation prompt on an estate that wrote no
    safety block — which is most estates and every other suite in this repository.
    `max_targets` is a ceiling, and `refuse_if_over_limit` already declines to read
    an unset one as a limit of anything.

    No selector, so both targets are in scope: the radius is 2 against an unset
    ceiling, which is exactly the combination the declined trigger would have
    caught. The radius is read off the plan rather than assumed -- a run that
    resolved to one target would pass the exit-code check while testing nothing.
    """
    estate()
    result = run(runner, argv, write_config(UNGUARDED), "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS
    assert radius(result) == 2


def test_the_declined_triggers_do_not_return_when_the_setting_is_present(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The combination, because the two decisions could disagree and only here.

    An estate that lists `dev` and runs against `prod` gets **no** prompt: the
    setting is what decides, and `environment: prod` contributes nothing of its
    own. A built-in that had survived as a union member would show up precisely
    here — as a gate firing on an environment the file did not name.
    """
    harness = estate()
    before = versions(harness)
    listed_dev = CONFIG.replace("confirm_environments: [prod]", "confirm_environments: [dev]")
    result = run(runner, ["creds", "apply"], write_config(listed_dev), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.SUCCESS
    assert versions(harness) != before, "`creds apply` writes, so this one can say so"


# --------------------------------------------------------------- the refusal ---


def test_the_refusal_names_the_setting_the_place_and_the_remedy(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Asserted on the exception rather than on stdout.

    `main()` is what maps a `ConfigError` to its exit code and prints it;
    `CliRunner` invokes the group, so a refusal reaches the test as the raised
    exception and stdout stays empty. Every other suite here asserts refusals the
    same way.
    """
    estate()
    result = run(runner, ["creds", "apply"], write_config(CONFIG), "--select", "tenant=alpha")

    assert isinstance(result.exception, RefusedError)
    assert "safety.confirm_environments" in str(result.exception)
    assert "prod" in str(result.exception)
    assert "--confirm" in str(result.exception.hint)


def test_the_refusal_is_a_policy_decision_and_not_a_broken_config(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Exit 8 with category `policy` through the boundary that maps it -- exit 9
    would send a scheduler to look for a defect in a file that is right."""
    estate()
    result = run(
        runner,
        ["creds", "apply"],
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--output",
        "json",
    )

    body = json.loads(result.output)
    assert body["error"]["category"] == "policy"
    assert body["exit_code"] == ExitCode.ABORTED


def test_it_refuses_before_the_database_is_reached(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 4's timing, and `readonly`'s precedent: the refusal happens at
    plan time, so a gated run spends no connection and no login attempt."""
    harness = estate()
    run(runner, ["creds", "apply"], write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"] == []


def test_a_run_spanning_both_environments_is_gated_by_the_listed_one(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """One prod target in a run of ten is still a run that reaches prod, and the
    gate is about reach rather than proportion."""
    harness = estate()
    result = run(runner, ["creds", "apply"], write_config(CONFIG))

    assert result.exit_code != ExitCode.SUCCESS
    assert issued(harness) == []


# ------------------------------------------------------------ the other gates ---


def test_force_does_not_satisfy_it(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """P3 (#89): `--force` overrides the account guardrails of §4 and never a
    safety setting. It is not a setting, has no layer to arrive on, and so has
    nothing to relax (invariant 10).

    `creds apply` gained a real `--force` in #286 -- it waives §4's *account*
    guardrails -- so this asserts the claim directly rather than relying on the
    parser to reject the flag, which is what it did when there was no such flag
    to pass. The run is accepted as valid argv and still refused by the
    confirmation gate.
    """
    estate()
    result = run(
        runner, ["creds", "apply"], write_config(CONFIG), "--select", "tenant=alpha", "--force"
    )

    assert isinstance(result.exception, RefusedError)
    assert "safety.confirm_environments" in str(result.exception)


def test_readonly_still_outranks_it(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Both refuse on exit 8, so what is asserted is that answering the weaker
    gate does not make the run available: `--confirm` satisfies confirmation and
    nothing satisfies `readonly`.

    `readonly` is set **in the file**, which is the only place it can be set --
    there is no `--readonly` flag, by design (invariant 10: a flag would be a
    layer, and a layer is something that could later be argued about).
    """
    estate()
    result = run(
        runner,
        ["creds", "apply"],
        write_config(CONFIG.replace("    confirm_environments: [prod]", "    readonly: true")),
        "--select",
        "tenant=alpha",
        "--confirm",
    )

    assert isinstance(result.exception, RefusedError)
    assert "safety.readonly" in str(result.exception)

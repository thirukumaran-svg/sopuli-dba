"""The §4 account guardrails, asked by the commands.

`sopuli/driver/guardrails.py` implements every one of
`02-oracle-privileges.md` §4's five checks. A command that did not call it
would issue `ALTER USER` against an `ORACLE_MAINTAINED` account, or one holding
`DBA`, provided the config declared it.

The unit suite is `tests/driver/test_guardrails.py`, which is about what
`review()` decides. This file is about the command: **the command asks, and
does the right thing with the answer.** Every case here asserts on the
statements the fake session recorded, because a guardrail that returns a refusal
the command then ignores looks identical in the output to one that worked.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator

from sopuli.admin import Resolved
from sopuli.apply import SKIPPED
from sopuli.cli import cli
from sopuli.config.model import Vault
from sopuli.config.targets import EXTERNAL
from sopuli.diagnostics import GUARDRAIL_UNCHECKED, PROMOTION_SKIPPED, WARNINGS
from sopuli.driver.protocol import (
    PASS,
    ChangeResult,
    Credential,
    PrivilegeAudit,
    Scope,
    UserState,
    VerifyResult,
)
from sopuli.exit_codes import ExitCode
from sopuli.output.document import SCHEMA_VERSION
from sopuli.secrets import Secret
from sopuli.store import MemoryStore, SecretStore

RUN_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

LIVE = "Correct-Horse-Battery-9"
STAGED = "Vertical-Anchor-Marble-4"

#: Two accounts on one target, so "the run does the rest of its job" is
#: observable: one is guarded and the other must still be applied.
CONFIG = """\
version: 1
defaults:
  policy: app-standard
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
applications:
  - name: acme
    accounts: [acme_web_user, acme_batch_user]
    secret_template: "apps/acme/db#DB_CREDENTIALS/{account}"
"""

#: The same estate declaring an account whose *name* is on §4 check 5's list.
#: Check 1 has to pass for check 5 to be the one doing the work, so the name has
#: to be declared -- which is the whole point: a site that genuinely runs `SCOTT`
#: says so in its config.
DECLARES_SCOTT = CONFIG.replace(
    "accounts: [acme_web_user, acme_batch_user]", "accounts: [scott, acme_batch_user]"
)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8")))


class FakeSession:
    def __init__(self, users: Mapping[str, UserState]) -> None:
        self.users = dict(users)
        self.attempts: list[str] = []
        self.changed: list[tuple[str, str]] = []

    def scope(self) -> Scope:
        return Scope(type="pdb", container="ALPHA", read_write=True, capabilities=frozenset())

    def privileges(self) -> PrivilegeAudit:
        return PrivilegeAudit()

    def describe_user(self, account: str) -> UserState | None:
        return self.users.get(account.upper())

    def require_rollover(self, account: str) -> None:
        return None

    def finish_rollover(self, account: str) -> ChangeResult:
        return ChangeResult(changed=True)

    def verify_password(self, account: str, secret: Secret, **_: Any) -> VerifyResult:
        self.attempts.append(account.upper())
        held = dict(self.changed).get(account.upper(), LIVE)
        return VerifyResult("login", PASS if secret.reveal() == held else "fail", latency_ms=9)

    def set_password(self, account: str, secret: Secret) -> ChangeResult:
        self.changed.append((account.upper(), secret.reveal()))
        return ChangeResult(changed=True)

    def close(self) -> None:
        return None


def account(name: str, **fields: Any) -> UserState:
    """One account as the database would describe it, guardrail fields included.

    ``password_file_member`` defaults to ``False`` -- *asked and answered* -- so
    that a case about check 2 or check 4 is not also a case about check 3 having
    no input. The estate that cannot answer is its own fixture below, because
    that is a separate fact about a run and deserves to be asserted rather than
    arrive as a side effect of every other test.
    """
    return UserState(**{"name": name, "status": "OPEN", "password_file_member": False, **fields})


#: An ordinary application account: nothing §4 objects to.
def ordinary(name: str = "ACME_WEB_USER") -> UserState:
    return account(name, vendor_maintained=False)


Harness = Callable[..., dict[str, Any]]


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Harness:
    def install(
        users: Mapping[str, UserState],
        *,
        document: dict[str, Any] | None = None,
        session: type[FakeSession] = FakeSession,
        by_target: Mapping[str, Mapping[str, UserState]] | None = None,
    ) -> dict[str, Any]:
        store = MemoryStore()
        store.write(
            "apps/acme/db",
            document
            or {
                "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
                "pending": {"acme_web_user": STAGED, "acme_batch_user": STAGED},
            },
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
                opened = session(by_target[target.name] if by_target else users)
                sessions.append(opened)
                return opened

        class FakeModule:
            OracleDriver = FakeDriver

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        monkeypatch.setattr("sopuli.cli.resolve_driver", lambda target: FakeModule)
        monkeypatch.setattr("sopuli.cli.admin_resolve", lambda target, **_: _credential())
        return {"store": store, "sessions": sessions}

    return install


def _credential() -> Any:
    """The admin credential the CLI would have resolved.

    A real :class:`~sopuli.admin.Resolved` rather than a stub with one attribute.
    The command reads its *provenance* as well as its value -- it reports
    where an admin credential came from -- and a stub stops being enough the
    moment anything but `.credential` is read. `external` because these estates
    declare no `admin:` block at all, and it is the one source that carries
    neither a username nor a secret.
    """
    return Resolved(
        credential=Credential(external=True),
        method=EXTERNAL,
        source="an external password store",
    )


def run(runner: CliRunner, config: Path, *args: str) -> Result:
    return runner.invoke(cli, ["creds", "apply", "--config", str(config), *args])


def document(result: Result) -> dict[str, Any]:
    return dict(json.loads(result.output))


def changed(harness: dict[str, Any]) -> list[str]:
    return [name for session in harness["sessions"] for name, _ in session.changed]


def states(result: Result) -> dict[str, str]:
    return {entry["account"]: entry["state"] for entry in document(result)["results"]}


# ---------------------------------------------------------- the checks fire ---


def test_a_vendor_maintained_account_is_not_touched(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """§4 check 2: no DDL is issued against a vendor-maintained account."""
    harness = estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert "ACME_WEB_USER" not in changed(harness)
    assert states(result)["acme_web_user"] == SKIPPED


def test_an_account_holding_dba_is_not_touched(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """§4 check 4. `describe_user` reads roles unconditionally for this reason --
    a lazy read would give an empty `roles` that looks exactly like an account
    holding none."""
    harness = estate(
        {
            "ACME_WEB_USER": account(
                "ACME_WEB_USER", vendor_maintained=False, roles=frozenset({"DBA"})
            ),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert "ACME_WEB_USER" not in changed(harness)
    guarded = next(one for one in document(result)["results"] if one["account"] == "acme_web_user")
    assert guarded["state"] == SKIPPED
    assert "DBA" in json.dumps(guarded)


def test_the_deny_list_covers_a_version_that_cannot_answer(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """§4 check 5, which runs only where check 2 said nothing -- 11.2, where
    `ORACLE_MAINTAINED` does not exist and `vendor_maintained` is `None`."""
    harness = estate(
        {
            "SCOTT": account("SCOTT", vendor_maintained=None),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        },
        document={
            "DB_CREDENTIALS": {"scott": LIVE, "acme_batch_user": LIVE},
            "pending": {"scott": STAGED, "acme_batch_user": STAGED},
        },
    )
    run(runner, write_config(DECLARES_SCOTT))

    assert "SCOTT" not in changed(harness)
    assert "ACME_BATCH_USER" in changed(harness)


def test_a_version_that_answers_overrules_the_deny_list(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """§4: "where the database can report ORACLE_MAINTAINED, that answer wins
    outright -- including when it says *no* about a name on the list". Sites do
    call an account `SCOTT`."""
    harness = estate(
        {
            "SCOTT": account("SCOTT", vendor_maintained=False),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        },
        document={
            "DB_CREDENTIALS": {"scott": LIVE, "acme_batch_user": LIVE},
            "pending": {"scott": STAGED, "acme_batch_user": STAGED},
        },
    )
    run(runner, write_config(DECLARES_SCOTT))

    assert "SCOTT" in changed(harness)


# ------------------------------------------------- the run does the rest ---


def test_the_other_accounts_are_still_applied(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """§4's rule: an account that fell inside a broad selection is SKIPPED and
    the run does the rest of its job. Refusing 200 rotations because the 47th
    account was ORACLE_MAINTAINED would make the guardrail more disruptive than
    the mistake it caught."""
    harness = estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    run(runner, write_config(CONFIG))

    assert changed(harness) == ["ACME_BATCH_USER"]


def test_a_skipped_account_costs_no_login(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The check runs before the first verification, not before the statement.

    An account the tool will not touch must not spend an attempt against a
    lockout counter -- which is the same argument UC-1 §7 makes for every login
    this tool budgets.
    """
    harness = estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    run(runner, write_config(CONFIG))

    attempted = [name for session in harness["sessions"] for name in session.attempts]
    assert "ACME_WEB_USER" not in attempted


def test_a_skipped_account_does_not_make_the_run_partial(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A guardrail-refused account is not a target that failed; it is one the run
    was never going to act on. Exit 4 would say "run `apply --repair`" about a
    run where everything the tool was willing to do succeeded — and the repair
    would skip the same account again, every night, forever."""
    estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS


def test_a_run_where_everything_is_skipped_still_exits_zero(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The same answer an empty selection already gives: nothing was eligible."""
    estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": account("ACME_BATCH_USER", vendor_maintained=True),
        }
    )
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS


#: One document shared by two targets, so one account has two pairs and one
#: promotion for both.
TWO_TARGETS = CONFIG.replace(
    "applications:",
    """\
  - name: appdb-beta
    type: oracle
    dsn: db-prod.example.com:1521/beta.pdb.example.com
    environment: prod
    labels: { env: prod, tenant: beta }
    vault: vault-prod
applications:""",
)


def test_an_account_skipped_on_one_of_its_targets_is_not_promoted(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#852 and invariant 7. The guardrails read each database, so one account
    can hold `DBA` on one target only. Its promotion is one password for both
    targets, and the skipped one still holds the old password."""
    harness = estate(
        {},
        by_target={
            "appdb-alpha": {
                "ACME_WEB_USER": ordinary("ACME_WEB_USER"),
                "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
            },
            "appdb-beta": {
                "ACME_WEB_USER": account(
                    "ACME_WEB_USER", vendor_maintained=False, roles=frozenset({"DBA"})
                ),
                "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
            },
        },
    )
    result = run(runner, write_config(TWO_TARGETS), "--output", "json")

    held = harness["store"].read("apps/acme/db")
    assert held is not None
    assert held.data["DB_CREDENTIALS"]["acme_web_user"] == LIVE
    assert held.data["pending"]["acme_web_user"] == STAGED
    assert result.exit_code == ExitCode.PARTIAL
    (skipped,) = [
        one for one in document(result)["diagnostics"] if one.get("code") == PROMOTION_SKIPPED
    ]
    assert "a guardrail skipped acme_web_user on appdb-beta" in skipped["message"]


def test_an_account_skipped_on_every_target_does_not_hold_its_neighbours_back(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The other half of `_by_document`'s rule: a permanently guarded account
    must not block promotion for every account sharing its document."""
    guarded = account("ACME_WEB_USER", vendor_maintained=False, roles=frozenset({"DBA"}))
    harness = estate(
        {},
        by_target={
            name: {"ACME_WEB_USER": guarded, "ACME_BATCH_USER": ordinary("ACME_BATCH_USER")}
            for name in ("appdb-alpha", "appdb-beta")
        },
    )
    result = run(runner, write_config(TWO_TARGETS))

    held = harness["store"].read("apps/acme/db")
    assert held is not None
    assert held.data["DB_CREDENTIALS"]["acme_batch_user"] == STAGED
    assert held.data["pending"]["acme_web_user"] == STAGED
    assert result.exit_code == ExitCode.SUCCESS


#: `acme_web_user` holds `DBA` on `appdb-beta` only, the #852 estate.
DBA_ON_BETA = {
    "appdb-alpha": {
        "ACME_WEB_USER": ordinary("ACME_WEB_USER"),
        "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
    },
    "appdb-beta": {
        "ACME_WEB_USER": account(
            "ACME_WEB_USER", vendor_maintained=False, roles=frozenset({"DBA"})
        ),
        "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
    },
}


def test_a_skip_that_holds_the_promotion_back_prints_its_remedy_and_no_repair_line(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The run's own `repair with:` line would name a run that skips the same
    pair again, so W050 carries the remedy, and says what `--force` would cost."""
    estate({}, by_target=DBA_ON_BETA)
    result = run(runner, write_config(TWO_TARGETS))

    assert result.exit_code == ExitCode.PARTIAL
    assert "a guardrail skipped acme_web_user on appdb-beta, and that target still holds" in (
        result.output
    )
    assert "waives the guardrails for every account the run selects" in result.output
    assert "repair with:" not in result.output


class FailsBatchUserOnBeta(FakeSession):
    """`acme_batch_user` never confirms on the session that holds `DBA` for
    `acme_web_user`, which is `appdb-beta`'s."""

    def verify_password(self, account: str, secret: Secret, **_: Any) -> VerifyResult:
        web = self.users.get("ACME_WEB_USER")
        on_beta = web is not None and "DBA" in web.roles
        if on_beta and account.upper() == "ACME_BATCH_USER":
            self.attempts.append(account.upper())
            return VerifyResult("login", "fail", latency_ms=9)
        return super().verify_password(account, secret)


def test_a_sibling_failure_is_the_reason_before_a_skip(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The same run again may fix a failure, and `--force` is the wrong remedy
    for it. So the failure holds the document back and W050 is not raised."""
    harness = estate({}, by_target=DBA_ON_BETA, session=FailsBatchUserOnBeta)
    result = run(runner, write_config(TWO_TARGETS), "--output", "json")

    held = harness["store"].read("apps/acme/db")
    assert held is not None
    assert held.data["pending"]["acme_web_user"] == STAGED
    assert result.exit_code == ExitCode.PARTIAL
    codes = [one.get("code") for one in document(result)["diagnostics"]]
    assert PROMOTION_SKIPPED not in codes


def test_a_skip_on_an_account_applied_from_current_holds_nothing_back(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`acme_web_user` has no `pending`, so its skip on beta moves nothing.
    Keeping it in the gate would block `acme_batch_user` on every run."""
    harness = estate(
        {},
        by_target=DBA_ON_BETA,
        document={
            "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
            "pending": {"acme_batch_user": STAGED},
        },
    )
    result = run(runner, write_config(TWO_TARGETS))

    held = harness["store"].read("apps/acme/db")
    assert held is not None
    assert held.data["DB_CREDENTIALS"]["acme_batch_user"] == STAGED
    assert result.exit_code == ExitCode.SUCCESS


class FailsWebUser(FakeSession):
    """A target where `acme_web_user` never confirms: every login is refused."""

    def verify_password(self, account: str, secret: Secret, **_: Any) -> VerifyResult:
        if account.upper() == "ACME_WEB_USER":
            self.attempts.append(account.upper())
            return VerifyResult("login", "fail", latency_ms=9)
        return super().verify_password(account, secret)


def test_a_skip_beside_a_failure_leaves_the_failure_as_the_reason(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Where the account confirmed nowhere, the failure already holds the
    document back. Reporting the skip would recommend `--force` on a run whose
    real blocker is the target that failed."""
    harness = estate({}, by_target=DBA_ON_BETA, session=FailsWebUser)
    result = run(runner, write_config(TWO_TARGETS), "--output", "json")

    held = harness["store"].read("apps/acme/db")
    assert held is not None
    assert held.data["pending"]["acme_web_user"] == STAGED
    assert result.exit_code == ExitCode.PARTIAL
    codes = [one.get("code") for one in document(result)["diagnostics"]]
    assert PROMOTION_SKIPPED not in codes


def test_a_skip_on_one_credential_does_not_hold_back_another_of_the_same_account(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The gate is keyed on the credential, the field and pointer, as `_left_out`
    is. Here each target has its own field for `acme_web_user`, so the skip on
    beta's field moves nothing, and alpha's field is promoted."""
    fields = {
        f"{account}_{target}": value
        for account in ("acme_web_user", "acme_batch_user")
        for target, value in (("appdb-alpha", LIVE), ("appdb-beta", LIVE))
    }
    harness = estate(
        {},
        by_target=DBA_ON_BETA,
        document={"DB_CREDENTIALS": fields, "pending": dict.fromkeys(fields, STAGED)},
    )
    config = TWO_TARGETS.replace("DB_CREDENTIALS/{account}", "DB_CREDENTIALS/{account}_{target}")
    result = run(runner, write_config(config), "--output", "json")

    held = harness["store"].read("apps/acme/db")
    assert held is not None
    assert held.data["DB_CREDENTIALS"]["acme_web_user_appdb-alpha"] == STAGED
    assert held.data["DB_CREDENTIALS"]["acme_web_user_appdb-beta"] == LIVE
    codes = [one.get("code") for one in document(result)["diagnostics"]]
    assert PROMOTION_SKIPPED not in codes


def test_a_rollback_is_held_back_by_a_skip_too(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A rollback promotes `previous` to `current`, so the same gate stands in
    front of it: `appdb-beta` still holds the password being rolled back from."""
    harness = estate(
        {},
        by_target=DBA_ON_BETA,
        document={
            "DB_CREDENTIALS": {"acme_web_user": STAGED, "acme_batch_user": STAGED},
            "previous": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
        },
    )
    result = run(
        runner,
        write_config(TWO_TARGETS),
        "--source",
        "previous",
        "--confirm",
        "--output",
        "json",
    )

    held = harness["store"].read("apps/acme/db")
    assert held is not None
    assert held.data["DB_CREDENTIALS"]["acme_web_user"] == STAGED
    assert result.exit_code == ExitCode.PARTIAL
    codes = [one.get("code") for one in document(result)["diagnostics"]]
    assert PROMOTION_SKIPPED in codes


def test_rotate_reports_the_skip_too(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`rotate` promotes through the same gate, so it holds the document back
    and reports W050 as `apply` does. Whether `--finish-rollover` leaves a
    held-back document's windows open is `_settled`'s rule for every withheld
    promotion, tested in `test_cli_creds_rotate.py`."""
    harness = estate({}, by_target=DBA_ON_BETA, document=NOTHING_STAGED)
    result = runner.invoke(
        cli,
        ["creds", "rotate", "--config", str(write_config(TWO_TARGETS)), "--confirm"]
        + ["--output", "json"],
    )

    held = harness["store"].read("apps/acme/db")
    assert held is not None
    assert held.data["DB_CREDENTIALS"]["acme_web_user"] == LIVE
    assert result.exit_code == ExitCode.PARTIAL
    codes = [one.get("code") for one in document(result)["diagnostics"]]
    assert PROMOTION_SKIPPED in codes


def test_the_reason_names_every_check_that_refused(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """An operator clearing these has to deal with all of them, and revealing
    them one run at a time would be three runs to learn one fact."""
    estate(
        {
            "ACME_WEB_USER": account(
                "ACME_WEB_USER", vendor_maintained=True, roles=frozenset({"DBA"})
            ),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG), "--output", "json")

    guarded = next(one for one in document(result)["results"] if one["account"] == "acme_web_user")
    reported = json.dumps(guarded)
    # Both checks, in §4's own numbering order: check 2 then check 4.
    assert "the database reports this account as its own" in reported
    assert "the account holds DBA" in reported


# -------------------------------------------------------------- `--force` ---


def test_force_waives_checks_two_to_five(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Decision P3's case: rotating `DBSNMP` is ordinary DBA work, and a tool
    with no override does not prevent it — it moves it to SQL*Plus, where
    nothing records that it happened."""
    harness = estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG), "--force")

    assert result.exit_code == ExitCode.SUCCESS
    assert "ACME_WEB_USER" in changed(harness)


def test_force_records_what_it_waived(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    """§4 requires the waiver to survive the waiving: a `--force` that merely
    returned "allowed" would leave the document unable to say that somebody
    rotated a vendor account on purpose."""
    estate(
        {
            "ACME_WEB_USER": account(
                "ACME_WEB_USER", vendor_maintained=True, roles=frozenset({"DBA"})
            ),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG), "--force", "--output", "json")

    body = document(result)
    assert not list(validator.iter_errors(body))
    forced = next(one for one in body["results"] if one["account"] == "acme_web_user")
    assert [one["check"] for one in forced["overridden"]] == [
        "vendor_maintained",
        "privileged_role",
    ]


def test_force_records_the_waiver_on_an_account_that_needed_no_change(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The no-op path keeps the audit trail.

    A forced account whose password the database already holds reports
    `changed: false` and issues nothing -- but the waiver was still granted and
    the tool still went on to touch an account §4 would have refused. That it
    turned out to need no change is a fact about the estate, not about what was
    overridden, and an audit trail recording the override only when something
    happened would be missing exactly the runs somebody skims looking for
    `--force`.
    """
    estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        },
        # `current` already holds what the database holds, and no `pending`: the
        # run reads `current`, the login passes, and nothing is issued.
        document={"DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE}},
    )
    result = run(runner, write_config(CONFIG), "--force", "--output", "json")

    forced = next(one for one in document(result)["results"] if one["account"] == "acme_web_user")
    assert forced["changed"] is False
    assert [one["check"] for one in forced["overridden"]] == ["vendor_maintained"]


def test_force_records_the_waiver_on_an_account_that_failed(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """And on the error path, for the same reason: the override happened."""

    class Refusing(FakeSession):
        def set_password(self, name: str, secret: Secret) -> ChangeResult:
            raise RuntimeError("ORA-01031: insufficient privileges")

    harness = estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        },
        session=Refusing,
    )
    result = run(runner, write_config(CONFIG), "--force", "--output", "json")

    assert changed(harness) == []
    forced = next(one for one in document(result)["results"] if one["account"] == "acme_web_user")
    assert forced["state"] == "ERROR"
    assert [one["check"] for one in forced["overridden"]] == ["vendor_maintained"]


def test_a_clean_account_carries_no_overridden_key(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The field records overrides, not intent. A document carrying an empty
    array on every forced run would make the ones that mattered harder to find."""
    estate({"ACME_WEB_USER": ordinary(), "ACME_BATCH_USER": ordinary("ACME_BATCH_USER")})
    result = run(runner, write_config(CONFIG), "--force", "--output", "json")

    assert all("overridden" not in one for one in document(result)["results"])


def test_force_never_waives_check_one(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 5 and decision P3: acting on an account absent from the config
    would make the tool's own audit trail meaningless, so no flag reaches
    check 1.

    The database answers to a name the config does not declare -- which is what
    a renamed account looks like -- and `--force` must not get past it.
    """
    harness = estate(
        {
            "ACME_WEB_USER": account("SOMEONE_ELSE", vendor_maintained=False),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    run(runner, write_config(CONFIG), "--force")

    assert "SOMEONE_ELSE" not in changed(harness)


# ------------------------------------------------ named vs fell inside ---


def test_a_named_account_makes_the_run_fail(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """§4's other half: the operator named the account with `--account`.

    "They asked for something the tool will not do, and quietly skipping it would
    report success for work nobody did." So the same refusal that is `SKIPPED`
    and exit 0 when the account fell inside a broad selection counts against the
    exit code when the operator named it.
    """
    harness = estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG), "--account", "acme_web_user")

    assert result.exit_code != ExitCode.SUCCESS
    assert "ACME_WEB_USER" not in changed(harness)


def test_debug_says_a_named_account_was_not_acted_on(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#788: the refusal fails the run, so its line does not read "left alone"."""
    estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG), "--account", "acme_web_user", "--debug")

    assert "plan: acme_web_user on " in result.stderr
    assert " not acted on: ERROR, " in result.stderr
    assert "left alone: ERROR" not in result.stderr
    assert STAGED not in result.stderr
    assert LIVE not in result.stderr


def test_the_same_account_falling_inside_a_selection_does_not(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The control for the case above, and the whole point of the distinction:
    one estate, one guardrail, two exit codes, decided only by how the account
    got into the run."""
    estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS


def test_naming_a_target_is_not_naming_an_account(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`--target` names a target, so an account inside it fell in.

    Asserted because the tempting implementation is "the selection resolved to
    one account, so they must have meant it" -- which would make a safety rule
    change behaviour according to how many rows an estate happens to have today.
    """
    estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG), "--target", "appdb-alpha")

    assert result.exit_code == ExitCode.SUCCESS


def test_a_named_account_is_told_what_to_type(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """An operator who typed `--account DBSNMP` asked for this specific thing and
    is owed the sentence that says how to get it. One that fell inside a broad
    selection needs no advice -- the run carried on."""
    estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG), "--account", "acme_web_user", "--output", "json")

    reported = json.dumps(document(result))
    assert "you named this account" in reported
    assert "--force" in reported


def test_a_named_account_refused_by_check_one_is_not_sent_to_force(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Check 1 is the one no flag reaches, so advising `--force` there would send
    an operator to a flag that is going to refuse them again."""
    estate(
        {
            "ACME_WEB_USER": account("SOMEONE_ELSE", vendor_maintained=False),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG), "--account", "acme_web_user", "--output", "json")

    reported = json.dumps(document(result))
    assert "no flag extends the whitelist" in reported
    assert "--force to override" not in reported


def test_force_clears_a_named_account_too(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The two rules compose: naming it decides what a refusal costs, and
    `--force` decides whether there is a refusal at all."""
    harness = estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    # Both accounts are named: they share a document and both have a password
    # staged, so a run narrowed to one of them would not promote it (see
    # decision #406), and this test is about the guardrail rather than the gate.
    result = run(
        runner,
        write_config(CONFIG),
        "--account",
        "acme_web_user",
        "--account",
        "acme_batch_user",
        "--force",
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert "ACME_WEB_USER" in changed(harness)


# --------------------------------------------------------------- `rotate` ---
#
# `rotate` refuses over a staged `pending` (#769), so its estate has none.

NOTHING_STAGED = {"DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE}}


def test_rotate_is_guarded_too(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`rotate` sequences `apply`, so it inherits the guardrail -- asserted rather
    than assumed, because "inherits it" is a property of today's call graph."""
    harness = estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        },
        document=NOTHING_STAGED,
    )
    runner.invoke(
        cli,
        ["creds", "rotate", "--config", str(write_config(CONFIG)), "--confirm"],
    )

    assert "ACME_WEB_USER" not in changed(harness)


def test_rotate_takes_force_as_well(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", vendor_maintained=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        },
        document=NOTHING_STAGED,
    )
    runner.invoke(
        cli,
        ["creds", "rotate", "--config", str(write_config(CONFIG)), "--confirm", "--force"],
    )

    assert "ACME_WEB_USER" in changed(harness)


# ------------------------------------------------- the check that could not run ---
#
# §4's third answer. `V$PWFILE_USERS` is outside §2's grant set on purpose, so
# the ordinary estate cannot answer check 3 -- which is why the driver reports
# `None` rather than `False`, and why the run says so rather than refusing.


def unreadable(name: str = "ACME_WEB_USER") -> UserState:
    """An ordinary account on a target whose service credential cannot read the
    password file, which is every target installed exactly as §2 documents."""
    return account(name, vendor_maintained=False, password_file_member=None)


def diagnostics(result: Result) -> list[dict[str, Any]]:
    return list(document(result).get("diagnostics", []))


def test_an_unreadable_password_file_warns_and_applies_anyway(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The whole shape of an unanswerable check 3, in one run.

    Refusing would be the wrong fix: the estate that cannot answer check 3 is the
    correctly installed one, so a refusal here means the tool applies nothing
    anywhere. What must not happen is the run reporting a clean result while one
    of five checks contributed nothing to it.
    """
    harness = estate(
        {"ACME_WEB_USER": unreadable(), "ACME_BATCH_USER": unreadable("ACME_BATCH_USER")}
    )
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS
    assert changed(harness) == ["ACME_WEB_USER", "ACME_BATCH_USER"]
    warnings = [one for one in diagnostics(result) if one["code"] == GUARDRAIL_UNCHECKED]
    assert len(warnings) == 1
    assert warnings[0]["level"] == "warning"
    assert warnings[0]["target"] == "appdb-alpha"
    assert "password_file" in warnings[0]["message"]
    assert "V_$PWFILE_USERS" in warnings[0]["message"]
    # A code is contract in the way an enum value is (`03-json-output.md` §8), so
    # it needs a documented meaning and not only a message somebody may reword.
    assert GUARDRAIL_UNCHECKED in WARNINGS


def test_the_warning_is_one_per_target_and_names_the_accounts(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """What could not be read is a grant on a database, so an estate with forty
    accounts on one target must not be told the same fact forty times -- the rule
    `creds generate` already applies to the constraints it cannot check.

    ``account`` is omitted where the group holds more than one, because the field
    takes a single value and naming one of two would be worse than naming none.
    """
    estate({"ACME_WEB_USER": unreadable(), "ACME_BATCH_USER": unreadable("ACME_BATCH_USER")})
    result = run(runner, write_config(CONFIG), "--output", "json")

    warning = next(one for one in diagnostics(result) if one["code"] == GUARDRAIL_UNCHECKED)
    assert "account" not in warning
    assert "ACME_WEB_USER" in warning["message"]
    assert "ACME_BATCH_USER" in warning["message"]


def test_a_target_that_can_answer_says_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A site that took the optional grant gets a silent run, which is what makes
    this a warning worth leaving on: it has a remedy, and taking the remedy
    removes it."""
    estate({"ACME_WEB_USER": ordinary(), "ACME_BATCH_USER": ordinary("ACME_BATCH_USER")})
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert [one for one in diagnostics(result) if one["code"] == GUARDRAIL_UNCHECKED] == []


def test_a_password_file_member_is_still_refused(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Check 3, on the account only it catches.

    Measured on 26ai 23.26.2.0.0: an account granted `SYSDBA` inside a PDB
    appears in `V$PWFILE_USERS` with its own `CON_ID`, reads
    `ORACLE_MAINTAINED = N`, and holds no roles at all -- so checks 2, 4 and 5
    all pass it and only this one does not. Such accounts exist in real
    estates, and without check 3 the tool would rotate one.
    """
    harness = estate(
        {
            "ACME_WEB_USER": account("ACME_WEB_USER", password_file_member=True),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert "ACME_WEB_USER" not in changed(harness)
    assert states(result)["acme_web_user"] == SKIPPED
    assert "ACME_BATCH_USER" in changed(harness)


def test_a_refused_account_contributes_no_caveat(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """An account the guardrails turned away was not touched, so what an unread
    check might have said about it changed nothing. The caveat is about what this
    run went ahead and did without."""
    estate(
        {
            "ACME_WEB_USER": account(
                "ACME_WEB_USER", vendor_maintained=True, password_file_member=None
            ),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert states(result)["acme_web_user"] == SKIPPED
    assert [one for one in diagnostics(result) if one["code"] == GUARDRAIL_UNCHECKED] == []


def test_force_does_not_silence_the_caveat(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`--force` waives an answer, and a caveat is the absence of one.

    The operator who passed the flag is the one most likely to be reading what
    the guardrails did, so hiding a missing grant from them is the wrong way
    round.
    """
    estate(
        {
            "ACME_WEB_USER": account(
                "ACME_WEB_USER", vendor_maintained=True, password_file_member=None
            ),
            "ACME_BATCH_USER": ordinary("ACME_BATCH_USER"),
        }
    )
    result = run(runner, write_config(CONFIG), "--output", "json", "--force")

    warning = next(one for one in diagnostics(result) if one["code"] == GUARDRAIL_UNCHECKED)
    assert warning["account"] == "ACME_WEB_USER"


def test_rotate_reports_it_too(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Asserted rather than assumed, for `test_rotate_is_guarded_too`'s reason:
    that `rotate` sequences `apply` is a property of today's call graph."""
    estate(
        {"ACME_WEB_USER": unreadable(), "ACME_BATCH_USER": unreadable("ACME_BATCH_USER")},
        document=NOTHING_STAGED,
    )
    result = runner.invoke(
        cli,
        [
            "creds",
            "rotate",
            "--config",
            str(write_config(CONFIG)),
            "--confirm",
            "--output",
            "json",
        ],
    )

    assert [one for one in diagnostics(result) if one["code"] == GUARDRAIL_UNCHECKED]


def test_the_document_still_validates(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    """Invariant 12. The warning needed no schema change -- `diagnostics[]` has
    carried a `code`, a `target` and an `account` since the section existed --
    which is the half worth pinning: a fix that quietly widened the contract
    would be a major question rather than a bug fix."""
    estate({"ACME_WEB_USER": unreadable(), "ACME_BATCH_USER": unreadable("ACME_BATCH_USER")})
    result = run(runner, write_config(CONFIG), "--output", "json")

    validator.validate(document(result))

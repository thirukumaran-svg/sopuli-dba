"""``sopuli creds apply`` end to end, without a database (#259).

Same arrangement as ``tests/test_cli_creds_check.py``: in-process through
``CliRunner``, with the vault a :class:`~sopuli.store.MemoryStore` and the driver
a fake session. The real ones have their own suites; this file is about *the
command* -- what it reads, in what order, what it issues, what it promotes, and
what it exits with.

Two properties carry most of it, and both are about restraint:

* **nothing is promoted that was not confirmed** (invariant 7), asserted on the
  document the store actually holds afterwards rather than on what the run said;
* **a second run changes nothing** (invariant 9), asserted on the statements the
  fake session recorded rather than on ``changed`` -- a command can report
  ``false`` and still have issued the DDL.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator

from sopuli import check
from sopuli.cli import cli
from sopuli.clock import utc_now
from sopuli.config.model import Vault
from sopuli.driver.protocol import (
    EXPIRE_PASSWORD,
    FAIL,
    PASS,
    PASSWORD_ROLLOVER,
    SKIPPED,
    VERIFY_LOGIN,
    ChangeResult,
    Scope,
    UserState,
    VerifyResult,
)
from sopuli.exit_codes import ExitCode
from sopuli.lock import Holder, LockKey, LockRecord, lock_path
from sopuli.output.document import SCHEMA_VERSION
from sopuli.secrets import Secret
from sopuli.store import MemoryStore, SecretStore

RUN_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

#: One application over two PDBs, one document per tenant, a field per account --
#: Q7's documented layout, so the shared-document path is the one under test.
CONFIG = """\
version: 1
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
    dsn: db-prod.example.com:1521/beta.pdb.example.com
    environment: prod
    labels: { env: prod, tenant: beta }
    vault: vault-prod
applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "apps/acme/{target}#DB_CREDENTIALS/{account}"
"""

#: Two accounts in one document, which is what makes the promotion gate visible:
#: both must confirm before either is promoted.
SHARED_CONFIG = """\
version: 1
vaults:
  vault-prod:
    type: hashicorp
    addr: https://vault-prod.example.com:8200
targets:
  - name: appdb-alpha
    type: oracle
    dsn: db-prod.example.com:1521/alpha.pdb.example.com
    environment: prod
    vault: vault-prod
applications:
  - name: acme
    accounts: [acme_web_user, acme_batch_user]
    secret_template: "apps/acme/db#DB_CREDENTIALS/{account}"
"""

LIVE = "Correct-Horse-Battery-9"
STAGED = "Vertical-Anchor-Marble-4"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8")))


class FakeSession:
    """One target's worth of answers, and a record of everything it was asked.

    The recording is the point. Half of what `apply` must get right is what it
    does *not* do -- no DDL against a locked account, no second change on a
    re-run, no login beyond the two it budgeted -- and none of that is visible in
    the output.
    """

    def __init__(
        self,
        users: Mapping[str, UserState | None],
        answers: Mapping[str, list[VerifyResult]],
        *,
        set_error: Exception | None = None,
        capabilities: frozenset[str] = frozenset(),
        rollover_refusal: Exception | None = None,
        on_call: Callable[[str], None] | None = None,
    ) -> None:
        self.on_call = on_call
        self.users = dict(users)
        self.answers = {name: list(results) for name, results in answers.items()}
        self.set_error = set_error
        self.capabilities = capabilities
        self.rollover_refusal = rollover_refusal
        self.attempts: list[tuple[str, str]] = []
        self.budgets: list[int] = []
        self.changed: list[tuple[str, str]] = []
        self.finished: list[str] = []
        self.closed = False

    def scope(self) -> Scope:
        return Scope(type="pdb", container="ALPHA", read_write=True, capabilities=self.capabilities)

    def describe_user(self, account: str) -> UserState | None:
        self._called("describe_user")
        found = self.users.get(account.upper())
        if found is None:
            return None
        # A window opens when the password is set on a rollover-enabled profile,
        # and closes when `finish_rollover` runs. Modelled rather than scripted,
        # because the command reads the state back after each of those and the
        # bug worth catching is it reading a stale one.
        opened = (
            bool(found.rollover_enabled)
            and any(name == found.name for name, _ in self.changed)
            and found.name not in self.finished
        )
        return replace(found, rollover_active=opened)

    def require_rollover(self, account: str) -> None:
        # The real driver raises for a missing account before it looks at
        # anything else (#181), so this one does too -- otherwise the pre-flight
        # could skip a case the estate would meet.
        if account.upper() not in self.users:
            raise RuntimeError(f'account "{account}" does not exist on this target')
        if self.rollover_refusal is not None:
            raise self.rollover_refusal

    def finish_rollover(self, account: str) -> ChangeResult:
        self.finished.append(account.upper())
        return ChangeResult(changed=True, detail="rollover window ended")

    def verify_password(
        self,
        account: str,
        secret: Secret,
        *,
        method: str = VERIFY_LOGIN,
        lockout_margin: int = 2,
        attempts: int = 1,
    ) -> VerifyResult:
        self.attempts.append((account.upper(), secret.reveal()))
        self.budgets.append(attempts)
        queued = self.answers.get(account.upper(), [])
        return queued.pop(0) if queued else VerifyResult(VERIFY_LOGIN, PASS, latency_ms=9)

    def set_password(self, account: str, secret: Secret) -> ChangeResult:
        if self.set_error is not None:
            raise self.set_error
        self.changed.append((account.upper(), secret.reveal()))
        self._called("set_password")
        return ChangeResult(changed=True)

    def _called(self, event: str) -> None:
        """The seam a takeover needs: something happens to the vault *while* this
        run is mid-estate.

        Two seams matter and they are one hook, because what separates the two
        cases the exit code splits on is only *when* it fires: before this
        session's first `describe_user`, nothing has been applied anywhere; after
        a `set_password`, one database has been changed. Hooked here rather than
        by patching `LockManager`, so the test exercises the real fence -- the
        record on the path really is somebody else's by the next check.
        """
        if self.on_call is not None:
            self.on_call(event)

    def close(self) -> None:
        self.closed = True


def user(name: str = "ACME_WEB_USER", **fields: Any) -> UserState:
    return UserState(**{"name": name, "status": "OPEN", **fields})


def passes(count: int = 2) -> list[VerifyResult]:
    return [VerifyResult(VERIFY_LOGIN, PASS, latency_ms=9)] * count


def drifted() -> list[VerifyResult]:
    """Refused, then accepted: the ordinary rotation, before and after."""
    return [
        VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017: invalid credential"),
        VerifyResult(VERIFY_LOGIN, PASS, latency_ms=9),
    ]


Harness = Callable[..., dict[str, Any]]


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Harness:
    """Patch the store and the driver, and hand back what the run will meet."""

    def install(
        *,
        documents: Mapping[str, dict[str, Any]] | None = None,
        users: Mapping[str, UserState | None] | None = None,
        answers: Mapping[str, list[VerifyResult]] | None = None,
        per_target: Mapping[str, Mapping[str, list[VerifyResult]]] | None = None,
        connect_error: Exception | None = None,
        set_error: Exception | None = None,
        capabilities: frozenset[str] = frozenset(),
        rollover_refusal: Exception | None = None,
        on_call: Callable[[dict[str, Any], str], None] | None = None,
    ) -> dict[str, Any]:
        store = MemoryStore()
        for path, body in (documents or _staged_two_targets()).items():
            store.write(path, body, cas=0)

        sessions: list[FakeSession] = []
        # Built up front so `on_change` can reach the store it is about to
        # interfere with, and handed back unchanged at the end.
        harness: dict[str, Any] = {"store": store, "sessions": sessions}

        def fake_connect(
            vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
        ) -> SecretStore:
            return store

        class FakeDriver:
            def __init__(self, **_: Any) -> None:
                pass

            def connect(self, target: Any, credential: Any) -> FakeSession:
                if connect_error is not None:
                    raise connect_error
                scripted = answers if answers is not None else {"ACME_WEB_USER": drifted()}
                if per_target is not None:
                    scripted = per_target[target.name]
                session = FakeSession(
                    users if users is not None else {"ACME_WEB_USER": user()},
                    scripted,
                    set_error=set_error,
                    capabilities=capabilities,
                    rollover_refusal=rollover_refusal,
                    on_call=None if on_call is None else (lambda event: on_call(harness, event)),
                )
                sessions.append(session)
                return session

        class FakeModule:
            OracleDriver = FakeDriver

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        monkeypatch.setattr("sopuli.cli.resolve_driver", lambda target: FakeModule)
        monkeypatch.setattr("sopuli.cli.admin_resolve", lambda target, env: _credential())
        return harness

    return install


def _staged_two_targets() -> dict[str, dict[str, Any]]:
    return {
        f"apps/acme/{target}": {
            "DB_CREDENTIALS": {"acme_web_user": LIVE},
            "pending": {"acme_web_user": STAGED},
        }
        for target in ("appdb-alpha", "appdb-beta")
    }


def _credential() -> Any:
    class Resolved:
        credential = object()

    return Resolved()


def run(runner: CliRunner, config: Path, *args: str) -> Result:
    return runner.invoke(cli, ["creds", "apply", "--config", str(config), *args])


def document(result: Result) -> dict[str, Any]:
    return dict(json.loads(result.output))


def stored(store: MemoryStore, path: str) -> dict[str, Any]:
    found = store.read(path)
    assert found is not None
    return dict(found.data)


# --------------------------------------------------------- the happy path ---


def test_a_staged_password_is_applied_and_promoted(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §5 end to end: the database takes `pending`, and only then does the
    vault promote it."""
    harness = estate()
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    body = stored(harness["store"], "apps/acme/appdb-alpha")
    assert body["DB_CREDENTIALS"]["acme_web_user"] == STAGED
    assert body["previous"]["acme_web_user"] == LIVE
    assert "acme_web_user" not in body.get("pending", {})


def test_the_database_is_changed_to_the_staged_value(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate()
    run(runner, write_config(CONFIG))

    for session in harness["sessions"]:
        assert session.changed == [("ACME_WEB_USER", STAGED)]


def test_the_promotion_stamps_who_and_when(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §3's stamps, per account, beside the value they describe."""
    harness = estate()
    run(runner, write_config(CONFIG))

    body = stored(harness["store"], "apps/acme/appdb-alpha")
    assert body["rotated_at"]["acme_web_user"].endswith("Z")
    assert "@" in body["rotated_by"]["acme_web_user"]
    assert body["targets"]["acme_web_user"] == ["appdb-alpha"]


def test_the_plan_and_the_source_table_come_before_anything_is_issued(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate()
    result = run(runner, write_config(CONFIG))

    assert result.output.index("Plan:") < result.output.index("SOURCE")
    assert result.output.index("SOURCE") < result.output.index("STATE")


def test_the_document_validates_and_reports_the_promotion(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    estate()
    result = run(runner, write_config(CONFIG), "--output", "json")

    body = document(result)
    assert not list(validator.iter_errors(body))
    kinds = [action["kind"] for action in body["results"][0]["actions"]]
    assert kinds == ["verify", "password_set", "verify", "vault_promote"]
    assert body["results"][0]["secret"]["stage"] == "current"


# ------------------------------------------------------------ idempotency ---


def test_a_second_run_changes_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 9 names `apply` as the convergent verb. With nothing staged and
    a password the database accepts, no DDL is issued at all."""
    harness = estate(
        documents={"apps/acme/appdb-alpha": {"DB_CREDENTIALS": {"acme_web_user": LIVE}}},
        answers={"ACME_WEB_USER": passes(1)},
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["sessions"][0].changed == []
    assert document(result)["results"][0]["changed"] is False


def test_nothing_is_promoted_when_nothing_was_staged(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A run that read `current` is a repair; the vault already holds what it
    should, and writing a new version would be a version describing no change."""
    harness = estate(
        documents={"apps/acme/appdb-alpha": {"DB_CREDENTIALS": {"acme_web_user": LIVE}}},
        answers={"ACME_WEB_USER": passes(1)},
    )
    before = harness["store"].read("apps/acme/appdb-alpha").version
    run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["store"].read("apps/acme/appdb-alpha").version == before


def test_a_repair_beside_a_rotation_exits_zero(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Two documents, one staged and one not. The repair has nothing to promote,
    so counting it as unpromoted would make a run where everything confirmed look
    like UC-1 §8 case 7 -- the database holding the new password while the vault
    still advertises the old one -- and exit 4 with nothing wrong."""
    harness = estate(
        documents={
            "apps/acme/appdb-alpha": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE},
                "pending": {"acme_web_user": STAGED},
            },
            "apps/acme/appdb-beta": {"DB_CREDENTIALS": {"acme_web_user": LIVE}},
        },
        per_target={
            "appdb-alpha": {"ACME_WEB_USER": drifted()},
            "appdb-beta": {"ACME_WEB_USER": passes(1)},
        },
    )
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"] == {}
    assert "previous" not in stored(harness["store"], "apps/acme/appdb-beta")


def test_a_drifted_target_is_repaired_from_current(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The repair case, and the one that makes the pre-flight login worth its
    cost: the same command converges a database that has fallen out of step."""
    harness = estate(
        documents={"apps/acme/appdb-alpha": {"DB_CREDENTIALS": {"acme_web_user": LIVE}}},
        answers={"ACME_WEB_USER": drifted()},
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["sessions"][0].changed == [("ACME_WEB_USER", LIVE)]


# ----------------------------------------------------- what is not touched ---


def test_a_locked_account_is_not_changed(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The DDL would succeed and could never be confirmed. Asserted on the
    session rather than on the state, because a command can report `LOCKED` and
    still have issued the statement."""
    harness = estate(
        users={"ACME_WEB_USER": user(status="LOCKED", locked=True)},
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].changed == []
    assert harness["sessions"][0].attempts == []
    assert check.LOCKED in result.output


def test_a_missing_account_is_reported_and_not_created(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate(users={})
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].changed == []
    assert check.ACCOUNT_MISSING in result.output
    assert result.exit_code == ExitCode.FAILURE


def test_an_empty_vault_fails_rather_than_reporting_success(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A mutating verb that exits 0 having converged nothing is the silent
    failure worth being loud about."""
    harness = estate(documents={"apps/acme/appdb-alpha": {"other": "value"}})
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.FAILURE
    assert harness["sessions"][0].changed == []
    assert "creds generate" in result.output


def test_dry_run_reads_the_vault_and_writes_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 8. The documents are still read -- which stage an account would
    be applied from is the thing worth reviewing, and a read needs no lock."""
    harness = estate()
    result = run(runner, write_config(CONFIG), "--dry-run")

    assert result.exit_code == ExitCode.SUCCESS
    assert "pending" in result.output
    assert "nothing was applied" in result.output
    assert harness["sessions"] == []
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]


# ----------------------------------------------------------- the promotion ---


def test_one_failed_target_stops_the_promotion_for_that_document(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 7 and UC-1 §5: promoting would advertise a password part of the
    estate does not have. Each target has its own document here, so only the one
    that failed is held back."""
    harness = estate(
        per_target={
            "appdb-alpha": {"ACME_WEB_USER": drifted()},
            "appdb-beta": {
                "ACME_WEB_USER": [
                    VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017"),
                    VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017"),
                ]
            },
        }
    )
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.PARTIAL
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"] == {}
    assert stored(harness["store"], "apps/acme/appdb-beta")["pending"]["acme_web_user"] == STAGED


def test_a_partial_run_names_the_invocation_that_repairs_it(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#264, and the half of exit 4 that was missing: the code exists to point at
    a remedy, and the remedy has to be narrowed the way this run was narrowed --
    otherwise the repair spends a login on every target the partial run already
    spent one on."""
    estate(
        per_target={
            "appdb-alpha": {"ACME_WEB_USER": drifted()},
            "appdb-beta": {
                "ACME_WEB_USER": [
                    VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017"),
                    VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017"),
                ]
            },
        }
    )
    config = write_config(CONFIG)

    result = run(runner, config, "--select", "env=prod")

    assert result.exit_code == ExitCode.PARTIAL
    assert f"repair with: sopuli creds apply --config {config} --select env=prod" in result.output


def test_a_run_that_worked_offers_no_repair(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The remedy is exit 4's, and a successful run naming one would be the table
    and the exit code describing the same run differently."""
    estate()

    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert "repair with:" not in result.output


def test_a_changed_database_with_no_promotion_carries_a_warning(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §8's highest-severity row: applications fetch `current`, and until
    the promotion lands they are fetching a password the database no longer
    has."""
    estate(
        answers={
            "ACME_WEB_USER": [
                VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017"),
                VerifyResult(VERIFY_LOGIN, SKIPPED, detail="within 2 of the limit"),
            ]
        }
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")

    warnings = document(result)["results"][0]["warnings"]
    assert any("was not promoted" in one["message"] for one in warnings)


# ------------------------------------------------------------------ the fence ---


def steal(path: str, *, at: str) -> Callable[[dict[str, Any], str], None]:
    """Somebody else takes this document's lock, once, mid-run (#282).

    A real record at the real path written under a different `correlation_id`, so
    the run's next fence check fails on the version and would fail on the id too.
    Once, because a takeover happens once and a hook firing on every call would
    also fence the run's very first target.

    ``at`` is which seam it happens on, and it is what makes the two exit codes
    testable: ``describe_user`` fires before this run has changed anything, and
    ``set_password`` fires once one database has been changed.
    """
    taken: list[str] = []

    def take(harness: dict[str, Any], event: str) -> None:
        if taken or event != at:
            return
        taken.append(path)
        theirs = LockRecord.acquired(
            correlation_id="01JSOMEBODYELSE",
            command="creds rotate",
            holder=Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli"),
            now=utc_now(),
        )
        harness["store"].write(
            lock_path(LockKey(store="vault-prod", path=path)), theirs.to_dict(), cas=None
        )

    return take


def test_a_takeover_after_a_change_stops_the_run_and_promotes_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §8's fence row: abort immediately, mutate nothing further. Exit 4
    rather than 7, because 7 asserts nothing happened and one database has just
    been changed."""
    harness = estate(on_call=steal("apps/acme/appdb-beta", at="set_password"))

    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.PARTIAL
    assert sum(len(session.changed) for session in harness["sessions"]) == 1
    # Neither document is promoted: not the one whose lock went, and not the one
    # this run still holds. A promotion asserts the whole estate has the password.
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]["acme_web_user"] == STAGED
    assert stored(harness["store"], "apps/acme/appdb-beta")["pending"]["acme_web_user"] == STAGED


def test_a_stopped_run_says_so_instead_of_offering_the_repair(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#264's line says *run this again*, which is the one thing not to do while
    somebody else holds this estate's lock."""
    estate(on_call=steal("apps/acme/appdb-beta", at="set_password"))

    result = run(runner, write_config(CONFIG))

    assert "taken over" in result.output
    assert "repair with:" not in result.output


def test_a_stopped_run_carries_the_code_that_separates_it_from_a_failed_one(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, validator: Any
) -> None:
    """Both exit 4, and they want opposite responses -- which is exactly what
    `03-json-output.md` §3 says a diagnostic code is for."""
    estate(on_call=steal("apps/acme/appdb-beta", at="set_password"))

    result = run(runner, write_config(CONFIG), "--output", "json")
    found = document(result)

    validator.validate(found)
    assert found["exit_code"] == ExitCode.PARTIAL
    assert [one["code"] for one in found["diagnostics"] if one["level"] == "error"] == [
        "SOPULI-W011"
    ]


def test_a_takeover_before_any_change_is_exit_seven(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The other half of the split `sopuli/lock/errors.py` leaves to the command.

    The lock went after this run acquired it and before it changed anything, so
    nothing happened -- which is what exit 7 asserts, and what exit 4 would deny.
    """
    harness = estate(on_call=steal("apps/acme/appdb-alpha", at="describe_user"))

    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.LOCK_HELD
    assert harness["sessions"][0].changed == []
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]["acme_web_user"] == STAGED


def test_the_lease_is_renewed_at_each_target_boundary(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §8 step 5. Visible as the lock record's version, because a renewal is
    a write -- which is also why it carries the boundary's fence check.

    Counted exactly rather than "more than before". Two targets means one
    boundary, so this path is written three times: acquired, renewed, released.
    Without the renewal it would be written twice, and a test asserting only that
    the version moved would pass either way.
    """
    harness = estate()
    assert harness["store"].read("locks/apps/acme/appdb-alpha") is None

    result = run(runner, write_config(CONFIG))
    after = harness["store"].read("locks/apps/acme/appdb-alpha")

    assert result.exit_code == ExitCode.SUCCESS
    assert after.version == 3


def test_two_accounts_sharing_a_document_promote_together(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Q7's default layout: one write, one version, both accounts."""
    harness = estate(
        documents={
            "apps/acme/db": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
                "pending": {"acme_web_user": STAGED, "acme_batch_user": STAGED},
            }
        },
        users={"ACME_WEB_USER": user(), "ACME_BATCH_USER": user("ACME_BATCH_USER")},
        answers={"ACME_WEB_USER": drifted(), "ACME_BATCH_USER": drifted()},
    )
    before = harness["store"].read("apps/acme/db").version
    result = run(runner, write_config(SHARED_CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["store"].read("apps/acme/db").version == before + 1
    assert stored(harness["store"], "apps/acme/db")["pending"] == {}


def test_one_account_failing_holds_back_its_sibling_too(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """They share a document, so they share its commit. Promoting one and not the
    other would need two writes and would leave a document nobody intended."""
    harness = estate(
        documents={
            "apps/acme/db": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
                "pending": {"acme_web_user": STAGED, "acme_batch_user": STAGED},
            }
        },
        users={"ACME_WEB_USER": user(), "ACME_BATCH_USER": None},
        answers={"ACME_WEB_USER": drifted()},
    )
    result = run(runner, write_config(SHARED_CONFIG))

    assert result.exit_code == ExitCode.PARTIAL
    assert stored(harness["store"], "apps/acme/db")["pending"]["acme_web_user"] == STAGED


# -------------------------------------------------------------- the failures ---


def test_an_unreachable_target_is_a_finding_and_not_a_crash(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """And it means something stronger here than in `check`: a database that
    could not be reached cannot cause a password it does not have to be
    advertised."""
    harness = estate(connect_error=RuntimeError("ORA-12541: no listener"))
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.FAILURE
    assert "ORA-12541" in result.output
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]


def test_a_refused_statement_is_reported_per_account(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """ORA-28003 and friends: the server refused the password. It is reported and
    never regenerated here -- the value came from the vault, and drawing a
    different one would make the vault and the database disagree with what the
    operator staged."""
    harness = estate(set_error=RuntimeError("ORA-28003: password verify function rejected it"))
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.FAILURE
    assert "ORA-28003" in result.output
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]


def test_readonly_refuses_before_anything_connects(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 10's ratchet, and invariant 4's timing."""
    harness = estate()
    result = run(runner, write_config(CONFIG), "--readonly")

    assert harness["sessions"] == []
    assert result.exit_code != ExitCode.SUCCESS


# ------------------------------------------------------- the lockout budget ---


def test_both_logins_are_budgeted_up_front(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §7 mitigation 1 counts attempts per *run*. Asking for one and then
    asking again would let a run spend two on a counter the guard was protecting
    from spending two."""
    harness = estate()
    run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].budgets == [2, 2]


def test_a_declined_pre_flight_still_applies(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The guard declining means the run cannot tell whether a change is needed,
    and `ALTER USER` is not a login -- so applying converges and costs the
    counter nothing."""
    harness = estate(
        answers={
            "ACME_WEB_USER": [
                VerifyResult(VERIFY_LOGIN, SKIPPED, detail="within 2 of the limit"),
                VerifyResult(VERIFY_LOGIN, PASS, latency_ms=9),
            ]
        }
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].changed == [("ACME_WEB_USER", STAGED)]
    assert result.exit_code == ExitCode.SUCCESS


# --------------------------------------------------------------- the strategy ---


def rollover_user(name: str = "ACME_WEB_USER") -> UserState:
    """An account whose profile grants a window."""
    return user(name, profile="APP_PROFILE", rollover_enabled=True, rollover_time="1")


def applying(harness: dict[str, Any]) -> Any:
    """The session that did the work.

    Not `sessions[0]`: an explicit `--strategy` surveys the estate first, so the
    first session per target is the pre-flight and it changes nothing by
    construction. Asserting on it would pass for the wrong reason.
    """
    return harness["sessions"][-1]


def test_rollover_is_the_default_where_the_estate_allows_it(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §6.3, and no flag needed: both passwords authenticate afterwards, so
    the run reports `ROLLOVER_ACTIVE` rather than `IN_SYNC`."""
    harness = estate(
        users={"ACME_WEB_USER": rollover_user()},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert check.ROLLOVER_ACTIVE in result.output
    assert harness["sessions"][0].finished == []


def test_the_window_is_reported_with_the_profile_that_grants_it(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`active` alone leaves a consumer inferring the deadline from a word, and
    `profile_rollover_time` is what says whether this was the regime asked for or
    the only one available."""
    estate(
        users={"ACME_WEB_USER": rollover_user()},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")

    rollover = document(result)["results"][0]["rollover"]
    assert rollover["active"] is True
    assert rollover["profile_rollover_time"] == "1"


def test_direct_closes_the_window_it_opened(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The difference between "the old password stops working in an hour" and
    "the old password stopped working just now"."""
    harness = estate(
        users={"ACME_WEB_USER": rollover_user()},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--strategy", "direct")

    assert applying(harness).finished == ["ACME_WEB_USER"]
    assert check.IN_SYNC in result.output
    assert "no longer works" in result.output


def test_direct_does_not_close_a_window_it_could_not_confirm(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Closing it on an unverified change leaves an account whose old password
    has stopped working and whose new one is not known to work -- the one state
    worse than the grace period `direct` exists to avoid."""
    harness = estate(
        users={"ACME_WEB_USER": rollover_user()},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
        answers={
            "ACME_WEB_USER": [
                VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017"),
                VerifyResult(VERIFY_LOGIN, SKIPPED, detail="within 2 of the limit"),
            ]
        },
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--strategy", "direct")

    assert applying(harness).changed
    assert applying(harness).finished == []
    assert result.exit_code != ExitCode.SUCCESS


def test_direct_against_a_plain_profile_closes_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The change was already immediate. A statement to prove it would have no
    work in it."""
    harness = estate(capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}))
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--strategy", "direct")

    assert applying(harness).finished == []
    assert result.exit_code == ExitCode.SUCCESS


def test_staged_against_a_rollover_profile_is_refused_before_anything_changes(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Oracle opens the window because the profile says so. Running anyway and
    reporting `staged` would tell an application team the old password had
    stopped working when it had not."""
    harness = estate(
        users={"ACME_WEB_USER": rollover_user()},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--strategy", "staged")

    assert result.exit_code != ExitCode.SUCCESS
    assert all(session.changed == [] for session in harness["sessions"])
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]


def test_an_unhonourable_strategy_stops_the_whole_estate(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 4, and the reason the pre-flight pays for a second connection:
    naming a regime is asking for a property of the *estate*, and honouring it on
    one PDB before discovering the second cannot would already have broken it."""
    harness = estate(
        users={"ACME_WEB_USER": rollover_user()},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
    )
    run(runner, write_config(CONFIG), "--strategy", "staged")

    assert all(session.changed == [] for session in harness["sessions"])
    for target in ("appdb-alpha", "appdb-beta"):
        assert stored(harness["store"], f"apps/acme/{target}")["pending"]


def test_the_default_strategy_costs_no_extra_connection(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The pre-flight is what `--strategy` buys and what it costs. With no flag
    there is nothing to refuse -- the regime is chosen per account from what that
    account can do -- so the run opens one session per target and no more."""
    harness = estate()
    run(runner, write_config(CONFIG))

    assert len(harness["sessions"]) == 2


def test_an_explicit_strategy_surveys_first(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Two sessions per target: one that clears the estate, one that changes it."""
    harness = estate(capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}))
    run(runner, write_config(CONFIG), "--strategy", "staged")

    assert len(harness["sessions"]) == 4


def test_rollover_is_refused_through_the_driver(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`require_rollover` owns both of its refusals (#181) and carries the exact
    `ALTER PROFILE` for the profile one. The command routes to it rather than
    restating either."""
    harness = estate(
        rollover_refusal=RuntimeError("profile APP_PROFILE grants no rollover window"),
    )
    result = run(runner, write_config(CONFIG), "--strategy", "rollover")

    assert result.exit_code != ExitCode.SUCCESS
    assert all(session.changed == [] for session in harness["sessions"])


def test_an_unreachable_target_is_not_a_strategy_problem(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The pre-flight skips it, and the run reports it per account with the
    vendor code -- which is a different thing to go and fix."""
    estate(connect_error=RuntimeError("ORA-12541: no listener"), capabilities=frozenset())
    result = run(runner, write_config(CONFIG), "--strategy", "staged")

    assert "ORA-12541" in result.output
    assert result.exit_code == ExitCode.FAILURE


def test_a_missing_account_does_not_refuse_the_estate_over_a_strategy(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`ACCOUNT_MISSING` is a state the run reports per account. The driver's
    `require_rollover` raises for one, having no way to know this caller would
    rather skip it, so the pre-flight has to check before asking -- otherwise an
    account the run was going to report on anyway takes the whole estate down."""
    harness = estate(users={})
    result = run(runner, write_config(CONFIG), "--strategy", "rollover")

    assert check.ACCOUNT_MISSING in result.output
    assert result.exit_code == ExitCode.FAILURE
    assert all(session.changed == [] for session in harness["sessions"])


# ------------------------------------------------------------- the rollback ---


def _rolled() -> dict[str, dict[str, Any]]:
    """A finished rotation with a `previous` to go back to."""
    return {
        "apps/acme/appdb-alpha": {
            "DB_CREDENTIALS": {"acme_web_user": LIVE},
            "previous": {"acme_web_user": "The-One-Before-2025"},
        }
    }


def test_a_rollback_puts_previous_back_and_swaps_the_vault(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §8's escape hatch. The estate ends consistent: `current` holds what
    the database now has, `previous` holds what was taken off it."""
    harness = estate(
        documents=_rolled(),
        answers={"ACME_WEB_USER": drifted()},
    )
    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--source",
        "previous",
        "--confirm",
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["sessions"][0].changed == [("ACME_WEB_USER", "The-One-Before-2025")]
    body = stored(harness["store"], "apps/acme/appdb-alpha")
    assert body["DB_CREDENTIALS"]["acme_web_user"] == "The-One-Before-2025"
    assert body["previous"]["acme_web_user"] == LIVE


def test_the_rollback_verdict_says_rolled_back(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The two runs are indistinguishable otherwise, and one of them moved an
    estate backwards on purpose."""
    estate(documents=_rolled(), answers={"ACME_WEB_USER": drifted()})
    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--source",
        "previous",
        "--confirm",
    )

    assert "1 rolled back" in result.output


def test_a_rollback_without_confirm_is_refused(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The one invocation whose *success* stops an application's credential
    working. A closed stdin is a refusal rather than a prompt that reads EOF."""
    harness = estate(documents=_rolled())
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--source", "previous")

    assert harness["sessions"] == []
    assert result.exit_code != ExitCode.SUCCESS


def test_a_rollback_with_no_previous_says_so(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Bounded to one generation (Q3, #84), so there is nothing to run and the
    message must not say `creds generate`."""
    harness = estate(
        documents={"apps/acme/appdb-alpha": {"DB_CREDENTIALS": {"acme_web_user": LIVE}}}
    )
    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--source",
        "previous",
        "--confirm",
    )

    assert harness["sessions"][0].changed == []
    assert "nothing to roll back to" in result.output
    assert result.exit_code == ExitCode.FAILURE


def test_a_rollback_under_a_rotation_in_flight_is_refused(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The `pending` would survive, and the next `apply` would move the estate
    forward with it -- undoing the undo, unattended."""
    harness = estate(
        documents={
            "apps/acme/appdb-alpha": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE},
                "pending": {"acme_web_user": STAGED},
                "previous": {"acme_web_user": "The-One-Before-2025"},
            }
        }
    )
    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--source",
        "previous",
        "--confirm",
    )

    assert harness["sessions"][0].changed == []
    assert "PENDING_APPLY" in result.output
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]["acme_web_user"] == STAGED


def test_a_rollback_dry_run_needs_no_confirmation(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A preview an operator has to authorise is a preview they will stop
    taking."""
    harness = estate(documents=_rolled())
    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--source",
        "previous",
        "--dry-run",
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert "previous" in result.output
    assert harness["sessions"] == []


# ------------------------------------------------------ the other two stages ---


def test_source_current_ignores_a_staged_pending(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The case for the flag: a staged password turns out to be wrong, and the
    estate goes back on what applications are actually reading -- without
    discarding the `pending`."""
    harness = estate(
        documents={
            "apps/acme/appdb-alpha": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE},
                "pending": {"acme_web_user": STAGED},
            }
        },
        answers={"ACME_WEB_USER": drifted()},
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--source", "current")

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["sessions"][0].changed == [("ACME_WEB_USER", LIVE)]
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]["acme_web_user"] == STAGED


def test_source_pending_does_not_fall_back_to_current(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """An explicit stage that holds nothing is a run that did not do what it was
    asked, and it must not quietly do something else."""
    harness = estate(
        documents={"apps/acme/appdb-alpha": {"DB_CREDENTIALS": {"acme_web_user": LIVE}}}
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--source", "pending")

    assert harness["sessions"][0].changed == []
    assert result.exit_code == ExitCode.FAILURE
    assert "creds generate" in result.output

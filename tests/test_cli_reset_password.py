"""`sopuli account reset-password` from the command line.

Tier 0 for the refusals, which need no database: each of the guards in
decision #439 has an exit code, and a guard whose code changed would be a
script's behaviour changing silently.

Tier 1 for the two things only a database can answer. The first is that a
`--dry-run` resets nothing: it draws no password, issues no DDL and leaves the
account open (invariant 8). It has to be tier 1 because the preview flag is
threaded through the verb, and a flag that is passed along and never read looks
correct to every tier-0 test; only the account's state shows whether DDL went
out. The second is that the seen path prints a password that works and expires
the account.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from conftest import WriteConfig
from oracle_harness import Environment
from sopuli.cli import cli
from sopuli.config.targets import ADMIN_PASSWORD_ENV
from sopuli.delivery.vault_wrapped import NotWrappableError
from sopuli.exit_codes import ExitCode
from sopuli.lock.errors import LockDeniedError, LockStolenError
from sopuli.lock.manager import LockManager
from sopuli.safety import RefusedError
from sopuli.store import StoreError
from sopuli.store.hashicorp.kv2 import Kv2Store

ACCOUNT = "acme_dev_alice"
OLD = "Old-Pa55word-Alice1"

MANUAL = """version: 1

defaults:
  policy: personal-standard

targets:
  - name: tier1-oracle
    type: oracle
    environment: dev
    dsn: "{dsn}"
    admin: {{ username: {user}, auth: {{ method: env }} }}

policies:
  personal-standard:
    password:
      length: 20
      charset: alnum_safe
      first_char: alpha
      require: {{ upper: 1, lower: 1, digit: 1, special: 1 }}

personal_accounts:
  - accounts: [{account}]
    policy: personal-standard

delivery:
  method: manual
  manual:
    force_expire: true
"""

OFFLINE = MANUAL.format(dsn="192.0.2.10:1521/ALPHA", user="SOPULI_SVC", account=ACCOUNT)


def run(runner: CliRunner, config: Path, *args: str, input: str | None = None) -> Any:  # noqa: A002
    return runner.invoke(
        cli, ["--config", str(config), "account", "reset-password", *args], input=input
    )


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ----------------------------------------------------- the refusals, tier 0 ---


def test_json_output_is_refused_on_the_seen_path(
    runner: CliRunner, write_config: WriteConfig
) -> None:
    """Guard 2, and the exit code a script branches on."""
    result = run(runner, write_config(OFFLINE), "--account", ACCOUNT, "--output", "json")

    assert result.exception.exit_code == ExitCode.USAGE
    assert "cannot be used with --output json" in str(result.exception)


def test_confirm_is_refused_on_the_seen_path(runner: CliRunner, write_config: WriteConfig) -> None:
    """Guard 4. `CliRunner` gives no terminal either, so this also pins the
    order: the usage error is asked before the environment one."""
    result = run(runner, write_config(OFFLINE), "--account", ACCOUNT, "--confirm")

    assert result.exception.exit_code == ExitCode.USAGE
    assert "--confirm cannot answer" in str(result.exception)


def test_a_non_terminal_stdout_is_refused_on_the_seen_path(
    runner: CliRunner, write_config: WriteConfig
) -> None:
    """Guard 3, which is what `CliRunner` is by default: its stdout is a buffer,
    exactly like a redirect or a CI log."""
    result = run(runner, write_config(OFFLINE), "--account", ACCOUNT)

    assert result.exception.exit_code == ExitCode.ABORTED
    assert "not a terminal" in str(result.exception)


def test_a_non_terminal_stdin_is_refused_on_the_seen_path(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Guard 4's other half (#853): the prompt comes after the DDL, so a stdin
    that cannot answer it is refused before anything connects. The target is
    unreachable on purpose, so a refusal that came later would be a timeout."""
    monkeypatch.setattr("sopuli.cli.is_a_terminal", lambda stream: stream is sys.stdout)
    result = run(runner, write_config(OFFLINE), "--account", ACCOUNT, input="y\n")

    assert result.exception.exit_code == ExitCode.ABORTED
    assert "stdin is not a terminal" in str(result.exception)


def test_an_unimplemented_method_is_refused_before_anything_connects(
    runner: CliRunner, write_config: WriteConfig
) -> None:
    """Exit 5, and the target is unreachable on purpose: the refusal has to come
    from the delivery gate rather than from a connection timing out."""
    config = OFFLINE.replace(
        "method: manual\n  manual:\n    force_expire: true",
        "method: one_time_link\n  one_time_link: {}",
    )
    result = run(runner, write_config(config), "--account", ACCOUNT)

    assert result.exception.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
    assert "not implemented in this build" in str(result.exception)


def test_no_delivery_configured_is_refused_before_anything_connects(
    runner: CliRunner, write_config: WriteConfig
) -> None:
    """The same argument one step earlier: a reset with nowhere to deliver must
    not reach a database, so this fails against an address nothing answers."""
    config = OFFLINE.split("\ndelivery:")[0] + "\n"
    result = run(runner, write_config(config), "--account", ACCOUNT)

    assert result.exception.exit_code == ExitCode.ABORTED
    assert "nowhere to go" in str(result.exception)


def test_force_expire_false_is_refused_at_load(
    runner: CliRunner, write_config: WriteConfig
) -> None:
    """Guard 5, and the config layer is where it lives -- exit 9, because this
    one really is the file being wrong."""
    config = OFFLINE.replace("force_expire: true", "force_expire: false")
    result = run(runner, write_config(config), "--account", ACCOUNT)

    assert result.exception.exit_code == ExitCode.CONFIG_INVALID
    assert "requires `force_expire: true`" in str(result.exception)


# ------------------------------------------------------ the preview, tier 1 ---


@pytest.fixture
def account(
    live_oracle: Environment, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Callable[..., Any]]:
    """A real account to reset, dropped afterwards.

    It also puts the admin password where `auth: { method: env }` reads it. The
    driver tests connect through their own fixture; this one goes through the CLI
    boundary, which resolves the credential the way a real run does -- and a run
    that could not authenticate would report `ERROR` and prove nothing about
    previews.
    """
    oracledb = pytest.importorskip("oracledb")
    user = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
    password = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")
    monkeypatch.setenv(ADMIN_PASSWORD_ENV, password)
    connection = oracledb.connect(user=user, password=password, dsn=live_oracle.dsn)

    def sql(statement: str) -> None:
        with connection.cursor() as cursor:
            cursor.execute(statement)

    def status() -> str:
        with connection.cursor() as cursor:
            cursor.execute(
                "select account_status from dba_users where username = :1", [ACCOUNT.upper()]
            )
            row = cursor.fetchone()
        return str(row[0]) if row else "ABSENT"

    with contextlib.suppress(Exception):  # absent is the ordinary case
        sql(f"drop user {ACCOUNT} cascade")
    sql(f'create user {ACCOUNT} identified by "{OLD}"')
    sql(f"grant create session to {ACCOUNT}")
    try:
        yield status
    finally:
        try:
            sql(f"drop user {ACCOUNT} cascade")
        finally:
            connection.close()


def test_a_dry_run_changes_nothing(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
) -> None:
    """Invariant 8, against a real account.

    The account status afterwards is the whole assertion. A preview that had
    issued the DDL would leave it `EXPIRED`, and the output would still read
    like a preview.

    It runs on the **seen** path deliberately: that is where the guards are, and
    a preview must work without a terminal -- refusing one would make *show me
    what this would do* impossible from the CI job that most wants it.
    """
    config = write_config(
        MANUAL.format(
            dsn=live_oracle.dsn,
            user=os.environ.get("SOPULI_TEST_ORACLE_USER", "system"),
            account=ACCOUNT,
        )
    )
    before = account()

    result = run(runner, config, "--account", ACCOUNT, "--dry-run")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "would reset" in result.output
    assert account() == before == "OPEN", "the preview issued the DDL"


def test_the_preview_prints_no_password(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
) -> None:
    """UC-2 §2: a `--dry-run` of a mutating verb prints the plan and never a
    password. Asserted on the shape of the output rather than on a value, since
    the run does not draw one to compare against -- which is itself the point."""
    config = write_config(
        MANUAL.format(
            dsn=live_oracle.dsn,
            user=os.environ.get("SOPULI_TEST_ORACLE_USER", "system"),
            account=ACCOUNT,
        )
    )

    result = run(runner, config, "--account", ACCOUNT, "--dry-run")

    assert "shown once" not in result.output
    assert "password for" not in result.output


def test_the_seen_path_prints_a_working_password_and_expires_the_account(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The whole feature, end to end, and the three claims it makes.

    **The terminal is faked, and it has to be.** Guard 3 refuses unless stdout is
    a terminal, and a test harness is by definition not one -- so the only way to
    exercise the path the guard protects is to answer that one question
    differently. Everything else is real: a real account, a real `ALTER USER`, a
    real logon with what was printed.

    Three assertions, one per claim:

    * the value shown **works** -- it is the account's password, not a sample;
    * the account is **EXPIRED**, so the exposure ends at the owner's first
      logon, which is what makes the fourth exception to invariant 2 allowable;
    * the value appears **once**, in the block meant for it, and nowhere else in
      the output -- not in the plan, not in the table, not in a detail string.
    """
    monkeypatch.setattr("sopuli.cli.is_a_terminal", lambda stream: True)
    config = write_config(
        MANUAL.format(
            dsn=live_oracle.dsn,
            user=os.environ.get("SOPULI_TEST_ORACLE_USER", "system"),
            account=ACCOUNT,
        )
    )

    result = run(runner, config, "--account", ACCOUNT, input="y\n")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "shown once" in result.output

    shown = [
        line.strip()
        for line in result.output.splitlines()
        if line.startswith("    ") and line.strip()
    ]
    assert len(shown) == 1, f"expected one indented password line, got {shown}"
    password = shown[0]

    assert account() == "EXPIRED"
    assert result.output.count(password) == 1, "the password appears more than once"

    oracledb = pytest.importorskip("oracledb")
    with pytest.raises(Exception, match="ORA-28001"):
        # It works *and* it is expired: Oracle answers the change-at-logon flow
        # rather than refusing, which is how §5 distinguishes an expired password
        # from a wrong one. A wrong one would be ORA-01017.
        oracledb.connect(user=ACCOUNT, password=password, dsn=live_oracle.dsn)


def test_debug_output_holds_no_password_on_the_seen_path(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`--debug` logs each statement, and the `ALTER USER` in its redacted form
    (#782). The seen path is the one that also prints the password, so the test
    has the value to look for: once on stdout, never on stderr."""
    monkeypatch.setattr("sopuli.cli.is_a_terminal", lambda stream: True)
    config = write_config(
        MANUAL.format(
            dsn=live_oracle.dsn,
            user=os.environ.get("SOPULI_TEST_ORACLE_USER", "system"),
            account=ACCOUNT,
        )
    )

    result = run(runner, config, "--account", ACCOUNT, "--debug", input="y\n")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    shown = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.startswith("    ") and line.strip()
    ]
    assert len(shown) == 1, f"expected one indented password line, got {shown}"
    password = shown[0]
    assert password not in result.stderr
    assert OLD not in result.stderr
    assert "IDENTIFIED BY ***" in result.stderr
    assert account() == "EXPIRED"


# ---------------------------------------------------------- the reset record ---

#: The same estate with a journal declared. The `vaults:` entry and the
#: `reset_records:` block are the whole difference, which is the point: a record
#: is written because the configuration names somewhere to put one, and for no
#: other reason (UC-2 §3.1).
JOURNALLED = (
    MANUAL
    + """
vaults:
  vault-dev:
    type: hashicorp
    addr: {addr}
    mount: {mount}
    kv_version: 2
    auth:
      method: token

reset_records:
  vault: vault-dev
  prefix: sopuli/personal-resets
"""
)

#: A target whose name cannot be one path segment. Nothing in the config layer
#: refuses it -- a `targets[].name` is "a non-empty string" -- so the refusal has
#: to come from the verb that would derive a record path from it.
SLASHED = OFFLINE.replace("name: tier1-oracle", "name: tier1/oracle")


def test_a_record_path_that_cannot_be_derived_is_refused_at_plan_time(
    runner: CliRunner, write_config: WriteConfig
) -> None:
    """Invariant 4, and the reason the path is derived before anything connects.

    A `/` in a target name derives the same record path as a *different* target
    and account, which is one journal describing two accounts and one lock
    where there should be two. Refusing after the password had
    changed would be finding that out in the worst order.
    """
    written = (
        SLASHED
        + """
vaults:
  vault-dev:
    type: hashicorp
    addr: http://127.0.0.1:8200
    mount: kv
    kv_version: 2
    auth:
      method: token

reset_records:
  vault: vault-dev
  prefix: sopuli/personal-resets
"""
    )
    # Under `--dry-run`, which is what makes this a tier-0 test: a preview is
    # exempt from the seen path's terminal guard and connects to nothing,
    # so what is left to refuse the run is the derivation itself. The refusal
    # firing in a preview is the property worth having anyway -- it is about
    # what the configuration says, not about an emission.
    result = run(runner, write_config(written), "--account", ACCOUNT, "--dry-run")

    assert result.exception.exit_code == ExitCode.CONFIG_INVALID
    rendered = str(result.exception)
    assert "no reset record path" in rendered
    assert ACCOUNT in rendered
    assert "tier1/oracle" in rendered


@pytest.fixture
def journal(vault_stack: Any, private_mount: str, monkeypatch: pytest.MonkeyPatch) -> Any:
    """A real Vault to journal into, and the token chain a real run uses.

    `method: token` with nothing written down falls through to the environment
    (§3a); invariant 1 rules out the other ways of getting it here.
    """
    monkeypatch.setenv("VAULT_TOKEN", vault_stack.token)
    monkeypatch.delenv("SOPULI_VAULT_TOKEN", raising=False)
    return vault_stack


def _journalled_config(live_oracle: Environment, vault_stack: Any, mount: str) -> str:
    return JOURNALLED.format(
        dsn=live_oracle.dsn,
        user=os.environ.get("SOPULI_TEST_ORACLE_USER", "system"),
        account=ACCOUNT,
        addr=vault_stack.addr,
        mount=mount,
    )


def test_the_reset_is_journalled(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The verb that has the facts writes the reset record (§3.1).

    Read back through the Vault API rather than through the tool, for
    `test_lock_status_vault.py`'s reason: a document this process read with its
    own reader is one it understood by construction.
    """
    monkeypatch.setattr("sopuli.cli.is_a_terminal", lambda stream: True)
    config = write_config(_journalled_config(live_oracle, journal, private_mount))

    result = run(runner, config, "--account", ACCOUNT, input="y\n")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    path = f"sopuli/personal-resets/tier1-oracle/{ACCOUNT}"
    stored = journal.client.get(f"/v1/{private_mount}/data/{path}")
    assert stored.status_code == 200, stored.text
    record = stored.json()["data"]["data"]

    assert record["account"] == ACCOUNT
    assert record["target"] == "tier1-oracle"
    # The seen path, which is what `seen` is for: `delivery.to` is absent
    # because the destination was a person, and this is the field that says so.
    assert record["seen"] is True
    assert record["expired"] is True
    assert record["delivery"] == {"method": "manual"}
    assert "to" not in record["delivery"]
    assert record["by"]["os_user"]
    assert record["correlation_id"]

    shown = [
        line.strip()
        for line in result.output.splitlines()
        if line.startswith("    ") and line.strip()
    ]
    assert len(shown) == 1, f"expected one indented password line, got {shown}"
    assert shown[0] not in json.dumps(record), "the record carries the password it set"


def test_a_run_with_no_journal_declared_says_so_and_still_resets(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """§3.4's first absence: a warning, never a refusal.

    The seen path may have no store at all -- that is the site `manual` exists
    for -- so a reset with nothing declared writes no record, takes no lock, and
    runs. A person who cannot log in is still locked out whether or not the
    estate keeps history.
    """
    monkeypatch.setattr("sopuli.cli.is_a_terminal", lambda stream: True)
    config = write_config(
        MANUAL.format(
            dsn=live_oracle.dsn,
            user=os.environ.get("SOPULI_TEST_ORACLE_USER", "system"),
            account=ACCOUNT,
        )
    )

    result = run(runner, config, "--account", ACCOUNT, input="y\n")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "no `reset_records:` block is declared" in result.output
    assert "no advisory lock" in result.output
    assert account() == "EXPIRED", "the reset was refused over a journal"


def test_a_record_that_cannot_be_written_warns_on_a_successful_run(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """§3.4's second absence, which is the one that must not fail the run.

    The password has already changed and the person still needs it, so a journal
    that could not be written is a warning on a **successful** run. Provoked by
    refusing the write rather than by breaking the token, so that what is
    exercised is this verb's handling rather than Vault's 403 path -- which the
    store's own tests already cover.
    """
    monkeypatch.setattr("sopuli.cli.is_a_terminal", lambda stream: True)
    config = write_config(_journalled_config(live_oracle, journal, private_mount))

    real = Kv2Store.write

    def refuse_the_record(self: Any, path: str, data: Any, *, cas: int | None) -> int:
        # The **record** path only, never `locks/`. A store that refused
        # both would fail the run at acquisition, before the password changed,
        # which is a different case with its own test below. What this stands in
        # for is a Vault policy granting the lock prefix and not the journal one.
        if path.startswith("locks/"):
            return int(real(self, path, data, cas=cas))
        raise RuntimeError("permission denied by the test")

    monkeypatch.setattr("sopuli.store.hashicorp.kv2.Kv2Store.write", refuse_the_record)

    result = run(runner, config, "--account", ACCOUNT, input="y\n")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "could not be written" in result.output
    assert "permission denied by the test" in result.output
    assert account() == "EXPIRED", "a failed record write rolled back the reset"


def test_a_journal_that_cannot_be_opened_refuses_before_anything_is_issued(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Not 3.4's absence, and the difference is *when*.

    A declared journal is opened before the first statement, because the lock
    lives in it. So a store that cannot be reached stops the run where UC-1's
    lock stores already stop one -- before the DDL, with the
    person's old password still working and nothing to explain. 3.4's absences
    are all about a store that went away *after* the password changed; there the
    reset stands and `SOPULI-W025` carries it.
    """
    monkeypatch.setattr("sopuli.cli.is_a_terminal", lambda stream: True)
    config = write_config(_journalled_config(live_oracle, journal, private_mount))
    before = account()

    def unreachable(run: Any, config: Any) -> Any:
        raise RuntimeError("the store could not be opened by the test")

    monkeypatch.setattr("sopuli.cli._reset_journal", unreachable)

    result = run(runner, config, "--account", ACCOUNT, input="y\n")

    assert result.exit_code != ExitCode.SUCCESS
    assert account() == before == "OPEN", "the reset ran without the lock it was told to take"


# -------------------------------------------------------------- the lock ---

#: Where the advisory lock for this (target, account) lives: the record's own
#: path under the `locks/` prefix the manager adds (UC-2 3.3).
LOCK_PATH = f"locks/sopuli/personal-resets/tier1-oracle/{ACCOUNT}"
RECORD_PATH = f"sopuli/personal-resets/tier1-oracle/{ACCOUNT}"

#: Somebody else's claim, expiring far enough away that nothing here is about
#: expiry. `break_expired` is off by default, so a live claim is a refusal.
THEIR_LOCK = {
    "state": "held",
    "correlation_id": "01JTHEIRS",
    "command": "account reset-password",
    "holder": {"host": "ci-runner-3", "pid": 8821, "os_user": "svc_sopuli"},
    "acquired_at": "2030-01-01T12:00:00Z",
    "expires_at": "2030-01-01T12:15:00Z",
}


def test_a_reset_of_an_account_somebody_else_is_resetting_is_refused(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The collision UC-2 3.3 keys the lock to prevent, from the command line.

    Two DBAs resetting the same person at once: the second password overwrites
    the first before the person has fetched either, and neither DBA finds out.
    The claim is written through the Vault API rather than by a second run of
    the tool, so what is asserted is that this run reads somebody else's lock
    rather than that it can read its own.

    **Nothing was issued**, which is the other half and the reason exit 7 is
    honest here: acquisition happens before the first connection.
    """
    monkeypatch.setattr("sopuli.cli.is_a_terminal", lambda stream: True)
    config = write_config(_journalled_config(live_oracle, journal, private_mount))
    # Written the way the tool writes one, not the short way: `cas_required` on
    # the path first, then the record under `cas: 0`. A path created without the
    # metadata is refused by the manager's own pre-flight with exit 5,
    # which would make this test pass for the wrong reason -- it would never
    # reach the claim it is about.
    journal.client.post(f"/v1/{private_mount}/metadata/{LOCK_PATH}", json={"cas_required": True})
    journal.client.post(
        f"/v1/{private_mount}/data/{LOCK_PATH}",
        json={"data": THEIR_LOCK, "options": {"cas": 0}},
    )
    before = account()

    result = run(runner, config, "--account", ACCOUNT, input="y\n")

    # `CliRunner` drives the group rather than `sopuli.cli.main`, so the refusal
    # arrives as the exception and the runner's own code is 1. `LockDeniedError`
    # is what the boundary maps to exit 7, and it carries no code of its own --
    # `tests/test_cli_creds_apply.py` asserts the same way for the same reason.
    assert isinstance(result.exception, LockDeniedError), result.exception
    assert "ci-runner-3" in str(result.exception), "the message names who holds it"
    assert account() == before == "OPEN", "the reset ran under somebody else's lock"
    stored = journal.client.get(f"/v1/{private_mount}/data/{RECORD_PATH}")
    assert stored.status_code == 404, "a refused reset wrote a record"


def test_the_lock_is_let_go_when_the_reset_is_done(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Released rather than deleted (UC-1 §8): a deleted path leaves a version
    counter no first acquisition could ever take again, so the record stays and
    says `released`. The next reset of this account has to be able to run."""
    monkeypatch.setattr("sopuli.cli.is_a_terminal", lambda stream: True)
    config = write_config(_journalled_config(live_oracle, journal, private_mount))

    result = run(runner, config, "--account", ACCOUNT, input="y\n")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    stored = journal.client.get(f"/v1/{private_mount}/data/{LOCK_PATH}")
    assert stored.status_code == 200, stored.text
    assert stored.json()["data"]["data"]["state"] == "released"


def test_a_preview_takes_no_lock(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
) -> None:
    """Invariant 8 read for the lock: a preview writes nothing, and a lock record
    is a write. `creds generate` takes none under `--dry-run` for the same
    reason, and a preview that left a claim in the vault would block the run it
    was previewing."""
    config = write_config(_journalled_config(live_oracle, journal, private_mount))

    result = run(runner, config, "--account", ACCOUNT, "--dry-run")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert journal.client.get(f"/v1/{private_mount}/data/{LOCK_PATH}").status_code == 404


#: The same estate with a second target pointed at the same database. Two
#: targets rather than two databases: what is under test is the run's handling of
#: a lost fence between one target and the next, and the number of Oracles in the
#: tier-1 stack has nothing to do with it.
TWO_TARGETS = """
  - name: tier1-oracle-b
    type: oracle
    environment: dev
    dsn: "{dsn}"
    admin: {{ username: {user}, auth: {{ method: env }} }}
"""


def test_a_fence_lost_between_targets_stops_there_and_exits_four(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`creds generate`'s split, on this verb.

    Exit 7 asserts that nothing happened. Once the first target's password has
    been reset, that is a lie -- somebody is holding a password that works -- so
    a fence lost before the *second* target is exit 4 with `SOPULI-W011`, and the
    second target is not touched.

    The steal is simulated at the fence rather than by racing a second process:
    what is under test is this verb's branch, and a real race would assert the
    lock manager's behaviour, which `tests/lock/` already holds.
    """
    monkeypatch.setattr("sopuli.cli.is_a_terminal", lambda stream: True)
    user = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
    # Inserted into `targets:` rather than appended, which is where a second
    # entry goes and not where the file ends.
    marker = "\npolicies:"
    written = _journalled_config(live_oracle, journal, private_mount).replace(
        marker, TWO_TARGETS.format(dsn=live_oracle.dsn, user=user) + marker
    )
    config = write_config(written)

    checks = {"count": 0}
    real = LockManager.check

    def fence(self: Any, *keys: Any) -> None:
        checks["count"] += 1
        if checks["count"] > 1:
            raise LockStolenError("somebody else holds it now", key=keys[0])
        real(self, *keys)

    monkeypatch.setattr("sopuli.lock.manager.LockManager.check", fence)

    result = run(runner, config, "--account", ACCOUNT, input="y\n")

    assert result.exit_code == ExitCode.PARTIAL, result.output
    assert "somebody else holds it now" in result.output
    first = journal.client.get(f"/v1/{private_mount}/data/{RECORD_PATH}")
    second = journal.client.get(
        f"/v1/{private_mount}/data/sopuli/personal-resets/tier1-oracle-b/{ACCOUNT}"
    )
    assert first.status_code == 200, "the target that ran before the fence was lost"
    assert second.status_code == 404, "the run carried on past the fence"


# ------------------------------------------- the unseen path, `vault_wrapped` ---

#: `JOURNALLED`'s estate, delivering through a wrapping token instead of a
#: terminal. Built on that one rather than on `MANUAL` so a journal exists: the
#: record's `delivery.to` is where this method puts its own reference, and a
#: config with no `reset_records:` writes no record to look at. `vault_wrapped:`
#: names no `vault:`, so the store comes from §3's chain -- `defaults.vault`
#: here, which is the resolution most estates will get.
WRAPPED = JOURNALLED.replace(
    """delivery:
  method: manual
  manual:
    force_expire: true
""",
    """delivery:
  method: vault_wrapped
  vault_wrapped:
    ttl: {ttl}
""",
).replace(
    """defaults:
  policy: personal-standard
""",
    """defaults:
  policy: personal-standard
  vault: vault-dev
""",
)


def _wrapped_config(
    live_oracle: Environment, vault_stack: Any, mount: str, *, ttl: str = "15m"
) -> str:
    return WRAPPED.format(
        dsn=live_oracle.dsn,
        user=os.environ.get("SOPULI_TEST_ORACLE_USER", "system"),
        account=ACCOUNT,
        addr=vault_stack.addr,
        mount=mount,
        ttl=ttl,
    )


def _token_in(text: str) -> str:
    """The wrapping token out of what the operator was shown.

    Parsed out of the real output rather than returned by a seam, because what
    this file is testing is that the operator *can* get it from there -- a helper
    reading it off the receipt would pass with the printing broken.
    """
    found = [word for word in text.split() if word.startswith("hvs.")]
    assert len(found) == 1, f"expected exactly one token in the output, got {found}"
    return found[0]


def _unwrap(vault_stack: Any, token: str) -> Any:
    return vault_stack.client.post(
        "/v1/sys/wrapping/unwrap", headers={"X-Vault-Token": token}, json={}
    )


def test_the_unseen_path_delivers_without_a_terminal_and_without_a_prompt(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
) -> None:
    """The two guards `manual` lives under, and neither applies here.

    `CliRunner`'s stdout is a buffer -- exactly like a redirect or a CI log -- and
    that is the state guard 3 refuses on the seen path. An unseen delivery is
    allowed it on purpose: a pipe is how a handover script works, and forbidding
    one would leave an estate no way to deliver unattended except the path that
    shows a DBA a password. No input is supplied either, so a prompt would abort.
    """
    config = write_config(_wrapped_config(live_oracle, journal, private_mount))

    result = run(runner, config, "--account", ACCOUNT)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "unwraps once" in result.output
    _token_in(result.output)


def test_the_delivered_password_is_the_account_s_and_the_dba_never_saw_it(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
) -> None:
    """The whole point of the path, asserted end to end.

    The password appears nowhere in what the operator was shown, and unwrapping
    the token produces it along with the account it belongs to. Whether it *works*
    is `tests/driver`'s and the by-hand run's; what this pins is that the value in
    the cubbyhole is the one the run set, and that the run's own output is not it.
    """
    config = write_config(_wrapped_config(live_oracle, journal, private_mount))

    result = run(runner, config, "--account", ACCOUNT)

    answer = _unwrap(journal, _token_in(result.output))
    assert answer.status_code == 200, answer.text
    data = answer.json()["data"]
    assert data["account"] == ACCOUNT
    assert data["target"] == "tier1-oracle"
    assert data["password"] not in result.output, "the password reached the operator's screen"


def test_the_account_is_not_expired_on_the_unseen_path(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
) -> None:
    """UC-2 §1's table, from the database's side. Expiry is what ends the *seen*
    path's exposure; here nobody but the owner is meant ever to know the value, so
    there is nothing to end and `PASSWORD EXPIRE` is not issued."""
    config = write_config(_wrapped_config(live_oracle, journal, private_mount))

    result = run(runner, config, "--account", ACCOUNT)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert account() == "OPEN"


def test_the_token_unwraps_exactly_once(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
) -> None:
    """§6.6's claim, checked against Vault rather than taken from the docs.

    Single use is what makes interception *detectable*: a value fetched twice is a
    value somebody else fetched first, and the person's own fetch failing is how
    anybody finds out. This is the assertion the whole method's promise rests on,
    and nothing in this codebase enforces it -- Vault does, which is why it is
    tested against a real one.
    """
    config = write_config(_wrapped_config(live_oracle, journal, private_mount))
    token = _token_in(run(runner, config, "--account", ACCOUNT).output)

    assert _unwrap(journal, token).status_code == 200
    assert _unwrap(journal, token).status_code == 400


def test_an_expired_token_no_longer_unwraps(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
) -> None:
    """A token past its TTL does not unwrap. A one-second TTL rather than a slept
    fifteen minutes -- and `1s` is a legal value the config layer accepts, which is
    worth knowing: nothing stops an estate configuring a handover nobody can catch.
    """
    config = write_config(_wrapped_config(live_oracle, journal, private_mount, ttl="1s"))
    token = _token_in(run(runner, config, "--account", ACCOUNT).output)

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if _unwrap(journal, token).status_code != 200:
            return
        time.sleep(1)
    pytest.fail("the token was still unwrappable 30s after a 1s ttl")


def test_the_token_goes_to_stderr_and_never_into_the_json_document(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
) -> None:
    """The stream split, and the rule the document half of it protects.

    `--output json` is *not* refused here, unlike on the seen path: the document
    is what makes a scheduled reset auditable, and taking it away would leave an
    estate choosing between an audit trail and the default delivery method. What
    it must never contain is the token -- a document is captured, shipped to log
    aggregation and kept, and a token in it outlives the TTL that is this method's
    whole guarantee. So stdout carries the document and stderr carries the
    hand-over, which is the split this verb already makes for the plan and the
    prompt.
    """
    config = write_config(_wrapped_config(live_oracle, journal, private_mount))

    result = run(runner, config, "--account", ACCOUNT, "--output", "json")

    # `result.stdout` rather than `result.output`, which since click 8.2 is the
    # two streams combined -- and using it here would have passed whichever
    # stream the token came out of, which is the entire claim.
    assert result.exit_code == ExitCode.SUCCESS, result.output
    document = json.loads(result.stdout)
    assert document["results"][0]["delivered"] == "vault_wrapped"
    assert "hvs." not in result.stdout, "the token reached the document"
    assert "unwraps once" in result.stderr
    _token_in(result.stderr)


def test_the_password_is_in_no_run_document(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
) -> None:
    """No run document holds the password. Asserted against the value rather than
    against the schema: the plaintext is fetched back out of the cubbyhole and
    looked for in everything the run emitted on either stream."""
    config = write_config(_wrapped_config(live_oracle, journal, private_mount))

    result = run(runner, config, "--account", ACCOUNT, "--output", "json")

    password = _unwrap(journal, _token_in(result.stderr)).json()["data"]["password"]
    assert password not in result.stdout, "the password reached the run document"
    assert password not in result.stderr, "the password reached the hand-over"


def test_a_failed_delivery_leaves_the_old_password_working(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """UC-2 §6.4's ordering, which is the reason the unseen path delivers first.

    Compare the two failures the section compares. Delivery fails and the DDL
    never runs: the store holds nothing usable and **the person's old password
    still works**, so nobody is worse off than before the run. The other order
    fails the other way -- an account with a password nobody holds, and a person
    who could not log in now cannot be helped by themselves either. Asserted on
    `ACCOUNT_STATUS` and on the exit code, because the observable claim is that
    nothing was issued.
    """
    config = write_config(_wrapped_config(live_oracle, journal, private_mount))
    before = account()

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise StoreError("the wrap was refused by the test")

    monkeypatch.setattr("sopuli.delivery.vault_wrapped.VaultWrapped.deliver", refuse)

    result = run(runner, config, "--account", ACCOUNT)

    assert result.exit_code != ExitCode.SUCCESS
    assert account() == before, "the DDL ran although the hand-over had failed"
    assert "hvs." not in result.output


def test_a_store_that_cannot_wrap_is_refused_before_the_ddl(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invariant 4 for a delivery capability.

    A store that cannot wrap is knowable from the file before any database is
    reached, so it has to be exit 5 naming the store -- not a per-target error row
    after a password has been drawn, which resolving the backend inside the loop
    would produce. Asserted on `ACCOUNT_STATUS`, because the observable claim
    is that nothing was issued.

    The refusal itself is `tests/test_delivery_vault_wrapped.py`'s; what this pins
    is *when* it arrives.
    """
    config = write_config(_wrapped_config(live_oracle, journal, private_mount))
    before = account()

    def refuse(store: Any, *, vault: str, ttl: str) -> Any:
        raise NotWrappableError(vault)

    # Patched at the definition site rather than on `sopuli.cli`, which does not
    # hold the name: the module is imported inside `_delivery_backend` so that an
    # offline command never loads `httpx` (ADR-006 rule 1).
    monkeypatch.setattr("sopuli.delivery.vault_wrapped.for_store", refuse)

    result = run(runner, config, "--account", ACCOUNT)

    assert result.exception.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
    assert "needs a HashiCorp store" in str(result.exception)
    assert account() == before, "the DDL ran although delivery could never have worked"


def test_the_plan_reaches_the_operator_before_the_unseen_path_mutates(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
) -> None:
    """Invariant 8 on a path with no prompt.

    The seen path echoes the plan early so the prompt cannot come first;
    here there is no prompt, and the argument is what happens when the run raises
    part way through. The verb returns its whole output as one string, so a failure
    before the return leaves the operator nothing at all -- no plan, no record of
    what was about to be touched. Echoing to stderr makes the plan survive that.

    Asserted on the stream rather than on ordering within one buffer, because that
    is the claim: stdout carries the result and stderr carries the plan, and a
    reader who lost stdout still knows what the run was for.
    """
    config = write_config(_wrapped_config(live_oracle, journal, private_mount))

    result = run(runner, config, "--account", ACCOUNT)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "Plan:" in result.stderr
    assert ACCOUNT in result.stderr


def test_a_preview_does_not_echo_the_plan_twice(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
) -> None:
    """`--dry-run` mutates nothing, so there is no failure for an early copy to
    survive and no prompt for it to precede -- and a preview that printed its plan
    on both streams would just be noisier."""
    config = write_config(_wrapped_config(live_oracle, journal, private_mount))

    result = run(runner, config, "--account", ACCOUNT, "--dry-run")

    assert "Plan:" in result.stdout
    assert "Plan:" not in result.stderr


def test_a_delivery_with_no_store_anywhere_in_the_chain_is_refused(
    runner: CliRunner, write_config: WriteConfig
) -> None:
    """A delivery with nowhere to deliver is refused before anything connects.

    §3's chain runs out when the method names no `vault:`, the target names none
    and `defaults.vault` is unset. That is knowable from the file, so it is refused
    before anything connects -- asserted against an address nothing answers, so a
    passing test cannot be one that reached a database first.

    Exit 8 rather than 9, following `deliverable`'s precedent for "no `delivery:`
    is configured": the file is not malformed, it is a delivery with nowhere to
    deliver.
    """
    config = OFFLINE.replace(
        "method: manual\n  manual:\n    force_expire: true",
        "method: vault_wrapped\n  vault_wrapped:\n    ttl: 15m",
    )

    result = run(runner, write_config(config), "--account", ACCOUNT)

    assert result.exception.exit_code == ExitCode.ABORTED
    assert "no store to deliver into" in str(result.exception)
    assert "defaults.vault" in str(result.exception.hint)


def test_each_target_s_handover_names_its_target(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
) -> None:
    """Each hand-over block names its target, as the operator sees it.

    A reset with no `--target` reaches every declared target and draws a *separate*
    password for each, so the hand-over blocks have to be told apart. Blocks that
    all read "hand this to alice" would carry different tokens, and sending the
    wrong one hands somebody a password that does not work on the host they were
    told about.

    One target here, because the tier-1 stack has one -- so what this pins is that
    the target reaches the block at all. `tests/test_delivery_view.py` holds the
    rendering, where two of them can be compared without a database.
    """
    config = write_config(_wrapped_config(live_oracle, journal, private_mount))

    result = run(runner, config, "--account", ACCOUNT)

    assert f"hand this to {ACCOUNT} for tier1-oracle" in result.output


def test_the_document_names_the_handover_without_being_able_to_perform_it(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
) -> None:
    """The pair of assertions is the whole design.

    The accessor is there, so a scheduled reset is auditable: somebody can tie this
    run to an entry in the vault's own log. The token is not, and no property could
    hold it -- a document is captured, shipped to log aggregation and kept, and a
    token in one outlives the TTL that is this method's guarantee.
    """
    config = write_config(_wrapped_config(live_oracle, journal, private_mount))

    result = run(runner, config, "--account", ACCOUNT, "--output", "json")

    handover = json.loads(result.stdout)["results"][0]["handover"]
    assert handover["accessor"], "the run is not auditable without it"
    assert handover["expires_at"]
    assert handover["accessor"] not in result.stderr, "the accessor is not the token"
    assert "hvs." not in result.stdout


def test_the_record_carries_the_accessor_as_its_destination(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
) -> None:
    """UC-2 §3.1's `to` holds the accessor.

    Read back out of the real journal, and checked against the *document's* own
    accessor so the two agree -- a record naming a different hand-over than the run
    reported would be worse than one naming none.
    """
    config = write_config(_wrapped_config(live_oracle, journal, private_mount))

    result = run(runner, config, "--account", ACCOUNT, "--output", "json")

    reported = json.loads(result.stdout)["results"][0]["handover"]["accessor"]
    path = f"sopuli/personal-resets/tier1-oracle/{ACCOUNT}"
    stored = journal.client.get(f"/v1/{private_mount}/data/{path}")
    assert stored.status_code == 200, stored.text
    record = stored.json()["data"]["data"]
    assert record["delivery"] == {"method": "vault_wrapped", "to": reported}


def test_the_record_never_carries_the_token(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
) -> None:
    """The `assert_no_secret` guard, asserted end to end rather than only
    against a hand-built document: the journal is readable by anyone who
    may know *that* a reset happened, which is precisely who must not be able to
    perform one."""
    config = write_config(_wrapped_config(live_oracle, journal, private_mount))

    result = run(runner, config, "--account", ACCOUNT)

    token = _token_in(result.output)
    path = f"sopuli/personal-resets/tier1-oracle/{ACCOUNT}"
    stored = journal.client.get(f"/v1/{private_mount}/data/{path}")
    assert stored.status_code == 200, stored.text
    assert token not in json.dumps(stored.json()["data"]["data"])


def test_a_journal_store_that_is_down_refuses_even_when_the_delivery_store_is_up(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    journal: Any,
    private_mount: str,
    free_tcp_port: int,
) -> None:
    """UC-2 3.3, decided in #516: the journal's store holds the lock.

    The journal is a `vaults:` entry of its own, at an address nothing answers,
    and the delivery names the store that is up. The delivery could work, and the
    run still refuses before any DDL: a reset without its lock would print like
    a locked one. An estate that must reset during a journal outage removes
    `reset_records:`, and `SOPULI-W024` says at plan time that no lock is taken.

    The old password still logging in is what shows that no DDL ran. An unseen
    reset does not expire the account, so `OPEN` afterwards would prove nothing.
    The address is a free port on the loopback interface, which refuses at once.
    """
    written = (
        _wrapped_config(live_oracle, journal, private_mount)
        .replace(
            "  vault_wrapped:\n    ttl: 15m\n",
            "  vault_wrapped:\n    ttl: 15m\n    vault: vault-dev\n",
        )
        .replace(
            "\nreset_records:\n  vault: vault-dev\n",
            f"""  vault-journal:
    type: hashicorp
    addr: http://127.0.0.1:{free_tcp_port}
    mount: kv
    kv_version: 2
    auth:
      method: token

reset_records:
  vault: vault-journal
""",
        )
    )
    assert "    vault: vault-dev\n" in written, "the delivery names no store of its own"
    assert "  vault: vault-journal\n" in written, "the journal is still in the delivery's store"
    before = account()

    result = run(runner, write_config(written), "--account", ACCOUNT)

    assert isinstance(result.exception, StoreError), result.exception
    assert "could not reach the store" in str(result.exception)
    assert account() == before == "OPEN"
    assert _logs_in(live_oracle, OLD), "the reset ran without the lock it was told to take"
    assert "hvs." not in result.output, "a password was handed over without the lock"


def _logs_in(live_oracle: Environment, password: str) -> bool:
    """Whether the account accepts ``password``, by a real logon."""
    oracledb = pytest.importorskip("oracledb")
    try:
        oracledb.connect(user=ACCOUNT, password=password, dsn=live_oracle.dsn).close()
    except oracledb.DatabaseError:
        return False
    return True


# -------------------------------------------------------- the notify channel ---
#
# These tests drive the verb. The renderer and the sender have their own unit
# tests, and neither unit can reach the ordering and refusal rules tested here.

NOTIFY_BLOCK = """
  notify:
    method: webhook
    webhook:
      url: { env: SOPULI_NOTIFY_WEBHOOK }
      template: "{account} on {target} has a new password waiting"
"""


class Recorder:
    """A sender that answers, and remembers whether it was asked."""

    def __init__(self) -> None:
        self.messages: list[str] = []

    def send(self, url: Any, message: str) -> None:
        self.messages.append(message)


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    """Replaces the *resolved channel's* sender, so the registry and the URL are
    still exercised -- an uninstalled client fails in the registry."""
    stub = Recorder()
    monkeypatch.setenv("SOPULI_NOTIFY_WEBHOOK", "https://chat.example.com/hooks/T0/B0/EXAMPLE")
    monkeypatch.setattr("sopuli.notify.registry.resolve", lambda method: stub)
    return stub


def _seen_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guard 3 satisfied the way a terminal satisfies it.

    `CliRunner` has no terminal, so the seen path is refused at plan time and the
    ordering this file cares about is unreachable. Patched at the one seam
    `refuse_seen_path` reads rather than at `isatty`, because the guard takes
    `stdout_is_terminal` as an argument for exactly this reason.
    """
    monkeypatch.setattr("sopuli.cli.is_a_terminal", lambda stream: True)


def test_declining_the_seen_prompt_tells_nobody_a_password_is_waiting(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    recorder: Recorder,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """**Declining the prompt sends no notification.**

    On the seen path `_hand_over` *is* the delivery: it prompts, and declining
    raises `click.Abort`, leaving the password set on an account nobody has read.
    A notification sent before that prompt would say "a new password is waiting"
    after the only channel that could have carried it had been refused -- and on
    `manual` there is no store to fetch it from, so the message would be not
    merely early but false.

    The password still changed. That is not what this asserts and is not a defect:
    §6.4 puts the DDL first and the abort path journals the mutation.
    """
    _seen_terminal(monkeypatch)
    config = MANUAL.format(
        dsn=live_oracle.dsn,
        user=os.environ.get("SOPULI_TEST_ORACLE_USER", "system"),
        account=ACCOUNT,
    ).replace("    force_expire: true", "    force_expire: true" + NOTIFY_BLOCK)

    result = run(runner, write_config(config), "--account", ACCOUNT, input="n\n")

    # `click.Abort` reaches `CliRunner` as a `SystemExit` rather than one of this
    # project's errors -- the prompt is click's, and so is declining it.
    assert result.exit_code != ExitCode.SUCCESS
    assert recorder.messages == [], "notified a hand-over that was refused"


def test_accepting_the_seen_prompt_does_notify(
    runner: CliRunner,
    write_config: WriteConfig,
    live_oracle: Environment,
    account: Callable[..., Any],
    recorder: Recorder,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other half, without which "never notify" would pass the test above.

    Notifying after `_hand_over` is only correct if the seen path still
    notifies when the operator looks.
    """
    _seen_terminal(monkeypatch)
    config = MANUAL.format(
        dsn=live_oracle.dsn,
        user=os.environ.get("SOPULI_TEST_ORACLE_USER", "system"),
        account=ACCOUNT,
    ).replace("    force_expire: true", "    force_expire: true" + NOTIFY_BLOCK)

    result = run(runner, write_config(config), "--account", ACCOUNT, input="y\n")

    assert result.exit_code == ExitCode.SUCCESS
    assert recorder.messages == [f"{ACCOUNT} on tier1-oracle has a new password waiting"]


def test_a_notify_client_that_is_not_installed_refuses_before_the_password_changes(
    runner: CliRunner,
    write_config: WriteConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """**Invariant 4 for an uninstalled notify client.**

    `_notify` catches every exception so a dead webhook cannot fail a reset that
    already worked. Inside it, `SOPULI-20003` would be swallowed too, turning
    ADR-006's E5 contract ("configured-but-uninstalled fails use with exit 9") into
    a warning issued *after* the password had changed. It is knowable before the
    run connects to anything, so it is answered there.

    Tier 0, and that is the assertion: nothing in this test can reach a database,
    because the refusal happens before anything opens one.
    """
    _seen_terminal(monkeypatch)
    monkeypatch.setenv("SOPULI_NOTIFY_WEBHOOK", "https://chat.example.com/hooks/T0/B0/EXAMPLE")

    def absent(name: str) -> Any:
        raise ModuleNotFoundError(f"No module named {'httpx'!r}", name="httpx")

    monkeypatch.setattr("sopuli.notify.registry.importlib.import_module", absent)
    config = OFFLINE.replace("    force_expire: true", "    force_expire: true" + NOTIFY_BLOCK)

    result = run(runner, write_config(config), "--account", ACCOUNT)

    assert result.exception.exit_code == ExitCode.CONFIG_INVALID
    assert "sopuli-dba[notify]" in str(result.exception.hint)


def test_a_missing_webhook_url_refuses_before_the_password_changes(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unresolvable webhook URL is refused like an uninstalled client.

    A missing variable leaves nobody told, as a refused request does, so it could
    be reported as `SOPULI-W026`. The timing differs: a refused request is news,
    and an unset environment variable is a configuration error that is
    answerable before a password is drawn.
    """
    _seen_terminal(monkeypatch)
    monkeypatch.delenv("SOPULI_NOTIFY_WEBHOOK", raising=False)
    config = OFFLINE.replace("    force_expire: true", "    force_expire: true" + NOTIFY_BLOCK)

    result = run(runner, write_config(config), "--account", ACCOUNT)

    assert result.exception.exit_code != ExitCode.SUCCESS
    assert "SOPULI_NOTIFY_WEBHOOK" in str(result.exception) + str(
        getattr(result.exception, "hint", "")
    )


def test_a_profile_that_cannot_answer_refuses_a_seen_reset_before_connecting(
    runner: CliRunner, write_config: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A profile's `confirm: false` refuses the seen path at plan time
    (decision #610).

    At a terminal, so the refusal is the profile's and not guard 3's. The target
    is unroutable, so reaching the driver would fail differently: exit 8 with the
    profile's message shows the run stopped before any password was drawn.
    """
    monkeypatch.setattr("sopuli.cli.is_a_terminal", lambda stream: True)
    config = write_config(OFFLINE + "\nprofiles:\n  ci:\n    confirm: false\n")

    result = run(runner, config, "--account", ACCOUNT, "--profile", "ci")

    assert isinstance(result.exception, RefusedError)
    assert result.exception.exit_code == ExitCode.ABORTED
    assert "the active profile says nobody is here to answer" in str(result.exception)

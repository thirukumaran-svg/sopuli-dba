"""`sopuli account reset-password` from the command line (#441).

Tier 0 for the refusals, which need no database: each of #439's guards has an
exit code, and a guard whose code changed would be a script's behaviour changing
silently.

Tier 1 for the two things only a database can answer, and the first of them is
here because **running it found the bug**: a `--dry-run` reset the password. The
preview parameter was threaded through the verb and never read, so a run that
promised to change nothing drew a password, issued the DDL and expired the
account before aborting at the prompt. Invariant 8 is the rule it broke, and no
test of the code as written could have caught it -- the code did exactly what it
said, which was nothing about previews.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from conftest import WriteConfig
from oracle_harness import Environment
from sopuli.cli import cli
from sopuli.config.targets import ADMIN_PASSWORD_ENV
from sopuli.exit_codes import ExitCode

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


def test_an_unimplemented_method_is_refused_before_anything_connects(
    runner: CliRunner, write_config: WriteConfig
) -> None:
    """Exit 5, and the target is unreachable on purpose: the refusal has to come
    from the delivery gate rather than from a connection timing out."""
    config = OFFLINE.replace(
        "method: manual\n  manual:\n    force_expire: true",
        "method: vault_wrapped\n  vault_wrapped:\n    ttl: 15m",
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
    """Invariant 8, against a real account -- the regression test for the bug
    running it found.

    The account status afterwards is the whole assertion. A preview that had
    issued the DDL would leave it `EXPIRED`, which is exactly what the first
    draft did, and the output would still have read like a preview.

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
    """The whole feature, end to end, and the three claims #441 makes about it.

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

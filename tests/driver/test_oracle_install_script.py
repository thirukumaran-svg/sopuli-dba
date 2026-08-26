"""`sql/oracle/00_install.sql` and `99_uninstall.sql`, executed (#229). Tier 1.

`tests/test_install_sql.py` reads these scripts; this runs them. The two are
complementary and neither replaces the other: parsing catches grant drift in
under a second with no container, and execution catches everything parsing
cannot see — the mode branches, the `CONTAINER=ALL` clause construction, the
guards, and whether the file runs end to end at all.

The distinction is not theoretical. Running these scripts by hand once turned up
four bugs (#231), and **two of them failed silently**: a `PROMPT` line ending in
`-` ate the statement after it, and `keep_audit=N` left an audit policy behind
while still exiting 0. Nothing that reads the file could have found either.

**The scripts are SQL*Plus, not SQL**, so `python-oracledb` cannot run them:
`DEFINE`/`&substitution`, `COLUMN … NEW_VALUE`, `PROMPT`, `SET SERVEROUTPUT` and
`/` terminators are client commands, and a fixture that split the file on `;`
could be made to "work" only by deleting the parts that make it correct. What
makes this module possible is that **the tier-1 container ships SQL*Plus** —
gvenzl's own init path runs `.sql` files as `sqlplus -s / as sysdba`, so the
client is already there. The scripts run byte for byte, as an operator runs them.

Two properties are load-bearing and worth naming, because without either this
module would be theatre:

* **`WHENEVER SQLERROR EXIT SQL.SQLCODE` makes the exit code meaningful.** A
  failed install exits non-zero, so `returncode` is an assertion rather than a
  formality. `01_audit_policy.sql` did not have this and could fail while exiting
  0 — found by review on the parametrisation PR, and asserted here.
* **The scripts take parameters** rather than needing their `DEFINE` lines
  rewritten. A test that edited the file before running it would no longer be
  running what an operator runs, which is the entire justification for the
  container hop.

Accounts are named from `CLAUDE.md`'s fictional vocabulary, and deliberately
neither `SOPULI_SVC` (the script's own default, which would make a parameter that
was silently ignored look identical to one that was honoured) nor `acme_svc_user`
(`test_oracle_service_account.py`, so the two modules cannot collide).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from sopuli.driver.oracle.privileges import (
    REQUIRED_PRIVILEGES,
    REQUIRED_READS,
    ROOT_ONLY_READS,
)

#: Which container holds the database. The default is `test/compose.yaml`'s
#: `oracle-free` under the `sopuli-test` project name, so a contributor who
#: brought the stack up needs no environment variables.
#:
#: A container rather than a DSN, and that is the whole difference from every
#: other tier-1 module: SQL*Plus is a *client*, and the one this suite can rely
#: on is inside the container rather than on the runner. CI installs Instant
#: Client Basic **Lite**, which has no `sqlplus` in it at all.
CONTAINER = os.environ.get("SOPULI_TEST_ORACLE_CONTAINER", "sopuli-test-oracle-free-1")

#: Same rule as the rest of tier 1 (`04-testing.md` §3): a missing environment is
#: a skip with a reason on a laptop and a **failure** in a lane that exists to run
#: it. A green run that skipped everything would be worse than no run, because it
#: would be quoted as evidence.
TIER1 = "SOPULI_TEST_TIER1"

SYS_PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")

#: Connect strings for the two containers. `/ as sysdba` is OS authentication
#: from inside the container and lands in `CDB$ROOT`, which is `COMMON` mode's
#: required context; the PDB needs a service name, because the container is
#: decided by the service and there is no `ALTER SESSION SET CONTAINER` anywhere.
ROOT = "/ as sysdba"
PDB = f"sys/{SYS_PASSWORD}@localhost:1521/freepdb1 as sysdba"

#: Where the scripts are copied to inside the container. Copied rather than
#: bind-mounted so this module works against any running container, however it
#: was started, and needs no change to `compose.yaml`.
REMOTE_DIR = "/tmp/sopuli-sql-under-test"

SCRIPTS = Path(__file__).resolve().parents[2] / "sql" / "oracle"

#: Fictional, per CLAUDE.md's provenance rule. See the module docstring for why
#: it is not the script's own default.
SVC = "acme_install_user"
COMMON_SVC = f"C##{SVC.upper()}"
LOCAL_SVC = SVC.upper()

#: A second install, for the one bug that only shows up when the audit policy
#: is still enabled BY an account the uninstall is not dropping. See
#: :func:`test_uninstall_with_keep_audit_n_drops_a_policy_another_install_enabled`.
SVC_OTHER = "acme_other_user"
COMMON_SVC_OTHER = f"C##{SVC_OTHER.upper()}"


def _missing(reason: str) -> None:
    if os.environ.get(TIER1) == "required":
        pytest.fail(f"tier 1 required, but: {reason}", pytrace=False)
    pytest.skip(reason)


def _docker(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check, timeout=300
    )


@pytest.fixture(scope="session")
def container() -> str:
    """The container name, or a skip saying which part was missing.

    Three things can be absent and they are three different findings, so they get
    three different messages -- reporting "no test environment" for a missing
    `docker` binary would send somebody to `docker compose` for a `PATH` problem.
    """
    if shutil.which("docker") is None:
        _missing("docker is not on PATH")
    probe = _docker("inspect", "-f", "{{.State.Running}}", CONTAINER)
    if probe.returncode != 0:
        _missing(
            f"container {CONTAINER!r} does not exist"
            " -- `docker compose --profile tier1 up -d` from test/"
        )
    if probe.stdout.strip() != "true":
        _missing(f"container {CONTAINER!r} exists but is not running")
    return CONTAINER


@pytest.fixture(scope="session")
def scripts(container: str) -> str:
    """The scripts, copied into the container, byte for byte.

    Copied once per session: the files do not change while the suite runs, and
    `docker cp` per test would be the slowest thing in the module.
    """
    _docker("exec", container, "rm", "-rf", REMOTE_DIR)
    _docker("exec", container, "mkdir", "-p", REMOTE_DIR)
    for name in ("00_install.sql", "01_audit_policy.sql", "99_uninstall.sql"):
        result = _docker("cp", str(SCRIPTS / name), f"{container}:{REMOTE_DIR}/{name}")
        if result.returncode != 0:
            pytest.fail(f"could not copy {name} into {container}: {result.stderr.strip()}")
    return REMOTE_DIR


def _exec(
    container: str, connect: str, *args: str, script: str | None = None
) -> subprocess.CompletedProcess[str]:
    """`docker exec` straight to `sqlplus`, with no shell anywhere in the path.

    **An argv list rather than `bash -lc`**, which matters for a reason that is
    not hypothetical here: the connect string carries a password, and
    `SOPULI_TEST_ORACLE_PASSWORD` is a contributor's to set. Through a shell, a
    password containing `$`, a backtick or `$(` is expanded rather than sent, and
    the failure would arrive as a puzzling authentication error rather than as
    anything pointing at quoting. The list form also removes the injection
    surface, which is small here but free to close.

    The image sets `ORACLE_HOME` and a `PATH` reaching `sqlplus` in its own
    environment, so a login shell was never buying anything. What it *was* buying
    is `< /dev/null`, and `stdin=DEVNULL` says the same thing without a shell:
    should a substitution variable ever go undefined, SQL*Plus prompts, and a
    prompt whose stdin is a terminal would **hang** the suite rather than fail
    it. Stdin at EOF is the difference between a red build and a stuck one.
    """
    command = ["docker", "exec", "-i", container, "sqlplus", "-s", connect, *args]
    if script is None:
        return subprocess.run(
            command, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=300
        )
    return subprocess.run(command, input=script, capture_output=True, text=True, timeout=300)


def sqlplus(
    container: str, connect: str, script: str, *args: str
) -> subprocess.CompletedProcess[str]:
    """Run one script file through the container's SQL*Plus, byte for byte."""
    return _exec(container, connect, f"@{script}", *args)


def query(container: str, connect: str, sql: str) -> list[str]:
    """One query, stripped to its rows -- and loud when it does not run.

    Bare values rather than a driver result set: this module's whole point is
    that it talks to the database the way the operator's client does, and
    reaching for `oracledb` here would mean asserting through a different path
    than the one under test.

    **`WHENEVER SQLERROR EXIT` and a `returncode` check, both.** Without them
    SQL*Plus prints an `ORA-` line and still exits 0, so a query that failed
    outright returns its error text as though it were rows -- and a caller
    comparing against an empty set gets a **passing** test out of a broken one.
    Filtering the error lines away would be worse again: it turns a failure into
    exactly the empty result several of these assertions expect.
    """
    script = (
        "WHENEVER SQLERROR EXIT SQL.SQLCODE\n"
        "SET HEADING OFF PAGESIZE 0 FEEDBACK OFF LINESIZE 200 VERIFY OFF\n"
        f"{sql}\nEXIT\n"
    )
    result = _exec(container, connect, script=script)
    if result.returncode != 0:
        raise AssertionError(f"query failed (rc={result.returncode}):\n{result.stdout.strip()}")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def grants_of(container: str, connect: str, account: str) -> set[str]:
    """Every grant the account holds, in `privileges.py`'s own spelling.

    The comparison is against the tool's constants rather than a list written
    here, for the reason `tests/test_install_sql.py` gives at length: a restated
    list agrees with the tool only until somebody edits one of the two, and the
    account is then right about the wrong thing.

    One normalisation, and it is a place the two legitimately differ rather than
    disagree -- a grant needs the owner (`SELECT ON SYS.DBA_USERS`), a read
    through the public synonym does not.
    """
    rows = query(
        container,
        connect,
        f"""SELECT privilege FROM dba_sys_privs WHERE grantee = UPPER('{account}')
            UNION ALL
            SELECT 'SELECT ON ' || table_name FROM dba_tab_privs
             WHERE grantee = UPPER('{account}') AND privilege = 'SELECT';""",
    )
    return set(rows)


def drop(container: str, connect: str, account: str) -> None:
    """Best-effort teardown: the account is usually not there, and that is fine.

    The one place `WHENEVER SQLERROR CONTINUE` is right rather than a hazard, and
    the return code is deliberately ignored: `ORA-01918` for an account that was
    never created is the expected outcome half the time this runs.
    """
    _exec(
        container,
        connect,
        script=f"WHENEVER SQLERROR CONTINUE\nDROP USER {account} CASCADE;\nEXIT\n",
    )


@pytest.fixture
def clean(container: str, scripts: str) -> Iterator[None]:
    """No test account before or after, in either container.

    Dropped **after** as well as before. A fixture whose recovery is "the next one
    will tidy up" leaves the database dirty at the end of the session, which on a
    developer's own instance is litter and on a shared one is worse -- the same
    finding review raised against `test_oracle_service_account.py` (#226).
    """
    accounts = ((ROOT, COMMON_SVC), (ROOT, COMMON_SVC_OTHER), (PDB, LOCAL_SVC))
    for connect, account in accounts:
        drop(container, connect, account)
    yield
    for connect, account in accounts:
        drop(container, connect, account)


# ---------------------------------------------------------------- the modes ---


def test_common_install_grants_exactly_what_the_tool_requires(
    container: str, scripts: str, clean: None
) -> None:
    """`COMMON` in `CDB$ROOT`: the documented install, asserted both ways.

    Both directions, because they catch opposite failures. Short, and an operator
    who followed the install finds out from a verb that fails several commands
    later; wide, and `--check-privileges` reports over-granting about an account
    that did exactly what the documentation said.
    """
    result = sqlplus(container, ROOT, f"{scripts}/00_install.sql", "COMMON", SVC)
    assert result.returncode == 0, result.stdout[-2000:]

    held = grants_of(container, ROOT, COMMON_SVC)
    expected = set(REQUIRED_PRIVILEGES) | set(REQUIRED_READS) | set(ROOT_ONLY_READS)
    assert held == expected, f"missing={expected - held} over={held - expected}"


def test_pdb_install_is_local_and_omits_the_root_only_read(
    container: str, scripts: str, clean: None
) -> None:
    """`PDB` mode: no `C##` prefix, and no `V_$PDBS`.

    `V_$PDBS` is §2's root-only row, and its absence here is the assertion that
    the mode branch is real rather than decorative -- a script that granted the
    same set in every mode would pass the COMMON test and fail this one.
    """
    result = sqlplus(container, PDB, f"{scripts}/00_install.sql", "PDB", SVC)
    assert result.returncode == 0, result.stdout[-2000:]

    held = grants_of(container, PDB, LOCAL_SVC)
    assert held == set(REQUIRED_PRIVILEGES) | set(REQUIRED_READS)
    assert not set(ROOT_ONLY_READS) & held

    common = query(container, PDB, f"SELECT common FROM dba_users WHERE username = '{LOCAL_SVC}';")
    assert common == ["NO"], f"expected a local account, got COMMON={common}"


def test_noncdb_mode_installs_the_same_local_account(
    container: str, scripts: str, clean: None
) -> None:
    """`NONCDB` differs from `PDB` only in which guard it passes.

    Worth its own test rather than an assumption: the two modes reach the same
    grants by different branches, and the sanity check treats them differently.
    """
    result = sqlplus(container, PDB, f"{scripts}/00_install.sql", "NONCDB", SVC)
    assert result.returncode == 0, result.stdout[-2000:]
    assert grants_of(container, PDB, LOCAL_SVC) == set(REQUIRED_PRIVILEGES) | set(REQUIRED_READS)


# --------------------------------------------------------------- the guards ---


def test_common_mode_refuses_to_run_outside_the_root(
    container: str, scripts: str, clean: None
) -> None:
    """`PDB` mode in `CDB$ROOT` is refused, and the refusal is non-zero.

    The exit code is the assertion. A guard that printed a complaint and exited 0
    would look identical to a successful install from anything automating this.
    """
    result = sqlplus(container, ROOT, f"{scripts}/00_install.sql", "PDB", SVC)
    assert result.returncode != 0
    assert "ORA-20011" in result.stdout
    assert grants_of(container, ROOT, COMMON_SVC) == set()


def test_an_unknown_mode_is_refused_before_anything_is_created(
    container: str, scripts: str, clean: None
) -> None:
    """A typo in `mode` must not fall through to a partial install."""
    result = sqlplus(container, ROOT, f"{scripts}/00_install.sql", "NONSENSE", SVC)
    assert result.returncode != 0
    assert "ORA-20012" in result.stdout
    assert grants_of(container, ROOT, COMMON_SVC) == set()


# ------------------------------------------------------------- the optionals ---


def test_the_optional_grants_are_off_unless_asked_for(
    container: str, scripts: str, clean: None
) -> None:
    """`SYS.USER$` and `SET CONTAINER` are opt-in, and both directions matter.

    §2 calls them optional; #86 makes `SYS.USER$`'s absence the ordinary
    configuration rather than a fault. A default that quietly granted either
    would hand every install a password-verifier read nobody asked for.
    """
    assert sqlplus(container, ROOT, f"{scripts}/00_install.sql", "COMMON", SVC).returncode == 0
    default = grants_of(container, ROOT, COMMON_SVC)
    assert "SELECT ON USER$" not in default
    assert "SET CONTAINER" not in default

    result = sqlplus(container, ROOT, f"{scripts}/00_install.sql", "COMMON", SVC, "USERS", "Y", "Y")
    assert result.returncode == 0, result.stdout[-2000:]
    asked = grants_of(container, ROOT, COMMON_SVC)
    assert "SELECT ON USER$" in asked
    assert "SET CONTAINER" in asked


def test_installing_twice_changes_nothing(container: str, scripts: str, clean: None) -> None:
    """Invariant 9, at the level of the script an operator re-runs.

    The second run must leave the same grants and must not fail on the account it
    created itself -- `CREATE USER` on an existing account is `ORA-01920`, and the
    existence check is what stops it.
    """
    first = sqlplus(container, ROOT, f"{scripts}/00_install.sql", "COMMON", SVC)
    assert first.returncode == 0, first.stdout[-2000:]
    before = grants_of(container, ROOT, COMMON_SVC)

    second = sqlplus(container, ROOT, f"{scripts}/00_install.sql", "COMMON", SVC)
    assert second.returncode == 0, second.stdout[-2000:]
    assert "already exists" in second.stdout
    assert grants_of(container, ROOT, COMMON_SVC) == before


# ------------------------------------------------------------- the uninstall ---


def test_uninstall_removes_the_account_and_every_grant_with_it(
    container: str, scripts: str, clean: None
) -> None:
    """Dropping the account takes the grants, which is what `99` claims."""
    assert sqlplus(container, ROOT, f"{scripts}/00_install.sql", "COMMON", SVC).returncode == 0
    assert grants_of(container, ROOT, COMMON_SVC)

    result = sqlplus(container, ROOT, f"{scripts}/99_uninstall.sql", COMMON_SVC)
    assert result.returncode == 0, result.stdout[-2000:]
    assert grants_of(container, ROOT, COMMON_SVC) == set()
    assert (
        query(container, ROOT, f"SELECT username FROM dba_users WHERE username = '{COMMON_SVC}';")
        == []
    )


def _policies(container: str) -> set[str]:
    return set(
        query(
            container,
            ROOT,
            "SELECT DISTINCT policy_name FROM audit_unified_policies"
            " WHERE policy_name IN ('SOPULI_POL','SOPULI_LOGON_POL');",
        )
    )


def test_uninstall_with_keep_audit_n_drops_every_policy(
    container: str, scripts: str, clean: None
) -> None:
    """`keep_audit=N` removes both policies. Regression for #231's third bug.

    `audit_unified_policies` returns one row **per policy per audit option** --
    six for `SOPULI_POL`. The cursor loop dropped it on the first iteration,
    raised `ORA-46357` on the second, and the exception aborted the block before
    `SOPULI_LOGON_POL` was reached.

    Asserting on `returncode` alone would still pass against that bug:
    `WHENEVER SQLERROR CONTINUE` holds the exit code at 0, so the uninstall
    reported success while leaving both policies behind. The assertion has to be
    that they are gone.
    """
    assert sqlplus(container, ROOT, f"{scripts}/00_install.sql", "COMMON", SVC).returncode == 0
    assert sqlplus(container, ROOT, f"{scripts}/01_audit_policy.sql", COMMON_SVC).returncode == 0
    assert _policies(container) == {"SOPULI_POL", "SOPULI_LOGON_POL"}

    result = sqlplus(container, ROOT, f"{scripts}/99_uninstall.sql", COMMON_SVC, "N")
    assert result.returncode == 0, result.stdout[-2000:]
    assert _policies(container) == set()


def test_uninstall_with_keep_audit_n_drops_a_policy_another_install_enabled(
    container: str, scripts: str, clean: None
) -> None:
    """Two installs, then uninstall one. This is the case that finds the bug.

    `01_audit_policy.sql` enables `sopuli_logon_pol` **`BY &svc_user`**, and
    `NOAUDIT POLICY p` unqualified does *not* lift a `BY <user>` enablement -- it
    reports success, leaves the policy enabled, and the `DROP` then fails with
    `ORA-46361`, aborting the block before the other policy is dropped either.

    **The single-install case above cannot catch it**, which is worth stating
    because it looks like it should. Section 1 drops the account first, and that
    removes the `BY`-user enablement as a side effect, so the `DROP` happens to
    succeed. Verified rather than reasoned: with the fix reverted, the test above
    still passes and this one fails.

    So the reproducer needs an enablement that **survives** the uninstall -- a
    second install, which is an ordinary thing for a site to have and the exact
    shape a hand-run never produces.
    """
    for account, name in ((SVC, COMMON_SVC), (SVC_OTHER, COMMON_SVC_OTHER)):
        assert (
            sqlplus(container, ROOT, f"{scripts}/00_install.sql", "COMMON", account).returncode == 0
        )
        assert sqlplus(container, ROOT, f"{scripts}/01_audit_policy.sql", name).returncode == 0

    enabled = set(
        query(
            container,
            ROOT,
            "SELECT entity_name FROM audit_unified_enabled_policies"
            " WHERE policy_name = 'SOPULI_LOGON_POL';",
        )
    )
    assert enabled == {COMMON_SVC, COMMON_SVC_OTHER}, enabled

    # Uninstall only the first. The second account -- and its enablement -- stay.
    result = sqlplus(container, ROOT, f"{scripts}/99_uninstall.sql", COMMON_SVC, "N")
    assert result.returncode == 0, result.stdout[-2000:]
    assert "ORA-46361" not in result.stdout, "NOAUDIT did not lift the BY-user enablement"
    assert _policies(container) == set()


def test_audit_policy_script_fails_loudly_on_an_account_that_does_not_exist(
    container: str, scripts: str, clean: None
) -> None:
    """`01` must not report success for an install that did not happen.

    Regression for the review finding on the parametrisation PR: `01` set no
    `WHENEVER SQLERROR`, so it continued past `ORA-01435` and still exited 0.
    Nothing automating these scripts could have told a working install from a
    broken one, and this module would have been the first thing misled.
    """
    result = sqlplus(container, ROOT, f"{scripts}/01_audit_policy.sql", "NO_SUCH_ACCOUNT")
    assert result.returncode != 0
    assert "ORA-01435" in result.stdout

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
from typing import NoReturn

import pytest
from _pytest.outcomes import Failed

from repo_files import requires_repo
from sopuli.driver.oracle.privileges import (
    PREDICATE_READS,
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


#: Wall clock allowed for any one `docker` invocation this module makes, in
#: seconds -- :func:`_exec`'s ``docker exec ... sqlplus`` and equally
#: :func:`_docker`'s ``inspect``, ``cp`` and ``exec``.
#:
#: **Not a budget, a stall detector** (#326). One `00_install.sql` run takes under
#: a second -- the whole of
#: :func:`test_the_optional_grants_are_off_unless_asked_for` is 1.93s and runs the
#: script twice -- and the container operations are faster still, so this is
#: roughly 300x headroom over the slowest thing it governs and nothing that merely
#: *finishes slowly* can reach it. It fired once, on 2026-09-02, on a
#: `GRANT CREATE SESSION ... CONTAINER=ALL` that had printed its label and never
#: returned.
#:
#: One number for both because it is one question -- *did a docker call stop?* --
#: and a second constant would be a second thing to keep proportionate to a
#: measurement neither of them states.
#:
#: So raising it is the one change to refuse: it would turn a visible stall into a
#: slow green run. Together with ``stdin=DEVNULL`` below it is what keeps a stuck
#: SQL*Plus a red build rather than a hung one.
EXEC_TIMEOUT_S = 300

#: Wall clock for the *diagnosis* after a timeout, in seconds. Short on purpose:
#: it runs when something is already wrong, and a diagnostic that hangs turns one
#: stuck call into two. Its own expiry is an answer rather than a failure -- see
#: :func:`_blocked_sessions`.
DIAGNOSE_TIMEOUT_S = 30


def _missing(reason: str) -> None:
    if os.environ.get(TIER1) == "required":
        pytest.fail(f"tier 1 required, but: {reason}", pytrace=False)
    pytest.skip(reason)


def _docker(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check, timeout=EXEC_TIMEOUT_S
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
    requires_repo(SCRIPTS)
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

    **`-i` only where there is something to send** (#326, occurrence 3). A script
    run from a file ends without an `EXIT` -- the shipped scripts must not
    disconnect a DBA who runs them from an interactive session -- so SQL*Plus
    goes back to reading stdin when the file is done and exits only on EOF. With
    `-i` that EOF is `DEVNULL`'s, forwarded by `docker exec`, and it did not
    always arrive: in two of the three stalls every statement had run and the
    process never exited, with nothing waiting in `V$SESSION`. Without `-i` the
    process's stdin is closed inside the container, so EOF is immediate and local
    (measured: a file script returns in about 0.3s, and an undefined substitution
    variable still fails at once with `SP2-0546` rather than hanging). The piped
    path keeps `-i`, since it has input to deliver, and every piped script ends in
    its own `EXIT`, so none of them waits on EOF. All three stalls were
    file scripts.

    **A timeout asks the database what it was waiting for before it gives up**
    (#326). The call that hung had printed the label of a
    `GRANT ... CONTAINER=ALL` and never returned, and nothing survived the kill
    that could say whether Oracle was blocked or `docker exec` was -- so the
    second occurrence would have been a second identical report. It is asked here
    rather than in the test, because every one of this module's eighteen calls
    goes through this function and the next stall will not be in the same one.
    """
    try:
        if script is None:
            return subprocess.run(
                ["docker", "exec", container, "sqlplus", "-s", connect, *args],
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=EXEC_TIMEOUT_S,
            )
        return subprocess.run(
            ["docker", "exec", "-i", container, "sqlplus", "-s", connect, *args],
            input=script,
            capture_output=True,
            text=True,
            timeout=EXEC_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired as expired:
        pytest.fail(_timeout_report(container, expired), pytrace=False)


def _timeout_report(container: str, expired: subprocess.TimeoutExpired) -> str:
    """Everything the next person needs, in the order they will want it (#326).

    The tail of the captured output first, because that is what located the one
    occurrence: `00_install.sql` prints a label before each statement, so the last
    line printed names the statement that never returned.

    Then what the database was doing. The distinction that decides the fix is
    whether **Oracle was waiting or `docker exec` was**, and the two are told
    apart by whether this diagnosis answers at all.

    ``pytrace=False`` at the call site: the traceback would be
    :mod:`subprocess`'s internals, which are the same on every timeout and say
    nothing about this one.
    """
    tail = _tail(expired.output)
    return "\n".join(
        [
            f"`docker exec` into {container} did not return within {EXEC_TIMEOUT_S}s.",
            "",
            "This is a stall, not a slow run: one `00_install.sql` takes under a",
            "second (#326), so do not raise EXEC_TIMEOUT_S to make it pass.",
            "",
            f"command: {' '.join(expired.cmd)}",
            "",
            "last output before the kill (the label names the statement that hung):",
            *(f"  {line}" for line in tail),
            "",
            _blocked_sessions(container),
        ]
    )


def _tail(output: bytes | str | None, lines: int = 12) -> list[str]:
    """The end of what the killed process had written, or a note that it wrote
    nothing.

    ``TimeoutExpired.output`` is ``bytes`` when the stream was never decoded and
    ``None`` when nothing arrived, and both reach here: the point of this report
    is a process that did not finish, so its output is exactly the thing that
    cannot be assumed well-formed.
    """
    if not output:
        return ["(nothing was written before the timeout)"]
    text = output.decode("utf-8", "replace") if isinstance(output, bytes) else output
    return text.splitlines()[-lines:] or ["(nothing was written before the timeout)"]


def _blocked_sessions(container: str) -> str:
    """What the database says it is waiting on, asked on a connection of its own.

    Best effort by construction, and **its own failure is an answer** rather than
    something to swallow. Three outcomes and they point at three different fixes:

    * rows -- Oracle was waiting, and on what. The hypothesis in #326 is a
      dictionary lock behind `CONTAINER=ALL`, and ``BLOCKING_SESSION`` is what
      confirms or kills it;
    * no rows -- the session was gone by the time this ran, so the stall was
      probably not the database at all;
    * this call *also* times out -- `docker exec` or the daemon is the problem
      and Oracle is a bystander, which is the reading no amount of SQL would
      have reached.

    Not through :func:`_exec`: that is the function that just timed out, and
    routing the diagnosis through it would recurse on the next failure.
    """
    # Both sides of a block, and never this probe.
    #
    # **The blocker is usually idle**, which is the case a ``wait_class <> 'Idle'``
    # filter alone misses entirely: a session holding a lock while waiting on its
    # own client is doing nothing, and is the whole answer. So a session appearing
    # in anybody's ``BLOCKING_SESSION`` is selected whatever it is waiting on --
    # measured against a real row lock, where the holder was invisible without it.
    #
    # **``sys_context`` excludes this session.** Reading ``V$SESSION`` from inside
    # it otherwise reports the probe's own ``Allocate CGA memory from OS``, which
    # means nothing and would make "nothing waiting" unreachable. Intermittent --
    # it depends on what the probe is doing at sample time -- which is worse than
    # constant, because it would look like a finding.
    # `WHENEVER SQLERROR EXIT` for the reason :func:`query` gives at length: SQL*Plus
    # prints an `ORA-` line and still exits 0, so a probe that failed outright
    # would hand its error text back as though it were rows -- and an empty
    # `stdout` from a refused connection would read as *nothing waiting*, which is
    # the one conclusion this function must never reach by accident.
    sql = (
        "whenever sqlerror exit sql.sqlcode\n"
        "set pagesize 0 feedback off heading off lines 200\n"
        "select s.sid || ' | ' || nvl(s.username, '(internal)') || ' | ' || s.status"
        " || ' | event=' || s.event || ' | waited=' || s.seconds_in_wait || 's'"
        " || ' | blocked_by=' || nvl(to_char(s.blocking_session), '-')"
        " || ' | sql_id=' || nvl(s.sql_id, '-')\n"
        "  from v$session s\n"
        " where s.type = 'USER'\n"
        "   and s.sid <> sys_context('userenv', 'sid')\n"
        "   and (s.blocking_session is not null\n"
        "        or s.wait_class <> 'Idle'\n"
        "        or s.sid in (select b.blocking_session from v$session b\n"
        "                      where b.blocking_session is not null));\n"
        "exit\n"
    )
    try:
        probe = subprocess.run(
            ["docker", "exec", "-i", container, "sqlplus", "-s", "/ as sysdba"],
            input=sql,
            capture_output=True,
            text=True,
            timeout=DIAGNOSE_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return (
            f"v$session could not be read either -- that probe also hung, within "
            f"{DIAGNOSE_TIMEOUT_S}s. Which is itself the finding: `docker exec` or the "
            f"daemon is what stalled, and the database is a bystander (#326)."
        )
    except OSError as error:  # docker gone, container gone
        return f"v$session could not be read: {error}"

    if probe.returncode != 0:
        # Not "nothing waiting". A missing container, a refused connection or an
        # `ORA-` from the query itself all land here, and every one of them is a
        # probe that did not answer rather than a database with nothing to say.
        detail = (probe.stderr.strip() or probe.stdout.strip() or "no output").splitlines()
        return "\n".join(
            [
                f"v$session could not be read: sqlplus exited {probe.returncode}.",
                *(f"  {line}" for line in detail[-6:]),
            ]
        )

    rows = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
    if not rows:
        return (
            "v$session reports nothing waiting -- no blocked session, and none holding "
            "up another. Either the session was already gone when this ran, or the "
            "stall was never the database's (#326)."
        )
    return "\n".join(["v$session, non-idle or blocked:", *(f"  {row}" for row in rows)])


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


@pytest.fixture(scope="session")
def is_cdb(container: str) -> bool:
    """Whether this container holds a CDB, asked of the server.

    `SYS_CONTEXT('USERENV','CON_NAME')` **raises** on a non-CDB rather than
    answering NULL: `ORA-02003: invalid USERENV parameter`, measured on 11g XE
    11.2.0.2.0 (#382). So the question is answered by whether the query runs at
    all, which is the same reading `capabilities.NO_CONTAINERS` makes in the
    driver and `00_install.sql` makes in its own guard.

    Session-scoped: a container does not stop being a CDB between tests, and this
    is a `docker exec` per call.
    """
    probe = _exec(
        container,
        ROOT,
        script=(
            "WHENEVER SQLERROR EXIT SQL.SQLCODE\n"
            "SET HEADING OFF PAGESIZE 0 FEEDBACK OFF\n"
            "SELECT sys_context('userenv','con_name') FROM dual;\nEXIT\n"
        ),
    )
    return probe.returncode == 0


@pytest.fixture
def local_connect(is_cdb: bool) -> str:
    """Where a *local* service account goes: the PDB on a CDB, the database
    itself on a non-CDB.

    `PDB` and `NONCDB` modes both install a local account and differ only in
    which guard they pass, so on a non-CDB the account belongs in the one
    container there is. Hard-coding `PDB` here is what made
    `test_noncdb_mode_installs_the_same_local_account` fail on 11g with
    `ORA-12514` — a test about the non-CDB mode that could only run on a CDB.
    """
    return PDB if is_cdb else ROOT


@pytest.fixture(scope="session")
def has_unified_audit(container: str) -> bool:
    """Whether this release has unified auditing, asked of the server.

    `AUDIT_UNIFIED_POLICIES` arrived in 12.1. On 11.2 it is `ORA-00942`, and
    `01_audit_policy.sql` refuses with `ORA-20020` rather than running (#382).
    """
    probe = _exec(
        container,
        ROOT,
        script=(
            "WHENEVER SQLERROR EXIT SQL.SQLCODE\n"
            "SET HEADING OFF PAGESIZE 0 FEEDBACK OFF\n"
            "SELECT COUNT(*) FROM audit_unified_policies WHERE ROWNUM = 1;\nEXIT\n"
        ),
    )
    return probe.returncode == 0


@pytest.fixture
def unified_audit_only(has_unified_audit: bool) -> None:
    """Skip where the release has no unified auditing to police.

    Not a coverage gap: `01_audit_policy.sql` creates audit *policies*, which do
    not exist before 12.1, and what the tool should do about auditing on such a
    release is an open decision rather than a missing statement (#382). The
    refusal itself is covered by `test_the_audit_script_refuses_a_release_without_unified_auditing`.
    """
    if not has_unified_audit:
        pytest.skip("this release has no unified auditing: audit policies do not exist")


@pytest.fixture
def install_mode(is_cdb: bool) -> str:
    """`COMMON` where there is a root to install into, `NONCDB` otherwise.

    Several tests below are about something else entirely -- the optional grants,
    re-running the script, the uninstall -- and used `COMMON` only because it is
    the script's default. On a non-CDB that is `ORA-20010` from the mode guard,
    which is the guard working and the test asking the wrong question (#382).
    Both modes run in the only container there is, so only the mode and the
    account name change.
    """
    return "COMMON" if is_cdb else "NONCDB"


@pytest.fixture
def install_account(is_cdb: bool) -> str:
    """The account name `install_mode` will produce. `COMMON` prefixes `C##`."""
    return COMMON_SVC if is_cdb else LOCAL_SVC


@pytest.fixture
def cdb_only(is_cdb: bool) -> None:
    """Skip where the container has no containers.

    `COMMON` mode needs `CDB$ROOT` and `PDB` mode needs a PDB; neither exists on
    a non-CDB, and neither is a gap in coverage there — a release with no
    containers has no common users to install for. `NONCDB` mode is what these
    two become, and it has its own test.
    """
    if not is_cdb:
        pytest.skip("this container is a non-CDB: COMMON and PDB modes do not apply")


@pytest.fixture
def clean(container: str, scripts: str, is_cdb: bool) -> Iterator[None]:
    """No test account before or after, in either container.

    Dropped **after** as well as before. A fixture whose recovery is "the next one
    will tidy up" leaves the database dirty at the end of the session, which on a
    developer's own instance is litter and on a shared one is worse -- the same
    finding review raised against `test_oracle_service_account.py` (#226).
    """
    local = PDB if is_cdb else ROOT
    accounts = ((ROOT, COMMON_SVC), (ROOT, COMMON_SVC_OTHER), (local, LOCAL_SVC))
    for connect, account in accounts:
        drop(container, connect, account)
    yield
    for connect, account in accounts:
        drop(container, connect, account)


# ---------------------------------------------------------------- the modes ---


def test_common_install_grants_exactly_what_the_tool_requires(
    container: str, scripts: str, clean: None, cdb_only: None
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
    expected = (
        set(REQUIRED_PRIVILEGES) | set(REQUIRED_READS) | set(PREDICATE_READS) | set(ROOT_ONLY_READS)
    )
    assert held == expected, f"missing={expected - held} over={held - expected}"


def test_pdb_install_is_local_and_omits_the_root_only_read(
    container: str, scripts: str, clean: None, cdb_only: None
) -> None:
    """`PDB` mode: no `C##` prefix, and no `V_$PDBS`.

    `V_$PDBS` is §2's root-only row, and its absence here is the assertion that
    the mode branch is real rather than decorative -- a script that granted the
    same set in every mode would pass the COMMON test and fail this one.
    """
    result = sqlplus(container, PDB, f"{scripts}/00_install.sql", "PDB", SVC)
    assert result.returncode == 0, result.stdout[-2000:]

    held = grants_of(container, PDB, LOCAL_SVC)
    assert held == set(REQUIRED_PRIVILEGES) | set(REQUIRED_READS) | set(PREDICATE_READS)
    assert not set(ROOT_ONLY_READS) & held

    common = query(container, PDB, f"SELECT common FROM dba_users WHERE username = '{LOCAL_SVC}';")
    assert common == ["NO"], f"expected a local account, got COMMON={common}"


def test_noncdb_mode_installs_the_same_local_account(
    container: str, scripts: str, clean: None, local_connect: str
) -> None:
    """`NONCDB` differs from `PDB` only in which guard it passes.

    Worth its own test rather than an assumption: the two modes reach the same
    grants by different branches, and the sanity check treats them differently.

    **`local_connect`, not `PDB`.** This is the one mode test that has to run on
    an actual non-CDB, and it was the one that could not: the hard-coded PDB
    service is `ORA-12514` on 11g, so the test named after the mode was the only
    one in the module that had never met it (#382).
    """
    result = sqlplus(container, local_connect, f"{scripts}/00_install.sql", "NONCDB", SVC)
    assert result.returncode == 0, result.stdout[-2000:]
    assert grants_of(container, local_connect, LOCAL_SVC) == (
        set(REQUIRED_PRIVILEGES) | set(REQUIRED_READS) | set(PREDICATE_READS)
    )


# --------------------------------------------------------------- the guards ---


def test_common_mode_refuses_to_run_outside_the_root(
    container: str, scripts: str, clean: None, cdb_only: None
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
    container: str, scripts: str, clean: None, install_mode: str, install_account: str
) -> None:
    """`SYS.USER$` and `SET CONTAINER` are opt-in, and both directions matter.

    §2 calls them optional; #86 makes `SYS.USER$`'s absence the ordinary
    configuration rather than a fault. A default that quietly granted either
    would hand every install a password-verifier read nobody asked for.

    **`SET CONTAINER` is asserted only in `COMMON` mode**, because it is only
    granted there: it moves a session between containers, so it means nothing to
    a local account in one container and nothing at all on 11.2. The script says
    so now rather than skipping in silence, and that sentence is asserted here --
    a parameter that was honoured and one that was ignored used to look identical
    (#382).
    """
    first = sqlplus(container, ROOT, f"{scripts}/00_install.sql", install_mode, SVC)
    assert first.returncode == 0, first.stdout[-2000:]
    default = grants_of(container, ROOT, install_account)
    assert "SELECT ON USER$" not in default
    assert "SET CONTAINER" not in default

    result = sqlplus(
        container, ROOT, f"{scripts}/00_install.sql", install_mode, SVC, "USERS", "Y", "Y"
    )
    assert result.returncode == 0, result.stdout[-2000:]
    asked = grants_of(container, ROOT, install_account)
    assert "SELECT ON USER$" in asked
    if install_mode == "COMMON":
        assert "SET CONTAINER" in asked
    else:
        assert "SET CONTAINER" not in asked
        assert "SET CONTAINER not granted" in result.stdout, "asked for, skipped, and said so"


def test_installing_twice_changes_nothing(
    container: str, scripts: str, clean: None, install_mode: str, install_account: str
) -> None:
    """Invariant 9, at the level of the script an operator re-runs.

    The second run must leave the same grants and must not fail on the account it
    created itself -- `CREATE USER` on an existing account is `ORA-01920`, and the
    existence check is what stops it.
    """
    first = sqlplus(container, ROOT, f"{scripts}/00_install.sql", install_mode, SVC)
    assert first.returncode == 0, first.stdout[-2000:]
    before = grants_of(container, ROOT, install_account)

    second = sqlplus(container, ROOT, f"{scripts}/00_install.sql", install_mode, SVC)
    assert second.returncode == 0, second.stdout[-2000:]
    assert "already exists" in second.stdout
    assert grants_of(container, ROOT, install_account) == before


# ------------------------------------------------------------- the uninstall ---


def test_uninstall_removes_the_account_and_every_grant_with_it(
    container: str, scripts: str, clean: None, install_mode: str, install_account: str
) -> None:
    """Dropping the account takes the grants, which is what `99` claims."""
    installed = sqlplus(container, ROOT, f"{scripts}/00_install.sql", install_mode, SVC)
    assert installed.returncode == 0, installed.stdout[-2000:]
    assert grants_of(container, ROOT, install_account)

    result = sqlplus(container, ROOT, f"{scripts}/99_uninstall.sql", install_account)
    assert result.returncode == 0, result.stdout[-2000:]
    assert grants_of(container, ROOT, install_account) == set()
    assert (
        query(
            container, ROOT, f"SELECT username FROM dba_users WHERE username = '{install_account}';"
        )
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
    container: str, scripts: str, clean: None, cdb_only: None, unified_audit_only: None
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
    container: str, scripts: str, clean: None, cdb_only: None, unified_audit_only: None
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
    container: str, scripts: str, clean: None, cdb_only: None, unified_audit_only: None
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


# ------------------------------------------------- what a timeout leaves behind ---
#
# #326. These need no container and no database: the subject is what the module
# says when `docker exec` does not return, and the one occurrence there has been
# left nothing behind that could say whether Oracle was waiting or `docker exec`
# was. `_blocked_sessions` is the part that asks, and it is stubbed here -- it is
# exercised for real by the tier-1 tests above simply by never firing.

HUNG_OUTPUT = (
    b"Session altered.\n\n[1] the service account\n"
    b"  C##ACME_INSTALL_USER exists; its password is left alone\n\n"
    b"PL/SQL procedure successfully completed.\n\n\n[2] core grants\n  CREATE SESSION\n"
)


def _expired() -> subprocess.TimeoutExpired:
    return subprocess.TimeoutExpired(
        cmd=["docker", "exec", "-i", CONTAINER, "sqlplus", "-s", ROOT, "@00_install.sql"],
        timeout=EXEC_TIMEOUT_S,
        output=HUNG_OUTPUT,
    )


def test_the_report_ends_with_the_statement_that_hung(monkeypatch: pytest.MonkeyPatch) -> None:
    """The whole reason the tail is in the report: `00_install.sql` prints a label
    before each statement, so the last line printed names the one that never
    returned. It is what located the 2026-09-02 occurrence."""
    monkeypatch.setattr(
        "test_oracle_install_script._blocked_sessions", lambda _container: "(stubbed)"
    )

    report = _timeout_report(CONTAINER, _expired())

    assert "[2] core grants" in report
    assert "CREATE SESSION" in report
    assert "(stubbed)" in report


def test_the_report_refuses_the_obvious_wrong_fix(monkeypatch: pytest.MonkeyPatch) -> None:
    """A five-minute timeout on a sub-second call reads as a budget problem, and
    the next person to meet it will reach for the number. The report says not to,
    where they will be looking."""
    monkeypatch.setattr(
        "test_oracle_install_script._blocked_sessions", lambda _container: "(stubbed)"
    )

    report = _timeout_report(CONTAINER, _expired())

    assert "stall, not a slow run" in report
    assert "do not raise EXEC_TIMEOUT_S" in report


PIPED = "SELECT 1 FROM dual;\nEXIT\n"


class _Recorded:
    """What `_exec` handed to :func:`subprocess.run`, and nothing else."""

    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    def __call__(self, command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        self.calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "", "")


def test_a_file_script_is_run_without_attaching_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    """The #326 fix, pinned where it can be pinned deterministically.

    The shipped scripts end without `EXIT`, so SQL*Plus exits on EOF, and with
    `-i` that EOF had to be forwarded by `docker exec`. Twice it was not. The
    tier-1 calls pass with `-i` restored until the stall happens to recur, so this
    is the test that fails the moment a refactor puts it back (Copilot's review of
    #538).
    """
    recorded = _Recorded()
    monkeypatch.setattr(subprocess, "run", recorded)

    _exec(CONTAINER, ROOT, "@00_install.sql", "COMMON", "acme_install_user")

    [(command, kwargs)] = recorded.calls
    assert command[:3] == ["docker", "exec", CONTAINER], "file scripts must not take -i"
    assert "-i" not in command
    assert kwargs.get("stdin") is subprocess.DEVNULL
    assert "input" not in kwargs


def test_a_piped_script_keeps_stdin_and_is_given_its_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other half: without `-i` a piped script would reach SQL*Plus as nothing
    at all, and every query this module makes through it would return empty."""
    recorded = _Recorded()
    monkeypatch.setattr(subprocess, "run", recorded)

    _exec(CONTAINER, ROOT, script=PIPED)

    [(command, kwargs)] = recorded.calls
    assert command[:4] == ["docker", "exec", "-i", CONTAINER]
    assert kwargs.get("input") == PIPED


@pytest.mark.parametrize("output", [None, b"", "", b"only one line", "only one line"], ids=repr)
def test_the_tail_survives_whatever_the_killed_process_left(output: object) -> None:
    """`TimeoutExpired.output` is `bytes` undecoded, `None` when nothing arrived,
    and `str` when the caller asked for text. The point of this report is a
    process that did not finish, so its output is exactly the thing that cannot
    be assumed well-formed -- an `IndexError` here would replace the diagnosis
    with a different traceback."""
    tail = _tail(output)  # type: ignore[arg-type]

    assert tail, "always something to print"
    assert all(isinstance(line, str) for line in tail)


def test_undecodable_output_is_not_a_second_failure() -> None:
    """A killed process can be cut mid-character."""
    assert _tail(b"[2] core grants\n  CREATE SESSI\xff") == [
        "[2] core grants",
        "  CREATE SESSI\ufffd",
    ]


def test_a_diagnosis_that_also_hangs_is_itself_the_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The distinction that decides the fix (#326): Oracle waiting, or `docker
    exec` not returning. If the probe cannot get in either, it is the second, and
    that is an answer rather than a diagnostic that failed."""

    def hangs(*_args: object, **_kwargs: object) -> NoReturn:
        raise subprocess.TimeoutExpired(cmd=["docker"], timeout=DIAGNOSE_TIMEOUT_S)

    monkeypatch.setattr(subprocess, "run", hangs)

    found = _blocked_sessions(CONTAINER)

    assert "also hung" in found
    assert "daemon is what stalled" in found


def test_a_docker_that_is_not_there_is_reported_rather_than_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """This runs when something is already wrong. A diagnostic that raises
    replaces the failure it was called to explain."""

    def gone(*_args: object, **_kwargs: object) -> NoReturn:
        raise OSError("no such file or directory: docker")

    monkeypatch.setattr(subprocess, "run", gone)

    assert "could not be read" in _blocked_sessions(CONTAINER)


def test_a_quiet_database_says_so_rather_than_printing_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ "No rows" and "the probe found nothing to say" are different findings, and
    a blank section reads as the second."""
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_k: subprocess.CompletedProcess(args=[], returncode=0, stdout="\n \n"),
    )

    found = _blocked_sessions(CONTAINER)

    assert "nothing waiting" in found


def test_a_probe_that_failed_is_not_reported_as_a_quiet_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The trap :func:`query` documents, one function over: SQL*Plus prints an
    `ORA-` and still exits 0 unless told otherwise, and a refused connection
    writes nothing at all. Either would have read as *nothing waiting* -- the one
    conclusion that must never be reached by accident, because it points the next
    reader away from the database."""
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_k: subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="Error response from daemon: no such container",
        ),
    )

    found = _blocked_sessions(CONTAINER)

    assert "could not be read" in found
    assert "no such container" in found
    assert "nothing waiting" not in found


def test_an_ora_error_from_the_probe_is_not_mistaken_for_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`whenever sqlerror exit sql.sqlcode` is what makes this a non-zero exit
    rather than error text arriving where rows were expected."""
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_k: subprocess.CompletedProcess(
            args=[], returncode=942, stdout="ORA-00942: table or view does not exist", stderr=""
        ),
    )

    found = _blocked_sessions(CONTAINER)

    assert "sqlplus exited 942" in found
    assert "ORA-00942" in found
    assert "non-idle or blocked" not in found


def test_a_timeout_fails_the_test_rather_than_escaping_as_a_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`_exec` is where every one of this module's eighteen calls goes, so the
    report has to be attached here rather than at any one of them."""

    def hangs(*_args: object, **_kwargs: object) -> NoReturn:
        raise subprocess.TimeoutExpired(cmd=["docker"], timeout=EXEC_TIMEOUT_S, output=HUNG_OUTPUT)

    monkeypatch.setattr(subprocess, "run", hangs)

    with pytest.raises(Failed) as failure:
        _exec(CONTAINER, ROOT, "@00_install.sql")

    assert "did not return" in str(failure.value)
    assert "[2] core grants" in str(failure.value)


def test_the_audit_script_refuses_a_release_without_unified_auditing(
    container: str, scripts: str, has_unified_audit: bool
) -> None:
    """`01_audit_policy.sql` on 11.2, which has no audit policies to create.

    Until #382 it ran head first into `AUDIT_UNIFIED_POLICIES` and produced four
    `ORA-00942`s wrapped in `ORA-06550` -- an operator told a view was missing
    and left to work out which release they were on and why. It did at least exit
    non-zero, so nothing was silently skipped; the fix is the message, not the
    exit code.

    The refusal names the release it needs and the traditional-auditing statement
    to use instead. It stops there deliberately: emitting `AUDIT ALTER USER`
    would give the tool a second audit story to own, and
    `02-oracle-privileges.md` §5 is written entirely around unified auditing, so
    what it should say about a release without it is a decision rather than a
    missing statement (#382).
    """
    if has_unified_audit:
        pytest.skip("this release has unified auditing: there is nothing to refuse")

    result = sqlplus(container, ROOT, f"{scripts}/01_audit_policy.sql", LOCAL_SVC)

    assert result.returncode != 0, "a refusal that exits 0 is indistinguishable from a run"
    assert "ORA-20020" in result.stdout
    assert "12.1" in result.stdout, "the release it needs, so nobody has to look it up"
    assert "AUDIT ALTER USER" in result.stdout, "and what to do instead"

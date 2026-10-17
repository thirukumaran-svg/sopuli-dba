"""sopuli-dba : what the client raises when a database goes away   (v2)

#775. A run that holds a session can lose it: its PDB is closed, or the CDB is
shut down. A run that logs on while the CDB starts gets refused. This records
the code python-oracledb raises in each case, in thick mode, which is the mode
the tool runs in (D3), so the driver maps the codes a run actually gets:

  SL1  a session held on the PDB when the PDB is closed IMMEDIATE: the next
       call, a second call, and a new logon to the PDB
  SL2  a session held on the PDB when the CDB shuts down IMMEDIATE: the next
       call; then, with the instance down, a logon to the PDB service and to
       the CDB service
  SL3  logons while the CDB starts: to the PDB service and to the CDB
       service, in NOMOUNT and in MOUNT
  SL4  a session held on the PDB when the CDB is shut down ABORT: the next
       call

It MEASURES and maps nothing. The mapping is driver/oracle/errors.py.

STATUS: run on 26ai Free 23.26.2.0.0 (gvenzl/oracle-free:latest), with Instant
Client 23.26.3.0.0 for Windows and python-oracledb 26.0.0 in thick mode,
2026-10-17. The file as it stands was run three times, exit 0 and the same
codes each time, which were also the codes of three earlier runs before its
safety checks were added.

RESULTS -- 26ai Free 23.26.2.0.0

  SL1  next call: DPY-4011 "the database or network closed the connection".
       Its message goes on "DPI-1080: connection was closed by ORA-03113" and
       "ORA-03113: end-of-file on communication channel", but full_code is
       DPY-4011, so that is the code the tool reads. Second call: DPY-1001
       "not connected to database". New logon: ORA-01109
  SL2  next call: DPY-4011, as SL1. Logons with the instance down: ORA-12514
       to both services
  SL3  NOMOUNT: ORA-12514 to the PDB service, ORA-12528 "all appropriate
       instances are blocking new connections" to the CDB service. MOUNT:
       ORA-12514 to the PDB service, ORA-01033 "initialization or shutdown in
       progress" to the CDB service
  SL4  next call: DPY-4011, as SL1

  Not produced by any step: ORA-00028, ORA-03113 and ORA-03135 as the code
  itself (ORA-03113 arrives inside DPY-4011), ORA-01034 and ORA-01089.

HOW TO RUN (from the repo root, against the tier-1 stack):

    python sql/oracle/14_session_loss_probe.py

It connects as SYSTEM over the listener and drives the DBA side through
SQL*Plus inside the container, with the SQL on stdin, so no password is ever in
argv (invariant 1). The container and the port follow the tier-1 tests:
COMPOSE_PROJECT_NAME or SOPULI_TEST_ORACLE_CONTAINER, and
SOPULI_TEST_ORACLE_PORT, so a second clone's stack is the one it shuts down
(test/README.md). The passwords are tier 1's public ones from
test/compose.yaml. Against any other database, copy the file, edit the
constants in the copy, run the copy and delete it, as 07 prescribes.

A measured DBA step that fails stops the probe with SQL*Plus's output, so a
step that did not happen is never printed as a result. Whatever happens, it
starts the CDB and opens its PDBs before it exits.

THROWAWAY DATABASES ONLY. It closes the PDB, shuts the CDB down twice (once
with ABORT) and starts it again. Every session on the database is lost.
"""

from __future__ import annotations

import os
import subprocess
import time

import oracledb

CONTAINER = os.environ.get(
    "SOPULI_TEST_ORACLE_CONTAINER",
    f"{os.environ.get('COMPOSE_PROJECT_NAME', 'sopuli-test')}-oracle-free-1",
)
PORT = os.environ.get("SOPULI_TEST_ORACLE_PORT", "1521")
PDB_DSN = f"127.0.0.1:{PORT}/FREEPDB1"
CDB_DSN = f"127.0.0.1:{PORT}/FREE"
USER = "system"
PASSWORD = "sopuli-test"

#: The codes a logon gets while the PDB or the CDB is on its way back. Any other
#: code, such as a wrong password or no Instant Client, will not clear by
#: waiting, so :func:`held` stops on it at once.
TRANSIENT = {"ORA-01109", "ORA-12514", "ORA-12528", "ORA-01033", "DPY-4011"}


def dba(sql: str, *, measured: bool = True) -> None:
    """Run SQL as SYSDBA inside the container. The SQL goes on stdin.

    ``measured`` steps are the ones a result depends on: SQL*Plus exits on the
    first error, and the probe stops with what it printed. The restore steps
    pass ``measured=False``, because a PDB that is already open is not a
    failure there.
    """
    on_error = "exit failure" if measured else "continue"
    result = subprocess.run(
        ["docker", "exec", "-i", CONTAINER, "sqlplus", "-S", "/ as sysdba"],
        input=f"whenever sqlerror {on_error}\n{sql}\nexit\n".encode(),
        capture_output=True,
        check=False,
    )
    output = result.stdout.decode("utf-8", "replace")
    if measured and (result.returncode != 0 or "ORA-" in output):
        raise SystemExit(f"DBA step failed, so nothing after it is a measurement:\n{sql}\n{output}")


def described(error: BaseException) -> str:
    """The code the tool reads, ``full_code``, and the message's first line."""
    detail = error.args[0] if error.args else None
    code = getattr(detail, "full_code", None)
    lines = str(getattr(detail, "message", "") or error).splitlines()
    return f"{code} {lines[0] if lines else ''!r}"


def code_of(error: oracledb.Error) -> str | None:
    detail = error.args[0] if error.args else None
    return getattr(detail, "full_code", None)


def call(conn: oracledb.Connection, label: str) -> None:
    try:
        with conn.cursor() as cursor:
            cursor.execute("select 1 from dual")
            cursor.fetchone()
        print(f"  {label}: no error")
    except oracledb.Error as error:
        print(f"  {label}: {described(error)}")


def logon(dsn: str, label: str) -> None:
    try:
        oracledb.connect(user=USER, password=PASSWORD, dsn=dsn).close()
        print(f"  {label}: logon succeeded")
    except oracledb.Error as error:
        print(f"  {label}: {described(error)}")


def held() -> oracledb.Connection:
    """A session on the PDB, once the PDB accepts one."""
    for _ in range(60):
        try:
            return oracledb.connect(user=USER, password=PASSWORD, dsn=PDB_DSN)
        except oracledb.Error as error:
            if code_of(error) not in TRANSIENT:
                raise
            time.sleep(5)
    raise SystemExit("FREEPDB1 did not open within five minutes")


def restore() -> None:
    """Start the CDB and open every PDB, from whatever state a step left."""
    dba("startup", measured=False)
    dba("alter database open;\nalter pluggable database all open;", measured=False)
    held().close()


def main() -> None:
    oracledb.init_oracle_client()
    print(f"thick mode: {not oracledb.is_thin_mode()}, python-oracledb {oracledb.__version__}")
    try:
        measure()
    finally:
        restore()
        print("done: the CDB and FREEPDB1 are open again")


def measure() -> None:
    print("SL1: the PDB closed IMMEDIATE under a held session")
    conn = held()
    dba("alter pluggable database freepdb1 close immediate;")
    call(conn, "next call")
    call(conn, "second call")
    logon(PDB_DSN, "new logon to the PDB")
    dba("alter pluggable database freepdb1 open;")

    print("SL2: the CDB shut down IMMEDIATE under a held session")
    conn = held()
    dba("shutdown immediate")
    call(conn, "next call")
    logon(PDB_DSN, "instance down, logon to the PDB service")
    logon(CDB_DSN, "instance down, logon to the CDB service")

    print("SL3: logons while the CDB starts")
    dba("startup nomount")
    time.sleep(15)  # until the instance registers with the listener
    logon(PDB_DSN, "NOMOUNT, logon to the PDB service")
    logon(CDB_DSN, "NOMOUNT, logon to the CDB service")
    dba("alter database mount;")
    time.sleep(15)
    logon(PDB_DSN, "MOUNT, logon to the PDB service")
    logon(CDB_DSN, "MOUNT, logon to the CDB service")
    dba("alter database open;", measured=False)
    dba("alter pluggable database all open;", measured=False)

    print("SL4: the CDB shut down ABORT under a held session")
    conn = held()
    dba("shutdown abort")
    call(conn, "next call")


if __name__ == "__main__":
    main()

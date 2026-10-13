"""Fault injection: the database changes part way through a rotation (`04-testing.md` §5).

Two rows of §5's table, asserted against UC-1 §8's *Failure at each step*:

* a PDB closes mid-run, on one target of two. The other target takes the new
  password, ``current`` is not promoted, and the run exits 4. Once the PDB is
  open, ``creds apply`` finishes the job. So does ``--repair`` with the run's
  document, followed by ``creds apply`` to promote;
* the admin user loses ``ALTER USER`` mid-run. The run reports the
  authorization error, and nothing is half-written: the database keeps the old
  password and ``current`` is unchanged.

Step 3, the pre-flight, finds a closed PDB or a missing grant before anything is
written. So the fault goes in after it. :class:`fault_harness.VaultGate` pauses
step 4's staging write, the test changes the database as ``SYS``, and the gate
lets the write through. Step 5 then meets the changed database.

These need only the tier-1 services, Oracle Free and Vault, and skip without
them. The PDB test creates a PDB of its own, which takes a few seconds.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import re
import subprocess
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from conftest import PASSWORD, USER
from fault_harness import (
    ACCOUNT,
    LOCK,
    OLD,
    SECRET,
    STAGING,
    TIMEOUT,
    Estate,
    Fault,
    VaultGate,
    start_paused,
)
from oracle_harness import Environment, current_container, execute, service_account_grants
from sopuli.config.targets import ADMIN_PASSWORD_ENV
from sopuli.diagnostics import PROMOTION_WITHHELD
from sopuli.exit_codes import ExitCode

#: The second PDB. Oracle Free has one, ``FREEPDB1``, and the test makes this one.
PDB = "acme_fault_pdb"
PDB_TARGET = "fault-pdb"

#: A service account with `02-oracle-privileges.md` §2's grants and no more, so
#: that revoking ``ALTER USER`` takes it away. ``system`` holds it through the
#: ``DBA`` role, and a direct revoke cannot remove that.
SERVICE = "acme_fault_svc_user"
SERVICE_PASSWORD = "Fault-Service-Acct-7q"

#: ``CREATE PLUGGABLE DATABASE`` requires an admin user. Nothing logs in as it.
PDB_ADMIN_PASSWORD = "Fault-Pdb-Admin-4w"

#: A directory object over the second PDB's datafile directory, for as long as
#: :func:`_remove_orphans` needs it.
ORPHANS = "ACME_FAULT_ORPHANS"


#: What ``CLOSE`` and ``DROP`` say about a PDB that is already in the wanted
#: state: ``ORA-65011``, it does not exist, and ``ORA-65020``, it is already
#: closed. Measured on 26ai Free 23.26.2.0.0.
ABSENT_OR_CLOSED = ("ORA-65011", "ORA-65020")

#: What step 5 can meet at a closed PDB. ``ORA-01109``, database not open, on
#: every run measured: the run opens a new session at step 5, and the closed
#: PDB's service is still registered. ``ORA-12514`` if the service has gone
#: from the listener by then.
CLOSED_PDB = ("ORA-01109", "ORA-12514")

#: A plain easy-connect DSN, ``host:port/service``, with nothing after the
#: service. The second PDB's DSN is this one with the service replaced.
EASY_CONNECT = re.compile(r"(?P<address>[^/?\s]+)/(?P<service>[\w.$#]+)")


def _container(sysdba: Any, name: str) -> None:
    execute(sysdba, f"alter session set container = {name}")


def _connect(dsn: str, user: str, password: str) -> Any:
    oracledb = pytest.importorskip("oracledb")
    return oracledb.connect(user=user, password=password, dsn=dsn)


def _logs_in(dsn: str, password: str) -> bool:
    oracledb = pytest.importorskip("oracledb")
    try:
        _connect(dsn, ACCOUNT, password).close()
    except oracledb.DatabaseError:
        return False
    return True


def _wait_for_service(dsn: str) -> None:
    """Wait until the listener knows the new PDB's service.

    The PDB registers with the listener after it opens, not as it opens, so a
    connection straight after ``OPEN`` can get ``ORA-12514``.
    """
    oracledb = pytest.importorskip("oracledb")
    deadline = time.monotonic() + TIMEOUT
    while True:
        try:
            _connect(dsn, USER, PASSWORD).close()
            return
        except oracledb.DatabaseError:
            if time.monotonic() > deadline:
                raise
            time.sleep(1)


def _drop_pdb(sysdba: Any) -> None:
    """Absent is the desired state, so "it was not there" is a success.

    Any other failure is raised. A drop that failed silently would surface at
    the next setup as "already exists", far from its cause.

    The drop runs in the root, and the session goes back to the container it
    started in. :func:`service_account` reads that container to decide whether
    it can run.
    """
    before = current_container(sysdba)
    _container(sysdba, "cdb$root")
    try:
        _close_and_drop(sysdba)
    finally:
        _container(sysdba, before)


def _close_and_drop(sysdba: Any) -> None:
    for statement in (
        f"alter pluggable database {PDB} close immediate",
        f"drop pluggable database {PDB} including datafiles",
    ):
        try:
            execute(sysdba, statement)
        except Exception as error:  # noqa: BLE001 -- classified on the next line
            if not any(code in str(error) for code in ABSENT_OR_CLOSED):
                raise


def _file_names(sysdba: Any) -> str:
    """Where the new PDB's datafiles go: beside the seed's, or where OMF puts them.

    With ``db_create_file_dest`` set, Oracle names the files itself and a
    ``FILE_NAME_CONVERT`` clause is not needed. Without it, the clause maps the
    seed's directory to a sibling named after the PDB. Any file already in the
    sibling under one of the seed's file names is removed first. A run that dies
    during the create leaves its files there with no PDB to own them, so the drop
    does not remove them, and the next create would fail with ``ORA-27038``, file
    already exists.
    """
    with sysdba.cursor() as cursor:
        cursor.execute("select value from v$parameter where name = 'db_create_file_dest'")
        if cursor.fetchone()[0]:
            return ""
        cursor.execute(
            "select name from v$datafile where con_id = 2"
            " union all select name from v$tempfile where con_id = 2"
        )
        seed = [row[0] for row in cursor]
    separator = "\\" if "\\" in seed[0] else "/"
    directories = {name.rpartition(separator)[0] for name in seed}
    if len(directories) > 1:
        pytest.skip(
            f"the seed's files are in {len(directories)} directories, "
            f"and this fixture maps only one: {sorted(directories)}"
        )
    directory = directories.pop()
    target = f"{directory.rpartition(separator)[0]}{separator}{PDB.upper()}"
    _remove_orphans(sysdba, target, [name.rpartition(separator)[2] for name in seed])
    return f" file_name_convert = ('{directory}{separator}', '{target}{separator}')"


def _remove_orphans(sysdba: Any, directory: str, names: list[str]) -> None:
    """Remove each named file in ``directory`` that is there.

    ``UTL_FILE`` is the one way, from a database session, to delete a file that
    no tablespace owns. For a directory that does not exist yet, ``FGETATTR``
    says the file is not there.
    """
    execute(sysdba, f"create or replace directory {ORPHANS} as '{directory}'")
    try:
        with sysdba.cursor() as cursor:
            for name in names:
                cursor.execute(
                    """
                    declare
                        present boolean;
                        file_length number;
                        block_size binary_integer;
                    begin
                        utl_file.fgetattr(:directory, :name, present, file_length, block_size);
                        if present then
                            utl_file.fremove(:directory, :name);
                        end if;
                    end;
                    """,
                    directory=ORPHANS,
                    name=name,
                )
    finally:
        execute(sysdba, f"drop directory {ORPHANS}")


@pytest.fixture
def second_pdb(sysdba: Any, live_oracle: Environment) -> Iterator[str]:
    """A PDB of its own with the fault account in it, and its DSN.

    The datafiles go beside the seed's. Dropped at the end, and before the
    start in case an earlier run died with one in place.
    """
    if current_container(sysdba) == "NON-CDB":
        pytest.skip("this database has no containers, so no second PDB")
    easy = EASY_CONNECT.fullmatch(live_oracle.dsn)
    if easy is None:
        pytest.skip(
            f"this fixture makes the second PDB's DSN from a plain host:port/service DSN, "
            f"and {live_oracle.dsn} is not one"
        )
    dsn = f"{easy['address']}/{PDB}"
    home = current_container(sysdba)
    _drop_pdb(sysdba)
    try:
        _container(sysdba, "cdb$root")
        try:
            execute(
                sysdba,
                f"create pluggable database {PDB} admin user acme_pdb_admin "
                f'identified by "{PDB_ADMIN_PASSWORD}"{_file_names(sysdba)}',
                f"alter pluggable database {PDB} open",
            )
        finally:
            _container(sysdba, home)
        _wait_for_service(dsn)
        with contextlib.closing(_connect(dsn, USER, PASSWORD)) as system:
            execute(
                system,
                f'create user {ACCOUNT} identified by "{OLD}"',
                f"grant create session to {ACCOUNT}",
            )
        yield dsn
    finally:
        _drop_pdb(sysdba)


@pytest.fixture
def service_account(sysdba: Any, live_oracle: Environment) -> Iterator[str]:
    """§2's service account in the estate's PDB. Returns its name."""
    if current_container(sysdba) == "CDB$ROOT":
        pytest.skip("this DSN answers as CDB$ROOT; a local service account needs a PDB")

    def drop() -> None:
        try:
            execute(sysdba, f"drop user {SERVICE} cascade")
        except Exception as error:  # noqa: BLE001 -- classified on the next line
            if "ORA-01918" not in str(error):  # absent is the ordinary case
                raise

    drop()
    try:
        execute(
            sysdba,
            f'create user {SERVICE} identified by "{SERVICE_PASSWORD}"',
            *service_account_grants(SERVICE),
        )
        yield SERVICE
    finally:
        drop()


#: Rotate through a gate that pauses the staging write. The callable is the
#: change the test makes to the database while the write waits.
Rotate = Callable[[Estate, Callable[[], None]], subprocess.CompletedProcess[str]]


@pytest.fixture
def rotate(vault_stack: Any) -> Iterator[Rotate]:
    """Rotate with the database changed between the pre-flight and step 5."""
    gates: list[VaultGate] = []
    with ThreadPoolExecutor(max_workers=1) as pool:

        def through(estate: Estate, change: Callable[[], None]) -> subprocess.CompletedProcess[str]:
            gate = VaultGate(
                vault_stack.addr,
                f"/v1/{estate.mount}/data/{SECRET}",
                Fault.PAUSE_WRITE,
                writes=STAGING,
            )
            gates.append(gate)
            run = start_paused(pool, estate, gate, "creds", "rotate", "--confirm")
            try:
                change()
            finally:
                gate.release()
            return run.result(timeout=TIMEOUT)

        # Closed inside the pool, so a run still paused at a gate is let go
        # before the pool waits for it.
        try:
            yield through
        finally:
            for gate in gates:
                gate.close()


def _rows(result: subprocess.CompletedProcess[str]) -> dict[str, dict[str, Any]]:
    """The applied rows by target. ``rotate`` lists its staging rows first."""
    document = json.loads(result.stdout)
    return {
        row["target"]: row for row in document.get("results", []) if row["state"] != "PENDING_APPLY"
    }


@dataclass
class Closed:
    """A rotation whose second target's PDB closed after the pre-flight.

    The PDB is open again by the time a test gets this, so a recovery can reach it.
    """

    estate: Estate
    config: Path
    result: subprocess.CompletedProcess[str]
    pdb: str
    old: str


@pytest.fixture
def closed_mid_run(
    fault_estate: Estate, vault_stack: Any, sysdba: Any, second_pdb: str, rotate: Rotate
) -> Closed:
    """Rotate once to the end on both targets, then again with the PDB closing.

    ``sysdba`` stands in the root throughout, where it opens and closes the PDB.
    """
    _container(sysdba, "cdb$root")
    estate = dataclasses.replace(fault_estate, more_targets=((PDB_TARGET, second_pdb),))
    config = estate.config(vault_stack.addr)
    first = estate.sopuli(config, "creds", "rotate", "--confirm")
    assert first.returncode == ExitCode.SUCCESS, first.stderr
    before, _ = estate.read(SECRET)

    result = rotate(
        estate, lambda: execute(sysdba, f"alter pluggable database {PDB} close immediate")
    )
    execute(sysdba, f"alter pluggable database {PDB} open")
    _wait_for_service(second_pdb)
    return Closed(
        estate=estate,
        config=config,
        result=result,
        pdb=second_pdb,
        old=before["DB_CREDENTIALS"][ACCOUNT],
    )


def test_a_pdb_closed_mid_run_is_partial_and_promotes_nothing(closed_mid_run: Closed) -> None:
    """UC-1 §8 row 5: one target has the new password, ``current`` is still old.

    The failure does not reach the other target: it takes the new password and
    keeps it. Invariant 7 holds the promotion back, and the closed PDB keeps
    the old password.
    """
    closed = closed_mid_run

    assert closed.result.returncode == ExitCode.PARTIAL, closed.result.stderr
    rows = _rows(closed.result)
    assert rows["free-pdb"]["changed"] is True
    assert rows[PDB_TARGET]["state"] == "ERROR"
    assert rows[PDB_TARGET]["changed"] is False
    assert rows[PDB_TARGET]["error"]["code"] in CLOSED_PDB
    assert rows[PDB_TARGET]["error"]["category"] == "connectivity"
    # ORA-01109 may clear when the PDB opens; ORA-12514 is not classified so (#774).
    assert rows[PDB_TARGET]["error"]["retryable"] is (
        rows[PDB_TARGET]["error"]["code"] == "ORA-01109"
    )
    assert "closed" in rows[PDB_TARGET]["error"].get("hint", ""), rows[PDB_TARGET]["error"]
    staged, _ = closed.estate.read(SECRET)
    assert staged["DB_CREDENTIALS"][ACCOUNT] == closed.old, "promoted with a target unconfirmed"
    assert closed.estate.login(staged["pending"][ACCOUNT])
    assert _logs_in(closed.pdb, closed.old), "the closed PDB was changed"


def test_apply_completes_a_rotation_a_closed_pdb_interrupted(closed_mid_run: Closed) -> None:
    """``creds apply`` verifies both targets, applies to the one that missed it,
    and promotes. It logs in to the target that was already right too, which is
    the cost ``--repair`` saves (next test).
    """
    closed = closed_mid_run
    staged, _ = closed.estate.read(SECRET)
    new = staged["pending"][ACCOUNT]

    applied = closed.estate.sopuli(closed.config, "creds", "apply", "--confirm")

    assert applied.returncode == ExitCode.SUCCESS, applied.stderr
    promoted, _ = closed.estate.read(SECRET)
    assert promoted["DB_CREDENTIALS"][ACCOUNT] == new
    assert ACCOUNT not in promoted.get("pending", {})
    assert _logs_in(closed.pdb, new)


def test_apply_repair_then_apply_finishes_a_rotation(closed_mid_run: Closed) -> None:
    """UC-1 §8 row 5's recovery: ``creds apply --repair`` with the run's document,
    then ``creds apply``.

    The repair reaches only the target that missed the password, and applies it.
    It withholds the promotion with ``SOPULI-W027``, because ``current`` is shared
    with the target it left out (UC-1 §5, *A repair of a rotation*). The plain
    apply then promotes.
    """
    closed = closed_mid_run
    staged, _ = closed.estate.read(SECRET)
    new = staged["pending"][ACCOUNT]
    document = closed.estate.tmp_path / "rotate.json"
    document.write_text(closed.result.stdout, encoding="utf-8")
    # `--repair` refuses a document produced over another config path. The rotation
    # ran over a config naming the gate, so the repair runs over that same path,
    # rewritten to name Vault itself.
    (rotated,) = json.loads(closed.result.stdout)["invocation"]["config_files"]
    config = Path(rotated)
    config.write_text(closed.config.read_text(encoding="utf-8"), encoding="utf-8")

    repaired = closed.estate.sopuli(
        config, "creds", "apply", "--repair", str(document), "--confirm"
    )

    assert repaired.returncode == ExitCode.PARTIAL, repaired.stderr
    assert set(_rows(repaired)) == {PDB_TARGET}
    codes = {one.get("code") for one in json.loads(repaired.stdout)["diagnostics"]}
    assert PROMOTION_WITHHELD in codes
    assert _logs_in(closed.pdb, new)
    withheld, _ = closed.estate.read(SECRET)
    assert withheld["DB_CREDENTIALS"][ACCOUNT] == closed.old

    applied = closed.estate.sopuli(config, "creds", "apply", "--confirm")

    assert applied.returncode == ExitCode.SUCCESS, applied.stderr
    promoted, _ = closed.estate.read(SECRET)
    assert promoted["DB_CREDENTIALS"][ACCOUNT] == new
    assert ACCOUNT not in promoted.get("pending", {})


def test_alter_user_revoked_mid_run_is_an_authorization_error(
    fault_estate: Estate,
    vault_stack: Any,
    sysdba: Any,
    service_account: str,
    rotate: Rotate,
) -> None:
    """The run names ``ORA-01031``, and leaves nothing half-written.

    The database keeps the old password and ``current`` is unchanged. Only
    ``pending`` is new, which UC-1 §8 allows at step 4 and the next rotation
    replaces.
    """
    estate = dataclasses.replace(
        fault_estate,
        user=service_account,
        env={**fault_estate.env, ADMIN_PASSWORD_ENV: SERVICE_PASSWORD},
    )
    first = estate.sopuli(estate.config(vault_stack.addr), "creds", "rotate", "--confirm")
    assert first.returncode == ExitCode.SUCCESS, first.stderr
    before, _ = estate.read(SECRET)
    old = before["DB_CREDENTIALS"][ACCOUNT]

    result = rotate(estate, lambda: execute(sysdba, f"revoke alter user from {service_account}"))

    assert result.returncode == ExitCode.FAILURE, result.stderr
    row = _rows(result)["free-pdb"]
    assert row["state"] == "ERROR"
    assert row["changed"] is False
    assert row["error"]["code"] == "ORA-01031"
    assert row["error"]["category"] == "authorization"
    after, _ = estate.read(SECRET)
    assert after["DB_CREDENTIALS"][ACCOUNT] == old
    assert estate.login(old)
    assert not estate.login(after["pending"][ACCOUNT])
    lock, _ = estate.read(LOCK)
    assert lock["state"] == "released"

# Measurements

This file says what has been run on which Oracle release, when, and what it
showed. It is the one place for that. Other documents link here instead of
listing releases themselves.

A result holds only for the release it names. Oracle's retention and auditing
behaviour is not a documented guarantee, and it differs between releases: 11.2
keeps the `ALTER USER` text in `V$SQLSTATS`, and every later release measured
does not. So always name the full release, such as `19.32.0.0.0`, and never
"19c".

Each script in `sql/oracle/` has a header that records its own runs in detail.
`tests/test_measurements.py` checks that the releases a script's header names are
the same releases the *Scripts* table below lists for it. When you run a script
on a new release, update both.

The tier-1 suite in CI is not a measurement here. It pulls the moving
`gvenzl/oracle-free:latest` image, so a green CI run does not show which
release it ran on. The suite has no rows in this file.

## Releases

| Release | Product, and where it ran |
|---|---|
| `23.26.2.0.0` | 26ai Free, the `gvenzl/oracle-free` container, as pulled for the runs below |
| `23.26.3.3.0` | 26ai, an Autonomous Database (serverless) on OCI |
| `23.26.3.0.0` | Instant Client for Windows. Not a database: the client for the wallet results below, where the client decides the outcome |
| `21.3.0.0.0` | 21c XE, the `gvenzl/oracle-xe:21-slim` container |
| `19.32.0.0.0` | 19c EE, an OCI Base Database Service DB system. A release update |
| `19.24.0.0.0` | 19c EE High Performance. Checked by hand, once |
| `19.3.0.0.0` | 19c EE, the Oracle registry image, `test/compose.yaml` profile `oracle19c`. The 19c base release |
| `18.4.0.0.0` | 18c XE, the `gvenzl/oracle-xe:18-slim` container |
| `12.2.0.1.0` | 12c EE, the Oracle registry slim image, profile `oracle12c`. Its character set is WE8DEC |
| `11.2.0.2.0` | 11g XE, the `gvenzl/oracle-xe:11.2.0.2-slim` container. A non-CDB |

Not measured: 12.1, any 23ai release before 23.26, and every 19c release update
other than 19.24 and 19.32. One release update is not every release update.

## Scripts

<!-- measurements: scripts -->
| Script | Release | Date | Issue | Result |
|---|---|---|---|---|
| `00_install.sql` | `23.26.2.0.0` | 2026-08-26 | — | All three modes, create and already-exists paths, both mode guards. `grant_pwfile` added and run 2026-09-05 (#296); `grant_connect_info` 2026-10-09 (#697) |
| `00_install.sql` | `21.3.0.0.0` | 2026-09-08 | #380 | PDB and `CDB$ROOT`. Ran only after the service account's random password was cut from 31 to 30 bytes |
| `00_install.sql` | `18.4.0.0.0` | 2026-09-08 | #381 | PDB and `CDB$ROOT` |
| `00_install.sql` | `11.2.0.2.0` | 2026-09-08 | #382 | `NONCDB` mode, after two fixes for a non-CDB |
| `00_install.sql` | `19.3.0.0.0` | 2026-09-28 | #479 | PDB and `COMMON` modes; the over-grant query is empty |
| `00_install.sql` | `12.2.0.1.0` | 2026-09-29 | #572 | PDB and `COMMON` modes. The image's root has no `USERS` tablespace |
| `00_install.sql` | `19.32.0.0.0` | 2026-10-01 | #581 | PDB and `COMMON` modes, after section 1's password was changed to pass `ORA12C_STRONG_VERIFY_FUNCTION` |
| `00_install.sql` | `23.26.3.3.0` | 2026-09-28 | #479 | PDB mode as `ADMIN`. `grant_user_dollar=Y` cannot succeed there (#478) |
| `01_audit_policy.sql` | `23.26.2.0.0` | 2026-08-26 | — | Create and already-exists paths; the correlation queries checked against a real audited `ALTER USER` |
| `01_audit_policy.sql` | `21.3.0.0.0` | 2026-09-08 | #380 | Runs. The XE image ships `AUDIT_TRAIL = NONE`, so it records nothing until that is changed |
| `01_audit_policy.sql` | `18.4.0.0.0` | 2026-09-08 | #381 | As on 21.3 |
| `01_audit_policy.sql` | `11.2.0.2.0` | 2026-09-08 | #382 | Refuses with `ORA-20020`: audit policies arrived in 12.1 |
| `01_audit_policy.sql` | `19.3.0.0.0` | 2026-09-28 | #479 | PDB and `CDB$ROOT` |
| `02_password_leak_probe.sql` | `23.26.2.0.0` | 2026-08-26 | — | All three positions. No cursor for the DDL; unified audit masks it; the only leak is the PL/SQL block (C3). Position 2 with `AUDIT_SYS_OPERATIONS` 2026-09-11 (#407) |
| `02_password_leak_probe.sql` | `21.3.0.0.0` | 2026-09-08 | #380 | Position 1 as on 26ai; traditional auditing masks too. Position 2 2026-09-11 (#407) |
| `02_password_leak_probe.sql` | `18.4.0.0.0` | 2026-09-08 | #381 | Position 1, as on 21.3 |
| `02_password_leak_probe.sql` | `11.2.0.2.0` | 2026-09-08 | #382 | Position 1. **`V$SQLSTATS` keeps the plain `ALTER USER` text.** It ages out, and `FLUSH SHARED_POOL` clears it (2026-09-09, #387) |
| `02_password_leak_probe.sql` | `19.3.0.0.0` | 2026-09-27 | #548 | All three positions. C3 only; `V$SQLSTATS` clean |
| `02_password_leak_probe.sql` | `12.2.0.1.0` | 2026-09-29 | #572 | All three positions. C3 only; `V$SQLSTATS` clean |
| `02_password_leak_probe.sql` | `19.32.0.0.0` | 2026-10-01 | #581 | All three positions. C3 only; `V$SQLSTATS` and `V$SQL_BIND_CAPTURE` clean with the verify function on. Under `AUDIT_TRAIL = DB` the traditional trail records no statement text |
| `03_app_container_probe.sql` | `23.26.2.0.0` | 2026-09-03 | #204 | An application root and an application PDB can be told apart with no grant |
| `04_password_leak_extensions.sql` | `23.26.2.0.0` | 2026-09-11 | #407 | Self-rotation and `IDENTIFIED BY VALUES` masked. A level-12 trace writes the DDL cut short, `ALTER USER sopulitest IDE`; the wrapped form (C8) leaks. No user DDL reaches the OS audit files |
| `04_password_leak_extensions.sql` | `21.3.0.0.0` | 2026-09-11 | #407 | As on 26ai; the OS audit file has the DDL masked |
| `04_password_leak_extensions.sql` | `19.3.0.0.0` | 2026-09-28 | #479 | As on 21.3 |
| `04_password_leak_extensions.sql` | `19.32.0.0.0` | 2026-10-01 | #581 | As on 19.3, except that `IDENTIFIED BY VALUES` is absent from the traditional trail. The cause is not known |
| `05_verifier_layout_probe.sql` | `23.26.2.0.0` | 2026-09-15 | #431 | `SPARE4` holds `S:` then `T:`; the salt offsets are read off the wire |
| `05_verifier_layout_probe.sql` | `21.3.0.0.0` | 2026-09-15 | #431 | As on 26ai |
| `05_verifier_layout_probe.sql` | `18.4.0.0.0` | 2026-09-15 | #431 | As on 26ai |
| `05_verifier_layout_probe.sql` | `11.2.0.2.0` | 2026-09-15 | #431 | No `T:`; the 10G verifier is in `USER$.PASSWORD` |
| `05_verifier_layout_probe.sql` | `19.3.0.0.0` | 2026-09-27 | #548 | As on 26ai |
| `05_verifier_layout_probe.sql` | `12.2.0.1.0` | 2026-09-29 | #572 | As on 26ai |
| `05_verifier_layout_probe.sql` | `19.32.0.0.0` | 2026-10-01 | #581 | As on 26ai. The wire step could not be seen: the DB system requires NNE |
| `06_verifier_reproduce.sql` | `23.26.2.0.0` | 2026-09-15 | #432 | Every `T:` reproduces client-side. A rollover window holds two verifiers, `T:` old and `t:` new. A 128-byte password is accepted |
| `06_verifier_reproduce.sql` | `21.3.0.0.0` | 2026-09-15 | #432 | As on 26ai, but 128 bytes is refused |
| `06_verifier_reproduce.sql` | `18.4.0.0.0` | 2026-09-15 | #432 | Every `T:` reproduces. No rollover |
| `06_verifier_reproduce.sql` | `19.3.0.0.0` | 2026-09-27 | #548 | Every `T:` reproduces. No rollover |
| `06_verifier_reproduce.sql` | `12.2.0.1.0` | 2026-09-29 | #572 | Every `T:` reproduces, from the password as converted to WE8DEC. No rollover |
| `06_verifier_reproduce.sql` | `19.32.0.0.0` | 2026-10-01 | #581 | Every `T:` reproduces, and a rollover window opens with `T:` old and `t:` new |
| `07_lock_and_rollover_probe.sql` | `23.26.2.0.0` | 2026-09-16 | #455 | `ACCOUNT UNLOCK` resets the failed-login count; `IDENTIFIED BY` unlocks nothing. `PASSWORD EXPIRE` on a rollover profile gives `EXPIRED & IN ROLLOVER`, and the old password still works |
| `07_lock_and_rollover_probe.sql` | `21.3.0.0.0` | 2026-09-26 | #461 | As on 26ai |
| `07_lock_and_rollover_probe.sql` | `19.3.0.0.0` | 2026-09-28 | #479 | Q1–Q5 as on 26ai. No rollover |
| `08_expire_password_probe.sql` | `23.26.2.0.0` | 2026-09-25 | #525 | A second `PASSWORD EXPIRE` is accepted silently; `EXPIRED(GRACE)` to `EXPIRED` is a real change; locks are untouched; expiry does not end a rollover window |
| `08_expire_password_probe.sql` | `19.3.0.0.0` | 2026-09-28 | #479 | E1–E5 as on 26ai, but the grace-period login sends `ORA-28002`. No rollover |
| `09_reset_from_expired_probe.sql` | `23.26.2.0.0` | 2026-09-26 | #529 | From `EXPIRED`, a reset opens no rollover window and every earlier password stops working |
| `09_reset_from_expired_probe.sql` | `21.3.0.0.0` | 2026-09-26 | #461 | As on 26ai |
| `09_reset_from_expired_probe.sql` | `19.3.0.0.0` | 2026-09-28 | #479 | No rollover; the script stops at section 0 |
| `10_awr_snapshot_probe.sql` | `19.32.0.0.0` | 2026-10-01 | #581 | The wrapped literal (C3) reaches `DBA_HIST_SQLTEXT`. C1, C2 and C4 do not |
| `11_proxy_connect_probe.sql` | `23.26.2.0.0` | 2026-10-01 | #459 | `ALTER USER` alone can grant `CONNECT THROUGH` and connect as the person. With no audit policy, nothing durable records it |
| `12_connection_encryption_probe.sql` | `23.26.2.0.0` | 2026-10-09 | #697 | Plain, NNE and TLS. `PUBLIC` reads the view; the account sees only its own SID |
| `12_connection_encryption_probe.sql` | `21.3.0.0.0` | 2026-10-09 | #697 | Plain, NNE and TLS. `PUBLIC` reads the view; it shows the account two SIDs |
| `12_connection_encryption_probe.sql` | `18.4.0.0.0` | 2026-10-09 | #697 | Plain, NNE and TLS. `PUBLIC` reads the view; it shows the account one or two SIDs |
| `12_connection_encryption_probe.sql` | `19.3.0.0.0` | 2026-10-09 | #697 | Plain, NNE and TLS. As on 21.3 |
| `12_connection_encryption_probe.sql` | `12.2.0.1.0` | 2026-10-09 | #697 | Plain, NNE and TLS. As on 21.3 |
| `12_connection_encryption_probe.sql` | `11.2.0.2.0` | 2026-10-09 | #697 | Plain and NNE. The adapter row reads `Oracle Advanced Security: AES256 encryption service adapter`; the view shows the account three SIDs. TLS did not run: `ORA-29106` on the wallet |
| `13_audit_coverage_probe.sql` | `23.26.2.0.0` | 2026-10-15 | #591 | Pure unified mode. A `BY` or `EXCEPT` list applies to the account that issues the statement, so a policy `BY` the person misses the DBA's `ALTER USER`. The account reads the policy views after `SYS` grants `READ`; `SYSTEM` cannot grant it. A common policy enabled in the root records nothing of local accounts' route, and records a common account's logon |
| `13_audit_coverage_probe.sql` | `23.26.2.0.0` | 2026-10-17 | #812 | `01_audit_policy.sql`'s policies, created in the root with no `CONTAINER` clause, record nothing in a PDB, not even the service account's `ALTER USER`. Created `CONTAINER = ALL`, they record common accounts in every container and no local account. Created in the PDB, they record every account's `ALTER USER` there. The logon policy records only the service account's failed logons, so no placement records a proxy logon. A common account reset in the root is recorded there. A common and a PDB policy may have one name |
| `99_uninstall.sql` | `23.26.2.0.0` | 2026-08-26 | — | `COMMON` and PDB installs, both `keep_audit` settings |
| `99_uninstall.sql` | `21.3.0.0.0` | 2026-09-08 | #380 | Both `keep_audit` settings |
| `99_uninstall.sql` | `18.4.0.0.0` | 2026-09-08 | #381 | As on 21.3 |
| `99_uninstall.sql` | `11.2.0.2.0` | 2026-09-08 | #382 | The account and its grants. There are no audit policies to keep |
| `99_uninstall.sql` | `19.3.0.0.0` | 2026-09-28 | #479 | PDB and `COMMON` installs |

## Other results

These came from the tool itself, from the test suite, or from a check by hand,
not from a script in `sql/oracle/`.

| Surface | Release | Date | Issue | Result |
|---|---|---|---|---|
| Longest password | `23.26.2.0.0` | 2026-09-08 | #383 | 128 bytes accepted |
| Longest password | `21.3.0.0.0`, `18.4.0.0.0`, `11.2.0.2.0` | 2026-09-08 | #383 | 30 bytes; 31 is `ORA-00972` |
| Longest password | `19.3.0.0.0` | 2026-09-27 | #548 | 30 bytes; 31 and 128 are `ORA-00972` |
| Longest password | `12.2.0.1.0` | 2026-09-29 | #572 | 30 bytes; 31 is `ORA-00972` |
| Longest password | `19.32.0.0.0` | 2026-10-01 | #581 | 30 bytes accepted; 128 is refused. 31 was not tried |
| `DBA_USERS.PASSWORD_CHANGE_DATE` | `23.26.2.0.0`, `21.3.0.0.0` | 2026-09-08 | #386 | Present, and equal to `SYS.USER$.PTIME` |
| `DBA_USERS.PASSWORD_CHANGE_DATE` | `18.4.0.0.0`, `11.2.0.2.0` | 2026-09-08 | #386 | Absent (`ORA-00904`); `PTIME` moves with a rotation. 18.4 has `ORACLE_MAINTAINED` (#381) |
| `DBA_USERS.PASSWORD_CHANGE_DATE` | `19.24.0.0.0` | 2026-09-17 | #386 | Present. Only its presence was checked |
| `DBA_USERS.PASSWORD_CHANGE_DATE` | `12.2.0.1.0` | 2026-09-29 | #572 | Absent; the suite's `PTIME` fallback test passes |
| Grace-period login warning | `23.26.2.0.0` | 2026-09-02 | #322 | `ORA-28098` or `ORA-28011`, on a login that succeeds |
| Grace-period login warning | `21.3.0.0.0` | 2026-09-26 | #461 | `ORA-28002`, seen in SQL\*Plus, not through the driver |
| Grace-period login warning | `19.3.0.0.0` | 2026-09-28 | #479 | `ORA-28002` |
| Thin mode | `19.32.0.0.0` | 2026-10-01 | #575 | Refused with `DPY-3001`: the shipped `sqlnet.ora` requires NNE |
| Thin mode | `23.26.3.3.0` | 2026-10-01 | #575 | Connects over TCPS; no NNE is negotiated |
| Wallet failures over mutual TLS | `23.26.3.3.0` | 2026-09-28 | #472 | Missing, misplaced or unreadable: `ORA-28759`. Damaged: `ORA-28768`. Each took 64 s, because the alias sets `retry_count=20`. Instant Client 23.26.3.0.0, on Windows only |
| The tool end to end | `23.26.3.3.0` | 2026-09-28 | #479 | Install, a rotation, a rollback and a rollover window, with a vault-held password. `docs/maintainer-environments.md` §6 has the setup |
| The tool end to end | `19.32.0.0.0` | 2026-10-01 | #581 | As the least-privilege service account, including a rollover window. `docs/maintainer-environments.md` §5 has the setup and the run |

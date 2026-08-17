# sopuli-dba
Tool for automating and simplifying database credential management and other common DBA tasks

---

## Release gate 2 — does a rotation leak the password into Oracle?

`ALTER USER` takes the password as a literal; DDL cannot use bind variables. So the
secret is on the wire and in the parser on every rotation, and the only question is
what Oracle retains afterwards. That is measured, not reasoned about:
[`sql/oracle/02_password_leak_probe.sql`](sql/oracle/02_password_leak_probe.sql)
plants a distinct canary per execution path and sweeps every source a statement's
text can come to rest in. Procedure and reading rules:
[`docs/design/04-testing.md`](docs/design/04-testing.md) §6 gate 2.

### Results

**Oracle AI Database 26ai Free 23.26.2.0.0** — `CDB$ROOT` and `FREEPDB1`, rotations
issued by a common service account holding `ALTER USER` and nothing else
(`isdba=FALSE`, so unified auditing's mandatory SYSDBA capture is not the thing
doing the recording).

| Surface | Result |
|---|---|
| `V$SQL`, `V$SQLAREA`, `V$SQLSTATS`, `GV$SQL` — the `CREATE/ALTER USER` statement | **clean.** No cursor for the DDL is retained at all. Not masked, absent — client-issued and `EXECUTE IMMEDIATE`'d alike |
| `V$OPEN_CURSOR`, `V$DIAG_ALERT_EXT` | clean |
| Unified audit `SQL_TEXT` — `UNIFIED_AUDIT_TRAIL` **and** `AUDSYS.AUD$UNIFIED` | **clean.** Masked to `IDENTIFIED BY *` at write time, in the base table as well as the view |
| **An anonymous PL/SQL block carrying the password as a literal** | **LEAK.** Retained verbatim in `V$SQL`, `V$SQLAREA`, `V$SQLSTATS`, `GV$SQL` and `V$DB_OBJECT_CACHE`. Oracle's protection is keyed to the `CREATE/ALTER USER` statement; a block that merely contains one is an ordinary block |
| Bind values in SQL predicates — `V$SQL_BIND_CAPTURE` | **retained in clear**, sampled at hard parse. Not reachable from rotation, since DDL takes no binds |
| Traditional audit (`DBA_AUDIT_TRAIL`, `SYS.AUD$`, `DBA_COMMON_AUDIT_TRAIL`) | not applicable. The views still exist but are empty: both `AUDIT USER` and `AUDIT ALTER USER` raise `ORA-46401`, traditional auditing being desupported. Recorded as inconclusive, not clean |

The two leaks are what the tool is built around: invariants 13 and 14 in
`CLAUDE.md` forbid a PL/SQL wrapper and a bound password respectively, and tier 0
asserts both against the generated statement text.

### What this table does not cover

Read the scope before treating the result as broad. It is one version, one
mechanism, and the on-disk surfaces are entirely unchecked.

| Open | Why it matters |
|---|---|
| **19c** unrun | the version most sites actually run, and not redistributable as a container — needs a hand-built image or real OCI |
| **11.2** unrun | **the one where a different answer is genuinely plausible rather than surprising.** It predates most of Oracle's redaction work and has no unified auditing at all, so both the masking result and the "no cursor retained" result have to be re-established from scratch |
| **Trace files** — `grep` of `Diag Trace` unreported | the probe emits the command (§7); nobody has run it. Assume not redacted |
| **OS audit files** — `grep` of `audit_file_dest` unreported | the SYSDBA path. Matters most on 11.2, where `AUDIT_SYS_OPERATIONS` writes statement text to files no query reaches |
| **AWR / `DBA_HIST_SQLTEXT`** untested | reported `pop=y` in one run and `pop=n` in the next, and no snapshot was taken before the sweep. Untested, not clean |
| **Self-rotation** (`IDENTIFIED BY … REPLACE …`, probe §6a) not exercised | exercises no privilege, so privilege auditing can miss it while statement auditing catches it — worth knowing before the docs claim rotations are audited |
| **`IDENTIFIED BY VALUES`** (probe §6b) not exercised | would be the restore-from-verifier path if one is ever added. Oracle masks a password; whether it masks a verifier is a separate question |

Findings are written up in
[`docs/design/02-oracle-privileges.md`](docs/design/02-oracle-privileges.md) §4.

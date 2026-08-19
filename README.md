# sopuli-dba
Tool for automating and simplifying database credential management and other common DBA tasks

---

## Installing

**Install the backends you have, not all of them.** Every client that exists to
reach one vendor — a secret store or a database — is an install extra. The base
install carries the CLI, the config layer and nothing that opens a socket, so
`pip install sopuli-dba` gives you a tool that can read and validate a config and
reach nothing.

| Install | Adds | Use it when |
|---|---|---|
| `pip install sopuli-dba` | nothing beyond the CLI and the config layer | you only need `config validate`, `config show`, `target list` — in an editor, a linter, a pre-commit hook |
| `pip install "sopuli-dba[oracle]"` | `python-oracledb` | you manage Oracle databases |
| `pip install "sopuli-dba[hashicorp]"` | the HashiCorp Vault client | your secrets are in HashiCorp Vault |
| `pip install "sopuli-dba[oci]"` | the OCI SDK | your secrets are in OCI Vault / Secrets |
| `pip install "sopuli-dba[all]"` | every extra | CI, or you genuinely have all of them |

A working install is one store plus one database. For most sites that is:

```
pip install "sopuli-dba[oracle,hashicorp]"      # or [oracle,oci]
```

`sopuli-dba[all]` exists for CI and the test matrix. It is deliberately not the
recommended line: a tool that handles credentials should be able to answer "what
is in its dependency tree" with the vendors you actually use, and vendor SDKs
carry version constraints — the OCI SDK pins `cryptography` and `pyOpenSSL` —
that a site with no OCI should not inherit.

**Oracle needs Instant Client too.** `sopuli-dba[oracle]` installs the driver;
thick mode is required for Native Network Encryption, so Instant Client is a
runtime prerequisite on every platform. `sopuli doctor` checks for it, and
reports which backends are installed against which your config declares.

If a config names a backend you have not installed, `config validate` warns and
still passes — the file is fine, the install is incomplete — and the first
command that needs to connect stops with the install line to fix it:

```
$ sopuli creds check --application acme
error: vault "oci-prod" declares type "oci", but that backend is not installed
       install it with:  pip install "sopuli-dba[oci]"
```

The rule and what it costs: [ADR-006](docs/decisions/adr-006-optional-dependencies.md).

> **Status: pre-implementation.** The extras above are declared in
> `pyproject.toml` and the registry behind them resolves a backend on first use.
> **`hashicorp` is the one backend that exists** — KV v2 and KV v1, with token,
> AppRole, Kubernetes and userpass auth — and `sopuli lock status` is so far the
> only command that reaches it. `oci`, `file` and `keyring` are accepted in a
> config and report that this build has no module for them. Nothing is on PyPI
> yet.

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

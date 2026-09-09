<p align="center">
  <img src="docs/assets/sopuli-dba-logo.png" alt="sopuli-dba logo" width="200">
</p>

# sopuli-dba

**Change a database account's password without anybody having to know it.**

sopuli-dba is a command-line tool for database administrators. It keeps the
password of a database account in a *vault* — a server built to store secrets and
hand them out to the applications that need them — and then makes the database
agree with what the vault holds. The vault is always the source of truth for a
password. The database never is.

Oracle is the first database it supports, and it is designed so other database
products can be added later.

---

## Status

**Pre-alpha. Do not point this at a production database yet.**

| | |
|---|---|
| **Version** | 0.58.0, and nothing is published to PyPI yet — you install from a git checkout |
| **Databases** | Oracle only. Tested against Oracle AI Database 26ai Free 23.26.2.0.0 |
| **Vaults** | HashiCorp Vault only. `oci`, `file` and `keyring` can be written in a config file, but this build has no code for them and says so when you try |
| **What works** | Thirteen commands, including a full password rotation from end to end. [`docs/local-testing.md`](docs/local-testing.md) is the by-hand map of exactly what this build can be made to do |

If you want the full design picture — every decision, and every question that is
still open — start at [`docs/README.md`](docs/README.md).

*(Build-status and coverage badges will go here once the repository is public and
CI runs on it. There are none yet, and a fake one would be worse than none.)*

---

## What this is not

- It **does not create or drop database accounts.** The account has to exist
  already.
- It **does not manage grants, roles or privileges.** That is a separate feature,
  and it is not built.
- It **never reads a password back out of a database.** Oracle does not store
  passwords in a form anything can read back, and the tool does not try.
- It **is not a general-purpose secrets manager.** It writes one specific kind of
  document to your vault — a database account's password — and reads that same
  document back. Everything else in your vault is none of its business.

---

## Installing

**Install the backends you have, not all of them.** Every client that exists to
reach one vendor — a secret store or a database — is an install extra. The base
install carries the CLI, the config layer and nothing that opens a socket, so
`pip install sopuli-dba` gives you a tool that can read and validate a config and
reach nothing.

An *extra* is Python packaging's word for an optional part of a package. You ask
for one by putting its name in square brackets after the package name, and `pip`
— the program that installs Python packages — then installs the extra
dependencies that part needs.

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

If a config names a backend this machine cannot serve — the client is not
installed, or this build has no module for that backend yet — `config validate`
warns and still passes. The file is fine; the install is incomplete. The first
command that needs to connect stops instead, with the install line where there
is one to give:

```
$ sopuli creds check --application acme
error: vault "oci-prod" declares type "oci", but that backend is not installed
       install it with:  pip install "sopuli-dba[oci]"
```

The rule and what it costs: [ADR-006](docs/decisions/adr-006-optional-dependencies.md).

> **Status: pre-alpha.** The extras above are declared in `pyproject.toml` and
> the registry behind them resolves a backend on first use.
> **`hashicorp` is the one secret store that exists** — KV v2 and KV v1, with
> token, AppRole, Kubernetes and userpass auth. Every command that reaches a
> store reaches that one. `oci`, `file` and `keyring` are accepted in a config
> and report that this build has no module for them. Nothing is on PyPI yet.

Step-by-step, including your first config file:
[`docs/getting-started.md`](docs/getting-started.md).

---

## Is this safe to use?

The honest answer for today is in the status box above: it is pre-alpha, so treat
it as something to try against a test database first. What follows is what the
tool does to protect you once you do trust it with something that matters.

**You can always see a change before it happens.** Every command that changes
something takes `--dry-run`, which prints exactly what the command would do and
then stops without doing it. No setting can take `--dry-run` away from you. It is
the one thing that is never blocked, because a preview is how you work out
whether to say yes.

**You can require somebody to say yes.** In the config file you can list the
environments — `prod`, `uat`, whatever you call them — that a change may not
enter without an explicit confirmation. That is the `safety.confirm_environments`
setting. When a run reaches one of those environments it asks first. There is no
built-in list: if you write nothing, nothing prompts.

**A safety setting can only be made stricter, never looser.** A config file can
be layered — a site-wide file, then a team's file, then a command-line flag.
For most settings the most specific layer wins. For the safety settings it is the
*safest* layer that wins, wherever it sits. So a subteam's file cannot switch off
a rule the site-wide file turned on. It can only add more.

**A scheduled check will not lock the account out.** To find out whether the
vault's password still works, the tool has to try logging in — and a failed login
counts against Oracle's failed-login limit. So before it tries, it reads how many
failed attempts the account has already collected. If one more attempt would come
too close to the limit, it does not try. It reports that it could not check, and
says why. Checking is never worth locking out the account you were checking on.

**Passwords do not reach your logs.** A password is held in a wrapper type whose
text form is `***`, so printing one prints the mask, in ordinary output and in a
crash traceback alike. There is exactly one command that prints a real password
(`policy sample --reveal`, which shows you what your password rules produce), and
it refuses to run when output is machine-readable JSON — because JSON output is
what gets shipped to a log collector.

**A password containing a double quote is rejected, not escaped.** Oracle's
quoted identifiers have no escape sequence for `"`, so there is no correct way to
send one. The tool refuses the password rather than mangling it.

The longer version, for deciding whether to trust this with a production
credential: [`docs/security-model.md`](docs/security-model.md).
To report a security problem privately: [SECURITY.md](SECURITY.md).

---

## Quick example

Three commands take a password from nowhere to in-use. This is a real run against
a local Oracle container, trimmed to the lines that matter.

```bash
# 1. Draw a new random password and park it in the vault as `pending`.
#    Nothing is sent to any database by this command.
sopuli --config sopuli.yaml creds generate

# 2. Set that password on the database, check it works by logging in,
#    and only then promote it in the vault from `pending` to `current`.
sopuli --config sopuli.yaml creds apply

# 3. Ask whether the vault's password still works. Run this from a scheduler.
sopuli --config sopuli.yaml creds check
```

Step 1 says what it staged, and reminds you that no database has changed yet:

```
ACCOUNT        SECRET                 RESULT
acme_app_user  vault-dev:acme/dev/db  staged v1

1 staged; no database was changed -- run `sopuli creds apply` to use them
```

Step 2 shows the order that makes this safe. `SOURCE pending` is the password it
took from the vault; `1 promoted to current` happened only after the database
accepted it:

```
ACCOUNT        TARGET    SECRET                 SOURCE
acme_app_user  free-pdb  vault-dev:acme/dev/db  pending

ACCOUNT        TARGET    STATE    DETAIL
acme_app_user  free-pdb  IN_SYNC  changed and verified by login

1 changed, 1 promoted to `current`
```

Step 3 answers one question per account, and exits 0 because there is nothing
wrong:

```
ACCOUNT        TARGET    STATE    DETAIL
acme_app_user  free-pdb  IN_SYNC  vault v2 verified by login

all 1 in sync
```

Running step 2 a second time changes nothing and says so — which is what makes
the tool safe to run from a scheduler.

The full walkthroughs, with the config file these commands read and what to do
when an answer is not `IN_SYNC`, are in
[`docs/scenarios/`](docs/scenarios/).

---

## Learn more

| Read this | If you want to |
|---|---|
| [docs/getting-started.md](docs/getting-started.md) | install the tool, write your first config file, and run one command safely |
| [docs/scenarios/rotate-and-sync.md](docs/scenarios/rotate-and-sync.md) | follow one password rotation from start to finish |
| [docs/scenarios/kubernetes-eso.md](docs/scenarios/kubernetes-eso.md) | let applications running in Kubernetes pick up the new password automatically |
| [examples/](examples/) | three complete config files, commented, from smallest to safety-hardened |
| [docs/security-model.md](docs/security-model.md) | decide whether to trust this with a production credential |
| [docs/local-testing.md](docs/local-testing.md) | exercise every command by hand, including the failures worth causing on purpose |
| [CONTRIBUTING.md](CONTRIBUTING.md) | send a change |
| [SECURITY.md](SECURITY.md) | report a security problem privately |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | know what is expected of everyone taking part |
| [docs/README.md](docs/README.md) | read the full design: principles, configuration reference, Oracle privileges, JSON output contract, testing strategy, and every decision record |

Licensed under [Apache 2.0](LICENSE).

---

## Release gate 2 — does a rotation leak the password into Oracle?

The rest of this file is evidence rather than instructions. It is here because
the answer is the reason several of the tool's design rules exist.

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

**21c XE 21.3.0.0.0 and 18c XE 18.4.0.0.0** agree with it row for row (#380,
#381), and add the half 26ai cannot answer at all: traditional auditing masks the
password too — `DBA_AUDIT_TRAIL`, `SYS.AUD$` and `DBA_COMMON_AUDIT_TRAIL` all
clean, with `SQL_TEXT` populated, so the clean is a result rather than an empty
column. The off-database greps in the probe's §7 were run for the first time on
both, with `AUDIT_SYS_OPERATIONS = TRUE`: no canary in `audit_file_dest`, the
trace directory, the listener log or the client history.

### 11g XE 11.2.0.2.0 — the one that differs

Non-CDB, rotations issued by a service account holding `ALTER USER` and nothing
else (#382, 2026-09-08). Traditional auditing is clean exactly as on 18c and 21c,
and the off-database greps are clean across 835 `adump` files. One row is not.

| Surface | Result |
|---|---|
| `V$SQLSTATS` — the `ALTER USER` statement itself | **LEAK.** Retained verbatim: `ALTER USER … IDENTIFIED BY "<password>"`, the plain client-issued statement, no wrapper. `V$SQL`, `V$SQLAREA` and `GV$SQL` hold no cursor for it, as on every other release — `V$SQLSTATS` keeps its own copy and it outlives the cursor. **Confirmed with the tool rather than only the probe**: a real `sopuli creds apply` on 2026-09-09 put its own generated password there, read back out of the vault to find it |
| Who can read it | a dictionary reader (`SELECT ANY DICTIONARY`, `SELECT_CATALOG_ROLE`, `DBA`). **Not the tool's own service account**, which gets `ORA-00942` holding exactly the documented grants |
| How long it lasts | a window, not a record. It ages out with the shared pool — at a full `V$SQLSTATS` a canary survived 2,000 further distinct statements and was gone by 3,000 — and `ALTER SYSTEM FLUSH SHARED_POOL` clears it at once (measured twice, 2026-09-09, #387) |
| AWR on 11.2 | **unanswerable on XE.** Two snapshots taken, `DBA_HIST_SQLTEXT` and `DBA_HIST_SQLSTAT` both empty of everything: XE ships `control_management_pack_access = NONE`. Untested, not clean |

Invariant 13's *reasoning* is untouched — wrapping the DDL is worse everywhere —
but its conclusion, that issuing the DDL directly keeps the password out of the
shared pool, is release-dependent. **The tool documents this and does not warn or
refuse**, decided in #387: `docs/design/02-oracle-privileges.md` §8 P8 has the
decision and the two declined alternatives, and
[`docs/security-model.md`](docs/security-model.md) §5 is what an operator is told.

### What this table does not cover

Read the scope before treating the result as broad. It is one version, one
mechanism, and the on-disk surfaces are entirely unchecked.

| Open | Why it matters |
|---|---|
| **19c** unrun | the version most sites actually run, and not redistributable as a container — needs a hand-built image or real OCI. It is now what two open questions turn on: the password byte limit (#383) and whether 11.2's `V$SQLSTATS` retention reaches it (#387) |
| **12.1 and 12.2** unrun, and 19c above | so **the boundary is unknown**. 11.2 retains the DDL text and 18.4 does not; nothing measures where between them that changed, and no freely pullable image exists for any release in the gap. Read the 11.2 result as *11.2 does*, never as *everything older does* |
| **Trace files** — `grep` of `Diag Trace` unreported | the probe emits the command (§7); nobody has run it. Assume not redacted |
| **OS audit files** — `grep` of `audit_file_dest`, run on 21c, 18c and 11.2 only | clean on all three, including 835 files on 11.2, which is the release it mattered most on. Not yet run on 26ai, and not yet run once with `svc_user = sys` |
| **AWR / `DBA_HIST_SQLTEXT`** untested | on 26ai it reported `pop=y` in one run and `pop=n` in the next with no snapshot taken; on 11g XE snapshots *were* taken and captured nothing at all, the Diagnostics Pack being off in XE. Needs a licensed EE. Untested, not clean |
| **Self-rotation** (`IDENTIFIED BY … REPLACE …`, probe §6a) not exercised | exercises no privilege, so privilege auditing can miss it while statement auditing catches it — worth knowing before the docs claim rotations are audited |
| **`IDENTIFIED BY VALUES`** (probe §6b) not exercised | would be the restore-from-verifier path if one is ever added. Oracle masks a password; whether it masks a verifier is a separate question |

Findings are written up in
[`docs/design/02-oracle-privileges.md`](docs/design/02-oracle-privileges.md) §4.

# sopuli-dba — Oracle privileges and grants

Depends on: `00-principles.md`, `../use-cases/uc-01-app-credential-sync.md`

This document says what the service account is granted, what it must not be
granted, and what the tool checks before it changes an account. The SQL is in
`sql/oracle/`. Which release each script ran on, and what it showed, is in
[`../measurements.md`](../measurements.md).

---

## 1. The model: direct `ALTER USER`

The tool connects as an account that holds the `ALTER USER` system privilege.
That is the whole privilege model. Installing it is a handful of grants.

### Why not something narrower

Oracle has nothing narrower. `ALTER USER` has no object scope: there is no
`GRANT ALTER USER ON ORDERS_APP`. An account that can change one user's password
can change every user's password in that container, `SYS` included.

The 23 codebase (23ai, renamed 26ai) adds schema privileges. They do not cover
`ALTER USER` either: §2.1 has the test.

The alternative is a definer-rights package. The package owns the privilege and
offers only whitelisted operations. It was rejected on cost:

- the package must be installed, versioned and upgraded in every PDB, because one
  common package in the root would itself need reach over the whole CDB;
- a server-side whitelist must be kept in step with the tool's own config;
- a tool and a package at different versions is a new kind of failure;
- all of this constrains an operator who already holds `SYSDBA`.

sopuli-dba helps a DBA do what they already do by hand, faster and more
reliably. A DBA who rotates a password with `sqlplus` has more power than the
tool is given. An in-database framework that hands them part of what they
already have adds work and no protection.

[`../decisions/adr-001-privilege-model.md`](../decisions/adr-001-privilege-model.md)
records the decision. §6 describes the one case where the package could be
worth its cost.

---

## 2. The grants

### 2.1 Schema privileges do not cover `ALTER USER` (P7)

`GRANT ALTER USER ON SCHEMA` is rejected with `ORA-00990: missing or invalid
privilege` on 26ai 23.26.2.0.0. So the direct grant in §1 is the model on every
release.

> **"23ai" and "26ai" are one product.** Oracle renamed Oracle Database 23ai to
> Oracle AI Database 26ai in October 2025, with no change to the architecture
> or the API. In `23.26.2.0.0` the **23** is the codebase and the **26** is the
> year of the release update. In this document "23ai+" means "codebase 23 and
> later". [`04-testing.md`](04-testing.md) §2 has the numbering.

The 23 codebase can grant a privilege on one schema:

```sql
GRANT SELECT ANY TABLE ON SCHEMA hr TO analyst;
```

This limits an `ANY` privilege to the objects of one schema, including objects
created later. A grant of that shape would let the tool hold a narrow privilege.
It does not extend to `ALTER USER`. These statements ran in one session, and
each comment shows the result:

```sql
-- CONTROL: a documented schema privilege, on the same database, same session
GRANT SELECT ANY TABLE ON SCHEMA orders_app TO sopuli_svc;
-- succeeded; appears in DBA_SCHEMA_PRIVS as SELECT ANY TABLE

GRANT ALTER USER ON SCHEMA orders_app TO sopuli_svc;
--                 *
-- ORA-00990: missing or invalid privilege

GRANT ALTER ANY USER ON SCHEMA orders_app TO sopuli_svc;   -- ORA-00990
GRANT ALTER USER ON SCHEMA orders_app TO sopuli_svc CONTAINER=CURRENT;  -- ORA-00990

SELECT privilege FROM dba_schema_privs WHERE grantee = 'SOPULI_SVC';
-- SELECT ANY TABLE   <- only the control; nothing from the ALTER USER attempts
```

**The control makes the result conclusive.** `ORA-00990` alone could mean that
schema privileges are missing, unlicensed or unsupported on this release. The
control grant succeeded in the same session, so the feature works, and the
refusal is specific to `ALTER USER`. `DBA_SCHEMA_PRIVS` shows that nothing from
the refused grants was partly applied.

Two reasons make the result general, not one observation:

1. Schema privileges cover objects inside a schema: tables, views, sequences,
   procedures. `ALTER USER` acts on an account, which is not an object in a
   schema. Oracle's documented examples are all of the first kind:
   `SELECT/INSERT/UPDATE/DELETE ANY TABLE`, `SELECT ANY SEQUENCE`,
   `EXECUTE ANY PROCEDURE`.
2. `ALTER USER` is not an `ANY` privilege, so it has no schema-scoped syntax.
   `ORA-00990` says exactly that.

Oracle lists the privileges that schema privileges exclude in *Configuring
Privilege and Role Authorization*.

**Consequences.** Nothing in §1 changes. Schema privileges offer no narrower
grant, so they are no reason to revisit the decision against a definer-rights
package. Its one remaining trigger is the unattended runner in §6
([ADR-001](../decisions/adr-001-privilege-model.md)). And no server-side
setting limits which accounts the service account can reach, so §4's client-side
guardrails do all of that work.

The probe stays as a regression check. A later release could add `ALTER USER`
to the schema privileges, and that would matter (`04-testing.md` §5).

### Non-CDB, or a single PDB with local users

This is the grant set for a local service account:

```sql
CREATE USER sopuli_svc IDENTIFIED BY "…" DEFAULT TABLESPACE users;

GRANT CREATE SESSION TO sopuli_svc;
GRANT ALTER USER     TO sopuli_svc;

-- dictionary reads
GRANT SELECT ON SYS.DBA_USERS      TO sopuli_svc;
GRANT SELECT ON SYS.DBA_PROFILES   TO sopuli_svc;
GRANT SELECT ON SYS.DBA_ROLE_PRIVS TO sopuli_svc;
GRANT SELECT ON SYS.DBA_ROLES      TO sopuli_svc;
GRANT SELECT ON SYS.V_$DATABASE    TO sopuli_svc;
GRANT SELECT ON SYS.V_$INSTANCE    TO sopuli_svc;
```

`SELECT_CATALOG_ROLE` covers all six dictionary reads in one grant (read from
`DBA_TAB_PRIVS` on 26ai 23.26.2.0.0). You may use it instead. It reaches the
`DBA_*` and `V$` views, but not base tables such as `SYS.USER$`. The explicit
list is the default because a privilege review can read it at a glance.

**Run these as `SYS`, not as `SYSTEM`.** On 26ai 23.26.2.0.0, every
`GRANT SELECT ON SYS.…` above fails with `ORA-01031: insufficient privileges`
when `SYSTEM` issues it, while `CREATE USER` and the two system privileges
succeed. The result is a service account that connects and can rotate, but
reads nothing. Its capability probes then report every capability absent, which
looks like a broken probe. Nothing in the statements says who must issue them.

Each dictionary read has a consumer, and a missing grant is never read as an
empty answer.

- **`DBA_ROLE_PRIVS`** is what guardrail 4 reads (§4). Check 4 refuses an
  account that holds `DBA`, `PDB_DBA`, `CDB_DBA` or `AUDIT_ADMIN`, and this view
  is the only place to see another account's roles. An empty role set means "this
  account holds none of them", which passes the check. So a missing grant would
  turn the check into a silent pass. The driver refuses to describe an account
  whose roles it cannot read (`RolesUnreadableError`) and names this grant. A
  capability probe that cannot be answered follows the same rule: it raises, and
  does not report the capability absent. Only a refused grant (`ORA-00942`,
  `ORA-01031`, `ORA-41900`) is reported this way, with the server's code and
  message. Any other failure is reported as itself, because a grant does not fix
  a dropped connection.
- **`DBA_USERS`** follows the same rule. Here "no row" means the account does not
  exist, so an unreadable view would report `ACCOUNT_MISSING` for every account.
  Instead `creds status` reports `ERROR` with category `authorization`,
  `ORA-00942` and a hint that names this grant, and exits 1. `ORA-00904` is the
  one code that narrows the query instead, because a missing column is how the
  driver finds the shape of a release's `DBA_USERS`.
- **`DBA_ROLES`** is not read by UC-1. It is the only place that says whether a
  role exists, and UC-2 §2 depends on that. A `role:` predicate that names no
  role is a misspelling and is refused. A predicate that names a real role that
  nobody holds is a true empty answer.

  An install that lacks this grant still works for everything except role
  predicates. `role_lookup` is a probed capability (P1), so `account list`
  refuses a role predicate at plan time, with exit 5, naming the capability, the
  target and this grant. It is not one of the required reads that
  `doctor --check-privileges` audits (§3). The pre-flight in `creds apply` and
  `creds rotate` blocks on a missing required read, and making this one required
  would stop older installs from rotating, for a grant that only a UC-2 listing
  uses. `doctor` shows it as the capability `role_lookup`, absent.

**A role-granted `ALTER USER` reads as absent.** The capability `common_users` is
probed through `USER_SYS_PRIVS`, which shows direct grants only. An account that
holds `ALTER USER` through a role, as `SYSTEM` does, reports the capability
absent and is refused at plan time. The grant above is direct, so a correctly
installed service account never hits this. The other views are worse:

- `DBA_SYS_PRIVS` is not readable with this grant set at all.
- `SESSION_PRIVS` sees role-derived privileges but has no `COMMON` column, so it
  would report a local `ALTER USER` as enough. An over-reported capability fails
  in the middle of a rotation instead of before it.

### CDB with common users — one grant covers every container

This is the grant set for a common service account, run in `CDB$ROOT`:

```sql
-- in CDB$ROOT
CREATE USER c##sopuli_svc IDENTIFIED BY "…" CONTAINER=ALL;

GRANT CREATE SESSION TO c##sopuli_svc CONTAINER=ALL;
GRANT ALTER USER     TO c##sopuli_svc CONTAINER=ALL;
GRANT SELECT ON SYS.DBA_USERS      TO c##sopuli_svc CONTAINER=ALL;
GRANT SELECT ON SYS.DBA_PROFILES   TO c##sopuli_svc CONTAINER=ALL;
GRANT SELECT ON SYS.DBA_ROLE_PRIVS TO c##sopuli_svc CONTAINER=ALL;
GRANT SELECT ON SYS.DBA_ROLES      TO c##sopuli_svc CONTAINER=ALL;
GRANT SELECT ON SYS.V_$DATABASE  TO c##sopuli_svc CONTAINER=ALL;
GRANT SELECT ON SYS.V_$INSTANCE  TO c##sopuli_svc CONTAINER=ALL;
GRANT SELECT ON SYS.V_$PDBS      TO c##sopuli_svc;   -- root only
```

One set of statements covers every PDB, and a new PDB inherits it. A package
would need an install in each PDB, repeated on every plug-in and clone.

The tool needs no `SET CONTAINER`. It opens one connection per target, to the
PDB's own service, and never switches container inside a session. So a target
that cannot be reached fails on its own, and the grant set stays small.
`00_install.sql` can still grant it (`grant_set_container`) for a site whose
other tools need it.

A `CONTAINER=ALL` clause on `ALTER USER` is legal only in a session in
`CDB$ROOT`. §4 *Statement construction* says when the tool adds it.

### Choosing common vs per-PDB local

The tool supports both. The choice is about how far one stolen credential
reaches, not about what the tool can do.

| | one common `C##SOPULI_SVC` | a local `SOPULI_SVC` per PDB |
|---|---|---|
| Install effort | one grant set | N grant sets |
| New PDB | inherits automatically | needs provisioning |
| Reach of one stolen credential | every PDB in the CDB | that one PDB |
| Credentials to store in the vault | one | N |
| Fits | one team owns the whole CDB | PDBs owned by different teams or tenants |

Use a common user when one DBA team owns the CDB, which is the usual case. Use
local users when different teams own the PDBs. The isolation is then worth the
extra provisioning, and the config already models each target on its own.
[P1](../decisions/log.md#p1) records the decision.

### Autonomous Database — PDB mode, as `ADMIN`, and no `SYS.USER$`

An Autonomous Database (ADB) is a PDB with a generated container name, a long
prefix and the database name, such as `G…_ACMEDB`. Its most privileged account
is `ADMIN`, which is not `SYSDBA`.

**`00_install.sql` runs unchanged on ADB in PDB mode, as `ADMIN`.** The mode
check accepts the generated name, every grant in the base set succeeds, and the
report's over-grant query is empty. `doctor --check-privileges` then reports
only the optional grants as missing. Use ADB's tablespace, `DATA`, as the third
argument. [`../measurements.md`](../measurements.md) has the run.

ADB takes some things away for good:

- **No `SYS.USER$`.** `ADMIN` gets `ORA-00942` on it, so `grant_user_dollar=Y`
  has nothing to grant. So ADB has no `check --method hash`, no `LCOUNT` guard,
  and `doctor` reports `offline_verify_available: false`. The driver detects ADB
  from `SYS_CONTEXT('USERENV','CLOUD_SERVICE')`, which needs no grant. On ADB it
  names the workload, such as `OLTP`. Elsewhere it is NULL, or `ORA-02003` on
  11.2, and the driver reads both as "not ADB". The driver's refusal says that
  no account on ADB can read `SYS.USER$`, and does not advise a grant. An
  explicit `check --method hash` or `both` is refused in those words, at plan
  time. `PASSWORD_CHANGE_DATE` exists on ADB, so the `PTIME` fallback is not
  needed.
- **`DEFAULT` is ADB's own profile**, and every created user gets it. It sets
  `PASSWORD_VERIFY_FUNCTION CLOUD_VERIFY_FUNCTION`, `PASSWORD_REUSE_MAX 4`,
  `PASSWORD_REUSE_TIME 1` and `PASSWORD_ROLLOVER_TIME 0`. The tool reports the
  verify function as `SOPULI-W016`. It refused a ten-character password with
  `ORA-28003` and accepted forty characters. So the 30-character limit in ADB's
  rules for `ADMIN`'s own password did not apply to a created user. The reuse
  limits make UC-1 §8's rollback fail with `ORA-28007`, which the rollback
  reports as `SOPULI-W028`. On ADB the way back is a rollover window, from a
  profile that `ADMIN` can create.
- **No retention result either way.** `02_password_leak_probe.sql` is gate 2's
  evidence (`04-testing.md` §6). It sweeps `V$SQLSTATS`, the OS audit files and
  the trace directory as `SYSDBA`. ADB has no `SYSDBA` and no OS access, so the
  sweep cannot run there. Its `SYSDBA` positions do not apply to ADB; they are
  not merely unrun. Do not carry 26ai Free's result over to ADB because both are
  26ai.
- **`db_version` is the base release**, `23.0.0.0.0`, because it comes from
  `V$INSTANCE.VERSION`. Since 18c that column holds only the base release: 19.3
  reports `19.0.0.0.0`, with `VERSION_FULL` `19.3.0.0.0`. `doctor` shows it as
  `scope.db_version`. Only the password-limit floor in
  `driver/oracle/limits.py` uses it to decide anything, and that compares the
  first two parts only.
- **Not tried:** whether `ADMIN` can grant `SELECT ON SYS.V_$PWFILE_USERS` (§4
  check 3), and whether `01_audit_policy.sql` runs on ADB, where unified auditing
  is on by default.

### `check`'s default method, and the optional `SYS.USER$` grant

`check` uses `--method login` by default, always. It never needs `SYS.USER$`.
The default path is a login attempt plus UC-1 §7's mitigations: never retry,
reset on success, and report `ACCOUNT_STATUS`. All of it runs on the base grant
set. [P2](../decisions/log.md#p2) records the decision.

`SELECT ON SYS.USER$` is optional. `sql/oracle/00_install.sql` grants it only
when `grant_user_dollar` is `Y`, and the default is `N`:

```sql
GRANT SELECT ON SYS.USER$ TO sopuli_svc;   -- or c##sopuli_svc CONTAINER=ALL
```

When the grant is present, the tool probes it as a capability at plan time
(invariant 3) and uses it for three things:

- **The `LCOUNT` guard.** It refuses a login attempt within `--lockout-margin`
  of the account's `FAILED_LOGIN_ATTEMPTS` limit (UC-1 §7 mitigation 2). This is
  the one place where the grant changes behaviour. Without it, `--method login`
  still runs on UC-1 §7's other mitigations (1, 3 and 6), and `check` says
  plainly that the guard is absent.
- **`check --method hash`.** See below.
- **The password change date, where `DBA_USERS` has no column for it.**
  `DBA_USERS.PASSWORD_CHANGE_DATE` exists from 19c, and is absent on 18c, 12.2
  and 11.2. Where it is absent, `SELECT PTIME FROM SYS.USER$` gives the same
  value; it equals the column to the second on the releases that have both. The
  value is for display only: `creds status`'s `DB_PW_CHANGED` and the run
  document's `password_age_days`. The driver never reads `PTIME` where the column
  exists. Without the grant the date is absent, and `SOPULI-W021` says so.

**Why the grant is optional.** It exposes every password verifier in the
database. An account that holds `ALTER USER` can already set any password, so
reading the verifiers adds little to what it can do in the database. But
verifiers can be attacked offline: a stolen copy is useful to an attacker who
never touches the database again. A site makes that trade, not the tool.

Whether to recommend the grant, and whether a narrower grant exists, is not
decided (open: #124). The Data Pump metadata views `SYS.KU$_USER_VIEW` and
`SYS.KU$_USER_BASE_VIEW` are granted to `PUBLIC`. A blog post says they show
`LCOUNT` under `SELECT_CATALOG_ROLE` alone, and hide `SPARE4` unless the session
also holds `EXP_FULL_DATABASE`. If that is true, a site could enable the `LCOUNT`
guard without exposing verifiers (unverified: lcount-grant). It comes from a blog
post, not from Oracle's documentation, so it must be measured before
`00_install.sql` recommends it.

#### Hash mode

`check --method hash` compares the vault's password with the account's stored
`T:` (12C, PBKDF2-SHA512) verifier. The tool regenerates the verifier
client-side. Reading the stored one needs `SELECT ON SYS.USER$`, because it is in
`SPARE4`. So hash mode needs the grant, although the derivation does not.

The layout, the derivation and the rules for a missing verifier are measured.
[`../measurements.md`](../measurements.md) lists the releases, and 12.1 is not
among them. `docs/README.md` §*Verify before implementing* has the entry
`t-verifier`.

**The layout.** `SPARE4` is `S:<60 hex>;T:<160 hex>` on every release measured
from 12.2 on, and `S:<60 hex>` alone on 11g. No release has an `H:` in `SPARE4`.
11g's 10G verifier is in `USER$.PASSWORD`.

- `T:` is a 64-byte digest followed by a 16-byte salt.
- `S:` is a 20-byte digest followed by a 10-byte salt.

The salt offsets are measured, not assumed: the `AUTH_VFR_DATA` that a traced
logon receives equals those trailing bytes. `SPARE4` does not store the
iteration count. The server sends `AUTH_PBKDF2_VGEN_COUNT` = 4096 at logon. On
19.32.0.0.0 the logon could not be read, because the DB system requires Native
Network Encryption (NNE) and the client trace shows no `AUTH_` key. There the
count is shown only by the reproduction succeeding with 4096.

Every `ALTER USER` draws a fresh salt, even one that sets the same password. So
a stored verifier can be compared only by regenerating it from its own salt.
`sql/oracle/05_verifier_layout_probe.sql` has the field table and the
normalisation notes.

**The derivation.** The stored `T:` digest regenerates byte for byte from the
password:

```
salt   = the last 16 bytes of the T: blob (its 32 trailing hex characters)
inter  = PBKDF2-HMAC-SHA512(password_utf8, salt || b"AUTH_PBKDF2_SPEEDY_KEY", 4096, 64)
digest = SHA-512(inter || salt)                # the 64-byte / 128-hex head of the blob
```

- The password is the raw UTF-8, with no case folding and no normalisation. A
  non-ASCII password reproduces unchanged.
- "The password" is the one the database holds, after conversion to its
  character set. On 12.2's WE8DEC image, `Ω` does not survive the conversion:
  the account's password became `…¿9`, and the verifier reproduced from the
  UTF-8 of that string. On AL32UTF8 the two strings are the same. The tool
  cannot reach this case, because `limits.py` measures a set with unmapped
  characters, such as WE8DEC, in ASCII. But hash mode must not assume that the
  vault's string is the one the database hashed.
- A 128-byte password reproduces on 26ai. Releases before the 23 codebase reject
  more than 30 bytes at the DDL (unverified: password-byte-limit).
- 4096 is the count the server sends at logon, not a value in `SPARE4`. A
  release that sends another count would not reproduce. That is why each
  release must be measured, not assumed.

`sql/oracle/06_verifier_reproduce.py` is the reference derivation, and
`06_verifier_reproduce.sql` is the probe.

**The rollover window holds two 12C verifiers.** During a gradual rollover,
`SPARE4` holds `T:` for the previous password and `t:` for the current one.
They share one salt, and a `V:` marker that is not a verifier sits beside them.
After the window, `T:` is the new password. Releases from 21c have the feature,
and 19c has it from 19.12; 18c, 19.3 and 12.2 do not. So `check` reports
`ROLLOVER_ACTIVE` when an account has two 12C verifiers. `--include-previous`
tells the current one from the previous one by which prefix the vault value
reproduces, never by drift.

**Accounts with several verifiers, and accounts with no `T:`.** The comparison
uses the 12C `T:` verifier and nothing else.

- An account can hold three verifiers (`PASSWORD_VERSIONS = 10G 11G 12C`). The
  10G verifier is then in `SYS.USER$.PASSWORD`, a different column, and `SPARE4`
  is the same `S:;T:` pair. `T:` is at the same offset and reproduces byte for
  byte. So older verifiers change nothing about reading or deriving `T:`.
- 10G and 11G are never a fallback. 10G is unsalted, case-insensitive DES, and
  11G (`S:`) is SHA-1. Comparing either would report a weaker check than
  `--method login` already gives.
- When an account has no `T:`, hash mode has nothing to compare. This is 11g,
  where `PASSWORD_VERSIONS` is `10G 11G` and `SPARE4` is `S:` alone, or any
  account whose `PASSWORD_VERSIONS` lacks `12C`. Hash mode then fails at plan
  time and names the capability and the target (invariant 4). It never fails
  with a generic error mid-run, and never falls back to a weaker verifier. For
  the same reason, `both` never falls back to `login` alone.
- **The gate is a capability, not a version** (invariant 3, P1): a readable `T:`
  verifier exists for this account. That is two conditions. The session-level
  grant (`OFFLINE_VERIFY`) makes `SPARE4` readable at all. The account's
  `PASSWORD_VERSIONS` says whether it has a `12C` verifier to read. The driver
  queries both and never infers them from the release: a server from 12.1 on can
  still hold an account with no `12C` verifier.
- The 23 codebase has dropped the 10G verifier. Even at
  `ALLOWED_LOGON_VERSION_SERVER = 8`, a new 26ai account is `11G 12C`. So 10G and
  12C occur together only on 12.1 to 19c. Nothing depends on this; it is written
  here so that nobody assumes 10G handling on the newest targets.
- On 19.3 and 12.2, a new account is `11G 12C` by default, with `S:` and `T:` in
  `SPARE4` and no 10G hash. With `ALLOWED_LOGON_VERSION_SERVER = 11` it is
  `10G 11G 12C`, and the 10G hash is in `SYS.USER$.PASSWORD`. So 10G and 12C
  occur together on 19c only where a site lowered the logon version.

To make a three-verifier account for a maintainer re-run, add
`SQLNET.ALLOWED_LOGON_VERSION_SERVER = 8` to the server's `sqlnet.ora`
(`$ORACLE_HOME/network/admin/sqlnet.ora`), then run `CREATE USER … IDENTIFIED BY
…`. `PASSWORD_VERSIONS` then reads `10G 11G 12C`. Restore the file afterwards.
It is not a public probe, because it changes the server's configuration.

- On 19.3 and 12.2 no restart was needed: a new `SYSDBA` session read the
  edited file.
- On 18c the recipe included a restart. Whether the restart was needed was not
  tested.
- On 26ai the recipe does not produce a 10G verifier.
- On 12.2's image, the server's `sqlnet.ora` is in `$ORACLE_HOME/admin/ORCLCDB`,
  its `TNS_ADMIN`.

**What the driver does.** `verify_password(method="hash")` reads `SPARE4`, binds
the account name and nothing else, and compares in
`src/sopuli/driver/oracle/verifier.py`. It refuses, and names the target, when:

- the session cannot read `SYS.USER$` (`offline_verify`);
- the account has no `12C` verifier (`verifier_12c`);
- a `T:` or `t:` token is not the measured 160 hex characters
  (`verifier_12c_format`);
- the database character set cannot hold the vault value exactly
  (`verifier_charset`). The server then hashed a converted copy, as in the WE8DEC
  case above, and a mismatch would be false drift.

During a rollover window it reports which of the two verifiers the password
reproduced. `verify_password(method="both")` compares first, and logs in only
when the comparison passed, so a mismatch uses up no login attempts.
`require_verifier` makes every one of those refusals without comparing
anything, so a caller can refuse at plan time. On ADB the `offline_verify`
refusal says that no account there can read `SYS.USER$`, and does not advise a
grant.

`creds check --method hash|both` asks every target `require_verifier` before it
checks any account. So each refusal is exit 5 at plan time, naming the target,
with the capability in `error.target_capability` and the account in the hint.

If the derivation failed on a release not yet read, both non-login modes would
leave the CLI. `both` is a login plus this comparison, and a `both` that
quietly fell back to `login` would report a stronger check than it ran. The
default, `login` with the optional `LCOUNT` guard, does not depend on hash mode.

**Invariant 14** applies to any server-side form: the verifier is never bound
into a SQL predicate. The comparison here is entirely client-side.

### §4 check 3, and the optional `V$PWFILE_USERS` grant

Guardrail 3 refuses an account that is in the password file. Only
`V$PWFILE_USERS` shows that. The grant is optional, not part of the default
install: decided in #296.

```sql
GRANT SELECT ON SYS.V_$PWFILE_USERS TO sopuli_svc;   -- or c##sopuli_svc CONTAINER=ALL
```

Without the grant, a service account with the base grants gets
`ORA-00942: table or view "SYS"."V_$PWFILE_USERS" does not exist`. That code is
in `ABSENT_CODES`, so the driver answers `None` ("unknown"), never `False`. With
the grant, the driver can read the view from inside a PDB with no further
privilege.

The grant has two consumers:

- guardrail 3, which asks about a target account;
- §3's `SYSDBA` and `SYSOPER` rows in `doctor --check-privileges`, which ask
  about the session's own user.

Neither reads the other's answer.

**Why it stays optional.** Checks 2 and 4 also catch most of the accounts check
3 catches. Making every service account need this grant for the rest is a poor
trade. But the rest exists. An account granted `SYSDBA` inside a PDB appears in
`V$PWFILE_USERS` with its own `CON_ID`, visible from the PDB and from
`CDB$ROOT`. It can still read `ORACLE_MAINTAINED = 'N'` and hold no roles. Such a
site-created account passes checks 2, 4 and 5, and only check 3 refuses it.

**Without the grant, check 3 does not silently pass.** The run reports
`SOPULI-W018`, one warning per target, naming this grant, and carries on.
Refusing on an unread check would refuse every change on every estate installed
as documented. §4 has the reasoning. This is a `creds apply` against a PDB
service account with exactly the base grants:

```
ACCOUNT        TARGET       STATE    DETAIL
acme_web_user  appdb-alpha  IN_SYNC  the vault's password is already accepted; nothing to change

nothing changed

1 note:
  appdb-alpha: guardrail check `password_file` did not run: could not establish whether the account is in the password file -- GRANT SELECT ON SYS.V_$PWFILE_USERS to the service account to enable it (ACME_WEB_USER)
```

With the grant taken, the same run prints no note. With `SYSDBA` granted to
`ACME_WEB_USER` and the view readable, check 3 refuses the account:

```
ACCOUNT        TARGET       STATE    DETAIL
acme_web_user  appdb-alpha  SKIPPED  the account is in the password file
```

**An administrative account can still be on a rollover profile.** 21c makes the
opposite look true. With a profile that sets `PASSWORD_ROLLOVER_TIME`, and a user
on that profile:

| | 26ai 23.26.2.0.0 | 21c XE 21.3.0.0.0 |
|---|---|---|
| `GRANT SYSDBA` to a user on that profile | ok | `ORA-28227: Gradual password rollover is not supported for administrative users.` |
| `GRANT SYSOPER` likewise | ok | `ORA-28227` |
| `GRANT DBA` (the role) likewise | ok | ok |
| `GRANT SYSDBA` first, *then* `ALTER USER ... PROFILE` onto it | ok | **ok** |

The last row matters. 21c enforces the rule on the `GRANT` and not on the
`ALTER USER`, so two statements reach the state it refuses to create directly.
So "in the password file, therefore no rollover window" is not a safe inference
on any release, and the tool does not draw it. Guardrail 3 refuses such an
account outright, so the answer is the same either way. A test fixture must set
the profile limit itself:
`tests/driver/test_oracle_accounts.py::test_a_pdb_local_account_granted_sysdba_appears_in_the_password_file`
is one that does.

### Whether the connection is encrypted, and the optional `V$SESSION_CONNECT_INFO` grant

The tool sends a new password in `ALTER USER ... IDENTIFIED BY "..."`. On an
unencrypted connection the password crosses the network in clear, so `doctor`
reports whether each connection is encrypted, and by what. Two reads answer it,
and neither needs a grant on any release measured
(`sql/oracle/12_connection_encryption_probe.sql`, [measurements](../measurements.md)):

- `SYS_CONTEXT('USERENV', 'NETWORK_PROTOCOL')` is `tcps` on a TLS connection
  and `tcp` on a plain one, with or without NNE.
- `V$SESSION_CONNECT_INFO`, filtered on the session's own SID, has one
  `NETWORK_SERVICE_BANNER` row per network service. With NNE in use, one row
  names the algorithm: `AES256 Encryption service adapter for Linux`, or on
  11.2.0.2.0 `Oracle Advanced Security: AES256 encryption service adapter`. A
  row `Encryption service for Linux` is there on every connection, encrypted or
  not, so it says nothing. On every release measured except 26ai the view also
  shows other sessions, which is why the read filters on the SID.

`PUBLIC` holds `READ` on the view (`SELECT` on 11.2.0.2.0) on every release
measured. The grant matters only where a site has revoked that:

```sql
GRANT SELECT ON SYS.V_$SESSION_CONNECT_INFO TO sopuli_svc;   -- or c##sopuli_svc CONTAINER=ALL
```

`00_install.sql` takes it as parameter 7, `grant_connect_info`, off by default.
Without the view, a plain TCP connection's encryption is `unknown`, never
`none`: the driver reads `ORA-00942`, `ORA-41900` or `ORA-01031` as "could not
look", and `doctor` names this grant. Any other failure reading either value is
`unknown` too, with the server's code and message in the hint. That includes
`ORA-00904`, which no grant fixes. So is a session that finds no row of its own
in the view, since every connection measured has at least one. Nothing branches
on this answer, so it never stops a run, unlike a failed capability probe. A connection over any transport other than TCP or
TCPS is also `unknown`, because none has been measured.

---

## 3. What must not be granted

| Not granted | Why |
|---|---|
| `SELECT ANY DICTIONARY` | includes `SYS.USER$` and everything else. If hash mode is wanted, grant `SELECT ON SYS.USER$` alone |
| `DBA`, `PDB_DBA`, `CDB_DBA` | the tool needs `ALTER USER`, not a role that carries a hundred other privileges |
| `SYSDBA` / `SYSOPER` | no operation of the tool needs them |
| `ALTER PROFILE` | no credential-sync verb edits a profile (UC-1 Q4). A profile is shared, so editing one reaches accounts nobody selected, and the config's account whitelist (invariant 5) cannot limit that. The tool reports the DDL that enables password rollover instead, and `doctor --check-privileges` reports this privilege if the service account holds it. Whether UC-4 may create and alter profiles is its own question; it would be a privilege of a principal UC-4 defines, not of this grant set |
| `CREATE USER` / `DROP USER` | creating and dropping accounts is outside UC-1 |
| `ALTER SYSTEM`, `GRANT ANY *`, `BECOME USER` | no operation needs them |
| `EXECUTE ON DBMS_LOCK` | `00-principles.md` P5's advisory lock is in the vault, not the database (UC-1 Q2). A session-scoped database lock does not solve the problem: a stalled run's session is still alive, so its lock blocks others while its plan goes stale. A fencing token, checked again before every change, does solve it, and it needs nothing from the database |

**The service account needs no grant to detect an application container.** `V$PDBS` is
granted in the root only and `CDB_PDBS` nowhere, so the three views that carry
`APPLICATION_ROOT` or `APPLICATION_PDB` all give `ORA-00942` to a PDB-mode
service account. `SYS_CONTEXT('USERENV','IS_APPLICATION_ROOT')` and
`'IS_APPLICATION_PDB'` answer the same question with no grant, as `CON_NAME`
does. `sql/oracle/03_app_container_probe.sql` measured this. A release before
12.2 lacks those attributes and raises `ORA-02003` instead of returning NULL.
The driver reads that as "not an application container", as it reads the same
code from `CON_NAME` on 11.2 as "not a CDB".

`sopuli doctor --check-privileges` reports what the service account holds, and
names anything on the list above. Over-granting is the common result of
debugging a permissions problem in a hurry. The tool notices it and says so.

**It warns and never fails** ([P5](../decisions/log.md#p5)). It reports; it does
not enforce. §4's guardrails are the enforcement, and they are a different thing.

**It reports both sides**, because they are two questions. §3's list is what the
account holds and should not. §2's list is what it needs and may lack. An
account can be in both states at once, which is what a half-finished debugging
session leaves. Reporting a missing grant at connect time means that a missing
`SELECT ON DBA_PROFILES` shows up as an install problem, not three commands later
as an unanswered limit lookup that names a view.

**A dictionary grant is checked by reading the view, not a grant table.** The
alternative was `USER_TAB_PRIVS` plus `ROLE_TAB_PRIVS`. Reading the view is
better for three reasons:

- a role-derived grant needs no special handling, because a view you can read
  is readable however the grant arrived;
- a grant row is not access: the view may have been dropped or renamed;
- the mechanism already exists and is measured. `ABSENT_CODES` treats
  `ORA-00942`, `ORA-01031` and `ORA-41900` as "no".

The cost is one round trip per documented grant, which is why the audit runs
only with the flag.

**`V_$PDBS` is required in the root only**, where §2 grants it. Elsewhere it is
in neither the held list nor the missing list. "Not required here" and "required
and missing" are two different answers, and the report keeps them apart.

**The audit is self-inspection.** The obvious implementation reads
`DBA_SYS_PRIVS` for this grantee, and it does not work: an account with exactly
§2's grants gets `ORA-00942` from it, so a correctly installed tool would report
nothing at all. That answer looks like good news and means "I could not look".
So the audit asks views that need no grant:

| View | Answers | Grant needed |
|---|---|---|
| `SESSION_PRIVS` | every system privilege in force, **role-derived included** | none |
| `USER_SYS_PRIVS` | the same account's *direct* grants, with `COMMON`, the column `SESSION_PRIVS` lacks | none |
| `DBA_ROLE_PRIVS` | granted roles, traversed with `CONNECT BY NOCYCLE` | §2 grants it |

**Roles are read as granted, not as enabled.** So the audit does not use
`SESSION_ROLES`, although it needs no grant. It shows the roles enabled in this
session, and a non-default `DBA` grant is one `SET ROLE` away. The audit asks
what an account could become, so a privilege one statement away counts as held.

**Some rows cannot be audited.** The report names them on every run, not only
when something is wrong. A caveat that appears only when something is wrong
cannot be quoted as evidence that nothing was.

| Row | Why not | What it would take |
|---|---|---|
| `EXECUTE ON DBMS_LOCK` | an **object** privilege; the three views above carry system privileges and roles | `USER_TAB_PRIVS` and `ROLE_TAB_PRIVS`, and the second does not fit the nested-role traversal. That is a design question, not a query |
| `SYSDBA` / `SYSOPER` | `V$PWFILE_USERS` is not in §2's default grant set | the optional grant that §2 describes for check 3. With it, the audit reads these rows |

If `DBA_ROLE_PRIVS` is refused at runtime, the three role rows join this list.
The report never merges "I looked and found nothing" with "I could not look".

**With the optional grant, the password-file rows are read.** On 26ai
23.26.2.0.0, against a PDB-local service account with §2's grants plus that
one:

- **The two rows are answered separately**, because the view has a column for
  each. Granted and revoked one at a time, all four combinations read back
  correctly. One "in the password file" answer would report `SYSOPER` because of
  a `SYSDBA` row.
- **A held row is an `over_granted` finding like any other.** It is the only
  finding that is neither a system privilege nor a role, but §3's list is one
  list, and a reader must not need to know which view each row came from.
- **Taking the grant does not make `doctor` report an over-grant.**
  `over_granted` reads system privileges and roles, and this is an object
  privilege.

**An absent answer does not make the audit partial.** `unreadable` means the
report cannot be taken at face value. An estate that declined an optional grant
is installed as documented. So the two rows go to the unaudited list with a
remedy: the operator may enable the grant. The audit's own output names no
database, so the `GRANT` text comes from the driver, as guardrail 3's remedy
does.

`EXECUTE ON DBMS_LOCK` cannot be audited, and no grant changes that.

The three states look like this. Each is an excerpt from `doctor
--check-privileges` against a PDB service account on 26ai Free 23.26.2.0.0,
created by `sql/oracle/00_install.sql` in `PDB` mode. The default install:

```
TARGET    REACHABLE  SCOPE  CONTAINER  OPEN MODE   CAPABILITIES
free-pdb  yes        pdb    FREEPDB1   READ WRITE  6
  free-pdb: not checked, and not visible from here: EXECUTE ON DBMS_LOCK, SYSDBA, SYSOPER
  free-pdb: SYSDBA and SYSOPER need SELECT on V$PWFILE_USERS, which 02-oracle-privileges.md §2 leaves optional: GRANT SELECT ON SYS.V_$PWFILE_USERS to the service account to audit them
```

The same account with the grant taken, holding neither privilege. One row is
left unchecked, and there is nothing to suggest about it:

```
TARGET    REACHABLE  SCOPE  CONTAINER  OPEN MODE   CAPABILITIES
free-pdb  yes        pdb    FREEPDB1   READ WRITE  6
  free-pdb: not checked, and not visible from here: EXECUTE ON DBMS_LOCK
```

The same account granted `SYSDBA`. The finding is reported and, under P5, is
not fatal: the run exits 0.

```
TARGET    REACHABLE  SCOPE  CONTAINER  OPEN MODE   CAPABILITIES
free-pdb  yes        pdb    FREEPDB1   READ WRITE  6
  free-pdb: not checked, and not visible from here: EXECUTE ON DBMS_LOCK
  free-pdb: over-granted, and the tool needs none of it: SYSDBA
```

---

## 4. Client-side guardrails

The account-safety checks are in the tool, not in the database. They are not a
security boundary: a stolen service credential bypasses them. They protect
against typos, and against a config change that reaches more accounts than
intended. An operator with `SYSDBA` never had more than that from them.

Before any `ALTER USER`, the tool refuses when the target account:

1. is not among the config's **declared accounts**. An account is declared by
   `accounts:` inline, by an `applications:` entry, or, for a personal account,
   by a name or a predicate in `personal_accounts:` (H1). The config is the
   whitelist. Note the predicate form: an implementation written from this item
   without it would refuse every personal account declared by predicate;
2. has `DBA_USERS.ORACLE_MAINTAINED = 'Y'`. This covers `SYS`, `SYSTEM`,
   `DBSNMP`, `GSMADMIN_INTERNAL` and the rest, with no hand-kept list to go
   stale;
3. appears in `V$PWFILE_USERS`. The grant is optional, so on most estates this
   check has no input, and the run says so instead of passing (§2);
4. holds `DBA`, `PDB_DBA`, `CDB_DBA` or `AUDIT_ADMIN`;
5. is on a literal deny list. This is for 11.2, where `ORACLE_MAINTAINED` does
   not exist.

`--force` overrides checks 2 to 5, for a DBA who deliberately manages an unusual
account ([P3](../decisions/log.md#p3)). The audit event and the JSON output
record the override. It never overrides check 1, because acting on an account
the config does not declare would make the tool's own audit trail meaningless.

`src/sopuli/driver/guardrails.py` implements the checks. It reviews; it does
not decide, as the error mapping does. `creds apply` and `creds rotate` call it.
These rules apply:

- **What a refusal does depends on how the account was selected.** The rule is
  the same for every mutating verb.
  - An account the operator **named**, as in `--account DBSNMP`, fails the run
    and is reported as `ERROR`. The operator asked for something the tool will
    not do. Skipping it quietly would report success for work nobody did.
  - An account that only **fell inside** a broad selection is `SKIPPED` with its
    reason, and the run does the rest of its work. Refusing 200 rotations
    because the 47th account is `ORACLE_MAINTAINED` would do more harm than the
    mistake the guardrail caught.

  The estate ends in the same state either way; only the exit code differs. The
  command layer knows how each account was selected, and the driver does not, so
  the command layer applies this rule.

  **Naming a target, group or application is not naming an account**, however
  few accounts it resolves to. Otherwise a safety rule would behave differently
  depending on how many accounts an estate has today. A named account refused by
  check 1 is not told to use `--force`, because no flag overrides check 1. It is
  told to declare the account.
- **The review runs before the first login, not just before the statement.** An
  account the tool will not touch must not use up a login attempt against its
  lockout counter. UC-1 §7 makes this argument for every login. It costs no extra
  round trip: `describe_user` has already read every fact the checks need.
- **Check 5 is used only where check 2 has no answer.** Where the database
  reports `ORACLE_MAINTAINED`, that answer wins, even when it says "no" about a
  name on the list. Sites do name an account `SCOTT`. If the tool's own list
  overruled the database's description of itself, it would be a second
  whitelist that nobody agreed to. The list is long rather than exact. A missing
  entry means one old release misses one check. An extra entry means an audited
  `--force`. The first cost is the larger one.
- **Check 1 compares names case-folded.** `01-configuration.md` writes
  `acme_web_user`, and Oracle stores `ACME_WEB_USER`, because it upper-cases an
  unquoted identifier. An exact comparison would refuse every correctly declared
  account. The remaining risk is an estate that holds both `ACME_WEB_USER` and a
  quoted `"acme_web_user"`. The tool does not handle that case.
- **Check 1 uses the unfiltered config.** A selector narrows what a run touches.
  It cannot remove an account from the declared set (invariant 5). So the
  whitelist is the file's declared set, not this run's part of it.

  For accounts declared by name, check 1 cannot fire from a mutating verb,
  because the run's accounts come from the same file. It runs anyway, because
  that is a property of today's call graph, not of the guardrail. For a personal
  account declared by a profile or a role predicate (H1), the declared set is a
  query result. Check 1 is then the only thing between a `GRANT` somebody made in
  the database and an account the tool will change. It is not dead code.
- **A refused account is `SKIPPED`, and the exit code does not count it.** It is
  neither a success nor a failure: it has left the run's scope, like an account
  the config never declared. If it counted as unconfirmed, the run would exit 4,
  which means "some of it worked, run `apply --repair`". But the repair would
  skip the same account again, every night. A run of nothing but skips exits 0,
  as an empty selection does.
- **A skipped account is dropped from its document's promotion**, from the gate
  as well as from the write. Promoting it would move its `pending` to `current`
  while its database still holds the old password, which invariant 7 forbids.
  Letting it block the gate would mean one account that is always refused, such
  as one with a `DBA` grant nobody will remove, blocks promotion for every other
  account at that secret path. Dropping it avoids both: its `pending` stays
  staged, and the other accounts are promoted.
- **The override is a structured field.** `--force` fills
  `results[].overridden` with the check and what it observed. A consumer can
  then branch on "this account was forced" instead of searching a sentence. The
  field is absent where nothing was overridden: it records overrides, not intent.

**Check 3 has three answers: refused, permitted, or could not establish.** The
third is a `Caveat`. It refuses nothing, `--force` does not affect it, and the
run reports it as `SOPULI-W018`, naming the optional grant that would settle it.
Without this third answer, "I could not look" would read as "I looked and found
nothing", which `privileges.py` already refuses to do for the same view.

- **It does not refuse.** The estate that cannot answer check 3 is the correctly
  installed one, so a refusal would mean the tool changes nothing anywhere.
  `--preflight` handles a privilege audit the service account cannot read the
  same way: a `warning` finding, and the run goes on.
- **It is one entry per target and check, not per account.** What could not be
  read is a grant on a database. An estate with forty accounts on one target
  would otherwise be told the same fact forty times. `creds generate` groups the
  constraints it cannot check in the same way, for the same reason.
- **It is printed, not only serialised.** The emitter prints the command's text,
  not the JSON document. A warning only in the JSON would not reach somebody who
  ran the command by hand.

An account the guardrails refused adds no caveat. The tool did not touch it, so
an unread check changed nothing about it.

**`sopuli lock break` uses the same flag.** It refuses a lock that has not
expired, and `--force` breaks it anyway. Both uses are an audited override of a
guardrail that is asked about one thing at one moment: this account now, or this
lock now. A safety setting is different: it is resolved from layers and only
ratchets toward safe. Both overrides are reported the same way. The lock
override is visible in the run document as `lock.broken[].expired: false`.

**`DBSNMP` is the case `--force` exists for.** Rotating its password is ordinary
DBA work, and it is `ORACLE_MAINTAINED = 'Y'`, so check 2 refuses it. Without an
override, the rotation still happens, but in SQL\*Plus, where nothing records
it. An audited override is the better outcome.

**It takes two deliberate acts.** `--force` alone does not rotate `DBSNMP`,
because check 1 still applies. The account must also be declared: in
`accounts:`, in an `applications:` entry, or, for a personal account, through
`personal_accounts:` (H1). That is invariant 5: the config is the whitelist, and
a flag cannot extend it. It keeps "an unusual account, managed deliberately"
apart from "a typo that was forced through".

**`--force` never overrides a safety setting.** `readonly`, `max_targets`,
`confirm_environments` and `dry_run` only ratchet toward safe, and no
higher-precedence source may relax them (invariant 10, `00-principles.md` P3).
`--force` is a higher-precedence source, so if it could relax one of them, the
ratchet would not hold. The code keeps the two apart by structure: **`--force` is
not a setting.** It is not in `src/sopuli/settings/registry.py`, so it has no
merge policy and no layer. It is an argument to §4's account checks, and to the
lock refusal, and to nothing else.

### Statement construction

DDL takes literals, so the password cannot be a bind variable. The tool builds
this statement:

```sql
ALTER USER "ORDERS_APP" IDENTIFIED BY "<generated>";
```

- **Passwords containing `"` are rejected, not escaped.** An Oracle quoted
  identifier has no escape for a double quote, so refusing is the only safe
  handling. The default character set, `alnum_safe`, excludes it.
- Control characters and `CHR(0)` are rejected. The byte length is checked
  against the target's limit, 30 or 128 bytes, in the database character set.
- The username in the statement is the spelling read back from `DBA_USERS` after
  validation, never the raw string from the config.
- `CONTAINER=ALL` is added only when the session is in `CDB$ROOT` and the account
  is a `C##` common user. Otherwise the tool refuses, instead of letting Oracle
  return a confusing error.
- **An application root is refused.** There, a statement with no container
  clause already applies to the whole application container. The tool's usual
  path reads "no `C##` prefix, so local, so no clause", and that would rotate
  the password across the application container. No property of the name tells
  the cases apart, because `C##` names cannot exist in an application container.
- **An application PDB takes the ordinary path.** A local account there is
  ordinary. Oracle itself refuses an application-common account (`ORA-65066`,
  mapped), so a guardrail is not needed and would also block the working case.
  `sql/oracle/03_app_container_probe.sql` measured both; UC-1 §6.2 has the rest.
- **`ALTER USER "ORDERS_APP" ACCOUNT UNLOCK` is built the same way** (UC-1 §5's
  first attribute): the same identifier rules and container clause, issued
  directly, never wrapped. It carries no secret. The habit keeps the next
  statement safe, and the next statement carries a password. It needs no grant
  beyond `ALTER USER`.
- **`ALTER USER "ORDERS_APP" PROFILE "ORDERS_PROF"` is built the same way** (UC-1
  §5's second attribute). The profile name follows the same identifier rules, and
  is the spelling read back from `DBA_PROFILES`, for the same reason as the
  username.
- **The tool never issues `ALTER PROFILE`.** The credential-sync verbs assign a
  profile and never edit one, because a profile is shared and editing it reaches
  accounts nobody selected (§3, UC-1 Q4). `alter_profile_ddl()` in
  `driver/oracle/rollover.py` builds the statement only as text in a message,
  for an operator to run. If UC-4 needs to author profiles, it needs a grant
  this set does not include, and a principal of its own.
- **The built statement redacts itself.** It carries a password, so it is as
  sensitive as one. Every string form of it is `ALTER USER "X" IDENTIFIED BY
  ***`, which is also what `--dry-run` prints. The plaintext is reachable only
  through a method named `reveal()`, like the one on `Secret`, so a search for
  one method name finds every place that can get plaintext.

The statement layer refuses a password on its own terms. That is a different act
from `passwords.check` finding a policy violation. UC-1 §4 lets an operator waive
the policy check with `--no-policy-check`. Nothing waives the statement layer's
refusal. A rule that can be turned off and a rule that cannot are two rules,
even where they reject the same character. Merging them would let
`--no-policy-check` turn off invariant 11.

### Where the password text can surface

`sql/oracle/02_password_leak_probe.sql` plants a distinct canary for each
execution path and searches 24 source and column pairs for it. For each column
it also reports whether the column holds any rows. A clean result on an empty
column is labelled inconclusive, not counted as a pass.

**Each result holds only for the releases it names.** None is a general
statement about Oracle. [`../measurements.md`](../measurements.md) lists every
run: the release, the positions, the date and the issue. The table below gives
the findings.

**11.2 differs on the most important row.** On 11.2.0.2.0, `V$SQLSTATS` keeps
the text of the plain `ALTER USER` that sopuli issues. Every later release
measured keeps nothing. So the change is after 11.2 and no later than 12.2.0.1.0
(unverified: ddl-text-versions). 12.1 has no image that can be pulled, and has
not been run. Read the 11.2 result as "11.2 keeps it", not as "every release
before 12.2 keeps it".

This was confirmed with sopuli's own statement, not just the probe's. A real
`creds apply` ran against 11g XE through the usual path: Instant Client,
`SOPULI_SVC` with exactly §2's grants, and a password that sopuli generated,
wrote to Vault and showed nobody. This is the search for that password, read
back from the vault, with the password masked by the search script, not by
Oracle:

```
V$SQLSTATS.sql_text           *** LEAK *** 1
V$SQL.sql_text                clean        0
V$SQLAREA.sql_text            clean        0
GV$SQL.sql_fulltext           clean        0
V$DB_OBJECT_CACHE.name        clean        0
DBA_AUDIT_TRAIL.sql_text      clean        0
--- V$SQLSTATS row, password masked by this script:
    ALTER USER "ACME_APP_USER" IDENTIFIED BY "<the password sopuli generated>"
```

**The tool does nothing about it, and the documents say so**
([P8](../decisions/log.md#p8)). The alternatives were a runtime warning on 11.2,
or refusing to rotate there. Refusing would have reversed
[`00-principles.md`](00-principles.md) D7. The decision rests on one fact: **the
kept text is a window, not a record.** On 11g XE 11.2.0.2.0:

| Question | Result |
|---|---|
| Can the service account read it? | **No.** `SOPULI_SVC` gets `ORA-00942` from `V$SQLSTATS` and `V$SQL` alike. A user who can read the dictionary can read it |
| Does `V$SQLSTATS` age the row out? | **Yes.** With `V$SQLSTATS` at its limit on this instance (about 5,590 rows), a planted canary survived 2,000 more distinct statements and was gone by 3,000. Planted into a nearly empty pool it survived longer, and 20,000 removed it |
| Does `ALTER SYSTEM FLUSH SHARED_POOL` clear it? | **Yes, at once.** The canary was present before and absent after, both times. This is the operator's remedy, not the tool's: `ALTER SYSTEM` is a privilege §3 refuses, and flushing a production shared pool affects performance, which nobody should get as a side effect of a rotation |
| Does it reach AWR? | **Not known** (unverified: ddl-text-awr). XE ships `control_management_pack_access = NONE`, so AWR snapshots on 11g XE capture nothing. Answering this needs an 11.2 Enterprise Edition with the Diagnostics Pack |

So on 11.2, a user who can read the dictionary can read the password while the
shared pool keeps the entry, and one statement removes it. That is less than "the
password is on disk" and more than nothing. So it is documented, not warned
about and not refused. `../security-model.md` §5 is what an operator is told.

The longest password a release accepts is the other per-release question
(unverified: password-byte-limit). The tool applies 128 bytes from the 23
codebase and 30 bytes below it, which agrees with every release measured.

This table gives the findings. "Every release measured" means the releases
[`../measurements.md`](../measurements.md) lists for the script that answers the
row.

| Surface | Finding | Action |
|---|---|---|
| `V$SQL`, `V$SQLAREA`, `V$SQLSTATS`, `GV$SQL`: the `CREATE/ALTER USER` statement itself | **No cursor for the DDL exists**, from 12.2.0.1.0 on: not masked, absent. This holds for DDL sent by a client and for DDL run with `EXECUTE IMMEDIATE`. **11.2.0.2.0 differs**: `V$SQL` has no cursor, but `V$SQLSTATS` keeps its own copy of the text, and the copy outlives the cursor. 12.1 is not measured | 11.2: documented, not warned about and not refused (P8, above). Elsewhere: nothing to do. Re-run the probe on every release claimed as supported: this is retention behaviour, not a documented guarantee, and that is how 11.2 came to differ |
| **An anonymous PL/SQL block that carries the password as a literal** | **leaks in full** into `V$SQL`, `V$SQLAREA`, `V$SQLSTATS`, `GV$SQL` and `V$DB_OBJECT_CACHE`. Oracle's protection is keyed to the `CREATE/ALTER USER` statement. A block that contains one is an ordinary block, and Oracle keeps its text verbatim | **The tool never builds one.** It issues `ALTER USER` directly (invariant 13) |
| Unified audit `SQL_TEXT` | **masked to `IDENTIFIED BY *` when the record is written.** Masked in the base table `AUDSYS.AUD$UNIFIED` as well as in `UNIFIED_AUDIT_TRAIL` | Keep checking the base table, not only the view. Masking only in the view could be bypassed by anyone with `SELECT ANY DICTIONARY` |
| AWR: `DBA_HIST_SQLTEXT` | **The PL/SQL block reaches it** (unverified: ddl-text-awr). On 19.32.0.0.0 with the Diagnostics Pack, one root snapshot at flush level `ALL` captured the block verbatim into `DBA_HIST_SQLTEXT` and `AWR_ROOT_SQLTEXT`. The plain `ALTER USER` did not reach it, because it has no cursor. That DB system keeps AWR for 8 days, so the block's literal outlives a shared-pool flush and stays on disk for a week. On a busy system the block may not rank among a snapshot's top SQL; that makes capture less likely, not impossible. `sql/oracle/10_awr_snapshot_probe.sql` takes the snapshot | Invariant 13 again, on the longest-lived surface. Still open: whether 11.2's kept `ALTER USER` reaches AWR. No 11.2 with the pack is available |
| `V$SQL_BIND_CAPTURE`: bind values in SQL predicates | Oracle samples them at hard parse and keeps them in clear. This does not apply to rotation, because DDL cannot take binds. On 19.32.0.0.0, with `ORA12C_STRONG_VERIFY_FUNCTION` enabled, no bind capture held the password, although the verify function receives it on every `ALTER USER` | Constrains `check --method hash` if the comparison ever moves to the server: **never bind a password or a verifier into a predicate** (invariant 14) |
| SQL trace (10046) | **A traced session does not capture the password.** At level 12 the cursor is written cut short, as `ALTER USER sopulitest IDE`, one character into `IDENTIFIED`. The PL/SQL block is the exception and leaks in full | Nothing to do. Re-run `sql/oracle/04_password_leak_extensions.sql` on every release added to the matrix: this is retention behaviour, not a documented guarantee |
| OS audit files (`audit_file_dest`): the `SYSDBA` path | **Clean** in position 1 on every release measured before the 23 codebase, with `AUDIT_SYS_OPERATIONS = TRUE`. In position 2, where `svc_user` is `SYS`, the DDL is written masked, `ACTION :[37] 'ALTER USER sopulitest IDENTIFIED BY *'`, and the only verbatim canary is the PL/SQL block. Position 2 ran on 21c, 19.3, 19.32 and 12.2, not on 18c or 11.2. The search must match the numbered canaries: matching the shared prefix finds the probe's own SQL text and reports a false leak | Nothing to do on releases before the 23 codebase. On 26ai the surface is absent, not clean: see the next row |
| OS audit files on the 23 codebase | **The surface is gone, so a clean search there measures nothing.** On 26ai 23.26.2.0.0, `AUDIT_SYS_OPERATIONS = TRUE` is accepted and writes nothing useful: five files, each a session header and one `ACTION` line for the same internal call, and no `CREATE`, `ALTER` or `DROP USER` text. Traditional auditing is desupported from the 23 codebase, and this parameter belongs to it | Read it as an empty column, as the search labels one `INCONCLUSIVE`. There is nothing to protect here on the 23 codebase. That is a different claim from "we looked and found nothing" |
| **Self-rotation**: `IDENTIFIED BY … REPLACE …` | **Audited, with both passwords masked.** The trail records `ALTER USER sopulitest IDENTIFIED BY * REPLACE *`, attributed to the account itself, not to a service account. The unified policy `ACTIONS ALTER USER` records it, and so does traditional `AUDIT USER` where it exists. The `REPLACE` clause carries the account's current password, masked with the same `*`. Not measured: self-rotation under a password verify function, which receives both passwords | The concern was that this path uses no `ALTER USER` privilege, so privilege auditing could miss it. It does not: **"rotations are audited" holds for self-rotation too**, which UC-1b needs. The tool does not have this path |
| **`IDENTIFIED BY VALUES`**: the verifier | **Masked.** The trail records `ALTER USER sopulitest IDENTIFIED BY VALUES *`, and under a level-12 trace the DDL is cut short at the same character as the password form. No raw verifier appears in a trace file or an OS audit file. On 19.32.0.0.0 it is masked in the unified trail and absent from both `DBA_AUDIT_TRAIL` and `audit_file_dest`. That traditional half is absent, not clean, and the cause is not known | A restore-from-verifier path, if one is ever added, does not widen the audit exposure. The verifier can still be attacked offline wherever it can be read, which is ADR-001's question. The probe needs `SELECT ON SYS.USER$`; without it, this row is unanswered, not clean. A verifier written as a literal into a PL/SQL block leaks like any other literal (invariant 13) |
| Network | encrypted when NNE or TLS is in use | `doctor` reports whether each connection is encrypted, and by what (§2). `creds apply`, `creds rotate` and `account reset-password` warn when they send a password over a connection that is not encrypted, `SOPULI-W031`, or whose encryption is not known, `SOPULI-W032` (`03-json-output.md` §3). Require NNE or TLS on the server |
| Tool's own output and logs | redacted at the output serialiser | covered by the redaction release gate, UC-1 §11 |

Run `sql/oracle/02_password_leak_probe.sql` in the three positions its header
describes: in a PDB with a service account that is not `SYSDBA`, in a PDB as
`SYSDBA`, and in `CDB$ROOT`. Only the service-account position proves anything
about the audit policy. `04-testing.md` §6 gate 2 says what the gate needs.

**Then run `sql/oracle/04_password_leak_extensions.sql`.** It covers three
surfaces the main probe does not: self-rotation, `IDENTIFIED BY VALUES`, and
trace and OS audit files. They are a separate script so that they run; a check
written only as a comment in a script does not run.

**Run the extensions with auditing enabled again.** The main probe's cleanup
drops `SOPULI_PROBE_POL` and issues `NOAUDIT USER`. Run straight afterwards, the
extensions record nothing, and their masking result proves nothing. 21c makes
this harder to see than 26ai does. On 26ai nothing is enabled, and the trail is
visibly empty. On 21c the Oracle-supplied `ORA_SECURECONFIG` policy covers
`ALTER USER`, so the trail looks populated anyway, by a policy you did not mean
to test.

---

## 5. Auditing

The tool installs no audit table in the database. The database-side trail is
unified auditing alone. It is the trail to trust, because it does not depend on
the tool behaving correctly.

This policy audits every account change:

```sql
CREATE AUDIT POLICY sopuli_pol
  ACTIONS ALTER USER, CREATE USER, DROP USER;
AUDIT POLICY sopuli_pol;
```

`ALTER USER` is the whole privilege model, so this policy is the compensating
control, not optional housekeeping. Enable it before the first rotation, not
after the first incident. `sql/oracle/01_audit_policy.sql` creates it.

**Correlation.** The tool calls `DBMS_SESSION.SET_IDENTIFIER(<correlation_id>)`
on every connection, so its UUID lands in `UNIFIED_AUDIT_TRAIL.CLIENT_ID`. That
joins the tool's JSON output, the database trail and the vault's secret
metadata. This query finds one run's records:

```sql
SELECT event_timestamp, dbusername, action_name, object_name, return_code
  FROM unified_audit_trail
 WHERE client_id = '9f1c2e7a-4d3b-4a51-9d2c-0b7f8e6a1234'
 ORDER BY event_timestamp;
```

On 11.2, use `AUDIT ALTER USER` and `DBA_AUDIT_TRAIL` instead. `CLIENT_ID`
exists there too.

- **The identifier is set on every connection**, not only on connections that
  change something. A session in the trail with no `CLIENT_ID` is one somebody
  must explain later, and setting it costs one round trip on a connection that is
  already open.
- **It is set before anything else runs**, so no statement can be audited
  without it. A session that cannot be labelled is closed, not used, because
  using it would lose the join this section exists for.
- **The call binds the id.** It does not build a string. This is the reverse of
  invariant 14. `V$SQL_BIND_CAPTURE` keeps bind values in clear, which is why a
  password must never be bound, and why a captured correlation id is useful. The
  dangerous habit is the other one: a `SET_IDENTIFIER` built by concatenation is
  the pattern that later writes a password into SQL text.

Tier 1 checks it from the database's side, by reading
`SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER')`. That is the value
`UNIFIED_AUDIT_TRAIL.CLIENT_ID` comes from, so the test needs no audit policy on
the test container.

Also audit failed logons by the service account. That is what credential
probing looks like.

---

## 6. When the package would be worth reconsidering

Not now, and possibly never. The case is about the stored credential, not the
operator.

An interactive DBA already holds `SYSDBA`, so granting the tool `ALTER USER`
gives away nothing. An **unattended scheduled runner** is different. Its
credential sits in a CI system, a container or a systemd unit. It authenticates
by machine identity and is used with no person present. If it is stolen, the
whole database is compromised, and it is exposed in more places than a DBA's
own login.

UC-1 §S2 assumes exactly this: a nightly `check` and a weekly `rotate` from a
scheduler. So the tool uses direct grants for interactive use. Reconsider the
package only if unattended rotation in an untrusted environment becomes a real
deployment pattern, and only for that runner's credential. A middle option is a
read-only service account for scheduled `check`, and an `ALTER USER` account
used only by `apply` and `rotate`.

This is an option, not a plan. If it is taken up, write the package new, against
the design as it is then.

---

## 7. Files

| File | Purpose |
|---|---|
| `sql/oracle/00_install.sql` | creates the service account and grants it, in non-CDB, common-user and per-PDB modes. The optional grants are parameters |
| `sql/oracle/01_audit_policy.sql` | the unified audit policy (§5) and correlation queries |
| `sql/oracle/02_password_leak_probe.sql` | release gate 2: plants canary passwords and searches for them anywhere queryable (§4) |
| `sql/oracle/03_app_container_probe.sql` | tells an application root and an application PDB from an ordinary PDB, and what the common-user rules mean inside one (§3, §4) |
| `sql/oracle/04_password_leak_extensions.sql` | the probe's other surfaces: self-rotation, `IDENTIFIED BY VALUES`, SQL trace and OS audit files (§4) |
| `sql/oracle/05_verifier_layout_probe.sql` | reads the verifier layout in `SPARE4` and finds the salt from a traced logon. It derives nothing (§2) |
| `sql/oracle/06_verifier_reproduce.{sql,py}` | sets known passwords, then regenerates each stored `T:`/`t:` digest client-side and compares byte for byte, for static passwords and a rollover window (§2) |
| `sql/oracle/07_lock_and_rollover_probe.sql` | what `ACCOUNT UNLOCK` and `IDENTIFIED BY` do to `LCOUNT` and locks, and the UC-2 reset on a rollover profile |
| `sql/oracle/08_expire_password_probe.sql` | the bare `PASSWORD EXPIRE` that `account expire-password` issues, from each account status |
| `sql/oracle/09_reset_from_expired_probe.sql` | setting a password on an `EXPIRED` account whose profile has a rollover window |
| `sql/oracle/10_awr_snapshot_probe.sql` | takes an AWR snapshot after `02_password_leak_probe.sql` and searches it (§4) |
| `sql/oracle/11_proxy_connect_probe.sql` | whether `ALTER USER` alone can grant `CONNECT THROUGH` and connect as another account, and what that leaves in the audit trail |
| `sql/oracle/12_connection_encryption_probe.sql` | what a session can read about whether its own connection is encrypted, with and without a grant (§2) |
| `sql/oracle/99_uninstall.sql` | removes the service account and, optionally, the audit policies |
| `docs/decisions/adr-001-privilege-model.md` | why this model, what was rejected, and when to reconsider |

`00_install.sql`, `01_audit_policy.sql` and `99_uninstall.sql` can be run again
safely, and report what they did. The probes are for throwaway databases only:
each header says what it creates and leaves behind.

---

## 8. Open questions

| # | Question | Leaning |
|---|---|---|
| ~~P1~~ | ~~Common `C##` service user or per-PDB local, as the documented default?~~ | **decided** (#615): common, with per-PDB documented for multi-tenant ownership. Reasons: [P1](../decisions/log.md#p1) |
| ~~P2~~ | ~~Grant `SELECT ON SYS.USER$` by default, to enable hash mode and the `LCOUNT` guard?~~ | **decided: no** (#86). An optional, capability-probed grant (§2); a narrower alternative is #124. Reasons: [P2](../decisions/log.md#p2) |
| ~~P3~~ | ~~Should `--force` exist at all?~~ | **decided: yes — one flag, overriding checks 2–5 of §4 and nothing else** (#89); it is not a setting. Reasons: [P3](../decisions/log.md#p3) |
| ~~P4~~ | ~~One service account per database, or per application?~~ | **decided** (#615): per database; the config's declared accounts provide the finer scoping. Reasons: [P4](../decisions/log.md#p4) |
| ~~P5~~ | ~~Does `doctor` fail or warn on over-granted privileges?~~ | **decided: warn** (#213); `scope.over_granted` is populated and the exit code is unchanged. Reasons: [P5](../decisions/log.md#p5) |
| ~~P6~~ | ~~11.2 support — worth the `DBA_AUDIT_TRAIL` and `ORACLE_MAINTAINED` special cases?~~ | **decided** (#615): keep for now, drop if it starts costing real complexity. Reasons: [P6](../decisions/log.md#p6) |
| ~~P7~~ | ~~Do the 23-codebase schema privileges cover `ALTER USER`?~~ (§2.1) | **decided: no**, `ORA-00990` on 26ai 23.26.2.0.0; the direct grant in §1 is the model. Reasons: [P7](../decisions/log.md#p7) |
| ~~P8~~ | ~~On 11.2 the `ALTER USER` text survives in `V$SQLSTATS` (§4). Document it, warn at runtime, or refuse to rotate there?~~ | **decided: document it** (#387), in §4 and `../security-model.md` §5. Reasons: [P8](../decisions/log.md#p8) |

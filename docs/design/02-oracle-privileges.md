# sopuli-dba — Oracle privileges and grants

Status: the SQL in `sql/oracle/` has been run, per script and per release, and
**each script's own `STATUS:` header says where** and what is still untried.
Trust that header over any summary, including this one.
Depends on: `00-principles.md`, `../use-cases/uc-01-app-credential-sync.md`

---

## 1. The model: direct `ALTER USER`

The tool connects as an account holding the `ALTER USER` system privilege. That
is the whole privilege model. Install is a handful of grants, not a deployment.

### Why not something narrower

Through 21c there is nothing narrower to have. `ALTER USER` has **no object
scope** — there is no `GRANT ALTER USER ON ORDERS_APP`. Any account that can
change one user's password can change every user's password in that container,
including `SYS`.

The 23 codebase — 23ai, renamed 26ai — adds **schema privileges**, which looked like
they might change that. **They do not: `GRANT ALTER USER ON SCHEMA` is rejected with
`ORA-00990`, tested on 26ai 23.26.2.0.0.** So there is nothing narrower to have on
any current release either, and §1's model is permanent rather than provisional.
Evidence and consequences in §2.1 (P7, closed).

The alternative is a definer-rights package that owns the privilege and exposes
only whitelisted operations. That was the earlier draft of this document, and it
was rejected on cost:

- a package to install, version and upgrade in **every PDB**, since a single
  common package in the root would itself need root-wide reach
- a server-side whitelist to maintain in parallel with the tool's own config
- version skew between tool and package as a new class of operational failure
- all of it in exchange for constraining an operator who already holds SYSDBA

sopuli-dba is a tool for DBAs to do faster and more reliably what they already do
by hand. A DBA rotating a password with `sqlplus` today has strictly more power
than the tool is being given. Requiring an in-database framework to hand them a
subset of what they already have is friction without a corresponding gain.

The reasoning is recorded in
[`../decisions/adr-001-privilege-model.md`](../decisions/adr-001-privilege-model.md);
the package implementation itself has been deleted rather than carried as dead
code. §6 describes the one situation where it may earn its cost back.

---

## 2. The grants

### 2.1 Schema privileges do not cover `ALTER USER` — tested, closed (P7)

**Answered 2026-08-17 on Oracle AI Database 26ai Free 23.26.2.0.0 (`FREEPDB1`).
`GRANT ALTER USER ON SCHEMA` is rejected with `ORA-00990: missing or invalid
privilege`, the error pointing at `USER`.** The direct grant in §1 is therefore the
model, permanently rather than provisionally, and the narrower grant this section
was hoping for does not exist on any current release.

> **"23ai" and "26ai" are one product, not two.** Oracle renamed Oracle Database
> 23ai to Oracle AI Database 26ai in October 2025: same codebase, no architectural
> or API change, and 26ai inherits 23ai's Lifetime Support Policy. In
> `23.26.2.0.0` the **23** is the codebase and the **26** is the release-update
> year. A 23ai instance becomes 26ai by applying the 23.26.0 RU, and 23ai is no
> longer separately downloadable — **so there is no pre-26ai 23ai to find, and
> nothing here is waiting on one.** Read "23ai" below as "the 23 codebase", and
> "23ai+" as "codebase 23 and later". Numbering detail:
> [`04-testing.md`](04-testing.md) §2.

Oracle 23ai introduced schema-level privilege grants:

```sql
GRANT SELECT ANY TABLE ON SCHEMA hr TO analyst;
```

This scopes an `ANY`-form privilege to the objects of a single schema, and covers
objects created later without re-granting. It is exactly the shape of thing that
would let this tool hold a narrow grant.

This scopes an `ANY`-form privilege to the objects of a single schema, and covers
objects created later without re-granting. It is exactly the shape of thing that
would have let this tool hold a narrow grant.

**It does not extend to `ALTER USER`.** What was run, and what came back:

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

**The control is the part that makes this conclusive.** A bare `ORA-00990` would be
consistent with schema privileges being absent, unlicensed, or syntactically
unsupported on this release. `SELECT ANY TABLE ON SCHEMA` succeeding in the same
session proves the feature is present and working, so the refusal is specific to
`ALTER USER` rather than incidental to the environment. Nothing partial landed
either — `DBA_SCHEMA_PRIVS` shows only the control.

This matches the predicted reasoning, which is worth keeping because it is what
makes the result general rather than a single observation:

1. Schema privileges scope privileges over *objects inside* a schema — tables,
   views, sequences, procedures. `ALTER USER` does not act on an object in a
   schema; it acts on the account as a security principal. The documented
   examples are all `SELECT/INSERT/UPDATE/DELETE ANY TABLE`,
   `SELECT ANY SEQUENCE`, `EXECUTE ANY PROCEDURE`.
2. `ALTER USER` is not an `ANY`-form privilege at all, so there is no natural
   syntax for it — which is exactly what `ORA-00990` is reporting.

Oracle publishes the definitive list of system and administrative privileges
excluded from schema privileges in *Configuring Privilege and Role Authorization*.

**Consequences.** The least-privilege model this section was testing for is not
available, so nothing about §1 changes and the direct grant is the model on every
supported release. Two follow-on effects worth naming: the P7 trigger for
reconsidering the definer-rights package is closed
([`../decisions/adr-001-privilege-model.md`](../decisions/adr-001-privilege-model.md)),
leaving the unattended-runner case as its only remaining trigger; and §4's
client-side guardrails carry the whole account-scoping job, since there is no
server-side way to bound which accounts the service credential can reach.

Keep the probe as a regression check rather than deleting it — a future release
could add `ALTER USER` to the schema-privilege list, and that would be worth
noticing (`04-testing.md` §5).

### Non-CDB, or a single PDB with local users

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

`SELECT_CATALOG_ROLE` covers all six in one grant (read off `DBA_TAB_PRIVS` on
26ai, 2026-09-25) and is a reasonable
convenience choice — it reaches the `DBA_*` and `V$` views but **not** base
tables such as `SYS.USER$`. The explicit list is the documented default because
it makes a privilege review trivial; the role is fine if your site prefers it.

**Run these as `SYS`, not as `SYSTEM`.** Measured on 26ai 23.26.2.0.0: every
`GRANT SELECT ON SYS.…` above fails with `ORA-01031: insufficient privileges`
when the granting session is `SYSTEM`, while the `CREATE USER` and the two system
privileges succeed. The result is a service account that connects, can rotate,
and reads nothing — whose capability probes then report absent for perfectly
correct reasons, which looks exactly like a broken probe. Worth stating because
nothing in the statements themselves says who has to issue them.

**`DBA_ROLE_PRIVS` is what guardrail 4 reads, and it was missing from this list
until #178.** §4 check 4 refuses an account holding `DBA`, `PDB_DBA`, `CDB_DBA`
or `AUDIT_ADMIN`, and the only place to see another account's roles is
`DBA_ROLE_PRIVS`. Measured: a service account holding exactly the grants above
got `ORA-00942` from it, so the guardrail's input was unobtainable by a correctly
installed tool.

The failure mode is why it is a grant rather than a graceful degradation. An
empty role set means *this account holds none of them* and reads as a pass, so a
missing grant would have turned a safety check into a silent success. The driver
therefore refuses to describe an account whose roles it cannot read
(`RolesUnreadableError`), naming this grant — the same rule as a capability probe
that could not be answered, which raises instead of reporting absent (#195).
Only a refused grant (`ORA-00942`, `ORA-01031`, `ORA-41900`) is reported that
way, with the server's code and message. Any other failure is classified as
itself, because the grant is the wrong fix for a dropped connection (#521).

**`DBA_USERS` is refused on the same rule** (#521). There the tempting
misreading is worse: "no row" means the database has no such account, so an
ungranted view read as `ACCOUNT_MISSING` for every account in the estate. That
was measured on 26ai against a service account holding `CREATE SESSION` and
`ALTER USER` only: `creds status` reported `ACCOUNT_MISSING` and exited 0. It now
reports `ERROR` with category `authorization`, `ORA-00942` and a hint naming
this grant, and exits 1. `ORA-00904` is still the one code that narrows the
query, since a missing column is how a release's `DBA_USERS` shape is found.

**`DBA_ROLES` joined this list with #531, and nothing in UC-1 reads it.** It is
the one place that says whether a role *exists*, and UC-2 §2 turns on that: a
`role:` predicate naming no role is a misspelling and is refused, and one naming
a role that matches nobody is a true empty answer. `resolve_role`'s docstring
said this view was already granted when it was not. Measured on 26ai, an account
holding exactly the grants above got `ORA-00942` from it, so `account list`
refused every role predicate as a misspelling on a correctly installed target.

**An estate installed before #531 is gated, not broken.** `role_lookup` is a
probed capability (P1), so `account list` refuses a role predicate at plan time,
exit 5, with the capability, the target and this grant named. It is deliberately
**not** one of the `doctor --check-privileges` audit's required reads (§3). The
pre-flight in `creds apply` and `rotate` blocks on a missing required read, and
adding this one there would stop every older install from rotating over a grant only a UC-2 listing uses. `doctor`
shows it the capability way instead, as `role_lookup` absent.

**A role-granted `ALTER USER` reads as absent.** `common_users` is probed through
`USER_SYS_PRIVS`, which shows **direct** grants only — so an account holding
`ALTER USER` through a role (as `SYSTEM` does) reports the capability absent and
is refused at plan time. The grant above is direct, so a correctly installed
service account is never that case. The alternatives were measured and are worse:
`DBA_SYS_PRIVS` is not readable under this grant set at all, and `SESSION_PRIVS`
sees role-derived privileges but has no `COMMON` column, so it calls a *local*
`ALTER USER` a pass — which would over-claim, and an over-claimed capability
fails halfway through a rotation instead of before it (#195).

### CDB with common users — one grant covers every container

This is where the direct model pays off most obviously:

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

One statement set, every PDB covered, new PDBs inherit it. Compare with a package
install per PDB, repeated on every plug-in and clone.

Two additional grants depending on how the tool connects:

```sql
-- only if the tool switches containers on an existing session rather than
-- connecting to each PDB service directly
GRANT SET CONTAINER TO c##sopuli_svc CONTAINER=ALL;

-- to manage the common user itself with CONTAINER=ALL
-- (already covered by ALTER USER above; noted because the *session* must be in
--  CDB$ROOT for the CONTAINER=ALL clause to be legal)
```

### Choosing common vs per-PDB local

Both are supported; it is a blast-radius decision, not a capability one.

| | one common `C##SOPULI_SVC` | a local `SOPULI_SVC` per PDB |
|---|---|---|
| Install effort | one grant set | N grant sets |
| New PDB | inherits automatically | needs provisioning |
| Reach of one stolen credential | every PDB in the CDB | that one PDB |
| Credentials to store in the vault | one | N |
| Fits | one team owns the whole CDB | PDBs owned by different teams or tenants |

Recommendation: common user when one DBA team owns the CDB, which is the usual
case. Per-PDB local users when PDBs have different owners — there the isolation
is worth the extra provisioning, and the tool's config already models targets
individually.

### Autonomous Database — PDB mode, as `ADMIN`, and no `SYS.USER$`

An Autonomous Database is a PDB whose container name is generated (a long prefix
and the database name, e.g. `G…_ACMEDB`), and `ADMIN` is its most privileged
account. It is not `SYSDBA`. **`00_install.sql` runs there unchanged in PDB
mode, run as `ADMIN`** (measured 2026-09-28 on ADB serverless 26ai 23.26.3.3.0,
#479). The mode check accepts the generated name, all eight grants in §2's base
set succeed, and the report's "should not appear" query is empty. `doctor
--check-privileges` then flags nothing beyond the optional grants. Use the PDB
tablespace ADB provides, `DATA`, as the third argument.

What ADB takes away is permanent rather than a version gap:

- **No `SYS.USER$`.** `ADMIN` gets `ORA-00942` on it (#478), so
  `grant_user_dollar=Y` has nothing to grant. That means no `check --method hash`
  on ADB, no `LCOUNT` guard, and `offline_verify_available: false` in `doctor`.
  The driver's refusal says so in ADB's terms rather than advising a grant
  (#437). It reads `SYS_CONTEXT('USERENV','CLOUD_SERVICE')`, which answered
  `OLTP` here on 2026-10-02, NULL on 26ai Free, 21c and 18c XE, and
  `ORA-02003` on 11g XE.
  An explicit `check --method hash` or `both` there is refused in those words,
  at plan time.
  None of this is evidence about the verifier layout, because nothing was read.
  The `PTIME` fallback is not needed there, since `PASSWORD_CHANGE_DATE` exists.
- **`DEFAULT` is ADB's own profile**, and every created user gets it:
  `PASSWORD_VERIFY_FUNCTION CLOUD_VERIFY_FUNCTION`, `PASSWORD_REUSE_MAX 4`,
  `PASSWORD_REUSE_TIME 1`, `PASSWORD_ROLLOVER_TIME 0`. The verify function is
  reported as `SOPULI-W016`, and it refused a ten-character password with
  `ORA-28003`. It accepted forty, so the 30-character upper bound in the ADB
  documentation's rules for `ADMIN`'s own password did not apply to a created
  user on this release. The reuse limits make UC-1 §8's rollback fail with
  `ORA-28007` (#568), which the rollback reports as `SOPULI-W028`; the way back
  there is a rollover window, from a profile `ADMIN` can create.
- **No retention claim either way.** `02_password_leak_probe.sql`, which is
  gate 2's evidence (`04-testing.md` §6), sweeps `V$SQLSTATS`, the OS audit files
  and the trace directory as `SYSDBA`. ADB has no `SYSDBA` and no OS access, so
  the sweep can't run there, and its `SYSDBA` positions are **inapplicable**
  rather than unrun. §4's surface table names the releases it was measured on,
  and ADB is not among them for that reason. It must not borrow 26ai's result
  because both are 26ai.
- **`db_version` is the base release**, `23.0.0.0.0`, because it is
  `V$INSTANCE.VERSION`, and that column has carried only the base release since
  18c. 19.3 reports `19.0.0.0.0` in the same column, with `VERSION_FULL`
  `19.3.0.0.0`. `doctor` displays it as `scope.db_version`. The one thing that
  *decides* anything with it is `driver/oracle/limits.py`'s password-limit floor,
  which compares the first two components only, so the zeros change nothing
  (#479).
- **Not tried:** whether `ADMIN` can grant `SELECT ON SYS.V_$PWFILE_USERS`
  (§4 check 3), and whether `01_audit_policy.sql` runs on ADB, where unified
  auditing is on by default.

### `check`'s default method, and the optional `SYS.USER$` grant

`check` defaults to `--method login` unconditionally — **decided in #86,
2026-08-18** (Q1: `login`; P2: `SELECT ON SYS.USER$` is not granted by
default). It never requires `SYS.USER$`: a login attempt plus
UC-1 §7's mitigations (never retry, reset on success, `ACCOUNT_STATUS`
reporting) is the whole of the default path, and all of it runs on the base
grant set in §7 alone.

`SELECT ON SYS.USER$` is **optional**, not part of the default install:

```sql
GRANT SELECT ON SYS.USER$ TO sopuli_svc;   -- or c##sopuli_svc CONTAINER=ALL
```

`sql/oracle/00_install.sql` already models it this way — `grant_user_dollar`
defaults to `N` — so this decision brings the docs into line with SQL that
predates it, not the other way round.

When present, the grant is probed as a capability at plan time (invariant 3,
`CLAUDE.md`) rather than assumed from config, and used for three things:

- **The `LCOUNT` guard** — refuse a login attempt within `--lockout-margin` of
  the account's `FAILED_LOGIN_ATTEMPTS` limit (UC-1 §7 mitigation 2). This is
  the one place the grant changes *behaviour*, not just what's queryable:
  without it, `--method login` still runs, on UC-1 §7's remaining runtime
  mitigations (1/3/6 — never retry, reset on success, `ACCOUNT_STATUS`
  reporting), and `check` must report the guard's absence plainly rather than
  silently run a weaker version of it.
- **`check --method hash`** (#437) — see below.
- **The password change date where `DBA_USERS` has no column for it** (#386).
  `DBA_USERS.PASSWORD_CHANGE_DATE` is `ORA-00904` on 18c and 11.2, and present on
  19c (19.24.0.0.0, measured 2026-09-17), which never takes this path as a result.
  12.2.0.1.0 has no such column either (2026-09-29, #572) and takes the path,
  as 18c does; 12.1 is unmeasured. Where it is absent, `SELECT PTIME FROM SYS.USER$` supplies
  the same value, measured equal to the column to the second on the releases
  that have both. Display only — `creds status`'s `DB_PW_CHANGED` and the run
  document's `password_age_days` — and never read where the column exists.
  Without the grant the date is absent and `SOPULI-W021` says so.

Under the package model this grant was the thing to avoid — it exposes every
password verifier in the database to a low-privilege account. Under the direct
model that objection largely evaporates: an account holding `ALTER USER` can
already set any password it likes, so being able to read the verifiers adds
little to what it can do. The residual concern is different in kind rather than
degree — verifiers are *offline-attackable*, so a stolen dump of them is useful
to an attacker who never touches the database again. That trade-off is a site's
to make, not the tool's to default to — which is why the grant is opt-in.

**Whether to recommend granting it, and whether a narrower alternative exists,
is deferred to #124.** `SYS.KU$_USER_VIEW` / `SYS.KU$_USER_BASE_VIEW` (Data
Pump metadata views, granted to `PUBLIC`) reportedly expose `LCOUNT` under
`SELECT_CATALOG_ROLE` alone, masking `SPARE4` unless the session also holds
`EXP_FULL_DATABASE` — which, if it reproduces, would let a site enable the
`LCOUNT` guard without exposing verifiers at all (unverified: lcount-grant).
That claim comes from a blog
post, not Oracle documentation, and needs the same measure-don't-trust
treatment #124 gives it before it goes anywhere near the install script.

**The reproduction question (#90) is independent of whether to *recommend* the
grant (#124) — but hash mode itself is not independent of the grant.** The `T:`
(12C, PBKDF2-SHA512) verifier must be regenerated client-side, which the grant
does not touch, *and* read from `SPARE4`, which needs `SELECT ON SYS.USER$`. So
`hash` mode requires the grant even though the derivation does not. The layout is
read, the derivation reproduces, and the degradation rule is settled — on the
tier-2 releases, on **19c 19.3.0.0.0** (#548), on **12c 12.2.0.1.0** (#572)
and on **19c 19.32.0.0.0** (#581), an OCI Base Database Service DB system and
the first release update read. 12.1 is still unread. #90 is three parts:

- **The layout — read on 26ai 23.26.2.0.0, 21c 21.3.0.0.0, 18c 18.4.0.0.0 and
  11g 11.2.0.2.0 (#431), 2026-09-15, on 19c 19.3.0.0.0 (#548), 2026-09-27, and
  on 12.2.0.1.0 (#572), 2026-09-29, and on 19.32.0.0.0 (#581), 2026-10-01;
  unread on 12.1.** `SPARE4`
  is `S:<60 hex>;T:<160 hex>` on the six 12.2+ releases and `S:<60 hex>` alone
  on 11g. There is no `H:` in `SPARE4` on any of them; 11g's 10G value is
  `USER$.PASSWORD`. `T:` is a 64-byte digest followed by a 16-byte salt, `S:` a
  20-byte digest followed by a 10-byte salt. The salt offsets are measured
  rather than assumed: the `AUTH_VFR_DATA` a traced logon receives equals those
  trailing bytes, twice on every release but 19.32. **The iteration count is
  not stored** — the server sends `AUTH_PBKDF2_VGEN_COUNT` = 4096 at logon, on
  all five 12.2+ releases where it could be read. **On 19.32 it could not**: the
  DB system requires NNE, so everything after the connect packet is encrypted
  and a client trace shows no `AUTH_` key at all. There the count is shown only
  indirectly, by the reproduction below succeeding with 4096. Every `ALTER USER` draws a fresh salt, including one to the
  same password, so a stored verifier can only ever be compared by regenerating
  from *its* salt. Field table, normalisation notes and the probe:
  `sql/oracle/05_verifier_layout_probe.sql`.
- **Reproduction — confirmed on 26ai, 21c and 18c (#432), 2026-09-15, on
  19.3.0.0.0 (#548), 2026-09-27, on 12.2.0.1.0 (#572), 2026-09-29, at least
  twice each, and on 19.32.0.0.0 (#581), 2026-10-01; not on 12.1.** The stored `T:` digest regenerates byte-for-byte from the password:

  ```
  salt   = the last 16 bytes of the T: blob (its 32 trailing hex characters)
  inter  = PBKDF2-HMAC-SHA512(password_utf8, salt || b"AUTH_PBKDF2_SPEEDY_KEY", 4096, 64)
  digest = SHA-512(inter || salt)                # the 64-byte / 128-hex head of the blob
  ```

  The password is fed as raw UTF-8 with no case folding and no normalisation —
  the non-ASCII case reproduces on the multibyte input unchanged. **"The
  password" means the one the database holds**, after conversion to its
  character set: on 12.2's WE8DEC image `Ω` does not survive that conversion,
  the account's password became `…¿9`, and the verifier reproduced from the
  UTF-8 of *that* (#572). On AL32UTF8 the two are the same string. The tool is
  unaffected — `limits.py` measures an unmapped set like WE8DEC in ASCII, so
  no password it sets can reach the lossy path — but a `hash` implementation
  must not assume the vault's string is the one hashed on such a database. A 128-byte
  password reproduces on 26ai (it is rejected at DDL below 23ai, the 30-byte
  limit of #383, which the probe reads from the server rather than a version).
  4096 is the count the
  server sends at logon (the layout bullet), not a value in `SPARE4`, so a
  release sending a different one would not reproduce and must be measured, not
  assumed. That is why 19c stayed open until an RU had been read. 19.32 has now
  been read and reproduces with 4096 (#581), with the count shown by the
  reproduction rather than read off the wire, and the register entry is settled
  for 19c on that basis. 12.1 is unread. The
  reference derivation and the probe are `sql/oracle/06_verifier_reproduce.py`
  and `.sql`.
- **The rollover window carries two 12C verifiers, distinguishable client-side
  (#432).** During a gradual rollover (measured on 26ai, 21c and 19.32.0.0.0;
  18c, 19.3 and 12.2 have no such feature), `SPARE4` holds `T:` = the *previous* password and `t:` = the
  *current* one, sharing one salt, alongside a non-verifier `V:` marker. So
  `check` reports `ROLLOVER_ACTIVE` from the presence of two 12C verifiers, and
  `--include-previous` tells current from previous by which prefix the vault
  value reproduces — never by drift. Confirmed on a real 19.12+ by 19.32 (#581):
  `T:` = old and `t:` = new during the window, `T:` = new after it.
- **Multi-verifier accounts and degradation when `T:` is absent — measured on
  11g and 18c (#433), 2026-09-15.** The comparison uses the **12C `T:` verifier
  and only it**; the older verifiers are neither compared nor in the way:
    - A genuine three-verifier account (`PASSWORD_VERSIONS = 10G 11G 12C`, forced
      on 18c with `SQLNET.ALLOWED_LOGON_VERSION_SERVER = 8` — see below) puts the
      **10G verifier in `SYS.USER$.PASSWORD`, a different column**, and leaves
      `SPARE4` as the same `S:;T:` pair. `T:` sits at the same offset and
      reproduces byte-for-byte with 10G and 11G both present. So the presence of
      older verifiers changes nothing about reading or deriving `T:`.
    - 10G and 11G must **never** be a silent fallback: 10G is unsalted,
      case-insensitive DES and 11G is `S:` (SHA-1); comparing either would report
      a weaker check than `--method login` already gives. `T:` is the only
      verifier `hash` mode trusts.
    - **When no `T:` is present** — 11g (`PASSWORD_VERSIONS = 10G 11G`, `SPARE4`
      is `S:` alone), or any account whose `PASSWORD_VERSIONS` lacks `12C` —
      `hash` mode has nothing to compare and **fails at plan time naming the
      capability and the target** (invariant 4), never a generic mid-run error
      and never a quiet fall-through to a weaker verifier. `both` cannot degrade
      to `login` silently for the same reason it cannot elsewhere.
    - **The gate is a capability, not a version** (invariant 3 / P1): *a readable
      `T:` verifier is present for this account*, which is `SPARE4` carrying a
      `T:`/`t:` token, mirrored by `DBA_USERS.PASSWORD_VERSIONS` containing
      `12C`. It is two conditions in one: the session-level `SELECT ON SYS.USER$`
      grant (`OFFLINE_VERIFY`) makes `SPARE4` readable at all, and the
      account-level `PASSWORD_VERSIONS` says whether this account has a `12C` to
      read. Both are queried, never inferred from the server release — a 12.1+
      server can still hold an account with no `12C` verifier.
    - Aside, measured in passing: **23ai has dropped the 10G verifier entirely.**
      Even at `ALLOWED_LOGON_VERSION_SERVER = 8` a fresh 26ai account is
      `11G 12C`, so 10G and 12C co-occur only on 12.1–19c. Nothing depends on
      this; it is recorded so a future `10G`-handling assumption is not made
      about the newest target.
    - **19.3.0.0.0 (2026-09-28, #479):** with no `ALLOWED_LOGON_VERSION_SERVER`
      set, a fresh account is `11G 12C`, with `SPARE4` holding `S:` and `T:` and
      no 10G hash. With `ALLOWED_LOGON_VERSION_SERVER = 11` it is `10G 11G 12C`,
      and the 10G hash lands in `SYS.USER$.PASSWORD` exactly as on 18c. So on 19c
      the co-occurrence is real, but only where a site lowered the logon version.
      A patched 19c is unmeasured.
    - **12.2.0.1.0 (2026-09-29, #572):** identical to 19.3 — `11G 12C` by
      default, `10G 11G 12C` with `ALLOWED_LOGON_VERSION_SERVER = 11` and the
      16-hex 10G hash in `SYS.USER$.PASSWORD`, `SPARE4` unchanged at 225
      characters. No restart needed. 12.1 is unmeasured.

  How the three-verifier account was produced, for a maintainer re-run (not a
  repeatable public probe, because it needs a server config change): append
  `SQLNET.ALLOWED_LOGON_VERSION_SERVER = 8` to the server `sqlnet.ora`
  (`$ORACLE_HOME/network/admin/sqlnet.ora`), then `CREATE USER … IDENTIFIED BY
  …`; `PASSWORD_VERSIONS` reads `10G 11G 12C`. On 19.3 no restart was needed:
  a new SYSDBA session read the edited file and the next `CREATE USER` got the
  10G verifier. On 18c the recipe included a restart, and whether that one
  needed it was not tested. Restore the file afterwards. The recipe worked on
  18c, 19.3 and 12.2 and not on 26ai. (On 12.2's image the server's
  `sqlnet.ora` is under `$ORACLE_HOME/admin/ORCLCDB`, its `TNS_ADMIN`.)

Since the derivation reproduces and degradation is settled, `--method hash|both`
is now a mechanical implementation on the tier-2 releases. **The driver half is
built (#437):** `verify_password(method="hash")` reads `SPARE4`, binds the
account name and nothing else, and compares in
`src/sopuli/driver/oracle/verifier.py`. It refuses, naming the target, where the
session cannot read `SYS.USER$` or the account has no `12C` verifier, and also
where a `T:`/`t:` token is not the measured 160 hex characters. It also refuses
where the database character set cannot hold the vault value exactly: the server
hashed a converted copy (the WE8DEC case above), and a mismatch reported there
would be false drift. During a window,
it reports which of the two verifiers the password reproduced.
`verify_password(method="both")` compares first and logs in only when the
comparison passed, so a mismatch spends no lockout budget (decided in #437).
`require_verifier` makes every one of those refusals without comparing anything
it reports, so a caller can refuse at plan time. Each refusal names a capability
rather than describing one: `offline_verify`, `verifier_12c`,
`verifier_12c_format` or `verifier_charset`. On Autonomous Database the
`offline_verify` refusal says no account there can read `SYS.USER$`, and does not
advise a grant. **The CLI half is built too:** `creds check --method hash|both`
asks every target `require_verifier` before any account is checked, so each of
those refusals is exit 5 naming the target, at plan time, with the name in
`error.target_capability` and the account in the hint. Were it ever to fail
on a release not yet read (12.1, or a later RU — 19.3 and 19.32 reproduce), both non-login modes would leave the
CLI entirely — `both` is login plus this same comparison, and a `both` that
silently degraded to `login` would report a stronger check than it performed.
Either way `login` with the optional `LCOUNT` guard is already the complete
default path (#86), so no default depends on the outcome. **Invariant 14**
governs any future server-side form: the verifier is never bound into a SQL
predicate — the reproduction here is entirely client-side.

### §4 check 3, and the optional `V$PWFILE_USERS` grant

Guardrail 3 refuses an account in the password file, and the only place to see
that is `V$PWFILE_USERS`. It is **optional**, not part of the default install —
decided in #296, which considered adding it to the set above and did not:

```sql
GRANT SELECT ON SYS.V_$PWFILE_USERS TO sopuli_svc;   -- or c##sopuli_svc CONTAINER=ALL
```

**Measured on 26ai Free 23.26.2.0.0, 2026-09-05.** A service account holding
exactly the grants above gets
`ORA-00942: table or view "SYS"."V_$PWFILE_USERS" does not exist` from it — the
same enumerated negative `ABSENT_CODES` already reads as *absent* — so the
driver answers `None` and never `False`. With the grant it answers a count from
inside a PDB without further privilege.

**It buys two things, and the second arrived later.** Guardrail 3 is the one it
was taken for; since #341 the same view also answers §3's `SYSDBA` and `SYSOPER`
rows for `doctor --check-privileges`, which reported them unaudited from a
constant until then. Same grant, same query, two consumers — and the audit asks
about the *session's own user* where the guardrail asks about a target account,
so neither reads the other's answer.

**Why it stays optional.** The accounts check 3 catches are largely caught by
checks 2 and 4 as well, and widening what every service account needs for the
remainder is a poor trade. What is left over is real, though, and was measured
rather than argued: an account granted `SYSDBA` **inside a PDB** appears in
`V$PWFILE_USERS` with its own `CON_ID` — visible from the PDB and from
`CDB$ROOT` — while reading `ORACLE_MAINTAINED = 'N'` and holding no roles at
all. So it is a site-created account that checks 2, 4 and 5 all pass, and only
this one refuses. Sites have those.

**Without the grant the check does not silently pass.** That was the bug (#296):
nothing populated the field, so *nobody looked* read as *not a member*. The run
now says so — `SOPULI-W018`, one warning per target, naming this grant — and
goes ahead, because refusing on an unread check would refuse every mutation on
every estate installed exactly as documented. §4 has the reasoning. What it looks
like, pasted from a `creds apply` against a PDB service account holding exactly
the grants above:

```
ACCOUNT        TARGET       STATE    DETAIL
acme_web_user  appdb-alpha  IN_SYNC  the vault's password is already accepted; nothing to change

nothing changed

1 note:
  appdb-alpha: guardrail check `password_file` did not run: could not establish whether the account is in the password file -- GRANT SELECT ON SYS.V_$PWFILE_USERS to the service account to enable it (ACME_WEB_USER)
```

and, once the grant is taken, the same run with no note. With `SYSDBA` granted to
`ACME_WEB_USER` and the view readable, check 3 fires for the first time:

```
ACCOUNT        TARGET       STATE    DETAIL
acme_web_user  appdb-alpha  SKIPPED  the account is in the password file
```

**An administrative account can still be on a rollover profile, and 21c makes
that easy to conclude the other way round.** Measured on both, 2026-09-08
(#380), creating a profile with `PASSWORD_ROLLOVER_TIME` and a user on it:

| | 26ai 23.26.2.0.0 | 21c XE 21.3.0.0.0 |
|---|---|---|
| `GRANT SYSDBA` to a user on that profile | ok | `ORA-28227: Gradual password rollover is not supported for administrative users.` |
| `GRANT SYSOPER` likewise | ok | `ORA-28227` |
| `GRANT DBA` (the role) likewise | ok | ok |
| `GRANT SYSDBA` first, *then* `ALTER USER ... PROFILE` onto it | ok | **ok** |

The last row is the one that matters. 21c enforces the rule on the `GRANT` path
and not on the `ALTER USER` path, so the state it refuses to create directly is
reachable in two statements — which means "in the password file, therefore no
rollover window" is not a safe inference on any version, and nothing here draws
it. Guardrail 3 refuses such an account outright, which is the same answer either
way.

It is recorded here rather than in §5 because it is a fact about the password
file and about profiles, not about auditing. The practical consequence for this
repository was in a test:
`tests/driver/test_oracle_accounts.py::test_a_pdb_local_account_granted_sysdba_appears_in_the_password_file`
borrowed a fixture whose profile set the limit, which no 26ai run could reveal.

---

## 3. What must not be granted

| Not granted | Why |
|---|---|
| `SELECT ANY DICTIONARY` | includes `SYS.USER$` *and* everything else; if hash mode is wanted, grant `SELECT ON SYS.USER$` specifically |
| `DBA`, `PDB_DBA`, `CDB_DBA` | the tool needs `ALTER USER`, not a role that carries a hundred other privileges |
| `SYSDBA` / `SYSOPER` | never; the tool has no operation that requires it |
| `ALTER PROFILE` | decided in UC-1 Q4 (#88): no credential-sync verb ever edits a profile — a profile is shared, so editing one reaches accounts nobody selected, which the config's account whitelist (invariant 5) has no way to constrain. The tool reports the DDL needed to enable password rollover instead, and `doctor --check-privileges` flags this privilege if the service account has it. Whether UC-4 may create and alter profiles is its own open question, and would be a privilege on a principal UC-4 defines rather than on this grant set |
| `CREATE USER` / `DROP USER` | account provisioning is out of scope for UC-1 |
| `ALTER SYSTEM`, `GRANT ANY *`, `BECOME USER` | no operation needs them |
| `EXECUTE ON DBMS_LOCK` | P5's advisory lock lives in the vault, not in the database (Q2, decided in #83). It was the one grant a `DBMS_LOCK`-based lock would have added, and the reason it is not here is that session-scoped locking does not solve the problem it looked like it solved: a stalled run's session is still alive, so its lock prevents nothing while its plan goes stale. A fencing token re-checked before every mutation does, and it needs nothing from the database |

**Application containers are the one scope §2 cannot see through a view, and do
not need to.** `V$PDBS` is granted in the root only and `CDB_PDBS` nowhere, so
the three views carrying `APPLICATION_ROOT` / `APPLICATION_PDB` are all
`ORA-00942` to a PDB-mode service account — measured, not assumed (#204). The
fact is available from `SYS_CONTEXT('USERENV','IS_APPLICATION_ROOT')` and
`'IS_APPLICATION_PDB'` instead, which need no grant, exactly as `CON_NAME` needs
none. **No grant is added for this**, which settles the trade #204 asked to argue
by removing it: there is nothing to buy. On a release without those attributes the
probe raises `ORA-02003` rather than returning null — the same code `CON_NAME`
gives on 11.2, carrying a different fact and the same conclusion.

`sopuli doctor --check-privileges` reports what the service account actually
holds and flags anything on this list. Over-granting is the common failure when
someone is debugging a permissions problem at 17:00 on a Friday; the tool should
notice and say so rather than quietly benefit from it.

**It warns and never fails** (P5, decided in #213 — see §8). Reporting is not
enforcing: #173 is the refusal and §4 is the guardrail set, and neither is this.

**It reports both sides**, and they are independent questions. §3's list is what
the account holds and should not; §2's is what it needs and may not have. An
account can be in both states at once, which is what a half-finished
17:00-on-a-Friday debugging session actually leaves behind. Reporting the second
at connect time is what stops a missing `SELECT ON DBA_PROFILES` surfacing as a
limit resolution that could not answer, three commands later, with an error about
a view rather than about the install.

**A dictionary grant is answered by reading the view, not by reading a grant
table** (#225). `USER_TAB_PRIVS` plus `ROLE_TAB_PRIVS` was the alternative, and
probing is better on three counts: a role-derived grant needs no special handling,
because a view you can read is a view you can read however the grant arrived; a
grant row is not access, since the view may have been dropped or renamed under it;
and the mechanism already exists and is already measured — `ABSENT_CODES` treats
`ORA-00942`, `ORA-01031` and `ORA-41900` as "no", the last of which was measured
rather than predicted. The cost is one round trip per documented grant, which is
why the whole thing is behind a flag.

**`V_$PDBS` is required in the root only**, where §2 grants it, and is absent from
both the held and the missing list elsewhere. "Not required here" and "required
and missing" are the two answers this report exists to keep apart.

**The audit is self-inspection**, which is what makes it possible at all. The
obvious implementation reads `DBA_SYS_PRIVS` for this grantee and does not work —
an account holding exactly §2's grants gets `ORA-00942` from it, measured on 26ai
in #178, so a *correctly installed* tool would report nothing at all. That is the
answer that looks like good news and means "I could not look", and it is the same
failure #178 found in `DBA_ROLE_PRIVS` and #195 in a capability probe. So the
questions are asked of views that need no grant:

| View | Answers | Grant needed |
|---|---|---|
| `SESSION_PRIVS` | every system privilege in force, **role-derived included** | none |
| `USER_SYS_PRIVS` | the same account's *direct* grants, with `COMMON` — the column `SESSION_PRIVS` lacks | none |
| `DBA_ROLE_PRIVS` | granted roles, traversed with `CONNECT BY NOCYCLE` | §2 grants it (#207) |

**Roles are read granted rather than enabled**, which is why `SESSION_ROLES` —
free of any grant — is not used: it shows what is enabled in *this* session, and
a non-default `DBA` grant is one `SET ROLE` away. For a guardrail that would be
splitting hairs; for an audit asking what an account could become, a privilege
one statement away is held.

**One row cannot be audited anywhere, and two more only where §2's optional
grant was declined.** The report names whichever apply on every run rather than
omitting them — E6's argument, applied to a caveat: one that appears only when
something is wrong cannot be quoted as evidence that nothing was.

| Row | Why not | What it would take |
|---|---|---|
| `EXECUTE ON DBMS_LOCK` | an **object** privilege; the three views above carry system privileges and roles | `USER_TAB_PRIVS` and `ROLE_TAB_PRIVS`, the second of which does not compose with the nested-role traversal — a design question rather than a query |
| `SYSDBA` / `SYSOPER` | `V$PWFILE_USERS` is not in §2's *default* grant set | nothing, on an estate that took the optional grant §4 check 3 documents. Read since #341, and unaudited only where the answer came back absent |

A refused `DBA_ROLE_PRIVS` joins them at runtime, taking the three role rows with
it. "I looked and found nothing" and "I could not look" are answers this report
never merges.

**The password-file rows are read, not assumed** (#341). Until then the audit
reported them unaudited from a constant, which #296 made wrong for the estates
that took the grant: the answer was available and the report said *I could not
look*, which is the same merge this section refuses, arrived at from the side
that under-reports. Three readings, measured on 26ai Free 23.26.2.0.0 on
2026-09-05 against a PDB-local service account holding §2's grants plus that one:

- **the two rows are answered separately**, because the view carries a column
  each — `SYSDBA`, `SYSOPER`, and four more it does not ask about. Granted and
  revoked one at a time, all four combinations read back as themselves;
  collapsing them into "in the password file" would report `SYSOPER` on the
  strength of a `SYSDBA` row;
- **a held row is an `over_granted` finding like any other**, which makes it the
  audit's first that is neither a system privilege nor a role. §3's must-not-grant
  list is one list, and a reader must not have to know which view each row came
  from;
- **taking the grant does not itself make `doctor` complain.** `over_granted`
  reads system privileges and roles, and this is an object privilege — confirmed
  on the same run, and it would have been a defect in #296 rather than a
  follow-up.

**An absent answer does not make the audit partial.** `unreadable` says the
report cannot be taken at face value; an estate that declined an optional grant
is installed exactly as documented. So the two rows go to the unaudited list and
bring a remedy with them — since #296 the reason they are unchecked is *you may
enable this* rather than *this cannot be known*, and only one of those has a next
action. The audit's own shape names no database, so the `GRANT` is the driver's
words rather than the report's, the same seam guardrail 3's remedy sits on.

**This does not make the audit complete**, and "make the audit complete" is the
tempting framing. `EXECUTE ON DBMS_LOCK` stays unauditable for its own reason and
no grant fixes it: it is two of three rows, on the estates that opted in.

What the three estates look like, pasted from `doctor --check-privileges`
against a PDB service account on 26ai Free 23.26.2.0.0. The default install,
which is unchanged except that the caveat now carries a next action:

```
TARGET       REACHABLE  SCOPE  CONTAINER  OPEN MODE   CAPABILITIES
appdb-alpha  yes        pdb    FREEPDB1   READ WRITE  5
  appdb-alpha: not checked, and not visible from here: EXECUTE ON DBMS_LOCK, SYSDBA, SYSOPER
  appdb-alpha: SYSDBA and SYSOPER need SELECT on V$PWFILE_USERS, which 02-oracle-privileges.md §2 leaves optional: GRANT SELECT ON SYS.V_$PWFILE_USERS to the service account to audit them
```

the same account with the grant taken, holding neither privilege — one row left
unchecked, and nothing to suggest about it:

```
TARGET       REACHABLE  SCOPE  CONTAINER  OPEN MODE   CAPABILITIES
appdb-alpha  yes        pdb    FREEPDB1   READ WRITE  5
  appdb-alpha: not checked, and not visible from here: EXECUTE ON DBMS_LOCK
```

and the same account granted `SYSDBA`, which is the finding this could not make
before — reported and, per P5, not fatal (the run exits 0):

```
TARGET       REACHABLE  SCOPE  CONTAINER  OPEN MODE   CAPABILITIES
appdb-alpha  yes        pdb    FREEPDB1   READ WRITE  5
  appdb-alpha: not checked, and not visible from here: EXECUTE ON DBMS_LOCK
  appdb-alpha: over-granted, and the tool needs none of it: SYSDBA
```

---

## 4. Guardrails, now client-side

Dropping the package moves the account-safety checks into the tool. They stop
being a security boundary — a compromised service credential bypasses them
entirely — and become what they realistically were for an operator with SYSDBA
anyway: **protection against typos and against a config change with a wider blast
radius than intended.** Worth keeping, worth being honest about.

Before any `ALTER USER`, the tool refuses when the target account:

1. is not among the config's **declared accounts** — `accounts:` inline, an
   `applications:` entry, or, for a personal account, a name or a predicate in
   `personal_accounts:` (H1, #449) — the config *is* the whitelist, just advisory
   rather than enforced. The list matters here rather than in the prose below,
   because an implementation written from this item alone would omit the
   predicate form and silently refuse every personal account
2. has `DBA_USERS.ORACLE_MAINTAINED = 'Y'` — covers SYS, SYSTEM, DBSNMP,
   GSMADMIN_INTERNAL and the rest without a hand-maintained list going stale
3. appears in `V$PWFILE_USERS` — behind an **optional** grant, so on most
   estates this check has no input and says so rather than passing (#296; §2)
4. holds `DBA`, `PDB_DBA`, `CDB_DBA`, or `AUDIT_ADMIN`
5. is on a literal deny list, for 11.2 where `ORACLE_MAINTAINED` does not exist

`--force` overrides 2–5 for the case where a DBA deliberately manages something
unusual (P3, decided in #89). It is recorded in the audit event and in the JSON
output; it never overrides 1, because acting on an account absent from the config
would make the tool's own audit trail meaningless.

Implemented in `sopuli/driver/guardrails.py` (#173), which reviews and does not
decide — the same shape as the error mapping. Three things it settles:

- **What a refusal does depends on how the account was selected**, and the rule
  is one rule for every mutating verb. An account the operator **named** —
  `--account DBSNMP` — refuses the run: they asked for something the tool will
  not do, and quietly skipping it would report success for work nobody did. An
  account that merely **fell inside** a broad selection is `SKIPPED` with its
  reason, and the run does the rest of its job; refusing 200 rotations because
  the 47th selected account turned out to be `ORACLE_MAINTAINED` would make the
  guardrail more disruptive than the mistake it caught. Selection is what the
  command layer knows and the driver does not, so the rule is written here and
  applied there.
- **Check 5 is consulted only where check 2 had nothing to say.** Where the
  database can report `ORACLE_MAINTAINED`, that answer wins outright — including
  when it says *no* about a name on the list. Sites do call an account `SCOTT`,
  and a list maintained by us overruling the database describing itself would
  make it a second whitelist nobody agreed to. The list is deliberately long
  rather than exact: a missing entry means one old version misses one check, a
  spurious entry means an audited `--force`, and those costs are not symmetrical.
- **Check 1 compares case-folded.** `01-configuration.md` writes
  `acme_web_user` and Oracle stores `ACME_WEB_USER`, because an unquoted
  identifier is upper-cased on the way in. Comparing exactly would refuse every
  correctly-declared account on Oracle — a guardrail that fires only on its own
  users. The residual risk, an estate holding both `ACME_WEB_USER` and a quoted
  `"acme_web_user"`, is named rather than solved.

### What the guardrails do in this build (#286)

`sopuli/driver/guardrails.py` was written in #173 and **called by nothing** until
now: it implemented all five checks, documented `--force`, and had a full unit
suite, while `creds apply` would happily issue `ALTER USER` against an
`ORACLE_MAINTAINED` account provided the config declared it. `creds apply` and
`creds rotate` now ask it. Five things about how are decisions:

- **The review runs before the first login, not before the statement.** An
  account the tool will not touch must not spend an attempt against a lockout
  counter, which is the argument §7 of UC-1 makes for every login this tool
  budgets. It costs no extra round trip either way: `describe_user` has already
  read every fact the checks need.
- **Check 1 asks the *unfiltered* config.** A selector narrows what a run
  touches and cannot un-declare an account (invariant 5), so the whitelist is
  the file's declared set and not this run's slice of it. In practice check 1
  cannot fire from a mutating verb today, because the bindings come from the same
  file — it is run anyway, because "enforced by construction" is a property of
  today's call graph rather than of the guardrail.

  **That stops being true under UC-2's predicate declaration** (H1, #449). Where a
  personal account is declared by a profile or a role rather than by name, the
  declared set is a query result rather than the file's own list, so check 1 is the
  thing standing between a `GRANT` somebody made in the database and an account
  this tool will touch. The property it has today — unfireable because the set and
  the check read the same file — is exactly what a predicate removes, which makes
  the check load-bearing rather than ceremonial and is worth knowing before anyone
  decides it is dead code.
- **A refusal is `SKIPPED`, and `SKIPPED` is not counted in the exit code.** It
  is neither a success nor a failure: it is an account that left the run's scope,
  the same way one the config never declared never entered it. Counting it as
  unconfirmed would exit 4 — "some of it worked, run `apply --repair`" — on a run
  where everything the tool was willing to do succeeded, and the repair would
  skip the same account again, every night, for ever. A run of nothing but skips
  exits 0, which is the answer an empty selection already gives.
- **A skipped account is dropped from its document's promotion entirely**, from
  the gate as well as from the write. Promoting it would move its `pending` to
  `current` while its database still holds the old password, which is what
  invariant 7 exists to prevent; letting it *gate* the document would mean one
  permanently guarded account — a `DBA` grant nobody is going to give up —
  blocking promotion for every neighbour sharing the secret path, for ever.
  Dropping it does neither: its `pending` stays staged and its neighbours
  promote.
- **The waiver is a structured field, not prose.** `--force` fills
  `results[].overridden` with the check and what it observed (run schema 1.17),
  because §4 requires the override to survive the waiving and a consumer has to
  be able to branch on "this account was forced" rather than grep a sentence. It
  is omitted where nothing was waived: the field records overrides, not intent.

**Two of the five checks could not fire when #286 landed**, and both were
recorded rather than quietly tolerated. Both are now built:

- ~~**Check 3 never runs.**~~ **Fixed in #296**, and the fix is not the obvious
  one. `UserState.password_file_member` was `None`-when-unknown and *nothing
  populated it* — no query read `V$PWFILE_USERS` — so `review()` read "I could
  not look" as "I looked and found nothing", which is exactly the merge
  `privileges.py` refuses to make one layer up about the same view. The driver
  now reads it. That alone would not have fixed anything: §2 deliberately does
  not grant the view, so the answer on a correct install is still *unknown*.

  What fixes it is that **`review()` has a third answer**. Refused, permitted,
  or *could not establish* — a `Caveat`, which refuses nothing, rides through
  `--force` untouched, and is reported as `SOPULI-W018`, one warning per target,
  naming the optional grant that would settle it. Three things about it are
  decisions:

  - **It does not refuse.** The estate that cannot answer check 3 is the
    correctly installed one, so refusing would mean the tool mutating nothing
    anywhere. The shape is `--preflight`'s for a privilege audit the service
    account may not read: a `warning`-level finding, and the run proceeds.
  - **It is one entry per (target, check), not per account.** What could not be
    read is a grant on a database; an estate with forty accounts on one target
    would otherwise be told the same fact forty times. `creds generate` groups
    the constraints it cannot check the same way and for the same reason.
  - **It is printed, not only serialised.** The emitter prints the command's
    text rather than the document, so a run-level warning is invisible to
    somebody reading a terminal — and a guardrail that did not run, reported
    only in JSON, is reported to nobody who ran the command by hand (#309).

  An account the guardrails **refused** contributes no caveat: it was not
  touched, so what an unread check might have said about it changed nothing.
- ~~**The "operator named the account" half of the refusal rule is
  unreachable.**~~ **Built in #297**, which added `--account` along with
  `--target`, `--group` and `--application`. An account the operator named is
  now reported as `ERROR` rather than `SKIPPED` — the estate is left in exactly
  the same state either way, and the difference is entirely in the exit code,
  which is the difference §4 asks for: "quietly skipping it would report success
  for work nobody did".

  Two things about it are decisions. **Naming a target, group or application is
  not naming an account**, however few accounts it resolves to — the tempting
  reading is "the selection came out as one account, so they must have meant
  it", and that would make a safety rule change behaviour according to how many
  rows an estate happens to have today. And **a named account refused by check 1
  is not advised to use `--force`**, because check 1 is the one no flag reaches;
  it is told to declare the account instead.

**One more refusal joined its catalogue, and it is not an account check** (#149).
`sopuli lock break` refuses a lock that has not expired, and `--force` is what
takes it anyway. The generalisation that makes both cases one flag is *an audited
override of a guardrail that is asked of one thing at one moment* — this account,
now; this lock, now — as opposed to a safety setting, which is resolved from
layers and ratchets. #89 delimited the flag to checks 2–5 because those were the
guardrails that existed; the boundary it actually drew is the one below, and the
lock refusal is on the same side of it. Both cases report the override the same
way, and the second is visible in the run document as `lock.broken[].expired:
false`.

**`DBSNMP` is the case it exists for.** Rotating its password is ordinary DBA
work, and it is `ORACLE_MAINTAINED = 'Y'`, so check 2 refuses it. A tool with no
override does not prevent that rotation — it moves it to SQL\*Plus, where nothing
records that it happened. An audited override is the better failure.

**It takes two deliberate acts, not one.** `--force` alone will not rotate
`DBSNMP`: guardrail 1 still applies, so the account has to be declared as well —
in `accounts:` or an `applications:` entry, or, for a personal account, admitted
by `personal_accounts:` (H1, #449). That is invariant 5 — the config is the
whitelist, and a flag cannot extend it — and it is what keeps "unusual account,
deliberately managed" distinguishable from "typo that happened to be forced past".

**What it may never override is a safety setting.** `readonly`, `max_targets`,
`confirm_environments` and `dry_run` ratchet toward safe and no
higher-precedence source may relax them (invariant 10, `00-principles.md` P3).
`--force` is a higher-precedence source, so if it could relax any of them the
ratchet would not be one. The two sets are kept apart structurally rather than by
care: **`--force` is not a setting.** It never enters
`sopuli/settings/registry.py`, so there is no merge policy for it to have and no
layer for it to win — it is a per-invocation argument to §4's account checks and
nothing else. A `relax-but-bounded` merge policy was considered for it and is not
needed.

### Statement construction

The password cannot be a bind variable — DDL takes literals — so the tool builds:

```sql
ALTER USER "ORDERS_APP" IDENTIFIED BY "<generated>";
```

- **Passwords containing `"` are rejected, not escaped.** Oracle quoted
  identifiers have no escape sequence for a double quote; there is no correct
  escaping, so refusal is the only safe handling. The `alnum_safe` charset
  default already excludes it.
- Control characters and `CHR(0)` are rejected; byte length is checked against
  the target's limit (30 vs 128) in the database character set.
- The username in the statement is the spelling read back from `DBA_USERS` after
  validation, never the raw string from config.
- `CONTAINER=ALL` is appended only when the session is in `CDB$ROOT` **and** the
  account is a `C##` common user; otherwise the tool refuses rather than letting
  Oracle produce a confusing error. An **application** root or PDB is refused
  either way — **no longer.** Measured in #204
  (`sql/oracle/03_app_container_probe.sql`), the two halves are not alike. An
  application **root** is refused: a statement with no container clause is already
  container-wide there, so the tool's "no `C##` prefix, therefore local, therefore
  no clause" path produces an application-container-wide rotation, and no property
  of the name distinguishes it because `C##` names cannot exist in an application
  container. An application **PDB** takes the ordinary path: a local account there
  is ordinary, and an application-common one is refused by Oracle itself
  (`ORA-65066`, mapped) rather than by a guardrail that would also have blocked
  the working case. See UC-1 §6.2.
- **`ALTER USER "ORDERS_APP" ACCOUNT UNLOCK` is built the same way** (#300, UC-1
  §5's first attribute): the same identifier rules, the same container clause, and
  issued directly rather than wrapped, even though it carries nothing secret. The
  habit is what keeps the next statement safe, and the next one carries a
  password. It needs no grant beyond §2's `ALTER USER`.
- **`ALTER USER "ORDERS_APP" PROFILE "ORDERS_PROF"` likewise** (#301, §5's second
  attribute). The profile name goes through the same identifier rules and is the
  spelling read back from `DBA_PROFILES`, for the reason the username is. There is
  no function in the statement layer that builds an `ALTER PROFILE`, and there is
  not meant to be one: the credential-sync verbs assign a profile and never edit
  one, because a profile is shared and editing one reaches accounts nobody
  selected (§3, and Q4 decided in #88). Should UC-4 ever need to author profiles,
  it needs a builder this grant set does not authorise and a principal of its own,
  which is the point of keeping the absence visible here. The absence is structural rather than an omission: there is no
  `ALTER PROFILE` call site to review because nothing builds one — narrow by
  construction, the way invariant 2 keeps plaintext to a single `reveal()` rather
  than by remembering to mask at each place it could escape.
- **The built statement redacts itself.** It carries a password, so it is as
  sensitive as one: every stringification is `ALTER USER "X" IDENTIFIED BY ***`,
  which is also the form `--dry-run` prints, and the plaintext is reachable only
  through a `reveal()` named after the one on `Secret` so that grepping a single
  method name still finds every place plaintext can be had.

The statement layer refuses a password on its own terms, which is deliberately
not the same act as `passwords.check` finding a policy violation. UC-1 §4 lets an
operator waive the second with `--no-policy-check`; nothing waives the first. A
rule that can be turned off and a rule that cannot are two rules even where they
reject the same character, and merging them would make `--no-policy-check` a way
to switch off invariant 11.

### Where the password text can surface

Measured, not assumed. `sql/oracle/02_password_leak_probe.sql` plants a distinct
canary per execution path and sweeps 24 source/column pairs, reporting whether
each column is populated at all so that a "clean" on an empty column is labelled
inconclusive rather than counted as a pass.

**Every finding below is scoped to the versions its row names**, and it is not a
general statement about Oracle. The column head is 26ai Free 23.26.2.0.0 in both
`CDB$ROOT` and a PDB, which is where all of it was first measured; **21c XE
21.3.0.0.0, 18c XE 18.4.0.0.0 and 11g XE 11.2.0.2.0 were added on 2026-09-08
(#380, #381, #382)**, the first two in a PDB and the third a non-CDB. 21c and 18c
agree on every row they reached, and add the two they can answer and 26ai cannot
— `DBA_AUDIT_TRAIL` and `SYS.AUD$`, since 23ai desupported traditional auditing.

**11.2 disagrees on one row, and it is the most important one.** `V$SQLSTATS`
retains the `ALTER USER` text there, so the first row below holds on 18c, 21c and
26ai and *not* on 11.2. Everything else on 11.2 matched, including the
off-database greps, which were clean across 835 audit files.

**What the tool does about it: nothing, and says so** — decided in #387,
2026-09-09, and recorded as P8 in §8. The two alternatives were a runtime warning
on 11.2 and refusing to rotate there at all; both were declined, and the reasons
are in P8 because the second one would have reversed
[`00-principles.md`](00-principles.md) D7. What the decision rests on was measured
on the day it was taken, and it is the part worth carrying: **the retained text is
a window, not a record.**

**It is sopuli's own statement, not just the probe's.** #387 was filed off a
canary planted by `02_password_leak_probe.sql`; before deciding it, a real
`creds apply` was run against 11g XE through the ordinary path — Instant Client,
`SOPULI_SVC` holding exactly §2's grants, a password sopuli generated and wrote to
Vault and never showed anybody. Reading it back out of the vault and looking for it
in the dictionary finds this, with the password masked here by the sweep rather
than by Oracle:

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

The same session then confirmed both halves of the mitigation: `SOPULI_SVC` gets
`ORA-00942` from `V$SQLSTATS` and `V$SQL` alike, and one
`ALTER SYSTEM FLUSH SHARED_POOL` takes the row to `clean 0`.

| Question #387 asked | Measured, 11g XE 11.2.0.2.0, 2026-09-09 |
|---|---|
| Does `V$SQLSTATS` age the row out? | **Yes.** With `V$SQLSTATS` at its cap on this instance (~5,590 rows), a planted canary survived 2,000 further distinct statements and was gone by 3,000. Planted into a nearly empty pool it survived longer, and 20,000 evicted it |
| Does `ALTER SYSTEM FLUSH SHARED_POOL` clear it? | **Yes, immediately** — canary present before, absent after, both times it was run. That is the operator's remedy, and it is the operator's rather than the tool's: `ALTER SYSTEM` is a privilege §3 refuses, and flushing a production shared pool is a performance event nobody should get as a side effect of a rotation |
| Does it reach AWR? | **Still untested, and now attributably so** (unverified: ddl-text-awr). Two snapshots were taken and `DBA_HIST_SQLTEXT` *and* `DBA_HIST_SQLSTAT` came back empty of everything — XE ships `control_management_pack_access = NONE`, so nothing was captured at all. The clean result is the image, not the release. Answering it needs a licensed EE with the Diagnostics Pack |

So on 11.2 the exposure is: readable by anyone who can read the dictionary, for as
long as the shared pool keeps the entry, and removable in one statement. It is
smaller than "the password is on disk" and larger than nothing, which is why it is
documented rather than warned about or refused.

**The boundary is narrowed to one release, not closed** (unverified:
ddl-text-versions). 11.2 retains; **12.2.0.1.0 does not** (2026-09-29, #572, all
three positions, `V$SQLSTATS` clean for the plain `ALTER USER`), and neither do
18.4, **19.3.0.0.0** (2026-09-27, #548), **19.32.0.0.0** (2026-10-01, #581, all
three positions, an OCI Base Database Service DB system), 21.3 or 26ai. So the
behaviour changed somewhere in (11.2, 12.2]; 12.1 has no pullable image and has
not been run. 19.3 is the base release and 19.32 a release update, and they
agree. Read the 11.2 row as *11.2 retains* and not as *everything before 12.2
retains* — the second is plausible and, for 12.1, unevidenced. The password
byte limit (#383) (unverified: password-byte-limit) is the other version
question; 19.3 and 12.2 both answer 30 bytes, as 21c does, and 19.32 accepts 30
and refuses 128 (31 not tried). Since #595 the tool keys the limit to 23 rather
than 12.2, which agrees with every one of those. The `04-testing.md` §6 gate 2 records what
is open. A row that names only 26ai means only 26ai.

| Surface | 26ai 23.26.2.0.0, `CDB$ROOT` and PDB; 21c 21.3, 19c 19.3 and 19.32, 18c 18.4 and 12c 12.2.0.1 in a PDB (19.3, 19.32 and 12.2 in `CDB$ROOT` too); 11g 11.2 non-CDB | Action |
|---|---|---|
| `V$SQL`, `V$SQLAREA`, `V$SQLSTATS`, `GV$SQL` — the `CREATE/ALTER USER` statement itself | **no cursor for the DDL exists at all** on 26ai, 21c, 19.3, 19.32, 18c and 12.2. Not masked — absent. Holds for client-issued DDL and for DDL run via `EXECUTE IMMEDIATE` alike. **On 11.2 it does not hold**: `V$SQL` still has no cursor for the DDL, but `V$SQLSTATS` keeps its own copy and that copy outlives it, so the plain `ALTER USER … IDENTIFIED BY` sopuli issues is readable verbatim (measured 2026-09-08, #382). The service account cannot read the view (`ORA-00942`); a dictionary reader can. It ages out under ordinary shared-pool turnover and `ALTER SYSTEM FLUSH SHARED_POOL` clears it at once (2026-09-09, #387). **19.3.0.0.0 does not retain it** (2026-09-27, #548): `V$SQLSTATS` clean for the plain `ALTER USER` in all three positions, and **nor does 12.2.0.1.0** (2026-09-29, #572, all three positions), so the change happened somewhere in (11.2, 12.2]. **Nor does 19.32.0.0.0** (2026-10-01, #581, all three positions), the first release update measured — under `AUDIT_TRAIL = DB` as an OCI DB system ships it, and under `DB,EXTENDED`. **Unmeasured on 12.1** | 11.2: documented, not warned about and not refused — P8 in §8, and `../security-model.md` §5 is what an operator is told. Elsewhere: nothing to do, and re-run the probe on every version claimed as supported — this is a retention behaviour and not a documented guarantee, which is exactly how 11.2 came to differ |
| **An anonymous PL/SQL block carrying the password as a literal** | **leaks in full** into `V$SQL`, `V$SQLAREA`, `V$SQLSTATS`, `GV$SQL` and `V$DB_OBJECT_CACHE`. Oracle's protection is keyed to the `CREATE/ALTER USER` statement; a block that merely *contains* one is an ordinary block, and the block's own text is retained verbatim | **the tool never builds one.** Issue `ALTER USER` directly — invariant 13 |
| Unified audit `SQL_TEXT` | **masked to `IDENTIFIED BY *`, at write time.** Confirmed in the base table `AUDSYS.AUD$UNIFIED` as well as in `UNIFIED_AUDIT_TRAIL` | keep verifying the base table rather than the view: view-level redaction alone would be bypassable by anyone holding `SELECT ANY DICTIONARY` |
| AWR — `DBA_HIST_SQLTEXT` | **The wrapped literal reaches it** (unverified: ddl-text-awr). AWR on 19.32.0.0.0 (2026-10-01, #581), the first database here with the Diagnostics Pack (`DIAGNOSTIC+TUNING`, licence included): straight after position 1 planted its canaries, one root snapshot at flush level `ALL` captured **C3 verbatim** into `DBA_HIST_SQLTEXT` and `AWR_ROOT_SQLTEXT` (`command_type` 47, the PL/SQL block, in `ORCLPDB1`), uncolored. C1, C2 and C4 reached neither, before or after a second snapshot with the C3 cursor colored. The DB system keeps AWR for 8 days on hourly snapshots, so the wrapped literal outlives a shared-pool flush and sits on disk for a week. A quiet system: on a busy one the block may not rank into a snapshot's top SQL, which makes it less likely, not safe. Earlier releases could not answer this: XE ships `control_management_pack_access = NONE`, so snapshots on 11g XE for #387 captured nothing, and no snapshot was taken before the 26ai sweeps | invariant 13 again, on its most durable surface: the tool never builds the block. **Still open: whether 11.2's retained plain `ALTER USER` reaches AWR**, since no 11.2 here has the pack — that half is why the entry stays open |
| `V$SQL_BIND_CAPTURE` — bind values in SQL *predicates* | sampled at hard parse and retained in clear. Does not apply to rotation, since DDL cannot take binds. **Clean for the rotation on 19.32.0.0.0 with `ORA12C_STRONG_VERIFY_FUNCTION` enabled** (2026-10-01, #581), the OCI DB system's `DEFAULT`: the verify function receives the clear password on every `ALTER USER` and left it in no bind capture, in all three positions | constrains `check --method hash` if verifier comparison ever moves server-side: **never bind a password or a verifier into a predicate** — invariant 14 |
| SQL trace / 10046 | **run, and the assumption it replaces was the pessimistic one** (#407, 2026-09-11, 26ai 23.26.2.0.0 and 21c 21.3.0.0.0). A session traced at level 12 does **not** capture the password: the cursor is written truncated, `ALTER USER sopulitest IDE`, stopping one character into `IDENTIFIED`. Five traced sessions across the two releases, every one identical, and the same on 19.3.0.0.0 (#479) and 19.32.0.0.0 (2026-10-01, #581, twice). The wrapped form is the exception and leaks in full, which is invariant 13 on a fifth surface. This row said "untested — assume not redacted" until the greps were actually run | nothing to do, and the pessimism is retired rather than confirmed. Re-run `04_password_leak_extensions.sql` on any release added to the matrix: this is retention behaviour, not a documented guarantee, and that is precisely how 11.2 came to differ on the row above |
| OS audit files (`audit_file_dest`) — the SYSDBA path | **clean on 21c, 18c and 11.2 in position 1** (2026-09-08, #380, #381, #382), all three with `AUDIT_SYS_OPERATIONS = TRUE` and 11.2 across 835 files. **Position 2 — `svc_user = sys`, the position this row exists for — was run on 21c only** (2026-09-11, #407), so read the masked OS-file result below as *21c*, and position 1's clean sweep as the thing that covers 18c and 11.2. The verdict does not change on 21c:  the DDL is written to the OS file *masked*, `ACTION :[37] 'ALTER USER sopulitest IDENTIFIED BY *'`, and the only verbatim canary in 646 `ACTION` lines is the PL/SQL wrapper. Note what it took to get a trustworthy answer — the grep as written matched the canary *prefix*, which the probe's own SQL text contains, so it reported a leak in the one place a leak would matter most. Fixed to match the numbered canaries; a run before 2026-09-08 that reported a hit here was reading the probe | answered on 11.2 through 21c, and on **19.3.0.0.0 in all three positions** (2026-09-27, #548): position 2 is identical to 21c's — the DDL written masked, `ACTION :[37] 'ALTER USER sopulitest IDENTIFIED BY *'`, and C3 the only verbatim canary. The same on **12.2.0.1.0 in all three positions** (2026-09-29, #572), across 468 files, and on **19.32.0.0.0 in all three positions** (2026-10-01, #581), across 251 files. **On 26ai it is not clean, it is absent** — see the row below |
| OS audit files on **23ai and later** | **the surface is gone, and a clean grep there measures nothing** (#407, 2026-09-11, 26ai 23.26.2.0.0). `AUDIT_SYS_OPERATIONS = TRUE` is accepted and writes nothing useful: `audit_file_dest` held five files, each a session header plus one `ACTION` line, all five the same internal call, and **no `CREATE`, `ALTER` or `DROP USER` text reached it at all** — no file so much as names the test account. Traditional auditing is desupported on 23ai+, and this parameter belongs to it | read it as `pop=n` in OS-file form, exactly as the sweep labels an empty column `INCONCLUSIVE` rather than clean. There is nothing here to protect on 23ai+, which is a different claim from "we looked and found nothing", and the difference is the one this whole table is organised around |
| **Self-rotation** — `IDENTIFIED BY … REPLACE …` | **audited and masked on both secrets** (#407, 2026-09-11, 26ai and 21c). The statement is recorded as `ALTER USER sopulitest IDENTIFIED BY * REPLACE *`, attributed to the account itself rather than to a service account, by the `ACTIONS ALTER USER` unified policy on both releases and by traditional `AUDIT USER` on 21c. The `REPLACE` clause carries the account's *current* password, and it is masked with the same `*`. The same in both trails on 19.32.0.0.0 (2026-10-01, #581), where the test account had a profile with no verify function: the function would have been handed both secrets, and canaries sharing a prefix cannot satisfy its eight-character difference rule, so self-rotation *under* a verify function is unmeasured | the worry was that this path exercises no `ALTER USER` privilege, so *privilege* auditing could miss what *statement* auditing catches. It does not: **"rotations are audited" holds for the self-rotation path too**, which UC-1b needed before it could claim it. The path itself is still not this build |
| **`IDENTIFIED BY VALUES`** — the verifier | **masked** (#407, 2026-09-11, 26ai and 21c): `ALTER USER sopulitest IDENTIFIED BY VALUES *` in the trail, and under a level-12 trace the DDL truncates at the same character the password form does — `len=44` declared, `ALTER USER sopulitest IDE` printed. No raw verifier appears in any trace file or OS audit file on either release. Oracle masks a verifier the way it masks a password, which was a separate question and had never been asked. **On 19.32.0.0.0** (2026-10-01, #581) it is masked in the unified trail and appears in **neither `DBA_AUDIT_TRAIL` nor `audit_file_dest`**, where 19.3 had it masked in both: the traditional half is absent there, not clean, and the cause is not established — the SYSDBA login was a non-SYS user granted `SYSDBA`, and the statement is recursive | so a restore-from-verifier path, if one is ever added, does not widen the *audit* exposure. It stays offline-crackable wherever the verifier itself can be read, which is ADR-001's question and not this one. Needs `SELECT ON SYS.USER$`; where that is withheld, 6b is **unanswered** rather than clean. And the finding is about the DDL, not about every way of reaching it: a verifier written as a *literal* into a PL/SQL block leaks like any other literal — invariant 13 does not stop applying because the secret changed shape |
| Network | encrypted when NNE or TLS is in use | `sopuli doctor` warns on an unencrypted connection |
| Tool's own output and logs | redacted at the sink | covered by the redaction release gate, UC-1 §11 |

The probe is `sql/oracle/02_password_leak_probe.sql`. Run it in the three positions
its header describes — PDB with a non-SYSDBA service account, PDB as SYSDBA, and
`CDB$ROOT` — and record the outcome in `04-testing.md` §6 gate 2. The
service-account position is the only one that proves anything about the audit
policy; see `04-testing.md` §6 gate 2.

**Then run `sql/oracle/04_password_leak_extensions.sql`**, which is the other
three checks the probe's §6 and §7 described in comments and left for somebody to
do by hand. Nobody did, for six weeks, and #407 is what that cost: two of the
three bore on claims this document was already making. **A check that is a comment
is a check that does not run**, which is the same defect as a flag named in a
specification and never built — the extensions are a file now for that reason
rather than a tidier one.

It has one ordering trap, measured on both releases before it was understood. The
main probe's §8 cleanup drops `SOPULI_PROBE_POL` and issues `NOAUDIT USER`, so
running the extensions straight afterwards records nothing and reports a masking
result it did not earn. **The dangerous form of that failure is 21c's**, not
26ai's: on 26ai nothing at all was enabled and the trail came back visibly empty,
while on 21c the Oracle-supplied `ORA_SECURECONFIG` policy covers `ALTER USER` and
the trail looked populated anyway. An empty result announces itself; a result
produced by a policy you did not think you were testing does not.

---

## 5. Auditing

With no package there is no `SOPULI_AUDIT` table, so the database-side trail is
unified auditing alone — which is the authoritative one anyway, since it does not
depend on the tool behaving.

```sql
CREATE AUDIT POLICY sopuli_pol
  ACTIONS ALTER USER, CREATE USER, DROP USER;
AUDIT POLICY sopuli_pol;
```

Given `ALTER USER` is now the whole privilege model, this policy is not optional
housekeeping — it is the compensating control. Enable it before the first
rotation, not after the first incident.

**Correlation still works.** The tool calls
`DBMS_SESSION.SET_IDENTIFIER(<correlation_id>)` on every connection, so its UUID
lands in `UNIFIED_AUDIT_TRAIL.CLIENT_ID`. That is the join between the tool's
JSON output, the database trail, and the vault's secret metadata — the property
that made the package's local audit table useful is preserved without the table:

```sql
SELECT event_timestamp, dbusername, action_name, object_name, return_code
  FROM unified_audit_trail
 WHERE client_id = '9f1c2e7a-4d3b-4a51-9d2c-0b7f8e6a1234'
 ORDER BY event_timestamp;
```

On 11.2, fall back to `AUDIT ALTER USER` and `DBA_AUDIT_TRAIL`, where
`CLIENT_ID` also exists.

Implemented in #176, on **every** connection rather than only on the ones that
mutate something: a session that shows up in the trail with no `CLIENT_ID` is
the one somebody has to account for afterwards, and the cost of setting it is
one round trip on a connection that has already been made. It is set before
anything else happens on the session, so there is no window in which a statement
could be audited without it — and a session that cannot be labelled is closed
rather than used, because carrying on would silently give up the join this
section exists to provide.

The call **binds** the id rather than building a string, which is the exact
inverse of invariant 14 and worth stating beside it: `V$SQL_BIND_CAPTURE` keeps
bind values in clear, which is precisely why a password must never be bound and
why a correlation id is a good thing to have captured. The dangerous habit is
the other one — a `SET_IDENTIFIER` assembled by concatenation is the pattern
that later writes a password into SQL text.

Tier 1 asserts it from the database's own side, reading
`SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER')` — the value `UNIFIED_AUDIT_TRAIL.
CLIENT_ID` is populated from — so the property is checked without requiring an
audit policy on the test container.

Worth auditing alongside it: failed logons by the service account, which is what
credential probing looks like.

---

## 6. When the package would be worth reconsidering

Not now, and possibly never — but the distinction is worth recording, because it
is about the *stored* credential rather than the operator.

An interactive DBA already holds SYSDBA, so granting the tool `ALTER USER` gives
away nothing. An **unattended scheduled runner** is different: its credential sits
in a CI system, a container, or a systemd unit, authenticated by machine identity
and used without a human present. If that credential is stolen it is a full
database compromise, and it has a broader exposure surface than a DBA's own
login.

UC-1 §S2 assumes exactly this — nightly `check`, weekly `rotate` from a scheduler.
So the honest position is: direct grants for the interactive and initial case;
revisit the package **only if** unattended rotation in a hostile-ish environment
becomes a real deployment pattern, and only for that runner's credential. A
sensible middle option if it comes to that is a read-only service account for
scheduled `check` plus an `ALTER USER` account used only by `apply`/`rotate`.

Filed as an option, not a plan. If it is ever taken up, write the package fresh
against the design as it stands then — the earlier draft was never executed and
is not worth recovering.

---

## 7. Files

| File | Purpose |
|---|---|
| `sql/oracle/00_install.sql` | create the service account and grant it, with non-CDB / common-user / per-PDB variants |
| `sql/oracle/01_audit_policy.sql` | unified audit policy and correlation queries |
| `sql/oracle/02_password_leak_probe.sql` | release gate 2: canary probe for password text retained anywhere queryable |
| `sql/oracle/05_verifier_layout_probe.sql` | #431: reads the `SPARE4` verifier layout and locates the salt from a traced logon; derives nothing |
| `sql/oracle/06_verifier_reproduce.{sql,py}` | #432: regenerates each stored `T:`/`t:` digest client-side and compares byte-for-byte, static passwords and a rollover window |
| `sql/oracle/99_uninstall.sql` | remove the account and policies |
| `docs/decisions/adr-001-privilege-model.md` | why this model, what was rejected, and when to revisit |

All scripts are idempotent and report what they did.

---

## 8. Open questions

| # | Question | Leaning |
|---|---|---|
| P1 | Common `C##` service user or per-PDB local, as the documented default? | common, with per-PDB documented for multi-tenant ownership |
| ~~P2~~ | ~~Grant `SELECT ON SYS.USER$` by default, to enable hash mode and the `LCOUNT` guard?~~ | **decided: no** (#86, 2026-08-18). Optional, capability-probed grant instead — see §2. `check` defaults to `login` unconditionally either way; whether to *recommend* the grant, and whether `SELECT_CATALOG_ROLE`/`KU$_USER_VIEW` is a narrower alternative, is deferred to #124 |
| ~~P3~~ | ~~Should `--force` exist at all?~~ | **decided: yes — one flag, overriding checks 2–5 of §4 and nothing else** (#89). Managing `DBSNMP`'s password is ordinary DBA work, and it is `ORACLE_MAINTAINED` — so a tool with no override does not prevent that rotation, it just makes it happen in SQL\*Plus where nothing records it. Per-check flags were rejected: a growing flag surface for a rare case, one more flag with every new guardrail. The bluntness is real and accepted — a DBA who wanted to bypass one check bypasses four — and is what §4's audit record is for. It never touches guardrail 1 (invariant 5), and it is **not a setting**: see below |
| P4 | One service account per database, or per application? | per database; the config's declared accounts provide the finer scoping |
| ~~P5~~ | ~~Does `doctor` fail or warn on over-granted privileges?~~ | **decided: warn** (#213). Failing would block the person who ran it, mid-incident, over a condition they did not create and cannot fix from this side — and the over-grant is somebody else's decision. So `--check-privileges` populates `scope.over_granted` and prints a line naming what to `REVOKE`, and leaves the exit code alone. A flag to gate on it (`--fail-on-over-grant`) was considered and not added: P3 already rejected a growing flag surface for rare cases, and adding one later is cheap where removing one is not |
| P6 | 11.2 support — worth the `DBA_AUDIT_TRAIL` and `ORACLE_MAINTAINED` special cases? | keep for now, drop if it starts costing real complexity |
| ~~P7~~ | ~~Do the 23-codebase schema privileges cover `ALTER USER`?~~ (§2.1) | **decided: no — tested 2026-08-17 on 26ai 23.26.2.0.0.** `GRANT ALTER USER ON SCHEMA` gives `ORA-00990: missing or invalid privilege`, while `GRANT SELECT ANY TABLE ON SCHEMA` succeeds in the same session — so the feature works and the refusal is specific to `ALTER USER`, not an artefact of the environment. Nothing lands in `DBA_SCHEMA_PRIVS`. The direct grant in §1 is the model on every supported release, the scoped-grant alternative does not exist, and ADR-001's P7 trigger is closed |
| ~~P8~~ | ~~On 11.2 the `ALTER USER` text survives in `V$SQLSTATS` (§4). Document it, warn at runtime, or refuse to rotate there?~~ | **decided: document it** (#387, 2026-09-09). The exposure needs a dictionary grant — the service account itself gets `ORA-00942` from the view, so it is not self-inflicted and §2's grant set does not narrow — and it is a *window*: it ages out with the shared pool and `ALTER SYSTEM FLUSH SHARED_POOL` removes it at once, both measured. **A runtime warning was the close call and was declined on what it would cost**: nothing can probe this. "Does this release retain DDL text?" is not answerable from a session holding §2's grants, so the warning would have to branch on `V$INSTANCE.VERSION` — a version branch, which is the shape invariant 3 exists to prevent, taken in the one place the tool cannot check its own answer. Buying a diagnostic with a rule that exists because version branches go stale is a bad trade for a fact that does not change per database. **Refusing was rejected outright**: it reverses D7 over a bounded, clearable exposure on a release the project deliberately supports, and it would leave the operator rotating in SQL\*Plus, which retains the same text and records nothing. What is owed instead is that the operator be told — `../security-model.md` §5 — and that the boundary below 18c stop being asserted from one measurement |

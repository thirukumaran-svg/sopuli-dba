# sopuli-dba — Oracle privileges and grants

Status: draft / sketch. **The SQL in `sql/oracle/` is unrun and untested.**
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
GRANT SELECT ON SYS.V_$DATABASE    TO sopuli_svc;
GRANT SELECT ON SYS.V_$INSTANCE    TO sopuli_svc;
```

`SELECT_CATALOG_ROLE` covers all four in one grant and is a reasonable
convenience choice — it reaches the `DBA_*` and `V$` views but **not** base
tables such as `SYS.USER$`. The explicit list is the documented default because
it makes a privilege review trivial; the role is fine if your site prefers it.

### CDB with common users — one grant covers every container

This is where the direct model pays off most obviously:

```sql
-- in CDB$ROOT
CREATE USER c##sopuli_svc IDENTIFIED BY "…" CONTAINER=ALL;

GRANT CREATE SESSION TO c##sopuli_svc CONTAINER=ALL;
GRANT ALTER USER     TO c##sopuli_svc CONTAINER=ALL;
GRANT SELECT ON SYS.DBA_USERS    TO c##sopuli_svc CONTAINER=ALL;
GRANT SELECT ON SYS.DBA_PROFILES TO c##sopuli_svc CONTAINER=ALL;
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
`CLAUDE.md`) rather than assumed from config, and used for two things:

- **The `LCOUNT` guard** — refuse a login attempt within `--lockout-margin` of
  the account's `FAILED_LOGIN_ATTEMPTS` limit (UC-1 §7 mitigation 2). This is
  the one place the grant changes *behaviour*, not just what's queryable:
  without it, `--method login` still runs, on UC-1 §7's remaining runtime
  mitigations (1/3/6 — never retry, reset on success, `ACCOUNT_STATUS`
  reporting), and `check` must report the guard's absence plainly rather than
  silently run a weaker version of it.
- **`check --method hash`**, if it ships at all — see below.

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
`LCOUNT` guard without exposing verifiers at all. That claim comes from a blog
post, not Oracle documentation, and needs the same measure-don't-trust
treatment #124 gives it before it goes anywhere near the install script.

**`--method hash` remains unresolved, independent of the grant question:** the
`T:` (12C, PBKDF2-SHA512) verifier layout in `SPARE4` must be reproduced
client-side for hash mode to work at all (#90). Prototype it against a
throwaway 19c before committing `--method hash` to the CLI. If it does not
reproduce reliably, drop hash mode from the CLI surface entirely — `login`
with the optional `LCOUNT` guard is already the complete default path, so
nothing else depends on the outcome.

---

## 3. What must not be granted

| Not granted | Why |
|---|---|
| `SELECT ANY DICTIONARY` | includes `SYS.USER$` *and* everything else; if hash mode is wanted, grant `SELECT ON SYS.USER$` specifically |
| `DBA`, `PDB_DBA`, `CDB_DBA` | the tool needs `ALTER USER`, not a role that carries a hundred other privileges |
| `SYSDBA` / `SYSOPER` | never; the tool has no operation that requires it |
| `ALTER PROFILE` | see UC-1 Q4 — the tool reports the DDL needed to enable password rollover rather than changing a shared profile itself |
| `CREATE USER` / `DROP USER` | account provisioning is out of scope for UC-1 |
| `ALTER SYSTEM`, `GRANT ANY *`, `BECOME USER` | no operation needs them |
| `EXECUTE ON DBMS_LOCK` | P5's advisory lock lives in the vault, not in the database (Q2, decided in #83). It was the one grant a `DBMS_LOCK`-based lock would have added, and the reason it is not here is that session-scoped locking does not solve the problem it looked like it solved: a stalled run's session is still alive, so its lock prevents nothing while its plan goes stale. A fencing token re-checked before every mutation does, and it needs nothing from the database |

`sopuli doctor --check-privileges` reports what the service account actually
holds and flags anything on this list. Over-granting is the common failure when
someone is debugging a permissions problem at 17:00 on a Friday; the tool should
notice and say so rather than quietly benefit from it.

---

## 4. Guardrails, now client-side

Dropping the package moves the account-safety checks into the tool. They stop
being a security boundary — a compromised service credential bypasses them
entirely — and become what they realistically were for an operator with SYSDBA
anyway: **protection against typos and against a config change with a wider blast
radius than intended.** Worth keeping, worth being honest about.

Before any `ALTER USER`, the tool refuses when the target account:

1. is not among the config's declared `accounts` (inline, or in an `applications`
   entry) — the config *is* the whitelist, just advisory rather than enforced
2. has `DBA_USERS.ORACLE_MAINTAINED = 'Y'` — covers SYS, SYSTEM, DBSNMP,
   GSMADMIN_INTERNAL and the rest without a hand-maintained list going stale
3. appears in `V$PWFILE_USERS`
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
`DBSNMP`: guardrail 1 still applies, so the account has to be declared in
`accounts:` as well. That is invariant 5 — the config is the whitelist, and a
flag cannot extend it — and it is what keeps "unusual account, deliberately
managed" distinguishable from "typo that happened to be forced past".

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
  either way, pending a real one to verify against — see UC-1 §6.2.
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

**Every finding below is scoped to Oracle AI Database 26ai Free 23.26.2.0.0, in
both `CDB$ROOT` and a PDB.** It is not a general statement about Oracle. No other
version has been run; the README's gate-2 table records what is still open.

| Surface | 26ai 23.26.2.0.0, `CDB$ROOT` and PDB | Action |
|---|---|---|
| `V$SQL`, `V$SQLAREA`, `V$SQLSTATS`, `GV$SQL` — the `CREATE/ALTER USER` statement itself | **no cursor for the DDL exists at all.** Not masked — absent. Holds for client-issued DDL and for DDL run via `EXECUTE IMMEDIATE` alike | nothing to do on this version; re-run the probe on every version claimed as supported, because this is a retention behaviour and not a documented guarantee |
| **An anonymous PL/SQL block carrying the password as a literal** | **leaks in full** into `V$SQL`, `V$SQLAREA`, `V$SQLSTATS`, `GV$SQL` and `V$DB_OBJECT_CACHE`. Oracle's protection is keyed to the `CREATE/ALTER USER` statement; a block that merely *contains* one is an ordinary block, and the block's own text is retained verbatim | **the tool never builds one.** Issue `ALTER USER` directly — invariant 13 |
| Unified audit `SQL_TEXT` | **masked to `IDENTIFIED BY *`, at write time.** Confirmed in the base table `AUDSYS.AUD$UNIFIED` as well as in `UNIFIED_AUDIT_TRAIL` | keep verifying the base table rather than the view: view-level redaction alone would be bypassable by anyone holding `SELECT ANY DICTIONARY` |
| AWR — `DBA_HIST_SQLTEXT` | **untested.** It reported `pop=y` in one FREEPDB1 run and `pop=n` in the next, and no snapshot was taken before the sweep, so "clean" here is an absence of evidence | take an AWR snapshot, then re-run the sweep. Needs the Diagnostics Pack. Stays untested until then — not clean |
| `V$SQL_BIND_CAPTURE` — bind values in SQL *predicates* | sampled at hard parse and retained in clear. Does not apply to rotation, since DDL cannot take binds | constrains `check --method hash` if verifier comparison ever moves server-side: **never bind a password or a verifier into a predicate** — invariant 14 |
| SQL trace / 10046 | **untested.** The probe's §7 emits the `grep` commands; they have not been run | run them. Until then assume not redacted: the tool never enables trace on its own sessions, and a DBA who traces this session captures the password |
| OS audit files (`audit_file_dest`) — the SYSDBA path | **untested**, same reason | run the §7 greps, and run the probe once with `svc_user = sys` to exercise the path. Matters most on 11.2, where `AUDIT_SYS_OPERATIONS` writes statement text to files no query in the probe can see |
| Network | encrypted when NNE or TLS is in use | `sopuli doctor` warns on an unencrypted connection |
| Tool's own output and logs | redacted at the sink | covered by the redaction release gate, UC-1 §11 |

The probe is `sql/oracle/02_password_leak_probe.sql`. Run it in the three positions
its header describes — PDB with a non-SYSDBA service account, PDB as SYSDBA, and
`CDB$ROOT` — and record the outcome in the README's gate-2 table. The
service-account position is the only one that proves anything about the audit
policy; see `04-testing.md` §6 gate 2.

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
| P5 | Does `doctor` fail or warn on over-granted privileges? | warn; failing would block someone mid-incident |
| P6 | 11.2 support — worth the `DBA_AUDIT_TRAIL` and `ORACLE_MAINTAINED` special cases? | keep for now, drop if it starts costing real complexity |
| ~~P7~~ | ~~Do the 23-codebase schema privileges cover `ALTER USER`?~~ (§2.1) | **decided: no — tested 2026-08-17 on 26ai 23.26.2.0.0.** `GRANT ALTER USER ON SCHEMA` gives `ORA-00990: missing or invalid privilege`, while `GRANT SELECT ANY TABLE ON SCHEMA` succeeds in the same session — so the feature works and the refusal is specific to `ALTER USER`, not an artefact of the environment. Nothing lands in `DBA_SCHEMA_PRIVS`. The direct grant in §1 is the model on every supported release, the scoped-grant alternative does not exist, and ADR-001's P7 trigger is closed |

# UC-1 — Application database account credentials: vault as master, sync to database

Status: draft / sketch
Depends on: `../design/00-principles.md`, `../design/01-configuration.md`

---

## 1. Summary

**Goal.** An application uses 1..N database accounts. The vault is the master
record of those passwords. The tool generates passwords, writes them to the
vault, applies them to the database, and verifies that the two agree.

**Actors.**

| Actor | Role |
|---|---|
| DBA / platform operator | runs the tool interactively for planned changes |
| Scheduler (cron, CI, systemd timer) | runs `check` continuously and `rotate` on cadence |
| Application | reads the password from the vault at startup or on reconnect; never talks to the tool |

**Direction of truth.** Vault → database, always. The database is never the
source. If they disagree, the fix is to re-apply from the vault, not to read the
database (which is impossible anyway — passwords are not readable).

**Non-goals for UC-1.** Creating or dropping accounts, grants and roles, personal
developer accounts (a separate use case), application-side reload/restart
orchestration.

---

## 2. Commands

```
sopuli creds generate   # new password → vault (does not touch the database)
sopuli creds apply      # vault → database (does not generate)
sopuli creds check      # do vault and database agree?
sopuli creds rotate     # generate + apply + check, as one guarded operation
sopuli creds status     # inventory: accounts, ages, versions, last rotation

sopuli creds promote          # finish an interrupted rotation (pending → current)
sopuli creds finish-rollover  # end an Oracle password rollover window early
```

Separating `generate` from `apply` is deliberate: it lets an operator stage a new
password, get a change window approved, and apply later — and it makes each half
independently retryable.

### Common selectors

Every command takes the same target/account selection options:

```
--application NAME      one entry from the `applications:` config section
                        (omit it entirely in a single-application config)
--account NAME          repeatable; filters accounts within the selection
--target NAME           repeatable
--group NAME            a named or selector-based group
--select k=v[,k=v]      filter by target labels, e.g. --select env=dev,tenant=beta
--all                   everything in config (requires --confirm)
--limit N               refuse if the plan exceeds N targets
--dry-run / --confirm / --output {text,json,jsonl}
```

**These are filters over what the config declares, not a second way of addressing
things.** The tool never acts on an account that is not in the config; a selector
narrows the declared set, it cannot extend it. With no selector at all, a command
covers everything declared — which is what makes `sopuli creds check` on its own
a meaningful scheduled job.

Selection is resolved and printed *before* anything is touched. Every command
starts by showing a plan.

---

## 3. State model

For each (account, scope) pair the tool reasons about a small state:

```
VaultState  = { current, pending?, previous?, version, updated_at, updated_by }
DbState     = { exists, lock_status, profile, password_versions,
                password_change_date, rollover_active?, container_scope }
SyncState   = IN_SYNC | DRIFT | PENDING_APPLY | ROLLOVER_ACTIVE
            | ACCOUNT_MISSING | LOCKED | UNVERIFIABLE
```

`SyncState` is what `check` reports and what `apply` acts on. The three fields in
the vault payload are the whole rotation mechanism:

```json
{
  "username": "ORDERS_APP",
  "password": "<current>",
  "pending":  "<generated, not yet applied>",
  "previous": "<the one before current>",
  "rotated_at": "2026-08-04T09:12:33Z",
  "rotated_by": "approle:sopuli-ci",
  "policy": "app-standard",
  "targets": ["cdb1-pdb-orders", "cdb1-pdb-billing"]
}
```

On a store with native staging (OCI, AWSSM) these map to version stages instead
of extra fields; the tool abstracts over that but reports which mechanism it used
— with one exception, below.

### The layout, and the one rule that covers both (Q7, decided in #85)

The documented default is **one secret per application, a field per account** —
`tenants/{tenant}#DB_CREDENTIALS/{account}`, the layout
`../design/01-configuration.md` §2 already uses. One secret per account remains
fully supported; a `secret` or `secret_template` naming a single field is the
same code path.

What differs between the two is only *how many accounts live in one document*,
and the payload follows from one rule:

> **Every root-level key mirrors the shape of the current-stage container.**

The container is what the configured ref addresses — the field, and any pointer
below it. Where that is a scalar, `pending`, `previous` and the rotation stamps
are scalars beside it, which is the payload above, unchanged. Where it is a map
keyed by account, they are maps keyed the same way:

```json
{ "DB_CREDENTIALS": { "acme_web_user": "<current>", "acme_api_user": "<current>" },
  "pending":        { "acme_web_user": "<generated, not yet applied>" },
  "previous":       { "acme_web_user": "<the one before current>" },
  "rotated_at":     { "acme_web_user": "2026-08-04T09:12:33Z", "acme_api_user": "…" },
  "rotated_by":     { "acme_web_user": "approle:sopuli-ci", "acme_api_user": "…" },
  "policy":         { "acme_web_user": "app-standard", "acme_api_user": "app-standard" },
  "targets":        { "acme_web_user": ["cdb1-pdb-orders"], "acme_api_user": ["…"] } }
```

Three things fall out of it, and each is why the rule is worth stating as a rule:

- **No new pointer syntax, and no nesting of the triple.** `#DB_CREDENTIALS/…`
  and `#pending/…` take the same pointer below the same key, so C14's
  `@stage=pending` means "the `pending` sibling, same key" in both layouts.
- **The ref an application reads does not change.** It still resolves to a
  password string, which is what rules out the other candidate shape — an object
  per account, holding its own triple. That would have made every consumer read a
  document and dig, to save the tool a rule it needs anyway.
- **The stamps sit beside the value they describe.** They are per-account because
  a single account can be rotated inside a shared document, and a root-level
  `rotated_at` would then describe some of the document and not the rest.
  `username` has no counterpart in the shared layout: the map key *is* the
  username, and a second copy is a thing that can disagree with itself.

**Native staging is the exception the first paragraph names.** An OCI or AWSSM
version stage is per *secret*, so it cannot promote one account's `pending`
without promoting every account's. A document holding more than one account's
credential therefore emulates the three stages in payload fields even on a store
that has them natively, and the run reports the emulated mechanism — which is
the reporting §3 already requires, with the condition now made explicit rather
than left to be discovered. Where each account has its own secret, native staging
is used as before.

**Sharing a document is not sharing a lock by accident.** Two accounts in one
document contend, deliberately: Q2 keys the lock on the path, so the second run
loses on the lock and exits 7 naming the holder, rather than racing to a lost
update. Under the common workflow — rotate an application's accounts together —
that is one lock, one document and one write for the whole application.

**Why `pending` exists.** Ordering is the central risk in this use case:

- Write vault first, then apply → if apply fails, the vault advertises a password
  the database does not have. Applications break at next credential fetch.
- Apply first, then write vault → if the vault write fails, nobody can obtain the
  new password. Applications break at next credential fetch, and the correct
  password now exists nowhere.

The `pending` field removes the window: the candidate is durably stored *before*
the database is touched, but `current` — the field applications read — is only
promoted after the database confirms. A crash at any point leaves a state the
tool can resume, and `check` can explain.

---

## 4. `sopuli creds generate`

Generate a password per the policy and write it to the vault's `pending` slot.
Does not connect to the database — except optionally to read constraints.

```
sopuli creds generate --application orders-app [--account ORDERS_APP]
                      [--promote]         # write straight to `current` (no staging)
                      [--from-stdin]      # take a supplied password instead of generating
                      [--policy NAME]     # override the policy
```

**Flow**

1. Resolve selection and policy; resolve SecretRefs from templates.
2. If reachable, connect to one representative target to read *constraints*:
   database character set, max password length, verify function presence,
   `PASSWORD_REUSE_*`, `PASSWORD_VERSIONS`. Constraints from the strictest target
   in the selection win. If no target is reachable, fall back to the policy's
   declared limits and say so in the output.
3. Generate from a CSPRNG. Reject and regenerate candidates that violate charset,
   first-character, length-in-bytes, or composition requirements. Bounded retries.
4. Acquire the lock for the secret path (Q2, #83) — which `generate` can do
   precisely because the lock lives in the vault: this step never connects to a
   database, so a database-side lock could not have protected the write below.
5. Write to the vault: `pending = candidate`, leave `current` untouched. Use CAS
   where supported so a concurrent writer cannot be overwritten silently.
6. Report new version, and the fact that the database has not changed.

**Notes**

- Generation and validation are `sopuli/passwords.py`, and step 3's "reject and
  regenerate" runs against the *same* predicate `--from-stdin` uses. A policy that
  declares no `length` is refused rather than defaulted; a policy no password could
  satisfy is refused before any drawing, naming what is wrong
  (`01-configuration.md` §8).
- `--from-stdin` exists for migration and for cases where an external system
  dictates the password. It validates against policy and refuses on violation
  unless `--no-policy-check` is passed, which is recorded in the audit event. It
  reads `length:` as a minimum rather than as an exact figure — a password an
  external system dictated is not weaker for being longer.
- Generating twice without applying simply replaces `pending`. That is safe and
  is reported as such.

---

## 5. `sopuli creds apply`

Take what the vault holds and make the database match it.

```
sopuli creds apply --application orders-app
                   [--source {pending,current}]   # default: pending if set, else current
                   [--strategy {rollover,staged,direct}]
                   [--continue-on-error]          # default: fail fast
                   [--repair]                     # only act on targets check says DRIFT
```

**Flow, per target**

1. Connect using the target's admin credential (§ P2 bootstrap order).
2. Verify scope: the connection really is in the container the config claims;
   the database is open read-write; version and capabilities as expected.
3. Verify the account exists and read its state (locked? profile? verifiers?).
   Missing account → `ACCOUNT_MISSING`, do not create it (out of scope for UC-1).
4. Pre-flight the password against the target's verify function where possible.
5. Change the password (see § 6 for the Oracle statement details).
6. Verify immediately with a fresh connection as that user (§ 7).
7. Record a per-target result.

**After all targets**

- All succeeded → promote in the vault: `previous = current`, `current = pending`,
  clear `pending`, stamp `rotated_at`/`rotated_by`. Exit 0.
- Some failed → do **not** promote. `pending` stays. Report per-target status and
  exit 4 (partial). The remedy is `apply --repair`, which is safe to re-run.
- All failed → nothing changed anywhere. Exit 1.

**Multi-target atomicity.** There is no distributed transaction across databases.
The tool is explicit about this: it applies target by target, and the vault
promotion is the single commit point that makes the new password visible to
applications. Sequence for a group of PDBs sharing one secret:

```
  pending written
     │
     ├─ apply → PDB ORDERS   ok
     ├─ apply → PDB BILLING  ok
     │
  promote current  ← only now do applications see the new password
```

If BILLING fails, ORDERS is already changed but `current` still holds the old
password — which is exactly why **rollover strategy is the default on databases
that support it**: during the rollover window both passwords work, so a partial
apply causes no outage at all.

**Attributes.** `apply` may also enforce non-password attributes declared in the
policy, each opt-in: profile assignment, account unlock, `PASSWORD_EXPIRE`
handling, default/temporary tablespace. Each is reported as a separate change so
the diff stays readable.

---

## 6. Oracle specifics

### 6.1 The statement

```sql
ALTER USER "ORDERS_APP" IDENTIFIED BY "<new>";
```

Points that matter:

- **Passwords cannot be bind variables.** DDL is literal text, so the password
  appears in the statement. Consequences to handle and document:
  - quote the password and escape embedded `"` — or avoid `"` entirely via the
    `alnum_safe` charset default
  - **not in `V$SQL`, on 26ai.** Measured on 26ai Free 23.26.2.0.0 in `CDB$ROOT`
    and a PDB: no cursor for the DDL is retained at all, so there is nothing to
    mask. Unified audit does retain the statement, masked to `IDENTIFIED BY *` at
    write time, in `AUDSYS.AUD$UNIFIED` as well as the view. Neither result is a
    general Oracle guarantee — re-verify per version with
    `sql/oracle/02_password_leak_probe.sql`. **SQL trace remains untested** (the
    greps in the probe's §7 have not been run), as do trace-consuming 3rd-party
    monitors. The tool: never enables trace on its own sessions, keeps the
    statement out of its own logs, and documents the residual risk.
  - **Never wrap the statement in an anonymous PL/SQL block.** Issue `ALTER USER`
    directly. Wrapping does not move the DDL literal into the shared pool — the
    DDL literal never reaches it either way — it *adds* an exposure, because the
    wrapper block's own text is retained verbatim in `V$SQL`, `V$SQLAREA`,
    `V$SQLSTATS`, `GV$SQL` and `V$DB_OBJECT_CACHE`. Oracle's protection is keyed
    to the `CREATE/ALTER USER` statement; a block that merely contains one is an
    ordinary block. Invariant 13.
- **Privileges.** `ALTER USER` is a system privilege with no object scope — there
  is no way to grant it for specific accounts only. The tool requires it and
  nothing more; in particular it must never require `DBA` or `SELECT ANY
  DICTIONARY`. Which accounts may be touched is enforced client-side from the
  config's `applications` section (or the inline `accounts:` list). See `../design/02-oracle-privileges.md`.
- **`IDENTIFIED BY new REPLACE old`** is required when a user changes *their own*
  password without holding the `ALTER USER` privilege and a password verify
  function is assigned to their profile. This matters only in self-rotation mode
  (the tool connecting as the account itself, Q6) — and there the old password is
  exactly what the vault's `current` field holds, so it is available. An admin
  holding `ALTER USER` never needs `REPLACE`.

### 6.2 Common users and containers

| Scope | Statement | Notes |
|---|---|---|
| non-CDB | `ALTER USER x IDENTIFIED BY …` | plain |
| PDB, local user | connect to the PDB service, then plain `ALTER USER` | one password per PDB unless the secret is shared |
| CDB root, common user | `ALTER USER "C##MON" IDENTIFIED BY … CONTAINER=ALL` | must be connected to `CDB$ROOT`; `CONTAINER=ALL` is the config's `oracle.container_clause` |
| Application container | connect to the application root; `CONTAINER=ALL` applies within the application container only | distinct scope, must not be conflated with CDB root |

Guardrails: refuse `CONTAINER=ALL` when not connected to a root; refuse to treat
`C##`-prefixed names as local users; refuse to apply to a PDB that is not
`OPEN READ WRITE`; skip (with a clear status) PDBs that are closed or in a
standby, rather than failing the whole run.

### 6.3 Gradual password rollover (19.12+/21c) — the default strategy

Where available, this makes zero-downtime rotation real:

1. The account's profile has `PASSWORD_ROLLOVER_TIME` > 0 (e.g. `1` day).
2. `ALTER USER x IDENTIFIED BY <new>` starts the rollover window. **Both the old
   and the new password authenticate** until the window closes.
3. Applications pick up the new password from the vault on their own schedule
   (restart, connection pool refresh, credential refresh loop).
4. When the window is confirmed complete:
   `ALTER USER x EXPIRE PASSWORD ROLLOVER PERIOD;` ends it early.

Tool support:

- `--strategy rollover` (default when the capability exists) verifies the profile
  actually has a non-zero `PASSWORD_ROLLOVER_TIME`; if not, it reports the exact
  `ALTER PROFILE` needed rather than silently changing a profile that affects
  other accounts.
- `check` reports `ROLLOVER_ACTIVE` with time remaining rather than calling it
  drift.
- `sopuli creds finish-rollover` ends the window explicitly.
- Fallback for databases without the capability: `--strategy staged`, meaning the
  tool applies and reports, and the operator owns the app-side restart. Documented
  as "brief authentication failures possible for connections established with the
  old password after the change".

### 6.4 Errors worth handling by name

| Error | Meaning | Tool behaviour |
|---|---|---|
| ORA-28003 | password verify function rejected it | regenerate (bounded), preserve the server message |
| ORA-28007 | password cannot be reused | regenerate; never retry the same value |
| ORA-01017 | invalid credentials | verification failure → drift, not a crash |
| ORA-28000 | account locked | report `LOCKED`; do not unlock unless policy says so |
| ORA-28001 | password expired | distinguish from drift; can be resolved by apply |
| ORA-28002 | password in grace period | informational, surfaced in `status` |
| ORA-01031 | insufficient privileges | fail early in pre-flight, name the missing grant |
| ORA-65040 / ORA-65048 | container-clause misuse, error while applying to a PDB | scope guardrail message |
| ORA-12154 / ORA-12541 | naming/listener | connectivity, distinct exit path |
| ORA-28040 / ORA-01017 with version mismatch | verifier / `ALLOWED_LOGON_VERSION` mismatch | explain password-version implications |

---

## 7. `sopuli creds check`

Answer one question per (account, target): does the vault's `current` password
work against this database?

```
sopuli creds check --application orders-app
                   [--method {login,hash,both}]
                   [--include-previous]     # is the old password still accepted?
                   [--output json]
```

### The lockout problem

A naive check logs in with the vault password. If it is wrong, the failed attempt
counts against `FAILED_LOGIN_ATTEMPTS` and repeated scheduled checks will
eventually **lock the production application account**. That is worse than the
drift it was detecting. Mitigations, all of which must be in place:

1. **Never retry.** One attempt per account per run, no back-off retries on
   ORA-01017.
2. **Read `LCOUNT` first** (`SYS.USER$.LCOUNT` where readable) and refuse to
   attempt a login when the account is already within `--lockout-margin` (default
   2) of the profile's `FAILED_LOGIN_ATTEMPTS`. Report `UNVERIFIABLE` with the
   reason.
3. **Reset on success.** A successful login resets the counter, which is why the
   happy path is self-cleaning.
4. **Offer hash mode** (below) as the safe alternative for high-frequency checks.
5. Document the interaction with `PASSWORD_LOCK_TIME` and with profiles that set
   `FAILED_LOGIN_ATTEMPTS UNLIMITED`.

### `--method hash` — verification without a login attempt

Oracle stores a salted PBKDF2-SHA512 verifier (the `12C` verifier in
`SYS.USER$.SPARE4`). Given read access to that column, the tool can derive the
verifier from the vault password and compare — **no authentication attempt, no
failed-login counter, no lockout risk**, and it works even for locked accounts.

Trade-offs to document honestly:

- requires a privileged read of `SYS.USER$` (not `DBA_USERS`), which some sites
  will not grant; the tool must degrade to `login` mode cleanly
- confirms the *stored verifier*, not that a login would succeed — an expired
  password, a locked account, or a failed listener still means the application
  cannot connect. Hence `--method both` for the strongest answer, and `status`
  surfacing lock/expiry independently.
- must handle multiple verifiers (10G/11G/12C) and pick the right one

### Output

```
$ sopuli creds check --application orders-app

Plan: 2 accounts × 2 targets = 4 checks   [group prod-pdbs]

ACCOUNT       TARGET             STATE             DETAIL
ORDERS_APP    cdb1-pdb-orders    IN_SYNC           vault v7, verified by login (12ms)
ORDERS_APP    cdb1-pdb-billing   DRIFT             vault v7 rejected (ORA-01017)
ORDERS_BATCH  cdb1-pdb-orders    ROLLOVER_ACTIVE   window ends 2026-08-05 09:12Z
ORDERS_BATCH  cdb1-pdb-billing   UNVERIFIABLE      lcount 8 of 10, within lockout margin

1 drift, 1 unverifiable
exit 3
```

Exit 3 for drift is what makes this schedulable: a monitoring system can alert on
"3" specifically, distinct from "the tool failed".

---

## 8. `sopuli creds rotate`

`generate` + `apply` + `check`, with the failure semantics tied together.

```
sopuli creds rotate --application orders-app
                    [--strategy rollover|staged|direct]
                    [--max-age-days N]    # only rotate what is older than N
                    [--finish-rollover]   # end the window at the end of the run
                    [--dry-run]
```

**Sequence**

```
 1. plan + confirm            ── nothing has changed yet
 2. acquire every lock        ── one per secret path, sorted order,
                                 all-or-nothing, never waiting
 3. pre-flight all targets    ── reachable, correct scope, account exists,
                                 privileges present, capability present
 4. generate                  ── vault: pending = new          (fence checked)
 5. apply to each target      ── database changed; old password still valid
                                 if strategy = rollover        (fence checked,
                                 lock renewed at each boundary)
 6. verify each target        ── login or hash with the new password
 7. promote                   ── vault: previous = current, current = pending
                                                              (fence checked)
 8. post-verify               ── read back from vault, verify once more
 9. release every lock, emit audit record
```

Step 3 exists so that the common failures (wrong privileges, closed PDB,
unreachable host) happen *before* anything is written anywhere.

**Step 2 and the fence** (Q2, decided in #83). Locks live in the vault, one per
**secret path** — not per account and not per target, because every target in a
run receives the same value and two accounts may share one document. A run that
touches several paths takes them all before the first mutation, in sorted order,
and never blocks waiting: partial acquisition releases what it took and exits 7
having applied nothing, which makes deadlock structurally impossible rather than
unlikely.

The fence is the vault version the acquiring write returned, and it is re-read
before every mutating call — each vault write and each `ALTER USER`. That is what
makes step 5 safe to resume after a stall: if this run's lock expired and another
took it over, the check fails and the run aborts before touching its remaining
targets, rather than applying a password the vault no longer advertises. Release
in step 9 happens in a `finally`, on every path including failure, and writes a
`released` record rather than deleting one.

`check` and `status` take no lock at all, and neither does any `--dry-run`.
An hourly scheduled check that blocked rotations would be a worse problem than
the one the lock solves.

**The record.** One per secret path, written under a `locks/` prefix on the same
mount as the secret — `secret/data/locks/<path>` on KV v2 — so the secret's own
version history stays clean for `previous` and rollback.

Pre-flight asserts `cas_required` on the lock path rather than assuming it: that
setting is what stops a *different* writer — an operator with a vault CLI — from
replacing the record without a compare-and-set, and the tool cannot claim a
guarantee it has not checked. A path with no metadata at all is the ordinary
state before the first lock and is not a failure.

`max_versions: 10` is recommended and deliberately **not** enforced. Pruning old
versions does not reset the version counter, so fencing survives any value of it,
and refusing a working vault over a housekeeping preference would be a guardrail
that only costs.

```json
{ "state": "held",
  "correlation_id": "01J…",
  "holder": { "host": "ci-runner-3", "pid": 8821, "os_user": "svc_sopuli" },
  "command": "creds rotate",
  "acquired_at": "…", "expires_at": "…",
  "selection": "env=prod" }
```

Nothing in it is a value: an account, a selection and a process, which is what
makes it safe to print at exit 7. Default TTL is 15 minutes, renewed at each
target boundary, and a lock counts as expired only past `expires_at` plus a
60-second clock-skew margin. `acquired_at` does not move on renewal — it answers
"how long has this been going on", which is the question somebody reading exit 7
is actually asking.

Three rules about reading and writing it, each of which is the safe side of a
choice that could have gone the other way:

- **Release writes, never deletes.** A KV v2 delete leaves the metadata behind,
  after which a first acquisition can never compare-and-set against version 0
  again — and that monotonic version *is* the fence.
- **Anything not `released` is held**, including a state this version has never
  heard of. Guessing that an unrecognised record is free is the one guess that
  ends with two runs rotating one credential.
- **A field this version does not know is kept**, because renewal rewrites the
  whole payload. Otherwise a record written by a newer sopuli comes back
  narrower than it went in.

Implemented in `sopuli/lock/` (#95), which holds the keying, the record and the
acquire/take-over/refuse decision as pure logic; the store, the fence and the
`finally` are #96.

**Failure at each step**

| Fails at | State afterwards | Recovery |
|---|---|---|
| 1–3 | nothing changed | fix and re-run |
| 4 | nothing changed in the database; `pending` may exist | re-run `rotate`, or `generate` then `apply` |
| 5 (some targets) | those targets have the new password, vault `current` is still old | `apply --repair`; with rollover strategy there is no outage meanwhile |
| 6 | database changed but verification failed | report loudly, no promotion; `check --include-previous` distinguishes "wrong password" from "account locked/expired" |
| 7 | database has new, vault `current` still old | **highest-severity case**: `pending` still holds the right value, so `sopuli creds promote` completes it; the tool must retry the promote before giving up |
| 8 | promoted but read-back disagreed | report; likely a vault replication lag issue |
| any fence check, at 4–7 | this run's lock was taken over by another; whatever it had already applied stands | abort immediately, mutate nothing further, exit non-zero. `check` establishes what is true; the run that holds the lock is the one that may fix it |

**Rollback.** `previous` is retained so that
`sopuli creds apply --source previous --confirm` can put the old password back on
the database. This is a real operation, not a theoretical one — it is the escape
hatch when an application turns out to have hard-coded the old password
somewhere. Rollback is bounded: only one generation back, and only while the
vault still holds `previous`. That bound is the decision, not the example (Q3,
settled in #84): OCI holds exactly one `PREVIOUS`, and `01-configuration.md` §7's
stage vocabulary — `current` / `pending` / `previous` — has nothing to address an
older generation with. Recovery further back is a matter of reading the store's
own version history, which not every backend has.

---

## 9. `sopuli creds status`

Read-only inventory, no login attempts, safe to run anywhere:

```
$ sopuli creds status --application orders-app --output text

ACCOUNT       TARGET             VAULT_V  AGE    DB_PW_CHANGED  LOCK      PROFILE       ROLLOVER
ORDERS_APP    cdb1-pdb-orders    7        12d    2026-07-23     OPEN      APP_PROFILE   24h configured
ORDERS_APP    cdb1-pdb-billing   7        12d    2026-05-02     OPEN      DEFAULT       not configured
ORDERS_BATCH  cdb1-pdb-orders    3        94d    2026-05-02     OPEN      APP_PROFILE   24h configured  ⚠ exceeds max_age 90d
```

The mismatch between vault age and `DB_PW_CHANGED` is a useful drift smell that
costs no login attempt.

---

## 10. Scenarios

**S1 — First adoption of an existing account.** The account exists, its password
is known to humans and not in the vault.
`generate --promote` → `apply` → `check`. The tool never needs the old password.

**S2 — Scheduled 90-day rotation, zero downtime.** Nightly `check` (hash mode,
exit 3 alerts). Weekly `rotate --max-age-days 90 --strategy rollover`. The app
refreshes credentials within the rollover window; a follow-up job runs
`finish-rollover` once the window has elapsed.

**S3 — One PDB was down during the last rotation.** `check` reports DRIFT for that
PDB. `apply --repair --target cdb1-pdb-billing` fixes only it, from the vault's
`current`. Idempotent for the ones already correct.

**S4 — Emergency rotation after a leak.** `rotate --strategy direct
--finish-rollover` — no grace window, old password invalid immediately, accepting
application errors as the price. The audit record captures who and when.

**S5 — Common user across a CDB.** One application entry, one secret, target
`cdb1-root`, `container_clause: ALL`. One statement covers every PDB.

**S6 — Vault write succeeds, database is unreachable.** `pending` exists, nothing
applied, `current` unchanged, applications unaffected. `check` reports
`PENDING_APPLY`. Re-running `rotate` resumes rather than starting over.

**S7 — Application still holds the old password after the window closed.**
Logins start failing. `check --include-previous` shows the old password is no
longer accepted, which points at the application rather than the tool.

---

## 11. Testing this

Because the failure modes are all about ordering and partial failure, the test
matrix is mostly fault injection. Environments, tiering and the capability-driven
matrix are in [`../design/04-testing.md`](../design/04-testing.md); what follows
is the UC-1 specific list.

- **Matrix:** Oracle 11.2 non-CDB / 18c and 21c XE / 23ai CDB+PDB / real 19.12+
  with rollover configured, against HashiCorp KV v2, KV v1, OCI Vault and the
  file backend. Note that rollover exists on 23ai Free and on a patched real
  19.12+, but not on the buildable 19.3 image — so that capability has no
  middle tier.
- **Fault injection at every step of § 8:** kill the process between apply and
  promote; make the vault unreachable mid-run; close a PDB mid-run; revoke
  `ALTER USER` mid-run.
- **Charset fuzzing:** generated passwords through the whole path — shell,
  connect string, JDBC URL, `.env` file, PL/SQL literal.
- **Lockout regression test:** run `check` against a deliberately drifted account
  N times with `FAILED_LOGIN_ATTEMPTS 3` and assert the account never locks.
- **Verify-function test:** a profile with `ora12c_strong_verify_function` and a
  policy that violates it — assert bounded regeneration and a clear final error.
- **Idempotency test:** every command run twice; the second run reports
  `unchanged` and emits no audit mutation record.
- **Concurrency test:** two `rotate` runs on the same account; one must lose on
  the lock with exit 7, and the final state must be consistent. The test stands
  as written after #83 even though locks are keyed on the path rather than on the
  account: two runs on one account resolve to one path, so they do contend.
- **Fencing test:** steal a lock mid-run — expire it and let a second run take it
  over — and assert the first aborts before its next `ALTER USER`. This is the
  case that a session-scoped `DBMS_LOCK` would not have caught, since a stalled
  session is still alive and still holding.
- **Redaction test:** run everything with `--log-level debug`, grep all output,
  logs and trace for the generated password. Zero hits is a release gate.

---

## 12. Open questions

| # | Question | Notes / leaning |
|---|---|---|
| Q1 | Should `check` default to `hash` or `login`? | leaning `login` interactively, `hash` under an unattended profile (`01-configuration.md` §5); needs a decision because it changes the privilege ask |
| ~~Q2~~ | ~~Where does the advisory lock live?~~ | **decided: in the vault** (#83). One record per secret path, CAS-guarded, carrying holder metadata and a TTL of 15 minutes, under a `locks/` prefix on the secret's own mount so the secret's version history stays clean for `previous` and rollback. `DBMS_LOCK`'s one unique benefit is release on session death, and that does not survive contact with the actual risk: a stalled run's session is still alive, so the lock it holds prevents nothing while its plan goes stale. A **fencing token** — the vault version, re-checked before every mutation — is what prevents it, and once fencing exists, automatic release does not pay for `EXECUTE ON DBMS_LOCK`, a widened grant set, a CDB/PDB scope answer, and product-specific behaviour in the command layer (P1). The grant set in `../design/02-oracle-privileges.md` §2 is unchanged. Keyed on the **path**, which is neither candidate P5 named: per-target is meaningless when every target gets the same value, and per-account misses two accounts sharing one document. Stores without `cas` (KV v1, the file backend) refuse mutations unless configured `locking: advisory-only`. |
| Q3 | ~~How many generations of `previous` to keep?~~ | **decided: exactly one**, plus whatever the store's native versioning gives for free (#84). C14 (#40) settled it: OCI holds exactly one `PREVIOUS`, and the closed `current` / `pending` / `previous` vocabulary has nothing to address an older generation with. Keeps the emulated payload the same shape as the native one, and `check --include-previous` need not say *which* previous it accepted. |
| Q4 | Does the tool ever alter a *profile* to enable rollover? | leaning no by default — profiles are shared; report the needed DDL instead |
| Q5 | Notification on drift | out of scope for the tool; exit code 3 + JSON output is the integration point |
| Q6 | Self-rotation mode (tool connects as the account itself, `REPLACE old`) | useful where no admin credential exists; defer to UC-1b |
| ~~Q7~~ | ~~One secret per account vs one secret with many fields for an app~~ | **decided: one secret per application, a field per account** (#85) — the layout §2 of `../design/01-configuration.md` already used in its worked example, now the documented default. An application's accounts are rotated together far more often than separately, and across a dozen tenants and environments the per-account layout is the difference between eight vault paths and forty-eight — which on a store that bills per secret is a line item, and on any store is a policy surface. One secret per account stays fully supported, and is the right answer where an account's lifecycle is genuinely its own. Neither the lock nor the write path changes shape: Q2 (#83) already keyed the lock on the **path** for exactly this case, and §7 already writes one field without touching its siblings — so the **account remains the unit of work** even where the document is shared. What the default settles is the payload, in §3 below. |
| Q8 | Should `apply` be able to create a missing account? | no in UC-1; belongs to a provisioning use case |
| Q9 | Time source for `max_age_days` | vault `rotated_at` (authoritative) vs DB `PTIME`; use vault, show both in `status` |

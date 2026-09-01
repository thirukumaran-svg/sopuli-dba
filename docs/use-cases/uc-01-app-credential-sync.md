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

sopuli creds finish-rollover  # end an Oracle password rollover window early
```

**There is no `creds promote`, and there is not going to be** (decided in #276,
built out in #284). Earlier drafts of this document listed one for the case where
a rotation is interrupted between applying and promoting. `apply` re-run already
completes that: it reads the `pending`, the pre-flight login finds the database
already accepts it, every account reports `IN_SYNC`, and the document is
promoted — invariant 9's `changed: false` and the recovery path turn out to be
the same code path. A cheap standalone `promote` that wrote the promotion
*without* re-verifying was weighed and rejected: as a separate verb invoked later
it would advertise a password to applications on the strength of a previous run's
document, and re-verification is exactly what makes `apply` safe to point §8's
worst row at.

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
                password_change_date, rollover_active?, scope }
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
  is reported as such — including a warning naming the version whose `pending`
  was replaced, because anything already holding that password is now stale.
  This is the **one exemption from invariant 9** and is decided rather than
  assumed (#254): the invariant governs commands that converge on a state, and a
  fresh draw has none. `apply` is the convergent half and reports
  `changed: false` on a re-run.

---

## 5. `sopuli creds apply`

Take what the vault holds and make the database match it.

```
sopuli creds apply --application orders-app
                   [--source {pending,current}]   # default: pending if set, else current
                   [--strategy {rollover,staged,direct}]
                   [--preflight]                  # survey every target before writing anything
                   [--continue-on-error]          # default: fail fast
                   [--repair FILE]                # act only on a run's unconfirmed set
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

### Account unlock, the first attribute (#300)

```yaml
policies:
  app-standard:
    account:
      unlock_if_locked: true      # default: false
```

`apply` refuses to change a locked account's password — the statement would
succeed, the verification could never pass, and the run would end holding a
database whose password is in no vault stage. That refusal is right and it leaves
a gap: a locked application account could not be rotated **at all**, and the
operator unlocked it by hand, outside the tool. With the attribute declared, the
run issues `ALTER USER … ACCOUNT UNLOCK` first and then does the work.

Four rules, and the first is the one the other three exist to protect:

- **opt-in, declared, never inferred.** Where the policy says nothing — which
  includes an estate that declares no `policies:` at all — a locked account is
  reported `LOCKED` exactly as before, and the message names the key that would
  change that. A tool that unlocked an account because it found one locked would
  be making a change nobody asked for during a credential rotation.
- **before the first login, after the guardrails.** A locked account refuses every
  login, so a pre-flight verification made before the unlock would spend an
  attempt against the counter §7's margin protects and learn nothing. §4's
  guardrails run first, because they decide whether this account may be touched at
  all and an unlock is touching it.
- **idempotent** (invariant 9). The driver reads the lock state and issues nothing
  where there is no lock; the action is still reported, with `applied: false`. A
  consumer inferring "not declared" from "not present" would be reading the policy
  out of the results.
- **it changes nothing about the promotion.** The unlock is a change to the
  database like the password is, and `pending` still waits for every target to
  confirm (invariant 7).

It reads as its own `actions[]` entry, which is what "reported as a separate
change" means concretely:

```json
"actions": [
  { "kind": "account_unlock", "applied": true,  "detail": "account was locked(timed); unlocked" },
  { "kind": "verify",         "applied": true,  "detail": "checked whether the database already has this password" },
  { "kind": "password_set",   "applied": true,  "detail": "changed and verified by login" }
]
```

`LOCKED(TIMED)` — what a profile's `FAILED_LOGIN_ATTEMPTS` produces, and the state
an account whose password has drifted is actually found in — is cleared by the
same statement as a deliberate lock. The capability is `account_lock_state`.

### Profile assignment, the second attribute (#301)

```yaml
policies:
  app-standard:
    account:
      profile: acme_app_prof
```

`apply` moves the account onto the named profile — `ALTER USER … PROFILE …` —
where it is on a different one. The same four rules the unlock follows apply
unchanged: opt-in, before the first login, idempotent, and no effect on the
promotion. Three things are its own.

**The tool assigns a profile and never creates or alters one.** `ALTER PROFILE`
edits a shared object and so reaches accounts nobody selected; §3 of
`02-oracle-privileges.md` keeps the privilege off the service account and Q4 (#88)
is open with a documented leaning of no. `creds finish-rollover` already takes the
other half of that position — it *reports* the `ALTER PROFILE` an operator would
run, and never issues it.

**A profile the target has not got is a pre-flight finding, not an `ORA-02380`
half way through.** Which profiles exist is a property of each database, so an
estate naming one that exists on nineteen PDBs and not the twentieth is an
ordinary misconfiguration rather than an exotic one — and discovering it on the
twentieth would leave nineteen accounts moved. `--preflight` asks for every
account it is about to touch and the run refuses before anything is written;
without the flag it is a refusal for that one account, before its own statement.

**Naming a `--strategy` across a move is refused.** This is the interaction that
makes assignment more than a statement:

> a profile decides whether `ALTER USER … IDENTIFIED BY` opens a rollover window,
> so it decides the regime a rotation runs under.

`--strategy staged` is refused today against a profile that grants a window,
because Oracle opens one regardless and reporting `staged` would tell an
application team the old password had stopped working when it had not (§6.3). That
check reads the profile the account holds **now** — which, for an account this run
is about to move, is the profile it is leaving. So the pair is refused:

```
--strategy staged cannot be honoured for 'acme_web_user' in 'appdb-prod-alpha':
this run would move it from ACME_LEGACY_PROF to acme_app_prof, and the regime a
rotation runs under is a property of the profile it ends on

hint: rotate under the profile it has, or let this run do the move and rotate
afterwards -- naming a regime and changing the profile that decides one are two
intentions for one run
```

**With no `--strategy` there is nothing to refuse**, which is the ordinary case:
the default regime is resolved per account *after* the attribute pass, from the
profile the account ends on. So an estate that declares a profile and does not name
a regime rotates correctly under the new one, first run.

The remaining two attributes are #302 (`PASSWORD_EXPIRE`, whose meaning has to be
settled first, since setting a password already clears an expiry) and #303
(tablespaces, which may belong to Q8's provisioning use case instead).

### What shipped in #259, and what the flags above still describe

The spine is implemented: read the source, set the password, verify, promote per
document. `--strategy` arrived with #262 and is described in §6.3; `--source`
with #265, and the rollback it exists for is §8. Two things in the sketch above
are still **not** in this build — `--repair` (#264, whose input is settled
below) and `--continue-on-error` (#266). The build is fail-fast, which is §5's
own default.

### `--source`, and the rollback (#265)

```
sopuli creds apply --source {pending,current,previous} [--confirm]
```

Omitted, the default is unchanged: `pending` if one is staged, else `current`.
Naming a stage reads **exactly** that one and **never falls back** — the fallback
is the thing somebody passing the flag was trying to avoid, and silently applying
`current` to an operator who asked for `previous` is a rollback that did not
happen and said it did. So a stage that holds nothing is a reported failure
naming *that* stage, because "no `previous` to roll back to" and "nothing staged
at all" send somebody to different places and only one of them is
`creds generate`.

`current` forces the repair path where a `pending` is staged: the staged password
turns out to be wrong, and the estate goes back on what applications are actually
reading, without discarding the `pending`. It owes the vault nothing, because the
vault already holds what went on the database.

**`previous` is the rollback**, and it is the only invocation in this use case
whose *success* stops an application's credential working. So it needs
`--confirm`, and where nothing can be asked it refuses (exit 8) rather than
prompting into a closed stdin. `--dry-run` needs no confirmation: a preview an
operator has to authorise is a preview they will stop taking.

**A rollback swaps the vault** (decided in #265). Once every target confirms,
`current` takes the rolled-back value and `previous` takes the one just removed
from the database — in the same single compare-and-set write a forward promotion
uses, because it is the same arithmetic on the other neighbour. The estate ends
consistent: applications fetch `current`, and `current` is what the databases
have.

**That is not a breach of "vault is master".** Invariant 6 is about the direction
values travel, and both of these came out of the vault — no database was read for
either. What changed is which stage is master, and an operator said so on the
command line.

**A rollback is refused while a `pending` is staged.** Rolling back under a
rotation in flight leaves the `pending` there, and the next `apply` moves the
estate forward with it — undoing the undo, unattended, at whatever hour that run
happens. Reported per account as `PENDING_APPLY`, the same word
`creds finish-rollover` uses for the same fact.

Rollback stays bounded to one generation, which is Q3 (#84) and not this
issue's to reopen: OCI holds exactly one `PREVIOUS`, and §7's stage vocabulary
has nothing to address an older one with.

Three decisions inside the spine are worth stating here, because none of them is
readable off the flag list:

- **The database is asked before it is changed.** Invariant 9 names `apply` as
  the convergent verb, and with `--method hash` unavailable (#86, #90) a login is
  the only way to know whether a change is needed. So each account is verified
  first, under §7's mitigations and with both logins budgeted as one run's worth
  of attempts, and a password that already works is left alone. A `pass` under an
  open rollover window is still a reason not to act: re-applying would restart the
  window and report a change nobody asked for.
- **A locked account is not changed at all.** The statement would succeed and the
  verification could never pass, which ends the run holding a database whose
  password is in no vault stage — the state §3's ordering exists to prevent. An
  *expired* one is changed, per §6.4: setting a password clears the expiry.
- **An empty vault is a failure, not a quiet no-op.** Where neither stage holds
  anything for a declared account, the run reports `ERROR` naming
  `creds generate` rather than exiting 0 having converged nothing. `check` calls
  the same situation `UNVERIFIABLE` because its survey merely has a gap in it;
  `apply` cannot do the thing it was run to do.

**A server that refuses the password is reported, never worked around.** §6.4
says regenerate on ORA-28003 and ORA-28007, and this build does not: the value
came from the vault's `pending`, which `generate` wrote and something may already
be holding, so drawing a different one here would make the vault and the database
disagree with what the operator staged. Regeneration inside `apply` is a design
question and is filed rather than guessed at.

### `--preflight`, and what it asks before anything is written (#283)

§8 step 3 belongs to `rotate`, and it is available here because the same
question is worth asking before a large `apply`: *would this work?* One
connection per target, before the first `ALTER USER`, checking §8's own list —
reachable, the scope the file claims, the accounts declared, the privileges
needed.

**Off by default**, which is the trade. A repair of one target should not pay for
a survey of twenty, and without the flag `apply` discovers each of these per
target as it goes and reports them per account — which is the right answer when
nobody asked. `--strategy` already opened one connection per target for its own
refusal (#262); the two are now **one pass on one connection** rather than two.

**Every finding is reported and one of them refuses.** A pre-flight exists so an
estate can be fixed in one pass, so the table lists all of them; but a run has
one exit code and one `error`, and that one is the finding earliest in §8's
order — the one closest to the cause. A target that could not be reached explains
its own missing scope, and a container that turned out to be the wrong one
explains every account that was not found in it.

**Exit 1, because nothing changed anywhere**, which is what exit 1 already means
for this verb. Not 9: the estate disagreeing with the file is not a file that
could not be read, and `config validate` passes on every one of these. Not 5
either — that is invariant 4's, and a capability the estate cannot honour is
still `--strategy`'s own refusal, raised where it is found rather than collected
among findings.

**Not knowing is not a finding.** An open mode the driver could not read is not a
read-only database, and a privilege audit the service account is not granted has
established nothing either way — so it is reported as a warning and the run goes
ahead. That is §7's rule for the `LCOUNT` guard applied here: a check that is not
running says so rather than being silently skipped, and refusing over it would
mean an estate that will not grant the audit view could never run a pre-flight at
all.

**`--dry-run --preflight` surveys too.** It writes nothing and needs no lock, and
"show me the plan, and tell me whether it would work" is the invocation somebody
reaches for first — a flag that silently meant nothing there would be a trap.

### `--repair`, and where the DRIFT list comes from (#264)

```
sopuli creds apply --repair result.json   # act only on what that run left unconfirmed
```

**The list comes from a previous run's document.** `--repair` takes a path to
one — an `apply` that exited 4, or a `check` that exited 3 — and narrows this run
to the (account, target) pairs it reported as not confirmed. That is decided;
the flag itself is not in this build, and what follows is what it will be when it
lands.

**What it buys is logins, not capability.** `apply` is already idempotent: every
account is verified before it is touched and one that already works is left
alone, so an unnarrowed repair converges the estate correctly and expensively.
The cost is one login per account per target — an attempt against the
failed-login counter §7 exists to protect, a connection, and an audit entry in a
database that had nothing wrong with it. Repairing one PDB in an estate of
twenty-one spends twenty-one.

**Why not run `check`'s logic first, in the same process.** Because that is what
this build already does. The pre-flight in the flow above *is* `check`'s
comparison, and the `ALTER USER` is skipped where it passes — so a flag that ran
it would spend exactly the logins `--repair` exists to save and change nothing
else. It is not a narrower option; it is an empty one.

**Why not take the target list from the operator.** `--repair --target x` is
`--target x` with more letters. `--select` already narrows the estate and #229
adds the named-entity selectors; a second spelling of them would be a flag whose
only distinguishing feature is that it is easier to get wrong.

**What the document form has to refuse, and what it does not.** A stale document
describes a stale estate — but two properties bound that before any rule is
written:

- **it can only ever narrow.** Invariant 5 makes the config the whitelist, and
  `--repair` feeds a filter rather than a target list. A pair the document names
  and the config no longer declares is dropped, not acted on;
- **a pair that has since been repaired costs one login and reports
  `changed: false`,** because the pre-flight asks before it acts.

Acting on a stale document is therefore wasteful rather than dangerous, so
freshness is a **warning naming the document's age**, not a gate with a threshold
in it: a threshold would have to be wrong for somebody, and the run it refused
would have been safe. What *is* refused is a document describing a different
estate — `--repair` reads `command` and `config.sources[]`, and one not produced
by `creds apply` or `creds check` over this configuration is rejected before a
target is dialled. A repair aimed at the wrong estate is the one failure the two
properties above do not catch.

**Exit 4 names the invocation that repairs it, and that part shipped.** A partial
run's closing line says what to type, narrowed the way that run was narrowed and
carrying `--config`, `--profile`, `--source` and `--strategy` so the repair
resolves and acts the way the run did:

```
1 changed, 1 not confirmed
repair with: sopuli creds apply --config estate.yaml --select env=prod
```

It names the plain re-run rather than `--repair`, because that is the invocation
that works today — safe (invariant 9) and merely more expensive than the flag
will be. Sending somebody holding a half-applied estate to a usage error is worse
than sending them to a slow remedy. The flag replaces it in this message when it
ships.

Both shapes of exit 4 get the line: targets that did not confirm, and an estate
that confirmed while its vault was not promoted. The second is §8 case 7 —
applications are fetching a password the databases no longer have — and it is the
row where knowing what to type next matters most.

**The line is text only, and carries no diagnostic code.** `03-json-output.md`
§3's rule is that a code exists for what the exit code cannot tell you, and here
it tells you exactly: exit 4, with `results[]` already carrying the states a
consumer would filter on. A code would be a third spelling of a fact the
document holds twice.

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

**Application containers are refused outright for now** (#171). The row above
describes the scope correctly and nothing has ever run against one: whether an
application-common user is `C##`-prefixed the way a CDB common user is has not
been checked against a real application root, and `CONTAINER=ALL` there means
something narrower than it does in `CDB$ROOT`. Guessing which of those applies
would produce a statement that is either refused or — worse — accepted against
the wrong set of containers, so `app_root` and `app_pdb` raise instead. The
refusal names the scope and says why, which is what makes it a gap somebody can
close rather than a silence. Closing it needs an application container to test
against, not a decision.

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
- `sopuli creds finish-rollover` ends the window explicitly (#263). Same
  statement as `--strategy direct`, and a different command because it has to
  *find* windows nobody handed it — see below.
- Fallback for databases without the capability: `--strategy staged`, meaning the
  tool applies and reports, and the operator owns the app-side restart. Documented
  as "brief authentication failures possible for connections established with the
  old password after the change".

### `creds finish-rollover`, and what it refuses (#263)

```
sopuli creds finish-rollover [selectors] [--dry-run] [--lockout-margin N]
```

`--strategy direct` closes the window it just opened, inside the run that opened
it. This verb finds windows nobody handed it, which makes it a different command
with a different failure mode: **closing a window is the one step in UC-1 whose
purpose is to stop something working**, so most of what it does is decide which
accounts to leave alone.

**It takes no lock and writes to no store.** Nothing in any vault changes, so
there is nothing for the advisory lock to protect — and a nightly job that took
one would block the rotation it exists to finish. It is the second verb after
`check` that leaves every document alone.

**Two gates, and only one of them costs a login** (decided in #263):

- **a staged `pending`** — the rotation is unfinished, so the vault's `current`
  is still the *old* password and closing the window would strand every
  application that has not been given the new one. Reported as `PENDING_APPLY`
  and refused **without an attempt**;
- **a refused `current`** — the vault's password is rejected even with the window
  open, so neither password in play is the one applications fetch. `DRIFT`, exit
  3, window left open.

**What the login proves, and what it does not**, is the reason those two are
separate rather than one check. Under an open window both passwords authenticate,
so a *pass* cannot tell "the database has the vault's password" from "it has the
previous one and accepts both" — the same caveat `check` reports as
`ROLLOVER_ACTIVE`. A *fail* is conclusive, and that is what the attempt is spent
on. The case a pass would have got wrong is exactly the staged-`pending` one, and
that is caught on the vault side for nothing.

Everything else with an open window is closed. An account with **no** window open
reports `changed: false` — invariant 9, and the ordinary result for the scheduled
job S2 describes: measured on 26ai, issuing the statement with no window open is
accepted silently and changes nothing, so a run that just issued it would report
a change every night. A locked or expired account keeps its window, and so does
one on a database with no `expire_password` capability — that is `SKIPPED` rather
than an error, because a window nobody can close early simply elapses on its own.

**`--dry-run` reads the state and spends no login.** What a preview is for here
is *who am I about to cut off, and how early*, and a login is a real cost against
a failed-login counter for a run that changes nothing.

### What `--strategy` actually decides (#262)

**The statement is the same in all three regimes.** That is the fact the flag is
built around, and it is why this is one code path with a precondition and a
follow-up rather than three:

| strategy | statement | after |
|---|---|---|
| `rollover` | `ALTER USER … IDENTIFIED BY …` | the window opens; both passwords work until it closes |
| `staged` | the same | the change is immediate |
| `direct` | the same, then `ALTER USER … EXPIRE PASSWORD ROLLOVER PERIOD` | the window is closed at once, so the old password stops working |

**The default is per account, and it is never `direct`.** `rollover` where the
capability exists *and* the account's profile grants a window, `staged`
otherwise — two accounts in one database can sit on different profiles, so this
is resolved per account rather than per run. `direct` is never chosen for
somebody: ending a grace window early is destructive to whoever still holds the
old password, and a default that did it would be making that decision for an
operator who did not know there was one.

**Oracle decides whether a window opens, not this tool.** It opens because the
profile's `PASSWORD_ROLLOVER_TIME` is greater than zero, whatever the run asked
for. So `--strategy staged` against a rollover-enabled profile is **refused**:
running anyway and reporting `staged` would tell an application team that the old
password had stopped working when it had not. The refusal names the profile and
offers `rollover` or `direct`.

**An explicit strategy is refused for the whole estate, before anything
changes.** Naming a regime is asking for a property of the estate — *no
application will see a failed login tonight* — and a run that honoured it on four
PDBs and discovered on the fifth that it could not would already have broken the
promise. So an explicit `--strategy` costs one extra connection per target, spent
on a pre-flight that clears every account or refuses. With no flag there is
nothing to refuse and the run pays nothing.

**`direct` closes the window only after the change is verified.** Closing it on a
change nobody confirmed leaves an account whose old password has stopped working
and whose new one is not known to work — the one state worse than the grace
period `direct` exists to avoid. And `direct` against a profile that grants no
window issues no second statement at all: the change was already immediate, which
is what was asked for.

**What the run reports.** `results[].rollover` carries `active`, `ends_at` where
there is a window, and `profile_rollover_time` — emitted for every account this
run acted on rather than only the ones with a window open, because the *absence*
of one is the answer to "did the old password stop working just now".

### 6.4 Errors worth handling by name

| Error | Meaning | Tool behaviour |
|---|---|---|
| ORA-28003 | password verify function rejected it | regenerate (bounded), preserve the server message |
| ORA-28007 | password cannot be reused | regenerate; never retry the same value |
| ORA-01017 | invalid credentials | verification failure → drift, not a crash |
| ORA-28000 | account locked | report `LOCKED`; unlock only where the policy declared it (#300) |
| ORA-28001 | password expired | distinguish from drift; can be resolved by apply |
| ORA-28002 | password in grace period | informational, surfaced in `status` |
| ORA-01031 | insufficient privileges | fail early in pre-flight, name the missing grant |
| ORA-65040 / ORA-65048 | container-clause misuse, error while applying to a PDB | scope guardrail message |
| ORA-12154 / ORA-12541 | naming/listener | connectivity, distinct exit path |
| ORA-28040 / ORA-01017 with version mismatch | verifier / `ALLOWED_LOGON_VERSION` mismatch | explain password-version implications |
| DPI-1047 / DPY-3001 | the *client* library, not the server: Instant Client missing, or thin mode reached because thick-mode initialisation did not happen | `config` and exit 9 — the same landing ADR-006 gives a backend that is configured and not installed, because it is fixed on this machine by the person reading the message |

Implemented in `sopuli/driver/oracle/errors.py` (#172), on three rules worth
stating because each one is a decision the table above does not make:

- **The mapping classifies; it does not decide.** Nothing there raises, because
  `ORA-01017` means two different things depending on whose credential was
  refused: exit 6 for the admin connection, `DRIFT` and exit 3 for a
  verification login. It returns a value and the caller — which knows what it
  was doing — decides whether that value is an exception, a state, or a reason
  to draw another password.
- **An unmapped code is terminal, and never regenerates.** It might be transient
  and it might be a value the server will refuse forever; of the two ways to be
  wrong, looping is the one that locks accounts. A code in Oracle's Net/TNS
  range still lands as `connectivity` rather than as `database`, so an unnamed
  member of a family is unknown without being misplaced.
- **Exit codes are P5's and are not invented here.** Connectivity and
  authorization have no number of their own and exit 1 carrying their own
  *category*. "Distinct exit path" means a distinct thing the operator reads;
  adding a number to P5's table is a change to a contract schedulers branch on.

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

**As shipped (#248):** the selectors, `--include-previous`, `--lockout-margin`
and `--output`. There is **no `--method` flag**, and its absence is the decision
rather than an omission — Q1 (#86) made `login` unconditional, hash mode depends
on #90 and may never ship, and a flag with one legal value advertises a choice
that does not exist. It arrives with hash mode or not at all. `--application`,
`--account`, `--target` and `--group` are the selectors this command shares with
every other verb and are not built yet; `--select` is.

### The lockout problem

A naive check logs in with the vault password. If it is wrong, the failed attempt
counts against `FAILED_LOGIN_ATTEMPTS` and repeated scheduled checks will
eventually **lock the production application account**. That is worse than the
drift it was detecting. Mitigations, all of which must be in place:

1. **Never retry.** One attempt per account per run, no back-off retries on
   ORA-01017.
2. **Read `LCOUNT` first, where the grant exists.** `SELECT ON SYS.USER$` is
   optional, not part of the default install (`02-oracle-privileges.md` §2,
   §8 P2 — decided in #86), and probed as a capability rather than assumed.
   Where present, refuse to attempt a login when the account is already within
   `--lockout-margin` (default 2) of the profile's `FAILED_LOGIN_ATTEMPTS`, and
   report `UNVERIFIABLE` with the reason. Where absent, `check` still runs on
   the remaining runtime mitigations (1/3/6 below), and must say so plainly
   rather than silently skip the guard.
3. **Reset on success.** A successful login resets the counter, which is why the
   happy path is self-cleaning.
4. **Offer hash mode** (below) as the safe alternative for high-frequency
   checks, if it ships at all — see #90.
5. Document the interaction with `PASSWORD_LOCK_TIME` and with profiles that set
   `FAILED_LOGIN_ATTEMPTS UNLIMITED`. (A documentation item, not a runtime
   check — excluded from the "1/3/6" runtime set above and below.)
6. **Report `ACCOUNT_STATUS` unconditionally**, from `DBA_USERS` (already in
   the baseline grant set, no extra privilege needed). A login attempt alone
   conflates an expired password, an already-locked account and a genuinely
   wrong password behind the same `ORA-01017` — `check` reads status
   separately and surfaces `LOCKED` / `LOCKED (TIMED)` / `EXPIRED` as their own
   states rather than folding them into `DRIFT`.

### `--method hash` — verification without a login attempt, if it ships at all

**Unresolved — tracked in #90, not part of the default path.** `check`
defaults to `login` unconditionally (Q1 — decided in #86); hash mode is an
opt-in extra that may not exist at all, not a fallback the default depends on.

Oracle stores a salted PBKDF2-SHA512 verifier (the `12C` verifier in
`SYS.USER$.SPARE4`). Given read access to that column, the tool could derive
the verifier from the vault password and compare — **no authentication
attempt, no failed-login counter, no lockout risk** — and it would work even
for locked accounts. Whether the `T:` layout can actually be reproduced
client-side is #90's open question; if it can't, this whole method is dropped
from the CLI.

Trade-offs to document honestly if it does ship:

- requires the same optional `SELECT ON SYS.USER$` grant as the `LCOUNT` guard
  (`02-oracle-privileges.md` §2), which some sites will not grant; the tool
  must degrade to `login` mode cleanly. #124 is investigating whether a
  narrower grant can expose just enough to avoid this trade-off
- confirms the *stored verifier*, not that a login would succeed — an expired
  password, a locked account, or a failed listener still means the application
  cannot connect. Hence `--method both` for the strongest answer. Lock/expiry
  status is already surfaced independently regardless of method — see
  mitigation 6 above.
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

**An unreachable target is exit 1, never exit 3.** A broken check must not page
whoever watches for drift, so `ERROR` outranks `DRIFT` when the run's own code is
decided: a run that reached nine targets and could not reach the tenth found
drift on nine targets' worth of estate, and reporting 3 would claim the survey
was complete. `LOCKED`, `EXPIRED`, `ACCOUNT_MISSING` and `UNVERIFIABLE` are exit
**0** — none of them established that a credential is wrong, and each is counted
in the "unverifiable" half of the closing line.

**A locked or expired account is never probed.** Mitigation 6 reads the status to
*report* those cases, and attempting a login anyway would spend a failed login
discovering something the status already said — the harm this section exists to
prevent, reached by a different route. `sopuli/cli.py:_settled_by_status` is the
refusal; `sopuli/check.py:decide` is the reporting.

---

## 8. `sopuli creds rotate`

`generate` + `apply` + `check`, with the failure semantics tied together.

**`--max-age-days` reads the vault, never the database** (Q9, decided in #87).
`rotated_at` lives on the secret path, one value regardless of how many targets
share it, so there is nothing to aggregate the way N database timestamps would
need — no "oldest, newest, or any" rule to write for an account that spans a
CDB's PDBs. A target the tool has not reached since the last rotation is
therefore selected by age exactly like one it has, which is the trade §9 makes
visible rather than hides: `status`'s `DB_PW_CHANGED` column is where that gap
shows up, not in what `rotate` selects.

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
unreachable host) happen *before* anything is written anywhere. It is
implemented and available on `creds apply` as `--preflight` (#283) — see §5,
which also records why it is opt-in there and unconditional here.

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

### What the fence does in this build (#282)

`creds apply` and `creds generate` re-read it, which is what makes the property
above true of the tool rather than only of `sopuli/lock/`. Five things about it
are decisions rather than transcription:

**It is checked per document, not per run.** Before an `ALTER USER`, what has to
still be this run's is *that account's* document lock — the one the change is
about to be made under. Checking every lock the run holds would be a store read
per held lock before every statement: on an estate of twenty documents, four
hundred reads to establish twenty facts, nineteen of which nothing was about to
act on. `LockManager.check()` with no arguments still checks everything, which is
what a renewal needs, since a renewal writes to all of them.

**The renewal is the boundary check.** The lease is extended between one target
and the next, and because a renewal is itself a write it goes behind the fence
like every other — so the boundary catches a takeover *before* the next target's
first statement rather than after it.

**A lock error is never a per-target finding.** Everything else that goes wrong
with one account becomes a row in the table and the run carries on, which is
exactly the wrong answer here: it would turn "somebody else owns this estate now"
into a footnote and apply to the next account anyway. `LockError` is re-raised
ahead of the per-account catch-all, and the run ends.

**Nothing is promoted after a takeover**, including documents whose own locks are
still held. Not because the write would fail — the fence would catch it — but
because a promotion asserts that every target holds this password, and a run
stopped part way through has no standing to assert it.

**The exit code splits on what had been applied**, which is the split
`sopuli/lock/errors.py` describes and deliberately leaves to the command: **7**
where the run was fenced out before it changed anything, and **4** where it had
already changed something. Reporting 7 after nine targets is the one answer that
would tell a scheduler nothing happened at exactly the moment something did.

Exit 4 is then ambiguous by itself — a run whose targets failed exits 4 too, and
that one *is* repaired by running `apply` again — so a fenced-out run carries the
diagnostic `SOPULI-W011` and its text says what stopped it **instead of** the
repair line #264 added. Advising a re-run while somebody else holds this estate's
lock is the one piece of advice to withhold.

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

**Reading one without holding it** is `sopuli lock status` (#105): the declared
set of secret paths, surveyed for records, with the holder reported the way exit
7 reports it. It takes no lock — it is a `status` verb, and the rule above
applies to it — so an hourly survey never blocks a rotation.

**Taking one back** is `sopuli lock break <vault>:<path>` (#149), deliberately a
different command from the one that reads:

```
$ sopuli lock break vault-prod:apps/acme/appdb-beta --confirm

LOCK                             STATE    HOLDER                  COMMAND       SINCE                 EXPIRES
vault-prod:apps/acme/appdb-beta  expired  svc_sopuli@ci-runner-3  creds rotate  2026-08-16T12:00:00Z  2026-08-16T12:15:00Z

broke this lock at version 41; svc_sopuli@ci-runner-3 pid 8821 running creds rotate is fenced at version 42 and stops at its next check
```

The argument is spelled the way exit 7 and `lock status` print it, so the
invocation in a refusal is a paste. It writes a `released` record over the held
one with `cas` set to the version it read — never a delete, for the reason above
— and the resulting version bump is the fence: the run it was taken from stops at
its next check rather than applying a password the vault no longer advertises.
That is what makes the verb survivable, so a store that cannot fence is refused
(exit 5) rather than given a version of it that guarantees nothing — and so is one
declared `locking: advisory-only`, whatever the mount turns out to support, which
is the combination `locking.break_expired` is already refused against.

It takes confirmation. A lock that has **not** expired takes `--force` as well,
and refusing one is exit 7 naming the holder — the answer to a colleague
mid-rotation is usually to talk to them. `--dry-run` prints the plan and writes
nothing; `safety.readonly` refuses the verb outright, on exit 8. A path with no
record, or one already released, is exit 0 having changed nothing, which is what
makes running it twice safe.

It will clear a record at a path this config no longer declares — the leftover
`lock status` surfaces (#150) is exactly the one nobody else can clear — and that
is not a breach of invariant 5: the write lands under the store's `locks/` prefix,
in a store `vaults:` declares, and never touches the secret the lock guards.

**Failure at each step**

| Fails at | State afterwards | Recovery |
|---|---|---|
| 1–3 | nothing changed | fix and re-run |
| 4 | nothing changed in the database; `pending` may exist | re-run `rotate`, or `generate` then `apply` |
| 5 (some targets) | those targets have the new password, vault `current` is still old | `apply --repair`; with rollover strategy there is no outage meanwhile |
| 6 | database changed but verification failed | report loudly, no promotion; `check --include-previous` distinguishes "wrong password" from "account locked/expired" |
| 7 | database has new, vault `current` still old | **highest-severity case**: `pending` still holds the right value, so `sopuli creds apply` completes it — it re-verifies every target and promotes; `rotate` retries the promote internally before giving up |
| 8 | promoted, and the read-back disagreed | the databases are converged and the vault is not serving what it accepted. Exit 4 carrying `SOPULI-W012`, which names the accounts; nothing needs undoing, and the place to look is the vault (a replica behind its primary) rather than any database |
| any fence check, at 4–7 | this run's lock was taken over by another; whatever it had already applied stands | abort immediately, mutate nothing further, exit **7** if nothing had been applied and **4** if something had, carrying `SOPULI-W011`. `check` establishes what is true; the run that holds the lock is the one that may fix it |

### What the verb does in this build (#284)

The sequence above is implemented, over parts that all existed by the time it was
written — `generate`'s staging write, `apply`'s convergence and promotion,
`finish-rollover`'s window, the lock's fence (#282) and the pre-flight (#283).
Eight things about it are decisions rather than transcription.

**It is not a wrapper, and the lock is why.** Each of the three verbs takes and
releases its own, so between a `generate` that released and an `apply` that has
not yet acquired, another run can stage a different `pending` — and this run
would then apply and promote a password it never generated. One acquisition spans
steps 2 to 9.

**The pre-flight is unconditional here and opt-in on `apply`.** §5 explains why it
is off by default there: a repair of one target should not pay for a survey of
twenty. A rotation is the opposite case, and it also asks about a *larger* set —
`apply` surveys the accounts it has something to apply, while `rotate` surveys
everything it is about to rotate, because at step 3 there is no `pending`
anywhere and a first rotation has no `current` either. Filtering on what the
vault already holds would skip the whole estate on exactly the run whose
pre-flight matters most.

**A staging failure stops the run before any database is touched.** Row 4 says
nothing changed in the database, and a rotation that staged two documents, failed
on a third and applied the two anyway would make that row untrue for the estate
somebody has to reason about afterwards. Exit 1 rather than 4: 4 means some
targets succeeded and some failed, and here no target was attempted.

**Step 8 is a second read, not a comparison against what was written.** Reading
back the object the run just wrote is the only way the check can find anything —
what it is looking for is a store that acknowledged a write and then served
something else, which is what a read replica behind its primary looks like. Only
documents this run actually promoted are read back; one nobody staged into was
never written, and one whose targets did not all confirm was deliberately left
alone. A document that no longer holds the stage counts as a disagreement, on the
grounds that "the vault has not got it" and "the vault has the wrong one" are the
same operational fact to the application about to fetch it.

**`--max-age-days` selects nothing whose age is unknown.** That is
`creds status`'s rule (Q9, #87) reused rather than restated, and it is the branch
that decides what this tool does the first night it is pointed at somebody else's
estate: a freshly adopted vault has no `rotated_at` anywhere in it, and treating
unknown as infinitely old would make the first scheduled run a rotation of every
credential. An operator who wants that asks by leaving the flag off.

**The takeover split has one more case than `apply`'s.** §5's rule is 7 where the
run was fenced out before it changed anything and 4 where it had already changed
something. `rotate` reaches a database later than it reaches the vault, so a
staged `pending` is a mutation that exists before any DDL does — and a run fenced
out between two step-4 writes exits **4**, not 7, because 7 asserts nothing
happened and a `pending` somebody has to clean up is something happening.

**The fence reaches `--finish-rollover` too**, which is worth stating because the
first version of this did not (found in review). Window-closing is the run's last
mutation and the furthest from the acquisition at step 2, so it is the one most
likely to be issued after a lease has already gone — and it is the one whose
direction cannot be undone: a window nobody closed elapses on its own, and one
closed by a run that had lost the estate cannot be reopened. So the closing path
re-reads the fence before each statement where a caller holds a lock, and lets a
`LockError` past its per-account catch-all rather than filing a takeover as one
account's bad luck. **The standalone `creds finish-rollover` still takes no lock
at all** — it writes to no store, and an hourly job that blocked rotations would
be a worse problem than the one the lock solves — so the manager is an argument a
caller supplies rather than something the verb acquires.

**Step 9's audit record is the run document.** `--output json` is the record a
scheduler keeps, and `creds.rotate` was already in the run schema's command enum;
the `sopuli-event-1.0` event stream is `--output jsonl` (#9), which has no emitter
for any verb yet and gains one for all of them at once.

**Confirmation, and what it is not.** §8 step 1 is "plan + confirm", so `rotate`
prints the plan to stderr and asks; `--confirm` answers in advance and an
unattended run without it is refused on exit 8 rather than left to an EOF abort.
`apply` does not ask, and the difference is real: it converges an estate on a
value somebody already staged and reviewed, while `rotate` invents the value and
replaces what every application is using, across the whole selection, in one
pass. The estate-wide `safety.confirm_environments` setting is a *different* gate
which nothing enforces yet (#292) — this flag is not it, and neither substitutes
for the other.

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

### What shipped in #275

The verb, the standard selectors, `--max-age-days`, and both output modes. Three
things about it are decisions rather than transcription:

**A healthy row reports `UNVERIFIABLE`, not `IN_SYNC`.** The one question an
inventory cannot answer is the one `check` exists for — *does the vault's
password actually work* — so this says it did not ask, in the detail column.
`IN_SYNC` from a command that never tried would be agreement nobody measured,
and it would be indistinguishable in a document from one `check` produced by
spending a login.

**What it *can* say without asking** is the rest of the state model: an account
the config declares and the database has not got, one locked or expired, a
rotation somebody staged and never applied (`PENDING_APPLY` — visible in the
vault alone), and a rollover window standing open.

**An unknown age is not an old one.** A credential this tool has never rotated
has no `rotated_at`, and `--max-age-days` does not select it. Treating unknown as
infinitely old would make the tool's first act against a freshly adopted estate a
proposal to rotate all of it — which is the opposite of what somebody running an
inventory over a new estate wants to find out.

**A target it cannot reach is exit 1**, which is `check`'s rule and for `check`'s
reason: a survey with a hole in it must not look complete. The vault half of
those rows is still filled in — the version and the age came from a document read
before any database was dialled, and throwing them away because a listener was
down would answer less than the run knows.

In the run document, `password_age_days` keeps the meaning it has everywhere
else — the **database's** age, from `PASSWORD_CHANGE_DATE`. The vault's age
travels as a `warning` naming its source, because two clocks under one field name
is exactly the confusion this section was written to prevent.

**`AGE` is `rotated_at`, from the vault, and is what `--max-age-days` filters
on** (Q9, decided in #87). `DB_PW_CHANGED` is read from the database purely
for display — it never gates a rotation and nothing currently reads it back —
which is why the ⚠ above marks only `ORDERS_BATCH`'s row, on its vault age
past 90 days. `ORDERS_APP`'s `cdb1-pdb-billing` row shares that exact
`DB_PW_CHANGED` date with `ORDERS_BATCH`, yet its vault age is 12d rather than
94d: the same database-side history, two very different answers depending on
which clock is asked, and only the vault's is acted on. The column's source is
version-dependent (`DBA_USERS.PASSWORD_CHANGE_DATE`, or `SYS.USER$.PTIME` on
11.2, behind the grant `02-oracle-privileges.md` P2 makes optional) and
unconfirmed — see `docs/README.md`'s "Verify before implementing".

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
| ~~Q1~~ | ~~Should `check` default to `hash` or `login`?~~ | **decided: `login`, unconditionally** (#86, 2026-08-18) — not profile-dependent. The earlier "hash under an unattended profile" leaning assumed hash mode existed and its grant was default; neither holds. `SELECT ON SYS.USER$` is optional and capability-probed (`02-oracle-privileges.md` §2); where present it powers the `LCOUNT` guard and, if #90 lands positive, hash mode. `check` needs no site-specific grant to run at all |
| ~~Q2~~ | ~~Where does the advisory lock live?~~ | **decided: in the vault** (#83). One record per secret path, CAS-guarded, carrying holder metadata and a TTL of 15 minutes, under a `locks/` prefix on the secret's own mount so the secret's version history stays clean for `previous` and rollback. `DBMS_LOCK`'s one unique benefit is release on session death, and that does not survive contact with the actual risk: a stalled run's session is still alive, so the lock it holds prevents nothing while its plan goes stale. A **fencing token** — the vault version, re-checked before every mutation — is what prevents it, and once fencing exists, automatic release does not pay for `EXECUTE ON DBMS_LOCK`, a widened grant set, a CDB/PDB scope answer, and product-specific behaviour in the command layer (P1). The grant set in `../design/02-oracle-privileges.md` §2 is unchanged. Keyed on the **path**, which is neither candidate P5 named: per-target is meaningless when every target gets the same value, and per-account misses two accounts sharing one document. Stores without `cas` (KV v1, the file backend) refuse mutations unless configured `locking: advisory-only`. |
| Q3 | ~~How many generations of `previous` to keep?~~ | **decided: exactly one**, plus whatever the store's native versioning gives for free (#84). C14 (#40) settled it: OCI holds exactly one `PREVIOUS`, and the closed `current` / `pending` / `previous` vocabulary has nothing to address an older generation with. Keeps the emulated payload the same shape as the native one, and `check --include-previous` need not say *which* previous it accepted. |
| Q4 | Does the tool ever alter a *profile* to enable rollover? | leaning no by default — profiles are shared; report the needed DDL instead |
| Q5 | Notification on drift | out of scope for the tool; exit code 3 + JSON output is the integration point |
| Q6 | Self-rotation mode (tool connects as the account itself, `REPLACE old`) | useful where no admin credential exists; defer to UC-1b |
| ~~Q7~~ | ~~One secret per account vs one secret with many fields for an app~~ | **decided: one secret per application, a field per account** (#85) — the layout §2 of `../design/01-configuration.md` already used in its worked example, now the documented default. An application's accounts are rotated together far more often than separately, and across a dozen tenants and environments the per-account layout is the difference between eight vault paths and forty-eight — which on a store that bills per secret is a line item, and on any store is a policy surface. One secret per account stays fully supported, and is the right answer where an account's lifecycle is genuinely its own. Neither the lock nor the write path changes shape: Q2 (#83) already keyed the lock on the **path** for exactly this case, and §7 already writes one field without touching its siblings — so the **account remains the unit of work** even where the document is shared. What the default settles is the payload, in §3 below. |
| Q8 | Should `apply` be able to create a missing account? | no in UC-1; belongs to a provisioning use case |
| ~~Q9~~ | ~~Time source for `max_age_days`~~ | **decided: vault `rotated_at`, unconditionally** (#87). `rotate --max-age-days N` reads only the vault — one age per secret path regardless of how many targets share it, so there is no "oldest, newest, or any" rule to write for a multi-target account, which option 2 (database-authoritative) would have needed. `status` shows the database's own timestamp beside it (§9) as a drift smell, not folded into one number and not read by anything yet. The rejected alternative, option 3, made the database age a `diagnostics[]` warning past a threshold instead of an always-shown column; deferred partly because it needs a warning code and J3's registry is itself still open |

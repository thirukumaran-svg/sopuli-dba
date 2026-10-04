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

**The run schema said otherwise until #392.** `creds.promote` sat in the
`command` enum from the first draft through 1.20 — a name for a verb this
paragraph had already declined, in the file `03-json-output.md` §8 points at as
the definition of what the tool can produce. It is gone in 1.21, and §8 carries
the rule that let a never-emitted enum value go on a minor bump.

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
--dry-run / --confirm / --output {text,json}
```

**Three lines left this block in #392**, because they named flags the binary has
not got. `--all` and `--limit N` were never built: with no selector at all a
command already covers everything declared, which is what the paragraph below
says and what makes `--all` a second spelling of nothing, and the ceiling
`--limit` offered is `safety.max_targets` — a setting the resolver will not
accept from the command line, for the reason `00-principles.md` P5 now gives.
`jsonl` left for a third reason: at the time `--output` took `text` and `json`,
and asking for `jsonl` was a usage error. Since #9 it is a real mode, offered by
the verbs that stream (`03-json-output.md` §5) and refused by the rest. `invocation.selection` still carries `all` and
`limit` as slots (`03-json-output.md` §1); a slot in a schema is a promise, and a
line in a list shaped like help output is a claim.

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
  "origin":   "generated",
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
  "origin":         { "acme_web_user": "generated" },
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

### `origin`: where a staged password came from (#311)

`generate` writes one more key beside `pending`, saying which of two things the
staged value is:

| `origin` | means |
|---|---|
| `generated` | the tool drew it from the policy |
| `supplied` | `--from-stdin` accepted it, and an external system dictated it |

**It exists so that `apply` can tell them apart.** #268 decided that `apply`
redraws on `ORA-28003`/`ORA-28007` rather than reporting and stopping, and a
redraw is right for a password the tool drew and wrong for one an external system
owns — replacing that silently makes the tool disagree with whoever dictated it.
Nothing in the document recorded the difference, so `apply` had no way to ask.

Three rules, and each is a decision rather than a detail:

- **It describes `pending`, not the credential.** So it is written when a value
  is staged and removed when `pending` is — it is not one of the rotation stamps,
  which describe what is *current* and are refreshed at promotion. A key that
  described `pending` on some documents and `current` on others would be a key
  that can lie, and the thing reading it is deciding whether to replace somebody's
  change ticket.
- **Absent means unknown, and unknown means "do not redraw."** A document staged
  before this key existed is exactly the case where guessing wrong overwrites a
  dictated password. It self-heals on the next `generate`.
- **A value going straight into `current` carries none.** There is nothing staged
  for it to describe, and what applications are already holding is not something a
  redraw may touch. Falling through to the rule above is the correct answer and
  needs no special case.

It follows the mirror rule like every other root-level key: a scalar beside a
scalar container, a map keyed by account beside a map. `origin` therefore joins
the reserved root names, so a `secret:` ref may not name a field called `origin`.

Named `origin` rather than `source` because `apply --source` already names a
*stage*, and two meanings of one word one flag apart is a collision somebody
eventually reads the wrong way round.

---

## 4. `sopuli creds generate`

Generate a password per the policy and write it to the vault's `pending` slot.
Does not connect to the database — except optionally to read constraints.

```
sopuli creds generate --application orders-app [--account ORDERS_APP]
                      [--promote]         # write straight to `current` (no staging)
                      [--overwrite-current]  # authorise replacing an existing `current`
                      [--from-stdin]      # take a supplied password instead of generating
                      [--policy NAME]     # override the policy
                      [--offline]         # do not read constraints from any target
```

**Flow**

1. Resolve selection and policy; resolve SecretRefs from templates.
2. If reachable, connect to read *constraints* — **one connection per selected
   target, not per account** — and let the strictest answer govern the draw. The
   constraints that cannot govern anything are read on the same connection and
   reported. If no target is reachable, fall back to the policy's declared limits
   and say so in the output. `--offline` declines to ask at all.
3. Generate from a CSPRNG. Reject and regenerate candidates that violate charset,
   first-character, length-in-bytes, or composition requirements. Bounded retries.
4. Acquire the lock for the secret path (Q2, #83) — which `generate` can do
   precisely because the lock lives in the vault: this step never connects to a
   database, so a database-side lock could not have protected the write below.
5. Write to the vault: `pending = candidate` and `origin` beside it (§3), leave
   `current` untouched. One write, both keys — a write that landed the password
   and not its provenance would stage a password no later `apply` may redraw. Use
   CAS where supported so a concurrent writer cannot be overwritten silently.
   Under `--promote` that one write carries `current = candidate` instead, the
   value `current` held moved into `previous` where there was one, and the §3
   stamps. No `origin`: that key describes what `pending` holds, and a promote
   writes no `pending`.
6. Report new version, and the fact that the database has not changed.

**Notes**

**What step 2 binds the draw with, and what it only reports** (#317). One thing
binds it: the byte limit, counted in the target's character set. That is the
*deterministic* constraint — a password too long in bytes, or holding characters
the target will not accept, fails identically for every account in the selection
and one policy fix ends it, which is exactly the class of refusal that can be
moved from `apply` to here. The refusal names the target whose limit governed —
the first, where several share the strictest. When a supplied password is
refused, each violation names the target it came from (#598), since in an estate
"the target" is not an answer invariant 4 accepts.

The other three names in step 2 cannot bind anything, and are read so the run can
**say** they are there:

- a **verify function** is arbitrary PL/SQL and cannot be consulted (invariants 13
  and 14). Its *presence* is reported, including the not-knowing: from inside a
  PDB a **common** profile's `PASSWORD_VERIFY_FUNCTION` reads as the literal
  `FROM ROOT`, and reporting that as *none* would tell an operator that nothing
  will judge their password when something will. §5's `--preflight` rule — *not
  knowing is not a finding* — applied to a reading rather than a check;
- **`PASSWORD_REUSE_*`** history is hashed, so the two resource values are
  reported and never interpreted. The warning fires only under `--from-stdin`:
  fresh randomness cannot collide with a history, and a supplied password is
  whatever an external system dictated. A rollback is the other case where the
  value is not fresh, and §5 reports it under its own code (#568);
- **`PASSWORD_VERSIONS`** is which verifiers the account holds, reported as a
  fact. Which of them a later rotation regenerates is the server's own
  configuration and not this tool's.

So `ORA-28003` and `ORA-28007` stay unpredictable before the statement is issued
and #312 handles them by redrawing. None of this is a prediction that a password
will be refused; it is the run saying that something other than the policy will
judge it. The readings go in the document's `constraints` section
(`03-json-output.md`), the caveats in `diagnostics[]` as `SOPULI-W016` and
`SOPULI-W017`, and both are printed under the constraints line in the default
output — a warning nobody can see in a terminal is not surfaced.

**Measured, on 26ai Free 23.26.2.0.0.** `FROM ROOT` is narrower than the
paragraph above used to leave it looking: a local profile read from inside a PDB
answers with its function's name, and `DEFAULT` — which is common — answers
`NULL`. So the unreadable case is a user-created common profile seen from a PDB.
A profile naming no verify function reports the **string** `NULL`, and
`PASSWORD_REUSE_MAX`/`PASSWORD_REUSE_TIME` report `UNLIMITED`; both are vendor
words in columns a reader expects other things in.

**There is no single strictest limit**, and the run does not invent one. A limit
is a byte count *and* the character set it is counted in, which makes "stricter"
a partial order: 128 bytes of `WE8MSWIN1252` holds more characters than 128 of
`AL32UTF8` and holds *fewer distinct* ones, so neither contains the other. Every
reading is kept and the two questions are asked separately:

- a **generated** password is drawn against the smallest byte count and nothing
  else. §8's alphabets are ASCII and an ASCII character is one byte in every
  character set the driver maps, so the count is the only thing that can bind it.
- a **supplied** password (`--from-stdin`) is validated against *every* answered
  target. A character storable in one target's set and not another's is a
  violation there whichever target had the smallest count — and it is the
  "characters the target will not accept" half of what this step is for. One
  violation is reported once however many targets report it.

**Reading is not writing, and the lock's argument is unchanged.** `creds generate`
takes the vault's advisory lock because there is no *change* here for a
database-side lock to protect (Q2, #83). That was never the same claim as opening
no session, and a read does not make one.

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
  This is **outside invariant 9 rather than an exemption from it**, and it is
  decided rather than assumed (#254): the invariant governs commands that
  converge on a state, and a fresh draw has none. `apply` is the convergent half
  and reports `changed: false` on a re-run. It read *the one exemption* until
  H7 (#454) put UC-2's reset on the same footing for the same reason and
  restated the invariant as a scope rule — this verb's behaviour is unchanged,
  and what changed is that it is no longer a special case of one.

### `--promote`, and the exception it takes to invariant 7 (#257, decided)

```
sopuli creds generate --application acme --promote [--overwrite-current]
```

Write the drawn password straight to `current`, with no `pending` and no
database touched. It exists for **S1 — first adoption of an existing account**:
the account is there, its password is known to humans and is not in the vault,
and `generate --promote` → `apply` → `check` adopts it without the tool ever
needing the old password. Staging first would mean a `pending` nothing has read
and a `current` that does not exist, then a promote of one into the other — two
writes and an intermediate state, to describe a document with no rotation in
progress.

**It takes invariant 7's one exception, and the exception is
`--overwrite-current`.** The invariant says never promote before every target has
confirmed, and `--promote` confirms nothing. Both readings were weighed (#257)
and the wider one was chosen: the flag may write over an existing `current`,
because refusing there outright would leave `--promote` unable to mean *I know
what I am doing* — which is what an operator passing it is saying. What makes
that safe to allow is not that the write is harmless; it is that the wider case
has to be asked for by name:

- **no `current` for that account** — nothing is reading the field being written,
  so there is no window to protect. Written without a question, and without a
  flag;
- **a `current` exists** — the field every application reads is about to be
  replaced by a password no database has been given, so the run refuses on
  **exit 8** unless `--overwrite-current` was passed, naming the accounts. Exit 8
  is "aborted, or confirmation declined", and a required authorisation nobody
  gave is that: the file is not wrong and the run is not broken.

**No prompt, and identically so attended or not.** `--overwrite-current` is an
authorisation you type, not a question you answer — `--force`'s register rather
than `--confirm`'s. An operator who did not know some accounts had a `current`
reads the refusal, then `--dry-run`, then decides; that is a better sequence than
a y/n on a write to the field every application reads, and it makes a scheduled
run behave exactly like a hand-run one.

**The value `current` held moves into `previous`**, in the same write that
replaces it — the prior password, never the one being written — or §8's rollback
has nothing to roll back to. An account being seeded has no such value and gets
no `previous`. One CAS write per document carries all of it, plus the §3 stamps,
like every other write this command makes.

**Its own flag rather than `--confirm`, and the reason is reversibility.**
`--confirm` was the obvious spelling — it already means *proceed without asking*
on this verb, and P5 gives every mutating command one. It was refused because
that meaning is scope-free by construction: every question this command learns to
ask in future folds into it, so the flag's blast radius grows without anyone
editing it, and an operator passing it because `safety.confirm_environments`
covers prod would also be authorising an overwrite they had not thought about.
The decisive argument is what each choice costs to undo. Shipping `--confirm`
alone and adding a dedicated flag later **breaks** every script that relied on the
first — a scheduled adoption run starts exiting 8. Shipping the dedicated flag
and later letting `--confirm` satisfy it is purely permissive: nothing that
worked stops working. On a gate protecting the field every application reads, take
the choice you can walk back.

**`--confirm` keeps its single meaning** and does not satisfy this gate. The two
are asked for different things — assent to touching a listed *environment*, and
authorisation to replace a *value* — and a run that needs both passes both.

**`--promote --dry-run` names the two groups separately**: accounts that would be
**seeded** and accounts whose `current` would be **replaced** are different risks,
and an operator should not have to count them. A preview is never gated, so it is
also how somebody finds out they need the flag.

**The refusal is at plan time** (invariant 4), read from the documents before
anything is written — and checked again under the lock, because a `current` that
appears between the two would otherwise be overwritten by a run that was told
there was none. Where the flag *was* passed, the second read has nothing to
refuse: the overwrite is authorised whenever it is found.

**What it reports is `VAULT_ONLY`** — the vault holds this password and no
database has been asked. A new `state` value rather than a reused one: the other
four candidates each assert something untrue (`03-json-output.md` §3), and
`PENDING_APPLY` in particular would send `check` and `apply` looking for a
`pending` that does not exist. `sopuli-run-1.20` carries it.

**Any `pending` is cleared, with the `origin` describing it.** Not tidiness:
`creds apply --source` defaults to `pending` where there is one, so a staged
password left beside a freshly promoted one is a password the next `apply` would
prefer — undoing this run without anybody asking it to. The promotion patch that
`creds apply` uses already does this, and `--promote` reuses it rather than
spelling a second promotion.

**Measured end to end**, on tier 1 against Oracle Free 23.26.2.0.0 and a dev-mode
Vault: `generate --promote` seeds `current` at v1, `apply` reads it with
`SOURCE: current` and reports `IN_SYNC` "changed and verified by login", and
`check` then reports `IN_SYNC` "vault v1 verified by login". A second promote
over that document refuses on exit 8 naming both accounts; with
`--overwrite-current` it writes v2, and `previous` holds what v1's `current`
held.

**There is still no `creds promote` verb**, and this does not reopen #276. That
decision is about promoting a *rotation* — advertising a password on the strength
of an earlier run's document, without re-verifying. This promotes a password
drawn in the same breath, for an account that has no rotation in flight.

---

## 5. `sopuli creds apply`

Take what the vault holds and make the database match it.

```
sopuli creds apply --application orders-app
                   [--source {pending,current,previous}]  # default: pending if set, else current
                   [--confirm]                            # required for --source previous
                   [--strategy {rollover,staged,direct}]
                   [--preflight]                          # survey every target before writing anything
                   [--repair FILE]                        # act only on a run's unconfirmed set
```

**Flow, per target**

1. Connect using the target's admin credential (§ P2 bootstrap order).
2. Verify scope: the connection really is in the container the config claims;
   the database is open read-write; version and capabilities as expected.
3. Verify the account exists and read its state (locked? profile? verifiers?).
   Missing account → `ACCOUNT_MISSING`, do not create it (out of scope for UC-1).
4. Change the password (see § 6 for the Oracle statement details). Where the
   server refuses the *value* — a verify function, a reuse rule — draw another
   and try again, bounded (§6.4).
5. Verify immediately with a fresh connection as that user (§ 7).
6. Record a per-target result.

**After all targets**

- All succeeded → promote in the vault: `previous = current`, `current = pending`,
  clear `pending`, stamp `rotated_at`/`rotated_by`. Exit 0.
- The run was narrower than the promotion → do **not** promote, and exit 4. See
  *The promotion gate* below.
- Some failed → do **not** promote. `pending` stays. Report per-target status and
  exit 4 (partial). The remedy is `apply` again — narrowed by `--repair FILE`
  where the run's document was captured — and it is safe to re-run either way.
- All failed → nothing changed anywhere. Exit 1.

**The promotion gate, stated once (decided in #406).** A secret document is
promoted only when every (account, target) pair it needs has confirmed **in this
run**, and the pairs it needs are counted over the **configuration**, not over
what the run was narrowed to:

- **every target the same credential is declared on** — same document, same ref,
  so one promotion moves the password every one of them is supposed to hold;
- **on a forward promotion, every pair of every sibling account in the document
  that has a `pending` of its own.** Its staged password may already be on its
  database, which is exactly what an earlier partial run leaves, and a promotion
  that skipped it would strand it there, database ahead of `current`. A sibling
  with nothing staged has no rotation in flight and is not needed, which is what
  keeps `--account` able to rotate one account in a shared document;
- a rollback (`--source previous`) asks only the first. It refuses where
  anything is staged, and a sibling's `previous` is not a rollback anybody asked
  for.

A run narrowed past any of those — `--target`, `--select`, `--account` or
`--repair` — still changes the databases it was pointed at, because that is how
a rollout is staged target by target, and then **withholds the promotion**:
`pending` stays, the run exits 4, and `SOPULI-W027` names the pairs it left out.
The remedy is a run wide enough to include them, so the `repair with:` line on
that run drops the selectors rather than echoing them back. It costs one login
per pair the narrow run already converged, and reports `changed: false` for
each. An account a guardrail skipped is inside the run, not outside it (#286
decides what a skip means).

**Why, when nothing failed.** Before #406 the gate counted only the pairs the
run had visited, so `apply --target appdb-alpha` promoted an account whose other
target still held the old password: the state invariant 7 exists to prevent,
reached by a selector rather than by a failure, behind an exit 0. The two
alternatives were leaving it and documenting the exception, and re-verifying the
excluded pairs before promoting; the second connects to targets the operator
deliberately excluded and costs the same logins as the wider run, so the gate
refuses instead and asks for that run.

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
policy, each opt-in: account unlock and profile assignment. Each is reported as a
separate change so the diff stays readable.

This sentence used to name four. Two of them are built (#300, #301) and two turned
out not to belong to this use case at all — `PASSWORD_EXPIRE` handling and
default/temporary tablespaces. The reasons are below rather than in a commit
message, because both read as missing features for as long as they stood here.

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
`02-oracle-privileges.md` keeps the privilege off the service account, and Q4
(#88) decided it: never, in any credential-sync verb. `creds finish-rollover`
takes the other half of that position — it *reports* the `ALTER PROFILE` an
operator would run, and never issues it. Creating and altering profiles is UC-4's,
provisioning (see the roadmap in `docs/README.md`), where a profile is part of
making an account exist rather than a shared object a credential rotation reached
sideways — an open question there, not one #88 closed.

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

For the two that were dropped, see below.

### `PASSWORD_EXPIRE`: why there is no such attribute (#302, closed)

§5 listed "`PASSWORD_EXPIRE` handling" among the four opt-in attributes for as
long as this document has existed. There is no operation left in it for UC-1, and
saying so is worth more than an attribute nobody could have used correctly.

**Clearing an expiry is already what `apply` does, and it is not opt-in.** Setting
a password clears `EXPIRED` — that is Oracle's behaviour, not a choice this tool
makes — which is why §6.4 lists `ORA-28001` as *resolvable by apply* and why
`apply` deliberately does not treat an expired account as a reason to stop. An
attribute for it would be a switch for something that is already true and cannot
be turned off.

**Which leaves expiring deliberately, and that breaks the accounts this use case
is about.** `ALTER USER … PASSWORD EXPIRE` after a rotation forces the next login
to set a new password. An application account cannot answer that prompt: the run
would write a password to the vault, put it on the database, and leave an account
that authenticates once into a session demanding a replacement no connection pool
will supply. The tool would rotate the credential and break the application in one
run — and it would *notice*, since an account that reads `EXPIRED` afterwards is
never promoted (§5's confirmation gate) and the run exits 4. A feature whose
successful use is a partial failure is not a feature.

**It is a real operation for a different use case.** A DBA rotating a *human*
account wants exactly this: hand over a password that must be changed on first
use. That belongs to a human-account use case, which is not written yet, and it
brings its own vocabulary with it — a credential nobody stores in a vault, a
handover rather than a sync, and no application to keep serving. Nothing about it
fits UC-1's first sentence.

**Two neighbours it would have collided with**, and both are why the phrase read
as ambiguous rather than absent:

- **"make the old password stop working now" already shipped**, as `--strategy
  direct` (§6.3) and `creds finish-rollover` (§6.3). That is
  `ALTER USER … EXPIRE PASSWORD ROLLOVER PERIOD`, a different statement, and it is
  the only consumer of the `expire_password` capability today. An attribute
  spelled `PASSWORD_EXPIRE` would have been a second way to ask for it.
- **The grace period**, which §6.4 files as informational and surfaced in
  `status`. That is a reporting question rather than an attribute — and looking
  for it turned up a real one: `EXPIRED(GRACE)` is currently read as a hard
  expiry, so `check` reports `EXPIRED` for an account whose password works and
  never attempts the login that would prove it. #309, where the states have since
  been measured: the status string is confirmed, the grace notice arrives as a
  connection *warning* rather than an error, and `ORA-28002` — the code §6.4
  names — is not what 26ai sends.

### Tablespaces: provisioning, not rotation (#303, closed)

§5's fourth attribute was default and temporary tablespace. It goes to UC-4
(provisioning), for a reason that is about *when* rather than about *whether*:

**`ALTER USER … DEFAULT TABLESPACE` moves no existing segment.** The account's
objects stay exactly where they were; what changes is where the *next* one is
created without an explicit `TABLESPACE` clause. During a credential rotation that
is the worst kind of change — it reads as done, it is half done, and nobody
looking at a rotation's output would think to check. During provisioning, where
the account has no objects yet, it is simply part of creating one correctly.

The same is true of the other things an account needs in order to exist — quotas,
grants, roles. None of them is a *credential* and none of them belongs to a verb
whose job is to make a database hold what a vault holds. Q8 already puts account
creation in that use case; this is the same boundary one field along.

So UC-1's attribute list is two, and it is closed rather than merely unfinished.
A third would be a decision, not an implementation detail.

### What shipped in #259, and what the flags above still describe

The spine is implemented: read the source, set the password, verify, promote per
document. `--strategy` arrived with #262 and is described in §6.3; `--source`
with #265, and the rollback it exists for is §8. `--repair` arrived with #391
and is described below. **Every flag in the sketch above is now built.**

A second, `--continue-on-error`, was in that sketch and has been **removed from
it** rather than built (#266); the section below says why, because a flag that
merely stopped being mentioned would read as an omission for as long as anybody
remembered it.

Step 4's redraw is decided (#268) and built (#312). §6.4 carries the reasoning
and the four rules.

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

**A profile that restricts reuse usually refuses a rollback** (#568). `previous`
is, by construction, the password the account held one change ago, whenever this
tool made that change — so where `PASSWORD_REUSE_MAX` or `PASSWORD_REUSE_TIME`
is anything but `UNLIMITED`, the value is the one most likely of any to be in the
history, and the statement is likely to fail with `ORA-28007` — certain where
one limit is `UNLIMITED` and the other a number, and dependent on elapsed time
and intervening changes where both are numbers. Measured on ADB, whose own
`DEFAULT` carries `4` / `1`, and on tier 1's `SOPULI_REUSE` (`5` / `UNLIMITED`):
both refused, both failed safely, and `check` afterwards was `IN_SYNC` against
`current`.

The run says so, and does not refuse in advance. Every rollback that reaches the
statement on such a profile carries `SOPULI-W028`, one per target and profile,
naming both values, whichever way the statement went. Reported rather than
interpreted, which is §4's rule for the same two values: when both are numbers,
Oracle's rule also counts the changes made outside the tool, which it cannot
see, so a plan-time refusal would sometimes refuse a rollback that would have
worked. A refused rollback is never redrawn — `previous` is the only value it
has — and its row's hint says that rather than the driver's "draw another".

**Under `--preflight` it is said before anything is sent** (#580). The survey
already reads each account's state, profile limits included, so a rollback on a
reuse-restricted profile raises the same `SOPULI-W028` there — under `--dry-run
--preflight`, which is "show me the plan and tell me whether it would work", and
in a real run, where the run does not raise it a second time for the same target
and profile. Raised ahead of the statement it is a prediction: it cannot know
that an account turns out to hold the password already, which the run's own
reading does. Nor is it raised where the run would first move the account to
another profile: the limits read are then not the ones the statement meets, and
the run's own reading covers it. A plain `--dry-run` still connects to nothing,
and so cannot say it.

**On such a profile, the way back is a rollover window, not a rollback.** A
profile with `PASSWORD_ROLLOVER_TIME` makes every rotation open one (§6.3): the
old password keeps authenticating until `finish-rollover` or the window's end,
which is exactly the escape hatch a rollback would have been, and it involves no
reuse because nothing is set back. An estate whose baseline restricts reuse —
CIS-style profiles set both limits — should plan its recovery around that
window rather than around `--source previous`. The window is only there if it
was opened by the rotation, though, so the decision has to be made before
rotating, not after something breaks.

Rollback stays bounded to one generation, which is Q3 (#84) and not this
issue's to reopen: OCI holds exactly one `PREVIOUS`, and §7's stage vocabulary
has nothing to address an older one with.

Three decisions inside the spine are worth stating here, because none of them is
readable off the flag list:

- **The database is asked before it is changed.** Invariant 9 names `apply` as
  the convergent verb, and `apply` verifies by login: `check --method hash`
  (#437) does not reach it, so a login is how `apply` knows whether a change is
  needed. So each account is verified
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

**"Says so" means in the text as well as in the document** (#606). A survey that
refuses prints every finding in its table, caveats included. A survey that passes
prints no table, so its caveats are added to the run's notes: one note per target,
naming what could not be established and the server's reason, with the accounts
that share a cause on one line. They print on every such run, `--dry-run` or not,
and `rotate`'s pre-flight prints them the same way. Leaving them JSON-only was
considered and declined. It holds for a real run, whose own statements meet the
same cause and name it per account. It fails for `--dry-run --preflight`, where
nothing runs afterwards and a clean "nothing was applied" would answer "would it
work" without saying part of the question went unasked.

**`--dry-run --preflight` surveys too.** It writes nothing and needs no lock, and
"show me the plan, and tell me whether it would work" is the invocation somebody
reaches for first — a flag that silently meant nothing there would be a trap.

### `--continue-on-error`: why the flag is gone rather than built (#266)

The sketch above used to carry `--continue-on-error`, described as the other
half of a fail-fast default. It is removed, because **the behaviour its name
promises is already what happens**, and the run-wide stops that are left are
each something else wearing the same word.

What a run does today when one part of it fails:

| failure | today |
|---|---|
| a target that will not connect | `ERROR` rows for its accounts, the run moves to the next target |
| an account whose statement the server refuses | `ERROR` row, the run moves to the next account |
| a **promotion** that fails | that document is not promoted, the others still are |
| a **lock** somebody else holds | exit 7, nothing ran |
| a **lock** this store or path cannot fence | exit 5, before anything is read or written (#346) |
| a **fence check** that finds the lock stolen | abort, mutate nothing further, exit 7 or 4 |
| a **pre-flight** blocking finding | exit 1, nothing was written |
| a **capability** the estate cannot honour | exit 5, before anything is written |
| a **vault document** that will not read | the store's own exit code, nothing ran |

The first three rows are the flag's whole intent and they need no flag: §5 wants
an estate surveyed rather than abandoned, so a failure that belongs to one
target, one account or one document is confined to it.

The first row is the one the flag was written for, so it is measured rather than
described — an estate of two targets, the unreachable one **first**, against
Oracle Free 26ai 23.26.2.0.0 and dev-mode Vault:

```
ACCOUNT        TARGET       STATE    DETAIL
acme_web_user  appdb-beta   ERROR    ORA-12170: Cannot connect. TCP connect timeout of 20s for host 192.0.2.10 port 1521.
acme_web_user  appdb-alpha  IN_SYNC  changed and verified by login

1 changed, 1 promoted to `current`, 1 not confirmed
```

Exit 4. The target that could not be dialled did not end the run, the one after
it was applied, and only the failed account's document was held back from
promotion — which is every behaviour `--continue-on-error` was named for,
without the flag. The same estate under `--preflight` refuses instead, at exit 1
with `nothing was written`, which is the row below it.

The remaining five rows are the ones `--continue-on-error` would have to reach in
order to mean anything, and none of them is a candidate:

- **the stolen lock must not move.** Another run is authoritative and this one
  stops mutating (§8's "any fence check" row). A flag that overrode it would let
  two runs write the same account, which is the outcome the fence exists to
  prevent;
- **the lock refusal must not move.** Exit 7 means nothing ran, and that is a
  promise a scheduler reads (`../design/03-json-output.md` §6);
- **the capability refusal must not move.** Invariant 4 makes a plan-time
  refusal with its own exit code the required shape, not a preference;
- **the pre-flight refusal could move, and should not be spelled this way.**
  "Survey everything, then apply to the targets that cleared" is coherent — with
  rollover as the default strategy a partial apply causes no outage — but it is
  a guardrail override, and this command already has one. `--force` waives the
  §4 account guardrails and records every waiver in the run document; an
  operator who has read the findings and wants the run anyway is asking for the
  same thing at estate scope. If that is ever wanted it belongs there, under the
  flag whose name says what it does. It is not wanted yet: nobody has run a
  pre-flight and wished it had been advisory, and a flag that only means
  something when a *second* flag is passed is the trap `--dry-run --preflight`
  is written to avoid;
- **the unreadable vault document is a different question.** One document out of
  twenty that cannot be read aborts before any `ALTER USER`, because the read is
  one pass over every path the run needs. Degrading that to `ERROR` rows for the
  affected accounts is arguable — it is the only one of the five that is
  genuinely "keep going" — but it weakens the same "sopuli could not run"
  promise exit 7 carries, and it is a change to what an exit code means rather
  than a flag. It gets its own issue if the multi-store case ever makes it real.

So the honest scope was empty, and a flag documented as doing what the tool does
anyway is worse than no flag: somebody passing it would conclude the runs where
they did not pass it had behaved differently.

### `--repair`, and where the DRIFT list comes from (#264)

```
sopuli creds apply --repair result.json   # act only on what that run left unconfirmed
```

**The list comes from a previous run's document.** `--repair` takes a path to
one — typically an `apply` that exited 4, or a `check` that exited 3 — and
narrows this run to the (account, target) pairs it reported as not confirmed.
Built in #391; what follows is what it does.

**The filter is the row's state, never the document's exit code**, and that is
deliberate rather than an omission (raised in review on #391). Refusing by exit
code would refuse an `apply` that exited 1 — every target failed, nothing
changed anywhere — which is the document *most* worth repairing from; and a
`check` that exited 1 because one target was unreachable, where retrying is
exactly the remedy. Nothing is lost by accepting them: `apply` verifies every
pair before it touches it, and invariant 5 still bounds what it can reach. What
the producer check refuses is a document from a command that reports no repair
set at all, such as `creds generate`.

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
freshness is a **warning naming the document's age** — `SOPULI-W020` — not a gate
with a threshold in it: a threshold would have to be wrong for somebody, and the
run it refused would have been safe. What *is* refused is a document describing a
different estate, before a target is dialled. A repair aimed at the wrong estate
is the one failure the two properties above do not catch.

**It reads `invocation.config_files`, not `config.sources[]`**, and this
paragraph said the second until #391 built it. The `config` section is emitted by
`config show` and `target list` only, so it is absent from every document this
flag can be handed — the estate could not have been checked the way this was
written. `invocation.config_files` was itself declared and never written until
#402; a document produced before that carries none and is refused, on whether the
field is *there* rather than on what version wrote it.

Paths and not their content, which decides one case worth naming: the same file
copied to a second path is a different estate to this check, and moving a config
file invalidates the documents produced over it. The message names both lists, so
the operator can see which. Order matters too — it is the layering order (§5 of
`01-configuration.md`), so the same files layered the other way round resolved
different settings and are not the same estate.

**The refusal exits 2, with no run document** (J7). That is what every other
selector does when it does not resolve: `--target nosuch` already raises
`ArgumentError` from `refuse_unknown`, and `--repair` feeds a filter, so a filter
that does not resolve is an invocation that did not resolve. Exit 9 was the
alternative and was declined in #391 — it means *fix your configuration*, and the
configuration here is fine.

**A repair of a rotation is the DDL, not the promotion** (#406). A repair
narrowed to one of a document's two accounts changes that account and then
withholds the promotion, because the sibling the earlier run already applied
still has its `pending` staged and nothing in this run asked its database
anything — §5's promotion gate. So a partial rotation takes two runs to finish:
`--repair` for the pairs that failed, then `apply` without the narrowing, which
spends one login on each converged pair and promotes. A repair from `current` —
drift, with nothing staged — has nothing to promote and still finishes in one.

**Exit 4 names the invocation that repairs it, and that part shipped.** A partial
run's closing line says what to type, narrowed the way that run was narrowed and
carrying `--config`, `--profile`, `--source` and `--strategy` so the repair
resolves and acts the way the run did:

```
1 changed, 1 not confirmed
repair with: sopuli creds apply --config estate.yaml --select env=prod
```

It **still** names the plain re-run now that `--repair` exists, and #391 found
two reasons this section could not have known. The first: The emitter writes the JSON
document or the human text and never both, so this line is only ever read in
**text** mode — and a text-mode run leaves no document on disk for `--repair` to
be pointed at. Replacing the line would hand a half-applied estate an invocation
that cannot run, which is the same trap the paragraph above refuses.

So the flag gets a second line instead, saying what it needs:

```
1 changed, 1 not confirmed
repair with: sopuli creds apply --config estate.yaml --select env=prod
         or: --repair FILE, if you captured this run with --output json
```

A JSON consumer needs no line at all: it has `results[]`, and
`03-json-output.md` §7's recipe is the same filter the flag applies.

The second reason is that **the flag does not fix both shapes of exit 4.** On
§8 case 7 — every target confirmed and the vault not promoted — there is no
unconfirmed row for a repair set to be built from, so `--repair` would filter
the estate to nothing and report `nothing to apply`. The plain re-run does fix
it. So the flag's line is printed only where an unconfirmed row exists, while
the re-run's is printed on both (found in review on #391).

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
  - quote the password, and **reject** a password containing `"` rather than
    escape it — an Oracle quoted identifier has no escape for it (invariant 11).
    The `alnum_safe` charset default never draws one. This bullet said "escape
    embedded `"`" until #457, which contradicted the invariant it now cites
  - **not in `V$SQL`, on 26ai.** Measured on 26ai Free 23.26.2.0.0 in `CDB$ROOT`
    and a PDB: no cursor for the DDL is retained at all, so there is nothing to
    mask. Unified audit does retain the statement, masked to `IDENTIFIED BY *` at
    write time, in `AUDSYS.AUD$UNIFIED` as well as the view. Neither result is a
    general Oracle guarantee — re-verify per version with
    `sql/oracle/02_password_leak_probe.sql`. **SQL trace has now been measured and
    does not capture the password** (#407, 2026-09-11, 26ai 23.26.2.0.0 and 21c
    21.3.0.0.0): a session traced at 10046 level 12 writes the cursor truncated,
    `ALTER USER sopulitest IDE`, stopping one character into `IDENTIFIED`. This
    paragraph said "remains untested — the greps have not been run" until then,
    and the assumption it carried was the pessimistic one, so retiring it is a
    correction in the tool's favour rather than a new risk.
    **Trace-consuming 3rd-party monitors are still untested**, and are a
    different question: what they retain is theirs, not Oracle's. The tool:
    never enables trace on its own sessions, keeps the statement out of its own
    logs, and documents the residual risk.
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
| Application root | every account is application-common; a statement with **no** container clause is already container-wide | distinct scope, must not be conflated with CDB root |
| Application PDB, local user | connect to the application PDB service, then plain `ALTER USER` | ordinary; measured, see below |

Guardrails: refuse `CONTAINER=ALL` when not connected to a root; refuse to treat
`C##`-prefixed names as local users; refuse to apply to a PDB that is not
`OPEN READ WRITE`; skip (with a clear status) PDBs that are closed or in a
standby, rather than failing the whole run.

**An application root is refused; an application PDB is not** (#171, #204). The
refusal used to cover both and could fire on neither, because the driver resolved
the scope from `SYS_CONTEXT('USERENV','CON_NAME')` alone and an application
container has an ordinary container name. Both halves changed once there was
something to measure.

**Measured against a real one** (#204, 2026-09-03, 26ai Free 23.26.2.0.0;
`sql/oracle/03_app_container_probe.sql` builds the container and reproduces every
line). The two things this section guessed at are now answers, and one of them is
the reverse of the guess:

- **Detection needs no grant.** `SYS_CONTEXT('USERENV','IS_APPLICATION_ROOT')`
  and `'IS_APPLICATION_PDB'` separate both scopes from an ordinary PDB, and a
  service account holding exactly §2's PDB-mode grants reads them in a session
  where `V$PDBS`, `DBA_PDBS` and `CDB_PDBS` are all `ORA-00942`. The grant this
  was expected to cost does not exist.
- **`C##` names cannot exist in an application container at all** — `ORA-60534`,
  either way. So the question this section asked, whether an application-common
  user is `C##`-prefixed the way a CDB common user is, has a third answer: there
  are no common-prefixed names there to be either.
- **In an application root every account is application-common**; a local one is
  `ORA-65049`, and `CREATE USER` with no container clause defaults to
  application-common. The hazard follows, and it is not the one guessed above.
  `CONTAINER=ALL` does mean something narrower there — but the tool never gets
  that far. It sees a name without a `C##` prefix, concludes *local account*,
  appends no clause, and issues a statement Oracle accepts and applies across the
  whole application container. **The danger is not that the clause means less
  than it looks; it is that the absence of one already means more.** Confirmed by
  login: after a clauseless rotation in the root, the new password authenticates
  in an already-synced application PDB with no sync in between, while the old one
  does not. `password_change_date` in that PDB reads empty throughout and would
  have reported the opposite — which is Q1's argument for `login` again (#86).
- **In an application PDB the refusal is not needed.** A local account is
  entirely ordinary, and an application-common one is refused by Oracle itself:
  `ORA-65066` with no clause, `ORA-65040` with `CONTAINER=ALL`.

**What that produced.** The scope now resolves: `IS_APPLICATION_ROOT` and
`IS_APPLICATION_PDB` are asked from within a container that would otherwise be
`pdb`, so a non-CDB and a root session pay nothing for a question whose answer
they already have. An application root is refused, naming the scope and saying
that a clauseless rotation there reaches the whole application container. An
application PDB takes the ordinary path — a local account gets a plain statement,
and a `C##` one is refused by the common-user guardrail, now for a second reason:
such an account cannot exist there at all.

The one case neither guardrail can pre-empt is an application-common account
declared against an application PDB, because it carries no marker to recognise it
by. Oracle refuses it, `ORA-65066`, which is mapped to the container-misuse
category and exit 9 with a hint naming the root as the place to rotate it from.

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
  actually has a non-zero `PASSWORD_ROLLOVER_TIME`. Where it has not, the tool
  **reports the exact `ALTER PROFILE` an operator would run and issues none** —
  decided in Q4 (#88), and the same position `finish-rollover` takes from the
  other end. A profile is shared, so editing one reaches accounts nobody
  selected, which is a blast radius invariant 5 cannot express: the config
  whitelists accounts, not profiles. Enabling rollover on a site that has not got
  it is therefore an out-of-band DBA change, and the tool's job is to name the
  statement rather than to run it. What the run does *instead* depends on whether
  the strategy was asked for — refused at pre-flight if it was, resolved per
  account to `staged` if it was not; see "What `--strategy` actually decides".
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
| ORA-28003 | password verify function rejected it | `apply` redraws (bounded), preserves the server message |
| ORA-28007 | password cannot be reused | `apply` redraws; never retry the same value |
| ORA-01017 | invalid credentials | verification failure → drift, not a crash |
| ORA-28000 | account locked | report `LOCKED`; unlock only where the policy declared it (#300) |
| ORA-28001 | password expired | distinguish from drift; resolved by apply, since setting a password clears the expiry. The tool never expires one deliberately — see §5 (#302) |
| ORA-28002 | password in grace period | informational, surfaced in `check` and `status` as `SOPULI-W013` — **not** as a state (#309). **Not the code 26ai sends** — see the note below |
| ORA-01031 | insufficient privileges | fail early in pre-flight, name the missing grant |
| ORA-65040 / ORA-65048 | container-clause misuse, error while applying to a PDB | scope guardrail message |
| ORA-12154 / ORA-12541 | naming/listener | connectivity, distinct exit path |
| ORA-28040 / ORA-01017 with version mismatch | verifier / `ALLOWED_LOGON_VERSION` mismatch | explain password-version implications |
| DPI-1047 / DPY-3001 | the *client* library, not the server: Instant Client missing, or thin mode reached because thick-mode initialisation did not happen | `config` and exit 9 — the same landing ADR-006 gives a backend that is configured and not installed, because it is fixed on this machine by the person reading the message |

**The grace-period row is the one measurement in this table that came back
differently from the book** (2026-09-02, 26ai Free 23.26.2.0.0, `python-oracledb`
in thick mode — full method in #309). Three things, and each changes what a fix
may rely on:

| Attempt | What actually happens |
|---|---|
| in grace, `PASSWORD_GRACE_TIME` limited | the login **succeeds**; `connection.warning` carries `ORA-28098` |
| in grace, `PASSWORD_GRACE_TIME UNLIMITED` | the login **succeeds**; `connection.warning` carries `ORA-28011` |
| hard expired | raises `ORA-28001`, as the row above says |

- **It is not an error.** A grace login connects, so nothing is raised and the
  notice arrives on the connection. `ORA-28002` sits in the table above as the
  code to expect and was not produced in either shape on this release. Whatever
  the server does attach is now carried as `SOPULI-W014` rather than discarded
  (#322) — verbatim, with its code as data, since the code varies with the
  profile.
- **The code depends on the profile, not just the version** — two codes for one
  condition, decided by whether the grace time is limited.
- **`DBA_USERS.ACCOUNT_STATUS` says `EXPIRED(GRACE)` in both cases**, and does not
  vary. So the dictionary is the dependable signal for the grace period and the
  login warning is not, which is what keeps a fix off a per-release code table.

Whether older lines send `ORA-28002` is **unmeasured** — tier 2, and deliberately
not on #309's critical path for exactly that reason. The row stays because the
code is real; what is now known is that it is not what 26ai sends.

#### What the grace period is reported as (#309, decided)

**A warning beside the state, never a state of its own.** An account in its grace
period authenticates, so `check` verifies it like any other and reports what the
login found:

```console
$ sopuli creds check --application acme
ACCOUNT        TARGET       STATE    DETAIL
acme_web_user  appdb-alpha  IN_SYNC  vault v1 verified by login

all 1 in sync

1 note:
  acme_web_user on appdb-alpha: the password is in its grace period: it still
  works, and expires 2026-09-03T14:26:11Z (in 23h56m)
```

The verdict still says **in sync**, because it is. `creds status` counts it
instead — *1 account: 1 in a grace period* — since that command's closing line
answers *is there anything to do*, and there is: rotate before the window
closes.

The alternative — a `state` of its own — was considered and refused. `state` is
one field, and an account in grace may equally well have **drifted**: a value
there would have to displace `IN_SYNC` or `DRIFT`, and either choice hides the
answer the reader came for. As a warning, *drifted, and expiring on Friday* is
sayable. It is also a smaller contract change: `results[].warnings[]` already
exists, so nothing in `03-json-output.md` §2's state enum moves.

**Read from the dictionary, not from the login.** `ACCOUNT_STATUS` says
`EXPIRED(GRACE)` in every profile shape, so the warning is produced on runs where
no login happened at all — which is exactly when the lockout guard declined to
try and an operator most wants the rest of what is known.

**The remedy the warning implies is `creds apply`**, and it needs no new
machinery: setting a password clears the expiry, so a rotation closes the window
as a side effect of what it already does (§5).

Before this, `EXPIRED(GRACE)` was read as a hard expiry — `check` reported
`EXPIRED` and skipped the login, which left a scheduled check blind to drift for
the whole grace window, the one period before a forced expiry when somebody most
wants to hear *still in sync*.

### Which verb redraws, and why it is `apply` (#268, decided)

"Regenerate" without a subject is what made the two rows above ambiguous for as
long as they stood there. The subject is **`apply`**, and `generate` is not where
this is fixed.

Neither refusal can be predicted before the `ALTER USER` is issued, so there is
no earlier verb that could have avoided it:

- `ORA-28003`'s verdict comes from arbitrary PL/SQL, and the function cannot be
  consulted. Calling it needs the password inside a PL/SQL block (invariant 13)
  or in a bind (invariant 14), and there is no third way to invoke one. That is
  also why §5's flow no longer claims to pre-flight a password against the verify
  function "where possible": there is no possible.
- From inside a PDB, a **common** profile's `PASSWORD_VERIFY_FUNCTION` reads as
  the literal `FROM ROOT`, so a service account without a root connection cannot
  even *name* the function it has to satisfy (`02-oracle-privileges.md`).
  Measured for #317: a *local* profile answers with the function's name from the
  same session, and `DEFAULT` answers `NULL` — so §4 step 2 reports the reading
  it got rather than assuming the container decides it.
- `ORA-28007` is hashed per-account history. `apply` already reads
  `PASSWORD_REUSE_MAX`/`TIME`; they state the rule, never whether this draw
  collides with it.

§4 step 2's constraint read — connect to a representative target and draw against
the strictest one — remains worth building and removes a different set of
refusals: byte length and character set. Those are the *deterministic* failure,
where one policy fix ends it for every account in the selection. It is not a
prerequisite for the above, and it would not remove either row.

**Four rules govern the redraw**, and each exists because the alternative is
worse:

| | |
|---|---|
| **Bounded** | three draws, the value the run arrived with included. A server that has refused three independent draws is describing its own rules, and the fourth learns nothing the third did not |
| **Only what the tool drew** | gated on the `origin` beside `pending` (§3). A `supplied` password was dictated by an external system, and an absent `origin` is the same case without the evidence |
| **Only a refused password** | an unmapped code never redraws. It might be transient and it might be a value the server will refuse forever; of the two ways to be wrong, looping is the one that locks accounts |
| **Never quietly** | each redraw is reported as its own change, naming the version whose `pending` it replaced — §4's warning, reused |

**The scope of a redraw is one account, not the document and not the estate.**
Passwords are drawn per account even where accounts share a document (§4), so a
refusal implicates exactly the account that met it — and the re-apply covers that
account's own targets, including ones already visited in this pass, so that every
target bound to it ends the run holding the same password.

`apply` does not become a generator by doing this. §4 step 3 is already a bounded
rejection-sampling loop against the policy predicate; this adds one more rejector,
and it is the only one that cannot be consulted offline.

**What a run says it did.** Every draw is a `SOPULI-W029` warning naming the
account, the version it staged, and the server's own message; every refusal to
draw is a `SOPULI-W030` warning naming the account and which of the
rules above stopped it. On the row itself, `results[].redraws` counts the extra
passwords that account was given — present only when there was one, and read as
"this row was applied more than once and reports the last attempt" rather than as
a failure. A redrawn account that ends `IN_SYNC` succeeded. Run schema 1.18.

**Two more refusals fall out of the rules rather than being added to them.** An
account whose policy the file does not declare cannot be drawn for, so it reports
instead of failing the run — the estate was being applied happily, and a
configuration error there would be a complaint about a file nothing had changed.
And a run applying from `current` rather than `pending` never redraws, because
`origin` describes a staged value and `current` is what applications are already
holding: replacing that mid-apply is a different and much worse operation, and
§3's rule that an absent `origin` blocks a redraw already says so without a case
of its own.

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

**As shipped (#248, #437):** the selectors, `--include-previous`,
`--lockout-margin`, `--method` and `--output`. `--method` defaults to `login`
unconditionally (Q1, #86). `hash` and `both` arrived with #437, once #90 had
reproduced the verifier, and an explicit one the estate cannot honour is refused
at plan time (below). `--application`, `--account`, `--target`, `--group` and
`--select` are the selectors this command shares with every other verb.

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
   checks: `--method hash`, built in #437 on #90's derivation.
5. Document the interaction with `PASSWORD_LOCK_TIME` and with profiles that set
   `FAILED_LOGIN_ATTEMPTS UNLIMITED`. (A documentation item, not a runtime
   check — excluded from the "1/3/6" runtime set above and below.)
6. **Report `ACCOUNT_STATUS` unconditionally**, from `DBA_USERS` (already in
   the baseline grant set, no extra privilege needed). A login attempt alone
   conflates an expired password, an already-locked account and a genuinely
   wrong password behind the same `ORA-01017` — `check` reads status
   separately and surfaces `LOCKED` / `LOCKED (TIMED)` / `EXPIRED` as their own
   states rather than folding them into `DRIFT`.

### `--method hash` — verification without a login attempt

**Built (#437); not part of the default path.** `check` defaults to `login`
unconditionally (Q1 — decided in #86); hash mode is an opt-in extra, not a
fallback the default depends on.

**`--method both` compares first** (decided in #437, 2026-10-02). A mismatch is
reported as drift from the comparison alone and no login is attempted, because
spending lockout budget on a value already shown to be wrong buys nothing. Only
a value that matches goes on to the ordinary guarded login, and the row says
which half answered.

**On Autonomous Database the refusal says so in its own words** (decided in
#437). No account there can read `SYS.USER$`, `ADMIN` included (#478), so the
no-grant message's advice to grant it would be advice nobody can follow. The
capability probe cannot tell the two apart, since both answer `ORA-00942`, so
the refusal reads `SYS_CONTEXT('USERENV','CLOUD_SERVICE')`: `OLTP` on ADB
serverless 23.26.3.3.0, NULL on 26ai Free, 21c and 18c, and `ORA-02003` on 11.2.

Oracle stores a salted PBKDF2-SHA512 verifier (the `12C` verifier in
`SYS.USER$.SPARE4`). Given read access to that column, the tool derives the
verifier from the vault password and compares — **no authentication attempt, no
failed-login counter, no lockout risk** — and it works on locked and expired
accounts too. Those are still reported as `LOCKED` or `EXPIRED`, because the
status is the more urgent fact, with what the comparison found beside it, so an
operator can tell whether unlocking would be enough. The `T:` verifier can be reproduced client-side — measured
in #432 on 26ai, 21c and 18c (`02-oracle-privileges.md` §2), which is what makes
this method possible at all; a rollover window's two verifiers (`T:` previous,
`t:` current) are told apart the same way, so this reports `ROLLOVER_ACTIVE`
rather than drift. An account with no `12C` verifier (11g, or any account whose
`PASSWORD_VERSIONS` lacks it) has nothing to compare, so an explicit
`--method hash` or `--method both` fails at plan time naming the capability and
the target (invariant 4) rather than falling back to a weaker verifier or
silently to `login` (#433). The pre-flight asks about every value the run will
compare, including the previous one under `--include-previous`, because the
character-set refusal is about the value. Confirmed on 19.3.0.0.0 (#548), 12.2.0.1.0 (#572)
and 19.32.0.0.0 (#581), a release update and so the release an OCI estate runs,
which settles it for 19c (register entry `t-verifier`). 12.1 is unread; if the
derivation went wrong there, the method would be dropped from the CLI.

Trade-offs, stated because it shipped:

- requires the same optional `SELECT ON SYS.USER$` grant as the `LCOUNT` guard
  (`02-oracle-privileges.md` §2), which some sites will not grant. Where no
  `--method` is given the default is `login` and nothing is lost; an *explicit*
  `--method hash` or `--method both` against a target lacking the grant (or the
  `12C` verifier) fails at plan time rather than silently becoming `login` — the
  same shape as an explicit `--strategy` in #262. #124 is investigating whether a
  narrower grant can expose just enough to avoid this trade-off
  (unverified: lcount-grant)
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

**A rotation narrower than its promotion is refused before anything is
staged** (#406). §5's promotion gate, asked of `rotate` up front: a selector that
leaves out another target of a credential being rotated, or a sibling in the same
document with a `pending` of its own, exits 8 naming the pairs. `apply` narrowed
the same way changes what it was pointed at and withholds the promotion, because
that is how a rollout is staged; a rotation has no such reading — it would draw a
password, put it on part of the estate and stop at case 7 by construction, on
every run. To rotate part of an estate at a time, `creds generate` then
`creds apply` per target, and a final `apply` to promote.

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
guarantee it has not checked.

**On a path with no metadata at all — the ordinary state before the first lock —
pre-flight sets it** (#390). It used to read the absence as "new path, nothing to
check" and go ahead, which created the path with `cas_required` unset and left
every later run refused by the assertion above until somebody set it by hand.
Reading a guarantee the tool could have arranged was the bug, and arranging it is
safe to do first: configuring a path does not create a version, so the `cas: 0`
write a first acquisition makes still succeeds (measured on Vault 2.0.4).

What the fix does *not* close is a gap between runs of this tool. A first
acquisition has always written with `cas: 0`, which succeeds only against a path
with no history, so two runs racing for a new lock have always had exactly one
winner. What was missing is the **store** enforcing on everybody else what the
tool already did voluntarily.

Where the store will not have it — Vault grants metadata writes as a capability
separate from data writes, so an ordinary policy refuses this one call — the run
goes ahead and reports `SOPULI-W019`. Stopping would break an install over a
guarantee it never had; the honest answer is that the path is unguarded, said out
loud, with the remedy named. The next run then meets the exit-5 refusal below,
which is correct: by then somebody has been told.

**Both pre-flight refusals are exit 5, not exit 7** (#346). Neither is a held
lock — one is a store with no compare-and-set that nobody marked
`locking: advisory-only`, the other is a path that does not require one — and
both are decided before any lock record is read or written. Exit 7 said "another
process holds the lock", which is a condition that clears; these do not, so an
unattended runner retried one for ever. `sopuli lock break` has always answered
5 for the identical fact, through `check_fenceable`. The second refusal is 5
rather than 9 because it is not *this tool's* configuration that is invalid —
the file is fine, and the remedy is a vault command.

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
| 7 | database has new, vault `current` still old | **highest-severity case**: `pending` still holds the right value, so `sopuli creds apply` completes it — it re-verifies every target and promotes; `rotate` does not retry the promote: a compare-and-set conflict means a writer outside the tool, and re-reading to merge over it would rewrite fields of accounts nobody selected |
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
the event stream is `--output jsonl`, which `creds check` was the first verb to
emit (#9); `creds apply` and then `rotate` followed (#535). `password.applied`
and `vault.promote` are where a stream that stops tells you the most, and
`rotate` puts its staging events — per secret, not per target — ahead of the
first target, in this section's own order (`03-json-output.md` §5).

**Confirmation, and what it is not.** §8 step 1 is "plan + confirm", so `rotate`
prints the plan to stderr and asks; `--confirm` answers in advance and an
unattended run without it is refused on exit 8 rather than left to an EOF abort.
`apply` does not ask, and the difference is real: it converges an estate on a
value somebody already staged and reviewed, while `rotate` invents the value and
replaces what every application is using, across the whole selection, in one
pass. The estate-wide `safety.confirm_environments` setting is a *different*
gate, and `rotate` does not ask it as well: this prompt is unconditional, so the
setting could only make it weaker.

**Rollback.** `previous` is retained so that
`sopuli creds apply --source previous --confirm` can put the old password back on
the database. This is a real operation, not a theoretical one — it is the escape
hatch when an application turns out to have hard-coded the old password
somewhere. Rollback is bounded: only one generation back, and only while the
vault still holds `previous`. That bound is the decision, not the example (Q3,
settled in #84): OCI holds exactly one `PREVIOUS`, and `01-configuration.md` §7's
stage vocabulary — `current` / `pending` / `previous` — has nothing to address an
older generation with. Recovery further back is a matter of reading the store's
own version history, which not every backend has. Nor does every profile allow
it: one that restricts password reuse is likely to refuse `previous` with
`ORA-28007`, and there the escape hatch is a rollover window opened by the rotation itself (§5,
#568).

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
which clock is asked, and only the vault's is acted on.

### Where `DB_PW_CHANGED` comes from without `PASSWORD_CHANGE_DATE` (#386, decided)

`DBA_USERS.PASSWORD_CHANGE_DATE` does not exist on every supported release.
Measured 2026-09-08, it is present on 26ai and 21c and `ORA-00904` on **18c and
11.2** — so 18c, a supported tier-2 target, had been silently in the same bucket
as 11.2. Below it the column reads `-` and `password_age_days` is omitted from
the run document.

Three options were on the table: leave it absent and say so, fall back to
`SYS.USER$.PTIME`, or make it an eighth capability in P1's list. **Decided: the
first two together.**

- **Fall back to `SYS.USER$.PTIME` where the optional grant exists.** Measured on
  all four releases: `PTIME` moves on `ALTER USER ... IDENTIFIED BY`, equals the
  column to the second where both exist, and `CTIME` beside it does not move — so
  it is the same clock rather than an approximation. It costs no new privilege:
  it is the grant `02-oracle-privileges.md` §2 already offers for the `LCOUNT`
  guard, gated on the same `offline_verify` probe. **One source per release**:
  the column answering is what selects it, so `PTIME` is never read where the
  column exists, not even to fill a `NULL`. That rule is what keeps a second
  source from becoming the second opinion #383 warns about, and a tier-1 test pins
  the equality on every release that has both.
- **Say why when neither answers.** `SOPULI-W021`, on each affected
  `results[].warnings[]` beside the missing field, carrying the driver's reason:
  no such column and no grant (which the grant fixes), or a value that could not
  be read (which is worth investigating). `creds status` prints the same reason
  once per target under the table.
- **Not a capability.** The query is its own probe — `ORA-00904` *is* the answer
  — and adding to P1's binding list would have changed the driver protocol,
  `doctor`, the schema and the skip vocabulary to report a display column.

12.2.0.1.0 takes the fallback, and `PTIME` tracked a rotation there (#572); 12.1
would take it too and is unmeasured (unverified: pw-changed-source) — see
`docs/README.md`'s "Verify before implementing".

---

## 10. Scenarios

**S1 — First adoption of an existing account.** The account exists, its password
is known to humans and not in the vault.
`generate --promote` → `apply` → `check`. The tool never needs the old password.

**S2 — Scheduled 90-day rotation, zero downtime.** Nightly `check` (hash mode,
exit 3 alerts). Weekly `rotate --max-age-days 90 --strategy rollover`. The app
refreshes credentials within the rollover window; a follow-up job runs
`finish-rollover` once the window has elapsed.

**S3 — One PDB was down during the last rotation.** The other targets took the
new password, and the promotion was withheld (invariant 7): `current` still holds
the old password and `pending` the new one. Once the PDB is back, run `apply`
without a target selector. It applies `pending` where a target does not hold it,
confirms every target, and only then promotes. Idempotent for the ones already
correct. `apply --target cdb1-pdb-billing` alone changes that PDB but still
withholds the promotion (`SOPULI-W027`), because a narrowed run cannot confirm
the targets it left out.

**S4 — Emergency rotation after a leak.** `rotate --strategy direct
--finish-rollover` — no grace window, old password invalid immediately, accepting
application errors as the price. The audit record captures who and when.

**S5 — Common user across a CDB.** One application entry, one secret, target
`cdb1-root`, `container_clause: ALL`. One statement covers every PDB.

**S6 — Vault write succeeds, database is unreachable.** `pending` exists, nothing
applied, `current` unchanged, applications unaffected. While the database is
unreachable, `check` reports `ERROR` and exits 1. Once it is back, `check` finds
no drift, because the database still holds `current`, and `creds status` shows
the staged `pending`. Finish with `apply`, which applies the staged `pending`,
confirms it, and promotes. Re-running `rotate` does not resume: it draws a fresh
password and stages it over the old `pending`.

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
- **Redaction test:** run everything, grep all output,
  logs and trace for the generated password. Zero hits is a release gate.

---

## 12. Open questions

| # | Question | Notes / leaning |
|---|---|---|
| ~~Q1~~ | ~~Should `check` default to `hash` or `login`?~~ | **decided: `login`, unconditionally** (#86); `--method hash` is opt-in. Reasons: [Q1](../decisions/log.md#q1) |
| ~~Q2~~ | ~~Where does the advisory lock live?~~ | **decided: in the vault** (#83), one CAS-guarded lock record per secret path under a `locks/` prefix, with a fencing token; stores without `cas` refuse unless `locking: advisory-only`. Reasons: [Q2](../decisions/log.md#q2) |
| Q3 | ~~How many generations of `previous` to keep?~~ | **decided: exactly one**, plus the store's own version history (#84). Reasons: [Q3](../decisions/log.md#q3) |
| ~~Q4~~ | ~~Does the tool ever alter a *profile* to enable rollover?~~ | **decided: never** (#88). The tool prints the `ALTER PROFILE` an operator would run, and may assign a profile but never creates or alters one. Reasons: [Q4](../decisions/log.md#q4) |
| Q5 | ~~Notification on drift~~ | **decided** (#615): out of scope for the tool; exit code 3 + JSON output is the integration point. Reasons: [Q5](../decisions/log.md#q5) |
| Q6 | Self-rotation mode (tool connects as the account itself, `REPLACE old`) | useful where no admin credential exists; defer to UC-1b (see the roadmap in `docs/README.md`) |
| ~~Q7~~ | ~~One secret per account vs one secret with many fields for an app~~ | **decided: one secret per application, a field per account** (#85); one secret per account stays supported (§3). Reasons: [Q7](../decisions/log.md#q7) |
| Q8 | ~~Should `apply` be able to create a missing account?~~ | **decided** (#615): no in UC-1; belongs to UC-4, provisioning. Reasons: [Q8](../decisions/log.md#q8) |
| ~~Q9~~ | ~~Time source for `max_age_days`~~ | **decided: vault `rotated_at`, unconditionally** (#87); `status` shows the database's time beside it (§9). Reasons: [Q9](../decisions/log.md#q9) |

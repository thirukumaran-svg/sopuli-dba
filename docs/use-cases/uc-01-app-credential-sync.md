# UC-1 — Application database account credentials: vault as master, sync to database

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

**Non-goals for UC-1.** Creating or dropping accounts, grants and roles; personal
accounts, which are UC-2 (`uc-02-personal-account-passwords.md`); and restarting
or reloading the application.

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

**There is no `creds promote` verb** (decided in #276). The case it would cover
is a rotation interrupted after the databases changed and before the vault was
promoted. Running `apply` again completes that case. It reads the `pending`, the
login before the change finds that the database already accepts it, every
account reports `IN_SYNC`, and the document is promoted. So the recovery path
and invariant 9's `changed: false` are the same code path.

A separate `promote` that wrote the promotion without verifying again was
rejected. Run later, it would advertise a password to applications because of an
earlier run's document. Verifying again is what makes `apply` safe to use for
§8's most severe failure.

`generate` and `apply` are separate on purpose. An operator can stage a new
password, get a change window approved, and apply it later. Each half can also be
retried on its own.

### Common selectors

Every command takes the same target/account selection options:

```
--application NAME      an entry from the `applications:` config section; alias --app
                        (omit it in a single-application config)
--account NAME          filters accounts within the selection
--target NAME
--group NAME            a named or selector-based group
--select k=v[,k=v]      filter by target labels, e.g. --select env=dev,tenant=beta
--dry-run / --output {text,json,jsonl}
```

Each selector can be repeated.

`--output jsonl` is accepted only by the verbs that stream events
(`03-json-output.md` §5). Each verb lists its other options in its own section.

There is no `--all` and no `--limit`. With no selector, a command already covers
everything the config declares. The ceiling on how many targets a run may touch
is `safety.max_targets`, which the command line cannot set (`00-principles.md`
P5).

**Selectors filter what the config declares. They are not a second way to name
things.** The tool never acts on an account that is not in the config. A
selector narrows the declared set and cannot extend it. With no selector, a
command covers everything declared, so `sopuli creds check` alone is a useful
scheduled job.

The selection is resolved and printed before anything is touched. Every command
starts by showing a plan.

---

## 3. State model

For each (account, scope) pair the tool reasons about a small state:

```
VaultState  = { current, pending?, previous?, version, updated_at, updated_by }
DbState     = { exists, lock_status, profile, password_versions,
                password_change_date, rollover_active?, scope }
SyncState   = the result's `state`; 03-json-output.md §3 lists the values
```

`SyncState` is what `check` reports and what `apply` acts on. The three stage
fields in the vault payload, `password`, `pending` and `previous`, are the whole
rotation mechanism:

```json
{
  "password": "<current>",
  "pending":  "<generated, not yet applied>",
  "previous": "<the one before current>",
  "origin":   "generated",
  "rotated_at": "2026-08-04T09:12:33Z",
  "rotated_by": "approle:sopuli-ci",
  "policy": "app-standard",
  "targets": ["appdb-alpha", "appdb-beta"]
}
```

On a store with native staging (OCI, AWSSM), these map to version stages instead
of extra fields. The tool hides that difference, but reports which mechanism it
used. There is one exception, below.

### The layout, and the rule that covers both (Q7, decided in #85)

The documented default is **one secret per application, with a field per
account**: `tenants/{tenant}#DB_CREDENTIALS/{account}`, the layout
`../design/01-configuration.md` §2 uses. One secret per account is also fully
supported. A `secret` or `secret_template` that names a single field uses the
same code path.

The two layouts differ only in how many accounts live in one document. The
payload follows from one rule:

> **Every root-level key mirrors the shape of the current-stage container.**

The container is what the configured ref addresses: the field, and any pointer
below it. Where the container is a scalar, `pending`, `previous` and the rotation
stamps are scalars beside it, as in the payload above. Where it is a map keyed by
account, they are maps keyed the same way:

```json
{ "DB_CREDENTIALS": { "acme_web_user": "<current>", "acme_api_user": "<current>" },
  "pending":        { "acme_web_user": "<generated, not yet applied>" },
  "previous":       { "acme_web_user": "<the one before current>" },
  "origin":         { "acme_web_user": "generated" },
  "rotated_at":     { "acme_web_user": "2026-08-04T09:12:33Z", "acme_api_user": "…" },
  "rotated_by":     { "acme_web_user": "approle:sopuli-ci", "acme_api_user": "…" },
  "policy":         { "acme_web_user": "app-standard", "acme_api_user": "app-standard" },
  "targets":        { "acme_web_user": ["appdb-alpha"], "acme_api_user": ["…"] } }
```

The rule has these consequences:

- **No new pointer syntax, and no nested triple.** `#DB_CREDENTIALS/…` and
  `#pending/…` take the same pointer below the same key. So C14's
  `@stage=pending` means "the `pending` sibling, same key" in both layouts.
- **The ref an application reads does not change.** It still resolves to a
  password string. That rules out the other candidate shape: an object per
  account that holds its own triple. With that shape, every consumer would have
  to read a document and look inside it, to save the tool a rule it needs anyway.
- **The stamps sit beside the value they describe.** They are per account,
  because one account can be rotated inside a shared document. A root-level
  `rotated_at` would then describe some of the document and not the rest.
  The document has no `username` key. In the shared layout the map key is the
  username, and a second copy could disagree with it.

**Native staging is the exception.** An OCI or AWSSM version stage belongs to
the whole secret. It cannot promote one account's `pending` without promoting
every account's. So a document that holds more than one account's credential
keeps the three stages in payload fields, even on a store that has native
stages. The run reports that mechanism. Where each account has its own secret,
the tool uses native staging.

**Two accounts in one document share a lock, on purpose.** Q2 keys the lock on
the path. A second run on the same document loses on the lock and exits 7,
naming the holder, instead of racing to a lost update. In the common workflow,
where an application's accounts are rotated together, that is one lock, one
document and one write for the whole application.

**Why `pending` exists.** Ordering is the central risk in this use case:

- Write vault first, then apply → if apply fails, the vault advertises a password
  the database does not have. Applications break at next credential fetch.
- Apply first, then write vault → if the vault write fails, nobody can obtain the
  new password. Applications break at next credential fetch, and the correct
  password now exists nowhere.

The `pending` field removes that window. The candidate is stored durably before
the database is touched. `current`, the field applications read, is promoted
only after the database confirms. A crash at any point leaves a state that the
tool can resume and that `check` can explain.

### `origin`: where a staged password came from

`generate` writes one more key beside `pending`, saying which of two things the
staged value is:

| `origin` | means |
|---|---|
| `generated` | the tool drew it from the policy |
| `supplied` | `--from-stdin` accepted it, and an external system dictated it |

**It lets `apply` tell the two apart.** When the server refuses a password with
`ORA-28003` or `ORA-28007`, `apply` draws a new one (§6.4). A new draw is right
for a password the tool drew. It is wrong for a password that an external system
owns: replacing it silently makes the tool disagree with whoever dictated it.

These rules apply to `origin`:

- **It describes `pending`, not the credential.** It is written when a value is
  staged, and removed when `pending` is removed. It is not one of the rotation
  stamps, which describe `current` and are refreshed at promotion. A key that
  described `pending` in some documents and `current` in others could be wrong,
  and the code that reads it decides whether to replace somebody's password.
- **Absent means unknown, and unknown means "do not redraw".** A document with a
  `pending` and no `origin` may hold a dictated password, and guessing wrong
  would overwrite it. The next `generate` writes the key.
- **A value written straight into `current` has no `origin`.** Nothing is staged
  for it to describe, and a redraw must never touch what applications already
  hold. The rule above covers this case, so it needs no special handling.

`origin` follows the mirror rule like every other root-level key: a scalar beside
a scalar container, a map keyed by account beside a map. It is one of the
reserved root names, so a `secret:` ref may not name a field called `origin`.

It is called `origin` and not `source` because `apply --source` already names a
stage. One word with two meanings, one flag apart, would eventually be misread.

---

## 4. `sopuli creds generate`

Generate a password from the policy and write it to the vault's `pending` slot.
It does not change the database. It may connect to read constraints.

```
sopuli creds generate --application acme [--account acme_web_user]
                      [--promote]            # write straight to `current` (no staging)
                      [--overwrite-current]  # authorise replacing an existing `current`
                      [--from-stdin]         # take a supplied password instead of generating
                      [--no-policy-check]    # accept a supplied password that violates the policy
                      [--policy NAME]        # override the policy
                      [--offline]            # do not read constraints from any target
                      [--confirm]            # proceed without asking
```

**Flow**

1. Resolve the selection and the policy. Resolve SecretRefs from templates.
2. Where a target is reachable, connect to read its *constraints*: **one
   connection per selected target, not per account**. The strictest answer
   governs the draw. The constraints that cannot govern anything are read on the
   same connection and reported. If no target is reachable, fall back to the
   policy's declared limits and say so in the output. `--offline` skips this
   step.
3. Generate from a CSPRNG. Reject and regenerate candidates that break the
   charset, first-character, length-in-bytes or composition rules. The retries
   are bounded.
4. Acquire the lock for the secret path (Q2, #83). `generate` can do this because
   the lock lives in the vault. This step never connects to a database, so a
   lock in the database could not protect the write below.
5. Write to the vault: `pending = candidate` and `origin` beside it (§3). Leave
   `current` untouched. One write carries both keys. A write that stored the
   password without its `origin` would stage a password that no later `apply`
   may redraw. Use CAS where the store supports it, so that a concurrent writer
   cannot be overwritten silently. Under `--promote`, the one write instead
   carries `current = candidate`, the old `current` moved into `previous` where
   there was one, and the §3 stamps. It writes no `origin`, because that key
   describes `pending` and a promote writes no `pending`.
6. Report the new version, and that the database has not changed.

**Notes**

**What step 2 uses to limit the draw, and what it only reports.** One reading
limits the draw: the byte limit, counted in the target's character set. It is
the *deterministic* constraint. A password too long in bytes, or with characters
the target does not accept, fails the same way for every account in the
selection, and one policy fix ends it. So this refusal can move from `apply` to
here. The refusal names the target whose limit governed; where several share the
strictest limit, it names the first. When a supplied password is refused, each
violation names the target it came from, because in an estate "the target" does
not say which one (invariant 4).

The other readings in step 2 cannot limit anything. The run reads them so
that it can **say** they are there:

- A **verify function** is arbitrary PL/SQL, and the tool cannot call it
  (invariants 13 and 14). The run reports whether there is one, including when
  it cannot tell. From inside a PDB, a **common** profile's
  `PASSWORD_VERIFY_FUNCTION` reads as the literal `FROM ROOT`. Reporting that as
  *none* would tell an operator that nothing will judge the password when
  something will. This is §5's `--preflight` rule, *not knowing is not a
  finding*, applied to a reading.
- **`PASSWORD_REUSE_*`** history is hashed, so the run reports the two resource
  values and never interprets them. The warning fires only under `--from-stdin`.
  A fresh random password cannot collide with the history, but a supplied
  password is whatever an external system dictated. A rollback is the other case
  where the value is not fresh, and §5 reports it under its own code.
- **`PASSWORD_VERSIONS`** says which verifiers the account holds, and the run
  reports it as a fact. Which verifiers a later rotation regenerates is the
  server's configuration, not this tool's.

So `ORA-28003` and `ORA-28007` cannot be predicted before the statement runs,
and `apply` handles them by drawing again (§6.4). None of these readings predicts
that a password will be refused. They say that something other than the policy
will judge it. The readings go in the document's `constraints` section
(`03-json-output.md`), and the caveats in `diagnostics[]` as `SOPULI-W016` and
`SOPULI-W017`. Both are printed under the constraints line in the default text
output, because a warning that a terminal user cannot see is not surfaced.

On 26ai Free 23.26.2.0.0, `FROM ROOT` covers less than the first bullet
suggests. A local profile read from inside a PDB answers with its function's
name, and `DEFAULT`, which is common, answers `NULL`. So the unreadable case is
a user-created common profile seen from a PDB. A profile with no verify function
reports the **string** `NULL`, and `PASSWORD_REUSE_MAX` and
`PASSWORD_REUSE_TIME` report `UNLIMITED`. Both are vendor words in columns where
a reader expects other values.

**There is no single strictest limit, and the run does not invent one.** A limit
is a byte count *and* the character set it is counted in, so "stricter" is only a
partial order. 128 bytes of `WE8MSWIN1252` hold more characters than 128 bytes
of `AL32UTF8`, but *fewer distinct* characters, so neither contains the other.
The run keeps every reading and asks two separate questions:

- A **generated** password is drawn against the smallest byte count and nothing
  else. The alphabets in `01-configuration.md` §8 are ASCII, and an ASCII
  character is one byte in every character set the driver maps. So the count is
  the only limit that applies.
- A **supplied** password (`--from-stdin`) is checked against *every* target
  that answered. A character that one target's set can store and another's
  cannot is a violation on that target, whichever target had the smallest
  count. One violation is reported once, however many targets report it.

**Reading is not writing, and the lock's reason is unchanged.** `creds generate`
takes the vault's advisory lock because it makes no *change* that a lock in the
database could protect (Q2, #83). That never meant it opens no session, and a
read does not change the argument.

- Generation and validation are in `sopuli/passwords.py`. Step 3's "reject and
  regenerate" uses the *same* check as `--from-stdin`. A policy that declares no
  `length` is refused, not given a default. A policy that no password could
  satisfy is refused before any drawing, naming what is wrong
  (`01-configuration.md` §8).
- `--from-stdin` is for migration, and for cases where an external system
  dictates the password. It checks the password against the policy and refuses
  on a violation, unless `--no-policy-check` is passed. The audit event records
  that flag. It reads `length:` as a minimum, not an exact figure, because a
  dictated password is not weaker for being longer.
- Generating twice without applying replaces `pending`. That is safe, and the run
  says so. It warns, naming the version whose `pending` it replaced, because
  anything that already holds that password is now stale. A fresh draw has no
  target state to converge on, so this verb is outside invariant 9 (decided in
  #254; reasons: [H7](../decisions/log.md#h7)). `apply` is the convergent half,
  and it reports `changed: false` when run again.

### `--promote`, and its exception to invariant 7 (decided in #257)

The command below writes the drawn password straight to `current`:

```
sopuli creds generate --application acme --promote [--overwrite-current]
```

It writes no `pending` and touches no database. It is for **S1, first adoption
of an existing account**. The account exists, people know its password, and the
vault does not have it. `generate --promote`, then `apply`, then `check` adopt it,
and the tool never needs the old password. Staging first would mean a `pending`
nothing has read and a `current` that does not exist, then a promotion of one
into the other: two writes and an intermediate state, for a document with no
rotation in progress.

**`--overwrite-current` is invariant 7's exception.** The invariant says never
promote before every target has confirmed, and `--promote` confirms nothing. The
flag may write over an existing `current`. Refusing that outright would leave
`--promote` unable to mean *I know what I am doing*, which is what an operator
who passes it is saying. It is safe to allow because the operator has to ask for
it by name:

- **The account has no `current`.** Nothing reads the field being written, so
  there is no window to protect. The run writes it without a question or a flag.
- **A `current` exists.** The field every application reads is about to be
  replaced by a password that no database has. The run refuses on **exit 8**
  unless `--overwrite-current` was passed, and names the accounts. Exit 8 means
  "aborted, or confirmation declined", and a required authorisation that nobody
  gave is that. The file is not wrong and the run is not broken.

**There is no prompt, attended or not.** `--overwrite-current` is an
authorisation you type, not a question you answer, like `--force` and unlike
`--confirm`. An operator who did not know that some accounts had a `current`
reads the refusal, runs `--dry-run`, and then decides. That is better than a y/n
prompt on a write to the field every application reads, and a scheduled run
behaves exactly like a run by hand.

**The value `current` held moves into `previous`**, in the same write that
replaces it. It is the prior password, never the one being written. Otherwise
§5's rollback (`--source previous`) has nothing to roll back to. An account
being seeded has no prior value and gets no `previous`. One CAS write per
document carries all of this, plus the §3 stamps, like every other write this
command makes.

**It has its own flag instead of `--confirm`, so that the choice can be undone.**
`--confirm` already means *proceed without asking* on this verb, and P5 gives
every mutating command one. That meaning has no scope: every question this
command learns to ask in future folds into it. An operator who passes `--confirm`
because `safety.confirm_environments` covers prod would also authorise an
overwrite they had not thought about. The deciding argument is the cost of
changing course later. Shipping `--confirm` alone and adding a dedicated flag
later **breaks** every script that relied on `--confirm`: a scheduled adoption
run starts exiting 8. Shipping the dedicated flag and later letting `--confirm`
satisfy it breaks nothing. Reasons and rejected options:
[#257](../decisions/log.md#257).

**`--confirm` keeps its single meaning** and does not satisfy this gate. The two
flags authorise different things: touching a listed *environment*, and replacing
a *value*. A run that needs both passes both.

**`--promote --dry-run` names the two groups separately.** Accounts whose
`current` would be **seeded** and accounts whose `current` would be **replaced**
are different risks, and an operator should not have to count them. A preview is
never gated, so it is also how an operator finds out they need the flag.

**The refusal happens at plan time** (invariant 4), from the documents read
before anything is written. The run checks again under the lock, because a
`current` that appears between the two reads would otherwise be overwritten by a
run that was told there was none. Where the flag *was* passed, the second read
has nothing to refuse.

**It reports `VAULT_ONLY`**: the vault holds this password and no database has
been asked. It is its own `state` value, because the other candidates each say
something untrue (`03-json-output.md` §3). `PENDING_APPLY` in particular would
send `check` and `apply` looking for a `pending` that does not exist.

**It clears any `pending`, and the `origin` that describes it.** `creds apply
--source` defaults to `pending` where there is one. A staged password left beside
a newly promoted one is a password the next `apply` would prefer, which would
undo this run without anyone asking. `--promote` reuses the promotion patch that
`creds apply` uses, which already clears it.

On tier 1 against Oracle Free 23.26.2.0.0 and a dev-mode Vault,
`generate --promote` seeds `current` at v1. `apply` then reads it with
`SOURCE: current` and reports `IN_SYNC` "changed and verified by login", and
`check` reports `IN_SYNC` "vault v1 verified by login". A second promote over that
document refuses on exit 8, naming both accounts. With `--overwrite-current` it
writes v2, and `previous` holds what v1's `current` held.

**This is not a `creds promote` verb**, and the reasons in §2 still hold. That
decision is about promoting a *rotation*: advertising a password because of an
earlier run's document, without verifying again. `--promote` writes a password
drawn in the same run, for an account with no rotation in progress.

---

## 5. `sopuli creds apply`

Take what the vault holds and make the database match it.

```
sopuli creds apply --application acme
                   [--source {pending,current,previous}]  # default: pending if set, else current
                   [--confirm]                            # required for --source previous
                   [--strategy {rollover,staged,direct}]
                   [--preflight]                          # survey every target before writing anything
                   [--repair FILE]                        # act only on a run's unconfirmed set
                   [--lockout-margin N]                   # default 2; see §7
                   [--force]                              # waive account guardrails 2 to 5
```

**Flow, per target**

1. Connect with the target's admin credential (P2's bootstrap order).
2. Verify the scope: the connection is in the container the config claims, the
   database is open read-write, and the version and capabilities are as
   expected.
3. Verify that the account exists, and read its state: locked, profile,
   verifiers. A missing account is `ACCOUNT_MISSING`. The tool does not create it
   (Q8).
4. Change the password (§6 has the Oracle statement). Where the server refuses
   the *value*, because of a verify function or a reuse rule, and the tool drew
   the staged password (`origin: generated`, §3), draw another, write it to the
   vault's `pending`, and apply it again, a bounded number of times. A password
   with any other `origin` is never redrawn. §6.4 has the rules.
5. Verify at once, with a fresh connection as that user (§7).
6. Record a result for the target.

**After all targets**

- All succeeded: promote in the vault. `previous = current`,
  `current = pending`, clear `pending`, stamp `rotated_at` and `rotated_by`.
  Exit 0.
- The run was narrower than the promotion: do **not** promote, and exit 4. See
  *The promotion gate* below.
- Some failed: do **not** promote. `pending` stays. Report the status per target
  and exit 4 (partial). The remedy is to run `apply` again, narrowed by
  `--repair FILE` where the run's document was captured. It is safe to run again
  either way.
- None confirmed: do not promote. Exit 1. Usually nothing changed. But where the
  server accepted the statement and the verification then failed, that database
  did change, and its row says the password was changed.

These rules decide what `apply` does with each account:

- **The database is asked before it is changed.** Invariant 9 makes `apply` a
  convergent verb, so it must know whether a change is needed. `apply` verifies
  by login; it does not use `check --method hash`. So the tool verifies each
  account first, under §7's mitigations, and leaves a password that already
  works alone. The two logins are budgeted as one run's attempts. A `pass` under
  an open rollover window is also a reason not to act, because applying again
  would restart the window and report a change nobody asked for.
- **A locked account is not changed at all,** unless the policy asks for an
  unlock (below). The statement would succeed and the verification could never
  pass. The run would end with a database whose password is in no vault stage,
  which is the state §3's ordering exists to prevent. An *expired* account is
  changed, as §6.4 says, because setting a password clears the expiry.
- **An empty vault is a failure, not a quiet no-op.** Where neither stage holds
  anything for a declared account, the run reports `ERROR`, naming
  `creds generate`, instead of exiting 0 having changed nothing. `check` calls
  the same situation `UNVERIFIABLE`, because for `check` it is only a gap in a
  survey. `apply` cannot do what it was run to do.

`--force` waives account guardrails 2 to 5 in `02-oracle-privileges.md` §4, and
never check 1. The run document records each waiver in `results[].overridden`.
`--lockout-margin` sets the lockout guard that §7 describes, for the logins
`apply` makes.

**The promotion gate (decided in #406).** A secret document is promoted only
when every (account, target) pair it needs has confirmed **in this run**. The
pairs it needs are counted over the **configuration**, not over what the run was
narrowed to:

- **every target on which the same credential is declared.** It is the same
  document and the same ref, so one promotion moves the password that every one
  of them should hold;
- **on a forward promotion, every pair of every sibling account in the document
  that has its own `pending`.** Its staged password may already be on its
  database, which is what an earlier partial run leaves. A promotion that skipped
  it would leave the database ahead of `current`. A sibling with nothing staged
  has no rotation in progress and is not needed. That is why `--account` can
  rotate one account in a shared document;
- **a rollback (`--source previous`) needs only the first.** It refuses where
  anything is staged, and a sibling's `previous` is not a rollback anyone asked
  for.

A run narrowed past any of these, by `--target`, `--select`, `--account` or
`--repair`, still changes the databases it was pointed at. That is how a rollout
is staged target by target. It then **withholds the promotion**: `pending`
stays, the run exits 4, and `SOPULI-W027` names the pairs it left out. The remedy
is a run wide enough to include them, so the `repair with:` line of that run
drops the selectors instead of repeating them. The wider run costs one login per
pair the narrow run already converged, and reports `changed: false` for each. An
account that a guardrail skipped is inside the run, not outside it
(`02-oracle-privileges.md` §4 says what a skip means).

The gate counts configured pairs, not visited pairs, because otherwise
`apply --target appdb-alpha` would promote an account whose other target still
holds the old password. That is the state invariant 7 exists to prevent, reached
by a selector instead of a failure, with exit 0. Reasons and rejected options:
[#406](../decisions/log.md#406).

**Multi-target atomicity.** There is no distributed transaction across
databases. The tool applies target by target, and the vault promotion is the
single commit point that makes the new password visible to applications. The
sequence for a group of PDBs that share one secret:

```
  pending written
     │
     ├─ apply → appdb-alpha  ok
     ├─ apply → appdb-beta   ok
     │
  promote current  ← only now do applications see the new password
```

If `appdb-beta` fails, `appdb-alpha` has already changed, but `current` still
holds the old password. That is why **the rollover strategy is the default on
databases that support it**. During the rollover window both passwords work, so
a partial apply causes no outage.

**Attributes.** `apply` can also enforce non-password attributes that the
policy declares, each opt-in: account unlock and profile assignment. Each is
reported as a separate change, so the diff stays readable. The list is closed:
a third attribute is a decision. `PASSWORD_EXPIRE` and tablespaces are not
attributes, for the reasons below.

### Account unlock

```yaml
policies:
  app-standard:
    account:
      unlock_if_locked: true      # default: false
```

`apply` refuses to change a locked account's password, for the reason given
above. Without this attribute, a locked application account cannot be rotated
at all, and the operator must unlock it by hand, outside the tool. With the
attribute declared, the run issues `ALTER USER … ACCOUNT UNLOCK` first and then
does the work.

These rules apply, and the first is the one the others protect:

- **Opt-in, declared, never inferred.** Where the policy says nothing, including
  an estate with no `policies:` at all, a locked account is reported `LOCKED`.
  The message names the key that would change that. A tool that unlocked an
  account because it found one locked would make a change nobody asked for during
  a credential rotation.
- **Before the first login, after the guardrails.** A locked account refuses
  every login. A verification login before the unlock would use up an attempt
  against the counter that §7's margin protects, and learn nothing. The account
  guardrails run first, because they decide whether this account may be touched
  at all, and an unlock touches it.
- **Idempotent** (invariant 9). The driver reads the lock state and issues
  nothing where there is no lock. The action is still reported, with
  `applied: false`. A consumer that read "not present" as "not declared" would be
  reading the policy out of the results.
- **No effect on the promotion.** The unlock is a change to the database, like
  the password. `pending` still waits for every target to confirm (invariant 7).

The unlock is its own `actions[]` entry:

```json
"actions": [
  { "kind": "account_unlock", "applied": true,  "detail": "account was locked(timed); unlocked" },
  { "kind": "verify",         "applied": true,  "detail": "checked whether the database already has this password" },
  { "kind": "password_set",   "applied": true,  "detail": "changed and verified by login" }
]
```

The same statement clears `LOCKED(TIMED)` and a deliberate lock.
`LOCKED(TIMED)` is what a profile's `FAILED_LOGIN_ATTEMPTS` produces, and it is
the state in which an account with a drifted password is usually found. The
capability is `account_lock_state`.

### Profile assignment

```yaml
policies:
  app-standard:
    account:
      profile: acme_app_prof
```

`apply` moves the account onto the named profile with `ALTER USER … PROFILE …`
where it is on a different one. The unlock's rules apply unchanged: opt-in, before
the first login, idempotent, and no effect on the promotion. These rules are its
own.

**The tool assigns a profile. It never creates or alters one** (Q4, decided in
#88). `ALTER PROFILE` edits a shared object, so it reaches accounts nobody
selected. `02-oracle-privileges.md` §3 keeps that privilege off the service
account. `creds finish-rollover` follows the same rule: it *reports* the
`ALTER PROFILE` an operator would run, and never issues it. Creating and
altering profiles belongs to UC-4, provisioning (see the roadmap in
`docs/README.md`). There a profile is part of making an account exist. Whether
UC-4 alters profiles is open there; Q4 does not decide it.

**A profile the target does not have is a pre-flight finding, not an
`ORA-02380` half way through.** Which profiles exist is a property of each
database. An estate can easily name a profile that exists on nineteen PDBs and
not on the twentieth. Finding that out on the twentieth would leave nineteen
accounts moved. `--preflight` checks every account it is about to touch, and the
run refuses before anything is written. Without the flag, the run refuses that
one account, before its own statement.

**Naming a `--strategy` together with a profile move is refused.** A profile
decides whether `ALTER USER … IDENTIFIED BY` opens a rollover window, so it
decides the regime a rotation runs under.

`--strategy staged` is refused against a profile that grants a window, because
Oracle opens one anyway. Reporting `staged` would tell an application team that
the old password had stopped working when it had not (§6.3). That check reads the
profile the account holds **now**. For an account this run is about to move, that
is the profile it is leaving. So the run refuses the pair:

```
--strategy staged cannot be honoured for 'acme_web_user' in 'appdb-prod-alpha':
this run would move it from ACME_LEGACY_PROF to acme_app_prof, and the regime a
rotation runs under is a property of the profile it ends on

hint: rotate under the profile it has, or let this run do the move and rotate
afterwards -- naming a regime and changing the profile that decides one are two
intentions for one run
```

**With no `--strategy` there is nothing to refuse**, and that is the usual case.
The default regime is resolved per account *after* the attribute pass, from the
profile the account ends on. So an estate that declares a profile and names no
regime rotates correctly under the new profile on the first run.

### Why `PASSWORD_EXPIRE` is not an attribute

Reasons and rejected options: [#302](../decisions/log.md#302).

**`apply` already clears an expiry, and that is not optional.** Setting a
password clears `EXPIRED`. That is Oracle's behaviour, not a choice this tool
makes. So §6.4 lists `ORA-28001` as *resolved by apply*, and `apply` does not
treat an expired account as a reason to stop. An attribute for it would be a
switch for something that is always true.

**Expiring a password on purpose breaks the accounts this use case is about.**
`ALTER USER … PASSWORD EXPIRE` after a rotation forces the next login to set a
new password. An application account cannot answer that prompt. The run would
write a password to the vault, put it on the database, and leave an account that
logs in once into a session that demands a replacement no connection pool will
supply. The run would also fail: an account that reads `EXPIRED` afterwards is
never promoted (§5's promotion gate), and the run exits 4.

**It is a real operation for personal accounts.** A DBA who resets a person's
password wants that person to change it at first logon. That is UC-2
(`uc-02-personal-account-passwords.md`). There `account expire-password` does
this, and so does the `PASSWORD EXPIRE` that the seen reset path always issues.
There the password is handed over to a person, not synced to an application.

Two neighbouring operations are often confused with it:

- **"Make the old password stop working now"** is `--strategy direct` and
  `creds finish-rollover` (§6.3). That is `ALTER USER … EXPIRE PASSWORD ROLLOVER
  PERIOD`, a different statement. An attribute called `PASSWORD_EXPIRE` would be
  a second way to ask for it.
- **The grace period** is something the tool reports, not an attribute: §6.4
  describes how `check` and `status` report it.

### Why tablespaces are not an attribute

Default and temporary tablespace belong to UC-4, provisioning. Reasons and
rejected options: [#303](../decisions/log.md#303).

**`ALTER USER … DEFAULT TABLESPACE` moves no existing segment.** The account's
objects stay where they are. Only the place where the *next* object is created
without a `TABLESPACE` clause changes. During a credential rotation, that change
looks done but is only half done, and nobody reading a rotation's output would
think to check. During provisioning, when the account has no objects yet, it is
part of creating the account correctly.

The same is true of quotas, grants and roles. None of them is a credential, and
none of them belongs to a verb whose job is to make a database hold what a vault
holds. Q8 puts account creation in UC-4 for the same reason.

### `--source`, and the rollback (decided in #265)

The command below chooses which vault stage to apply:

```
sopuli creds apply --source {pending,current,previous} [--confirm]
```

Without the flag, the default is `pending` if one is staged, else `current`.
Naming a stage reads **exactly** that stage and **never falls back**. An
operator who names a stage is trying to avoid the fallback. Silently applying
`current` when the operator asked for `previous` would be a rollback that did not
happen and said it did. So a stage that holds nothing is a reported failure that
names *that* stage. "No `previous` to roll back to" and "nothing staged at all"
send the operator to different places, and only one of them is
`creds generate`.

`current` forces the repair path where a `pending` is staged. The staged password
turns out to be wrong, and the estate goes back to what applications actually
read, without discarding the `pending`. It writes nothing to the vault, because
the vault already holds what went on the database.

**`previous` is the rollback.** Its *success* stops an application's credential
from working. So it needs `--confirm`. Where nothing can ask, it refuses with
exit 8 instead of prompting into a closed stdin. `--dry-run` needs no
confirmation: if a preview had to be authorised, operators would stop running
previews.

**A rollback swaps the vault stages.** Once every target confirms, `current`
takes the rolled-back value, and `previous` takes the value just removed from the
database. This is the same single compare-and-set write a forward promotion uses,
with the same arithmetic on the other neighbour. The estate ends consistent:
applications fetch `current`, and `current` is what the databases have.

**This does not break "vault is master".** Invariant 6 is about the direction
values travel. Both values came from the vault, and no database was read for
either. Only which stage is master changed, and an operator said so on the
command line.

**A rollback is refused while a `pending` is staged.** A rollback during a
rotation in progress leaves the `pending` in place. The next `apply` would then
move the estate forward with it and undo the rollback, unattended, whenever that
run happens. The account is reported as `PENDING_APPLY`, the word
`creds finish-rollover` uses for the same fact.

**A profile that restricts reuse usually refuses a rollback** (decided in #568).
`previous` is the password the account held one change ago. Where
`PASSWORD_REUSE_MAX` or `PASSWORD_REUSE_TIME` is anything but `UNLIMITED`, it is
the value most likely to be in the history, and the statement is likely to fail
with `ORA-28007`. The failure is certain where one limit is `UNLIMITED` and the
other is a number. Where both are numbers, it depends on the time elapsed and on
changes made since. On ADB serverless 23.26.3.3.0, whose own `DEFAULT` profile
has `4` / `1`, and on tier 1's `SOPULI_REUSE` profile (`5` / `UNLIMITED`) on
Oracle Free 23.26.2.0.0, both rollbacks were refused, both failed safely, and
`check` afterwards reported `IN_SYNC` against `current`.

The run says so, and does not refuse in advance. Every rollback that reaches the
statement on such a profile carries `SOPULI-W028`, one per target and profile,
naming both values, whether the statement succeeded or not. The run reports the
values and does not interpret them, which is §4's rule for the same two values.
When both are numbers, Oracle's rule also counts changes made outside the tool,
which the tool cannot see. So a refusal at plan time would sometimes refuse a
rollback that would have worked. A refused rollback is never redrawn, because
`previous` is the only value it has. Its row's hint says that, instead of the
driver's "draw another".

**Under `--preflight`, the warning comes before anything is sent.** The survey
already reads each account's state, including the profile limits. So a rollback
on a reuse-restricted profile raises the same `SOPULI-W028` in the survey. This
happens under `--dry-run --preflight`, which asks "show me the plan and tell me
whether it would work", and in a real run, which then does not raise it a second
time for the same target and profile. Raised before the statement, it is a
prediction: it cannot know that an account already holds the password, which the
run's own reading can. It is not raised where the run would first move the
account to another profile, because the limits read are then not the ones the
statement meets. The run's own reading covers that case. A plain `--dry-run`
connects to nothing, so it cannot raise the warning.

**On such a profile, the way back is a rollover window, not a rollback.** A
profile with `PASSWORD_ROLLOVER_TIME` makes every rotation open a window (§6.3).
The old password keeps working until `finish-rollover` or the end of the window.
That gives the same way back a rollback would, with no reuse, because nothing is
set back. An estate whose baseline restricts reuse should plan its recovery
around that window, not around `--source previous`. CIS-style profiles set both
limits. The window exists only if the rotation opened it, so the decision must be
made before rotating, not after something breaks.

Rollback goes back one generation only (Q3, decided in #84). OCI holds exactly
one `PREVIOUS`, and the stage vocabulary in `01-configuration.md` §7 has no name
for an older one.

### `--preflight`, and what it checks before anything is written

§8 step 3 belongs to `rotate`. It is available here too, because the same
question is worth asking before a large `apply`: *would this work?* The survey
makes one connection per target, before the first `ALTER USER`, and checks §8's
list: reachable, the scope the file claims, the accounts declared, and the
privileges needed.

**It is off by default.** A repair of one target should not pay for a survey of
twenty. Without the flag, `apply` finds each of these problems per target as it
goes, and reports them per account. An explicit `--strategy` also needs one
connection per target for its own refusal. The survey and that refusal share
**one pass on one connection**.

**Every finding is reported, and one of them refuses.** A pre-flight lets an
estate be fixed in one pass, so the table lists every finding. But a run has one
exit code and one `error`. That one is the finding earliest in §8's order, the
one closest to the cause. A target that could not be reached explains its own
missing scope. A container that turned out to be the wrong one explains every
account that was not found in it.

**It exits 1, because nothing changed anywhere.** That is what exit 1 already
means for this verb. It is not 9: an estate that disagrees with the file is not a
file that could not be read, and `config validate` passes on all of these. It is
not 5 either. Exit 5 is invariant 4's, and a capability the estate cannot honour
is still `--strategy`'s own refusal, raised where it is found.

**Not knowing is not a finding.** An open mode the driver could not read is not a
read-only database. A privilege audit that the service account may not run has
established nothing. So each is reported as a warning, and the run goes ahead.
This is §7's rule for the `LCOUNT` guard: a check that is not running says so,
and is not skipped silently. Refusing over it would mean that an estate that does
not grant the audit view could never run a pre-flight at all.

**These caveats are printed as well as written to the document** (decided in
#606). A survey that refuses prints every finding in its table, caveats
included. A survey that passes prints no table, so its caveats go in the run's
notes. There is one note per target, naming what could not be established and
the server's reason, with the accounts that share a cause on one line. They
print on every such run, `--dry-run` or not. `rotate`'s pre-flight prints them
the same way. Reasons: [#606](../decisions/log.md#606).

**`--dry-run --preflight` surveys too.** It writes nothing and needs no lock.
"Show me the plan, and tell me whether it would work" is often the first command
an operator runs. A flag that silently did nothing there would mislead.

### There is no `--continue-on-error` (decided in #266)

The behaviour that name promises is what `apply` already does. The run-wide
stops that remain each exist for a different reason. Reasons and rejected
options: [#266](../decisions/log.md#266).

This table shows what a run does when one part of it fails:

| failure | what the run does |
|---|---|
| a target that will not connect | `ERROR` rows for its accounts; the run moves to the next target |
| an account whose statement the server refuses | `ERROR` row; the run moves to the next account |
| a **promotion** that fails | that document is not promoted; the others still are |
| a **lock** somebody else holds | exit 7, nothing ran |
| a **lock** this store or path cannot fence | exit 5, before anything is read or written |
| a **fence check** that finds the lock taken | abort, change nothing more, exit 7 or 4 |
| a **pre-flight** blocking finding | exit 1, nothing was written |
| a **capability** the estate cannot honour | exit 5, before anything is written |
| a **vault document** that will not read | the store's own exit code, nothing ran |

The first three rows are what the flag would be for, and they need no flag. A
failure that belongs to one target, one account or one document stays confined
to it.

The sample below is from an estate of two targets, with the unreachable one
**first**, against Oracle Free 26ai 23.26.2.0.0 and a dev-mode Vault:

```
ACCOUNT        TARGET       STATE    DETAIL
acme_web_user  appdb-beta   ERROR    ORA-12170: Cannot connect. TCP connect timeout of 20s for host 192.0.2.10 port 1521.
acme_web_user  appdb-alpha  IN_SYNC  changed and verified by login

1 changed, 1 promoted to `current`, 1 not confirmed
```

It exits 4. The target that could not be reached did not end the run, the one
after it was applied, and only the failed account's document was held back from
promotion. The same estate under `--preflight` refuses instead, with exit 1 and
`nothing was written`.

The other rows are the stops a `--continue-on-error` flag would have to override,
and none of them should move:

- **The taken lock must not move.** Another run owns the estate, and this one
  stops changing things (§8's fence row). Overriding it would let two runs write
  the same account, which the fence exists to prevent.
- **The lock refusal must not move.** Exit 7 means nothing ran, and schedulers
  rely on that (`../design/03-json-output.md` §6).
- **The capability refusal must not move.** Invariant 4 requires a refusal at
  plan time with its own exit code.
- **The pre-flight refusal could move, but not under this name.** "Survey
  everything, then apply to the targets that passed" is coherent: with rollover
  as the default strategy, a partial apply causes no outage. But it is a
  guardrail override, and this command already has one. `--force` waives the
  account guardrails and records every waiver in the run document. If an
  estate-wide override is ever wanted, it belongs under that flag. A flag that
  means something only when a *second* flag is passed is the trap that
  `--dry-run --preflight` avoids.
- **The unreadable vault document is a different question.** If one document out
  of twenty cannot be read, the run aborts before any `ALTER USER`, because it
  reads every path it needs in one pass. Turning that into `ERROR` rows for the
  affected accounts is arguable. But it weakens the "sopuli could not run"
  promise that exit 7 also makes, and it changes what an exit code means, which
  a flag should not do.

A flag documented as doing what the tool does anyway is worse than no flag. An
operator who passed it would conclude that the runs without it behaved
differently.

### `--repair`, and where its list comes from (decided in #264)

The command below acts only on what an earlier run left unconfirmed:

```
sopuli creds apply --repair result.json
```

**The list comes from an earlier run's document.** `--repair` takes the path to
one, usually an `apply` that exited 4 or a `check` that exited 3. It narrows this
run to the (account, target) pairs that the document reports as not confirmed.
Reasons and rejected options: [#264](../decisions/log.md#264).

**The filter is each row's state, never the document's exit code.** Refusing by
exit code would refuse an `apply` that exited 1, where every target failed and
nothing changed. That is the document *most* worth repairing from. It would also
refuse a `check` that exited 1 because one target was unreachable, where trying
again is the remedy. Accepting them loses nothing: `apply` verifies every pair
before it touches it, and invariant 5 still limits what it can reach. The tool
refuses a document from a command that reports no repair set at all, such as
`creds generate`.

**It saves logins; it adds no capability.** `apply` is already idempotent. Every
account is verified before it is touched, and one that already works is left
alone. So a repair without the flag converges the estate correctly, at a cost.
The cost is one login per account per target: an attempt against the
failed-login counter §7 protects, a connection, and an audit entry in a database
that had nothing wrong with it. Repairing one PDB in an estate of twenty-one
spends twenty-one logins.

**Why it does not run `check`'s logic first, in the same process.** `apply`
already does. Its verification before the change *is* `check`'s comparison, and
the `ALTER USER` is skipped where it passes. A flag that ran `check` first would
spend exactly the logins `--repair` saves, and change nothing else.

**Why it does not take the target list from the operator.**
`--repair --target x` would be `--target x` with more letters. `--select`,
`--target`, `--group` and `--account` already narrow the estate. A second
spelling of them would only be easier to get wrong.

**What the tool refuses in the document, and what it does not.** A stale
document describes a stale estate. Two properties limit the harm before any rule
is needed:

- **It can only narrow.** Invariant 5 makes the config the whitelist, and
  `--repair` feeds a filter, not a target list. A pair that the document names
  and the config no longer declares is dropped, not acted on.
- **A pair repaired since costs one login and reports `changed: false`,**
  because `apply` checks before it acts.

So acting on a stale document wastes logins but is not dangerous. Freshness is a
**warning that names the document's age**, `SOPULI-W020`, not a gate with a
threshold. Any threshold would be wrong for somebody, and the run it refused
would have been safe. What the tool *does* refuse is a document that describes a
different estate, before any target is dialled. A repair aimed at the wrong
estate is the one failure the two properties above do not catch.

**It reads `invocation.config_files`, not `config.sources[]`.** Only
`config show` and `target list` emit the `config` section, so no document this
flag accepts has it. A document with no `invocation.config_files` is refused.
The check is on whether the field is present, not on the version that wrote the
document.

The check compares paths, not file contents. So the same file copied to a second
path counts as a different estate, and moving a config file invalidates the
documents produced with it. The message names both lists, so the operator can see
which. Order matters too. It is the layering order (`01-configuration.md` §5),
so the same files layered the other way round resolve different settings and are
not the same estate.

**The refusal exits 2, with no run document** (J7). That is what every other
selector does when it does not resolve. `--target nosuch` raises `ArgumentError`
from `refuse_unknown`, and `--repair` feeds a filter, so a filter that does not
resolve is an invocation that did not resolve. Exit 9 means *fix your
configuration*, and the configuration here is fine.

**A repair of a rotation applies the change; a later run promotes it.** Take a
repair narrowed to one of a document's two accounts. It changes that account and
then withholds the promotion, because the sibling that the earlier run already
applied still has its `pending` staged, and this run did not check its database.
That is §5's promotion gate. So a partial rotation takes two runs to finish:
`--repair` for the pairs that failed, then `apply` without narrowing. The second
run spends one login on each converged pair and promotes. A repair from
`current`, which is drift with nothing staged, has nothing to promote and
finishes in one run.

**Exit 4 prints the command that repairs it.** A partial run's closing line says
what to type. It is narrowed the way the run was narrowed, and it carries
`--config`, `--profile`, `--source` and `--strategy`, so the repair resolves and
acts the way the run did:

```
1 changed, 1 not confirmed
repair with: sopuli creds apply --config estate.yaml --select env=prod
         or: --repair FILE, if you captured this run with --output json
```

The first line is the plain re-run. It works for both shapes of exit 4: targets
that did not confirm, and an estate that confirmed while its vault was not
promoted. The second shape is §8 case 7. Applications fetch a password the
databases no longer have, so knowing what to type next matters most there.

The `--repair` line is printed only where an unconfirmed row exists. On §8 case
7, every target confirmed, so there is no unconfirmed row to build a repair set
from. `--repair` would filter the estate to nothing and report
`nothing to apply`.

The plain re-run is the first line, and not `--repair`, because the closing line
is text output only. The emitter writes the JSON document or the text, never
both. A text-mode run leaves no document on disk for `--repair` to read. A JSON
consumer needs no line: it has `results[]`, and `03-json-output.md` §7's recipe
is the same filter the flag applies.

**The line carries no diagnostic code.** `03-json-output.md` §3's rule is that a
code exists for what the exit code cannot tell you. Here exit 4 says it, and
`results[]` already carries the states a consumer would filter on.

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

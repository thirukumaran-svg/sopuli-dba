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
                      [--overwrite-pending]  # authorise discarding a staged `pending`
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
- **A staged `pending` is not discarded unless you ask** (decided in #769).
  Where a selected account already has one, the run refuses on exit 8, naming
  the accounts, and points to `creds apply`, which applies and promotes what is
  staged. An `apply` may be putting that password on a database at that moment,
  for example one that took over an expired lock. Drawing over it would leave
  the database holding a password that the vault holds nowhere.
  `--overwrite-pending` authorises the discard, for a staged password that
  nobody should use. Like `--overwrite-current`, it is a flag you type, not a
  prompt, and `--confirm` does not satisfy it. `--dry-run` is never refused,
  and it names the accounts that have a `pending`. To do that it reads the
  vault, so a preview needs the vault token, as `--promote --dry-run` does. A
  document the plan cannot read is named, with the note that whether it has a
  `pending` is not known. The run checks again under
  the lock, and a `pending` that appeared after the plan is not discarded: that
  document's write fails and names the accounts.
- Generating twice with `--overwrite-pending` replaces `pending`, and the run
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
`creds apply` uses, which already clears it. Clearing a `pending` discards it,
so `--promote` over one needs `--overwrite-pending` as well, for the reason §4
gives. `--overwrite-current` does not cover it.

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

A guardrail skip counts against the promotion only where the promotion would
move past it: the account has a `pending` to promote, or a `previous` on a
rollback, and confirmed on another target. The guardrails read each database, so
one account can hold `DBA` on one target and not on another. The skipped target
then still holds the old password, so the document is not promoted: `pending`
stays, the run exits 4, and `SOPULI-W050` names the skipped pairs. A failure on
another target is reported first, because the same run again may fix it. Every
other skip is dropped from the gate: an account skipped on every one of its
targets, or applied from `current`, does not hold back the other accounts in its
document.

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
one, usually an `apply` or a `rotate` that exited 4, or a `check` that exited 3.
It narrows this run to the (account, target) pairs that the document reports as
not confirmed. Reasons and rejected options: [#264](../decisions/log.md#264).

**A `rotate` document's staging rows are skipped.** `rotate` lists a row for its
staging write (§8 step 4) before its apply rows. The staging row's state is
`PENDING_APPLY`, which is not confirmed, so counting it would put every target in
the repair set, including the targets that took the password. The tool tells the
staging row by its `vault_write_pending` action, not by its state: `apply` also
reports `PENDING_APPLY`, for a rollback it refused, and that row is a pair to
repair. A `rotate` document with only staging rows stopped at step 4, before any
database was changed. The tool refuses it, because a repair set of nothing would
report `nothing to apply` and read as "already repaired". §8 row 4's recovery is
`apply` where the run staged a `pending`, and otherwise `rotate` again. A new
rotation refuses over a staged `pending` (§8).

**A document from a run that lost its lock is refused**, whichever verb wrote
it. It carries `SOPULI-W011`, and §8 says the run that holds the lock is the one
that may fix it. The document also leaves out the pairs that run never reached,
so a repair set built from it would leave them out too. `check` establishes what
is true.

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
repair narrowed to the targets a rotation missed. It changes those targets and
then withholds the promotion with `SOPULI-W027`, because the same credential is
on a target that the earlier run already applied, and this run did not check
that database. The same happens to a repair narrowed to one of a document's two
accounts: the sibling still has its `pending` staged. That is §5's promotion
gate. So a partial rotation takes two runs to finish:
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
code exists for what the exit code cannot tell you. Here exit 4 says that the run
is partial, and `results[]` carries the states a consumer would filter on. What
exit 4 cannot say is why an estate that confirmed was not promoted. So a failed
promotion write has its own code, `SOPULI-W033`, which names the same repair
command, printed as a note under the line.

---

## 6. Oracle specifics

### 6.1 The statement

The tool changes a password with this statement:

```sql
ALTER USER "ACME_WEB_USER" IDENTIFIED BY "<new>";
```

Points that matter:

- **A password cannot be a bind variable.** DDL is literal text, so the password
  appears in the statement. Consequences:
  - The tool quotes the password, and **rejects** a password that contains `"`
    instead of escaping it. An Oracle quoted identifier has no escape for it
    (invariant 11). The default `alnum_safe` charset never draws one.
  - **The statement is not kept in `V$SQL` on 26ai.** In `CDB$ROOT` and in a
    PDB, no cursor for the DDL is retained, so there is nothing to mask. Unified
    audit does keep the statement, masked to `IDENTIFIED BY *` when it is
    written, in `AUDSYS.AUD$UNIFIED` and in the view. A session traced at 10046
    level 12 writes the statement cut short, `ALTER USER sopulitest IDE`, so SQL
    trace does not capture the password. These are measurements, not Oracle
    guarantees. `docs/measurements.md` lists the releases they ran on, and
    `sql/oracle/02_password_leak_probe.sql` and
    `04_password_leak_extensions.sql` repeat them on another release.
    **Third-party monitors that read trace files are untested.** What they keep
    is theirs, not Oracle's. The tool never enables trace on its own sessions,
    keeps the statement out of its own logs, and documents the remaining risk.
  - **Never wrap the statement in an anonymous PL/SQL block.** Issue
    `ALTER USER` directly. Wrapping does not keep the DDL literal out of the
    shared pool. Wrapping *adds* an exposure, because the block's own text is kept
    verbatim in `V$SQL`, `V$SQLAREA`, `V$SQLSTATS`, `GV$SQL` and
    `V$DB_OBJECT_CACHE`. Oracle's protection is tied to the `CREATE USER` or
    `ALTER USER` statement. A block that contains one is an ordinary block
    (invariant 13).
- **Privileges.** `ALTER USER` is a system privilege with no object scope. It
  cannot be granted for specific accounts only. The tool needs it and nothing
  more. It must never need `DBA` or `SELECT ANY DICTIONARY`. The tool enforces
  which accounts it may touch, on the client side, from the config's
  `applications` section or the inline `accounts:` list. See
  `../design/02-oracle-privileges.md`.
- **`IDENTIFIED BY new REPLACE old`** is needed when a user changes *their own*
  password without the `ALTER USER` privilege, and their profile has a password
  verify function. This matters only in self-rotation mode, where the tool
  connects as the account itself (Q6). There the old password is what the
  vault's `current` field holds, so it is available. An admin with `ALTER USER`
  never needs `REPLACE`.

### 6.2 Common users and containers

| Scope | Statement | Notes |
|---|---|---|
| non-CDB | `ALTER USER x IDENTIFIED BY …` | plain |
| PDB, local user | connect to the PDB service, then plain `ALTER USER` | one password per PDB unless the secret is shared |
| CDB root, common user | `ALTER USER "C##MON" IDENTIFIED BY … CONTAINER=ALL` | must be connected to `CDB$ROOT`; `CONTAINER=ALL` is the config's `oracle.container_clause` |
| Application root | every account is application-common; a statement with **no** container clause already applies to the whole application container | refused; see below |
| Application PDB, local user | connect to the application PDB service, then plain `ALTER USER` | ordinary |

Guardrails: refuse `CONTAINER=ALL` when not connected to a root. Refuse to treat
`C##`-prefixed names as local users. Refuse to apply to a PDB that is not
`OPEN READ WRITE`. Skip PDBs that are closed or in a standby, with a clear
status, instead of failing the whole run.

**An application root is refused; an application PDB is not.** The driver
detects both scopes. The facts below were measured on 26ai Free 23.26.2.0.0.
`sql/oracle/03_app_container_probe.sql` builds the container and reproduces each
one.

- **Detection needs no grant.** `SYS_CONTEXT('USERENV','IS_APPLICATION_ROOT')`
  and `'IS_APPLICATION_PDB'` tell both scopes apart from an ordinary PDB. A
  service account with exactly `02-oracle-privileges.md` §2's PDB-mode grants
  can read them, in a session where `V$PDBS`, `DBA_PDBS` and `CDB_PDBS` all
  give `ORA-00942`.
- **`C##` names cannot exist in an application container.** Oracle refuses
  them with `ORA-60534`, in the root and in a PDB.
- **In an application root, every account is application-common.** A local
  account gives `ORA-65049`, and `CREATE USER` with no container clause creates
  an application-common user. So the tool sees a name without a `C##` prefix,
  concludes it is a local account, and adds no clause. Oracle accepts that
  statement and applies it across the whole application container. **The danger
  is that the missing clause already means more than it seems to.** A login test
  confirmed it: after a rotation with no clause in the root, the new password
  works in an application PDB that had already been synced, with no sync in
  between, and the old one does not. `password_change_date` in that PDB stays
  empty throughout, and would have said the opposite. That is Q1's argument for
  verifying by `login`.
- **In an application PDB, the refusal is not needed.** A local account is
  ordinary. Oracle itself refuses an application-common one: `ORA-65066` with no
  clause, `ORA-65040` with `CONTAINER=ALL`.

The driver asks `IS_APPLICATION_ROOT` and `IS_APPLICATION_PDB` only in a
container that would otherwise be `pdb`. A non-CDB or a root session already has
its answer and pays nothing. An application root is refused. The message names
the scope and says that a rotation with no clause there reaches the whole
application container. An application PDB takes the ordinary path. A local
account gets a plain statement. A `C##` account is refused by the common-user
guardrail, and could not exist there anyway.

Neither guardrail can catch an application-common account declared against an
application PDB, because nothing in its name marks it. Oracle refuses it with
`ORA-65066`. The tool maps that to the container-misuse category and exit 9,
with a hint that the root is where to rotate it.

### 6.3 Gradual password rollover (19.12+/21c): the default strategy

Where it is available, rollover makes a rotation with no downtime possible:

1. The account's profile has `PASSWORD_ROLLOVER_TIME` > 0, for example `1` day.
2. `ALTER USER x IDENTIFIED BY <new>` starts the rollover window. **Both the old
   and the new password work** until the window closes.
3. Applications pick up the new password from the vault on their own schedule:
   a restart, a connection pool refresh, or a credential refresh loop.
4. When the window is no longer needed,
   `ALTER USER x EXPIRE PASSWORD ROLLOVER PERIOD;` ends it early.

What the tool does:

- `--strategy rollover`, the default where the capability exists, checks that
  the profile has a non-zero `PASSWORD_ROLLOVER_TIME`. Where it has not, the tool
  **reports the exact `ALTER PROFILE` an operator would run, and issues none**
  (Q4, decided in #88). `finish-rollover` takes the same position. A profile is
  shared, so editing one reaches accounts nobody selected. Invariant 5 cannot
  limit that, because the config whitelists accounts, not profiles. So enabling
  rollover where a site has not got it is a DBA change outside the tool. What the
  run does *instead* depends on whether the strategy was asked for: refused at
  pre-flight if it was, resolved per account to `staged` if it was not. See
  *What `--strategy` decides*.
- `check` reports `ROLLOVER_ACTIVE`, with the time remaining, instead of calling
  it drift.
- `sopuli creds finish-rollover` ends the window explicitly. It issues the same
  statement as `--strategy direct`. It is a separate command because it has to
  *find* windows that no run handed it; see below.
- Where the database has no rollover capability, use `--strategy staged`. The
  tool applies and reports, and the operator restarts the application. The
  documented risk: "brief authentication failures are possible for connections
  established with the old password after the change".

### `creds finish-rollover`, and what it refuses (decided in #263)

The command below closes rollover windows:

```
sopuli creds finish-rollover [selectors] [--dry-run] [--confirm] [--lockout-margin N]
```

`--strategy direct` closes the window it just opened, in the run that opened it.
This verb finds windows that no run handed it. **Closing a window is a step whose
purpose is to stop something working**, so most of what this verb does is decide
which accounts to leave alone. Reasons and rejected options:
[#263](../decisions/log.md#263).

**It takes no lock and writes to no store.** Nothing in any vault changes, so the
advisory lock has nothing to protect. A nightly job that took the lock would
block the rotation it exists to finish. Like `check`, it leaves every vault
document alone.

**It applies these gates, and only the second costs a login:**

- **a staged `pending`**: the rotation is unfinished, so the vault's `current` is
  still the *old* password. Closing the window would cut off every application
  that has not been given the new one. The account is reported as
  `PENDING_APPLY` and refused **without a login**.
- **a refused `current`**: the database rejects the vault's password even with
  the window open, so neither password in play is the one applications fetch.
  The account is `DRIFT`, the run exits 3, and the window stays open.

**What the login proves, and what it does not.** That is why the gates are
separate checks. Under an open window, both passwords work. So a *pass* cannot
tell "the database has the vault's password" from "it has the previous one and
accepts both". `check` reports the same doubt as `ROLLOVER_ACTIVE`. A *fail* is
conclusive, and that is what the login is for. The case where a pass would
mislead is the staged-`pending` one, and the vault reveals that without a login.

Every other account with an open window has its window closed. An account with
**no** window open reports `changed: false` (invariant 9). That is the usual
result for S2's scheduled job. On 26ai, the statement issued with no window open
is accepted silently and changes nothing, so a run that issued it anyway would
report a change every night. A locked or expired account keeps its window. So
does an account on a database with no `expire_password` capability. That is
`SKIPPED`, not an error, because a window nobody can close early ends on its own.

`--confirm` answers the `safety.confirm_environments` question in advance.
`--lockout-margin` sets §7's lockout guard for the login.

**`--dry-run` reads the state and spends no login.** A preview here answers *who
am I about to cut off, and how early*. A login has a real cost against the
failed-login counter, and a preview changes nothing.

### What `--strategy` decides

**The statement is the same in all three regimes.** So this is one code path with
a precondition and a follow-up, not three:

| strategy | statement | after |
|---|---|---|
| `rollover` | `ALTER USER … IDENTIFIED BY …` | the window opens; both passwords work until it closes |
| `staged` | the same | the change is immediate |
| `direct` | the same, then `ALTER USER … EXPIRE PASSWORD ROLLOVER PERIOD` | the window is closed at once, so the old password stops working |

**The default is chosen per account, and it is never `direct`.** It is `rollover`
where the capability exists *and* the account's profile grants a window, and
`staged` otherwise. Two accounts in one database can have different profiles, so
it is resolved per account, not per run. `direct` is never chosen for the
operator. Ending a grace window early harms whoever still holds the old password,
and a default that did it would make that decision for an operator who did not
know there was one.

**Oracle decides whether a window opens, not this tool.** It opens when the
profile's `PASSWORD_ROLLOVER_TIME` is greater than zero, whatever the run asked
for. So `--strategy staged` against a rollover-enabled profile is **refused**.
Running anyway and reporting `staged` would tell an application team that the old
password had stopped working when it had not. The refusal names the profile and
offers `rollover` or `direct`.

**An explicit strategy is checked for the whole estate, before anything
changes.** Naming a regime asks for a property of the estate, such as *no
application will see a failed login tonight*. A run that honoured it on four PDBs
and found on the fifth that it could not would already have broken that promise.
So an explicit `--strategy` costs one extra connection per target, for a
pre-flight that clears every account or refuses. With no flag there is nothing to
refuse, and the run pays nothing.

**`direct` closes the window only after the change is verified.** Closing it
after an unconfirmed change could leave an account whose old password has stopped
working and whose new one is not known to work. That is worse than the grace
period `direct` exists to avoid. Against a profile that grants no window, `direct`
issues no second statement, because the change was already immediate.

**What the run reports.** `results[].rollover` carries `active`, `ends_at` where
there is a window, and `profile_rollover_time`. It is present for every account
the run acted on, not only those with an open window, because the *absence* of a
window answers "did the old password stop working just now".

### 6.4 Errors worth handling by name

| Error | Meaning | Tool behaviour |
|---|---|---|
| ORA-28003 | password verify function rejected it | `apply` redraws (bounded), keeps the server message with the password replaced by `***` ([#786](../decisions/log.md#786)) |
| ORA-28007 | password cannot be reused | `apply` redraws; never retries the same value |
| ORA-01017 | invalid credentials | verification failure → drift, not a crash |
| ORA-28000 | account locked | report `LOCKED`; unlock only where the policy declares it (§5) |
| ORA-28001 | password expired | distinguish from drift; `apply` resolves it, because setting a password clears the expiry. The tool never expires a password on purpose (§5) |
| ORA-28002 | password in grace period | informational, **not** a state. `check` and `status` report the grace period as `SOPULI-W013`, read from `ACCOUNT_STATUS`; `check` carries the login's own notice, whatever its code, as `SOPULI-W014`. See below |
| ORA-01031 | insufficient privileges | fail early in pre-flight, naming the missing grant |
| ORA-65040 / ORA-65048 | container-clause misuse, error while applying to a PDB | scope guardrail message |
| ORA-12154 / ORA-12541 | naming/listener | connectivity, a separate category |
| ORA-01109 / ORA-12514 | the database is not open, or the listener does not know the service. A PDB closed during a run gives one of the two | connectivity. The hint says the PDB may be closed, because neither message does |
| DPY-4011 | the database or the network closed a session the run held: its PDB closed, the CDB shut down, or the network dropped. The message carries DPI-1080 and ORA-03113 below it | connectivity, not retryable: whether a statement in flight took effect is unknown. The hint says so, and to run the command again once the database answers |
| ORA-12528 / ORA-01033 | a logon while the CDB starts: in NOMOUNT the listener blocks it, in MOUNT the database refuses it | connectivity, retryable, because both pass once the database opens |
| ORA-28759 / ORA-28768 | the client's wallet could not be opened, or is damaged | connectivity. The hint names `TNS_ADMIN`, `WALLET_LOCATION` in `sqlnet.ora` and `cwallet.sso`, because the server message names none of them |
| ORA-28040 / ORA-01017 with version mismatch | verifier / `ALLOWED_LOGON_VERSION` mismatch | explain the password-version implications |
| DPI-1047 / DPY-3001 | the *client* library, not the server: Instant Client missing, or thin mode reached because thick-mode initialisation did not happen | `config` and exit 9, as ADR-006 does for a backend that is configured and not installed, because the person reading the message fixes it on this machine. An Instant Client that cannot be used at start-up has `error.code` `SOPULI-20004` (`03-json-output.md` §3). `DPY-3001` keeps the vendor code, because it means start-up never ran, which is this tool's fault and not the machine's |

**The grace-period code depends on the release and the profile.** These are the
measured results. Each was measured with `python-oracledb` in thick mode, unless
the row says otherwise. `docs/measurements.md` has the dates:

| Release | In grace, `PASSWORD_GRACE_TIME` limited | In grace, `PASSWORD_GRACE_TIME UNLIMITED` |
|---|---|---|
| 26ai Free 23.26.2.0.0 | login **succeeds**; `connection.warning` carries `ORA-28098` | login **succeeds**; `connection.warning` carries `ORA-28011` |
| 19.3.0.0.0 | login **succeeds**; `connection.warning` carries `ORA-28002` | not measured |
| 21.3.0.0.0 | `ORA-28002`, seen in SQL\*Plus; not measured through the driver | not measured |

A hard-expired password raises `ORA-28001` on every release measured.

- **It is not an error.** A login in its grace period connects, so nothing is
  raised, and the notice arrives on the connection. The tool carries whatever the
  server attaches as `SOPULI-W014`, verbatim, with its code as data, because the
  code varies.
- **`DBA_USERS.ACCOUNT_STATUS` says `EXPIRED(GRACE)` in every case.** So the
  dictionary is the dependable signal for the grace period, and the login
  warning is not. That keeps the tool off a per-release code table.

#### What the grace period is reported as

**A warning beside the state, never a state of its own.** An account in its grace
period can log in, so `check` verifies it like any other account and reports
what the login found:

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
instead, as *1 account: 1 in a grace period*. That command's closing line answers
*is there anything to do*, and there is: rotate before the window closes.

A `state` of its own was rejected. `state` is one field, and an account in grace
may also have **drifted**. A grace value would have to replace `IN_SYNC` or
`DRIFT`, and either way it would hide the answer the reader came for. As a
warning, *drifted, and expiring on Friday* can be said. It is also a smaller
contract change: `results[].warnings[]` already exists, so the state enum in
`03-json-output.md` §2 does not change.

**It is read from the dictionary, not from the login.** `ACCOUNT_STATUS` says
`EXPIRED(GRACE)` in every profile shape. So the warning appears even on runs
where no login happened, which is when the lockout guard declined to try and an
operator most wants the rest of what is known.

**The remedy the warning implies is `creds apply`.** It needs nothing new.
Setting a password clears the expiry, so a rotation ends the grace period as a
side effect (§5).

### Which verb redraws, and why it is `apply` (decided in #268)

Reasons and rejected options: [#268](../decisions/log.md#268).

`apply` redraws when the server refuses a password. `generate` cannot prevent
either refusal, because neither can be predicted before the `ALTER USER` runs:

- `ORA-28003`'s verdict comes from arbitrary PL/SQL, and the tool cannot call
  the function. Calling it needs the password inside a PL/SQL block
  (invariant 13) or in a bind (invariant 14), and there is no other way to
  invoke it.
- From inside a PDB, a **common** profile's `PASSWORD_VERIFY_FUNCTION` reads as
  the literal `FROM ROOT`. A service account without a root connection cannot
  even *name* the function it must satisfy (`02-oracle-privileges.md`). A
  *local* profile answers with the function's name, and `DEFAULT` answers
  `NULL`, so §4 step 2 reports the reading it got.
- `ORA-28007` depends on hashed per-account history. `apply` reads
  `PASSWORD_REUSE_MAX` and `PASSWORD_REUSE_TIME`. They state the rule, never
  whether this draw collides with it.

§4 step 2's constraint read removes a different set of refusals: byte length and
character set. Those failures are *deterministic*, and one policy fix ends them
for every account in the selection. It does not remove either of the rows above.

**These rules govern the redraw**, and each exists because the alternative is
worse:

| | |
|---|---|
| **Bounded** | three draws, including the value the run started with. A server that has refused three independent draws is describing its own rules, and a fourth draw learns nothing new |
| **Only what the tool drew** | gated on the `origin` beside `pending` (§3). A `supplied` password was dictated by an external system, and an absent `origin` is the same case without the evidence |
| **Only a refused password** | an unmapped code never redraws. It might be transient, or a value the server will always refuse; of the two ways to be wrong, looping is the one that locks accounts |
| **Never quietly** | each redraw is reported as its own change, naming the version whose `pending` it replaced (§4's warning) |

**A redraw covers one account, not the document and not the estate.** Passwords
are drawn per account even where accounts share a document (§4). So a refusal
concerns only the account that met it. The new password is applied to all of
that account's targets, including those already visited in this run, so that
every target bound to it ends the run with the same password.

`apply` does not become a generator by doing this. §4 step 3 is already a bounded
loop that rejects candidates against the policy. This adds one more check, and it
cannot be run offline.

**What a run says it did.** Every draw is a `SOPULI-W029` warning naming the
account, the version it staged, and the server's own message. Every refusal to
draw is a `SOPULI-W030` warning naming the account and the rule that stopped it.
On the row, `results[].redraws` counts the extra passwords the account was given.
It is present only when there was one. It means "this row was applied more than
once and reports the last attempt", not a failure. A redrawn account that ends
`IN_SYNC` succeeded.

**Two more refusals follow from the rules.** An account whose policy the file
does not declare cannot be drawn for, so it is reported and the run goes on. The
run was applying the estate correctly, and a configuration error would complain
about a file nothing had changed. A run that applies from `current` instead of
`pending` never redraws, because `origin` describes a staged value, and `current`
is what applications already hold. Replacing that during an apply would be a
different and much worse operation. §3's rule that an absent `origin` blocks a
redraw already covers it.

`sopuli/driver/oracle/errors.py` maps the codes, under these rules:

- **The mapping classifies; it does not decide.** Nothing there raises, because
  `ORA-01017` means different things depending on whose credential was refused:
  exit 6 for the admin connection, `DRIFT` and exit 3 for a verification login.
  It returns a value, and the caller, which knows what it was doing, decides
  whether that value is an exception, a state, or a reason to draw another
  password.
- **An unmapped code is final, and never causes a redraw.** A code in Oracle's
  Net/TNS range still lands as `connectivity`, not as `database`, so an unnamed
  member of a family is unknown but not misplaced.
- **Exit codes are P5's and are not invented here.** Connectivity and
  authorization errors have no exit code of their own. They exit 1 and carry
  their own *category*. Adding a number to P5's table would change a contract
  that schedulers rely on.

---

## 7. `sopuli creds check`

Answer one question per (account, target): does the vault's `current` password
work against this database?

```
sopuli creds check [--application acme]          # and the other selectors (§2)
                   [--method {login,hash,both}]  # default: login
                   [--include-previous]          # is the old password still accepted?
                   [--lockout-margin N]          # default 2
                   [--output json]
```

`--method` defaults to `login` (Q1, decided in #86). An explicit `hash` or
`both` that the estate cannot honour is refused at plan time (below).

### The lockout problem

A simple check logs in with the vault password. If the password is wrong, the
failed attempt counts against `FAILED_LOGIN_ATTEMPTS`, and repeated scheduled
checks will eventually **lock the production application account**. That is
worse than the drift the check was looking for. All of these mitigations apply:

1. **Never retry.** One attempt per account per run, with no retries on
   ORA-01017.
2. **Read `LCOUNT` first, where the grant exists.** `SELECT ON SYS.USER$` is
   optional and not part of the default install (`02-oracle-privileges.md` §2
   and §8 P2; decided in #86). The tool probes it as a capability. Where it is
   present, the tool does not attempt a login when the account is already within
   `--lockout-margin` (default 2) of the profile's `FAILED_LOGIN_ATTEMPTS`. It
   reports `UNVERIFIABLE` with the reason. Where it is absent, `check` still runs
   on the other runtime mitigations (1, 3 and 6), and says plainly that the guard
   is not running.
3. **A successful login resets the counter.** So the normal path cleans up after
   itself.
4. **Offer hash mode** (below) as the safe alternative for frequent checks:
   `--method hash`.
5. Document how this interacts with `PASSWORD_LOCK_TIME` and with profiles that
   set `FAILED_LOGIN_ATTEMPTS UNLIMITED`. This is documentation, not a runtime
   check.
6. **Report `ACCOUNT_STATUS` always**, from `DBA_USERS`, which is in the baseline
   grant set. A login attempt alone gives the same `ORA-01017` for an expired
   password, a locked account and a wrong password. `check` reads the status
   separately, and reports `LOCKED` and `EXPIRED` as their own states instead
   of folding them into `DRIFT`. A `LOCKED(TIMED)` account is reported as
   `LOCKED`.

### `--method hash`: verification without a login attempt

Hash mode is an opt-in extra. The default, `login`, does not depend on it.

Oracle stores a salted PBKDF2-SHA512 verifier, the `12C` verifier in
`SYS.USER$.SPARE4`. With read access to that column, the tool derives the
verifier from the vault password and compares them. There is **no login attempt,
no failed-login counter and no lockout risk**, and it works on locked and expired
accounts too. Those are still reported as `LOCKED` or `EXPIRED`, because the
status is the more urgent fact, with what the comparison found beside it. So an
operator can tell whether unlocking would be enough.

The client can reproduce the `T:` verifier, which is what makes this method
possible (`docs/README.md`, register entry `t-verifier`). A rollover window's two
verifiers, `T:` for the previous password and `t:` for the current one, are told
apart the same way, so hash mode reports `ROLLOVER_ACTIVE` instead of drift. It
has been confirmed on the releases in `docs/measurements.md`, including
19.32.0.0.0, a release update and so the release an OCI estate runs. 12.1 is
unmeasured. If the derivation turned out wrong there, the method would be removed
from the CLI.

An account with no `12C` verifier (11g, or any account whose `PASSWORD_VERSIONS`
lacks it) has nothing to compare. So an explicit `--method hash` or
`--method both` fails at plan time, naming the capability and the target
(invariant 4). It does not fall back to a weaker verifier, or silently to
`login`. The pre-flight checks every value the run will compare, including the
previous one under `--include-previous`, because the character-set refusal
depends on the value.

**`--method both` compares first** (decided in #437). A mismatch is reported as
drift from the comparison alone, and no login is attempted, because spending
lockout budget on a value already shown to be wrong gains nothing. Only a value
that matches goes on to the ordinary guarded login. The row says which half
answered.

**On Autonomous Database, the refusal says so in its own words** (decided in
#437). No account there can read `SYS.USER$`, `ADMIN` included. So the usual
advice to grant it would be advice nobody can follow. The capability probe gets
`ORA-00942` in both cases and cannot tell them apart. So the refusal reads
`SYS_CONTEXT('USERENV','CLOUD_SERVICE')`. It is `OLTP` on ADB serverless
23.26.3.3.0, NULL on 26ai Free 23.26.2.0.0, 21.3.0.0.0 and 18.4.0.0.0, and
`ORA-02003` on 11.2.0.2.0.

Trade-offs:

- It needs the same optional `SELECT ON SYS.USER$` grant as the `LCOUNT` guard
  (`02-oracle-privileges.md` §2), which some sites will not grant. With no
  `--method`, the default is `login`, and nothing is lost. An *explicit*
  `--method hash` or `--method both` against a target without the grant or the
  `12C` verifier fails at plan time, instead of silently becoming `login`. A
  narrower grant might expose just enough (unverified: lcount-grant).
- It confirms the *stored verifier*, not that a login would succeed. An expired
  password, a locked account or a failed listener still means the application
  cannot connect. `--method both` gives the strongest answer. Lock and expiry
  status are reported whatever the method (mitigation 6).
- It must handle several verifiers (10G, 11G, 12C) and pick the right one.

### Output

The sample below is from tier 1. `acme_app_user`'s password was changed by hand
after `apply`, and `acme_batch_user`'s profile opened a rollover window:

```
$ sopuli --config sopuli.yaml creds check
Plan: 2 accounts x 1 target = 2 checks   [dev]

ACCOUNT          TARGET    INTENT  SECRET
acme_app_user    free-pdb  verify  vault-dev:acme/dev/acme
acme_batch_user  free-pdb  verify  vault-dev:acme/dev/acme

shared secrets (1 document):
SECRET                   TARGETS   ACCOUNTS
vault-dev:acme/dev/acme  free-pdb  acme_app_user, acme_batch_user

ACCOUNT          TARGET    STATE            DETAIL
acme_app_user    free-pdb  DRIFT            vault v2 the database rejected this password (ORA-01017): ORA-01017: invalid credential or not authorized; logon denied
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  vault v2 accepted, but a rollover window is open: the previous password still works too

1 drift
```

It exits 3. Exit 3 for drift is what makes `check` useful on a schedule: a
monitoring system can alert on 3, separately from "the tool failed".

**An unreachable target is exit 1, never exit 3.** A broken check must not page
whoever watches for drift. So `ERROR` outranks `DRIFT` when the run's exit code
is decided. A run that reached nine targets and could not reach the tenth found
drift on only nine targets, and exit 3 would claim the survey was complete.
`LOCKED`, `EXPIRED`, `ACCOUNT_MISSING` and `UNVERIFIABLE` exit **0**. None of
them shows that a credential is wrong, and each is counted in the "unverifiable"
part of the closing line.

**A locked or expired account is never probed.** Mitigation 6 reads the status to
*report* those cases. A login attempt would spend a failed login to find out what
the status already said, which is the harm this section exists to prevent.
`sopuli/cli.py:_settled_by_status` is the refusal; `sopuli/check.py:decide` is
the reporting.

---

## 8. `sopuli creds rotate`

`generate`, `apply` and `check`, with their failure handling tied together.

```
sopuli creds rotate [--application acme]          # and the other selectors (§2)
                    [--strategy rollover|staged|direct]
                    [--max-age-days N]    # only rotate what is older than N
                    [--finish-rollover]   # end the window at the end of the run
                    [--confirm]           # proceed without asking
                    [--lockout-margin N]  # default 2; see §7
                    [--force]             # waive account guardrails 2 to 5
                    [--dry-run]
```

`--force` and `--lockout-margin` mean what they mean on `apply` (§5).

**`--max-age-days` reads the vault, never the database** (Q9, decided in #87).
`rotated_at` lives on the secret path, one value however many targets share it.
So there is nothing to combine, as N database timestamps would need, and no
"oldest, newest, or any" rule for an account that spans a CDB's PDBs. A target
the tool has not reached since the last rotation is selected by age exactly like
one it has reached. `status` shows that gap in its `DB_PW_CHANGED` column (§9);
it does not affect what `rotate` selects.

**A rotation narrower than its promotion is refused before anything is
staged** (decided in #406). This is §5's promotion gate, asked of `rotate` at the
start. A selector that leaves out another target of a credential being rotated,
or a sibling in the same document with its own `pending`, exits 8 and names the
pairs. `apply` narrowed the same way changes what it was pointed at and withholds
the promotion, because that is how a rollout is staged. A rotation narrowed that
way would draw a password, put it on part of the estate, and stop at case 7 on
every run. To rotate part of an estate at a time, run `creds generate`, then
`creds apply` per target, then a final `apply` to promote.

**A rotation over a staged `pending` is refused before the pre-flight**
(decided in #769). Where an account being rotated already has a `pending`, the
run exits 8, names the accounts, and points to `creds apply`. The reason is
§4's: some run may be putting that password on a database now, and step 4 would
draw over it. `rotate` has no flag to go ahead; `creds generate
--overwrite-pending` discards the `pending` for an operator who means to. The
check reads the documents under the lock. Only a run that took the lock over can
stage between that read and step 4's write. The fence check before the write
stops this run if the takeover came first. If it came between the fence check
and the write, the write reads the document first, finds the `pending`, and
fails that document with a message that points to `apply`. If it came after
that read, the write's compare-and-set fails. In the last two cases the run
exits 1, and nothing is applied to any database.

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
                                 lock renewed at each boundary
                                 and at half the TTL)
 6. verify each target        ── login or hash with the new password
 7. promote                   ── vault: previous = current, current = pending
                                                              (fence checked)
 8. post-verify               ── read back from vault, verify once more
 9. release every lock, emit audit record
```

Step 3 makes the common failures (wrong privileges, closed PDB, unreachable host)
happen *before* anything is written anywhere. `creds apply` offers the same
survey as `--preflight` (§5).

**Step 2 and the fence** (Q2, decided in #83). Locks live in the vault, one per
**secret path**, not per account and not per target. Every target in a run
receives the same value, and two accounts may share one document. A run that
touches several paths takes them all before the first change, in sorted order,
and never waits. If it cannot take them all, it releases what it took and exits 7
having applied nothing. So a deadlock cannot happen.

The fence is the vault version that the acquiring write returned. The run reads
it again before every change: each vault write and each `ALTER USER`. That makes
step 5 safe to resume after a stall. If this run's lock expired and another run
took it over, the check fails and the run aborts before it touches its remaining
targets, instead of applying a password the vault no longer advertises. Step 9
releases the lock in a `finally`, on every path including failure, and writes a
`released` record instead of deleting one.

### How the fence is checked

`creds apply`, `creds generate` and `creds rotate` read the fence again before
each change. These rules apply:

**It is checked per document, not per run.** Before an `ALTER USER`, the lock
that must still belong to this run is *that account's* document lock, the one
the change is made under. Checking every lock the run holds would mean a store
read per lock before every statement. On an estate of twenty documents, that is
four hundred reads to establish twenty facts, nineteen of which nothing was
about to act on. `LockManager.check()` with no arguments still checks every lock,
which a renewal needs, because a renewal writes to all of them.

**The renewal is the boundary check.** The lease is extended between one target
and the next. A renewal is itself a write, so it goes behind the fence like every
other write. So the boundary catches a takeover *before* the next target's first
statement, not after it.

**Inside a target the lease is renewed by the fence check** (#864). One target
with many accounts, or a slow one, can outlast the TTL, and a lock that expires
mid-target can be taken over by a run with `locking.break_expired`. The fence
check before each fenced statement renews when a lock it checks expires within
half a TTL: each `ALTER USER`, the window that closes a rollover, and the
promotion write. It then renews every held lock that is due, not only that
document's, because a document untouched for the rest of a long target is still
promoted at the end. So a check reads only its own document, except at a
renewal, which comes at most once per half TTL. An ordinary target finishes well
inside half a TTL, so it costs no write beyond the boundary renewal. The renewal
happens at a check, not on a timer, so one statement that hangs for longer than
the TTL is not covered.

**The check and the write are two requests**, and the tool accepts the window
between them (decided in [#769](../decisions/log.md#769)). Vault has no
compare-and-set across two paths, so a fence check on the lock and a write to the
secret cannot be one operation. A takeover can land after the check and before
the write. A renewal writes the lock itself, with a compare-and-set on its fence,
so a takeover makes that write fail. Its one window is between locks: with
several locks held, lock 1 can be rewritten before the renewal finds lock *n*
taken.

For a staging write, this is what follows. The stale run's write lands, so
`pending` holds a new random password that nobody has. The stale run's next
fence check fails before its `ALTER USER`, so it changes no database, and it
promotes nothing. The next `apply` applies that `pending` and promotes it.

If the run that took over is a `rotate` and the stale write lands before that
run reads the document, the new run refuses over the `pending` (§8). If it lands
between that run's read and its own staging write, the staging write fails its
compare-and-set: exit 1, and the row is `ERROR` with `category: vault`.

```
compare-and-set failed at 'acme/dev/acme': check-and-set parameter did not match the current version
```

It applied nothing. The message names a conflict, not the takeover. Running it
again refuses over the stale run's `pending`, and `apply` applies and promotes
that `pending`. `tests/test_fault_lock.py` produces these cases.

**A lock error is never a finding for one target.** Anything else that goes wrong
with one account becomes a row in the table, and the run carries on. Here that
would be wrong: it would turn "somebody else owns this estate now" into a
footnote and apply to the next account anyway. `LockError` is raised past the
per-account handler, and the run ends.

The account the run was working on still gets a row if the run had already
changed it. Two checks come after a change to the same account:

- the check before `--strategy direct` closes the rollover window. The password
  is set and the window stays open. The row is `ROLLOVER_ACTIVE` with
  `changed: true`, and its detail says the run lost its lock before it closed
  the window.
- the check before `ALTER USER`, after the attribute pass unlocked the account
  or changed its profile. The row is `ERROR`, its attribute actions show what
  was done, and its detail says the password was not set.

Without the row, the change would be in no run document, and neither would its
`SOPULI-W031` or `SOPULI-W032`.

**Nothing is promoted after a takeover**, including documents whose own locks are
still held. The fence would catch the write, but that is not the reason. A
promotion asserts that every target holds this password, and a run stopped part
way through cannot assert that.

**The exit code depends on what had been applied.** `sopuli/lock/errors.py`
leaves this split to the command. The run exits **7** where it was fenced out
before it changed anything, and **4** where it had already changed something.
Exit 7 after nine targets would tell a scheduler that nothing happened, when
something did.

Exit 4 alone is ambiguous: a run whose targets failed also exits 4, and that one
*is* repaired by running `apply` again. So a fenced-out run carries the
diagnostic `SOPULI-W011`, and its text says what stopped it **instead of** the
`repair with:` line (§5). The tool must not advise a re-run while somebody else
holds this estate's lock.

`check` and `status` take no lock, and neither does any `--dry-run`. An hourly
scheduled check that blocked rotations would be a worse problem than the one the
lock solves.

**The record.** There is one record per secret path, written under a `locks/`
prefix on the same mount as the secret: `secret/data/locks/<path>` on KV v2. So
the secret's own version history stays clean for `previous` and rollback.

The pre-flight checks `cas_required` on the lock path instead of assuming it.
That setting stops a *different* writer, such as an operator with a vault CLI,
from replacing the record without a compare-and-set. The tool cannot claim a
guarantee it has not checked.

**On a path with no metadata at all, the pre-flight sets it.** That is the normal
state before the first lock. Setting it first is safe: configuring a path creates
no version, so the `cas: 0` write that a first acquisition makes still succeeds
(measured on Vault 2.0.4). Two runs of this tool racing for a new lock always had
exactly one winner, because a `cas: 0` write succeeds only on a path with no
history. The setting makes the **store** enforce the same rule on every other
writer.

Where the store refuses the setting, the run goes ahead and reports
`SOPULI-W019`. Vault grants metadata writes as a capability separate from data
writes, so an ordinary policy refuses this one call. Stopping would break an
install over a guarantee it never had. The run says that the path is unguarded,
and names the remedy. The next run then meets the exit-5 refusal below. That is
correct, because by then somebody has been told.

**Both pre-flight refusals are exit 5, not exit 7.** Neither is a held lock. One
is a store with no compare-and-set that nobody marked `locking: advisory-only`.
The other is a path that does not require compare-and-set. Both are decided
before any lock record is read or written. Exit 7 means "another process holds
the lock", a condition that clears. These do not clear, so an unattended runner
would retry forever. `sopuli lock break` answers 5 for the same fact, through
`check_fenceable`. The second refusal is 5, not 9, because *this tool's*
configuration is fine. The remedy is a vault command.

`max_versions: 10` is recommended and **not** enforced. Pruning old versions does
not reset the version counter, so fencing works with any value. Refusing a
working vault over a housekeeping preference would cost something and protect
nothing.

The lock record looks like this:

```json
{ "state": "held",
  "correlation_id": "01J…",
  "holder": { "host": "ci-runner-3", "pid": 8821, "os_user": "svc_sopuli" },
  "command": "creds rotate",
  "acquired_at": "…", "expires_at": "…",
  "selection": "env=prod" }
```

Nothing in it is a secret value: an account, a selection and a process. So it is
safe to print at exit 7. The default TTL is 15 minutes, renewed at each target
boundary, and at the next fence check once half of it has gone. A lock counts as
expired only after `expires_at` plus a 60-second clock-skew margin.
`acquired_at` does not move on renewal. It answers "how long has this been
going on", which is what somebody reading exit 7 wants to know.

These rules apply to reading and writing it. Each takes the safe side of a choice
that could have gone the other way:

- **Release writes; it never deletes.** A KV v2 delete leaves the metadata
  behind. After that, a first acquisition can never compare-and-set against
  version 0 again, and that increasing version *is* the fence.
- **Anything not `released` is held**, including a state this version does not
  know. Guessing that an unknown record is free could end with two runs rotating
  one credential.
- **A field this version does not know is kept**, because renewal rewrites the
  whole payload. Otherwise a record written by a newer sopuli would lose fields.

`sopuli/lock/` holds the keying, the record and the acquire, take-over or refuse
decision as pure logic.

**To read a lock without holding it**, use `sopuli lock status`. It surveys the
declared set of secret paths for records, and reports each holder the way exit 7
does. It takes no lock, because it is a `status` verb and the rule above applies
to it. So an hourly survey never blocks a rotation.

**To take a lock back**, use `sopuli lock break <vault>:<path>`. It is a
different command from the one that reads, on purpose:

```
$ sopuli lock break vault-prod:apps/acme/appdb-beta --confirm

LOCK                             STATE    HOLDER                  COMMAND       SINCE                 EXPIRES
vault-prod:apps/acme/appdb-beta  expired  svc_sopuli@ci-runner-3  creds rotate  2026-08-16T12:00:00Z  2026-08-16T12:15:00Z

broke this lock at version 41; svc_sopuli@ci-runner-3 pid 8821 running creds rotate is fenced at version 42 and stops at its next check
```

The argument is spelled the way exit 7 and `lock status` print it, so the command
in a refusal can be pasted. It writes a `released` record over the held one, with
`cas` set to the version it read. It never deletes, for the reason above. The
version bump is the fence: the run it was taken from stops at its next check,
instead of applying a password the vault no longer advertises. That is what
makes breaking a lock safe. So a store that cannot fence is refused with exit 5.
So is a store declared `locking: advisory-only`, whatever the mount supports;
`locking.break_expired` is refused in the same combination.

It needs confirmation. A lock that has **not** expired also needs `--force`.
Refusing one is exit 7, naming the holder: when a colleague is mid-rotation, the
usual answer is to talk to them. `--dry-run` prints the plan and writes nothing.
`safety.readonly` refuses the verb outright, with exit 8. A path with no record,
or one already released, exits 0 having changed nothing, so running it twice is
safe.

It will clear a record at a path the config no longer declares. `lock status`
reports such leftovers, and nothing else can clear them. That does not break
invariant 5: the write lands under the store's `locks/` prefix, in a store that
`vaults:` declares, and never touches the secret the lock guards.

**Failure at each step**

| Fails at | State afterwards | Recovery |
|---|---|---|
| 1–3 | nothing changed | fix and run again |
| 4 | nothing changed in the database; `pending` may exist | `apply` where a `pending` was staged, which applies and promotes it; otherwise run `rotate` again. A staging write that passed its fence can land after a takeover. Its `pending` holds a password that nobody has, and the next `apply` applies and promotes it (*How the fence is checked*) |
| 5 (some targets) | those targets have the new password, vault `current` is still old | `apply --repair` with the run's document, then `apply` to promote (§5, *A repair of a rotation*); with the rollover strategy there is no outage meanwhile |
| 6 | database changed but verification failed | report loudly, no promotion; `check --include-previous` tells "wrong password" from "account locked/expired" |
| 7 | database has new, vault `current` still old | **the most severe case**: exit 4 with `SOPULI-W033`, which names the document, its accounts and the store's message, and each row carries the failed `vault_promote`. `pending` still holds the right value, so `sopuli creds apply` completes it. It verifies every target again and promotes. `rotate` does not retry the promotion: a compare-and-set conflict means a writer outside the tool, and reading again to merge over it would rewrite fields of accounts nobody selected |
| 8 | promoted, and the read-back disagreed or failed | the databases are converged, and the run cannot confirm that the vault serves what it accepted. Exit 4 with `SOPULI-W012`, which names the accounts, and the store's message for a document it could not read. Nothing needs undoing; the place to look is the vault, not any database: a replica behind its primary, or a store that stopped answering |
| any fence check, at 4–7 | another run took this run's lock; what this run already applied stands | abort at once, change nothing more, exit **7** if nothing had been applied and **4** if something had, with `SOPULI-W011`. `check` establishes what is true; the run that holds the lock is the one that may fix it. A write that passed its fence check before the takeover still lands, so `pending` can hold this run's password |

### How `rotate` is built

These rules are not visible in the sequence above.

**It is not a wrapper around the other verbs, because of the lock.** Each of
`generate`, `apply` and `check` takes and releases its own lock. Between a
`generate` that released and an `apply` that has not yet acquired, another run
could stage a different `pending`. This run would then apply and promote a
password it never generated. One acquisition covers steps 2 to 9.

**The pre-flight is always on here, and opt-in on `apply`.** §5 explains why it
is off by default there: a repair of one target should not pay for a survey of
twenty. A rotation is the opposite case. It also checks a *larger* set. `apply`
surveys the accounts it has something to apply to. `rotate` surveys everything it
is about to rotate, because at step 3 there is no `pending` anywhere, and a first
rotation has no `current` either. Filtering on what the vault already holds would
skip the whole estate on the run whose pre-flight matters most.

**A staging failure stops the run before any database is touched.** Row 4 says
nothing changed in the database. A rotation that staged two documents, failed on
a third, and applied the two anyway would make that row untrue. It exits 1, not
4: 4 means some targets succeeded and some failed, and here no target was tried.

**Step 8 is a second read, not a comparison with what was written.** The check
looks for a store that acknowledged a write and then served something else, which
is what a read replica behind its primary does. Only reading the object back can
find that. Only documents this run promoted are read back. A document nobody
staged into was never written, and one whose targets did not all confirm was
left alone on purpose, and one whose promotion failed is row 7, not row 8. A
document that no longer holds the stage counts as a disagreement: "the vault has
not got it" and "the vault has the wrong one" are the same fact to the
application about to fetch it. A read-back that fails counts as one too, because
the run cannot say what the vault serves. The run still reports every row, and
`SOPULI-W012` carries the store's message.

**`--max-age-days` selects nothing whose age is unknown.** That is
`creds status`'s rule (Q9), and it decides what the tool does the first night it
runs against an existing estate. A newly adopted vault has no `rotated_at`
anywhere. Treating unknown as infinitely old would make the first scheduled run
rotate every credential. An operator who wants that leaves the flag off.

**The takeover split has one more case than `apply`'s.** The rule is 7 where the
run was fenced out before it changed anything, and 4 where it had already changed
something. `rotate` writes to the vault before it reaches a database. So a staged
`pending` is a change that exists before any DDL. A run fenced out between two
step-4 writes exits **4**, not 7, because 7 asserts that nothing happened, and a
`pending` that somebody has to clean up is something.

**`--finish-rollover` closes a window only where the vault serves the new
password.** Closing a window removes the old password from the database. An
account is left open where its target failed, where its document's promotion was
withheld or failed (row 7), or where step 8 could not confirm the promotion
(row 8). In each case `current` may still hold the old password, and
applications that fetch it would be locked out. A document that owed no
promotion, because the vault already held what was applied, is closed as usual.
The run names each account and target it left open, in a note and as a warning
diagnostic. `creds finish-rollover` closes them once `current` holds the new
password. Where the promotion did not happen, `creds apply` promotes it first.

**The fence also covers `--finish-rollover`.** Closing windows is the run's last
change and the furthest from the acquisition at step 2, so it is the most likely
to happen after a lease has gone. It also cannot be undone: a window nobody
closed ends on its own, but one closed by a run that had lost the estate cannot
be reopened. So the closing path reads the fence again before each statement
where the caller holds a lock, and lets a `LockError` past its per-account
handler. **The standalone `creds finish-rollover` still takes no lock.** It
writes to no store, and an hourly job that blocked rotations would be a worse
problem than the one the lock solves. So the lock manager is an argument the
caller passes, not something the verb acquires.

**Step 9's audit record is the run document.** `--output json` is the record a
scheduler keeps. The event stream is `--output jsonl`. `password.applied` and
`vault.promote` are the events that tell the most when a stream stops. `rotate`
emits its staging events, one per secret and not per target, before the first
target, in this section's order (`03-json-output.md` §5).

**Confirmation, and what it is not.** §8 step 1 is "plan + confirm". So `rotate`
prints the plan to stderr and asks. `--confirm` answers in advance. An unattended
run without it is refused with exit 8, instead of being left to abort at end of
input. `apply` has no prompt of its own like this one, for a real reason: it converges an estate on a value
somebody already staged and reviewed. `rotate` invents the value and replaces
what every application is using, across the whole selection, in one run. The
estate-wide `safety.confirm_environments` setting is a *different* gate, and
`rotate` does not ask it as well. This prompt is unconditional, so the setting
could only make it weaker.

**Rollback.** `previous` is kept so that
`sopuli creds apply --source previous --confirm` can put the old password back on
the database. This is a real operation: it is the way back when an application
turns out to have the old password hard-coded somewhere. Rollback goes back only
one generation, and only while the vault still holds `previous` (Q3, decided in
#84). OCI holds exactly one `PREVIOUS`, and the stage vocabulary in
`01-configuration.md` §7 (`current`, `pending`, `previous`) has no name for an
older generation. Recovery further back means reading the store's own version
history, which not every backend has. Not every profile allows a rollback
either. A profile that restricts password reuse is likely to refuse `previous`
with `ORA-28007`. There the way back is a rollover window opened by the rotation
itself (§5).

---

## 9. `sopuli creds status`

A read-only inventory. It makes no login attempts, so it is safe to run anywhere.

The sample below is from tier 1. `acme_batch_user`'s `rotated_at` in the vault
was set back to 2026-07-01, and both passwords were changed on the database
today:

```
$ sopuli --config sopuli.yaml creds status --max-age-days 90
Plan: 2 accounts x 1 target = 2 accounts   [dev]

ACCOUNT          TARGET    INTENT  SECRET
acme_app_user    free-pdb  none    vault-dev:acme/dev/acme
acme_batch_user  free-pdb  none    vault-dev:acme/dev/acme

shared secrets (1 document):
SECRET                   TARGETS   ACCOUNTS
vault-dev:acme/dev/acme  free-pdb  acme_app_user, acme_batch_user

ACCOUNT          TARGET    STATE            VAULT_V  AGE    DB_PW_CHANGED  PROFILE          ROLLOVER
acme_app_user    free-pdb  UNVERIFIABLE     4        0d     2026-10-06     DEFAULT          not configured
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  4        97d !  2026-10-06     SOPULI_ROLLOVER  window open

2 accounts: 1 past max age
```

**`AGE` is `rotated_at`, from the vault, and `--max-age-days` filters on it**
(Q9, decided in #87). The `!` marks an age past the limit. `DB_PW_CHANGED` is
read from the database for display only. It never decides a rotation. In the
sample, both accounts' passwords changed on the database today, but only
`acme_batch_user` is past the limit, because only the vault's clock is acted on.
A difference between `AGE` and `DB_PW_CHANGED` is a sign of drift that costs no
login attempt.

These rules apply to `status`:

**A healthy row reports `UNVERIFIABLE`, not `IN_SYNC`.** An inventory cannot
answer the question `check` exists for, *does the vault's password actually
work*. So it says it did not ask. `IN_SYNC` from a command that never tried would
be agreement nobody measured, and a document could not tell it apart from one
that `check` produced by spending a login.

**What it *can* say without asking** is the rest of the state model: an account
the config declares and the database does not have, an account that is locked or
expired, a rotation that was staged and never applied (`PENDING_APPLY`, visible
in the vault alone), and an open rollover window.

**An unknown age is not an old one.** A credential this tool has never rotated
has no `rotated_at`, and `--max-age-days` does not select it. Treating unknown as
infinitely old would make the tool's first act on a newly adopted estate a
proposal to rotate all of it. Somebody running an inventory on a new estate
wants the opposite.

**A target it cannot reach is exit 1**, as for `check`, and for the same reason:
a survey with a gap must not look complete. The vault half of those rows is still
filled in. The version and the age come from a document read before any database
was dialled, and dropping them because a listener was down would report less
than the run knows.

In the run document, `password_age_days` means what it means everywhere else:
the **database's** age, from `PASSWORD_CHANGE_DATE`. The vault's age is a
`warning` that names its source, so that one field name never holds two clocks.

### Where `DB_PW_CHANGED` comes from without `PASSWORD_CHANGE_DATE` (decided in #386)

Reasons and rejected options: [#386](../decisions/log.md#386).

`DBA_USERS.PASSWORD_CHANGE_DATE` does not exist on every supported release. It
is present on 26ai Free 23.26.2.0.0, 21.3.0.0.0 and 19.24.0.0.0, and absent
(`ORA-00904`) on 18.4.0.0.0, 12.2.0.1.0 and 11.2.0.2.0 (`docs/measurements.md`).
On 19.24.0.0.0 only the column's presence was checked. Where it is absent and no
fallback answers, the column reads `-` and the run document omits
`password_age_days`.

- **The tool falls back to `SYS.USER$.PTIME` where the optional grant exists.**
  `PTIME` moves on `ALTER USER … IDENTIFIED BY`, and equals the column to the
  second where both exist. `CTIME` beside it does not move. So it is the same
  clock, not an approximation. It needs no new privilege: it is the grant that
  `02-oracle-privileges.md` §2 already offers for the `LCOUNT` guard, behind the
  same `offline_verify` probe. **One source per release**: the column's presence
  selects it, so `PTIME` is never read where the column exists, not even to fill
  a `NULL`. A tier-1 test checks that the two are equal on every release that has
  both.
- **The tool says why when neither answers.** `SOPULI-W021` goes on each
  affected `results[].warnings[]`, beside the missing field, with the driver's
  reason: no such column and no grant (the grant fixes it), or a value that could
  not be read (worth investigating). `creds status` prints the same reason once
  per target under the table.
- **It is not a capability.** The query is its own probe: `ORA-00904` *is* the
  answer. Adding to P1's list would have changed the driver protocol, `doctor`,
  the schema and the skip vocabulary to report a display column.

12.2.0.1.0 takes the fallback, and `PTIME` tracked a rotation there. 12.1 would
take the fallback too, and is unmeasured (unverified: pw-changed-source). See
`docs/README.md`, "Verify before implementing".

---

## 10. Scenarios

**S1: first adoption of an existing account.** The account exists, people know
its password, and the vault does not have it. Run `generate --promote`, then
`apply`, then `check`. The tool never needs the old password.

**S2: scheduled 90-day rotation, no downtime.** A nightly `check` in hash mode,
alerting on exit 3. A weekly `rotate --max-age-days 90 --strategy rollover`. The
application refreshes its credentials within the rollover window, and a later
job runs `finish-rollover` once the window has passed.

**S3: one PDB was down during the last rotation.** The other targets took the
new password, and the promotion was withheld (invariant 7). `current` still
holds the old password, and `pending` the new one. Once the PDB is back, run
`apply` without a target selector. It applies `pending` where a target does not
hold it, confirms every target, and only then promotes. It changes nothing on the
targets that are already correct. `apply --target cdb1-pdb-billing` alone changes
that PDB but still withholds the promotion (`SOPULI-W027`), because a narrowed
run cannot confirm the targets it left out.

**S4: emergency rotation after a leak.**
`rotate --strategy direct --finish-rollover`. There is no grace window, the old
password stops working at once, and application errors are the price. The audit
record says who and when.

**S5: common user across a CDB.** One application entry, one secret, target
`cdb1-root`, `container_clause: ALL`. One statement covers every PDB.

**S6: the vault write succeeds and the database is unreachable.** `pending`
exists, nothing is applied, `current` is unchanged, and applications are not
affected. While the database is unreachable, `check` reports `ERROR` and exits 1.
Once it is back, `check` finds no drift, because the database still holds
`current`, and `creds status` shows the staged `pending`. Finish with `apply`,
which applies the staged `pending`, confirms it and promotes. Running `rotate`
again does not resume: it refuses on exit 8, names the account, and points to
`apply` (§8).

**S7: the application still holds the old password after the window closed.**
Logins start failing. `check --include-previous` shows that the old password is
no longer accepted, which points at the application, not the tool.

---

## 11. Testing this

The failure modes are about ordering and partial failure, so most of the test
matrix is fault injection. Environments, tiers and the capability-driven matrix
are in [`../design/04-testing.md`](../design/04-testing.md). This is the UC-1
list.

- **Matrix:** Oracle 11.2.0.2.0 non-CDB, 18.4.0.0.0 and 21.3.0.0.0 XE, and 26ai
  Free 23.26.2.0.0 CDB+PDB, plus the maintainer-only 19.3.0.0.0, 12.2.0.1.0 and
  19.32.0.0.0 (`docs/maintainer-environments.md`), against HashiCorp KV v2 and
  KV v1. `docs/measurements.md` says which releases
  have rollover. The buildable 19.3.0.0.0 image has none.
- **Fault injection at every step of §8:** kill the process between apply and
  promote; make the vault unreachable mid-run; serve a stale read after the
  promotion; close a PDB mid-run; revoke `ALTER USER` mid-run; run two
  rotations at once; take a lock over mid-run. These are built (`04-testing.md`
  §5).
- **Charset fuzzing:** generated passwords through every path an operator uses.
  `tests/test_password_paths.py` covers a shell, a `.env` file, a connect
  string and a JDBC URL, and logs in through the connect string and the JDBC
  URL. Never a PL/SQL literal: invariant 13 keeps the password out of
  every PL/SQL block. The results are in
  [`01-configuration.md` §8](../design/01-configuration.md#8-password-charsets).
- **Lockout regression test:** run `check` against a deliberately drifted
  account N times with `FAILED_LOGIN_ATTEMPTS 3`, and assert the account never
  locks.
- **Verify-function test:** a profile with `ora12c_strong_verify_function` and a
  policy that breaks it. Assert bounded regeneration and a clear final error.
- **Idempotency test:** every convergent command run twice. The second run
  reports `changed: false` and emits no mutation audit record (invariant 9).
- **Concurrency test:** two `rotate` runs on the same account. One must lose on
  the lock with exit 7, and the final state must be consistent. Locks are keyed
  on the path, and two runs on one account resolve to one path, so they contend.
- **Fencing test:** take a lock over mid-run, by expiring it and letting a second
  run take it, and assert that the first run aborts before its next
  `ALTER USER`. A session-scoped `DBMS_LOCK` would not catch this case, because a
  stalled session is still alive and still holds its lock.
- **Redaction test:** run everything, and search all output, logs and trace for
  the generated password. Zero hits is a release gate.

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

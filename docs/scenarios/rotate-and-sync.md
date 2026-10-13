# Scenario: rotate a password from start to finish

One application, one Oracle database, one password. This document follows it all
the way: draw a new password, put it on the database, confirm it works, and close
the window where the old password still worked.

It picks up where [getting-started.md](../getting-started.md) stops. If you have
not written a config file yet, start there.

Every command and every block of output below is from one continuous session
against the project's own test containers on 2026-09-07, sopuli 0.58.0. The
account is `acme_app_user` in `FREEPDB1`, and `acme` is a fictional application
name this project uses throughout its documentation.

---

## The config this uses

Two applications, because the second half of this document needs an account with
a different password policy. Save it as `sopuli.yaml`, outside the repository.

```yaml
version: 1

vaults:
  vault-dev:
    type: hashicorp
    addr: http://127.0.0.1:8200
    mount: kv
    kv_version: 2
    auth: { method: token }

defaults:
  vault: vault-dev

targets:
  - name: free-pdb
    type: oracle
    environment: dev
    dsn: "127.0.0.1:1521/FREEPDB1"
    admin: { username: SYSTEM, auth: { method: env } }
    oracle: { scope: pdb, container: FREEPDB1 }

policies:
  app-standard:
    password:
      length: 24
      charset: alnum_safe
      first_char: alpha
      require: { upper: 1, lower: 1, digit: 1, special: 1 }

  # The same password rules, plus one account attribute: put the account on a
  # profile that grants a rollover window. Section 6 is what that is for.
  rollover-capable:
    password:
      length: 24
      charset: alnum_safe
      first_char: alpha
      require: { upper: 1, lower: 1, digit: 1, special: 1 }
    account:
      profile: SOPULI_ROLLOVER

applications:
  - name: acme
    accounts: [acme_app_user]
    secret_template: "vault-dev:acme/{env}/{application}#DB_CREDENTIALS/{account}"
    policy: app-standard

  - name: acme-batch
    accounts: [acme_batch_user]
    secret_template: "vault-dev:acme/{env}/batch#DB_CREDENTIALS/{account}"
    policy: rollover-capable
```

Set the two credentials the run needs. Neither is ever written in the file, and
neither is ever a command-line option:

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=sopuli-test-root
export SOPULI_DB_ADMIN_PASSWORD=sopuli-test
```

---

## 1. Look before you touch anything

`creds status` is the safest command in the tool. It reads the vault and reads
Oracle's data dictionary, and it attempts no login at all — so it cannot lock
anything out, and it is the right first command every time.

```bash
sopuli --config sopuli.yaml creds status
```
```
Plan: 2 accounts x 1 target = 2 accounts   [dev]

ACCOUNT          TARGET    INTENT  SECRET
acme_app_user    free-pdb  none    vault-dev:acme/dev/acme
acme_batch_user  free-pdb  none    vault-dev:acme/dev/batch

ACCOUNT          TARGET    STATE         VAULT_V  AGE  DB_PW_CHANGED  PROFILE  ROLLOVER
acme_app_user    free-pdb  UNVERIFIABLE  -        -    2026-09-07     DEFAULT  not configured
acme_batch_user  free-pdb  UNVERIFIABLE  -        -    2026-09-07     DEFAULT  not configured

2 accounts, nothing to act on
```

Read that as three blocks, and every command in this document prints the same
three:

- **The plan.** How much this run would touch — the *blast radius*. Two accounts
  on one database, both in the `dev` environment.
- **The intent table.** What would be done to each row. `none` here, because
  `status` changes nothing by definition.
- **The result table.** What was found.

`UNVERIFIABLE` with `VAULT_V -` is the empty state: there is no document in the
vault for this account at all, so there is nothing to compare the database with.
`DB_PW_CHANGED` is populated anyway, because it comes from the dictionary — the
database has a password, the vault has never heard of it, and nothing has been
compared.

---

## 2. Stage a new password, without touching the database

`creds generate` draws a password from the policy and writes it into the vault as
`pending`. Applications read `current`, which does not change, so nothing is
disturbed.

Preview it first:

```bash
sopuli --config sopuli.yaml creds generate --application acme --dry-run
```
```
Plan: 1 account x 1 target = 1 generation   [dev]

ACCOUNT        TARGET    INTENT                         SECRET
acme_app_user  free-pdb  generate, vault_write_pending  vault-dev:acme/dev/acme

constraints: 128 bytes in AL32UTF8, from free-pdb

SECRET                   STAGE    ACCOUNTS
vault-dev:acme/dev/acme  pending  acme_app_user

nothing was written (--dry-run)
```

The `constraints:` line is the one surprise in this command. `generate` **does**
connect — it asks each selected database how long a password may be in that
database's own character set, and the strictest answer governs the draw. It reads
and never writes. `--offline` declines to ask, and the policy's declared length is
used instead, which is what you want when staging against an estate that is
deliberately down.

Drop the flag:

```bash
sopuli --config sopuli.yaml creds generate --application acme
```
```
ACCOUNT        SECRET                   RESULT
acme_app_user  vault-dev:acme/dev/acme  staged v1

1 staged; no database was changed -- run `sopuli creds apply` to use them
```

**Running this twice stages a second password and says so.** A command that
*converges* on something reports "nothing changed" on a second run — `apply` and
`check` both do. This one cannot: drawing a fresh random secret has no earlier
state to converge on, so the second run replaces the `pending` and tells you it
did (`staged v2, replaced the pending in v1`). Nothing is lost — `current` is
untouched either way.

To supply a password rather than draw one, pipe it in. There is no option that
takes a password as its value, anywhere in this tool:

```bash
printf 'YourPasswordHere' | sopuli --config sopuli.yaml creds generate --from-stdin
```

---

## 3. Put it on the database

`creds apply` takes the vault's password and makes the database hold it. The
order it does that in is the entire safety design of this tool, so it is worth
reading the output rather than skimming it.

```bash
sopuli --config sopuli.yaml creds apply --application acme
```
```
Plan: 1 account x 1 target = 1 apply   [dev]

ACCOUNT        TARGET    INTENT                               SECRET
acme_app_user  free-pdb  verify, password_set, vault_promote  vault-dev:acme/dev/acme

ACCOUNT        TARGET    SECRET                   SOURCE
acme_app_user  free-pdb  vault-dev:acme/dev/acme  pending

ACCOUNT        TARGET    STATE    DETAIL
acme_app_user  free-pdb  IN_SYNC  changed and verified by login

1 changed, 1 promoted to `current`
```

Two lines carry the whole design.

**`SOURCE pending`** — the password came from the `pending` field, the one section
2 staged. Applications are still reading `current`, which is still the old value.

**`1 promoted to current`** — and this happened *last*. The order was: set the
password on the database, log in with it to prove it works, and only then move
`pending` into `current` in the vault.

Why that order and not the other one? Both alternatives break the application:

- Vault first, then the database. If the database change fails, the vault now
  advertises a password the database does not have. Every application breaks at
  its next credential fetch.
- Database first, then the vault. If the vault write fails, nobody can obtain the
  new password — and the correct password now exists nowhere at all.

Staging into `pending` removes the window. The candidate is durably stored before
the database is touched, and the field applications read only moves after the
database has confirmed. A crash at any point leaves a state the tool can resume
from and `creds check` can explain.

The promotion also moves the old `current` into `previous`, which section 5 uses.

### Run it again

```bash
sopuli --config sopuli.yaml creds apply --application acme
```
```
ACCOUNT        TARGET    SECRET                   SOURCE
acme_app_user  free-pdb  vault-dev:acme/dev/acme  current

ACCOUNT        TARGET    STATE    DETAIL
acme_app_user  free-pdb  IN_SYNC  the vault's password is already accepted; nothing to change

nothing changed
```

`SOURCE` moved from `pending` to `current` by itself, because there is no longer
a pending to apply. Nothing was written. This is the property that makes the
command safe to run from a scheduler: a second run reports `nothing changed` and
writes no audit record.

---

## 4. Ask whether it is still true

`creds check` answers one question per account: does the vault's `current`
password work on this database?

```bash
sopuli --config sopuli.yaml creds check --application acme
```
```
ACCOUNT        TARGET    STATE    DETAIL
acme_app_user  free-pdb  IN_SYNC  vault v2 verified by login

all 1 in sync
```

Now change the password behind the tool's back, the way a colleague with SQL\*Plus
and a good reason would:

```sql
ALTER USER acme_app_user IDENTIFIED BY "Drifted#2026x";
```

```bash
sopuli --config sopuli.yaml creds check --application acme
```
```
ACCOUNT        TARGET    STATE  DETAIL
acme_app_user  free-pdb  DRIFT  vault v2 the database rejected this password (ORA-01017): ORA-01017: invalid credential or not authorized; logon denied

1 drift
```

**This exits 3, not 1.** Drift has its own exit code precisely so a scheduler can
tell "the estate has moved" apart from "the check itself failed", and alert on
them differently. The full list is in
[00-principles.md](../design/00-principles.md) P5.

`creds apply` converges it — vault to database, always, never the reverse:

```
ACCOUNT        TARGET    SECRET                   SOURCE
acme_app_user  free-pdb  vault-dev:acme/dev/acme  current

ACCOUNT        TARGET    STATE    DETAIL
acme_app_user  free-pdb  IN_SYNC  changed and verified by login

1 changed
```

Note `SOURCE current`: there was nothing staged, so the tool put back what the
vault already held. The database is what changed, and that direction is not
configurable.

### Two things `check` will not do to you

It attempts **one** login per account per run. No retries, no back-off loop, so a
wrong password costs exactly one failed login rather than five.

And where it has been granted `SELECT ON SYS.USER$`, it reads how many failed
logins the account has already collected before it tries. If one more attempt
would come too close to the profile's limit, it does not try:

```
ACCOUNT        TARGET    STATE         DETAIL
acme_app_user  free-pdb  UNVERIFIABLE  no login attempted: 2 of 3 failed logins are already
                                       recorded, and 1 more would leave less than the
                                       2-attempt margin

1 unverifiable
```

Exit 0, and no login was attempted. The margin is `--lockout-margin`, two
attempts by default. Checking is never worth locking out the account you were
checking on.

---

## 5. Rotate in one command, and roll back

`creds rotate` is sections 2 and 3 in one run, holding the lock throughout. That
is the point of it: run separately, the two halves leave a window where another
operator's run can interleave with yours.

```bash
sopuli --config sopuli.yaml creds rotate --application acme --confirm
```
```
Plan: 1 account x 1 target = 1 rotation   [dev]

ACCOUNT        TARGET    INTENT                                                              SECRET
acme_app_user  free-pdb  generate, vault_write_pending, verify, password_set, vault_promote  vault-dev:acme/dev/acme

ACCOUNT        TARGET    STATE    DETAIL
acme_app_user  free-pdb  IN_SYNC  changed and verified by login

1 changed, 1 promoted to `current`

rotation: staged 1 document, promoted 1 document
```

That `INTENT` column is the whole scenario in one row, in order: draw, stage,
verify, set, promote.

`rotate` always asks for confirmation, whatever your config says — the
`confirm_environments` setting can only ever make a gate stricter, and this one is
already unconditional. `--confirm` above is that yes, given in advance.

### Rolling back

The promotion in section 3 moved the old `current` into `previous` rather than
overwriting it. That is what makes this possible:

```bash
sopuli --config sopuli.yaml creds apply --application acme --source previous --confirm
```
```
ACCOUNT        TARGET    SECRET                   SOURCE
acme_app_user  free-pdb  vault-dev:acme/dev/acme  previous

ACCOUNT        TARGET    STATE    DETAIL
acme_app_user  free-pdb  IN_SYNC  changed and verified by login

1 rolled back, 1 promoted to `current`
```

Without `--confirm` it asks first, and answering anything but yes stops the run
with exit 8:

```
put the vault's `previous` password back on every selected target? [y/N]: sopuli: aborted
```

Exercise this at least once on a system you can afford to break. A rollback path
nobody has run is a rollback path you are trusting rather than relying on.

---

## 6. The rollover window, and why finishing it matters

Everything above has a gap in it. Between the moment `apply` changes the password
and the moment every application has been restarted with the new one, those
applications are using a password the database no longer accepts. On a system
with a dozen consumers, that gap is however long the slowest restart takes.

Oracle 19.12 and later can close that gap. **Gradual password rollover** lets the
*old* password keep working for a window after the new one is set, so applications
can pick up the new one at their own pace and nothing fails in the meantime.

The window comes from the account's **profile** — specifically
`PASSWORD_ROLLOVER_TIME` — and a policy can put the account on a profile that has
one. That is the `rollover-capable` policy in the config at the top of this
document.

```bash
sopuli --config sopuli.yaml creds generate --application acme-batch
sopuli --config sopuli.yaml creds apply --application acme-batch
```
```
Plan: 1 account x 1 target = 1 apply   [dev]

ACCOUNT          TARGET    INTENT                                              SECRET
acme_batch_user  free-pdb  attribute_set, verify, password_set, vault_promote  vault-dev:acme/dev/batch

ACCOUNT          TARGET    SECRET                    SOURCE
acme_batch_user  free-pdb  vault-dev:acme/dev/batch  pending

ACCOUNT          TARGET    STATE            DETAIL
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  changed and verified; a rollover window is open, so the previous password authenticates until it closes

1 changed, 1 promoted to `current`
```

`attribute_set` in the intent is the profile being assigned, before the password
is set. `ROLLOVER_ACTIVE` is not an error and not drift — it is the tool telling
you that two passwords currently work.

Both `status` and `check` report the window rather than mistaking it for drift:

```
ACCOUNT          TARGET    STATE            VAULT_V  AGE  DB_PW_CHANGED  PROFILE          ROLLOVER
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  2        0d   2026-09-07     SOPULI_ROLLOVER  window open
```
```
ACCOUNT          TARGET    STATE            DETAIL
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  vault v2 accepted, but a rollover window is open: the previous password still works too
```

### Why you should not just let it expire

The window closes by itself when `PASSWORD_ROLLOVER_TIME` runs out. Leaving it to
do that has a cost that is easy to underrate, and it is the reason this command
exists:

**Until the window closes, the old password still works.** That is the whole
point during the restart, and it is a liability afterwards. If you rotated
because a password leaked, the leaked password keeps working for the rest of the
window. The rotation is not finished until the old one stops working.

**And the failure looks like the tool's fault.** An application that was never
restarted keeps working perfectly right up to the moment the window expires, and
then fails — hours after the change, with nothing in anybody's change log at that
timestamp. Closing the window on purpose, right after you have confirmed the
restarts, moves that failure to a moment when somebody is watching for it.

So close it explicitly once your applications have restarted:

```bash
sopuli --config sopuli.yaml creds finish-rollover --application acme-batch --confirm
```
```
Plan: 1 account x 1 target = 1 window   [dev]

ACCOUNT          TARGET    INTENT                   SECRET
acme_batch_user  free-pdb  verify, rollover_finish  vault-dev:acme/dev/batch

ACCOUNT          TARGET    WINDOW
acme_batch_user  free-pdb  open, 59m left

ACCOUNT          TARGET    STATE    DETAIL
acme_batch_user  free-pdb  IN_SYNC  rollover window closed, 59m early

1 closed
```

Run it again and it changes nothing, and says so:

```
ACCOUNT          TARGET    WINDOW
acme_batch_user  free-pdb  none open

ACCOUNT          TARGET    STATE    DETAIL
acme_batch_user  free-pdb  IN_SYNC  no rollover window is open

no rollover window was open on any of 1
```

That second run is worth doing once. Oracle accepts the statement silently when
no window is open, so a tool that simply issued it would report a change for a
run that did nothing.

`creds rotate --finish-rollover` does the rotation and closes the window at the
end of the same run, for the case where you know the restart is immediate.

### If the account's profile has no window

The tool will not create one for you:

```bash
sopuli --config sopuli.yaml creds apply --strategy rollover
```
```
sopuli: profile DEFAULT grants no rollover window (PASSWORD_ROLLOVER_TIME is 0)
  hint: sopuli does not alter a profile, because profiles are shared and changing one affects
        accounts nobody selected. Run this yourself if it is what you want:
        ALTER PROFILE DEFAULT LIMIT PASSWORD_ROLLOVER_TIME 1;
```

Exit 1, and nothing was written. A profile is shared between accounts, so
altering one reaches accounts you did not select — and the config's account
whitelist has no way to constrain that. The tool prints the statement and leaves
the decision with you.

This is a different failure from asking for rollover on Oracle 18c or 11g, where
the *release* has no such feature at all. That is exit 5, and no local action
changes it. This one is a profile setting, and one `ALTER PROFILE` changes it.

---

## What to do when it goes wrong

| What you see | What it means |
|---|---|
| `DRIFT`, exit 3 | the vault's password does not work on the database. `creds apply` converges it |
| `UNVERIFIABLE`, `VAULT_V -` | there is no document in the vault yet. `creds generate` then `creds apply` |
| `UNVERIFIABLE`, "no login attempted" | the lockout guard stopped the check. Fix the drift with `apply`, which does not need to log in first |
| `ROLLOVER_ACTIVE` | not an error. Two passwords work. `creds finish-rollover` when the restarts are done |
| `SKIPPED  the account holds DBA` | a guardrail refused an account a credential tool should not touch. The run did the rest of its job. A skipped account does not change the exit code |
| exit 7 | somebody else holds the lock on this secret. `sopuli lock status` names them |
| exit 8 | a confirmation was declined, or a `readonly` setting refused the command |
| `the vault did not read back the new password for: ...`, exit 4 | every database has the new password and the promotion was written, but the vault serves a different value when read back, or does not answer the read. Nothing needs undoing on a database. Look at the vault, for example a replica behind its primary |

Every command also takes `--output json` for a machine-readable version of the
same run, with passwords redacted. The contract is in
[03-json-output.md](../design/03-json-output.md).

---

## Next

- [kubernetes-eso.md](kubernetes-eso.md) — letting applications in Kubernetes
  collect the new password by themselves, so the restart in section 6 is the
  only manual step left.
- [../security-model.md](../security-model.md) — what the tool can and cannot do,
  before you point this at production.
- [../local-testing.md](../local-testing.md) — the contributor's version of this
  walkthrough, against the local test stack.

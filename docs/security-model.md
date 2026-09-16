# The security model

This document is for someone deciding whether to let this tool change a password
on a database they care about. It says what the tool is able to do, what stops a
mistake from happening quietly, and what the tool cannot do at all.

It is written in plain language on purpose. The precise versions live in
[`design/00-principles.md`](design/00-principles.md) P5,
[`design/02-oracle-privileges.md`](design/02-oracle-privileges.md) and
[`use-cases/uc-01-app-credential-sync.md`](use-cases/uc-01-app-credential-sync.md)
§8. Nothing here is new behaviour; it is the same behaviour, explained for a
reader who is outside the project.

A note on the current state before anything else: this is pre-alpha software.
Only Oracle is supported, and only HashiCorp Vault is supported as the secret
store. Try it against a test database first.

---

## 1. What the tool can do to your database

**It holds the same reach as a DBA typing `ALTER USER` by hand. That is not
narrowed, and it cannot be.**

The tool connects to Oracle as an account that holds the `ALTER USER` system
privilege. `ALTER USER` is what changes a password. That single privilege is the
entire permission model — there is nothing else to install in the database.

The uncomfortable part is that Oracle offers no way to grant that privilege for
one account only. There is no `GRANT ALTER USER ON acme_app_user`. Any account
that can change one user's password in a container can change every user's
password in that container, including `SYS`. This is true up to and including the
current release: the 23 codebase added *schema privileges*, which looked like they
might change it, and `GRANT ALTER USER ON SCHEMA` is rejected with `ORA-00990`.
That was tested, not assumed
([`design/02-oracle-privileges.md`](design/02-oracle-privileges.md) §2.1).

So the service account you create for this tool is a powerful account. Treat it
that way. What the tool does with that power is bounded by three things, in
descending order of how much you should rely on them:

1. **The database's own auditing.** This is the real boundary, and it is outside
   the tool. `sql/oracle/01_audit_policy.sql` sets up unified audit policies so
   every `ALTER USER` the service account issues is recorded by Oracle itself.
2. **The config file, which is a whitelist.** The tool will not touch an account
   that is not named in the config file. Selectors on the command line — pick
   this application, pick that target — can only narrow the declared set. They
   can never add to it. Not even `--force` overrides this one.
3. **Client-side guardrails.** Before any `ALTER USER`, the tool refuses accounts
   that a credential-sync tool has no business touching: anything Oracle marks as
   its own (`ORACLE_MAINTAINED`), anything holding `DBA`, `PDB_DBA`, `CDB_DBA` or
   `AUDIT_ADMIN`, and anything in the password file. `--force` overrides these,
   and the override is written into the audit record.

**Be honest about what number 3 is.** These checks run in the tool, on your
machine. Somebody who has stolen the service account's credential can simply not
use the tool. The guardrails are protection against a typo and against a config
change with a wider blast radius than intended. They are not a security boundary,
and this document will not pretend otherwise. Auditing is the boundary; the
guardrails are the seatbelt.

### What must never be granted to the service account

The tool needs `ALTER USER` and a small set of read-only dictionary grants. It
never needs, and you should never give it, `SYSDBA`, `SYSOPER`, `DBA`,
`SELECT ANY DICTIONARY`, `CREATE USER`, `DROP USER`, `ALTER PROFILE` or
`ALTER SYSTEM`. `sopuli doctor --check-privileges` reports what the account
actually holds and warns about anything on that list. Over-granting is the
ordinary failure when somebody is debugging a permissions problem late on a
Friday, and the tool should notice rather than quietly benefit from it. The full
list, and the reason each entry is on it, is in
[`design/02-oracle-privileges.md`](design/02-oracle-privileges.md) §3.

---

## 2. What stops a mistake from being silent

Four separate mechanisms. They do different jobs, and none of them replaces
another.

### Dry run: see it before it happens

Every command that changes something accepts `--dry-run`. With that flag the
command works out its whole plan, prints it, and stops. Nothing is written to the
vault and nothing is sent to the database.

**No setting can take `--dry-run` away from you.** That is deliberate. A preview
is how you work out whether to agree to something, so blocking the preview would
block the wrong thing.

The plan is not decoration. Every limit the tool enforces — the maximum number of
targets, the environments that need confirming, whether the database can do what
was asked at all — is decided from the plan, before the first connection is
opened. A command that needs something the database cannot do fails while
printing the plan, not halfway through changing things.

### Confirmation: require somebody to say yes

In the config file you can list environments that a change may not enter without
an explicit yes:

```yaml
defaults:
  safety:
    # A run that touches any target in these environments asks before
    # changing anything. An empty or missing list asks nothing.
    confirm_environments: [prod, uat]
```

Four things are worth knowing about it:

- **There is no built-in list.** If you write nothing, nothing prompts. Marking a
  target `environment: prod` does not by itself cause a prompt — you have to list
  `prod` here. This is specified behaviour, not a missing feature, and section 4
  below says why.
- **It matches the environments the run actually reaches**, not the ones your
  config file happens to mention. A run narrowed to your dev databases is not
  asked about production merely because production exists elsewhere in the file.
- **`--confirm` is that yes, given in advance.** A scheduled job adds the flag
  once instead of keeping an environment list in step with your config.
- **With no terminal, it refuses rather than prompts.** There is nobody to ask, so
  the run stops with a message naming the setting, where it was written, and both
  `--confirm` and `--dry-run` as the two ways forward.

Two commands confirm every time regardless of this setting: `creds rotate` and
`lock break`. A third is designed but not built yet: resetting a person's own
account password in the mode where the DBA sees the new password
(`docs/use-cases/uc-02-personal-account-passwords.md`).

### The safety ratchet: settings can only get stricter

Settings can come from several places at once — a site-wide config file, a more
specific one, a named profile inside it, an environment variable, a command-line
flag. For most settings, the most specific one wins. That is the ordinary rule
and it is what you would expect.

**The safety settings work the other way round. The safest value wins, wherever
it came from.** These are the settings that behave this way:

| Setting | What it does | How the layers merge |
|---|---|---|
| `safety.readonly` | refuse every change | one layer asking for it is enough |
| `safety.dry_run` | preview only, never change | one layer asking for it is enough |
| `safety.max_targets` | most databases one run may touch | the smallest number any layer named |
| `safety.confirm_environments` | environments needing an explicit yes | every environment any layer listed |
| `locking.break_expired` | permission to take over an expired lock | one layer withholding it is enough |

The thing this protects against is concrete. A site-wide config file turns on a
safety rule. A team writes their own more specific file, which for every other
setting would override it. If the ordinary rule applied here, that team file
could switch the site-wide rule off — probably by accident, and nothing would say
so. Under the ratchet it cannot. It can only add more restrictions.

Note the last row: `locking.break_expired` is *permission* rather than a guard,
so for that one the safe direction is `false`, and one layer saying `false` wins.
The direction is declared per setting rather than guessed from its name.

`--force` is not in the table because it is not a setting. It overrides the
account guardrails from section 1, and nothing else. It cannot relax a safety
setting and it cannot extend the config's whitelist.

To see which layer produced each effective setting, run
`sopuli config show --explain`. It prints every setting and where its value came
from.

### Locking: two people cannot rotate the same credential at once

Before changing anything, a run takes a *lock* — a marker saying "this credential
is mine for the moment". The lock lives in the vault, next to the secret it
guards, so two operators on two laptops, or two scheduled jobs, see the same one.

Three details make it survivable rather than merely present:

- **A run takes every lock it needs before it changes anything**, in a fixed
  order, and never waits. If it cannot get them all, it gives back the ones it
  took and stops, having changed nothing. Two runs cannot end up each holding
  half of what the other needs.
- **The lock is guarded by compare-and-set.** Compare-and-set is a safe way to
  update something only if nobody else changed it first: you say which version
  you read, and the write is rejected if the stored version has moved on. The
  tool always writes the lock this way, and requires the vault path to demand it
  of everyone else too — otherwise somebody with a vault command line could
  replace the lock record without one.
- **The lock carries a fencing token, re-checked before every change.** The token
  is the version number the vault returned when the lock was taken. It is read
  again before each vault write and each `ALTER USER`. If another run took the
  lock over in the meantime, the check fails and this run stops before touching
  its next database — rather than setting a password the vault no longer
  advertises.

Read-only commands — `creds check`, `creds status`, and anything with `--dry-run`
— take no lock at all. An hourly check must never block a rotation.

If a run dies without releasing its lock, `sopuli lock status` shows you who holds
what, and `sopuli lock break` takes one back. Breaking a lock always asks for
confirmation, and a lock that has not yet expired needs `--force` on top.

---

## 3. What stops a scheduled check from causing harm

`sopuli creds check` answers one question: does the password in the vault still
work on this database? The only way to answer it is to try logging in.

That is the risk. A failed login counts against Oracle's `FAILED_LOGIN_ATTEMPTS`
limit. A check that runs every hour against an account whose password has drifted
would eventually lock out the production application account — which is worse than
the problem it was detecting.

Four things prevent that:

1. **One attempt per account per run.** No retries, no back-off loop. A wrong
   password costs exactly one failed login, not five.
2. **The tool looks before it leaps.** Where it has been granted
   `SELECT ON SYS.USER$`, it reads how many failed attempts the account has
   already collected and compares that with the profile's limit. If one more
   attempt would leave less than the margin you asked for — `--lockout-margin`,
   two attempts by default — it does not try. The result is reported as
   `UNVERIFIABLE`, with the count that stopped it, and the run exits 0. Here is
   what that looks like on an account with two of its three attempts already
   spent:

   ```
   ACCOUNT        TARGET    STATE         DETAIL
   acme_app_user  free-pdb  UNVERIFIABLE  no login attempted: 2 of 3 failed logins are already
                                          recorded, and 1 more would leave less than the
                                          2-attempt margin

   1 unverifiable
   ```

   `UNVERIFIABLE` is the honest answer. The tool declines to find out, and names
   the fact that stopped it.
3. **It says when the guard is unavailable.** `SELECT ON SYS.USER$` is an optional
   grant, not part of the standard install, because it is a broad read. Where it
   has not been granted the tool cannot read the counter — and it reports that
   plainly instead of quietly skipping the check. The other three mitigations
   still apply.
4. **Success cleans up after itself.** A successful login resets Oracle's failed
   attempt counter, so the normal path never accumulates anything.

One more thing `check` does that is easy to miss: it reads the account's status —
locked, expired, locked with a timer — separately, from a view that needs no
special grant. A login attempt on its own cannot tell an expired password from a
locked account from a genuinely wrong one; Oracle answers `ORA-01017` to all
three. Reading the status separately is what lets the tool report `LOCKED` or
`EXPIRED` as themselves rather than folding them into "drift".

---

## 4. What the tool cannot do

**It cannot read an existing password out of a database.** Oracle does not store
passwords in a recoverable form — it stores a verifier, which is a one-way
transformation. There is no command in this tool that recovers a password from a
database, and there could not be one. If the password exists nowhere but the
database, it is already lost; the tool cannot adopt it, only replace it.

**It never treats the database as the source of truth.** The direction is always
vault to database. When the two disagree, the vault is right by definition and
the database is what gets changed. That is what `creds check` reporting `DRIFT`
means, and `creds apply` is what resolves it — in that direction, never the
reverse.

**It cannot act on an account your config file does not name.** Covered in
section 1, repeated here because it is the invariant that makes the audit trail
mean anything. `--force` does not override it.

**It cannot alter a profile.** Password rollover — Oracle's feature where the old
password keeps working for a window after the new one is set — comes from the
account's profile. Profiles are shared between accounts, so changing one reaches
accounts you did not select and the config's whitelist has no way to constrain
that. When a run needs a profile setting that is not there, it stops and prints
the `ALTER PROFILE` statement for you to run yourself:

```
sopuli: profile DEFAULT grants no rollover window (PASSWORD_ROLLOVER_TIME is 0)
  hint: sopuli does not alter a profile, because profiles are shared and changing one affects
        accounts nobody selected. Run this yourself if it is what you want:
        ALTER PROFILE DEFAULT LIMIT PASSWORD_ROLLOVER_TIME 1;
```

**It cannot prompt you into safety you did not configure.** There is no built-in
list of environments that require confirmation. This is worth stating as a
limitation rather than leaving you to discover it: if you mark a target
`environment: prod` and write no `confirm_environments`, changes to it are not
confirmed. The reason is that a built-in entry could never be removed again —
because of the ratchet in section 2, any layer's value is added and none can be
taken away, so a built-in `prod` would be a floor nobody could lift. Listing
`prod` yourself is one line, and it is the same line you would have needed for
`staging` or `uat` anyway.

---

## 5. What happens to the password itself

**In the tool's own output: nothing.** A secret value is held in a wrapper type
whose text form, debug form and JSON form are all `***`. Masking is applied where
output is produced, not at each place a password is handled — so there is no
"remember to mask this one" for anybody to forget, in ordinary output or in a
crash traceback.

There is exactly one command that prints a real password: `policy sample
--reveal`, which shows what your password rules actually produce. A sample is not
a credential — nothing authenticates with it, it is never stored, and it guards
nothing. Even so it is fenced in: it refuses to run together with `--output json`,
because JSON output is what gets captured and shipped to a log collector.

```
$ sopuli policy sample --reveal --output json
Usage: sopuli policy sample [OPTIONS] [NAME]
Try 'sopuli policy sample --help' for help.

Error: --reveal cannot be used with --output json
       json output is what gets captured and shipped to log aggregation, so a sample never
       appears in it -- drop --reveal, or use the text output
```

**On the command line: never.** No option to any command takes a password as its
value. Command-line arguments are visible to every other user on the machine,
through `ps` on Linux and the process list on Windows. Where a flag has to name a
secret, it names *where the secret is* — `--vault-token-file PATH` — and never the
secret. A supplied password arrives on standard input instead.

**A password containing a double quote is rejected.** Oracle's quoted identifiers
have no escape sequence for `"`, so there is no correct way to send one. The tool
refuses the password rather than mangling it or guessing.

**Inside Oracle: measured, not assumed.** `ALTER USER` has to carry the password
as literal text, because Oracle's data definition statements cannot use bind
variables. So the question is what Oracle keeps afterwards, and that was tested
with a canary password swept through every place a statement's text can come to
rest. On Oracle 26ai the statement itself is not retained anywhere queryable, and
the unified audit trail masks it at write time. Two things do leak, and both are
now forbidden in the tool's own code: wrapping the statement in a PL/SQL block
(the block *is* retained, verbatim), and sending a password as a bind value in a
query (bind values are captured in clear). The full results, per version and
with their scope, are in
[`design/02-oracle-privileges.md`](design/02-oracle-privileges.md) §4; the
versions and surfaces still unchecked are in
[`design/04-testing.md`](design/04-testing.md) §6 gate 2.

**On Oracle 11.2, one of those results does not hold, and you should know it
before you rotate there.** The same test on 11g XE 11.2.0.2.0 found the plain
`ALTER USER … IDENTIFIED BY "<password>"` — the statement this tool issues, not a
wrapper — retained verbatim in `V$SQLSTATS`. `V$SQL` holds no cursor for it there
either, exactly as on every other release; `V$SQLSTATS` keeps its own copy, and
that copy outlives the cursor. 18c, 21c and 26ai retain nothing. Where 12.1, 12.2
and 19c fall has not been measured, so read this as *11.2 does* rather than
*everything older does*.

This is not an artefact of the test. A real `sopuli creds apply` was run against
11.2 the ordinary way, and the password it generated — written to the vault and
never shown to anybody — was then readable in `V$SQLSTATS`, inside the tool's own
`ALTER USER "ACME_APP_USER" IDENTIFIED BY "…"`.

What it means in practice, all of it measured rather than reasoned:

- **Who can read it.** Anyone who can read the dictionary — `SELECT ANY
  DICTIONARY`, `SELECT_CATALOG_ROLE` or `DBA`, which on most estates is the DBAs
  and the monitoring accounts. The tool's own service account **cannot**: holding
  exactly the grants this project documents, it gets `ORA-00942` from the view. So
  this is not something the tool's installation creates, and no grant needs
  narrowing to fix it.
- **How long.** Until the entry ages out of the shared pool, which happens under
  ordinary traffic — on an idle test instance with a full `V$SQLSTATS` a planted
  value survived 2,000 further distinct statements and was gone by 3,000. On a
  quiet database it can sit there considerably longer.
- **How to clear it now.** `ALTER SYSTEM FLUSH SHARED_POOL` removes it
  immediately. **The tool will not do this for you.** It needs `ALTER SYSTEM`, a
  privilege the service account is deliberately not granted, and flushing a
  production shared pool is a performance event that should be somebody's decision
  rather than a side effect of a password change.
- **What is still unknown.** Whether the text reaches AWR (`DBA_HIST_SQLTEXT`) on
  a licensed 11.2. It could not be tested on XE, which ships with the Diagnostics
  Pack turned off and captured nothing at all. Treat it as unanswered, not as
  clean.

Rotating the same password by hand in SQL\*Plus on 11.2 leaves the identical text
in the identical view, so this is a property of the release rather than of the
tool — which is why the tool documents it and carries on rather than refusing to
run. The decision, and the two alternatives that were declined, are recorded in
[`docs/design/02-oracle-privileges.md`](design/02-oracle-privileges.md) §8 as P8.

---

## 6. Reporting a problem

If you have found a security vulnerability in this tool, please do not open a
public issue. [SECURITY.md](../SECURITY.md) has the private route, and says
what to include and what happens next.

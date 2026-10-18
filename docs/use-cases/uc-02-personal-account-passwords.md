# UC-2 — Personal account passwords: reset and hand over

Depends on: `../design/00-principles.md`, `../design/01-configuration.md`,
`../design/02-oracle-privileges.md`

This document specifies `personal_accounts:`, `sopuli account reset-password`,
`sopuli account expire-password`, `sopuli account suspend` and
`sopuli account list`. The reset is built for the `manual` and `vault_wrapped`
delivery methods; §6.2 lists the methods that are not built yet. §9 lists the
open questions.

**These commands are experimental in the alpha.** They are the newest part of
the tool, and the decision on the seen reset's rollover refusal is still open
(open: #541), so they may change more than the application-credential commands.

---

## 1. Summary

**Goal.** A person cannot get into their own database account: a developer's, a
tester's or a DBA's. Usually the password expired and they no longer know it. A
DBA resets it, and the tool makes the new password **the person's alone**. There
are two ways to do that. They do not give the same guarantee, and which one a
reset takes decides almost everything else in this document:

| Path | The DBA sees the password | How the person gets it | Expired on reset |
|---|---|---|---|
| **unseen**, the default | no | fetches it from a store meant for them alone: a single-use wrapping token (the default), a Vault path only their identity can read, a one-time link, a password manager or encrypted mail. §6 says what each actually promises | **no** |
| **seen**, `manual` | yes | the DBA passes it on, by encrypted email or similar, with instructions to change it | **yes, always** |

**The unseen path is the default**, and it is what the tool exists to make
possible. A DBA resets a password without ever seeing it, and the tool puts the
value in none of its own output. Nothing needs expiring, because nobody but the
person is meant to know it. §4.1 and §6.6 say where that intent meets its limits.

**"Never sees it" and "cannot obtain it" are different promises.** On the default
method the DBA holds a *wrapping token*, and a token can be unwrapped. What the
single use gives is that an unwrap by someone else is **detectable**: the
person's own fetch fails, and somebody knows. It is not prevented. This section
claims the first promise and not the second.

**What the unseen path guarantees, and on what condition** (decided as a
principle on #459 and #496, which decided H8 and H9 by it). It does not defend
against a privileged DBA, and could not. Whoever can reset a personal account's
password can also connect *as* that person, by
`ALTER USER person GRANT CONNECT THROUGH dba`, which needs only `ALTER USER`, the
privilege this tool's service account is built around. On 26ai 23.26.2.0.0 the
grant succeeds with `CREATE SESSION` and `ALTER USER` and nothing else. The
session reports `USER` as the person and `PROXY_USER` as the DBA, and the same
privilege revokes the grant again, leaving `DBA_PROXIES` empty
(`sql/oracle/11_proxy_connect_probe.sql`). So the guarantee is about
*attribution*, not access:

> **Where the database audits `ALTER USER` and logons, the unseen path guarantees
> that the DBA cannot act as the person without leaving their own name behind.
> Where it does not, the unseen path only keeps the password from being usable
> beyond that one database.**

The condition is the measured part. A reset to a known value and a proxy session
both point at the DBA, but only in an audit trail. The proxy grant can be
revoked, and a reset leaves a `PASSWORD_CHANGE_DATE` and a person locked out,
and neither says who did it. With no unified audit policy enabled, which is
FREEPDB1's default, the same probe found the grant, the proxy logon and the
revoke recorded **nowhere**. With a `LOGON, ALTER USER` policy, every step was
recorded, and the proxy logon names the DBA in `DBPROXY_USERNAME`. Knowing the
person's actual password is the one route on which the record names only the
person, and closing that route is what "unseen" is for. On a database that audits
neither, the DBA can already act as the person there without a trace. What the
unseen path still protects is the password's value *elsewhere*: on the person's
other targets, and wherever they reused it. A proxy grant is per database, and a
password is not.

**An unseen reset records whether the database audits the DBA's routes**, as
`audited` in the reset record (§3.1) and in the run document's result (decided
in H10). It does not warn and it does not refuse. The tool creates no audit
policy. `sql/oracle/01_audit_policy.sql` creates policies that give `true` when
it runs in the person's own container with the person in its list. On a
multitenant database that means a run in the PDB, not only in the root.
`02-oracle-privileges.md` §5 says where to run it and what each run gives. There
are three values:

- `true`: enabled audit policies record the person's logons, and every user's
  `ALTER USER`.
- `false`: the database uses unified auditing only, and for one of the two, no
  enabled policy records it or might record it.
- `unknown`: the tool could not tell. The result says why. For example, the
  service account cannot read the audit policies, traditional auditing might
  also be in use, or a policy might record the action but has a condition the
  tool does not evaluate. The tool never gives `false` for a fact it could not
  read.

`ALTER USER` must be recorded for every user, not only for the person, because
the DBA issues it. A policy enabled for a list of users records the statements
those users issue. So a policy enabled for the person records the proxy logon
and not the DBA's `ALTER USER`. `02-oracle-privileges.md` §5 says how each kind
of policy is read, and §2 has the optional grant the check needs.

The value describes the moment of the check. Not measured: whether a DBA who
also holds `AUDIT SYSTEM` can disable a policy first, and the audit behaviour of
any release other than 26ai.

**The name is left in any durable record the DBA does not control** (decided on
#459 and #496): the database's audit trail or Vault's audit device, not the
database trail alone. On the database trail alone, the default method would fail
its own principle: a DBA who unwraps a token and logs in as the person leaves a
database trail that names only the person. It would also ask more of the unseen
path than the database gives the other two routes, which it names the DBA on only
where audit is configured.

**This tool's own reset record is not such a record**, and neither is the run
document. Both are written by the DBA's own run with the DBA's own store
credentials, and `by` is the run reporting who ran it. A DBA who means to act as
the person can leave the record unwritten (§3.4 lets a reset succeed without one)
or rewrite it afterwards. The record is an **index** into the evidence, never the
evidence.

So **the Vault methods have a second condition, the Vault half of the first**:
the Vault the handover goes through must have an audit device enabled. Without
one, nothing independent records the handover at all. These results are from the
tier-1 Vault (2.0.4), with a file device enabled for the run and removed after:

- **`vault_wrapped` meets it by inference.** The audit device records the wrap
  under the DBA's own identity (`display_name`, policies), and its response
  carries the HMAC of the wrapping token's accessor. It records the unwrap under
  that **same** accessor HMAC, with policy `response-wrapping` and no identity,
  only a remote address. `sys/audit-hash` on the plaintext accessor, which
  `results[].handover` and the record's `delivery.to` carry, reproduces the HMAC
  and finds both entries. So the device alone shows that a token issued to this
  DBA was unwrapped, by somebody. An unwrap the person did not make also fails
  their own fetch. That the DBA did the unwrap is an inference, and it holds only
  while the token went to nobody else. **A redirected token is where it stops.** A
  token piped into a CI log or a file can be unwrapped by whoever reads it, with
  no name attached. If they unwrap first, the evidence points at the DBA instead
  of at them. The redirect is allowed so that a handover can run unattended
  (§6.6).
- **`vault_path` meets it directly.** The device records an authenticated request
  under the caller's identity, as the wrap entry above shows, so a read of the
  person's path names its reader. The tool still checks, before writing, that the
  DBA's token cannot read the path (§6.6). A guarantee that records a read is
  weaker than one that prevents it.

The Vault half is stated, not checked (H10). A token scoped to the DBA's job gets
`403` on `sys/audit`, so it cannot even see whether a device exists, and no reset
token should hold the `sudo` capability that would let it. A token that can
write `sys/audit` can also disable the device; the probe did, to clean up. That
is the Vault form of the `AUDIT SYSTEM` question above.

**The seen path is the traditional one, and it is not the default.** The DBA
generates the password, sees it, and sends it on. **That is a deliberate,
time-limited exposure, not the same guarantee by another route.** Until the
owner's first logon, the DBA holds a working password. `PASSWORD EXPIRE` forces
a change at first logon, but does not decide *who* logs in first. Expiry is what
ends the exposure: once the owner has set their own password, the one the DBA saw
no longer works. So on this path expiry is forced, not offered, and the command
asks for confirmation before it runs (§2).

**Actors.**

| Actor | Role |
|---|---|
| DBA | runs the reset, usually because somebody asked for one |
| Account owner | fetches the password (unseen) or receives it (seen), and logs in |
| Secure store | holds the password for the owner to fetch; a Vault first (§6.2) |

**Direction of truth.** There is none, and that is the first way this differs
from UC-1. `docs/README.md` puts it as *a password is handed over, not synced*.
Nothing reads the value to stay in step with it, so no store is master of it. On
the unseen path a store does hold it for the person to fetch. That is transport,
not mastery. How long that copy lives depends on the method (§6.6): on
`vault_wrapped` nothing outlives the unwrap, and on `vault_path` it is open
(open: #447). So invariants 6 and 7 have nothing to govern here (§7). **That does
not make the database a source of truth either.** The tool reads account state
from it, as UC-1 does, and never a password. §3.2 makes that boundary precise,
because H2 puts the database on the authoritative side of one question, *when*
the password last changed, and nowhere near the value.

**Why this cannot be a mode of UC-1.** Each point is a place where UC-1's design
would do the wrong thing:

- **Expiring on purpose is correct on the seen path.** `PASSWORD EXPIRE` breaks an
  application account, which is why UC-1 §5 has no such attribute and sends the
  operation here.
- **Lockout tolerance is different.** UC-1 §7's mitigations exist because locking
  a production application account is an outage. Locking a developer out of their
  own account is not (§5).
- **Nothing is promoted, so nothing waits on confirmation from a target.** UC-1's
  safety design is the ordering of `pending` → `current`. A handover has no
  `current`.

**Non-goals.** Creating, dropping or granting accounts (UC-4). Application
accounts (UC-1). A person changing their own password through the tool: an owner
who knows their password changes it without the tool (§5). Keeping any copy of
the password as a record of it.

---

## 2. Commands

**The noun is `account`** (H3, decided in #451). Oracle says *user*, and the
driver agrees (`describe_user`, `UserState`). But *account* is the word the
configuration uses for the thing being managed, and every other noun in this CLI
follows the file an operator edits, not the database: `target`, `policy`,
`lock`, `creds`. D2's noun-verb grammar is satisfied either way, so the
configuration's own word wins. The configuration declares personal accounts in
a `personal_accounts:` section (H1), and an operator who reads *accounts* there
types `account` at the prompt.

| Command | What it does | Mutates |
|---|---|---|
| `sopuli account reset-password` | **unseen, the default**: generate a password, set it, write it where only the owner is meant to fetch it; show it to nobody. Built for `vault_wrapped`. A file naming an unseen method that is not built yet (`vault_path`, `one_time_link`, `onepassword_share`, `smtp_encrypted`) is refused at plan time with exit 5, before the password changes | yes |
| `sopuli account reset-password`, `manual` | **seen**: generate a password, set it **with expiry**, and show it once, after confirmation. Under §6.5's five guards | yes |
| `sopuli account expire-password` | `PASSWORD EXPIRE` with no new password: "make them change it". Closes an open rollover window first | yes |
| `sopuli account suspend` | `ACCOUNT LOCK`, for offboarding | yes |
| `sopuli account list` | resolve the declaration (names, or a predicate over a profile or role) and report what it matched, with each account's state. Reads no password and writes none | no |
| any of the mutating verbs, under `--dry-run` | prints the plan and never a password (invariant 8, which binds on every one of them) | no |

**The seen reset asks for confirmation every time.** `00-principles.md` P5
records it beside the other two gates that always ask, `creds rotate` and
`lock break`. Like them, it does not consult `safety.confirm_environments`, and
no layer can relax it.

**`--confirm` does not answer it** (decided in #439). So it is a gate that cannot
be given a yes in advance. The reason is not that this operation is more
dangerous than a rotation. The prompt here is not a formality to be waived. The
run is about to print a working password to a screen. `--confirm` would assert
that somebody is watching, when finding out whether somebody is watching is the
purpose of the gate. A flag cannot vouch for that.

The terminal check in §6.5 makes the same claim, on purpose: if nobody is present
to answer, nobody is present to receive the password either.

**`expire-password` is its own verb, not a flag on the reset.** The two
operations take different inputs. A reset draws a password and so needs somewhere
to deliver it. An expiry needs neither a password nor a delivery method. As a
flag, it would make the reset's delivery arguments meaningless in half its
invocations.

**It closes an open rollover window before it expires the password** (decided in
#525). `sql/oracle/08_expire_password_probe.sql` measured the plain statement on
26ai Free 23.26.2.0.0. Expiring an account with a window open leaves
`EXPIRED & IN ROLLOVER`, and the **old** password still answers `ORA-28001`: it
authenticates, and it can itself be used to set the next password. That is §4.3's
Q7 finding again, on the form that sets no password. Closing first makes the old
password fail (`ORA-01017`). The reset does the same by default, for the reason
§4.3 gives: the only holder of the old password is the person whose account this
is.

These rules follow:

- **Close, then expire.** Both orders end in plain `EXPIRED`. They differ only
  when the second statement fails. Close-then-expire leaves `OPEN` with the old
  password already dead. The reverse would leave an expired account whose old
  password still works.
- **Only an open window is closed**, not a profile that merely grants one. A plain
  expiry sets no password and so opens no window. On a rollover profile with no
  window open, it leaves plain `EXPIRED`. The reset closes on the wider test,
  because its own `IDENTIFIED BY` opens a window.
- **The converged state is `EXPIRED` with no window open** (invariant 9). Oracle
  accepts a second `PASSWORD EXPIRE` silently, so the driver reads the state
  first. An account at `EXPIRED & IN ROLLOVER` is not converged: the verb closes
  the window and reports a change. `EXPIRED(GRACE)` is not converged either,
  because the password still logs in. Expiring it moves the expiry date to now.
- **A lock is left alone, of either kind.** `LOCKED` becomes `EXPIRED & LOCKED`.
  This verb unlocks nothing.

**The cost:** somebody who knows only the old password loses the self-service
change the window would have given them, and needs a reset. The benefit is that
the safety does not depend on a release nobody has measured. On 26ai Free
23.26.2.0.0, the expiry leaves the old password working
(`08_expire_password_probe.sql`), so there the close is what ends it. A
close with no window open is accepted silently (§4.3). So on a release where the
expiry already ends the old password, the close costs one statement that does
nothing.

**It writes no reset record and takes no reset lock**, like `account suspend`.
§3.1's record journals resets and where they were delivered, and §3.3's lock stops
two deliveries overwriting each other. An expiry draws nothing and delivers
nothing, so the run document is its record. **It has no flag to keep the
window**, because nobody has asked for one. The reset's `--keep-rollover` (§4.3)
is for an owner who still knows the old password.

### `account suspend`

Disabling an account, the offboarding case, is `sopuli account suspend`. The verb
is not `lock`, because `lock` already means something else in this CLI:
`lock status` and `lock break`, the advisory locks on vault paths. A second sense
of that word would give one surface two meanings. The other choices are to live
with that, or to rename the advisory-lock noun. Naming this verb differently
costs nothing.

**Only the verb has a different name, not the state.** `suspend` is what a DBA does to a
person's account when they leave. `LOCKED` is what `ACCOUNT_STATUS` then says,
and §5 depends on that word meaning Oracle's fact, not the tool's. The statement
is `ALTER USER … ACCOUNT LOCK`.

The command below suspends one account:

```
sopuli account suspend --account NAME [--target NAME] [--force] [--dry-run]
```

`--account` is required and takes one name. That is this section's rule for a
mutating verb: an offboarding is one person leaving, and a declaration that
resolved to a set would be a predicate widening what a mutating verb may touch.
The target selectors narrow *where*, not *who*.

The guardrails are the ones every mutating verb uses, so suspending `DBSNMP` is
refused exactly as rotating it would be. `--force` waives checks 2 to 5 and never
the whitelist. A refusal exits **0**: `SKIPPED` means the guardrails worked, and
only an unreachable target sets exit 4. The action kind is `account_lock`. The
run document carries `results[].account_status`, the state the database was in
*before* anything was issued, because `state: LOCKED` with `changed: false`
cannot say by itself whether the account was already locked or would be locked
under `--dry-run`. The driver relies on two facts measured on 26ai Free
23.26.2.0.0:

- A second `ACCOUNT LOCK` against an account that is already `LOCKED` is
  **accepted silently** and changes nothing. So the driver reads the state first
  and reports `changed: false`. The driver holds invariant 9, as it does for
  UC-1 §5's unlock.
- **`LOCKED(TIMED)` is not already suspended.** `ACCOUNT LOCK` takes it to
  `LOCKED`, and that is a real change. The timed lock ends on its own under
  `PASSWORD_LOCK_TIME`, and this one does not. §5's reset clears the first and
  refuses the second. Reporting no change there would claim an offboarding that
  never happened.

**So the driver parses the state; it does not compare it.** Both obvious tests
are wrong. `LOCKED(TIMED)` *contains* `LOCKED`, so a substring test calls a
failed login an offboarding. The status also combines: `EXPIRED & LOCKED`,
`LOCKED & IN ROLLOVER` and `EXPIRED & LOCKED & IN ROLLOVER` are all real values.
So equality against the whole string calls a deliberately locked account open.
The driver splits on ` & ` and looks for a `LOCKED` component, as it does for
`EXPIRED(GRACE)`.

### `account list`

`sopuli account list` resolves the declaration against each selected target and
reports what it matched, with the rule that admitted each account. It changes
nothing and reads no password. Under a predicate (H1, decided in #449),
something has to resolve the rule and show what it matched. `creds status` would
show empty vault-version and age columns for accounts no store masters. Where the
declaration is a list of names, it is the same command answering a shorter
question, so it is one verb, not two.

- **An account admitted by more than one rule is listed once.** An enumerated
  entry yields the *file's* spelling and a predicate the *dictionary's*, so
  `jdoe` and `JDOE` are one person. A listing that showed one account twice would
  misreport the size of the whitelist somebody is reviewing. Where the account
  exists, the name shown is the database's own.
- **A predicate can admit an account that no reset will touch, and the listing
  says so.** Creating a role grants it to the creator, so `role: ACME_DEV_TEAM`
  admits whoever ran the `CREATE ROLE`. On the tier-1 stack that was `SYSTEM`.
  Guardrail 2 refuses it at plan time, and the row carries a notice saying so.
  This makes H1's cost visible, which is why the verb exists.
- **The refusals are the ones this section specifies.** The two-rules,
  two-policies refusal fires here exactly as it does in the mutating verbs. A
  listing that quietly showed the first match would be where an operator formed
  a belief that a reset then refuses.

**There is no separate read verb.** "When was this person last reset" is
answered by `account list` (H2, decided in #450). It shows two columns for it:
the database's password-change date and the metadata record's `reset_at`. §3.2
says why both are shown instead of one number.

**Either column can be empty, and an empty one is not an error.** Where no store
is configured, there is no `reset_at` to report. `SOPULI-W021`'s rule applies to
the pair: a documented column that is empty with nothing saying why is a gap in
the contract. So `account list` prints `-` and carries a warning that says
which absence it is. **That warning is `SOPULI-W023`**, once per run, not once per
account, because a missing journal is a property of the configuration, while a
missing database date is a property of one account. It reports what exists; the
verb does not fail because history is missing.

### What declares a personal account

Every operation is limited to declared accounts. **A `personal_accounts:`
section declares them** (H1, decided in #449), holding either names or a
**predicate** over a profile or a role. It is not an application binding.
`01-configuration.md` §1 defines a binding as *these accounts are mastered by
these secrets*, and names three things that depend on it: `check`'s desired
state, the account-to-secret mapping, and fan-out. A personal account has none of
them, so an application entry marked personal would serve none of its purposes.
Reasons: [H1](../decisions/log.md#h1).

**A predicate never widens what a mutating verb may touch.** That is how invariant
5's rule that selectors cannot extend the declared set stays exactly as written.
`account list` resolves the predicate. `reset-password`, `expire-password` and
`suspend` also require the account named on the command line, and refuse any name
the declaration does not admit. So one run touches exactly one account.

**A name may not be declared twice.** An account that is both an application
account and a personal one would make the whitelist ambiguous about which
guarantee applies: mastered by a secret, or handed over. So the validator rejects
the duplicate instead of picking one.

**The cost:** predicate membership is controlled in the database, by whoever
**assigns the profile** or **grants the role**, not by whoever reviews the file.
The two are different operations, `ALTER USER … PROFILE` and `GRANT … TO`, and
the predicate inherits whichever governs it. Adding an account to an enumerated
whitelist is a commit somebody reads. Adding one to a predicate is a profile
change or a grant. The checks in `02-oracle-privileges.md` §4 narrow that without
closing it: check 2 still refuses `ORACLE_MAINTAINED`, and check 4 still refuses
`DBA`, `PDB_DBA`, `CDB_DBA` and `AUDIT_ADMIN`, whatever profile an account has.
The blast radius is one named account, so a bad predicate is a wrong *offer*,
not a wrong *action*. On the other side, a list of four hundred developers is not
really reviewed either, and a predicate is a policy statement somebody can read.

**Two rules may admit one account; two rules naming different policies may not.**
An enumerated entry and a profile predicate can both be true of one person. That
is ordinary: both say the same thing about the same account, with the same
guarantee. A `policy:` is different. Taking the first match would make the
password policy depend on the order in which somebody wrote two entries. That is
refused at **plan time**, not at load, naming both rules, because whether a
predicate admits an account is a fact about a database.

**Refusals follow the asymmetry in `01-configuration.md` §2.** A predicate that
names a profile or role that **does not exist** is refused, because that is a
misspelling. One that exists and **matches no accounts** is not an error, because
that is a true answer about today's estate.

---

## 3. What is recorded

UC-1's vault payload answers three questions at once: when a password last
changed (Q9's `rotated_at`), what to roll back to (`previous`), and where the
lock lives (Q2, keyed on the secret path). UC-2 has no payload, so each question
needs its own answer. **H2 (decided in #450) gives those answers, and they are in
different places**: the database, a metadata record, and nowhere at all.
Reasons: [H2](../decisions/log.md#h2).

| Question | Answered by | Why there |
|---|---|---|
| **when** the password last changed | the **database**: `DBA_USERS.PASSWORD_CHANGE_DATE`, or `SYS.USER$.PTIME` behind the optional grant where the column is absent. 12.1 is unmeasured on the fallback (unverified: pw-changed-source) | it is the only thing that knows about a change the tool did not make, and on the seen path there is *always* one (§3.2) |
| **who** reset it, by **which path**, and **where** it was delivered | a **metadata record** in a store, written where an estate configures one (§3.1) | the database cannot know any of it, and the run document answers only for whoever kept that run's output |
| **what to roll back to** | **nothing** | rollback is not a UC-2 operation: the recovery for a lost personal password is another reset |
| **where the lock lives** | the metadata record's own path (§3.3) | it exists on the seen path and the unseen one alike, for every delivery method |

**The record never holds the password**, in any form: not the value, not a hash,
not a verifier. That is invariant 2, and it is also the point. A record that
could leak what it records would be worse than no record. UC-1's payload can
hold `rotated_at` because the payload is already the secret. This record is not,
so anyone allowed to know *that* a reset happened can read it without being able
to use it.

### 3.1 The metadata record

**It is written wherever a store is configured. Where none is, a reset still
runs.** The unseen path already needs a store as its delivery target, so on the
default path the record costs nothing extra. The seen (`manual`) path may have no
store at all, and that is exactly the site `manual` exists for. Requiring a store
would take the fallback away from the estates that have nothing else. So a reset
with no store configured is **not refused**; it warns (§3.4).

There is one record per **(target, account)**, under a prefix of its own. This is
not the unit UC-1 locks on, and the difference matters. UC-1 keys on the vault
document, because the document is what changes. Here what changes is **the
database account**. One person's account on `appdb-dev-alpha` and on
`appdb-qa-alpha` is two accounts with two passwords, which two DBAs can reset
independently.

The record holds what happened:

```json
{"account": "acme_dev_alice",
 "audited": true,
 "audited_detail": "LOGON by ACME_ROUTE_POL; ALTER USER by ACME_ROUTE_POL",
 "by": {"host": "dba-ws-4.example.com", "os_user": "dba01", "pid": 98004},
 "correlation_id": "65ca65a5-5a05-49a4-9c80-8814c13234f2",
 "delivery": {"method": "vault_wrapped", "to": "PYfXbFKBlw3U0ieUm0lvdCkY"},
 "expired": false,
 "reset_at": "2026-10-15T18:55:14.059388Z",
 "seen": false,
 "target": "free-pdb"}
```

That record is from a tier-1 run, with the host and the operating-system user
replaced.

**`audited` and `audited_detail` are what §1 describes**: whether the database
audits the DBA's routes to acting as the person, and why. They are the run
document's two fields, written the same way. A seen reset's record has neither,
because the seen path does not check.

**On `vault_wrapped`, `to` is the wrapping token's *accessor*.** The accessor
above is a made-up example. A real one is what Vault returns beside the token. It
names the handover in Vault's own audit log and **cannot unwrap it**. That is the
only reason a journal that anyone may read is allowed to carry it. The token
itself must never be written here: §6.1 makes it secret-bearing, and a record is
exactly the long-lived, widely readable object its TTL exists to outlive.
`assert_no_secret` checks for the token as well as the password, so putting the
token in this field raises an `AssertionError`.

**`delivery.to` is present only where delivery has a location.** A store path or
an accessor is one. The seen path's destination is a person, reached by a route
the tool did not carry, so `manual` records the method and omits `to` instead of
inventing a value for stdout. `seen` makes that unambiguous, and `seen` is the
field a reader is actually asking about there.

`by` has the lock record's `holder` shape (`sopuli/lock/record.py`), not a second
spelling of the same fact. `correlation_id` joins this record to the run document
that produced it. **`seen` is the field that matters most.** A seen reset is a
deliberate, time-limited exposure (§1). Six months later, the question somebody
asks is not *when was this reset*, but *did a DBA hold a working password for
this account, and which DBA*.

**The destination is a `reset_records:` block**: a `vault:` naming an entry in
`vaults:`, and a `prefix:` with no default. `01-configuration.md` §1 documents
it. The record's path is derived beneath it: `<prefix>/<target>/<account>`. These
rules apply:

- **The store name is resolved at load**, with every other store reference, so a
  misspelled `vault:` is refused while the file is read. If the verb resolved it,
  that failure would come *after* a password had already changed.
- **The account is case-folded into the path, and the target is not.** An Oracle
  account name is matched case-insensitively everywhere else. A path that did not
  fold would let one account own two records that never find each other, so two
  concurrent resets would not collide. That is the failure §3.3 keys the lock to
  prevent. A target name is a `targets:` key, matched exactly. Folding it would
  merge two targets an operator declared as distinct.
- **Invariant 2 is checked against the serialised document**, not trusted to the
  writer. The type has no field a password could go in, but that proves only that
  no writer *in this build* puts one there. `assert_no_secret` walks what is about
  to be written and refuses a password at any depth, in a key as well as a value.
  It runs on the write path, not only in a test.
- **The record path is derived at plan time**, before anything connects. A target
  or account name that is not a single path segment is refused, naming both
  (invariant 4). Two such names could derive one path, which would be one journal
  for two accounts and one lock where there should be two.

**The record is written after the database confirms and after delivery** (§6.4).
On the seen path, "after delivery" is as late as possible: the value is composed
and every guard has passed, a moment before it reaches the screen. `seen` records
the **path**, not whether anyone looked. A `manual` delivery whose prompt was
declined still journals `seen: true`. That is what gives the absent `delivery.to`
its meaning, and a journal that understated an exposure would be wrong in the
direction that matters. A run whose prompt was declined is still journalled, for
the same reason as the run document: the password was set, and the reset that
most needs explaining is the one where nobody received it. For the same reason,
the run prints its result table and its notes before it exits 8, for every target
it reset, the declined one included. The seen path refuses JSON (§6.5), so no run
document carries them. The declined target is not notified, because nothing was
handed over, so it has no `SOPULI-W026`. A decline loses no password the
operator accepted on an earlier target: §6.5 prints each one on its own target.

§3.4 lists the warnings: `SOPULI-W024` when no store is configured, and
`SOPULI-W025` when the write fails after a successful reset. They are separate
codes because the operator's next step differs. An absent journal is a
configuration somebody chose, and a failed write is a store to go and look at.

### 3.2 Why the database is authoritative for *when*, and Q9 is not the precedent

Q9 (decided in #87) chose the opposite for UC-1: the vault's `rotated_at`,
unconditionally, with the database's own timestamp shown beside it. UC-2 differs
from a settled question, so it needs a reason:

- **On the seen path, the owner must change the password** at first logon,
  because that path always issues `PASSWORD EXPIRE` (§1). So the record's
  `reset_at` is **designed** to be overtaken, usually within a day, by a change
  the tool never sees. A record that was authoritative about when the password
  last changed would be wrong in the normal case.
- **The record only knows about resets this tool made.** A password changed by
  hand at a SQL prompt, by a DBA who did not use sopuli, exists only in the
  database.
- **Q9's reason does not carry over.** The vault is authoritative in UC-1
  *because it is master*: its value is the one applications use, so its timestamp
  is the fact. Nothing is master here (§1), so that argument does not apply.

**Reading a timestamp from the database does not break invariant 6.** Invariant 6
governs the *value*: the vault is master of the password, and a write goes from
vault to database, always. UC-2 syncs no value in either direction and reads no
password from anywhere. What is left is the tool reading account state from the
database, which it already does in UC-1 (§1, and UC-1 §5's attributes). **The
database is a source of truth about the account, and never about the password.**

**Both dates are shown, and a disagreement is information.** `account list`
reports the database's change date and the record's `reset_at` as two columns,
not one folded number, for the reason Q9 gave. What the pair means:

| The two dates | Meaning |
|---|---|
| database **later** than `reset_at`, **seen** path | expected: the owner logged in and set their own password, which is what that path is for |
| database **later** than `reset_at`, **unseen** path | **a finding.** Somebody changed the password after the tool delivered it, so the copy the person was told to fetch no longer works |
| database **earlier** than `reset_at`, by more than the skew allowance | the reset did not take, or this release does not answer by the column the run read (§3.4) |
| database **earlier** than `reset_at`, within it | means nothing, and is not reported. The timestamps come from two clocks: `reset_at` from the host that ran `sopuli`, the change date from the database. A few seconds' difference is ordinary drift. The allowance is `sopuli/lock/record.py`'s `CLOCK_SKEW`, which exists for the same reason against the same two clocks |
| no database date | §3.4: the release or the grant; `SOPULI-W021` says which |

Whether the unseen-path disagreement gets a `diagnostics[]` code of its own, or
stays a column an operator reads, is for the verb that displays it to decide.

### 3.3 The lock, and why the record's path is its key

Q2 (decided in #83) keys the advisory lock on the **store and secret path**: one
CAS-guarded record per path under a `locks/` prefix, with the store's version
counter as the fencing token. UC-2 has no secret path. The wrapping-token method
never writes one, and `manual` writes nothing at all. Yet two DBAs can reset the
same person at once, and the second password would overwrite the first before
the person has fetched either.

**The metadata record's path is the lock key.** It exists on the seen path and
the unseen one alike, for every delivery method. There is one per (target,
account), and it is the unit two concurrent resets collide on. Nothing else about
the lock changes: the same `locks/` prefix, the same CAS, the same fencing token,
the same `lock break`.

These rules apply to the reset lock:

- **The lock is taken before the run connects to a database.** So a reset refused
  at exit 7 did not start, and the person's old password still works.
- **The fence is read again just before each target's statements.** A fence lost
  part way through a multi-target run exits **4**, not 7, as `creds generate`
  does. Exit 7 asserts that nothing happened, which is false once one target has
  been reset.
- **A `--dry-run` takes no lock**, for invariant 8's reason: a preview that left a
  claim in the vault would block the run it was previewing.

**`lock status` finds these locks by listing the prefix, not by enumerating
keys.** The listing verb builds its estate from bindings, which come from
`applications:` and `accounts:`, so it would never see a UC-2 lock. Extending
that estate does not work either. A personal account declared by a *predicate*
(H1) has no name until a database is asked, and `lock status` asks none. A
key-by-key expansion would list the accounts declared by name and silently omit
the rest. So `lock status` lists the store under the declared `reset_records:`
prefix and reports what is there, as it does for records at paths the file no
longer declares. It reports these with `declared_by: reset_records`
(`03-json-output.md` §2). `lock break` takes the key on the command line, so it
needs no listing.

**A selector narrows the bindings, not the prefix.** A record path contains its
target, so `--target` could filter on that segment. But a record under this
prefix whose target segment matches nothing declared is exactly the one an
operator needs to see, and such a filter would hide it. A path segment is not a
declaration, so the whole prefix is listed.

**A declared store that cannot be reached refuses the run.** This is not one of
§3.4's absences. The lock lives in the journal's store, so a store that does not
answer means the lock cannot be taken. Nothing has happened yet, which is where
UC-1's lock stores already stop a run. §3.4's absences are about a store that
fails *after* the password changed; there the reset stands and a warning reports
it.

**This holds when the journal and the delivery use different stores** (decided
in [#516](../decisions/log.md#516)). `delivery.vault_wrapped.vault` can name a
store other than `reset_records.vault`, because §3.5 keeps the journal and the
delivery apart. If the journal's store is down and the delivery's store is up,
the run still refuses before any DDL. The delivery could work, but the run could
not take its lock, and a reset without its lock would look like a locked one in
the output.

**To reset during a journal outage, remove `reset_records:`.** The run then takes
no lock and writes no record, and `SOPULI-W024` says so at plan time (§3.4). The
operator chooses this, and the run says what it does not have.

**Where there is no store, there is no lock.** That is the other half of §3.1's
cost, and the reason §3.4's warning says so, not only that no record is written.
A store configured `locking: advisory-only`, or one without `cas`, behaves here
as it does in UC-1 (`01-configuration.md` §9).

### 3.4 When something is missing, say which thing

These absences are not the same:

- **No store configured.** No record is written and no lock is taken. The run
  document and the database are the record for that reset. The run warns with
  `SOPULI-W024`, at plan time, so an operator who did not mean to run this way
  finds out before the password changes.
- **The record write fails, after the reset succeeded.** The run warns with
  `SOPULI-W025`, and succeeds: no rollback and no non-zero exit. The password has
  already changed and the person still needs it, so failing the run would report
  a false negative about the part that mattered. The record is written **after**
  the database confirms and after delivery, so it holds a fact, not an intention,
  and its absence is the case above reached another way. It has its own code
  because the next step differs: this one names a store that answered, and the
  message carries what it said.
- **The database will not say when.** `SOPULI-W021` already tells the causes
  apart: a release with no `DBA_USERS.PASSWORD_CHANGE_DATE` and no
  `SELECT ON SYS.USER$` to read `PTIME` instead, which a grant fixes, or a value
  that could not be read, which is worth investigating (`03-json-output.md`).
  12.2.0.1.0 takes the fallback. 12.1 would too and is unmeasured
  (unverified: pw-changed-source).

**None of these is a refusal**, on purpose. Invariant 4 refuses at plan time when
a command needs a capability it cannot have. A reset needs none of these to do
what it is for. A person who cannot log in is locked out whether or not the
estate keeps history. A tool that refused to help them because it could not
write a journal entry would have its priorities backwards.

### 3.5 What is deliberately not recorded

- **No password, in any form** (invariant 2, §3).
- **No previous value.** There is nothing to roll back to, because rollback is not
  a UC-2 operation. The recovery for a lost personal password is another reset.
- **The unseen path's store copy is not a record.** It exists for the person to
  fetch. Whether it outlives the fetch depends on the method (§6.6), and the tool
  never reads it back as history. A record and a handover in the same store are
  two objects with two lifetimes. Treating them as one would make the handover
  copy live as long as the audit trail.
- **The run document is always a record**, and it never carries a password
  (invariant 2). So is the jsonl stream: `account reset-password` streams under
  `--output jsonl`, and no event carries a password. A real seen reset refuses
  every machine format, so the only seen-path run that can stream is a
  `--dry-run`, which shows no password (`03-json-output.md` §5).

---

## 4. The reset

### 4.1 The statement

**One statement sets the password, and a reset may issue up to three** (H4,
decided in #455). The other two are separate and conditional, not clauses on the
first; §5 gives the reasons. The account is the quoted identifier in the spelling
the dictionary returns, as in UC-1: `account.quoted()` in
`sopuli/driver/oracle/statements.py`. The statements are:

```sql
-- 1. only where the account is LOCKED(TIMED); a deliberate LOCKED is refused (§5)
ALTER USER "<ACCOUNT>" ACCOUNT UNLOCK

-- 2. the reset itself
--    unseen (default)
ALTER USER "<ACCOUNT>" IDENTIFIED BY "<password>"
--    seen (manual)
ALTER USER "<ACCOUNT>" IDENTIFIED BY "<password>" PASSWORD EXPIRE

-- 3. only where a rollover window is open, and not under --keep-rollover (§4.3)
ALTER USER "<ACCOUNT>" EXPIRE PASSWORD ROLLOVER PERIOD
```

Statements 1 and 3 are issued only where the state calls for them. So the usual
reset, of an unlocked account on a profile with no rollover time, is a single
statement.

Setting a password clears an existing `EXPIRED` state. That is Oracle's
behaviour, and UC-1 §5 relies on it too. So the unseen statement is the whole fix
for an account that expired and whose owner no longer knows the password. **It is
not the whole fix for a locked account.** `IDENTIFIED BY` leaves `LOCKED(TIMED)`
exactly as it was, down to the `LOCK_DATE`, and a logon with the *new* password
gives `ORA-28000` (§5, Q3). An expired account is fixed by the password; a locked
one needs statement 1.

What UC-1 §6.1 and `02-oracle-privileges.md` §4 say about issuing `ALTER USER`
applies on both paths:

- **Issued directly, never inside a PL/SQL block** (invariant 13). A block that
  contains `ALTER USER … IDENTIFIED BY` keeps its text verbatim in `V$SQL` on every
  release measured (`docs/measurements.md`). The reason does not depend on the
  suffix: a wrapper is an ordinary block whatever it contains.
- **No password that contains `"`** (invariant 11). It is rejected, never
  escaped, and generation never draws one.
- **What the direct DDL leaves behind depends on the release.** For the unseen
  path's statement it is measured: on 11.2.0.2.0, `V$SQLSTATS` keeps the text
  until the shared pool ages it out or is flushed. 12.2.0.1.0 and every later
  release measured, 19.32.0.0.0 included, keep nothing. 12.1 is unrun
  (unverified: ddl-text-versions). **This is the limit of the unseen path's
  claim.** The claim is about the tool: it puts the value in none of its own
  output. On 11.2, the database itself keeps the statement where a dictionary
  reader, which a DBA usually is, can read it. The tool documents that and does
  not refuse it (decided in #387). **The seen path's `PASSWORD EXPIRE` form has
  not been probed on any release** (unverified: expire-ddl-text). Oracle's masking
  is keyed to the statement type, which gives no reason to expect a difference,
  but that is not a measurement. Quote none of these results without the release.

**The store write and the DDL are two steps, and neither order is free.** Setting
the password first and failing the write leaves an account nobody knows the
password to. Writing first and failing the DDL leaves a store holding a password
that does not work. Another reset recovers both, so this is a smaller problem
than UC-1 §3's ordering. **§6.4 decides it**: the irreversible step goes last.
That is *deliver, then `ALTER USER`* on the unseen path, and *`ALTER USER`, then
print* on the seen one, because what cannot be undone is the DDL on one path and
the print on the other.

`Session.reset_password` in the driver issues all three statements as one
operation. `Session.require_no_rollover_window` is §4.3's refusal, asked at plan
time. These rules apply to the driver:

- **One state read decides all three statements.** Three reads could see three
  different states. An operation that unlocked an account because of a status it
  no longer had would report something that did not happen.
- **Every statement is reported, including the ones not issued**, as
  `apply_attributes` does. An account that was not locked gets a row saying so. A
  caller should not have to read *absent* as *nothing to do*.
- **The window is read from the state before the reset.** `IDENTIFIED BY` on a
  rollover profile *opens* a window. A state read afterwards would show one open
  on every such account, and the row could no longer tell a profile that grants a
  window from an account that has just been given one.
- **`expire` is required, not defaulted.** That is §1 made structural: the seen
  path always expires and the unseen path never does. A caller that has not
  decided which path it is on has not decided what it is doing.

Tier-1 tests check two results on 26ai Free 23.26.2.0.0. A seen reset leaves the
account `EXPIRED` with the **new password still authenticating**: `ORA-28001` is
Oracle's change-at-logon flow, not a refusal. An unseen reset on a rollover
profile leaves the old password answering `ORA-01017` once statement 3 has closed
the window, while `--keep-rollover` leaves **both** passwords working. That is
the exposure §4.3's default removes.

### 4.2 The password

The password is generated from a policy, by the same tier-0 code UC-1 uses
(`01-configuration.md` §8). A seen-path policy is likely to differ, because a
person types the password once, from a message, but generation is the same. The
maximum length is the same question as in UC-1. The tool enforces 30 bytes below
release 23 and 128 bytes from 23. The draw asks each target for its limit, after
connecting and before any DDL, so a long policy is refused on that target with an
`ERROR` row, instead of failing at the statement. A `--dry-run` asks too, and
draws no password: its row is the `ERROR` row the real run would report. That is
the tool's rule, not a measured maximum for every release
(unverified: password-byte-limit).

### 4.3 The rollover window

On a release with gradual password rollover (UC-1 §6.3), an account whose profile
sets `PASSWORD_ROLLOVER_TIME` keeps accepting its **old** password after
`IDENTIFIED BY`, until the window closes.

**On the unseen path, that leaves an exposure.** Anyone who knows the old password
can still log in until the window closes. Usually that is nobody, because the
owner forgot it. But that is a likelihood, not a guarantee, and a reset after a
suspected disclosure is exactly the case where it is somebody.

**The reset ends the window by default** (H4, decided in #455). It issues the
`EXPIRE PASSWORD ROLLOVER PERIOD` statement that `creds finish-rollover` issues.
UC-2 defaults the opposite way to UC-1 here, and that is not a contradiction.
UC-1 §6.3 never chooses `--strategy direct` for the operator because the old
password's holders are applications that have not restarted yet, and the operator
cannot see them. Here the old password's only holder is the person being reset,
and the reset assumes they no longer have it. *A reset means the new password is
the only one that works.* A reset that left the old one working for an hour would
not be one. Reasons: [H4](../decisions/log.md#h4).

These rules follow. The first two are measured on 26ai 23.26.2.0.0
(`sql/oracle/07_lock_and_rollover_probe.sql`, Q6):

- **It is a second statement, not a suffix.** `IDENTIFIED BY`, then
  `EXPIRE PASSWORD ROLLOVER PERIOD`, one after the other in one session, which is
  the shape `--strategy direct` uses. After the first, the status is
  `OPEN & IN ROLLOVER` and **both** passwords work. After the second, the status
  is `OPEN`, the old password gives `ORA-01017`, and the new one works. Issued with
  no window open, the statement is accepted silently and changes nothing. So an
  account whose profile grants no window costs one extra statement and nothing
  else.
- **It closes the window without verifying the change**, which UC-1 §6.3 does not
  do: UC-1 closes only after the change is verified. UC-2 verifies nothing (§5),
  so that precondition is dropped. It is safe here for the same reason as the
  default: nobody holding the old password is cut off.
- **A window outlives the profile that granted it, and the status then
  misleads.** On 26ai Free 23.26.2.0.0, setting `PASSWORD_ROLLOVER_TIME` to zero
  while a window is open leaves `ACCOUNT_STATUS` reading `OPEN & IN ROLLOVER`,
  but the old password **already fails** with `ORA-01017`. What survives the
  profile change is the *status*, not the exposure. The close statement is
  accepted in that state and takes the account back to `OPEN`. So the driver
  closes on either signal, the profile's grant or an open window. That is safe
  under this measurement, and necessary on a release where the old password does
  outlive the change. Unmeasured on releases other than 26ai
  (unverified: stale-rollover).
- **`--keep-rollover` keeps the window**, for a reset where the person *does*
  still know their old password and a grace period helps them. **A reset after a
  suspected disclosure must not use it**, because there the old password is known
  to somebody who should not have it.

**On the seen path, the rollover profile is refused at plan time.** The seen
statement was measured on 26ai 23.26.2.0.0 (Q7) and on 21c 21.3.0.0.0, with the
same answer on both. `IDENTIFIED BY … PASSWORD EXPIRE` **is** accepted on a
rollover profile, the resulting `ACCOUNT_STATUS` is `EXPIRED & IN ROLLOVER`, and
**expiring does not end the old password's window**. The old password answers
`ORA-28001`, not `ORA-01017`: it still authenticates, and it can itself be used to
set the new one. So on this path, the expiry that should end the DBA's exposure
leaves a second working password for the length of the window. 19.32.0.0.0, the
19c release with rollover, has not been measured.

**From `EXPIRED`, the answer is different**
(`sql/oracle/09_reset_from_expired_probe.sql`, 26ai 23.26.2.0.0 and 21c
21.3.0.0.0). This section's main case, an account whose password expired and
whose owner no longer knows it, is in that state. There the same statement opens
no window. Every earlier password gives `ORA-01017`, including the pre-window
one on an account that started `EXPIRED & IN ROLLOVER`, and the new, expired
password is the only one that works. `EXPIRED(GRACE)` behaves like `OPEN`,
because its password still authenticates. So on both releases, the exposure Q7
found depends on whether the old password still works, not on what the profile
grants.

**A seen reset of an account whose profile sets a non-zero rollover time is
refused on that target**, naming the account and the profile, before a password
is drawn or any DDL is issued. The row is `ERROR`. A `--dry-run` asks the same
question and reports the same row. The real run asks again, because the profile
can change between the two. Reasons: [#671](../decisions/log.md#671). The
refusal keys on the profile. Narrowing it to accounts whose
old password still authenticates is an open decision (open: #541). The unseen
path is available for the same account.

### 4.4 Guardrails

The account checks in `02-oracle-privileges.md` §4 apply unchanged, and one of
them conflicts with the scope of this use case. **Check 4 refuses any account
holding `DBA`, `PDB_DBA`, `CDB_DBA` or `AUDIT_ADMIN`**, and DBA accounts are in
scope (§1). So every reset of a DBA's personal account needs `--force`, which
overrides checks 2 to 5 and is recorded in the audit event
([P3](../decisions/log.md#p3)).

This document states that and does not resolve it. It may be the right answer: a
DBA account is where a reset deserves an explicit override. Or it may make
`--force` routine in a way P3 did not intend.

### 4.5 Running it twice

**A reset reports `changed: true` every time, and warns that it replaced
something** (H7, decided in #454). It draws a fresh random password, which has no
target state to converge on. So it is outside invariant 9's scope, like
`creds generate`. Reasons: [H7](../decisions/log.md#h7).

**The warning says more than `generate`'s, because more has already happened.**
`generate` replaces a `pending` that nothing has read yet. A reset has already
changed the database and already delivered. A second run leaves somebody holding a
password that no longer works. On `vault_wrapped`, they will spend their single
unwrap finding that out. The warning says so, not only that a value was replaced.

**The cost falls almost entirely on the unseen path.** The seen path cannot be
scripted: it confirms every time, `--confirm` cannot answer that prompt, and
stdout must be a terminal (§6.5). So a run that silently delivers twice is an
unattended one, which means the unseen path.

#### Why not a convergent verb

Two shapes were considered and rejected:

- **Convergent on a request identity**: a ticket number or `--request-id`, where a
  run again under the same id delivers nothing. §3.1's record already carries
  `correlation_id`, so a `request_id` beside it would be small. It fails because
  of where that record is. An estate need not configure one (§3.1), and the write
  can fail after a successful reset (§3.4), which is exactly the run somebody
  retries. So the key is missing exactly when it is needed, and the verb would
  draw a second password without saying so.
- **Convergent on account state**: reset only an account that has not been
  `EXPIRED` since a recorded reset. **That signal does not exist on the default
  path.** §4.1 issues `PASSWORD EXPIRE` on the seen path only. The unseen
  statement is a plain `IDENTIFIED BY`, and the owner need not change what they
  were given. So `PASSWORD_CHANGE_DATE` stays at `reset_at` and cannot tell
  *fetched and in use* from *never fetched*. Only reading the handover copy back
  could, and §3.5 says the tool never does.

Both would also refuse the recovery this document specifies. §6.4 says the
recovery for either ordering failure is the same reset run again, and §3.5 says
the recovery for a lost personal password is another reset. A verb that refused
the documented recovery by default would need a `--force`-shaped way out for the
ordinary case, which is the wrong way round.

---

## 5. Lockout, unlocking, and self-service

**A reset attempts no login**, so most of UC-1 §7 has nothing to guard. Its
mitigations exist to stop a scheduled *check* from locking an account. What
remains is H4 (decided in #455), and each part of it was measured on a real
database before it was decided, because each depends on what Oracle actually
does.

**A reset never verifies the password it delivered**, by login or by hash, on
either path. On the seen path, a login would consume the `EXPIRED` state that the
reset exists to create. The reason that covers both paths is about the tool:
**verification would put the password somewhere other than the store.** A login
means the tool holds and uses a value that the unseen path otherwise only writes.
A hash comparison needs the optional `SELECT ON SYS.USER$` grant, and must never
bind a value (invariant 14). Both would spend the unseen path's own guarantee to
learn something nobody asked for.

**Reporting `ACCOUNT_STATUS` is not verification, and the reset always does it**,
before and after. UC-1 §7's mitigation 6 is the one part of UC-1's lockout
mitigations that UC-2 keeps.

**The two reads do not cost the same.** The *before* status is already in hand:
`describe_user` reads it as the input to the unlock decision below, to §4.3's
window decision and to §4.4's guardrails, so reporting it adds nothing. The
*after* status is **a second dictionary read**, and it has to be: `ALTER USER`
returns no status, so the DDL's success does not tell the tool what state the
account ended in. Reporting the status from before the reset as the outcome would
be wrong on exactly the runs where it matters: the reset that unlocked an
account, or the one that did not. The status afterwards shows that the reset did
what it said: the `EXPIRED` component on the seen path, and its absence on the
unseen one.

**A reset unlocks `LOCKED(TIMED)` by default, and refuses a deliberate
`LOCKED`.** This is where UC-2 departs from the rule in `01-configuration.md` §8
that every account attribute is opt-in, so it needs the justification that rule
asks for. Measured on 26ai 23.26.2.0.0
(`sql/oracle/07_lock_and_rollover_probe.sql`, Q3 and Q4):

- **`ALTER USER … IDENTIFIED BY` clears neither lock.** Status, `LOCK_DATE` and
  `LCOUNT` are unchanged, and a login with the **new** password gives
  `ORA-28000`. So a reset that does not unlock does not let the person in. It
  fixes what they did not ask about and leaves what they did. §8's rule is for a
  rotation where nobody asked for anything else to change. Here the unlock is
  what was asked for.
- **The two locks are different requests, and Oracle tells them apart.**
  `LOCKED(TIMED)` comes from a failed-login limit: nobody chose it, and
  `PASSWORD_LOCK_TIME` clears it on its own. It is the state a person who asks
  for a reset is usually in. Plain `LOCKED` is one a DBA issued, and on a
  *personal* account that usually means offboarding (`account suspend`). A reset
  that silently cleared it would re-enable an account somebody disabled on
  purpose, and the DBA running the reset need not be the one who disabled it. H1
  narrows this without closing it. Under a **predicate**, a departed person
  leaves the declared set when they are moved to another profile or their role is
  revoked, and that is usually the same offboarding step that locked the account.
  But an enumerated `personal_accounts:` entry stays declared until somebody edits
  the file, and an offboarding nobody completed leaves the predicate admitting
  them either way.
- So plain `LOCKED` **is refused before any DDL.** The account is reported
  `SKIPPED`, naming the lock, with a hint to unlock it first if that is what the
  operator means. **`--force` does not waive it.** It is not one of the account
  guardrails that `--force` overrides; it is somebody's offboarding decision. The
  unseen path has no confirmation prompt to catch it (only the seen path confirms,
  §2), so the refusal is the only place it can show.

**The unlock is its own statement, issued first**, in UC-1 §5's order:
guardrails, unlock, then the password. It is not folded into one
`ALTER USER … ACCOUNT UNLOCK IDENTIFIED BY …`, although Q5 measured that both
clause orders are accepted. There are two reasons. `protocol.py` requires each
attribute to be reported as its own change, and a combined statement would be one
result describing two changes. And no leak probe has been run against the
combined form: every retention result in `02-oracle-privileges.md` §4 is for the
plain `IDENTIFIED BY` form. Two measured statements are better than one
unmeasured statement that only adds atomicity.

**The unlock is read-then-issue, never issued unconditionally**, because of a
measurement. Q1: `ACCOUNT UNLOCK` against an account that is *not* locked is
accepted silently, but **resets `SYS.USER$.LCOUNT`**, from 2 to 0, while
`IDENTIFIED BY` does not (Q2). So an unconditional unlock is not harmless: it
clears the failed-login counter that UC-1 §7's `--lockout-margin` reads. The
driver reads the lock state and issues nothing where there is no lock, reporting
`applied: false`, as UC-1 §5's unlock does. That makes the unlock and the window
close the two *convergent* steps of a verb that is otherwise not convergent. The
verb still reports `changed: true`, because the draw decides that (UC-2 §4.5). The
steps still report `applied: false` for a statement that was not issued, because
*the account was not locked* and *the account was unlocked* are different facts.

**Self-service here means fetching, not resetting.** An owner who knows their
password changes it without the tool: before expiry with
`ALTER USER … IDENTIFIED BY new REPLACE old`, and after expiry at logon. A correct
password against an expired account answers `ORA-28001` and Oracle's change
flow, not a refusal (`tests/driver/test_oracle_verify.py`). **A DBA reset is
needed when the owner no longer knows the password.** Then self-service is the
owner **fetching the new value** from a store meant for them alone, which is the
unseen path. The person never uses the tool or the service account's
`ALTER USER`, so ADR-001's premise, that the operator is a DBA, is unchanged. H5
(decided in #452) rejected a person resetting through the tool. Reasons:
[H5](../decisions/log.md#h5).

---

## 6. Delivery

How the new password reaches the person.

### 6.1 The one binding rule

Everything below follows from one rule (decided in #438):

> **The channel that notifies may be low-trust. The channel that carries the
> secret may not.** "Your new password is ready" may go anywhere; the password, or
> anything that retrieves it, may not.

**"Anything that retrieves it" is the important clause**, and it is broader than
"the password" on purpose. A Vault wrapping token and a one-time link hold no
password, but either one, in the wrong hands, produces one. Treating them as
notifications because they are short-lived and single-use would read the rule as
being about the *value*, when it is about what can *reach* the value.

So **a retrieval credential is secret-bearing, and never travels the notify
channel.** The webhook carries `{account}`, `{target}` and "it is ready". It
does not carry `{wrap_token}` or `{item_link}`, and a template that references
one is refused, not rendered.

**The closed set of placeholders enforces this**, not a list of forbidden names.
A template may use `{account}`, `{target}` and `{expires_at}`. Every other name is
refused at load, because a blocklist would let `{wrapping_token}` through, or
whatever a later method calls its credential. `sopuli/notify.Facts` gives the
same guarantee one layer down. It has a field per placeholder and none for a
password, a token or a link, so the renderer cannot emit what it was never given.
`01-configuration.md` §1 has the grammar.

§6.8 says where such a credential does travel.

### 6.2 The methods

`delivery.method` is a closed set, and the sub-block for the selected method must
exist. A file that breaks either rule is refused at load as config-invalid
(exit 9).

| `method` | Path | The person gets | Built |
|---|---|---|---|
| `vault_wrapped` | unseen | a Vault response-wrapping token, single use | yes |
| `vault_path` | unseen | a KV path only their own identity can read | no (open: #447) |
| `one_time_link` | unseen | a URL that decrypts once | no (open: #445) |
| `onepassword_share` | unseen | an item in a password manager | no (open: #446) |
| `manual` | **seen** | the password, printed to the DBA's terminal | yes |
| `smtp_encrypted` | unseen | encrypted mail the tool sends | no; no issue yet |

A method that is not built is refused when a reset runs, with exit 5, before the
password changes. `config validate` warns about it and exits 0.

**`vault_wrapped` is the default, because it is available**, not because it is
preferred. It works against a stock Vault and needs nothing but the mount the
estate already has. Every other unseen method needs infrastructure the tool does
not create. `vault_path` needs human-identity auth (LDAP, OIDC, userpass) and a
templated policy, and sopuli sets up neither. `one_time_link` needs a Yopass
deployment. `onepassword_share` needs an account. A default that required an
estate to build something first would be a default nobody could use, and the
fallback would silently become `manual`, the one path that shows a DBA a working
password.

**`vault_path` is not wrapping.** Nothing is single-use, the value sits at a path,
and the guarantee comes from the path's policy, not from a token. They are two
methods because they make two different promises, and one of them, as §1 says,
is a promise about a value that persists.

**`smtp_encrypted` is specified only this far:** it is *unseen*, because the tool
encrypts and sends without a DBA reading anything. That is what makes it
different from a DBA emailing a password by hand. The encryption is to a key the
estate holds for the person. Choosing the mechanism (S/MIME, OpenPGP, a keyserver
or a configured key) is a separate issue, when somebody needs it. It is in the
enum so that the enum is the whole set.

### 6.3 Per-method configuration

Each method's own keys are specified with its own issue. This section gives the
shape and the rules that apply to every method. A configuration looks like this:

```yaml
delivery:
  method: vault_wrapped
  vault_wrapped:
    ttl: 15m
    # vault: vault-handover   # optional; else the target's vault, then defaults.vault
  notify:
    method: webhook
    webhook:
      url: { env: SOPULI_NOTIFY_WEBHOOK }
      template: "{account} on {target} has a new password waiting"
```

**These constraints apply to every method**, and each exists because the obvious
implementation breaks it:

- **Secret-bearing keys are MaterialRefs** (C9), never plain strings. A webhook
  URL often embeds its own token, a 1Password Connect token is a credential, and
  a key written inline in a config file is a credential in a repository. Use
  `{ env: NAME }` or `{ file: PATH }`. They are redacted wherever the config is
  shown.
- **A method that opens a socket ships as an install extra** (ADR-006), and the
  base install still opens none. A method that is configured but not installed
  follows E4/E5: `config validate` warns and exits 0, and using it fails with
  exit 9. `manual` is the only method in the table that needs no extra. So the
  fallback for an estate that can install nothing is the path that shows the DBA
  the password. That is an argument for building `smtp_encrypted`.
- **Delivery events are named `noun.verb`** (`03-json-output.md` §5).
  `password.delivered` is emitted on success when `account reset-password`
  streams under `--output jsonl`. `password.displayed`, the seen path's exposure,
  is a registered name that is never emitted: a seen reset refuses every machine
  format, `jsonl` included, and its `--dry-run` displays nothing. Neither event
  carries the password, and the run schema has no property that could. A real
  unseen delivery records the handover in `results[].handover` in the run
  document: the accessor that names the handover, never the credential that
  performs it. A `manual` row and a `--dry-run` row have no `handover`.

**`manual` requires `force_expire: true`**. A `manual` block without it is
refused when the config is loaded, as config-invalid (exit 9), so
`config validate` fails too (§6.5). That is the configuration half of the seen
path's guarantee: the exposure ends at the person's next logon, or it does not
end at all.

### 6.4 The order of the two steps

A reset both **writes the password somewhere** and **issues the DDL**. Neither
order is free (§4.1), so the order is a choice.

**The rule is that the irreversible step goes last.** That gives a different
order on each path, because what is irreversible differs:

| Path | Order | The irreversible step |
|---|---|---|
| unseen | **deliver, then `ALTER USER`** | the DDL: it kills the old password |
| seen (`manual`) | **`ALTER USER`, then print** | the print: nobody can unsee it |

**On the unseen path, deliver first.** Compare the two failures:

- **DDL first, delivery fails:** the account has a password nobody holds. The
  person is *worse off than before the run*: they could not log in, and now nobody
  can.
- **Delivery first, DDL fails:** the store holds a value that authenticates
  nothing, and **the person's old password still works**, because the DDL never
  ran. Nobody is worse off than they were.

The second can always be recovered, and the first cannot, so the order follows.
The cost is a window in which the store holds a password the account does not
have. A person who fetches during it gets a value that fails, and on
`vault_wrapped` spends their single unwrap on it. That is confusing; the other
order is a lockout. Another reset cures both (§3.5), but only one of them needs
somebody other than the person who is already locked out.

**On the seen path, issue the DDL first.** The rule is the same, with the
irreversible step in the other place. Printing a password that was never set
tells a DBA something false, and the DBA will pass it on. Neither half can be
undone. Setting the password first means the value on the screen is the account's
password by the time anybody reads it.

**The record is written after both** (§3.1). That is not a third ordering
question: the record holds what happened, so writing it earlier would make it
hold an intention.

**This is not a two-phase commit.** UC-1 §3's `pending` → `current` ordering
exists because something reads the vault at runtime, and invariant 7 protects that
window. Nothing reads this value at runtime: a person fetches it once. So the
ordering is a choice of *which failure to prefer*, not a protocol, and the
recovery for either is the same reset run again.

**A failure between §4.1's statements is a third case** (decided in #528). DDL
commits as it goes, so when a statement fails after an earlier one ran, the
earlier one stays done. The row is `ERROR` with exit 4 either way, with
`changed: true` and the committed statements reported as applied. What happens
next depends on whether the password was set:

| Committed | Failed | Password | Handed over | Record and notify |
|---|---|---|---|---|
| `ACCOUNT UNLOCK` | the set | unchanged, the old one works | **no** | no |
| the set | the window close | **live**, and the old one may work until the window ends | **yes** | yes |

The first is this section's recoverable failure, with one extra step done. The
token already made would retrieve a value that authenticates nothing, so it is
not printed. The timed lock is gone, and the row says so instead of calling the
account untouched.

The second is handed over, because withholding it is the lockout this section
orders the steps to avoid. On the seen path, nobody would hold the expired
password the account now has. On an unseen one, the token has already been made,
and discarding it leaves a live password nobody can fetch. The state it leaves is
the one `--keep-rollover` leaves on purpose (§4.3), so it is not a new kind of
exposure. The row still fails, because the reset promised that the old password
would stop working, and it may not have. The record is written, because it holds
what happened, and a password was reset. It has no field for the open window,
which is in the run document.

### 6.5 The seen path, and what narrows it

**`manual` is the one method that shows a working password to somebody who is not
its owner.** #439 decided that it may, and how narrow that stays. `CLAUDE.md`
invariant 2 lists it as its fourth exception. The five guards are:

| Guard | Why |
|---|---|
| one reveal site, in the seen path's view, reachable only when `delivery.method` is `manual` | the exception stays narrow by structure, not by care, as the third exception does |
| refused with `--output json` and `--output jsonl`; no schema property can hold the value | as `--reveal` already is: a machine-readable document must never carry it |
| **refused unless stdout is a terminal** | `--reveal` has no such guard, and this is the guard that carries the argument. A value redirected to a file or captured in a CI log outlives the single logon it is good for, because a log is read later and by other people, and expiry does not unpublish it. `\| clip` stops working; that cost is accepted |
| confirmed every time, and `--confirm` does not answer it (§2). Refused unless stdin is a terminal, checked before the password is drawn | a yes given in advance asserts what the prompt exists to establish. The prompt comes after the password is set, so a closed stdin would leave a password nobody has seen, and a pipe such as `yes \|` would give the yes in advance |
| `force_expire: true` required; a `manual` block without it is refused when the config is loaded (exit 9) | the exposure ends at the person's next logon, or it does not end at all |

**A `--dry-run` is exempt from guards 2 to 4.** A preview prints a plan and never a
password (§2), so those guards have no emission to guard. Refusing a preview for
want of a terminal would make *show me what this would do* impossible from the
CI job that most wants it. Guard 5 still applies to a preview, because it is a
property of the file, not of an emission: a `manual` block without
`force_expire: true` is refused whether or not anything runs.

**Each password prints on its own target**, after its record is written and
before the next target starts, and not at the end of the run. On a run over
several targets, the operator may accept the prompt on one target and decline it
on a later one. The decline aborts the run. A password held back for the end
would then never be shown, and its account would keep an expired password that
nobody holds. Printing on the target adds no emission, because every guard has
passed by then. A finished run therefore shows each password before the result
table. Reasons: [#741](../decisions/log.md#741).

`tests/test_reveal_sites.py` enforces guard 1. It parses `src/` and fails on a
`reveal()` call in a module that holds none of invariant 2's sites, and on a
second call in the seen path's view.

**The justification is different from `policy sample --reveal`'s, and weaker**,
so the guards are stricter. A sample protects nothing; this is a credential
somebody can log in with. What allows it is not that it is harmless, but that it
is deliberate, witnessed and time-limited. The exposure is the purpose of the
path, not a side effect of it (§1).

### 6.6 The unseen paths, and what each actually promises

They are not one guarantee with several implementations. The config key makes them
look interchangeable, so this section says how they differ.

- **`vault_wrapped`**: single use. The unwrap is the last read, so a value fetched
  twice is a value somebody else fetched first. **Interception is detectable even
  where it is not preventable.** That is the strongest property in the list, and
  it comes with the weakest: the token is a **bearer credential**, so whoever
  holds it can unwrap it, whatever their identity. **The single use is Vault's,
  not the tool's.** On the tier-1 Vault, the second unwrap answers 400. There is no
  `num_uses` to configure, because the tool keeps no counter.
- **`vault_path`**: owner-only by the store's own access control, for as long as
  the path's policy says so. It uses identity instead of a bearer token, which is
  the opposite trade. Interception needs the person's own credentials, but
  nothing makes the read single-use, so **the value stays a live credential**
  until something removes it. That something could be the next reset overwriting
  it, or a destroy on a clock, since KV has no after-first-read hook. It is not
  decided (open: #447). §1's principle narrows it: a copy that persists keeps the
  one unattributable route open for as long as it exists, and the password is
  worth something beyond the one database.
- **`one_time_link`**: one use, like the wrapping token, and a bearer credential
  for the same reason: the URL carries its own decryption key in the fragment. It
  adds a third party to the trust story, which the two Vault methods do not.
- **`onepassword_share`**: whatever 1Password's API offers, which is not yet known
  (open: #446). If single view has to be simulated with a follow-up delete, the
  documentation must not claim single view.
- **`smtp_encrypted`**: as strong as the recipient's key management, and no
  stronger.

**What the DBA is shown on `vault_wrapped`, and where.** The password goes to
Vault and to nobody else. What comes back is the token, and the tool prints it,
because §6.1 bars it from the notify channel and the tool has no other channel.
These rules apply, and the second has no counterpart on the seen path:

- **Never in the run document, and no property could hold it.** A document is
  captured, shipped to log aggregation and kept. A token in one would outlive the
  TTL that is this method's whole guarantee. The document carries the *accessor*
  instead, in `results[].handover` beside the expiry. The accessor names the
  handover and cannot perform it, so a run stays auditable without the document
  leaking.
- **No terminal is required**, unlike `manual`'s third guard. A pipe is how a
  handover script works. Forbidding one would leave an estate no way to deliver
  unattended except the path that shows a DBA a password. The cost: a redirect to
  a file outlives the token. The trade is different because of the object:
  fifteen single-use minutes whose one use is detectable, against a password
  good until somebody's first logon. **It is also where §1's attribution
  guarantee stops** (H9, decided in #496): whoever reads the redirect can unwrap
  with no name attached.
- **Under `--output json`, the token goes to stderr**, because stdout carries the
  document. `manual` is *refused* with `--output json`; this method is not. The
  document is what makes a scheduled reset auditable, and taking it away would
  make an estate choose between an audit trail and the default method.

**"The DBA never sees it" must be true of the store, not only asserted.** A DBA
whose store token can read the person's path could read the password back, and
the unseen path's reason for skipping expiry would be gone. So the tool checks
(H8, decided in #459). Before writing, `vault_path` asks Vault for the DBA token's
capabilities on the person's path (`sys/capabilities-self`), and **refuses at plan
time if they include `read` or `root`**, naming the path and the policy
(invariant 4). `root` matters: a root-policy token answers `["root"]` and never
lists `read`, so a check for `read` alone would admit the one token that can read
everything. On the tier-1 Vault (2.0.4), a root token answered `["root"]`, a token
scoped to the write `["create","update"]`, and one also granted read
`["create","read","update"]`. The tool does not proceed on documentation alone,
which would let a misconfigured policy silently turn an unseen reset into a seen
one that was never expired. It does not fall back to the seen path either, which
would swap one guarantee for another without being asked. The check is built with
`vault_path` (open: #447). On `vault_wrapped` the question does not arise: the
DBA's token never holds the wrapping token's cubbyhole. What the DBA holds is the
token itself, and §1 says what that is worth.

### 6.7 Reusable by UC-4

The abstraction is a **delivery method that takes a value and a recipient**. It is
not a property of resetting a password. UC-4's onboarding hands a person a first
credential, which is the same operation for a different reason. So `delivery:` is
specified here, under UC-2, but it is not named for it, and nothing in the block
refers to a reset. A method needs the value, the account, the target and a notify
channel. It must never need to know *why*.

That constrains the implementation: a method that reached for the reset record
(§3), or for `seen` or `expired`, would not work when called by a use case that
has neither.

### 6.8 Where a retrieval credential travels, and restricting methods

§6.1 says a retrieval credential never travels the notify channel. It travels
**nowhere the tool carries it**: the wrapping token comes back to the DBA's
terminal, and the handover to the person is out of band.

**That is decided** (H9, decided in #496). "The DBA never sees the password" stays
literally true, and "the DBA cannot obtain it" does not, because the token is a
bearer credential. What the method promises instead is §1's: an unwrap the person
did not make is detectable, through their failed fetch. Where Vault has an audit
device enabled, the unwrap is also attributable. The device records the wrap
under the DBA's identity and the unwrap under the same accessor HMAC, and the
accessor in the run document finds both. Without a device, or once a token has
been redirected to a place other people read, that stops, as §1 and §6.6 say.
Reasons: [H9](../decisions/log.md#h9).

Two stronger answers were rejected. **Making `vault_path` the default** fails
§6.2's availability argument: it needs human-identity auth and a templated policy
that the tool does not create, and an estate that cannot use the default falls
back to `manual`, the seen path. **A second, "trusted" notify channel** for
retrieval credentials would rest on a trust level declared in configuration. That
is an assertion by whoever wrote the file, which is the kind of guarantee §6.6
refuses for the store.

**An estate restricts the set of methods with `safety.delivery.allowed_methods`**
(H6, decided in #453). It ratchets by **intersection**, so each layer may only
narrow it, and no higher-authority layer can restore a method that a lower one
removed. It fails closed on purpose: a method that a later release adds is
unusable until an estate names it. A `forbidden_methods` union would do the
opposite on upgrade, and this guard stands in front of putting a live credential
on a wire. Its merge shape is declared, not read off its type;
`01-configuration.md` §9 has the rules. The key is read from any `safety:` block,
and the intersection is taken across every layer, including a target's and a
group's. Two layers with no method in common are refused at plan time, naming all
of them. `config show --explain` reports the effective set and which layer
narrowed it. `account reset-password` checks it before anything connects
(`safety.refuse_disallowed_method`), and refuses a method that no layer permits.
Reasons: [H6](../decisions/log.md#h6).

---

## 7. The invariants, read for UC-2

| # | Invariant | Here |
|---|---|---|
| 1 | no secret in `argv` | applies unchanged, including every store credential |
| 2 | redaction at the serialiser | applies. §3's metadata record is inside it, not an exception to it: it holds no password in any form, not a hash and not a verifier. A **Vault** write is already a permitted plaintext site, so the Vault methods need no widening. The other stores (`one_time_link`, `onepassword_share`, `smtp_encrypted`) are not automatically permitted, and each says how it keeps the invariant when it is built. **The seen path's display is the invariant's fourth exception** (decided in #439), under §6.5's five guards. It is allowed because the exposure is deliberate, witnessed and expired, not because it is harmless; harmlessness is the third exception's argument and does not apply here. The wrapping token an unseen delivery returns is the fifth (§6.6) |
| 3 | branch on capability, not version | applies: rollover (§4.3) is a capability |
| 4 | unavailable capability fails at plan time | applies: §4.4's guardrails, and `vault_path`'s store-capability check (§6.6). §4.3's seen-path refusal and §4.2's byte limit are asked on each target before any DDL, and a `--dry-run` asks them too ([#671](../decisions/log.md#671)). §3.4's absences are deliberately **not** on that list: a reset needs none of them to do what it is for |
| 5 | the config is the whitelist | applies, with H1's addition: a personal account is declared in `personal_accounts:` by name or by predicate, and a predicate never widens what a mutating verb may touch. Selectors still cannot extend the declared set (§2) |
| 6 | vault is master | nothing to govern, because there is no master (§1). H2 makes the database authoritative for **when** a password last changed. That does not break this invariant: invariant 6 governs the value, and a timestamp about the account is not the value (§3.2) |
| 7 | never promote before confirmation | nothing to govern: there is no promotion (§1) |
| 8 | `--dry-run` and a plan first | applies, on both paths; the seen path also confirms (§2) |
| 9 | idempotency | **applies, and does not govern the reset** (H7). A verb that draws a fresh random password has no target state to converge on, so `account reset-password` is outside the invariant, like `creds generate`. It reports `changed: true` every run and warns what it replaced (§4.5). `expire-password`, `suspend` and `list` are inside the invariant and hold it |
| 10 | safety settings only ratchet | applies, and H6 adds a setting: `safety.delivery.allowed_methods`, ratcheting by **intersection** (§6.8). `01-configuration.md` §9 has the shape, and `00-principles.md` P3 says why it is not a union. It is a `delivery:` sub-block of a `safety:` block, not a key of the `delivery:` block it governs |
| 11 | no `"` in a password | applies, by generation |
| 12 | JSON output is versioned | applies: new verbs and events are schema bumps |
| 13 | no password literal in a PL/SQL block | applies to both statements (§4.1) |
| 14 | no password bound into a predicate | applies, and nothing here reaches it: a reset never verifies, by hash or otherwise (§5) |

Invariants 6 and 7 do not govern here because of what this use case is, not
because of an exemption. A store here holds a value for one person to fetch,
never a value to sync from. The metadata record does not change that: nothing
fetches a value from it either, because it holds none (§3.1).

---

## 8. Testing

Tier 1 covers the core: Oracle Free with its rollover capability, and the Vault
container the unseen path writes to. Tier 0 covers everything with no I/O: the
plan, the refusals, the confirmation, generation, and the statement text, which is
where invariant 13's check already lives for UC-1.

A test must show:

- **unseen:** after a reset, the account is not `EXPIRED`. The value can be
  retrieved by the owner's identity or wrapping token, and on `vault_path` by
  nothing the DBA's token can read (§6.6). The statement sent carries no
  `PASSWORD EXPIRE`. The password appears in no output of the tool at all.
- **seen:** the reset does not run without confirmation. Afterwards,
  `DBA_USERS.ACCOUNT_STATUS` has the `EXPIRED` component, and for an account
  that is not locked, a logon with the password is forced to change it. A
  rollover profile is refused before any DDL (§4.3). The password is emitted
  exactly once, to stdout, and nowhere else. **Each of §6.5's five guards is its
  own test, and all five are tier 0**, because none needs a database: the reveal
  site is unreachable for any delivery method other than `manual`;
  `--output json` and `--output jsonl` are refused; a non-terminal stdout is
  refused; `--confirm` is refused as a usage error; and `manual` without
  `force_expire: true` is refused when the config is loaded. The schema
  restriction is **part of the second guard**: `--output json` is refused, *and*
  no property of a result could hold a password. It is checked against the
  published schema, as `policy sample`'s is, not against a run.
- **H4's behaviours (§5, §4.3).** Each is a tier-1 test, because each was a
  measurement first. **The unlock test differs by path.** On the **unseen** path,
  a reset of a `LOCKED(TIMED)` account leaves it `OPEN`, and the owner can log in
  with the new password and nothing else. On the **seen** path, the same reset
  leaves `EXPIRED`, so the test checks that the first logon is **forced to change
  the password**, never a plain login. Then, on both paths: a reset of a
  deliberately `LOCKED` account is refused and issues no DDL. An account that is
  not locked gets no `ACCOUNT UNLOCK` statement at all, checked by reading
  `SYS.USER$.LCOUNT` across the reset and finding it unchanged. A reset on a
  rollover profile leaves the old password answering `ORA-01017`, and
  `--keep-rollover` is the one way to see `OPEN & IN ROLLOVER` afterwards.
- **The record (§3):** it is written after the database confirms, not before. It
  contains no password in any form; that is a tier-0 test on the serialised
  document, not a tier-1 test on what the store received. A reset with no store
  configured still succeeds and warns at plan time. Two concurrent resets of one
  (target, account) collide on the lock that its path keys.
- **Both paths:** the password appears in no run document, diagnostic or log
  sink, and in no jsonl event. The seen path's one deliberate emission is the only
  exception, and its confirmation guards it.
- **The measurement behind the seen path's open marker**: gate 2's probe extended
  to the `PASSWORD EXPIRE` form (unverified: expire-ddl-text). Only a run can
  remove the marker. §4.3's window behaviour on the seen path is already measured
  on 26ai Free 23.26.2.0.0 and 21.3.0.0.0.

Tests declare the capabilities they need and skip with a reason when one is
absent (`04-testing.md`). They never branch on a version.

---

## 9. Open questions

| # | Question | Issue |
|---|---|---|
| ~~H1~~ | ~~Where is a personal account declared, so invariant 5 still whitelists it?~~ | **closed** — a `personal_accounts:` section, by name or by a predicate over a profile or role; a mutating verb names its one account (§2). Reasons: [H1](../decisions/log.md#h1) · #449 |
| ~~H2~~ | ~~With no vault as master, what is recorded about a reset, and where?~~ | **closed** — the database records when, an optional metadata record records who and where, and nothing records a rollback value (§3). Reasons: [H2](../decisions/log.md#h2) · #450 |
| ~~H3~~ | ~~The noun and the verbs~~ | **closed** — the noun `account`, with `reset-password`, `expire-password`, `suspend` and `list` (§2). Reasons: [H3](../decisions/log.md#h3) · #451 |
| ~~H4~~ | ~~Does a reset verify the password, unlock (including `LOCKED(TIMED)`), or end a rollover window?~~ | **closed** — never verifies; unlocks `LOCKED(TIMED)` and refuses `LOCKED`; ends the rollover window by default (§4.3, §5). Reasons: [H4](../decisions/log.md#h4) · #455 |
| ~~H5~~ | ~~Is self-service part of UC-2?~~ | **closed** — self-service means fetching the password from a secure store, not resetting through the tool (§5). Reasons: [H5](../decisions/log.md#h5) · #452 |
| ~~H6~~ | ~~Restricting delivery methods: an `allowed_methods` intersection or a `forbidden_methods` union?~~ | **closed** — `safety.delivery.allowed_methods`, merged by intersection; no `forbidden_methods`. Reasons: [H6](../decisions/log.md#h6) · #453 |
| ~~H7~~ | ~~A reset never converges: a second invariant-9 exemption, or a convergent verb?~~ | **closed** — reports `changed: true` every run; invariant 9 is restated as a scope rule (§4.5). Reasons: [H7](../decisions/log.md#h7) · #454 |
| ~~H8~~ | ~~On the unseen path, what happens to the stored copy, and how is the DBA shown unable to read it?~~ | **closed** — split by method: `vault_wrapped` keeps nothing, `vault_path` refuses a DBA token that can read (§6.6). Reasons: [H8](../decisions/log.md#h8) · #459 |
| ~~H9~~ | ~~On `vault_wrapped`, the DBA holds the token — so what does "unseen" guarantee, and is there a channel the tool should carry a retrieval credential by instead?~~ | **closed** — attribution, not access; no second channel (§1, §6.8). Reasons: [H9](../decisions/log.md#h9) · #496 |
| ~~H10~~ | ~~§1's attribution guarantee holds only where the database audits `ALTER USER` and logons. Does a reset check that, and warn, refuse or record what it found?~~ | **closed** — an unseen reset records `audited` as `true`, `false` or `unknown`, and does not warn or refuse (§1). Reasons: [H10](../decisions/log.md#h10) · #591 |
| ~~—~~ | ~~How the seen path's one plaintext emission is narrowed, and whether `--confirm` answers its prompt in advance~~ | **closed** — it prints, under five structural guards (§6.5): one reveal site, refused with `--output json`/`jsonl` and unrepresentable in the schema, refused unless stdout is a terminal, confirmed every time with `--confirm` **not** answering it and stdin required to be a terminal (#853), and `force_expire: true` required. `CLAUDE.md` invariant 2's fourth exception · #439 |
| ~~—~~ | ~~When the reset journal's store and the delivery store are different vaults, and the journal's is down, does the run refuse or deliver without a lock and a record (§3.3)?~~ | **closed** — it refuses before any DDL; to reset during a journal outage, remove `reset_records:` and `SOPULI-W024` says so (§3.3). Reasons: [#516](../decisions/log.md#516) · #516 |
| — | Should the seen reset's rollover refusal narrow to accounts whose old password still authenticates (§4.3)? | #541 |

§4.4's conflict between guardrail check 4 and DBA accounts is not a question with
an issue. It is P3 applied to a population it was not written for, stated here so
that it is not rediscovered.

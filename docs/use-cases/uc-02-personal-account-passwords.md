# UC-2 — Personal account passwords: reset and hand over

Status: partly built. §9 lists what is still open, and each open question is a
`decision` issue. What an operator can run today: `personal_accounts:` (#467),
**`sopuli account suspend`** (#463), **`sopuli account list`** (#490), and
**`sopuli account reset-password`** on the seen path (#441) and the default unseen
one (`vault_wrapped`, #444), and **`sopuli account expire-password`** (#525).
Depends on: `../design/00-principles.md`, `../design/01-configuration.md`,
`../design/02-oracle-privileges.md`

The whole specification (#438), in two parts as it was written: the reset in #457
and delivery — the methods by which a new password reaches a person — in #456, §6.

---

## 1. Summary

**Goal.** A person cannot get into their own database account — a developer's, a
tester's, a DBA's — usually because the password expired and they no longer know
it. A DBA resets it, and the tool makes the new password **the person's alone**.
There are two ways to get there, they do not give the same guarantee, and which one
a reset takes decides almost everything else in this document:

| Path | The DBA sees the password | How the person gets it | Expired on reset |
|---|---|---|---|
| **unseen** — the default | no | fetches it from a store meant for them alone: a single-use wrapping token (#444, the default), a Vault path only their identity can read (#447), a one-time link (#445), a password manager (#446) or encrypted mail — §6 says what each actually promises | **no** |
| **seen** — `manual` | yes | the DBA passes it on — encrypted email or similar — with instructions to change it | **yes, always** |

**The unseen path is the default**, and it is what the tool exists to make possible:
a DBA resets a password without ever seeing it, and the tool puts the value in none
of its own output. Nothing needs expiring, because nobody but the person is meant
ever to know it — §4.1 and H8 say where that intent meets its limits.

**"Never sees it" and "cannot obtain it" are different promises**, and §6.8 (H9)
is where the difference bites. On the default method the DBA holds a *wrapping
token*, and a token is something that can be unwrapped. What the single use buys is
that doing so is **detectable** — the person's fetch fails, and somebody knows —
rather than prevented. This section claims the first promise and not the second,
which is a narrower claim than the table above used to imply.

**What the unseen path guarantees, and on what condition** (accepted as the
principle on #459 and #496, both of which stay open). It does not defend against a privileged DBA, and could not: whoever can
reset a personal account's password can also connect *as* that person, by
`ALTER USER person GRANT CONNECT THROUGH dba` — which needs only `ALTER USER`, the
privilege this tool's service account is built around — and connect with their own
password. Measured, not taken from the documentation: on 26ai 23.26.2.0.0 the
grant succeeds with `CREATE SESSION` and `ALTER USER` and nothing else, the session
reports `USER` as the person and `PROXY_USER` as the DBA, and the same privilege
revokes the grant again, leaving `DBA_PROXIES` empty
(`sql/oracle/11_proxy_connect_probe.sql`, #589). So the guarantee is about
*attribution*, not access:

> **Where the database audits `ALTER USER` and logons, the unseen path guarantees
> that the DBA cannot act as the person without leaving their own name behind.
> Where it does not, the unseen path only keeps the password from being usable
> beyond that one database.**

The condition is the measured part. A reset to a known value and a proxy session
both point at the DBA — but only in an audit trail: the proxy grant can be revoked,
and a reset leaves `PASSWORD_CHANGE_DATE` and a person locked out, neither of which
says who did it. With no unified audit policy enabled
— FREEPDB1's default — the same probe found the grant, the proxy logon and the
revoke recorded **nowhere**; with a `LOGON, ALTER USER` policy, every step was
recorded, and the proxy logon names the DBA in `DBPROXY_USERNAME`. Knowing the
person's actual password is the one route on which the record names only the person,
and closing that route is what "unseen" is for. On a database that audits neither,
the DBA can already act as the person there without a trace, and what the unseen
path still protects is the password's value *elsewhere* — on the person's other
targets, and wherever they reused it — because a proxy grant is per database and a
password is not.

**The condition is stated, not checked.** The tool creates no audit policy and
reads none. Whether a reset should check that one is enabled, and warn, refuse or
record what it found, is H10 (#591). Not measured: whether a DBA who also holds
`AUDIT SYSTEM` can disable the policy first; and every release but 26ai. H8 and H9
are still open, and this sentence is the yardstick their answers are measured by.

**The seen path is the traditional one**, and it is not the default. The DBA
generates the password, sees it, and sends it on. **That is a deliberate,
time-limited exposure, not the same guarantee by another route**: until the owner's
first logon the DBA holds a working password, and `PASSWORD EXPIRE` forces a change
at first logon without deciding *who* logs in first. Expiry is what ends the
exposure — once the owner has set their own password, the one the DBA saw is dead —
so on this path expiry is forced, not offered, and the command asks for
confirmation before it runs (§2).

**Actors.**

| Actor | Role |
|---|---|
| DBA | runs the reset, usually because somebody asked for one |
| Account owner | fetches the password (unseen) or receives it (seen), and logs in |
| Secure store | holds the password for the owner to fetch — a Vault first (§6.2) |

**Direction of truth.** There isn't one, and that is the first way this differs
from UC-1. `docs/README.md` puts it as *a password is handed over, not synced*.
Nothing reads the value to stay in step with it, so no store is master of it. On
the unseen path a store does hold it for the person to fetch, and that is
transport, not mastery; what happens to that copy afterwards is H8 (#459).
Invariants 6 and 7 therefore have nothing to govern here (§7). **That does not
make the database a source of truth either**: the tool reads account state from
it, as UC-1 does, and never a password. §3.2 makes that boundary precise, because
H2 (#450) puts the database on the authoritative side of one question — *when* the
password last changed — and nowhere near the value.

**Why this cannot be a mode of UC-1**, from the roadmap, each point being a place
UC-1's design would do the wrong thing:

- **Expiring deliberately is correct on the seen path.** `PASSWORD EXPIRE` breaks an
  application account — which is why UC-1 §5 has no such attribute and sent the
  operation here (#302).
- **Lockout tolerance is different.** UC-1 §7's apparatus exists because locking a
  production application account is an outage. Locking a developer out of their
  own account is not (§5).
- **Nothing is promoted, so nothing waits on confirmation from a target.** UC-1's
  safety design is the ordering of `pending` → `current`. A handover has no
  `current`.

**Non-goals.** Creating, dropping or granting accounts (UC-4). Application
accounts (UC-1). A person changing their own password through the tool — an owner
who knows their password changes it without one (§5). Keeping any copy of the
password as a record of it.

---

## 2. Commands

**The noun is `account`** — H3 (#451), decided. Not `user`, although Oracle says
user and the driver agrees with it (`describe_user`, `UserState`): *account* is
the word the configuration already uses for the thing being managed, and every
other noun in this CLI mirrors the file an operator edits rather than the
database — `target`, `policy`, `lock`, `creds`. D2's noun-verb grammar is
satisfied either way, so the tie goes to the configuration's own vocabulary.

**That settled the word and nothing about the file**, and H1 (#449) has since
settled the file: a `personal_accounts:` section of its own, holding names or a
predicate. The noun never rested on which — the argument was only that somebody
who reads `accounts:` in a configuration file should not have to type `user` at a
prompt — and it holds unchanged now that the answer is a different key.

| Command | What it does | Mutates |
|---|---|---|
| `sopuli account reset-password` | **unseen, the default**: generate a password, set it, write it where only the owner is meant to fetch it; show it to nobody. **Built** for `vault_wrapped` (#444); a file naming an unseen method that is not implemented yet (#445-#447, `smtp_encrypted`) is refused at plan time on exit 5, before the password changes | yes |
| `sopuli account reset-password`, `manual` | **seen**: generate a password, set it **with expiry**, show it once — after confirmation. **Built** (#441), under §6.5's five guards | yes |
| `sopuli account expire-password` | `PASSWORD EXPIRE` with no new password — "make them change it". Closes an open rollover window first. **Built** (#525) | yes |
| `sopuli account list` | resolve the declaration — names, or a predicate over a profile or role — and report what it matched, with each account's state. Reads no password and writes none (H1, #449) | no |
| any of the mutating verbs, under `--dry-run` | prints the plan and never a password (invariant 8, which binds on every one of them — not the resets alone) | no |

**The seen reset asks for confirmation every time** — decided on review of #457,
and recorded in P5 beside the two gates that already do, `creds rotate` and
`lock break`. Like them it does not consult `safety.confirm_environments`, and it
is not a setting a layer could relax.

**`--confirm` does not answer it** (#439, decided), which makes it the one gate in
the tool that cannot be given a yes in advance. The reason is not that this
operation is more dangerous than a rotation — it is that the prompt here is not a
formality to be waived. The run is about to print a working password to a screen,
and `--confirm` would assert that somebody is watching when establishing that
somebody is watching is the entire purpose of the gate. A flag cannot testify to
its own premise.

It is the same claim the terminal check below makes, made twice deliberately: if
nobody is present to answer, nobody is present to receive the password either.

**`expire-password` is its own verb rather than a flag on the reset**, which is
the half of H3 this section used to leave open. The two operations differ in what
they take, not only in what they do: a reset draws a password and therefore needs
somewhere to deliver it, while expiring one needs neither a password nor a
delivery method. As a flag it would leave the reset's delivery arguments
meaningless in half its invocations, which is how a verb acquires options that are
errors in most combinations.

**It closes an open rollover window before it expires** — #525, option (b),
decided rather than inherited. `sql/oracle/08_expire_password_probe.sql` measured
the bare statement on 26ai Free 23.26.2.0.0, twice. Expiring an account with a
window open leaves `EXPIRED & IN ROLLOVER`, and the **old** password still answers
`ORA-28001`: it authenticates, and it is itself a way to set the next one. That is
§4.3's Q7 finding again, now on the form that sets no password. Closing first
kills it (`ORA-01017`), which is the reset's default for the reason §4.3 gives:
the only holder of the old password is the person whose account this is.

Four things follow from that, and each is measured or decided rather than assumed:

- **Close, then expire.** Both orders end in plain `EXPIRED`. They differ only
  when the second statement fails: close-then-expire leaves `OPEN` with the old
  password already dead, while the reverse would leave option (a)'s state by
  accident.
- **Only an open window is closed**, not a profile that merely grants one. A bare
  expiry sets no password and so opens no window; on a rollover profile with none
  open it leaves plain `EXPIRED`. The reset closes on the wider test because its
  own `IDENTIFIED BY` opens one.
- **The converged state is `EXPIRED` with no window open** (invariant 9). Oracle
  accepts a second `PASSWORD EXPIRE` silently, so the driver reads the state
  first. An account at `EXPIRED & IN ROLLOVER` is not converged: the verb closes
  the window and reports a change. `EXPIRED(GRACE)` is not converged either,
  because the password still logs in; expiring it moves the expiry date to now.
- **A lock is left alone, either kind.** `LOCKED` becomes `EXPIRED & LOCKED`.
  This verb unlocks nothing.

**The cost, stated rather than buried:** somebody who knows only the old password
loses the self-service change the window would have given them, and needs a reset.
The benefit is that the safety does not depend on a release nobody has measured.
On 26ai and 21c the expiry leaves the old password live (#455, #461), so there the
close is what ends it. A close with no window open is accepted silently (§4.3), so
if 19c already kills the old password on expiry, the close costs one no-op
statement.

**It writes no reset record and takes no reset lock** (#525), the same as
`account suspend`. §3.1's record journals resets and where they were delivered,
and §3.3's lock stops two deliveries overwriting each other. An expiry draws
nothing and delivers nothing, so the run document is its record. **There is no
flag to keep the window**, for the reason §4.3's promised flag is still unnamed:
H3 invented no flags for an operation nobody had asked for.

**Two more verbs, and neither is specified here.** Disabling an account — the
offboarding case — is **`sopuli account suspend`**. It is *named* rather than
merely deferred, because the name had to be settled before it reached the JSON
contract, where renaming a verb is a major bump (invariant 12): `lock` already
means something else in this CLI — `lock status` and `lock break`, the advisory
locks on vault paths — and a second sense of that word would have been two
meanings in one surface. Of the three ways out, living with the collision,
renaming this verb, or renaming the advisory-lock noun, the middle one costs
nothing and reads better for the case that motivates it.

**The rename is of the verb, not of the state.** `suspend` is what a DBA does to
a person's account when they leave; `LOCKED` is what `ACCOUNT_STATUS` then says,
and §5 already depends on that word meaning Oracle's fact rather than ours. The
statement is still `ALTER USER … ACCOUNT LOCK`, and **#463** specifies the verb.

**The verb is built** (#463): `sopuli account suspend --account NAME`, with the
target selectors narrowing where rather than who. `--account` is required and
takes one name, which is §2's rule for a mutating verb applied to this one -- an
offboarding is one person leaving, and a declaration that resolved a set would be
a predicate widening what a mutating verb may touch.

The guardrails are the ones every mutating verb uses, so suspending `DBSNMP`
refuses exactly as rotating it would; `--force` waives checks 2 to 5 and never the
whitelist. A refusal exits **0** rather than failing: `SKIPPED` is the guardrails
working, and only an unreachable target sets exit 4. The action kind is
`account_lock` and the run document carries `results[].account_status` -- the state
the database was in *before* anything was issued -- because `state: LOCKED` with
`changed: false` cannot by itself say whether the account was already locked or
would be under `--dry-run`. Two things were measured on 26ai Free 23.26.2.0.0 on 2026-09-17, each
twice, and the driver rests on both:

- a second `ACCOUNT LOCK` against an already-`LOCKED` account is **accepted
  silently** and changes nothing, so the driver reads the state first and reports
  `changed: false` — invariant 9 held by the driver, as UC-1 §5's unlock is;
- **`LOCKED(TIMED)` is not already suspended.** `ACCOUNT LOCK` takes it to
  `LOCKED`, and that is a real change rather than a no-op on a technicality: the
  timed lock expires on its own under `PASSWORD_LOCK_TIME` and this one does not,
  and §4.4's reset clears the first while refusing the second. Reporting no change
  there would claim an offboarding that never happened.

**Which makes the state a parse rather than a comparison**, and that is worth
writing down because both obvious spellings are wrong. `LOCKED(TIMED)` *contains*
`LOCKED`, so a substring test calls a failed login an offboarding; and the status
compounds — `EXPIRED & LOCKED`, `LOCKED & IN ROLLOVER`,
`EXPIRED & LOCKED & IN ROLLOVER` are all real values — so equality against the
whole string calls a deliberately locked account open. The answer is to split on
` & ` and look for a `LOCKED` component, which is #309's `EXPIRED(GRACE)` lesson
applied in the one other field that has the same shape.

**The verb is built** (#490): `sopuli account list`, which resolves the
declaration against each selected target and reports what it matched, with the
rule that admitted each account. It mutates nothing and reads no password. Three
things about the build belong here rather than in a diff:

- **A name may be admitted by more than one rule, and is listed once.** An
  enumerated entry yields the *file's* spelling and a predicate the
  *dictionary's*, so `jdoe` and `JDOE` are one person — and the first draft
  listed them as two rows. Found by running it, not by reasoning: a listing that
  shows one account twice misreports the size of the whitelist somebody is
  reviewing. The name shown is the database's own where the account exists.
- **A predicate can admit an account no reset will touch**, and the listing says
  so rather than leaving it to be discovered. Creating a role grants it to the
  creator, so `role: ACME_DEV_TEAM` admits whoever ran the `CREATE ROLE` —
  measured on the tier-1 stack, where that was `SYSTEM`. Guardrail 2 refuses it
  at plan time; the row carries a notice saying so. This is H1's stated cost made
  visible, which is the whole reason the verb exists.
- **The refusals are the ones §2 specifies**, and the two-rules-two-policies one
  fires here exactly as it does in the mutating verb — a listing that quietly
  showed the first match would be where an operator formed the belief a reset
  then refuses.

A **listing**
verb is `account list`, and H1 (#449) is what earns it rather than H3. Under a
predicate something has to resolve the rule and show what it matched, and
`creds status` would answer with empty vault-version and age columns for accounts
nothing masters. Where the declaration is a list of names instead, it is the same
command answering a shorter question — which is why it is one verb and not two.

**There is no separate read verb**, which is the half of this section H2 (#450)
was holding. "When was this person last reset" is answered by `account list`, which
already resolves the declaration and reports each account's state: H2 gives it two
more columns — the database's password-change date and the metadata record's
`reset_at` — and §3.2 says why both are shown rather than folded into one number.

**Either column can be empty, and an empty one is not an error.** Where no store is
configured there is no `reset_at` to report, and `SOPULI-W021`'s own rule applies to
the pair: a documented column that vanishes with nothing saying why is a hole in the
contract, so `account list` prints `-` and carries the §3.4 warning that says which
absence it is. **That warning is `SOPULI-W023`** (#490), one per run rather than one
per account, because a missing journal is a property of the configuration while a
missing database date is a property of one account. It is allocated with this verb
and not with the reset: #468 built the block and left the number unallocated because
nothing could emit it, and the emitter turned out to be the verb with a column to
leave empty. It is the listing verb reporting what exists, not a verb that fails
because history does not.

Every operation is limited to declared accounts, and **H1 (#449) settled what
declares one: a `personal_accounts:` section**, holding either names or a
**predicate** over a profile or a role. Not an application binding, because §1 of
`01-configuration.md` defines that as *these accounts are mastered by these
secrets* and names three things that depend on it existing — `check`'s desired
state, the account→secret mapping, and fan-out. A personal account has none of
the three, so an application entry marked personal would satisfy no purpose the
concept exists for.

**A predicate never widens what a mutating verb may touch**, which is how this
keeps invariant 5's second sentence exactly as written while amending its first.
`account list` resolves the predicate; `reset-password` and `expire-password`
additionally require the account named on the command line and refuse any name the
predicate does not admit. So one run touches exactly one account — and refusing a
selection that resolves to more than one is not a limit bolted onto the verb, it
is what the verb is.

**A name may not be declared twice.** An account that is both an application
account and a personal one makes the whitelist ambiguous about which guarantee
applies — mastered by a secret, or handed over — so the validator rejects the
duplicate rather than picking one. The concrete rule lands with the config
section (#467), together with §1's "two shapes" ceasing to be true.

**The cost, stated rather than buried:** predicate membership is controlled in the
database, by whoever **assigns the profile** or **grants the role**, and not by
whoever reviews the file. The two are different operations —
`ALTER USER … PROFILE` against `GRANT … TO`, which is why UC-1 §5 calls profile
assignment an *attribute* — and the predicate inherits whichever governs it.
Adding an account to an enumerated whitelist is a commit somebody reads; adding
one to a predicate is a profile change or a grant. `02-oracle-privileges.md` §4's checks
narrow that without closing it — check 2 still refuses `ORACLE_MAINTAINED` and
check 4 still refuses `DBA`, `PDB_DBA`, `CDB_DBA` and `AUDIT_ADMIN`, whatever
profile an account carries — and the blast radius is one named account, so a bad
predicate is a wrong *offer* rather than a wrong *action*. Against that: a list of
four hundred developers is not meaningfully reviewed either, and a predicate is a
policy statement somebody can actually read.

**Two rules may admit one account; two rules naming different policies may not.**
An enumerated entry and a profile predicate can both be true of one person, and
that is ordinary — both say the same thing about the same account, and both carry
the same guarantee, so membership is not ambiguous. A `policy:` is a different
matter: taking the first match would make which password policy applies depend on
the order somebody happened to write two entries in. That is refused at **plan
time** rather than at load, naming both rules, because whether a predicate admits a
given account is a fact about a database (#463).

**Refusals follow §2 of `01-configuration.md`'s own asymmetry.** A predicate naming
a profile or role that **does not exist** is refused — that is a misspelling. One
that exists and **matches no accounts** is not an error, because that is a true
answer about today's estate.

---

## 3. What is recorded

UC-1's vault payload answers three questions at once: when a password last changed
(Q9's `rotated_at`), what to roll back to (`previous`), and where the lock lives
(Q2, keyed on the secret path). UC-2 has no payload, so each needs its own answer.
**H2 (#450) is those answers, and they are three different places** — the database,
a metadata record, and nowhere at all:

| Question | Answered by | Why there |
|---|---|---|
| **when** the password last changed | the **database** — `DBA_USERS.PASSWORD_CHANGE_DATE`, `SYS.USER$.PTIME` behind the optional grant otherwise (#386), and 12.1 unmeasured on the fallback (unverified: pw-changed-source) | it is the only thing that knows about a change the tool did not make, and on the seen path there is *always* one (§3.2) |
| **who** reset it, by **which path**, and **where** it was delivered | a **metadata record** in a store, written where an estate configures one (§3.1) | the database cannot know any of it, and the run document answers only for whoever kept that run's output |
| **what to roll back to** | **nothing** | rollback is not a UC-2 operation: the recovery for a lost personal password is another reset |
| **where the lock lives** | the metadata record's own path (§3.3) | it is the one location that exists on the seen path and the unseen one alike, and in both of the unseen path's delivery forms |

**The record never holds the password**, in any form — not the value, not a hash,
not a verifier. That is invariant 2, and it is also the point: a record that could
leak the thing it records would be worse than no record. What lets `rotated_at`
live in UC-1's payload is that the payload is already the secret; this one is not,
so it can be read by anyone who may know *that* a reset happened without thereby
being able to use it.

### 3.1 The metadata record

**Written wherever a store is configured, and where none is, a reset still runs.** The unseen
path already needs a store — it is the delivery target — so on the default path the
record costs nothing that was not already there. The seen (`manual`) path may have
no store at all, and that is exactly the site `manual` exists for, so requiring one
would take the fallback away from the estates that have nothing else. A reset with
no store configured is therefore **not refused**; it warns (§3.4).

One record per **(target, account)**, under a prefix of its own. The unit is not
the one UC-1 locks on, and the difference is the whole reason it needs saying: UC-1
keys on the vault document because the document is what gets mutated, while here
the mutated resource is **the database account**. One person's account on
`appdb-dev-alpha` and on `appdb-qa-alpha` is two accounts with two passwords,
which two DBAs can reset independently.

It carries what happened, and nothing that happened *to*:

```json
{"account": "jdoe",
 "target": "appdb-dev-alpha",
 "reset_at": "2026-09-17T09:14:22Z",
 "seen": false,
 "expired": false,
 "delivery": {"method": "vault_wrapped", "to": "EXAMPLEaccessor000000000"},
 "by": {"host": "dba-ws-4.example.com", "os_user": "dba01"},
 "correlation_id": "01J..."}
```

**On `vault_wrapped`, `to` is the wrapping token's *accessor*, and this example
used to read `cubbyhole/response`** — a placeholder written before the method
existed. The accessor above is a synthetic stand-in. A real one is what Vault returns
beside the token; it names the handover
in Vault's own audit log and **cannot unwrap it**, which is the only reason a
journal that "anyone who may know *that* a reset happened" can read is allowed to
carry it at all. The token itself must never be written here: §6.1 makes it
secret-bearing, and a record is exactly the long-lived, widely-readable object its
TTL exists to outlive. **#444 writes it**, and
`assert_no_secret` now takes the token as well as the password, so putting the
*token* in this field is an `AssertionError` rather than a matter of the writer
having picked the right one of the two things Vault returns.

**`delivery.to` is present only where delivery has a location.** A store path or an
accessor is one; the seen path's destination is a person, by a route the
tool did not carry, so `manual` records the method and omits `to` rather than
inventing a value for stdout. What makes that unambiguous is `seen`, which is the
field a reader is actually asking about there. #468 has the key optional for this
reason and no other.

`by` is the lock record's `holder` shape (`sopuli/lock/record.py`) rather than a
second spelling of the same fact, and `correlation_id` is what joins this row to
the run document that produced it. **`seen` is the field worth writing down**: a
seen reset is a deliberate, time-limited exposure (§1), and six months later the
question somebody actually asks is not *when was this reset* but *did a DBA hold a
working password for this account, and which DBA*.

**The concrete keys, the generated schema and the validators are #468**, split out
in the shape H1's were (#467): this section decides *that* there is a record,
*what it answers* and *what it may never contain*, and `01-configuration.md`
documents configuration that is built.

**They are now built.** The destination is a `reset_records:` block — a `vault:`
naming an entry in `vaults:`, and a `prefix:` with no default — documented in
`01-configuration.md` §1, and the record's own path is derived beneath it,
`<prefix>/<target>/<account>`. Three things about the build are worth reading back
into this section rather than leaving in a diff:

- **The store name is resolved at load**, with every other store reference, so a
  misspelled `vault:` is refused while the file is open. Left to the verb, that
  failure would arrive *after* a password had already changed — §3.4's second
  absence reached by the worst possible route.
- **The account is case-folded into the path and the target is not.** An Oracle
  account name is matched case-insensitively everywhere else here, so a path that
  did not fold would let one account own two records that never find each other,
  which is two concurrent resets not colliding — the exact failure §3.3 keys the
  lock to prevent. A target name is a `targets:` key, matched exactly, and folding
  it would merge two targets an operator declared as distinct.
- **Invariant 2 is asserted against the serialised document**, not trusted to the
  writer. The type has no field a password could go in, which proves only that no
  writer *in this build* puts one there; `assert_no_secret` walks what is about to
  be written and refuses a password at any depth, in a key as well as a value. It
  runs on the write path rather than in a test alone, which is the difference
  between the invariant holding and the invariant having held once.

**What #468 deliberately did not build is the warning, and #511 built both of
them.** §3.4's "no store configured" is `SOPULI-W024`, raised at plan time; a
record that could not be written after a successful reset is `SOPULI-W025`.
Neither could be allocated before there was a verb to emit it — a code with no
emitter is the shape #477 found and fixed, where `Resolved.low_assurance` was
computed on every run and read by nothing. Two codes rather than one, because
the operator's next move differs: an absent journal is a configuration somebody
chose, and a failed write is a store to go and look at.

**The writer is #511, and three things about it are worth reading back here.**
The record is written after the database confirms and after delivery (§6.4), and
on the seen path "after delivery" is as late as a function can be — the value is
composed and every guard has passed, a moment before it reaches the screen.
`seen` records the **path** rather than the operator's eyes: a `manual` delivery
whose prompt was declined still journals `seen: true`, because that is what makes
the absent `delivery.to` mean something, and a journal that understated an
exposure would be wrong in the direction that matters. And a run whose prompt was
declined is journalled at all, which is the same argument as the run document's:
the password was set, so the reset that most needs explaining is exactly the one
where nobody received it.

**The record path is derived at plan time**, before anything connects, so a
target or account name that is not a single path segment is a refusal naming both
(invariant 4) rather than a discovery made after the password has changed. Two
such names derive one path, which is one journal describing two accounts — and,
once §3.3's lock lands, one lock where there should be two.

### 3.2 Why the database is authoritative for *when*, and Q9 is not the precedent

Q9 (#87) decided the opposite for UC-1 — the vault's `rotated_at`, unconditionally,
with the database's own timestamp shown beside it — and UC-2 diverging from a
settled question needs a better reason than taste. It has one, and it is not a
preference about trust:

- **On the seen path the owner is required to change the password**, at first
  logon, by the `PASSWORD EXPIRE` that path always issues (§1). The record's
  `reset_at` is not stale by accident there: it is **designed** to be overtaken,
  usually within a day, by a change the tool will never see. A record that was
  authoritative about when the password last changed would be authoritatively
  wrong about the normal case.
- **The record only knows about resets this tool performed.** A password changed by
  hand at a SQL prompt, by a DBA who did not use sopuli, exists only in the
  database.
- **Q9's reason does not carry over.** The vault is authoritative in UC-1 *because
  it is master*: the value there is the one the applications are using, so its
  timestamp is the fact. Nothing is master here (§1), which removes that argument
  rather than reversing it.

**Reading a timestamp out of the database is not a breach of invariant 6.**
Invariant 6 governs the *value* — vault is master of the password, and the
direction of a write is vault → database, always. UC-2 syncs no value in either
direction and reads no password from anywhere, so what is left is the tool reading
account state from the database, which it already does in UC-1 (§1, and UC-1 §5's
attributes). The distinction to keep hold of: **the database is a source of truth
about the account, and never about the password.**

**Both are shown, and a disagreement is information.** `account list` reports the
database's change date and the record's `reset_at` as two columns rather than one
folded number, for the reason Q9 gave and which this section does not change. What
the pair says:

| The two dates | Meaning |
|---|---|
| database **later** than `reset_at`, **seen** path | expected — the owner logged in and set their own password, which is what that path is for |
| database **later** than `reset_at`, **unseen** path | **a finding.** Somebody changed the password after the tool delivered it, so the copy the person was told to fetch no longer works |
| database **earlier** than `reset_at`, by more than the skew allowance | the reset did not take, or this release does not answer by the column the run read (§3.4) |
| database **earlier** than `reset_at`, within it | says nothing, and is not reported as anything. The two timestamps come off two clocks — `reset_at` off the host that ran `sopuli`, the change date off the database — so a few seconds' disagreement is ordinary drift rather than evidence. The allowance is `sopuli/lock/record.py`'s `CLOCK_SKEW`, which exists for the same reason against the same pair of clocks, and reusing it keeps one number rather than two |
| no database date | §3.4 — the release or the grant, and `SOPULI-W021` already says which |

Whether the unseen-path disagreement gets a `diagnostics[]` code of its own or is
a column an operator reads, is left to the verb that displays it: that is a
presentation question about a fact this section establishes, not another H.

### 3.3 The lock, and why the record's path is its key

Q2 (#83) keyed the advisory lock on the **store and secret path**, one CAS-guarded
record per path under a `locks/` prefix, with the store's version counter as the
fencing token. UC-2 has no secret path: the wrapping-token form (#444) never writes
one, and `manual` writes nothing at all. So the collision #450 raised — two DBAs
resetting the same person at once, the second password overwriting the first before
the person has fetched either — had nothing to key on.

**The metadata record's path is that key.** It exists on the seen path and the
unseen one alike, and in both of the unseen path's delivery forms; it is one per
(target, account); and it is the unit two concurrent resets actually collide on. Nothing about the lock machinery changes: same `locks/`
prefix, same CAS, same fencing token, same `lock break`. The key is the only new
thing, and it is a key of the shape that layer already takes.

**Built in #512**, and three things about the build belong here. The lock is
taken **before the run connects to a database**, so a reset refused at exit 7 is
one that did not start and the person's old password still works. The fence is
re-read immediately before each target's statements, and a fence lost part way
through a multi-target run exits **4** rather than 7 -- `creds generate`'s split,
because 7 asserts that nothing happened and that is a lie once one target has
been reset. A `--dry-run` takes no lock at all, for invariant 8's reason: a
preview that left a claim in the vault would block the run it was previewing.

**`lock status` surveys these locks by listing the prefix, not by enumerating
keys** (#514). The obvious implementation does not work and the first build did
not have one: the listing verb builds its estate from `bindings`, which come from
`applications:` and `accounts:`, so between #512 and #514 a configuration whose
only locks were UC-2's reported `no lock paths are declared` while one was held.
Extending that estate is not the fix either, because a personal account declared
by a *predicate* (H1) has no name until a database is asked and this verb asks
none -- so a key-by-key expansion would list the name-declared accounts and
silently omit the rest, which is a listing wrong in the direction that matters.

What it does instead is list the store under the declared `reset_records:`
prefix and report what is actually there, which is the same move #150 made for
records at paths the file no longer declares. The difference is in what the
survey then *calls* them: a reset lock is this estate's, so it is neither a
binding's nor a leftover, and `declared_by: reset_records` is the third answer
(`03-json-output.md` §8, schema 1.28). `lock break` was unaffected throughout --
it takes the key on the command line.

**A selector narrows the bindings and not the prefix**, which is a cost worth
stating rather than leaving to be discovered. A record path spells its target, so
`--target` could filter on that segment -- and a record under this prefix whose
target segment matches nothing declared is exactly the one an operator needs to
see, which such a filter would hide. A path segment is not a declaration, so the
region is surveyed whole.

**A declared store that cannot be reached refuses the run**, and that is not
§3.4's absence wearing a different hat. The lock lives in the journal's store, so
a store that does not answer means the lock cannot be taken -- and nothing has
happened yet, which is exactly where UC-1's lock stores already stop a run.
§3.4's absences are all about a store that went away *after* the password
changed; there the reset stands and a warning carries it.

**Where there is no store there is no lock**, which is the other half of §3.1's
cost and the reason §3.4's warning says so rather than mentioning only the record.
A store configured `locking: advisory-only`, or one without `cas`, behaves here as
it does in UC-1 (`01-configuration.md` §9).

### 3.4 When something is missing, say which thing

Three absences, and they are not the same absence:

- **No store configured.** No record is written and no lock is taken; the run
  document and the database are the record for that reset. **A warning with a code
  of its own**, at plan time rather than after the fact, because an operator who did
  not mean to run this way should find out before the password changes rather than
  after. Built in #511 as `SOPULI-W024`, allocated by hand with the verb that
  raises it — how codes are allocated in general is J3, still open
  (`03-json-output.md` §9).
- **The record write fails, after the reset succeeded.** A warning on a successful
  run — never a rollback, never a non-zero exit. The password has already changed
  and the person still needs it, so failing the run would report a false negative
  about the part that mattered. The record is written **after** the database
  confirms and after delivery, so what it holds is a fact rather than an intention,
  and its absence is the case above reached by a different route. `SOPULI-W025` in
  #511, and a second code rather than a reuse of the first: the absence is the
  same and what to do about it is not, since this one names a store that answered
  and the message carries what it said.
- **The database will not say when.** `SOPULI-W021` exists for exactly this and
  already distinguishes the causes: a release with no
  `DBA_USERS.PASSWORD_CHANGE_DATE` and no `SELECT ON SYS.USER$` to read `PTIME`
  instead, which a grant fixes, or a value that could not be read, which is worth
  investigating (`03-json-output.md`). 12.2.0.1.0 takes the fallback (#572); 12.1
  would too and is unmeasured (unverified: pw-changed-source).

**None of the three is a refusal**, and that is a deliberate departure from this
codebase's usual reflex. Invariant 4 refuses at plan time when a command needs a
capability it cannot have; a reset needs none of these to do what it is for. A
person who cannot log in is still locked out whether or not the estate keeps
history, and a tool that refused to help them because it could not write a journal
entry would have its priorities backwards.

### 3.5 What is deliberately not recorded

- **No password, in any representation** (invariant 2, §3).
- **No previous value.** There is nothing to roll back to, because rollback is not
  a UC-2 operation — the recovery for a lost personal password is another reset.
  Stated rather than implied, which is what #450 asked for.
- **The unseen path's store copy is not a record.** It exists for the person to
  fetch; whether it outlives the fetch is H8 (#459), and the tool never reads it
  back as history. A record and a handover in the same store are two objects with
  two lifetimes, and conflating them is how the handover copy would end up living
  as long as the audit trail.
- **The run document is always a record**, and it never carries a password
  (invariant 2). So will the jsonl stream be when this verb streams — today
  `account reset-password` does not, and refuses `--output jsonl` as every
  non-streaming verb does (`03-json-output.md` §5).

---

## 4. The reset

### 4.1 The statement

**One statement sets the password; the reset may issue up to three.** H4 (#455)
added the other two, and each is separate and conditional rather than a clause on
the first — §5 has the reasons, and they are not tidiness. The account is the
quoted identifier in the spelling the dictionary gives back, as for UC-1 —
`account.quoted()` in `sopuli/driver/oracle/statements.py`:

```sql
-- 1. only where the account is LOCKED(TIMED); a deliberate LOCKED is refused (§5)
ALTER USER "<ACCOUNT>" ACCOUNT UNLOCK

-- 2. the reset itself
--    unseen (default)
ALTER USER "<ACCOUNT>" IDENTIFIED BY "<password>"
--    seen (manual)
ALTER USER "<ACCOUNT>" IDENTIFIED BY "<password>" PASSWORD EXPIRE

-- 3. only where a rollover window is open, and unless the flag keeps it (§4.3)
ALTER USER "<ACCOUNT>" EXPIRE PASSWORD ROLLOVER PERIOD
```

Statements 1 and 3 are each issued only where the state calls for them, so the
ordinary reset of an unlocked account on a profile with no rollover time is still
the single statement this section used to describe.

Setting a password clears an existing `EXPIRED` state — Oracle's behaviour, which
UC-1 §5 already relies on — so the unseen statement is the whole fix for an account
that expired and whose owner no longer knows the password. **It is not the whole
fix for one that is locked**, and that asymmetry is measured rather than assumed:
`IDENTIFIED BY` leaves `LOCKED(TIMED)` exactly as it found it, down to the
`LOCK_DATE`, and a logon with the *new* password is `ORA-28000` (§5, Q3). An
expired account is fixed by the password; a locked one needs statement 1.

What UC-1 §6.1 and `02-oracle-privileges.md` §4 settle about issuing `ALTER USER`
binds on both paths, with **invariant 11 authoritative** wherever older wording
disagrees — UC-1 §6.1 said to escape an embedded `"` until #457 corrected it:

- **issued directly, never inside a PL/SQL block** (invariant 13). A block
  containing `ALTER USER … IDENTIFIED BY` keeps its text verbatim in `V$SQL` —
  measured on 26ai, 21c, 18c and 11.2. Invariant 13's reasoning does not depend on
  the suffix: a wrapper is an ordinary block whatever it contains;
- **no password containing `"`** (invariant 11) — rejected, never escaped, and
  generation guarantees it by construction rather than by a check afterwards;
- **what the direct DDL leaves behind is release-dependent.** For the unseen
  path's statement it is measured: on 26ai, 21c and 18c no `V$SQL` cursor exists at
  all; on 11.2 `V$SQLSTATS` keeps the text until the shared pool ages it out
  (#387); 12.2.0.1.0 and 19.3.0.0.0 keep nothing, as 18c does (#572, #548), and
  12.1 and a patched 19c are unrun (unverified: ddl-text-versions). **This is
  the limit of the unseen path's claim.** The claim is about the tool: it puts the
  value in none of its own output. On 11.2 the database itself keeps the statement
  where a dictionary reader — which a DBA usually is — can read it until the shared
  pool ages it out or is flushed (#387 decided to document that rather than refuse
  it). **The seen path's `PASSWORD EXPIRE` form has not been probed on any
  release** (unverified: expire-ddl-text) — Oracle's masking is keyed to the
  statement type, which gives no reason to expect a difference and is not a
  measurement of one. Quote none of these without its release.

**Store write and DDL are two steps**, and neither order is free: setting the
password first and failing the write leaves an account nobody knows the password
to; writing first and failing the DDL leaves a store holding a password that does
not work. Both are recovered by another reset, which is what makes this smaller
than UC-1 §3's ordering problem. **§6.4 settles it**: the irreversible step goes
last, which is *deliver then `ALTER USER`* on the unseen path and *`ALTER USER`
then print* on the seen one — because what cannot be undone is the DDL on one path
and the print on the other.

**The driver half is built** (#441): `Session.reset_password`, which issues all
three statements as one operation, and `Session.require_no_rollover_window`, which
is §4.3's refusal asked at plan time. The verb, the delivery and the record are the
other half; **the verb and the seen delivery are built too** (#441), and the
record is the part that is not — every run warns that the run document and the
database are its whole trace. Four things about the driver build belong here
rather than
in a diff, and the last two were measured on 26ai Free 23.26.2.0.0 on 2026-09-20
because reasoning could not settle them:

- **One state read decides all three statements.** Three reads would be three
  chances to see three different states, and an operation that unlocked an account
  on the strength of a status it no longer had would be reporting somebody else's
  run.
- **Every statement is reported, including the ones not issued** — the rule
  `apply_attributes` already follows. An account that was not locked is a row
  saying so, because a caller that had to read *absent* as *nothing to do* would be
  inferring the operation's shape from its output.
- **The window is read from the state taken before the reset.** `IDENTIFIED BY` on
  a rollover profile *opens* a window, so a state read afterwards says one is open
  on every such account, and the row would stop distinguishing the profile that
  grants a window from the account that has just been given one.
- **`expire` is required rather than defaulted**, and that is §1 made structural:
  the seen path always expires and the unseen path never does, so a caller that has
  not decided which path it is on has not decided what it is doing.

Two measurements the tier-1 tests now hold, both of which the earlier sections
predicted and neither of which had been run against this code: a seen reset leaves
the account `EXPIRED` with the **new password still authenticating** — `ORA-28001`
is Oracle's change-at-logon flow rather than a refusal — and an unseen reset on a
rollover profile leaves the old password answering `ORA-01017` once statement 3 has
closed the window, while `keep_rollover` leaves **both** passwords working, which
is the exposure §4.3's default exists to remove.

### 4.2 The password

Generated from a policy, by the same tier-0 code UC-1 uses (01-configuration §8).
A seen-path policy is likely to differ — a person types it once, from a message —
but nothing about generation does. The maximum length is the same live question it
is for UC-1: the limit is derived against a floor that #383 showed to be wrong, so
a long policy can plan clean and fail mid-run on 21c and older
(unverified: password-byte-limit).

### 4.3 The rollover window

On a release with gradual password rollover (UC-1 §6.3), an account whose profile
sets `PASSWORD_ROLLOVER_TIME` keeps accepting its **old** password after
`IDENTIFIED BY`, until the window closes.

**On the unseen path the behaviour is UC-1's and measured, and it leaves an
exposure.** Anyone who knows the old password can still authenticate until the
window closes. In the usual case that is nobody — the owner forgot it — but that is
a likelihood, not a guarantee, and a reset after a suspected disclosure is exactly
the case where it is not nobody.

**The reset ends the window, by default** — decided in H4 (#455). Closing it early
is the `EXPIRE PASSWORD ROLLOVER PERIOD` statement `creds finish-rollover` issues
(#263), and this is the one place UC-2 deliberately defaults the opposite way to
UC-1. **UC-1 §6.3's argument does not transfer, and that is why this is not a
contradiction.** `--strategy direct` is never chosen for somebody there because the
old password's holders are applications that have not restarted yet — a blast radius
the operator cannot see. Here the old password's only holder is the person being
reset, and the premise of the reset is that they no longer have it. *A reset means
the new password is the only one that works*; a reset that left the old one
authenticating for an hour would not be one.

Three things follow, and the first two are measured
(`sql/oracle/07_lock_and_rollover_probe.sql`, Q6, on 26ai 23.26.2.0.0):

- **It is a second statement, not a suffix.** `IDENTIFIED BY` then
  `EXPIRE PASSWORD ROLLOVER PERIOD`, back to back in one session, which is the
  shape `--strategy direct` already uses. Measured: after the first, status is
  `OPEN & IN ROLLOVER` and **both** passwords authenticate; after the second,
  status is `OPEN`, the old password is `ORA-01017` and the new one works. Issued
  with no window open it is accepted silently and changes nothing, so an account
  whose profile grants no window costs an extra statement and nothing else.
- **It closes on an unverified change**, which UC-1 §6.3 refuses to do — it closes
  only after the change is verified. UC-2 verifies nothing (§5), so the
  precondition is dropped rather than inherited. That is safe here for the same
  reason the default is: there is nobody holding the old password to strand.
- **A window outlives the profile that granted it, and the status then lies.**
  Measured twice on 26ai Free 23.26.2.0.0 on 2026-09-20, prompted by a review of
  #504 that predicted the opposite: setting `PASSWORD_ROLLOVER_TIME` to zero while
  a window is open leaves `ACCOUNT_STATUS` reading `OPEN & IN ROLLOVER`, and the
  old password is **already dead** — `ORA-01017` — so what survives the profile
  change is the *status* rather than the exposure. The close statement is accepted
  in that state and takes the account back to `OPEN`. The driver therefore closes
  on either signal, the profile's grant or an open window, which is safe under this
  measurement and safety-critical under a release where the old password does
  outlive the change. Unmeasured anywhere but 26ai (unverified: stale-rollover).
- **An explicit flag keeps the window**, for the reset where the person *does*
  still know their old password and a grace period is a convenience. The
  asymmetry is worth stating: **a reset after a suspected disclosure is exactly
  the case that must not use it**, because there the old password is known to
  somebody who should not have it. The flag is named when the verb is built: H3
  (#451) settled the noun and the verbs, and deliberately invented no flags for an
  operation nobody has implemented yet.

**On the seen path it is measured on two releases, and the refusal stands.**
#455's probe ran it on 26ai 23.26.2.0.0 (Q7) and #461 on 21c 21.3.0.0.0, with the
same answer on both, and that answer is worse than the guess was: `IDENTIFIED BY … PASSWORD EXPIRE` **is**
accepted on a rollover profile, the resulting `ACCOUNT_STATUS` is
`EXPIRED & IN ROLLOVER` — both at once — and **expiring does not end the old
password's window**. The old password answers `ORA-28001`, not `ORA-01017`: it
still authenticates, and it is itself a way to set the new one. So on this path
the expiry that is supposed to end the DBA's exposure leaves a second live
password behind it for the length of the window. 19c is unmeasured.

**That is the answer from `OPEN`, and from `EXPIRED` it is different** (#529,
`sql/oracle/09_reset_from_expired_probe.sql`, 26ai 23.26.2.0.0 and 21c
21.3.0.0.0, twice each, identical). This
section's motivating account, one whose password expired and whose owner no longer
knows it, is in the second state. There the same statement opens no window. Every
earlier password answers `ORA-01017`, including the pre-window one on an account
that started `EXPIRED & IN ROLLOVER`, and the new, expired password is the only
one that works. `EXPIRED(GRACE)` behaves as `OPEN` does, because its password still
authenticates. So on both releases the exposure Q7 found depends on whether the
old password is live, not on what the profile grants. **The refusal below is
unchanged by this.** It keys on the profile, and narrowing it is #541's decision,
which now has both measurements it was waiting for.

**A seen reset of an account whose profile sets a non-zero rollover time is
therefore still refused at plan time**, naming the account and the profile, before
any DDL is issued — invariant 4, and for a reason measured on 26ai and 21c rather
than an absent one. Whether it narrows (#541), and whether the answer is instead
to close the window on this path too, belongs with #438/#457 rather than here. The unseen path remains available
for the same account.

### 4.4 Guardrails

`02-oracle-privileges.md` §4's five account checks bind unchanged, and one of them
collides with the roadmap. **Check 4 refuses any account holding `DBA`, `PDB_DBA`,
`CDB_DBA` or `AUDIT_ADMIN`**, and the roadmap names DBA accounts as in scope. Under
today's rule every reset of a DBA's personal account needs `--force`, which
overrides checks 2–5 and is recorded in the audit event (#89).

That is stated here rather than solved. It may be the right answer — a DBA account
is precisely where a reset deserves an explicit override — or it may make `--force`
routine in a way #89 did not intend. Neither reading is taken here.

### 4.5 Running it twice

**A reset reports `changed: true` every time, and warns that it replaced
something** (H7, #454). It draws a fresh random password, which has nothing to
converge on, so it sits outside invariant 9 rather than taking an exception to it
— the same footing `creds generate` has had since #254, and `CLAUDE.md`
invariant 9 now states the rule that admits both rather than listing them.

**What the warning has to say is sharper than `generate`'s**, because more has
already happened. `generate` replaces a `pending` nothing has read yet. A reset has
already changed the database and already delivered, so a second run leaves somebody
holding a password that no longer works — and on `vault_wrapped` (#444) they will
spend their single unwrap discovering it. The warning names that, not merely that a
value was replaced. **Its code is allocated with the verb** (#441), for §3.4's
reason: a code with no emitter is the defect #477 found in `Resolved.low_assurance`.

**The cost is real and lands almost entirely on the unseen path.** The seen path
cannot be scripted at all — it confirms every time, `--confirm` cannot answer that
prompt, and stdout must be a terminal (§6.5) — so the run that silently delivers
twice is an unattended one, which is the unseen path by construction.

#### Why not a convergent verb

Two shapes were weighed and both refused, and the reasons are worth keeping because
each would look attractive again from a distance:

- **Convergent on a request identity** — a ticket number or `--request-id`, with a
  re-run under the same id delivering nothing. H2 gave it somewhere to live: §3.1's
  record already carries `correlation_id`, so a `request_id` beside it is small. It
  fails on where that record is: an estate need not configure one (§3.1), and the
  write can fail after a successful reset (§3.4) — which is *precisely* the run
  somebody retries. So the key is absent exactly when it is needed, and the verb
  falls back to drawing a second password without saying that is what happened.
- **Convergent on account state** — reset only an account not already `EXPIRED`
  since a recorded reset. **The signal does not exist on the default path.** §4.1
  issues `PASSWORD EXPIRE` on the seen path only; the unseen statement is a bare
  `IDENTIFIED BY`, and the owner is under no obligation to change what they were
  given, so `PASSWORD_CHANGE_DATE` stays at `reset_at` and cannot tell *fetched and
  in use* from *never fetched*. The only thing that could is reading the handover
  copy back, which §3.5 says the tool never does and whose lifetime is H8 (#459),
  still open.

Both would also refuse the recovery this document specifies. §6.4 says of either
ordering failure that *the recovery for either is the same reset run again*, and
§3.5 says the recovery for a lost personal password is another reset. A verb whose
default is to refuse the documented recovery would need a `--force`-shaped escape
for the ordinary case, which is the wrong way round.

---

## 5. Lockout, unlocking, and self-service

**A reset attempts no login**, so most of UC-1 §7 has nothing to guard: its six
mitigations exist to stop a scheduled *check* from locking an account. H4 (#455)
is what survived it, and it is now answered in three parts — each of them measured
on a real database before it was decided, because every one turned on what Oracle
actually does rather than on what the statement looks like.

**A reset never verifies the password it delivered** (H4, #455). Not by login and
not by hash, on either path. The seen path has the argument that was always
obvious — a login would consume the `EXPIRED` state the reset exists to create —
but the reason that covers both paths is stronger and is about the tool rather
than the account: **verification is the one thing that would put the password
somewhere other than the store.** A login means the tool holds and uses a value
the unseen path otherwise only writes; a hash comparison needs the optional
`SELECT ON SYS.USER$` grant and a derivation still unconfirmed on 19c (#433, #90),
and never a bound value (invariant 14). Both spend the unseen path's own
guarantee to learn something nobody asked for.

**Reporting `ACCOUNT_STATUS` is not verification, and the reset always does it** —
before and after. UC-1 §7's mitigation 6 is the single piece of that apparatus
UC-2 keeps; mitigations 1–5 have nothing to guard.

**The two reads are not the same cost, and only the first is free.** The
*before* status is already in hand: `describe_user` reads it as the input to the
unlock decision below, to §4.3's window decision and to §4.4's guardrails, so
reporting it adds nothing. The *after* status is **a second dictionary read**, and
it has to be — `ALTER USER` returns no status, so nothing about the DDL's success
tells the tool what state the account ended in. An implementation that reported
the pre-reset status as the outcome would be reporting stale state on exactly the
runs where it matters: the reset that unlocked an account, or the one that did
not. The status afterwards is what shows the reset did what it said — the
`EXPIRED` component on the seen path, its absence on the unseen one.

**A reset unlocks `LOCKED(TIMED)` by default, and refuses a deliberate `LOCKED`.**
This is the one place UC-2 departs from 01-configuration §8's rule that every
account attribute is opt-in, and it needs the justification that rule asks for.
Measured on 26ai 23.26.2.0.0 (`sql/oracle/07_lock_and_rollover_probe.sql`, Q3 and
Q4):

- **`ALTER USER … IDENTIFIED BY` does not clear either lock.** Status, `LOCK_DATE`
  and `LCOUNT` are all unchanged, and a login with the **new** password is
  `ORA-28000`. So a reset that does not unlock does not let the person in — it
  fixes the thing they did not ask about and leaves the thing they did. §8's rule
  was argued for a rotation nobody asked to change anything else; this is the
  opposite case, and the change is the one that was asked for.
- **The two locks are different asks, and Oracle tells them apart.**
  `LOCKED(TIMED)` is what a failed-login limit produced — a lock nobody chose,
  which `PASSWORD_LOCK_TIME` clears on its own — and it is the state a person who
  asks for a reset is actually in. Plain `LOCKED` is one a DBA issued, and on a
  *personal* account that usually means offboarding or suspension. A reset that
  silently cleared it would re-enable an account somebody disabled on purpose, and
  the DBA running the reset need not be the one who disabled it. H1 (#449) narrows
  this without closing it: under a **predicate** a departed person leaves the
  declared set when they are moved to another profile, or their role is revoked —
  profiles are assigned and roles are granted, so the two exits are different
  statements — and that is usually the same offboarding step that locked the
  account. But an enumerated `personal_accounts:` entry stays declared until
  somebody edits the file, and an offboarding nobody completed leaves the predicate
  admitting them either way.
- So plain `LOCKED` **fails at plan time**, naming the account and the lock, and
  `--force` or the explicit unlock flag is what proceeds. The unseen path has no
  confirmation prompt to catch it — only the seen path confirms (§2) — so the plan
  is the only place it can surface.

**The unlock is its own statement, issued first**, in UC-1 §5's order: guardrails,
unlock, then the password. Not folded into one `ALTER USER … ACCOUNT UNLOCK
IDENTIFIED BY …`, although Q5 measured that both clause orders are accepted. Two
reasons, and neither is style. `protocol.py` requires each attribute to be reported
as its own change, and a combined statement would be one result describing two
mutations; and the combined form is a statement shape **no leak probe has been run
against** — every retention result in `02-oracle-privileges.md` §4 is for the bare
`IDENTIFIED BY` form. Two already-measured statements beat one unmeasured one that
buys only atomicity.

**The unlock is read-then-issue, never issued unconditionally**, and that is a
measurement rather than a preference. Q1: `ACCOUNT UNLOCK` against an account that
is *not* locked is accepted silently but **resets `SYS.USER$.LCOUNT`** — 2 before,
0 after — while `IDENTIFIED BY` does not (Q2). "It does no harm even if the account
is not locked" is false on that axis: it clears the failed-login counter UC-1 §7's
`--lockout-margin` reads. So the driver reads the lock state and issues nothing
where there is no lock, reporting `applied: false`, exactly as #300 already does.
That also makes the unlock and the window-close the two *convergent* steps of an
otherwise non-convergent verb. **H7 (#454) did not build on them, and §4.5 says
why**: the draw dominates, so the verb reports `changed: true` however little the
other two statements did. What they keep is their own honesty one level down —
`applied: false` for a statement that was not issued — and that is worth having
whatever the verb reports, because *the account was not locked* and *the account
was unlocked* are different facts about somebody's morning.

**Self-service here means fetching, not resetting.** An owner who knows their
password changes it themselves, without the tool: before expiry with
`ALTER USER … IDENTIFIED BY new REPLACE old`, and after it at logon — a correct
password against an expired account answers `ORA-28001` and Oracle's change flow,
not a refusal (measured in `tests/driver/test_oracle_verify.py`). **A DBA reset is
needed when the owner no longer knows the password**, and then self-service is the
owner **retrieving the new value** from a store meant for them alone — which is the
unseen path. The person never uses the tool, and never the service account's
`ALTER USER`, so ADR-001's premise that the operator is a DBA is untouched. H5
(#452) asked whether a person should reset through the tool, and is closed on this
reading.

---

## 6. Delivery

How the new password reaches the person. **This is part 2 of the specification
(#456)**, and it closes #438.

### 6.1 The one binding rule

Everything below is written against a single sentence, set by #438:

> **The channel that notifies may be low-trust. The channel that carries the
> secret may not.** "Your new password is ready" may go anywhere; the password, or
> anything that retrieves it, may not.

**"Anything that retrieves it" is the clause that does the work**, and it is
deliberately broader than "the password". A Vault wrapping token (#444) and a
one-time link (#445) hold no password between them — and either one, in the wrong
hands, produces one. Treating them as notifications because they are short-lived
and single-use would be reading the rule as being about *value* when it is about
*reach*.

So the rule's consequence is settled here: **a retrieval credential is
secret-bearing, and never travels the notify channel.** #442's webhook carries
`{account}`, `{target}` and "it is ready"; it does not carry `{wrap_token}` or
`{item_link}`, and a template that references one is refused rather than rendered.

**Built in #442, and enforced by the closed set rather than by naming those two.**
A template may use `{account}`, `{target}` and `{expires_at}`; every other name is
a load-time refusal, because a blocklist would fail open on `{wrapping_token}` or
on whatever a later method calls its credential. `sopuli/notify.Facts` is the same
guarantee one layer down: it has a field per placeholder and none for a password,
a token or a link, so the renderer cannot emit what it was never handed.
`01-configuration.md` §1 has the grammar.

What that leaves open is the subject of H9 below.

### 6.2 The methods

`delivery.method` is a closed set. Six values, and the sub-block for the selected
method must exist — both refused at load, config-invalid (exit 9), by #440.

| `method` | Path | The person gets | Issue |
|---|---|---|---|
| `vault_wrapped` | unseen | a Vault response-wrapping token, single use | #444, **built** |
| `vault_path` | unseen | a KV path only their own identity can read | #447 |
| `one_time_link` | unseen | a URL that decrypts once | #445 |
| `onepassword_share` | unseen | an item in a password manager | #446 |
| `manual` | **seen** | the password, printed to the DBA's terminal | #441 |
| `smtp_encrypted` | unseen | encrypted mail the tool sends | — |

**`vault_wrapped` is the default**, and the reason is availability rather than
preference: it works against a stock Vault, needing nothing but the mount the
estate already has. Every other unseen method needs infrastructure the tool does
not create — `vault_path` needs human-identity auth (LDAP, OIDC, userpass) and a
templated policy, and #447 says plainly that sopuli sets up neither; `one_time_link`
needs a Yopass deployment; `onepassword_share` needs an account. A default that
required an estate to build something first would be a default nobody could use,
and the fallback would silently become `manual`, which is the one path that shows a
DBA a working password.

**`vault_path` is the renaming #447 asked for.** That issue carried the variant as
`vault_wrapped.identity_scoped: true` and noted the key "probably wants a name that
doesn't say wrapped", raising it rather than renaming silently. It is not wrapping:
nothing is single-use, the value sits at a path, and the guarantee comes from the
path's policy rather than from a token. Two methods, because they are two different
promises — and one of them, per §1, is a promise about a value that persists.

**`smtp_encrypted` has no issue yet** and is specified no further here than this:
it is *unseen*, because the tool encrypts and sends without a DBA reading anything,
which is the property that distinguishes it from a DBA emailing a password by hand.
The encryption is to a key the estate holds for the person, and choosing the
mechanism — S/MIME, OpenPGP, a keyserver or a configured key — is its own issue
when somebody needs it. It is listed in the enum now so that the enum is the whole
set rather than the set that happened to have issues.

### 6.3 Per-method configuration

Each method's own keys land with its own issue; what belongs here is the shape and
the rules that cross methods.

```yaml
delivery:
  method: vault_wrapped
  vault_wrapped:
    ttl: 15m
    # vault: vault-handover   # optional; §3's chain otherwise
  notify:
    method: webhook
    webhook:
      url: { env: SOPULI_NOTIFY_WEBHOOK }
      template: "{account} on {target} has a new password waiting"
```

**Three constraints bind every method**, and each exists because the obvious
implementation violates it:

- **Secret-bearing keys are MaterialRefs** (C9), never plain strings. A webhook URL
  routinely embeds its own token, a 1Password Connect token is a credential, and a
  key written inline in a config file is a credential in a repository. `{ env: NAME }`
  or `{ file: PATH }`, redacted wherever the config is shown.
- **A method that opens a socket ships as an install extra** (ADR-006), and the base
  install continues to open none. A configured-but-uninstalled method follows E4/E5:
  `config validate` warns and exits 0, and using it fails with exit 9. `manual` is
  the only method in the table that needs no extra, which is worth noticing — the
  fallback for an estate that can install nothing is the path that shows the DBA the
  password, and that is an argument for `smtp_encrypted` existing rather than a
  comfort.
- **Every delivery emits an event**, named `noun.verb` (`03-json-output.md` §5):
  `password.delivered` on success, and `password.displayed` for the seen path's
  exposure, which is its own fact and not a variant of the first (#441). Neither
  event carries the password, and the run schema has no property that could.
  **`password.delivered` is emitted since #535**, when `account reset-password`
  learned to stream; **`password.displayed` never will be**, because a seen reset
  is refused under every machine format, `jsonl` included, and its `--dry-run` —
  exempt, as under `json` — displays nothing. Before
  that, both words were registered with no emitter,
  so `password.displayed` arrived with #441 and
  `password.delivered` with #444, each with the change that knows why the event
  exists rather than with the stream that will carry it. What records a delivery
  today is `results[].handover` in the run document, which every run has — the
  accessor that names the hand-over, never the credential that performs it.

**`manual` requires `force_expire: true`** and is refused at plan time without it
(§6.4). That is the runtime half of the seen path's guarantee: the exposure is
bounded by the person's next logon or it is not bounded at all.

### 6.4 The order of the two steps

§4.1 leaves this here: a reset both **writes the password somewhere** and **issues
the DDL**, neither order is free, and the order is a choice.

**The rule is that the irreversible step goes last**, which resolves to a different
order on each path — and that is the answer rather than an inconsistency, because
what is irreversible differs.

| Path | Order | The irreversible step |
|---|---|---|
| unseen | **deliver, then `ALTER USER`** | the DDL — it kills the old password |
| seen (`manual`) | **`ALTER USER`, then print** | the print — nobody can unsee it |

**On the unseen path, deliver first.** Compare the two failures:

- **DDL first, delivery fails:** the account has a password nobody holds. The person
  is *worse off than before the run* — they could not log in, and now nobody can.
- **Delivery first, DDL fails:** the store holds a value that authenticates nothing,
  and **the person's old password still works**, because the DDL never ran. Nobody
  is worse off than they were.

The second is strictly recoverable and the first is strictly not, so the order
follows. The cost is a window in which the store holds a password the account does
not have — a person who fetches during it gets a value that fails, and on
`vault_wrapped` spends their single unwrap on it. That is confusing; the other order
is a lockout. Both are cured by another reset (§3.5), and one of them needs curing
by somebody other than the person who is already locked out.

**On the seen path, issue the DDL first.** The reason is the same rule with the
irreversible step in the other place: printing a password that was never set tells a
DBA something false, and a DBA who has been told it will pass it on. There is no
undo for either half of that. Setting it first means the value on the screen is the
account's password by the time anybody reads it.

**The record is written after both** (§3.1), and that is not a third ordering
question: it holds what happened, so writing it earlier would make it hold an
intention. §3.4's second absence — the record write failing after a successful reset
— is a warning on a successful run for exactly this reason.

**Nothing here is a two-phase commit, and the document should not imply one.** UC-1
§3's `pending` → `current` ordering exists because something reads the vault at
runtime and invariant 7 protects that window. Nothing reads this value at runtime:
it is fetched once by a person. So the ordering is a choice about *which failure to
prefer*, not a protocol, and the recovery for either is the same reset run again.

**A failure between §4.1's statements is a third case, and it is decided too** (#528).
DDL commits as it goes, so a statement that fails after an earlier one ran leaves
that earlier one done. The row is `ERROR` at exit 4 either way, with `changed: true`
and the committed statements reported as applied. What happens next depends on
whether the password was set:

| Committed | Failed | Password | Handed over | Record and notify |
|---|---|---|---|---|
| `ACCOUNT UNLOCK` | the set | unchanged, the old one works | **no** | no |
| the set | the window close | **live**, and the old one may work until the window ends | **yes** | yes |

The first is this section's recoverable failure with one extra step done. The token
already made would retrieve a value that authenticates nothing, so it is not
printed. The timed lock is gone, and the row says so rather than calling the
account untouched.

The second is handed over because withholding it is the lockout this section orders
the steps to avoid. On the seen path nobody would hold the expired password the
account now has. On an unseen one the token has already been made, and discarding it
leaves a live password nobody can fetch. The state it leaves is the one
`--keep-rollover` leaves on purpose (§4.3), so it is not a new kind of exposure. The
row still fails, because a reset promised that the old password would stop working
and it may not have. The record is written because it holds what happened, and a
password was reset. It has no field for the open window, which lives in the run
document.

### 6.5 The seen path, and what narrows it

**`manual` is the one method that shows a working password to somebody who is not
its owner**, and #439 decided both that it may and exactly how narrow that stays.
`CLAUDE.md` invariant 2 carries it as a fourth permitted plaintext path; the five
guards are:

| Guard | Why |
|---|---|
| one reveal site, in the seen path's view, reachable only when `delivery.method` is `manual` | the third exception stays narrow structurally rather than carefully, and so does this one |
| refused with `--output json` and `--output jsonl`; no schema property can hold the value | as `--reveal` already is — a machine-readable document must never be the thing that carries it |
| **refused unless stdout is a terminal** | the guard `--reveal` has no counterpart for, and the one that carries the argument: a value redirected to a file or captured in a CI log outlives the single logon it is good for, because a log is read later and by other people, and expiry does not unpublish it. `\| clip` stops working; that cost is accepted rather than worked around |
| confirmed every time, and `--confirm` does not answer it (§2) | a yes given in advance asserts the very thing the prompt exists to establish |
| `force_expire: true` required, refused at plan time when absent | the exposure is bounded by the person's next logon, or it is not bounded at all |

**All five are built** (#441), and the build added one absence worth stating
here rather than leaving to be discovered: **a `--dry-run` is exempt from guards
2 to 4.** A preview prints a plan and never a password (§2), so there is no
emission for those three to guard — and the first draft refused one for want of a
terminal, which made *show me what this would do* impossible from the CI job that
most wants it. Guard 5 still binds on a preview, because it is a property of the
file rather than of an emission: a `manual` block without `force_expire: true` is
refused whether or not anything runs.

Guard 1 is also now **enforced rather than described**:
`tests/test_reveal_sites.py` parses `src/` and holds the set of `reveal()` call
sites to exactly those invariant 2 permits. Until #441 the count lived in three
docstrings, one of which said "the only `reveal()` call in the tool" and had been
false since this path was designed.

**The justification is different from `policy sample --reveal`'s, and weaker**,
which is why the narrowing is stricter. A sample guards nothing; this is a
credential somebody can log in with. What allows it is not that it is harmless but
that it is deliberate, witnessed and time-limited — the exposure is the point of
the path rather than a side effect of it (§1).

### 6.6 The unseen paths, and what each actually promises

They are not one guarantee with several implementations. Saying so is the point of
this subsection, because the config key makes them look interchangeable.

- **`vault_wrapped`** — single use. The unwrap is the last read, so a value fetched
  twice is a value somebody else fetched first, and **interception is detectable
  even where it is not preventable**. That is the strongest property in the table,
  and it comes with the weakest: the token is a **bearer credential**, so whoever
  holds it can unwrap it, whatever their identity. **Built in #444, and single use
  is Vault's rather than ours** — measured against the container, not taken from
  the documentation: the second unwrap answers 400, and there is no `num_uses` to
  configure because there is no counter this tool keeps.
- **`vault_path`** — owner-only by the store's own access control, for as long as
  the path's policy says so. Identity rather than bearer, which is the opposite
  trade: interception needs the person's own credentials, and nothing makes the
  read single-use, so **the value persists as a live credential** until something
  removes it. What that something is, is H8 (#459).
- **`one_time_link`** — one use, like the wrapping token, and a bearer credential
  for the same reason: the URL carries its own decryption key in the fragment
  (#445). It adds a third party to the trust story, which the two Vault forms do
  not.
- **`onepassword_share`** — whatever 1Password's API turns out to offer, which #446
  is explicitly unsure of and refuses to guess at. If single-view has to be
  simulated with a follow-up delete, the documentation must not claim single-view.
- **`smtp_encrypted`** — as strong as the recipient's key management, and no
  stronger.

**What the DBA is shown, and where** (#444). The password goes to Vault and to
nobody else; what comes back is the token, and it is printed because §6.1 bars it
from the notify channel and the tool carries no other channel at all. Three rules,
and the third has no counterpart on the seen path:

- **Never in the run document, and no property could hold it.** A document is
  captured, shipped to log aggregation and kept; a token in one outlives the TTL
  that is this method's whole guarantee. What it carries instead is the *accessor*,
  in `results[].handover` beside the expiry, which names the hand-over and cannot
  perform it — so a run stays auditable without the document becoming the thing
  that leaks.
- **No terminal is required**, which is a deliberate departure from `manual`'s
  third guard. A pipe is how a handover script works, and forbidding one would
  leave an estate no way to deliver unattended except the path that shows a DBA a
  password. The cost is stated rather than hidden: a redirect to a file outlives
  the token. What makes it a different trade is the object — fifteen single-use
  minutes whose one use is detectable, against a password good until somebody's
  first logon.
- **Under `--output json` it goes to stderr**, because stdout is carrying the
  document. `manual` is *refused* with `--output json`; this is not, because the
  document is what makes a scheduled reset auditable and taking it away would make
  an estate choose between an audit trail and the default method.

**"The DBA never sees it" has to be true of the store, not asserted.** A DBA whose
store token can read the person's path could read the password back, and the unseen
path's reason for skipping expiry would be gone. Whether the tool probes for that,
and what it does when the answer is yes, is H8 (#459).

### 6.7 Reusable by UC-4

The abstraction is a **delivery method taking a value and a recipient**, and it is
deliberately not a property of resetting a password. UC-4's onboarding hands a
person a first credential, which is the same operation with a different reason —
so `delivery:` is specified here, under UC-2, but it is not named for it, and
nothing in the block refers to a reset. What a method needs is the value, the
account, the target and a notify channel; what it must never need is *why*.

That is a constraint on the implementation rather than an aspiration: a method that
reached for the reset record (§3) or for `seen`/`expired` would not survive being
called by a use case that does neither.

### 6.8 What is still open

**H9 is new, and this section raises it rather than settling it.** §6.1 settles that
a retrieval credential never travels the notify channel. It does not settle where it
*does* travel, and the honest answer today is: nowhere the tool carries. The
wrapping token comes back to the DBA's terminal, and the handover to the person is
out of band.

That is not obviously wrong — a single-use token is a *detectable* interception, so
a DBA who unwraps it is caught by the person's failed fetch rather than trusted not
to. But it changes what §1 claims. "The DBA never sees the password" stays literally
true, and "the DBA cannot obtain it" does not. Those are different promises, and the
use case currently makes the second while describing the first.

So: **H9 — on `vault_wrapped`, the DBA holds the token; what does "unseen"
guarantee, and is there a channel the tool should carry it by instead?** It
interacts with H8 (#459), since both are about the difference between a guarantee
that is enforced and one that is asserted. Registered in §9 and tracked as **#496**;
it blocks no delivery method, because every one of them can be built against the
text above.

The shared notify channel is #442, the config block is #440 and the ratchet is #498.

**How an estate restricts the set of methods is decided** (H6, #453):
`safety.delivery.allowed_methods`, ratcheting by **intersection**, so each layer may
only narrow it and no higher-authority layer can restore a method a lower one
removed. It is fail-closed on purpose — a method a later release adds is unusable
until an estate names it — which is the opposite of what a `forbidden_methods` union
would have done on upgrade, and this is a guard in front of putting a live
credential on a wire. It is the fifth ratcheted setting and the first whose merge
shape is declared rather than read off its type; `01-configuration.md` §9 has the
rules, and **#498 built it**: the key is read from any `safety:` block, the
intersection is taken across every layer including a target's and a group's, two
layers with no method in common refuse at plan time naming all of them, and
`config show --explain` reports the effective set and which layer narrowed it. No
verb consults the answer, because no delivery method exists yet — the setting is
marked inert in the registry until one does.

---

## 7. The invariants, read for UC-2

| # | Invariant | Here |
|---|---|---|
| 1 | no secret in `argv` | binds unchanged, including every store credential |
| 2 | redaction at the serialiser | binds, and §3's metadata record is inside it rather than an exception to it: it holds no password in any representation, not a hash and not a verifier. A **Vault** write is already a permitted plaintext path, so the Vault forms of the unseen path need no widening; the other stores (#445, #446, `smtp_encrypted`) are not automatically one, and #456 says how each keeps the invariant. **The seen path's display is now the invariant's fourth permitted path** (#439), under the five guards in §6 — allowed because the exposure is deliberate, witnessed and expired, rather than because it is harmless, which is the third exception's argument and does not carry here |
| 3 | branch on capability, not version | binds — rollover (§4.3) is a capability |
| 4 | unavailable capability fails at plan time | binds — §4.3's seen-path refusal, §5's refusal of a deliberate `LOCKED`, §4.4's guardrails, and possibly H8's store check. §3.4's three absences are deliberately **not** on that list, and it says why: a reset needs none of them to do what it is for |
| 5 | the config is the whitelist | binds, with H1's amendment (#449): a personal account is declared in `personal_accounts:` by name or by predicate, and a predicate never widens what a mutating verb may touch — the second sentence, that selectors cannot extend the declared set, is untouched (§2) |
| 6 | vault is master | nothing to govern — no master (§1). H2 (#450) makes the database authoritative for **when** a password last changed, which is not a breach of this: invariant 6 governs the value, and a timestamp about the account is not one (§3.2) |
| 7 | never promote before confirmation | nothing to govern — no promotion (§1) |
| 8 | `--dry-run` and a plan first | binds, on both paths; the seen path also confirms (§2) |
| 9 | idempotency | **binds, and does not govern the reset** — H7 (#454) closed it by scope rather than by exception: a verb that draws fresh randomness has nothing to converge on, which puts `account reset-password` where `creds generate` already was (#254). It reports `changed: true` every run and warns what it replaced (§4.5). `expire-password`, `account suspend` and `account list` are all inside the invariant and hold it. The convergent shapes were refused because both key on a record an estate need not configure, and account state is not a signal on the unseen path at all |
| 10 | safety settings only ratchet | binds, and H6 (#453) has added the axis: `safety.delivery.allowed_methods`, ratcheting by **intersection** so a layer may only narrow which delivery methods an estate may use. The fifth ratcheted setting and the first whose merge is declared rather than read off its type — `01-configuration.md` §9 has the shape, P3 has why it is not a union. Built by #498, as a `delivery:` sub-block of a `safety:` block rather than a key of the `delivery:` block it governs |
| 11 | no `"` in a password | binds, by generation; authoritative over UC-1 §6.1's older wording |
| 12 | JSON output is versioned | binds — new verbs and events are schema bumps |
| 13 | no password literal in a PL/SQL block | binds on both statements (§4.1) |
| 14 | no password bound into a predicate | binds, and nothing here reaches it: H4 decided a reset never verifies, by hash or by anything else (§5) |

Invariants 6 and 7 not governing is a property of this use case, not an exemption
from them: a store here holds a value for one person to fetch, never a value to be
synced from. The metadata record is not a third thing to read that sentence
against — nothing fetches a value from it either, because there is none in it
(§3.1).

---

## 8. Testing

Tier 1 covers the core: Oracle Free with its rollover capability, and the Vault
container the unseen path writes to. Tier 0 covers everything with no I/O — the
plan, the refusals, the confirmation, generation, and the statement text, which is
where invariant 13's assertion already lives for UC-1.

What a test must show, once there is something to test:

- **unseen:** after a reset the account is not `EXPIRED`; the value is retrievable
  by the owner's identity or wrapping token and by nothing the DBA holds (H8); the
  statement sent carries no `PASSWORD EXPIRE`; the password appears in no output of
  the tool at all;
- **seen:** the reset does not run without confirmation; afterwards
  `DBA_USERS.ACCOUNT_STATUS` carries the `EXPIRED` component — `EXPIRED`, or
  `EXPIRED & IN ROLLOVER` on a rollover profile, which is the combination §4.3
  refuses at plan time and which #455's probe measured rather than predicted —
  and, for an account that is not locked, a logon with the password is forced to
  change it; a rollover profile is refused at plan time (§4.3); the password is
  emitted exactly once, to stdout, and nowhere else. **Each of §6's five guards is
  its own assertion, and all five are tier 0** — none of them needs a database:
  the reveal site is unreachable for any delivery method other than `manual`;
  `--output json` and `--output jsonl` are refused; a non-terminal stdout is
  refused; `--confirm` is refused as a usage error; and `manual` without
  `force_expire: true` is refused at plan time. The schema restriction is **part of
  the second guard rather than a sixth** — `--output json` is refused *and* no
  property of a result could hold a password if it were not — and it is asserted
  the way `policy sample`'s already is, against the published schema rather than
  against a run;
- **the H4 behaviours (§5, §4.3)**, and each of these is a tier-1 assertion
  because each was a measurement first. **The unlock assertion differs by path,
  and saying so is the point**: on the **unseen** path a reset of a
  `LOCKED(TIMED)` account leaves it `OPEN` and the owner able to log in with the
  new password *and nothing else*; on the **seen** path the same reset leaves
  `EXPIRED`, so what is asserted there is that the first logon is **forced to
  change the password**, never a plain login — the expiry that path exists for is
  not an obstacle the unlock removes. Then, on both: a reset of a deliberately
  `LOCKED` account is refused at plan time and issues no DDL; an account that is
  not locked gets no `ACCOUNT UNLOCK` statement at all, which is checked by
  reading `SYS.USER$.LCOUNT` across the reset and finding it unmoved — the
  assertion that would have caught the Q1 behaviour had anyone thought to write
  it; and a reset on a rollover profile leaves the old password answering
  `ORA-01017`, with the window-keeping flag the one way to see
  `OPEN & IN ROLLOVER` afterwards;
- **the record (§3):** it is written after the database confirms and not before; it
  contains no password in any representation, which is a tier-0 assertion on the
  serialised document rather than a tier-1 one on what the store received; a reset
  with no store configured still succeeds and warns at plan time; and two
  concurrent resets of one (target, account) collide on the lock its path keys,
  where before H2 they collided on nothing;
- **both:** the password appears in no run document, diagnostic or log sink, and in
  no jsonl event once this verb streams. The seen path's one deliberate emission
  is the only exception, and it is what that path's confirmation guards;
- the two measurements behind the seen path's markers, each on 26ai and then 21c —
  gate 2's probe extended to the `PASSWORD EXPIRE` form
  (unverified: expire-ddl-text), and §4.3's window behaviour, which #461 ran on
  21c and which agreed with 26ai. Run, not reasoned, which is the only way either
  marker comes off.

Tests declare the capabilities they need and skip with a reason when absent
(`04-testing.md`), never on a version.

---

## 9. Open questions

| # | Question | Issue |
|---|---|---|
| ~~H1~~ | ~~Where is a personal account declared, so invariant 5 still whitelists it?~~ | **closed** — a `personal_accounts:` section, holding names or a predicate over a profile or role. The predicate amends invariant 5's first sentence and leaves its second intact, because it never widens what a mutating verb may touch: a reset names its account and `account list` resolves the rule. The stated cost is that membership is a profile assignment or a role grant rather than a commit somebody reads; the keys and validators are #467 (§2) · #449 |
| ~~H2~~ | ~~With no vault as master, what is recorded about a reset, and where?~~ | **closed** — three places, not one. The **database** answers *when* (`PASSWORD_CHANGE_DATE`, `PTIME` behind the grant, with 12.1 unmeasured on that fallback (unverified: pw-changed-source)), which is a divergence from Q9 and §3.2 says why: on the seen path the owner is required to change the password, so a record's own timestamp is designed to go stale. A **metadata record**, written wherever a store is configured, answers *who*, *which path* and *where it was delivered*, never a value — and its path is what Q2's lock finally has to key on. **Nothing** answers *what to roll back to*, because rollback is not a UC-2 operation. A reset with no store configured warns and runs; the keys, schema and validators are #468 (§3) · #450 |
| ~~H3~~ | ~~The noun and the verbs~~ | **closed** — the noun is `account`, the configuration's own word for what is being managed, whichever key declares it (`accounts:`, an `applications:` entry, or H1's `personal_accounts:`); the verbs are `reset-password` and `expire-password`, the latter its own verb rather than a flag; suspending an account is `account suspend`, named that way to avoid a second sense of `lock` and specified in #463; and listing is `account list`, which H1 earned (§2) · #451 |
| ~~H4~~ | ~~Does a reset verify the password, unlock (including `LOCKED(TIMED)`), or end a rollover window?~~ | **closed** — never verifies (reports `ACCOUNT_STATUS` instead); unlocks `LOCKED(TIMED)` by default and refuses a deliberate `LOCKED`; ends the rollover window by default, with a flag to keep it (§4.3, §5) · #455 |
| ~~H5~~ | ~~Is self-service part of UC-2?~~ | **closed** — self-service means fetching the password from a secure store, not resetting through the tool (§5) · #452 |
| ~~H6~~ | ~~Restricting delivery methods: an `allowed_methods` intersection or a `forbidden_methods` union?~~ | **closed** — `safety.delivery.allowed_methods`, ratcheting by **intersection**. Fail-closed: a method added in a later release is unusable until an estate names it, where a `forbidden_methods` union would have permitted it everywhere on upgrade. It costs a fourth ratchet shape, declared per setting as `safe_bool` already is, since both keys would be lists of strings and the type cannot say which merges how. Unset means no constraint; two layers with disjoint lists refuse at plan time naming both; and there is no `forbidden_methods`, now or later · #453 |
| ~~H7~~ | ~~A reset never converges: a second invariant-9 exemption, or a convergent verb?~~ | **closed** — neither, as asked. The reset reports `changed: true` every run and warns what it replaced, and invariant 9 is restated as a **scope** rule rather than gaining a second exemption: a verb that draws fresh randomness has nothing to converge on, which admits `creds generate` and this one by the same sentence and will admit UC-4's account creation without another argument. Convergence on a request id or on account state was refused for one reason each — the key is a record an estate need not configure and which is missing in exactly the runs somebody retries, and account state does not exist on the unseen path, which issues no `PASSWORD EXPIRE`. The stated cost is that an unattended retry delivers twice, and the warning is what carries it (§4.5) · #454 |
| H8 | On the unseen path, what happens to the stored copy, and how is the DBA shown unable to read it? | #459 |
| H9 | On `vault_wrapped`, the DBA holds the token — so what does "unseen" guarantee, and is there a channel the tool should carry a retrieval credential by instead? | #496, raised by §6.8 |
| H10 | §1's attribution guarantee holds only where the database audits `ALTER USER` and logons. Does a reset check that, and warn, refuse or record what it found? | #591, raised by §1 |
| ~~—~~ | ~~How the seen path's one plaintext emission is narrowed, and whether `--confirm` answers its prompt in advance~~ | **closed** — it prints, under five structural guards (§6): one reveal site, refused with `--output json`/`jsonl` and unrepresentable in the schema, refused unless stdout is a terminal, confirmed every time with `--confirm` **not** answering it, and `force_expire: true` required. `CLAUDE.md` invariant 2 gains a fourth exception, justified by the exposure being deliberate, witnessed and expired rather than harmless — so the narrowing is stricter than `--reveal`'s, not equal to it · #439 |

Deliberately not a question with an issue: §4.4's collision between guardrail
check 4 and DBA accounts in scope, which is decided #89 applied to a population it
was not written for, and is stated so that H1 and part 2 meet it rather than
rediscover it. The seen path's default for ending a rollover window is not one
either. `expire-rollover` is **settled on 26ai and 21c** (#455, #461): the
statement is accepted, the status is `EXPIRED & IN ROLLOVER`, and the expiry
leaves the old password authenticating. The refusal stands on that, and whether
it narrows to accounts whose old password is still live is #541 (§4.3).

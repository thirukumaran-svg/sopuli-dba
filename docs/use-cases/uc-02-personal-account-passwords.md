# UC-2 — Personal account passwords: reset and hand over

Status: draft / sketch. **Nothing here is built, and much of it is not decided** —
§9 lists what is open, and each open question is a `decision` issue.
Depends on: `../design/00-principles.md`, `../design/01-configuration.md`,
`../design/02-oracle-privileges.md`

This is part 1 of the specification (#438). Delivery — the methods by which the
new password reaches a person — is part 2, #456; §6 sets out what part 2 builds on.

---

## 1. Summary

**Goal.** A person cannot get into their own database account — a developer's, a
tester's, a DBA's — usually because the password expired and they no longer know
it. A DBA resets it, and the tool makes the new password **the person's alone**.
There are two ways to get there, they do not give the same guarantee, and which one
a reset takes decides almost everything else in this document:

| Path | The DBA sees the password | How the person gets it | Expired on reset |
|---|---|---|---|
| **unseen** — the default | no | fetches it from a store meant for them alone: a Vault path only their identity can read (#447), or a single-use wrapping token (#444) — a bearer credential, so owner-only only as far as its delivery is (#456); password managers later | **no** |
| **seen** — `manual` | yes | the DBA passes it on — encrypted email or similar — with instructions to change it | **yes, always** |

**The unseen path is the default**, and it is what the tool exists to make possible:
a DBA resets a password without ever seeing it, and the tool puts the value in none
of its own output. Nothing needs expiring, because nobody but the person is meant
ever to know it — §4.1 and H8 say where that intent meets its limits.

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
| Secure store | holds the password for the owner to fetch — a Vault first (#456) |

**Direction of truth.** There isn't one, and that is the first way this differs
from UC-1. `docs/README.md` puts it as *a password is handed over, not synced*.
Nothing reads the value to stay in step with it, so no store is master of it. On
the unseen path a store does hold it for the person to fetch, and that is
transport, not mastery; what happens to that copy afterwards is H8 (#459).
Invariants 6 and 7 therefore have nothing to govern here (§7). **That does not
make the database a source of truth either**: the tool reads account state from
it, as UC-1 does, and never a password.

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

**Not named yet** — H3 (#451) is the noun and the verbs, and D2's noun-verb
grammar is the only constraint already binding. What the use case needs, whatever
it ends up being called:

| Operation | What it does | Mutates |
|---|---|---|
| reset, unseen (default) | generate a password, set it, write it where only the owner is meant to fetch it; show it to nobody | yes |
| reset, seen (`manual`) | generate a password, set it **with expiry**, show it once — after confirmation | yes |
| plan | either of the above under `--dry-run`, printing the plan and never a password (invariant 8) | no |
| expire only | `PASSWORD EXPIRE` with no new password — "make them change it" | yes |

**The seen reset asks for confirmation every time** — decided on review of #457,
and recorded in P5 beside the two gates that already do, `creds rotate` and
`lock break`. Like them it does not consult `safety.confirm_environments`, and it
is not a setting a layer could relax. Whether `--confirm` answers it in advance, as
it does those two, is not decided here: it is the one reset where the prompt is the
point, and it belongs with the rest of how the seen path's one plaintext emission
is narrowed, in #439.

Whether *expire only* is its own verb, a flag, or out of scope is part of H3.
Whether there is a read verb — "when was this person last reset" — depends on H2.

Every operation is limited to declared accounts. **Where a personal account is
declared is H1 (#449)** — the application binding that declares UC-1's accounts
means *these accounts are mastered by these secrets*, which is not true of any
account here.

---

## 3. What is recorded

UC-1's vault payload answers three questions at once: when a password last changed
(Q9's `rotated_at`), what to roll back to (`previous`), and where the lock lives
(Q2, keyed on the secret path). UC-2 has no payload, so each needs its own answer.
**H2 (#450) is those answers**; what is already true regardless:

- **Rollback is not a UC-2 operation.** The recovery for a lost personal password
  is another reset. Nothing keeps an old value to go back to.
- **The unseen path's store copy is not a record.** It exists for the person to
  fetch; whether it outlives the fetch is H8 (#459), and it is never read back by
  the tool as history.
- **The run document is always a record**, and it never carries a password
  (invariant 2). So will the jsonl stream be, once there is one — `--output jsonl`
  is a usage error in this build (`03-json-output.md`). Whether anything more
  durable exists is H2.
- **The database can report when a password changed**, but not on every release by
  the same route: `DBA_USERS.PASSWORD_CHANGE_DATE` where it exists, `SYS.USER$.PTIME`
  behind the optional grant otherwise (#386), and 12.1, 12.2 and 19c unmeasured
  (unverified: pw-changed-source).

---

## 4. The reset

### 4.1 The statement

One direct statement on each path. The seen path adds the expiry to it. The account
is the quoted identifier in the spelling the dictionary gives back, as for UC-1 —
`account.quoted()` in `sopuli/driver/oracle/statements.py`:

```sql
-- unseen (default)
ALTER USER "<ACCOUNT>" IDENTIFIED BY "<password>"
-- seen (manual)
ALTER USER "<ACCOUNT>" IDENTIFIED BY "<password>" PASSWORD EXPIRE
```

Setting a password clears an existing `EXPIRED` state — Oracle's behaviour, which
UC-1 §5 already relies on — so the unseen statement is the whole fix for an account
that expired and whose owner no longer knows the password.

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
  (#387); 12.1, 12.2 and 19c are unrun (unverified: ddl-text-versions). **This is
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
than UC-1 §3's ordering problem — but the order is still a choice, and it belongs
to the delivery section (#456).

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
the case where it is not nobody. Closing the window early is the
`EXPIRE PASSWORD ROLLOVER PERIOD` statement `creds finish-rollover` issues (#263),
and UC-1 §6.3 refuses to choose it for anyone, because it is destructive to whoever
still holds the old password. Whether a UC-2 reset closes it by default, offers it,
or never does is part of H4 (#455).

**On the seen path it is unmeasured.** How `PASSWORD EXPIRE` combines with an open
window — whether expiring the new password also ends the old one's, and whether
the statement is accepted at all during one — has not been run
(unverified: expire-rollover). Until it has, **a seen reset of an account whose
profile sets a non-zero rollover time is refused at plan time**, naming the account
and the profile, before any DDL is issued. That is invariant 4, and it is the
project's standing rule for an unmeasured answer: refuse rather than guess. The
unseen path remains available for the same account.

### 4.4 Guardrails

`02-oracle-privileges.md` §4's five account checks bind unchanged, and one of them
collides with the roadmap. **Check 4 refuses any account holding `DBA`, `PDB_DBA`,
`CDB_DBA` or `AUDIT_ADMIN`**, and the roadmap names DBA accounts as in scope. Under
today's rule every reset of a DBA's personal account needs `--force`, which
overrides checks 2–5 and is recorded in the audit event (#89).

That is stated here rather than solved. It may be the right answer — a DBA account
is precisely where a reset deserves an explicit override — or it may make `--force`
routine in a way #89 did not intend. Neither reading is taken here.

---

## 5. Lockout, unlocking, and self-service

**A reset attempts no login**, so most of UC-1 §7 has nothing to guard: its six
mitigations exist to stop a scheduled *check* from locking an account. What
survives is H4 (#455):

- **Does UC-2 ever verify a delivered password?** On the seen path a login with it
  would consume the `EXPIRED` state the reset exists to create, so verifying by
  login is wrong by construction there. The unseen path has no expiry to consume,
  so the question is open on its own terms — a failed attempt still counts against
  `FAILED_LOGIN_ATTEMPTS`. Verifying by hash depends on #437 and #90, and never by
  a bound value (invariant 14).
- **Does a reset unlock, or end a rollover window?** People ask for a reset because
  they are locked out. But 01-configuration §8 makes every account attribute opt-in
  *as a rule, not a default*, and `unlock_if_locked` is `false` (#300). That rule
  was argued for a rotation nobody asked to change anything else; a person's reset
  is arguably asked for. **`LOCKED(TIMED)` is part of the same question, not a
  variant of `LOCKED`**: Oracle clears it when `PASSWORD_LOCK_TIME` passes, so a
  reset that does not unlock leaves the owner waiting on that timer rather than
  locked indefinitely. Whether setting a password affects the timer has not been
  run, and nothing here assumes it does.

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

**Part 2 of this specification, #456.** What it builds on:

- **The unseen path is the default, and Vault is the first store.** Two forms, and
  they are not the same guarantee:
  - a **path only the person's identity can read** (#447) — owner-only by the store's
    own access control, for as long as the path's policy says so;
  - a **response-wrapping token** (#444) — single use, the unwrap is the last read.
    This is what "the person fetches it from a cubbyhole" means in practice: a
    cubbyhole belongs to the token that wrote it, so a DBA's own cubbyhole is
    unreadable by anyone else, and the wrapping token's cubbyhole is the handover.
    **But the wrapping token is a bearer credential**: whoever holds it can unwrap
    it, whatever their identity. It is owner-only exactly as far as the channel it
    travels by is, and that channel is #456's to decide.

  Which form is the default, or whether that is configuration, is #456's.
- **Then other stores**: password managers (#446), one-time links (#445), and
  `smtp_encrypted` — encrypted email sent by the tool, which is unseen, unlike the
  DBA sending it by hand. It has no issue of its own yet; #456 carries it.
- **"The DBA never sees it" has to be true of the store, not asserted.** A DBA whose
  store token can read the person's path could read the password back, and the
  unseen path's reason for skipping expiry would be gone. Whether the tool checks
  that, and what it does if the token can read, is H8 (#459).
- **`manual` is the seen path**: #441, non-default, confirmed, forced expiry — and
  #439 for how its one plaintext emission is narrowed.
- **One rule is binding now**, because #438 set it and every delivery issue is
  written against it:

  > **The channel that notifies may be low-trust. The channel that carries the
  > secret may not.** "Your new password is ready" may go anywhere; the password,
  > or anything that retrieves it, may not.

  A wrapping token and a one-time link both retrieve the secret, so by this rule
  neither may travel by the notify channel; how each does travel is #456's.

The shared notify channel is #442, the config block #440, and how an estate
restricts the set of methods is H6 (#453).

---

## 7. The invariants, read for UC-2

| # | Invariant | Here |
|---|---|---|
| 1 | no secret in `argv` | binds unchanged, including every store credential |
| 2 | redaction at the serialiser | binds. A **Vault** write is already a permitted plaintext path, so the Vault forms of the unseen path need no widening; the other stores (#445, #446, `smtp_encrypted`) are not automatically one, and #456 says how each keeps the invariant. The seen path's display is not a permitted path, and is #439 |
| 3 | branch on capability, not version | binds — rollover (§4.3) is a capability |
| 4 | unavailable capability fails at plan time | binds — §4.3's seen-path refusal, §4.4's guardrails, and possibly H8's store check |
| 5 | the config is the whitelist | binds; *where* the account is declared is H1 |
| 6 | vault is master | nothing to govern — no master (§1) |
| 7 | never promote before confirmation | nothing to govern — no promotion (§1) |
| 8 | `--dry-run` and a plan first | binds, on both paths; the seen path also confirms (§2) |
| 9 | idempotency | **open** — a reset as sketched draws a new password on every run; H7 (#454) decides between an exemption and a convergent verb |
| 10 | safety settings only ratchet | binds; H6 (#453) would add an axis, written in #456 |
| 11 | no `"` in a password | binds, by generation; authoritative over UC-1 §6.1's older wording |
| 12 | JSON output is versioned | binds — new verbs and events are schema bumps |
| 13 | no password literal in a PL/SQL block | binds on both statements (§4.1) |
| 14 | no password bound into a predicate | binds — relevant only if H4 verifies by hash |

Invariants 6 and 7 not governing is a property of this use case, not an exemption
from them: a store here holds a value for one person to fetch, never a value to be
synced from.

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
  the tool's at all;
- **seen:** the reset does not run without confirmation; afterwards
  `DBA_USERS.ACCOUNT_STATUS` carries the `EXPIRED` component — `EXPIRED`, or
  `EXPIRED & LOCKED` for an account that stays locked under whatever H4 decides —
  and, for an account that is not locked, a logon with the password is forced to
  change it; a rollover profile is refused at plan time (§4.3); the password is
  emitted exactly once, by the path #439 decides, and nowhere else;
- **both:** the password appears in no run document, diagnostic or log sink, and in
  no jsonl event once that stream exists. The seen path's one deliberate emission
  is the only exception, and it is what that path's confirmation guards;
- the two measurements behind the seen path's markers, each on 26ai and then 21c —
  gate 2's probe extended to the `PASSWORD EXPIRE` form
  (unverified: expire-ddl-text), and §4.3's window behaviour
  (unverified: expire-rollover). Run, not reasoned, which is the only way either
  marker comes off.

Tests declare the capabilities they need and skip with a reason when absent
(`04-testing.md`), never on a version.

---

## 9. Open questions

| # | Question | Issue |
|---|---|---|
| H1 | Where is a personal account declared, so invariant 5 still whitelists it? | #449 |
| H2 | With no vault as master, what is recorded about a reset, and where? | #450 |
| H3 | The noun and the verbs | #451 |
| H4 | Does a reset verify the password, unlock (including `LOCKED(TIMED)`), or end a rollover window? | #455 |
| ~~H5~~ | ~~Is self-service part of UC-2?~~ | **closed** — self-service means fetching the password from a secure store, not resetting through the tool (§5) · #452 |
| H6 | Restricting delivery methods: an `allowed_methods` intersection or a `forbidden_methods` union? | #453 |
| H7 | A reset never converges: a second invariant-9 exemption, or a convergent verb? | #454 |
| H8 | On the unseen path, what happens to the stored copy, and how is the DBA shown unable to read it? | #459 |
| — | How the seen path's one plaintext emission is narrowed, and whether `--confirm` answers its prompt in advance (invariant 2) — that it exists, non-default and confirmed, is decided | #439 |

Deliberately not a question with an issue: §4.4's collision between guardrail
check 4 and DBA accounts in scope, which is decided #89 applied to a population it
was not written for, and is stated so that H1 and part 2 meet it rather than
rediscover it. The seen path's default for ending a rollover window is not one
either: the refusal stands until `expire-rollover` is measured, and the register
entry is where that is tracked.

# sopuli-dba — working agreement

A CLI for DBAs that manages database account credentials with a vault as the
master record. Oracle first, multi-product by design.

**Status: pre-implementation.** The design documents are complete and decided;
almost no code exists yet. The SQL in `sql/` has been executed against Oracle 26ai
Free 23.26.2.0.0, Oracle 21c XE 21.3.0.0.0, Oracle 18c XE 18.4.0.0.0 and Oracle
11g XE 11.2.0.2.0. Each script carries a `STATUS:` header saying which paths ran
and which are still untried — trust that header, not this line, and update it
when you run one. 19c is the one still untried, and it is the one that matters
most: it is what an OCI estate runs, and both #383 and #387 need it answered.

---

## Read before changing behaviour

`docs/design/00-principles.md` is **binding**. A use case may refine it; nothing
may contradict it. If a change seems to require contradicting it, stop and say
so — that is a design decision, not an implementation detail.

| Document | When it applies |
|---|---|
| `docs/design/00-principles.md` | always — driver interface, vault interface, config precedence, cross-platform rules, exit codes |
| `docs/design/01-configuration.md` | anything touching config, targets, applications, SecretRefs, password policy |
| `docs/design/02-oracle-privileges.md` | anything issuing SQL against Oracle |
| `docs/design/03-json-output.md` | anything that produces output |
| `docs/design/04-testing.md` | anything touching tests or the test stack |
| `docs/use-cases/uc-01-app-credential-sync.md` | the credential sync/rotate feature — the only use case in scope |
| `docs/decisions/adr-001-privilege-model.md` | before proposing a definer-rights package (it was considered and rejected) |
| `docs/decisions/adr-005-vault-client.md` | before proposing `hvac` or another Vault client library for the HashiCorp backend (it was considered and rejected — the HTTP API over `httpx` is the answer) |
| `docs/decisions/adr-006-optional-dependencies.md` | before adding a dependency, or before assuming a vendor client is present — vendor clients are install extras and base opens no sockets |
| `docs/decisions/adr-007-vault-token-flag.md` | before giving any flag a secret *value*, or before adding `--vault-token-stdin` — `--vault-token` was considered and is refused; the flag takes a path |
| `docs/README.md` | before deferring work to "another use case" — the roadmap names UC-2…UC-5 and UC-1b, and says what already defers to each |
| `docs/local-testing.md` | adding or changing a command, a flag, an exit code, or a message an operator meets — the by-hand guide moves with the surface, not after it |
| `docs/workflow.md` | branching, commit format, and release process |

---

## Invariants — do not violate these without an explicit decision

These are not style preferences. Each exists because getting it wrong breaks
something specific.

1. **Secrets never appear in `argv`.** Visible in `ps` and the Windows process
   list. Passwords come from stdin, a file, or a vault ref — never a command-line
   option.
2. **Redaction happens at the output serialiser, not at each call site.** Secret
   values are wrapped in a type whose `str`, `repr` and JSON serialisation are
   `"***"`. There must be no code path that emits plaintext except the vault write,
   the driver call, `policy sample --reveal`, UC-2's seen reset, and the wrapping
   token an unseen delivery hands back (#444, and the only one of the five that is
   not a password). Do not "remember to mask" at a log statement.

   The third exception is allowed because **a sample is not a credential**:
   nothing authenticates with it, it is never stored, and it guards nothing —
   which is what makes `pwgen` safe and a vault write dangerous. It stays narrow
   structurally rather than carefully: the one `reveal()` call outside the tests
   lives in `sopuli/output/policy_view.py`, it is reachable only under `--reveal`,
   `--reveal` is refused with `--output json`, and the run schema gives a sample no
   value property to put a password in. Widening it again is a decision, not an
   implementation detail.

   **The fourth exception is `account reset-password` on the seen (`manual`) path,
   decided in #439, and its justification is different from the third's** — which
   is the thing to understand before touching it. A sample guards nothing; this
   *is* a credential, and one somebody can log in with. What makes it allowed is
   not that it is harmless but that it is **deliberate, witnessed and
   time-limited**: an operator asked for the seen path by name, answered a prompt,
   and the password is expired at the moment it is set, so the person's first logon
   must change it. The exposure is the point of the path rather than a side effect
   of it, and UC-2 §1 calls it that.

   Because the justification is weaker, the narrowing is **stricter** than
   `--reveal`'s, not merely equal to it. Five structural guards, and none of them
   is a reminder:

   - one reveal site, in the seen path's own view module, reachable only when the
     configured delivery method is `manual` -- and `tests/test_reveal_sites.py`
     now holds the whole set by parsing `src/`, so a new site fails the suite
     rather than being noticed in review (#441);
   - refused with `--output json` and `--output jsonl`, as `--reveal` is, and the
     run schema gives the result no property a password could occupy;
   - **refused unless stdout is a terminal.** This has no counterpart in
     `--reveal` and is the guard that carries the argument: a value redirected to a
     file or captured in a CI log outlives the one logon it is good for, because a
     log is read later and by other people, and expiry does not unpublish it. The
     cost is real and accepted — `| clip` and `| pbcopy` stop working, and the
     operator reads the value off the screen instead;
   - **confirmed every time, and `--confirm` does not answer it in advance.** The
     third unconditional gate in P5, and the strictest: `creds rotate` and `lock
     break` both take the yes given ahead of time, and this one does not, because
     if nobody is present to answer then nobody is present to receive the password
     either. It is the same claim the terminal check makes, made twice on purpose;
   - `force_expire: true` is required on the method, and a `manual` delivery
     without it is refused at plan time rather than silently defaulted.

   **All five are built** (#441). A sixth guard the build added on its own is
   worth knowing because it is an absence: a `--dry-run` of the seen path is
   *exempt* from guards 2 to 4, because a preview prints a plan and never a
   password, and refusing one for want of a terminal made "show me what this
   would do" impossible from the job that most wants it.

   **The fifth exception is the wrapping token an unseen delivery hands back,
   decided in #444, and it is not a password at all** — which is why its argument
   is shaped differently from the four above rather than being a weaker version of
   the fourth. What makes it an exception is §6.1's rule that the guard is about
   *reach* and not about value: "the password, or anything that retrieves it". A
   response-wrapping token holds no password and produces one, so it is typed as a
   `Secret` and emitted through one `reveal()`, in
   `sopuli/output/delivery_view.py`.

   What allows the emission is that there is nowhere else for it to go. §6.1 bars
   it from the notify channel, the tool carries no other channel, and the handover
   to the person is out of band — so a method that could not print it could not
   deliver at all. Three rules keep it narrow, and the middle one is **weaker**
   than the seen path's on purpose:

   - **never in the run document, and no property could hold it.** The document is
     captured and kept, and a token in one outlives the TTL that is the method's
     whole guarantee. What it carries instead is the *accessor*, in
     `results[].handover`, which names the hand-over and cannot perform it (#444);
   - **no terminal is required**, which is guard 3 deliberately not applied. A pipe
     is how a handover script works, and forbidding one would leave an estate no
     unattended path but `manual`. The cost is real and accepted: a redirect
     outlives the token. What makes it a different trade is the object — minutes of
     single use, whose one use is detectable, against a password good until
     somebody's first logon;
   - **under `--output json` it goes to stderr** rather than being refused, because
     the document is what makes a scheduled reset auditable and refusing it would
     make an estate choose between an audit trail and the default method.

   A **sixth** exception is a decision, not an implementation detail — and so is
   loosening any of the five guards above, or any of the three rules here.
   `tests/test_reveal_sites.py` holds the whole set by parsing `src/`, so a new
   site fails the suite rather than being noticed in review.
3. **Never branch on a version number from config.** Query the database for its
   capabilities, cache per session, and branch on the capability. See P1.
4. **A command that needs an unavailable capability fails at plan time**, with a
   distinct exit code and a message naming the capability and the target — never
   a generic error mid-execution.
5. **The config is the whitelist.** The tool never touches an account the config
   does not declare. Selectors filter the declared set; they cannot extend it.
   `--force` overrides other guardrails, never this one.

   **What counts as *declared* has two forms** (H1, decided in #449). UC-1's
   accounts are enumerated by name, in `accounts:` or an `applications:` entry. A
   **personal account** is declared in `personal_accounts:`, by name *or* by a
   **predicate** over a profile or a role, resolved against the database at run
   time — because enumerating four hundred developers is transcription rather than
   review. The predicate amends this invariant's first sentence and leaves the
   second intact: `--account` filters the resolved set, it does not widen it.

   **A name may not be declared twice.** An account that is both an application
   account and a personal one makes the whitelist ambiguous about which guarantee
   applies — mastered by a secret, or handed over — so the validator rejects it
   rather than picking. Enforced across `accounts:`, `applications:` and
   `personal_accounts:` alike.

   **A predicate never widens what a mutating verb may touch.** A listing verb
   resolves it and shows what it matched; a mutating verb additionally requires the
   account named on the command line and refuses any name the predicate does not
   admit — so one run touches exactly one account, which the operator typed and the
   configuration admits. The cost is real and is stated in UC-2 §2 rather than
   buried: predicate membership is controlled by whoever grants the profile or
   role, not by whoever reviews the file.
6. **Vault is master; direction is vault → database, always.** The database is
   never the source of truth.
7. **Never promote in the vault before every target has confirmed.** The
   `pending` → `current` ordering in UC-1 §3 is the whole safety design. Read it
   before touching rotation. **`creds generate --promote` is the one exception**
   (decided in #257): it writes `current` having asked no database anything, and
   over an existing `current` only with `--overwrite-current`. What the invariant protects
   is a *window* — a `current` that applications are reading, replaced before any
   database can serve the new value — and `--promote` exists for the case where
   the operator already knows the password and no rotation is in flight. The same
   write moves the value `current` held into `previous`, so §8's rollback keeps
   somewhere to go.
   Written here rather than left to be discovered in a diff, as invariant 9's
   scope rule is, and a second exception is a decision rather than an
   implementation detail.
8. **Every mutating command supports `--dry-run` and prints a plan first.**
9. **Idempotency:** running a **convergent** command twice must report
   `changed: false` the second time and emit no mutation audit record.

   **A convergent command is one with a state to converge on, which is all of
   them but the two below** — the qualifier narrows the sentence and is not a
   loophole in it. `apply` converges the database on the vault, and it is the one
   that must report `changed: false` on a re-run. `account suspend` is the same
   rule read through the driver: it reads `ACCOUNT_STATUS` first, so a second
   `ACCOUNT LOCK` against an already-locked account reports `changed: false`.
   `04-testing.md` §6's release gate states the criterion in the same words, and
   the two must stay in step.

   **A verb that draws fresh randomness has nothing to converge on, and is
   outside the invariant rather than an exception to it.** `creds generate`
   (#254) and `account reset-password` (#454) are both instances: each reports
   `changed: true` on every run, and each must say what it replaced — `generate`
   names the version whose `pending` it overwrote, and a reset says that whoever
   holds the previously delivered password now holds one that no longer works.

   **Scope rather than a list of exemptions, decided in #454**, and the framing
   is the decision. A list grows one entry at a time and invites the same
   argument with every later verb that draws a password — UC-4's account
   creation being the next one — while the rule that admits both of these admits
   that one too, for a reason anybody can check. What is *not* open to an
   implementer is the membership test: a verb is outside only because a fresh
   random draw has nothing to compare against, and anything with an observable
   target state is convergent and must report `changed: false`. A verb that is
   inside the invariant and cannot satisfy it is a decision, not an
   implementation detail.

   **Convergence bought with an optional key does not count**, which is the
   other half of #454 and the reason a reset is not made convergent instead. Both
   ways of doing it — on a request id, or on "already expired since the last
   recorded reset" — key on a metadata record an estate need not configure
   (UC-2 §3.1), which is also absent in exactly the partly-failed runs somebody
   retries (§3.4); and account state does not exist as a signal on the unseen
   path at all, since it issues no `PASSWORD EXPIRE`. An idempotency that holds
   only where an optional block was written is worse than an honest
   `changed: true`, because nothing in the output says which of the two you got.
10. **Safety settings only ratchet toward safe.** `readonly`, `--dry-run`,
    `max_targets`, `confirm_environments` and `safety.delivery.allowed_methods` cannot
    be relaxed by a higher-precedence source. See P3.

    **`safety.delivery.allowed_methods` ratchets by *intersection*, and it is the one
    setting whose merge cannot be read off its type** (H6, decided in #453). The
    other four take one of three shapes chosen by type — a bool to its declared
    safe value, an int to the minimum, a list to the union — and this is a list
    that must not union: each layer may only narrow the set of UC-2 delivery
    methods, never restore one a lower layer removed. Since
    `confirm_environments` is a list of strings too, the shape is **declared per
    setting**, exactly as `safe_bool` already is for the booleans whose polarity
    the type could not give.

    It is fail-closed on purpose, which is the whole reason for the extra shape:
    a method added in a later release is unusable until an estate names it. A
    `forbidden_methods` union would have cost no new code and permitted every new
    method everywhere on upgrade — silently widening a guard that stands in front
    of putting a live credential on a wire.

    Three rules come with it, and each exists because the union has no equivalent
    problem: **unset means no constraint**, not the empty intersection, so a file
    that declares nothing can still deliver; **two layers with disjoint lists are
    a plan-time refusal** naming both, because an empty result is a configuration
    nobody can have meant; and **there is no `forbidden_methods`**, now or later.
    One key, so there is no evaluation order to document and no second spelling
    of one guard. Adding the second key is a decision rather than an addition.
11. **Passwords containing `"` are rejected, not escaped.** Oracle quoted
    identifiers have no escape for it.
12. **JSON output is a versioned contract.** Adding a field is a minor bump;
    renaming or removing one is major. Samples must validate against
    `docs/schemas/*.schema.json` — this runs in CI.
13. **The password never appears as a literal inside a PL/SQL block sent to the
    server.** `ALTER USER` is issued directly, never wrapped in
    `BEGIN`/`DECLARE`/`EXECUTE IMMEDIATE`. Measured on 26ai: Oracle retains no
    cursor for the DDL itself, but a block *containing* the DDL is an ordinary
    block and its text is kept verbatim in `V$SQL` and `V$DB_OBJECT_CACHE`. So
    wrapping does not hide the literal — it is the only thing that exposes it.
    This is easy to violate by accident, because a wrapper looks like the more
    careful option. Tier 0 asserts it against the generated statement text.
    **The rule is universal; the second half of that measurement is not.** On
    11.2 the direct DDL is retained too, in `V$SQLSTATS` (#387) — wrapping is
    still strictly worse there, so nothing about this invariant changes, but do
    not restate "issuing it directly keeps the password out of the shared pool"
    without naming the release.
14. **The password is never bound into a SQL predicate.** `V$SQL_BIND_CAPTURE`
    samples bind values at hard parse and keeps them in clear. Rotation is
    unaffected — DDL cannot take binds — so this binds on `check --method hash`:
    never compare a password or a verifier by sending it as a bind.

---

## Open questions: surface, do not resolve

The design docs contain deliberate open decisions, tagged `D`, `C`, `P`, `J`,
`T`, `Q`. They are consolidated in `docs/README.md` and tracked as GitHub issues
labelled `decision`.

**If a task requires one to be answered, stop and ask.** Do not pick a plausible
option and continue — that silently converts an open decision into a fact buried
in a diff. Say which question is blocking and what the options cost.

Several are marked "verify before implementing" and need a real database rather
than reasoning:

- whether the `T:` (12C) verifier in `SYS.USER$.SPARE4` can be regenerated
  client-side — `--method hash` depends on it. **The layout is read (#431) and
  the derivation reproduces byte-for-byte (#432)** on 26ai, 21c and 18c:
  `SHA-512(PBKDF2-HMAC-SHA512(pw_utf8, salt‖"AUTH_PBKDF2_SPEEDY_KEY", 4096, 64)‖
  salt)`, 4096 sent at logon not stored. Degradation is settled too (#433):
  compare `T:` only, and an account with no `12C` fails at plan time.
  **Answered on every tier-2 release; still marked because 19c — the release an
  OCI estate runs, and so the target of interest — is unread (not pullable), and
  12.1/12.2 are unread too.** Do not treat the tier-2 result as 19c's. Probes:
  `sql/oracle/05_verifier_layout_probe.sql`, `06_verifier_reproduce.{sql,py}`
- whether `ALTER USER` text leaks the password into `V$SQL` or
  `UNIFIED_AUDIT_TRAIL`, per version (unverified: ddl-text-versions) —
  **answered on 26ai 23.26.2.0.0, 21c 21.3.0.0.0, 18c 18.4.0.0.0 and 11g
  11.2.0.2.0; unmeasured on 12.1, 12.2 and
  19c.** `02_password_leak_probe.sql` was run in all three documented positions on
  2026-08-26: unified audit masks the statement at write time, no `V$SQL` cursor
  for the DDL exists at all, and the sole leak is an anonymous PL/SQL block
  carrying the password as a literal — which is invariant 13, now measured rather
  than assumed. Two of the three runs were as a service account holding
  `ALTER USER` and nothing else (`isdba=FALSE`), so the capture is attributable to
  the audit policy rather than to mandatory `SYSDBA` auditing; the earlier SYS-only
  runs could not establish that. 21c and 18c agree with 26ai row for row and add
  that traditional auditing masks it too. **11.2 does not agree**: `V$SQLSTATS`
  retains the plain `ALTER USER` text there, readable by a dictionary reader
  though not by the service account. Decided in #387 — documented, not warned
  about and not refused, because it ages out with the shared pool and one
  `FLUSH SHARED_POOL` clears it. Do not quote a leak result without its version
  (`docs/design/02-oracle-privileges.md` §4 and §8 P8)
- ~~whether the 23-codebase schema privileges cover `ALTER USER` (P7)~~ —
  **answered: no.** `GRANT ALTER USER ON SCHEMA` gives `ORA-00990`, tested on 26ai
  23.26.2.0.0 with a succeeding `SELECT ANY TABLE ON SCHEMA` as the control. The
  direct grant is the model permanently; do not re-open it as an option
  (`docs/design/02-oracle-privileges.md` §2.1)
- whether a pullable Oracle 11g XE image exists (T1)

Do not assume any of these. Where the answer is unknown, the code should refuse
rather than guess — as the deleted package draft did for the T-verifier.

---

## Working agreement

**Issues.** Work comes from GitHub issues. One issue ≈ one reviewable PR. If an
issue turns out to need more than about 400 changed lines, split it and say so
before writing the larger version.

**Docs move with code.** A PR that changes behaviour updates the relevant design
document in the same PR. The documents are the specification, not a description
written afterwards — if they disagree with the code, that is a bug in one of them
and it needs resolving, not noting.

**`docs/local-testing.md` moves with the CLI surface**, and that is a second
obligation rather than a restatement of the first. The design documents say what
the tool is *for*; the guide is the by-hand map of what this build can actually be
made to do, so a PR that adds or changes a command, a flag, an exit code, or a
message an operator meets belongs in it too — including the failures worth causing
on purpose, which are most of its value.

Paste the output from the run "Run it, do not only test it" already required.
That rule and this one are the same work: you ran the verb, so write down what it
printed, and no sample in the guide is ever written from a diff.

A guide that lists eight commands when there are thirteen is worse than no guide,
because it reads as an inventory — so whatever it omits reads as *not built*. It
went stale exactly that way between #243 and #366: the entire `creds` surface
shipped while the document still told the reader "you cannot rotate a credential
end to end today; if that is what you sat down to test, stop here". Nobody was
lied to by a design document in that window; they were lied to by this one.

**Order of work.** Tier 0 first (`docs/design/04-testing.md` §4): config parsing
and validation, target-set expansion, precedence resolution, SecretRef parsing,
password generation, redaction. All pure logic, no containers, no I/O. Keeping
those layers free of I/O is an architecture requirement, not just a test
convenience.

**Tests.** Every behaviour change carries a test. Tests declare the capabilities
they need and skip with a reason when absent — never branch on a version. The
public suite must stay green using only freely pullable images (tier 0 and
tier 1); anything needing more must skip, not fail, or forks cannot run it.

**Run it, do not only test it.** A change to what the tool reads from a target
or a store, writes to one, or *reports* about one is not done when its tests
pass. Bring the tier-1 stack up — `docker compose --profile tier1 up -d` from
`test/` — and run the verb end to end. **Tier 1**, because that is the stack that
comes up locally; tiers 2 and 3 stay the maintainer's pre-release matrix. That is
a floor rather than a ceiling while the repository is private — reach for a
harder environment when a change deserves it. `04-testing.md` §1's rule that a
contributor must be able to go green on their own machine is the thing that would
cap it, and it starts binding when the repository goes public.

CI already runs tier 1 on every PR, so this is not about coverage. It is about
the assertions nobody writes, because a test can only check what its author
already suspected. Three that got through, and how (#309, #322, #326):

- **output that was described rather than produced.** Every sample in a design
  document, a PR body or a docstring is pasted from a real run. A hand-written
  one is a *prediction*: #309's first draft documented a warning the command did
  not print at all.
- **the shape of what the server actually sends.** `ORA-28002` is the documented
  grace-period code and 26ai does not send it; the message repeats its own code
  and appends a URL on a second line. Neither is guessable, and both changed the
  design (#322).
- **anything intermittent.** A diagnostic query reported the probe's own session
  in one run out of two (#326). One run is not a measurement.

**Commits.** Conventional-ish subject lines, imperative mood. Reference the issue.
Do not commit generated artefacts, `.env` files, Oracle binaries, or anything
pulled from a real environment.

**Every commit is signed off** — `git commit -s`, which adds the
`Signed-off-by:` line `CONTRIBUTING.md` requires (DCO). No CI check enforces
it, which is exactly why it is written here: a commit without one is caught
only by somebody reading the log, and fixing it afterwards means rewriting a
pushed branch.

**Every PR gets a Copilot review, and the review gets answered.** Opening a pull
request is not the end of the task. Request the review, wait for it, and then
resolve every comment it leaves — one of exactly two ways:

- **change the code**, or
- **decline the change**, having decided it is wrong or that the existing form is
  right for a reason.

Either way, **reply on the PR saying which and why**. A comment that was silently
acted on is indistinguishable from one that was silently ignored, and neither is
reviewable six months later. A decline needs the actual reason — "working as
intended" is not one; the reason is whatever the reviewer would have needed to
know in order not to raise it.

Judge each comment on its merits rather than deferring to it. A review tool is
often right and occasionally confidently wrong, and this codebase makes a lot of
deliberate choices that look like mistakes until you know why — the DDL that
must not be wrapped in PL/SQL (invariant 13), the password that must not be
bound (invariant 14), the refusals that exist because guessing is worse than
stopping. Applying a suggestion that makes the code worse because it was
suggested is the failure mode here, and so is dismissing a real bug because
answering it is inconvenient. Where a comment is right about the problem and
wrong about the fix, say both.

If a comment is accepted, push the fix and let CI go green again before
reporting the PR as ready.

`/request-copilot-review` does the mechanics. The request is
`copilot-pull-request-reviewer[bot]` through the REST endpoint, which is the
only route — GraphQL's `requestReviews` takes `userIds` and `teamIds` and will
not resolve a bot. Confirming it landed takes GraphQL, though: the pull
request's `requested_reviewers` omits Bot-type reviewers, so it reads empty even
when the request succeeded.

---

## Style

Python 3.11+, `python-oracledb` in **thick mode** — thin mode cannot be used
because it does not support Native Network Encryption, which OCI-hosted databases
require. Instant Client is therefore a runtime prerequisite on every platform.

- `ruff` for lint and format, `mypy` for types, `pytest` for tests
- Type hints on anything public
- Prefer boring, readable code over clever code. This project is reviewed by
  someone who is a DBA first and a Python developer second, and credential
  handling is a bad place for cleverness.
- Errors carry the vendor code, a category, and a hint about what to do next.
  Never swallow an ORA- code — map it, and preserve the server's own message.

---

## Provenance — this matters more than usual

This is an independent open-source project developed on personal time and
equipment. It is **not** derived from any employer codebase, and it must stay
that way.

- Do not copy code, configuration, schema, or identifiers from any other
  repository into this one.
- Examples and fixtures use the fictional vocabulary in
  `docs/design/01-configuration.md`: application `acme`, accounts `acme_*_user`,
  tenants `alpha`…`theta`, hosts under `example.com`, IPs from `192.0.2.0/24`.
  Never a real hostname, account name, tenant, service, or vault path.
- If asked to add an example drawn from a real system, anonymise it completely
  and say that you did.

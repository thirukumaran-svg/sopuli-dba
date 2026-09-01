# sopuli-dba — working agreement

A CLI for DBAs that manages database account credentials with a vault as the
master record. Oracle first, multi-product by design.

**Status: pre-implementation.** The design documents are complete and decided;
almost no code exists yet. The SQL in `sql/` has been executed only against
Oracle 26ai Free 23.26.2.0.0. Each script carries a `STATUS:` header saying which
paths ran and which are still untried — trust that header, not this line, and
update it when you run one.

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
   the driver call, and `policy sample --reveal`. Do not "remember to mask" at a
   log statement.

   The third exception is allowed because **a sample is not a credential**:
   nothing authenticates with it, it is never stored, and it guards nothing —
   which is what makes `pwgen` safe and a vault write dangerous. It stays narrow
   structurally rather than carefully: the one `reveal()` call outside the tests
   lives in `sopuli/output/policy_view.py`, it is reachable only under `--reveal`,
   `--reveal` is refused with `--output json`, and the run schema gives a sample no
   value property to put a password in. Widening it again is a decision, not an
   implementation detail.
3. **Never branch on a version number from config.** Query the database for its
   capabilities, cache per session, and branch on the capability. See P1.
4. **A command that needs an unavailable capability fails at plan time**, with a
   distinct exit code and a message naming the capability and the target — never
   a generic error mid-execution.
5. **The config is the whitelist.** The tool never touches an account that is not
   declared in `accounts:` or an `applications:` entry. Selectors filter the
   declared set; they cannot extend it. `--force` overrides other guardrails,
   never this one.
6. **Vault is master; direction is vault → database, always.** The database is
   never the source of truth.
7. **Never promote in the vault before every target has confirmed.** The
   `pending` → `current` ordering in UC-1 §3 is the whole safety design. Read it
   before touching rotation.
8. **Every mutating command supports `--dry-run` and prints a plan first.**
9. **Idempotency:** running any command twice must report `changed: false` the
   second time and emit no mutation audit record. **`creds generate` is the one
   exemption** (decided in #254): drawing a fresh random secret has no state to
   converge on, so a second run replaces `pending` and reports `changed: true`,
   warning that it did. The invariant governs the *convergent* verbs — `apply`
   converges the database on the vault, and it is the one that must report
   `changed: false` on a re-run. An exemption is written here rather than left to
   be discovered in a diff, and adding a second one is a decision, not an
   implementation detail.
10. **Safety settings only ratchet toward safe.** `readonly`, `--dry-run`,
    `max_targets` and `confirm_environments` cannot be relaxed by a
    higher-precedence source. See P3.
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

- the `T:` (12C) verifier layout in `SYS.USER$.SPARE4` — `--method hash` depends
  on it and it is not confirmed
- whether `ALTER USER` text leaks the password into `V$SQL` or
  `UNIFIED_AUDIT_TRAIL`, per version — **answered on 26ai 23.26.2.0.0 only, and
  still open on every other version.** `02_password_leak_probe.sql` was run in
  all three documented positions on 2026-08-26: unified audit masks the statement
  at write time, no `V$SQL` cursor for the DDL exists at all, and the sole leak is
  an anonymous PL/SQL block carrying the password as a literal — which is
  invariant 13, now measured rather than assumed. Two of the three runs were as a
  service account holding `ALTER USER` and nothing else (`isdba=FALSE`), so the
  capture is attributable to the audit policy rather than to mandatory `SYSDBA`
  auditing; the earlier SYS-only runs could not establish that
  (`docs/design/02-oracle-privileges.md` §4)
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

**Order of work.** Tier 0 first (`docs/design/04-testing.md` §4): config parsing
and validation, target-set expansion, precedence resolution, SecretRef parsing,
password generation, redaction. All pure logic, no containers, no I/O. Keeping
those layers free of I/O is an architecture requirement, not just a test
convenience.

**Tests.** Every behaviour change carries a test. Tests declare the capabilities
they need and skip with a reason when absent — never branch on a version. The
public suite must stay green using only freely pullable images (tier 0 and
tier 1); anything needing more must skip, not fail, or forks cannot run it.

**Commits.** Conventional-ish subject lines, imperative mood. Reference the issue.
Do not commit generated artefacts, `.env` files, Oracle binaries, or anything
pulled from a real environment.

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

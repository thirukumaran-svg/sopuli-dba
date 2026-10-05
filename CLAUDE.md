# sopuli-dba — working agreement

A CLI for DBAs that manages database account credentials with a vault as the
master record. Oracle first, multi-product by design. The code is in
`src/sopuli/`. The use cases are specified in `docs/use-cases/`, among them
UC-1, application credentials, and UC-2, personal account passwords. Each
document says which parts of it are built.

This file is the working agreement for every assistant and contributor. It states
each rule briefly and links to the document that explains it. Read the linked
document before you change the behaviour it governs.

---

## Read before changing behaviour

`docs/design/00-principles.md` is **binding**. A use case may refine it; nothing
may contradict it. If a change seems to require contradicting it, stop and say
so. That is a design decision, not an implementation detail.

| Document | When it applies |
|---|---|
| `docs/design/00-principles.md` | always: driver interface, vault interface, config precedence, cross-platform rules, exit codes |
| `docs/design/01-configuration.md` | config, targets, applications, SecretRefs, password policy, delivery methods |
| `docs/design/02-oracle-privileges.md` | any SQL issued against Oracle |
| `docs/design/03-json-output.md` | anything that produces output, and redaction |
| `docs/design/04-testing.md` | tests and the test stack |
| `docs/use-cases/uc-01-app-credential-sync.md` | application credentials: `creds generate`, `apply`, `check`, `rotate` |
| `docs/use-cases/uc-02-personal-account-passwords.md` | personal accounts: `account` verbs, password reset, delivery methods |
| `docs/measurements.md` | quoting or adding a result measured on an Oracle release |
| `docs/decisions/log.md` | why a decision was made, and what was rejected |
| `docs/decisions/adr-001-privilege-model.md` | before proposing a definer-rights package. It was considered and rejected |
| `docs/decisions/adr-005-vault-client.md` | before proposing `hvac` or another Vault client library. The HashiCorp backend uses the HTTP API over `httpx` |
| `docs/decisions/adr-006-optional-dependencies.md` | before adding a dependency, or assuming a vendor client is installed. Vendor clients are install extras, and the base package opens no sockets |
| `docs/decisions/adr-007-vault-token-flag.md` | before giving any flag a secret *value*. `--vault-token` was refused; the flag takes a path |
| `docs/README.md` | the decision register, the verify-before-implementing register, and the roadmap (UC-3 to UC-5 and UC-1b). Read it before deferring work to "another use case" |
| `docs/local-testing.md` | adding or changing a command, a flag, an exit code, or a message an operator sees |
| `docs/workflow.md` | branching, commit format, and the release process |

---

## Invariants — do not violate these without an explicit decision

Each invariant exists because getting it wrong breaks something specific. The
reasons and the rejected options are in the linked documents. Changing an
invariant, or adding an exception to one, is a decision and not an implementation
detail.

1. **Secrets never appear in `argv`.** `ps` and the Windows process list show
   the command line. Passwords come from stdin, a file, or a vault ref, never a
   command-line option. ADR-007 applies this to the vault token.

2. **Redaction happens at the output serialiser, not at each call site.** Secret
   values are wrapped in a type whose `str`, `repr` and JSON serialisation are
   `"***"`. Do not "remember to mask" at a log statement. Plaintext leaves the
   process at these sites only:

   1. the vault write;
   2. the driver call;
   3. `policy sample --reveal`. A sample is not a credential: nothing
      authenticates with it and it is never stored;
   4. `account reset-password` on the seen (`manual`) path. This is a real
      credential, so it has five structural guards, stricter than the sample's.
      The exposure is deliberate, witnessed, and ends at the owner's first logon;
   5. the wrapping token an unseen delivery returns. It holds no password, but it
      retrieves one, so it is a `Secret`. The tool has no other channel to hand it
      over on.

   `tests/test_reveal_sites.py` parses `src/` and fails on a `.reveal()` call in
   a module that holds none of these sites, and on a second call in the seen
   path's view. It is a tripwire: it does not catch a second call in another
   permitted module, or a call spelled another way. The guards are in
   `docs/design/03-json-output.md` §4 (3 and 4), UC-2 §6.5 (4) and UC-2 §6.6
   (5). Loosening any guard is a decision.

3. **Never branch on a version number from config.** Query the database for its
   capabilities, cache them per session, and branch on the capability. See P1.

4. **A command that needs an unavailable capability fails at plan time.** It
   exits with a distinct exit code and a message that names the capability and
   the target. It never fails with a generic error during execution.

5. **The config is the whitelist.** The tool never touches an account the config
   does not declare. Selectors filter the declared set; they cannot extend it.
   `--force` overrides other guardrails, never this one. A personal account may be
   declared by a predicate over a profile or role; a mutating verb then still
   requires the account named on the command line. A name may not be declared
   twice. Reasons: [H1](docs/decisions/log.md#h1).

6. **Vault is master; direction is vault → database, always.** The database is
   never the source of truth.

7. **Never promote in the vault before every target has confirmed.** The
   `pending` → `current` ordering in UC-1 §3 is the safety design. "Every target"
   means every target the config declares, not every target this run visited.
   UC-1 §5 has the promotion gate. `creds generate --promote` over an existing
   `current` is an exception, and it writes only with `--overwrite-current`. Seeding an absent `current` has no reader to protect,
   so it is not an exception. Reasons: [#257](docs/decisions/log.md#257),
   [#406](docs/decisions/log.md#406).

8. **Every mutating command supports `--dry-run` and prints a plan first.**

9. **Idempotency.** Running a convergent command twice reports `changed: false`
   the second time and emits no mutation audit record. A verb that draws a fresh
   random password has nothing to converge on, so it is outside this rule:
   `creds generate` and `account reset-password` report `changed: true` and say
   what they replaced. Any verb with an observable target state is convergent.
   Reasons: [H7](docs/decisions/log.md#h7).

10. **Safety settings only ratchet toward safe.** `readonly`, `--dry-run`,
    `max_targets`, `confirm_environments` and `safety.delivery.allowed_methods`
    cannot be relaxed by a higher-precedence source. See P3. The merge shape is
    declared per setting. `allowed_methods` merges by intersection, so a new
    delivery method is unusable until a config names it. Reasons:
    [H6](docs/decisions/log.md#h6).

11. **Passwords containing `"` are rejected, not escaped.** Oracle quoted
    identifiers have no escape for it.

12. **JSON output is a versioned contract.** Adding a field is a minor bump;
    renaming or removing one is major. Samples must validate against
    `docs/schemas/*.schema.json`. CI checks this. See `03-json-output.md`.

13. **The password never appears as a literal inside a PL/SQL block sent to the
    server.** Issue `ALTER USER` directly, never inside `BEGIN`, `DECLARE` or
    `EXECUTE IMMEDIATE`. A wrapper looks more careful, but on every release
    measured Oracle keeps the text of a block that contains the DDL, password
    included, in `V$SQL`. The block is never less exposed than the direct
    statement. What each release retains is in
    `docs/design/02-oracle-privileges.md` §4. Tier 0 checks the generated
    statement text.

14. **The password is never bound into a SQL predicate.** `V$SQL_BIND_CAPTURE`
    keeps sampled bind values in clear. DDL cannot take binds, so rotation is not
    affected. The rule applies to `check --method hash`: never send a password or
    a verifier as a bind to compare it.

---

## Open questions: surface, do not resolve

The design documents contain open decisions, tagged `D`, `E`, `C`, `P`, `J`,
`T`, `Q` and `H`. The decision register in `docs/README.md` is the one place that
says whether each is open.

**If a task requires an open decision, stop and ask.** Do not pick a plausible
option and continue. Say which question blocks the task and what each option
costs.

Some questions need a real database rather than reasoning. They are in
`docs/README.md` §*Verify before implementing*, with their status. Where the
answer is unknown, the code refuses rather than guesses.

---

## Working agreement

**Issues.** Work comes from GitHub issues. One issue is about one reviewable PR.
If an issue needs more than about 400 changed lines, split it, and say so before
writing the larger version.

**Docs move with code.** A PR that changes behaviour updates the design document
in the same PR. The documents are the specification. If a document and the code
disagree, one of them has a bug: fix it, do not add a note.

**Write documentation and comments by the rules in `CONTRIBUTING.md`**,
§*Writing documentation and comments*. Read them before writing prose or
comments. When a fact changes, replace the old wording. Do not add a correction
beside it.

**`docs/local-testing.md` moves with the CLI surface.** A PR that adds or changes
a command, a flag, an exit code, or a message an operator sees updates the guide
too, including the failures worth causing on purpose. Paste output from a real
run. A guide that omits a command makes it look unbuilt.

**Measurements.** When you run a script in `sql/oracle/`, update its header and
the matrix in `docs/measurements.md`; `tests/test_measurements.py` checks that
they agree. Name the full release, such as 19.3.0.0.0 or 19.32.0.0.0, never
"19c". Results differ between releases, and between release updates of one
release.

**Keep pure layers pure.** Config parsing and validation, target-set expansion,
precedence resolution, SecretRef parsing, password generation and redaction do no
I/O. This is an architecture requirement, and it is what makes them testable in
tier 0 (`docs/design/04-testing.md` §4).

**Tests.** Every behaviour change carries a test. Tests declare the capabilities
they need and skip with a reason when one is absent. They never branch on a
version. The public suite stays green using only freely pullable images (tier 0
and tier 1). Anything that needs more must skip, not fail. The Oracle 19.3 and
12.2 images need an Oracle account, so they are maintainer-only
(`docs/local-testing.md` §5).

**Run it, do not only test it.** A change to what the tool reads from a target or
a store, writes to one, or reports about one is not done when its tests pass.
Start the tier-1 stack with `docker compose --profile tier1 up -d` from `test/`
and run the verb end to end. A test checks only what its author already
suspected. A real run catches faults like these:

- output that was described rather than produced. Paste every sample in a
  document, PR body or docstring from a real run;
- the shape of what the server actually sends, such as an error code that the
  documentation names and the server does not send;
- anything intermittent. One run is not a measurement.

**Commits.** Conventional Commit subject lines, imperative mood, referencing the
issue. Do not commit generated artefacts, `.env` files, Oracle binaries, or
anything from a real environment.

**Every commit is signed off** with `git commit -s`, which adds the
`Signed-off-by:` line that `CONTRIBUTING.md` requires (DCO). No CI check enforces
it, and fixing it later means rewriting a pushed branch.

**Every PR gets one review, and every comment gets an answer.** The review is
Copilot's. When the maintainer's Copilot budget for additional usage is spent,
it is a Claude Code review (`/code-review`) instead, because Copilot reviews
cost money past the included allowance. `/request-copilot-review` checks the
budget before it requests anything. Wait for the review, and resolve each comment
by one of these:

- **change the code**, or
- **decline the change**, because it is wrong or the existing form is right for a
  reason.

Either way, **reply on the PR saying which, and why**. A decline gives the reason
the reviewer would have needed in order not to raise the comment. "Working as
intended" is not a reason. Judge each comment on its merits. This codebase makes
choices that look like mistakes until you know the reason, such as invariants 13
and 14. Where a comment is right about the problem and wrong about the fix, say
both. If you accept a comment, push the fix and wait for CI to pass before you
report the PR as ready.

**A second review is the exception.** After you answer the first review, decide
whether to request another, and say on the PR which you chose. Request one only
when the fixes are large: more than about 100 changed lines, or new or rewritten
logic in `src/` beyond what the comments asked for. Otherwise skip it. Most
fixes are small and need no second review.

`/request-copilot-review` does the mechanics. Request the reviewer
`copilot-pull-request-reviewer[bot]` through the REST endpoint; GraphQL's
`requestReviews` cannot request a bot. Confirm the request with GraphQL, because
the REST `requested_reviewers` list omits bots.

---

## Style

Python 3.11+, `python-oracledb` in **thick mode** (D3). Thin mode has no Native
Network Encryption, connects only to 12.1 and later, and cannot do
`auth: external`. Instant Client is therefore a runtime prerequisite on every
platform. Autonomous Database uses TLS, not NNE, so it is not one of the reasons.
`docs/design/00-principles.md` §*Why thick mode* has the details and the
measurements.

- `ruff` for lint and format, `mypy` for types, `pytest` for tests.
- Type hints on anything public.
- Prefer boring, readable code over clever code. A DBA first and a Python
  developer second reviews this project, and credential handling is a bad place
  for cleverness.
- Errors carry the vendor code, a category, and a hint about what to do next.
  Never swallow an ORA- code: map it, and keep the server's own message.

---

## Provenance

This is an independent open-source project developed on personal time and
equipment. It is **not** derived from any employer codebase, and it must stay
that way.

- Do not copy code, configuration, schema, or identifiers from any other
  repository into this one.
- Examples and fixtures use the fictional vocabulary in
  `docs/design/01-configuration.md`: application `acme`, accounts `acme_*_user`,
  tenants `alpha` to `theta`, hosts under `example.com`, IPs from
  `192.0.2.0/24`. Never a real hostname, account name, tenant, service, or vault
  path.
- If asked to add an example drawn from a real system, anonymise it completely
  and say that you did.

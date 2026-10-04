# sopuli-dba — design documentation

This index is for contributors. **If you arrived here wanting to use the tool,
start at [getting-started.md](getting-started.md) instead** — the documents below
are the specification, written in the project's own declarative voice. Why they
record rejected options and cite the issue behind each decision is in
[CONTRIBUTING.md](../CONTRIBUTING.md#how-this-project-is-built-and-what-that-means-for-you).

Pre-alpha. UC-1 is built and the rest of this directory is ahead of the code; each
document says which of it exists. The SQL in `sql/oracle/` has been executed
against Oracle 26ai Free 23.26.2.0.0 only; each script's `STATUS:` header records
which paths ran and which are still untried.

## For a reader outside the project

| Document | Contents |
|---|---|
| [getting-started.md](getting-started.md) | first run: install, a first config file, `config validate`, `doctor`, and one command under `--dry-run` |
| [security-model.md](security-model.md) | what the tool can and cannot do to a database, and what stops a mistake from being silent — plain English, for deciding whether to trust it |
| [scenarios/rotate-and-sync.md](scenarios/rotate-and-sync.md) | one password rotation end to end: stage, apply, check, roll back, and close the rollover window |
| [scenarios/kubernetes-eso.md](scenarios/kubernetes-eso.md) | the vault-write side of an External Secrets Operator setup, and the division of responsibility that makes it safe |
| [../examples/](../examples/) | three runnable config files, commented: smallest, several applications, safety-hardened |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | what a first-time contributor needs that `workflow.md` and `CLAUDE.md` do not say for that audience |
| [../SECURITY.md](../SECURITY.md) | reporting a vulnerability privately |

## Design

| Document | Contents |
|---|---|
| [design/00-principles.md](design/00-principles.md) | P1 multi-product DB support (Oracle first), P2 multi-vault support, P3 config file + precedence, P4 cross-platform, P5 cross-cutting behaviour and exit codes |
| [design/01-configuration.md](design/01-configuration.md) | YAML schema in two shapes (single application inline, `applications:` for several), the estate sections, target templating with labels, profiles (run context), environment variables, SecretRef syntax, password charsets, precedence |
| [design/02-oracle-privileges.md](design/02-oracle-privileges.md) | The grant model: direct `ALTER USER`, common vs per-PDB service accounts, client-side guardrails, auditing |
| [design/03-json-output.md](design/03-json-output.md) | The `--output json` / `--output jsonl` contract, redaction, stability policy, `jq` recipes |
| [design/04-testing.md](design/04-testing.md) | What can and cannot be containerised, capability-driven matrix, tiering, fault injection, release gates |
| [use-cases/uc-01-app-credential-sync.md](use-cases/uc-01-app-credential-sync.md) | UC-1: application DB account credentials, vault as master — `generate` / `apply` / `check` / `rotate` |
| [workflow.md](workflow.md) | Binding: branching (`issue-<n>-<slug>`, no long-lived integration branch), Conventional Commits, release-please and the 0.x policy |
| [local-testing.md](local-testing.md) | Exercising the implemented surface by hand: laptop, WSL, the tier-1 stack, the `creds` lifecycle end to end, and every refusal worth producing on purpose |

## Machine-readable artefacts

| File | Purpose |
|---|---|
| [schemas/sopuli-config-1.8.schema.json](schemas/sopuli-config-1.8.schema.json) | JSON Schema (2020-12) for the config file (P3). Generated from the config layer by `python -m sopuli.config.schema` — never edited by hand |
| [schemas/sopuli-run-1.31.schema.json](schemas/sopuli-run-1.31.schema.json) | JSON Schema (2020-12) for the `--output json` document — the current one; earlier minors stay published beside it, because a build emitting `schema_version: "1.20"` has to be able to fetch what it validates against |
| [schemas/sopuli-event-1.7.schema.json](schemas/sopuli-event-1.7.schema.json) | JSON Schema for `--output jsonl` events |
| [schemas/example-creds-check-drift.json](schemas/example-creds-check-drift.json) | Worked example: a scheduled check finding drift in one of two PDBs |
| `../sql/oracle/00_install.sql` | Create and grant the service account — `NONCDB` / `COMMON` / `PDB` modes |
| `../sql/oracle/01_audit_policy.sql` | Unified audit policies and correlation queries |
| `../sql/oracle/02_password_leak_probe.sql` | Release gate 2: canary probe for password text retained anywhere queryable. Run on 26ai, 21c, 18c and 11.2; findings in `design/02-oracle-privileges.md` §4, what is still open in `design/04-testing.md` §6 gate 2 |
| `../sql/oracle/04_password_leak_extensions.sql` | Gate 2's other three checks — self-rotation, `IDENTIFIED BY VALUES`, and a 10046-traced session. Run on 26ai and 21c (#407). Run it after the probe and **before** the probe's section 8, which turns the audit policies off |
| `../sql/oracle/99_uninstall.sql` | Remove the account; keeps the audit policies by default |
| [decisions/adr-001-privilege-model.md](decisions/adr-001-privilege-model.md) | Why direct `ALTER USER`, what was rejected, and the two triggers for revisiting |
| [decisions/adr-003-text-tables.md](decisions/adr-003-text-tables.md) | No table library: columns formatted with click and the standard library, and why output must not depend on the terminal |
| [decisions/adr-004-yaml-parser.md](decisions/adr-004-yaml-parser.md) | PyYAML on a hardened `SafeLoader`, why not ruamel, and the pywin32 dependency for the P4 permission check |
| [decisions/adr-005-vault-client.md](decisions/adr-005-vault-client.md) | The HTTP API directly, over `httpx`, not `hvac` — measured against a real Vault, why renewal doesn't change the answer, and what still binds OCI to its own SDK |
| [decisions/adr-006-optional-dependencies.md](decisions/adr-006-optional-dependencies.md) | Vendor clients are install extras: what base carries, why base opens no sockets, and what a configured-but-uninstalled backend does |
| [decisions/adr-007-vault-token-flag.md](decisions/adr-007-vault-token-flag.md) | `--vault-token-file` takes a path and `--vault-token` is refused; why a SecretRef cannot authenticate the store it lives in, and where the token chain merges |
| [decisions/adr-008-contribution-provenance.md](decisions/adr-008-contribution-provenance.md) | A DCO sign-off rather than a CLA, why review-time checking rather than CI, and what would change either |
| [decisions/log.md](decisions/log.md) | One short record for each smaller decision: the question, the answer, the reasons and the options rejected |
| `../test/compose.yaml` | Test stack by tier: Vault (KV v1 + v2), PostgreSQL, Oracle Free/21c/18c/11g, an NNE-required Oracle, toxiproxy |
| `../test/capabilities.py` | Sketch of capability probing and the pytest skip markers |
| `../test/k8s_eso_probe.py` | Applies [scenarios/kubernetes-eso.md](scenarios/kubernetes-eso.md)'s own manifests to a throwaway Kubernetes cluster, and checks that ESO reads what sopuli wrote. Needs a cluster, not compose |

All three schemas validate as Draft 2020-12, and the example validates against the
run schema. That is no longer an assertion in prose: `tests/test_schemas.py`
checks it, and CI runs it on every push and pull request (invariant 12).

To get completion and inline errors while editing a config, put
`# yaml-language-server: $schema=./sopuli-config-1.8.schema.json` on the file's
first line — see [design/01-configuration.md](design/01-configuration.md) §9b,
which also explains why the schema's `$id` is not a URL to paste there.

The config schema is generated rather than written, and
`tests/config/test_schema.py` fails if the committed file is not what the config
layer produces today. A key added to a section without the schema following it
does not merge. What the schema deliberately leaves to the validators — the
cross-key rules, whose errors have to name the offending key — is listed in
[design/01-configuration.md](design/01-configuration.md) §9b.

## Conventions

- Binary name `sopuli`, project name `sopuli-dba` (D1)
- CLI grammar is noun-verb: `sopuli creds rotate`, `sopuli config validate` (D2)
- Anything marked **open decision** or **open question** is a real fork in the
  road, not a placeholder — decide it before writing the code that depends on it
- **A claim this project has not measured carries a marker naming its register
  entry**, wherever it is asserted — `(unverified: <slug>)` — and
  §*Verify before implementing* below is the register.
  `tests/test_verification_register.py` fails when an entry becomes `verified`
  and a document still carries its marker, naming every file.

  **The marker goes at every site, not only where the question was raised.** That
  is the whole point of it: the register already recorded these questions, and
  twice in two PRs a measured result reached one document and left others
  asserting the opposite (#408, #411). A marker is a join key for a checker that
  cannot read prose — "SQL trace remains untested" and "SQL trace is unchecked on
  every version" share no token with the table that answers them, and the obvious
  greps drown in *unknown config keys* and *macOS is untested*.

  Removing a marker is part of settling the question, not tidying afterwards, and
  the test is what makes that difference enforceable rather than remembered.

  **Never inside user-visible text.** A click verb's docstring is its `--help`
  output, so a marker in one reaches every operator who asks for help. Where the
  claim is in help text the marker goes in a comment beside it, naming the
  sentence it belongs to — `sopuli/cli.py`'s `creds_check` is the example.
- **Work that waits on an open issue carries a marker naming the issue**:
  `(open: #N)` in Markdown, or `(open: #N, #M)` for several, and `TODO(#N)` in
  code. Write what is true now and put the marker beside it. Do not write "until
  #N lands" or "#N will": `tests/test_pending_work.py` rejects those phrases, and
  rejects a `TODO` that names no issue. The `pending-work` workflow runs weekly
  and fails when a marker names a closed issue. When that happens, say what the
  issue did and remove the marker. The rule above about user-visible text
  applies to these markers too.

## Decision register

This table is the one place that says whether a decision is open. Each row names
the document that raises the question. That document's own table keeps the
question and the answer. The reasons for a decided question are in its record in
[the decision log](decisions/log.md), or in its ADR.
`tests/test_decision_register.py` checks those tables against this one:

- a row whose question is struck through there (`~~…~~`) must be `decided`
  here, and the other way round;
- a `deferred` row must say there what it is deferred to;
- `00-principles.md` has a status column, and it must match;
- every ADR is `decided` and says `Status: **accepted**`.

The weekly `pending-work` workflow also compares the register with GitHub: an
`open` row's issue must be open, a `decided` row's issue must be closed, and every
open issue labelled `decision` must have a row. The label means exactly that.

The statuses are:

- `open`: not answered. Do not write code that depends on it. Ask first.
- `decided`: answered. The answer is the rule.
- `deferred`: answered as "not now". The document's row says what would reopen
  it.

Where: `00` to `04` are `design/00-principles.md` to `design/04-testing.md`;
`UC-1` and `UC-2` are the two use-case documents; `ADR` is the file in
`decisions/` with that number, and `ADR-006` rows are sections of
[ADR-006](decisions/adr-006-optional-dependencies.md).

| ID | Where | Question | Status | Answer | Issue |
|---|---|---|---|---|---|
| D1 | 00 | Binary name | decided | `sopuli`; the project is `sopuli-dba` | |
| D2 | 00 | CLI grammar | decided | noun-verb: `sopuli creds rotate` | |
| D3 | 00 | Implementation language | decided | Python, `python-oracledb` in thick mode | |
| D4 | 00 | Config format | decided | YAML; JSON is accepted because it is valid YAML | |
| D5 | 00 | macOS tier | decided | best effort, untested, no macOS CI | |
| D6 | 00 | Plugin model for drivers and stores | decided | in-tree until a second driver exists | |
| D7 | 00 | Minimum Oracle version | decided | 11.2 stays in scope | |
| D8 | 00 | CLI framework | decided | click | |
| D9 | 00 | Dependency layering | decided | vendor clients are install extras | #130 |
| D10 | 00 | Which confirmation triggers are built in | decided | none; `safety.confirm_environments` only | #294 |
| E1 | ADR-006 | Does the extras rule bind database drivers? | decided | yes; `python-oracledb` is `sopuli-dba[oracle]` | #130 |
| E2 | ADR-006 | Is the HashiCorp store base or an extra? | decided | an extra, `sopuli-dba[hashicorp]` | #130 |
| E3 | ADR-006 | Does `sopuli-dba[all]` exist? | decided | yes, for CI; not the recommended install | #130 |
| E4 | ADR-006 | Configured but uninstalled backend: fail or warn? | decided | warn | #130 |
| E5 | ADR-006 | Exit code and category for a missing backend | decided | `config`, exit 9, with an `error.code` | #130 |
| E6 | ADR-006 | Does `doctor` always list the install shape? | decided | always | #214 |
| E7 | ADR-006 | Where a notify channel's client goes | decided | a fourth extra category, `sopuli-dba[notify]` | #442 |
| C1 | 01 | Name of the binding section | decided | `applications`, with an inline form | |
| C2 | 01 | Selector syntax | decided | `--select k=v` over labels, and `match:` in groups | #615 |
| C3 | 01 | Arbitrary expressions in secret templates? | decided | no; a fixed token list plus labels | #615 |
| C4 | 01 | Per-account overrides in an application entry | open | per-label cases are covered; per-account is not | #640 |
| C5 | 01 | Config encryption at rest | decided | out of scope; the config holds no secrets | #615 |
| C6 | 01 | Several vaults for one application (mirror writes) | deferred | to a later use case | |
| C7 | 01 | More than two `target_sets` nesting levels? | decided | no; write a second set | |
| C8 | 01 | Labels on explicit `targets:`? | decided | allowed | |
| C9 | 01 | How the file points at vault auth and the admin credential | decided | one grammar, two vocabularies | #27 |
| C10 | 01 | What profiles are for | decided | run context, not target selection | |
| C11 | 01 | Composable `--profile`? | decided | no; one active profile | #615 |
| C12 | 01 | A built-in `interactive` profile? | decided | no | #615 |
| C13 | 01 | `vault:` under `defaults:` and profiles: a name or a block? | decided | a name, everywhere | #31 |
| C14 | 01 | `@version=` and `@stage=` vocabularies | decided | the tool owns both | #40 |
| C15 | 01 | A binding with a secret and no store | decided | caught at plan time | #118 |
| C16 | 01 | What `--vault-token` takes | decided | refused; `--vault-token-file PATH` instead | #145 |
| C17 | 01 | P5's built-in confirmation against `01-configuration.md` §9's ratchet rule | decided | §9 governs; P5 is reworded | #294 |
| P1 | 02 | Default service user: common `C##` or per-PDB local? | decided | common; per-PDB is documented | #615 |
| P2 | 02 | Grant `SELECT ON SYS.USER$` by default? | decided | no; an optional, probed grant | #86 |
| P3 | 02 | Does `--force` exist? | decided | yes; it overrides account checks 2–5 only | #89 |
| P4 | 02 | One service account per database or per application? | decided | per database | #615 |
| P5 | 02 | Does `doctor` fail or warn on over-grants? | decided | warn | #213 |
| P6 | 02 | Keep 11.2 support? | decided | keep (D7) | #615 |
| P7 | 02 | Do schema privileges cover `ALTER USER`? | decided | no, `ORA-00990` | |
| P8 | 02 | 11.2 keeps the `ALTER USER` text in `V$SQLSTATS` | decided | document it | #387 |
| J1 | 03 | Does `--output json` print nothing until the end? | decided | yes; `jsonl` streams | #615 |
| J2 | 03 | `plan` in every run? | decided | in every command that plans | #615 |
| J3 | 03 | Machine-readable warning codes | open | codes exist; how numbers are allocated is open | #641 |
| J4 | 03 | Host and pid in the output | decided | `invocation.actor.host`; no pid | #615 |
| J5 | 03 | OpenTelemetry export | deferred | later; `correlation_id` serves until then | |
| J6 | 03 | Resumable event stream after a crash? | decided | no; run again | #615 |
| J7 | 03 | A run document on a usage error? | decided | no; exit 2 never emits one | #8 |
| T1 | 04 | Does an 11g XE image exist? | decided | yes | #1 |
| T2 | 04 | testcontainers or compose? | decided | compose | #174 |
| T3 | 04 | Is LocalStack Secrets Manager in the community tier? | open | | #642 |
| T4 | 04 | Does OCI Vault cost matter in a test loop? | open | | #643 |
| T5 | 04 | Public CI provider | decided | GitHub Actions | |
| T6 | 04 | A real Data Guard standby for the read-only test? | deferred | until a driver bug needs it | |
| T7 | 04 | Snapshot and restore for Oracle resets | deferred | drop and recreate until tier 2 is too slow | |
| Q1 | UC-1 | `check`'s default method | decided | `login` | #86 |
| Q2 | UC-1 | Where the advisory lock lives | decided | in the vault, per secret path | #83 |
| Q3 | UC-1 | Generations of `previous` | decided | one | #84 |
| Q4 | UC-1 | Does the tool alter a profile? | decided | never | #88 |
| Q5 | UC-1 | Notification on drift | decided | out of scope; exit 3 and JSON | #615 |
| Q6 | UC-1 | Self-rotation mode | deferred | to UC-1b | |
| Q7 | UC-1 | One secret per account or per application | decided | per application, a field per account | #85 |
| Q8 | UC-1 | Does `apply` create a missing account? | decided | no; account creation is UC-4 | #615 |
| Q9 | UC-1 | Time source for password age | decided | the vault's `rotated_at` | #87 |
| H1 | UC-2 | Where a personal account is declared | decided | `personal_accounts:`, by name or predicate | #449 |
| H2 | UC-2 | What a reset records, and where | decided | the database, a metadata record, nothing for rollback | #450 |
| H3 | UC-2 | The noun and the verbs | decided | `account reset-password`, `account expire-password` | #451 |
| H4 | UC-2 | Verify, unlock, or end a rollover window? | decided | no verify; unlock timed locks; end the window | #455 |
| H5 | UC-2 | Is self-service part of UC-2? | decided | no | #452 |
| H6 | UC-2 | How an estate restricts delivery methods | decided | `allowed_methods`, by intersection | #453 |
| H7 | UC-2 | A reset never converges | decided | outside invariant 9 by scope | #454 |
| H8 | UC-2 | The stored copy on the unseen path | decided | split by method | #459 |
| H9 | UC-2 | What "unseen" guarantees on `vault_wrapped` | decided | attribution, not access | #496 |
| H10 | UC-2 | Does a reset check that the database audits it? | open | | #591 |
| ADR-001 | ADR | Oracle privilege model | decided | direct `ALTER USER`, no definer-rights package | |
| ADR-002 | ADR | CLI framework | decided | click | |
| ADR-003 | ADR | Text tables | decided | click only, formatted by hand | #15 |
| ADR-004 | ADR | YAML parser | decided | PyYAML, hardened | |
| ADR-005 | ADR | HashiCorp Vault client | decided | the HTTP API over `httpx` | #103 |
| ADR-006 | ADR | Optional dependencies | decided | vendor clients are extras; base opens no sockets | #130 |
| ADR-007 | ADR | The vault token flag | decided | `--vault-token-file PATH` | #145 |
| ADR-008 | ADR | Contribution provenance | decided | DCO sign-off, no CLA | #370 |
| — | — | A narrower grant than `SYS.USER$` for the `LCOUNT` guard | open | | #124 |
| — | — | Should `doctor` check that a TNS alias resolves? | open | | #240 |
| — | — | `auth: prompt` with no terminal never exits 8 | open | | #481 |
| — | — | The reset lock when journal and delivery are different vaults | open | | #516 |
| — | — | Narrow the seen reset's rollover refusal | open | | #541 |
| — | — | Is logging to a file needed? | open | | #629 |

Closed decision issues with no ID are not listed here.

## Verify before implementing

**Each entry carries a status and a slug**, and the slug is how the rest of the
tree points back here — see §Conventions. `tests/test_verification_register.py`
reads this section, so the two code spans at the head of each bullet are
structure rather than decoration; the prose after them is for people.

**The status is this register's, not GitHub's.** #383, #387 and #87 are closed
issues whose verification is still outstanding: the decision was taken and the
measurement was not. A reader who resolves these against the issue tracker gets
three wrong answers.

- `verified` `t-verifier` (#90) — **Whether a client can regenerate the `T:` (12C) verifier in `SYS.USER$.SPARE4`.**
  The layout is read (#431) and the derivation reproduces byte-for-byte (#432),
  both on 26ai, 21c and 18c: `SHA-512(PBKDF2-HMAC-SHA512(pw_utf8, salt ‖
  "AUTH_PBKDF2_SPEEDY_KEY", 4096, 64) ‖ salt)`, and a rollover window's two
  verifiers (`T:` previous, `t:` current) are told apart the same way —
  `sql/oracle/05_verifier_layout_probe.sql` and `06_verifier_reproduce.{sql,py}`.
  Degradation is settled too (#433): the comparison uses `T:` only, an account
  with no `12C` fails at plan time (invariant 4), and the gate is a per-account
  capability (`SPARE4` carries a `T:`), never a version. **All three parts are
  answered on the tier-2 releases, on 19c 19.3.0.0.0** (#548, 2026-09-27: the
  same layout, `VGEN_COUNT` 4096 on the wire, every `T:` reproduced, twice) **and
  on 12c 12.2.0.1.0** (#572, 2026-09-29, the same again — and on a WE8DEC
  database, which showed that `pw_utf8` is the password *as the database holds
  it*, after conversion to its character set), **and on 19c 19.32.0.0.0** (#581,
  2026-10-01, an OCI Base Database Service DB system and the first release update
  read: the same layout, every `T:` reproduced, and a rollover window's `T:` old
  and `t:` new). One step there could not be observed: the DB system requires
  NNE, so `VGEN_COUNT` is encrypted on the wire, and 4096 is shown only by the
  reproduction succeeding. **Settled for 19c, 2026-10-01**: a base release and a
  release update both reproduce, and the maintainer judged one RU enough (#581).
  **12.1 is still unread**, and the derivation is not claimed there. What this
  unblocked is `--method hash|both`, built in #437; `check`'s default (`login`)
  never waited on this (#86).
- `unverified` `lcount-grant` (#124) — **Whether `SELECT_CATALOG_ROLE` via
  `SYS.KU$_USER_VIEW` exposes `LCOUNT` without `SPARE4`** — a narrower alternative to `SELECT ON SYS.USER$`
  for the `LCOUNT` guard, from a blog post rather than Oracle documentation.
  Affects what `sql/oracle/00_install.sql` recommends to sites that want the
  guard; nothing in the default path depends on it.
- `unverified` `adb-external-auth` (#471) — **Whether `auth: external` can be
  made to work against an OCI Autonomous Database, by adding a credential to the
  downloaded wallet with `mkstore -createCredential`.** What *is* established is
  the fact that made the entry necessary: the ADB wallet zip holds TLS
  certificates and no credential, so `auth: external` against an unmodified one
  has nothing to log in with — `docs/local-testing.md` §14 presented it as the
  one path to a real wallet that skips `mkstore`, and an operator following that
  got a login failure. What is untried is the repair. sopuli *has* now run
  against an ADB with a vault-held password (#479, §14's *An Autonomous Database
  end to end*), but never with `auth: external`, so the `mkstore` line in §14 is
  still Oracle's documented syntax rather than a command anybody here has watched
  succeed. Nothing in the
  default path depends on it: the password sources are unaffected, and §14's
  example now uses one.
**Password text retained by Oracle** is three entries rather than one, and the
split is #412's doing. It was a single `partial` entry, and a partial entry is a
loophole: the SQL-trace surface is settled while the version matrix is not, so a
stale marker on a *trace* claim would have been allowed to sit there
indefinitely — which is the #410 failure this register exists to catch, still
uncaught. **There is no `partial` status any more.** A question whose surfaces
settle separately splits into entries that each settle whole. Shared context for
all three: the probe is `sql/oracle/02_password_leak_probe.sql`, its extensions
are `sql/oracle/04_password_leak_extensions.sql`, and the findings are in
`design/02-oracle-privileges.md` §4 and `design/04-testing.md` §6 gate 2.

- `unverified` `ddl-text-versions` (#387) — **Whether `ALTER USER` text leaks the
  password into the shared pool, on the releases nobody has run.** Measured on
  26ai 23.26.2.0.0, 21c 21.3.0.0.0, 18c 18.4.0.0.0 and 11g 11.2.0.2.0 (#380,
  #381, #382): `V$SQL` holds no cursor for the DDL at all on the first three, and
  the one leak everywhere is an anonymous PL/SQL block carrying the password as a
  literal — which is now invariant 13, measured rather than reasoned. **11.2
  disagrees**: `V$SQLSTATS` keeps its own copy there, so the *conclusion* is
  release-dependent even though the reasoning is not (#387). **19c 19.3.0.0.0
  agrees with 18c and later** (#548, 2026-09-27, all three positions:
  `V$SQLSTATS` clean for the plain `ALTER USER`), and **so does 12c 12.2.0.1.0**
  (#572, 2026-09-29, all three positions), and **so does 19c 19.32.0.0.0**, the
  first release update measured (#581, 2026-10-01, all three positions, with the
  stock verify function enabled), so the change sits somewhere in (11.2, 12.2].
  **12.1 is unrun** — read the 11.2 result as *11.2 does*, never as *everything
  older does*.
- `unverified` `ddl-text-awr` (#387) — **Whether the retained text reaches AWR.**
  `DBA_HIST_SQLTEXT` needs a snapshot taken *before* the sweep, on a database
  where the Diagnostics Pack is enabled. Every image in this stack ships
  `control_management_pack_access = NONE`, so two snapshots taken on 11g XE
  captured nothing whatsoever and the clean result measured the image rather than
  the release. **Half answered on 19.32.0.0.0** (#581, 2026-10-01), an OCI DB
  system with `DIAGNOSTIC+TUNING`: one uncolored snapshot put the wrapped literal
  (C3) verbatim into `DBA_HIST_SQLTEXT`, kept 8 days, while the `ALTER USER`
  sopuli issues (C2) reached nothing, having no cursor to capture. **Open: 11.2**,
  where the plain `ALTER USER` *is* retained in `V$SQLSTATS` and whether it
  reaches AWR needs an 11.2 with the pack. That is why this stays `unverified`
  rather than being called settled by the release that never retains it.
- `verified` `ddl-text-trace` (#407) — **Whether a traced session captures the
  password.** Answered 2026-09-11 on 26ai and 21c, and it retires the pessimistic
  assumption rather than confirming it: at 10046 level 12 the cursor is written
  truncated, `ALTER USER sopulitest IDE`, stopping one character into
  `IDENTIFIED`. Five traced sessions, both releases, identical. The wrapped form
  leaks in full, which is invariant 13 on a fifth surface. The OS audit trail was
  answered in the same run (masked on 21c; no user-management DDL reaches it at
  all on 23ai+), as were self-rotation and `IDENTIFIED BY VALUES` — both masked.
- `unverified` `password-byte-limit` (#383) — **What the maximum password length
  actually is, on every release from 12.1 to 23ai.** `limits.py` derived the
  limit from the probed server version against `LONG_IDENTIFIER_FLOOR = (12, 2)`,
  and **the premise was wrong**: 12.2 raised *identifiers* from 30 bytes to 128
  and passwords did not move with them. #383 measured it — 31 bytes is
  `ORA-00972` on 21c, 18c and 11.2, and accepted on 26ai — and **19c 19.3.0.0.0
  refuses 31 and 128 the same way** (#548, 2026-09-27), as does **12c
  12.2.0.1.0**, the release the floor is keyed to (#572, 2026-09-29: 30 bytes
  accepted, 31 `ORA-00972`, and a 40-character policy planned with
  `constraints: 128 bytes in WE8DEC` and failed in `apply`), so the floor is somewhere
  in `(21.3, 23.26]` and `(12, 2)` was below every version ever tested against it.

  **Fixed in #595**: the floor is now `LONG_PASSWORD_FLOOR = (23, 0)`. Until
  then this was a live bug: on 21c, 19.3 and 12.2 a policy asking for 40 bytes
  planned clean, reported `constraints: 128 bytes`, and failed with `ORA-00972`
  mid-`apply`, which violated invariant 4. #383 closed without fixing it. On
  21c XE a 40-character policy is now refused by `creds generate` at plan time,
  exit 9, and a 30-character one generates, applies and checks clean.
  `23` is the only floor the tool can express rather than a choice among
  several, because `V$INSTANCE.VERSION` reads the base release: every 23ai and
  26ai reads `23.0.0.0.0`.

  **What keeps the entry `unverified`** is what no release in the stack can
  answer. A 23ai before 23.26 is unmeasured and reads the same as 26ai. 12.1 is
  unmeasured, though it falls under the 30-byte rule, which is the safe
  direction. And whether the legacy limit is 30 *bytes* or 30 *characters* has
  only been run with ASCII, which every password `01-configuration.md` §8 draws is.
- `unverified` `pw-changed-source` (#87, #386) — **Whether `SYS.USER$.PTIME` is
  the password change date on the releases nobody has run.** Measured 2026-09-08:
  `DBA_USERS.PASSWORD_CHANGE_DATE` is present on 26ai and 21c and `ORA-00904` on
  **18c and 11.2 alike** — the column arrived after 18c, not in 12.1 as this entry
  used to imply. On all four `PTIME` moved with `ALTER USER ... IDENTIFIED BY`,
  equalled the column to the second where both exist, and `CTIME` did not move.
  #386 decided to fall back to `PTIME` behind the optional grant, and to say why
  when neither answers (`SOPULI-W021`).

  **19c has the column** — measured 2026-09-17 on **Oracle Database 19c EE High
  Performance 19.0.0.0.0, version 19.24.0.0.0**, which this entry had only expected.
  So the release an OCI estate runs takes the column path and never the fallback,
  and it is off this entry's list. **What was measured there is the column's
  presence**, by hand and not by running the suite: whether its value moves with
  `ALTER USER … IDENTIFIED BY` on 19c is inferred from 26ai and 21c rather than
  seen, and the tier-1 test that would pin it has not run on that release.

  **12.2.0.1.0 takes the fallback**, measured 2026-09-29 (#572): no
  `PASSWORD_CHANGE_DATE` column, and the suite's
  `test_password_change_date_tracks_a_rotation` passed there through `PTIME` —
  the value the driver read moved with `ALTER USER … IDENTIFIED BY`. The test
  comparing `PTIME` with the column skipped, having no column to compare with, so
  on 12.2 `PTIME` is shown to track a rotation rather than shown equal to anything.
  **12.1 would take the fallback too and is unmeasured**, and that is what keeps
  this entry open. Purely a display question — Q9 decided `--max-age-days` reads
  only the vault.
- `verified` `expire-rollover` (#438, #461) — **What `ALTER USER … IDENTIFIED BY …
  PASSWORD EXPIRE` does to an account whose profile sets `PASSWORD_ROLLOVER_TIME`.**
  UC-2's **seen** (`manual`) reset is that one statement; its default, unseen reset
  issues no expiry and is unaffected. On a rollover-capable release the old
  password keeps authenticating after `IDENTIFIED BY` until the window closes.
  **Measured on 26ai 23.26.2.0.0, 2026-09-16** (#455,
  `sql/oracle/07_lock_and_rollover_probe.sql` Q7), and the answer is worse than the
  guess was: the statement **is** accepted on a rollover profile, the resulting
  status is `EXPIRED & IN ROLLOVER` — both at once — and **the expiry does not end
  the old password's window.** The old password answers `ORA-28001`, not
  `ORA-01017`, so it still authenticates and is merely expired, which leaves it a
  way to set the new one. **21c 21.3.0.0.0 agrees row for row** (#461, twice,
  2026-09-26): accepted, `EXPIRED & IN ROLLOVER`, old and new passwords both
  `ORA-28001`, and 07's Q1–Q6b match 26ai as well. That is the second release
  the entry named, so it is settled. 19c is unmeasured, and nothing here says
  what it does.
  `use-cases/uc-02-personal-account-passwords.md` §4.3 still refuses a seen
  reset on a rollover profile at plan time, and now the reason has been measured
  on both releases.
  **Q7 was measured from `OPEN`, and the start state turns out to decide it**
  (#529, `sql/oracle/09_reset_from_expired_probe.sql`, 26ai 23.26.2.0.0, twice,
  2026-09-26; **21c 21.3.0.0.0 identical in every status and every login check**,
  twice, 2026-09-26, #461, though its grace-period logins warn with `ORA-28002`
  where 26ai sends `ORA-28098`). From `EXPIRED`, and from `EXPIRED & IN ROLLOVER`, the same
  statement opens **no** window and leaves every earlier password `ORA-01017`,
  so the new, expired one is the only password that works. From `EXPIRED(GRACE)`
  it behaves exactly as from `OPEN`, old password `ORA-28001`. So the exposure
  depends on whether the old password still authenticates, not on whether the
  status reads `EXPIRED`. That is a measurement on two releases, not a change to
  the refusal: whether §4.3 narrows is #541's decision, and the measurement it
  was waiting on is now in.
- `unverified` `stale-rollover` (#441) — **What an open rollover window does when
  the profile that granted it is set back to zero.** Raised by a review of #504,
  which predicted the old password would keep working; **measured twice on 26ai
  Free 23.26.2.0.0, 2026-09-20**, and the prediction is wrong on this release in a
  way worth writing down. `ACCOUNT_STATUS` still reads `OPEN & IN ROLLOVER`, and
  the old password is **already dead** — `ORA-01017` — so what outlives the profile
  change is the *status* rather than the exposure. `EXPIRE PASSWORD ROLLOVER
  PERIOD` is accepted in that state and takes the account back to `OPEN`. The
  driver therefore closes the window on either signal, the profile's grant or an
  open window, which costs one silently-accepted statement here and is
  safety-critical on any release where the old password *does* outlive the change.
  **Unmeasured on 19c and 21c**: needs tier 2. Nothing refuses on this and nothing
  waits for it — the wider condition is correct under both answers, which is why
  this is a note rather than a blocker.
- `unverified` `expire-ddl-text` (#438, #457) — **Whether `ALTER USER … IDENTIFIED BY
  … PASSWORD EXPIRE` is retained or masked the way the bare `IDENTIFIED BY` form
  is.** Gate 2's probe (`sql/oracle/02_password_leak_probe.sql`) issues the bare
  form only, so every retention result in `design/02-oracle-privileges.md` §4 is a
  result for that statement. Oracle's protection is keyed to the statement type,
  which gives no reason to expect the suffix to change it and is not a measurement
  that it does not. UC-2's **seen** (`manual`) reset is the suffixed form, so the
  probe needs extending to it, on 26ai and 21c first; the default, unseen reset
  issues the bare form and is covered by `ddl-text-versions`.
- `verified` `vault-cas-conflict` (#103, #104) — **What a real Vault's
  compare-and-set conflict looks like on the wire** — **answered.** Against `hashicorp/vault:2.0.4` dev mode: every lost
  compare-and-set, whatever caused it (a stale `cas: 0`, a stale nonzero `cas`,
  or `cas: 0` against a path whose latest version was soft-deleted but whose
  version counter survived), is a 400 with the identical body
  `{"errors": ["check-and-set parameter did not match the current version"]}`
  — one string `CasConflictError` can match on regardless of which client
  wraps the call (#103). A malformed `cas` is a different 400
  (`"error parsing check-and-set parameter"`), so the match does not misfire.
  One refinement to `sopuli/store/protocol.py`'s `read()` docstring: the two
  states it says both collapse to `None` are not actually identical on the
  wire — a soft-deleted path's 404 still carries a `data.metadata` envelope
  (`deletion_time`, `version`); a never-written path's 404 is bare. `read()`
  is right not to expose this — nothing that calls it needs the distinction —
  but the information is there if a future diagnostic ever wants it. Spike is
  `test/vault_cas_probe.py`, run by hand against tier0 (`docker compose
  --profile tier0 up -d`). The string dependency itself — the fact that a
  future `CasConflictError` mapping would key on — is promoted to a real,
  capability-skipped regression test in `tests/store/test_hashicorp_cas_conflict.py`,
  which runs as part of the ordinary suite and skips cleanly (not a failure)
  when Vault is unreachable.
- `verified` `vault-client` (#103) — **Which HashiCorp Vault client** — **decided in
  [ADR-005](decisions/adr-005-vault-client.md): the HTTP API directly, over
  `httpx`. No `hvac`.** The case for `hvac` rested on auth being where a
  library "earns its keep" (renewal, OIDC, Kubernetes). Against the real
  tier0 Vault: AppRole is genuinely two calls — read a `role_id`, `POST
  role_id`+`secret_id` to `auth/approle/login`, no auth header, get a
  `client_token` straight back, confirmed to authenticate a follow-up call.
  Kubernetes could only be exercised up to the point a real cluster becomes
  load-bearing — no control plane exists in this stack, same category as real
  OCI — but the client-side request needed nothing beyond `{role, jwt}`:
  Vault accepted a syntactically-valid fake JWT past every check that does
  not require one (`kubernetes_ca_cert` does have to be a parseable PEM, or
  `auth/kubernetes/config` itself is refused — the one genuine surprise) and
  only failed reading claims out of it. Renewal is one POST
  (`auth/token/renew-self`) with no scheduling logic behind it in `hvac`
  either, and what sopuli needs is bespoke regardless — #83 renews at each
  target boundary behind a fence check, not on a background timer. Net: the
  auth argument for `hvac` is thin across every method in `01-configuration.md`
  §3a except OIDC's browser/callback dance, which `hvac` does not provide
  either. Probe is `test/vault_auth_probe.py`, run against tier0. OCI keeps
  its own SDK — ADR-005's criterion is request signing and principal
  federation, not "is it HTTP." `httpx` lands with #104, in
  `sopuli-dba[hashicorp]` rather than in base — ADR-005 said base until #130 made
  "base can import none of the backends' clients" a testable rule (ADR-006,
  E2).
- `verified` `nne-oci-default` (#575) — **Whether OCI's Base Database Service and Exadata Cloud require Native Network Encryption as provisioned.**
  One of D3's three reasons for thick mode (`design/00-principles.md`, *Why
  thick mode*). **Answered for Base Database Service: yes**, on a 19.32.0.0.0
  DB system (#581, 2026-10-01, `local-testing.md` §14). The shipped
  `sqlnet.ora`, untouched, sets `SQLNET.ENCRYPTION_SERVER=REQUIRED` and
  `SQLNET.CRYPTO_CHECKSUM_SERVER=REQUIRED`; a thin connection is refused with
  `DPY-3001`; a thick one negotiates AES256 and SHA256 with no client-side
  configuration. **Exadata Cloud is not part of the answer**: it is cited from
  Oracle's documentation, no run of it is planned, and every sentence that
  names it beside Base Database says *documented, not measured* for that half
  rather than carrying a marker. The local `nne` compose profile is still
  unrun and still only an approximation. Blocked nothing: D3 holds on either of
  its other two reasons.
- `verified` `adb-thin-mode` (#575) — **Whether Autonomous Database uses TLS rather than Native Network Encryption, and accepts a python-oracledb thin-mode connection.**
  **Answered: both**, on the ADB serverless instance #479 used, 26ai
  23.26.3.3.0 with mutual TLS required (2026-10-01, `local-testing.md` §14).
  python-oracledb 4.0.2 in thin mode connects through the wallet
  (`connection.thin` is `True`, the server records the driver as `thn`), over
  `tcps`, twice out of two. No NNE is negotiated in either mode: the session's
  `V$SESSION_CONNECT_INFO` lists the encryption and checksumming *services*
  but no algorithm *adapter*, and a local 26ai with no NNE configured lists
  exactly the same lines — the adapter rows are what 19.32's required NNE adds.
  One thing the run found that the citation did not say: thin mode needs the
  wallet's **download password**, because it reads the encrypted
  `ewallet.pem` rather than the auto-login `cwallet.sso`. Changes no
  behaviour: the tool has one mode, and it is thick.

## Next use cases

**None of these is specified, and each is a number you may cite today.** That is
the point of the section: UC-1 keeps meeting work that is plainly this tool's job
and plainly not *this* use case's, and "belongs to another use case" is only a
real answer if the other use case has a name. Where something is deferred here,
the deferral says which one and why.

The numbers are stable once written down. Renumbering would break references from
documents, issues and pull requests that have already used them, so a new use case
takes the next free number rather than the position it feels like it deserves.

### UC-2 — personal account passwords

Developer, tester and DBA accounts: a human's own credential rather than an
application's. Different in almost every dimension that matters, which is why it
cannot be a mode of UC-1:

- **there is no vault as master.** A password is handed over, not synced. Nothing
  fetches it at runtime, so invariant 6's direction has nothing to be a direction
  *of*;
- **expiring deliberately is the point.** `ALTER USER … PASSWORD EXPIRE` forces a
  change on first use, which is correct for a person and breaks an application —
  that is why UC-1 §5 has no `PASSWORD_EXPIRE` attribute (#302), and this is where
  the operation lands;
- **lockout tolerance is different.** UC-1 §7's whole apparatus exists because
  locking a production application account is an outage. Locking a developer out
  of their own account is a Tuesday;
- a self-service angle is possible here and is not possible in UC-1, where the
  point is that no human is in the loop at 03:00.

*Defers to it today:* UC-1 §5 (deliberate expiry, #302).

**Now specified** as [use-cases/uc-02-personal-account-passwords.md](use-cases/uc-02-personal-account-passwords.md)
(#438), both parts: the reset in #457 and delivery in #456. The paragraphs above are the
argument for the use case existing; the document is where it is specified, and
its questions are H1–H10: H9 the delivery section raised about itself, and H10
the principle UC-2 §1 states. One correction to the paragraphs above: expiring
deliberately is the point only on the **seen** path, where the DBA knows the
password — a deliberate exposure that the owner's first logon ends. The default,
unseen path writes it to a store meant for its owner alone and expires nothing;
how far "alone" holds depends on the store form and its delivery (UC-2 §6, #456).

#### What UC-2 adds to a config file

**Three blocks, not ten.** The delivery work is split across eight issues because
each method is its own dependency, its own extra and its own verification, and the
issue count reads much heavier than the configuration surface actually is. This is
that surface, gathered, so it does not have to be reconstructed from issues again.
`01-configuration.md` documents each block when it is **built**; this says what is
coming and what each one waits on.

| Block | Issue | State |
|---|---|---|
| `personal_accounts:` | #467 | **built**, schema 1.4 |
| `reset_records:` | #468, #511, #512, #514, #444 | **built**, schema 1.5; written by `account reset-password` since #511, locked on since #512, surveyed by `lock status` since #514, and carrying an unseen delivery's accessor in `delivery.to` since #444 |
| `delivery:`, with `notify:` inside it | #440, #441, #442, #444 | **built**. Two delivery methods -- `manual` (#441) and `vault_wrapped` (#444, the default) -- and `notify.method: webhook` (#442), which posts through the `[notify]` extra. **The two ways it can fail are not the same** (#520): a client that is not installed refuses the reset at plan time with `SOPULI-20003` and exit 9, before the password changes, because it is knowable then; a webhook that cannot be reached at send time is `SOPULI-W026` at exit 0, because by then the password has changed and the person can still fetch it |

The verbs, for the same reason: `account suspend` (#463), `account list` (#490)
and `reset-password` are built -- the latter on **both** the seen path (#441) and
the default unseen one (#444, `vault_wrapped`) -- and so is `expire-password`
(#525), which closes an open rollover window before it expires. The other four
unseen methods are not (#445-#447 and `smtp_encrypted`).

**`personal_accounts:`** is a list, each entry declaring exactly one of
`accounts:`, `profile:` or `role:`, plus optional `targets:` and `policy:`. What
it *reuses* is worth as much as what it adds —
`policy:` names an ordinary `policies:` entry, so **UC-2 introduces no policy block
of its own**, and a personal account's password is generated under the same
`policies:` machinery an application account's is.

**`reset_records:`** is one block with two keys — a store and a prefix — declared
once for the estate rather than per account. It is the DBA side's
journal — *who* reset an account, by which path, where it was delivered, never the
password (UC-2 §3.1) — and it is not the delivery target, which on the unseen path is
written where only the person can read it. The same path is what UC-2's advisory
lock keys on (§3.3), which is why the block is a prerequisite of the reset verb
rather than an accessory to it. **#511 writes the record** — a run with the block
declared journals one per (target, account), and one without it warns at plan
time and resets anyway. **#512 takes the advisory lock** keyed on that path, so
two DBAs resetting one person at once no longer overwrite each other -- the
second is refused at exit 7 before it connects. **#514 makes `lock status` see
them**, by listing the declared prefix rather than enumerating keys under it —
which is the only way an offline verb can reach a predicate-declared account —
and reporting what it finds as this estate's rather than as a leftover
(`declared_by`, schema 1.28). `lock break` has cleared one by name throughout.

**`delivery:`** is one enum plus a sub-block per method, and #440 builds only the
skeleton: the `method` key, and a check that the matching sub-block exists. Each
method's own keys land with that method's issue.

| Sub-block | Issue | What it adds, and what is unsettled |
|---|---|---|
| `manual` | #441 | **unblocked** — #439 decided it prints to stdout, under five guards (invariant 2's fourth exception). Adds `force_expire: true`, refused at plan time when absent |
| `vault_wrapped` | #444 | `ttl` only. A response-wrapping token is single-use by construction, so `num_uses` is a **config error** rather than a key that is silently ignored |
| `vault_path` | #447 | a path template, and the **renaming** #447 asked for rather than a flag on `vault_wrapped`: it is not wrapping, nothing is single-use, and the guarantee comes from the path's policy. Needs human-identity auth and a templated policy that sopuli does not create, which is why it is not the default |
| `one_time_link` | #445 | `backend: yopass`, `base_url`, and `ttl`/`one_time`. Needs an OpenPGP dependency, because Yopass encrypts client-side; may not be buildable as sketched |
| `onepassword_share` | #446 | the API token as a MaterialRef (C9). **May not be buildable at all** — Connect may have no sharing, and #446 refuses to guess |
| `smtp_encrypted` | — | no issue of its own; UC-2 §6.2 puts it in the enum and specifies it no further than *unseen*, so the enum is the whole set rather than the set that happened to have issues |

**`notify:`** (#442) is a channel the unseen methods reuse rather than a fourth
method: `notify.method: webhook`, configured as `notify.webhook.{url, template}`,
with `url` a MaterialRef because a webhook URL routinely embeds its own credential.
It nests **under `delivery:`** (UC-2 §6.3).

**Whether a retrieval credential may travel it is settled** (UC-2 §6.1): no. "Anything
that retrieves it" counts as secret-bearing, so a wrapping token and a one-time
link are refused in a notify template rather than rendered — the rule is about
*reach* rather than about *value*, and a token that holds no password still
produces one. What that leaves open is where such a credential does travel, which
is H9 (#496), decided: nowhere the tool carries. The hand-over is out of band; an
unwrap the person did not make is attributable through the accessor where Vault
has an audit device; and no device, or a redirected token, is where that stops
(UC-2 §6.8).

**The restriction axis is not a `delivery:` key**, which is the one thing in this
map that is easy to file in the wrong place. **H6 is decided** (#453):
`safety.delivery.allowed_methods`, ratcheting by **intersection** so a layer may
only narrow the set and no higher-authority layer can restore a method a lower one
removed.

It is fail-closed, and that is what the decision turned on. A
`forbidden_methods` union would have fitted the existing machinery without a line
of new code — and would have permitted every method a later release adds, in every
estate that had not yet heard of it. An intersection makes the same method unusable
until somebody names it. The cost is a **fourth ratchet shape**, declared per
setting rather than read off the type, since `confirm_environments` is a list of
strings too and the two must merge oppositely; `safe_bool` is the precedent, which
is what makes it a fourth shape rather than a second mechanism. `CLAUDE.md`
invariant 10, P3's safety bullet and `01-configuration.md` §9's merge-policy table
all carry it, and **#498 built it** — the key in a `safety:` block, the
intersection across every layer, the plan-time refusal when two layers have no
method in common, and the effective set in `config show --explain`. **#441 gave
it its consumer**, which is what #498 said would happen: `account reset-password`
refuses a method the resolved set does not permit, after the estate merge and
with no `--force` to waive it, and the registry's `inert_reason` is deleted
rather than left to rot.

**The seen path is built** (#441): `sopuli account reset-password` with
`delivery.method: manual`, under #439's five guards. So is the unseen default,
`vault_wrapped` (#444). A method this build does not implement is refused at plan
time on exit 5 (open: #445, #446, #447). The reset record and the advisory lock
keyed on its path are written where `reset_records:` is declared (#468, #512);
without that block, every run warns that the run document and the database are
the whole record.

**What blocks what.** **#456 is written and #440 and #498 have landed**, so every
`delivery:` issue now waits on nothing — the config block and the ratchet are both
built, and everything below that is implementation rather than decision. **H7
(#454) is closed** too — a reset draws fresh randomness, so it is outside
invariant 9 rather than an exception to it, and reports `changed: true` with a
warning naming what it replaced, which is what #441 needed before it could report
anything at all. H8 (#459) and H9 (#496) are closed, both decided by
UC-2 §1's principle — attribution, not access — and one UC-2 decision remains, which blocks
nothing in this table: H10 (#591), whether a reset checks the audit condition that
principle rests on.

**Each block is a schema minor bump** — 1.4 became 1.5 with the record, 1.5 became
1.6 with `delivery:` and 1.6 became 1.7 with `safety.delivery.allowed_methods`, and
onward for each method sub-block unless they are batched. Additive and
optional every time, so a file that declares none of them keeps meaning exactly
what it did, which is the rule every bump so far has followed.

### UC-3 — run a statement across many targets

The verb a DBA reaches for constantly and this tool has no answer to: *run this
against all twenty-one PDBs and tell me what each one said*. Fanning one
statement across a selected estate, with the run document's per-target results,
the same selectors, the same lock and safety ratchets.

**The hard part is not the fan-out, it is the privilege model.** ADR-001 buys its
whole argument from the service account holding `ALTER USER` and nothing else —
`02-oracle-privileges.md` §3 lists what must never be granted, and the guardrails
in §4 exist because even `ALTER USER` reaches `SYS`. A verb that runs arbitrary
SQL needs whatever privilege that SQL needs, so it either connects as a different
principal or it dissolves the model. That is the first thing this use case has to
answer, and it is a genuine question rather than a reason to refuse: a DBA
pasting the same statement into twenty-one sessions by hand has strictly more
power than the tool would be given, which is §1's argument for the whole project.

Also unresolved before it could be written: whether a statement is allowed to
mutate at all or only to read; whether `--dry-run` can mean anything for SQL the
tool does not understand; and what a *result* is when twenty targets each return
a different row set.

### UC-4 — user provisioning

Creating and dropping accounts, and everything an account needs in order to
exist: grants, roles, quotas, profiles, default and temporary tablespaces.

UC-1 deliberately does none of it. A missing account is `ACCOUNT_MISSING`, a state
to report rather than a failure to recover from, and invariant 5 makes the config
a whitelist of what may be *touched* rather than a list of what should exist.

Profiles are the one item on that list UC-1 half-touches, so the split is worth
stating. UC-1 *assigns* a profile (#301) and never creates or alters one, decided
in Q4 (#88): `ALTER PROFILE` edits a shared object and so reaches accounts nobody
selected, which the account whitelist cannot constrain. Here that argument does
not hold in the same way — provisioning is where a profile is authored on purpose
rather than reached sideways during a rotation — so **whether this use case may
issue `ALTER PROFILE` and `CREATE PROFILE` is its own question, open, and not
foreclosed by #88.** What #88 does foreclose is the credential-sync verbs ever
doing it. If the answer here is yes, the privilege belongs to a principal this use
case defines, not to UC-1's service account, whose grant set `02-oracle-privileges.md`
§3 keeps it off.

*Defers to it today:* Q8 (may `apply` create a missing account — no, it belongs
here), the *creating and altering* half of profiles, which Q4 (#88) settled only
for the credential-sync verbs, and UC-1 §5's default/temporary tablespace
attribute (#303). The tablespace one is worth stating plainly: `ALTER USER … DEFAULT TABLESPACE` moves no existing
segment, so an account's objects stay exactly where they were. During a credential
rotation that is a half-change that reads as done and is not — while during
provisioning, where the account has no objects yet, it is simply part of creating
one correctly.

### UC-5 — drift and compliance reporting across a fleet

`creds check` answers "does the vault agree with this database" for the accounts
one config declares. The reporting use case asks the estate-wide version: which
accounts exist that nobody declared, which profiles are in use, where password
versions or verifiers are older than policy allows, what the fleet looks like to
an auditor.

Distinguished from UC-1 by what it is allowed to touch, which is nothing.

### UC-1b — self-rotation, where there is no admin credential

`ALTER USER … IDENTIFIED BY new REPLACE old`, connecting **as the account being
rotated**, for estates that will not issue a service account holding `ALTER USER`.
A variant of UC-1 rather than a use case of its own — same vault, same direction,
same promotion ordering — which is why it keeps the `b`.

*Defers to it today:* Q6 (UC-1 §12).

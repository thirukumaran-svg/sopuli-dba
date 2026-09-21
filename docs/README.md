# sopuli-dba — design documentation

This index is for contributors. **If you arrived here wanting to use the tool,
start at [getting-started.md](getting-started.md) instead** — the documents below
are the specification, written in the project's own declarative voice.

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
| [schemas/sopuli-config-1.7.schema.json](schemas/sopuli-config-1.7.schema.json) | JSON Schema (2020-12) for the config file (P3). Generated from the config layer by `python -m sopuli.config.schema` — never edited by hand |
| [schemas/sopuli-run-1.27.schema.json](schemas/sopuli-run-1.27.schema.json) | JSON Schema (2020-12) for the `--output json` document — the current one; earlier minors stay published beside it, because a build emitting `schema_version: "1.20"` has to be able to fetch what it validates against |
| [schemas/sopuli-event-1.1.schema.json](schemas/sopuli-event-1.1.schema.json) | JSON Schema for `--output jsonl` events |
| [schemas/example-creds-check-drift.json](schemas/example-creds-check-drift.json) | Worked example: a scheduled check finding drift in one of two PDBs |
| `../sql/oracle/00_install.sql` | Create and grant the service account — `NONCDB` / `COMMON` / `PDB` modes |
| `../sql/oracle/01_audit_policy.sql` | Unified audit policies and correlation queries |
| `../sql/oracle/02_password_leak_probe.sql` | Release gate 2: canary probe for password text retained anywhere queryable. Run on 26ai, 21c, 18c and 11.2; findings in `design/02-oracle-privileges.md` §4, what is still open in `design/04-testing.md` §6 gate 2 |
| `../sql/oracle/04_password_leak_extensions.sql` | Gate 2's other three checks — self-rotation, `IDENTIFIED BY VALUES`, and a 10046-traced session. Run on 26ai and 21c (#407). Run it after the probe and **before** the probe's §8, which turns the audit policies off |
| `../sql/oracle/99_uninstall.sql` | Remove the account; keeps the audit policies by default |
| [decisions/adr-001-privilege-model.md](decisions/adr-001-privilege-model.md) | Why direct `ALTER USER`, what was rejected, and the two triggers for revisiting |
| [decisions/adr-003-text-tables.md](decisions/adr-003-text-tables.md) | No table library: columns formatted with click and the standard library, and why output must not depend on the terminal |
| [decisions/adr-004-yaml-parser.md](decisions/adr-004-yaml-parser.md) | PyYAML on a hardened `SafeLoader`, why not ruamel, and the pywin32 dependency for the P4 permission check |
| [decisions/adr-005-vault-client.md](decisions/adr-005-vault-client.md) | The HTTP API directly, over `httpx`, not `hvac` — measured against a real Vault, why renewal doesn't change the answer, and what still binds OCI to its own SDK |
| [decisions/adr-006-optional-dependencies.md](decisions/adr-006-optional-dependencies.md) | Vendor clients are install extras: what base carries, why base opens no sockets, and what a configured-but-uninstalled backend does |
| [decisions/adr-007-vault-token-flag.md](decisions/adr-007-vault-token-flag.md) | `--vault-token-file` takes a path and `--vault-token` is refused; why a SecretRef cannot authenticate the store it lives in, and where the token chain merges |
| [decisions/adr-008-contribution-provenance.md](decisions/adr-008-contribution-provenance.md) | A DCO sign-off rather than a CLA, why review-time checking rather than CI, and what would change either |
| `../test/compose.yaml` | Test stack by tier: Vault (KV v1 + v2), PostgreSQL, Oracle Free/21c/18c/11g, an NNE-required Oracle, toxiproxy |
| `../test/capabilities.py` | Sketch of capability probing and the pytest skip markers |
| `../test/k8s_eso_probe.py` | Applies [scenarios/kubernetes-eso.md](scenarios/kubernetes-eso.md)'s own manifests to a throwaway Kubernetes cluster, and checks that ESO reads what sopuli wrote. Needs a cluster, not compose |

All three schemas validate as Draft 2020-12, and the example validates against the
run schema. That is no longer an assertion in prose: `tests/test_schemas.py`
checks it, and CI runs it on every push and pull request (invariant 12).

To get completion and inline errors while editing a config, put
`# yaml-language-server: $schema=./sopuli-config-1.7.schema.json` on the file's
first line — see [design/01-configuration.md](design/01-configuration.md) §9b,
which also explains why the schema's `$id` is not a URL to paste there.

The config schema is generated rather than written, and
`tests/config/test_schema.py` fails if the committed file is not what the config
layer produces today. A key added to a section without the schema following it
does not merge. What the schema deliberately leaves to the validators — the
cross-key rules, whose errors have to name the offending key — is listed in
[design/01-configuration.md](design/01-configuration.md) §9b.

## Conventions

- Binary name `sopuli`, project name `sopuli-dba` (open decision D1)
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

## Consolidated open decisions

**Principles (00): all decided.** Binary `sopuli` (D1); noun-verb CLI (D2);
Python with python-oracledb thick mode (D3); YAML config (D4); macOS best-effort
and untested (D5); drivers in-tree until there is a second one (D6); Oracle 11.2
stays in scope, unreachable from Apple Silicon (D7); click as the CLI framework
(D8); vendor clients are install extras (D9).

**Packaging (130): all decided**, in
[ADR-006](decisions/adr-006-optional-dependencies.md). Every dependency that
exists only to reach one vendor is an install extra; base carries the CLI
framework, the YAML parser, `pywin32` on Windows and sopuli itself, and **opens
no sockets** — a testable property, not a slogan. ~~Does the rule bind database
drivers as well as stores~~ (E1 — **decided: yes.** `python-oracledb` is
`sopuli-dba[oracle]`; binding stores and not drivers would read as arbitrary, and
D3's Instant Client prerequisite already makes reaching Oracle a per-site
condition), ~~is the HashiCorp store base or an extra~~ (E2 — **decided: an
extra.** #103 landed on the HTTP API, so there is no vendor client — but `httpx`
is still a network client, and rule 3 names the installed dependency set —
`httpx`, the OCI SDK, `python-oracledb` — precisely so a test can hold it.
`httpx` ships in `sopuli-dba[hashicorp]` and ADR-005's consequence is amended),
~~does `sopuli-dba[all]` exist~~ (E3 —
**decided: yes**, CI and the test matrix need one name that means everything;
user-facing install instructions recommend the extras a site actually has, never
`all` as the default line), ~~does `config validate` fail or warn on a
configured-but-uninstalled backend~~ (E4 — **decided: warn.** The config is
valid; the install is incomplete. A validator that calls a good file broken is
less trustworthy for the case it exists to serve), ~~which exit code and
category~~ (E5 — **decided: `config`, exit 9.** `capability` names what a
*target* cannot do; a missing backend is fixed locally by the person reading the
message. It carries an `error.code` so a consumer can branch without parsing
prose), ~~does `doctor` always list install shape~~ (E6 — **decided: always.**
Its output is audit evidence as often as it is a diagnostic, and a section that
appears only on mismatch cannot be quoted as proof that there was none). The
documents that cite the rule are updated with it: `01-configuration.md` §3a has
what a declared-but-uninstalled `type:` does and §9/§10 have the warning,
`03-json-output.md` §3 has `SOPULI-20001` and `SOPULI-W003`, `04-testing.md` §3
makes install shape a dimension of the matrix, and the root `README.md` leads
with the install matrix. `pyproject.toml` and the registry's lazy import landed
in #134, with `SOPULI-20001` and `SOPULI-W003` as the first codes anything
actually emits, and `doctor`'s install-shape section landed in #214 as
`install` in schema 1.13 — every registry entry on every run, so *installed and
not configured* is reportable and a clean run can be quoted as evidence.

**Configuration (01):** ~~naming of the binding section~~ (C1 — **decided:
`applications`, with an inline single-application form**), label selector syntax
(C2), template expressiveness (C3), per-account overrides (C4), config encryption
(C5, proposed out of scope), mirrored vault writes (C6), ~~target-set nesting
depth~~ (C7 — **decided: two levels, write a second set**), ~~labels on explicit
targets~~ (C8 — **decided: allowed**), ~~how the file points at vault auth
material and the database admin credential~~ (C9 — **decided in #27**: one
grammar, two vocabularies. A vault's secret-bearing keys are each a MaterialRef,
one of `env` / `file`, so the config has nowhere to hold a credential; the admin
credential names one of P2's four sources, with `external` constraining the DSN to
a TNS alias; `oracle.scope` adopts the run document's vocabulary and is an
assertion checked on connect), ~~what profiles are for~~ (C10 —
**decided: run context, not target selection**), composable profiles (C11,
proposed no), a built-in `interactive` profile (C12, leaning no), ~~whether `vault:`
under `defaults`/`profiles` is a name or a block~~ (C13 — **decided in #31: a
name, everywhere.** Settings *of* a store are reached by naming it under
`vaults:`, which `defaults:` and a profile may each carry as partial entries;
this is §6's `SOPULI_VAULT` / `SOPULI_VAULT__VAULT_DEV__ADDR` pair written in the
file. A layer may set every reach setting a store has, but not `type` and not the
guardrails `non_production` and `locking`. Implemented in #136 for the layers the
file supplies, which corrected one word: `defaults.vaults:` is layer 5 and so
fills gaps rather than patching — only a profile, at layer 3, is above the
declaration. A profile's block was applied in #153, in the same pass, and the environment's half in #154 — `SOPULI_VAULT__VAULT_DEV__ADDR` at layer 2 and `VAULT_ADDR` and friends at layer 3, with an ambiguous store-name-to-variable mapping refused rather than resolved, and the unnamed `SOPULI_VAULT_ADDR` bound to the store `defaults.vault` names rather than to whichever store a binding happened to reach), ~~the `@version=` and `@stage=` vocabularies in a
SecretRef and who owns them~~ (C14 — **decided in #40: the tool owns both.**
`stage` is `current` / `pending` / `previous`, any case in, lower case out;
`version` is a whole number from 1; neither may hold a `{token}`. OCI's rotation
states turned out to be a fixed Oracle-defined set rather than user-definable
labels, so there was no backend vocabulary to defer to and the run schema is
ratified as written), ~~a binding names a secret and no store, anywhere: refuse,
warn, or leave it to plan time~~ (C15 — **decided in #118: mostly plan time.**
`_vault_for` resolving to `None` is not always wrong — a profile's `vault:` or
`SOPULI_VAULT` can still complete it, and neither is consulted while bindings
are built once at load — so it is left alone, shown as `-` by `config show
--resolved`, and caught exactly by the first command that needs a store.
Refused at load only for the narrower case nothing at run time can ever
complete: `vaults:` declaring no store at all, so there is nothing for a
profile or `SOPULI_VAULT` to name), ~~what does `--vault-token` take~~ (C16 —
**decided in #145: a path, under a different name.** `--vault-token-file PATH`
hoists §3a's `token: { file: … }` onto the command line, and a bare
`--vault-token` is **refused** with a message naming invariant 1 and all four
working sources — refused rather than absent, because Vault's own CLI accepts
`-token=` and somebody will try it, and refused rather than ignored, because a
flag that parsed and did nothing is a plan that looks like it accounted for auth
and did not. The crux is that P5's "or a vault ref" escape cannot apply to vault
auth itself: a ref is resolved *by* an authenticated store, which is P2's
bootstrap problem one layer earlier. Reusing the MaterialRef grammar
(`--vault-token env:NAME`) was rejected as a semantic collision rather than mere
cleverness — two identical-looking grammars with opposite resolution order.
`--vault-token-stdin` is deferred because `--from-stdin` claims the pipe, and the
rule it will have to satisfy is banked in P5 now. Recorded in
[ADR-007](decisions/adr-007-vault-token-flag.md), which also confirms `vault
login` as the human bootstrap and gives the flag's file P4's permission check),
~~P5 requires confirmation by default on `environment: prod` and over
`max_targets`, and §9 forbids a built-in that joins a ratchet~~ (C17 —
**decided in #294: §9 governs and P5 is reworded.** Confirmation is opt-in
through `safety.confirm_environments` alone. A built-in `[prod]` is an
unremovable floor under the union ratchet — §9 illustrates that trap with
`confirm` itself — and the blast-radius trigger would prompt on every
multi-target mutation for an estate that configured nothing, while reading a
*ceiling* as a confirmation threshold. Both are **declined rather than
deferred**, so a `prod` target no layer listed is not prompted for by design, and
`tests/test_cli_confirm_environments.py` fails if either returns. `creds rotate`
and `lock break` confirm unconditionally and were never part of the question).

**Oracle privileges (02):** common `C##` service user or per-PDB local as the
documented default (P1), ~~grant `SELECT ON SYS.USER$` by default~~ (P2 —
**decided in #86: no.** Optional, capability-probed grant instead — `check`
defaults to `login` unconditionally either way. Whether to *recommend* the
grant, and whether `SELECT_CATALOG_ROLE`/`KU$_USER_VIEW` is a narrower
alternative, is deferred to #124), ~~whether `--force` exists~~ (P3 — **decided in #89: yes**, one flag overriding
§4's account checks 2–5 and nothing else. `DBSNMP` is the case: rotating its
password is ordinary DBA work and it is `ORACLE_MAINTAINED`, so a tool with no
override does not prevent that rotation — it moves it to SQL\*Plus, where nothing
records it. Per-check flags were rejected as a growing flag surface for a rare
case. It never overrides the config whitelist, and it is deliberately **not a
setting**, which is what keeps it structurally unable to relax `readonly`,
`max_targets`, `confirm_environments` or `dry_run`),
one service account per database or per application (P4),
does `doctor` fail or warn on over-granted privileges (P5), keep 11.2 support
(P6). *(~~P7 — do the 23-codebase schema privileges cover `ALTER USER`~~ — is
answered: **no**, `ORA-00990`, tested on 26ai 23.26.2.0.0 with a succeeding
`SELECT ANY TABLE ON SCHEMA` as the control. The direct grant is the permanent
model and ADR-001's P7 revisit trigger is closed. ~~P8 — 11.2 retains the
`ALTER USER` text in `V$SQLSTATS`; document it, warn, or refuse~~ — is answered
in #387: **document it**. The exposure needs a dictionary grant the service
account does not have, and it is a window rather than a record — it ages out with
the shared pool and one `FLUSH SHARED_POOL` clears it. A runtime warning would
have had to branch on a version number, since nothing can probe the fact; refusing
would have reversed D7 and moved the rotation to SQL\*Plus, which retains the same
text. The boundary between 11.2 and 18.4 stays unmeasured.)*

**JSON output (03):** buffering policy for `--output json` (J1), always emit
`plan` (J2), warning code registry (J3), host/pid in output (J4), OpenTelemetry
(J5), resumable streams (J6). *~~Does a usage error emit a run document~~
resolved 2026-08-13 in issue #8: no — a run document describes a run, and a run
begins when the invocation resolves. Exit 2 is the only code that never produces
one; P5 gained exit 9 so that an invalid config file, which has a perfectly good
invocation, stops sharing a code with a bad command line (J7).* *~~Which library
renders text tables~~ decided
2026-08-11 in [ADR-003](decisions/adr-003-text-tables.md): none — `click` plus
the standard library, on dependency weight and on keeping output independent of
the terminal. `config show --resolved` was the first command with real results
to display, which is what the decision was waiting for.*

**Testing (04):** testcontainers or compose (T2), LocalStack tier (T3), OCI Vault
cost in a test loop (T4), real standby for the read-only refusal (T6), Oracle
reset strategy (T7). *T1 resolved 2026-08-08: the 11g XE image exists and works,
so 11.2 stays tier 2. T5 resolved 2026-08-09: GitHub Actions, tier 0 wired in
`.github/workflows/ci.yml`.*

**UC-1:** ~~default verification method and the privilege it implies~~ (Q1 —
**decided in #86: `login`, unconditionally**, independent of profile. The
earlier "hash under an unattended profile" leaning assumed hash mode existed
and its grant was default; neither holds. The `LCOUNT` guard and `--method
hash` both depend on the same optional, capability-probed `SELECT ON
SYS.USER$` grant instead — see 02 P2, also #86), ~~where the advisory lock
lives~~ (Q2 — **decided in #83: in the vault**, one
CAS-guarded record per *secret path*, with a fencing token re-checked before
every mutation. `DBMS_LOCK` was rejected: its one advantage is release on session
death, and a stalled session is still alive, so it does not prevent the failure
that matters — a run waking from a stall and applying a stale plan. Fencing does,
and it costs no widened grant set. Stores without `cas` refuse mutations unless
configured `locking: advisory-only`), ~~how many `previous` generations to keep~~ (Q3 —
**decided in #84: exactly one**, plus whatever the store's native versioning
gives for free. C14 settled it: OCI holds exactly one `PREVIOUS`, and a closed
three-stage vocabulary has nothing to address an older generation with),
~~whether the tool ever alters a profile~~ (Q4 — **decided in #88: never**, in
any credential-sync verb. A profile is shared, so editing one reaches accounts
nobody selected, and the config whitelists accounts rather than profiles, so
invariant 5 has no way to constrain it. The tool reports the `ALTER PROFILE` an
operator would run and issues none; `02-oracle-privileges.md` §3 keeps the
privilege off the service account and `doctor` flags it as an over-grant. An
`--allow-profile-change` opt-in was rejected because a flag cannot conjure a
privilege — the grant would sit on every installation whether or not anyone used
it — and altering a profile only where declared accounts use it exclusively was
rejected as a race, on a question `DEFAULT` almost always answers no. Creating
and altering profiles is UC-4's to decide, for its own principal), drift
notification (Q5),
self-rotation mode (Q6), ~~one-secret-per-account vs one-secret-per-app~~ (Q7 —
**decided in #85: one secret per application**, a field per account, as the
documented *default*; per-account stays fully supported. An application's accounts
rotate together far more often than separately, and the per-account layout
multiplies paths by accounts across every tenant and environment. Nothing about
the lock or the write path changes shape, because Q2 already keyed the lock on the
path and the merge patch already writes one field without touching its siblings —
so the account remains the unit of work even in a shared document. The payload
follows one rule: every root-level key mirrors the shape of the current-stage
container. The one real cost is that a shared document cannot use native version
staging, because an OCI or AWSSM stage is per secret),
account creation scope (Q8), ~~authoritative time source for password age~~ (Q9 —
**decided in #87: vault `rotated_at`**, unconditionally; `status` shows the
database's own timestamp beside it rather than folding the two into one number.
Settles the aggregation question option 2 would have raised — one vault age
per secret path, however many targets share it, needs no rule for "oldest,
newest, or any" the way N database ages would have. The database column stays
purely informational: a target the tool has never reached still looks exactly
as fresh as the vault says, and nothing currently reads that column to decide
anything, which is the cost this option accepts over option 3's thresholded
`diagnostics[]` warning).

**UC-2 (personal account passwords).** Two paths: an **unseen** default, where the
DBA never sees the password, the tool writes it to a store meant for its owner
alone, and nothing is expired — owner-only by the store's access control on an
identity-scoped path (#447), and only as far as its delivery on a wrapping token,
which is a bearer credential (#444, UC-2 §6.6) — and a **seen** `manual` path, which is
a deliberate exposure until the owner's first logon: non-default, confirmed,
always expired. Decided on review of #457, and **how its one plaintext emission is
narrowed is now decided too** (#439): five structural guards, invariant 2's fourth
exception. ~~Is self-service in scope~~ (H5, #452 — **closed:**
self-service means the owner fetching the password from a secure store, not
resetting through the tool). ~~How an estate
restricts delivery methods~~ (H6, #453 — **closed:** `safety.delivery.allowed_methods`,
ratcheting by **intersection**, so a layer may only narrow the set. Fail-closed:
a method a later release adds is unusable until an estate names it, where the
`forbidden_methods` union would have permitted it everywhere on upgrade. It costs
a fourth ratchet shape, declared per setting the way `safe_bool` already is, and
there is no `forbidden_methods` now or later; built in #498). ~~A reset never
converges~~ (H7, #454 — **closed:** it reports `changed: true` every run and warns
what it replaced, and invariant 9 is restated as a **scope** rule rather than
gaining a second exemption: a verb that draws fresh randomness has nothing to
converge on, which admits `creds generate` and this one by one sentence.
Convergence on a request id or on account state was refused because both key on a
record an estate need not configure — and account state is not a signal on the
unseen path, which issues no `PASSWORD EXPIRE`). Open: on the unseen path, what
happens to the stored copy and how the DBA is shown unable to read it (H8, #459);
and, raised by the delivery section itself, what "unseen" guarantees when the DBA
holds the wrapping token (H9, #496).
**H2 is decided** (#450): what a reset records lives in three places rather than
one. The **database** answers *when* the password last changed
— `DBA_USERS.PASSWORD_CHANGE_DATE`, `SYS.USER$.PTIME` behind the optional grant,
12.1 and 12.2 unmeasured on that fallback (unverified: pw-changed-source). That
diverges from Q9 deliberately: on the seen path the owner is required to change the
password at first logon, so a record's own timestamp is designed to be overtaken by
a change the tool never sees — and reading a timestamp is not invariant 6's
business, because invariant 6 governs the value. A **metadata record**, written
wherever a store is configured and never where one is not, answers *who* reset it,
by *which path*, and *where it was delivered*, and holds no password in any
representation; its path is what Q2's lock keys on, which is the first key UC-2 has
had, since the wrapping-token form writes no secret path and `manual` writes nothing
at all. **Nothing** answers *what to roll back to*: rollback is not a UC-2
operation. A reset with no store configured warns at plan time and runs, because
requiring one would take `manual` away from the estates it exists for. The keys,
schema and validators are **#468**, split out in #467's shape. **H4 is
decided** (#455): a reset never verifies a delivered password and reports
`ACCOUNT_STATUS` instead, unlocks `LOCKED(TIMED)` by default while refusing a
deliberate `LOCKED` at plan time, and ends an open rollover window by default with
a flag to keep it — each measured on 26ai before it was decided. **H3 is decided**
(#451): the noun is `account` — the configuration's own word for what is being
managed, which settled the vocabulary and not the file; the file is
`personal_accounts:`, decided in H1 below — and the verbs are `reset-password` and
`expire-password`; suspending an account is `account suspend` — named that way to
avoid a second sense of `lock`, which already means the advisory locks `lock break`
takes, and specified in #463 — and the listing verb is `account list`, which H1 earns.
**H1 is decided** (#449): a personal account is declared in a `personal_accounts:`
section of its own, by name or by a **predicate** over a profile or a role. The
predicate amends invariant 5's first sentence — what counts as *declared* — and
leaves the second intact, because it never widens what a mutating verb may touch:
`account list` resolves it, while a reset names its account and refuses any name
the predicate does not admit. The cost is that predicate membership is controlled
by whoever assigns the profile or grants the role, rather than by whoever reviews
the file. The delivery
section is written (#456), and H6's amendment to invariant 10 landed with #453. **How the seen path's
one plaintext emission is narrowed is decided** (#439): it prints, under five
structural guards — one reveal site, refused with `--output json`/`jsonl`, refused
unless stdout is a terminal, confirmed every time with `--confirm` *not* answering
it, and `force_expire: true` required. `CLAUDE.md` invariant 2 carries a fourth
exception for it, and says why its justification is weaker than the third's and its
narrowing therefore stricter. See
[use-cases/uc-02-personal-account-passwords.md](use-cases/uc-02-personal-account-passwords.md) §9.

### Settled

**The privilege model is direct `ALTER USER`.** The definer-rights package was
drafted and rejected: the operator is a DBA who already holds SYSDBA, so the
package constrains someone who is not actually constrained, while adding a
per-PDB install, a second whitelist to keep in sync with the tool's config, and
version skew as a new failure mode. Recorded in
[ADR-001](decisions/adr-001-privilege-model.md). It named two triggers for
revisiting; **P7 is now closed** — schema privileges do not cover `ALTER USER`
(`ORA-00990`) — so an unattended scheduled runner is the only one left, and it is
about credential custody rather than a narrower grant being available.

### Settle these next

1. **C1–C6** — the configuration questions, since the YAML schema is the next
   thing that becomes code.
*(T1 was here and is now answered: the image exists, 11.2 support costs nothing.
Q2 was here too and is answered in #83: the lock lives in the vault, keyed on the
secret path, fenced by the vault's own version counter. Building it is #94–#97.
Q1 + P2 was here too and is answered in #86: `check` defaults to `login`
unconditionally, and `SELECT ON SYS.USER$` is optional rather than granted by
default. What's left of it is deferred, not settled here — see #90 and #124
below.)*

## Verify before implementing

**Each entry carries a status and a slug**, and the slug is how the rest of the
tree points back here — see §Conventions. `tests/test_verification_register.py`
reads this section, so the two code spans at the head of each bullet are
structure rather than decoration; the prose after them is for people.

**The status is this register's, not GitHub's.** #383, #387 and #87 are closed
issues whose verification is still outstanding: the decision was taken and the
measurement was not. A reader who resolves these against the issue tracker gets
three wrong answers.

- `unverified` `t-verifier` (#90) — **Whether a client can regenerate the `T:` (12C) verifier in `SYS.USER$.SPARE4`.**
  The layout is read (#431) and the derivation reproduces byte-for-byte (#432),
  both on 26ai, 21c and 18c: `SHA-512(PBKDF2-HMAC-SHA512(pw_utf8, salt ‖
  "AUTH_PBKDF2_SPEEDY_KEY", 4096, 64) ‖ salt)`, and a rollover window's two
  verifiers (`T:` previous, `t:` current) are told apart the same way —
  `sql/oracle/05_verifier_layout_probe.sql` and `06_verifier_reproduce.{sql,py}`.
  Degradation is settled too (#433): the comparison uses `T:` only, an account
  with no `12C` fails at plan time (invariant 4), and the gate is a per-account
  capability (`SPARE4` carries a `T:`), never a version. **All three parts are
  answered on the tier-2 releases; the entry stays `unverified` because 19c — the
  release an OCI estate runs, and so the target of interest — is unread, as are
  12.1 and 12.2, none of them pullable.** Blocks
  `--method hash|both` only — `check`'s default (`login`) no longer waits on
  this (#86). If it does not reproduce on 19c, **both non-login modes go**:
  `both` is login *plus* the verifier comparison, so it cannot survive a
  negative result either, and a mode that silently degraded to `login` would
  report a stronger check than it performed.
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
  got a login failure. What is untried is the repair. Nobody has run sopuli
  against an ADB at all, so the `mkstore` line in §14 is Oracle's documented
  syntax rather than a command anybody here has watched succeed. Nothing in the
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
  release-dependent even though the reasoning is not (#387). **12.1, 12.2 and 19c
  are unrun, so the boundary below 18c is unknown** — read the 11.2 result as
  *11.2 does*, never as *everything older does*.
- `unverified` `ddl-text-awr` (#387) — **Whether the retained text reaches AWR.**
  `DBA_HIST_SQLTEXT` needs a snapshot taken *before* the sweep, on a database
  where the Diagnostics Pack is enabled. Every image in this stack ships
  `control_management_pack_access = NONE`, so two snapshots taken on 11g XE
  captured nothing whatsoever and the clean result measured the image rather than
  the release. Needs a licensed EE. **Untested, not clean** — the one row #407
  could not close.
- `verified` `ddl-text-trace` (#407) — **Whether a traced session captures the
  password.** Answered 2026-09-11 on 26ai and 21c, and it retires the pessimistic
  assumption rather than confirming it: at 10046 level 12 the cursor is written
  truncated, `ALTER USER sopulitest IDE`, stopping one character into
  `IDENTIFIED`. Five traced sessions, both releases, identical. The wrapped form
  leaks in full, which is invariant 13 on a fifth surface. The OS audit trail was
  answered in the same run (masked on 21c; no user-management DDL reaches it at
  all on 23ai+), as were self-rotation and `IDENTIFIED BY VALUES` — both masked.
- `unverified` `password-byte-limit` (#383) — **What the maximum password length
  actually is, on every release between 12.2 and 23ai.** `limits.py` derives the
  limit from the probed server version against `LONG_IDENTIFIER_FLOOR = (12, 2)`,
  and **the premise is wrong**: 12.2 raised *identifiers* from 30 bytes to 128
  and passwords did not move with them. #383 measured it — 31 bytes is
  `ORA-00972` on 21c, 18c and 11.2, and accepted on 26ai — so the floor is
  somewhere in `(18.4, 23.26]` and `(12, 2)` is below every version ever tested
  against it.

  **This is a live bug, not a latent one**, and saying so is the point of the
  entry: on 21c a policy asking for 40 bytes plans clean, reports
  `constraints: 128 bytes`, and fails with `ORA-00972` mid-`apply` — which is
  invariant 4 violated, the exact thing plan-time refusal exists to prevent.
  #383 closed **without fixing it** because the constant cannot be corrected
  safely without measuring 19c, and 19c is the release it matters most on. An
  earlier draft of this entry said "nothing is broken today"; that was wrong, and
  #412's review caught it.
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

  **12.1 and 12.2 would take the fallback and are unmeasured**, and that is what
  keeps this entry open. Purely a display question — Q9 decided `--max-age-days`
  reads only the vault — and the tier-1 test pinning `PTIME` equal to the column
  fails on any release where the two part, so running the suite there settles it.
- `unverified` `expire-rollover` (#438) — **What `ALTER USER … IDENTIFIED BY …
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
  way to set the new one. **21c is unmeasured, so this stays open**: needs 21c,
  tier 2. Until it has one, `use-cases/uc-02-personal-account-passwords.md` §4.3
  still refuses a seen reset on a rollover profile at plan time — now for a
  measured reason rather than an absent one.
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
its questions are H1–H9, the last of which the delivery section raised about
itself. One correction to the paragraphs above: expiring
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
| `reset_records:` | #468, #511 | **built**, schema 1.5; written by `account reset-password` since #511 |
| `delivery:`, with `notify:` beside or inside it | #440, #442 | blocked, and the rest of this table is inside it |

The verbs, for the same reason: `account suspend` (#463), `account list` (#490)
and `reset-password` (#441, on the seen path) are built; `expire-password` is
not, and neither is any unseen delivery method.

**`personal_accounts:`** is a list, each entry declaring exactly one of
`accounts:`, `profile:` or `role:`, plus optional `targets:` and `policy:`. What
it *reuses* is worth as much as what it adds —
`policy:` names an ordinary `policies:` entry, so **UC-2 introduces no policy block
of its own**, and a personal account's password is generated under the same
`policies:` machinery an application account's is.

**`reset_records:`** is one block with two keys — a store and a prefix — declared
once for the estate rather than per account. It is the DBA side's
journal — *who* reset an account, by which path, where it was delivered, never the
password (§3.1) — and it is not the delivery target, which on the unseen path is
written where only the person can read it. The same path is what UC-2's advisory
lock keys on (§3.3), which is why the block is a prerequisite of the reset verb
rather than an accessory to it. **#511 writes the record** — a run with the block
declared journals one per (target, account), and one without it warns at plan
time and resets anyway. The lock keyed on that path is **#512** and is not built,
so two concurrent resets of one account are not yet serialised.

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
| `smtp_encrypted` | — | no issue of its own; §6.2 puts it in the enum and specifies it no further than *unseen*, so the enum is the whole set rather than the set that happened to have issues |

**`notify:`** (#442) is a channel the unseen methods reuse rather than a fourth
method: `notify.method: webhook`, configured as `notify.webhook.{url, template}`,
with `url` a MaterialRef because a webhook URL routinely embeds its own credential.
It nests **under `delivery:`** (§6.3).

**Whether a retrieval credential may travel it is settled** (§6.1): no. "Anything
that retrieves it" counts as secret-bearing, so a wrapping token and a one-time
link are refused in a notify template rather than rendered — the rule is about
*reach* rather than about *value*, and a token that holds no password still
produces one. What that leaves open is where such a credential does travel, which
is H9 (#496): today, nowhere the tool carries.

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
`delivery.method: manual`, under #439's five guards, and the unseen methods
refused at plan time on exit 5 until #444-#447 land. The reset record and the
advisory lock keyed on its path are the part #468 shaped and nobody has written
yet, so every run warns that the run document and the database are the whole
record.

**What blocks what.** **#456 is written and #440 and #498 have landed**, so every
`delivery:` issue now waits on nothing — the config block and the ratchet are both
built, and everything below that is implementation rather than decision. **H7
(#454) is closed** too — a reset draws fresh randomness, so it is outside
invariant 9 rather than an exception to it, and reports `changed: true` with a
warning naming what it replaced, which is what #441 needed before it could report
anything at all. Two UC-2 decisions remain and neither blocks this table: H8
(#459), the stored copy's lifetime; and H9 (#496), what "unseen" guarantees when
the DBA holds the wrapping token — which the delivery section raised about itself.

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

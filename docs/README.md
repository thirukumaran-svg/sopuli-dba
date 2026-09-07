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
| [schemas/sopuli-config-1.3.schema.json](schemas/sopuli-config-1.3.schema.json) | JSON Schema (2020-12) for the config file (P3). Generated from the config layer by `python -m sopuli.config.schema` — never edited by hand |
| [schemas/sopuli-run-1.16.schema.json](schemas/sopuli-run-1.16.schema.json) | JSON Schema (2020-12) for the `--output json` document |
| [schemas/sopuli-event-1.0.schema.json](schemas/sopuli-event-1.0.schema.json) | JSON Schema for `--output jsonl` events |
| [schemas/example-creds-check-drift.json](schemas/example-creds-check-drift.json) | Worked example: a scheduled check finding drift in one of two PDBs |
| `../sql/oracle/00_install.sql` | Create and grant the service account — `NONCDB` / `COMMON` / `PDB` modes |
| `../sql/oracle/01_audit_policy.sql` | Unified audit policies and correlation queries |
| `../sql/oracle/02_password_leak_probe.sql` | Release gate 2: canary probe for password text retained anywhere queryable. Run on 26ai; results in the top-level README |
| `../sql/oracle/99_uninstall.sql` | Remove the account; keeps the audit policies by default |
| [decisions/adr-001-privilege-model.md](decisions/adr-001-privilege-model.md) | Why direct `ALTER USER`, what was rejected, and the two triggers for revisiting |
| [decisions/adr-003-text-tables.md](decisions/adr-003-text-tables.md) | No table library: columns formatted with click and the standard library, and why output must not depend on the terminal |
| [decisions/adr-004-yaml-parser.md](decisions/adr-004-yaml-parser.md) | PyYAML on a hardened `SafeLoader`, why not ruamel, and the pywin32 dependency for the P4 permission check |
| [decisions/adr-005-vault-client.md](decisions/adr-005-vault-client.md) | The HTTP API directly, over `httpx`, not `hvac` — measured against a real Vault, why renewal doesn't change the answer, and what still binds OCI to its own SDK |
| [decisions/adr-006-optional-dependencies.md](decisions/adr-006-optional-dependencies.md) | Vendor clients are install extras: what base carries, why base opens no sockets, and what a configured-but-uninstalled backend does |
| [decisions/adr-007-vault-token-flag.md](decisions/adr-007-vault-token-flag.md) | `--vault-token-file` takes a path and `--vault-token` is refused; why a SecretRef cannot authenticate the store it lives in, and where the token chain merges |
| `../test/compose.yaml` | Test stack by tier: Vault (KV v1 + v2), PostgreSQL, Oracle Free/21c/18c/11g, an NNE-required Oracle, toxiproxy |
| `../test/capabilities.py` | Sketch of capability probing and the pytest skip markers |

All three schemas validate as Draft 2020-12, and the example validates against the
run schema. That is no longer an assertion in prose: `tests/test_schemas.py`
checks it, and CI runs it on every push and pull request (invariant 12).

To get completion and inline errors while editing a config, put
`# yaml-language-server: $schema=./sopuli-config-1.3.schema.json` on the file's
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
model and ADR-001's P7 revisit trigger is closed.)*

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

- **The `T:` (12C) verifier layout in `SYS.USER$.SPARE4`** (#90) — field order,
  salt length, iteration count, and whether a client library can reproduce the
  derivation. Fully open, cheap to settle against a throwaway 19c. Blocks
  `--method hash|both` only — `check`'s default (`login`) no longer waits on
  this (#86). If it does not reproduce reliably, `--method hash` is dropped
  from the CLI entirely.
- **Whether `SELECT_CATALOG_ROLE` via `SYS.KU$_USER_VIEW` exposes `LCOUNT`
  without `SPARE4`** (#124) — a narrower alternative to `SELECT ON SYS.USER$`
  for the `LCOUNT` guard, from a blog post rather than Oracle documentation.
  Affects what `sql/oracle/00_install.sql` recommends to sites that want the
  guard; nothing in the default path depends on it.
- **Whether `ALTER USER` text leaks the password** into `V$SQL`,
  `UNIFIED_AUDIT_TRAIL`, or trace files, per Oracle version — **partially
  answered.** On 26ai Free 23.26.2.0.0, in `CDB$ROOT` and a PDB, `V$SQL` retains no
  cursor for the DDL at all and unified audit masks it at write time in
  `AUDSYS.AUD$UNIFIED` as well as the view. The probe found one leak by
  measurement that reasoning had missed: an anonymous PL/SQL block carrying the
  password as a literal is retained verbatim, which is now invariant 13. Still
  open: 19c and 11.2, and the trace-file and `audit_file_dest` greps on every
  version. The probe is `sql/oracle/02_password_leak_probe.sql`; results are in the
  top-level README's gate-2 table.
- **Which view supplies `status`'s `DB_PW_CHANGED` column, per version** (#87)
  — `DBA_USERS.PASSWORD_CHANGE_DATE` is absent on 11.2, where the same value
  means reading `SYS.USER$.PTIME` instead, behind the same optional grant Q1/P2
  (#86) already made capability-probed rather than assumed. Purely a display
  question — Q9 decided `rotate --max-age-days` reads only the vault, so
  nothing gates on this — but `status` has no source for the column without it.
  Worth confirming on the 11g XE and 19c images alongside #90.
- **What a real Vault's compare-and-set conflict looks like on the wire** (#103,
  #104) — **answered.** Against `hashicorp/vault:2.0.4` dev mode: every lost
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
- **Which HashiCorp Vault client** (#103) — **decided in
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

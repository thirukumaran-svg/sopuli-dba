# sopuli-dba — design documentation

Sketch stage. Nothing here is implemented. The SQL has never been executed.

| Document | Contents |
|---|---|
| [design/00-principles.md](design/00-principles.md) | P1 multi-product DB support (Oracle first), P2 multi-vault support, P3 config file + precedence, P4 cross-platform, P5 cross-cutting behaviour and exit codes |
| [design/01-configuration.md](design/01-configuration.md) | YAML schema in two shapes (single application inline, `applications:` for several), the estate sections, target templating with labels, profiles (run context), environment variables, SecretRef syntax, password charsets, precedence |
| [design/02-oracle-privileges.md](design/02-oracle-privileges.md) | The grant model: direct `ALTER USER`, common vs per-PDB service accounts, client-side guardrails, auditing |
| [design/03-json-output.md](design/03-json-output.md) | The `--output json` / `--output jsonl` contract, redaction, stability policy, `jq` recipes |
| [design/04-testing.md](design/04-testing.md) | What can and cannot be containerised, capability-driven matrix, tiering, fault injection, release gates |
| [use-cases/uc-01-app-credential-sync.md](use-cases/uc-01-app-credential-sync.md) | UC-1: application DB account credentials, vault as master — `generate` / `apply` / `check` / `rotate` |
| [workflow.md](workflow.md) | Binding: branching (`issue-<n>-<slug>`, no long-lived integration branch), Conventional Commits, release-please and the 0.x policy |

## Machine-readable artefacts

| File | Purpose |
|---|---|
| [schemas/sopuli-config-1.0.schema.json](schemas/sopuli-config-1.0.schema.json) | JSON Schema (2020-12) for the config file (P3). Generated from the config layer by `python -m sopuli.config.schema` — never edited by hand |
| [schemas/sopuli-run-1.5.schema.json](schemas/sopuli-run-1.5.schema.json) | JSON Schema (2020-12) for the `--output json` document |
| [schemas/sopuli-event-1.0.schema.json](schemas/sopuli-event-1.0.schema.json) | JSON Schema for `--output jsonl` events |
| [schemas/example-creds-check-drift.json](schemas/example-creds-check-drift.json) | Worked example: a scheduled check finding drift in one of two PDBs |
| `../sql/oracle/00_install.sql` | Create and grant the service account — `NONCDB` / `COMMON` / `PDB` modes |
| `../sql/oracle/01_audit_policy.sql` | Unified audit policies, correlation queries, password-leak release-gate probes |
| `../sql/oracle/99_uninstall.sql` | Remove the account; keeps the audit policies by default |
| [decisions/adr-001-privilege-model.md](decisions/adr-001-privilege-model.md) | Why direct `ALTER USER`, what was rejected, and the two triggers for revisiting |
| [decisions/adr-003-text-tables.md](decisions/adr-003-text-tables.md) | No table library: columns formatted with click and the standard library, and why output must not depend on the terminal |
| [decisions/adr-004-yaml-parser.md](decisions/adr-004-yaml-parser.md) | PyYAML on a hardened `SafeLoader`, why not ruamel, and the pywin32 dependency for the P4 permission check |
| `../test/compose.yaml` | Test stack by tier: Vault (KV v1 + v2), PostgreSQL, Oracle Free/21c/18c/11g, an NNE-required Oracle, toxiproxy |
| `../test/capabilities.py` | Sketch of capability probing and the pytest skip markers |

All three schemas validate as Draft 2020-12, and the example validates against the
run schema. That is no longer an assertion in prose: `tests/test_schemas.py`
checks it, and CI runs it on every push and pull request (invariant 12).

To get completion and inline errors while editing a config, put
`# yaml-language-server: $schema=./sopuli-config-1.0.schema.json` on the file's
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
stays in scope, unreachable from Apple Silicon (D7).

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
proposed no), a built-in `interactive` profile (C12, leaning no), **whether `vault:`
under `defaults`/`profiles` is a name or a block (C13, issue #31 — the loader
refuses the block form)**, ~~the `@version=` and `@stage=` vocabularies in a
SecretRef and who owns them~~ (C14 — **decided in #40: the tool owns both.**
`stage` is `current` / `pending` / `previous`, any case in, lower case out;
`version` is a whole number from 1; neither may hold a `{token}`. OCI's rotation
states turned out to be a fixed Oracle-defined set rather than user-definable
labels, so there was no backend vocabulary to defer to and the run schema is
ratified as written).

**Oracle privileges (02):** common `C##` service user or per-PDB local as the
documented default (P1), grant `SELECT ON SYS.USER$` by default (P2), whether
`--force` exists (P3), one service account per database or per application (P4),
does `doctor` fail or warn on over-granted privileges (P5), keep 11.2 support
(P6), **do 23ai schema privileges cover `ALTER USER` (P7 — to be tested on
26ai; a yes would narrow the whole privilege model)**.

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

**UC-1:** default verification method and the privilege it implies (Q1),
~~where the advisory lock lives~~ (Q2 — **decided in #83: in the vault**, one
CAS-guarded record per *secret path*, with a fencing token re-checked before
every mutation. `DBMS_LOCK` was rejected: its one advantage is release on session
death, and a stalled session is still alive, so it does not prevent the failure
that matters — a run waking from a stall and applying a stale plan. Fencing does,
and it costs no widened grant set. Stores without `cas` refuse mutations unless
configured `locking: advisory-only`), ~~how many `previous` generations to keep~~ (Q3 —
**decided in #84: exactly one**, plus whatever the store's native versioning
gives for free. C14 settled it: OCI holds exactly one `PREVIOUS`, and a closed
three-stage vocabulary has nothing to address an older generation with),
whether the tool ever alters a profile (Q4), drift notification (Q5),
self-rotation mode (Q6), one-secret-per-account vs one-secret-per-app (Q7),
account creation scope (Q8), authoritative time source for password age (Q9).

### Settled

**The privilege model is direct `ALTER USER`.** The definer-rights package was
drafted and rejected: the operator is a DBA who already holds SYSDBA, so the
package constrains someone who is not actually constrained, while adding a
per-PDB install, a second whitelist to keep in sync with the tool's config, and
version skew as a new failure mode. Recorded in
[ADR-001](decisions/adr-001-privilege-model.md), which also names the two
triggers for revisiting: an unattended scheduled runner, or P7 turning out
positive.

### Settle these next

1. **Q1 + P2** — whether `SELECT ON SYS.USER$` is granted by default. It enables
   `check --method hash` and, more importantly, the `LCOUNT` guard that stops
   scheduled checks from locking production accounts. With `ALTER USER` already
   granted, the verifier exposure is a smaller concern than it was.
2. **C1–C6** — the configuration questions, since the YAML schema is the next
   thing that becomes code.
*(T1 was here and is now answered: the image exists, 11.2 support costs nothing.
Q2 was here too and is answered in #83: the lock lives in the vault, keyed on the
secret path, fenced by the vault's own version counter. Building it is #94–#97.)*

## Verify before implementing

Two things are asserted with less confidence than the rest, and both are cheap to
settle against a throwaway 19c:

- **The `T:` (12C) verifier layout in `SYS.USER$.SPARE4`** — field order, salt
  length, iteration count, and whether a client library can reproduce the
  derivation. If it does not reproduce reliably, drop `--method hash` and rely on
  `--method login` with the `LCOUNT` guard.
- **Whether `ALTER USER` text leaks the password** into `V$SQL`,
  `UNIFIED_AUDIT_TRAIL`, or trace files, per Oracle version. This matters more
  under the direct model than it did under the package. The probe queries are in
  `sql/oracle/01_audit_policy.sql` §3; whatever they find goes in the README.

## Likely next use cases

- UC-2 — personal developer/tester account passwords (different lifecycle,
  different lockout tolerance, self-service angle)
- UC-3 — account provisioning: create/drop users, grants, roles, profiles
- UC-4 — drift and compliance reporting across a fleet
- UC-1b — self-rotation mode (`IDENTIFIED BY … REPLACE`) where no admin
  credential is available

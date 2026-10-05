# Copilot instructions for sopuli-dba

## Read the specification first

`docs/design/00-principles.md` is binding for every change. Read the applicable
document before changing behaviour:

| Change area | Read first |
| --- | --- |
| Configuration, targets, applications, SecretRefs, password policies | `docs/design/01-configuration.md` |
| Oracle SQL or privileges | `docs/design/02-oracle-privileges.md` |
| CLI text, JSON, JSONL, or result shapes | `docs/design/03-json-output.md` |
| Tests or the test stack | `docs/design/04-testing.md` |
| Credential synchronization and rotation | `docs/use-cases/uc-01-app-credential-sync.md` |
| Personal accounts, password reset, delivery methods | `docs/use-cases/uc-02-personal-account-passwords.md` |
| A result measured on an Oracle release | `docs/measurements.md` |
| Oracle grants, or a definer-rights package | `docs/decisions/adr-001-privilege-model.md` (the package was rejected) |
| A flag or input that carries a secret | `docs/decisions/adr-007-vault-token-flag.md` (secrets never go in argv; a flag takes a path) |
| Dependencies or vendor clients | `docs/decisions/adr-005-vault-client.md` and `docs/decisions/adr-006-optional-dependencies.md` |
| Commands, flags, exit codes, or operator-facing messages | `docs/local-testing.md` |

Do not resolve an open decision marked in the design documents. Open decisions
are collected in `docs/README.md` and tracked as `decision` issues; stop and
surface the required decision instead.

`CLAUDE.md` is the repository-wide working agreement despite its name. Its
invariants apply to every assistant and contributor. `CONTRIBUTING.md` adds
setup, documentation, testing, DCO, provenance, and PR requirements.

## Commands

Use Python 3.11+ and install the editable development environment:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev,all]"
```

Tier 0 is pure logic and must not need network access or containers:

```powershell
ruff check .
ruff format --check .
mypy
pytest
```

Run a focused test with its node selector, for example:

```powershell
pytest tests\config\test_loading.py::test_a_minimal_document_loads
pytest tests\driver\test_oracle_statements.py -k password
```

For changes that read from or write to Oracle or Vault, run the Tier 1 stack
and exercise the affected command end to end; then capture real output in
`docs/local-testing.md` when its surface changes:

```powershell
Set-Location test
docker compose --profile tier1 up -d
Set-Location ..
pytest
```

All compose services use profiles, so stop them with
`docker compose --profile '*' down`. Tier 2 and 3 environments are
maintainer pre-release coverage; unavailable capabilities must skip with a
reason, not fail. Never branch on an Oracle version: probe and use capabilities.

## Architecture

The project is a Click noun-verb CLI (`src/sopuli/cli.py`) for keeping database
accounts synchronized with a vault, where vault-to-database is always the
direction of truth.

1. `sopuli.invocation` is the execution boundary. It resolves CLI/environment
   settings, opens the run document before config loading, loads and validates
   layered config, resolves final settings, and passes each command an
   `Invocation`. Commands must use `run.config` and resolved settings rather
   than reload config or read raw global flags.
2. `sopuli.config` parses hardened YAML, validates it into typed models, applies
   profile/vault layers, expands target sets, and filters the declared estate.
   Keep this layer pure: it does no socket I/O. Config is a whitelist; selectors
   can only narrow declared accounts and targets.
3. Command modules such as `apply.py`, `rotate.py`, `check.py`, and
   `suspend.py` calculate plans and coordinate safety, locking, stores, and
   drivers. Mutating commands print a plan and support `--dry-run`.
4. `sopuli.driver.protocol` and `sopuli.store.protocol` are the vendor seams.
   Registries resolve configured backends lazily; vendor dependencies remain
   extras. Oracle implementation belongs under `driver/oracle`; HashiCorp Vault
   implementation belongs under `store/hashicorp` and uses `httpx`, not `hvac`.
5. `sopuli.output` owns user-facing views and serialization. `RunDocument` is
   the one JSON run record; `emit.py` emits it, while command-specific
   `*_view.py` modules create text and structured result views. JSON schemas in
   `docs/schemas/` are a versioned public contract.

## Repository conventions

- Treat values that could authenticate or retrieve credentials as `Secret`.
  `str()`, `repr()`, formatting, and JSON serialization redact them. Do not
  introduce ad hoc masking or new `reveal()` sites. Secrets never appear in
  argv; inputs use stdin, files, or configured vault references.
- Do not put vendor SQL in command modules. Database operations go through the
  driver protocol; cache capability observations per session and reject missing
  required capabilities at plan time with the target and capability named.
  Password DDL is direct `ALTER USER`, never a PL/SQL wrapper, and a password
  must never be bound in a SQL predicate.
- Preserve synchronization ordering: stage as `pending`, update and verify every
  database target, then promote to `current`. A convergent rerun reports
  `changed: false` and emits no mutation audit record. Fresh-password commands
  are intentionally non-convergent.
- Safety settings only become stricter as config layers are resolved. Safety
  booleans, target limits, confirmations, and allowed delivery methods use the
  setting registry/resolver rather than local precedence code.
- Keep optional backend imports lazy. The base package must not open sockets or
  require an Oracle/Vault client for offline config commands. Missing backend
  clients are structured, actionable errors rather than import failures.
- Preserve the output contract. Add fields as a minor schema-version change;
  rename or remove fields only as a major change. Update the matching schema and
  samples/tests whenever JSON output changes. Omit unavailable optional document
  sections rather than emitting `null`.
- Configuration keys and accepted CLI inputs must either work or fail
  explicitly; never accept and silently ignore one. Config files are strict:
  unknown keys are errors.
- Behaviour changes update the relevant design document and
  `docs/local-testing.md`. Use the repository's fictional examples only:
  `acme`, `acme_*_user`, `alpha` through `theta`, `example.com`, and
  `192.0.2.0/24`; do not add real-system identifiers or material.

## Writing documentation and comments

`CONTRIBUTING.md`, section "Writing documentation and comments", has the rules
and is authoritative. This is a summary, kept because the reviewer cannot follow
the link. Apply the rules to new and changed text, and flag a change that breaks
them:

- Plain English: short sentences, common words, active voice, no idioms or
  rhetorical framing. Many readers are not native English speakers.
- Present tense, describing the current build. No "until #N", no "this used to
  say", no change dates. History belongs in commits, PRs and `CHANGELOG.md`.
- Keep the reason, and the rejected options, wherever a rule could look like a
  mistake. Do not suggest removing one.
- One home for each fact; link to it elsewhere instead of restating it.
- No counts and no "the only" unless a test checks them.
- Cite an issue once, as provenance ("decided in #N"), or as a pending-work
  marker: `(open: #N)` in Markdown, `TODO(#N)` in code. Never as narration. The
  reason itself is always written in the repository.
- Comments say what the code does and why, not which issue changed it. Module
  docstrings stay short.

## Change and review requirements

One GitHub issue maps to one reviewable PR; discuss a change that will exceed
roughly 400 lines before implementing it. Use imperative Conventional Commit
subjects that reference the issue, sign commits with `git commit -s`, and do not
manually update the release-managed project version. Every PR gets one
review, from Copilot or from Claude Code, and every review comment needs an
explicit PR reply explaining the change or reason for declining it. A second
review is requested only when the fixes are large.

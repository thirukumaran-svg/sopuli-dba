# sopuli-dba — Common Design Principles

Status: draft / sketch
Applies to: all commands and use cases

These principles are binding on every feature. A use case document may refine them
but must not contradict them.

---

## P1. Multi-product database support, Oracle first

### The rule

Every operation that touches a database goes through a **driver interface**. No
command contains vendor SQL. Oracle is the first and only implemented driver;
its shape must not leak into the interface.

### Driver interface (conceptual)

```
Driver
  connect(target, credential) -> Session
  capabilities() -> CapabilitySet
  resolve_scope(target) -> Scope          # CDB root / PDB / schema-only
  user_exists(session, account) -> bool
  describe_user(session, account) -> UserState
  set_password(session, account, secret, opts) -> ChangeResult
  verify_password(session|offline, account, secret) -> VerifyResult
  apply_attributes(session, account, attrs) -> ChangeResult
```

### Capability negotiation

Drivers do not pretend to support what they cannot. Each driver reports a
capability set, and commands degrade or refuse explicitly rather than silently.

| Capability | Meaning | Oracle |
|---|---|---|
| `container_scope` | Target can be a CDB root / PDB / ALL containers | 12.1+ multitenant only |
| `common_users` | `C##`-prefixed users created with `CONTAINER=ALL` | 12.1+ CDB |
| `password_rollover` | Two passwords valid during a grace window | 19.12+ / 21c+ |
| `offline_verify` | Password verifiable against a stored hash without a login | needs `SYS.USER$` read |
| `profile_management` | Tool can read/alter password profile parameters | yes |
| `password_reuse_policy` | Server may reject a generated password | yes (`PASSWORD_REUSE_*`, verify function) |
| `expire_password` | Force expiry / end rollover | yes |
| `account_lock_state` | Read and set lock state | yes |

A command that needs a capability the target lacks must fail with a distinct exit
code and a message naming the capability and the target — never a generic error.

### Oracle variants that must all work

- **Single-instance non-CDB** (11.2, 12.1 non-CDB, 19c non-CDB)
- **CDB root** — common users (`C##APP_OWNER`), `CONTAINER=ALL` vs `CONTAINER=CURRENT`
- **PDB** — local users, connected via service name; the same local username may
  exist independently in many PDBs
- **Application containers** (application root + application PDBs) — a distinct
  scope, not the same as CDB root
- **Autonomous / OCI-hosted** — Native Network Encryption forces a thick-mode
  client (python-oracledb thick / godror). This is a runtime prerequisite, not a
  configuration option.
- **RAC / Data Guard** — connect via service, not SID; on a physical standby the
  driver must detect `OPEN MODE = READ ONLY` and refuse write operations up front
  rather than failing mid-statement.

### Version-dependent behaviour to detect at runtime, never assume

- Max password length: 30 bytes (< 12.2) vs 128 bytes (12.2+)
- Password verifiers present (`DBA_USERS.PASSWORD_VERSIONS`: 10G/11G/12C) and
  `SQLNET.ALLOWED_LOGON_VERSION_SERVER` — a generated password longer than 30
  bytes silently breaks clients still relying on 10G/11G verifiers
- Case sensitivity (`SEC_CASE_SENSITIVE_LOGON`, removed in 12.2+)
- Gradual password rollover availability
- Unified vs traditional auditing

The tool queries version and capabilities on connect and caches the result per
session. It never branches on a version number typed into config.

**Client reach is a separate constraint from server support.** Per Oracle's
client/server interoperability matrix, a 23.x client supports servers from 19c
onward; reaching an 11.2 server needs a 19.x client. Since Instant Client for
macOS ARM64 exists only in 23.x, an 11.2 target cannot be reached from an
Apple Silicon machine at all. `sopuli doctor` reports the installed client
version and warns when a configured target is out of its reach, rather than
letting the connection fail with a bare ORA error.

### Adding a second product later

Intended order after Oracle: PostgreSQL, SQL Server, MySQL. Nothing in the config
schema, CLI grammar, or vault layout may be Oracle-specific at the top level.
Vendor-specific settings live in a namespaced block:

```yaml
targets:
  - name: prod-appdb
    type: oracle          # driver selector
    oracle:               # vendor-specific block, validated by the driver
      container: PDB1
```

---

## P2. Multi-vault support

### The rule

Vaults are pluggable behind a **secret store interface**. A secret is addressed by
a *SecretRef* that is uniform across backends; only the resolution of that ref is
backend-specific.

```
SecretStore
  read(ref) -> SecretValue + metadata(version, created, custom)
  write(ref, value, cas, opts) -> version
  metadata(path) -> PathMetadata | none
  list(prefix) -> [ref]
  supports() -> StoreCapabilitySet
  health() -> ok | degraded | unreachable
```

Two of those arrived with the advisory lock (#83, #96) and were not in the
original sketch. **`write` takes a compare-and-set version and returns the new
one**, because that returned version is the lock's fencing token — a write that
only said "ok" would leave the design with nothing to fence with. **`metadata`
reads what a store knows about a path apart from its contents**, so pre-flight
can check that a lock path is not configured to accept writes without a CAS: a
guarantee the tool cannot check is one it should not claim. The slice the lock
uses is `sopuli/store/protocol.py`; the rest arrives with the first real backend.

### Backends in scope

| Backend | Priority | Notes |
|---|---|---|
| HashiCorp Vault KV v2 | 1 | versioning, CAS, soft delete — the reference implementation |
| HashiCorp Vault KV v1 | 2 | no versioning → rollback and staging degrade to emulation |
| OCI Vault / Secrets | 2 | secret bundles with version *stages* (CURRENT/PENDING/PREVIOUS) map cleanly onto rotation |
| File backend (age/gpg-encrypted) | 3 | local dev and CI fixtures; must be obviously non-production |
| OS keyring | 4 | personal / workstation use |
| AWS Secrets Manager, Azure Key Vault | later | AWSSM's AWSCURRENT/AWSPENDING is the same shape as OCI |

### Store capability negotiation

| Capability | HCV KV v2 | HCV KV v1 | OCI | File |
|---|---|---|---|---|
| `versioning` | yes | no | yes | optional |
| `cas` (compare-and-set) | yes | no | via ETag | no |
| `staging_labels` | emulated in payload | emulated | native | emulated |
| `structured_value` (JSON inside a secret) | yes | yes | yes (base64 content) | yes |
| `soft_delete` / undelete | yes | no | yes | no |

Where a capability is missing the tool **emulates it in the secret payload**
(explicit `current` / `pending` / `previous` fields) rather than pretending the
guarantee exists. Emulation is not atomic; commands must say so in dry-run output.

**`cas` is the one capability that cannot be emulated**, since "not atomic" is
precisely what it is for. A store without it therefore gets no lock rather than a
weaker one: P5's advisory lock refuses on KV v1 and the file backend unless that
store is explicitly configured down to `locking: advisory-only`, where the record
is written without CAS and every run says so (issue #83, `01-configuration.md`
§3a).

### Authenticating to the vault

Vault auth is configuration too, and must cover at least:

- token (`VAULT_TOKEN`, token file, token helper)
- AppRole (role_id + secret_id, secret_id from file or env)
- Kubernetes / OIDC / userpass where the backend supports it
- OCI: instance principal, resource principal, config-file profile, session token

Auth material is never written to the config file in plaintext; the config points
at *where* the material comes from. See `01-configuration.md`.

### Bootstrap / chicken-and-egg

The DBA credential the tool uses to reach the database is itself a secret.
Sources, in order of preference:

1. External authentication — Oracle Wallet / secure external password store,
   Kerberos, OS authentication
2. A vault path (vault authenticated by machine identity, not by a password)
3. Interactive prompt
4. Environment variable — supported, but flagged in output as low-assurance

Storing the admin password in the config file is not supported at all.

---

## P3. Structured configuration file with documented precedence

### The rule

All targets, vaults, groups, policies and defaults live in a YAML file. Command
options and environment variables may override a documented subset. **Exactly one
precedence order applies everywhere**, and the tool can print it.

### Precedence (highest wins)

```
1. Command-line option              --vault-addr https://…
2. Environment variable             SOPULI_VAULT_ADDR
3. Profile block in config          profiles.ci.vaults.hcv-prod.addr
4. Target/vault-level setting       vaults.hcv-prod.addr
5. Top-level defaults in config     defaults.vaults.hcv-prod.addr
6. Built-in default                 (compiled into the tool)
```

Layers 3 to 5 all name the store, because **`vault:` is a store name everywhere
in the config and never a block** — the same word `SOPULI_VAULT` and a SecretRef's
`[<vault>:]` prefix already use, with `SOPULI_VAULT__HCV_PROD__ADDR` as the
environment form of the same addressing. Settings *of* a store are therefore
written under `vaults:` keyed by its name, which `defaults:` and a profile may
each carry as a partial entry. C13, decided in #31; `01-configuration.md` §3a
and §5 are the specification.

A profile is named after **how the run was invoked** — `interactive`, `ci`,
`scheduled` — never after an environment. `--profile prod` reads like a target
selector and is not one; profiles change behaviour, never scope.
`01-configuration.md` §5 is the specification, and validation warns on a profile
named after any target's `environment`.

Rationale for env above config: config files are committed and shared; env is set
per execution context (CI job, container) and must be able to redirect a shared
config without editing it. Rationale for CLI above env: the operator typing the
command expresses the most specific intent available.

**Layer 1 is one layer.** A CLI parser that accepts a flag both before and after
the subcommand does not thereby create two layers: it is the same person, in the
same command line, at the same moment, so there is no authority to rank. Both
positions resolve as `cli` and the position, where it matters, is recorded in
`source_detail`. Safety flags are accepted in the trailing position only, so no
group-position value ever reaches the resolver — see `adr-002-cli-framework.md`.

Two deliberate exceptions, documented as such:

- **Third-party env vars** (`VAULT_ADDR`, `VAULT_TOKEN`, `ORACLE_HOME`,
  `TNS_ADMIN`, `OCI_CLI_PROFILE`) are honoured but rank *below* the `SOPULI_*`
  equivalent, so `SOPULI_VAULT_ADDR` beats `VAULT_ADDR`.
- **Safety settings only ratchet toward safe.** `--dry-run`, `--confirm`,
  `--max-targets` and `readonly: true` cannot be relaxed by any source. If config
  says `readonly: true`, no command-line flag re-enables writes.

### Making precedence debuggable

`sopuli config show --explain` prints every effective setting with the layer it
came from:

```
vault.addr         = https://vault.example.com:8200   [env SOPULI_VAULT_ADDR]
vault.auth.method  = approle                          [config vaults.hcv-prod]
verify.method      = hash                             [profile ci]
db.timeout_s       = 30                               [built-in default]
targets            = 4 targets from group "prod-pdbs" [cli --group]
safety.max_targets = 1                                [defaults]
                     ↑ profile ci asked for 200; safety only ratchets toward safe
```

Secret values are always redacted here. Anything resolved from a source the tool
considers low-assurance is marked.

The `safety.max_targets` line is the one worth being able to see. A setting that
was *requested* and did not win is invisible in the result and obvious in this
view, which is the difference between "the ratchet works" as a claim and as
something an operator can check. It also reaches `--output json`: the same
defeated request is a warning in `diagnostics[]`, on every run rather than only
when `--explain` was asked for.

**`--explain` does not require `--resolved`**, although the example above was
once written with both. Where a setting came from is the same answer in the
declared view and the resolved one, because provenance does not depend on target
expansion — unlike `--select`, which has nothing to filter until the estate
exists. In `--output json` it widens `invocation.options` to include settings
answered by a built-in default, which the document otherwise omits as not having
changed behaviour. One producer, one shape, two questions about how much of it to
show. Implemented in `sopuli/output/explain_view.py`.

### Config file discovery

First match wins; `--config` may be repeated to layer files:

1. `--config PATH` (repeatable; later files override earlier ones)
2. `SOPULI_CONFIG`
3. `./sopuli.yaml`
4. `$XDG_CONFIG_HOME/sopuli/config.yaml` → `~/.config/sopuli/config.yaml` (Linux/macOS)
   / `%APPDATA%\sopuli\config.yaml` (Windows)
5. `/etc/sopuli/config.yaml` (Linux/macOS) / `%PROGRAMDATA%\sopuli\config.yaml` (Windows)

**A path that was named behaves differently from one that was searched.** Steps 1
and 2 name a file, and a named file that is missing is an error — never a reason
to try step 3. A CI job whose `SOPULI_CONFIG` has a typo must not quietly run
against the system config instead; that is the whole estate read from a file
nobody chose. Steps 3 to 5 are searched, so an absent one is skipped, which is
what "first match wins" means. An empty `SOPULI_CONFIG` counts as unset, and a
Windows location whose variable is unset is left out rather than guessed at.

Finding nothing at all is an error listing everywhere it looked. A command with
no config has no whitelist, and invariant 5 makes that the one thing it cannot
proceed without. Implemented in `sopuli/config/discovery.py`.

Config files are validated against a published JSON Schema. `sopuli config
validate` is a first-class command and exits non-zero on unknown keys — a typo in
a credential tool must never be silently ignored.

The schema is `docs/schemas/sopuli-config-1.1.schema.json`, generated from the
config layer by `sopuli/config/schema.py` so that it cannot drift from what the
tool actually accepts. It is structural: an editor pointed at it catches the
typo, and the cross-key rules stay in the validators, where an error can name the
key. `01-configuration.md` §9b lists which rules fall on which side.

---

## P4. Cross-platform: Linux, Windows, macOS

### The rule

**Linux and Windows are supported tiers. macOS is best-effort and untested** —
the code stays portable, the README claims nothing, and there is no macOS CI.
Nothing may assume a POSIX-only primitive without a documented Windows
equivalent.

| Concern | Linux/macOS | Windows |
|---|---|---|
| Config path | XDG / `/etc/sopuli` | `%APPDATA%` / `%PROGRAMDATA%` |
| Config permission check | refuse on any `0o077` bit — group/world access of any kind, not only read | walk the DACL; refuse any ACE granting read *or write* to a SID outside {owner, `OWNER RIGHTS`, `CREATOR OWNER`, `SYSTEM`, `Administrators`} |
| Secret in memory | best-effort zeroing, documented as best-effort | same |
| Path handling | never string-concatenate paths | same |
| Line endings | write LF, read LF/CRLF | same |
| Stream encoding | UTF-8 on stdin/stdout/stderr, forced at startup | same — a *redirected* stream otherwise uses the locale codepage |
| Keyring | Secret Service / libsecret; macOS Keychain | Credential Manager / DPAPI |
| Oracle client | Instant Client + `LD_LIBRARY_PATH` | Instant Client on `PATH` + VC++ redistributable |
| Terminal | ANSI colour, off when not a TTY or `NO_COLOR` | same, with VT mode enabled; plain fallback |
| Exit codes | identical numeric set on all platforms | same |

The stream encoding row is the one that has actually bitten. On Windows an
attached console is UTF-8, but a *redirected* stream falls back to the locale
codepage — and redirection is how a scheduled run is captured
(`sopuli creds check > nightly.log`). Under cp1252 an em dash reaches a UTF-8
reader as mojibake, and anything outside the codepage — box drawing, a check
mark, an arrow — raises `UnicodeEncodeError` and kills the command mid-write.
The tool therefore forces UTF-8 on all three standard streams at startup, before
any argument parsing, so that a usage error is written correctly too. stdin is
included because the failure there is the quiet one: a password read under
cp1252 becomes a *different* password with no error at all, surfacing much later
as an authentication failure.

Because Instant Client is required at runtime on every platform, packaging is
"install the client, then install sopuli" regardless of implementation language.
`sopuli doctor` checks client presence and version, `TNS_ADMIN`, wallet
readability, vault reachability and clock skew, and prints a per-platform
remediation hint.

### Why macOS is best-effort rather than supported or excluded (D5)

The obvious blocker turned out not to exist. Oracle ships **Instant Client for
macOS ARM64** — 23.26.x, notarized DMGs, with SQL\*Plus and the OCI libraries —
so thick-mode drivers work on Apple Silicon. Intel macOS has its own 19.x line.
Thin mode remains unusable for this tool on every platform, since python-oracledb
still does not support Native Network Encryption in thin mode, but that is not a
macOS-specific problem.

What actually argues against a supported tier:

- **You cannot run an Oracle database on macOS.** There has been no macOS server
  build since 10g, and Oracle's container images are `linux/amd64` only — under
  emulation on Apple Silicon they are unsupported and unreliable. A macOS
  developer or CI runner therefore cannot run the integration suite locally; it
  needs a remote database. That is the real cost, and it is a testing-
  infrastructure cost rather than a code cost.
- **Apple Silicon cannot reach an 11.2 database.** Only the 23.x client exists
  for ARM64, and a 23 client supports 19c and later. Intel macOS keeps a 19.x
  client that does reach 11.2, but Intel Macs are on their way out.
- **No evidence of demand.** There is no DBA-specific OS survey. The Stack
  Overflow 2024 figures (Windows 47.6%, Linux 40%, macOS 31.8%, professional,
  multi-select) describe a population skewed toward web and application
  developers, and cannot be read across to DBAs.

What argues against *excluding* it: in Python there is essentially no
macOS-specific code. Path handling, `NO_COLOR`, and the keyring backend are
abstractions Windows already forces. Excluding macOS would save nothing and would
have to be undone the first time someone asks.

So: keep the code portable, keep macOS out of the README's support statement,
run no macOS CI, and revisit only if a real user turns up. If one does, the first
question is where their test database lives.

---

## P5. Cross-cutting behaviours (every command)

**Safety**

- Every mutating command supports `--dry-run` and prints the exact plan, redacted.
- Every mutating command supports `--confirm`/`--yes`; interactive confirmation is
  required by default when blast radius exceeds `max_targets` (default 1) or the
  target is marked `environment: prod`.
- `--limit`/`--max-targets` prevents a wildcard from hitting 200 PDBs by accident.
- Mutating operations take an advisory **lock** keyed on the secret path being
  mutated, so two operators or two CI jobs cannot rotate the same credential
  concurrently. The lock lives in the vault, is compare-and-set guarded, and
  carries a fencing token that is re-checked before every mutation (Q2, decided
  in issue #83). This bullet said "account+target" until then; neither half was
  right. Per-target is meaningless when every target receives the same value, and
  per-account misses two accounts sharing one document. The mutated resource is
  the vault document, and compare-and-set operates on exactly that.
  `check`, `status` and every `--dry-run` take no lock at all — otherwise an
  hourly scheduled check blocks rotations.

**Idempotency**

Running a command twice must not make things worse. `apply` against an
already-correct state is a no-op reporting `unchanged`. This is what makes the
tool safe to run from a scheduler.

**Observability**

- Human output by default; `--output json` for one machine-readable object,
  `--output jsonl` to stream per-target events. Scripts consume JSON, never text.
- One structured audit record per mutation: who (OS user + vault identity), what
  (account, target, operation), when, correlation id, result. Never the secret.
- `--log-level`, optional log file, and an explicit statement in the docs that
  secrets are redacted from all output including tracebacks.

**Secret hygiene**

- Secrets are never passed as command-line arguments (visible in `ps` and in the
  Windows process list). They come from stdin, a file, or a vault ref.
- Never written to temp files, never logged, never in exception messages.
  Redaction is applied at the output sink, not hopefully at each call site.
- On Oracle the tool must document that `ALTER USER ... IDENTIFIED BY` text can
  reach SQL trace, `V$SQL` and some audit paths, and what it does to minimise it.

**Exit codes** (draft)

| Code | Meaning |
|---|---|
| 0 | success — changes applied, or nothing to do |
| 1 | generic failure |
| 2 | usage error — argv did not resolve to a valid command and options |
| 3 | drift detected (`check` found a mismatch) — distinct so schedulers can alert |
| 4 | partial success (some targets succeeded, some failed) |
| 5 | capability not supported by target/driver |
| 6 | authentication failure (vault or database) |
| 7 | lock held by another process |
| 8 | aborted by user / confirmation declined |
| 9 | configuration invalid — missing, unreadable, or refused by validation |

**2 and 9 are deliberately not the same code.** They were, until J7 (issue #8)
needed them on opposite sides of one seam: a usage error has no invocation, an
invalid config has a perfectly good one. That is what decides whether a run
document exists — see `03-json-output.md` §6 — and "empty stdout plus exit 2" is
only a usable rule for a consumer if exit 2 never carries one.

It also reads better for the operator. Exit 2 means *fix your command line*;
exit 9 means *fix your config file*. Different people, different moments: one is
somebody typing, the other is a deployed artefact a scheduler is running.

---

## Decisions

| # | Question | Decision | Status |
|---|---|---|---|
| D1 | Binary name | `sopuli` (project `sopuli-dba`) | decided |
| D2 | CLI grammar | noun-verb: `sopuli creds rotate`, `sopuli target list` | decided |
| D3 | Implementation language | Python with python-oracledb in thick mode. Thin mode cannot be used: it still does not support Native Network Encryption, which OCI-hosted databases require. Since Instant Client is therefore mandatory at runtime, Go's single-binary advantage does not apply, and Python's readability matters more for reviewing AI-assisted code. | decided |
| D4 | Config format | YAML only; JSON accepted since it is valid YAML | decided |
| D5 | macOS tier | Best-effort and untested: portable code, no support claim, no macOS CI. See the rationale under P4 — the blocker is the absence of a local Oracle database for testing, not the client, which now exists for Apple Silicon. | decided |
| D6 | Plugin model for drivers/stores | in-tree first; entry-point plugin API only after a second driver exists | decided |
| D7 | Minimum Oracle version | 11.2 stays in scope, and testing it is cheap: `gvenzl/oracle-xe:11.2.0.2-slim` pulls freely and starts in seconds, so 11.2 is a tier-2 compose service rather than maintainer-only (T1, resolved 2026-08-08). Two independent caveats on Apple Silicon: it has only the 23.x client, which reaches 19c and later, and the 11g XE image is published for linux/amd64 only. Intel macOS, Linux and Windows all have a 19.x client that reaches it. | decided |
| D8 | CLI framework | click. The grammar (D2) and exit code 2 on usage errors are equally easy in argparse; the deciding factors were `click.testing.CliRunner`, which keeps tier-0 CLI tests in-process and I/O-free, and a real exception hierarchy to hang error mapping on. See `../decisions/adr-002-cli-framework.md`. | decided |

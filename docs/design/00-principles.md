# sopuli-dba — Common Design Principles

Applies to: all commands and use cases

These principles are binding on every feature. A use case document may refine them
but must not contradict them.

---

## P1. Multi-product database support, Oracle first

### The rule

Every operation that touches a database goes through a **driver interface**. No
command contains vendor SQL. Oracle is the first and only implemented driver;
its shape must not leak into the interface.

### Driver interface

The interface is `sopuli/driver/protocol.py`. This sketch lists its methods:

<!-- checked-list: driver-protocol -->
```
Driver
  connect(target, credential) -> Session

Session
  scope() -> Scope                              # what this connection is, and what it may do
  describe_user(account) -> UserState | None
  set_password(account, secret) -> ChangeResult
  suspend_account(account) -> AccountChange     # UC-2: lock an account on purpose
  reset_password(account, secret, expire, keep_rollover) -> AccountChange[]   # UC-2 §4.1
  expire_password(account) -> AccountChange[]   # UC-2: change at next logon
  require_no_rollover_window(account) -> None   # refuses, or returns
  audit_coverage(account) -> AuditCoverage      # UC-2 §1: never raises
  apply_attributes(account, attributes) -> AttributeChange[]   # UC-1 §5
  resolve_profile(profile) -> str | None        # how this database spells it, if it has it
  resolve_role(role) -> str | None
  accounts_matching(profile, role) -> str[]     # UC-2 §2 predicates
  verify_password(account, secret, method, lockout_margin, attempts) -> VerifyResult
  require_verifier(account, secret) -> None     # refuses, or returns
  require_rollover(account) -> None             # refuses, or returns
  finish_rollover(account) -> ChangeResult
  close()
```

The interface has this shape for these reasons:

- **The session carries the operations.** Capabilities are cached per session,
  because the PDBs of one estate can answer differently. A flat interface would
  need a cache keyed on a connection, and that is what a session object is.
- **`scope()` returns the capabilities and the container scope together.** Both
  are observed at one moment on one connection and cached together. The run
  document prints them as one `scope` object.
- **There is no `user_exists`.** A caller that asks whether an account exists
  then asks what state it is in. `describe_user` answers both, and returns `None`
  for an account that does not exist.
- **`apply_attributes` takes a typed `AccountAttributes`, one field per
  attribute, never a mapping.** A mapping would accept a misspelled key such as
  `container_clase`, do nothing, and report no error. `01-configuration.md` §10
  exists to prevent that failure.
- **`apply_attributes` returns one `AttributeChange` per attribute.** UC-1 §5
  reports each attribute as a separate change, so that the result says which
  attribute changed. `set_password` takes no attributes and returns one
  `ChangeResult`, because one result must not describe two changes.
- **`resolve_profile` and `resolve_role` return the name as the database spells
  it**, not a boolean. A quoted identifier is case-sensitive, and only the
  dictionary's spelling may reach a statement (`02-oracle-privileges.md` §4).
  UC-1 §8's pre-flight uses `resolve_profile` to check that a profile exists
  before anything is written.
- **A `require_*` method raises or returns nothing.** The tool calls it at plan
  time, before any account is changed, so a run that cannot be done fails before
  it starts (invariant 4). It raises instead of returning a value, so a caller
  cannot ignore the answer.
- **A method exists only when something calls it.** Each method is a demand on
  every driver, so the protocol does not declare a method that no verb uses.

`OracleDriver` in `sopuli/driver/oracle/session.py` implements the interface. It
is also the module the driver registry imports for `type: oracle`, so a missing
client is a structured error and not a traceback.

**The driver is an object, and `connect` takes only the target and the
credential.** The driver holds what belongs to the run: the environment, the
correlation id, the timeouts, and where Instant Client is. `connect` takes what
belongs to the target. A module function with extra keyword arguments would not
match `Driver`, and a caller written against `Driver` would get a `TypeError`.
`tests/driver/test_oracle_connect.py` asserts `isinstance(driver, Driver)`, so
the two stay the same.

The Oracle driver also follows these rules:

- **It finds Instant Client in a fixed order.** First
  `SOPULI_ORACLE_CLIENT_LIB_DIR` (`01-configuration.md` §6), then
  `runtime.oracle.client_lib_dir` from the file, then the platform's own loader
  (P4's table).
- **It initialises thick mode on the first connect, not at startup.**
  `init_oracle_client` is process-global and runs once. At startup it would fail
  earlier, but ADR-006 rule 3 says a base install loads no vendor client. An
  offline `config validate` must not load Instant Client for a database it never
  contacts, and must not fail on a machine where Instant Client is missing.
- **It opens one connection per target, and never shares a session with
  `SET CONTAINER`.** A CDB root and its PDBs are separate services. Sharing one
  session needs `ALTER SESSION SET CONTAINER`, which `02-oracle-privileges.md` §2
  lists as optional and avoids, to keep the grant set small. With one connection
  per target, a PDB that cannot be reached fails alone and does not affect the
  others.
- **It sets the correlation id on every session**, including a session that
  reads nothing. §5's `DBMS_SESSION.SET_IDENTIFIER` joins the tool's JSON, the
  database's audit trail and the vault's metadata. A session without the label
  appears in the audit trail and nobody can say which run it belonged to.

`Scope` is the run document's `scope` object without `labels`. Labels come from
the config, and a driver cannot observe them.

### Capability negotiation

Drivers do not pretend to support what they cannot. Each driver reports a
capability set, and commands degrade or refuse explicitly rather than silently.

| Capability | Meaning | Oracle |
|---|---|---|
| `common_users` | Session holds `ALTER USER` granted commonly, which is what altering a `C##` user with `CONTAINER=ALL` requires | 12.1+ CDB, and the grant made with `CONTAINER=ALL` |
| `password_rollover` | Two passwords valid during a grace window | 19.12+ / 21c+ |
| `offline_verify` | Password verifiable against a stored hash without a login | needs `SYS.USER$` read |
| `profile_management` | Tool can read/alter password profile parameters | yes |
| `password_reuse_policy` | Server may reject a generated password | yes (`PASSWORD_REUSE_*`, verify function) |
| `expire_password` | Force expiry / end rollover | yes |
| `account_lock_state` | Read and set lock state | yes |
| `role_lookup` | Which roles exist can be read, so a `role:` predicate naming no role is told apart from one matching nobody (UC-2 §2) | `SELECT ON SYS.DBA_ROLES`, in `02-oracle-privileges.md` §2's grant set |

A command that needs a capability the target lacks must fail with a distinct exit
code and a message naming the capability and the target — never a generic error.

**A capability is what the session may do. Where the session is connected is
`scope.type`.** They are separate facts. A root session that lacks the common
grant and a PDB session that holds it are different failures. Oracle returns
different codes for them (`ORA-01031` and `ORA-65040`), and only one of them is
fixed by a grant. `scope.type` already says `non_cdb`, `cdb_root` or `pdb`, read
on the same connection at the same moment. A capability that repeated it would be
a second place for the same fact to disagree. For the same reason,
`offline_verify_available` is `supports(offline_verify)` and not a separate field.

**A capability that cannot be determined is not a capability that is absent.** A
probe answers no when the view, the column or the grant is missing. Any other
error means the tool asked a wrong question, so it refuses instead of reporting
a negative that looks plausible. Without this rule, a probe that was invalid on
every release would read as a clean "no", because every failure would count as
an answer.

### Oracle variants that must all work

- **Single-instance non-CDB** (11.2, 12.1 non-CDB, 19c non-CDB)
- **CDB root** — common users (`C##APP_OWNER`), `CONTAINER=ALL` vs `CONTAINER=CURRENT`
- **PDB** — local users, connected via service name; the same local username may
  exist independently in many PDBs
- **Application containers** (application root + application PDBs) — a distinct
  scope, not the same as CDB root
- **OCI database services.** Autonomous Database encrypts with TLS or mutual TLS
  over TCPS and uses no Native Network Encryption (NNE). Base Database Service
  and Exadata Cloud require NNE. *Why thick mode* below gives the measurements.
  The client is thick mode for all of them. Thick mode is a runtime
  prerequisite, not a configuration option.
- **RAC / Data Guard** — connect via service, not SID; on a physical standby the
  driver must detect `OPEN MODE = READ ONLY` and refuse write operations up front
  rather than failing mid-statement.

### Version-dependent behaviour to detect at runtime, never assume

- Maximum password length. The tool enforces 30 bytes below release 23 and 128
  bytes from 23. This is the tool's rule, not a measured Oracle limit on every
  release. A 31st byte is refused on 11.2, 12.2, 18c, 19.3 and 21c, and 128
  bytes are accepted on 26ai. 12.1, and 23ai before 23.26, are not measured
  (unverified: password-byte-limit). The limit does not change at 12.2: that
  release raised the identifier limit and left passwords at 30 bytes.
- Password verifiers present (`DBA_USERS.PASSWORD_VERSIONS`: 10G/11G/12C) and
  `SQLNET.ALLOWED_LOGON_VERSION_SERVER` — a generated password longer than 30
  bytes silently breaks clients still relying on 10G/11G verifiers
- Case sensitivity (`SEC_CASE_SENSITIVE_LOGON`, removed in 12.2+)
- Gradual password rollover availability
- Unified vs traditional auditing

The tool queries version and capabilities on connect and caches the result per
session. It never branches on a version number typed into config.

**Client reach is a separate constraint from server support.** Oracle's
client/server interoperability matrix says a 23.x client supports servers from
19c onward, and an 11.2 server needs a 19.x client. Instant Client for macOS
ARM64 exists only in 23.x, so an Apple Silicon machine cannot reach an 11.2
target. `sopuli doctor` reports the installed client version and warns when a
configured target is out of its reach, so the connection does not fail with a
bare ORA error.

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

**A driver is an install extra**, by the same rule as a store.
`python-oracledb` exists only to reach Oracle, so it comes with
`sopuli-dba[oracle]`. PostgreSQL would come with `sopuli-dba[postgres]`.
`sopuli/driver/registry.py` implements this. The driver registry and the store
registry share `sopuli/extras.py`, which finds a module without importing it and
reads a `ModuleNotFoundError` three ways. That logic is subtle, so it has one
copy. The error messages stay separate: a store is named by `vaults:` and a
driver by a target's `type:`, and one message for both would name neither.
Instant Client must be installed to reach Oracle anyway (D3), so making the
driver an extra adds no new condition. See P2's *Backends are install extras*
and [ADR-006](../decisions/adr-006-optional-dependencies.md). D6 is unaffected:
an extra controls which dependencies are installed, not which modules exist.

---

## P2. Multi-vault support

### The rule

Vaults are pluggable behind a **secret store interface**. A secret is addressed by
a *SecretRef* that is uniform across backends; only the resolution of that ref is
backend-specific.

The interface is `sopuli/store/protocol.py`. This sketch lists its methods:

<!-- checked-list: store-protocol -->
```
SecretStore
  supports() -> capability set
  health() -> StoreHealth                   # ok, degraded or unreachable, and the store's clock
  read(path, version) -> Stored | None      # the document and the version it was read at
  write(path, data, cas) -> version
  patch(path, changes, cas) -> version      # RFC 7396 merge patch
  metadata(path) -> PathMetadata | None
  require_cas(path) -> None                 # makes the path refuse writes without a CAS
  list(prefix) -> path[]
```

**`write` and `patch` take a compare-and-set version and return the new
version.** The returned version is the advisory lock's fencing token. A write
that returned only "ok" would leave the lock nothing to fence with.

**`metadata` reads what a store knows about a path apart from its contents.**
Pre-flight uses it to check that a lock path does not accept writes without a
compare-and-set. The tool does not claim a guarantee it cannot check.

**`list` has these properties.** A backend's own listing endpoint gives none of
them directly, and without them two adapters would disagree:

- it returns **full paths**, which can be passed straight to `read`, not the
  tails a KV mount returns;
- it is **recursive and returns leaves only**. KV answers one level at a time
  and marks a subtree with a trailing `/`. The adapter walks the tree, so that no
  caller writes the same walk for each backend;
- **a path that is listed may have nothing to read.** A soft-deleted path keeps
  its metadata in KV v2, so it is listed and reads as nothing. `lock status`
  needs exactly this: it finds a leftover record by listing and reports on it by
  reading;
- the prefix matches on a **segment boundary**, so `locks` does not return
  `locksmiths/db`. The result is **sorted**, so two surveys of one estate give
  the same answer.

A store without the `list` capability **raises** instead of returning `()`. "I
looked and found nothing" and "I cannot look" are different answers. A caller
acts on the first by concluding that nothing is there.

**`read` takes a version.** This is C14's `@version=N`. It needs the
`versioning` capability, and a store without it **raises** instead of returning
the latest version. A caller pins a version because it does not want the current
one, so returning the current one would make a rotation read the wrong
generation. KV v1 refuses.

**`patch` applies an RFC 7396 merge patch**, and needs the `merge_patch`
capability. It makes `01-configuration.md` §7's "must not clobber siblings" a
property of the structure: the tool never sends the keys a run did not come for,
so another account's password is neither read into the process nor written back.
A store without the capability falls back to a compare-and-set read-modify-write.
So does a Vault policy that grants `update` and not `patch`; that is a policy, not
a fault. The run **reports which of the two it used**, because the fallback sends
more. Both use the same compare-and-set, so they differ in what they send, never
in atomicity.

`sopuli/store/credentials.py` is the secret side of the interface. It resolves a
SecretRef against a stored document (field, JSON pointer, `@stage=` and
`@version=`). It returns a `Secret` and the version it was read at, and it builds
the merge patch that changes one stage of one account. It provides these
operations and decides no order. The `pending` → `current` ordering that
invariant 7 depends on is UC-1 §3's, and `creds rotate` carries it out.

**`health` is asked by `doctor`'s vault section.** It differs from the other
methods in these ways:

- **it is not about a path.** It describes the store, not a document in it;
- **it never raises for an unreachable store.** The other methods treat "could
  not reach it" as a failure, because their callers wanted something done.
  `doctor` asks in order to find out, and it surveys a whole estate, so one
  unreachable vault must not stop the survey. `unreachable` is a value that
  `health` returns, not an exception;
- **it reports the store's clock.** `sopuli/lock/decide.py` compares a lease's
  expiry with this machine's clock and allows `CLOCK_SKEW` for the difference. A
  host whose clock is minutes out takes over locks that are still live, or
  refuses locks that expired long ago. That looks like a locking bug, not an NTP
  problem. The store's clock is the only other clock the lock depends on.

The skew measurement corrects for latency and reports what it cannot know. The
store answered somewhere inside the round trip, so half the round trip is the
uncertainty of one request. A difference that a slow link could explain is not
reported. A store that exposes no clock returns `None`, never a substitute. This
host's clock is what is being tested, and a caller given it would compute a skew
of zero and report agreement.

A store that cannot report its own health needs no capability flag:
`unreachable` already covers "nothing came back". `health` must never **write**
to prove the store is reachable. P5 makes `doctor` change nothing, and a check
that left a lease behind would change the mount a rotation is using.

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
| `list` (paths below a prefix) | yes | yes | yes | yes |
| `staging_labels` | emulated in payload | emulated | native | emulated |
| `structured_value` (JSON inside a secret) | yes | yes | yes (base64 content) | yes |
| `soft_delete` / undelete | yes | no | yes | no |

**Each capability stands alone; there are no tiers.** KV v1 has no
compare-and-set, and it lists paths without any problem. Reporting no
capabilities because one important capability is missing would stop `lock
status` from finding a leftover record it could have found.

Where a capability is missing the tool **emulates it in the secret payload**
(explicit `current` / `pending` / `previous` fields) rather than pretending the
guarantee exists. Emulation is not atomic; commands must say so in dry-run output.

**`list` is neither emulated nor fatal.** A command that wanted it **reports what
it could reach and says that it could not look further**. A refusal would make
`lock status` work on some backends and not on others. A partial answer that says
it is partial is better.

**`merge_patch` is emulated, and the run says so.** The emulation is the
read-modify-write described above. It is as safe against a concurrent writer and
it sends more. A run that used it without saying so would look the same as one
that did not.

**`versioning` cannot be emulated.** To read a version back, the store must have
kept it at the time it was written. Nothing written into a payload later can
create it. So `@version=N` against KV v1 is refused with `UNSUPPORTED_CAPABILITY`
and a message that names the ref. It is never answered with the current document.
The three **stages** are a different matter. They are emulated in the payload on
every backend except OCI, and `@stage=pending` works on a store with no versions,
because a stage is a key beside the value and not a generation of it.

**`cas` cannot be emulated either**, because its purpose is atomicity. A store
without it gets no lock, not a weaker lock. P5's advisory lock refuses KV v1 and
the file backend unless the store is configured as `locking: advisory-only`. Then
the record is written without compare-and-set, and every run says so
(`01-configuration.md` §3a).

### Backends are install extras (D9, ADR-006)

A backend's client is installed only by the sites that use that backend. The
base install carries what every invocation uses; a vendor client is an extra.
These commands install the base and each extra:

<!-- checked-list: extras -->
```
pip install sopuli-dba                 # config, selection, schema — no network client
pip install "sopuli-dba[oracle]"       # + python-oracledb, to reach Oracle
pip install "sopuli-dba[hashicorp]"    # + HashiCorp Vault
pip install "sopuli-dba[oci]"          # + OCI Vault / Secrets
pip install "sopuli-dba[notify]"       # + UC-2's webhook notify channel
pip install "sopuli-dba[all]"          # everything
```

| Layer | Contents | Installed by |
|---|---|---|
| base | CLI framework, YAML parser, `pywin32` on Windows, sopuli itself | `sopuli` |
| store extras | one vendor client per secret store | `sopuli-dba[<store>]` |
| driver extras | one database driver per product (P1) | `sopuli-dba[<product>]` |
| channel extras | the client a delivery channel needs | `sopuli-dba[notify]` |
| `all` | every extra above | `sopuli-dba[all]` |

This is packaging, not architecture: nothing above about `SecretStore`, the
SecretRef, or capability negotiation changes. What changes is that P2's
pluggability becomes true at install time and not only at import time. These
rules make that real:

1. **A vendor client is imported inside its backend module, never at package
   import time.** The registry maps `type:` to a module path and imports on
   first use.
2. **A missing backend is a diagnosable condition, not a traceback.** An
   `ImportError` at registry resolution becomes a structured error naming the
   extra that supplies it — `error.category: "config"`, exit 9, and a run
   document under `--output json` like any other config-resolution failure:

   ```
   $ sopuli creds check
   sopuli: vault "vault-prod" declares type "hashicorp", but that backend is not installed
     hint: install it with:  pip install "sopuli-dba[hashicorp]"
   exit 9
   ```

3. **Nothing in base opens a socket.** The dependency set makes this testable: a
   base install cannot import any of the clients the backends use — `httpx`, the
   OCI SDK, `python-oracledb`. The standard library's `urllib` can be imported in
   every Python, so the rule covers it by intent, not by test: base code does not
   reach the network by any means.

Every command that does not open a connection works with no backend installed:
`config validate`, `config show --resolved --explain`, `target list`. Declaring a
store is config, and only reaching it needs its client, so a file that names
every backend validates with none of them installed. A backend that is
configured but not installed is a `config validate` **warning** and a `doctor`
**failure**. `doctor` lists installed and configured backends on every run, not
only when they differ.

This is a decision and not a packaging detail. sopuli handles credentials, so a
security review will read its dependency tree. Vendor SDKs also carry
constraints that conflict: the OCI SDK pins `cryptography` and `pyOpenSSL` and
bundles its own `requests`, and a site that uses no OCI service should not get
them. Extras are also a published interface: making base smaller later breaks
installs that never named an extra, while making it larger never does. The full
reasoning is in [ADR-006](../decisions/adr-006-optional-dependencies.md).

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

`sopuli/admin.py` resolves one of these sources into a `Secret` at connect time.
`01-configuration.md` §3a specifies the sources and the rules that come with
them, such as the refusal when a target names no source, what `prompt` does
with no terminal, how one prompt is shared across targets, and why the
environment source is flagged and not refused.

**The vault's own credential has the same problem.** The list above is about
reaching the database. Reaching the store needs a credential too. A SecretRef
cannot provide it, because a ref is resolved by an authenticated store. That
removes the second source from the list. What remains is an external or machine
identity (AppRole, Kubernetes, instance principal), a file, an interactive
prompt, and the environment. `--vault-token-file` is the command-line form of
the file source. It takes a **path**, for the reason invariant 1 gives: a token
as an option value is visible in `ps`.
[ADR-007](../decisions/adr-007-vault-token-flag.md) records the decision, and
`01-configuration.md` §3a is the specification.

---

## P3. Structured configuration file with documented precedence

### The rule

All targets, vaults, groups, policies and defaults live in a YAML file. Command
options and environment variables may override a documented subset. **Exactly one
precedence order applies everywhere**, and the tool can print it.

### Precedence (highest wins)

```
1. Command-line option              --vault-addr https://…
2. Environment variable             SOPULI_VAULT_ADDR, then VAULT_ADDR
3. Profile block in config          profiles.ci.vaults.hcv-prod.addr
4. Target/vault-level setting       vaults.hcv-prod.addr
5. Top-level defaults in config     defaults.vaults.hcv-prod.addr
6. Built-in default                 (compiled into the tool)
```

**Within layer 2, a `SOPULI_*` variable outranks the third-party variable for
the same setting**, so `SOPULI_VAULT_ADDR` beats `VAULT_ADDR`. The
third-party variables are Vault's own, such as `VAULT_ADDR` and
`VAULT_NAMESPACE`; `sopuli/config/vault_env.py` maps them to settings. The
resolver records them as the sources `env` and `env_thirdparty`, and
`sopuli/settings/registry.py` declares them as separate members of `Layer`.

Layers 3 to 5 all name the store, because **`vault:` is a store name everywhere
in the config and never a block**. `SOPULI_VAULT` and a SecretRef's `[<vault>:]`
prefix use the same word, and `SOPULI_VAULT__HCV_PROD__ADDR` is the environment
form of the same addressing. Settings of a store are therefore written under
`vaults:`, keyed by its name, and `defaults:` and a profile may each carry a
partial entry. C13 is the decision; `01-configuration.md` §3a and §5 are the
specification.

`sopuli/config/vault_layers.py` merges layers 2 to 5 through the one resolver in
`sopuli/settings/`. That is why `vaults.*.tls.verify` ratchets instead of being
overwritten by the highest layer. All the layers are merged in one pass. If two
were resolved first and the rest folded in later, the tool would report the
winner of the first pass, not the layer an operator has to edit. Read the
direction from the table: `defaults:` is *below* the declaration and fills gaps;
only a profile and the environment are above it.

**Layer 1 has one flag for a vault key: `--vault-addr`.** It sets
`vaults.*.addr`, and no flag sets any other key of a store. It addresses the
store that `SOPULI_VAULT` or `defaults.vault` names, by the rule in
`01-configuration.md` §6 that the variables use, so the command line does not
define "the default store" a second time. It is refused when neither names a
store. There is no `--vault-addr NAME=URL`: a run that uses two stores sets
`SOPULI_VAULT__<NAME>__ADDR`. `01-configuration.md` §6 explains why an address
has a flag and `mount` does not.

Layer 2 has two spellings for an address. `SOPULI_VAULT__HCV_PROD__ADDR` names a
store. `SOPULI_VAULT_ADDR` has no name and applies to the store that
`SOPULI_VAULT` or `defaults.vault` names. When neither names one, the tool
refuses instead of guessing. `01-configuration.md` §6 is the specification.

**The tool reads the config file before a verb runs.** It must: a profile is
layer 3 and may set `output`, and a verb that has started has already chosen how
to write its output. So `sopuli/invocation.py` finds the file, reads it under the
profile that `--profile` or `SOPULI_PROFILE` names, and resolves all the layers.
A verb receives the loaded config; it does not load one. The run document is
opened first, from the command line alone, so that an unreadable file still
reports itself with exit 9 and a document (J7).

A profile is named after **how the run was invoked** — `interactive`, `ci`,
`scheduled` — never after an environment. `--profile prod` reads like a target
selector and is not one; profiles change behaviour, never scope.
`01-configuration.md` §5 is the specification, and validation warns on a profile
named after any target's `environment`.

Rationale for env above config: config files are committed and shared; env is set
per execution context (CI job, container) and must be able to redirect a shared
config without editing it. Rationale for CLI above env: the operator typing the
command expresses the most specific intent available.

**Layer 1 is one layer.** The CLI parser accepts some flags both before and after
the subcommand. Both positions are the same person, in the same command line, at
the same moment, so there is nothing to rank. Both resolve as `cli`, and
`source_detail` records the position where it matters. Safety flags are accepted
in the trailing position only, so a group-position value never reaches the
resolver — see `adr-002-cli-framework.md`.

**Safety settings only ratchet toward safe** (invariant 10). No source can relax
them. `SAFETY_SETTINGS` in `sopuli/settings/registry.py` lists them, and
`tests/settings/test_ratchet.py` checks each one. They include the `--dry-run`
flag, `readonly: true`, `safety.max_targets`, `safety.confirm_environments` and
`safety.delivery.allowed_methods`.

- If the config says `readonly: true`, no flag re-enables writes. That includes
  `--force`, which is not a setting and has no layer. A run that would mutate a
  `readonly` target is refused at plan time (see the end of this section).
  `lock break` refuses under `readonly` with **exit 8**: the file is valid, so it
  is not exit 9, and the operator declined in advance by writing it, which is
  what exit 8 means. `--dry-run` is refused with it as well. Under `readonly` the
  mutating verbs are unavailable, and the read-only verbs are how to ask.
- `safety.delivery.allowed_methods` is scoped under `safety.delivery.*` because it
  restricts what UC-2 delivery may do. It is not a key of the `delivery:` block
  it governs, and a reader who looked for it there would look in the wrong place.

**`safety.delivery.allowed_methods` merges by intersection** (H6). It restricts
which UC-2 delivery methods an estate may use. A layer may narrow the set, but
never restore a method that a lower layer removed. `01-configuration.md` §9 has
the shape and its rules. It is not a union like `confirm_environments`, because
of what each does on **upgrade**. A `forbidden_methods` union names what is
refused, so a method added in a later release is allowed by every estate that has
not heard of it. The guard widens without anyone noticing, and it guards putting
a live credential on a wire (UC-2 §6). An `allowed_methods` intersection names
what is allowed, so the same new method is unusable until somebody writes it
down. Failing closed costs a merge shape in the registry. Failing open would cost
a guarantee on every upgrade.

**Layer 4 of the safety settings is merged later than layers 3 and 5.** A
`safety:` block under `defaults` or a profile belongs to the run, and it is
resolved with everything else before the verb runs. A block on a target or a
group is different: which blocks apply depends on which targets the run reaches,
and no selector has been applied yet. So a verb merges them after it has
narrowed its estate and before it builds its plan. It uses the same resolver and
the same ratchet, in one pass over the earlier and the new contributions, for the
reason the `vaults.*` layers are merged in one pass.

**A run that reaches a `readonly` target is refused as a whole**, at plan time.
The refusal names the marked targets and the selectors that would leave them
out. `01-configuration.md` §3a has the decision and what the other two readings
would cost.

### Making precedence debuggable

`sopuli config show --explain` prints every effective setting with the layer it
came from. This excerpt is its `settings` section, from a run with
`--profile ci`, where the profile asks for `max_targets: 200` and the config's
`defaults` set 4:

```
  db.connect_timeout_s            = 30                                      [built-in default]
  db.query_timeout_s              = 120                                     [profiles.ci.db.query_timeout_s]
  output                          = text                                    [cli --output (verb)]
  profile                         = ci                                      [cli --profile (group)]
  safety.max_targets              = 4                                       [defaults.safety.max_targets]
                                    profiles.ci.safety.max_targets asked for 200; safety.max_targets stays 4 (defaults.safety.max_targets) -- safety settings only ratchet toward safe
  safety.readonly                 = false                                   [built-in default]
  vaults.vault-prod.addr          = https://vault.example.com:8200          [env SOPULI_VAULT_ADDR]
  vaults.vault-prod.mount         = kv                                      [vaults.vault-prod.mount]
```

Secret values are always redacted here. Anything resolved from a source the tool
considers low-assurance is marked.

The `safety.max_targets` line matters most. A setting that was requested and did
not win is invisible in the result and visible in this view, so an operator can
check that the ratchet works. It also reaches `--output json`: the same defeated
request is a warning in `diagnostics[]` on every run, not only when `--explain`
was asked for.

**`--explain` does not require `--resolved`.** Where a setting came from is the
same in the declared view and the resolved one, because provenance does not
depend on target expansion. `--select` is different: it has nothing to filter
until the estate exists. In `--output json`, `--explain` widens
`invocation.options` to include settings answered by a built-in default, which
the document otherwise leaves out because they changed nothing. One producer and
one shape answer both questions. `sopuli/output/explain_view.py` implements it.

### Config file discovery

First match wins; `--config` may be repeated to layer files:

1. `--config PATH` (repeatable; later files override earlier ones)
2. `SOPULI_CONFIG`
3. `./sopuli.yaml`
4. `$XDG_CONFIG_HOME/sopuli/config.yaml` → `~/.config/sopuli/config.yaml` (Linux/macOS)
   / `%APPDATA%\sopuli\config.yaml` (Windows)
5. `/etc/sopuli/config.yaml` (Linux/macOS) / `%PROGRAMDATA%\sopuli\config.yaml` (Windows)

**A path that was named behaves differently from one that was searched.** Steps 1
and 2 name a file, and a named file that is missing is an error, never a reason
to try step 3. A CI job whose `SOPULI_CONFIG` has a typo must not run against the
system config instead, because that reads the whole estate from a file nobody
chose. Steps 3 to 5 are searched, so an absent file is skipped, which is what
"first match wins" means. An empty `SOPULI_CONFIG` counts as unset. A Windows
location whose variable is unset is left out, not guessed.

Finding nothing at all is an error that lists every place the tool looked. A
command with no config has no whitelist, and invariant 5 makes the whitelist a
requirement. `sopuli/config/discovery.py` implements discovery.

Config files are validated against a published JSON Schema. `sopuli config
validate` is a first-class command and exits non-zero on unknown keys — a typo in
a credential tool must never be silently ignored.

The schema is `docs/schemas/sopuli-config-3.0.schema.json`. `sopuli/config/schema.py`
generates it from the config layer, so it cannot drift from what the tool
accepts. It is structural: an editor that uses it catches a typo, and the rules
that span several keys stay in the validators, where an error can name the key.
`01-configuration.md` §9b lists which rules are on which side.

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
| Config permission check | refuse on any `0o077` bit — group/world access of any kind, not only read — and on an owner other than the effective user or root | walk the DACL; refuse any ACE granting read *or write* to a SID outside {owner, `OWNER RIGHTS`, `CREATOR OWNER`, `SYSTEM`, `Administrators`} |
| Secret in memory | best-effort zeroing, documented as best-effort | same |
| Path handling | never string-concatenate paths | same |
| Line endings | write LF, read LF/CRLF | same |
| Stream encoding | UTF-8 on stdin/stdout/stderr, forced at startup | same — a *redirected* stream otherwise uses the locale codepage |
| Keyring | Secret Service / libsecret; macOS Keychain | Credential Manager / DPAPI |
| Oracle client | Instant Client + `LD_LIBRARY_PATH` | Instant Client on `PATH` + VC++ redistributable |
| Terminal | ANSI colour, off when not a TTY or `NO_COLOR` | same, with VT mode enabled; plain fallback |
| Exit codes | identical numeric set on all platforms | same |

**Stream encoding.** On Windows an attached console is UTF-8, but a redirected
stream uses the locale codepage. A scheduled run is captured by redirection
(`sopuli creds check > nightly.log`). Under cp1252 an em dash reaches a UTF-8
reader as mojibake, and a character outside the codepage, such as box drawing, a
check mark or an arrow, raises `UnicodeEncodeError` and stops the command
mid-write. The tool therefore forces UTF-8 on all three standard streams at
startup, before it parses arguments, so that a usage error is also written
correctly. stdin is included because its failure is silent: a password read
under cp1252 becomes a different password with no error, and it appears much
later as an authentication failure.

Instant Client is required at runtime on every platform, so installation is
"install the client, then install sopuli". `sopuli doctor` checks the client's
presence and version, `TNS_ADMIN`, wallet readability, vault reachability and
clock skew. It reports which backends are installed against which the config
declares (P2), and prints a remediation hint for the platform.

**`doctor` measures the vault's clock beside its reachability.** The vault's
clock is the other clock in the system. `sopuli/lock/decide.py` compares a
lease's expiry with this machine's clock and allows `CLOCK_SKEW` for the
difference. A host outside that window takes over locks that are still live, or
refuses locks that expired long ago, and that looks like a locking bug, not an
NTP problem. Measuring the clock shows the problem before a rotation depends on
it. An unreachable vault fails the run with exit 1, the same as an unreachable
target. A degraded vault and a skewed clock are warnings, because `doctor` must
still survey the estate when the person running it did not cause the problem.

### Why thick mode (D3)

Each of these reasons is enough on its own:

1. **Native Network Encryption.** python-oracledb thin mode does not implement
   NNE, and a server that requires NNE refuses the connection. Base Database
   Service and Exadata Cloud require it: their default `sqlnet.ora` sets
   `SQLNET.ENCRYPTION_SERVER` to require it. So does any on-premises database
   configured the same way. **Measured for Base Database Service** on
   19.32.0.0.0: the shipped `sqlnet.ora` sets both `SQLNET.ENCRYPTION_SERVER` and
   `SQLNET.CRYPTO_CHECKSUM_SERVER` to `REQUIRED`, and thin mode is refused with
   `DPY-3001`. **For Exadata Cloud this is Oracle's documented default, not
   measured here**, and no Exadata run is planned.
2. **Oracle 11.2.** Thin mode connects only to 12.1 and later, and 11.2 is a
   release this tool supports.
3. **`auth: external`.** A wallet-based `/@alias` logon through an external
   password store needs the Oracle client libraries.

**Autonomous Database is not on that list.** It encrypts with TLS or mutual TLS
over TCPS and does not use NNE. Measured on ADB serverless 23.26.3.3.0: a thin
connection succeeds through the wallet, and neither mode negotiates an NNE
algorithm. The tool still reaches it in thick mode, because the tool has one
mode and not one mode per target. It is wrong to say that every OCI-hosted
database requires NNE.

**SQLcl connecting "thin" to an NNE-required database is not a counter-example.**
That is JDBC thin, a separate pure-Java driver that implements NNE. It says
nothing about python-oracledb's thin mode, which does not.

None of this reopens D3: thick mode, always, on every target.

### Why macOS is best-effort rather than supported or excluded (D5)

The obvious blocker does not exist. Oracle ships **Instant Client for macOS
ARM64** — 23.26.x, notarized DMGs, with SQL\*Plus and the OCI libraries — so
thick-mode drivers work on Apple Silicon. Intel macOS has its own 19.x line.
Thin mode is unusable for this tool on every platform, for the reasons
above, but that is not a macOS problem.

These are the reasons against a supported tier:

- **An Oracle database cannot run on macOS.** There has been no macOS server
  build since 10g, and Oracle's container images are `linux/amd64` only. Under
  emulation on Apple Silicon they are unsupported and unreliable. A macOS
  developer or CI runner therefore cannot run the integration suite locally and
  needs a remote database. The cost is in testing infrastructure, not in code.
- **Apple Silicon cannot reach an 11.2 database.** Only the 23.x client exists
  for ARM64, and a 23 client supports 19c and later. Intel macOS has a 19.x
  client that reaches 11.2, but Intel Macs are going out of use.
- **There is no evidence of demand.** There is no DBA-specific OS survey. The
  Stack Overflow 2024 figures (Windows 47.6%, Linux 40%, macOS 31.8%,
  professional, multi-select) describe mostly web and application developers,
  and do not apply to DBAs.

The reason against *excluding* macOS: in Python there is almost no
macOS-specific code. Path handling, `NO_COLOR` and the keyring backend are
abstractions that Windows already requires. Excluding macOS would save nothing,
and the exclusion would have to be undone the first time someone asks.

So the code stays portable, the README's support statement leaves macOS out, and
there is no macOS CI. Revisit this only if a real user asks. If one does, the
first question is where their test database runs.

---

## P5. Cross-cutting behaviours (every command)

**Safety**

- Every mutating command supports `--dry-run` and prints the exact plan, redacted.
- Every mutating command supports **`--confirm`**, with one exception: UC-2's
  seen reset refuses it as a usage error (exit 2), because there the prompt
  establishes that a person is present. **The tool asks for confirmation where
  the configuration asks for it, and nowhere else.** D10 has the decision. The
  table shows which triggers exist:

  | trigger | status |
  |---|---|
  | the run reaches an environment in `safety.confirm_environments` | **built** |
  | ~~the target is marked `environment: prod`~~ | **declined** — it would be a built-in `[prod]` under another name, and `01-configuration.md` §9 forbids a built-in in a union ratchet, because no layer could ever remove `prod` again. §9's own example of the problem is `confirm` |
  | ~~blast radius exceeds `max_targets` (default 1)~~ | **declined** — every multi-target mutation would prompt on an estate that wrote no safety block. `max_targets` is a ceiling, not a confirmation threshold. An unset `max_targets` is no limit, which is not the same as a default limit chosen by the tool |

  **The declined triggers are declined, not deferred.** An estate that marks
  a target `environment: prod` and does not list `prod` gets no prompt, and that
  is the specified behaviour. `sopuli/safety.py` and
  `tests/test_cli_confirm_environments.py` test both.

  Some gates confirm every time, without reading the setting: `creds rotate`
  (UC-1 §8 step 1), `lock break`, and UC-2's seen (`manual`) reset, where the
  DBA sees a working password (`../use-cases/uc-02-personal-account-passwords.md`
  §2).

  **`--confirm` does not answer the seen reset's gate.** For the other gates and
  for the setting, `--confirm` is a yes given in advance. Here it is a usage
  error, because the prompt is not a formality. The run is about to print a
  working password to a screen. A yes given in advance claims that somebody is
  watching, and the purpose of the gate is to establish that somebody is. The
  seen path's terminal check makes the same claim, on purpose. Invariant 2 in
  `CLAUDE.md` covers both.

  A profile's `confirm: false` says that nobody can be asked. A run that needs
  confirmation then *refuses* (exit 8) instead of proceeding.

  **The flag is `--confirm`, and there is no `--yes` alias.** An alias would save
  an operator four keystrokes and give the CLI two spellings of one flag. Adding
  one would be a change to D2's grammar.
- **`safety.max_targets` stops a wildcard from reaching 200 PDBs by accident. It
  is a setting, not a flag.** There is no `--limit` or `--max-targets`.
  `sopuli/settings/registry.py` declares the setting on
  `(PROFILE, OBJECT, DEFAULTS)`. The resolver enforces `Setting.layers` and
  raises on a contribution from an undeclared layer, so a flag would be refused
  until the tuple included `Layer.CLI`.

  **Invariant 10 does not forbid the flag.** `safety.max_targets` is
  `MergePolicy.RATCHET`, and an `int` ratchets to the minimum, so a flag could
  only lower the ceiling. That is safe, as `safety.dry_run` is safe on
  `Layer.CLI`. The flag is missing because nobody has made the case for it. A
  ceiling in the file a reviewer reads says what an estate permits. A ceiling an
  operator passes per run says what that operator chose, and
  `invocation.options` would report two different claims. Adding the flag means
  adding `Layer.CLI` to the registry entry, with the reason.
- Mutating operations take an advisory **lock** keyed on the vault path of the
  secret they change, so two operators or two CI jobs cannot rotate the same
  credential at the same time. The lock lives in the vault, is guarded by
  compare-and-set, and carries a fencing token that is checked again before
  every mutation (Q2). The key is the path, not the account or the target. Every
  target receives the same value, so a per-target lock means nothing, and a
  per-account lock misses two accounts that share one document. The vault
  document is what changes, and compare-and-set works on exactly that.
  `check`, `status` and every `--dry-run` take no lock. Otherwise an hourly
  scheduled check would block rotations. `sopuli lock status` reads the lock
  records without taking a lock, so anyone can find out what an exit 7 was about.
  It also **lists** each store's lock prefix, so it reports a record left at a
  path that the config no longer declares, marked `declared: false`. That does
  not break invariant 5: the config whitelists what the tool may change, and a
  survey changes nothing.
- **Breaking a lock is a verb, and it is not self-service.**
  `sopuli lock break <vault>:<path>` writes a `released` record over the held
  one, with `cas` set to the version it read. It never deletes the record: a
  delete leaves the metadata behind, and a first acquisition could then never
  compare-and-set against version 0 again. The write increases the version, and
  that **fences** the holder: its next check fails, and it stops before its next
  mutation. The fence is what makes the verb safe, so a store that cannot fence is
  refused with exit 5. This includes a store declared `locking: advisory-only`,
  whatever it supports. The declaration decides, because `locking.break_expired`
  is refused for the same combination, and two guards must not disagree about one
  configuration. `lock break` asks for confirmation. A lock that has not expired
  also needs `--force`. Without it the verb refuses with exit 7, naming the
  holder, in the same words a rotation that lost the lock would use. The verb may
  clear a record at a path the config does not declare, because nothing else can
  clear the leftover that `lock status` finds. Invariant 5 still holds: the write
  goes under the lock prefix of a store that `vaults:` declares, never to the
  secret the lock guards.

**Idempotency**

Running a command twice must not make things worse. `apply` against an
already-correct state is a no-op reporting `unchanged`. This is what makes the
tool safe to run from a scheduler.

**Observability**

- Human output by default; `--output json` for one machine-readable object,
  `--output jsonl` to stream per-target events. Scripts consume JSON, never text.
  **Only a verb that streams accepts `jsonl`.** `STREAMING_COMMANDS` in
  `sopuli/invocation.py` lists them, and the refusal names them. Any other verb
  refuses `jsonl` as a usage error instead of emitting a stream with less in it
  than its document. `03-json-output.md` §5 has the rule, and the event schema is
  `../schemas/sopuli-event-1.7.schema.json`.
- One structured audit record per mutation: who (OS user + vault identity), what
  (account, target, operation), when, correlation id, result. Never the secret.
- `--debug` writes debug output to stderr, at one level. The tool writes no log
  file: an operator who wants one redirects stderr. A config file cannot turn
  debug output on, so a profile has no log keys. Debug output is not part of
  the JSON contract. Secrets are redacted from all output, including debug
  output and tracebacks. `03-json-output.md` §*Debug output* has the rules, and
  [#629](../decisions/log.md#629) has the reasons.

**Secret hygiene**

- Secrets are never passed as command-line arguments (visible in `ps` and in the
  Windows process list). They come from stdin, a file, or a vault ref. Where a
  flag must name a secret it names its **location**: `--vault-token-file PATH`,
  never `--vault-token VALUE`. The vault-ref source cannot authenticate to the
  vault itself — see P2's bootstrap note.
- **One stream, one reader.** stdin carries at most one secret per run. A command
  that would need two refuses at plan time, instead of reading them in an order
  nobody can see. `creds generate --from-stdin` (UC-1 §4) reads a supplied
  password from stdin, so there is no `--vault-token-stdin`.
- Never written to temp files, never logged, never in exception messages.
  Redaction is applied at the output sink, not hopefully at each call site.
- On Oracle the tool must document that `ALTER USER ... IDENTIFIED BY` text can
  reach SQL trace, `V$SQL` and some audit paths, and what it does to minimise it.

**Exit codes**

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

**2 and 9 are different codes on purpose.** A usage error has no invocation. An
invalid config has a complete invocation. That difference decides whether a run
document exists (J7, `03-json-output.md` §6). "Empty stdout and exit 2" is a rule
a consumer can rely on only if exit 2 never comes with a document.

The split also helps the operator. Exit 2 means *fix your command line*. Exit 9
means *fix your config file*. These are different people at different times: one
is somebody typing, the other is a deployed file that a scheduler runs.

---

## Decisions

| # | Question | Decision | Status |
|---|---|---|---|
| D1 | Binary name | `sopuli` (project `sopuli-dba`). Reasons: [D1](../decisions/log.md#d1) | decided |
| D2 | CLI grammar | noun-verb: `sopuli creds rotate`, `sopuli target list`. Reasons: [D2](../decisions/log.md#d2) | decided |
| D3 | Implementation language | Python with python-oracledb in thick mode, on every target (P4, *Why thick mode*). Reasons: [D3](../decisions/log.md#d3) | decided |
| D4 | Config format | YAML only; JSON accepted since it is valid YAML. Reasons: [D4](../decisions/log.md#d4) | decided |
| D5 | macOS tier | Best-effort and untested: portable code, no support claim, no macOS CI (P4). Reasons: [D5](../decisions/log.md#d5) | decided |
| D6 | Plugin model for drivers/stores | in-tree first; entry-point plugin API only after a second driver exists. Reasons: [D6](../decisions/log.md#d6) | decided |
| D7 | Minimum Oracle version | 11.2 stays in scope. Reasons: [D7](../decisions/log.md#d7) | decided |
| D8 | CLI framework | click. See `../decisions/adr-002-cli-framework.md`. Reasons: [D8](../decisions/log.md#d8) | decided |
| D9 | Dependency layering | Vendor clients are install extras, and base opens no sockets. See `../decisions/adr-006-optional-dependencies.md`. Reasons: [D9](../decisions/log.md#d9) | decided |
| D10 | Which confirmation triggers are built in | **none** (#294); `safety.confirm_environments` is the only trigger. Reasons: [D10](../decisions/log.md#d10) | decided |

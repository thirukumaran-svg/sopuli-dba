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

### Driver interface

```
Driver
  connect(target, credential) -> Session

Session
  scope() -> Scope                          # what this connection is, and can do
  describe_user(account) -> UserState | none
  resolve_profile(name) -> string | none     # how this database spells it, if it has it
  set_password(account, secret) -> ChangeResult
  verify_password(account, secret, method) -> VerifyResult
  apply_attributes(account, attrs) -> AttributeChange[]
  close()
```

Four of those changed shape when the interface became code (#169), the way P2's
`write` grew a compare-and-set when the advisory lock made it real. Each is a
refinement of the same rule and none of them relaxes it:

- **The session carries the operations.** The sketch threaded a session through
  every call and gave `capabilities()` no argument at all — which cannot be right
  for an estate where twenty-one PDBs answer differently. Capabilities are cached
  **per session**, so a flat interface needs a cache keyed on a connection, which
  is this object with extra steps.
- **`capabilities()` and `resolve_scope()` are one call.** Both are observed at
  one moment, from one connection, and cached together, and the run document
  already prints them as one `scope` object. Two calls would mean two caches and
  a merge at the output layer.
- **`user_exists` is `describe_user(...) is not none`.** A caller asking whether
  an account exists asks what it is in the next breath; UC-1 §5 step 3 is one
  step, not two.
- **`opts` became `apply_attributes`' own `attrs`** (#300). It is where UC-1 §5's
  opt-in attributes go, and it is typed — one field per attribute. An untyped bag
  would accept a misspelled `container_clase: ALL` and silently do nothing, which
  is the failure `01-configuration.md` §10 exists to prevent. `set_password` grew
  no second argument: see below.

`connect` is implemented (#176) — `OracleDriver` in
`sopuli/driver/oracle/session.py`, which is also the module the driver registry
imports for `type: oracle`, so that a missing client is a structured error
rather than a traceback.

**A driver is an object, and the split is load-bearing.** Everything the driver
holds is a property of the *run* — which environment, which correlation id,
which timeout budgets, where Instant Client lives — and everything `connect`
takes is a property of the *target*. The first draft made `connect` a module
function with four extra keyword arguments, which is not the interface above:
a caller written against `Driver` would have got a `TypeError`, which is exactly
the drift this sketch exists to prevent. `tests/driver/test_oracle_connect.py`
asserts `isinstance(driver, Driver)` so the two cannot part company again.

Three further decisions came with it, each a fork rather than a detail:

- **Where Instant Client lives is resolved, not assumed.** §6's
  `SOPULI_ORACLE_CLIENT_LIB_DIR` first, then `runtime.oracle.client_lib_dir`
  from the file, then the platform's own loader (P4's table). The config key had
  been documented and parsed since the config layer was written and was ignored
  by the first draft of this — a documented key that silently does nothing is
  worse than one that does not exist.
- **Thick-mode initialisation is lazy, on the first connect.**
  `init_oracle_client` is process-global and effectively one-shot, so the
  alternative was doing it at startup, where the failure is earliest. Lazy wins
  because ADR-006 rule 3 says a base install opens no sockets and loads no
  vendor client: an offline `config validate` that initialised Instant Client
  would be working for a database it will never contact, and would *fail* on a
  machine where that command is perfectly valid.
- **One connection per target, never a shared session with `SET CONTAINER`.** A
  CDB root and its PDBs are separate services. The alternative needs
  `ALTER SESSION SET CONTAINER`, which `02-oracle-privileges.md` §2 lists as
  optional and which the document's whole position is to avoid needing — the
  grant set stays minimal, and a run that cannot reach one PDB fails for that
  PDB rather than poisoning a session shared with others.
- **The correlation id goes on every session**, including ones that turn out to
  read nothing. §5's `DBMS_SESSION.SET_IDENTIFIER` is the join between the
  tool's JSON, the database's own trail and the vault's metadata; a session that
  appears in the trail unlabelled is the one somebody has to explain later.

`apply_attributes` was the one operation above that the code deliberately did
**not** declare — the same seam P2 drew around `health` until #216 gave it a
caller. A method on the protocol is a demand on every implementation, so
declaring one nothing calls would oblige the Oracle driver to write a body for a
caller that does not exist. **It arrived with #300**, the first of UC-1 §5's
attributes, and it took two refinements of the sketch with it:

- **`attrs` is a typed `AccountAttributes`, one field per attribute** — never a
  mapping. `01-configuration.md` §10's rule: a bag would accept a misspelled key,
  do nothing, and report that it had done nothing wrong.
- **it returns one `AttributeChange` per attribute**, not the single
  `ChangeResult` the sketch shows. §5 requires each attribute to be *reported as a
  separate change so the diff stays readable*, and one result for four attributes
  could not say which of them moved. `set_password` keeps its own `ChangeResult`
  and grew no `opts`: a password set that also unlocked would be exactly the one
  result describing two mutations that §5 rules out.

`resolve_profile` arrived the same way, with #301's profile assignment: UC-1 §8's
pre-flight has to know whether a profile a policy names exists on a target
*before* anything is written, and the driver is the only thing that can answer it.
It returns the **spelling** rather than a boolean, because a quoted identifier is
case-sensitive and the dictionary's spelling is the only one that may reach a
statement (`02-oracle-privileges.md` §4).

`Scope` is the run document's `scope` object minus `labels`, which belong to the
config rather than to anything a driver can observe.

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
| `role_lookup` | Which roles exist can be read, so a `role:` predicate naming no role is told apart from one matching nobody (UC-2 §2) | `SELECT ON SYS.DBA_ROLES`, §2's grant set since #531 |

A command that needs a capability the target lacks must fail with a distinct exit
code and a message naming the capability and the target — never a generic error.

**A capability is what the session may *do*; where it is standing is
`scope.type`.** These were briefly one idea — `container_scope` sat in this table
until #195 — and separating them is not tidying. A root session that lacks the
common grant and a PDB session that holds it are different failures, Oracle
returns different codes for them (`ORA-01031` and `ORA-65040`), and only one of
the two is fixed by granting anything. `scope.type` already distinguishes
`non_cdb` / `cdb_root` / `pdb`, observed on the same connection at the same
moment, so a capability restating it would be one fact with a second place to
disagree — the reason `offline_verify_available` is `supports(offline_verify)`
and not a field of its own.

**A capability that cannot be *determined* is not a capability that is absent.**
A probe answers no when the view, the column or the grant is missing; anything
else means the tool asked a question it should not have asked, and it refuses
rather than reporting a plausible negative. #195 is the case: a probe invalid on
every release read as a clean `--` for a full release cycle, because any failure
counted as an answer.

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

**A driver is an install extra**, on the same rule as a store: `python-oracledb`
exists only to reach Oracle, so it arrives with `sopuli-dba[oracle]` and PostgreSQL
would arrive with `sopuli-dba[postgres]`. `sopuli/driver/registry.py` implements
it (#170), and the two registries share a mechanism rather than a message:
`sopuli/extras.py` holds looking a module up without importing it and the
three-way reading of a `ModuleNotFoundError`, because that discrimination is
subtle and a second copy of it would drift. The sentences stay apart — a store is
named by `vaults:` and a driver by a target's `type:`, and a message serving both
would name neither. Binding stores and not drivers would read
as arbitrary, and D3 already makes reaching Oracle a per-site runtime condition
— Instant Client has to be installed either way. See P2's *Backends are install
extras* and [ADR-006](../decisions/adr-006-optional-dependencies.md); D6 is
unaffected, since an extra controls which dependencies are installed and not
which modules exist.

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
guarantee the tool cannot check is one it should not claim.

**`list` was in the sketch and is now specified** (#150). Four properties, all of
them things a backend's own listing endpoint does not give a caller unaided, and
each one a place two adapters would otherwise disagree:

- it returns **full paths**, which can be handed straight to `read` — not the
  tails a KV mount answers with;
- it is **recursive and returns leaves only**. KV answers one level at a time and
  marks a subtree with a trailing `/`; walking that is the adapter's job, or every
  caller writes the same walk once per backend;
- **knowing about a path is not the same as having something to read.** A
  soft-deleted path keeps its metadata in KV v2, so it is listed and reads as
  nothing. That pair is exactly what `lock status` needs: a leftover record is
  *found* by listing and then reported on by reading;
- the prefix matches on a **segment boundary**, so `locks` does not return
  `locksmiths/db`, and it is **sorted**, so two surveys of one estate are the same
  survey.

A store without the capability **raises** rather than answering `()`: "I looked
and found nothing" and "I cannot look" are the two answers a caller must never
confuse, since it acts on the first by concluding there is nothing out there.

**`read` takes a version** (#183), which is C14's `@version=N` and the first
thing on this interface that exists for a *secret* rather than for a lock record.
It is behind the `versioning` capability and a store without it **raises** rather
than answering with the latest — the same rule as `list`, and for a sharper
reason: a caller pins a version precisely because it does not want whatever is
current, so substituting the current one is a rotation reading the wrong
generation. KV v1 is the store that refuses.

**`patch` applies an RFC 7396 merge patch** (#183), behind `merge_patch`. What
makes §7's "must not clobber siblings" a structural property rather than a
careful one: the keys a run did not come for are never sent, so another account's
password is neither read into the process nor written back. A store without the
capability — or a Vault policy granting `update` and not `patch`, which is a
policy and not a fault — falls back to a check-and-set read-modify-write, and the
run **reports which of the two it used**, because they are not equally narrow.
Both carry the same compare-and-set, so the difference is blast radius and never
atomicity.

The slice implemented is `sopuli/store/protocol.py`, and the secret side of it is
`sopuli/store/credentials.py`: a SecretRef resolved against a stored document —
field, JSON pointer, `@stage=`, and `@version=` — producing a `Secret` and the
version it was read at, and the merge patch that changes one stage of one
account. That module supplies primitives and decides no sequence: the
`pending` → `current` ordering invariant 7 turns on is UC-1 §3's and belongs to
`creds rotate`.

**`health` arrived with #216**, last of the sketch and deliberately so: its only
consumer is `doctor`'s vault section, and the argument is the one P1 makes two
paragraphs above about `apply_attributes` — a method on the protocol is a demand
on every implementation, so declaring one nothing calls would oblige each backend
to write a body for a caller that does not exist. It came with the command that
asks the question.

Three things make it unlike everything else on this interface:

- **it is not about a path**, so it is the one call that says something about the
  store rather than about a document in it;
- **it never raises for an unreachable store.** Every other method treats "could
  not reach it" as a failure, because every other caller wanted something done;
  this one is asked precisely in order to find out, and `doctor` surveys a whole
  estate — one dead vault must not end the run before the next is tried. So
  `unreachable` is a value it returns, not an exception it throws;
- **it reports the store's clock**, and that is the part that is not a health
  nicety. `sopuli/lock/decide.py` compares a lease's expiry against *this*
  machine's clock and allows `CLOCK_SKEW` for the two disagreeing (#83). A host
  minutes out takes over locks that are still live, or refuses ones long dead,
  and the failure presents as a locking bug rather than as an NTP problem. The
  skew is the assumption the lock rests on, measured against the only other clock
  in the system that matters.

The measurement is latency-corrected and reports what it does not know: the far
end answered somewhere inside the round trip, so half the trip is the exact width
of what one request cannot pin down, and a difference a slow link can account for
is not reported as a finding. A store that exposes no clock answers `None` and
never a substitute — this host's clock is the thing under test, and a caller
handed it would compute a skew of zero and print it as agreement.

A store that cannot report its own health has no third answer here, unlike `list`
and `patch`: `unreachable` already covers "nothing came back", so there is
nothing a capability flag would add. What it must not do is **write** to prove it
is reachable — P5 makes `doctor` mutate nothing, and a check that left a lease
behind would be a measurement that changes what it measures, on a mount a
rotation is using.

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

**Capabilities are per capability, not a tier**, and the `list` row is what makes
that concrete: KV v1 has no compare-and-set and enumerates perfectly well.
Reporting an empty capability set because the interesting one is missing would
deny `lock status` a leftover record it could have found.

Where a capability is missing the tool **emulates it in the secret payload**
(explicit `current` / `pending` / `previous` fields) rather than pretending the
guarantee exists. Emulation is not atomic; commands must say so in dry-run output.

`list` is neither emulated nor fatal, and is the first capability with a third
answer: a command that wanted it **reports what it could reach and says it could
not look further**. Refusing would make `lock status` a command that works on some
backends and not others, which is worse than a partial answer that admits to being
one (#150).

**`merge_patch` is emulated, and visibly** (#183) — the read-modify-write above.
It is the one capability whose emulation the run has to *announce* rather than
merely perform, and the reason is that the emulation is not equivalent: it is
equally safe against a concurrent writer and strictly wider in what it sends. A
run that used it silently would look identical to one that did not.

**`versioning` is the second that cannot be emulated** (#183), and for a reason
worth stating beside `cas`'s rather than assuming it follows: a version somebody
wants to read back is a version the store had to have kept *at the time*, and
nothing written into a payload afterwards can manufacture one. So `@version=N`
against KV v1 is refused with `UNSUPPORTED_CAPABILITY` and a message naming the
ref, and never answered with the current document. Note what this does *not*
touch — the three **stages** are emulated in the payload on every backend but
OCI, and that emulation is unaffected: `@stage=pending` works perfectly well on a
store with no versions, because a stage is a key beside the value rather than a
generation of it.

**`cas` is the one capability that cannot be emulated**, since "not atomic" is
precisely what it is for. A store without it therefore gets no lock rather than a
weaker one: P5's advisory lock refuses on KV v1 and the file backend unless that
store is explicitly configured down to `locking: advisory-only`, where the record
is written without CAS and every run says so (issue #83, `01-configuration.md`
§3a).

### Backends are install extras (D9, ADR-006)

A backend's client is installed only by the sites that use that backend. The
base install carries what every invocation uses; a vendor client is an extra.

```
pip install sopuli-dba                 # config, selection, schema — no network client
pip install "sopuli-dba[oci]"          # + OCI Vault / Secrets
pip install "sopuli-dba[hashicorp]"    # + HashiCorp Vault
pip install "sopuli-dba[all]"          # everything
```

| Layer | Contents | Installed by |
|---|---|---|
| base | CLI framework, YAML parser, `pywin32` on Windows, sopuli itself | `sopuli` |
| store extras | one vendor client per secret store | `sopuli-dba[<store>]` |
| driver extras | one database driver per product (P1) | `sopuli-dba[<product>]` |
| `all` | every extra above | `sopuli-dba[all]` |

This is packaging, not architecture: nothing above about `SecretStore`, the
SecretRef, or capability negotiation changes. What changes is that P2's
pluggability becomes true at *install* time and not only at import time. Three
rules make that real rather than cosmetic:

1. **A vendor client is imported inside its backend module, never at package
   import time.** The registry maps `type:` to a module path and imports on
   first use.
2. **A missing backend is a diagnosable condition, not a traceback.** An
   `ImportError` at registry resolution becomes a structured error naming the
   extra that supplies it — `error.category: "config"`, exit 9, and a run
   document under `--output json` like any other config-resolution failure:

   ```
   $ sopuli creds check --application acme
   error: vault "oci-prod" declares type "oci", but that backend is not installed
          install it with:  pip install "sopuli-dba[oci]"
   exit 9
   ```

3. **Nothing in base opens a socket.** That is the property being defended, and
   the dependency set is what makes it testable: a base install can import none
   of the clients the backends reach with — `httpx`, the OCI SDK,
   `python-oracledb`. The stdlib's `urllib` is importable in every Python and
   always will be, so it is covered by intent rather than by assertion: base
   code does not reach the network, whatever it would reach it with.

Every command that does not open a connection works with no backend installed —
`config validate`, `config show --resolved --explain`, `target list`. This is
what makes the boundary honest rather than a trick: declaring a store is config,
and only *reaching* one needs its client, so a file naming eleven backends
validates with none of them installed. A backend that is configured but not
installed is a `config validate` **warning** and a `doctor` **failure**;
`doctor` lists installed and configured backends on every run, not only when the
two disagree.

Why it is a decision and not a packaging detail: sopuli's subject is
credentials, so its dependency tree is something a security review will actually
read, and vendor SDKs carry constraints that collide — the OCI SDK pins
`cryptography` and `pyOpenSSL` and vendors its own `requests`, which a site
using neither OCI Vault nor OCI-hosted databases should not inherit. Extras are
also a published interface: narrowing base later breaks installs that never
named an extra, while widening it never does. Full reasoning, and the six
questions this closed, in [ADR-006](../decisions/adr-006-optional-dependencies.md).

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

Resolution is `sopuli/admin.py` (#175), which turns one of the four into a
`Secret` at connect time; `01-configuration.md` §3a specifies the sources and
the four decisions that resolving them forces — the refusal when a target names
no source, what `prompt` does with no terminal, how a prompt is shared across
targets, and why the environment source is flagged rather than refused.

**The same shape, one layer earlier: the vault's own credential.** The list above
is about reaching the *database*; reaching the *store* has the identical problem,
and it is worth naming as the same problem rather than discovering it twice. A
SecretRef cannot be the answer there — a ref is resolved *by* an authenticated
store, so it cannot be what authenticates one — which is the list above with its
second entry struck out, since the second entry is the circular one. What is left
is external/machine identity (AppRole, Kubernetes, instance principal), a file
in its place, an interactive act, and the environment. `--vault-token-file` is the
command-line form of the file case, and it takes a **path** for the reason
invariant 1 gives: a token as an option *value* is visible in `ps`. Decided in
issue #145, recorded in [ADR-007](../decisions/adr-007-vault-token-flag.md);
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

Layers 2 to 5 of that merge are implemented (`sopuli/config/vault_layers.py`,
#136, #153 and #154) and go through the one resolver in `sopuli/settings/`, which
is what makes `vaults.*.tls.verify` ratchet rather than being overwritten by
whichever layer is higher. All of them are merged in one pass, because resolving
two of them first and folding the rest in afterwards reports the winner of the
first pass rather than the layer somebody has to edit. So **the direction is
worth reading off the table rather than off the word "patch"**: `defaults:` is
*below* the declaration and fills gaps; only a profile and the environment are
above it.

Layer 1 arrived in #422 and is **one key wide**: `--vault-addr` hoists
`vaults.*.addr` onto the command line and no flag hoists any other reach key. It
addresses the store `SOPULI_VAULT` or `defaults.vault` names — §6's rule, shared
with the variables rather than restated, so the command line cannot become a
second definition of "the default store" — and is refused where neither names
one. There is no named `--vault-addr NAME=URL`: a run touching two stores uses
`SOPULI_VAULT__<NAME>__ADDR`. `01-configuration.md` §6 has the reasoning,
including why an *address* earns a flag when `mount` does not.
Layer 2 comes in two spellings, decided in #154 —
`SOPULI_VAULT__HCV_PROD__ADDR` names a store, and the unnamed `SOPULI_VAULT_ADDR`
applies to whichever store `SOPULI_VAULT` or `defaults.vault` names, refusing
rather than guessing when neither does. `01-configuration.md` §6 is the
specification.

**The config file is read at the boundary, before a verb runs** (#153). It has to
be: a profile is layer 3 and may supply `output`, and a run whose output format
is settled after the verb started has already chosen an emitter. So
`sopuli/invocation.py` discovers the file, reads it under whichever profile
`--profile` or `SOPULI_PROFILE` asked for, and resolves all six layers; a verb
receives the loaded config rather than loading one. The run document is opened
first, over the command line alone, so that an unreadable file still reports
itself on exit 9 with a document (J7).

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
  `safety.max_targets`, `readonly: true` and `safety.delivery.allowed_methods`
  cannot be relaxed by any source.
  Two of those are flags and three are settings, and the spelling is not
  decoration: this bullet said `--max-targets` until #392, for a flag that has
  never existed and that P5 below now explains will not. The newest of the three
  is scoped `safety.delivery.*` for the same reason — it is a **safety axis**
  restricting what UC-2 delivery may do, not a key of the `delivery:` block it
  governs, and a reader who filed it there would look for it in the wrong file. If config
  says `readonly: true`, no command-line flag re-enables writes — including
  `--force`, which is not a setting and has no layer to arrive on. The first
  command to consume `readonly` is `lock break` (#149), which refuses on **exit
  8**: the file is not invalid, so this is not exit 9; the operator declined in
  advance by writing it, which is what exit 8 already means. `--dry-run` is
  refused with it, because "under `readonly` the mutating verbs are unavailable
  and the read-only verb is how you ask" is a rule that holds without being
  reasoned about per flag.

**`safety.delivery.allowed_methods` is the fifth ratcheted setting, and the
first whose merge is not given by its type** (H6, #453). It restricts which UC-2
delivery methods an estate may use, and it merges by **intersection**: a layer may
narrow the set, never restore a method a lower layer removed. `01-configuration.md`
§9 has the shape and the rules that come with it; what belongs here is why it is
not a union like `confirm_environments`, which would have fitted the existing
machinery without a line of new code.

The answer is what the two do on **upgrade**. A `forbidden_methods` union names
what is refused, so a method added in a later release is permitted by every estate
that has not yet heard of it — the guard widens silently, and it is a guard in
front of putting a live credential on a wire (UC-2 §6). An `allowed_methods`
intersection names what is permitted, so the same new method is unusable until
somebody writes it down. Fail-closed costs a shape in the registry; fail-open costs
a guarantee on every upgrade, and this is not a setting to be wrong about cheaply.

**Layer 4 of the safety settings is merged later than layers 3 and 5** (#424).
A `safety:` block under `defaults` or a profile is a property of the run and is
resolved at the boundary with everything else; one on a target or a group is not,
because which of them applies depends on which targets the run is about to reach
and no selector has been applied yet. So a verb merges those once it has narrowed
its estate and before it builds its plan — the same resolver, the same ratchet,
one pass over prior and new contributions together, for the reason the `vaults.*`
layers are merged in one pass: resolving two layers first and folding the rest in
afterwards reports the winner of the first pass rather than the layer somebody has
to edit.

This is written here because for most of the project it was true of the
documents and false of the tool. The keys parsed, validated, ratcheted and
appeared in `config show`, and nothing read the answer: `readonly: true` on a
target stopped no mutation. A site that marked its production population
`readonly` had been getting no protection and nothing said so. **The refusal is
whole-run**, at plan time, naming the marked targets and the selectors that would
leave them out — `01-configuration.md` §3a has the decision and what the other two
readings cost.

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

The schema is `docs/schemas/sopuli-config-1.8.schema.json`, generated from the
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
readability (#215), vault reachability and clock skew (#216), reports which
backends are installed against which the config declares (P2, #214), and prints a
per-platform remediation hint.

The last of those pairs two things that look unrelated and are not. A vault's
clock is the *other* clock in the system: `sopuli/lock/decide.py` compares a
lease's expiry against this machine's and allows `CLOCK_SKEW` for the two
disagreeing, so a host outside that window takes over locks that are still live
or refuses ones long dead — and it presents as a locking bug rather than as an
NTP problem. Measuring it beside reachability is what makes the assumption
visible before a rotation depends on it. An unreachable vault fails the run at
exit 1, the same as an unreachable target; a degraded one and a skewed clock
warn, because `doctor` must not refuse to survey an estate over a condition the
person running it did not create.

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
- Every mutating command supports **`--confirm`**, with **one exception named
  below**: UC-2's seen reset refuses it as a usage error (exit 2), because there
  the prompt is what establishes that a person is present (#439). **Interactive
  confirmation is required where the configuration asks for it, and nowhere
  else** — decided in #294, and this bullet is the rewrite that decision called
  for. It asked for three triggers and only one survives:

  | trigger | status |
  |---|---|
  | the run reaches an environment in `safety.confirm_environments` | **built** (#292) |
  | ~~the target is marked `environment: prod`~~ | **declined** — it is a built-in `[prod]` in everything but name, and `01-configuration.md` §9 forbids a built-in that takes part in a union ratchet: no layer could ever remove `prod` again. §9's own worked example of the trap is `confirm` |
  | ~~blast radius exceeds `max_targets` (default 1)~~ | **declined** — it would make every multi-target mutation prompt on an estate that wrote no safety block at all, and `max_targets` is a *ceiling* rather than a confirmation threshold. An unset one is no limit, which is not the same claim as a default limit the tool chose |

  **The two declined triggers are declined, not deferred**, which is the half
  worth writing down: an estate that marks a target `environment: prod` and does
  not list `prod` gets no prompt, and that is the specified behaviour rather than
  a gap. `sopuli/safety.py` and `tests/test_cli_confirm_environments.py` pin both.

  Two gates confirm without consulting the setting, and are unaffected: `creds
  rotate` confirms unconditionally under UC-1 §8 step 1, and `lock break` always
  has. **A third is built** (#441): UC-2's seen (`manual`) reset, where the DBA
  sees a working password, confirms every time — decided on review of #457,
  `../use-cases/uc-02-personal-account-passwords.md` §2.

  **That third gate is the one `--confirm` does not answer** (#439), and it is the
  only such gate in the tool. For the other two and for the setting, `--confirm` is
  the yes given in advance. Here it is refused as a usage error, because the prompt
  is not a formality to be waived: the run is about to print a working password to
  a screen, and a yes given ahead of time asserts that somebody is watching when
  the *point* of the gate is to establish that somebody is. It is the same claim
  the seen path's terminal check makes, made twice deliberately — invariant 2 in
  `CLAUDE.md` carries both.

  A profile's `confirm: false` says nobody could be asked, which makes a gated run
  *refuse* (exit 8) rather than proceed.

  **The flag is `--confirm`, and there is no `--yes` alias.** This bullet
  promised one from the first draft and nothing ever built it, which #294's
  review caught: a spec naming a flag the binary does not have is the same defect
  as a trigger that never fires, one document over. Struck rather than
  implemented — the alias buys an operator four keystrokes and costs the CLI a
  second spelling of one flag, and if a site wants it that is a change to D2's
  grammar rather than a footnote here.
- **`safety.max_targets` prevents a wildcard from hitting 200 PDBs by accident,
  and it is a setting rather than a flag.** This bullet offered
  `--limit`/`--max-targets` from the first draft and nothing ever built either,
  which is #294's `--yes` defect one bullet along (#392). Struck rather than
  implemented, and the striking is a statement about the registry rather than a
  preference: `sopuli/settings/registry.py` declares the setting on
  `(PROFILE, OBJECT, DEFAULTS)`, `Setting.layers` is *enforced*, and a
  contribution from an undeclared layer raises — so the flag is not merely
  absent, it would be refused by the resolver until that tuple gained
  `Layer.CLI`.

  **Invariant 10 is not the argument against it**, and saying so is worth a line
  because it looks like the argument. `safety.max_targets` is `MergePolicy.RATCHET`
  and an `int` ratchets to the *minimum*, so a CLI contribution could only lower
  the ceiling — safe by construction, exactly as `safety.dry_run` is safe on
  `Layer.CLI` today. What is actually missing is the case for widening the tuple.
  A ceiling that lives in the file a reviewer reads says what an estate permits;
  one an operator can also pass per run says what an operator chose, and those
  are different claims to put in `invocation.options`. If anyone wants the flag,
  that is where the argument is won — a registry entry and the reason for it, not
  a footnote here.
- Mutating operations take an advisory **lock** keyed on the secret path being
  mutated, so two operators or two CI jobs cannot rotate the same credential
  concurrently. The lock lives in the vault, is compare-and-set guarded, and
  carries a fencing token that is re-checked before every mutation (Q2, decided
  in issue #83). This bullet said "account+target" until then; neither half was
  right. Per-target is meaningless when every target receives the same value, and
  per-account misses two accounts sharing one document. The mutated resource is
  the vault document, and compare-and-set operates on exactly that.
  `check`, `status` and every `--dry-run` take no lock at all — otherwise an
  hourly scheduled check blocks rotations. `sopuli lock status` reads the
  records without taking one (#105), which is how anybody other than the holder
  finds out what exit 7 was about; it also **lists** each store's lock prefix, so
  a record left at a path the config no longer declares is reported rather than
  invisible (#150, marked `declared: false`). That is not a breach of invariant
  5 — the config whitelists what the tool may *touch*, and a survey touches
  nothing.
- **Breaking a lock is a verb, and it is not self-service** (#149).
  `sopuli lock break <vault>:<path>` writes a `released` record over the held
  one, with `cas` set to the version it read — never a delete, because a delete
  leaves the metadata behind and a first acquisition could then never
  compare-and-set against version 0 again. The write bumps the version, which
  **fences** whoever held it: their next check fails and they stop before their
  next mutation. That fence is what makes the verb survivable, so a store that
  cannot fence is refused with exit 5 rather than served a weaker version of it —
  **including one declared `locking: advisory-only`, whatever it turns out to
  support.** The declaration decides, because `locking.break_expired` is refused
  against the same combination (#94) and two guards disagreeing about one
  configuration is worse than either answer. It takes confirmation, and a lock that has *not* expired takes
  `--force` as well; refusing one is exit 7, naming the holder, in the words a
  rotation losing the same lock would use. It may clear a record at a path this
  config does not declare — the leftover `lock status` surfaces is precisely the
  one nobody else can clear — and invariant 5 is untouched because the write
  lands under the store's lock prefix, in a store `vaults:` declares, and never
  on the secret the lock guards.

**Idempotency**

Running a command twice must not make things worse. `apply` against an
already-correct state is a no-op reporting `unchanged`. This is what makes the
tool safe to run from a scheduler.

**Observability**

- Human output by default; `--output json` for one machine-readable object,
  `--output jsonl` to stream per-target events. Scripts consume JSON, never text.
  **`jsonl` is offered only by a verb that streams** (#9): `creds check`,
  `creds apply`, `creds rotate`, `creds generate` and `account reset-password`
  (#535) today.
  Any other verb refuses it as a usage error rather than emitting a stream
  thinner than its document — `03-json-output.md` §5 has the rule, and the
  event schema is `../schemas/sopuli-event-1.7.schema.json`.
- One structured audit record per mutation: who (OS user + vault identity), what
  (account, target, operation), when, correlation id, result. Never the secret.
- A log level, an optional log file, and an explicit statement in the docs that
  secrets are redacted from all output including tracebacks. **This bullet said
  `--log-level` until #392, and there is no such flag.** `profiles: log_level` is
  parsed and validated and has no consumer — the state `sopuli/invocation.py`
  calls "waiting for a consumer" — so what is true today is that the level can be
  *written*, not that anything reads it. Whether the flag ever joins the setting
  is D2's grammar, and naming one here before that is decided is the defect #392
  was opened about.

**Secret hygiene**

- Secrets are never passed as command-line arguments (visible in `ps` and in the
  Windows process list). They come from stdin, a file, or a vault ref. Where a
  flag must name a secret it names its **location**: `--vault-token-file PATH`,
  never `--vault-token VALUE` (#145). The vault-ref branch of this rule does not
  reach vault auth itself — see P2's bootstrap note.
- **One stream, one reader.** stdin carries at most one secret per run, and a
  command that would need two refuses at plan time rather than reading them in an
  order nobody can see. This is banked before anything needs it, because the
  collision is already there: `--from-stdin` (UC-1 §5) claims the pipe for a
  supplied password on `creds apply`, so there is no `--vault-token-stdin` — the
  rule has to exist before that flag can, not after somebody discovers the clash.
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
| D7 | Minimum Oracle version | 11.2 stays in scope, and testing it is cheap: `gvenzl/oracle-xe:11.2.0.2-slim` pulls freely and starts in seconds, so 11.2 is a tier-2 compose service rather than maintainer-only (T1, resolved 2026-08-08). Two independent caveats on Apple Silicon: it has only the 23.x client, which reaches 19c and later, and the 11g XE image is published for linux/amd64 only. Intel macOS, Linux and Windows all have a 19.x client that reaches it. **Re-affirmed 2026-09-09 (#387) on an input this decision did not originally have.** D7 was taken on the cost of *testing* 11.2; what #382 then found is that 11.2 retains the `ALTER USER` text in `V$SQLSTATS` where 18c, 21c and 26ai retain nothing, so a rotation there leaves the password readable to anyone who can read the dictionary. 11.2 stays in scope anyway: the exposure is a window rather than a record — it ages out with the shared pool and one `FLUSH SHARED_POOL` clears it, both measured — and dropping the release would not stop the rotation happening, it would move it to SQL\*Plus, where the same text is retained and nothing is recorded. It is documented instead, in `02-oracle-privileges.md` §4 and P8 and in `../security-model.md` §5. Where 12.1, 12.2 and 19c fall is unmeasured; if 19c turns out to retain it too, this decision is worth taking again, because the population affected stops being "a release nobody should still be running". | decided |
| D8 | CLI framework | click. The grammar (D2) and exit code 2 on usage errors are equally easy in argparse; the deciding factors were `click.testing.CliRunner`, which keeps tier-0 CLI tests in-process and I/O-free, and a real exception hierarchy to hang error mapping on. See `../decisions/adr-002-cli-framework.md`. | decided |
| D9 | Dependency layering | Vendor clients are install extras; base carries only the CLI framework, the YAML parser, `pywin32` on Windows and sopuli itself, and opens no sockets. Stores and drivers follow the same rule, `sopuli-dba[all]` exists but is not the recommended install, a configured-but-uninstalled backend warns in `config validate` and fails `doctor`, and reaches the operator as `error.category: "config"` with exit 9. See `../decisions/adr-006-optional-dependencies.md`. | decided |
| D10 | Which confirmation triggers are built in | **none** (#294). P5 asked for three; `safety.confirm_environments` is the only one, and the other two are declined rather than deferred. A built-in `[prod]` is an unremovable floor under `01-configuration.md` §9's union ratchet — §9 uses `confirm` as its worked example of exactly that trap — and "blast radius over `max_targets`, default 1" would prompt on every multi-target mutation for an estate that configured nothing, while also reading `max_targets` as a threshold when it is a ceiling. What P5 and §9 could not both be is *as written*; §9 governs and P5 now says so | decided |

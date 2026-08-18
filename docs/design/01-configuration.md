# sopuli-dba — Configuration Reference (draft)

Status: draft / sketch
Depends on: `00-principles.md` (P3 defines precedence)

---

## 1. Two shapes, and you start with the simpler one

**One application, and every target is its own → no `applications:` section.**
Put the binding keys at the top level and the file reads like a straightforward
target list. This is the shape most users will ever need.

```yaml
# yaml-language-server: $schema=./sopuli-config-1.2.schema.json
version: 1

vaults: {}          # named secret stores
targets: []         # explicit database endpoints
target_sets: {}     # generated database endpoints (§4)
groups: {}          # named sets of targets
policies: {}        # password + rotation policies
defaults: {}        # inherited settings
profiles: {}        # how this run is invoked (interactive / ci / scheduled) — §5

# --- the single application, inline ---
accounts: []            # which database accounts the tool manages
secret_template: ""     # where each account's password is mastered
policy: ""              # which policy governs them
overrides: []           # per-label exceptions to the above
```

**Two or more applications → move those four keys into `applications:`.**

```yaml
applications:
  - name: acme
    accounts: [...]
    secret_template: "..."
    policy: app-standard
  - name: reporting
    accounts: [report_reader]
    secret_template: "..."
```

The two forms are mutually exclusive: any of the inline binding keys —
`accounts`, `secret`, `secret_template`, `policy`, `overrides` — alongside
`applications:` is a validation error, not only `accounts:`. A leftover
top-level `secret_template:` after a file is converted would otherwise be
silently ignored, which is the mistake §1 calls the one with the worst
consequences.

The inline form is exactly sugar for a single unnamed application entry —
everything below applies to both, with one boundary worth knowing:

**The inline form carries only those five keys.** `targets`, `vault`, `oracle`
and `name` are available only inside `applications:`, because at the top level
`targets:` already means the estate's explicit target list and cannot also mean
one application's target selector. An inline application therefore applies to
all targets, which is the documented default anyway; needing any of those keys
is the point at which a file moves to the `applications:` form.

That boundary is what decides the shape of a real file, more often than the
number of applications does. An estate whose targets exist for more than one
purpose — the worked example in §2 has a CDB root for common-user maintenance —
cannot be bound by the inline form at all, because "all targets" would include
the ones this application has nothing to do with. §2 shows what that looks like.

### What an application entry actually is

It is the statement: *these accounts, in these targets, are mastered by these
secrets, under this policy.* Three things depend on it existing:

- **`check` needs a declared desired state.** Drift is "declared vs. actual". If
  the tool only knows what you typed on the command line, `sopuli creds check`
  with no arguments has nothing to compare.
- **The account→secret mapping is the safety-critical part.** A mistyped
  `--secret` either writes the new password where the app does not read it, or
  rotates the database while the app keeps reading a stale path. Keeping that
  binding in a reviewed file — and refusing to let env or CLI override it — is
  what makes the tool's audit trail mean anything.
- **Fan-out.** One account in eleven PDBs behind one secret is a sentence you
  write once.

---

## 2. Worked example: one application

A fictional but representative estate: Oracle multitenant, one application, one
PDB per tenant across three environments, HashiCorp Vault as master. It needs no
`applications:` section.

```yaml
# yaml-language-server: $schema=./sopuli-config-1.2.schema.json
version: 1

runtime:
  oracle:
    # Optional. Thick mode is required (Native Network Encryption); the client is
    # found on PATH unless this points elsewhere.
    client_lib_dir: C:\Oracle\instantclient_23_0

defaults:
  policy: app-standard
  safety:
    max_targets: 1
    confirm_environments: [prod]

vaults:
  vault-dev:
    type: hashicorp
    addr: https://vault-dev.example.com
    mount: kv
    kv_version: 2
    auth:
      method: token        # --vault-token, then $VAULT_TOKEN, then ~/.vault-token
  vault-test:
    type: hashicorp
    addr: https://vault-test.example.com
    mount: kv
    kv_version: 2
    auth: { method: token }
  vault-prod:
    type: hashicorp
    addr: https://vault.example.com
    mount: kv
    kv_version: 2
    auth: { method: token }

# One explicit target: the CDB root, needed for common-user maintenance.
targets:
  - name: cdb-root-dev
    type: oracle
    environment: dev
    vault: vault-dev
    dsn: "db-dev.example.com:1521/CDBDEV.pdb.example.com"
    admin: { username: C##SOPULI_SVC, auth: prompt }
    oracle: { scope: cdb_root }

# 21 PDB targets, generated: 6 dev + 8 qa + 7 prod. See §4.
target_sets:
  appdb:
    type: oracle
    name: "appdb-{env}-{tenant}"
    dsn: "{host}:{port}/{tenant}{pdb_suffix}.{db_domain}"
    environment: "{env}"
    vault: "{vault}"
    admin: { username: C##SOPULI_SVC, auth: prompt }
    oracle: { scope: pdb, container: "{tenant}{pdb_suffix}" }

    for_each:
      env:
        dev:
          host: db-dev.example.com
          port: 1521
          pdb_suffix: dev
          db_domain: pdb.example.com
          vault: vault-dev
          tenant: [alpha, beta, gamma, delta, epsilon, zeta]
        qa:
          host: db-test.example.com
          port: 1521
          pdb_suffix: qa
          db_domain: pdb.example.com
          vault: vault-test
          tenant: [alpha, beta, gamma, delta, epsilon, zeta, eta, theta]
        prod:
          host: db-prod.example.com
          port: 1521
          pdb_suffix: prod
          db_domain: pdb.example.com
          vault: vault-prod
          tenant: [alpha, beta, gamma, delta, epsilon, zeta, eta]

    # Exceptions, by generated target name. Any key may be patched.
    overrides:
      appdb-qa-delta:
        dsn: "192.0.2.75:1521/deltaqa.legacy.example.com"     # migrated host
      appdb-qa-epsilon:
        dsn: "db-test.example.com:1521/epsilonqa2.pdb.example.com"

groups:
  app-pdbs:  { match: { target_set: appdb } }
  dev-pdbs:  { match: { target_set: appdb, env: dev } }
  prod-pdbs: { match: { target_set: appdb, env: prod } }

policies:
  app-standard:
    password:
      length: 24
      charset: alnum_safe        # A-Za-z0-9 plus _ # $ - . + = ~ ^
      first_char: alpha
      require: { upper: 1, lower: 1, digit: 1, special: 1 }
    rotation:
      strategy: rollover
      rollover_hours: 24
      keep_previous: true
      max_age_days: 90
    verify:
      method: login              # profiles may override this — see §5
      lockout_margin: 2
    account:
      unlock_if_locked: false

# How a run is invoked, as opposed to what it points at. See §5.
profiles:
  ci:
    verify: { method: hash }     # no login attempts from an unattended runner
    output: json
    confirm: false
    safety: { max_targets: 200 }
  scheduled:
    verify: { method: hash }
    output: jsonl
    log_level: warning

# ---------------------------------------------------------------------------
# The single application. It names its targets, so it uses `applications:` --
# see "why not the inline form" below.
# ---------------------------------------------------------------------------
applications:
  - name: acme
    targets: { group: app-pdbs }        # the generated PDBs, not the CDB root
    accounts:
      - acme_web_user
      - acme_api_user
      - acme_batch_user
      - acme_integration_user
      - acme_search_user
      - acme_svc_user

    # One JSON document per tenant secret, mapping username -> password.
    secret_template: "tenants/{tenant}#DB_CREDENTIALS/{account}"
    policy: app-standard

    # dev shares one document across every dev PDB rather than one per tenant.
    overrides:
      - where: { env: dev }
        secret_template: "tenants/_shared#DB_CREDENTIALS/{account}"
```

Both `ci` and `scheduled` above assume `--method hash` exists. It doesn't yet:
`check`'s **default** is `login` unconditionally regardless of profile
(`02-oracle-privileges.md` §2, decided in #86), and `hash` itself is still an
open spike (#90). These examples are not yet buildable as written — the tool
does not silently substitute `login` for a `method:` it doesn't recognise, any
more than it would for a typo. If #90 comes back negative, `hash` is removed
from the CLI surface entirely and these two examples need editing to
`method: login`, guarded by `LCOUNT` where the optional `SYS.USER$` grant is
present — the unattended win there is `--lockout-margin`, not skipping the
login attempt.

### Why not the inline form

§1 says one application means no `applications:` wrapper, and this file has one
application. It uses the wrapper anyway, for the reason §1 gives: *needing any of
those keys is the point at which a file moves to the `applications:` form* — and
the key needed here is `targets`.

`cdb-root-dev` is in the estate for common-user maintenance, which is a different
job from this application. The inline form applies to **all** targets by
definition, so it would bind `acme_web_user` to the CDB root as well — and
`{tenant}` cannot even render there, since that target carries no labels. The
file would not load, and if it did it would describe an estate nobody meant.

So the rule is sharper than "one application": **the inline form fits an estate
where every target is that application's.** The moment the estate serves a second
purpose — another application, or a use case that is not designed yet — the
binding has to say which targets it means, and only `applications:` can.

Commands against it:

```bash
sopuli creds check                                 # everything declared
sopuli creds check  --select env=dev               # all dev PDBs
sopuli creds rotate --select env=dev,tenant=beta
sopuli creds rotate --group prod-pdbs --confirm
sopuli creds apply  --target appdb-qa-delta --account acme_web_user

sopuli creds check --profile scheduled             # same targets, different behaviour
```

Note what the config bought: `sopuli creds check` with no arguments is
meaningful, because `accounts` + `secret_template` + the generated targets say
what *should* be true.

Note also what the last line does **not** do: `--profile scheduled` changes how
the run behaves, not which targets it touches. That distinction is §5.

---

## 3. Worked example: two applications

The moment a second application has its own secret layout in the same databases,
the inline form cannot express it — one `secret_template` cannot serve two
layouts. Move to `applications:`; nothing else changes.

```yaml
applications:
  - name: acme
    accounts: [acme_web_user, acme_api_user, acme_batch_user]
    targets: { group: prod-pdbs }
    secret_template: "tenants/{tenant}#DB_CREDENTIALS/{account}"
    policy: app-standard
    overrides:
      - where: { env: dev }
        secret_template: "tenants/_shared#DB_CREDENTIALS/{account}"

  - name: reporting
    accounts: [report_reader]
    targets: { group: prod-pdbs }
    secret: "reporting/{env}/db#password"          # one field, not a JSON map
    policy: app-standard

  - name: monitoring
    accounts: ["C##MONITOR"]
    targets: [cdb-root-dev]
    secret: "ops/monitoring/db/common#password"
    policy: app-standard
    oracle:
      container_clause: ALL                        # ALTER USER … CONTAINER=ALL
```

```bash
sopuli creds check                                 # all three applications
sopuli creds rotate --application reporting
sopuli creds rotate --app acme --select env=dev    # --app is an accepted alias
```

### Fields of an application entry

| Key | Meaning |
|---|---|
| `name` | required and unique in the `applications:` form; absent in the inline form — it is what `--application` selects on |
| `accounts` | list of database usernames |
| `targets` | list of target names, `{ group: NAME }`, or `{ match: {...} }`; defaults to all targets |
| `vault` | store name; defaults to the target's vault, then `defaults.vault` |
| `secret` / `secret_template` | SecretRef, literal or templated (§7). Mutually exclusive: one entry uses one of them |
| `policy` | policy name |
| `oracle` | vendor-specific options, e.g. `container_clause` |
| `overrides` | list of `{ where: {labels}, ...keys }` patches applied to matching targets. `where` is required, and the patchable keys are `vault`, `secret`, `secret_template`, `policy` and `oracle` — **not `accounts`**, see §10 |

`where:` matches **labels**, so it reaches generated targets by their dimension
values and explicit ones by the `labels:` they declare. `environment` is a field
rather than a label (§4) and is not matched on.

Every override that matches a target applies, in document order, and a later one
wins key by key. That is what lets a broad rule be narrowed by a later exception
instead of writing every case out separately; it also means two overrides that
both match and both set the same key resolve to the later one, so order is worth
keeping deliberate.

Resolution, once a target is selected — implemented in `sopuli/config/bindings.py`:

| Key | Resolves as |
|---|---|
| `secret` / `secret_template` | the last matching override's, else the entry's. The tokens are then expanded per account and target (§7) |
| `vault` | the ref's own `vault:` prefix if it has one, else the last matching override's, else the entry's, else the target's, else `defaults.vault` |
| `policy` | the last matching override's, else the entry's, else `defaults.policy` |

This is the chain the file itself describes. The `SOPULI_*` and command-line
layers above it are P3's and belong to the precedence resolver, not here — a
config file can be read without knowing what environment it will be read in.

---

## 3a. The estate: vaults, targets, groups

§2 shows these in use; this says what the fields are. Implemented in
`sopuli/config/vaults.py`, `targets.py`, `target_sets.py` and `groups.py`.

### `vaults:` — a mapping of name to store

| Key | Meaning |
|---|---|
| `type` | **required** — the backend: `hashicorp`, `oci`, `file`, `keyring` (P2). AWS and Azure are listed there as "later" and are refused until they exist. A declared type is validated here and *resolved* to a client only when something connects — see below (ADR-006) |
| `addr` | backend address, where the backend has one |
| `mount` | KV mount point (HashiCorp) |
| `kv_version` | `1` or `2` — different backends with different capabilities, not a version to branch on casually (P2) |
| `namespace` | HashiCorp Enterprise namespace, sent as the `X-Vault-Namespace` header. Absent means no namespace |
| `timeout_s` | request timeout against this store. `httpx` has no default (ADR-005), so this is not optional the way a stdlib client's would be |
| `tls` | `{ ca_file, ca_path, client_cert, client_key, server_name, verify }` (ADR-005) — see below |
| `auth` | how to authenticate, and where the material comes from — see below |
| `non_production` | marks a store that must never master a `prod` target (§10). Absent means production |
| `locking` | `required` (default) or `advisory-only` — whether this store can hold P5's advisory lock. See below |

#### `tls:` — transport verification (ADR-005)

`ca_file` / `ca_path` name a CA bundle; `client_cert` / `client_key` are for
mutual TLS; `server_name` overrides SNI, for a store reached by an address that
does not match the certificate (an SSH tunnel, a load balancer by IP). All four
are plain paths or strings, not MaterialRefs — none of them is a credential.

`verify` (default `true`) is the one field here that is not ordinary config: it
falls under P3's safety ratchet, so the *resolved* value is the strictest across
every layer, and no higher-precedence source can turn verification off once a
lower one has it on. A run with verification disabled emits a warning
diagnostic into the run document, so the weakening is visible in the audit
trail and not only in the config file. `VAULT_SKIP_VERIFY` (§6) is read and
refused with a config error rather than silently ignored — this is the one
environment variable in the honoured-third-party list that the tool does not
honour, precisely because it would otherwise bypass the ratchet from outside
the config it governs.

Only `type` is required. A file backend has no address, and P2 puts per-backend
validation behind the store interface, so demanding a HashiCorp shape of every
entry would be exactly the top-level vendor bias P1 forbids.

#### A declared backend that is not installed (ADR-006)

A backend's client is an install extra (P2, D9): `sopuli-dba[oci]` brings the OCI
SDK, `sopuli-dba[hashicorp]` brings `httpx`, and the base install brings neither.
So `type: oci` is a perfectly ordinary thing to write on a machine that cannot
reach OCI, and the file has to keep meaning the same thing on both.

It does, because **declaring a store is config and reaching one is not.** Every
rule in §10 that touches a `vaults:` entry — unknown keys, the MaterialRef
grammar, `non_production` against a `prod` target, `locking.break_expired`
against `advisory-only` — is decided from the file. None of them needs the
client. A config naming eleven backends therefore loads, validates and prints
with none of them installed, and `config show --resolved`, `target list` and
`config validate` all work as they always did.

What changes is where it stops:

| Moment | With the backend missing |
|---|---|
| load, `config validate`, `config show`, `target list` | works. `config validate` adds a **warning** (§9, §10), and exits 0 |
| any command that resolves the store to a client | **error**, `error.category: "config"`, code `SOPULI-20001`, exit 9 (`03-json-output.md` §3) |
| `sopuli doctor` | **failure**. Its question is "can I reach my vaults", and this is a no |

```
$ sopuli creds check --application acme
error: vault "oci-prod" declares type "oci", but that backend is not installed
       install it with:  pip install "sopuli-dba[oci]"
exit 9
```

The message names the extra rather than the import that failed, because the
extra is what the operator can act on. It is a config-category error under
invariant 4's rule — a command that needs something unavailable fails at plan
time, naming what is missing, rather than partway through a rotation.

#### `vault:` names a store; `vaults:` describes one (C13, decided)

**`vault:` is always the name of a store and never a block** — under `defaults:`,
in a profile, on a target, on an application, in an `overrides:` patch, and as a
SecretRef's `[<vault>:]` prefix. `SOPULI_VAULT` overrides that name.

Settings *of* a store are reached by naming it, under `vaults:`. `defaults:` and
a profile may each carry a `vaults:` block whose entries are **partial** — they
patch a store declared at the top level rather than declaring one:

```yaml
defaults:
  vault: vault-dev              # which store, by name
  vaults:
    vault-dev:
      addr: https://vault-dev.example.com   # something about that store
```

This is the environment table's shape written in the file: §6 already has
`SOPULI_VAULT` for the default store's *name* and
`SOPULI_VAULT__VAULT_DEV__ADDR` for one setting of one named store, so the two
sides of the config now address a store the same way. It also keeps every layer
of P3 stating which store it is talking about, which the alternative — a key
meaning "whichever store is active" — could not: auth written for dev would
follow a changed `vault:` to prod without anything in the file having changed.

§5 has the profile case and the keys a profile may patch. Parsing these blocks
arrives with the vault layer (#103); until then the closed whitelists refuse
them, because a shape nothing reads is a contract no test can mean anything by.

### `locking:` — on a store, and as a block

P5's advisory lock lives in the vault, keyed on the secret path being mutated
(Q2, decided in #83). Two keys configure it, and they are one decision seen from
two ends.

**On a store**, `locking:` says whether that store can hold a real lock:

```yaml
vaults:
  legacy-kv:
    type: hashicorp
    mount: secret
    kv_version: 1
    locking: advisory-only      # default: required
```

A lock needs compare-and-set. P2's capability table gives `cas` to KV v2 and,
through ETags, to OCI; KV v1 and the file backend have none. Everywhere else a
missing store capability is emulated in the payload — but "not atomic" is exactly
what CAS is for, so there is nothing to emulate, and under the default a mutating
command **refuses** on a store that cannot lock, with `error.category: capability`
naming this key. `advisory-only` is the operator saying they know: the record is
still written, every run emits a warning diagnostic so the weakening reaches each
run's audit trail rather than only the config file, and the run document reports
`lock.mode: none`. The documented remedy is `vault kv enable-versioning`, which
is in place on an existing mount. The file backend does not attempt `flock`: it
is documented as non-production, and one rule is worth more here than a
marginally stronger local mutex.

**As a block**, under `defaults:` or in a profile:

```yaml
defaults:
  locking:
    break_expired: true         # default: off
```

`break_expired` lets an unattended runner take over a lock that is past
`expires_at` plus a 60-second clock-skew margin. Breaking one is otherwise not
self-service — the holder may be a colleague mid-rotation rather than a process
that died — and what makes automatic takeover safe enough to exist is the fence:
the takeover write bumps the vault's version, so the run that was broken
discovers it at its next check and stops before its next `ALTER USER`.

Which is why **the two may not be combined**: `break_expired: true` beside any
store marked `advisory-only` is refused when the config is read. Without CAS
there is no fence, and unattended breaking without a fence is the recipe for two
runners applying different passwords to different targets, each believing it
holds the lock.

Both are config-only, per invariant 10 — no flag and no environment variable. A
store's key could not be anything else, and `break_expired` is deliberately the
same: a flag that unblocks a stuck run at 17:00 on a Friday is the one thing
nobody would remove afterwards.

### `auth:` — the method, and where its material lives

Implemented in `sopuli/config/auth.py`, which is also where the target `admin:`
grammar lives: the two positions share a grammar and not a vocabulary.

An `auth:` block is `{ method: NAME, ...the keys that method takes }`. Where a
method needs nothing else it may be written as the bare method name —
`auth: token` is sugar for `auth: { method: token }`. A method that needs material
may **not**: there is nowhere in a scalar to say where the material comes from.

| `method` | Its keys |
|---|---|
| `token` | `token` (optional — without it, `--vault-token`, then `$VAULT_TOKEN`, then `~/.vault-token`) |
| `approle` | `role_id`, `secret_id`, and optionally `mount` |
| `kubernetes` | `role`, `jwt`, and optionally `mount` |
| `oidc` | optionally `role` and `mount` |
| `userpass` | `username`, `password`, and optionally `mount` |
| `instance_principal`, `resource_principal` | none |
| `config_file`, `session_token` | optionally `profile` |

A key belongs to the method that uses it: `role_id` under `method: token` is an
error naming the method in force, because it is a leftover from an edit that
changed the method rather than a typo. `mount` here is the **auth** mount, not the
KV `mount:` on the vault itself, and it defaults to the method's own name.

### MaterialRef — where auth material comes from

Everything secret-bearing above — `token`, `role_id`, `secret_id`, `jwt`,
`password` — is a **MaterialRef**: a one-key mapping, exactly one of `env` or
`file`.

```yaml
vaults:
  vault-prod:
    type: hashicorp
    addr: https://vault.example.com
    auth:
      method: approle
      mount: approle                                   # optional
      role_id:   { env: SOPULI_VAULT_ROLE_ID }
      secret_id: { file: /run/secrets/vault_secret_id }

  vault-dev:
    type: hashicorp
    addr: https://vault-dev.example.com
    auth: { method: token, token: { file: ~/.vault-token } }

  vault-oci:
    type: oci
    auth: instance_principal
```

This is **not** a SecretRef (§7). A SecretRef addresses a value *in* a vault; this
is what you need before you have a vault, and the two are named differently so
that the chicken-and-egg stays visible instead of being papered over by one word
meaning both.

The one-key shape is preferred over an `_env` / `_file` suffix convention because
it makes P2's constraint **structural**: there is no slot for an inline string, so
"auth material is never written to the config file in plaintext" is enforced by
the shape rather than by a validation rule someone has to remember to write. A
string where a MaterialRef belongs is refused with a message that says so, rather
than as a type complaint.

A token *helper* (`command:`) is deliberately absent. Shelling out from a
credential tool deserves its own decision, and Vault's own helper is the only real
use.

Two properties follow from the shape and are worth stating, because they are the
reason for it:

- **A source chain stays inside one method.** `method: token` falls through
  `--vault-token` → `$VAULT_TOKEN` → `~/.vault-token`, and stops there. An earlier
  draft fell through to AppRole after that; falling into a *different* method makes
  an authentication failure impossible to explain.
- **Identity is inline, proof is not.** `role`, `username`, `profile` and `mount`
  name *who* rather than prove it, so they are written as they are. `role_id` is
  arguably an identifier too, and is a MaterialRef anyway: carving out one field
  that may be inline sets a precedent to be re-litigated for every method added
  later. Uniform now; relax it if it turns out to be friction.

### `targets:` — a list of endpoints

The same field set describes a `target_sets:` template, which is why one reader
builds both: a field an explicit target has and a generated one does not would be
something the estate can express and the set silently cannot.

| Key | Meaning |
|---|---|
| `name` | **required, unique** — what `--target` selects on. In a target set this is the *name template* |
| `type` | **required** — the driver selector (P1). Only `oracle` exists; a target the tool cannot drive is refused while the file is being written, not at the first connection |
| `dsn` | **required** — `host:port/service`, or a TNS alias |
| `environment` | first-class rather than a label, because safety rules key on it (§4). Not overridable from the environment (§6) |
| `vault` | which store masters passwords here |
| `admin` | `{ username, auth }` — the credential that reaches the database. There is no password field, and there will not be one (P2). See below |
| `oracle` | `{ scope, container }` — **not** an application's `oracle:` block. Both are assertions about the database rather than settings on it, and both are optional. See below |
| `labels` | free labels for selection (C8). A generated target gets its dimension values as labels automatically |
| `safety` | a `safety:` block (§9) |

A block that is present and empty — `oracle: {}`, `admin: {}` — is an error.
Absent and empty mean the same thing to the tool, so the difference between them
is a sentence somebody started and did not finish.

`type`, `oracle.scope` and `admin.auth.method` are closed sets. A free string
there means `scope: cdb-root` loads happily and the tool then operates in a
different container from the one that was meant — and this file is the whitelist
(invariant 5). Widening a set is a one-line change once the reference names the
new value.

### `admin:` — the credential that reaches the database

The bootstrap problem P2 states: the DBA credential the tool uses is itself a
secret, and it cannot come from the vault the tool has not authenticated to yet.
So `admin.auth` names one of P2's four sources, **in its order of preference**,
in the same grammar as a vault's `auth:` (§3a) and with its own vocabulary.

| `method` | Its keys | |
|---|---|---|
| `external` | none | a wallet / secure external password store, Kerberos, OS auth |
| `vault` | `secret` | a vault authenticated by machine identity, not by a password |
| `prompt` | none | interactive |
| `env` | `password_env` | supported, and flagged low-assurance in output (P2) |

```yaml
targets:
  - name: cdb-root-dev
    type: oracle
    dsn: "db-dev.example.com:1521/CDBDEV.pdb.example.com"
    admin: { username: C##SOPULI_SVC, auth: prompt }

  - name: cdb-root-qa
    type: oracle
    dsn: "db-test.example.com:1521/CDBQA.pdb.example.com"
    admin:
      username: C##SOPULI_SVC
      auth: { method: vault, secret: "ops/sopuli/qa/admin#password" }

  - name: cdb-root-prod
    type: oracle
    dsn: CDBPROD                                   # a TNS alias, see below
    admin: { auth: external }
```

`auth: prompt` as a bare value is sugar for `{ method: prompt }`, legal where the
method needs nothing else — which is why §2's and §4's examples read as they do.

**`method: vault` names a whole SecretRef** (§7), so it takes a `vault:` prefix
and the template tokens without a second addressing syntax to learn; with no
prefix it resolves in the target's own `vault:`. It is required — there is no
default admin path to fall back on, and a credential tool guessing at one is how a
run authenticates as something nobody chose.

A `{placeholder}` in that ref is rendered from a **target set's** dimensions, like
every other string a template writes. On an explicit target it is an error, because
nothing renders it: §7's tokens are expanded per account and target for an
application's ref, and an admin credential belongs to no account. Who — if anyone —
should expand `{env}` there is undecided, and refusing is the reversible half of
that: §10 already says an unresolved placeholder is an error rather than an empty
string.

**`method: env` names its own variable.** §6's single `SOPULI_DB_ADMIN_PASSWORD`
does not scale past one admin credential, so `password_env:` says which variable
holds this one; absent, it is that pair. Either way this source stays flagged
low-assurance wherever it is reported.

**`external` constrains the rest of the target**, and both halves are errors
rather than warnings:

- the `dsn` must be a **TNS alias** resolvable through `TNS_ADMIN`. External auth
  connects as `/@alias` and the wallet is keyed on that alias, so an EZConnect
  string has no entry to match — and the failure surfaces as an authentication
  error, which is the most misleading way for a config mistake to appear.
- a `username:` is **refused**, not ignored. The wallet supplies it. A file that
  appears to name the connecting account while the wallet names another is worth
  stopping for, not least because "who" is half of every audit record (P5).

Both are checked against the *expanded* estate, so an `overrides:` patch that
introduces the combination is caught too.

### `oracle:` on a target — assertions, not settings

`scope` is one of the scopes P1 names, spelled the way the run document already
spells them:

| `scope` | |
|---|---|
| `non_cdb` | single-instance non-CDB (11.2, 12.1 non-CDB, 19c non-CDB) |
| `cdb_root` | the CDB root — common users, `CONTAINER=ALL` vs `CONTAINER=CURRENT` |
| `pdb` | a pluggable database, reached by its own service name |
| `app_root` | an application root — a distinct scope, not the same as the CDB root |
| `app_pdb` | an application PDB |

That is `scope.type` from
[`sopuli-run-1.7.schema.json`](../schemas/sopuli-run-1.7.schema.json), minus
`unknown`. Adopting the vocabulary the run document has typed since it was written
means the word a file *asserts* and the word the tool *reports* are the same word,
so a mismatch between them needs no translation to explain. `unknown` is
observation-only: something the driver may find, never something a file can claim.

**Both keys are assertions.** The driver detects the real scope and container when
it connects (P1 `resolve_scope`), so what the file writes is a claim to be checked
rather than a setting to be applied — which is what UC-1's pre-flight already asks
for: *"the connection really is in the container the config claims"*
(`uc-01-app-credential-sync.md` §4). A declared value that disagrees with what the
driver finds is an **error naming both**. That is worth more than it sounds: it
catches a `dsn:` edit that silently repointed a target at a different container,
and a PDB whose role changed under an estate that still describes the old one —
neither of which any amount of load-time validation could see.

Being assertions, both are optional. A target that says nothing about its scope is
not incompletely configured; it just makes no claim, and the driver reports what it
found.

**They do not constrain each other.** `scope: pdb` with no `container` is fine
unless something actually needs the value, and the thing that needs it is §7's
`{container}` token — where §4 rule 4 already makes an unresolved placeholder an
error, for a reason about the *template* rather than about the connection. So the
rule falls out of one that already exists rather than being a new one. `scope:
cdb_root` beside `container: CDB$ROOT` is redundant but not contradictory, so the
connect-time comparison decides it rather than the schema. `container_clause: ALL`
keeps its own guardrail (UC-1 §6.2) and belongs to an application, not here.

### `groups:` — a mapping of name to selection

| Key | Meaning |
|---|---|
| `match` | **required** — the labels a target must carry. May not be empty: a group matching everything is `--all` with a name that hides what it does |
| `safety` | a `safety:` block, so a whole population can be marked `readonly` in one place |

### `safety:`, wherever it appears

| Key | Meaning |
|---|---|
| `max_targets` | at least 1. Use `readonly: true` to block changes entirely — `max_targets: 0` is far more likely to be a slip that then blocks every run |
| `confirm_environments` | environments that always require confirmation |
| `readonly` | refuse every mutation |

Every field is optional, and an unset one stays unset rather than taking the
built-in default. §9 resolves safety by taking the *safest* of all layers rather
than the last one, and "safest of all layers" needs to know which layers said
nothing.

---

## 4. Target templating (`target_sets`)

Listing 35 PDBs by hand is not viable, and the list changes when a tenant is
added. A target set generates targets from a name template, a DSN template, and
one or more dimensions.

### Rules

1. `for_each` has exactly **one outer dimension** — its key names the dimension
   (`env` above), and its values are maps of variables.
2. Inside an outer value, **at most one** variable whose value is a list becomes
   the **inner dimension**, expanded per outer value. That is what allows a
   different tenant list per environment. A value may have none, in which case it
   generates a single target.
3. Every combination produces one target. `name` must render uniquely; a
   collision is a validation error.
4. Every `{placeholder}` in `name`, `dsn` and other string fields is substituted
   from the dimension values and variables in scope. An unresolved placeholder is
   an error, never an empty string.
5. `overrides` patch generated targets **by rendered name**, after generation.
   Any key may be patched except `name` itself — the rendered name is the key the
   patch is found by.
6. Nesting stops at two levels. If you need three, write a second target set —
   this is deliberate, because a general templating language in a credential tool
   is a debugging liability. Concretely, all three of these are errors rather
   than something quietly flattened: a second list variable in one value, a
   variable whose value is a mapping, and a list of lists.
7. Where a value has an inner dimension, it must be the **same variable in every
   value** of the outer one. Dimension values become labels, so a set where `dev`
   expands over `tenant` and `qa` over `shard` is two populations that no single
   `--select` can address, written as though it were one estate. The remedy is
   rule 6's: write a second target set.

Variables are substituted as written, so `port: 1521` and `port: "1521"` render
identically. Two things to know: a boolean is refused rather than stringified
(`pdb_suffix: true` would render as `True`), and an unquoted value with a leading
zero is a YAML 1.1 octal — `port: 0640` is the number 416. Quote anything whose
digits matter.

### What substitution is, exactly

Implemented in `sopuli/config/expansion.py`, and deliberately not a template
language (C7): `{name}` is looked up in one flat scope and that is all there is.

| | |
|---|---|
| **In scope** | the outer dimension (`{env}`), the scalar variables of the value being rendered, and the inner dimension's current value (`{tenant}`) |
| **Substituted in** | every string the template writes — `name`, `dsn`, `environment`, `vault`, `admin.username`, `admin.auth.secret`, `admin.auth.password_env`, `oracle.container`, `labels` keys and values, `safety.confirm_environments`. A field left unrendered would reach a connection string, or a vault, with its braces intact |
| **Not substituted in** | `type`, `oracle.scope`, `admin.auth.method`. They are closed sets, so a placeholder there is already refused when the set is read |
| **No escaping** | there is no way to write a literal brace. An unbalanced or empty one (`{`, `{}`) is an error, not a literal |
| **Shadowing** | a variable may not share the name of the dimension it sits under — `for_each: { env: { dev: { env: production } } }` gives `{env}` two meanings, and either choice silently decides a rendered secret path |

An `overrides:` patch is rendered in the same scope as the target it patches, so
a placeholder is resolved there too rather than reaching a DSN intact. A patch
merges rather than replaces: `oracle: { container: X }` keeps the `scope:` the
template set, `labels:` keeps the dimension labels `--select` found the target
by, and a key the patch does not mention keeps its generated value. The one
exception is `admin.auth`, which is replaced as a whole: its keys belong to its
`method:`, so merging `{ method: prompt }` over `{ method: vault, secret: … }`
would leave a prompt carrying a ref that means nothing. Patching
`admin: { username: … }` alone still keeps the `auth:` the template chose. A `safety:`
block written in a patch is not a way to relax one — §9 resolves the effective
setting by taking the safest of all layers.

### Labels

Each generated target carries its dimension values as **labels**
(`target_set: appdb`, `env: qa`, `tenant: delta`). Labels are what make
selection ergonomic:

```bash
sopuli creds check --select env=dev
sopuli creds check --select env=prod,tenant=beta
sopuli target list --select env=qa
```

```yaml
groups:
  dev-pdbs: { match: { target_set: appdb, env: dev } }
```

A `--select` is every pair at once, the same conjunction a group's `match:`
means — one selector language whether it was written in the file or typed. It
may be repeated (`--select env=qa --select tenant=beta`), which accumulates.
Two values for one key is refused rather than read as "or": a conjunction can
only answer that with an empty estate, and set membership is exactly what C2
leaves open. An implemented command shows what it filtered by, so output that
covers part of an estate cannot be mistaken for the whole of a small one.

Explicit `targets:` entries may carry `labels: {}` of their own, so the two kinds
mix in one selection. `environment:` remains a first-class field rather than a
label, because safety rules key on it.

Only the dimensions become labels, not every variable: `host` and `db_domain`
say how to connect, and offering them to `--select` would offer choices that
select nothing meaningful. A template may add labels of its own, and one that
contradicts a dimension — `labels: { env: production }` under `for_each: { env:
… }` — is an error rather than a silent winner either way. Writing the same
value twice (`labels: { env: "{env}" }`) is redundant and allowed.

### Seeing what it produced

Generation is invisible until it goes wrong, so `target list` is a first-class
command:

```
$ sopuli target list --select env=qa --output text
config: /etc/sopuli/config.yaml
select: env=qa

NAME                DSN                                              ENV  SCOPE  SOURCE
appdb-qa-alpha      db-test.example.com:1521/alphaqa.pdb.example.com  qa   pdb    target_set appdb
appdb-qa-beta       db-test.example.com:1521/betaqa.pdb.example.com   qa   pdb    target_set appdb
appdb-qa-delta      192.0.2.75:1521/deltaqa.legacy.example.com        qa   pdb    override
appdb-qa-epsilon    db-test.example.com:1521/epsilonqa2.pdb.example…  qa   pdb    override
…
8 targets (6 generated, 2 overridden)
```

No VAULT column, unlike the estate table in `config show --resolved`: which
store masters a target is a fact about the binding, and this view is about the
target. Both are offline, and both count the estate with the same code, because
two commands disagreeing about how many databases are in scope is worse than
either being wrong alone.

`sopuli config show --resolved` expands target sets fully, so what the tool will
act on is always inspectable without connecting to anything.

---

## 5. Profiles — how a run is invoked

### The distinction that makes them coherent

**`environment` and labels describe what you are pointing at. A profile describes
where you are running from.**

`--profile scheduled` never changes which targets or accounts are in scope. It
changes how the tool behaves while it works on them: whether it may prompt,
whether it verifies by login or by hash comparison, what it prints, how loudly it
logs.

This is the one thing to get right, because a selector-shaped option that is not
a selector is a bad footgun in a tool that rotates credentials. Hence the naming
rule below.

### Why the concept exists at all

The same config is used from a laptop, from a CI job, and from a scheduler, and
those three want genuinely different behaviour:

| | interactive | ci | scheduled |
|---|---|---|---|
| may prompt for confirmation | yes | no | no |
| verification method | `login` | `hash` | `hash` |
| output | text | json | jsonl |
| blast-radius guard | tight, a human is watching | wide, the plan is reviewed in the PR | wide |

Without profiles this lives in environment variables scattered across a workflow
file — unversioned, unreviewed, and invisible when someone asks why the nightly
run behaved differently from the one they just did by hand.

The clearest evidence the need is real: an earlier draft had
`policies.*.verify.scheduled_method`, which is run-context configuration hiding
inside a password policy because there was nowhere else to put it. That key is
gone; a profile overriding `verify.method` replaces it.

### What a profile may contain

A closed list. Anything else is a validation error.

| Key | Effect |
|---|---|
| `vault` | which named store to use, by name |
| `vaults.<name>.*` | how to *reach* a named store — `addr`, `mount`, `kv_version`, `auth`. This is what lets a profile say "token from a laptop, AppRole from CI" without re-declaring the store. Not `type`, and not `non_production` or `locking` — see below (C13) |
| `verify.method` | `login` \| `hash` \| `both` \| `none` |
| `verify.lockout_margin` | how close to `FAILED_LOGIN_ATTEMPTS` to stop trying |
| `safety.*` | `max_targets`, `confirm_environments`, `readonly` |
| `locking.break_expired` | may an unattended run take over an expired lock (#83)? The profile is where this belongs: it is a property of running without anybody watching |
| `confirm` | whether interactive confirmation is possible at all |
| `output` | `text` \| `json` \| `jsonl` |
| `log_level`, `log_file` | |
| `db.connect_timeout_s`, `db.query_timeout_s` | slower budgets for unattended runs |
| `rotation.strategy` | e.g. force `staged` where no human can watch a rollover. Only `strategy` — `rollover_hours` and the rest describe the credential's lifecycle, which belongs to the estate |

### Reaching a store differently, without redeclaring it

A profile's `vaults:` entries are **partial** — they patch a store declared in
the top-level `vaults:`, key by key, and naming a store that does not exist there
is an error rather than a new declaration. The case this exists for:

```yaml
vaults:
  vault-prod:
    type: hashicorp
    addr: https://vault.example.com
    mount: secret
    auth: { method: token }          # a laptop, with ~/.vault-token

profiles:
  ci:
    vault: vault-prod
    vaults:
      vault-prod:
        auth:                        # the same store, a different way in
          method: approle
          role_id:   { env: SOPULI_VAULT_ROLE_ID }
          secret_id: { env: SOPULI_VAULT_SECRET_ID }
```

`type` is not patchable: a store that is HashiCorp from a laptop and OCI from CI
is two stores, and pretending otherwise would put a `vaults:` name in the audit
trail that means different things depending on how the run was started.
`non_production` and `locking` are not patchable either, and for the sharper
reason — both are guardrails. `non_production` is what §10 checks a `prod` target
against, and `locking: advisory-only` is the operator conceding a store cannot
hold P5's lock. A profile that could set either would be a way to relax a safety
setting from the invocation context, which invariant 10 forbids outright.

### What a profile may not contain

Rejected at validation, with a message naming the key:

- `accounts`, `applications`, `secret`, `secret_template` — the account→secret
  binding is the safety-critical part and must not vary by how you invoked the
  tool. This is the same rule as §6's "not overridable" list, for the same reason.
- `targets`, `target_sets`, `groups`, or anything that selects — a profile is not
  a selector.
- `environment` on any target — you cannot relabel prod as dev by choosing a
  profile.
- `policies.*.password.*` — a weaker password policy is a reviewed config change,
  never a side effect of running from CI.
- `vaults.<name>.type`, `.non_production`, `.locking`, and any `vaults:` name not
  declared at the top level — see above.

### Resolution rules

1. **Exactly one profile is active.** Selected by `--profile NAME`, else
   `SOPULI_PROFILE`, else `defaults.profile`, else none. Multiple profiles do not
   compose; if you want a variant, write it out.
2. **No inheritance.** Profiles are flat and independent. A three-line duplicate
   is cheaper to read than an inheritance graph in a credential tool.
3. **Keys sit directly in the profile**, mirroring the shape they have under
   `defaults`.
4. **Precedence layer 3**, between environment variables and per-object settings
   — see §9. A CLI flag or a `SOPULI_*` variable still wins over the profile.
5. **The safety ratchet still applies.** A profile may make `safety` stricter but
   never looser than any other layer. `profiles.ci.safety.max_targets: 200` only
   takes effect if no other layer sets something lower; `readonly: true` anywhere
   cannot be undone by a profile.
6. **Selecting an undefined profile is an error**, not a silent fallback to
   defaults. A typo in `--profile` must not quietly give you interactive
   behaviour in a scheduler.

### Naming

Name profiles after **invocation context**: `interactive`, `ci`, `scheduled`,
`maintenance`. Never after an environment.

Validation **warns** when a profile name matches any target's `environment`
value, because `--profile prod` reads like a target selector and is not one. It
is a warning rather than an error only because a site may have a legitimate
reason; the warning text says what the flag actually does.

### Reporting

The active profile appears in `config show --explain` and in the JSON output's
`invocation.profile`, and every setting it supplied is attributed to it:

```
verify.method      = hash    [profile scheduled]
output             = jsonl   [profile scheduled]
safety.max_targets = 1       [defaults]        ← profile asked for 200, ratchet held
```

That last line is the case worth being able to see.

---

## 6. Environment variables

Naming: `SOPULI_` + upper-snake path, `__` for nesting into a named object.

| Variable | Overrides |
|---|---|
| `SOPULI_CONFIG` | config file path |
| `SOPULI_PROFILE` | active profile (§5) — the usual way a CI job or scheduler selects one |
| `SOPULI_VAULT` | default vault name |
| `SOPULI_VAULT_ADDR` | address of the active vault |
| `SOPULI_VAULT_TOKEN` | token for the active vault |
| `SOPULI_VAULT__VAULT_DEV__ADDR` | address of a *specific* named vault |
| `SOPULI_DB_ADMIN_USER` / `SOPULI_DB_ADMIN_PASSWORD` | admin credentials (password is low-assurance, flagged in output). The password pair is the default for `admin.auth: { method: env }`; a target may name its own variable with `password_env:` (§3a) |
| `SOPULI_ORACLE_CLIENT_LIB_DIR` | Oracle client directory for thick mode |
| `SOPULI_OUTPUT` | `text` \| `json` \| `jsonl` |
| `SOPULI_LOG_LEVEL` | log level |
| `SOPULI_NO_COLOR` / `NO_COLOR` | disable colour — set and not empty, whatever the value. Outranked by an explicit `--color always`; see `03-json-output.md` §1 for the full precedence |
| `SOPULI_DRY_RUN` | force dry-run globally (safety ratchet: no flag turns it off). Set and non-empty is the whole answer, whatever the value — `SOPULI_DRY_RUN=0` means dry-run |

Honoured third-party variables, ranked *below* their `SOPULI_*` equivalent:
`VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, `VAULT_CACERT`,
`OCI_CLI_PROFILE`, `OCI_CLI_CONFIG_FILE`, `TNS_ADMIN`, `ORACLE_HOME`,
`NLS_LANG`, `HTTPS_PROXY`, `NO_PROXY`.

**`VAULT_SKIP_VERIFY` is the one exception.** It is read and **refused** with a
config error rather than honoured or silently ignored (ADR-005): it names the
same setting as `vaults.*.tls.verify`, which is under the P3 safety ratchet, and
honouring an unranked environment variable there would let it bypass every
layer the ratchet is supposed to outrank. Refusing loudly means anyone who set
it (Vault's own CLI convention) learns that it did nothing, instead of running
unverified and believing otherwise.

### Set, unset, and empty

**Set-but-empty counts as unset**, so a CI job can clear an inherited variable
without unsetting it. This is the `NO_COLOR` convention the tool already follows
for `SOPULI_NO_COLOR`, applied to the whole table.

**A safety variable's value is not read at all** — presence is the answer.
`SOPULI_DRY_RUN=0` means dry-run, which is deliberate: under the ratchet nothing
can turn a safety setting *off*, so a variable that parsed `0` / `false` / `no`
would be one that looks like it disables dry-run and cannot. That is worse than
either reading on its own.

Implemented in `sopuli/settings/sources.py`, which converts the table into
contributions for the resolver. `SOPULI_CONFIG` is not there — file discovery is
a different chain (§9a) — and neither is `SOPULI_NO_COLOR`, because colour is
settled with TTY detection rather than by precedence.

### What is *not* overridable

- `accounts` / `applications` — which accounts are mastered where. Changing that
  from the environment would make the audit trail meaningless.
- `secret` / `secret_template` — same reason, and it is the mistake with the
  worst consequences.
- `policies.*.password.*` — a weaker password policy must be a reviewed change.
- `targets.*.environment` — you cannot relabel prod as dev to skip confirmation.

---

## 7. SecretRef syntax

A SecretRef addresses a value **in** a vault. What the *vault itself* is
authenticated with is a MaterialRef (§3a) — a different, smaller type, because
that material is what you need before you have a vault to address anything in.
Nothing in this section applies to it: no vault prefix, no qualifiers, no tokens.

One string addresses a value in any backend:

```
[<vault>:]<path>[#<field>][/<json-pointer>]
```

| Example | Resolves to |
|---|---|
| `apps/orders/prod/db/ORDERS_APP` | whole secret (scalar or single-field) — a **read** address; see below |
| `apps/orders/prod/db/ORDERS_APP#password` | field `password` in the KV secret |
| `vault-dev:apps/orders/prod/db/creds#password` | explicit vault |
| `tenants/beta#DB_CREDENTIALS/acme_web_user` | one entry in a JSON map held in one property — the layout in §2 |
| `apps/orders/prod/db/creds#password@version=7` | pinned version (read-only contexts) |
| `apps/orders/prod/db/creds#password@stage=pending` | staging label (OCI native, emulated elsewhere) |

### Parsing it

Implemented in `sopuli/config/secret_refs.py`, and parsed when the file is read
rather than at the first rotation — §1 calls the account→secret binding the
safety-critical part, and the failure at the far end of a malformed ref is a
password written where the application does not read it.

Three ambiguities have to be settled to parse the grammar at all. Each is
settled the way that keeps a realistic ref working:

| Written | Read as | Why |
|---|---|---|
| `vault-dev:path`, `vault:x` | vault prefix | a `:` **before the first `/` or `#`** |
| `tenants/beta#DB:extra` | part of the field | otherwise this names a vault called `tenants/beta#DB` |
| `apps/user@example.com/db` | part of the path | an `@` starts a qualifier only when what follows contains `=` |
| `creds#password@versio=7` | **error** | a misspelt qualifier would otherwise become field text and address a different secret |
| `#DB_CREDENTIALS/a/b` | field `DB_CREDENTIALS`, pointer `/a/b` | a field name is one segment; the rest addresses into its document |

A pointer is an RFC 6901 pointer, so `a~1b` is the single key `a/b` and `~0` is a
literal `~`. An empty segment (`#DB/`, `#DB/a//b`) is refused: the RFC allows a
key named nothing, and a credential store has no such key, so it is a stray `/`.

Only `version` and `stage` are qualifiers, and only one may appear — a pinned
version and a stage select the same secret two different ways and nothing says
which would win.

### The qualifier vocabularies (C14, decided)

Both vocabularies are the **tool's**, and both are checked when the file is read.
Not the backend's: OCI's rotation states are a fixed set Oracle defines rather
than labels anybody may invent, and both stores in scope number versions with
integers — so carrying an unknown value through to the store would buy nothing
and move a typo to rotation time. That is the same reasoning as the paragraph
above: a ref is parsed when the file is read precisely because the failure at the
far end of a malformed one is a password written where nobody reads it.

| Qualifier | Accepted | Refused |
|---|---|---|
| `@version=` | a whole number from 1 upwards | `@version=v3-beta`, `@version=0`, and `@version=007` |
| `@stage=` | `current`, `pending`, `previous`, in any case | anything else, including `latest` and `deprecated` |

- **Stages are the three states UC-1 §2 names**, matched case-insensitively and
  normalised to lower case. Case-insensitively because OCI writes `PENDING` and
  that is the spelling somebody copies out of the console; normalised because one
  spelling should reach the store, and each backend maps *from* it — to OCI's
  upper-case rotation states, or to the payload's JSON fields on a store with no
  native staging.
- **Three of OCI's five, deliberately.** `LATEST` is an upload-ordering artefact
  with no counterpart in a payload of JSON fields, so there is nothing to emulate
  it with; `DEPRECATED` names a *set* of versions rather than selecting one, so
  it is not a selector at all. Note also that an OCI version may hold several
  states at once — a new secret is both `CURRENT` and `LATEST` — so `@stage=`
  selects a version rather than identifying one.
- **Versions start at 1**, because KV v2 reads version 0 as "the latest version"
  while OCI numbers from 1, and a ref that meant two different things depending
  on where it resolved would be a rotation reading the wrong password. The
  current version is `@stage=current`, or no qualifier at all.
- **A qualifier value may not contain a `{token}`.** Templates parse through the
  same grammar (below), and a version or stage that varied per target would have
  one rotation reading a different generation on each of them.

Normalising costs one thing, and it is the only thing: a ref whose stage was
written in upper case does not render back byte-for-byte. `@stage=PENDING` comes
out of `config show` as `@stage=pending`. The trade is worth it, because two refs
that differ only in the case of a stage now compare equal — which is what
"addresses the same secret" ought to mean.

That it stays the *only* thing is why `@version=007` is refused rather than read
as 7: upper case has a source, since OCI spells its rotation states that way, and
padding has none, so accepting it would be canonicalising for nothing.

The **run document** types the same two fields (`secret_ref.version` as an
integer, `secret_ref.stage` as this closed lower-case enum), so the config layer
and the JSON contract agree by construction. One difference between the two is
deliberate: `vault` is optional in a written ref and **required** on an emitted
`secret_ref`. §7 describes the ref as written, where the prefix may be left to
the resolved store; the schema describes it after resolution, where the store is
always known and a plan that named a secret without naming its store would make
the audit record unreadable without re-deriving precedence.

**Templates** in `secret_template` expand from labels and built-ins:

| Token | Meaning |
|---|---|
| `{account}` | database username as written |
| `{account_lower}` / `{account_upper}` | case-normalised |
| `{target}` | target name |
| `{env}` | the target's `environment` |
| `{container}` | Oracle PDB / container name |
| `{application}` | application entry name (empty in the inline form) |
| `{<label>}` | any label on the target, e.g. `{tenant}` |

A built-in wins over a label of the same name: the built-in is specified here and
a label is whatever somebody typed. A target with no `environment` supplies no
`{env}`, and one with no container no `{container}`, so a template using either
against such a target fails to render rather than rendering short — §10's rule,
applied to refs. `{application}` is the one documented exception, and is empty
rather than missing in the inline form.

A template parses as the ref it will expand into: the punctuation that gives a
ref its shape is literal, and the tokens sit inside the parts. So
`tenants/{tenant}#DB_CREDENTIALS/{account}` is checked structurally at load. The
one thing that cannot be checked early is a token whose *value* turns out to
contain `:`, `#` or `/` — that changes the structure, and the labels are not
known until target expansion.

Rule: a template must resolve to **one** secret per (account × logical scope). If
an account exists in eleven PDBs and the template mentions no distinguishing
label, all eleven share one password — legal and often intended, but the plan
output states it explicitly so it is never accidental.

"States it explicitly" is `config show --resolved`'s **shared secrets** section
and the run document's `shared_secrets` (#110), which report both ways a document
can be shared: the targets bound to it, and — since Q7 made one document per
application the default — the accounts whose credentials it holds. They are read
from the file rather than from the store, so the answer is available offline and
is the same on two runs of the same command.

**An application's ref must have somewhere to stage into** (#111). Where the
store emulates the three stages in payload fields — every backend in P2's table
but OCI — `pending` and `previous` are keys *beside* the container, so two refs
that parse perfectly well still cannot be rotated:

| Refused | Why |
|---|---|
| `apps/orders/prod/db/creds` | no field: nowhere to put `pending` and `previous`. The "single-field" reading in the table above only holds until the first rotation, which makes the document three-field |
| `tenants/beta#pending/{account}` | the container is a key the rotation mechanism owns. `pending`, `previous`, `rotated_at`, `rotated_by`, `policy` and `targets` are all reserved; `current` is not, because the ref already points at it |

Both are refused **while the file is read** rather than at the first rotation —
§1 calls this binding the safety-critical part, and invariant 4 wants a command
that cannot succeed to fail before it has written anything. The check runs per
binding in `sopuli/config/bindings.py`, on the *rendered* ref, which is what lets
it be exact about two things a check on the written template could not be: the
tokens are already substituted, and the store is known.

**The store is why this is not a universal rule.** On OCI the stages are versions
of the secret rather than fields in it (P2's `staging_labels` row), so a ref
naming a whole secret is the natural layout there and a field called `pending`
collides with nothing. Neither refusal fires against a store that stages
natively. A store type P2 gives no capability row — `keyring` — is left alone
too, rather than assumed to emulate.

None of this constrains a ref that is only ever *read*. An `admin.auth.secret` is
a credential the tool authenticates with and never rotates, so the whole-secret
form stays exactly as the table above describes it.

**A ref's own `vault-name:` prefix is resolved here too**, against the same
declared set and with the same message as every other dangling name (§10). It is
checked at this point rather than with the others because it is the only one that
is not readable until the ref has been rendered — the rest are plain keys, while
this one sits inside a template. It matters for the reason §10 gives about store
names generally, with one turn of the screw: an entry's `vault:` that names
nothing falls back, whereas a **prefix wins outright**, so a typo there produces a
binding pointing at a store that does not exist — or one that later exists and
belongs to somebody else.

**Writing into a shared JSON document.** One secret per application with a field
per account is the **documented default** (Q7, decided in #85; the payload shape
is `../use-cases/uc-01-app-credential-sync.md` §3). One secret per account stays
fully supported — it is the same code path with one account in the map.

Where several accounts live in one property (`DB_CREDENTIALS` above), the tool
must not clobber siblings. On KV v2 it uses a JSON merge patch, falling back to a
check-and-set read-modify-write; a concurrent change aborts the write rather than
overwriting. Sibling properties in the same secret — application settings and the
like — are never touched.

Aborting is worth stating as a rule rather than as caution, because the reason
changed once the lock landed. A mutating run holds the advisory lock on the
**path** (Q2, #83), so no other run of this tool can be writing that document. A
compare-and-set conflict therefore means a *foreign* writer — somebody at a vault
CLI. Re-reading and merging over them is exactly the read-modify-write that
rewrites fields belonging to accounts nobody selected, which invariant 5 exists to
prevent. So the write is abandoned and reported; it is never retried into a
document that moved underneath it.

The same reasoning gives the read side its rule: **keys the tool does not
recognise are preserved verbatim**, never dropped and never rebuilt from config.
A document is edited, not regenerated.

---

## 8. Password charsets

The alphabets are `sopuli/config/charsets.py`, which is §8's table as characters
rather than as prose; generation and validation are `sopuli/passwords.py`.

**To see what a policy actually produces**, `sopuli policy sample NAME` draws from
it offline — no vault, no database, nothing stored. It reports each sample's
length, its byte length in an encoding you name, and its composition; `--reveal`
prints the passwords themselves, which is the one place in the tool where
plaintext reaches output on purpose. That is the answer to the questions this
section raises and cannot settle on paper: whether a `custom` charset renders what
was meant, and whether the shape survives a connect string or a `.env` file.

| Name | Contents | Notes |
|---|---|---|
| `alnum` | `A–Z a–z 0–9` | safest; no quoting anywhere |
| `alnum_safe` | alnum + `_ # $ - . + = ~ ^` | avoids shell, connection-string and SQL-quoting hazards. **Default.** |
| `printable_ascii` | printable ASCII except space **and except `"`** | requires quoted identifiers; may break connect strings and `.env` files |
| `custom` | explicit `allow:` string | you take responsibility |

`printable_ascii` names the `"` exclusion rather than leaving it to the rule
below, because an alphabet containing a character every password is rejected for
would produce nothing but candidates that are thrown away.

A **class** is `upper`, `lower`, `digit`, or `special` — where `special` is
everything else in the alphabet. That is what makes `require: { special: 1 }`
answerable for `charset: custom`, whose alphabet is whatever somebody typed.

Independent of charset:

- `first_char: alpha` — an unquoted Oracle password may not start with a digit
- max byte length from the target (30 vs 128), computed in the **database
  character set**, not in characters. `length:` counts *characters*, so the two
  are separate numbers and the byte limit travels with the encoding it was counted
  in — 30 bytes is 30 characters in `WE8MSWIN1252` and as few as 7 in `AL32UTF8`.
  Where no target could be reached there is no byte limit to apply, and the run
  says so rather than assuming one (UC-1 §4)
- passwords containing `"` are rejected outright — Oracle quoted identifiers have
  no escape for it (see `02-oracle-privileges.md` §4) — as are control characters,
  `CHR(0)` included
- the target's verify function: generate → validate → on rejection (ORA-28003, or
  ORA-20xxx from the function) retry with a new candidate up to N times, then
  fail with the server's message intact
- `PASSWORD_REUSE_TIME` / `PASSWORD_REUSE_MAX` — never retry blindly on ORA-28007

### `length` has no default

There is no built-in password length. A policy that does not declare one is legal
— nothing has to generate from it — but generating **refuses**, naming the key to
add. §8 names a default charset and deliberately no default length: which charset
is safe is a property of Oracle, while how much entropy every credential in an
estate gets is a decision about that estate, and a credential tool choosing it
quietly is the opposite of a reviewed line in a file. If a built-in is ever wanted
it belongs in P3's layer 6, where `config show --explain` can attribute it.

### Generation, and what "compliant" means

One definition, used twice. `creds generate` draws candidates from a CSPRNG and
keeps the first compliant one; `creds apply --from-stdin` runs a supplied password
through the same predicate (UC-1 §4). Two implementations would eventually
disagree, and the disagreement would be a password the tool wrote and then refused.

`length` is read slightly differently by each, which is deliberate: generation
produces **exactly** `length`, while a *supplied* password satisfies it at
`length` **or longer**. A password an external system dictated is not weaker for
being longer, and refusing it would block the migration case `--from-stdin` exists
for; shorter is a violation.

A policy that no password could satisfy is refused before any drawing happens,
naming what is wrong — a `require:` asking for a class the alphabet lacks, a
`first_char: alpha` against an alphabet with no letters, an alphabet the target's
character set cannot store, or a `length:` that cannot fit the target's byte limit.
§10 catches most of these when the file is read, which is the better moment; the
rest need the target's limits and so cannot be known until a command runs.

---

## 9. Precedence, restated with examples

Order (highest first): **CLI → `SOPULI_*` env → third-party env → profile →
named object → `defaults` → built-in**.

```
$ export VAULT_ADDR=https://vault-a:8200
$ export SOPULI_VAULT_ADDR=https://vault-b:8200
$ sopuli creds check --vault-addr https://vault-c:8200
→ vault-c   [cli]

$ sopuli creds check
→ vault-b   [env SOPULI_VAULT_ADDR]

$ unset SOPULI_VAULT_ADDR
$ sopuli creds check
→ vault-a   [env VAULT_ADDR, third-party]
```

A profile sits below both, so a flag still wins over it:

```
$ sopuli creds check --profile scheduled              # profile sets verify.method: hash
→ hash    [profile scheduled]

$ sopuli creds check --profile scheduled --method login
→ login   [cli]      ← the operator at the keyboard is the more specific intent
```

Safety ratchet:

```
$ sopuli creds apply --no-dry-run          # config has readonly: true
error: target group "prod-pdbs" is readonly (config safety.readonly);
       safety settings cannot be relaxed from the command line
exit 2
```

Multiple `--config` files layer left to right (deep merge for maps, replace for
lists). The asymmetry is deliberate: a mapping is a set of named settings, so an
overlay that sets `vaults.vault-dev.addr` must not delete `vaults.vault-prod`,
while a list is a whole answer — merging two `accounts:` lists would produce a
whitelist that appears in no file (invariant 5).

Each layer is a config file in its own right, `version:` included, and is checked
on its own — permissions, encoding, parse, version — before anything is merged.
So a file-level error still names its file. A *validation* error over several
layers carries its key path but no filename: the value may have been written in
one file and overridden in another, and naming either would be a guess.

A `safety:` block may appear under `defaults`, a target, a group, or a
profile, and unlike everything else these do **not** follow last-one-wins: the
resolved value is the *safest* of all layers — lowest `max_targets`, union of
`confirm_environments`, `readonly: true` if any layer sets it.

### The unit that gets resolved is a setting, not an option

`readonly` has no flag at all. `verify.method` arrives from a profile block.
`--dry-run` will have both a flag and `SOPULI_DRY_RUN`. A resolver keyed on
command-line options would leave half the things that need a merge policy with
nowhere to declare one.

So the resolvable unit is a **setting** — `safety.dry_run`, `output`,
`safety.readonly` — declared with its type, the layers that may supply it, and
how colliding layers merge. Flags, `SOPULI_*` variables and config keys all bind
to setting names. The same declarations are what `invocation.options` and
`config show --resolved --explain` iterate over, so the merge rule, the JSON
attribution and the human view are one mechanism rather than three that must
agree. Implemented in `sopuli/settings/`.

A setting's declared layers are **enforced**: a value arriving from a layer the
setting does not list is a programming error, not a silently-accepted override.
Otherwise the table above describes intent rather than behaviour.

### Two merge policies

| Policy | Rule | Applies to |
|---|---|---|
| `override` | the highest-authority layer wins | everything not below |
| `ratchet` | the *safest* layer wins, whichever it is | `safety.dry_run`, `safety.readonly`, `safety.max_targets`, `safety.confirm_environments`, `locking.break_expired` |

The ratcheted set is invariant 10's, and it is one frozenset in
`sopuli/settings/registry.py` so it can be reviewed at a glance. A setting
declaring `ratchet` without being in it — or the reverse — fails to construct,
so the two cannot drift apart.

Merge policy is a **required** field with no default. The failure mode worth
designing against is not a wrong policy; it is a safety setting added later that
silently inherits `override` because nobody wrote one.

One policy, three shapes, taken from the setting's type — exactly the three the
safety paragraph above names: a boolean ratchets toward its safe value, an
integer to the minimum, a list to the union.

**Which boolean value is the safe one is declared per setting**, and it was not
worth saying until `locking.break_expired` arrived (#83). `readonly: true`
refuses more, so one layer asking for it is enough. `break_expired: true`
refuses *less* — it is permission rather than a guard — so there the layer saying
`false` is the one that must win, and one layer withholding permission is enough.
Merging both with "true wins" would have advertised a guardrail while doing the
opposite of one. The direction is a field on the setting rather than something
inferred from its name, because a ratchet that reads its polarity out of a string
flips silently the day somebody renames a setting. `relax-but-bounded` was
considered for `--force` and deliberately not built, and P3's answer (#89) is why
it is not needed: `--force` overrides the *account* guardrails of
`02-oracle-privileges.md` §4, never a safety setting, so it is not a setting at
all. That is invariant 10 made structural — a flag with no entry in the registry
has no layer to arrive on and nothing to relax. Because the field is required and
declared, adding a third policy later is additive rather than a migration.

Two rules follow from the ratchet and are easy to get backwards:

- **The built-in default is a fallback, not a contributor.** If any other layer
  spoke, layer 6 drops out before merging. A built-in that took part in a ratchet
  would be an unremovable floor rather than a default: a built-in `confirm: true`
  would make `profiles.ci.confirm: false` unreachable forever. "Built-in default"
  in `--explain` means precisely *nothing else spoke*.
- **Ties resolve downward.** Where several layers supply the effective value —
  two of them saying `readonly: true`, or three contributing to a union — the
  reported source is the *lowest-authority* one. If config says `readonly: true`
  and a flag asked to relax it, the answer to "why did this refuse to write" is
  the config key. It is also the only actionable answer: dropping the flag
  changes nothing, editing the key does.

---

## 9a. The file itself

Before any key is looked at, the file has to be one the tool will read at all.
Implemented in `sopuli/config/loading.py`; decided in
[ADR-004](../decisions/adr-004-yaml-parser.md).

| Rule | Why |
|---|---|
| `version:` is required, and must be a number this build knows | A file with no version cannot be migrated later — nothing distinguishes "written before versioning" from "written for a version we do not have" |
| The root must be a mapping | A list or a bare scalar is a different file, not an empty config |
| UTF-8, with or without a BOM | Notepad writes a BOM and offers no way not to, and Windows is a supported tier |
| Parsed with `safe_load` only | A config file may arrive from a shared drive; the default loader would construct Python objects from tags in it |
| **Duplicate keys are an error** | Stock YAML keeps the last one silently. Invariant 5 makes this file the whitelist, and a whitelist that can lose half its entries without saying so is not one |
| **`yes` / `no` / `on` / `off` stay strings** | PyYAML is YAML 1.1, where they are booleans. Tenants, environments and PDB suffixes are bare words here, and each flows into a rendered secret path — a tenant called `no` becoming `False` would surface only as a wrong path |

Anchors and merge keys (`<<:`) work normally; a merged-in key does not count as
a duplicate.

Errors name a location. Parse errors carry a line and column; validation errors
carry a key path (`applications[1].secret_template`). "invalid config" is not an
error message for a file this long.

---

## 9b. The published schema

P3 requires a published JSON Schema. It is
[`docs/schemas/sopuli-config-1.2.schema.json`](../schemas/sopuli-config-1.2.schema.json),
Draft 2020-12, and it exists for the editor rather than for the tool: pointed at
from a YAML language server, it gives completion and inline errors while somebody
is editing a 130-line file, which is worth more than the validation itself.

**It is generated, not maintained.** `sopuli/config/schema.py` composes it from
the same constants the builders validate with — `TARGET_KEYS`, `VAULT_TYPES`,
`CHARSETS`, `SUPPORTED_VERSIONS` and the rest — and refuses to generate at all if
a section's keys and its type table disagree. Regenerate with:

```
python -m sopuli.config.schema > docs/schemas/sopuli-config-1.2.schema.json
```

`tests/config/test_schema.py` fails when the committed file is not what the model
produces today, so a key cannot be added to a section without the schema moving
with it. Two hand-written descriptions of one schema drift, and the one that
drifts silently is the published one, because nothing runs it.

The version in the filename is the schema contract's, not the config file's: a
new optional key is a minor bump there and changes nothing about a file that says
`version: 1`.

**What it says.** Key names, JSON types, the closed sets, which keys are
required, and `additionalProperties: false` — P3's "exits non-zero on unknown
keys", in the form an editor can use. The shape rules of §4 are here too, since
they are about shape: one outer dimension, one list per value. So is a
MaterialRef's — exactly one of `env` / `file`, and no property for a value at all,
which is the one rule in the artefact that is a security property rather than a
convenience (P2).

**What it deliberately does not say.** Every rule in §10 that relates two keys
to each other stays with the hand-written validators, because those errors have
to name the offending key and a `oneOf` failure reports every branch that did not
match instead:

| Rule | §10 |
|---|---|
| the inline form and `applications:` are mutually exclusive | yes |
| `secret` and `secret_template` are mutually exclusive | §3 |
| an `auth:` block carries only the keys its own `method:` takes | §3a |
| `admin.auth: external` requires a TNS-alias `dsn` and no `username` | yes |
| two accounts may not resolve to one secret ref | yes |
| `require:` may not exceed `length:`, or ask for specials a charset lacks | yes |
| `allow:` belongs to `charset: custom` | §8 |
| every `vault`, `policy`, `group`, `profile` and target name must resolve | yes |
| a `for_each`'s inner dimension must be one variable throughout | §4 |
| a profile may not set a key that changes scope | §5 |
| `locking.break_expired` beside an `advisory-only` store | yes |
| an application's ref must have somewhere to stage into, where the store emulates staging | §7 |

So a file the schema accepts may still be refused by `sopuli config validate`,
and that is the intended division rather than a gap. The schema is the fast,
local, incomplete check; the tool is the complete one.

### Pointing an editor at it

A schema nothing is pointed at is a file in a directory. The association is made
from the config file itself, with a comment on the first line:

```yaml
# yaml-language-server: $schema=./sopuli-config-1.2.schema.json
version: 1
```

That comment is the [YAML Language Server][yamlls] convention, which is what the
Red Hat **YAML** extension for VS Code uses, and what most other editors' YAML
support is built on. Verified with that extension: hovering a key shows the
description the generator wrote for it, and an unknown key is underlined where it
was typed.

**The path is relative to the YAML file**, not to the repository. Copy the schema
next to the config, or point at it where it lives — `$schema=../sopuli-dba/docs/schemas/sopuli-config-1.2.schema.json`
is as valid as the form above.

**The `$id` inside the schema is an identifier, not an address.** It reads like a
URL because JSON Schema identifiers conventionally do, and it matches the sibling
schemas — but nothing serves it, so it is not a value to paste after `$schema=`.
Use a path to a local copy. (If the schema is ever served from somewhere stable,
the URL form belongs here beside the path form, and this paragraph goes away.)

**Every complete example in this documentation carries the comment.** Not
decoration: the line is the only part of using the schema that has to be
discovered rather than deduced, and a reader who copies a worked example as a
starting file should get the editor support without having read this section.
Fragments — an `applications:` block on its own, a `groups:` snippet — do not,
because they are not files. `tests/config/test_design_document_examples.py`
enforces the split, so an example added later cannot quietly drop the line, and a
schema version bump has to be reflected in the examples that name it.

[yamlls]: https://github.com/redhat-developer/yaml-language-server

### `sopuli config validate`

The command P3 names. It loads the file through the same path every other command
does — discovery, the permission check, the hardened parser, the builders — and
reports what it found:

| Outcome | Exit | Output |
|---|---|---|
| the file loads | 0 | the files read, and how much they declare: targets, bindings, warnings |
| §10 warnings | 0 | each warning in full, and `diagnostics[]` under `--output json` |
| a declared backend is not installed | 0 | a warning naming the store, its `type`, and the extra that supplies it (`SOPULI-W003`) |
| anything §9a or §10 refuses | 9 | the message, with its key path and its hint |

**A missing backend warns rather than fails (ADR-006, E4).** The config is
valid; the install is incomplete, and those are different sentences. Validating
on a laptop a file that runs on a scheduler elsewhere is the ordinary case, not
the strange one, and a validator that calls a good file broken is less
trustworthy for exactly the case it exists to serve. The command that actually
needs the client is where this becomes an error (§3a).

Exit 9 rather than 1 or 2: a scheduler can tell "fix your file" from "something
broke" *and* from "fix your command line". A bad file produces a run document
under `--output json` — the invocation resolved and it is the configuration that
failed, which is J7's seam (`03-json-output.md` §6). This command is the reason
the seam is there: reporting configuration problems is its entire purpose, and a
validator that goes silent exactly when it has something to say is not one.

It validates through the builders, not through the published schema above. The
two are not equivalent and the stricter one wins; `jsonschema` stays a
development dependency.

Offline, like `config show`: no vault and no database is contacted.

Secret refs are typed as strings. §7's grammar is parsed by
`sopuli/config/secret_refs.py`, and a regex approximation of it in a published
artefact would be a second parser that disagrees with the first in a way nobody
notices until a rotation.

---

## 10. Validation rules worth enforcing early

- unknown keys → error, not warning
- both top-level `accounts:` and `applications:` present → error
- a secret ref that cannot produce **distinct refs for distinct accounts** → error.
  Concretely: more than one account declared, and neither `{account}`,
  `{account_lower}` nor `{account_upper}` appears in `secret` / `secret_template`.
  The second password written would overwrite the first, and whichever
  application reads the first is locked out at the next rotation. This is about
  *accounts*, not scopes — one account sharing a password across eleven PDBs is
  legal and often intended (§7), and is surfaced in plan output rather than
  refused
- an `overrides` entry patching `accounts` → error. Invariant 5 says selectors
  filter the declared set and cannot extend it, not even under `--force`. A
  patchable `accounts` would be a label match buried in a long file that adds to
  the whitelist; what the tool manages has to be readable from `accounts:` alone
- two `targets:` entries with the same `name` → error. `--target` becomes
  ambiguous, and the second would shadow the first everywhere a name is looked up
- a `for_each` with more or fewer than one outer dimension, or with two list
  variables in one value → error (§4 rules 1 and 6), rather than a set that
  generates a surprising number of targets
- a target with `environment: prod` referencing a vault marked
  `non_production: true` → error
- `locking.break_expired: true` anywhere in the file while any vault is
  `locking: advisory-only` → error naming both ends (#83). Either alone is
  legitimate; together they are an unattended run taking over a lock with no
  fence to stop the run it took it from, which is how two runners end up applying
  different passwords to different targets. Both halves are written in the file,
  so the answer does not depend on which targets a run selects
- auth material written inline — a string where a MaterialRef belongs → error, and
  a different one from "wrong type": it is the credential itself appearing in a
  file that is committed and shared, which P2 forbids outright
- a MaterialRef naming two sources, or none → error. Two leave nothing to say which
  was meant, so the tool would silently pick one and authenticate as something
  nobody chose
- an `auth:` key that belongs to another method → error, naming the method in
  force. `role_id` under `method: token` is a leftover from an edit that changed
  the method, not a typo
- a method written as a bare value when it needs material — `auth: approle` →
  error. There is nowhere in a scalar to say where `role_id` comes from, and the
  alternative is a fall-through into some other method that nobody can explain
  afterwards
- an `auth:` method missing material it requires → error at load, not at the first
  rotation (invariant 4). `admin.auth: vault` with no `secret:` is the same rule:
  there is no default admin path, and guessing at one is how a run authenticates as
  something nobody chose
- `admin.auth: external` on a target whose `dsn` is not a TNS alias → error.
  External auth connects as `/@alias` and the wallet is keyed on that alias, so an
  EZConnect string fails as an *authentication* error, which is the most
  misleading way for a config mistake to surface
- `admin.auth: external` beside a `username:` → error rather than the username
  being ignored. The wallet decides who connects, and a file that appears to name
  the connecting account while the wallet names another is worth stopping for
- a malformed `admin.auth.secret` → error (§7), like any other ref, wherever it is
  written; and one still holding a `{placeholder}` on an explicit target → error,
  since a target set's dimensions are the only thing that renders one
- a declared `oracle.scope` or `oracle.container` that disagrees with what the
  driver finds on connect → error naming both. Not a load-time rule — it is the one
  check here that needs a session, and it is what catches a `dsn:` edit that
  repointed a target at a different container
- a `target_set` whose `name` renders a duplicate → error, listing the collision.
  Across the whole estate, not one set: a generated name colliding with an
  explicit `targets:` entry makes `--target` just as ambiguous
- an `overrides` key naming a target the set does not generate → error (catches
  renames)
- an unresolved `{placeholder}` anywhere → error, never an empty string. So is an
  unbalanced or empty one, because there is no escape syntax to have meant
- a `secret` / `secret_template` that is not a well-formed ref → error (§7),
  wherever it is written, including inside an `overrides` entry
- a `for_each` variable named after the dimension it sits under → error (§4);
  `{env}` with two meanings resolves to one of them and silently decides a
  rendered secret path
- a profile containing a key outside the §5 whitelist → error, naming the key.
  The keys that would change *scope* — `accounts`, `applications`, `secret`,
  `secret_template`, `targets`, `target_sets`, `groups`, `environment`,
  `policies` — get their own message rather than "unknown key", because they are
  a wrong model rather than a typo
- a name that names nothing → error. Every `vault`, `policy`, `group`, `profile`
  and `targets:` entry written anywhere in the file must be declared in the
  section that declares them — target names against the *expanded* estate, since
  a generated name is as real as a written one. An application whose
  `targets: [cdb-root-dv]` names nothing manages nothing, and a run reports
  success over an empty set. A dangling `vault:` is the dangerous one: it does
  not stay dangling, it falls back to `defaults.vault`, and the tool then
  rotates a production password into whatever that is
- a binding with a secret ref, no store named for it anywhere — not the ref's own
  prefix, not the entry, an override, the target, or `defaults.vault` — **and**
  `vaults:` declaring nothing at all → error (C15, #118). A profile's `vault:`
  and `SOPULI_VAULT` are both still able to complete a binding like this, since
  neither is consulted until a run picks one (§5, §9) — but only by naming a
  store the file declared, and there is nothing here to name. Where `vaults:`
  *does* declare a store, the same ungrounded binding is left alone: its
  `vault` resolves to `None`, `config show --resolved` renders it as `-`, and
  the first command that actually needs a store is where the exact answer
  belongs (invariant 4) — see §3's binding chain and `config/bindings.py`
- `charset: custom` whose `allow:` contains `"` → error (invariant 11), or a
  control character, `CHR(0)` included (`02-oracle-privileges.md` §4). The
  generator applies those rules to what it produces; this applies them to the
  alphabet it produces *from*, which is the only place a config file can name such
  a character
- a `require:` block no password could satisfy → error: more characters demanded
  than `length` allows, or a class the policy's alphabet does not contain —
  `require: { special: N }` against `alnum`, and equally against a
  `charset: custom` whose `allow:` has no punctuation. Both would leave generation
  looping rather than failing
- `first_char: alpha` against an alphabet with no letters → error, for the same
  reason and with no `require:` block needed to reach it
- `--profile` or `SOPULI_PROFILE` naming a profile that does not exist → error,
  never a silent fallback to defaults
- a profile name matching any target's `environment` value → warning, explaining
  that a profile does not select targets
- a `vaults:` entry whose `type` names a backend that is not installed → warning,
  naming the store, the type and the extra that supplies it (ADR-006, E4). Not an
  error: nothing about the file is wrong, and §3a has where it stops being a
  warning
- a `vaults:` entry with `tls.verify: false` → warning, naming the store,
  carrying `SOPULI-W004` and repeated on **every run** rather than only at
  `config validate` (ADR-005). Not an error: an internal CA nobody has
  distributed yet is a real situation, and a tool that refused would be unusable
  exactly where an operator most needs it to say what it is doing
- a `tls.client_key` with no `tls.client_cert` beside it → error. The reverse is
  allowed: a client certificate may be written alone when the file holds both
  halves, which is an ordinary way to write mutual TLS, but a key with no
  certificate presents nothing and is an edit that stopped halfway
- `timeout_s: 0` or negative → error, rather than being read as "no timeout".
  Waiting forever is what the key exists to prevent — ADR-005 chose `httpx`
  partly because it has no default deadline — and the advisory lock is held for
  as long as the request is outstanding. Omitting the key is how you ask for the
  backend's own default
- `VAULT_SKIP_VERIFY` set and non-empty → error (§6), naming
  `vaults.*.tls.verify` and what to write instead
- `charset: printable_ascii` on a target detected below 12.2 → warning
- `rotation.strategy: rollover` on a target without the `password_rollover`
  capability → error at plan time, not at execution time
- config file **accessible** to others → refuse to run (P4). Wider than "readable"
  on purpose: the file holds no secrets (C5), so the risk it carries is
  *tampering*, and a group-writable config is the worse version of that — anyone
  who can write it can repoint `secret_template` at a path they control, and the
  tool will faithfully rotate a production password into it — no read access
  required. POSIX therefore refuses any `0o077` bit, and Windows refuses any ACE
  granting read *or* write to a SID outside {owner, `OWNER RIGHTS`,
  `CREATOR OWNER`, `SYSTEM`, `Administrators`}. `OWNER RIGHTS` (`S-1-3-4`) and
  `CREATOR OWNER` (`S-1-3-0`) are not accounts — they resolve to whoever owns
  the file, and a file created under `%TEMP%` commonly inherits the former and
  no explicit ACE for the user at all. Rights that grant neither content access
  nor control — `READ_CONTROL`, `SYNCHRONIZE`, `FILE_READ_ATTRIBUTES` — do not
  count, so the check fires on real exposure rather than on incidental bits

---

## 11. Open decisions

| # | Question | Current proposal |
|---|---|---|
| C1 | ~~Name of the binding section~~ | **decided: `applications`**, with the inline single-application form as the default shape |
| C2 | Selector syntax | `--select k=v` over labels, plus `match:` in groups. Revisit if a real case needs negation or set membership |
| C3 | Should secret templates support arbitrary expressions? | no — fixed token list plus labels, so the mapping stays auditable |
| C4 | Per-account overrides inside an application entry | the `overrides: [{where: …}]` mechanism covers per-label cases; per-*account* exceptions are still unsolved |
| C5 | Config encryption at rest | out of scope; config holds no secrets by construction |
| C6 | Multiple vaults for one application (mirror writes) | defer to a later use case |
| C7 | ~~Should `target_sets` allow more than two nesting levels?~~ | **decided: no** — write a second set. §4 rules 2, 6 and 7 are what that costs |
| C8 | ~~Do explicit `targets:` need labels, or is `environment` enough?~~ | **decided: labels are allowed on them**, so mixed estates select uniformly |
| C9 | ~~How does the file point at vault auth material, and at the database admin credential?~~ | **decided** (§3a), in #27. One grammar, two vocabularies: `{ method: ..., ...method-specific keys }`, with a scalar shorthand where the method needs nothing else. A vault's material is a MaterialRef — one key, `env` or `file` — so P2's no-plaintext rule is structural rather than remembered; identity fields stay inline; `method: token`'s source chain stops inside the method; a token helper is deferred. The admin credential uses P2's four sources, with `method: vault` naming a whole SecretRef, `method: env` naming its own variable, and `external` constraining the `dsn` to a TNS alias and refusing a `username`. `oracle.scope` adopts the run document's own vocabulary and is an **assertion** checked on connect, as is `container`; the two do not constrain each other in the loader |
| C10 | ~~What are profiles for?~~ | **decided: run context, not target selection** (§5). Closed key whitelist; `policies.*.verify.scheduled_method` removed in favour of a profile overriding `verify.method` |
| C11 | Should `--profile` be composable (several at once)? | no — one active profile, no inheritance. Revisit only if a real config duplicates three or more profiles |
| C12 | Ship a built-in `interactive` profile as the implicit default? | leaning no: an absent profile means "just `defaults`", and an invisible built-in would be one more thing to explain when output surprises someone |
| C13 | ~~Is `vault:` under `defaults:` and in a profile a store *name* or a block?~~ | **decided: a name, everywhere** (§3a), in #31. Settings *of* a store are reached by naming it under `vaults:`, which `defaults:` and a profile may each carry as **partial** entries patching a top-level declaration. Settled once C9 closed and the `auth:` grammar stopped being the unknown: what was left was only where the file writes it, and §6's `SOPULI_VAULT` / `SOPULI_VAULT__VAULT_DEV__ADDR` pair had already chosen that shape on the environment side. P3's precedence table is amended to `defaults.vaults.hcv-prod.addr`; §5's `vault.auth` row becomes `vaults.<name>.*`, restricted to `addr` / `mount` / `kv_version` / `auth` — not `type`, and not the two guardrails `non_production` and `locking`, which invariant 10 keeps out of the invocation context. The rejected alternative was a `vault_settings:` applying to whichever store is active: shorter, but it lets auth written for dev follow a changed `vault:` into prod. Parsing arrives with the vault layer (#103) |
| C14 | ~~What are the `@version=` and `@stage=` vocabularies, and who owns them?~~ | **decided: the tool owns both** (§7), in #40. `stage` is the closed set `current` / `pending` / `previous`, matched in any case and normalised to lower case; `version` is a whole number from 1; neither may hold a `{token}`. Settled by Oracle's own documentation: OCI's rotation states are a fixed set (`CURRENT`, `PENDING`, `LATEST`, `PREVIOUS`, `DEPRECATED`) rather than user-definable labels, and versions are integers — so there was no backend vocabulary to defer to, and passing a value through would only have moved a typo to rotation time. `sopuli-run-1.7.schema.json` is thereby ratified rather than changed, including `vault` staying required on an emitted `secret_ref`: §7 describes the ref as written, the schema describes it after resolution. Knock-on: this settles Q3 (#84) at one `previous`. |
| C15 | ~~A binding names a secret and no store, anywhere — refuse, warn, or leave it to plan time?~~ | **decided in #118: mostly plan time, refused only when nothing could ever complete it.** `_vault_for`'s chain resolving to `None` is not always a mistake — a profile's `vault:` or `SOPULI_VAULT` may still supply one, and neither is consulted while bindings are built (§5, §9), so the null can be a real, temporary state rather than an error. Left alone: `config show --resolved` renders it as `-` (§10), and the command that actually needs a store fails there, once a run's profile is known and the answer is exact. Refused at load only for the narrower, genuinely unrecoverable case — `vaults:` declaring nothing at all, so there is no name even a profile or `SOPULI_VAULT` could point at (§10). The naive rule — refuse whenever a binding's store is unnamed — was rejected first: it rejects the legitimate config where one profile sets `vault:` and a run selects a different one that inherits `defaults.vault` instead |

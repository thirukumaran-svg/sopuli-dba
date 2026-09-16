# sopuli-dba — Configuration Reference (draft)

Status: draft / sketch
Depends on: `00-principles.md` (P3 defines precedence)

---

## 1. Two shapes, and you start with the simpler one

**One application, and every target is its own → no `applications:` section.**
Put the binding keys at the top level and the file reads like a straightforward
target list. This is the shape most users will ever need.

```yaml
# yaml-language-server: $schema=./sopuli-config-1.3.schema.json
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

**A third declaration is decided and is not written here yet.** UC-2's personal
accounts are declared in `personal_accounts:` — by name, or by a predicate over a
profile or a role — decided in H1 (#449) and specified in
[`../use-cases/uc-02-personal-account-passwords.md`](../use-cases/uc-02-personal-account-passwords.md) §2.
It is deliberately *not* an application binding, for the reason the next paragraph
gives: nothing masters a personal account's password, so none of the three things
an application entry exists for applies to one.

The keys, the generated schema, the validators, and the rule that **a name may not
be declared both ways**, are **#467**. Until that lands, this reference documents
what is built — the two forms above — and the heading is a statement about
application bindings rather than about the whole configuration.

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
# yaml-language-server: $schema=./sopuli-config-1.3.schema.json
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
      method: token        # --vault-token-file, $VAULT_TOKEN, ~/.vault-token
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

### The selectors, and the one rule that separates them (#297)

Five flags, on every command that acts on the estate: `--select` for labels, and
`--target`, `--account`, `--group` and `--application` for names. `--app` is an
accepted alias for the last. All are repeatable. These examples were written
before any but `--select` existed, and were what #297 was filed over.

**They combine as *and*.** `--application acme --select env=dev` is acme's
accounts on dev targets, not their union. An *or* would need a selector
language, and C2 records why this file does not have one — the same reasoning
that keeps `target_sets` to two dimensions.

**An account selector narrows targets too**, by dropping the ones left with no
bindings. That is what keeps the blast radius honest: `--account acme_web_user`
against an estate where three of twenty targets have that account is a run
reaching three targets, and a plan counting twenty would make `max_targets` and
`confirm_environments` answer about work the run is not going to do. It is also
what stops any flag silently meaning nothing on a command that lists targets:
`target list --account acme_web_user` is "the targets where this account lives".

**A name that names nothing is refused; a label that matches nothing is not.**
That asymmetry is the one worth stating, because it looks inconsistent until you
have met the failure it prevents. Labels describe an estate that changes
underneath them, so `--select env=staging` matching no target is a true answer
about today's estate. A name is a claim that a particular thing exists — so a
scheduled `creds rotate --application acme` where somebody renamed the entry to
`acme-web` must not select nothing, do nothing, exit 0, and go on reporting
success for a credential that stopped being rotated. Every other guardrail here
is about doing too much; this one is about doing nothing and saying it went fine.

Names are checked against the **unfiltered** estate, so a name that exists but
was excluded by another selector is an empty run rather than a misspelling —
those are different mistakes with different fixes.

`--account` is compared case-folded, for the reason §4 of
`02-oracle-privileges.md` gives about check 1: the file writes `acme_web_user`
where Oracle stores `ACME_WEB_USER`, and an operator copying a name out of a
database is doing the obvious thing. Target, group and application names are the
tool's own vocabulary and are compared as written.

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

**Which layer wins is P3's answer, and it is not the same in both positions.** A
top-level `vaults:` entry is layer 4 and `defaults.vaults:` is layer 5, so a
`defaults:` block **supplies keys the declaration did not write** rather than
replacing ones it did — the word "patch" reads the other way and is right only
for a profile, which is layer 3 and above the declaration.

The one exception is `tls.verify`, which is under the safety ratchet: there the
safest layer wins whichever it is, so a `verify: true` written anywhere holds
against a `verify: false` written anywhere else, and the request that lost is
reported as a warning naming both ends (invariant 10).

`auth:` is **replaced whole** and `tls:` is **merged key by key**. Not an
inconsistency: an `auth:` block's keys are only meaningful together with a
`method`, so a key-by-key merge produces credentials nobody wrote — `method:
approle` carrying a leftover `token:` authenticates as nobody. A `tls:` block's
keys are independent facts about one connection, and one of them is a guardrail,
so replacing the block whole would let a layer mentioning only `ca_file` drop a
`verify: true` it never spoke about.

§5 has the profile case and the keys a profile may patch. Implemented in
`sopuli/config/vault_layers.py` for all three layers the file supplies — the
declaration and `defaults:` in #136, the active profile's block in #153 — merged
in one pass so that `tls.verify` ratchets across the three at once.

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

`sopuli lock break` is the attended form of the same act (#149), and the two are
deliberately different mechanisms: this key is a standing permission for a runner
with nobody watching, and the verb is a person naming one path. They emit the same
warning code, because it is the same event.

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
| `token` | `token` (optional — without it, `--vault-token-file PATH`, then `$SOPULI_VAULT_TOKEN`, then `$VAULT_TOKEN`, then `~/.vault-token`) |
| `approle` | `role_id`, `secret_id`, and optionally `mount` |
| `kubernetes` | `role`, `jwt`, and optionally `mount` |
| `oidc` | optionally `role` and `mount` |
| `userpass` | `username`, `password`, and optionally `mount` |
| `instance_principal`, `resource_principal` | none |
| `config_file`, `session_token` | optionally `profile` |

**What a HashiCorp store can actually perform today** (#138): `token`,
`approle`, `kubernetes`, `userpass`. `oidc` parses and is refused at plan time
with a message saying *not implemented yet* rather than *unsupported* — ADR-005
records why the gap is small: the hard part is the browser launch, the local
callback listener and the `state`/`nonce` handling, which is CLI work that no
Python client provides. The four OCI methods parse here too, because §3a is one
grammar with two vocabularies, and are refused against a HashiCorp store with a
message saying they authenticate to a different vendor.

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
  `--vault-token-file PATH` → `$SOPULI_VAULT_TOKEN` → `$VAULT_TOKEN` →
  `~/.vault-token`, and stops there. An earlier draft fell through to AppRole
  after that; falling into a *different* method makes an authentication failure
  impossible to explain. The `SOPULI_` variable is in the chain because §6 ranks
  every honoured third-party variable below its `SOPULI_*` equivalent — one
  order, stated in one place, rather than a second one implied here.
- **The flag takes a path, and `--vault-token` is refused** (#145,
  [ADR-007](../decisions/adr-007-vault-token-flag.md)). A token as a
  command-line *value* is visible in `ps` and in the Windows process list, which
  invariant 1 forbids without qualification — and the vault-ref escape in P5's
  wording cannot apply here, because a ref is resolved *by* an authenticated
  store. So the command line names the location, exactly as `token: { file: … }`
  does in the file, and `--vault-token` is declared only so that somebody who
  types what Vault's own CLI takes gets an explanation instead of "no such
  option". Accepting it silently would be worse than either: a run that looks
  like it accounted for authentication and did not. The refusal exits 2 and names
  all four working sources, not only the file form — a CI job that cannot write a
  token to disk already has `SOPULI_VAULT_TOKEN`. This chain, and not the settings
  resolver, is where the flag merges: the flag has no per-store key to layer
  against, and half a chain in the registry would be a second resolver for one
  question.
- **A `file:` MaterialRef is not permission-checked**, unlike the config file
  itself. P4 guards `sopuli.yaml` because the tool chose where it lives and reads
  it on every invocation; `/run/secrets/…` belongs to whatever mounted it, and a
  Kubernetes projected token arrives mode 0644. Refusing to read it would break a
  method P2 lists, so the asymmetry is deliberate rather than an oversight.
  **`--vault-token-file` is the one exception**: it is a bearer token at a path
  the operator typed for *this* run, so it gets P4's check and refuses when
  anyone else can reach the file — the same reasoning P4 itself gives, that the
  person reading the message is the one who can fix it, here, now. The
  `~/.vault-token` fallback stays unchecked with the config form: it is Vault's
  own file, written 0600 by `vault login`, and refusing the file another tool
  just wrote would refuse the bootstrap ADR-007 names as the answer for a human
  at a terminal.
- **Exactly one trailing newline is stripped**, and nothing else. Vault's own CLI
  writes `~/.vault-token` without one and every editor adds one, and a token
  carrying a trailing newline fails with a 403 that mentions no whitespace.
  Leading whitespace survives, because in a secret it is somebody's real secret. The file is read as
  bytes rather than text for the same reason: text mode would rewrite a carriage
  return inside a value and the symptom would be a credential that authenticates
  nowhere while the file on disk looks right.
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

**Whether the wallet is actually there is a runtime question, not a load-time
one** (#215). Both rules above are about the file and are errors; whether
`TNS_ADMIN` names a directory holding a readable `cwallet.sso` is about the
machine, changes between one host and the next, and is reported by `sopuli
doctor` in its `wallet` section rather than refused here. Loading a config on a
laptop for an estate that runs elsewhere is the common case, and a loader that
demanded a local wallet would break it.

#### What happens when one of these is resolved (#175)

Parsing says where the material lives; resolution reads it, and it happens **at
connect time rather than at load time** — `sopuli/admin.py`, beside
`sopuli/material.py` and for its reason: prompting and reading the environment
are I/O, and `04-testing.md` §4 keeps the config layer free of it as an
architecture requirement. Four decisions fall out of doing it, and each is
written here because each is silent when it goes wrong.

**A target that names no source is refused, not guessed at.** `admin:` is
optional and so is `auth:` inside it, so a target can reach a connection having
named nothing. Picking up `SOPULI_DB_ADMIN_PASSWORD` because it happens to be
set is the tempting reading of §6 and it is a guess: §6 calls that pair *the
default for* `method: env`, which is a statement about a declared method and not
about an absent one. A credential tool that authenticates from whatever variable
it found lying in the environment, because the file said nothing, is doing the
thing P2's bootstrap section exists to prevent. The error names the four methods
and the variable, so the fix is the one line it quotes. Refusing is also the
reversible half: deciding later that a bare variable implies `method: env` only
widens what works.

**`auth: prompt` with no terminal fails, and fails as exit 8** — aborted, not
config-invalid. The file is right, the invocation is right, and the run stopped
because it needed a human and there was not one; sending a scheduler's owner to
a config file with nothing wrong with it is the worse message. The same
condition is answerable *before* anything is touched — `needs_prompt()` over the
selected estate — which is invariant 4's shape applied to a source rather than
to a capability. Both guards exist: the plan phase does not yet, and the one that
must not be forgotten is the one nearest the pipe.

**A prompt never reads stdin**, which is how P5's *one stream, one reader*
survives contact with this method. `--from-stdin` (UC-1 §5) claims the pipe for
the *account's* new password, so a prompt falling back to stdin would read that
and send it to the database as the DBA's. Refusing when there is no terminal
makes the collision impossible rather than merely discouraged: a prompter exists
only when stdin is a terminal, and a terminal is not carrying a piped password,
so the two sources are mutually exclusive by construction and no ordering
between them ever has to be defined.

**One prompt covers every target that declares the same credential**, keyed on
*what the configuration declares* rather than on the username. The key is the
declaration site plus the **effective** username — the one `SOPULI_DB_ADMIN_USER`
may have overridden, not the one the file wrote:

- one `target_sets:` entry is one operator writing one credential down once, so
  its thirty-four generated targets are asked once. `username: sopuli_{tenant}`
  resolves differently per target and is therefore thirty-four credentials,
  asked separately — which is why the username is in the key at all;
- two explicit targets are two acts of writing it down and are asked twice even
  where the blocks are identical, because the file gives no reason to believe
  they are the same credential;
- the username **alone** is the unsafe key and is not used: two PDBs can hold
  same-named local accounts with different passwords, and a cache keyed on the
  name sends the first PDB's password to the second, where the ORA-01017 reads
  as a rotation problem;
- the DSN is deliberately *not* in the key. Targets generated from one entry
  point at different databases by design, so including it would defeat the cache
  entirely. Where those databases really do hold different passwords the run
  fails at the second one with an authentication error naming the target —
  diagnosable, and the file's own claim being wrong rather than a cache guessing.

Taking the username from the file alone gets two things wrong at once, which is
why *effective* is stated rather than implied. The operator would be **asked
about one account and connected as another**, since the variable outranks
`username:` — the two differ exactly when it is set, and the mismatch surfaces
as ORA-01017 long after the prompt. And the key would **separate targets the
variable has just made identical**: `sopuli_{tenant}` under
`SOPULI_DB_ADMIN_USER` is one account on thirty-four databases, asked about
thirty-four times. "What the configuration declares" means the value P3's layers
resolve to, not the lowest layer that had an opinion.

The prompt is also the one place a typed password becomes a `Secret`. The asker
the CLI supplies returns a `str`, because every terminal read does — `getpass`
included — and it is wrapped once, at that boundary, rather than by each
supplier. Invariant 2's argument applies to itself here: a supplier that forgot
would put a bare `str` where `repr` prints it in full.

**`SOPULI_DB_ADMIN_USER` outranks a target's `username:`** (P3: the environment
is layer 3, the file is layer 4) and is **ignored under `external`**. The
asymmetry with the refusal above is deliberate: a `username:` written beside a
wallet is somebody claiming something about *this* target and is worth stopping
for, while the variable is ambient and set once for a whole run — refusing a run
because one target of thirty-four uses a wallet would make the variable unusable
in a mixed estate.

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
[`sopuli-run-1.11.schema.json`](../schemas/sopuli-run-1.11.schema.json), minus
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

**A container is compared case-insensitively.** Oracle upper-cases an unquoted
identifier, so `container: freepdb1` in a file and `FREEPDB1` from `con_name` are
one container, and a check that said otherwise would fail on a correct estate
every time. A PDB created with a quoted lower-case name would defeat that; it is
exotic enough to be worth the trade in this direction, since the alternative
rejects the ordinary spelling on every run. The same rule already applies to
`C##` prefixes when the driver decides whether a name is a common user.

**An unresolved scope does not satisfy an assertion.** Where the driver reports
`unknown`, a declared scope is an error rather than a pass: a claim that could not
be checked is not a claim that held, and treating "we could not tell" as agreement
is the mistake that made a broken capability probe look like a measurement (#195).

**Open mode is checked separately, and only by the commands that write.** UC-1 §5
step 2 asks for read-write as part of pre-flight, but `check` reads and must keep
working against a physical standby — so refusing one belongs to `apply` rather
than to having connected. Implemented in
`sopuli/driver/oracle/capabilities.py` (#177) as `assert_scope` and
`require_read_write`, which are two calls for that reason.

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
| `safety` | a `safety:` block, so a whole population can be marked `readonly` in one place. It applies to a run that reaches any target the group matches — nothing has to select *by* the group (#424) |

### `safety:`, wherever it appears

| Key | Meaning |
|---|---|
| `max_targets` | at least 1. Use `readonly: true` to block changes entirely — `max_targets: 0` is far more likely to be a slip that then blocks every run |
| `confirm_environments` | environments a mutation may not enter without an explicit yes |
| `readonly` | refuse every mutation |

A block may be written under `defaults`, a profile, a target, a target set's
template or `overrides:` entry, or a group. §9 resolves the lot by taking the
safest of them.

Every field is optional, and an unset one stays unset rather than taking the
built-in default. §9 resolves safety by taking the *safest* of all layers rather
than the last one, and "safest of all layers" needs to know which layers said
nothing.

#### Where a block may be written, and when each one is merged (#424)

`defaults` and a profile are properties of the **run**, so they are resolved at
the boundary before a verb starts. A target's and a group's are not: which of
them applies depends on which targets the run is about to reach, and at the
boundary no selector has been applied yet. So they are merged a second time, once
a verb has narrowed its estate and before it builds its plan —
`sopuli/safety.py`'s `for_estate`, through the same resolver and on the same
contributions, so the ratchet stays one mechanism rather than two that have to
agree.

**A target speaks when the plan names it**, which is the set
`plan.blast_radius` counts. A declared target this run touches nothing on is not
reached, and a block on it says nothing about this run. A group speaks when it
matches a target that is in the plan.

This was parsed and enforced by nothing until #424. `readonly: true` on a target
did not stop a mutation, a `max_targets` on one bounded no run, and a
`confirm_environments` on one asked nobody anything — the keys validated cleanly,
appeared in `config show`, and refused nothing. A config that reads like
protection and is not is worse than no setting, and this is the one direction
invariant 10 must not fail in.

#### What `readonly` does when it fires

**It refuses the whole run, at plan time** (#424). A run that reaches one
readonly target does not apply to the others and report the first as skipped.
Three readings were on the table and this is the decided one:

- **Skipping the marked targets** would make `readonly` mean two different things
  depending on where it was written — a refusal under `defaults`, a filter on a
  target — and it does not generalise to the rest of the block: there is no
  per-target reading of `max_targets` that skips its way under a ceiling, and a
  `safety:` block is resolved as a unit. It also turns an incomplete rotation
  into an exit code somebody has to notice.
- **Refusing without saying what to do** is the same refusal with less in it. The
  cost of refusing is real — one readonly PDB in a selection of two hundred stops
  the other hundred and ninety-nine — so the message names the marked targets,
  the key that marked each one, and the selectors that would leave them out.
  Narrowing is the mechanism the tool already has for "operate on less than
  this", and handing it back is what makes the operator's call theirs rather than
  the tool's.

At **plan time** rather than on the way past, which is invariant 4: a readonly
target discovered while the estate is being walked is exactly the generic
mid-execution failure that invariant forbids. Exit 8, `category: policy`, like
every other refusal in the block.

The message names a target and the key, and the key is where it was *written* —
a generated target's block lives in its set's template, or in the `overrides:`
entry that patched it, and pointing at the template when an override is the
reason would send the reader to the one place the value is spelled the way they
expected. A group has no key of its own to point a target at, so the refusal
pairs the two: which database is protected, and which line protects it.

```
$ sopuli creds apply --application acme --dry-run
sopuli: applying a password is a mutation, and `safety.readonly` is set on 1 of the 2 targets it reaches
  hint: readonly: free-pdb (targets[0].safety.readonly); no layer can relax it (invariant 10) -- narrow the run with --target, --group or --select so it does not reach it, or read instead with `sopuli creds check` or `sopuli creds status`
```

Where every target in the plan is marked there is no narrowing to offer, and
saying "narrow the run" would be advice that cannot work, so the message says so
instead:

```
$ sopuli creds apply --application acme --dry-run
sopuli: applying a password is a mutation, and `safety.readonly` is set on the target it reaches
  hint: readonly: free-pdb (groups.sandbox-pdbs.safety.readonly); no layer can relax it (invariant 10) -- no narrowing of this run can avoid it, so read instead with `sopuli creds check` or `sopuli creds status`
```

`--dry-run` is refused with the rest, for the reason `defaults` already refuses
it: under `readonly` the mutating verbs are unavailable, and the read-only verb
is how you ask.

**`lock break` is the one mutating verb a target's or a group's block does not
reach**, and that is a decision rather than a verb that was missed (#424, raised
in review on #425). Three reasons, and the third is the one that settles it:

- It addresses a **vault document by path** and takes no selector, so there is no
  estate for layer 4 to arrive from. It acts on the lock named whether or not the
  configuration declares a binding for it, which is #150's decision and the whole
  reason the verb can clear a leftover at a path the file no longer names.
- `readonly` on a *target* is a statement about that database. The lock is not
  the database, and breaking it changes no credential — it takes an advisory lock
  and fences its holder.
- **It protects nothing that is not already protected.** Every verb that would
  use the lock to change that target — `rotate`, `apply`, `generate`,
  `finish-rollover` — is refused by the same block. So gating `lock break` here
  would block a harmless cleanup and guard nothing, and the operator left holding
  a stuck lock on a readonly population would have to edit their config to clear
  a record that could not have been used against them.

`defaults` and a profile still refuse it, and there the statement is a different
one and coherent: *this file may not write anything*, lock store included.

#### Seeing what a file guards (#426)

A block's effect is enforced; **where it is written** is a separate question, and
until #426 nothing answered it. `config show --explain` reports the *run's*
settings, and `config show` applies no selector and builds no plan, so
`safety.readonly = false [built-in default]` is the correct answer there for a
file whose target sets it — §9 defines that phrase as *nothing else spoke*, and
about the run, nothing did. The row was never the defect. The defect was that
nothing else in the command said a block existed.

`config show` now carries a **`safety` section**: one row per key, by the key that
writes it, over every place a block may appear.

```
safety
KEY                                                         VALUE      NOTE
defaults.safety.confirm_environments                        prod
groups.legacy.safety.confirm_environments                   prod, uat
profiles.audit.safety.readonly                              true
target_sets.appdb.overrides.appdb-dev-beta.safety.readonly  true
target_sets.appdb.safety.max_targets                        4
targets[0].safety.max_targets                               1
targets[0].safety.readonly                                  true
```

Four things about it are decisions:

- **Every block, not only the object layer.** `defaults` and a profile are already
  visible in `--explain`'s table, and omitting them here would make this section
  its own half-truth — a map of a file's guards with two of the six kinds of place
  missing. The two views answer different questions and both are worth having.
- **One row per key, not per block**, because a key path is what gets edited and a
  block writes up to three of them. Deduplicated by that path, which collapses a
  target set's template to one row however many targets it generates — the
  template is one line in the file.
- **An `overrides:` entry is its own line.** Reporting a patched key against the
  template would point at the place the value is spelled the way the reader
  expected. Keys the override did **not** write stay on the template's line, which
  is the same rule the enforcement uses (`sopuli/settings/sources.py`).
- **A defeated relaxation is marked, not hidden.** An override asking for less than
  its template loses the ratchet, and its row says `defeated by the ratchet`.
  Dropping it would leave somebody who wrote `readonly: false` with no sign of it
  anywhere — this section's own failure in miniature — and showing it unmarked
  beside rows that are in force would read as an effective value. A row is marked
  only where nothing it applies to ever reads it, so a template lowered by one
  generated target's override is not called defeated while it governs the rest.

The section is absent from a file that writes no block.

**`--resolved` answers it per target instead**, and the JSON contract with it:
`config.targets[].safety` is the block in force for that target after the template
and any `overrides:` entry have been ratcheted together, or `null`. `defaults`, a
profile and a group are not folded in — none is a property of a target, and
folding them would make one object's answer depend on four while hiding which.
Schema 1.22, additive (`03-json-output.md`).

#### What `confirm_environments` does when it fires (#292)

Parsed since this document was written and **enforced since #292**, which is
longer than it should have been: the key validated cleanly, merged under the
ratchet, appeared in `config show`, and was read by nothing — a config that read
like protection and was not, which is worse than the setting not existing.

`creds generate`, `creds apply` and `creds finish-rollover` consult it. `creds
rotate` does not, and that is not an omission: UC-1 §8 step 1 makes its
confirmation unconditional, so the setting could only ever make that gate weaker.
`lock break` does not either, for the same reason one step further along — it
always confirms and takes `--force` on top.

Four things about it are decisions:

- **It matches the environments the *run* reaches**, not the ones the file
  declares. `plan.blast_radius.environments` is the list, which is what that
  field was added for. A run narrowed to dev by a selector is not asked about
  prod merely because prod exists elsewhere in the estate — a gate that asked
  every time is one that gets switched off within a week.
- **`--confirm` satisfies it.** P5 says every mutating command supports
  `--confirm` — and only that, since #294 struck the `--yes` alias P5 had
  promised and nothing ever built — and this setting says these environments are not entered
  without an explicit yes; the flag is that yes, given in advance. So the setting
  configures *where a yes is required*, not a second gate that a yes cannot
  answer. A scheduler adds one flag rather than keeping an environment list in
  step with its config.
- **Unattended is a refusal, not a prompt.** With no terminal there is nobody to
  ask, and click's EOF abort would tell an operator that the run stopped without
  telling them what to type. Exit 8, `category: policy`, naming the setting, where
  it was written, and both `--confirm` and `--dry-run`.
- **`--dry-run` is never gated**, which is the opposite of `readonly` and right
  for the opposite reason. `readonly` decides whether a verb is available at all;
  this decides assent, and a preview is how somebody works out what they are
  assenting to. Prompting before printing the plan would ask for a yes to the
  question the operator ran the command to see.

`--force` does not satisfy it and is not consulted: P3 (#89) puts `--force` on
the *account* guardrails of `02-oracle-privileges.md` §4 and never on a safety
setting. It is not a setting, has no layer to arrive on, and so has nothing to
relax (invariant 10).

**There is no built-in list, and that is load-bearing.** P5 used to say
confirmation was required by default when "the target is marked
`environment: prod`", which reads like a built-in `confirm_environments: [prod]`
— and §9 forbids exactly that: a built-in taking part in a union ratchet is an
unremovable floor, so no layer could ever remove `prod` again. §9's own worked
example of the trap is `confirm`.

**§9 won, and P5 was reworded** (#294, C17). The two documents could not both be
honoured as written, and the tie-breaker was which of them would be doing damage
if it were wrong: a §9 that yields here gains an unremovable floor and loses the
property that makes the whole precedence table legible, while a P5 that yields
loses a default some estates would have wanted and that any of them can write in
one line. So confirmation is **opt-in**, `environment: prod` is a label like any
other, and a site that wants the prompt lists `prod` — which is the thing the
estate was always going to have to do for `staging` or `uat` anyway.

The consequence is worth stating plainly rather than leaving to be inferred: an
estate that marks a target `environment: prod` and writes no
`confirm_environments` is **not prompted**, and that is specified behaviour and
not an unimplemented trigger.

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
| `vaults.<name>.*` | how to *reach* a named store — everything except the three below. This is what lets a profile say "token from a laptop, AppRole from CI" without re-declaring the store. Not `type`, and not `non_production` or `locking` — see below (C13) |
| `verify.method` | `login` \| `hash` \| `both` \| `none` |
| `verify.lockout_margin` | how close to `FAILED_LOGIN_ATTEMPTS` to stop trying |
| `safety.*` | `max_targets`, `confirm_environments`, `readonly` |
| `locking.break_expired` | may an unattended run take over an expired lock (#83)? The profile is where this belongs: it is a property of running without anybody watching |
| `confirm` | whether interactive confirmation is possible at all |
| `output` | `text` \| `json` \| `jsonl` |
| `log_level`, `log_file` | |
| `db.connect_timeout_s`, `db.query_timeout_s` | slower budgets for unattended runs. `connect_timeout_s` defaults to 30 s — a connection that times out has applied nothing. `query_timeout_s` defaults to **no bound**, deliberately: a call timeout cancels the round trip without undoing what the server did with it, and `ALTER USER` is not transactional, so an imposed default turns a slow success into a run that cannot say whether the password changed. Invariant 7 has no answer for that state; an operator may still set one. **Both are consulted** (#360): `_timeouts()` in `sopuli/cli.py` resolves the pair and hands them to every driver the tool builds, so a profile narrowing either changes what the connection does. Wiring `query_timeout_s` did not change what the tool *imposes* — the built-in is still no bound, for the reason above — only what an operator can reach on purpose. This row has been wrong twice: it once said neither key was consulted, and then that only one was, while `connect_timeout_s` had a reader that was reading a mapping the name was never put into. Which is why the claim now lives in the registry and in `tests/settings/test_settings_are_wired.py` (#358) rather than in this sentence |
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

**Everything else is patchable**, which is the rule rather than the four keys the
table above used to list: that list was written before `namespace`, `timeout_s`
and the `tls:` block existed (#135). Stating it as the complement means a key
added to a vault entry becomes patchable unless somebody writes down why it is
not — which fails loudly for whoever adds the next guardrail and quietly for
nobody.

Applied as of #153, in the same single pass that merges layers 4 and 5
(`sopuli/config/vault_layers.py`). Resolving those two first and folding the
profile in afterwards would give the right *value* for an overridden key and the
wrong *provenance* — and for `tls.verify`, the one vault key under the ratchet,
it would report the winner of the first pass rather than the layer somebody has
to go and edit. So the active profile has to be chosen before the file's stores
are merged, which is why `build_config` takes the profile name.

A profile that is declared and not active patches nothing: rule 1 below is that
exactly one profile is active, so the rest are inert text in the file.

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
   compose; if you want a variant, write it out. The chain is the ordinary one —
   `--profile` and `SOPULI_PROFILE` are layers 1 and 2 of the `profile` setting,
   and `defaults.profile` is layer 5 — so it is resolved by the same resolver as
   everything else, and `config show --explain` attributes the *choice* as well
   as what it supplied.
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
   behaviour in a scheduler. Exit 9, like every other name in the file that names
   nothing, and the message lists the profiles that are declared. A name written
   in `defaults.profile` is reported against that key; one typed on the command
   line has no line to point at, so it is reported against the file.

**Not every key a profile may write is a setting yet.** `verify.*`, `confirm`,
`log_level`, `log_file`, `rotation.strategy`, `db.*` and `vault` are parsed and
validated, and reach nothing, because nothing consumes them — they join the
resolver with their consumers, which is the rule `sopuli/settings/registry.py`
states. What layer 3 supplies today is `output`, `safety.*`,
`locking.break_expired` and `vaults.<name>.*`. A profile writing one of the
others is not an error and does not appear in `invocation.options`, because it
changed nothing.

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
output             = json    [profiles.scheduled.output]
profile            = scheduled  [cli --profile (verb)]
safety.max_targets = 1       [defaults.safety.max_targets]
                     profiles.scheduled.safety.max_targets asked for 200; …
```

That last line is the case worth being able to see. The source is the key path
rather than the layer word plus the profile name — the same choice `defaults.*`
rows already make (#53): the question the view answers is *what do I edit*, and a
key path answers it while `[profile scheduled]` sends somebody looking.

`invocation.profile` is reported whether or not the profile changed anything,
unlike `options`: *which* profile a scheduled run was invoked under is the first
question when two runs over one config behaved differently, and answering it only
when a key happened to differ would be answering a different one. It is omitted
when no profile is active.

---

## 6. Environment variables

Naming: `SOPULI_` + upper-snake path, `__` for nesting into a named object.

| Variable | Overrides |
|---|---|
| `SOPULI_CONFIG` | config file path |
| `SOPULI_PROFILE` | active profile (§5) — the usual way a CI job or scheduler selects one |
| `SOPULI_VAULT` | default vault name — layer 2 of the same setting `defaults.vault` writes |
| `SOPULI_VAULT_ADDR` | address of the **default** store: whichever one `SOPULI_VAULT` or `defaults.vault` names. Refused when neither does — see *Which store is "the active" one* below. `--vault-addr` is the same setting one layer up (#422) |
| `SOPULI_VAULT_TOKEN` | token for the active vault. Outranked by `--vault-token-file` and by a store's own `token:` (§3a); there is deliberately no flag carrying a token value, so this is the answer where writing one to disk is awkward |
| `SOPULI_VAULT__VAULT_DEV__ADDR` | address of a *specific* named vault. `ADDR` is the only key addressable this way today; any other spelling under `SOPULI_VAULT__` is refused, naming what is available |
| `SOPULI_DB_ADMIN_USER` / `SOPULI_DB_ADMIN_PASSWORD` | admin credentials (password is low-assurance, flagged in output). The password pair is the default for `admin.auth: { method: env }`; a target may name its own variable with `password_env:` (§3a) |
| `SOPULI_ORACLE_CLIENT_LIB_DIR` | Oracle client directory for thick mode. Read at the first connect (#176) and passed to `init_oracle_client(lib_dir=…)`. Outranks `runtime.oracle.client_lib_dir` (P3: environment is layer 3, the file is layer 6); with neither set the platform's own loader decides, which is the ordinary Linux install and needs nothing |
| `SOPULI_OUTPUT` | `text` \| `json` \| `jsonl` |
| `SOPULI_LOG_LEVEL` | log level |
| `SOPULI_NO_COLOR` / `NO_COLOR` | disable colour — set and not empty, whatever the value. Outranked by an explicit `--color always`; see `03-json-output.md` §1 for the full precedence |
| `SOPULI_DRY_RUN` | force dry-run globally (safety ratchet: no flag turns it off). Set and non-empty is the whole answer, whatever the value — `SOPULI_DRY_RUN=0` means dry-run |

Honoured third-party variables, ranked *below* their `SOPULI_*` equivalent:
`VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, `VAULT_CACERT`,
`OCI_CLI_PROFILE`, `OCI_CLI_CONFIG_FILE`, `TNS_ADMIN`, `ORACLE_HOME`,
`NLS_LANG`, `HTTPS_PROXY`, `NO_PROXY`.

Of that list, `VAULT_ADDR`, `VAULT_NAMESPACE` and `VAULT_CACERT` reach a store's
`addr`, `namespace` and `tls.ca_file`, on the default store, at P3's layer 3.
`VAULT_TOKEN` is auth material rather than a setting and belongs to §3a's token
chain; the rest wait for the subsystems that read them.

**`VAULT_SKIP_VERIFY` is the one exception.** It is read and **refused** with a
config error rather than honoured or silently ignored (ADR-005): it names the
same setting as `vaults.*.tls.verify`, which is under the P3 safety ratchet, and
honouring an unranked environment variable there would let it bypass every
layer the ratchet is supposed to outrank. Refusing loudly means anyone who set
it (Vault's own CLI convention) learns that it did nothing, instead of running
unverified and believing otherwise. No *other* variable reaches `tls.verify`
either, under any spelling — the environment can supply a CA file and cannot
turn verification off.

### Which store is "the active" one

`SOPULI_VAULT__VAULT_DEV__ADDR` says which store it means. `SOPULI_VAULT_ADDR`,
`VAULT_ADDR` and `--vault-addr` do not, and a run touching two vaults has two
active stores and one of each. **They apply to the store `defaults.vault` names**
— with `SOPULI_VAULT` above it, being layer 2 of the same setting — and to no
other.

The alternative, following whichever store the current binding resolved to, is
the `vault_settings:` block C13 rejected, spelled as a variable: it lets a
setting written for dev follow a changed `vault:` into prod. Decided in #154.

Where nothing names a default store, the two halves answer differently:

- **A `SOPULI_*` variable or `--vault-addr` is refused** with a config error
  naming the three ways to fix it. It was written for this tool, and §6's own
  argument about `VAULT_SKIP_VERIFY` applies — silently doing nothing is worse
  than either honouring or refusing.
- **A third-party variable warns** and is not applied. `VAULT_ADDR` is exported
  in every shell that has run `vault`, and it was not set for this tool at all;
  failing a run over somebody else's variable would be taking a position on an
  environment the tool does not own. The warning appears in `diagnostics[]`.

### `--vault-addr` — layer 1, and the only flag of its kind (#422)

```
$ sopuli config show --vault-addr https://vault-standby.example.com:8200
vaults
NAME       TYPE       ADDRESS                                 NOTE
vault-dev  hashicorp  https://vault-standby.example.com:8200  layered: addr
```

It reaches `addr` and nothing else: the store keeps the `mount`, `kv_version`
and `auth:` the file wrote. Where nothing names a default store it is refused,
in the words `SOPULI_VAULT_ADDR` is already refused in:

```
$ sopuli config show --vault-addr https://vault-standby.example.com:8200
sopuli: no-default.yaml: --vault-addr names no store, and this run has no default one to apply it to
  hint: it applies to the store `defaults.vault` names -- write one, export SOPULI_VAULT=<store>, or address a store directly with SOPULI_VAULT__<STORE>__<KEY>
```

Exit 9. The `NOTE` column says which key was layered and not which layer did it,
which is true of every one of them. Which layer did it is
`config show --explain`'s answer — see *Which layer wrote it* below.

Three things were decided with it, and the third is the one that keeps it small.

**It addresses the store this section already defines as the active one** — what
`SOPULI_VAULT` or `defaults.vault` names — and is refused where neither does. It
does not follow whichever store the current binding resolved to; that is C13's
rejected `vault_settings:` block spelled as a flag, and it lets an address typed
for dev follow a changed `vault:` into prod. A command line resolving "the
default store" its own way would be a *second definition* of it, one layer above
the first, and the two would agree until the day somebody changed one. It shares
the placement code with the variables so they cannot.

**There is no named form.** A run touching two stores uses
`SOPULI_VAULT__<NAME>__ADDR`; `--vault-addr NAME=URL` would put a third `K=V`
grammar on a command line that has one (`--select`). `--vault-token-file` is the
precedent and is unnamed for the same reason — with one difference worth stating
rather than discovering: a token is plausibly the same across the stores one run
touches and an address is definitionally per-store, so the multi-store case here
really does fall back to the environment rather than merely preferring it.

**There is no `--vault-mount`, `--vault-namespace` or anything else.** One flag
per reach key would be six spellings of what `vaults:` already says once. The
case for this one is specific: an **address** is the thing an operator redirects
for a single run — a standby, a test instance, a port-forward — and every other
way to do that outlives the command. `env VAR=… sopuli …` is a clean one-shot on
Linux; PowerShell has no inline prefix, so the same thing is two statements and a
session that remembers it, and P4 makes Windows a supported tier rather than a
best-effort one. That asymmetry is the argument, and it does not generalise to
`mount`, which nobody redirects for one command.

It takes both parser positions, like every global option that is not a safety
flag: both are layer 1, the same person in the same command line, so neither
outranks the other (P3).

### Which layer wrote it (#428)

`addr` is the one key seven different sources can write, and for as long as the
`NOTE` column was the only report of it, all seven produced the same line. A
store whose address came from a colleague's exported `VAULT_ADDR` looked
identical to one an operator redirected on purpose, and *why is this run talking
to that vault* is the first question when a rotation lands somewhere unexpected.

`config show --explain` answers it, as rows in the same `settings` table the
run's own settings appear in:

```
$ sopuli --config layers.yaml --profile standby config show --explain
vaults
NAME       TYPE       ADDRESS                                 NOTE
vault-dev  hashicorp  https://vault-standby.example.com:8200  layered: addr, namespace, timeout_s

settings
  db.connect_timeout_s        = 30                                      [built-in default]
  db.query_timeout_s          = 0                                       [built-in default]
  output                      = text                                    [built-in default]
  profile                     = standby                                 [cli --profile (group)]
  safety.dry_run              = false                                   [built-in default]
  safety.readonly             = false                                   [built-in default]
  vault                       = vault-dev                               [defaults.vault]
  vaults.vault-dev.addr       = https://vault-standby.example.com:8200  [profiles.standby.vaults.vault-dev.addr]
  vaults.vault-dev.kv_version = 2                                       [vaults.vault-dev.kv_version]
  vaults.vault-dev.mount      = kv                                      [vaults.vault-dev.mount]
  vaults.vault-dev.namespace  = acme-dev                                [defaults.vaults.vault-dev.namespace]
  vaults.vault-dev.timeout_s  = 10                                      [defaults.vaults.vault-dev.timeout_s]
```

with `defaults.vaults.vault-dev` writing the namespace and the timeout, the
declaration writing the mount and the KV version, and the active profile
redirecting the address. The other sections of that run's output are elided; the
table is not.

The seven sources render as `[cli --vault-addr]`,
`[env SOPULI_VAULT__VAULT_DEV__ADDR]`, `[env SOPULI_VAULT_ADDR]`,
`[env_thirdparty VAULT_ADDR]`, `[profiles.<name>.vaults.<store>.addr]`,
`[vaults.<store>.addr]` and `[defaults.vaults.<store>.addr]`. Four decisions are
in that table rather than in its layout.

**The rows join the run's table rather than getting a section.** They are
settings of the same chain, merged by the same resolver — and P3's own worked
example of this view is a vault key. A `SOURCE` column on the `vaults` table was
the alternative and loses to the reason `--explain` is laid out by hand: a
truncated `SOPULI_VAULT__…` is useless in exactly the moment the view exists for.
Keeping `NOTE` and appending the layer to it was the third option, and it keeps
the layer while losing the location, which is the half that says what to edit.

**Every key that has a value, not only the layered ones.** `vaults.vault-dev.mount`
gets a row reading `[vaults.vault-dev.mount]` — the file wrote it, there. The
bracket repeats the row name exactly in that one case, which is what that sentence
looks like rather than noise: without it, an absent row would mean either *nobody
wrote this key* or *only the declaration did*, and a provenance view that cannot
separate those two answers the question it exists for with a shrug.

**The store is concrete.** The registry's key is `vaults.*.addr`, with `*`
standing for every store at once, and that is not something anybody can act on.
The row names the store, which makes it character-for-character the config key to
grep for.

**`auth:` gets no row.** It is replaced whole rather than resolved key by key
(`sopuli/config/vault_layers.py`), so no layer *won* a key and there is no
provenance to report; `NOTE` still says `layered: auth`. It is also the one part
of a store entry that addresses credentials, and a section whose every value is a
setting is not where those belong.

One knock-on, found in review of #428: `vaults.*.<key>` is the name the resolver
is **asked** with — §9's registry is a literal, so a store's settings are one
entry with `*` where the name goes — and it is not a name anybody can be told.
Nothing quoted it back until this view existed; now the ratchet note under a
defeated `tls.verify` does, and so does the warning every command that loads the
file emits. Both name the concrete store, and they are renamed once where the
merge happens rather than in either view — one sentence spelled two ways, three
lines apart, is the defect §9's single resolver exists to make impossible.

`config show --output json` carries the same answer for a consumer, as
`config.vaults[]` — see `03-json-output.md`. It is there in **both** shapes,
which is the part of this that was not a provenance question at all: `--explain`
emitted `config.declared`, the address the *file* wrote, and `--resolved` dropped
stores entirely, so no mode of the command told a script which vault a run would
talk to.

### Naming a store in a variable

A store's name becomes a variable segment by upper-casing it and writing `-` as
`_`, since a hyphen is not legal in a variable name. That mapping is not
injective: `vault-dev` and `vault_dev` are both `VAULT_DEV`. Where a file
declares both and the ambiguous variable is **set**, it is refused, naming both
stores — never resolved by picking one. Declaring both is legal on its own; the
ambiguity is not real until something depends on it.

Anything under `SOPULI_VAULT__` that addresses no declared store's setting is
refused the same way, whether the store name is wrong, the key is, or the store
was renamed. That prefix is this tool's namespace, and invariant 5 already says a
variable cannot address a store the config does not declare.

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

The vault variables that name a setting *of* a store are the other exception:
they live in `sopuli/config/vault_env.py` and join the merge in
`sopuli/config/vault_layers.py`, because a store's settings belong to the store
rather than to the run and that merge is where the file's own layers already
meet (C13). `SOPULI_VAULT` stays in `sources.py` with the rest — it names a
store, and which store a run defaults to *is* a setting of the run, reported in
`invocation.options` like every other. `SOPULI_VAULT_TOKEN` and `VAULT_TOKEN`
are in neither: a token is auth material, resolved by `sopuli/material.py`, and
must never be reported as a setting (ADR-007).

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

**Resolving** one — turning a parsed ref plus a stored document into a value, and
back — is `sopuli/store/credentials.py` (#183), and it is a separate layer on
purpose: the address is decided when the file is read and the document is not
touched until something connects. Two things it settles that the grammar above leaves open. The
value has to be a **string**: a ref landing on a map has addressed the wrong
depth, typically the container rather than the account inside it, and that is
refused rather than wrapped and passed on to `ALTER USER`. And a ref that finds
**nothing** — no such field, no `pending` staged for this account, no document at
all — resolves to nothing rather than failing, because UC-1 §3's state model
reads all of those as one state.

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
| `tenants/beta#pending/{account}` | the container is a key the rotation mechanism owns. `pending`, `previous`, `origin`, `rotated_at`, `rotated_by`, `policy` and `targets` are all reserved; `current` is not, because the ref already points at it |

Both are refused **while the file is read** rather than at the first rotation —
§1 calls this binding the safety-critical part, and invariant 4 wants a command
that cannot succeed to fail before it has written anything. The check runs per
binding in `sopuli/config/bindings.py`, on the *rendered* ref, which is what lets
it be exact about two things a check on the written template could not be: the
tokens are already substituted, and the store is known.

**And no two accounts may stage into the same place** (#255). The rule above is
about a ref with *nowhere* to stage; this one is about a set of refs that all
have the same somewhere:

```yaml
accounts: [acme_web_user, acme_batch_user]
secret_template: "apps/acme/db#{account}"     # a FIELD per account, no pointer
```

That renders to a distinct ref per account, so it passes every check that looks
at one ref at a time — and then the mirror rule puts *both* accounts' `pending`
at the document root, because neither ref has a pointer for the stage to follow.
One document, one `pending`, two passwords: the merge keeps whichever was written
last, so one account's new password is lost and the other's is given to both.

The shared layout wants a pointer per account — `#DB_CREDENTIALS/{account}`, the
spelling §2 uses — which addresses the stage per account and merges cleanly. The
broken form is one character away from it, which is why this is refused rather
than reported.

It is a property of the **set** of bindings for one document rather than of any
single ref, so it runs once every binding exists; that is still load time, and
still before a command has done anything. `sopuli/generate.py` keeps the same
guard at the write boundary, because a binding whose store C15 completes later
(§6) has no known backend while the file is being read, and the rule below is
why that matters.

**The store is why this is not a universal rule.** On OCI the stages are versions
of the secret rather than fields in it (P2's `staging_labels` row), so a ref
naming a whole secret is the natural layout there and a field called `pending`
collides with nothing. No refusal in this section fires against a store that
stages natively. A store type P2 gives no capability row — `keyring` — is left alone
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

**What triggers the fallback** (#183) is either of two things, and neither is a
failure. A store with no merge-patch endpoint — KV v1 — is answered by
`supports()` before anything is sent. A Vault **policy** granting `update` and
not `patch` is not: `patch` is a capability of the mount, while whether this
token may call it is a question no capability set can answer, so it is discovered
by asking and the 403 on that one verb is read as "use the other mechanism". A
403 on any other verb keeps its ordinary meaning. If the token really was bad,
the fallback's own read fails with the refusal it deserves — one wasted round
trip, never a silent success.

**The run says which mechanism it used**, per UC-1 §3, and that reporting is
load-bearing rather than informational: under a merge patch a sibling account's
password is never read into the process, and under the fallback the whole
document goes out. Equally safe against a concurrent writer, and not equally
narrow.

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

### `account:` — what the tool may do to the account itself

Separate from `password:` because it is a different question. `password:` says
what a credential must look like; `account:` says which of UC-1 §5's non-password
attributes this run may enforce.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `unlock_if_locked` | bool | `false` | `apply` issues `ALTER USER … ACCOUNT UNLOCK` for a locked account before setting its password (#300) |
| `profile` | string | — | the profile this account is to sit on. `apply` issues `ALTER USER … PROFILE …` where the account is on a different one (#301) |

**These two are the whole list, and it is closed.** §5 named four attributes; the
other two never became keys here and never will. `PASSWORD_EXPIRE` handling
(#302) is not an operation this use case has — clearing an expiry is what `apply`
already does, and expiring one deliberately breaks an application account — and
default/temporary tablespaces (#303) belong to UC-4, provisioning, because
assigning one moves no existing segment and so is a half-change during a rotation
and the right thing during a create. UC-1 §5 has the argument for both; the
roadmap in `docs/README.md` has the use cases they went to.

A third key here would be a decision rather than an implementation detail.

**`profile:` is a name, and which profiles exist is a property of each target.**
It is resolved against `DBA_PROFILES` and used in the spelling the dictionary
gives back, for the reason `02-oracle-privileges.md` §4 gives about account names:
an Oracle quoted identifier is case-sensitive, so a file writing `acme_app_prof`
would otherwise address a profile no database has. A target that has no such
profile is a pre-flight finding and, failing that, a refusal for that account —
never an `ORA-02380` part way through an estate.

**The tool assigns a profile and never creates or alters one.** `ALTER PROFILE`
edits a shared object, so it reaches accounts nobody selected; §3 of
`02-oracle-privileges.md` keeps the privilege off the service account, and Q4
(#88) decided it: never, in any credential-sync verb. Creating and altering
profiles is UC-4's, provisioning (see the roadmap in `docs/README.md`), and #88
leaves that question open rather than foreclosing it.

**Naming a profile and naming a `--strategy` in one run is refused** where the
assignment would actually move the account. A profile decides whether a rotation
opens a rollover window, so a regime judged against the profile an account is
leaving is a regime judged against the wrong thing — see UC-1 §5.

**Every one of them is opt-in and off by default, and that is the rule rather
than a default.** A tool that unlocked an account because it found one locked, or
moved it to a profile because a policy named one, would be making a change nobody
asked for during a credential rotation — which is the worst moment in an estate
for a surprise. Omitting the key and writing `false` therefore mean the same
thing, and a policy that declares no `account:` block at all means it too.

An estate that declares no policy is unaffected: applying a password has never
needed one, and reading these attributes does not make a policy a precondition —
which is the one way this section could have broken a working config.

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

`output` is the setting that shows the most of it at once: it is the one with a
flag, an environment variable *and* a profile layer. Against a config whose `ci`
profile sets `output: json`, climbing one layer per command:

```
$ sopuli config show --explain
  output               = text   [built-in default]

$ sopuli config show --explain --profile ci
"output": { "value": "json", "source": "profile", "source_detail": "profiles.ci.output" }

$ SOPULI_OUTPUT=text sopuli config show --explain --profile ci
  output               = text   [env SOPULI_OUTPUT]

$ SOPULI_OUTPUT=json sopuli config show --explain --profile ci --output text
  output               = text   [cli --output (verb)]
```

The second command answers in JSON because the profile it selected says to, which
is the layer being demonstrated; its line above is abridged from that document's
`invocation.options`. In the last, the flag wins over both the environment and
the profile beneath it — the operator at the keyboard is the more specific intent.

The third-party layer does not appear, because `output` has none: `VAULT_ADDR`
ranking below `SOPULI_VAULT_ADDR` and below `--vault-addr` is §6's to show, being
a setting of a store rather than of the run. A store's keys are nonetheless *in*
this table — as `vaults.<store>.<key>` rows beneath the run's, since #428 — and
the reason to work `output` rather than `addr` through here is that this section
is about the chain and §6 is about the store.

**These examples are pasted, not written** (#409). They were once drawn on
`--vault-addr` and `--method`, and at the time neither flag existed — `sopuli`
rejected both before any precedence was consulted, so the documented outcomes
were predictions. `output` was chosen over marking the old blocks illustrative
because it has a real layer at every level shown, which leaves nothing in this
section excused from running. **`--vault-addr` has since been built** (#422) and
these examples were still not moved back onto it: §6 is where its own chain is
worked through, and it is the longer one — seven sources across six layers, with
a third-party variable ranked between two of them. That paragraph used to add
that a store's settings "never appear in the `settings` table this section is
showing", which was true when it was written and stopped being true in #428.
Fixing the sentence rather than the example on the strength of it: `output` is
still the setting with one clean layer at every level.

Safety ratchet — `defaults.safety.readonly: true`, and a `ci` profile that tries
to undo it with `safety: { readonly: false }`:

```
$ sopuli creds apply --application acme --profile ci --output text
sopuli: applying a password is a mutation, and `safety.readonly` is set
  hint: set at defaults.safety.readonly; no layer can relax it (invariant 10) -- `sopuli lock status` reads without writing
```

Exit 8. The profile is the higher layer and loses anyway, and the refusal names
`defaults`, the layer that has to be edited — ties and ratchets resolve toward the
config key, not toward the layer that asked to relax it. `readonly` has no flag, so
there is nothing on the command line to try; `--dry-run` is refused the same way.
This example used to be written on `--no-dry-run`, which does not exist, and
printed a refusal no run could reach (#409).

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

**A target's and a group's are merged later than the rest** (#424). They are
layer 4 and they go through this same resolver, but they cannot be resolved at
the boundary with the others: which of them applies depends on which targets the
run is about to reach, and no selector has run yet. So a verb merges them once it
has narrowed its estate and before it builds its plan. §3a says which blocks
speak and what `readonly` does when one fires; the merge itself is the ordinary
one, and the reported location is the lowest-authority contributor as it is
everywhere else. Until #424 this second merge did not exist, and the three keys
refused nothing wherever a target or a group wrote them.

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
[`docs/schemas/sopuli-config-1.3.schema.json`](../schemas/sopuli-config-1.3.schema.json),
Draft 2020-12, and it exists for the editor rather than for the tool: pointed at
from a YAML language server, it gives completion and inline errors while somebody
is editing a 130-line file, which is worth more than the validation itself.

**It is generated, not maintained.** `sopuli/config/schema.py` composes it from
the same constants the builders validate with — `TARGET_KEYS`, `VAULT_TYPES`,
`CHARSETS`, `SUPPORTED_VERSIONS` and the rest — and refuses to generate at all if
a section's keys and its type table disagree. Regenerate with:

```
python -m sopuli.config.schema > docs/schemas/sopuli-config-1.3.schema.json
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
# yaml-language-server: $schema=./sopuli-config-1.3.schema.json
version: 1
```

That comment is the [YAML Language Server][yamlls] convention, which is what the
Red Hat **YAML** extension for VS Code uses, and what most other editors' YAML
support is built on. Verified with that extension: hovering a key shows the
description the generator wrote for it, and an unknown key is underlined where it
was typed.

**The path is relative to the YAML file**, not to the repository. Copy the schema
next to the config, or point at it where it lives — `$schema=../sopuli-dba/docs/schemas/sopuli-config-1.3.schema.json`
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
| a declared backend this machine cannot serve | 0 | a warning naming the store and its `type` (`SOPULI-W003`), and either the extra that supplies it or that there is nothing to install |
| anything §9a or §10 refuses | 9 | the message, with its key path and its hint |

**A missing backend warns rather than fails (ADR-006, E4).** The config is
valid; the install is incomplete, and those are different sentences. Validating
on a laptop a file that runs on a scheduler elsewhere is the ordinary case, not
the strange one, and a validator that calls a good file broken is less
trustworthy for exactly the case it exists to serve. The command that actually
needs the client is where this becomes an error (§3a).

**Missing means "this machine cannot serve it", not "the client is absent"**
(E4, widened in #238). Three of the four types in §3a have no module in this
build, so the narrower reading validated a file whose every store was unusable
as `ok: 0 warnings` — and warned about `oci` only where the machine happened to
lack the SDK, which is a fact about the laptop rather than about the file. Both
halves warn now, and the wording carries which is which:

```console
$ sopuli config validate
ok: 0 targets, 0 bindings, 2 warnings

2 warnings:
  vault "vault-local" declares type "file", but this build has no file backend yet -- this is not something to install
  vault "vault-hc" declares type "hashicorp", but that backend is not installed; install it with: pip install "sopuli-dba[hashicorp]"
```

Ordered by backend `type:` rather than by the order the stores are written in —
the survey's order, so a reader comparing this against `doctor`'s table is
reading the same list twice rather than two shuffles of it.

The second is a warning `pip` cannot act on, and that is the price of the wide
reading. The action it names is still real — *do not deploy this file yet* — and
it is temporary by construction, where the silence it replaced was not.

**The same survey `doctor` reads, at a different level.** One function answers
"can this machine serve it" for the whole tool (`sopuli/diagnostics.py`'s
`install_diagnostics`); `doctor` reads it as an `error` and exits 9 (E6), this
command reads it as a `warning` and exits 0. What differs is each command's
judgement of what the fact is worth, never the fact. `doctor` additionally
*reports* the survey as a table, which is E6's and its alone — this command
answers "is my file good", and a row per registry entry would bury the answer.

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
  belongs (invariant 4) — see §3's binding chain and `config/bindings.py`.
  **That answer is `config/binding_stores.py` (#250):** a command that needs a
  store calls `complete()`, which fills the gap from `SOPULI_VAULT` (layer 2) or
  the active profile's `vault:` (layer 3) and validates the name against
  `vaults:`, then `refuse_unresolved()`, which is invariant 4's plan-time
  refusal. It **fills gaps and never overrides** — a binding that resolved a
  store at load keeps it, so an exported variable cannot repoint a rotation at a
  different vault. `config show --resolved` deliberately does *not* call it, and
  still renders `-`: it describes the file, not a run
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
| C13 | ~~Is `vault:` under `defaults:` and in a profile a store *name* or a block?~~ | **decided: a name, everywhere** (§3a), in #31. Settings *of* a store are reached by naming it under `vaults:`, which `defaults:` and a profile may each carry as **partial** entries patching a top-level declaration. Settled once C9 closed and the `auth:` grammar stopped being the unknown: what was left was only where the file writes it, and §6's `SOPULI_VAULT` / `SOPULI_VAULT__VAULT_DEV__ADDR` pair had already chosen that shape on the environment side. P3's precedence table is amended to `defaults.vaults.hcv-prod.addr`; §5's `vault.auth` row becomes `vaults.<name>.*`, restricted to `addr` / `mount` / `kv_version` / `auth` — not `type`, and not the two guardrails `non_production` and `locking`, which invariant 10 keeps out of the invocation context. The rejected alternative was a `vault_settings:` applying to whichever store is active: shorter, but it lets auth written for dev follow a changed `vault:` into prod. **Implemented in #136** for the layers the file supplies, with one correction to the sentence above: `defaults.vaults:` is layer 5 and therefore *outranked* by the declaration, so it fills gaps rather than patching — only a profile's block, at layer 3, patches in the direction the word suggests. The `addr` / `mount` / `kv_version` / `auth` restriction became the complement of the three unpatchable keys, since #135 added three more reach settings the original list could not have named. **Applying a profile's block landed in #153**, in the same pass as the other two. **The environment's half landed in #154**: `SOPULI_VAULT__VAULT_DEV__ADDR` at layer 2, `VAULT_ADDR` / `VAULT_NAMESPACE` / `VAULT_CACERT` at layer 3, in the same single pass, with the name-to-variable mapping refusing a collision rather than picking one of two stores. It also had to answer what the *unnamed* `SOPULI_VAULT_ADDR` addresses, and the answer is C13's own: the store `defaults.vault` names, with `SOPULI_VAULT` above it — refused where nothing names one, because a variable that followed whichever store was active would be the rejected `vault_settings:` block spelled differently. **The reporting landed last, in #428**, and its absence had outlived every layer above: each of them was visible only as `layered: <key>` in one `NOTE` column, so a store redirected by a colleague's exported `VAULT_ADDR` read identically to one an operator had pointed somewhere on purpose, and `--output json` carried the address the *file* wrote or no store at all. `config show --explain` now spells each merged key as `vaults.<store>.<key>` beside the run's own settings, and `config.vaults[]` carries the same answer for a consumer (§6, `03-json-output.md`) |
| C14 | ~~What are the `@version=` and `@stage=` vocabularies, and who owns them?~~ | **decided: the tool owns both** (§7), in #40. `stage` is the closed set `current` / `pending` / `previous`, matched in any case and normalised to lower case; `version` is a whole number from 1; neither may hold a `{token}`. Settled by Oracle's own documentation: OCI's rotation states are a fixed set (`CURRENT`, `PENDING`, `LATEST`, `PREVIOUS`, `DEPRECATED`) rather than user-definable labels, and versions are integers — so there was no backend vocabulary to defer to, and passing a value through would only have moved a typo to rotation time. The run schema is thereby ratified rather than changed, including `vault` staying required on an emitted `secret_ref`: §7 describes the ref as written, the schema describes it after resolution. Knock-on: this settles Q3 (#84) at one `previous`. |
| C15 | ~~A binding names a secret and no store, anywhere — refuse, warn, or leave it to plan time?~~ | **decided in #118: mostly plan time, refused only when nothing could ever complete it.** `_vault_for`'s chain resolving to `None` is not always a mistake — a profile's `vault:` or `SOPULI_VAULT` may still supply one, and neither is consulted while bindings are built (§5, §9), so the null can be a real, temporary state rather than an error. Left alone: `config show --resolved` renders it as `-` (§10), and the command that actually needs a store fails there, once a run's profile is known and the answer is exact. Refused at load only for the narrower, genuinely unrecoverable case — `vaults:` declaring nothing at all, so there is no name even a profile or `SOPULI_VAULT` could point at (§10). The naive rule — refuse whenever a binding's store is unnamed — was rejected first: it rejects the legitimate config where one profile sets `vault:` and a run selects a different one that inherits `defaults.vault` instead |
| C16 | ~~What does `--vault-token` take? Every document treated it as a step in a chain and none said what an operator types after it~~ | **decided: nothing — it takes a path under a different name.** `--vault-token-file PATH` is the command line's position in `method: token`'s chain (§3a), and a bare `--vault-token` is **refused** with a message naming invariant 1 and all four working sources. A token as an option *value* is visible in `ps` and in the Windows process list, and P5's "or a vault ref" escape cannot apply to vault auth itself, since a ref is resolved *by* an authenticated store — the same bootstrap shape P2 already describes for the database admin credential, one layer earlier. `--vault-token-stdin` is deferred rather than rejected, because `--from-stdin` (UC-1 §5) already claims the pipe; the constraint it will have to satisfy is banked in P5 today. Reusing the MaterialRef grammar (`--vault-token env:NAME`) was rejected outright: `env:` / `file:` in a SecretRef means "resolve this via an already-authenticated store", so two identical-looking grammars would have opposite resolution order. Filed as #145 and recorded in [ADR-007](../decisions/adr-007-vault-token-flag.md), which also confirms `vault login` plus `~/.vault-token` as the intended bootstrap for a human at a terminal, and gives the flag's file P4's permission check |
| C17 | ~~P5 requires confirmation "by default" when a target is `environment: prod` or the blast radius exceeds `max_targets`; §9 forbids a built-in that joins a ratchet. Both are binding and they cannot both hold~~ | **decided: §9 governs, and P5 is reworded** (#294). Confirmation is opt-in through `safety.confirm_environments` and there is no built-in list — a built-in `[prod]` would be an unremovable floor, which is the trap §9 illustrates with `confirm` itself. The `max_targets` trigger is declined separately and for its own reason: it would prompt on every multi-target mutation for an estate that configured nothing, and it reads a *ceiling* as a confirmation threshold, which `refuse_if_over_limit` already refuses to do. Neither is deferred — a `prod` target nobody listed is not prompted for, by design, and `tests/test_cli_confirm_environments.py` pins it. `creds rotate` and `lock break` confirm unconditionally and were never part of the question |

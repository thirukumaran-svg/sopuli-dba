# sopuli-dba — Configuration Reference (draft)

Status: draft / sketch
Depends on: `00-principles.md` (P3 defines precedence)

---

## 1. Two shapes, and you start with the simpler one

**One application, and every target is its own → no `applications:` section.**
Put the binding keys at the top level and the file reads like a straightforward
target list. This is the shape most users will ever need.

```yaml
# yaml-language-server: $schema=./sopuli-config-1.0.schema.json
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
# yaml-language-server: $schema=./sopuli-config-1.0.schema.json
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
      method: token        # --vault-token, $VAULT_TOKEN, ~/.vault-token, then AppRole
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
| `type` | **required** — the backend: `hashicorp`, `oci`, `file`, `keyring` (P2). AWS and Azure are listed there as "later" and are refused until they exist |
| `addr` | backend address, where the backend has one |
| `mount` | KV mount point (HashiCorp) |
| `kv_version` | `1` or `2` — different backends with different capabilities, not a version to branch on casually (P2) |
| `auth` | `{ method: ... }` — see below |
| `non_production` | marks a store that must never master a `prod` target (§10). Absent means production |

Only `type` is required. A file backend has no address, and P2 puts per-backend
validation behind the store interface, so demanding a HashiCorp shape of every
entry would be exactly the top-level vendor bias P1 forbids.

`auth.method` is one of the methods P2 names: `token`, `approle`, `kubernetes`,
`oidc`, `userpass`, `instance_principal`, `resource_principal`, `config_file`,
`session_token`. **No other key is accepted inside `auth:` yet** — see C9.

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
| `admin` | `{ username, auth }` — the credential that reaches the database. `auth` is one of P2's bootstrap sources: `external`, `vault`, `prompt`, `env`. There is no password field, and there will not be one (P2). `vault` has nowhere yet to name *which* ref — see C9 |
| `oracle` | `{ scope, container }` — **not** an application's `oracle:` block. `scope` is `cdb_root` or `pdb`; a non-CDB database omits the block. How the two keys constrain each other is not decided — see C9 |
| `labels` | free labels for selection (C8). A generated target gets its dimension values as labels automatically |
| `safety` | a `safety:` block (§9) |

A block that is present and empty — `oracle: {}`, `admin: {}` — is an error.
Absent and empty mean the same thing to the tool, so the difference between them
is a sentence somebody started and did not finish.

`type`, `oracle.scope` and `admin.auth` are closed sets. A free string there
means `scope: cdb-root` loads happily and the tool then operates in a different
container from the one that was meant — and this file is the whitelist
(invariant 5). Widening a set is a one-line change once the reference names the
new value.

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
| **Substituted in** | every string the template writes — `name`, `dsn`, `environment`, `vault`, `admin.username`, `oracle.container`, `labels` keys and values, `safety.confirm_environments`. A field left unrendered would reach a connection string with its braces intact |
| **Not substituted in** | `type`, `oracle.scope`, `admin.auth`. They are closed sets, so a placeholder there is already refused when the set is read |
| **No escaping** | there is no way to write a literal brace. An unbalanced or empty one (`{`, `{}`) is an error, not a literal |
| **Shadowing** | a variable may not share the name of the dimension it sits under — `for_each: { env: { dev: { env: production } } }` gives `{env}` two meanings, and either choice silently decides a rendered secret path |

An `overrides:` patch is rendered in the same scope as the target it patches, so
a placeholder is resolved there too rather than reaching a DSN intact. A patch
merges rather than replaces: `oracle: { container: X }` keeps the `scope:` the
template set, `labels:` keeps the dimension labels `--select` found the target
by, and a key the patch does not mention keeps its generated value. A `safety:`
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

NAME                DSN                                              ENV  SCOPE  SOURCE
appdb-qa-alpha      db-test.example.com:1521/alphaqa.pdb.example.com  qa   pdb    target_set appdb
appdb-qa-beta       db-test.example.com:1521/betaqa.pdb.example.com   qa   pdb    target_set appdb
appdb-qa-delta      192.0.2.75:1521/deltaqa.legacy.example.com        qa   pdb    override
appdb-qa-epsilon    db-test.example.com:1521/epsilonqa2.pdb.example…  qa   pdb    override
…
8 targets (6 generated, 2 overridden)
```

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
| `vault.auth` | how to authenticate to it — token interactively, AppRole in CI. **Not yet accepted**: `vault:` is a store name everywhere else in the file, and one key cannot be both. See C13 |
| `verify.method` | `login` \| `hash` \| `both` \| `none` |
| `verify.lockout_margin` | how close to `FAILED_LOGIN_ATTEMPTS` to stop trying |
| `safety.*` | `max_targets`, `confirm_environments`, `readonly` |
| `confirm` | whether interactive confirmation is possible at all |
| `output` | `text` \| `json` \| `jsonl` |
| `log_level`, `log_file` | |
| `db.connect_timeout_s`, `db.query_timeout_s` | slower budgets for unattended runs |
| `rotation.strategy` | e.g. force `staged` where no human can watch a rollover. Only `strategy` — `rollover_hours` and the rest describe the credential's lifecycle, which belongs to the estate |

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
| `SOPULI_DB_ADMIN_USER` / `SOPULI_DB_ADMIN_PASSWORD` | admin credentials (password is low-assurance, flagged in output) |
| `SOPULI_ORACLE_CLIENT_LIB_DIR` | Oracle client directory for thick mode |
| `SOPULI_OUTPUT` | `text` \| `json` \| `jsonl` |
| `SOPULI_LOG_LEVEL` | log level |
| `SOPULI_NO_COLOR` / `NO_COLOR` | disable colour — set and not empty, whatever the value. Outranked by an explicit `--color always`; see `03-json-output.md` §1 for the full precedence |
| `SOPULI_DRY_RUN` | force dry-run globally (safety ratchet: no flag turns it off) |

Honoured third-party variables, ranked *below* their `SOPULI_*` equivalent:
`VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, `VAULT_CACERT`,
`OCI_CLI_PROFILE`, `OCI_CLI_CONFIG_FILE`, `TNS_ADMIN`, `ORACLE_HOME`,
`NLS_LANG`, `HTTPS_PROXY`, `NO_PROXY`.

### What is *not* overridable

- `accounts` / `applications` — which accounts are mastered where. Changing that
  from the environment would make the audit trail meaningless.
- `secret` / `secret_template` — same reason, and it is the mistake with the
  worst consequences.
- `policies.*.password.*` — a weaker password policy must be a reviewed change.
- `targets.*.environment` — you cannot relabel prod as dev to skip confirmation.

---

## 7. SecretRef syntax

One string addresses a value in any backend:

```
[<vault>:]<path>[#<field>][/<json-pointer>]
```

| Example | Resolves to |
|---|---|
| `apps/orders/prod/db/ORDERS_APP` | whole secret (scalar or single-field) |
| `apps/orders/prod/db/ORDERS_APP#password` | field `password` in the KV secret |
| `vault-dev:apps/orders/prod/db/creds#password` | explicit vault |
| `tenants/beta#DB_CREDENTIALS/acme_web_user` | one entry in a JSON map held in one property — the layout in §2 |
| `apps/orders/prod/db/creds#password@version=7` | pinned version (read-only contexts) |
| `apps/orders/prod/db/creds#password@stage=PENDING` | staging label (OCI native, emulated elsewhere) |

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
which would win. Their *values* are carried as written: version numbering and
the stage vocabulary belong to the backend, and P2 puts per-backend validation
behind the store interface.

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

**Writing into a shared JSON document.** Where several accounts live in one
property (`DB_CREDENTIALS` above), the tool must not clobber siblings. On KV v2 it
uses a JSON merge patch, falling back to a check-and-set read-modify-write; a
concurrent change aborts the write rather than overwriting. Sibling properties in
the same secret — application settings and the like — are never touched.

---

## 8. Password charsets

| Name | Contents | Notes |
|---|---|---|
| `alnum` | `A–Z a–z 0–9` | safest; no quoting anywhere |
| `alnum_safe` | alnum + `_ # $ - . + = ~ ^` | avoids shell, connection-string and SQL-quoting hazards. **Default.** |
| `printable_ascii` | all printable ASCII except space | requires quoted identifiers; may break connect strings and `.env` files |
| `custom` | explicit `allow:` string | you take responsibility |

Independent of charset:

- `first_char: alpha` — an unquoted Oracle password may not start with a digit
- max byte length from the target (30 vs 128), computed in the **database
  character set**, not in characters
- passwords containing `"` are rejected outright — Oracle quoted identifiers have
  no escape for it (see `02-oracle-privileges.md` §4)
- the target's verify function: generate → validate → on rejection (ORA-28003, or
  ORA-20xxx from the function) retry with a new candidate up to N times, then
  fail with the server's message intact
- `PASSWORD_REUSE_TIME` / `PASSWORD_REUSE_MAX` — never retry blindly on ORA-28007

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
[`docs/schemas/sopuli-config-1.0.schema.json`](../schemas/sopuli-config-1.0.schema.json),
Draft 2020-12, and it exists for the editor rather than for the tool: pointed at
from a YAML language server, it gives completion and inline errors while somebody
is editing a 130-line file, which is worth more than the validation itself.

**It is generated, not maintained.** `sopuli/config/schema.py` composes it from
the same constants the builders validate with — `TARGET_KEYS`, `VAULT_TYPES`,
`CHARSETS`, `SUPPORTED_VERSIONS` and the rest — and refuses to generate at all if
a section's keys and its type table disagree. Regenerate with:

```
python -m sopuli.config.schema > docs/schemas/sopuli-config-1.0.schema.json
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
they are about shape: one outer dimension, one list per value.

**What it deliberately does not say.** Every rule in §10 that relates two keys
to each other stays with the hand-written validators, because those errors have
to name the offending key and a `oneOf` failure reports every branch that did not
match instead:

| Rule | §10 |
|---|---|
| the inline form and `applications:` are mutually exclusive | yes |
| `secret` and `secret_template` are mutually exclusive | §3 |
| two accounts may not resolve to one secret ref | yes |
| `require:` may not exceed `length:`, or ask for specials a charset lacks | yes |
| `allow:` belongs to `charset: custom` | §8 |
| every `vault`, `policy`, `group`, `profile` and target name must resolve | yes |
| a `for_each`'s inner dimension must be one variable throughout | §4 |
| a profile may not set a key that changes scope | §5 |

So a file the schema accepts may still be refused by `sopuli config validate`,
and that is the intended division rather than a gap. The schema is the fast,
local, incomplete check; the tool is the complete one.

### Pointing an editor at it

A schema nothing is pointed at is a file in a directory. The association is made
from the config file itself, with a comment on the first line:

```yaml
# yaml-language-server: $schema=./sopuli-config-1.0.schema.json
version: 1
```

That comment is the [YAML Language Server][yamlls] convention, which is what the
Red Hat **YAML** extension for VS Code uses, and what most other editors' YAML
support is built on. Verified with that extension: hovering a key shows the
description the generator wrote for it, and an unknown key is underlined where it
was typed.

**The path is relative to the YAML file**, not to the repository. Copy the schema
next to the config, or point at it where it lives — `$schema=../sopuli-dba/docs/schemas/sopuli-config-1.0.schema.json`
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
| anything §9a or §10 refuses | 2 | the message, with its key path and its hint |

Exit 2 rather than 1: P5 puts config validation with usage errors, so a scheduler
can tell "fix your file" from "something broke". A bad file produces no run
document even under `--output json`, which is not an oversight — whether a usage
error should emit one is J7, and this command must not answer it by accident.

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
- `charset: custom` whose `allow:` contains `"` → error (invariant 11). The
  generator applies that rule to what it produces; this applies it to the
  alphabet it produces *from*, which is the only place a config file can name
  the character
- a `require:` block no password could satisfy → error: more characters demanded
  than `length` allows, or `require: { special: N }` against a charset with no
  special characters. Both would leave generation looping rather than failing
- `--profile` or `SOPULI_PROFILE` naming a profile that does not exist → error,
  never a silent fallback to defaults
- a profile name matching any target's `environment` value → warning, explaining
  that a profile does not select targets
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
| C9 | How does the file point at vault auth material, and at the database admin credential? | unresolved — P2 names the methods and forbids plaintext material in the file, but nothing names the keys. The loader accepts `auth.method` and refuses every other key rather than inventing a schema the vault layer must then live with. Also covers the `oracle.scope` vocabulary, of which only `cdb_root` and `pdb` are written down, and whether `scope` and `container` constrain each other — §2 shows `cdb_root` without a container and `pdb` with one, but never says that is a rule, and `container` is also the `{container}` token in a secret template (§7). Issue #27 |
| C10 | ~~What are profiles for?~~ | **decided: run context, not target selection** (§5). Closed key whitelist; `policies.*.verify.scheduled_method` removed in favour of a profile overriding `verify.method` |
| C11 | Should `--profile` be composable (several at once)? | no — one active profile, no inheritance. Revisit only if a real config duplicates three or more profiles |
| C12 | Ship a built-in `interactive` profile as the implicit default? | leaning no: an absent profile means "just `defaults`", and an invisible built-in would be one more thing to explain when output surprises someone |
| C13 | Is `vault:` under `defaults:` and in a profile a store *name* or a block? | unresolved — §3 and `SOPULI_VAULT` say name; P3's `defaults.vault.addr` and §5's `vault.auth` say block. The loader accepts the name form and refuses the block form rather than settling it in a diff. Overlaps C9. Issue #31 |
| C14 | What are the `@version=` and `@stage=` vocabularies, and who owns them? | unresolved, and a **conflict between committed documents** rather than only a gap. §7 writes `@stage=PENDING`; UC-1 §2 names the states `current` / `pending` / `previous` in lower case; and `sopuli-run-1.1.schema.json` has typed `secret_ref.stage` as a closed lower-case enum and `secret_ref.version` as an integer since it was written — so §7's own example cannot be emitted as a structured ref. Widening that enum is a *major* bump under `03-json-output.md` §8, which is why the schema is evidence rather than an accident. The parser carries both values as written rather than settling it, the same way `auth.method` is left to P2. Issue #40 |

# sopuli-dba — Configuration Reference (draft)

Status: draft / sketch
Depends on: `00-principles.md` (P3 defines precedence)

---

## 1. Two shapes, and you start with the simpler one

**One application → no `applications:` section.** Put the binding keys at the top
level and the file reads like a straightforward target list. This is the shape
most users will ever need.

```yaml
version: 1

vaults: {}          # named secret stores
targets: []         # explicit database endpoints
target_sets: {}     # generated database endpoints (§4)
groups: {}          # named sets of targets
policies: {}        # password + rotation policies
defaults: {}        # inherited settings
profiles: {}        # named overlays (dev / test / prod)

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

The two forms are mutually exclusive: using both top-level `accounts:` and
`applications:` is a validation error. The inline form is exactly sugar for a
single unnamed application entry — everything below applies to both.

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

# ~35 PDB targets, generated. See §4.
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
      method: login
      scheduled_method: hash
      lockout_margin: 2
    account:
      unlock_if_locked: false

# ---------------------------------------------------------------------------
# The single application. No `applications:` wrapper, no name to invent.
# ---------------------------------------------------------------------------
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

Commands against it:

```bash
sopuli creds check                                 # everything declared
sopuli creds check  --select env=dev               # all dev PDBs
sopuli creds rotate --select env=dev,tenant=beta
sopuli creds rotate --group prod-pdbs --confirm
sopuli creds apply  --target appdb-qa-delta --account acme_web_user
```

Note what the config bought: `sopuli creds check` with no arguments is
meaningful, because `accounts` + `secret_template` + the generated targets say
what *should* be true.

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
| `name` | required in the `applications:` form; absent in the inline form |
| `accounts` | list of database usernames |
| `targets` | list of target names, `{ group: NAME }`, or `{ match: {...} }`; defaults to all targets |
| `vault` | store name; defaults to the target's vault, then `defaults.vault` |
| `secret` / `secret_template` | SecretRef, literal or templated (§6) |
| `policy` | policy name |
| `oracle` | vendor-specific options, e.g. `container_clause` |
| `overrides` | list of `{ where: {labels}, ...keys }` patches applied to matching targets |

---

## 4. Target templating (`target_sets`)

Listing 35 PDBs by hand is not viable, and the list changes when a tenant is
added. A target set generates targets from a name template, a DSN template, and
one or more dimensions.

### Rules

1. `for_each` has exactly **one outer dimension** — its key names the dimension
   (`env` above), and its values are maps of variables.
2. Inside an outer value, any variable whose value is a **list becomes an inner
   dimension**, expanded per outer value. That is what allows a different tenant
   list per environment.
3. Every combination produces one target. `name` must render uniquely; a
   collision is a validation error.
4. Every `{placeholder}` in `name`, `dsn` and other string fields is substituted
   from the dimension values and variables in scope. An unresolved placeholder is
   an error, never an empty string.
5. `overrides` patch generated targets **by rendered name**, after generation.
6. Nesting stops at two levels. If you need three, write a second target set —
   this is deliberate, because a general templating language in a credential tool
   is a debugging liability.

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

## 5. Environment variables

Naming: `SOPULI_` + upper-snake path, `__` for nesting into a named object.

| Variable | Overrides |
|---|---|
| `SOPULI_CONFIG` | config file path |
| `SOPULI_PROFILE` | active profile |
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

## 6. SecretRef syntax

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

## 7. Password charsets

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

## 8. Precedence, restated with examples

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

Safety ratchet:

```
$ sopuli creds apply --no-dry-run          # config has readonly: true
error: target group "prod-pdbs" is readonly (config safety.readonly);
       safety settings cannot be relaxed from the command line
exit 2
```

Multiple `--config` files layer left to right (deep merge for maps, replace for
lists). A `safety:` block may appear under `defaults`, a target, a group, or a
profile, and unlike everything else these do **not** follow last-one-wins: the
resolved value is the *safest* of all layers — lowest `max_targets`, union of
`confirm_environments`, `readonly: true` if any layer sets it.

---

## 9. Validation rules worth enforcing early

- unknown keys → error, not warning
- both top-level `accounts:` and `applications:` present → error
- a `secret_template` that cannot produce distinct refs for distinct scopes → error
- a target with `environment: prod` referencing a vault marked
  `non_production: true` → error
- a `target_set` whose `name` renders a duplicate → error, listing the collision
- an `overrides` key naming a target the set does not generate → error (catches
  renames)
- an unresolved `{placeholder}` anywhere → error, never an empty string
- `charset: printable_ascii` on a target detected below 12.2 → warning
- `rotation.strategy: rollover` on a target without the `password_rollover`
  capability → error at plan time, not at execution time
- config file readable by others → refuse to run (P4)

---

## 10. Open decisions

| # | Question | Current proposal |
|---|---|---|
| C1 | ~~Name of the binding section~~ | **decided: `applications`**, with the inline single-application form as the default shape |
| C2 | Selector syntax | `--select k=v` over labels, plus `match:` in groups. Revisit if a real case needs negation or set membership |
| C3 | Should secret templates support arbitrary expressions? | no — fixed token list plus labels, so the mapping stays auditable |
| C4 | Per-account overrides inside an application entry | the `overrides: [{where: …}]` mechanism covers per-label cases; per-*account* exceptions are still unsolved |
| C5 | Config encryption at rest | out of scope; config holds no secrets by construction |
| C6 | Multiple vaults for one application (mirror writes) | defer to a later use case |
| C7 | Should `target_sets` allow more than two nesting levels? | no — write a second set |
| C8 | Do explicit `targets:` need labels, or is `environment` enough? | allow `labels:` on them, so mixed estates select uniformly |

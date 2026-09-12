# Testing sopuli by hand

How to set up a laptop, WSL, containers and OCI so you can exercise every command
this build has, and see each one succeed *and* fail on purpose.

Every command and every output in this document was re-run on 2026-09-06 against
Windows 11, sopuli 0.58.0, Instant Client 23.26.3.0.0, and the `tier1` container
stack. Where something was **not** verified it says so. Working paths in the
samples are shortened to `C:\tmp\sopuli-guide\` — that is the only edit made to
any output here.

§15's run document was re-captured on 2026-09-11 on the same stack, against
sopuli 0.60.0, when the run schema became 1.21 (#392), and §3's `sopuli about`
on the same day against 0.61.0, the release that added the command (#413). A
sample carrying a field the tool has since gained -- or a `schema_version` it no
longer emits -- is the failure this guide is most prone to, so the date moves
per sample rather than for the file.

Related: [`../test/README.md`](../test/README.md) for the container stack itself,
[`design/04-testing.md`](design/04-testing.md) for the automated tiers,
[`use-cases/uc-01-app-credential-sync.md`](use-cases/uc-01-app-credential-sync.md)
for the design the `creds` verbs implement, and
[`design/01-configuration.md`](design/01-configuration.md) as the configuration
reference this guide only skims.

---

## 1. What actually exists, before you plan an evening around it

`sopuli --help` lists five nouns, and the implemented surface is **fourteen
commands**:

```
sopuli config validate      sopuli creds generate         sopuli lock status
sopuli config show          sopuli creds apply            sopuli lock break
sopuli target list          sopuli creds check            sopuli doctor
sopuli policy sample        sopuli creds rotate           sopuli about
                            sopuli creds status
                            sopuli creds finish-rollover
```

**UC-1 is built.** You can rotate a credential end to end against the local
stack, roll one back, detect drift, open and close a rollover window, and watch
each guardrail refuse. §10 is that walkthrough, and it is the reason to sit down.

**There is still no `sopuli admin`.** The JSON schema's `command` enum lists
`admin.install`, because the contract was written ahead of the code; run the SQL
in `sql/oracle/` by hand (§9).

Likewise, of the four store backends `vaults:` accepts, **only `hashicorp` is
implemented**. `file`, `keyring` and `oci` parse in a config file and fail when a
command tries to reach one. `doctor` reports this directly:

```
install
  KIND     NAME       STATUS           CONFIGURED
  backend  file       not_implemented  -
  backend  hashicorp  installed        vault-dev
  backend  keyring    not_implemented  -
  backend  oci        not_implemented  -
  driver   oracle     installed        1 target
```

So "test against OCI" means an OCI-hosted **database** through Instant Client.
OCI Vault as a secret store does not exist — see §14.

---

## 2. The three places you will run this, and why

| Where | What it is for |
|---|---|
| **Windows laptop** | the primary target. The ACL permission checks, the console encoding and the wallet report all behave differently here, and Windows is where the bugs have been |
| **WSL** | the POSIX side of the same checks — file modes instead of ACLs. Cheap second opinion, and closer to where this would run scheduled |
| **Docker** | Oracle and Vault. Neither needs installing on the host |
| **OCI** | the only place Native Network Encryption and a real ADB wallet can be exercised |

Run through §§3–12 on Windows first, then repeat §§6–12 in WSL. The interesting
differences are called out as they come.

---

## 3. Install sopuli

Python 3.11+ (3.13 recommended — it is what CI runs on Windows).

```bash
git clone https://github.com/villebase/sopuli-dba.git
cd sopuli-dba
python -m venv .venv
```

```powershell
.venv\Scripts\Activate.ps1        # Windows
```
```bash
source .venv/bin/activate         # WSL
```

```bash
pip install -e ".[dev,all]"
sopuli --version
```

`[all]` pulls every vendor client. To see what a lean install does — which is
worth doing once, because it is what a new user gets — use `pip install -e .` in
a separate venv and run `sopuli doctor`; the `install` section will show
`hashicorp` as `not_installed` with the exact `pip` line that fixes it.

**`sopuli --version` reports the version recorded when the editable install was
made, not the version in the tree.** An install left over from an earlier session
will happily report `0.24.0` against a `0.58.0` checkout, and it is the number
that lands in every `--output json` run document as `tool.version` — so an audit
sample captured that way is wrong in the one field an auditor would trust.
`pip install -e . --no-deps` refreshes the metadata in a second or two; do it
after any pull that crossed a release.

### `sopuli about`, the one command that needs nothing at all

*Captured on 2026-09-11 against sopuli 0.61.0, when the command was added
(#413) — not in the 0.58.0 pass the header describes.*

No config, no Docker, no Instant Client, no vault. It is the first thing that
proves the install works, and the second place the version appears:

```
$ sopuli about
 ####  ###  ####  #   # #     #####
#     #   # #   # #   # #       #
 ###  #   # ####  #   # #       #
    # #   # #     #   # #       #
####   ###  #      ###  ##### #####

         ####  ####   ###
         #   # #   # #   #
         #   # ####  #####
         #   # #   # #   #
         ####  ####  #   #

Database credential rotation, without the ceremony.
version 0.61.0
https://github.com/villebase/sopuli-dba

Maintained by Ville (github.com/villebase)
Support the project: https://ko-fi.com/villeronkko
```

The banner is cyan and bold on a terminal and plain everywhere else — piped,
redirected, under `NO_COLOR=1`, or with `--color never`. Nothing is lost either
way; there is no word on that screen that only the colour is carrying.

**It takes no options at all**, which is worth causing on purpose once —
and it is worth doing in *both* positions, because the two answers differ:

```
$ sopuli about --output json
Usage: sopuli about [OPTIONS]
Try 'sopuli about --help' for help.

Error: No such option '--output'.
```

```
$ sopuli --output json about
Usage: sopuli about [OPTIONS]
Try 'sopuli about --help' for help.

Error: --output cannot be honoured by `about`, which is not a run:
       about prints compiled-in text: no configuration, no settings, no machine-readable form
       --color is the one exception, and it is read in this same position
```

Exit 2 both times, and the second is the one that matters. `--output` belongs to
the *group*, so its parser accepts it before any subcommand and `about` would
otherwise have printed the banner and exited 0 — a run that looks like it did
what was asked. `--config`, `--profile` and `--vault-token-file` are refused
there for the same reason, and `--vault-token` gets ADR-007's own message rather
than this one:

```
$ sopuli --vault-token s.notatoken about
sopuli: --vault-token is not an option: a token given on the command line is visible in `ps` and in the Windows process list (P5, invariant 1)
  hint: name where the token is instead of passing it. Any of: --vault-token-file PATH, $SOPULI_VAULT_TOKEN, $VAULT_TOKEN, or `vault login`, which writes ~/.vault-token
```

The token is in `argv` and visible in `ps` whether or not the command reaches a
store, so invariant 1 does not relax for the command that reaches none.

There is no `--output json` for `about` anywhere. That is the whole design:
`about` is a screen, not a run, which is also why it is not in the JSON
contract's `command` enum (`03-json-output.md` §6, J7).

`--color` is the one global flag it honours, and only before the verb:

```
$ sopuli --color never about      # plain
$ sopuli about --color never      # exit 2, no such option
```

If you want the version in a script, use `sopuli --version` — one line, never
coloured, never a banner. That is what `about` exists to keep true.

---

## 4. Oracle Instant Client

**Mandatory.** `python-oracledb` runs in *thick* mode here, because thin mode does
not support Native Network Encryption and OCI-hosted databases require it. There
is no configuration that avoids this.

Download **Basic** plus **SQL\*Plus** (the second is not required by sopuli but
you will want it for sanity checks) from Oracle's Instant Client downloads.

**Windows** — unzip to a path with no spaces, e.g. `C:\oracle\instantclient_23_26`,
and either add it to `PATH` or name it in the config:

```yaml
runtime:
  oracle:
    client_lib_dir: C:\oracle\instantclient_23_26
```

**WSL / Linux** — unzip to `/opt/oracle/instantclient_23_26`, install `libaio1`,
and either set `LD_LIBRARY_PATH` or use `client_lib_dir` as above.

Confirm it loaded — this needs no database:

```
client
  tns_admin         (unset)
  instant_client    23.26.3.0.0
  reaches           19.1 and later
```

`instant_client  not loaded` with a `detail:` line underneath means the library
was not found; the detail says why. This is `doctor`'s one job that works with
nothing else set up, so run it before anything else.

---

## 5. Bring up Oracle and Vault

The stack already exists. Read [`../test/README.md`](../test/README.md) — it has
the service table, the ports, and a teardown section that is genuinely
counterintuitive.

```bash
cd test
docker compose --profile tier1 up -d
```

Oracle Free was healthy in ~30 s on this machine. Two things from that README
that will bite otherwise:

- **`docker compose down` is a silent no-op here.** Every service carries a
  `profiles:` key, so with no profile selected it matches nothing and exits 0.
  Use `docker compose --profile '*' down`.
- **Restarting Vault loses its mounts.** Dev mode is in-memory and `vault-init`
  only runs on `up`. After a `stop`/`start`, run
  `docker compose --profile tier0 up -d vault-init` to put `kv` and `kv1` back.

Credentials: Vault root token `sopuli-test-root` at `http://127.0.0.1:8200`
(UI included). Oracle `SYSTEM` / `sopuli-test` at `127.0.0.1:1521/FREEPDB1`.

### The accounts §10 rotates

The container ships profiles, not accounts — `test/oracle-init/` creates
`SOPULI_LOCKOUT`, `SOPULI_STRONG`, `SOPULI_REUSE` and `SOPULI_ROLLOVER`, and the
automated suite makes its own accounts per run. For this guide, make three:

```sql
CREATE USER acme_app_user   IDENTIFIED BY "Placeholder#1" QUOTA UNLIMITED ON USERS;
CREATE USER acme_batch_user IDENTIFIED BY "Placeholder#1";
CREATE USER acme_priv_user  IDENTIFIED BY "Placeholder#1";
GRANT CREATE SESSION TO acme_app_user, acme_batch_user, acme_priv_user;
GRANT DBA TO acme_priv_user;
```

```bash
docker exec -i sopuli-test-oracle-free-1 \
  sqlplus -S system/sopuli-test@localhost:1521/FREEPDB1 < accounts.sql
```

`acme_priv_user` holds `DBA` on purpose: it is what §11's guardrail refuses, and a
refusal you have not watched happen is one you are trusting rather than testing.

### Running all of this against a different Oracle version

Everything from here on works against tier 2 as well. **All three are done** —
21c (#380), 18c (#381) and 11g (#382). What each one differs in is in the table
below; nothing in §§6–12 needs anything but a different `dsn:`.

```bash
cd test
docker compose --profile tier2 up -d oracle-xe21   # or oracle-xe18, oracle-xe11
```

| Version | Container | DSN | Shape |
|---|---|---|---|
| 26ai Free | `sopuli-test-oracle-free-1` | `127.0.0.1:1521/FREEPDB1` | CDB + PDB |
| 21c XE | `sopuli-test-oracle-xe21-1` | `127.0.0.1:1522/XEPDB1`, root `.../XE` | CDB + PDB |
| 18c XE | `sopuli-test-oracle-xe18-1` | `127.0.0.1:1523/XEPDB1`, root `.../XE` | CDB + PDB, **no rollover** (5 capabilities, not 6), and no `PASSWORD_CHANGE_DATE` so `status` leaves `DB_PW_CHANGED` empty |
| 11g XE | `sopuli-test-oracle-xe11-1` | `127.0.0.1:1524/XE` | **non-CDB** (`scope: non_cdb`, no `container:`), no rollover, no `DB_PW_CHANGED`, no unified auditing — `01_audit_policy.sql` refuses. **`V$SQLSTATS` retains the `ALTER USER` text here**, and does not on the other three containers, so a leak result from this one does not generalise — nor does a clean result from the others, since 12.1, 12.2 and 19c are unmeasured. See [`security-model.md`](security-model.md) §5 and #387 |

Change `dsn:` and `oracle.container:` in §6's config and the rest of the guide
follows. All three images are already on the machine and reach healthy in about a
minute; the 11g one is the smallest and fastest of the four.

**One Instant Client covers all of them.** Measured 2026-09-08 with the
23.26.3.0.0 client from §4: 21c, 18c and 11.2 all connect. That is worth knowing
before planning an evening, because `00-principles.md` D7 warns that a 23.x
client reaches 19c and later, which reads like 18c and 11g need a second client
and a second process. They do not. Note that connecting is not the same as being
*certified*, and `doctor`'s `reaches 19.1 and later` line is Oracle's support
statement rather than a measurement — on 18c and 11g it will read as though the
connection you are looking at should not exist.

To point the automated suite at one instead:

```bash
SOPULI_TEST_TIER1=required \
SOPULI_TEST_ORACLE_DSN=localhost:1522/XEPDB1 \
SOPULI_TEST_ORACLE_NAME="21c XE" \
SOPULI_TEST_ORACLE_CONTAINER=sopuli-test-oracle-xe21-1 \
pytest
```

`SOPULI_TEST_ORACLE_CONTAINER` is not optional. `tests/driver/test_oracle_install_script.py`
shells into a container by name — SQL\*Plus is a *client*, and the only one the
suite can rely on is inside the container — and it defaults to the tier-1 one. Left
unset, that module reports on 26ai while everything else reports on 21c, and
nothing says so.

### Seeing 11.2 keep your password, on purpose

Worth twenty minutes if you run 11.2 anywhere, because it is the one place this
tool's own statement is retained where you can read it. Rotate normally against
`xe11` first — §10.3 — then read the password back out of the vault and go looking
for it. It is in `V$SQLSTATS` and nowhere else:

```
V$SQLSTATS.sql_text           *** LEAK *** 1
V$SQL.sql_text                clean        0
V$SQLAREA.sql_text            clean        0
GV$SQL.sql_fulltext           clean        0
V$DB_OBJECT_CACHE.name        clean        0
DBA_AUDIT_TRAIL.sql_text      clean        0
--- V$SQLSTATS row, password masked by this script:
    ALTER USER "ACME_APP_USER" IDENTIFIED BY "<the password sopuli generated>"
```

Three things to check while you are there, all of which the same session answered
on 2026-09-09:

- **your service account cannot see it.** Connect as `SOPULI_SVC` and the same
  query is `ORA-00942: table or view does not exist`, from `V$SQL` too. The
  exposure needs a dictionary grant somebody else holds.
- **`ALTER SYSTEM FLUSH SHARED_POOL` clears it**, immediately and completely. That
  is the remedy, and it is yours rather than the tool's — sopuli is not granted
  `ALTER SYSTEM`, and flushing a production shared pool is not something a password
  change should do to you.
- **do the same thing on 18c or 21c and find nothing**, which is the comparison
  that makes the result mean something rather than looking like a property of
  Oracle in general.

Write the search so it cannot match itself: assemble the password from two halves
inside PL/SQL (`pat := '%' || 'firsthalf' || 'secondhalf' || '%'`), or your own
query's text is the leak you find. `02_password_leak_probe.sql` does the same
thing for the same reason, and its §7 explains what it cost to learn.

The decision this fed into is #387 — documented, not warned about and not refused.
[`security-model.md`](security-model.md) §5 is the short version for an
operator; `design/02-oracle-privileges.md` §4 and §8 P8 have the measurements.

**Auditing is off in the XE images, and silently.** They ship
`AUDIT_TRAIL = NONE`, on which nothing is captured at all — not even the
Oracle-supplied `ORA_LOGON_FAILURES` policy after a real failed logon, measured
on 21c. So `01_audit_policy.sql` creates and enables a policy that then records
nothing, and `02_password_leak_probe.sql` reports `NOTHING CAPTURED - this trail
proves nothing` in §4a. Fix it before concluding anything about auditing:

```sql
alter system set audit_trail=db,extended scope=spfile;
alter system set audit_sys_operations=true scope=spfile;
```

then `docker restart` the container. **Unquoted and two tokens** —
`audit_trail='DB,EXTENDED'` is `ORA-00096: invalid value DB,EXTENDED for
parameter audit_trail, must be from among extended, xml, none, os, db`.

---

## 6. A config file, and the check that will reject it first

Save this as `sopuli.yaml` somewhere outside the repo:

```yaml
version: 1

defaults:
  policy: standard

vaults:
  vault-dev:
    type: hashicorp
    addr: http://127.0.0.1:8200
    mount: kv
    kv_version: 2
    auth: { method: token }

targets:
  - name: free-pdb
    type: oracle
    environment: dev
    vault: vault-dev
    dsn: "127.0.0.1:1521/FREEPDB1"
    admin: { username: SYSTEM, auth: { method: env } }
    oracle: { scope: pdb, container: FREEPDB1 }
    labels: { tier: sandbox }

policies:
  standard:
    password:
      length: 24
      charset: alnum_safe
      first_char: alpha
      require: { upper: 1, lower: 1, digit: 1, special: 1 }

applications:
  - name: acme
    accounts:
      - acme_app_user
    secret_template: "vault-dev:acme/{env}/{application}#{account}"
    policy: standard
```

### The permission check

P4 refuses to run on a config file other people can reach — not for
confidentiality (the file holds no secrets) but for **tampering**: anyone who can
write it can repoint `secret_template` at a path they control, and the tool will
faithfully rotate a production password into it.

A file you just created will normally **fail** this:

```
sopuli: C:\tmp\sopuli-guide\sopuli.yaml: config file is accessible to BUILTIN\Users
  hint: remove the extra grant, e.g. icacls "<file>" /inheritance:r /grant:r "%USERNAME%:R"
```

Exit 9. Fix it before anything else:

```powershell
icacls sopuli.yaml /inheritance:r /grant:r "$($env:USERNAME):F"
```
```bash
chmod 600 sopuli.yaml            # WSL
```

The POSIX check is on `0o077` — *any* group or other access, not just read —
because refusing a world-readable file while accepting a group-writable one would
guard the smaller problem.

### `#{account}` holds exactly one account

The `secret_template` above works, and it stops working the moment the
application has a second account. Add one and the file is refused at load:

```
sopuli: C:\tmp\sopuli-guide\clash.yaml: applications[0]: `acme_app_user` and `acme_priv_user`
  share the secret document vault-dev:acme/dev/acme and would both stage into `pending`, so one
  password would overwrite the other
  hint: give the ref a pointer per account, as in `path#FIELD/{account}` -- a bare `#{account}`
        makes each account a root *field*, and the mirror rule then puts every account's stage at
        the document root
```

Exit 9, at load time rather than at the second rotation — which is the whole
argument for parsing refs when the file is read. The pointer form is what a
multi-account entry wants:

```yaml
    secret_template: "vault-dev:acme/{env}/{application}#DB_CREDENTIALS/{account}"
```

§11 uses that form, because it needs two accounts in one entry.

### Four more things worth getting wrong on purpose

Each of these is a real error message worth seeing once:

| Change | What you should get |
|---|---|
| `applications:` as a mapping instead of a list | `must be a list, not a mapping` |
| `length: 24` directly under the policy name | `unknown keys 'charset', 'length'` — it belongs under `password:` |
| drop the `#{account}` from `secret_template` | `names a whole secret, which has nowhere to stage into` |
| `dsn: "host:1521/svc"` with `auth: external` | refused at load: external auth needs a TNS alias |

All four cost me time while writing this guide, which is why they are here.

### The one warning you will see without asking for it

If `VAULT_ADDR` is set in your shell — and it will be, because §8 tells you to set
it — a config with no `defaults.vault` says so:

```
ok: 1 target, 1 binding, 1 warning

1 warning:
  VAULT_ADDR is set and was not applied: this run has no default store, and a third-party
  variable names none
    hint: P3 honours it as a setting of the store `defaults.vault` names, below SOPULI_VAULT --
          write `defaults.vault`, or ignore this if the variable belongs to something else on
          this machine
```

That is correct behaviour and not a problem to fix: the store's `addr:` is in the
file, so nothing is missing. It is here so you recognise it rather than chase it.

---

## 7. The offline commands

None of these open a socket. They work with Docker stopped and no Instant Client.

```bash
sopuli --config sopuli.yaml config validate
```
```
config: C:\tmp\sopuli-guide\sopuli.yaml

ok: 1 target, 1 binding, 0 warnings
```

```bash
sopuli --config sopuli.yaml target list
```
```
config: C:\tmp\sopuli-guide\sopuli.yaml

NAME      DSN                      ENV  SCOPE  SOURCE
free-pdb  127.0.0.1:1521/FREEPDB1  dev  pdb    targets

1 target (1 explicit)
```

```bash
sopuli --config sopuli.yaml config show --resolved   # expanded estate + bindings
sopuli --config sopuli.yaml config show --explain    # every setting and its layer
```

`--explain` is the one to know: it prints where each effective setting came from,
which is the fastest way to understand the precedence chain.

```
settings
  db.connect_timeout_s = 30     [built-in default]
  db.query_timeout_s   = 0      [built-in default]
  output               = text   [built-in default]
  safety.dry_run       = false  [built-in default]
  safety.readonly      = false  [built-in default]
```

Set `SOPULI_OUTPUT=json` and run it again to watch a layer change. Only three
variables reach a setting this way — `SOPULI_OUTPUT`, `SOPULI_DRY_RUN` and
`SOPULI_PROFILE` — plus `SOPULI_VAULT` and the per-store `SOPULI_VAULT__*` forms.
**There is no `SOPULI_READONLY` and no `SOPULI_MAX_TARGETS`**, and an invented one
is ignored rather than refused, so a run you believe is guarded by an environment
variable is not guarded at all. Those live in the file (§11).

### Profiles

A profile changes how a run behaves, never what it acts on. Add one:

```yaml
profiles:
  unattended:
    confirm: false
    output: json
    safety:
      confirm_environments: []
    locking:
      break_expired: true
    rotation:
      strategy: staged
    db:
      connect_timeout_s: 60
```

```bash
sopuli --config sopuli.yaml --profile unattended config show --explain --output text
```
```
profiles
unattended

...

settings
  db.connect_timeout_s  = 60          [profiles.unattended.db.connect_timeout_s]
  db.query_timeout_s    = 0           [built-in default]
  locking.break_expired = true        [profiles.unattended.locking.break_expired]
  output                = text        [cli --output (verb)]
  profile               = unattended  [cli --profile (group)]
  safety.dry_run        = false       [built-in default]
  safety.readonly       = false       [built-in default]
```

Two things to read out of that. `--output text` on the command line beat the
profile's `output: json`, which is precedence working — drop the flag and the
source reads `[profiles.unattended.output]`.

And `confirm`, `rotation.strategy` and `verify.method` are **absent from the list
entirely**. They validate, they appear in `config show`, and nothing reads them
yet — deliberately (`sopuli/settings/registry.py`: a setting arrives with its
consumer), but it means a profile can look like it configures something it does
not. `--explain` is how you tell, and it is worth checking before trusting one.

### Password policy

```bash
sopuli --config sopuli.yaml policy sample --count 2
```
```
config: C:\tmp\sopuli-guide\sopuli.yaml
policy: standard    length 24, alnum_safe, first_char alpha, require digit 1, lower 1, special 1, upper 1

#  CHARS  BYTES  CLASSES
1  24     -      u10 l8 d4 s2
2  24     -      u10 l6 d4 s4

2 samples, all compliant. Not stored anywhere; pass --reveal to print them.
```

The policy name is a positional argument (`policy sample standard`), so an estate
with several policies does not need a config edit to look at one of them.

`--reveal` prints the passwords — the one place this tool prints a secret, allowed
because a sample is not a credential: nothing authenticates with it and it is
never stored. Prove the guard around it:

```bash
sopuli --config sopuli.yaml policy sample --reveal --output json
```
```
Error: --reveal cannot be used with --output json
       json output is what gets captured and shipped to log aggregation, so a sample never
       appears in it -- drop --reveal, or use the text output
```

Exit 2. Also try `--max-bytes 30 --encoding cp1252` to see the byte-limit preview
that models an 11g password.

---

## 8. Vault, locks, and the fence that makes them mean something

`lock status` is the first command that opens a socket. It needs a token, and
**the token is never a command-line value** — it comes from the environment, a
file, or `~/.vault-token`.

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=sopuli-test-root
sopuli --config sopuli.yaml lock status
```
```
config: C:\tmp\sopuli-guide\sopuli.yaml
mode:   cas

0 of 1 declared lock paths held
```

`mode: cas` means the store can fence — it supports compare-and-set, so two runs
starting in the same second cannot both believe they hold a lock.

**`mode` follows the store, not the config key.** Setting
`locking: advisory-only` on a KV v2 vault changes nothing here — it is
*permission* to run without a fence, not a demotion, and a store that can fence
still reports `cas`. To see `mode: none` you need a store that genuinely cannot,
which the dev stack has: point the vault at the `kv1` mount.

```yaml
    mount: kv1
    kv_version: 1
    locking: advisory-only
```
```
mode:   none

0 of 1 declared lock paths held
```

Drop the `locking:` line and the same config is refused before it writes
anything:

```
sopuli: vault-dev:acme/dev/acme cannot be locked: store 'vault-dev' has no compare-and-set
  hint: set `vaults.vault-dev.locking: advisory-only` to proceed without one, or move the
        secret to a store with versioning
```

Exit 5 — the weakening has to be written down somewhere a reviewer sees it,
rather than discovered at rotation time.

That combination is a demonstration, not a working setup: `advisory-only` gets a
run past the *lock* preflight, and then the credential write asks for a
compare-and-set of its own and fails on the same mount.

```
ACCOUNT        SECRET                   RESULT
acme_app_user  vault-dev:acme/dev/acme  this store has no compare-and-set, and the write to
                                        'acme/dev/acme' asked for one

1 failed
```

Exit 1. Put the vault back on `kv` before §10.

Without a token:

```
sopuli: vault "vault-dev": no token, and none of the places it is looked for had one
  hint: write `token: { file: … }` on the store, or supply one of: --vault-token-file PATH,
        $SOPULI_VAULT_TOKEN, $VAULT_TOKEN, or `vault login` so that ~/.vault-token exists
```

Exit 9 — no token is a configuration gap, not an authentication failure. A token
that is present and *wrong* is the one that exits 6, and it is worth seeing the
pair next to each other:

```
sopuli: the store refused this token at 'locks/': 2 errors occurred:
        * permission denied
        * invalid token

  hint: check the token's policy for this path, and that it has not expired
```

Try the file form too, which is what `--vault-token-file` is for:

```bash
unset VAULT_TOKEN
printf 'sopuli-test-root' > vault-token.txt
chmod 600 vault-token.txt      # or icacls, same as the config file
sopuli --config sopuli.yaml --vault-token-file vault-token.txt lock status
```

### The lock path's `cas_required`, which the tool now arranges itself

**This used to be a chore, and it is not one any more** (#390). Read this only if
you meet the refusal below on a stack that was set up before that change, or if
your Vault token cannot write path metadata.

`cas_required` on a lock path is what stops *someone else* — an operator with a
vault CLI — replacing the lock record without a compare-and-set. sopuli always
sends one; the setting is about everybody else. Until #390 the tool read that
setting and never arranged it, so a first acquisition created the path without
it and every run after that was refused:

```
sopuli: vault-dev:acme/dev/acme cannot be locked safely: its lock path does not require
  compare-and-set
```

Now the first acquisition sets it, and the second run just works:

```
$ sopuli creds generate --application acme --offline    # brand-new path
ACCOUNT        SECRET                   RESULT
acme_app_user  vault-dev:acme/dev/acme  staged v1

$ vault kv metadata get -mount=kv locks/acme/dev/acme
cas_required    true

$ sopuli creds generate --application acme --offline    # this used to be exit 5
acme_app_user  vault-dev:acme/dev/acme  staged v2, replaced the pending in v1
```

**Worth causing on purpose: a token that cannot write metadata.** Vault grants
`update` on `<mount>/metadata/<path>` separately from the data path, so a policy
written for secrets alone locks perfectly well and cannot set this. The run goes
ahead and says so rather than stopping — it is no worse off than it was before
the tool asked:

```bash
docker exec -i -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=sopuli-test-root \
  sopuli-test-vault-1 sh -c 'cat > /tmp/p.hcl <<EOF
path "kv/data/*"     { capabilities = ["create","update","read"] }
path "kv/metadata/*" { capabilities = ["read","list"] }
EOF
vault policy write dataonly /tmp/p.hcl'
# then run with a token created from it:
#   vault token create -policy=dataonly
```

```
1 staged; no database was changed -- run `sopuli creds apply` to use them

1 note:
  the lock path for vault-dev:acme/dev/acme is not guarded against a write carrying no compare-and-set: the store refused to set `cas_required` on 'locks/acme/dev/acme'
    hint: a Vault policy grants `update` on <mount>/metadata/<path> separately from the data path -- add it, or run `vault kv metadata put -cas-required=true kv/locks/acme/dev/acme` once
```

`SOPULI-W019`, and the run exits 0. Run it a second time and you get the exit-5
refusal above, which is correct and is the sequence to look at whole: the run that
could not arrange the guarantee warns, and the next one refuses. Nobody is
silently unguarded twice.

If you need to set it by hand — an old path, or that token:

```bash
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=sopuli-test-root \
  sopuli-test-vault-1 \
  vault kv metadata put -mount=kv -cas-required=true locks/acme/dev/acme
```

### Making a held lock, so `lock break` has something to break

`lock break` with nothing held is exit 0 having changed nothing, which is what
makes running it twice safe — and it means the interesting paths never run. Write
a held record by hand instead. Read the current version first, because the write
needs it:

```bash
docker exec ... vault kv get -mount=kv -format=json locks/acme/dev/acme
```

then, with `-cas=` set to the version that came back:

```json
{
  "state": "held",
  "command": "creds rotate",
  "correlation_id": "11111111-2222-3333-4444-555555555555",
  "acquired_at": "2026-09-06T18:00:00.000000Z",
  "expires_at": "2026-09-06T23:59:00.000000Z",
  "holder": {"host": "beta.example.com", "os_user": "someone-else", "pid": 1234}
}
```

```bash
docker exec -i ... sh -c 'cat > /tmp/held.json && \
  vault kv put -mount=kv -cas=29 locks/acme/dev/acme @/tmp/held.json'
```

Write `holder` as nested JSON, not as `holder=host=...` key-value pairs — the flat
form stores a string, and `lock status` then reports the holder as `unknown`,
which looks like a tool bug and is a fixture bug.

Now all three paths are reachable:

```
LOCK                     STATE  HOLDER                        COMMAND       SINCE                 EXPIRES
vault-dev:acme/dev/acme  held   someone-else@beta.example...  creds rotate  2026-09-06T18:00:00Z  2026-09-06T23:59:00Z

not declared by this config -- a leftover, or another config's:
LOCK                        STATE     HOLDER              COMMAND       SINCE                        EXPIRES
vault-dev:acme/dev/batch    released  ville@Awesominator  creds rotate  2026-09-06T17:29:55.224821Z  2026-09-06T17:44:55.224821Z
vault-dev:acme/dev/guarded  released  ville@Awesominator  creds rotate  2026-09-06T17:31:42.920345Z  2026-09-06T17:46:42.920345Z
vault-dev:apps/acme/dev     released  ville@Awesominator  creds apply   2026-09-06T14:47:56.306209Z  2026-09-06T15:02:56.306209Z

1 of 1 declared lock paths held; 3 records at paths this config does not declare (0 held)
```

That second table is `lock status` surveying the whole `locks/` prefix rather than
only what this config declares — deliberate, and the reason the local `kv` mount
accumulates records from every config you have ever pointed at it.

Any mutating verb now stops:

```
sopuli: vault-dev:acme/dev/acme is locked by someone-else@beta.example.com pid 1234 running
  creds rotate
  hint: wait for it to finish, or coordinate with whoever is running it
```

Exit 7. So does `lock break` without `--force`, because the lock has not expired:

```
sopuli: vault-dev:acme/dev/acme is held by someone-else@beta.example.com pid 1234 running
  creds rotate and has not expired
  hint: wait for it to finish, or coordinate with whoever is running it. `--force` breaks a
        lock that is still live -- the holder is fenced and stops at its next check, having
        applied whatever it applied
```

Exit 7 again. With `--force`:

```
broke this lock at version 30; someone-else@beta.example.com pid 1234 running creds rotate is
fenced at version 31 and stops at its next check
```

Exit 0. The version numbers are the fence: the broken holder re-reads before its
next mutation, finds 31 where it wrote 30, and stops. That is the mechanism
`--force` is safe *because of*, and those two numbers in one line are the clearest
look at it you will get.

---

## 9. `doctor`

The command that connects, and mutates nothing.

```bash
export SOPULI_DB_ADMIN_PASSWORD=sopuli-test
sopuli --config sopuli.yaml doctor
```

```
install
  KIND     NAME       STATUS           CONFIGURED
  backend  file       not_implemented  -
  backend  hashicorp  installed        vault-dev
  backend  keyring    not_implemented  -
  backend  oci        not_implemented  -
  driver   oracle     installed        1 target

vaults
  VAULT      TYPE       STATUS  AUTH  SKEW
  vault-dev  hashicorp  ok      yes   -468ms

client
  tns_admin         (unset)
  instant_client    23.26.3.0.0
  reaches           19.1 and later

TARGET    REACHABLE  SCOPE  CONTAINER  OPEN MODE   CAPABILITIES
free-pdb  yes        pdb    FREEPDB1   READ WRITE  6
```

The `vaults` section is the store half of the same survey: whether the address
answers, whether the token authenticates, and the clock skew between this machine
and the server. Skew matters because lock expiry is written in the store's time —
a laptop minutes adrift will take over locks that have not expired, or wait on
ones that have.

Then `--output json` for the same run — `targets[].scope.capabilities` names the
six the driver probed for, which is what `--strategy rollover` branches on in §10.

### Failures worth causing

- **Stop the container** (`docker compose --profile tier1 stop oracle-free`) →
  `reachable: no`, `ORA-12541 TNS:no listener`, exit 1. The whole point is that
  one unreachable target does not end the survey.
- **Wrong password** → `ORA-01017`, category `authentication`.
- **Wrong container**: set `oracle: { container: WRONGPDB }` → the connection
  still succeeds and `asserted.matches` is `false`. Reachability and assertion are
  deliberately separate.
- **A config naming an unimplemented backend** — add `vault-x: { type: oci }` and
  a target using it → exit **9**, not 1, and the `install` section says
  `not_implemented` with no `pip` line, because nothing you install fixes it.

### `--check-privileges`

Reports what the service account holds and does not need. Against `SYSTEM` it is
dramatic, which makes the point:

```
TARGET    REACHABLE  SCOPE  CONTAINER  OPEN MODE   CAPABILITIES
free-pdb  yes        pdb    FREEPDB1   READ WRITE  6
  free-pdb: not checked, and not visible from here: EXECUTE ON DBMS_LOCK
  free-pdb: over-granted, and the tool needs none of it: ALTER PROFILE, ALTER SYSTEM,
    BECOME USER, CREATE USER, DBA, DROP USER, GRANT ANY DATA ROLE, GRANT ANY OBJECT
    PRIVILEGE, GRANT ANY PRIVILEGE, GRANT ANY ROLE, SELECT ANY DICTIONARY
```

**It warns and never fails** — exit 0. An over-granted account is somebody else's
decision to fix, and a `doctor` that exited non-zero over it would block the
person who ran it mid-incident over a condition they did not create.

The first line matters as much as the second: it names what the audit *could not
see*, so `over_granted: []` can never mean both "nothing is over-granted" and "the
view that would have said so was refused". It is short here because `SYSTEM` holds
`SELECT ANY DICTIONARY` and can therefore read `V$PWFILE_USERS`; a service account
that cannot will see `SYSDBA, SYSOPER` listed as unchecked alongside `DBMS_LOCK`.

For a realistic run, create the proper service account with
[`../sql/oracle/00_install.sql`](../sql/oracle/00_install.sql) and point the
target at it:

```bash
docker exec -i sopuli-test-oracle-free-1 \
  sqlplus -S sys/sopuli-test@localhost:1521/FREEPDB1 as sysdba \
  < sql/oracle/00_install.sql
```

Read the script's `STATUS:` header first — it says which paths have actually been
run. Use `99_uninstall.sql` to undo it.

---

## 10. The `creds` verbs, end to end

This is UC-1, and it is what the rest of the guide has been setting up. Everything
below is one continuous session against the config in §6 and the accounts in §5,
in order — each command's state is the previous one's output.

```bash
export VAULT_TOKEN=sopuli-test-root
export SOPULI_DB_ADMIN_PASSWORD=sopuli-test
```

Every verb prints its plan before doing anything, and every mutating one takes
`--dry-run`. The plan is not decoration: `max_targets`, `confirm_environments` and
the capability refusals are all decided from it, before the first connection.

### Colour, and turning it off

The `STATE` column is coloured, and nothing else in a result table is. Four
meanings, decided in #395:

| Looks like | Means | States |
|---|---|---|
| cyan | nothing to do | `IN_SYNC` |
| yellow | somebody has to act, the run is fine | `DRIFT`, `PENDING_APPLY`, `ROLLOVER_ACTIVE`, `VAULT_ONLY` |
| red, bold | the tool could not do the job, or the estate is not in a state it can | `ERROR`, `ACCOUNT_MISSING`, `LOCKED`, `EXPIRED` |
| dim | nothing could be concluded | `UNVERIFIABLE`, `SKIPPED` |

**Converged is cyan and not green on purpose.** Green against yellow is the one
pairing a red-green colour-blind reader cannot separate, and `IN_SYNC` against
`DRIFT` is the exact distinction this tool exists to report. If you were about to
file "shouldn't ok be green" — that is why, and `tests/test_palette.py` will fail
if somebody changes it without reading this.

**The colour never carries the meaning.** The word is on the line either way, so
piping to a file, `--color never` and `NO_COLOR=1` all lose nothing at all. Worth
proving to yourself once, because it is a rule the whole design leans on:

```bash
sopuli --color always creds check --application acme | cat -v   # see the escapes
NO_COLOR=1 sopuli creds check --application acme                # the same table, plain
```

`--output json` is never coloured, whatever any of that says.

**Worth seeing on purpose**, since a healthy estate is all one colour. Against
§5's accounts, in this order, each command's output feeding the next:

```
$ sopuli creds check --application acme
ACCOUNT        TARGET  STATE    DETAIL
acme_app_user  xe11    IN_SYNC  vault v2 verified by login          <- cyan

all 1 in sync
```

then change the password behind the tool's back —
`ALTER USER acme_app_user IDENTIFIED BY "Drifted2026x"` —

```
ACCOUNT        TARGET  STATE  DETAIL
acme_app_user  xe11    DRIFT  vault v2 the database rejected this password (ORA-01017)

1 drift                                                             <- yellow
```

and drop the account outright:

```
ACCOUNT        TARGET  STATE            DETAIL
acme_app_user  xe11    ACCOUNT_MISSING  the config declares this account; the database has no such user

1 unverifiable                                                      <- red, bold
```

**That last pair is not a bug.** The row is red and the counter says
`unverifiable`, because they answer different questions: the summary counts what
the run learned *about the password* — nothing, here — while the colour says
whether this is a row to go and look at. A missing account is very much one.
`03-json-output.md` §1 has the reasoning.

`creds status` is the command where the palette is most obvious, because its
ordinary row is `UNVERIFIABLE` — it spends no logins, so most rows say the
password was not checked. The whole column goes dim, and the one row that is not
`UNVERIFIABLE` is the only thing on the screen with a colour.

### The spinner, and why you will probably never see it

*Captured on 2026-09-12 against sopuli 0.61.0 and the `tier1` stack (#419).*

While a verb is reading a document out of Vault, a spinner runs on **stderr**:

```
| Reading `vault-dev:acme/dev/acme`
```

The leading character cycles through `|`, `/`, `-`, `\`. Against the tier-1
Vault on `127.0.0.1` that read takes a few milliseconds, so what you actually see
is a single frame and then nothing -- the run above emitted exactly one, 73 bytes
including the blanking. **That is the intended outcome** -- the spinner exists for the case where the wait is real, and the only
way to test it deliberately is to cause one.

Add a vault at an address that goes nowhere. `192.0.2.0/24` is TEST-NET-1 and is
guaranteed unroutable, so this hangs rather than failing fast:

```yaml
vaults:
  vault-blackhole:
    type: hashicorp
    addr: http://192.0.2.7:8200
    mount: kv
    kv_version: 2
    timeout_s: 8
    auth: { method: token }
```

Point the application's `secret_template` at it and run `sopuli creds status`.
For eight seconds the line animates, naming the path it is waiting on, and then
the line is blanked and the error takes its place:

```
sopuli: the store did not answer within the timeout: timed out
  hint: raise `timeout_s` on the store, or check that `addr` reaches it
```

Exit 1. The blanking matters: the error starts at column zero on a clean line
rather than after the wreckage of a half-drawn frame.

**Four things it deliberately will not do**, each worth causing on purpose:

- **It does not run when stderr is not a terminal.** Redirect **stderr**
  specifically -- `sopuli creds status 2>frames.txt`, or `2>/dev/null` -- and
  there are **no frames at all**, not even stripped ones.

  Check the file for carriage returns rather than for size, because stderr is
  also where the tool's own error messages go: on a run that succeeds the file is
  genuinely empty (measured: 0 bytes against the local vault), but on the timeout
  run below it holds the `sopuli:` message and its hint, and **no `\r`**. The
  frames are what has to be absent, not the bytes.

  **`| cat` does not demonstrate this, and it is the mistake to make on
  purpose.** A pipe redirects stdout; stderr stays attached to the terminal, so
  `sopuli creds status | cat` animates exactly as it did before. That is correct
  behaviour -- the spinner is keeping a human company, and piping the *result*
  somewhere does not mean nobody is watching -- but it means the obvious way to
  test the gate tests nothing. Measured, same command: 73 bytes of frames with
  stdout piped, and not one carriage return with stderr redirected.

  There is no `--spinner` flag and no `SOPULI_SPINNER` to force it on, because
  carriage-return-separated frames in a log file are worse than silence for every
  reader. (Measured in #416: at one frame per 100ms that is about 12,000
  characters over a 30-second vault timeout.)
- **It does not run under `--output json`.** Verified on a terminal, which is the
  only place it could have: `sopuli creds status --output json` writes **not one
  frame** to stderr, where the same run in text mode wrote 74. stdout is the
  contract (invariant 12), and a consumer capturing `2>&1` would otherwise find
  frames ahead of the document.
- **It ignores `NO_COLOR`.** Not an oversight -- there is nothing to turn off.
  The frames are four ASCII characters and a carriage return, with no ANSI
  anywhere, so a `NO_COLOR=1` run animates identically. Try it.
- **It never fails your command.** If the stream it is writing to closes
  underneath it, the animation stops and the rotation carries on. Decoration must
  not be able to break a credential change.

**It is on the vault read, not on opening the vault** -- which is the opposite of
where it was first put, and measuring is what moved it. With
`auth: { method: token }` nothing about opening a store touches the network:
`connect` reads the token and builds an HTTP client, all of it local. In the
eight-second run above, opening the store accounted for 0.7s and the read
accounted for the other eight.

**`doctor` uses the same four roles for two more vocabularies**, and a healthy
run is deliberately quiet — the only colour on it is `ok`:

```
install
  KIND     NAME       STATUS           CONFIGURED
  backend  file       not_implemented  -              <- dim: true on every run
  backend  hashicorp  installed        vault-dev
  driver   oracle     installed        1 target

vaults
  VAULT      TYPE       STATUS  AUTH  SKEW
  vault-dev  hashicorp  ok      yes   -833ms          <- cyan

TARGET  REACHABLE  SCOPE    CONTAINER  OPEN MODE   CAPABILITIES
xe11    yes        non_cdb  -          READ WRITE  4  <- `-` dim on a non-CDB
```

Two worth causing on purpose. Add `vault-x: { type: oci }` to `vaults:` — the
row that was dim on every other run turns red, because a backend nobody
configured is noise and one somebody configured is why the run exits 9:

```
  backend  oci        not_implemented  vault-x        <- red, bold
vaults
  vault-x    oci        unreachable  -     -          <- red, bold; the `-`s dim
```

And `docker stop sopuli-test-oracle-xe11-1`:

```
TARGET  REACHABLE  SCOPE  CONTAINER  OPEN MODE  CAPABILITIES
xe11    no         -      -          -          -
        ^^ red     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ all dim
  xe11: ORA-12541: Cannot connect. No listener at host 127.0.0.1 port 1524.
```

That row is the design working: reachability is the first fact and everything
else is *absent* rather than empty, and the colours say exactly that without a
word of explanation.

**`yes` is not coloured and `IN_SYNC` is**, which looks inconsistent until you
see why. A result state is one of eleven with no norm, so cyan means "this row is
done". Reachability has two values and almost always the same one — painting
`yes` would colour the whole column and make the single `no` ordinary again. Same
reason `config show` paints `prod` and no other environment.

### 10.1 `status` — the inventory that spends no logins

Start here, always. It reads the vault and the data dictionary and attempts no
authentication, so it cannot lock anything out:

```
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT        TARGET    INTENT  SECRET
acme_app_user  free-pdb  none    vault-dev:acme/dev/acme

ACCOUNT        TARGET    STATE         VAULT_V  AGE  DB_PW_CHANGED  PROFILE  ROLLOVER
acme_app_user  free-pdb  UNVERIFIABLE  -        -    2026-09-06     DEFAULT  not configured

1 account, nothing to act on
```

`UNVERIFIABLE` with `VAULT_V -` is the empty state: there is no document in the
vault at all. `DB_PW_CHANGED` comes from the dictionary, so it is populated even
now — the database has a password, the vault has never heard of it, and nothing
has been compared.

### 10.2 `generate` — stage a password, touch no database

```bash
sopuli --config sopuli.yaml creds generate --dry-run
```
```
Plan: 1 account x 1 target = 1 generation   [dev]

ACCOUNT        TARGET    INTENT                         SECRET
acme_app_user  free-pdb  generate, vault_write_pending  vault-dev:acme/dev/acme

constraints: 128 bytes in AL32UTF8, from free-pdb

SECRET                   STAGE    ACCOUNTS
vault-dev:acme/dev/acme  pending  acme_app_user

nothing was written (--dry-run)
```

The `constraints:` line is the one surprise in this verb: `generate` **does**
connect, to ask each selected target how long a password may be in that database's
own character set, and the strictest answer governs the draw. It reads and never
writes. `--offline` declines to ask — the line disappears and the policy's declared
length governs instead — which is what you want when staging against an estate that
is deliberately down.

Drop `--dry-run`:

```
ACCOUNT        SECRET                   RESULT
acme_app_user  vault-dev:acme/dev/acme  staged v1

1 staged; no database was changed -- run `sopuli creds apply` to use them
```

**Run it twice and it stages again**, which is invariant 9's one exemption —
drawing a fresh random secret has no state to converge on. The run says so rather
than leaving you to notice:

```
acme_app_user  vault-dev:acme/dev/acme  staged v2, replaced the pending in v1
```

Supplying a password instead of drawing one goes through stdin, never a flag:

```bash
printf 'Correct#Horse9Battery' | sopuli --config sopuli.yaml creds generate --from-stdin
```
```
sopuli: the supplied password for 'acme_app_user' violates policy 'standard'
  hint: length (is 21 characters, policy asks for at least 24) -- fix the password, or pass
        `--no-policy-check`, which records in the audit event what it let through
```

Exit 9. A compliant one stages exactly like a drawn one.

### 10.3 `apply` — vault to database, then promote

```
Plan: 1 account x 1 target = 1 apply   [dev]

ACCOUNT        TARGET    INTENT                               SECRET
acme_app_user  free-pdb  verify, password_set, vault_promote  vault-dev:acme/dev/acme

ACCOUNT        TARGET    SECRET                   SOURCE
acme_app_user  free-pdb  vault-dev:acme/dev/acme  pending

ACCOUNT        TARGET    STATE    DETAIL
acme_app_user  free-pdb  IN_SYNC  changed and verified by login

1 changed, 1 promoted to `current`
```

`SOURCE pending` and `1 promoted to current` are invariant 7 in two lines: the
database confirmed the new password before the vault promoted it, never the other
way round.

Run it again — this is the verb idempotency actually governs:

```
ACCOUNT        TARGET    SECRET                   SOURCE
acme_app_user  free-pdb  vault-dev:acme/dev/acme  current

ACCOUNT        TARGET    STATE    DETAIL
acme_app_user  free-pdb  IN_SYNC  the vault's password is already accepted; nothing to change

nothing changed
```

`SOURCE` moved from `pending` to `current` on its own, because there is no longer a
pending to apply, and nothing was written.

### 10.4 `check` — drift, and the exit code that carries it

Change the password behind the tool's back:

```sql
ALTER USER acme_app_user IDENTIFIED BY "Drifted#2026x";
```

```
ACCOUNT        TARGET    STATE  DETAIL
acme_app_user  free-pdb  DRIFT  vault v3 the database rejected this password (ORA-01017):
                                ORA-01017: invalid credential or not authorized; logon denied

1 drift
```

**Exit 3**, its own code precisely so a scheduler can tell drift from failure.
`creds apply` converges it — vault to database, always, never the reverse:

```
ACCOUNT        TARGET    STATE    DETAIL
acme_app_user  free-pdb  IN_SYNC  changed and verified by login

1 changed
```

### 10.4a `apply --repair` — spend one login instead of twenty

`apply` is already safe to re-run, so the plain re-run repairs a partial run
correctly. What it costs is a login per account per target, against the
failed-login counter §7 exists to protect. `--repair` narrows that to the pairs
a previous run left unconfirmed.

**It needs the previous run's document on disk**, which means that run has to
have been captured. Under `--output text` there is nothing to point it at — the
tool prints the document or the text, never both:

```bash
sopuli --config sopuli.yaml --output json creds check > drift.json ; echo "exit $?"
```

```
exit 3
```

Two accounts, one drifted. `--dry-run` first, which is where you see the
narrowing — a plan of **1 account x 1 target** where the estate has two:

```
Plan: 1 account x 1 target = 1 apply   [dev]

ACCOUNT          TARGET    INTENT                               SECRET
acme_batch_user  free-pdb  verify, password_set, vault_promote  vault-dev:acme/dev/acme

ACCOUNT          TARGET    SECRET                   SOURCE
acme_batch_user  free-pdb  vault-dev:acme/dev/acme  current

nothing was applied (--dry-run)
```

Then for real:

```bash
sopuli --config sopuli.yaml creds apply --repair drift.json
```

```
ACCOUNT          TARGET    SECRET                   SOURCE
acme_batch_user  free-pdb  vault-dev:acme/dev/acme  current

ACCOUNT          TARGET    STATE    DETAIL
acme_batch_user  free-pdb  IN_SYNC  changed and verified by login

1 changed
```

`acme_app_user` was never dialled. That is the whole feature.

#### The exit-4 loop, which is what it is for

Stage a rotation, lock one account so it cannot confirm, and apply:

```sql
ALTER USER acme_batch_user ACCOUNT LOCK;
```

```
ACCOUNT          TARGET    STATE    DETAIL
acme_app_user    free-pdb  IN_SYNC  changed and verified by login
acme_batch_user  free-pdb  LOCKED   account is locked; the password was not changed, because a locked account cannot confirm one -- declare `account: { unlock_if_locked: true }` on this account's policy to have `apply` unlock it first

1 changed, 1 not confirmed
repair with: sopuli creds apply --config C:\tmp\sopuli-guide\sopuli.yaml --select tier=sandbox
         or: --repair FILE, if you captured this run with --output json
```

Exit 4 — but that run was text mode, so it captured nothing. **Re-run it as JSON
while the account is still locked**, which is the document you actually repair
from:

```bash
sopuli --config sopuli.yaml --output json creds apply --select tier=sandbox > partial.json
echo "exit $?"      # 4
```

*Then* unlock the account and repair from that document:

```sql
ALTER USER acme_batch_user ACCOUNT UNLOCK;
```

```bash
sopuli --config sopuli.yaml creds apply --repair partial.json
```

```
ACCOUNT          TARGET    SECRET                   SOURCE
acme_batch_user  free-pdb  vault-dev:acme/dev/acme  pending

ACCOUNT          TARGET    STATE    DETAIL
acme_batch_user  free-pdb  IN_SYNC  changed and verified by login

1 changed, 1 promoted to `current`
```

The pending is applied to the one account that missed it and *then* promoted,
which is invariant 7's ordering surviving the narrowing. Getting the order wrong
is worth doing once: unlock first and the locked run's document is the one you
already fixed, so the repair set is empty and you get `nothing to apply`.

#### The refusals, which are most of the value

Every one of these exits **2** with nothing on stdout — the same treatment
`--target nosuch` gets, because `--repair` feeds a filter and a filter that does
not resolve is an invocation that did not resolve.

A document from a different configuration, which is the one mistake the
narrowing does not make harmless:

```
sopuli: --repair: C:\tmp\sopuli-guide\foreign.json: was produced over a different configuration
  hint: produced over C:\tmp\sopuli-guide\other.yaml; this run resolves C:\tmp\sopuli-guide\sopuli.yaml
```

Note what that compares: the *paths*, not their content. A config file copied
somewhere else is a different estate to this check.

A document from a command that reports no repair set:

```
sopuli: --repair: C:\tmp\sopuli-guide\notaproducer.json: was produced by `target.list`, which reports no repair set
  hint: pass a document from `creds.apply` or `creds.check` -- an apply that exited 4, or a check that exited 3
```

Something that is not a run document at all, and a path that is not there:

```
sopuli: --repair: C:\tmp\sopuli-guide\garbage.json: is not JSON (line 1)
  hint: this flag reads a run document, which is what `--output json` writes

sopuli: --repair: C:\tmp\sopuli-guide\nosuch.json: cannot be read (No such file or directory)
  hint: pass the path to a `creds apply` or `creds check` run document
```

A document produced by sopuli 0.60 or earlier carries no
`invocation.config_files` (#402), so the estate cannot be checked and it is
refused rather than trusted. Cause it on purpose by deleting that key from a
captured document:

```
sopuli: --repair: C:\tmp\sopuli-guide\old.json: names no config files, so it cannot be shown to describe this estate
  hint: `invocation.config_files` arrived in #402 -- re-run the command that produced this document to get one that carries it
```

#### Staleness warns and proceeds

Edit `invocation.finished_at` in a captured document to something old. The run
does the work and says how old its instructions were:

```
1 note:
  C:\tmp\sopuli-guide\stale.json: this document is 13 days old, so the run it describes may not be the estate's current state -- a pair since repaired costs one login and reports changed: false
```

`SOPULI-W020` in `diagnostics[]` under `--output json`. Deliberately not a gate:
the set can only narrow, and a pair since repaired costs one login and reports
`changed: false`, so a stale document is wasteful rather than dangerous.

### 10.5 `check` and the lockout guard

`check` authenticates, so a loop over a drifted account is a loop that can lock it
out. `--lockout-margin` is the guard. Put the account somewhere it matters and
spend two of its three attempts:

```sql
ALTER USER acme_app_user PROFILE sopuli_lockout;   -- FAILED_LOGIN_ATTEMPTS 3
ALTER USER acme_app_user IDENTIFIED BY "Drifted#2026x";
```
```bash
# twice, to record two failed logins
docker exec sopuli-test-oracle-free-1 \
  sqlplus -S -L acme_app_user/wrongpw@localhost:1521/FREEPDB1 < /dev/null
```

```bash
sopuli --config sopuli.yaml creds check --lockout-margin 2
```
```
ACCOUNT        TARGET    STATE         DETAIL
acme_app_user  free-pdb  UNVERIFIABLE  no login attempted: 2 of 3 failed logins are already
                                       recorded, and 1 more would leave less than the
                                       2-attempt margin

1 unverifiable
```

**Exit 0, and no login was attempted.** `UNVERIFIABLE` is the honest answer — the
tool declines to find out rather than risk the lockout, and names the fact that
stopped it. This needs `SELECT ON SYS.USER$`; `test/oracle-init/` grants it to
`SYSTEM`, and without it the guard reports itself unavailable instead.

Put the account back on `DEFAULT` before continuing.

### 10.6 `rotate` — the whole sequence under one lock

`rotate` is `generate` then `apply`, in one run, holding the lock throughout —
which is the point, since the two halves run separately leave a window where
another run can interleave.

```
Plan: 1 account x 1 target = 1 rotation   [dev]

ACCOUNT        TARGET    INTENT                                                              SECRET
acme_app_user  free-pdb  generate, vault_write_pending, verify, password_set, vault_promote  vault-dev:acme/dev/acme

ACCOUNT        TARGET    STATE    DETAIL
acme_app_user  free-pdb  IN_SYNC  changed and verified by login

1 changed, 1 promoted to `current`

rotation: staged 1 document, promoted 1 document
```

That `INTENT` column is the whole use case in one row, and it is worth reading once
in that order.

### 10.7 Rolling back

`--source previous` re-applies the value the last promotion displaced:

```
ACCOUNT        TARGET    SECRET                   SOURCE
acme_app_user  free-pdb  vault-dev:acme/dev/acme  previous

ACCOUNT        TARGET    STATE    DETAIL
acme_app_user  free-pdb  IN_SYNC  changed and verified by login

1 rolled back, 1 promoted to `current`
```

Exercise this at least once. It is the reason a promotion moves the old `current`
into `previous` rather than overwriting it, and the reason invariant 7's ordering is
worth the extra vault write.

### 10.8 `--promote`, and the refusal in front of it

`creds generate --promote` writes `current` directly, for adopting an account whose
password you already know. It is invariant 7's one exception, and where a `current`
already exists it refuses:

```
sopuli: 1 of the selected accounts already have a `current` in the vault (acme_app_user), and
  promoting would replace what applications are reading
  hint: pass --overwrite-current to authorise replacing them, --dry-run to see which would be
        seeded and which replaced, or drop --promote to stage a `pending` instead
```

Exit 8. With `--overwrite-current`:

```
ACCOUNT        TARGET    INTENT                   SECRET
acme_app_user  free-pdb  generate, vault_promote  vault-dev:acme/dev/acme

SECRET                   SEEDED  REPLACED
vault-dev:acme/dev/acme  -       acme_app_user

ACCOUNT        SECRET                   RESULT
acme_app_user  vault-dev:acme/dev/acme  promoted to v9, replaced the current

1 promoted to current; no database was changed -- run `sopuli creds apply` to use them
```

Note the `INTENT` has no `password_set`: nothing asked a database anything. Which is
why the very next `check` reports drift —

```
acme_app_user  free-pdb  DRIFT  vault v9 the database rejected this password (ORA-01017): ...
```

— and that is correct, not a bug. The vault is master; the database has not caught
up yet, and `apply` is what makes it.

### 10.9 Rollover, and `finish-rollover`

Gradual password rollover lets the old password keep working for a window after the
new one is set, so applications can be restarted at leisure. It comes from the
account's **profile**, and a policy can put it there:

```yaml
policies:
  rollover-capable:
    password: { length: 24, charset: alnum_safe, first_char: alpha,
                require: { upper: 1, lower: 1, digit: 1, special: 1 } }
    account:
      profile: SOPULI_ROLLOVER
```

`apply` then assigns the profile before setting the password, and the window opens
by itself:

```
ACCOUNT          TARGET    INTENT                                              SECRET
acme_batch_user  free-pdb  attribute_set, verify, password_set, vault_promote  vault-dev:acme/dev/batch

ACCOUNT          TARGET    STATE            DETAIL
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  changed and verified; a rollover window is open, so
                                            the previous password authenticates until it closes
```

`status` and `check --include-previous` both report the window rather than treating
it as drift:

```
ACCOUNT          TARGET    STATE            VAULT_V  AGE  DB_PW_CHANGED  PROFILE          ROLLOVER
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  2        0d   2026-09-06     SOPULI_ROLLOVER  window open
```
```
ACCOUNT          TARGET    STATE            DETAIL
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  vault v2 accepted, but a rollover window is open:
                                            the previous password still works too
```

Close it early once the applications have restarted:

```
ACCOUNT          TARGET    WINDOW
acme_batch_user  free-pdb  open, 59m left

ACCOUNT          TARGET    STATE    DETAIL
acme_batch_user  free-pdb  IN_SYNC  rollover window closed, 59m early

1 closed
```

Run it again to see invariant 9 hold on a verb where it was easy to get wrong —
Oracle accepts the statement silently when no window is open, so a driver that just
issued it would report `changed: true` for a run that did nothing:

```
ACCOUNT          TARGET    WINDOW
acme_batch_user  free-pdb  none open

ACCOUNT          TARGET    STATE    DETAIL
acme_batch_user  free-pdb  IN_SYNC  no rollover window is open

no rollover window was open on any of 1
```

### 10.10 Asking for a strategy the estate cannot serve

`--strategy rollover` against an account on `DEFAULT` fails **at plan time**, before
anything is written, and names the fix rather than performing it:

```
sopuli: profile DEFAULT grants no rollover window (PASSWORD_ROLLOVER_TIME is 0)
  hint: sopuli does not alter a profile, because profiles are shared and changing one affects
        accounts nobody selected. Run this yourself if it is what you want:
        ALTER PROFILE DEFAULT LIMIT PASSWORD_ROLLOVER_TIME 1;
```

Exit **1**, not 5, and the difference is worth knowing: exit 5 means the *release*
cannot do rollover at all, which no local action changes. This is a profile
setting, which one `ALTER PROFILE` changes — a configuration rather than a
limitation. The tool never issues that statement itself; `ALTER PROFILE` reaches
accounts nobody selected.

**And here is the exit 5, measured on 18c** (#381) — the same command against a
release that has no such feature, so §5's table is the only thing that changed:

```
$ sopuli --config sopuli-18c.yaml creds apply --application acme --strategy rollover --dry-run
sopuli: target "xe18-pdb" does not support password_rollover
  hint: gradual password rollover needs Oracle 19.12 or later; this release has no such
        feature and no profile setting adds it -- use `--strategy staged`, or omit
        `--strategy` and let the target decide
```

It refuses under `--dry-run`, which is the point: nothing was staged, nothing was
connected to twice, and the plan never became a run. `--output json` carries the
same fact for a consumer that should not be parsing prose — `exit_code: 5`,
`error.category: "capability"`, `error.target_capability: "password_rollover"` —
and emits the `plan` object alongside it, so the document shows what *would* have
happened next to the reason it did not.

`doctor` says the same thing one column earlier, and is the cheaper place to find
out: **`CAPABILITIES` reads 5 on 18c and 6 on 21c and 26ai.** The missing one is
`password_rollover`, and `--output json` names them under
`targets[].scope.capabilities`.

---

## 11. Getting refused on purpose

Everything in §10 succeeded. These are the paths that must not.

### The account guardrails, and the two answers they give

`02-oracle-privileges.md` §4 refuses accounts a credential-sync tool has no
business touching. Put `acme_priv_user` (which holds `DBA`) in the same application
entry as `acme_app_user` — this needs the pointer-form `secret_template` from §6 —
and rotate both:

```
ACCOUNT         TARGET    STATE    DETAIL
acme_app_user   free-pdb  IN_SYNC  changed and verified by login
acme_priv_user  free-pdb  SKIPPED  the account holds DBA

1 changed, 1 promoted to `current`, 1 not confirmed

rotation: staged 1 document, promoted 1 document
the vault read back a different password for: acme_priv_user
```

**Exit 4, partial.** The run did the rest of its job; the refused account carries
its reason. That last line is `generate`'s half having run before the guardrail
declined the `apply` half — a staged `pending` nothing will use, which `status`
shows until the next successful rotation replaces it.

Name the account explicitly and the same fact reads differently:

```bash
sopuli --config guarded.yaml creds rotate --account acme_priv_user --confirm
```
```
ACCOUNT         TARGET    STATE  DETAIL
acme_priv_user  free-pdb  ERROR  the account holds DBA -- you named this account, so the run
                                 stopped short: pass --force to override, which is recorded

nothing changed, 1 not confirmed
```

Exit 1. Asking for one thing and being told "skipped" would be a run reporting
success for work nobody did. `--force` overrides it, and is audited:

```
ACCOUNT         TARGET    STATE    DETAIL
acme_priv_user  free-pdb  IN_SYNC  changed and verified by login
```

`--force` reaches these guardrails and nothing else. It cannot extend the whitelist
(invariant 5) and it cannot relax a safety setting (invariant 10).

### A selector cannot invent an account

```bash
sopuli --config sopuli.yaml creds status --account nosuch
```
```
sopuli: --account: name not declared in the configuration: `nosuch`
  hint: the configuration declares acme_app_user -- a selector filters the declared set and
        cannot extend it (invariant 5)
```

Exit 2. `--target`, `--group`, `--application` and `--select K=V` all behave the
same way: they narrow, never widen.

### The safety block

These go under `defaults:` (or a profile), never at the top level — a top-level
`safety:` is `unknown key 'safety'`, exit 9.

```yaml
defaults:
  policy: standard
  safety:
    readonly: true
```

```
sopuli: applying a password is a mutation, and `safety.readonly` is set
  hint: set at defaults.safety.readonly; no layer can relax it (invariant 10) --
        `sopuli lock status` reads without writing
```

Exit 8, and **`--dry-run` is refused too** — under `readonly` the mutating verbs are
unavailable, and the read-only verb is how you ask. `creds check` still runs and
exits 0.

Swap it for `confirm_environments: [dev]` and run a mutation with nothing on stdin
(`sopuli ... creds apply < /dev/null`):

```
applying a password in `dev`? [y/N]: sopuli: aborted
```

Exit 8. `--confirm` satisfies it, given in advance; `--force` does not and is not
consulted.

`max_targets` is the third key, and `readonly: true` is the way to block
everything — `max_targets: 0` is far more likely to be a slip that then blocks every
run.

---

## 12. Oracle wallets and `auth: external`

A target using `auth: external` connects as `/@alias`, and the wallet supplies
**both** the username and the password. This is the case where failures are most
misleading, and where `doctor` earns its keep.

### First: you probably cannot create a wallet on your laptop

`mkstore` and `orapki` are **not in Instant Client** — any edition. Two dead ends,
both verified here so you do not have to:

- `gvenzl/oracle-free` *has* `mkstore` and `orapki` in `$ORACLE_HOME/bin`, but
  **ships no Java**, and both are shell wrappers around a Java class:
  `ERROR: No Java`.
- Installing a JRE into that container with `microdnf`/`dnf` failed too — no
  usable package source in the image.

To create a *real* wallet you need one of these, **none verified here**:

- a full Oracle Database or Oracle Client installation (both bundle a JDK);
- Oracle's own container image from `container-registry.oracle.com/database/free`,
  which is the full product rather than a slimmed rebuild;
- for OCI Autonomous Database, the wallet Oracle generates for you — download it
  from the console and skip `mkstore` entirely (§14).

For reference, the real commands are:

```bash
mkstore -wrl /path/to/wallet -create
mkstore -wrl /path/to/wallet -createCredential FREEPDB1 SYSTEM sopuli-test
mkstore -wrl /path/to/wallet -listCredential
```

### But you can test sopuli's wallet report today

**sopuli never opens the wallet.** It checks that a directory is listable, that
`cwallet.sso` is there, that this process can read it, and what its permissions
are — deliberately, because confirming the wallet holds a credential means asking
the client, and the connection attempt already does that better.

So a dummy file exercises the whole report. Set up a `TNS_ADMIN`:

```
tns/
  tnsnames.ora
  cwallet.sso        <- any bytes at all
```

```
FREEPDB1 =
  (DESCRIPTION =
    (ADDRESS = (PROTOCOL = TCP)(HOST = 127.0.0.1)(PORT = 1521))
    (CONNECT_DATA = (SERVICE_NAME = FREEPDB1))
  )
```

and a target that uses it — note the DSN is the **alias**, and no `username:`
(both are load-time errors otherwise):

```yaml
targets:
  - name: wallet-pdb
    type: oracle
    environment: dev
    vault: vault-dev
    dsn: "FREEPDB1"
    admin: { auth: external }
```

```bash
export TNS_ADMIN=/path/to/tns
sopuli --config wallet-test.yaml doctor
```

**With the directory empty:**

```
wallet
  required by       wallet-pdb
  tns_admin         C:\tmp\sopuli-guide\tns
  searched          C:\tmp\sopuli-guide\tns
  found             nothing
  auto-login        no
  no readable cwallet.sso in C:\tmp\sopuli-guide\tns, and no wallet of any kind
```

**With a `cwallet.sso` present:**

```
  found             cwallet.sso
  auto-login        yes
```

The permission warning (`SOPULI-W008`) is the one worth producing deliberately, and
on this machine it did **not** fire on a file simply created under `%TEMP%` — that
directory grants no `BUILTIN\Users` here, so the file inherits none. Add the grant
yourself:

```powershell
icacls tns\cwallet.sso /grant "BUILTIN\Users:R"
```
```
  found             cwallet.sso
  auto-login        yes
  cwallet.sso wallet file is accessible to BUILTIN\Users: an auto-login wallet is a credential,
  and this one is not private
```

Tighten it again with `/inheritance:r /grant:r` and watch it go away — this is P4's
config-file check applied to the file that actually holds a password.

### The reason all of this exists

Run `doctor --output json` against that dummy wallet and read the target's error:

```json
{
  "category": "authentication",
  "code": "ORA-01017",
  "message": "ORA-01017: invalid credential or not authorized; logon denied",
  "hint": "the password this run used is not the one the database holds"
}
```

**The wallet is the problem and the error is entirely about the password.** Left to
that message you would go looking for an account and a password you do not have.
The `wallet` section above it is what redirects you to the file.

Nothing in that section changes the exit code — a bad wallet rides on the target's
own reachability, which the connection settles a moment later.

### Other states worth producing

| Do this | Expect |
|---|---|
| `unset TNS_ADMIN` | `$TNS_ADMIN is unset, so there is nowhere to read a wallet from` |
| point `TNS_ADMIN` at a missing directory | `is missing or not readable by this user` |
| leave only `ewallet.p12` | `no readable cwallet.sso ... needs a passphrase this tool cannot supply` |
| deny yourself read on `cwallet.sso` | `this process cannot read it -- check who owns it, and which account this is running as` |
| add `sqlnet.ora` with `WALLET_LOCATION = (SOURCE=(METHOD=FILE)(METHOD_DATA=(DIRECTORY=/elsewhere)))` | `searched` moves, and says `(from sqlnet.ora WALLET_LOCATION)` |

The last one matters: the client follows that redirect, so a check that did not
would report "no wallet" for a correctly configured estate.

Remove the target that uses `external` and the whole `wallet` section disappears —
deliberately, since most estates have no wallet to report on.

---

## 13. WSL

Repeat §§6–12. Everything behaves identically except two things, and both are worth
seeing:

- **Permissions are modes, not ACLs.** `chmod 600` instead of `icacls`, and the
  message reads `config file is accessible to others (mode 0644)`. `chmod 640` is
  refused too — the check is on `0o077`, not just the read bits.
- **Reaching the containers.** Under WSL2 with Docker Desktop, `127.0.0.1` works
  from WSL. Under a Docker daemon running inside WSL, it also works. If you are
  running Docker on Windows and sopuli in a *different* WSL distro, use the Windows
  host IP from `/etc/resolv.conf` instead.

Install a separate Instant Client for Linux; the Windows one is not usable from
WSL.

---

## 14. OCI

Two halves, and only one exists.

**A database in OCI — supported.** This is the reason for thick mode: OCI-hosted
databases require Native Network Encryption, which thin mode cannot do. Point a
target at it exactly like any other:

```yaml
targets:
  - name: adb-prod
    type: oracle
    environment: prod
    vault: vault-dev
    dsn: "myadb_high"
    admin: { auth: external }
```

For Autonomous Database, download the wallet zip from the OCI console, unzip it,
and set `TNS_ADMIN` to that directory. It contains `cwallet.sso`, `tnsnames.ora`
and `sqlnet.ora` already — which is the one path to a real wallet that does not need
`mkstore` at all. The aliases (`_high`, `_medium`, `_low`) are in its
`tnsnames.ora`.

**Locally you can approximate the NNE constraint** without OCI:

```bash
docker compose --profile nne up -d      # Oracle on 1525, NNE required
```

Note `test/compose.yaml`'s own header: the `nne` profile is **unrun and its image
tag unverified**. Treat a failure there as possibly the fixture.

**OCI Vault as a secret store — does not exist.** `type: oci` parses and then fails:
there is no `sopuli/store/oci` module. `doctor` reports it as `not_implemented` with
no install command, precisely because `pip` cannot supply it. Do not spend time on
it.

---

## 15. Exit codes

Branch on these; they are a published interface. Every one is now reachable from
this guide.

| Code | Meaning | Where you will see it here |
|---|---|---|
| 0 | success, or nothing to do | most runs |
| 1 | generic failure | an unreachable target in `doctor` (§9); `--strategy rollover` on a `DEFAULT`-profile account (§10.10); a named account the guardrails refuse (§11) |
| 2 | argv did not parse — **no JSON document, message on stderr** | `--reveal --output json` (§7); `--account` naming something undeclared (§11) |
| 3 | `check` found drift | §10.4 |
| 4 | partial | a guardrail-skipped account inside a wider selection (§11) |
| 5 | unsupported capability | a lock path with no `cas_required` — since #390 the tool sets it on a path it creates, so this is a path created before that or by something else (§8); rollover on 18c/11g |
| 6 | authentication failed | a bad vault token |
| 7 | lock held | any mutating verb against a held lock, and `lock break` without `--force` (§8) |
| 8 | aborted / confirmation declined | `readonly` and `confirm_environments` (§11); `--promote` over an existing `current` (§10.8) |
| 9 | configuration unusable | bad YAML, bad permissions, two accounts sharing a staging root (§6), a supplied password violating policy (§10.2), or a configured backend this build cannot serve |

**Exit 2 is the only one that never produces a run document.** Every other code
emits one on stdout under `--output json`, including 9 — a validator that goes
silent exactly when it has something to say is not a validator. Worth confirming
once:

```bash
sopuli --config broken.yaml --output json config validate; echo "exit $?"
```

### The JSON contract

`--output json` on any verb emits the run document
[`schemas/sopuli-run-1.21.schema.json`](schemas/sopuli-run-1.21.schema.json) describes. `creds check`,
trimmed to its shape:

```json
{
  "schema_version": "1.21",
  "tool": { "name": "sopuli", "version": "0.60.0" },
  "command": "creds.check",
  "invocation": {
    "correlation_id": "f8aa9373-77ca-456d-b5a4-5272a0ccf873",
    "started_at": "2026-09-11T10:21:17.576520Z",
    "duration_ms": 750,
    "actor": { "os_user": "ville", "host": "Awesominator" },
    "dry_run": false,
    "config_files": ["C:\\tmp\\sopuli-guide\\sopuli.yaml"],
    "options": {
      "output": { "value": "json", "source": "cli", "source_detail": "--output (group)" }
    }
  },
  "summary": { "total": 1, "ok": 1, "changed": 0, "drift": 0, "by_state": { "IN_SYNC": 1 } },
  "exit_code": 0,
  "plan": {
    "units": [ { "account": "acme_app_user", "target": "free-pdb", "intent": ["verify"],
                 "secret": { "vault": "vault-dev", "path": "acme/dev/acme",
                             "field": "acme_app_user" } } ],
    "blast_radius": { "targets": 1, "accounts": 1, "environments": ["dev"] }
  },
  "results": [
    {
      "account": "acme_app_user", "target": "free-pdb", "state": "IN_SYNC", "changed": false,
      "secret": { "vault": "vault-dev", "path": "acme/dev/acme", "field": "acme_app_user",
                  "version": 2, "stage": "current" },
      "actions": [ { "kind": "verify", "applied": true, "detail": "vault v2 verified by login" } ],
      "verification": { "method": "login", "result": "pass", "lcount": 0,
                        "failed_login_attempts_limit": "UNLIMITED", "lockout_margin_hit": false,
                        "previous_password_accepted": null },
      "password_age_days": 0.0, "duration_ms": 118
    }
  ]
}
```

`invocation.options` is `--explain` in machine form, `plan.blast_radius` is what
`max_targets` and `confirm_environments` read, and no field anywhere holds a
password. Grepping a captured document for one is a reasonable thing to do once.

---

## 16. Cleanup

```bash
cd test
docker compose --profile '*' down          # the only form that works
```

That discards the database, so the accounts from §5 go with it. If you are keeping
the container — and you should, startup dominates everything else — drop them
instead:

```sql
DROP USER acme_app_user CASCADE;
DROP USER acme_batch_user CASCADE;
DROP USER acme_priv_user CASCADE;
```

Vault's `kv` mount is in-memory and goes with a restart, but it is shared with every
config you have pointed at it, so `lock status` keeps listing this guide's records
under "not declared by this config" until then.
`vault kv metadata delete -mount=kv locks/acme/dev/acme` removes one for good.

Then remove the config, the token file and the `TNS_ADMIN` directory. Nothing sopuli
did wrote outside them, the accounts above, and Vault under `acme/` and `locks/`.

---

## What this guide cannot cover yet

- **`admin install`**, which will run the SQL in `sql/oracle/` for you. Run the
  scripts by hand for now.
- **`--output jsonl`** and the streaming event contract. Nothing streams yet, so the
  format is deliberately not offered.
- **`--method hash`**, verification without a login attempt. It depends on the `T:`
  verifier layout in `SYS.USER$.SPARE4`, which is unconfirmed — `verify.method`
  parses in a profile and reaches no consumer.
- **The `file`, `keyring` and `oci` stores.** Only `hashicorp` exists.
- **A real wallet without a full Oracle install**, per §12.
- **19c, and anything above tier 2.** The whole tier-2 matrix is done — 21c
  (#380), 18c (#381) and 11g (#382) — and §5's *Running all of this against a
  different Oracle version* is the map. 19c is tier 3, needs a real OCI tenancy
  or a built 19c, and is now what two open questions turn on: the password byte
  limit (#383) and whether the `ALTER USER` text survives in `V$SQLSTATS` —
  measured true on 11.2 and false on 18c and later, with 12.1, 12.2 and 19c
  unmeasured in between, so #387 decided what to do about 11.2 and left the
  boundary open.

When those land, this document should grow with them — it is meant to stay a
complete map of what can be exercised by hand, and a stale one is worse than none.

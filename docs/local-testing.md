# Testing sopuli by hand

How to set up a laptop, WSL, containers and OCI so you can exercise every command
this build has, and see each one succeed *and* fail on purpose.

Every command and every output in this document was re-run on 2026-09-06 against
Windows 11, sopuli 0.58.0, Instant Client 23.26.3.0.0, and the `tier1` container
stack. Where something was **not** verified it says so. Working paths in the
samples are shortened to `C:\tmp\sopuli-guide\` — that is the only edit made to
any output here.

§15's run document was re-captured on 2026-09-15 on the same stack, against
sopuli 0.61.0, when the run schema became 1.23 (#428), and §3's `sopuli about`
on 2026-09-11 against the same release, the one that added the command (#413). A
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
| **OCI** | the only place Native Network Encryption and a real ADB wallet can be exercised — and note that an ADB wallet is TLS certificates, not a credential store (§14) |

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
| 18c XE | `sopuli-test-oracle-xe18-1` | `127.0.0.1:1523/XEPDB1`, root `.../XE` | CDB + PDB, **no rollover** (5 capabilities, not 6), and no `PASSWORD_CHANGE_DATE` — `DB_PW_CHANGED` is read from `SYS.USER$.PTIME` where the grant exists, and is empty with a `SOPULI-W021` note saying why where it does not (#386) |
| 11g XE | `sopuli-test-oracle-xe11-1` | `127.0.0.1:1524/XE` | **non-CDB** (`scope: non_cdb`, no `container:`), no rollover, `DB_PW_CHANGED` only through `SYS.USER$.PTIME` as on 18c, no unified auditing — `01_audit_policy.sql` refuses. **`V$SQLSTATS` retains the `ALTER USER` text here**, and does not on the other three containers, so a leak result from this one does not generalise — nor does a clean result from the others, since 12.1, 12.2 and 19c are unmeasured. See [`security-model.md`](security-model.md) §5 and #387 |

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
  vault: vault-dev

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

### Personal accounts, which nothing masters

UC-2 is not built — there is no `account` verb to run — but the **declaration** is
(#467), and `config show` reports it like any other section. Add this to the file
from §6:

```yaml
personal_accounts:
  - accounts: [jdoe, asmith]
    targets: [appdb-dev-alpha]
    policy: personal-standard
  - profile: DEV_USERS
    policy: personal-standard
```

```
personal_accounts
DECLARED BY          ACCOUNTS  TARGETS          POLICY
names                2         appdb-dev-alpha  personal-standard
profile 'DEV_USERS'  -         all              personal-standard
```

**The dash is the point of the second row.** A `profile:` or `role:` entry is a
**predicate**, resolved against the database by the verb that reads it, so how
many accounts it covers is not something the file knows — and `config show`
describes the file. A count there would be a guess.

Three failures worth causing, all of them at load, all of them exit **9**:

| Change | What you get |
|---|---|
| put an application's account in `personal_accounts:` too | `personal_accounts[0].accounts[0]: account 'acme_web_user' is declared both as a personal account and by acme` |
| write `accounts:` and `profile:` in one entry | ``personal_accounts[1]: must declare exactly one of `accounts:`, `profile:` or `role:` (found `accounts:`, `profile:`)`` |
| misspell the `policy:` | `personal_accounts[0].policy: no policy named 'personal-standrd' is declared` |

The first is the one worth understanding rather than just seeing. An account that
is both an application's and a person's is ambiguous about **which guarantee
applies** — mastered by a secret and synced from it, or handed over once and
mastered by nothing — so the tool refuses instead of picking. It compares
case-insensitively: `ACME_WEB_USER` and `acme_web_user` collide, because one
`--account` reaches both.

What a file **cannot** catch is the same collision through a predicate: if
`DEV_USERS` happens to admit `acme_web_user`, nothing here can know it. That is
stated rather than hidden — it is the cost H1 (#449) accepted when it allowed a
predicate at all, and the verb that resolves one is where it has to be caught.

### `defaults.vault` is the line that makes three other things work

`vault: vault-dev` under `defaults:` is not decoration. It names the **default
store**, which is what `--vault-addr`, `SOPULI_VAULT_ADDR` and `VAULT_ADDR` all
address — none of them names a store, and a run touching two vaults has two. Drop
the line and all three stop working, in two different ways (§11 causes both on
purpose).

Drop it and `VAULT_ADDR` — which *will* be set in your shell, because §8 tells you
to set it — warns instead of applying:

```
ok: 1 target, 1 binding, 1 warning

1 warning:
  VAULT_ADDR is set and was not applied: this run has no default store, and a third-party
  variable names none
    hint: P3 honours it as a setting of the store `defaults.vault` names, below SOPULI_VAULT --
          write `defaults.vault`, or ignore this if the variable belongs to something else on
          this machine
```

Keep it and the variable is honoured silently instead, at P3's layer 3 — which
means an exported `VAULT_ADDR` you forgot about is redirecting every run. §7 is
how you see that; it is the case `config show --explain` exists for.

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
  db.connect_timeout_s        = 30                     [built-in default]
  db.query_timeout_s          = 0                      [built-in default]
  output                      = text                   [built-in default]
  safety.dry_run              = false                  [built-in default]
  safety.readonly             = false                  [built-in default]
  vault                       = vault-dev              [defaults.vault]
  vaults.vault-dev.addr       = http://127.0.0.1:8200  [vaults.vault-dev.addr]
  vaults.vault-dev.kv_version = 2                      [vaults.vault-dev.kv_version]
  vaults.vault-dev.mount      = kv                     [vaults.vault-dev.mount]
```

Set `SOPULI_OUTPUT=json` and run it again to watch a layer change. Only three
variables reach a setting this way — `SOPULI_OUTPUT`, `SOPULI_DRY_RUN` and
`SOPULI_PROFILE` — plus `SOPULI_VAULT` and the per-store `SOPULI_VAULT__*` forms.
**There is no `SOPULI_READONLY` and no `SOPULI_MAX_TARGETS`**, and an invented one
is ignored rather than refused, so a run you believe is guarded by an environment
variable is not guarded at all. Those live in the file (§11).

The `vaults.vault-dev.*` rows are the store's own settings (#428). A store's keys
go through the same chain as the run's, so they get rows in the same table — and
those three say `[vaults.vault-dev.…]`, meaning the file wrote them, right there.
The next subsection is where that stops being the answer.

### Where the store's address actually came from

Export `VAULT_ADDR` at a different port and run the same command:

```bash
VAULT_ADDR=http://127.0.0.1:8202 sopuli --config sopuli.yaml config show --explain
```
```
vaults
NAME       TYPE       ADDRESS                NOTE
vault-dev  hashicorp  http://127.0.0.1:8202  layered: addr

...

settings
  ...
  vaults.vault-dev.addr       = http://127.0.0.1:8202  [env_thirdparty VAULT_ADDR]
  vaults.vault-dev.kv_version = 2                      [vaults.vault-dev.kv_version]
  vaults.vault-dev.mount      = kv                     [vaults.vault-dev.mount]
```

Nothing is listening on 8202, the file says 8200, and the table is reporting the
address the run will actually use — `layered: addr` in `NOTE` says a layer wrote
it and the `settings` row says **which**. Seven sources can write that one key:

| Source | Renders as |
|---|---|
| `--vault-addr URL` | `[cli --vault-addr]` |
| `SOPULI_VAULT__VAULT_DEV__ADDR` | `[env SOPULI_VAULT__VAULT_DEV__ADDR]` |
| `SOPULI_VAULT_ADDR` | `[env SOPULI_VAULT_ADDR]` |
| `VAULT_ADDR` | `[env_thirdparty VAULT_ADDR]` |
| a profile's `vaults:` block | `[profiles.<name>.vaults.vault-dev.addr]` |
| the `vaults:` entry itself | `[vaults.vault-dev.addr]` |
| `defaults.vaults:` | `[defaults.vaults.vault-dev.addr]` |

Try any of them; they are all one command. **This is the question to ask first**
when a command reaches a vault you did not expect — the `NOTE` column says
`layered: addr` for six of those seven and nothing at all for the last, so until
#428 they were one indistinguishable answer, and "a colleague's exported
`VAULT_ADDR`" looked exactly like "I redirected this on purpose".

`auth:` gets no row even when a layer replaced it. It is swapped whole rather
than merged key by key, so no layer *won* a key — `NOTE` says `layered: auth` and
that is the whole of it.

`--output json` carries the same answer as `config.vaults[]`, in both views and
whether or not you pass `--explain`:

```bash
sopuli --config sopuli.yaml config show --output json --vault-addr https://standby.example.com:8200
```
```json
"vaults": [
  {
    "name": "vault-dev",
    "type": "hashicorp",
    "settings": {
      "addr": {
        "value": "https://standby.example.com:8200",
        "source": "cli",
        "source_detail": "--vault-addr"
      },
      "kv_version": {
        "value": 2,
        "source": "object",
        "source_detail": "vaults.vault-dev.kv_version"
      },
      "mount": {
        "value": "kv",
        "source": "object",
        "source_detail": "vaults.vault-dev.mount"
      }
    }
  }
]
```

An excerpt of the `config` section; the rest of the run document sits around it.
Before this, **no** mode of `config show` reported a store's effective settings in
JSON at all: `--explain` emitted `config.declared`, the address the *file* wrote,
and `--resolved` dropped stores and emitted targets and bindings.

### Finding every `safety:` block in a file

The settings table above answers *what did this run resolve to*, and a
`safety:` block on a target or a group is not a property of the run — so
`safety.readonly = false [built-in default]` is the right answer there even for a
file whose target sets it. The **`safety` section** answers the other question:
what does this file guard, and where is it written.

```
$ sopuli --config estate.yaml config show
...
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

One row per key, by the key that writes it — which is what you edit. A target
set's template is one row however many targets it generates, and a block written
in an `overrides:` entry is reported against the override rather than the
template.

The `NOTE` column fires in one case: an override asking for **less** than its
template. Change `appdb-dev-beta`'s to `safety: { readonly: false }` and the row
stays, marked, because the value is in your file and is not what any run reads:

```
target_sets.appdb.overrides.appdb-dev-beta.safety.readonly     false      defeated by the ratchet
target_sets.appdb.safety.readonly                              true
```

The section is absent entirely from a file that writes no block, which is most of
them.

`--resolved` answers it per target instead, with the template and any override
already ratcheted together:

```
$ sopuli --config estate.yaml config show --resolved --output json
```
```json
{
  "config": {
    "targets": [
      { "name": "legacy-pdb",      "safety": { "max_targets": 1, "readonly": true } },
      { "name": "appdb-dev-alpha", "safety": { "max_targets": 4 } },
      { "name": "appdb-dev-beta",  "safety": { "max_targets": 4, "readonly": true } }
    ]
  }
}
```

One document per run, so that is an excerpt: every target carries the other
fields of §15's `config.targets[]` beside `safety`, and the run document's own
sections sit above it.

`null` where nothing constrains the target — it writes no block, or writes an
empty one, which guards the same. `defaults`, a profile and a group are **not**
folded in: none of them is a property of a target, and `config.declared` carries
every block as written.

### `--vault-addr`, the one flag that redirects a store

One vault key has a flag, and it is the address (#422). Point a command at a
different Vault without touching the file or exporting anything:

```
$ sopuli --config sopuli.yaml config show --explain --vault-addr http://127.0.0.1:8201
vaults
NAME       TYPE       ADDRESS                NOTE
vault-dev  hashicorp  http://127.0.0.1:8201  layered: addr

...

settings
  ...
  vaults.vault-dev.addr       = http://127.0.0.1:8201  [cli --vault-addr]
  vaults.vault-dev.kv_version = 2                      [vaults.vault-dev.kv_version]
  vaults.vault-dev.mount      = kv                     [vaults.vault-dev.mount]
```

`layered: addr` is the store reporting that something above the file wrote that
key, and `[cli --vault-addr]` is which. It is not cosmetic — nothing is listening
on 8201, and a command that actually opens a socket says so:

```
$ sopuli --config sopuli.yaml lock status --vault-addr http://127.0.0.1:8201
sopuli: could not reach the store: [WinError 10061] No connection could be made because the target machine actively refused it
  hint: check `addr`, and `tls.ca_file` if the certificate is your own CA
```

Exit 1. Three things to know before you reach for it:

- **It applies to the *default* store** — whichever one `SOPULI_VAULT` or
  `defaults.vault` names. With a file that names neither, it is refused rather
  than guessed at (§11).
- **There is no named form.** For a file with two stores, use
  `SOPULI_VAULT__<NAME>__ADDR`.
- **It is the only one.** There is no `--vault-mount` and no
  `--vault-namespace`; those are the file's, or the `SOPULI_VAULT__*` forms'.

It takes either position, like `--output` and `--profile`:
`sopuli --vault-addr URL config show …` and `sopuli config show … --vault-addr URL`
are the same layer and the same result.

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
  db.connect_timeout_s        = 60                     [profiles.unattended.db.connect_timeout_s]
  db.query_timeout_s          = 0                      [built-in default]
  locking.break_expired       = true                   [profiles.unattended.locking.break_expired]
  output                      = text                   [cli --output (verb)]
  profile                     = unattended             [cli --profile (group)]
  safety.dry_run              = false                  [built-in default]
  safety.readonly             = false                  [built-in default]
  vault                       = vault-dev              [defaults.vault]
  vaults.vault-dev.addr       = http://127.0.0.1:8200  [vaults.vault-dev.addr]
  vaults.vault-dev.kv_version = 2                      [vaults.vault-dev.kv_version]
  vaults.vault-dev.mount      = kv                     [vaults.vault-dev.mount]
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
free-pdb  yes        pdb    FREEPDB1   READ WRITE  7

1 note:
  free-pdb: the admin credential came from the environment variable SOPULI_DB_ADMIN_PASSWORD, which P2 supports and flags as low assurance
```

**That note is `SOPULI-W022`, and you will see it on every run in this guide**,
because the config in §6 authenticates from a variable and §5 told you to export
one. It is a flag rather than a complaint: P2 supports `method: env` — it is the
bootstrap source, and an estate with no other way in is the case it exists for —
and what the tool owes you is to say which variable it used, so that "who can
read that" is a question you can go and answer. The same fact is
`diagnostics[].code` under `--output json`:

```json
{
  "level": "warning",
  "code": "SOPULI-W022",
  "target": "free-pdb",
  "message": "free-pdb: the admin credential came from the environment variable SOPULI_DB_ADMIN_PASSWORD, which P2 supports and flags as low assurance"
}
```

To watch it go away, point the target at any other source: `auth: external`,
`method: vault` and `auth: prompt` are none of them flagged.

**Only `doctor` prints it.** Every verb that opens a database session puts
`SOPULI-W022` in `diagnostics[]` — the four `account` verbs, `creds status`, `creds
generate` (unless `--offline`), `check`, `apply`, `rotate` and `finish-rollover`
as well as `doctor` — so anything alerting on JSON sees it wherever a credential
was used. None of them print a line, because the fact is a property of your
config file and identical on every run: a note under every rotation forever is
one you would stop reading by Thursday.

They all resolve the credential through one function, so that list is what
connects today rather than a set of verbs somebody wired up individually.

The `vaults` section is the store half of the same survey: whether the address
answers, whether the token authenticates, and the clock skew between this machine
and the server. Skew matters because lock expiry is written in the store's time —
a laptop minutes adrift will take over locks that have not expired, or wait on
ones that have.

Then `--output json` for the same run — `targets[].scope.capabilities` names the
seven the driver probed for, which is what `--strategy rollover` branches on in §10.

### 9a. `auth: { method: vault }` — the unattended admin source

`method: env` above is the low-assurance one and `auth: prompt` needs a human.
This is the one P2 ranks highest of the three, and the one a scheduled run wants.
Put the password in the vault first:

```bash
docker exec -i -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=sopuli-test-root   sopuli-test-vault-1 vault kv put kv/ops/dba password=sopuli-test
```

Then point the target's admin block at it, and **unset**
`SOPULI_DB_ADMIN_PASSWORD` so you can tell which source actually worked:

```yaml
targets:
  - name: free-pdb
    type: oracle
    environment: dev
    vault: vault-dev
    dsn: "127.0.0.1:1521/FREEPDB1"
    admin:
      username: SYSTEM
      auth: { method: vault, secret: "ops/dba#password" }
    oracle: { scope: pdb, container: FREEPDB1 }
```

```
TARGET    REACHABLE  SCOPE  CONTAINER  OPEN MODE   CAPABILITIES
free-pdb  yes        pdb    FREEPDB1   READ WRITE  7
```

Exit 0, and **no `SOPULI-W022` note** — which is the cheapest way to see what
that flag in §9 actually means. The ref has no `vault-dev:` prefix here, so it
resolved through the target's own `vault:`; a prefix would override that, and
`defaults.vault` or `$SOPULI_VAULT` would fill in if neither were written.

The store is opened only if this method is used, and once per run however many
targets share it — so an estate of thirty-four PDBs in one vault authenticates
once.

#### Failures worth causing

- **A path with nothing at it**: change the ref to `ops/nothing-here#password`.

  ```
  free-pdb  no         -      -          -          -
    free-pdb: target 'free-pdb' authenticates from 'vault-dev', and there is nothing at 'ops/nothing-here#password'
  ```

  The store *answered*; the path is empty. Deliberately worded to distinguish
  that from a vault nobody could reach, because they send you to different
  places.

- **No store named anywhere**: delete the target's `vault:` line, with no
  `defaults.vault` and no `$SOPULI_VAULT`.

  ```
  free-pdb  no         -      -          -          -
    free-pdb: target 'free-pdb' authenticates from a vault, and nothing says which one
  ```

  Exit 1 in both cases, as a per-target finding rather than a whole-run refusal
  — `doctor` surveys the estate, so one target with a bad ref does not stop the
  next being tried.

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
free-pdb  yes        pdb    FREEPDB1   READ WRITE  7
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

#### An empty `DB_PW_CHANGED`, and the note that says why

`DBA_USERS.PASSWORD_CHANGE_DATE` does not exist on 18c or 11g. There the date is
read from `SYS.USER$.PTIME` instead, which needs the optional `SELECT ON
SYS.USER$` grant (#386). The test containers make that grant to `SYSTEM`, so an
18c target reads exactly like 21c. Add `xe21-pdb` and `xe18-pdb` from
[§5's table](#running-all-of-this-against-a-different-oracle-version) as extra
targets beside `free-pdb`, then take the grant away on 18c to see the other
half — on purpose:

```bash
printf '\nrevoke select on sys.user$ from system container=all;\nexit\n' \
  | docker exec -i sopuli-test-oracle-xe18-1 sqlplus -S "/ as sysdba"
```

```
ACCOUNT        TARGET    STATE         VAULT_V  AGE  DB_PW_CHANGED  PROFILE  ROLLOVER
acme_app_user  free-pdb  UNVERIFIABLE  -        -    2026-09-13     DEFAULT  not configured
acme_app_user  xe21-pdb  UNVERIFIABLE  -        -    2026-09-13     DEFAULT  not configured
acme_app_user  xe18-pdb  UNVERIFIABLE  -        -    -              DEFAULT  not configured

3 accounts, nothing to act on

1 note:
  xe18-pdb: DB_PW_CHANGED is empty for acme_app_user: this release has no DBA_USERS.PASSWORD_CHANGE_DATE; GRANT SELECT ON SYS.USER$ to the service account to read the same date from SYS.USER$.PTIME
```

Exit 0: nothing gates on the database's date. The note is grouped per target, so
forty accounts on one 18c database print one line naming "40 accounts". In
`--output json` the same reason is on each affected result instead, next to the
`password_age_days` that is now missing from it — `creds check` does the same:

```json
"warnings": [
  {
    "level": "warning",
    "message": "this release has no DBA_USERS.PASSWORD_CHANGE_DATE; GRANT SELECT ON SYS.USER$ to the service account to read the same date from SYS.USER$.PTIME",
    "code": "SOPULI-W021",
    "target": "xe18-pdb",
    "account": "acme_app_user"
  }
]
```

Put the grant back (`grant select on sys.user$ to system container=all`), and the
`-` becomes a date and the note goes. The lockout guard tests need it too.

#### A service account that cannot read `DBA_USERS`

Make an account that can connect and rotate, and read nothing:

```sql
CREATE USER acme_nogrant_svc IDENTIFIED BY "Svc-Pass-2026x";
GRANT CREATE SESSION, ALTER USER TO acme_nogrant_svc;
```

Add a second target that authenticates as it:

```yaml
  - name: free-pdb-nogrant
    type: oracle
    environment: dev
    vault: vault-dev
    dsn: "127.0.0.1:1521/FREEPDB1"
    admin: { username: ACME_NOGRANT_SVC, auth: { method: env, password_env: SOPULI_NOGRANT_PASSWORD } }
    oracle: { scope: pdb, container: FREEPDB1 }
```

```
ACCOUNT          TARGET            STATE  VAULT_V  AGE  DB_PW_CHANGED  PROFILE  ROLLOVER
acme_batch_user  free-pdb-nogrant  ERROR  -        -    -              -        -

1 account: 1 unreachable
```

The exit code is 1. `--output json` carries the server's code and names the
grant:

```json
"error": {
  "category": "authorization",
  "message": "could not read DBA_USERS: ORA-00942: table or view \"SYS\".\"DBA_USERS\" does not exist",
  "code": "ORA-00942",
  "hint": "GRANT SELECT ON SYS.DBA_USERS to the service account -- 02-oracle-privileges.md section 2, or sql/oracle/00_install.sql"
}
```

Before #521 this same run said `ACCOUNT_MISSING` and exited 0. The account was
there, the tool just wasn't allowed to look.

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

**Run it twice and it stages again**, which is invariant 9 not applying rather
than being broken — drawing a fresh random secret has no state to converge on, so
the verb is outside the invariant (#454 restated it as a scope rule; `creds apply`
is the convergent half, and §10.3 is where you watch it report `changed: false`).
The run says so rather than leaving you to notice:

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

#### A standby, which is refused before the login

Open a window as above, then make the PDB read-only. That is the tier-1 stack's
closest stand-in for a physical standby:

```bash
printf "alter pluggable database FREEPDB1 close immediate;\nalter pluggable database FREEPDB1 open read only;\nexit\n" \
  | docker exec -i sopuli-test-oracle-free-1 sqlplus -S "/ as sysdba"
```

(From Git Bash, prefix `docker exec` with `MSYS_NO_PATHCONV=1`, or the `/`
arrives as a Windows path.)

```
ACCOUNT          TARGET    WINDOW
acme_batch_user  free-pdb  open, 59m left

ACCOUNT          TARGET    STATE  DETAIL
acme_batch_user  free-pdb  ERROR  the database is open READ ONLY and cannot end a window; point the target at the primary

nothing closed, 1 failed
```

The exit code is 1, and `--dry-run` refuses in the same words. Before #521 a real
run spent its one login and then sent the `ALTER USER`, which came back
`ORA-16000`. Worse, a preview said `would end this window, 59m early` about a
close that could only fail. Put the PDB back with `open read write` in place of
`open read only`, and the same command closes the window.

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

## 10a. The UC-2 verbs

Four exist: `account reset-password`, `account expire-password`, `account
suspend` and `account list`.

`reset-password` is built on **two** paths now: the seen one (`manual`, #441) and
the default unseen one (`vault_wrapped`, #444). The other four unseen methods are
#445-#447 and `smtp_encrypted`, and a file naming one of those is refused at plan
time rather than after the password has changed.

They are worth testing in that order, because they fail in opposite directions and
the guards are almost disjoint. `manual` prints a working password and lives under
five guards; `vault_wrapped` prints a *token* and lives under three rules, one of
which is the absence of a guard the seen path has.

**#454 is what decides what a retry does**, and it is worth knowing before you run
anything twice: **there is no re-run that quietly does nothing.** A second reset
draws a second password, and whoever holds the first now holds one that fails.

### `account reset-password` — the seen path

The configuration needs three things: a `personal_accounts:` entry declaring the
account, a policy to draw from, and a `delivery:` block selecting `manual`.

```yaml
personal_accounts:
  - accounts: [acme_dev_alice]
    policy: personal-standard

delivery:
  method: manual
  manual:
    force_expire: true
```

Make the account first:

```sql
CREATE USER acme_dev_alice IDENTIFIED BY "Old-Pa55word-Alice1";
GRANT CREATE SESSION TO acme_dev_alice;
```

#### The preview, which reaches the database and changes nothing

```bash
sopuli --config manual.yaml account reset-password --account acme_dev_alice --dry-run
```
```
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT         TARGET    INTENT        SECRET
acme_dev_alice  free-pdb  password_set  -

ACCOUNT         TARGET    STATE  WAS   DETAIL
acme_dev_alice  free-pdb  RESET  OPEN  declared by accounts 'acme_dev_alice'; would be reset

would reset acme_dev_alice on 1 of 1 targets
```

Exit 0. Three things to read out of it. `SECRET` is `-` because nothing masters a
personal account's password — there is no vault document, which is the first way
UC-2 differs from UC-1. `WAS` is the account status *before* anything would be
issued. And the preview **works without a terminal**, which is deliberate: the
guards below protect an emission, and a preview emits nothing.

That last one is worth causing on purpose, because it was a bug: the first build
of this verb reset the password under `--dry-run` and then aborted at the prompt,
leaving the account expired with a password nobody had seen. Check it yourself —
run the preview, then look at `ACCOUNT_STATUS`. It must still be `OPEN`.

#### Doing it

At a terminal, because it will not run anywhere else:

```bash
sopuli --config manual.yaml account reset-password --account acme_dev_alice
```
```
show the new password for acme_dev_alice on free-pdb on this terminal? [y/N]: y
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT         TARGET    INTENT        SECRET
acme_dev_alice  free-pdb  password_set  -

ACCOUNT         TARGET    STATE  WAS   DETAIL
acme_dev_alice  free-pdb  RESET  OPEN  declared by accounts 'acme_dev_alice'

reset acme_dev_alice on 1 of 1 targets

password for acme_dev_alice, shown once:

    <the password, on a line of its own>

It is expired: the owner must change it at first logon, which is what ends
your sight of it. It is not stored anywhere and will not be shown again.
```

**The password in that sample is substituted and nothing else is.** The run was
real — against 26ai in the tier-1 stack, on an account dropped afterwards — and
the value it printed is left out on purpose: a document that shows something
shaped exactly like a working credential teaches the wrong reflex, and the shape
of the output is what this sample is for.

The account is `EXPIRED` afterwards, and the password **works**: logging in with
it answers `ORA-28001`, which is Oracle's change-at-logon flow rather than a
refusal. `ORA-01017` would mean it did not work at all. That distinction is the
whole of UC-2 §5, and it is what makes the exposure time-limited — the owner's
first logon ends it.

#### What the journal then holds

Everything above runs without a `reset_records:` block, and every one of those
runs ends with a note saying what that costs:

```
1 note:
  no `reset_records:` block is declared, so no record of this reset will be written and no advisory lock is taken on the account: the run document and the database are the whole record of it
```

`SOPULI-W024`, raised at **plan time** — before the password changes, so an
operator who did not mean to run this way can still stop. It fires under
`--dry-run` too, which is the cheapest way to see it. It is a warning and never
a refusal: the seen path may have no store at all, and that is the site `manual`
exists for.

Declare one — the `reset_records:` block below in this section, with the
`vault-dev` store from §6 — and run the reset again:

```yaml
reset_records:
  vault: vault-dev
  prefix: sopuli/personal-resets
```

The note goes away, and there is now something to go and look at:

```bash
vault kv get -mount=kv sopuli/personal-resets/free-pdb/acme_dev_alice
```
```
========= Data =========
Key               Value
---               -----
account           acme_dev_alice
by                map[host:dba-ws-4.example.com os_user:dba01 pid:17976]
correlation_id    404c461b-5308-4418-99f8-ea99e204ecb5
delivery          map[method:manual]
expired           true
reset_at          2026-09-21T16:22:15.673177Z
seen              true
target            free-pdb
```

**That is a real record from a real run** against the tier-1 stack, with `by`
anonymised — the host and user were this laptop's, and the vocabulary rule in
`CLAUDE.md` applies to a sample as much as to a fixture. Nothing else is
substituted.

Four things to read out of it:

- **`seen: true`, and no `delivery.to`.** The destination was a person, by a
  route the tool did not carry, so there is no location to record — and `seen`
  is the field that makes the absence mean something rather than look like
  missing data. **An unseen method carries both**, which is worth seeing beside
  it; the same account, reset through `vault_wrapped`:

  ```
  delivery          map[method:vault_wrapped to:EXAMPLEaccessor000000000]
  expired           false
  seen              false
  ```

  `to` is the wrapping token's **accessor** and never the token. The accessor
  names the hand-over in Vault's audit log and cannot perform it; the token can,
  and a journal readable by anyone who may know *that* a reset happened is the
  last place it belongs. `assert_no_secret` is given the token as well as the
  password since #444, so writing one here is an `AssertionError` rather than a
  matter of the writer having picked the right one of Vault's two return values.
  `expired: false` is the other half of the path showing through: nothing needs
  expiring when nobody but the owner was ever meant to know the value.
- **No password, in any representation.** Not the value, not a hash, not a
  verifier. There is no field one could go in, and `assert_no_secret` checks the
  serialised document on the way out rather than trusting the writer.
- **`correlation_id` joins it to the run** that produced it, and `by` says which
  runner — the lock record's own shape, so a reader who has learned one has
  learned both.
- **`reset_at` is the tool's moment, not the database's.** The database stays
  authoritative for *when the password last changed* (UC-2 §3.2), and on this
  path it is designed to go stale: the owner must change the password at first
  logon, and the tool never sees that.

Run it twice and the record is overwritten, which is the second run reporting
`changed: true` doing what it says.

#### The lock on that same path

Two DBAs resetting the same person at the same moment is the collision UC-2
§3.3 exists to stop: the second password overwrites the first before the person
has fetched either, and neither DBA finds out. Since #512 the reset takes an
advisory lock keyed on the **record's own path** — the one location that exists
on every delivery path — with the `locks/` prefix, the compare-and-set and the
fencing token that `creds rotate` has always used.

You can watch it being taken and let go. After a reset:

```bash
vault kv get -mount=kv locks/sopuli/personal-resets/free-pdb/acme_dev_alice
```
```
========= Data =========
Key               Value
---               -----
acquired_at       2026-09-21T18:18:34.665634Z
command           account reset-password
correlation_id    4575ac3a-5f90-4c18-9c0e-c873ecd95dfc
expires_at        2026-09-21T18:33:34.665634Z
holder            map[host:dba-ws-4.example.com os_user:dba01 pid:17336]
state             released
```

`released`, not deleted, and not absent: a KV v2 delete leaves the version
counter behind, after which no first acquisition can ever compare-and-set
against version 0 again — and that counter *is* the fence (#83). `by` is
anonymised here as above; nothing else is.

**Cause the collision on purpose.** Write somebody else's claim straight into
Vault, at the same path, with an expiry far enough away that nothing about this
is about expiry:

```bash
vault kv metadata put -mount=kv -cas-required=true   locks/sopuli/personal-resets/free-pdb/acme_dev_alice
vault kv put -mount=kv -cas=<current version>   locks/sopuli/personal-resets/free-pdb/acme_dev_alice   state=held command="account reset-password" correlation_id=01JTHEIRS   acquired_at=2030-01-01T12:00:00Z expires_at=2030-01-01T12:15:00Z
```

The `-cas-required=true` matters: a lock path created without it is refused by
the manager's own pre-flight with exit **5** (#390), which is a different
failure and not the one you are trying to see. Then run the reset:

```
sopuli: vault-dev:sopuli/personal-resets/free-pdb/acme_dev_alice is locked by dba02@dba-ws-9.example.com pid 8821 running account reset-password
  hint: wait for it to finish, or coordinate with whoever is running it
```

Exit **7**, and **nothing was issued** — the lock is taken before the run
connects to a database, so the person's old password still works and there is
nothing to explain. Check `ACCOUNT_STATUS` afterwards to prove it.

`sopuli lock break vault-dev:sopuli/personal-resets/free-pdb/acme_dev_alice`
clears it, exactly as it clears a UC-1 lock, and refuses a live claim without
`--force`:

```
sopuli: vault-dev:sopuli/personal-resets/free-pdb/acme_dev_bob is held by an unknown holder running account reset-password and has not expired
  hint: wait for it to finish, or coordinate with whoever is running it. `--force` breaks a lock that is still live -- the holder is fenced and stops at its next check, having applied whatever it applied
```

**`sopuli lock status` shows these locks since #514, and the way it finds them is
the interesting part.** Its estate comes from `applications:` and `accounts:` —
the secret documents UC-1 locks — and no binding produces a record path, so
between #512 and #514 a configuration whose only locks were UC-2's reported `no
lock paths are declared` while one was held. Extending that estate would not have
worked either: a personal account declared by *predicate* has no name until a
database is asked, and this verb asks none. So it lists the declared
`reset_records:` prefix instead and reports what is actually there.

Plant the claim above and ask:

```bash
sopuli --config manual.yaml lock status
```
```
config: manual.yaml
mode:   cas

personal-account resets, under the prefix this config declares:
LOCK                                                      STATE  HOLDER   COMMAND           SINCE                 EXPIRES
vault-dev:sopuli/personal-resets/free-pdb/acme_dev_alice  held   unknown  account reset...  2030-01-01T12:00:00Z  2030-01-01T12:15:00Z

1 reset lock under the declared prefix (1 held)
```

Exit 0 — a held lock is a finding, not a failure. `HOLDER` is `unknown` because
the recipe above writes no `holder` key, which is the same reason `lock break`
says so two paragraphs up; a claim the tool itself took names the host, the pid
and the user.

**Three things in that output are deliberate.** The table is a *third* one, beside
the declared locks and the leftovers, because a reset lock is neither: it is this
estate's, so calling it a leftover would say a colleague's reset belongs to
somebody else's configuration, and it was discovered rather than enumerated, so
listing it with the bindings would imply the file names it. The summary counts it
in its own clause and **not** as a proportion — there is no denominator, because
the paths under the prefix cannot be counted without resolving a predicate
against a database. And the `LOCK` cell is no longer truncated at 52 characters,
which it had been since #105: the full key is what `lock break` takes, and a
reset key is long enough (`<prefix>/<target>/<account>`) that every row was cut.

In JSON it is one `found[]` entry with the field that carries the distinction:

```bash
sopuli --config manual.yaml lock status --output json | jq '.lock.found[]'
```
```json
{
  "vault": "vault-dev",
  "path": "sopuli/personal-resets/free-pdb/acme_dev_alice",
  "held": true,
  "declared": true,
  "declared_by": "reset_records",
  "state": "held",
  "expired": false,
  "version": 1,
  "acquired_at": "2030-01-01T12:00:00Z",
  "expires_at": "2030-01-01T12:15:00Z",
  "holder": {
    "host": null,
    "pid": null,
    "os_user": null,
    "correlation_id": "01JTHEIRS",
    "command": "account reset-password"
  }
}
```

`declared_by` is new in schema **1.28** and is `binding` for a rotation lock,
`reset_records` for this one, and `null` for a leftover. `declared` stays a
boolean and now means "this configuration accounts for the path at all", which is
what a consumer filtering its own locks was already asking it.

Break it and ask again, which is the shape you see after an ordinary reset:

```bash
sopuli --config manual.yaml lock break vault-dev:sopuli/personal-resets/free-pdb/acme_dev_alice --force --confirm
sopuli --config manual.yaml lock status
```
```
personal-account resets, under the prefix this config declares:
LOCK                                                      STATE     HOLDER   COMMAND           SINCE                 EXPIRES
vault-dev:sopuli/personal-resets/free-pdb/acme_dev_alice  released  unknown  account reset...  2030-01-01T12:00:00Z  2030-01-01T12:15:00Z

1 reset lock under the declared prefix (0 held)
```

`released`, still listed, and `(0 held)` — the record stays because the version
counter is the fence, and the survey reports what is there rather than only what
is in the way.

**The empty answer says which empty it is**, and that distinction is the whole
reason #514 was a bug rather than a missing feature. With the claim cleared:

```
no lock paths are declared, and nothing is held under the reset-record prefix
```

Take `reset_records:` out of the file and the same estate says only `no lock paths
are declared`. One of those sentences means *I looked and it is quiet* and the
other means *there was nowhere to look*, and before this they were the same
sentence.

**A journal store that cannot be reached now fails this verb**, which is new and
is the same answer a binding's store has always got. Point `reset_records.vault`
at a second `vaults:` entry on a dead port:

```
sopuli: could not reach the store: [WinError 10061] No connection could be made because the target machine actively refused it
  hint: check `addr`, and `tls.ca_file` if the certificate is your own CA
```

Exit 1. Answering *what is held* without contacting the store the locks live in
would be a false negative, which is the bug this section is about — so the store
being unreachable is a failure rather than a quiet gap. Note the difference from
the `SOPULI-W005` warning above it: that one is a store which cannot **list** at
all, a permanent property reported without failing, because refusing there would
cost the operator the report for every other store too.

**A preview takes no lock**, which is invariant 8 read for the lock: a
`--dry-run` that left a claim in the vault would block the run it was
previewing.

### `account reset-password` — the unseen path (`vault_wrapped`)

The default method, and the one the tool exists to make possible: a DBA resets a
password without ever seeing it. Swap the `delivery:` block for this one — the
`vault-dev` store from §6 is already there, and `vault_wrapped:` names no `vault:`,
so it takes §3's chain and lands on `defaults.vault`:

```yaml
delivery:
  method: vault_wrapped
  vault_wrapped:
    ttl: 15m
```

```bash
sopuli --config wrapped.yaml account reset-password --account acme_dev_alice
```
```
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT         TARGET    INTENT        SECRET
acme_dev_alice  free-pdb  password_set  -

ACCOUNT         TARGET    STATE  WAS   DETAIL
acme_dev_alice  free-pdb  RESET  OPEN  declared by accounts 'acme_dev_alice'

reset acme_dev_alice on 1 of 1 targets

hand this to acme_dev_alice for free-pdb; it unwraps once:

    hvs.EXAMPLE-not-a-real-token-AAAAAAAAAAAAAAAAAAAAAAAA

It stops working at 2026-09-22T10:21:00.953243Z, and the first unwrap is the
last. Do not unwrap it to check -- that spends the person's one read, and
them finding it spent is the only warning either of you gets.
```

**The plan also went to stderr**, before anything was issued, which that capture
does not show because it is stdout. Both streams carry it on a real run: stdout
because the plan is part of the result, and stderr because the plan has to survive
a run that raises part way through — a multi-target reset that fails on target
three never builds the returned string at all, and the operator would otherwise be
left with no record of what it had been about to touch. `--dry-run` echoes it once,
to stdout, because a preview mutates nothing for an early copy to outlive.

**The token above is substituted and nothing else is.** The run was real, against
the tier-1 stack, and the value it printed is replaced here for the reason the
password is in the seen path's sample and then some: a response-wrapping token *is*
a credential that retrieves a password (UC-2 §6.1), and committing one to a
repository is committing material pulled from a real environment. What this sample
is for is the shape.

**That run was redirected to a file**, which is the first thing to notice: it is
the state `manual` refuses with exit 8. An unseen delivery is allowed a pipe on
purpose — `| mail` is how a handover works — and the cost is stated rather than
hidden, because a redirect outlives the token's TTL. What makes it a different
trade from `manual`'s is the object: fifteen single-use minutes whose one use is
detectable, against a password good until somebody's first logon.

**No prompt, either.** The seen path asks every time and `--confirm` cannot answer
it; there is nothing to ask here, because nobody is being shown a password.

**The heading names the target, and that was a defect worth knowing about.** Drop
`--target` on an estate with several and the verb resets the account on every one,
drawing a *separate* password for each — so you get one block per target, and until
the code review of #518 they were identical apart from the token. Sending somebody
the wrong one hands them a password that does not work on the host you named. The
cubbyhole itself always carried the target, so the person unwrapping could tell;
the DBA holding three tokens could not.

#### Fetch it, and then fail to fetch it again

```bash
vault unwrap -format=json <the token>
```
```json
{
  "data": {
    "account": "acme_dev_alice",
    "password": "<24 characters>",
    "target": "free-pdb"
  }
}
```

The `account` and `target` are in the cubbyhole so that somebody sent two tokens
does not have to guess which is which. **The password is substituted here and
nothing else is**, for the reason the seen path's sample says: a document showing
something shaped exactly like a working credential teaches the wrong reflex.

Now do it again:

```
Error unwrapping: Error making API request.

URL: PUT http://127.0.0.1:8200/v1/sys/wrapping/unwrap
Code: 400. Errors:
```

**That failure is the whole promise of the method.** Single use does not prevent
interception; it makes it *detectable*. If the person's own unwrap fails, somebody
else has already read it — and that is the only warning either of them gets, which
is why the output tells the DBA not to unwrap it to check.

**Log in with what you fetched, and check `ACCOUNT_STATUS`.** It is `OPEN`, not
`EXPIRED`: expiry is what ends the *seen* path's exposure, and on this path nobody
but the owner is meant ever to know the value, so there is nothing to end.

#### `--output json`, and where the token goes

```bash
sopuli --config wrapped.yaml account reset-password --account acme_dev_alice --output json > run.json
```
```
hand this to acme_dev_alice for free-pdb; it unwraps once:

    hvs.EXAMPLE-not-a-real-token-AAAAAAAAAAAAAAAAAAAAAAAA

It stops working at 2026-09-22T10:21:35.594645Z, and the first unwrap is the
last. Do not unwrap it to check -- that spends the person's one read, and
them finding it spent is the only warning either of you gets.
```

That went to **stderr**, and `run.json` is a clean document:

```bash
jq '.results[0] | {delivered, handover}' run.json ; grep -c 'hvs\.' run.json
```
```json
{
  "delivered": "vault_wrapped",
  "handover": {
    "accessor": "EXAMPLEaccessor000000000",
    "expires_at": "2026-09-22T13:07:34.882513Z"
  }
}
0
```

**Three things there are deliberate.** `--output json` is *not* refused, unlike on
the seen path — the document is what makes a scheduled reset auditable, and taking
it away would make an estate choose between an audit trail and the default delivery
method. The token is not in it, and there is no property that could hold one: a
document is captured, shipped to log aggregation and kept, and a token in one
outlives the TTL that is this method's guarantee. And so it goes to stderr, which
is the split this verb already makes for the plan and the confirmation prompt —
stdout carries the result, and here the result is the document.

**`handover.accessor` is the half of Vault's answer that cannot fetch anything.**
Vault returns two values beside a wrapped password: the token, which produces the
password in anybody's hands, and the accessor, which names the wrap in the audit
log and produces nothing. The document carries the second and has no property for
the first — so a scheduled reset stays auditable, and `grep` for `hvs.` still
answers `0`. The accessor above is substituted; everything else in that block is
what the run printed.

`handover.expires_at` is the store's own clock, not this host's: Vault's
`creation_time` plus the TTL it actually applied, which a mount's `max_ttl` may
have cut below what the file asked for. It is reported and never enforced — nothing
here polices a TTL Vault is already policing.

#### Telling the person a password is waiting

`notify:` nests inside `delivery:` and is the **low-trust** half of UC-2 §6: it says
that a password is ready, never what it is. Built in #442, and it needs its own
install extra:

```bash
pip install -e '.[oracle,hashicorp,notify]'
```

**`[notify]` rather than reusing `[hashicorp]`**, although both install `httpx`: an
estate on OCI Vault that wants a chat message should not install a HashiCorp extra
to get one, because ADR-006's whole point is that an extra names *why* a dependency
is there (E7). Without it the block still validates — a missing client is E4/E5's
case, not a broken configuration — but a reset refuses before it changes anything
([below](#without-the-extra-installed)).

```yaml
delivery:
  method: vault_wrapped
  vault_wrapped:
    ttl: 15m
  notify:
    method: webhook
    webhook:
      url: { env: SOPULI_NOTIFY_WEBHOOK }
      template: "{account} on {target} has a new password waiting"
```

#### Watch one arrive

You do not need a chat service. Run something that prints what it is posted:

```bash
python - <<'EOF' &
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        print("POSTED to", self.path, flush=True)
        print(json.dumps(json.loads(body), indent=2), flush=True)
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 8477), H).serve_forever()
EOF
export SOPULI_NOTIFY_WEBHOOK=http://127.0.0.1:8477/hooks/T00/B00/EXAMPLE
sopuli --config wrapped.yaml account reset-password --account acme_dev_alice
```

The listener prints:

```
POSTED to /hooks/T00/B00/EXAMPLE
{
  "text": "acme_dev_alice on free-pdb has a new password waiting"
}
```

**Read what is not in that body.** No password, no wrapping token, no accessor, and
no second key: the body is `{"text": ...}` and nothing else, so a low-trust channel
cannot accumulate the shape of an estate. `{account}` and `{target}` are there
because the template asked for them.

#### When the channel is down

Stop the listener and run the same reset again. **Exit 0**, the password is
delivered, and:

```
2 notes:
  no `reset_records:` block is declared, so no record of this reset will be written and no advisory lock is taken on the account: the run document and the database are the whole record of it
  the password for acme_dev_alice on free-pdb was delivered and the notification could not be sent, so nobody has been told it is waiting -- tell them another way today and look at `delivery.notify.webhook.url` afterwards: the webhook could not be reached: ConnectError
```

**The target is in that sentence, and it was not in the first build** (#520). One
reset reaches every declared target and notifies once per target, so two failures
out of three produced two identical notes and no way to tell whose person had not
been told. The same defect #519 found in the hand-over block, one object over.

`SOPULI-W026`, and a warning rather than a failure for `SOPULI-W025`'s reason and
more easily: by the time anything is posted the password has changed and the person
can fetch it, so ending the run would report a false negative about the part that
mattered. What is lost is that somebody has to be told another way, which is what
the note says to do.

**The URL is not in that message**, and that is deliberate rather than incidental:
`httpx` puts it in the text of several of its own errors, and the URL *is* the
credential — so a warning built from the exception's message would put a live chat
webhook into `diagnostics[]`, a run document, and whatever ingests them. What is
carried is the exception's class name.

**Two things about producing that sample, because both nearly became wrong entries
in this guide.** `pkill -f listener.py` does not stop a background Python on
Windows, so the run that was supposed to fail succeeded and the absent warning
looked like a bug in the tool — use `Stop-Process` and check the port. And `tail -6`
of the output shows the hand-over block, not the note: notes print *before* it, so
look for the note by name rather than at the end.

#### Without the extra installed

Uninstall `httpx` — or read this and take it on trust, because the dev environment
has it for the HashiCorp store. `config validate` says:

```
delivery.notify.method: `delivery.notify.method: webhook` is configured and its client is not installed, so nothing can send through it (pip install "sopuli-dba[notify]")
    hint: the block is valid and this build cannot send through it. `account reset-password` refuses rather than resetting without notifying -- before the password changes -- so install the client or take `delivery.notify` out of the file. `config validate` warns instead of failing because it is the question *is this file usable here*, and the answer is yes everywhere but this block
```

To produce it without uninstalling anything, hide the module from the lookup —
`installed()` asks `importlib.util.find_spec`, which answers `None` for a
`sys.modules` entry set to `None`:

```bash
python -c "import sys; sys.modules['httpx']=None; sys.argv=['sopuli','--config','sopuli.yaml','config','validate']; from sopuli.cli import main; main()"
```

The first wording ended "so nothing will be sent when a password is delivered",
which promised a delivery that the refusal below no longer makes (#520).

Exit 0, and it is **separate from the delivery method's** warning on purpose: an
estate can have a working delivery and an inert notification, and one sentence
covering both would say only that something in the block does not work.

**A reset then refuses, at exit 9, and does not change the password** (#520). The
first build ran it, delivered, and raised `SOPULI-W026` — the same note as an
unreachable webhook, on the argument that from the person's side it is the same
outcome. It is not: an unreachable webhook is news that arrives after the password
has changed and there is nothing better to do with it, while a client that is not
installed is knowable before the run connects to anything. That is invariant 4, and
E5's contract that configured-but-uninstalled fails use with exit 9:

```
sopuli: notify method 'webhook' needs a client this machine does not have
  hint: pip install "sopuli-dba[notify]" -- or take `delivery.notify` out of the file if nobody should be told. The reset is refused rather than run without the notification, because it is refused *before* the password changes and running it would leave somebody holding a credential nobody told them about
```

**Two things about reproducing that, because neither is obvious.** The output above
came from a `--dry-run`, which resolves the channel on purpose — telling you the
client is missing is among the things a preview is for, and it is the one place this
deliberately does *not* mirror the delivery backend, which a preview skips because
opening a store would demand credentials the preview does not need.

And `[notify]` and `[hashicorp]` both supply `httpx`, so you cannot see this on the
default unseen path by uninstalling it: the HashiCorp store needs the same client and
refuses first, with `SOPULI-20001` naming `vault-dev`. The configuration where
`[notify]` is the only thing that supplies it is `manual` delivery with a notify
channel, which is what the sample above ran.

**The URL is resolved there too**, which went further than the review asked. An
absent environment variable is a configuration error rather than news, so it is
answered in the same place:

```
sopuli: delivery.notify.webhook.url: the environment variable SOPULI_NOTIFY_WEBHOOK is not set
  hint: an empty value counts as unset (§6). Check the name, and that whatever exports it runs in the same process tree as this command
```

Exit 9, and the account is untouched.

#### Three templates that look fine and are not

**Found by Copilot on #520, and all three were holes in this guide's own claim**
that a template is proved renderable at load. They passed validation and raised
inside `render()` — which happens *after* the password has changed, and is the one
moment UC-2 §6 has no answer for. `Formatter().parse()` hands back the format spec
and the conversion separately, and the walk was discarding both; it also called
`.strip()` on a name that `str.format` does not strip.

```yaml
      template: "fetch it before {expires_at:%Y}"
```
```
sopuli: t.yaml: delivery.notify.webhook.template: a notify template may not give {expires_at} a format spec
  hint: `{expires_at:%Y}` would be applied to a string and raise when the message is rendered -- which is after the password has changed. Every substitution is already formatted the way the run document formats it, so write `{expires_at}`
```

```yaml
      template: "{ account } has a new password"
```
```
sopuli: t.yaml: delivery.notify.webhook.template: a notify template may not pad a placeholder with spaces: { account }
  hint: `str.format` looks up the name exactly as written, spaces included, so `{ account }` would raise when the message is rendered -- which is after the password has changed. Write `{account}`
```

```yaml
      template: "{account!r} has a new password"
```
```
sopuli: t.yaml: delivery.notify.webhook.template: a notify template may not give {account} a conversion
  hint: `{account!r}` converts a value that is already a string. Write `{account}`
```

Exit 9 for each. **The middle one is refused rather than trimmed**, which is the
decision worth knowing: accepting `{ account }` would mean this validator and
`str.format` read the same file differently, and the estate wrote the file, so the
file is what should say what it means. The third does not raise at render at all —
`!r` merely quotes a string that is already one — and is refused anyway, because the
closed set is about what a template may *ask for*, and a conversion is a second
spelling of one placeholder.

#### The refusal that is the point of the whole block

**A template may not name the secret, or anything that fetches it.** Try the thing
everybody will try first:

```yaml
      template: "your new password is {wrap_token}"
```
```
sopuli: notify_secret.yaml: delivery.notify.webhook.template: a notify template may not reference {wrap_token}
  hint: UC-2 6.1: the channel that notifies may be low-trust and the channel that carries the secret may not -- and that covers the password *or anything that retrieves it*, because the rule is about reach rather than value. Say that a password is ready and let the person fetch it: available: `{account}`, `{target}`, `{expires_at}`
```

Exit 9, **at load** — before a password has been drawn, which is the only time a
refusal about a template is any use. `{wrap_token}` is worth trying specifically
because #442 proposed it as a placeholder before §6.1 settled the question, so it
is the mistake the design itself nearly made.

**The guard is the closed set, not that word.** Try a name nobody has ever listed:

```yaml
      template: "hello {full_name}"
```
```
sopuli: notify_unknown.yaml: delivery.notify.webhook.template: unknown placeholder {full_name} in the notify template
  hint: available: `{account}`, `{target}`, `{expires_at}`. An unknown name is refused rather than left empty, because a message with a hole in it is one somebody has to go and diagnose. Write `{{` for a literal brace
```

Same exit, different message, and the difference is the whole design: `{full_name}`
is refused because it is *not in the allowed set*, not because it is on a forbidden
list. A blocklist would have let `{wrapping_token}` through. The list of named
secrets exists only to make the first message better than the second one.

Worth doing both, because the second refusal is the one that proves the first is not
load-bearing.

#### A URL is named, not written

```yaml
      url: https://chat.example.com/hooks/T00/B00/XXXX
```
```
sopuli: notify_literal.yaml: delivery.notify.webhook.url: a webhook URL is named, not written here
  hint: write one of `env:`, `file:` -- e.g. `{ env: SOPULI_NOTIFY_WEBHOOK }`. P2: the config points at where the material comes from, never at the material itself
```

Exit 9. A chat incoming-webhook URL **is** a credential — the path segments are the
token — so a literal one is a credential in a file people commit. That is C9, and
it also answers something #442 asked for separately: the URL is redacted wherever
the configuration is shown, and it is redacted *structurally*, because the model
holds a location and never a value. There is nothing to redact.

**That message used to say "auth material" and suggest `SOPULI_VAULT_SECRET_ID`.**
The reader is shared with every `auth:` block, and #442 is the first caller that is
not one — so it now takes the noun and the example from its caller. Somebody who
pasted a chat URL should not be told about a vault secret id.

#### Failures worth causing on purpose

**A `num_uses` key.** Reach for the thing you already have:

```yaml
delivery:
  method: vault_wrapped
  vault_wrapped:
    ttl: 15m
    num_uses: 1
```
```
sopuli: wrapped.yaml: delivery.vault_wrapped.num_uses: `vault_wrapped` takes no `num_uses`
  hint: a Vault response-wrapping token is single use by construction -- the unwrap is the last read, and that is what makes interception detectable (UC-2 6.6). There is no counter to set, so the key is refused rather than accepted and ignored
```

Exit 9. Refused rather than accepted and ignored, because a file that sets it reads
as an estate having chosen something.

**A TTL that is not a duration**, and this one has two answers worth seeing rather
than one. Unquoted, YAML hands the tool a number:

```
sopuli: wrapped.yaml: delivery.vault_wrapped.ttl: must be a string, not a number
```

Quoted, it reaches the duration check:

```
sopuli: wrapped.yaml: delivery.vault_wrapped.ttl: ttl '15' is not a duration
  hint: digits and one unit -- `s`, `m` or `h`, as in `15m`. The value is passed to Vault rather than interpreted here, so an unparseable one would otherwise fail with a 400 after a password had already been drawn
```

Both exit 9 at load, and `"0m"` and `"fifteen minutes"` get the second. Worth
causing both, because the first sample in this section was written as a prediction
and said the *second* message — `ttl: 15` is the spelling somebody will actually
type, and it is a type error before it is ever a duration error. The shape is
checked here and the grammar stays Vault's, which is what keeps the two from
disagreeing about what `90m` means.

**A delivery with nowhere to deliver.** Take `vault:` off the target *and*
`defaults.vault` out, leaving `vault_wrapped:` naming none either:

```
sopuli: wrapped.yaml: delivery.vault_wrapped.vault: `delivery.method: vault_wrapped` has no store to deliver into
  hint: name one under the method, on the target, or as `defaults.vault` -- the same chain a secret ref walks. A store is not guessed at, because the wrong one would hand somebody else's vault a working password
```

Exit **8**, before anything connects — the chain is knowable from the file. Note
what it does *not* fall back to: `reset_records.vault` is still set in that file
and is not used, because §3.5 keeps the journal and the delivery target apart.

**A store that cannot wrap.** Point the delivery at a non-HashiCorp entry and it is
refused with exit 5, naming the store: response wrapping is a Vault feature with no
equivalent elsewhere, so there is nothing to degrade to. **Before the DDL**, which
is invariant 4 and was a bug in the first build of this — the backend used to be
resolved inside the per-target loop, so an estate that could never have delivered
found out after a password had been drawn. You cannot cause this one against the
tier-1 stack, which has only HashiCorp stores; it is
`test_a_store_that_cannot_wrap_is_refused_before_the_ddl`'s.

**A one-second TTL.** `ttl: 1s` is legal and nothing stops you configuring a
handover nobody can catch. Worth doing once, because it is the cheapest way to see
the expiry failure — and worth remembering that the tool will not argue with you
about it.

#### A journal that cannot be written

Worth causing on purpose, because the rule is the opposite of this codebase's
usual reflex. Point the store at a mount that is not there:

```yaml
vaults:
  vault-dev:
    mount: kv-that-is-not-there
```
```
1 note:
  the password was reset and its record at sopuli/personal-resets/free-pdb/acme_dev_alice could not be written, so the run document and the database are the whole record of it: the store answered HTTP 404 at 'sopuli/personal-resets/free-pdb/acme_dev_alice': no handler for route "kv-that-is-not-there/data/sopuli/personal-resets/free-pdb/acme_dev_alice". route entry not found.
```

Exit **0**, and the password is printed as usual. `SOPULI-W025` is a warning on
a **successful** run: the password has already changed and the person still
needs it, so failing here would report a false negative about the part that
mattered. It is a separate code from `SOPULI-W024` because the next move
differs — an absent journal is a configuration somebody chose, and this is a
store to go and look at.

The one thing that *is* refused is a record path that cannot be derived. A `/`
in a target name would put two different (target, account) pairs at one path:

```
sopuli: no reset record path for acme_dev_alice on tier1/oracle: target 'tier1/oracle' cannot be a record path component: a `/` in it would derive the same record path as a different target and account
  hint: the record is one per (target, account) under `reset_records.prefix` (sopuli/personal-resets), so each name has to be a single path segment
```

Exit **9**, at plan time, before anything connects — and under `--dry-run` too,
because it is about what the configuration says rather than about an emission.

#### Six failures worth causing

Each has its own exit code, and a script branching on them wants them apart:

```bash
sopuli --config manual.yaml account reset-password --account acme_dev_alice --output json
```
```
sopuli: `delivery.method: manual` cannot be used with --output json or --output jsonl
  hint: json is what gets captured and shipped to log aggregation, so a working password never appears in it -- use the text output, or an unseen delivery method
```

Exit **2**. Guard 2, and it is `policy sample --reveal`'s refusal one verb over:
the machine-readable format is the safe one, so it wins.

```bash
sopuli --config manual.yaml account reset-password --account acme_dev_alice | cat
```
```
sopuli: `delivery.method: manual` prints a password, and stdout is not a terminal
  hint: a value redirected to a file or captured in a CI log outlives the single logon it is good for, and expiry does not unpublish it. Run this at a terminal and read the password off the screen -- `| clip` and `| pbcopy` do not work here, deliberately -- or use an unseen delivery method
```

Exit **8**. Guard 3, the one the whole argument rests on. **There is no flag that
turns it off**, and that is a decision rather than an omission: a flag that exists
to weaken a guard ends up in scripts, which is the exact place this value must
never reach. `| clip` not working is the accepted cost.

```bash
sopuli --config manual.yaml account reset-password --account acme_dev_alice --confirm
```
```
sopuli: --confirm cannot answer the prompt `delivery.method: manual` asks
  hint: that prompt is not a formality to be waived: the run is about to print a working password to a screen, and a flag cannot establish that somebody is at it. Drop --confirm and answer it -- if that is impossible, nobody is there to receive the password either
```

Exit **2**. Guard 4, and the only gate in the tool that cannot be given a yes in
advance — `creds rotate` and `lock break` both take one.

The two usage errors are asked **before** the terminal check, which is also worth
knowing: a redirected run with `--confirm` is told about the flag rather than
about a terminal it was never going to have.

```bash
sopuli --config no-expire.yaml config validate
```
```
sopuli: no-expire.yaml: delivery.manual.force_expire: `manual` delivery needs `force_expire: true`
  hint: `manual` prints a working password to your terminal, and expiry at first logon is what ends that exposure -- so it is written down rather than assumed (UC-2 6.5). Use an unseen method if you do not want the account expired
```

Exit **9**. Guard 5, and the only one of the five that lives in the file. Writing
`force_expire: false` is refused in its own words rather than flipped:

```
sopuli: expire-false.yaml: delivery.manual.force_expire: `manual` delivery requires `force_expire: true`, not false
  hint: there is no unexpiring seen path: until the owner's first logon the password on your screen is a working credential, and expiry is the only thing that ends that. An unseen method delivers without expiring
```

The last two are about having somewhere to deliver at all, and both refuse
**before anything connects** — a reset that reached a database and then found
nowhere to put the password would have changed one nobody can be told:

```
sopuli: `delivery.method: one_time_link` is configured and is not implemented in this build
  hint: this build serves `manual` (#441) and `vault_wrapped` (#444); the methods still to come are #445-#447 and `smtp_encrypted`. `config validate` warns about this before a run needs it
```

Exit **5** — the capability code, because the file is not wrong. And with no
`delivery:` block at all:

```
sopuli: no `delivery:` is configured, so a new password would have nowhere to go
  hint: a reset hands a password to a person; without a delivery method there is nobody to hand it to. Configure `delivery:` (UC-2 6.2), or use `account expire-password` if what you want is to force a change
```

Exit **8**.

#### A reset that fails half way (#528)

A reset is up to three statements (UC-2 §4.1): unlock a timed lock, set the password,
close the rollover window. DDL commits as it goes, so when a later statement fails the
earlier ones have already happened. Cause the first case on purpose: a timed-locked
account on a profile whose verify function refuses every password, so the unlock
commits and the set is refused by the server. As `SYS`, in the PDB:

```sql
CREATE OR REPLACE FUNCTION sopuli_refuse_all
  (username VARCHAR2, password VARCHAR2, old_password VARCHAR2) RETURN BOOLEAN IS
BEGIN
  raise_application_error(-20001, 'no new password is acceptable on this profile');
END;
/
CREATE PROFILE sopuli_refusing LIMIT FAILED_LOGIN_ATTEMPTS 3 PASSWORD_LOCK_TIME 1/24
  PASSWORD_VERIFY_FUNCTION sopuli_refuse_all;
CREATE USER acme_dev_alice IDENTIFIED BY "Old-Pa55word-Alice1";
GRANT CREATE SESSION TO acme_dev_alice;
ALTER USER acme_dev_alice PROFILE sopuli_refusing;
```

Create the user first and move it onto the profile afterwards. The verify function
runs on `CREATE USER ... IDENTIFIED BY` too, so creating the account on that
profile fails with `ORA-28003`. Log in wrongly three times until `ACCOUNT_STATUS`
reads `LOCKED(TIMED)`, then reset, with `vault_wrapped` as the method:

```
ACCOUNT         TARGET    STATE  WAS            DETAIL
acme_dev_alice  free-pdb  ERROR  LOCKED(TIMED)  account was locked(timed); unlocked; then: ORA-28003: The password chosen did not meet the required complexity rules set by your organization.

acme_dev_alice was not reset on any of 1; 1 failed
```

Exit **4**, and **no token is printed**. The password is still the old one, so a
token would fetch a value that does not log in. Under `--output json` the row
says what did happen:

```json
{
  "state": "ERROR",
  "changed": true,
  "actions": [
    { "kind": "account_unlock", "applied": true, "detail": "account was locked(timed); unlocked" },
    { "kind": "password_set", "applied": false, "detail": "ORA-28003: The password chosen did not meet the required complexity rules set by your organization." }
  ],
  "account_status": "LOCKED(TIMED)",
  "error": {
    "category": "policy",
    "message": "ORA-28003: The password chosen did not meet the required complexity rules set by your organization.",
    "code": "ORA-28003",
    "hint": "the profile's password verify function refused this candidate; draw another. The server message usually carries an ORA-20000 saying which rule was broken"
  }
}
```

That is the row alone, with `account`, `target` and `duration_ms` left out.

Before #528 this row read `changed: false` with no actions, while the account was
now open. `ACCOUNT_STATUS` is `OPEN`, and the old password logs in. Run it again
and you get the ordinary failure: nothing is locked, so nothing commits before the
refusal, and the row goes back to `changed: false`.

The other case is the set committing and the window close failing. It cannot be
caused by hand on this stack, because nothing refuses `EXPIRE PASSWORD ROLLOVER
PERIOD` once `ALTER USER` has succeeded, so the test suite injects that failure
instead. There the password **is** handed over, and the record and the notification
follow, because the password is live and withholding it would leave a password
nobody holds. The row is still `ERROR` at exit 4, because the old password may work
until the window ends (UC-2 §6.4).

Clean up with `DROP USER acme_dev_alice CASCADE`, `DROP PROFILE sopuli_refusing` and
`DROP FUNCTION sopuli_refuse_all`.

#### The safety ratchet, refusing a method

`safety.delivery.allowed_methods` (§10b) now has the consumer #498 said would
arrive with the first delivery method. Narrow the set to something `manual` is
not in:

```yaml
defaults:
  safety:
    delivery:
      allowed_methods: [vault_wrapped]
```
```
sopuli: `delivery.method: manual` is not permitted here; `safety.delivery.allowed_methods` allows vault_wrapped
  hint: set at defaults.safety.delivery.allowed_methods; no layer can widen it (invariant 10), and --force does not reach a safety setting -- deliver by one of the permitted methods, or change the set where it is written
```

Exit **8**. Worth trying `--force` against it: it changes nothing, because
`--force` waives the *account* guardrails and never a safety setting. Worth
trying under `--dry-run` too — the refusal still fires, because it is about what
the run is configured to do rather than about an emission.

#### What is not built

- **Four of the six delivery methods.** `manual` is this section and
  `vault_wrapped` is [the unseen path](#account-reset-password--the-unseen-path-vault_wrapped);
  `vault_path`, `one_time_link`, `onepassword_share` and `smtp_encrypted` are
  refused at exit 5 as shown above (#445-#447).
- Nothing else on this path. `expire-password`, which forces a change without
  setting a password, has [its own section](#account-expire-password--make-them-change-it).

### The two other UC-2 verbs

`account suspend` locks an account, and `account list` reads the declaration and
shows you what it matched.

**What this verb does** is `ALTER USER "…" ACCOUNT LOCK` against an account
`personal_accounts:` declares — the offboarding case. The state it produces is
`LOCKED`, which is **not** the `LOCKED(TIMED)` a failed-login limit produces: that
one clears itself under `PASSWORD_LOCK_TIME` and this one does not.

Add a personal account to the file from §6, and make one in the database:

```sql
CREATE USER acme_suspend_demo IDENTIFIED BY "Aa1-demo-pw-00001";
GRANT CREATE SESSION TO acme_suspend_demo;
```

```yaml
personal_accounts:
  - accounts: [acme_suspend_demo]
    policy: personal-standard
```

### The preview, which reaches the database

```
$ sopuli account suspend --account acme_suspend_demo --dry-run
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT            TARGET        INTENT        SECRET
acme_suspend_demo  tier1-oracle  account_lock  -

ACCOUNT            TARGET        STATE   STATUS  DETAIL
acme_suspend_demo  tier1-oracle  LOCKED  OPEN    declared by accounts 'acme_suspend_demo'; would be suspended

would suspend acme_suspend_demo on 1 of 1 targets
```

**`SECRET` is `-` and that is the point**: nothing masters a personal account's
password, so the plan has no document to name. Every other verb in this guide
fills that column.

**A preview still connects.** Which account is declared here, what state it is in,
and which guardrail would stop it are the answers you ran a preview for, and none
of them can be had from the file.

### Doing it, then doing it again

```
ACCOUNT            TARGET        STATE   STATUS  DETAIL
acme_suspend_demo  tier1-oracle  LOCKED  OPEN    account was open; locked

suspended acme_suspend_demo on 1 of 1 targets
```

Run the identical command again:

```
ACCOUNT            TARGET        STATE   STATUS  DETAIL
acme_suspend_demo  tier1-oracle  LOCKED  LOCKED  the account is already locked

acme_suspend_demo was already locked on 1 of 1
```

**That second line is invariant 9, and it is worth causing on purpose**, because
the first version of this verb got it wrong in a way only running it twice
revealed: the closing line counted rows in state `LOCKED` rather than rows this
run changed, so a no-op re-run reported having suspended an account it had not
touched. A `LOCKED` row cannot say which of the two it is — `STATUS` is what does.

The JSON says it more precisely:

```json
{
  "account": "acme_suspend_demo",
  "target": "tier1-oracle",
  "state": "LOCKED",
  "changed": true,
  "actions": [
    { "kind": "account_lock", "applied": true, "detail": "account was open; locked" }
  ],
  "account_status": "OPEN",
  "duration_ms": 299
}
```

`account_status` is what the database said **before** anything was issued, which
is why the row above reads `OPEN` on the run that locked it.

### Failures worth causing

| Try | What you get |
|---|---|
| omit `--account` | usage error, exit **2**: this verb acts on exactly one account and will not resolve a set |
| `--account system` | exit **0**, state `SKIPPED` — see below |
| an account the file does not declare | the same `SKIPPED`, naming the whitelist |
| `--select env=nosuch` | `Plan: 0 accounts x 0 targets = 0 accounts`, then `nothing to suspend`, exit **0** |

`--account system` is the one to run, because it fires three guardrails at once
and prints all three:

```
ACCOUNT  TARGET        STATE    STATUS  DETAIL
system   tier1-oracle  SKIPPED  OPEN    the config does not declare this account, and no flag extends the whitelist; the database reports this account as its own; the account holds DBA

system was not suspended on any of 1
```

**Exit 0, not a failure**, and that is deliberate: `SKIPPED` is the guardrails
doing their job, and a scheduled caller should not be paged because somebody asked
a reasonable question and got a correct refusal. Only an unreachable target sets
exit 4.

**`--force` waives the last two and never the first**, which is worth running
because it is invariant 5's own sentence and you can watch it hold. Add `--force`
to the same command and two of the three refusals disappear:

```
ACCOUNT  TARGET        STATE    STATUS  DETAIL
system   tier1-oracle  SKIPPED  OPEN    the config does not declare this account, and no flag extends the whitelist

system was not suspended on any of 1
```

`SYSTEM` is still `OPEN` afterwards — check it. A waived check is recorded in
`results[].overridden`, so a document can say somebody did it on purpose; the
whitelist is not waivable and so never appears there.

### `account expire-password` — make them change it

**What this verb does** is `ALTER USER "…" PASSWORD EXPIRE` with no password in
it: the person's next logon is forced to change the password. Nothing is drawn,
nothing is delivered and nothing is shown, so there is no `delivery:` block to
configure and no guard to satisfy beyond the ones every mutating verb has.

**If a rollover window is open, it is closed first** (#525). Expiring does not
close one, and that was measured rather than assumed: through the window the
**old** password keeps authenticating (`ORA-28001`, not `ORA-01017`) and can be
used to set the next one. So the verb issues `EXPIRE PASSWORD ROLLOVER PERIOD`,
then the expiry. Somebody who remembers only the old password then needs a reset.

It needs two accounts to be worth trying. One is plain, and the other has a window
open, which takes a rollover profile and a second password:

```sql
CREATE USER acme_expire_demo IDENTIFIED BY "Aa1-demo-pw-00001";
GRANT CREATE SESSION TO acme_expire_demo;
CREATE USER acme_expire_roll IDENTIFIED BY "Aa1-roll-old-0001" PROFILE sopuli_rollover;
GRANT CREATE SESSION TO acme_expire_roll;
ALTER USER acme_expire_roll IDENTIFIED BY "Aa1-roll-new-0002";
-- acme_expire_roll is now OPEN & IN ROLLOVER: both passwords work
```

```yaml
personal_accounts:
  - accounts: [acme_expire_demo, acme_expire_roll]
```

No `policy:` is needed, because nothing is generated.

#### The preview, then the run, then the run again

```
$ sopuli account expire-password --account acme_expire_demo --dry-run
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT           TARGET        INTENT           SECRET
acme_expire_demo  tier1-oracle  password_expire  -

ACCOUNT           TARGET        STATE    STATUS  DETAIL
acme_expire_demo  tier1-oracle  EXPIRED  OPEN    declared by accounts 'acme_expire_demo', 'acme_expire_roll'; would be expired

would expire acme_expire_demo's password on 1 of 1 targets
```

Without `--dry-run`:

```
ACCOUNT           TARGET        STATE    STATUS  DETAIL
acme_expire_demo  tier1-oracle  EXPIRED  OPEN    account was open; password expired

expired acme_expire_demo's password on 1 of 1 targets
```

And again, which is invariant 9:

```
ACCOUNT           TARGET        STATE    STATUS   DETAIL
acme_expire_demo  tier1-oracle  EXPIRED  EXPIRED  the password is already expired

acme_expire_demo's password was already expired on 1 of 1
```

Oracle accepts a second `PASSWORD EXPIRE` **silently**. The second run says
"already expired" only because the verb reads `ACCOUNT_STATUS` first, and the
closing line counts changes rather than rows in `EXPIRED`, which is `account
suspend`'s lesson applied before it could cost anything.

#### The window, closed

```
$ sopuli account expire-password --account acme_expire_roll
ACCOUNT           TARGET        STATE    STATUS              DETAIL
acme_expire_roll  tier1-oracle  EXPIRED  OPEN & IN ROLLOVER  rollover window closed; the old password no longer works; account was open & in rollover; password expired

expired acme_expire_roll's password on 1 of 1 targets
```

Then try both passwords from sqlplus, **each as its own invocation with the
`CONNECT` on stdin**. An expired login prompts for a new password and would read
the rest of a script as its answer:

```
old password:      ORA-01017: invalid credential or not authorized; logon denied
current password:  ORA-28001: The account has expired. The password must be changed.
```

`ORA-01017` is the window gone. `ORA-28001` is the current password still
authenticating, and being made to change.

The JSON of a re-run shows both statements the driver considered, neither issued:

```json
{
  "account": "acme_expire_roll",
  "target": "tier1-oracle",
  "state": "EXPIRED",
  "changed": false,
  "actions": [
    { "kind": "rollover_finish", "applied": false, "detail": "no rollover window is open" },
    { "kind": "password_expire", "applied": false, "detail": "the password is already expired" }
  ],
  "account_status": "EXPIRED",
  "duration_ms": 232
}
```

**`EXPIRED & IN ROLLOVER` is not "already expired"**, and it is the case worth
setting up by hand, because it is what a DBA's own `ALTER USER … PASSWORD EXPIRE`
leaves behind on a rollover profile. From `OPEN & IN ROLLOVER`, issue
`ALTER USER acme_expire_roll PASSWORD EXPIRE` yourself, then run the verb:

```
ACCOUNT           TARGET        STATE    STATUS                 DETAIL
acme_expire_roll  tier1-oracle  EXPIRED  EXPIRED & IN ROLLOVER  rollover window closed; the old password no longer works

expired acme_expire_roll's password on 1 of 1 targets
```

Only the window closes, the expiry is not reissued, and the row reports a change.
**Getting back to `OPEN & IN ROLLOVER` takes two `IDENTIFIED BY`s, not one.**
Measured on 26ai, twice: setting a password on an `EXPIRED` account opens no
window, and it even clears one that was open. The first `IDENTIFIED BY` gives plain
`OPEN`, and only the second opens the window.

**The window closing and the expiry then failing** cannot be caused by hand on this
stack, because nothing refuses `PASSWORD EXPIRE` once the close's `ALTER USER` has
succeeded, so the test suite injects that failure instead. The row is `ERROR` at
exit 4 with `changed: true`, since the old password is dead, and `summary.changed`
counts it. The closing line does not. It reads
`acme_dev_alice's password was not expired on any of 1; 1 failed`, because nothing
was expired. Before #537 it read `expired … on 1 of 1 targets; 1 failed`.

#### Failures worth causing

| Try | What you get |
|---|---|
| omit `--account` | `Error: Missing option '--account'.`, exit **2** |
| `--account system` | exit **0**, state `SKIPPED`, all three guardrails named, as for `account suspend` |
| `--account system --force` | exit **0**, still `SKIPPED`, because the whitelist is the one refusal `--force` never waives |
| `--account acme_nobody_here` | exit **0**, state `ACCOUNT_MISSING`: the tool creates nothing |
| `--select env=nosuch` | `Plan: 0 accounts x 0 targets = 0 accounts`, then `nothing to expire`, exit **0** |

```
$ sopuli account expire-password --account system --force
ACCOUNT  TARGET        STATE    STATUS  DETAIL
system   tier1-oracle  SKIPPED  OPEN    the config does not declare this account, and no flag extends the whitelist

system's password was not expired on any of 1
```

It writes no `reset_records:` entry and takes no advisory lock, so `lock status`
shows nothing for it. It delivers nothing, so there is nothing for either to
protect (#525).

### `account list` — reading a whitelist you cannot enumerate

This is the verb H1 earned. A personal account may be declared by **name** or by a
**predicate** over a database profile or role, and a predicate is not in the file —
membership is a profile assignment or a role grant, made by whoever administers the
database rather than whoever reviews the config. So the whitelist is not something
you can read off the page, and this is the command that reads it for you.

Add a predicate to the file from §6, and make an estate for it:

```sql
CREATE PROFILE acme_dev_prof LIMIT PASSWORD_LIFE_TIME 90;
CREATE USER acme_dev_alice IDENTIFIED BY "Aa1-demo-pw-00001" PROFILE acme_dev_prof;
CREATE USER acme_dev_bob   IDENTIFIED BY "Aa1-demo-pw-00002";
CREATE USER acme_dev_carol IDENTIFIED BY "Aa1-demo-pw-00003" PROFILE acme_dev_prof;
CREATE ROLE acme_dev_team;
GRANT acme_dev_team TO acme_dev_bob;
```

```yaml
personal_accounts:
  - accounts: [acme_dev_alice, acme_dev_bob]
    policy: personal-standard
  - profile: ACME_DEV_PROF
    policy: personal-standard
```

```bash
sopuli account list
```
```
ACCOUNT         TARGET        DECLARED BY              STATUS  DB_PW_CHANGED  RESET_AT
ACME_DEV_ALICE  tier1-oracle  names                    OPEN    2026-09-18     -
ACME_DEV_BOB    tier1-oracle  names                    OPEN    2026-09-18     -
ACME_DEV_CAROL  tier1-oracle  profile 'ACME_DEV_PROF'  OPEN    2026-09-18     -

3 declared accounts, 3 on the selected targets
```

**Alice is declared twice and listed once.** She is named in the enumerated entry
*and* carries the profile, which UC-2 §2 calls ordinary — and the two rules give her
name in two spellings, `acme_dev_alice` from the file and `ACME_DEV_ALICE` from the
dictionary. The first build of this verb printed both. That is worth knowing because
it is the kind of bug a listing verb must not have: it misreports the size of the
whitelist you are reviewing.

**RESET_AT is empty and says why.** This config declares no `reset_records:`
block, so there is no journal to read:

```bash
sopuli --output json account list | jq -r '.diagnostics[] | "\(.code) \(.message)"'
```
```
SOPULI-W023 no `reset_records:` block is declared, so there is no reset journal to read and RESET_AT is empty for every account; the database's own password-change date is unaffected and is reported beside it
```

#### Filling that column in

`account reset-password` fills it for real since #511 — §10a's *What the journal
then holds* does that end to end. What follows writes a record **by hand**, which
is still the quicker way to exercise the column on its own: it needs no database
and no password, and it lets you put a date in the column and see it rendered.
Declare the journal (§10a's `reset_records:` block, below), then:

```bash
vault kv put -mount=kv sopuli/personal-resets/tier1-oracle/acme_dev_alice   account=acme_dev_alice target=tier1-oracle reset_at=2026-09-17T09:14:22Z   seen=false expired=false
```
```
ACCOUNT         TARGET        DECLARED BY  STATUS  DB_PW_CHANGED  RESET_AT
ACME_DEV_ALICE  tier1-oracle  names        OPEN    2026-09-18     2026-09-17T09:14:22Z

1 declared account, 1 on the selected targets
```

The path is `<prefix>/<target>/<account>`, lowercased on the account — one record
per (target, account), which is the pair two concurrent resets collide on (#468).
No `SOPULI-W023` this time, because there is now a journal.

**Look at those two dates.** The database says the password changed *after* the
journal says it was reset. On the unseen path that is a **finding**, not a
curiosity: somebody changed the password after the tool delivered it, so whatever
the person was told to fetch no longer works. That is why UC-2 §3.2 keeps them as
two columns off two clocks rather than folding them into one number — here the
disagreement is only an artefact of a hand-written record, but the shape is the
real one.

#### The asymmetry worth causing on purpose

**A predicate that matches nothing is an answer.** Make an empty profile and point
a rule at it:

```sql
CREATE PROFILE acme_empty_prof LIMIT PASSWORD_LIFE_TIME 90;
```
```
no declared personal accounts on the selected targets
```

Exit **0**. That is a true fact about today's estate, not a failure to look.

**A predicate that names nothing is a typo.** Change it to a profile that does not
exist:

```
Error: target 'tier1-oracle' has no profile 'ACME_NOSUCH_PROF', which `personal_accounts:` declares a predicate over -- a predicate that matches no accounts is an answer, and one that names nothing is a typo
```

Exit **1**. Both cases are an empty list from the database, which is exactly why the
tool asks whether the profile exists as a separate question — an empty list cannot
tell the two apart, and only one of them is somebody's mistake.

The same pair holds for `role:`.

#### A role predicate on a service account installed before #531

A `role:` rule needs to know which roles **exist**, and that answer lives in
`DBA_ROLES`. §2 has granted it since #531. Before that it did not, whatever the
code said, so a correctly installed service account could not tell a real role
from a typo. Install one with the script, then take the grant away to rebuild the
older estate:

```bash
docker cp sql/oracle/00_install.sql sopuli-test-oracle-free-1:/tmp/00_install.sql
docker exec -i sopuli-test-oracle-free-1   sqlplus -S "sys/sopuli-test@localhost:1521/FREEPDB1 as sysdba"   @/tmp/00_install.sql PDB acme_list_svc USERS N N N
```

Point a target at it (`admin: { username: ACME_LIST_SVC, auth: { method: env,
password_env: SOPULI_SVC_PASSWORD } }`) with `role: ACME_DEV_TEAM` declared. With
the grant, the list is what it is as `SYSTEM`:

```
ACCOUNT       TARGET        DECLARED BY           STATUS  DB_PW_CHANGED  RESET_AT
ACME_DEV_BOB  free-pdb-svc  role 'ACME_DEV_TEAM'  OPEN    2026-09-25     -
SYS           free-pdb-svc  role 'ACME_DEV_TEAM'  OPEN    -              -

2 declared accounts, 2 on the selected targets
```

Then `revoke select on sys.dba_roles from acme_list_svc` as `SYS`:

```
sopuli: target "free-pdb-svc" does not support role_lookup
  hint: the service account cannot read DBA_ROLES, so a role that matches nobody cannot be told from one that does not exist: GRANT SELECT ON SYS.DBA_ROLES to it (02-oracle-privileges.md section 2, or sql/oracle/00_install.sql)
```

Exit **5**, the capability exit code. Before #531 the same run said `target
'free-pdb-svc' has no role 'ACME_DEV_TEAM'` and exited 1, blaming the file for
the missing grant. `doctor` shows it too: that target reports 5 capabilities
rather than 6, with `role_lookup` absent. Nothing else changes. `creds` and the
mutating `account` verbs never read `DBA_ROLES`, so an older install keeps
working for everything but this listing.

#### The thing a predicate will teach you

Point a rule at a role and look at who holds it:

```yaml
personal_accounts:
  - role: ACME_DEV_TEAM
```
```
ACCOUNT       TARGET        DECLARED BY           STATUS  DB_PW_CHANGED  RESET_AT
ACME_DEV_BOB  tier1-oracle  role 'ACME_DEV_TEAM'  OPEN    2026-09-18     -
SYSTEM        tier1-oracle  role 'ACME_DEV_TEAM'  OPEN    -              -

2 declared accounts, 2 on the selected targets
```

**`SYSTEM` is in the whitelist**, and it is not a bug — creating a role grants it to
the creator, and `acme_dev_team` was created by `SYSTEM`. This is H1's stated cost,
live: *predicate membership is controlled by whoever grants the role, not by whoever
reviews the file.* The row carries a notice saying a mutating verb would refuse it:

```bash
sopuli --output json account list | jq -r '.results[] | select(.account=="SYSTEM") | .warnings[].message'
```
```
the database reports this account as its own, so a mutating verb refuses it at plan time (guardrail 2) -- a predicate can admit an account no reset will touch, and creating a role grants it to the creator
```

Try `profile: DEFAULT` if you want the lesson in full — on the tier-1 stack it
declares **34 accounts**, most of them Oracle's own.

#### Other things worth doing

| Try | What you get |
|---|---|
| an enumerated account the database does not have | a row with `ACCOUNT_MISSING` and the count says `(1 not present)` — the declaration is a claim worth reporting as unmet |
| `--account NAME` | filters the resolved set. It **cannot extend** it: invariant 5's second sentence, and a name the declaration does not admit simply lists nothing |
| `--select env=nosuch` | `no targets selected`, exit 0 |
| a second rule naming a different `policy:` for one account | refused at plan time, naming both rules — which password policy applies must not depend on file order |

---

### `reset_records:` — where the journal lives

UC-2's reset journal became configurable in #468 and **written** in #511: an
`account reset-password` run with this block declared writes one record per
(target, account), and a run without it says so and resets anyway. What the
record holds, and how to read it back out of Vault, is §10a's *What the journal
then holds*; this is the block that decides where it goes.

Add it to the file from §6:

```yaml
reset_records:
  vault: vault-dev
  prefix: sopuli/personal-resets
```

```bash
sopuli --config sopuli.yaml config validate
```
```
config: C:\Users\ville\AppData\Local\Temp\sopuli-468\ok.yaml

ok: 1 target, 0 bindings, 0 warnings
```

The block names **where the journal lives**, once for the estate. A record's own
path is derived under the prefix, one per (target, account) — that pair is what two
concurrent resets collide on, and it is what UC-2's advisory lock will key on. It
is **not** where a password is delivered: on the unseen path that goes somewhere
only the person can read, and the record holds no password in any representation.

`config show` says where it was configured, which is the only way to confirm the
block took:

```bash
sopuli --config sopuli.yaml config show
```
```
personal_accounts
DECLARED BY  ACCOUNTS  TARGETS  POLICY
names        1         all      personal-standard

reset_records
STORE      PREFIX
vault-dev  sopuli/personal-resets
```

Two columns rather than one rendered path, because the two fail differently: a
store that is not declared is refused at load, while a prefix that is not the one
you meant is accepted and looks entirely correct. Showing the pair is what lets the
second be noticed.

#### Failures worth causing

All four exit **9**, and each names the key:

| Try | What you get |
|---|---|
| a `vault:` no `vaults:` entry declares | `no vault named 'vault-prd' is declared`, at load |
| no `prefix:` | `must name the prefix records are written under` |
| a `prefix:` with `..` in it | refused as a path segment, not silently rewritten |
| any other key | `unknown key 'ttl'` |

The first is the one worth understanding. It is resolved **while the file is
open**, with every other store reference, rather than when a record is written:

```bash
sopuli --config typo.yaml config validate; echo "exit $?"
```
```
sopuli: C:\Users\ville\AppData\Local\Temp\sopuli-468\typo.yaml: reset_records.vault: no vault named 'vault-prd' is declared
  hint: declared vaults: vault-dev
exit 9
```

Left to the verb, that failure would arrive *after* a password had already
changed — the worst possible moment to learn a store name is misspelled.

The `..` refusal is the same rule `lock break` got in #344, applied to the one
other place a file names a store path:

```bash
sopuli --config traversal.yaml config validate; echo "exit $?"
```
```
sopuli: C:\Users\ville\AppData\Local\Temp\sopuli-468\traversal.yaml: reset_records.prefix: prefix 'sopuli/../secrets' contains '..' as a path segment
  hint: write the path records actually live at -- a relative segment resolves somewhere else on the way to the store, so records would be written outside the prefix this file names
exit 9
```

A `..` under a prefix walks out of it, and what it would walk into here is whatever
else the estate keeps in that store. Rewriting it silently would be worse than
refusing, which is exactly the argument #344 made about `locks/`.

**`prefix:` has no default**, deliberately, so leaving it out is a refusal rather
than a guess:

```
sopuli: C:\Users\ville\AppData\Local\Temp\sopuli-468\noprefix.yaml: reset_records.prefix: must name the prefix records are written under
  hint: a path in the store, such as `sopuli/personal-resets`
exit 9
```

A default would put records somewhere the file does not say, in a store the file
does name — so nobody could tell where the journal is by reading the configuration.

**With no block at all**, a reset still runs and says so, as `SOPULI-W024` — shown under
[What the journal then holds](#what-the-journal-then-holds) — and `account list`
leaves `RESET_AT` empty with `SOPULI-W023`.

### `delivery:` — which method, and what the file is checked for

#440 built the block and **two of its six methods deliver**: `manual`, the seen
path (#441), and `vault_wrapped`, the unseen one and the default (#444). What they
do is under [`account reset-password`](#account-reset-password--the-seen-path)
above; this section is only about the file. The other four — `vault_path`,
`one_time_link`, `onepassword_share` and `smtp_encrypted` — parse and cannot hand
anybody a password yet.

A block that works:

```yaml
delivery:
  method: vault_wrapped
  vault_wrapped:
    ttl: 15m
  notify:
    method: webhook
    webhook:
      url: { env: SOPULI_NOTIFY_WEBHOOK }
      template: "{account} on {target} has a new password waiting"
```

```bash
sopuli --config ok.yaml config validate
```
```
config: ok.yaml

ok: 1 target, 1 binding, 0 warnings
```

`template:` is required; leave it out and the file is refused with
`delivery.notify.webhook.template: must be given`.

Select one of the four that are not built, and `config validate` says so rather
than letting a clean parse read as a working delivery:

```bash
sopuli --config unimpl.yaml config validate
```
```
config: unimpl.yaml

ok: 1 target, 1 binding, 1 warning

1 warning:
  delivery.method: `delivery.method: one_time_link` is configured and is not implemented in this build, so nothing can hand a password over that way yet
    hint: the block is valid and this build cannot act on it; nothing is wrong with the file
```

**Exit 0 with a warning**, not a refusal: the file is valid and the build is
incomplete, which is E4/E5's shape for a configured backend this build cannot
serve.

#### Failures worth causing

All exit **9**.

```bash
sopuli --config unknown-method.yaml config validate
```
```
sopuli: unknown-method.yaml: delivery.method: unknown delivery method 'carrier_pigeon'
  hint: known: vault_wrapped, vault_path, one_time_link, onepassword_share, manual, smtp_encrypted
```

The method is checked **before** unknown keys are, and that ordering is the message
rather than a detail: a file saying `method: carrier_pigeon` usually has a
`carrier_pigeon:` block under it, so it is an unknown *key* as well — and reporting
the key would answer a question you did not ask while burying the one you did.

```bash
sopuli --config no-subblock.yaml config validate
```
```
sopuli: no-subblock.yaml: delivery.one_time_link: delivery method 'one_time_link' is selected and has no `one_time_link:` block
  hint: every method needs settings of its own -- a wrapping token needs a ttl, a link needs a backend; write the block, or select a different method
```

Leave `method:` out entirely and you get the same refusal naming `vault_wrapped` —
the default still needs its block, because a default is not an excuse to skip the
settings it needs.

```bash
sopuli --config unknown-key.yaml config validate
```
```
sopuli: unknown-key.yaml: delivery: unknown key 'retries'
  hint: known keys here: manual, method, notify, one_time_link, onepassword_share, smtp_encrypted, vault_path, vault_wrapped
```

A typo inside the block of a **built** method is refused too, because the method's
keys are known now:

```
sopuli: subtypo.yaml: delivery.vault_wrapped: unknown key 'tt1'
  hint: known keys here: ttl, vault
```

And `manual` without `force_expire: true` is refused rather than defaulted —
invariant 2's fifth guard on the seen path:

```
sopuli: manual-noexpire.yaml: delivery.manual.force_expire: `manual` delivery needs `force_expire: true`
  hint: `manual` prints a working password to your terminal, and expiry at first logon is what ends that exposure -- so it is written down rather than assumed (UC-2 6.5). Use an unseen method if you do not want the account expired
```

**What will not be refused**, and is worth trying so the boundary is clear: a typo
inside the block of a method that is **not built**. `one_time_link: { bakend: x }`
validates with only the not-implemented warning above. Which keys a method takes
belongs to that method's own issue, because the answer is a fact about the service
behind it — and the warning is what stops a clean parse being mistaken for
approval.

A sub-block for a method you did **not** select is also left alone — keeping a
`vault_wrapped:` block beside `method: manual` is how you switch between them, and
its keys are unjudged even when the method is built: `vault_wrapped: { tt1: 15m }`
beside `method: manual` validates with no warning.

But it must still be an *object*. `vault_wrapped: 15m` is refused wherever it
appears:

```
sopuli: loose.yaml: delivery.vault_wrapped: must be a mapping, not a string
```

That is the one thing checked about an unselected block, and it is checked because
the published schema types all six method properties as objects — the tool must
never accept a file the schema refuses, which is the wrong way round for §9b's
division of labour.

### `safety.delivery.allowed_methods` — the list that only narrows

The block above says which delivery method an estate uses. This says which ones it
**may** use, and it is the one setting in the tool that merges by *intersection*:
each layer can take methods away and none can put one back. It goes in a `safety:`
block — under `defaults:`, a profile, a target, a target set or a group — not in
`delivery:`.

```yaml
defaults:
  safety:
    delivery:
      allowed_methods: [vault_wrapped, one_time_link, manual]

profiles:
  unattended:
    safety:
      delivery:
        allowed_methods: [vault_wrapped]
```

```bash
sopuli --config ok.yaml config show --explain
```
```
safety
KEY                                                  VALUE                                 NOTE
defaults.safety.delivery.allowed_methods             vault_wrapped, one_time_link, manual
profiles.unattended.safety.delivery.allowed_methods  vault_wrapped

settings
  db.connect_timeout_s            = 30                                    [built-in default]
  db.query_timeout_s              = 0                                     [built-in default]
  output                          = text                                  [built-in default]
  safety.delivery.allowed_methods = manual, one_time_link, vault_wrapped  [defaults.safety.delivery.allowed_methods]
  safety.dry_run                  = false                                 [built-in default]
  safety.readonly                 = false                                 [built-in default]
  vault                           = vault-dev                             [defaults.vault]
  vaults.vault-dev.addr           = http://127.0.0.1:8200                 [vaults.vault-dev.addr]
  vaults.vault-dev.kv_version     = 2                                     [vaults.vault-dev.kv_version]
  vaults.vault-dev.mount          = kv                                    [vaults.vault-dev.mount]
```

Now select the profile, which permits one of the three:

```bash
sopuli --config ok.yaml --profile unattended config show --explain
```
```
settings
  db.connect_timeout_s            = 30                     [built-in default]
  db.query_timeout_s              = 0                      [built-in default]
  output                          = text                   [built-in default]
  profile                         = unattended             [cli --profile (group)]
  safety.delivery.allowed_methods = vault_wrapped          [profiles.unattended.safety.delivery.allowed_methods]
                                    defaults.safety.delivery.allowed_methods asked for vault_wrapped, one_time_link, manual; safety.delivery.allowed_methods stays vault_wrapped (profiles.unattended.safety.delivery.allowed_methods) -- safety settings only ratchet toward safe
  safety.dry_run                  = false                  [built-in default]
  safety.readonly                 = false                  [built-in default]
  vault                           = vault-dev              [defaults.vault]
  vaults.vault-dev.addr           = http://127.0.0.1:8200  [vaults.vault-dev.addr]
  vaults.vault-dev.kv_version     = 2                      [vaults.vault-dev.kv_version]
  vaults.vault-dev.mount          = kv                     [vaults.vault-dev.mount]
```

Two things to read out of that. The reported source is the **profile**, because
that is the layer that narrowed the set and the key you would edit to get a method
back — `defaults:` only permitted what the profile decided. And the second line is
the ratchet note, which names what the lower layer lost; swap the two lists and it
does not appear, because a layer that permitted more than survived is the only kind
of loser this setting has.

Now reverse the two lists — `[vault_wrapped]` in `defaults:`, and the profile
asking for `manual` as well. Layer 3 outranks layer 5 everywhere else in the file:

```bash
sopuli --config reversed.yaml --profile unattended config show --explain
```
```
safety
KEY                                                  VALUE                  NOTE
defaults.safety.delivery.allowed_methods             vault_wrapped
profiles.unattended.safety.delivery.allowed_methods  vault_wrapped, manual  defeated by the ratchet

settings
  safety.delivery.allowed_methods = vault_wrapped          [defaults.safety.delivery.allowed_methods]
                                    profiles.unattended.safety.delivery.allowed_methods asked for vault_wrapped, manual; safety.delivery.allowed_methods stays vault_wrapped (defaults.safety.delivery.allowed_methods) -- safety settings only ratchet toward safe
```

`manual` is gone, the higher layer is marked **defeated by the ratchet**, and the
reported source has moved to `defaults:` — the layer that now does the narrowing.
That is the whole point of the intersection: there is no layer from which a method
can be added back.

#### Four failures worth causing

All exit **9**.

```bash
sopuli --config disjoint.yaml --profile unattended config validate
```
```
sopuli: `safety.delivery.allowed_methods` resolves to nothing: profiles.unattended.safety.delivery.allowed_methods allows vault_wrapped; defaults.safety.delivery.allowed_methods allows manual
  hint: these layers have no method in common, so nothing could be delivered under all of them -- widen one, or delete it; the setting only ever narrows, so a layer meant to impose nothing is a layer that should not be written
```

Two layers with nothing in common is the refusal worth understanding: an empty
intersection is a configuration nobody can have meant, and honouring one of the two
layers would be choosing which guard to ignore. The message names **every** layer
that spoke, because an empty result is never one block's doing. Note that it has no
file path in front of it, unlike the three below: this one is not found while the
file is being read, but while the layers are being merged, which is after the last
file has been closed.

The same refusal reaches a target's own block, and there it needs a run to appear
at all — these two layers are compatible until something selects the target that
makes them disjoint:

```bash
sopuli --config target-disjoint.yaml --profile unattended creds status --dry-run
```
```
sopuli: `safety.delivery.allowed_methods` resolves to nothing: profiles.unattended.safety.delivery.allowed_methods allows vault_wrapped; targets[0].safety.delivery.allowed_methods allows manual; defaults.safety.delivery.allowed_methods allows vault_wrapped, one_time_link, manual
  hint: these layers have no method in common, so nothing could be delivered under all of them -- widen one, or delete it; the setting only ever narrows, so a layer meant to impose nothing is a layer that should not be written
```

```bash
sopuli --config empty.yaml config validate
```
```
sopuli: empty.yaml: defaults.safety.delivery.allowed_methods: allowed_methods is empty, so no delivery method would be permitted
  hint: the set only ever narrows, so nothing could widen it again -- name the methods this estate permits, or leave the key out, which imposes no constraint at all
```

`allowed_methods: []` is not the way to say "never hand a password over" — leaving
the key out is no constraint at all, and an empty list is a layer nothing could
ever widen. An estate that means it configures no `delivery:` block instead.

```bash
sopuli --config unknown.yaml config validate
```
```
sopuli: unknown.yaml: defaults.safety.delivery.allowed_methods[0]: unknown delivery method 'carrier_pigeon'
  hint: known: vault_wrapped, vault_path, one_time_link, onepassword_share, manual, smtp_encrypted
```

```bash
sopuli --config forbidden.yaml config validate
```
```
sopuli: forbidden.yaml: defaults.safety.delivery: unknown key 'forbidden_methods'
  hint: known keys here: allowed_methods
```

There is no `forbidden_methods`, now or later, and the refusal is the answer to the
obvious question. A list of what is *refused* would have cost no new code and would
have permitted every method a later release adds, everywhere, on upgrade — silently
widening a guard that stands in front of putting a live credential on a wire.

#### Where a target's own list shows up in JSON

Write the key on a *target* rather than in `defaults:`, and the resolved view
carries it as a sub-block — run schema 1.26, and the shape matters because
`config.targets[].safety` refuses any property it does not name:

```bash
sopuli --config tier1-target.yaml config show --resolved --output json
```
```json
"safety": {
  "delivery": {
    "allowed_methods": [
      "manual",
      "vault_wrapped"
    ]
  }
}
```

Sorted, and intersected with whatever a target set's template or `overrides:` entry
wrote — so what the document carries is what a run would read rather than what the
target's own line says.

**What you cannot test yet**: any of this having an effect. No delivery method is
implemented, so the set is resolved, ratcheted, reported here and read by no verb —
which is what the registry means by marking it inert. The first method to land is
what starts consulting it.

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
run. The fourth is `delivery.allowed_methods`, which is a list rather than a switch
and merges by intersection rather than union; it has its own section above, because
what is worth trying about it is the merge rather than the refusal.

#### A block with nothing under it

The failure worth causing on purpose here is the half-finished edit. Write the
heading and indent nothing under it:

```yaml
defaults:
  policy: standard
  vault: vault-dev
  safety:
```

```
$ sopuli --config null-safety.yaml config validate
sopuli: null-safety.yaml: defaults.safety: must be a mapping, not nothing
```

Exit 9. Until #501 that file loaded, and loaded as *no safety block at all* — so a
`readonly` somebody thought they had written could vanish because the key beneath
it was left blank. The same for the list:

```yaml
  safety:
    readonly: true
    confirm_environments:
```

```
$ sopuli --config null-confirm.yaml config validate
sopuli: null-confirm.yaml: defaults.safety.confirm_environments: must be a list, not nothing
```

Exit 9, where it used to read as `()` — silently "confirm nothing, anywhere".
Both refusals apply wherever a `safety:` block may be written: `defaults:`, a
profile, a target, a group, a target set's template or an `overrides:` entry.

### `--vault-addr` with nothing to apply it to

Delete `vault: vault-dev` from `defaults:` and try to redirect the store anyway:

```
$ sopuli --config no-default.yaml config show --vault-addr https://vault-standby.example.com:8200
sopuli: no-default.yaml: --vault-addr names no store, and this run has no default one to apply it to
  hint: it applies to the store `defaults.vault` names -- write one, export SOPULI_VAULT=<store>, or address a store directly with SOPULI_VAULT__<STORE>__<KEY>
```

Exit 9. `SOPULI_VAULT_ADDR` is refused in the same words for the same reason: it
was written for this tool, so silently doing nothing is worse than either
honouring it or refusing. `VAULT_ADDR` only warns, because that one is not this
tool's to fail a run over.

### The same block, on a target or a group

All three keys also work on a target, on a group, and on a target set's template
or `overrides:` entry — **since #424, and not before it.** Until then they parsed,
validated, showed up in `config show` and refused nothing, so this is the part of
§11 most worth causing on purpose if you are checking a build.

Put the block on the target instead of under `defaults:`:

```yaml
targets:
  - name: free-pdb
    type: oracle
    environment: dev
    vault: vault-dev
    dsn: "127.0.0.1:1521/FREEPDB1"
    admin: { username: SYSTEM, auth: { method: env } }
    oracle: { scope: pdb, container: FREEPDB1 }
    labels: { tier: sandbox }
    safety: { readonly: true }
```

```
$ sopuli --config sopuli.yaml creds apply --application acme --dry-run
sopuli: applying a password is a mutation, and `safety.readonly` is set on the target it reaches
  hint: readonly: free-pdb (targets[0].safety.readonly); no layer can relax it (invariant 10) -- no narrowing of this run can avoid it, so read instead with `sopuli creds check` or `sopuli creds status`
```

Exit 8, and `--dry-run` is refused with everything else. `creds generate`,
`creds rotate` and `creds finish-rollover` refuse the same way; `creds check` and
`creds status` still run and exit as they would have.

**`lock break` does not**, from a target or a group — it names a vault document
and takes no selector, so there is no estate for the block to come from, and
every verb that would use that lock to change the target is already refused.
Under `defaults:` or a profile it is refused like everything else. §3a of
`01-configuration.md` has the reasoning.

Move the block to a group and the refusal points at the group's key instead. A
group is a label match, so nothing has to select *by* it — it applies because a
target it matches is in the run:

```yaml
groups:
  sandbox-pdbs:
    match: { tier: sandbox }
    safety: { readonly: true }
```

```
$ sopuli --config sopuli.yaml creds apply --application acme --dry-run
sopuli: applying a password is a mutation, and `safety.readonly` is set on the target it reaches
  hint: readonly: free-pdb (groups.sandbox-pdbs.safety.readonly); no layer can relax it (invariant 10) -- no narrowing of this run can avoid it, so read instead with `sopuli creds check` or `sopuli creds status`
```

The case worth seeing needs a **second target**. Copy the `free-pdb` block, call
the copy `free-pdb-b`, leave the DSN pointing at the same database, and mark only
the first one `readonly`. The run is refused whole rather than applying to the
one that is writable, and the message says how much of the plan is affected and
what would narrow past it:

```
$ sopuli --config sopuli.yaml creds apply --application acme --dry-run
sopuli: applying a password is a mutation, and `safety.readonly` is set on 1 of the 2 targets it reaches
  hint: readonly: free-pdb (targets[0].safety.readonly); no layer can relax it (invariant 10) -- narrow the run with --target, --group or --select so it does not reach it, or read instead with `sopuli creds check` or `sopuli creds status`
```

Take the narrowing and the run goes ahead:

```
$ sopuli --config sopuli.yaml creds apply --application acme --target free-pdb-b --dry-run
Plan: 1 account x 1 target = 1 apply   [dev]

ACCOUNT        TARGET      INTENT                               SECRET
acme_app_user  free-pdb-b  verify, password_set, vault_promote  vault-dev:acme/dev/acme

nothing was applied (--dry-run)
```

Swap the target's block for `safety: { max_targets: 1 }` on the same two-target
estate and the ceiling fires instead. It is compared against the targets the
**plan** reaches, so narrowing satisfies it as well:

```
$ sopuli --config sopuli.yaml creds apply --application acme --dry-run
sopuli: applying a password would reach 2 targets, and `safety.max_targets` is 1
  hint: set at targets[0].safety.max_targets; no layer can raise it (invariant 10) -- narrow the run with --select, --target or --group, or raise the ceiling where it is written
```

`confirm_environments` on a target behaves exactly as it does under `defaults:` —
the prompt above, or the unattended refusal — because all three keys go through
one resolver and one ratchet whichever layer wrote them.

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
  which is the full product rather than a slimmed rebuild.

**The Autonomous Database wallet is not a third way**, and this guide used to
say it was. "Wallet" means two different things in Oracle, and the ADB download
is the other one — see §14. It holds TLS certificates; authenticating *from a
wallet* needs a credential store, and the zip contains no credential.
Downloading it gets you a directory `sqlplus` can connect *through*, not one it
can log in *with*.

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
    admin: { username: ADMIN, auth: prompt }
```

### "Wallet" means two different things, and ADB uses both words for one zip

This is the part that will cost you an afternoon if nobody says it, so:

| | what it is | what needs it |
|---|---|---|
| **TLS certificates** | the client certificate and trust anchors that finish a mutual-TLS handshake | the *connection*, whatever login method you use |
| **secure external password store** | a credential keyed on an alias, so `/@alias` can log in with no username or password | `auth: external` **when a wallet is what authenticates** |

`auth: external` is wider than that second row: §3a's `external` is *a wallet or
secure external password store, Kerberos, or OS auth*, and the Kerberos and OS
paths need no password store at all. What follows is about the wallet path,
because that is the one an ADB wallet looks like it satisfies.

**The ADB wallet zip is the first row.** It contains `cwallet.sso`,
`tnsnames.ora`, `sqlnet.ora` and the certificates, and it contains **no
credential**. So `admin: { auth: external }` *authenticating from that wallet*
has nothing to log in with — which is why the example above uses a password
instead.

Download the zip from the OCI console, unzip it, and set `TNS_ADMIN` to that
directory. That is needed for the **TLS** half under mTLS, not for
authentication. The aliases (`_high`, `_medium`, `_low`) are in its
`tnsnames.ora`.

`doctor` will not catch this for you: its wallet report checks that `cwallet.sso`
is present and readable (§12), and a certificate-only `cwallet.sso` passes that
happily. The failure surfaces as an Oracle *login* error, which is the most
misleading way for it to appear — the exact thing §12 says the report exists to
prevent, in the one case the report cannot see.

### Using `auth: external` against ADB anyway

It is a separate step, and it needs the `mkstore` that §12 says you probably do
not have: you add a credential to the downloaded wallet.

```bash
mkstore -wrl /path/to/unzipped/wallet -createCredential myadb_high ADMIN
```

**Untried** (unverified: adb-external-auth). Nobody has run sopuli against an ADB
this way, and the claim above is about what Oracle's zip contains rather than a
measured sopuli failure. Treat a failure here as possibly the instructions.

So for a laptop holding only Instant Client, ADB is **not** a way around
`mkstore` — it is another case that needs it.

### The mTLS-free case, which needs no wallet at all

If the ADB is configured for **TLS only** — mutual TLS not required, access
controlled by an ACL or a private endpoint — there is no wallet in the picture.
Copy the connect descriptor out of the OCI console and put it straight in `dsn:`,
and leave `TNS_ADMIN` unset.

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
[`schemas/sopuli-run-1.30.schema.json`](schemas/sopuli-run-1.30.schema.json) describes. `creds check`,
trimmed to its shape:

```json
{
  "schema_version": "1.23",
  "tool": { "name": "sopuli", "version": "0.61.0" },
  "command": "creds.check",
  "invocation": {
    "correlation_id": "ca133135-8721-4a4a-97e6-8a76f09323d4",
    "started_at": "2026-09-15T05:38:04.219978Z",
    "duration_ms": 916,
    "actor": { "os_user": "ville", "host": "Awesominator" },
    "dry_run": false,
    "config_files": ["C:\\tmp\\sopuli-guide\\sopuli.yaml"],
    "selection": { "applications": ["acme"] },
    "options": {
      "output": { "value": "json", "source": "cli", "source_detail": "--output (group)" },
      "vault": { "value": "vault-dev", "source": "defaults", "source_detail": "defaults.vault" }
    }
  },
  "summary": { "total": 1, "ok": 1, "changed": 0, "unchanged": 1, "drift": 0, "by_state": { "IN_SYNC": 1 } },
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
      "password_age_days": 0.0, "duration_ms": 150
    }
  ]
}
```

`invocation.options` is `--explain` in machine form, `plan.blast_radius` is what
`max_targets` and `confirm_environments` read, and no field anywhere holds a
password. Grepping a captured document for one is a reasonable thing to do once.

`config show` adds `config.vaults[]` to that, which is where a *store's* settings
and their layers are reported (#428) -- `invocation.options` deliberately carries
only the run's, which is why `vault` is in the block above and
`vaults.vault-dev.addr` is not.

### Streaming: `--output jsonl`

`creds check` is the one verb that streams (#9): one JSON object per line,
flushed as each target finishes. With §10's drift in place:

```bash
sopuli --config sopuli.yaml creds check --output jsonl ; echo "exit $?"
```

```
{"schema_version":"1.3","event":"run.started","seq":0,"ts":"2026-09-25T17:48:29.670694Z","correlation_id":"9352c606-8399-4ca3-836f-86a769203940","data":{"command":"creds.check","dry_run":false}}
{"schema_version":"1.3","event":"plan.resolved","seq":1,"ts":"2026-09-25T17:48:29.670851Z","correlation_id":"9352c606-8399-4ca3-836f-86a769203940","data":{"units":[{"account":"acme_app_user","target":"free-pdb","intent":["verify"],"secret":{"vault":"vault-dev","path":"acme/dev/acme","field":"acme_app_user"}}],"blast_radius":{"targets":1,"accounts":1,"environments":["dev"]}}}
{"schema_version":"1.3","event":"target.started","seq":2,"ts":"2026-09-25T17:48:30.167605Z","correlation_id":"9352c606-8399-4ca3-836f-86a769203940","target":"free-pdb"}
{"schema_version":"1.3","event":"diagnostic","seq":3,"ts":"2026-09-25T17:48:31.447496Z","correlation_id":"9352c606-8399-4ca3-836f-86a769203940","target":"free-pdb","level":"warning","message":"free-pdb: the admin credential came from the environment variable SOPULI_DB_ADMIN_PASSWORD, which P2 supports and flags as low assurance","data":{"code":"SOPULI-W022"}}
{"schema_version":"1.3","event":"target.finished","seq":4,"ts":"2026-09-25T17:48:31.447583Z","correlation_id":"9352c606-8399-4ca3-836f-86a769203940","account":"acme_app_user","target":"free-pdb","data":{"account":"acme_app_user","target":"free-pdb","state":"DRIFT","changed":false,"secret":{"vault":"vault-dev","path":"acme/dev/acme","field":"acme_app_user","version":1,"stage":"current"},"actions":[{"kind":"verify","applied":true,"detail":"vault v1 the database rejected this password (ORA-01017): ORA-01017: invalid credential or not authorized; logon denied"}],"verification":{"method":"login","result":"fail","latency_ms":null,"lcount":0,"failed_login_attempts_limit":"UNLIMITED","lockout_margin_hit":false,"previous_password_accepted":null},"password_age_days":0.0,"duration_ms":1087}}
{"schema_version":"1.3","event":"run.finished","seq":5,"ts":"2026-09-25T17:48:31.448006Z","correlation_id":"9352c606-8399-4ca3-836f-86a769203940","data":{"summary":{"total":1,"ok":0,"changed":0,"failed":0,"unchanged":1,"drift":1,"unverifiable":0,"by_state":{"DRIFT":1}},"exit_code":3}}
exit 3
```

Three things worth checking by hand, because they are the contract:

- **`run.finished.data` is the `--output json` document's `summary` and
  `exit_code`**, byte for byte. Run the same check with `--output json` and
  compare; the exit code is 3 in both.
- **`SOPULI-W022` arrives just before `target.finished`**, not when the admin
  credential was resolved. A diagnostic goes out ahead of the next event, which
  is the stream keeping pace with `diagnostics[]` rather than every place that
  makes one writing to stdout.
- **A failure still closes the stream.** With a token the vault will not accept
  (`VAULT_TOKEN=not-a-token`) the target's `target.finished` carries `"state":
  "ERROR"` and the store's `error`, and `run.finished` says `exit_code: 1`. With
  `--config` pointing at a file that is not there, the stream is `run.started`
  then `run.finished` with `exit_code: 9` and `error.category: "config"`.

**Every other verb refuses it**, because a stream carrying less than the
document would be a quiet downgrade — `config show` has a `config` section the
event schema has no home for:

```bash
sopuli --config sopuli.yaml config show --output jsonl ; echo "exit $?"
```

```
sopuli: --output (verb): `config show` does not stream, so it has no jsonl output
  hint: use --output json for the same run as one document; jsonl is offered by: creds check
exit 2
```

Worth causing once from the environment too — `SOPULI_OUTPUT=jsonl` is how a CI
image sets it for its scheduled check, and every other verb the same job runs
then refuses it, with `SOPULI_OUTPUT` named where `--output (verb)` is above.

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
- **`--output jsonl` on any verb but `creds check`.** The mode exists (§15), and
  the verbs that take a lock or change a password -- whose events are the most
  interesting ones -- do not stream yet, so they refuse it.
- **`--method hash`**, verification without a login attempt. The spike behind it
  is done — the layout is read (#431), the derivation reproduces (#432), and
  degradation on an account with no `T:` is settled (#433), all on the tier-2
  releases — but no product code ships it yet, and it waits on 19c confirmation
  before it can. `verify.method` parses in a profile and reaches no consumer.
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

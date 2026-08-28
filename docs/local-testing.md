# Testing sopuli by hand

How to set up a laptop, WSL, containers and OCI so you can exercise every command
this build has, and see each one succeed *and* fail on purpose.

Every command and every output in this document was run on 2026-08-27 against
Windows 11, Instant Client 23.26.3.0.0, and the `tier1` container stack. Where
something was **not** verified it says so.

Related: [`../test/README.md`](../test/README.md) for the container stack itself,
[`design/04-testing.md`](design/04-testing.md) for the automated tiers, and
[`design/01-configuration.md`](design/01-configuration.md) as the configuration
reference this guide only skims.

---

## 1. What actually exists, before you plan an evening around it

`sopuli --help` lists five nouns, and the whole implemented surface is **seven
commands**:

```
sopuli config validate      sopuli lock status
sopuli config show          sopuli lock break
sopuli target list          sopuli doctor
sopuli policy sample
```

**There is no `sopuli creds` and no `sopuli admin` yet.** The JSON schema's
`command` enum lists `creds.generate`, `creds.apply`, `creds.rotate`,
`admin.install` and others, because the contract was written ahead of the code —
but nothing implements them. **You cannot rotate a credential end to end today.**
If that is what you sat down to test, stop here; UC-1 is not built.

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
OCI Vault as a secret store does not exist — see §12.

---

## 2. The three places you will run this, and why

| Where | What it is for |
|---|---|
| **Windows laptop** | the primary target. The ACL permission checks, the console encoding and the wallet report all behave differently here, and Windows is where the bugs have been |
| **WSL** | the POSIX side of the same checks — file modes instead of ACLs. Cheap second opinion, and closer to where this would run scheduled |
| **Docker** | Oracle and Vault. Neither needs installing on the host |
| **OCI** | the only place Native Network Encryption and a real ADB wallet can be exercised |

Run through §§3–10 on Windows first, then repeat §§6–10 in WSL. The interesting
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
error: config file is accessible to BUILTIN\Users
```

Fix it before anything else:

```powershell
icacls sopuli.yaml /inheritance:r /grant:r "$($env:USERNAME):F"
```
```bash
chmod 600 sopuli.yaml            # WSL
```

The POSIX check is on `0o077` — *any* group or other access, not just read —
because refusing a world-readable file while accepting a group-writable one would
guard the smaller problem.

### Four things worth getting wrong on purpose

Each of these is a real error message worth seeing once:

| Change | What you should get |
|---|---|
| `applications:` as a mapping instead of a list | `must be a list, not a mapping` |
| `length: 24` directly under the policy name | `unknown keys 'charset', 'length'` — it belongs under `password:` |
| drop the `#{account}` from `secret_template` | `names a whole secret, which has nowhere to stage into` |
| `dsn: "host:1521/svc"` with `auth: external` | refused at load: external auth needs a TNS alias |

All four cost me time while writing this guide, which is why they are here.

---

## 7. The offline commands

None of these open a socket. They work with Docker stopped and no Instant Client.

```bash
sopuli --config sopuli.yaml config validate
```
```
ok: 1 target, 1 binding, 0 warnings
```

```bash
sopuli --config sopuli.yaml target list
```
```
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
  output          = text   [built-in default]
  safety.dry_run  = false  [built-in default]
  safety.readonly = false  [built-in default]
```

Set `SOPULI_OUTPUT=json` and run it again to watch a layer change.

### Password policy

```bash
sopuli --config sopuli.yaml policy sample --count 2
```
```
policy: standard    length 24, alnum_safe, first_char alpha, require digit 1, ...

#  CHARS  BYTES  CLASSES
1  24     -      u8 l10 d3 s3
2  24     -      u5 l14 d3 s2

2 samples, all compliant. Not stored anywhere; pass --reveal to print them.
```

`--reveal` prints the passwords — the one place this tool prints a secret, allowed
because a sample is not a credential: nothing authenticates with it and it is
never stored. Prove the guard around it:

```bash
sopuli --config sopuli.yaml policy sample --reveal --output json
```
```
Error: --reveal cannot be used with --output json
       json output is what gets captured and shipped to log aggregation, so a
       sample never appears in it -- drop --reveal, or use the text output
```

Exit 2. Also try `--max-bytes 30 --encoding cp1252` to see the byte-limit preview
that models an 11g password.

---

## 8. Vault

`lock status` is the first command that opens a socket. It needs a token, and
**the token is never a command-line value** — it comes from the environment, a
file, or `~/.vault-token`.

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=sopuli-test-root
sopuli --config sopuli.yaml lock status
```
```
mode:   cas

0 of 1 declared lock paths held
```

`mode: cas` means the store can fence — it supports compare-and-set, so two runs
starting in the same second cannot both believe they hold a lock. Set
`locking: advisory-only` on the vault and watch the mode change and a
`SOPULI-W001` warning appear.

Without a token:

```
error: vault "vault-dev": no token, and none of the places it is looked for had one
```

Try the file form too, which is what `--vault-token-file` is for:

```bash
unset VAULT_TOKEN
printf 'sopuli-test-root' > vault-token.txt
chmod 600 vault-token.txt      # or icacls, same as the config file
sopuli --config sopuli.yaml --vault-token-file vault-token.txt lock status
```

`sopuli lock break vault-dev:<path>` takes a lock back. With nothing held it is
exit 0 having changed nothing, which is what makes running it twice safe. To see
it do something you need a held lock, and nothing writes one yet — the commands
that take locks are the unimplemented `creds` verbs. `--dry-run` still prints the
plan.

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

client
  tns_admin         (unset)
  instant_client    23.26.3.0.0
  reaches           19.1 and later

TARGET    REACHABLE  SCOPE  CONTAINER  OPEN MODE   CAPABILITIES
free-pdb  yes        pdb    FREEPDB1   READ WRITE  6
```

Then `--output json` for the same run — `targets[].scope.capabilities` names the
six the driver probed for, which is what `--strategy rollover` will later branch
on.

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
free-pdb: not checked, and not visible from here: EXECUTE ON DBMS_LOCK, SYSDBA, SYSOPER
free-pdb: over-granted, and the tool needs none of it: ALTER PROFILE, ALTER SYSTEM,
  BECOME USER, CREATE USER, DBA, DROP USER, GRANT ANY DATA ROLE, ...
```

**It warns and never fails** — exit 0. An over-granted account is somebody else's
decision to fix, and a `doctor` that exited non-zero over it would block the
person who ran it mid-incident over a condition they did not create.

The first line matters as much as the second: it names what the audit *could not
see*, so `over_granted: []` can never mean both "nothing is over-granted" and "the
view that would have said so was refused".

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

## 10. Oracle wallets and `auth: external`

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
  from the console and skip `mkstore` entirely (§12).

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
  cwallet.sso wallet file is accessible to BUILTIN\Users: an auto-login wallet is
  a credential, and this one is not private
```

That second warning (`SOPULI-W008`) fires because a file created normally under
Windows `%TEMP%` inherits a `BUILTIN\Users` grant. Tighten it with `icacls` and
watch it go away — this is P4's config-file check applied to the file that
actually holds a password.

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

**The wallet is the problem and the error is entirely about the password.** Left
to that message you would go looking for an account and a password you do not
have. The `wallet` section above it is what redirects you to the file.

Nothing in that section changes the exit code — a bad wallet rides on the
target's own reachability, which the connection settles a moment later.

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

## 11. WSL

Repeat §§6–10. Everything behaves identically except two things, and both are
worth seeing:

- **Permissions are modes, not ACLs.** `chmod 600` instead of `icacls`, and the
  message reads `config file is accessible to others (mode 0644)`. `chmod 640` is
  refused too — the check is on `0o077`, not just the read bits.
- **Reaching the containers.** Under WSL2 with Docker Desktop, `127.0.0.1` works
  from WSL. Under a Docker daemon running inside WSL, it also works. If you are
  running Docker on Windows and sopuli in a *different* WSL distro, use the
  Windows host IP from `/etc/resolv.conf` instead.

Install a separate Instant Client for Linux; the Windows one is not usable from
WSL.

---

## 12. OCI

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
and `sqlnet.ora` already — which is the one path to a real wallet that does not
need `mkstore` at all. The aliases (`_high`, `_medium`, `_low`) are in its
`tnsnames.ora`.

**Locally you can approximate the NNE constraint** without OCI:

```bash
docker compose --profile nne up -d      # Oracle on 1525, NNE required
```

Note `test/compose.yaml`'s own header: the `nne` profile is **unrun and its image
tag unverified**. Treat a failure there as possibly the fixture.

**OCI Vault as a secret store — does not exist.** `type: oci` parses and then
fails: there is no `sopuli/store/oci` module. `doctor` reports it as
`not_implemented` with no install command, precisely because `pip` cannot supply
it. Do not spend time on it.

---

## 13. Exit codes

Branch on these; they are a published interface.

| Code | Meaning | Where you will see it here |
|---|---|---|
| 0 | success, or nothing to do | most runs |
| 1 | generic failure | an unreachable target in `doctor` |
| 2 | argv did not parse — **no JSON document, message on stderr** | `--reveal --output json` |
| 3 | `check` found drift | not reachable yet |
| 4 | partial | not reachable yet |
| 5 | unsupported capability | not reachable yet |
| 6 | authentication failed | a bad vault token |
| 7 | lock held | `lock break` on a live lock without `--force` |
| 8 | aborted / confirmation declined | `lock break` answering no |
| 9 | configuration unusable | bad YAML, bad permissions, or a configured backend this build cannot serve |

**Exit 2 is the only one that never produces a run document.** Every other code
emits one on stdout under `--output json`, including 9 — a validator that goes
silent exactly when it has something to say is not a validator. Worth confirming
once:

```bash
sopuli --config broken.yaml --output json config validate; echo "exit $?"
```

---

## 14. Cleanup

```bash
cd test
docker compose --profile '*' down          # the only form that works
```

Then remove the config, the token file and the `TNS_ADMIN` directory. Nothing
sopuli did wrote outside them — every command in this guide either reads, or
writes only to Vault under its lock prefix.

---

## What this guide cannot cover yet

- **Credential rotation.** `creds generate|apply|check|rotate|promote` do not
  exist. The vault→database direction, the `pending`→`current` promotion, drift
  detection and rollover are all unbuilt.
- **`admin install`**, which will run the SQL in `sql/oracle/` for you. Run the
  scripts by hand for now.
- **`--output jsonl`** and the streaming event contract.
- **A real wallet without a full Oracle install**, per §10.

When those land, this document should grow with them — it is meant to stay a
complete map of what can be exercised by hand, and a stale one is worse than
none.

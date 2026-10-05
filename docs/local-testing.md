# Testing sopuli by hand

This guide sets up the local test stack and runs the usual commands against it.
You see each command succeed, and a few of them refuse on purpose.

Every sample was run on 2026-10-05 on Windows 11, with sopuli 0.69.0, Instant
Client 23.26.3.0.0, and the `tier1` container stack (Oracle 26ai Free and Vault).
Commands are written for Git Bash or WSL. Where a sample was shortened, `...`
marks the cut. The tokens and passwords the runs printed are replaced with
`<TOKEN>` and `<PASSWORD>`, and the local user and host name with
`op@ws1.example.com`. Nothing else is edited.

Other places to read:

- [`../test/README.md`](../test/README.md): the container stack.
- [`design/04-testing.md`](design/04-testing.md): the automated test tiers.
- [`maintainer-environments.md`](maintainer-environments.md): other Oracle
  releases, OCI, wallets and WSL.
- [`getting-started.md`](getting-started.md): a first run for a new user.

---

## 1. What this build has

These are the commands:

<!-- checked-list: commands -->
```
sopuli config validate      sopuli creds generate         sopuli account list
sopuli config show          sopuli creds apply            sopuli account suspend
sopuli target list          sopuli creds check            sopuli account reset-password
sopuli policy sample        sopuli creds rotate           sopuli account expire-password
sopuli lock status          sopuli creds status           sopuli doctor
sopuli lock break           sopuli creds finish-rollover  sopuli about
```

The `creds` commands manage application credentials (UC-1). The `account`
commands manage personal accounts (UC-2).

There is no `sopuli admin` command. To install the service account, run the SQL
in `sql/oracle/` by hand. The only store backend is `hashicorp`; `doctor` lists
the others as `not_implemented`.

---

## 2. Install sopuli

You need Python 3.11 or later.

```bash
git clone https://github.com/villebase/sopuli-dba.git
cd sopuli-dba
python -m venv .venv
source .venv/Scripts/activate      # Git Bash; on WSL: source .venv/bin/activate
pip install -e ".[dev,all]"
```

Check the install:

```
$ sopuli --version
sopuli, version 0.69.0
```

`sopuli --version` reports the version recorded when the editable install was
made, not the version in the tree. After a pull that crossed a release, refresh
it:

```bash
pip install -e . --no-deps
```

`sopuli about` needs no config, no database and no vault. It prints a banner, the
version and the project links.

---

## 3. Oracle Instant Client

sopuli runs `python-oracledb` in thick mode, so Instant Client is required.
[`design/00-principles.md`](design/00-principles.md) §*Why thick mode* says why.

Download **Basic** from Oracle's Instant Client page. **SQL\*Plus** is optional
but useful.

- **Windows:** unzip to a path with no spaces, such as
  `C:\oracle\instantclient_23_26`, and add it to `PATH`.
- **WSL or Linux:** unzip to `/opt/oracle/instantclient_23_26`, install
  `libaio1`, and set `LD_LIBRARY_PATH`.

Instead of `PATH`, you can name the directory in the config:

```yaml
runtime:
  oracle:
    client_lib_dir: C:\oracle\instantclient_23_26
```

`sopuli doctor` shows whether the client loaded, in its `client` section (§7).

---

## 4. Start Oracle and Vault

From `test/`:

```bash
docker compose --profile tier1 up -d
```

Oracle takes about a minute to report `healthy` in `docker ps`. Vault is ready in
seconds.

- Vault: `http://127.0.0.1:8200`, root token `sopuli-test-root`.
- Oracle: `127.0.0.1:1521/FREEPDB1`, user `SYSTEM`, password `sopuli-test`.

Two things to know about this stack:

- **`docker compose down` does nothing here.** Every service has a profile. Stop
  the stack with `docker compose --profile '*' down`.
- **Vault keeps its data in memory.** A restart loses the `kv` mounts. After a
  `stop` and `start`, run `docker compose --profile tier0 up -d vault-init` to
  create them again.

The container has no application accounts. Save this as `accounts.sql`. The
first line is the logon. SQL\*Plus reads it from stdin, so the password is not
on a command line.

```sql
system/sopuli-test@localhost:1521/FREEPDB1
CREATE USER acme_app_user   IDENTIFIED BY "Placeholder#1";
CREATE USER acme_batch_user IDENTIFIED BY "Placeholder#1" PROFILE sopuli_rollover;
CREATE USER acme_priv_user  IDENTIFIED BY "Placeholder#1";
CREATE USER acme_dev_alice  IDENTIFIED BY "Placeholder#1";
CREATE USER acme_dev_bob    IDENTIFIED BY "Placeholder#1";
GRANT CREATE SESSION TO acme_app_user, acme_batch_user, acme_priv_user, acme_dev_alice, acme_dev_bob;
GRANT DBA TO acme_priv_user;
```

Then run it with the container's own SQL\*Plus:

```bash
docker exec -i sopuli-test-oracle-free-1 sqlplus -S < accounts.sql
```

The accounts are used like this:

| Account | Used for |
|---|---|
| `acme_app_user` | application credentials (§8) |
| `acme_batch_user` | the same, with the `SOPULI_ROLLOVER` profile, so a password change opens a rollover window |
| `acme_priv_user` | holds `DBA`, so the tool refuses it (§10) |
| `acme_dev_alice`, `acme_dev_bob` | personal accounts (§9) |

The guide uses the vault CLI inside the container. This alias saves typing:

```bash
alias vault='docker exec -i -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=sopuli-test-root sopuli-test-vault-1 vault'
```

---

## 5. A config file

Save this as `sopuli.yaml`, outside the repository:

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

policies:
  standard:
    password:
      length: 24
      charset: alnum_safe
      first_char: alpha
      require: { upper: 1, lower: 1, digit: 1, special: 1 }

applications:
  - name: acme
    accounts: [acme_app_user, acme_batch_user]
    secret_template: "vault-dev:acme/{env}/{application}#DB_CREDENTIALS/{account}"

personal_accounts:
  - accounts: [acme_dev_alice, acme_dev_bob]

delivery:
  method: vault_wrapped
  vault_wrapped:
    ttl: 15m

reset_records:
  vault: vault-dev
  prefix: sopuli/personal-resets
```

[`design/01-configuration.md`](design/01-configuration.md) is the reference for
every key.

### The permission check

The tool refuses a config file that other users can read or write. The file
holds no secrets, but anyone who can change it can point `secret_template` at a
vault path they control. A new file on Windows often inherits a grant to other
users:

```
$ sopuli --config sopuli.yaml config validate
sopuli: sopuli.yaml: config file is accessible to NT AUTHORITY\INTERACTIVE
  hint: remove the extra grant, e.g. icacls "<file>" /inheritance:r /grant:r "%USERNAME%:R"
```

Exit 9. Remove the inherited grants and give yourself full control:

```powershell
icacls sopuli.yaml /inheritance:r /grant:r "$($env:USERNAME):F"   # PowerShell
```
```bash
chmod 600 sopuli.yaml                                             # WSL or Linux
```

In Git Bash, put `MSYS_NO_PATHCONV=1` in front of `icacls`. Otherwise Git Bash
rewrites `/grant` into a file path.

### Commands that open no connection

These work with Docker stopped.

```
$ sopuli --config sopuli.yaml config validate
config: sopuli.yaml

ok: 1 target, 2 bindings, 0 warnings
```

```
$ sopuli --config sopuli.yaml target list
config: sopuli.yaml

NAME      DSN                      ENV  SCOPE  SOURCE
free-pdb  127.0.0.1:1521/FREEPDB1  dev  pdb    targets

1 target (1 explicit)
```

`config show --explain` prints the whole configuration, and then each effective
setting with the layer it came from:

```
$ sopuli --config sopuli.yaml config show --explain
...
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

Set `VAULT_ADDR` or `SOPULI_OUTPUT=json` and run it again to see a layer change.

`policy sample` shows what a policy produces. It prints the shape of each sample,
not the password:

```
$ sopuli --config sopuli.yaml policy sample
config: sopuli.yaml
policy: standard    length 24, alnum_safe, first_char alpha, require digit 1, lower 1, special 1, upper 1

#  CHARS  BYTES  CLASSES
1  24     -      u8 l11 d4 s1
2  24     -      u6 l9 d2 s7
3  24     -      u10 l8 d4 s2

3 samples, all compliant. Not stored anywhere; pass --reveal to print them.
```

---

## 6. The vault token

A vault token is never a command-line value. The tool reads it from
`--vault-token-file`, `SOPULI_VAULT_TOKEN`, `VAULT_TOKEN`, or `~/.vault-token`.
Without one:

```
$ sopuli --config sopuli.yaml lock status
sopuli: vault "vault-dev": no token, and none of the places it is looked for had one
  hint: write `token: { file: … }` on the store, or supply one of: --vault-token-file PATH, $SOPULI_VAULT_TOKEN, $VAULT_TOKEN, or `vault login` so that ~/.vault-token exists
```

Exit 9. A token the vault rejects is exit 6 instead:

```
$ VAULT_TOKEN=not-a-token sopuli --config sopuli.yaml lock status
sopuli: the store refused this token at 'locks/': 2 errors occurred:
	* permission denied
	* invalid token


  hint: check the token's policy for this path, and that it has not expired
```

Set the token for the rest of the guide:

```
$ export VAULT_TOKEN=sopuli-test-root
$ sopuli --config sopuli.yaml lock status
config: sopuli.yaml
mode:   cas

0 of 1 declared lock paths held
```

`mode: cas` means the store supports compare-and-set, so two runs cannot both
take the same lock.

---

## 7. `doctor`

`doctor` connects to every target and every vault, and changes nothing. The
config reads the admin password from `SOPULI_DB_ADMIN_PASSWORD`. Without it, the
target is unreachable:

```
$ sopuli --config sopuli.yaml doctor
...
TARGET    REACHABLE  SCOPE  CONTAINER  OPEN MODE  CAPABILITIES
free-pdb  no         -      -          -          -
  free-pdb: target 'free-pdb' admin credential: the environment variable SOPULI_DB_ADMIN_PASSWORD is not set
```

Exit 1. Set it and run again:

```
$ export SOPULI_DB_ADMIN_PASSWORD=sopuli-test
$ sopuli --config sopuli.yaml doctor
install
  KIND     NAME       STATUS           CONFIGURED
  backend  file       not_implemented  -
  backend  hashicorp  installed        vault-dev
  backend  keyring    not_implemented  -
  backend  oci        not_implemented  -
  driver   oracle     installed        1 target

vaults
  VAULT      TYPE       STATUS  AUTH  SKEW
  vault-dev  hashicorp  ok      yes   -991ms

client
  tns_admin         (unset)
  instant_client    23.26.3.0.0
  reaches           19.1 and later

TARGET    REACHABLE  SCOPE  CONTAINER  OPEN MODE   CAPABILITIES
free-pdb  yes        pdb    FREEPDB1   READ WRITE  7

1 note:
  free-pdb: the admin credential came from the environment variable SOPULI_DB_ADMIN_PASSWORD, which P2 supports and flags as low assurance
```

The note is `SOPULI-W022`. Every verb that connects puts it in the JSON output,
and only `doctor` prints it. `--output json` lists the capabilities by name.

`doctor --check-privileges` also lists privileges the admin account holds and
the tool does not need. Against `SYSTEM` that list is long. For a realistic
setup, create the least-privilege service account with
[`../sql/oracle/00_install.sql`](../sql/oracle/00_install.sql), and point the
target at it.

---

## 8. Application credentials (UC-1)

The vault is the master copy of each password. The `creds` commands make the
database match the vault. [`use-cases/uc-01-app-credential-sync.md`](use-cases/uc-01-app-credential-sync.md)
specifies them.

Every command prints its plan first, and every command that changes something
takes `--dry-run`. The `STATE` column is coloured. The word is always printed
too, so `--color never` and `NO_COLOR=1` lose nothing:

<!-- checked-list: state-colours -->
| Looks like | Means | States |
|---|---|---|
| cyan | nothing to do | `IN_SYNC` |
| yellow | somebody has to act, the run is fine | `DRIFT`, `PENDING_APPLY`, `ROLLOVER_ACTIVE`, `VAULT_ONLY`, `RESET` |
| red, bold | the tool could not do the job, or the estate is not in a state it can | `ERROR`, `ACCOUNT_MISSING`, `LOCKED`, `EXPIRED` |
| dim | nothing could be concluded | `UNVERIFIABLE`, `SKIPPED`, `DECLARED` |

### 8.1 `status`: what is there

`status` reads the vault and the database dictionary. It does not log in as the
accounts.

```
$ sopuli --config sopuli.yaml creds status
Plan: 2 accounts x 1 target = 2 accounts   [dev]

ACCOUNT          TARGET    INTENT  SECRET
acme_app_user    free-pdb  none    vault-dev:acme/dev/acme
acme_batch_user  free-pdb  none    vault-dev:acme/dev/acme

shared secrets (1 document):
SECRET                   TARGETS   ACCOUNTS
vault-dev:acme/dev/acme  free-pdb  acme_app_user, acme_batch_user

ACCOUNT          TARGET    STATE         VAULT_V  AGE  DB_PW_CHANGED  PROFILE          ROLLOVER
acme_app_user    free-pdb  UNVERIFIABLE  -        -    2026-10-05     DEFAULT          not configured
acme_batch_user  free-pdb  UNVERIFIABLE  -        -    2026-10-05     SOPULI_ROLLOVER  60m configured

2 accounts, nothing to act on
```

The vault holds nothing yet, so `VAULT_V` is empty.

### 8.2 `generate`: stage a password in the vault

`generate` draws a password for each account and writes it to the vault's
`pending` stage. It changes no database.

```
$ sopuli --config sopuli.yaml creds generate
...
constraints: 128 bytes in AL32UTF8, from free-pdb

SECRET                   STAGE    ACCOUNTS
vault-dev:acme/dev/acme  pending  acme_app_user, acme_batch_user

ACCOUNT          SECRET                   RESULT
acme_app_user    vault-dev:acme/dev/acme  staged v1
acme_batch_user  vault-dev:acme/dev/acme  staged v1

2 staged; no database was changed -- run `sopuli creds apply` to use them
```

The `constraints` line is the byte limit the tool read from the target.

### 8.3 `apply`: put the password on the database

`apply` sets the `pending` password on each database, logs in with it, and then
promotes it to `current` in the vault.

```
$ sopuli --config sopuli.yaml creds apply
...
ACCOUNT          TARGET    SECRET                   SOURCE
acme_app_user    free-pdb  vault-dev:acme/dev/acme  pending
acme_batch_user  free-pdb  vault-dev:acme/dev/acme  pending

ACCOUNT          TARGET    STATE            DETAIL
acme_app_user    free-pdb  IN_SYNC          changed and verified by login
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  changed and verified; a rollover window is open, so the previous password authenticates until it closes

2 changed, 1 promoted to `current`
```

"1 promoted" counts vault documents, and both accounts share one.

Run it again. Nothing changes, because the database already has the vault's
password:

```
$ sopuli --config sopuli.yaml creds apply
...
ACCOUNT          TARGET    STATE            DETAIL
acme_app_user    free-pdb  IN_SYNC          the vault's password is already accepted; nothing to change
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  the vault's password is already accepted, and a rollover window is open: the previous password still works too

nothing changed
```

### 8.4 `finish-rollover`: close a rollover window

`acme_batch_user` has a profile with `PASSWORD_ROLLOVER_TIME`, so after a change
its old password also works for an hour. `finish-rollover` ends that window:

```
$ sopuli --config sopuli.yaml creds finish-rollover --confirm
...
ACCOUNT          TARGET    WINDOW
acme_app_user    free-pdb  none open
acme_batch_user  free-pdb  open, 59m left

ACCOUNT          TARGET    STATE    DETAIL
acme_app_user    free-pdb  IN_SYNC  no rollover window is open
acme_batch_user  free-pdb  IN_SYNC  rollover window closed, 59m early

1 closed
```

### 8.5 `check`: find drift

`check` logs in as each account with the vault's password. Change a password
behind the tool's back, then check:

```bash
printf '%s\n' 'system/sopuli-test@localhost:1521/FREEPDB1' \
  'ALTER USER acme_app_user IDENTIFIED BY "Changed-by-hand#1";' | \
  docker exec -i sopuli-test-oracle-free-1 sqlplus -S
```

```
$ sopuli --config sopuli.yaml creds check
...
ACCOUNT          TARGET    STATE    DETAIL
acme_app_user    free-pdb  DRIFT    vault v2 the database rejected this password (ORA-01017): ORA-01017: invalid credential or not authorized; logon denied
acme_batch_user  free-pdb  IN_SYNC  vault v2 verified by login

1 drift
```

Exit 3 means drift. `apply` repairs it from the vault's `current`:

```
$ sopuli --config sopuli.yaml creds apply
...
ACCOUNT          TARGET    STATE    DETAIL
acme_app_user    free-pdb  IN_SYNC  changed and verified by login
acme_batch_user  free-pdb  IN_SYNC  the vault's password is already accepted; nothing to change

1 changed
```

A login that fails counts toward the account's lockout limit. `--method hash`
compares the password with the account's verifier instead, and needs no login:

```
$ sopuli --config sopuli.yaml creds check --method hash
...
ACCOUNT          TARGET    STATE    DETAIL
acme_app_user    free-pdb  IN_SYNC  vault v2 verified by hash; matches the account's current 12C verifier, with no login attempted
acme_batch_user  free-pdb  IN_SYNC  vault v2 verified by hash; matches the account's current 12C verifier, with no login attempted

all 2 in sync
```

### 8.6 `rotate`: generate and apply in one run

`rotate` asks for confirmation. With no terminal to ask on, it refuses:

```
$ sopuli --config sopuli.yaml creds rotate < /dev/null
sopuli: rotating a password needs confirmation, and there is nobody here to ask
  hint: pass --confirm to answer in advance, or --dry-run to see the plan without touching anything
```

Exit 8. With `--confirm`:

```
$ sopuli --config sopuli.yaml creds rotate --confirm
...
ACCOUNT          TARGET    STATE            DETAIL
acme_app_user    free-pdb  IN_SYNC          changed and verified by login
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  changed and verified; a rollover window is open, so the previous password authenticates until it closes

2 changed, 1 promoted to `current`

rotation: staged 1 document, promoted 1 document
```

### 8.7 Roll back

The vault keeps the password `current` held before, as `previous`. Applying it
rolls back:

```
$ sopuli --config sopuli.yaml creds apply --source previous --confirm
...
ACCOUNT          TARGET    SECRET                   SOURCE
acme_app_user    free-pdb  vault-dev:acme/dev/acme  previous
acme_batch_user  free-pdb  vault-dev:acme/dev/acme  previous

ACCOUNT          TARGET    STATE            DETAIL
acme_app_user    free-pdb  IN_SYNC          changed and verified by login
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  the vault's password is already accepted, and a rollover window is open: the previous password still works too

1 rolled back, 1 promoted to `current`
```

`acme_batch_user` needs no change: its rollover window is still open, so the old
password still works.

---

## 9. Personal accounts (UC-2)

A personal account belongs to a person. The vault is not its master copy: the
tool hands a new password to the person and keeps no copy.
[`use-cases/uc-02-personal-account-passwords.md`](use-cases/uc-02-personal-account-passwords.md)
specifies these commands.

### `account list`

`list` shows the accounts `personal_accounts:` declares, as the database sees
them:

```
$ sopuli --config sopuli.yaml account list
ACCOUNT         TARGET    DECLARED BY  STATUS  DB_PW_CHANGED  RESET_AT
ACME_DEV_ALICE  free-pdb  names        OPEN    2026-10-05     -
ACME_DEV_BOB    free-pdb  names        OPEN    2026-10-05     -

2 declared accounts, 2 on the selected targets
```

`personal_accounts:` can also select accounts by a database profile or role, with
`profile:` or `role:` instead of `accounts:`. `list` is how you see which
accounts that selects.

### `account reset-password`

This config delivers by `vault_wrapped`. The tool sets a new password, wraps it in
a single-use Vault token, and prints the token. You never see the password.

```
$ sopuli --config sopuli.yaml account reset-password --account acme_dev_alice
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT         TARGET    INTENT        SECRET
acme_dev_alice  free-pdb  password_set  -

ACCOUNT         TARGET    STATE  WAS   DETAIL
acme_dev_alice  free-pdb  RESET  OPEN  declared by accounts 'acme_dev_alice', 'acme_dev_bob'

reset acme_dev_alice on 1 of 1 targets

hand this to acme_dev_alice for free-pdb; it unwraps once:

    <TOKEN>

It stops working at 2026-10-05T16:12:59.524979Z, and the first unwrap is the
last. Do not unwrap it to check -- that spends the person's one read, and
them finding it spent is the only warning either of you gets.
```

`SECRET` is `-`, because no vault document holds a personal password. Add
`--dry-run` to see the plan without resetting.

The person unwraps the token once:

```
$ vault unwrap -format=json <TOKEN>
{
  "request_id": "888f02b2-7a7a-4db1-ed78-715c5f62d726",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "account": "acme_dev_alice",
    "password": "<PASSWORD>",
    "target": "free-pdb"
  },
  "warnings": null,
  "mount_type": "system"
}
```

A second unwrap fails. If the person finds the token already spent, somebody else
read it.

```
$ vault unwrap <TOKEN>
Error unwrapping: Error making API request.

URL: PUT http://127.0.0.1:8200/v1/sys/wrapping/unwrap
Code: 400. Errors:

* wrapping token is not valid or does not exist
```

The reset is recorded under `reset_records:`, and `list` shows when:

```
$ sopuli --config sopuli.yaml account list
ACCOUNT         TARGET    DECLARED BY  STATUS  DB_PW_CHANGED  RESET_AT
ACME_DEV_ALICE  free-pdb  names        OPEN    2026-10-05     2026-10-05T15:57:59.559643Z
ACME_DEV_BOB    free-pdb  names        OPEN    2026-10-05     -

2 declared accounts, 2 on the selected targets
```

A reset draws a new password every time, so running it twice resets twice.

### The seen path

With this `delivery:` block, the tool prints the password on your terminal once
and expires it, so the owner must change it at first logon:

```yaml
delivery:
  method: manual
  manual:
    force_expire: true
```

It asks for confirmation every time, and `--confirm` does not answer the prompt.
It refuses when stdout is not a terminal, or when the output is JSON. UC-2 §6.5
lists its guards. This run used a config with no `reset_records:` block, so it
ends with a note:

```
$ sopuli account reset-password --account acme_dev_alice
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT         TARGET    INTENT        SECRET
acme_dev_alice  free-pdb  password_set  -
show the new password for acme_dev_alice on free-pdb on this terminal? [y/N]: y
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT         TARGET    INTENT        SECRET
acme_dev_alice  free-pdb  password_set  -

ACCOUNT         TARGET    STATE  WAS   DETAIL
acme_dev_alice  free-pdb  RESET  OPEN  declared by accounts 'acme_dev_alice'

reset acme_dev_alice on 1 of 1 targets


1 note:
  no `reset_records:` block is declared, so no record of this reset will be written and no advisory lock is taken on the account: the run document and the database are the whole record of it

password for acme_dev_alice, shown once:

    <PASSWORD>

It is expired: the owner must change it at first logon, which is what ends
your sight of it. It is not stored anywhere and will not be shown again.
```

The prompt comes after the password is set. Answer `n` and the account keeps a
password nobody has seen; reset it again to fix that.

The plan appears twice. The first copy goes to stderr before anything changes,
so a run that fails part way still shows what it was about to touch. The second
is part of the result on stdout.

### `account expire-password`

This makes the person change their password at the next logon:

```
$ sopuli --config sopuli.yaml account expire-password --account acme_dev_alice --confirm
...
ACCOUNT         TARGET    STATE    STATUS  DETAIL
acme_dev_alice  free-pdb  EXPIRED  OPEN    account was open; password expired

expired acme_dev_alice's password on 1 of 1 targets
```

A second run changes nothing:

```
ACCOUNT         TARGET    STATE    STATUS   DETAIL
acme_dev_alice  free-pdb  EXPIRED  EXPIRED  the password is already expired

acme_dev_alice's password was already expired on 1 of 1
```

### `account suspend`

This locks the account, for example when a person leaves:

```
$ sopuli --config sopuli.yaml account suspend --account acme_dev_bob --confirm
...
ACCOUNT       TARGET    STATE   STATUS  DETAIL
acme_dev_bob  free-pdb  LOCKED  OPEN    account was open; locked

suspended acme_dev_bob on 1 of 1 targets
```

A second run changes nothing:

```
ACCOUNT       TARGET    STATE   STATUS  DETAIL
acme_dev_bob  free-pdb  LOCKED  LOCKED  the account is already locked

acme_dev_bob was already locked on 1 of 1
```

---

## 10. Refusals worth seeing once

### An account with too much privilege

The tool refuses to change an account that holds `DBA` or a similar privilege.
Copy `sopuli.yaml` to `priv.yaml`, add `acme_priv_user` to the `acme`
application, and run `creds generate` and then `creds apply`:

```
$ sopuli --config priv.yaml creds apply
...
ACCOUNT          TARGET    STATE            DETAIL
acme_app_user    free-pdb  IN_SYNC          changed and verified by login
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  changed and verified; a rollover window is open, so the previous password authenticates until it closes
acme_priv_user   free-pdb  SKIPPED          the account holds DBA

2 changed, 1 promoted to `current`, 1 not confirmed
```

Exit 0. The tool skips the account and does the rest of the job. Name the account
on the command line, and the same refusal fails the run, because you asked for
exactly that account:

```
$ sopuli --config priv.yaml creds apply --account acme_priv_user
...
ACCOUNT         TARGET    STATE  DETAIL
acme_priv_user  free-pdb  ERROR  the account holds DBA -- you named this account, so the run stopped short: pass --force to override, which is recorded

nothing changed, 1 not confirmed
```

Exit 1. [`design/02-oracle-privileges.md`](design/02-oracle-privileges.md) §4
lists the guardrails.

### An account the config does not declare

A selector narrows the declared accounts. It cannot add one:

```
$ sopuli --config sopuli.yaml creds status --account nosuch
sopuli: --account: name not declared in the configuration: `nosuch`
  hint: the configuration declares acme_app_user, acme_batch_user -- a selector filters the declared set and cannot extend it (invariant 5)
```

Exit 2.

### A lock somebody else holds

Every command that changes a password first takes a lock in the vault. To see a
held lock, write one by hand. Save this as `held.json`, with an `expires_at` in
the future:

```json
{"state":"held","command":"creds rotate","correlation_id":"11111111-2222-3333-4444-555555555555","acquired_at":"2026-10-05T12:00:00.000000Z","expires_at":"2026-10-06T23:59:00.000000Z","holder":{"host":"beta.example.com","os_user":"someone-else","pid":1234}}
```

The write must name the lock path's current version. Read it, then write:

```bash
ver=$(vault kv metadata get -mount=kv locks/acme/dev/acme | awk '/^current_version/ {print $2}')
vault kv put -mount=kv -cas="$ver" locks/acme/dev/acme - < held.json
```

`lock status` now shows the lock as held:

```
$ sopuli --config sopuli.yaml lock status
config: sopuli.yaml
mode:   cas

LOCK                     STATE  HOLDER                        COMMAND       SINCE                 EXPIRES
vault-dev:acme/dev/acme  held   someone-else@beta.example...  creds rotate  2026-10-05T12:00:00Z  2026-10-06T23:59:00Z

personal-account resets, under the prefix this config declares:
LOCK                                                      STATE     HOLDER              COMMAND           SINCE                        EXPIRES
vault-dev:sopuli/personal-resets/free-pdb/acme_dev_alice  released  op@ws1.example.com  account reset...  2026-10-05T15:57:59.277759Z  2026-10-05T16:12:59.277759Z

1 of 1 declared lock paths held; 1 reset lock under the declared prefix (0 held)
```

`check` changes nothing and takes no lock, so it still runs. `apply` stops:

```
$ sopuli --config sopuli.yaml creds apply
sopuli: vault-dev:acme/dev/acme is locked by someone-else@beta.example.com pid 1234 running creds rotate
  hint: wait for it to finish, or coordinate with whoever is running it
```

Exit 7. `lock break` refuses too, because the lock has not expired:

```
$ sopuli --config sopuli.yaml lock break vault-dev:acme/dev/acme --confirm
sopuli: vault-dev:acme/dev/acme is held by someone-else@beta.example.com pid 1234 running creds rotate and has not expired
  hint: wait for it to finish, or coordinate with whoever is running it. `--force` breaks a lock that is still live -- the holder is fenced and stops at its next check, having applied whatever it applied
```

Exit 7. `--force` breaks it:

```
$ sopuli --config sopuli.yaml lock break vault-dev:acme/dev/acme --force --confirm
...
broke this lock at version 19; someone-else@beta.example.com pid 1234 running creds rotate is fenced at version 20 and stops at its next check
```

The two version numbers are the fence. Before its next change, the old holder
reads the lock again, finds version 20, and stops.

---

## 11. JSON output

`--output json` prints one JSON document for the run.
[`design/03-json-output.md`](design/03-json-output.md) specifies it, and the
schemas are in [`schemas/`](schemas/). For example, read the summary with Python:

```
$ sopuli --config sopuli.yaml --output json creds check > check.json
$ python -c "import json; d=json.load(open('check.json')); print(d['schema_version'], d['exit_code'], d['summary'])"
1.31 0 {'total': 2, 'ok': 1, 'changed': 0, 'failed': 0, 'unchanged': 2, 'drift': 0, 'unverifiable': 0, 'by_state': {'IN_SYNC': 1, 'ROLLOVER_ACTIVE': 1}}
```

No field holds a password. Every exit code except 2 produces a document.

`--output jsonl` prints one event per line, as the run happens. `creds check`,
`creds apply`, `creds rotate`, `creds generate` and `account reset-password` take
it. The last event carries the summary and the exit code:

```
$ sopuli --config sopuli.yaml creds check --output jsonl
{"schema_version":"1.7","event":"run.started","seq":0,"ts":"2026-10-05T15:58:22.185206Z","correlation_id":"53889e6d-f4ef-4f23-8512-8e424124b0ee","data":{"command":"creds.check","dry_run":false}}
...
{"schema_version":"1.7","event":"run.finished","seq":6,"ts":"2026-10-05T15:58:23.173547Z","correlation_id":"53889e6d-f4ef-4f23-8512-8e424124b0ee","data":{"summary":{"total":2,"ok":1,"changed":0,"failed":0,"unchanged":2,"drift":0,"unverifiable":0,"by_state":{"IN_SYNC":1,"ROLLOVER_ACTIVE":1}},"exit_code":0}}
```

Other commands refuse it:

```
$ sopuli --config sopuli.yaml config show --output jsonl
sopuli: --output (verb): `config show` does not stream, so it has no jsonl output
  hint: use --output json for the same run as one document; jsonl is offered by: account reset-password, creds apply, creds check, creds generate, creds rotate
```

---

## 12. Exit codes

Scripts can branch on these. P5 in
[`design/00-principles.md`](design/00-principles.md) defines them.

| Code | Meaning | Example in this guide |
|---|---|---|
| 0 | success, or nothing to do | most runs |
| 1 | failure | `doctor` with no admin password (§7); a named account the guardrails refuse (§10) |
| 2 | the command line is wrong; no JSON document | `--account nosuch` (§10); `--output jsonl` on `config show` (§11) |
| 3 | `check` found drift | §8.5 |
| 4 | partial: some of the work succeeded, some failed | not shown |
| 5 | a target lacks a capability the command needs | not shown |
| 6 | authentication failed | a token the vault rejects (§6) |
| 7 | a lock is held | §10 |
| 8 | aborted, or confirmation declined | `rotate` with nobody to confirm (§8.6) |
| 9 | the configuration is unusable | file permissions (§5); no vault token (§6) |

---

## 13. Cleanup

To throw everything away, stop the stack from `test/`:

```bash
docker compose --profile '*' down
```

To keep the containers, remove only what this guide created. Save this as
`cleanup.sql` and run it as in §4:

```sql
system/sopuli-test@localhost:1521/FREEPDB1
DROP USER acme_app_user CASCADE;
DROP USER acme_batch_user CASCADE;
DROP USER acme_priv_user CASCADE;
DROP USER acme_dev_alice CASCADE;
DROP USER acme_dev_bob CASCADE;
```

Then delete the vault paths. The application secret, the reset record, and a lock
for each:

```bash
vault kv metadata delete -mount=kv acme/dev/acme
vault kv metadata delete -mount=kv locks/acme/dev/acme
vault kv metadata delete -mount=kv sopuli/personal-resets/free-pdb/acme_dev_alice
vault kv metadata delete -mount=kv locks/sopuli/personal-resets/free-pdb/acme_dev_alice
```

`vault kv list -mount=kv` then answers `No value found at kv/metadata`. Finally,
delete `sopuli.yaml`, `priv.yaml`, `held.json` and the two SQL files.

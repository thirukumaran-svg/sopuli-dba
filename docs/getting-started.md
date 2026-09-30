# Getting started

This is a first run, from nothing to one working command. It assumes you know
Oracle and it does **not** assume you have installed a Python program before.

By the end you will have installed the tool, written a config file, checked that
the file is valid, and previewed a change without making one.

**Do this against a test database.** The tool is pre-alpha, and the last step of
this guide is deliberately a preview rather than a change.

What you need before you start:

- **Python 3.11 or newer** on the machine you are working from.
- **Oracle Instant Client**, which is Oracle's set of client libraries. This is
  not optional — section 2 explains why.
- **An Oracle database** you may change a password on, and an admin account that
  can do it.
- **A HashiCorp Vault** you can write to. A *vault* is a server built to store
  secrets and hand them out to the applications that need them; HashiCorp Vault
  is the one this build supports. If you have none, section 1 gives you a
  throwaway one in a container.

Everything below was run on Windows 11 with sopuli 0.58.0 and Instant Client
23.26.3.0.0, against the project's own test containers. The output shown is what
those runs printed.

That version is a **record of what the capture printed**, not a claim about what
this build is at — it is supposed to name an old release, and it moves when the
samples are re-captured rather than when a version is cut. Do not "correct" it to
the current number: `pyproject.toml` owns that number, and `sopuli --version`
reports the *installed distribution's* version, which under an editable install
can itself lag the tree — see [`local-testing.md`](local-testing.md) §3, which
keeps the same kind of per-sample note.

---

## 1. Get a database and a vault, if you do not have them

Skip this if you already have both. Otherwise the repository ships a container
stack that gives you an Oracle database and a Vault, neither of which installs
anything on your machine. You need Docker.

```bash
git clone https://github.com/villebase/sopuli-dba.git
cd sopuli-dba/test
# Start Oracle Free and Vault. Oracle takes about 30-60 seconds to become
# healthy the first time; Vault is ready in seconds.
docker compose --profile tier1 up -d
```

That gives you:

| | |
|---|---|
| Oracle | `127.0.0.1:1521/FREEPDB1`, admin account `SYSTEM`, password `sopuli-test` |
| Vault | `http://127.0.0.1:8200`, root token `sopuli-test-root` |

Neither is secure and neither survives a restart of the container. That is the
point: it is a sandbox.

Create an account for this guide to manage. It has to exist already — this tool
changes passwords, it does not create accounts. Save this as `accounts.sql`:

```sql
CREATE USER acme_app_user IDENTIFIED BY "Placeholder#1" QUOTA UNLIMITED ON USERS;
GRANT CREATE SESSION TO acme_app_user;
EXIT
```

```bash
# Feed that file to the container's own sqlplus, so you need no client installed.
docker exec -i sopuli-test-oracle-free-1 \
  sqlplus -S system/sopuli-test@localhost:1521/FREEPDB1 < accounts.sql
```
```
User created.

Grant succeeded.
```

Details of the stack, including the two ways tearing it down surprises people,
are in [`../test/README.md`](../test/README.md).

---

## 2. Install the tool

### 2a. Make a virtual environment

A *virtual environment* is a private folder holding one project's Python
packages, so installing something for this tool cannot disturb anything else on
the machine. Making one is two commands, and you make it wherever you like:

```bash
python -m venv .venv
```

Then *activate* it, which points the `python` and `pip` commands at that folder
for the rest of your terminal session:

```powershell
.venv\Scripts\Activate.ps1        # Windows PowerShell
```
```bash
source .venv/bin/activate         # Linux, macOS, WSL
```

You will need to activate it again in every new terminal window.

### 2b. Install sopuli-dba

`pip` is the program that installs Python packages. Nothing is published to PyPI
— the public index `pip` normally downloads from — yet, so you install from a
copy of the repository:

```bash
git clone https://github.com/villebase/sopuli-dba.git
cd sopuli-dba
# Install this checkout, plus the two optional parts named in the brackets:
# the Oracle driver and the HashiCorp Vault client.
pip install ".[oracle,hashicorp]"
```

Those names in square brackets are *extras* — Python packaging's word for an
optional part of a package that brings its own dependencies. This tool installs
nothing that talks to a vendor unless you ask for it, so a site with no OCI never
inherits the OCI SDK's version constraints. The reasoning is in
[ADR-006](decisions/adr-006-optional-dependencies.md).

Check it arrived:

```bash
sopuli --version
```
```
sopuli, version 0.58.0
```

### 2c. Install Oracle Instant Client

**This one is mandatory and there is no configuration that avoids it.** The
Oracle driver can run in two modes. Thin mode needs no Oracle libraries, but it
cannot do three things this tool needs: Native Network Encryption, which a
database can be configured to require; a connection to Oracle 11.2; and a logon
through an external password store (`auth: external`). So
this tool always uses thick mode, and thick mode needs Oracle's client libraries
present on the machine.

(If your database is an Autonomous Database, it is not the first of those that
applies to you — Autonomous encrypts with TLS, not Native Network Encryption
(unverified: adb-thin-mode). The client is needed all the same.)

Download **Basic** from Oracle's Instant Client downloads page. (Take
**SQL\*Plus** as well if you want a command-line SQL client for sanity checks;
the tool does not need it.)

- **Windows** — unzip to a path with no spaces, for example
  `C:\oracle\instantclient_23_26`. Then either add that folder to your `PATH`, or
  name it in the config file you are about to write:

  ```yaml
  runtime:
    oracle:
      client_lib_dir: C:\oracle\instantclient_23_26
  ```

- **Linux, WSL** — unzip to `/opt/oracle/instantclient_23_26`, install the
  `libaio1` package, and either set the `LD_LIBRARY_PATH` environment variable to
  that folder or use `client_lib_dir` as above.

---

## 3. Write your first config file

The config file is the whole point of the tool, so it is worth understanding
rather than pasting. It is written in *YAML*, a plain-text format for structured
data where indentation shows what belongs inside what.

The file says four things: which vaults may be used, which databases may be
touched, what a password has to look like, and which account's password lives
where. Save this as `sopuli.yaml`, in a folder of your own — **not** inside the
repository:

```yaml
version: 1

# The secret stores this file is allowed to use. One entry per store.
vaults:
  vault-dev:
    type: hashicorp
    addr: http://127.0.0.1:8200
    mount: kv
    kv_version: 2
    auth: { method: token }

# Settings every part of this file inherits unless it says otherwise.
defaults:
  vault: vault-dev

# The databases this file is allowed to touch. One entry per endpoint.
targets:
  - name: free-pdb
    type: oracle
    environment: dev
    dsn: "127.0.0.1:1521/FREEPDB1"
    admin: { username: SYSTEM, auth: { method: env } }
    oracle: { scope: pdb, container: FREEPDB1 }

# The rules a generated password has to satisfy.
policies:
  standard:
    password:
      length: 24
      charset: alnum_safe
      first_char: alpha
      require: { upper: 1, lower: 1, digit: 1, special: 1 }

# The one account this file manages, and where its password is mastered.
accounts:
  - acme_app_user
secret_template: "vault-dev:acme/{env}/db#DB_CREDENTIALS/{account}"
policy: standard
```

Four parts of it are worth a sentence each.

**`admin: { username: SYSTEM, auth: { method: env } }`** — how the tool logs in to
the database as an administrator. `method: env` means the password comes from an
environment variable, not from this file. **No password is ever written in this
file.** Section 4 sets that variable.

**`accounts:`** — the list of database accounts this tool is allowed to touch, and
it is a whitelist rather than a starting point. The tool will never change an
account that is not named here. Command-line options can narrow this list; nothing
can extend it.

**`secret_template:`** — where each account's password is mastered in the vault.
Read `vault-dev:acme/{env}/db#DB_CREDENTIALS/{account}` in three pieces: the store
name before the colon, then the path to a document inside it, then after the `#`
the field inside that document. `{env}` and `{account}` are filled in per target
and per account, so one line covers an estate. For the account and target above
it resolves to `vault-dev:acme/dev/db`, field `DB_CREDENTIALS/acme_app_user`.

**The file has no `applications:` section**, because there is only one
application here. With two or more, the four binding keys at the bottom
(`accounts`, `secret_template`, `policy`, `overrides`) move into an
`applications:` list, one entry each. The full reference is
[`design/01-configuration.md`](design/01-configuration.md).

### The file's permissions matter, and will stop you first

The tool refuses to read a config file that other people on the machine can
reach. This is not about confidentiality — the file holds no secrets. It is about
tampering: anyone who can write this file can repoint `secret_template` at a path
they control, and the tool would then faithfully rotate a production password into
it.

A file you just created will usually fail that check:

```
sopuli: sopuli.yaml: config file is accessible to BUILTIN\Users
  hint: remove the extra grant, e.g. icacls "<file>" /inheritance:r /grant:r "%USERNAME%:R"
```

The exit code is 9, which means *fix your config*. Fix it with:

```powershell
# Windows: drop inherited permissions, then grant only yourself.
icacls sopuli.yaml /inheritance:r /grant:r "${env:USERNAME}:F"
```
```bash
# Linux, WSL: owner only, nobody else at all.
chmod 600 sopuli.yaml
```

Note for later: editing the file with a tool that replaces it rather than writing
in place can restore the inherited permissions, and the same error comes back.
Re-run the command above if it does.

---

## 4. Tell the tool its passwords, without writing them down

Two credentials are needed at run time and neither belongs in a file you edit:
the token that authenticates you to the vault, and the database admin password.
Both come from environment variables.

```powershell
# Windows PowerShell
$env:VAULT_ADDR = "http://127.0.0.1:8200"
$env:VAULT_TOKEN = "sopuli-test-root"
$env:SOPULI_DB_ADMIN_PASSWORD = "sopuli-test"
```
```bash
# Linux, WSL
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=sopuli-test-root
export SOPULI_DB_ADMIN_PASSWORD=sopuli-test
```

These are the sandbox's throwaway values. On a real system the vault token would
come from `~/.vault-token` or a file named with `--vault-token-file`, and the
admin password from whatever your site already uses for that.

**No option to any command takes a password as its value**, here or anywhere
else. Command-line arguments are visible to every other user on the machine.
Where a flag has to name a secret it names the *file* the secret is in.

---

## 5. Check the file before you use it

```bash
sopuli --config sopuli.yaml config validate
```
```
config: sopuli.yaml

ok: 1 target, 1 binding, 0 warnings
```

This opens no network connection. It reads the file, checks every rule that can
be checked without asking anything, and tells you what it found. "1 binding"
means one account-to-secret pairing was resolved.

`config validate` warns rather than fails when your file names a backend this
machine cannot reach — the file is fine, the install is incomplete.

Two more commands that also connect to nothing, both worth running now:

```bash
# What databases does this file actually resolve to?
sopuli --config sopuli.yaml target list
```
```
config: sopuli.yaml

NAME      DSN                      ENV  SCOPE  SOURCE
free-pdb  127.0.0.1:1521/FREEPDB1  dev  pdb    targets

1 target (1 explicit)
```

```bash
# Every effective setting, and which layer of config produced it.
sopuli --config sopuli.yaml config show --explain
```
```
settings
  db.connect_timeout_s = 30         [built-in default]
  db.query_timeout_s   = 0          [built-in default]
  output               = text       [built-in default]
  safety.dry_run       = false      [built-in default]
  safety.readonly      = false      [built-in default]
  vault                = vault-dev  [defaults.vault]
```

`--explain` is the one to remember. Settings can arrive from several places at
once, and this is how you find out which one won.

---

## 6. Check that everything is reachable

```bash
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
  vault-dev  hashicorp  ok      yes   -279ms

client
  tns_admin         (unset)
  instant_client    23.26.3.0.0
  reaches           19.1 and later

TARGET    REACHABLE  SCOPE  CONTAINER  OPEN MODE   CAPABILITIES
free-pdb  yes        pdb    FREEPDB1   READ WRITE  6
```

`doctor` connects to everything your config names and reports what it found. Read
it in four parts:

- **install** — which backends this machine has code for, against which your
  config asks for. `not_implemented` means this build has no module for that
  backend yet, not that you installed something wrong.
- **vaults** — whether the store answered, whether your token authenticated, and
  how far its clock is from yours.
- **client** — whether Instant Client loaded, and which Oracle versions it can
  reach. If this says `instant_client  not loaded`, go back to section 2c; a
  `detail:` line underneath says why the library was not found. This part works
  with nothing else set up, so it is the first thing to run when something is
  wrong.
- **the target table** — whether each database answered, and whether it is where
  you said it was.

---

## 7. Ask what would happen, without making it happen

Now a command that changes something — except it will not, because of the flag.

```bash
sopuli --config sopuli.yaml creds generate --dry-run
```
```
Plan: 1 account x 1 target = 1 generation   [dev]

ACCOUNT        TARGET    INTENT                         SECRET
acme_app_user  free-pdb  generate, vault_write_pending  vault-dev:acme/dev/db

constraints: 128 bytes in AL32UTF8, from free-pdb

SECRET                 STAGE    ACCOUNTS
vault-dev:acme/dev/db  pending  acme_app_user

nothing was written (--dry-run)
```

`--dry-run` means: work out the whole plan, print it, change nothing. Every
command that changes something accepts it, and no setting can take it away from
you.

Read the plan from the top. `1 account x 1 target = 1 generation` is the blast
radius — how much this run would touch. The `INTENT` column is what would be done
to each row: draw a password, and write it into the vault as `pending`. Nothing
in that list touches the database, which is why `creds generate` is the safe
first verb.

The `constraints:` line is the one thing that will surprise you. `generate` does
connect — it asks each database how long a password may be in that database's own
character set, and the strictest answer governs the draw. It reads and never
writes. Pass `--offline` to skip asking, and the policy's declared length is used
instead.

Now drop the flag, if you are on a database you are happy to change:

```bash
sopuli --config sopuli.yaml creds generate
```
```
ACCOUNT        SECRET                 RESULT
acme_app_user  vault-dev:acme/dev/db  staged v1

1 staged; no database was changed -- run `sopuli creds apply` to use them
```

The password now exists in the vault, as `pending`. Applications read `current`,
which has not changed, so nothing has been disturbed. `creds apply` is what sets
it on the database and then promotes it — and that is the next document.

---

## 8. Where to go next

| Read this | For |
|---|---|
| [scenarios/rotate-and-sync.md](scenarios/rotate-and-sync.md) | the rest of this story: `apply`, `check`, rolling back, and closing a rollover window |
| [scenarios/kubernetes-eso.md](scenarios/kubernetes-eso.md) | letting applications in Kubernetes collect the new password by themselves |
| [../examples/](../examples/) | three complete config files, commented, from smallest to safety-hardened |
| [security-model.md](security-model.md) | what the tool can and cannot do, before you trust it with production |
| [design/01-configuration.md](design/01-configuration.md) | the full config reference — every key, every rule |
| [local-testing.md](local-testing.md) | every command this build has, and the failures worth causing on purpose |

---

## Troubleshooting the first run

| What you see | What it means |
|---|---|
| `config file is accessible to ...`, exit 9 | the file's permissions are too open. Section 3 has the fix |
| `instant_client  not loaded` in `doctor` | Instant Client is missing or not on the library path. Section 2c |
| `... declares type "oci", but that backend is not installed` | your config names a store this build or this install cannot serve. The message carries the `pip` line where there is one |
| `cannot be locked safely: its lock path does not require compare-and-set`, exit 5 | a vault housekeeping step, needed once per secret path. See [`local-testing.md`](local-testing.md) §8 |
| `VAULT_ADDR is set and was not applied` (a warning) | you have `VAULT_ADDR` in your environment and your config names no default store. Harmless if the variable belongs to something else; write `defaults.vault` to silence it |
| exit 3 from `creds check` | not an error. Exit 3 means drift was found — the vault's password does not work on the database. It has its own exit code so a scheduler can tell it apart from a failure |

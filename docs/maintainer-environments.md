# Maintainer environments

How to run sopuli against environments beyond the tier-1 stack: other Oracle
releases, OCI, wallets and WSL. Most of them need an Oracle account, a paid
tenancy or a particular host, so CI does not run them.

[`local-testing.md`](local-testing.md) is the usual path, and everything here
assumes you have done it once. [`measurements.md`](measurements.md) records what
ran on which release and what it showed. This document says how to set the
environment up.

---

## 1. Other Oracle releases in containers

`test/compose.yaml` has a service for each release. To use one, change the
target's `dsn:` and `oracle:` in the guide's config as the table says: the
service name, the container, and for 11g `scope: non_cdb` with no `container:`.
Everything else works unchanged.

| Release | Profile | Container | DSN | Notes |
|---|---|---|---|---|
| 26ai Free | `tier1` | `sopuli-test-oracle-free-1` | `127.0.0.1:1521/FREEPDB1` | the tier-1 database |
| 21c XE | `tier2` | `sopuli-test-oracle-xe21-1` | `127.0.0.1:1522/XEPDB1` | freely pullable |
| 18c XE | `tier2` | `sopuli-test-oracle-xe18-1` | `127.0.0.1:1523/XEPDB1` | freely pullable; no rollover |
| 11g XE | `tier2` | `sopuli-test-oracle-xe11-1` | `127.0.0.1:1524/XE` | freely pullable; **non-CDB**, so `scope: non_cdb` and no `container:`; no rollover; no unified auditing |
| 19.3 EE | `oracle19c` | `sopuli-test-oracle-19c-1` | `127.0.0.1:1526/ORCLPDB1` | pull it yourself (§2); no rollover |
| 19.19 EE | `oracle19c-ru` | `sopuli-test-oracle-19c-ru-1` | `127.0.0.1:1527/ORCLPDB1` | arm64 hosts only, never run (§4) |
| 12.2 EE | `oracle12c` | `sopuli-test-oracle-12c-1` | `127.0.0.1:1528/ORCLPDB1.localdomain` | pull it yourself (§3); no rollover; `WE8DEC` |

Start one with its profile, from `test/`:

```bash
docker compose --profile tier2 up -d oracle-xe21
```

One Instant Client 23.x reaches all of them. `doctor`'s client report prints
`reaches 19.1 and later` even on a run that has just reached an 18c or 11g
target. That line is Oracle's support statement, not a measurement.

Below Oracle 23, the password limit is 30 bytes, so a policy with `length:`
above 30 is refused at plan time on these releases. On 23 and later the limit is
128 bytes.

### Pointing the automated suite at another release

```bash
SOPULI_TEST_TIER1=required \
SOPULI_TEST_ORACLE_DSN=localhost:1522/XEPDB1 \
SOPULI_TEST_ORACLE_NAME="21c XE" \
SOPULI_TEST_ORACLE_CONTAINER=sopuli-test-oracle-xe21-1 \
SOPULI_TEST_ORACLE_PDB_SERVICE=XEPDB1 \
pytest
```

Set all five. `tests/driver/test_oracle_install_script.py` runs SQL\*Plus inside
the container named by `SOPULI_TEST_ORACLE_CONTAINER`, and connects to the PDB by
`SOPULI_TEST_ORACLE_PDB_SERVICE`. Both default to the tier-1 container, so if
you leave them unset, that module tests 26ai while the rest of the suite tests
the release you chose.

Without `SOPULI_TEST_TIER1=required`, a stopped container makes the tests skip
rather than fail. Wait for `healthy` after a start: the listener answers before
the PDB is open.

### Auditing is off in these images

The XE images and 19.3 ship with `AUDIT_TRAIL = NONE`, so nothing is audited.
Turn it on before you trust any audit result:

```sql
alter system set audit_trail=db,extended scope=spfile;
alter system set audit_sys_operations=true scope=spfile;
```

Then `docker restart` the container. Write the value unquoted, as two words:
`audit_trail='DB,EXTENDED'` fails with `ORA-00096`.

### 11.2 keeps the `ALTER USER` text

On 11.2, `V$SQLSTATS` keeps the text of the `ALTER USER` statement the tool
issues, password included. The service account cannot read that view; a
dictionary reader can. `ALTER SYSTEM FLUSH SHARED_POOL` clears it.
[`security-model.md`](security-model.md) §5 is what an operator is told, and
[`design/02-oracle-privileges.md`](design/02-oracle-privileges.md) §4 has the
measurements on each release.

To see it, rotate against `xe11`, read the password back from the vault, and run
`sql/oracle/02_password_leak_probe.sql`. Build any search pattern from two halves,
or your own query's text matches.

---

## 2. Oracle 19.3 EE

This image comes from Oracle's registry. It is not freely pullable and you cannot
redistribute it.

1. Sign in at <https://container-registry.oracle.com> with an Oracle account.
2. Open **Database → enterprise** and accept the licence. Without this, the pull
   is refused even when you are logged in.
3. Log Docker in. **Type the password at the prompt**; never pass `-p`, which
   puts it in your shell history and the process list.

```bash
docker login container-registry.oracle.com
docker pull container-registry.oracle.com/database/enterprise:19.3.0.0
cd test
docker compose --profile oracle19c up -d
```

The first start builds the database and takes about twenty minutes. Wait for
`DATABASE IS READY TO USE!` in `docker logs`. The datafiles are in a named
volume, so later starts take under a minute. `--profile '*' down -v` deletes the
volume, and the next start builds again.

This image keeps `COMMON_USER_PREFIX = C##`, as a real CDB does:

- the test profiles are created in `ORCLPDB1`, by `test/oracle-init-19c/`;
- a common account in `CDB$ROOT` needs the `C##` prefix.

On Windows, `docker exec … sqlplus / as sysdba` from Git Bash fails, because
Git Bash rewrites the bare `/` into a path. Set `MSYS_NO_PATHCONV=1` first, or use
PowerShell.

---

## 3. Oracle 12.2 EE

Same registry and same terms as 19.3.

```bash
docker pull container-registry.oracle.com/database/enterprise:12.2.0.1-slim
cd test
docker compose --profile oracle12c up -d
```

The database is open in about a minute and a half, but the container stays
`starting` until you run the init script once. The image has no hook to run it
for you:

```bash
docker exec sopuli-test-oracle-12c-1 bash /opt/sopuli/oracle-init-12c/init.sh
```

The script writes a password file, creates a `USERS` tablespace in `CDB$ROOT`,
and creates the test profiles. It writes a marker into the volume, so a recreated
container needs no second run. `down -v` removes the marker with the database.

Three differences from the other images:

- **The service names end in `.localdomain`.** `ORCLPDB1` alone is `ORA-12514`.
  `oracle: { container: ORCLPDB1 }` stays the bare name, because that is the
  container, not the service.
- **The character set is `WE8DEC`**, the only non-Unicode database in the stack.
- **`AUDIT_TRAIL` ships as `DB`.** Set `db,extended` before you trust an audit
  result.

---

## 4. Oracle 19.19 EE

`enterprise:19.19.0.0` is the only pullable 19c release past 19.12, so the only
one that can open a rollover window. It is built for linux/arm64 only. On an x86
host Docker runs it under emulation, and the instance does not start:

```
[WARNING] ORA-00443: background process "PMON" did not start
[FATAL] ORA-01034: ORACLE not available
```

Run it on an arm64 Docker host. Nobody has run it there, so treat the
`oracle19c-ru` service as untested. Clean up a failed attempt with
`docker compose --profile oracle19c-ru down -v`; that leaves 19.3's volume alone.

---

## 5. OCI Base Database Service

A Base Database Service DB system runs a current 19c release update and enforces
Native Network Encryption. It is not a container and it is not free: it bills per
ECPU-hour while the node runs, and for storage until you delete it.

`test/oci-dbcs/new-db-system.ps1` creates the smallest DB system the tenancy
offers: one `VM.BaseDB.x86` node with 4 ECPU, Enterprise Edition, CDB `ORCLCDB`
and PDB `ORCLPDB1`, in a VCN of its own. SSH is open to your address only, and
the listener to the VCN only.

**Run it from an interactive PowerShell window.** It asks for the SYS password
at a prompt, and refuses to run without a terminal.

```powershell
.\test\oci-dbcs\new-db-system.ps1 -CompartmentName <name>
```

It prints a plan and asks before it creates anything. Provisioning takes about
three quarters of an hour; Ctrl-C is safe, and a re-run goes on waiting. When it
is ready, it prints the service names. Copy them from that report: they carry the
subnet's domain, and the CDB's name is generated.

### Reaching the listener

Use `-Connect`. It creates an OCI Bastion in the DB system's subnet, opens a
three-hour port-forwarding session, and prints an `ssh` command:

```powershell
.\test\oci-dbcs\new-db-system.ps1 -CompartmentName <name> -Connect
```

Run that `ssh` command and leave it running. Then `127.0.0.1:1529` is the
listener. Port 1529 is the local end of the tunnel, because the stack's
containers use 1521 to 1528.

**`ssh -L` through the DB node does not work.** OCI disables TCP forwarding in
the node's sshd. The tunnel still opens and accepts a TCP connection, but every
database login through it fails: `DPY-4011` in thin mode, `ORA-12547` in thick
mode. That looks like an encryption failure and is not one. Only a login proves
the route.

SSH needs a running `ssh-agent`, or a passphrase typed at a prompt. On Windows,
`C:\Windows\System32\OpenSSH\ssh.exe` uses the Windows `ssh-agent` service; Git
Bash's `ssh` does not.

### Stopping and removing it

```powershell
.\test\oci-dbcs\new-db-system.ps1 -CompartmentName <name> -Stop       # stops ECPU billing; storage still bills
.\test\oci-dbcs\new-db-system.ps1 -CompartmentName <name> -Start
.\test\oci-dbcs\new-db-system.ps1 -CompartmentName <name> -Teardown   # deletes the DB system, bastion and network
```

`-Teardown` deletes only what the script made. If the VCN holds any subnet,
gateway or security list without the script's tag, it refuses and deletes
nothing. The database goes with the DB system, and there are no backups.

### What differs from a container

- **NNE is required.** The server's `sqlnet.ora` sets
  `SQLNET.ENCRYPTION_SERVER=REQUIRED`. Thick mode negotiates it with no client
  configuration; thin mode is refused with `DPY-3001`.
- **The `DEFAULT` profile is strict.** It has `ORA12C_STRONG_VERIFY_FUNCTION`,
  `FAILED_LOGIN_ATTEMPTS 3`, `PASSWORD_LIFE_TIME 60` and `PASSWORD_REUSE_MAX 5`.
  `generate` warns that it cannot evaluate the verify function, which wants two
  characters of each class. `check` logs in, against an account that locks
  after three failures.
- **Rollover works.** Create `SOPULI_ROLLOVER` in the PDB as
  `test/oracle-init/` does, and the guide's rollover steps run unchanged.

A run on 19.32.0.0.0, as the least-privilege service account:

```
TARGET   REACHABLE  SCOPE  CONTAINER  OPEN MODE   CAPABILITIES
oci-pdb  yes        pdb    ORCLPDB1   READ WRITE  6
```
```
ACCOUNT          TARGET   STATE            DETAIL
acme_batch_user  oci-pdb  ROLLOVER_ACTIVE  changed and verified; a rollover window is open, so the previous password authenticates until it closes

1 changed, 1 promoted to `current`
```
```
ACCOUNT          TARGET   WINDOW
acme_batch_user  oci-pdb  open, 58m left

ACCOUNT          TARGET   STATE    DETAIL
acme_batch_user  oci-pdb  IN_SYNC  rollover window closed, 58m early

1 closed
```

---

## 6. OCI Autonomous Database

An Autonomous Database encrypts with TLS, or mutual TLS, and uses no Native
Network Encryption.

### The service account

In SQL\*Plus as `ADMIN`, with `TNS_ADMIN` set to the unzipped wallet, install in
PDB mode with ADB's `DATA` tablespace:

```
SQL> @sql/oracle/00_install.sql PDB SOPULI_SVC DATA N N N
```

Set its password with SQL\*Plus's `PASSWORD SOPULI_SVC`, which never echoes, and
put the same value in the vault. Keep `grant_user_dollar` at `N`: `ADMIN` cannot
read `SYS.USER$` on ADB.

### The target

The container is the name `SYS_CONTEXT('USERENV','CON_NAME')` returns.

```yaml
targets:
  - name: adb-acme
    type: oracle
    environment: dev
    vault: vault-dev
    dsn: "acmedb_tp"
    admin:
      username: SOPULI_SVC
      auth: { method: vault, secret: "ops/sopuli/adb#password" }
    oracle: { scope: pdb, container: GXXXXXXXXXXXXXX_ACME }
```

What differs from a container:

- **`DEFAULT` names `CLOUD_VERIFY_FUNCTION`**, and every new user gets
  `DEFAULT`. `generate` warns that it cannot evaluate the function. A short
  password plans clean and then fails at `apply` with `ORA-28003`.
- **Rolling back fails on `DEFAULT`**, which sets `PASSWORD_REUSE_MAX 4`:
  `apply --source previous` gets `ORA-28007`. Use a rollover window instead.
  `ADMIN` can create the rollover profile.
- **Every run notes `SOPULI-W018`**, because `V$PWFILE_USERS` is not granted.

### "Wallet" means two things

| | What it is | What needs it |
|---|---|---|
| **TLS certificates** | the client certificate and trust anchors for a mutual-TLS connection | the connection, whatever login method you use |
| **secure external password store** | a stored username and password for an alias, so `/@alias` can log in | `auth: external` when a wallet is what authenticates |

The ADB wallet zip is the first kind. It holds no credential, so
`auth: external` has nothing to log in with. Unzip it and set `TNS_ADMIN` to the
directory for the TLS connection. The aliases (`_high`, `_medium`, `_low`) are
in its `tnsnames.ora`. `doctor`'s wallet report cannot tell the two kinds apart:
a certificate-only `cwallet.sso` passes it.

To use `auth: external` with ADB, add a credential to the wallet with `mkstore`
(§7). Nobody has tried this with sopuli (unverified: adb-external-auth).

If the database allows plain TLS, with no mutual TLS, no wallet is involved. Put
the connect descriptor from the OCI console in `dsn:`, and leave `TNS_ADMIN`
unset.

**Thin mode needs the wallet's download password**, and thick mode does not.
Thick mode reads the auto-login `cwallet.sso`; thin mode reads `ewallet.pem`,
which is encrypted. The `sqlnet.ora` in a fresh zip says
`DIRECTORY="?/network/admin"`; point it at the unzipped directory.

---

## 7. Wallets and `auth: external`

A target with `auth: external` connects as `/@alias`, and a wallet supplies the
username and the password.

`mkstore` and `orapki` are not in Instant Client. The `gvenzl/oracle-free` image
has them, but no Java, so they fail with `ERROR: No Java`. To create a real
wallet you need a full Oracle Database or Client installation. The commands are:

```bash
mkstore -wrl /path/to/wallet -create
mkstore -wrl /path/to/wallet -createCredential FREEPDB1 SYSTEM
mkstore -wrl /path/to/wallet -listCredential
```

### Testing the wallet report without a wallet

sopuli never opens the wallet. It checks that the directory is readable, that
`cwallet.sso` exists and is readable, and its permissions. A dummy file is
enough. Make a `TNS_ADMIN` directory with a `tnsnames.ora`:

```
FREEPDB1 =
  (DESCRIPTION =
    (ADDRESS = (PROTOCOL = TCP)(HOST = 127.0.0.1)(PORT = 1521))
    (CONNECT_DATA = (SERVICE_NAME = FREEPDB1))
  )
```

Use the alias as the DSN, with no `username:`:

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

With no `cwallet.sso`, the `wallet` section says `found nothing`. Put any file
named `cwallet.sso` there and it says `found cwallet.sso` and `auto-login yes`.
The login then fails with `ORA-01017`, which is about the password; the wallet
section is what points you at the file.

Other states to try:

| Do this | Expect |
|---|---|
| `unset TNS_ADMIN` | `no wallet directory to check: $TNS_ADMIN is unset and no sqlnet.ora named one` |
| point `TNS_ADMIN` at a missing directory | `it is missing, or not readable by this user` |
| leave only `ewallet.p12` | `no readable cwallet.sso ... which needs a passphrase this tool has no way to supply` |
| grant `BUILTIN\Users` read on `cwallet.sso` | `SOPULI-W008`: the auto-login wallet is not private |
| add a `sqlnet.ora` with `WALLET_LOCATION` pointing elsewhere | `searched` follows it, and says `(from sqlnet.ora WALLET_LOCATION)` |

---

## 8. WSL

Run the guide again under WSL. Two things differ:

- **Permissions are file modes, not ACLs.** Use `chmod 600`. The check refuses
  any group or other access, so `chmod 640` is refused too.
- **Instant Client for Linux.** The Windows one does not work from WSL.

With Docker Desktop, `127.0.0.1` reaches the containers from WSL.

---

## 9. The NNE container

```bash
docker compose --profile nne up -d      # Oracle on 1525, NNE required
```

This approximates Base Database Service's encryption requirement locally. The
profile has never been run, and its image tag is unverified, so a failure may be
the fixture.

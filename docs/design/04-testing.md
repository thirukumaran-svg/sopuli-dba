# sopuli-dba — Testing strategy

Depends on: `00-principles.md` (P1 capabilities), `../use-cases/uc-01-app-credential-sync.md` §11

---

## 1. The constraint that shapes everything

**Contributors cannot pull an Oracle Enterprise Edition image.** Images built
from Oracle installation binaries may not be redistributed. A public CI job
cannot `docker pull` a 19c image, and neither can anyone who forks the
repository.

This has three consequences:

1. The **public test suite must pass on freely pullable images alone**: 26ai
   Free, 21c XE, 18c XE, 11g XE, PostgreSQL and HashiCorp Vault. A contributor
   who cannot make a pull request pass on their own machine stops contributing.
2. A test that needs a particular environment **skips, not fails**, when that
   environment is absent. A skipped test reports why it skipped.
3. The environments only the maintainer can run, 19c EE, 12.2 EE and OCI, form a
   **pre-release matrix**. They do not run on every commit.

This is also why the matrix is keyed on capabilities, not versions (§3).

---

## 2. Environment inventory

### Freely pullable: the public tier

| Environment | Image | Covers |
|---|---|---|
| Oracle 23ai/26ai Free | `gvenzl/oracle-free`, or `container-registry.oracle.com/database/free` | CDB and PDB, common users, password rollover, 128-byte passwords, schema privileges (the P7 test) |
| Oracle 21c XE | `gvenzl/oracle-xe:21` | CDB and PDB on an older line, password rollover, unified auditing |
| Oracle 18c XE | `gvenzl/oracle-xe:18` | no rollover, which makes it a negative case; passwords limited to 30 bytes |
| Oracle 11g XE | `gvenzl/oracle-xe:11.2.0.2-slim` | non-CDB, 30-byte passwords, 10G and 11G verifiers, `DBA_AUDIT_TRAIL` |
| PostgreSQL 13–18 | `postgres:<v>` | the second driver, when it exists |
| SQL Server 2019/2022 | `mcr.microsoft.com/mssql/server` | a third driver, later |
| HashiCorp Vault | `hashicorp/vault` dev mode | KV v2 **and** KV v1, mounted side by side |
| File / age backend | none needed | the non-production store |

`test/compose.yaml` has a service for each Oracle release, and
[`../maintainer-environments.md`](../maintainer-environments.md) §1 says how to
point a config or the automated suite at one.

**"23ai" and "26ai" are the same database.** Oracle renamed Oracle Database 23ai
to Oracle AI Database 26ai in October 2025. 26ai adds features to the same
codebase, and 23ai is no longer downloadable on its own. In a version such as
`23.26.2.0.0`, the **23** is the codebase, the **26** is the year of the release
update, and the third number is the quarter. This has two consequences:

- A result from `gvenzl/oracle-free:latest` is the result for the 23ai line.
  Where this document says "23ai Free", it means this image.
- **Name the release number, not the marketing name.** `23.26.2.0.0` says what
  was tested. "26ai" does not, because next quarter's 26ai is a different release
  update. [`../measurements.md`](../measurements.md) has the rule and the
  releases measured.

The 11g XE image is published for **linux/amd64 only**. That is a second reason,
beside the 23.x client limit in D7, why Apple Silicon cannot test 11.2 locally.
Reasons: [T1](../decisions/log.md#t1).

### Maintainer-only tier

| Environment | How | Why it cannot be public |
|---|---|---|
| Oracle 19c EE 19.3.0.0.0 | Oracle's prebuilt `container-registry.oracle.com/database/enterprise:19.3.0.0`, the `oracle-19c` service under `--profile oracle19c`. [`../maintainer-environments.md`](../maintainer-environments.md) §2 | pulling it needs an Oracle account and the licence accepted on the registry website |
| Oracle 12c EE 12.2.0.1.0 | Oracle's prebuilt `enterprise:12.2.0.1-slim`, the `oracle-12c` service under `--profile oracle12c`. It differs from the 19c images: no DBCA, an init script run once by hand, a `WE8DEC` database, and service names ending in `.localdomain`. [`../maintainer-environments.md`](../maintainer-environments.md) §3. No image is known for 12.1 | the same registry terms as 19.3 |
| Oracle 19c EE 19.19.0.0.0 | `enterprise:19.19.0.0`, the `oracle-19c-ru` service. It is above 19.12, so it can open a rollover window, but the image is linux/arm64 only, and under emulation on an x86 host the instance does not start. It has never run. [`../maintainer-environments.md`](../maintainer-environments.md) §4 | the same registry terms, and an arm64 host |
| Oracle 19c release update | an OCI Base Database Service DB system, created by `test/oci-dbcs/new-db-system.ps1` and reached through an OCI Bastion session. [`../maintainer-environments.md`](../maintainer-environments.md) §5 | the DB system is billed by the hour |
| Autonomous Database | a personal OCI tenancy. [`../maintainer-environments.md`](../maintainer-environments.md) §6 | needs an OCI tenancy |
| OCI Vault | a personal OCI tenancy | needs an OCI tenancy and its credentials, and no local emulator is faithful |

What each of these has run, and on which release, is in
[`../measurements.md`](../measurements.md).

**Cost does not limit the OCI Vault tests.** They run only in tier 3, for the
reasons in the table, and not because of cost. They use one vault and a fixed set
of secrets, and they stay free:

- the vault is a default vault, not a private vault;
- its key is software-protected, not HSM-protected;
- no secret is replicated to another region.

The pull request that builds an OCI store checks the prices again. It also checks
the service limits that a fixed set of secrets can reach
(unverified: oci-vault-cost-limits). Reasons: [T4](../decisions/log.md#t4).

### Emulators: smoke tests only

The emulators are `localstack` (Secrets Manager; whether the free tier includes
it is T3), `lowkey-vault` (Azure Key Vault, which has a Python example),
`cameritelabs/oci-emulator` and Floci (OCI). A passing emulator test shows only
that the code path runs. **The authoritative test for a cloud store is the real
service.** That is what the OCI tenancy is for. Nobody knows or maintains the
emulators' fidelity, so a green emulator test is never the reason to cut a
release.

### Two Oracle behaviours that containers do not give you

- **Gradual password rollover** needs 19.12 or later, and every 19c container
  that runs here is 19.3. Rollover is tested on 26ai Free (tier 1), on 21c XE
  (tier 2), and on a 19c release update in an OCI DB system (tier 3). Releases
  do not report the rollover time in the same unit: 19.32.0.0.0 reports
  `PASSWORD_ROLLOVER_TIME` in seconds, and 26ai in days.
  `sopuli/driver/oracle/rollover.py` explains how the driver tells them apart.
- **Native Network Encryption** (NNE) is one of the reasons for thick mode
  (`00-principles.md`, *Why thick mode*). Only a real server that requires NNE
  tests it properly. The `nne` compose profile approximates one locally: its
  `sqlnet.ora` sets `SQLNET.ENCRYPTION_SERVER = required`, so a thin-mode
  connection must fail with `DPY-3001`, and the tool's diagnostics must say
  something useful. That covers the failure path. The profile has never been run
  ([`../maintainer-environments.md`](../maintainer-environments.md) §9). The
  success path needs a server that enforces NNE: Base Database Service, **not**
  Autonomous Database. Autonomous Database encrypts with TLS, so it proves
  nothing about NNE. Both are measured in
  [`../maintainer-environments.md`](../maintainer-environments.md) §5 and §6.

---

## 3. Capability-driven matrix

Tests declare the capabilities they need. The harness probes each target once per
session, and skips a test with a reason when a capability is absent.

The markers look like this:

```python
@requires_capability("password_rollover")
def test_rotate_keeps_old_password_valid_during_window(oracle_target, vault):
    ...

@requires_capability("offline_verify")
def test_check_hash_mode_makes_no_login_attempt(oracle_target):
    ...

@requires_no_capability("password_rollover")
def test_rotate_falls_back_to_staged_strategy(oracle_target):
    ...
```

This gives two things beyond convenience:

- **The test suite checks the capability model itself.** If a driver claims
  `password_rollover` on 18c XE, the rollover test runs there and fails. That
  failure is the bug. A skip keyed on the version would have hidden it.
- **A new environment costs nothing.** Point the harness at a new container or a
  real database, and the right subset of tests runs. No test file changes.

At the end of a run the harness prints the resolved matrix, so that "green" is
never ambiguous. It has this shape:

```
capabilities exercised
                       23ai Free  21c XE  18c XE  11g XE  OCI 19c
common_users               –         –       –       –        ✓
password_rollover          ✓         –       –       –        ✓
offline_verify             –         ✓       ✓       ✓        ✓
password_reuse_policy      ✓         ✓       ✓       ✓        ✓

23 tests skipped (capability absent), 0 skipped (environment unavailable)
```

Watch the second skip count. A skip for an absent capability is correct. A skip
for an absent environment is a gap in coverage.

**A dash can describe the connecting account, not the release.** Two of the
dashes above are like that:

- `common_users` asks whether the session holds `ALTER USER` *granted commonly*.
  The test lane connects as `SYSTEM`, which holds it through a role, so
  `USER_SYS_PRIVS` returns nothing and the capability is absent.
- `offline_verify` needs `SELECT ON SYS.USER$`. That is an optional grant (P2),
  and `SYSTEM` does not hold it on 23ai Free.

Both results are correct. Editing the probe does not change them. Connecting as
an account that the install script has granted does.

The harness is `tests/oracle_harness.py`, with the tier-1 fixtures in
`tests/conftest.py`. Three things about it are decisions, not mechanics:

- **The probes use P1's capability list, not a list of their own.** To check the
  capability model, the harness must ask the same question the driver answers. A
  test asserts that the two lists are one list, so a new capability must be put
  on one side or the other.
- **Not everything is a query.** Every supported Oracle release can expire a
  password and lock an account. Those are properties of the product, not of the
  instance. A query such as `select 1 from dual` would look like a probe and
  measure nothing. So these capabilities are declared structural, with the
  reason attached, and the report shows the difference between *asked, and the
  answer was yes* and *there was nothing to ask*.
- **Three absences, three messages.** A missing `oracledb`, a missing Instant
  Client and an unreachable database are different findings. Only the third is
  what most people mean by "no test environment". If the other two were
  reported the same way, someone would look for a `docker` problem when the
  problem is `pip`. So the skip names which one it was, and the Instant Client
  case is reported as itself, not as `DPI-1047`.

The real report uses ASCII, not the check marks drawn above. On Windows, a
redirected stream uses the locale code page, and a box-drawing character stops
the writer mid-line (P4). A test report must survive being piped into a log.

### Install shape is a dimension too (ADR-006)

Capabilities describe what the server can do. **Install shape describes what
this machine can import at all.** It is a matrix dimension for the same reason:
a property that nothing exercises is not a property you have.

| Shape | Installed | What it proves |
|---|---|---|
| base | `pip install .` | the boundary in ADR-006 rule 3: no backend's client is importable, and the offline commands still work |
| one extra | `pip install ".[<name>]"`, each in turn | that backend imports on its own; no extra depends on another without saying so |
| `all` | `pip install ".[all]"` | the shape every other test runs under, and the only one where the full suite means something |

Base and `all` run on every commit of a pull request that changes code. Both
are tier 0, and neither
needs a container. Each per-extra cell is one install and one import. They
matter most for an extra that nobody develops against, where a missing import
would otherwise be found by a user.

The developer environment is `sopuli-dba[all]`. That is why the base cell must
exist: every ordinary test passes there whether or not the base install is
clean, so nothing else in the suite can see rule 3 break.

**A claim about the process needs a process of its own.** Rule 3 says that
asking whether a client is installed must not import it. A check such as
`"oracledb" not in sys.modules` inside the test session depends on every test
that ran before it. Any test that imported the client earlier makes it false,
and the driver fixtures do import it. Such a check passes or fails with the
order of the tests. A check that fails only in some orders gets dismissed as
flaky, and then a real regression gets dismissed too.

So there are two rules:

- A test whose subject is **what importing did** runs in a subprocess.
  `tests/test_import_order.py` and `tests/store/test_install_shape.py` do this.
  Where the property can only be seen with a vendor package installed, the
  subprocess puts a stub package on `PYTHONPATH`. It does not depend on what
  this machine happens to have installed.
- A test whose subject is **what one call did** asserts on that call: it patches
  the import machinery, and the failure names the function.

---

## 4. Tiers

| Tier | Runs | Where | Budget | Contents |
|---|---|---|---|---|
| 0 | every commit of a pull request that changes code | public CI (`ci.yml`) | < 60 s | unit tests; config parsing and validation; target-set expansion; precedence resolution; SecretRef parsing; password generation and charset rules; redaction; the offline commands (`config`, `target list`, `policy sample`) through `CliRunner`; `lock status` and `lock break` with the store passed in, including whether a lock is live, expired or absent; the install-shape checks in §3 |
| 1 | every pull request that changes code | public CI (`tier1.yml`) | < 10 min | Oracle 26ai Free and Vault dev: the full UC-1 happy path, idempotency, drift, locking; fault injection (§5) |
| 2 | by hand | a developer's machine, `docker compose --profile tier2` | < 30 min | 21c XE, 18c XE and 11g XE |
| 3 | before a release | maintainer | by hand | 19c and 12.2 EE, OCI DB systems and Autonomous Database, OCI Vault, the release gates in §6 |

A pull request that changes only documentation runs the `docs` job in `ci.yml`
instead of tiers 0 and 1. No workflow runs tier 2. To run the suite against a tier-2 release, follow
[`../maintainer-environments.md`](../maintainer-environments.md) §1, *Pointing
the automated suite at another release*.

**The tier-1 lane installs Oracle Instant Client.** It has to. D3 makes thick
mode mandatory, because thin mode has no Native Network Encryption, no 11.2 and
no external authentication. A runner without the client would skip every driver
test and still report green. Instant Client Basic Lite is a free download that
needs no account, so a fork can do exactly what the lane does, as §1 requires.

**A missing environment fails that lane; it does not skip.**
`SOPULI_TEST_TIER1=required` turns "no environment" into a failure, and leaves
capability skips alone. This is §3's distinction put to use. A job that exists to
run tier 1, skips all of it and reports green is worse than no job, because
people quote it as evidence. Everywhere else, such as a laptop or a fork with no
stack running, the same tests skip with a reason, as §1 requires.

Tier 0 needs no containers, and it must stay that way: it is what makes the
inner development loop fast. Every pure-logic concern above (precedence,
templating, charsets, redaction) can be tested without a database. That is a
reason to keep those layers free of I/O.

**Container lifecycle.** Most Oracle containers take minutes to start. 11g XE
slim starts in about 15 seconds, because it ships prebuilt datafiles. Do not
create a container per test. Run one container per release per session. Between
tests, drop and recreate the test accounts and profiles, not the container. The
stack is `test/compose.yaml`, and the harness starts nothing itself
([T2](../decisions/log.md#t2)).

---

## 5. What gets tested

### Pure logic (tier 0, no database)

- **Config validation:** unknown keys; both `accounts:` and `applications:`
  present; duplicate generated target names; an unresolved `{placeholder}`; an
  `overrides` key naming a target that is not generated.
- **Target-set expansion:** inner dimensions per outer value, overrides, label
  assignment.
- **Precedence:** every layer in P3, including the safety ratchet and the
  ranking of third-party environment variables.
- **SecretRef parsing,** including `#field/json/pointer` and
  `@version=`/`@stage=`.
- **The staged payload layout** (Q7): Q7's two layouts give the same result
  under one rule, and a merge patch **omits** every sibling account instead of
  rewriting it with the value last read. The second check asserts on what the
  patch does *not* contain. A patch that names a sibling looks correct until two
  accounts share a document.
- **Password generation:** charset, first character, byte length in a given
  database character set, and composition requirements. Each is asserted over
  enough draws that a rule that holds only "usually" fails. Two things that
  output cannot show are also checked: that the randomness comes from the
  CSPRNG, not from `random`, and that no message about a rejected candidate
  repeats any part of it.
- **Redaction:** the serialiser cannot emit a secret value.
- **Statement shape: the generated SQL is never a PL/SQL block, and never binds
  the password** (invariants 13 and 14). The test checks the statement text that
  the Oracle driver produces. It must be `ALTER USER … IDENTIFIED BY …` directly,
  with no `BEGIN`, `DECLARE` or `EXECUTE IMMEDIATE` wrapper, and no bind
  placeholder where the password goes. This belongs in tier 0 because it needs no
  database. It belongs in a test, not only in review, because the measured
  result is surprising: the wrapper looks safer and is the form that leaks
  (`02-oracle-privileges.md` §4). A database test would not notice a wrapper
  added later, for example to batch several rotations, because the DDL itself
  stays clean either way.
- **Install shape (ADR-006): a base install can import none of the backends'
  clients:** `httpx`, the OCI SDK, `python-oracledb`, and any name added to an
  extra later. The check runs against the installed environment, not the source.
  The property is "an operator who ran `pip install sopuli-dba` cannot open a
  socket", and a search of the source for imports would pass on a machine where
  the extras happen to be installed. The check covers that dependency set, not
  "any HTTP client": `urllib` is importable in every Python, so keeping base code
  to the standard library is ADR-006 rule 3's discipline, and no packaging test
  can enforce it. This property breaks silently: one convenient module-level
  import breaks it, and nothing else notices, because developers install
  `sopuli-dba[all]`. Two checks hold it, because neither is enough alone:
  - `tests/store/test_install_shape.py` blocks the clients at the import system
    and imports every sopuli module outside a backend. It runs in any
    environment, and it names the module that broke the rule.
  - CI's `install-shape` job installs the base package for real and asserts that
    the clients are absent. Only this check can see a mistake in
    `pyproject.toml` itself.
- **The absent-backend path, for each backend (ADR-006).** Resolve a store whose
  extra is not installed, and assert the whole contract: the message names the
  right extra, `error.category` is `config`, `error.code` is `SOPULI-20001`, and
  the exit code is 9. Every other test imports the module successfully, so
  without this test a renamed module would turn the clean error into a
  traceback, and nothing would notice.
- **The advisory lock:** acquire, fence, renew and release, against an in-memory
  KV v2 fake with an injected clock. This includes the fencing case: a lock is
  stolen mid-run, and the original holder must stop before its next change. The
  case belongs in tier 0 because none of it is I/O. A stolen lock is detected by
  comparing versions, and a dictionary can supply the versions. The tier-1 test
  below then checks the same property against a real Vault.

### Against a database (tiers 1–3)

These come from UC-1 §11. The second column is the environment each one needs.

| Test | Needs |
|---|---|
| UC-1 happy path: `creds generate`, then `creds apply`, which verifies every target and promotes, then `creds check` | any |
| Idempotency: every **convergent** command run twice reports `changed: false` the second time. `creds generate` and `account reset-password` draw a fresh password, so for them the second run must say what it replaced (invariant 9) | any |
| Drift: change a password out of band; `check` reports `DRIFT` and exits 3 | any |
| **Lockout regression:** with a profile set to `FAILED_LOGIN_ATTEMPTS 3`, run `check` five times against a drifted account; the account never locks | any |
| Verify function: a profile with `ora12c_strong_verify_function` and a policy that violates it. The tool regenerates a bounded number of times, then fails with a clear error that carries the server's message. **Assert on the error, never on `DBA_PROFILES`.** In a PDB, a *common* profile's `PASSWORD_VERIFY_FUNCTION` limit reads `FROM ROOT`, not the function's name, so the dictionary shows an unconfigured profile while the function is enforcing (`ORA-28003` with `ORA-20000`). A profile created *in* the PDB shows the function's name. That is why `creds generate` reports three states, not two | any |
| Password reuse: with `PASSWORD_REUSE_MAX` set, the tool does not retry blindly on `ORA-28007` | any |
| **The password length limit.** A policy that asks for more bytes than the release allows is refused at *plan* time, not by `ORA-00972` during `apply`. Below Oracle 23 the limit is 30 bytes, and from 23 it is 128 bytes. `sopuli/driver/oracle/limits.py` holds the limit. The results per release are in [`../measurements.md`](../measurements.md) | 21c XE, 18c XE, 11g XE, 19.3 EE, 12.2 EE |
| Verifiers: 11g has 10G and 11G verifiers and no `T:`, so `--method hash` must refuse at plan time, not guess. `hash` compares the `12C` verifier only. `sql/oracle/05_verifier_layout_probe.sql` reads the verifier layout, and `06_verifier_reproduce.{sql,py}` recomputes each stored digest on the client. The results per release are in [`../measurements.md`](../measurements.md) | 11g XE, 18c XE |
| **The non-CDB shape.** This is not a missing capability. Oracle answers a different set of questions. `SYS_CONTEXT('USERENV','CON_NAME')` *raises* `ORA-02003` instead of returning NULL. `DBA_USERS` has no `ORACLE_MAINTAINED`, `PASSWORD_CHANGE_DATE` or `COMMON`. `USER_SYS_PRIVS` has no `COMMON`. There are no audit policies. Code unrelated to containers can break on any of these, for example by blanking a whole target row in the privilege audit while the run still exits 0 | 11g XE |
| **DDL text retention differs between releases** (unverified: ddl-text-versions). `V$SQLSTATS` keeps the `ALTER USER` statement on 11.2 and on no later release measured. Invariant 13's reasoning holds everywhere, but its conclusion depends on the release. The decision is to document this, not to warn or refuse ([P8](../decisions/log.md#p8)). That is defensible only while the record is accurate, so every release claimed as supported gets `02_password_leak_probe.sql` run against it. The releases are in [`../measurements.md`](../measurements.md) | every release claimed |
| Common user with `CONTAINER=ALL`, and the refusal outside `CDB$ROOT` | any CDB |
| Rollover: both passwords are valid during the window, and `finish-rollover` ends it | 26ai Free, a real 19.12 or later |
| Rollover *absent*: `--strategy rollover` fails at plan time, not during execution. It exits 5 under `--dry-run`, with `error.category` `capability` and `error.target_capability` `password_rollover`, and the `plan` beside the refusal. `doctor` reports `password_rollover` absent. The test carries `@requires_no_capability(password_rollover)`, so it skips on 26ai and runs only on a release without rollover | 18c XE, 11g XE |
| `DBA_USERS` columns: `ORACLE_MAINTAINED` exists from 12.1, and `PASSWORD_CHANGE_DATE` only from 19c. So 18c has one and not the other. If the driver assumed both arrive together, 18c would answer like 11.2, read `vendor_maintained` as `None`, and silently switch off guardrail check 2 on a release that can answer it. The driver uses three query shapes, which all return the same columns | 18c XE, 11g XE |
| Standby refusal: `OPEN MODE = READ ONLY` is detected before any DDL | real OCI |
| NNE: thin mode fails with `DPY-3001`, and the diagnostics are useful | the `nne` profile |
| Schema-privilege regression (P7): `GRANT ALTER USER ON SCHEMA` must still fail with `ORA-00990`, and `GRANT SELECT ANY TABLE ON SCHEMA` must still succeed. **Assert both.** Without the second, a release that dropped schema privileges entirely would also pass. If the `ALTER USER` grant ever succeeds, the privilege model needs review | 23 codebase (tier 1) |
| Shared JSON document: writing one account's password leaves its siblings byte-identical | any, with Vault |
| KV v1 degradation: no versioning, staging emulated in the payload, and the tool says so | Vault KV v1 mount |
| `lock status` reads a record the tool did not write: a config entry opens a store, authenticates, and reports a lock held by someone else. The survey leaves the version counter unchanged, because `status` takes no lock | Vault |
| `list` gives the same answers on the fake and on the real mount: full readable paths; recursion through subtree markers; a prefix that stops at a segment boundary; and a soft-deleted path that is still listed but reads as nothing. A dictionary-backed fake would never produce the last case by itself. KV v2 lists metadata, and metadata outlives data | Vault, both mounts |
| `lock status` reports a record at a path the config does not declare, marked `declared: false`. A store with no `list` capability warns with `SOPULI-W005` instead of failing the survey, so the command works on every backend | Vault |
| `lock break` takes a record the tool did not write, with a compare-and-set against a version that Vault issued, and **the manager that held it fails its next check.** The fence is the reason the verb may exist, and a fake cannot establish it: a store that counts integers agrees with the tool by construction | Vault |

### Running it, which is not the same as testing it

The table above is what CI asserts. This rule comes before writing any of it:
**a change to what the tool reads from a target or a store, writes to one, or
reports about one is verified by running the verb against a real one before the
pull request opens.** Tier 1 is the minimum, because it is the stack that runs
locally. A change may use tier 2 or 3 when it needs to.

CI already runs tier 1 on every pull request that changes code, so the point is
not coverage. The
point is that **a test asserts what its author already suspected.** A real run
catches the faults nobody suspected. Faults like these pass every test:

| Fault | Why no test catches it |
|---|---|
| A sample in a design document is written before the command is run, and the command prints something else | the sample is prose, and prose is not executed |
| The vendor documents one error code and the server sends another. `ORA-28002` is the documented code for the grace period, and 26ai sends `ORA-28098` or `ORA-28011`, depending on the profile, on a connection that **succeeds** | the code checks for a constant that nobody has seen the server send |
| A fault is intermittent, such as a diagnostic query that reports the probing session itself in one run out of two | one green run does not measure an intermittent fault |

Two rules follow:

1. **Paste real output.** Every sample in a design document, a pull request
   body, a docstring or an issue comes from a run that happened. Never write what
   a command *would* print.
2. **Measure a vendor's behaviour; do not reason about it.** What an error code
   is, whether it arrives as an exception, how a status column is spelled: these
   are facts about someone else's software. `02-oracle-privileges.md` §4 and
   `sopuli/driver/oracle/accounts.py` record several that were the opposite of
   the obvious guess.

### Fault injection

The failure table in UC-1 §8 is a test list. Each row asserts the documented
recovery, not only that the tool did not crash:

| Injection | Assert |
|---|---|
| kill the process between `password_set` and `vault_promote` | `pending` still holds the new value; `status` reports `PENDING_APPLY`; a second `creds apply` completes the promotion |
| vault unreachable mid-run | lost at the staging write: nothing applied, exit 1. Lost at the promotion: applied and not promoted, and `creds apply` completes it. Never promoted silently |
| close a PDB mid-run (several targets) | partial success, exit 4: the other targets take the new password, the closed one keeps the old one, and `current` is not promoted. `creds apply --repair` with the run document applies to the closed target, and a later `creds apply` promotes |
| revoke `ALTER USER` mid-run | a clean authorization error, and no half-written state |
| two `rotate` runs on one account at once | one loses the lock and exits 7; the final state is consistent |
| steal a held lock mid-run: let it expire, and let a second run take it over | the first run's next fence check fails, and it stops before its next `ALTER USER`: no database gets its password, and `current` is not promoted. A write that passed its fence check before the takeover still lands, so `pending` can hold the stale run's password. The run exits 4 with `SOPULI-W011`, and the next run to hold the lock applies that `pending` |
| a `pending` already staged when a rotation reads its document, or staged by a run that takes its lock over while its staging write is held | the rotation stages nothing over it. Staged before the read: it refuses on exit 8 and names the account. Staged after: the held write loses its compare-and-set, and the run exits 1 with nothing applied. Either way, `creds apply` then applies and promotes that `pending` (#769) |
| as above, but the run that takes over is a `rotate`, and it is held at its own staging write while the stale write lands | the stale run stops as above, exit 4 with `SOPULI-W011`. The new holder's staging write fails its compare-and-set on the version it read: exit 1, a row in `ERROR` with `category: vault` and a message that names the conflict, not the takeover. Neither run changes a database, and `current` is not promoted |
| kill a run that holds a lock, then start another | by default the second run refuses with exit 7, and reports the holder and that the lock has expired. Breaking a lock is not self-service. Under `locking.break_expired`, the second run takes the lock with a compare-and-set write that increases the version, which fences the killed run if it ever resumes |
| the vault returns a stale read after the promotion | the post-verify step catches it: exit 4 with `SOPULI-W012`, not success |

The mechanics are in `tests/fault_harness.py`. Each test runs `sopuli` as
its own process, with an HTTP proxy between it and the vault. The proxy acts on
one request to the secret's path: it holds a write, drops it and stops
listening, or forwards a write and stops listening before the reply, or
answers a read with an older reply. For a database fault, it pauses the staging
write while the test changes the database as `SYS`, then forwards it. The
pre-flight has passed by then, so the run meets the change at step 5. For a
lock row, it pauses the same write while the run holds its lock, and a second
run starts. Step 4 checks the fence before that write, so the paused run's next
check is the one before its `ALTER USER`.

The fault is placed on a request, not on an event, because an event is a race.
The run goes on to verify and promote while the test reads `password.applied`,
so a kill or a cut sent then lands before the promotion on most runs, not all.
A TCP proxy has the same race, because it cannot tell one HTTP request from the
next. A process kill therefore waits for the proxy to hold the promotion write.

The tests need only the tier-1 services, so the tier-1 lane runs them:

| Rows | Tests |
|---|---|
| the two kill rows | `tests/test_fault_kill.py` |
| vault unreachable at a write or after it, stale read | `tests/test_fault_vault.py` |
| PDB closed, `ALTER USER` revoked | `tests/test_fault_database.py`. The PDB row creates a second PDB and drops it afterwards. Both recoveries are tested: plain `creds apply`, and `creds apply --repair` with the `rotate` document followed by `creds apply` |
| two runs at once, a lock taken over, a takeover by `rotate`, a `pending` already staged | `tests/test_fault_lock.py`. In the takeover row, the run that takes the lock over is a `creds apply` with nothing to do, so it writes no secret document. In the `rotate` row, a second gate holds the new holder's staging write until the stale write has landed. In the `pending` row's second case, a `creds generate` takes the lock over |

---

## 6. Release gates

These are not tests that may be skipped. A release does not happen if any of
them is red.

1. **Redaction.** Run the full suite, then search every artefact (stdout,
   stderr, log files, JSON output, audit records) for every generated password.
   There must be no hits.

   **`policy sample --reveal` is excluded by name**, and so is UC-2's seen reset
   (`03-json-output.md` §4 has its rule). `policy sample --reveal` prints a
   password because that is its purpose. This is invariant 2's third exception:
   a sample is not a credential, because nothing authenticates with it and it is
   never stored.

   The exclusion alone would weaken the gate, so the gate adds a narrower
   property: **no JSON document contains a sample value, with or without
   `--reveal`.** This holds because the run schema gives a `sample` object no
   value property, and because `--reveal` with `--output json` is refused.
   Search the JSON artefacts of a `policy sample` run for the values it printed.
   There must be no hits.
2. **Password leakage into Oracle.** Run `sql/oracle/02_password_leak_probe.sql`
   on each supported major release. It plants one canary per execution path:
   `CREATE USER` from the client, `ALTER USER` from the client, `EXECUTE
   IMMEDIATE` with the password as a literal in the block, and `EXECUTE
   IMMEDIATE` with the password assembled at runtime. It then searches every
   place where a statement's text can be kept. The findings are in
   `02-oracle-privileges.md` §4. This is the measurement that §4 refuses to
   replace with an assumption.

   **Run it in three positions on each release.** They are not interchangeable:

   | # | Connect to | `svc_user` | What it establishes |
   |---|---|---|---|
   | 1 | the PDB service | the account holding `ALTER USER` and nothing else | **the only position that proves the audit policy works.** This is how sopuli operates |
   | 2 | the PDB service | `sys` | the SYSDBA path, including the `audit_file_dest` searches, which only `AUDIT_SYS_OPERATIONS` populates |
   | 3 | the CDB service | a common `C##` account | that container scope does not change the answer |

   Position 1 carries the result. Before you believe its findings, check that
   the probe's section 3 prints **`isdba=FALSE`**. Mandatory unified auditing
   captures SYS's actions whatever the policy, so a run that reports
   `isdba=TRUE` shows nothing about `SOPULI_PROBE_POL`: the trail would look the
   same with no policy at all. Also check that the `ALTER USER` rows in section 5
   are attributed to the service account, not to `SYS`.

   Two more rules turn an apparent pass into no result:
   - A `clean` on a `pop=n` column is an absence of evidence, and the probe
     labels it `INCONCLUSIVE`.
   - `DBA_HIST_SQLTEXT` needs an AWR snapshot taken *before* the search
     (unverified: ddl-text-awr). `sql/oracle/10_awr_snapshot_probe.sql` takes
     one.

   `sql/oracle/04_password_leak_extensions.sql` adds the surfaces that need more
   setup: trace files, OS audit files, self-rotation, and `IDENTIFIED BY
   VALUES`. Run it with the probe.

   Which positions ran on which release is in
   [`../measurements.md`](../measurements.md). When something has not run, name
   the *surface*, not the position. A position covers several surfaces. For
   example, position 2's `audit_file_dest` searches mean something only with
   `AUDIT_SYS_OPERATIONS = TRUE`, so a position 2 run without it leaves that
   surface unrun.

   These are not yet measured, and none of them is a pass:

   | Open | Why it blocks a claim |
   |---|---|
   | **12.1** (unverified: ddl-text-versions) | 11.2 keeps the DDL text and 12.2.0.1.0 does not, so the change is somewhere after 11.2 and no later than 12.2. 12.1 is the one release left in that range, and no image is known for it. Read the 11.2 result as *11.2 keeps it*, never as *every older release keeps it* |
   | **Other 19c release updates** | 19.3.0.0.0 and 19.32.0.0.0 agree. One release update is not every release update, so name the release when you quote a result |
   | **AWR on 11.2** (unverified: ddl-text-awr) | Whether 11.2's retained `ALTER USER` reaches AWR needs an 11.2 database with the Diagnostics Pack. Every image in this stack sets `control_management_pack_access = NONE` |
3. **Schema conformance.** Every sample and recorded output validates against the
   published JSON Schema. The schemas and the example in `docs/schemas/`
   validate, a test asserts that the config schema is the one the config layer
   generates, and `01-configuration.md`'s worked example is validated against
   it.
4. **Lockout.** The lockout regression test passes on every Oracle release in the
   matrix. A tool that locks production accounts while it checks them is worse
   than no tool.
5. **Idempotency.** Every **convergent** command, run twice anywhere, reports
   `changed: false` the second time.

   The qualifier is invariant 9's, in the same words. A gate that said *every
   command* could never pass. `creds generate` and `account reset-password`
   draw a fresh password and have nothing to converge on, so they report
   `changed: true` on every run by design. The gate still checks them: the
   second run must **say what it replaced**.
6. **The lock holds under contention, and a stolen lock stops the run that lost
   it.** `tests/store/test_lock_concurrency.py` runs against a real Vault. Two
   concurrent processes take one lock and exactly one wins; the loser exits 7
   and has changed nothing; and a holder whose record is overwritten mid-run
   fails its next fence check.

   **Two processes, not two managers over one dictionary.** Tier 0 covers the
   same properties, but it forces the race by driving the store in a chosen
   order. That proves the manager reacts correctly to a lost compare-and-set,
   but it never lets two runs start together. A gate that only ran in one
   process would not be the gate a release note claims.

   Two facts about the *store* are asserted here for the same reason:
   - `cas: 0` fails forever on a deleted path. This is why release writes a
     record and never deletes one.
   - A KV v1 mount has no compare-and-set. The test asserts that **weakness**
     on purpose: a run that reported `cas` there would claim a guarantee it does
     not have.

   **Tier 0 owns claims about ordering. Tier 1 owns claims about simultaneity.**
   Each tier can force exactly one of the two:
   - Tier 1 cannot assert an *interleaving*, such as two runs that both read
     before either writes. The window is inside `acquire`, nothing outside can
     hold it open, and two processes started together land in it only
     sometimes. A test that asserted it would be a coin flip. On the KV v1 mount,
     tier 1 asserts only what holds on every run, whatever the scheduler did: no
     run gets a fence, every run reports `mode: none`, and a denial is never a
     *lost* compare-and-set, because the mount has none to lose. A test against a
     planted record asserts the last point deterministically.
   - The interleaving itself, that two runs *can* hold one advisory lock at
     once, is asserted in `tests/lock/test_manager.py`, where a barrier holds the
     window open. Its docstring explains why the outcome there does not depend on
     the scheduler, and the same interleaving against a store with `cas` still
     gives exactly one winner.

   A tool that lets two runs rotate one credential at once is worse than a tool
   with no locking at all, because the second one does not claim to protect you.

---

## 7. Test data and fixtures

- **Never a real account name, host, tenant or path.** Fixtures use the same
  fictional vocabulary as `01-configuration.md`: application `acme`, accounts
  `acme_*_user`, tenants `alpha` to `theta`, hosts under `example.com`, and
  documentation IPs from `192.0.2.0/24`.
- Each test creates its own accounts under a per-run prefix and drops them
  afterwards, so a failed run leaves nothing that breaks the next one.
- The harness creates the profiles that tests use (`FAILED_LOGIN_ATTEMPTS 3`,
  rollover configured, a verify function attached). Tests never assume they
  exist.
- The Vault dev container starts empty, and every test seeds what it needs.
  Tests share no fixture state. This tool is sensitive to concurrency, and
  shared fixtures would hide exactly the bugs worth finding.

---

## 8. Open questions

| # | Question | Leaning |
|---|---|---|
| ~~T1~~ | ~~Does `gvenzl/oracle-xe:11` exist?~~ | **decided: yes** (#1), `11.2.0.2-slim`, amd64 only. See §2. Reasons: [T1](../decisions/log.md#t1) |
| ~~T2~~ | ~~`testcontainers-python` or `compose.yaml` + fixtures?~~ | **decided: compose** (#174). The harness starts nothing; `SOPULI_TEST_ORACLE_DSN` points it elsewhere. Reasons: [T2](../decisions/log.md#t2) |
| T3 | Is LocalStack Secrets Manager in the community tier? | verify before committing to it as the AWS path |
| ~~T4~~ | ~~Does OCI Vault cost enough to matter in a test loop?~~ | **decided: no** (#643). Tier 3 only, because it needs a tenancy. See §2. Reasons: [T4](../decisions/log.md#t4) |
| ~~T5~~ | ~~Public CI provider~~ | **decided: GitHub Actions.** See `../workflow.md`. Reasons: [T5](../decisions/log.md#t5) |
| T6 | Do we need a real Data Guard standby to test the read-only refusal? | probably: a closed PDB is not the same failure. Defer until a driver bug argues for it |
| T7 | Snapshot/restore for faster Oracle resets | **deferred**: start with drop-and-recreate; revisit if tier 2 exceeds its budget |

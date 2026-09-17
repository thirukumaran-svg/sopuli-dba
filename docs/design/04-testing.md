# sopuli-dba — Testing strategy

Status: draft / sketch. Nothing here has been run.
Depends on: `00-principles.md` (P1 capabilities), `../use-cases/uc-01-app-credential-sync.md` §11

---

## 1. The constraint that shapes everything

**Contributors cannot pull an Oracle Enterprise Edition image.** Images built
from Oracle installation binaries may not be redistributed, so a public CI job
cannot `docker pull` a 19c image and neither can anyone who forks the repo.

Three consequences, and they are easier to design for now than to retrofit:

1. The **public test suite must be fully green on freely pullable images alone**
   (23ai/26ai Free, 21c XE, 18c XE, PostgreSQL, HashiCorp Vault). If a
   contributor's PR cannot go green on their own machine, they stop contributing.
2. Everything version-specific must **skip, not fail**, when its environment is
   absent. A skipped test reports *why* it skipped.
3. The versions only the maintainer can run — built 19c, 11.2, real OCI — form a
   **pre-release matrix**, not a per-commit one.

This is also why the matrix is capability-driven rather than version-driven (§3).

---

## 2. Environment inventory

### Freely pullable — the public tier

| Environment | Image | Covers |
|---|---|---|
| Oracle 23ai/26ai Free | `gvenzl/oracle-free`, or `container-registry.oracle.com/database/free` | CDB+PDB, common users, password rollover, schema privileges (P7 test) |
| Oracle 21c XE | `gvenzl/oracle-xe:21` | CDB+PDB on an older line, unified auditing |
| Oracle 18c XE | `gvenzl/oracle-xe:18` | 12.2+ password length, no rollover — good negative case |
| Oracle 11g XE | `gvenzl/oracle-xe:11.2.0.2-slim` | non-CDB, 30-byte passwords, 10G/11G verifiers, `DBA_AUDIT_TRAIL` |
| PostgreSQL 13–18 | `postgres:<v>` | the second driver, when it exists |
| SQL Server 2019/2022 | `mcr.microsoft.com/mssql/server` | third driver, later |
| HashiCorp Vault | `hashicorp/vault` dev mode | KV v2 **and** KV v1, mounted side by side |
| File / age backend | none needed | the non-production store |

**"23ai" and "26ai" are the same database.** Oracle renamed Oracle Database 23ai
to Oracle AI Database 26ai in October 2025; 26ai adds functionality on top of the
same codebase, with no change to the architecture or existing APIs, and it inherits
23ai's Lifetime Support Policy. The numbering scheme changed at the same time:
in `23.26.2.0.0` the **23** is the codebase, the **26** is the release-update year
(2026), and the third digit is the quarter — so the version now tells you the date
of the RU. A 23ai instance becomes 26ai by applying the 23.26.0 RU, and 23ai is no
longer separately downloadable.

Two consequences for this matrix:

- **There is no pre-26ai 23ai to test, and no way to obtain one.** A result from
  `gvenzl/oracle-free:latest` *is* a result for the 23ai line. Where this document
  says "23ai Free" it means exactly this image. P7 ("do 23ai schema privileges
  cover `ALTER USER`?") was answered here rather than being blocked on finding a
  23ai instance — **no, `ORA-00990`** (`02-oracle-privileges.md` §2.1).
- **Qualify findings by release number, not by marketing name.** `23.26.2.0.0`
  says what was tested; "26ai" does not, since next quarter's 26ai is a different
  RU. Verified 2026-08-17 as `Oracle AI Database 26ai Free Release 23.26.2.0.0`,
  CDB `FREE` plus `FREEPDB1`, reaching `healthy` in 30–60 s.

The 11g XE tag exists and works, so 11.2 support (D7) is cheap: it stays a tier-2
compose service and never needs building from `oracle/docker-images`. Verified
2026-08-08 against `gvenzl/oracle-xe:11.2.0.2-slim`
(`sha256:a546a62d6574d125c6520011cad328748c869038d52cd94ca4eb0fed7407d1fe`) —
starts clean as `Oracle Database 11g Express Edition Release 11.2.0.2.0`, non-CDB,
SID `XE`, `AL32UTF8`. See §8 T1.

The image is published for **linux/amd64 only**. That is a second, independent
reason Apple Silicon cannot exercise 11.2 locally, on top of the 23.x-client
limitation in D7.

### Maintainer-only tier

| Environment | How | Why it cannot be public |
|---|---|---|
| Oracle 19c EE | built from `oracle/docker-images` + downloaded binaries | not redistributable |
| Oracle 19.12+ | patched 19c — needs a support licence | rollover is unavailable on the buildable 19.3 base |
| Real 19c / 26ai / ADB | personal OCI tenancy | NNE, thick mode, Autonomous behaviour |
| OCI Vault | personal OCI tenancy | no faithful local emulator |

### Emulators — smoke tests only

`localstack` (Secrets Manager — confirm which tier), `lowkey-vault` (Azure Key
Vault, has a Python example), `cameritelabs/oci-emulator` and Floci (OCI). Treat
all of these as "the code path runs" evidence. **The authoritative test for a
cloud store is the real service**, which is what the OCI tenancy is for. Emulator
fidelity is unknown and unowned; never let a green emulator test be the reason a
release is cut.

### Two Oracle behaviours containers do not give you

- **Gradual password rollover** needs 19.12+. The buildable 19c base is 19.3.
  Rollover therefore gets tested on 23ai Free (public tier), on 21c XE (tier 2,
  and the *only* thing between them — run 2026-09-08 for #380: `apply` opens the
  window, `status` and `check --include-previous` report it rather than calling it
  drift, `finish-rollover` closes it early and a second run reports
  `changed: false`, all identical to 26ai) and on real OCI 19c (maintainer tier).
  19.12 to 19.x itself is still covered nowhere but the tenancy.
- **Native Network Encryption**, the thing that forces thick mode, is properly
  exercised only against a real NNE-required server. It can be **approximated
  locally**: set `SQLNET.ENCRYPTION_SERVER = required` in a container's
  `sqlnet.ora` and assert that a thin-mode connection fails with `DPY-3001` and
  that the tool's diagnostics say something useful. That covers the failure path;
  the success path still needs real OCI.

---

## 3. Capability-driven matrix

Tests declare the capabilities they need. The harness probes each target once per
session, and skips with a reason when a capability is absent.

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

Two things this buys beyond convenience:

- **The test suite validates the capability model itself.** If a driver claims
  `password_rollover` on 18c XE, the rollover test runs and fails there — which
  is the bug. Version-keyed skips would have hidden it.
- **New environments cost nothing.** Point the harness at a new container or a
  real database and the right subset runs. Adding 23ai did not require editing
  test files.

Report the resolved matrix at the end of a run, so "green" is never ambiguous:

```
capabilities exercised
                       23ai Free  21c XE  18c XE  11g XE  OCI 19c
common_users               –         –       –       –        ✓
password_rollover          ✓         –       –       –        ✓
offline_verify             –         ✓       ✓       ✓        ✓
password_reuse_policy      ✓         ✓       ✓       ✓        ✓

23 tests skipped (capability absent), 0 skipped (environment unavailable)
```

The second skip count is the one to watch: capability skips are correct, missing
environments are a coverage gap.

**Two of those dashes are the connecting account, not the release**, and they are
worth naming because a dash that looks wrong is what #195 turned out to be.
`common_users` asks whether the session holds `ALTER USER` *granted commonly*,
and the lane connects as `SYSTEM`, which holds it through a role — so
`USER_SYS_PRIVS` reads nothing and the capability is absent. `offline_verify`
needs `SELECT ON SYS.USER$`, which #86 made an optional grant and which `SYSTEM`
does not hold on 23ai Free either. Both were measured, both are correct, and
neither is fixed by editing the probe: they are fixed by connecting as an account
the install script has granted.

Implemented in `tests/oracle_harness.py` and the tier-1 fixtures in
`tests/conftest.py` (#174). Three things about it are decisions rather than
mechanics:

- **The probes are keyed on P1's capability list, not on a list of their own.**
  The sketch in `test/capabilities.py` asked about three things no driver
  reports and missed three that are capabilities — and a harness keyed on its
  own list cannot do the job claimed above, because validating the model
  requires asking the same question the driver answers. A test asserts the two
  lists are one list, so a new capability has to choose a side.
- **Not everything is a query.** Every supported Oracle can expire a password
  and lock an account; those are properties of the product, not of the instance.
  Writing `select 1 from dual` for them would look like a probe and measure
  nothing, which is worse than saying so — a reader would believe it. They are
  declared structural, with the reason attached, and the report can therefore
  distinguish *asked and told yes* from *there was nothing to ask*.
- **Three absences, three messages.** `oracledb` missing, Instant Client missing
  and the database unreachable are different findings, and only the third is
  what most people mean by "no test environment". Reporting the other two that
  way sends somebody to `docker` for a `pip` problem — so the skip names which
  it was, and the Instant Client case reads as itself rather than as `DPI-1047`.

The report is ASCII rather than the check marks drawn above. P4's cp1252 story
is exactly this: a redirected stream on Windows takes the locale codepage, and a
box-drawing character kills the writer mid-line. A test report that cannot
survive being piped into a log is not much of a report.

### Install shape is a dimension too (ADR-006)

Capabilities describe what the thing at the far end can do. **Install shape
describes what this machine can reach at all**, and it is a matrix dimension for
the same reason: a property nobody exercises is a property nobody has.

| Shape | Installed | What it proves |
|---|---|---|
| base | `pip install .` | the boundary in rule 3: none of the backends' clients importable, and the offline commands still work |
| one extra | `pip install ".[<name>]"`, each in turn | that backend imports on its own — no extra silently depends on a sibling |
| `all` | `pip install ".[all]"` | the shape every other test runs under, and the only one where a full suite is meaningful |

Base and `all` are cheap enough to run on every PR commit; both are tier 0 and
neither needs a container. The per-extra cells are one install and one import
each, and they matter most for the extra nobody develops against — the one whose
missing sibling import is discovered by a user rather than by CI.

The developer environment is `sopuli-dba[all]`, which is exactly why the base cell
has to exist: every ordinary test passes there whether or not base is clean, so
nothing else in the suite can see rule 3 break.

---

## 4. Tiers

| Tier | Runs | Where | Budget | Contents |
|---|---|---|---|---|
| 0 | every PR commit | public CI (`ci.yml`) | < 60 s | unit tests, config parsing and validation, target-set expansion, precedence resolution, SecretRef parsing, password generation and charset rules, redaction, the offline commands (`config`, `target list`, `policy sample`) through `CliRunner`, `lock status` and `lock break` with the store handed in — including the live/expired/nothing matrix, which is a comparison rather than a container and a sleep — and the install-shape assertions in §3 |
| 1 | every PR | public CI (`tier1.yml`, #184) | < 10 min | Oracle 23ai Free + Vault dev: the full UC-1 happy path, idempotency, drift, locking |
| 2 | nightly | public CI | < 30 min | 21c XE, 18c XE, 11g XE, PostgreSQL matrix; fault injection |
| 3 | pre-release | maintainer | manual | built 19c, real OCI 19c/26ai/ADB, OCI Vault, the release gates in §6 |

**The tier-1 lane installs Oracle Instant Client, and has to** (#184). D3 makes
thick mode mandatory — thin mode has no Native Network Encryption — so a runner
without the client would skip every driver test while reporting green. Basic Lite
is a free download needing no account, which keeps §1's rule intact: a fork can
do exactly what the lane does.

**A missing environment fails that lane rather than skipping.**
`SOPULI_TEST_TIER1=required` turns "no environment" into a failure and leaves
capability skips alone, which is §3's distinction made operational: a job that
exists to run tier 1 and reports green while skipping all of it is worse than no
job, because it gets quoted as evidence. Everywhere else — a laptop, a fork with
no stack up — the same tests skip with a reason, which is §1 working.

Tier 0 needs no containers at all and should stay that way — it is what makes the
inner development loop tolerable. Every pure-logic concern above (precedence,
templating, charsets, redaction) is deliberately testable without a database,
which is a reason to keep those layers free of I/O.

**Container lifecycle.** Most Oracle containers take minutes to start — 11g XE
slim is the exception, ready in about 15 seconds because it ships pre-built
datafiles. Do not create one per test. One long-running container per version per session; reset state
between tests by dropping and recreating the test accounts and profiles, not the
container. `testcontainers-python` handles session-scoped containers; a
`compose.yaml` plus fixtures works equally well and is easier to run by hand.

---

## 5. What gets tested

### Pure logic (tier 0, no database)

- config validation: unknown keys, both `accounts:` and `applications:` present,
  duplicate generated target names, unresolved `{placeholder}`, an `overrides`
  key naming a target that is not generated
- target-set expansion: per-outer-value inner dimensions, override application,
  label assignment
- precedence: every layer in P3, including the safety ratchet and the
  third-party-env ranking
- SecretRef parsing, including `#field/json/pointer` and `@version=`/`@stage=`
- the staged payload layout (Q7, #85): that Q7's two layouts produce the same
  arithmetic under one rule, and that a merge patch **omits** every sibling
  account rather than rewriting it with what was last read. The second is the
  interesting one — a patch that names a sibling is indistinguishable from a
  correct one until two accounts share a document, so it is asserted on what the
  patch does not contain
- password generation: charset, first character, byte length in a given database
  character set, composition requirements — each asserted over enough draws that
  "usually" fails. Two things output cannot show are pinned as well: that the
  source of randomness is the CSPRNG rather than `random`, and that no message
  about a rejected candidate repeats any of it
- redaction: the serialiser cannot emit a secret value
- **statement shape: the generated SQL is never a PL/SQL block, and never binds
  the password.** Assert against the statement text the Oracle driver layer
  produces — it must match `ALTER USER … IDENTIFIED BY …` directly, with no
  `BEGIN`/`DECLARE`/`EXECUTE IMMEDIATE` wrapper and no bind placeholder where the
  password goes. Invariants 13 and 14. This belongs in tier 0 because it needs no
  database, and it belongs *here* rather than being left to review because the
  measured 26ai result is counter-intuitive: wrapping the DDL in a block is the
  instinct that looks safer and is the one thing that actually leaks
  (`02-oracle-privileges.md` §4). A later refactor that introduces a wrapper —
  batching several rotations, say — breaks it silently and no database test would
  notice, because the DDL itself stays clean either way
- **install shape (ADR-006): a base install can import none of the backends'
  clients** — `httpx`, the OCI SDK, `python-oracledb`, and every name added to
  an extra afterwards. Assert against the resolved environment, not against
  source: the property is "an operator who ran `pip install sopuli-dba` cannot open
  a socket", and a grep for imports would pass on a machine where the extras
  happen to be present. The assertion is over that dependency set rather than
  over "an HTTP client", because `urllib` is importable in every Python — the
  stdlib is base code's own discipline (ADR-006 rule 3), not something a
  packaging test can hold. This is the one in the pair that regresses silently: it breaks the
  first time someone adds a convenient module-level import, and nothing else
  notices, because the developer environment is `sopuli-dba[all]`. Held in two
  halves, because neither is sufficient alone: `tests/store/test_install_shape.py`
  blocks the clients at the import system and imports every sopuli module outside
  a backend, which runs in any environment and names the module that broke it,
  and CI's `install-shape` job installs base for real and asserts the clients are
  absent, which is the only check that can see `pyproject.toml` itself go wrong
- **the absent-backend path, per backend (ADR-006).** Resolve a store whose
  extra is uninstalled and assert the whole contract: the message names the
  correct extra, `error.category` is `config`, `error.code` is `SOPULI-20001`,
  and the exit code is 9. Without it, the clean error rots into a traceback the
  first time a module is renamed — a rename that no other test can see, since
  every other test imports the module successfully
- the advisory lock: acquire, fence, renew and release against an in-memory KV v2
  fake with an injected clock — including the fencing case, where a lock is
  stolen mid-run and the original must abort before its next mutation. That case
  belongs here rather than in tier 2 because none of it is I/O: what makes a
  stolen lock detectable is a version comparison, and the store that supplies the
  version can be a dictionary. The tier-1 version below then checks the same
  property against a real Vault rather than discovering it there

### Against a database (tiers 1–3)

Carried over from UC-1 §11, with the environment each one needs:

| Test | Needs |
|---|---|
| UC-1 happy path: generate → apply → verify → promote | any |
| Idempotency: every command twice, second reports `unchanged` | any |
| Drift: change a password out of band, `check` reports DRIFT, exit 3 | any |
| **Lockout regression**: profile with `FAILED_LOGIN_ATTEMPTS 3`, run `check` against a drifted account 5×, assert the account never locks | any |
| Verify-function: profile with `ora12c_strong_verify_function` and a violating policy — bounded regeneration, then a clear error carrying the server message. **Assert on the error, never on `DBA_PROFILES`**: in a PDB a *common* profile's `PASSWORD_VERIFY_FUNCTION` limit reads `FROM ROOT` rather than the function name, so a dictionary check reports an unconfigured profile while the function is in fact enforcing (`ORA-28003` + `ORA-20000`). Measured for #317: a profile created *in* the PDB answers with the function's name, so a fixture that builds one locally can read it back — which is why `creds generate` reports three states and not two | any |
| Password reuse: `PASSWORD_REUSE_MAX`, assert no blind retry on ORA-28007 | any |
| **30-byte password limit** — a policy asking for more must be refused at *plan* time, not by `ORA-00972` mid-`apply`. Measured 2026-09-08 (#380): 31 bytes is refused on 11g XE, 18c XE **and 21c XE**, and accepted on 26ai. The two halves of the old wording do not travel together — see the next row — and `sopuli/driver/oracle/limits.py` keys the limit to 12.2, which is wrong on every line below 23ai (#383) | 21c XE / 18c XE / 11g XE |
| 10G/11G verifiers, and no `T:` — so `--method hash` must refuse rather than guess. Measured 2026-09-08: `SYS.USER$.SPARE4` carries `S:` alone on 11g and `S:` plus `T:` on 18c, 21c and 26ai (#382, #90). The field layout and salt offsets behind that were read 2026-09-15 by `sql/oracle/05_verifier_layout_probe.sql` (#431), and `06_verifier_reproduce.{sql,py}` regenerated every stored `T:`/`t:` digest client-side the same day (#432). #433 confirmed the refusal: 11g's absent `12C` (and a forced `10G 11G 12C` account on 18c) fix the rule that `hash` compares `12C` only and fails at plan time when there is none | 11g XE, 18c XE |
| **The non-CDB shape**, which is not a missing capability but a different set of questions Oracle will answer. `SYS_CONTEXT('USERENV','CON_NAME')` *raises* (`ORA-02003`) rather than answering NULL; `DBA_USERS` has no `ORACLE_MAINTAINED`, `PASSWORD_CHANGE_DATE` or `COMMON`; `USER_SYS_PRIVS` has no `COMMON`; there are no audit policies. Each of those took something down that had nothing to do with containers — the privilege audit blanked a whole target row while exiting 0 (#382) | 11g XE |
| **DDL text retention is not uniform** (unverified: ddl-text-versions). `V$SQLSTATS` keeps the `ALTER USER` statement on 11.2 and not on 18c, 21c or 26ai, so invariant 13's *conclusion* is release-dependent even though its reasoning is not. Decided in #387: documented, not warned about and not refused — which is only defensible while the table saying so is accurate, so a release claimed as supported gets `02_password_leak_probe.sql` run against it. 12.1, 12.2 and 19c are unmeasured, and the boundary below 18c is therefore unknown | every version claimed |
| Common user + `CONTAINER=ALL`, and refusal outside `CDB$ROOT` | any CDB |
| Rollover: both passwords valid during the window; `finish-rollover` ends it | 23ai Free, real 19.12+ |
| Rollover *absent*: `--strategy rollover` fails at plan time, not execution. **Measured on 18c 2026-09-08 (#381), and it had never run anywhere before that** — `test_a_release_without_rollover_refuses_at_plan_time` carries `@requires_no_capability(password_rollover)`, so on 26ai, the only server the suite had ever met, it skipped every time. Exit 5 under `--dry-run`, `error.category` `capability`, `error.target_capability` `password_rollover`, the `plan` emitted beside the refusal, and `doctor` reporting 5 capabilities rather than 6 one command earlier | 18c XE, 11g XE |
| `DBA_USERS` columns do not arrive together, and a fallback that assumes they do gives up a guardrail. `ORACLE_MAINTAINED` is present from 12.1 and `PASSWORD_CHANGE_DATE` only from 19c, so 18c has one and not the other (measured 2026-09-08, #381; the 19c end confirmed on 19.24.0.0.0, 2026-09-17). Narrowing on the first `ORA-00904` made 18c answer as 11.2 and read `vendor_maintained` as `None`, which silently switched guardrail check 2 off on a release that can answer it. Three query shapes now, all projecting the same columns | 18c XE, 11g XE |
| Standby refusal: `OPEN MODE = READ ONLY` detected before any DDL | real OCI |
| NNE: thin mode fails with `DPY-3001`, diagnostics are useful | container with `SQLNET.ENCRYPTION_SERVER=required` |
| Schema-privilege regression (P7, answered): `GRANT ALTER USER ON SCHEMA` must still fail with `ORA-00990`, while `GRANT SELECT ANY TABLE ON SCHEMA` must still succeed. **Assert both** — without the control, a future release that dropped schema privileges entirely would look like the same pass. A newly-succeeding `ALTER USER` grant re-opens the privilege model, so this is a test worth keeping rather than a question worth deleting | 23-codebase (tier 1) |
| Shared JSON document: writing one account's password leaves siblings byte-identical | any + Vault |
| KV v1 degradation: no versioning, staging emulated in payload, and the tool says so | Vault KV v1 mount |
| `lock status` reads a record the tool did not write: a config entry opens a store, authenticates, and reports somebody else's held lock — and the survey leaves the version counter where it found it, because `status` takes no lock (#105) | Vault |
| `list` agrees between the fake and the real mount (#150): full readable paths, recursion through subtree markers, a prefix that stops on a segment boundary, and — the one a dictionary-backed fake would never produce on its own — a soft-deleted path that is still listed and still reads as nothing, because KV v2 lists metadata and metadata outlives data | Vault, both mounts |
| `lock status` reports a record at a path the config does not declare (#150), marked `declared: false`, and a store with no `list` capability warns (`SOPULI-W005`) instead of failing the survey — so the command does not become one that works on some backends and not others | Vault |
| `lock break` takes a record the tool did not write, with a compare-and-set against a version Vault issued, and **the manager that held it fails its next check** (#149). The fence is the whole reason the verb is allowed to exist, and it is the one thing about it a fake cannot establish: a store that counts integers agrees with the tool by construction | Vault |

### Running it, which is not the same as testing it

The table above is what CI asserts. This is the step before writing any of it,
and it is a rule rather than a habit: **a change to what the tool reads from a
target or a store, writes to one, or reports about one is verified by running the
verb against a real one before the PR opens.** Tier 1 is the floor — it is the
stack that comes up locally — and tiers 2 and 3 stay the pre-release matrix §1
describes.

**A floor, not a ceiling.** While the repository is private there are no
contributors for §1's constraint to protect, so nothing stops a change reaching
for a harder environment when it deserves one. §1 starts capping this at tier 1
when the repository goes public, and that is the point to revisit the wording
rather than now.

The point is not coverage; CI runs tier 1 on every pull request. The point is
that **a test asserts what its author already suspected**, and the failures worth
catching here are the ones nobody thought to suspect. Three that got through:

| What happened | Why no test would have caught it |
|---|---|
| A `creds check` sample was written into this repository's documents before the command was run, and the command did not print it (#309) | the sample was prose, and prose is not executed |
| `ORA-28002` is the documented grace-period code; 26ai sends `ORA-28098` or `ORA-28011` depending on the profile, on a connection that **succeeds** (#322) | the dead branch matched a constant nobody had ever seen the server produce |
| A diagnostic query reported the probing session itself — in one run out of two (#326) | a single green run is not a measurement of an intermittent fault |

Two rules follow from those, and they are the whole of it:

1. **Paste real output.** Any sample in a design document, a PR body, a docstring
   or an issue comes from a run that happened. Never write what a command *would*
   print.
2. **Measure, do not reason, about a vendor's behaviour.** What an error code is,
   whether it arrives as an exception, what a status column spells — these are
   facts about somebody else's software. `02-oracle-privileges.md` §4 and
   `sopuli/driver/oracle/accounts.py` record several that came out the opposite
   way from the obvious guess.

### Fault injection (tier 2)

The UC-1 §8 failure table is a test list. Each row asserts the documented
recovery, not merely that the tool did not crash:

| Injection | Assert |
|---|---|
| kill the process between `password_set` and `vault_promote` | `pending` still holds the new value; `check` reports `PENDING_APPLY`; `promote` completes it |
| vault unreachable mid-run | nothing applied, or applied-but-not-promoted; never silently promoted |
| close a PDB mid-run (multi-target) | partial success, exit 4, other targets untouched; `apply --repair` fixes it |
| revoke `ALTER USER` mid-run | clean authorization error, no half-written state |
| two `rotate` runs on one account concurrently | one loses the lock with exit 7; final state consistent |
| steal a held lock mid-run: expire it, let a second run take it over | the first run's next fence check fails, and it aborts before its next `ALTER USER`. Nothing half-applied from a stale plan |
| kill a run holding a lock, then start another | by default the second refuses with exit 7, reporting the holder and that the lock has expired — breaking one is not self-service. Under `locking.break_expired` it takes it with a CAS write that bumps the version, which fences the zombie if it ever wakes |
| vault returns a stale read after write | post-verify catches it and reports rather than promoting |

Mechanics: `docker pause`/`stop` for the database, and a TCP proxy (toxiproxy or
equivalent) between the tool and both the database and the vault for latency,
truncation and connection-drop faults. Process kills are easiest driven from the
`jsonl` event stream — wait for `seq` of `password.applied`, then `SIGKILL`.
That the event stream makes this testable is a good sign the stream is right.

---

## 6. Release gates

Not tests that can be skipped. A release does not happen if any of these is red.

1. **Redaction.** Run the full suite at `--log-level debug`, then grep every
   artefact — stdout, stderr, log files, JSON output, audit records — for every
   generated password. Zero hits.

   **`policy sample --reveal` is excluded by name**, and it is the only exclusion.
   That command prints a password because printing one is what it is for
   (invariant 2's third exception: a sample is not a credential, since nothing
   authenticates with it and it is never stored). Excluding it would weaken the
   gate if it stopped there, so the gate gains the narrower property in exchange:
   **no JSON document contains a sample value, `--reveal` or not** — which holds
   because the run schema gives a `sample` object no value property, and because
   `--reveal` with `--output json` is refused. Grep the JSON artefacts of a
   `policy sample` run for the values it printed; zero hits.
2. **Password leakage into Oracle.** Run `sql/oracle/02_password_leak_probe.sql`
   on each supported major version. It plants one canary per execution path —
   client-issued `CREATE USER`, client-issued `ALTER USER`, `EXECUTE IMMEDIATE`
   with the password as a literal in the block, and `EXECUTE IMMEDIATE` with it
   assembled at runtime — then sweeps every source a statement's text can come to
   rest in. Whatever it finds is written up in `02-oracle-privileges.md` §4, and
   what is still outstanding is recorded below. This is the empirical check that
   §4 refuses to assume.

   **Three positions per version, and they are not interchangeable:**

   | # | Connect to | `svc_user` | What it establishes |
   |---|---|---|---|
   | 1 | the PDB service | the account holding `ALTER USER` and nothing else | **the only position that proves the audit policy works.** This is how sopuli operates |
   | 2 | the PDB service | `sys` | the SYSDBA path, including the `audit_file_dest` greps that only `AUDIT_SYS_OPERATIONS` populates |
   | 3 | the CDB service | a common `C##` account | that container scope does not change the answer |

   Position 1 is the one that carries the result, and it has a validity check that
   must be read before its findings are believed: **§3's output must say
   `isdba=FALSE`.** SYS's actions are captured by MANDATORY unified auditing
   regardless of any policy, so a run that reports `isdba=TRUE` demonstrates
   nothing about `SOPULI_PROBE_POL` — the trail would look identical with no policy
   at all. Confirm alongside it that the `ALTER USER` rows in §5 are attributed to
   the service account rather than to `SYS`.

   Two more reading rules, both of which turn an apparent pass into a non-result:
   a `clean` on a `pop=n` column is an absence of evidence and the sweep labels it
   `INCONCLUSIVE`; and `DBA_HIST_SQLTEXT` needs an AWR snapshot taken *before* the
   sweep, so it stays untested until one is (unverified: ddl-text-awr).

   **Where it stands.** Position 1 has been run on 26ai Free 23.26.2.0.0 (PDB
   and `CDB$ROOT`), 21c XE 21.3.0.0.0 and 18c XE 18.4.0.0.0 (PDB), and 11g XE
   11.2.0.2.0 (non-CDB) — #380, #381, #382. **Position 2 with
   `AUDIT_SYS_OPERATIONS = TRUE` was run on 21c and 26ai on 2026-09-11** (#407),
   which is what the `audit_file_dest` greps needed to mean anything, together
   with §7's greps on 26ai and the three checks the probe left manual. The
   findings and their scope are `02-oracle-privileges.md` §4; the one release
   that disagrees is 11.2, whose `V$SQLSTATS` retains the `ALTER USER` text
   (#387).

   **This entry said "position 2 has not been run anywhere" until #407, and that
   was wrong in a way worth recording** rather than quietly fixing. The probe's
   own header records a position 2 run on 26ai on 2026-08-26, in the table of
   three positions. What had never been run was the half position 2 *exists*
   for — the `audit_file_dest` greps that only `AUDIT_SYS_OPERATIONS` populates
   — and this list compressed that into a claim about the position. Two
   documents describing the same run at different resolutions is how a gate
   loses track of itself, and the fix is to say which *surface* is unrun rather
   than which position.

   Outstanding, and none of it is a pass:

   | Open | Why it blocks a claim |
   |---|---|
   | **19c** unrun | what an OCI estate runs, and not redistributable as a container. Two open questions turn on it: the password byte limit (#383) and whether 11.2's `V$SQLSTATS` retention reaches it (#387) |
   | **12.1 and 12.2** unrun (unverified: ddl-text-versions) | so **the boundary is unknown.** 11.2 retains the DDL text and 18.4 does not, and nothing measures where between them that changed. Read the 11.2 result as *11.2 does*, never as *everything older does* |
   | **AWR / `DBA_HIST_SQLTEXT`** untested (unverified: ddl-text-awr) | needs a snapshot taken before the sweep, on a database where the Diagnostics Pack is enabled — so a licensed EE, not any XE image. Untested, not clean. **The only row here that #407 could not close**, and the reason is the one that keeps it open: every image in this stack ships `control_management_pack_access = NONE` |

   Closed by #407 on 2026-09-11, on 26ai 23.26.2.0.0 and 21c 21.3.0.0.0, and
   recorded in `02-oracle-privileges.md` §4 with the version on every row:

   | Was open | Answer |
   |---|---|
   | **Trace files** — the `grep` of `Diag Trace` | **does not capture the password**, which retires an assumption rather than confirming it. Level 12 writes the cursor truncated — `ALTER USER sopulitest IDE` — across five traced sessions on two releases. The wrapped form leaks in full, so this is invariant 13 on a fifth surface |
   | **OS audit files**, `svc_user = sys` | 21c writes the DDL **masked** to the OS file, one verbatim canary in 646 `ACTION` lines and it is the PL/SQL wrapper. **26ai writes no user-management DDL there at all**, so its clean grep is `pop=n` in OS-file form and is recorded as absent rather than clean |
   | **Self-rotation** (probe §6a) | **audited and masked on both secrets** — `IDENTIFIED BY * REPLACE *`, attributed to the account itself. Privilege auditing does not miss it, so "rotations are audited" holds for this path too |
   | **`IDENTIFIED BY VALUES`** (probe §6b) | **the verifier is masked** — `IDENTIFIED BY VALUES *` — and appears in no OS audit file and no trace file |

   The last three were comments in the probe rather than code, which is why they
   sat unrun from the first version of the gate to #407. They are
   `sql/oracle/04_password_leak_extensions.sql` now, and that is the general
   lesson rather than a filing decision: **a check that is a comment is a check
   that does not run.**
3. **Schema conformance.** Every sample and recorded output validates against the
   published JSON Schema. Already wired: the schemas and example in
   `docs/schemas/` validate today, the config schema is asserted to be what the
   config layer generates, and `01-configuration.md`'s own worked example is
   validated against it.
4. **Lockout.** The lockout regression test passes on every Oracle version in the
   matrix. A tool that locks production accounts while checking them is worse
   than no tool.
5. **Idempotency.** Every command twice, everywhere, `changed: false` on the
   second run.
6. **The lock holds under contention, and a stolen lock stops the run that lost
   it** (#106). `tests/store/test_lock_concurrency.py`, against a real Vault:
   two genuinely concurrent processes take one lock and exactly one wins, the
   loser exits 7 having changed nothing, and a holder whose record is overwritten
   mid-run fails its next fence check.

   **Two processes, not two managers over one dictionary.** Tier 0 covers both
   properties already and cannot cover this one: it forces the race by driving
   the store in a chosen order, which proves the manager reacts correctly to a
   lost compare-and-set but never lets two runs actually start together. A gate
   that only ever ran in-process is not the gate a release note claims.

   The two facts about the *store* rather than the manager are asserted here for
   the same reason: that `cas: 0` fails forever on a deleted path — the fact
   behind "release writes a record, never deletes one" — and what a KV v1 mount
   with no compare-and-set does and does not promise. The second asserts a
   **weakness** on purpose: a run reporting `cas` there would be claiming a
   guarantee it does not have, and that is the failure worth catching.

   **The split cuts both ways, and #197 is the case that showed it.** That
   second gate asserted that two racers on the KV v1 mount *both* acquire, and
   it was asserting a coin flip: `acquire` reads the path before it writes on
   `advisory-only` exactly as on `required`, so a racer whose read lands after
   the other's write is correctly denied. Both outcomes are legal and which one
   appears is a fact about how a loaded machine schedules two processes. It
   passed for as long as it did because an idle machine wins the toss every
   time; the lane added in #184 is what finally ran it enough to lose.

   So a claim about an **interleaving** — two runs both reading before either
   writes — cannot be made from this side either, for the mirror of the reason
   the one-winner claim cannot be made from tier 0. The window is inside
   `acquire`, no handshake reaches into it, and two processes released together
   land in it only sometimes. What tier 1 asserts is what holds on every run
   whatever the scheduler did: nobody is handed a fence, every run reports
   `mode: none`, and a denial is never a *lost* compare-and-set, because on a
   mount without `cas` there is none to lose. That last one is also asserted
   deterministically beside it, against a planted record, since the raced form
   reaches it only when the timing cooperates.

   The interleaving claim itself — two runs *can* hold one advisory lock at once
   — moved to `tests/lock/test_manager.py`, where the window can be held open:
   a store that parks each racer's first read on a barrier until they have all
   looked, so no write happens until every read has answered against the empty
   path. Threads are the mechanism and not the subject — **no outcome depends on
   which one the scheduler favours**, only on an ordering that is imposed, which
   is what separates this from the coin flip it replaces.

   Two overrides make it honest rather than convenient, and both were forced by
   review. The barrier is per thread's *first* read, because `release` and
   `check` read too and a barrier they also hit would deadlock the moment one
   racer finished first. And `write` takes a lock, because `MemoryStore` has
   never had to be thread-safe and its compare-and-set is a check followed by an
   increment — two threads can both pass it and both commit, which would have
   made the contrast below flaky in exactly the way this whole change is about.
   A real store serialises writes; the fake does too, now that anything calls it
   from two threads.

   The contrast is the part that makes it a test about locking rather than about
   a double that was told to lie: the *same* interleaving against a store that
   has `cas` still yields exactly one winner. Which one loses is not asserted —
   an outcome worth asserting is one the ordering cannot change.

   The rule this leaves: **tier 0 owns claims about ordering, tier 1 owns claims
   about simultaneity.** Each tier can force exactly one of them, and a claim
   asserted on the wrong side of that line is a coin flip whether or not it has
   started losing yet.

   A tool that lets two runs rotate one credential at once is worse than one with
   no locking at all, because the second at least does not claim otherwise.

---

## 7. Test data and fixtures

- **Never a real account name, host, tenant or path.** Fixtures use the same
  fictional vocabulary as `01-configuration.md`: application `acme`, accounts
  `acme_*_user`, tenants `alpha…theta`, hosts under `example.com`, documentation
  IPs from `192.0.2.0/24`.
- Each test creates its own accounts under a per-run prefix and drops them
  afterwards, so a failed run leaves nothing that breaks the next one.
- Profiles used by tests (`FAILED_LOGIN_ATTEMPTS 3`, rollover configured, verify
  function attached) are created by the harness, never assumed to exist.
- The Vault dev container starts empty; every test seeds what it needs. No shared
  fixture state between tests — this is a concurrency-sensitive tool and shared
  fixtures would hide exactly the bugs worth finding.

---

## 8. Open questions

| # | Question | Leaning |
|---|---|---|
| ~~T1~~ | ~~Does `gvenzl/oracle-xe:11` exist?~~ | **resolved 2026-08-08: yes.** `11.2.0.2-slim` pulls, starts in ~15 s and accepts the test profiles. 11.2 stays tier 2; D7 is cheap. amd64-only. See §2 |
| ~~T2~~ | ~~`testcontainers-python` or `compose.yaml` + fixtures?~~ | **resolved 2026-08-20 in #174: compose.** The harness configures a DSN and probes whatever answers; it starts nothing and stops nothing. That is the choice made concrete rather than merely stated — a fixture that managed containers would be a second definition of the stack alongside `test/compose.yaml`, and the reason for compose in the first place is that this tool's users are DBAs who will want to run the stack by hand and look at it. `SOPULI_TEST_ORACLE_DSN` points it elsewhere; the default is the compose service |
| T3 | Is LocalStack Secrets Manager in the community tier? | verify before committing to it as the AWS path |
| T4 | Does OCI Vault cost enough to matter in a test loop? | check pricing; if so, tier 3 only and reuse one secret |
| ~~T5~~ | ~~Public CI provider~~ | **resolved 2026-08-09: GitHub Actions.** Tier 0 runs in `.github/workflows/ci.yml`; the repository and release-please were already there, so a second provider would have bought nothing. Oracle Free containers run on amd64 hosted runners when tier 1 arrives. One constraint found while wiring it: branch protection is unavailable on a private repo on the free plan, so CI reports but cannot block — see `../workflow.md` |
| T6 | Do we need a real Data Guard standby to test the read-only refusal? | probably: a closed PDB is not the same failure. Defer until a driver bug argues for it |
| T7 | Snapshot/restore for faster Oracle resets | start with drop-and-recreate; revisit if tier 2 exceeds its budget |

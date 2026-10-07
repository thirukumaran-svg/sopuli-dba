# Test environments

What each environment is, and what to know before using it:

- **tier 0** brings up Vault, with both KV versions mounted, and PostgreSQL.
- **tier 1** adds Oracle Free, with the profiles in `oracle-init/`.
- **21c XE** (`oracle-xe21`) is healthy in about a minute. The `oracle-init/`
  profiles are created, including `SOPULI_ROLLOVER`. **Set `AUDIT_TRAIL` before
  you believe anything about auditing on it.** The image ships `NONE`, which
  captures nothing, not even the Oracle-supplied `ORA_LOGON_FAILURES` policy
  after a real failed logon. Run `alter system set audit_trail=db,extended
  scope=spfile` and restart. Quoting the value gives `ORA-00096`.
- **18c XE** (`oracle-xe18`) is the release the matrix keeps for what it
  *cannot* do. It has no `password_rollover`, so `doctor` reports one capability
  fewer and `--strategy rollover` exits 5 at plan time. `SOPULI_ROLLOVER` is not
  created there, by design: step 4 of `oracle-init/01_test_profiles.sql` reports
  and carries on. A test that needs a second profile must use `SOPULI_REUSE`.
  The `AUDIT_TRAIL` note above applies here too.
- **11g XE** (`oracle-xe11`) is the fastest to start. Its *shape* differs, not
  only its capabilities. It is a non-CDB, so `SYS_CONTEXT('USERENV','CON_NAME')`
  **raises** `ORA-02003` instead of returning NULL. It has no unified auditing,
  so `01_audit_policy.sql` refuses. It has no `ORACLE_MAINTAINED`,
  `PASSWORD_CHANGE_DATE` or `COMMON` columns. `ora12c_strong_verify_function`
  does not exist, so `SOPULI_STRONG` is absent beside `SOPULI_ROLLOVER`. Read
  its rows in [`../docs/measurements.md`](../docs/measurements.md) before you
  quote a leak result from it: `V$SQLSTATS` keeps the `ALTER USER` text there.
- **19.3 EE** has a profile of its own, `oracle19c`, and is maintainer-only. Read
  `docs/maintainer-environments.md` §2 before you pull it.
- **19.19 EE**, profile `oracle19c-ru`, runs on **arm64 hosts only**. On x86 it
  does not start under emulation, and it has not been run on arm64. A current
  release update is an OCI DB system instead, not a compose service: see
  `oci-dbcs/new-db-system.ps1`.
- **12.2.0.1 EE**, profile `oracle12c`, is maintainer-only on the same terms as
  19.3, and needs a one-time `docker exec` after its first start. See
  `docs/maintainer-environments.md` §3.
- `nne` and `emulators` have not been run.

The releases each environment was measured on are in
[`../docs/measurements.md`](../docs/measurements.md).

Strategy and rationale: [`../docs/design/04-testing.md`](../docs/design/04-testing.md).

## Quick start

```bash
docker compose --profile tier0 up -d      # Vault + PostgreSQL, seconds
docker compose --profile tier1 up -d      # + Oracle Free, ~30-60 s to healthy
docker compose --profile tier2 up -d      # + 21c/18c/11g XE + toxiproxy, minutes
docker compose --profile nne   up -d      # Oracle requiring Native Network Encryption
docker compose --profile oracle19c up -d  # 19.3 EE, maintainer-only, 15-25 min the first time
docker compose --profile oracle19c-ru up -d  # 19.19 EE, arm64 hosts only; fails under emulation on x86
docker compose --profile oracle12c up -d  # 12.2.0.1 EE, maintainer-only; run its init.sh once, then healthy
docker compose --profile '*'   down       # tear down EVERYTHING — see below
```

**Profiles are additive, so the tiers nest.** Every tier0 service also carries the
tier1 and tier2 profiles, so `--profile tier1 up -d` over a running tier0 adds
Oracle and leaves Vault and PostgreSQL untouched — same containers, uninterrupted
uptime, and Vault's in-memory `kv`/`kv1` data intact. Verified by container id, and
it matters: dev-mode Vault is `inmem`, so a recreate would silently discard
anything a test had written. There is no tier0-only service, which is why moving
up a tier can never tear something down.

Oracle containers are deliberately long-running. Tests reset state by dropping
and recreating accounts, never by recreating the container — startup dominates
everything else. **Nothing in this file enforces that**: no service has a named
data volume but the two 19c ones and 12.2, so any teardown discards the database and the next
`up` re-initialises from scratch.

## Teardown, which is not what you would guess

`docker compose down` **does nothing at all here.** Every service in
`compose.yaml` carries a `profiles:` key, so a command with no profile selected
matches zero services — it prints nothing and exits 0. `--remove-orphans` does not
help either: an orphan is a container whose service left the file, not one
excluded by a profile.

| Command | What it actually does |
|---|---|
| `docker compose --profile '*' down` | **the one you want.** Removes every container and the network |
| `docker compose down` | no-op. Silent, exit 0 |
| `docker compose down --remove-orphans` | also a no-op |
| `docker compose --profile tier0 down` | removes *only* tier0's services. Leaves Oracle running and then cannot remove the network — `Resource is still in use`. A half-torn-down stack that does not announce itself |

`-v` matters for exactly three services. `oracle-19c` and `oracle-19c-ru` have
named volumes (`oracle19c-data`, `oracle19c-ru-data`) because their databases take
tens of minutes to create; `oracle-12c` has one (`oracle12c-data`) because its
one-time init — the password file, a `USERS` tablespace, the profiles — lives in
the datafiles. `--profile '*' down` keeps all three and the next `up` is a
restart, and `--profile '*' down -v` throws them away.
`-v` is scoped to the selected profile, so `--profile oracle19c-ru down -v` removes
only the 19.19 volume and leaves 19.3's (checked 2026-09-28 with a scratch
two-profile project). Every other service loses its state on any `down`, with or
without `-v`.

| Service | Port | Notes |
|---|---|---|
| vault | 8200 | dev mode, root token `sopuli-test-root`; `kv` (v2) and `kv1` (v1) both mounted. **Restarting it loses both** — dev mode is in-memory and `vault-init` only runs on `up`, so a `stop`/`start` leaves a healthy Vault with no mounts and every tier-1 store test failing on a 404. `docker compose --profile tier0 up -d vault-init` puts them back. **UI at <http://127.0.0.1:8200/ui>** — enabled by default in dev mode, log in with the root token. Dev mode also mounts `secret/` (KV v2) and `agent-registry/`, which is not a KV mount. So three KV mounts exist, and a test asserting on the mount list must expect all of these |
| postgres | 5432 | `postgres` / `sopuli-test` |
| oracle-free | 1521 | 23ai/26ai Free — CDB + PDB, rollover |
| oracle-xe21 | 1522 | 21c XE |
| oracle-xe18 | 1523 | 18c XE — no rollover, a deliberate negative case |
| oracle-xe11 | 1524 | 11g XE — non-CDB, SID `XE` not a PDB service; 30-byte passwords; amd64 only |
| oracle-nne | 1525 | NNE required; thin mode must fail with `DPY-3001` |
| oracle-19c | 1526 | **19.3.0.0.0 EE, `--profile oracle19c` only**, maintainer-only (Oracle account + licence acceptance to pull, never in CI). CDB `ORCLCDB`, PDB `ORCLPDB1`; `SYSTEM` / `sopuli-test`. No rollover (19.12+). Named volume, so it survives `down` |
| oracle-19c-ru | 1527 | **19.19.0.0.0 EE, `--profile oracle19c-ru` only**, same terms as oracle-19c. **The image is linux/arm64 only and needs an arm64 host**: under QEMU on x86 DBCA dies with `ORA-00443` / `ORA-01096` (#565). The one pullable 19c past 19.12, so the one that can open a rollover window. Untested on arm64 so far. Named volume, so it survives `down` |
| oracle-12c | 1528 | **12.2.0.1.0 EE, `--profile oracle12c` only**, same terms as oracle-19c. CDB `ORCLCDB`, PDB service **`ORCLPDB1.localdomain`** (this image appends `DB_DOMAIN`; a bare `ORCLPDB1` is `ORA-12514`); `SYSTEM` / `sopuli-test`. **`WE8DEC`, not `AL32UTF8`**. No rollover. Run `test/oracle-init-12c/init.sh` once after the first start — the image has no user-script hook. Named volume, so it survives `down` |
| toxiproxy | 8474 | fault injection in front of DB and vault |

## Before trusting any of this

1. Confirm the `sqlnet.ora` mount path for the NNE service — it is image- and
   version-specific.
2. Confirm which LocalStack tier includes Secrets Manager (T3).

## Gotchas found by actually running tier0 and tier1

- **`SOPULI_STRONG` reads as `FROM ROOT`, not as the function name.** In the PDB,
  `DBA_PROFILES.LIMIT` for `PASSWORD_VERIFY_FUNCTION` is `FROM ROOT`. The function
  *is* enforced — a 4-character password gives `ORA-28003` plus
  `ORA-20000: password length less than 9 characters` — so **assert on the error,
  not on the dictionary value.** A test checking for
  `PASSWORD_VERIFY_FUNCTION = 'ORA12C_STRONG_VERIFY_FUNCTION'` concludes the
  profile is unconfigured when it is working correctly.
- **`kv` and `kv1` are shared with whatever you have run by hand**, and that is a
  trap for any test that surveys a *prefix* rather than reading back the one path
  it wrote. `lock status` reports every record under `locks/` on purpose (#150),
  so a single `sopuli creds apply` against the local stack leaves
  `locks/apps/acme/dev` behind and turns `tests/store/test_lock_status_vault.py`
  red — a failure that reads as a regression in `lock status` and is nothing of
  the kind. The fix for one record is
  `vault kv metadata delete -mount=kv locks/apps/acme/dev`; the fix for a *test*
  is the `private_mount` fixture in `tests/conftest.py`, which gives the module a
  KV v2 mount of its own and tears it down afterwards. Prefer the fixture — the
  mount is the only boundary available, since the `locks/` prefix is fixed by
  `sopuli.lock.manager.LOCK_PREFIX` and cannot be moved out of the way (#272).
- **`vault-init` logs two 400 errors on every `up` after the first.** It is a
  one-shot that has already exited, so `up` starts it again, and both
  `vault secrets enable` calls fail with `path is already in use`. `|| true`
  swallows them, so it exits 0 and still prints `kv (v2) and kv1 (v1) mounted` —
  harmless, but the errors are the first thing anyone debugging this stack will
  find. A `vault secrets list | grep -q` guard before each enable would silence it.
- **Vault is pinned to `hashicorp/vault:2.0.4`**, not tracked as `:latest`,
  because `tests/store/test_hashicorp_cas_conflict.py`
  asserts on Vault's own error wording and an upstream bump has to be a
  deliberate line change here, not a silent moving target.
- **`gvenzl/oracle-free:latest` is 26ai**, which is the *same database* as 23ai
  under a new name, not a newer version. So this image is the 23ai line, and
  results from it apply to it; there is no separate 23ai to obtain. Cite the release number rather than the name, because next quarter's 26ai
  is a different RU. Detail in
  [`../docs/design/04-testing.md`](../docs/design/04-testing.md) §2.
- Oracle Free usually reaches `healthy` in **30–60 s**, because the image ships
  a pre-built database. The `start_period: 120s` is generous, not necessary.
- `gvenzl/oracle-xe:11.2.0.2-slim`, the image `oracle-xe11` uses, exists and
  `oracle-init/01_test_profiles.sql` runs against it, so Oracle 11.2 stays in tier 2 ([T1](../docs/decisions/log.md#t1)).

## What is *not* here, on purpose

- **Oracle 19c and 12.2 EE in a public tier.** The images need an Oracle account
  to pull, so they are compose services under their own profiles (`oracle19c`,
  `oracle19c-ru`, `oracle12c`), maintainer-only and never in CI.
- **Real OCI** — 19c, 26ai, ADB, OCI Vault. No emulator is faithful enough to be
  release evidence, and this is where Native Network Encryption and Autonomous
  behaviour are actually verified.
- **Emulators** (`--profile emulators`: LocalStack, lowkey-vault) are smoke tests
  only. A green emulator run is never a reason to cut a release.

The public test suite must be green using only what a contributor can pull —
`tier0` and `tier1`. Anything needing more must skip with a reason, never fail.

## Files

| File | Purpose |
|---|---|
| `compose.yaml` | the stack, split by profile |
| `oracle-init/01_test_profiles.sql` | profiles the suite needs: lockout, strong verify function, password reuse, rollover |
| `oracle-init/sqlnet-nne.ora` | forces Native Network Encryption on the NNE service |
| `capabilities.py` | sketch of capability probing and the pytest skip markers |
| `vault_cas_probe.py` | exploratory spike: what a real Vault CAS conflict looks like on the wire (#103, #104). Run by hand; the regression it found lives in `../tests/store/test_hashicorp_cas_conflict.py` instead |
| `vault_auth_probe.py` | exploratory spike behind [ADR-005](../docs/decisions/adr-005-vault-client.md): whether `hvac`'s auth surface was worth the dependency (#103) — it wasn't. Run by hand |
| `paths_ignore_probe.py` | which files under `docs/`, `sql/` and `examples/` — **and the root `README.md` and `CLAUDE.md`** — a **skipped lane** actually opens, and whether either workflow's prose allowlist covers one of them. Not "the suite": it deselects the modules `ci.yml`'s `docs` job runs, because what that job covers is not a hole in the list. Run by hand with tier 1 up — with no containers ~100 tests skip and whatever they read is invisible to it. Exits non-zero on a conflict, so `ci.yml`'s and `tier1.yml`'s lists stay measured rather than guessed. It watches the two root files because both are on the prose list and `tests/test_verification_register.py` scans both. It **deselects** the `DOCS_LANE` modules because `ci.yml`'s `docs` job runs those on exactly the pull requests where the other lanes are skipped, so the question is what a *skipped lane* reads, not what the suite reads. Adding a test that reads prose means adding it to `DOCS_LANE` **and** to that job, or this goes quiet about whatever it reads |
| `k8s_eso_probe.py` | the evidence behind [`../docs/scenarios/kubernetes-eso.md`](../docs/scenarios/kubernetes-eso.md) §7: stands up Vault, the External Secrets Operator and the document's own manifests on a throwaway cluster, and checks that ESO reads what sopuli wrote. Needs Kubernetes rather than compose — see below. Run by hand |

Test accounts are created and dropped per test under a per-run prefix. Only the
profiles are created at container init, so no test assumes anything pre-exists.
Fixtures use the fictional vocabulary from `01-configuration.md` — application
`acme`, tenants `alpha…theta`, hosts under `example.com`.

## Kubernetes, which is not part of the compose stack

`k8s_eso_probe.py` is the one thing here that does not use `compose.yaml`. It
needs a Kubernetes cluster, because the thing it is checking is a Kubernetes
add-on reading a vault. Docker Desktop's built-in cluster is what it was
written against — *Settings → Kubernetes → Enable Kubernetes* — and any cluster
`kubectl` can reach should do.

```bash
python k8s_eso_probe.py          # stand it up, check it, tear it down
python k8s_eso_probe.py --keep   # leave it up to poke at
python k8s_eso_probe.py --down   # remove everything it created
```

It creates two namespaces — `sopuli-test` for the vault and the document's
objects, `external-secrets` for the operator. It installs nothing on the host:
Helm runs in a container and only ever renders YAML, which `kubectl` then
applies.

**`--down` uninstalls ESO from the cluster**, not just from its namespace. It
deletes both namespaces and then re-renders the chart to delete what that
installed — the CRDs, the cluster roles and the webhook configurations, none of
which a namespace deletion touches. Deleting the CRDs takes every
`ExternalSecret` and `SecretStore` in the cluster with them, this probe's or
not, so do not run any of this on a cluster where somebody else is using ESO.
The script warns if it finds ESO already installed.

It is deliberately not a pytest test, for the reason `vault_cas_probe.py` is
not one: it needs an environment the suite cannot assume, it installs a
third-party operator, and it takes minutes. **It is the thing to re-run when
`kubernetes-eso.md` changes**, because it reads the manifests out of that
document rather than keeping a copy of them.

# Test environments

Draft sketch. Nothing here has been run; image tags are unverified.
Strategy and rationale: [`../docs/design/04-testing.md`](../docs/design/04-testing.md).

## Quick start

```bash
docker compose --profile tier0 up -d      # Vault + PostgreSQL, seconds
docker compose --profile tier1 up -d      # + Oracle 23ai Free, ~1-2 min first start
docker compose --profile tier2 up -d      # + 21c/18c/11g XE + toxiproxy, minutes
docker compose --profile nne   up -d      # Oracle requiring Native Network Encryption
docker compose down -v                    # tear down, including volumes
```

Oracle containers are deliberately long-running. Tests reset state by dropping
and recreating accounts, never by recreating the container — startup dominates
everything else.

| Service | Port | Notes |
|---|---|---|
| vault | 8200 | dev mode, root token `sopuli-test-root`; `kv` (v2) and `kv1` (v1) both mounted |
| postgres | 5432 | `postgres` / `sopuli-test` |
| oracle-free | 1521 | 23ai/26ai Free — CDB + PDB, rollover |
| oracle-xe21 | 1522 | 21c XE |
| oracle-xe18 | 1523 | 18c XE — no rollover, a deliberate negative case |
| oracle-xe11 | 1524 | 11g XE — non-CDB, 30-byte passwords (**tag unverified**) |
| oracle-nne | 1525 | NNE required; thin mode must fail with `DPY-3001` |
| toxiproxy | 8474 | fault injection in front of DB and vault |

## Before trusting any of this

1. **Confirm `gvenzl/oracle-xe:11-slim` exists** (04-testing.md T1). It decides
   whether Oracle 11.2 support is cheap or maintainer-only, and it is the single
   highest-value thing to check first.
2. Confirm the `sqlnet.ora` mount path for the NNE service — it is image- and
   version-specific.
3. Confirm which LocalStack tier includes Secrets Manager (T3).

## What is *not* here, on purpose

- **Oracle 19c EE.** Not redistributable, so it cannot be a compose service.
  Build it from [`oracle/docker-images`](https://github.com/oracle/docker-images)
  with binaries you download, and keep it in the maintainer tier.
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

Test accounts are created and dropped per test under a per-run prefix. Only the
profiles are created at container init, so no test assumes anything pre-exists.
Fixtures use the fictional vocabulary from `01-configuration.md` — application
`acme`, tenants `alpha…theta`, hosts under `example.com`.

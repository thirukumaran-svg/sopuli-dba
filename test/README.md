# Test environments

**tier0 and tier1 verified working 2026-08-17** — both come up, Vault mounts both
KV versions, Oracle initialises and the profiles in `oracle-init/` are created.
tier2, `nne` and `emulators` are still unrun and their image tags unverified.
Strategy and rationale: [`../docs/design/04-testing.md`](../docs/design/04-testing.md).

## Quick start

```bash
docker compose --profile tier0 up -d      # Vault + PostgreSQL, seconds
docker compose --profile tier1 up -d      # + Oracle Free, ~30-60 s to healthy
docker compose --profile tier2 up -d      # + 21c/18c/11g XE + toxiproxy, minutes
docker compose --profile nne   up -d      # Oracle requiring Native Network Encryption
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
everything else. **Nothing in this file enforces that**: no service declares a
volume, so any teardown discards the database and the next `up` re-initialises
from scratch.

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

`-v` is pointless in every form: the project declares no named volumes, so there
is nothing for it to remove. It is omitted above rather than carried as
reassurance that does nothing.

| Service | Port | Notes |
|---|---|---|
| vault | 8200 | dev mode, root token `sopuli-test-root`; `kv` (v2) and `kv1` (v1) both mounted. **Restarting it loses both** — dev mode is in-memory and `vault-init` only runs on `up`, so a `stop`/`start` leaves a healthy Vault with no mounts and every tier-1 store test failing on a 404. `docker compose --profile tier0 up -d vault-init` puts them back. **UI at <http://127.0.0.1:8200/ui>** — enabled by default in dev mode, log in with the root token. Dev mode also mounts `secret/` and `agent-registry/`, so three KV mounts exist and a test asserting on the mount list must expect them |
| postgres | 5432 | `postgres` / `sopuli-test` |
| oracle-free | 1521 | 23ai/26ai Free — CDB + PDB, rollover |
| oracle-xe21 | 1522 | 21c XE |
| oracle-xe18 | 1523 | 18c XE — no rollover, a deliberate negative case |
| oracle-xe11 | 1524 | 11g XE — non-CDB, SID `XE` not a PDB service; 30-byte passwords; amd64 only |
| oracle-nne | 1525 | NNE required; thin mode must fail with `DPY-3001` |
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
- **`hashicorp/vault:latest` was 2.x, not 1.x, as of 2026-08-17** — the version
  that first surfaced this is now pinned (`hashicorp/vault:2.0.4`) rather than
  tracked as `:latest`, because `tests/store/test_hashicorp_cas_conflict.py`
  asserts on Vault's own error wording and an upstream bump has to be a
  deliberate line change here, not a silent moving target.
- **`gvenzl/oracle-free:latest` is now 26ai** (`23.26.2.0.0`) — which is the *same
  database* as 23ai, renamed in October 2025, not a newer version. So this image is
  the 23ai line, and results from it apply to it; there is no separate 23ai to
  obtain. Cite the release number rather than the name, because next quarter's 26ai
  is a different RU. Detail in
  [`../docs/design/04-testing.md`](../docs/design/04-testing.md) §2.
- Oracle reaches `healthy` in **30–60 s**, not the 1–2 minutes assumed here — the
  image ships a pre-built database. The `start_period: 120s` is generous rather
  than necessary.

*(T1 — whether `gvenzl/oracle-xe:11-slim` exists — is settled: it does, it starts
in ~15 s, and `oracle-init/01_test_profiles.sql` runs against it. Oracle 11.2
support is cheap and stays in tier 2.)*

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
| `vault_cas_probe.py` | exploratory spike: what a real Vault CAS conflict looks like on the wire (#103, #104). Run by hand; the regression it found lives in `../tests/store/test_hashicorp_cas_conflict.py` instead |
| `vault_auth_probe.py` | exploratory spike behind [ADR-005](../docs/decisions/adr-005-vault-client.md): whether `hvac`'s auth surface was worth the dependency (#103) — it wasn't. Run by hand |

Test accounts are created and dropped per test under a per-run prefix. Only the
profiles are created at container init, so no test assumes anything pre-exists.
Fixtures use the fictional vocabulary from `01-configuration.md` — application
`acme`, tenants `alpha…theta`, hosts under `example.com`.

# ADR-005 — HashiCorp Vault client: the HTTP API directly, over `httpx`

Status: **accepted**
Related: `../design/00-principles.md` (P2), `../design/01-configuration.md`
(§3a), `../README.md` (#103), issue #104 (HashiCorp KV v2 store adapter),
issue #130 / [ADR-006](adr-006-optional-dependencies.md) (vendor clients
are install extras)

---

## Context

The lock (#96) is built against a store protocol with no backend behind it. The
first real backend is HashiCorp KV v2, per P2's priority order. Reaching it
needs either a client library or the HTTP API, and the project has no vault
dependency yet. The precedent is ADR-002 (click) and ADR-004 (the YAML parser):
a dependency under a credential path is reviewed before it is added, not after.

The candidates were `hvac`, the HTTP API directly (over `httpx` or `requests`),
or both — `httpx` for the KV data plane and `hvac` for auth.

`sopuli/store/protocol.py` is four methods, and the lock uses three of them:
read a path (data and version), write with `cas`, read a path's metadata
(`cas_required`, `max_versions`), and report capabilities. The secret side adds
versioned reads, `previous`/`pending` staging, and the auth methods
`01-configuration.md` §3a already declares — token, AppRole, Kubernetes, OIDC,
userpass.

## What did not decide it

- **Shared transport amortisation.** The argument was that `httpx` serves every
  future HTTP backend while `hvac` serves one. It does not survive the roadmap:
  OCI, AWS Secrets Manager and Azure Key Vault all require their vendor SDK
  because their protocols involve request signing, and the file and keyring
  backends do not speak HTTP at all. HashiCorp is the only member of the "plain
  HTTP plus a bearer token" class — `httpx` is shared with nothing.
- **`CasConflictError` mapping.** Retired by measurement. The probe
  (`../../test/vault_cas_probe.py`) established that the conflict signal is one
  exact string, identical across a stale `cas=0`, a stale nonzero `cas`, and
  `cas=0` against a soft-deleted path, and cleanly distinct from a
  malformed-`cas` 400. It is a string match under either client, so the mapping
  is the same few lines either way — a confirmed fact both options need, not a
  differentiator.

## Decision

**The HTTP API directly, over `httpx`.** No `hvac`. Scoped to HashiCorp Vault;
it does not bind OCI (below).

`hvac` does not cover renewal, which is what it was supposed to buy. The issue
is right that renewal is where people get this wrong, but `hvac`'s contribution
is `auth.token.renew_self()` — a wrapper over one POST. There is no lifetime
watcher, no re-auth on expiry, no non-renewable-token handling; that logic is
ours under every option, and bespoke regardless — #83 renews at each target
boundary and checks the fencing version before every mutating call, which no
general client expresses.

With renewal removed, §3a's auth surface is about five POSTs. Token is not a
call at all — it is a header, plus token-file and token-helper discovery, which
is the config layer's problem either way. Kubernetes is "read the projected
service-account token off disk, POST it"; the file read is the work. AppRole
and userpass are one POST each. OIDC is the only awkward one, and `hvac` does
not do the awkward part: the browser launch, the local callback listener, the
`state`/`nonce` handling. That is CLI-side work the Vault CLI does and the
Python client does not.

Measured against the real tier0 Vault (`../../test/vault_auth_probe.py`):
AppRole is genuinely two calls — read a `role_id`, `POST role_id`+`secret_id`
to `auth/approle/login`, no auth header, get a `client_token` straight back,
confirmed to authenticate a follow-up call. Kubernetes could only be exercised
up to the point a real cluster becomes load-bearing, but the client-side
request needed nothing beyond `{role, jwt}` — Vault accepted a
syntactically-valid fake JWT past every check that does not require one
(`kubernetes_ca_cert` does have to be a parseable PEM, or `auth/kubernetes/config`
itself is refused — the one genuine surprise) and only failed reading claims
out of it. Net: the auth argument for `hvac` is thin across every method in
§3a except OIDC's browser/callback dance, which `hvac` does not provide either.

**Release cadence, under a credential path.** `hvac` 2.4.0 is from October
2025; 2.3.0 before it from June 2024. Alive, not abandoned, but bursty enough
that "we need this fixed this week" is not something to plan around. For a
tool whose entire subject matter is credentials, patching the transport
ourselves the same day has value.

**Minor, but pointing the same way:** reading a soft-deleted version is a
library parameter under `hvac` — `raise_on_deleted_version`, whose default is
scheduled to flip in 3.0.0 — where over HTTP the envelope is simply in the
body.

## What this does not bind

**OCI keeps its SDK.** The general rule is the criterion, not the outcome:

> Write the client ourselves when the vendor protocol is HTTP plus a bearer
> credential. Take the SDK when it involves request signing, principal
> federation, or a credential exchange whose correctness we cannot inspect.

Vault is the first. OCI is emphatically the second — RSA-SHA256 signing over a
canonical header set, plus instance and resource principal federation against
the metadata service. An implementation bug there is a security bug, and
Oracle's SDK is the reference. One rule, two answers.

## Consequences

**`httpx`, not `requests`.** Not for tree size — `httpx`'s is not smaller. For
explicit default timeouts (`requests` defaults to none, and the lock is held
while we work), and because it takes a real `SSLContext`, which is what makes
`vaults.*.tls.ca_path` and `vaults.*.tls.server_name` expressible.

**`httpx` ships in `sopuli-dba[hashicorp]`.** This consequence originally read
"`httpx` is a base dependency", on the grounds that a generic transport is not a
vendor client and so #130's extras rule does not reach it. That is right about
`httpx` and wrong about the outcome: #130 landed with rule 3 stated as *nothing
in base opens a socket*, tested as "a base install can import none of the
clients the backends reach with", and `httpx` in base falsifies that exactly as
a vendor SDK would. Nothing else in base wants `httpx`, so the extra costs
nothing and keeps the property holdable by a test. The client choice above is
untouched — this is where the dependency is declared, not which dependency it
is. See [ADR-006](adr-006-optional-dependencies.md) (E2). Lands with #104, not
with this decision.

**Error mapping lives at the transport boundary** —
`sopuli/store/hashicorp/_errors.py`, one module, never at call sites and never
in `protocol.py`. Vault's `errors[]` string is preserved verbatim into
`StoreError.message` after the scrubber; the category is assigned by the
mapper. Two rules the probe made concrete:

- **Fail closed.** An unrecognised 400 is not a lost race. Misclassifying a
  real conflict costs one retry; misclassifying a hard error as a lost race
  retries into a wall.
- **Match the full phrase, not a prefix.** The `cas_required`-but-missing case
  also opens with "check-and-set parameter", and #83 asserts `cas_required:
  true` on the mount, so that 400 is reachable by design.

**`sys/health` returns non-2xx by design** — 429 standby, 473 performance
standby, 501 uninitialised, 503 sealed. A client that raises on non-2xx will
misreport a healthy cluster.

**TLS is config surface**, under `vaults.*.tls`: `ca_file`, `ca_path`,
`client_cert`/`client_key`, `server_name`, `verify`, alongside `namespace` and
`timeout_s`. `verify` falls under the P3 safety ratchet — the resolved value is
the strictest across layers, and a run with verification disabled emits a
warning diagnostic into the run document. `VAULT_SKIP_VERIFY` is read and
**refused** with a config error rather than silently ignored, so anyone who set
it learns it did nothing.

## The cost accepted

New auth methods and Enterprise header quirks arrive by reading the API docs
rather than by bumping a pin. For the KV v2 data plane this is close to zero:
the shape is frozen and versioned in the path. For auth it is small but real.

The margin is narrow enough to name the trigger for revisiting: **an auth
method whose client-side protocol is not "POST a credential."** Vault's AWS IAM
auth is the concrete case — it requires a pre-signed `sts:GetCallerIdentity`
request, at which point the criterion above flips and an SDK is the right
answer for that method.

## Follow-ups

- Pin the Vault image tag in `../../test/compose.yaml`; the probes validated
  against whatever `:latest` resolved to.
- Declare sopuli's supported Vault floor and run the probes as a matrix over
  it. They established shape-invariance within one build, not version
  stability.
- Promote `vault_cas_probe.py` to a tier-0 regression test, with fixture paths
  in the `acme` / `alpha…theta` vocabulary. (Its `CasConflictError` finding is
  already promoted, in `../../tests/store/test_hashicorp_cas_conflict.py`.)
- Add the `cas_required`-but-missing and `max_versions`-exhaustion cases.
- Drop `cap_add: [IPC_LOCK]` from the vault service in `compose.yaml`; Vault
  2.0.2 removed the capability at build time.
- `_errors.py` is specifiable now — same status codes, same strings, same
  fail-closed rule under either client — so it does not wait on #104's other
  scope.

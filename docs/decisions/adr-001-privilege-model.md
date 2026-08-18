# ADR-001 — Oracle privilege model: direct `ALTER USER`, not a definer-rights package

Status: **accepted**
Supersedes: an earlier draft that made the package the recommended model
Related: `../design/02-oracle-privileges.md`, `../../sql/oracle/00_install.sql`

---

## Context

`ALTER USER` is a system privilege with **no object scope**. There is no
`GRANT ALTER USER ON app_web_user`. Any account that can change one user's
password can change every password in that container, including `SYS`.

The tool needs to change application account passwords. So either it holds
`ALTER USER` directly, or something else holds it and exposes a narrower
interface.

## The rejected alternative

A definer-rights PL/SQL package:

- an owner schema (`NO AUTHENTICATION`, so it cannot be logged into) holding
  `ALTER USER` and the dictionary grants
- a whitelist table naming the accounts that may be touched
- a local audit table
- a package exposing only `set_password`, `expire_rollover`, `unlock_account`,
  and read helpers
- the tool's service account holding nothing but `CREATE SESSION` and `EXECUTE`

It also solved the `check --method hash` privilege problem elegantly: the package
returned only the verifier's salt, the client derived a candidate hash, and a
definer-rights function compared it inside the database — so `SYS.USER$.SPARE4`
never left the server, and the comparison could be rate-limited.

## Decision

**Direct `ALTER USER` on a dedicated service account.** Install is a handful of
grants (`sql/oracle/00_install.sql`), not a deployment.

## Why

The package constrains someone who is not actually constrained. sopuli-dba is a
tool for DBAs to do faster and more reliably what they already do by hand, and a
DBA rotating a password in `sqlplus` today has strictly more power than the tool
is being given. Requiring an in-database framework to hand them a subset of what
they already hold is friction without a corresponding gain.

The costs were concrete:

- a package to install, version and upgrade **in every PDB** — a single common
  package in the root would itself need root-wide reach, which is the blast
  radius the design was trying to avoid
- a server-side whitelist to maintain in parallel with the tool's own config
- tool-versus-package version skew as a new class of operational failure
- repeated on every PDB plug-in and clone

Against that, the direct model in a CDB is one grant set with `CONTAINER=ALL`
that new PDBs inherit automatically.

A secondary effect made the trade better than expected: once the service account
holds `ALTER USER`, granting `SELECT ON SYS.USER$` costs much less than it did
under the package model. An account that can already set any password gains
little from reading verifiers. That makes `check --method hash` — and, more
importantly, the `LCOUNT` guard that stops scheduled checks from locking
production accounts — available without the package.

## Consequences

**Accepted:** a stolen service credential is a full database compromise in that
container. Mitigations are custody of the credential and unified auditing on
`ALTER USER`, which is therefore not optional housekeeping but *the* compensating
control (`sql/oracle/01_audit_policy.sql`).

**Guardrails moved client-side.** Refusing `ORACLE_MAINTAINED` accounts,
`V$PWFILE_USERS` members and privileged-role holders now happens in the tool.
These stop being a security boundary — a compromised credential bypasses them —
and become protection against typos and over-wide config changes. The docs say so
plainly rather than overselling them.

**Correlation survived.** The package's local audit table was useful because it
joined a database row to a tool run. `DBMS_SESSION.SET_IDENTIFIER` puts the run's
correlation id into `UNIFIED_AUDIT_TRAIL.CLIENT_ID`, preserving that join with no
table.

## When to revisit

One case, and it is about the *stored* credential rather than the operator: an
unattended scheduled runner whose credential lives in CI, a container, or a
systemd unit. That has a wider exposure surface than a DBA's own login, and UC-1
scenario S2 assumes exactly it — nightly `check`, weekly `rotate`.

If unattended rotation in a low-trust environment becomes a real deployment
pattern, revisit this **for that runner's credential only**. A lighter option to
try first: a read-only account for scheduled `check`, and an `ALTER USER` account
used only by interactive `apply`/`rotate`.

**The second trigger, P7, is now closed.** The hope was that the schema privileges
introduced in the 23 codebase would cover `ALTER USER`
(`GRANT ALTER USER ON SCHEMA app_web_user TO sopuli_svc`), giving scoped direct
grants the least-privilege property the package was meant to provide at none of its
cost. Tested 2026-08-17 on 26ai 23.26.2.0.0: **`ORA-00990: missing or invalid
privilege`**, with `GRANT SELECT ANY TABLE ON SCHEMA` succeeding in the same session
to prove the feature itself works. Exactly as the reasoning predicted — schema
privileges scope privileges over objects *inside* a schema, and `ALTER USER` acts on
the account as a principal. Evidence in `../design/02-oracle-privileges.md` §2.1.

So the unattended-runner case above is the **only** remaining reason to revisit this
decision, and it is about credential custody rather than about a narrower grant
being available. No such grant exists to be had.

## Note on the implementation

The package implementation was drafted and has been deleted. It was never
executed, and two things in it were never resolved. Both apply to the direct model
equally. One is now partially closed:

- **Whether `ALTER USER` statement text leaks the password into `V$SQL` or
  `UNIFIED_AUDIT_TRAIL`** — **answered for Oracle AI Database 26ai Free
  23.26.2.0.0, in `CDB$ROOT` and a PDB, and for that version only.** No cursor for
  the DDL is retained in `V$SQL` at all, and unified audit masks the statement to
  `IDENTIFIED BY *` at write time in the base table `AUDSYS.AUD$UNIFIED` as well as
  the view. The probe also found one real leak that neither model would have
  caught by reasoning: an anonymous PL/SQL block whose own text carries the
  password as a literal is retained verbatim, because Oracle's protection is keyed
  to the `CREATE/ALTER USER` statement rather than to the password. 19c and 11.2
  are unrun, and SQL trace and the OS audit files are unchecked on every version.
  The probe is `sql/oracle/02_password_leak_probe.sql`; findings are recorded in
  `../design/02-oracle-privileges.md` §4 and the README's gate-2 table.
- **The `T:` (12C) verifier layout in `SYS.USER$.SPARE4`** — untouched, and still
  fully open. `--method hash` depends on it. Prototype it against a throwaway 19c
  before committing hash mode to the CLI.

If this decision is ever reversed, write the package fresh against the design as
it stands then, rather than recovering the draft from git history.

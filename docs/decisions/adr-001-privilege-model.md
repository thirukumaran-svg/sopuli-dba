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

**Schema privileges are not a reason to revisit it (P7).** If the schema privileges
of the 23 codebase covered `ALTER USER`
(`GRANT ALTER USER ON SCHEMA app_web_user TO sopuli_svc`), scoped direct grants
would have the least-privilege property the package was meant to provide, at none
of its cost. They do not. On 26ai 23.26.2.0.0 the grant fails with
**`ORA-00990: missing or invalid privilege`**, and `GRANT SELECT ANY TABLE ON
SCHEMA` succeeds in the same session, which shows the feature itself works. Schema
privileges scope privileges over objects *inside* a schema, and `ALTER USER` acts
on the account as a principal. Evidence in `../design/02-oracle-privileges.md` §2.1.

So the unattended-runner case above is the **only** remaining reason to revisit this
decision, and it is about credential custody rather than about a narrower grant
being available. No such grant exists to be had.

## Note on the implementation

There is no package implementation. Two questions that a package would have had
to answer apply to the direct model equally, and both are measured. The releases
each ran on are in [`../measurements.md`](../measurements.md).

- **Whether `ALTER USER` statement text leaks the password into `V$SQL` or
  `UNIFIED_AUDIT_TRAIL`.** On every release measured, `V$SQL` keeps no cursor
  for the DDL. The probe also found a leak that neither model would have caught
  by reasoning: Oracle keeps the text of an anonymous PL/SQL block verbatim, and
  if the block carries the password as a literal, the password is kept with it.
  Oracle's protection is tied to the `CREATE USER` and `ALTER USER` statements,
  not to the password. That is invariant 13. From 12.2, unified auditing masks
  the statement to `IDENTIFIED BY *` when it writes the record, in the base table
  `AUDSYS.AUD$UNIFIED` as well as the view, and the block is the only leak. 11.2
  has no unified auditing, and its `V$SQLSTATS` also keeps the plain `ALTER USER`
  text. 12.1 is not measured (unverified: ddl-text-versions). A traced session
  does not capture the password, because the trace file cuts the statement
  short. The probe is `sql/oracle/02_password_leak_probe.sql`, its extensions
  are `sql/oracle/04_password_leak_extensions.sql`, the findings are in
  `../design/02-oracle-privileges.md` §4, and what is not yet measured is in
  `../design/04-testing.md` §6 gate 2.
- **The `T:` (12C) verifier in `SYS.USER$.SPARE4`.** Its layout is known, a
  derivation on the client reproduces it byte for byte, and the rule for a
  missing verifier is settled: `--method hash` compares `T:` only, and an account
  with no `12C` verifier fails at plan time. The details are in
  `../design/02-oracle-privileges.md` §2.

If this decision is ever reversed, write the package fresh against the design as
it stands then, rather than recovering the draft from git history.

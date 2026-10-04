# Decision log

This file records why each small decision was made. A large decision has its
own ADR in this folder instead.

The [decision register](../README.md#decision-register) says whether a decision
is open. This file says why a closed one was decided the way it was. A
document's own decision table keeps the question and a one-line answer, and
links here for the reasons.

Each record is a section named by the decision's ID in the register, with five
fields in this order:

- **Decided:** the date, and the issue that holds the full discussion.
- **Question:** what had to be decided.
- **Decision:** the answer.
- **Why:** the reasons, including the cost that was accepted.
- **Rejected:** the other options, and why each one lost.

A record must make sense without its issue. The issue is extra depth, not the
only copy.

A pull request that closes an issue labelled `decision` adds its record here.
`tests/test_decision_log.py` checks the format, and that each record agrees with
the register.

## P1

- **Decided:** 2026-10-03, #615
- **Question:** Is the documented default service user one common `C##` user
  for the whole CDB, or a local user in each PDB?
- **Decision:** A common user. A local user per PDB is documented for a CDB whose
  PDBs have different owners.
- **Why:** The choice is about how far one stolen credential reaches, not about
  what the tool can do. Both are supported. Usually one DBA team owns the whole
  CDB, and then a common user means one grant set, one credential, and new PDBs
  covered automatically. Where PDBs belong to different teams or tenants,
  limiting a stolen credential to one PDB is worth the extra setup.
  `02-oracle-privileges.md` §2 has the comparison.
- **Rejected:**
  - A local user per PDB as the default: N grant sets and N credentials, and
    each new PDB needs setup, for isolation the usual estate does not need.

## P2

- **Decided:** 2026-08-18, #86
- **Question:** Does the install script grant `SELECT ON SYS.USER$` by default?
  The grant enables the `LCOUNT` lockout guard and `check --method hash`.
- **Decision:** No. It is an optional grant. The tool probes for it at run time
  and uses it where it exists. `check` defaults to `login` whether or not the
  grant is present (Q1).
- **Why:** The grant makes password verifiers readable by the service account,
  and a verifier can be attacked offline. That is a different kind of exposure
  from what `ALTER USER` already allows, so a site should choose it, not get it
  by default. Without the grant, `check` still runs, with the other lockout
  guards. Whether to recommend the grant, and whether a narrower grant would do,
  is still open (#124).
- **Rejected:**
  - Grant by default: every site would expose its verifiers to the service
    account, whether or not it uses the features that need them.

## P3

- **Decided:** 2026-08-17, #89
- **Question:** Does `--force` exist, and what does it override?
- **Decision:** Yes. It is one flag that overrides account checks 2 to 5 in
  `02-oracle-privileges.md` §4: Oracle-maintained accounts, password-file users,
  privileged roles, and the 11.2 deny list. It never overrides check 1, the
  configuration whitelist (invariant 5), and it never relaxes a safety setting.
  It is not a setting itself. It is recorded in the audit event and in the run
  document.
- **Why:** Managing the password of an Oracle-maintained account such as
  `DBSNMP` is ordinary DBA work. A tool with no override does not stop that
  change. It moves it to SQL\*Plus, where nothing records it. An audited
  override is better than an unrecorded workaround. The accepted cost: a DBA who
  wants to bypass one check bypasses four, and the audit record is there for
  that.
- **Rejected:**
  - No override: the tool gets worked around, and the workaround is not
    audited.
  - One flag per check: a growing set of flags for a rare case, and a new flag
    with every new check.

## P4

- **Decided:** 2026-10-03, #615
- **Question:** One service account per database, or one per application?
- **Decision:** One per database.
- **Why:** The configuration already limits which accounts the tool may touch,
  because it declares them per application (invariant 5). The database privilege
  is the same `ALTER USER` either way, so a service account per application would
  add accounts and credentials to install and store without narrowing what each
  one can do.
- **Rejected:**
  - One per application: more accounts and credentials, and no narrower
    privilege.

## P5

- **Decided:** 2026-08-26, #213
- **Question:** Does `doctor --check-privileges` fail or warn when the service
  account holds more privileges than it should?
- **Decision:** Warn. The run document lists them in `scope.over_granted`, the
  text output names what to `REVOKE`, and the exit code does not change.
- **Why:** Failing would block the person who ran `doctor`, perhaps during an
  incident, over a grant they did not make and cannot fix from the tool's side.
  The over-grant is somebody else's decision. A tier-1 test against a live
  Oracle checks the behaviour.
- **Rejected:**
  - Fail: it blocks the wrong person.
  - A `--fail-on-over-grant` flag: P3 already rejected flags for rare cases, and
    a flag is easy to add later and hard to remove.

## P6

- **Decided:** 2026-10-03, #615
- **Question:** Is 11.2 support worth its special cases, such as
  `DBA_AUDIT_TRAIL` and the missing `ORACLE_MAINTAINED` column?
- **Decision:** Keep 11.2 (D7). Drop it if it starts to cost real complexity.
- **Why:** 11.2 is cheap to test, because a free 11g XE image exists (T1), so
  its special cases cost little. D7 has the full reasoning, including why 11.2
  stays in scope after the `V$SQLSTATS` finding (P8).
- **Rejected:**
  - Drop 11.2 now: it removes support that costs little to keep.

## P7

- **Decided:** 2026-08-17
- **Question:** Do the schema privileges of the 23 codebase cover `ALTER USER`?
  If they did, the service account could be limited to one schema.
- **Decision:** No. The direct `ALTER USER` grant is the model on every release.
- **Why:** Measured on 26ai 23.26.2.0.0. `GRANT ALTER USER ON SCHEMA` fails with
  `ORA-00990: missing or invalid privilege`. `GRANT SELECT ANY TABLE ON SCHEMA`
  succeeds in the same session, so schema privileges work, and the refusal is
  specific to `ALTER USER`. This closes ADR-001's P7 trigger for revisiting.
- **Rejected:**
  - There was no choice between options: the scoped grant does not exist.

## P8

- **Decided:** 2026-09-09, #387
- **Question:** On 11.2, the `ALTER USER` text, with the password, stays in
  `V$SQLSTATS`. Does the tool document this, warn at run time, or refuse to
  rotate on 11.2?
- **Decision:** Document it, in `02-oracle-privileges.md` §4 and
  `../security-model.md` §5.
- **Why:** Reading the view needs a dictionary grant. The service account itself
  gets `ORA-00942`. The text stays until it ages out of the shared pool. On an
  idle test instance it survived 2,000 further distinct statements, and on a
  quiet database it can stay much longer. `ALTER SYSTEM FLUSH SHARED_POOL`
  removes it at once. Both were measured.
- **Rejected:**
  - Warn at run time: a session holding the tool's grants cannot ask whether a
    release keeps DDL text. The warning would have to branch on the version
    number, which invariant 3 forbids.
  - Refuse on 11.2: it reverses D7 over an exposure that ends when the text
    ages out and can be cleared at once. The operator would rotate in SQL\*Plus
    instead, which keeps the same text and records nothing.

## Q1

- **Decided:** 2026-08-18, #86
- **Question:** Does `creds check` default to `--method login` or
  `--method hash`?
- **Decision:** `login`, always. The default does not depend on the profile.
- **Why:** Hash mode needs the optional `SELECT ON SYS.USER$` grant (P2), so it
  cannot be the default. A login check needs no site-specific grant. A
  successful login resets the failed-login counter, and where the grant exists
  the `LCOUNT` guard stops a check before it could lock the account.
  `--method hash` exists and is opt-in.
- **Rejected:**
  - `login` interactively and `hash` under an unattended profile: it assumed
    that the grant was standard and that hash mode existed. Neither was true when
    this was decided.

## Q2

- **Decided:** 2026-08-16, #83
- **Question:** Where does the advisory lock live: in the vault, or in the
  database with `DBMS_LOCK`?
- **Decision:** In the vault. There is one lock record per secret path, written
  with check-and-set, with holder details and a TTL, under a `locks/` prefix on
  the secret's own mount. A store without check-and-set (KV v1, the file
  backend) refuses mutations unless it is configured `locking: advisory-only`.
- **Why:** The vault is the one participant every mutating command talks to.
  `DBMS_LOCK` has one advantage: a lock is released when its session dies. That
  does not help with the real risk. A stalled run's session is still alive, so
  its lock prevents nothing while its plan goes out of date. A fencing token
  prevents that: the vault version, checked again before each change. With
  fencing in place, automatic release is not worth a wider grant set. The lock
  is keyed on the path, because two accounts can share one secret. The `locks/`
  prefix keeps lock writes out of the secret's own version history, which
  `previous` and rollback use.
- **Rejected:**
  - `DBMS_LOCK`: it needs `EXECUTE ON DBMS_LOCK`, cannot cover `creds generate`
    or coordinate across targets, and puts Oracle-specific behaviour in the
    command layer.
  - Both, one per scope: two mechanisms, two ways to fail, and two places to
    look for a stuck lock.
  - Keyed per target or per account: per target means nothing when every target
    gets the same value, and per account misses two accounts that share one
    secret.

## Q3

- **Decided:** 2026-08-16, #84
- **Question:** How many generations of `previous` does the vault payload keep?
- **Decision:** Exactly one, plus whatever version history the store keeps on
  its own.
- **Why:** C14 settled it. OCI Vault has exactly one `PREVIOUS` stage, and the
  tool's fixed stage names (`current`, `pending`, `previous`) cannot address an
  older generation. One `previous` keeps the emulated payload the same shape as
  the native one, and `check --include-previous` never has to say which previous
  it accepted. Rollback goes back one generation only.
- **Rejected:**
  - A configurable list of N: an unbounded payload, emulation on every backend,
    and stage names that cannot address the older entries.
  - None, relying on the store's history: rollback would depend on the backend,
    and KV v1 and the file backend have no history.

## Q4

- **Decided:** 2026-09-03, #88
- **Question:** May the tool ever alter a database profile, for example to
  enable password rollover?
- **Decision:** Never. The tool prints the exact `ALTER PROFILE` an operator
  would run, and runs none. It may assign a profile to an account, but it never
  creates or alters one. Whether UC-4 may create or alter profiles is a question
  for UC-4, and would need a privilege outside this grant set.
- **Why:** A profile is shared. Changing one affects accounts nobody selected,
  and invariant 5 cannot limit that, because the configuration lists accounts,
  not profiles.
- **Rejected:**
  - An `--allow-profile-change` flag: a flag cannot grant a privilege at run
    time, so every service account would need `ALTER PROFILE` from install,
    whether or not anyone used the flag.
  - Alter a profile only when declared accounts are its only users: the check
    and the `ALTER` race each other. The usual profile is `DEFAULT`, which fails
    the check anyway.

## Q5

- **Decided:** 2026-10-03, #615
- **Question:** Does the tool send a notification when `check` finds drift?
- **Decision:** No. Exit code 3 and the JSON run document are the integration
  point.
- **Why:** Exit code 3 means drift, and the run document says which accounts
  drifted. Whatever runs `check` on a schedule can act on those, so the tool
  needs no notification client of its own.
- **Rejected:**
  - Built-in notification: the caller that schedules `check` can already
    alert on exit code 3 and read the run document. UC-2's `delivery.notify`
    exists for a different job, telling a person a password is ready, and
    is not a drift alert.

## Q7

- **Decided:** 2026-08-17, #85
- **Question:** One secret per account, or one secret per application with a
  field per account?
- **Decision:** One secret per application, with a field per account, is the
  documented default. One secret per account stays fully supported.
- **Why:** An application's accounts are usually rotated together. Across a
  dozen tenants and environments, one secret per account can mean 48 vault paths
  instead of 8. On a store that bills per secret that is a cost, and on any
  store it is more access policy to maintain. The lock is keyed on the path
  (Q2), and a write changes one field without touching the others, so the
  account is still the unit of work.
- **Rejected:**
  - One secret per account as the default: more paths and policies, for a
    separate lifecycle that most accounts do not have. It is still the right
    choice where an account's lifecycle really is its own.

## Q8

- **Decided:** 2026-10-03, #615
- **Question:** Can `creds apply` create an account that does not exist?
- **Decision:** No. Creating accounts is provisioning, which is UC-4.
- **Why:** UC-1 manages the passwords of accounts that already exist. Creating
  one is provisioning, and `CREATE USER` is outside the service account's grant
  set (`02-oracle-privileges.md` §3).
- **Rejected:**
  - Create on `apply`: it mixes provisioning into password sync, and needs a
    wider grant set.

## Q9

- **Decided:** 2026-08-18, #87
- **Question:** Which clock decides a password's age for
  `rotate --max-age-days`: the vault's `rotated_at`, or the database's password
  change time?
- **Decision:** The vault's `rotated_at`, always. `creds status` shows the
  database's own time beside it, as a sign of drift.
- **Why:** The vault has one age per secret path, however many targets share
  it. With the database as the clock, an account on several targets has several
  ages, and the CLI would need a rule for which one counts: oldest, newest or
  any. The database time also changes when anyone else runs `ALTER USER`, and a
  target the tool cannot reach would have no age at all.
- **Rejected:**
  - The database as the clock: the problems above.
  - The vault for selection, with a warning when the database age differs: it
    needs a warning code, and how codes are allocated is still open (J3).

## H1

- **Decided:** 2026-09-16, #449
- **Question:** Where is a personal account declared, so that invariant 5 (the
  configuration is the whitelist) still covers it?
- **Decision:** In a top-level `personal_accounts:` section. An entry names
  accounts, or gives a predicate over a profile or a role, which is resolved
  against the database at run time.
  - A listing verb, `account list`, shows what a predicate matched.
  - A mutating verb also needs the account named on the command line. It refuses
    a name the predicate does not admit, so one run touches exactly one account.
  - A name may not be declared both here and in an application binding.
  - A predicate that names a profile or role that does not exist is refused. A
    predicate that matches no accounts is not an error.
- **Why:** An application binding means "these accounts are mastered by these
  secrets". A personal account has no secret, no desired state for `check`, and
  no fan-out, so it fits none of the things a binding exists for. Listing four
  hundred developers by name is copying, not review, so a predicate is allowed.
  The accepted cost: whoever can grant the role or assign the profile can bring
  an account into scope, without a change to the reviewed file. The checks in
  `02-oracle-privileges.md` §4 still refuse the most privileged accounts, and a
  run touches only the one account the operator typed.
- **Rejected:**
  - An application entry marked personal: a binding that serves none of a
    binding's purposes, and every validator would need a branch for it.
  - A `personal: true` flag on an account in `accounts:`: the same problem, and
    one `secret_template` could then mix synced and handed-over accounts.

## H2

- **Decided:** 2026-09-17, #450
- **Question:** UC-2 has no vault as master. What does a reset record, and
  where?
- **Decision:** Three facts, three places.
  - When the password changed: the database. `DBA_USERS.PASSWORD_CHANGE_DATE`,
    or `SYS.USER$.PTIME` where that grant exists. The `PTIME` fallback is
    unmeasured on 12.1 (unverified: pw-changed-source).
  - Who reset it, which path was used, and where it was delivered: a metadata
    record in a store, written when a store is configured. It never holds the
    password. The advisory lock keys on its path.
  - What to roll back to: nothing. Rollback is not a UC-2 operation. A lost
    password gets another reset.

  A reset with no store configured warns at plan time and runs.
- **Why:** Reading a fact from the database is safe here, because nothing is
  mastered, so invariant 6 does not apply. The record's own timestamp is not
  used for age. On the seen path the person must change the password at first
  logon, so the record's time goes stale by design. This is a deliberate
  difference from Q9. The record also gives two concurrent resets of one account
  a lock to collide on.
- **Rejected:**
  - Only the run's own output: no memory for `status` or for age, and nothing to
    lock on.
  - A store as a requirement: UC-2 exists for estates without a vault as master,
    so the record is optional.

## H3

- **Decided:** 2026-09-16, #451
- **Question:** What noun and verbs does UC-2 use? The grammar is noun-verb
  (D2).
- **Decision:** The noun is `account`. The verbs are `account reset-password`,
  `account expire-password` (a verb of its own, not a flag), `account suspend`
  and `account list`.
- **Why:** `account` is the configuration's own word for what is managed,
  whichever key declares it. `suspend` is used instead of `lock`, so that `lock`
  keeps its one meaning, the advisory lock. `account list` is needed because a
  predicate (H1) has to be resolved and shown somewhere, and `creds status` would
  show empty vault columns for accounts nothing masters.
- **Rejected:**
  - `creds`: every `creds` verb means the vault is master. One noun for both
    sync and handover makes `--help` and the run document's verb ambiguous.
  - `user`: the natural noun for UC-4's account provisioning. Taking it now
    forces UC-4 to share it or to pick a worse one.
  - `password` or `handover`: `password` reads as a synonym for `creds`, and
    `handover` is unfamiliar to a DBA.

## H4

- **Decided:** 2026-09-16, #455
- **Question:** Does a reset verify the new password, unlock the account, or end
  an open rollover window?
- **Decision:**
  - Verify: never. The reset reports `ACCOUNT_STATUS` afterwards instead.
  - Unlock: a `LOCKED(TIMED)` account is unlocked by default. A plain `LOCKED`
    account is refused at plan time. An account with no lock gets no
    `ACCOUNT UNLOCK`.
  - Rollover window: ended by default with `EXPIRE PASSWORD ROLLOVER PERIOD`. A
    flag keeps it open.
- **Why:** Each part was measured on 26ai 23.26.2.0.0 with
  `sql/oracle/07_lock_and_rollover_probe.sql`.
  - Verifying means the tool logs in with the password, or reads the verifier
    through an optional grant. Either one uses the password outside the store,
    which the unseen path exists to avoid. On the seen path, a login would also
    use up the expiry that forces the person to choose a new password.
  - `IDENTIFIED BY` does not clear a lock. A login with the new password fails
    with `ORA-28000`, so a reset that does not unlock leaves the person locked
    out. `LOCKED(TIMED)` is a lock nobody chose. A plain `LOCKED` on a personal
    account usually means somebody disabled it on purpose, for example when the
    person left, so a reset must not clear it silently.
  - `ACCOUNT UNLOCK` on an account that is not locked resets
    `SYS.USER$.LCOUNT`, so it is issued only where a lock exists.
  - After a reset, the only holder of the old password is the person, who has
    lost it. Keeping the window open helps nobody. UC-1 §6.3 is different,
    because there the holders are applications. Ending a window on an account
    that has none is accepted and changes nothing.
- **Rejected:**
  - Verify by hash: needs the optional grant, and still uses the password
    outside the store.
  - Never unlock: the most common request would need a second command.
  - Unlock any lock: would re-enable an account somebody disabled on purpose.
  - One combined `IDENTIFIED BY … ACCOUNT UNLOCK` statement: it works, but no
    leak probe has been run against that statement shape, and it reports two
    changes as one result.
  - Never end the window: the old password would keep working after a reset.

## H5

- **Decided:** 2026-09-15, #452
- **Question:** Is self-service part of UC-2?
- **Decision:** Not in the sense of a person resetting their own password
  through sopuli. In UC-2, self-service means the person fetches a password the
  DBA set, from a place only they can read, such as a Vault response-wrapping
  token.
- **Why:** The question assumed the person would reset through the tool. That
  would use the service account's `ALTER USER` for someone who does not hold it,
  which ADR-001's argument does not cover, and the tool has no way to
  authenticate a person. It is also not needed. A person who knows their
  password changes it without the tool: before expiry with
  `ALTER USER … IDENTIFIED BY new REPLACE old`, and after expiry through
  Oracle's change flow at logon. A DBA reset is needed only when the person no
  longer knows the password, and then the person fetches the new one.
- **Rejected:**
  - The person runs the tool as themselves with `REPLACE old`: it needs the old
    password, which is exactly what a person who needs a reset does not have.
  - An identity provider in front of the tool: needs a server component and an
    identity mapping, and would reopen ADR-001.

## H6

- **Decided:** 2026-09-18, #453
- **Question:** How does an estate restrict delivery methods, so that a
  higher-precedence layer cannot add a method back?
- **Decision:** `safety.delivery.allowed_methods`, merged across layers by
  intersection. Each layer can only narrow the set.
  - Unset means no constraint.
  - Two layers whose lists share no method are refused at plan time, naming both
    layers.
  - There is no `forbidden_methods` key.
- **Why:** An intersection fails closed: a delivery method added in a later
  release cannot be used until an estate names it. A forbidden list fails open:
  a new method would be allowed everywhere on upgrade. The cost is a fourth merge
  shape in the settings registry. It is declared per setting, as `safe_bool` is,
  because both options are lists of strings and the type cannot say which merge
  applies.
- **Rejected:**
  - `forbidden_methods`, merged by union: no new code, but it fails open.
  - Both keys: two ways to write one guard, and an evaluation order to document.

## H7

- **Decided:** 2026-09-20, #454
- **Question:** Running a reset twice gives two different passwords. Is the
  reset a second exception to invariant 9 (idempotency), or should it be made
  convergent?
- **Decision:** Neither. Invariant 9 is restated as a scope rule. It applies to
  convergent commands, and a verb that draws a fresh random password has no
  state to converge on, so it is outside the invariant. The reset reports
  `changed: true` on every run, and says that the password delivered before no
  longer works.
- **Why:** One scope rule covers `creds generate`, this reset and UC-4's account
  creation by the same test, so no later verb needs its own argument. The test
  is not open to an implementer: anything with an observable target state must
  report `changed: false`. The accepted cost is that an unattended retry
  delivers twice, and the warning is what tells people.
- **Rejected:**
  - A second listed exception: a list grows one entry at a time, and each new
    verb repeats the argument.
  - Convergent on a request id: needs a record that an estate need not
    configure, and that record is missing in exactly the partly failed runs that
    get retried.
  - Convergent on account state ("already expired since the last reset"): the
    same problem, and the unseen path issues no `PASSWORD EXPIRE`, so there is
    no state to read.

## H8

- **Decided:** 2026-10-01, #459
- **Question:** On the unseen path, what happens to the stored copy of the
  password after the person has it? And how is it shown that the DBA cannot
  read it?
- **Decision:** It depends on the delivery method.
  - `vault_wrapped`: nothing persists. The tool calls only
    `sys/wrapping/wrap`, and the person's unwrap is the last read.
  - `vault_path`: before writing, the tool must ask Vault for the DBA token's
    capabilities on the person's path. If they include `read` or `root`, the
    reset is refused at plan time.

  `vault_path` is not built yet. How long its stored copy lives is decided
  together with the method itself (open: #447).
- **Why:** "The DBA cannot read it" has to be checked, not assumed. A DBA token
  that can read the path lets the DBA learn the password, and then act as the
  person while the database audit trail shows only the person's name. A root
  token reports only `root`, so it is checked by name. For `vault_wrapped`, the
  single read was measured against the Vault test container: a second unwrap
  fails, and an expired token no longer unwraps.
- **Rejected:**
  - Document the requirement only: a wrong Vault policy would silently make an
    unseen reset readable by the DBA, with no expiry to limit it.
  - Fall back to the seen path when the token can read: the operator asked for
    one guarantee and would silently get a different one.

## H9

- **Decided:** 2026-10-01, #496
- **Question:** On `vault_wrapped`, the wrapping token comes back to the DBA's
  terminal, and whoever holds it can unwrap it. What does "unseen" guarantee,
  then? Should the tool carry the token to the person by some other channel?
- **Decision:** The guarantee is about attribution, not access. Where the
  database audits `ALTER USER` and logons, the DBA cannot act as the person
  without leaving their own name in a record the DBA does not control: the
  database audit trail, or Vault's audit device. An unwrap the person did not
  make is detectable, and attributable where Vault has an audit device. There is
  no second channel.
- **Why:** A DBA who can reset a password can always get into the account: by
  resetting it, or by granting themselves `CONNECT THROUGH` with the same
  `ALTER USER` privilege. The proxy route was measured on 26ai 23.26.2.0.0 with
  `sql/oracle/11_proxy_connect_probe.sql`. Both routes leave the DBA's name
  behind where auditing is on. The one route that must stay closed is learning
  the person's real password, because then only the person's name is recorded.
  The reset record does not count as an audit trail, because the DBA's own run
  writes it. The guarantee ends where Vault has no audit device, or where the
  token output was redirected. Whether a reset checks the database's audit
  settings is H10, which is still open.
- **Rejected:**
  - `vault_path` as the default method: it needs human-identity auth and a Vault
    policy that sopuli does not create, so the default would not work on a stock
    Vault, and estates would fall back to the seen path.
  - A `notify:` channel declared trusted: the trust level would be an assertion
    in the configuration, not something the tool can check.

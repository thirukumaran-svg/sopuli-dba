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

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

## D1

- **Decided:** 2026-08-08
- **Question:** What is the binary called?
- **Decision:** `sopuli`. The project and its package are `sopuli-dba`.
- **Why:** The maintainer chose it as a sensible way for the tool to work.
  There was no particular reason beyond that.
- **Rejected:** No alternatives were weighed.

## D2

- **Decided:** 2026-08-08
- **Question:** What grammar does the CLI use?
- **Decision:** Noun-verb, for example `sopuli creds rotate` and
  `sopuli target list`.
- **Why:** The maintainer chose it as a sensible way for the tool to work.
  There was no particular reason beyond that.
- **Rejected:** No alternatives were weighed.

## D3

- **Decided:** 2026-08-08
- **Question:** What language is the tool written in?
- **Decision:** Python, with `python-oracledb` in thick mode, on every target.
- **Why:** Thin mode cannot be used, for three independent reasons. It does not
  support Native Network Encryption, which Base Database Service and any
  database that requires NNE refuse to do without (measured on 19.32.0.0.0,
  #575). It connects only to 12.1 and later, and 11.2 is supported. And
  `auth: external` needs the Oracle client libraries. So Instant Client must be
  installed at run time anyway. Python is also easier to review for a DBA who
  is not mainly a developer, which matters for code that handles credentials.
  `00-principles.md` P4, *Why thick mode*, has the detail.
- **Rejected:**
  - Go: its advantage is a single binary with no runtime dependencies, and
    Instant Client removes that advantage.

## D4

- **Decided:** 2026-08-08
- **Question:** What format is the configuration file?
- **Decision:** YAML. JSON is also accepted, because JSON is valid YAML.
- **Why:** The maintainer chose it as a sensible way for the tool to work.
  There was no particular reason beyond that. JSON is accepted because a YAML
  parser reads it anyway.
- **Rejected:** No alternatives were weighed.

## D5

- **Decided:** 2026-08-08
- **Question:** Is macOS a supported platform?
- **Decision:** Best effort. The code stays portable, the README claims no
  support, and there is no macOS CI.
- **Why:** Instant Client exists for macOS, including Apple Silicon, so the
  tool can run there. The problem is testing. There is no Oracle server build
  for macOS, so a Mac cannot host the full test stack locally and needs a remote
  database (`SOPULI_TEST_ORACLE_DSN`). The 11.2 test image is `linux/amd64`
  only, and Apple Silicon has only a 23.x client, which cannot reach 11.2. Excluding macOS would save nothing,
  because the code has almost nothing macOS-specific. `00-principles.md` P4 has
  the detail.
- **Rejected:**
  - A supported tier: a Mac cannot run the test stack locally, there would be
    no macOS CI behind the claim, and there is no evidence of demand.
  - Excluding macOS: saves nothing, and would have to be undone when someone
    asks.

## D6

- **Decided:** 2026-08-08
- **Question:** How are drivers and stores added: in the tree, or through a
  plugin API?
- **Decision:** In the tree. An entry-point plugin API comes only after a second
  database driver exists.
- **Why:** The decision ties the plugin API to a second driver, so the API is
  designed against two implementations rather than one. Install extras (D9)
  control which dependencies are installed, not which modules exist, so they do
  not change this.
- **Rejected:**
  - A plugin API now: it would be designed against a single driver.

## D7

- **Decided:** 2026-08-08
- **Question:** What is the oldest Oracle release the tool supports?
- **Decision:** 11.2. It was confirmed again on 2026-09-09 (#387), after the
  `V$SQLSTATS` finding.
- **Why:** 11.2 is cheap to test: `gvenzl/oracle-xe:11.2.0.2-slim` pulls freely
  and starts in seconds (T1). On 11.2 the `ALTER USER` text stays in
  `V$SQLSTATS`. Every later release measured keeps nothing: 12.2.0.1.0,
  18.4.0.0.0, 19.3.0.0.0, 19.32.0.0.0, 21.3.0.0.0 and 26ai 23.26.2.0.0. 12.1 is
  unmeasured, and one measured release update is not every release update. 11.2 stayed in scope anyway,
  because the text ages out of the shared pool and one `FLUSH SHARED_POOL`
  clears it, and dropping 11.2 would move the rotation to SQL\*Plus, which keeps
  the same text and records nothing (P8). Apple Silicon cannot reach 11.2,
  because only the 23.x client exists there.
- **Rejected:**
  - Drop 11.2: the rotations would still happen, outside the tool.

## D8

- **Decided:** 2026-08-09
- **Question:** Which CLI framework does the tool use?
- **Decision:** click.
- **Why:** `click.testing.CliRunner` runs CLI tests in-process with no I/O, and
  click has a real exception hierarchy to map errors onto. The noun-verb grammar
  (D2) and exit code 2 on a usage error are equally easy in either candidate.
  ADR-002 has the detail.
- **Rejected:**
  - `argparse`: more verbose, and harder to test in-process.
  - `typer`: click with an implicit layer on top, which loses the explicitness
    that a reviewer who is a DBA first needs.

## D9

- **Decided:** 2026-08-18, #130
- **Question:** Which dependencies does the base install carry?
- **Decision:** Only the CLI framework, the YAML parser, `pywin32` on Windows,
  and sopuli itself. Vendor clients, for stores and database drivers, are
  install extras. The base install opens no sockets. ADR-006 holds the full
  decision, and E1 to E7 are its parts.
- **Why:** The dependency tree of a credential tool is something a security
  review reads. "Only the vendors you use" is a better answer than "all of them".
  Vendor SDKs also pin versions that can collide, and a site should not inherit
  the pins of a backend it never configured. Extras are a published interface,
  so this had to be decided before the first release.
- **Rejected:** See ADR-006.

## D10

- **Decided:** 2026-09-05, #294
- **Question:** Which confirmation prompts are built in, with no configuration?
- **Decision:** None. `safety.confirm_environments` is the only trigger, and an
  estate lists its production environments there.
- **Why:** P5 asked for three triggers, and `01-configuration.md` §9 forbids two
  of them. A built-in `[prod]` would be a floor that no layer could remove,
  because the list merges by union. That is the trap §9 uses `confirm` to
  illustrate. A prompt whenever more than one target is touched would prompt on
  every multi-target change for an estate that configured nothing, and it would
  read `max_targets` as a threshold when it is a ceiling. §9 governs, and P5 is
  reworded to match.
- **Rejected:**
  - `environment: prod` as a separate built-in trigger: the same unremovable
    floor, outside the ratchet instead of inside it.
  - All three triggers as P5 first stated them: a default install would prompt
    on any multi-target change.

## C1

- **Decided:** 2026-08-08
- **Question:** What is the section that binds accounts to secrets called?
- **Decision:** `applications`. A file whose one application applies to all
  its targets can instead put the binding keys at the top level. This inline
  form is the default shape. An application that covers only some targets needs
  `applications:`, for example in an estate that also has a CDB root for
  maintenance.
- **Why:** The common case is one application over every target, so the default
  shape is the simplest one: a file that reads like a list of targets.
  `01-configuration.md` §1 describes both forms. No reason was recorded for the
  name itself.
- **Rejected:** No alternatives were weighed.

## C2

- **Decided:** 2026-10-03, #615
- **Question:** What syntax selects targets?
- **Decision:** `--select k=v` over labels on the command line, and `match:` in
  a group. Revisit only if a real case needs negation or set membership.
- **Why:** It is what the build does, and no real case has needed negation or
  set membership.
- **Rejected:**
  - A richer expression language now: negation and set membership have no real
    case yet.

## C3

- **Decided:** 2026-10-03, #615
- **Question:** Can a secret template contain arbitrary expressions?
- **Decision:** No. A template uses a fixed list of tokens, plus labels.
- **Why:** The template is the account-to-secret mapping, which is the
  safety-critical part of the configuration. With a fixed token list, a reviewer
  can see exactly which path each account maps to.
- **Rejected:**
  - Arbitrary expressions: a reviewer would have to evaluate code to know where
    a password goes.

## C5

- **Decided:** 2026-10-03, #615
- **Question:** Does the tool encrypt the configuration file at rest?
- **Decision:** No. It is out of scope.
- **Why:** The configuration holds no secrets, by construction. Secrets are
  references to a store, and auth material is a reference to an environment
  variable or a file. There is nothing in the file to protect with encryption.
- **Rejected:**
  - Encryption at rest: there is nothing secret in the file to protect.

## C7

- **Decided:** 2026-08-10
- **Question:** Can `target_sets` nest more than two levels?
- **Decision:** No. Write a second target set instead.
- **Why:** A general templating language in a credential tool is hard to debug.
  Two levels cover an environment with a list of tenants. A deeper or mixed
  shape is refused rather than quietly flattened. `01-configuration.md` §4,
  rules 2, 6 and 7, say what is refused.
- **Rejected:**
  - Deeper nesting: more power than the estates need, and harder to read and
    debug.

## C8

- **Decided:** 2026-08-10
- **Question:** Can explicit `targets:` carry labels, or only `environment`?
- **Decision:** Labels are allowed on explicit targets.
- **Why:** Generated targets get labels from their dimensions. If explicit
  targets could not carry labels too, an estate with both kinds could not be
  selected the same way.
- **Rejected:**
  - `environment` only: a mixed estate could not be selected uniformly.

## C9

- **Decided:** 2026-08-12, #27
- **Question:** How does the configuration point at vault auth material, and at
  the database admin credential?
- **Decision:** One grammar with two vocabularies: `{ method: ..., ... }`, with
  a scalar shorthand where a method needs nothing else.
  - A vault's auth material is a MaterialRef, with one key, `env` or `file`.
    Identity fields stay inline. `method: token`'s chain of sources stops inside
    the method. A token helper is deferred.
  - The admin credential uses P2's four sources. `method: vault` names a whole
    SecretRef, `method: env` names its own variable, and `external` limits the
    `dsn` to a TNS alias and refuses a `username`.
  - `oracle.scope` and `container` on a target are assertions, checked on
    connect.
- **Why:** With a MaterialRef, the file can only point at a secret, never hold
  one. So P2's no-plaintext rule is enforced by the grammar, not by care. One
  grammar for both places means one thing to learn and validate.
  `01-configuration.md` §3a has the detail.
- **Rejected:**
  - An `_env` / `_file` suffix on each key: the rule against plaintext would
    then be a validation someone must remember to write, not a missing slot.
  - Allowing `role_id` inline because it is an identifier: one exception would
    have to be argued again for every method added later.
  - A separate field for the admin credential's vault path: `method: vault`
    reuses the SecretRef type instead.
  - A token helper (`command:`): running a command from a credential tool
    needs its own decision, so it is deferred.

## C10

- **Decided:** 2026-08-10
- **Question:** What are profiles for?
- **Decision:** Run context, not target selection. A profile changes how the
  tool behaves (prompts, verification method, output, logging), never which
  targets or accounts are in scope. A profile may contain only a fixed list of
  keys.
- **Why:** The same configuration runs from a laptop, a CI job and a scheduler,
  and those need different behaviour. Without profiles, that lives in
  environment variables scattered across workflow files, where nobody reviews
  it. A profile that could change the scope would be a selector that does not
  look like one, which is dangerous in a tool that rotates credentials.
  An earlier draft had `policies.*.verify.scheduled_method`, run context hidden
  in a password policy, and a profile overriding `verify.method` replaced it.
- **Rejected:**
  - Profiles that also select targets: a selector in disguise.

## C11

- **Decided:** 2026-10-03, #615
- **Question:** Can several profiles be active at once?
- **Decision:** No. One active profile, and no inheritance between profiles.
  Revisit only if a real configuration repeats itself across three or more
  profiles.
- **Why:** Composition would be worth its precedence rules only if
  configurations repeated themselves across profiles, and no real configuration
  has shown that.
- **Rejected:**
  - Composable profiles: precedence rules between profiles, for a need not yet
    seen.

## C12

- **Decided:** 2026-10-03, #615
- **Question:** Does the tool ship a built-in `interactive` profile as the
  implicit default?
- **Decision:** No. No profile means "just `defaults`".
- **Why:** An invisible built-in profile would be one more thing to explain when
  output surprises someone.
- **Rejected:**
  - A built-in `interactive` profile: hidden behaviour.

## C13

- **Decided:** 2026-08-18, #31
- **Question:** Is `vault:` under `defaults:` and in a profile a store name, or a
  block of settings?
- **Decision:** A name, everywhere. To change a store's settings, `defaults:`
  and a profile may carry partial `vaults:` entries for a store declared at the
  top level. They may change how the store is reached (such as `addr`, `mount`
  and `auth`), but not `type`, `non_production` or `locking`. Invariant 10 keeps
  the last two out of the run context.
- **Why:** The environment variables had already chosen this shape:
  `SOPULI_VAULT` names a store, and `SOPULI_VAULT__VAULT_DEV__ADDR` sets one of
  its settings. Settings that follow a store's name cannot leak to another
  store. `01-configuration.md` §3a and §5 have the detail, and `config show
  --explain` reports which layer set each key.
- **Rejected:**
  - A `vault_settings:` block that applies to whichever store is active:
    shorter, but auth written for dev would follow a changed `vault:` into prod.

## C14

- **Decided:** 2026-08-16, #40
- **Question:** What values can `@version=` and `@stage=` take in a SecretRef,
  and who defines them?
- **Decision:** The tool defines both. `stage` is one of `current`, `pending`
  and `previous`, matched in any case and stored in lower case. `version` is a
  whole number from 1. Neither may hold a `{token}`.
- **Why:** OCI Vault's rotation states are a fixed set (`CURRENT`, `PENDING`,
  `LATEST`, `PREVIOUS`, `DEPRECATED`), not labels a user defines, and its
  versions are integers. So there was no backend vocabulary to pass through,
  and passing values through would only move a typo from load time to rotation
  time. This also settled Q3 at one `previous`.
- **Rejected:**
  - Pass the value through to the backend: a typo would fail during a rotation
    instead of when the file is loaded.

## C15

- **Decided:** 2026-08-18, #118
- **Question:** A binding names a secret, and no store is named anywhere. Does
  the tool refuse, warn, or leave it to plan time?
- **Decision:** Mostly plan time. `config show --resolved` shows the store as
  `-`, and the command that needs a store fails at plan time, once the run's
  profile is known. The file is refused at load only when `vaults:` declares no
  store at all, so nothing could ever fill the gap.
- **Why:** A missing store is not always a mistake. A profile's `vault:` or
  `SOPULI_VAULT` may supply one, and neither is known while the bindings are
  built. Plan time is when the answer is exact.
- **Rejected:**
  - Refuse at load whenever a binding's store is unnamed: it rejects a valid
    file that declares stores and names no `defaults.vault`, where the run's
    profile or `SOPULI_VAULT` supplies the store's name.

## C16

- **Decided:** 2026-08-19, #145
- **Question:** What does `--vault-token` take?
- **Decision:** Nothing. A bare `--vault-token` is refused with a message that
  names invariant 1 and the working sources. `--vault-token-file PATH` is the
  command line's place in `method: token`'s chain. ADR-007 holds the full
  decision.
- **Why:** A token as an option value is visible in `ps` and in the Windows
  process list (invariant 1). A vault ref cannot help, because a ref is resolved
  by a store that is already authenticated.
- **Rejected:**
  - `--vault-token env:NAME` or `file:PATH`, borrowing MaterialRef's keys: on a
    command line, `env:NAME` has the shape of a SecretRef (`[<vault>:]<path>`),
    which would address path `NAME` in a store called `env`. One string would
    read as one type and be the other, which blurs the line
    `01-configuration.md` §3a draws between MaterialRef and SecretRef.
  - `--vault-token-stdin`: deferred rather than rejected, because
    `--from-stdin` already uses the pipe.

## C17

- **Decided:** 2026-09-05, #294
- **Question:** P5 asked for a confirmation prompt by default for a `prod`
  target or a large blast radius. `01-configuration.md` §9 forbids a built-in
  that takes part in a ratchet. Which one holds?
- **Decision:** §9 holds, and P5 is reworded. This is the same decision as D10,
  seen from the configuration side.
- **Why:** See D10. `creds rotate` and `lock break` confirm every time, and were
  never part of this question.
- **Rejected:** See D10.

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

## J1

- **Decided:** 2026-10-03, #615
- **Question:** Does `--output json` print nothing until the run ends, even for
  a long run?
- **Decision:** Yes. `--output jsonl` streams events for the case that needs
  them.
- **Why:** A partial JSON document is worse than none: a consumer cannot parse
  it, and cannot tell how much of the run it describes.
- **Rejected:**
  - Stream the document as the run goes: it leaves invalid JSON when a run
    stops early.

## J2

- **Decided:** 2026-10-03, #615
- **Question:** Is `plan` in every run document, or only with `--dry-run` or
  `--verbose`?
- **Decision:** In every command that plans. A command with no units, such as
  `doctor`, has none.
- **Why:** The plan is small, and having it in every document makes comparing
  the plan with the result a mechanical job.
- **Rejected:**
  - Only with `--dry-run` or `--verbose`: a consumer could not compare plan and
    result for an ordinary run.

## J4

- **Decided:** 2026-10-03, #615
- **Question:** Does the run document carry a host name and a process id for
  log correlation?
- **Decision:** The host, as `invocation.actor.host`. No process id.
- **Why:** `correlation_id` already ties a run to the audit and vault trails. A
  process id means nothing once the process has exited.
- **Rejected:**
  - A process id: it adds nothing that `correlation_id` does not give.

## J6

- **Decided:** 2026-10-03, #615
- **Question:** Can the event stream resume after a crash?
- **Decision:** No. Run the command again.
- **Why:** `check` finds the true state cheaply, so a rerun recovers without a
  resume protocol.
- **Rejected:**
  - A resumable stream: a protocol to design and test, for a case a rerun
    already covers.

## J7

- **Decided:** 2026-08-13, #8
- **Question:** Does `--output json` emit a run document on a usage error?
- **Decision:** No. A run document describes a run, and a run begins when the
  invocation resolves. Exit code 2 is the only exit code that never produces a
  document, and stdout is empty on exit 2. An invalid configuration file moved
  to its own exit code, 9, and does produce a document.
- **Why:** The schema requires `command` and `invocation`. A command line that
  did not parse has neither, so a document for it would either break the schema
  or force every consumer to handle a document that describes nothing. An
  invalid configuration is different: the command line was valid, and
  `config validate --output json` must report it. So the two needed different
  exit codes.
- **Rejected:**
  - A document on a usage error too: it weakens the schema for every consumer.
  - Keep exit 2 for both usage and configuration errors: then "empty stdout and
    exit 2" no longer means one thing.
  - Move configuration errors to exit 1: loses the most useful distinction the
    tool has, because a broken configuration is something an operator can fix.

## T1

- **Decided:** 2026-08-08, #1
- **Question:** Is there a freely pullable Oracle 11g XE image for the test
  stack?
- **Decision:** Yes. `gvenzl/oracle-xe:11.2.0.2-slim` pulls, starts in about 15
  seconds, and accepts the test profiles. 11.2 is a tier-2 compose service.
- **Why:** This was a measurement. It made D7 cheap to keep. The image is
  `linux/amd64` only, which is a second reason Apple Silicon cannot test 11.2
  locally.
- **Rejected:** Not a choice between options.

## T2

- **Decided:** 2026-08-20, #174
- **Question:** Does the test harness start containers with
  `testcontainers-python`, or use `test/compose.yaml` and fixtures?
- **Decision:** Compose. The harness reads a DSN and probes whatever answers. It
  starts and stops nothing. `SOPULI_TEST_ORACLE_DSN` points it elsewhere.
- **Why:** The users are DBAs, who will want to run the stack by hand and look
  at it. A harness that managed containers would be a second definition of the
  stack beside `test/compose.yaml`.
- **Rejected:**
  - `testcontainers-python`: a second definition of the stack, which the tests
    and the by-hand stack could disagree on.

## T5

- **Decided:** 2026-08-09
- **Question:** Which public CI provider does the project use?
- **Decision:** GitHub Actions.
- **Why:** The repository and release-please were already on GitHub, so a second
  provider would have added nothing. Oracle Free containers run on its amd64
  hosted runners.
- **Rejected:** No other provider was evaluated.

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

# sopuli-dba — JSON output contract

This document specifies what the tool writes for programs to read: the run
document (`--output json`), the event stream (`--output jsonl`), and the rules
for text output that keep it consistent with both.
`sopuli/output/` produces them, and CI validates the output against the
published schemas.

Schemas: [`../schemas/sopuli-run-1.31.schema.json`](../schemas/sopuli-run-1.31.schema.json),
[`../schemas/sopuli-event-1.7.schema.json`](../schemas/sopuli-event-1.7.schema.json)
Example: [`../schemas/example-creds-check-drift.json`](../schemas/example-creds-check-drift.json)

---

## 1. Why this is a contract and not just output

Every program that uses this tool reads JSON: the scheduler that alerts on
drift, the CI job that gates a release, a dashboard. Text output is for people
and may change freely. JSON output may not. It is a versioned interface
(invariant 12), and §8 says what may change in a minor version.

These are the three output modes:

| Mode | Shape | Use |
|---|---|---|
| `--output text` (default) | tables, colour when a TTY | people |
| `--output json` | one document on stdout when the run completes | scripts, `jq`, CI |
| `--output jsonl` | one event object per line, streamed as work happens | long runs, live dashboards, log shipping |

`jsonl` and `json` describe the same run. The last event, `run.finished`,
carries the same `summary` and `exit_code` as the `json` document, so a consumer
can use either without a second code path. **Only a verb that streams offers
`jsonl`**. These verbs stream:

- `creds check`
- `creds apply`
- `creds rotate`
- `creds generate`
- `account reset-password`

Every other verb refuses `jsonl` as a usage error. §5 says what is emitted and
why the others refuse.

### Encoding, on every mode

**All three standard streams are UTF-8.** The tool sets this at startup,
whatever the platform's locale and whatever `PYTHONIOENCODING` says.
`00-principles.md` P4 has the reason: redirected stdout on Windows is cp1252,
and there a status glyph crashes the command.

JSON output does not depend on this. `json.dumps` escapes non-ASCII by default,
so the document is ASCII on the wire. The rule is for `--output text`, and for
error and diagnostic messages that carry a server's own wording.

### Colour

Colour is a property of a run. It is resolved once, and every call site asks
`Emitter.use_color()` for the answer. These rules apply in order, and the first
that matches decides:

| # | Rule | Result |
|---|---|---|
| 1 | `--output json` or `jsonl` | never coloured, whatever else says |
| 2 | `--color never` | off |
| 3 | `--color always` | on |
| 4 | `SOPULI_NO_COLOR` or `NO_COLOR` set and not empty | off |
| 5 | `TERM=dumb` | off |
| 6 | stdout is not a TTY | off |
| 7 | Windows console where VT mode cannot be enabled | off (P4's plain fallback) |
| 8 | otherwise | on |

These parts of the table are decisions:

- **An explicit flag beats the environment** (rules 2 and 3 come before 4). In
  P3 the command line outranks the environment. It is also why `--color always`
  exists: a CI job whose log viewer shows ANSI colour has no TTY, so
  autodetection would remove the colour that was wanted. This does not break
  invariant 10. That ratchet is for safety settings, and red text is not less
  safe.
- **`--output json` always wins** (rule 1 comes before 3). The document is a
  versioned contract (invariant 12), and a consumer must never have to remove
  escape sequences before parsing it.
- **"Set and not empty"** follows no-color.org, so `NO_COLOR=0` also turns
  colour off. The variable being present is the signal. Reading `0` as "colour,
  please" would break every program that follows the convention.

When colour is off, the serialiser removes escape sequences. Call sites do not
avoid them. This is the same shape as redaction, for the same reason: a
guarantee held in one place cannot be lost by a call site that forgot, and a
vendor message can arrive with escapes already in it.

### Progress, and the one thing on stderr that is not a message

While a verb reads a document from a vault, a spinner turns on **stderr**. It is
the tool's only progress indicator. One call site turns it on:
`_read_documents` in `sopuli/cli.py`, which `creds apply`, `creds rotate`,
`creds finish-rollover` and `creds status` all read through.

**Other reads of the vault do not animate.** `creds check` reads through
`_stored_credential`, and `creds generate` calls `store.read` directly where it
needs a document's current version for a compare-and-set. Turning the spinner
on at one call site, not everywhere, keeps "which operations count as slow" a
decision that someone makes in a diff. Adding another call site is another such
decision.

`Emitter.spinner()` decides whether the spinner runs, as `Emitter.use_color()`
does for colour, so no call site works it out for itself:

| # | Rule | Result |
|---|---|---|
| 1 | `--output json` | never, whatever else says |
| 2 | stderr is not a TTY | never |
| 3 | otherwise | animate |

These parts of the table are decisions:

- **No flag turns the spinner on.** `--color always` exists because a CI log
  viewer with no TTY can still show colour. Nothing shows a carriage-return
  animation usefully in a log file: a `--spinner` flag would only let somebody
  write about 12,000 characters of `|/-\` into 30 seconds of nightly log. So
  there is no flag, no `SOPULI_SPINNER`, no precedence rule, and nothing in the
  settings registry.
- **`--output json` turns it off, although the spinner never writes to
  stdout.** Rule 1 is not the same as rule 2. stdout is the contract (invariant
  12), and a scheduler often captures `2>&1`, which would put spinner frames
  ahead of the document. So the animation is turned off at the source.
- **Colour settings do not apply to it, and neither does `NO_COLOR`.** The frames
  are four ASCII characters and a carriage return, with no escape sequence. A
  `NO_COLOR=1` run writes the same bytes as an ordinary one.
- **It must never run while anything else writes to stderr.** The plan preview
  and `click.confirm` both write to stderr on purpose (§6, and
  `00-principles.md` P3). A spinner frame written over a prompt leaves the
  operator looking at a spinner while the process waits for an answer to a
  question that is no longer on screen. So a spinner wraps one call, not a whole
  verb, and that call is one the store layer serves without printing anything.

### What colour is allowed to mean

These rules bind the text renderer that
[ADR-003](../decisions/adr-003-text-tables.md) chose.

**The colours map onto the JSON vocabulary**: `state`, `by_state`, `drift`,
`unverifiable`, `failed`, and the `state` enum in the run schema. The text view
and the JSON view must not be able to describe one run differently. A separate
set of visual categories would be a second vocabulary, and the two would drift
apart.

`sopuli/output/palette.py` holds the roles. The rule applies to every view,
including `config show`, which has no states: there it applies to the fields
its `config` section emits.

<!-- checked-list: state-roles -->
| Role | What it marks | The field behind it |
|---|---|---|
| `heading` | a section name, a column heading | structure, not data |
| `muted` | the `-` standing in for a value that is not there | any nullable field |
| `notable` | an overridden target, a `non_production` store, a warning | `overridden`, `non_production` |
| `production` | the `prod` environment wherever it appears | `environment` |
| `good` | a state a reader can stop reading at | `state` = `IN_SYNC` |
| `attention` | something true that a person has to act on, the run being fine | `state` ∈ `DRIFT`, `PENDING_APPLY`, `ROLLOVER_ACTIVE`, `VAULT_ONLY`, `RESET` |
| `bad` | the tool could not do the job, or the estate is not in a state it can | `state` ∈ `ERROR`, `ACCOUNT_MISSING`, `LOCKED`, `EXPIRED` |
| `inconclusive` | no answer, and the absence is the finding | `state` ∈ `UNVERIFIABLE`, `SKIPPED`, `DECLARED` |

The same roles also colour a second vocabulary, the health of a store or an
install. There is no separate palette for it:

| Value | Role | Why |
|---|---|---|
| `vaults[].status` = `ok` | `good` | |
| `= degraded` | `attention` | it **answered** and cannot serve; the reader goes to the vault |
| `= unreachable` | `bad` | nothing answered; the reader goes to the network |
| `install.backends[].status` / `install.drivers[].status` = `not_installed` | `attention` | there is a `pip` line under the table |
| `= not_implemented`, nothing configured | `muted` | true on every run of this build; colouring it would make every `doctor` look broken |
| `= not_implemented`, something configured | `bad` | the run's actual failure, exit 9, and no install fixes it |
| `targets[].reachable` = `false` | `bad` | |

Each of these is a field the JSON already carries, so the two views still
cannot disagree.

**Two rules that can look inconsistent:**

- `IN_SYNC` is coloured and `reachable: true` is not. A result state is one of
  many, with no normal value, so cyan says "this row is done". Reachability has
  two values and one of them is almost always true. Colouring the common value
  would make the rare `no` look ordinary again. `config show` colours `prod`
  and no other environment for the same reason.
- `not_implemented` is the only status whose role depends on another column.
  Unconfigured, it is true on every run and means nothing. Configured, it is why
  the run exited 9.

`wallet_view` and `constraints_view` stay plain on purpose. They show prose and
key-value blocks, not tables, so there is no column to scan, and colour would
only decorate a sentence. Both carry diagnostic codes for a program that needs
to branch. Their module docstrings say so.

**`role_for_state` in `sopuli/output/palette.py` is the one function that gives
a state its role.** Every view calls it. When each view kept its own subset of
the enum, `check` coloured `DRIFT` and `apply` did not, and `apply` coloured
`ERROR` and `check` did not. One state got different emphasis depending on the
verb, which is what the roles exist to prevent.

These properties of the palette are decisions, not taste:

- **Converged is cyan, not green.** A deuteranopic reader cannot tell green
  `IN_SYNC` from yellow `DRIFT`, and that is exactly the distinction this tool
  exists to report. So the usual traffic light is the wrong palette here. Red
  stays for `bad`, where it is close to universal. `tests/test_palette.py`
  asserts that the three roles that must never look alike are distinct.
- **Inconclusive is dim, not coloured.** A row that says nothing must not
  compete with a row that says something, and must not read as good or bad.
  This also makes the palette usable in `creds status`, whose ordinary row is
  `UNVERIFIABLE`: the whole column recedes.
- **The grouping is not the exit code's grouping.**
  `sopuli.check.is_inconclusive` counts `ACCOUNT_MISSING`, `LOCKED` and
  `EXPIRED` as inconclusive, correctly: none of them says anything about the
  password. For a colour that is the wrong question, because a locked account is
  news. So those three are `bad` in the palette and inconclusive in the summary.
  A reader can see a red `ACCOUNT_MISSING` row above a `1 unverifiable`
  counter. The two answer different questions; they do not contradict each
  other.

**Colour never carries meaning alone.** Drift has its own exit code (3) because
schedulers alert on it. A person needs that distinction without colour too,
from a word or a symbol, with colour only reinforcing it. So the `NO_COLOR` view
loses nothing. This is the accessibility floor.

Every role decorates a word that is already on the line, such as `prod`,
`override`, `non-production` or `-`. So the guarantee holds by construction.
`tests/test_cli_smoke.py` checks the strong form of it end to end: with the
escapes removed, `--color always` output equals `--color never` output byte for
byte.

**The tool's own text is ASCII.** `tests/test_cli_smoke.py` checks this across
the whole command tree. It keeps decoration deliberate: box drawing, status
glyphs and other non-ASCII presentation belong to the text renderer, where the
choice is made once and can be switched off. They do not belong in a message
because someone typed a nicer dash. Text from outside the tool, such as an
account name, an `ORA-` message or a vault path, passes through unchanged. The
UTF-8 streams make that safe.

---

## 2. The run document

This sketch shows the run document's shape:

<!-- checked-list: run-document -->
```
{
  schema_version, tool, command,
  invocation { correlation_id, started_at, finished_at, duration_ms, actor,
               dry_run, profile, config_files[], selection, options },
  config     { sources[], resolved, declared | targets[] + bindings[] },
  policy     { name, length, charset, first_char, require, limit, samples[] },
  plan       { units[], shared_secrets[], confirmation_required, blast_radius },
  lock       { mode, held[], found[], broken, denied },
  results    [ { account, target, scope, secret, state, delivered, handover,
                 account_status, changed, actions[], verification, rollover,
                 password_age_days, started_at, duration_ms, error, warnings[],
                 overridden[], redraws, declared_by, reset_at } ],
  targets    [ { target, reachable, scope, asserted, duration_ms, privileges,
                 error, warnings[] } ],
  install    { backends[], drivers[] },
  wallet     { required_by[], tns_admin, directory, from_sqlnet, readable,
               files[], unreadable[], auto_login, insecure[] },
  vaults     [ { vault, type, status, detail, version, authenticated, skew_ms,
                 error, … } ],
  constraints { source, max_password_bytes, character_set, strictest_target,
                targets[], accounts[] },
  summary    { total, ok, changed, unchanged, drift, unverifiable, skipped,
               failed, by_state },
  diagnostics[],
  error      { category, message, hint },
  exit_code
}
```

`tests/test_doc_lists.py` checks the top-level keys and the `results[]` keys of
this sketch against the schema. The other objects are abridged.

The sections below explain the parts that encode a decision.

### `diagnostics`

`diagnostics[]` holds run-level findings: things the run reports and did not
refuse to run over. A config warning (`01-configuration.md` §10) is one, because
it belongs to no single target. Every command that loads a config emits its
warnings, including `config show` in both views and `config validate`. A warning
that reached only the text output would be invisible to the scheduler, which is
the reader that most needs it.

Each entry has a `level`: `info`, `warning` or `error`. §3 lists the codes. A
run with nothing to report omits the key; it does not emit an empty array.

### `config`, emitted by `config show`

`resolved` tells the two views of one file apart:

- **`resolved: false`** carries `declared`, the merged config document as
  loaded. The schema leaves it untyped on purpose. It is the user's YAML after
  `--config` layering, and reshaping it would answer a different question.
- **`resolved: true`** carries `targets[]` and `bindings[]`. `targets[]` is the
  expanded estate, with labels, provenance, and whether anything manages each
  target. `bindings[]` has one row per account per target, with its secret ref.

A binding's `secret` is the ref **as written**, a string that round-trips
(`01-configuration.md` §7), so it matches the config file by eye. The structured
form is `plan.units[].secret`, which does a different job: it addresses a
specific version at a specific moment, and this records what the file says.
Neither ever carries a value.

#### `config.vaults[]` — which store, at which address, from which layer

`config.vaults[]` answers "which vault will this run talk to, and which layer set
its address?" It is in both views, because neither view carries it otherwise:
`declared` has the address the file wrote, and `resolved` reports targets and
bindings, not stores. `doctor`'s `vaults[]` has no `addr` either.

This is one entry, from a run with `--vault-addr` set:

```json
"vaults": [
  {
    "name": "vault-dev",
    "type": "hashicorp",
    "settings": {
      "addr": {
        "value": "https://standby.example.com:8200",
        "source": "cli",
        "source_detail": "--vault-addr"
      },
      "kv_version": {
        "value": 2,
        "source": "object",
        "source_detail": "vaults.vault-dev.kv_version"
      },
      "mount": {
        "value": "kv",
        "source": "object",
        "source_detail": "vaults.vault-dev.mount"
      }
    }
  }
]
```

You cannot report where `addr` came from without reporting what it is, so each
entry carries the value with its provenance.

A `settings` entry has the **same shape** as an `invocation.options` entry. The
schema has one `$defs/resolved_setting` that both use: it is one question about
one resolver, and a second shape for it would be two things a consumer must
learn for one fact. `source_detail` is a location, never a value, by that
definition's own contract.

**Store settings are not in `invocation.options`.** `RESOLVED_SETTINGS` excludes
a store's keys, because they describe a store and not a run, and
`sopuli/invocation.py`'s `_wired()` raises on a name that is not listed. That
guard is right. Sharing the shape is not sharing the section.

These properties of the object are decisions:

- **It is always emitted, `[]` included**, as `install` is. Every estate that
  does anything has stores, so an empty array is a real answer here.
- **Only `name` and `type` sit beside `settings`.** Both are the store's
  identity, and neither can be layered: a store that is HashiCorp from a laptop
  and OCI from CI is two stores ([C13](../decisions/log.md#c13)).
  `non_production` and `locking` are absent: both are guardrails set only by
  declaration, `declared` carries them as written, and `doctor` reports the
  second as `lock.mode`. Adding either later is a minor change.
- **A key that no layer wrote is absent**, not `null`. A store with no namespace
  has no provenance for one, and a `null` would invite a consumer to branch on a
  field that is almost always empty.
- **`auth:` is not in `settings`.** A layer replaces it whole; it is not
  resolved key by key, so no layer won a key and there is no `resolved_setting`
  to emit. It is also the part of a store entry that addresses credentials, and
  §4's redaction rule is easier to keep by structure: there is nowhere here for
  it to go.

The JSON carries the provenance whether or not `--explain` was passed, unlike the
text table. There is nothing to filter: no `vaults.*` setting has a built-in
default, so every key reported is one that some layer wrote. That is the filter
`invocation.options` applies and `--explain` lifts.

### `policy`, emitted by `policy sample`

The section holds the policy as declared, and one entry per sample. Each entry
says how many characters the sample has, how many bytes in the encoding it was
measured against, how many of each character class, and whether it satisfies
the policy it was drawn from.

**A sample object has no value property**, just as `secret_ref` has none.
`policy sample --reveal` prints passwords to a terminal for a person to look at.
It is refused with `--output json`, because JSON is what gets captured and
shipped to log aggregation. The schema has nowhere to put a password, so the
refusal is a property of the format, not a promise.

`compliant` is always `true` for a generated sample. It is reported anyway,
because `false` would mean that the generator and the validator disagree. One
predicate serves both (`01-configuration.md` §8).

### `error`, when the run failed as a whole

The run-level `error` is not `results[].error`, which is one target failing in a
run that otherwise worked. The run-level one is present when there is no
per-target work to report: the configuration could not be read, or something
failed before the first target was touched. It is what makes exit 9 and exit 1
answerable from the document alone.

It has **no location field**. A config error's file and key path go inside
`message`. `hint` has its own field and is not repeated in `message`. The
category comes from the exception itself. The output boundary does not infer
one from a Python type, because that mapping is the first to go wrong when
someone adds a subclass.

**A driver error carries its own category.** A capability refusal has
`category: "capability"`, exit 5, and the capability's name in
`target_capability`. That is invariant 4's distinct exit code, and the field a
consumer branches on, so it does not have to parse the name out of the message.

**`target_capability` holds a name, never a sentence.** Most names are about a
target. `creds check --method hash|both` adds names about an account:

- `verifier_12c`: the account has no 12C verifier;
- `verifier_12c_format`: a `T:` or `t:` token is in a format never measured;
- `verifier_charset`: the database character set cannot hold the vault value.

`error.hint` names the account, because per-account detail goes there.
`offline_verify` is the probe's name for a `SYS.USER$` that this session cannot
read. On Autonomous Database its hint says that no account there can read it,
and does not advise a grant nobody there can make.

**A pre-flight refusal** has the `category` of the problem that stopped it:
`connectivity`, `authorization` or `database`. `message` gives the number of
findings over the number of targets and names the first. Each finding is a
`diagnostics[]` entry with its `target`, and its `account` where the check is
about one. The findings have no diagnostic code: §3's rule is that a code exists
for what the exit code cannot tell you, and here `category` already carries the
branch. A `warning`-level finding is one the survey could not establish, such as
an unreadable privilege audit. It did not refuse, and it appears on runs that
went ahead.

**A rotation reports both phases in one `results[]`.** `creds rotate` runs the
steps of other verbs and reuses their entries; it does not add a third shape.
The staging write (UC-1 §8 step 4) produces `generate`'s entry, with its
`vault_write_pending` action. Steps 5 to 7 produce `apply`'s entry, with
`password_set`, the two `verify` actions and `vault_promote`. So an account that
the run rotated appears twice, once per phase, which matches the two writes it
made.

`rotate` adds one diagnostic and no fields. `SOPULI-W012` is UC-1 §8 step 8.
When `--max-age-days` narrows a run, `summary.total` shows it; there is no
member for it. An account the age filter left alone is one this run did not act
on. A fourth state for it would put "not attempted" in the same vocabulary as
"attempted and unverifiable".

**An account a guardrail refused is `SKIPPED`, with its reason.** `SKIPPED` is
the schema's word for something the tool declined to do, as against something it
tried and could not do; `creds finish-rollover` uses it the same way. It is not
a failure, it does not make the run partial, and the exit code ignores it.
`02-oracle-privileges.md` §4 has the reasoning: the run was never going to act
on that account, and a nightly rotation that exited 4 forever because one
account holds `DBA` would be more disruptive than the mistake the guardrail
catches.

### `invocation.selection`

`invocation.selection` records what the run was narrowed to, as the selectors
were given, not as they resolved. The resolved answer is `config.targets[]` or
`results[]`. Having both is what makes a filtered run auditable.

The members are `applications`, `accounts`, `targets`, `groups` and `select`.
They come from `--application`, `--account`, `--target`, `--group` and
`--select k=v`. A selector that was not given is omitted, not sent empty: an
empty array would claim the run applied a selector it was not given.

`selection` is absent when the whole estate was in scope. A consumer that reads
`total: 2` cannot otherwise tell a small estate from a filtered one, and "2
rotated" means very different things in each.

### `invocation.profile`

The active profile's name, or absent (`01-configuration.md` §5).

It is reported whether or not the profile changed anything. `options` is
different: it carries only what changed behaviour. When two runs over one config
behaved differently, the first question is which profile each ran under, and
that question has an answer even when no key differed.

It is absent, not `null`, when no profile is active. The schema allows either. A
key with no name in it reads as "a profile was considered and found", which is
not what happened.

The choice of profile is itself a resolved setting, `profile`, from
`--profile`, `SOPULI_PROFILE` or `defaults.profile`. So `options` says where the
name came from, and this field says what it resolved to. They differ in one
case: when nobody asked for a profile and the file names no default, `options`
has no `profile` row and this field is absent.

### `invocation.config_files`

The files this run read, in layering order (`01-configuration.md` §5).

`invocation.options` names a file only through the `source_detail` of a setting
that file changed. This field lists every file read, so a run whose config
supplied nothing worth reporting still names its files.
`tests/test_run_document.py` checks that the committed example carries no
`invocation` key that the producer cannot write.

**The order is part of the contract.** Later files are layered over earlier
ones, so sorting them would describe a precedence the run did not use.

**It holds paths, not content.** A consumer asks this field which estate the
document is about, which is what `creds apply --repair` reads it for. Two runs
over the same paths are the same estate for that question. A file edited between
them is a question of staleness, for whatever compares the documents.

**It is absent, not empty, when the run loaded no configuration layer**: the
file was missing, unreadable or rejected. Every command that writes a run
document loads a config before its body runs (`sopuli about` writes none), so
absence always means the run stopped while trying, and the
`error` on exit 9 names the path. An empty array would say that the run looked
and found nothing, which is a different statement.

### `invocation.correlation_id`

A UUID for each run. The tool also:

- sets it as the Oracle **client identifier** on every session
  (`DBMS_SESSION.SET_IDENTIFIER`), so it lands in
  `UNIFIED_AUDIT_TRAIL.CLIENT_ID`;
- writes it into the **vault secret metadata** on every write.

So one id joins the tool's JSON, the database audit trail and the vault's
version history. With it, "something rotated at 03:00 and half of it failed"
has an answer.

### `invocation.options`

Every effective option that changed behaviour, with the precedence layer it came
from:

```json
"verify.method": { "value": "hash", "source": "profile",
                   "source_detail": "profiles.scheduled.verify.method" }
```

This is the machine-readable form of `config show --explain` (P3). When someone
asks why a scheduled run behaved differently from their interactive one, the
answer is in the output they already have. They do not need to run it again.

By default it carries only the settings that **changed behaviour**. A setting
answered by its built-in default changed nothing, and reporting
`output: text [builtin]` on every clean run would be noise in a document that
consumers compare. `--explain` lifts that filter, in this mode as in text mode:
it means "show everything you consulted". An entry has the same shape either
way, so the flag changes how many entries appear and nothing about what an
entry means.

**`source_detail` is a location, never a value.** It is the flag as typed (`-o`
is recorded as `-o`), the variable name, or the config key. It exists so that
somebody can find the setting in their own command line or CI job definition.
That is why the profile layer points at `profiles.ci.verify.method`, not just
`"profile"`. No code path puts a value in this field, so it is inside §4's
redaction rule by construction.

This rule is about what may appear **in the document**. Invariant 1 is about
what may appear **in argv**, and the two are separate rules. A flag that took a
token as its value would satisfy this rule and still be forbidden. That is why
`--vault-token-file PATH` takes a path and `--vault-token` is refused (§3a of
`01-configuration.md`, [ADR-007](../decisions/adr-007-vault-token-flag.md)).
The vault token chain does not appear in `invocation.options` at all: it is its
own merge, resolved when a run reaches a store, and the settings registry does
not resolve it.

**For a ratcheted setting, `source` names the layer that decided the effective
value, not the highest layer present.** If `defaults.safety.readonly` is `true`
and a flag asked to relax it, the pair is `"source": "defaults"`,
`"source_detail": "defaults.safety.readonly"`: the layer that held, and the key
in it. Reporting `"cli"` because the command line is layer 1 would be exactly
backwards. The refused request still appears, in `diagnostics[]`, as a warning
that names both ends.

The two fields always agree, because `source_detail` is where the value named by
`source` was written. A `safety:` block under a target resolves as `"object"` /
`"targets.acme-alpha.safety.readonly"`, and the same block under a profile as
`"profile"` / `"profiles.ci.safety.readonly"`. The enum has no `config` value:
"somewhere in the file" is not a precedence layer, and several layers live in
the file.

A ratcheted setting can have **several** contributing sources while `source`
names the floor, not the top. A union of `confirm_environments` is the clearest
case. That is correct, and the text output says so. Do not report it as a bug.
If the whole contribution chain is ever wanted in JSON, it arrives as a new
optional field (a minor bump), never as a change to what `source` means.

The `source` enum has no `cli_group` / `cli_verb` split. A precedence layer
encodes authority: who expressed the more specific or more recent intent. A flag
before the subcommand and one after it come from the same person, in the same
command line, at the same moment. Splitting them would expose a detail of the
CLI parser in a field that scripts branch on. If the position is worth
recording, it goes in `source_detail`.

### `plan`, emitted on real runs too

`plan` is not only for dry runs. A real run emits the same structure it would
have emitted with `--dry-run`, so comparing "what we said we would do" with
`results` is mechanical. `plan.shared_secrets` exists to show the case where one
secret serves many targets (UC-1 §4): rotating one account changes three PDBs.
That is legal and often intended, but never invisible.

**`confirmation_required` is optional, and the tool does not emit it**
(open: #663). Emitting `false` would claim that the run met a confirmation gate
and passed it. Absent says that the run was never asked, which is true.

**A unit omits `secret` when nothing has named its store yet.** `secret_ref`
requires `vault` as a string, so there is no shape for half an address, and
`units[].secret` is optional so that a unit can say it has none.
`01-configuration.md` §3's chain for a binding's store leaves out a profile's `vault:` and `SOPULI_VAULT` on purpose: the active
profile is a property of a run, and bindings are built once, at load. So a valid
file can reach the plan with no store resolved. The plan does not refuse it
([C15](../decisions/log.md#c15)). The command that needs a store fails, once the
run's profile is known and the answer is exact (invariant 4).
`config show --resolved` shows `-` for the same binding.
`config/binding_stores.py` completes such a binding, called by the command that
needs a store, not at load.

**`results` is per credential; `targets` is per target.** `creds check` emits the
first and `doctor` the second: one reports on a password in a database, the other
on the database. Read `results[]` beside `plan.units[]`: they have the same
grain and the same order, so comparing what a run said it would do with what it
did is mechanical.

**`summary`'s optional counters appear only from the verbs that count them.**
`drift: 0` from `doctor` would say that `doctor` looked for drift and found none,
and it never looks. `by_state` likewise carries only the states a run produced.

**`plan` is absent on a command that plans nothing**: `config show`, `doctor`,
`lock status`. [J2](../decisions/log.md#j2) says every command that plans emits
`plan`, and a command with no units does not plan. `sopuli.plan` builds the
section and `sopuli/output/plan_view.py` reads it.

One secret per application is the documented default
([Q7](../decisions/log.md#q7)), so sharing has a second axis, and a
`shared_secrets` entry carries it: `accounts[]`, present when one document holds
more than one account's credential. Then rotating `acme_orders_user` rewrites
the document that `acme_batch_user` reads. The two axes are different questions:
`targets[]` answers "who receives this password", and `accounts[]` answers
"whose password is in this document". A consumer that knew only the first would
report a blast radius of one account for a write that touched six.

`accounts[]` is optional, and means "sharing the operator might not have
intended". A document with exactly one account omits it, because a list of one is
not a warning.

**An entry is one document, not one ref.** The accounts in a document differ only
by the pointer below the field. A write, a compare-and-set and the advisory lock
all act on the whole document, so there is one entry per lock, and its `secret`
is a `vault` and a `path` with no `field`. One entry per ref would emit six
near-identical entries for a six-account document, each repeating the same five
neighbours. The path is normalised by the same function that
`sopuli/lock/keys.py` uses, so "shares a document" and "shares a lock" cannot give
different answers.

**`accounts[]` comes from the config, never from the store.** The accounts in an
entry are the ones the file declares for that document: invariant 5's set, which
is also the set a write may touch. This has two intended consequences:

- The plan is offline and deterministic. A plan can be reviewed ahead of time
  only if it depends on the config and the selection alone. The section is also
  emitted on real runs, and a list read from a live document would make the
  plan-versus-`results` comparison depend on whether somebody edited the vault
  in between.
- It does not show an account that is in the document but not in the file. That
  is worth knowing, but it is drift, not plan, so `creds check` reports it.

**`config.shared_secrets` is the same shape, asked of the whole file.**
`config show --resolved` emits it from the config alone. That answers the
offline question: what does my file share, before I run anything?
`plan.shared_secrets` is the same detection narrowed to one run's work. They
coexist for the same reason as `config.bindings` and `plan.units[]`: one
describes the file, the other a run. Both are omitted when nothing is shared,
because an empty array reads like a finding that came back negative.

### `lock`, on runs that take one

`00-principles.md` P5's advisory lock is in the vault, keyed on the **secret
path** being changed ([Q2](../decisions/log.md#q2)). These verbs write the
section:

- `creds generate`, `creds apply`, `creds rotate` and
  `account reset-password` take locks and fill `held[]`. All four go through
  `_record_locks` in `sopuli/cli.py`, which runs after release, so `released`
  reports the store's record, not the moment;
- `lock status` fills `found[]`;
- `lock break` fills `broken[]`.

`denied` appears on any of them that is refused a live lock.
`sopuli/output/lock_view.py` builds the section, and `tests/test_lock_view.py`
validates every shape it can build against the schema. The section describes the
guarantee, not the mechanism. This is from `creds generate --output json` against
the tier-1 stack:

```json
"lock": {
  "mode": "cas",
  "held": [ { "vault": "vault-dev", "path": "acme/dev/acme",
              "fence": 1,
              "acquired_at": "2026-09-11T10:20:52.999171Z",
              "expires_at": "2026-09-11T10:35:52.999171Z",
              "released": true } ]
}
```

**`mode` is `cas` or `none`**, not `kv2` or `flock`. A consumer needs to know
whether the run was protected; it should not need to know what KV v1 is to find
out. A store configured with `locking: advisory-only` reports `none`: the record
was written without compare-and-set, which catches two operators minutes apart
and misses two CI jobs in the same second. Every such run also carries a
`diagnostics[]` warning, `SOPULI-W001` (§3), so the weakening is in each run's
audit trail, not only in a config file somebody would have to read.

**`fence` is the version that the acquiring write returned.** It is the reason
the lock is in the vault and not in the database. The risk to design against is
the stolen lock, not the stale one: a run stalls, its lock expires, a second run
takes over and rotates, and then the first run wakes up and applies
`ALTER USER` to its remaining targets from a plan that is no longer true.
`DBMS_LOCK` does not prevent that: the stalled session is still alive and still
holds it. Re-reading the fence before every change does prevent it. So releasing
the lock automatically when a session dies was not worth a wider grant set.

**`denied` appears on exit 7**, with the holder: host, pid, os_user, and the
holder's own `correlation_id`. Those fields answer the question everyone has at
that moment: is this a colleague in the middle of a rotation, or a process that
died? There is never more than one, because acquisition is all-or-nothing and
stops at the first refusal.

Its `reason` says **how** the run lost, and the two ways are different events:

- `held`: the run read a held, unexpired record. The holder and the timestamps
  describe that record, and the schema requires them.
- `race`: the compare-and-set write was refused, because another run acquired
  the lock between this run's read and its write. The winner's record was never
  read. So `holder` is optional, and `reason` says why it is absent. An all-null
  holder would look the same as a vault that answered badly.

A conflict on the *renewal* write is neither, and is not `denied` at all. This
run held the lock, so losing the compare-and-set is a takeover, reported like
every other takeover. Every field in `held[]` is required, because the section is
written when the run ends, and by then the tool knows everything about its own
locks.

**The section is absent on a run that takes no lock**: `check`, `status` and
every `--dry-run`. Absent means none was needed, not none was available.

**`found[]` lists other runs' locks.** `sopuli lock status` takes no lock. It
reads the record at every secret path the config declares, and lists each
store's lock prefix, so a record at a path the config does *not* declare is
reported too:

```json
"lock": {
  "mode": "cas",
  "found": [ { "vault": "vault-prod", "path": "apps/acme/db",
               "held": true, "declared": true, "declared_by": "binding",
               "state": "held",
               "expired": false, "version": 41,
               "acquired_at": "…", "expires_at": "…",
               "holder": { "host": "ci-runner-3", "pid": 8821,
                           "os_user": "svc_sopuli", "correlation_id": "…",
                           "command": "creds rotate" } } ]
}
```

It is a separate array, not `held[]` reused, because **`held` is possessive**.
In `held[]`, `released: true` means "this run let go cleanly". In a survey the
same word would mean "this path is free". One field would mean two things
depending on `command`, which §8's rules exist to prevent, and a consumer that
counted held locks across runs would count surveys as acquisitions. The holder
uses the same definition as `denied.holder`, because exit 7 and `lock status`
answer the same question.

**`declared` says whether this configuration accounts for the record.** `false`
is a record the store holds and the file names nowhere: an application renamed
or removed, or another config's estate sharing the mount. An operator cannot see
it any other way, and it is the reason for listing. Invariant 5 still holds: the
config whitelists what the tool may *touch*, and a survey touches nothing. It is
judged against the **unfiltered** estate, so `--select` never turns somebody's
own lock into a leftover. It is required on every entry: a consumer that had to
read absence as "mine" would be branching on a gap, and a gap is also what a
producer that forgot the field would emit.

**`declared_by` says how**: `binding`, `reset_records`, or `null` for a
leftover. From UC-2 on, "whose" has three answers. A reset lock is keyed on the
reset record's own path, which no binding produces. The file declares the
`reset_records:` prefix and cannot name the keys under it, because an account
admitted by a `profile:` or `role:` predicate has no name until a database is
asked, and `lock status` asks none. So the survey finds reset locks by listing
the prefix. Such an entry has `declared: true` and
`declared_by: "reset_records"`.

- **`declared` widened; it was not replaced.** It means "this configuration
  accounts for the path at all", which is what a consumer filtering its own locks
  out of a survey asks. Widening a boolean is a minor bump. Turning it into a
  three-valued string would be a rename, which is major, and every consumer
  would pay for a question none of them asked.
- **`declared_by` is not an enum**, unlike `state`. A later use case may claim
  another prefix: UC-4 hands accounts over through the same delivery
  abstraction (UC-2 §6.7). A consumer that switched on two values would break on
  a third, instead of treating it as "not mine".

A **fourth array was rejected.** `held` and `found` are separate because one
field would mean different things in each. Nothing like that happens here: every
field of a leftover means what it means for a declared record, and only ownership
differs. The text view does show the two separately, which is a rendering
choice, not a contract.

**A store with no `list` capability gets a warning, not a refusal**
(`SOPULI-W005`). A refusal would make `lock status` work on some backends and not
others, and would lose the report for every other store too. But it cannot be
silent: an empty `found[]` tells a consumer there are no leftovers, and that
conclusion must come from having looked.

`held` is the verdict and `state` is the evidence; they are not one field twice.
Anything that is not `released` is held, **including a state this build does not
know**. Treating an unknown state as free is the one guess that ends with two
runs rotating one credential. A consumer that saw only `held: true` could not
tell such a record from an ordinary one. `version` is the store's version and is
not called a fence: a fence is a claim, and a survey holds none.

**A declared path with no record is not an entry.** `found` is what was read,
which keeps every member of an entry required. `summary.total` is how many paths
were examined, and the difference between the two numbers is how many are free.
On `lock status` the array is emitted even when empty, because there an empty
array is the finding: a quiet estate must not look like a command that did not
look.

`mode` means the same in every array: the guarantee available in the stores the
section covers. On a run that took locks, it is what they were taken under. On a
survey, it is what a lock in those stores would be worth.

**`broken[]` lists locks this run ended.** `sopuli lock break` writes a
`released` record over a held one, comparing against the version it read:

```json
"lock": {
  "mode": "cas",
  "broken": [ { "vault": "vault-prod", "path": "apps/acme/db",
                "applied": true, "state": "held", "expired": true,
                "version": 41, "new_version": 42,
                "acquired_at": "…", "expires_at": "…",
                "holder": { "host": "ci-runner-3", "pid": 8821,
                            "os_user": "svc_sopuli", "correlation_id": "…",
                            "command": "creds rotate" } } ]
}
```

It is its own array for the reason `held` and `found` are separate: a broken lock
is neither a claim the run holds nor a record it only read. Its important fields
are ones the other arrays lack:

- **`version` is what the write compared against**, and **`new_version` is what
  it produced.** The second fences the previous holder, whose next check now
  fails. Neither is called a fence: `held[]`'s `fence` is a claim this run holds,
  and after a break nobody holds anything.
- `version` is never null here, unlike `found[].version`. A store that cannot
  fence is refused before the read, with exit 5, and so is a store declared
  `locking: advisory-only`, whatever it supports. A break with no fence is worse
  than a weaker guarantee. The released record keeps the holder's own
  `correlation_id`, so without a version to compare, the holder's next check
  would find a record that still says "mine", and it would carry on rotating
  without being told.
- **`applied` makes `--dry-run` and the real run one shape.** The plan is the
  entry, and whether it happened is a boolean in it, so a consumer compares like
  with like (invariant 8). It is `false` under `--dry-run`, where `new_version`
  is null because no version was produced.

**An empty `broken[]` is the finding**, as an empty `found[]` is in a survey.
There was no claim at the path, either no record or one already released, so
nothing was broken, `summary.changed` is 0 and the run exits 0. This is
invariant 9 for this verb, and it follows from the design: a second `lock break`
on a path finds the record the first one wrote.

**The holder is reported here and nowhere afterwards.** The write replaces the
holder's record with a released one that still carries their name, so a later
`lock status` cannot tell a break from a clean release. `locking.break_expired`
already accepts the same cost, because its takeover overwrites the record
entirely. The path is not the audit trail; the run document is. `SOPULI-W002`
says the same in words.

An unexpired lock is **not** in this array. It is `denied`, on exit 7, with the
holder named. It is the same object and the same wording as a rotation that lost
the same lock, because it answers the same question for the same person.

### `targets`, emitted by `doctor`

One entry per target. It is not `results[]`, on purpose.

A `result` is per account and target. It requires an `account`, and a `state`
from a vocabulary that is entirely about credential sync: `IN_SYNC`, `DRIFT`,
`ACCOUNT_MISSING`. `doctor` manages no credential and touches no account, so
each of those words would mean something else. `IN_SYNC` on a healthy target
would claim a sync that never happened, and `SKIPPED` means "we chose not to
try".

Widening `result` was the alternative: make `account` optional and add states.
That is a major change, because a consumer that reads `result.account`
unconditionally breaks. A new section is a minor one.

```json
"targets": [
  {
    "target": "orders-pdb",
    "reachable": true,
    "duration_ms": 84,
    "scope": {
      "type": "pdb",
      "container": "ORDERS",
      "db_version": "23.0.0.0.0",
      "open_mode": "READ WRITE",
      "read_write": true,
      "capabilities": ["account_lock_state", "expire_password", "password_rollover"],
      "offline_verify_available": false,
      "labels": { "target_set": "appdb", "env": "qa" }
    },
    "asserted": { "scope": "pdb", "container": "ORDERS", "matches": true }
  },
  {
    "target": "billing-pdb",
    "reachable": false,
    "error": { "category": "connectivity", "code": "ORA-12541", "message": "TNS:no listener" }
  }
]
```

**Branch on `reachable`. Everything else is absent, not empty, on an
unreachable target.** A target that could not be reached has no scope, no
capabilities and no assertion result. An empty `capabilities` array would read as
a database that supports nothing, which is a different and much more alarming
claim than "nobody could reach it".

**`asserted` is absent when the target asserts nothing**, not present with
`matches: true`. `01-configuration.md` §3a says that an assertion nobody makes is
not a gap. An object claiming a match would report agreement with a claim that
was never made.

### `targets[].privileges`, emitted by `doctor --check-privileges`

What the service account holds, judged against the lists in
`02-oracle-privileges.md` §2 and §3. This is from a run against a PDB service
account on 26ai Free 23.26.2.0.0:

```json
"privileges": {
  "held": ["ALTER USER", "CREATE SESSION", "SELECT ON DBA_PROFILES",
           "SELECT ON DBA_ROLE_PRIVS", "SELECT ON DBA_USERS",
           "SELECT ON V_$DATABASE", "SELECT ON V_$INSTANCE"],
  "missing": [],
  "common": [],
  "roles": [],
  "unaudited": ["EXECUTE ON DBMS_LOCK"],
  "unreadable": []
}
```

**It is absent unless the flag asked for it, and complete whenever it is
present**, empty arrays included, so every property is required. That is
ADR-006's E6 applied to an audit: a section that appeared only when there was a
problem could not be quoted as evidence that there was none. "Not asked" and
"asked, and nothing found" are different facts, and a consumer that tested the
section for truthiness would merge them.

**The findings are not here.** `over_granted` is on `scope`. Two copies of one
finding are two things that can disagree. A consumer reads what was found from
`scope.over_granted`, and how far the audit reached from this section.

**`held`/`missing` and `over_granted` are separate questions**, not two ends of
one scale. The first is what the account needs and may lack; the second is what
it has and must not. An account can be in both states at once, which is what a
half-finished debugging session leaves. `missing` is written as the `GRANT` to
issue, because somebody has to go and issue it.

**`unaudited` and `unreadable` are the report's two ways of saying it did not
look**, and they are not interchangeable:

- **`unaudited`** is a row of `02-oracle-privileges.md` §3's list that this run
  did not check. It is never empty on Oracle: `EXECUTE ON DBMS_LOCK` is an
  object privilege, and no view the audit reads carries it. `SYSDBA` and
  `SYSOPER` are in it only where the optional `SELECT ON V$PWFILE_USERS` grant
  (§2 of that document) was not taken. Where it was, the audit checks them like
  anything else, and a held one appears in `scope.over_granted`.
- **`unreadable`** is a view that *raised*. That makes the audit partial and
  changes how `over_granted` should be read. A grant documented as optional
  never lands here: declining it is the documented install. A report that called
  every correct install partial would teach readers to skip the line that matters
  when a view really was refused.

Both reach the text report and `targets[].warnings` as caveats, on every run, not
only on a bad one. Where a `GRANT` would shrink `unaudited`, a line names it.
Neither changes the exit code: `--check-privileges` warns and does not fail
([P5](../decisions/log.md#p5)), because failing would block somebody in the
middle of an incident over a condition they did not create.

### `install`, emitted by `doctor`

Which backends and drivers this build can serve, which the config asks for, and
where the two disagree. **It is on every run, not only on a mismatch.** That is
ADR-006's E6, and it sets the whole shape of the section:

> `doctor`'s question is "can I reach my vaults", and its output is audit
> evidence as often as it is a diagnostic; a section that appears only when
> something is wrong cannot be quoted as proof that nothing was.

```json
"install": {
  "backends": [
    { "name": "file",      "status": "not_implemented", "vaults": [] },
    { "name": "hashicorp", "status": "installed",       "vaults": ["vault-prod"] },
    { "name": "keyring",   "status": "not_implemented", "vaults": [] },
    { "name": "oci",       "status": "not_installed",   "vaults": ["vault-dr"],
      "install_command": "pip install \"sopuli-dba[oci]\"" }
  ],
  "drivers": [
    { "name": "oracle", "status": "installed", "targets": 21 }
  ]
}
```

**Every registry entry appears, configured or not.** So the section can report
the third case: installed and not configured. Nothing else in the tool looks at
it that way round, and the gap between what a machine can do and what it was
asked to do is worth seeing before somebody is troubleshooting inside it. An
unconfigured backend is a row with an empty `vaults`, never a missing row.

**`status` has three values, not two**, because the two failing ones have
different remedies, and only one is the reader's to apply:

- `not_installed`: the module is here and the client is not. `install_command`
  is the line to paste.
- `not_implemented`: this build has no module for it, and nothing the operator
  installs changes that. Such a row has no install line, however much its name
  suggests one exists.

These are the two conditions that `SOPULI-20001` and its sibling
`BackendNotImplementedError` already separate. Merging them would send somebody
to `pip` for something `pip` cannot supply.

**Backends name their `vaults:` entries; drivers count their targets.** A store
is written by hand, there are a few, and its name is the thing to go and look at.
Targets are generated by the dozen from one `target_sets:` entry, and
`targets[]` already lists every one, so naming them again would be a second copy
of a fact in the same document. `SOPULI-W006` is one warning per driver *type*
for the same reason.

**A configured component this machine cannot serve fails the run, with exit 9.**
`config validate` warns about the same fact and exits 0 (E4). The two commands
answer differently on purpose: one asks whether the file is valid, and it is; the
other asks whether this machine can reach what the file names. Exit 9 and not 1
is E5's number for the same condition when a command resolves a component, and
`doctor` reporting it under another number would give the tool two answers to
one question. `summary` still counts targets: an install-shape failure is not a
target that failed.

### `wallet`, emitted by `doctor`

Whether this machine has an Oracle wallet that the run can authenticate with. P4
names wallet readability beside client presence and `TNS_ADMIN`. `doctor`
reports whether `TNS_ADMIN` is set; this section reports whether there is a
wallet there that this process can read. On a machine where a service runs as
one user and a DBA tests as another, those are different facts.

```json
"wallet": {
  "required_by": ["cdb-root-dev"],
  "tns_admin": "/opt/oracle/network/admin",
  "directory": "/opt/oracle/wallet",
  "from_sqlnet": true,
  "readable": true,
  "files": ["cwallet.sso"],
  "unreadable": [],
  "auto_login": true,
  "insecure": []
}
```

**It is absent when nothing in the estate uses `auth: external`.** That is the
opposite of `install`'s rule, for the opposite reason. Install shape is always
true of the machine. A wallet matters only for a configuration option that most
files never use, and a missing-wallet warning in every document that never needed
one would be noise.

**`directory` is not always `tns_admin`, and `from_sqlnet` says when it is not.**
`WALLET_LOCATION` in `sqlnet.ora` moves the wallet, and the client follows it. A
check that did not follow it would report "no wallet" for a correctly configured
estate, and send somebody to fix a directory that was never wrong. A reader who
looks in the obvious directory and finds nothing must be able to see that the
tool looked elsewhere.

**Presence is not access, so `files` holds what could be opened.** A wallet owned
by the service's account exists for every account on the machine and opens for
exactly one. This section exists for that case, so the tool reads a byte; it
does not infer access from the file existing. A file that is there and
unreadable goes in `unreadable[]` and does not count towards `auto_login`. That
is a different finding from a missing wallet, with a different remedy: a missing
wallet means asking somebody for one, and an unreadable one is in the right place
and owned by the wrong account.

**`auto_login`, not just `files`.** `ewallet.p12` alone is a wallet, but it needs
a passphrase that this tool cannot supply. A directory holding only that file
cannot serve an unattended run, although a naive "is there a wallet here?" says
yes. That is why the field exists.

**Nothing here changes the exit code.** An unreadable wallet is not a separate
verdict. It shows in each target's reachability, which the connection attempt
settles a moment later. The section explains the failure that is about to happen;
it does not pre-empt it. `SOPULI-W007` carries the explanation into
`diagnostics[]`. A wallet that other people can read is `SOPULI-W008`, also a
warning, for the reason P5 gives for over-granted accounts: it is somebody else's
file, and refusing to run would block the person who ran the command over a
condition they did not create.

**The wallet is not opened.** Confirming that it holds a credential for the
alias means asking the Oracle client, and the connection already does that
better than any inspection: a target that connects has proved its wallet works.
What is left for this section is the diagnosis when it does not.

### `vaults`, emitted by `doctor`

Every store the configuration declares: whether it answered, whether this run's
credential was accepted, and how far its clock is from this machine's. P4 names
vault reachability and clock skew beside client presence and `TNS_ADMIN`.

```json
"vaults": [
  {
    "vault": "vault-prod",
    "type": "hashicorp",
    "status": "ok",
    "duration_ms": 41,
    "version": "2.0.4",
    "authenticated": true,
    "server_time": "2026-08-28T11:35:29Z",
    "skew_ms": -210,
    "skew_uncertain_by_ms": 1003,
    "skew_within_tolerance": true,
    "tolerance_ms": 60000
  },
  {
    "vault": "vault-dr",
    "type": "hashicorp",
    "status": "unreachable",
    "duration_ms": 2334,
    "detail": "the store did not answer within the timeout: timed out"
  }
]
```

**The clock skew matters for locking.** `sopuli/lock/decide.py` compares a
lease's `expires_at` with *this* machine's clock, and allows `CLOCK_SKEW` for
the two to disagree. A host whose clock is minutes out takes over locks that are
still live, or refuses ones long dead, and the failure looks like a locking bug,
not a clock problem. `tolerance_ms` is that allowance, reported so that the
verdict can be checked.

**`status` has three values, not two.**

- `ok`: the store answered and can serve this run.
- `degraded`: it answered and cannot serve: sealed, standing by, not
  initialised, or refusing the credential it was opened with.
- `unreachable`: nothing recognisable answered.

`degraded` exists because the reader's next step differs: `degraded` sends
somebody to the vault, and `unreachable` sends them to the network. Going to the
wrong one costs an outage's worth of time.

**An answer the tool cannot read is `unreachable`, not `degraded`.** A proxy's
502 is not a Vault saying anything about itself, and treating it as evidence that
a store is there would make the survey worthless.
`sopuli/store/hashicorp/_errors.py` applies the same fail-closed rule to an
unrecognised 400.

**Only `unreachable` changes the exit code**, to 1, as an unreachable target
does. The vault is master and the direction is always vault → database
(invariant 6), so no `creds` verb can do anything with a store nobody can reach.
A degraded store and a skewed clock leave the run at 0 and appear in
`diagnostics[]` as `SOPULI-W010` and `SOPULI-W009`. That is P5's answer for
over-granted accounts applied to the same kind of question: `doctor` must not
refuse to survey an estate over a condition the person running it did not create.

**`summary` still counts targets.** A vault is not a target, and adding vaults to
`failed` to make the exit code look derivable would put a number in the document
that no `targets[]` entry explains. The exit code is not a function of the
summary, here or in `install`.

**Absent skew and zero skew are different answers.** A backend that exposes no
server time has `server_time`, `skew_ms` and the three fields beside it all
absent. Two clocks that agree have `skew_ms: 0`. Using this host's clock for a
store that cannot report one would produce a confident zero, which is the exact
confusion the measurement exists to avoid.

**The measurement says what it does not know.** The store answered at some point
during the round trip, so half the round trip, plus whatever the store rounds its
own answer to, is how much one request cannot pin down. That is
`skew_uncertain_by_ms`, and `skew_within_tolerance` is judged against the
*unexplained* part of the difference. So a slow link cannot create a skew
finding. That matters: an operator who once chases a clock that was fine stops
believing the next report. HashiCorp answers in whole seconds, so two
synchronised clocks report a small negative figure, not zero.

**`authenticated` absent means "not asked".** `sys/health` takes no token, so a
store whose credential expired last night answers it normally. The token is
looked up separately, and only where a sealed store would not refuse the lookup
and have the refusal blamed on the credential. Absent, `false` and `true` are
three findings, and none collapses into another.

**`detail` and `error` are not two spellings of one thing.** `detail` is always
the one-line answer to "why", whichever way the store failed. `error` appears
only where something **raised**: a backend with no module, a client that is not
installed, a refused login. Only those carry a category and a code worth
branching on. So read `status` to branch, `detail` for the reason, and `error`
when there is a classified cause.

**Nothing here writes.** P5 makes `doctor` change nothing. A reachability check
that proved itself by leaving a lease behind would change what it measures, and
on a lock mount a concurrent rotation would notice.

### `constraints`, emitted by `creds generate`

What the estate said a password may be, read before one was drawn (UC-1 §4 step
2). One entry for each target asked, and one for each account that answered. This
is from a tier-1 run:

```json
"constraints": {
  "source": "targets",
  "max_password_bytes": 128,
  "character_set": "AL32UTF8",
  "targets": [
    {
      "target": "appdb-alpha",
      "reachable": true,
      "max_password_bytes": 128,
      "measured_as": "utf-8",
      "character_set": "AL32UTF8"
    }
  ],
  "accounts": [
    {
      "target": "appdb-alpha",
      "account": "ACME_WEB_USER",
      "profile": "ACME_LOCAL_PROF",
      "verify_function": {
        "state": "named",
        "name": "ORA12C_STRONG_VERIFY_FUNCTION"
      },
      "password_reuse_max": "3",
      "password_reuse_time": "10",
      "password_versions": ["11G", "12C"]
    },
    {
      "target": "appdb-alpha",
      "account": "ACME_BATCH_USER",
      "profile": "ACME_COMMON_PROF",
      "verify_function": { "state": "unknown" },
      "password_reuse_max": "5",
      "password_reuse_time": "30",
      "password_versions": ["11G", "12C"]
    }
  ]
}
```

The second account's profile was created in the root with `CONTAINER=ALL`, so
its verify function reads as the literal `FROM ROOT` from inside the PDB.

**Readings, never a verdict.** Nothing here predicts that a password will be
accepted. Only the byte count is binding. A verify function is arbitrary PL/SQL
that cannot be consulted (invariants 13 and 14), and a reuse history is hashed.
So `ORA-28003` and `ORA-28007` cannot be predicted before the statement is
issued, and the tool answers them by drawing again. The section says what the
run found out; `diagnostics[]` says what it could not check.

**A verify function has three states, not a nullable name.** `named`, `none` and
`unknown` are three answers. A missing name would merge the last two into the
one reading that misleads: "nothing will judge this password". §5's
`--preflight` rule applies: not knowing is not a finding. The run above shows
why: the account reported `unknown` was in fact guarded, and applying its staged
password was refused with `ORA-28003`.

**`unknown` is narrower than "a PDB".** On 26ai, a **common** profile read from
inside a PDB answers `FROM ROOT`. A local profile read in the same session
answers with its function's name. `DEFAULT`, which is common, answers `NULL`. So
the unreadable case is a user-created common profile seen from a PDB, and
treating every PDB as unknowable would refuse to report the ordinary case.

**`source` has two values.** `targets` means at least one database answered.
`policy` means none did, and the policy's declared length governed, which UC-1
§4 makes a legitimate fallback, not a failure. A run that asked nothing
(`--offline`) omits the section, because "we could not find out" and "we did not
look" are answers a report must never merge. Absence is the third value.

**It is present even when nothing answered**, as `install` is and `wallet` is
not. The section is evidence that the estate was consulted, and one that appeared
only when something was wrong could never be quoted as proof that nothing was.

**Every reading is kept.** A limit is a byte count *and* the character set it is
counted in, so 128 bytes of `WE8MSWIN1252` and 128 of `AL32UTF8` do not contain
each other: "stricter" is only a partial order. `max_password_bytes` at the top
is what a *generated* password was drawn against, which uses no character set.
`targets[]` carries every reading, because a *supplied* password must satisfy
each.

**`measured_as` is the codec, and `character_set` does not imply it.** An
unmapped character set falls back to `ascii` on purpose
(`driver/oracle/limits.py`). That refuses a non-ASCII password rather than
guessing its width, and a reader whose database refuses one should see the
reason here, not have to deduce it.

**The reuse resources are strings.** `UNLIMITED` is a word in a column a reader
expects numbers in, and the two resources interact: one of them `UNLIMITED`
beside a number is not the same regime as two numbers. They are reported, not
interpreted, because the run measured neither the interaction nor the hashed
history.

### `results[].changed` vs `results[].state`

These are separate on purpose:

- `state` is **what is true now** (`IN_SYNC`, `DRIFT`, `ROLLOVER_ACTIVE`, …);
- `changed` is **whether this run did anything**.

An idempotent re-run of `apply` reports `state: IN_SYNC, changed: false`. A
monitoring system watches `state`; a change-management system watches `changed`.
One field for both would break one of the two consumers.

`creds apply` shows the difference. It reaches `IN_SYNC` in two ways: by changing
the password, or by finding the database already had it. The second is
invariant 9 for this verb. `summary.ok` and `summary.changed` differ for the same
reason. `summary.unchanged` is the complement of `changed`, not of `ok`: it
answers "how much did this run leave alone?"

**`actions[]` carries the sequence, not just the outcome.** UC-1 §5 is a flow,
and an `apply` entry holds up to four steps in the order they ran: the
pre-flight `verify`, the `password_set`, the `verify` that confirmed it, and the
`vault_promote`. `applied` on each says whether the step *ran*, never whether it
succeeded. A `verify` with `applied: false` is a login the lockout guard
declined, and a `password_set` with `applied: false` is a password that was
already right. With one action per result, "we did not need to change it" and
"we changed it and could not confirm it" would be the same row.

**`results[].rollover` is emitted for every account `apply` acted on**, not only
for accounts with an open window. `active: false` beside a
`profile_rollover_time` of `"1"` is a different fact from `active: false` beside
`null`. The first says a window opened and was closed in the run
(`--strategy direct`); the second says no window was possible. With the
`rollover_finish` action, these make the regime each account ran under
recoverable from the document, so `--strategy` needed no new field.

**A promotion is reported on every account in the document it promoted**, with
the version it produced, because they shared one compare-and-set. Where the
database was changed and the document was *not* promoted, every account involved
carries a `warning` that says so. Applications read `current`, and until the
promotion lands they read a password that part of the estate no longer has. That
is UC-1 §8's highest-severity row. It is a per-result warning, not a run-level
diagnostic, so it survives any filter a consumer applies to `results[]`.

---

## 3. Enumerations

Enums are part of the contract. Adding a value is a minor version bump; removing
or renaming one is major.

<!-- checked-list: enum state -->
**`state`** — `IN_SYNC`, `DRIFT`, `PENDING_APPLY`, `ROLLOVER_ACTIVE`,
`ACCOUNT_MISSING`, `LOCKED`, `EXPIRED`, `UNVERIFIABLE`, `SKIPPED`, `ERROR`,
`VAULT_ONLY`, `DECLARED`, `RESET`

**`VAULT_ONLY` is what `creds generate --promote` reports**: the vault holds this
password, and no database has been asked. No other value would be true of that
result:

- `IN_SYNC` claims a match that nobody checked.
- `DRIFT` claims a comparison that never happened, and exits 3, so a successful
  adoption would exit non-zero.
- `PENDING_APPLY` sends `check` and `apply` looking for a `pending` that is not
  there.
- `UNVERIFIABLE` means "tried and could not", and `check` relies on that meaning.
- `SKIPPED` would be false, and emitting no `results[]` at all would leave the
  verb that writes the field applications read with nothing machine-readable to
  say about what it changed.

So the enum has a value of its own for it. A consumer that switches over every
`state` value had to handle it once.

**It is not `PENDING_APPLY` with the stage swapped.** `PENDING_APPLY` says a
rotation is in progress and something waits to be applied. `VAULT_ONLY` says no
rotation is in progress. `creds apply` still follows a `VAULT_ONLY`: it finds the
databases behind the vault and converges them. But a consumer that counts
rotations in progress must not count these, and `check` correctly finds no
`pending` here.

<!-- checked-list: enum action_kind -->
**`action_kind`** — `none`, `generate`, `vault_write_pending`, `vault_promote`,
`vault_rollback`, `password_set`, `rollover_start`, `rollover_finish`,
`account_unlock`, `account_lock`, `password_expire`, `attribute_set`, `verify`

The action list is a readable trace of the UC-1 §8 sequence. A completed rotation
of one account on one target reads:

```json
"actions": [
  { "kind": "generate",            "applied": true },
  { "kind": "vault_write_pending", "applied": true },
  { "kind": "password_set",        "applied": true },
  { "kind": "verify",              "applied": true },
  { "kind": "vault_promote",       "applied": true }
]
```

An interrupted rotation stops partway, and where it stopped says which recovery
in the UC-1 §8 table applies.

`attribute_set` is what UC-1 §5's other attributes report as, profile
assignment first. One kind covers several attributes on purpose: a new enum value
per attribute would mean a minor bump each time, on a field consumers branch on.
**The `detail` tells them apart**, for example `"profile ACME_LEGACY_PROF ->
ACME_APP_PROF"`, so every implementation writes one.

`account_unlock` is UC-1 §5's first opt-in attribute, and comes first in the
list because it happens first: an unlock is what makes the pre-flight login worth
trying. It is emitted whenever the policy declares the attribute, with
`applied: false` where the account was not locked. Otherwise a consumer would
have to read "not declared" from "not present", which is reading the policy out
of the results. `results[].changed` covers every change on the row, so an account
that was unlocked and needed no new password is `changed: true`, with a
`password_set` that did not apply.

**`error.category`** — `config`, `selection`, `connectivity`, `authentication`,
`authorization`, `capability`, `policy`, `vault`, `database`, `lock`, `internal`.
Categories are stable. `error.code` carries the vendor detail (`ORA-01017`), or a
tool code from the registry below (`SOPULI-20001`). Consumers branch on the
category and log the code.

**`install.*[].status`** — `installed`, `not_installed`, `not_implemented`. Three
values, not two, because the two failing values have different remedies: `pip`
fixes one, and nothing the operator installs fixes the other.

**`verification.method`** — `login`, `hash`, `both`, `none`.
`lockout_margin_hit` records the UC-1 §7 case where the tool *declined* to try a
login because the account was near its lockout threshold. That outcome is not a
failed verification, and must not be reported as drift.

### Diagnostic codes

`diagnostic.code` is optional. Where it is present, it comes from this registry.
A code is part of the contract, like an enum value: adding one is a minor bump,
and changing what one means is not allowed at all. The *message* around it is
not contract and may improve.

| Code | Meaning |
|---|---|
| `SOPULI-W001` | A store in this run is `locking: advisory-only`, so its lock record was written without compare-and-set. The run has no fence: two runs that start in the same second can both believe they hold the lock |
| `SOPULI-W002` | A lock was taken from its holder: automatically, because it was past its expiry and `locking.break_expired` allows that, or on purpose by `sopuli lock break`. The previous holder is fenced, so its next check fails, but it may have applied changes before then |
| `SOPULI-W003` | A `vaults:` entry names a backend this machine cannot serve. The config is valid and the install is incomplete (ADR-006, E4). What that means depends on the command: `config validate` warns and exits 0, `doctor` reports an `error` and exits 9 (E6), and any command that resolves the store to a client fails with `SOPULI-20001` |
| `SOPULI-W004` | A store in this run is `tls.verify: false`, so its certificate is not checked, and anything on the network path can read every secret that crosses it. The setting is under P3's safety ratchet, so no layer can weaken it further, but nothing in the run undoes it either (ADR-005) |
| `SOPULI-W005` | A store in this survey has no `list` capability, so `lock status` reported only the paths the configuration declares. A record at a path the file no longer names would not appear, in that store. Everything reported is accurate; the survey is narrower than it looks |
| `SOPULI-W006` | A `targets:` entry names a driver this machine cannot serve. Each command weighs it as it weighs `SOPULI-W003`. They are two codes on purpose: one code for "some backend is missing" would not tell a store the tool cannot reach from a database it cannot reach, and those are different outages. Emitted once per driver *type*, not once per target, because an estate generates targets by the dozen from one `target_sets:` entry |
| `SOPULI-W007` | The estate uses `auth: external`, and this machine has no auto-login wallet that this process can read. The connection will fail as an Oracle *login* error, which is the most misleading way for a file-permission problem to appear, so this says why in advance. It is a warning, not a verdict: the target's own reachability decides the run |
| `SOPULI-W008` | A wallet file in this run's `TNS_ADMIN` can be read by somebody other than its owner (P4). An auto-login wallet is a credential: whoever can read it can authenticate as the account it holds. `doctor` warns and never fails, for the reason P5 gives for over-granted accounts |
| `SOPULI-W009` | This machine's clock is further from a configured store's clock than the advisory lock tolerates. A lease's expiry is compared with the local clock, so a run on this host will take over locks that are still live, or refuse ones long dead, and the failure looks like a locking bug, not a clock problem. `doctor` warns and never fails: the condition is real, this run did not create it, and refusing to survey the estate would block the person who ran it |
| `SOPULI-W010` | A configured store answered and cannot serve this run: sealed, standing by, not initialised, or refusing the credential it was opened with. A store that could not be *reached* is different: it fails the run and gets no code. Here something answered, so the reader goes to the vault, not to the network |
| `SOPULI-W011` | Another run took over this run's lock while it was running, found at a fence check. This run stopped before its next change and promoted nothing, so the vault still serves what it did before. But whatever it had already applied to a database stands. The code exists because the exit code cannot say this: a fenced-out run exits 4, like a run whose targets failed. The second is repaired by running `apply` again, and the first must not be. `SOPULI-W002` is the other side of the same event. They are two codes because "I broke somebody's lock" and "my lock was broken" are opposite things to be paged about |
| `SOPULI-W012` | A rotation promoted a secret document and then read a different password back out of it (UC-1 §8 step 8). Every database took the new password and the vault acknowledged the promotion, so nothing needs undoing, and `apply` converges what is left. But until the vault serves what it accepted, an application that fetches `current` may get the old password. It has its own code for `SOPULI-W011`'s reason: the run exits 4, as a run with half its targets failed does, and the two need opposite responses. Here the *databases* are converged and the vault is not, so the reader looks at the store. Replication lag on a mount with read replicas is the usual cause |
| `SOPULI-W013` | An account's password is in its grace period: past `PASSWORD_LIFE_TIME`, inside the window `PASSWORD_GRACE_TIME` allows, and **still working** (UC-1 §6.4). It is on `results[].warnings[]` beside the state, not a state of its own, because `state` is one field and the account may be `IN_SYNC` or may have drifted. A value of its own would hide the answer the reader came for. It is read from `DBA_USERS.ACCOUNT_STATUS`, so it is reported even on a run with no login. It is not read from `ORA-28002`, which 26ai does not send |
| `SOPULI-W014` | A login **succeeded**, and the server attached a diagnostic to the connection without raising. A password in its grace period is the usual cause: the login works, and Oracle puts the notice on the connection. The verification passed. The message is carried verbatim with its vendor code. The code is *data* and is never matched against a list, because the same condition is `ORA-28098` or `ORA-28011` on one release, depending on the profile. It can appear beside `SOPULI-W013` for one account. Those are two sources, what `ACCOUNT_STATUS` says and what the server said on this login, and they are reported side by side, not deduplicated, because telling them apart would need the code list this refuses to keep |
| `SOPULI-W015` | `creds generate` could not read a target's password constraints, so the policy's declared length governed the draw (UC-1 §4 step 2). It is a **warning**, not an error, because UC-1 §4 makes the fallback legitimate: operators do stage a password for an estate that is down. The run may not stay quiet about it, because a password drawn against a policy alone and one drawn against a database that answered are different claims, and nothing in the password tells them apart. One code covers both cases, no target answered and some did, because the remedy is the same and the message names the targets. `--offline` emits nothing: the operator has said they know, and a warning that fires because a flag was passed teaches readers to filter it |
| `SOPULI-W016` | An account's profile names a password verify function, or the run could not establish whether it names one: a common profile read from inside a PDB answers `FROM ROOT` (UC-1 §4 step 2). **Reported and never acted on.** The function is arbitrary PL/SQL that cannot be consulted before the statement is issued (invariants 13 and 14), so this does not predict that the password will be refused, and `creds apply` draws again if it is. It says that something other than the policy will judge this password. The not-knowing case shares the code because the consequence is the same, and the message says which case it is. It must never report the unreadable case as "no verify function", which reads as a guarantee. One per target and profile, because that is where the function lives: forty accounts on one profile are one fact |
| `SOPULI-W017` | An account's profile restricts password reuse, and the run was given a password instead of drawing one. **Only under `--from-stdin`**, so it is not part of `SOPULI-W016`. A fresh random password cannot collide with a hashed history, so a reuse warning on an ordinary draw would fire on every run and mean nothing. A supplied password is whatever an external system dictated, and that can be the one it had last year. The two resource values are carried and not interpreted: they interact, and the run measured neither the interaction nor the history |
| `SOPULI-W018` | One of `02-oracle-privileges.md` §4's account guardrails could not run against a target, because the run could not read the fact it checks. The run **went ahead** and applied the other checks. In this build it is always check 3, the password file: `V$PWFILE_USERS` is outside that document's default grant set on purpose, so the code appears on a correctly installed estate, and the optional grant removes it. Without the code, nothing in the exit code, the states or `results[].overridden` would say that one check contributed nothing. **Not a refusal**, because the estate that cannot answer is the correctly installed one, and refusing would change nothing anywhere. **One per target and check**, because a missing grant is a property of the database. **Printed as well as serialised**, because a warning nobody sees in the default output has not been reported |
| `SOPULI-W019` | A lock path was created without `cas_required`, because this run's store credential may not write path metadata. The run's own lock was still taken with compare-and-set and its fence held, so the result is correct. What is missing is the store refusing a write without compare-and-set from **anybody else**, including an operator with a vault CLI. It has a code because the run exits 0 and the condition is a property of the path, still there on the next run, which a reader goes and fixes in the vault. **One per path**, not per store, unlike `SOPULI-W001`: advisory locking is one fact however many locks it covers, and this names a path to repair. **Only the run that creates the path emits it.** Every later run finds the metadata with `cas_required` unset and is refused with exit 5 |
| `SOPULI-W020` | The document given to `creds apply --repair` is old enough to mention. **A warning, never a gate.** A threshold that refused would be wrong for somebody, and the run it stopped would have been safe: the set can only narrow (invariant 5), and a pair already repaired costs one login and reports `changed: false`. So a stale document wastes work and does no harm. It **names the age**, not the threshold, because a reader decides from "eleven days" whether that is still the estate they are looking at. It has a code because the run exits 0 having done less than the operator may have expected, and nothing else in the document says the narrowing came from something written last week. **Printed as well as serialised**: the emitter writes the document or the text, never both, and the person who typed the flag is who this is for |
| `SOPULI-W021` | The database would not say when an account's password was last set, so `results[].password_age_days` is absent and `creds status` prints `-` under `DB_PW_CHANGED`. **The message says why**, because the two causes need different responses. Either the release has no `DBA_USERS.PASSWORD_CHANGE_DATE` (18c, 11.2) and the service account lacks `SELECT ON SYS.USER$` to read `PTIME` instead, which a grant fixes; or a value could not be read, which is worth investigating. It exists because a consumer cannot see a dash: a documented field that vanishes for some targets, with nothing saying why, is a hole in the contract. **One per result, on `results[].warnings[]`**, beside the field it explains, unlike `SOPULI-W018`'s grouping per target: a consumer reading one result should not have to join it to a run-level array. The text output groups it per target. `creds check` and `creds status` emit it. It is informational: nothing depends on the database's date ([Q9](../decisions/log.md#q9)) |
| `SOPULI-W022` | A target's admin credential was read from an environment variable. P2 lists `env` last in its bootstrap order and **supports** it, for an estate with no other way in, so this is a flag and never a refusal. `01-configuration.md` §3a says the source "stays flagged wherever it is reported". The run connects, succeeds and exits 0, and nothing else in the document says *how* the tool got the credential: without the code, a run that used a wallet and one that used a variable a CI job exported look the same. **The message names the variable**, from `Resolved.source`, because the reader next looks at where it is set. **One per target per run**, deduplicated on code and target: one run may resolve a target twice (`creds apply --strategy` pre-flights and then applies), and the configuration did not change in between. It is keyed on `admin.LOW_ASSURANCE`, not on the method name, so another low-assurance source would be flagged with no change at the reporting sites. **Every command that connects emits it**, because each one resolves its admin credential through `cli._admin_credential`. **Only `doctor` prints it.** P2 asks for the flag in output, so something must print it. But it is a property of the configuration, the same on every run until the file changes, and a line under every rotation would be a warning readers learn to filter. `doctor` is the command that reports on the setup, and `diagnostics[]` is where anything that alerts reads it |
| `SOPULI-W023` | `account list` had no reset journal to read, so its `RESET_AT` column is empty for every row and `results[].reset_at` is absent. The configuration declares no `reset_records:` block, which is **a documented mode, not a fault**: UC-2 §3.1 keeps the journal optional, because the seen (`manual`) path may have no store at all. It is `SOPULI-W021`'s rule applied to the other date column: a documented column that vanishes with nothing saying why is a hole in the contract. **One per run, not one per result.** That is the difference from `SOPULI-W021`: a missing journal is a property of the configuration and the same on every row, while whether the database reports a password change date can differ between two accounts on one target. A journal that has no record for this account yet is not a finding, and gets no code |
| `SOPULI-W024` | `account reset-password` wrote no record of a reset, because the configuration declares no `reset_records:` block. The run document and the database are the whole record of it, and **no advisory lock was taken on the account either**. Those two facts have one cause (UC-2 §3.3), and an operator told only the first would not learn that two concurrent resets are not serialised. **Raised at plan time**, before the password changes, so an operator who did not mean to run this way can still stop. A **documented mode, not a fault**, for `SOPULI-W023`'s reason. It is a separate code because that one explains an empty column in a listing, and this one says a change went unrecorded |
| `SOPULI-W025` | A reset succeeded, and its record could not be written. **A warning on a successful run**, never a rollback and never a non-zero exit: the password has already changed and the person still needs it, so failing would report a false negative about the part that mattered (UC-2 §3.4). It is separate from `SOPULI-W024` because the next step differs. An absent journal is a configuration somebody chose. Here a store answered: a revoked token, a policy that grants read and not write, or a mount that is not there. The store's own message comes **last** in the text, so its punctuation ends the sentence |
| `SOPULI-W026` | A password was delivered, and the notification saying so could not be sent. The account **and the target** are named, because a reset can notify once per target, and two failures would otherwise read the same. A warning on a successful run, for `SOPULI-W025`'s reason and more so: the notification carries nothing anybody needs (UC-2 §6.1 limits it to "a password is ready"), so all that is lost is that somebody must be told another way. The webhook URL is never in the message. It is itself a credential ([C9](../decisions/log.md#c9)), and `httpx` puts it in the text of its own errors, so the message carries the exception's class name instead |
| `SOPULI-W027` | A secret document was not promoted, because the run was narrowed past pairs the promotion needs (UC-1 §5's *promotion gate*): the same credential on a target outside the run, or another account in the document with its own `pending`. The databases in scope **were** changed, `pending` stays, and the run exits 4. It has its own code for `SOPULI-W011`'s reason. A run whose targets failed also exits 4, and the same narrowed run repairs it. This one is finished only by a **wider** run that covers the pairs the message names; repeating the narrow run withholds the promotion again. It is also raised under `--dry-run`, where it says what the run would withhold |
| `SOPULI-W028` | A rollback (`creds apply --source previous`) reached the statement on an account whose profile restricts password reuse, or, under `--preflight`, is planned against one. One entry per target and profile, naming `PASSWORD_REUSE_MAX` and `PASSWORD_REUSE_TIME` as the database spells them. `previous` is usually a password the account held one change ago, so `ORA-28007` is likely. Where one limit is `UNLIMITED` and the other a number, a password the account has held is never accepted again. Reported, not interpreted, as UC-1 §4 does with the same two values, and raised whichever way the statement went. Under `--preflight` the survey raises it before any statement, from the profile it already reads, which is the only way a `--dry-run` carries it. The run then does not repeat it for that target and profile. It is not raised in advance where the run would first move the account to another profile, because the new profile's limits are not read; the run's own reading covers that case. It has its own code, not a wider `SOPULI-W017`, because that code means a *supplied* password, and a consumer branching on it would be told something false. On such a profile the way back is a rollover window (UC-1 §6.3), not a rollback |
| `SOPULI-W029` | The server refused a password the run applied, with `ORA-28003` or `ORA-28007`, so the run drew another and staged it, to be applied again to every target of that account (UC-1 §6.4). One entry per draw, naming the account, the version staged and the server's message. It says a draw happened, not that the new password was accepted: the result rows say whether the re-apply succeeded, and `results[].redraws` counts the draws |
| `SOPULI-W030` | The server refused a password the run applied, and the run was not allowed to draw another (UC-1 §6.4). The reason is one of these: nothing shows this tool drew the password, the redraw limit was reached, the account has no policy to draw from, or the run is a rollback. The message names which. The target that refused keeps the password it had. Another target of the same account may already hold the refused value, and the result rows say which |

`sopuli/diagnostics.py` is the registry. `tests/test_lock_view.py` asserts that
nothing emits a code the registry does not describe.

**How codes are allocated is open** (J3, open: #641). The code format and the
fact that these warnings have codes are settled. Whether every warning gets one
is not: the config layer's findings (`01-configuration.md` §10) have none. Nor
is the scheme for numbering across categories. Each code so far was allocated by
hand when something needed it.

**For `doctor`, a finding gets a code only for what the exit code cannot say.**
An unreachable store fails the run, so anything watching the exit code already
knows, and the `vaults[]` entry names the store and the reason, as an unreachable
target's `targets[]` entry does. A store that answered and cannot serve, or a
clock outside the lock's tolerance, leaves the run exiting 0 with something
still wrong, and a diagnostic is for that. This is a rule for one command, not an
answer to J3.

**`SOPULI-W002` has two emitters and one meaning.** It means "a lock was taken
from its holder". `lock break` adds a person deciding it, where
`locking.break_expired` is a config key deciding it. The table's wording covers
both, and the wording is not contract. A second code would tell a consumer that
alerts on "somebody's lock was taken" that there were now two things to watch.

### Error codes

`error.code` carries the vendor's code where there is one: `ORA-01017` comes from
the server, and the tool passes it through. Where the condition is the tool's
own, the code is a `SOPULI-` code from this registry, under the same rule as the
diagnostic codes above.

| Code | Category | Exit | Meaning |
|---|---|---|---|
| `SOPULI-20001` | `config` | 9 | A `vaults:` entry names a backend whose client is not installed. The message names the store, its `type`, and the extra that supplies it (ADR-006, `01-configuration.md` §3a) |
| `SOPULI-20002` | `config` | 9 | A `targets:` entry names a driver whose client is not installed. The same shape as `SOPULI-20001`, for the same reason (ADR-006 E1, E5): `python-oracledb` is `sopuli-dba[oracle]`, and a driver that is declared and absent is fixed on this machine by the person reading the message |
| `SOPULI-20003` | `config` | 9 | `delivery.notify.method` names a channel whose client is not installed. The same shape again (ADR-006 E5, E7): `webhook` posts with `httpx` from `sopuli-dba[notify]`. Only a run that has something to send reaches it. `config validate` reports the same condition as a warning at load, which is where an operator meets it first |

**The category is `config`, not `capability`** (ADR-006, E5). `capability` names
what a *target* cannot do: a property of the database at the other end, which
nothing the operator does locally changes, and which `target_capability` reports
per target. A missing client is fixed on this machine, by the person reading the
message, with the command in the message. So it belongs with an unreadable config
file and an unresolvable name, and exit 9 already means "fix your configuration,
not your command line" (`00-principles.md` P5). No enum value is added, so a
consumer that already branches on `config` handles it without a change.

---

## 4. Redaction

One rule, enforced in one place: **redaction happens at the serialiser, not at
each call site.** Every secret value the process holds is wrapped in a type whose
serialisation is the literal string `"***"`, and whose `__str__` and `__repr__`
are the same. No call site can emit a secret by forgetting a helper.

A password, or a credential that retrieves one, leaves the process only at the
sites `CLAUDE.md` invariant 2 lists:

1. the vault write;
2. the driver call;
3. `policy sample --reveal`;
4. `account reset-password` on the seen (`manual`) path;
5. the wrapping token that an unseen (`vault_wrapped`) delivery returns.

The tool also presents credentials to the services it calls: the vault login,
the vault token on the wire, and a webhook URL ([C9](../decisions/log.md#c9)).
Each is a `Secret`, revealed only where it is sent. That is a separate class, not
an exception to invariant 2: a credential that never reached the wire would
authenticate nothing.

`tests/test_reveal_sites.py` parses `src/` and fails on a `.reveal()` call in a
module that holds none of these sites, of either class. It is a tripwire, not a
proof: a second call in a permitted module, or a call spelled another way,
passes it.

These consequences show in the schema:

- `secret_ref` objects address a secret (`vault`, `path`, `field`, `version`,
  `stage`) and have **no value property at all**. There is nowhere to put a
  password. `version` is an integer, and `stage` is the closed lower-case enum
  `current` / `pending` / `previous` ([C14](../decisions/log.md#c14),
  `01-configuration.md` §7). The config layer refuses anything else before a
  document is emitted. `vault` is required here, although a written ref may omit
  the prefix: this object is emitted after resolution, when the store is known,
  and a plan that named a secret without its store would make the reader work
  out precedence again.
- A `sample` object has no value property either, for the same reason.
- `error.message` and `diagnostic.message` are documented as redacted. Driver
  exceptions pass through a scrubber before they reach either.
- `password.applied` events carry the vault version, never the value.
- `results[].handover` carries the wrapping token's *accessor*, never the token.

Sites 1 and 2 are where a password must go. Sites 3 to 5 are exceptions, and the
sections below say what keeps each one narrow.

### `policy sample --reveal`

`policy sample --reveal` prints generated passwords on purpose. It is allowed
because **a sample is not a credential**: nothing authenticates with it, it is
never stored, and it protects nothing. That property is what makes `pwgen` safe
and a vault write dangerous.

Structure, not care, stops it from becoming a leak:

| | |
|---|---|
| it is opt-in | the default output reports properties (length, bytes, class counts) and no value |
| it is text-only | `--reveal` with `--output json` is **refused**, not quietly downgraded |
| JSON cannot carry it | a `sample` object has no value property, so the section could not hold one even if asked |
| it is one call site | its one `reveal()` is in `sopuli/output/policy_view.py` |

The output says that the samples must not be used. The real hazard is not the
printing. It is somebody who likes sample 2 pasting it into an `ALTER USER` by
hand, and then a value from a scrollback is a live credential.

The release gate from UC-1 §11 tests the rest: run everything, search every
artefact for the generated password, and release only with zero hits.
`policy sample --reveal` is excluded by name, because its output is *supposed*
to contain a password, as the seen reset's is (below). In exchange the gate
asserts the narrower property above: no sample value in any JSON document,
`--reveal` or not. See `04-testing.md` §6.

### UC-2's seen reset

`account reset-password` on the `manual` delivery path prints a working password
once, under five structural guards.

**Nothing in this contract can carry the value.** `results[]` has no property a
password could occupy, and the verb refuses `--output json` and `--output jsonl`.
Those are one guard checked twice. The second check is the one that still holds
if somebody adds an output mode.

**Its justification is weaker than the sample's.** A sample is no credential at
all. This password *is* one, and somebody can log in with it. What allows it is
that the exposure is **deliberate, witnessed and time-limited**: the operator
chose the seen path and answered a prompt, and the password is expired when it is
set, so the owner's first logon must change it.

Because the justification is weaker, the structure is **stricter**: the sample's
four guards, plus a fifth with no counterpart there.

| | |
|---|---|
| it is opt-in | not the default; `delivery.method: manual` selects it, and an estate that asks for nothing gets the unseen path |
| it is text-only | refused with `--output json` **and** `--output jsonl` |
| JSON cannot carry it | no property of a `result` can hold a password, whatever `--output` says |
| it is one call site | one `reveal()`, in the seen path's own view, reachable only when the method is `manual` |
| **stdout must be a terminal** | the guard `--reveal` lacks, and the one the argument rests on. A value redirected to a file or captured in a CI log outlives the single logon it is good for: other people read a log later, and expiry does not remove it from the log |

Two more limits are not redaction rules, so `CLAUDE.md` invariant 2 and UC-2 §6
hold them. The run is confirmed every time, and `--confirm` does **not** answer
the prompt. The method requires `force_expire: true`.

**The release gate treats it like `policy sample --reveal`.** It is excluded by
name from the search, because its output is supposed to contain a password. In
exchange it must satisfy the narrower assertion: no password in any JSON
document, any jsonl event or any log sink, whatever the delivery method.

### The wrapping token from an unseen delivery

On the `vault_wrapped` path the password goes to Vault and to nobody else. What
comes back is a wrapping token: a single-use bearer credential that retrieves the
password once, and expires. It holds no password, but it retrieves one, so the
tool keeps it in a `Secret`. The tool has no other channel to hand it over on,
and UC-2 §6.1 bars it from the notify channel, so it is printed. UC-2 §6.6 has
the full argument.

| | |
|---|---|
| no document can carry it | the run document has no property for it. `results[].handover` carries the token's *accessor*, which names the hand-over and cannot perform it, and its expiry. The `password.delivered` event carries the same `handover` object, and event schema 1.7 closes that payload |
| it never goes to stdout under a machine format | under `--output json` or `jsonl` it is written to stderr, because stdout carries the document. `vault_wrapped` is not refused with `--output json`, unlike `manual`: the document is what makes a scheduled reset auditable |
| it is one call site | its one `reveal()` is in `sopuli/output/delivery_view.py`. `delivery/vault_wrapped.py` holds the vault write that creates it, which is site 1 |

**No terminal is required**, unlike the seen path. A handover script reads the
token from a pipe, and requiring a terminal would leave an estate no way to
deliver unattended except the path that shows a DBA a password. The cost is
stated: a redirect to a file outlives the token. The object is what makes the
trade different: a token that expires within minutes and works once, where a
second use is detectable, against a password that works until somebody's first
logon.

---

## 5. Streaming events

`--output jsonl` writes one event per line as the run happens. This is
`creds check` on a drifted account against the tier-1 stack, pasted from the run
and trimmed only where `…` says so:

```jsonl
{"schema_version":"1.3","event":"run.started","seq":0,"ts":"2026-09-25T17:48:29.670694Z","correlation_id":"9352c606-…","data":{"command":"creds.check","dry_run":false}}
{"schema_version":"1.3","event":"plan.resolved","seq":1,"ts":"2026-09-25T17:48:29.670851Z","correlation_id":"9352c606-…","data":{"units":[{"account":"acme_app_user","target":"free-pdb","intent":["verify"],…}],"blast_radius":{…}}}
{"schema_version":"1.3","event":"target.started","seq":2,"ts":"2026-09-25T17:48:30.167605Z","correlation_id":"9352c606-…","target":"free-pdb"}
{"schema_version":"1.3","event":"diagnostic","seq":3,"ts":"2026-09-25T17:48:31.447496Z","correlation_id":"9352c606-…","target":"free-pdb","level":"warning","message":"free-pdb: the admin credential came from the environment variable SOPULI_DB_ADMIN_PASSWORD, which P2 supports and flags as low assurance","data":{"code":"SOPULI-W022"}}
{"schema_version":"1.3","event":"target.finished","seq":4,"ts":"2026-09-25T17:48:31.447583Z","correlation_id":"9352c606-…","account":"acme_app_user","target":"free-pdb","data":{"account":"acme_app_user","target":"free-pdb","state":"DRIFT","changed":false,…,"duration_ms":1087}}
{"schema_version":"1.3","event":"run.finished","seq":5,"ts":"2026-09-25T17:48:31.448006Z","correlation_id":"9352c606-…","data":{"summary":{"total":1,"ok":0,"changed":0,"failed":0,"unchanged":1,"drift":1,"unverifiable":0,"by_state":{"DRIFT":1}},"exit_code":3}}
```

The samples in this section came from runs against earlier event schema
versions, as their `schema_version` shows. Later minor versions only add to
them.

`seq` increases within a run, so a consumer can detect truncation. That matters,
because the failure that counts is the process dying in the middle of a run. A
stream that ends without `run.finished` means the run did not complete, and the
last `seq` says where it stopped. **Every line is flushed as it is written.** A
line held in a pipe buffer until exit would make this `json` with worse syntax.

Payloads reuse shapes; they do not redefine them. `target.finished.data` is a
`result` object, the same entry `results[]` carries.
`run.finished.data` carries `summary` and `exit_code`, and `plan.resolved.data`
is a `plan`. The event schema requires those three shapes.

**The emitter writes two events itself**, so the next verb to stream cannot
forget them:

- **`run.started` always opens the stream**, ahead of whichever event comes
  first. A run that fails before any target, such as one whose config file is
  missing (exit 9), is `run.started` then `run.finished`. That is
  [J7](../decisions/log.md#j7) for jsonl: the run began, so it has a stream, and
  the stream ends.
- **`run.finished` is written by the same call that writes the `json` document**,
  on every way out of a run: success, a failure that escaped the verb, an abort.
  When the run failed as a whole, it carries `error` beside `summary` and
  `exit_code`, because the stream has nowhere else to say why.

**`diagnostic` events stream what `diagnostics[]` holds**, each one ahead of the
next event, with its code in `data.code`. Code that makes a diagnostic only
appends it to the document. Before each event, the emitter sends whatever is new.
So a diagnostic arrives with the *next* event, not the moment it is made. Above,
`SOPULI-W022` is made while the target is being connected to, and is sent just
before that target's `target.finished`.

`creds check` streams **per target**, not per account. The accounts on one
target share one connection and finish together, so their `target.finished`
events arrive together when that connection is done.

### `creds apply`

A staged password applied and promoted against the tier-1 stack, pasted from the
run and trimmed only where `…` says so:

```jsonl
{"schema_version":"1.4","event":"run.started","seq":0,"ts":"2026-09-26T12:55:57.739823Z","correlation_id":"be07e5d1-…","data":{"command":"creds.apply","dry_run":false}}
{"schema_version":"1.4","event":"plan.resolved","seq":1,"ts":"2026-09-26T12:55:57.739965Z","correlation_id":"be07e5d1-…","data":{"units":[{"account":"acme_app_user","target":"free-pdb","intent":["verify","password_set","vault_promote"],…}],"blast_radius":{…}}}
{"schema_version":"1.4","event":"lock.acquired","seq":2,"ts":"2026-09-26T12:55:58.305433Z","correlation_id":"be07e5d1-…","data":{"vault":"vault-dev","path":"acme/dev/acme","fence":13,"acquired_at":"2026-09-26T12:55:58.294164Z","expires_at":"2026-09-26T13:10:58.294164Z","released":false}}
{"schema_version":"1.4","event":"vault.read","seq":3,"ts":"2026-09-26T12:55:58.307418Z","correlation_id":"be07e5d1-…","data":{"vault":"vault-dev","path":"acme/dev/acme","version":3}}
{"schema_version":"1.4","event":"target.started","seq":4,"ts":"2026-09-26T12:55:58.307538Z","correlation_id":"be07e5d1-…","target":"free-pdb"}
{"schema_version":"1.4","event":"diagnostic","seq":5,"ts":"2026-09-26T12:55:59.661498Z","correlation_id":"be07e5d1-…","target":"free-pdb","level":"warning","message":"free-pdb: the admin credential came from the environment variable SOPULI_DB_ADMIN_PASSWORD, which P2 supports and flags as low assurance","data":{"code":"SOPULI-W022"}}
{"schema_version":"1.4","event":"password.applied","seq":6,"ts":"2026-09-26T12:55:59.661586Z","correlation_id":"be07e5d1-…","account":"acme_app_user","target":"free-pdb","data":{"version":3,"outcome":"IN_SYNC"}}
{"schema_version":"1.4","event":"verification.done","seq":7,"ts":"2026-09-26T12:55:59.661692Z","correlation_id":"be07e5d1-…","account":"acme_app_user","target":"free-pdb","data":{"method":"login","result":"pass",…}}
{"schema_version":"1.4","event":"vault.promote","seq":8,"ts":"2026-09-26T12:55:59.669352Z","correlation_id":"be07e5d1-…","data":{"vault":"vault-dev","path":"acme/dev/acme","promoted_to":4}}
{"schema_version":"1.4","event":"lock.released","seq":9,"ts":"2026-09-26T12:55:59.671666Z","correlation_id":"be07e5d1-…","data":{"vault":"vault-dev","path":"acme/dev/acme","fence":13,"acquired_at":"2026-09-26T12:55:58.294164Z","expires_at":"2026-09-26T13:10:58.294164Z","released":true}}
{"schema_version":"1.4","event":"target.finished","seq":10,"ts":"2026-09-26T12:55:59.671771Z","correlation_id":"be07e5d1-…","account":"acme_app_user","target":"free-pdb","data":{"account":"acme_app_user","target":"free-pdb","state":"IN_SYNC","changed":true,"secret":{"vault":"vault-dev","path":"acme/dev/acme","field":"acme_app_user","version":4,"stage":"current"},"actions":[…],"verification":{…},"rollover":{…},"duration_ms":1159}}
{"schema_version":"1.4","event":"run.finished","seq":11,"ts":"2026-09-26T12:55:59.672032Z","correlation_id":"be07e5d1-…","data":{"summary":{"total":1,"ok":1,"changed":1,"failed":0,"unchanged":0,"unverifiable":0,"by_state":{"IN_SYNC":1}},"exit_code":0}}
```

Read from top to bottom, this is UC-1 §3's order as it happened: the lock, the
document read under it (`version` 3, which is what was applied), the target, the
database changed and verified, *then* the promotion to version 4, then the
release.

**`target.finished` arrives after the promotion, not as each target finishes.**
That is where `apply`'s stream differs from `check`'s. `target.finished.data`
*is* the `results[]` entry, and an apply row is not final until its document's
promotion is decided: `promoted_to` and the `vault_promote` action are written
on every account the promotion covered, and a redraw (UC-1 §6.4) can replace a
row after its target is done. Sending the row early would mean either a row that
differs from the document, or a second event that corrects the first. These
events carry the progress per target:

- **`password.applied`**, once per account and target whose `ALTER USER` was
  issued, with the document version the value was read at and the account's
  state, and nothing else. Event schema 1.4 closes the payload. This includes an
  account whose re-read or verification failed *after* the statement: its row is
  `ERROR` **and** `changed: true`, because the database was changed. A re-run
  that changes nothing sends no `password.applied` at all, only
  `verification.done`: invariant 9, visible in the stream.
- **`verification.done`**, with the result's own `verification` object.
- **`vault.read`**, once per document, with its version. `null` is a path with
  nothing at it. **`vault.write`** and **`password.generated`** appear only on a
  redraw, naming the path and the stage, never the value.
- **`vault.promote`**, once per document **whose promotion was attempted**, with
  the version it produced, or `null` and an `error` when the vault refused the
  write. A document held back because a target did not confirm gets no event,
  and the absence is the point. `password.applied` lines with no `vault.promote`
  after them are the state invariant 7 describes: database changed, vault not
  promoted. A stream cut short by a crash between the two reads the same way.
  This verb's stream exists for that case.

**A dry run streams its reads and nothing else**: `run.started`,
`plan.resolved`, one `vault.read` per document, and `run.finished`. It takes no
lock and connects to no target.

**A lock somebody else holds** gives `lock.denied`, then `run.finished` with exit
7 and the error. This is from the same stack, with a held record planted as
`local-testing.md` §10 does:

```jsonl
{"schema_version":"1.4","event":"lock.denied","seq":2,"ts":"2026-09-26T12:56:19.697278Z","correlation_id":"aacd2f9f-…","data":{"vault":"vault-dev","path":"acme/dev/acme","reason":"held","holder":{"host":"beta.example.com","pid":1234,"os_user":"someone-else","correlation_id":"11111111-2222-3333-4444-555555555555","command":"creds rotate"},"acquired_at":"2026-09-26T12:00:00Z","expires_at":"2026-09-26T23:59:00Z","expired":false}}
{"schema_version":"1.4","event":"run.finished","seq":3,"ts":"2026-09-26T12:56:19.697391Z","correlation_id":"aacd2f9f-…","data":{"summary":{"total":0,"ok":0,"changed":0,"failed":0},"exit_code":7,"error":{"category":"lock","message":"vault-dev:acme/dev/acme is locked by someone-else@beta.example.com pid 1234 running creds rotate","hint":"wait for it to finish, or coordinate with whoever is running it"}}}
```

**The lock manager emits the lock events itself**, because only the manager sees
a partial acquisition. Two locks taken and given back before a third is denied
are in `lock.held[]` on exit 7. A stream that reported them from outside the
manager would put them after the denial that caused their release. **A release
that failed sends no `lock.released`**: the document says `released: false`, and
an event that said otherwise would contradict it.

### `creds rotate`

`rotate` streams `apply`'s events with a vault phase in front of them. Against
the tier-1 stack, with `--confirm`, trimmed only where `…` says so:

```jsonl
{"schema_version":"1.5","event":"run.started","seq":0,"ts":"2026-09-26T14:10:11.974415Z","correlation_id":"0306dc38-…","data":{"command":"creds.rotate","dry_run":false}}
{"schema_version":"1.5","event":"plan.resolved","seq":1,"ts":"2026-09-26T14:10:11.974569Z","correlation_id":"0306dc38-…","data":{"units":[{"account":"acme_app_user","target":"free-pdb","intent":["generate","vault_write_pending","verify","password_set","vault_promote"],…}],"blast_radius":{…}}}
{"schema_version":"1.5","event":"lock.acquired","seq":2,"ts":"2026-09-26T14:10:12.493418Z","correlation_id":"0306dc38-…","data":{"vault":"vault-dev","path":"acme/dev/acme","fence":17,"acquired_at":"2026-09-26T14:10:12.487821Z","expires_at":"2026-09-26T14:25:12.487821Z","released":false}}
{"schema_version":"1.5","event":"vault.read","seq":3,"ts":"2026-09-26T14:10:12.495419Z","correlation_id":"0306dc38-…","data":{"vault":"vault-dev","path":"acme/dev/acme","version":4}}
{"schema_version":"1.5","event":"diagnostic","seq":4,"ts":"2026-09-26T14:10:13.298561Z","correlation_id":"0306dc38-…","target":"free-pdb","level":"warning","message":"free-pdb: the admin credential came from the environment variable …","data":{"code":"SOPULI-W022"}}
{"schema_version":"1.5","event":"vault.read","seq":5,"ts":"2026-09-26T14:10:13.298639Z","correlation_id":"0306dc38-…","data":{"vault":"vault-dev","path":"acme/dev/acme","version":4}}
{"schema_version":"1.5","event":"password.generated","seq":6,"ts":"2026-09-26T14:10:13.298701Z","correlation_id":"0306dc38-…","account":"acme_app_user","data":{"vault":"vault-dev","path":"acme/dev/acme","stage":"pending"}}
{"schema_version":"1.5","event":"vault.write","seq":7,"ts":"2026-09-26T14:10:13.301380Z","correlation_id":"0306dc38-…","data":{"vault":"vault-dev","path":"acme/dev/acme","version":5,"stage":"pending"}}
{"schema_version":"1.5","event":"vault.read","seq":8,"ts":"2026-09-26T14:10:13.303210Z","correlation_id":"0306dc38-…","data":{"vault":"vault-dev","path":"acme/dev/acme","version":5}}
{"schema_version":"1.5","event":"target.started","seq":9,"ts":"2026-09-26T14:10:13.303317Z","correlation_id":"0306dc38-…","target":"free-pdb"}
{"schema_version":"1.5","event":"password.applied","seq":10,"ts":"2026-09-26T14:10:14.554989Z","correlation_id":"0306dc38-…","account":"acme_app_user","target":"free-pdb","data":{"version":5,"outcome":"IN_SYNC"}}
{"schema_version":"1.5","event":"verification.done","seq":11,"ts":"2026-09-26T14:10:14.555063Z","correlation_id":"0306dc38-…","account":"acme_app_user","target":"free-pdb","data":{"method":"login","result":"pass",…}}
{"schema_version":"1.5","event":"vault.promote","seq":12,"ts":"2026-09-26T14:10:14.562842Z","correlation_id":"0306dc38-…","data":{"vault":"vault-dev","path":"acme/dev/acme","promoted_to":6}}
{"schema_version":"1.5","event":"vault.read","seq":13,"ts":"2026-09-26T14:10:14.564655Z","correlation_id":"0306dc38-…","data":{"vault":"vault-dev","path":"acme/dev/acme","version":6}}
{"schema_version":"1.5","event":"lock.released","seq":14,"ts":"2026-09-26T14:10:14.567062Z","correlation_id":"0306dc38-…","data":{"vault":"vault-dev","path":"acme/dev/acme","fence":17,"acquired_at":"2026-09-26T14:10:12.487821Z","expires_at":"2026-09-26T14:25:12.487821Z","released":true}}
{"schema_version":"1.5","event":"target.finished","seq":15,"ts":"2026-09-26T14:10:14.567175Z","correlation_id":"0306dc38-…","account":"acme_app_user","target":"free-pdb","data":{"account":"acme_app_user","target":"free-pdb","state":"PENDING_APPLY","changed":true,"secret":{"vault":"vault-dev","path":"acme/dev/acme","stage":"pending","field":"acme_app_user","version":5},"actions":[{"kind":"vault_write_pending","applied":true,"detail":"staged v5"}]}}
{"schema_version":"1.5","event":"target.finished","seq":16,"ts":"2026-09-26T14:10:14.567274Z","correlation_id":"0306dc38-…","account":"acme_app_user","target":"free-pdb","data":{"account":"acme_app_user","target":"free-pdb","state":"IN_SYNC","changed":true,"secret":{"vault":"vault-dev","path":"acme/dev/acme","field":"acme_app_user","version":6,"stage":"current"},"actions":[…],"verification":{…},"rollover":{…},"duration_ms":1204}}
{"schema_version":"1.5","event":"run.finished","seq":17,"ts":"2026-09-26T14:10:14.567540Z","correlation_id":"0306dc38-…","data":{"summary":{"total":1,"ok":1,"changed":1,"failed":0,"unchanged":0,"unverifiable":0,"by_state":{"IN_SYNC":1}},"exit_code":0}}
```

**The vault phase is per document, and comes first.** Staging is one
compare-and-set per secret path, however many targets share it. So its events, a
`vault.read`, a `password.generated` per account drawn, and a `vault.write`, name
a `path` and no `target`, and all of them come before the first
`target.started`. That is UC-1 §8's own order: stage everything, *then* touch a
database. Interleaving the two phases per target would put a database event
between two vault writes that happened one after the other.

- **`vault.read` appears three times per document**, and each is a real read:
  under the lock at step 3, which `--max-age-days` is answered from; just before
  the staging write, whose version is the compare-and-set; and after the
  promotion, which is step 8's read-back. `rotate` has that last read and
  `apply` does not.
- **The version applied is the version staged**: `vault.write` says 5,
  `password.applied` says 5, and the promotion produced 6.
- **A staging write the vault refused is a `vault.write` with `version: null`
  and the store's `error`**, not a missing event. It is a finding for that
  document, and the run continues to its refusal. Nothing reaches a database
  after one, so there is no `target.started`, and the staging rows still arrive
  as `target.finished`.
- **The rows come last, in `results[]` order**: first the staging rows
  (`PENDING_APPLY`, one per account and target), then the applied ones. `apply`'s
  reason for waiting applies unchanged.
- **`--finish-rollover` has no event of its own.** Closing a window is reported
  on the row, and no event in the enum names it.

**`confirmation.required` is sent only when somebody is actually asked**, with
the prompt they were shown in `data.prompt`. So a stream that stops after it is a
run waiting for a person, which a consumer can tell from a hang. `--confirm`
answers in advance, so nothing waits and nothing is sent. A prompt answered with
end-of-file, from the same stack:

```jsonl
{"schema_version":"1.5","event":"confirmation.required","seq":2,"ts":"2026-09-26T14:10:18.252939Z","correlation_id":"b60184d7-9d90-4e8a-ad31-c3d496eefb67","data":{"prompt":"draw a new password for 1 account on 1 target in `dev` and promote it?"}}
```

`run.finished` follows, with exit 8.

### `creds generate`

`generate` adds one event that no other verb needs, for its `constraints`
section. From the tier-1 stack, trimmed only where `…` says so:

```jsonl
{"schema_version":"1.6","event":"run.started","seq":0,"ts":"2026-09-26T16:02:28.187333Z","correlation_id":"f3925d23-…","data":{"command":"creds.generate","dry_run":false}}
{"schema_version":"1.6","event":"plan.resolved","seq":1,"ts":"2026-09-26T16:02:28.187582Z","correlation_id":"f3925d23-…","data":{"units":[{"account":"acme_app_user","target":"free-pdb","intent":["generate","vault_write_pending"],…}],"blast_radius":{…}}}
{"schema_version":"1.6","event":"diagnostic","seq":2,"ts":"2026-09-26T16:02:28.966181Z","correlation_id":"f3925d23-…","target":"free-pdb","level":"warning","message":"free-pdb: the admin credential came from the environment variable …","data":{"code":"SOPULI-W022"}}
{"schema_version":"1.6","event":"constraints.resolved","seq":3,"ts":"2026-09-26T16:02:28.966448Z","correlation_id":"f3925d23-…","data":{"source":"targets","max_password_bytes":128,"character_set":"AL32UTF8","targets":[{"target":"free-pdb","reachable":true,"max_password_bytes":128,"measured_as":"utf-8","character_set":"AL32UTF8"}],"accounts":[{"target":"free-pdb","account":"ACME_APP_USER","profile":"DEFAULT","verify_function":{"state":"none"},"password_reuse_max":"UNLIMITED","password_reuse_time":"UNLIMITED","password_versions":["11G","12C"]}]}}
{"schema_version":"1.6","event":"lock.acquired","seq":4,"ts":"2026-09-26T16:02:29.520019Z","correlation_id":"f3925d23-…","data":{"vault":"vault-dev","path":"acme/dev/acme","fence":21,"acquired_at":"2026-09-26T16:02:29.507471Z","expires_at":"2026-09-26T16:17:29.507471Z","released":false}}
{"schema_version":"1.6","event":"vault.read","seq":5,"ts":"2026-09-26T16:02:29.526852Z","correlation_id":"f3925d23-…","data":{"vault":"vault-dev","path":"acme/dev/acme","version":8}}
{"schema_version":"1.6","event":"password.generated","seq":6,"ts":"2026-09-26T16:02:29.526997Z","correlation_id":"f3925d23-…","account":"acme_app_user","data":{"vault":"vault-dev","path":"acme/dev/acme","stage":"pending"}}
{"schema_version":"1.6","event":"vault.write","seq":7,"ts":"2026-09-26T16:02:29.530758Z","correlation_id":"f3925d23-…","data":{"vault":"vault-dev","path":"acme/dev/acme","version":9,"stage":"pending"}}
{"schema_version":"1.6","event":"lock.released","seq":8,"ts":"2026-09-26T16:02:29.535031Z","correlation_id":"f3925d23-…","data":{"vault":"vault-dev","path":"acme/dev/acme","fence":21,"acquired_at":"2026-09-26T16:02:29.507471Z","expires_at":"2026-09-26T16:17:29.507471Z","released":true}}
{"schema_version":"1.6","event":"target.finished","seq":9,"ts":"2026-09-26T16:02:29.535146Z","correlation_id":"f3925d23-…","account":"acme_app_user","target":"free-pdb","data":{"account":"acme_app_user","target":"free-pdb","state":"PENDING_APPLY","changed":true,"secret":{"vault":"vault-dev","path":"acme/dev/acme","stage":"pending","field":"acme_app_user","version":9},"actions":[{"kind":"vault_write_pending","applied":true,"detail":"staged v9"}]}}
{"schema_version":"1.6","event":"run.finished","seq":10,"ts":"2026-09-26T16:02:29.535349Z","correlation_id":"f3925d23-…","data":{"summary":{"total":1,"ok":1,"changed":1,"failed":0,"unchanged":0,"by_state":{"PENDING_APPLY":1}},"exit_code":0}}
```

**`constraints.resolved` is the whole section, sent once, as soon as it
exists**: the `constraints` object the run document carries, unchanged, sent
after every target has been read and before anything is drawn. That is how
`plan.resolved` works. One event per target as each is read was the
alternative. It was rejected because the section's estate-wide fields,
`strictest_target` and `character_set`, belong to no single target, and a
stream per target would leave every consumer to work out "strictest" again,
which is logic this tool already owns. The notes the reading produced
(`SOPULI-W015` to `W017`) arrive just before it as `diagnostic` events. A
`--dry-run` streams it too, because the reading is most of what a preview of
`generate` is for: `run.started`, `plan.resolved`, `constraints.resolved`,
`run.finished`.

- **The staging events are `rotate`'s**, from the same code: a `vault.read` per
  document, a `password.generated` per account drawn, and one `vault.write` per
  document, however many accounts share it.
- **A password from `--from-stdin` is not reported as generated.** The event
  reports where the password came from, and that value was supplied. Its row
  says so, and the `vault.write` still appears.
- **`--promote` is `vault.promote`, not `vault.write`.** A consumer watches that
  event to learn that `current` changed and applications will now fetch the new
  password, and that is what happened. Invariant 7's one exception shows in the
  stream as what it is, with the draws marked `"stage":"current"`:

  ```jsonl
  {"schema_version":"1.6","event":"vault.read","seq":5,"ts":"2026-09-26T16:02:31.805675Z","correlation_id":"074237b8-ab4f-4f4e-b784-9615a0fa5dbe","data":{"vault":"vault-dev","path":"acme/dev/acme","version":9}}
  {"schema_version":"1.6","event":"password.generated","seq":6,"ts":"2026-09-26T16:02:31.805763Z","correlation_id":"074237b8-ab4f-4f4e-b784-9615a0fa5dbe","account":"acme_app_user","data":{"vault":"vault-dev","path":"acme/dev/acme","stage":"current"}}
  {"schema_version":"1.6","event":"vault.promote","seq":7,"ts":"2026-09-26T16:02:31.808371Z","correlation_id":"074237b8-ab4f-4f4e-b784-9615a0fa5dbe","data":{"vault":"vault-dev","path":"acme/dev/acme","promoted_to":10}}
  ```

- **The environment gate (`safety.confirm_environments`) also sends
  `confirmation.required`**, which `generate` shares with `apply`: only when
  somebody is actually asked, with the question in `data.prompt`.

### `account reset-password`

**The unseen paths stream, and so does the seen path's preview.** A seen
(`manual`) reset is refused under every machine format before a password is
drawn: invariant 2's second guard checks for any machine format, not only JSON.
Its `--dry-run` is allowed, as it is under `json`, because a preview prints a
plan and never a password. It streams `run.started`, `plan.resolved`,
`target.started`, `target.finished` and `run.finished`, and no `password.*`
event. So `password.displayed` has no emitter by construction: the one seen-path
run that can stream is the one that shows nothing. That is the design, not a
gap. A `vault_wrapped` reset against the tier-1 stack, trimmed only where `…`
says so:

```jsonl
{"schema_version":"1.7","event":"run.started","seq":0,"ts":"2026-09-26T17:13:35.870495Z","correlation_id":"8ebe1029-…","data":{"command":"account.reset-password","dry_run":false}}
{"schema_version":"1.7","event":"plan.resolved","seq":1,"ts":"2026-09-26T17:13:35.870664Z","correlation_id":"8ebe1029-…","data":{"units":[{"account":"acme_dev_alice","target":"free-pdb","intent":["password_set"]}],"blast_radius":{"targets":1,"accounts":1,"environments":["dev"]}}}
{"schema_version":"1.7","event":"diagnostic","seq":2,"ts":"2026-09-26T17:13:36.478946Z","correlation_id":"8ebe1029-…","level":"warning","message":"no `reset_records:` block is declared, s…","data":{"code":"SOPULI-W024"}}
{"schema_version":"1.7","event":"target.started","seq":3,"ts":"2026-09-26T17:13:36.479212Z","correlation_id":"8ebe1029-…","target":"free-pdb"}
{"schema_version":"1.7","event":"diagnostic","seq":4,"ts":"2026-09-26T17:13:37.595170Z","correlation_id":"8ebe1029-…","target":"free-pdb","level":"warning","message":"free-pdb: the admin credential came from…","data":{"code":"SOPULI-W022"}}
{"schema_version":"1.7","event":"password.applied","seq":5,"ts":"2026-09-26T17:13:37.595243Z","correlation_id":"8ebe1029-…","account":"acme_dev_alice","target":"free-pdb","data":{"version":null,"outcome":"RESET"}}
{"schema_version":"1.7","event":"password.delivered","seq":6,"ts":"2026-09-26T17:13:37.595276Z","correlation_id":"8ebe1029-…","account":"acme_dev_alice","target":"free-pdb","data":{"method":"vault_wrapped","handover":{"accessor":"OApZG15TURKJpBT5fJGXjFF0","expires_at":"2026-09-26T17:28:37.542706Z"}}}
{"schema_version":"1.7","event":"target.finished","seq":7,"ts":"2026-09-26T17:13:37.595303Z","correlation_id":"8ebe1029-…","account":"acme_dev_alice","target":"free-pdb","data":{"account":"acme_dev_alice","target":"free-pdb","state":"RESET","changed":true,"actions":[…],"account_status":"OPEN","delivered":"vault_wrapped","handover":{"accessor":"OApZG15TURKJpBT5fJGXjFF0","expires_at":"2026-09-26T17:28:37.542706Z"},"duration_ms":1111}}
{"schema_version":"1.7","event":"run.finished","seq":8,"ts":"2026-09-26T17:13:37.595600Z","correlation_id":"8ebe1029-…","data":{"summary":{"total":1,"ok":1,"changed":1,"failed":0},"exit_code":0}}
```

**Per target, as each finishes**: `creds check`'s grain, not `apply`'s. An apply
row waits for a promotion decided after every target. A reset row is final when
its target is, because nothing decided later is written back onto it. So a stream
that stops on target three has already said what happened on one and two.

- **`password.applied`** where the password was set, with `"version": null`: a
  reset draws a password and keeps it in no document that a version could name.
- **`password.delivered`** where the row says the password was handed over. It
  carries the `method` and, on an unseen path, the row's `handover` object: the
  accessor, which names the hand-over and cannot perform it, and its expiry.
  **Never the wrapping token**, which goes to stderr under every machine format,
  and never the password (§4). Event schema 1.7 closes the payload, so no later
  field can carry either.
- **A partly applied reset** streams what it did: the password set and handed
  over, then a row that is `ERROR`, then exit 4. **An unlock that committed and a
  set that did not** streams neither event, because no working password was set
  or handed over.
- **No `password.generated`**: its payload names the vault path and stage the
  draw was staged to, and a reset's password is staged nowhere.
  `password.delivered` says where it went.

### Which verbs stream, and why the rest refuse

**Only a verb that has events to stream accepts `--output jsonl`.** Every other
verb refuses it with exit 2 and no events, and names where the value came from:
`--output`, `SOPULI_OUTPUT` or a profile's `output:`.

```
sopuli: --output (verb): `config show` does not stream, so it has no jsonl output
  hint: use --output json for the same run as one document; jsonl is offered by: account reset-password, creds apply, creds check, creds generate, creds rotate
```

The alternative was to accept `jsonl` everywhere and emit `run.started` and
`run.finished` around nothing. It is refused for §1's reason: `jsonl` and `json`
must describe the same run, and the event schema has no place for a `config` or
`targets` section. A stream that silently carried less than the document would
be the quiet downgrade §2 refuses everywhere else. `STREAMING_COMMANDS` in
`sopuli/invocation.py` is the list. Adding a verb to it means giving the verb
events, not only adding a line there.

**`lock break` refuses it on purpose.** Streaming is for runs whose progress or
stopping point matters. `lock break` is one action, and nothing unfolds: its
stream would be `run.started`, one event carrying the `broken[]` entry, and
`run.finished`. That is the run document with worse syntax, at the cost of a new
event name. `--output json` already gives a consumer all of it.

```
sopuli: --output (verb): `lock break` does not stream, so it has no jsonl output
  hint: use --output json for the same run as one document; jsonl is offered by: account reset-password, creds apply, creds check, creds generate, creds rotate
```

**A path that refuses the machine formats refuses `jsonl` too.** `account
reset-password`'s seen path and `policy sample --reveal` are refused under
`--output json`, and the refusal treats `jsonl` as a machine format. So the
guard still holds for `account reset-password`, which streams.
`policy sample` is not a streaming verb either.

The three `lock.*` events carry a payload. `lock.acquired` and `lock.released`
carry a `lock.held[]` entry as it is at that moment: `vault`, `path`, `fence`,
the two timestamps and `released`. `lock.denied` carries the run document's
`lock.denied` object, holder included. **None of them carries `account`.** The
lock is keyed on the path, and two accounts that share one document contend for
one lock. Naming either account would invite a consumer to group by account and
report that contention as two separate locks.

---

## 6. Exit codes and JSON together

`exit_code` in the document always equals the process exit code, so a consumer
that captured only stdout can still branch correctly.

### Which exits produce a document (J7)

One rule:

> **A run document describes a run, and a run begins when the invocation
> resolves. No valid invocation, no document.**

From which: **exit 2 is the only exit code that never produces a document. Empty
stdout with exit 2 means the invocation never parsed; the message is on stderr.**
Every other code emits one, exit 1 and internal errors included — they all have a
valid invocation to describe, and withholding the document exactly when something
went wrong is the opposite of useful.

The seam is there and not elsewhere for a schema reason as much as a conceptual
one. `command` is a closed enum of dotted paths and sits in `required`, as does
`invocation`. `sopuli config bogus` has no `command` value that exists, so
emitting a document for it means either violating this schema or relaxing
`required` and adding an `"unknown"` member — permanently, for every consumer, so
that all of them must handle a document that describes nothing. That is
contract-weakening dressed as contract-completing. `additionalProperties: false`
and a closed `command` enum are only worth their strictness because every
document describes a real run.

**With one command outside the rule rather than an exception to it: `sopuli
about` (#413).** It exits 0 and emits no document, and that is not a second seam
in J7 — it is a screen that is not a run. It takes no options, reads no
configuration, resolves no settings, touches no estate and prints compiled-in
text, so there is no invocation for a document to describe and nothing a
consumer could branch on. It is the same footing `--version` and `--help` stand
on, and the reason it is a verb rather than a flag is D2's grammar: a bare
top-level command fits it, a root-level `--about` would not.

**Asking it for JSON is a usage error, not a quiet text answer.** `--output`
belongs to the group's parser, so `sopuli --output json about` is accepted
*there* whatever the command does — and a command that then printed human text
and exited 0 would be the silent-ignore this document's §2 refuses everywhere
else: the run looks like it did what was asked. So `about` refuses `--output`,
`--config`, `--profile` and `--vault-token-file` in that position by name, and
exits 2 with no document, which is J7 unchanged.

The consequence for this contract is that **`about` is not in the `command`
enum and must not be added to it.** An enum value nothing emits is a branch a
consumer can write and never reach, which is the defect #392 was opened about;
`tests/test_cli_precedence.py` holds both halves — the command is named in
`NOT_A_RUN`, and that list is asserted to be absent from the enum and to take
none of the global options. A later change that gave `about` `--output json`
would be a change to what the command is, not a field addition, and it would
need the enum entry, a schema bump under §8's minor rule, and a reason why the
tool now answers one question in two places.

And `--output json` is itself an option that has to parse. `sopuli config show
--output jsom` is a usage error *in the request for JSON*; the tool cannot honour
a request it failed to read. A rule of "emit one if the parse got far enough to
see `--output`" would make the behaviour depend on where in argv the parse died —
not statable as a contract.

**A bad config file is not a usage error.** It has a perfectly good invocation:
argv resolved, the run began, and the file it was told to read turned out to be
unusable. It exits 9 (P5), carries `error.category: "config"`, and emits a
document. `config validate --output json` is the case that forced this: a
validator that goes silent exactly when it has something to say is not a
validator.

> **Implementation note, because the convenient way is the wrong way.** A missing
> or invalid config file must not be raised as a CLI-framework usage error, even
> though `--config` is an option and its callback is the natural place to load
> the file. Doing that hands the error to the framework's usage path, which
> prints text and exits 2 — putting config errors back on the no-document side
> whatever this section says.

**How it is enforced.** The document is opened the moment the invocation
resolves, not assembled when the run ends, and it is serialised once by a single
exit handler wrapped around every verb (`sopuli/invocation.py`). That ordering is
what makes the rule true rather than aspirational: an exception three lines into
a verb still has a document to attach the error to, carrying `command`, the
`invocation` including its resolved options, a zeroed `summary`, and the error —
schema-valid, and the case most likely to be missed if the document were built at
the end. The handler decides by **exit code**, never by exception type, so a new
error class cannot arrive on the wrong side of the seam by forgetting to be
listed somewhere.

A run document *is* the `--output json` mode; text output has no such thing to
withhold, and a failure there is the located message on stderr that it always
was. Both streams are used on a failed JSON run: the document on stdout for the
scheduler, the message on stderr for whoever is watching the log.

**An abort is a run that happened and did not finish**, so it gets a document
too, on exit 8. Withholding one would be worst in the case the code exists for: a
confirmation declined halfway through a rotation is exactly when a consumer needs
to know which targets were already touched. It carries no `error` — the category
enum has no value for "the operator said no", and `internal` would be a lie about
what happened — so the exit code says it and a `diagnostics[]` entry says it in
words. `error` is optional precisely so a document can report an outcome that is
not a failure.

The same rule holds for `jsonl`: a usage error produces zero events, not a
truncated stream. That is already consistent with "a stream that ends without
`run.finished` did not complete".

So a consumer faces **three** shapes, not two:

| What it sees | What it means |
|---|---|
| a document | the run happened; branch on `exit_code` |
| empty stdout, exit 2 | the invocation never parsed; the message is on stderr |
| empty stdout, any other exit | the process died before it could serialise |

The third is real and worth planning for — `jsonl` exists precisely for runs long
enough that dying halfway is a possibility worth observing.

### The pairing that makes scheduling work

```bash
sopuli creds check --application orders-app --profile scheduled --output json > result.json
case $? in
  0) ;;                                     # in sync, say nothing
  2) alert "sopuli: bad command line" ;;    # no document — result.json is empty
  3) alert "credential drift" < result.json ;;   # distinct: DRIFT, not a failure
  4) alert "partial rotation — needs apply --repair" < result.json ;;
  9) alert "sopuli: fix the config" < result.json ;;
  6|7) alert "sopuli could not run" < result.json ;;
  *) alert "sopuli failed" < result.json ;;
esac
```

The `2)` arm is the one worth copying: it is the only arm that must not read
`result.json`, and a canonical example that leaves it out is how the rule gets
discovered in production instead of in the docs.

Exit 3 being distinct from exit 1 is the whole reason a scheduled check is
useful: "the passwords disagree" and "the tool is broken" need different pagers.

---

## 7. Recipes

```bash
# which accounts drifted, and where
jq -r '.results[] | select(.state=="DRIFT") | "\(.account)@\(.target)"' result.json

# what a partial apply left unconfirmed: the repair set `--repair` reads (#264, #391)
# -- the same filter the flag applies, kept in step with it deliberately
jq -r '.results[] | select(.state != "IN_SYNC" and .state != "ROLLOVER_ACTIVE")
       | "\(.account)@\(.target)"' result.json

# and the flag itself, which needs the document on disk rather than on a pipe
sopuli creds apply --config estate.yaml --output json > result.json
sopuli creds apply --config estate.yaml --repair result.json

# anything the tool actually changed, for the change record
jq '[.results[] | select(.changed)] | map({account,target,actions:[.actions[]|.kind]})' result.json

# targets missing zero-downtime rotation, i.e. what to fix next
jq -r '.results[] | select((.scope.capabilities // []) | index("password_rollover") | not)
       | .target' result.json | sort -u

# where did this setting come from
jq '.invocation.options' result.json

# drift grouped by any target label, without parsing target names
jq -r '.results[] | select(.state=="DRIFT") | .scope.labels.tenant' result.json | sort | uniq -c

# follow a scheduled check live, one line per target as it finishes
sopuli creds check --application orders-app --output jsonl \
  | jq -r 'select(.event=="target.finished") | "\(.seq) \(.target) \(.account) \(.data.state)"'

# join to the database audit trail
jq -r .invocation.correlation_id result.json
# → SELECT event_timestamp, dbusername, action_name, object_name, return_code
#     FROM unified_audit_trail WHERE client_id = '<that>' ORDER BY event_timestamp;
```

---

## 8. Stability policy

`schema_version` is `MAJOR.MINOR`.

**Minor** (consumers must tolerate): new optional properties, new enum values,
new event types, new diagnostic codes.

**Major** (announced, with an overlap release): removing or renaming a property,
removing an enum value, changing a type, changing the meaning of a field.

Both schemas set `additionalProperties: false` so the tool's own tests catch
accidental additions — but *consumers* must ignore unknown properties, and the
docs say so explicitly. The strictness is a producer-side guard, not a
consumer-side requirement.

**1.0 became 1.1 when `config` was added**, which is the minor rule above
working as written: an optional property, and no consumer of 1.0 breaks by
ignoring it. The published schema file was renamed rather than duplicated. It is
a *producer-side* guard — it describes what this build emits — so a retained 1.0
file would guard nothing and drift.

**1.1 became 1.2 when `target.list` joined the `command` enum**, which is the
same rule again: a new enum value, and a consumer of 1.1 that switches on
`command` already has to cope with a value it does not recognise, because the
enum was never the set of commands it happened to know. Renamed rather than
duplicated, for the reason above.

**1.2 became 1.3 when `policy.sample` arrived**, which is both rules at once: a
new enum value and a new optional property (`policy`). Nothing existing changed
meaning, so a 1.2 consumer that ignores unknown properties reads a 1.3 document
correctly. Renamed again, for the reason above.

**1.3 became 1.4 when exit code 9 joined the `exit_code` enum** (J7, issue #8),
**and 1.4 became 1.5 when `lock` arrived** — a new enum value and then a new
optional property, which is the minor rule twice over.
`lock` is the first section published *ahead* of the code that fills it, which
the minor rule tolerates for the same reason it tolerates `plan` and `results`
having sat unimplemented since 1.0: the schema is a producer-side guard on the
shape, and a section nothing emits constrains nothing. What it does buy is that
the decision in issue #83 has one written form, in the file CI validates against,
rather than two that can disagree.

**1.5 became 1.6 with the staged payload** (#85, #109) **and 1.6 became 1.7 with
`config.shared_secrets`** (#110) — optional properties both, and neither was
recorded here at the time. Written down now because a list that stops at 1.5 and
resumes at 1.8 reads as two renames nobody can account for, which is worse than
either entry is interesting.

**1.7 became 1.8 when `lock status` arrived** (#105): `lock.status` joined the
`command` enum and `lock.found[]` joined the section, which is the minor rule
twice over again. Nothing existing changed meaning — `found` was added *beside*
`held` precisely so that `held` would not have to. The `denied.holder` object
moved into a `$defs/lock_holder` the two arrays share, which is a refactor of the
schema file and not of the contract: the shape a consumer sees is byte-identical.

**1.8 became 1.9 when the survey started looking past the declared set** (#150):
`lock.found[].declared` joined the entry, required. A new *required* property is
still a minor bump under §8's rule — the rule is about what a consumer that knows
1.8 can still do, and every 1.8 field means what it meant. What changed is that
`found[]` may now carry entries a 1.8 consumer would not have received at all,
and `declared` is the field that tells it so. A consumer that ignores the field
sees more rows than before; one that reads it sees exactly what it saw in 1.8 by
keeping `declared: true`.

**1.9 became 1.10 when a lock could be broken** (#149): `lock.break` joined the
`command` enum and `lock.broken[]` joined the section, which is the minor rule
twice over — for the fourth time, and by now that is the pattern rather than a
coincidence. A verb arrives, it needs a name in the enum and an array of its own
beside the ones that already mean something else, and nothing existing changes
meaning. `SOPULI-W002`'s description widened in the same change and is
deliberately *not* a schema matter: a code's meaning is contract, its wording is
not, and this widening was neither.

**1.10 became 1.11 when `doctor` had somewhere to put its findings** (#182):
`targets[]` joined the document, and `doctor` was already in the `command` enum.
The minor rule for the fifth time, and the first time the alternative was
seriously weighed: `results[]` existed and looked like the obvious home, and it
required an `account` this command does not have and a `state` vocabulary about
a sync it does not perform. Reusing it would have cost nothing in schema version
and lied in every document.

**1.11 became 1.12 when `--check-privileges` had something positive to report**
(#225): `targets[].privileges` joined the entry, and every property inside it is
required. The minor rule for the sixth time. Recorded here after the fact —
#227 bumped the schema and did not write the entry, and a list that skips a
number reads as a rename nobody can account for, which §8's own 1.5-to-1.8 gap
already demonstrated. The section's prose was owed to §2 by whoever next touched
the privilege audit, and #341 was that — it is there now.

**1.12 became 1.13 when `doctor` reported install shape** (#214, ADR-006 E6):
`install` joined the document as an optional property, and `doctor` was already
in the `command` enum. The minor rule for the seventh time, and the same
alternative was weighed and rejected as in 1.11: `targets[]` was the section that
already existed, and install shape is a property of the *machine* rather than of
any target — so putting it there would have repeated one fact once per target and
said it twenty-one times on the estate `01-configuration.md` §2 uses as its
example. The new `status` enum arrives in the same bump, which is the minor rule
again rather than a second thing.

**1.13 became 1.14 when `doctor` looked for the wallet** (#215, P4): `wallet`
joined the document as an optional property. The minor rule for the eighth time,
and the first section whose *absence* carries meaning in the way `lock`'s does —
it is omitted when nothing in the estate uses `auth: external`, which is not the
same as omitted because the command did not look.

**1.14 became 1.15 when `doctor` asked the vaults** (#216, P4): `vaults[]`
joined the document as an optional array. The minor rule for the ninth time, and
the same argument 1.13 made — a vault is neither a target nor an account, so
widening `targets[]` would have meant a field that means nothing for most of its
rows. It follows `install`'s always-present rule rather than `wallet`'s
sometimes-absent one, and the two are not inconsistent: a wallet matters only to
an estate using `auth: external`, while every estate that does anything has
stores, so an empty array is a real answer here and an absent section would not
be.

**One rename has happened under 1.0, deliberately.** `actor.scheduled` became
`actor.unattended` when run context moved into profiles
(`01-configuration.md` §5). By the rule above that is a major change, and it was
made in place anyway: no released build ever emitted the property — it is written
only when true and nothing ever set it — so there is no consumer to overlap with.
The rule holds from the first release that emits a populated `actor`; this is the
grace before it. A second rename does not get the same treatment.

Every release validates its own sample outputs against the published schema in
CI. The schema is the test fixture, not documentation written afterwards.

**1.30 became 1.31 when the redraw codes joined the registry** (#610).
`SOPULI-W029` and `SOPULI-W030` are new diagnostic codes, a minor bump by §8's
list. The schema file is byte-identical apart from its `$id`, as at 1.16. The
two conditions were reported before, as `password_redrawn` and
`password_not_redrawn`, outside the registry, and those two strings are no
longer emitted. A consumer matching them must match the new codes instead.
`SOPULI-W028` (#568) was added at 1.30 without a bump, so 1.31 is also the first
version a consumer can rely on to carry it.

**1.29 became 1.30 with `sopuli account expire-password`** (#525). Two additive
changes, each a minor bump by the ordinary rule:

- `password_expire` joins the `action_kind` enum. It is the bare
  `ALTER USER … PASSWORD EXPIRE`, which sets no password, so it could not report
  as `password_set`: the seen reset's `IDENTIFIED BY … PASSWORD EXPIRE` does set
  one, and reports as that;
- `account.expire-password` joins the `command` enum.

**A row carries two actions**, `rollover_finish` then `password_expire`, in the
order the driver considered them, and each is reported whether or not it was
issued. That is `reset-password`'s shape rather than `suspend`'s single action.
The two are separate facts, and on an account found at `EXPIRED & IN ROLLOVER` only
the first happens: the window is closed, the expiry is not reissued, and the row
reports `changed: true`. A row that never reached the driver (refused, missing,
unreachable, or previewed) carries the single `password_expire` action with
`applied: false`, as `suspend`'s rows do.

**1.28 became 1.29 when a hand-over could be described without being performed**
(#444). One additive change: **`results[].handover`**, an object carrying
`accessor` and `expires_at`, emitted on an unseen delivery and absent on the seen
path.

**It exists because `delivered` could not grow.** That property is a string and
its own description says "never a value and **never a destination**", so the
accessor could not go in it without a rename — major, under §8, to answer a
question no consumer had asked. A sibling object also generalises where a widened
string would not: `vault_path` would report a path here and `one_time_link` a
link id (open: #445, #447), and each is the same *kind* of fact about a hand-over.

**What it holds is the half that cannot fetch.** Vault returns two things beside a
wrapped password: the token, which produces the password in anybody's hands, and
the accessor, which names the wrap in the audit log and produces nothing. The first
has no property here and will not get one — a document is captured, shipped to log
aggregation and kept, and a token in one outlives the TTL that is the method's
whole guarantee. That is the argument the password's absence already rests on,
applied to a different object, and UC-2 §6.1 is why it applies at all: the rule is
about reach rather than value.

**Present whenever a delivery put the password somewhere, and absent otherwise.**
That is a fact about the *path*, not about how much the store was willing to say:
a wrap that returned neither an accessor nor a usable TTL is still a hand-over, and
the section is there with two nulls. Keying its presence on "is either field set"
was a real bug in the first draft — it reported such a delivery as the seen path,
which is the one thing the section exists to tell apart. On `manual` it is absent,
because the destination is a person reading a screen: no accessor to name, and no
store clock to expire.

**`expires_at` comes from the store's clock, not this host's** — Vault's
`creation_time` plus the TTL it actually applied, which a mount's `max_ttl` may
have shortened below what the file asked for. Reported and never enforced: nothing
here polices a TTL the store is already policing, and a second clock would only
disagree with the first.

**The event schema went 1.1 to 1.2 in the same change**, adding
**`password.delivered`** — the event UC-2 §6.3 says every delivery emits. It has no
emitter, for 1.1's reason exactly: `--output jsonl` was unimplemented then (#9), so this
extends an artefact already ahead of its stream, and the word is registered with
the change that knows why the event exists. Neither it nor `password.displayed`
carries the password, and neither carries the retrieval credential — a consumer
that wants to tie a stream to a vault's audit log reads `handover.accessor` from
the run document. (It got its emitter in 1.7, #535, and carries that accessor
itself now.)

**The event schema went 1.2 to 1.3 when something first emitted it** (#9). Three
payloads §5 had described since 1.0 became requirements: `run.finished.data`
must carry `summary` and `exit_code` (and may carry `error`), `target.started`
must name its `target`, and `plan.resolved` must carry `data`. A `diagnostic`
event must carry `level` and `message`. Tightening a schema nothing emitted
breaks no consumer — there were none — and it is what turns §1's "the last event
carries the same summary" from prose into something CI checks on every line.
**Added rather than renamed**, which is the event schema's own practice since
1.1 and 1.17's reasoning: 1.3 is the first version a build emits, so it is the
one a consumer will fetch.

**The event schema went 1.3 to 1.4 when `creds apply` began to stream** (#535),
which is the "comes with the first verb that emits them" #535 named. Every
constraint is on an event nothing emitted before, so no 1.3 stream fails it:
`lock.acquired` and `lock.released` must carry a `lock.held[]` entry's six
fields, `lock.denied` its `vault`, `path` and `reason`; `vault.read` and
`vault.write` a `vault`, `path` and `version`; `vault.promote` a `promoted_to`;
`verification.done` its `account`, `target` and `data`. **`password.applied`
and `password.generated` have closed payloads** — `version` and `outcome` for
the first, `vault`, `path` and `stage` for the second, and
`additionalProperties: false` on both. That is the one tightening of an event
1.3 already constrained, and it is invariant 2 held by the schema rather than by
the emitter's discipline: a field added later that could carry a password fails
CI on every line rather than being noticed in review. Added rather than renamed,
for 1.3's reason.

**The event schema went 1.6 to 1.7 with `account reset-password`** (#535), the
first emitter of `password.delivered`. Its payload is closed: `method`, and an
optional `handover` of exactly the run schema's shape (`accessor`,
`expires_at`) — `additionalProperties: false` at both levels, for the reason
1.4 closed `password.applied`'s: the event sits next to a credential, and a
field added later that could carry it must fail CI rather than a review.
`password.displayed` keeps no emitter, by construction: the seen path streams
only as a `--dry-run`, which displays nothing.

**The event schema went 1.4 to 1.5 with `creds rotate`** (#535), the first verb
to emit `confirmation.required`: its `data` must carry the `prompt`. `vault.write`
may carry an `error` object, for a staging write the vault refused. Both are on
events nothing emitted under 1.4 in those shapes, so no 1.4 stream fails 1.5.

**The event schema went 1.5 to 1.6 with `creds generate`** (#535), and it is the
first bump since 1.1 to add an event *name*: `constraints.resolved`, which must
carry `data` — the run schema's `$defs/constraints`. Adding a value to the event
enum is minor under §8, and it is the one kind of minor change an exhaustive
consumer notices; that is the cost of giving the section a home, weighed against
putting it inside `run.finished` (late, and a catch-all) or one event per target
(which strands the estate-wide fields).


**1.27 became 1.28 when the survey found a third kind of record** (#514). One
additive change: **`lock.found[].declared_by`**, which says *how* this
configuration accounts for a path — `binding`, `reset_records`, or `null` for a
leftover.

**It exists because a boolean ran out of answers.** Until UC-2 there were two
kinds of record: one a binding names, and one nothing names. A reset lock is
neither. It is keyed on the reset record's own path, so the file declares the
*prefix* and cannot name the keys beneath it — an account admitted by a
`profile:` or `role:` predicate has no name until a database is asked, and `lock
status` asks none. Reporting it `declared: false` would tell an operator a
colleague's reset belongs to another estate; reporting it `true` with nothing
else would claim the file enumerates it.

**`declared` stayed and widened rather than being replaced.** It now means "this
configuration accounts for the path at all", which is what a consumer filtering
its own locks out of a survey was already asking it. Widening a boolean's
extension is a minor bump; turning it into a tri-state string is a rename, which
is major — and it would have cost every consumer a change to answer a question
none of them asked.

**`declared_by` is not an enum, deliberately**, which is the opposite call from
`state`'s neighbours in §3. A later release may claim another region by prefix —
UC-4 hands accounts over through the same delivery abstraction (UC-2 §6.7) — and
a consumer that switched exhaustively on two values would break on the third
rather than fall through to "not mine, or not mine yet".


**The event schema went 1.0 to 1.1 in the same change** (#441), and it adds an
event nothing emits: **`password.displayed`**, the seen reset's exposure.

That is deliberate rather than an oversight, and it is the one place this
document's usual rule bends. A contract value with no emitter is normally the
defect `SOPULI-W022` was written to fix -- but the whole event schema has had no
emitter since it was published, because `--output jsonl` was unimplemented (#9),
so this is extending an artefact that is already ahead of its stream rather than
creating a new inconsistency. The word is registered with **the change that
causes the exposure** rather than with the one that will carry it, because the
change that knows why the event exists is the one that should name it.

**What records the exposure today is the run document**, which every run has:
`results[].delivered` says the method was `manual`, and `manual` is by definition
the path that shows somebody a password. `password.displayed` is what a *stream*
consumer would read — and it never will: `account reset-password` streams since
#535, but the seen path only as a `--dry-run`, which shows nothing; the real one
is refused under every machine format. The run document remains what records the exposure.

**1.26 became 1.27 with `sopuli account reset-password`** (#441), UC-2's reset.
Two additive changes:

- `account.reset-password` joins the `command` enum;
- **`RESET` joins the `state` enum** — what a reset row reports, the way
  `account suspend` reports `LOCKED`: the thing that happened to the account. It
  is not one of the existing words and reusing one would have been worse than a
  bump — `IN_SYNC` claims a comparison this verb never makes, and the account's
  own status differs by path (`EXPIRED` on the seen path, `OPEN` on the unseen
  one), so neither is a fact about the *reset*;
- **`results[].delivered`** — how the password was handed over: the delivery
  *method*, never a value and never a destination. `manual` records the method
  and no location, because the seen path's destination is a person by a route the
  tool did not carry, and UC-2 §3.1's record draws the same distinction. Absent on
  a row that delivered nothing, which is every row a run refused.

**No new `action_kind`**, which is worth saying because the verb issues three
statements and reports each: `account_unlock`, `password_set` and
`rollover_finish` have all been in that enum since it was written.

**`state` did need one**, and the first draft of this section claimed otherwise —
caught by Copilot's review of #505, which found that `account reset-password
--dry-run --output json` emitted `state: "RESET"` against an enum that stopped at
`DECLARED`, so the tool produced a document its own contract rejected. That
combination is reachable because a preview is exempt from the seen path's output
guard: it prints a plan and never a password.

**There is no property a password could occupy, and that is a guard rather than
an omission** (#439's second). Refusing `--output json` stops the seen path from
running while a document is produced; this makes the document unable to carry the
value whatever runs. The two are one guard asserted twice, and the second is the
one that survives somebody adding an output mode.

**1.25 became 1.26 with `safety.delivery.allowed_methods`** (#498), H6's ratchet.
One additive change: **`config.targets[].safety.delivery`**, an object holding
`allowed_methods` — the delivery methods left after this target's own block and any
target set template or `overrides:` entry have been intersected.

**It is a sub-block, and that is the whole content of the bump.** Every safety
setting was one key deep until this one, so the resolved view built each property
by stripping `safety.` off the setting's name — which is nesting, as long as
nothing nests. With a sub-block it stopped being: the view emitted a property
literally called `delivery.allowed_methods`, and `safety`'s
`additionalProperties: false` refused it, so `config show --resolved --output json`
produced a document this contract rejected the moment a target wrote the key. Found
by Copilot's review of #500 rather than by a test, because nothing had ever put a
nested setting on a target. The view now nests along every separator in a setting's
name, so the next sub-block needs no change to either.

`allowed_methods` is never the empty array: two layers with no method in common
refuse at plan time (`01-configuration.md` §9) rather than resolving to nothing, so
a consumer reading an empty list would be reading a state the tool does not produce.

**1.24 became 1.25 with `sopuli account list`** (#490), UC-2's listing verb.
Four additive changes, each a minor bump by the ordinary rule:

- `account.list` joins the `command` enum;
- **`DECLARED` joins the `state` enum.** It is that verb's ordinary row: the
  declaration matched this account and the database has it. It is deliberately
  not `IN_SYNC` — nothing was compared, because this verb never reads a password
  — and an account the declaration names and the database does not have is
  `ACCOUNT_MISSING`, which already meant exactly that and did not need a synonym.
- **`results[].declared_by`** — which `personal_accounts:` rule admitted the
  account: `accounts '...'` for an enumerated entry, or `profile '...'` /
  `role '...'` for a predicate. **This is the field the verb exists for.** Under a
  predicate the answer is not in the configuration at all, because membership is a
  profile assignment or a role grant (H1, #449), so a record saying an account is
  declared without saying by what cannot be checked afterwards. `null` where the
  declaration named an account the database does not have, since there was nothing
  to resolve the rule against.
- **`results[].reset_at`** — when the reset journal says this account was last
  reset, from the `reset_records:` store (#468). Absent where no journal is
  configured, and `SOPULI-W023` says so.

**`reset_at` and `password_age_days` are two clocks and must not be folded**, which
is UC-2 §3.2 and the one thing to know before consuming either. The first is what
this tool recorded; the second is the database's own. On the unseen path a database
date *later* than `reset_at` is a finding: somebody changed the password after the
tool delivered it, so the copy the person was told to fetch no longer works. A
consumer that averaged them, or took whichever was present, would turn that finding
into a number.

**1.23 became 1.24 with `sopuli account suspend`** (#463), UC-2's offboarding verb.
Three additive changes, each a minor bump by the ordinary rule:

- `account_lock` joins the `action_kind` enum, beside the `account_unlock` that
  was already there — the two are one pair, and this is the write half;
- `account.suspend` joins the `command` enum;
- **`results[].account_status`**, which is Oracle's own `ACCOUNT_STATUS` as it was
  read *before* anything was issued. It is emitted for a row the verb refused as
  well as one it changed, because "I left it alone and here is the state it is in"
  is the whole answer for those. Compound values are ordinary and a consumer must
  expect them: `EXPIRED & LOCKED` is real, and `LOCKED(TIMED)` is a failed-login
  lock rather than a deliberate one — a substring test for `LOCKED` cannot tell
  those apart, which is the mistake the driver's own parse exists to avoid.

**Why `state: LOCKED` is not enough on its own**, and this is the thing to know
before consuming it: a row can read `LOCKED` with `changed: false` because the
account was *already* locked, and under `--dry-run` because it *would be*. The
document's `dry_run` distinguishes them, and `account_status` is what says which
state the database was actually in.

**1.22 became 1.23 when `config show` learned to report the stores** (#428):
`config.vaults[]`, additive, and a minor bump by the ordinary rule.

It is the one entry in this list that fixes an *absence* rather than adding a
fact. `config.declared` carried the address the file wrote and `config.resolved`
carried no store at all, so "which vault will this run talk to" had no answer in
either shape — and the text view had been answering it, from effective values,
since the store layers were built. Two views of one command disagreeing about the
same store is the defect; adding the provenance without the value would have been
a smaller version of it.

The same release lifted `invocation.options`' entry shape into
`$defs/resolved_setting` and pointed both consumers at it. **That is not a
contract change**: the definition is byte-for-byte what `options` inlined, so
every document that validated before validates now. It is here because the layer
enum lives in it, and two copies of an enum are two things that can disagree —
which `tests/settings/test_registry.py` reads the schema specifically to prevent.

**1.21 became 1.22 when the expanded estate gained a `safety:` block** (#426):
`config.targets[].safety`, additive, and a minor bump by the ordinary rule rather
than by any exception.

What it reports is **the block in force for that target**, after a target set's
template and its `overrides:` entry have been ratcheted together — not the
flattened value the config model carries. The two differ exactly where an override
asks for less than its template, and there the flattened one is the target layer's
literal statement rather than what any run reads (#425). A contract that carried
`readonly: false` for a target the tool then refuses to mutate would be the
precise failure this property was added to remove.

What it does **not** fold in is `defaults`, a profile, or a group. None of those is
a property of a target, and folding them would make one object's answer depend on
four while hiding which — `config.declared` already carries every block as
written, and `config show`'s own `safety` section lists each by the key that
writes it.

**1.20 became 1.21 when a verb that will never exist left the `command` enum**
(#392): `creds.promote` removed. The list above calls removing an enum value a
**major** change, and this one is minor, so the exception gets stated rather than
waved at:

> **A value no released build has ever emitted was never part of what a document
> could say**, so removing it cannot break a reader of one. The test is the
> *emitter*, not the schema.

It is a claim about evidence, and the evidence is checkable rather than argued:
`creds.promote` has been in this enum since the schema was written, and
`git log -S"creds.promote" -- src tests` returns no commit in the repository's
history. Nothing has ever produced the value, so no document carries it and no
`case` over `command` has ever taken that branch except by writing it blind.

**The exception is narrow in three directions**, and a later removal that cites
it has to meet all three. It does not cover a value some released build *did*
emit and this one no longer does — that changes what a document can say, and
stays major with the overlap release. It does not cover properties: `plan` and
`results` sat published and unfilled from 1.0, and a consumer that wrote a reader
against either would have been right to — an unfilled property is a shape
promised, where an enum value is a name. And it does not cover a value merely
unimplemented *yet*: `admin.install` stays in the enum on exactly that ground,
because whether the verb exists is open (open: #655), and §8 has tolerated a name
published ahead of its code since `plan`, `results` and `lock`. What made `creds.promote` different is that
the verb was **declined**, not deferred — `uc-01-app-credential-sync.md` §4 says
"there is no `creds promote`, and there is not going to be" (#276, #284). A slot
for something that might arrive is honest; a branch nothing can ever reach is
not, and it is worse here than elsewhere because this enum is what this section
points at as the definition of what the tool can produce.

**The bump is still paid**, for a change that makes no document different,
because `schema_version` answers *which build is capable of what* — the argument
1.15 → 1.16 made for a file that was byte-identical apart from its `$id`. The
1.20 file stays published: a build emitting `schema_version: "1.20"` has to be
able to fetch the schema it validates against, which is 1.16 → 1.17's rule and
the reason that one was added rather than renamed.

**1.19 became 1.20 when a password could be written straight to `current`**
(#257): `state` gains `VAULT_ONLY`, which §3's own first line makes a **minor**
bump — an added enum value, with nothing existing changing meaning. The cost is a
consumer switching exhaustively over `state`, and it is paid deliberately: the
alternatives were a value that asserts something untrue and a successful mutation
with no `results[]` at all.

Nothing else in the document moves. `vault_promote` has been in the `action_kind`
enum since the schema was written, and `results[].secret.stage` has always been
able to say `current`, so the verb that arrived with this bump needed one new
word and no new shape.

**1.18 became 1.19 when `creds generate` reported what it read** (#317): a
`constraints` section, described above, carrying the limit that bound the draw
and — per account — the three things UC-1 §4 step 2 names that no draw can be
bound by. A new optional property, which §8's own list calls a minor bump.

**A section rather than more warnings**, which is #216's rule applied one verb
along: a diagnostic is for what the exit code cannot tell you, and everything
else belongs in the section that names it. A run answering *what may a password
be here* with eleven warnings has nowhere to put the eleven answers. The two
codes that come with it, `SOPULI-W016` and `SOPULI-W017`, are a registry addition
of the kind 1.15 → 1.16 was.

**1.17 became 1.18 when a run could draw a second password** (#312):
`results[].redraws` says how many *extra* passwords an account was given because
the server refused the value itself — `ORA-28003` or `ORA-28007`, UC-1 §6.4. A
new optional property, which §8's own list calls a minor bump.

**Emitted only when it happened**, like `overridden` below and for the same
reason: the field records redraws rather than the budget for them, and a `0` on
every row of every ordinary run would bury the rows that carry one. A consumer
counting rotations should read it as "this row was applied more than once and
reports the last attempt", not as a failure — a redrawn account that ends
`IN_SYNC` succeeded.

The two diagnostic codes that come with it, `SOPULI-W029` and `SOPULI-W030`
(§3), were first emitted as `password_redrawn` and `password_not_redrawn`,
outside the registry and with no schema bump. #610 renamed them and made the
bump that should have come with them: 1.31, above.

**1.16 became 1.17 when `--force` gained something to record** (#286):
`results[].overridden` carries the §4 account guardrails a run waived — the
check that refused and what it observed. A new optional property, which §8's own
list calls a minor bump.

**Added rather than renamed, unlike the bump below**, and the difference is the
point: 1.16's file was byte-identical to 1.15's, so renaming lost nothing. This
one changes the document's shape, so 1.16 and 1.17 are genuinely different
schemas and a consumer pinned to either has to be able to fetch the one it
validates against. A renamed-away 1.16 would leave a build emitting
`schema_version: "1.16"` with no schema of that name.

`declared` — §4 check 1 — is deliberately absent from the `check` enum. It is the
one refusal `--force` cannot waive, so a document could never legitimately carry
it here, and an enum admitting it would advertise an override the tool refuses to
perform.

**1.15 became 1.16 when a run could be fenced out** (#282): `SOPULI-W011`
joined the diagnostic registry, which §8's own list calls a minor bump — a new
diagnostic code, and nothing existing changing meaning. The schema *file* is
byte-identical apart from its `$id`, because `diagnostic.code` was never an
enum: a consumer branching on codes has to cope with one it does not know
whatever the schema says. What the bump buys is the only thing it could — a
consumer can tell which builds are capable of emitting `SOPULI-W011`, which is
the question `schema_version` exists to answer. Renamed rather than duplicated,
for the reason every entry above gives.

---

## 9. Open questions

| # | Question | Leaning |
|---|---|---|
| J1 | ~~Should `--output json` stream nothing until completion, even for long runs?~~ | **decided** (#615): yes; `jsonl` covers the streaming case. Reasons: [J1](../decisions/log.md#j1) |
| J2 | ~~Include `plan` in every run, or only with `--dry-run`/`--verbose`?~~ | **decided: every command that plans** (#615). A command with no units, such as `doctor`, emits none (§2). Reasons: [J2](../decisions/log.md#j2) |
| J3 | Stable machine-readable codes for warnings (`SOPULI-W014`) | yes, and they get a documented registry — otherwise consumers grep messages. **Opened, not answered**: §3 now carries a registry with the two codes the advisory lock needed (#83), a third for a configured-but-uninstalled backend (#130), and an error-code registry beside it holding `SOPULI-20001`. The config layer's other warnings still have none. What is left is the policy — which warnings get a code, and how numbers are allocated across categories; #130 allocated two by hand and did not settle it, and #317 allocated `SOPULI-W015`, `SOPULI-W016` and `SOPULI-W017` the same way, and #296 `SOPULI-W018` — following the established practice rather than answering the question, which stays open |
| J4 | ~~Emit a top-level `hostname`/`pid` for log correlation~~ | **decided: host only** (#615), as `invocation.actor.host`; no pid. Reasons: [J4](../decisions/log.md#j4) |
| J5 | OpenTelemetry span export alongside JSON | **deferred**: later; `correlation_id` is already the trace id in spirit |
| J6 | ~~Should the event stream be resumable after a crash?~~ | **decided** (#615): no; run it again. Reasons: [J6](../decisions/log.md#j6) |
| ~~J7~~ | ~~Does `--output json` emit a run document on a usage error?~~ | *resolved 2026-08-13 (issue #8): no, and exit 2 is the only code that never does; an invalid config file exits 9 (§6)*. Reasons: [J7](../decisions/log.md#j7) |

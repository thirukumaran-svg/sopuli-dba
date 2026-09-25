# sopuli-dba — JSON output contract

Status: draft / sketch, **partly implemented**. The run document, `--output
text|json`, colour resolution, the `config` section, `diagnostics`, `plan`,
`results` and four of `invocation.selection`'s six members are real and validated
against the schema in CI (`sopuli/output/`). **`--output jsonl` is the one output
mode that does not exist** — `--output` takes `text` and `json`, and asking for
`jsonl` is a usage error — so §5 and everything else said about streaming here is
still a sketch. This paragraph called `plan` and `results` unwritten until #392;
they have been emitted by every `creds` verb for many releases.

**`lock` is emitted by the two `lock` verbs and by the three mutating `creds`
verbs** (#105, #149). `sopuli/output/lock_view.py` produces the whole section,
and `tests/test_lock_view.py` validates every shape it can produce against the
published schema. `lock status` fills in `found[]` — records it read at paths it
does not hold, whether or not the config declares them (#150). `lock break`
fills in `broken[]`, and `denied` when it is refused a live lock. `held[]` is
filled by whatever *takes* a lock for itself, which is `creds generate`,
`creds apply` and `creds rotate`; `_record_locks` in `sopuli/cli.py` is the one
place all three go through, and it is called after release so that `released`
reports the store record rather than the moment (#348). This paragraph said
`held[]` was still waiting on `creds generate`, "which does not exist", until
#392 — it had shipped, with a lock, three releases earlier.
The `lock.*` events are the remaining wait: they need `--output jsonl` (#9),
which has no emitter, so their payloads are specified in §5 and not yet produced
by anything.

**`invocation.selection` is now filled in** (#297). The object has carried
slots for `applications`, `accounts`, `targets`, `groups`, `all` and `limit`
since the schema was written, and until the flags existed only `select` was ever
populated. Four of the six are real; `all` and `limit` remain slots for flags
that do not exist, and stay omitted rather than sent empty — an empty array would
claim the tool considered a selector it has not got. **No schema change was
needed**, which is the schema having been right about where this was going.

`diagnostics` carries what §10 of `01-configuration.md` calls warnings: findings
the loader decided not to refuse to run over. They are run-level because a config
warning belongs to no single target, and `level` is `warning` for all of them so
far — the config layer has no other severity to report. Every command that loads
a config emits them, `config show` in both its views as well as
`config validate`: a warning that reached only the text output would be invisible
to the scheduler, which is the reader that most needs it. A run with nothing to
report omits the key rather than carrying an empty array.
Schemas: [`../schemas/sopuli-run-1.29.schema.json`](../schemas/sopuli-run-1.29.schema.json),
[`../schemas/sopuli-event-1.2.schema.json`](../schemas/sopuli-event-1.2.schema.json)
Example: [`../schemas/example-creds-check-drift.json`](../schemas/example-creds-check-drift.json)

---

## 1. Why this is a contract and not just output

Everything that consumes this tool programmatically — the scheduler that alerts on
drift, the CI job that gates a release, the dashboard someone will inevitably
build — reads JSON. Text output is for humans and may change freely. JSON output
may not. Treating it as a versioned interface from day one costs almost nothing
now and saves a compatibility mess later.

Three output modes:

| Mode | Shape | Use |
|---|---|---|
| `--output text` (default) | tables, colour when a TTY | humans |
| `--output json` | one document on stdout when the run completes | scripts, `jq`, CI |
| `--output jsonl` | one event object per line, streamed as work happens | long runs, live dashboards, log shipping |

`jsonl` and `json` describe the same run. The last `run.finished` event carries
the same `summary` and `exit_code` as the `json` document, so a consumer can use
either without a second code path.

### Encoding, on every mode

**All three standard streams are UTF-8**, forced at startup regardless of the
platform's locale and regardless of `PYTHONIOENCODING`. See P4 in
`00-principles.md` for why — the short version is that redirected stdout on
Windows is cp1252, and that turns a status glyph into a crashed command rather
than a cosmetic problem.

JSON output was never exposed to this: `json.dumps` escapes non-ASCII by
default, so the document is ASCII on the wire whatever the stream does. The rule
exists for `--output text`, and for the error and diagnostic messages that carry
a server's own wording back to the user.

### Colour

Colour is a property of a run, resolved once, and asked for rather than decided
at each call site — `Emitter.use_color()` is the single answer. Precedence, in
order:

| # | Rule | Result |
|---|---|---|
| 1 | `--output json` | never coloured, whatever else says |
| 2 | `--color never` | off |
| 3 | `--color always` | on |
| 4 | `SOPULI_NO_COLOR` or `NO_COLOR` set and not empty | off |
| 5 | `TERM=dumb` | off |
| 6 | stdout is not a TTY | off |
| 7 | Windows console where VT mode cannot be enabled | off (P4's plain fallback) |
| 8 | otherwise | on |

Three of those are decisions rather than transcription.

**An explicit flag beats the environment** (rules 2 and 3 above 4). This follows
P3, where the command line outranks the environment, and it is the reason
`--color always` exists at all: a CI job whose log viewer renders ANSI has no
TTY, so autodetection strips exactly the output that was wanted. It does not
contradict invariant 10 — that ratchet governs *safety* settings, and nothing
becomes more dangerous because it is red.

**`--output json` is not negotiable** (rule 1 above 3). The document is a
versioned contract (invariant 12); a consumer must never have to strip escape
sequences before parsing.

**Set-and-not-empty**, per no-color.org, so `NO_COLOR=0` still disables colour.
That reads wrong and is correct: presence is the signal, and treating `0` as
"yes please" would break every consumer that follows the convention.

When colour is off, escape sequences are **stripped at the serialiser** rather
than avoided upstream — the same shape as redaction, and for the same reason. A
guarantee held in one place cannot be lost by a call site that forgot, and a
vendor message may arrive already decorated.

### Progress, and the one thing on stderr that is not a message

A verb reading a document out of a vault animates a spinner on **stderr** while
it waits (#419, assessed in #416). It is the only progress indicator in the tool,
and it is opt-in at exactly one call site: `sopuli/cli.py`'s `_read_documents`,
which `creds apply`, `creds rotate`, `creds finish-rollover` and `creds status`
all read through.

**That is not every read of the vault, and the difference is deliberate.**
`creds check` reads through `_stored_credential`, and `creds generate` calls
`store.read` directly where it needs a document's current version for a
compare-and-set; neither animates. #419 scoped this to one call site rather than
a sweep, so that which operations are considered slow stays a decision somebody
made in a diff. Extending it is another one.

Gated the same way colour is, and in the same place, for the same reason:
`Emitter.spinner()` is the single answer, so no call site works it out for
itself.

| # | Rule | Result |
|---|---|---|
| 1 | `--output json` | never, whatever else says |
| 2 | stderr is not a TTY | never |
| 3 | otherwise | animate |

Three things about that table are decisions.

**There is no rule 3 for a flag**, and there will not be one. `--color always`
exists because a CI log viewer with no TTY can still render ANSI; nothing renders
a carriage-return animation usefully into a log file, so a `--spinner` flag would
exist only to let somebody write about 12,000 characters of `|/-\` into 30
seconds of nightly log. Measured in #416. The absence is the design: no flag, no
`SOPULI_SPINNER`, no precedence rule, and nothing for the settings registry.

**`--output json` is refused even though the spinner never touches stdout.**
Rule 1 is not redundant with rule 2. stdout is the contract (invariant 12), and a
consumer capturing `2>&1` -- which is ordinary in a scheduler -- would otherwise
find frames ahead of the document. The animation is turned off at the source
rather than defended by which stream it went to.

**Colour is not consulted, and `NO_COLOR` does not apply.** The frames are four
ASCII characters and a carriage return, with no escape sequence anywhere, so
there is nothing for the stripping rule above to strip and nothing `NO_COLOR`
promises that the spinner could break. Verified on a terminal: a `NO_COLOR=1` run
emits byte-for-byte what an ordinary one does.

**It must never be live across anything else that writes to stderr.** The plan
preview and `click.confirm` are both on stderr deliberately (§*Exit codes*
below, and `00-principles.md` P3), and a frame written over a prompt leaves the
operator reading a spinner while the process blocks on an answer to a question
no longer on screen -- measured in #416. That is why a spinner wraps one call
rather than decorating a verb, and why the call it wraps is one the store layer
services without printing anything.

### What colour is allowed to mean

Two rules, both binding on the renderer that ADR-003 selects:

**The palette maps onto the JSON vocabulary** — `state`, `by_state`, `drift`,
`unverifiable`, `failed`, and the `state` enum in the run schema. The human and
machine views must not be able to describe the same run differently. Inventing a
separate set of visual categories produces two vocabularies that will drift.

That rule was written against *results*, because results were the only text
output anticipated. `config show` arrived first and has no states at all, so the
rule applies to it in the same form against the fields its `config` section
emits. Implemented in `sopuli/output/palette.py`:

| Role | What it marks | The field behind it |
|---|---|---|
| `heading` | a section name, a column heading | structure, not data |
| `muted` | the `-` standing in for a value that is not there | any nullable field |
| `notable` | an overridden target, a `non_production` store, a warning | `overridden`, `non_production` |
| `production` | the `prod` environment wherever it appears | `environment` |
| `good` | a state a reader can stop reading at | `state` = `IN_SYNC` |
| `attention` | something true that a person has to act on, the run being fine | `state` ∈ `DRIFT`, `PENDING_APPLY`, `ROLLOVER_ACTIVE`, `VAULT_ONLY` |
| `bad` | the tool could not do the job, or the estate is not in a state it can | `state` ∈ `ERROR`, `ACCOUNT_MISSING`, `LOCKED`, `EXPIRED` |
| `inconclusive` | no answer, and the absence is the finding | `state` ∈ `UNVERIFIABLE`, `SKIPPED` |

The same four roles carry a second vocabulary — a store's health — rather than
growing a palette of their own:

| Value | Role | Why |
|---|---|---|
| `vaults[].status` = `ok` | `good` | |
| `= degraded` | `attention` | it **answered** and cannot serve; the reader goes to the vault |
| `= unreachable` | `bad` | nothing answered; the reader goes to the network |
| `install.backends[].status` / `install.drivers[].status` = `not_installed` | `attention` | there is a `pip` line under the table |
| `= not_implemented`, nothing configured | `muted` | true on every run of this build; colouring it would make every `doctor` look broken |
| `= not_implemented`, something configured | `bad` | the run's actual failure, exit 9, and no install fixes it |
| `targets[].reachable` = `false` | `bad` | |

**Two rules a reader will otherwise take as inconsistency.** `IN_SYNC` is
coloured and `reachable: true` is not, because a result state is one of eleven
with no norm — cyan says *this row is done* — while reachability has two values
and an overwhelming one, so painting the common one would make the single `no`
ordinary again. That is `config show`'s argument for painting `prod` and no other
environment, and it is the same rule seen from the other end. And
`not_implemented` is the one status whose role depends on another column, which
it earns: unconfigured it is noise on every run, configured it is why the run
exited 9.

Two views were reviewed and left plain on purpose: `wallet_view` and
`constraints_view` render prose and key-value blocks rather than tables, so there
is no column to scan and a colour would decorate a sentence. Both already carry
diagnostic codes for a consumer that wants to branch. Their module docstrings say
so, rather than leaving the absence to look like an oversight.

Nothing there is a new category: each is a field the JSON already carries, so
the two views still cannot disagree.

**The result palette arrived in #395**, which is what the deferral this paragraph
used to carry was waiting for. Four roles, and one function —
`sopuli/output/palette.py`'s `role_for_state` — decides which a state gets. Before
it, four views each kept their own subset of the enum and painted it `notable`:
`check` coloured `DRIFT` and `apply` did not, `apply` coloured `ERROR` and `check`
did not. One state, one run, different emphasis depending on the verb, which is
the thing the role indirection exists to prevent.

Three properties of that palette are decisions rather than taste.

**Converged is cyan, not green.** Green `IN_SYNC` against yellow `DRIFT` is the
one pairing a deuteranopic reader cannot separate, on the exact distinction this
tool exists to report — so the conventional traffic light is the wrong palette
here specifically. Red is kept for `bad`, where it is close to universal, and the
three that must never collapse into one are asserted distinct in
`tests/test_palette.py`.

**Inconclusive is dim rather than coloured.** A row nothing could be concluded
about must not compete with a row that says something, and must not read as
either good or bad. It is also what makes the palette affordable in `creds
status`, whose *ordinary* row is `UNVERIFIABLE` — the whole column recedes
instead of shouting.

**The grouping is not the exit code's grouping, deliberately.**
`sopuli.check.is_inconclusive` counts `ACCOUNT_MISSING`, `LOCKED` and `EXPIRED`
as inconclusive, correctly: none says anything about the *password*. For a colour
that is the wrong question — a locked account is not an absence of news — so those
three are `bad` in the palette and inconclusive in the summary. A reader will meet
both at once, an `ACCOUNT_MISSING` row in red above a `1 unverifiable` counter,
and the two are answering different questions rather than contradicting each other.

**Meaning is never carried by colour alone.** Drift has its own exit code (3)
because schedulers alert on it; a human needs that distinction without colour
too — a symbol or a word, with colour as reinforcement. This makes the
`NO_COLOR` path lossless rather than degraded, and it is the accessibility
floor.

Every role above decorates a word that is already on the line — `prod`,
`override`, `non-production`, `-` — so the guarantee holds by construction
rather than by care. `tests/test_cli_smoke.py` asserts the strong form of it end
to end: strip the escapes from `--color always` output and it equals `--color
never` output byte for byte.

**The tool's own prose stays ASCII by convention**, enforced across the whole
command tree by `tests/test_cli_smoke.py`. This is not a limitation left over
from the encoding problem — it is the rule that keeps decoration deliberate.
Box drawing, status glyphs and any other non-ASCII presentation belong to the
text renderer, where the choice is made once and can be switched off; they do
not belong in a message because someone typed a nicer dash. Text that came from
outside — an account name, an `ORA-` message, a vault path — is passed through
unchanged, which is precisely what the UTF-8 streams make safe.

---

## 2. The run document

```
{
  schema_version, tool, command,
  invocation { correlation_id, timing, actor, dry_run, profile, selection, options },
  config     { sources[], resolved, declared | targets[] + bindings[] },
  plan       { units[], shared_secrets[], confirmation_required, blast_radius },
  lock       { mode, held[], denied, found[] },
  results    [ { account, target, scope, secret, state, changed, actions[],
                 verification, rollover, error, warnings[] } ],
  targets    [ { target, reachable, scope, asserted, duration_ms, privileges,
                 error, warnings[] } ],
  install    { backends[], drivers[] },
  wallet     { required_by[], tns_admin, directory, from_sqlnet, readable,
               files[], unreadable[], auto_login, insecure[] },
  summary    { total, ok, changed, drift, unverifiable, skipped, failed, by_state },
  diagnostics[],
  error      { category, message, hint },
  exit_code
}
```

Several parts of it are worth explaining, because they encode decisions rather
than just data.

### `config`, emitted by `config show`

Two views of one file, discriminated by `resolved`:

- **`resolved: false`** carries `declared`, the merged config document as
  loaded. Deliberately untyped in the schema: it is the user's YAML after
  `--config` layering, and reshaping it on the way out would answer a different
  question from the one it is there to answer.
- **`resolved: true`** carries `targets[]` — the expanded estate with labels,
  provenance and whether anything manages each one — and `bindings[]`, one row
  per account per target with its secret ref rendered.

A binding's `secret` is the ref **as written**, a string that round-trips
(`01-configuration.md` §7), so it lines up by eye with the config file. The
structured form is `plan.units[].secret`, which is a different job: that one
addresses a specific version at a specific moment, and this one records what the
file says. Neither ever carries a value.

#### `config.vaults[]` — which store, at which address, from which layer (#428)

Present in **both** views, and the reason it is not a rider on either is that
neither carried it: `declared` is the address the *file wrote*, and `resolved`
dropped stores entirely to report targets and bindings. `doctor`'s own `vaults[]`
has no `addr` either. So a consumer could not answer *which vault will this run
talk to*, for any layer — true since the store layers were built rather than
since `--vault-addr` was.

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

That forces an ordering worth stating: **you cannot report where `addr` came from
before reporting what `addr` is.** The value is the substantive half and the
provenance rides along with it — which also means this section answers the
broader question *should `config show --resolved` report the stores a run will
use*, and the answer is yes.

A `settings` entry is the **same shape** `invocation.options` carries, and the
schema has one `$defs/resolved_setting` both point at: it is one question about
one resolver, and a second grammar for it would be two shapes a consumer has to
learn for one fact. `source_detail` is a location and never a value, by that
definition's own contract.

**Not admitted into `invocation.options`**, which was the alternative and would
contradict what that section means: `RESOLVED_SETTINGS` excludes a store's keys
on the documented grounds that they "describe a store rather than a run", and
`sopuli/invocation.py: _wired()` *raises* on a name that is not listed. The guard
is right; the fix should not be to defeat it. Sharing the shape is not sharing
the section.

Four properties of the object:

- **Always emitted, `[]` included**, following `install`'s always-present rule
  rather than `shared_secrets`' sometimes-absent one — and for `vaults[]`' own
  reason under `doctor`: every estate that does anything has stores, so an empty
  array is a real answer here.
- **`name` and `type` only, beside `settings`.** Both are the store's identity
  and neither is layerable — a store that is HashiCorp from a laptop and OCI from
  CI is two stores (C13). `non_production` and `locking` are deliberately absent:
  both are declaration-only guardrails, `declared` carries them as written, and
  `doctor` reports the second as `lock.mode`. Adding either later is additive.
- **A key no layer wrote is absent**, not `null`. A store with no namespace has
  no provenance for one, and a `null` would invite a consumer to branch on a
  field that is empty almost always.
- **`auth:` is not in `settings` at all.** It is replaced whole rather than
  resolved key by key, so no layer *won* a key and there is no
  `resolved_setting` to emit. It is also the one part of a store entry that
  addresses credentials, and §4's redaction rule is easier to hold structurally
  than by remembering: there is nowhere here for it to sit.

Unlike the text table, the provenance is carried whether or not `--explain` was
passed. There is nothing to filter — no `vaults.*` setting has a built-in
default, so every key reported is one some layer actually wrote, which is the
filter `invocation.options` applies and `--explain` lifts.

### `policy`, emitted by `policy sample`

The policy as declared, plus one entry per sample describing it: how many
characters, how many bytes in the encoding it was measured against, how many of
each character class, and whether it satisfies the policy it was drawn from.

**A sample object has no value property at all**, the same way `secret_ref` has
none. That is not an oversight to fix later: `policy sample --reveal` prints
passwords to a terminal for a human to look at, and it is refused with
`--output json` precisely because JSON is what gets captured and shipped to log
aggregation. The schema having nowhere to put a password is what makes the
refusal a property rather than a promise.

`compliant` is always `true` for a generated sample. It is reported anyway,
because `false` would mean the generator and the validator disagree — and one
predicate serving both is the design (`01-configuration.md` §8).

### `error`, when the run failed as a whole

Distinct from `results[].error`, which is one target failing inside a run that
otherwise worked. The run-level one is present when there is no per-target work
to report at all — the configuration could not be read, or something went wrong
before the first target was touched — and it is what makes exit 9 and exit 1
answerable from the document alone.

It has **no location field**, so a config error's file and key path travel inside
`message`; `hint` has a field of its own and is not repeated there. The category
comes from the exception rather than from the boundary inferring one from a
Python type, which is the mapping that goes wrong first when a subclass is added.

**A driver error reached this object for the first time in #287**, and the gap it
closed is the one that mapping was written to prevent. Every `DriverError` had
been falling into the boundary's catch-all: `internal` on exit 1, the hint folded
into `message` rather than into the field it has, and the message prefixed with
the exception's class name. That included `UnsupportedCapabilityError`, so
invariant 4's *distinct exit code* was 1 like everything else and
`target_capability` — in this schema since it was written — had never been
emitted by anything. A capability refusal now carries `category: "capability"`,
exit 5, and the capability's name in its own field, which is what a consumer
branches on instead of parsing it back out of prose.

**A pre-flight refusal is the other new producer** (#283): `category` is the kind
of problem that stopped it — `connectivity`, `authorization` or `database` —
`message` says how many were found over how many targets and names the first, and
each finding is a `diagnostics[]` entry with its `target` and, where the check is
about one, its `account`. The findings get no diagnostic *code*: §3's rule is
that a code exists for what the exit code cannot tell you, and here `category`
already carries the branch. A `warning`-level finding is one the survey could not
establish rather than one that refused — an unreadable privilege audit — and it
appears on runs that went ahead.

**A rotation reports both halves in one `results[]`** (#284). `creds rotate`
sequences verbs that already have entries here and reuses theirs rather than
inventing a third shape: the staging write at §8 step 4 produces `generate`'s
entry with its `vault_write_pending` action, and steps 5 to 7 produce `apply`'s,
with `password_set`, the two `verify`s and `vault_promote`. So an account this
run rotated appears twice, once per phase, which is what the two writes actually
were — and `creds.rotate` needed no schema bump, having been in the `command`
enum since before the command existed.

What the verb adds is one diagnostic and no fields. `SOPULI-W012` is §8 step 8,
and `--max-age-days` narrowing a run is visible in `summary.total` rather than in
a member of its own: an account the age filter left alone is one this run did not
act on, and inventing a fourth state for it would put "not attempted" in the same
vocabulary as "attempted and unverifiable".

**A guardrail-skipped account is `SKIPPED` with its reason** (#286). The state
is the schema's own word and `creds finish-rollover` already uses it for the
neighbouring idea — something the tool declined to do here, as against something
it tried and could not. It is worth knowing what the state does *not* mean: it is
not a failure, it does not make the run partial, and it is excluded from the
exit code's arithmetic on both sides. §4 of `02-oracle-privileges.md` carries the
reasoning; the short version is that an account a guardrail refused is one the
run was never going to act on, and a nightly rotation that exited 4 for ever
because one account holds `DBA` would be a guardrail more disruptive than the
mistake it catches.

### `invocation.selection`

What the run was narrowed to, as the selectors were given rather than as they
resolved — the resolved answer is `config.targets[]` or `results[]`, and having
both is what makes a filtered run auditable.

Only `select` is populated so far, from `--select k=v`. The other slots —
`applications`, `accounts`, `targets`, `groups`, `all` and `limit` — are the
selectors that do not exist yet, and are omitted rather than sent empty: an
empty array would claim the tool weighed a selector it has not implemented.

`selection` is absent entirely when the whole estate was in scope. This matters
more than it looks — a consumer reading `total: 2` cannot otherwise tell a small
estate from a filtered one, and "2 rotated" means very different things in each.

### `invocation.profile`

The active profile's name, or absent (`01-configuration.md` §5, #153).

Reported whether or not the profile changed anything, unlike `options` — which
carries only what changed behaviour. *Which* profile a scheduled run was invoked
under is the first question when two runs over one config behaved differently,
and answering it only when some key happened to differ would be answering a
different question.

Absent rather than `null` when no profile is active. The schema allows either;
the key with no name in it reads as "a profile was considered and found", which
is not what happened.

The *choice* is also a resolved setting in its own right — `profile`, from
`--profile`, `SOPULI_PROFILE` or `defaults.profile` — so `options` says where the
name came from, and this says what it resolved to. The two differ in exactly one
case worth being exact about: nobody asked and the file's default did not either,
so `options` has no `profile` row and this is absent.

### `invocation.config_files`

The files this run read, in layering order (`01-configuration.md` §5, #402).

**Declared here from the beginning and emitted by nothing until #402**, which is
worth recording rather than quietly fixing: the schema described it, the
committed sample showed it populated, and no run had ever written it. The sample
validated against the schema throughout — conformance is not the claim *a run
produces this* — so nothing was red. `tests/test_run_document.py` now asserts the
example carries no `invocation` key the producer cannot write, which is the
assertion that was missing rather than the field.

Until then a document said which *settings* a file changed, through
`options.source_detail`, and never which files were read: a run whose config
supplied nothing worth reporting named no file anywhere.

**Order is contract, the set is not.** Later files layer over earlier ones, so a
producer that sorted these would describe a precedence the run did not use.

**Paths, not content.** What a consumer asks of this is *which estate is this
document about* — which is what `creds apply --repair` reads it for (#391) — and
two runs over the same paths are the same estate for that question. A file edited
between them is a staleness question, and belongs to whatever compares the
documents rather than to their identity.

**Absent, not empty, on a run that never loaded a configuration layer** — the
file was missing, unreadable or rejected. There is no verb for which that is the
ordinary case: every command loads a config before its body runs, so absence
here always means the run got no further than trying, and the `error` on exit 9
names the path. An empty array would say the run looked and found nothing, which
is a different statement.

### `invocation.correlation_id`

A UUID per run. The tool also:

- sets it as the Oracle **client identifier** on every session
  (`DBMS_SESSION.SET_IDENTIFIER`), so it lands in
  `UNIFIED_AUDIT_TRAIL.CLIENT_ID`
- writes it into the **vault secret metadata** on every write

One id therefore joins the tool's JSON, the database's audit trail, and the
vault's version history. That join is the difference between "something rotated
at 03:00 and half of it failed" and an actual answer.

### `invocation.options`

Every effective option that changed behaviour, with the precedence layer it came
from:

```json
"verify.method": { "value": "hash", "source": "profile",
                   "source_detail": "profiles.scheduled.verify.method" }
```

This is the machine-readable form of `config show --explain` (P3). When someone
asks why a scheduled run behaved differently from their interactive one, the
answer is in the output they already have, not in a re-run with `--debug`.

By default it carries the settings that **changed behaviour** — a setting
answered by its built-in default changed nothing, and reporting
`output: text [builtin]` on every clean run would be noise in a document
consumers diff. `--explain` lifts that filter and includes them, in this mode as
well as in the text one: it means *show everything you consulted*. The shape of
an entry is identical either way, so the flag changes how many entries appear and
nothing about what one means.

Two rules about the pair, both load-bearing:

**`source_detail` is a location, never a value.** The flag as typed (`-o` records
as `-o`), the variable name, the config key. It exists so somebody can find the
thing in their own command line or CI job definition — which is why the config
layer points at `profiles.ci.verify.method` rather than just `"profile"`. That
keeps the field inside §4's redaction rule for free, because no code path puts a
value there at all.

This paragraph used to offer `--vault-token` as the example of a flag whose
*value* is a secret and whose `source_detail` is only its name. #145 removed the
example by removing the flag: `--vault-token-file PATH` is what exists, it takes
a location, and `--vault-token` is refused (§3a of `01-configuration.md`,
[ADR-007](../decisions/adr-007-vault-token-flag.md)). Worth recording, because
the two rules were easy to read as one and are not: this one is about what may
appear **in the document**, and invariant 1 is about what may appear **in argv**.
A flag carrying a token would have satisfied this rule perfectly and still been
forbidden. Neither `--vault-token-file` nor the rest of §3a's token chain appears
in `invocation.options` at all — the chain is its own merge, resolved when a run
reaches a store, and nothing in the settings registry claims to have settled it.

**For a ratcheted setting, `source` names the layer that determined the effective
value, not the highest layer present.** If `defaults.safety.readonly` is `true`
and a flag asked to relax it, the pair is `"source": "defaults"`,
`"source_detail": "defaults.safety.readonly"` — the layer that held, and the key
inside it. Reporting `"cli"` because the command line is layer 1 would be
precisely backwards. The defeated request is not swallowed either: it appears in
`diagnostics[]` as a warning naming both ends.

The two always agree, because `source_detail` is where the value named by
`source` was written: a `safety:` block under a target resolves as
`"object"` / `"targets.acme-alpha.safety.readonly"`, and the same block under a
profile as `"profile"` / `"profiles.ci.safety.readonly"`. There is no `config`
value in the enum, deliberately — "somewhere in the file" is not a precedence
layer, and four of the seven layers live in the file.

One consequence to record so it is not re-opened later as a bug report: a
ratcheted setting can have **several** contributing sources while the reported
one is the floor rather than the top — a union of `confirm_environments` is the
clearest case. That is correct, and text output says as much. If the full
contribution chain is ever wanted in JSON it arrives as a new optional field
(a minor bump), never as a change to what `source` means.

There is deliberately no `cli_group` / `cli_verb` distinction in the `source`
enum. A precedence layer encodes authority — who expressed more specific or more
current intent — and flag position before or after the subcommand is the same
person, in the same command line, at the same moment. Splitting it would push an
artefact of the CLI parser into an interface scripts branch on; position, where
it is worth recording at all, goes in `source_detail`.

### `plan`, emitted on real runs too

`plan` is not a dry-run-only section. A real run emits the identical structure it
would have emitted with `--dry-run`, so a diff between "what we said we'd do" and
`results` is mechanical. `plan.shared_secrets` exists specifically to surface the
one-secret-many-targets case from UC-1 §4 — the situation where rotating one
account quietly changes three PDBs. Legal, often intended, never invisible.

**`confirmation_required` is optional, and is not emitted yet** (#247). Answering
it needs a profile's `confirm:` reaching the precedence resolver, which has not
happened — the key is parsed and has no consumer. Emitting `false` in the
meantime would be the one reading that is actually wrong: it claims a run was put
to a gate and passed it. Absent says the run was never asked, which is true.
Adding it later is a minor bump, since the property already exists in the schema.

**A unit omits `secret` when nothing has named its store yet.** `secret_ref`
requires `vault` as a string, so there is no shape for half an address, and
`units[].secret` is optional exactly so a unit can say it has none. §3's chain
deliberately leaves out a profile's `vault:` and `SOPULI_VAULT` — which profile is
active is a property of a run, and bindings are built once at load — so a valid
file can reach the plan with no store resolved. The plan does not refuse it, and
C15 (#118) is what says so: it decided "mostly plan time" — the null is a real
temporary state, and the command that actually *needs* a store is what fails,
once a run's profile is known and the answer is exact (invariant 4). `config show
--resolved` renders `-` for the same binding. The completion step that turns
such a binding into an addressable one is `config/binding_stores.py` (#250),
called by the command that needs a store rather than at load.

**`results` is per credential; `targets` is per target.** `creds check` emits the
first (#248) and `doctor` the second (#182): one reports on a password in a
database and the other on the database. `results[]` is meant to be read beside
`plan.units[]` — same grain, same order — so a diff between what a run said it
would do and what it did is mechanical.

**`summary`'s optional counters are populated by the verbs that count them**, and
omitted by the ones that do not. `drift: 0` from `doctor` would say that command
looked for drift and found none, and it never looked. `by_state` likewise carries
only the states a run actually produced.

**`plan` is absent entirely on a command that plans nothing** — `config show`,
`doctor`, `lock status`. That is not J2 ("always emit `plan`") being answered: J2
asks whether a *planning* command may ever omit it, and the answer here is that a
command with no units is not planning. `sopuli.plan` builds the section and
`sopuli/output/plan_view.py` reads it.

Since Q7 (#85) made one secret per application the documented default, sharing has
a second axis and the entry carries it: `accounts[]`, present when one document
holds more than one account's credential. That is the case where rotating
`acme_orders_user` rewrites the document `acme_batch_user` reads, and the two axes
are genuinely different questions — `targets[]` answers "who receives this
password", `accounts[]` answers "whose password is in this document". A consumer
that only knew the first would report a blast radius of one account for a write
that touched six.

`accounts[]` is optional rather than always-present, and reads as "the sharing the
operator might not have intended". A document with exactly one account in it omits
it, because a list of one is not a warning.

**An entry is one document, not one ref** (#110). Every account in a document
differs only by the pointer below the field, and the document is what a write, a
compare-and-set and the advisory lock all operate on — so an entry is one entry
per lock, and the `secret` it carries is a `vault` and a `path` with no `field`.
Keying on the full ref instead would emit six near-identical entries for one
six-account document, each repeating the same five neighbours. The path is
normalised through the same function `sopuli/lock/keys.py` uses, so "shares a
document" and "shares a lock" cannot give two different answers.

**Where `accounts[]` comes from: the config, never the store.** The accounts in an
entry are the ones the file declares for that document — invariant 5's set, which
is also the set a write may touch. Two consequences, both intended. It is offline
and deterministic, which it has to be: a plan is reviewable ahead of time only if
it is a function of the config and the selection, and this section is emitted on
real runs too, so a list read from a live document would make the plan-versus-
`results` diff a question of whether somebody else edited the vault in between. And
it will not show an account that is in the document but absent from the file —
that is worth knowing, and it is drift rather than plan, so `creds check` reports
it.

**`config.shared_secrets` is the same shape, asked of the whole file.** `config
show --resolved` emits it from the config alone, which is the offline question:
*what does my file share, before I run anything?* `plan.shared_secrets` is the
same detection narrowed to one run's work. They coexist for the reason
`config.bindings` and `plan.units[]` do — one describes the file, the other
describes a run. Both are omitted entirely when nothing is shared, rather than
emitted empty: an empty array reads like a finding that came back negative.

### `lock`, on runs that take one

P5's advisory lock lives in the vault and is keyed on the **secret path** being
mutated (Q2, decided in issue #83). What reaches the document is deliberately
about the guarantee rather than the mechanism:

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

Captured from `creds generate --output json` against the tier-1 stack on
2026-09-11, not written by hand.

**`mode` is `cas` or `none`**, not `kv2` or `flock`. A consumer needs to know
whether the run was actually protected; it should not have to know what KV v1 is
to find out. `none` is what a store configured `locking: advisory-only` reports —
the record was written without compare-and-set, which catches two operators
minutes apart and misses two CI jobs in the same second. That weakening is also a
`diagnostics[]` warning on every run, carrying the code `SOPULI-W001` (§3), so it
appears in the audit trail of each run rather than only in the config file
somebody would have to go and read.

**`fence` is the version the acquiring write returned**, and it is the whole
safety argument for putting the lock in the vault rather than in the database.
The risk worth designing against is not the stale lock but the stolen one: a run
stalls, its lock expires, a second run takes over and rotates, and the first
wakes up and applies `ALTER USER` to its remaining targets from a plan that is no
longer true. `DBMS_LOCK` does not prevent that either — the stalled session is
still alive and still holds it. Re-reading the fence before every mutation does,
which is why automatic release on session death stopped being worth a widened
grant set.

**`denied` appears on exit 7**, carrying the holder — host, pid, os_user, and
the holder's own `correlation_id`. That is the field that answers the only
question anyone has at that moment: is this a colleague mid-rotation, or a
process that died? There is never more than one, because acquisition is
all-or-nothing and stops at the first refusal.

Its `reason` says **how** the run lost, and the two ways are not the same event.
`held` means a held, unexpired record was read, so the holder and the timestamps
describe it and the schema requires them. `race` means the compare-and-set write
was refused — another run acquired between this run's read and its write — and
there the winner's record was never read. The schema therefore leaves `holder`
optional and `reason` says why it is absent, which is better than a producer
emitting an all-null holder that a consumer cannot distinguish from a vault that
answered badly. A conflict on the *renewal* write is neither of these and is not
`denied` at all — this run held the lock, so losing the compare-and-set is a
takeover, reported the way every other takeover is (#346). Everything in `held[]` is required by contrast: that section is
written when the run ends, by which point there is nothing about its own locks
the tool does not know.

**The section is absent on a run that takes no lock**, which is `check`,
`status` and every `--dry-run`. Absent means none was needed, not none was
available.

**`found[]` is the third array, and it is somebody else's locks** (#105).
`sopuli lock status` takes no lock, reads the records at every secret path the
config declares, and — since #150 — lists each store's lock prefix so that a
record at a path the config *does not* declare is reported too:

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

It is a separate array rather than a reuse of `held[]`, and the reason is that
**`held` is possessive**. There, `released: true` means *this run let go
cleanly*; in a survey the same word would mean *this path is free*. That is one
field meaning two things depending on `command`, which is what §8's stability
rules exist to prevent — and a consumer aggregating held locks across runs would
start counting surveys as acquisitions. The holder is reported through the same
definition `denied.holder` uses, because the question at exit 7 and the question
`lock status` answers are the same question.

**`declared` says whose the record is** (#150). `false` is one the store holds
and the file names nowhere — an application renamed or removed, or another
config's estate sharing the mount — and it is the entry an operator cannot
otherwise see, which is the entire reason for listing. Invariant 5 is not
strained: the config whitelists what the tool may *touch*, and a survey touches
nothing. It is judged against the **unfiltered** estate, so `--select` narrowing
a survey never turns somebody's own lock into a leftover, and it is required on
every entry rather than written only on the leftovers — a consumer that had to
read absence as "mine" would be branching on a gap, which is also what a producer
that forgot the field emits.

**`declared_by` says how** (#514), because from UC-2 onwards "whose" has three
answers rather than two. A reset lock is keyed on the reset record's path, which
no binding produces, so the survey finds it by listing the declared
`reset_records:` prefix rather than by enumerating keys — an account admitted by
a predicate has no name until a database is asked, and this verb asks none. Such
an entry carries `declared: true` and `declared_by: "reset_records"`; a binding's
carries `"binding"`; a leftover carries `null`. §8's 1.28 entry says why the
boolean widened instead of becoming a tri-state, and why this field is not an
enum.

A **fourth array was rejected.** What split `held` from `found` was that one
field would have meant different things in each; nothing of the sort happens
here, since every field means exactly what it means for a declared record and
only ownership differs. The text view does render the two separately, which is a
rendering decision rather than a contract one.

**A store with no `list` capability is named in a warning, not refused**
(`SOPULI-W005`). Refusing would make `lock status` a command that works on some
backends and not others, and would cost the operator the report for every other
store as well. But it cannot be silent either: an empty `found[]` is something a
consumer acts on — it concludes there are no leftovers — and that conclusion has
to be earned by having looked.

`held` and `state` are the verdict and the evidence, and they are not the same
field twice. Anything that is not `released` is held, **including a state this
build has never heard of** — treating an unknown state as free is the one guess
that ends with two runs rotating one credential — and a consumer that saw only
`held: true` could not tell such a record from an ordinary one. `version` is the
store's version and is deliberately not called a fence: a fence is a claim, and
nothing in a survey holds one.

**A declared path with no record at it is not an entry.** `found` is what was
read, which is what keeps every member of an entry required; how many paths were
examined is `summary.total`, and the difference between the two numbers is how
many are free. On `lock status` the array is emitted even when empty, because
there an empty array is the finding — a quiet estate must not be
indistinguishable from a command that did not look.

`mode` means one thing in every array: the guarantee available in the stores the
section is about. On a run that took locks that is what it took them under; on a
survey it is what a lock in those stores would be worth.

**`broken[]` is the fourth array, and it is a lock this run ended** (#149).
`sopuli lock break` writes a `released` record over a held one, comparing against
the version it read:

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

Its own array for the reason that split `held` from `found`: this is neither a
claim the run holds nor a record it merely read. The fields that matter are the
ones neither of the others has. **`version` is what the write compared against**
and **`new_version` is what it produced** — and it is the second that fences the
previous holder, whose next check now fails. Neither is called a fence: `held[]`'s
`fence` is a claim *this* run holds, and after a break nobody holds anything.
`version` is never null here, unlike `found[].version`, because a store that
cannot fence is refused before the read (exit 5) — and so is one *declared*
`locking: advisory-only`, whatever it turns out to support. An unfenced "break"
is worse than a weaker guarantee: the released record keeps the holder's own
`correlation_id`, so with no version to compare, their next check would find a
record that still answers "mine" and they would carry on rotating, never told.

**`applied` is what makes `--dry-run` and the run that follows one shape.** The
plan *is* the entry; whether it happened is a boolean inside it, so a consumer
diffing them compares like with like rather than two documents (invariant 8). It
is false under `--dry-run`, where `new_version` is null because no version was
produced.

**An empty `broken[]` is the finding**, as an empty `found[]` is on a survey:
there was no claim at the path — nothing there, or a record already released — so
nothing was broken, `summary.changed` is 0 and the run exits 0. That is where
invariant 9 comes from for this verb rather than being arranged: the second `lock
break` on a path finds the record the first one wrote.

**The holder is reported here and nowhere else afterwards.** The write replaces
their record with a released one that still carries their name, so a later `lock
status` cannot tell a break from a clean release. That cost is the one already
accepted for `locking.break_expired`, where the takeover overwrites the record
entirely: the path is not the audit trail, the run document is. `SOPULI-W002` says
the same thing in words.

An unexpired lock is **not** in this array — it is `denied`, on exit 7, with the
holder named. Same object, same wording as a rotation that lost the same lock,
because it is the same question being answered to the same person.

### `targets`, emitted by `doctor`

One entry per target, and deliberately **not** `results[]`.

`result` is per (account, target). It requires an `account` and a `state` from a
vocabulary that is entirely about credential sync — `IN_SYNC`, `DRIFT`,
`ACCOUNT_MISSING`. `doctor` manages no credential and touches no account, so
every one of those words would have meant something else: `IN_SYNC` on a healthy
target claims a sync that never happened, and `SKIPPED` means *we chose not to
try*.

Widening `result` was the alternative — make `account` optional, add states —
and it is a major change: a consumer reading `result.account` unconditionally
breaks. Adding a section is the minor rule again, for the fifth time.

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

**`reachable` is the field to branch on, and everything else is absent rather
than empty.** A target that could not be reached has no scope, no capabilities
and no assertion result. An empty `capabilities` array there would read as a
database that supports nothing, which is a different and much more alarming
claim than *nobody could get to it*.

**`asserted` is absent when the target asserts nothing**, rather than present
with `matches: true`. `01-configuration.md` §3a is explicit that an assertion
nobody makes is not a gap, and an object claiming a match would be reporting
agreement with a claim that was never made.

### `targets[].privileges`, emitted by `doctor --check-privileges`

What the service account holds, from `02-oracle-privileges.md` §2's and §3's
lists. Added in 1.12 and owed prose here ever since; written now by #341, the
first change to alter what one of its properties means. Pasted from a run against
a PDB service account on 26ai Free 23.26.2.0.0:

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

**Absent unless the flag asked, and whole whenever it is present** — empty arrays
included, which is why every property is required. That is ADR-006's E6 applied
to an audit: a section that appeared only on a problem could not be quoted as
evidence that there was none. *Not asked* and *asked, nothing found* are
different facts, and a consumer that tested the section for truthiness would
merge them.

**The findings are not here.** `over_granted` lives on `scope`, where the schema
has had it since 1.10, and two copies of one finding are two things that can
disagree. A consumer reads what was found from `scope.over_granted` and how far
the audit reached from this section.

**`held`/`missing` and `over_granted` are independent questions**, not two ends
of one scale: what the account needs and may not have, and what it has and must
not. An account can be in both states at once, which is what a half-finished
debugging session leaves behind. `missing` is spelled as the `GRANT` to issue,
because the point of an entry is that somebody has to go and issue it.

**`unaudited` and `unreadable` are the report's two ways of saying it did not
look**, and they are not interchangeable:

- **`unaudited`** is a row of §3's list this run did not check. Never empty on
  Oracle — `EXECUTE ON DBMS_LOCK` is an object privilege that no view the audit
  reads carries. `SYSDBA` and `SYSOPER` join it only where §2's *optional*
  `SELECT ON V$PWFILE_USERS` was not granted; where it was, they are audited like
  anything else and a held one appears in `scope.over_granted` (#341). Before
  that they were named unaudited unconditionally, which was true of the default
  install and not of every install.
- **`unreadable`** is a view that *raised*, which makes the audit partial and
  changes how `over_granted` should be read. A grant the product documents as
  optional never lands here: declining it is the documented install, and a run
  that called every correct install partial would teach a reader to skip the line
  that matters when a view really was refused.

Both reach the text report and `targets[].warnings` as caveats, on every run
rather than only on a bad one — including a line naming the `GRANT` that would
shrink `unaudited`, where one exists. Neither moves the exit code: P5 is decided
and `--check-privileges` warns rather than fails, because failing would block
somebody mid-incident over a condition they did not create.

### `install`, emitted by `doctor`

Which backends and drivers this build can serve, which the config asks for, and
where the two disagree. **On every run, not only on a mismatch** — that is
ADR-006 E6 and it is the whole shape of the section:

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

**Every registry entry appears, configured or not**, which is what makes the
third direction reportable at all: *installed and not configured*. Nothing else
in the tool looks that way round, and the gap between what a machine can do and
what it was asked to do is worth seeing before somebody is troubleshooting inside
it. An unconfigured backend is a row with an empty `vaults`, never an omission.

**`status` is three values and not a boolean**, because the two failing ones have
different remedies and only one of them is the reader's to run. `not_installed`
means the module is here and the client is not, and `install_command` is the line
to paste; `not_implemented` means this build has no module for it, which nothing
the operator installs changes — so a row in that state carries no install line,
however much its name suggests one exists. They are the same two conditions
`SOPULI-20001` and its `BackendNotImplementedError` sibling already separate, and
collapsing them here would send somebody to `pip` for something `pip` cannot
supply.

**Backends name their `vaults:` entries and drivers count their targets.** A
store is written out by hand, there are a handful, and its name is the thing to
go and look at. Targets are generated by the dozen from one `target_sets:` entry
and every one of them is already listed in full in `targets[]`, so naming them
again here would be a second copy of a fact the same document carries — the same
reasoning that makes `SOPULI-W006` one warning per driver *type*.

**A configured component this machine cannot serve fails the run, at exit 9.**
`config validate` warns over the identical fact and exits 0 (E4), and the two
commands answering differently is deliberate: one asks whether the file is
valid — it is — and the other asks whether this machine can reach what the file
names. Exit 9 rather than 1 is E5's number for the same condition when a command
*resolves* one, and `doctor` reporting it under a different number would give the
tool two answers to one question. `summary` is unaffected and still counts
targets: an install-shape failure is not a target that failed.

### `wallet`, emitted by `doctor`

Whether this machine has an Oracle wallet the run can authenticate with. P4 names
wallet readability in the same breath as client presence and `TNS_ADMIN`, and the
gap it closes is between *the variable is set* — which `doctor` already reported
— and *there is a wallet there this process can read*. Those are different facts
on every machine where a service runs as one user and a DBA tests as another.

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

**Absent when nothing in the estate uses `auth: external`**, which is the
opposite of `install`'s always-present rule and right for the opposite reason.
Install shape is a fact about the machine that is always true of it; this is a
fact about a configuration option most files never use, and a section warning
about a missing wallet in every document that never needed one is noise rather
than evidence.

**`directory` is not always `tns_admin`, and `from_sqlnet` says when it is not.**
`sqlnet.ora`'s `WALLET_LOCATION` moves the wallet, and the client follows it. A
survey that did not would report "no wallet" for a correctly configured estate —
sending somebody to fix a directory that was never wrong, which is worse than not
checking at all. A reader who checks the obvious directory and finds nothing has
to be able to see that the tool looked elsewhere.

**Presence is not access, so `files` holds what could actually be opened.** A
wallet owned by the account a service runs as is `is_file()` from every account
on the machine and opens from exactly one — which is the case this whole section
exists for, so it is measured by reading a byte rather than inferred from the
file existing. One that is there and unreadable lands in `unreadable[]` and does
not count towards `auto_login`: it is a different finding from a missing wallet,
because the remedy is different. A missing wallet is somebody to ask for one; an
unreadable one is already where it should be and owned by the wrong account.

**`auto_login` and not just `files`.** `ewallet.p12` alone is a wallet, and it
needs a passphrase this tool has no way to supply — so a directory holding only
that one cannot serve an unattended run, and the naive reading of *is there a
wallet here* says yes. That gap is the whole reason the field exists.

**Nothing here moves the exit code.** An unreadable wallet is not a separate
verdict: it rides on each target's own reachability, which the connection attempt
settles a moment later. The section explains the failure that is about to happen
rather than pre-empting it, and `SOPULI-W007` is the warning that carries the
explanation into the diagnostics array. A wallet other people can read is
`SOPULI-W008` and is likewise a warning, for the reason #213 settled for
over-granted accounts: it is somebody else's file, and refusing to run would
block the person who ran it over a condition they did not create.

**What is deliberately not checked.** The wallet is not opened. Confirming it
holds a credential for the alias means asking the Oracle client, and the
connection report already does that better than any inspection could — a target
that connects has proved its wallet works. What is left for this section is the
diagnosis when it does not.

### `vaults`, emitted by `doctor`

Every store the configuration declares: whether it answered, whether this run's
credential was accepted, and how far its clock is from this machine's. P4 names
vault reachability and clock skew in the same breath as client presence and
`TNS_ADMIN`, and the pairing is not arbitrary.

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

**The skew is not a health nicety.** `sopuli/lock/decide.py` compares a lease's
`expires_at` against *this* machine's clock and allows `CLOCK_SKEW` for the two
disagreeing (#83). A host minutes out takes over locks that are still live, or
refuses ones long dead — and the failure presents as a locking bug rather than as
an NTP problem. `tolerance_ms` is that allowance, reported so the verdict can be
checked rather than assumed.

**Three words, not a boolean.** `ok` is answering and able to serve this run;
`degraded` is answering and not — sealed, standing by, not initialised, or
refusing the credential it was opened with; `unreachable` is nothing recognisable
answering at all. The middle one earns its place because the reader's next move
differs: `degraded` sends somebody to the vault and `unreachable` sends them to
the network, and being sent to the wrong one costs an outage's worth of time.

**An answer the tool cannot read is `unreachable`, not `degraded`.** A proxy's
502 is not a Vault saying anything about itself, and treating it as evidence a
store is present is precisely what makes a survey worthless. The same fail-closed
rule `sopuli/store/hashicorp/_errors.py` applies to an unrecognised 400.

**Only `unreachable` moves the exit code**, and it moves it to 1 — the same as an
unreachable target, and if anything it deserves worse: the vault is master and
the direction is always vault → database (invariant 6), so a store nobody can
reach is an estate on which no `creds` verb can do anything. A degraded store and
a skewed clock leave the run at 0 and land in `diagnostics[]` as `SOPULI-W010`
and `SOPULI-W009`, which is #213's answer for over-granted accounts applied to
the same shape of question: `doctor` must not refuse to survey an estate over a
condition the person running it did not create.

**`summary` still counts targets.** A vault is not one, and inflating `failed` to
make the exit code look derivable would put a number in the document that no
entry in `targets[]` accounts for. The exit code is deliberately not a function
of the summary — `install` made that true first, and this makes it true a second
way.

**Absent skew and zero skew are different answers.** A backend exposing no server
time has `server_time`, `skew_ms` and the three fields around it all absent; two
clocks that agree have `skew_ms: 0`. Substituting this host's clock for a store
that cannot report one would produce a confident zero, which is the single
confusion the whole measurement exists to avoid.

**The measurement says what it does not know.** The store answered somewhere
inside the round trip, so half the trip — plus whatever the store rounds its own
answer to — is the width of what one request cannot pin down. That is
`skew_uncertain_by_ms`, and `skew_within_tolerance` is judged against the
*unexplained* part of the difference. A slow link therefore cannot manufacture a
skew finding, which matters because an operator who once chases a clock that was
fine stops believing the next report. HashiCorp answers in whole seconds, so a
perfectly synchronised pair reports a small negative figure rather than zero.

**`authenticated` absent means not asked.** `sys/health` takes no token, so a
store whose credential expired last night answers it perfectly — the token is
looked up separately, and only where a sealed store would not refuse the lookup
and have the refusal blamed on the credential. Absent, `false` and `true` are
three findings and none collapses into another.

**`detail` and `error` are not two spellings of one thing.** `detail` is always
the one-line answer to *why*, whichever way the store failed. `error` appears
only where something **threw** — a backend with no module, a client that is not
installed, a refused login — because only those carry a category and a code worth
branching on. So the reading order is `status` to branch, `detail` for the
reason, `error` when there is a machine-classified cause to go with it.

**Nothing here writes.** P5 makes `doctor` mutate nothing, and a reachability
check that proved itself by leaving a lease behind would be a measurement that
changes what it measures — on a lock mount, one a concurrent rotation notices.

### `constraints`, emitted by `creds generate`

What the estate said a password may be, read before one was drawn (UC-1 §4
step 2, #317). One entry per target asked, and one per account that answered.

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

That is a real document from a tier-1 run, not a sketch — including the second
account, whose profile was created in the root with `CONTAINER=ALL` and whose
verify function therefore reads as the literal `FROM ROOT` from inside the PDB.

**Readings, never a verdict.** Nothing here predicts that a password will be
accepted. Only the byte count *binds* anything: a verify function is arbitrary
PL/SQL that cannot be consulted (invariants 13 and 14) and a reuse history is
hashed, so `ORA-28003` and `ORA-28007` stay unpredictable before the statement is
issued and #312 answers them by redrawing. The section says what the run found
out; `diagnostics[]` says what it could not check.

**Three states for a verify function, not a nullable name.** `named`, `none` and
`unknown` are three answers, and a missing name would merge the last two into the
one reading that misleads — *nothing will judge this password*. §5's
`--preflight` rule applies here: not knowing is not a finding. The run above is
the case that makes it concrete: the account reported `unknown` was in fact
guarded, and applying its staged password was refused with `ORA-28003`.

**`unknown` is narrower than "a PDB".** Measured on 26ai: a **common** profile
read from inside a PDB answers `FROM ROOT`; a local profile read from the same
session answers with its function's name; and `DEFAULT`, which is common,
answers `NULL`. So the unreadable case is a user-created common profile seen from
a PDB, and treating every PDB as unknowable would refuse to report the ordinary
one.

**`source` has two values and no third.** `targets` means at least one database
answered; `policy` means none did and the policy's declared length governed,
which UC-1 §4 makes a legitimate fallback rather than a failure. A run that asked
*nothing* — `--offline` — omits the section entirely, because "we could not find
out" and "we did not look" are answers a report must never merge. Absence is
therefore the third value, and it is the only one that needs no name.

**Present even when nothing answered**, which is `install`'s rule rather than
`wallet`'s: the section is evidence that the estate was consulted, and one that
appeared only when something was wrong could never be quoted as proof that
nothing was.

**Every reading is kept.** A limit is a byte count *and* the character set it is
counted in, so 128 bytes of `WE8MSWIN1252` and 128 of `AL32UTF8` do not contain
one another — "stricter" is a partial order. `max_password_bytes` at the top is
what a *generated* password was drawn against, which consults no character set;
`targets[]` carries them all, because a *supplied* password has to satisfy each.

**`measured_as` is the codec, and it is not implied by `character_set`.** An
unmapped character set falls back to `ascii` deliberately (`driver/oracle/limits.py`),
which refuses a non-ASCII password rather than guessing its width — and a reader
whose database refuses one should see that here rather than deduce it from the
refusal.

**The reuse resources are strings.** `UNLIMITED` is a word in a column a reader
expects numbers in, and the two resources interact: one of them `UNLIMITED`
beside a number is not the same regime as both being numbers. They are reported
rather than interpreted, because this run measured neither the interaction nor
the hashed history.

### `results[].changed` vs `results[].state`

Deliberately separate:

- `state` is **what is true now** (`IN_SYNC`, `DRIFT`, `ROLLOVER_ACTIVE`, …)
- `changed` is **whether this run did anything**

An idempotent re-run of `apply` reports `state: IN_SYNC, changed: false`. A
monitoring system watches `state`; a change-management system watches `changed`.
Collapsing them into one field breaks one of the two consumers.

`creds apply` is where the two visibly come apart (#259). It reaches `IN_SYNC`
two ways — by changing the password, and by finding the database already had it
— and the second is invariant 9's requirement on this verb. `summary.ok` and
`summary.changed` differ for the same reason, and `summary.unchanged` is the
complement of `changed` rather than of `ok`: it answers *how much did this run
leave alone*.

**`actions[]` carries the sequence, not just the outcome.** UC-1 §5 is a flow,
and an `apply` entry holds up to four steps in the order they ran — the
pre-flight `verify`, the `password_set`, the `verify` that confirmed it, and the
`vault_promote`. `applied` on each is whether the step *ran*, never whether it
succeeded, so a `verify` with `applied: false` is a login the lockout guard
declined and a `password_set` with `applied: false` is a password that was
already right. A single action per result would make "we did not need to change
it" and "we changed it and could not confirm it" the same row.

**`results[].rollover` is emitted for every account `apply` acted on** (#262),
not only for the ones with an open window. `active: false` beside a
`profile_rollover_time` of `"1"` is a different fact from `active: false` beside
a `null`: the first says a window opened and was closed inside the run
(`--strategy direct`), the second says none was ever possible. Together with the
`rollover_finish` action they make the regime each account ran under recoverable
from the document, which is why `--strategy` needed no new field.

**A promotion is reported on every account in the document it promoted**, with
the version it produced, because they shared one compare-and-set. Where the
database was changed and the document was *not* promoted, every account involved
carries a `warning` saying so: applications read `current`, and until the
promotion lands they are reading a password part of the estate no longer has.
That is UC-1 §8's highest-severity row, and it is a per-result warning rather
than a run-level diagnostic so that it survives whatever a consumer filters
`results[]` down to.

---

## 3. Enumerations

Enums are part of the contract. Adding a value is a minor version bump; removing
or renaming one is major.

**`state`** — `IN_SYNC`, `DRIFT`, `PENDING_APPLY`, `ROLLOVER_ACTIVE`,
`ACCOUNT_MISSING`, `LOCKED`, `EXPIRED`, `UNVERIFIABLE`, `SKIPPED`, `ERROR`,
`VAULT_ONLY`

**`VAULT_ONLY` is what `creds generate --promote` reports** (#257): the vault
holds this password and no database has been asked. None of the other values
would have been true of that result. `IN_SYNC` asserts a match nobody checked;
`DRIFT` asserts a comparison that never happened — and exits 3, so a successful
adoption would exit non-zero; `PENDING_APPLY` sends `check` and `apply` looking
for a `pending` that is not there; and `UNVERIFIABLE` means *tried and could
not*, which `check` leans on. Reusing `SKIPPED` was weighed and refused as a lie,
and emitting no `results[]` at all was refused because it would leave the one verb
that writes the field applications read with nothing machine-readable to say about
what it changed. So the enum gains a value, which this section's own first line
makes a **minor** bump. The cost is a consumer switching exhaustively over
`state`, paid once here rather than argued again per verb, and `sopuli-run-1.20`
carries it.

**Not `PENDING_APPLY` with the stage swapped.** That state says a rotation is in
flight and something is waiting to be applied; this one says there is none. What
follows a `VAULT_ONLY` is still `creds apply` — it finds the databases behind the
vault and converges them — but a consumer counting rotations in progress must not
count these, and `check` looking for a `pending` here would find nothing and be
right.

**`action_kind`** — `none`, `generate`, `vault_write_pending`, `vault_promote`,
`vault_rollback`, `password_set`, `rollover_start`, `rollover_finish`,
`account_unlock`, `attribute_set`, `verify`

The action list is a readable trace of the UC-1 §8 sequence. A completed rotation
of one account against one target reads:

```json
"actions": [
  { "kind": "generate",            "applied": true },
  { "kind": "vault_write_pending", "applied": true },
  { "kind": "password_set",        "applied": true },
  { "kind": "verify",              "applied": true },
  { "kind": "vault_promote",       "applied": true }
]
```

An interrupted one stops partway, and where it stopped tells you exactly which
recovery from the UC-1 §8 table applies.

`attribute_set` is what UC-1 §5's remaining attributes report as, starting with
profile assignment (#301). One kind for several attributes is deliberate: it is
what the value has meant since the schema was written, and the alternative was a
minor bump and a new enum value per attribute on a contract consumers branch on.
**The detail is what distinguishes them** — `"profile ACME_LEGACY_PROF ->
ACME_APP_PROF"` — so every implementation writes one.

`account_unlock` is UC-1 §5's first opt-in attribute (#300) and reads at the head
of the list, because that is where it happens: an unlock is what makes the
pre-flight login worth attempting. It is emitted whenever the policy declared the
attribute, `applied: false` where the account was not locked — a consumer
inferring "not declared" from "not present" would be reading the policy out of the
results. `results[].changed` is the union of every mutation on the row, so an
account that was unlocked and needed no new password is `changed: true` with a
`password_set` that did not apply.

**`error.category`** — `config`, `selection`, `connectivity`, `authentication`,
`authorization`, `capability`, `policy`, `vault`, `database`, `lock`, `internal`.
Categories are stable; `error.code` carries the vendor detail (`ORA-01017`) or
a tool-side code from the registry below (`SOPULI-20001`). Consumers branch on
category, log the code.

**`install.*[].status`** — `installed`, `not_installed`, `not_implemented`.
Three and not a boolean, because the two failing values have different remedies:
`pip` fixes one and nothing the operator installs fixes the other.

**`verification.method`** — `login`, `hash`, `both`, `none`, with
`lockout_margin_hit` recording the UC-1 §7 case where the tool *declined* to try
a login because the account was near its threshold. That is a distinct outcome
from a failed verification and must not be reported as drift.

### Diagnostic codes

`diagnostic.code` is optional and, where present, comes from this registry. A
code is contract in the way an enum value is: adding one is a minor bump, and
changing what one means is not a bump at all but a lie. The *message* around it
is not contract and may improve.

| Code | Meaning |
|---|---|
| `SOPULI-W001` | A store in this run is `locking: advisory-only`, so its lock record was written without compare-and-set. The run has no fence: two runs starting in the same second can both believe they hold the lock (#83) |
| `SOPULI-W002` | A lock was taken from its holder: automatically, because it was past its expiry and `locking.break_expired` permits that, or deliberately by `sopuli lock break` (#149). The previous holder is fenced — its next check will fail — but it may have applied changes before that |
| `SOPULI-W003` | A `vaults:` entry names a backend this machine cannot serve. The config is valid and the install is incomplete (ADR-006, E4), and what that is worth depends on the question asked: `config validate` warns and exits 0, `doctor` reports it as an `error` and exits 9 (E6), and any command that resolves the store to a client fails with `SOPULI-20001` |
| `SOPULI-W004` | A store in this run is `tls.verify: false`, so its certificate is not checked and anything on the path can read every secret that crosses. Under P3's safety ratchet, so no layer can weaken it further — but nothing in the run undoes it either (#135, ADR-005) |
| `SOPULI-W005` | A store in this survey has no `list` capability, so `lock status` reported only the paths the configuration declares. A record left at a path the file no longer names would not appear — in that store. Everything reported is accurate; the survey is narrower than it looks (#150) |
| `SOPULI-W006` | A `targets:` entry names a driver this machine cannot serve (#170), weighed by each command exactly as its store counterpart `SOPULI-W003` is. They are deliberately two codes: one meaning "some backend or other is missing" would leave a consumer unable to tell a store it cannot reach from a database it cannot reach, which are different outages. Emitted once per driver *type* rather than once per target, since an estate generates targets by the dozen from one `target_sets:` entry |
| `SOPULI-W007` | An estate uses `auth: external`, and this machine has no auto-login wallet this process can read (#215). The connection will fail as an Oracle *login* error, which is the most misleading way for a file-permission problem to appear; this says why in advance. A warning and not a verdict — the target's own reachability decides the run |
| `SOPULI-W008` | A wallet file in this run's `TNS_ADMIN` is reachable by somebody other than its owner (#215, P4). An auto-login wallet is a credential: whoever can read it can authenticate as the account it holds. `doctor` warns and never fails, for the reason #213 settled for over-granted accounts |
| `SOPULI-W009` | This machine's clock is further from a configured store's than the advisory lock tolerates (#216, #83). A lease's expiry is compared against the local clock, so a run on this host will take over locks that are still live or refuse ones long dead — and the failure looks like a locking bug rather than an NTP problem. `doctor` warns and never fails: the condition is real, this run did not create it, and refusing to survey an estate over it would block the person who ran it |
| `SOPULI-W011` | This run's lock was taken over by another while it was running, found at a fence check (#282). It stopped before its next mutation and promoted nothing, so the vault still advertises what it did before — but whatever it had already applied to a database stands. The code exists because the exit code cannot say it: a fenced-out run exits 4 exactly like one whose targets failed, and the second is repaired by running `apply` again while the first must not be. The other side of the same event is `SOPULI-W002`, and they are two codes because *broke somebody's lock* and *had mine broken* are opposite things to be paged about |
| `SOPULI-W010` | A configured store answered and cannot serve this run: sealed, standing by, not yet initialised, or refusing the credential it was opened with (#216). Distinct from a store that could not be *reached*, which fails the run instead and gets no code — here something answered, and what the reader does next is go and look at the vault rather than at the network |
| `SOPULI-W014` | A login **succeeded** and the server attached a diagnostic to the connection rather than raising (#322). A password in its grace period is the ordinary cause: it connects, and Oracle puts the notice on the connection where nothing was reading it. The verification passed and the message is carried verbatim with its vendor code — the code is *data*, never matched against a list, because one condition is `ORA-28098` or `ORA-28011` on the same release depending on the profile. It can appear beside `SOPULI-W013` for one account: those are two sources — what `ACCOUNT_STATUS` says, and what the server said on this login — and they are reported side by side rather than deduplicated, because telling them apart would need exactly the code list this refuses |
| `SOPULI-W015` | `creds generate` could not read a target's password constraints, so the policy's declared length governed the draw (#317, UC-1 §4 step 2). A **warning** rather than an error because §4 makes the fallback legitimate — staging a password for an estate that is down is a thing operators do, and the run staged one; what it may not do is stay quiet, because a password drawn against a policy alone and one drawn against a database that answered are different claims about the same run and nothing in the password distinguishes them. One code for both shapes — no target answered, and some did — because the remedy is identical and the message names which targets either way; a partial read is the same condition with fewer databases missing. `--offline` emits nothing: it is the operator saying they know, and a warning that fires because a flag was passed teaches its reader to filter it |
| `SOPULI-W016` | An account's profile names a password verify function, or whether it names one could not be established — a common profile read from inside a PDB answers `FROM ROOT` (#317, UC-1 §4 step 2). **Reported and never acted on**: the function is arbitrary PL/SQL that cannot be consulted before the statement is issued (invariants 13 and 14), so this is not a prediction that the password will be refused, and `creds apply` redraws if it is. What it says is that something other than the policy will judge this password. The not-knowing shares the code because the consequence is identical — this run cannot tell you the password will be accepted — and the message says which of the two it is; what it must never do is report the unreadable case as *no verify function*, which reads as a guarantee. One per (target, profile), because that is where the function lives: forty accounts on one profile is one fact, not forty |
| `SOPULI-W017` | An account's profile restricts password reuse, and the run was given a password rather than drawing one (#317). **Only under `--from-stdin`**, which is why it is not part of `SOPULI-W016`: fresh randomness cannot collide with a hashed history, so a reuse warning on an ordinary draw would fire on every run and mean nothing on any of them — while a supplied password is whatever an external system dictated, and *the one it had last year* is an ordinary thing for one to dictate. The two resource values are carried and not interpreted: they interact, and the run measured neither the interaction nor the history |
| `SOPULI-W013` | An account's password is in its grace period: past `PASSWORD_LIFE_TIME`, inside the window `PASSWORD_GRACE_TIME` grants, and **still working** (#309, UC-1 §6.4). Emitted on `results[].warnings[]` beside the state rather than as a state, because `state` is one field and the account may be `IN_SYNC` or may have drifted — a value of its own would have to displace one of those answers and hide what the reader came for. Read from `DBA_USERS.ACCOUNT_STATUS`, so it is reported even on a run where no login was attempted; not from `ORA-28002`, which 26ai does not send |
| `SOPULI-W012` | A rotation promoted a secret document and then read a different password back out of it (#284, UC-1 §8 step 8). Every database took the new password and the promotion was acknowledged, so nothing needs undoing and `apply` converges what is left — but until the vault serves what it accepted, an application fetching `current` may get the old password. Its own code for the reason `SOPULI-W011` has one: the run exits 4, and so does a run with half its targets failed, and those two want opposite responses. Here the *databases* are the converged half and the vault is not, so the reader goes and looks at the store — replication lag on a mount with read replicas is the ordinary cause |
| `SOPULI-W018` | One of `02-oracle-privileges.md` §4's account guardrails could not be run against a target, because the fact it checks could not be read (#296). The run **proceeded** and the other four checks were applied. Today this is always check 3, the password file: `V$PWFILE_USERS` is outside §2's default grant set on purpose, so the code appears on a correctly installed estate and the optional grant is what removes it — which is what makes it a warning worth leaving on rather than one a reader learns to filter. It exists for #216's rule: the run exits 0 with every account applied, and nothing in the exit code, the states or `results[].overridden` says that one of five checks contributed nothing to that answer. **Not a refusal**, because the estate that cannot answer is the correct one and refusing would mutate nothing anywhere; **one per (target, check)**, because a missing grant is a property of the database and forty accounts on it is one fact; and **printed as well as serialised**, on #309's rule that a warning nobody can see in the default output is not surfaced |
| `SOPULI-W019` | A lock path was created without `cas_required`, because this run's store credential may not write path metadata (#390). The run's own lock was still taken under a compare-and-set and its fence held, so nothing in the result is wrong — what is missing is the store refusing an un-CAS'd write from **anybody else**, an operator with a vault CLI included. Its own code for #216's rule: the run exits 0 and the condition it describes is a property of the path that will still be there on the next run, which is the shape of thing a reader goes and fixes in the vault. **One per path**, not per store — the opposite of `SOPULI-W001`, and deliberately: advisory locking is one fact however many locks are held on it, while this names a path to repair. **Emitted only by the run that creates the path**; every later run finds the metadata, finds `cas_required` unset, and is refused at exit 5 instead |
| `SOPULI-W020` | The document `creds apply --repair` was handed is old enough to say so (#391). A **warning and never a gate**: a threshold that refused would have to be wrong for somebody, and the run it stopped would have been safe -- the set can only narrow (invariant 5) and a pair since repaired costs one login and reports `changed: false`, so a stale document is wasteful rather than dangerous. It **names the age** rather than quoting the threshold, because what the reader does with "eleven days" is decide whether that is still the estate they are looking at. Its own code on #216's rule: the run exits 0 having done less than the operator may have expected, and nothing else in the document says the narrowing came from something written last week. **Printed as well as serialised** (#309): the emitter writes the document or the text and never both, and the person who typed the flag is exactly who this is for |
| `SOPULI-W021` | The database would not say when an account's password was last set, so `results[].password_age_days` is absent and `creds status` prints `-` under `DB_PW_CHANGED` (#386). **The message says why**, because the two causes want different responses: a release with no `DBA_USERS.PASSWORD_CHANGE_DATE` (18c, 11.2) and no `SELECT ON SYS.USER$` to read `PTIME` instead — which a grant fixes — or a value that could not be read, which is worth investigating. It exists because a consumer cannot see a dash: a documented field that vanishes per target with nothing saying why is a hole in the contract. **One per result, on `results[].warnings[]`**, beside the field it explains, unlike `SOPULI-W018`'s per-target grouping — a consumer reading one result should not have to join it to a run-level array. The text output groups it per target. Emitted by `creds check` and `creds status`; informational, since nothing gates on the database's date (Q9) |

| `SOPULI-W022` | A target's admin credential was read from an environment variable (#477). P2 lists `env` last in its bootstrap order and **supports** it — an estate with no other way in is the case it exists for — so this is a flag and never a refusal; `01-configuration.md` §3a says twice that the source "stays flagged wherever it is reported", and until this code existed `Resolved.low_assurance` was computed on every run and read by nothing. It is #216's rule exactly: the run connects, succeeds and exits 0, and nothing else in the document says *how* the tool got hold of the credential — a reader cannot tell a run that authenticated from a wallet from one that used a variable a CI job exported. **The message names the variable**, from `Resolved.source`, because what the reader does next is go and look at where it is set. **One per target per run**, deduplicated on (code, target): a target may be resolved twice in one run — `creds apply --strategy` pre-flights and then applies — and the configuration did not change between them. Keyed on `admin.LOW_ASSURANCE` rather than on the method name, so a second low-assurance source is flagged without finding every reporting site again. **Emitted by every command that connects** — `doctor`, `account suspend`, `creds status`, `creds generate` (unless `--offline`), `creds check`, `creds apply`, `creds rotate` and `creds finish-rollover`, which is every verb that opens a database session today — and **printed by `doctor` alone**. The list is exhaustive rather than illustrative because the alternative is a consumer concluding that the verbs it omits do not carry the code; it is exhaustive *as of writing*, and the mechanism rather than the list is the guarantee: every one of them resolves its admin credential through `cli._admin_credential`, so a verb that starts connecting gets this without anybody remembering to add it. P2 asks for the flag *in output* and text is the default output, so something must print it; but the fact is a property of the *configuration*, identical on every run until the file changes, so a line under every rotation would be the warning a reader learns to filter. That is the same line the other printed notices draw: `SOPULI-W020` is printed because the stale document is the one the operator just passed, and `SOPULI-W018` because the unrun check is about this run's accounts. `doctor` is the verb whose job is to report on the setup, and `diagnostics[]` is where anything alerting reads it |
| `SOPULI-W023` | `account list` had no reset journal to read, so its `RESET_AT` column is empty for every row and `results[].reset_at` is absent (#490). The configuration declares no `reset_records:` block (#468), which is a **documented mode rather than a fault**: UC-2 §3.1 keeps the journal optional because the seen (`manual`) path may have no store at all, and that is the site it exists for. It is `SOPULI-W021`'s rule applied to the other date column — a documented column that vanishes with nothing saying why is a hole in the contract — and §2 asks for it by name. **One per run, not one per result**, and that is the difference from `SOPULI-W021` beside it: a missing journal is a property of the configuration and is identical on every row, while whether the database will say when *this* account's password changed can differ between two accounts on one target. **Allocated with the verb that raises it**, which turned out to be the listing verb and not the reset: #468 built the block and deliberately left this number unallocated, because a code with no emitter is what `SOPULI-W022` was written to fix. It says which absence it is, because the other one — a journal that holds no record for this account yet — is not a finding at all and gets no code |
| `SOPULI-W024` | `account reset-password` wrote no record of a reset, because the configuration declares no `reset_records:` block (#511). The run document and the database are the whole record of it, and **no advisory lock was taken on the account either** — two facts with one cause (UC-2 §3.3), and an operator told only the first would not learn that two concurrent resets are not serialised. **Raised at plan time**, before the password changes, which is what makes it worth saying at all: the operator who did not mean to run this way can still stop. A **documented mode rather than a fault**, for `SOPULI-W023`'s reason — the seen (`manual`) path may have no store at all — and distinct from it because that one explains an empty column in a listing and this one says a mutation went unrecorded |
| `SOPULI-W025` | A reset succeeded and its record could not be written (#511). **A warning on a successful run**, never a rollback and never a non-zero exit: the password has already changed and the person still needs it, so failing would report a false negative about the part that mattered (UC-2 §3.4). Separate from `SOPULI-W024` because the next move differs — an absent journal is a configuration somebody chose, and this is a store that answered: a revoked token, a policy granting read and not write, or a mount that is not there. The store's own message is carried **last** in the text, so its punctuation ends the sentence rather than reading as a fragment |
| `SOPULI-W026` | A password was delivered and the notification saying so could not be sent (#442). The account **and the target** are named, because a reset can notify once per target and two failures would otherwise read identically (#520). A warning on a successful run for `SOPULI-W025`'s reason and more easily: the notification carries nothing anybody needs (UC-2 §6.1 keeps it to "a password is ready"), so what is lost is that somebody must be told another way. The webhook URL is never in the message — it is itself a credential (C9), and `httpx` puts it in the text of its own errors, so the exception's class name is carried instead |

The registry is `sopuli/diagnostics.py`, and `tests/test_lock_view.py` asserts
that nothing emits a code the registry does not describe. **J3 is not thereby
answered**: what is settled is the spelling this document already used as its
example and that these warnings have codes. Whether *every* warning gets one
— the config layer's §10 findings still do not — and how numbers are allocated
across categories is the part still open. Every one was allocated by hand at the
moment something needed it, which is the evidence rather than the answer.

**What #216 did settle, narrowly and only for `doctor`, is when a finding gets a
code at all: one for what the exit code cannot tell you.** An unreachable store
fails the run, so anything watching the exit code already knows and the entry in
`vaults[]` names which store and why — exactly as an unreachable *target* has
been an entry and never a diagnostic since #212. A store that answered and cannot
serve, or a clock outside the lock's tolerance, leaves the run exiting 0 with
something still wrong, and that is what a diagnostic is for. This is a rule for
one command rather than an answer to J3, but it is the first time the question
"why does this finding have a code and that one not" has had one.

`SOPULI-W002` gained a second emitter in #149 and **did not gain a second
meaning**, which is the distinction the rule above draws. It has always meant *a
lock was taken from its holder*; what `lock break` adds is a person deciding it
rather than a config key. The wording in the table widened to cover both, and the
wording is not contract. A second code would have told a consumer alerting on
"somebody's lock was taken" that there were now two things to watch for.

### Error codes

`error.code` carries the vendor detail where there is one — `ORA-01017` comes
from the server and the tool passes it through. Where the condition is the
tool's own, the code is a `SOPULI-` one from this registry, under the same rule
as the diagnostics above.

| Code | Category | Exit | Meaning |
|---|---|---|---|
| `SOPULI-20001` | `config` | 9 | A `vaults:` entry names a backend whose client is not installed. The message names the store, its `type`, and the extra that supplies it (ADR-006, `01-configuration.md` §3a) |
| `SOPULI-20002` | `config` | 9 | A `targets:` entry names a driver whose client is not installed. The same shape as `SOPULI-20001` and for the same reason (ADR-006 E1, E5): `python-oracledb` is `sopuli-dba[oracle]`, and a driver that is declared but absent is fixed on this machine by the person reading the message (#170) |
| `SOPULI-20003` | `config` | 9 | `delivery.notify.method` names a channel whose client is not installed. The same shape and the same reason a third time (ADR-006 E5, E7): `webhook` posts with `httpx` from `sopuli-dba[notify]`, and a channel that is declared but absent is fixed on this machine by the person reading the message (#442). It is reached only by a run that had something to send — `config validate` reports the same condition as a warning at load, which is where an operator meets it first |

`SOPULI-20001` was this document's illustrative placeholder for a tool-side code
before it meant anything; #130 gave it something to mean rather than adding a
second number beside it.

**The category is `config`, not `capability` (ADR-006, E5).** `capability` names
what a *target* cannot do — a property of the database at the other end, which
nothing the operator does locally changes, and which `target_capability` reports
per target. A missing backend is not that: it is fixed on this machine, by the
person reading the message, with the command in the message. It belongs where an
unreadable config file and an unresolvable name already are, and exit 9 already
says *fix your configuration, not your command line* (`00-principles.md` P5). No
enum value is added — which is the point, since a consumer that already branches
on `config` handles this without a change.

---

## 4. Redaction

One rule, enforced in one place: **redaction happens at the serialiser, not at
each call site.** Every secret value the process holds is wrapped in a type whose
serialisation is the literal string `"***"`, and whose `__str__`/`__repr__` is the
same. Nothing in the codebase can accidentally emit one by forgetting a helper,
because there is no code path that produces the plaintext except the vault write,
the database driver call, `policy sample --reveal`, and UC-2's seen reset (#439,
built in #441). `tests/test_reveal_sites.py` pins that list by parsing `src/`, so
a fifth path fails the suite rather than being noticed in review.

Consequences that show up in the schema:

- `secret_ref` objects address a secret (`vault`, `path`, `field`, `version`,
  `stage`) and have **no value property at all**. There is nowhere to put a
  password. `version` is an integer and `stage` is the closed lower-case enum
  `current` / `pending` / `previous`, which C14 ratified rather than widened
  (`01-configuration.md` §7): the config layer refuses anything else before a
  document is ever emitted. `vault` is required here even though a written ref
  may omit the prefix — this object is emitted after resolution, when the store
  is known, and a plan that named a secret without naming its store would need
  precedence re-derived to read.
- a `sample` object has none either, for the same reason and with the same effect.
- `error.message` and `diagnostic.message` are documented as redacted. Driver
  exceptions are passed through a scrubber before they reach either.
- `password.applied` events carry the vault version, never the value.

### The two exceptions, and what keeps each narrow

`policy sample --reveal` prints generated passwords on purpose. It is allowed
because **a sample is not a credential**: nothing authenticates with it, it is
never stored, and it guards nothing — the property that makes `pwgen` safe and a
vault write dangerous.

What stops it from becoming a leak is structure rather than care:

| | |
|---|---|
| it is opt-in | the default output reports properties — length, bytes, class counts — and no value |
| it is text-only | `--reveal` with `--output json` is **refused**, not quietly downgraded |
| JSON cannot carry it | a `sample` object has no value property, so the section could not hold one even if asked |
| it is one call site | the only `reveal()` outside the tests is in `sopuli/output/policy_view.py`, findable by grepping one method name |

The output says the samples must not be used, because the realistic hazard is not
the printing. It is somebody liking sample 2 and pasting it into an `ALTER USER`
by hand, at which point a value that sat in a scrollback becomes a live credential.

The release gate from UC-1 §11 tests the rest: run everything at
`--log-level debug`, grep every artefact for the generated password, zero hits or
no release. `policy sample --reveal` is excluded by name — it is the one command
whose output is *supposed* to contain one — and in exchange the gate asserts the
narrower property above: no sample value in any JSON document, `--reveal` or not.
See `04-testing.md` §6.

#### The second exception: UC-2's seen reset (#439)

**Built** (#441). `account reset-password` on the `manual` delivery path prints a
working password once, under five structural guards. Written here because this
section is the redaction contract, and a contract that named only the first
exception would have contradicted the use case the moment the verb landed — the
failure #411 was raised about, where a settled result reaches one document and
leaves the others disagreeing.

**Nothing in this contract can carry the value**, which is the half that matters
here: `results[]` has no property a password could occupy, and the verb refuses
`--output json` and `--output jsonl` outright. Those are one guard asserted twice,
and the second is the one that survives somebody adding an output mode.

**Its justification is different, and weaker.** The first exception rests on a
sample being no credential at all. This *is* one, and somebody can log in with it.
What allows it is that the exposure is **deliberate, witnessed and time-limited**:
the operator selected the seen path, answered a prompt, and the password is expired
at the moment it is set, so the owner's first logon must change it.

Because the justification is weaker, the structure is **stricter** than the first
exception's — the same four guards plus a fifth that has no counterpart there:

| | |
|---|---|
| it is opt-in | non-default; `delivery.method: manual` selects it, and the unseen path is what an estate gets without asking |
| it is text-only | refused with `--output json` **and** `--output jsonl` |
| JSON cannot carry it | no property of a `result` can hold a password, `--output` notwithstanding |
| it is one call site | one `reveal()`, in the seen path's own view, reachable only when the method is `manual` |
| **stdout must be a terminal** | the guard `--reveal` has none of, and the one the argument rests on: a value redirected to a file or captured in a CI log outlives the single logon it is good for, because a log is read later and by other people, and expiry does not unpublish it |

Two more things bound it and are not redaction rules, so they live in `CLAUDE.md`
invariant 2 and UC-2 §6 rather than here: it is confirmed every time with
`--confirm` **not** answering the prompt, and `force_expire: true` is required on
the method.

**The release gate treats it as it treats `policy sample --reveal`**: excluded by
name from the grep, since its output is supposed to contain a password, and in
exchange it must satisfy the narrower assertion — no password in any JSON document,
in any jsonl event, or in any log sink, whatever the delivery method.

---

## 5. Streaming events

```jsonl
{"schema_version":"1.0","event":"run.started","seq":0,"ts":"…","correlation_id":"…"}
{"schema_version":"1.0","event":"plan.resolved","seq":1,"ts":"…","correlation_id":"…","data":{…}}
{"schema_version":"1.0","event":"lock.acquired","seq":2,"ts":"…","correlation_id":"…","account":"ORDERS_APP","data":{"vault":"vault-prod","path":"apps/acme/db","mode":"cas","fence":41}}
{"schema_version":"1.0","event":"target.started","seq":3,"ts":"…","correlation_id":"…","target":"cdb1-pdb-orders"}
{"schema_version":"1.0","event":"password.applied","seq":4,"ts":"…","correlation_id":"…","target":"cdb1-pdb-orders","account":"ORDERS_APP","data":{"vault_version":8}}
{"schema_version":"1.0","event":"target.finished","seq":5,"ts":"…","correlation_id":"…","target":"cdb1-pdb-orders","account":"ORDERS_APP","data":{…result…}}
{"schema_version":"1.0","event":"run.finished","seq":9,"ts":"…","correlation_id":"…","data":{"summary":{…},"exit_code":0}}
```

`seq` is monotonic within a run, so a consumer can detect truncation — which
matters because the interesting failure mode is the process dying mid-rotation.
A stream that ends without `run.finished` means the run did not complete, and the
last `seq` says where it stopped.

Payload shapes are reused, not redefined: `target.finished.data` is a `result`
object, `run.finished.data` carries `summary` + `exit_code`, `plan.resolved.data`
is a `plan`.

The three `lock.*` events were in the enum from 1.0 and now have a payload. Each
carries the store, the path and the fence — `lock.denied` carries the holder
instead of a fence, matching `lock.denied` in the run document. `account` stays
on the event as a label, which is what it is: the lock is keyed on the path, and
two accounts sharing one document contend on one lock. A consumer grouping by
`account` alone would report that contention as two independent locks.

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

# follow a live rotation
sopuli creds rotate --application orders-app --output jsonl \
  | jq -r 'select(.event|test("target|password|vault")) | "\(.seq) \(.event) \(.target // "-")"'

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

**1.28 became 1.29 when a hand-over could be described without being performed**
(#444). One additive change: **`results[].handover`**, an object carrying
`accessor` and `expires_at`, emitted on an unseen delivery and absent on the seen
path.

**It exists because `delivered` could not grow.** That property is a string and
its own description says "never a value and **never a destination**", so the
accessor could not go in it without a rename — major, under §8, to answer a
question no consumer had asked. A sibling object also generalises where a widened
string would not: `vault_path` (#447) will report a path here, `one_time_link`
(#445) a link id, and each is the same *kind* of fact about a hand-over.

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
emitter, for 1.1's reason exactly: `--output jsonl` is unimplemented (#9), so this
extends an artefact already ahead of its stream, and the word is registered with
the change that knows why the event exists. Neither it nor `password.displayed`
carries the password, and neither carries the retrieval credential — a consumer
that wants to tie a stream to a vault's audit log reads `handover.accessor` from
the run document.


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
emitter since it was published, because `--output jsonl` is unimplemented (#9),
so this is extending an artefact that is already ahead of its stream rather than
creating a new inconsistency. The word is registered with **the change that
causes the exposure** rather than with the one that will carry it, because the
change that knows why the event exists is the one that should name it.

**What records the exposure today is the run document**, which every run has:
`results[].delivered` says the method was `manual`, and `manual` is by definition
the path that shows somebody a password. `password.displayed` is what a *stream*
consumer will read when there is a stream.

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
unimplemented *yet*: `admin.install` stays
in the enum on exactly that ground, because the verb is planned
(`../local-testing.md`) and §8 has tolerated a name published ahead of its code
since `plan`, `results` and `lock`. What made `creds.promote` different is that
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

The two diagnostic codes that come with it, `password_redrawn` and
`password_not_redrawn`, are a registry addition of the kind 1.15 → 1.16 was:
`diagnostic.code` is an open string, so neither changes the schema file.

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
| J1 | Should `--output json` stream nothing until completion, even for long runs? | yes — a partial JSON document is worse than none; `jsonl` covers the streaming case |
| J2 | Include `plan` in every run, or only with `--dry-run`/`--verbose`? | every run; it is small and makes plan-vs-result diffing mechanical |
| J3 | Stable machine-readable codes for warnings (`SOPULI-W014`) | yes, and they get a documented registry — otherwise consumers grep messages. **Opened, not answered**: §3 now carries a registry with the two codes the advisory lock needed (#83), a third for a configured-but-uninstalled backend (#130), and an error-code registry beside it holding `SOPULI-20001`. The config layer's other warnings still have none. What is left is the policy — which warnings get a code, and how numbers are allocated across categories; #130 allocated two by hand and did not settle it, and #317 allocated `SOPULI-W015`, `SOPULI-W016` and `SOPULI-W017` the same way, and #296 `SOPULI-W018` — following the established practice rather than answering the question, which stays open |
| J4 | Emit a top-level `hostname`/`pid` for log correlation | probably, under `invocation.actor` |
| J5 | OpenTelemetry span export alongside JSON | later; `correlation_id` is already the trace id in spirit |
| J6 | Should the event stream be resumable after a crash? | no — re-run instead; `check` establishes truth cheaply |
| ~~J7~~ | ~~Does `--output json` emit a run document on a usage error?~~ | *resolved 2026-08-13 (issue #8): no, and exit 2 is the only code that never does. §6 states the rule and P5 gained exit 9 so that a bad config file — which has a perfectly good invocation — is no longer on the same code as a bad command line.* |

# sopuli-dba — JSON output contract

Status: draft / sketch, **partly implemented**. The run document, `--output
text|json`, colour resolution, the `config` section, `diagnostics` and
`invocation.selection.select` are real and validated against the schema in CI
(`sopuli/output/`). `--output jsonl`, `plan` and `results` are not written yet,
so everything about them here is still a sketch, and so are the other members of
`invocation.selection`.

`diagnostics` carries what §10 of `01-configuration.md` calls warnings: findings
the loader decided not to refuse to run over. They are run-level because a config
warning belongs to no single target, and `level` is `warning` for all of them so
far — the config layer has no other severity to report. Every command that loads
a config emits them, `config show` in both its views as well as
`config validate`: a warning that reached only the text output would be invisible
to the scheduler, which is the reader that most needs it. A run with nothing to
report omits the key rather than carrying an empty array.
Schemas: [`../schemas/sopuli-run-1.4.schema.json`](../schemas/sopuli-run-1.4.schema.json),
[`../schemas/sopuli-event-1.0.schema.json`](../schemas/sopuli-event-1.0.schema.json)
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

Nothing there is a new category: each is a field the JSON already carries, so
the two views still cannot disagree. **The result palette is deliberately not
defined yet** — nothing emits a `state`, and a mapping written before there is
anything to map is the renderer-against-guesses ADR-003 warns about. It arrives
with `creds check`.

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
  results    [ { account, target, scope, secret, state, changed, actions[],
                 verification, rollover, error, warnings[] } ],
  summary    { total, ok, changed, drift, unverifiable, skipped, failed, by_state },
  diagnostics[],
  exit_code
}
```

Five parts of it are worth explaining, because they encode decisions rather than
just data.

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

Two rules about the pair, both load-bearing:

**`source_detail` is a location, never a value.** The flag as typed (`-o` records
as `-o`), the variable name, the config key. It exists so somebody can find the
thing in their own command line or CI job definition — which is why the config
layer points at `profiles.ci.verify.method` rather than just `"profile"`.
`--vault-token` names the flag; the token never appears. That keeps the field
inside §4's redaction rule for free, because no code path puts a value there at
all.

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

### `results[].changed` vs `results[].state`

Deliberately separate:

- `state` is **what is true now** (`IN_SYNC`, `DRIFT`, `ROLLOVER_ACTIVE`, …)
- `changed` is **whether this run did anything**

An idempotent re-run of `apply` reports `state: IN_SYNC, changed: false`. A
monitoring system watches `state`; a change-management system watches `changed`.
Collapsing them into one field breaks one of the two consumers.

---

## 3. Enumerations

Enums are part of the contract. Adding a value is a minor version bump; removing
or renaming one is major.

**`state`** — `IN_SYNC`, `DRIFT`, `PENDING_APPLY`, `ROLLOVER_ACTIVE`,
`ACCOUNT_MISSING`, `LOCKED`, `EXPIRED`, `UNVERIFIABLE`, `SKIPPED`, `ERROR`

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

**`error.category`** — `config`, `selection`, `connectivity`, `authentication`,
`authorization`, `capability`, `policy`, `vault`, `database`, `lock`, `internal`.
Categories are stable; `error.code` carries the vendor detail (`ORA-01017`,
`SOPULI-20001`). Consumers branch on category, log the code.

**`verification.method`** — `login`, `hash`, `both`, `none`, with
`lockout_margin_hit` recording the UC-1 §7 case where the tool *declined* to try
a login because the account was near its threshold. That is a distinct outcome
from a failed verification and must not be reported as drift.

---

## 4. Redaction

One rule, enforced in one place: **redaction happens at the serialiser, not at
each call site.** Every secret value the process holds is wrapped in a type whose
serialisation is the literal string `"***"`, and whose `__str__`/`__repr__` is the
same. Nothing in the codebase can accidentally emit one by forgetting a helper,
because there is no code path that produces the plaintext except the vault write,
the database driver call, and `policy sample --reveal`.

Consequences that show up in the schema:

- `secret_ref` objects address a secret (`vault`, `path`, `field`, `version`) and
  have **no value property at all**. There is nowhere to put a password.
- a `sample` object has none either, for the same reason and with the same effect.
- `error.message` and `diagnostic.message` are documented as redacted. Driver
  exceptions are passed through a scrubber before they reach either.
- `password.applied` events carry the vault version, never the value.

### The one exception, and what keeps it narrow

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

---

## 5. Streaming events

```jsonl
{"schema_version":"1.0","event":"run.started","seq":0,"ts":"…","correlation_id":"…"}
{"schema_version":"1.0","event":"plan.resolved","seq":1,"ts":"…","correlation_id":"…","data":{…}}
{"schema_version":"1.0","event":"lock.acquired","seq":2,"ts":"…","correlation_id":"…","account":"ORDERS_APP"}
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

**One rename has happened under 1.0, deliberately.** `actor.scheduled` became
`actor.unattended` when run context moved into profiles
(`01-configuration.md` §5). By the rule above that is a major change, and it was
made in place anyway: no released build ever emitted the property — it is written
only when true and nothing ever set it — so there is no consumer to overlap with.
The rule holds from the first release that emits a populated `actor`; this is the
grace before it. A second rename does not get the same treatment.

Every release validates its own sample outputs against the published schema in
CI. The schema is the test fixture, not documentation written afterwards.

---

## 9. Open questions

| # | Question | Leaning |
|---|---|---|
| J1 | Should `--output json` stream nothing until completion, even for long runs? | yes — a partial JSON document is worse than none; `jsonl` covers the streaming case |
| J2 | Include `plan` in every run, or only with `--dry-run`/`--verbose`? | every run; it is small and makes plan-vs-result diffing mechanical |
| J3 | Stable machine-readable codes for warnings (`SOPULI-W014`) | yes, and they get a documented registry — otherwise consumers grep messages |
| J4 | Emit a top-level `hostname`/`pid` for log correlation | probably, under `invocation.actor` |
| J5 | OpenTelemetry span export alongside JSON | later; `correlation_id` is already the trace id in spirit |
| J6 | Should the event stream be resumable after a crash? | no — re-run instead; `check` establishes truth cheaply |
| ~~J7~~ | ~~Does `--output json` emit a run document on a usage error?~~ | *resolved 2026-08-13 (issue #8): no, and exit 2 is the only code that never does. §6 states the rule and P5 gained exit 9 so that a bad config file — which has a perfectly good invocation — is no longer on the same code as a bad command line.* |

# sopuli-dba — JSON output contract

Status: draft / sketch. Schemas validate; nothing is implemented.
Schemas: [`../schemas/sopuli-run-1.0.schema.json`](../schemas/sopuli-run-1.0.schema.json),
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

**Meaning is never carried by colour alone.** Drift has its own exit code (3)
because schedulers alert on it; a human needs that distinction without colour
too — a symbol or a word, with colour as reinforcement. This makes the
`NO_COLOR` path lossless rather than degraded, and it is the accessibility
floor.

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
  plan       { units[], shared_secrets[], confirmation_required, blast_radius },
  results    [ { account, target, scope, secret, state, changed, actions[],
                 verification, rollover, error, warnings[] } ],
  summary    { total, ok, changed, drift, unverifiable, skipped, failed, by_state },
  diagnostics[],
  exit_code
}
```

Four parts of it are worth explaining, because they encode decisions rather than
just data.

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
                   "source_detail": "policies.app-standard.verify.scheduled_method" }
```

This is the machine-readable form of `config show --explain` (P3). When someone
asks why a scheduled run behaved differently from their interactive one, the
answer is in the output they already have, not in a re-run with `--debug`.

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
because there is no code path that produces the plaintext except the vault write
and the database driver call.

Consequences that show up in the schema:

- `secret_ref` objects address a secret (`vault`, `path`, `field`, `version`) and
  have **no value property at all**. There is nowhere to put a password.
- `error.message` and `diagnostic.message` are documented as redacted. Driver
  exceptions are passed through a scrubber before they reach either.
- `password.applied` events carry the vault version, never the value.

The release gate from UC-1 §11 tests this: run everything at `--log-level debug`,
grep every artefact for the generated password, zero hits or no release.

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

The pairing that makes scheduling work:

```bash
sopuli creds check --application orders-app --scheduled --output json > result.json
case $? in
  0) ;;                                     # in sync, say nothing
  3) alert "credential drift" < result.json ;;   # distinct: DRIFT, not a failure
  4) alert "partial rotation — needs apply --repair" < result.json ;;
  6|7) alert "sopuli could not run" < result.json ;;
  *) alert "sopuli failed" < result.json ;;
esac
```

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

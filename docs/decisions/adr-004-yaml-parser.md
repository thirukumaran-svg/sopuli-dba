# ADR-004 — YAML parser: PyYAML, hardened

Status: **accepted**
Related: `../design/00-principles.md` (D4, P4), `../design/01-configuration.md`,
`../../src/sopuli/config/yaml_loader.py`, `../../src/sopuli/config/permissions.py`

---

## Context

D4 settles that the config file is YAML. It does not say what reads it, and
until #20 there was no code to hang the choice on — the same position ADR-002
described for the CLI framework.

The candidates were `PyYAML`, `ruamel.yaml`, and `strictyaml`.

## What did not decide it

- **Speed.** The file is a few hundred lines, read once per run, and every
  candidate parses it in single-digit milliseconds. Next to opening an Oracle
  connection this is not measurable.
- **YAML feature coverage.** All three handle anchors, merge keys and block
  scalars, which is everything `01-configuration.md` uses.
- **Safety against hostile documents.** `safe_load` is the answer with PyYAML
  and the default with the others. Free either way, as long as it is not
  forgotten — see the consequences below.

## Decision

**PyYAML**, on a `SafeLoader` subclass.

The deciding argument is what the alternative is *for*. `ruamel.yaml`'s
distinguishing feature is round-trip fidelity — parse, modify, write back with
comments and formatting intact. **This tool never writes a config file.** The
config is a reviewed artefact under version control; the tool reads it, and
writes only to the vault and the database. Taking a heavier dependency for a
capability the design forbids using is paying for the wrong thing.

That leaves ruamel's real secondary benefits, and they are real:

- **YAML 1.2**, where `no` is a string and `0640` is six hundred and forty.
- **Line and column on every node**, so a *validation* error — not just a parse
  error — can point at a line.

The first is addressed directly in the loader (below). The second is a genuine
loss, and it is accepted: validation errors carry a `KeyPath`
(`applications[1].secret_template`) instead of a line number. For a file a human
wrote and can search, a key path is arguably the better address anyway, and it
survives the file being reformatted.

`strictyaml` was rejected outright. It removes flow style, anchors and implicit
typing, and requires a schema up front to get anything but strings. The
type-safety argument is real but this project validates into typed structures
anyway, so it would buy a restricted YAML dialect that surprises anyone who
writes ordinary YAML — for a config file whose audience is DBAs, not a good
trade.

## The argument against

PyYAML's defaults are wrong in two ways that are *silent*, and silence is the
one failure mode this project cannot tolerate in the file that decides which
account is mastered where. Choosing it means writing code to fix that, and the
fix is ours to maintain. Both are pinned by tests that assert the stock
behaviour alongside the corrected one, so if PyYAML ever changes its mind the
pair fails rather than leaving dead defence in place.

## Consequences

**`safe_load` only, structurally.** `SopuliSafeLoader` derives from `SafeLoader`,
so no tag can reach a Python constructor. A config file may arrive from a shared
drive or a repository someone else can write to; `yaml.load` with the default
loader would execute what it finds there.

**Duplicate mapping keys are an error.** Stock PyYAML keeps the last one and
says nothing:

```python
>>> yaml.safe_load("accounts: [a]\naccounts: [b]")
{'accounts': ['b']}
```

Invariant 5 makes the config the whitelist. A whitelist that can silently lose
half its entries is not one — the tool would manage three of six accounts and
report success. Reported at the *second* occurrence, since that is the one to
delete.

**`yes` / `no` / `on` / `off` are strings.** PyYAML implements YAML 1.1, where
they are booleans. This config is full of bare words in positions that matter —
tenant names, environment names, PDB suffixes, label values — and every one of
them can flow into a rendered secret path. The well-known form is the "Norway
problem", where the country code `NO` stops being a string. Only `true` and
`false` remain boolean. The resolver table is rebuilt on the subclass, not on
`SafeLoader`, so no other library in the process is affected.

**YAML 1.1 octal is left alone**, where `0640` parses as 416. No field in the
schema is written with a leading zero, and the schema layer types numeric fields
explicitly, so a wrong value is caught by that field's own validation rather than
accepted. Recorded here so the next person does not have to rediscover it.

**Anchors and aliases are left alone.** Useful in a file a human maintains, and
the billion-laughs concern is about hostile input — this file is the operator's
own, and they can already point the tool at any database they like.

## A second dependency, from the same issue

`pywin32`, Windows only (`sys_platform == "win32"`), for P4's config permission
check. It is recorded here rather than in its own ADR because it is not a fork
in the road: `os.stat().st_mode` reports `0o666` for essentially every file on
Windows regardless of its real ACL, so there is no stdlib route to the answer
and no second candidate. The alternative was ~150 lines of `ctypes` structure
marshalling — ACL and ACE layouts, SID comparison — inside a security check,
which is the worst place for a subtle marshalling bug and the hardest kind of
code for a DBA-first reviewer to check. Against D3, which already makes Oracle
Instant Client a hard runtime prerequisite on every platform, a Windows-only
Python wheel is a small addition.

`types-pyyaml` and `types-pywin32` are dev dependencies. The pywin32 stubs are
platform-independent, so mypy checks the Windows-only branch on Linux too —
which is the second thing the OS matrix in CI pays for.

## When to revisit

If validation errors turn out to need line numbers in practice — if "path in the
config" is not enough to find the problem in a real estate's file — that is the
argument for ruamel, and it is a contained change: the loader is one module
behind `parse_yaml`.

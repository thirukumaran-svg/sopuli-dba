You are auditing one area of the sopuli-dba repository for documentation drift:
claims in the text that no longer match the build. The area is **{AREA}**. Its
files are:

{FILES}

Work read-only. Do not change any file. The repository root is the current
directory. The CLI is installed: run `.venv/Scripts/sopuli.exe` on Windows or
`.venv/bin/sopuli` elsewhere, with `--help` on any command or subcommand. The
`gh` CLI can read issue states, for example `gh issue view 123 --json state`.

## What to check

Read every file in the area in full. For each claim of the kinds below, check it
against the source of truth: the code in `src/sopuli/`, the tests in `tests/`,
the help text, the JSON schemas in `docs/schemas/`, the example configs in
`examples/`, or the issue state on GitHub.

1. **Absence and uniqueness.** "does not", "never", "not yet", "no command",
   "the only", "every", "all", "none". These go stale when a later change adds
   the thing. Search the code for it.
2. **Counts.** "three verbs", "five guards", "31 codes". Count the real things.
   Skip a list under a `<!-- checked-list: ... -->` marker; a test checks it.
3. **Pending and future work.** "until #N", "once #N lands", "will", "planned",
   "is being written", "(open: #N)". Check the issue state, and check whether
   the code already does it.
4. **CLI surface.** Verbs, flags, defaults, exit codes, diagnostic codes, refusal
   and hint messages. Check against `--help` and the code that produces them.
5. **Behaviour.** What a command does, in what order, what it writes, what it
   refuses, what it reports. Find the code path and read it.
6. **Output samples.** Field names and values in a JSON or text sample. Check
   field names against the schema and the code that emits them. Check that a
   sample's `schema_version` or similar matches the current schema.
7. **Restated facts.** A fact whose home is elsewhere: an Oracle release number,
   a schema version, a measured result. Check it against its home, such as
   `docs/measurements.md` or `docs/schemas/`.
8. **Narration.** Text that tells history instead of the current build: "used
   to", "this paragraph used to say", "#N changed this", "now" contrasted with an
   earlier state, a date a behaviour changed. Report it as `NARRATION`; it is a
   writing-rule break, not a false claim.

## What not to report

- `§` section references, backticked repository paths, `:func:` and similar
  roles, fenced `sopuli` command lines, and `(unverified: ...)` markers. Tier-0
  tests check them.
- Style, wording, typos and length, unless the wording makes the claim false.
- Design opinions. Report only a claim that disagrees with the build.
- A claim about an open decision or unbuilt work that is marked as open. That is
  correct.

## How to decide

- `FALSE`: you found the code, help text, schema or issue state that contradicts
  the claim. Give the evidence as `path:line`, or as the command and its output.
- `UNSURE`: you could not settle it, for example because the answer needs a
  live database. Say what you checked.
- A claim you checked and found true is not reported, but it is counted.

Be careful. A claim is often true because of a branch you have not read yet.
Before you report `FALSE`, look for the code that would make the claim true.

## What to return

Start with one line: `CHECKED: <n>`, the number of claims you checked, true or
not. Then one row per finding, in this form:

```
<file>:<line> | <kind 1-8> | <FALSE|UNSURE|NARRATION> | "<the claim, quoted, at most 25 words>" | <evidence>
```

Return nothing else. No summary, and no proposed fixes.

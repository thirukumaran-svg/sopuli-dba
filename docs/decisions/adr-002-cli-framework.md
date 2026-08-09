# ADR-002 — CLI framework: click

Status: **accepted**
Related: `../design/00-principles.md` (D2, D8), `../design/03-json-output.md`,
`../../src/sopuli/cli.py`

---

## Context

D2 fixes the grammar as noun-verb (`sopuli creds rotate`). Something has to
parse it. The choice was left open until there was code to hang it on, and the
CLI skeleton is that code — every later command inherits whatever is chosen
here, so it is worth being explicit about *why*.

The candidates were stdlib `argparse`, `click`, and `typer`.

## What did not decide it

Three arguments that look decisive and are not:

- **Noun-verb grammar.** `argparse` subparsers nest as well as click groups.
  All three express the grammar without strain.
- **Exit code 2 on usage errors.** Both argparse and click already exit 2, which
  is what the P5 table specifies. Free either way.
- **Global flags without per-verb boilerplate.** Neither framework gives this.
  A click option declared on the group is only accepted *before* the
  subcommand, so `sopuli config show --output json` fails unless the option is
  attached to the verb — the same per-command wiring argparse needs via
  `parents=[...]`. This had to be solved deliberately regardless of choice; see
  `common_options` in `cli.py`.

## Decision

**click.** Two reasons, both specific to this project rather than general
preference:

1. **`click.testing.CliRunner`.** Tier 0 is the mandated first work and must
   stay free of I/O (`04-testing.md` §4). CliRunner invokes a command in-process
   and returns stdout, stderr and the exit code, so asserting an exact exit code
   or an exact JSON document is an ordinary unit test. With argparse that
   harness is written by hand. Given how much of this design rests on precise
   exit codes and a versioned JSON contract, that is the ergonomic worth paying
   a dependency for.
2. **A real exception hierarchy.** `ClickException` / `UsageError` give one
   place to attach the rule that errors carry a vendor code, a category and a
   hint, and one place to later answer whether `--output json` should emit a
   document on a usage error. `argparse.ArgumentParser.error()` calls
   `sys.exit` directly; intercepting it means subclassing the parser, which is
   the kind of thing discovered after twenty commands exist.

## The argument against

CLAUDE.md asks for boring, readable code, reviewed by someone who is a DBA first
and a Python developer second. `argparse` is more verbose but wholly explicit —
no decorators, no context object, no `pass_obj`. Someone reading `cli.py` cold
sees the parser built in front of them. That is a real cost of this decision,
and it is accepted rather than dismissed: the test ergonomics matter more for a
tool whose correctness argument is largely its test suite.

`typer` was rejected outright. It is click with an implicit layer on top, its
API has churned (the `Annotated` migration), and non-default exit codes need
working around its conventions. Adding an abstraction over the library you would
otherwise use directly cuts against the same readability rule that argues for
argparse, while giving up argparse's explicitness too.

## Consequences

- One runtime dependency. Minor next to D3, which already makes Instant Client a
  hard runtime prerequisite on every platform.
- Global options are a shared `common_options` decorator applied per verb. A new
  command that forgets it silently loses `--output` and `--dry-run`, so it is
  worth a test once there is more than one verb.
- `sopuli --output json config show` (flag before the noun) is a usage error.
  Pinned by a test so the behaviour is recorded rather than rediscovered.

## When to revisit

If the flag-position asymmetry proves to be a real usability problem in the
field, the fix is a custom `click.Group` that reconciles group-level and
command-level options — not a change of framework.

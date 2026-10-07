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
  `global_options` in `invocation.py`.

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
   hint, and one place to apply [J7](log.md#j7): a usage error (exit 2) emits
   no `--output json` document. `argparse.ArgumentParser.error()` calls
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

- Click is one more runtime dependency. That is minor next to D3, which already makes Instant Client a
  hard runtime prerequisite on every platform.
- Global options are a shared `global_options` decorator applied per verb, *and*
  a `group_options` decorator on the group. A new command that forgets the first
  silently loses `--output` and `--dry-run`, so `tests/test_cli_precedence.py`
  walks the command tree and fails if one does.
- Both parser positions are accepted for the inert options and both are layer 1;
  the verb's value wins where both were given. See `sopuli/invocation.py`.

### The position asymmetry, and how it was resolved (#10)

This ADR originally recorded `sopuli --output json config show` as a usage error,
and said the fix — if the asymmetry ever mattered — was a custom `click.Group`
reconciling group-level and command-level options.

It mattered, and the fix is narrower than a custom `Group`. Declaring the option
in both places is mechanically fine: click hands back both values, and
`default=None` distinguishes "not given" from "given the default", including for
`is_flag` options. What was missing was not parsing but a *rule* about which one
wins — and that rule cannot be the same for every option, because
`--dry-run` may only ratchet toward safe (invariant 10) while `--output` may
not care. So the merge belongs to the precedence resolver, not to the parser.

**Safety flags are the exception, and they are refused rather than merged.**
`--dry-run` is declared on the group as a hidden trap whose callback raises a
`UsageError` naming the trailing position. Group and verb position express
identical intent for a safety flag, so accepting both would buy typing tolerance
and nothing else — at the price of a merge policy in the smallest and least
visible layer there is. The trap buys the typing tolerance anyway, and no
group-position safety value ever reaches the resolver.

## When to revisit

If a *verb* ever needs an option the group also declares, with different meaning
in each, this arrangement breaks: one name binds to one setting. That would be a
naming problem rather than a framework one.

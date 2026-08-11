# ADR-003 — Text tables: click only, formatted by hand

Status: **accepted**
Related: `../design/03-json-output.md` (§1 colour, §8 stability),
`../design/01-configuration.md` (§4 `target list`),
`../../src/sopuli/output/table.py`, `../../src/sopuli/output/emit.py`

---

## Context

Several commands display rows: `config show --resolved` lists an estate and its
bindings, `target list` is a first-class command in §4, and `creds check` will
report one line per account per target. Something has to lay out columns.

The choice was deliberately left open until a command had real results to show —
`docs/README.md` recorded it as gated on exactly that — because a table library
chosen against imaginary output tends to be chosen for features nothing needs.
`config show --resolved` is the first command with a real table, so this is the
moment.

The candidates were `rich`, `tabulate`, and formatting with the standard library
plus the `click` already in use.

## What did not decide it

- **Column arithmetic.** Padding to a computed width is `str.ljust`. No
  candidate wins on the part everyone imagines is the work.
- **Colour.** `sopuli.output.emit.Emitter` already owns whether a run may emit
  ANSI, resolves it once, and strips it when the answer is no. Any renderer
  plugs into that; none of them gets to decide it. A library that colours by
  default would have to be told not to, which is a cost rather than a feature.
- **Unicode box drawing.** Pretty, and refused on its own merits: the tool's own
  prose is ASCII by convention (`tests/test_cli_smoke.py`), and a box-drawn table
  is decoration that has to survive a Windows console, a redirected stream and a
  CI log.

## Decision

**No table library. `sopuli/output/table.py` formats columns with the standard
library, and `click` remains the only CLI dependency.**

Three reasons, in order of weight:

1. **Dependency weight on a credential tool.** `rich` brings `markdown-it-py`
   and `pygments` with it. Every package in the install of a tool that holds
   production passwords is a package whose supply chain matters, and the
   provenance rules in `CLAUDE.md` are not the only reason to keep that list
   short. Three packages to right-align a column is a bad trade.
2. **Output must not depend on the terminal.** A library that detects width and
   reflows produces different bytes when piped, in CI, and in a 200-column
   window. That is a poor property for output a person will paste into a ticket
   and a worse one for a test. Our renderer takes fixed per-column maxima and
   ignores the terminal entirely, so the same config always renders the same
   text. `03-json-output.md` is explicit that scripts should consume JSON rather
   than parse this, which is what makes fixed widths affordable.
3. **The work is small and bounded.** Widths, padding, and truncation with an
   ASCII ellipsis. What a library would add beyond that — wrapping, nested
   renderables, markup — is not in any command's output and would not be used.

## Consequences

- Long values are truncated rather than wrapped, and the full value is available
  in `--output json`. A truncated cell ends in `...` so it is visibly not the
  whole value.
- A narrow terminal wraps the line itself. We accept that in exchange for
  deterministic output.
- Nothing prevents revisiting this. If a later command genuinely needs wrapping
  or nested layout, the renderer is one module behind one function, and the
  Emitter still owns colour either way.

## Alternatives

**`rich`.** The best of the libraries, and the one to pick if this decision is
ever revisited. Rejected here on dependency weight and on terminal-dependent
output, not on quality.

**`tabulate`.** Lighter than `rich` and does one thing. Still a dependency for
`str.ljust`, and its default styles lean on box drawing.

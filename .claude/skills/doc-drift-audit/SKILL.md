---
name: doc-drift-audit
description: Audit the documentation and code comments for claims that no longer match the build. Runs the tier-0 doc checkers, then one read-only Sonnet sweep per document area, verifies a sample of the findings by hand, and records the result. Use when asked for a documentation drift audit, or when docs/workflow.md §Documentation drift audit says one is due.
user_invocable: true
---

# Documentation drift audit

The tier-0 tests in the `docs` CI job check references, lists, command lines and
markers. They cannot check a sentence such as "the tool does not retry" or "three
verbs take `--force`" against the code. This audit checks those sentences. A
Sonnet agent reads each document area and checks its claims against the code,
`sopuli --help`, the schemas and the issue states. The main model then verifies a
sample of the findings and records the result.

`docs/workflow.md` §*Documentation drift audit* says when to run it.

Run commands from the project root. Do not prefix them with `cd`.

## 1. Record the starting point

1. Note the time. The record needs the wall time.
2. Note the commit: `git rev-parse --short HEAD`. Audit a clean `main`.
3. Check that the build is installed in `.venv`, because the agents run the CLI
   from there: `.venv/Scripts/sopuli.exe --help` on Windows,
   `.venv/bin/sopuli --help` elsewhere. If it fails, create the environment and
   install into it with its own interpreter: `python -m venv .venv`, then
   `.venv/Scripts/python -m pip install -e ".[dev]"` on Windows or
   `.venv/bin/python -m pip install -e ".[dev]"` elsewhere.

The `pytest` commands below mean that environment's `pytest`. Activate `.venv`
first, or call `.venv/Scripts/python -m pytest` (Windows) or
`.venv/bin/python -m pytest`.

## 2. Run the checkers first

```bash
pytest tests/test_verification_register.py tests/test_decision_register.py tests/test_decision_log.py tests/test_doc_command_lines.py tests/test_doc_lists.py tests/test_doc_sections.py tests/test_doc_symbols.py tests/test_measurements.py tests/test_pending_work.py tests/test_readme_links.py
```

This is the `docs` job in `.github/workflows/ci.yml`. If the list there has
changed, use that list. A failure here is a finding in its own right. Fix it or
file it before the sweep, because the sweep does not repeat these checks.

Then run the checks that ask GitHub for issue states. The weekly `pending-work`
workflow runs them too. Without `SOPULI_CHECK_ISSUES` they skip. In bash:

```bash
SOPULI_CHECK_ISSUES=1 pytest tests/test_pending_work.py tests/test_decision_register.py tests/test_decision_log.py -k "closed_issue or issue_has_a_row or matches_its_issue or closed_decision_issue"
```

In PowerShell, set the variable first:

```powershell
$env:SOPULI_CHECK_ISSUES = "1"
pytest tests/test_pending_work.py tests/test_decision_register.py tests/test_decision_log.py -k "closed_issue or issue_has_a_row or matches_its_issue or closed_decision_issue"
```

## 3. Sweep each area

Start one agent per area in the table below, all in one message so that they run
in parallel. Use `subagent_type: "Explore"` and `model: "sonnet"`. Explore has no
write tools, so a sweep cannot change the tree.

The prompt for each agent is the text of `sweep-prompt.md` in this directory,
with `{AREA}` and `{FILES}` filled in from the table. Read the file and paste it;
the agent cannot read this skill.

| Area | Files |
|---|---|
| config | `docs/design/01-configuration.md`, `examples/*.yaml` |
| output | `docs/design/03-json-output.md` |
| uc1 | `docs/use-cases/uc-01-app-credential-sync.md`, `docs/scenarios/*.md` |
| uc2 | `docs/use-cases/uc-02-personal-account-passwords.md` |
| oracle | `docs/design/00-principles.md`, `docs/design/02-oracle-privileges.md`, `docs/measurements.md` |
| process | `docs/design/04-testing.md`, `docs/workflow.md`, `docs/maintainer-environments.md`, `test/README.md`, `CONTRIBUTING.md`, `CLAUDE.md`, `.github/copilot-instructions.md` |
| front | `README.md`, `SECURITY.md`, `docs/getting-started.md`, `docs/security-model.md`, `docs/local-testing.md` |
| register | `docs/README.md`, `docs/decisions/*.md` |
| code | module docstrings, docstrings and comments in `src/sopuli/**/*.py` |

Some areas need a note after the file list in the prompt:

- **oracle**: "Check `docs/measurements.md` against the headers of the scripts in
  `sql/oracle/`. Dated results are allowed in `docs/measurements.md`; do not
  report them as narration."
- **process**: "The sources of truth also include `.github/workflows/*.yml`, the
  compose files in `test/`, `pyproject.toml` and `tests/`."
- **register**: "Decision records and ADRs record why a decision was made, so
  describing the rejected options is not narration. An ADR's *Context*
  section describes the situation when the decision was made; do not report
  it. Report claims about the current build that are false, and status claims
  (open, decided, built, not built) that disagree with the code or the issue
  state."
- **code**: "A claim is what a comment or docstring says about the code: what a
  function does, who calls it, what it never does, how many of something there
  are. Check each against the code it describes, including callers in other
  modules." While an issue for narration in comments is open, also say: "Report
  at most 10 `NARRATION` rows, and spend the effort on kinds 1 to 5."

When a new document appears, add it to the area it fits. Keep each area under
about 30,000 words, because a larger area gets a shallower sweep.

## 4. Verify the findings

An agent can be wrong. It may misread the code, or miss the branch that makes a
claim true. Before anything is filed:

1. Read every `FALSE` finding. Drop one whose evidence does not support it.
2. Re-check at least ten `FALSE` findings yourself, from the code, and spread
   them over the areas. If there are twenty or fewer, re-check them all. Count
   the ones that do not hold. These are the false positives.
3. If more than one in five of the re-checked findings does not hold, re-check
   that area's findings in full before filing them.
4. Look at the `UNSURE` findings. Settle each one, or leave it out of the record.
5. Compare each area's `CHECKED` count with its size. In the trial, the process
   sweep checked about 8 claims per 1,000 words and the uc2 sweep about 3. An
   area far below 8 had a shallow sweep. Say so in the record, or run that area again.

## 5. File and record

1. File the confirmed findings as issues, one issue per area or per document.
   Each issue names the audit commit and gives every finding as `file:line`,
   the claim, and the evidence. That way the issue does not depend on this
   session. Label each issue `documentation`.
2. File the `NARRATION` findings together in one issue. They break the writing
   rules in `CONTRIBUTING.md`, but they are not false.
3. Open an issue titled `docs: drift audit <date>`, with the record as its body,
   and close it when its findings are filed. The record gives:
   - the commit, the date and the wall time;
   - the number of claims checked, from the agents' `CHECKED` lines;
   - the number of `FALSE`, `NARRATION` and `UNSURE` findings, per area;
   - the number re-checked and the number of false positives;
   - the tokens: the sum of `subagent_tokens` from each agent's completion
     notice;
   - the issues filed.

Compare the numbers with the previous record. The past runs are the issues
titled `docs: drift audit`, and #626, which holds the trial.

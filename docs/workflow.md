# Working agreement — branching & releases

Status: binding, same as CLAUDE.md.

## Branching

- `main` is always green — tests pass, the tool works. Every commit on it
  came from a merged PR, even solo.
- One branch per issue: `issue-<n>-<slug>`, e.g. `issue-12-lcount-guard`.
- No long-lived integration branch. `dev`/`main` splits solve a staged-release
  problem this project doesn't have yet. Revisit only if we ever need to
  patch an old release line while `main` has moved on — that's a
  `release-x.y` branch cut from a tag, not a permanent branch.
- PR description includes `Closes #<n>`. The branch is deleted after merge —
  GitHub does this automatically (`delete_branch_on_merge` is enabled).
- **Squash merge only.** One PR becomes exactly one commit on `main`, so
  `main`'s history is one line per change and a revert is one commit. Work
  inside a branch can be as untidy as it needs to be. This has a consequence
  for commit format — see below.
- **Every PR gets a Copilot review before it merges**, and every comment it
  leaves gets resolved: the code changes, or the change is declined with a
  reason, and either way the PR says which and why. This is a solo repository,
  so the review is the only second opinion a change gets — and an unanswered
  comment leaves no record of whether it was considered or missed. CLAUDE.md's
  *Working agreement* has the full rule; `/request-copilot-review` has the
  mechanics.

## Commits

Conventional Commits, since release-please reads them:
- `feat:` — new capability, minor bump
- `fix:` — bug fix, patch bump
- `feat!:` or a `BREAKING CHANGE:` footer — major bump (holds at 0.x until
  we decide otherwise — see below)
- `chore:`, `docs:`, `test:`, `refactor:` — no release impact

Because merges are squashed, **the PR title is the commit subject on `main`**
and the only thing release-please ever parses. A PR titled
`Fix the LCOUNT guard` lands as an unparseable commit and silently produces no
changelog entry and no version bump — release-please logs `commit could not be
parsed` and moves on. Nothing fails; the release is just quietly wrong. So the
PR title has to be a valid Conventional Commit even when the branch's own
commits are not.

## Continuous integration

`.github/workflows/ci.yml` runs tier 0 (`design/04-testing.md` §4) on every pull
request: `ruff check`, `ruff format --check`, `mypy`, `pytest`, and a smoke check
that the installed `sopuli` binary runs. No containers, under a minute.
`.github/workflows/tier1.yml` is the container lane and runs on the same trigger.

- **Pull requests only, not the push to `main` as well.** A `pull_request` run
  checks out `refs/pull/N/merge` — the head *already merged into the base* — so it
  tests the tree the squash merge is about to produce, not the branch in
  isolation. The run on `main` afterwards re-tested an identical tree and was
  billed again for it, which on a private repository's free minutes is the
  single largest duplicate there is.
- **A prose-only pull request runs neither lane**, and the two arrange that
  differently. `tier1.yml` filters on the trigger with `paths-ignore`; `ci.yml`
  filters in a `changes` job that every other job carries an `if:` on, for the
  branch-protection reason below. **Both lists are measured, not "docs"** — the
  suite reads `docs/design/00-principles.md`, `docs/design/01-configuration.md`,
  every `docs/schemas/*.json`, every `examples/*.yaml` and
  `sql/oracle/00_install.sql`, so a blanket `docs/**` or an `examples/**` would
  switch off a test while leaving it green. `test/paths_ignore_probe.py` measures
  what the suite opens; `tests/test_workflow_prose_list.py` keeps the two copies
  of the list equal. The lists drifted seven patterns behind the tree between
  #370 and #373, which is what #375 fixed.
- **`ruff` runs once**, on Linux. It is deterministic — same answer on every OS
  and interpreter — so six identical failures would be noise, not coverage.
- **`mypy` runs on the whole matrix**, unlike `ruff`, because it is not
  OS-independent: it narrows `sys.platform` to the platform it runs on, so
  Windows-only branches are dead code to a Linux run and never get checked
  there.
- **The matrix is Python 3.11/3.12/3.13 on Linux, and 3.13 alone on Windows.**
  3.11 because `requires-python` allows it; Windows because the cp1252
  stream-encoding bug (#12) was invisible on Linux and P4 requires identical
  behaviour on both. macOS is out, per D5.

  Windows bills at 2× and rounds up per job, so three Windows cells were two
  thirds of this workflow's cost. One cell keeps every axis they were buying: the
  platform axis is per-platform by definition, mypy's narrowing is too — and is
  pinned to `python_version = "3.11"` in `pyproject.toml`, so it gives the same
  answer whichever interpreter starts it — and the interpreter axis is still run
  in full on Linux, with nothing in `src/` or `tests/` branching on
  `sys.version_info`. Restoring the other two cells is a two-line revert if a
  Windows-and-version-specific break ever appears.

### "main is always green" is discipline, not enforcement

The rule at the top of this document is not enforced by the platform. **Branch
protection is unavailable on a private repository on the free plan** —
`/branches/main/protection` returns 403, "Upgrade to GitHub Pro or make this
repository public". So CI reports a status, and nothing stops a red PR being
merged anyway.

This is recorded rather than assumed closed. The workflow exists now so that
closing the gap later is a settings change and not a project: when the repository
goes public (or the plan changes), **add `ci ok` as the required status check.
One name, and not `lint` or the `test` cells** — that job name is the contract,
and renaming it silently disables the requirement.

That is a change from what this paragraph used to say, and it is measured rather
than reasoned (#375, verified on #379). `ci.yml` skips its lanes on a prose-only
pull request — `changes` decides, and `lint`, `test` and `install shape` carry
`if: needs.changes.outputs.code == 'true'` — because a job skipped by an `if:`
reports `skipped`, which protection accepts, while a whole workflow skipped by
`paths-ignore` never creates its contexts at all and a required one stays pending
forever. That is why `ci.yml` has no `paths-ignore` and `tier1.yml` still does.

But **a skipped matrix job never expands.** Instead of six contexts named
`test (ubuntu-latest, py3.11)` and so on, it publishes exactly one, named
`test (${{ matrix.os }}, py${{ matrix.python-version }})` — the literal
expression. Requiring the cell names would leave six contexts that were never
created, which is the original trap one step along. `ci ok` has a fixed name,
runs on every pull request under `if: always()`, and fails if any lane reports
anything but `success` or `skipped`.

It closes the other edge too: because a skipped required check *passes*, a
`changes` job that failed would skip everything downstream and wave the pull
request through. `ci ok` needs `changes` like any other lane, so a failure there
is a failure here. Tier 1 needs none of this — it is not among the required
checks, so it can keep filtering on the trigger.

**Nothing runs on `main` itself any more**, and that is not a widening of this
gap. Because a `pull_request` run tests the merge result, the commit that lands on
`main` has already been tested — as long as the branch was current when it merged.
Two pull requests open at once is where that stops being true: the second one's
last run predates the first one landing, and nothing here enforces up-to-date
branches, precisely because of the 403 above. One PR at a time is the working
pattern rather than an enforced rule, and `workflow_dispatch` on `ci` and `tier 1`
is how `main` gets checked by hand when that assumption does not hold — which is
what it was used for during the Actions incident in #233.

## Releases

- Versioning stays `0.x.y` until we explicitly decide to cut 1.0 — no
  automatic promotion out of 0.x.
- release-please runs on push to `main`, maintains a standing release PR
  with the accumulated changelog and version bump. Merging that PR is the
  explicit act that cuts the tag and GitHub Release.
- No manual tagging.

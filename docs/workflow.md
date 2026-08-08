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
- PR description includes `Closes #<n>`. Delete the branch after merge.

## Commits

Conventional Commits, since release-please reads them:
- `feat:` — new capability, minor bump
- `fix:` — bug fix, patch bump
- `feat!:` or a `BREAKING CHANGE:` footer — major bump (holds at 0.x until
  we decide otherwise — see below)
- `chore:`, `docs:`, `test:`, `refactor:` — no release impact

## Releases

- Versioning stays `0.x.y` until we explicitly decide to cut 1.0 — no
  automatic promotion out of 0.x.
- release-please runs on push to `main`, maintains a standing release PR
  with the accumulated changelog and version bump. Merging that PR is the
  explicit act that cuts the tag and GitHub Release.
- No manual tagging.

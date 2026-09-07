# ADR-008 — Contribution provenance is a DCO sign-off, not a CLA

Status: **accepted**
Related: `../../CONTRIBUTING.md`, `../../CLAUDE.md` (Provenance),
`../../LICENSE` (Apache 2.0), issue #370

---

## Context

`CLAUDE.md` states that this is an independent open-source project developed on
personal time and equipment, and that it is not derived from any employer
codebase. That claim is load-bearing rather than decorative: it is the reason the
repository can go public at all, and the reason the provenance rules on examples
and fixtures exist.

Until now the claim rests on nothing but the statement itself. A solo repository
can carry that, because there is exactly one contributor and the maintainer knows
who they are. **Opening the repository changes it**, because a public repository
accepts contributions from people the maintainer has no other record of. The
question then is not whether the maintainer's own work is clean; it is whether
anything a contributor sends can be shown to have been knowingly offered under
Apache 2.0.

Two mechanisms are conventional:

| | What it is | What it costs a contributor |
|---|---|---|
| **CLA** — contributor licence agreement | a separate legal agreement, often assigning or licensing rights beyond the project's own licence | signing a document, usually through a third-party service, before a first contribution is accepted |
| **DCO** — Developer Certificate of Origin | a standard one-line attestation per commit that the contributor has the right to submit the work under the project's licence | `git commit -s` |

## Decision

**Every commit carries a `Signed-off-by:` line, per the
[Developer Certificate of Origin](https://developercertificate.org/) 1.1. There
is no CLA.**

The sign-off is checked at review time. **No CI tooling enforces it**, and adding
some is a separate decision rather than a consequence of this one.

## Why the DCO and not a CLA

**It answers the question that was actually asked.** What this project needs is a
checkable record that a contribution was knowingly offered under Apache 2.0. A
DCO is exactly that record and nothing more. A CLA answers a different question —
who holds what rights afterwards — that this project has no reason to ask.

**A CLA is a barrier at the worst moment.** It arrives before a first
contribution is accepted, needs a service to administer, and asks somebody to
sign a legal document to fix a typo. For a project of this size that trades a
real contributor for a hypothetical dispute.

**It is per-commit, which is where the record is useful.** A CLA covers a person
once. A sign-off is attached to the artefact, so `git log` answers the provenance
question for any given line of history without a second system to consult.

## Why no CI enforcement yet

A DCO bot is easy to add and it is not free: it fails pull requests on a missing
flag, and the fix — rewriting history to add the trailer — is the least
approachable Git operation a first-time contributor can be handed. While the
volume of external contributions is zero, review is a sufficient check and a
friendlier one.

Adding enforcement later is a settings change, and this ADR is where the
reasoning for turning it on belongs when the volume makes review insufficient.

## Consequences

- `CONTRIBUTING.md` documents `git commit -s`, what the line attests to, and why
  this project asks for it.
- Contributions arrive under Apache 2.0, the licence the repository already
  carries. Nothing about the licence changes.
- A pull request whose commits are not signed off is asked to sign off before
  merge, the same way any other review comment is handled.
- The provenance rules in `CLAUDE.md` — no code, configuration, schema or
  identifiers copied from another repository, and the fictional vocabulary for
  examples — are unchanged. The DCO records that a contribution was offered
  legitimately; it does not check what is in it.

## Revisit if

- The volume of external contributions makes review-time checking unreliable —
  then add a DCO check to CI, and say in `CONTRIBUTING.md` how to fix a missing
  sign-off.
- The project ever needs to relicense or dual-license, which is the one thing a
  DCO does not enable and a CLA does. That would be a new decision, and a
  disruptive one, made with the contributors of the day rather than in advance of
  having any.

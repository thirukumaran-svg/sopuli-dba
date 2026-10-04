# Contributing

Thank you for considering it. This file covers what a first-time contributor
from outside the project needs, and points at the documents that already say the
rest rather than repeating them.

Two documents govern how this project works, and both are binding:

- **[`docs/workflow.md`](docs/workflow.md)** — branching, commit format, CI, and
  releases.
- **[`CLAUDE.md`](CLAUDE.md)** — the working agreement, the design invariants,
  and which design document applies to which kind of change. It is addressed to
  Claude Code, the AI coding agent that writes much of the code here (see the
  next section), but everything in it applies to any contributor. **Read the
  invariants before changing behaviour.** Each one exists because getting it
  wrong breaks something specific, and several of them look like mistakes until
  you know why.

If you are new to the tool itself rather than to the codebase, start at
[`docs/getting-started.md`](docs/getting-started.md).

---

## How this project is built, and what that means for you

Much of this project's code is written by AI coding agents. The maintainer
decides what gets built and how, and reviews and signs off every change. This
section explains how those two roles fit together, because the process explains
why the documentation looks the way it does.

### How the pieces fit

- **The design documents and decision records are the specification.**
  `docs/design/`, `docs/use-cases/` and `docs/decisions/` say what the tool must
  do and why. Code is written against them, and a change that alters behaviour
  updates them in the same pull request.
- **`CLAUDE.md` is the working agreement.** It holds the invariants and says
  which document applies to which kind of change. It is written for agents, and
  it binds every contributor the same way.
- **Open questions wait for the maintainer.** A design question that is not yet
  answered is `open` in the decision register in `docs/README.md`, and it stays
  open until the maintainer answers it. An agent that needs one answered stops and asks; that
  is the rule *surface, do not resolve*, and it applies to you too (see
  [Before you write code](#before-you-write-code)).
- **Every review comment is answered.** Every pull request gets a Copilot
  review. Each comment, Copilot's included, is judged on its merits, then either
  acted on or declined, with a reply saying which and why (see
  [Pull requests](#pull-requests)).

### What is expected of you, with or without an agent

The same rules, whoever or whatever typed the change: the documentation moves
with the code, sample output comes from a real run, an open decision is surfaced
rather than settled in a diff, and every review comment gets an answer.

**AI-assisted contributions are welcome under those rules, and you are
accountable for them.** Your `Signed-off-by:` line (see
[Signing off your commits](#signing-off-your-commits-dco)) certifies that you
have the right to submit the change under this project's licence. Using an
agent does not move that responsibility to anyone else. If you sign off a
change, you are vouching for it, whether you wrote it by hand or directed a
tool that did.

Some organisations restrict AI-generated code because the copyright position of
machine-generated output is unsettled in some jurisdictions. This project does
not claim a legal position on that. What it can say is what happens here: a
person directs every change, reviews it, and signs it off.

### Why the process is shaped this way

A credential tool maintained largely by agents needs design decisions that
cannot be silently made again. An agent that meets a rule without its reason
may "fix" it, and several rules here look like mistakes until you know why.
That is why the documents record the options that were rejected as carefully
as the one that was chosen, why a decision cites the issue that made it, and
why *surface, do not resolve* exists. The length of the documentation is the
cost of that, and it is paid on purpose.

---

## Before you write code

**Work comes from GitHub issues, and one issue is about one reviewable pull
request.** If you want to change something, open an issue first or comment on an
existing one. This is a small project and a design conversation is cheaper than a
rewritten branch.

**Some decisions are deliberately still open.** The design documents mark them
with a letter and a number — `C4`, `J3`, `H10`. The decision register in
[`docs/README.md`](docs/README.md) says which are open, and many have a GitHub
issue labelled `decision`. **If your change needs one of them answered, say so in the issue and
stop.** Picking a plausible option and continuing turns an open decision into a
fact buried in a diff, which is the one outcome this project is most careful to
avoid.

When a decision is made, the pull request that closes its issue also adds a
record to [`docs/decisions/log.md`](docs/decisions/log.md), or writes an ADR for
a large decision. The record says what was decided, why, and what was rejected,
so the reasons stay in the repository and not only on GitHub.

---

## Setting up

Python 3.11 or newer. 3.13 is what CI runs on Windows.

```bash
git clone https://github.com/villebase/sopuli-dba.git
cd sopuli-dba
python -m venv .venv
```
```powershell
.venv\Scripts\Activate.ps1        # Windows PowerShell
```
```bash
source .venv/bin/activate         # Linux, macOS, WSL
```
```bash
# `dev` brings the test and lint tools; `all` brings every vendor client, so
# nothing skips for want of an install.
pip install -e ".[dev,all]"
sopuli --version
```

**`sopuli --version` reports the version recorded when the editable install was
made, not the version in your working tree.** After a pull that crossed a
release, run `pip install -e . --no-deps` to refresh it — it takes a second, and
that number lands in every `--output json` run document.

**Oracle Instant Client is a runtime prerequisite** for anything that reaches a
database. `python-oracledb` runs in thick mode here, because thin mode does not
support Native Network Encryption, cannot reach Oracle 11.2, and cannot log on
through an external password store (`auth: external`).
[`docs/getting-started.md`](docs/getting-started.md) §2c has the install steps.

---

## Running the tests

### Tier 0 — no containers, under a minute

```bash
ruff check .
ruff format --check .
mypy
pytest
```

Tier 0 is pure logic: config parsing and validation, target-set expansion,
precedence resolution, SecretRef parsing, password generation, redaction. It
opens no sockets. Keeping those layers free of I/O is an architecture
requirement, not just a test convenience.

### Tier 1 — Oracle and a vault, in containers

```bash
cd test
docker compose --profile tier1 up -d
```

That starts Oracle Free — about 30 to 60 seconds to healthy the first time — and
a HashiCorp Vault in dev mode. Then run `pytest` again from the repository root;
the tests that need a database stop skipping.

Two things in [`test/README.md`](test/README.md) will cost you time otherwise:

- **`docker compose down` does nothing here.** Every service carries a
  `profiles:` key, so with no profile selected it matches nothing and exits 0.
  Use `docker compose --profile '*' down`.
- **Restarting Vault loses its mounts.** Dev mode is in-memory. After a
  `stop`/`start`, run `docker compose --profile tier0 up -d vault-init` to put
  the `kv` and `kv1` mounts back.

### Which Oracle images you can actually pull

This is the constraint that shapes the whole test strategy, so it is worth
knowing before you wonder why a test skipped.

**Images built from Oracle installation binaries may not be redistributed.** So a
public CI job cannot pull a 19c Enterprise Edition image, and neither can you.
What follows from that:

- **Tiers 0 and 1 are the public suite, and it must be fully green using only
  freely pullable images** — Oracle Free, the XE editions, PostgreSQL,
  HashiCorp Vault. If a contributor cannot go green on their own machine, they
  stop contributing.
- **Tiers 2 and 3 are the maintainer's pre-release matrix** — built 19c, 11.2 in
  some configurations, real Oracle Cloud. Do not expect to run them.
- **Anything that needs an environment you do not have must skip, not fail**, and
  a skipped test says *why* it skipped. Tests declare the capabilities they need.
  **Never branch on a version number** — query the database for what it can do
  and branch on that. This is invariant 3, and it is not negotiable.

The full inventory of images, what each one covers, and which tier it belongs to
is [`docs/design/04-testing.md`](docs/design/04-testing.md) §1–2. It is a table
and it changes; this file deliberately does not copy it.

---

## Run it, do not only test it

**A change to what the tool reads from a target or a store, writes to one, or
reports about one is not finished when its tests pass.** Bring up tier 1 and run
the command end to end.

CI already runs tier 1 on every pull request, so this is not about coverage. It
is about the assertions nobody writes, because a test can only check what its
author already suspected. Three real examples from this project's history:

- **Output that was described rather than produced.** Every sample in a design
  document, a pull request body or a docstring is pasted from a real run. A
  hand-written one is a prediction, and one such prediction documented a warning
  the command did not print at all.
- **The shape of what the server actually sends.** `ORA-28002` is the documented
  grace-period code, and Oracle 26ai does not send it; the message repeats its
  own code and appends a URL on a second line. Neither is guessable, and both
  changed the design.
- **Anything intermittent.** A diagnostic query reported the probe's own session
  in one run out of two. One run is not a measurement.

---

## Documentation moves with the code

**A pull request that changes behaviour updates the relevant design document in
the same pull request.** The documents in `docs/design/` are the specification,
not a description written afterwards. If they disagree with the code, that is a
bug in one of them and it needs resolving, not noting.

[`docs/local-testing.md`](docs/local-testing.md) is a second obligation rather
than a restatement of the first. The design documents say what the tool is *for*;
that guide is the by-hand map of what the current build can actually be made to
do. So a change that adds or alters a command, a flag, an exit code, or a message
an operator meets belongs in it too — including the failures worth causing on
purpose, which are most of its value.

Paste the output from the run the previous section already required. That rule
and this one are the same work: you ran the command, so write down what it
printed. No sample in that guide is ever written from a diff.

The public-facing documents — `README.md`, `docs/getting-started.md`,
`docs/security-model.md`, `docs/scenarios/` and the comments in `examples/` —
have a different audience and a different voice. They are written for a DBA or
ops engineer who may not be a Python developer and may not have English as a
first language: short sentences, jargon defined the first time it is used, and a
sentence saying what a code block does before showing it. The design documents in
`docs/design/`, `docs/decisions/` and `docs/use-cases/` keep their existing
declarative voice, for contributors.

---

## Pull requests

**Aim for about 400 changed lines.** If a change turns out to need more than
that, split it and say so before writing the larger version. Documentation
changes that cannot be split below that — three documents that only make sense
reviewed together — are the ordinary exception, and the pull request should say
which exception it is claiming.

**Split a large documentation change into two pull requests** rather than one
enormous one: the material a reader hits first in one, and everything that
depends on it in the second. That keeps each one reviewable and keeps `main`
publishable at every point.

### Commits and the pull request title

Commit messages are [Conventional Commits](https://www.conventionalcommits.org/),
imperative mood, referencing the issue number:

```
feat(oracle): report SYSDBA where V$PWFILE_USERS is readable (#341)
fix(config): import the package's re-exports on demand (#363)
docs: bring the by-hand testing guide up to the implemented surface (#368)
```

`feat:` is a minor bump, `fix:` is a patch bump, and `chore:`, `docs:`, `test:`
and `refactor:` have no release impact.

**The pull request title matters more than the individual commits.** Merges are
squashed, so the title becomes the commit subject on `main`, and it is the only
thing the release tooling ever reads. A title it cannot parse produces no
changelog entry and no version bump — silently. Nothing fails; the release is
just quietly wrong. So the title has to be a valid Conventional Commit even when
the branch's own commits are not.

Put `Closes #<n>` in the description.

**Do not commit** generated artefacts, `.env` files, Oracle binaries, or anything
taken from a real environment. See "Provenance" below.

### Every pull request gets a review, and every comment gets answered

Every comment gets resolved one of exactly two ways:

- **change the code**, or
- **decline the change**, having decided it is wrong or that the existing form is
  right for a reason.

**Either way, reply on the pull request saying which and why.** A comment that
was silently acted on is indistinguishable from one that was silently ignored,
and neither is reviewable six months later. A decline needs the actual reason —
"working as intended" is not one. The reason is whatever the reviewer would have
needed to know in order not to raise it.

Judge each comment on its merits rather than deferring to it. This codebase makes
a number of deliberate choices that look like mistakes until you know why — the
data definition statement that must not be wrapped in PL/SQL, the password that
must not be sent as a bind value, the refusals that exist because guessing is
worse than stopping. Applying a suggestion that makes the code worse because it
was suggested is a real failure mode here, and so is dismissing a real bug
because answering it is inconvenient. Where a comment is right about the problem
and wrong about the fix, say both.

---

## Signing off your commits (DCO)

**Every commit needs a `Signed-off-by:` line.** Add it automatically with
`git commit -s`:

```
Signed-off-by: Jane Doe <jane@example.com>
```

That line is the [Developer Certificate of Origin](https://developercertificate.org/)
— a short, standard statement that you wrote the contribution, or otherwise have
the right to submit it, and that you are offering it under this project's licence
(Apache 2.0). It is not a copyright assignment and it takes nothing away from
you.

**Why this project asks for it.** This is an independent open-source project
developed on personal time and equipment, and it is not derived from any
employer's codebase. That claim needs a checkable record rather than an
assertion, and a signed-off commit history is the standard way to have one. A
DCO is the lighter of the two usual mechanisms — no separate agreement to sign,
no account to create, one flag on `git commit`.

Use your real name and an email address that reaches you. Nothing enforces this
in CI today; it is a review-time check. Adding tooling for it is a separate
decision, not a thing this file quietly introduces.

---

## Provenance — this matters more than usual

**Do not copy code, configuration, schema or identifiers from any other
repository into this one.** That includes anything from an employer's systems.

Examples and fixtures use the fictional vocabulary in
[`docs/design/01-configuration.md`](docs/design/01-configuration.md): the
application `acme`, accounts named `acme_*_user`, tenants `alpha` through
`theta`, hosts under `example.com`, and IP addresses from `192.0.2.0/24`. Never a
real hostname, account name, tenant, service or vault path.

If a useful example comes from a real system, anonymise it completely — and say
in the pull request that you did.

---

## Reporting a security problem

Do not open a public issue. [`SECURITY.md`](SECURITY.md) has the private route.

## Conduct

[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) applies to everyone taking part.

## Licence

Contributions are made under the [Apache 2.0](LICENSE) licence, which is what
your `Signed-off-by:` line attests to.

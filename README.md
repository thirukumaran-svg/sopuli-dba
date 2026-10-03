<p align="center">
  <img src="https://github.com/villebase/sopuli-dba/raw/main/docs/assets/sopuli-dba-logo-glow.png" alt="sopuli-dba logo" width="240">
</p>

# sopuli-dba

**Change a database account's password without anybody having to know it.**

sopuli-dba is a command-line tool for database administrators. It keeps the
password of a database account in a *vault* — a server built to store secrets and
hand them out to the applications that need them — and then makes the database
agree with what the vault holds. The vault is always the source of truth for a
password. The database never is.

Oracle is the first database it supports, and it is designed so other database
products can be added later.

---

## Why use it

### The problem it solves

If you've looked after Oracle databases for a while, you probably know this
picture:

- An application account's password was set years ago, and nobody dares change
  it. Nobody is sure which application servers, batch jobs and reporting tools
  have it in a config file, and a single missed one means a 3 a.m. call.
- When it *does* get changed, it's a planned change window with the application
  teams on standby. Someone runs `ALTER USER`, someone else edits config files,
  and everyone hopes the list of places was complete.
- The one place that was missed keeps trying the old password until
  `FAILED_LOGIN_ATTEMPTS` locks the account, and then *every* application using it
  is down.
- The password has passed through e-mails, tickets, wiki pages and the heads of
  people who have since left.
- An auditor asks when this account's password was last changed and who knows it.
  The honest answers are "a long time ago" and "we're not sure".

The root cause is that **the password lives in too many places, and people have
to carry it between them.**

### What changes with sopuli-dba

The password is stored in one place: the vault. Applications read it from there
when they start or reconnect, instead of from a config file. The tool's job is to
keep the database in agreement with the vault. That gives you:

- **Nobody has to know the password.** The tool draws a random one, writes it to
  the vault and sets it on the database. No person reads it, types it or pastes it
  anywhere, so nobody can leak it or take it with them when they leave.
- **Rotation becomes routine instead of an event.** `sopuli creds rotate`
  generates, applies, verifies and publishes a new password in one guarded
  operation. Because nobody has to update config files by hand, you can run it as
  often as your policy asks: monthly, quarterly, or right after someone who knew
  the old password leaves.
- **The new password is published only after it works.** The vault holds the new
  password as `pending` while the tool sets it on the database and then *logs in
  with it*. Only when that succeeds is it promoted to `current`, the version
  applications read. If a run fails partway, nothing is promoted and the new
  password stays in the vault as `pending`, so running `sopuli creds apply` again
  finishes the job. That keeps the vault honest, but it does not by itself keep
  applications running: once a database has the new password, the old one stops
  working there, unless a rollover window (the next point) keeps it valid.
- **Applications don't have to switch at the same second.** On Oracle releases
  with gradual password rollover, the tool can put the account on a profile that
  keeps the old password valid for a window you choose. Applications pick up the
  new one as they reconnect, and when the window closes (or when you close it
  early with `sopuli creds finish-rollover`), only the new password works.
- **One account on many databases stays consistent.** The same application account
  on twenty tenant databases, or across dev, test and prod, is one entry in the
  config file. One command brings them all in line, and `--dry-run` shows exactly
  what it would do first.
- **You find out about drift before the applications do.** `sopuli creds check`,
  run from a scheduler, logs in with the vault's password and reports whether each
  database still accepts it. If someone changed the password by hand, you hear
  about it from a report, not from an outage. Before it tries, it reads the
  account's failed-login count, and does not try if one more failure would come
  too close to the lockout limit. Reading that count needs one optional grant
  (`SELECT ON SYS.USER$`); without it the check still runs, and each result says
  that the lockout guard was unavailable.
- **You get evidence for the auditor.** Every run can produce a machine-readable
  report of what was checked and what was changed. `sopuli creds status` shows
  each account's vault version, how old that password is, and when the database
  last recorded a password change, and the vault entry itself records when the
  tool last rotated it and which user on which host ran it. "When was it last
  changed, and by whom?" gets a real answer.

### What it asks of you

The benefits depend on one thing: **applications have to read the password from
the vault.** If today they hold it in a properties file, moving them to the vault
is the first step, and it's work the tool can't do for you. It doesn't have to
happen all at once, though. You can move one application at a time, and an
application that already reads from a vault gains everything above as soon as its
account is in the config file.

For applications on Kubernetes, the vault-to-application step can be automatic:
see [`docs/scenarios/kubernetes-eso.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/scenarios/kubernetes-eso.md).

---

## Status

**Pre-alpha. Do not point this at a production database yet.**

| | |
|---|---|
| **Install** | Nothing is published to PyPI yet — you install from a git checkout. `sopuli --version` and `sopuli about` report the installed distribution's version |
| **Databases** | Oracle only. CI runs against Oracle AI Database 26ai Free 23.26.2.0.0. The maintainer also tests 21.3.0.0.0, 18.4.0.0.0 and 11.2.0.2.0 XE, 19.3.0.0.0 and 12.2.0.1.0 EE, and 19.32.0.0.0 on OCI. 12.1 is not tested |
| **Vaults** | HashiCorp Vault only. `oci`, `file` and `keyring` can be written in a config file, but this build has no code for them and says so when you try |
| **What works** | The commands `sopuli --help` lists, including a full password rotation from end to end. [`docs/local-testing.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/local-testing.md) is the by-hand map of exactly what this build can be made to do |

If you want the full design picture — every decision, and every question that is
still open — start at [`docs/README.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/README.md).

*(Build-status and coverage badges will go here once the repository is public and
CI runs on it. There are none yet, and a fake one would be worse than none.)*

---

## What this is not

- It **does not create or drop database accounts.** The account has to exist
  already.
- It **does not manage grants, roles or privileges.** That is a separate feature,
  and it is not built.
- It **never reads a password back out of a database.** Oracle does not store
  passwords in a form anything can read back, and the tool does not try.
- It **is not a general-purpose secrets manager.** It writes one specific kind of
  document to your vault — a database account's password — and reads that same
  document back. Everything else in your vault is none of its business.

---

## Installing

**Install the backends you have, not all of them.** Every client that exists to
reach one vendor — a secret store or a database — is an install extra. The base
install carries the CLI, the config layer and nothing that opens a socket, so
`pip install sopuli-dba` gives you a tool that can read and validate a config and
reach nothing.

An *extra* is Python packaging's word for an optional part of a package. You ask
for one by putting its name in square brackets after the package name, and `pip`
— the program that installs Python packages — then installs the extra
dependencies that part needs.

| Install | Adds | Use it when |
|---|---|---|
| `pip install sopuli-dba` | nothing beyond the CLI and the config layer | you only need `config validate`, `config show`, `target list` — in an editor, a linter, a pre-commit hook |
| `pip install "sopuli-dba[oracle]"` | `python-oracledb` | you manage Oracle databases |
| `pip install "sopuli-dba[hashicorp]"` | the HashiCorp Vault client | your secrets are in HashiCorp Vault |
| `pip install "sopuli-dba[oci]"` | the OCI SDK | your secrets are in OCI Vault / Secrets |
| `pip install "sopuli-dba[notify]"` | an HTTP client for the notify webhook | `account reset-password` posts a notice to a webhook |
| `pip install "sopuli-dba[all]"` | every extra | CI, or you genuinely have all of them |

A working install is one store plus one database. For most sites that is:

```
pip install "sopuli-dba[oracle,hashicorp]"      # or [oracle,oci]
```

`sopuli-dba[all]` exists for CI and the test matrix. It is deliberately not the
recommended line: a tool that handles credentials should be able to answer "what
is in its dependency tree" with the vendors you actually use, and vendor SDKs
carry version constraints — the OCI SDK pins `cryptography` and `pyOpenSSL` —
that a site with no OCI should not inherit.

**Oracle needs Instant Client too.** `sopuli-dba[oracle]` installs the driver;
thick mode is required — for Native Network Encryption, for Oracle 11.2 and for
`auth: external` — so Instant Client is a
runtime prerequisite on every platform. `sopuli doctor` checks for it, and
reports which backends are installed against which your config declares.

If a config names a backend this machine cannot serve — the client is not
installed, or this build has no module for that backend yet — `config validate`
warns and still passes. The file is fine; the install is incomplete. The first
command that needs to connect stops instead, with the install line where there
is one to give:

```
$ sopuli creds check --application acme
error: vault "oci-prod" declares type "oci", but that backend is not installed
       install it with:  pip install "sopuli-dba[oci]"
```

The rule and what it costs: [ADR-006](https://github.com/villebase/sopuli-dba/blob/main/docs/decisions/adr-006-optional-dependencies.md).

> **Status: pre-alpha.** The extras above are declared in `pyproject.toml` and
> the registry behind them resolves a backend on first use.
> **`hashicorp` is the one secret store that exists** — KV v2 and KV v1, with
> token, AppRole, Kubernetes and userpass auth. Every command that reaches a
> store reaches that one. `oci`, `file` and `keyring` are accepted in a config
> and report that this build has no module for them. Nothing is on PyPI yet.

Step-by-step, including your first config file:
[`docs/getting-started.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/getting-started.md).

---

## Is this safe to use?

The honest answer for today is in the status box above: it is pre-alpha, so treat
it as something to try against a test database first. What follows is what the
tool does to protect you once you do trust it with something that matters.

**You can always see a change before it happens.** Every command that changes
something takes `--dry-run`, which prints exactly what the command would do and
then stops without doing it. No setting can take `--dry-run` away from you. It is
the one thing that is never blocked, because a preview is how you work out
whether to say yes.

**You can require somebody to say yes.** In the config file you can list the
environments — `prod`, `uat`, whatever you call them — that a change may not
enter without an explicit confirmation. That is the `safety.confirm_environments`
setting. When a run reaches one of those environments it asks first. There is no
built-in list: if you write nothing, nothing prompts.

**A safety setting can only be made stricter, never looser.** A config file can
be layered — a site-wide file, then a team's file, then a command-line flag.
For most settings the most specific layer wins. For the safety settings it is the
*safest* layer that wins, wherever it sits. So a subteam's file cannot switch off
a rule the site-wide file turned on. It can only add more.

**A scheduled check is guarded against locking the account out.** To find out
whether the vault's password still works, the tool has to try logging in — and a
failed login counts against Oracle's failed-login limit. So before it tries, it
reads how many failed attempts the account has already collected. If one more
attempt would come too close to the limit, it does not try. It reports that it
could not check, and says why. Checking is never worth locking out the account
you were checking on.

That guard needs one optional grant: `SELECT ON SYS.USER$`, which lets the tool
read the failed-login count. Without it, the check still runs. It logs in once
per account per run (twice with `--include-previous`, which also tries the
previous password), and every result from a login it attempted says that the
lockout guard was unavailable.
The grant is not part of the standard install, because it is a broad read.
[`docs/security-model.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/security-model.md) §3 explains the trade-off.

**Passwords do not reach your logs.** A password is held in a wrapper type whose
text form is `***`, so printing one prints the mask, in ordinary output and in a
crash traceback alike. A secret reaches output in only these cases, and each
one is asked for on purpose:

- `policy sample --reveal` shows sample passwords, so you can see what your
  password rules produce. Nothing logs in with a sample.
- `account reset-password` with `delivery.method: manual` prints the new
  password for a person to read. It asks every time, needs a terminal, and
  expires the password so the person must change it at first logon.
- `account reset-password` with `delivery.method: vault_wrapped` prints a
  short-lived, single-use token that fetches the password. It is never in the
  JSON run document; with `--output json` it goes to stderr.

The two that print a password refuse machine-readable JSON output, because JSON
output is what gets shipped to a log collector.

**A password containing a double quote is rejected, not escaped.** Oracle's
quoted identifiers have no escape sequence for `"`, so there is no correct way to
send one. The tool refuses the password rather than mangling it.

**What Oracle itself keeps is measured, not assumed.** `ALTER USER` takes the
password as a literal — DDL cannot use bind variables — so the question is what
the server retains afterwards. A probe plants a canary per execution path and
sweeps every source a statement's text can come to rest in, on each version;
that is release gate 2, and its results are the reason two of the tool's design
rules exist. The findings, per version and with their scope:
[`docs/design/02-oracle-privileges.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/design/02-oracle-privileges.md) §4.

The longer version, for deciding whether to trust this with a production
credential: [`docs/security-model.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/security-model.md).
To report a security problem privately: [SECURITY.md](https://github.com/villebase/sopuli-dba/blob/main/SECURITY.md).

---

## Quick example

Three commands take a password from nowhere to in-use. This is a real run against
a local Oracle container, trimmed to the lines that matter.

```bash
# 1. Draw a new random password and park it in the vault as `pending`.
#    Nothing is sent to any database by this command.
sopuli --config sopuli.yaml creds generate

# 2. Set that password on the database, check it works by logging in,
#    and only then promote it in the vault from `pending` to `current`.
sopuli --config sopuli.yaml creds apply

# 3. Ask whether the vault's password still works. Run this from a scheduler.
sopuli --config sopuli.yaml creds check
```

Step 1 says what it staged, and reminds you that no database has changed yet:

```
ACCOUNT        SECRET                 RESULT
acme_app_user  vault-dev:acme/dev/db  staged v1

1 staged; no database was changed -- run `sopuli creds apply` to use them
```

Step 2 shows the order that makes this safe. `SOURCE pending` is the password it
took from the vault; `1 promoted to current` happened only after the database
accepted it:

```
ACCOUNT        TARGET    SECRET                 SOURCE
acme_app_user  free-pdb  vault-dev:acme/dev/db  pending

ACCOUNT        TARGET    STATE    DETAIL
acme_app_user  free-pdb  IN_SYNC  changed and verified by login

1 changed, 1 promoted to `current`
```

Step 3 answers one question per account, and exits 0 because there is nothing
wrong:

```
ACCOUNT        TARGET    STATE    DETAIL
acme_app_user  free-pdb  IN_SYNC  vault v2 verified by login

all 1 in sync
```

Running step 2 a second time changes nothing and says so — which is what makes
the tool safe to run from a scheduler.

The full walkthroughs, with the config file these commands read and what to do
when an answer is not `IN_SYNC`, are in
[`docs/scenarios/`](https://github.com/villebase/sopuli-dba/tree/main/docs/scenarios/).

---

## How this project is built

sopuli-dba is developed with AI coding agents, under a process designed to make
that safe for a tool that handles credentials. Design decisions are the
maintainer's, and each is recorded as a GitHub issue or decision record,
including the options that were rejected and why. An agent that meets an open
design question while implementing stops and asks, or proposes an answer in the
pull request, and the answer stands only once the maintainer accepts it. Agents
implement against the design documents, which are the specification rather than
a description written afterwards. A change that alters behaviour updates the
relevant document in the same pull request.

What the tool claims about a database is measured on real releases, not reasoned
about, and every sample output in the documentation is pasted from a real run.
That is why the documentation is long: it is written so a reviewer, human or not,
can see *why* each rule exists before changing it.

How this works in practice, and what it expects of contributors:
[CONTRIBUTING.md](https://github.com/villebase/sopuli-dba/blob/main/CONTRIBUTING.md#how-this-project-is-built-and-what-that-means-for-you).

---

## Learn more

| Read this | If you want to |
|---|---|
| [docs/getting-started.md](https://github.com/villebase/sopuli-dba/blob/main/docs/getting-started.md) | install the tool, write your first config file, and run one command safely |
| [docs/scenarios/rotate-and-sync.md](https://github.com/villebase/sopuli-dba/blob/main/docs/scenarios/rotate-and-sync.md) | follow one password rotation from start to finish |
| [docs/scenarios/kubernetes-eso.md](https://github.com/villebase/sopuli-dba/blob/main/docs/scenarios/kubernetes-eso.md) | let applications running in Kubernetes pick up the new password automatically |
| [examples/](https://github.com/villebase/sopuli-dba/tree/main/examples/) | three complete config files, commented, from smallest to safety-hardened |
| [docs/security-model.md](https://github.com/villebase/sopuli-dba/blob/main/docs/security-model.md) | decide whether to trust this with a production credential |
| [docs/local-testing.md](https://github.com/villebase/sopuli-dba/blob/main/docs/local-testing.md) | exercise every command by hand, including the failures worth causing on purpose |
| [CONTRIBUTING.md](https://github.com/villebase/sopuli-dba/blob/main/CONTRIBUTING.md) | send a change |
| [SECURITY.md](https://github.com/villebase/sopuli-dba/blob/main/SECURITY.md) | report a security problem privately |
| [CODE_OF_CONDUCT.md](https://github.com/villebase/sopuli-dba/blob/main/CODE_OF_CONDUCT.md) | know what is expected of everyone taking part |
| [docs/README.md](https://github.com/villebase/sopuli-dba/blob/main/docs/README.md) | read the full design: principles, configuration reference, Oracle privileges, JSON output contract, testing strategy, and every decision record |

Licensed under [Apache 2.0](https://github.com/villebase/sopuli-dba/blob/main/LICENSE).

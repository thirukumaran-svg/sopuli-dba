# Security policy

## Reporting a vulnerability

**Please do not open a public issue.** A public issue is visible to everyone
before anything is fixed.

Report it privately, by either route:

- **Email `sopuli-dba@proton.me`.** This is the address to use today, and it is
  the one that works whatever state the repository is in.
- **GitHub's private vulnerability reporting** — on the repository's *Security*
  tab, choose *Report a vulnerability*. This creates a private advisory only the
  maintainers can see. It is enabled once the repository is public.

There is no PGP key. If you need one to send the report, say so in a first
message with no details in it and one will be arranged.

### What to include

Whatever you have. A report with less in it is better than no report:

- what the problem is, and what an attacker gets out of it;
- the steps to reproduce it, or the code path if you found it by reading;
- the version — `sopuli --version` — and, if it is relevant, the Oracle release
  and the secret store you were using.

**Do not include a real password, a real vault path, a real hostname or a real
account name.** If a demonstration needs one, describe its shape or use the
project's fictional vocabulary (`acme`, `acme_app_user`, `example.com`,
`192.0.2.0/24`).

### What happens next

This is a solo project, so the honest version rather than a service-level
promise:

- You get an acknowledgement that the report arrived, normally within a few days.
- You get an assessment — whether it is a vulnerability, and how serious — once
  there has been time to look properly.
- You are told when a fix ships, and credited in the advisory unless you would
  rather not be.

If you have had no reply at all after two weeks, the message probably did not
arrive. Send it again.

## Which versions are supported

**None, formally.** This project is pre-alpha and is not published to PyPI.
There are no maintained release branches, so a fix lands on `main` and in the
next release. Report anything you find against `main` or against the most recent
release, and it will be looked at.

That will change when there is a stable release; this section is where it will
say so.

## What is in scope

This project, its documentation, and the SQL in `sql/oracle/`.

Some things are known and are not vulnerabilities, because they are the design.
Reporting them is welcome but the answer will be a pointer to
[`docs/security-model.md`](docs/security-model.md), which explains each of them
in full:

- **The service account can change any password in its container, including
  `SYS`.** Oracle has no way to grant `ALTER USER` for one account only —
  `GRANT ALTER USER ON SCHEMA` is rejected with `ORA-00990`, tested. The tool
  cannot narrow what Oracle does not let it narrow.
- **The account guardrails are client-side and can be bypassed by not using the
  tool.** They protect against a typo and a too-wide config change. The security
  boundary is the database's own auditing, and `docs/security-model.md` says so
  rather than claiming otherwise.
- **`policy sample --reveal` prints a password.** It prints a *sample*: nothing
  authenticates with it, it is never stored, and it guards nothing. It is refused
  together with `--output json`.

A finding that one of those guarantees does not hold in practice — a redaction
that leaks, a guardrail that fails open, an ordering that promotes before the
database has confirmed — is very much in scope.

## Thank you

Finding this kind of problem takes real work, and reporting it privately takes
more. It is appreciated.

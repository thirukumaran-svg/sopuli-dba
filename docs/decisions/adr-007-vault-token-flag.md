# ADR-007 — `--vault-token-file` takes a path; `--vault-token` is refused

Status: **accepted**
Related: `../design/00-principles.md` (P2, P4, P5, invariant 1),
`../design/01-configuration.md` (§3a, §6, C16),
`../design/03-json-output.md` (`invocation.options`),
`../use-cases/uc-01-app-credential-sync.md` (§5, `--from-stdin`), issue #145

---

## Context

`--vault-token` appeared in three design documents and **never once carried a
value**. Every mention treated it as a step in a chain — "`--vault-token`, then
`$SOPULI_VAULT_TOKEN`, then `$VAULT_TOKEN`, then `~/.vault-token`" — and none
said what an operator types after it.

The obvious reading is forbidden. A token given as a command-line value is
visible in `ps` and in the Windows process list, and P5 states the rule without
qualification: secrets "come from stdin, a file, or a vault ref".

The third of those is circular here. **A SecretRef is resolved *by* an
authenticated store, so it cannot be what authenticates one.** That is not a new
problem; it is P2's bootstrap problem — external auth, then a vault path
authenticated by machine identity, then an interactive prompt, then a
low-assurance environment variable — showing up one layer earlier, against the
store instead of against the database. Naming it as the same problem is half the
decision, because it says which shapes are available before any of them is
argued for: machine identity, a file, an interactive act, and the environment.

Nothing was blocked by this. #137 landed `resolve_token` with the flag's value as
a parameter and a working fall-through, and #138 shipped the auth methods against
that chain, so a laptop and a CI job both authenticated with no flag in existence.
That is the reason to decide it deliberately rather than in a diff: a signature
with a `flag: Secret | None` parameter waiting is exactly where an invariant gets
violated by accident, because the wrong answer is the one that requires no
thought.

## What did not decide it

- **Symmetry with Vault's own CLI.** `vault -token=…` is why somebody will type
  `--vault-token` and therefore why it must be *answered*, but it is not an
  argument for accepting it. Compatibility with another tool's interface does not
  outrank invariant 1.
- **Typing convenience.** `--vault-token-file` is longer than `--vault-token`.
  The chain already has three sources needing no flag at all; the flag is for the
  case where none of them fits, which is not the common case.
- **`03-json-output.md`'s existing sentence.** It said "`--vault-token` names the
  flag; the token never appears", which reads like a resolution and is not. It
  governs what may appear **in the run document**; invariant 1 governs what may
  appear **in argv**. A flag carrying a token would have satisfied the first rule
  perfectly and still been forbidden by the second.

## Decision

**`--vault-token-file PATH`.** It hoists the `token: { file: … }` shape
`01-configuration.md` §3a already documents onto the command line, the same way
`--vault-addr` hoists `vaults.*.addr`. No new grammar, no new concept, and the
auth-methods list in P2 already said "token (`VAULT_TOKEN`, token file, token
helper)".

**`--vault-token` is declared and refused**, not absent and not ignored.

- *Absent* answers with click's "no such option", which is correct and teaches
  nothing about why.
- *Ignored* is worse than either: a flag that parsed and did nothing leaves an
  operator believing the token was used. That is a plan which looks like it
  accounted for authentication and did not — the failure mode P5's plan-first
  rule exists to prevent elsewhere.

It is accepted in both click parser positions, in all three spellings
(`--vault-token`, `--vault-token X`, `--vault-token=X`), so that whichever way
somebody writes it they get the explanation rather than a parser complaint. The
value it carried is discarded in the parser callback: what travels is a boolean
saying the flag was written, so there is no field on any object between the
parser and the store where a token could sit.

**The refusal names all four working sources**, not only the file form:

```
sopuli: --vault-token is not an option: a token given on the command line is
        visible in `ps` and in the Windows process list (P5, invariant 1)
  hint: name where the token is instead of passing it. Any of:
        --vault-token-file PATH, $SOPULI_VAULT_TOKEN, $VAULT_TOKEN, or
        `vault login`, which writes ~/.vault-token
```

A CI job where writing a token to disk is awkward is precisely the case that hits
this, and `SOPULI_VAULT_TOKEN=… sopuli …` already works. A hint recommending the
file form alone would read as though the file were the only way out.

### Exit 2, and why not a plan-time refusal with a document

The refusal fires in `resolve_invocation`, before any other work in a run, and
raises `ArgumentError` — exit 2. That is P5's code for "argv did not resolve to a
valid command and options", which is exactly what a flag the tool does not have
is. J7 (issue #8) then makes exit 2 the one code that carries **no** run
document, so this cannot be reported *inside* a plan the way a missing capability
(exit 5) is: there is no run to describe.

What it keeps from the plan-first mechanism is the part that matters. It is not a
one-off argparse check bolted to a callback: it lives beside `check_output_mode`
in the invocation layer, it fires under `--dry-run` like any other, and a
rehearsal therefore cannot come back clean while the flag silently did nothing.

### The flag's file is permission-checked

`--vault-token-file` is a bearer token on disk, so it gets P4's check — the same
one that refuses a config file other people can reach — and refuses when anyone
but the owner has access.

This is a deliberate exception to §3a's rule that a `file:` MaterialRef is *not*
permission-checked, and the two paths it does not extend to are the reason the
rule exists:

- **`token: { file: /run/secrets/… }`** belongs to whatever mounted it. A
  Kubernetes projected token arrives mode 0644, and refusing to read it would
  break a method P2 lists.
- **`~/.vault-token`** is Vault's own file, written 0600 by `vault login`.
  Refusing the file another tool just wrote for us would refuse the bootstrap
  named below as the answer for a human at a terminal.

What is left is the path an operator typed for *this* run — which is P4's own
case, in P4's own words: the person reading the message is the one who can fix
it, here, now.

### The chain, not the settings resolver, is where the flag merges

`--vault-token-file` accepts both click parser positions and the verb's wins,
like every other inert global option. It is **not** a registered setting, and it
does not appear in `invocation.options`.

§3a's token chain *is* its merge — a store's own `token:`, then this flag, then
the variables, then `~/.vault-token` — and it is resolved when a run reaches a
store. Registering half of it in `sopuli/settings/` would give the tool two
resolvers for one question, and would put a row in `invocation.options` claiming
the precedence engine settled something it never saw. `auth:` is already absent
from the registry for a related reason: it is a block, replaced whole.

## The interactive prompt, and why there is no fifth option

P2's bootstrap order for the *database* admin credential includes an interactive
prompt, and the vault-token chain has no equivalent. The question is whether a
DBA at a terminal with no `~/.vault-token` is left with nowhere to go but "write
a file first".

**They are not, and the answer is `vault login`.** It writes `~/.vault-token`,
which is the last step of the chain, so the human path already exists and is one
command — the same command they would run before using Vault's own CLI. That is
confirmed here as the intended bootstrap rather than left implicit.

A prompt was considered on its merits and is not added:

- It would be a **fifth** place a token can come from, and the value of a short
  chain is that an authentication failure can be explained.
- It cannot work unattended or under `--output json`, so every non-interactive
  caller would need the chain anyway.
- It competes for the same stdin the one-stream rule below governs.

Revisit if a real site turns out to have a terminal where `vault login` is not
available.

## `--vault-token-stdin` is deferred, and its rule is banked now

stdin is not taken because `--from-stdin` (UC-1 §5) already claims the pipe for a
supplied password on `creds apply`. Two readers, one stream.

The constraint that a future `--vault-token-stdin` would have to satisfy is
written into P5 **today**, before the flag exists: *one stream, one reader; a
command needing both refuses at plan time*. Banking it now is the point — whoever
adds the flag should not also be the one who has to rediscover the collision.

## What was rejected

**`--vault-token env:NAME` | `file:PATH`, reusing the MaterialRef grammar.** One
syntax meaning one thing everywhere is a real argument, and this is not an
instance of it. It is a **semantic collision**: `env:` / `file:` in a SecretRef
means "resolve this via an already-authenticated store", and using the identical
spelling for the thing that *authenticates* the store gives two grammars that
look the same and resolve in opposite order. §3a already names the two types
apart — MaterialRef and SecretRef — precisely so the chicken-and-egg stays
visible rather than being papered over by one word meaning both. This is the kind
of thing that reads well in a design document and costs somebody an afternoon in
a support thread.

**`--vault-token-env NAME`.** Redundant with `$SOPULI_VAULT_TOKEN` and
`$VAULT_TOKEN`, which a CI job can already set to whatever it likes by exporting
under that name. It buys a variable of one's own and nothing else, at the price of
a fifth step in the chain.

## Consequences

- `01-configuration.md` §1, §3a and §6 name `--vault-token-file`; §11 records the
  decision as C16.
- `00-principles.md` P2 names the vault-credential bootstrap as the same shape as
  the database one, and P5 carries the location rule and the one-stream rule.
- `03-json-output.md` loses `--vault-token` as its `source_detail` example and
  records why the two rules are not one.
- `sopuli/material.py` takes `token_file: Path | None`, not `flag: Secret | None`.
  **No signature between the parser and §3a's chain has a slot a command-line
  credential could occupy**, which is invariant 1 made structural rather than
  remembered. `sopuli/store/registry.py`, the HashiCorp backend and
  `sopuli/cli.py` forward the path the same way.
- `tests/test_cli_smoke.py`'s invariant-1 guard gains an allowlist of exactly two
  option names, each held to its reason by a test: one takes a path, one refuses.
  The list is a literal rather than a suffix rule, so a third entry is a line
  somebody has to write and defend — `--password-file` should not be admitted by
  a pattern.

## The cost accepted

A token file mounted 0644 by a platform cannot be named with `--vault-token-file`;
it has to be written as `token: { file: … }` in the config, or supplied through
`$SOPULI_VAULT_TOKEN`. That is a real asymmetry between two spellings of "read
the token from this path", and it is accepted because the alternative is worse in
both directions: checking every `file:` breaks the Kubernetes method P2 lists,
and checking none of them means the one path an operator can fix in the moment
goes unguarded.

## Follow-ups

- `--vault-token-stdin`, if anything ever needs it, against P5's one-stream rule.
- The remaining CLI hoists of `vaults.*` reach settings, so they go through the
  resolver rather than beside it. #154 delivered the `SOPULI_VAULT__<NAME>__*`
  half of C13's addressing and closed without `--vault-addr`, which is now #422
  — including whether it should exist at all. The analogy in *Decision* above is
  to a flag that has not been built.

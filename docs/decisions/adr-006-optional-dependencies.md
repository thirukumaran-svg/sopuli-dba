# ADR-006 — Vendor clients are install extras; base sopuli opens no sockets

Status: **accepted**
Related: `../design/00-principles.md` (P1, P2, D3, D6, D9),
`../design/01-configuration.md` (§3a),
[ADR-005](adr-005-vault-client.md) (`httpx`), issue #130

---

## Context

sopuli reaches two kinds of remote system: secret stores (P2) and databases
(P1). Every client that exists to reach one of them is a dependency that only
some sites need. A site with OCI Vault and Oracle needs the OCI SDK and
`python-oracledb`; it has no use for a HashiCorp client, an AWS client, or a
PostgreSQL driver, and installing them buys it nothing.

The question is whether those clients belong in the base install or behind
`pip install "sopuli-dba[<name>]"`. It arrives now rather than later because
**extras are a published interface**. Moving a dependency out of base after a
release breaks every install that never named the extra; moving one *into* base
is harmless. The default chosen at the first release is the one that is hard to
change afterwards, which makes this cheaper to decide than to retrofit.

## What did not decide it

- **Install size.** Wheels are cheap and disk is cheaper. If this were the
  argument, `sopuli-dba[all]` everywhere would be the answer and nobody would
  notice.
- **Import time.** Lazy imports fix a slow start-up on their own, without any
  packaging change. They are a *consequence* of this decision, not a reason for
  it.
- **Pluggability.** P2 already puts stores behind an interface and D6 already
  settles that the registry stays in-tree. Extras change when a dependency is
  installed, not what the tool is able to address.

## Decision

**Every dependency that exists only to reach one vendor is an install extra.**
The base install carries what every invocation uses and nothing else.

| Layer | Contents | Installed by |
|---|---|---|
| base | CLI framework (`click`, ADR-002), YAML parser (`pyyaml`, ADR-004), `pywin32` on Windows for P4's permission check, and sopuli itself | `sopuli` |
| store extras | one vendor client per secret store | `sopuli-dba[<store>]` |
| driver extras | one database driver per product | `sopuli-dba[<product>]` |
| notify extras | the client a notify channel posts with (E7, #442) | `sopuli-dba[notify]` |
| `all` | every extra above | `sopuli-dba[all]` |

`pywin32` is in base and is not a counter-example: it is selected by a platform
marker, not by a backend the operator configured. Every Windows invocation uses
it, and no Linux install receives it.

`jsonschema` is **not** in base. The published schema is an editor aid and a CI
check (`01-configuration.md` §9b); `config validate` runs through the builders,
which are the stricter of the two. It stays a development dependency, which is
where `pyproject.toml` already has it.

Three rules follow, and they are what makes the split real rather than
cosmetic:

1. **A vendor client is imported inside its backend module, never at package
   import time.** The registry maps `type:` to a module path and imports on
   first use.
2. **A missing backend is a diagnosable condition, not a traceback.** An
   `ImportError` at registry resolution becomes a structured error naming the
   extra that supplies it, with `error.category: "config"` and exit 9.
3. **Nothing in base opens a socket.** This is the property being defended.
   What a test can hold is the dependency set that stands for it: in a base
   install none of the clients the backends reach with — `httpx`, the OCI SDK,
   `python-oracledb` — is importable. The standard library's `urllib` and
   `http.client` are importable in every Python and no packaging rule changes
   that, so they are covered by the rule's intent rather than by its assertion:
   base code does not reach the network, whatever it would reach it with.

Rule 3 is true of `pyproject.toml` today. That is the cheap case, and the reason
to write it down now — this ADR defends a property the project already has
rather than describing a migration it has to perform.

## Why it is a decision rather than a packaging detail

**The dependency tree is a reviewed artefact.** sopuli's whole subject matter is
credentials, so "what is in the tree" is a question a security review will
actually ask. "Only the vendors you use" is a materially better answer than "all
of them, whether or not you have that vendor". A site with only OCI Vault should
not have to get a HashiCorp client past review in order to install the tool.

**Vendor SDKs carry version constraints that collide.** The OCI SDK pins
`cryptography` and `pyOpenSSL` to upper bounds and vendors its own copy of
`requests` under `oci._vendor`. Those constraints have to coexist with
`python-oracledb` and with whatever the operator already has in the environment.
A site that does not use OCI should not inherit them, and should not be blocked
from upgrading by a bound belonging to a backend it never configured.

## What base sopuli can still do

Every command that does not open a connection works with no backend installed:

- `sopuli config validate`
- `sopuli config show --resolved --explain`
- `sopuli target list --select …`
- schema-driven editor assistance, which is a static artefact and never had a
  runtime dependency

This is what makes the boundary honest rather than a trick. Validating a
`vaults.hcv-prod` block is config-layer work; only *connecting* needs the
client. A config naming eleven backends validates with none of them installed.

## Consequences

**Drivers follow the same rule as stores (E1).** `python-oracledb` exists only
to reach Oracle, so it is `sopuli-dba[oracle]`. Symmetry decides it: a split that
bound stores and not drivers would read as arbitrary the first time somebody
asked why. The cost is an interface with one member today, and D3's thick-mode
Instant Client prerequisite already makes reaching Oracle a per-site runtime
condition rather than a universal one — the extra names a fact that was true
anyway.

**The HashiCorp backend has an extra, and `httpx` is in it (E2).** ADR-005
decided the HTTP API over `httpx` rather than `hvac`, and originally recorded
`httpx` as a base dependency on the grounds that a generic transport is not a
vendor client. That is right about `httpx` and wrong about the outcome: a
third-party HTTP client in base is still a network client in base, and rule 3
names the installed dependency set precisely so that a test can hold it, and
`httpx` in base is exactly as visible to that test as an SDK would be. Nothing
else in base wants `httpx`, so putting it behind `sopuli-dba[hashicorp]` costs
nothing and keeps the property testable. ADR-005's consequence is amended
accordingly; the client choice itself is untouched.

**`sopuli-dba[all]` exists, and is not the recommended install (E3).** CI and the
test matrix need one name that means everything, and inventing it later is
worse than having it from the start. But user-facing installation instructions
recommend the extras a site actually has, because a README whose first line is
`sopuli-dba[all]` quietly undoes the benefit for every reader who copies it.

**`config validate` warns on a backend this machine cannot serve (E4).** It
does not fail. The config is valid; the install is incomplete. Telling an
operator their file is broken when it is not would make `config validate` less
trustworthy for the case it exists to serve — and validating on a laptop a
config that runs elsewhere is the common case, not the strange one.

**"Cannot serve" is the wide reading, and it was not always** (amended in #238).
The word originally in this paragraph was *uninstalled*, and it was implemented
as *the client is not on this machine* — which left the validator silent about
`file` and `keyring`, whose backends do not exist in this build for anybody, and
silent about `oci` on any machine that happened to carry the SDK. Three of the
four types in `01-configuration.md` §3a have no module, so a file declaring all
four reported one warning, and which one depended on the laptop rather than on
the file. A validator quiet about a store that cannot work is failing at its one
job, so E4 now covers both halves:

| What is wrong | What the warning says |
|---|---|
| the extra's client is not installed | *install it with:* `pip install "sopuli-dba[…]"` |
| this build has no module for it | *this build has no `<type>` backend yet — this is not something to install* |

The cost accepted here is a **warning `pip` cannot act on**: a reader who writes
`type: file` sees the second line on every run until the backend is written. That
is worth paying because the action it names is a real one — *do not deploy this
yet* — and because it is temporary by construction, disappearing backend by
backend, where the silence it replaces was permanent. It is one code
(`SOPULI-W003`) rather than two: both are the same outage and differ only in the
remedy, and splitting them would make a consumer alerting on an unusable store
subscribe to a pair.

**The failure is `config` / exit 9, not `capability` (E5).** `capability` in
`03-json-output.md` names something a *target* cannot do — a property of the
database at the other end, which no local action changes. A missing backend is
resolvable by installing it, on the same machine, by the person reading the
message; that is the `config` category's shape, and exit 9 already means "fix
your configuration, not your command line" (P5). It carries an `error.code` so
that a consumer can branch on this case specifically without parsing the
message.

**A notify channel is a fourth category, not a reuse (E7).** UC-2's notify channel
posts to a webhook (#442), which needs `httpx` — the same client `[hashicorp]`
already installs. Reusing that extra was the obvious move and is refused: an estate
on OCI Vault that wants a chat message would install a *HashiCorp* extra to get one,
and the property this ADR defends is that an extra names **why** a dependency is
there. A name that has stopped meaning that is a split in appearance only.

The cost is one more name in an install line and one more cell in the matrix, which
is small and is paid by the estates that use the feature. What it buys is that the
three registries — stores, drivers, and now channels — all answer the same question
the same way, and `tests/store/test_install_shape.py` derives its exemptions from all
three rather than from a hand-kept list.

**A channel with nothing to install needs no extra**, and one is coming: a future
`smtp` channel sends with the standard library, so
`sopuli.notify.registry.Notifier.extra` is optional exactly as a store's is. The
category is "the client a channel posts with", not "every channel".

**`doctor` always reports install shape (E6).** Which backends are installed,
which are configured, and where the two disagree — listed every run, not only on
mismatch. `doctor`'s question is "can I reach my vaults", and its output is
audit evidence as often as it is a diagnostic; a section that appears only when
something is wrong cannot be quoted as proof that nothing was. A configured
backend that is not installed is a `doctor` failure.

## Non-goals

- **This is not a plugin system.** The registry stays in-tree, per D6. Extras
  control which dependencies are installed, not which modules exist; a third
  party cannot register a backend by installing a package.
- **No change to `SecretStore`, to the SecretRef grammar, or to capability
  negotiation.** P2's pluggability becomes true at *install* time as well as at
  import time. Nothing about the interface moves.
- **No change to what is Oracle-specific at the top level** (P1).

## The cost accepted

`pip install sopuli-dba` on its own produces a tool that can read a config and reach
nothing. That is a real first-run cliff, and it is paid for in two places rather
than by defaulting to `all`: the root `README.md` leads with an install matrix,
and rule 2 turns the failure into a message naming the exact command that fixes
it.

The named gap: the file backend (P2, priority 3) has no extra yet, because P2
does not say whether age/gpg is reached by subprocess or by a Python library.
Whichever it turns out to be decides the answer, and the rule above already
covers both — a library makes it `sopuli-dba[file]`, a subprocess makes it a runtime
prerequisite like Instant Client. It is not settled here because there is
nothing yet to settle it from.

## Follow-ups

- ~~`pyproject.toml`: the extras themselves, and the store registry's lazy
  import and error mapping~~ — **done in #134.** `sopuli/store/registry.py` maps
  `type:` to a module path and imports on first use; `BackendNotInstalledError`
  carries `SOPULI-20001` and `BackendNotImplementedError` is the separate case
  for a backend nobody has written yet, which is every backend today. The trap
  worth remembering is that both, plus a genuine bug inside a backend module,
  arrive as `ModuleNotFoundError`: the registry matches on `exc.name` against the
  modules the extra provides and re-raises anything else, so our own typo keeps
  its traceback.
- ~~`01-configuration.md` §3a and §9: what a declared-but-uninstalled `type:`
  does, and the `config validate` warning (E4)~~ — **done, and E4 widened, in
  #238.** `config validate` derives its warnings from the same
  `install_shape.survey()` `doctor` reads, through the same
  `install_diagnostics()` at `level="warning"` rather than `"error"`. The pair
  that computed the answer separately, `backend_diagnostics` and
  `driver_diagnostics`, is deleted: two definitions of "this machine cannot serve
  it" is what produced the `doctor` defect fixed in #237, and the second one had
  gone on to produce a `pip` line for a backend `pip` cannot supply.
- `03-json-output.md`: the `error.code` for a missing backend, and the warning's
  diagnostic code (E4/E5).
- ~~E6: `doctor` reporting install shape~~ — **done in #214.** The `install`
  section arrived in schema 1.13 and is emitted on every `doctor` run: one row per
  registry entry, configured or not, so *installed and not configured* is
  reportable and a healthy run can be quoted as evidence. `sopuli/install_shape.py`
  is the survey and asks `find_spec` throughout, which keeps rule 3 true of the
  command that reports on rule 3. Two things worth remembering: `status` is three
  values rather than a boolean, because a backend with an extra and no module —
  `oci` today — would otherwise report itself installable on a developer machine
  that has the SDK and still refuse at connect time; and E6's "a configured backend
  that is not installed is a `doctor` failure" is exit **9**, E5's number, rather
  than a generic 1, so the tool gives one answer to one question.
- `04-testing.md`: install shape as a dimension of the matrix, plus the two
  tier-0 tests — the absent-backend message per backend, and the base install
  importing none of the backends' clients.
- Root `README.md`: the install matrix.

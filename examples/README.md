# Example configurations

Three complete config files, from the smallest one that works to one with the
safety settings turned on. Each is commented for a reader who has not written one
before.

| File | Shows |
|---|---|
| [single-application.yaml](single-application.yaml) | the smallest config that does something useful: one vault, one database, one account |
| [multiple-applications.yaml](multiple-applications.yaml) | the `applications:` shape, target groups, and per-application selection |
| [safety-hardened.yaml](safety-hardened.yaml) | `confirm_environments`, `max_targets`, `readonly`, and profiles |

Check any of them before you use it. This opens no network connection:

```bash
sopuli --config single-application.yaml config validate
```

**All three are checked in CI** (`tests/test_examples.py`), so an example cannot
silently drift out of date with the config layer.

**They point at addresses that are not yours.** The first two point at the
project's own test containers (`127.0.0.1:1521/FREEPDB1`,
`http://127.0.0.1:8200`); the third points at `example.com`, which is reserved
for documentation and reaches nothing. Change the addresses, the account names
and the vault paths before running anything against a real database.

## The one thing that will stop you first

**The tool refuses to read a config file that other people on the machine can
reach.** A file checked out of a repository is readable by everyone who checks it
out, so copying one of these and running it straight away gives you exit 9:

```
sopuli: sopuli.yaml: config file is accessible to BUILTIN\Users
  hint: remove the extra grant, e.g. icacls "<file>" /inheritance:r /grant:r "%USERNAME%:R"
```

That check is not about confidentiality — these files hold no secrets. It is
about tampering: anyone who can write the file can repoint `secret_template` at a
vault path they control, and the tool would then faithfully rotate a production
password into it.

Copy the example somewhere of your own and fix the permissions:

```powershell
# Windows: drop inherited permissions, then grant only yourself.
icacls sopuli.yaml /inheritance:r /grant:r "${env:USERNAME}:F"
```
```bash
# Linux, WSL: owner only, nobody else at all.
chmod 600 sopuli.yaml
```

## Seeing what a file resolves to

Two commands answer most questions about a config without connecting to
anything:

```bash
# Which databases does this file actually resolve to?
sopuli --config safety-hardened.yaml target list
```
```
config: safety-hardened.yaml

NAME         DSN                                ENV   SCOPE  SOURCE
prod-orders  db-orders.example.com:1521/ORDERS  prod  pdb    targets
uat-orders   db-uat.example.com:1521/ORDERS     uat   pdb    targets

2 targets (2 explicit)
```

```bash
# Every effective setting, and which layer of config produced it.
sopuli --config safety-hardened.yaml config show --explain
```

`--explain` is worth knowing because of the safety ratchet: a safety setting can
be made stricter by any layer and looser by none, so "which layer won" is not
always the one you would expect. Running it against `safety-hardened.yaml` with
its `audit` profile selected shows the ratchet saying so out loud.

`--output text` is on that command line because the `audit` profile sets
`output: json`, and without the flag you get the same information as a JSON
document. A flag on the command line beats a profile, which is precedence
working:

```
$ sopuli --config safety-hardened.yaml --profile audit config show --explain --output text

settings
  db.connect_timeout_s        = 30          [built-in default]
  db.query_timeout_s          = 0           [built-in default]
  output                      = text        [cli --output (verb)]
  profile                     = audit       [cli --profile (group)]
  safety.confirm_environments = prod, uat   [defaults.safety.confirm_environments]
  safety.dry_run              = false       [built-in default]
  safety.max_targets          = 2           [profiles.audit.safety.max_targets]
                                defaults.safety.max_targets asked for 4; safety.max_targets stays 2 (profiles.audit.safety.max_targets) -- safety settings only ratchet toward safe
  safety.readonly             = true        [profiles.audit.safety.readonly]
  vault                       = vault-prod  [defaults.vault]
```

## More

- [../docs/getting-started.md](../docs/getting-started.md) — writing your first
  config from scratch, with the surrounding steps.
- [../docs/design/01-configuration.md](../docs/design/01-configuration.md) — the
  full reference: every key, every rule, and the validation errors worth causing
  on purpose.
- [../docs/schemas/sopuli-config-1.6.schema.json](../docs/schemas/sopuli-config-1.6.schema.json)
  — the JSON Schema. Put
  `# yaml-language-server: $schema=<path to it>` on the first line of your config
  to get completion and inline errors in an editor, as these examples do.

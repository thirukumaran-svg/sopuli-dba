# Scenario: applications in Kubernetes, picking up the new password themselves

[The rotation scenario](rotate-and-sync.md) ends with a manual step: somebody has
to restart the applications so they collect the new password. This document
removes that step, for applications running in Kubernetes.

**It does that without sopuli knowing anything about Kubernetes.** That is the
part worth understanding before the YAML, so section 1 is about the division of
responsibility rather than about configuration.

## What you need to already have

This document assumes you have a Kubernetes cluster and can install things into
it. If you have never used Kubernetes, this scenario is not the place to start —
it is written for the case where the cluster already exists and somebody else
runs it, and you are the DBA being asked how the password gets in there.

Two terms, defined once and then used:

- **Kubernetes** is a system for running applications across a group of machines.
  A **Secret** is Kubernetes' own object for holding a small piece of sensitive
  data — a password, a token — which it then hands to an application as an
  environment variable or a file.
- **ESO** is the **External Secrets Operator**: a Kubernetes add-on that copies a
  secret from an external store — a vault — into a Kubernetes Secret, and keeps
  copying it on a schedule so the Kubernetes side stays in step. It is a separate
  open-source project, not part of this one. From here on this document says ESO.

---

## 1. Who talks to what

The whole arrangement is three parties, and **no party talks to more than two**:

```
        sopuli-dba                     ESO                   your application
            |                           |                            |
            | writes the password       | reads the password         | reads a
            | to the vault              | from the vault             | Kubernetes
            v                           v                            | Secret
      +-----------------+         +-----------------+                v
      |     Vault       | ------> |   Kubernetes    | ------> +----------------+
      |  (the master)   |         |     Secret      |         |  the pod, with |
      +-----------------+         +-----------------+         |  DB_PASSWORD   |
            ^                                                 +----------------+
            |                                                          |
            | sets the same password                                   | connects
            | on the database                                          |
            v                                                          v
      +-----------------+                                     +----------------+
      |     Oracle      | <---------------------------------- |    a login     |
      +-----------------+                                     +----------------+
```

| Party | Talks to | Never talks to |
|---|---|---|
| **sopuli-dba** | the vault, and the Oracle database | Kubernetes. It has no client for it, no credential for it, and no code that mentions it |
| **ESO** | the vault, and the Kubernetes API | any database. It has no idea a database exists |
| **your application** | the Kubernetes Secret, and the database | the vault. It never authenticates to the vault at all |

**Nothing talks to both Kubernetes and the database.** That is the property that
makes this arrangement worth setting up, rather than an accident of how the tools
happen to be built:

- The credential that lets sopuli change passwords in Oracle never leaves the
  machine or job that runs sopuli. It is not in your cluster.
- The credential that lets ESO read your vault is scoped to reading one path. It
  cannot change a database password, because it has no database access at all.
- Your application never holds a vault credential. It reads a file or an
  environment variable, exactly as it would if somebody had typed the password in
  by hand.

The vault is the only thing both sides touch, and it touches them in opposite
directions: sopuli writes, ESO reads.

**Order matters, and it is already handled.** sopuli only promotes a password to
`current` after the database has accepted it (see
[rotate-and-sync.md](rotate-and-sync.md) section 3). ESO reads `current`. So ESO
can never copy a password the database has not already been given — which is the
failure this whole ordering exists to prevent.

---

## 2. What sopuli writes, exactly

ESO has to be told which field to read, so you need to know the shape of the
document sopuli writes. This is a real document, read back from the vault after
the rotation in [rotate-and-sync.md](rotate-and-sync.md). Three values are edited:
the two passwords, replaced by a description of what is there, and the operator
identity in `rotated_by`, replaced with a fictional one.

```json
{
  "DB_CREDENTIALS": {
    "acme_app_user": "<the password applications should use>"
  },
  "pending":  {},
  "previous": {
    "acme_app_user": "<the password before the last rotation>"
  },
  "origin":     {},
  "policy":     { "acme_app_user": "app-standard" },
  "rotated_at": { "acme_app_user": "2026-09-07T13:57:48.053157Z" },
  "rotated_by": { "acme_app_user": "dba@workstation" },
  "targets":    { "acme_app_user": ["free-pdb"] }
}
```

The document came from this line in the config file:

```yaml
secret_template: "vault-dev:acme/{env}/{application}#DB_CREDENTIALS/{account}"
```

which for this account resolved to the vault path `acme/dev/acme`, field
`DB_CREDENTIALS`, key `acme_app_user`.

Three rules govern that shape, and each one matters for writing the ESO manifest:

- **`DB_CREDENTIALS` holds the password applications should use.** It is the
  field your `secret_template` names, and it is the *only* field ESO should ever
  read. `pending` is a candidate that no database has confirmed yet. `previous`
  is the old one, kept so a rollback has somewhere to go.
- **Every top-level key mirrors the shape of that field.** Here `DB_CREDENTIALS`
  is a map keyed by account, so `pending`, `previous` and the stamps are maps
  keyed the same way. Where an application has one account per document, they are
  all plain strings instead. Either way `DB_CREDENTIALS` resolves to a password
  string, which is what makes the ESO side simple.
- **The value ESO reads is a string, not an object.** This is deliberate. The
  alternative shape — one object per account, holding its own current, pending
  and previous — would have made every consumer read a whole document and dig
  through it.

`origin` is empty here because nothing is staged. When something is, it says
whether the staged password was drawn by the tool or supplied by an external
system. ESO has no use for it.

---

## 3. Tell ESO how to reach the vault

This is the standard ESO setup and there is nothing sopuli-specific in it. It is
here so the document is followable rather than a fragment.

A `SecretStore` tells ESO where a vault is and how to authenticate to it. This
one uses Kubernetes authentication, where the vault trusts the cluster's own
identity for a named service account, so there is no vault token to store
anywhere:

```yaml
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: vault-dev
  namespace: acme
spec:
  provider:
    vault:
      server: "https://vault.example.com:8200"
      # The KV mount and the path prefix, matching `mount:` in the sopuli
      # config. `version: v2` is the KV store that keeps history.
      path: "kv"
      version: v2
      auth:
        # ESO presents the service account's token; the vault checks it with
        # the cluster and issues a short-lived vault token in return. Nothing
        # long-lived is stored in Kubernetes.
        kubernetes:
          mountPath: "kubernetes"
          role: "acme-reader"
          serviceAccountRef:
            name: "acme-secret-reader"
```

**Scope the vault policy behind that role to reading, and to this path.** The
role should not be able to write anything. sopuli writes; ESO reads. A role that
can do both removes the property section 1 is about:

```hcl
# The vault policy attached to the `acme-reader` role.
# Read the data, and its metadata. Nothing else, nowhere else.
path "kv/data/acme/dev/acme" {
  capabilities = ["read"]
}
path "kv/metadata/acme/dev/acme" {
  capabilities = ["read"]
}
```

---

## 4. The ExternalSecret

An `ExternalSecret` says: read this field from that store, put it in a Kubernetes
Secret with this name, and keep doing it.

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: acme-db-credentials
  namespace: acme
spec:
  # How often ESO re-reads the vault. One hour is a reasonable default; the
  # trade-off is in section 5.
  refreshInterval: "1h"

  secretStoreRef:
    name: vault-dev
    kind: SecretStore

  target:
    # The Kubernetes Secret ESO creates and maintains. Your application mounts
    # this, and never sees the vault.
    name: acme-db-credentials
    creationPolicy: Owner

  data:
    - secretKey: DB_PASSWORD          # the key inside the Kubernetes Secret
      remoteRef:
        # The vault path, without the `kv/` mount -- ESO adds that from the
        # SecretStore's `path:`.
        key: acme/dev/acme
        # The field inside the document. This is `DB_CREDENTIALS/<account>`,
        # written as a JSON pointer -- `property` walks into the nested map.
        # It matches the `#DB_CREDENTIALS/{account}` half of the
        # `secret_template` in the sopuli config.
        property: "DB_CREDENTIALS.acme_app_user"
```

The one line to get right is `property`. Everything else is ordinary ESO.

**There is no username to read.** The document has no `username` field in this
layout, because the account name *is* the map key — a second copy is a thing that
can disagree with itself. Put the username in your application's ordinary
configuration, where it is not a secret, or add it to the Secret with ESO's
`template:` block. Do not try to read it from the vault.

**Never point `property` at `pending`.** That is a candidate password no database
has accepted yet. Reading it would break every application in the namespace until
the next `creds apply`, and it would look like sopuli's fault.

---

## 5. What happens on a rotation, minute by minute

Assume `refreshInterval: 1h`, a rollover window configured on the account, and
that the sequence in [rotate-and-sync.md](rotate-and-sync.md) is what runs.

| | What happens | What is working |
|---|---|---|
| **T+0** | `creds generate` writes `pending` in the vault | everything. `current` is untouched, so ESO's next refresh sees nothing new |
| **T+0** | `creds apply` sets the new password on Oracle, logs in to confirm it, and promotes `pending` to `current` | everything. The old password still works, because the rollover window is open |
| **T+0 to T+1h** | ESO's refresh interval elapses. Pods still hold the old password | everything, because of the rollover window |
| **T+1h** | ESO reads `current`, updates the Kubernetes Secret. Your application picks it up — immediately if it mounts the Secret as a file and re-reads it, or at its next restart if it reads an environment variable at startup | everything |
| **when you say so** | `creds finish-rollover` closes the window. The old password stops working | everything, if the step above has actually happened |

**The last row is the one that needs a human.** `creds finish-rollover` is not
automatic, and it should not be: only you know whether every consumer has
actually collected the new password. Run `kubectl get secret` and check the
version, or check that the pods have restarted, and then close the window.

Three practical consequences of that table:

**Your rollover window must be longer than your refresh interval.** If
`PASSWORD_ROLLOVER_TIME` is one hour and `refreshInterval` is one hour, the race
is too close. Make the window comfortably longer, or shorten the refresh.

**An environment variable is not updated in a running pod.** ESO updates the
Kubernetes Secret, but a pod that read it into an environment variable at startup
keeps the old value until it restarts. Mounting the Secret as a file and
re-reading it is what makes the update actually take effect without a restart;
otherwise you still need one, and the rollover window is what buys you the time
to do it calmly. ESO can be configured to restart deployments for you — that is
its documentation's business, not this document's.

**Without a rollover window, this becomes an outage.** If the account's profile
grants no window, the old password stops working the instant `apply` runs, and
every pod is broken until ESO refreshes and the pods pick it up. With a
`refreshInterval` of one hour that is up to an hour of failed logins. Either
configure a rollover window, or shorten `refreshInterval` drastically and accept
a short outage on every rotation.

---

## 6. Checking it worked

From the database side, the tool's own answer:

```bash
sopuli --config sopuli.yaml creds check --application acme
```
```
ACCOUNT        TARGET    STATE    DETAIL
acme_app_user  free-pdb  IN_SYNC  vault v2 verified by login
```

That says the vault and the database agree. It says nothing about Kubernetes,
because sopuli cannot see Kubernetes. For that half, ask ESO:

```bash
# Has ESO managed to read the vault at all?
kubectl -n acme get externalsecret acme-db-credentials

# Does the Kubernetes Secret hold what you expect? This prints the password,
# so do not do it into a shared terminal or a log.
kubectl -n acme get secret acme-db-credentials \
  -o jsonpath='{.data.DB_PASSWORD}' | base64 -d
```

If those two agree and the database says `IN_SYNC`, the loop is closed and you
can run `creds finish-rollover`.

**One column will mislead you.** `kubectl get secretstore` prints a
`CAPABILITIES` column, and for this store it says `ReadWrite`:

```
NAME        AGE     STATUS   CAPABILITIES   READY
vault-dev   6m51s   Valid    ReadWrite      True
```

That describes what ESO's vault support *can* do in general — it can write to a
vault, given a role that allows it. It says nothing about what your role is
allowed to do, and it does not change when you tighten the policy. To find out
whether the role really is read-only, ask the vault: log in with the service
account and try a write, which is what
[`../../test/k8s_eso_probe.py`](../../test/k8s_eso_probe.py) does.

---

## 7. Has any of this been run, or is it just written down?

It has been run. This section says exactly what was run and what was not, so
you can tell the measured parts from the reasoned ones.

[`test/k8s_eso_probe.py`](../../test/k8s_eso_probe.py) in this repository
stands the whole arrangement up on a throwaway cluster and checks it.
**It does not keep a copy of the manifests above — it reads them out of this
file** and applies those. A copy would drift away from the document over time,
and a check that passes against its own stale copy is worse than no check at
all.

```bash
python test/k8s_eso_probe.py
```

Run on 2026-09-07 against Kubernetes 1.36.1 (the cluster built into Docker
Desktop), ESO 2.10.0, and sopuli 0.58.0. The last part of what it printed —
the setup before this is Vault, ESO and the vault role being created:

```
=== sopuli writes the credential to the vault =========================
  $ ... vault kv metadata delete -mount=kv acme/dev/acme
  $ sopuli.exe --config ...\sopuli.yaml --vault-token-file ...\vault-token.txt creds generate --promote --offline --application acme

=== what sopuli actually wrote ========================================
  $ ... vault kv get -mount=kv -format=json acme/dev/acme
  top-level keys written:    ['DB_CREDENTIALS', 'origin', 'pending', 'policy', 'rotated_at', 'rotated_by']
  top-level keys documented: ['DB_CREDENTIALS', 'origin', 'pending', 'policy', 'previous', 'rotated_at', 'rotated_by', 'targets']
  absent as expected: previous -- no `current` existed to move (first adoption)
  absent as expected: targets -- no database confirmed anything (`--promote` asks none)

=== applying the document's own manifests =============================
  $ kubectl -n sopuli-test delete externalsecret acme-db-credentials --ignore-not-found
  $ kubectl apply -f -
  $ kubectl apply -f -

=== does ESO produce the Kubernetes Secret? ===========================
  $ kubectl -n sopuli-test wait --for=condition=Ready externalsecret/acme-db-credentials --timeout=120s
externalsecret.external-secrets.io/acme-db-credentials condition met
  $ kubectl -n sopuli-test get secret acme-db-credentials -o jsonpath={.data.DB_PASSWORD}
  sha256 in the vault:             292043d7fde9
  sha256 in the Kubernetes Secret: 292043d7fde9

=== is ESO's vault role really read-only? =============================
  $ kubectl -n sopuli-test create token acme-secret-reader --duration=10m
  $ kubectl -n sopuli-test exec -i deploy/vault -- sh -c <script>
  logged in as acme-secret-reader through the `acme-reader` role: ['READ_OK', 'WRITE_DENIED']

=== result ============================================================
  PASS: the manifests in docs/scenarios/kubernetes-eso.md work as written.
  PASS: `property: DB_CREDENTIALS.acme_app_user` resolves against a document
        sopuli wrote, and the value reaches a Kubernetes Secret unchanged.
  PASS: the vault policy in section 3 permits the read and refuses a write.
```

The password itself is never printed. The two lines above are the first twelve
characters of a SHA-256 of each side's value — a fingerprint, which is enough
to see that the two agree and no use to anyone reading over your shoulder.

**Two lines are edited before the manifests are applied**, and the script says
so each time it does it. Both are placeholders that no example could avoid
having:

| In this document | What the test uses instead |
|---|---|
| `namespace: acme` | `namespace: sopuli-test`, the throwaway namespace |
| `server: "https://vault.example.com:8200"` | the address of the throwaway Vault inside the cluster |

Everything else is applied exactly as it is written above: the `property`
pointer, the whole Kubernetes authentication block, the vault policy, the KV
mount name and the path.

### What that establishes

- **The `SecretStore` in section 3 is accepted by ESO and works.** ESO logged
  in to the vault as the `acme-secret-reader` service account through the
  `acme-reader` role, with no vault token stored anywhere in the cluster.
- **The vault policy in section 3 is the right shape.** It permits the read ESO
  needs, and a write with the same credentials is refused. That is section 1's
  claim about direction — sopuli writes, ESO reads — checked rather than
  asserted.
- **The `ExternalSecret` in section 4 works, `property` included.** The
  `DB_CREDENTIALS.acme_app_user` pointer resolved against a document sopuli
  itself wrote, and the password arrived in the Kubernetes Secret unchanged.
- **The document shape in section 2 is what sopuli writes**, with two keys
  missing for a reason worth knowing: the test has no database, so it writes
  the password with `creds generate --promote`. `previous` holds whatever
  `current` held before, and there was no earlier `current`. `targets` records
  which databases *confirmed* the password, and only `creds apply` can write
  that, because only `apply` asks a database anything. A completed rotation —
  which is what section 2 was captured from — has both.

### What it does not establish

- **Anything about TLS.** The test's vault is plain HTTP inside the cluster.
  Section 3's `https://` address is what you should use and is not what was
  tested.
- **Anything about a real vault.** The test uses Vault in development mode:
  in memory, unsealed, with a known root token. The authentication *path* is
  the real one; the server is not a real deployment of one.
- **That an application picks the Secret up.** Nothing consumed the Kubernetes
  Secret. That half is your deployment's business and is unchanged by any of
  this.
- **The timings in section 5.** Nobody waited an hour for a refresh, and there
  was no Oracle and therefore no rollover window. Section 5 is reasoning about
  how the pieces compose, not a measurement.

---

## What is not built yet

Said plainly rather than left for you to discover:

- **sopuli has no Kubernetes integration and none is planned for this use case.**
  Everything above works because both tools use the vault, not because they know
  about each other. If you want the pods restarted automatically, that is ESO's
  feature, not this project's.
- **Only HashiCorp Vault is supported today.** ESO can read many stores; sopuli
  can currently write to one. `oci`, `file` and `keyring` are accepted in a config
  file and report that this build has no module for them.
- **The manifests are checked against one ESO version, and that version will
  move.** Section 7 has the details of what was run. It was ESO 2.10.0; ESO's
  own API has changed between major versions before, and `apiVersion:
  external-secrets.io/v1` is the line most likely to need changing. If your
  cluster runs a different version, read its documentation before assuming the
  YAML above is current.

---

## Next

- [rotate-and-sync.md](rotate-and-sync.md) — the rotation itself, in detail.
- [../security-model.md](../security-model.md) — what the tool can and cannot do.
- [../design/01-configuration.md](../design/01-configuration.md) §7 — the full
  SecretRef syntax, if your layout is not the one above.
- [../use-cases/uc-01-app-credential-sync.md](../use-cases/uc-01-app-credential-sync.md)
  §3 — the document shape as a specification rather than an example.

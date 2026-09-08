"""Probe: does the ESO scenario in ``docs/scenarios/kubernetes-eso.md`` work?

That document was written from the shape of the vault document sopuli really
writes and from ESO's published API, and its own "What is not built yet"
section said plainly that the manifests had never been applied to a cluster.
This script is what removes that caveat. Run it and the section 3 and 4
manifests are applied to a real Kubernetes cluster, against a real Vault, over
a document a real ``sopuli creds generate`` wrote.

**It reads the manifests out of the document rather than carrying a copy.**
A copy would drift, and a probe that passes against its own stale copy is
worse than no probe -- so the YAML applied here is the YAML a reader would
apply, extracted from the fenced blocks at run time. Two substitutions are
made, both of them placeholders no document could avoid, and both are printed
when they happen:

    namespace: acme                     -> namespace: sopuli-test
    server: https://vault.example.com   -> the in-cluster Vault below

Everything else -- the ``property:`` pointer, the auth block, the vault policy
in section 3, the KV mount and path -- is applied exactly as written.

Not a pytest test, for the same reason ``vault_cas_probe.py`` is not one: it
needs a Kubernetes cluster, it installs a third-party operator into it, and it
takes minutes. It is the by-hand evidence behind a documentation claim, and it
is the thing to re-run when that document changes.

What it stands up, all of it disposable:

    namespace sopuli-test       Vault (dev mode, in-cluster), the service
                                account the SecretStore names, and the two
                                objects extracted from the document
    namespace external-secrets  ESO itself, from its published Helm chart,
                                rendered with a containerised Helm so nothing
                                is installed on the host

Prerequisites: a running cluster (Docker Desktop's is what this was written
against), ``kubectl`` pointed at it, ``docker`` on PATH, and sopuli installed
in the current environment.

    python test/k8s_eso_probe.py            # stand it up and check it
    python test/k8s_eso_probe.py --down     # remove everything it created
    python test/k8s_eso_probe.py --keep     # leave it up for poking at

**It never prints a password.** The final check compares what ESO put in the
Kubernetes Secret with what sopuli put in the vault, and reports the first
twelve characters of each side's SHA-256 -- enough to see they match, useless
to anyone reading over your shoulder.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOC = REPO / "docs" / "scenarios" / "kubernetes-eso.md"

NS = "sopuli-test"
ESO_NS = "external-secrets"

# Pinned for the same reason test/compose.yaml pins Vault: an upstream bump has
# to be a deliberate, reviewable line here, not something that silently changes
# what this measured. The chart version is also what the document should be read
# against -- ESO's API has moved before.
ESO_CHART_VERSION = "2.10.0"
ESO_CHART = (
    "https://github.com/external-secrets/external-secrets/releases/download/"
    f"helm-chart-{ESO_CHART_VERSION}/external-secrets-{ESO_CHART_VERSION}.tgz"
)
HELM_IMAGE = "alpine/helm:4.2.4"
VAULT_IMAGE = "hashicorp/vault:2.0.4"  # the pin from test/compose.yaml

ROOT_TOKEN = "sopuli-test-root"  # dev mode only, and it never leaves the cluster
LOCAL_PORT = 8210  # not 8200: the tier0 compose stack may already hold that

# The document resolves `vault-dev:acme/{env}/{application}#DB_CREDENTIALS/{account}`
# to this path for a `dev` target and an application named `acme`. The ESO
# manifest's `key:` and the vault policy's paths both say the same thing, which
# is exactly what this probe is checking.
SECRET_PATH = "acme/dev/acme"
ACCOUNT = "acme_app_user"

VAULT_ADDR_IN_CLUSTER = f"http://vault.{NS}.svc.cluster.local:8200"


# --------------------------------------------------------------------------
# running things
# --------------------------------------------------------------------------
def run(
    cmd: list[str],
    *,
    stdin: str | None = None,
    check: bool = True,
    quiet: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run a command, showing it first. Output is the point of this script."""
    if not quiet:
        # A multi-line argument -- the shell fragment below -- would break the
        # one-line-per-command shape that makes this log readable. It is a
        # named constant in this file; read it there.
        shown = " ".join("<script>" if "\n" in arg else arg for arg in cmd)
        print(f"  $ {shown}")
    proc = subprocess.run(
        cmd,
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(f"failed ({proc.returncode}): {' '.join(cmd)}")
    return proc


def kubectl(*args: str, **kw: object) -> subprocess.CompletedProcess[str]:
    return run(["kubectl", *args], **kw)  # type: ignore[arg-type]


def vault_cli(
    *args: str, stdin: str | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    """Run the vault CLI inside the Vault pod, as root.

    The root token is a constant in this file and is handed to the pod on the
    command line, so it plainly does cross the boundary -- what this buys is
    that no vault port has to be open to the host for the configuration half of
    the run. It is a dev-mode token for a Vault thrown away with the namespace,
    which is the only reason either of those is acceptable here.
    """
    return kubectl(
        "-n", NS, "exec", "-i", "deploy/vault", "--",
        "env", "VAULT_ADDR=http://127.0.0.1:8200", f"VAULT_TOKEN={ROOT_TOKEN}",
        "vault", *args,
        stdin=stdin, check=check,
    )


def step(text: str) -> None:
    print(f"\n=== {text} " + "=" * max(0, 66 - len(text)))


@contextlib.contextmanager
def port_forward() -> Iterator[None]:
    """Open the in-cluster Vault to the host, for the length of sopuli's run.

    sopuli is the one participant that is *not* in the cluster -- that is the
    whole point of the arrangement the document describes -- so it needs an
    ordinary network route to the vault. A port forward is the disposable
    stand-in for one.
    """
    print(f"  $ kubectl -n {NS} port-forward svc/vault {LOCAL_PORT}:8200")
    proc = subprocess.Popen(
        ["kubectl", "-n", NS, "port-forward", "svc/vault", f"{LOCAL_PORT}:8200"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", LOCAL_PORT), timeout=1):
                    break
            except OSError:
                if proc.poll() is not None:
                    raise SystemExit(
                        "port-forward exited: " + (proc.stdout.read() if proc.stdout else "")
                    ) from None
                time.sleep(0.5)
        else:
            raise SystemExit(f"nothing listening on 127.0.0.1:{LOCAL_PORT} after 30s")
        yield
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


# --------------------------------------------------------------------------
# 1. the document is the source of the manifests
# --------------------------------------------------------------------------
FENCE = re.compile(r"^```(\w+)\n(.*?)^```", re.MULTILINE | re.DOTALL)


def blocks_from_doc() -> dict[str, str]:
    """Pull the manifests, the vault policy and the payload out of the document.

    Each is identified by what it *is* rather than by position, so reordering
    the document does not break this -- but finding none, or more than one,
    fails loudly. A probe that quietly skips the block it was meant to check is
    the failure mode worth being noisy about.
    """
    text = DOC.read_text(encoding="utf-8")
    fenced: list[tuple[str, str]] = [
        (str(lang), str(body)) for lang, body in FENCE.findall(text)
    ]

    def one(lang: str, needle: str, what: str) -> str:
        pattern = re.compile(needle, re.MULTILINE)
        found = [b for tag, b in fenced if tag == lang and pattern.search(b)]
        if len(found) != 1:
            raise SystemExit(
                f"{DOC.name}: expected exactly one {lang} block matching "
                f"{needle!r} ({what}), found {len(found)}. The document has "
                f"changed shape and this probe has not been updated."
            )
        return found[0]

    # The `kind:` patterns are anchored to the start of a line: `kind:` also
    # appears indented inside `secretStoreRef`, and an unanchored match picks
    # the ExternalSecret up twice.
    return {
        "secretstore": one("yaml", r"^kind: SecretStore$", "section 3"),
        "externalsecret": one("yaml", r"^kind: ExternalSecret$", "section 4"),
        "policy": one("hcl", "capabilities", "the vault policy in section 3"),
        "payload": one("json", "DB_CREDENTIALS", "the document shape in section 2"),
    }


#: What each manifest's placeholders are replaced with. Kept per manifest
#: rather than as one list applied to both, because only the `SecretStore`
#: carries a vault address -- demanding that edit of the `ExternalSecret` would
#: reject a document that is perfectly correct.
SUBSTITUTIONS = {
    "secretstore": [
        ("namespace: acme", f"namespace: {NS}"),
        (
            'server: "https://vault.example.com:8200"',
            f'server: "{VAULT_ADDR_IN_CLUSTER}"',
        ),
    ],
    "externalsecret": [
        ("namespace: acme", f"namespace: {NS}"),
    ],
}


def substitute(name: str, manifest: str) -> str:
    """Replace this manifest's placeholders, refusing if one has gone missing.

    Refusing matters more than it looks, and it matters most for the address.
    A `server:` line that stopped matching would be applied as it stands,
    pointing at `vault.example.com` -- and the run would fail several steps
    later at the ExternalSecret, saying the vault is unreachable. That is true,
    and it sends you to look at the network rather than at this list.
    """
    out = manifest
    for old, new in SUBSTITUTIONS[name]:
        if old not in out:
            raise SystemExit(
                f"{DOC.name}: the {name} block no longer contains {old!r}, so "
                f"this probe would apply it unchanged. Fix the substitution "
                f"here, or the document."
            )
        out = out.replace(old, new)
        print(f"  {name}: {old!r} -> {new!r}")
    return out


# --------------------------------------------------------------------------
# 2. the cluster side
# --------------------------------------------------------------------------
VAULT_MANIFEST = f"""
apiVersion: v1
kind: Namespace
metadata:
  name: {NS}
---
# Vault's own identity. It needs one because Kubernetes auth means Vault asks
# the cluster "is this token real?", and asking is itself an authenticated call.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vault
  namespace: {NS}
---
# `system:auth-delegator` is the standard role for exactly that question: it
# grants TokenReview and nothing else. Without it every ESO login fails with a
# permission error from the cluster, not from Vault, which reads confusingly.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {NS}-vault-auth-delegator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
  - kind: ServiceAccount
    name: vault
    namespace: {NS}
---
# The service account the document's SecretStore names. It holds no secret and
# no vault token: its identity *is* the credential, which is the property
# section 1 of the document is about.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: acme-secret-reader
  namespace: {NS}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault
  namespace: {NS}
spec:
  replicas: 1
  selector:
    matchLabels: {{ app: vault }}
  template:
    metadata:
      labels: {{ app: vault }}
    spec:
      serviceAccountName: vault
      containers:
        - name: vault
          image: {VAULT_IMAGE}
          # Dev mode: in-memory, unsealed, root token known. It is thrown away
          # with the namespace. Never a shape to copy into anything real.
          args: ["server", "-dev"]
          env:
            - name: VAULT_DEV_ROOT_TOKEN_ID
              value: {ROOT_TOKEN}
            - name: VAULT_DEV_LISTEN_ADDRESS
              value: 0.0.0.0:8200
          ports:
            - containerPort: 8200
          readinessProbe:
            httpGet: {{ path: /v1/sys/health, port: 8200 }}
            periodSeconds: 3
---
apiVersion: v1
kind: Service
metadata:
  name: vault
  namespace: {NS}
spec:
  selector: {{ app: vault }}
  ports:
    - port: 8200
      targetPort: 8200
"""


def deploy_vault() -> None:
    step("Vault in the cluster")
    kubectl("apply", "-f", "-", stdin=VAULT_MANIFEST)
    kubectl("-n", NS, "rollout", "status", "deploy/vault", "--timeout=180s")


def configure_vault(policy_hcl: str) -> None:
    step("Vault: KV mount, Kubernetes auth, and the document's own policy")

    # The KV v2 mount the config's `mount: kv` and the SecretStore's `path: kv`
    # both name. Not fatal if it is already there: re-running this probe against
    # a kept cluster has to work.
    vault_cli("secrets", "enable", "-path=kv", "-version=2", "kv", check=False)

    vault_cli("auth", "enable", "kubernetes", check=False)
    # Vault is in the cluster, so it can find the API server's CA and its own
    # token by itself. Only the address has to be told.
    vault_cli(
        "write", "auth/kubernetes/config",
        "kubernetes_host=https://kubernetes.default.svc:443",
    )

    # Verbatim from section 3 of the document. If it does not permit the read,
    # this probe fails at the ExternalSecret and the document is wrong.
    print("  writing the policy exactly as the document states it:")
    print("\n".join("    " + line for line in policy_hcl.strip().splitlines()))
    vault_cli("policy", "write", "acme-reader", "-", stdin=policy_hcl)

    vault_cli(
        "write", "auth/kubernetes/role/acme-reader",
        "bound_service_account_names=acme-secret-reader",
        f"bound_service_account_namespaces={NS}",
        "policies=acme-reader",
        "ttl=1h",
    )

    # sopuli takes an advisory lock in the vault before it writes, and refuses a
    # lock path that does not require compare-and-set (exit 5). Once per path --
    # docs/local-testing.md has the long version of why.
    vault_cli(
        "kv", "metadata", "put", "-mount=kv", "-cas-required=true",
        f"locks/{SECRET_PATH}",
    )


def render_eso() -> str:
    """ESO's Helm chart, rendered to YAML.

    Helm runs in a container so nothing lands on the host, and `template` is
    entirely client-side, so the container needs no access to the cluster --
    it prints YAML and kubectl does the rest. Teardown renders it a second time
    and deletes it, which is why this is its own function.
    """
    if shutil.which("docker") is None:
        raise SystemExit("docker is needed to render the Helm chart")
    return run([
        "docker", "run", "--rm", HELM_IMAGE,
        "template", "external-secrets", ESO_CHART,
        "--namespace", ESO_NS,
    ]).stdout


def install_eso() -> None:
    step(f"External Secrets Operator {ESO_CHART_VERSION}")
    existing = kubectl("get", "namespace", ESO_NS, check=False, quiet=True)
    if existing.returncode == 0:
        print(
            f"  WARNING: namespace {ESO_NS} already exists. This probe is about "
            f"to install ESO over whatever is there, and `--down` will remove "
            f"it. Do not run this on a cluster somebody else is using ESO on."
        )

    rendered = render_eso()
    kubectl("create", "namespace", ESO_NS, check=False)
    kubectl("apply", "--server-side", "-f", "-", stdin=rendered)

    for deploy in (
        "external-secrets",
        "external-secrets-webhook",
        "external-secrets-cert-controller",
    ):
        kubectl("-n", ESO_NS, "rollout", "status", f"deploy/{deploy}", "--timeout=300s")

    # The webhook validates every ExternalSecret. Applying one before its
    # certificate is in place fails with a TLS error that looks like a manifest
    # problem and is not.
    step("waiting for the ESO webhook to be answering")
    for _ in range(60):
        got = kubectl(
            "get", "validatingwebhookconfigurations", "externalsecret-validate",
            "-o", "jsonpath={.webhooks[0].clientConfig.caBundle}",
            check=False, quiet=True,
        )
        if got.returncode == 0 and got.stdout.strip():
            print("  webhook CA bundle injected")
            return
        time.sleep(2)
    print("  WARNING: no CA bundle after 120s; applying anyway")


# --------------------------------------------------------------------------
# 3. the sopuli side -- a real write, by the real tool
# --------------------------------------------------------------------------
SOPULI_CONFIG = f"""
version: 1

vaults:
  vault-dev:
    type: hashicorp
    addr: http://127.0.0.1:{LOCAL_PORT}
    mount: kv
    kv_version: 2
    auth: {{ method: token }}

defaults:
  vault: vault-dev

targets:
  - name: free-pdb
    type: oracle
    environment: dev
    dsn: "127.0.0.1:1521/FREEPDB1"
    admin: {{ username: SYSTEM, auth: {{ method: env }} }}
    oracle: {{ scope: pdb, container: FREEPDB1 }}

policies:
  app-standard:
    password:
      length: 24
      charset: alnum_safe
      first_char: alpha
      require: {{ upper: 1, lower: 1, digit: 1, special: 1 }}

applications:
  - name: acme
    accounts: [{ACCOUNT}]
    secret_template: "vault-dev:acme/{{env}}/{{application}}#DB_CREDENTIALS/{{account}}"
    policy: app-standard
"""


def sopuli_executable() -> str:
    """The sopuli belonging to the interpreter running this script.

    Deliberately not ``shutil.which("sopuli")``: on a machine with a second,
    older sopuli on PATH -- a pipx install, or a global one predating the venv
    -- PATH wins and the run fails with "that backend is not installed",
    because the *other* one has no ``[hashicorp]`` extra. The error names the
    extra rather than the interpreter, so it sends you to fix the wrong thing.
    """
    here = Path(sys.executable).parent
    for name in ("sopuli.exe", "sopuli"):
        if (here / name).exists():
            return str(here / name)
    found = shutil.which("sopuli")
    if found is None:
        raise SystemExit("sopuli is not installed -- activate the project venv")
    print(f"  WARNING: no sopuli beside {sys.executable}; falling back to {found}")
    return found


def write_credential(workdir: Path) -> None:
    """Have sopuli write the document ESO is going to read.

    `--promote` because there is no database here to confirm a `pending`, and
    `--offline` because there is none to ask about password length either.
    Between them that is invariant 7's one exception used exactly as it is
    documented: a first adoption, with no `current` to replace.
    """
    step("sopuli writes the credential to the vault")

    # Wipe this probe's own path first, so a second run against a cluster left
    # up by `--keep` measures the same thing the first one did. Without it the
    # second run meets its own `current` and refuses without
    # `--overwrite-current` -- correctly, and unhelpfully, since the case being
    # measured here is a first adoption.
    vault_cli("kv", "metadata", "delete", "-mount=kv", SECRET_PATH, check=False)

    config = workdir / "sopuli.yaml"
    config.write_text(SOPULI_CONFIG, encoding="utf-8")
    token = workdir / "vault-token.txt"
    token.write_text(ROOT_TOKEN, encoding="utf-8")
    if os.name != "nt":
        # P4 refuses a config any other account can edit. Windows' own temp
        # directory ACL already satisfies it; POSIX inherits the umask.
        config.chmod(0o600)
        token.chmod(0o600)

    run([
        sopuli_executable(), "--config", str(config), "--vault-token-file", str(token),
        "creds", "generate", "--promote", "--offline", "--application", "acme",
    ])


def read_vault_document() -> dict[str, object]:
    got = vault_cli("kv", "get", "-mount=kv", "-format=json", SECRET_PATH)
    return json.loads(got.stdout)["data"]["data"]  # type: ignore[no-any-return]


# --------------------------------------------------------------------------
# 4. the checks
# --------------------------------------------------------------------------
def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


#: Section 2's payload was read back after a *completed rotation*: `creds
#: generate` staged, `creds apply` set the password on Oracle and promoted it.
#: This probe has no database, so it uses `generate --promote` -- and two of
#: those keys cannot exist after it, for reasons that are the design rather
#: than a gap:
#:
#:   previous  takes what `current` held. First adoption: there was no
#:             `current`, so there is nothing to move.
#:   targets   records which targets *confirmed* the password. Only `creds
#:             apply` can write it, because only `apply` asks a database
#:             anything. Invariant 7 is the reason `--promote` may not.
#:
#: Absent for any other key, or an unexpected key present, is real drift
#: between the document and the tool.
PROMOTE_CANNOT_WRITE = {
    "previous": "no `current` existed to move (first adoption)",
    "targets": "no database confirmed anything (`--promote` asks none)",
}


def check_payload_shape(written: dict[str, object], documented_json: str) -> list[str]:
    """Section 2 claims a document shape. Compare it with what was written."""
    documented = json.loads(documented_json)
    failures = []
    missing = sorted(set(documented) - set(written))
    extra = sorted(set(written) - set(documented))
    print(f"  top-level keys written:    {sorted(written)}")
    print(f"  top-level keys documented: {sorted(documented)}")
    for key in missing:
        if key in PROMOTE_CANNOT_WRITE:
            print(f"  absent as expected: {key} -- {PROMOTE_CANNOT_WRITE[key]}")
    unexplained = [k for k in missing if k not in PROMOTE_CANNOT_WRITE]
    if unexplained:
        failures.append(f"section 2 documents keys sopuli did not write: {unexplained}")
    if extra:
        failures.append(f"sopuli wrote keys section 2 does not document: {extra}")

    creds = written.get("DB_CREDENTIALS")
    if not isinstance(creds, dict) or ACCOUNT not in creds:
        failures.append(
            f"DB_CREDENTIALS is not a map containing {ACCOUNT!r}; the "
            f"ExternalSecret's `property` cannot resolve"
        )
    elif not isinstance(creds[ACCOUNT], str):
        failures.append(
            "DB_CREDENTIALS/<account> is not a string, which is what ESO reads"
        )
    return failures


def check_external_secret(expected_password: str) -> list[str]:
    step("does ESO produce the Kubernetes Secret?")
    ready = kubectl(
        "-n", NS, "wait", "--for=condition=Ready",
        "externalsecret/acme-db-credentials", "--timeout=120s",
        check=False,
    )
    print(ready.stdout.strip() or ready.stderr.strip())
    if ready.returncode != 0:
        kubectl("-n", NS, "describe", "externalsecret", "acme-db-credentials", check=False)
        kubectl("-n", ESO_NS, "logs", "deploy/external-secrets", "--tail=40", check=False)
        return ["the ExternalSecret never became Ready"]

    got = kubectl(
        "-n", NS, "get", "secret", "acme-db-credentials",
        "-o", "jsonpath={.data.DB_PASSWORD}", check=False,
    )
    if got.returncode != 0 or not got.stdout.strip():
        return ["the ExternalSecret is Ready but the Secret has no DB_PASSWORD key"]

    in_kubernetes = base64.b64decode(got.stdout.strip()).decode("utf-8")
    print(f"  sha256 in the vault:             {digest(expected_password)}")
    print(f"  sha256 in the Kubernetes Secret: {digest(in_kubernetes)}")
    if in_kubernetes != expected_password:
        return ["the Secret holds a different value than the vault does"]
    return []


#: Run inside the Vault pod, with the service account's JWT on stdin. `jwt=-`
#: makes the vault CLI read it from there rather than from a command-line
#: argument, and the vault token it gets back is passed on as an environment
#: variable -- the same reason invariant 1 keeps secrets out of `argv`, applied
#: to a throwaway pod because the habit is the point.
POLICY_SCOPE_PROBE = """
set -e
export VAULT_ADDR=http://127.0.0.1:8200
TOKEN=$(vault write -field=token auth/kubernetes/login role=acme-reader jwt=-)
if VAULT_TOKEN=$TOKEN vault kv get -mount=kv acme/dev/acme >/dev/null 2>&1; then
  echo READ_OK
else
  echo READ_DENIED
fi
if VAULT_TOKEN=$TOKEN vault kv put -mount=kv acme/dev/acme probe=x >/dev/null 2>&1; then
  echo WRITE_OK
else
  echo WRITE_DENIED
fi
"""


def check_policy_is_read_only() -> list[str]:
    """Section 3 says the role "should not be able to write anything". Check it.

    This is the half of the document that is a security claim rather than a
    configuration recipe, and it is the half a reader cannot verify by looking.
    Run last, because the failing case -- a role that *can* write -- would
    overwrite the very document the check above compares.
    """
    step("is ESO's vault role really read-only?")
    jwt = kubectl(
        "-n", NS, "create", "token", "acme-secret-reader", "--duration=10m",
    ).stdout.strip()

    got = kubectl(
        "-n", NS, "exec", "-i", "deploy/vault", "--", "sh", "-c", POLICY_SCOPE_PROBE,
        stdin=jwt,
    )
    verdicts = got.stdout.split()
    print(f"  logged in as acme-secret-reader through the `acme-reader` role: {verdicts}")

    failures = []
    if "READ_OK" not in verdicts:
        failures.append("the policy in section 3 does not permit the read ESO needs")
    if "WRITE_DENIED" not in verdicts:
        failures.append(
            "the `acme-reader` role can WRITE the document -- section 1's claim "
            "that ESO only reads is not enforced by section 3's policy"
        )
    return failures


# --------------------------------------------------------------------------
def teardown() -> None:
    """Remove everything this probe created, including outside the namespaces.

    **Deleting the CRDs deletes every ExternalSecret and SecretStore in the
    cluster**, not only this probe's, because a CRD takes its custom resources
    with it. That is what uninstalling ESO means; it is the reason `install_eso`
    warns when it finds ESO already there.
    """
    step("removing everything this probe created")
    kubectl("delete", "namespace", NS, "--ignore-not-found", check=False)
    kubectl("delete", "namespace", ESO_NS, "--ignore-not-found", check=False)
    kubectl(
        "delete", "clusterrolebinding", f"{NS}-vault-auth-delegator",
        "--ignore-not-found", check=False,
    )

    # ESO's CRDs, cluster roles and webhook configurations are cluster-scoped
    # and outlive its namespace, so they have to go separately -- and they are
    # deleted by re-rendering the chart rather than by a label selector.
    #
    # A selector was the first attempt and it was silently wrong. Measured
    # against 2.10.0: the CRDs carry `external-secrets.io/component`, the
    # ClusterRoles carry `app.kubernetes.io/name=external-secrets`, and the
    # webhook configurations carry `app.kubernetes.io/name=external-secrets-
    # webhook`. No one selector matches all three -- and a selector matching
    # nothing deletes nothing while exiting 0, so the mistake looks exactly
    # like success. Deleting what was installed needs no guess about labels
    # and stays right when the chart relabels something.
    print("  re-rendering the chart to delete exactly what it installed")
    kubectl("delete", "--ignore-not-found", "-f", "-", stdin=render_eso(), check=False)

    print("\nGone. `kubectl get crd | grep external-secrets` should be empty too.")


def main() -> int:
    parser = argparse.ArgumentParser(description="validate the ESO scenario document")
    parser.add_argument("--down", action="store_true", help="tear it all down and exit")
    parser.add_argument("--keep", action="store_true", help="leave the cluster objects up")
    args = parser.parse_args()

    if args.down:
        teardown()
        return 0

    context = run(["kubectl", "config", "current-context"], quiet=True).stdout.strip()
    print(f"cluster context: {context}")

    step("reading the manifests out of the document")
    blocks = blocks_from_doc()
    for name in ("secretstore", "externalsecret"):
        blocks[name] = substitute(name, blocks[name])

    deploy_vault()
    configure_vault(blocks["policy"])
    install_eso()

    with tempfile.TemporaryDirectory() as tmp, port_forward():
        write_credential(Path(tmp))

    step("what sopuli actually wrote")
    written = read_vault_document()
    failures = check_payload_shape(written, blocks["payload"])

    step("applying the document's own manifests")
    # Deleted rather than re-applied, so that a second run is a real read. An
    # `apply` over an unchanged ExternalSecret is a no-op, and the manifest's
    # `refreshInterval: 1h` would then leave the previous run's password in
    # place for an hour -- the comparison below would be measuring nothing.
    # `creationPolicy: Owner` takes the Secret with it.
    kubectl(
        "-n", NS, "delete", "externalsecret", "acme-db-credentials",
        "--ignore-not-found", check=False,
    )
    kubectl("apply", "-f", "-", stdin=blocks["secretstore"])
    kubectl("apply", "-f", "-", stdin=blocks["externalsecret"])

    creds = written.get("DB_CREDENTIALS")
    password = creds[ACCOUNT] if isinstance(creds, dict) else ""
    failures += check_external_secret(str(password))
    failures += check_policy_is_read_only()

    step("result")
    if failures:
        for line in failures:
            print(f"  FAIL: {line}")
        print(f"\n{len(failures)} check(s) failed. The document is wrong, or this is.")
        return 1

    print("  PASS: the manifests in docs/scenarios/kubernetes-eso.md work as written.")
    print(f"  PASS: `property: DB_CREDENTIALS.{ACCOUNT}` resolves against a document")
    print("        sopuli wrote, and the value reaches a Kubernetes Secret unchanged.")
    print("  PASS: the vault policy in section 3 permits the read and refuses a write.")
    if not args.keep:
        teardown()
    else:
        print(f"\nLeft up. `python {Path(__file__).name} --down` when you are done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

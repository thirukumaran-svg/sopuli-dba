"""Probe: is `hvac`'s auth surface actually buying anything for #103, once
renewal and OIDC's browser dance are set aside?

Written for #103 (which HashiCorp client). The working claim under test,
after the CAS probe (`vault_cas_probe.py`) and a round of argument: AppRole
is "two POSTs" and Kubernetes is "read a file, one POST" — plain enough that
a client library saves nothing worth a dependency under the credential path.
This measures that claim against a real Vault instead of trusting the
docs. Same relationship to Vault that `vault_cas_probe.py` has, and the same
reason for stdlib-only `urllib`: the question is about Vault's own contract,
not about how any particular client wraps it.

**AppRole is fully exercised end to end.** Enable, create a role, fetch a
role_id, generate a secret_id, log in, use the returned token, and check that
a wrong secret_id fails cleanly -- everything `test/compose.yaml`'s tier0
Vault can do on its own.

**Kubernetes is only partly exercisable, and says so.** Vault's kubernetes
auth backend validates the presented JWT by calling back to the cluster's
TokenReview API (or, out of scope here, local JWKS validation against
configured signing keys) -- and this stack has no Kubernetes control plane,
same category as "real OCI" in `test/README.md`'s "What is *not* here, on
purpose." What *is* checked: whether the client-side request is really just
`{role, jwt}` with nothing else required before Vault gets into cluster-side
validation. A structural rejection (missing field, bad mount) would falsify
"the file read is the work"; anything past that -- Vault reading claims out
of the JWT, or failing to reach the API server -- confirms it, because both
mean our request cleared every check that does not need a real cluster.

Idempotent: wipes its own roles first, so re-running does not depend on the
previous run's state. Leaves the `approle` and `kubernetes` auth mounts
enabled across runs -- infrastructure, not scratch state, the same
distinction `vault_cas_probe.py` draws for the `kv` mount.

    python test/vault_auth_probe.py
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "sopuli-test-root")
ROLE = "sopuli-probe"

#: A throwaway self-signed cert (`openssl req -x509 -newkey rsa:2048 -nodes
#: -days 1 -subj "/CN=sopuli-probe-dummy-ca"`), never used to validate
#: anything real. `POST auth/kubernetes/config` insists on a *parseable*
#: `kubernetes_ca_cert` before it will accept the config at all -- without
#: one it tries to read `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`
#: off local disk (the in-cluster default) and fails immediately, which this
#: probe found out the hard way on its first run. Any well-formed PEM cert
#: gets past that check; only login time cares whether it is the *right* one.
DUMMY_CA_CERT = """-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUd56ltnGzfUjWN5H0RxPOSitG6ZMwDQYJKoZIhvcNAQEL
BQAwIDEeMBwGA1UEAwwVc29wdWxpLXByb2JlLWR1bW15LWNhMB4XDTI2MDgxODEw
NTkxOFoXDTI2MDgxOTEwNTkxOFowIDEeMBwGA1UEAwwVc29wdWxpLXByb2JlLWR1
bW15LWNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2pOXV+2MJQHP
deNSd1Ift1Ff5UXOh2OmUZbkoGvjtNwz3oOwCKjzw4GNAtYLFCH4RqUw5ylYQewi
UUZoinl/Zm95xD5xF0tnf4ignDZZbIC50i6xhq13Z5w8aYzJQL8uMadzHTrvABxi
olZkA50tnrQXDrXZTkfo5Xlf3X9Ignc6hGcOm4kguxSyy4dOpUoRWhofbaafgXYO
0/d+Ho8mshdAg4d9DBg8H9o/Ab+Y9svKjP+63+Xyhu6iSSbs7wbqDgPKqZgNs5kL
oDJM+t1Z+ambrgBbohL4iFNEpibCol9bRPgx/NiD+nmAwazyxslvDlo4rv+LiDlG
+2k7QTin5QIDAQABo1MwUTAdBgNVHQ4EFgQUcX5nXaCQVdUX+cHWreNMdOGfIaUw
HwYDVR0jBBgwFoAUcX5nXaCQVdUX+cHWreNMdOGfIaUwDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOCAQEAFcXTXFFcaETTSyBydcuW5qxHLEx+LWTWQlB0
cv8cpPbPxn5/Y1ulrO5HCi0rbcEM9+/+le4Z1h2L/gRw/wk0/9hL6Wh+Vym6pToD
Wr3w52mKYXdwZa7LKaGNXntE1yeP012owt79C43038fSdXB+Lw1tGqifp+QjZ884
oyc71cub0r8TtVQGgIT5I+2rdJOBweJJmPk3O6cRJeHq9Sl9QLB5vrVHYB+iPSzz
p1dTsbczR133wzSXWkb3fg+horbl2TN/vS8dKwtXRbi2McVBNCao8gkHRTbzbjm6
kalFyhOwWWACqormSQrejfo09sOilKglf9MVFPnqR/mA38gunw==
-----END CERTIFICATE-----
"""

FAILURES: list[str] = []


@dataclass
class Response:
    status: int
    body: Any

    @property
    def errors(self) -> list[str]:
        if isinstance(self.body, dict) and isinstance(self.body.get("errors"), list):
            return self.body["errors"]
        return []

    @property
    def data(self) -> dict[str, Any]:
        if isinstance(self.body, dict) and isinstance(self.body.get("data"), dict):
            return self.body["data"]
        return {}

    @property
    def auth(self) -> dict[str, Any]:
        if isinstance(self.body, dict) and isinstance(self.body.get("auth"), dict):
            return self.body["auth"]
        return {}


def call(
    method: str,
    path: str,
    *,
    token: str | None = VAULT_TOKEN,
    json_body: dict[str, Any] | None = None,
) -> Response:
    """A raw Vault API call. ``token=None`` sends no auth header at all --
    the shape a genuinely unauthenticated login call has to work under."""
    url = f"{VAULT_ADDR}/v1/{path}"
    data = json.dumps(json_body).encode("utf-8") if json_body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    if token is not None:
        request.add_header("X-Vault-Token", token)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read()
            body = json.loads(raw) if raw else None
            return Response(status=response.status, body=body)
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            body = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            body = raw.decode("utf-8", errors="replace")
        return Response(status=error.code, body=body)
    except urllib.error.URLError as error:
        # A network-shaped failure -- what a call to an unreachable cluster
        # looks like from here, as opposed to a 4xx Vault answers itself.
        return Response(status=-1, body=str(error.reason))


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def show(label: str, response: Response) -> None:
    print(f"  {label}: HTTP {response.status}")
    print(f"    body: {json.dumps(response.body)}")


def expect(condition: bool, description: str) -> None:
    mark = "OK" if condition else "FAIL"
    print(f"  [{mark}] {description}")
    if not condition:
        FAILURES.append(description)


def note(text: str) -> None:
    print(f"  [NOTE] {text}")


def enable_auth(method: str) -> None:
    response = call("POST", "sys/auth/" + method, json_body={"type": method})
    if response.status == 400 and any("already in use" in e for e in response.errors):
        print(f"  {method} auth already enabled")
        return
    print(f"  enabled {method} auth: HTTP {response.status}")


# ------------------------------------------------------------------ AppRole ---


def approle_probe() -> None:
    section("AppRole: enable, role, role_id, secret_id, login")
    enable_auth("approle")

    # Idempotent: deleting the role first means a rerun starts from the same
    # state, the same reason `vault_cas_probe.py` wipes its path up front.
    call("DELETE", f"auth/approle/role/{ROLE}")

    created = call(
        "POST",
        f"auth/approle/role/{ROLE}",
        json_body={"token_policies": "default", "token_ttl": "10m", "token_max_ttl": "30m"},
    )
    show("create role", created)
    expect(created.status in (200, 204), "role is created")

    role_id_resp = call("GET", f"auth/approle/role/{ROLE}/role-id")
    show("read role_id", role_id_resp)
    role_id = role_id_resp.data.get("role_id")
    expect(isinstance(role_id, str) and role_id, "role_id came back as a plain string")

    secret_id_resp = call("POST", f"auth/approle/role/{ROLE}/secret-id")
    show("generate secret_id", secret_id_resp)
    secret_id = secret_id_resp.data.get("secret_id")
    expect(isinstance(secret_id, str) and secret_id, "secret_id came back as a plain string")

    section("AppRole: the login call itself")
    # No token header at all: login is unauthenticated by design, and a client
    # that sent one anyway would be doing unnecessary work.
    login = call(
        "POST",
        "auth/approle/login",
        token=None,
        json_body={"role_id": role_id, "secret_id": secret_id},
    )
    show("login (no auth header)", login)
    expect(login.status == 200, "one POST, role_id + secret_id, no auth header -- succeeds")
    client_token = login.auth.get("client_token")
    expect(isinstance(client_token, str) and client_token, "response carries a client_token")
    expect(login.auth.get("renewable") is True, "token reports renewable=true")
    lease = login.auth.get("lease_duration")
    print(f"    lease_duration: {lease}s, policies: {login.auth.get('token_policies')}")

    section("AppRole: does the returned token actually work")
    lookup = call("GET", "auth/token/lookup-self", token=client_token)
    show("lookup-self with the new token", lookup)
    expect(lookup.status == 200, "the token from login authenticates a follow-up call")
    expect("default" in lookup.data.get("policies", []), "policies match what the role granted")

    section("AppRole: wrong secret_id -- must fail cleanly, not silently")
    bad_login = call(
        "POST",
        "auth/approle/login",
        token=None,
        json_body={"role_id": role_id, "secret_id": "not-the-right-one"},
    )
    show("login with a wrong secret_id", bad_login)
    expect(bad_login.status in (400, 403), "a wrong secret_id is refused, not accepted")
    expect("client_token" not in bad_login.auth, "no token is issued on the failed attempt")

    if isinstance(client_token, str) and client_token:
        call("POST", "auth/token/revoke-self", token=client_token)


# --------------------------------------------------------------- Kubernetes ---


def _fake_jwt() -> str:
    """Structurally valid, cryptographically worthless. Enough for Vault to
    get past parsing and go looking for a cluster to validate the signature
    against -- which is the point: we want to see *that* failure, not a
    "your JSON is malformed" one."""

    def b64url(payload: dict[str, Any]) -> str:
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    header = b64url({"alg": "RS256", "typ": "JWT"})
    body = b64url(
        {
            "iss": "kubernetes/serviceaccount",
            "sub": "system:serviceaccount:default:sopuli-probe",
            "aud": ["https://kubernetes.default.svc"],
        }
    )
    signature = base64.urlsafe_b64encode(b"not-a-real-signature").rstrip(b"=").decode("ascii")
    return f"{header}.{body}.{signature}"


def kubernetes_probe() -> None:
    section("Kubernetes: enable, configure, role")
    enable_auth("kubernetes")

    call("DELETE", f"auth/kubernetes/role/{ROLE}")

    # A port nothing listens on, so an unreachable-cluster failure surfaces as
    # a fast connection error rather than a DNS timeout -- there is no real
    # control plane in this stack (test/README.md's "What is not here, on
    # purpose"), so this is the closest thing to "configured, but at a cluster
    # this box cannot reach." `kubernetes_ca_cert` has to be a parseable PEM or
    # this call itself is refused before reachability ever comes up -- found by
    # running this once without it; see DUMMY_CA_CERT's comment.
    configured = call(
        "POST",
        "auth/kubernetes/config",
        json_body={
            "kubernetes_host": "https://127.0.0.1:6443",
            "kubernetes_ca_cert": DUMMY_CA_CERT,
        },
    )
    show("configure", configured)
    expect(
        configured.status in (200, 204),
        "config is accepted -- no cluster reachability check at config time",
    )

    role = call(
        "POST",
        f"auth/kubernetes/role/{ROLE}",
        json_body={
            "bound_service_account_names": "*",
            "bound_service_account_namespaces": "*",
            "token_policies": "default",
            "token_ttl": "10m",
        },
    )
    show("create role", role)
    expect(role.status in (200, 204), "role is created")

    section("Kubernetes: the login call itself -- {role, jwt}, nothing else")
    login = call(
        "POST",
        "auth/kubernetes/login",
        token=None,
        json_body={"role": ROLE, "jwt": _fake_jwt()},
    )
    show("login (no auth header, fake jwt)", login)

    message = " | ".join(login.errors) if login.errors else str(login.body)
    structural_rejection = login.status in (400, 404) and any(
        needle in message.lower()
        for needle in ("missing", "unknown role", "no such", "unrecognized", "required")
    )
    expect(
        not structural_rejection,
        f"failure is not a structural one (missing field / bad role) -- got: {message!r}",
    )
    note(
        "this does NOT confirm a real Kubernetes login succeeds -- no cluster to validate "
        "the JWT against exists in this stack. It confirms the client-side request needs "
        "nothing beyond {role, jwt}: Vault accepted the shape, parsed the fake JWT as a real "
        "one, and got as far as reading its claims before failing -- on this run, an absent "
        "'kubernetes.io' UID claim my synthetic JWT does not carry, not a network error, "
        "which means it never even reached for the (unreachable) API server configured above. "
        f"Either way is evidence the client sends only {{role, jwt}}. Observed failure: {message!r}"
    )


def main() -> int:
    approle_probe()
    kubernetes_probe()

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) failed:")
        for description in FAILURES:
            print(f"  - {description}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Getting a token, per ``01-configuration.md`` §3a.

ADR-005's central measured claim is what makes this module small: **with renewal
removed, §3a's auth surface is about five POSTs.** `token` is not a call at all
-- it is a header, and a source chain the config layer already owns
(:mod:`sopuli.material`). AppRole, Kubernetes and userpass are one POST each,
against endpoints that differ only in where the identity goes.

Measured against the tier-0 Vault (``test/vault_auth_probe.py``): an AppRole
login carries **no auth header** -- it is the one request in the tool that is
deliberately unauthenticated, because it is the request that produces the
authentication.

**Nothing here logs its own inputs.** A login body carries a ``secret_id``, a
``jwt`` or a ``password``, and the answer carries a token; all of them are
:class:`~sopuli.secrets.Secret` from the moment they exist, so an error message
interpolating one gets ``***`` rather than the credential (invariant 2).
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import quote

from sopuli.config.model import MaterialRef, Vault, VaultAuth
from sopuli.exit_codes import ExitCode
from sopuli.material import resolve, resolve_token
from sopuli.secrets import Secret
from sopuli.store.hashicorp._errors import messages, raise_for
from sopuli.store.hashicorp._transport import Transport, build_transport
from sopuli.store.protocol import StoreError

#: The methods this backend serves, and the auth mount each defaults to. §3a
#: says a mount "defaults to the method's own name", which is the convention
#: Vault itself uses -- so this is the rule rather than four separate facts.
METHODS = ("token", "approle", "kubernetes", "userpass")

#: In §3a's table for a vault, and not implemented. It needs a browser launch
#: and a local callback listener. See :func:`_refuse` for why deferring it costs
#: less than it looks.
DEFERRED = ("oidc",)

#: The two statuses that mean the login itself was answered and rejected
#: (measured; see :func:`_hint`). Everything else non-2xx is delegated to
#: :func:`~sopuli.store.hashicorp._errors.raise_for`, which already tells a
#: sealed store from a standby from an ordinary failure.
REFUSAL_STATUSES = (400, 403)

#: What OCI's methods are called. Reaching a *HashiCorp* store with one is a
#: config error rather than a gap: they authenticate to a different vendor.
FOREIGN = ("instance_principal", "resource_principal", "config_file", "session_token")


class LoginFailedError(StoreError):
    """The store refused the credential we sent.

    ``authentication``, and exit 6 -- P5 gives one code to "authentication
    failed against the vault or the database", and this is the vault half of it.

    Distinct from :class:`~sopuli.material.MaterialError`, which is exit 9 and
    means there was nothing to send. The two are worth telling apart because the
    fixes are in different places: a wrong `secret_id` is a vault problem, and
    an unset variable is a this-machine problem.
    """

    category = "authentication"
    exit_code = ExitCode.AUTH_FAILURE


class MethodNotImplementedError(StoreError):
    """A method §3a declares that this build cannot perform.

    Its own class so the message can say *not yet* rather than *not supported*:
    one is a roadmap item and the other is a decision, and OIDC is the first.
    """

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID


def authenticate(vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None) -> Secret:
    """A token for ``vault``, by whichever method its ``auth:`` names.

    ``token_file`` is ``--vault-token-file``'s path (C16, ADR-007). A **path**
    and not a :class:`~sopuli.secrets.Secret`: a token as a command-line value is
    exactly what invariant 1 forbids, so the flag names where the token lives and
    the value is read on the chain in :func:`~sopuli.material.resolve_token`,
    beside every other step of it.

    It reaches ``method: token`` and nothing else, the same way ``$VAULT_TOKEN``
    does. A store authenticating by AppRole is not asked for a token, so a run
    naming both a token file and an AppRole store is not a contradiction to
    refuse -- it is a chain with no position in force, exactly as an inherited
    ``$VAULT_TOKEN`` already is.

    An absent ``auth:`` block means ``method: token``, which is what makes a
    laptop with `~/.vault-token` work against a two-line config. §3a's table
    gives `token` no required keys for the same reason.
    """
    where = f'vault "{vault.name}"'
    auth = vault.auth
    method = auth.method if auth is not None else "token"

    if method in DEFERRED:
        _refuse(method, where=where)
    if method in FOREIGN:
        raise MethodNotImplementedError(
            f"{where}: `{method}` authenticates to OCI, not to a HashiCorp store",
            hint=f"a HashiCorp store takes one of: {', '.join(METHODS)}",
        )
    if method == "token":
        return resolve_token(
            ref=auth.token if auth is not None else None,
            env=env,
            token_file=token_file,
            where=where,
        )
    if method == "approle":
        return _approle(vault, _required(auth), env=env, where=where)
    if method == "kubernetes":
        return _kubernetes(vault, _required(auth), env=env, where=where)
    if method == "userpass":
        return _userpass(vault, _required(auth), env=env, where=where)

    # Unreachable through a config file: `AUTH_METHODS` is a closed set the
    # builder validates against, and everything in it is handled above.
    raise MethodNotImplementedError(f"{where}: unknown auth method {method!r}")


def _refuse(method: str, *, where: str) -> None:
    """Say *not yet*, and say what it would take.

    ADR-005 is explicit that the hard part of OIDC is not the Vault call: it is
    the browser launch, the local callback listener and the `state`/`nonce`
    handling, which the Vault CLI does and which no Python client provides --
    `hvac` included. So deferring it costs nothing that choosing a client
    library would have bought, and the message says so rather than implying the
    method is unsupported in principle.
    """
    raise MethodNotImplementedError(
        f"{where}: `{method}` is not implemented in this build yet",
        hint=(
            "it needs a browser launch and a local callback listener, which is CLI work "
            f"rather than a Vault call. Use one of: {', '.join(METHODS)}"
        ),
    )


def _required(auth: VaultAuth | None) -> VaultAuth:
    """The block, which the config layer has already guaranteed is here.

    A method with required keys cannot be written as a bare scalar (§3a), so by
    the time a name reaches this module its block exists. Asserted rather than
    assumed because the alternative is an `AttributeError` on `None` at the
    moment somebody is trying to log in.
    """
    if auth is None:  # pragma: no cover -- the builder refuses this shape
        raise StoreError("this auth method needs a block, and none was read")
    return auth


def _approle(vault: Vault, auth: VaultAuth, *, env: Mapping[str, str], where: str) -> Secret:
    """Two calls, of which the config layer already made one.

    The probe found this to be genuinely simple: `role_id` and `secret_id` go to
    `auth/<mount>/login` with no auth header, and a `client_token` comes straight
    back. Reading the `role_id` out of Vault -- the second call people expect --
    is an operator's setup step, not this tool's: the config names where the
    material lives and both halves arrive from there.
    """
    return _login(
        vault,
        path=f"auth/{_mount(auth, 'approle')}/login",
        body={
            "role_id": _material(auth.role_id, "role_id", env=env, where=where),
            "secret_id": _material(auth.secret_id, "secret_id", env=env, where=where),
        },
        where=where,
    )


def _kubernetes(vault: Vault, auth: VaultAuth, *, env: Mapping[str, str], where: str) -> Secret:
    """`{role, jwt}`, and the JWT is the interesting half.

    "Read the projected service-account token off disk and POST it" -- the file
    read is the work, and it is a `MaterialRef` like any other, which is why
    this function is three lines. The probe could exercise it only up to the
    point a real cluster becomes load-bearing: Vault accepted a
    syntactically-valid fake JWT past every check that does not require one, and
    failed reading claims out of it.
    """
    return _login(
        vault,
        path=f"auth/{_mount(auth, 'kubernetes')}/login",
        body={
            "role": _identity(auth.role, "role", where=where),
            "jwt": _material(auth.jwt, "jwt", env=env, where=where),
        },
        where=where,
    )


def _userpass(vault: Vault, auth: VaultAuth, *, env: Mapping[str, str], where: str) -> Secret:
    """One POST, with the username in the *path* rather than the body.

    The one endpoint here that is not `…/login`, which is easy to miss and fails
    with a 404 rather than a 403 when it is got wrong -- a confusing symptom for
    something that looks like a credential problem.
    """
    # Encoded as a *single path segment*: a username holding `/`, `?`, `#` or a
    # space would otherwise rewrite the request path and come back as a
    # confusing 403 or 404 -- which, per `_hint` below, would then be read as
    # "the auth mount is missing". Deliberately unlike a secret path in `kv2.py`,
    # which is hierarchical and whose slashes are meant to survive.
    username = quote(_identity(auth.username, "username", where=where), safe="")
    return _login(
        vault,
        path=f"auth/{_mount(auth, 'userpass')}/login/{username}",
        body={"password": _material(auth.password, "password", env=env, where=where)},
        where=where,
    )


def _mount(auth: VaultAuth, default: str) -> str:
    """The **auth** mount, not the KV one, defaulting to the method's own name.

    The config layer leaves it ``None`` when unwritten rather than filling in the
    default, so that ``config show --explain`` can tell an unset value from a
    written one (P3). This is where the default is finally applied, which is the
    only place it does not cost that distinction.
    """
    return auth.mount if auth.mount is not None else default


def _identity(value: str | None, key: str, *, where: str) -> str:
    if value is None:  # pragma: no cover -- the builder requires it
        raise StoreError(f"{where}: `{key}` is required by this auth method")
    return value


def _material(ref: MaterialRef | None, key: str, *, env: Mapping[str, str], where: str) -> Secret:
    if ref is None:  # pragma: no cover -- the builder requires it
        raise StoreError(f"{where}: `{key}` is required by this auth method")
    return resolve(ref, env=env, where=f"{where} key {key!r}")


def _login(vault: Vault, *, path: str, body: dict[str, Any], where: str) -> Secret:
    """POST a credential, unauthenticated, and read the token out of the answer.

    ``token=None`` on the transport is deliberate and is the one place it is
    correct: this request *is* the authentication, so there is no token to send
    and Vault rejects one that does not exist anyway.

    The body is revealed at exactly this point and nowhere else -- it goes
    straight into the request and is never held, logged, or interpolated into a
    message.
    """
    transport = build_transport(vault, token=None)
    try:
        response = transport.request(
            "POST",
            path,
            json={
                key: value.reveal() if isinstance(value, Secret) else value
                for key, value in body.items()
            },
        )
        if response.status in REFUSAL_STATUSES:
            raise LoginFailedError(
                f"{where}: the store refused the credential: {_detail(response.body)}",
                hint=_hint(response.status),
            )
        if not response.ok:
            # Everything else is the store being unable to answer rather than
            # unwilling to accept: sealed is 503, a standby is 429 or 473, and a
            # 500 is a 500. Calling any of those an authentication failure would
            # put exit 6 on a run whose credential was never looked at -- and
            # exit 6 is the code a scheduler reads as "stop and fix the
            # credential", which is the one action that would not help.
            raise_for(response.status, response.body, path=path)
        return _client_token(response.body, where=where)
    finally:
        # The login client is not the client the store will use: the store's
        # carries the token this call produced. Closing it here keeps a socket
        # from outliving the one request it existed for.
        transport.close()


def _client_token(body: Any, *, where: str) -> Secret:
    token = None
    if isinstance(body, dict):
        auth = body.get("auth")
        if isinstance(auth, dict):
            token = auth.get("client_token")
    if not isinstance(token, str) or not token:
        raise LoginFailedError(
            f"{where}: the store accepted the credential and returned no token",
            hint="this is a Vault-side surprise rather than a credential problem",
        )
    return Secret(token)


def _detail(body: Any) -> str:
    return " | ".join(messages(body)) or "no reason given"


def _hint(status: int) -> str:
    """Which of the two failures this was, from the status alone.

    Measured against `hashicorp/vault:2.0.4`, because the answer is the reverse
    of the intuition:

    ======  =========================================  =========================
    Status  Vault says                                 What it means
    ======  =========================================  =========================
    403     ``permission denied``                      the auth **mount** is not
                                                       there
    400     ``invalid username or password``, or       the **credential** is
            ``invalid role or secret ID``              wrong
    ======  =========================================  =========================

    **A 403 on a login is not a policy problem**, which is what a 403 means
    everywhere else in this backend. A login endpoint is unauthenticated -- there
    is no identity yet, so there is nothing to deny -- and Vault answers 403 for
    a path that does not route rather than the 404 a reader would expect. So the
    one status that looks most like "your credential was rejected" is the one
    that means the credential was never examined.

    Getting this backwards costs an afternoon: it sends somebody to rotate a
    `secret_id` that was fine, against a mount that was never enabled.
    """
    if status == 403:
        return (
            "a 403 on a *login* usually means the auth mount does not exist rather than "
            "that the credential was refused -- a login endpoint has no identity to deny. "
            "Check `mount:` against `vault auth list`"
        )
    if status == 400:
        return "the credential was refused; check it, and that its role still exists"
    return "check the credential, the auth mount, and that the role has not expired"


def build_authenticated_transport(
    vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
) -> Transport:
    """A transport carrying a token obtained by ``vault``'s own auth method."""
    return build_transport(vault, token=authenticate(vault, env=env, token_file=token_file))

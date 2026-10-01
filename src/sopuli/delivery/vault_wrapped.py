"""`delivery.method: vault_wrapped` — a Vault response-wrapping token (#444).

UC-2 §6.2 makes this the default, and the reason is availability rather than
preference: it works against a stock Vault, needing nothing but the mount the
estate already has. Every other unseen method needs infrastructure the tool does
not create, and a default an estate could not use would fall back to `manual` —
the one path that shows a DBA a working password.

**What it promises, exactly**, from §6.6: single use, so a value fetched twice is
a value somebody else fetched first, and **interception is detectable even where
it is not preventable**. That is the strongest property in the table and it comes
with the weakest — the token is a *bearer* credential, so whoever holds it can
unwrap it, whatever their identity. H9 (#496) decided what that is worth: where
Vault has an audit device, the accessor this module returns finds the wrap (under
the DBA's identity) and the unwrap (under the same accessor HMAC) in it; no
device, or a redirected token, is where that stops (UC-2 §1). The reset record
that carries the accessor is an index, not evidence. Nothing here claims more.

**Single use is Vault's, not ours.** A response-wrapping token is single-use by
construction, so there is no `num_uses` to configure and this module has no
counter to keep. `sopuli/config/delivery.py` refuses the key rather than
accepting and ignoring it, because a file that sets `num_uses: 1` is a file whose
author believes the tool is enforcing something.

**The TTL is passed through, not parsed.** Vault owns the grammar of
``X-Vault-Wrap-TTL``; a second implementation of it here would be a parser that
disagrees with the server about what ``90m`` means. What is checked is the shape,
in the config layer, so a typo is a config error rather than a 400 after a
password has been drawn. ``expires_at`` on the receipt comes from the *response* —
the server's own answer about its own clock — rather than from the string.

**It borrows the transport of a store the run already opened** (§3a's auth chain,
#483's one-client rule). Wrapping is a `sys/` operation rather than a KV one, so
it is not a :class:`~sopuli.store.protocol.SecretStore` capability: adding one
would have given every backend a method most cannot serve, for an operation that
is not about a path. What it needs is an authenticated connection, and the run
has one.

**The two imports that reach `httpx` are inside the functions that use them**,
which ADR-006 rule 1 requires of every module that is not itself a registered
backend. `tests/store/test_install_shape.py` walks every `sopuli.*` module and
imports it with the vendor clients blocked, exempting only the paths named in
`BACKENDS` and `DRIVERS` -- and this module is not one of those, so a module-scope
`from sopuli.store.hashicorp._transport import Transport` fails it. That is how
the first build of this file was caught: three install-shape tests went red
together, which is the whole point of having them.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sopuli.delivery import Receipt
from sopuli.exit_codes import ExitCode
from sopuli.safety import RefusedError
from sopuli.secrets import Secret
from sopuli.store.protocol import SecretStore, StoreError

if TYPE_CHECKING:  # pragma: no cover -- annotations only
    from sopuli.store.hashicorp._transport import Transport

#: The method's name in `delivery.method`, and what a receipt records.
METHOD = "vault_wrapped"

#: Vault's wrap endpoint, and the header that says for how long.
WRAP_PATH = "sys/wrapping/wrap"
WRAP_TTL_HEADER = "X-Vault-Wrap-TTL"

#: What the person sees when they unwrap. The password, and enough context to
#: know which account it is for -- a cubbyhole holding a bare string would make
#: somebody who was sent two tokens guess which was which.
PASSWORD_KEY = "password"


class NotWrappableError(RefusedError):
    """The configured store cannot wrap, so this method cannot deliver.

    Exit 5 rather than 8, for :class:`~sopuli.reset.DeliveryUnavailableError`'s
    reason: the estate asked for something this *backend* cannot do, which is
    what exit 5 has meant since P1. Reached when `delivery.method:
    vault_wrapped` is configured against a store that is not a HashiCorp one --
    an OCI vault has no cubbyhole and no equivalent, so there is nothing to
    degrade to and guessing would be worse than refusing (invariant 4).
    """

    exit_code = ExitCode.UNSUPPORTED_CAPABILITY
    category = "capability"

    def __init__(self, vault: str) -> None:
        super().__init__(
            f"`delivery.method: vault_wrapped` needs a HashiCorp store and {vault!r} is not one",
            hint=(
                "response wrapping is a Vault feature with no equivalent elsewhere. Name a "
                "`type: hashicorp` entry in `delivery.vault_wrapped.vault`, on the target, "
                "or as `defaults.vault` -- or choose another method (UC-2 6.2). Not "
                "`reset_records.vault`, which this does not read: the journal and the "
                "delivery target are two objects with two lifetimes (§3.5)"
            ),
        )


@dataclass(frozen=True)
class VaultWrapped:
    """Wraps a password into a single-use cubbyhole and returns the token."""

    transport: Transport
    ttl: str

    def deliver(self, secret: Secret, *, account: str, target: str) -> Receipt:
        """Wrap, and return what the person fetches with.

        **This is invariant 2's first exception**, the vault write, reached as a
        wrap rather than as a KV put: the plaintext goes to Vault over the same
        authenticated connection a rotation writes a document on, and to nobody
        else. It is the same permission `store/credentials.py` already holds, and
        `tests/test_reveal_sites.py` records this site with that reason.

        The body carries the account and the target beside the password so that
        an unwrap answers *which account is this for*. Nothing in it identifies
        the DBA: a cubbyhole is read by the owner, and who reset it is the
        journal's business (UC-2 §3.1).
        """
        # Inside the call, not at module scope: see this module's docstring.
        from sopuli.store.hashicorp._errors import raise_for

        body: dict[str, Any] = {
            PASSWORD_KEY: secret.reveal(),
            "account": account,
            "target": target,
        }
        response = self.transport.request(
            "POST", WRAP_PATH, json=body, headers={WRAP_TTL_HEADER: self.ttl}
        )
        if not response.ok:
            raise_for(response.status, response.body, path=WRAP_PATH)
        return _receipt(response.body)


def _receipt(body: Any) -> Receipt:
    """Read `wrap_info` out of the answer, or say the answer made no sense.

    **A missing token is a failure rather than an empty receipt.** A 200 with no
    `wrap_info` means wrapping did not happen -- most plausibly a proxy that
    stripped the header -- and returning a receipt with ``token=None`` would let
    the caller go on to issue the DDL, leaving an account whose password nobody
    holds. That is precisely the failure UC-2 §6.4 orders the steps to prevent,
    so it has to raise here rather than be reported as a partial success.
    """
    info = body.get("wrap_info") if isinstance(body, dict) else None
    if not isinstance(info, dict):
        info = {}
    token = info.get("token")
    if not isinstance(token, str) or not token:
        raise StoreError(
            "the wrap request returned no token, so nothing was handed over",
            hint=(
                f"Vault answered 200 with no usable `wrap_info.token`. Check that nothing "
                f"between this host and the vault strips the {WRAP_TTL_HEADER} header, and "
                f"that the token may write `{WRAP_PATH}`"
            ),
        )
    accessor = info.get("accessor")
    return Receipt(
        method=METHOD,
        token=Secret(token),
        accessor=accessor if isinstance(accessor, str) else None,
        expires_at=_expiry(info),
    )


def _expiry(info: dict[str, Any]) -> datetime | None:
    """When the cubbyhole stops answering, from the server's own two numbers.

    Computed from the response rather than from the configured string, because the
    TTL Vault applied may be shorter than the one asked for -- a mount's
    ``max_ttl`` caps it silently -- and reporting the request back as though it
    were the outcome would tell an operator the handover lasts longer than it
    does.

    **``creation_time`` plus ``ttl``, not *now* plus ``ttl``** (Copilot's review of
    #518). The first draft added the server's TTL to the *client's* clock while
    this docstring claimed it was the server's answer, which is wrong by however
    far the two clocks differ plus the round trip -- small, usually, and not
    something to be casually wrong about in the one line that tells somebody how
    long they have.

    ``None`` when the answer carries no usable ``ttl``: a receipt that admits to
    not knowing is better than one carrying a number this module made up.

    **A malformed ``creation_time`` falls back to the client clock rather than to
    ``None``**, which is where this departs from the review's suggested fix. The
    TTL is the number that matters and it parsed; discarding it would replace a
    figure that is wrong by milliseconds with no figure at all, and the operator
    reading the line needs to know roughly when their hand-over stops working.
    """
    ttl = info.get("ttl")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
        return None
    return (_created(info) or datetime.now(UTC)) + timedelta(seconds=ttl)


def _created(info: dict[str, Any]) -> datetime | None:
    """``wrap_info.creation_time``, or ``None`` when it is not a timestamp.

    Vault sends RFC 3339 with a ``Z``, which :meth:`datetime.fromisoformat` reads
    from 3.11 on -- the floor this project already requires.
    """
    created = info.get("creation_time")
    if not isinstance(created, str):
        return None
    try:
        parsed = datetime.fromisoformat(created)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def for_store(store: SecretStore, *, vault: str, ttl: str) -> VaultWrapped:
    """The backend for a store the run has already opened, or a refusal.

    The import is local for this module's own reason, and it has a second one
    here: a base install with no `httpx` cannot have opened a HashiCorp store
    either, so the only way to reach this line is in an install where the import
    works.

    ``getattr`` rather than ``isinstance`` on the *store*, deliberately: what this needs is an
    authenticated :class:`~sopuli.store.hashicorp._transport.Transport`, which
    both KV v1 and KV v2 carry, and naming either class here would tie a delivery
    method to the two KV versions that happen to exist today. What it must not do
    is guess -- a store with no transport is :class:`NotWrappableError`, named and
    refused at plan time.
    """
    transport = getattr(store, "transport", None)
    if transport is None:
        # **Before the import, and that ordering is the whole of it** (Copilot's
        # review of #518). A base install has no `httpx`, so importing the
        # transport to compare against would raise `ModuleNotFoundError` for an
        # estate whose delivery store is not a HashiCorp one at all -- burying the
        # capability refusal this function exists to give under an import error
        # about a client that was never relevant. A store with no transport cannot
        # be a HashiCorp one, which is answerable without importing anything.
        raise NotWrappableError(vault)

    from sopuli.store.hashicorp._transport import Transport

    # Only reachable where a store *has* a transport, which means a HashiCorp
    # backend was opened, which means the client is installed.
    if not isinstance(transport, Transport):
        raise NotWrappableError(vault)
    return VaultWrapped(transport=transport, ttl=ttl)

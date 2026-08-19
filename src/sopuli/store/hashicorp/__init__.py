"""The HashiCorp Vault backend -- P2's first real store (#104).

What :data:`sopuli.store.registry.BACKENDS` resolves ``type: hashicorp`` to.
Importing this module imports `httpx`, which is the whole point of importing it
lazily: ADR-006 rule 1 keeps a vendor client inside the backend that needs it,
so a base install carries neither the client nor a socket.

Two mounts, two stores, one interface. KV v2 is P2's reference implementation
(:mod:`.kv2`); KV v1 is a different backend with the guarantees removed
(:mod:`.kv1`), and the difference that matters to the tool is that one has
compare-and-set and the other cannot have it emulated.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from sopuli.config.model import Vault
from sopuli.secrets import Secret
from sopuli.store.hashicorp._auth import authenticate
from sopuli.store.hashicorp._transport import build_transport
from sopuli.store.hashicorp.kv1 import Kv1Store
from sopuli.store.hashicorp.kv2 import Kv2Store
from sopuli.store.protocol import SecretStore, StoreError

#: KV v2 unless the config says otherwise. P2 puts v2 first and calls it the
#: reference implementation, and a mount created by anything recent is v2 -- so
#: the assumption an unwritten `kv_version` makes is the one that is right far
#: more often, and getting it wrong fails loudly on the first read rather than
#: silently doing something weaker.
DEFAULT_KV_VERSION = 2

#: Where KV lives when the entry does not say. Vault's own default mount path.
DEFAULT_MOUNT = "secret"


def connect(vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None) -> SecretStore:
    """A usable store from a config entry, and the first function that is one.

    The whole chain in one line, which is worth naming because until now each
    piece existed without the next: the entry describes the transport (#135),
    the registry finds this module (#134), the material resolver turns an
    ``auth:`` block into a credential (#137), an auth method turns that into a
    token (#138), and the adapter reads and writes with it (#104).

    ``env`` is passed in rather than read here, the arrangement the rest of the
    tool already uses -- and it matters more here than elsewhere, because the
    environment is where half of §3a's auth material lives. ``token_file`` is
    ``--vault-token-file``'s path (#145) and travels the same way, for the same
    reason: it is a location, and the value behind it is read on §3a's chain.
    """
    return open_store(vault, token=authenticate(vault, env=env, token_file=token_file))


def open_store(vault: Vault, *, token: Secret) -> SecretStore:
    """The store for ``vault``, with a token already in hand.

    Kept beside :func:`connect` rather than folded into it: a token that came
    from somewhere else -- a test's dev-mode root token, a future `sopuli
    doctor` reusing one -- is a legitimate caller, and the KV data plane has no
    business knowing how the token was obtained.
    """
    mount = vault.mount if vault.mount is not None else DEFAULT_MOUNT
    version = vault.kv_version if vault.kv_version is not None else DEFAULT_KV_VERSION
    transport = build_transport(vault, token=token)

    if version == 2:
        return Kv2Store(transport=transport, mount=mount)
    if version == 1:
        return Kv1Store(transport=transport, mount=mount)
    # Unreachable through a config file -- `kv_version` is validated against a
    # closed set -- and kept because this function is also reachable from code.
    raise StoreError(f"unsupported kv_version {version!r} on vault {vault.name!r}")


__all__ = [
    "DEFAULT_KV_VERSION",
    "DEFAULT_MOUNT",
    "Kv1Store",
    "Kv2Store",
    "authenticate",
    "connect",
    "open_store",
]

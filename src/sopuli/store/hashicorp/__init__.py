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

from sopuli.config.model import Vault
from sopuli.secrets import Secret
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


def open_store(vault: Vault, *, token: Secret) -> SecretStore:
    """The store for ``vault``, ready to read and write.

    ``token`` is passed in rather than resolved here: turning an ``auth:`` block
    into a token is #138's job, and keeping it out of this function is what lets
    the KV data plane be tested against a dev-mode root token without an auth
    method existing yet.
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


__all__ = ["DEFAULT_KV_VERSION", "DEFAULT_MOUNT", "Kv1Store", "Kv2Store", "open_store"]

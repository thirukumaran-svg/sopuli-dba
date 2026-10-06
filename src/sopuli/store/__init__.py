"""Secret stores (P2).

:mod:`sopuli.store.protocol` is the interface. ``health`` is the one method
that is not about a path, and the one that reports an unreachable store rather
than raising at it. :mod:`sopuli.store.memory` is a KV v2 emulation that keeps
the tests in tier 0 and is the reference reading of those semantics.
:mod:`sopuli.store.hashicorp` is the HashiCorp Vault backend, for KV v1 and v2.

:mod:`sopuli.store.credentials` is the secret side of P2's interface: the
lock reads and writes a *record*, and this reads and writes a **credential** -- a
§7 SecretRef resolved against a stored document, honouring ``@version=`` and
``@stage=``, and a merge patch that changes one account's password without
sending anybody else's. Its own ``resolve`` is not re-exported here, because
:func:`sopuli.store.registry.resolve` already has the name and the two answer
very different questions -- import it from the module.

:mod:`sopuli.store.registry` is what finds them: a mapping from ``vaults.*.type``
to a module path, imported on first use so that a vendor client is a dependency
only of the site that configured its backend (ADR-006). Importing this package
therefore imports no client, and importing a client from anywhere outside a
backend module is what ``tests/store/test_install_shape.py`` fails on.

:func:`sopuli.store.registry.connect` is the front door: a config entry in, an
authenticated store out, with the backend chosen by ``type:``. Everything above
this package goes through it rather than importing a backend by name, which is
what keeps the choice of store in the config file where §3a puts it.
"""

from sopuli.store.credentials import (
    READ_MODIFY_WRITE,
    CannotPinVersionError,
    SecretShapeError,
    StoredSecret,
    Written,
    apply_patch,
    read_secret,
    staged_patch,
)
from sopuli.store.memory import MemoryStore
from sopuli.store.protocol import (
    CAS,
    DEGRADED,
    MERGE_PATCH,
    OK,
    UNREACHABLE,
    VERSIONING,
    CasConflictError,
    PatchNotPermittedError,
    PathMetadata,
    SecretStore,
    Stored,
    StoreError,
    StoreHealth,
)
from sopuli.store.registry import (
    BACKEND_NOT_INSTALLED,
    BACKENDS,
    Backend,
    BackendNotImplementedError,
    BackendNotInstalledError,
    connect,
    installed,
    resolve,
)

__all__ = [
    "BACKENDS",
    "BACKEND_NOT_INSTALLED",
    "CAS",
    "DEGRADED",
    "MERGE_PATCH",
    "OK",
    "UNREACHABLE",
    "READ_MODIFY_WRITE",
    "VERSIONING",
    "Backend",
    "BackendNotImplementedError",
    "BackendNotInstalledError",
    "CannotPinVersionError",
    "CasConflictError",
    "MemoryStore",
    "PatchNotPermittedError",
    "PathMetadata",
    "SecretShapeError",
    "SecretStore",
    "Stored",
    "StoreError",
    "StoreHealth",
    "StoredSecret",
    "Written",
    "apply_patch",
    "connect",
    "installed",
    "read_secret",
    "resolve",
    "staged_patch",
]

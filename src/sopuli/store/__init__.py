"""Secret stores (P2), as far as the advisory lock needs them.

:mod:`sopuli.store.protocol` is the slice #83's lock reads and writes;
:mod:`sopuli.store.memory` is a KV v2 emulation that keeps the lock's tests in
tier 0 and doubles as the reference reading of those semantics. The real
backends -- HashiCorp KV v2 first, per P2's priority order -- arrive with the
rest of the interface.

:mod:`sopuli.store.registry` is what finds them: a mapping from ``vaults.*.type``
to a module path, imported on first use so that a vendor client is a dependency
only of the site that configured its backend (ADR-006). Importing this package
therefore imports no client, and importing a client from anywhere outside a
backend module is what ``tests/store/test_install_shape.py`` fails on.

:func:`sopuli.store.registry.connect` is the front door: a config entry in, an
authenticated store out, with the backend chosen by ``type:``. Everything above
this package -- ``lock status`` today, the ``creds`` verbs next -- goes through
it rather than importing a backend by name, which is what keeps the choice of
store in the config file where §3a puts it.
"""

from sopuli.store.memory import MemoryStore
from sopuli.store.protocol import (
    CAS,
    CasConflictError,
    PathMetadata,
    SecretStore,
    Stored,
    StoreError,
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
    "Backend",
    "BackendNotImplementedError",
    "BackendNotInstalledError",
    "CasConflictError",
    "MemoryStore",
    "PathMetadata",
    "SecretStore",
    "Stored",
    "StoreError",
    "connect",
    "installed",
    "resolve",
]

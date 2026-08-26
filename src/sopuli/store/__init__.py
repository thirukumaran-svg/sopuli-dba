"""Secret stores (P2).

:mod:`sopuli.store.protocol` is the interface, grown a method at a time as
something needed one: #83's lock reads and writes a record, #150 added listing,
and #183 added a version-pinned read;
:mod:`sopuli.store.memory` is a KV v2 emulation that keeps the lock's tests in
tier 0 and doubles as the reference reading of those semantics. The real
backends -- HashiCorp KV v2 first, per P2's priority order -- arrive with the
rest of the interface.

:mod:`sopuli.store.credentials` is the secret side of P2's interface (#183): the
lock reads a *record*, and this reads a **credential** -- a §7 SecretRef resolved
against a stored document, honouring ``@version=`` and ``@stage=``. The read half
only; the write is the other half of the same issue. Its own ``resolve`` is not
re-exported here, because :func:`sopuli.store.registry.resolve` already has the
name and the two answer very different questions -- import it from the module.

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

from sopuli.store.credentials import (
    CannotPinVersionError,
    SecretShapeError,
    StoredSecret,
    read_secret,
)
from sopuli.store.memory import MemoryStore
from sopuli.store.protocol import (
    CAS,
    VERSIONING,
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
    "VERSIONING",
    "Backend",
    "BackendNotImplementedError",
    "BackendNotInstalledError",
    "CannotPinVersionError",
    "CasConflictError",
    "MemoryStore",
    "PathMetadata",
    "SecretShapeError",
    "SecretStore",
    "Stored",
    "StoreError",
    "StoredSecret",
    "connect",
    "installed",
    "read_secret",
    "resolve",
]

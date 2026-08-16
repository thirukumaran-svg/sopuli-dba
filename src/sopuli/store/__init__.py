"""Secret stores (P2), as far as the advisory lock needs them.

:mod:`sopuli.store.protocol` is the slice #83's lock reads and writes;
:mod:`sopuli.store.memory` is a KV v2 emulation that keeps the lock's tests in
tier 0 and doubles as the reference reading of those semantics. The real
backends -- HashiCorp KV v2 first, per P2's priority order -- arrive with the
rest of the interface.
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

__all__ = [
    "CAS",
    "CasConflictError",
    "MemoryStore",
    "PathMetadata",
    "SecretStore",
    "Stored",
    "StoreError",
]

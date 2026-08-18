"""KV v2 -- P2's reference implementation of the store interface (#104).

The four methods of :mod:`sopuli.store.protocol` against Vault's KV v2 API:

======================== =====================================================
``read(path)``           ``GET  /v1/<mount>/data/<path>``
``write(path, …)``       ``POST /v1/<mount>/data/<path>`` with ``options.cas``
``metadata(path)``       ``GET  /v1/<mount>/metadata/<path>``
``supports()``           ``{cas}``
======================== =====================================================

Three things the advisory lock depends on, and which are the reason this module
is worth reading rather than skimming. Each was checked against a real Vault.

**A 404 means "nothing to read" and nothing else.** A path that was never
written and a path whose latest version was *deleted* both answer 404 -- the
second with a body carrying the version it used to have. Both are ``None``
here, deliberately, because the difference is not knowable from a read in a way
a caller could act on: what distinguishes them is that a ``cas: 0`` write
succeeds against the first and can never succeed against the second. That is
why #83 releases a lock by writing a ``released`` record instead of deleting
one -- a delete would leave a path no first acquisition could ever take again.

**The version comes back from the write.** Not from a read afterwards: that
would reopen the window the fence exists to close, since anything could write
between the two.

**A lost compare-and-set is a** :class:`~sopuli.store.protocol.CasConflictError`
**and nothing else** (:mod:`._errors`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sopuli.store.hashicorp._errors import raise_for
from sopuli.store.hashicorp._transport import Response, Transport
from sopuli.store.protocol import CAS, PathMetadata, Stored, StoreError

#: Vault's "no per-path limit" for ``max_versions``: the mount's own setting
#: applies. Reported as ``None`` rather than 0, because ``PathMetadata`` means
#: "how many versions this path keeps" and zero would read as "none at all".
UNLIMITED = 0


@dataclass(frozen=True)
class Kv2Store:
    """One KV v2 mount, reached through one :class:`Transport`."""

    transport: Transport
    mount: str

    def supports(self) -> frozenset[str]:
        """KV v2 has compare-and-set. That is the whole capability set the lock
        asks about; the rest of P2's table arrives with the secret side."""
        return frozenset({CAS})

    def read(self, path: str) -> Stored | None:
        response = self.transport.request("GET", f"{self.mount}/data/{path}")
        if response.status == 404:
            return None
        _check(response, path=path)

        payload = _data(response)
        metadata = payload.get("metadata")
        if not isinstance(metadata, dict) or not isinstance(metadata.get("version"), int):
            # The version is the fencing token, so a response without one is not
            # something to paper over with a default -- a store that answered 200
            # to a read and could not say which version it read is a store this
            # tool cannot fence against.
            raise StoreError(
                f"the store answered a read of {path!r} without a version",
                hint="this is a KV v2 path, is it not? A v1 mount has no versions",
            )
        return Stored(data=payload.get("data"), version=metadata["version"])

    def write(self, path: str, data: Any, *, cas: int | None) -> int:
        body: dict[str, Any] = {"data": data}
        if cas is not None:
            body["options"] = {"cas": cas}
        response = self.transport.request("POST", f"{self.mount}/data/{path}", json=body)
        _check(response, path=path)

        version = _data(response).get("version")
        if not isinstance(version, int):
            raise StoreError(
                f"the store accepted a write to {path!r} without returning a version",
                hint="that version is this run's fence; there is nothing to hold without it",
            )
        return version

    def metadata(self, path: str) -> PathMetadata | None:
        response = self.transport.request("GET", f"{self.mount}/metadata/{path}")
        if response.status == 404:
            # Ordinary for a lock path before the first lock is taken, so not a
            # failure -- pre-flight reads it to ask whether `cas_required` is set,
            # and "the path has no metadata" is a perfectly good answer.
            return None
        _check(response, path=path)

        payload = _data(response)
        maximum = payload.get("max_versions")
        return PathMetadata(
            cas_required=bool(payload.get("cas_required")),
            max_versions=None if maximum in (None, UNLIMITED) else int(maximum),
        )


def _check(response: Response, *, path: str) -> None:
    if not response.ok:
        raise_for(response.status, response.body, path=path)


def _data(response: Response) -> dict[str, Any]:
    """Vault wraps every answer in an envelope; this is the useful half."""
    if isinstance(response.body, dict):
        payload = response.body.get("data")
        if isinstance(payload, dict):
            return payload
    return {}

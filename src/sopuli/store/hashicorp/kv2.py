"""KV v2 -- P2's reference implementation of the store interface.

The four methods of :mod:`sopuli.store.protocol` against Vault's KV v2 API:

======================== =====================================================
``read(path, version)``  ``GET  /v1/<mount>/data/<path>[?version=N]``
``write(path, …)``       ``POST /v1/<mount>/data/<path>`` with ``options.cas``
``metadata(path)``       ``GET  /v1/<mount>/metadata/<path>``
``list(prefix)``         ``LIST /v1/<mount>/metadata/<prefix>``, walked
``supports()``           ``{cas, list, versioning}``
======================== =====================================================

Three things the advisory lock depends on, and which are the reason this module
is worth reading rather than skimming. Each was checked against a real Vault.

**A 404 means "nothing to read" and nothing else.** A path that was never
written and a path whose latest version was *deleted* both answer 404 -- the
second with a body carrying the version it used to have. Both are ``None``
here, deliberately, because the difference is not knowable from a read in a way
a caller could act on: what distinguishes them is that a ``cas: 0`` write
succeeds against the first and can never succeed against the second. That is
why a lock is released by writing a ``released`` record instead of deleting
one -- a delete would leave a path no first acquisition could ever take again.

**The version comes back from the write.** Not from a read afterwards: that
would reopen the window the fence exists to close, since anything could write
between the two.

**A lost compare-and-set is a** :class:`~sopuli.store.protocol.CasConflictError`
**and nothing else** (:mod:`._errors`).

**Listing goes to the metadata endpoint, and that is not the same set of paths
the data endpoint holds**. Metadata outlives data in KV v2, so a
soft-deleted path is still listed and still reads as ``None``. The protocol says
so out loud rather than hiding it: for the case listing exists for -- a leftover
lock record -- "what is out there" is the question, and a caller that wants
contents reads and finds out.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sopuli.store.hashicorp._errors import raise_for
from sopuli.store.hashicorp._health import health as probe_health
from sopuli.store.hashicorp._listing import keys_of, walk
from sopuli.store.hashicorp._transport import Response, Transport
from sopuli.store.protocol import (
    CAS,
    LIST,
    MERGE_PATCH,
    VERSIONING,
    MetadataNotPermittedError,
    PatchNotPermittedError,
    PathMetadata,
    Stored,
    StoreError,
    StoreHealth,
)

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
        """Compare-and-set, listing, versions, and server-side merge patch.

        ``merge_patch`` is a capability of the *mount* and not of the token: the
        endpoint exists on every KV v2 mount, while whether this token may call
        it is a policy question no capability set can answer. That is why
        :meth:`patch` raises :class:`PatchNotPermittedError` rather than this
        method reporting less -- a store that dropped the capability because one
        token was unprivileged would be reporting the wrong subject.

        The rest of P2's table -- staging labels, soft delete -- still has no
        caller: ``staging_labels`` is emulated in the payload on this backend
        (Q7), so nothing negotiates it, and undelete has no command that asks.
        """
        return frozenset({CAS, LIST, MERGE_PATCH, VERSIONING})

    def health(self) -> StoreHealth:
        """Whether the Vault behind this mount is well, and what its clock says.

        Delegates whole, because the question is about the **server**: a
        ``sys/health`` answer says nothing about which mount asked, and an estate
        pointing two ``vaults:`` entries at one Vault gets the same seal state
        from both because it is the same seal.
        """
        return probe_health(self.transport)

    def read(self, path: str, *, version: int | None = None) -> Stored | None:
        params = None if version is None else {"version": str(version)}
        response = self.transport.request("GET", f"{self.mount}/data/{path}", params=params)
        if response.status == 404:
            # Also the answer for a version that was pruned, destroyed or never
            # written -- which the protocol reads as "there is nothing to read"
            # rather than as an error, for the same reason an empty path does.
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

    def patch(self, path: str, changes: Any, *, cas: int | None) -> int:
        """``PATCH /v1/<mount>/data/<path>``, as ``application/merge-patch+json``.

        The content type is what selects the operation -- the URL is the same one
        :meth:`write` posts to -- so without the header this is a request Vault
        declines to interpret rather than a merge patch it applies wrongly.

        Two answers are handled here rather than by :func:`._errors.raise_for`,
        and both because the *verb* carries information the status does not:

        **403** may mean the policy grants ``update`` and not ``patch``, which is
        an ordinary policy and not a failure. :class:`PatchNotPermittedError`
        says so and the caller falls back. **401 is not included**, and the
        asymmetry is the point: Vault answers 403 both for a token it will not
        accept and for one that may not do this, which is why the second reading
        is available at all — while 401 says only that the token is not valid,
        and no policy grants its way out of that. Reading it as a patch refusal
        would replace a precise message with a wasted round trip.

        **404** means there is nothing at the path to patch. Vault will not
        create a document by merge patch, which is right -- a patch describes a
        change to something -- so the first write to a path is a
        :meth:`write` and never this. The caller knows which it is doing from its
        ``cas``, so this raises rather than silently promoting itself to a write:
        a patch that turned into a create would be a patch that ignored the
        siblings it was written to protect, on the one path where there are none
        yet only because nobody has looked.
        """
        body: dict[str, Any] = {"data": changes}
        if cas is not None:
            body["options"] = {"cas": cas}
        response = self.transport.request(
            "PATCH",
            f"{self.mount}/data/{path}",
            json=body,
            headers={"Content-Type": "application/merge-patch+json"},
        )
        if response.status == 403:
            raise PatchNotPermittedError(
                f"the store refused a merge patch at {path!r}",
                hint=(
                    "a Vault policy grants `patch` separately from `update` -- add it, or "
                    "let the run read the document and write it back under a `cas`"
                ),
            )
        if response.status == 404:
            raise StoreError(
                f"there is nothing at {path!r} to merge a patch into",
                hint="the first write to a path creates it; a merge patch changes one that exists",
            )
        _check(response, path=path)

        version = _data(response).get("version")
        if not isinstance(version, int):
            raise StoreError(
                f"the store accepted a merge patch at {path!r} without returning a version",
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

    def require_cas(self, path: str) -> None:
        """``POST /v1/<mount>/metadata/<path>`` with ``cas_required: true``.

        The same endpoint :meth:`metadata` reads, written rather than read. Only
        ``cas_required`` is sent: a metadata write replaces the fields it names
        and leaves the rest, so naming ``max_versions`` here would push this
        store's opinion onto a housekeeping setting the lock deliberately does
        not enforce (:meth:`~sopuli.lock.manager.LockManager.preflight`).

        **403 is a policy, not a fault.** ``update`` on ``<mount>/metadata/<path>``
        is a separate capability from the ``create``/``update`` on
        ``<mount>/data/<path>`` that writing a record needs, so a policy written
        for secrets alone produces this on a token that then locks perfectly
        well. :class:`MetadataNotPermittedError` says so, and the lock degrades.
        The asymmetry with :meth:`patch` is deliberate and the same: **401 is not
        included**, because a token Vault will not accept is not a token some
        policy could have saved.
        """
        response = self.transport.request(
            "POST", f"{self.mount}/metadata/{path}", json={"cas_required": True}
        )
        if response.status == 403:
            raise MetadataNotPermittedError(
                f"the store refused to set `cas_required` on {path!r}",
                hint=(
                    "a Vault policy grants `update` on <mount>/metadata/<path> separately "
                    f"from the data path -- add it, or run `vault kv metadata put "
                    f"-cas-required=true {self.mount}/{path}` once"
                ),
            )
        _check(response, path=path)

    def list(self, prefix: str) -> tuple[str, ...]:
        """Every path under ``prefix``, walked out of KV's one-level listing.

        The recursion and the sorting are :mod:`._listing`'s; what is here is the
        endpoint and the shape of one level.
        """
        return walk(self._level, prefix)

    def _level(self, prefix: str) -> tuple[str, ...] | None:
        response = self.transport.request("LIST", f"{self.mount}/metadata/{prefix}")
        if response.status == 404:
            # A prefix with nothing under it, which is the ordinary state of the
            # lock prefix in a store nobody has locked anything in. Not a
            # failure, for the same reason `metadata`'s 404 is not one.
            return None
        _check(response, path=prefix)
        return keys_of(response, prefix=prefix)


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

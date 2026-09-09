"""KV v1 -- the same interface with the guarantees removed (#104, P2).

A different backend that happens to share an address, not an older version of
the one next door. It has no versioning, no compare-and-set and no soft delete,
and P2's rule is that a missing capability is emulated in the payload rather
than pretended into existence -- **except ``cas``, which cannot be emulated**,
because "not atomic" is precisely what it is for.

So this store reports no ``cas``, and what happens next is the config's
decision rather than this module's: under the default ``locking: required`` a
mutating command refuses on it, and under ``advisory-only`` the lock record is
written unguarded and every run says so (`SOPULI-W001`, #83, #94).

This is the first place "this store has no `cas`" is a fact about a real
backend rather than a constructor argument -- ``MemoryStore`` can be built
without the capability, but only here does the absence come from the store.

It **can** be listed, though (#150), and the pair is worth reading together:
capabilities are per capability, not a tier. A v1 mount having no compare-and-set
says nothing about whether its paths can be enumerated, and reporting an empty
set because the interesting one is missing would deny ``lock status`` a leftover
record it could perfectly well have found.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sopuli.store.hashicorp._errors import raise_for
from sopuli.store.hashicorp._health import health as probe_health
from sopuli.store.hashicorp._listing import keys_of, walk
from sopuli.store.hashicorp._transport import Response, Transport
from sopuli.store.protocol import LIST, PathMetadata, Stored, StoreError, StoreHealth

#: The version a store without versioning reports.
#:
#: **Not a fencing token, and nothing may treat it as one.** The lock never asks
#: it to be: :meth:`~sopuli.lock.manager.LockManager.acquire` keeps a fence only
#: when the store can fence, and the comparison at each boundary is skipped when
#: it cannot (#83). Zero rather than a fabricated counter, because a number that
#: looked like a version would be exactly the lie that makes a stolen lock
#: undetectable -- and because ``cas: 0`` already means "there must be nothing
#: here", which is the one reading that stays honest.
NO_VERSION = 0


@dataclass(frozen=True)
class Kv1Store:
    """One KV v1 mount, reached through one :class:`Transport`."""

    transport: Transport
    mount: str

    def supports(self) -> frozenset[str]:
        """``list`` and nothing else. No versioning, no compare-and-set, no soft
        delete -- but the mount does enumerate, so say so (see the module note)."""
        return frozenset({LIST})

    def health(self) -> StoreHealth:
        """Whether the Vault behind this mount is well, and what its clock says.

        Delegates whole, because the question is about the **server**: a
        ``sys/health`` answer says nothing about which mount asked, and an estate
        pointing two ``vaults:`` entries at one Vault gets the same seal state
        from both because it is the same seal.
        """
        return probe_health(self.transport)

    def read(self, path: str, *, version: int | None = None) -> Stored | None:
        """Read the one document there is, and refuse to fake an older one.

        A ``@version=N`` ref against a v1 mount is not a read that comes back
        empty -- it is a question this store cannot be asked, and answering it
        with the current document would be the same lie :meth:`write` refuses to
        tell about ``cas``: the caller pinned a version *because* it did not want
        whatever is current, and handing it the current one silently is a
        rotation reading the wrong generation.
        """
        if version is not None:
            raise StoreError(
                f"this store keeps no versions, and a read of {path!r} asked for version {version}",
                hint=(
                    "KV v1 has no version history: drop the `@version=` qualifier, or "
                    "`vault kv enable-versioning` on the mount"
                ),
            )
        response = self.transport.request("GET", f"{self.mount}/{path}")
        if response.status == 404:
            return None
        _check(response, path=path)

        body = response.body
        data = body.get("data") if isinstance(body, dict) else None
        return Stored(data=data, version=NO_VERSION)

    def write(self, path: str, data: Any, *, cas: int | None) -> int:
        """Write, and refuse to pretend a ``cas`` was honoured.

        A caller that passes one has asked for a guarantee this store cannot
        give. Sending the write anyway and returning a number would be the worst
        of the available answers: the caller would hold what it believes is a
        fence, and two runs could hold it at once. So the refusal is a
        :class:`~sopuli.store.protocol.StoreError` and it names the setting that
        makes the write legitimate.
        """
        if cas is not None:
            raise StoreError(
                f"this store has no compare-and-set, and the write to {path!r} asked for one",
                hint=(
                    "KV v1 has no versioning: `vault kv enable-versioning` on the mount, or "
                    "`locking: advisory-only` on the store to accept unguarded writes "
                    "knowingly (01-configuration.md §3a)"
                ),
            )
        # A v1 write answers 204 with no body at all, which is why nothing here
        # looks for a version to return.
        response = self.transport.request("POST", f"{self.mount}/{path}", json=data)
        _check(response, path=path)
        return NO_VERSION

    def patch(self, path: str, changes: Any, *, cas: int | None) -> int:
        """Always a refusal. A v1 mount has no merge-patch endpoint.

        Third in the same pattern as :meth:`read`'s version and :meth:`write`'s
        ``cas``, and the pattern is the point: this store declines what it cannot
        do rather than approximating it. The approximation here would be a
        read-modify-write done quietly inside the adapter, which is exactly the
        fallback :func:`sopuli.store.credentials.apply_patch` performs *visibly*
        -- and the run reports which mechanism it used (UC-1 §3), so hiding it
        one layer down would make the report a lie.
        """
        raise StoreError(
            f"this store cannot apply a merge patch, and a write to {path!r} asked it to",
            hint=(
                "KV v1 has no merge-patch endpoint: read the document, apply the patch "
                "locally, and write it back -- which is what this run falls back to"
            ),
        )

    def metadata(self, path: str) -> PathMetadata | None:
        """Always ``None``. There is no metadata endpoint on a v1 mount.

        Not an error, and the distinction matters at pre-flight: ``None`` means
        "this store knows nothing about the path apart from its contents", which
        is true. What the lock does about a store that cannot promise
        ``cas_required`` is the capability check above, not this.
        """
        return None

    def require_cas(self, path: str) -> None:
        """Always raises. A v1 mount has no metadata to set (#390).

        The mirror of :meth:`metadata` answering ``None``, and a raise rather
        than a silent no-op for the reason that method gives at greater length:
        "there is nothing to configure here" and "it is configured" are answers a
        caller must never confuse, and a no-op would let the lock report a
        guarantee this mount cannot make.

        **Nothing reaches it.** A v1 mount has no :data:`~sopuli.store.protocol.CAS`
        capability, so the lock has already refused it or been configured
        ``locking: advisory-only``, where there is no compare-and-set to require.
        """
        raise StoreError(
            f"a KV v1 mount cannot require a compare-and-set on {path!r}",
            hint=(
                "there is no metadata endpoint on a v1 mount, and no compare-and-set to "
                "require -- this store locks under `locking: advisory-only` or not at all"
            ),
        )

    def list(self, prefix: str) -> tuple[str, ...]:
        """Every path under ``prefix``. The same walk as v2, one endpoint shorter.

        There is no ``metadata/`` segment because there is no metadata -- which
        also means the answer here is exactly the readable set, since a v1 mount
        has no soft delete and so lists nothing a read would decline to return.
        """
        return walk(self._level, prefix)

    def _level(self, prefix: str) -> tuple[str, ...] | None:
        response = self.transport.request("LIST", f"{self.mount}/{prefix}")
        if response.status == 404:
            return None
        _check(response, path=prefix)
        return keys_of(response, prefix=prefix)


def _check(response: Response, *, path: str) -> None:
    if not response.ok:
        raise_for(response.status, response.body, path=path)

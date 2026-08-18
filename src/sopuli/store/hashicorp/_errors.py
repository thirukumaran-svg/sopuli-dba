"""Vault's HTTP answers as this project's exceptions (#104, ADR-005).

**One module, and never at a call site.** ADR-005 puts the mapping at the
transport boundary precisely so that "was this a lost race" is answered in one
place: a call site that pattern-matched on a message would be a second, worse
copy of the rules below, and the two would disagree the first time Vault
rewords something.

Every string here was measured against ``hashicorp/vault:2.0.4``, not read from
the documentation. The three that matter are all 400s and all mention the
check-and-set parameter:

======================================= ================================================
Vault says                              What it means
======================================= ================================================
``check-and-set parameter did not       the version moved -- a lost race, and the only
match the current version``             one of the three that is
``check-and-set parameter required      the path is ``cas_required`` and the write
for this call``                         carried no CAS
``error parsing check-and-set           the ``cas`` we sent was not a number
parameter``
======================================= ================================================

Which is why **the match is on the full phrase and not a prefix.** Matching
``check-and-set parameter`` would catch all three, turning a malformed request
and a missing-CAS refusal into "somebody beat me to it" -- and #83 asserts
``cas_required: true`` on the lock mount, so the second row is reachable by
design rather than hypothetically.

And why the rule is **fail closed**: anything unrecognised is a
:class:`~sopuli.store.protocol.StoreError`, never a conflict. Misclassifying a
real conflict costs one retry. Misclassifying a hard error as a lost race
retries into a wall.
"""

from __future__ import annotations

from typing import Any, NoReturn

from sopuli.store.protocol import CasConflictError, StoreError

#: The lost race, in full. Deliberately not the whole sentence Vault sends --
#: "the current version" carries no information and is the part most likely to
#: be reworded -- but long enough to exclude the other two 400s above.
#:
#: ``tests/store/test_hashicorp_cas_conflict.py`` asserts this against a real
#: Vault, which is what turns a dependency on somebody else's wording into
#: something that fails loudly on an upgrade rather than silently.
CAS_MESSAGE_FRAGMENT = "check-and-set parameter did not match"

#: A path configured ``cas_required`` and a write that carried no CAS. Not a
#: conflict: nothing raced, the caller simply did not guard the write.
CAS_REQUIRED_FRAGMENT = "check-and-set parameter required"


class StoreAuthError(StoreError):
    """The token was refused, or it lacks the policy for this path.

    ``authorization`` rather than ``vault``: what an operator does next is look
    at a policy or a token, not at the store. Vault answers 403 for both "this
    token is invalid" and "this token may not do that", and does not distinguish
    them in a way worth branching on -- its own message says which.
    """

    category = "authorization"


class StoreUnavailableError(StoreError):
    """Sealed, standby, or otherwise not answering requests right now.

    Kept apart from the general case because it is the one worth retrying, and
    because "the vault is sealed" is an answer an operator can act on in a way
    that "500" is not.
    """

    category = "connectivity"


def messages(body: Any) -> list[str]:
    """Vault's ``errors[]``, verbatim.

    Preserved rather than summarised (CLAUDE.md, Style: never swallow a vendor
    code -- map it, and keep the server's own message). An empty list is normal:
    a 404 for a path that was never written carries ``errors: []``, which is
    Vault saying "nothing here" rather than declining to explain itself.
    """
    if isinstance(body, dict):
        found = body.get("errors")
        if isinstance(found, list):
            return [str(item) for item in found]
    return []


def raise_for(status: int, body: Any, *, path: str) -> NoReturn:
    """Turn a non-2xx answer into the right exception. Never returns.

    Callers handle 404 themselves before reaching here: for ``read`` it is
    ``None`` rather than a failure, and telling "never written" from "deleted"
    is not this module's job -- both are 404, which is the ambiguity
    :meth:`~sopuli.store.protocol.SecretStore.read` documents and the write is
    what resolves.
    """
    detail = " | ".join(messages(body))
    said = f": {detail}" if detail else ""

    if status == 400 and CAS_MESSAGE_FRAGMENT in detail:
        raise CasConflictError(f"compare-and-set failed at {path!r}{said}")
    if status == 400 and CAS_REQUIRED_FRAGMENT in detail:
        raise StoreError(
            f"{path!r} requires a compare-and-set and the write did not carry one{said}",
            hint=(
                "the path is configured `cas_required`, which is what stops anyone -- a "
                "vault CLI, a script -- clobbering it without a version. This tool always "
                "sends one, so an unguarded write here came from `locking: advisory-only`"
            ),
        )
    if status in (401, 403):
        raise StoreAuthError(
            f"the store refused this token at {path!r}{said}",
            hint="check the token's policy for this path, and that it has not expired",
        )
    if status == 503:
        raise StoreUnavailableError(
            f"the store is sealed or unavailable{said}",
            hint="`vault status` says which; a sealed store answers 503 to everything",
        )
    if status in (429, 472, 473):
        raise StoreUnavailableError(
            f"the store is a standby and will not serve this request{said}",
            hint="point `addr` at the active node, or at a load balancer that does",
        )
    # Fail closed. An unrecognised 400 is not a lost race, and neither is
    # anything else that lands here -- if this raised CasConflictError as a
    # catch-all, a run would report a race that never happened and retry into
    # whatever actually went wrong.
    raise StoreError(f"the store answered HTTP {status} at {path!r}{said}")

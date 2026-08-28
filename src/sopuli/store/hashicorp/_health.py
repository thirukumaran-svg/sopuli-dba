"""Is this Vault there, can it serve, and what does its clock say (#216).

One module for both mounts, because ``sys/health`` is a property of the
**server** and not of a KV mount: two ``vaults:`` entries pointing at one Vault
with different mounts are one process to ask about, and two copies of this would
be two readings of the same seal state.

Why the clock is here at all, rather than as a general health nicety:
`sopuli/lock/` compares a lease's ``expires_at`` against *this* machine's clock
and allows :data:`~sopuli.lock.record.CLOCK_SKEW` for the two disagreeing (#83).
A host minutes out will take over locks that are still live or refuse ones long
dead, and the failure presents as a locking bug rather than as an NTP problem.
So this measures the assumption rather than observing a curiosity.

**The body decides the verdict, not the status code.** Vault's ``sys/health``
lets a caller remap every one of its statuses with query parameters, and a load
balancer in front of it may rewrite them without being asked -- so the status
code is the least reliable thing in the response. ``sealed`` and ``initialized``
are booleans Vault sends in the payload and are the facts themselves. The status
code is the fallback for a reply with no usable body, and an unrecognised one
then reads as :data:`~sopuli.store.protocol.UNREACHABLE` on :mod:`._errors`'
fail-closed rule: an answer this build cannot interpret is not evidence that a
store is well, which is exactly what a proxy's 502 would otherwise become.

**Nothing here writes.** P5 makes `doctor` mutate nothing, and a reachability
check that proved itself by leaving a lease behind would be a measurement that
changes what it measures -- on a lock mount, one a concurrent rotation notices.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sopuli.clock import utc_now
from sopuli.store.hashicorp._transport import Transport
from sopuli.store.protocol import DEGRADED, OK, UNREACHABLE, StoreError, StoreHealth

#: Vault's own health endpoint. Takes no token, which is why the seal state and
#: the clock are readable even from a run whose credential is refused -- and why
#: :func:`health` asks a second question before reporting ``ok``.
HEALTH = "sys/health"

#: What a token is checked against. The cheapest authenticated call there is,
#: and the only one guaranteed to be permitted: every token may look itself up,
#: whatever its policy, so a refusal here is a bad token rather than a narrow one.
LOOKUP_SELF = "auth/token/lookup-self"

#: **Not** ``clock_skew_ms``, which the same payload carries and which is not
#: this measurement. Vault reports there how far a *cluster node* is from its
#: peers -- an answer about Vault's own members that is 0 on a single node
#: however wrong that node's clock is, and which says nothing about the host
#: running this tool. The field looks like the answer and is a different
#: question, so the reading here stays ``server_time_utc`` minus this host's own
#: clock. Measured against ``hashicorp/vault:2.0.4``, which reports both.
#:
#: ``server_time_utc`` is epoch **seconds**, so any reading finer than this is
#: rounding rather than measurement. Carried onto every
#: :class:`~sopuli.store.protocol.StoreHealth` this module builds, so the skew
#: comparison widens its band by it instead of reporting invented precision.
RESOLUTION = timedelta(seconds=1)

#: What each status code means when there is no body to read it from. Vault's
#: documented set, and the same one ``tests/conftest.py`` already treats as "a
#: Vault answered".
_BY_STATUS: dict[int, tuple[str, str | None]] = {
    200: (OK, None),
    429: (DEGRADED, "standby"),
    472: (DEGRADED, "disaster recovery secondary"),
    473: (DEGRADED, "performance standby"),
    501: (DEGRADED, "not initialised"),
    503: (DEGRADED, "sealed"),
}


def health(transport: Transport, *, now: Callable[[], datetime] = utc_now) -> StoreHealth:
    """Ask one Vault how it is, and never raise because it is not.

    Two requests and not one, and the second is the point. ``sys/health`` takes
    no token, so a store whose credential has expired answers it perfectly --
    ``tests/conftest.py`` already says so about the fixture, where a bad
    ``VAULT_TOKEN`` survives the health probe and fails the first real test with
    a 403 instead. A report calling that store ``ok`` would be the wallet problem
    one layer up: a green line beside a run that cannot do anything.

    So the token is looked up too, and only where that question is answerable: a
    sealed or uninitialised Vault refuses every request including this one, and
    reporting ``authenticated: false`` there would blame a token for a seal.

    ``now`` is injected for the reason everything else in this project injects a
    clock, and matters more here: it is read **twice**, either side of the
    request, and the midpoint of the two is what the skew is measured against.
    """
    sent = now()
    try:
        response = transport.request("GET", HEALTH)
    except StoreError as error:
        # The one place a StoreError is data rather than a failure. `doctor`
        # surveys an estate, and a vault that is not there is the finding it went
        # looking for -- so the transport's own message, which already names the
        # timeout or the TLS failure, becomes the detail rather than ending the
        # run.
        return StoreHealth(status=UNREACHABLE, detail=error.message)
    received = now()

    status, detail = _verdict(response.status, response.body)
    authenticated = None
    if status in (OK, DEGRADED) and _serving(response.body, response.status):
        authenticated = _authenticated(transport)
        if authenticated is False:
            # Reachable, and useless to this run. `degraded` rather than a new
            # word: what a reader does next is go and look at a token, which is
            # the same move a seal or a standby asks for -- at the vault, not at
            # the network.
            status = DEGRADED
            detail = "the credential this store was opened with was refused"

    return StoreHealth(
        status=status,
        version=_text(response.body, "version"),
        detail=detail,
        server_time=_server_time(response.body),
        time_resolution=RESOLUTION,
        # The midpoint, which is the best single estimate of when the far end
        # read its own clock: the answer was formed somewhere inside the round
        # trip. See `sopuli.clock.measure_skew`.
        measured_at=sent + (received - sent) / 2,
        round_trip=received - sent,
        authenticated=authenticated,
    )


def _verdict(status: int, body: object) -> tuple[str, str | None]:
    """What the store is, preferring what it said over what it was labelled.

    Body first, on the argument in the module note: the status codes are
    remappable by query parameter and rewritable by anything in the path, while
    ``sealed`` and ``initialized`` are the facts. A body carrying neither is not
    a Vault health response whatever the code said, so the fallback table runs
    only when there is nothing to read.
    """
    if isinstance(body, dict):
        sealed = body.get("sealed")
        initialised = body.get("initialized")
        if isinstance(sealed, bool) and isinstance(initialised, bool):
            if not initialised:
                return DEGRADED, "not initialised"
            if sealed:
                return DEGRADED, "sealed"
            if body.get("performance_standby") is True:
                return DEGRADED, "performance standby"
            if body.get("standby") is True:
                return DEGRADED, "standby"
            return OK, None

    known = _BY_STATUS.get(status)
    if known is not None:
        return known
    return UNREACHABLE, f"answered HTTP {status}, which is not a Vault health response"


def _serving(body: object, status: int) -> bool:
    """Whether a *second*, authenticated request has any chance of being answered.

    Not the same question as :func:`_verdict`, which is why it is its own
    function: a performance standby is ``degraded`` and will happily look a token
    up, while a sealed Vault is ``degraded`` and will refuse. Asking anyway would
    turn a seal into a report about a credential.
    """
    if isinstance(body, dict) and isinstance(body.get("sealed"), bool):
        return not body["sealed"] and body.get("initialized") is True
    return status not in (501, 503)


def _authenticated(transport: Transport) -> bool | None:
    """Whether this store's credential is still good.

    ``None`` for anything that is neither a clean acceptance nor a clean
    refusal. A 500 from the token backend says nothing about the token, and
    reporting ``False`` for it would send somebody to re-issue a credential that
    was never the problem -- the same fail-closed reading :mod:`._errors` applies
    to an unrecognised 400.
    """
    try:
        response = transport.request("GET", LOOKUP_SELF)
    except StoreError:
        return None
    if response.ok:
        return True
    if response.status in (400, 403):
        # 403 is a refused or expired token. 400 is what Vault answers when no
        # token was sent at all, which a `method: token` store with an empty
        # credential reaches -- a different cause and the same finding.
        return False
    return None


def _server_time(body: object) -> datetime | None:
    """Vault's own clock, or ``None`` if this answer did not carry one.

    ``None`` and never a substitute. The obvious fallback -- this host's clock --
    is the very thing being measured, and a caller handed it would compute a skew
    of zero and print it as evidence that the clocks agree.
    """
    if not isinstance(body, dict):
        return None
    seconds = body.get("server_time_utc")
    # `bool` is an `int`, and `True` would otherwise read as the epoch plus one
    # second -- a 1970 clock, reported as a fifty-six-year skew.
    if not isinstance(seconds, int) or isinstance(seconds, bool):
        return None
    return datetime.fromtimestamp(seconds, tz=UTC)


def _text(body: object, key: str) -> str | None:
    if not isinstance(body, dict):
        return None
    value = body.get(key)
    return value if isinstance(value, str) else None

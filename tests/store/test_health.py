"""What a Vault's `sys/health` answer means, without a Vault (#216).

Tier 0. Every case here is a reading the adapter makes of a body it has already
received, so none of it needs a container -- and the readings are exactly where a
live test is weakest, because a healthy container only ever produces one of them.
A sealed Vault, a standby, and a token that has expired are all conditions this
suite can construct on a laptop and could otherwise only wait for.

Two of these are load-bearing rather than defensive:

* **the body outranks the status code.** Vault lets a caller remap every status
  `sys/health` returns, and anything in the network path can rewrite them
  unasked. A reader that trusted the code would call a sealed Vault healthy the
  first time somebody put it behind a load balancer that normalises 503 to 200.
* **`sys/health` takes no token**, so a store whose credential has expired
  answers it perfectly. `tests/conftest.py` already records this about the
  fixture. Reporting that store `ok` would be a green line beside a run that
  cannot read anything.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

# Tier 0 by tier, not by install shape: the subject imports the transport type,
# which lives beside `httpx`. A skip rather than a collection error keeps the
# rest of the suite running on a base+dev install (`04-testing.md` §3).
pytest.importorskip("httpx", reason="the hashicorp extra is not installed")

import httpx  # noqa: E402

from sopuli.clock import utc_now  # noqa: E402
from sopuli.config.model import Vault  # noqa: E402
from sopuli.lock.record import CLOCK_SKEW  # noqa: E402
from sopuli.secrets import Secret  # noqa: E402
from sopuli.store.hashicorp._health import (  # noqa: E402
    HEALTH,
    LOOKUP_SELF,
    RESOLUTION,
    health,
)
from sopuli.store.hashicorp._transport import Transport, build_transport  # noqa: E402
from sopuli.store.protocol import DEGRADED, OK, UNREACHABLE  # noqa: E402

#: A moment with no sub-second part, because that is what an epoch-seconds
#: field can express and a fixture that could not round-trip would be testing
#: the fixture.
NOW = datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC)


def body(**overrides: object) -> dict[str, object]:
    """An unsealed, initialised, active Vault -- what `sys/health` answers at 200.

    Only the keys this module reads, plus `version`, which it reports. The real
    payload carries a dozen replication fields that nothing here looks at, and
    copying them in would suggest they were part of the contract.
    """
    payload: dict[str, object] = {
        "initialized": True,
        "sealed": False,
        "standby": False,
        "performance_standby": False,
        "server_time_utc": int(NOW.timestamp()),
        "version": "1.20.4",
    }
    payload.update(overrides)
    return payload


@dataclass
class Recorder:
    """What was asked of the store, and how.

    Paths **and** methods, because two different claims are made about them:
    several cases turn on whether the token lookup happened at all -- "did not
    ask" has to be distinguishable from "asked and was refused" -- and one turns
    on nothing here being a write.
    """

    paths: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)


def transport_for(
    recorder: Recorder | None = None,
    *,
    probe: httpx.Response | Exception | None = None,
    lookup: httpx.Response | Exception | None = None,
) -> Transport:
    """A real :class:`Transport` over canned answers.

    ``httpx.MockTransport`` rather than a hand-written stand-in, which earns its
    extra lines: the subject then runs through the *real* request path -- the
    timeout and transport-error mapping, the SNI extension, and ``_decode``'s
    handling of a body that is not JSON -- so a change to any of those is caught
    here rather than passing tier 0 and failing against a container. A double
    satisfying :meth:`Transport.request` by shape would have exercised none of
    it, and an unreachable store in particular would have been asserted against
    an exception this test raised itself.
    """
    seen = recorder if recorder is not None else Recorder()

    def handle(request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/v1/")
        seen.paths.append(path)
        seen.methods.append(request.method)
        answer = {HEALTH: probe, LOOKUP_SELF: lookup}.get(path)
        if isinstance(answer, Exception):
            raise answer
        if answer is not None:
            return answer
        if path == HEALTH:
            return httpx.Response(200, json=body())
        return httpx.Response(200, json={"data": {}})

    return Transport(
        httpx.Client(base_url="https://vault.example.com", transport=httpx.MockTransport(handle))
    )


def ticking(*, step: timedelta = timedelta(0)) -> Callable[[], datetime]:
    """A clock that advances by ``step`` on every reading.

    `health` reads it twice, either side of the request, so this is how a round
    trip of a known width is produced without one second of real waiting.
    """
    moments = iter(NOW + step * index for index in range(100))
    return lambda: next(moments)


# ---------------------------------------------------------------- verdicts ---


def test_an_unsealed_active_vault_is_ok() -> None:
    report = health(transport_for(), now=ticking())

    assert report.status == OK
    assert report.authenticated is True


def test_a_sealed_vault_is_degraded_and_says_so() -> None:
    """Degraded rather than unreachable, which is the distinction worth having.

    Something answered. What the reader does next is unseal a vault, not chase a
    network -- and being sent to the wrong one of those costs an outage's worth
    of time.
    """
    transport = transport_for(probe=httpx.Response(503, json=body(sealed=True)))

    report = health(transport, now=ticking())

    assert report.status == DEGRADED
    assert report.detail is not None
    assert "sealed" in report.detail


def test_a_standby_is_degraded() -> None:
    transport = transport_for(probe=httpx.Response(429, json=body(standby=True)))

    assert health(transport, now=ticking()).status == DEGRADED


def test_a_performance_standby_is_named_as_one() -> None:
    """Reported apart from an ordinary standby, because they behave differently.

    A performance standby serves reads; an ordinary standby forwards. A reader
    deciding whether this run can do anything needs to know which.
    """
    transport = transport_for(
        probe=httpx.Response(473, json=body(standby=True, performance_standby=True))
    )

    report = health(transport, now=ticking())

    assert report.detail is not None
    assert "performance standby" in report.detail


def test_an_uninitialised_vault_is_degraded() -> None:
    transport = transport_for(probe=httpx.Response(501, json=body(initialized=False)))

    report = health(transport, now=ticking())

    assert report.status == DEGRADED
    assert report.detail is not None
    assert "not initialised" in report.detail


def test_the_body_outranks_a_rewritten_status_code() -> None:
    """The reason the mapping reads the payload first.

    `sys/health` accepts query parameters that remap every status it returns, and
    a load balancer may normalise them without being asked. A sealed Vault behind
    one answers 200 with `sealed: true`, and a reader trusting the code would
    call it healthy -- which is the single most expensive wrong answer this
    module can give.
    """
    transport = transport_for(probe=httpx.Response(200, json=body(sealed=True)))

    assert health(transport, now=ticking()).status == DEGRADED


def test_a_reply_that_is_not_a_health_response_is_unreachable() -> None:
    """Fail closed, the rule `_errors.py` already applies to an unrecognised 400.

    A 502 from a gateway is not a Vault saying anything about itself. Reading it
    as `degraded` would report a store as present because something on its
    address answered, which is precisely the mistake that makes a survey
    worthless.
    """
    transport = transport_for(probe=httpx.Response(502, text="<html>Bad Gateway</html>"))

    report = health(transport, now=ticking())

    assert report.status == UNREACHABLE
    assert report.detail is not None
    assert "502" in report.detail


def test_an_unreachable_store_is_an_answer_and_not_an_exception() -> None:
    """The one place a `StoreError` is data.

    Every other call on the interface treats "could not reach it" as a failure,
    because every other caller wanted something done. This one was asked in order
    to find out, and `doctor` surveys a whole estate -- so one dead vault must
    not end the run before the next is tried.
    """
    transport = transport_for(probe=httpx.ConnectError("connection refused"))

    report = health(transport, now=ticking())

    assert report.status == UNREACHABLE
    assert report.detail is not None
    assert "connection refused" in report.detail
    # The transport's own message survives, hint and all -- never re-worded here
    # (CLAUDE.md, Style: never swallow the server's own message).
    assert report.server_time is None


def test_an_unreachable_store_is_never_asked_for_a_token() -> None:
    seen = Recorder()

    health(transport_for(seen, probe=httpx.ConnectError("connection refused")), now=ticking())

    assert LOOKUP_SELF not in seen.paths


# ------------------------------------------------------------ the credential ---


def test_a_refused_token_is_degraded_rather_than_ok() -> None:
    """The gap `sys/health` alone cannot see.

    It takes no token, so a store whose credential expired last night answers it
    exactly as a healthy one does. Reporting `ok` there is a green line beside a
    run that will fail on its first read.
    """
    transport = transport_for(lookup=httpx.Response(403, json={"errors": ["permission denied"]}))

    report = health(transport, now=ticking())

    assert report.status == DEGRADED
    assert report.authenticated is False


def test_a_sealed_vault_is_not_asked_about_its_token() -> None:
    """Because it would refuse, and the refusal would be blamed on the token.

    A seal is not a credential problem, and a report saying `authenticated:
    false` beside it sends somebody to re-issue a token that was never wrong.
    """
    seen = Recorder()

    report = health(
        transport_for(seen, probe=httpx.Response(503, json=body(sealed=True))), now=ticking()
    )

    assert LOOKUP_SELF not in seen.paths
    assert report.authenticated is None


def test_a_performance_standby_is_still_asked_about_its_token() -> None:
    """Degraded and serving are different questions, which is why they are two.

    A performance standby answers reads, so the token question is answerable and
    worth answering -- an estate running against one wants to know its credential
    is good just as much as one against an active node.
    """
    seen = Recorder()

    report = health(
        transport_for(
            seen, probe=httpx.Response(473, json=body(standby=True, performance_standby=True))
        ),
        now=ticking(),
    )

    assert LOOKUP_SELF in seen.paths
    assert report.authenticated is True


def test_a_server_error_on_the_lookup_says_nothing_about_the_token() -> None:
    """`None` and not `False`, on the same fail-closed reading as everything else.

    A 500 from the token backend is not evidence that a credential is bad, and
    reporting it as one sends somebody to re-issue something that was fine.
    """
    transport = transport_for(lookup=httpx.Response(500, json={"errors": ["oh dear"]}))

    report = health(transport, now=ticking())

    assert report.authenticated is None
    assert report.status == OK


# ------------------------------------------------------------------ the clock ---


def test_the_server_clock_comes_back_as_an_aware_utc_moment() -> None:
    report = health(transport_for(), now=ticking())

    assert report.server_time == NOW
    assert report.server_time is not None
    assert report.server_time.tzinfo is not None


def test_the_reported_resolution_is_the_one_epoch_seconds_can_express() -> None:
    """Carried so the skew comparison widens its band rather than inventing precision."""
    report = health(transport_for(), now=ticking())

    assert report.time_resolution == RESOLUTION == timedelta(seconds=1)


def test_a_body_without_a_server_time_reports_none_rather_than_this_host_s() -> None:
    """The substitution that would make the whole measurement a lie.

    This host's clock is the thing under test. A caller handed it as the server's
    would compute a skew of exactly zero and print it as evidence that the two
    agree.
    """
    payload = body()
    del payload["server_time_utc"]
    transport = transport_for(probe=httpx.Response(200, json=payload))

    report = health(transport, now=ticking())

    assert report.server_time is None
    assert report.skew(CLOCK_SKEW) is None


def test_a_boolean_where_a_timestamp_belongs_is_not_a_1970_clock() -> None:
    """`True` is an `int` in Python, and would read as the epoch plus one second.

    Which would be reported, straight-faced, as a fifty-six-year skew.
    """
    transport = transport_for(probe=httpx.Response(200, json=body(server_time_utc=True)))

    assert health(transport, now=ticking()).server_time is None


def test_the_measurement_is_taken_at_the_midpoint_of_the_request() -> None:
    """Not before it and not after it, which is a two-second error either way here.

    The far end read its clock somewhere inside the round trip. The midpoint is
    the point no further than half the trip from wherever that was, which is what
    makes `uncertain_by` an exact width rather than a fudge factor.
    """
    report = health(transport_for(), now=ticking(step=timedelta(seconds=4)))

    assert report.round_trip == timedelta(seconds=4)
    assert report.measured_at == NOW + timedelta(seconds=2)


def test_a_round_trip_wide_enough_to_explain_the_difference_is_not_a_finding() -> None:
    """End to end, on a body whose clock genuinely differs from this host's.

    The store is two minutes ahead and the request took five, so nothing about
    the difference is unaccounted for. A report that warned here would be one
    nobody believes the next time.
    """
    transport = transport_for(
        probe=httpx.Response(
            200, json=body(server_time_utc=int((NOW + timedelta(minutes=2)).timestamp()))
        )
    )

    report = health(transport, now=ticking(step=timedelta(minutes=5)))
    skew = report.skew(CLOCK_SKEW)

    assert skew is not None
    assert not skew.beyond_tolerance


def test_a_local_clock_five_minutes_out_is_a_finding() -> None:
    """The case the whole section exists for, with the host half injected.

    `skew(local=...)` is what lets this be asserted against a *real* server
    reading in tier 1 as well: a container sharing the runner's clock always
    reports zero, and a comparison only ever exercised against zero is one that
    passes while broken.
    """
    report = health(transport_for(), now=ticking())

    skew = report.skew(CLOCK_SKEW, local=NOW + timedelta(minutes=5))

    assert skew is not None
    assert skew.delta == timedelta(minutes=-5)
    assert skew.beyond_tolerance


def test_a_clock_that_agrees_is_within_tolerance() -> None:
    report = health(transport_for(), now=ticking())

    skew = report.skew(CLOCK_SKEW)

    assert skew is not None
    assert not skew.beyond_tolerance


def test_nothing_here_writes() -> None:
    """P5: `doctor` mutates nothing, and this is its only store call.

    Asserted on the *methods* rather than on the paths, because the failure this
    guards against is somebody proving reachability by leaving a lease behind --
    which on a lock mount is a write a concurrent rotation notices.
    """
    seen = Recorder()

    health(transport_for(seen), now=ticking())

    assert set(seen.methods) == {"GET"}


def test_the_default_clock_is_this_host_s() -> None:
    """The injection is for tests; the production reading is `utc_now`."""
    before = utc_now()

    report = health(transport_for())

    assert report.measured_at is not None
    assert before <= report.measured_at <= utc_now()


def test_a_real_transport_against_a_dead_address_reports_unreachable() -> None:
    """The one case a canned answer cannot make: the chain, end to end.

    Every test above hands `health` a `StoreError` and checks what it does with
    one. None of them establishes that a store nobody is listening on actually
    *produces* one -- which is the whole path `doctor` will rest its exit code
    on, and the one that breaks silently if `httpx` ever raises something the
    transport does not catch.

    Tier 0 regardless: port 1 on loopback needs no container and refuses in
    microseconds. Nothing is written and nothing is reachable, which is the
    point.
    """
    transport = build_transport(
        Vault(name="vault-dev", type="hashicorp", addr="http://127.0.0.1:1", timeout_s=2),
        token=Secret("unused-because-nothing-answers"),
    )
    try:
        report = health(transport)
    finally:
        transport.close()

    assert report.status == UNREACHABLE
    assert report.server_time is None
    assert report.authenticated is None


def test_the_store_version_is_its_own_field_and_not_prose() -> None:
    """A consumer reads it as a value, so it must not be recoverable only by parsing.

    It rode inside `detail` in the first version of this module, which read fine
    and would have broken the first time the sentence around it was reworded --
    exactly the line `03-json-output.md` §8 draws between a contract and the
    wording near it.
    """
    report = health(transport_for(), now=ticking())

    assert report.version == "1.20.4"
    assert report.detail is None


def test_a_degraded_store_reports_its_version_too() -> None:
    """The version does not depend on the verdict: a sealed Vault still says what it is.

    Which is the case an operator most wants it in -- "sealed" plus a version is
    a release note to go and read, and "sealed" alone is a shrug.
    """
    report = health(transport_for(probe=httpx.Response(503, json=body(sealed=True))), now=ticking())

    assert report.version == "1.20.4"
    assert report.detail == "sealed"

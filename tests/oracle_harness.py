"""Capability probing for the tier-1 suite (`04-testing.md` §3).

`test/capabilities.py` sketched this and was never run. This is the version that
runs, and the difference that matters is not the code — it is which list the
probes are keyed on.

**The harness no longer owns the questions; it imports them** (#177, #195). The
sketch kept its own list and the first version of this file kept a second copy of
the driver's, which is one probe with a spare place to disagree. It disagreed:
`container_scope` and `common_users` shared a question that was invalid on every
release, and because the harness answered it from its own copy there was nothing
to compare against. §3's claim only holds while the two ask the same thing:

    The test suite validates the capability model itself. If a driver claims
    `password_rollover` on 18c XE, the rollover test runs and fails there —
    which is the bug. Version-keyed skips would have hidden it.

So :data:`PROBES`, :data:`STRUCTURAL` and :func:`probe` now belong to
:mod:`sopuli.driver.oracle.capabilities`, and are re-exported here because that
is where the fixtures reach for them. P1's vocabulary is asserted against them in
`tests/driver/test_capabilities.py`. What remains the harness's own work is which
environment, what to skip, and how to report it.

**Nothing here imports ``oracledb``.** The pure parts — what to ask, how to read
an answer, what to skip, how to report — are testable in tier 0, and only the
fixture in `conftest.py` opens a socket.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from sopuli.driver.oracle.capabilities import PROBES, STRUCTURAL, probe
from sopuli.driver.protocol import CAPABILITIES

#: Re-exported deliberately. The questions belong to the driver (#177, #195) and
#: the fixtures reach for them here, so this names the intent rather than leaving
#: three imports that look unused.
__all__ = [
    "PROBES",
    "STRUCTURAL",
    "Environment",
    "below",
    "decide_skip",
    "dsn_host",
    "probe",
    "render_matrix",
]


@dataclass
class Environment:
    """One database the suite can run against, and what it turned out to be.

    ``unreachable_reason`` is a string rather than an exception because it is
    printed, not raised: a missing environment is a coverage gap to report, not
    a failure to debug. §1's rule is that everything version-specific skips with
    a reason rather than failing, or a contributor cannot go green on their own
    machine.
    """

    name: str
    dsn: str
    version: str | None = None
    capabilities: set[str] = field(default_factory=set)
    unreachable_reason: str | None = None

    @property
    def available(self) -> bool:
        return self.unreachable_reason is None

    @property
    def max_password_bytes(self) -> int:
        """30 bytes below 23, 128 from 23 (#595).

        Read off the version rather than probed, because there is no dictionary
        view that states it -- and it is the one number a tier-1 test needs in
        order to build a statement at all (#171 makes the limit a required
        argument).
        """
        return 30 if below(self.version, (23, 0)) else 128


def below(version: str | None, floor: tuple[int, int]) -> bool:
    """Whether ``version`` is older than ``floor``.

    Version comparison in the *harness* is not a violation of invariant 3. The
    rule is that the **tool** must never branch on a version, and it does not:
    it asks the database. This asks so that a test can know what the answer
    ought to be, which is the whole point of a harness that validates the
    capability model rather than trusting it.
    """
    if not version:
        return False
    parts = version.split(".")
    try:
        return (int(parts[0]), int(parts[1])) < floor
    except (IndexError, ValueError):
        return False


def dsn_host(dsn: str) -> str:
    """The host out of an Oracle DSN, in any of the shapes one is written in.

    Easy Connect is `host:port/service`, and the `//` prefix and a `tcps://`
    scheme are both ordinary -- `//localhost:1521/FREEPDB1` is what most
    documentation shows. Taking everything before the first `/` gets that one
    exactly backwards and returns nothing at all, which reads as *not loopback*
    and skips the tier-1 suite on the machine most likely to have it running.

    A bracketed IPv6 host keeps its brackets, since the port is split off the
    right: `[::1]:1521/X` -> `[::1]`.

    A TNS alias has no host, so it comes back as itself and is treated as
    remote. That is the conservative reading and the right one: an alias
    resolves through `TNS_ADMIN` to somewhere this function cannot see.
    """
    remainder = dsn.split("://", 1)[-1].lstrip("/")
    return remainder.split("/")[0].rsplit(":", 1)[0]


def decide_skip(
    environment: Environment | None,
    *,
    required: Iterable[str] = (),
    forbidden: Iterable[str] = (),
) -> str | None:
    """Why this test cannot run here, or ``None`` to run it.

    Two kinds of skip, and §3 is emphatic that they are not the same finding:
    a **capability** skip is correct and expected, while a **missing
    environment** is a coverage gap. The wording differs so the counts can be
    kept apart in the summary, and the reason always names what was missing.
    """
    if environment is None or not environment.available:
        reason = environment.unreachable_reason if environment else "no environment configured"
        return f"environment unavailable: {reason}"

    missing = sorted(set(required) - environment.capabilities)
    if missing:
        return f"capability absent: {', '.join(missing)}"

    present = sorted(set(forbidden) & environment.capabilities)
    if present:
        return f"capability present, and this test needs it absent: {', '.join(present)}"

    return None


def render_matrix(
    environments: Sequence[Environment],
    *,
    capability_skips: int = 0,
    environment_skips: int = 0,
) -> str:
    """§3's report: what was actually exercised, so "green" is never ambiguous.

    Takes a sequence because the matrix is a matrix — 23ai Free, 21c XE, 18c XE,
    11g XE, OCI 19c across the top — even though today's harness configures one
    environment at a time. Extending it is then data rather than code, which is
    §3's claim that a new environment costs nothing.

    **ASCII, not the check marks the document draws with.** P4's cp1252 story is
    about exactly this: a redirected stream on Windows takes the locale codepage,
    and a box-drawing character kills the writer mid-line. A test report that
    cannot survive being piped into a log is not much of a report.
    """
    if not environments:
        return "capabilities exercised: no environment was configured"

    width = max(len(name) for name in CAPABILITIES) + 2
    columns = [environment.name for environment in environments]
    lines = ["capabilities exercised", " " * width + "  ".join(columns)]

    for capability in sorted(CAPABILITIES):
        marks = []
        for environment in environments:
            if not environment.available:
                marks.append("?".center(len(environment.name)))
            elif capability in environment.capabilities:
                marks.append("ok".center(len(environment.name)))
            else:
                marks.append("--".center(len(environment.name)))
        lines.append(capability.ljust(width) + "  ".join(marks))

    for environment in environments:
        if not environment.available:
            lines.append(f"  {environment.name}: {environment.unreachable_reason}")

    lines.append(
        f"{capability_skips} tests skipped (capability absent), "
        f"{environment_skips} skipped (environment unavailable)"
    )
    return "\n".join(lines)

"""Capability probing for the tier-1 suite (`04-testing.md` §3).

`test/capabilities.py` sketched this and was never run. This is the version that
runs, and the difference that matters is not the code — it is which list the
probes are keyed on.

**The probes cover P1's capability vocabulary, not an ad-hoc list.** The sketch
asked about `oracle_maintained_flag`, `unified_audit` and `schema_privileges`,
none of which is a capability any driver reports; it had no probe for three that
are. A harness keyed on its own list can never do the job §3 claims for it:

    The test suite validates the capability model itself. If a driver claims
    `password_rollover` on 18c XE, the rollover test runs and fails there —
    which is the bug. Version-keyed skips would have hidden it.

That only holds if the harness and the driver are answering the same question,
so :data:`PROBES` and :data:`STRUCTURAL` are asserted against
:data:`~sopuli.driver.protocol.CAPABILITIES` and a new capability has to choose a
side deliberately.

**Not everything is a query, and pretending otherwise would be worse.** Two
capabilities are properties of the product rather than of the instance: every
supported Oracle can expire a password and can lock an account. Writing
`select 1 from dual` for those would look like a probe and measure nothing —
worse than saying so, because a reader would believe it. They live in
:data:`STRUCTURAL` with the reason attached.

**Nothing here imports ``oracledb``.** The pure parts — what to ask, how to read
an answer, what to skip, how to report — are testable in tier 0, and only the
fixture in `conftest.py` opens a socket.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from sopuli.driver.protocol import (
    ACCOUNT_LOCK_STATE,
    CAPABILITIES,
    COMMON_USERS,
    CONTAINER_SCOPE,
    EXPIRE_PASSWORD,
    OFFLINE_VERIFY,
    PASSWORD_REUSE_POLICY,
    PASSWORD_ROLLOVER,
    PROFILE_MANAGEMENT,
)

#: One question per capability, each answering with a truthy first column. A
#: query that raises means *absent*: an unsupported feature usually shows up as a
#: missing view or column, and that refusal is itself the answer.
PROBES: Mapping[str, str] = {
    # Multitenant at all. `common_users` asks the same question because the
    # answer is the same fact -- a common user is a thing that exists only in a
    # CDB -- and two probes agreeing by construction would be one probe with a
    # second chance to disagree.
    CONTAINER_SCOPE: "select case when sys_context('userenv','cdb') = 'YES' "
    "then 1 else 0 end from dual",
    COMMON_USERS: "select case when sys_context('userenv','cdb') = 'YES' "
    "then 1 else 0 end from dual",
    # Gradual password rollover: 19.12+ / 21c+. The profile resource simply does
    # not exist below that, so its presence is the test -- and this is the
    # capability with no middle tier, since the buildable 19.3 base lacks it
    # (`04-testing.md` §2).
    PASSWORD_ROLLOVER: "select count(*) from dba_profiles "
    "where resource_name = 'PASSWORD_ROLLOVER_TIME'",
    # The column exists on every supported version; the *grant* is what is
    # optional (#86), so the probe is the read itself rather than the column's
    # existence.
    OFFLINE_VERIFY: "select count(*) from sys.user$ where rownum = 1",
    PROFILE_MANAGEMENT: "select count(*) from dba_profiles where rownum = 1",
    PASSWORD_REUSE_POLICY: "select count(*) from dba_profiles "
    "where resource_name = 'PASSWORD_REUSE_MAX'",
}

#: Capabilities with nothing to ask, and why. Every supported Oracle has these:
#: they are facts about the product, not about the instance in front of us.
#:
#: Kept as data rather than quietly added to whatever a probe returns, so the
#: report can distinguish "we asked and it said yes" from "there was nothing to
#: ask". A capability that is *assumed* is worth being able to see.
STRUCTURAL: Mapping[str, str] = {
    EXPIRE_PASSWORD: "ALTER USER ... PASSWORD EXPIRE exists on every supported release",
    ACCOUNT_LOCK_STATE: "ACCOUNT_STATUS and ALTER USER ... ACCOUNT LOCK likewise",
}


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
        """30 bytes below 12.2, 128 from 12.2.

        Read off the version rather than probed, because there is no dictionary
        view that states it -- and it is the one number a tier-1 test needs in
        order to build a statement at all (#171 makes the limit a required
        argument).
        """
        return 30 if below(self.version, (12, 2)) else 128


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


def read(cursor: object, sql: str) -> bool:
    """Run one probe. Any failure means the capability is absent.

    A missing view, a missing column, a privilege the service account was never
    granted: all of them arrive as an exception and all of them mean the same
    thing to a caller — *you cannot do this here*.
    """
    try:
        row = cursor.execute(sql).fetchone()  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 -- see the docstring: any failure is "no"
        return False
    return bool(row and row[0])


def probe(cursor: object) -> set[str]:
    """Every capability this connection reports, asked one question at a time."""
    found = {name for name, sql in PROBES.items() if read(cursor, sql)}
    return found | set(STRUCTURAL)


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

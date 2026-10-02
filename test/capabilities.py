"""Capability probing for the sopuli-dba test harness.

STATUS: DRAFT sketch. Never run. Illustrates the shape described in
docs/design/04-testing.md §3 — it is not the implementation.

The point: tests declare the capabilities they need, and the harness decides
whether an environment provides them by *asking the database*, never by matching
a version string. That way the suite validates the capability model in
00-principles.md P1 rather than duplicating its assumptions.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

# --------------------------------------------------------------------------
# Probes
#
# One SQL question per capability. Each returns True/False and never raises:
# an unsupported feature usually shows up as a missing column or view, which is
# itself the answer.
# --------------------------------------------------------------------------

PROBES: dict[str, str] = {
    # Multitenant at all?
    "container_scope": """
        select case when sys_context('userenv','cdb') = 'YES'
                    then 1 else 0 end from dual
    """,
    # Gradual password rollover: 19.12+ / 21c+. The profile resource simply does
    # not exist below that, so its presence is the test.
    "password_rollover": """
        select count(*) from dba_profiles
         where resource_name = 'PASSWORD_ROLLOVER_TIME'
    """,
    # Offline verification needs SYS.USER$; the grant may be absent even where
    # the column exists, so probe the read itself.
    "offline_verify": """
        select count(*) from sys.user$ where rownum = 1
    """,
    # 12.1+ marks Oracle-supplied accounts, which the client-side guardrails use.
    "oracle_maintained_flag": """
        select count(*) from dba_users
         where oracle_maintained = 'Y' and rownum = 1
    """,
    # Unified auditing replaced the traditional trail in 21c/23ai.
    "unified_audit": """
        select count(*) from audit_unified_enabled_policies where rownum = 1
    """,
    # 23ai schema privileges — the P7 question in 02-oracle-privileges.md.
    "schema_privileges": """
        select count(*) from dba_schema_privs where rownum = 1
    """,
}


@dataclass
class Environment:
    """One database the suite can run against."""

    name: str                       # "oracle-free", "oci-19c", …
    dsn: str
    tier: int                       # 0-3, see 04-testing.md §4
    capabilities: set[str] = field(default_factory=set)
    version: str | None = None
    max_password_bytes: int | None = None
    unreachable_reason: str | None = None

    @property
    def available(self) -> bool:
        return self.unreachable_reason is None


def probe(env: Environment, connect) -> Environment:
    """Fill in an Environment's capabilities by asking the database.

    Called once per session per environment. A connection failure is recorded
    rather than raised: a missing environment is a coverage gap to report, not a
    test failure to debug.
    """
    try:
        conn = connect(env.dsn)
    except Exception as exc:  # noqa: BLE001 — any failure means "not available"
        env.unreachable_reason = f"{type(exc).__name__}: {exc}"
        return env

    with conn:
        cur = conn.cursor()

        (env.version,) = cur.execute(
            "select version_full from v$instance"
        ).fetchone() or (None,)

        # Byte limit is version-dependent and worth knowing explicitly, because
        # a generated password longer than the target allows fails late and
        # confusingly. 30 bytes below 23, 128 from 23 (#595) -- not 12.2, which
        # raised identifiers and left passwords at 30.
        env.max_password_bytes = 30 if _below(env.version, "23.0") else 128

        for name, sql in PROBES.items():
            try:
                (found,) = cur.execute(sql).fetchone()
                if found:
                    env.capabilities.add(name)
            except Exception:  # noqa: BLE001 — missing view/column == absent
                continue

    return env


def _below(version: str | None, floor: str) -> bool:
    if not version:
        return False
    to_tuple = lambda v: tuple(int(p) for p in v.split(".")[:2])  # noqa: E731
    return to_tuple(version) < to_tuple(floor)


# --------------------------------------------------------------------------
# pytest integration
# --------------------------------------------------------------------------

def requires_capability(*names: str):
    """Skip unless the target under test reports every named capability."""
    return pytest.mark.requires_capability(names)


def requires_no_capability(*names: str):
    """Run only where the capability is ABSENT.

    Just as important as the positive form: the tool must degrade correctly, so
    "rollover unavailable → --strategy rollover fails at plan time" needs an
    environment that genuinely lacks it.
    """
    return pytest.mark.requires_no_capability(names)


def pytest_runtest_setup(item):
    env: Environment | None = getattr(item, "_sopuli_env", None)
    if env is None:
        return

    if not env.available:
        # Distinct from a capability skip — this one is a coverage gap, and the
        # session summary counts the two separately.
        pytest.skip(f"environment {env.name} unavailable: {env.unreachable_reason}")

    for marker, want_present in (
        ("requires_capability", True),
        ("requires_no_capability", False),
    ):
        for mark in item.iter_markers(name=marker):
            for cap in mark.args[0]:
                has = cap in env.capabilities
                if has is not want_present:
                    state = "lacks" if want_present else "has"
                    pytest.skip(f"{env.name} {state} capability {cap!r}")


def session_matrix(envs: list[Environment]) -> str:
    """Render the capability grid printed at the end of a run.

    Making this visible matters: without it, "all green" cannot be distinguished
    from "almost everything skipped".
    """
    caps = sorted(PROBES)
    width = max(len(c) for c in caps) + 2
    header = " " * width + "".join(f"{e.name:>12}" for e in envs)
    rows = [header]
    for cap in caps:
        cells = "".join(
            f"{('yes' if cap in e.capabilities else '-') if e.available else '?':>12}"
            for e in envs
        )
        rows.append(f"{cap:<{width}}{cells}")
    return "\n".join(rows)

"""The ``targets`` section and what `doctor` prints (#182). Tier 0.

The shape is the contract here: `doctor` is the first command to emit
``targets[]``, which arrived in schema 1.11 rather than being squeezed into
``results[]``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from sopuli.config.model import ExpandedTarget, Target, TargetOracle
from sopuli.driver.protocol import PrivilegeAudit, Scope
from sopuli.output.doctor_view import build_target, render
from sopuli.output.document import SCHEMA_VERSION, Error

SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)


def _target(
    name: str = "orders-pdb",
    *,
    scope: str | None = None,
    container: str | None = None,
    labels: tuple[tuple[str, str], ...] = (),
    target_set: str | None = None,
) -> ExpandedTarget:
    return ExpandedTarget(
        target=Target(
            name=name,
            type="oracle",
            dsn="db.example.com:1521/orders",
            oracle=TargetOracle(scope=scope, container=container),
            labels=labels,
        ),
        target_set=target_set,
        index=0,
    )


def _found(**kwargs: Any) -> Scope:
    defaults: dict[str, Any] = {
        "type": "pdb",
        "container": "ORDERS",
        "db_unique_name": "ORDERSDB",
        "db_version": "23.0.0.0.0",
        "open_mode": "READ WRITE",
        "read_write": True,
        "capabilities": frozenset({"expire_password", "password_rollover"}),
    }
    return Scope(**{**defaults, **kwargs})


def _validate(entry: dict[str, Any]) -> list[str]:
    """Validate one entry against the schema's own ``target_health`` definition."""
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator({**schema["$defs"]["target_health"], "$defs": schema["$defs"]})
    return [f"{list(e.path)}: {e.message}" for e in validator.iter_errors(entry)]


# --------------------------------------------------------------- the shape ---


def test_a_reachable_target_reports_what_it_found() -> None:
    entry = build_target(_target(), connected=True, scope=_found())

    assert _validate(entry) == []
    assert entry["reachable"] is True
    assert entry["scope"]["type"] == "pdb"
    assert entry["scope"]["capabilities"] == ["expire_password", "password_rollover"]


def test_an_unreachable_target_has_no_scope_at_all() -> None:
    """Not an empty one. A capability list of `[]` on a database nobody could
    reach reads as a database that supports nothing, which is a different and
    much more alarming claim."""
    entry = build_target(
        _target(),
        connected=False,
        error=Error(category="connectivity", message="no listener", code="ORA-12541"),
    )

    assert _validate(entry) == []
    assert entry["reachable"] is False
    assert "scope" not in entry
    assert entry["error"]["code"] == "ORA-12541"


def test_capabilities_are_sorted_so_two_runs_can_be_diffed() -> None:
    entry = build_target(
        _target(), connected=True, scope=_found(capabilities=frozenset({"b", "a", "c"}))
    )

    assert entry["scope"]["capabilities"] == ["a", "b", "c"]


def test_offline_verify_is_reported_from_the_capability_set() -> None:
    """One fact, reported twice in the schema because a consumer asks it
    directly — and stored once on `Scope`, because two copies are two things
    that can disagree."""
    without = build_target(_target(), connected=True, scope=_found())
    with_it = build_target(
        _target(), connected=True, scope=_found(capabilities=frozenset({"offline_verify"}))
    )

    assert without["scope"]["offline_verify_available"] is False
    assert with_it["scope"]["offline_verify_available"] is True


def test_labels_come_from_the_config_and_not_the_driver() -> None:
    """A driver has no idea what a target set called this database, which is why
    `Scope` has no field for them and this adds them."""
    entry = build_target(
        _target(labels=(("env", "qa"),), target_set="appdb"), connected=True, scope=_found()
    )

    assert entry["scope"]["labels"] == {"target_set": "appdb", "env": "qa"}


# ----------------------------------------------------------- the assertion ---


def test_a_target_that_asserts_nothing_gets_no_assertion_object() -> None:
    """`01-configuration.md` §3a: an assertion nobody makes is not a gap. An
    object saying `matches: true` would report agreement with a claim that was
    never made."""
    entry = build_target(_target(), connected=True, scope=_found())

    assert "asserted" not in entry


def test_a_matching_assertion_is_reported_as_matching() -> None:
    entry = build_target(_target(scope="pdb", container="ORDERS"), connected=True, scope=_found())

    assert _validate(entry) == []
    assert entry["asserted"] == {"scope": "pdb", "container": "ORDERS", "matches": True}


@pytest.mark.parametrize(
    ("declared_scope", "declared_container"),
    [("cdb_root", None), (None, "BILLING"), ("pdb", "BILLING"), ("cdb_root", "ORDERS")],
)
def test_a_disagreeing_assertion_is_reported_as_not_matching(
    declared_scope: str | None, declared_container: str | None
) -> None:
    """The `dsn:` edit that silently repointed a target, made visible in a survey
    rather than only at the moment somebody tries to rotate."""
    entry = build_target(
        _target(scope=declared_scope, container=declared_container),
        connected=True,
        scope=_found(),
    )

    assert entry["asserted"]["matches"] is False


def test_a_container_assertion_is_compared_case_insensitively() -> None:
    """The same rule the driver applies, for the same reason: Oracle upper-cases
    an unquoted identifier, so `orders` and `ORDERS` are one container."""
    entry = build_target(_target(container="orders"), connected=True, scope=_found())

    assert entry["asserted"]["matches"] is True


# --------------------------------------------------------------- the report ---


def test_the_report_leads_with_the_client() -> None:
    """Two sections, because only the first can be answered without a network:
    *can this machine reach an Oracle at all*, and then *what is each target*."""
    text = render(
        [build_target(_target(), connected=True, scope=_found())],
        client={"instant_client": "23.5.0.0", "reaches": "19.1 and later"},
    )

    assert text.splitlines()[0] == "client"
    assert "23.5.0.0" in text
    assert "orders-pdb" in text


def test_the_report_names_a_mismatch_in_full() -> None:
    """Both halves, because the found one is the half the reader cannot see."""
    text = render(
        [build_target(_target(scope="cdb_root"), connected=True, scope=_found())],
        client={"instant_client": "23.5.0.0"},
    )

    assert "cdb_root" in text
    assert "pdb" in text


def test_the_report_names_a_failure_and_its_target() -> None:
    text = render(
        [
            build_target(
                _target(),
                connected=False,
                error=Error(category="connectivity", message="no listener"),
            )
        ],
        client={"instant_client": "23.5.0.0"},
    )

    assert "orders-pdb" in text
    assert "no listener" in text


def test_a_session_that_opened_but_could_not_be_described_stays_reachable() -> None:
    """`reachable` means *a session was opened*, and nothing more.

    A probe can fail on a connection that is perfectly fine — a dictionary view
    the service account cannot read, or a question this build should not have
    asked (`ProbeError`). Deriving `reachable` from whether a scope came back
    reported those as connectivity failures, which sends somebody to the
    listener over a grant.
    """
    entry = build_target(
        _target(),
        connected=True,
        error=Error(category="database", message="a capability probe failed", code="ORA-00942"),
    )

    assert _validate(entry) == []
    assert entry["reachable"] is True, "the session opened; that is what the field means"
    assert "scope" not in entry, "but nothing could be said about what it is"
    assert entry["error"]["code"] == "ORA-00942"


# ------------------------------------------------------- the privilege section ---


def _audit(**kwargs: Any) -> PrivilegeAudit:
    return PrivilegeAudit(**kwargs)


def test_a_privilege_section_validates_against_the_schema() -> None:
    """1.12's `privilege_report`, checked as an artefact rather than described.

    Invariant 12 wants the samples validated; this validates the *producer*,
    which is the half that can drift after the schema is written.
    """
    entry = build_target(
        _target(),
        connected=True,
        scope=_found(over_granted=("DBA",)),
        privileges=_audit(
            over_granted=("DBA",),
            held=("ALTER USER", "CREATE SESSION"),
            missing=("SELECT ON DBA_PROFILES",),
            roles=("DBA",),
        ),
    )

    assert _validate(entry) == []


def test_an_empty_privilege_section_still_validates() -> None:
    """The E6 case: nothing found, every array present and empty. If `required`
    and the producer ever disagree, this is where it shows."""
    entry = build_target(_target(), connected=True, scope=_found(), privileges=_audit())

    assert _validate(entry) == []


def test_a_half_emitted_privilege_section_is_refused_by_the_schema() -> None:
    """What `required` buys, asserted rather than assumed.

    The section's own description promises it is emitted whole, empty arrays
    included, so that an audit can be quoted as evidence of what it covered. A
    schema that let a producer omit `unreadable` would let a partial audit
    validate as a complete one — which is the exact confusion the field exists to
    prevent.
    """
    entry = build_target(_target(), connected=True, scope=_found(), privileges=_audit())
    del entry["privileges"]["unreadable"]

    assert _validate(entry) != []


def test_the_section_is_absent_when_the_audit_was_not_run() -> None:
    """Absent and empty mean different things -- *not asked* and *asked, nothing
    found* -- and a consumer needs both. A falsy check would destroy it."""
    entry = build_target(_target(), connected=True, scope=_found())

    assert "privileges" not in entry
    assert _validate(entry) == []


def test_a_missing_grant_reaches_the_text_report() -> None:
    """Ahead of the over-grant line, because it is the one that stops the tool
    working: an account short a grant fails at the verb that needs it, several
    commands away, with an error about a view rather than about the install."""
    entry = build_target(
        _target(),
        connected=True,
        scope=_found(),
        privileges=_audit(missing=("SELECT ON DBA_PROFILES",)),
    )

    output = render([entry], client={})

    assert "SELECT ON DBA_PROFILES" in output
    assert "the tool needs it" in output

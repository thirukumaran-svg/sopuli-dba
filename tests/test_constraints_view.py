"""The ``constraints`` section, as a shape. Tier 0.

What `creds generate` puts in the document after asking the estate what a
password may be. Pure: :mod:`sopuli.output.constraints_view` turns a
:class:`~sopuli.constraints.Constraints` into JSON and never opens anything.

The section is a **contract** (invariant 12), so most of what is asserted here is
about the three answers a verify function can give. Two of them are easy and the
third is the whole point: ``unknown`` must not render as ``none``, because a
missing verify function reads as a guarantee that nothing will judge the
password.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from sopuli.constraints import AccountConstraints, Constraints, survey
from sopuli.output.constraints_view import build_constraints, render_constraints
from sopuli.output.document import SCHEMA_VERSION, RunDocument, Summary
from sopuli.passwords import ByteLimit

RUN_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

MODERN = ByteLimit(max_bytes=128, encoding="utf-8", charset="AL32UTF8")
LEGACY = ByteLimit(max_bytes=30, encoding="ascii", charset="US7ASCII")
UNMAPPED = ByteLimit(max_bytes=128, encoding="ascii", charset="JA16SJIS")

GUARDED = AccountConstraints(
    account="ACME_WEB_USER",
    profile="ACME_PROF",
    verify_function="ORA12C_STRONG_VERIFY_FUNCTION",
    reuse_max="3",
    reuse_time="10",
    versions=("11G", "12C"),
)
PLAIN = AccountConstraints(
    account="ACME_BATCH_USER",
    profile="DEFAULT",
    reuse_max="UNLIMITED",
    reuse_time="UNLIMITED",
    versions=("11G", "12C"),
)
UNREADABLE = AccountConstraints(
    account="ACME_COMMON_USER", profile="ACME_COMMON_PROF", verify_function_known=False
)


@pytest.fixture
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8")))


def _section(found: Constraints) -> dict[str, Any]:
    built = build_constraints(found)
    assert built is not None
    return built


def test_offline_omits_the_section_rather_than_emitting_an_empty_one() -> None:
    """Absence *means* something here: the run did not ask.

    A section with no readings would say the estate was consulted and told this
    run nothing, which is the `policy` source and a different run.
    """
    assert build_constraints(Constraints()) is None


def test_a_run_that_asked_and_learned_nothing_still_emits_the_section() -> None:
    section = _section(survey([], unreachable=("appdb-alpha",)))

    assert section["source"] == "policy"
    assert section["targets"] == [{"target": "appdb-alpha", "reachable": False}]
    assert "max_password_bytes" not in section


def test_the_count_that_governed_the_draw_is_at_the_top() -> None:
    """Rather than left to be worked out from `targets[]` -- which would mean a
    consumer reimplementing the partial order this section exists to state."""
    section = _section(survey([("alpha", MODERN), ("beta", LEGACY)]))

    assert section["max_password_bytes"] == 30
    assert section["strictest_target"] == "beta"


def test_one_reading_names_no_strictest_target() -> None:
    section = _section(survey([("alpha", MODERN)]))

    assert "strictest_target" not in section


def test_every_target_keeps_its_own_limit() -> None:
    """The readings do not collapse into the winner: a supplied password has to
    satisfy each character set, whichever target had the smallest count."""
    section = _section(survey([("alpha", MODERN), ("beta", LEGACY)]))

    assert [one["target"] for one in section["targets"]] == ["alpha", "beta"]
    assert [one["max_password_bytes"] for one in section["targets"]] == [128, 30]
    assert [one["character_set"] for one in section["targets"]] == ["AL32UTF8", "US7ASCII"]


def test_the_codec_is_reported_because_the_character_set_does_not_imply_it() -> None:
    """`limits.py` falls back to ASCII for a character set it does not map, and a
    reader whose database refuses a non-ASCII password should see that here
    rather than deduce it from a refusal."""
    section = _section(survey([("alpha", UNMAPPED)]))

    assert section["targets"][0] == {
        "target": "alpha",
        "reachable": True,
        "max_password_bytes": 128,
        "measured_as": "ascii",
        "character_set": "JA16SJIS",
    }


def test_a_named_verify_function_carries_its_name() -> None:
    section = _section(survey([("alpha", MODERN)], accounts=[("alpha", GUARDED)]))
    account = section["accounts"][0]

    assert account["verify_function"] == {
        "state": "named",
        "name": "ORA12C_STRONG_VERIFY_FUNCTION",
    }
    assert account["profile"] == "ACME_PROF"
    assert account["password_reuse_max"] == "3"
    assert account["password_versions"] == ["11G", "12C"]


def test_an_unreadable_verify_function_is_unknown_and_carries_no_name() -> None:
    """The reading that must not render as `none`. `none` says nothing will judge
    this password; this says the run could not find out."""
    section = _section(survey([("alpha", MODERN)], accounts=[("alpha", UNREADABLE)]))

    assert section["accounts"][0]["verify_function"] == {"state": "unknown"}


def test_a_profile_naming_none_says_so_positively() -> None:
    section = _section(survey([("alpha", MODERN)], accounts=[("alpha", PLAIN)]))

    assert section["accounts"][0]["verify_function"] == {"state": "none"}


def test_accounts_are_omitted_where_none_answered() -> None:
    assert "accounts" not in _section(survey([("alpha", MODERN)]))


def test_the_section_validates_against_the_published_schema(
    validator: Draft202012Validator,
) -> None:
    """Invariant 12. The document is the contract, and a section nothing
    validates is a shape that drifts the first time somebody adds a field."""
    document = RunDocument.start("creds.generate")
    document.constraints = _section(
        survey(
            [("alpha", MODERN), ("beta", UNMAPPED)],
            unreachable=("gamma",),
            accounts=[("alpha", GUARDED), ("alpha", PLAIN), ("beta", UNREADABLE)],
        )
    )
    document.finish(0, Summary(total=2, ok=2, changed=2))

    validator.validate(document.to_dict())


def test_the_line_says_which_answer_the_run_got() -> None:
    line = render_constraints(survey([("alpha", MODERN), ("beta", LEGACY)]))

    assert line is not None
    assert "30 bytes in US7ASCII" in line
    assert "beta" in line


def test_the_line_says_when_the_estate_was_only_partly_read() -> None:
    line = render_constraints(survey([("alpha", MODERN)], unreachable=("beta",)))

    assert line is not None
    assert "not read from beta" in line


def test_the_line_says_when_nothing_answered() -> None:
    line = render_constraints(survey([], unreachable=("alpha",)))

    assert line is not None
    assert "no target answered" in line
    assert "policy" in line


def test_offline_prints_no_line() -> None:
    """Repeating a flag back at the person who typed it is not reporting."""
    assert render_constraints(Constraints()) is None

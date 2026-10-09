"""What colour is allowed to mean, and what it must never be the only carrier of.

Tier 0. The rules under test are `03-json-output.md` §1's, and two of them are
the kind that hold until somebody adds a state in a hurry:

* **the palette covers the schema's vocabulary**, so a new state cannot arrive
  uncoloured without a test saying so;
* **stripping the escapes gives the plain output back, byte for byte**, which is
  what makes the `NO_COLOR` path lossless by construction rather than by care.

Nothing here asserts *which* colour a role gets, except where the colour itself
was the decision -- see :func:`test_the_converged_state_is_not_green`. Tests that
pin a palette are tests that have to be edited every time somebody improves it,
which teaches the next person to edit tests rather than to think.
"""

from __future__ import annotations

import json
from pathlib import Path

import click
import pytest

from sopuli.apply import PENDING_APPLY, SKIPPED
from sopuli.check import (
    ACCOUNT_MISSING,
    DRIFT,
    ERROR,
    EXPIRED,
    IN_SYNC,
    LOCKED,
    ROLLOVER_ACTIVE,
    UNVERIFIABLE,
)
from sopuli.generate import VAULT_ONLY
from sopuli.output.document import SCHEMA_VERSION
from sopuli.output.palette import (
    Role,
    absent_cell,
    paint,
    role_for_health,
    role_for_state,
    state_cell,
)
from sopuli.output.table import Cell
from sopuli.store.protocol import DEGRADED, OK, UNREACHABLE

RUN_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)


def schema_states() -> tuple[str, ...]:
    """Every value of the run document's `state` enum, read from the contract.

    From the schema rather than from a list here, so this test measures the
    thing that is published rather than a copy of it that can drift from it.
    """
    schema = json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))
    return tuple(schema["$defs"]["state"]["enum"])


# ------------------------------------------------------- covering the enum ---


@pytest.mark.parametrize("state", schema_states())
def test_every_published_state_has_a_role(state: str) -> None:
    """A state added to the schema and not to the palette loses its colour
    quietly, which is the safe direction and still worth being told about."""
    assert role_for_state(state) is not None


def test_a_value_that_is_not_a_state_gets_no_role() -> None:
    """A caller may hand `state_cell` whatever is in the cell. An unknown value
    renders plain rather than raising -- the word is the meaning either way."""
    assert role_for_state("NOT_A_STATE") is None
    assert state_cell("NOT_A_STATE") == "NOT_A_STATE"


# ------------------------------------------------------------ the grouping ---


def test_the_converged_state_is_the_only_good_one() -> None:
    """`IN_SYNC` is the one row a reader can stop reading at. If a second state
    were `good`, the column would stop answering "what do I have to look at"."""
    good = [state for state in schema_states() if role_for_state(state) is Role.GOOD]

    assert good == [IN_SYNC]


@pytest.mark.parametrize(
    ("state", "role"),
    [
        (IN_SYNC, Role.GOOD),
        (DRIFT, Role.ATTENTION),
        (PENDING_APPLY, Role.ATTENTION),
        (ROLLOVER_ACTIVE, Role.ATTENTION),
        (VAULT_ONLY, Role.ATTENTION),
        (ERROR, Role.BAD),
        (ACCOUNT_MISSING, Role.BAD),
        (LOCKED, Role.BAD),
        (EXPIRED, Role.BAD),
        (UNVERIFIABLE, Role.INCONCLUSIVE),
        (SKIPPED, Role.INCONCLUSIVE),
    ],
)
def test_the_grouping_is_what_was_decided(state: str, role: Role) -> None:
    """Decision #395's four buckets, spelled out once.

    Deliberately explicit rather than derived from a predicate: this *is* the
    decision, and a test that recomputed it from the same table it is checking
    would pass whatever the table said.
    """
    assert role_for_state(state) is role


def test_a_locked_account_is_not_dimmed() -> None:
    """Where the palette parts company with `check`'s exit-code grouping, on
    purpose.

    `is_inconclusive` counts `ACCOUNT_MISSING`, `LOCKED` and `EXPIRED` as
    inconclusive -- correctly, for an exit code: none of them says anything
    about the *password*. For a colour it is the wrong question. A locked
    account is not an absence of news, and dimming it would tell a reader to
    look past the row they most need to see.
    """
    for state in (ACCOUNT_MISSING, LOCKED, EXPIRED):
        assert role_for_state(state) is not Role.INCONCLUSIVE


# ----------------------------------------------------- the colours as such ---


def test_the_converged_state_is_not_green() -> None:
    """The one place a colour itself is the decision, as decision #395 records.

    Green `IN_SYNC` against yellow `DRIFT` is the pairing a deuteranopic reader
    cannot separate, on the exact distinction this tool exists to report. Cyan
    against yellow is separable, and red stays for failure where it is close to
    universal. This test exists so that "make it green, green means ok" is a
    conversation rather than a commit.
    """
    styled = paint(IN_SYNC, Role.GOOD)

    assert "\x1b[32m" not in styled  # green
    assert "\x1b[36m" in styled  # cyan


def test_the_three_that_have_to_be_told_apart_are_distinct() -> None:
    """Whatever the colours are, these three must never collapse into one."""
    distinct = {paint("X", role) for role in (Role.GOOD, Role.ATTENTION, Role.BAD)}

    assert len(distinct) == 3


# ------------------------------------------------------------ losslessness ---


@pytest.mark.parametrize("state", schema_states())
def test_stripping_a_state_cell_gives_the_plain_word_back(state: str) -> None:
    """§1's binding rule: meaning is never carried by colour alone.

    Byte for byte, because "close enough" is how a padding change becomes a
    `NO_COLOR` regression nobody notices.
    """
    cell = state_cell(state)
    text = cell.text if isinstance(cell, Cell) else cell
    role = role_for_state(state)

    assert text == state
    assert click.unstyle(paint(text, role)) == state


def test_painting_nothing_stays_nothing() -> None:
    """An empty cell must not become two escape sequences wrapped around it --
    the width would still be zero and the table would still be wrong."""
    assert paint("", Role.BAD) == ""


# ------------------------------------------------- one decision, four views ---


@pytest.mark.parametrize(
    "module",
    [
        "sopuli.output.apply_view",
        "sopuli.output.check_view",
        "sopuli.output.status_view",
        "sopuli.output.finish_rollover_view",
    ],
)
def test_every_result_view_defers_to_the_one_decision(module: str) -> None:
    """The bug a shared mapping prevents, asserted at the four call sites.

    Each of these kept its own subset of the state enum and painted it
    `NOTABLE`, so `DRIFT` was emphasised by `check` and not by `apply` while
    `ERROR` was emphasised by `apply` and not by `check` -- one state, one run,
    different emphasis depending on the verb. Asserting the *mapping* is right
    would not have caught that; asserting each view produces the same cell for
    the same state does.
    """
    import importlib

    view = importlib.import_module(module)

    for state in schema_states():
        rendered = view._state(state)
        expected = state_cell(state)
        assert rendered == expected, f"{module} disagrees about {state}"


# -------------------------------------------------- the second vocabulary ---


@pytest.mark.parametrize(
    ("status", "role"),
    [(OK, Role.GOOD), (DEGRADED, Role.ATTENTION), (UNREACHABLE, Role.BAD)],
)
def test_store_health_maps_onto_the_same_four_roles(status: str, role: Role) -> None:
    """A second vocabulary, not a second palette. `doctor` and every `creds`
    run print this word about the same store, so one function decides it."""
    assert role_for_health(status) is role


def test_a_degraded_store_is_not_as_loud_as_an_unreachable_one() -> None:
    """The distinction `sopuli.store.protocol` already draws, kept in the colour.

    A degraded store *answered* and sends the reader to the vault; an
    unreachable one did not and sends them to the network. Collapsing them would
    undo the whole reason those are three words instead of a boolean.
    """
    assert role_for_health(DEGRADED) is not role_for_health(UNREACHABLE)


def test_a_word_that_is_not_a_health_status_gets_no_role() -> None:
    assert role_for_health("splendid") is None


# --------------------------------------------------- the absent placeholder ---


@pytest.mark.parametrize("value", ["", None])
def test_an_absent_value_becomes_a_dimmed_placeholder(value: str | None) -> None:
    """`-` has to mean the same thing in every table, which is what stops a
    column of them competing with the values beside it."""
    cell = absent_cell(value)

    assert isinstance(cell, Cell)
    assert cell.text == "-"
    assert cell.role is Role.MUTED


def test_a_value_that_is_there_is_left_alone() -> None:
    assert absent_cell("FREEPDB1") == "FREEPDB1"

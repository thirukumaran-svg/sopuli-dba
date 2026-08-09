"""Every YAML example in the configuration reference must actually parse.

CLAUDE.md: the design documents are the specification, and if they disagree with
the code that is a bug in one of them. This is the cheapest place to find that
out. `01-configuration.md` §2 is a 129-line worked example nobody has ever run;
without this it stays prose that only looks like a config file.

It also pins the hardened loader against the real thing. Rejecting duplicate
keys and narrowing YAML 1.1 booleans are changes to the dialect, and the test
that they did not break the documented config is to feed them the documented
config.

**If a future example is meant to be invalid** -- illustrating an error message,
say -- fence it as ```` ```text ```` rather than ```` ```yaml ````, or this test
will fail and be right to.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

import pytest

from sopuli.config.loading import load_document
from sopuli.config.yaml_loader import parse_yaml

REFERENCE = Path(__file__).resolve().parents[2] / "docs" / "design" / "01-configuration.md"

YAML_BLOCK = re.compile(r"```yaml\n(.*?)```", re.DOTALL)


def _blocks() -> list[tuple[int, str]]:
    text = REFERENCE.read_text(encoding="utf-8")
    return [(index, match) for index, match in enumerate(YAML_BLOCK.findall(text))]


def test_the_reference_has_examples_to_check() -> None:
    """Guards the regex: a change to the fence style would otherwise leave every
    test below passing over an empty list."""
    assert len(_blocks()) >= 4


@pytest.mark.parametrize(("index", "block"), _blocks(), ids=lambda value: str(value)[:20])
def test_every_yaml_example_parses(index: int, block: str) -> None:
    parse_yaml(block, source=REFERENCE)


def test_the_worked_example_is_a_loadable_document(write_config: Callable[[str], Path]) -> None:
    """§2 is the one complete file in the document -- the others are fragments.

    It is the only block that should satisfy the whole-file rules, so it is the
    only one checked against them.
    """
    complete = [block for _, block in _blocks() if "version:" in block and "runtime:" in block]
    assert len(complete) == 1, "expected exactly one complete worked example in §2"

    document = load_document(write_config(complete[0]))

    assert document["accounts"][0] == "acme_web_user"
    assert document["target_sets"]["appdb"]["for_each"]["env"]["prod"]["tenant"][0] == "alpha"


def test_the_worked_example_survives_the_boolean_narrowing() -> None:
    """`pdb_suffix: dev` and friends are bare words in exactly the position the
    Norway problem bites. None of them may come back as a boolean."""
    complete = next(block for _, block in _blocks() if "runtime:" in block)
    for_each = parse_yaml(complete)["target_sets"]["appdb"]["for_each"]["env"]

    for environment, variables in for_each.items():
        assert isinstance(environment, str)
        for name, value in variables.items():
            assert not isinstance(value, bool), f"{environment}.{name} parsed as a boolean"

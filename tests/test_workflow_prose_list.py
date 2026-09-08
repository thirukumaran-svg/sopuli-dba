"""The two CI workflows agree about what counts as prose.

Tier 0 (04-testing.md §4): reads two files, runs nothing.

`tier1.yml` skips a prose-only pull request with `paths-ignore` on the trigger.
`ci.yml` cannot -- a workflow skipped that way never creates its check contexts,
and a required context that was never created leaves every prose-only pull
request pending forever. It filters in a `changes` job instead, whose skipped
dependants report `skipped` and satisfy the requirement, with `ci ok` as the one
check `workflow.md` says to require (#375).

The cost of that is the list existing twice, in two syntaxes. This is what makes
the second copy safe: a pattern added to one and not the other is a failing test
rather than a lane that quietly stopped skipping. Drift is the failure #375 was
opened about -- seven patterns arrived in #370 and #373 and neither list heard
about them, because nothing looked.

It does **not** check that the list is *correct*. What the suite actually opens
under `docs/`, `sql/` and `examples/` is a property of running the suite, and
`test/paths_ignore_probe.py` is what measures it. This only checks that the two
copies say the same thing.
"""

from __future__ import annotations

import re
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def _paths_ignore(text: str) -> list[str]:
    """The `paths-ignore:` list of a workflow trigger, in file order."""
    block = re.search(r"^ *paths-ignore:\n((?: *- '[^']+'\n)+)", text, re.MULTILINE)
    assert block is not None, "no paths-ignore block found"
    return re.findall(r"- '([^']+)'", block.group(1))


def _prose_array(text: str) -> list[str]:
    """The `prose=(...)` bash array in `ci.yml`'s `changes` job, in file order.

    Delimited by the `prose-list-start` / `prose-list-end` markers so that the
    comment explaining the array is not mistaken for part of it.
    """
    block = re.search(r"# prose-list-start\n(.*?)\n *# prose-list-end", text, re.DOTALL)
    assert block is not None, "no prose-list markers found in ci.yml"
    return re.findall(r"^ *'([^']+)'$", block.group(1), re.MULTILINE)


def test_the_two_prose_lists_are_identical() -> None:
    """Same patterns, same order.

    Order is asserted too, and not out of tidiness: the lists are read side by
    side when either changes, and a diff against a reordered copy is unreadable
    at exactly the moment somebody needs to read it.
    """
    tier1 = _paths_ignore((WORKFLOWS / "tier1.yml").read_text(encoding="utf-8"))
    ci = _prose_array((WORKFLOWS / "ci.yml").read_text(encoding="utf-8"))

    assert ci == tier1


def test_neither_list_is_empty() -> None:
    """A regex that found its block but nothing in it would pass the test above.

    The extractors assert when they cannot find the block at all, so a workflow
    reorganised out from under them fails loudly. The quieter failure is a block
    that is still found and no longer yields entries -- reformat either list to
    double quotes, say, and `findall` returns `[]` for both. Two empty lists
    compare equal, and this file becomes a test of nothing while staying green.
    """
    tier1 = _paths_ignore((WORKFLOWS / "tier1.yml").read_text(encoding="utf-8"))
    ci = _prose_array((WORKFLOWS / "ci.yml").read_text(encoding="utf-8"))

    assert len(tier1) > 10
    assert len(ci) > 10


def test_examples_is_not_ignored() -> None:
    """`examples/` is a tested artefact, not documentation that happens to sit
    in a directory.

    `tests/test_examples.py` (#372) runs `config validate` against every
    `examples/*.yaml` precisely so an example cannot drift out of date with the
    config layer. Ignoring the directory would switch that off and leave the
    test passing on whatever was last committed -- green, and measuring nothing.
    It is the exact trap the workflow comments describe, so it gets an assertion
    rather than a sentence.
    """
    tier1 = _paths_ignore((WORKFLOWS / "tier1.yml").read_text(encoding="utf-8"))
    ci = _prose_array((WORKFLOWS / "ci.yml").read_text(encoding="utf-8"))

    for pattern in tier1 + ci:
        assert not pattern.startswith("examples/"), pattern
        assert not pattern.startswith("sql/"), pattern

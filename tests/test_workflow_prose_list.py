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


# --------------------------------------------------------------- the docs lane ---
#
# The prose list is allowed to ignore most of `docs/` only because `ci.yml`'s
# `docs` job runs the two tier-0 modules that read it (#458). That makes the job
# load-bearing rather than convenient: delete it, or let it drift out of step with
# what `test/paths_ignore_probe.py` deselects, and prose-only pull requests go
# back to reporting green on a broken register — the #457 failure, restored.
#
# Nothing else checks this. The probe measures what the *suite* opens and now
# deliberately excludes these two modules, so it cannot notice that the job which
# justifies the exclusion has gone.

PROBE = Path(__file__).resolve().parents[1] / "test" / "paths_ignore_probe.py"


def _docs_lane_from_probe() -> list[str]:
    """The modules `paths_ignore_probe.py` deselects, read from its `DOCS_LANE`."""
    text = PROBE.read_text(encoding="utf-8")
    block = re.search(r"^DOCS_LANE = \(\n(.*?)\n\)", text, re.MULTILINE | re.DOTALL)
    assert block is not None, f"no DOCS_LANE tuple found in {PROBE}"
    return re.findall(r'"([^"]+)"', block.group(1))


#: The modules this whole arrangement exists to keep running, named outright.
#:
#: Asserting only that the job and the probe *agree* would pass on two empty
#: lists, or on two lists changed in lockstep to something else entirely -- the
#: `test_neither_list_is_empty` failure one file over, in a new place. The pair is
#: therefore pinned rather than merely cross-checked.
PROSE_READERS = (
    "tests/test_doc_command_lines.py",
    "tests/test_verification_register.py",
)


def _docs_job() -> str:
    """The `docs:` job block from `ci.yml`."""
    text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    job = re.search(r"\n  docs:\n(.*?)(?=\n  [a-z-]+:\n)", text, re.DOTALL)
    assert job is not None, "ci.yml has no `docs:` job"
    return job.group(1)


def _docs_job_modules() -> list[str]:
    """The test paths `ci.yml`'s `docs` job passes to pytest."""
    line = re.search(r"run: pytest ([^\n]+)", _docs_job())
    assert line is not None, "the `docs` job runs no pytest command"
    return line.group(1).split()


def test_the_docs_job_runs_exactly_what_the_probe_deselects() -> None:
    """The two lists are the same decision written in two files.

    The probe stops counting these modules because the job runs them. If the job
    ran a subset, the probe would be excusing a file nothing checks; if it ran a
    superset, that is a module doing prose work nobody deselected, and the probe
    would report a conflict for it on the next run.

    Both are compared against :data:`PROSE_READERS` rather than only against each
    other, so that changing them together cannot quietly turn the guard off.
    """
    assert sorted(_docs_job_modules()) == list(PROSE_READERS)
    assert sorted(_docs_lane_from_probe()) == list(PROSE_READERS)


def test_the_docs_job_is_gated_on_prose_only() -> None:
    """The `if:` is the whole mechanism, and nothing else here was checking it.

    The guards above pin *what* the job runs and that `ci ok` waits for it. Invert
    this condition to `'true'`, or delete it, and every one of them stays green
    while prose-only pull requests skip the readers again -- #458 restored, with a
    full set of passing tests over it. `needs: changes` is asserted alongside,
    because the condition reads an output of that job and silently evaluates
    false-y without the dependency.
    """
    block = _docs_job()

    assert "if: needs.changes.outputs.code == 'false'" in block, (
        "the docs job must run when `changes` reports prose only; it is the lane "
        "that covers the tests the prose list lets the other lanes skip"
    )
    assert re.search(r"^    needs: changes$", block, re.MULTILINE), block


def test_ci_ok_requires_the_docs_job() -> None:
    """A lane missing from `ci ok`'s `needs` is a lane whose failure merges.

    `ci ok` is the one required check (`workflow.md`), and it judges
    `join(needs.*.result, ' ')` — so a job absent from that list is invisible to
    it however red it goes.
    """
    text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    needs = re.search(r"^    needs: \[([^\]]+)\]$", text, re.MULTILINE)
    assert needs is not None, "ci ok has no needs list"

    assert "docs" in [name.strip() for name in needs.group(1).split(",")]

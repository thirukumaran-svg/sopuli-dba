"""What a pre-flight found, as a table (UC-1 §8 step 3, #283).

The shape here, the decision in :mod:`sopuli.preflight` -- the arrangement
:mod:`sopuli.output.apply_view` and :mod:`sopuli.output.check_view` have with
theirs.

**Every finding is printed, not just the one that refused.** A pre-flight exists
so an estate can be fixed in one pass; reporting only the first would turn a
survey into a round trip per problem, which is the cost the survey was run to
avoid. The run-level ``error`` still names one of them, because a run has one
exit code and one reason -- see :func:`sopuli.preflight.refusal` for which.

**The hint is printed under the table rather than in it.** Hints are sentences
and a column of them wraps into unreadability; a finding's hint is also the half
that repeats across targets, so the same advice appearing once per row would
bury the rows.
"""

from __future__ import annotations

from collections.abc import Sequence

from sopuli.output.palette import Role, paint
from sopuli.output.table import Cell, Column, render_table
from sopuli.preflight import Finding

__all__ = ["render_preflight"]

_TARGET = 28
_CHECK = 12
_ACCOUNT = 24


def render_preflight(findings: Sequence[Finding]) -> str:
    """The findings table, then one line per distinct hint, then the verdict."""
    table = render_table(
        [
            Column("TARGET", _TARGET),
            Column("CHECK", _CHECK),
            Column("ACCOUNT", _ACCOUNT),
            Column("DETAIL"),
        ],
        [
            [
                one.target,
                Cell(one.check, Role.NOTABLE),
                one.account or Cell("-", Role.MUTED),
                one.message,
            ]
            for one in findings
        ],
    )

    lines = [*table, ""]
    for hint in _hints(findings):
        lines.append(f"  {hint}")
    if len(lines) > 2:
        lines.append("")
    lines.append(paint(_verdict(findings), Role.NOTABLE))
    return "\n".join(lines)


def _hints(findings: Sequence[Finding]) -> list[str]:
    """Each distinct hint once, in the order it was first raised.

    Deduplicated because a missing grant on twenty targets is one install script
    to run, and twenty identical sentences would make the twenty rows above them
    harder to read rather than easier.
    """
    seen: list[str] = []
    for one in findings:
        if one.hint is not None and one.hint not in seen:
            seen.append(one.hint)
    return seen


def _verdict(findings: Sequence[Finding]) -> str:
    """How many, over how many targets, and that nothing was written.

    **Counts what refused, not what was printed**, which is the same count
    :func:`sopuli.preflight.summarise` puts in the run-level ``error``. A caveat
    is in the table because it is worth seeing and is not a problem: counting it
    here would have the text say four where the document said three, and one run
    described two ways is exactly what the JSON contract exists to prevent. It is
    named separately instead, because a reader who fixes three things and sees a
    fourth row needs to know why it is there.

    The last clause is the one worth the words. Every other refusal in this tool
    happens where an operator can see what had already been done; this one is the
    whole point of running the survey, and a verdict that did not say so would
    leave somebody checking.
    """
    blocking = [one for one in findings if one.blocking]
    caveats = len(findings) - len(blocking)
    targets = len({one.target for one in blocking})
    plural = "" if len(blocking) == 1 else "s"
    over = "1 target" if targets == 1 else f"{targets} targets"
    line = f"{len(blocking)} problem{plural} over {over}; nothing was written"
    if caveats:
        was = "1 check could not" if caveats == 1 else f"{caveats} checks could not"
        line = f"{line} ({was} be established)"
    return line

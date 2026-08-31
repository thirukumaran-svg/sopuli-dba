"""What a rotation did, as text (UC-1 §8, #284).

`rotate` sequences verbs that already have views, so most of this file is about
**not** writing a second one. The result table is
:func:`sopuli.output.apply_view.render_apply`, unchanged and called directly: the
middle of a rotation *is* an apply, and a table that differed would be two
renderings of one operation for a reader to reconcile. The `results[]` entries
are :func:`sopuli.output.apply_view.build_result` for the same reason, which is
also why this verb needs no new run-schema surface -- ``creds.rotate`` was in the
command enum before the command existed.

What is left is the part no existing view has: the **sequence**. A rotation is
nine steps and can stop at any of them, and the one question its output has to
answer that `apply`'s does not is *how far did this get*. So the two things here
are a header saying what the run is about to do, and a closing line saying which
steps it completed.

**The step line is printed on success too**, not only on failure. A scheduled
rotation that exits 0 every night is the case where nobody reads the output, and
the run where it silently stopped promoting is the one somebody needs to be able
to find afterwards by eye.
"""

from __future__ import annotations

from collections.abc import Sequence

from sopuli.check import Outcome
from sopuli.config import Binding
from sopuli.output.apply_view import render_apply
from sopuli.output.palette import Role, paint
from sopuli.output.table import Cell, Column, render_table
from sopuli.rotate import Selection

__all__ = ["render_rotate", "render_selection_table"]

_ACCOUNT = 24
_TARGET = 28
_AGE = 10


def render_selection_table(selections: Sequence[Selection]) -> list[str]:
    """What ``--max-age-days`` kept and what it left alone, before anything runs.

    Printed only when the flag was given. Without it every account is due and a
    column of ``yes`` beside a column of blanks is a table that says nothing --
    the plan above it already lists what the run covers.

    **The skipped rows are printed too**, which is the half worth the width. An
    operator running a 90-day rotation wants to see that eleven of fourteen
    accounts were young enough, because the alternative reading of a three-row
    run is that the selector was wrong -- and those two have very different next
    actions.
    """
    return list(
        render_table(
            [
                Column("ACCOUNT", _ACCOUNT),
                Column("TARGET", _TARGET),
                Column("AGE", _AGE),
                Column("ROTATING"),
            ],
            [
                [
                    one.binding.account,
                    one.binding.target,
                    _age(one.age),
                    Cell("yes", Role.NOTABLE) if one.due else one.reason,
                ]
                for one in selections
            ],
        )
    )


def _age(age: float | None) -> Cell | str:
    """The vault's age in days, or a dash where the vault has never said.

    A dash rather than ``0`` or ``unknown``: this column is beside a decision
    that turned on the value being absent, and a number would be the one
    rendering that could be misread as young.
    """
    return Cell("-", Role.MUTED) if age is None else f"{age}d"


def render_rotate(
    rows: Sequence[tuple[Binding, Outcome, bool]],
    *,
    staged: int,
    promoted: int,
    disagreed: Sequence[str] = (),
    closed: int | None = None,
    stopped: str | None = None,
    repair: str | None = None,
) -> str:
    """The apply table, then which of §8's steps this run completed.

    ``staged`` is documents written at step 4, ``promoted`` documents committed
    at step 7, ``closed`` rollover windows ended by ``--finish-rollover`` and
    ``None`` where it was not asked for -- which is not the same as ``0``, and
    the run that closed no windows because it was told to is a different fact
    from the run that was never told to.

    ``disagreed`` is step 8's account names. It is passed as names rather than a
    count because the closing line has to be actionable: "the vault disagreed"
    with no subject sends somebody to read three documents, and a rotation whose
    read-back failed on one account of twenty is the case where that matters
    most.

    ``stopped`` and ``repair`` mean what they mean in
    :func:`~sopuli.output.apply_view.render_apply`, and are handed straight to
    it: never both, and ``stopped`` wins. Deciding that twice would be two
    renderers with one opinion between them.
    """
    return "\n".join(
        [
            render_apply(rows, promoted=promoted, repair=repair, stopped=stopped),
            "",
            paint(
                _steps(staged=staged, promoted=promoted, disagreed=disagreed, closed=closed),
                Role.NOTABLE,
            ),
        ]
    )


def _steps(
    *,
    staged: int,
    promoted: int,
    disagreed: Sequence[str],
    closed: int | None,
) -> str:
    """One line naming what the sequence got through.

    Counted in documents rather than accounts, because that is the grain both
    steps actually operate at -- one compare-and-set per secret path, however
    many accounts share it. A line counting accounts would report six writes
    where the vault saw two, which is the number an operator comparing this
    against their vault audit log would be trying to match.
    """
    parts = [
        f"staged {staged} {_documents(staged)}",
        f"promoted {promoted} {_documents(promoted)}",
    ]
    if closed is not None:
        parts.append(f"closed {closed} rollover {'window' if closed == 1 else 'windows'}")
    line = "rotation: " + ", ".join(parts)
    if disagreed:
        # Named, and named last, because it is the one clause that describes
        # something still wrong after a run whose table above it may be entirely
        # green -- every target confirmed, the promotion acknowledged, and the
        # vault serving something else back.
        names = ", ".join(sorted(disagreed))
        return f"{line}\nthe vault read back a different password for: {names}"
    return line


def _documents(count: int) -> str:
    return "document" if count == 1 else "documents"

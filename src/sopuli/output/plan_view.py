"""The plan, as a person reads it.

Invariant 8 says every mutating command prints a plan first, and UC-1 §2 widens
that to every command: "Selection is resolved and printed *before* anything is
touched." So this is not a `--dry-run` decoration -- it is the header of every
`creds` run, and the last thing an operator sees before the tool starts work.

The JSON half lives on :class:`sopuli.plan.Plan` itself, beside the data, the way
:class:`~sopuli.config.sharing.SharedSecret` keeps its own ``as_json``. What is
here is only the reading of it.

Two decisions:

**The header counts, and then says what the count is of.** ``2 accounts x 2
targets = 4 checks`` is a sentence an operator can check against what they meant
to type, which a bare ``4 units`` is not. The two factors are what a wrong
selector gets wrong -- a `--select` that missed a label multiplies out to a
different pair of numbers long before it produces a different total.

**ASCII, including the multiplication sign.** UC-1 §7's worked output writes it
as ``x``. Nothing this codebase *emits* is outside ASCII -- every non-ASCII
character in `sopuli/output/` is in a docstring -- and P4 requires identical
behaviour on Windows, where redirected stdout is cp1252. `x` is not a compromise
anybody has to notice; a `UnicodeEncodeError` in a plan header would be.
"""

from __future__ import annotations

from collections.abc import Sequence

from sopuli.config.sharing import SharedSecret
from sopuli.output.palette import Role, paint
from sopuli.output.table import Cell, Column, render_table
from sopuli.plan import Plan

__all__ = ["render_plan"]

#: Column caps, matching the views that already print these strings. An estate
#: truncated at one width in `config show` and another here would read as two
#: estates -- `lock_view` pins `_LOCK` to `config_view`'s `_REF` for this reason.
_ACCOUNT = 24
_TARGET = 28
_SECRET = 52


def render_plan(plan: Plan, *, noun: str = "change") -> str:
    """The plan as text, headed by the count and what it is a count of.

    ``noun`` is what one unit *is* for the calling verb -- ``check`` for a
    verification, ``rotation`` for a rotate. It is a parameter rather than a
    field on :class:`~sopuli.plan.Plan` because it is a word for humans and
    nothing in the JSON contract carries it: the machine-readable answer to the
    same question is ``units[].intent``, which is a closed enum and not a noun.

    **Environments are named, not counted.** ``max_targets`` is a number and
    `confirm_environments` is not; an operator scanning for whether this run
    reaches prod is reading for the word.
    """
    radius = plan.blast_radius
    total = len(plan.units)
    head = (
        f"Plan: {_count(radius.accounts, 'account')} x "
        f"{_count(radius.targets, 'target')} = {_count(total, noun)}"
    )
    if radius.environments:
        head = f"{head}   [{', '.join(_environment(name) for name in radius.environments)}]"

    lines = [head]
    if plan.units:
        lines.extend(["", *_table(plan)])
    if plan.shared:
        lines.extend(["", *_shared(plan.shared)])
    return "\n".join(lines)


def _environment(name: str) -> str:
    """One environment name, with `prod` picked out.

    :attr:`~sopuli.output.palette.Role.PRODUCTION` exists for exactly this: §9
    keys `confirm_environments` on it, and it is the one word on the line worth
    finding without reading. The name is on the line either way -- colour
    reinforces and never carries the meaning, since `NO_COLOR` is honoured.
    """
    return paint(name, Role.PRODUCTION) if name == "prod" else name


def _table(plan: Plan) -> list[str]:
    """One row per unit, in binding order.

    Deliberately not sorted. :func:`~sopuli.config.sharing.shared_secrets` gives
    the same argument: the operator reads this beside the estate table and the
    binding rows, and a third ordering would make one set of names look like
    three.

    INTENT is a column rather than part of the heading because `rotate` puts
    several kinds in it, and a run whose units do not all intend the same thing
    is exactly the run where a header could not have said so. It repeats where
    they do all agree, which costs a narrow column and keeps one reading rule.
    """
    return list(
        render_table(
            [
                Column("ACCOUNT", _ACCOUNT),
                Column("TARGET", _TARGET),
                Column("INTENT"),
                Column("SECRET", _SECRET),
            ],
            [
                [
                    unit.account,
                    unit.target,
                    ", ".join(unit.intent),
                    _secret(unit.secret),
                ]
                for unit in plan.units
            ],
        )
    )


def _secret(secret: dict[str, object] | None) -> Cell | str:
    """``vault:path`` for a unit's document, or a muted placeholder.

    The same spelling `lock status` prints and `lock break` takes, because it
    addresses the same thing: a unit's document is what a lock is keyed on (Q2),
    so an operator reading a plan and then a lock refusal should be matching one
    string rather than translating between two.

    The field and pointer are left off. They say *where in* the document, and the
    plan's question is which documents this run touches -- the parts are in the
    JSON for a consumer that needs them.
    """
    if secret is None:
        return Cell("-", Role.MUTED)
    vault = secret.get("vault")
    path = secret.get("path")
    return f"{vault}:{path}" if vault is not None else str(path)


def _shared(shared: Sequence[SharedSecret]) -> list[str]:
    """What else this run's writes land on, under a heading that says so.

    Sharing is legal and often intended (§7); what it must not be is invisible.
    The heading takes :attr:`~sopuli.output.palette.Role.NOTABLE` -- worth a
    second look, not a problem -- matching `config show`, which prints the same
    finding asked of the whole file rather than of one run.
    """
    heading = paint(f"shared secrets ({_count(len(shared), 'document')}):", Role.NOTABLE)
    rows = render_table(
        [
            Column("SECRET", _SECRET),
            Column("TARGETS"),
            Column("ACCOUNTS"),
        ],
        [
            [
                f"{entry.vault}:{entry.path}" if entry.vault else entry.path,
                ", ".join(entry.targets),
                ", ".join(entry.accounts),
            ]
            for entry in shared
        ],
    )
    return [heading, *rows]


def _count(number: int, noun: str, plural: str | None = None) -> str:
    if number == 1:
        return f"1 {noun}"
    return f"{number} {plural if plural is not None else noun + 's'}"

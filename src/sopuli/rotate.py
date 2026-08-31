"""What ``sopuli creds rotate`` decides, with no I/O in it.

UC-1 §8. The verb is a sequence over parts that already exist -- `generate`
stages a password, `apply` converges the database and promotes the document,
`finish-rollover` closes the window -- and the two properties that make it a verb
rather than a shell script arrived before it: one lock held across the whole
sequence and the fence re-read at every boundary (#282), and the pre-flight that
asks the estate before anything is written (#283).

So what is genuinely new is the *decisions between* the steps, and they are here:

* **which accounts are due**, when ``--max-age-days`` narrows the run;
* **whether the vault agrees afterwards** with what the databases were given,
  which is §8 step 8 and the only step with no home in any existing verb;
* **which of §8's nine steps the exit code should be describing**, since a
  rotation can end at any of them and they do not all mean the same thing.

The sequencing itself is in :mod:`sopuli.cli`, which is the arrangement every
other verb in this tool has with its own decision module.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sopuli import apply as apply_states
from sopuli import status as status_states
from sopuli.config import Binding
from sopuli.exit_codes import ExitCode
from sopuli.payload import CURRENT, stage_layout
from sopuli.secrets import Secret

#: What :func:`select` says about an account ``--max-age-days`` left alone. Two
#: reasons, and they are not the same thing to an operator: one credential is
#: young enough that the schedule does not want it yet, and the other has no
#: rotation this tool has ever recorded.
TOO_YOUNG = "rotated {age}d ago, inside --max-age-days {limit}"
NEVER_ROTATED = "no rotated_at in the vault, so age is unknown"


@dataclass(frozen=True)
class Selection:
    """One declared account, and whether this run is going to rotate it.

    ``reason`` is filled only where ``due`` is ``False``. A run that rotates
    everything it was given has nothing to explain, and an empty string beside
    every row would be a column that only ever carries noise.
    """

    binding: Binding
    age: float | None
    due: bool
    reason: str = ""


def select(
    pairs: Sequence[tuple[Binding, Any]],
    *,
    max_age_days: int | None,
    now: datetime | None = None,
) -> tuple[Selection, ...]:
    """Which of these accounts ``--max-age-days`` leaves in the run.

    ``pairs`` is each binding beside the vault document its credential lives in,
    which is the shape the caller already has -- one document may hold several
    accounts, and each carries its own ``rotated_at`` (UC-1 §3).

    **The age is the vault's and never the database's** (Q9, decided in #87).
    One ``rotated_at`` per secret path however many targets share it, so there is
    nothing to aggregate and no "oldest, newest, or any" rule to invent for an
    account that spans a CDB's PDBs. The database's own
    ``PASSWORD_CHANGE_DATE`` is displayed by `creds status` and acted on by
    nothing.

    **An account whose age is unknown is not selected**, which is
    :func:`sopuli.status.exceeds`'s rule and is reused rather than restated. It
    is the one that could plausibly have gone the other way, so it is worth
    being explicit about why it did not: a freshly adopted estate has no
    ``rotated_at`` anywhere in it, and treating unknown as infinitely old would
    make this tool's first scheduled act against that estate a rotation of every
    credential in it. An operator who wants that asks for it by leaving
    ``--max-age-days`` off, which rotates everything selected and says so in the
    plan.

    With no ``--max-age-days`` every account is due, and the ages are still
    computed -- they are what the run prints beside each row, and a rotation
    nobody filtered still benefits from showing how old the thing it replaced
    was.
    """
    found: list[Selection] = []
    for binding, document in pairs:
        age = status_states.age_days(status_states.rotated_at(document, binding), now=now)
        if max_age_days is None:
            found.append(Selection(binding, age, due=True))
        elif age is None:
            found.append(Selection(binding, age, due=False, reason=NEVER_ROTATED))
        elif status_states.exceeds(age, max_age_days):
            found.append(Selection(binding, age, due=True))
        else:
            found.append(
                Selection(
                    binding,
                    age,
                    due=False,
                    reason=TOO_YOUNG.format(age=age, limit=max_age_days),
                )
            )
    return tuple(found)


def due(selections: Sequence[Selection]) -> list[Binding]:
    """Just the bindings the run will act on, in the order they were given."""
    return [one.binding for one in selections if one.due]


def disagreements(entries: Sequence[tuple[Binding, Secret, Any]]) -> tuple[str, ...]:
    """§8 step 8: the accounts whose promoted ``current`` is not what was applied.

    ``entries`` is each account, the password this run put on its databases, and
    the document **as it was read back** after the promotion -- a second read,
    not the copy the promotion was computed from. Reading back the object the run
    just wrote is the only way this check can find anything: what it is looking
    for is a store that acknowledged a write and then served something else, and
    a replica that is behind is the ordinary way that happens.

    **The comparison never reveals either value.** :class:`~sopuli.secrets.Secret`
    compares by value, so the plaintext stays inside the wrapper and there is no
    ``reveal()`` in this module -- which is invariant 2 working structurally
    rather than by everyone remembering. The return is account names, so a
    disagreement can be reported without the report becoming the leak.

    A document that no longer holds the stage at all counts as a disagreement,
    and deliberately: "the vault does not have it" is the same operational fact
    as "the vault has the wrong one" for the application about to fetch it.
    """
    found: list[str] = []
    for binding, applied, document in entries:
        ref = binding.secret
        if ref is None:
            continue
        stored = stage_layout(ref).read(document, CURRENT)
        if not isinstance(stored, str) or Secret(stored) != applied:
            found.append(binding.account)
    return tuple(found)


def exit_code_for(
    *,
    staged_failures: int,
    applied: Sequence[str],
    promoted: bool,
    promotable: bool,
    disagreed: int,
) -> int:
    """§8's failure table, as one number.

    The table's rows are steps, and the steps are ordered, so this reads in the
    same order the run went through them. Each branch is a row:

    **A staging failure ends the run at step 4**, before any database is touched,
    and that is the caller's rule as much as this function's -- `rotate` does not
    apply a document it failed to stage into. So the state afterwards is the
    table's row 4 exactly: nothing changed in any database, a ``pending`` may
    exist, and re-running is the remedy. Exit 1 rather than 4, because 4 says
    *some targets succeeded and some failed* and here no target was attempted.

    **A read-back disagreement is exit 4** (row 8). The databases hold the new
    password and the promotion was acknowledged, so the estate is not broken --
    but this run cannot assert that applications fetching ``current`` will get
    what was applied, and a rotation that cannot assert that has not finished.
    Re-running `apply` converges it and is safe, which is what makes 4 the honest
    code rather than 1.

    **Everything else is `apply`'s own answer**, unchanged and deliberately so.
    Steps 5, 6 and 7 are `apply` doing what `apply` does, and a rotation that
    exits differently from the `apply` inside it would be two commands describing
    one outcome in two vocabularies -- with the scheduler that reads both left to
    reconcile them.

    The takeover split -- 7 where the run was fenced out before it changed
    anything and 4 where it had already changed something -- is **not** here. It
    stays with the caller for the reason :mod:`sopuli.lock.errors` gives: only
    the command knows what it had applied by then.
    """
    if staged_failures:
        return int(ExitCode.FAILURE)
    if disagreed:
        return int(ExitCode.PARTIAL)
    return apply_states.exit_code_for(applied, promoted=promoted, promotable=promotable)

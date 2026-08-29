"""What `creds status` reports about each account, and what it refuses to (#275).

UC-1 §9's inventory: read-only, **no login attempts**, safe to run anywhere. It
is the least dangerous verb in the tool — `check` at least tries a password, and
this reads two dictionary views and a vault document.

Pure, like the other decision modules, and it borrows `check`'s state vocabulary
for their reason: the verbs describe one estate and must not give it two names.

**The line this module holds is what it will not conclude.** Every column here is
observable without authenticating as the account, and the one question an
inventory cannot answer is the one `check` exists for — *does the vault's
password actually work*. So a healthy row is :data:`~sopuli.check.UNVERIFIABLE`
and says why, rather than ``IN_SYNC``. That reads oddly for a whole run of them
until you notice the alternative: `IN_SYNC` from a command that never asked is a
report of agreement nobody measured, and it would be indistinguishable in a
document from one `check` produced by trying.

**`AGE` is the vault's ``rotated_at`` and nothing else** (Q9, decided in #87).
The database's own `PASSWORD_CHANGE_DATE` is displayed beside it and never acted
on. §9's worked example is two rows sharing a `DB_PW_CHANGED` date and differing
by 82 days of vault age: the same database-side history, two very different
answers depending on which clock is asked. Only the vault's is acted on, because
``rotated_at`` is one value per secret path however many targets share it —
nothing to aggregate, and no "oldest, newest, or any" rule to invent for an
account spanning a CDB's PDBs.

This is the first thing to read ``rotated_at`` back. `apply` has been writing it
since #259 and nothing has needed it until now.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sopuli.check import (
    ACCOUNT_MISSING,
    EXPIRED,
    LOCKED,
    ROLLOVER_ACTIVE,
    UNVERIFIABLE,
    Outcome,
)
from sopuli.clock import as_utc, from_rfc3339, until, utc_now
from sopuli.config.model import Binding
from sopuli.driver.protocol import UserState
from sopuli.payload import PENDING, ROTATED_AT, stage_layout
from sopuli.store.credentials import StoredSecret

__all__ = [
    "PENDING_APPLY",
    "Row",
    "age_days",
    "decide",
    "exceeds",
    "rotated_at",
]

#: A rotation nobody finished: the vault holds a `pending` the database has not
#: been confirmed to have. Knowable without a login, which is what makes it an
#: inventory finding rather than a `check` one.
PENDING_APPLY = "PENDING_APPLY"


@dataclass(frozen=True)
class Row:
    """One (account, target), as the inventory sees it.

    Every field is ``None``-when-unknown rather than defaulted, because an
    inventory's whole job is to distinguish "this is so" from "nobody could
    say". A `DB_PW_CHANGED` of ``None`` is a database whose version does not
    expose it (#87), not an account that has never had its password set.
    """

    binding: Binding
    outcome: Outcome
    #: The store's version for the document this credential lives in.
    version: int | None = None
    #: Days since the vault's ``rotated_at``. ``None`` before the first rotation
    #: this tool performed -- a seeded secret has no stamp, and inventing one
    #: from the document's creation time would report an age for a rotation that
    #: never happened.
    age: float | None = None
    #: The account as the database describes it, or ``None`` where there is no
    #: such account and where the target could not be reached.
    user: UserState | None = None
    #: Whether ``age`` is past the run's ``--max-age-days``.
    over_age: bool = False


def rotated_at(document: Any, binding: Binding) -> datetime | None:
    """When the vault says this account was last rotated, or ``None``.

    Read through the same :class:`~sopuli.payload.StageLayout` the stages go
    through, because the stamp mirrors them: per account in a shared document,
    beside the value it describes (UC-1 §3). A root-level one would describe some
    of the document and not the rest.

    ``None`` covers every way of finding nothing, and the ordinary one is a
    secret this tool has never rotated -- seeded by hand, or written by whatever
    the estate used before. That is an age of *unknown*, not of zero, and
    `--max-age-days` must not select on it either way.

    A stamp that does not parse is also ``None``. It is somebody else's string in
    somebody else's document, and refusing to display a whole inventory over one
    malformed field would be the wrong trade for a read-only verb.
    """
    ref = binding.secret
    if ref is None or document is None:
        return None
    written = stage_layout(ref).read(document, ROTATED_AT)
    if not isinstance(written, str):
        return None
    try:
        return from_rfc3339(written)
    except ValueError:
        return None


def age_days(moment: datetime | None, *, now: datetime | None = None) -> float | None:
    """Days since ``moment``, or ``None``.

    The number `--max-age-days` filters on and `rotate` will select by, so it is
    computed once here rather than in each of them. Rounded to one decimal, which
    is the precision a column reading ``94d`` can carry and more than a rotation
    schedule needs.
    """
    if moment is None:
        return None
    return round((as_utc(now or utc_now()) - as_utc(moment)).total_seconds() / 86400, 1)


def exceeds(age: float | None, limit: int | None) -> bool:
    """Whether ``age`` is past ``limit``.

    ``None`` for either is ``False``, and the first of those is the one worth
    stating: an account whose age is unknown is **not** selected by
    `--max-age-days`. Treating unknown as infinitely old would make the tool's
    first act against a freshly adopted estate a rotation of everything in it,
    which is the opposite of what an operator running an inventory wants to
    discover.
    """
    if age is None or limit is None:
        return False
    return age > limit


def decide(
    user: UserState | None,
    stored: StoredSecret | None,
    document: Any,
    binding: Binding,
) -> Outcome:
    """The state for one row, from what could be seen without authenticating.

    In the order :func:`sopuli.check.decide` establishes -- what the database says
    about the account outranks everything downstream of it, because it is the
    *cause* of whatever anything else would have found.

    * **No account.** ``ACCOUNT_MISSING``. The config declares it and the
      database has not got it, which is exactly the row an inventory exists to
      show: invariant 5 makes the config the whitelist, so this is a discrepancy
      between the two and not an omission to hide.
    * **Locked or expired.** Reported as itself.
    * **A staged ``pending``.** ``PENDING_APPLY``: a rotation nobody finished.
      Visible in the vault alone, which is what makes it an inventory finding --
      and it is the one row here that names a next step.
    * **An open rollover window.** ``ROLLOVER_ACTIVE``, with however long is left
      on it. Two passwords authenticate until it closes, and an operator
      surveying an estate should see the deadline.
    * **Everything else.** ``UNVERIFIABLE``, saying so: no login was attempted,
      and `creds check` is the verb that compares. See the module docstring for
      why this is not ``IN_SYNC``.

    ``document`` is the raw secret document and ``binding`` addresses this
    account inside it, which is what the ``pending`` check needs -- the resolved
    ``stored`` knows only the stage it was asked for. ``stored``'s absence is
    reported in the detail rather than as a state of its own: a declared account
    the vault has nothing for is a gap in the file's own story, and an inventory
    should say it in words rather than borrow a state that means something else.
    """
    if user is None:
        return Outcome(
            ACCOUNT_MISSING, "the config declares this account; the database has no such user"
        )
    if user.locked:
        return Outcome(LOCKED, f"account is {user.status.lower()}")
    if user.expired:
        return Outcome(EXPIRED, f"account is {user.status.lower()}")
    if _has_pending(document, binding):
        return Outcome(
            PENDING_APPLY,
            "a password is staged that this database is not confirmed to hold "
            "-- run `sopuli creds apply`",
        )
    if user.rollover_active:
        # With the deadline where there is one. The state alone says two
        # passwords work; what an operator surveying an estate needs is how long
        # for, because that is what decides whether tonight's job has to run
        # `creds finish-rollover` or can leave the window to elapse.
        left = until(user.rollover_ends_at)
        deadline = "" if left is None else f", {left} left"
        return Outcome(
            ROLLOVER_ACTIVE,
            f"a rollover window is open{deadline}; both passwords authenticate",
        )
    if stored is None:
        return Outcome(UNVERIFIABLE, "the vault holds no password for this account")
    return Outcome(UNVERIFIABLE, "no login was attempted; `sopuli creds check` compares")


def _has_pending(document: Any, binding: Binding) -> bool:
    """Whether a ``pending`` is staged for this account.

    Through the binding's own ref rather than the resolved credential: `stored`
    knows only the stage it was asked for, and this asks about a different one.
    Same :class:`~sopuli.payload.StageLayout` every other stage-aware read uses,
    so "where `pending` lives" keeps one answer in this codebase.
    """
    ref = binding.secret
    if ref is None or document is None:
        return False
    return stage_layout(ref).read(document, PENDING) is not None

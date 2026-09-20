"""What colour is allowed to mean (``03-json-output.md`` §1).

:mod:`sopuli.output.color` answers *is colour on*. This answers *what may be
coloured*, and the two are separate on purpose: the gate is a property of the
run, the palette is a property of the thing being rendered.

Two rules from §1 bind everything here, and both are structural rather than
aspirational:

**Colour never carries meaning alone.** Every role below decorates a word that
is already there -- ``prod``, ``override``, ``non-production``, ``-``. Nothing is
distinguishable only by being coloured, so the ``NO_COLOR`` path is lossless by
construction rather than by care, and ``tests/test_palette.py`` asserts exactly
that: strip the escapes and the output is the plain output, byte for byte.

**The palette maps onto what the machine view emits.** §1 wrote that rule
against the result vocabulary (``state``, ``by_state``, ``drift``), because
results were the only text output anticipated. ``config show`` came first and
has no states at all, so these roles map onto the fields its ``config`` section
*does* emit -- ``overridden``, ``environment``, ``non_production``, and absence.
Same vocabulary, reinforced; not a second one that could disagree with it.

**The result palette arrived in #395**, which is what that deferral was waiting
for. Four roles -- :attr:`Role.GOOD`, :attr:`Role.ATTENTION`, :attr:`Role.BAD`,
:attr:`Role.INCONCLUSIVE` -- and :func:`role_for_state` is the one function that
decides which a state gets. Before it, four views each kept their own subset of
the state enum and painted it :attr:`Role.NOTABLE`: ``check`` coloured ``DRIFT``
and ``apply`` did not, ``apply`` coloured ``ERROR`` and ``check`` did not. Same
state, same run, different emphasis depending on which verb printed it -- which
is precisely the "yellow meaning three things in three views" this indirection
exists to prevent. The indirection was here; nobody had used it for states.

Styling goes through :func:`paint` rather than ``click.style`` at call sites, so
the set of things a role can do stays visible in one file -- and so a renderer
cannot invent a colour that means nothing to anyone else.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Any

import click

from sopuli.account_list import DECLARED
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
from sopuli.reset import RESET
from sopuli.store.protocol import DEGRADED, OK, UNREACHABLE

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sopuli.output.table import Cell


class Role(StrEnum):
    """What a piece of text *is*, never what colour it should be.

    A renderer names the role; this file decides how it looks. That is what
    keeps "yellow" from meaning three different things in three views.
    """

    HEADING = "heading"
    """A section name or a column heading. Structure, not data."""

    BANNER = "banner"
    """The project's own name, drawn large. Neither structure nor data (#413).

    The only role here that decorates something a reader never has to interpret,
    which is why it is allowed to reuse cyan without weakening what cyan means in
    a result table: it appears on exactly one screen, ``sopuli about``, and that
    screen contains no table, no state and no target. Nothing on it could be
    mistaken for :attr:`GOOD`, because nothing on it is a row.

    It is a role rather than a ``click.style`` call at the call site for the
    reason this module exists at all -- a view that picked its own colour would
    be a second authority on what colours mean."""

    MUTED = "muted"
    """A value that is not there. The placeholder is already visible; this stops
    a column of them from competing with the values around it."""

    NOTABLE = "notable"
    """Something that departs from the norm around it and is worth a second
    look: a target an override rewrote, a store marked non-production, a
    warning. Not a problem -- problems get an exit code, not a colour."""

    PRODUCTION = "production"
    """The `prod` environment, wherever it appears. The one distinction on a
    `config show` screen worth finding without reading: `01-configuration.md` §9
    keys `confirm_environments` on it, and it is what `--select env=prod` is
    about to touch."""

    GOOD = "good"
    """This account and this target agree, and nobody has to do anything.

    One state, `IN_SYNC`, and it is the only role here that means *stop reading*.
    Worth a colour of its own precisely because most rows on a healthy estate are
    this one: what a reader is looking for is the row that is **not**."""

    ATTENTION = "attention"
    """Something is true that a person has to act on, and the run is fine.

    `DRIFT` is the case this exists for -- exit code 3, and the reason `check` is
    schedulable. `PENDING_APPLY` and `ROLLOVER_ACTIVE` join it because both
    describe work that is staged or half-done rather than wrong, and `VAULT_ONLY`
    because a password promoted with no database behind it is the same shape of
    unfinished."""

    BAD = "bad"
    """The tool could not do the job, or the estate is not in a state it can.

    Distinct from :attr:`ATTENTION` because the reader's next action differs: a
    drifted account is repaired by running `apply`, and an `ERROR` or a
    `LOCKED` account is not repaired by running anything until somebody has
    looked. Distinct from :attr:`INCONCLUSIVE` because these are answers."""

    INCONCLUSIVE = "inconclusive"
    """No answer, and the absence is the finding.

    Dim rather than coloured, and that is the decision: a row nothing could be
    concluded about must not compete with a row that says something, and must
    not read as either good or bad. `UNVERIFIABLE` always carries *why* beside
    it, and `SKIPPED` is a row the tool deliberately did not act on."""


#: Role to ``click.style`` keywords. Kept small and conventional on purpose --
#: a palette a reader has to learn is a palette that has stopped helping.
_STYLES: dict[Role, dict[str, Any]] = {
    Role.HEADING: {"bold": True},
    Role.BANNER: {"fg": "cyan", "bold": True},
    Role.MUTED: {"dim": True},
    Role.NOTABLE: {"fg": "yellow"},
    Role.PRODUCTION: {"fg": "red", "bold": True},
    Role.GOOD: {"fg": "cyan"},
    Role.ATTENTION: {"fg": "yellow"},
    Role.BAD: {"fg": "red", "bold": True},
    Role.INCONCLUSIVE: {"dim": True},
}

#: What a state means to a reader, which is not always what it means to the exit
#: code -- see :func:`role_for_state`.
_STATE_ROLES: dict[str, Role] = {
    IN_SYNC: Role.GOOD,
    DRIFT: Role.ATTENTION,
    PENDING_APPLY: Role.ATTENTION,
    ROLLOVER_ACTIVE: Role.ATTENTION,
    VAULT_ONLY: Role.ATTENTION,
    ERROR: Role.BAD,
    ACCOUNT_MISSING: Role.BAD,
    LOCKED: Role.BAD,
    EXPIRED: Role.BAD,
    UNVERIFIABLE: Role.INCONCLUSIVE,
    SKIPPED: Role.INCONCLUSIVE,
    # `account list`'s ordinary row (#490), and dim for `creds status`'s reason
    # rather than by analogy: neither verb reports a state that means the
    # credential is healthy, because neither asks. `DECLARED` says the
    # declaration matched and nothing about the password -- so it must not
    # compete with a row that does say something, and `IN_SYNC` stays the only
    # state a reader can stop reading at.
    DECLARED: Role.INCONCLUSIVE,
    # A reset that happened (#441). **`ATTENTION`, not `GOOD`**, and the first
    # draft had it the other way round until `test_the_converged_state_is_the_
    # only_good_one` refused it -- rightly, and the rule it enforces is the
    # reason: `IN_SYNC` is the one row a reader can stop at, and a second `GOOD`
    # would make the column stop answering *what do I have to look at*.
    #
    # `ATTENTION` is also the honest answer here rather than a concession. A
    # reset leaves work: the password is on a screen and has to reach a person,
    # and that person must change it at first logon. A row saying *nothing to
    # see* would be wrong about the one path whose whole premise is that
    # somebody is watching it.
    RESET: Role.ATTENTION,
}


#: A store's health, which is a second vocabulary and not a second palette
#: (#395). The same four roles, mapped from ``StoreHealth.status`` -- one place
#: for the same reason :data:`_STATE_ROLES` is one place, and the reason is
#: `doctor` and `creds` printing the same word about the same store.
#:
#: :data:`~sopuli.store.protocol.DEGRADED` is :attr:`Role.ATTENTION` rather than
#: :attr:`Role.BAD` deliberately, and the distinction is the one that module
#: already draws: a sealed or standing-by store **answered**, and the reader's
#: next move is to go and look at the vault. An unreachable one did not answer,
#: and sends them to the network instead.
_HEALTH_ROLES: dict[str, Role] = {
    OK: Role.GOOD,
    DEGRADED: Role.ATTENTION,
    UNREACHABLE: Role.BAD,
}


def role_for_health(status: str) -> Role | None:
    """Which role a store's health gets. ``None`` for a word that is not one."""
    return _HEALTH_ROLES.get(status)


def role_for_state(state: str) -> Role | None:
    """Which role a result state gets. The one place that decides (#395).

    Four views used to keep their own subset of the state enum and paint it
    :attr:`Role.NOTABLE`, which is how ``DRIFT`` came to be coloured by `check`
    and not by `apply` while ``ERROR`` was coloured by `apply` and not by
    `check`. One state, one run, different emphasis depending on which verb
    printed it. This function is the fix, and a view that hand-rolls a subset
    again is re-introducing the bug rather than adding a feature.

    **The grouping is not `check`'s exit-code grouping, and the difference is
    deliberate.** :func:`sopuli.check.is_inconclusive` counts
    ``ACCOUNT_MISSING``, ``LOCKED`` and ``EXPIRED`` as inconclusive, because none
    of them says anything about *the password* -- which is the right question for
    an exit code. It is the wrong question for a colour: a locked account is not
    an absence of news, it is news, and dimming it would tell a reader to look
    past the row they most need to see. So those three are :attr:`Role.BAD` here
    and inconclusive there, and the two classifications answer different
    questions rather than disagreeing. Only ``UNVERIFIABLE`` and ``SKIPPED`` --
    where the tool genuinely learned nothing and deliberately did nothing -- are
    :attr:`Role.INCONCLUSIVE`.

    ``None`` for a string that is not a state, which is not a failure: a caller
    may hand this whatever is in a cell, and an unknown value renders plain
    rather than raising. A state added to the schema and not to :data:`_STATE_ROLES`
    therefore loses its colour and keeps its word, which is the safe direction --
    ``tests/test_palette.py`` asserts the map covers the enum so it does not
    happen quietly.
    """
    return _STATE_ROLES.get(state)


def absent_cell(value: str | None, placeholder: str = "-") -> Cell | str:
    """A value, or a dimmed placeholder where there is not one.

    The idiom six views had already written by hand, made callable so the
    seventh does not have to decide the placeholder for itself. :attr:`Role.MUTED`
    is the established meaning -- a column of placeholders must not compete with
    the values beside it -- and the point is that ``-`` keeps meaning the same
    thing in every table rather than being dim in some and plain in others.
    """
    from sopuli.output.table import Cell

    return value if value else Cell(placeholder, Role.MUTED)


def state_cell(state: str) -> Cell | str:
    """A table cell for ``state``, coloured by :func:`role_for_state`.

    Returns the bare string where there is no role, so a table's plain rows stay
    plain strings and only the ones that mean something carry a
    :class:`~sopuli.output.table.Cell`. Imported by every result view, which is
    what makes "one function decides" true at the call sites rather than only in
    this module.

    :class:`~sopuli.output.table.Cell` lives in :mod:`sopuli.output.table`, which
    imports *this* module -- so the import is under ``TYPE_CHECKING`` and the
    runtime one is inside the function. The annotation is the real type either
    way, which matters: returning ``Any`` here would silently switch off type
    checking in every view that calls it, and four of them do.
    """
    from sopuli.output.table import Cell

    role = role_for_state(state)
    return Cell(state, role) if role is not None else state


def paint(text: str, role: Role | None = None) -> str:
    """Style ``text`` for ``role``, or return it unchanged.

    Never asks whether colour is on. :class:`~sopuli.output.emit.Emitter` owns
    that and strips escapes when the answer is no -- the same shape as redaction,
    where a guarantee held in one place cannot be lost by a call site that
    forgot. A renderer that checked for itself would be a second authority, and
    the two would eventually disagree.

    Empty text is left alone so that a blank cell does not become two escape
    sequences wrapped around nothing.
    """
    if role is None or not text:
        return text
    return click.style(text, **_STYLES[role])

"""Resolving `personal_accounts:` the other way round (UC-2 §2).

:mod:`sopuli.personal` answers *does this rule admit that account* — a yes-or-no
question about one name, which is what a mutating verb needs. This answers *which
accounts does this rule admit*, which is what a **listing** verb needs, and the two
are not the same question reversed: one is a lookup and the other is a query
against a database.

**This is what H1 promised.** A predicate amends invariant 5's first sentence —
what counts as *declared* — and the cost H1 accepted and stated is that
membership is controlled by whoever assigns the profile or grants the role, not
by whoever reviews the file. The mitigation is that the tool can *show* you the
set, because an operator cannot review a whitelist they cannot enumerate.

**It widens nothing.** Invariant 5's second sentence is untouched: a mutating verb
still requires the account named on the command line and refuses any name the
predicate does not admit. What is produced here is a report.

**Two refusals and one non-refusal**, which is §2's asymmetry and the whole of why
:meth:`~sopuli.driver.protocol.Session.resolve_role` exists beside
:meth:`~sopuli.driver.protocol.Session.accounts_matching`:

* a predicate naming a profile or role that **does not exist** is a misspelling,
  and is refused at plan time (invariant 4);
* a predicate that exists and matches **no accounts** is a true answer about
  today's estate, and is not an error;
* two rules admitting one account is ordinary; two naming different policies is
  refused, by :func:`~sopuli.personal.declared_on`, for the reason it gives.

Both of the first two produce an empty set, which is exactly why the empty set
cannot be the thing that decides between them.

**The database work is the caller's.** This module takes what a session returned
and assembles rows, so every rule in it is tier 0 (``04-testing.md`` §4) and none
needs a container to test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sopuli.config.model import Config, PersonalAccountRule
from sopuli.driver.protocol import UserState
from sopuli.personal import declared_on, rules_for

#: What `account list` reports where a column has no value. The dash is the
#: honest answer rather than a gap, and `SOPULI-W021`'s rule applies to every one
#: of them: a documented column that vanishes with nothing saying why is a hole in
#: the contract, so an absence is accompanied by a diagnostic naming which absence
#: it is (UC-2 §2, §3.4).
ABSENT = "-"

#: ``results[].state`` for an account the declaration matched and the database
#: has. Not a state in the mutating sense -- this verb changes nothing -- but the
#: schema requires the field and this is what is true of the row.
#:
#: Defined here rather than in the view for an import reason worth stating: the
#: palette maps every published state to a role, and a state defined in a view
#: that already imports the palette could not be read by it. Every other verb's
#: states live in its logic module for the same reason.
DECLARED = "DECLARED"

#: The declaration named it and the database does not have it. UC-1's word,
#: reused deliberately: it means the same thing here, and a second spelling of
#: one fact is how a consumer ends up having to match two.
ACCOUNT_MISSING = "ACCOUNT_MISSING"

#: A target that could not be answered. **Never** :data:`ACCOUNT_MISSING`, which
#: is a fact about an estate rather than about a run -- see
#: :attr:`Row.unreachable`.
ERROR = "ERROR"


@dataclass(frozen=True)
class Resolution:
    """One rule, and the account names it turned out to admit on one target.

    ``names`` is what the *database* gave back for a predicate, and what the file
    wrote for an enumerated rule — in both cases the spelling that will be shown.
    An enumerated rule's names are reported whether or not the account exists,
    because a declared account that is missing is a finding rather than something
    to omit: §2 asks what the declaration matched, and "nothing, and here is what
    it asked for" is an answer.
    """

    rule: PersonalAccountRule
    names: tuple[str, ...]

    @property
    def matched_nothing(self) -> bool:
        """Whether this rule admitted no account here — a true answer, not an error."""
        return not self.names


@dataclass(frozen=True)
class Notice:
    """A finding about one row, with its ``SOPULI-Wnnn`` code (J3)."""

    code: str
    message: str


@dataclass(frozen=True)
class Row:
    """One account on one target, as the listing reports it."""

    account: str
    target: str
    #: The rule that admitted it, for the ``DECLARED BY`` column. `None` only
    #: where the account came from an enumerated rule and the database has no
    #: such account, so nothing could be resolved against it.
    rule: PersonalAccountRule | None
    state: UserState | None
    #: When the store's reset record says this account was last reset, or `None`
    #: where there is no record, no journal configured, or it could not be read.
    #: Three absences with one rendering and three different diagnostics — §3.4.
    reset_at: str | None = None
    #: Findings about this row that belong beside it rather than at the run level.
    notices: tuple[Notice, ...] = field(default_factory=tuple)
    #: Why this target could not be answered at all, where it could not.
    #:
    #: Distinct from ``state is None``, and that distinction is the whole reason
    #: the field exists: an account the declaration names and the database does
    #: not have is ``ACCOUNT_MISSING``, a **fact about the estate**, while a
    #: target that could not be reached is ``ERROR`` and a fact about this run.
    #: Inferring the first from the second would report a down target as a
    #: missing account.
    unreachable: Any | None = None

    @property
    def exists(self) -> bool:
        """Whether the database has this account at all."""
        return self.state is not None

    @property
    def failed(self) -> bool:
        """Whether this row is a target that could not be answered."""
        return self.unreachable is not None


def enumerated_names(rule: PersonalAccountRule) -> tuple[str, ...]:
    """What an enumerated rule declares, in file order.

    File order rather than sorted, because the file is the whitelist and a
    reviewer reads the listing against it. Sorting would be tidier and would make
    the two harder to compare, which is the opposite of what this verb is for.
    """
    return rule.accounts


def rules_on(config: Config, target: str) -> tuple[PersonalAccountRule, ...]:
    """Every `personal_accounts:` rule that applies to ``target``.

    A thin re-export of :func:`sopuli.personal.rules_for`, named for the question
    this module asks. It is here so a reader of the listing verb finds the
    selector rule without having to know that the *mutating* verb's module is
    where target selection lives.
    """
    return rules_for(config, target)


def rule_for(
    config: Config,
    account: str,
    target: str,
    *,
    profile: str | None = None,
    roles: tuple[str, ...] = (),
) -> PersonalAccountRule | None:
    """Which rule to credit an account to, refusing a policy collision.

    :func:`~sopuli.personal.declared_on` unchanged, and deliberately so: the
    listing verb must answer *declared by what* exactly as the mutating verb does,
    or the two would disagree about an estate on which one of them refuses. In
    particular the two-rules-two-policies refusal fires here too — a listing that
    quietly showed the first match would be the place an operator formed the wrong
    belief before running the verb that refuses.
    """
    return declared_on(config, account, target, profile=profile, roles=roles)


def cross_declared(config: Config, account: str) -> str | None:
    """The application that also declares ``account``, if one does.

    **The collision a file cannot see.**
    :func:`~sopuli.config.personal_accounts.reject_cross_declaration` refuses a
    name declared both as an application account and an enumerated personal one,
    at load, and its docstring says what it cannot reach: an account a *predicate*
    admits and an application declares is a fact about a database, so no validator
    can catch it. H1 accepted that cost and said the verb resolving the predicate
    is where it has to be caught. This is that verb.

    A **notice rather than a refusal**, and the asymmetry is deliberate. The
    load-time rule refuses because a file can be fixed before anything runs; here
    the estate already is what it is, and refusing to *describe* it would leave an
    operator with an ambiguous whitelist and no way to look at it. Describing the
    ambiguity is what lets them resolve it.
    """
    folded = account.casefold()
    for application in config.applications:
        if any(declared.casefold() == folded for declared in application.accounts):
            return application.label
    return None

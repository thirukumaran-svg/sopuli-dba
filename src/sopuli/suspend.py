"""Deciding whether one account may be suspended (UC-2, #463).

The DDL is the driver's (:meth:`~sopuli.driver.protocol.Session.suspend_account`)
and so is the question of whether it changes anything. What is left, and what is
here, is the question that has to be answered **before** anything is issued: may
this run touch this account at all?

Two gates, in this order, and the order is the point:

1. **is it declared** -- invariant 5, which H1 (#449) made harder than a list
   lookup by allowing a predicate. :mod:`sopuli.personal` answers it from the
   state the run has already read;
2. **do the guardrails allow it** -- ``02-oracle-privileges.md`` §4's five checks,
   unchanged and shared with every other mutating verb, because locking
   ``DBSNMP`` ought to refuse exactly as rotating it does.

**Pure, and it issues nothing.** It takes the :class:`UserState` the caller read
and returns a decision, so every refusal in it is tier 0 (``04-testing.md`` §4)
and none of them needs a database to test. The caller is what turns a decision
into a statement.

**One account, and the plan is the whole blast radius.** UC-2 §2 requires a
mutating verb to name its account on the command line and refuse anything the
declaration does not admit, so there is no shape here that returns a set to act
on. An offboarding is one person leaving.
"""

from __future__ import annotations

from dataclasses import dataclass

from sopuli.config.model import Config
from sopuli.driver.guardrails import Review, review
from sopuli.driver.protocol import UserState
from sopuli.personal import declared_on

#: ``results[].state`` words this verb uses, all of them already in the run
#: schema's ``state`` enum -- a verb that needed a new one would be saying
#: something the contract has no word for, and that is a schema question rather
#: than a verb's to settle.
LOCKED = "LOCKED"
ACCOUNT_MISSING = "ACCOUNT_MISSING"
SKIPPED = "SKIPPED"


@dataclass(frozen=True)
class Decision:
    """Whether to issue ``ALTER USER … ACCOUNT LOCK``, and what to report either way."""

    proceed: bool
    state: str
    detail: str
    #: The §4 review, where one was run. ``None`` where the account was not found
    #: or not declared -- there was nothing to review, and an empty
    #: :class:`Review` would read as *every check passed*.
    review: Review | None = None

    @property
    def refused(self) -> bool:
        """Whether this decision is a refusal rather than an ordinary no-op."""
        return not self.proceed


def decide(
    state: UserState | None,
    *,
    config: Config,
    account: str,
    target: str,
    force: bool = False,
) -> Decision:
    """May this run suspend ``account`` on ``target``?

    ``state`` is ``None`` where the account does not exist there, which is a
    finding rather than an error: the tool creates nothing (Q8), and an estate
    where a person has an account on four of nine targets is ordinary.

    **`--force` waives guardrails 2 to 5 and never the declaration**, which is
    invariant 5's own sentence: ``--force`` overrides other guardrails, never the
    whitelist. That is enforced by :func:`~sopuli.driver.guardrails.review` rather
    than here, and it is why the declaration is expressed *through* the review's
    check 1 instead of short-circuiting it -- one refusal vocabulary, one place
    that decides what ``--force`` may do.
    """
    if state is None:
        return Decision(
            proceed=False,
            state=ACCOUNT_MISSING,
            detail="the account does not exist on this target",
        )

    rule = declared_on(
        config,
        state.name,
        target,
        profile=state.profile,
        roles=state.roles,
    )
    # Check 1 takes the declared set, so handing it this account's own name where
    # a rule admits it -- and nothing where none does -- expresses the predicate
    # in the vocabulary the guardrails already refuse in. The alternative was a
    # second kind of "not declared" refusal that renders differently from the one
    # every other verb produces.
    found = review(state, declared=[state.name] if rule is not None else [], force=force)

    if not found.permitted:
        return Decision(
            proceed=False,
            state=SKIPPED,
            detail="; ".join(refusal.reason for refusal in found.refusals),
            review=found,
        )

    return Decision(
        proceed=True,
        state=LOCKED,
        detail=f"declared by {rule.label}" if rule is not None else "declared",
        review=found,
    )

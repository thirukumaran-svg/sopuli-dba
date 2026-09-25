"""Deciding whether one account's password may be expired (UC-2, #525).

The DDL is the driver's (:meth:`~sopuli.driver.protocol.Session.expire_password`),
and so is the question of whether it changes anything. The question left, which
has to be answered **before** anything is issued, is the same one
:mod:`sopuli.suspend` answers: may this run touch this account at all?

**The same two gates, deliberately.** Declared (invariant 5, with H1's predicate)
and permitted by ``02-oracle-privileges.md`` §4's guardrails. Nothing about
either depends on which statement follows, so this module delegates rather than
restating them. A second copy is the one that would drift. What differs is only
the word a permitted row reports: ``EXPIRED``, the state the verb produces.

**Pure, and it issues nothing**, as :mod:`sopuli.suspend` is -- every refusal is
tier 0.
"""

from __future__ import annotations

from sopuli.config.model import Config
from sopuli.driver.protocol import UserState
from sopuli.suspend import ACCOUNT_MISSING, SKIPPED, Decision
from sopuli.suspend import decide as _decide

#: ``results[].state`` for a row this verb expired, or found expired. Already in
#: the run schema's ``state`` enum, where `creds check` has used it since the
#: contract was written.
EXPIRED = "EXPIRED"

__all__ = ["ACCOUNT_MISSING", "EXPIRED", "SKIPPED", "Decision", "decide"]


def decide(
    state: UserState | None,
    *,
    config: Config,
    account: str,
    target: str,
    force: bool = False,
) -> Decision:
    """May this run expire ``account``'s password on ``target``?

    :func:`sopuli.suspend.decide`, reporting ``EXPIRED`` where it proceeds. Its
    docstring is the specification: a missing account is a finding rather than
    an error, and ``--force`` waives guardrails 2 to 5 and never the whitelist.
    """
    return _decide(
        state,
        config=config,
        account=account,
        target=target,
        force=force,
        proceeding_as=EXPIRED,
    )

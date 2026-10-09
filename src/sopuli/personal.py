"""Whether a personal account is declared, and by which rule (H1).

Invariant 5 says the config is the whitelist. For an application account that is
a list lookup; for a personal account H1 added a second form -- a **predicate**
over a profile or a role, resolved against the database -- so "is this account
declared" stops being answerable from the file alone. This module is that answer.

**It is pure, and it is not a query.** The two inputs a predicate needs, the
account's profile and its roles, are already on the
:class:`~sopuli.driver.protocol.UserState` that every mutating verb reads before it
does anything: the profile because `creds status` reports it and UC-1 §5 sets it, the
roles because guardrail 4 refuses ``DBA`` and friends. So a predicate costs no extra
round trip, and this layer takes the two values rather than a cursor -- which keeps it
tier 0 (``04-testing.md`` §4) and keeps the resolution testable without a database.

**A predicate never widens what a mutating verb may touch.** UC-2 §2 is explicit:
the verb requires the account named on the command line and refuses any name the
predicate does not admit, so one run touches exactly one account. Nothing here
returns a set of accounts to act on; it answers a yes-or-no question about one
name. `account list` is the verb that resolves a rule the other way, and it
mutates nothing.

**Where the inputs are missing, the answer is no.** That is the safe direction and
it is the opposite of :class:`~sopuli.driver.oracle.accounts.RolesUnreadableError`'s
problem: there, an unreadable ``DBA_ROLE_PRIVS`` read as "holds no dangerous role"
and turned a guardrail into a silent pass. Here an unreadable role set means a
rule does not admit the account, so the verb refuses to act. Both cases follow the
same rule -- a check with no input must not read as permission -- and it points
opposite ways because one check permits and the other forbids.
"""

from __future__ import annotations

from collections.abc import Collection

from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.model import Config, PersonalAccountRule
from sopuli.config.selection import select


def rules_for(config: Config, target: str) -> tuple[PersonalAccountRule, ...]:
    """Every `personal_accounts:` rule that applies to ``target``.

    A rule's ``targets:`` selector is the same one an application entry takes, so
    the same resolver answers it -- including the default, which is every target.
    """
    return tuple(
        rule
        for rule in config.personal_accounts
        if target in {expanded.name for expanded in select(config, rule.targets)}
    )


def admits(
    rule: PersonalAccountRule,
    account: str,
    *,
    profile: str | None = None,
    roles: Collection[str] = (),
) -> bool:
    """Whether ``rule`` declares ``account``.

    Comparison is case-folded throughout, for
    :func:`~sopuli.driver.guardrails.is_declared`'s reason: a config file writes
    ``jdoe`` and Oracle stores ``JDOE``, since an unquoted identifier is
    upper-cased on the way in, and comparing exactly would refuse every correctly
    declared account.
    """
    folded = account.casefold()

    if rule.accounts:
        return folded in {name.casefold() for name in rule.accounts}

    if rule.profile is not None:
        # `None` is a profile that could not be read, not a profile named
        # `None`, so it admits nothing -- see the module docstring on why the
        # missing-input direction differs from guardrail 4's.
        return profile is not None and profile.casefold() == rule.profile.casefold()

    if rule.role is not None:
        return rule.role.casefold() in {held.casefold() for held in roles}

    # Unreachable through the config layer, which refuses an entry declaring
    # none of the three. Answered rather than asserted: a rule that says
    # nothing admits nothing, which is invariant 5's own default.
    return False


def rules_admitting(
    config: Config,
    account: str,
    target: str,
    *,
    profile: str | None = None,
    roles: Collection[str] = (),
) -> tuple[PersonalAccountRule, ...]:
    """Every rule that declares ``account`` on ``target``, in file order.

    More than one is ordinary and not by itself a problem -- an enumerated entry
    and a profile predicate can both be true of one person, and both carry the
    same guarantee. What it costs is settled in :func:`declared_on`.
    """
    return tuple(
        rule
        for rule in rules_for(config, target)
        if admits(rule, account, profile=profile, roles=roles)
    )


def declared_on(
    config: Config,
    account: str,
    target: str,
    *,
    profile: str | None = None,
    roles: Collection[str] = (),
) -> PersonalAccountRule | None:
    """The rule that declares ``account`` on ``target``, or ``None``.

    The **rule** rather than a bool, because a caller that refuses needs to say
    which declaration it was looking for and a caller that proceeds should be
    able to name what admitted the account. An audit record saying "declared"
    without saying by what is the kind of record nobody can check afterwards.

    **Two rules admitting one account is ordinary; two rules naming different
    policies is not**, and the difference is what this refuses. Membership itself
    is not ambiguous -- both rules say the same thing about the same account, and
    unlike the duplicate-name rule they carry the same guarantee. A
    ``policy:`` is a different matter: returning the first match would make which
    password policy applies depend on the order somebody happened to write two
    entries in, which is exactly the silent, file-order-dependent answer
    invariant 5 exists to keep out of a whitelist.

    It cannot be caught at load time, which is why it is here: whether a
    predicate admits a given account is a fact about a database. So this is a
    plan-time refusal (invariant 4) naming both rules, raised before anything is
    issued.
    """
    admitting = rules_admitting(config, account, target, profile=profile, roles=roles)
    if not admitting:
        return None

    policies = {rule.policy for rule in admitting if rule.policy is not None}
    if len(policies) > 1:
        named = ", ".join(sorted(f"`{policy}`" for policy in policies))
        raise ConfigError(
            f"account {account!r} on target {target!r} is declared by "
            f"{len(admitting)} personal_accounts rules naming different policies ({named})",
            at=ROOT.key("personal_accounts"),
            hint=(
                "the rules are "
                + "; ".join(rule.label for rule in admitting)
                + " -- give them the same `policy:`, or narrow one with `targets:`"
            ),
        )
    return admitting[0]

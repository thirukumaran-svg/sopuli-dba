"""The `personal_accounts:` section: who the tool may hand a password to (H1, #449).

UC-2's accounts belong to **people**, and an application entry is the wrong shape
for them: `01-configuration.md` §1 defines one as *these accounts are mastered by
these secrets*, and names three things that depend on that being true --
``check``'s desired state, the account->secret mapping, and fan-out. A personal
account has none of the three, so H1 gave it a section of its own.

**Two ways to be declared, and only one of them is a list of names.** An estate
with four hundred developers does not review a four-hundred-line whitelist, so an
entry may instead carry a **predicate** -- ``profile:`` or ``role:`` -- resolved
against the database at run time. That amends invariant 5's first sentence, what
counts as *declared*, and leaves its second exactly as written: a predicate never
widens what a mutating verb may touch, because a reset names its account on the
command line and refuses any name the predicate does not admit.

**Resolution is not here.** A predicate is a question for a database -- which
accounts carry this profile, who holds this role -- so this module validates the
*shape* of the question and nothing else. Whether ``profile: DEV_USERS`` names a
profile that exists is a plan-time refusal belonging to the verb that resolves it
(`account list`, UC-2 §2), and §2's asymmetry says what it answers: a profile that
does not exist is a misspelling and is refused; one that exists and matches no
accounts is a true answer about today's estate and is not an error.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.applications import build_target_selector
from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.fields import (
    mapping,
    optional_string,
    reject_unknown_keys,
    sequence,
    string_list,
)
from sopuli.config.model import Application, PersonalAccountRule

PERSONAL_ACCOUNT_KEYS = ("accounts", "profile", "role", "targets", "policy")

#: The three ways an entry says *which* accounts, of which it may use exactly
#: one. Ordered as the reference documents them, since a message lists them.
DECLARATION_KEYS = ("accounts", "profile", "role")


def build_personal_accounts(document: dict[str, Any]) -> tuple[PersonalAccountRule, ...]:
    """Normalise `personal_accounts:` into entries. Absent means none declared."""
    if "personal_accounts" not in document:
        return ()

    at = ROOT.key("personal_accounts")
    entries = sequence(document["personal_accounts"], at=at)
    if not entries:
        # An empty section is a file that started to declare personal accounts
        # and stopped. Absent means "none"; present and empty means somebody
        # meant to write something, and a silent "none" would look like it took.
        raise ConfigError(
            "must declare at least one personal account entry",
            at=at,
            hint="delete the section to declare none",
        )

    built = [_build_entry(entry, at=at.index(index)) for index, entry in enumerate(entries)]
    _reject_duplicate_names(built, at=at)
    return tuple(built)


def _build_entry(raw: Any, *, at: KeyPath) -> PersonalAccountRule:
    entry = mapping(raw, at=at)
    reject_unknown_keys(entry, allowed=PERSONAL_ACCOUNT_KEYS, at=at)

    declared = [key for key in DECLARATION_KEYS if key in entry]
    if not declared:
        raise ConfigError(
            "must declare `accounts:`, `profile:` or `role:`",
            at=at,
            hint="invariant 5: the config is the whitelist, so nothing is declared by default",
        )
    if len(declared) > 1:
        # Two would leave the entry meaning either the union or the
        # intersection, and neither reading is more obvious than the other --
        # which is the shape of ambiguity invariant 5 exists to keep out of a
        # whitelist. Two entries say the union, unambiguously.
        named = ", ".join(f"`{key}:`" for key in declared)
        raise ConfigError(
            f"must declare exactly one of `accounts:`, `profile:` or `role:` (found {named})",
            at=at,
            hint="write one entry per rule; the section is a list",
        )

    return PersonalAccountRule(
        accounts=_build_accounts(entry, at=at) if "accounts" in entry else (),
        profile=optional_string(entry, "profile", at=at),
        role=optional_string(entry, "role", at=at),
        targets=build_target_selector(entry.get("targets"), at=at.key("targets")),
        policy=optional_string(entry, "policy", at=at),
    )


def _build_accounts(entry: dict[str, Any], *, at: KeyPath) -> tuple[str, ...]:
    accounts = string_list(entry["accounts"], at=at.key("accounts"))
    if not accounts:
        raise ConfigError("must declare at least one account", at=at.key("accounts"))
    return accounts


def _reject_duplicate_names(entries: list[PersonalAccountRule], *, at: KeyPath) -> None:
    """One account name may appear once across the whole section.

    Compared **case-insensitively**, because that is how a name is matched
    everywhere it is used: ``sopuli/config/selection.py`` casefolds before
    comparing, so ``--account jdoe`` selects a declared ``JDOE``. A rule that
    compared exactly would call two spellings distinct and then let one selector
    reach both.
    """
    seen: dict[str, KeyPath] = {}
    for index, entry in enumerate(entries):
        where = at.index(index).key("accounts")
        for position, account in enumerate(entry.accounts):
            folded = account.casefold()
            if folded in seen:
                raise ConfigError(
                    f"duplicate personal account {account!r}",
                    at=where.index(position),
                    hint=f"already declared at {seen[folded]}",
                )
            seen[folded] = where.index(position)


def reject_cross_declaration(
    applications: tuple[Application, ...], personal: tuple[PersonalAccountRule, ...]
) -> None:
    """A name may not be declared both as an application account and a personal one.

    The two carry **different guarantees** -- one is mastered by a secret and
    synced from it, the other is handed to a person and mastered by nothing -- so
    a name in both makes the whitelist ambiguous about which applies, and the
    validator refuses rather than picking. H1 (#449) decided this; UC-2 §2 is
    where the reasoning lives.

    Only the enumerated form can be checked here. A **predicate** is resolved
    against a database, so an account that a profile admits *and* an application
    declares is a collision nothing in a file can see -- which is the cost H1
    accepted and stated, and the verb that resolves the predicate is where it has
    to be caught.
    """
    owners: dict[str, str] = {}
    for application in applications:
        for account in application.accounts:
            owners[account.casefold()] = application.label

    for index, entry in enumerate(personal):
        for position, account in enumerate(entry.accounts):
            owner = owners.get(account.casefold())
            if owner is None:
                continue
            raise ConfigError(
                f"account {account!r} is declared both as a personal account and by {owner}",
                at=ROOT.key("personal_accounts").index(index).key("accounts").index(position),
                hint=(
                    "an account is mastered by a secret or handed to a person, not both; "
                    "declare it in one section"
                ),
            )

"""Building application entries, and the rules that make them safe.

§1 of the reference calls the account→secret mapping "the safety-critical part":
a wrong binding either writes the new password where the application does not
read it, or rotates the database while the application keeps reading a stale
path. Neither shows up as an error at the time. That is why this layer is
pedantic.

Two shapes, one object. The inline form -- ``accounts:`` and friends at the top
level -- is, in §1's words, "exactly sugar for a single unnamed application
entry", so both build the same :class:`~sopuli.config.model.Application` and
nothing downstream has to know which was written.

The rules enforced here are the ones that do not need the target set expanded.
Anything requiring rendered target names (duplicate names, unresolved
placeholders, an override naming a target that is not generated) belongs with
target expansion and is deliberately absent.
"""

from __future__ import annotations

import re
from typing import Any

from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.fields import (
    label_selector,
    mapping,
    optional_string,
    reject_unknown_keys,
    sequence,
    string,
    string_list,
)
from sopuli.config.model import Application, OracleOptions, Override, TargetSelector
from sopuli.config.secret_refs import parse_secret_ref

#: What the inline form may carry at the top level -- the four keys §1's skeleton
#: lists, plus `secret` as the documented alternative to `secret_template` (§3).
#:
#: It is deliberately *not* the full set of application keys, and the reason is
#: a name collision rather than a decision: `targets:` at the top level is the
#: estate's explicit target list, so it cannot also mean an application's target
#: selector. `vault:`, `oracle:` and `name:` are absent for the same
#: one-file-one-meaning reason. An inline application therefore applies to all
#: targets, which is the documented default anyway; needing any of those keys is
#: the point at which a file moves to the `applications:` form.
INLINE_KEYS = ("accounts", "secret", "secret_template", "policy", "overrides")

APPLICATION_KEYS = (
    "name",
    "accounts",
    "targets",
    "vault",
    "secret",
    "secret_template",
    "policy",
    "oracle",
    "overrides",
)

#: What an `overrides:` entry may patch. `accounts` is absent on purpose --
#: see `_build_override`.
OVERRIDE_KEYS = ("where", "vault", "secret", "secret_template", "policy", "oracle")

ORACLE_KEYS = ("container_clause",)

TARGET_SELECTOR_KEYS = ("group", "match")

#: `{account}`, `{account_lower}`, `{account_upper}` -- the tokens that make a
#: rendered ref differ between two accounts. §7 fixes the token list (C3: no
#: arbitrary expressions), so matching them literally is enough.
ACCOUNT_TOKEN = re.compile(r"\{account(_lower|_upper)?\}")


def build_applications(document: dict[str, Any]) -> tuple[Application, ...]:
    """Normalise either config shape into a tuple of application entries."""
    inline_keys_present = sorted(key for key in INLINE_KEYS if key in document)
    has_applications = "applications" in document

    if inline_keys_present and has_applications:
        # §1: "The two forms are mutually exclusive". Guessing which one was
        # meant would bind accounts to a secret layout nobody wrote down.
        #
        # Every inline key counts here, not just `accounts:`. A stray top-level
        # `secret_template:` left behind when a file was converted to the
        # `applications:` form would otherwise be silently ignored -- and a
        # secret ref that looks configured and is not is precisely the mistake
        # §1 calls the one with the worst consequences.
        named = ", ".join(f"`{key}:`" for key in inline_keys_present)
        raise ConfigError(
            f"a config file uses either the inline form or `applications:`, not both "
            f"(found {named} alongside `applications:`)",
            at=ROOT,
            hint=(
                "move the top-level keys into an `applications:` entry, or delete "
                "the `applications:` section"
            ),
        )

    if has_applications:
        return _build_named(document["applications"], at=ROOT.key("applications"))
    if inline_keys_present:
        return (_build_inline(document),)
    # Neither form: a config that declares no accounts. Legal -- a file may hold
    # only vaults and targets while an estate is being described - and the
    # commands that need a binding say so themselves.
    return ()


def _build_named(raw: Any, *, at: KeyPath) -> tuple[Application, ...]:
    entries = sequence(raw, at=at)
    if not entries:
        raise ConfigError("must declare at least one application", at=at)

    applications = []
    for index, entry in enumerate(entries):
        applications.append(_build_entry(entry, at=at.index(index), named=True))

    _reject_duplicate_names(applications, at=at)
    return tuple(applications)


def _build_inline(document: dict[str, Any]) -> Application:
    """The top-level form. Only the application keys are read from the root."""
    inline = {key: document[key] for key in INLINE_KEYS if key in document}
    return _build_entry(inline, at=ROOT, named=False)


def _build_entry(raw: Any, *, at: KeyPath, named: bool) -> Application:
    entry = mapping(raw, at=at)
    reject_unknown_keys(entry, allowed=APPLICATION_KEYS if named else INLINE_KEYS, at=at)

    name = optional_string(entry, "name", at=at)
    if named and name is None:
        raise ConfigError(
            "an application entry must have a name",
            at=at.key("name"),
            hint="the name is what `--application` selects on",
        )

    accounts = _build_accounts(entry, at=at)
    secret, secret_template = _build_secret(entry, at=at)

    application = Application(
        name=name,
        accounts=accounts,
        targets=_build_targets(entry.get("targets"), at=at.key("targets")),
        vault=optional_string(entry, "vault", at=at),
        secret=secret,
        secret_template=secret_template,
        policy=optional_string(entry, "policy", at=at),
        oracle=_build_oracle(entry.get("oracle"), at=at.key("oracle")),
        overrides=_build_overrides(entry.get("overrides"), at=at.key("overrides")),
    )

    _require_distinguishable_accounts(application, at=at)
    return application


def _build_accounts(entry: dict[str, Any], *, at: KeyPath) -> tuple[str, ...]:
    if "accounts" not in entry:
        raise ConfigError(
            "an application must declare the accounts it manages",
            at=at.key("accounts"),
            hint="invariant 5: the config is the whitelist, so nothing is managed by default",
        )

    accounts = string_list(entry["accounts"], at=at.key("accounts"))
    if not accounts:
        raise ConfigError("must declare at least one account", at=at.key("accounts"))

    seen: dict[str, int] = {}
    for index, account in enumerate(accounts):
        if account in seen:
            # Harmless today and not harmless later: a duplicate would rotate the
            # same account twice in one run, which two password changes in quick
            # succession can turn into a lockout under PASSWORD_REUSE rules.
            raise ConfigError(
                f"duplicate account {account!r}",
                at=at.key("accounts").index(index),
                hint=f"already declared at index {seen[account]}",
            )
        seen[account] = index
    return accounts


def _build_secret(entry: dict[str, Any], *, at: KeyPath) -> tuple[str | None, str | None]:
    secret = optional_string(entry, "secret", at=at)
    secret_template = optional_string(entry, "secret_template", at=at)
    if secret is not None and secret_template is not None:
        raise ConfigError(
            "an application uses either `secret:` or `secret_template:`, not both",
            at=at,
            hint="`secret` is a literal ref; `secret_template` expands per account and label",
        )
    _check_ref_syntax(secret, secret_template, at=at)
    return secret, secret_template


def _check_ref_syntax(secret: str | None, template: str | None, *, at: KeyPath) -> None:
    """Both fields hold a §7 ref, so both are parsed while the file is being read.

    A template parses as the ref it will expand into -- the punctuation that
    gives a ref its shape is literal, and the ``{tokens}`` sit inside the parts
    (:mod:`sopuli.config.secret_refs`). So a malformed ref is caught here rather
    than at the first rotation, which is worth the parse: §1 calls this binding
    the safety-critical part, and the failure at the far end of it is a password
    written where the application does not read it.

    The parse result is discarded. Resolution needs an account and a target to
    expand the tokens against, and re-parsing there costs nothing next to
    keeping a half-resolved object on the model.
    """
    for key, value in (("secret", secret), ("secret_template", template)):
        if value is not None:
            parse_secret_ref(value, at=at.key(key))


def _require_distinguishable_accounts(application: Application, *, at: KeyPath) -> None:
    """More than one account must not resolve to one secret ref.

    This is §10's "cannot produce distinct refs" rule, read as being about
    *accounts*. §7 is explicit that one account sharing a password across eleven
    PDBs is "legal and often intended", so the rule cannot be about targets --
    but two *accounts* landing on the same ref is never intended: whichever is
    written second overwrites the first, and the application that reads the first
    is locked out at the next rotation.

    A literal ``secret:`` with several accounts is the same fault in a starker
    form -- it cannot vary at all -- so it gets the same error.
    """
    ref = application.secret_ref
    if ref is None or len(application.accounts) <= 1:
        return
    if ACCOUNT_TOKEN.search(ref):
        return

    field = "secret" if application.secret is not None else "secret_template"
    raise ConfigError(
        f"{len(application.accounts)} accounts would share one secret ref",
        at=at.key(field),
        hint=(
            "add {account} (or {account_lower} / {account_upper}) so each account "
            "gets its own ref; without it the second password written overwrites the first"
        ),
    )


def _build_targets(raw: Any, *, at: KeyPath) -> TargetSelector:
    """`targets:` is a list of names, `{group: NAME}` or `{match: {...}}` (§3)."""
    if raw is None:
        return TargetSelector()
    if isinstance(raw, list):
        return TargetSelector(names=string_list(raw, at=at))

    selector = mapping(raw, at=at)
    reject_unknown_keys(selector, allowed=TARGET_SELECTOR_KEYS, at=at)
    if len(selector) != 1:
        raise ConfigError(
            "must name exactly one of `group:` or `match:`",
            at=at,
            hint="or give a list of target names",
        )
    if "group" in selector:
        return TargetSelector(group=string(selector["group"], at=at.key("group")))
    return TargetSelector(match=label_selector(selector["match"], at=at.key("match")))


def _build_oracle(raw: Any, *, at: KeyPath) -> OracleOptions:
    if raw is None:
        return OracleOptions()
    options = mapping(raw, at=at)
    reject_unknown_keys(options, allowed=ORACLE_KEYS, at=at)
    return OracleOptions(container_clause=optional_string(options, "container_clause", at=at))


def _build_overrides(raw: Any, *, at: KeyPath) -> tuple[Override, ...]:
    if raw is None:
        return ()
    entries = sequence(raw, at=at)
    return tuple(_build_override(entry, at=at.index(index)) for index, entry in enumerate(entries))


def _build_override(raw: Any, *, at: KeyPath) -> Override:
    """One `{ where: {labels}, ...keys }` patch.

    ``accounts`` is not a patchable key, and that is a rule rather than an
    oversight. Invariant 5 says selectors filter the declared set and cannot
    extend it -- not even under ``--force``. An override that could add accounts
    would be a selector that extends the whitelist, reached by a label match
    somewhere in the middle of a long file. Whatever the tool manages has to be
    readable from ``accounts:`` alone.
    """
    patch = mapping(raw, at=at)
    reject_unknown_keys(patch, allowed=OVERRIDE_KEYS, at=at)

    if "where" not in patch:
        raise ConfigError(
            "an override must say which targets it applies to",
            at=at.key("where"),
            hint="`where: { env: dev }` -- an override matching everything is not an exception",
        )

    secret = optional_string(patch, "secret", at=at)
    secret_template = optional_string(patch, "secret_template", at=at)
    if secret is not None and secret_template is not None:
        raise ConfigError(
            "an override sets either `secret:` or `secret_template:`, not both",
            at=at,
        )
    _check_ref_syntax(secret, secret_template, at=at)

    return Override(
        where=label_selector(patch["where"], at=at.key("where")),
        vault=optional_string(patch, "vault", at=at),
        secret=secret,
        secret_template=secret_template,
        policy=optional_string(patch, "policy", at=at),
        oracle=_build_oracle(patch.get("oracle"), at=at.key("oracle")),
    )


def _reject_duplicate_names(applications: list[Application], *, at: KeyPath) -> None:
    seen: dict[str, int] = {}
    for index, application in enumerate(applications):
        name = application.name
        if name is None:
            continue
        if name in seen:
            raise ConfigError(
                f"duplicate application name {name!r}",
                at=at.index(index).key("name"),
                hint=f"already used at index {seen[name]}; `--application` needs it to be unique",
            )
        seen[name] = index

"""Cross-section rules, and the ones that need the estate expanded first.

Mostly one question: does every name in this file name something in it?

Each section validates its own shape. Nothing so far has checked that
``vault: vault-prd`` names a store that exists — and that is the typo with real
consequences, because a dangling vault name does not stay dangling: resolution
falls back to ``defaults.vault``, and the tool faithfully rotates a production
password into whatever that is. §1 calls a wrong secret binding the mistake with
the worst consequences; this is the same mistake reached by a different route.

Deliberately last, and deliberately one pass. Doing half of these while only half
the sections existed would have meant writing the resolver twice, and it is
easier to see that every reference is covered when they are in one list.

**Targets are read after expansion, never before.** A set writes
``vault: "{vault}"``, whose value comes from a dimension variable, so resolving
the template would be resolving a name no store will ever have. Running after
:mod:`sopuli.config.expansion` means every target here -- explicit or generated
-- names a store literally. A ``{placeholder}`` reaching this module therefore
comes from an application, a profile or ``defaults``, where there is nothing to
substitute from, and is an error rather than a hole in the resolver.

That is also why the §10 rules about *pairs of keys on one target* are here
rather than in :mod:`sopuli.config.targets`: a target's final ``dsn`` and ``admin``
may come from a template and an ``overrides:`` patch respectively, so the pair only
exists once the estate is expanded. Checking the written form instead would pass a
patch that breaks it, and invariant 4 wants the refusal at plan time.
"""

from __future__ import annotations

from dataclasses import dataclass

from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.expansion import declared_at
from sopuli.config.model import Config, ConfigWarning, ExpandedTarget
from sopuli.config.targets import EXTERNAL

#: The environment §10 singles out. Safety rules key on `environment` as a
#: first-class field (§4), and this is the value the reference names.
PRODUCTION = "prod"

#: What a TNS alias cannot contain. `:` and `/` are EZConnect's punctuation, `(`
#: starts a connect descriptor, `@` is a connect-string separator, and a space is
#: not a net service name.
_NOT_IN_AN_ALIAS = (":", "/", "@", "(", " ")


@dataclass(frozen=True)
class _Reference:
    """One name written somewhere, and where it was written."""

    name: str
    at: KeyPath


def _admin_at(expanded: ExpandedTarget, *parts: str) -> KeyPath:
    """Where inside a target's ``admin:`` block something was written.

    :func:`~sopuli.config.expansion.declared_at` keys on *target* fields, because
    that is what an ``overrides:`` patch replaces -- so the block is located
    override-aware first, and the keys inside it are descended afterwards. The
    result is the line to edit (``targets[0].admin.auth.secret``, or the override's
    own path) rather than the block it sits in.
    """
    at = declared_at(expanded, "admin")
    for part in parts:
        at = at.key(part)
    return at


def check_references(config: Config) -> tuple[ConfigWarning, ...]:
    """Resolve every name in the file against what the file declares.

    Raises on a dangling reference; returns the warnings that are worth saying
    but not worth refusing to run over.
    """
    _check_vaults(config)
    _check_policies(config)
    _check_groups(config)
    _check_targets(config)
    _check_profiles(config)
    _check_non_production_vaults(config)
    _check_external_admin(config)
    _check_admin_refs(config)
    return _warn_about_profile_names(config)


# ------------------------------------------------------------ resolution ---


def _check_vaults(config: Config) -> None:
    declared = {vault.name for vault in config.vaults}
    _resolve(_vault_references(config), declared, noun="vault", section="vaults")


def _vault_references(config: Config) -> list[_Reference]:
    found: list[_Reference] = []

    # The expanded estate covers `targets:` and `target_sets:` at once, and is
    # the only form in which a generated target's store has a name to check.
    for expanded in config.expanded_targets:
        if expanded.target.vault is not None:
            found.append(_Reference(expanded.target.vault, declared_at(expanded, "vault")))
        # `admin: { auth: { method: vault, secret: "vault-prod:..." } }`. A prefix
        # here is a store name like any other, and the credential it addresses is
        # the one that reaches the database -- a dangling name means the tool
        # cannot connect at all, which is worth saying while the file is open.
        admin = expanded.target.admin
        if admin is not None and admin.auth is not None and admin.auth.secret is not None:
            prefix = admin.auth.secret.vault
            if prefix is not None:
                found.append(_Reference(prefix, _admin_at(expanded, "auth", "secret")))

    at = ROOT.key("applications")
    for index, application in enumerate(config.applications):
        # The inline form writes its keys at the root, so its path is the root.
        where = ROOT if application.is_inline else at.index(index)
        if application.vault is not None:
            found.append(_Reference(application.vault, where.key("vault")))
        for position, override in enumerate(application.overrides):
            if override.vault is not None:
                found.append(
                    _Reference(override.vault, where.key("overrides").index(position).key("vault"))
                )

    at = ROOT.key("profiles")
    for profile in config.profiles:
        if profile.vault is not None:
            found.append(_Reference(profile.vault, at.key(profile.name).key("vault")))

    if config.defaults.vault is not None:
        found.append(_Reference(config.defaults.vault, ROOT.key("defaults").key("vault")))

    return found


def _check_policies(config: Config) -> None:
    declared = {policy.name for policy in config.policies}
    found: list[_Reference] = []

    at = ROOT.key("applications")
    for index, application in enumerate(config.applications):
        where = ROOT if application.is_inline else at.index(index)
        if application.policy is not None:
            found.append(_Reference(application.policy, where.key("policy")))
        for position, override in enumerate(application.overrides):
            if override.policy is not None:
                path = where.key("overrides").index(position).key("policy")
                found.append(_Reference(override.policy, path))

    if config.defaults.policy is not None:
        found.append(_Reference(config.defaults.policy, ROOT.key("defaults").key("policy")))

    _resolve(found, declared, noun="policy", section="policies")


def _check_groups(config: Config) -> None:
    declared = {group.name for group in config.groups}
    found: list[_Reference] = []

    at = ROOT.key("applications")
    for index, application in enumerate(config.applications):
        where = ROOT if application.is_inline else at.index(index)
        group = application.targets.group
        if group is not None:
            found.append(_Reference(group, where.key("targets").key("group")))

    _resolve(found, declared, noun="group", section="groups")


def _check_targets(config: Config) -> None:
    """An application's `targets: [name]` must name targets that exist.

    The same rule as every other name here, and the same failure: a typo does not
    stay a typo. `targets: [cdb-root-dv]` selects nothing, so the application
    manages nothing, and a run reports success over an empty set. Resolved
    against the *expanded* estate, because a generated name is as real a target
    as a written one.
    """
    declared = {expanded.name for expanded in config.expanded_targets}
    found: list[_Reference] = []

    for index, application in enumerate(config.applications):
        where = ROOT if application.is_inline else ROOT.key("applications").index(index)
        for position, name in enumerate(application.targets.names):
            found.append(_Reference(name, where.key("targets").index(position)))

    _resolve(found, declared, noun="target", section="targets")


def _check_profiles(config: Config) -> None:
    declared = {profile.name for profile in config.profiles}
    found: list[_Reference] = []
    if config.defaults.profile is not None:
        found.append(_Reference(config.defaults.profile, ROOT.key("defaults").key("profile")))

    # §5: selecting a profile that does not exist is an error rather than a
    # silent fallback, and that has to hold for the one named in the file too.
    _resolve(found, declared, noun="profile", section="profiles")


def dangling(name: str, declared: set[str], *, noun: str, section: str, at: KeyPath = ROOT) -> None:
    """Raise the standard "that name names nothing" error, or return quietly.

    Public because a name can also be typed rather than written: ``policy sample``
    takes one on the command line, and a second phrasing of the same failure would
    be a second thing to learn. The message names what *is* declared, because a
    rejection that does not is an invitation to guess at spelling.
    """
    _resolve([_Reference(name, at)], declared, noun=noun, section=section)


def _resolve(references: list[_Reference], declared: set[str], *, noun: str, section: str) -> None:
    for reference in references:
        if reference.name in declared:
            continue
        if "{" in reference.name:
            # Targets have been expanded by now, so a placeholder here comes from
            # somewhere with nothing to substitute from. Saying that is worth
            # more than "no vault named '{vault}' is declared", which invites
            # somebody to go and declare one.
            raise ConfigError(
                f"{reference.name!r} contains a placeholder, and this is not a target set",
                at=reference.at,
                hint=(
                    "placeholders resolve from a target set's `for_each:` variables (§4); "
                    "elsewhere they have nothing to substitute from"
                ),
            )
        known = ", ".join(sorted(declared)) if declared else f"none — there is no `{section}:`"
        raise ConfigError(
            f"no {noun} named {reference.name!r} is declared",
            at=reference.at,
            hint=f"declared {section}: {known}",
        )


# ------------------------------------------------------------ the §10 rule ---


def _check_non_production_vaults(config: Config) -> None:
    """§10: a `prod` target may not be mastered by a store marked non-production.

    The marking exists so a development store can be obviously a development
    store (P2 says the file backend "must be obviously non-production"). Pointing
    production at one is not a preference to warn about: the passwords that
    actually guard production would be sitting somewhere chosen for convenience.
    """
    non_production = {vault.name for vault in config.vaults if vault.non_production}
    if not non_production:
        return

    for expanded in config.expanded_targets:
        target = expanded.target
        if target.environment != PRODUCTION or target.vault not in non_production:
            continue
        raise ConfigError(
            f"target {target.name!r} is {PRODUCTION} but its vault {target.vault!r} "
            f"is marked `non_production: true`",
            at=declared_at(expanded, "vault"),
            hint="point it at a production store, or drop the marking if it is wrong",
        )


def _check_external_admin(config: Config) -> None:
    """§10: what ``auth: external`` requires of the rest of the target.

    External authentication means the client connects as ``/@alias`` and a secure
    external password store -- an Oracle wallet -- supplies both the username and
    the password for that alias. Two things follow, and neither is a preference:

    * **The DSN has to be a TNS alias**, resolvable through ``TNS_ADMIN``. An
      EZConnect string has no wallet entry to match, so the connection fails as an
      authentication error, which is the most misleading way for a config mistake
      to surface.
    * **A ``username:`` is refused rather than ignored.** The wallet decides who
      connects. A username written beside ``external`` says something the tool
      cannot honour, and a file that appears to name the connecting account while
      the wallet names another is worth stopping for -- especially in the audit
      trail, where "who" is half the record (P5).
    """
    for expanded in config.expanded_targets:
        target = expanded.target
        if target.admin is None or target.admin.auth is None:
            continue
        if target.admin.auth.method != EXTERNAL:
            continue

        if target.admin.username is not None:
            raise ConfigError(
                f"target {target.name!r} uses external authentication, so its "
                f"`username:` cannot be honoured",
                at=_admin_at(expanded, "username"),
                hint=(
                    "a wallet supplies the username for the alias it is keyed on -- drop "
                    "`username:`, or use a method that takes one"
                ),
            )

        offending = _not_in_an_alias(target.dsn)
        if offending is not None:
            raise ConfigError(
                f"target {target.name!r} uses external authentication, so its `dsn:` must "
                f"be a TNS alias, and {target.dsn!r} contains {offending!r}",
                at=declared_at(expanded, "dsn"),
                hint=(
                    "external auth connects as `/@alias`, and the wallet is keyed on that "
                    "alias -- name one resolvable through TNS_ADMIN rather than a "
                    "host:port/service string"
                ),
            )


def _check_admin_refs(config: Config) -> None:
    """An admin ref that still has a ``{placeholder}`` has nobody left to render it.

    A generated target's ref was rendered from its ``for_each:`` variables during
    expansion, and an unresolvable token there was already an error. So a template
    surviving to here was written on an explicit target, where there is nothing to
    substitute from: §7's own tokens are expanded *per account and target* for an
    application's ref, and the admin credential belongs to no account.

    §10 says an unresolved placeholder is an error and never an empty string, and
    this is that rule applied one section over. Refusing is also the reversible
    choice: who expands ``{env}`` in an admin ref on an explicit target is not
    decided, and allowing it now would mean a brace reaching a vault while it stays
    undecided.
    """
    for expanded in config.expanded_targets:
        admin = expanded.target.admin
        if admin is None or admin.auth is None or admin.auth.secret is None:
            continue
        if not admin.auth.secret.is_templated:
            continue
        raise ConfigError(
            f"admin ref {str(admin.auth.secret)!r} still contains a placeholder",
            at=_admin_at(expanded, "auth", "secret"),
            hint=(
                "a target set's `for_each:` variables render one (§4); elsewhere there is "
                "nothing to substitute from -- an admin credential belongs to no account, "
                "so §7's per-account tokens never reach it"
            ),
        )


def _not_in_an_alias(dsn: str) -> str | None:
    """The first character that makes this a connect string rather than a name.

    A blocklist rather than a pattern for an alias, deliberately: net service names
    are more varied than any charset this layer should invent, and the rule being
    enforced is narrower than "looks like a name" -- it is "is not an EZConnect
    string or a connect descriptor".
    """
    return next((character for character in _NOT_IN_AN_ALIAS if character in dsn), None)


# -------------------------------------------------------------- warnings ---


def _warn_about_profile_names(config: Config) -> tuple[ConfigWarning, ...]:
    """§5: warn when a profile is named after an environment.

    `--profile prod` reads like a target selector and is not one — it changes how
    the run behaves, never what it touches. A warning rather than an error
    because a site may have a reason; the text says what the flag actually does.
    """
    environments = _environments(config)
    warnings = []
    for profile in config.profiles:
        if profile.name not in environments:
            continue
        warnings.append(
            ConfigWarning(
                message=f"profile {profile.name!r} is named after an environment",
                at=str(ROOT.key("profiles").key(profile.name)),
                hint=(
                    f"`--profile {profile.name}` selects no targets -- a profile changes how a "
                    "run behaves, not what it acts on (§5). Name it after where you are "
                    "running from: interactive, ci, scheduled"
                ),
            )
        )
    return tuple(warnings)


def _environments(config: Config) -> set[str]:
    """Every environment value the estate actually declares.

    Read from the expanded targets, because that is the only place a set's
    ``environment: "{env}"`` has become ``dev``, ``qa``, ``prod``. Reading the
    templates instead would mean recognising the one shape §2 happens to write,
    and missing the warning on any set that composes its environment differently.
    """
    return {
        expanded.target.environment
        for expanded in config.expanded_targets
        if expanded.target.environment is not None
    }

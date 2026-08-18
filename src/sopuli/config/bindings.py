"""*These accounts, in these targets, mastered by these secrets* (§1, §3, §7).

§1 says that sentence is what the whole config file exists to state, and calls
the account→secret mapping the safety-critical part of it. This is where the
sentence becomes a list: one :class:`~sopuli.config.model.Binding` per account
per target, each carrying the ref its password is mastered by.

Three things happen here, in this order, because each needs the one before it:

1. **Selection** -- which targets the application applies to
   (:mod:`sopuli.config.selection`).
2. **Patching** -- its ``overrides:`` are applied to the targets they match, in
   document order, so a broad rule can be narrowed by a later one.
3. **Rendering** -- the ref's ``{tokens}`` are expanded per account and target,
   which is the only step that can fail.

It is built at load, so a ref that cannot render is a config error rather than a
surprise at the first rotation. §10 is explicit that an unresolved
``{placeholder}`` is an error and never an empty string: a ref with `{tenant}`
still in it addresses a secret nobody wrote, and one with it replaced by nothing
addresses the *wrong* secret, which is worse.

**No vault is contacted and no value is read.** A binding is an address. What is
stored there -- whether anything is -- is the vault layer's question (P2), and
``config show --resolved`` answers this one offline precisely because the two are
separate.

A target no application selects simply has no bindings. That is a legitimate
state, not an oversight: §2's estate declares a CDB root for a use case that is
not designed yet, and the view that renders this shows it as unmanaged rather
than warning about it.
"""

from __future__ import annotations

from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.model import (
    Application,
    Binding,
    Config,
    ExpandedTarget,
    Override,
    as_dict,
)
from sopuli.config.references import dangling
from sopuli.config.secret_refs import SecretRef, parse_secret_ref
from sopuli.config.selection import matches, select
from sopuli.config.templates import substitute
from sopuli.config.vaults import STAGING_EMULATED, STAGING_LABELS
from sopuli.payload import stage_layout

#: What an unresolved token in a secret ref is measured against (§7).
_SCOPE = "a secret template resolves from the account, the target and the target's labels (§7)"

_APPLICATIONS = ROOT.key("applications")


def build_bindings(config: Config) -> tuple[Binding, ...]:
    """Every (account, target) the file declares, with its resolved ref.

    Ordered by application, then by estate order, then by the order the accounts
    are declared in -- all three of which are document order, so the result is
    stable enough to diff between runs.
    """
    bindings: list[Binding] = []
    for index, application in enumerate(config.applications):
        at = ROOT if application.is_inline else _APPLICATIONS.index(index)
        bindings.extend(_bind(config, application, at=at))
    return tuple(bindings)


def _bind(config: Config, application: Application, *, at: KeyPath) -> list[Binding]:
    bound: list[Binding] = []

    for expanded in select(config, application.targets):
        patches = _patches_for(application, expanded)
        ref, where = _ref_for(application, patches, at=at)
        vault = _effective(application.vault, patches, key="vault")
        policy = _effective(application.policy, patches, key="policy")

        for account in application.accounts:
            secret = _render(ref, application, account, expanded, at=where)
            store = _vault_for(secret, vault, expanded, config)
            _check_store_declared(secret, config, at=where)
            _check_has_somewhere_to_resolve_from(secret, store, config, at=where)
            _check_stageable(secret, store, config, at=where)
            bound.append(
                Binding(
                    application=application.name,
                    account=account,
                    target=expanded.name,
                    secret=secret,
                    vault=store,
                    policy=policy if policy is not None else config.defaults.policy,
                )
            )
    return bound


def _check_store_declared(secret: SecretRef | None, config: Config, *, at: KeyPath) -> None:
    """A ref's own ``vault-name:`` prefix names a store like every other name does.

    :mod:`sopuli.config.references` resolves every *other* way a store gets named
    -- the target's ``vault:``, the entry's, an override's, a profile's,
    ``defaults.vault``, and the prefix on an ``admin.auth.secret``. The prefix on
    an **application's** ref was the one that went unchecked, because it is the
    only one that is not resolvable until the ref has been rendered: §7's tokens
    expand per account and target, and `check_references` runs before that on
    purpose (see :func:`~sopuli.config.loading.build_config`).

    So it is resolved here, against the same declared set and through the same
    :func:`~sopuli.config.references.dangling` message, because a second phrasing
    of "that name names nothing" would be a second thing to learn.

    This is the failure `references.py`'s own docstring describes: a dangling
    store name does not stay dangling. ``vault-prd:apps/acme/db#password`` is a
    ref the file accepts, a binding that resolves, and a rotation that discovers
    at the far end that there is no such store -- or, worse, a name that later
    *becomes* a store belonging to somebody else.
    """
    if secret is None or secret.vault is None:
        return
    dangling(
        secret.vault,
        {vault.name for vault in config.vaults},
        noun="vault",
        section="vaults",
        at=at,
    )


def _check_has_somewhere_to_resolve_from(
    secret: SecretRef | None, store: str | None, config: Config, *, at: KeyPath
) -> None:
    """#118: a ref with no store, and no `vaults:` block to point one at later.

    ``store`` is `None` here means none of §3's chain named one -- not the ref's
    own prefix, not the entry, not an override, not the target, not
    ``defaults.vault``. That is not always a mistake: a profile's `vault:` is
    deliberately left out of the chain (`_vault_for`'s docstring), because which
    profile is active is a property of a *run* and bindings are built once at
    load, and the same is true of `SOPULI_VAULT` (P3, issue #10). Both can still
    complete this binding once a run picks one -- but only if the file declared
    somewhere for them to point *at*. `config show --resolved` already renders a
    `-` for this binding rather than a verdict, and the command that actually
    needs a store is where the exact answer belongs (invariant 4).

    What is refused here is narrower: `vaults:` declaring nothing at all. Then
    there is no name a profile or `SOPULI_VAULT` could select even in principle
    -- a store name resolves against what the file declared (invariant 5; see
    `references.py`'s own dangling-name rule) -- so no run of this file can ever
    rotate this account, and that is true regardless of profile or environment.
    Refusing here is `config validate` catching the case #111 was raised about,
    rather than every target discovering it separately at plan time.
    """
    if secret is None or store is not None or config.vaults:
        return
    raise ConfigError(
        "no vault is declared, and this binding names no store",
        at=at,
        hint=(
            "no `vaults:` entry exists for a profile or SOPULI_VAULT to select later -- "
            "declare one under `vaults:`, or name a store on the ref, the entry, an "
            "override, the target, or `defaults.vault`"
        ),
    )


def _check_stageable(
    secret: SecretRef | None, store: str | None, config: Config, *, at: KeyPath
) -> None:
    """A rendered ref must have somewhere to stage into (#111, Q7 in #85).

    :func:`~sopuli.payload.stage_layout` refuses a ref naming a whole secret --
    nothing to put ``pending`` and ``previous`` beside -- and one whose field is a
    key the mirror rule generates, which would put the current stage and a
    staging sibling in one place. Both refusals already existed; what this does is
    move *when* they happen, from the first rotation to the moment the file is
    read. §1 calls the account→secret binding the safety-critical part, and
    invariant 4 wants a command that cannot succeed to fail before it has written
    anything.

    Here rather than in :mod:`sopuli.config.references` for two reasons, both of
    which turn on this being the rendered ref rather than the written one:

    * **The template question does not arise.** ``{account}`` and ``{tenant}`` are
      already substituted, so what is checked is what will reach the store --
      including the §7 case a written template cannot settle, a token whose value
      turns out to contain a ``#``.
    * **The store is known.** Which matters, because the rule is not universal.

    **Native staging is the reason for that last point.** Where a store stages
    natively -- OCI, per P2's table -- the three stages are versions of the
    secret, so a ref naming a whole secret is not merely legal but the natural
    layout, and a field called ``pending`` collides with nothing. Refusing it
    everywhere would reject a correct OCI config to enforce a rule that only
    exists because HashiCorp KV has to emulate what OCI has. A store this layer
    has no capability row for is left alone; see
    :data:`~sopuli.config.vaults.STAGING_LABELS`.
    """
    if secret is None or store is None:
        return
    # Every way a store can be named is resolved before this runs -- the five in
    # `references.py` and the ref's own prefix just above -- so a name with no
    # store behind it has already been refused. The `is None` arm is therefore
    # unreachable rather than a silent skip, and it stays because a lookup that
    # returns nothing must not decide a safety rule by falling through to it.
    declared = next((vault for vault in config.vaults if vault.name == store), None)
    if declared is None or STAGING_LABELS.get(declared.type) != STAGING_EMULATED:
        return
    stage_layout(secret, at=at)


# ---------------------------------------------------------------- overrides ---


def _patches_for(application: Application, expanded: ExpandedTarget) -> list[tuple[int, Override]]:
    """The application's overrides that apply to this target, in document order.

    §3 calls them "patches applied to matching targets" -- plural, and applied,
    so all of them are. Later ones win key by key, which is what lets a broad
    rule be narrowed by a later exception rather than forcing every case to be
    written out separately.

    Each keeps its position in ``overrides:``, because a value's location is the
    line that wrote it and that line is the one worth reporting.
    """
    return [
        (position, override)
        for position, override in enumerate(application.overrides)
        if matches(expanded.target, override.where)
    ]


def _effective(base: str | None, patches: list[tuple[int, Override]], *, key: str) -> str | None:
    """The last patch that sets ``key``, or the entry's own value."""
    for _, override in reversed(patches):
        value = getattr(override, key)
        if value is not None:
            return str(value)
    return base


def _ref_for(
    application: Application, patches: list[tuple[int, Override]], *, at: KeyPath
) -> tuple[str | None, KeyPath]:
    """The ref that applies to this target, and the key it was written under.

    The location travels with the value because the two can come from different
    places: an override may set ``secret_template`` where the entry set
    ``secret``, and a failure reported against the entry would point at the one
    line that is not the problem. The same rule as
    :func:`~sopuli.config.expansion.declared_at` applies to a patched target.
    """
    for position, override in reversed(patches):
        if override.secret_ref is not None:
            key = "secret" if override.secret is not None else "secret_template"
            return override.secret_ref, at.key("overrides").index(position).key(key)

    key = "secret" if application.secret is not None else "secret_template"
    return application.secret_ref, at.key(key)


def _vault_for(
    secret: SecretRef | None, chosen: str | None, expanded: ExpandedTarget, config: Config
) -> str | None:
    """The ref's own prefix, else §3's chain: the entry's store, the target's,
    ``defaults.vault``.

    The prefix comes first because §7 calls ``vault-dev:path`` an *explicit*
    vault, and because the alternative is output that contradicts itself -- a
    ref reading ``vault-dev:...`` beside a resolved store of something else.

    This is the chain the reference writes, and only that chain. The `SOPULI_*`
    and command-line layers above it are P3's and belong to the precedence
    resolver (issue #10): a config file can be read without knowing what
    environment it will be read in.
    """
    if secret is not None and secret.vault is not None:
        return secret.vault
    if chosen is not None:
        return chosen
    if expanded.target.vault is not None:
        return expanded.target.vault
    return config.defaults.vault


# ---------------------------------------------------------------- rendering ---


def _render(
    ref: str | None,
    application: Application,
    account: str,
    expanded: ExpandedTarget,
    *,
    at: KeyPath,
) -> SecretRef | None:
    """Expand a ref's tokens for one account in one target.

    ``at`` is where this ref was written, which :func:`_ref_for` worked out --
    the entry's own key, or the override's if one supplied it.

    Absent stays absent: an application may declare no ref at all (§3), and this
    layer does not invent one.
    """
    if ref is None:
        return None
    rendered = substitute(ref, _tokens(application, account, expanded), at=at, source=_SCOPE)
    return parse_secret_ref(rendered, at=at)


def _tokens(application: Application, account: str, expanded: ExpandedTarget) -> dict[str, str]:
    """§7's token table, as a flat scope.

    Labels go in first and the built-ins overwrite them, so `{target}` means the
    target name even on an estate that labels something `target`. The built-ins
    are documented and a label is whatever somebody typed; the one that is
    specified wins.

    Two absences are deliberate. A target with no `environment` contributes no
    `{env}`, and one with no container no `{container}` -- so a template using
    either against a target that has neither fails to render, which §10 requires
    of any unresolved token. `{application}` is the documented exception: §7 says
    it is empty in the inline form, so it is present and empty rather than
    missing.
    """
    target = expanded.target
    tokens = dict(as_dict(target.labels))
    tokens.update(
        {
            "account": account,
            "account_lower": account.lower(),
            "account_upper": account.upper(),
            "target": target.name,
            "application": application.name or "",
        }
    )
    if target.environment is not None:
        tokens["env"] = target.environment
    if target.oracle.container is not None:
        tokens["container"] = target.oracle.container
    return tokens

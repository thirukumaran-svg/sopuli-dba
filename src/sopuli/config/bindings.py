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

from collections.abc import Mapping, Sequence

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
from sopuli.config.secret_refs import SecretRef, normalise_path, parse_secret_ref
from sopuli.config.selection import matches, select
from sopuli.config.sharing import STAGE_COLLISION_HINT, StageCollision, colliding_stages
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
    where: dict[str | None, KeyPath] = {}
    for index, application in enumerate(config.applications):
        at = ROOT if application.is_inline else _APPLICATIONS.index(index)
        where[application.name] = at
        bindings.extend(_bind(config, application, at=at))
    # Two accounts on one password first: where staging is emulated they would
    # also collide in `pending`, and this message names the actual fault.
    _check_one_account_per_password(bindings, where=where)
    _check_stages_do_not_collide(bindings, config, where=where)
    _check_one_policy_per_password(bindings, where=where)
    return tuple(bindings)


def _check_one_account_per_password(
    bindings: Sequence[Binding], *, where: Mapping[str | None, KeyPath]
) -> None:
    """No two accounts resolve to one password, or to places that overlap.

    §10 refuses an entry whose ref cannot give its accounts distinct refs
    (``applications._require_distinguishable_accounts``). That rule sees one
    entry. Two entries can still put two accounts on the same field and pointer
    in the same document, for example by writing one literal ref in both. Then
    `creds generate` writes both passwords into one field, the last one wins, and
    one account's application reads the other account's password. The second
    rotation locks the first out.

    **Overlapping is the same fault.** A place is the field, then the pointer's
    segments; a ref with no field is the whole document. Where one account's
    place contains the other's, as ``apps/acme#DB`` contains
    ``apps/acme#DB/acme_api_user``, writing the first replaces the object that
    holds the second.

    It is about the password, not the stage. Where staging is emulated,
    ``_check_stages_do_not_collide`` would also refuse the file, because both
    accounts stage into one key in ``pending``, but its hint is about a bare
    ``#{account}``, which is a different mistake. So this runs first. Where a
    store stages natively, as OCI does, that rule does not apply and only this
    one refuses the file (decided in #841).

    **One account in two nested places is the same fault too.** An override or
    a second entry can give one account ``#DB`` on one target and
    ``#DB/acme_web_user`` on another. Those are two values, and writing one
    replaces the other. One account in one place is a shared password, which §7
    allows.

    Refused at load, as the policy rule below is. The error names the accounts,
    where they are declared, and the refs. It compares stores as the file states
    them, for the reason ``_check_one_policy_per_password`` gives. Where one
    store comes only from a profile or ``SOPULI_VAULT``, the file cannot show the
    pair. ``sopuli.generate.draw_once`` then draws each account its own value,
    and ``generate.group`` refuses a write that carries two values for one
    password, before anything is written.

    Accounts are compared as the file spells them. Whether two spellings are
    one Oracle user is the duplicate-name rule's question, not this one's.
    """
    documents: dict[tuple[str | None, str], dict[tuple[tuple[str, ...], str], Binding]] = {}
    for binding in bindings:
        ref = binding.secret
        if ref is None:
            continue
        place = () if ref.field is None else (ref.field, *ref.pointer_segments)
        seen = documents.setdefault((binding.vault, normalise_path(ref.path)), {})
        if (place, binding.account) in seen:
            # One account in one place on another target: a shared password.
            continue
        for (other_place, _), other in seen.items():
            if not _overlaps(place, other_place):
                continue
            other_ref = other.secret
            assert other_ref is not None
            if place == other_place:
                fault = f"resolve to one password at {_address(binding, ref)}"
            else:
                fault = (
                    f"overlap at {_address(other, other_ref)} and {_address(binding, ref)}: "
                    "writing one password replaces the other"
                )
            declared = _declared_in(other, binding)
            if other.account == binding.account:
                # The places differ, or `seen` would have skipped this binding.
                message = f"{binding.account!r} ({declared}) has two places that {fault}"
            else:
                message = f"{other.account!r} and {binding.account!r} ({declared}) {fault}"
            raise ConfigError(
                message,
                at=where.get(binding.application, ROOT),
                hint=(
                    "each account needs one place of its own in the document, such as "
                    "path#FIELD/{account}: give the refs distinct, non-nested fields or pointers"
                ),
            )
        seen[(place, binding.account)] = binding


def _overlaps(one: tuple[str, ...], other: tuple[str, ...]) -> bool:
    """Whether one place contains the other, or they are the same place."""
    shorter = min(len(one), len(other))
    return one[:shorter] == other[:shorter]


def _declared_in(first: Binding, second: Binding) -> str:
    """Where two bindings come from, for a message about the pair."""
    if first.application == second.application:
        return (
            "both in the inline application"
            if first.application is None
            else (f"both in entry {first.application!r}")
        )
    return f"entries {first.application!r} and {second.application!r}"


def _address(binding: Binding, ref: SecretRef) -> str:
    """``ref``, with the binding's store in front where the ref names none."""
    if ref.vault is not None or binding.vault is None:
        return str(ref)
    return f"{binding.vault}:{ref}"


def _check_one_policy_per_password(
    bindings: Sequence[Binding], *, where: Mapping[str | None, KeyPath]
) -> None:
    """Every binding that resolves to one password resolves to one policy.

    Two bindings resolve to one password when they are the same account and
    their refs address the same field and pointer in the same document of the
    same store. That is one account on several targets with no target label in
    its ref, which §7 allows and often intends. An override can still give one
    of those targets its own ``policy:``, or a second application entry can
    declare the account with another policy and the same ref. Then one stored
    password would have to follow two policies. ``creds generate`` would draw it
    against one of them, and ``creds check`` would report it against the other on
    every run.

    Refused at load, as a defect in the file, so every verb and
    ``config validate`` say so before anything is drawn (decided in #830). The
    error names the account, the ref with its store, and each policy with a
    target it governs. It points at the application entry: a binding does not
    record which override set its policy.

    **Only as the file states the stores**, as ``_check_stages_do_not_collide``
    is. A binding whose ``vault`` is still ``None`` gets one later from a profile
    or ``SOPULI_VAULT``, and the file alone cannot say which. Two such bindings
    with one ref are compared, because they will get the same store. One of them
    beside a binding that names a store is not, because the run may give it
    another. Checking again at run time would check only what the run's
    selectors kept, so the answer would depend on the selection.

    Two *different* accounts on one field never reach it:
    ``_check_one_account_per_password`` refuses them first.
    """
    seen: dict[tuple[str, str | None, str, str | None, str | None], Binding] = {}
    for binding in bindings:
        ref = binding.secret
        if ref is None:
            continue
        key = (binding.account, binding.vault, normalise_path(ref.path), ref.field, ref.pointer)
        first = seen.setdefault(key, binding)
        if first.policy == binding.policy:
            continue
        address = _address(binding, ref)
        if first.target == binding.target:
            # Two entries on one target: the entries tell them apart.
            places = (
                f"on target {binding.target!r}, under two policies: {_policy(first)} from "
                f"entry {first.application!r} and {_policy(binding)} from entry "
                f"{binding.application!r}"
            )
        else:
            places = (
                f"on targets {first.target!r} and {binding.target!r}, under two policies: "
                f"{_policy(first)} on {first.target!r} and {_policy(binding)} on "
                f"{binding.target!r}"
            )
        raise ConfigError(
            f"{binding.account!r} has one password at {address} {places}",
            at=where.get(binding.application, ROOT),
            hint=(
                "one password cannot follow two policies: give these targets one policy, "
                "or give each target its own secret by putting a target label, such as "
                "{tenant}, in the ref"
            ),
        )


def _policy(binding: Binding) -> str:
    return "no policy" if binding.policy is None else repr(binding.policy)


def _check_stages_do_not_collide(
    bindings: Sequence[Binding], config: Config, *, where: Mapping[str | None, KeyPath]
) -> None:
    """No two accounts may stage into the same place in one document.

    ``_check_stageable`` refuses a ref with *nowhere* to stage. This refuses a
    set of refs that all have the **same** somewhere -- which is what
    ``path#{account}`` produces, because a field per account with no pointer
    below it leaves every account's ``pending`` at the document root. The merge
    then keeps whichever was written last: one account's new password lost, and
    the other's given to both.

    It cannot live beside ``_check_stageable``, which is called per binding with
    no view of its siblings. It is a property of the set, so it runs once every
    binding exists -- which is still load time, and still before any command has
    done anything (invariant 4). ``sopuli.generate.group`` also guards it at the
    write boundary, but that is one lock and one printed plan too late, and the
    wrong audience: this is a defect in the *file*, so it is what
    ``config validate`` should say.

    **Only where staging is emulated**, for ``_check_stageable``'s own reason:
    where a store stages natively the stages are versions of the secret, so there
    is no root ``pending`` key for two accounts to contend over.

    **Only where the store is known.** A binding whose ``vault`` is still ``None``
    is one C15 completes later from a profile or ``SOPULI_VAULT``, and its
    backend -- and therefore whether this rule applies at all -- is not knowable
    from the file alone. Those are left to ``generate.group``'s guard, which is
    the second reason that guard stays.
    """
    labels = {vault.name: STAGING_LABELS.get(vault.type) for vault in config.vaults}
    stageable = [
        binding
        for binding in bindings
        if binding.vault is not None and labels.get(binding.vault) == STAGING_EMULATED
    ]
    for collision in colliding_stages(stageable):
        raise ConfigError(
            collision.description,
            at=where.get(_declared_by(stageable, collision), ROOT),
            hint=STAGE_COLLISION_HINT,
        )


def _declared_by(bindings: Sequence[Binding], collision: StageCollision) -> str | None:
    """Which application entry produced the second half of ``collision``.

    The *second* account of the pair, because that is the one whose arrival made
    it a collision -- and in the ordinary case both are in the same entry anyway,
    since one ``secret_template`` is what puts two accounts in one document.

    Matched on the **document as well as the account**, not on the name alone.
    One account may be declared by more than one application entry, each with its
    own ref, and only one of those entries is the one that collides; locating by
    name would then point at whichever entry mentions the account first and send
    an operator to a line that is fine.
    """
    return next(
        (
            binding.application
            for binding in bindings
            if binding.account == collision.accounts[1]
            and binding.vault == collision.vault
            and binding.secret is not None
            and normalise_path(binding.secret.path) == collision.path
        ),
        None,
    )


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
    """A ref with no store, and no `vaults:` block to point one at later.

    ``store`` is `None` here means none of §3's chain named one -- not the ref's
    own prefix, not the entry, not an override, not the target, not
    ``defaults.vault``. That is not always a mistake: a profile's `vault:` is
    deliberately left out of the chain (`_vault_for`'s docstring), because which
    profile is active is a property of a *run* and bindings are built once at
    load, and the same is true of `SOPULI_VAULT` (P3, decision #10). Both can
    still complete this binding once a run picks one -- but only if the file declared
    somewhere for them to point *at*. `config show --resolved` already renders a
    `-` for this binding rather than a verdict, and the command that actually
    needs a store is where the exact answer belongs (invariant 4).

    What is refused here is narrower: `vaults:` declaring nothing at all. Then
    there is no name a profile or `SOPULI_VAULT` could select even in principle
    -- a store name resolves against what the file declared (invariant 5; see
    `references.py`'s own dangling-name rule) -- so no run of this file can ever
    rotate this account, and that is true regardless of profile or environment.
    Refusing here is `config validate` catching the case early, rather than
    every target discovering it separately at plan time.
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
    """A rendered ref must have somewhere to stage into (Q7).

    :func:`~sopuli.payload.stage_layout` refuses a ref naming a whole secret --
    nothing to put ``pending`` and ``previous`` beside -- and one whose field is a
    key the mirror rule generates, which would put the current stage and a
    staging sibling in one place. This check makes both refusals happen when the
    file is read, not at the first rotation. §1 calls the account→secret binding
    the safety-critical part, and invariant 4 wants a command that cannot succeed
    to fail before it has written anything.

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
    resolver (decision #10): a config file can be read without knowing what
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

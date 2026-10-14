"""Which targets a selector names (§3, §4).

An application says which targets it applies to in one of three ways -- a list of
names, a group, or a label match -- or says nothing, which means all of them.
This resolves any of those against the expanded estate.

One rule, applied everywhere: **a selector filters the declared set and cannot
extend it** (invariant 5). Every target returned here came out of
:mod:`sopuli.config.expansion`, so there is no path by which a match string
introduces a target the file does not declare.

A match is *every* pair, compared for equality against the target's labels. C2
records that as the deliberate limit: no negation, no set membership, no
wildcards, revisited only when a real config needs them. A selector language is
a debugging liability in the file that decides where passwords go, and the same
reasoning that keeps `target_sets` to two dimensions applies here.

Results keep estate order rather than the order the selector wrote, so two
applications selecting the same targets different ways produce the same list --
which is what makes plan output comparable between them.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace

from sopuli.config.errors import ROOT, ArgumentError
from sopuli.config.model import (
    Binding,
    Config,
    ExpandedTarget,
    Pairs,
    Target,
    TargetSelector,
    as_dict,
)

#: One (account, target) pair, which is the row :class:`Config.bindings` is keyed
#: by and the unit a repair set is written in.
#:
#: Not called ``Pair``: this module already spends that word on a label pair, and
#: two things called a pair in one file is the sort of collision that survives
#: review and confuses the next reader.
AccountTarget = tuple[str, str]

#: What a `--select` pair is written with. Not configurable: a separator that
#: could be something else is one more thing to get wrong in a shell.
PAIR_SEPARATOR = ","
KEY_SEPARATOR = "="

#: Where a `--select` error points. A `KeyPath` names a place in the document
#: and this is not one, but it renders as the option the user typed, which is
#: where the reader has to go and fix it.
#:
#: That location is also why these raise `ArgumentError` rather than a plain
#: `ConfigError`: nothing is wrong with any file, so the exit code is 2 and there
#: is no run document (J7). The message shape is identical.
AT_SELECT = ROOT.key("--select")


@dataclass(frozen=True)
class Selection:
    """Everything the command line said about *which* of the estate to act on.

    `01-configuration.md` §2 and §3 show these flags in their examples. They are
    one object rather than five arguments because every command that narrows an
    estate narrows it the same way, and because the run document reports the set
    as given in ``invocation.selection``.

    **Every member narrows; none extends** (invariant 5). They combine as *and*,
    which is the same rule `--select`'s own pairs already follow: `--application
    acme --select env=dev` is acme's accounts on dev targets, not their union. An
    *or* would need a language, and C2 records why this file does not have one.

    **Names are looked up, labels are filtered.** A `--select` pair that matches
    no target is an empty run and not an error -- labels describe an estate that
    changes. A `--target` that names nothing is a typo, and reporting it as "0
    targets, nothing to do" is how a scheduled rotation silently stops rotating.
    :meth:`refuse_unknown` is where that distinction is enforced.
    """

    #: Label pairs, from ``--select``. Every pair must hold.
    select: Pairs = ()
    #: Target names, from ``--target``.
    targets: tuple[str, ...] = ()
    #: Account names, from ``--account``. Matched case-folded, for the reason
    #: :func:`sopuli.driver.guardrails.is_declared` gives: the file writes
    #: ``acme_web_user`` and Oracle stores ``ACME_WEB_USER``, and neither is
    #: wrong.
    accounts: tuple[str, ...] = ()
    #: Group names, from ``--group``. A group is a named label match (§4), so
    #: this resolves to labels and then filters like ``select`` does.
    groups: tuple[str, ...] = ()
    #: Application entry names, from ``--application`` / ``--app``.
    applications: tuple[str, ...] = ()

    @property
    def is_everything(self) -> bool:
        """Whether this run was given no narrowing at all.

        The case worth keeping distinct: a command given nothing and one given a
        selector that happens to match the whole estate take the same path, and
        only the first omits ``selection`` from the run document.
        """
        return not (
            self.select or self.targets or self.accounts or self.groups or self.applications
        )

    def names(self, account: str) -> bool:
        """Whether ``--account`` named this account specifically.

        §4's guardrail rule turns on this: an account the operator **named**
        refuses the run, and one that merely fell inside a broader selection is
        skipped. Naming a *target*, a *group* or an application is the second
        case however few accounts it resolves to -- otherwise the rule would
        change behaviour according to how many rows an estate happens to have
        today, which is the one thing a safety rule must not do.
        """
        folded = {name.casefold() for name in self.accounts}
        return account.casefold() in folded

    def as_json(self) -> dict[str, object]:
        """``invocation.selection``, omitting the members nobody used.

        Omitted rather than sent empty, which is the rule the document already
        applies to this object: an empty array would claim the run considered a
        selector it was never given.
        """
        found: dict[str, object] = {}
        if self.select:
            found["select"] = as_dict(self.select)
        for name, values in (
            ("targets", self.targets),
            ("accounts", self.accounts),
            ("groups", self.groups),
            ("applications", self.applications),
        ):
            if values:
                found[name] = list(values)
        return found


def matches(target: Target, match: Pairs) -> bool:
    """Whether a target carries every label in ``match``.

    An empty match matches everything, which is why the readers refuse to build
    one: a group whose `match:` is `{}` is `--all` wearing a name that hides it
    (:func:`~sopuli.config.fields.label_selector`).
    """
    labels = as_dict(target.labels)
    return all(labels.get(key) == value for key, value in match)


def select(config: Config, selector: TargetSelector) -> tuple[ExpandedTarget, ...]:
    """The targets a selector names, in estate order.

    Names are looked up rather than filtered on, because a name that names
    nothing is a typo worth reporting -- :mod:`sopuli.config.references` does
    that before this runs, so by here every name resolves.
    """
    if selector.is_everything:
        return config.expanded_targets

    if selector.names:
        wanted = set(selector.names)
        return tuple(expanded for expanded in config.expanded_targets if expanded.name in wanted)

    match = selector.match
    if selector.group is not None:
        match = _group_match(config, selector.group)

    return tuple(
        expanded for expanded in config.expanded_targets if matches(expanded.target, match)
    )


def parse_selector(values: Sequence[str]) -> Pairs:
    """``--select env=qa,tenant=beta`` as a label match.

    Repeats accumulate and every pair must hold, which is what ``matches``
    already means for a group's ``match:``. One selector language, whether it
    was written in the file or on the command line.

    A key given twice is refused rather than resolved. ``--select env=dev,env=qa``
    is either a typo or a wish for "dev *or* qa", and a match that can only
    ever be a conjunction would silently answer the second reading with an
    empty estate. C2 has no set membership; this refuses to pretend.
    """
    seen: dict[str, str] = {}
    for value in values:
        for pair in value.split(PAIR_SEPARATOR):
            key, label = _split_pair(pair)
            if key in seen and seen[key] != label:
                raise ArgumentError(
                    f"label '{key}' selected twice, as '{seen[key]}' and '{label}'",
                    at=AT_SELECT,
                    hint="a selector is every pair at once; there is no 'or' (C2)",
                )
            seen[key] = label
    return tuple(sorted(seen.items()))


def _split_pair(pair: str) -> tuple[str, str]:
    """One ``k=v``, or an error quoting exactly what was typed."""
    if KEY_SEPARATOR not in pair:
        raise ArgumentError(
            f"'{pair}' is not a label match",
            at=AT_SELECT,
            hint="write it as key=value, e.g. --select env=qa,tenant=beta",
        )
    key, _, label = pair.partition(KEY_SEPARATOR)
    if not key.strip() or not label.strip():
        raise ArgumentError(
            f"'{pair}' has an empty {'key' if not key.strip() else 'value'}",
            at=AT_SELECT,
            hint="both sides are required; a label with no value selects nothing",
        )
    return key.strip(), label.strip()


def filter_estate(config: Config, selection: Selection) -> Config:
    """The estate reduced to what ``selection`` names, bindings with it.

    Invariant 5 holds structurally rather than by inspection: this only ever
    *removes* from ``expanded_targets`` and ``bindings``, so no selector can
    introduce a target or an account the file does not declare. `--force` does
    not reach here either; there is nothing here for it to relax.

    An empty selection returns the config unchanged rather than everything or
    nothing, so a command given no selector and one given a selector matching the
    whole estate take the same path.

    **Targets are narrowed first, then bindings.** A binding whose target was
    filtered out describes work on something this run cannot see, so it goes
    whatever else selected it -- which is why ``--account`` cannot resurrect an
    account on a target ``--select`` removed.

    **An account selector narrows targets too**, by dropping the ones left with
    no bindings. That is what keeps the blast radius honest: `--account
    acme_web_user` against an estate where three of twenty targets have that
    account is a run reaching *three* targets, and a plan counting twenty would
    make `max_targets` and `confirm_environments` answer about work this run is
    not going to do.

    It is also what stops any of these flags silently meaning nothing on a
    command that lists targets rather than accounts -- which
    :func:`sopuli.cli.select_option` calls the same defect as ignoring one that
    does. `target list --account acme_web_user` is "the targets where this
    account lives", and every flag narrows every command that carries it.

    **Each flag is a union within itself and an intersection with the others.**
    `--target a --target b` is both targets; `--group x --group y` is the targets
    in either group; and `--select env=dev --group prod-pdbs` is targets that
    satisfy *both*, which for a `prod-pdbs` matching `env=prod` is correctly
    nothing. Groups are therefore evaluated as their own predicate rather than
    merged into the label match: merging would let a group's labels silently
    overwrite the ones the operator typed, and would turn two groups into one
    conjunction that can match nothing an operator asked for.
    """
    return narrow(config, selection)[0]


@dataclass(frozen=True)
class LeftOut:
    """One declared target, or one binding on a selected target, that a selector
    left out of the run, and the flag that did.

    What ``--debug`` reports about selection. :func:`filter_estate` returns only
    what is left, so an operator whose run planned fewer units than expected
    cannot see from the plan which flag removed the others.
    """

    target: str
    #: The flag as the operator types it, such as ``--select``.
    flag: str
    #: ``None`` where the whole target was left out. Where a target flag did
    #: that, its bindings are not listed one by one: the target's line already
    #: says why they are gone.
    account: str | None = None


def narrow(config: Config, selection: Selection) -> tuple[Config, tuple[LeftOut, ...]]:
    """:func:`filter_estate`, and each target and binding it left out, and why.

    One walk gives both, so the reasons cannot disagree with what was removed.
    Targets come first, then the bindings left out on the targets a target flag
    kept. A target left with no bindings, which only a binding-level flag
    drops, is named with the first flag that removed one of its bindings, or
    with the first such flag given where it had none.
    """
    if selection.is_everything:
        return config, ()
    prune = None
    if selection.accounts:
        prune = "--account"
    elif selection.applications:
        # Only where a binding-level selector was given. Without one, a target
        # with no bindings is an ordinary part of the estate -- a database
        # nothing is declared against yet -- and dropping it would make
        # `target list` and `doctor` stop reporting the targets most worth
        # noticing.
        prune = "--application"
    tests = _Tests.of(config, selection)
    return _walk(config, tests.target, tests.binding, prune=prune)


def narrow_to_pairs(
    config: Config, pairs: Iterable[AccountTarget]
) -> tuple[Config, tuple[LeftOut, ...]]:
    """:func:`filter_to_pairs`, and each binding and target it left out.

    Everything is left out by the flag that hands in a pair set, ``--repair``.
    """
    wanted = {(account.casefold(), target) for account, target in pairs}

    def binding(one: Binding) -> str | None:
        return None if (one.account.casefold(), one.target) in wanted else "--repair"

    return _walk(config, lambda expanded: None, binding, prune="--repair")


def _walk(
    config: Config,
    target_test: Callable[[ExpandedTarget], str | None],
    binding_test: Callable[[Binding], str | None],
    *,
    prune: str | None,
) -> tuple[Config, tuple[LeftOut, ...]]:
    """Narrow targets, then the bindings on the targets left, then, where
    ``prune`` is a flag, the targets left with no bindings.

    Each test returns the flag that excludes its argument, or ``None``. This
    only ever removes, so no test can introduce a target or a binding the file
    does not declare (invariant 5).
    """
    targets: list[ExpandedTarget] = []
    gone: list[LeftOut] = []
    for expanded in config.expanded_targets:
        flag = target_test(expanded)
        if flag is None:
            targets.append(expanded)
        else:
            gone.append(LeftOut(expanded.name, flag))

    selected = {expanded.name for expanded in targets}
    bindings: list[Binding] = []
    dropped: list[LeftOut] = []
    first: dict[str, str] = {}
    for binding in config.bindings:
        if binding.target not in selected:
            continue
        flag = binding_test(binding)
        if flag is None:
            bindings.append(binding)
        else:
            dropped.append(LeftOut(binding.target, flag, binding.account))
            first.setdefault(binding.target, flag)

    if prune is not None:
        kept = {binding.target for binding in bindings}
        gone.extend(
            LeftOut(expanded.name, first.get(expanded.name, prune))
            for expanded in targets
            if expanded.name not in kept
        )
        targets = [expanded for expanded in targets if expanded.name in kept]

    narrowed = replace(config, expanded_targets=tuple(targets), bindings=tuple(bindings))
    return narrowed, (*gone, *dropped)


@dataclass(frozen=True)
class _Tests:
    """Each selector flag as a test, built once per selection.

    :func:`narrow` builds it and hands its two tests to :func:`_walk`.
    """

    selection: Selection
    groups: tuple[Pairs, ...]
    targets: frozenset[str]
    #: ``--account``, case-folded for the reason :attr:`Selection.accounts` gives.
    accounts: frozenset[str]

    @classmethod
    def of(cls, config: Config, selection: Selection) -> _Tests:
        return cls(
            selection,
            tuple(_group_match(config, name) for name in selection.groups),
            frozenset(selection.targets),
            frozenset(name.casefold() for name in selection.accounts),
        )

    def target(self, expanded: ExpandedTarget) -> str | None:
        """The first flag that excludes this target, or ``None`` if none does."""
        if self.targets and expanded.name not in self.targets:
            return "--target"
        if not matches(expanded.target, self.selection.select):
            return "--select"
        if self.groups and not any(matches(expanded.target, match) for match in self.groups):
            return "--group"
        return None

    def binding(self, binding: Binding) -> str | None:
        """The first binding-level flag that excludes this binding, or ``None``."""
        if self.accounts and binding.account.casefold() not in self.accounts:
            return "--account"
        applications = self.selection.applications
        if applications and binding.application not in applications:
            return "--application"
        return None


def filter_to_pairs(config: Config, pairs: Iterable[AccountTarget]) -> Config:
    """The estate reduced to a named set of (account, target) pairs.

    What :class:`Selection` cannot express. Its members are independent
    dimensions combined as *and*, so the nearest thing to a pair set --
    ``accounts={a, b}`` with ``targets={x, y}`` -- is their **cross product**,
    which is strictly wider. For ``{a@x, b@y}`` that is four pairs where two were
    wanted, and the two extra are exactly the logins ``creds apply --repair``
    exists to save (UC-1 §``--repair``).

    Invariant 5 holds the same structural way :func:`filter_estate` does: this
    only ever *removes* from ``bindings`` and ``expanded_targets``, so no pair
    can introduce an account or a target the file does not declare.

    **A pair the configuration does not declare is dropped, not refused** -- the
    opposite of :func:`refuse_unknown`, and the difference is what the caller is
    holding. ``--target nosuch`` is a claim about the estate *now*, so a name
    that resolves to nothing is a typo worth stopping for. A pair set comes from
    a document describing a run that already happened, and a pair since removed
    from the config is drift somebody has already dealt with. Refusing there
    would make a document unusable for the accounts it is still right about,
    which is the whole of what it was read for.

    Accounts are compared case-folded, for the reason ``--account`` already is:
    the file writes ``acme_web_user`` where Oracle stores ``ACME_WEB_USER``, and
    a pair set that has been through a database carries the second spelling.
    Target names are the tool's own vocabulary and are compared as written.

    Targets left with no bindings are pruned, which is
    :func:`filter_estate`'s rule for a binding-level selector and is what keeps
    the blast radius honest: a repair of two pairs on one target is a run
    reaching *one* target, and a plan counting the other twenty would make
    ``max_targets`` and ``confirm_environments`` answer about work this run is
    not going to do.
    """
    return narrow_to_pairs(config, pairs)[0]


def refuse_unknown(config: Config, selection: Selection) -> None:
    """Refuse a selector that names something the configuration does not have.

    **A name that names nothing is a typo; a label that matches nothing is an
    empty run.** That asymmetry is the whole function, and it is the same one
    :func:`select` already applies inside the file: labels describe an estate
    that changes underneath them, and a name is a claim that a particular thing
    exists.

    The failure this prevents is specific and quiet. A scheduled
    ``creds rotate --application acme`` where somebody renamed the entry to
    ``acme-web`` would otherwise select nothing, do nothing, exit 0, and go on
    reporting success for a credential that has stopped being rotated. Every
    other guardrail in this tool is about doing too much; this one is about
    doing nothing and saying it went fine.

    Checked against the **unfiltered** estate, so the message can tell an
    operator that the name exists but their other selectors excluded it -- which
    is a different mistake from a misspelling and has a different fix.
    """
    _refuse_missing(
        "--target",
        selection.targets,
        {expanded.name for expanded in config.expanded_targets},
    )
    _refuse_missing("--group", selection.groups, {group.name for group in config.groups})
    # From `applications:` and not from the bindings they produced. An entry
    # whose `targets:` selector matches nothing is validly declared and yields no
    # binding, and refusing its name as undeclared would report a typo the
    # operator did not make -- while the thing they actually want to know, that
    # the entry currently reaches no target, is what the empty run tells them.
    _refuse_missing(
        "--application",
        selection.applications,
        {entry.name for entry in config.applications if entry.name},
    )
    _refuse_missing(
        "--account",
        selection.accounts,
        {name for entry in config.applications for name in entry.accounts},
        folded=True,
    )


def _refuse_missing(
    flag: str, given: Sequence[str], declared: set[str], *, folded: bool = False
) -> None:
    """One flag's names against what the file declares.

    ``folded`` for accounts, and only accounts: the file writes
    ``acme_web_user`` where Oracle stores ``ACME_WEB_USER``, and an operator
    copying a name out of a database into ``--account`` is doing the obvious
    thing. Target, group and application names are the tool's own vocabulary and
    are compared as written.
    """
    known = {name.casefold() for name in declared} if folded else set(declared)
    missing = [name for name in given if (name.casefold() if folded else name) not in known]
    if not missing:
        return
    named = ", ".join(f"`{name}`" for name in missing)
    plural = "" if len(missing) == 1 else "s"
    listed = ", ".join(sorted(declared)[:8]) or "nothing"
    raise ArgumentError(
        # The flag is not repeated in the message: `at` renders as the option the
        # operator typed, and "--target: --target name not declared" reads as a
        # bug in the tool rather than a typo in the command.
        f"name{plural} not declared in the configuration: {named}",
        at=ROOT.key(flag),
        hint=(
            f"the configuration declares {listed}"
            f"{', ...' if len(declared) > 8 else ''} -- a selector filters the "
            f"declared set and cannot extend it (invariant 5)"
        ),
    )


def _group_match(config: Config, name: str) -> Pairs:
    """A group is a named match, so selecting by group is selecting by its labels.

    The group is known to exist: references.py resolves every group name against
    `groups:` before anything selects with one.
    """
    for group in config.groups:
        if group.name == name:
            return group.match
    return ()  # pragma: no cover - references.py rejects an undeclared group first

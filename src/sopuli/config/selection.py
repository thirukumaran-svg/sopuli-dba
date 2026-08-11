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

from sopuli.config.model import Config, ExpandedTarget, Pairs, Target, TargetSelector, as_dict


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


def _group_match(config: Config, name: str) -> Pairs:
    """A group is a named match, so selecting by group is selecting by its labels.

    The group is known to exist: references.py resolves every group name against
    `groups:` before anything selects with one.
    """
    for group in config.groups:
        if group.name == name:
            return group.match
    return ()  # pragma: no cover - references.py rejects an undeclared group first

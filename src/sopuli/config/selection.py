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

from collections.abc import Sequence
from dataclasses import replace

from sopuli.config.errors import ROOT, ArgumentError
from sopuli.config.model import Config, ExpandedTarget, Pairs, Target, TargetSelector, as_dict

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
#: is no run document (J7, issue #8). The message shape is identical.
AT_SELECT = ROOT.key("--select")


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
    empty estate. C2 leaves set membership open; this refuses to pretend.
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


def filter_estate(config: Config, match: Pairs) -> Config:
    """The estate reduced to the targets ``match`` selects, bindings with them.

    Invariant 5 holds structurally rather than by inspection: this only ever
    removes from ``expanded_targets``, so no selector can introduce a target the
    file does not declare. Bindings follow their target -- a binding whose
    target was filtered out describes work on something this run cannot see.

    An empty ``match`` returns the config unchanged rather than everything or
    nothing, so a command that was given no ``--select`` and one given a
    selector matching the whole estate take the same path.
    """
    if not match:
        return config

    targets = tuple(
        expanded for expanded in config.expanded_targets if matches(expanded.target, match)
    )
    selected = {expanded.name for expanded in targets}
    bindings = tuple(binding for binding in config.bindings if binding.target in selected)
    return replace(config, expanded_targets=targets, bindings=bindings)


def _group_match(config: Config, name: str) -> Pairs:
    """A group is a named match, so selecting by group is selecting by its labels.

    The group is known to exist: references.py resolves every group name against
    `groups:` before anything selects with one.
    """
    for group in config.groups:
        if group.name == name:
            return group.match
    return ()  # pragma: no cover - references.py rejects an undeclared group first

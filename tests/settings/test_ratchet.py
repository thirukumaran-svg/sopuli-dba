"""Invariant 10, as one test over every safety setting rather than per option.

    Safety settings only ratchet toward safe. `readonly`, `--dry-run`,
    `max_targets` and `confirm_environments` cannot be relaxed by a
    higher-precedence source.

A per-option test is one somebody has to remember to write when `--skip-verify`
arrives next year. This one enumerates :data:`SAFETY_SETTINGS`, so a setting
added to that frozenset is covered from the moment it is added, and a setting
added *without* being put there fails ``test_registry.py`` instead.

Exhaustive rather than sampled: every subset of a setting's declared layers,
crossed with every assignment from a small per-type domain. The domains are tiny
on purpose -- what is being checked is the merge rule, and a third integer says
nothing a second one did not. No ``hypothesis``: it is not in the dev extras, and
tier 0 (04-testing.md §4) is worth keeping dependency-light when
``itertools.product`` says the same thing.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from itertools import combinations, product
from typing import Any

import pytest

from sopuli.settings import (
    SAFETY_SETTINGS,
    Contribution,
    Layer,
    Resolved,
    resolve,
    setting,
)

#: Values per declared type. Enough to distinguish "safest" from "last one wins"
#: in every direction, and no more.
DOMAINS: dict[type, tuple[Any, ...]] = {
    bool: (False, True),
    int: (1, 5, 200),
    tuple: ((), ("prod",), ("dev", "prod")),
}


def at_least_as_safe(resolved: Any, asked: Any, safe_bool: bool = True) -> bool:
    """Whether ``resolved`` gives away nothing that ``asked`` would have kept.

    Written out here rather than imported from the resolver: a test that reuses
    the implementation's own notion of "safer" would pass for any consistent
    definition, including a wrong one.

    ``safe_bool`` is the one thing taken from the registry, because it is a
    *declaration* rather than a merge rule: `readonly: true` refuses more and
    `locking.break_expired: true` refuses less (#83), and no property of the two
    values themselves says which. Everything about how layers combine is still
    written out here.
    """
    if isinstance(resolved, bool):
        return resolved is safe_bool or asked is not safe_bool
    if isinstance(resolved, tuple):
        return set(asked) <= set(resolved)
    return bool(resolved <= asked)


def cases() -> Iterator[tuple[str, tuple[Contribution, ...]]]:
    """Every setting, every subset of its layers, every assignment of values."""
    for name in sorted(SAFETY_SETTINGS):
        definition = setting(name)
        # The built-in default is the resolver's own fallback, not something a
        # caller supplies, so it is not part of the enumeration.
        layers = sorted(
            (one for one in definition.layers if one is not Layer.BUILTIN),
            key=lambda one: one.authority,
        )
        values = DOMAINS[definition.type]
        for size in range(1, len(layers) + 1):
            for chosen in combinations(layers, size):
                for assignment in product(values, repeat=size):
                    yield (
                        name,
                        tuple(
                            Contribution(layer, value, f"{layer}.{name}")
                            for layer, value in zip(chosen, assignment, strict=True)
                        ),
                    )


CASES = list(cases())


def test_the_enumeration_is_not_empty() -> None:
    """Guards the generator itself.

    An empty case list would make every assertion below a vacuous pass -- green,
    and checking nothing. The same reason ``tests/test_schemas.py`` guards its
    glob.
    """
    assert len({name for name, _ in CASES}) == len(SAFETY_SETTINGS)
    assert len(CASES) > 100


@pytest.mark.parametrize(("name", "contributions"), CASES)
def test_no_layer_is_ever_relaxed(name: str, contributions: Sequence[Contribution]) -> None:
    """The invariant itself: the answer is at least as safe as every request."""
    answer = resolve(name, contributions)
    assert answer is not None
    safe = setting(name).safe_bool
    for one in contributions:
        assert at_least_as_safe(answer.value, one.value, safe), (
            f"{name}: resolved {answer.value!r} is less safe than {one.location}'s {one.value!r}"
        )


@pytest.mark.parametrize(("name", "contributions"), CASES)
def test_the_reported_source_is_the_lowest_that_produced_the_value(
    name: str, contributions: Sequence[Contribution]
) -> None:
    """Ties resolve downward, over the whole enumeration rather than one example.

    The reported layer must be one that actually contributed, and where several
    did, the most durable of them -- the config key rather than the flag.
    """
    answer = resolve(name, contributions)
    assert answer is not None
    assert answer.layer in {one.layer for one in contributions}
    contributors = [one for one in answer.contributions if _contributed(one, answer)]
    assert contributors, f"{name}: nothing contributed to {answer.value!r}"
    assert answer.layer is contributors[-1].layer


@pytest.mark.parametrize(("name", "contributions"), CASES)
def test_every_reported_relaxation_really_asked_for_less(
    name: str, contributions: Sequence[Contribution]
) -> None:
    """A note that fires on a layer which got what it asked for is noise.

    The other half of `--explain`'s usefulness: the ratchet line has to mean
    something every time it appears, or it becomes the line people skip.
    """
    answer = resolve(name, contributions)
    assert answer is not None
    safe = setting(name).safe_bool
    for one in answer.relaxations:
        assert not at_least_as_safe(one.value, answer.value, safe)


def _contributed(one: Contribution, answer: Resolved) -> bool:
    """Whether this contribution is part of why the answer is what it is."""
    if isinstance(answer.value, tuple):
        return bool(one.value) or not answer.value
    return bool(one.value == answer.value)

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

from sopuli.config.errors import ConfigError
from sopuli.settings import (
    SAFETY_SETTINGS,
    Contribution,
    Layer,
    ListMerge,
    Resolved,
    Setting,
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

#: The domain for a list that **intersects** rather than unions (H6, #453). Two
#: single-method layers and the pair, which gives every shape that matters: one
#: layer narrowing another, two layers agreeing, and two layers with nothing in
#: common -- which is the refusal and is enumerated rather than excluded.
#:
#: The empty list is deliberately absent, and its absence is the rule rather than
#: a gap: :func:`~sopuli.config.safety.build_safety` refuses it, so no layer can
#: ever supply one, and a domain containing it would be testing a merge of values
#: the config layer cannot produce.
INTERSECTION_DOMAIN: tuple[Any, ...] = (
    ("manual",),
    ("vault_wrapped",),
    ("manual", "vault_wrapped"),
)


def domain(definition: Setting) -> tuple[Any, ...]:
    """The values to enumerate for one setting.

    By type, except for the one thing the type cannot say. Both list settings are
    ``tuple[str, ...]`` and they merge oppositely, so `confirm_environments`
    takes environment names and `delivery.allowed_methods` takes delivery
    methods -- and giving the second the first's domain would enumerate an
    allow-list of methods that do not exist.
    """
    if definition.list_merge is ListMerge.INTERSECTION:
        return INTERSECTION_DOMAIN
    return DOMAINS[definition.type]


def at_least_as_safe(
    resolved: Any, asked: Any, safe_bool: bool = True, list_merge: ListMerge | None = None
) -> bool:
    """Whether ``resolved`` gives away nothing that ``asked`` would have kept.

    Written out here rather than imported from the resolver: a test that reuses
    the implementation's own notion of "safer" would pass for any consistent
    definition, including a wrong one.

    ``safe_bool`` and ``list_merge`` are the two things taken from the registry,
    because both are *declarations* rather than merge rules: `readonly: true`
    refuses more and `locking.break_expired: true` refuses less (#83);
    `confirm_environments` unions and `delivery.allowed_methods` intersects
    (H6, #453). No property of the values themselves says which, in either case.
    Everything about how layers combine is still written out here -- and the two
    list directions are written out *separately*, so a resolver that merged one
    the other's way fails here rather than agreeing with itself.
    """
    if isinstance(resolved, bool):
        return resolved is safe_bool or asked is not safe_bool
    if isinstance(resolved, tuple):
        if list_merge is ListMerge.INTERSECTION:
            # Narrower is safer: the answer may permit no method a layer did not.
            return set(resolved) <= set(asked)
        return set(asked) <= set(resolved)
    return bool(resolved <= asked)


def resolved_or_refusal(name: str, contributions: Sequence[Contribution]) -> Resolved | None:
    """The resolved answer, or ``None`` where the case is the disjoint refusal.

    The enumeration crosses every layer with every value, so for an intersecting
    setting it necessarily produces layers with no method in common -- which is a
    refusal rather than an answer (§9). Asserting the refusal here rather than
    filtering those cases out keeps them covered: a resolver that returned the
    empty tuple for them would reach the assertions below with a value that is
    vacuously "safest", and every one of them would pass.
    """
    if setting(name).list_merge is ListMerge.INTERSECTION and not set.intersection(
        *(set(one.value) for one in contributions)
    ):
        with pytest.raises(ConfigError, match="resolves to nothing"):
            resolve(name, contributions)
        return None
    answer = resolve(name, contributions)
    assert answer is not None
    return answer


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
        values = domain(definition)
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
    answer = resolved_or_refusal(name, contributions)
    if answer is None:
        return
    definition = setting(name)
    for one in contributions:
        assert at_least_as_safe(
            answer.value, one.value, definition.safe_bool, definition.list_merge
        ), f"{name}: resolved {answer.value!r} is less safe than {one.location}'s {one.value!r}"


@pytest.mark.parametrize(("name", "contributions"), CASES)
def test_the_reported_source_is_the_lowest_that_produced_the_value(
    name: str, contributions: Sequence[Contribution]
) -> None:
    """Ties resolve downward, over the whole enumeration rather than one example.

    The reported layer must be one that actually contributed, and where several
    did, the most durable of them -- the config key rather than the flag.
    """
    answer = resolved_or_refusal(name, contributions)
    if answer is None:
        return
    assert answer.layer in {one.layer for one in contributions}
    contributors = [
        one
        for index, one in enumerate(answer.contributions)
        if _contributed(one, answer, answer.contributions, index)
    ]
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
    answer = resolved_or_refusal(name, contributions)
    if answer is None:
        return
    definition = setting(name)
    for one in answer.relaxations:
        assert not at_least_as_safe(
            one.value, answer.value, definition.safe_bool, definition.list_merge
        )


def _contributed(
    one: Contribution, answer: Resolved, every: Sequence[Contribution], index: int
) -> bool:
    """Whether this contribution is part of why the answer is what it is.

    Written out here rather than imported, like `at_least_as_safe`. Under an
    intersection a layer contributes either by writing the answer itself -- the
    tie, where several layers wrote the same list -- or by narrowing it jointly
    with another, which only shows when the layer is taken away: an intersection
    is often something no single layer wrote, so a value test alone would report
    those cases as having no contributors at all.
    """
    if answer.list_merge is ListMerge.INTERSECTION:
        if set(one.value) == set(answer.value):
            return True
        others = [other.value for position, other in enumerate(every) if position != index]
        if not others:
            return True
        return set.intersection(*(set(value) for value in others)) != set(answer.value)
    if isinstance(answer.value, tuple):
        return bool(one.value) or not answer.value
    return bool(one.value == answer.value)

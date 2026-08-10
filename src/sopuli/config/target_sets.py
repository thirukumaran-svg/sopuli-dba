"""Building the ``target_sets:`` section -- the shape, not the expansion (§4).

Listing 35 PDBs by hand is not viable, so a set generates targets from a name
template, a DSN template and one or two dimensions. This module validates that
the set *is* one -- exactly one outer dimension, at most one inner one, nothing
nested deeper -- and leaves generation alone.

What is deliberately absent, because it needs rendered names:

* whether two combinations render the same ``name`` (§4 rule 3)
* whether every ``{placeholder}`` resolves (§4 rule 4)
* whether an ``overrides`` key names a target the set actually generates
  (§4 rule 5)

Those are the target-expansion change. The rules kept here are the ones readable
from the shape alone -- rules 1, 2 and 6 -- and they are worth having early
because a malformed ``for_each`` is otherwise discovered as a strange number of
generated targets rather than as an error.

The template is a :class:`~sopuli.config.model.Target` with its placeholders
still in it, read by the same code as an explicit target. See
:mod:`sopuli.config.targets` for why that sharing is deliberate.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.fields import (
    choice,
    describe,
    mapping,
    optional_string,
    pairs,
    reject_unknown_keys,
    string,
    string_list,
)
from sopuli.config.model import (
    DimensionValue,
    ForEach,
    InnerDimension,
    Pairs,
    TargetPatch,
    TargetSet,
)
from sopuli.config.safety import build_safety
from sopuli.config.targets import TARGET_KEYS, TARGET_TYPES, read_admin, read_oracle, read_target

TARGET_SET_KEYS = (*TARGET_KEYS, "for_each", "overrides")

#: What an override may patch: everything a target has except its name. §2 says
#: "any key may be patched"; the name is the exception because the rendered name
#: is the key the patch is found by, so patching it would make the key a lie.
PATCH_KEYS = tuple(key for key in TARGET_KEYS if key != "name")


def build_target_sets(document: dict[str, Any]) -> tuple[TargetSet, ...]:
    """Read ``target_sets:`` into templates, in document order."""
    if "target_sets" not in document:
        return ()

    at = ROOT.key("target_sets")
    entries = mapping(document["target_sets"], at=at)
    return tuple(_build_set(name, entry, at=at.key(name)) for name, entry in entries.items())


def _build_set(name: str, raw: Any, *, at: KeyPath) -> TargetSet:
    entry = mapping(raw, at=at)
    reject_unknown_keys(entry, allowed=TARGET_SET_KEYS, at=at)

    if "for_each" not in entry:
        raise ConfigError(
            "a target set must declare `for_each:`",
            at=at.key("for_each"),
            hint="a set with no dimensions generates nothing; write it under `targets:` instead",
        )

    return TargetSet(
        name=name,
        template=read_target(entry, at=at),
        for_each=_build_for_each(entry["for_each"], at=at.key("for_each")),
        overrides=_build_overrides(entry.get("overrides"), at=at.key("overrides")),
    )


# ------------------------------------------------------------- dimensions ---


def _build_for_each(raw: Any, *, at: KeyPath) -> ForEach:
    """§4 rule 1: exactly one outer dimension, whose key names it."""
    outer = mapping(raw, at=at)
    if len(outer) != 1:
        named = ", ".join(repr(key) for key in sorted(outer)) or "none"
        raise ConfigError(
            f"must name exactly one outer dimension, found {len(outer)} ({named})",
            at=at,
            hint="§4 rule 1 -- for a second independent dimension, write a second target set",
        )

    dimension, body = next(iter(outer.items()))
    at_dimension = at.key(dimension)
    entries = mapping(body, at=at_dimension)
    if not entries:
        raise ConfigError(
            f"dimension {dimension!r} has no values",
            at=at_dimension,
            hint="each key here is one value of the dimension, e.g. `dev:`",
        )

    values = tuple(
        _build_dimension_value(value, variables, at=at_dimension.key(value))
        for value, variables in entries.items()
    )
    _require_one_inner_dimension(dimension, values, at=at_dimension)
    return ForEach(dimension=dimension, values=values)


def _build_dimension_value(value: str, raw: Any, *, at: KeyPath) -> DimensionValue:
    """One value of the outer dimension: its variables, and the list among them.

    §4 rule 2 -- a variable whose value is a list becomes the inner dimension, so
    each environment can have its own tenant list. Rule 6 stops there: a list of
    lists, a mapping, or a second list variable would be a third dimension, and
    §4 is explicit that the answer to needing one is a second target set rather
    than a deeper language (C7).
    """
    variables = mapping(raw, at=at)

    scalars: list[tuple[str, str]] = []
    inner: InnerDimension | None = None

    for name, item in variables.items():
        if isinstance(item, list):
            if inner is not None:
                raise ConfigError(
                    f"a value may have only one list variable, found {inner.name!r} and {name!r}",
                    at=at.key(name),
                    hint=(
                        "two lists would be a third dimension -- §4 rule 6 stops at two, "
                        "so write a second target set"
                    ),
                )
            inner = InnerDimension(name=name, values=string_list(item, at=at.key(name)))
            if not inner.values:
                raise ConfigError(
                    f"list variable {name!r} is empty, so this value generates no targets",
                    at=at.key(name),
                    hint="delete the value, or give the list at least one entry",
                )
        elif isinstance(item, dict):
            raise ConfigError(
                f"variable {name!r} must be a value or a list, not a mapping",
                at=at.key(name),
                hint="§4 rule 6 -- nesting stops at two levels; write a second target set",
            )
        else:
            scalars.append((name, _variable(item, at=at.key(name))))

    return DimensionValue(value=value, variables=tuple(sorted(scalars)), inner=inner)


def _variable(value: Any, *, at: KeyPath) -> str:
    """A scalar variable, kept as text.

    Variables exist to be substituted into templates, so ``port: 1521`` and
    ``port: "1521"`` render identically and there is nothing to gain from
    remembering which was written. A boolean is refused rather than stringified:
    the hardened loader already keeps bare ``yes``/``no`` as strings, so a
    boolean here was written as one, and ``pdb_suffix: true`` rendering as
    ``True`` in a secret path is not what anybody meant.
    """
    if isinstance(value, bool):
        raise ConfigError(
            "must be a value or a list, not a boolean",
            at=at,
            hint='quote it -- "true" -- if the literal word is wanted in the rendered name',
        )
    if isinstance(value, str):
        return string(value, at=at)
    if isinstance(value, int | float):
        return str(value)
    raise ConfigError(f"must be a value or a list, not {describe(value)}", at=at)


def _require_one_inner_dimension(
    dimension: str, values: tuple[DimensionValue, ...], *, at: KeyPath
) -> None:
    """Every value that has an inner dimension must use the same variable for it.

    Not in §4 as a rule, but implied by what labels are for. Each dimension value
    becomes a label on the generated target (§4), so a set where ``dev`` expands
    over ``tenant`` and ``qa`` over ``shard`` produces two populations that no
    single ``--select`` can address, in one section that looks like one estate.
    §4's own remedy for anything more complex applies: write a second target set.
    """
    names = sorted({value.inner.name for value in values if value.inner is not None})
    if len(names) > 1:
        named = ", ".join(repr(name) for name in names)
        raise ConfigError(
            f"the inner dimension of {dimension!r} must be the same variable throughout, "
            f"found {named}",
            at=at,
            hint=(
                "dimension values become labels, and two different inner dimensions make "
                "one set that no single --select can address; write a second target set"
            ),
        )


# --------------------------------------------------------------- overrides ---


def _build_overrides(raw: Any, *, at: KeyPath) -> tuple[tuple[str, TargetPatch], ...]:
    """``overrides:`` -- patches keyed by *rendered* target name (§4 rule 5).

    Whether a key names a target the set generates cannot be known until
    expansion, so the check §10 asks for -- an override naming a target that is
    not generated is an error, which is what catches a rename -- lives with it.
    """
    if raw is None:
        return ()
    entries = mapping(raw, at=at)
    return tuple((name, _build_patch(patch, at=at.key(name))) for name, patch in entries.items())


def _build_patch(raw: Any, *, at: KeyPath) -> TargetPatch:
    patch = mapping(raw, at=at)
    reject_unknown_keys(
        patch,
        allowed=PATCH_KEYS,
        at=at,
        hint=(
            f"known keys here: {', '.join(sorted(PATCH_KEYS))} -- not `name`, "
            "which is the rendered name this patch is found by"
        ),
    )
    if not patch:
        raise ConfigError(
            "an override must change something",
            at=at,
            hint="an empty patch is either a leftover or a rename that was not finished",
        )

    kind = patch.get("type")
    return TargetPatch(
        type=(
            None
            if kind is None
            else choice(kind, allowed=TARGET_TYPES, at=at.key("type"), noun="target type")
        ),
        dsn=optional_string(patch, "dsn", at=at),
        environment=optional_string(patch, "environment", at=at),
        vault=optional_string(patch, "vault", at=at),
        admin=read_admin(patch.get("admin"), at=at.key("admin")),
        oracle=(
            None if "oracle" not in patch else read_oracle(patch["oracle"], at=at.key("oracle"))
        ),
        labels=_patch_labels(patch, at=at),
        safety=build_safety(patch.get("safety"), at=at.key("safety")),
    )


def _patch_labels(patch: dict[str, Any], *, at: KeyPath) -> Pairs:
    if "labels" not in patch:
        return ()
    return pairs(patch["labels"], at=at.key("labels"))

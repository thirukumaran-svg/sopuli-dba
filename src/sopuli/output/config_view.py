"""Rendering a configuration -- as loaded, and as resolved (§2, §4, §7).

Two views of one file, and the difference between them is the whole point:

* **as loaded** answers *did my YAML say what I think it says*, after however
  many ``--config`` layers were merged. It shows the file, not its consequences.
* **``--resolved``** answers *what will this tool act on*. Target sets are
  expanded, labels attached, overrides applied, and every secret ref rendered per
  account. §4 says generation is invisible until it goes wrong; this is where it
  stops being invisible.

Both are offline. No vault is contacted and no database is opened, which is what
makes ``--resolved`` safe to run against a production config from a laptop. A
secret ref here is an address and never a value (invariant 2, P2).

The JSON form is the ``config`` section of the run document. It carries the same
two views, discriminated by ``resolved``, and is pinned by
``docs/schemas/sopuli-run-1.5.schema.json``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Any

from sopuli.config import Binding, Config, ExpandedTarget, as_dict
from sopuli.config.model import Pairs
from sopuli.output.explain_view import section as explain_section
from sopuli.output.palette import Role, paint
from sopuli.output.table import Cell, Column, render_table
from sopuli.settings import Resolved

#: The environment safety rules key on (§9), and the one this view highlights.
PRODUCTION = "prod"

#: How wide a cell may get before it is truncated. A DSN and a secret ref are the
#: two that run long; both are complete in `--output json`.
_NAME = 24
_DSN = 46
_REF = 52


def render_text(
    paths: Sequence[Path],
    config: Config,
    *,
    resolved: bool,
    match: Pairs = (),
    settings: Mapping[str, Resolved] = MappingProxyType({}),
) -> str:
    """The human view. ASCII by convention; user-supplied values pass through.

    ``match`` is shown rather than assumed remembered. Filtered output is the
    kind of thing that gets pasted into a ticket, and a table of four targets
    with no note of the filter reads as an estate of four.

    ``settings`` is ``--explain``'s section, empty unless it was asked for. It is
    appended rather than replacing anything: the subject of ``config show`` is
    still the configuration, and where a setting came from is a third question
    beside the file and the estate (:mod:`sopuli.output.explain_view`).
    """
    lines = [f"config: {paths[0]}"]
    lines.extend(f"        {path} (layered)" for path in paths[1:])
    if match:
        lines.append(f"select: {_pairs(match)}")

    if resolved and match and not config.expanded_targets:
        # Not an error: a selector that matches nothing is a legitimate question
        # with the answer "none of them" (exit 0). But an empty table under a
        # `targets` heading looks like an estate that expanded to nothing, which
        # is a different and much more alarming thing.
        lines.extend(["", f"no targets carry {_pairs(match)}"])
        # `--explain` still answers its own question: a selector that matched
        # nothing says nothing about where `output` came from.
        lines.extend(explain_section(settings))
        lines.extend(_warnings(config))
        return "\n".join(lines)

    sections = _resolved_sections(config) if resolved else _declared_sections(config)
    for heading, body in sections:
        if not body:
            continue
        lines.extend(["", paint(heading, Role.HEADING)])
        lines.extend(body)

    lines.extend(explain_section(settings))
    lines.extend(_warnings(config))
    return "\n".join(lines)


def render_target_list(paths: Sequence[Path], config: Config, *, match: Pairs = ()) -> str:
    """``target list`` -- the estate, and nothing else (§4).

    The narrower question `config show --resolved` answers on the way past:
    which targets exist and where each came from. §4 makes it a command of its
    own because "generation is invisible until it goes wrong", and the moment
    it goes wrong is before a rotation, when nobody wants to read a binding
    table to count PDBs.

    Two columns short of the estate table in the resolved view. §4's own
    example has no VAULT, and the omission is the difference between the
    commands rather than an oversight: which store masters a target is a fact
    about the binding, and this view is about the target.

    §10's warnings are rendered here as they are in every other view, including
    the path where nothing matched. A command that reads a config and shows
    none of its findings is the same defect whichever view does it.
    """
    lines = [f"config: {paths[0]}"]
    lines.extend(f"        {path} (layered)" for path in paths[1:])
    if match:
        lines.append(f"select: {_pairs(match)}")

    if not config.expanded_targets:
        lines.extend(["", f"no targets carry {_pairs(match)}" if match else "no targets"])
        lines.extend(_warnings(config))
        return "\n".join(lines)

    rows = [
        [
            expanded.name,
            expanded.target.dsn,
            _environment(expanded.target.environment),
            _or_dash(expanded.target.oracle.scope),
            _source_cell(expanded),
        ]
        for expanded in config.expanded_targets
    ]
    lines.extend(
        [
            "",
            *render_table(
                [
                    Column("NAME", _NAME),
                    Column("DSN", _DSN),
                    Column("ENV"),
                    Column("SCOPE"),
                    Column("SOURCE"),
                ],
                rows,
            ),
            "",
            _estate_summary(config),
        ]
    )
    lines.extend(_warnings(config))
    return "\n".join(lines)


def render_validation(paths: Sequence[Path], config: Config) -> str:
    """The human view of ``config validate`` -- what was read, and what it holds.

    Deliberately short. A validation that passed has nothing to show, and the
    interesting output of this command is the one it does not produce: an error
    naming a key. What is here is the two facts that make a pass meaningful --
    which files were read, since discovery and layering are both invisible
    otherwise, and how much the file turned out to declare, since a config that
    expands to no targets at all passes validation and manages nothing.

    Warnings are rendered in full by the same helper ``config show`` uses. §10
    puts real findings behind them -- a profile named after an environment, a
    charset a target may not support -- and a summary line would be the wrong
    place to meet one.
    """
    lines = [f"config: {paths[0]}"]
    lines.extend(f"        {path} (layered)" for path in paths[1:])
    lines.append("")
    lines.append(
        "ok: "
        + ", ".join(
            (
                _count(len(config.expanded_targets), "target"),
                _count(len(config.bindings), "binding"),
                _count(len(config.warnings), "warning"),
            )
        )
    )
    lines.extend(_warnings(config))
    return "\n".join(lines)


def build_section(
    paths: Sequence[Path], config: Config, document: dict[str, Any], *, resolved: bool
) -> dict[str, Any]:
    """The ``config`` section of the run document.

    ``declared`` is the merged document itself rather than a reshaping of it.
    The question it answers is what the YAML says after layering, and any
    normalisation on the way out would be a second answer to that question --
    one that could drift from the first.
    """
    section: dict[str, Any] = {
        "sources": [str(path) for path in paths],
        "resolved": resolved,
    }
    if not resolved:
        section["declared"] = document
        return section

    # Built once. A set per target would be one pass over every binding for
    # every target, and §2's estate is already 22 x 126 of them.
    bound = _bound_targets(config)
    section["targets"] = [
        _target_json(expanded, bound=bound) for expanded in config.expanded_targets
    ]
    section["bindings"] = [_binding_json(binding) for binding in config.bindings]
    return section


# ------------------------------------------------------------- as loaded ---


def _declared_sections(config: Config) -> list[tuple[str, list[str]]]:
    """One block per section of the file, in the order the file writes them."""
    return [
        ("vaults", _vault_rows(config)),
        ("targets", _declared_target_rows(config)),
        ("target_sets", _target_set_rows(config)),
        ("groups", _group_rows(config)),
        ("policies", _named(policy.name for policy in config.policies)),
        ("profiles", _named(profile.name for profile in config.profiles)),
        ("applications", _application_rows(config)),
    ]


def _vault_rows(config: Config) -> list[str]:
    return render_table(
        [Column("NAME", _NAME), Column("TYPE"), Column("ADDRESS", _DSN), Column("NOTE")],
        [
            [
                vault.name,
                vault.type,
                _or_dash(vault.addr),
                Cell("non-production", Role.NOTABLE) if vault.non_production else "",
            ]
            for vault in config.vaults
        ],
    )


def _declared_target_rows(config: Config) -> list[str]:
    return render_table(
        [Column("NAME", _NAME), Column("DSN", _DSN), Column("ENV"), Column("SCOPE")],
        [
            [
                target.name,
                target.dsn,
                _environment(target.environment),
                _or_dash(target.oracle.scope),
            ]
            for target in config.targets
        ],
    )


def _target_set_rows(config: Config) -> list[str]:
    """A set is a template plus its dimensions, which is what needs checking
    before it is expanded: the wrong dimension values are 34 targets, not 35."""
    rows = []
    for target_set in config.target_sets:
        values = ", ".join(value.value for value in target_set.for_each.values)
        inner = {value.inner.name for value in target_set.for_each.values if value.inner}
        rows.append(
            [
                target_set.name,
                target_set.template.name,
                f"{target_set.for_each.dimension}: {values}",
                _or_dash(", ".join(sorted(inner)) or None),
            ]
        )
    return render_table(
        [Column("NAME", _NAME), Column("TEMPLATE", _NAME), Column("OUTER", _DSN), Column("INNER")],
        rows,
    )


def _group_rows(config: Config) -> list[str]:
    return render_table(
        [Column("NAME", _NAME), Column("MATCH", _DSN)],
        [[group.name, _pairs(group.match)] for group in config.groups],
    )


def _application_rows(config: Config) -> list[str]:
    return render_table(
        [
            Column("NAME", _NAME),
            Column("ACCOUNTS"),
            Column("TARGETS", _NAME),
            Column("SECRET", _REF),
        ],
        [
            [
                application.name or "(inline)",
                str(len(application.accounts)),
                _selector(application),
                _or_dash(application.secret_ref),
            ]
            for application in config.applications
        ],
    )


def _selector(application: Any) -> str:
    selector = application.targets
    if selector.is_everything:
        return "all"
    if selector.names:
        return ", ".join(selector.names)
    if selector.group is not None:
        return f"group {selector.group}"
    return _pairs(selector.match)


# -------------------------------------------------------------- resolved ---


def _resolved_sections(config: Config) -> list[tuple[str, list[str]]]:
    return [("targets", _estate_rows(config)), *_binding_sections(config)]


def _estate_rows(config: Config) -> list[str]:
    rows = [
        [
            expanded.name,
            expanded.target.dsn,
            _environment(expanded.target.environment),
            _or_dash(expanded.target.oracle.scope),
            _or_dash(expanded.target.vault),
            _source_cell(expanded),
        ]
        for expanded in config.expanded_targets
    ]
    lines = render_table(
        [
            Column("NAME", _NAME),
            Column("DSN", _DSN),
            Column("ENV"),
            Column("SCOPE"),
            Column("VAULT", _NAME),
            Column("SOURCE"),
        ],
        rows,
    )
    return [*lines, "", _estate_summary(config)]


def _estate_summary(config: Config) -> str:
    """How many targets, and where they came from.

    A kind that contributed nothing is left out rather than printed as a zero.
    `0 explicit` is not a fact about the estate, it is the absence of one, and
    an estate that is entirely generated -- which is most of them, and every
    filtered one -- should not have to say so. The breakdown itself stays even
    when one kind accounts for all of it: §4's point is that generation is
    invisible until it goes wrong, and `3 targets (3 generated)` is where it
    stops being invisible.
    """
    generated = [target for target in config.expanded_targets if target.target_set is not None]
    overridden = [target for target in generated if target.overridden]
    explicit = len(config.expanded_targets) - len(generated)
    parts = []
    if explicit:
        parts.append(f"{explicit} explicit")
    if generated:
        parts.append(f"{len(generated)} generated")
    if overridden:
        parts.append(f"{len(overridden)} overridden")

    summary = _count(len(config.expanded_targets), "target")
    if parts:
        summary += f" ({', '.join(parts)})"
    unmanaged = _unmanaged(config)
    if unmanaged:
        listed = ", ".join(unmanaged)
        summary += f"; {_count(len(unmanaged), 'target')} managed by nothing: {listed}"
    return summary


def _unmanaged(config: Config) -> list[str]:
    """Targets no application binds.

    Shown rather than warned about: §2's estate declares a CDB root for a use
    case that is not designed yet, and a declared-but-unmanaged target is the
    honest state until it is. Invisible is the one thing it must not be.
    """
    bound = _bound_targets(config)
    return [expanded.name for expanded in config.expanded_targets if expanded.name not in bound]


def _binding_sections(config: Config) -> list[tuple[str, list[str]]]:
    """Bindings grouped by application rather than carrying an application column.

    One estate is usually one or two applications, and a heading costs one line
    where a column costs width on every row -- width that a secret ref needs.
    """
    sections = []
    for application in config.applications:
        bindings = [b for b in config.bindings if b.application == application.name]
        if not bindings:
            continue
        label = application.name or "the inline application"
        targets = len({binding.target for binding in bindings})
        heading = (
            f"bindings: {label} "
            f"({_count(len(application.accounts), 'account')}, "
            f"{_count(targets, 'target')})"
        )
        sections.append((heading, _binding_rows(bindings)))
    return sections


def _binding_rows(bindings: Sequence[Binding]) -> list[str]:
    return render_table(
        [
            Column("TARGET", _NAME),
            Column("ACCOUNT", _NAME),
            Column("SECRET", _REF),
            Column("VAULT", _NAME),
            Column("POLICY"),
        ],
        [
            [
                binding.target,
                binding.account,
                _or_dash(str(binding.secret) if binding.secret is not None else None),
                _or_dash(binding.vault),
                _or_dash(binding.policy),
            ]
            for binding in bindings
        ],
    )


# ------------------------------------------------------------------ json ---


def _target_json(expanded: ExpandedTarget, *, bound: frozenset[str]) -> dict[str, Any]:
    target = expanded.target
    return {
        "name": target.name,
        "type": target.type,
        "dsn": target.dsn,
        "environment": target.environment,
        "vault": target.vault,
        "scope": target.oracle.scope,
        "container": target.oracle.container,
        "labels": as_dict(target.labels),
        "target_set": expanded.target_set,
        "overridden": expanded.overridden,
        "managed": target.name in bound,
    }


def _binding_json(binding: Binding) -> dict[str, Any]:
    return {
        "application": binding.application,
        "account": binding.account,
        "target": binding.target,
        # The ref in its canonical form (§7), which is what was written apart
        # from the case of a stage. Its parts are not broken out here:
        # `plan.units[].secret` is the structured form, and it carries the
        # resolved vault name that a written ref may leave off.
        "secret": str(binding.secret) if binding.secret is not None else None,
        "vault": binding.vault,
        "policy": binding.policy,
    }


# ----------------------------------------------------------------- shared ---


def _bound_targets(config: Config) -> frozenset[str]:
    """Every target some application binds an account in.

    One pass over the bindings, asked once and then looked up. §2's estate is 22
    targets and 126 bindings, and both views ask this question per target.
    """
    return frozenset(binding.target for binding in config.bindings)


def _or_dash(value: str | None) -> Cell | str:
    """A value, or a muted placeholder where there is none.

    The dash is what says "nothing here" -- the colour only stops a column of
    them from competing with the values beside it, which is why removing it
    loses nothing.
    """
    return value if value is not None else Cell("-", Role.MUTED)


def _environment(environment: str | None) -> Cell | str:
    """`prod` is the one value on this screen worth finding without reading."""
    if environment is None:
        return _or_dash(None)
    return Cell(environment, Role.PRODUCTION) if environment == PRODUCTION else environment


def _source_cell(expanded: ExpandedTarget) -> Cell | str:
    """An overridden target departs from what its set generated, which is the
    thing a reader is scanning this column for."""
    source = _source(expanded)
    return Cell(source, Role.NOTABLE) if expanded.overridden else source


def _source(expanded: ExpandedTarget) -> str:
    """§4's SOURCE column, in §4's words."""
    if expanded.target_set is None:
        return "targets"
    if expanded.overridden:
        return "override"
    return f"target_set {expanded.target_set}"


def _pairs(pairs: tuple[tuple[str, str], ...]) -> str:
    return ", ".join(f"{key}={value}" for key, value in pairs)


def _named(names: Any) -> list[str]:
    listed = sorted(names)
    return [", ".join(listed)] if listed else []


def _warnings(config: Config) -> list[str]:
    """§10's warnings, in full. This is the only place anybody will read them."""
    if not config.warnings:
        return []
    body = [f"  {line}" for warning in config.warnings for line in str(warning).splitlines()]
    return ["", paint(f"{_count(len(config.warnings), 'warning')}:", Role.NOTABLE), *body]


def _count(number: int, noun: str, plural: str | None = None) -> str:
    if number == 1:
        return f"1 {noun}"
    return f"{number} {plural if plural is not None else noun + 's'}"

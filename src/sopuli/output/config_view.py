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
``docs/schemas/sopuli-run-1.16.schema.json``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Any

from sopuli.config import Binding, Config, ExpandedTarget, as_dict
from sopuli.config.locking import LOCK_REQUIRED
from sopuli.config.model import Pairs, Safety, Vault
from sopuli.config.selection import matches
from sopuli.config.sharing import SharedSecret, shared_secrets
from sopuli.output.document import Option
from sopuli.output.explain_view import section as explain_section
from sopuli.output.palette import Role, paint
from sopuli.output.table import Cell, Column, render_table
from sopuli.settings import Contribution, Layer, Resolved, render_value, resolve_all
from sopuli.settings.sources import safety_block, target_safety

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

    **The stores' own settings join that table when it is asked for** (#428), as
    ``vaults.<name>.<key>`` rows beneath the run's. They are resolved inside the
    file rather than at the boundary, so they never arrive in ``settings`` -- but
    they are settings of the same chain, merged by the same resolver, and P3's own
    worked example of this view is a vault key. An empty ``settings`` is what says
    ``--explain`` was not asked for, so there is no second argument for it.
    """
    lines = [f"config: {paths[0]}"]
    lines.extend(f"        {path} (layered)" for path in paths[1:])
    if match:
        lines.append(f"select: {_pairs(match)}")

    explained = {**settings, **_vault_settings(config)} if settings else {}

    if resolved and match and not config.expanded_targets:
        # Not an error: a selector that matches nothing is a legitimate question
        # with the answer "none of them" (exit 0). But an empty table under a
        # `targets` heading looks like an estate that expanded to nothing, which
        # is a different and much more alarming thing.
        lines.extend(["", f"no targets carry {_pairs(match)}"])
        # `--explain` still answers its own question: a selector that matched
        # nothing says nothing about where `output` came from.
        lines.extend(explain_section(explained))
        lines.extend(_warnings(config))
        return "\n".join(lines)

    sections = _resolved_sections(config) if resolved else _declared_sections(config)
    for heading, body in sections:
        if not body:
            continue
        lines.extend(["", paint(heading, Role.HEADING)])
        lines.extend(body)

    lines.extend(explain_section(explained))
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


def render_validation(
    paths: Sequence[Path], config: Config, extra_warnings: Sequence[str] = ()
) -> str:
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

    ``extra_warnings`` are findings the *config layer* could not make, because
    making them is not pure: a configured-but-uninstalled backend (ADR-006, E4)
    is a fact about this machine rather than about the file, and
    ``04-testing.md`` §4 keeps the config layer free of anything that has to look
    outside the document. They arrive from the boundary already worded and are
    counted and shown here exactly like the file's own, because to the person
    reading the output the distinction is ours and not theirs.
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
                _count(len(config.warnings) + len(extra_warnings), "warning"),
            )
        )
    )
    lines.extend(_warnings(config, extra_warnings))
    return "\n".join(lines)


def build_section(
    paths: Sequence[Path], config: Config, document: dict[str, Any], *, resolved: bool
) -> dict[str, Any]:
    """The ``config`` section of the run document.

    ``declared`` is the merged document itself rather than a reshaping of it.
    The question it answers is what the YAML says after layering, and any
    normalisation on the way out would be a second answer to that question --
    one that could drift from the first.

    ``vaults`` is in **both** shapes, and it is the one thing here that neither
    of them carried (#428). ``declared`` is the address the *file wrote*, and
    ``--resolved`` dropped stores entirely, so no mode of this command told a
    JSON consumer which vault a run would actually talk to -- true since the
    layers were built rather than since ``--vault-addr`` was. Which forces the
    ordering: you cannot report where ``addr`` came from before reporting what
    ``addr`` is, so the value is the substantive half and the provenance rides
    along with it.

    Always present, empty array included, for the reason ``doctor``'s own
    ``vaults[]`` is: every estate that does anything has stores, so ``[]`` is a
    real answer here rather than the negative finding an absent
    ``shared_secrets`` would be.

    It carries the provenance in both output modes and whether or not
    ``--explain`` was passed, unlike the text table. There is nothing to filter:
    no ``vaults.*`` setting has a built-in default, so every key reported is one
    some layer actually wrote -- which is the filter ``invocation.options``
    applies and ``--explain`` lifts.
    """
    section: dict[str, Any] = {
        "sources": [str(path) for path in paths],
        "resolved": resolved,
        "vaults": [_vault_json(vault) for vault in config.vaults],
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
    # Omitted rather than emitted empty, the same way `diagnostics` is: a config
    # where nothing is shared has nothing to say, and an empty array reads like a
    # finding that came back negative.
    shared = shared_secrets(config.bindings)
    if shared:
        section["shared_secrets"] = [entry.as_json() for entry in shared]
    return section


# ------------------------------------------------------------- as loaded ---


def _declared_sections(config: Config) -> list[tuple[str, list[str]]]:
    """One block per section of the file, in the order the file writes them --
    and then one that is not a section of the file at all.

    ``safety`` is derived: a ``safety:`` block may be written under six different
    things, so the question "what does this file guard, and where is it written"
    has no home among the sections. It goes last because it is a summary over
    them rather than one of them.
    """
    return [
        ("vaults", _vault_rows(config)),
        ("targets", _declared_target_rows(config)),
        ("target_sets", _target_set_rows(config)),
        ("groups", _group_rows(config)),
        ("policies", _named(policy.name for policy in config.policies)),
        ("profiles", _named(profile.name for profile in config.profiles)),
        ("applications", _application_rows(config)),
        ("personal_accounts", _personal_account_rows(config)),
        ("safety", _safety_rows(config)),
    ]


def _safety_rows(config: Config) -> list[str]:
    """Every ``safety:`` key the file writes, by the key that writes it (#426).

    **The section exists because a block outside ``defaults`` was invisible.**
    ``config show --explain`` reports the *run's* settings, and ``config show``
    applies no selector and builds no plan -- so its ``safety.readonly`` is
    correctly ``false`` even for a file whose target sets it, and §9 defines
    ``[built-in default]`` as precisely *nothing else spoke*. The row was never
    the defect; the defect was that nothing else in the command said a block
    existed. This is what says it.

    **Every block, not only the object layer.** ``defaults`` and a profile are
    already visible in ``--explain``'s table, and leaving them out here would make
    this section its own half-truth -- a map of the file's guards with two of the
    six kinds of place missing. The two views answer different questions: that one
    is *what did this run resolve to*, this one is *what does this file say, and
    where*.

    **One row per key rather than per block**, because the key path is the thing
    to edit and a block writes up to three of them. Deduplicated by that path,
    which is what collapses a target set's template to one row instead of one per
    generated target -- the template is a single line in the file however many
    targets it makes.

    **Generated targets are addressed through**
    :func:`~sopuli.config.expansion.declared_at`, so a block an ``overrides:``
    entry wrote is reported against the override. Reporting it against the
    template would point at the one place the value is spelled the way the reader
    expected.
    """
    written: dict[str, str] = {}
    for _, value, key, _ in _safety_keys(config):
        if value is not None and key not in written:
            written[key] = render_value(value)
    defeated = _defeated_keys(config)
    return render_table(
        # **No width cap on the key**, which is the one column here that must not
        # be truncated: two `target_sets.appdb.overrides.…` paths differ in their
        # tail, so a cap turns the answer into two identical rows. The same reason
        # `explain_view` lays its own table out by hand rather than through this
        # module -- a truncated location is useless in exactly the moment the view
        # exists for.
        [Column("KEY"), Column("VALUE", _DSN), Column("NOTE")],
        [
            [
                key,
                written[key],
                Cell("defeated by the ratchet", Role.NOTABLE) if key in defeated else "",
            ]
            for key in sorted(written)
        ],
    )


def _safety_keys(config: Config) -> list[tuple[str, object, str, Layer]]:
    """Every ``safety:`` key the file writes, with the path that writes it.

    In the order a reader would look for them: the two that govern the whole run
    first, then the objects. **Every declared profile**, not only the active one --
    the section says what the file contains, and a profile nobody selected is
    still written down.

    **Targets go through** :func:`~sopuli.settings.sources.target_safety` rather
    than through :func:`~sopuli.config.expansion.declared_at` directly, and that
    is the whole reason this is not four lines. A patch merges into a target set's
    template key by key, so the flattened block holds the template's answer for
    every key the ``overrides:`` entry did not write -- and addressing all of them
    at the override's path reports it as the source of values it never mentions.
    That function already decides which key belongs to which line (#424, #425),
    and a second rule here would be a second answer to one question.
    """
    found: list[tuple[str, object, str, Layer]] = []
    if config.defaults.safety is not None:
        found.extend(_keys(config.defaults.safety, at="defaults.safety"))
    for profile in config.profiles:
        if profile.safety is not None:
            found.extend(_keys(profile.safety, at=f"profiles.{profile.name}.safety"))
    for expanded in config.expanded_targets:
        found.extend(target_safety(expanded))
    for group in config.groups:
        if group.safety is not None:
            found.extend(_keys(group.safety, at=f"groups.{group.name}.safety"))
    return found


def _keys(block: Safety, *, at: str) -> list[tuple[str, object, str, Layer]]:
    """One block's keys. The contribution builder, reused so that a fourth key
    added to a ``safety:`` block appears here without a second edit.

    Its ``layer`` is irrelevant to a listing and is discarded by the caller.
    """
    return safety_block(block, at=at, layer=Layer.OBJECT)


def _defeated_keys(config: Config) -> frozenset[str]:
    """Keys a ``safety:`` block writes that no run will ever read (#426).

    A ratchet has losers wherever two layers disagree, and this section lists
    every layer, so every pairing can produce one: an ``overrides:`` entry asking
    for less than its template, a group asking for less than a target it matches,
    an active profile asking for less than ``defaults``. The first version
    resolved only the first of those and left the other two reading as effective
    values (found in review) -- which is this section's own failure, one layer
    along.

    **Resolved per target, against the layers enforcement uses.**
    :func:`sopuli.safety.for_estate` merges ``defaults`` and the active profile
    with a target's own block and the blocks of the groups matching it; the same
    contributions go through the same resolver here. Only the **active** profile,
    because a profile nobody selected patches nothing -- a declared one still gets
    a row, since the section says what the file contains, but it cannot lose a
    ratchet it never entered.

    **Defeated everywhere, not merely somewhere**, and this is the case the first
    run of it got wrong in the other direction. A template writes one line and
    generates many targets, so a key can lose on the one an override patched and
    hold on every other -- marking it because *one* target lowered it would say a
    line has no effect while it governs the rest of the set. So a row is marked
    only where nothing it applies to ever reads it.
    """
    run = _run_contributions(config)
    won: set[str] = set()
    lost: set[str] = set()
    per_target = [_estate_contributions(config, expanded) for expanded in config.expanded_targets]
    # An estate with no targets still has a `defaults`/profile pair to resolve,
    # and a defeat between those two is not about any target.
    for extra in per_target or [{}]:
        contributions = {
            name: [*run.get(name, ()), *extra.get(name, ())] for name in {*run, *extra}
        }
        for answer in resolve_all(contributions).values():
            won.add(answer.location)
            lost.update(one.location for one in answer.relaxations)
    return frozenset(lost - won)


def _run_contributions(config: Config) -> dict[str, list[Contribution]]:
    """``defaults`` and the active profile -- the layers that govern every target."""
    found: list[tuple[str, object, str, Layer]] = []
    if config.defaults.safety is not None:
        found.extend(
            safety_block(config.defaults.safety, at="defaults.safety", layer=Layer.DEFAULTS)
        )
    profile = config.active_profile
    if profile is not None and profile.safety is not None:
        found.extend(
            safety_block(profile.safety, at=f"profiles.{profile.name}.safety", layer=Layer.PROFILE)
        )
    return _contributions(found)


def _estate_contributions(
    config: Config, expanded: ExpandedTarget
) -> dict[str, list[Contribution]]:
    """One target's own block, and the blocks of the groups that match it."""
    found = list(target_safety(expanded))
    for group in config.groups:
        if group.safety is not None and matches(expanded.target, group.match):
            found.extend(
                safety_block(group.safety, at=f"groups.{group.name}.safety", layer=Layer.OBJECT)
            )
    return _contributions(found)


def _contributions(
    found: Sequence[tuple[str, object, str, Layer]],
) -> dict[str, list[Contribution]]:
    """Rows to contributions, dropping the keys nobody wrote."""
    built: dict[str, list[Contribution]] = {}
    for name, value, detail, layer in found:
        if value is None:
            continue
        built.setdefault(name, []).append(Contribution(layer=layer, value=value, detail=detail))
    return built


def _vault_rows(config: Config) -> list[str]:
    return render_table(
        [Column("NAME", _NAME), Column("TYPE"), Column("ADDRESS", _DSN), Column("NOTE")],
        [
            [
                vault.name,
                vault.type,
                _or_dash(vault.addr),
                _vault_note(vault),
            ]
            for vault in config.vaults
        ],
    )


def _vault_settings(config: Config) -> dict[str, Resolved]:
    """Every store's merged keys, spelled the way the settings table names them.

    ``vaults.vault-dev.addr``, the concrete store where the registry writes
    ``vaults.*.addr`` -- which is the spelling P3's own example of this view uses
    and the one an operator would grep their file for. The ``*`` form is a
    registry key and stands for every store at once (``sopuli/settings/registry.py``);
    it is not an address anybody can act on.

    The :class:`~sopuli.settings.Resolved` objects come straight off the store,
    where :mod:`sopuli.config.vault_layers` put them. Nothing is re-resolved here:
    a second merge in a renderer is the shape that lets a view and an enforcement
    disagree.

    **Every source of ``addr`` is distinguishable, the four outside the file
    included** (#428): ``--vault-addr`` renders ``[cli --vault-addr]``,
    ``SOPULI_VAULT__VAULT_DEV__ADDR`` and ``SOPULI_VAULT_ADDR`` render
    ``[env <VARIABLE>]``, ``VAULT_ADDR`` renders ``[env_thirdparty VAULT_ADDR]``,
    and a profile, the declaration and ``defaults.vaults:`` each render their own
    key path -- seven in all, across P3's six layers. Before this they were one
    indistinguishable ``layered: addr`` in the store's ``NOTE`` column, which said
    *that* a layer wrote the key and never which -- and "why is this run talking to
    that vault" is the first question when a rotation lands somewhere unexpected.
    """
    return {
        f"vaults.{vault.name}.{key}": answer
        for vault in config.vaults
        for key, answer in vault.settings
    }


def _vault_json(vault: Vault) -> dict[str, Any]:
    """One store, as ``config.vaults[]`` carries it.

    ``settings`` reuses :class:`~sopuli.output.document.Option` -- the same
    ``value`` / ``source`` / ``source_detail`` triple ``invocation.options``
    carries -- because it is the same question about the same resolver, and a
    second grammar for it would be two shapes a consumer has to learn for one
    fact. It is **not** put *in* ``invocation.options``, which was the rejected
    option (b) of #428: that section is what changed the behaviour of the *run*,
    and ``RESOLVED_SETTINGS`` excludes a store's keys on the documented grounds
    that they describe a store rather than a run.

    ``name`` and ``type`` are the store's identity and neither can be layered --
    a store that is HashiCorp from a laptop and OCI from CI is two stores (C13).
    ``non_production`` and ``locking`` are deliberately absent: both are
    declaration-only guardrails, ``config.declared`` carries them as written, and
    ``doctor`` reports the second as ``lock.mode``. Adding either later is
    additive.
    """
    return {
        "name": vault.name,
        "type": vault.type,
        "settings": {
            key: Option(
                value=answer.value,
                source=str(answer.layer),
                source_detail=answer.detail,
            ).to_dict()
            for key, answer in vault.settings
        },
    }


def _vault_note(vault: Vault) -> Cell | str:
    """What is worth saying about a store beyond its type and address.

    The first two notes are the same kind of thing -- a store that is *less* than
    the default assumption -- so they share the column and the ``notable`` role
    rather than each getting one. ``advisory-only`` is here because a store that
    cannot hold a real lock is exactly what somebody reading this table needs to
    notice, and the run document's ``lock.mode: none`` says the same thing to the
    other reader (#83).

    The third is a different kind of remark and shares the column anyway: this
    table renders **effective** values (C13, #136), so a row can show an address
    the ``vaults:`` entry never wrote. Without saying so, the view answers "did my
    YAML say what I think it says" with a value from a different part of the file,
    which is the one question this view exists for. Which layer supplied it is
    ``--explain``'s answer and not this column's -- what belongs here is that it
    was not written on the entry.

    **``--explain`` now answers it**, which until #428 it did not: this docstring
    deferred to a view that had never been built, so three different layers
    writing ``addr`` produced one ``layered: addr`` here and nothing anywhere
    else. The deferral was the right split and is unchanged; what
    changed is that the other half exists. A ``SOURCE`` column here was the
    alternative and loses to the reason ``explain_view`` lays its table out by
    hand: a truncated ``SOPULI_VAULT__...`` is useless in exactly the moment it is
    wanted.
    """
    notes = []
    if vault.non_production:
        notes.append("non-production")
    if vault.locking != LOCK_REQUIRED:
        notes.append(vault.locking)
    if vault.patched:
        notes.append(f"layered: {', '.join(vault.patched)}")
    return Cell(", ".join(notes), Role.NOTABLE) if notes else ""


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


def _personal_account_rows(config: Config) -> list[str]:
    """UC-2's section (H1, #449). One row per rule, not per account.

    ``ACCOUNTS`` is a count for an enumerated entry and ``-`` for a predicate,
    and the dash is the honest answer rather than a gap: how many accounts carry
    a profile is a fact about a database, and this command describes the file.
    `account list` is the verb that asks.
    """
    return render_table(
        [
            Column("DECLARED BY", _NAME),
            Column("ACCOUNTS"),
            Column("TARGETS", _NAME),
            Column("POLICY", _NAME),
        ],
        [
            [
                "names" if not entry.is_predicate else entry.label,
                "-" if entry.is_predicate else str(len(entry.accounts)),
                _selector(entry),
                _or_dash(entry.policy),
            ]
            for entry in config.personal_accounts
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
    return [
        ("targets", _estate_rows(config)),
        *_binding_sections(config),
        *_shared_secret_sections(config),
    ]


def _shared_secret_sections(config: Config) -> list[tuple[str, list[str]]]:
    """The binding rows seen the other way up: grouped by the document they write.

    Last, because it is a reading of what is above it rather than new material --
    and because the question it answers ("what else does this touch?") is one
    somebody asks after seeing the bindings, not before.

    The heading takes :attr:`~sopuli.output.palette.Role.NOTABLE`, which is the
    role for a fact worth catching the eye without being an error. Sharing is
    legal and often intended (§7); what it must not be is invisible. The word
    "shared" is on the line either way, so the colour reinforces and never
    carries the meaning on its own.
    """
    shared = shared_secrets(config.bindings)
    if not shared:
        return []
    heading = paint(f"shared secrets ({_count(len(shared), 'document')}):", Role.NOTABLE)
    return [(heading, _shared_secret_rows(shared))]


def _shared_secret_rows(shared: Sequence[SharedSecret]) -> list[str]:
    return render_table(
        [
            Column("SECRET", _REF),
            Column("VAULT", _NAME),
            Column("TARGETS"),
            Column("ACCOUNTS"),
        ],
        [
            [
                entry.path,
                _or_dash(entry.vault),
                ", ".join(entry.targets),
                ", ".join(entry.accounts),
            ]
            for entry in shared
        ],
    )


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
        "safety": _target_safety_json(expanded),
        "target_set": expanded.target_set,
        "overridden": expanded.overridden,
        "managed": target.name in bound,
    }


def _target_safety_json(expanded: ExpandedTarget) -> dict[str, Any] | None:
    """This target's ``safety:`` block as the run will read it (#426, schema 1.22).

    ``None`` where nothing constrains this target, which is most of them. That
    covers a target with no block **and** one written as an empty ``safety: {}``,
    and collapsing the two is deliberate (found in review): an empty block guards
    exactly as much as no block, so a consumer branching on the difference would
    be branching on nothing. Presence is not lost -- ``config.declared`` carries
    the file as written, which is where a question about what somebody *typed*
    belongs.

    **Resolved rather than flattened**, which is the whole reason this is not
    ``as_dict(target.safety)``. A patch merges into a template key by key, so
    :attr:`~sopuli.config.model.Target.safety` on a generated target can hold an
    override's ``readonly: false`` over a template's ``true`` -- the target layer's
    literal statement, and not what the run does, because the ratchet takes the
    safest of the two (#425). Reporting the flattened value here would put the
    relaxed answer in the machine-readable contract while the tool refused the
    run, which is the shape of lie this whole section exists to remove. So the
    same contributions go through the same resolver, and it is correct in both
    directions: an override may always refuse *more*.

    **Only this target's block.** ``defaults``, a profile and a group can each
    refuse a mutation too, and none of them is a property of a target -- folding
    them in would make one object's answer depend on four, and hide which. They
    are in ``config.declared`` as written, and in the text view's ``safety``
    section by the key that writes them.
    """
    contributions: dict[str, list[Contribution]] = {}
    for name, value, detail, layer in target_safety(expanded):
        if value is None:
            continue
        contributions.setdefault(name, []).append(
            Contribution(layer=layer, value=value, detail=detail)
        )
    if not contributions:
        return None
    resolved = resolve_all(contributions)
    return {
        name.split(".", 1)[1]: list(answer.value)
        if isinstance(answer.value, tuple)
        else answer.value
        for name, answer in resolved.items()
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


def _warnings(config: Config, extra: Sequence[str] = ()) -> list[str]:
    """§10's warnings, in full. This is the only place anybody will read them."""
    messages = [str(warning) for warning in config.warnings]
    messages.extend(extra)
    if not messages:
        return []
    body = [f"  {line}" for message in messages for line in message.splitlines()]
    return ["", paint(f"{_count(len(messages), 'warning')}:", Role.NOTABLE), *body]


def _count(number: int, noun: str, plural: str | None = None) -> str:
    if number == 1:
        return f"1 {noun}"
    return f"{number} {plural if plural is not None else noun + 's'}"

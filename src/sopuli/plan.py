"""What a run intends to do, decided before it does any of it.

The `plan` section of the run document, and the only section every `creds` verb
needs before it can start. `03-json-output.md` is explicit that this is **not a
dry-run-only structure**: a real run emits the identical shape, so a diff between
what the run said it would do and what `results[]` says it did is mechanical
rather than a reading exercise.

That requirement is what fixes this module's inputs. A plan is a function of the
config and the selection and **nothing else** -- no store read, no connection, no
clock. Two runs of one command over one file must produce the same plan, or the
diff above compares a plan against results it was never the plan for. So this is
tier 0 in the sense `04-testing.md` §4 means it: pure, and pure by requirement
rather than by convenience.

Three things here are decisions rather than transcription:

**`intent` is supplied by the verb, not inferred here.** A unit's intent is the
schema's `action_kind` vocabulary -- `verify`, `password_set`, `vault_promote` --
and which of them a run means is the verb's whole identity. `creds check` intends
`verify` on every unit; `creds rotate` intends four things in an order. Inferring
it from anything available here would mean guessing at the caller, and a plan that
guessed would be a plan the caller could not be held to.

**The unit's `secret` is the structured form, and it is the resolved one.**
`config.bindings[].secret` is the canonical string a §7 ref renders back to, which
is right there: it lines up by eye with the file. Here the consumer is a machine
about to address a document, so it gets parts -- and it gets
:attr:`~sopuli.config.model.Binding.vault`, the *resolved* store name, which a
written ref is allowed to leave off. `config_view._binding_json` already points
here for exactly this.

**Blast radius counts distinct things, and reads environments off the estate.**
:class:`~sopuli.config.model.Binding` carries a target *name*, not its
environment, so the estate is the second input rather than a convenience: nothing
else can answer "which environments does this run reach", and that is the question
`confirm_environments` is asked against. Counting distinct targets rather than
units matters for the same reason -- six accounts in one PDB is one target's worth
of blast radius, and a count of six would refuse a run `max_targets: 1` was never
aimed at.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sopuli.config.model import Binding, Config
from sopuli.config.sharing import SharedSecret, shared_secrets

__all__ = ["ACTION_KINDS", "BlastRadius", "Plan", "PlanUnit", "build", "build_for_accounts"]


#: The run schema's ``action_kind`` enum, as a literal.
#:
#: Copied rather than derived, for :data:`~sopuli.settings.registry.SAFETY_SETTINGS`'s
#: reason: a reviewer should be able to read the closed set without loading a JSON
#: file, and :func:`build` refuses an intent outside it. Reading the schema at
#: runtime would also make the config layer depend on a document that ships beside
#: the docs, which is a dependency in the wrong direction.
ACTION_KINDS = frozenset(
    (
        "none",
        "generate",
        "vault_write_pending",
        "vault_promote",
        "vault_rollback",
        "password_set",
        "rollover_start",
        "rollover_finish",
        "account_unlock",
        "account_lock",
        "password_expire",
        "attribute_set",
        "verify",
    )
)


@dataclass(frozen=True)
class PlanUnit:
    """One account, in one target, and what this run means to do to it.

    The same grain as :class:`~sopuli.config.model.Binding` -- one row per account
    per target -- because that is the grain `results[]` reports at, and the two
    arrays are meant to be lined up.
    """

    account: str
    target: str
    #: What the verb intends, in the schema's ``action_kind`` vocabulary. A
    #: sequence rather than one value: `rotate` is four actions on one unit, and
    #: an array is what lets the plan say so without inventing a compound verb.
    intent: tuple[str, ...]
    #: The document this unit's credential lives in, or ``None`` where the config
    #: binds no ref. §3 makes `secret` optional and this layer does not invent one.
    secret: dict[str, Any] | None = None

    def as_json(self) -> dict[str, Any]:
        """The run schema's ``plan.units[]`` item.

        ``secret`` is omitted rather than nulled when there is none: the schema
        types it as a `secret_ref` object, so a null would fail validation, and
        `additionalProperties: false` means nothing else may be added here.
        """
        item: dict[str, Any] = {
            "account": self.account,
            "target": self.target,
            "intent": list(self.intent),
        }
        if self.secret is not None:
            item["secret"] = dict(self.secret)
        return item


@dataclass(frozen=True)
class BlastRadius:
    """How much of the estate this run reaches.

    Distinct targets and distinct accounts, not a count of units. The two differ
    exactly where sharing happens, which is the case every guardrail here exists
    for: one document backing eleven PDBs is eleven targets and one account, and
    six accounts in one PDB is one target and six.
    """

    targets: int
    accounts: int
    #: Every environment the selected targets sit in, in estate order and
    #: de-duplicated. A target that declares none contributes nothing rather than
    #: an empty string -- `environment:` is optional, and `confirm_environments`
    #: matching `""` would be a rule nobody wrote.
    environments: tuple[str, ...] = ()

    def as_json(self) -> dict[str, Any]:
        return {
            "targets": self.targets,
            "accounts": self.accounts,
            "environments": list(self.environments),
        }


@dataclass(frozen=True)
class Plan:
    """Everything a run decided before touching anything."""

    units: tuple[PlanUnit, ...]
    blast_radius: BlastRadius
    #: The documents this run's work lands in that more than one binding shares.
    #: Narrowed to the run, which is the whole distinction from
    #: `config.shared_secrets`: that one answers "what does my file share", this
    #: one answers "what does *this run* touch that something else reads".
    shared: tuple[SharedSecret, ...] = ()

    def as_json(self, *, confirmation_required: bool) -> dict[str, Any]:
        """The run document's ``plan`` section.

        ``shared_secrets`` is omitted when nothing is shared rather than emitted
        empty, the way `diagnostics` and `config.shared_secrets` are: an empty
        array reads like a finding that came back negative, and this one would
        appear in every clean document consumers diff.

        ``confirmation_required`` is whether a real run of this plan needs an
        explicit yes before it changes anything: a prompt, or `--confirm` given in
        advance. The verb answers it, because the gates are per verb: `creds
        rotate` asks whenever it has something to rotate, and `creds check` never
        asks. The plan cannot see
        them, so the keyword has no default, and no call site can emit a guess. It
        does not say how the gate was answered: a `--dry-run` and a run given
        `--confirm` report the same value as the run that prompts, because `plan`
        is the same on all three.
        """
        section: dict[str, Any] = {
            "units": [unit.as_json() for unit in self.units],
            "blast_radius": self.blast_radius.as_json(),
            "confirmation_required": confirmation_required,
        }
        if self.shared:
            section["shared_secrets"] = [entry.as_json() for entry in self.shared]
        return section


def build(config: Config, *, intent: Sequence[str]) -> Plan:
    """The plan for running ``intent`` over everything ``config`` still declares.

    ``config`` is the **already-selected** estate --
    :func:`~sopuli.config.selection.filter_estate` has run, and what is left is
    what the run acts on. Selection is not repeated here, and that is invariant 5
    holding structurally: a plan is built from bindings the config declares, so
    there is no argument this function could take that would let it reach an
    account the file does not name.

    ``intent`` applies to every unit, because a verb intends one thing and the
    units are the estate it intends it over. A run that meant different things for
    different accounts would be two runs, and `results[]` would have no way to say
    which was which.
    """
    kinds = _checked_intent(intent)
    environments = _environments(config)
    units = tuple(
        PlanUnit(
            account=binding.account,
            target=binding.target,
            intent=kinds,
            secret=_secret_json(binding),
        )
        for binding in config.bindings
    )
    return Plan(
        units=units,
        blast_radius=_blast_radius(config.bindings, environments),
        shared=shared_secrets(config.bindings),
    )


def build_for_accounts(
    config: Config, pairs: Sequence[tuple[str, str]], *, intent: Sequence[str]
) -> Plan:
    """The plan for running ``intent`` over ``pairs`` of (account, target).

    :func:`build` reads its units from ``config.bindings``, which is right for
    every verb whose unit of work is *an account mastered by a secret*. UC-2's
    accounts are mastered by nothing (H1), so they produce no binding and that
    function would plan an empty run over them.

    **The pairs are the caller's, and invariant 5 is therefore the caller's too.**
    That is the real difference from :func:`build`, where the config *is* the
    argument and no selector can reach an account the file does not name. Here
    the caller has already answered "is this account declared" -- with
    :func:`sopuli.personal.declared_on`, which needs a database for a predicate --
    and this function trusts the answer. It is the one place in the plan layer
    where the whitelist is upstream rather than structural, so a caller that
    skipped that step would plan work on an undeclared account.

    ``shared`` is empty rather than computed: a shared secret is two bindings
    landing in one document, and these units address no document at all.
    """
    kinds = _checked_intent(intent)
    environments = _environments(config)
    units = tuple(
        PlanUnit(account=account, target=target, intent=kinds) for account, target in pairs
    )
    return Plan(units=units, blast_radius=_radius(pairs, environments))


def _checked_intent(intent: Sequence[str]) -> tuple[str, ...]:
    """The intent as a tuple, refusing anything outside the schema's enum.

    A `ValueError` rather than a :class:`~sopuli.config.errors.ConfigError`: an
    intent comes from a verb in this codebase and never from a file or a command
    line, so a bad one is a programming error and not something an operator can
    fix. Refused here rather than at validation time because the alternative is a
    document that fails schema validation in CI with no clue which verb wrote it.
    """
    kinds = tuple(intent)
    if not kinds:
        raise ValueError("a plan unit needs at least one intent")
    unknown = sorted(set(kinds) - ACTION_KINDS)
    if unknown:
        raise ValueError(
            f"not an action_kind: {', '.join(unknown)} -- the enum is in sopuli.plan.ACTION_KINDS"
        )
    return kinds


def _secret_json(binding: Binding) -> dict[str, Any] | None:
    """A binding's ref as the schema's ``secret_ref``, or ``None``.

    ``vault`` comes from the binding rather than from the ref, because the ref is
    what was *written* and the binding carries what it *resolved to* -- §7 lets a
    ref leave the store off and inherit it. The plan addresses a document, so it
    needs the resolved one.

    **A ref whose store nothing has named yet emits no ``secret`` at all**, which
    is why this returns ``None`` for two different reasons. ``secret_ref`` requires
    ``vault`` as a *string*, so there is no shape for half an address, and the
    schema makes ``units[].secret`` optional precisely so a unit can say it does
    not have one. C15 is why the case exists: §3's chain deliberately leaves
    out a profile's ``vault:`` and ``SOPULI_VAULT``, because which profile is
    active is a property of a run and bindings are built once at load, so a file
    that gets its store from either has ``binding.vault is None`` here and is
    perfectly valid. ``config show --resolved`` already renders ``-`` for such a
    binding rather than a verdict, and this matches it.

    **This is not the place that refuses one**, and C15 is what says so. It decided
    "mostly plan time": the null is a real temporary state, `config show --resolved`
    shows it as ``-``, and *the command that actually needs a store* is what fails
    -- once a run's profile is known and the answer is exact. A refusal written into
    this function would fire before either of those is true and would reject every
    file whose store comes from ``SOPULI_VAULT``, which is the arrangement C15
    explicitly preserved. Invariant 4 puts it in the command, which is also where
    ``_check_has_somewhere_to_resolve_from``'s docstring says it belongs. What a
    *file* can be refused for at load -- ``vaults:`` declaring nothing at all, so no
    run could ever complete the binding -- it already is. C15's other half -- a run
    completing the store from a profile or ``SOPULI_VAULT`` -- is
    :mod:`sopuli.config.binding_stores` (decision #250). **A command that needs a
    store is required to run it before building a plan**, and to call
    ``refuse_unresolved`` after; this function does not, and cannot, check that it
    happened. A unit that still has no store is therefore either a binding with no
    ref or a caller that skipped the step -- and the second is why the refusal
    belongs to the caller rather than here, where it would fire before a run's
    profile is even known.

    ``updated_at`` is absent by construction: it describes what the store holds,
    and reading the store here would make a plan a function of something other
    than the config -- see the module note. ``version`` appears only when the
    **ref itself pins one** (``…@version=7``), which is config and therefore
    deterministic; the version a run *observes* is `results[]`'s to report once
    something has actually looked.
    """
    ref = binding.secret
    if ref is None or binding.vault is None:
        return None
    item: dict[str, Any] = {"vault": binding.vault, "path": ref.path}
    if ref.field is not None:
        item["field"] = ref.field
    if ref.pointer is not None:
        item["pointer"] = ref.pointer
    if ref.stage is not None:
        item["stage"] = ref.stage
    if ref.version is not None:
        item["version"] = ref.version
    return item


def _environments(config: Config) -> Mapping[str, str | None]:
    """Target name to the environment it declares, for the whole selected estate.

    One pass, then a lookup per binding. §2's estate is 22 targets and 126
    bindings, and a scan per binding would be the same question asked 126 times.
    """
    return {expanded.name: expanded.target.environment for expanded in config.expanded_targets}


def _blast_radius(
    bindings: Iterable[Binding], environments: Mapping[str, str | None]
) -> BlastRadius:
    """Distinct targets, distinct accounts, and the environments they sit in.

    ``dict`` rather than ``set`` for the environments, so estate order survives:
    the operator reads this beside the plan table, and a set's ordering would make
    the same three environments look like a different three between runs.

    A binding naming a target the estate does not describe contributes no
    environment rather than raising. That combination cannot arise from a loaded
    config -- bindings are built *from* the estate -- and a guard against it here
    would be one this function cannot test honestly.
    """
    return _radius([(binding.account, binding.target) for binding in bindings], environments)


def _radius(
    pairs: Iterable[tuple[str, str]], environments: Mapping[str, str | None]
) -> BlastRadius:
    """The same count over bare (account, target) pairs.

    Split out so :func:`build_for_accounts` shares it rather than reimplementing
    it: a blast radius counted two ways is the number `max_targets` and
    `confirm_environments` read, and two implementations of it would eventually
    disagree about how big a run is.
    """
    targets: dict[str, None] = {}
    accounts: dict[str, None] = {}
    seen: dict[str, None] = {}
    for account, target in pairs:
        targets[target] = None
        accounts[account] = None
        environment = environments.get(target)
        if environment is not None:
            seen[environment] = None
    return BlastRadius(targets=len(targets), accounts=len(accounts), environments=tuple(seen))

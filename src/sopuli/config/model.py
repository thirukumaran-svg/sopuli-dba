"""The validated shape of a config file.

Everything here is frozen. A config is read once and then consulted from a lot
of places; a mutable one invites a command to "just adjust" a target list or a
secret ref in passing, and invariant 5 -- the config is the whitelist, selectors
filter it and cannot extend it -- is much easier to hold if the whitelist cannot
be edited after it is read.

Mapping-shaped fields are stored as sorted tuples of pairs rather than dicts, for
two reasons: a frozen dataclass with a dict field has an ``__hash__`` that raises,
which is a landmine to leave lying around, and sorted pairs make error messages
and plan output deterministic instead of dependent on YAML key order.

:class:`Config` deliberately carries only what this change validates. The estate
sections -- ``vaults``, ``targets``, ``target_sets``, ``groups``, ``policies``,
``defaults``, ``profiles``, ``runtime`` -- are recognised at the top level but
not yet modelled, and arrive as fields here rather than as a reshaping of it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: Label matches and vendor options, kept as sorted pairs. See the module note.
Pairs = tuple[tuple[str, str], ...]


def as_dict(pairs: Pairs) -> dict[str, str]:
    """The mapping form, for callers that want to look a key up."""
    return dict(pairs)


@dataclass(frozen=True)
class OracleOptions:
    """``oracle:`` on an application entry (§3).

    Only ``container_clause`` is documented, so only it is modelled -- an
    untyped bag would accept ``container_clase: ALL`` and silently do nothing,
    which is the failure §9 exists to prevent.
    """

    container_clause: str | None = None


@dataclass(frozen=True)
class TargetSelector:
    """Which targets an application entry applies to (§3).

    Three mutually exclusive forms, plus the default. Absent means *all targets*,
    which is what the field table says, and is represented by every field being
    empty rather than by a fourth flag.
    """

    names: tuple[str, ...] = ()
    group: str | None = None
    match: Pairs = ()

    @property
    def is_everything(self) -> bool:
        """True when the entry named no targets and so applies to all of them."""
        return not self.names and self.group is None and not self.match


@dataclass(frozen=True)
class Override:
    """A per-label exception inside an application entry (§2, §3).

    ``where`` selects the targets it applies to; the remaining fields patch the
    entry's own resolution for those targets. Notably absent: ``accounts``. See
    :mod:`sopuli.config.applications` for why that is a rule and not an omission.
    """

    where: Pairs
    vault: str | None = None
    secret: str | None = None
    secret_template: str | None = None
    policy: str | None = None
    oracle: OracleOptions = field(default_factory=OracleOptions)


@dataclass(frozen=True)
class Application:
    """*These accounts, in these targets, mastered by these secrets, under this
    policy* -- the sentence §1 says the whole config exists to state.

    ``name`` is ``None`` for the inline single-application form, which §1 calls
    "exactly sugar for a single unnamed application entry". Both shapes build
    this same object, so nothing downstream has to know which one was written.
    """

    accounts: tuple[str, ...]
    name: str | None = None
    targets: TargetSelector = field(default_factory=TargetSelector)
    vault: str | None = None
    secret: str | None = None
    secret_template: str | None = None
    policy: str | None = None
    oracle: OracleOptions = field(default_factory=OracleOptions)
    overrides: tuple[Override, ...] = ()

    @property
    def is_inline(self) -> bool:
        """Whether this came from the top-level form rather than ``applications:``."""
        return self.name is None

    @property
    def label(self) -> str:
        """How to refer to this entry in a message.

        The inline form has no name to quote, and "application None" is worse
        than saying plainly which form it came from.
        """
        return self.name if self.name is not None else "the inline application"

    @property
    def secret_ref(self) -> str | None:
        """Whichever of ``secret`` / ``secret_template`` was given, if either.

        They are mutually exclusive by validation, so this cannot hide a
        conflict -- it exists so rules about "the ref" do not each have to
        re-derive which field holds it.
        """
        return self.secret if self.secret is not None else self.secret_template


@dataclass(frozen=True)
class Config:
    """One validated config file."""

    version: int
    applications: tuple[Application, ...] = ()

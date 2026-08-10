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

:class:`Config` deliberately carries only what has been validated so far. The
remaining sections -- ``policies``, ``defaults``, ``profiles``, ``runtime`` --
are recognised at the top level but not yet modelled, and arrive as fields here
rather than as a reshaping of it.

Sections that YAML writes as a mapping (``vaults``, ``target_sets``, ``groups``)
are stored as tuples in document order, with the map key copied onto the object
as its name. Document order is what error messages want; output that needs a
stable order sorts at render time.
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
    which is the failure §10 exists to prevent.
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


# --------------------------------------------------------------- the estate ---


@dataclass(frozen=True)
class Safety:
    """A ``safety:`` block, which §9 allows under ``defaults``, a target, a group
    or a profile.

    Every field is optional, and that is load-bearing rather than lazy. §9 says
    safety settings do *not* follow last-one-wins: the resolved value is the
    safest of all layers -- the lowest ``max_targets``, the union of
    ``confirm_environments``, ``readonly`` if any layer sets it. A layer that
    says nothing must therefore be distinguishable from one that sets the
    built-in default, or "safest of all layers" cannot be computed. Resolution
    itself belongs to the precedence work; this only reads what was written.
    """

    max_targets: int | None = None
    confirm_environments: tuple[str, ...] = ()
    readonly: bool | None = None


@dataclass(frozen=True)
class VaultAuth:
    """``auth:`` on a vault -- *how* to authenticate, never the material.

    Only ``method`` is modelled. P2 names the methods but says nothing about the
    keys that point at the material (an AppRole's ``role_id``, a token file), and
    it is explicit that "auth material is never written to the config file in
    plaintext; the config points at *where* the material comes from". Inventing
    those key names here would fix a schema the vault layer has to live with.
    """

    method: str


@dataclass(frozen=True)
class Vault:
    """One entry in ``vaults:`` (§2).

    Only ``type`` is required. The rest is backend-specific -- a file backend has
    no ``addr``, and P2 puts per-backend validation behind the store interface --
    so demanding a HashiCorp shape of every vault would be exactly the top-level
    vendor bias P1 forbids.
    """

    name: str
    type: str
    addr: str | None = None
    mount: str | None = None
    kv_version: int | None = None
    auth: VaultAuth | None = None
    non_production: bool = False


@dataclass(frozen=True)
class AdminCredential:
    """``admin:`` on a target -- the credential the tool uses to reach the database.

    Both fields are optional: P2 puts external authentication (a wallet, where
    there is no username to give) first among the bootstrap sources, and §6 lets
    ``SOPULI_DB_ADMIN_USER`` supply the username per execution context. Storing
    the admin *password* in the config file is not supported at all (P2), so
    there is no field for one.
    """

    username: str | None = None
    auth: str | None = None


@dataclass(frozen=True)
class TargetOracle:
    """``oracle:`` on a target (§2) -- *not* the same block as an application's.

    A target's says which container the tool connects to; an application's
    (:class:`OracleOptions`) says how ``ALTER USER`` is written. They share a key
    name and nothing else, so they are separate types -- one bag accepting both
    key sets would let ``container_clause`` on a target look configured and do
    nothing.
    """

    scope: str | None = None
    container: str | None = None


@dataclass(frozen=True)
class Target:
    """One database endpoint.

    Also the shape a :class:`TargetSet` generates: a set's ``template`` is one of
    these with ``{placeholder}`` tokens still in it. Sharing the type is what
    keeps the two from drifting -- a field added to explicit targets but not to
    generated ones would mean a target set silently cannot express something the
    estate can.
    """

    name: str
    type: str
    dsn: str
    environment: str | None = None
    vault: str | None = None
    admin: AdminCredential | None = None
    oracle: TargetOracle = field(default_factory=TargetOracle)
    labels: Pairs = ()
    safety: Safety | None = None


@dataclass(frozen=True)
class TargetPatch:
    """A ``target_sets.*.overrides`` entry: what to change about one generated
    target, keyed by its rendered name (§4 rule 5).

    Every field optional, since a patch says only what differs. ``name`` is
    absent: the rendered name is the key this patch is found by, so patching it
    would make the key a lie.
    """

    type: str | None = None
    dsn: str | None = None
    environment: str | None = None
    vault: str | None = None
    admin: AdminCredential | None = None
    oracle: TargetOracle | None = None
    labels: Pairs = ()
    safety: Safety | None = None


@dataclass(frozen=True)
class InnerDimension:
    """A variable inside a ``for_each`` value whose value is a list (§4 rule 2).

    ``tenant: [alpha, beta]`` under ``env: dev`` means six dev targets rather
    than one, and is what lets each environment have its own tenant list.
    """

    name: str
    values: tuple[str, ...]


@dataclass(frozen=True)
class DimensionValue:
    """One value of the outer dimension -- ``env: dev`` -- and what it carries.

    ``variables`` are the scalars in scope while rendering this value's targets;
    ``inner`` is the at-most-one list variable found beside them.
    """

    value: str
    variables: Pairs = ()
    inner: InnerDimension | None = None


@dataclass(frozen=True)
class ForEach:
    """``for_each:`` -- exactly one outer dimension and its values (§4 rule 1)."""

    dimension: str
    values: tuple[DimensionValue, ...]


@dataclass(frozen=True)
class TargetSet:
    """One entry in ``target_sets:`` -- a template plus the dimensions to expand it
    over (§4).

    Expansion does not happen here. ``template.name`` and ``template.dsn`` still
    contain ``{placeholder}`` tokens, and nothing in this object has been
    rendered, checked for a duplicate name, or matched against ``overrides``.
    That is the next piece of work; this validates the shape it will read.
    """

    name: str
    template: Target
    for_each: ForEach
    overrides: tuple[tuple[str, TargetPatch], ...] = ()


@dataclass(frozen=True)
class Group:
    """One entry in ``groups:`` -- a named label match over the estate (§4)."""

    name: str
    match: Pairs
    safety: Safety | None = None


# -------------------------------------------------------------- policies ---


@dataclass(frozen=True)
class PasswordPolicy:
    """``policies.*.password`` (§8).

    ``allow`` belongs to ``charset: custom`` and to nothing else. §8's own words
    for that charset are "you take responsibility", which is why the one rule
    this layer enforces on it is invariant 11: a `"` in the allowed set is
    refused rather than escaped, because Oracle quoted identifiers have no escape
    for it.
    """

    length: int | None = None
    charset: str | None = None
    allow: str | None = None
    first_char: str | None = None
    #: ``require: { upper: 1, digit: 1 }`` as sorted pairs. See the module note.
    require: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True)
class RotationPolicy:
    """``policies.*.rotation`` -- how a new password replaces the old one (UC-1 §6)."""

    strategy: str | None = None
    rollover_hours: int | None = None
    keep_previous: bool | None = None
    max_age_days: int | None = None


@dataclass(frozen=True)
class VerifyPolicy:
    """``verify:`` -- how the tool confirms a password works.

    Shared with :class:`Profile`, because §5 makes ``verify.method`` the
    canonical example of run context: the same estate is verified by login from a
    laptop and by hash comparison from a scheduler.
    """

    method: str | None = None
    lockout_margin: int | None = None


@dataclass(frozen=True)
class AccountPolicy:
    """``policies.*.account`` -- what the tool may do to the account itself."""

    unlock_if_locked: bool | None = None


@dataclass(frozen=True)
class Policy:
    """One entry in ``policies:`` -- password rules, rotation, verification."""

    name: str
    password: PasswordPolicy = field(default_factory=PasswordPolicy)
    rotation: RotationPolicy = field(default_factory=RotationPolicy)
    verify: VerifyPolicy = field(default_factory=VerifyPolicy)
    account: AccountPolicy = field(default_factory=AccountPolicy)


# ------------------------------------------------- profiles and the rest ---


@dataclass(frozen=True)
class ProfileDb:
    """``db:`` inside a profile -- budgets that differ when nobody is waiting."""

    connect_timeout_s: int | None = None
    query_timeout_s: int | None = None


@dataclass(frozen=True)
class Profile:
    """One entry in ``profiles:`` -- *where a run is invoked from* (§5).

    Never what it points at. Every field here changes how the tool behaves while
    it works; none of them changes which targets or accounts are in scope, and
    the builder refuses the keys that would.
    """

    name: str
    vault: str | None = None
    verify: VerifyPolicy = field(default_factory=VerifyPolicy)
    rotation_strategy: str | None = None
    safety: Safety | None = None
    confirm: bool | None = None
    output: str | None = None
    log_level: str | None = None
    log_file: str | None = None
    db: ProfileDb = field(default_factory=ProfileDb)


@dataclass(frozen=True)
class Defaults:
    """``defaults:`` -- precedence layer 5 (P3), the bottom of the config file."""

    vault: str | None = None
    policy: str | None = None
    profile: str | None = None
    safety: Safety | None = None


@dataclass(frozen=True)
class OracleRuntime:
    """``runtime.oracle`` -- where the Instant Client lives.

    Not a database setting: thick mode is a runtime prerequisite on every
    platform (P4, D3), so this is about the machine the tool runs on.
    """

    client_lib_dir: str | None = None


@dataclass(frozen=True)
class Runtime:
    """``runtime:`` -- how this installation of the tool is set up."""

    oracle: OracleRuntime = field(default_factory=OracleRuntime)


@dataclass(frozen=True)
class ConfigWarning:
    """Something worth saying that is not worth refusing to run over.

    §10 asks for warnings as well as errors, and they need somewhere to go that
    is not stderr: the config layer does no I/O (``04-testing.md`` §4), and the
    JSON contract has a ``diagnostics`` array these become. Same fields as
    :class:`~sopuli.config.errors.ConfigError` so both render identically.
    """

    message: str
    at: str
    hint: str | None = None

    def __str__(self) -> str:
        rendered = f"{self.at}: {self.message}" if self.at else self.message
        return f"{rendered}\n  hint: {self.hint}" if self.hint else rendered


@dataclass(frozen=True)
class Config:
    """One validated config file."""

    version: int
    applications: tuple[Application, ...] = ()
    vaults: tuple[Vault, ...] = ()
    targets: tuple[Target, ...] = ()
    target_sets: tuple[TargetSet, ...] = ()
    groups: tuple[Group, ...] = ()
    policies: tuple[Policy, ...] = ()
    profiles: tuple[Profile, ...] = ()
    defaults: Defaults = field(default_factory=Defaults)
    runtime: Runtime = field(default_factory=Runtime)
    #: Non-fatal findings, in the order they were made. Empty for a clean file.
    warnings: tuple[ConfigWarning, ...] = ()

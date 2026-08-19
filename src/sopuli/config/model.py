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

from sopuli.config.secret_refs import SecretRef

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

    @property
    def secret_ref(self) -> str | None:
        """Whichever of ``secret`` / ``secret_template`` this patch sets.

        Same shape as :attr:`Application.secret_ref`, and for the same reason:
        they are mutually exclusive by validation, so a rule about "the ref" does
        not have to re-derive which field holds it.
        """
        return self.secret if self.secret is not None else self.secret_template


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
class Binding:
    """One account, in one target, mastered by one secret (§1).

    The sentence §1 says the whole config exists to state, one row at a time.
    Produced by :mod:`sopuli.config.bindings` once selection, overrides and token
    expansion have been applied, so nothing here is still a template.

    ``secret`` is an *address*, never a value -- P2 keeps resolution behind the
    store interface, and this is the object a command hands it.
    """

    account: str
    target: str
    application: str | None = None
    secret: SecretRef | None = None
    vault: str | None = None
    policy: str | None = None


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
class Locking:
    """A ``locking:`` block, under ``defaults`` or a profile (Q2, #83).

    Optional for the reason :class:`Safety`'s fields are, and inverted for a
    reason of its own: ``break_expired`` is the first ratcheted boolean whose
    *safe* value is ``False``. ``readonly: true`` refuses more; permission to
    break a lock nobody is watching refuses less, so the layer that says ``false``
    is the one that must win. See :class:`sopuli.settings.registry.Setting`.
    """

    break_expired: bool | None = None


@dataclass(frozen=True)
class MaterialRef:
    """*Where* a piece of auth material comes from -- never the material (P2).

    Deliberately not a :class:`~sopuli.config.secret_refs.SecretRef`: that
    addresses a value in a vault, and this is what you need *before* you have a
    vault. Two types with two names keep the chicken-and-egg visible. See
    :mod:`sopuli.config.auth`.

    Stored as a kind and a location rather than as two optional fields, so that
    every consumer -- a message, a store, ``config show --explain`` -- handles one
    shape instead of re-deriving which of them was set. There is no field for a
    value, and that absence is the guarantee: nothing downstream can be handed
    plaintext from this object because there is nowhere for plaintext to sit.
    """

    #: One of :data:`~sopuli.config.auth.MATERIAL_KINDS` -- ``env`` or ``file``.
    kind: str
    #: The variable name or the path, as written.
    location: str

    def __str__(self) -> str:
        """``env SOPULI_VAULT_ROLE_ID`` -- a source and where to look, never a
        value. Safe to render anywhere, which is the point of the type."""
        return f"{self.kind} {self.location}"


@dataclass(frozen=True)
class VaultAuth:
    """``auth:`` on a vault -- *how* to authenticate, never the material itself.

    Flat rather than one class per method, with every method-specific field
    optional. A method's own keys are validated when the block is read
    (:mod:`sopuli.config.auth`), so the alternative -- nine small classes and a
    union -- would buy type-level exclusivity at the cost of every consumer having
    to match on it, in the part of the tool that most needs to stay readable.

    Which fields are meaningful follows from ``method``:

    ==================== =========================================
    ``token``            ``token``
    ``approle``          ``mount``, ``role_id``, ``secret_id``
    ``kubernetes``       ``mount``, ``role``, ``jwt``
    ``oidc``             ``mount``, ``role``
    ``userpass``         ``mount``, ``username``, ``password``
    ``instance_principal``  --
    ``resource_principal``  --
    ``config_file``      ``profile``
    ``session_token``    ``profile``
    ==================== =========================================

    ``mount`` here is the *auth* mount, not the KV mount on :class:`Vault`. It
    stays ``None`` when unwritten rather than being filled with the method name it
    defaults to: an unset value has to stay distinguishable from a written one for
    ``config show --explain`` to attribute it (P3).
    """

    method: str
    mount: str | None = None
    role: str | None = None
    username: str | None = None
    profile: str | None = None
    token: MaterialRef | None = None
    role_id: MaterialRef | None = None
    secret_id: MaterialRef | None = None
    jwt: MaterialRef | None = None
    password: MaterialRef | None = None


@dataclass(frozen=True)
class VaultTls:
    """``tls:`` on a vault -- how the transport to it is verified (ADR-005).

    All five paths are plain strings and **not** MaterialRefs, which looks
    inconsistent beside :class:`VaultAuth` until you ask what each one is: a CA
    bundle and a server name are not credentials, and ``client_key`` names a
    *path* rather than holding a key, so nothing here is a secret the config file
    would be storing. The one-key MaterialRef shape exists to make "auth material
    is never written in plaintext" structural; applying it to a CA path would be
    ceremony that protects nothing.

    ``verify`` is the field that is not ordinary config. §3a puts it under P3's
    safety ratchet, so it stays ``None`` when unwritten rather than defaulting to
    ``True`` here: once a profile or ``defaults:`` can patch a store (C13, #136),
    "nobody said" and "somebody wrote true" have to stay distinguishable, or the
    ratchet cannot tell a layer that declined to speak from one that agreed. Read
    it through :attr:`verified`.
    """

    ca_file: str | None = None
    ca_path: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    server_name: str | None = None
    verify: bool | None = None

    @property
    def verified(self) -> bool:
        """The effective value. Absent means verified, and only an explicit
        ``false`` turns it off -- which is the safe reading of a missing key and
        the one a ratchet can agree with later."""
        return self.verify is not False


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
    #: HashiCorp Enterprise namespace, sent as ``X-Vault-Namespace``. Absent means
    #: no namespace, which is not the same as the root one: sending the header
    #: empty is a request about a namespace, and omitting it is not.
    namespace: str | None = None
    #: Request timeout against this store, in seconds. Not optional the way a
    #: stdlib client's would be: ADR-005 chose ``httpx`` partly because it has
    #: **no** default timeout, and a request with no deadline is one that can
    #: hold P5's advisory lock for as long as the network stays open.
    timeout_s: int | None = None
    tls: VaultTls | None = None
    auth: VaultAuth | None = None
    non_production: bool = False
    #: ``required`` or ``advisory-only`` (#83). Unlike the fields above this one
    #: takes its default here rather than staying ``None``: a store either offers
    #: compare-and-set or it does not, and no other precedence layer has an
    #: opinion about one store, so there is nothing to be safest of later.
    locking: str = "required"
    #: The keys some layer other than this entry supplied (C13, #136), sorted.
    #:
    #: Provenance rather than data: every field above already holds the effective
    #: value, and this says which of them did not come from the ``vaults:`` block
    #: itself. It exists because ``config show`` renders a store from this object,
    #: and a table showing an address the entry never wrote -- with nothing to say
    #: so -- would answer "did my YAML say what I think it says" with a value from
    #: a different part of the file.
    #:
    #: Key names, not layers. Which layer won is the resolver's answer and belongs
    #: in ``--explain`` beside every other setting (#153); what belongs here is the
    #: one bit a reader of this table needs, which is *this was not written here*.
    patched: tuple[str, ...] = ()


@dataclass(frozen=True)
class VaultPatch:
    """A partial ``vaults:`` entry, written under ``defaults:`` or in a profile.

    C13 (#31): **`vault:` is a store name everywhere and never a block**, so a
    layer that wants to say something *about* a store names it under ``vaults:``
    -- the file's half of §6's ``SOPULI_VAULT__VAULT_DEV__ADDR``.

    Shaped as :class:`Vault` minus three fields rather than as a ``Vault`` with
    ``type`` made optional, and the difference is the point: what a layer may say
    about a store is a smaller vocabulary than what declares one, and a type that
    could be ``None`` here would be a type that could be ``None`` everywhere.

    * ``type`` is absent because a store that is HashiCorp from a laptop and OCI
      from CI is *two stores*, and one ``vaults:`` name meaning two things is a
      name the audit trail cannot be read with.
    * ``non_production`` and ``locking`` are absent because both are guardrails
      -- §10 checks the first against a ``prod`` target, and ``advisory-only`` is
      the operator conceding a store cannot hold P5's lock. A layer that could
      set either would relax a safety setting from the invocation context, which
      invariant 10 forbids outright.

    Every field is optional and ``None`` means *this layer said nothing*, which
    is what :mod:`sopuli.config.vault_layers` merges on. That distinction is
    load-bearing for ``tls.verify`` in particular -- see :class:`VaultTls`.
    """

    name: str
    addr: str | None = None
    mount: str | None = None
    kv_version: int | None = None
    namespace: str | None = None
    timeout_s: int | None = None
    tls: VaultTls | None = None
    auth: VaultAuth | None = None


@dataclass(frozen=True)
class AdminAuth:
    """``admin.auth`` -- which of P2's bootstrap sources reaches the database.

    The same grammar as :class:`VaultAuth` and a different vocabulary, which is
    the point: both are ``{ method: ... }`` with method-specific keys and a scalar
    shorthand where the method needs nothing else, but ``prompt`` is meaningless
    for a vault and ``approle`` for a database. See :mod:`sopuli.config.auth`.

    ================ ==================================================
    ``external``     -- (a wallet, Kerberos, OS authentication)
    ``vault``        ``secret``
    ``prompt``       --
    ``env``          ``password_env``
    ================ ==================================================

    ``secret`` is a full :class:`~sopuli.config.secret_refs.SecretRef` rather than
    a field of its own invention, so it gains the ``[vault:]`` prefix and §7's
    template tokens without a second grammar to learn -- and defaults to the
    target's own ``vault:`` when it carries no prefix.

    ``password_env`` names its own variable because §6's single
    ``SOPULI_DB_ADMIN_PASSWORD`` does not scale past one admin credential. Absent
    means that pair, and this source stays flagged low-assurance wherever it is
    reported (P2).
    """

    method: str
    secret: SecretRef | None = None
    password_env: str | None = None


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
    auth: AdminAuth | None = None


@dataclass(frozen=True)
class TargetOracle:
    """``oracle:`` on a target (§2) -- *not* the same block as an application's.

    A target's says which container the tool connects to; an application's
    (:class:`OracleOptions`) says how ``ALTER USER`` is written. They share a key
    name and nothing else, so they are separate types -- one bag accepting both
    key sets would let ``container_clause`` on a target look configured and do
    nothing.

    Both fields are **assertions rather than settings**, and optional because an
    assertion nobody makes is not a gap. The driver detects the real scope and
    container on connect (P1 ``resolve_scope``); a declared value that disagrees is
    an error naming both, which is what catches a DSN edit that repointed a target
    somewhere else. Neither constrains the other in the config layer -- see
    :func:`~sopuli.config.targets.read_oracle`.
    """

    #: One of :data:`~sopuli.config.targets.ORACLE_SCOPES`, which is the run
    #: document's own ``scope.type`` vocabulary minus ``unknown``: the same word on
    #: both sides means a mismatch needs no translation to report.
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
    :mod:`sopuli.config.expansion` does that, and produces
    :class:`ExpandedTarget`; this is the shape it reads.
    """

    name: str
    template: Target
    for_each: ForEach
    overrides: tuple[tuple[str, TargetPatch], ...] = ()


@dataclass(frozen=True)
class ExpandedTarget:
    """One target the tool will actually act on, and where it came from (§4).

    Provenance travels with the target rather than being reconstructed later.
    §4 gives ``target list`` a SOURCE column for a reason: generation is
    invisible until it goes wrong, and *why is this target here* is the first
    question asked of a set that produced 34 targets where 35 were expected.

    ``target`` is fully rendered -- no ``{placeholder}`` survives expansion --
    and carries its dimension labels and any ``overrides:`` patch already
    applied.
    """

    target: Target
    #: The ``target_sets:`` entry that generated it. ``None`` for an explicit one.
    target_set: str | None = None
    #: Position in ``targets:``. ``None`` for a generated one.
    index: int | None = None
    #: Which of its keys came from an ``overrides:`` patch rather than from the
    #: template, sorted. Kept per key rather than as one flag because an error
    #: about a value has to point at the line that wrote it: a mistyped `vault:`
    #: in an override reported against the template sends the reader to the one
    #: place the name is spelled correctly.
    patched: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        """The rendered target name -- what ``--target`` selects on."""
        return self.target.name

    @property
    def overridden(self) -> bool:
        """Whether an ``overrides:`` entry patched this target at all.

        Exact rather than approximate: an empty patch is refused when the set is
        read, so a patched key exists whenever an override applied.
        """
        return bool(self.patched)


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
    locking: Locking | None = None
    confirm: bool | None = None
    output: str | None = None
    log_level: str | None = None
    log_file: str | None = None
    db: ProfileDb = field(default_factory=ProfileDb)
    #: Partial entries patching stores declared at the top level (C13, #136).
    #:
    #: Layer 3, the highest the file can supply, so these **override** what the
    #: declaration wrote -- which is the case §5 exists for: token from a laptop,
    #: AppRole from CI, one store, one name in the audit trail.
    #:
    #: Parsed and validated; **not yet applied**, because nothing activates a
    #: profile (#153). A run has no active profile to take these from.
    vaults: tuple[VaultPatch, ...] = ()


@dataclass(frozen=True)
class Defaults:
    """``defaults:`` -- precedence layer 5 (P3), the bottom of the config file."""

    vault: str | None = None
    policy: str | None = None
    profile: str | None = None
    safety: Safety | None = None
    locking: Locking | None = None
    #: Partial entries patching stores declared at the top level (C13, #136).
    #:
    #: Layer 5, so these are **outranked by the declaration itself**: they supply
    #: keys the ``vaults:`` entry did not write rather than replacing ones it did.
    #: A profile's block is the other way round, being layer 3.
    vaults: tuple[VaultPatch, ...] = ()


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

    ``code`` is optional and mostly absent. §10's findings have none, and J3 --
    which warnings get a code, and how numbers are allocated across categories --
    is still open, so this is a slot rather than a policy: a finding a consumer
    would want to branch on can carry one, and the rest stay prose. The first is
    ``SOPULI-W004``, because a run with certificate verification turned off is
    exactly what a scheduler should be able to notice without matching text.
    """

    message: str
    at: str
    hint: str | None = None
    code: str | None = None

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
    #: The estate after §4 expansion: every explicit target, then every generated
    #: one. Derived from the two fields above and built once, at load, so that
    #: what a command acts on and what ``config show --resolved`` prints are the
    #: same objects rather than two expansions that could differ.
    expanded_targets: tuple[ExpandedTarget, ...] = ()
    #: One row per account per target, with its ref rendered (§1). Derived from
    #: `applications` and the expanded estate, and built at load for the same
    #: reason: the binding a command acts on and the one `config show --resolved`
    #: prints must be the same object.
    bindings: tuple[Binding, ...] = ()
    groups: tuple[Group, ...] = ()
    policies: tuple[Policy, ...] = ()
    profiles: tuple[Profile, ...] = ()
    defaults: Defaults = field(default_factory=Defaults)
    runtime: Runtime = field(default_factory=Runtime)
    #: Non-fatal findings, in the order they were made. Empty for a clean file.
    warnings: tuple[ConfigWarning, ...] = ()

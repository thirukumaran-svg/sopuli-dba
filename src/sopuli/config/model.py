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

Sections that YAML writes as a mapping (``vaults``, ``target_sets``, ``groups``)
are stored as tuples in document order, with the map key copied onto the object
as its name. Document order is what error messages want; output that needs a
stable order sorts at render time.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sopuli.config.secret_refs import SecretRef
from sopuli.settings import Resolved

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
class SafetyDelivery:
    """The ``delivery:`` sub-block of a ``safety:`` block (H6).

    A block of its own rather than a ``delivery_allowed_methods`` field, because
    the key path is what an operator edits and what every message names:
    ``safety.delivery.allowed_methods``. Flattening it here would leave the model
    spelling one thing and the file another, and a second UC-2 safety axis would
    have nowhere obvious to go.

    **``None`` means no constraint, not the empty set**, which is the one reading
    an intersection cannot get wrong twice: a layer that wrote nothing must be
    distinguishable from one that allows nothing, or a file configuring no
    delivery policy at all would resolve to an estate that can deliver nothing.
    :class:`Safety`'s fields keep the same distinction for the same reason, and
    ``allowed_methods: []`` is refused where it is read rather than stored as
    ``()`` -- see :func:`sopuli.config.safety.build_safety`.
    """

    allowed_methods: tuple[str, ...] | None = None


@dataclass(frozen=True)
class Safety:
    """A ``safety:`` block, which §9 allows under ``defaults``, a target, a group
    or a profile.

    Every field is optional, and that is load-bearing rather than lazy. §9 says
    safety settings do *not* follow last-one-wins: the resolved value is the
    safest of all layers -- the lowest ``max_targets``, the union of
    ``confirm_environments``, the *intersection* of
    ``delivery.allowed_methods``, ``readonly`` if any layer sets it. A layer that
    says nothing must therefore be distinguishable from one that sets the
    built-in default, or "safest of all layers" cannot be computed. Resolution
    itself belongs to the precedence work; this only reads what was written.
    """

    max_targets: int | None = None
    confirm_environments: tuple[str, ...] = ()
    readonly: bool | None = None
    delivery: SafetyDelivery | None = None


@dataclass(frozen=True)
class Locking:
    """A ``locking:`` block, under ``defaults`` or a profile (Q2).

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

    The four paths and ``server_name`` are plain strings and **not** MaterialRefs, which looks
    inconsistent beside :class:`VaultAuth` until you ask what each one is: a CA
    bundle and a server name are not credentials, and ``client_key`` names a
    *path* rather than holding a key, so nothing here is a secret the config file
    would be storing. The one-key MaterialRef shape exists to make "auth material
    is never written in plaintext" structural; applying it to a CA path would be
    ceremony that protects nothing.

    ``verify`` is the field that is not ordinary config. §3a puts it under P3's
    safety ratchet, so it stays ``None`` when unwritten rather than defaulting to
    ``True`` here: once a profile or ``defaults:`` can patch a store (C13),
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
    #: ``required`` or ``advisory-only``. Unlike the fields above this one
    #: takes its default here rather than staying ``None``: a store either offers
    #: compare-and-set or it does not, and no other precedence layer has an
    #: opinion about one store, so there is nothing to be safest of later.
    locking: str = "required"
    #: The keys some layer other than this entry supplied (C13), sorted.
    #:
    #: Provenance rather than data: every field above already holds the effective
    #: value, and this says which of them did not come from the ``vaults:`` block
    #: itself. It exists because ``config show`` renders a store from this object,
    #: and a table showing an address the entry never wrote -- with nothing to say
    #: so -- would answer "did my YAML say what I think it says" with a value from
    #: a different part of the file.
    #:
    #: Key names, not layers. Which layer won is :attr:`settings`' answer and
    #: belongs in ``--explain`` beside every other setting; what belongs
    #: here is the one bit a reader of this table needs, which is *this was not
    #: written here*.
    patched: tuple[str, ...] = ()
    #: Every merged key with the layer that supplied it, as sorted pairs
    #: (decision #428).
    #:
    #: The rest of :attr:`patched`'s answer. :mod:`sopuli.config.vault_layers`
    #: resolves each reach key through :mod:`sopuli.settings` and keeps the
    #: :class:`~sopuli.settings.Resolved`. With only the key *name*, three
    #: different layers writing ``addr`` would look the same, and no view could
    #: tell an address an operator redirected on purpose from one a colleague's
    #: exported ``VAULT_ADDR`` supplied.
    #:
    #: **Every key that has a value, not only the layered ones.** A store whose
    #: ``mount`` came from its own ``vaults:`` entry gets a pair too, because
    #: otherwise an absent key means either *nobody wrote it* or *only the
    #: declaration did*, and a provenance view that cannot separate those answers
    #: the question it exists for with a shrug. ``auth:`` is the one exclusion: it
    #: is replaced whole rather than resolved key by key, so there is no
    #: ``Resolved`` for it -- :attr:`patched` still names it.
    #:
    #: Sorted pairs rather than a mapping, for the reason the module note gives.
    settings: tuple[tuple[str, Resolved], ...] = ()


@dataclass(frozen=True)
class VaultPatch:
    """A partial ``vaults:`` entry, written under ``defaults:`` or in a profile.

    C13: **`vault:` is a store name everywhere and never a block**, so a
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
    #: The ``safety:`` block the **template** wrote, where an ``overrides:``
    #: entry patched it -- ``None`` everywhere else, the patched value being the
    #: only one there is.
    #:
    #: Kept because a patch merges key by key, so the flattened
    #: :attr:`Target.safety` can hold an override's ``readonly: false`` over a
    #: template's ``true`` and the safer of the two is gone before anything can
    #: ratchet them. Both reach
    #: :func:`~sopuli.settings.sources.estate_contributions` as separate
    #: contributions, and the one resolver takes the safest (invariant 10, §9;
    #: decision #424).
    template_safety: Safety | None = None

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
    """``policies.*.account`` -- what the tool may do to the account itself.

    Every field is ``None`` when the file said nothing, which for these means the
    same as saying no: UC-1 §5's attributes are opt-in, and the tool enforces
    only what was declared. The distinction is kept rather than collapsed for
    :class:`Safety`'s reason -- a layer that said nothing has to stay
    distinguishable from one that said no, or a later precedence question cannot
    be asked at all.
    """

    unlock_if_locked: bool | None = None
    #: The profile this account is to sit on (decision #301). A *name*, resolved
    #: against the database rather than against anything in the file: which profiles
    #: exist is a property of each target.
    profile: str | None = None


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
    #: Partial entries patching stores declared at the top level (C13).
    #:
    #: Layer 3, the highest the file can supply, so these **override** what the
    #: declaration wrote -- which is the case §5 exists for: token from a laptop,
    #: AppRole from CI, one store, one name in the audit trail.
    #:
    #: Applied when this profile is the one :attr:`Config.active_profile` names,
    #: in the same pass that merges layers 4 and 5. A declared profile
    #: nobody selected patches nothing: §5 rule 1 makes exactly one active.
    vaults: tuple[VaultPatch, ...] = ()


@dataclass(frozen=True)
class Defaults:
    """``defaults:`` -- precedence layer 5 (P3), the bottom of the config file."""

    vault: str | None = None
    policy: str | None = None
    profile: str | None = None
    safety: Safety | None = None
    locking: Locking | None = None
    #: Partial entries patching stores declared at the top level (C13).
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
class PersonalAccountRule:
    """One rule in `personal_accounts:` -- accounts belonging to people (H1).

    Named for the **rule** rather than the accounts because one entry is not one
    account: it is a list of names, or a predicate that stands for however many
    accounts a database says carry a profile. The rest of the model is singular
    per entry (:class:`Application`, :class:`Policy`, :class:`Profile`) and this
    follows it.

    Exactly one of ``accounts``, ``profile`` and ``role`` says *which*: a list of
    names, or a **predicate** over a profile or a role that a database resolves at
    run time. The predicate exists because enumerating four hundred developers is
    transcription rather than review, and it amends invariant 5's first sentence
    without touching its second -- `account list` resolves it, while a reset names
    its account and refuses any name the predicate does not admit.

    Notably absent: ``secret`` and ``secret_template``. Nothing masters a personal
    account's password, which is the whole reason this is not an
    :class:`Application` (UC-2 §1).
    """

    accounts: tuple[str, ...] = ()
    profile: str | None = None
    role: str | None = None
    targets: TargetSelector = field(default_factory=TargetSelector)
    policy: str | None = None

    @property
    def is_predicate(self) -> bool:
        """Whether this entry is resolved against a database rather than read."""
        return not self.accounts

    @property
    def label(self) -> str:
        """How to refer to this entry in a message."""
        if self.profile is not None:
            return f"profile {self.profile!r}"
        if self.role is not None:
            return f"role {self.role!r}"
        return "accounts " + ", ".join(repr(account) for account in self.accounts)


@dataclass(frozen=True)
class ResetRecords:
    """Where UC-2 journals a reset -- a store and a prefix (H2).

    One destination for the estate rather than one per account, because the
    record's own path is derived from the (target, account) pair rather than
    written (:func:`sopuli.reset_record.record_path`). What an operator chooses
    is where the journal lives; what a run chooses is which record in it.

    **Not the delivery target.** On the unseen path the password goes where only
    the person can read it; this holds what happened and no password in any
    representation (UC-2 §3.1, §3.5). Two objects, two lifetimes, and a store
    that happens to be the same store does not make them one thing.

    ``vault`` names an entry in `vaults:`, resolved with every other store
    reference by :mod:`sopuli.config.references`, so a misspelling is refused at
    load with the same message an application's ``vault:`` gets.
    """

    vault: str
    prefix: str


@dataclass(frozen=True)
class ManualDelivery:
    """`delivery.manual:` -- the seen path's settings.

    One key, and it is **required rather than defaulted**. `manual` is the only
    method that shows a working password to somebody who is not its owner, and
    what makes that allowable is not that it is harmless but that the exposure is
    deliberate, witnessed and *time-limited* (UC-2 §1). Expiry is what ends it: a
    `manual` delivery without `force_expire: true` would be an exposure with no
    end, so the fifth of the five guards (decision #439) refuses one when the file
    is loaded, rather than quietly supplying the safe value.

    **Defaulting it to `True` would have been worse than refusing**, which is why
    it is a required key and not a field with a default. An estate that never
    wrote it would get the guard silently, and the one that wrote
    `force_expire: false` deliberately would get it too -- so the file would say
    one thing and the run would do another, in the direction that reads as
    protection.
    """

    force_expire: bool


@dataclass(frozen=True)
class WrappedDelivery:
    """`delivery.vault_wrapped:` -- the default method's settings.

    One key, and it is **required rather than defaulted** for the same reason
    `manual`'s is: a wrapping token's whole safety story is that it stops working,
    and for how long is not something a tool should choose on an estate's behalf.
    A default would be a number nobody reviewed standing between a password and
    whoever finds the token later.

    **The TTL is a string, passed to Vault rather than parsed.** Vault owns the
    grammar of ``X-Vault-Wrap-TTL``, and a second implementation of it here would
    be a parser that disagrees with the server about what ``90m`` means -- and
    disagrees silently, since both sides would accept the input. What the config
    layer checks is the *shape*, so a typo is a config error rather than a 400
    after a password has been drawn.

    **There is no `num_uses`, and writing one is an error.** A response-wrapping
    token is single-use by construction, so the key would describe a guarantee
    this tool is not providing and Vault is. Accepting and ignoring it is the
    failure mode that matters: a file saying `num_uses: 1` reads as an estate
    having chosen something.
    """

    ttl: str
    #: Which `vaults:` entry to wrap into, or ``None`` for §3's chain -- the
    #: target's `vault:`, then `defaults.vault`. Not `reset_records.vault`:
    #: UC-2 §3.5 keeps the journal and the delivery target apart, and a default
    #: that joined them would hide whether an estate meant them to be one store.
    vault: str | None = None


@dataclass(frozen=True)
class WebhookNotify:
    """`delivery.notify.webhook:` -- where to post, and what to say.

    ``url`` is a :class:`MaterialRef` rather than a string, and that is C9 doing
    real work rather than being applied uniformly: a chat incoming-webhook URL
    *embeds its own credential*, so a plain string here would put one in a file
    people commit and in every rendering of that file. Holding a location instead
    means the redaction is structural -- there is no value to
    redact, because the model never has one.

    ``template`` is the estate's own sentence, which is why the tool never authors
    it: what is true of a hand-over differs by path, and a message the tool wrote
    would be wrong on one of them. Its placeholders are checked at load against a
    closed set (:mod:`sopuli.config.notify`), so a template that cannot render is
    a config error rather than a failure once a password has been drawn.
    """

    url: MaterialRef
    template: str


@dataclass(frozen=True)
class Notify:
    """`delivery.notify:` -- the low-trust channel that says a password is ready.

    **Nests inside `delivery:` rather than beside it** (UC-2 §6.3), because it is
    a property of a delivery rather than of a run: an estate delivering two ways
    would need two of these.

    **It may never carry the password, or anything that retrieves it** (§6.1).
    That is the one binding rule of UC-2 §6 and it is enforced in the config
    layer, where a template is read -- not at send time, because by then a
    password has been drawn and the run has something to lose.
    """

    method: str
    #: `webhook`'s settings, where `webhook` is the selected method.
    webhook: WebhookNotify | None = None


@dataclass(frozen=True)
class Delivery:
    """How a personal account's new password reaches its owner (UC-2 §6).

    ``method`` is one of :data:`~sopuli.config.delivery.DELIVERY_METHODS`, and it
    is the whole type on purpose.

    **A per-method sub-block reaches the model only as a typed field.** Every
    sub-block is checked for shape, and the selected method must have brought
    one. *Which* keys a method takes is a fact about the service behind it -- a
    response-wrapping token is single-use by construction, so `num_uses` is a
    config error rather than a key with a default -- and nothing in a config layer
    can know that. A field holding the sub-block as opaque pairs would carry
    unvalidated content through the model and invite a consumer to read it, which
    is the shape of the mistake `01-configuration.md` §1 calls the one with the worst consequences.
    Each built method has a typed field of its own. A method that is not built
    has none, and its sub-block is not retained.

    The same applies to `notify:`, which nests under delivery because it is
    a property of a delivery rather than of a run -- and which may never carry the
    secret or anything that retrieves it (UC-2 §6.1), a rule its own builder must
    enforce because it needs the template grammar.

    **`manual` has a typed field of its own**, as each built method does, rather
    than a bag. It is ``None`` where `manual` is not the selected method -- an
    unselected method's settings are not read, and a field holding them would
    invite a consumer to act on a block the run is not using.
    """

    method: str
    #: `manual`'s settings, where `manual` is selected.
    manual: ManualDelivery | None = None
    #: `vault_wrapped`'s settings, where it is selected. Each built method has a
    #: typed field, ``None`` for every method the run is not using.
    vault_wrapped: WrappedDelivery | None = None
    #: The channel that says a password is ready, or ``None`` where the
    #: estate configured none. Read whichever `method` is selected, unlike a
    #: method's own sub-block: a notification is a property of the delivery as a
    #: whole, and the template is the estate's sentence rather than the tool's --
    #: so it is theirs to make true of the path they chose.
    notify: Notify | None = None

    @property
    def is_seen(self) -> bool:
        """Whether this method shows a working password to the DBA.

        The one property of a delivery the rest of the tool branches on, and it is
        a method comparison rather than a flag somebody sets: a path is seen
        because of what it does, not because a file said so.
        """
        return self.method == "manual"


@dataclass(frozen=True)
class Config:
    """One validated config file."""

    version: int
    applications: tuple[Application, ...] = ()
    #: UC-2's personal accounts, by name or by predicate (H1). Separate
    #: from `applications` because the two carry different guarantees, and a
    #: name may not appear in both -- see
    #: :func:`~sopuli.config.personal_accounts.reject_cross_declaration`.
    personal_accounts: tuple[PersonalAccountRule, ...] = ()
    #: Where UC-2's reset journal lives, or `None` where the file declares no
    #: destination. `None` is a documented mode rather than a default
    #: waiting to be filled in: a reset with nowhere to journal warns and runs,
    #: because the seen path may have no store at all and refusing would take
    #: the fallback away from the estates it exists for (UC-2 §3.1, §3.4).
    reset_records: ResetRecords | None = None
    #: How UC-2 hands a password over, or `None` where the file says nothing.
    #: `None` is not `vault_wrapped`: an estate that configured no
    #: delivery has not silently chosen one, and a reset with nowhere to deliver
    #: is a refusal for the verb to make rather than a default to materialise
    #: here.
    delivery: Delivery | None = None
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
    #: The one profile this run is invoked under, or ``None`` (§5).
    #:
    #: A property of the *run* rather than of the file, and it lives here anyway
    #: because it is what makes layer 3 reachable: `vaults:` patching happens
    #: while the file is being built, and it cannot know which patches apply
    #: until the profile is chosen. Selected by
    #: :func:`~sopuli.config.profiles.select_profile` from the name the command
    #: line or the environment supplied, falling back to `defaults.profile`.
    active_profile: Profile | None = None
    defaults: Defaults = field(default_factory=Defaults)
    runtime: Runtime = field(default_factory=Runtime)
    #: Non-fatal findings, in the order they were made. Empty for a clean file.
    warnings: tuple[ConfigWarning, ...] = ()

"""Resolving the admin credential: P2's four sources, at connect time (#175).

``admin:`` has been parsed since the config layer was written
(:mod:`sopuli.config.targets`) and validated against its target
(:mod:`sopuli.config.references`), and nothing has ever resolved one. This is
the database half of what :mod:`sopuli.material` did for vault material: turn a
named source into a :class:`~sopuli.secrets.Secret`.

P2's bootstrap list, in its order of preference:

=============== ================================================================
``external``    a wallet, Kerberos, OS auth -- there is no material to resolve
``vault``       a whole SecretRef (§7), resolved through the target's store
``prompt``      interactive
``env``         ``password_env:``, defaulting to ``SOPULI_DB_ADMIN_PASSWORD``
=============== ================================================================

**Here rather than in** :mod:`sopuli.config`, for the reason
:mod:`sopuli.material` gives at greater length: prompting and reading the
environment are I/O, and ``04-testing.md`` §4 makes the config layer I/O-free as
an architecture requirement rather than a test convenience. The file names a
location; this reads it, when something connects.

**Resolution is a function over a ref, never a method on one** -- #137's shape,
kept for its reason. An :class:`~sopuli.config.model.AdminCredential` that had
been "resolved" would have to hold the value, and the guarantee ends the moment
somebody caches one.

**Every source arrives through a supplier the caller passes in.** ``env`` is a
mapping, ``prompt`` is a callable, ``vault`` is a callable over a ref. Three
consequences, and the first two are the reasons:

* a run that authenticates by wallet never builds a store client, because the
  ``vault`` branch is the only thing that calls one and a function is lazy;
* ``prompt=None`` is how "nobody is at a terminal" is expressed, so the refusal
  in :func:`_from_prompt` is reachable in a test without a pty;
* the ``vault`` branch has no implementation to wait for. Resolving a SecretRef
  against a stored document is #183's, and this module deliberately does not
  reimplement it -- Q7's "one rule for both layouts" would be two rules the day
  it did.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from sopuli.config.errors import ConfigError, KeyPath
from sopuli.config.expansion import declared_at
from sopuli.config.model import AdminAuth, ExpandedTarget, MaterialRef
from sopuli.config.secret_refs import SecretRef
from sopuli.config.targets import ADMIN_METHODS, ADMIN_PASSWORD_ENV, EXTERNAL
from sopuli.driver.protocol import Credential
from sopuli.exit_codes import ExitCode
from sopuli.material import MaterialError
from sopuli.material import resolve as resolve_material
from sopuli.secrets import Secret

#: §6's username variable. Overrides a target's ``username:`` per execution
#: context, and is ignored under ``external`` -- see :func:`_username`.
ADMIN_USER_ENV = "SOPULI_DB_ADMIN_USER"

VAULT = "vault"
PROMPT = "prompt"
ENV = "env"

#: The method whose material is an environment variable, and so the one P2
#: requires be "flagged in output as low-assurance". A set of one rather than
#: ``method == ENV`` at each call site, because what gets reported is
#: *assurance* and not *which method*: a second low-assurance source would
#: otherwise have to find every reporting site again.
LOW_ASSURANCE = frozenset({ENV})

#: Reads a §7 ref and returns its value. Supplied by the caller, because the
#: store it resolves against is authenticated well before this module is reached
#: and #183 owns what a credential document looks like.
RefReader = Callable[[SecretRef], Secret]

#: Asks for one target's admin password, given the target and the username the
#: connection will actually use. Both, rather than a line of text, so that the
#: prompter can decide whether it has been asked this before -- see
#: :class:`PasswordPrompt`.
Prompter = Callable[[ExpandedTarget, "str | None"], Secret]

#: Shows a line and reads a password without echoing it. Returns a ``str``, and
#: that is deliberate: :func:`getpass.getpass` is the obvious implementation and
#: this makes it usable *as it is*, with :class:`PasswordPrompt` wrapping the
#: result exactly once. A contract returning :class:`~sopuli.secrets.Secret`
#: would put that wrapping in every supplier instead, which is invariant 2's own
#: argument against remembering to mask at a call site: a supplier that forgot
#: would put a bare ``str`` into :attr:`Resolved.credential`, where ``repr``
#: prints it in full.
#:
#: The module does not name :mod:`getpass` itself. Importing it here would put a
#: terminal read one import away from the config layer, and the CLI is where the
#: decision *whether there is a terminal* already lives.
Asker = Callable[[str], str]


class AdminCredentialError(ConfigError):
    """The named source for a target's admin credential held nothing usable.

    ``config`` and exit 9, matching :class:`~sopuli.material.MaterialError` and
    for its reasoning: the file is not wrong in a way the parser could have
    caught and the database has refused nothing -- what is incomplete is *this
    machine and this moment*, and the person reading the message is the one who
    fixes it.

    Distinct from the exit 6 the driver raises when Oracle rejects a credential.
    That one means "we sent it and it was not accepted"; this means "there was
    nothing to send".
    """


class NobodyToAskError(AdminCredentialError):
    """``auth: prompt`` on a run with no terminal.

    Exit 8 rather than 9, the distinction ``lock break`` already draws with
    :class:`~sopuli.safety.RefusedError`: the file is right, the invocation is
    right, and the run stopped because it needed a human and there was not one.
    A scheduler branching on 9 would send somebody to look at a config file that
    has nothing wrong with it.
    """

    exit_code = ExitCode.ABORTED
    category = "policy"


@dataclass(frozen=True)
class Resolved:
    """One target's admin credential, and where it came from.

    Two halves, deliberately apart. :attr:`credential` is what the driver takes
    -- P1's :class:`~sopuli.driver.protocol.Credential`, which is a username, a
    secret, or neither. Everything else is *provenance*, which the driver has no
    use for and the run document does: P2 requires the environment source be
    flagged low-assurance wherever it is reported, and a flag that travelled
    inside the driver's input would have to be carried back out again.

    This module classifies and does not decide -- the shape #172 and #173
    settled on. Nothing here emits a warning or picks an exit code for the
    *reporting* of a low-assurance source: the command that connects knows
    whether this run produces a document, and it is the one that says so.
    """

    credential: Credential
    #: Which of :data:`~sopuli.config.targets.ADMIN_METHODS` produced it.
    method: str
    #: Where the material came from, in words, for the plan and the document --
    #: ``the environment variable SOPULI_DB_ADMIN_PASSWORD``. Never the value.
    source: str

    @property
    def low_assurance(self) -> bool:
        """P2: the environment source is supported and flagged, not refused."""
        return self.method in LOW_ASSURANCE


def prompt_key(target: ExpandedTarget, username: str | None) -> str:
    """What makes two targets share one prompt.

    Prompting per target for the same credential is a bad experience -- an
    estate of thirty-four generated targets would ask thirty-four times -- and
    caching across targets that only *look* alike is a worse bug. So the key is
    **what the configuration declares**, not what the credential turns out to be:

    * the **declaration site** -- ``target_sets.appdb`` for a generated target,
      ``targets[2]`` for an explicit one. One ``target_sets:`` entry is one
      operator writing one credential down once, and every target it generates
      is covered by that act. Two explicit targets are two acts and are asked
      twice, even where the blocks are identical, because the file gives no
      reason to believe they are the same credential;
    * the **effective username** -- what :func:`_username` resolved, so §6's
      ``SOPULI_DB_ADMIN_USER`` counts. That is what distinguishes generated
      targets from one another: ``username: C##SOPULI_SVC`` across a CDB
      resolves the same everywhere and is one credential, while ``username:
      sopuli_{tenant}`` resolves differently per target and is thirty-four.

    **Effective and not as-written**, which is the correction #196's review
    forced. Taking it from the file alone gets both halves wrong at once. The
    operator would be asked for one account's password while the connection used
    another, since the variable overrides ``username:`` -- so the two differ
    exactly when it is set. And the key would separate targets the variable has
    just made identical: ``sopuli_{tenant}`` under ``SOPULI_DB_ADMIN_USER`` is
    one account on thirty-four databases, and would have been asked about
    thirty-four times. The variable is P3's layer 3 and the file is layer 4;
    "what the configuration declares" means the resolved value, not the lowest
    layer that had an opinion.

    Deliberately **not** the username alone, which is the tempting key and the
    unsafe one: two PDBs can hold same-named local accounts with different
    passwords, and a cache keyed on the name would send the first PDB's password
    to the second and read the resulting ORA-01017 as a rotation problem.

    The DSN is deliberately not in the key either. Targets generated from one
    entry with a literal username point at different databases *by design*, and
    including the DSN would defeat the whole cache. Where those databases really
    do hold different passwords the run fails at the second one with an
    authentication error naming the target -- diagnosable, and the file's own
    claim being wrong rather than this cache guessing.
    """
    # NUL, because it cannot appear in a key path or in an Oracle identifier and
    # so cannot be smuggled in by a username to make two distinct keys collide.
    return "\x00".join((str(declared_at(target, "admin")), username or ""))


@dataclass
class PasswordPrompt:
    """A :data:`Prompter` that asks once per declared credential.

    Mutable and stateful, unlike almost everything else here, and that is the
    point: the state *is* the answer to "have we asked for this one already".
    One instance lives for one run.

    :attr:`ask` is injected rather than being :func:`getpass.getpass` directly,
    which keeps this testable without a pty and keeps the terminal read at the
    CLI boundary where the decision about whether there *is* a terminal already
    lives.

    **This is where a typed password becomes a** :class:`~sopuli.secrets.Secret`,
    and it is the only place. The asker hands back a ``str`` because every
    terminal read does; wrapping it here means a supplier cannot forget to, and
    invariant 2's guarantee holds for the prompt source the way it holds for the
    other three -- structurally, rather than because each caller remembered.
    """

    ask: Asker
    _answers: dict[str, Secret] = field(default_factory=dict, repr=False)

    def __call__(self, target: ExpandedTarget, username: str | None) -> Secret:
        key = prompt_key(target, username)
        if key not in self._answers:
            self._answers[key] = Secret(self.ask(self.line(target, username)))
        return self._answers[key]

    @staticmethod
    def line(target: ExpandedTarget, username: str | None) -> str:
        """What the operator is asked, naming both halves of the answer.

        The account *and* the target, because an estate prompts for several and
        "Password:" on its own is a question nobody can answer correctly twice.

        ``username`` is the **effective** one, for the reason
        :func:`prompt_key` gives: being asked for ``C##SOPULI_SVC`` and then
        connecting as whatever ``SOPULI_DB_ADMIN_USER`` says is a question whose
        answer is wrong through no fault of the person answering it.
        """
        who = username or "the admin account"
        return f"password for {who} on {target.name}: "


def needs_prompt(target: ExpandedTarget) -> bool:
    """Whether reaching this target will stop and ask for a password.

    Pure, and separate from :func:`resolve` on purpose. Invariant 4's shape is
    that a run which cannot succeed says so *before* it touches anything, and a
    run with ``auth: prompt`` and no terminal can never succeed -- but resolution
    itself belongs at connect time, so the check and the read cannot be the same
    call. This is the half a plan can ask, over the whole selected estate, while
    it is still deciding what to do.

    :func:`resolve` refuses on the same condition rather than trusting the plan
    to have asked. Two guards, because the plan phase does not exist yet and the
    one that must not be forgotten is the one nearest the pipe.
    """
    auth = _auth(target)
    return auth is not None and auth.method == PROMPT


def resolve(
    target: ExpandedTarget,
    *,
    env: Mapping[str, str],
    read_ref: RefReader | None = None,
    prompt: Prompter | None = None,
) -> Resolved:
    """The credential that reaches ``target``, from whichever source it names.

    ``env`` is passed in and never :data:`os.environ`, the arrangement
    :mod:`sopuli.material`, :mod:`sopuli.config.discovery` and
    :mod:`sopuli.settings.sources` already use: a test that had to set a real
    variable to check a rule is a test that cannot run beside another one.
    """
    auth = _auth(target)
    if auth is None:
        raise _no_source(target)

    if auth.method == EXTERNAL:
        # No username, and none read from the environment either: the wallet
        # supplies both halves, and `Credential.external` is what says so.
        return Resolved(
            credential=Credential(external=True),
            method=EXTERNAL,
            source="an external password store",
        )

    username = _username(target, env=env)

    if auth.method == VAULT:
        secret = _read_ref(auth.secret, target=target, read_ref=read_ref)
        source = f"vault ref {auth.secret}"
    elif auth.method == PROMPT:
        secret, source = _from_prompt(target, username=username, prompt=prompt)
    elif auth.method == ENV:
        secret, source = _from_env(auth, target=target, env=env)
    else:  # pragma: no cover - `ADMIN_METHODS` is a closed set the builder checks
        raise AdminCredentialError(
            f"target {target.name!r} names an unknown admin auth method {auth.method!r}",
            at=_at(target, "auth", "method"),
        )

    return Resolved(
        credential=Credential(username=username, secret=secret),
        method=auth.method,
        source=source,
    )


# ------------------------------------------------------------------ sources ---


def _from_prompt(
    target: ExpandedTarget, *, username: str | None, prompt: Prompter | None
) -> tuple[Secret, str]:
    """``method: prompt`` -- and the refusal when there is nobody there.

    **A prompt never reads stdin**, which is how P5's "one stream, one reader"
    survives contact with this method. That rule reserves the pipe for at most
    one secret per run and ``--from-stdin`` (UC-1 §5) already claims it on
    ``creds apply``; a prompt that fell back to stdin on finding no terminal
    would be a second reader of the same stream, taking the password meant for
    the *account* and sending it to the database as the DBA's.

    The refusal makes that impossible rather than merely discouraged. A prompter
    is supplied only when stdin is a terminal, and a terminal is not carrying a
    piped password -- so the two sources are mutually exclusive by construction
    and no ordering between them ever has to be defined.
    """
    if prompt is None:
        raise NobodyToAskError(
            f"target {target.name!r} asks for its admin password interactively, "
            f"and there is nobody here to ask",
            at=_at(target, "auth"),
            hint=(
                f"run it from a terminal, or name a source that needs no one: "
                f"`auth: {{ method: vault, secret: … }}`, `auth: {{ method: env }}` "
                f"reading ${ADMIN_PASSWORD_ENV}, or `auth: external` with a wallet"
            ),
        )
    return prompt(target, username), "an interactive prompt"


def _from_env(
    auth: AdminAuth, *, target: ExpandedTarget, env: Mapping[str, str]
) -> tuple[Secret, str]:
    """``method: env`` -- ``password_env:``, or §6's pair.

    Delegated to :func:`sopuli.material.resolve` rather than reading the mapping
    here, so that §6's "set but empty counts as unset" is decided in one place
    and worded once: a CI job that clears an inherited variable gets the same
    message as one that never set it, because it is the same situation described
    two ways.

    **Re-raised with a location**, which is the one thing the delegate cannot
    supply. :func:`sopuli.material.resolve` reports at :data:`ROOT` because it is
    also used for a store's auth material and has no idea which target asked;
    here the key that named the variable is known, so the error can point at the
    line to edit instead of at the document. The message and hint are the
    delegate's own -- reworded here, they would be two descriptions of one rule.
    """
    name = auth.password_env or ADMIN_PASSWORD_ENV
    where = f"target {target.name!r} admin credential"
    try:
        secret = resolve_material(MaterialRef(kind="env", location=name), env=env, where=where)
    except MaterialError as error:
        # Where `password_env:` was written, that is the key to point at. Where
        # it was not, the variable is a default and no such key exists -- naming
        # one would send the reader looking for a line that is not there.
        at = _at(target, "auth", "password_env") if auth.password_env else _at(target, "auth")
        raise AdminCredentialError(error.message, at=at, hint=error.hint) from error
    return secret, f"the environment variable {name}"


def _read_ref(
    ref: SecretRef | None, *, target: ExpandedTarget, read_ref: RefReader | None
) -> Secret:
    """Resolve ``method: vault``'s ref through the caller's store."""
    if ref is None:  # pragma: no cover - `Method(required=("secret",))` guarantees one
        raise AdminCredentialError(
            f"target {target.name!r} authenticates from a vault and names no ref",
            at=_at(target, "auth", "secret"),
            hint="there is no default admin path; write `secret:` on the auth block",
        )
    if read_ref is None:
        # Not an operator's mistake: the file is right and a caller failed to
        # supply the store it had already authenticated. Worded so that whoever
        # reads it in a bug report can tell those apart at a glance.
        raise AdminCredentialError(
            f"target {target.name!r} authenticates from a vault, and no store was "
            f"available here to read {str(ref)!r}",
            at=_at(target, "auth", "secret"),
            hint="the file is fine -- this is a caller that supplied no reader",
        )
    return read_ref(ref)


# ------------------------------------------------------------------ helpers ---


def _auth(target: ExpandedTarget) -> AdminAuth | None:
    admin = target.target.admin
    return None if admin is None else admin.auth


def _at(target: ExpandedTarget, *parts: str) -> KeyPath:
    """Where inside a target's ``admin:`` block something was written.

    :func:`~sopuli.config.expansion.declared_at` points at the target -- or at
    the ``overrides:`` entry that patched its ``admin:`` -- and the rest of the
    path is appended, so the result is the line to edit rather than the block
    containing it. The same helper ``config/references.py`` keeps for its own
    admin checks; a shared one would have to live somewhere both can import, and
    two callers is not yet a module.
    """
    at = declared_at(target, "admin")
    for part in parts:
        at = at.key(part)
    return at


def _username(target: ExpandedTarget, *, env: Mapping[str, str]) -> str | None:
    """Who connects: §6's variable, then the file, then nothing.

    P3's layering applied to one field -- the environment is layer 3 and the
    file is layer 4, so a variable set for this execution context wins.

    **Not consulted under** ``external``, and that asymmetry is deliberate.
    §3a *refuses* a ``username:`` written beside a wallet, because a file that
    appears to name the connecting account while the wallet names another is
    worth stopping for. The variable is the same claim from a different place --
    but it is ambient, set once for a whole run, and refusing a run because one
    target of thirty-four uses a wallet would make the variable unusable in a
    mixed estate. So the file is an error and the variable is ignored: the
    strict reading where somebody wrote it about *this* target, the permissive
    one where they did not.
    """
    declared = target.target.admin.username if target.target.admin is not None else None
    return env.get(ADMIN_USER_ENV) or declared


def _no_source(target: ExpandedTarget) -> AdminCredentialError:
    """No ``admin.auth`` at all -- refused rather than guessed at.

    ``admin:`` is optional in the schema and ``auth:`` is optional inside it, so
    a target can reach here naming no source whatever. Falling back to §6's
    ``SOPULI_DB_ADMIN_PASSWORD`` when it happens to be set is the tempting
    reading of the variable table, and it is a guess: §6 calls that pair *the
    default for* ``method: env``, which is a statement about a declared method
    rather than about an absent one. A credential tool that authenticates from
    whatever variable it found lying in the environment, because the file said
    nothing, is doing the thing P2's bootstrap section exists to prevent.

    So it refuses, and the hint is the one line that fixes it. Refusing is also
    the reversible half: deciding later that a bare variable implies ``method:
    env`` only widens what works, while unpicking a silent fallback means
    breaking runs that had come to depend on it.
    """
    return AdminCredentialError(
        f"target {target.name!r} declares no admin credential, so there is no way "
        f"to authenticate to it",
        at=declared_at(target, "admin"),
        hint=(
            f"name one of {', '.join(sorted(ADMIN_METHODS))} under "
            f"`admin: {{ auth: … }}` -- `auth: {{ method: env }}` reads "
            f"${ADMIN_PASSWORD_ENV}"
        ),
    )

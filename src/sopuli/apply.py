"""What `creds apply` decides, before and after it touches a database (#259).

UC-1 §5 in one sentence: *take what the vault holds and make the database match
it*. Invariant 6 makes the direction one-way, so nothing here ever reads a
password out of a database and writes it to a store.

Pure, the same way :mod:`sopuli.check` and :mod:`sopuli.generate` are. Every
function is of values the caller already holds, so the whole decision table --
including the interesting half, which is *when not to act* -- is testable without
a container and without a vault.

**The vocabulary is `check`'s.** States, the inconclusive set and the failure
predicate are imported rather than restated: `check` and `apply` describe the
same estate, and two spellings of ``IN_SYNC`` would be one state that consumers
had to learn twice. What this module adds is the *sequence* -- which of those
states settles the question before any DDL is issued, and which of them permits a
promotion afterwards.

Four decisions here are this module's own:

**Nothing is issued that cannot be verified.** UC-1 §5 step 6 verifies with a
fresh login and §8 case 6 says a change that could not be confirmed is reported
loudly and never promoted. A locked account refuses every login, so its password
is not changed at all: the DDL would succeed, the verification would fail, and
the run would end holding a database whose password is in no vault stage. That
is the state invariant 7's ordering exists to prevent, and it is cheaper not to
enter it than to report it.

Since #300 there is one way past that, and it is not an exception to it: where
the policy declares §5's ``unlock_if_locked``, the run *removes* the reason the
change could not be confirmed and then asks the same question again. What may
never happen is the change going ahead with the lock still there --
:func:`settled_before_acting` is asked twice for that reason, and its default is
still to settle.

**The database is asked before it is changed.** Invariant 9 names `apply` as the
convergent verb -- the one that must report ``changed: false`` on a re-run -- and
with `--method hash` unavailable (#86, #90) the only way to know whether a change
is needed is a login attempt. So each account is verified first, under UC-1 §7's
lockout mitigations, and a password that already works is left alone. The run
costs one extra login per account and buys the invariant.

**A rollover window makes a `pass` mean less, and it still means "do not act".**
During one, both passwords authenticate (UC-1 §6.3), so a pre-check `pass`
cannot distinguish "the database has this password" from "it has the previous one
and accepts both". `check` reports that as ``ROLLOVER_ACTIVE`` and this module
does the same -- but it does not turn the ambiguity into a reason to issue DDL.
Re-applying would restart the window, report a change nobody asked for, and break
the invariant above in the default strategy's ordinary case.

**Promotion is per document and all-or-nothing.** The unit of work is the target
and the unit of the commit is the document, which is the one place `check`'s
per-target grouping and `generate`'s per-document grouping have to meet. A
document is promoted only when every (account, target) pair belonging to the
accounts *in that document* confirmed -- so a run touching two documents may
promote one and not the other.

**Every pair the configuration declares, not only the ones this run visited**
(#406). The pairs a selector excluded are found by ``cli._left_out`` from the
config and the document, and a document with any is held back rather than
promoted on the strength of a subset; :func:`summarise_document` is then only
asked about a run that covered everything the promotion needs.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sopuli.check import (
    ACCOUNT_MISSING,
    ERROR,
    EXPIRED,
    IN_SYNC,
    LOCKED,
    ROLLOVER_ACTIVE,
    UNVERIFIABLE,
    Outcome,
    is_failure,
    is_inconclusive,
)
from sopuli.config.model import AccountPolicy, Binding, Config
from sopuli.config.secret_refs import SecretRef
from sopuli.driver.protocol import (
    FAIL,
    PASS,
    UNAVAILABLE,
    AccountAttributes,
    UserState,
    VerifyResult,
)
from sopuli.driver.protocol import SKIPPED as VERIFY_SKIPPED
from sopuli.exit_codes import ExitCode
from sopuli.payload import (
    CURRENT,
    GENERATED,
    ORIGIN,
    PENDING,
    PREVIOUS,
    REMOVE,
    SUPPLIED,
    StageLayout,
    merge,
    stage_layout,
)
from sopuli.secrets import Secret

#: The state a rollback reports where a rotation is in flight. From the schema's
#: own enum, and the same word `creds finish-rollover` uses for the same fact:
#: the vault has staged a password the database has not been given.
PENDING_APPLY = "PENDING_APPLY"

#: ``VERIFY_SKIPPED`` above is the *verification result* of the same name, and
#: the alias is there because the two are different vocabularies sharing a word:
#: a verification result says an attempt was not made, and this state says an
#: account was not acted on. One name for both would make every reader check
#: which was meant.
#:
#: An account a client-side guardrail would not let this run touch
#: (``02-oracle-privileges.md`` §4, #286). The schema's own word, and
#: `creds finish-rollover` already uses it for the neighbouring idea: something
#: the tool declined to do here, as opposed to something it tried and could not.
#:
#: **It is not counted as a failure and not counted as a success** -- see
#: :func:`exit_code_for`. §4's rule is that a guardrail-refused account is
#: skipped *and the run does the rest of its job*, so the account leaves the run's
#: scope rather than failing in it. That is the same shape invariant 5 already
#: has for an account the config never declared: not eligible, rather than
#: attempted and lost.
SKIPPED = "SKIPPED"

#: The same guardrail refusal, on an account the operator **named**
#: (``02-oracle-privileges.md`` §4, #297). ``ERROR``'s spelling because it is
#: `check`'s word for "this did not happen and you need to know", and because
#: §4's whole argument for splitting the two cases is that one of them must not
#: report success:
#:
#: > An account the operator **named** -- `--account DBSNMP` -- refuses the run:
#: > they asked for something the tool will not do, and quietly skipping it would
#: > report success for work nobody did.
#:
#: So the difference between this and :data:`SKIPPED` is entirely in the exit
#: code, and that is the difference §4 asks for. Sharing `ERROR`'s spelling keeps
#: it out of the schema's state enum as a new value, and a consumer reading
#: `results[]` still sees the detail saying which guardrail refused.
REFUSED = ERROR

#: Re-exported so a caller holding this module does not need `check` as well for
#: the predicates a summary is built from. They are `check`'s, unchanged: the two
#: commands describe one estate and must count it the same way.
__all__ = [
    "CONFIRMED",
    "PENDING_APPLY",
    "SKIPPED",
    "DRAW_LIMIT",
    "PROMOTES",
    "SOURCES",
    "Promotable",
    "Redraw",
    "Source",
    "after_change",
    "already_applied",
    "attributes_for",
    "counts",
    "exit_code_for",
    "is_confirmed",
    "is_failure",
    "is_inconclusive",
    "may_redraw",
    "promotes",
    "promotion_patch",
    "settled_before_acting",
    "source_for",
    "summarise_document",
]

#: The states in which the database is known to hold what the vault does.
#:
#: ``ROLLOVER_ACTIVE`` is here and that is the decision worth arguing about. The
#: window means the *previous* password also authenticates (UC-1 §6.3), so the
#: login proved less than it usually does -- but what a promotion asserts is that
#: this database will serve the vault's value, and a rollover window does not put
#: that in doubt. Refusing to promote here would leave `pending` staged on every
#: run of the default strategy, which is the strategy §6.3 makes the default
#: precisely because it is the safe one.
CONFIRMED = frozenset({IN_SYNC, ROLLOVER_ACTIVE})


@dataclass(frozen=True)
class Source:
    """The password this run is applying, and which stage it came out of.

    ``stage`` is what decides whether there is anything to promote afterwards: a
    ``pending`` becomes ``current`` once every target confirms, while a run that
    read ``current`` is a repair and the vault already holds what it should.
    """

    #: :data:`~sopuli.payload.PENDING` or :data:`~sopuli.payload.CURRENT`.
    stage: str
    #: The value to apply. Wrapped, and never unwrapped in this module.
    value: Secret
    #: What ``current`` held when the document was read, or ``None`` if it held
    #: nothing. Carried because a promotion moves it into ``previous``, and the
    #: document is read once -- re-reading it at promotion time would be reading
    #: a document this run has since changed nothing in but somebody else may
    #: have.
    replaces: Secret | None = None
    #: Whether the document has a ``pending`` staged, whichever stage was read.
    #: Only a rollback acts on it (:func:`settled_before_acting`): rolling back
    #: underneath a rotation in flight leaves a `pending` that the next `apply`
    #: would move the estate *forward* with, silently undoing the undo.
    pending_staged: bool = False
    #: The document version the value was read at, where the caller knows it.
    #: Not read by anything in this module; it is what ``password.applied``
    #: names as the version it applied (#535), and ``None`` for a caller that
    #: built a source without a stored document behind it.
    version: int | None = None


#: The stages a run can be asked to apply from, in the order UC-1 §5 lists them.
#: ``previous`` is the rollback and is the reason the flag exists (§8).
SOURCES = (PENDING, CURRENT, PREVIOUS)

#: The stages whose use owes the vault a write once every target confirms.
#:
#: ``pending`` promotes forward -- ``current`` takes it and ``previous`` takes
#: what ``current`` held. ``previous`` does the same arithmetic in the other
#: direction: ``current`` takes the rolled-back value and ``previous`` takes the
#: one that was just removed from the database. One patch serves both, which is
#: not a coincidence -- a rollback *is* a promotion, of the other neighbour.
#:
#: ``current`` owes nothing: the vault already holds what the run put on the
#: database, which is what makes `--source current` a repair.
PROMOTES = (PENDING, PREVIOUS)


def promotes(stage: str) -> bool:
    """Whether a run reading ``stage`` owes a vault write. See :data:`PROMOTES`."""
    return stage in PROMOTES


def source_for(document: Any, ref: SecretRef, *, stage: str | None = None) -> Source | None:
    """What to apply for one account, from ``stage`` or from UC-1 §5's default.

    ``stage`` is ``None`` for the default the flag was added to override:
    ``pending`` if one is staged, else ``current``. Naming one instead reads
    exactly that stage and returns ``None`` where it holds nothing -- an explicit
    request does **not** fall back, because the fallback is the thing somebody
    passing the flag was trying to avoid, and silently applying `current` to an
    operator who asked for `previous` is a rollback that did not happen and said
    it did.

    ``replaces`` is what ``current`` held, for every stage that owes a write. For
    a rollback that is the password being taken *off* the database, which is
    exactly what ``previous`` should hold afterwards -- so the promotion patch
    needs no rollback-shaped variant.

    Pure and store-free: it reads the document a caller already has, through the
    same :class:`~sopuli.payload.StageLayout` every other stage-aware operation
    uses, so "where `pending` lives" has one answer in this codebase.
    """
    layout = stage_layout(ref)
    current = _string(layout.read(document, CURRENT))
    staged = _string(layout.read(document, PENDING))

    if stage is None:
        chosen, value = (PENDING, staged) if staged is not None else (CURRENT, current)
    else:
        chosen = stage
        value = {PENDING: staged, CURRENT: current}.get(
            stage, _string(layout.read(document, PREVIOUS))
        )
    if value is None:
        return None
    return Source(
        stage=chosen,
        value=value,
        replaces=current if promotes(chosen) else None,
        pending_staged=staged is not None,
    )


def attributes_for(config: Config, binding: Binding) -> AccountAttributes:
    """The non-password attributes declared for this account (UC-1 §5, #300).

    The same chain :func:`sopuli.generate.policy_for` reads -- the binding's own
    ``policy:``, then ``defaults.policy`` -- and **lenient where that one
    refuses**. A policy is required in order to *draw* a password, because §8 has
    no default length and inventing one is the thing it exists not to do; it is
    not required in order to *apply* one, and an estate that has never declared a
    policy applies passwords today. Refusing here would make an unrelated feature
    a new precondition on a command that already works.

    So an account with no policy, or one whose policy declares no ``account:``
    block, gets :class:`~sopuli.driver.protocol.AccountAttributes` with nothing
    set -- which is the same answer as declaring every attribute ``false``, and
    the same behaviour this command had before attributes existed.

    A name that names nothing is not handled here either, and does not need to be:
    :mod:`sopuli.config.references` refuses a dangling ``policy:`` when the file
    is read, which is the earlier and better moment.
    """
    name = binding.policy if binding.policy is not None else config.defaults.policy
    if name is None:
        return AccountAttributes()
    found = next((policy for policy in config.policies if policy.name == name), None)
    if found is None:
        return AccountAttributes()
    return _attributes(found.account)


def _attributes(policy: AccountPolicy) -> AccountAttributes:
    """One ``account:`` block as what the driver is asked to enforce.

    ``is True`` rather than a truth test, and the difference is the whole shape of
    :class:`~sopuli.config.model.AccountPolicy`: its fields are ``None`` when the
    file said nothing and ``False`` when the file said no. Both mean *do not*, and
    keeping them distinguishable in the config layer is what lets a later
    precedence question be asked at all.
    """
    return AccountAttributes(
        unlock=policy.unlock_if_locked is True,
        profile=policy.profile,
    )


def settled_before_acting(
    user: UserState | None,
    source: Source | None,
    *,
    requested: str | None = None,
    unlock: bool = False,
) -> Outcome | None:
    """The outcome for an account nothing should be issued against, or ``None``.

    Four cases, in this order, and the order is the same argument
    :func:`sopuli.check.decide` makes about status outranking the attempt: what
    the database says about the account is the *cause* of whatever a login would
    have seen.

    * **No source.** The vault holds no password for this account at the stage
      this run was to read. Reported as :data:`~sopuli.check.ERROR` rather than
      as `check`'s ``UNVERIFIABLE``, and the difference between the two commands
      is real: `check` reached the estate and could not compare, which is a
      survey with a gap in it, while `apply` cannot do the thing it was run to
      do. A mutating verb that exits 0 having converged nothing is the silent
      failure worth being loud about. ``requested`` is the stage the operator
      named, so the message can say *which* one is empty -- "no `previous` to
      roll back to" and "nothing staged at all" send somebody to different
      places.
    * **No account.** ``ACCOUNT_MISSING``, and it is not created: Q8 puts
      provisioning in its own use case, and invariant 5 makes the config a
      whitelist of what may be *touched* rather than a list of what should exist.
    * **A locked account, where nothing may unlock it.** ``LOCKED``, and no DDL.
      See the module docstring: the change would succeed and could never be
      confirmed, which is the one state the ordering in UC-1 §3 exists to keep a
      run out of. ``unlock`` is §5's opt-in attribute having been declared for
      this account (#300), and it is the *permission* rather than the act: the
      caller unlocks and asks again, so this function is what decides both
      whether the estate may be acted on and whether the unlock got it there. The
      default is off, because an account that was locked and is still locked when
      the question is asked again must settle rather than loop.
    * **A rollback with a rotation in flight.** ``PENDING_APPLY``. Rolling back
      while a `pending` is staged leaves it staged, and the next `apply` moves
      the estate forward with it -- undoing the undo, unattended. Last of the
      four, because it is a reason not to do something that was going to happen
      and the two above it are reasons it was never going to.

    **An expired password is deliberately not here.** ``ORA-28001`` is listed in
    §6.4 as resolvable *by* apply -- setting a password clears the expiry -- so an
    expired account is one this command fixes rather than one it declines. The
    state is only reported when something else stops the run.
    """
    if source is None:
        return Outcome(ERROR, _nothing_to_apply(requested))
    if user is None:
        return Outcome(
            ACCOUNT_MISSING,
            "the config declares this account; the database has no such user",
        )
    if user.locked and not unlock:
        return Outcome(
            LOCKED,
            f"account is {user.status.lower()}; the password was not changed, because a "
            f"locked account cannot confirm one -- declare `account: {{ unlock_if_locked: "
            f"true }}` on this account's policy to have `apply` unlock it first",
        )
    if source.stage == PREVIOUS and source.pending_staged:
        # A rollback underneath a rotation in flight. The `pending` would survive
        # this run, and the next `apply` would move the estate *forward* with it
        # -- silently undoing the undo, at whatever hour that next run happens.
        # `creds finish-rollover` refuses on the same fact for the same reason.
        #
        # **Last of the four**, and deliberately so: it is a reason not to do
        # something that was going to happen, and the two above it are reasons it
        # was never going to. Telling somebody to deal with a `pending` first,
        # about an account the database does not have, would be answering a
        # question they had not reached.
        return Outcome(
            PENDING_APPLY,
            "a password is staged for this account, so a rollback now would be "
            "undone by the next `sopuli creds apply` -- deal with the `pending` first",
        )
    return None


def already_applied(
    user: UserState, verification: VerifyResult, *, source: Source
) -> Outcome | None:
    """The outcome when the pre-flight login says no change is needed, or ``None``.

    ``None`` means *go ahead and apply*, and it covers three different reasons for
    saying so, which is why this returns an outcome rather than a boolean:

    * the password was **refused** -- the ordinary case, and what `check` would
      have called ``DRIFT``. No state is reported for it here, because the run is
      about to change the thing that made it drift and reporting the transient
      would put a state in the document that was true for a hundred milliseconds;
    * the attempt was **declined** by the lockout guard, or verification was
      **unavailable**. The run cannot tell whether a change is needed, and
      applying is the answer: it converges either way and costs the counter
      nothing, since ``ALTER USER`` is not a login. The post-change verification
      will be declined for the same reason and the account ends
      ``UNVERIFIABLE`` and unpromoted -- honest, safe, and re-runnable once the
      counter has been reset.

    A **pass** settles it. ``changed: false``, no DDL, and invariant 9's
    requirement on this verb met without a special case for it: the second run of
    a successful rotation reads ``current``, is accepted, and does nothing.

    Under an open rollover window the state is ``ROLLOVER_ACTIVE`` rather than
    ``IN_SYNC``, carrying `check`'s caveat verbatim -- the pass could have come
    from the previous password. It is still a reason not to act; see
    :data:`CONFIRMED`.
    """
    if verification.result != PASS:
        return None
    where = "the vault's `pending`" if source.stage == PENDING else "the vault's password"
    if user.rollover_active:
        return Outcome(
            ROLLOVER_ACTIVE,
            f"{where} is already accepted, and a rollover window is open: "
            f"the previous password still works too",
            verification,
        )
    return Outcome(IN_SYNC, f"{where} is already accepted; nothing to change", verification)


def after_change(user: UserState, verification: VerifyResult) -> Outcome:
    """The outcome once the password has been set and re-verified (UC-1 §5 step 6).

    The asymmetry with :func:`already_applied` is the point. Before the change, a
    refusal is expected and unremarkable; after it, a refusal means the tool
    issued a statement the server accepted and the account still will not
    authenticate with the value. §8 case 6 calls for that to be reported loudly
    and never promoted, so it is :data:`~sopuli.check.ERROR` rather than
    ``DRIFT`` -- ``DRIFT`` is a statement about an estate somebody should go and
    fix, and this is a statement about a run that did not work.

    A declined or unavailable verification is ``UNVERIFIABLE``: the database was
    changed and the tool cannot say the change took. Not a failure of the estate
    and not a success either, and the promotion gate reads it as neither
    (:data:`CONFIRMED`).

    A lock that appeared *during* the run is reported as ``LOCKED`` for the
    reason `check` gives -- it is the cause of what the login saw -- and an
    expired one as ``EXPIRED``, which after a password change means something
    else expired it.
    """
    if user.locked:
        return Outcome(
            LOCKED,
            f"the password was changed, and the account is now {user.status.lower()}: "
            f"the change could not be confirmed",
            verification,
        )
    if user.expired:
        return Outcome(
            EXPIRED,
            f"the password was changed, and the account is now {user.status.lower()}: "
            f"the change could not be confirmed",
            verification,
        )
    if verification.result == PASS:
        if user.rollover_active:
            return Outcome(
                ROLLOVER_ACTIVE,
                "changed and verified; a rollover window is open, so the previous "
                "password authenticates until it closes",
                verification,
            )
        return Outcome(IN_SYNC, "changed and verified by login", verification)
    if verification.result in (VERIFY_SKIPPED, UNAVAILABLE):
        return Outcome(
            UNVERIFIABLE,
            _one_line(verification.detail) or "the change could not be verified",
            verification,
        )
    if verification.result == FAIL:
        return Outcome(
            ERROR,
            f"the password was changed and then refused: "
            f"{_one_line(verification.detail) or 'rejected'}",
            verification,
        )
    # A result outside the schema's closed enum -- `check.decide` refuses one for
    # the same reason, and here it is worse: guessing which state an unknown
    # result means is how an unconfirmed change becomes a promotion.
    raise ValueError(f"not a verification result: {verification.result!r}")


# -------------------------------------------------------------- the redraw ---

#: How many passwords one account may be given in a single run (#312, #268).
#:
#: Three, and the number is a judgement about what a refusal *means* rather than
#: about cost. A server that has refused three independent draws from the same
#: policy is describing its own rules -- a verify function this policy cannot
#: satisfy, or a reuse history this account cannot get past -- and a fourth draw
#: does not learn anything the third did not. At that point the server's own
#: message is the useful output, which is what exhausting the budget produces.
#:
#: It counts **draws, not failures**: the value the run arrived with is the first
#: one, so three is the original plus two more.
DRAW_LIMIT = 3


@dataclass(frozen=True)
class Redraw:
    """Whether a refused password may be drawn again, and why not when it may not.

    A value rather than a bool, because every refusal here has to be *reported*.
    UC-1 §6.4's whole complaint about the old behaviour was a run that said
    "``ORA-28003``" and left the operator to work out what the tool had decided
    not to do about it -- and three of the four answers below are the tool
    declining to act, which is exactly the thing that has to be visible.
    """

    allowed: bool
    #: Why not, in the operator's terms. ``None`` when :attr:`allowed`.
    reason: str | None = None


def may_redraw(error: Any, origin: Any, *, drawn: int, limit: int = DRAW_LIMIT) -> Redraw:
    """Whether this account's password may be drawn again (#312, deciding #268).

    Pure, and deliberately knows nothing about Oracle. ``error`` is asked one
    vendor-neutral question -- :attr:`~sopuli.driver.protocol.DriverError.regenerate`,
    which the driver set from its own classification -- so a second backend
    answering the same question gets this logic unchanged.

    Four answers, in this order, because when more than one applies the first is
    the one closest to the cause:

    **The server did not refuse the password.** Anything else that went wrong --
    a lost connection, a privilege that was missing, a code nobody has
    classified -- is not evidence about the value, and drawing another one would
    change the vault's state on the strength of a guess. This is also where an
    unmapped code lands, by ``regenerate`` defaulting to ``False`` rather than by
    a rule of its own: of the two ways to be wrong about an unknown code, looping
    is the one that locks accounts.

    **The tool did not draw this password.** ``origin`` is what #311 staged
    beside the value. Only :data:`~sopuli.payload.GENERATED` may be replaced:
    ``supplied`` means an external system dictated it, and absent means a document
    written before the key existed, which is the same case without the evidence.
    Redrawing either would make the tool disagree with whoever owns the value,
    silently, at the moment they were least expecting it.

    **The budget is spent.** :data:`DRAW_LIMIT`, and what the caller reports is
    the server's own message rather than this one.

    Otherwise it may be redrawn.
    """
    if not getattr(error, "regenerate", False):
        return Redraw(False, "the server did not refuse the password")
    if origin != GENERATED:
        return Redraw(False, _unredrawable(origin))
    if drawn >= limit:
        return Redraw(False, f"{limit} passwords were refused")
    return Redraw(True)


def _unredrawable(origin: Any) -> str:
    """Why an ``origin`` that is not :data:`~sopuli.payload.GENERATED` blocks a redraw.

    Three cases and not two, because the operator's next move differs. *Supplied*
    sends them to whoever dictated the value; *absent* sends them to a document
    staged before #311 existed, which the next `creds generate` heals on its own;
    and a value this tool does not recognise sends them to the document itself,
    which something other than `generate` has written to.

    The unrecognised value is described and **never quoted**. It is a document
    field, and `store/credentials.py` holds the same line for the same reason --
    every message built from keys and never from values, because the obvious way
    to say "that is not one of mine" is to show what it was instead.
    """
    if origin == SUPPLIED:
        return "this run did not draw that password"
    if origin is None:
        return "there is no record of where that password came from"
    return "the record of where that password came from is not one this tool wrote"


# ------------------------------------------------------------- the promote ---


@dataclass(frozen=True)
class Promotable:
    """One account's half of a document's promotion.

    Assembled per account rather than per document because UC-1 §3's stamps are
    per account: a single account can be rotated inside a shared document, and a
    root-level ``rotated_at`` would describe some of the document and not the
    rest.
    """

    binding: Binding
    #: The value moving from ``pending`` to ``current``.
    value: Secret
    #: What ``current`` held, which becomes ``previous``. ``None`` where there
    #: was none -- the first rotation of a freshly seeded account, where there is
    #: nothing to roll back to and the key is simply not written.
    replaces: Secret | None
    #: The policy the value was drawn under, for the stamp of the same name.
    policy: str | None
    #: Which targets this run confirmed, for ``targets``.
    targets: tuple[str, ...]


def promotion_patch(entries: Sequence[Promotable], *, at: datetime, by: str) -> dict[str, Any]:
    """One merge patch promoting every account in ``entries`` (UC-1 §5, invariant 7).

    Five changes per account, and **one write**: ``current`` takes what
    ``pending`` held, ``previous`` takes what ``current`` held, ``pending`` and
    the ``origin`` describing it are removed, and the stamps are refreshed.
    :func:`sopuli.payload.merge` exists for exactly this -- five writes would be
    five versions, four of which describe a state that was never true, and any of
    which can be the one that fails.

    Every key is written through the account's own
    :class:`~sopuli.payload.StageLayout`, so siblings in a shared document are
    **absent** from the patch rather than rewritten with what was last read. That
    is the property `01-configuration.md` §7 requires and the reason a
    concurrent writer cannot lose a password to this run.

    No value is revealed. The patch carries :class:`~sopuli.secrets.Secret`
    objects to :func:`sopuli.store.credentials.apply_patch`, which holds the one
    permitted unwrapping on this path (invariant 2), and is safe to log until
    then.
    """
    patches: list[Mapping[str, Any]] = []
    stamp = at.isoformat().replace("+00:00", "Z")
    for entry in entries:
        layout = _layout(entry.binding)
        patches.append(layout.patch(CURRENT, entry.value))
        if entry.replaces is not None:
            patches.append(layout.patch(PREVIOUS, entry.replaces))
        patches.append(layout.patch(PENDING, REMOVE))
        # `origin` describes what `pending` held, so it is cleared with it (#311).
        # Leaving it behind would leave a document asserting the provenance of a
        # stage that no longer has a value, and the next reader of it would be
        # #312 deciding whether it may redraw. "Cleared" is RFC 7396's clearing
        # and not a root delete: promoting the last staged account empties the
        # container rather than removing the key, exactly as `pending` above has
        # always done. `tests/test_payload.py` pins that and says why it stays.
        patches.append(layout.patch(ORIGIN, REMOVE))
        patches.append(layout.patch("rotated_at", stamp))
        patches.append(layout.patch("rotated_by", by))
        if entry.policy is not None:
            patches.append(layout.patch("policy", entry.policy))
        if entry.targets:
            patches.append(layout.patch("targets", list(entry.targets)))
    return merge(*patches)


def summarise_document(states: Iterable[str]) -> bool:
    """Whether a document's accounts all confirmed, which is the promotion gate.

    All-or-nothing on purpose, and across every (account, target) pair the
    document's accounts produced. UC-1 §5 is explicit: some targets failing means
    ``pending`` stays and the run exits 4, because promoting would advertise a
    password that part of the estate does not have -- which is the first of the
    two orderings §3 rules out.

    An empty sequence is **not** a promotion. It means nothing about the document
    was attempted, and "no failures" is not the same fact as "every target
    confirmed".
    """
    found = list(states)
    return bool(found) and all(state in CONFIRMED for state in found)


# ------------------------------------------------------------- the reporting ---


def exit_code_for(states: Sequence[str], *, promoted: bool, promotable: bool) -> int:
    """The process exit code for a whole run of `apply` (UC-1 §5, P5).

    §5's three outcomes, asked in the order a scheduler cares about:

    * **everything confirmed, and whatever needed promoting was promoted** --
      exit 0;
    * **some of it worked** -- exit 4, P5's partial. This is the code that says
      the estate is now in a mixed state and `apply --repair` is the remedy, and
      it is distinct from exit 1 for that reason: 1 means nothing changed
      anywhere and re-running is free;
    * **none of it worked** -- exit 1.

    ``promotable`` says whether this run read a stage that owes the vault a
    write -- a ``pending`` or, for a rollback, a ``previous`` (:data:`PROMOTES`)
    -- and ``promoted`` whether every such document got one. Together they are what
    makes the difference between "the database is right and the vault agrees" and
    "the database is right and the vault still advertises the old password". The
    second is UC-1 §8 case 7 -- the highest-severity row in the table -- and it
    must not exit 0 just because every target confirmed.

    **:data:`SKIPPED` is not counted at all**, in either the numerator or the
    denominator (#286). A guardrail-refused account is not a target that failed;
    it is one this run was never going to act on, and §4's rule is explicitly that
    the run does the rest of its job. Counting it as unconfirmed would exit 4 --
    "some of it worked, run `apply --repair`" -- on a run where everything the
    tool was willing to do succeeded and re-running would skip the same account
    again, every night, forever. `creds finish-rollover` already takes this
    reading of the same word: its `SKIPPED` exits 0.

    A run whose accounts were *all* skipped therefore exits 0, which is the same
    answer an empty selection already gives. Nothing was eligible, and the table
    says so per account with the reason.
    """
    counted = [state for state in states if state != SKIPPED]
    if not counted:
        return int(ExitCode.SUCCESS)
    confirmed = sum(1 for state in counted if state in CONFIRMED)
    if confirmed == 0:
        return int(ExitCode.FAILURE)
    if confirmed < len(counted) or (promotable and not promoted):
        return int(ExitCode.PARTIAL)
    return int(ExitCode.SUCCESS)


def counts(states: Sequence[str]) -> dict[str, int]:
    """``summary.by_state``, omitting the states with none. `check`'s rule."""
    tally: dict[str, int] = {}
    for state in states:
        tally[state] = tally.get(state, 0) + 1
    return dict(sorted(tally.items()))


def is_confirmed(state: str) -> bool:
    """Whether this state permits a promotion. See :data:`CONFIRMED`."""
    return state in CONFIRMED


# ------------------------------------------------------------------ helpers ---


def _layout(binding: Binding) -> StageLayout:
    ref = binding.secret
    if ref is None:
        raise ValueError(f"cannot promote {binding.account!r}: the binding names no secret ref")
    return stage_layout(ref)


def _nothing_to_apply(requested: str | None) -> str:
    """Why there is nothing to apply, in words that name the operator's next step.

    Three different situations wear the same shape, and only one of them is
    "run generate". A rollback with no `previous` is bounded by design (Q3, #84)
    and there is nothing to run; an explicit `pending` that is not there means
    the staging step has not happened.
    """
    if requested == PREVIOUS:
        return (
            "the vault holds no `previous` for this account, so there is nothing to "
            "roll back to -- rollback is bounded to one generation (Q3)"
        )
    if requested == CURRENT:
        return "the vault holds no `current` for this account"
    if requested == PENDING:
        return "the vault holds no `pending` for this account -- run `sopuli creds generate` first"
    return (
        "the vault holds no password for this account, at either stage "
        "-- run `sopuli creds generate` first"
    )


def _string(value: Any) -> Secret | None:
    """A stored value as a :class:`~sopuli.secrets.Secret`, or ``None``.

    Anything that is not a string is ``None`` rather than an error, and the
    caller's :func:`settled_before_acting` reports it as "the vault holds no
    password". A ref that lands on a map has addressed the container rather than
    the account inside it, which :func:`sopuli.store.credentials.resolve` refuses
    by name on the read path -- this is the promotion side, where the document
    was read once and the shape has already been through that check.
    """
    if isinstance(value, Secret):
        return value
    if isinstance(value, str):
        return Secret(value)
    return None


def _one_line(detail: str | None) -> str | None:
    """The first line of a driver's message. :func:`sopuli.check._one_line`'s rule."""
    if detail is None:
        return None
    lines = detail.splitlines()
    return lines[0] if lines else None

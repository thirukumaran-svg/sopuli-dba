"""What `creds generate` writes, and how it is grouped into writes.

Stage a new password per the policy into the vault's ``pending`` slot. The first
credential mutation, and it changes nothing in a database -- which is what lets it
take the advisory lock at all: the lock lives in the vault (Q2), so a
database-side one could not have protected the write below.

**It connects to read, and that does not change the argument.** UC-1 §4 step 2
reads one constraint per selected target -- how long a password may be, in that
database's own character set -- because a policy written by somebody who never
saw the estate can otherwise stage a `pending` no target can hold. The lock's
case was never "this command opens no session"; it was that there is no *change*
here for a database-side lock to protect, and reading does not make one. The
connecting is :func:`sopuli.cli._constraints_for`; the merge is
:mod:`sopuli.constraints`; what arrives here is a
:class:`~sopuli.passwords.ByteLimit` or ``None``.

Pure, like :mod:`sopuli.check`. Drawing is :mod:`sopuli.passwords` and writing is
:mod:`sopuli.store.credentials`; what lives here is the arithmetic between them --
which policy applies to which account, and which accounts share a write.

Three things here are decisions rather than transcription:

**One document is one write, however many accounts land in it.** Q7 made one
secret per application the documented default, so generating for three accounts
of one application is *one* CAS write carrying three fields -- not three writes
producing three versions, two of which describe states that were never intended.
:func:`sopuli.payload.merge` exists for exactly this and says so: "two accounts
staged in one run both live under ``pending``, and a shallow update would file
the second and lose the first."

**A second run replaces ``pending`` and reports ``changed: true``**
(decision #254). That is UC-1 §4 as written, and it is **outside invariant 9
rather than an oversight**: the invariant governs *convergent* commands, and
drawing a fresh secret has no fixed point to converge on. `apply` converges the
database on the vault and `check` mutates nothing; those are the commands the
invariant is about.

UC-2's reset is outside the invariant for the same reason. The invariant is a
scope rule (H7), not a list of exemptions, and CLAUDE.md carries it.

**Each account is drawn separately, even when they share a document.** Sharing a
document is a storage layout, not a shared credential -- `acme_web_user` and
`acme_batch_user` authenticate as different principals and must not end up with
one password because they happened to be written together.

**One password is drawn once, however many targets it serves.** One account on
eleven PDBs with no target label in its ref is one password (§7). It has one
binding per target, and :func:`draw_once` gives every one of them the same
candidate. A draw per binding put eleven values into one merge patch, the last
one won, and the run announced eleven draws for one stored password.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from typing import Any

from sopuli.config.errors import ConfigError
from sopuli.config.model import Binding, Config, PasswordPolicy
from sopuli.config.references import dangling
from sopuli.config.secret_refs import SecretRef
from sopuli.config.sharing import STAGE_COLLISION_HINT, colliding_stages
from sopuli.lock.keys import LockKey, normalise_path
from sopuli.passwords import ByteLimit, PasswordPolicyError, Violation, check
from sopuli.passwords import generate as draw_password
from sopuli.payload import GENERATED, ORIGIN, PENDING, SUPPLIED, merge
from sopuli.secrets import Secret
from sopuli.store.credentials import staged_patch

#: What ``--promote`` reports (decision #257): the vault holds this password and
#: no database has been asked. A new value rather than a reused one: ``SKIPPED``
#: would not be true, and ``PENDING_APPLY`` would send `check` and `apply`
#: looking for a ``pending`` that does not exist.
#:
#: **Not the same claim as ``PENDING_APPLY`` with the stage swapped.** That state
#: says a rotation is in flight; this one says there is none, and the next thing
#: to run is `apply`, which will find the databases behind the vault and converge
#: them.
#:
#: **Here rather than in the view.** Every other member of the schema's
#: ``state`` enum is declared in the domain module of the verb that reports it
#: -- ``IN_SYNC`` in `check`, ``PENDING_APPLY`` in `apply`. The palette
#: (decision #395) maps every state in one place and cannot import a view
#: without a cycle: the output layer imports the domain, so a state living in
#: the output layer is a state nothing else can name.
VAULT_ONLY = "VAULT_ONLY"

__all__ = [
    "Candidate",
    "DocumentWrite",
    "DrawFunction",
    "PasswordKey",
    "VAULT_ONLY",
    "candidate_for",
    "draw_once",
    "group",
    "one_per_password",
    "password_key",
    "policy_for",
]


@dataclass(frozen=True)
class Candidate:
    """One account's new password, and how it was arrived at.

    ``value`` is a :class:`~sopuli.secrets.Secret` and stays one all the way to
    :func:`sopuli.store.credentials.apply_patch`, which holds the single
    permitted unwrapping on this path (invariant 2). Nothing here reveals it, so
    a ``Candidate`` is safe to log, repr and put in an error.
    """

    binding: Binding
    value: Secret
    #: The policy this was drawn against, or ``None`` where the file names none.
    policy: str | None
    #: ``True`` when the operator supplied it on stdin rather than the tool
    #: drawing one. Recorded because the audit event distinguishes them: a
    #: password an external system dictated has a different provenance from one
    #: this tool generated, whatever its strength.
    supplied: bool = False
    #: Policy violations that were **accepted** under ``--no-policy-check``.
    #: Empty for everything else, including a compliant supplied password. UC-1
    #: §4 requires the override to be recorded in the audit event, and recording
    #: it as "the flag was passed" would not say what it let through.
    accepted_violations: tuple[Violation, ...] = ()


@dataclass(frozen=True)
class DocumentWrite:
    """One document, one lock, one compare-and-set write.

    The unit `generate` actually performs. Several accounts sharing a document
    are one of these; an account with a document to itself is also one, and the
    two go down the same path so there is no "several accounts" branch that only
    the shared layout exercises.
    """

    key: LockKey
    candidates: tuple[Candidate, ...]

    def patch(self, *, stage: str = PENDING) -> dict[str, Any]:
        """The one merge patch this write sends.

        Built by merging each account's own single-field patch, so the property
        :func:`~sopuli.store.credentials.staged_patch` guarantees per account --
        every sibling **absent** rather than rewritten with what was last read --
        survives the combination. That is the assertion ``04-testing.md`` §4 calls
        the interesting one, and it is asserted on what the patch does not
        contain.

        **Two keys per account when staging**: the value, and
        :data:`~sopuli.payload.ORIGIN` beside it saying whether the tool drew it
        or an operator supplied it. They go in one patch because they describe
        one value -- a write that landed the password and not its origin would
        leave a staged password whose provenance is unknown, which is the state
        the key exists to remove.

        **Only when staging.** ``origin`` is a property of ``pending``, not of the
        credential, so a write that puts a value straight into ``current`` writes none:
        there is nothing staged for it to describe, and what applications are already
        holding is not a thing :func:`sopuli.apply.may_redraw` may redraw. Absent then
        reads as unknown, which is the same refusal by the same rule.
        """
        # Also here, for a write built without `group`, as `apply`'s redraw does.
        _refuse_two_values_for_one_password(self)
        patches: list[dict[str, Any]] = []
        for candidate in self.candidates:
            ref = _ref(candidate.binding)
            patches.append(staged_patch(ref, candidate.value, stage=stage))
            if stage == PENDING:
                patches.append(
                    staged_patch(ref, SUPPLIED if candidate.supplied else GENERATED, stage=ORIGIN)
                )
        return merge(*patches)

    @property
    def accounts(self) -> tuple[str, ...]:
        """Who this write touches, in binding order, each account once.

        Once, because an account on several targets with one shared password
        has a candidate per target and one field in the document.
        """
        return tuple(dict.fromkeys(candidate.binding.account for candidate in self.candidates))


@dataclass(frozen=True)
class PasswordKey:
    """One password: a place in one document.

    ``document`` is the :class:`~sopuli.lock.keys.LockKey` the write and the
    lock use, so "shares a password" cannot disagree with "shares a write".
    Two bindings with one key are one password whatever else differs.
    """

    document: LockKey
    field: str | None
    pointer: str | None


#: How a caller draws or validates one binding's password.
DrawFunction = Callable[[Binding], Candidate]


def password_key(binding: Binding) -> PasswordKey | None:
    """Where ``binding``'s password is stored.

    ``None`` where it names no ref or no store yet. :func:`group` refuses such a
    binding, so it never reaches a write.
    """
    ref = binding.secret
    if ref is None or binding.vault is None:
        return None
    document = LockKey(store=binding.vault, path=normalise_path(ref.path))
    return PasswordKey(document=document, field=ref.field, pointer=ref.pointer)


def draw_once(bindings: Iterable[Binding], draw: DrawFunction) -> list[Candidate]:
    """One candidate per binding, drawn once per password.

    The first binding of each password is drawn by ``draw``. Every later
    binding of the same password gets that candidate with its own binding, so
    each still has a result of its own and all of them name one value.

    The key is the password and the account. Two bindings of one password under
    two policies are a defect in the file, which the loader refuses (#830).
    Were one to get here, one value drawn against the first binding's policy is
    still better than two values for one field, where the last write wins.

    **Two different accounts are never given one value.** The loader refuses
    two accounts on one password where the file states both stores (#841).
    Where it cannot, because one store comes from a profile or
    ``SOPULI_VAULT``, each account is drawn its own value, and :func:`group`
    then refuses a write carrying two values for one password, before anything
    is written.
    """
    drawn: dict[tuple[PasswordKey, str], Candidate] = {}
    candidates: list[Candidate] = []
    for binding in bindings:
        key = password_key(binding)
        first = drawn.get((key, binding.account)) if key is not None else None
        if first is None:
            candidate = draw(binding)
            if key is not None:
                drawn[(key, binding.account)] = candidate
        else:
            candidate = replace(first, binding=binding)
        candidates.append(candidate)
    return candidates


def one_per_password(candidates: Iterable[Candidate]) -> list[Candidate]:
    """The first candidate of each password, for what is reported per draw.

    A ``password.generated`` event says a password was drawn, so a password
    shared by several targets gets one, not one per target.
    """
    seen: set[PasswordKey] = set()
    found: list[Candidate] = []
    for candidate in candidates:
        key = password_key(candidate.binding)
        if key is None or key not in seen:
            found.append(candidate)
        if key is not None:
            seen.add(key)
    return found


def _refuse_two_values_for_one_password(write: DocumentWrite) -> None:
    """Refuse a write that carries two different values for one password.

    The merge patch would keep the last value and lose the others without a
    word, which is the fault #830 found. Two causes reach it:

    * two accounts on one password, which the loader refuses only where the
      file states both stores (#841). That is a defect in the file, so it is a
      :class:`~sopuli.config.errors.ConfigError`, raised before anything is
      written;
    * one account drawn twice, by a draw site that skips :func:`draw_once`.
      That is a defect in the code, so it is a ``ValueError``.
    """
    values: dict[PasswordKey, Candidate] = {}
    for candidate in write.candidates:
        key = password_key(candidate.binding)
        if key is None:
            continue
        first = values.setdefault(key, candidate)
        if first.value is candidate.value:
            continue
        if first.binding.account != candidate.binding.account:
            raise ConfigError(
                f"{first.binding.account!r} and {candidate.binding.account!r} resolve to one "
                f"password in {write.key}: each account needs one place of its own in the "
                "document",
                hint=(
                    "the store for one of them came from a profile or SOPULI_VAULT, so loading "
                    "the file could not show this; give the refs distinct, non-nested fields or "
                    "pointers, such as path#FIELD/{account}"
                ),
            )
        raise ValueError(
            f"two different passwords for {candidate.binding.account!r} in "
            f"{write.key}: draw a shared password once (generate.draw_once)"
        )


def group(candidates: Iterable[Candidate]) -> tuple[DocumentWrite, ...]:
    """Collect candidates into one write per document, in binding order.

    Keyed on the store and the **normalised path** -- the same
    :class:`~sopuli.lock.keys.LockKey` the advisory lock uses, through the same
    normaliser -- so "shares a document", "shares a write" and "shares a lock"
    cannot give three different answers. :mod:`sopuli.config.sharing` groups the
    same way for the same reason.

    Order is the bindings' own, not sorted: the operator reads this beside the
    plan table, and a second ordering would make one set of accounts look like
    two. Lock *acquisition* is sorted separately by
    :func:`~sopuli.lock.keys.acquisition_order`, where the ordering is a deadlock
    property rather than a presentation one.

    A candidate whose binding has no ref or no store is refused rather than
    dropped. Both are caller errors by this point -- `binding_stores` completes
    the store and refuses what it cannot, and a binding with no ref should never
    have become a candidate -- and silently generating a password that lands
    nowhere is the failure mode worth being loud about.
    """
    grouped: dict[LockKey, list[Candidate]] = {}
    for candidate in candidates:
        binding = candidate.binding
        if binding.secret is None or binding.vault is None:
            raise ValueError(
                f"cannot stage {binding.account!r} in {binding.target!r}: "
                f"the binding names no {'secret ref' if binding.secret is None else 'store'}"
            )
        key = LockKey(store=binding.vault, path=normalise_path(binding.secret.path))
        grouped.setdefault(key, []).append(candidate)
    writes = tuple(
        DocumentWrite(key=key, candidates=tuple(found)) for key, found in grouped.items()
    )
    for write in writes:
        # Two values for one password first, as the loader orders its rules:
        # the stage collision is a symptom of it where staging is emulated.
        _refuse_two_values_for_one_password(write)
        _refuse_colliding_stages(write)
    return writes


def _refuse_colliding_stages(write: DocumentWrite) -> None:
    """Refuse a document where two accounts would stage into the same place.

    A ref like ``apps/acme/db#{account}`` renders to a *field per account* with no
    pointer below it, and :func:`~sopuli.payload.stage_layout` then puts the stage
    at the document root -- which is right for the one-account layout UC-1 §3
    describes (``{"password": ..., "pending": ..., "previous": ...}``) and wrong
    the moment a second account shares the document. Both would write ``pending``
    at the root, and the merge would keep whichever came last: one account's new
    password silently lost, and the other's applied to both.

    Q7's actual default is ``#FIELD/{account}`` -- a field holding an object, a
    pointer per account -- which addresses the stage per account and merges
    cleanly. That is the layout `01-configuration.md`'s worked example and the
    sharing fixtures use.

    **:mod:`sopuli.config.bindings` refuses this spelling at load time**, so a file
    spelled this way does not reach here. This guard stays for the case that one
    cannot cover: it fires only where the store is known, and a binding whose
    ``vault`` C15 completes later from a profile or ``SOPULI_VAULT`` has no backend
    while the file is being read -- so whether the rule applies is not knowable
    there. Those arrive here unchecked.

    Detection is :func:`~sopuli.config.sharing.colliding_stages`, the same
    function the load-time refusal calls, so the two cannot come to disagree
    about a pair. What differs is only the exception: this is a caller error at a
    write boundary and not a statement about any file, and the ``ValueError``
    lands as generic failure rather than as P5's exit 9.
    """
    for collision in colliding_stages(candidate.binding for candidate in write.candidates):
        raise ValueError(f"{collision.description} -- {STAGE_COLLISION_HINT}")


def policy_for(config: Config, binding: Binding) -> tuple[str, PasswordPolicy]:
    """The password policy that governs this account, and the name it goes by.

    The chain the file itself describes (§3): the binding's own ``policy:``, then
    ``defaults.policy``. The ``SOPULI_*`` and command-line layers above it belong
    to the precedence resolver rather than here, which is the same split
    :func:`sopuli.cli._policy_to_sample` and :mod:`sopuli.config.bindings` already
    make.

    A missing policy is refused rather than defaulted, and so is a name that
    names nothing -- both through the message every other dangling name in the
    file gets. §8 is explicit that a policy declaring no ``length`` is refused
    rather than given one the tool chose, and having no policy at all is the same
    argument one level up: there is no safe length to invent.
    """
    chosen = binding.policy if binding.policy is not None else config.defaults.policy
    if chosen is None:
        raise _no_policy(binding)
    dangling(
        chosen,
        {policy.name for policy in config.policies},
        noun="policy",
        section="policies",
    )
    found = next(policy for policy in config.policies if policy.name == chosen)
    return chosen, found.password


def _smallest(
    readings: Sequence[tuple[str, ByteLimit]],
) -> tuple[str | None, ByteLimit | None]:
    """The target with the tightest byte count and its limit, or ``(None, None)``.

    Ties keep the first reading, as :attr:`sopuli.constraints.Constraints.
    strictest_target` does -- so the target a refusal names is the one the
    constraint line names.
    """
    found = min(readings, key=lambda pair: pair[1].max_bytes, default=None)
    return (None, None) if found is None else found


def _every_violation(
    supplied: Secret, policy: PasswordPolicy, readings: Sequence[tuple[str, ByteLimit]]
) -> tuple[Violation, ...]:
    """Every way ``supplied`` fails the policy at *any* target, each reported once.

    With no readings this is one ordinary :func:`sopuli.passwords.check` -- the
    policy's own rules, and no byte rule to apply, which is the offline and
    unreachable case.

    "Once" is per distinct violation, and a byte violation names its target,
    so two targets that cannot hold the password report twice -- each
    with the target it came from -- while a policy rule that every target agrees
    about is still reported once.
    """
    if not readings:
        return check(supplied, policy, limit=None)

    seen: dict[Violation, None] = {}
    for target, limit in readings:
        for violation in check(supplied, policy, limit=limit, target=target):
            seen.setdefault(violation, None)
    return tuple(seen)


def candidate_for(
    binding: Binding,
    policy: PasswordPolicy,
    *,
    name: str,
    readings: Sequence[tuple[str, ByteLimit]] = (),
    supplied: Secret | None = None,
    enforce: bool = True,
) -> Candidate:
    """Draw a password for one account, or validate one that was supplied.

    **One predicate, both paths.** A generated candidate is drawn by rejection
    sampling against :func:`sopuli.passwords.check`, and a supplied one is put
    through the same function -- UC-1 §4 requires that, and it is what stops
    ``--from-stdin`` becoming a way to write a password the policy would have
    refused. A constructive generator or a second validator would encode the
    rules twice, and the second copy is the one that drifts.

    That one predicate already reads ``length:`` as a **minimum** rather than as
    an exact figure, which is §4's rule for a supplied password and needs nothing
    from this function: "a password an external system dictated is not weaker for
    being longer". :func:`~sopuli.passwords.generate` produces exactly ``length``
    because it is choosing, not because the rule differs.

    ``enforce=False`` is ``--no-policy-check``. It accepts the password **and
    records what it accepted**: the violations travel on the candidate to the
    audit event, because "the flag was passed" does not say what it let through.
    It has no effect on a generated password -- there is nothing to override when
    the tool drew the value itself, and a flag that silently changed the
    generator would be a different feature wearing this one's name.

    ``readings`` is every answered target's limit, paired with the target so a
    refusal can name it, and the two paths use it differently for a reason
    :mod:`sopuli.constraints` sets out: a **drawn** password is ASCII by §8, so only
    the smallest byte count can bind it, while a **supplied** one is whatever an
    external system dictated and has to satisfy every target it will be applied to.
    A password storable in one character set and not another is the deterministic
    failure that reading the limits moves earlier, and checking only the smallest
    limit would let exactly that one through.

    Checking a supplied password once per limit re-runs the policy half each
    time, which is deliberate: the alternative is a second entry point that
    validates only the byte rules, and the second copy of a rule is the one that
    drifts. Violations are unioned in first-seen order, so a message names each
    distinct problem once however many targets report it.
    """
    if supplied is None:
        target, limit = _smallest(readings)
        return Candidate(
            binding=binding,
            value=draw_password(policy, limit=limit, target=target),
            policy=name,
        )

    violations = _every_violation(supplied, policy, readings)
    if violations and enforce:
        raise _refused(binding, name, violations)
    return Candidate(
        binding=binding,
        value=supplied,
        policy=name,
        supplied=True,
        accepted_violations=violations,
    )


def _ref(binding: Binding) -> SecretRef:
    """The binding's ref, which :func:`group` has already proved is there."""
    if binding.secret is None:  # pragma: no cover - group() refuses this first
        raise ValueError(f"{binding.account!r} has no secret ref")
    return binding.secret


def _no_policy(binding: Binding) -> ConfigError:
    return ConfigError(
        f"no password policy governs {binding.account!r} in {binding.target!r}",
        hint=(
            "name one on the application entry's `policy:` or set `defaults.policy:` -- "
            "there is no built-in length for the tool to fall back on (§8)"
        ),
    )


def _refused(binding: Binding, name: str, violations: Sequence[Violation]) -> PasswordPolicyError:
    """Why a supplied password was not accepted.

    Counts and rule names only, never characters or positions -- which is
    :class:`~sopuli.passwords.Violation`'s own rule, and the reason its ``detail``
    is safe to put in a message at all. Naming the offending characters would put
    part of a credential into whatever reads this.
    """
    described = "; ".join(f"{one.rule} ({one.detail})" for one in violations)
    return PasswordPolicyError(
        f"the supplied password for {binding.account!r} violates policy {name!r}",
        hint=(
            f"{described} -- fix the password, or pass `--no-policy-check`, "
            f"which records in the audit event what it let through"
        ),
    )

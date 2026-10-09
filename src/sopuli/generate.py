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
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
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
    "VAULT_ONLY",
    "candidate_for",
    "group",
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
        """Who this write touches, in binding order."""
        return tuple(candidate.binding.account for candidate in self.candidates)


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

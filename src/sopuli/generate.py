"""What `creds generate` writes, and how it is grouped into writes (#254).

Stage a new password per the policy into the vault's ``pending`` slot. The first
credential mutation, and it never connects to a database -- which is what lets it
take the advisory lock at all: the lock lives in the vault (Q2, #83), so a
database-side one could not have protected the write below.

Pure, like :mod:`sopuli.check`. Drawing is :mod:`sopuli.passwords` and writing is
:mod:`sopuli.store.credentials`; what lives here is the arithmetic between them --
which policy applies to which account, and which accounts share a write.

Three things here are decisions rather than transcription:

**One document is one write, however many accounts land in it.** Q7 (#85) made
one secret per application the documented default, so generating for three
accounts of one application is *one* CAS write carrying three fields -- not
three writes producing three versions, two of which describe states that were
never intended. :func:`sopuli.payload.merge` exists for exactly this and says so:
"two accounts staged in one run both live under ``pending``, and a shallow update
would file the second and lose the first."

**A second run replaces ``pending`` and reports ``changed: true``** (#254). That
is UC-1 §4 as written, and it is an explicit exemption from invariant 9 rather
than an oversight: the invariant governs *convergent* commands, and drawing a
fresh secret has no fixed point to converge on. `apply` converges the database on
the vault and `check` mutates nothing; those are the commands the invariant is
about. CLAUDE.md carries the footnote.

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

__all__ = [
    "Candidate",
    "DocumentWrite",
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

        **Two keys per account when staging** (#311): the value, and
        :data:`~sopuli.payload.ORIGIN` beside it saying whether the tool drew it
        or an operator supplied it. They go in one patch because they describe
        one value -- a write that landed the password and not its origin would
        leave a staged password whose provenance is unknown, which is the state
        the key exists to remove.

        **Only when staging.** ``origin`` is a property of ``pending``, not of the
        credential, so a write that puts a value straight into ``current`` writes
        none: there is nothing staged for it to describe, and what applications
        are already holding is not a thing #312 may redraw. Absent then reads as
        unknown, which is the same refusal by the same rule.
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

    **The load-time refusal is #255 and is now in place**, so a file spelled this
    way no longer reaches here. This guard stays for the case that one cannot
    cover: it fires only where the store is known, and a binding whose ``vault``
    C15 (#118) completes later from a profile or ``SOPULI_VAULT`` has no backend
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


def candidate_for(
    binding: Binding,
    policy: PasswordPolicy,
    *,
    name: str,
    limit: ByteLimit | None = None,
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
    """
    if supplied is None:
        return Candidate(binding=binding, value=draw_password(policy, limit=limit), policy=name)

    violations = check(supplied, policy, limit=limit)
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

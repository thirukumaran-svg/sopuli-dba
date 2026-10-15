"""What UC-2 writes down about a reset, and where (H2).

A personal account's password is handed to a person, not synced from a master, so
UC-1's vault payload has no counterpart here. H2 split the three questions that
payload answered at once. This module is the second of the three answers: **who**
reset an account, by **which path**, and **where it was delivered**. The database
answers *when* (`DBA_USERS.PASSWORD_CHANGE_DATE`, `SYS.USER$.PTIME` behind the
grant), and nothing answers *what to roll back to*, because rollback is not a UC-2
operation -- the recovery for a lost personal password is another reset.

**The record never holds the password, in any representation** -- not the value,
not a hash, not a verifier. That is invariant 2, and it is also what makes the
record useful: it can be read by anyone entitled to know *that* a reset happened
without thereby being able to use it. :func:`assert_no_secret` enforces that
against the serialised document rather than against the writer's intentions, and
:class:`ResetRecord` has no field that could hold one.

**One record per (target, account)**, and the divergence from
:mod:`sopuli.lock.keys` is deliberate rather than an oversight. That module keys
UC-1's lock on (store, secret path) and explains at length why per-target and
per-account were both wrong *there*: every target in a run receives the same
value, so the mutated resource is the vault document. Here the mutated resource is
**the database account**. One person's account on `appdb-dev-alpha` and on
`appdb-qa-alpha` is two accounts with two passwords, which two DBAs may reset
independently and which must not contend; the same account on one target, reset
twice at once, is the collision that matters. Same reasoning, different resource,
different answer.

**The record's path is what the advisory lock keys on** (UC-2 §3.3). It is the one
location that exists on the seen path and the unseen one alike, and in both of the
unseen path's delivery forms -- a wrapping token writes no secret path, and
`manual` writes nothing at all -- so it is the only thing two concurrent resets
could ever collide on. Nothing else about the lock changes: :func:`record_lock_key`
returns an ordinary :class:`~sopuli.lock.keys.LockKey`, which
:func:`~sopuli.lock.manager.lock_path` puts under the same ``locks/`` prefix, under
the same CAS, with the same fencing token, visible to the same `lock status` and
breakable by the same `lock break`.

Nothing here reads a clock, a store or a database. A moment arrives as an
argument, which is what keeps the whole module tier 0 (`04-testing.md` §4).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sopuli.clock import to_rfc3339
from sopuli.config.model import ResetRecords
from sopuli.config.secret_refs import TRAVERSAL, normalise_path
from sopuli.lock.keys import LockKey
from sopuli.lock.record import Holder
from sopuli.secrets import Secret


@dataclass(frozen=True)
class Delivery:
    """How the password reached the person, and where it was put.

    ``method`` is a name to write down, deliberately **not** checked against a
    closed set here. Which methods exist is the `delivery:` block's question, and
    methods are added one at a time; a closed set in this module would be a second
    place to update each time one is added, and the one more likely to be forgotten.

    ``to`` is **optional, and its absence is meaningful** rather than missing
    data. A store path or a cubbyhole reference is a location; the seen path's
    destination is a person, reached by a route the tool did not carry, so
    `manual` records the method and omits ``to`` rather than inventing a value
    for stdout. What a reader is actually asking there is answered by
    :attr:`ResetRecord.seen`, which is why that field exists separately and why
    this key is optional for that reason and no other (UC-2 §3.1).
    """

    method: str
    to: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"method": self.method}
        if self.to is not None:
            data["to"] = self.to
        return data


@dataclass(frozen=True)
class ResetRecord:
    """One reset, journalled. Never the password it set.

    **There is no field a password could go in**, and that is the structural half
    of invariant 2 as it applies here -- the same arrangement the run schema uses
    to keep a `policy sample` from carrying a value. :func:`assert_no_secret` is
    the other half, for the document rather than the type.

    ``seen`` is the field worth writing down. A seen reset is a deliberate,
    time-limited exposure: a DBA held a working password for somebody else's
    account. Six months later the question asked of this record is not *when was
    this reset* -- the database answers that, and better (UC-2 §3.2) -- but
    *did a DBA hold a working password for this account, and which DBA*.

    ``by`` is :class:`~sopuli.lock.record.Holder`, the shape the lock record
    already uses, rather than a second spelling of the same fact. Both answer
    "which runner did this", and a reader who has learned one should not have to
    learn the other.
    """

    account: str
    target: str
    reset_at: datetime
    seen: bool
    expired: bool
    delivery: Delivery
    by: Holder | None = None
    correlation_id: str | None = None
    #: Whether the database audits the DBA's routes to acting as the person,
    #: as the run document's ``audited`` says it (UC-2 §1, H10): ``True``,
    #: ``False`` or ``"unknown"``. ``None`` on the seen path, which does not check.
    audited: bool | str | None = None
    #: Why, in the driver's words. Present exactly when ``audited`` is.
    audited_detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """The document to write.

        Every key is written, including the two that may be ``None``, except
        where absence is the meaning: :attr:`Delivery.to` is omitted rather than
        written null, per UC-2 §3.1. ``by`` and ``correlation_id`` are omitted
        the same way -- a record whose runner could not be described says so by
        having no ``by``, which is what :meth:`Holder.from_dict` already reads
        back as "nothing readable there". ``audited`` and ``audited_detail`` are
        omitted on the seen path, which does not check.
        """
        data: dict[str, Any] = {
            "account": self.account,
            "target": self.target,
            "reset_at": to_rfc3339(self.reset_at),
            "seen": self.seen,
            "expired": self.expired,
            "delivery": self.delivery.to_dict(),
        }
        if self.by is not None:
            data["by"] = self.by.to_dict()
        if self.correlation_id is not None:
            data["correlation_id"] = self.correlation_id
        if self.audited is not None:
            data["audited"] = self.audited
            data["audited_detail"] = self.audited_detail
        return data


def record_path(records: ResetRecords, *, target: str, account: str) -> str:
    """Where one (target, account)'s record lives under the configured prefix.

    Target before account, which is the order the estate is usually read in --
    `lock status` groups by store and path, and a listing of the prefix then
    groups a target's people together, which is the question an operator asks of
    a listing ("what happened on this database"). The other order would group one
    person across targets, which is a question `account list` answers from the
    configuration without reading this prefix at all.

    **Case is folded on the account and not on the target.** An Oracle account
    name is matched case-insensitively everywhere else in this codebase --
    `sopuli/config/selection.py` casefolds before comparing, so ``--account
    jdoe`` reaches a declared ``JDOE`` -- and a path that did not fold would let
    one account own two records that never find each other, which is two
    concurrent resets not colliding. A target name is a `targets:` key, matched
    exactly, and folding it would merge two targets an operator declared as
    distinct.

    **A name that is not a single path segment is refused here** rather than
    interpolated, because interpolating one is how two different (target,
    account) pairs end up sharing a record. Nothing validates a `targets:` key or
    an `accounts:` entry against a path grammar -- both are "a non-empty string"
    -- so a target called ``a/b`` with account ``jdoe`` and a target called ``a``
    with account ``b/jdoe`` would derive the same path. That is one journal
    describing two accounts, and one lock where there should be two, which is the
    exact failure this pair is keyed on to prevent. ``.`` and ``..`` are refused
    for decision #344's reason: under a prefix they walk out of it.

    :class:`ValueError` rather than a :class:`~sopuli.config.errors.ConfigError`,
    matching :func:`~sopuli.config.secret_refs.normalise_path`'s own boundary: no
    file is malformed. ``account reset-password`` derives every path at plan time
    and turns this into a refusal naming the target and the account
    (invariant 4).
    """
    for noun, value in (("target", target), ("account", account)):
        _reject_unusable_component(noun, value)
    return normalise_path(f"{records.prefix}/{target}/{account.casefold()}")


def _reject_unusable_component(noun: str, value: str) -> None:
    """One name, checked for being usable as exactly one path segment."""
    if not value or value != value.strip():
        raise ValueError(f"{noun} {value!r} cannot be a record path component: it is not a name")
    if "/" in value:
        raise ValueError(
            f"{noun} {value!r} cannot be a record path component: a `/` in it would "
            f"derive the same record path as a different target and account"
        )
    if value in TRAVERSAL:
        raise ValueError(
            f"{noun} {value!r} cannot be a record path component: a relative segment "
            f"resolves outside the prefix the record is written under"
        )


def record_lock_key(records: ResetRecords, *, target: str, account: str) -> LockKey:
    """The advisory lock a reset of this (target, account) is taken under.

    An ordinary :class:`~sopuli.lock.keys.LockKey`, which is the whole claim of UC-2
    §3.3: the key is the only new thing, and everything downstream of it -- the
    ``locks/`` prefix, the CAS, the fencing token, `lock break` -- is the machinery
    UC-1 already uses (Q2), unchanged.

    **`lock status` reaches them too.** That verb enumerates its estate from
    `bindings`, and no binding produces a record path, so read that way alone it
    would report an empty estate while a reset held a lock. It reaches these keys
    the only way an offline verb can -- by listing the declared `reset_records:`
    prefix -- because a predicate-declared account (H1) has no name until a database
    is asked.

    Keyed on the *record's* path rather than on the delivery target's, because
    the delivery target does not exist on every path: `manual` writes nothing,
    and a wrapping token writes no path either. A key that only existed on one
    delivery form would leave the other form's concurrent resets uncontended,
    which is the collision this lock is for.
    """
    return LockKey(store=records.vault, path=record_path(records, target=target, account=account))


#: Every key a record document may carry, and the only ones. The closed set is
#: half of what :func:`assert_no_secret` enforces -- see its note on why a value
#: comparison alone cannot be the whole of it.
RECORD_KEYS = frozenset(
    {
        "account",
        "target",
        "reset_at",
        "seen",
        "expired",
        "delivery",
        "by",
        "correlation_id",
        "audited",
        "audited_detail",
    }
)

#: What ``delivery`` may carry (UC-2 §3.1). ``to`` is optional; nothing else is
#: permitted, which is what keeps a provider's "reference" from becoming a place
#: to put a retrievable value.
DELIVERY_KEYS = frozenset({"method", "to"})


def assert_no_secret(document: Any, *, secret: Secret, token: Secret | None = None) -> None:
    """Refuse a record document that could carry the password, or fetch it.

    Invariant 2 held against the **serialised document**, which is where it has
    to be held. A type with no password field proves that no *writer in this
    build* puts one there; it proves nothing about a field added later, or about
    a delivery method that stuffs a value into ``delivery.to`` because the
    provider's reference happened to be one.

    **Two checks, because one of them cannot be done.** §3.1 says the record holds
    no password "in any representation -- not the value, not a hash, not a
    verifier", and no function can look at a string and decide whether it is a
    derivation of a password it was not given. So the rule is enforced by shape
    and by value, and neither half is the whole:

    * **the shape is closed.** A document may carry only :data:`RECORD_KEYS`, and
      ``delivery`` only :data:`DELIVERY_KEYS`. This is what a hash or a verifier
      would fail: there is no key to put one in, and adding one is refused here
      rather than noticed later. It is the structural guarantee made checkable,
      rather than resting on the dataclass having no such attribute today.
    * **the value is compared**, against the **whole** value rather than a
      substring, at every depth, in keys as well as values: a record has no field
      a password is a *part* of, so an occurrence anywhere is the failure, and
      checking keys costs nothing while catching a document built by inverting a
      mapping. This is what catches the password reaching a key that legitimately
      exists.

    **``token`` closes a hole the shape alone leaves.** The shape proves nothing
    about a delivery method that puts a secret into ``delivery.to`` because the
    provider's reference happens to be one, and `vault_wrapped` has two candidates
    for that field: the accessor, which names the hand-over and cannot perform it,
    and the **token**, which performs it. UC-2 §6.1 makes the second secret-bearing
    because the rule is about reach rather than value, so a record carrying it would
    be a long-lived, widely-readable object holding the thing whose TTL exists to
    keep it short-lived. Passing the token in makes writing one an
    :class:`AssertionError` rather than a matter of the caller having picked the
    right field.

    ``None`` where the method produced no token -- the seen path, and the
    identity-scoped path of TODO(#447) -- because there is then nothing to compare
    against and an absent argument says that better than a sentinel.

    What remains uncovered is a *derived* value written into one of the permitted
    string fields -- a hash of the password in ``delivery.to``. Saying so is better
    than implying a check that is not there: the closed shape is what makes it
    unreachable in practice, since ``to`` is a location and the writers of it are
    the delivery method's own non-secret references.

    **It takes the** :class:`~sopuli.secrets.Secret`, not the plaintext, and that
    is what keeps the check from being the leak: the comparison goes through the
    type's own ``__eq__``, so no caller has to reveal a password in order to
    prove the document does not carry one.

    :class:`AssertionError` rather than a store error or a refusal with an exit
    code, because reaching it is a **programming** error and not a configuration
    one: no config file can provoke it, and no operator can fix it. It is the
    tier-0 assertion UC-2 §8 asks for, wired into the write path so that it holds
    in a run and not only in a test.
    """
    _assert_closed(document, allowed=RECORD_KEYS, what="record")
    if isinstance(document, dict) and isinstance(document.get("delivery"), dict):
        _assert_closed(document["delivery"], allowed=DELIVERY_KEYS, what="record's `delivery`")

    for value in _walk(document):
        # Wrapped rather than revealed. `Secret.__eq__` compares two wrapped
        # values without producing either, so the one function whose job is to
        # look for a password does not become a tenth site in
        # `tests/test_reveal_sites.py` -- which would be an odd way to enforce
        # invariant 2.
        if not isinstance(value, str):
            continue
        if Secret(value) == secret:
            raise AssertionError(
                "reset record carries the password it set: invariant 2 permits plaintext "
                "out through the vault write, the driver call and `policy sample --reveal`, "
                "and a metadata record is none of the three (UC-2 §3.1)"
            )
        if token is not None and Secret(value) == token:
            raise AssertionError(
                "reset record carries the hand-over token: it holds no password and "
                "produces one, which UC-2 §6.1 treats the same way because the rule is "
                "about reach. `delivery.to` takes the accessor, which names the hand-over "
                "and cannot perform it (UC-2 §3.1)"
            )


def _assert_closed(document: Any, *, allowed: frozenset[str], what: str) -> None:
    """Refuse a key the record has no business carrying.

    The half of invariant 2 a value comparison cannot do. A password's *hash* is
    caught by having nowhere to live, which only works if "nowhere" is checked.
    """
    if not isinstance(document, dict):
        raise AssertionError(f"reset {what} is not an object: {type(document).__name__}")
    unknown = sorted(key for key in document if key not in allowed)
    if unknown:
        raise AssertionError(
            f"reset {what} carries {', '.join(repr(key) for key in unknown)}, which "
            f"UC-2 §3.1 does not declare -- a record holds what happened, and a key "
            f"nothing specified is where a password representation would go"
        )


def _walk(document: Any) -> list[Any]:
    """Every scalar in a JSON-shaped document, keys included."""
    if isinstance(document, dict):
        found: list[Any] = []
        for key, value in document.items():
            found.append(key)
            found.extend(_walk(value))
        return found
    if isinstance(document, (list, tuple)):
        return [item for value in document for item in _walk(value)]
    return [document]

"""What the estate says a password may be, before one is drawn (UC-1 §4 step 2).

`creds generate` draws against the *policy*. The policy is written by a human who
may never have seen the databases it will be applied to, so a run can stage a
password no target can hold -- and nobody finds out until `apply` connects, by
which time the vault has a `pending` that cannot be applied anywhere.

**This does not answer the server's refusals, and must not be described as doing
so.** A verify function is arbitrary PL/SQL that cannot be consulted (invariants
13 and 14) and a reuse history is hashed, so `ORA-28003` and `ORA-28007` cannot
be predicted before the statement is issued; `apply` handles those by redrawing
(decision #268). What is predictable is the *deterministic* pair -- a password
longer than the target's maximum, counted in bytes in the target's own character
set, and characters the target will not accept. Those hit every account in the
selection identically and one policy fix ends them, which is exactly why they
are the wrong answer to those refusals and are worth fixing on their own.

**There is no single strictest limit, and inventing one loses information.** A
:class:`~sopuli.passwords.ByteLimit` is a count *and* the character set it is
counted in, which makes "stricter" a partial order rather than a total one: 128
bytes of ``WE8MSWIN1252`` holds more characters than 128 of ``AL32UTF8`` and
holds *fewer distinct* ones, so neither limit contains the other. Collapsing the
two into one comparable number gets both halves wrong -- it refuses policies
that every target could satisfy, and it accepts supplied passwords that one
target deterministically cannot store.

So every reading is kept, and the two questions are asked separately:

* **drawing** uses the smallest byte count, and nothing else. §8's alphabets are
  ASCII, and an ASCII character is one byte in every encoding
  ``driver/oracle/limits.py`` maps, so the count is the only thing that can bind
  a password this tool generates.
* **validating a supplied password** uses *all* of them, because
  ``--from-stdin`` takes whatever an external system dictated. A character
  outside one target's set is a violation there whether or not that target had
  the smallest count, and it is exactly the "characters the target will not
  accept" half of what §4 step 2 is for.

**What is read and cannot bind anything is still worth reading.** §4 step 2 also
names a verify function, ``PASSWORD_REUSE_*`` and ``PASSWORD_VERSIONS``. None of
the three can gate a draw, for the reason above -- and the run reports them
anyway, in :class:`AccountConstraints`, because an operator staging a password
against a profile that will judge it with arbitrary PL/SQL should not have to
find that out from `apply`. Reporting is the whole of what they do here: nothing
branches on them, and the redraw in `apply` remains the answer to a refusal.

**Not reaching a target is not a failure.** §4 says so, and it is the difference
between this being useful and being a new way for `generate` to fail: staging a
password for an estate that is down is a thing operators do, and the policy's
declared limits are the documented fallback. What the run must not do is stay
quiet about which of the two happened, so :class:`Constraints` carries its own
provenance rather than leaving the caller to remember.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from sopuli.passwords import ByteLimit

__all__ = [
    "AccountConstraints",
    "Constraints",
    "NAMED",
    "NONE",
    "POLICY",
    "TARGETS",
    "UNKNOWN",
    "UNLIMITED",
    "UNREAD",
    "reuse_restricted",
    "survey",
]

#: The limit came from at least one target that answered.
TARGETS = "targets"

#: No target answered, so the policy's declared length governs. §4's fallback,
#: and the reason :attr:`Constraints.drawing_limit` may be ``None``.
POLICY = "policy"

#: Nothing was asked. ``--offline``, and a distinct value from :data:`POLICY`
#: because "we could not find out" and "we did not look" are answers a report
#: must never merge -- the same rule ``driver/oracle/privileges.py`` states about
#: an unreadable view, applied one layer up.
UNREAD = "unread"


#: The profile names a verify function, and this run cannot evaluate it.
NAMED = "named"

#: The profile names none, so nothing but the policy judges the password here.
NONE = "none"

#: Whether the profile names one could not be established. Measured: a **common**
#: profile read from inside a PDB answers the literal ``FROM ROOT``. Reported as
#: itself rather than as :data:`NONE`, which is §5's `--preflight` rule -- not
#: knowing is not a finding -- and the direction that cannot mislead: absent reads
#: as *nothing will judge this password*, which is the one thing this cannot say.
UNKNOWN = "unknown"

#: What Oracle spells for a password resource that restricts nothing. Compared
#: case-insensitively and never parsed as a number: the other values are counts
#: and days, and this module reports them rather than doing arithmetic on them.
UNLIMITED = "UNLIMITED"


@dataclass(frozen=True)
class AccountConstraints:
    """What an account's profile says about a password, beyond how long it may be.

    The three §4 step 2 names that a draw cannot be *bound* by, which is why they
    are here rather than in :attr:`Constraints.limits`: a verify function is
    arbitrary PL/SQL that cannot be consulted (invariants 13 and 14) and a reuse
    history is hashed, so neither can be predicted before the ``ALTER USER`` is
    issued. They are read so that the run can **say** they are there.

    ``versions`` is the account's, and the other fields are its *profile's* --
    which is why a report groups by profile and this object does not: two
    accounts on one profile share a verify function and may hold different
    verifiers.
    """

    #: The account, as the database spells it -- never the config file's string
    #: (``02-oracle-privileges.md`` §4).
    account: str
    profile: str | None = None
    #: The verify function's name, or ``None`` where the profile names none **or**
    #: the answer was not knowable. :attr:`verify_state` is what tells those two
    #: apart, and nothing should read this field without it.
    verify_function: str | None = None
    #: Whether the dictionary could answer at all. ``False`` for the ``FROM ROOT``
    #: reading, which is a common profile seen from inside a PDB.
    verify_function_known: bool = True
    #: ``PASSWORD_REUSE_MAX`` and ``PASSWORD_REUSE_TIME``, each as the database
    #: spells it -- a count, a number of days, or :data:`UNLIMITED`. Strings for
    #: :class:`~sopuli.driver.protocol.UserState`'s reason: a vendor word is not a
    #: number, and a report that parsed one would have to invent what to do with
    #: the other.
    reuse_max: str | None = None
    reuse_time: str | None = None
    #: ``PASSWORD_VERSIONS`` -- which verifiers the account currently holds, in the
    #: order the dictionary listed them (``11G 12C`` on 26ai).
    versions: tuple[str, ...] = ()

    @property
    def verify_state(self) -> str:
        """:data:`NAMED`, :data:`NONE` or :data:`UNKNOWN`."""
        if not self.verify_function_known:
            return UNKNOWN
        return NAMED if self.verify_function else NONE

    @property
    def reuse_enforced(self) -> bool:
        """Whether the profile restricts reuse at all.

        ``False`` only where both resources read :data:`UNLIMITED`, which is what
        Oracle's own ``DEFAULT`` profile carries. Anything else restricts
        something, and this deliberately does not work out *what*: the two
        resources interact, the interaction is documented rather than measured
        here, and the report names both values so a reader can apply the rule
        they know.
        """
        return reuse_restricted(self.reuse_max, self.reuse_time)


def reuse_restricted(reuse_max: str | None, reuse_time: str | None) -> bool:
    """Whether a profile's two ``PASSWORD_REUSE_*`` values restrict reuse at all.

    Public because two readings need the same answer: a `generate` report reads
    it off :class:`AccountConstraints`, and a rollback in `apply` off the
    :class:`~sopuli.driver.protocol.UserState` it already holds (decision #568).
    A value that was not read restricts nothing here -- this is a reporting
    test, and a warning built on a limit nobody read would be inventing its own
    subject.
    """
    return _restricts(reuse_max) or _restricts(reuse_time)


def _restricts(value: str | None) -> bool:
    return value is not None and value.upper() != UNLIMITED


@dataclass(frozen=True)
class Constraints:
    """What was learned about the estate, and from where.

    ``readings`` is every target that answered, paired with its limit, in the
    order they were tried. It is the whole answer; :attr:`drawing_limit` and
    :attr:`limits` are two views of it for the two questions a password gets
    asked, and keeping the pairs means a message can name the target as well as
    the number.

    ``unreachable`` names the targets that did not answer. It is not an error
    list: a run that reached three of four targets used the three, and the fourth
    is a caveat on how strict the answer is rather than a reason to stop.
    """

    readings: tuple[tuple[str, ByteLimit], ...] = ()
    source: str = UNREAD
    unreachable: tuple[str, ...] = ()
    #: One pair per account that answered, target first -- the same arrangement
    #: as ``readings`` and for the same reason: the target is not a property of
    #: the account, it is where the account was read, and a report names both.
    #:
    #: Not every account in the selection appears. An account the target has not
    #: got, or one whose profile could not be read, is simply absent: this is the
    #: reporting half of §4 step 2 and nothing here gates a draw, so an entry
    #: that could not be made is a thing not said rather than a finding.
    accounts: tuple[tuple[str, AccountConstraints], ...] = ()

    @property
    def read(self) -> tuple[str, ...]:
        """The targets that answered, named."""
        return tuple(target for target, _ in self.readings)

    @property
    def limits(self) -> tuple[ByteLimit, ...]:
        """Every limit that must be satisfied.

        What a *supplied* password is validated against -- all of them, because a
        password can be storable in one target's character set and not in
        another's, and that is independent of which target had the smallest
        count.
        """
        return tuple(limit for _, limit in self.readings)

    @property
    def drawing_limit(self) -> ByteLimit | None:
        """The limit a generated password is drawn against, or ``None``.

        The smallest byte count, and the encoding is not consulted: §8's
        alphabets are ASCII and an ASCII character is one byte in every encoding
        the driver maps, so nothing but the count can bind a password this tool
        draws. Ties keep the first reading, so the order targets were tried in
        decides an otherwise arbitrary choice -- nothing depends on which of two
        identical limits is used, but a run that picked a different one each time
        would be reporting noise as a fact.

        ``None`` where nothing was learned, which is what
        :func:`sopuli.generate.candidate_for` already means by no target limit:
        the policy's declared length governs, which is §4's fallback written as a
        default rather than as a branch.
        """
        if not self.readings:
            return None
        return min(self.limits, key=lambda limit: limit.max_bytes)

    @property
    def strictest_target(self) -> str | None:
        """The target whose count decided the draw, where more than one answered.

        ``None`` for a single reading, because there was nothing to be strictest
        *than* and naming a winner of a one-horse race invites a reader to think
        an estate was surveyed.
        """
        if len(self.readings) < 2:
            return None
        return min(self.readings, key=lambda pair: pair[1].max_bytes)[0]

    @property
    def partial(self) -> bool:
        """Some targets answered and some did not.

        Worth its own name because it is the case a reader is most likely to get
        wrong: the limits are real, they came from databases, and they are still
        not necessarily every limit in the estate.
        """
        return bool(self.readings) and bool(self.unreachable)


def survey(
    readings: Iterable[tuple[str, ByteLimit]],
    *,
    unreachable: Sequence[str] = (),
    accounts: Iterable[tuple[str, AccountConstraints]] = (),
) -> Constraints:
    """What the estate reported, with where it came from.

    ``readings`` is one pair per target that answered -- **one connection per
    target, never one per account**, which is what §4's "one representative"
    means for a command whose unit of work is an account and whose selection
    routinely puts several of them on one database.

    ``accounts`` is the reporting half, and it is separate from ``readings``
    because it answers nothing: an :class:`AccountConstraints` cannot bind a
    draw, and folding the two together would put a verify function next to a
    byte limit as though a run could act on both.

    Named for what it does rather than for what the caller wants out of it. An
    earlier ``strictest()`` promised a single answer and had to invent one; this
    collects, and :class:`Constraints` answers the two questions separately.
    """
    seen = tuple(readings)
    unreached = tuple(unreachable)
    read_accounts = tuple(accounts)

    if not seen:
        return Constraints(
            source=POLICY if unreached else UNREAD,
            unreachable=unreached,
            accounts=read_accounts,
        )
    return Constraints(
        readings=seen,
        source=TARGETS,
        unreachable=unreached,
        accounts=read_accounts,
    )

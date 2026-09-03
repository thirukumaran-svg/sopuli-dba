"""What the estate says a password may be, before one is drawn (#317, UC-1 §4 step 2).

`creds generate` draws against the *policy*. The policy is written by a human who
may never have seen the databases it will be applied to, so a run can stage a
password no target can hold -- and nobody finds out until `apply` connects, by
which time the vault has a `pending` that cannot be applied anywhere.

**This is not #268's problem and must not be described as its answer.** A verify
function is arbitrary PL/SQL that cannot be consulted (invariants 13 and 14) and
a reuse history is hashed, so `ORA-28003` and `ORA-28007` cannot be predicted
before the statement is issued; #312 handles those by redrawing. What is
predictable is the *deterministic* pair -- a password longer than the target's
maximum, counted in bytes in the target's own character set, and characters the
target will not accept. Those hit every account in the selection identically and
one policy fix ends them, which is exactly why they were the wrong answer to #268
and are worth fixing on their own.

**There is no single strictest limit, and inventing one loses information.** A
:class:`~sopuli.passwords.ByteLimit` is a count *and* the character set it is
counted in, which makes "stricter" a partial order rather than a total one: 128
bytes of ``WE8MSWIN1252`` holds more characters than 128 of ``AL32UTF8`` and
holds *fewer distinct* ones, so neither limit contains the other. An earlier
draft of this module collapsed the two into one comparable number and got both
halves wrong -- it refused policies that every target could satisfy, and it
accepted supplied passwords that one target deterministically could not store.

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
    "Constraints",
    "POLICY",
    "TARGETS",
    "UNREAD",
    "survey",
]

#: The limit came from at least one target that answered.
TARGETS = "targets"

#: No target answered, so the policy's declared length governs. §4's fallback,
#: and the reason :attr:`Constraints.limit` may be ``None``.
POLICY = "policy"

#: Nothing was asked. ``--offline``, and a distinct value from :data:`POLICY`
#: because "we could not find out" and "we did not look" are answers a report
#: must never merge -- the same rule ``driver/oracle/privileges.py`` states about
#: an unreadable view, applied one layer up.
UNREAD = "unread"


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
) -> Constraints:
    """What the estate reported, with where it came from.

    ``readings`` is one pair per target that answered -- **one connection per
    target, never one per account**, which is what §4's "one representative"
    means for a command whose unit of work is an account and whose selection
    routinely puts several of them on one database.

    Named for what it does rather than for what the caller wants out of it. An
    earlier ``strictest()`` promised a single answer and had to invent one; this
    collects, and :class:`Constraints` answers the two questions separately.
    """
    seen = tuple(readings)
    unreached = tuple(unreachable)

    if not seen:
        return Constraints(source=POLICY if unreached else UNREAD, unreachable=unreached)
    return Constraints(readings=seen, source=TARGETS, unreachable=unreached)

"""Handing a password to the person it belongs to (UC-2 §6, #444).

**A delivery method takes a value and a recipient**, and it is deliberately not
a property of resetting a password — UC-2 §6.7 says so, because UC-4's
onboarding hands a password to a new account through the same act. So this
package sits beside :mod:`sopuli.reset` rather than inside it, and nothing here
knows that a database was involved.

**What a backend returns is a receipt, not a location.** :class:`Receipt` carries
the method, what the person needs in order to fetch (:attr:`Receipt.token`), and
what an auditor needs in order to recognise the handover afterwards
(:attr:`Receipt.accessor`). Those are two different things on purpose: the first
produces a password in the wrong hands and the second does not, and keeping them
in separate fields is what lets the output layer emit one and never the other.

**The token is a `Secret`**, although it is not a password. UC-2 §6.1's rule is
about *reach* rather than about value — "the password, or anything that retrieves
it" — so a wrapping token is secret-bearing, and typing it as one means the
default for every log line, every ``repr`` and every JSON serialisation is
``***``. Emitting it takes an explicit ``reveal()``, which
``tests/test_reveal_sites.py`` then holds to a declared set. An ordinary ``str``
would have inverted that: safe only where somebody remembered.

**Nothing here opens a socket on import.** ADR-006 keeps vendor clients behind
extras, and a backend is handed the transport it needs by the caller that already
opened one (:mod:`sopuli.delivery.vault_wrapped`), so importing this package
costs an estate with no delivery configured nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from sopuli.secrets import Secret

__all__ = ["DeliveryBackend", "Handover", "Receipt"]


@dataclass(frozen=True)
class Handover:
    """The half of a :class:`Receipt` that may be written down.

    **A type rather than two arguments, and that is the point of it** (Copilot's
    review of #519). The run document's `handover` section exists when a delivery
    put the password somewhere, which is not the same as either of these fields
    being populated: a wrap that returned a token but no accessor and no usable
    TTL is a real hand-over with nothing to say about itself, and building the
    section out of "is either field set" reported it as the *seen* path -- the one
    case the section's presence is supposed to distinguish. Presence of this
    object is the signal; its fields are nullable inside it.

    **It carries no token and has no field for one**, which is what makes the
    output layer unable to receive one by mistake. :attr:`Receipt.token` stays on
    the receipt, in the delivery package, beside the docstring that argues for it.
    """

    accessor: str | None = None
    expires_at: datetime | None = None


@dataclass(frozen=True)
class Receipt:
    """What one delivery produced.

    ``token`` is what the person fetches with, and it is ``None`` for a method
    that hands over nothing to carry — a path the owner reads by their own
    identity (#447) has no bearer credential, and neither does mail that has
    already been sent. The field is optional for that reason and no other, the
    same way :attr:`sopuli.reset_record.Delivery.to` is.

    ``accessor`` names the handover without being able to use it. Vault's
    wrapping tokens have one natively; other methods will have their own
    equivalent, or none. It is what the run document carries, in
    ``results[].handover``, and the reason a document can describe a delivery at
    all without becoming the thing that leaks it. The reset record's
    :attr:`sopuli.reset_record.Delivery.to` is the same value, for the same
    reason: both are long-lived and widely readable, and the accessor is the one
    of Vault's two return values that survives being either.

    ``expires_at`` is when fetching stops working, where the method knows. It is
    reported rather than enforced: nothing in this tool polices a TTL the store
    is already policing, and a second clock would only disagree with the first.
    """

    method: str
    token: Secret | None = None
    accessor: str | None = None
    expires_at: datetime | None = None

    def reported(self) -> Handover:
        """What may be written down about this hand-over.

        The narrowing happens here rather than at each reader, so a caller cannot
        reach the token by taking the wrong attribute: what it gets back has no
        such attribute at all.
        """
        return Handover(accessor=self.accessor, expires_at=self.expires_at)


class DeliveryBackend(Protocol):
    """One way of getting a password to a person.

    One method, because a delivery is one act. A backend that needed a
    ``prepare`` and a ``commit`` would be describing a two-phase commit, and UC-2
    §6.4 is explicit that this is not one: the ordering there is a choice about
    which failure to prefer, and the recovery for either is the same reset run
    again.
    """

    def deliver(self, secret: Secret, *, account: str, target: str) -> Receipt:
        """Hand ``secret`` over, or raise.

        ``account`` and ``target`` are for the message a failure carries and for
        methods that address a person by name; a backend that needs neither is
        free to ignore both. Raising is how a delivery fails — the caller turns
        that into a per-target finding, and on the unseen path it turns into a
        run that never issued the DDL, which is why UC-2 §6.4 puts delivery
        first.
        """
        ...

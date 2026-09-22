"""Handing a password to the person it belongs to (UC-2 §6, #444).

**A delivery method takes a value and a recipient**, and it is deliberately not
a property of resetting a password — UC-2 §6.7 says so, because UC-4's
onboarding hands a password to a new account through the same act. So this
package sits beside :mod:`sopuli.reset` rather than inside it, and nothing here
knows that a database was involved.

**What a backend returns is a receipt, not a location.** :class:`Receipt` carries
the method, what the person needs in order to fetch (:attr:`Receipt.token`), and
what an auditor will need in order to recognise the handover afterwards
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

__all__ = ["DeliveryBackend", "Receipt"]


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
    equivalent, or none. It is what the run document **will** carry, and the
    reason a document can describe a delivery at all without becoming the thing
    that leaks it.

    **Nothing reads it yet**, and that is worth saying here rather than leaving a
    reader to grep for a consumer: #444's first part computes it and stops, and
    the second adds `results[].handover` and the reset record's `to`. A field with
    no consumer is normally the defect `SOPULI-W022` exists for -- it is here
    because the alternative was reading the accessor out of the response in part
    two and discarding the part of the receipt that already knows how.

    ``expires_at`` is when fetching stops working, where the method knows. It is
    reported rather than enforced: nothing in this tool polices a TTL the store
    is already policing, and a second clock would only disagree with the first.
    """

    method: str
    token: Secret | None = None
    accessor: str | None = None
    expires_at: datetime | None = None


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

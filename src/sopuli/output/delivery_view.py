"""What an unseen delivery tells the operator (UC-2 §6.6, #444).

**The wrapping token is emitted and the password is not**, and that difference is
the whole of this module. `reset_view.render_password` shows a DBA a working
password under five structural guards, because on the seen path the exposure *is*
the delivery. Here the password goes to Vault and to nobody else; what the DBA
holds is a retrieval credential they pass on out of band, because §6.1 bars it
from the notify channel and the tool carries no other.

**It is still secret-bearing.** §6.1's rule is about reach rather than value —
"the password, or anything that retrieves it" — so the token is a
:class:`~sopuli.secrets.Secret`, and this module holds the one ``reveal()`` that
emits one. `tests/test_reveal_sites.py` records it with that reason.

**Three rules, and the third is the one with no counterpart on the seen path.**

- **Never in the run document, and there is no property it could occupy.** The
  document is what gets captured, shipped to log aggregation and kept; a token in
  it outlives the TTL that is the method's whole guarantee. **What the document
  will carry instead is the *accessor***, which names the hand-over without being
  able to use it -- `Receipt.accessor` holds it and #444's second part writes it.
  Today the document records the method and nothing else about the hand-over, so
  this bullet is a statement about the token and not yet about the accessor.
- **No terminal is required**, which is where this departs from `manual`
  deliberately. A pipe is how a handover script works — `| mail`, `| chat-send` —
  and forbidding one would leave an estate with no way to deliver unattended
  except the path that shows a DBA a password. The cost is real and accepted: a
  redirect to a file outlives the token's TTL. What makes that a different trade
  from `manual`'s is the object: fifteen single-use minutes, whose one use is
  detectable, against a password good until somebody's first logon.
- **Under `--output json` it goes to stderr**, because stdout is carrying the
  document. The same split this verb already makes for the plan and the prompt
  (`cli.py`), and for the same reason: stdout carries the result, and in that mode
  the result is the document.
"""

from __future__ import annotations

from datetime import datetime

from sopuli.clock import to_rfc3339
from sopuli.delivery import Receipt
from sopuli.output.palette import Role, paint

#: What to say when the receipt knows no expiry -- see
#: :func:`sopuli.delivery.vault_wrapped._expiry` for when that happens. A phrase
#: rather than a blank, because a line reading "it expires at" and then nothing
#: reads as a bug in the tool rather than as a fact about the answer.
UNKNOWN_EXPIRY = "as soon as the store's TTL says"


def render_handover(receipt: Receipt, *, account: str, target: str) -> str | None:
    """The token, and what the operator has to do with it.

    ``None`` for a receipt with no token: a method that hands over nothing to
    carry (#447's path, mail that has been sent) leaves the operator nothing to
    pass on, and printing a heading over an empty value would suggest something
    had gone missing.

    **The target is named, and leaving it out was a real defect** (the code review
    of #518). `account reset-password` with no `--target` reaches every declared
    target and draws a *separate* password for each, so an operator saw N blocks
    reading "hand this to alice" with N different tokens and nothing saying which
    database each belonged to -- and sending the wrong one hands somebody a
    password that does not work on the host they were told about. The cubbyhole
    itself already carried `target` for exactly this reason
    (:mod:`sopuli.delivery.vault_wrapped`), so the person unwrapping was helped and
    the DBA holding both tokens was not.

    The seen path needs no such help, which is why the gap was easy to miss: its
    per-target prompt names the target before each password is shown. An unseen
    delivery has no prompt by design.

    **The instruction is part of the output rather than left to a runbook.** The
    single use is what makes interception detectable, and it only does that if
    whoever receives the token is the person who unwraps it -- so the line saying
    *do not unwrap it yourself* is doing work, not being polite.
    """
    if receipt.token is None:
        return None
    return "\n".join(
        [
            paint(f"hand this to {account} for {target}; it unwraps once:", Role.HEADING),
            "",
            # The one `reveal()` for a retrieval credential. Everything that makes
            # it allowable is in this module's docstring, and none of it is a
            # property of this function's good behaviour.
            f"    {receipt.token.reveal()}",
            "",
            f"It stops working {_expires(receipt.expires_at)}, and the first unwrap is the",
            "last. Do not unwrap it to check -- that spends the person's one read, and",
            "them finding it spent is the only warning either of you gets.",
        ]
    )


def _expires(when: datetime | None) -> str:
    """``at <timestamp>``, or an admission that the answer did not say."""
    if when is None:
        return UNKNOWN_EXPIRY
    return f"at {to_rfc3339(when)}"

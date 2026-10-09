"""Saying that a password is ready, without saying what it is (UC-2 §6.1).

The low-trust half of UC-2 §6. Every unseen delivery method reuses it —
`vault_wrapped` now, and `one_time_link` (TODO(#445)) and `onepassword_share`
(TODO(#446)) when they are built. They share it so that it is built once.

**What can be sent is decided in the config layer, not here.**
:mod:`sopuli.config.notify` refuses a template whose placeholders are not in a
closed set, at load, so this module renders a message that has already been proved
renderable. That ordering is the point: a refusal at send time arrives after a
password has been drawn, and there is nothing useful to do with it then.

**Nothing here opens a socket.** Rendering is pure, which is what lets §6.1's
rule be tested without a network and what keeps the base install socket-free
(ADR-006 rule 3). The `webhook` sender lives beside this, the way
:mod:`sopuli.delivery.vault_wrapped` lives beside :mod:`sopuli.delivery`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sopuli.clock import to_rfc3339
from sopuli.config.model import Notify

__all__ = ["PLACEHOLDERS", "Facts", "render"]


@dataclass(frozen=True)
class Facts:
    """What a notification may say, and therefore all a template can ask for.

    **:data:`PLACEHOLDERS` is derived from this type's fields**, which is what
    makes the closed set enforced rather than agreed. Two separate constants
    would need a run-time check that they match; deriving one from the other
    means they *cannot* disagree, which is the same move `Handover` makes -- let
    the type carry the guarantee rather than checking that somebody maintained
    it.

    **There is no field for the password, the token, or a link**, and that absence
    is §6.1 made structural: this is the only thing a renderer is handed, so the
    channel cannot carry what does not exist here. The rule says "the password, or
    anything that retrieves it" — a type with nowhere to put either is a stronger
    guarantee than a check that looks for them.
    """

    account: str
    target: str
    #: When the hand-over stops working, where the method knows. ``None`` for
    #: one that never expires -- `manual`, or the identity path (TODO(#447)) --
    #: and rendered as an empty string there, because a message reading "expires
    #: at None" is worse than one whose estate chose to mention an expiry that
    #: does not exist.
    expires_at: datetime | None = None

    def as_fields(self) -> dict[str, str]:
        """The substitutions, all of them strings.

        Formatted here rather than by the template, so an estate cannot ask for a
        format spec that raises at send time -- `{expires_at:%Y}` against ``None``
        would -- and so every channel renders a timestamp the same way the run
        document does.
        """
        return {
            "account": self.account,
            "target": self.target,
            "expires_at": to_rfc3339(self.expires_at) if self.expires_at is not None else "",
        }


#: Every placeholder a template may use, **derived from :class:`Facts`** so the two
#: cannot disagree. The closed set is the guard for UC-2 §6.1 -- see
#: :mod:`sopuli.config.notify`, which refuses everything outside it at load.
PLACEHOLDERS: tuple[str, ...] = tuple(Facts.__dataclass_fields__)


def render(notify: Notify, facts: Facts) -> str:
    """The message this notification would send.

    Pure, and separate from sending, for two reasons:
    a rendering that could only be exercised through a socket would be tested
    against a mock of the thing it is supposed to prove, and a message pasted into
    a document from anything but a real render is a prediction.

    :class:`AssertionError` if :meth:`Facts.as_fields` stops covering every field
    -- a programming error, not a configuration one. The *set* cannot drift, since
    it is derived from the type; what a fourth field still needs is a line in
    ``as_fields``, and this is what says so rather than rendering a hole.
    """
    fields = facts.as_fields()
    assert set(fields) == set(PLACEHOLDERS), (
        f"`as_fields` does not cover every field: {sorted(set(fields) ^ set(PLACEHOLDERS))}"
    )
    webhook = notify.webhook
    if webhook is None:  # pragma: no cover -- the builder fills it for every method
        raise AssertionError(f"notify method {notify.method!r} has no settings to render from")
    return webhook.template.format(**fields)

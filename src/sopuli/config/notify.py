"""The `delivery.notify:` block: saying a password is ready (UC-2 §6.1).

UC-2 §6.1 is the one binding rule of the whole delivery section:

    The channel that notifies may be low-trust. The channel that carries the
    secret may not. "Your new password is ready" may go anywhere; the password,
    or anything that retrieves it, may not.

**This module is where the second half is enforced**: the template can never
reference the password itself, and that is enforced, not documented. It is
enforced *here*, in the config layer, because the alternative is finding out at
send time, by which point a password has been drawn and the run has something
to lose.

**The enforcement is the closed set, not a list of forbidden words**, and the
difference is the whole reason this file is worth reading. A blocklist of
`password`, `wrap_token`, `item_link` would fail open on `{wrapping_token}`, on
`{pw}`, and on whatever the next method's credential gets called. So
:data:`PLACEHOLDERS` is closed and every other name is refused — and
:data:`NAMED_SECRETS` exists only to give a *better message* for the names
somebody would actually reach for. It adds no safety, and saying so keeps anybody
from later treating it as the guard and widening the allowed set to compensate.

**The tool does not author the message.** What is true of a hand-over differs by
path — a wrapping token is waiting in a vault, a `manual` password is with a DBA —
so a sentence the tool wrote would be wrong on one of them. The estate writes it,
which also means `notify:` needs no rule about which delivery methods it applies
to: all of them, with the estate's own words.
"""

from __future__ import annotations

from string import Formatter
from typing import Any

from sopuli.config.auth import read_material
from sopuli.config.errors import ConfigError, KeyPath
from sopuli.config.fields import choice, mapping, reject_unknown_keys, required_string
from sopuli.config.model import Notify, WebhookNotify
from sopuli.extras import install_command
from sopuli.notify import PLACEHOLDERS
from sopuli.notify.registry import NOTIFIERS

#: The methods this block may select. **One, and deliberately not padded out.**
#: `delivery.method` lists all six of UC-2 §6.2's values even where the code is
#: not written, because that section *defines* the set and an enum shaped by what
#: is built would be a contract shaped by project bookkeeping. Nothing defines
#: a set of notify channels: §6.3 shows `webhook` and no other. Inventing two
#: values to make the enum look finished would publish a contract nobody has
#: decided.
WEBHOOK = "webhook"

NOTIFY_METHODS = (WEBHOOK,)

#: The methods this build can send with, not only parse. Sending opens a socket,
#: so a method's client is an install extra (ADR-006).
IMPLEMENTED: tuple[str, ...] = (WEBHOOK,)

#: The keys the block itself takes.
NOTIFY_KEYS = ("method", WEBHOOK)

#: `webhook:`'s own keys. Both required: a channel with no URL cannot post, and a
#: channel with no template has nothing to say, so neither is a default worth
#: guessing at.
WEBHOOK_KEYS = ("url", "template")

#: Every placeholder a template may use, and the closed set is the guard.
#:
#: **Imported rather than declared**, from :class:`sopuli.notify.Facts`'s own
#: fields: the renderer's type is what a message can possibly say, so deriving the
#: refusal from it means the config layer cannot refuse something the renderer
#: would have filled, or accept something it could not. Two constants would have
#: needed an assertion that somebody kept them in step.
#:
#: All three are facts an estate's own audit log would hold anyway: **who** the
#: account is, **where** it lives, and **when** the hand-over stops working. None
#: retrieves anything, which is §6.1's test -- the rule is about reach rather than
#: about value.
#:
#: ``expires_at`` is worth having rather than minimal-by-reflex: "fetch this
#: within fifteen minutes" is the difference between a notification that helps and
#: one that makes somebody ask a DBA what the hurry is. It is empty for a method
#: with no expiry, which is a fact about the method rather than a missing value.

#: Names that get a message about §6.1 instead of a message about spelling.
#:
#: **This is not the guard.** Every name outside :data:`PLACEHOLDERS` is refused
#: whether or not it appears here, and a reader who mistook this for the
#: enforcement would be one widening away from a hole. What it buys is that an
#: operator who wrote `{wrap_token}` -- a reasonable thing to want -- is told
#: *why* the tool will not do it, rather than being told the word is misspelled.
NAMED_SECRETS = (
    "password",
    "secret",
    "token",
    "wrap_token",
    "wrapping_token",
    "item_link",
    "link",
    "credential",
)


def build_notify(raw: Any, *, at: KeyPath) -> Notify:
    """Normalise `delivery.notify:`.

    Called whichever delivery method is selected, which is the opposite of a
    method's own sub-block (`sopuli/config/delivery.py`): an unselected method's
    settings are never read because nothing consults them, and a notification is
    a property of the delivery as a whole.
    """
    block = mapping(raw, at=at)
    method = (
        choice(block["method"], allowed=NOTIFY_METHODS, at=at.key("method"), noun="notify method")
        if "method" in block
        else WEBHOOK
    )
    reject_unknown_keys(block, allowed=NOTIFY_KEYS, at=at)
    if method not in block:
        raise ConfigError(
            f"notify method {method!r} is selected and has no `{method}:` block",
            at=at.key(method),
            hint=(
                "a channel needs somewhere to post and something to say; write the block, "
                "or drop `notify:` if nothing should be sent"
            ),
        )
    return Notify(method=method, webhook=_build_webhook(block[WEBHOOK], at=at.key(WEBHOOK)))


def _build_webhook(raw: Any, *, at: KeyPath) -> WebhookNotify:
    """`webhook:`'s URL and message."""
    block = mapping(raw, at=at)
    reject_unknown_keys(block, allowed=WEBHOOK_KEYS, at=at)
    if "url" not in block:
        raise ConfigError(
            "`webhook` needs a `url`",
            at=at.key("url"),
            hint=(
                "and it is named rather than written: `{ env: SOPULI_NOTIFY_WEBHOOK }` or "
                "`{ file: /path }` (C9). A chat webhook URL carries its own credential, so "
                "a literal one here is a credential in a file people commit"
            ),
        )
    url = read_material(
        block["url"],
        at=at.key("url"),
        noun="a webhook URL",
        example="SOPULI_NOTIFY_WEBHOOK",
    )
    template = required_string(block, "template", at=at)
    check_template(template, at=at.key("template"))
    return WebhookNotify(url=url, template=template)


def check_template(template: str, *, at: KeyPath) -> None:
    """Refuse a template that cannot render, or that must not (§6.1).

    Two refusals out of one walk, because they are one condition read two ways: a
    name outside :data:`PLACEHOLDERS` cannot be filled, and *some* of those names
    cannot be filled for a reason worth saying out loud.

    ``{{`` and ``}}`` are literal braces, which is :class:`string.Formatter`'s own
    convention and is why the walk uses it rather than a regex. Without that an
    estate whose message contains a brace would meet a refusal about a placeholder
    it did not write.
    """
    for _, field, spec, conversion in Formatter().parse(template):
        if field is None:
            continue
        # **Not `field.strip()`, and not a discarded spec.** `str.format` does
        # neither: `{ account }` looks up the key ``" account "`` and raises
        # `KeyError`, and `{expires_at:%Y}` applies ``%Y`` to a string and raises
        # `ValueError`. A walk that accepted either would let `render()` raise --
        # which happens after the password has changed, and is the one place UC-2
        # §6 has no answer for.
        #
        # Refused rather than normalised. Trimming the name would accept a template
        # this validator and `str.format` read differently, and the estate wrote the
        # file, so the file is what should say what it means.
        if spec:
            raise ConfigError(
                f"a notify template may not give {{{field}}} a format spec",
                at=at,
                hint=(
                    f"`{{{field}:{spec}}}` would be applied to a string and raise when the "
                    "message is rendered -- which is after the password has changed. Every "
                    "substitution is already formatted the way the run document formats it, "
                    f"so write `{{{field}}}`"
                ),
            )
        if conversion:
            raise ConfigError(
                f"a notify template may not give {{{field}}} a conversion",
                at=at,
                hint=(
                    f"`{{{field}!{conversion}}}` converts a value that is already a string. "
                    f"Write `{{{field}}}`"
                ),
            )
        name = field
        if name != name.strip():
            raise ConfigError(
                f"a notify template may not pad a placeholder with spaces: {{{field}}}",
                at=at,
                hint=(
                    f"`str.format` looks up the name exactly as written, spaces included, so "
                    f"`{{{field}}}` would raise when the message is rendered -- which is "
                    f"after the password has changed. Write `{{{name.strip()}}}`"
                ),
            )
        if name in PLACEHOLDERS:
            continue
        if name.casefold() in NAMED_SECRETS:
            raise ConfigError(
                f"a notify template may not reference {{{name}}}",
                at=at,
                hint=(
                    "UC-2 6.1: the channel that notifies may be low-trust and the channel "
                    "that carries the secret may not -- and that covers the password *or "
                    "anything that retrieves it*, because the rule is about reach rather "
                    f"than value. Say that a password is ready and let the person fetch it: "
                    f"{_allowed()}"
                ),
            )
        raise ConfigError(
            f"unknown placeholder {{{name}}} in the notify template",
            at=at,
            hint=(
                f"{_allowed()}. An unknown name is refused rather than left empty, because a "
                "message with a hole in it is one somebody has to go and diagnose. Write "
                "`{{` for a literal brace"
            ),
        )


def unserviceable(notify: Notify | None) -> str | None:
    """Why a configured channel cannot send, or ``None`` when it could.

    E4's shape, and the same argument `sopuli/config/delivery.py`'s twin makes: a
    block that validates clean reads as a channel that will send, and finding out
    otherwise once a password has changed is the failure that costs something.

    **Says what cannot send, not what will happen.** A wording such as
    "so nothing will be sent when a password is delivered" would imply a password
    *would* be delivered, which is false where the missing client is a plan-time
    refusal. What happens is the caller's to say, and `sopuli/config/loading.py`
    says it in the hint.

    **Two conditions, and only the second survives a full install.** A method this
    build has no code for is one answer; a method whose *client* is not installed is
    the other, and it is E4's own case -- the file is valid, the install is
    incomplete, and `pip` is the remedy. Asked without importing anything
    (:attr:`sopuli.notify.registry.Notifier.available`), because a validator that
    had to load a client in order to report it missing could not report it at all.
    """
    if notify is None:
        return None
    if notify.method not in IMPLEMENTED:
        return (
            f"`delivery.notify.method: {notify.method}` is configured and is not implemented "
            f"in this build, so nothing can send through it"
        )
    notifier = NOTIFIERS.get(notify.method)
    if notifier is not None and not notifier.available and notifier.extra is not None:
        return (
            f"`delivery.notify.method: {notify.method}` is configured and its client is not "
            f"installed, so nothing can send through it "
            f"({install_command(notifier.extra)})"
        )
    return None


def _allowed() -> str:
    """The placeholders a message may use, for a hint to list."""
    return "available: " + ", ".join(f"`{{{name}}}`" for name in PLACEHOLDERS)

"""The `delivery:` block: how a personal account's new password reaches a person.

UC-2 §6 specifies it; this reads and validates it. The two live apart for
`01-configuration.md`'s standing reason — the use case decides, the reference
documents what is *built*, and this is the layer that makes the second true.

**One key selects, and the rest describe.** `method` names one of six values, and
the sub-block with the same name carries that method's own settings. Both halves
are checked here and only the first is *understood* here: which keys a
`vault_wrapped:` block may hold is #444's, a `one_time_link:` block's is #445's,
and so on. This module refuses a method nobody implements and a method whose
sub-block is missing, which is the part that is common to all six.

**Why the sub-block must exist at all**, rather than defaulting: every method
needs something. A wrapping token needs a TTL, a link needs a backend and a base
URL, `manual` needs `force_expire: true` (#439). A block that could be omitted
would make "delivery is configured" mean "a word was typed", and the failure would
arrive when a password had already been drawn.

**Nothing here opens a socket or knows how to deliver anything.** ADR-006 keeps
vendor clients behind extras and the base install free of them, so a config layer
that imported a delivery backend to validate its settings would undo that for
every run of `config validate`.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.fields import choice, mapping, reject_unknown_keys
from sopuli.config.model import Delivery

#: The methods UC-2 §6.2 defines, in the order that section lists them. **The
#: whole set, not the subset with issues**: `smtp_encrypted` has no issue of its
#: own and is here anyway, because an enum that listed only what somebody had
#: written a ticket for would be a contract shaped by project bookkeeping.
#:
#: Five are *unseen* — the tool puts the value somewhere only the person can get
#: it. `manual` is the one *seen* method, and the only one that shows a working
#: password to somebody who is not its owner (`CLAUDE.md` invariant 2's fourth
#: exception, #439).
DELIVERY_METHODS = (
    "vault_wrapped",
    "vault_path",
    "one_time_link",
    "onepassword_share",
    "manual",
    "smtp_encrypted",
)

#: The default, and §6.2 says why it is this one rather than the strongest-sounding
#: one: it works against a stock Vault. Every other unseen method needs
#: infrastructure the tool does not create, and a default an estate could not use
#: would fall back to `manual` — the path that shows a DBA a live password.
DEFAULT_METHOD = "vault_wrapped"

#: The seen path. Named because two rules key on it and neither should re-spell it.
MANUAL = "manual"

#: Keys the block itself takes, beside one sub-block per method. `notify` nests
#: here rather than sitting beside `delivery:` (§6.3): it is a property of a
#: delivery rather than of a run, and an estate delivering two ways would need two
#: of them.
DELIVERY_KEYS = ("method", "notify", *DELIVERY_METHODS)


def build_delivery(document: dict[str, Any]) -> Delivery | None:
    """Normalise `delivery:`, or ``None`` where the section is absent.

    ``None`` rather than a :class:`Delivery` carrying :data:`DEFAULT_METHOD`, and
    the distinction matters for the same reason `reset_records:`' does (#468): an
    estate that configured no delivery has not silently chosen one. A reset with
    nowhere to deliver is a refusal for the verb to make when it exists, and a
    default materialised here would make it impossible to tell that estate from
    one that asked for `vault_wrapped` by name.
    """
    if "delivery" not in document:
        return None

    at = ROOT.key("delivery")
    block = mapping(document["delivery"], at=at)

    # The method is resolved **before** unknown keys are rejected, and the order
    # is the message rather than a detail. A file saying `method: carrier_pigeon`
    # usually has a `carrier_pigeon:` block under it, which is an unknown *key* as
    # well as an unknown method -- and reporting the key would answer a question
    # the operator did not ask while burying the one they did.
    method = (
        choice(
            block["method"], allowed=DELIVERY_METHODS, at=at.key("method"), noun="delivery method"
        )
        if "method" in block
        else DEFAULT_METHOD
    )
    reject_unknown_keys(block, allowed=DELIVERY_KEYS, at=at)
    _require_sub_block(block, method, at=at)
    _check_shape(block, method, at=at)

    return Delivery(method=method)


def _require_sub_block(block: dict[str, Any], method: str, *, at: KeyPath) -> None:
    """The selected method must have brought its own settings.

    Refused rather than defaulted, and the message names the method as well as
    the key: an operator who wrote `method: one_time_link` and no `one_time_link:`
    block has typed half a configuration, and the half they typed is the half
    that reads as done.

    **A sub-block for a method that is not selected is left alone.** Writing
    `vault_wrapped:` settings beside `method: manual` is how somebody keeps a
    configuration they are switching between, and refusing it would make the file
    harder to edit without making any run safer -- nothing reads an unselected
    block. That is the opposite of §1's rule for the inline application keys,
    where a leftover `secret_template:` *is* refused, and the difference is real:
    there the stale key silently governs, and here it silently does nothing.
    """
    if method in block:
        return
    raise ConfigError(
        f"delivery method {method!r} is selected and has no `{method}:` block",
        at=at.key(method),
        hint=(
            "every method needs settings of its own -- a wrapping token needs a ttl, "
            "a link needs a backend; write the block, or select a different method"
        ),
    )


def _check_shape(block: dict[str, Any], method: str, *, at: KeyPath) -> None:
    """Every present method block, and `notify:`, checked for shape only.

    **Validated and not retained**, which is #440's boundary: the check that a
    method brought settings is common to all six and belongs here, while which
    keys it takes is its own issue. :class:`~sopuli.config.model.Delivery` says
    why nothing carries the content forward.

    **Every block that is written, not only the selected one** (Copilot's review
    of #499). The published schema types all six properties as objects, so
    ``vault_wrapped: 15m`` beside ``method: manual`` was refused by the schema and
    accepted here -- which inverts the relationship §9b documents. That section's
    whole claim is that the schema is "the fast, local, incomplete check" and the
    tool is the complete one, so a file the tool accepts and the schema refuses is
    the one direction that must not happen.

    **Three different things, and only one of them widened.** A sub-block for a
    method that is *not* selected is still left alone in the senses that matter:
    its presence is not refused, and its keys are not judged. What is checked now
    is that it is an object at all, which is a claim about the file's grammar
    rather than about the method's settings -- and an operator who typed
    ``vault_wrapped: 15m`` meant ``ttl:`` and wants to be told.

    The consequence worth stating: until each method's issue lands, a typo *inside*
    a sub-block is accepted. That is why :func:`unserviceable` warns -- a file that
    validates clean must not be read as a file that would deliver.

    `notify:`'s keys are #442's, and the rule that governs it is UC-2 §6.1's
    rather than this module's: the channel that notifies may be low-trust and the
    channel that carries the secret may not, so a template referencing a wrapping
    token or a one-time link is refused rather than rendered. That check needs the
    template grammar, which arrives with the channel.
    """
    for name in DELIVERY_METHODS:
        if name in block:
            mapping(block[name], at=at.key(name))
    if "notify" in block:
        mapping(block["notify"], at=at.key("notify"))


def unserviceable(delivery: Delivery | None) -> str | None:
    """Why the configured method cannot deliver yet, or ``None`` when it could.

    **No method is implemented**, which is the true state of this build and has to
    be said out loud. #440 builds the block; #441 and #444-#447 build the methods,
    and until one of them lands a file naming `method: vault_wrapped` is a file
    that parses and cannot hand anybody a password.

    A **warning rather than a refusal**, following E4/E5's shape for a configured
    backend this build cannot serve (ADR-006): the file is valid, the install is
    incomplete, and what that is worth depends on the question asked. `config
    validate` says so and exits 0; the verb that tries to deliver will fail.

    It exists because the alternative is worse than an unhelpful message. A
    `delivery:` block that validates silently reads as delivery being configured,
    and the operator would find out otherwise at the moment a password had already
    been drawn -- which is exactly the reading `docs/local-testing.md` calls the
    failure of an inventory that omits things.
    """
    if delivery is None:
        return None
    return (
        f"`delivery.method: {delivery.method}` is configured and no delivery method is "
        f"implemented in this build, so nothing can hand a password over yet"
    )

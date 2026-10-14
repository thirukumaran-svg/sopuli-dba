"""`notify.method: webhook` — posting "a password is waiting".

The low-trust channel, and the only one there is. What it may say was decided at
load (:mod:`sopuli.config.notify`) and rendered without a socket
(:mod:`sopuli.notify`); what is here is the POST and nothing else, which is why
this module is small and the two above it are not.

**`httpx` is imported at module scope here**, unlike
:mod:`sopuli.delivery.vault_wrapped`, and the difference is not inconsistency: this
module is named in :data:`sopuli.notify.registry.NOTIFIERS`, so ADR-006 rule 1's
"inside its backend module" applies to it literally and
`tests/store/test_install_shape.py` exempts it the way it exempts a store backend.
The delivery backend is not in any registry, so it has to import inside its
functions instead.

**A failure here never fails the run**, and the caller is what enforces that — see
`cli.py`'s `SOPULI-W026`. The reasoning is UC-2 §3.4's, one object over: by the time
anything is posted the password has changed and the person can fetch it, so a run
that failed over an unsent notification would report a false negative about the part
that mattered. What is lost is that somebody has to be told another way, which is
exactly what a warning is for.

**The body is `{"text": ...}`**, which is what Slack-shaped and Mattermost-shaped
incoming webhooks accept and what most others tolerate. Making it configurable is a
second template with a second set of rules about what may appear in it, and §6.1
would have to be enforced twice; if an estate needs another shape, that is an issue
with a named service in it rather than a key.
"""

from __future__ import annotations

import time

import httpx

from sopuli.output.debug import logger
from sopuli.secrets import Secret
from sopuli.store.protocol import StoreError

#: How long to wait. Short on purpose: a notification is the least important
#: thing a reset does, and this runs after the database has confirmed -- so a
#: slow chat service must not hold a run open. UC-2 §3.3's lock is still held
#: while this runs, so a hung request would also be a lock nobody else can take.
TIMEOUT_S = 10

LOG = logger("webhook")

#: The key an incoming webhook reads. See this module's docstring for why it is not
#: configurable.
BODY_KEY = "text"


def send(url: Secret, message: str) -> None:
    """Post ``message`` to ``url``, or raise.

    ``url`` is a :class:`~sopuli.secrets.Secret` because a chat incoming-webhook
    URL embeds its own credential -- that is C9's reason for the config key being a
    MaterialRef, carried through to the value. It is revealed here and nowhere else,
    and `tests/test_reveal_sites.py` records the site -- **as a credential on the
    wire, not as a sixth numbered exception to invariant 2.** That invariant
    enumerates the paths a *password* may take; material the tool presents to a
    service it is calling is a separate class the list has always held, beside the
    vault login and the store transport's token, for the reason that a credential
    which never reached the wire would authenticate nothing.

    **The message is not a secret and is not typed as one.** It cannot be: it was
    rendered from :class:`~sopuli.notify.Facts`, which has no field a password or a
    token could occupy, and the placeholder set it came from is closed. Wrapping it
    in a `Secret` would suggest a check that had happened somewhere else.

    Raises :class:`~sopuli.store.protocol.StoreError` on anything that goes wrong,
    which is the shape the caller already handles -- and the URL never appears in
    the message, because an exception carrying a chat webhook's token would put it
    wherever the exception goes.
    """
    address = url.reveal()
    # The host only: the path and the query of a chat webhook URL are its token.
    host = httpx.URL(address).host or "an address with no host"
    started = time.monotonic()
    try:
        response = httpx.post(address, json={BODY_KEY: message}, timeout=TIMEOUT_S)
    except httpx.HTTPError as error:
        LOG.debug("POST to %s: %s in %.3fs", host, type(error).__name__, time.monotonic() - started)
        # `type(error).__name__` rather than `str(error)`: httpx puts the URL in
        # the message of several of its errors, and the URL is the credential.
        raise StoreError(
            # Phrased as a *cause* rather than as a sentence, because
            # `SOPULI-W026` already says what happened and appends this: running it
            # showed "the notification could not be sent ... : the notification
            # could not be sent: ConnectError".
            f"the webhook could not be reached: {type(error).__name__}",
            hint=(
                "the webhook URL is not repeated here, because it carries its own "
                "credential. Check the value behind `delivery.notify.webhook.url`"
            ),
        ) from error
    LOG.debug("POST to %s: %s in %.3fs", host, response.status_code, time.monotonic() - started)
    if not 200 <= response.status_code < 300:
        raise StoreError(
            f"the webhook refused it: HTTP {response.status_code}",
            hint=(
                "a 4xx usually means the webhook has been revoked or the body shape is "
                "not what the service accepts; the password was delivered either way"
            ),
        )

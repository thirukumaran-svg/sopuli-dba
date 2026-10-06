"""`delivery.notify:` — the low-trust channel, and what it may not carry (#442).

Tier 0, and that is the point rather than a convenience. UC-2 §6.1's rule is the
one binding rule of the delivery section, #442 asked for it "enforced, not
documented", and enforcing it in the config layer is what makes it testable
without a socket — and what makes it arrive *before* a password has been drawn
rather than after.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.notify import (
    NAMED_SECRETS,
    NOTIFY_METHODS,
    build_notify,
    unserviceable,
)
from sopuli.notify import PLACEHOLDERS

AT = ROOT.key("delivery").key("notify")

URL: dict[str, Any] = {"env": "SOPULI_NOTIFY_WEBHOOK"}
MESSAGE = "{account} on {target} has a new password waiting"


def built(**webhook: Any) -> Any:
    settings: dict[str, Any] = {"url": URL, "template": MESSAGE}
    settings.update(webhook)
    return build_notify({"method": "webhook", "webhook": settings}, at=AT)


def refused(**webhook: Any) -> ConfigError:
    with pytest.raises(ConfigError) as raised:
        built(**webhook)
    return raised.value


# ------------------------------------------------------------- the grammar ---


def test_the_url_is_named_rather_than_written() -> None:
    """C9, and here it is doing real work rather than being applied uniformly: a
    chat incoming-webhook URL embeds its own credential, so a literal one is a
    credential in a file people commit."""
    section = built()

    assert section.webhook is not None
    assert section.webhook.url.kind == "env"
    assert section.webhook.url.location == "SOPULI_NOTIFY_WEBHOOK"


def test_a_literal_url_is_refused_as_material_rather_than_as_a_type() -> None:
    """`read_material`'s own message, which says the thing worth saying: material
    is named here, not written. "Must be a mapping" would read as a complaint
    about YAML rather than about a credential in a repository."""
    error = refused(url="https://chat.example.com/hooks/T00/B00/XXXX")

    assert "named, not written" in str(error)


def test_the_method_defaults_to_the_only_one_there_is() -> None:
    assert build_notify({"webhook": {"url": URL, "template": MESSAGE}}, at=AT).method == "webhook"


def test_a_selected_method_with_no_block_is_refused() -> None:
    with pytest.raises(ConfigError, match="has no `webhook:` block"):
        build_notify({"method": "webhook"}, at=AT)


@pytest.mark.parametrize("missing", ["url", "template"])
def test_both_keys_are_required(missing: str) -> None:
    """Neither is a default worth guessing at: a channel with no URL cannot post,
    and one with no template has nothing to say."""
    settings = {"url": URL, "template": MESSAGE}
    del settings[missing]

    with pytest.raises(ConfigError):
        build_notify({"method": "webhook", "webhook": settings}, at=AT)


def test_the_enum_holds_only_what_is_decided() -> None:
    """The opposite call from `DELIVERY_METHODS`, and the difference is real.
    UC-2 §6.2 *defines* six delivery methods, so listing only the ones with
    tickets would be a contract shaped by project bookkeeping. Nothing defines a
    set of notify channels -- §6.3 shows one and #442 sends `smtp` and `chat` to
    their own issues -- so inventing two values would publish a contract nobody
    has decided."""
    assert NOTIFY_METHODS == ("webhook",)


# ------------------------------------------------------------ §6.1's rule ---


@pytest.mark.parametrize("name", NAMED_SECRETS)
def test_a_template_naming_a_secret_is_refused_with_the_reason(name: str) -> None:
    """The half #442 asked to be "enforced, not documented" -- and refused at
    *load*, because a refusal at send time arrives after a password has been
    drawn."""
    error = refused(template=f"your password is {{{name}}}")

    assert f"may not reference {{{name}}}" in str(error)
    assert "6.1" in str(error.hint)
    assert "reach rather than value" in str(error.hint)


def test_an_unknown_placeholder_is_refused_rather_than_left_empty() -> None:
    """#442's own words. A message with a hole in it is one somebody has to go and
    diagnose, and the hole appears in front of the person being notified."""
    error = refused(template="hello {nobody}")

    assert "unknown placeholder {nobody}" in str(error)
    assert "{account}" in str(error.hint)


def test_the_guard_is_the_closed_set_and_not_the_list_of_names() -> None:
    """**The test that matters most in this file.** A blocklist would fail open on
    the next credential's name, so the enforcement has to be that everything
    outside `PLACEHOLDERS` is refused -- with `NAMED_SECRETS` only improving the
    message. Asserted with names nobody has listed, which is precisely the case a
    blocklist gets wrong."""
    for name in ("wrapping_token_v2", "pw", "otp", "retrieval_url", "unwrap_me"):
        assert name not in NAMED_SECRETS
        with pytest.raises(ConfigError, match="unknown placeholder"):
            built(template=f"take this: {{{name}}}")


def test_every_allowed_placeholder_renders_nothing_that_retrieves() -> None:
    """The closed set, asserted as a set rather than trusted to review: three
    facts about *who, where and when*, and nothing that fetches anything. A fourth
    is a decision, and this is where it gets argued for."""
    assert PLACEHOLDERS == ("account", "target", "expires_at")


def test_the_allowed_placeholders_are_accepted() -> None:
    assert built(template="{account}/{target} until {expires_at}") is not None


def test_a_literal_brace_is_not_a_placeholder() -> None:
    """`{{` is `str.format`'s own convention, and supporting it is why the walk
    uses `string.Formatter` rather than a regex: without it an estate whose
    message contains a brace meets a refusal about a placeholder it did not
    write."""
    assert built(template="{{ok}} for {account}") is not None


# --------------------------------------------- whether a channel can send ---


def test_a_served_channel_with_its_client_installed_warns_about_nothing() -> None:
    """`webhook` is implemented, and `httpx` is installed in the dev environment,
    so there is nothing to say."""
    assert unserviceable(built()) is None


def test_a_channel_whose_client_is_missing_says_what_to_install(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """E4's own case: the file is valid, the install is incomplete, and `pip` is the
    remedy. Asked **without importing** the client, which is what lets a validator
    report a missing one at all."""
    monkeypatch.setattr("sopuli.config.notify.NOTIFIERS", {"webhook": _uninstallable()})

    notice = unserviceable(built())

    assert notice is not None
    assert "its client is not installed" in notice
    assert "sopuli-dba[notify]" in notice


def _uninstallable() -> Any:
    from sopuli.notify.registry import Notifier

    return Notifier(
        module="sopuli.notify.webhook",
        extra="notify",
        provides=frozenset({"a_module_nobody_has_installed"}),
    )


def test_no_notify_block_warns_about_nothing() -> None:
    assert unserviceable(None) is None


# ------------------------------------- what `str.format` reads differently ---
#
# All three of these passed the first build's walk and raised inside `render()`,
# which happens after the password has changed -- the one moment UC-2 §6 has no
# answer for. Copilot found them on #520. The walk discarded the format spec and
# the conversion, and called `.strip()` on a name that `str.format` does not
# strip.


def test_a_format_spec_is_refused_at_load() -> None:
    """`{expires_at:%Y}` raises `ValueError: Invalid format specifier` at render,
    because every substitution is already a string -- `Facts.as_fields` formats the
    timestamp so that no channel has to."""
    with pytest.raises(ConfigError) as raised:
        build_notify(
            {
                "method": "webhook",
                "webhook": {
                    "url": {"env": "SOPULI_NOTIFY_WEBHOOK"},
                    "template": "fetch it before {expires_at:%Y}",
                },
            },
            at=AT,
        )

    assert "may not give {expires_at} a format spec" in str(raised.value)
    assert "after the password has changed" in str(raised.value.hint)


def test_a_conversion_is_refused_at_load() -> None:
    """`{account!r}` does not raise -- it quotes a string that is already one. It
    is refused anyway, because the closed set is about what a template may ask for
    and a conversion is a second spelling of one placeholder."""
    with pytest.raises(ConfigError) as raised:
        build_notify(
            {
                "method": "webhook",
                "webhook": {
                    "url": {"env": "SOPULI_NOTIFY_WEBHOOK"},
                    "template": "{account!r} has a password",
                },
            },
            at=AT,
        )

    assert "may not give {account} a conversion" in str(raised.value)


def test_a_padded_placeholder_is_refused_rather_than_trimmed() -> None:
    """`{ account }` raises `KeyError: ' account '` at render: `str.format` looks
    the name up exactly as written.

    **Refused rather than normalised**, which is the decision in this fix. Trimming
    it here would accept a template that this validator and `str.format` read
    differently, and the estate wrote the file, so the file should say what it
    means."""
    with pytest.raises(ConfigError) as raised:
        build_notify(
            {
                "method": "webhook",
                "webhook": {
                    "url": {"env": "SOPULI_NOTIFY_WEBHOOK"},
                    "template": "{ account } has a password",
                },
            },
            at=AT,
        )

    assert "may not pad a placeholder with spaces" in str(raised.value)
    assert "{account}" in str(raised.value.hint)


@pytest.mark.parametrize(
    "template",
    [
        "{account} on {target} has a new password waiting",
        "fetch it before {expires_at}",
        "{{literal}} braces and {account}",
        "no placeholders at all",
    ],
)
def test_the_templates_an_estate_would_actually_write_still_load(template: str) -> None:
    """The other half of the three refusals above: a guard that tightened until it
    refused the documented samples would be worse than the hole it closed."""
    build_notify(
        {
            "method": "webhook",
            "webhook": {"url": {"env": "SOPULI_NOTIFY_WEBHOOK"}, "template": template},
        },
        at=AT,
    )


def test_every_loadable_template_can_actually_render() -> None:
    """**The assertion that ties the two layers together.** The bug was not any one
    of the three holes; it was that a template could pass the config layer and
    raise in the renderer, and nothing in the suite crossed that boundary. Anything
    `build_notify` accepts, `render` must survive."""
    from sopuli.notify import Facts, render

    for template in (
        "{account} on {target} has a new password waiting",
        "fetch it before {expires_at}",
        "{{literal}} and {account}",
        "plain text",
    ):
        notify = build_notify(
            {
                "method": "webhook",
                "webhook": {"url": {"env": "SOPULI_NOTIFY_WEBHOOK"}, "template": template},
            },
            at=AT,
        )
        render(notify, Facts(account="acme_dev_alice", target="free-pdb"))

"""Building the ``profiles:`` section -- how a run is invoked (§5).

§5's sentence is the whole design: **`environment` and labels describe what you
are pointing at; a profile describes where you are running from.** Everything
this module does follows from it.

The two lists matter more than the parsing. A profile may set the things that
change *behaviour* -- whether it may prompt, how it verifies, what it prints --
and may not set anything that changes *scope*. A selector-shaped option that is
not a selector is a bad footgun in a tool that rotates credentials, so the
scope-changing keys get their own message rather than a generic unknown-key one:
somebody who wrote ``targets:`` in a profile has a wrong model, not a typo, and
telling them the known keys would not fix it.

The naming rule (`--profile prod` reads like a selector) needs the estate to
check against, so it lives in :mod:`sopuli.config.references` with the other
cross-section rules.

:func:`select_profile` is the other half, and it is here rather than at the
boundary for one reason: **applying layer 3 happens while the file is being
built**. A profile's ``vaults:`` block patches a store declaration, and
:mod:`sopuli.config.vault_layers` merges the three file layers in a single pass
so that ``tls.verify`` ratchets across all of them at once -- which it can only
do if it already knows which profile is active. So the *name* arrives from
outside as a plain string (:mod:`sopuli.invocation` resolves it from
``--profile`` and ``SOPULI_PROFILE``), and everything downstream of the name is
decided here, with no I/O and no click.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.fields import (
    choice,
    mapping,
    optional_bool,
    optional_int,
    reject_unknown_keys,
)
from sopuli.config.locking import build_locking
from sopuli.config.model import Profile, ProfileDb
from sopuli.config.policies import ROTATION_STRATEGIES, build_verify
from sopuli.config.references import dangling
from sopuli.config.safety import read_safety
from sopuli.config.vaults import build_vault_patches, vault_name

#: §5's whitelist. Everything here changes how the run behaves; nothing here
#: changes what it acts on.
PROFILE_KEYS = (
    "vault",
    "vaults",
    "verify",
    "rotation",
    "safety",
    "locking",
    "confirm",
    "output",
    "db",
)

#: §5's blocklist, each with why it is refused. These are not typos, so the
#: message says what a profile *is* instead of listing keys.
FORBIDDEN_KEYS = {
    "accounts": "the account→secret binding must not vary by how you invoked the tool",
    "applications": "the account→secret binding must not vary by how you invoked the tool",
    "secret": "the account→secret binding must not vary by how you invoked the tool",
    "secret_template": "the account→secret binding must not vary by how you invoked the tool",
    "targets": "a profile is not a selector -- use --select, --group or --target",
    "target_sets": "a profile is not a selector -- use --select, --group or --target",
    "groups": "a profile is not a selector -- use --select, --group or --target",
    "environment": "you cannot relabel prod as dev by choosing a profile",
    "policies": "a weaker password policy is a reviewed config change, never a side "
    "effect of running from CI",
}

#: Keys a profile could once write, each with why it is gone. Refused by name,
#: so that a file written for an older build is not told it has a typo.
REMOVED_KEYS = {
    "log_level": "a config cannot turn on debug output; use --debug on the command line",
    "log_file": "the tool writes no log file; use --debug and redirect stderr",
}

ROTATION_KEYS = ("strategy",)

DB_KEYS = ("connect_timeout_s", "query_timeout_s")

OUTPUTS = ("text", "json", "jsonl")


def build_profiles(document: dict[str, Any]) -> tuple[Profile, ...]:
    """Read ``profiles:`` into entries, in document order."""
    if "profiles" not in document:
        return ()

    at = ROOT.key("profiles")
    entries = mapping(document["profiles"], at=at)
    return tuple(_build_profile(name, entry, at=at.key(name)) for name, entry in entries.items())


def _build_profile(name: str, raw: Any, *, at: KeyPath) -> Profile:
    entry = mapping(raw, at=at)
    _reject_forbidden_keys(entry, at=at)
    _reject_removed_keys(entry, at=at)
    reject_unknown_keys(entry, allowed=PROFILE_KEYS, at=at)

    return Profile(
        name=name,
        vault=vault_name(entry, at=at),
        verify=build_verify(entry.get("verify"), at=at.key("verify")),
        rotation_strategy=_build_rotation_strategy(entry.get("rotation"), at=at.key("rotation")),
        safety=read_safety(entry, at=at),
        locking=build_locking(entry.get("locking"), at=at.key("locking")),
        confirm=optional_bool(entry, "confirm", at=at),
        output=_closed(entry, "output", allowed=OUTPUTS, noun="output format", at=at),
        db=_build_db(entry.get("db"), at=at.key("db")),
        # Applied at layer 3 when this profile is the active one, by
        # `sopuli.config.vault_layers`. The refusals are useful either way: a
        # profile writing `vaults.<name>.locking` is wrong whether or not any run
        # ever selects it, and `config validate` is where somebody finds that out.
        vaults=build_vault_patches(entry, at=at),
    )


def select_profile(
    profiles: tuple[Profile, ...], *, requested: str | None, declared_default: str | None
) -> Profile | None:
    """The one profile this run is invoked under, or ``None`` (§5, rules 1 and 6).

    ``requested`` is what ``--profile`` or ``SOPULI_PROFILE`` said, already
    merged by the one resolver; ``declared_default`` is ``defaults.profile``.
    The chain is §5's, in order, and it stops at the first answer -- so a
    ``--profile`` that names nothing is refused rather than falling through to
    the file's default. **A typo must not quietly give you interactive behaviour
    in a scheduler**, which is the whole of rule 6.

    Exactly one, and no composition: C11 settled that, so there is a name
    here and never a list.

    The error points at ``defaults.profile`` when that is where the name was
    written and at the document root when it was typed, which is the same
    distinction ``policy sample`` already makes about a policy name: a name the
    file wrote has a line to go and fix, and one typed on the command line does
    not.
    """
    chosen = requested if requested is not None else declared_default
    if chosen is None:
        return None
    dangling(
        chosen,
        {profile.name for profile in profiles},
        noun="profile",
        section="profiles",
        at=ROOT if requested is not None else ROOT.key("defaults").key("profile"),
    )
    return next(profile for profile in profiles if profile.name == chosen)


def _reject_forbidden_keys(entry: dict[str, Any], *, at: KeyPath) -> None:
    """§5's blocklist, reported before the whitelist gets a chance to.

    Order matters for the message, not the outcome: both reject the key, but
    "unknown key 'targets'" beside a list of the known ones invites somebody to
    go looking for the right spelling of a thing that must not exist here.
    """
    for key in sorted(entry):
        if key in FORBIDDEN_KEYS:
            raise ConfigError(
                f"a profile may not set `{key}:`",
                at=at.key(key),
                hint=f"{FORBIDDEN_KEYS[key]} (§5)",
            )


def _reject_removed_keys(entry: dict[str, Any], *, at: KeyPath) -> None:
    """Refuse a key an older build accepted, and say why it is gone."""
    for key in sorted(entry):
        if key in REMOVED_KEYS:
            raise ConfigError(
                f"`{key}:` was removed from profiles",
                at=at.key(key),
                hint=f"delete it; {REMOVED_KEYS[key]}",
            )


def _build_rotation_strategy(raw: Any, *, at: KeyPath) -> str | None:
    """Only ``strategy`` -- §5 lists no other rotation key.

    ``rollover_hours`` and friends describe the credential's lifecycle, which is
    a property of the estate rather than of the machine running the command.
    """
    if raw is None:
        return None
    block = mapping(raw, at=at)
    reject_unknown_keys(block, allowed=ROTATION_KEYS, at=at)
    return _closed(block, "strategy", allowed=ROTATION_STRATEGIES, noun="strategy", at=at)


def _build_db(raw: Any, *, at: KeyPath) -> ProfileDb:
    if raw is None:
        return ProfileDb()
    block = mapping(raw, at=at)
    reject_unknown_keys(block, allowed=DB_KEYS, at=at)
    return ProfileDb(
        connect_timeout_s=_seconds(block, "connect_timeout_s", at=at),
        query_timeout_s=_seconds(block, "query_timeout_s", at=at),
    )


def _seconds(block: dict[str, Any], key: str, *, at: KeyPath) -> int | None:
    value = optional_int(block, key, at=at)
    if value is not None and value < 1:
        raise ConfigError(
            f"{key} must be at least 1 second, not {value}",
            at=at.key(key),
            hint="a zero or negative timeout is a hang, not an unlimited budget",
        )
    return value


def _closed(
    block: dict[str, Any], key: str, *, allowed: tuple[str, ...], noun: str, at: KeyPath
) -> str | None:
    if key not in block:
        return None
    return choice(block[key], allowed=allowed, at=at.key(key), noun=noun)

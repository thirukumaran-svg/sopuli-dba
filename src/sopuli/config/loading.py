"""Getting a config file into memory as raw data, safely and in one place.

Which file, and whether there are several, is
:mod:`sopuli.config.discovery`. This is what happens to each one, in the order
the steps have to happen:

1. the file exists
2. nobody else can get at it (P4 -- see :mod:`sopuli.config.permissions`)
3. it decodes as UTF-8
4. it parses as YAML, under the hardened loader
5. the root is a mapping
6. it declares a ``version`` this build understands

Every failure is a :class:`ConfigError` carrying a location, so the caller never
has to translate an ``OSError`` or a ``yaml.YAMLError`` into something a user can
act on.

The result is **raw data** -- nested dicts and lists. Turning it into typed
objects, and enforcing the §10 rules, is :func:`build_config`. Keeping the two
apart means the file layer can be tested with a two-line document, and the
schema layer can be tested without touching a filesystem at all
(``04-testing.md`` §4).

The permission check runs *before* the read, not after. Reading first would mean
the contents of a file we are about to refuse are already in the process, and
the ordering is the only thing that makes the refusal mean anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import fields, replace
from pathlib import Path
from typing import Any

from sopuli.config.applications import build_applications
from sopuli.config.bindings import build_bindings
from sopuli.config.codes import DELIVERY_UNSERVICEABLE, NOTIFY_UNSERVICEABLE, UNREAD_POLICY_KEYS
from sopuli.config.defaults import build_defaults, build_runtime
from sopuli.config.delivery import build_delivery, unserviceable
from sopuli.config.discovery import CONFIG_ENV
from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.expansion import expand_targets
from sopuli.config.fields import describe, reject_unknown_keys
from sopuli.config.groups import build_groups
from sopuli.config.model import Config, ConfigWarning
from sopuli.config.notify import unserviceable as unserviceable_notify
from sopuli.config.permissions import check_permissions
from sopuli.config.personal_accounts import build_personal_accounts, reject_cross_declaration
from sopuli.config.policies import build_policies
from sopuli.config.profiles import build_profiles, select_profile
from sopuli.config.references import check_references
from sopuli.config.reset_records import build_reset_records
from sopuli.config.target_sets import build_target_sets
from sopuli.config.targets import build_targets
from sopuli.config.vault_env import NO_ENV
from sopuli.config.vault_layers import apply_vault_layers
from sopuli.config.vaults import build_vaults
from sopuli.config.yaml_loader import parse_yaml

_VERSION = ROOT.key("version")

#: Config schema versions this build understands. The key is required: a file
#: with no version cannot be migrated later, because there is nothing to
#: distinguish "written before versioning" from "written for version 4".
SUPPORTED_VERSIONS = (1,)

#: Notepad writes a BOM and gives no way to turn it off, and Windows is a
#: supported tier. `utf-8-sig` accepts a file with or without one.
ENCODING = "utf-8-sig"

#: Every section name a config file may use at the top level. §10 makes an
#: unknown key an error rather than a warning, and P3 is explicit that "a typo in
#: a credential tool must never be silently ignored".
TOP_LEVEL_KEYS = (
    "version",
    "runtime",
    "defaults",
    "vaults",
    "targets",
    "target_sets",
    "groups",
    "policies",
    "profiles",
    # The application binding, in either shape (§1).
    "applications",
    "accounts",
    "secret",
    "secret_template",
    "policy",
    "overrides",
    # UC-2's personal accounts, which are a declaration and not a binding (H1).
    # Beside the application keys rather than among them: nothing masters one, so
    # it shares no key with the form above.
    "personal_accounts",
    # UC-2's reset journal: where a reset is recorded, never what it set.
    "reset_records",
    # UC-2's delivery: how the new password reaches the person.
    "delivery",
)


def load_document(path: Path) -> dict[str, Any]:
    """Read, parse and sanity-check one config file. Returns raw data."""
    if not path.exists():
        raise ConfigError(
            "config file does not exist",
            source=path,
            hint="pass --config PATH, or set SOPULI_CONFIG",
        )
    if not path.is_file():
        # A directory passes `exists` and fails `is_file`. Reporting that as
        # "does not exist" sends someone looking for a typo in a path that is
        # spelled correctly -- `--config /etc/sopuli` rather than
        # `--config /etc/sopuli/sopuli.yaml` is an easy thing to type.
        raise ConfigError(
            "config path is not a file",
            source=path,
            hint="point --config at the file itself, not the directory holding it",
        )

    check_permissions(path)
    document = _require_mapping(parse_yaml(_read(path), source=path), path)
    _require_supported_version(document, path)
    return document


def load_documents(paths: Sequence[Path]) -> dict[str, Any]:
    """Read every layer and merge them left to right (§9).

    Each file is checked on its own first -- permissions, encoding, parse,
    ``version:`` -- so those errors still name the file they came from. Only
    then are they merged, because a merged document has no filename.

    Every layer is a config file in its own right, including its ``version:``.
    A fragment with the key left off cannot be migrated later, which is the
    reason §9a requires it, and that reason does not weaken when the fragment is
    one of several.
    """
    return merge_documents([load_document(path) for path in paths])


def merge_documents(documents: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Layer raw documents: deep merge for mappings, replace for everything else.

    §9's rule, and the asymmetry in it is deliberate. A mapping is a set of
    named settings, so a later file adding one should not delete the rest. A
    list is a whole answer -- ``targets:``, ``accounts:`` -- and merging two
    would produce an estate that appears in no file, which is a bad way to
    discover what the tool is about to touch (invariant 5).
    """
    merged: dict[str, Any] = {}
    for document in documents:
        merged = _merge(merged, document)
    return merged


def _merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _merge(current, value)
        else:
            merged[key] = value
    return merged


def load_config(
    path: Path,
    *,
    profile: str | None = None,
    env: Mapping[str, str] = NO_ENV,
    vault_addr: str | None = None,
) -> Config:
    """Read one config file and validate it into typed objects.

    The two steps stay separate because they fail for different reasons and are
    worth testing apart: :func:`load_document` is about the file, this is about
    what is written in it. Anything raised here already knows which key it is
    complaining about.

    ``profile`` is the name ``--profile`` or ``SOPULI_PROFILE`` supplied, or
    ``None``. See :func:`build_config`.
    """
    return _validate(
        load_document(path), source=path, profile=profile, env=env, vault_addr=vault_addr
    )


def load_config_from(
    paths: Sequence[Path],
    *,
    profile: str | None = None,
    env: Mapping[str, str] = NO_ENV,
    vault_addr: str | None = None,
) -> Config:
    """Read one or more layered config files and validate the result.

    What :func:`~sopuli.config.discovery.discover` returns goes straight in
    here. With several layers a validation error carries its key path but no
    filename: the offending value may have been written in one file and
    overridden in another, and naming either of them would be a guess. Errors
    about a *file* -- unreadable, unparseable, unversioned -- are raised before
    the merge and still say which one.
    """
    return load_layers(paths, profile=profile, env=env, vault_addr=vault_addr)[1]


def load_layers(
    paths: Sequence[Path],
    *,
    profile: str | None = None,
    env: Mapping[str, str] = NO_ENV,
    vault_addr: str | None = None,
) -> tuple[dict[str, Any], Config]:
    """The merged document *and* the config built from it.

    ``config show`` needs both: once several ``--config`` files have been
    merged, "the configuration as loaded" is the merged document rather than any
    file on disk, and it is the only form in which the effect of layering can be
    inspected. Everything else wants the :class:`Config`.

    One code path rather than two, so a caller that needs both cannot read the
    files twice -- which would be wasteful on a small file and wrong on a file
    that changed in between.
    """
    if not paths:
        raise ConfigError(
            "no config file to load",
            hint=f"pass --config PATH, or set {CONFIG_ENV}",
        )
    document = load_documents(paths)
    # With one file a validation error can name it. With several it cannot: the
    # offending value may have been written in one and overridden in another.
    source = paths[0] if len(paths) == 1 else None
    return document, _validate(
        document, source=source, profile=profile, env=env, vault_addr=vault_addr
    )


def _validate(
    document: dict[str, Any],
    *,
    source: Path | None,
    profile: str | None,
    env: Mapping[str, str],
    vault_addr: str | None = None,
) -> Config:
    try:
        reject_unknown_keys(document, allowed=TOP_LEVEL_KEYS, at=ROOT)
        config = build_config(document, profile=profile, env=env, vault_addr=vault_addr)
    except ConfigError as error:
        # The builders work on raw data and have never seen a filename. Filling
        # it in here means every message says which file, without threading a
        # path through every function that reads a key.
        if source is not None:
            error.source = source
        raise
    return config


def build_config(
    document: dict[str, Any],
    *,
    profile: str | None = None,
    env: Mapping[str, str] = NO_ENV,
    vault_addr: str | None = None,
) -> Config:
    """Validate raw data into a :class:`Config`, with no filesystem involved.

    Sections are built estate-first so that the first error a half-finished file
    produces is about the estate it declares rather than about the application
    bound to it. Then, in order, because each step needs the one before it: the
    profile is selected, the vault layers are merged, the target sets are
    expanded, every name is resolved -- a set's ``vault: "{vault}"`` names nothing
    until it has been rendered -- and the application bindings are built over the
    estate that results.

    ``profile`` is the name the command line or the environment asked for, as a
    plain string: this layer does not know what a flag is. It arrives here rather
    than at the boundary because **layer 3 is applied while the file is being
    built** -- a profile's ``vaults:`` block patches a store declaration, and
    :mod:`sopuli.config.vault_layers` merges all three file layers in one pass
    (§5). ``None`` means neither said anything, which leaves
    ``defaults.profile`` to answer, and a name nothing declares is refused here
    the same way every other dangling name in the file is.

    ``env`` arrives for the same reason and one layer higher: §6's
    ``SOPULI_VAULT__VAULT_DEV__ADDR`` addresses a *store*, so it belongs to the
    same merge rather than to the invocation. Empty by default -- nothing
    in this package reads ambient state, and a caller that wants the process's
    own environment passes it (:func:`sopuli.invocation.load_config_layers`).
    """
    config = Config(
        version=document["version"],
        vaults=build_vaults(document),
        targets=build_targets(document),
        target_sets=build_target_sets(document),
        groups=build_groups(document),
        policies=build_policies(document),
        profiles=build_profiles(document),
        defaults=build_defaults(document),
        runtime=build_runtime(document),
        applications=build_applications(document),
        personal_accounts=build_personal_accounts(document),
        reset_records=build_reset_records(document),
        delivery=build_delivery(document),
    )
    # Before anything else looks at either section: a name in both makes the
    # whitelist ambiguous about which guarantee applies, and every later step --
    # expansion, references, bindings -- would be reasoning about an account
    # that means two things (H1).
    reject_cross_declaration(config.applications, config.personal_accounts)
    # Exactly one profile is active (§5 rule 1), and it has to be settled before
    # the vault layers are merged: layer 3 *is* the active profile's `vaults:`
    # block, and a merge that ran first would have nothing to put there.
    config = replace(
        config,
        active_profile=select_profile(
            config.profiles, requested=profile, declared_default=config.defaults.profile
        ),
    )
    # The file's own precedence layers, merged before anything reads a store
    # (C13). Before `check_references`, because that is where §10's
    # unverified-transport warning asks a store whether it verifies its
    # certificate -- and the answer has to be the effective one, or a
    # `defaults:` block could turn verification off without warning.
    vaults, layered = apply_vault_layers(config, env=env, vault_addr=vault_addr)
    config = replace(config, vaults=vaults)
    config = replace(config, expanded_targets=expand_targets(config))
    # References are resolved before bindings are built, not after: an
    # application naming a target that does not exist should say so, rather than
    # silently selecting nothing and producing no bindings at all.
    warnings = check_references(config)
    config = replace(config, bindings=build_bindings(config))
    return replace(
        config,
        warnings=(*layered, *warnings, *_policy_warnings(config), *_delivery_warnings(config)),
    )


#: The flag that supplies each policy key a run does not read, or ``None`` where
#: nothing does. A policy's `rotation:` and `verify:` are parsed and validated,
#: and every run takes these from the command line instead.
_UNREAD_POLICY_KEYS: dict[str, dict[str, str | None]] = {
    "rotation": {
        "strategy": "--strategy",
        "rollover_hours": None,
        "keep_previous": None,
        "max_age_days": "--max-age-days",
    },
    "verify": {"method": "--method", "lockout_margin": "--lockout-margin"},
}


def _policy_warnings(config: Config) -> tuple[ConfigWarning, ...]:
    """Say that a policy's `rotation:` or `verify:` keys change nothing.

    The keys validate, so a file writing them reads as configuring something.
    It does not (decision #610): the verbs take these from flags, and `check`
    defaults to `login` whatever a policy says (Q1). One warning per block,
    naming the keys written and the flag that does the job, where there is one.
    """
    found = []
    for policy in config.policies:
        for block_name, flags in _UNREAD_POLICY_KEYS.items():
            block = getattr(policy, block_name)
            written = [one.name for one in fields(block) if getattr(block, one.name) is not None]
            if not written:
                continue
            flagged = [f"`{key}` with `{flags[key]}`" for key in written if flags[key]]
            unflagged = [f"`{key}`" for key in written if not flags[key]]
            remedies = []
            if flagged:
                remedies.append(f"the command line sets {', '.join(flagged)}")
            if unflagged:
                remedies.append(f"nothing sets {', '.join(unflagged)}")
            found.append(
                ConfigWarning(
                    message=(
                        f"{', '.join(f'`{key}`' for key in written)} "
                        f"{'is' if len(written) == 1 else 'are'} parsed and not read"
                    ),
                    at=str(ROOT.key("policies").key(policy.name).key(block_name)),
                    hint=f"no run reads these from a policy; {', and '.join(remedies)}",
                    code=UNREAD_POLICY_KEYS,
                )
            )
    return tuple(found)


def _delivery_warnings(config: Config) -> tuple[ConfigWarning, ...]:
    """Say that a configured delivery method cannot deliver yet.

    A load-time warning rather than a check inside one verb, so every command
    reports it the same way -- `config validate` in text, and `diagnostics[]` for
    the schedulers that never see the text. A file that parses clean must not read
    as a file that would hand somebody a password, and a file naming a method
    this build does not implement would not.

    Two codes, `SOPULI-W035` for the method and `SOPULI-W036` for the notify
    channel, because an estate can have one working and the other not.
    """
    found = []
    notice = unserviceable(config.delivery)
    if notice is not None:
        found.append(
            ConfigWarning(
                message=notice,
                at=str(ROOT.key("delivery").key("method")),
                hint=(
                    "the block is valid and this build cannot act on it; nothing is wrong "
                    "with the file"
                ),
                code=DELIVERY_UNSERVICEABLE,
            )
        )
    # The notify channel's own. A second warning rather than a widened
    # first: an estate can have a working delivery and an inert notification, and
    # one sentence covering both would have to say "something here does not work"
    # -- which is the message that sends somebody to read the whole block.
    channel = unserviceable_notify(config.delivery.notify if config.delivery else None)
    if channel is not None:
        found.append(
            ConfigWarning(
                message=channel,
                at=str(ROOT.key("delivery").key("notify").key("method")),
                hint=(
                    "the block is valid and this build cannot send through it. `account "
                    "reset-password` refuses rather than resetting without notifying -- "
                    "before the password changes -- so install the client or take "
                    "`delivery.notify` out of the file. `config validate` warns instead of "
                    "failing because it is the question *is this file usable here*, and the "
                    "answer is yes everywhere but this block"
                ),
                code=NOTIFY_UNSERVICEABLE,
            )
        )
    return tuple(found)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding=ENCODING)
    except UnicodeDecodeError as error:
        raise ConfigError(
            f"config file is not valid UTF-8 (byte {error.start})",
            source=path,
            hint="save the file as UTF-8",
        ) from error
    except OSError as error:
        raise ConfigError(
            f"cannot read the config file: {error.strerror or error}",
            source=path,
        ) from error


def _require_mapping(document: Any, path: Path) -> dict[str, Any]:
    if document is None:
        # An empty file, or one that is nothing but comments. Distinguished from
        # the wrong-type case because the fix is different: write some config.
        raise ConfigError(
            "config file is empty",
            source=path,
            hint=f"a config file needs at least `version: {SUPPORTED_VERSIONS[-1]}`",
        )
    if not isinstance(document, dict):
        raise ConfigError(
            f"config file must contain a mapping of keys, not {describe(document)}",
            source=path,
        )
    return document


def _require_supported_version(document: dict[str, Any], path: Path) -> None:
    if "version" not in document:
        raise ConfigError(
            "config file does not declare a version",
            source=path,
            at=_VERSION,
            hint=f"add `version: {SUPPORTED_VERSIONS[-1]}` at the top of the file",
        )

    version = document["version"]
    supported = ", ".join(str(candidate) for candidate in SUPPORTED_VERSIONS)

    # The type check comes first, and the bool half of it is not pedantry:
    # `bool` is a subclass of `int` and `True == 1`, so `version: true` would
    # satisfy `version in SUPPORTED_VERSIONS` and load as version 1.
    if isinstance(version, bool) or not isinstance(version, int):
        raise ConfigError(
            f"version must be a number, not {describe(version)}",
            source=path,
            at=_VERSION,
            hint=f"supported: {supported}",
        )
    if version in SUPPORTED_VERSIONS:
        return
    raise ConfigError(
        f"unsupported config version {version}",
        source=path,
        at=_VERSION,
        hint=f"this build understands: {supported}",
    )

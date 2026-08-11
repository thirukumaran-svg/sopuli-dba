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

from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from sopuli.config.applications import build_applications
from sopuli.config.bindings import build_bindings
from sopuli.config.defaults import build_defaults, build_runtime
from sopuli.config.discovery import CONFIG_ENV
from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.expansion import expand_targets
from sopuli.config.fields import describe, reject_unknown_keys
from sopuli.config.groups import build_groups
from sopuli.config.model import Config
from sopuli.config.permissions import check_permissions
from sopuli.config.policies import build_policies
from sopuli.config.profiles import build_profiles
from sopuli.config.references import check_references
from sopuli.config.target_sets import build_target_sets
from sopuli.config.targets import build_targets
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


def load_config(path: Path) -> Config:
    """Read one config file and validate it into typed objects.

    The two steps stay separate because they fail for different reasons and are
    worth testing apart: :func:`load_document` is about the file, this is about
    what is written in it. Anything raised here already knows which key it is
    complaining about.
    """
    return _validate(load_document(path), source=path)


def load_config_from(paths: Sequence[Path]) -> Config:
    """Read one or more layered config files and validate the result.

    What :func:`~sopuli.config.discovery.discover` returns goes straight in
    here. With several layers a validation error carries its key path but no
    filename: the offending value may have been written in one file and
    overridden in another, and naming either of them would be a guess. Errors
    about a *file* -- unreadable, unparseable, unversioned -- are raised before
    the merge and still say which one.
    """
    if not paths:
        raise ConfigError(
            "no config file to load",
            hint=f"pass --config PATH, or set {CONFIG_ENV}",
        )
    if len(paths) == 1:
        return load_config(paths[0])
    return _validate(load_documents(paths), source=None)


def _validate(document: dict[str, Any], *, source: Path | None) -> Config:
    try:
        reject_unknown_keys(document, allowed=TOP_LEVEL_KEYS, at=ROOT)
        config = build_config(document)
    except ConfigError as error:
        # The builders work on raw data and have never seen a filename. Filling
        # it in here means every message says which file, without threading a
        # path through every function that reads a key.
        if source is not None:
            error.source = source
        raise
    return config


def build_config(document: dict[str, Any]) -> Config:
    """Validate raw data into a :class:`Config`, with no filesystem involved.

    Sections are built estate-first so that the first error a half-finished file
    produces is about the estate it declares rather than about the application
    bound to it. Then, in order, because each step needs the one before it: the
    target sets are expanded, every name is resolved -- a set's
    ``vault: "{vault}"`` names nothing until it has been rendered -- and the
    application bindings are built over the estate that results.
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
    )
    config = replace(config, expanded_targets=expand_targets(config))
    # References are resolved before bindings are built, not after: an
    # application naming a target that does not exist should say so, rather than
    # silently selecting nothing and producing no bindings at all.
    warnings = check_references(config)
    config = replace(config, bindings=build_bindings(config))
    return replace(config, warnings=warnings)


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

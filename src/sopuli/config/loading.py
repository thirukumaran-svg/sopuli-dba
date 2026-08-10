"""Getting a config file into memory as raw data, safely and in one place.

This is the whole file layer, in the order the steps have to happen:

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
objects, and enforcing the §9 rules, is the next piece of work. Keeping the two
apart means the file layer can be tested with a two-line document, and the
schema layer can be tested without touching a filesystem at all
(``04-testing.md`` §4).

The permission check runs *before* the read, not after. Reading first would mean
the contents of a file we are about to refuse are already in the process, and
the ordering is the only thing that makes the refusal mean anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sopuli.config.applications import build_applications
from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.fields import describe, reject_unknown_keys
from sopuli.config.groups import build_groups
from sopuli.config.model import Config
from sopuli.config.permissions import check_permissions
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

#: Every section name a config file may use at the top level. §9 makes an
#: unknown key an error rather than a warning, and P3 is explicit that "a typo in
#: a credential tool must never be silently ignored".
#:
#: `policies`, `defaults`, `profiles` and `runtime` are listed but not yet
#: modelled -- their *interiors* are still raw. Recognising the names is what
#: stops `polices:` from being silently ignored while the section that reads it
#: is written.
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


def load_config(path: Path) -> Config:
    """Read a config file and validate it into typed objects.

    The two steps stay separate because they fail for different reasons and are
    worth testing apart: :func:`load_document` is about the file, this is about
    what is written in it. Anything raised here already knows which key it is
    complaining about.
    """
    document = load_document(path)
    try:
        reject_unknown_keys(document, allowed=TOP_LEVEL_KEYS, at=ROOT)
        config = build_config(document)
    except ConfigError as error:
        # The builders work on raw data and have never seen a filename. Filling
        # it in here means every message says which file, without threading a
        # path through every function that reads a key.
        error.source = path
        raise
    return config


def build_config(document: dict[str, Any]) -> Config:
    """Validate raw data into a :class:`Config`, with no filesystem involved.

    Sections are built estate-first so that the first error a half-finished file
    produces is about the estate it declares rather than about the application
    bound to it.
    """
    return Config(
        version=document["version"],
        vaults=build_vaults(document),
        targets=build_targets(document),
        target_sets=build_target_sets(document),
        groups=build_groups(document),
        applications=build_applications(document),
    )


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

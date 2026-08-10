"""Configuration: from a file on disk to validated objects.

Two layers, deliberately separable:

* **The file layer** -- :func:`~sopuli.config.loading.load_document` performs the
  P4 permission check, reads, parses under a hardened YAML loader, and confirms
  the document is a versioned mapping. It returns raw data.
* **The schema layer** -- :func:`~sopuli.config.loading.build_config` turns that
  raw data into the typed structures in ``01-configuration.md`` and enforces the
  §10 rules that do not need target expansion.

The split is not just tidiness. The file layer is the only part that touches a
filesystem, so keeping it separate is what lets the schema layer be tested with
a dict and no I/O at all (``04-testing.md`` §4 makes that an architecture
requirement, not a test convenience).

Still raw, and still to come: ``policies``, ``defaults``, ``profiles`` and
``runtime``; every cross-section name reference (a target naming a vault, an
application naming a group or policy); and target-set expansion, which is what
turns a :class:`~sopuli.config.model.TargetSet` into targets.

Nothing here imports click. The loader is meant to be usable without the CLI
wrapped around it, and errors are plain exceptions that the boundary maps to an
exit code.
"""

from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.loading import (
    SUPPORTED_VERSIONS,
    build_config,
    load_config,
    load_document,
)
from sopuli.config.model import (
    AdminCredential,
    Application,
    Config,
    DimensionValue,
    ForEach,
    Group,
    InnerDimension,
    OracleOptions,
    Override,
    Safety,
    Target,
    TargetOracle,
    TargetPatch,
    TargetSelector,
    TargetSet,
    Vault,
    VaultAuth,
)
from sopuli.config.permissions import check_permissions

__all__ = [
    "ROOT",
    "SUPPORTED_VERSIONS",
    "AdminCredential",
    "Application",
    "Config",
    "ConfigError",
    "DimensionValue",
    "ForEach",
    "Group",
    "InnerDimension",
    "KeyPath",
    "OracleOptions",
    "Override",
    "Safety",
    "Target",
    "TargetOracle",
    "TargetPatch",
    "TargetSelector",
    "TargetSet",
    "Vault",
    "VaultAuth",
    "build_config",
    "check_permissions",
    "load_config",
    "load_document",
]

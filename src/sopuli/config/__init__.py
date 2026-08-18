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

Every section of ``01-configuration.md`` is now modelled, every
:class:`~sopuli.config.model.TargetSet` is expanded into the targets it
generates (:mod:`sopuli.config.expansion`), and every name written in one
section is resolved against the section that declares it. Those three run in
that order: a set's ``vault: "{vault}"`` names nothing until it is rendered.

Not every finding is fatal. :attr:`~sopuli.config.model.Config.warnings` carries
the ones §10 asks for as warnings rather than errors.

Nothing here imports click. The loader is meant to be usable without the CLI
wrapped around it, and errors are plain exceptions that the boundary maps to an
exit code.
"""

from sopuli.config.bindings import build_bindings
from sopuli.config.discovery import CONFIG_ENV, discover, search_path
from sopuli.config.errors import ROOT, ArgumentError, ConfigError, KeyPath
from sopuli.config.expansion import declared_at, expand_targets
from sopuli.config.loading import (
    SUPPORTED_VERSIONS,
    build_config,
    load_config,
    load_config_from,
    load_document,
    load_documents,
    load_layers,
    merge_documents,
)
from sopuli.config.model import (
    AccountPolicy,
    AdminCredential,
    Application,
    Binding,
    Config,
    ConfigWarning,
    Defaults,
    DimensionValue,
    ExpandedTarget,
    ForEach,
    Group,
    InnerDimension,
    OracleOptions,
    OracleRuntime,
    Override,
    PasswordPolicy,
    Policy,
    Profile,
    ProfileDb,
    RotationPolicy,
    Runtime,
    Safety,
    Target,
    TargetOracle,
    TargetPatch,
    TargetSelector,
    TargetSet,
    Vault,
    VaultAuth,
    VaultTls,
    VerifyPolicy,
    as_dict,
)
from sopuli.config.permissions import check_permissions
from sopuli.config.references import dangling
from sopuli.config.secret_refs import SecretRef, parse_secret_ref
from sopuli.config.selection import AT_SELECT, filter_estate, matches, parse_selector, select

__all__ = [
    "AT_SELECT",
    "CONFIG_ENV",
    "ROOT",
    "SUPPORTED_VERSIONS",
    "AccountPolicy",
    "ArgumentError",
    "AdminCredential",
    "Application",
    "Binding",
    "Config",
    "ConfigError",
    "ConfigWarning",
    "Defaults",
    "DimensionValue",
    "ExpandedTarget",
    "ForEach",
    "Group",
    "InnerDimension",
    "KeyPath",
    "OracleOptions",
    "OracleRuntime",
    "Override",
    "PasswordPolicy",
    "Policy",
    "Profile",
    "ProfileDb",
    "RotationPolicy",
    "Runtime",
    "Safety",
    "SecretRef",
    "Target",
    "TargetOracle",
    "TargetPatch",
    "TargetSelector",
    "TargetSet",
    "Vault",
    "VaultAuth",
    "VaultTls",
    "VerifyPolicy",
    "build_bindings",
    "build_config",
    "check_permissions",
    "dangling",
    "declared_at",
    "discover",
    "expand_targets",
    "filter_estate",
    "load_config",
    "load_config_from",
    "load_document",
    "as_dict",
    "matches",
    "load_documents",
    "load_layers",
    "merge_documents",
    "parse_secret_ref",
    "parse_selector",
    "search_path",
    "select",
]

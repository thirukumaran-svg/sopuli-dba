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

from importlib import import_module
from typing import TYPE_CHECKING, Final

#: Every name this package re-exports, and the submodule it comes from.
#:
#: **Imported on demand rather than at module scope** (#363), which is a fix to
#: the import graph rather than a performance tweak. Importing *any*
#: ``sopuli.config.X`` runs this file, and this file used to import ``bindings``
#: and ``sharing`` eagerly -- so :mod:`sopuli.payload`, which needs two exception
#: types and a :class:`KeyPath` from :mod:`sopuli.config.errors`, dragged in the
#: two modules that import :mod:`sopuli.payload` straight back. The dependency
#: that closed the loop was never the one it looked like, and #357 was the same
#: shape one package over.
#:
#: A flat table rather than a clever walk, because the failure mode of a clever
#: one is a name that silently stops being exported.
#: ``tests/config/test_package_exports.py`` holds it to ``__all__`` in both
#: directions and checks every name resolves to the same object the submodule
#: holds, so this cannot drift from the eager version it replaced.
_EXPORTS: Final[dict[str, str]] = {
    "AT_SELECT": "selection",
    "AccountPolicy": "model",
    "AdminCredential": "model",
    "Application": "model",
    "ArgumentError": "errors",
    "Binding": "model",
    "CONFIG_ENV": "discovery",
    "Config": "model",
    "ConfigError": "errors",
    "ConfigWarning": "model",
    "Defaults": "model",
    "DimensionValue": "model",
    "ExpandedTarget": "model",
    "ForEach": "model",
    "Group": "model",
    "InnerDimension": "model",
    "KeyPath": "errors",
    "OracleOptions": "model",
    "OracleRuntime": "model",
    "Override": "model",
    "PasswordPolicy": "model",
    "Policy": "model",
    "Profile": "model",
    "ProfileDb": "model",
    "ROOT": "errors",
    "RotationPolicy": "model",
    "Runtime": "model",
    "SUPPORTED_VERSIONS": "loading",
    "Safety": "model",
    "SafetyDelivery": "model",
    "SecretRef": "secret_refs",
    "Selection": "selection",
    "Target": "model",
    "TargetOracle": "model",
    "TargetPatch": "model",
    "TargetSelector": "model",
    "TargetSet": "model",
    "Vault": "model",
    "VaultAuth": "model",
    "VaultPatch": "model",
    "VaultTls": "model",
    "VerifyPolicy": "model",
    "as_dict": "model",
    "build_bindings": "bindings",
    "build_config": "loading",
    "AccountTarget": "selection",
    "check_permissions": "permissions",
    "dangling": "references",
    "declared_at": "expansion",
    "discover": "discovery",
    "expand_targets": "expansion",
    "filter_estate": "selection",
    "filter_to_pairs": "selection",
    "load_config": "loading",
    "load_config_from": "loading",
    "load_document": "loading",
    "load_documents": "loading",
    "load_layers": "loading",
    "matches": "selection",
    "merge_documents": "loading",
    "parse_secret_ref": "secret_refs",
    "parse_selector": "selection",
    "refuse_unknown": "selection",
    "search_path": "discovery",
    "select": "selection",
}


def __getattr__(name: str) -> object:
    """Resolve a re-exported name the first time somebody asks for it (PEP 562).

    Python calls this only when normal lookup fails, so a name already imported
    costs nothing on the second use -- it is set on the module below.
    """
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(f"{__name__}.{module}"), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """`dir()` and tab-completion, which `__getattr__` alone does not answer."""
    return sorted(set(globals()) | set(_EXPORTS))


if TYPE_CHECKING:
    # The eager imports, for type checkers only. mypy does not follow
    # `__getattr__`, so without this block every `from sopuli.config import X`
    # in the tool would resolve to `Any` and this fix would cost the type safety
    # `--strict` exists for. The test named above is what keeps the two lists
    # honest with each other.
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
        SafetyDelivery,
        Target,
        TargetOracle,
        TargetPatch,
        TargetSelector,
        TargetSet,
        Vault,
        VaultAuth,
        VaultPatch,
        VaultTls,
        VerifyPolicy,
        as_dict,
    )
    from sopuli.config.permissions import check_permissions
    from sopuli.config.references import dangling
    from sopuli.config.secret_refs import SecretRef, parse_secret_ref
    from sopuli.config.selection import (
        AT_SELECT,
        AccountTarget,
        Selection,
        filter_estate,
        filter_to_pairs,
        matches,
        parse_selector,
        refuse_unknown,
        select,
    )


__all__ = [
    "AT_SELECT",
    "CONFIG_ENV",
    "ROOT",
    "SUPPORTED_VERSIONS",
    "AccountPolicy",
    "AccountTarget",
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
    "SafetyDelivery",
    "SecretRef",
    "Target",
    "TargetOracle",
    "TargetPatch",
    "TargetSelector",
    "TargetSet",
    "Vault",
    "VaultAuth",
    "VaultPatch",
    "VaultTls",
    "VerifyPolicy",
    "build_bindings",
    "build_config",
    "check_permissions",
    "dangling",
    "declared_at",
    "discover",
    "expand_targets",
    "Selection",
    "filter_estate",
    "filter_to_pairs",
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
    "refuse_unknown",
    "search_path",
    "select",
]

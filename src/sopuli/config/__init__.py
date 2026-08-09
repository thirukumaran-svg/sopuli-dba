"""Configuration: from a file on disk to validated objects.

Two layers, deliberately separable:

* **The file layer** (this PR) -- :func:`~sopuli.config.loading.load_document`
  performs the P4 permission check, reads, parses under a hardened YAML loader,
  and confirms the document is a versioned mapping. It returns raw data.
* **The schema layer** (next) -- typed structures for the two config shapes in
  ``01-configuration.md`` §1, and the §9 validation rules.

The split is not just tidiness. The file layer is the only part that touches a
filesystem, so keeping it separate is what lets the schema layer be tested with
a dict and no I/O at all (``04-testing.md`` §4 makes that an architecture
requirement, not a test convenience).

Nothing here imports click. The loader is meant to be usable without the CLI
wrapped around it, and errors are plain exceptions that the boundary maps to an
exit code.
"""

from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.loading import SUPPORTED_VERSIONS, load_document
from sopuli.config.permissions import check_permissions

__all__ = [
    "ROOT",
    "SUPPORTED_VERSIONS",
    "ConfigError",
    "KeyPath",
    "check_permissions",
    "load_document",
]

"""Package version lookup.

``pyproject.toml`` is the single source of truth and release-please bumps it.
Nothing else in the tree carries a version string.
"""

from importlib.metadata import PackageNotFoundError, version

DISTRIBUTION = "sopuli-dba"


def get_version() -> str:
    """Return the installed distribution version.

    Falls back to ``0.0.0+unknown`` when the package is running from a source
    tree that was never installed, so ``--version`` degrades to a readable
    string instead of raising.
    """
    try:
        return version(DISTRIBUTION)
    except PackageNotFoundError:
        return "0.0.0+unknown"

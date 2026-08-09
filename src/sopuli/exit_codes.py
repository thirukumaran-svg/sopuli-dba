"""Process exit codes.

The full table from ``docs/design/00-principles.md`` P5 is written out here even
though a skeleton can only ever return SUCCESS or USAGE. The table is a
published interface — schedulers branch on these numbers — so it belongs in one
place rather than being re-derived by whichever command needs a value next.

The JSON run document's ``exit_code`` mirrors whatever the process returns.
"""

from enum import IntEnum


class ExitCode(IntEnum):
    """Exit codes, identical on every platform (P4)."""

    SUCCESS = 0
    """Changes applied, or nothing to do."""

    FAILURE = 1
    """Generic failure."""

    USAGE = 2
    """Usage or config validation error."""

    DRIFT = 3
    """`check` found a mismatch. Distinct so schedulers can alert on it."""

    PARTIAL = 4
    """Some targets succeeded, some failed."""

    UNSUPPORTED_CAPABILITY = 5
    """The target or driver cannot do what was asked (P1, invariant 4)."""

    AUTH_FAILURE = 6
    """Authentication failed against the vault or the database."""

    LOCK_HELD = 7
    """Another process holds the lock."""

    ABORTED = 8
    """Aborted by the user, or confirmation declined."""

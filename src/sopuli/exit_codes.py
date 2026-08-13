"""Process exit codes.

The full table from ``docs/design/00-principles.md`` P5 is written out here even
though a skeleton can only ever return a few of them. The table is a published
interface — schedulers branch on these numbers — so it belongs in one place
rather than being re-derived by whichever command needs a value next.

The JSON run document's ``exit_code`` mirrors whatever the process returns, with
one exception that is the whole point of the split between :attr:`ExitCode.USAGE`
and :attr:`ExitCode.CONFIG_INVALID` (J7, issue #8):

    A run document describes a run, and a run begins when the invocation
    resolves. No valid invocation, no document.

**Exit 2 is the only code that never produces a document.** Everything else has
a valid invocation to describe, including a config file the loader rejected —
and ``config validate --output json`` going silent exactly when it has something
to say is what forced the two apart. ``03-json-output.md`` §6 is the statement of
the rule; this is where the two numbers live.
"""

from enum import IntEnum


class ExitCode(IntEnum):
    """Exit codes, identical on every platform (P4)."""

    SUCCESS = 0
    """Changes applied, or nothing to do."""

    FAILURE = 1
    """Generic failure."""

    USAGE = 2
    """argv did not resolve to a valid command and options.

    Narrower than it looks, and deliberately: this is the *pre-invocation* code.
    Nothing has been decided, nothing has been read, and there is no run to
    describe -- so stdout is byte-empty and the message is on stderr, whatever
    ``--output`` asked for. A tool cannot honour a request for JSON that it
    failed to parse.

    A config file the loader rejects is **not** this. See
    :attr:`CONFIG_INVALID`.
    """

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

    CONFIG_INVALID = 9
    """The configuration is unusable -- missing, unreadable, or invalid.

    Split out of :attr:`USAGE` when J7 was answered (issue #8). Two arguments,
    and the second is the one that decided it:

    * It reads better for the operator. Exit 2 means *fix your command line*;
      exit 9 means *fix your config file*. Different people, different moments --
      one is somebody typing, the other is a deployed artefact a scheduler is
      running.
    * Exit 2 has to stay unambiguous. "Empty stdout and exit 2" is only a usable
      consumer rule if exit 2 never carries a document, and a config error has a
      perfectly good invocation to describe. Leaving both on 2 would have meant
      exit 2 sometimes carrying one, which destroys the rule for every consumer.

    Generic failure (1) was the cheaper alternative and discards the most
    actionable distinction the tool has: a broken config is the failure an
    operator can actually go and fix.
    """

"""The secret wrapper (invariant 2).

Redaction happens because a secret value is *typed*, not because a particular
call site remembered to mask it. Every stringification of :class:`Secret`
yields ``***``; the plaintext is reachable only through :meth:`Secret.reveal`,
which exists so that the two places allowed to see it — the vault write and the
driver call — can be found by grepping for one method name.

The JSON side of the same guarantee lives in :mod:`sopuli.output.emit`.
"""

from __future__ import annotations

REDACTED = "***"


class Secret:
    """A string that refuses to render itself.

    >>> s = Secret("hunter2")
    >>> str(s), f"{s}", repr(s)
    ('***', '***', '***')
    >>> s.reveal()
    'hunter2'
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        """Return the plaintext. Callers of this are audited by review."""
        return self._value

    def __str__(self) -> str:
        return REDACTED

    def __repr__(self) -> str:
        return REDACTED

    def __format__(self, format_spec: str) -> str:
        # Without this, ``f"{secret:>20}"`` would raise rather than redact.
        # A padded ``***`` is a better failure than a TypeError in a log line.
        return format(REDACTED, format_spec)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Secret):
            return self._value == other._value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        return len(self._value)

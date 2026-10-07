"""The two keys the advisory lock reads (Q2).

P5's lock lives in the vault: one compare-and-set guarded record per secret path,
carrying a fencing token that is re-checked before every mutation. Two things
about it are configuration rather than behaviour, and both are here because they
are one decision seen from two ends.

**A store's ``locking:``** says whether that store can hold a real lock. P2's
capability table gives ``cas`` to KV v2 and, through ETags, to OCI; KV v1 and the
file backend have no atomic primitive at all. Everywhere else a missing store
capability is emulated in the payload, but "not atomic" is precisely what CAS is
for, so there is nothing to emulate -- a store without it gets no lock rather
than a weaker one, and mutating commands refuse on it. ``advisory-only`` is the
operator saying they know: the record is still written, every run warns, and the
guarantee reported in the run document drops to ``none``.

**``locking.break_expired``** permits an unattended runner to take over a lock
that is past its expiry. Breaking one is otherwise not self-service, because the
holder may be a colleague mid-rotation rather than a process that died.

Both are config-only, per invariant 10: no flag, no environment variable. A
store's key could not be anything else -- ``vaults:`` exists nowhere but the file
-- and ``break_expired`` is deliberately the same, because a flag that unblocks a
run at 17:00 on a Friday is exactly how a guardrail becomes a habit.

The two interact, and :mod:`sopuli.config.references` refuses the combination:
without CAS there is no fence, and unattended breaking without a fence is what
puts two runners on one credential applying different passwords to different
targets.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.errors import KeyPath
from sopuli.config.fields import choice, mapping, optional_bool, reject_unknown_keys
from sopuli.config.model import Locking

#: A store that must be able to hold a real lock, and one that has been excused.
LOCK_REQUIRED = "required"
LOCK_ADVISORY_ONLY = "advisory-only"

#: What a store's ``locking:`` may say. ``required`` is the default and is not a
#: value anybody needs to write; it exists so the refusal can name what was asked
#: for rather than what was omitted.
LOCK_MODES = (LOCK_REQUIRED, LOCK_ADVISORY_ONLY)

#: Absent means ``required``. Unlike a ``safety:`` field, there is nothing to be
#: safest *of* here -- a store either supports CAS or it does not, and no other
#: layer has an opinion about one store -- so this one does take its default at
#: read time.
DEFAULT_LOCK_MODE = LOCK_REQUIRED

#: The ``locking:`` block, under ``defaults:`` or a profile. One key so far.
LOCKING_KEYS = ("break_expired",)


def build_lock_mode(entry: dict[str, Any], *, at: KeyPath) -> str:
    """Read a store's ``locking:``, defaulting to ``required``."""
    if "locking" not in entry:
        return DEFAULT_LOCK_MODE
    return choice(
        entry["locking"],
        allowed=LOCK_MODES,
        at=at.key("locking"),
        noun="locking mode",
    )


def build_locking(raw: Any, *, at: KeyPath) -> Locking | None:
    """Read a ``locking:`` block, or ``None`` where there is none.

    ``break_expired`` stays ``None`` when unwritten rather than becoming
    ``False``, for the reason :class:`~sopuli.config.model.Safety` keeps its
    fields optional: §9 resolves it by taking the safest of every layer, and
    "safest" needs to know which layers said nothing. Here the safe value is
    ``False`` rather than ``True``, which is the first setting to invert the
    ratchet -- see :class:`sopuli.settings.registry.Setting`.
    """
    if raw is None:
        return None
    block = mapping(raw, at=at)
    reject_unknown_keys(block, allowed=LOCKING_KEYS, at=at)
    return Locking(break_expired=optional_bool(block, "break_expired", at=at))

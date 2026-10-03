"""The `reset_records:` block: where UC-2 journals a reset (H2, #450, #468).

UC-1's vault payload answers three questions at once -- when a password last
changed, what to roll back to, and where the lock lives -- because the payload
*is* the secret and all three are facts about it. UC-2 has no payload, and H2
(#450) split the three apart: the **database** answers *when*, **nothing**
answers *what to roll back to* because rollback is not a UC-2 operation, and this
block says where the record that answers *who, which path and where delivered*
lives.

**One destination for the estate, not one per account.** A store and a prefix,
declared once. The record's own path is built under that prefix from the
(target, account) pair -- :func:`sopuli.reset_record.record_path` -- because that
pair is what two concurrent resets collide on, and the prefix is the only part of
it an operator chooses.

**It is not the delivery target, and must not be read as one.** On the unseen
path the password is written where only the *person* can read it (#444, #447);
this is the DBA side's own journal, holds no password in any representation, and
is readable by anyone who may know *that* a reset happened without thereby being
able to use it. Two objects, two lifetimes -- UC-2 §3.5.

**Absent is a mode rather than an error.** The seen path may have no store at all,
and that is the site `manual` exists for, so a reset with nothing configured here
warns and runs (§3.1, §3.4). Which means this module's only job is to validate a
block that *is* written; nothing here refuses a file for leaving it out.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.fields import mapping, reject_unknown_keys, required_string, string
from sopuli.config.model import ResetRecords
from sopuli.config.secret_refs import TRAVERSAL, normalise_path

RESET_RECORDS_KEYS = ("vault", "prefix")


def build_reset_records(document: dict[str, Any]) -> ResetRecords | None:
    """Normalise `reset_records:`, or ``None`` where the section is absent.

    ``None`` rather than a :class:`ResetRecords` with empty fields, because the
    two states are different answers and a later caller has to tell them apart:
    no section means "this estate keeps no journal, warn and carry on", while a
    section with an unreadable store is a file to refuse. An empty-field default
    would collapse the first into the second's shape and leave the warning site
    guessing which it had.
    """
    if "reset_records" not in document:
        return None

    at = ROOT.key("reset_records")
    block = mapping(document["reset_records"], at=at)
    reject_unknown_keys(block, allowed=RESET_RECORDS_KEYS, at=at)

    return ResetRecords(
        vault=required_string(block, "vault", at=at),
        prefix=_build_prefix(block, at=at),
    )


def _build_prefix(block: dict[str, Any], *, at: KeyPath) -> str:
    """The prefix every record path is built under.

    Required rather than defaulted. A default would put records somewhere the
    file does not say, in a store the file *does* name -- so an operator reading
    the configuration could not tell where the journal is without knowing this
    module's constant, and a later change to that constant would strand every
    record already written. Naming it costs one line and removes both.

    Normalised the way a lock key's path is, and for the same reason
    (:func:`sopuli.config.secret_refs.normalise_path`): the path is a string and
    the store's document is not, so ``sopuli/resets`` and ``sopuli//resets/``
    have to become one prefix rather than two that never find each other's
    records. Normalising can only ever merge, which is the safe direction here
    exactly as it is there.

    **A traversal segment is refused here rather than normalised**, with a
    located message, which is :func:`~sopuli.config.secret_refs.parse_secret_ref`'s
    arrangement applied to the one other place a file names a store path (#344). The
    backstop in ``normalise_path`` raises a bare :class:`ValueError`, and a config
    file is entitled to be told which key is wrong; more to the point, a ``..`` under
    a prefix walks out of it, and what it would walk into here is whatever else the
    estate keeps in that store.
    """
    where = at.key("prefix")
    if "prefix" not in block:
        raise ConfigError(
            "must name the prefix records are written under",
            at=where,
            hint="a path in the store, such as `sopuli/personal-resets`",
        )

    written = string(block["prefix"], at=where)
    traversal = sorted({segment for segment in written.split("/") if segment in TRAVERSAL})
    if traversal:
        raise ConfigError(
            f"prefix {written!r} contains "
            f"{', '.join(repr(one) for one in traversal)} as a path segment",
            at=where,
            hint=(
                "write the path records actually live at -- a relative segment resolves "
                "somewhere else on the way to the store, so records would be written "
                "outside the prefix this file names"
            ),
        )

    prefix = normalise_path(written)
    if not prefix:
        raise ConfigError(
            "must name the prefix records are written under",
            at=where,
            hint="a path in the store, such as `sopuli/personal-resets`",
        )
    return prefix

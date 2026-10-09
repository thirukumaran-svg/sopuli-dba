"""Reading a previous run's document back in, for ``creds apply --repair``.

The first place the tool **consumes** its own JSON output, which is worth
noticing rather than discovering: ``03-json-output.md`` §8's compatibility rule
now cuts both ways. A document from an older minor version has to stay readable
here, so nothing below requires a property the schema marks optional, and
nothing branches on ``schema_version``.

What the flag is for, and what it is not (UC-1 §``--repair``; decision #264):

**It buys logins, not capability.** ``creds apply`` is already idempotent, so an
unnarrowed repair converges the estate correctly and expensively -- one login per
account per target, against the failed-login counter UC-1 §7 exists to protect.
Repairing one PDB in an estate of twenty-one spends twenty-one.

**Staleness is a warning, not a gate.** Two properties bound it before any rule
is written: the pair set can only ever *narrow* (invariant 5, and
:func:`~sopuli.config.selection.filter_to_pairs` drops a pair the config no
longer declares), and a pair since repaired costs one login and reports
``changed: false``. Acting on a stale document is therefore wasteful rather than
dangerous, and a threshold that refused would have to be wrong for somebody --
the run it stopped would have been safe.

**A document describing a different estate is refused**, because it is the one
failure those two properties do not catch. That check reads
``invocation.config_files``, *not* ``config.sources[]``: the ``config`` section
is emitted by ``config show`` and ``target list`` only, so it is absent from
every document this flag can be handed. A document from a build that did not
write ``config_files`` carries none, and is refused for the reason below rather
than waved through.

Refusals here are :class:`~sopuli.config.errors.ArgumentError`, so exit 2 and no
run document (J7). That is the same treatment ``--target nosuch`` gets from
:func:`~sopuli.config.selection.refuse_unknown`, and for the same reason: what
``--repair`` feeds is a *filter*, so a filter that does not resolve is an
invocation that did not resolve. Putting it on exit 9 would have said "fix your
configuration" about a run whose configuration is fine.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sopuli.clock import utc_now
from sopuli.config.errors import ROOT, ArgumentError
from sopuli.config.selection import AccountTarget
from sopuli.diagnostics import REPAIR_DOCUMENT_STALE
from sopuli.output.document import Diagnostic

#: Where a ``--repair`` refusal points. Renders as the option the operator typed,
#: which is where they have to go and fix it -- the same arrangement
#: ``AT_SELECT`` has.
AT_REPAIR = ROOT.key("--repair")

#: The commands whose documents describe an estate this flag can act on. A
#: ``creds generate`` document names accounts too, and asked no database
#: anything -- every row would be unconfirmed, which is not the same claim.
PRODUCERS = ("creds.apply", "creds.check")

#: The states that count as confirmed. Everything else in ``results[]`` is a
#: pair to repair -- ``03-json-output.md`` §7's recipe for the same set, kept in
#: step with it deliberately: an operator filtering by hand and this flag must
#: not disagree about what a partial run left behind.
#:
#: **The filter is the row's state, never the document's exit code**, and that is
#: deliberate rather than an omission (decision #264). Refusing a producer by exit
#: code would refuse an ``apply`` that exited 1 -- every target failed, nothing
#: changed anywhere -- which is the document most worth repairing from. It would
#: also refuse a ``check`` that exited 1 because one target was unreachable, where
#: retrying is exactly the remedy. Nothing is lost by accepting them: ``apply``
#: verifies every pair before it touches it, and invariant 5 still bounds what it
#: can reach.
#:
#: ``ROLLOVER_ACTIVE`` is confirmed because the window is open and both passwords
#: authenticate: the target took the new one, and what remains is
#: ``creds finish-rollover`` rather than an apply.
CONFIRMED = ("IN_SYNC", "ROLLOVER_ACTIVE")

#: Past this, the age is worth saying out loud. Not a threshold that refuses --
#: see the module docstring -- so it is chosen to be roughly "older than a
#: working day", the point at which an operator may be holding yesterday's
#: incident rather than this one's.
STALE_AFTER = timedelta(hours=12)


@dataclass(frozen=True)
class RepairSet:
    """What a previous run left unconfirmed, and where it came from."""

    #: The (account, target) pairs to narrow this run to. Possibly empty: a
    #: document whose every row confirmed is a valid thing to hand this flag,
    #: and the run it produces does nothing and says so.
    pairs: tuple[AccountTarget, ...]
    #: The document's own ``command``, for the message that reports what was
    #: read -- repairing from a ``check`` and from an ``apply`` are different
    #: enough that the operator should see which they handed over.
    command: str
    #: How old the document is, or ``None`` when it carries no usable timestamp.
    #: Absent rather than zero, so "no age to report" cannot be read as "fresh".
    age: timedelta | None
    #: The path as given, for messages.
    path: Path


def read(path: Path, *, sources: Sequence[Path]) -> RepairSet:
    """Load a run document and reduce it to the pairs it left unconfirmed.

    ``sources`` is what *this* run loaded, from ``Invocation.sources``. Compared
    against the document's ``invocation.config_files``, which the same producer
    wrote, so the two are the same kind of thing rather than one being the
    command line and the other the resolved set.
    """
    document = _load(path)
    _refuse_foreign(document, path=path, sources=sources)
    return RepairSet(
        pairs=_unconfirmed(document),
        command=str(document.get("command", "")),
        age=_age(document),
        path=path,
    )


def staleness(found: RepairSet) -> Diagnostic | None:
    """The age warning, or nothing when the document is recent enough.

    A diagnostic rather than a refusal, and it names the age rather than
    quoting a threshold: what the reader does with "eleven days old" is decide
    whether that estate is still the one they are looking at, which no constant
    in this file can decide for them.
    """
    if found.age is None or found.age < STALE_AFTER:
        return None
    return Diagnostic(
        level="warning",
        code=REPAIR_DOCUMENT_STALE,
        message=(
            f"{found.path}: this document is {_span(found.age)} old, so the run it "
            f"describes may not be the estate's current state -- a pair since repaired "
            f"costs one login and reports changed: false"
        ),
    )


def _load(path: Path) -> dict[str, Any]:
    """The document, or an ArgumentError naming what is wrong with the file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as problem:
        raise ArgumentError(
            f"{path}: cannot be read ({problem.strerror or problem})",
            at=AT_REPAIR,
            hint="pass the path to a `creds apply` or `creds check` run document",
        ) from problem

    try:
        document = json.loads(text)
    except json.JSONDecodeError as problem:
        raise ArgumentError(
            f"{path}: is not JSON (line {problem.lineno})",
            at=AT_REPAIR,
            hint="this flag reads a run document, which is what `--output json` writes",
        ) from problem

    if (
        not isinstance(document, dict)
        or not isinstance(document.get("command"), str)
        or not isinstance(document.get("invocation", {}), dict)
        or not isinstance(document.get("results") or [], list)
    ):
        # Every shape this module goes on to walk, checked in one place. Without it, an
        # `invocation` that was a string would reach `_refuse_foreign` and raise
        # `AttributeError`, and a `config_files` holding numbers would reach
        # `os.path.abspath` and raise `TypeError` -- both exit 1 with a traceback, from
        # a reader whose whole contract is that a file it cannot use is exit 2 with a
        # message.
        raise ArgumentError(
            f"{path}: is JSON, but not a run document",
            at=AT_REPAIR,
            hint="a run document has `command`, `invocation` and `results` at its top level",
        )

    command = document["command"]
    if command not in PRODUCERS:
        named = " or ".join(f"`{one}`" for one in PRODUCERS)
        raise ArgumentError(
            f"{path}: was produced by `{command}`, which reports no repair set",
            at=AT_REPAIR,
            hint=(
                f"pass a document from {named} -- an apply that exited 4, or a check that exited 3"
            ),
        )
    return document


def _refuse_foreign(document: dict[str, Any], *, path: Path, sources: Sequence[Path]) -> None:
    """Refuse a document produced over a different configuration.

    The one failure the narrowing properties do not catch: a repair aimed at the
    wrong estate names pairs that may well exist in this one, and would then act
    on them.

    **A document carrying no ``config_files`` is refused rather than trusted.** A
    document from a build that did not write the field is in that position. The
    check is on whether the field is *there*, not on what version wrote it, so
    nothing here needs to know when the field arrived -- which is invariant 3's
    habit applied to a document instead of a database.
    """
    declared = document.get("invocation", {}).get("config_files")
    if (
        not declared
        or not isinstance(declared, list)
        or not all(isinstance(one, str) for one in declared)
    ):
        raise ArgumentError(
            f"{path}: names no usable config files, so it cannot be shown to describe this estate",
            at=AT_REPAIR,
            hint=(
                "`invocation.config_files` arrived in #402 and is a list of paths -- re-run "
                "the command that produced this document to get one that carries it"
            ),
        )

    mine = [_absolute(str(one)) for one in sources]
    theirs = [_absolute(one) for one in declared]
    if _comparable(theirs) != _comparable(mine):
        # Both sides shown normalised. The document's paths are resolved by its
        # producer, but this run's may be relative as typed, and a hint that compared a
        # resolved list against a bare `estate.yaml` would ask the reader to do the
        # normalising in their head.
        raise ArgumentError(
            f"{path}: was produced over a different configuration",
            at=AT_REPAIR,
            hint=f"produced over {', '.join(theirs)}; this run resolves {', '.join(mine)}",
        )


def _absolute(path: str) -> str:
    """One path, made absolute and user-expanded, but still readable.

    ``abspath`` resolves against *this* run's working directory, which is right for
    this run's own sources and meaningless for the document's -- those are resolved
    by their producer before being written. A relative entry in a document therefore
    stays relative here and fails the comparison, which is the intended answer: it
    came from a build that did not record where it was standing.
    """
    return os.path.abspath(os.path.expanduser(path))


def _comparable(paths: Any) -> tuple[str, ...]:
    """The same paths reduced to what may be *compared*, order preserved.

    Split from :func:`_absolute` so the message can show a path a reader
    recognises: ``normcase`` lower-cases on Windows, and a hint quoting a
    lower-cased drive and home directory reads as a bug rather than as a
    comparison.

    ``normcase`` because Windows is case- and separator-insensitive and the two
    runs may have spelled one path either way; ``abspath`` for *this* run's
    side, which is whatever was typed on the command line.

    **It does not make the comparison sound on its own.** ``abspath`` runs during
    the repair, so it resolves against the repairing run's working directory --
    which tells you nothing about the one the document was written in, so two
    different files both called ``estate.yaml`` would compare equal. The producer
    resolves before writing, and that is what makes the comparison sound; this is
    for spelling.

    Order is kept rather than sorted: it is the layering order
    (``01-configuration.md`` §5), so two runs over the same files in the
    opposite order resolved different settings and are not the same estate.
    """
    return tuple(os.path.normcase(one) for one in paths)


def _unconfirmed(document: dict[str, Any]) -> tuple[AccountTarget, ...]:
    """The (account, target) pairs whose state is not one of :data:`CONFIRMED`.

    Rows missing an account or a target are skipped rather than refused: both
    are required by the schema, so a document without them is malformed in a way
    this flag has no better answer to than acting on the rows that are whole.
    """
    found: list[AccountTarget] = []
    for row in document.get("results") or ():
        if not isinstance(row, dict):
            continue
        account, target = row.get("account"), row.get("target")
        if account and target and row.get("state") not in CONFIRMED:
            found.append((str(account), str(target)))
    return tuple(found)


def _age(document: dict[str, Any]) -> timedelta | None:
    """How long ago the run *finished*, or started where it never said.

    ``finished_at`` is the honest end of the run and is what a reader means by
    "how old is this". It is optional in the schema, so ``started_at`` is the
    fallback, and a document carrying neither reports no age at all.
    """
    invocation = document.get("invocation", {})
    for key in ("finished_at", "started_at"):
        stamp = invocation.get(key)
        if not isinstance(stamp, str):
            continue
        try:
            when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            continue
        return utc_now() - when
    return None


def _span(age: timedelta) -> str:
    """An age in the largest unit that does not make it sound precise."""
    days = age.days
    if days >= 1:
        return f"{days} day{'s' if days != 1 else ''}"
    hours = int(age.total_seconds() // 3600)
    return f"{hours} hour{'s' if hours != 1 else ''}"

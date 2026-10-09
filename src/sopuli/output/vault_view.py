"""The run document's ``vaults`` section, and what ``doctor`` prints.

P4 names vault reachability and clock skew in the same breath as client presence
and ``TNS_ADMIN``, and the two halves of that sentence belong together for a
reason that is not obvious: the skew is not a health nicety. `sopuli/lock/` puts
an expiry on every lease and compares it against *this* machine's clock, with
:data:`~sopuli.lock.record.CLOCK_SKEW` allowed for the two disagreeing. A host
that is minutes out takes over locks that are still live, or refuses ones long
dead, and the failure presents as a locking bug rather than as an NTP problem.
So the number here is the assumption the lock rests on, measured.

**Its own section, because it is neither per-target nor per-account.** The same
reasoning as ``install``: a vault does not appear in ``targets[]`` and has no
``account``, so widening either would have meant a field that means nothing for
most of its rows.

**Present on every ``doctor`` run, empty array included**, which is ``install``'s
rule rather than ``wallet``'s. The two differ because the questions do: a wallet
matters only to an estate that uses ``auth: external``, while every estate that
does anything at all has stores, and a section that appeared only when one was
unwell could never be quoted as evidence that none of them was.

**Reachability is the first fact and the only one that moves the exit code.** A
store nobody can reach fails the run at exit 1, the same as an unreachable
target: the vault is master (invariant 6), so this is a wider outage than one
dead database rather than a narrower one. A ``degraded`` store does not -- what
a reader does next is go and look at the vault, not at the network -- and a
clock outside tolerance does not either, for the reason decision P5 gives for
over-granted accounts: it is a real hazard this run did not create and cannot
fix, and refusing to survey an estate over it would block the person who ran it.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sopuli.clock import to_rfc3339
from sopuli.output.document import Error
from sopuli.output.palette import Role, absent_cell, role_for_health
from sopuli.output.table import Cell, Column, render_table
from sopuli.store.protocol import OK, UNREACHABLE
from sopuli.store.survey import VaultReport


def build(report: VaultReport, *, error: Error | None = None) -> dict[str, Any]:
    """One entry in ``vaults[]``, as ``sopuli-run-1.16.schema.json`` describes it.

    ``error`` is passed rather than derived from
    :attr:`~sopuli.store.survey.VaultReport.failure`, because building the
    document's error object is the boundary's job: an exception carries its own
    category and exit code (``03-json-output.md`` §2) and the one function that
    reads them back out lives in the CLI, beside the one that does it for a
    target.

    **``detail`` and ``error`` are not two spellings of one thing.** ``detail``
    is always the one-line answer to *why*, whichever way the store failed, so a
    reader never has to look in two places for it. ``error`` appears only where
    something **threw** -- a backend with no module, a client that is not
    installed, a refused login -- because only those carry a category and a code
    worth branching on. A store that opened fine and then answered
    ``unreachable`` has no exception behind it and no vendor code to report, and
    manufacturing one so the shape matched would be inventing a classification.

    **The skew fields are absent together or present together.** A backend that
    exposes no server time has nothing to compare, and emitting ``skew_ms: 0``
    there would be indistinguishable from two clocks that agree -- which is the
    one confusion this whole measurement exists to avoid.
    """
    entry: dict[str, Any] = {
        "vault": report.name,
        "type": report.type,
        "status": report.health.status,
        "duration_ms": report.duration_ms,
    }
    if report.health.detail is not None:
        entry["detail"] = report.health.detail
    if report.health.version is not None:
        entry["version"] = report.health.version
    if report.health.authenticated is not None:
        # Absent means *not asked*, which is a third state and not a shrug: a
        # sealed store refuses the request that would answer it, and a `false`
        # there would blame a token for a seal.
        entry["authenticated"] = report.health.authenticated
    if report.health.server_time is not None:
        entry["server_time"] = to_rfc3339(report.health.server_time)
    if report.skew is not None:
        entry["skew_ms"] = _ms(report.skew.delta)
        entry["skew_uncertain_by_ms"] = _ms(report.skew.uncertain_by)
        entry["skew_within_tolerance"] = not report.skew.beyond_tolerance
        entry["tolerance_ms"] = _ms(report.skew.tolerance)
    if error is not None:
        entry["error"] = error.to_dict()
    return entry


def _ms(value: timedelta) -> int:
    """Whole milliseconds, rounded rather than truncated.

    A skew of -1.6 s truncates towards zero to -1600 either way, but a
    *positive* 1.6 s truncates to 1600 and a naive `int()` on the seconds would
    have given 1 -- so the arithmetic is done on the whole timedelta. Rounded
    because the schema says integer and the sub-millisecond part of a
    measurement taken over a network is not information.
    """
    return round(value.total_seconds() * 1000)


def render(reports: list[VaultReport]) -> list[str]:
    """The text form: a row per store, then a line per thing worth saying.

    A table rather than the key-value block ``wallet`` uses, because there is one
    wallet per run and there may be a dozen stores -- and the columns are the
    questions somebody scans for: is it there, can I authenticate to it, do our
    clocks agree.

    ``SKEW`` carries its units and its sign, because both are the answer: the
    sign says which clock to go and fix, and a bare number in a column headed
    with no unit gets read as seconds by half its readers.
    """
    lines = ["vaults"]
    columns = [
        Column("VAULT"),
        Column("TYPE"),
        Column("STATUS"),
        Column("AUTH"),
        Column("SKEW"),
    ]
    rows: list[list[Cell | str]] = [
        [
            report.name,
            report.type,
            _status(report),
            _auth(report),
            _skew(report),
        ]
        for report in reports
    ]
    lines.extend(f"  {line}" for line in render_table(columns, rows))
    lines.extend(f"  {line}" for line in _findings(reports))
    lines.append("")
    return lines


def _status(report: VaultReport) -> Cell | str:
    """The store's health, coloured by :func:`~sopuli.output.palette.role_for_health`.

    One function decides, for the reason `role_for_state` is one function: this
    word appears in `doctor` and in every `creds` run's ``vaults`` section, and
    a store that is ``degraded`` in one and plain in the other would be the
    inconsistency decision #395 rules out, one vocabulary over.
    """
    role = role_for_health(report.health.status)
    return Cell(report.health.status, role) if role is not None else report.health.status


def _auth(report: VaultReport) -> Cell | str:
    """Three states in one column, and none of them collapsible.

    ``-`` is *not asked*, not *no*: a sealed store refuses the lookup that would
    answer it, and printing "no" there sends somebody to re-issue a credential
    that was never the problem.
    """
    if report.health.authenticated is None:
        return absent_cell(None)
    return "yes" if report.health.authenticated else Cell("no", Role.BAD)


def _skew(report: VaultReport) -> Cell | str:
    """The clock difference, or why there is not one.

    ``-`` for a backend that exposes no server time. That is a different answer
    from ``0ms`` and the column has to keep them apart, because a reader
    scanning for trouble treats a number as a measurement somebody took.
    """
    if report.skew is None:
        return absent_cell(None)
    if not report.skew.beyond_tolerance:
        return f"{_ms(report.skew.delta):+d}ms"
    # Beyond tolerance is `attention` and not `bad`: the store answered and the
    # run works, and what is wrong is usually this machine's clock rather than
    # anything in the vault. `(!)` stays -- the colour reinforces the marker it
    # already had rather than replacing it.
    return Cell(f"{_ms(report.skew.delta):+d}ms  (!)", Role.ATTENTION)


def _findings(reports: list[VaultReport]) -> list[str]:
    """The lines worth printing only when something is wrong.

    Ordered by what stops the tool working before what merely will: a store
    nobody can reach is why the next command fails, and a clock out of tolerance
    is why a *rotation* will misjudge a lock some other day.
    """
    lines = []
    for report in reports:
        if report.health.status == UNREACHABLE:
            lines.append(f"{report.name}: {report.health.detail or 'could not be reached'}")
        elif report.health.status != OK:
            lines.append(
                f"{report.name}: {report.health.detail or 'is not able to serve this run'}"
            )
    for report in reports:
        if report.skew is not None and report.skew.beyond_tolerance:
            lines.append(
                f"{report.name}: this host's clock is {_offset(report)} the store's, "
                f"further than the {_ms(report.skew.tolerance)}ms the lock allows -- "
                f"leases will be judged against a clock that disagrees"
            )
    return lines


def _offset(report: VaultReport) -> str:
    """Which way round, in words.

    The sign alone is not enough in a sentence: a reader who has to remember
    whether positive means the store is ahead will remember it wrongly half the
    time, and the two directions are different failures -- one takes over live
    locks, the other refuses dead ones.
    """
    assert report.skew is not None
    delta = report.skew.delta
    size = abs(_ms(delta))
    return f"{size}ms {'behind' if delta > timedelta(0) else 'ahead of'}"

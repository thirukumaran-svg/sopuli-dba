"""The run document's ``wallet`` section, and what ``doctor`` prints (#215).

P4 names wallet readability in the same breath as client presence and
``TNS_ADMIN``, and the gap it closes is between *the variable is set* -- which
`doctor` already reported -- and *there is a wallet there this process can read*.
Those are different facts on every machine where a service runs as one user and a
DBA tests as another.

**Absent when nothing uses ``auth: external``**, which is most estates. A target
with a password-based ``admin.auth`` has no wallet to report on, and a section
warning about one would be noise in every document that carries it. This is the
one place where absence is the right answer rather than an empty section -- E6's
argument for reporting install shape unconditionally does not transfer, because
install shape is a fact about the machine that is always true of it, and this is
a fact about a configuration option most files never use.

**It names the directory it actually looked in**, which is the field most likely
to be the answer. ``sqlnet.ora``'s ``WALLET_LOCATION`` moves the wallet away from
``TNS_ADMIN``, and a reader checking the obvious directory needs to know the tool
looked somewhere else -- otherwise the report and the reader disagree about where
the wallet is supposed to be, and the report loses.

**Nothing here is a verdict.** The section explains a failure the connection
attempt is about to produce; it does not pre-empt it, and it moves no exit code.
"""

from __future__ import annotations

from typing import Any

from sopuli.driver.oracle.wallet import AUTO_LOGIN, WalletReport


def build(report: WalletReport) -> dict[str, Any]:
    """The ``wallet`` section, as ``sopuli-run-1.16.schema.json`` describes it.

    ``tns_admin`` and ``directory`` are nulled rather than omitted when there is
    nothing to put in them, which is the opposite of what the rest of the output
    layer does and is right here: both are *always* part of the answer, and a
    consumer asking "where did it look" must be able to tell "nowhere, the
    variable is unset" from "the producer does not report that". The optional
    fields elsewhere in the document mean *not applicable*; these mean *empty*.
    """
    return {
        "required_by": list(report.required_by),
        "tns_admin": report.tns_admin,
        "directory": report.directory,
        "from_sqlnet": report.from_sqlnet,
        "readable": report.readable,
        "files": list(report.files),
        "unreadable": list(report.unreadable),
        "auto_login": report.auto_login,
        "insecure": [name for name, _reason in report.insecure],
    }


def render(report: WalletReport) -> list[str]:
    """The text form: where it looked, what it found, and what is wrong with it.

    A key-value block rather than a table, matching the ``client`` block above it
    -- there is one wallet per run, and a table of one row with six columns is a
    table nobody reads across.
    """
    lines = ["wallet"]
    for key, value in (
        ("required by", _targets(report.required_by)),
        ("tns_admin", report.tns_admin or "(unset)"),
        ("searched", _searched(report)),
        ("found", _found(report)),
        ("auto-login", "yes" if report.auto_login else "no"),
    ):
        lines.append(f"  {key:<18}{value}")

    lines.extend(f"  {line}" for line in _findings(report))
    lines.append("")
    return lines


def _found(report: WalletReport) -> str:
    """What is there, marking what could not be read.

    Present-but-unreadable is listed rather than omitted, because the reader's
    next move differs completely: a missing wallet is somebody to ask for one,
    and an unreadable one is already sitting where it should be.
    """
    names = [*report.files, *(f"{name} (unreadable)" for name in report.unreadable)]
    return ", ".join(names) or "nothing"


def _searched(report: WalletReport) -> str:
    """Where it looked, and why there rather than somewhere else."""
    if report.directory is None:
        return "(nowhere -- TNS_ADMIN is unset)"
    if report.from_sqlnet:
        return f"{report.directory}  (from sqlnet.ora WALLET_LOCATION)"
    return report.directory


def _targets(names: tuple[str, ...]) -> str:
    """The external targets, named or counted.

    Named while there are few, because the reader's next move is to open the
    config at that entry. Counted past three, because a generated ``target_sets:``
    entry can put two dozen on one line and turn the block into a paragraph.
    """
    if len(names) <= 3:
        return ", ".join(names)
    return f"{len(names)} targets, including {', '.join(names[:3])}"


def _findings(report: WalletReport) -> list[str]:
    """The lines worth printing only when something is wrong.

    Ordered by what stops the tool working before what is merely unsafe: a
    missing wallet is why the next connection fails, and a wallet other people
    can read is a problem that has been true for a while and will still be true
    after this run.
    """
    lines = []
    if report.directory is None:
        lines.append(
            "no wallet directory to check: $TNS_ADMIN is unset and no sqlnet.ora "
            "named one, so external authentication has nowhere to read from"
        )
    elif not report.readable:
        lines.append(f"cannot read {report.directory}: it is missing, or not readable by this user")
    elif AUTO_LOGIN in report.unreadable:
        lines.append(
            f"{AUTO_LOGIN} is in {report.directory} and this process cannot read it: "
            f"check who owns it, and which account this is running as"
        )
    elif not report.auto_login:
        missing = f"no readable {AUTO_LOGIN} in {report.directory}"
        present = sorted({*report.files, *report.unreadable})
        if present:
            lines.append(
                f"{missing} -- only {', '.join(present)}, which needs a passphrase "
                f"this tool has no way to supply"
            )
        else:
            lines.append(f"{missing}, and no wallet of any kind")

    for name, reason in report.insecure:
        lines.append(
            f"{name} {reason}: an auto-login wallet is a credential, and this one is not private"
        )
    return lines

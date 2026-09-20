"""Rendering what a password policy produces (§8, ``policy sample``).

A policy is a handful of numbers and a charset name, and none of that answers the
question somebody actually has: *what do the passwords look like*. This renders
samples so they can answer it — offline, drawing from
:func:`sopuli.passwords.generate`, writing nothing anywhere.

**This module holds one of the tool's two output-layer ``reveal()`` calls, and it
is the third exception to invariant 2.** It was *the only one* until #441 built
UC-2's seen path, whose reveal lives in :mod:`sopuli.output.reset_view` and is
invariant 2's fourth exception -- narrowed more strictly than this one, because
its justification is weaker: that is a credential somebody can log in with, and
this is a sample. The rule is that no code path emits plaintext except
the vault write and the driver call; a sample is neither, and it is allowed
because *a sample is not a credential*: nothing authenticates with it, it is never
stored, and it guards nothing. What keeps the exception narrow is structural
rather than careful:

* the plaintext appears only under ``--reveal``, and only in text output
* :func:`build_section` — the ``--output json`` half — has no access to it at all,
  and the schema gives a sample no value property to put one in
* the command refuses ``--reveal`` together with ``--output json``, so the
  combination cannot be reached by a script that captures its output

The footer says the samples must not be used, because the realistic hazard is not
the printing. It is somebody liking sample 2 and pasting it into an ``ALTER USER``
by hand, at which point a password that sat in a terminal, a scrollback and
possibly a CI log becomes a live credential.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from sopuli.config.model import PasswordPolicy
from sopuli.output.palette import Role, paint
from sopuli.output.table import Cell, Column, render_table
from sopuli.passwords import ByteLimit, Properties, properties
from sopuli.secrets import Secret

#: How the class counts are abbreviated in the table. Spelled out per column would
#: be four headings wider than the numbers under them.
_ABBREVIATIONS = {"upper": "u", "lower": "l", "digit": "d", "special": "s"}

_VALUE = 40


def describe_all(
    samples: Sequence[Secret], policy: PasswordPolicy, *, limit: ByteLimit | None
) -> list[Properties]:
    """Describe every sample once, for both views.

    The text table and the JSON section are rendered from the same list, so they
    cannot disagree about a sample they are describing together.
    """
    return [properties(sample, policy, limit=limit) for sample in samples]


def render_samples(
    paths: Sequence[Path],
    name: str,
    policy: PasswordPolicy,
    samples: Sequence[Secret],
    described: Sequence[Properties],
    *,
    limit: ByteLimit | None,
    reveal: bool,
) -> str:
    """The human view: the policy, one row per sample, and a footer that warns."""
    lines = [f"config: {paths[0]}"]
    lines.extend(f"        {path} (layered)" for path in paths[1:])
    lines.append(f"policy: {name}    {_summarise(policy)}")
    if limit is not None:
        lines.append(f"limit:  {limit.max_bytes} bytes in {limit.encoding}")

    columns = [Column("#"), Column("CHARS"), Column("BYTES"), Column("CLASSES")]
    if reveal:
        columns.append(Column("PASSWORD", _VALUE))

    rows: list[list[Cell | str]] = []
    for index, (sample, description) in enumerate(zip(samples, described, strict=True), start=1):
        row: list[Cell | str] = [
            str(index),
            str(description.characters),
            _or_dash(description.encoded_bytes),
            _classes(description),
        ]
        if reveal:
            # Invariant 2's third exception. One of two `reveal()` calls in the
            # output layer -- `output/reset_view.py` has the fourth exception's --
            # and `tests/test_reveal_sites.py` holds the pair to exactly that.
            # See this module's docstring for why it is allowed.
            row.append(sample.reveal())
        rows.append(row)

    lines.extend(["", *render_table(columns, rows), "", _footer(described, reveal=reveal)])
    return "\n".join(lines)


def build_section(
    name: str,
    policy: PasswordPolicy,
    described: Sequence[Properties],
    *,
    limit: ByteLimit | None,
) -> dict[str, Any]:
    """The ``policy`` section of the run document.

    Takes the descriptions rather than the samples, so there is no plaintext in
    scope here to leak in the first place -- the JSON half of this module cannot
    emit a password because it never receives one.
    """
    return {
        "name": name,
        "length": policy.length,
        "charset": policy.charset,
        "first_char": policy.first_char,
        "require": dict(policy.require),
        "limit": (
            None if limit is None else {"max_bytes": limit.max_bytes, "encoding": limit.encoding}
        ),
        "samples": [
            {
                "characters": description.characters,
                "encoded_bytes": description.encoded_bytes,
                "counts": dict(description.counts),
                "compliant": description.compliant,
            }
            for description in described
        ],
    }


def _summarise(policy: PasswordPolicy) -> str:
    """The policy in one line -- what was asked for, not what came out."""
    parts = [f"length {policy.length}", policy.charset or "alnum_safe (default)"]
    if policy.first_char is not None:
        parts.append(f"first_char {policy.first_char}")
    if policy.require:
        parts.append(
            "require " + ", ".join(f"{key} {value}" for key, value in policy.require if value)
        )
    return ", ".join(parts)


def _classes(description: Properties) -> str:
    """``u4 l13 d4 s3`` -- the composition, compactly."""
    counts = dict(description.counts)
    return " ".join(
        f"{short}{counts.get(name, 0)}" for name, short in _ABBREVIATIONS.items() if name in counts
    )


def _footer(described: Sequence[Properties], *, reveal: bool) -> str:
    """What the reader is looking at, and what they must not do with it."""
    total = len(described)
    failing = sum(1 for description in described if not description.compliant)
    count = f"{total} sample{'' if total == 1 else 's'}"
    # "all compliant" of one sample reads like a summary of something larger.
    verdict = (
        f"{failing} not compliant" if failing else "compliant" if total == 1 else "all compliant"
    )
    if not reveal:
        return f"{count}, {verdict}. Not stored anywhere; pass --reveal to print them."
    return paint(
        f"{count}, {verdict}. Samples only -- not stored anywhere, and not for use.",
        Role.NOTABLE,
    )


def _or_dash(value: int | None) -> Cell | str:
    """A byte count, or a muted placeholder where no limit was given."""
    return str(value) if value is not None else Cell("-", Role.MUTED)

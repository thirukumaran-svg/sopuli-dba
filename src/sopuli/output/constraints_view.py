"""The ``constraints`` section, and the line an operator reads (#317, UC-1 §4 step 2).

What `creds generate` asked the estate before it drew, as a document section and
as one sentence. Same arrangement as :mod:`sopuli.output.install_view`: the shape
here, the decision in :mod:`sopuli.constraints`.

**It reports readings and never a verdict.** Nothing in the section says a
password will be accepted or refused -- a verify function is arbitrary PL/SQL
that cannot be consulted (invariants 13 and 14) and a reuse history is hashed. A
consumer wanting *what this run could not check* branches on the diagnostic codes
(`SOPULI-W016`, `SOPULI-W017`); this is the evidence underneath them.

**A section rather than more warnings.** #216's rule for `doctor`: a diagnostic
is for what the exit code cannot tell you, and everything else belongs in the
section that names it. A run that answers "what may a password be here" with
eleven warnings has no place to put the eleven answers.

**Present whenever the question was asked**, including where nothing answered --
which is `install`'s rule and right for the same reason: the section is evidence
that the estate was consulted, and one that appeared only when something was
wrong could never be quoted as proof that nothing was. ``--offline`` is the
exception, and the only one: there the question was not asked.

**Deliberately not coloured** (#395), for the reason
:mod:`sopuli.output.wallet_view` gives: this section is one line of prose, and
`render_constraints` returns a sentence rather than a row. Its caveats print
themselves as warnings with codes of their own (`SOPULI-W015`, `SOPULI-W016`,
`SOPULI-W017`), which is where a reader looking for trouble is already sent.
"""

from __future__ import annotations

from typing import Any

from sopuli.constraints import NAMED, POLICY, UNREAD, AccountConstraints, Constraints
from sopuli.passwords import ByteLimit

__all__ = ["build_constraints", "render_constraints"]


def build_constraints(found: Constraints) -> dict[str, Any] | None:
    """The ``constraints`` section, or ``None`` where nothing was asked.

    ``None`` for ``--offline`` alone. The document omits the section entirely
    there, which *means* something rather than merely leaving something out: the
    run declined to consult the estate, and an empty section would say it
    consulted one and learned nothing -- which is
    :data:`~sopuli.constraints.POLICY`, a different run.
    """
    if found.source == UNREAD:
        return None

    section: dict[str, Any] = {"source": found.source}
    limit = found.drawing_limit
    if limit is not None:
        # The count that governed the draw, at the top rather than left to be
        # worked out from `targets[]`. It is what a reader came for, and
        # recomputing it means reimplementing the partial order this section
        # exists to stop anybody reimplementing.
        section["max_password_bytes"] = limit.max_bytes
        if limit.charset is not None:
            section["character_set"] = limit.charset
    if found.strictest_target is not None:
        section["strictest_target"] = found.strictest_target
    section["targets"] = [
        *(_answered(target, limit) for target, limit in found.readings),
        *({"target": target, "reachable": False} for target in found.unreachable),
    ]
    accounts = [_account(target, one) for target, one in found.accounts]
    if accounts:
        section["accounts"] = accounts
    return section


def _answered(target: str, limit: ByteLimit) -> dict[str, Any]:
    """One target that answered, with its own limit rather than the run's.

    Every reading is kept for the reason :mod:`sopuli.constraints` keeps them: a
    limit is a byte count *and* a character set, so the estate's readings do not
    collapse into one and a section that showed only the winner would be hiding
    the ones a supplied password still has to satisfy.
    """
    entry: dict[str, Any] = {
        "target": target,
        "reachable": True,
        "max_password_bytes": limit.max_bytes,
        # The codec the count was measured in, which is not always implied by the
        # character set: `limits.py` falls back to ASCII for a character set it
        # does not map, deliberately, and a reader whose database refuses a
        # non-ASCII password wants to see that here rather than deduce it.
        "measured_as": limit.encoding,
    }
    if limit.charset is not None:
        entry["character_set"] = limit.charset
    return entry


def _account(target: str, one: AccountConstraints) -> dict[str, Any]:
    """One account's profile constraints, none of which gate anything.

    ``verify_function`` is an object with a ``state`` rather than a nullable
    string, and that is the whole of what #317 asked for here: ``named``,
    ``none`` and ``unknown`` are three answers, and a missing string would merge
    the last two into the one reading that misleads -- *nothing will judge this
    password*.
    """
    entry: dict[str, Any] = {"target": target, "account": one.account}
    if one.profile is not None:
        entry["profile"] = one.profile
    verify: dict[str, Any] = {"state": one.verify_state}
    if one.verify_state == NAMED:
        verify["name"] = one.verify_function
    entry["verify_function"] = verify
    if one.reuse_max is not None:
        entry["password_reuse_max"] = one.reuse_max
    if one.reuse_time is not None:
        entry["password_reuse_time"] = one.reuse_time
    if one.versions:
        entry["password_versions"] = list(one.versions)
    return entry


def render_constraints(found: Constraints) -> str | None:
    """One line saying what bound the draw, or ``None`` where there is nothing to say.

    Deliberately a line and not a table. The section carries a row per target and
    a row per account; what an operator reading a terminal needs before they look
    at the write table is which of §4's two answers this run got, and the
    caveats print themselves as warnings.
    """
    if found.source == UNREAD:
        return None
    if found.source == POLICY:
        return (
            "constraints: no target answered ("
            + ", ".join(found.unreachable)
            + "); the policy's declared length governs"
        )
    limit = found.drawing_limit
    if limit is None:  # pragma: no cover - `source` is TARGETS only with readings
        return None
    where = found.strictest_target or ", ".join(found.read)
    line = f"constraints: {limit.max_bytes} bytes in {limit.described}, from {where}"
    if found.partial:
        return line + "; not read from " + ", ".join(found.unreachable)
    return line

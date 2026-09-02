"""Row-level findings rendered under a table (#309).

`check` and `creds status` both report things that belong to one account but do
not fit in a column -- a grace period and the date it ends, so far. In
``--output json`` they are ``results[].warnings[]``; here they are the block that
makes them visible to somebody reading a terminal, which is what UC-1 §6.4 means
by *surfaced*.

**One renderer for both verbs**, because it is one block: `config validate`
already prints warnings this way under its summary, and a third spelling of the
same idea would be a third thing to keep consistent.
"""

from __future__ import annotations

from collections.abc import Sequence

from sopuli.output.palette import Role, paint

__all__ = ["render_notices"]


def render_notices(notices: Sequence[str]) -> list[str]:
    """Findings that belong to a row but do not fit in it.

    A table column cannot hold a sentence with a date in it, and a warning nobody
    can see in the default output is not surfaced -- which is what UC-1 §6.4 asks
    for and what `results[].warnings[]` alone does not give a person reading a
    terminal (#309).

    The same block `config validate` prints under its summary, and deliberately
    the same words: an operator who has read one of these has read all of them.
    Empty for the ordinary run, so nothing is added to the output that says
    nothing.
    """
    if not notices:
        return []
    body = [f"  {line}" for notice in notices for line in notice.splitlines()]
    count = "1 note" if len(notices) == 1 else f"{len(notices)} notes"
    return ["", paint(f"{count}:", Role.NOTABLE), *body]

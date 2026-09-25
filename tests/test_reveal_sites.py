"""Every place the tool turns a `Secret` back into plaintext, pinned (#441).

`CLAUDE.md` invariant 2 permits the vault write, the driver call, `policy sample
--reveal`, UC-2's seen reset, and -- since #444 -- the wrapping token an unseen
delivery hands back. Each is argued for in the module
that holds it, and each is supposed to stay where it is -- #439's first guard is
literally *one reveal site, and there must be no third*.

**Nothing enforced that until this file.** The count lived in three docstrings,
one of which said "the only `reveal()` call in the tool" and was true when it was
written and false the day UC-2's seen path landed. A guard that is a sentence in
a docstring is a guard that decays silently, which is the failure
`tests/settings/test_settings_are_wired.py` exists for one layer over -- and this
is the same sweep applied to the invariant that matters most.

**A tripwire, not a proof.** What it checks is where `.reveal()` is *called*, by
parsing the tree rather than grepping, so a call inside a comment or a docstring
does not count and a call spelled `getattr(secret, "reveal")()` would not be
caught. The four real ones are all ordinary attribute calls; catching the clever
form needs dataflow analysis, and every instance so far has been the simple one.

Adding a site means adding it here **and** to invariant 2, in the same change.
That is the point: the edit is small, and it is impossible to make by accident.

**Two classes of site, and the list has always held both.** Invariant 2 enumerates
the paths a *password* may take, and those are the entries that carry a number. The
others -- the vault login, the token on the wire, and since #442 a webhook URL --
are credentials the tool *presents to a service it is calling*, which is a separate
and already-accepted class: a credential that never reached the wire would
authenticate nothing. Adding one of those is not a new exception to invariant 2, and
saying so here is what keeps somebody from either renumbering the invariant or
sneaking a password path in under this heading.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "sopuli"

#: The permitted sites, by module path and by why invariant 2 allows each.
#:
#: Keyed by path rather than counted, because a count would stay green while a
#: reveal moved from the driver call into, say, a log formatter -- and the
#: location is the entire argument in three of the four cases.
PERMITTED = {
    "driver/oracle/client.py": "the driver call -- invariant 2's second exception",
    "output/policy_view.py": "`policy sample --reveal` -- the third; a sample is not a credential",
    "output/reset_view.py": "UC-2's seen reset -- the fourth, under five structural guards (#439)",
    "output/delivery_view.py": (
        "the wrapping token -- not a password, but UC-2 6.1's retrieval credential, "
        "which the rule covers because it is about reach rather than value (#444)"
    ),
    "delivery/vault_wrapped.py": (
        "the vault write -- invariant 2's first exception, reached as a wrap rather "
        "than a KV put (#444)"
    ),
    "passwords.py": "generation's own validation, which never leaves the process",
    "store/credentials.py": "the vault write -- invariant 2's first exception",
    "store/hashicorp/_auth.py": "the vault login, which is the write's other half",
    "store/hashicorp/_transport.py": "the token on the wire, for the same reason",
    "notify/webhook.py": (
        "a webhook URL on the wire (#442) -- `_transport.py`'s reason, not a sixth "
        "numbered exception: invariant 2 enumerates the paths a *password* may take, "
        "and material the tool presents to a service it is calling has always been a "
        "separate already-accepted class. A chat URL is a credential (C9), so it is a "
        "`Secret`, and it is revealed where every credential is -- at the wire"
    ),
    "driver/oracle/statements.py": "building the DDL, which is the driver call's text",
    "driver/oracle/session.py": "issuing that DDL -- the one cursor.execute it reaches",
}


def _reveal_sites() -> dict[str, list[int]]:
    """Every ``.reveal()`` call in ``src/``, by module path.

    Parsed rather than grepped: `secrets.py` documents the method with a doctest
    and half the codebase mentions it in prose, so a text search reports a dozen
    files that call nothing.
    """
    found: dict[str, list[int]] = {}
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "reveal"
            ):
                found.setdefault(path.relative_to(SRC).as_posix(), []).append(node.lineno)
    return found


def test_every_reveal_site_is_one_invariant_2_permits() -> None:
    """The sweep itself. A new site fails here until somebody argues for it."""
    unexpected = {
        where: lines for where, lines in _reveal_sites().items() if where not in PERMITTED
    }

    assert not unexpected, (
        f"plaintext is revealed somewhere invariant 2 does not permit: {unexpected}. "
        f"Either move it behind one of the permitted sites, or -- if it is genuinely a "
        f"fifth exception -- say so in `CLAUDE.md` invariant 2 and add it to PERMITTED "
        f"here. A fifth exception is a decision, not an implementation detail."
    )


def test_the_permitted_list_has_not_gone_stale() -> None:
    """The other direction, and the one that lasts.

    A path listed here that no longer reveals anything is a permission nobody
    needs, and leaving it would make the next reveal added to that module invisible
    to the test above. Same argument as `inert_reason`'s second test one layer over.
    """
    sites = _reveal_sites()
    stale = sorted(where for where in PERMITTED if where not in sites)

    assert not stale, (
        f"listed as permitted and revealing nothing: {stale}. Delete the entry -- a "
        f"stale permission is what lets the next one in without being noticed."
    )


def test_the_seen_path_reveals_in_exactly_one_place() -> None:
    """#439's first guard, asserted rather than described.

    The whole of UC-2's fourth exception is that there is *one* site, in the seen
    path's own view module, reachable only where the delivery method is `manual`.
    Two calls in that file would be two things to keep reachable-only, which is
    the shape the guard exists to prevent.
    """
    assert len(_reveal_sites()["output/reset_view.py"]) == 1


def test_the_sweep_finds_a_call_it_should() -> None:
    """A detector that answered "nothing anywhere" would make both tests above
    vacuous for ever. The driver call is the one site that cannot go away: every
    connection this tool opens goes through it."""
    assert _reveal_sites().get("driver/oracle/client.py")

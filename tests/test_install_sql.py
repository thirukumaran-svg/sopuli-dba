"""`sql/oracle/00_install.sql` against what the tool says it needs (#226).

Tier 0, and it needs no database — which is the point. The script cannot be
executed from *here*: it is SQL*Plus rather than SQL. `DEFINE`/`&substitution`,
`COLUMN … NEW_VALUE`, `PROMPT`, `SET SERVEROUTPUT` and `/` terminators are all
client commands, and `python-oracledb` sends statements to a server that has
never heard of any of them. Running it properly means a real `sqlplus`: the
tier-1 container ships one, and automating that is #229.

Executing the file is a different test, not a better one. That one proves it
runs; this one proves it grants the right things, in under a second and with no
container. #231 is the argument for keeping both — running the scripts by hand
found four bugs this module cannot see, and not one of them was grant drift,
which is the thing it does see.

What can be checked without running it is the thing most likely to be wrong, and
the only thing that gets *worse* over time: **whether the grants the script issues
are still the grants the tool needs.** Two lists in two languages in two files,
maintained by hand, is a drift that shows up as a service account installed
exactly per the documentation and refused by the tool that documented it.

So the assertion runs both ways:

* every grant `sopuli/driver/oracle/privileges.py` requires appears in the script,
  or an operator who followed the install ends up short;
* every grant the script issues is one the tool asked for, or the documented
  install is wider than §2 and `--check-privileges` will say so about an account
  that did nothing wrong.

The second direction is the one nobody writes unprompted, and it is the one that
catches a grant added to the script for a feature that was later cut.
"""

from __future__ import annotations

import re
from pathlib import Path

from sopuli.driver.oracle.privileges import (
    REQUIRED_PRIVILEGES,
    REQUIRED_READS,
    ROOT_ONLY_READS,
)

SCRIPT = Path(__file__).resolve().parents[1] / "sql" / "oracle" / "00_install.sql"

#: Grants the script issues behind a `DEFINE` an operator sets to `Y`, which are
#: therefore **not** part of §2's default set and must not be required.
#:
#: `SYS.USER$` is #86's decision: optional, capability-probed, and its absence is
#: the ordinary configuration rather than a fault. `SET CONTAINER` is §2's other
#: optional row, for a site whose tool switches containers on an open session
#: rather than connecting to each PDB service.
OPTIONAL = frozenset({"SELECT ON USER$", "SET CONTAINER"})

#: `GRANT <what> TO <account>`, wherever it appears -- bare, or inside the
#: `EXECUTE IMMEDIATE` of a PL/SQL block, which is how the script issues the ones
#: that depend on a mode. Deliberately does not try to evaluate the conditions:
#: what is asserted is the *set of grants the file contains*, and a condition
#: this parser misread would be a condition the test silently stopped checking.
#:
#: **Single-line, and not by accident.** The first draft used `DOTALL` and
#: matched the file's own header -- "create and grant the service account ... TO"
#: -- across forty lines of comment. Every grant this script issues sits on one
#: line, so spanning them buys nothing and costs the parser its footing.
GRANT = re.compile(r"GRANT\s+(.+?)\s+TO\s+[&'A-Za-z_]", re.IGNORECASE)

#: A `--` comment to end of line. Stripped before matching, for the reason above:
#: prose about granting things is not a grant.
COMMENT = re.compile(r"--.*$", re.MULTILINE)


def granted() -> frozenset[str]:
    """Every grant the script issues, normalised to the tool's own spelling.

    Two normalisations, and both are places the script and the tool legitimately
    differ rather than disagree:

    * **the `SYS.` qualifier.** The script grants `SELECT ON SYS.DBA_USERS`
      because a grant needs the owner; the tool reads `dba_users` through the
      public synonym and names the grant without it.
    * **`V_$` versus `V$`.** A grant must name the underlying view (`SYS.V_$PDBS`)
      because `V$PDBS` is a synonym and cannot be granted on. The tool spells it
      the same way in `REQUIRED_READS` for exactly this reason, so this leaves it
      alone -- noted because the temptation is to normalise it away, and doing so
      would make the test pass against a script that granted something ungrantable.
    """
    text = COMMENT.sub("", SCRIPT.read_text(encoding="utf-8"))
    found = set()
    for what in GRANT.findall(text):
        cleaned = " ".join(what.split()).upper().replace("SYS.", "")
        found.add(cleaned)
    return frozenset(found)


def required() -> frozenset[str]:
    """§2's default set: what an install must produce for the tool to work."""
    return frozenset(REQUIRED_PRIVILEGES) | frozenset(REQUIRED_READS)


def test_the_script_exists_and_issues_grants() -> None:
    """A guard on the parser rather than on the script.

    Every assertion below is a set comparison, and a regex that matched nothing
    would make all of them pass. That failure mode is the reason this test is
    here and not a comment: it is the one that reports green.
    """
    assert SCRIPT.exists()
    assert len(granted()) >= len(required())


def test_the_script_issues_every_grant_the_tool_requires() -> None:
    """Otherwise an operator who followed the install ends up short, and finds out
    from a verb that fails several commands later rather than from the install."""
    assert required() <= granted(), f"missing from the script: {sorted(required() - granted())}"


def test_the_script_issues_nothing_the_tool_did_not_ask_for() -> None:
    """The direction nobody writes unprompted, and the one that catches a grant
    added for a feature later cut.

    An install wider than §2 is not harmless: `doctor --check-privileges` reports
    over-granting, and it would be reporting it about an account that did exactly
    what the documentation said.
    """
    accounted = required() | frozenset(ROOT_ONLY_READS) | OPTIONAL

    assert granted() <= accounted, f"in the script and not in §2: {sorted(granted() - accounted)}"


def test_the_root_only_grant_is_in_the_script_and_not_in_the_default_set() -> None:
    """`V_$PDBS` is granted in `COMMON` mode only, which is the script's spelling
    of "the CDB root" -- and it must not be in the set every install produces, or
    a PDB install would be reported as short of a grant §2 never gives it there."""
    assert frozenset(ROOT_ONLY_READS) <= granted()
    assert not frozenset(ROOT_ONLY_READS) & required()


def test_the_optional_grants_are_optional_on_both_sides() -> None:
    """`SYS.USER$` is #86's decision -- optional, probed, and its absence ordinary.
    A script that granted it unconditionally, or a tool that required it, would
    each quietly reverse that."""
    assert not OPTIONAL & required()
    for grant in OPTIONAL:
        assert grant in granted(), f"{grant} should still be offered by the script"

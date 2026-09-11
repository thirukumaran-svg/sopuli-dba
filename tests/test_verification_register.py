"""Unverified claims, and the register that says which are still unverified (#411).

Tier 0 (``04-testing.md`` §4): reads files, opens no socket, needs no container.

**What went wrong twice.** A measured result lands in one document and the others
go on asserting the opposite. #408 struck ``--limit`` from ``00-principles.md``
and left the same flag standing in four other places; #410 recorded that SQL
trace had been measured and left ``uc-01-app-credential-sync.md`` saying "SQL
trace remains untested" and ``adr-001-privilege-model.md`` saying "unchecked on
every version" -- a use case and an ADR, the two kinds of document `CLAUDE.md`
tells a reader to trust. Copilot caught both. Nothing in the repository did.

**Why a checker cannot read the prose.** "SQL trace remains untested", "SQL trace
is unchecked on every version" and the §4 table row answering them share no
reliable token, and the obvious greps are useless in the other direction:
``grep -rn unknown docs/`` is dominated by *unknown config keys*, and
``untested`` by *macOS is untested*. A confirming grep can be written once the
sentences are known -- that is how #410 was verified afterwards -- but not
before, which is the definition of not being a check.

So the claims carry the join key the prose does not have:

    (unverified: t-verifier)

and ``docs/README.md`` §*Verify before implementing* is the register that says
what each slug's status is. When an entry becomes ``verified``, this test fails
and names every file still carrying its marker. Against the real failure:
closing out #407 would have failed here naming ``uc-01`` and ``adr-001``.

**A marker never goes in user-visible text.** A click command's docstring *is*
its ``--help`` output, so a marker placed in one is shown to every operator who
asks for help -- the same mistake as a debug string in a user-facing message.
Where the claim lives in help text, the marker goes in a comment beside it
naming the sentence it belongs to; ``sopuli/cli.py``'s ``creds_check`` is the
worked example. This was found the hard way while writing this file: the first
attempt put the marker inside that docstring, broke its indentation, and
``ruff format`` then reflowed all thirty lines of published help text.

**What this cannot check, and it is worth being plain about it.** The rule below
requires that an open entry be marked *somewhere*, which is not the same as
*everywhere*. Whether a given paragraph asserts a given open question is a
judgement about prose, and no test makes it -- #412's review found seven sites
this file's own author had missed, after he wrote the convention saying every
site gets one. So the marker narrows the problem rather than removing it: it
turns "remember every document" into "remember at the moment you write the
claim", and it makes the *settling* step mechanical even when the *marking* step
is not. A site nobody marks is still a site nobody finds.

**There is no `partial` status**, and that is the other thing #412's review
changed. `ddl-text-retention` was one partial entry covering versions, AWR and
SQL trace; the trace surface was settled while the other two were not, so a stale
marker on a trace claim would have been allowed to sit indefinitely -- the #410
failure this file exists to catch, uncaught. A question whose surfaces settle
separately splits into entries that each settle whole.

**The register is the authority, not GitHub.** #383, #387 and #87 are all closed
issues whose verification is still outstanding -- the decision was taken, the
measurement was not -- so a check keyed on issue state would call them settled
and be wrong about all three. It would also need the network, which tier 0 does
not have.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: Where the register lives, and the heading it lives under.
REGISTER = ROOT / "docs" / "README.md"
REGISTER_HEADING = "## Verify before implementing"

#: One register entry:  - `unverified` `ddl-text-versions` (#387) — ...
#:
#: Status and slug are code spans so that the line stays readable as prose and
#: parseable without one. The issue numbers after them are for a human; this
#: test deliberately does not read them -- see the module note on why GitHub is
#: not the authority here.
ENTRY = re.compile(r"^- `(unverified|verified)` `([a-z0-9][a-z0-9-]*)`")

#: One marker, anywhere else:  (unverified: t-verifier)
#:
#: Deliberately NOT the same spelling as the register's, so neither pattern can
#: match the other's lines. The register says "`unverified` `slug`" in backticks;
#: a site says "(unverified: slug)" in parentheses.
MARKER = re.compile(r"\(unverified: ([a-z0-9][a-z0-9-]*)\)")

#: What gets scanned for markers. `src/` is in the list because two of #408's
#: five stale claims were in docstrings -- `sopuli/invocation.py` and
#: `sopuli/safety.py`, the latter quoting the very bullet being rewritten.
SCANNED = (
    ("docs", "**/*.md"),
    ("src", "**/*.py"),
    ("sql", "**/*.sql"),
    (".", "README.md"),
    (".", "CLAUDE.md"),
)

#: The register's own section is not a site: its bullets assert the unverified
#: state, because that is what a register is. **Only that section**, not the whole
#: file -- #412's review pointed out that excluding `docs/README.md` entirely made
#: the checker blind to the README's own prose, where §*Consolidated open
#: decisions* repeats several of these claims and a typo'd marker would never have
#: been validated.
#:
#: §Conventions needs no exclusion: it shows the syntax as `(unverified: <slug>)`,
#: and `<` is outside the slug character class, so the example cannot be mistaken
#: for a marker. That is cheaper than a second excluded range and it cannot drift.
NOT_A_SITE_SECTION = {REGISTER: REGISTER_HEADING}

#: Entries that are genuinely asserted nowhere, and why. Kept as a named list
#: rather than inferred, for `RESERVED_COMMANDS`'s reason one test over: an
#: exemption somebody has to write down is one a reviewer can see, and the
#: alternative is a rule that quietly stops applying.
#:
#: Empty today. If it grows past two or three, the rule below is wrong rather
#: than the entries.
UNSITED: frozenset[str] = frozenset()


def _scan() -> list[Path]:
    out: list[Path] = []
    for directory, pattern in SCANNED:
        for path in sorted((ROOT / directory).glob(pattern)):
            if path.is_file() and "__pycache__" not in path.parts:
                out.append(path)
    return out


def register() -> dict[str, str]:
    """Slug to status, read from the register's own section only.

    Scoped to the section rather than the file: a ``- `verified` `x` `` line in
    some other part of the README would otherwise silently become an entry.
    """
    text = REGISTER.read_text(encoding="utf-8")
    assert REGISTER_HEADING in text, f"{REGISTER} has no {REGISTER_HEADING!r} section"

    section = text.split(REGISTER_HEADING, 1)[1]
    # Stops at the next same-level heading; entries are bullets, never headings.
    section = re.split(r"^## ", section, maxsplit=1, flags=re.MULTILINE)[0]

    found: dict[str, str] = {}
    for line in section.splitlines():
        match = ENTRY.match(line)
        if match is None:
            continue
        status, slug = match.group(1), match.group(2)
        assert slug not in found, f"duplicate register slug {slug!r}"
        found[slug] = status
    return found


def _outside_the_register(path: Path, text: str) -> str:
    """``text`` with the register's own section blanked, line count preserved.

    Blanked rather than removed so that reported line numbers still match the
    file a reader opens.
    """
    heading = NOT_A_SITE_SECTION.get(path)
    if heading is None:
        return text

    kept, inside = [], False
    for line in text.splitlines():
        if line.startswith("## "):
            inside = line.strip() == heading
        kept.append("" if inside else line)
    return "\n".join(kept)


def markers() -> dict[str, list[str]]:
    """Slug to the ``path:line`` of every site claiming it."""
    out: dict[str, list[str]] = {}
    for path in _scan():
        text = _outside_the_register(path, path.read_text(encoding="utf-8"))
        for number, line in enumerate(text.splitlines(), 1):
            for slug in MARKER.findall(line):
                rel = path.relative_to(ROOT).as_posix()
                out.setdefault(slug, []).append(f"{rel}:{number}")
    return out


#: A register bullet that opens with a code span but is not a valid entry. The
#: strict parse would skip it in silence, so a typo in the status word -- or a
#: slug with a capital in it -- would remove an entry from the register while
#: leaving something that still reads like one to a person. #412's review raised
#: this, and it is the failure mode the whole file is about, one level down.
MALFORMED = re.compile(r"^- `(?!(?:unverified|verified)` `[a-z0-9][a-z0-9-]*`)")


def test_no_register_bullet_is_silently_skipped() -> None:
    """Every ``- `...`` bullet in the section parses, or this names it.

    The prose paragraphs between entries are fine -- they do not start with a
    bullet and a code span. What must not happen is a bullet that looks like an
    entry to a reader and is invisible to :func:`register`.
    """
    text = REGISTER.read_text(encoding="utf-8")
    section = text.split(REGISTER_HEADING, 1)[1]
    section = re.split(r"^## ", section, maxsplit=1, flags=re.MULTILINE)[0]

    bad = [line for line in section.splitlines() if MALFORMED.match(line)]

    assert not bad, (
        "register bullets that do not parse as entries, and would be skipped "
        f"in silence: {bad}. Statuses are `unverified` or `verified`; slugs are "
        "lowercase, digits and hyphens."
    )


def test_the_register_has_entries() -> None:
    """Guards the parse: an empty register would make every test below vacuous."""
    assert len(register()) >= 4


def test_every_marker_names_a_register_entry() -> None:
    """A typo in a slug is a marker that can never be cleared, because nothing
    will ever mark its entry verified. It has to fail now rather than look fine
    forever."""
    known = register()
    unknown = {slug: where for slug, where in markers().items() if slug not in known}

    assert not unknown, f"markers naming no register entry: {unknown}. Known slugs: {sorted(known)}"


def test_nothing_is_still_marked_unverified_once_it_is_verified() -> None:
    """**The rule this file exists for.**

    Mark an entry `verified` in the register and every document still calling it
    unverified is named here. That is the check #408 and #410 both needed and
    neither had.
    """
    verified = {slug for slug, status in register().items() if status == "verified"}
    stale = {slug: where for slug, where in markers().items() if slug in verified}

    assert not stale, (
        "the register calls these verified, but they are still marked unverified "
        f"in: {stale}. Update each site, or put the entry back to `partial`."
    )


def test_every_open_entry_is_marked_somewhere() -> None:
    """The other direction, and the one that stops the convention rotting.

    Without it, deleting every marker for an open entry is invisible: the test
    above passes trivially on a tree where nobody marks anything. An entry with
    no site at all is legitimate and goes in ``UNSITED``, by name.
    """
    open_entries = {slug for slug, status in register().items() if status == "unverified"}
    marked = set(markers())
    unmarked = sorted(open_entries - marked - UNSITED)

    assert not unmarked, (
        f"register entries nothing marks: {unmarked}. Either mark the documents "
        "that assert them unverified, or add the slug to UNSITED with a reason."
    )


@pytest.mark.parametrize("slug", sorted(register()))
def test_slug_is_not_bare_issue_number(slug: str) -> None:
    """Slugs are names, not issue numbers, and the distinction is load-bearing.

    #103 heads two register entries, so a numeric key could not tell them apart;
    #383, #387 and #87 are closed issues with open verifications, so a numeric
    key invites reading the answer off GitHub, which would be wrong for three of
    the entries currently listed.
    """
    assert not slug.isdigit(), f"{slug!r} is an issue number; use a stable name"

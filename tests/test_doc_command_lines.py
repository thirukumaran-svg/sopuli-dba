"""Every `sopuli` command line in `docs/` parses against the real CLI. Tier 0.

**What this catches.** A worked example can name an option the binary has not
got, and can even print the refusal it is illustrating. `sopuli` rejects an
unknown option before any precedence or safety check runs, so such output is a
prediction, not a pasted sample, in the document that specifies the refusal.

**Why this parses command lines instead of grepping for flags.** A grep of
`docs/` for `--[a-z-]+` finds two dozen tokens the CLI has not got, and almost all
of them are right: other tools' flags (`pip --no-deps`), and flags the documents
exist to *decline* -- `--yes`, `--continue-on-error`, `--method hash`. This
repository argues about flags it refuses to build, and a checker that could not
tell that from a broken example would be suppressed within a week.

So the unit is a **command line**: a line inside a fenced code block whose first
word, after an optional `$ ` prompt and any `NAME=value` environment prefix, is
`sopuli`. Prose is never in one, and a declined flag is discussed rather than
invoked. Two traps:

* **Option values are consumed.** Otherwise `--config sopuli.yaml creds status`
  leaves `sopuli.yaml` looking like a subcommand.
* **Only fenced blocks count.** `sopuli reaches two kinds of remote system…` is a
  sentence, not an invocation.

**A rejection the document shows on purpose is not drift -- if it is true.**
A document may cause a failure deliberately, such as `sopuli about --output
json`, where the point of the example is the `No such option` it prints. So an
undeclared option passes when the same block prints click's own rejection for
it, or the line's comment says "no such option". That is not an escape hatch,
because it is checked in both directions: a block claiming an option does not
exist, for an option that does, fails too.
What there is **not** is a marker that exempts a block unconditionally.
Illustrative examples use real flags instead, because a documented way to skip a
block is the way a real drift gets hidden.

**What this does not check**: that an option's *value* is valid, that a command
path exists (an unknown word stops the walk rather than failing it, because
placeholders like `<verb>` are legitimate), or the reverse direction -- a flag no
document mentions.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import click

from repo_files import requires_repo
from sopuli.cli import cli

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

#: Where a shell command stops being an argument list for `sopuli`.
SHELL_OPERATORS = frozenset({"|", "||", "&&", ";", "<", ">", ">>", "2>", "2>&1", "&"})

#: A leading `NAME=value` in `SOPULI_OUTPUT=text sopuli …`.
ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

#: A trailing shell comment. Written as a pattern rather than left to `shlex`,
#: whose comment handling also ends a *word* at `#` -- and a SecretRef such as
#: `vault-dev:acme/dev/acme#acme_app_user` has one in the middle.
TRAILING_COMMENT = re.compile(r"\s+#(.*)$")

FENCE = re.compile(r"^\s*(```|~~~)")

#: What a document says when it shows an option being refused on purpose.
REJECTED_IN_COMMENT = "no such option"


def _click_rejection(option: str) -> str:
    """click's own words for an undeclared option, as a pasted run shows them."""
    return f"No such option '{option}'"


@dataclass(frozen=True)
class CommandLine:
    """One documented invocation, with what the document says around it."""

    number: int
    arguments: list[str]
    #: The line's trailing `# ...`, lower-cased, or empty.
    comment: str
    #: This command and what is pasted beneath it, up to the next command in the
    #: same block. **Not the whole block**: a fence often holds several commands
    #: (`docs/scenarios/rotate-and-sync.md`), and a rejection printed for one of
    #: them must not excuse a bad option on another.
    output: str

    def shows_rejection_of(self, option: str) -> bool:
        return REJECTED_IN_COMMENT in self.comment or _click_rejection(option) in self.output


def command_lines(text: str) -> Iterator[CommandLine]:
    """Every command line in ``text``.

    A backslash continuation is joined and reported at its first line, which is
    the line a reader would go to.
    """
    lines = text.splitlines()
    for block_start, block in _fenced_blocks(lines):
        found: list[tuple[int, list[str], str]] = []
        index = 0
        while index < len(block):
            start = index
            line = block[index]
            index += 1
            while line.rstrip().endswith("\\") and index < len(block):
                line = line.rstrip()[:-1] + " " + block[index]
                index += 1
            parsed = _parse(line)
            if parsed is not None:
                found.append((start, *parsed))
        if not found:
            continue
        ends = [start for start, _, _ in found[1:]] + [len(block)]
        for (start, arguments, comment), end in zip(found, ends, strict=True):
            yield CommandLine(
                block_start + start + 1, arguments, comment, "\n".join(block[start:end])
            )


def _fenced_blocks(lines: list[str]) -> Iterator[tuple[int, list[str]]]:
    """``(index of the block's first line, its lines)``, fences excluded."""
    inside: list[str] | None = None
    first = 0
    for index, line in enumerate(lines):
        if FENCE.match(line):
            if inside is None:
                inside, first = [], index + 1
            else:
                yield first, inside
                inside = None
        elif inside is not None:
            inside.append(line)


def _parse(line: str) -> tuple[list[str], str] | None:
    """The words after `sopuli` and the trailing comment, or ``None``."""
    body = line.strip()
    if body.startswith("$ "):
        body = body[2:]
    comment_match = TRAILING_COMMENT.search(body)
    comment = comment_match.group(1).strip().lower() if comment_match else ""
    body = TRAILING_COMMENT.sub("", body)
    try:
        words = shlex.split(body)
    except ValueError:
        # An unbalanced quote in an example. Whitespace is a worse tokeniser and
        # a good enough one for finding option names.
        words = body.split()
    while words and ENV_ASSIGNMENT.match(words[0]):
        words = words[1:]
    if not words or words[0] != "sopuli":
        return None
    arguments = []
    for word in words[1:]:
        if word in SHELL_OPERATORS:
            break
        arguments.append(word)
    return arguments, comment


def unknown_options(arguments: list[str]) -> list[str]:
    """Options in ``arguments`` that the command they are given to does not declare.

    Walks the click tree the way click itself would: options are looked up on the
    command reached *so far*, a word naming a subcommand descends, and an option
    that takes a value consumes the next word unless it was written `--opt=value`.
    """
    command: click.Command = cli
    context = click.Context(cli, info_name="sopuli")
    found: list[str] = []
    words = iter(arguments)
    for word in words:
        if word == "--":
            break
        if word.startswith("-") and word != "-":
            name = word.split("=", 1)[0]
            option = _option(command, context, name)
            if option is None:
                found.append(name)
            elif "=" not in word and not (option.is_flag or option.count):
                next(words, None)
            continue
        if isinstance(command, click.Group):
            sub = command.get_command(context, word)
            if sub is None:
                # A placeholder or prose inside a block. Nothing to check the
                # rest of the line against, and guessing would be a false alarm.
                break
            context = click.Context(sub, info_name=word, parent=context)
            command = sub
    return found


def _option(command: click.Command, context: click.Context, name: str) -> click.Option | None:
    for param in command.get_params(context):
        if isinstance(param, click.Option) and name in (*param.opts, *param.secondary_opts):
            return param
    return None


def _documented() -> list[tuple[str, CommandLine]]:
    found = []
    for path in sorted(DOCS.glob("**/*.md")):
        relative = path.relative_to(ROOT).as_posix()
        for line in command_lines(path.read_text(encoding="utf-8")):
            found.append((relative, line))
    return found


# ------------------------------------------------------------- the check ---


def test_every_documented_command_line_names_only_options_its_command_has() -> None:
    """**The rule.** A failure names the line and the option, which is all a
    reader needs: open the file, and either the example is wrong or the flag was
    renamed and the example was not."""
    broken = [
        f"{path}:{line.number}  {option}"
        for path, line in _documented()
        for option in unknown_options(line.arguments)
        if not line.shows_rejection_of(option)
    ]

    assert not broken, (
        "documented `sopuli` command lines name options the command does not have:\n  "
        + "\n  ".join(broken)
        + "\nEvery sample is pasted from a real run; fix the example, not this test."
    )


def test_a_rejection_shown_on_purpose_is_of_an_option_that_really_is_missing() -> None:
    """The other direction, and what keeps the rule above from being an exemption:
    a block that pastes `No such option` for a flag that has since been added is
    as stale as an example using a flag that has been removed.

    Both forms the rule accepts are checked here, because a form checked in only
    one direction is an exemption for the other: a pasted
    rejection must name an option that is still undeclared, and a `# no such
    option` comment must sit on a line that still has one.
    """
    stale = []
    for path, line in _documented():
        unknown = unknown_options(line.arguments)
        if REJECTED_IN_COMMENT in line.comment and not unknown:
            stale.append(f"{path}:{line.number}  (says 'no such option'; every option parses)")
        stale.extend(
            f"{path}:{line.number}  {option}"
            for option in _options_named(line.arguments)
            if _click_rejection(option) in line.output and option not in unknown
        )

    assert not stale, (
        "these blocks show an option being refused that the command now declares:\n  "
        + "\n  ".join(stale)
    )


def _options_named(arguments: list[str]) -> list[str]:
    return [word.split("=", 1)[0] for word in arguments if word.startswith("--")]


def test_the_scan_finds_the_documents_command_lines() -> None:
    """Guards the parse. A fence regex that stopped matching would find nothing,
    and every test above would pass on an empty list."""
    requires_repo(DOCS)
    assert len(_documented()) >= 50


# ---------------------------------------------------------- the parser ---


def _only(text: str) -> tuple[int, list[str]]:
    (line,) = command_lines(text)
    return line.number, line.arguments


def test_only_fenced_lines_are_command_lines() -> None:
    text = "sopuli reaches two kinds of remote system\n\n```\n$ sopuli creds status\n```\n"

    assert _only(text) == (4, ["creds", "status"])


def test_an_environment_prefix_and_a_comment_are_not_arguments() -> None:
    text = "```\n$ SOPULI_OUTPUT=text sopuli config show --explain   # the env layer\n```\n"

    assert _only(text) == (2, ["config", "show", "--explain"])


def test_a_secret_ref_keeps_its_fragment() -> None:
    """`#` inside a word is not a comment -- a SecretRef has one."""
    text = "```\nsopuli creds generate --target vault-dev:acme/dev/acme#acme_app_user\n```\n"

    assert _only(text) == (
        2,
        ["creds", "generate", "--target", "vault-dev:acme/dev/acme#acme_app_user"],
    )


def test_a_continuation_is_one_command_at_its_first_line() -> None:
    text = "```\nsopuli creds apply \\\n  --dry-run\n```\n"

    assert _only(text) == (2, ["creds", "apply", "--dry-run"])


def test_a_pipe_ends_the_arguments() -> None:
    text = "```\nsopuli creds status --output json | jq .results\n```\n"

    assert _only(text) == (2, ["creds", "status", "--output", "json"])


def test_an_option_value_is_not_mistaken_for_a_subcommand() -> None:
    """The first trap: without consuming values, every
    `--config FILE` leaves the file name in the verb's position."""
    assert unknown_options(["--config", "sopuli.yaml", "creds", "status", "--output", "json"]) == []


def test_an_undeclared_option_is_reported() -> None:
    assert unknown_options(["creds", "apply", "--no-dry-run"]) == ["--no-dry-run"]


def test_an_option_is_looked_up_on_the_command_it_follows() -> None:
    """`--dry-run` is trailing-only (`invocation.py`), so where it is written is
    the point: the check uses click's own tree rather than a flat list of every
    option anywhere."""
    assert unknown_options(["creds", "apply", "--dry-run"]) == []
    assert unknown_options(["about", "--dry-run"]) == ["--dry-run"]


def test_a_placeholder_stops_the_walk_rather_than_failing_it() -> None:
    assert unknown_options(["<verb>", "--anything"]) == []


def test_a_rejection_counts_only_where_the_block_shows_it_for_that_option() -> None:
    shown = "```\n$ sopuli about --output json\nError: No such option '--output'.\n```\n"
    commented = "```\n$ sopuli about --color never      # exit 2, no such option\n```\n"
    unexplained = "```\n$ sopuli about --output json\nError: No such option '--color'.\n```\n"

    (one,) = command_lines(shown)
    (two,) = command_lines(commented)
    (three,) = command_lines(unexplained)

    assert one.shows_rejection_of("--output")
    assert two.shows_rejection_of("--color")
    assert not three.shows_rejection_of("--output")


def test_a_rejection_belongs_to_the_command_it_was_pasted_under() -> None:
    """One fence, two commands, and the rejection printed under the first must not
    excuse the second."""
    text = (
        "```\n"
        "$ sopuli about --output json\n"
        "Error: No such option '--output'.\n"
        "$ sopuli creds status --output-format json\n"
        "```\n"
    )

    first, second = command_lines(text)

    assert first.shows_rejection_of("--output")
    assert not second.shows_rejection_of("--output")
    assert second.output.startswith("$ sopuli creds status")

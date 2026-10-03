"""Probe: which files under `docs/`, `sql/` and `examples/` -- and the root
`README.md` and `CLAUDE.md` -- does a **skipped lane** open, and does either
workflow's `paths-ignore` list one of them?

**"A skipped lane", not "the suite", and the distinction is #458's.** `ci.yml`'s
`docs` job runs :data:`DOCS_LANE` on exactly the pull requests where the other
lanes are skipped, so what those modules read is covered by CI and is not a
hole in the list. They are deselected below, and a conflict reported here is
therefore a file that *nothing* would check on a prose-only pull request. Before
that job existed the two questions had the same answer; they do not any more.

Written for issue #375, where the list had drifted seven patterns behind the
tree and every documentation pull request was starting both lanes. The
`paths-ignore` allowlists in `.github/workflows/ci.yml` and `tier1.yml` are
measured, not guessed: `docs/design/00-principles.md`,
`docs/design/01-configuration.md`, every `docs/schemas/*.json`, every
`examples/*.yaml` and `sql/oracle/00_install.sql` are read by tests, so a
blanket `docs/**` would silently stop testing them. Keeping that true needs a
measurement, and this is it.

It replaces a one-liner the workflow comments used to carry::

    python -c "import sys,pytest;sys.addaudithook(
        lambda e,a: e=='open' and print(a[0]));pytest.main(['tests/','-q'])" | sort -u

**That command under-reports, and plausibly is why the list drifted.** The audit
hook prints to `sys.stdout`, which pytest's capture and Click's `CliRunner` both
replace, so almost every path is swallowed into a per-test buffer and never
reaches the terminal. Measured on 2026-09-08 it reported 1 of the 19 files the
suite opens. Adding `-s` recovers all 19, but the prints then land inside the
output the CLI tests assert on and 212 of them fail, which makes the run look
broken rather than measured. This writes through an OS-level file descriptor
instead, which nothing in the process can intercept, so the suite runs clean.

Its `-q` was doing harm too, which is why there is none below: `pyproject.toml`
already passes `-q` in `addopts`, so a second one is `-qq`, and `-qq` suppresses
the `N passed in Xs` line. The measurement then had no way to say whether the
suite it measured was green.

Not a pytest test -- a spike, run by hand, the same relationship
`vault_cas_probe.py` has to Vault and `sql/oracle/02_password_leak_probe.sql`
has to Oracle. What it measures is a property of the whole suite, and a test
that ran the suite inside the suite would be a different kind of object.

**Bring the tier-1 stack up first.** With no containers ~100 tests skip on
"environment unavailable" and whatever they read is invisible to this. The
script says which it was, and refuses to call the answer complete without them::

    docker compose --profile tier1 up -d   # from test/
    python test/paths_ignore_probe.py       # from the repository root

Exit status is 0 when nothing the **non-docs-lane** suite opens is ignored by
either workflow, and 1 when something is -- so it can be read by a human or by a
shell. A green run says the prose list is safe *given* that `ci.yml`'s `docs` job
still runs :data:`DOCS_LANE`; `tests/test_workflow_prose_list.py` is what holds
that second half, since this script cannot see whether the job exists.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: The paths the question is about. Everything else in the tree either is code,
#: or is not a candidate for either allowlist.
#:
#: **`README.md` and `CLAUDE.md` are in here, and their absence was a second bug**
#: (#458). Both are on the prose list, and `tests/test_verification_register.py`
#: scans both for `(unverified: <slug>)` markers -- but this tuple used to hold
#: directories only, so `relative.parts[0]` never matched them and no drift
#: involving either could ever be reported. A probe with a blind spot over two of
#: the twenty patterns it checks is worse than a shorter list honestly described.
#:
#: Matched against `relative.parts[0]`, which for a root file is the file name.
#:
#: **Today this catches nothing, and that is the correct state**, measured on the
#: run that added it: the only tests reading either root file are the `DOCS_LANE`
#: modules below, which are deselected, so the measured suite opens neither. It is a
#: guard against the *next* test that reads one -- which the old tuple could not
#: have reported however far the list drifted.
#:
#: Split in two because they print differently, not because they match
#: differently: a directory is shown with a trailing slash and a file without one,
#: and joining the whole tuple with `/` produced `README.md/`.
WATCHED_DIRS = ("docs", "sql", "examples")
WATCHED_FILES = ("README.md", "CLAUDE.md")
WATCHED = WATCHED_DIRS + WATCHED_FILES

#: The modules `ci.yml`'s `docs` job runs on a prose-only pull request (#458).
#:
#: **Deselected, and that is the point of the job.** The question this probe asks
#: is not "does the suite read an ignored file" but "does a *skipped lane* read
#: one" -- those became different questions when the `docs` job arrived. These
#: modules read most of `docs/` and the root `README.md`, and they now run on
#: exactly the pull requests where the other lanes do not, so counting them here
#: would report 21 conflicts that the workflow already covers and leave the list
#: unfixable.
#:
#: Adding a test that reads prose means adding it here *and* to the `docs` job, or
#: this probe goes quiet about whatever it reads.
DOCS_LANE = (
    "tests/test_verification_register.py",
    "tests/test_decision_register.py",
    "tests/test_doc_command_lines.py",
    "tests/test_doc_lists.py",
    "tests/test_doc_sections.py",
    "tests/test_doc_symbols.py",
    "tests/test_pending_work.py",
    "tests/test_readme_links.py",
)

WORKFLOWS = (
    ROOT / ".github" / "workflows" / "ci.yml",
    ROOT / ".github" / "workflows" / "tier1.yml",
)


def measure() -> tuple[set[str], str]:
    """Run the suite under an audit hook and return the paths it opened.

    The hook writes to a file descriptor opened here rather than to
    `sys.stdout`, because `sys.stdout` is not ours during a test -- see the
    module docstring. The child is a separate interpreter so that this
    script's own imports are not counted.
    """
    fd, path = tempfile.mkstemp(prefix="sopuli-opens-", suffix=".txt")
    os.close(fd)
    # Built out here rather than inside the f-string below: nesting an f-string
    # that uses the same quote style is a syntax error before 3.12 (PEP 701), and
    # `requires-python` allows 3.11 -- which is also a cell in the CI matrix.
    ignores = [f"--ignore={module}" for module in DOCS_LANE]
    hook = f"""
import os, sys, pytest
out = os.open({path!r}, os.O_WRONLY | os.O_TRUNC)


def audit(event, args):
    if event == "open":
        try:
            os.write(out, (str(args[0]) + "\\n").encode("utf-8", "replace"))
        except Exception:  # a hook must never be the reason a test fails
            pass


sys.addaudithook(audit)
sys.exit(pytest.main(["tests/"] + {ignores!r}))
"""
    run = subprocess.run(
        [sys.executable, "-c", hook],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    opened = set()
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            candidate = Path(line.strip())
            if not candidate.is_absolute():
                candidate = ROOT / candidate
            try:
                relative = candidate.resolve().relative_to(ROOT)
            except ValueError:
                continue  # site-packages, the interpreter, pytest's tmp_path
            if relative.parts and relative.parts[0] in WATCHED:
                opened.add(relative.as_posix())
    os.unlink(path)
    return opened, run.stdout + run.stderr


def ignored_patterns(workflow: Path) -> list[str]:
    """The `paths-ignore` list, or the `changes` job's `prose` array, as written.

    Read with a regex rather than a YAML parser on purpose: `ci.yml` no longer
    has a `paths-ignore` key at all -- #375 moved the same list into a bash
    array so the required checks keep reporting -- and the question here is what
    the file *says*, in either shape. Both shapes single-quote their entries,
    which is what makes one extractor enough.

    `tests/test_workflow_prose_list.py` is what keeps the two copies equal. This
    reads both anyway rather than trusting that, because a probe that reported a
    list the workflow does not have would be worse than no probe.
    """
    text = workflow.read_text(encoding="utf-8")
    block = re.search(r"^ *paths-ignore:\n((?: *- '[^']+'\n)+)", text, re.MULTILINE)
    if block is None:
        block = re.search(r"# prose-list-start\n(.*?)\n *# prose-list-end", text, re.S)
    return re.findall(r"'([^']+)'", block.group(1)) if block else []


def matches(pattern: str, path: str) -> bool:
    """Does a `paths-ignore` pattern cover this path?

    `**` matches across separators and `*` does not, which is GitHub's rule and
    not `fnmatch`'s -- `fnmatch` would call `docs/*` a match for
    `docs/design/01-configuration.md` and report a conflict that is not there.
    """
    expression = re.escape(pattern).replace(r"\*\*", "\x00").replace(r"\*", "[^/]*")
    return re.fullmatch(expression.replace("\x00", ".*"), path) is not None


def main() -> int:
    opened, output = measure()

    match = re.search(r"(\d+) skipped \(environment unavailable\)", output)
    skipped = int(match.group(1)) if match else 0

    # The suite's own last line, so that a pasted run says what it measured
    # against rather than only what it concluded. A measurement taken while the
    # suite was failing is still a measurement, but the reader should be told.
    for line in reversed(output.splitlines()):
        if re.search(r"\d+ (passed|failed|error)", line):
            print(f"suite: {line.strip()}\n")
            break

    watched = ", ".join([f"{name}/" for name in WATCHED_DIRS] + list(WATCHED_FILES))
    print(f"opened under {watched} ({len(opened)} files):\n")
    for path in sorted(opened):
        print(f"  {path}")

    conflicts = []
    for workflow in WORKFLOWS:
        patterns = ignored_patterns(workflow)
        print(f"\n{workflow.relative_to(ROOT).as_posix()}: {len(patterns)} patterns")
        for pattern in patterns:
            hits = sorted(path for path in opened if matches(pattern, path))
            if hits:
                conflicts.append((workflow, pattern, hits))
                for hit in hits:
                    print(f"  CONFLICT  {pattern} ignores {hit}, which the suite opens")

    if skipped:
        print(
            f"\nINCOMPLETE: {skipped} tests skipped for want of an environment.\n"
            "Bring the tier-1 stack up (docs/design/04-testing.md §4) and measure\n"
            "again -- whatever those tests read is invisible to this run."
        )

    if conflicts:
        print(f"\n{len(conflicts)} pattern(s) ignore a file the suite reads.")
        return 1

    print("\nNo ignored pattern covers a file the suite opens.")
    return 1 if skipped else 0


if __name__ == "__main__":
    raise SystemExit(main())

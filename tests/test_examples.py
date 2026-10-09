"""Every file in `examples/` is a config the tool actually accepts.

Tier 0 (04-testing.md §4): in-process, no containers, no network. The examples
are documentation, and documentation that stopped being true is worse than
documentation that is missing -- a reader who pastes one and gets exit 9 has no
way to tell whether they mistyped it or whether the project moved on without it.
So the file is not read as a fixture; it is read from `examples/`, copied, and
run through the real `config validate`.

Two things this deliberately does *not* do:

- **It does not validate against the JSON schema instead.** The schema is
  generated from the config layer and cannot see the cross-key rules -- the ones
  whose errors have to name the offending key (`01-configuration.md` §9b). A
  `secret_template` that stages two accounts into one field passes the schema
  and is refused at load, which is exactly the class of mistake an example is
  most likely to contain.
- **It does not run a mutating verb.** Nothing here connects. The examples point
  at `example.com` and at a local container that CI does not have, so what can
  be asserted from tier 0 is that the file parses, resolves and binds -- which
  is what `config validate` promises and all an example claims.

The copy exists because of the P4 permission check: a file committed to a
repository is readable by everyone who checks it out, so `examples/*.yaml` can
never pass that check where it sits. `write_config` writes it somewhere it can.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from conftest import WriteConfig
from repo_files import requires_repo
from sopuli.cli import cli
from sopuli.exit_codes import ExitCode

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

#: Named rather than globbed, so adding a file to `examples/` without adding it
#: here is a review comment rather than silently untested. The count is asserted
#: below.
EXAMPLE_FILES = [
    "single-application.yaml",
    "multiple-applications.yaml",
    "safety-hardened.yaml",
]


def test_every_example_file_is_listed() -> None:
    """A new example must be added to EXAMPLE_FILES to be tested at all."""
    requires_repo(EXAMPLES)
    on_disk = sorted(p.name for p in EXAMPLES.glob("*.yaml"))
    assert on_disk == sorted(EXAMPLE_FILES)


@pytest.mark.parametrize("name", EXAMPLE_FILES)
def test_example_config_validates(name: str, write_config: WriteConfig) -> None:
    source = EXAMPLES / name
    path = write_config(source.read_text(encoding="utf-8"))

    result = CliRunner().invoke(cli, ["--config", str(path), "config", "validate"])

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "ok:" in result.output


@pytest.mark.parametrize("name", EXAMPLE_FILES)
def test_example_config_validates_without_warnings(name: str, write_config: WriteConfig) -> None:
    """An example that warns teaches the warning along with the config.

    Split from the test above because the two failures mean different things: a
    non-zero exit is a broken example, and a warning is a working example that
    would still make a first-time reader think they had done something wrong.
    """
    source = EXAMPLES / name
    path = write_config(source.read_text(encoding="utf-8"))

    result = CliRunner().invoke(cli, ["--config", str(path), "config", "validate"])

    assert "0 warnings" in result.output, result.output


# ------------------------------------------- and the editor pointer is real ---


def test_every_example_points_its_editor_at_a_schema_that_exists() -> None:
    """The `# yaml-language-server:` line is a real reference, not a comment.

    **A schema rename can update the README and miss the examples**, so an editor
    opening any example resolves a `$schema` that has been deleted. It fails
    silently -- the reader gets no completion and no validation, and nothing says
    why -- which is why a test holds it rather than a reviewer noticing.

    Checked here rather than in `test_schemas.py` because the path is relative to
    the example, so the file it names is only resolvable from where the file sits.
    The identical pointers inside `docs/design/01-configuration.md` are deliberately
    *not* checked: those are inside code fences, showing what a reader would write
    next to their own config, and `./` there means their directory rather than ours.
    """
    requires_repo(EXAMPLES)
    pointer = "# yaml-language-server: $schema="
    checked = 0
    for example in sorted(EXAMPLES.glob("*.yaml")):
        for line in example.read_text(encoding="utf-8").splitlines():
            if not line.startswith(pointer):
                continue
            schema = (example.parent / line[len(pointer) :].strip()).resolve()
            assert schema.is_file(), (
                f"{example.name} points at a schema that does not exist: {schema}"
            )
            checked += 1
    assert checked, "no example declares a schema pointer -- did the convention change?"

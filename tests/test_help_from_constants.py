"""Help text and hints take their facts from the constants they describe.

Tier 0. Each fact below has a constant that defines it and text that an
operator reads. A fix that reached the constant and not the text would leave the
help saying something the build does not do. These tests fail if the text stops
following the constant.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from repo_files import requires_repo
from sopuli.cli import cli, help_with
from sopuli.config.delivery import IMPLEMENTED, MANUAL
from sopuli.driver.oracle import limits
from sopuli.driver.oracle.errors import INSTALL_SCRIPT

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "sopuli"


def _help(*command: str) -> str:
    """``sopuli <command> --help``, with click's line wrapping undone."""
    result = CliRunner().invoke(cli, [*command, "--help"])
    assert result.exit_code == 0, result.output
    return " ".join(result.output.split())


def test_max_bytes_help_states_the_rule_max_bytes_applies() -> None:
    assert f"({limits.describe_max_bytes()})" in _help("policy", "sample")


def test_the_rule_in_words_follows_the_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    assert limits.describe_max_bytes() == "30 below 23, 128 from 23"

    monkeypatch.setattr(limits, "LONG_PASSWORD_FLOOR", (12, 2))
    assert limits.describe_max_bytes() == "30 below 12.2, 128 from 12.2"


def test_reset_password_help_names_every_implemented_unseen_method() -> None:
    text = _help("account", "reset-password")
    unseen = [method for method in IMPLEMENTED if method != MANUAL]

    assert unseen
    for method in unseen:
        assert f"`{method}`" in text
    assert f"`delivery.method: {MANUAL}`" in text
    assert "{" not in text


def test_the_method_phrase_reads_for_one_method_or_several(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sopuli import cli as cli_module
    from sopuli.config import delivery

    monkeypatch.setattr(delivery, "IMPLEMENTED", (MANUAL, "a"))
    assert cli_module._unseen_methods_built() == "`a` is the unseen method"

    monkeypatch.setattr(delivery, "IMPLEMENTED", (MANUAL, "a", "b"))
    assert cli_module._unseen_methods_built() == "`a`, `b` are the unseen methods"


def test_a_placeholder_with_no_fact_fails_at_import_time() -> None:
    """A typo in a placeholder is an error when the module loads, not a `{typo}`
    in somebody's terminal."""

    def verb() -> None:
        """Uses {missing}."""

    with pytest.raises(KeyError):
        help_with(present="x")(verb)


def test_the_install_script_named_in_hints_exists() -> None:
    path = ROOT / INSTALL_SCRIPT
    requires_repo(path)
    assert path.is_file()


def test_no_hint_spells_the_install_script_by_hand() -> None:
    name = Path(INSTALL_SCRIPT).name
    spelled = [
        path.relative_to(ROOT).as_posix()
        for path in sorted(SRC.rglob("*.py"))
        for line in path.read_text(encoding="utf-8").splitlines()
        if name in line and "INSTALL_SCRIPT =" not in line
    ]

    assert spelled == []

"""Which file the tool reads (P1, "Config file discovery").

Nothing here touches the real environment, the real home directory or the real
`/etc`. Every input is injected, which is not only tidiness: a test that read
`$HOME` would pass or fail depending on whether the person running it happens to
keep a `~/.config/sopuli/config.yaml`, and the Windows branch would never run on
Linux at all.

That last point is the reason `platform` is a parameter rather than a
`sys.platform` check inside the module: mypy narrows `sys.platform` to whatever
it is checking, so a literal branch would be dead code -- unchecked and untested
-- on the other platform, which P4 explicitly warns about.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from sopuli.config.discovery import CONFIG_ENV, discover, search_path
from sopuli.config.errors import ConfigError

POSIX = "linux"
WINDOWS = "win32"


# ------------------------------------------------------------- search path ---


def test_the_working_directory_comes_first_on_every_platform(tmp_path: Path) -> None:
    """P1 step 3. A project's own `sopuli.yaml` beats anything installed: the
    file you are standing next to is the one you meant."""
    for platform in (POSIX, WINDOWS):
        found = search_path(
            {"APPDATA": str(tmp_path)}, platform=platform, cwd=tmp_path, home=tmp_path
        )

        assert found[0] == tmp_path / "sopuli.yaml"


def test_the_posix_search_path_is_xdg_then_etc(tmp_path: Path) -> None:
    home = tmp_path / "home"
    found = search_path({}, platform=POSIX, cwd=tmp_path, home=home)

    assert found == (
        tmp_path / "sopuli.yaml",
        home / ".config" / "sopuli" / "config.yaml",
        Path("/etc") / "sopuli" / "config.yaml",
    )


def test_xdg_config_home_wins_over_the_default_when_it_is_set(tmp_path: Path) -> None:
    """P1 writes the user location as `$XDG_CONFIG_HOME/...` -> `~/.config/...`:
    the variable when set, the spec's default when not."""
    elsewhere = tmp_path / "xdg"
    found = search_path(
        {"XDG_CONFIG_HOME": str(elsewhere)}, platform=POSIX, cwd=tmp_path, home=tmp_path
    )

    assert elsewhere / "sopuli" / "config.yaml" in found
    assert tmp_path / ".config" / "sopuli" / "config.yaml" not in found


def test_the_windows_search_path_is_appdata_then_programdata(tmp_path: Path) -> None:
    appdata = tmp_path / "AppData"
    programdata = tmp_path / "ProgramData"

    found = search_path(
        {"APPDATA": str(appdata), "PROGRAMDATA": str(programdata)},
        platform=WINDOWS,
        cwd=tmp_path,
        home=tmp_path,
    )

    assert found == (
        tmp_path / "sopuli.yaml",
        appdata / "sopuli" / "config.yaml",
        programdata / "sopuli" / "config.yaml",
    )


def test_windows_locations_whose_variable_is_unset_are_left_out(tmp_path: Path) -> None:
    """Rather than guessed at. Inventing a fallback would look for a config file
    somewhere no installer would ever write one."""
    found = search_path({}, platform=WINDOWS, cwd=tmp_path, home=tmp_path)

    assert found == (tmp_path / "sopuli.yaml",)


def test_the_posix_and_windows_paths_never_mix(tmp_path: Path) -> None:
    """The bug this would be: `%APPDATA%` honoured on Linux because the variable
    happened to be set in a container, or `/etc/sopuli` searched on Windows.

    The marker directories are named rather than derived from `tmp_path`, which
    on a Windows runner is itself under `AppData`.
    """
    env = {"APPDATA": str(tmp_path / "from-appdata"), "XDG_CONFIG_HOME": str(tmp_path / "from-xdg")}

    on_posix = search_path(env, platform=POSIX, cwd=tmp_path, home=tmp_path)
    on_windows = search_path(env, platform=WINDOWS, cwd=tmp_path, home=tmp_path)

    assert not any("from-appdata" in str(path) for path in on_posix)
    assert not any("from-xdg" in str(path) for path in on_windows)
    assert not any(path.parts[:2] == (Path("/").anchor, "etc") for path in on_windows)


# --------------------------------------------------------------- discovery ---


def test_the_first_file_that_exists_wins(tmp_path: Path, write_at: Callable[[Path], Path]) -> None:
    home = tmp_path / "home"
    write_at(home / ".config" / "sopuli" / "config.yaml")

    (found,) = discover(env={}, platform=POSIX, cwd=tmp_path, home=home)

    assert found == home / ".config" / "sopuli" / "config.yaml"


def test_a_local_file_beats_the_user_one(tmp_path: Path, write_at: Callable[[Path], Path]) -> None:
    home = tmp_path / "home"
    local = write_at(tmp_path / "sopuli.yaml")
    write_at(home / ".config" / "sopuli" / "config.yaml")

    assert discover(env={}, platform=POSIX, cwd=tmp_path, home=home) == (local,)


def test_the_environment_variable_beats_the_search_path(
    tmp_path: Path, write_at: Callable[[Path], Path]
) -> None:
    """§6: `SOPULI_CONFIG` is how a CI job redirects a shared config without
    editing it, so it has to outrank the file sitting in the checkout."""
    write_at(tmp_path / "sopuli.yaml")
    named = write_at(tmp_path / "elsewhere.yaml")

    found = discover(env={CONFIG_ENV: str(named)}, platform=POSIX, cwd=tmp_path, home=tmp_path)

    assert found == (named,)


def test_an_explicit_path_beats_the_environment_variable(
    tmp_path: Path, write_at: Callable[[Path], Path]
) -> None:
    """P3: the operator typing the command expresses the most specific intent."""
    named = write_at(tmp_path / "env.yaml")
    explicit = write_at(tmp_path / "cli.yaml")

    found = discover([explicit], env={CONFIG_ENV: str(named)}, platform=POSIX, cwd=tmp_path)

    assert found == (explicit,)


def test_every_explicit_path_is_returned_in_order(
    tmp_path: Path, write_at: Callable[[Path], Path]
) -> None:
    """Unlike the searched locations, `--config` does not stop at the first: §9
    layers them left to right."""
    first = write_at(tmp_path / "first.yaml")
    second = write_at(tmp_path / "second.yaml")

    assert discover([first, second], env={}, platform=POSIX, cwd=tmp_path) == (first, second)


def test_an_empty_environment_variable_is_treated_as_unset(
    tmp_path: Path, write_at: Callable[[Path], Path]
) -> None:
    """`SOPULI_CONFIG=` in a shell profile means "not set", not "the file called
    nothing"."""
    local = write_at(tmp_path / "sopuli.yaml")

    found = discover(env={CONFIG_ENV: "   "}, platform=POSIX, cwd=tmp_path, home=tmp_path)

    assert found == (local,)


# ------------------------------------------------------------------ errors ---


def test_a_named_file_that_is_missing_is_not_skipped(tmp_path: Path) -> None:
    """The whole reason named and searched paths behave differently. Falling
    through would run a CI job with a typo in its path against whatever config
    the machine happens to have, which is the estate read from the wrong file."""
    with pytest.raises(ConfigError) as caught:
        discover([tmp_path / "nope.yaml"], env={}, platform=POSIX, cwd=tmp_path)

    rendered = str(caught.value)
    assert "config file named by --config does not exist" in rendered
    assert "never skipped" in rendered


def test_a_missing_file_named_by_the_environment_says_which_variable(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as caught:
        discover(env={CONFIG_ENV: str(tmp_path / "nope.yaml")}, platform=POSIX, cwd=tmp_path)

    assert f"named by ${CONFIG_ENV} does not exist" in str(caught.value)


def test_a_directory_is_reported_as_a_directory(tmp_path: Path) -> None:
    """`--config /etc/sopuli` rather than `--config /etc/sopuli/config.yaml` is
    an easy thing to type, and "does not exist" sends someone looking for a typo
    in a path that is spelled correctly."""
    with pytest.raises(ConfigError) as caught:
        discover([tmp_path], env={}, platform=POSIX, cwd=tmp_path)

    assert "is not a file" in str(caught.value)


def test_finding_nothing_lists_everywhere_it_looked(tmp_path: Path) -> None:
    """A command with no config has no whitelist, so this is an error rather
    than an empty run -- and the message has to say where to put the file."""
    home = tmp_path / "home"

    with pytest.raises(ConfigError) as caught:
        discover(env={}, platform=POSIX, cwd=tmp_path, home=home)

    rendered = str(caught.value)
    assert "no config file found" in rendered
    assert str(tmp_path / "sopuli.yaml") in rendered
    assert str(home / ".config" / "sopuli" / "config.yaml") in rendered
    assert CONFIG_ENV in rendered


# ---------------------------------------------------------------- defaults ---


def test_the_process_supplies_the_defaults(
    tmp_path: Path, write_at: Callable[[Path], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The parameters exist for testability; the CLI calls `discover()` with
    none of them, so the wiring to the real process has to be exercised too."""
    local = write_at(tmp_path / "sopuli.yaml")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(CONFIG_ENV, raising=False)

    assert discover() == (local,)


@pytest.fixture
def write_at() -> Callable[[Path], Path]:
    """Create a config file at an exact path, permissions included.

    Not `write_config`: discovery is about *where* a file is, so these need to
    land at a chosen path rather than at one the fixture picks.
    """

    def write(path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("version: 1\n", encoding="utf-8")
        if sys.platform != "win32":
            path.chmod(0o600)
        return path

    return write

"""Which file the tool reads, before anything reads it (P1, "Config file discovery").

The search order is P1's, and the two halves behave differently on purpose:

* A path that was **named** -- ``--config``, ``SOPULI_CONFIG`` -- must exist. A
  missing one is an error rather than a reason to carry on down the list. Falling
  through would mean a CI job whose ``SOPULI_CONFIG`` has a typo silently running
  against ``/etc/sopuli/config.yaml`` instead, which is the whole estate read
  from a file nobody meant to use.
* A path that was **searched** -- the working directory, the user's config
  directory, the system one -- is skipped when absent. That is what "first match
  wins" means, and it is why those are tried in the order P1 gives.

``--config`` may be repeated, and then every file is read and layered rather than
only the first (§9). :func:`~sopuli.config.loading.load_documents` does the
merging; this only decides which files there are.

Everything the answer depends on is a parameter -- environment, platform, working
directory, home -- with the process supplying the defaults. That is not only for
tests: ``sys.platform`` is narrowed by mypy to whatever it is running on, so a
literal check here would leave the Windows branch unchecked on Linux and the
POSIX branch unchecked on Windows, which is exactly the arrangement P4 warns
about.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from sopuli.config.errors import ConfigError

#: §6's name for the config path. One path, not a list: a Windows path contains
#: the separator that splitting it would use.
CONFIG_ENV = "SOPULI_CONFIG"

#: The value of ``sys.platform`` this module branches on. Compared against a
#: parameter rather than ``sys.platform`` itself, so both branches stay live for
#: the type checker on both platforms.
WINDOWS = "win32"

#: In the working directory the file is the project's own, so it is named after
#: the tool; everywhere else it sits in a ``sopuli/`` directory and is not.
LOCAL_NAME = "sopuli.yaml"
CONFIG_NAME = "config.yaml"
DIRECTORY_NAME = "sopuli"

SYSTEM_DIRECTORY = Path("/etc")


def discover(
    explicit: Sequence[Path] = (),
    *,
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    cwd: Path | None = None,
    home: Path | None = None,
) -> tuple[Path, ...]:
    """The config files to read, in the order they should be layered.

    Returns one path in every case except a repeated ``--config``, which returns
    them all. Raises rather than returning nothing: a command with no config has
    no whitelist, and invariant 5 makes that the one thing it cannot proceed
    without.
    """
    environment = os.environ if env is None else env
    on = sys.platform if platform is None else platform
    here = Path.cwd() if cwd is None else cwd
    user_home = Path.home() if home is None else home

    if explicit:
        return tuple(_require_file(Path(path), source="--config") for path in explicit)

    named = environment.get(CONFIG_ENV, "").strip()
    if named:
        return (_require_file(Path(named), source=f"${CONFIG_ENV}"),)

    searched = search_path(environment, platform=on, cwd=here, home=user_home)
    for candidate in searched:
        if candidate.is_file():
            return (candidate,)

    raise ConfigError(
        "no config file found",
        hint=(
            f"searched: {', '.join(str(path) for path in searched)} -- "
            f"pass --config PATH, or set {CONFIG_ENV}"
        ),
    )


def search_path(
    env: Mapping[str, str], *, platform: str, cwd: Path, home: Path
) -> tuple[Path, ...]:
    """P1's steps 3 to 5, as paths. Pure: it touches no filesystem.

    A location whose environment variable is unset is left out rather than
    guessed at. ``%APPDATA%`` is always set on a real Windows session, and
    inventing a fallback for the case where it is not would put a config file
    somewhere no installer would ever write one.
    """
    candidates = [cwd / LOCAL_NAME]

    if platform == WINDOWS:
        candidates.extend(
            Path(env[variable]) / DIRECTORY_NAME / CONFIG_NAME
            for variable in ("APPDATA", "PROGRAMDATA")
            if env.get(variable)
        )
        return tuple(candidates)

    # P1 writes the user location as `$XDG_CONFIG_HOME/sopuli/config.yaml` ->
    # `~/.config/sopuli/config.yaml`: the variable when it is set, the default
    # the XDG spec gives it when it is not.
    xdg = env.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else home / ".config"
    candidates.append(base / DIRECTORY_NAME / CONFIG_NAME)
    candidates.append(SYSTEM_DIRECTORY / DIRECTORY_NAME / CONFIG_NAME)
    return tuple(candidates)


def _require_file(path: Path, *, source: str) -> Path:
    """A named path has to be there, and has to be a file.

    The two failures are separated because the fixes are different: one is a
    typo or a file that was never deployed, the other is a directory passed
    where the file inside it was meant.
    """
    if path.is_file():
        return path
    if path.exists():
        raise ConfigError(
            f"config path named by {source} is not a file",
            source=path,
            hint="name the file itself, not the directory holding it",
        )
    raise ConfigError(
        f"config file named by {source} does not exist",
        source=path,
        hint="a named config file is never skipped -- correct the path, or drop the option",
    )

"""Generated passwords through the paths an operator passes them through (UC-1 §11).

`01-configuration.md` §8 says `alnum` and `alnum_safe` survive a shell, a `.env`
file and a connect string, and names the `printable_ascii` characters that do
not. This file checks both claims against the real consumers:

* **shell:** an unquoted assignment, `PW=<password>`, read back by `sh`;
* **`.env`:** a `.env` file read by `docker compose`;
* **connect string:** `CONNECT user/<password>@dsn` in SQL*Plus, after the
  driver has set the password, so the check is a login.

The JDBC URL is the fourth path UC-1 §11 names. It is not in this file (#743).

**Which passwords.** Every special character of each charset at the start, in
the middle and at the end of a short password, which is where a consumer reads a
character differently. Letters and digits need no sweep: no consumer here treats
one specially. Then passwords drawn by :func:`sopuli.passwords.generate`, for the
character pairs a sweep of one character cannot reach.

**No PL/SQL literal.** Invariant 13 keeps the password out of every PL/SQL
block, so no test here puts one there.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from oracle_harness import Environment
from sopuli.config import charsets
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, PasswordPolicy, Target
from sopuli.driver.protocol import Credential
from sopuli.passwords import generate
from sopuli.secrets import Secret

USER = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")

CORRELATION_ID = "3b8e1f40-6c2d-4e7a-9a15-d0c4b7e2f913"

ACCOUNT = "acme_paths_user"

#: The charsets §8 says need no quoting on any path here.
SAFE = ("alnum", "alnum_safe")

#: The `printable_ascii` characters each path changes or refuses, in any of the
#: three positions. `01-configuration.md` §8 names the same sets. Measured with
#: bash 5.2.37 as `sh`, Docker Compose v5.5.1 and SQL*Plus 23.26.3.0.0 against
#: Oracle 26ai Free 23.26.2.0.0, and in the tier-1 lane on Ubuntu, where `sh`
#: is dash and SQL*Plus is the latest Linux download. An upstream change that
#: moves a set fails here, and §8 is then wrong too.
BREAKS = {
    "shell": set("$&'();<>\\`|"),
    "env": set("$'"),
    "connect": set("&()/@"),
}

#: How many generated passwords each safe charset sends through each path.
DRAWS = {"shell": 200, "env": 200, "connect": 10}

#: Seconds any one consumer may take. A stalled listener or a prompt SQL*Plus
#: waits at then fails the test with a reason, instead of hanging the lane.
TIMEOUT = 60


def _specials(charset: str) -> str:
    return "".join(
        character
        for character in charsets.ALPHABETS[charset]
        if charsets.class_of(character) == charsets.SPECIAL
    )


def _swept(characters: str) -> list[str]:
    """Each character at the start, in the middle and at the end."""
    return [shape.format(c) for c in characters for shape in ("{}Ab1xy", "Ab1{}xy", "Ab1xy{}")]


def _drawn(charset: str, count: int) -> list[str]:
    policy = PasswordPolicy(length=24, charset=charset)
    return [generate(policy, limit=None).reveal() for _ in range(count)]


def _samples(charset: str, path: str) -> list[str]:
    return _swept(_specials(charset)) + _drawn(charset, DRAWS[path])


def _broken(path_survives: Any, candidates: list[str]) -> set[str]:
    """The characters whose sweep did not come through unchanged."""
    return {
        next(c for c in candidate if not c.isalnum())
        for candidate in candidates
        if not path_survives(candidate)
    }


# ------------------------------------------------------------------ shell ---


def _shell() -> str:
    found = shutil.which("sh")
    if found is None:
        pytest.skip("no `sh` on PATH")
    return found


def _through_shell(sh: str, directory: Path, candidates: list[str]) -> tuple[list[str], str]:
    """What `sh` read for each candidate, and its stderr.

    One `sh` for the lot. Each value comes back on its own NUL-ended record. The
    script goes on stdin: as an argument it is cut short on Windows. It runs in
    ``directory`` because a `>` in a broken password redirects to a file.
    """
    script = "".join(
        f"P{index}={candidate}\nprintf '%s\\0' \"$P{index}\"\n"
        for index, candidate in enumerate(candidates)
    )
    result = subprocess.run(
        [sh, "-s"],
        input=script,
        cwd=directory,
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT,
    )
    return result.stdout.split("\0")[: len(candidates)], result.stderr


@pytest.mark.parametrize("charset", SAFE)
def test_a_safe_password_survives_an_unquoted_shell_assignment(
    charset: str, tmp_path: Path
) -> None:
    sh = _shell()
    candidates = _samples(charset, "shell")

    read, errors = _through_shell(sh, tmp_path, candidates)

    assert read == candidates, errors


def test_printable_ascii_breaks_a_shell_on_the_characters_section_8_names(
    tmp_path: Path,
) -> None:
    sh = _shell()

    def survives(candidate: str) -> bool:
        return _through_shell(sh, tmp_path, [candidate])[0] == [candidate]

    assert _broken(survives, _swept(_specials("printable_ascii"))) == BREAKS["shell"]


# ------------------------------------------------------------------- .env ---


def _compose() -> list[str]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("no `docker` on PATH")
    probe = subprocess.run(
        [docker, "compose", "version"], capture_output=True, check=False, timeout=TIMEOUT
    )
    if probe.returncode != 0:
        pytest.skip("`docker compose` is not available")
    return [docker, "compose"]


def _through_env(
    compose: list[str], directory: Path, candidates: list[str]
) -> tuple[list[str | None], str]:
    """What Compose reads for each line of a `.env` file, and its stderr.

    A file Compose refuses reads as nothing for every line, and the stderr says
    why.

    `config` writes a literal `$` as `$$`, its own escape, so the output is
    unescaped once to get the value a container would see.
    """
    lines = "".join(f"P{index}={candidate}\n" for index, candidate in enumerate(candidates))
    (directory / ".env").write_text(lines, encoding="utf-8", newline="\n")
    (directory / "compose.yaml").write_text(
        "services:\n  probe:\n    image: alpine\n    env_file: .env\n", encoding="utf-8"
    )
    result = subprocess.run(
        [*compose, "--project-directory", str(directory), "config", "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT,
    )
    if result.returncode != 0:
        return [None] * len(candidates), result.stderr
    environment = json.loads(result.stdout)["services"]["probe"].get("environment", {})
    read = [environment.get(f"P{index}") for index in range(len(candidates))]
    unescaped = [None if value is None else value.replace("$$", "$") for value in read]
    return unescaped, result.stderr


@pytest.mark.parametrize("charset", SAFE)
def test_a_safe_password_survives_a_compose_env_file(charset: str, tmp_path: Path) -> None:
    compose = _compose()
    candidates = _samples(charset, "env")

    read, errors = _through_env(compose, tmp_path, candidates)

    assert read == candidates, errors


def test_printable_ascii_breaks_an_env_file_on_the_characters_section_8_names(
    tmp_path: Path,
) -> None:
    """One file per character: a stray `'` swallows the lines after it."""
    compose = _compose()

    def survives(candidate: str) -> bool:
        return _through_env(compose, tmp_path, [candidate])[0] == [candidate]

    assert _broken(survives, _swept(_specials("printable_ascii"))) == BREAKS["env"]


# --------------------------------------------------------- connect string ---


@pytest.fixture
def sqlplus() -> str:
    """SQL*Plus, or a skip. Requested before ``account``, so a machine without it
    skips before the fixture touches the database."""
    lib_dir = os.environ.get("SOPULI_ORACLE_CLIENT_LIB_DIR")
    found = shutil.which("sqlplus") or (lib_dir and shutil.which("sqlplus", path=lib_dir))
    if not found:
        pytest.skip("no SQL*Plus on PATH or in SOPULI_ORACLE_CLIENT_LIB_DIR")
    return found


@pytest.fixture
def account(live_oracle: Environment) -> Iterator[Any]:
    """An account the driver sets passwords on, with a session open as `USER`."""
    session_module = pytest.importorskip("sopuli.driver.oracle.session")
    driver = session_module.OracleDriver(env=os.environ, correlation_id=CORRELATION_ID)
    session = driver.connect(
        ExpandedTarget(
            target=Target(
                name="tier1-oracle",
                type="oracle",
                dsn=live_oracle.dsn,
                admin=AdminCredential(username=USER, auth=AdminAuth(method="env")),
            ),
            index=0,
        ),
        Credential(username=USER, secret=Secret(PASSWORD)),
    )

    with contextlib.suppress(Exception):
        _run(session, f"drop user {ACCOUNT} cascade")
    _run(session, f'create user {ACCOUNT} identified by "Init1aaaaaaa"')
    _run(session, f"grant create session to {ACCOUNT}")
    try:
        yield session
    finally:
        with contextlib.suppress(Exception):
            _run(session, f"drop user {ACCOUNT} cascade")
        session.close()


def _run(session: Any, statement: str) -> None:
    with session.connection.cursor() as cursor:
        cursor.execute(statement)


def _logs_in(sqlplus: str, session: Any, dsn: str, candidate: str) -> bool:
    """Set the password with the driver, then log in with it in SQL*Plus.

    The connect string goes to SQL*Plus on stdin, not in `argv` (invariant 1).
    The unlock is there because the `printable_ascii` sweep fails some logins on
    purpose, and the DEFAULT profile locks the account after ten.
    """
    _run(session, f"alter user {ACCOUNT} account unlock")
    session.set_password(ACCOUNT, Secret(candidate))
    script = (
        "whenever sqlerror exit 3\n"
        f"connect {ACCOUNT}/{candidate}@{dsn}\n"
        "select 'LOGGED' || 'IN' from dual;\n"
        "exit\n"
    )
    result = subprocess.run(
        [sqlplus, "-S", "-L", "/nolog"],
        input=script,
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT,
    )
    return "LOGGEDIN" in result.stdout


@pytest.mark.parametrize("charset", SAFE)
def test_a_safe_password_logs_in_through_a_connect_string(
    charset: str, sqlplus: str, account: Any, live_oracle: Environment
) -> None:
    failed = [
        candidate
        for candidate in _samples(charset, "connect")
        if not _logs_in(sqlplus, account, live_oracle.dsn, candidate)
    ]

    assert failed == []


def test_printable_ascii_breaks_a_connect_string_on_the_characters_section_8_names(
    sqlplus: str, account: Any, live_oracle: Environment
) -> None:
    def survives(candidate: str) -> bool:
        return _logs_in(sqlplus, account, live_oracle.dsn, candidate)

    assert _broken(survives, _swept(_specials("printable_ascii"))) == BREAKS["connect"]

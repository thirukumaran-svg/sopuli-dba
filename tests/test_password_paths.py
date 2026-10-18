"""Generated passwords through the paths an operator passes them through (UC-1 §11).

`01-configuration.md` §8 says `alnum` and `alnum_safe` survive a shell, a `.env`
file and a connect string, and that a JDBC URL needs `alnum_safe` in double
quotes. It names the `printable_ascii` characters that break each path. This file
checks those claims against the real consumers:

* **shell:** an unquoted assignment, `PW=<password>`, read back by `sh`;
* **`.env`:** a `.env` file read by `docker compose`;
* **connect string:** `CONNECT user/<password>@dsn` in SQL*Plus, after the
  driver has set the password, so the check is a login;
* **JDBC URL:** `jdbc:oracle:thin:user/<password>@//host:port/service` in the
  Oracle JDBC thin driver, also a login. `test/jdbc/JdbcLogin.java` runs in a
  JDK container, so the machine needs no Java.

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
import hashlib
import http.client
import json
import os
import queue
import secrets
import shutil
import subprocess
import tempfile
import threading
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any, NoReturn

import pytest

from oracle_harness import Environment, dsn_host, dsn_is_loopback
from sopuli.config import charsets
from sopuli.config.model import PasswordPolicy
from sopuli.passwords import generate
from sopuli.secrets import Secret

ACCOUNT = "acme_paths_user"

#: The charsets §8 says need no quoting on the shell, `.env` and connect-string
#: paths. A JDBC URL quotes the password for all but `alnum`.
SAFE = ("alnum", "alnum_safe")

#: The `printable_ascii` characters each path changes or refuses, in any of the
#: three positions. `01-configuration.md` §8 names the same sets. `jdbc` is the
#: unquoted URL; quoted, it refuses none. Measured with bash 5.2.37 as `sh`,
#: Docker Compose v5.5.1, SQL*Plus 23.26.3.0.0 and ojdbc11 23.26.3.0.0 against
#: Oracle 26ai Free 23.26.2.0.0, and in the tier-1 lane on Ubuntu, where `sh`
#: is dash and SQL*Plus is the latest Linux download. An upstream change that
#: moves a set fails here, and §8 is then wrong too.
BREAKS = {
    "shell": set("$&'();<>\\`|"),
    "env": set("$'"),
    "connect": set("&()/@"),
    "jdbc": set("',-./?@\\`{|}"),
}

#: How many generated passwords each safe charset sends through each path.
DRAWS = {"shell": 200, "env": 200, "connect": 10, "jdbc": 50}

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


def _docker() -> str:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("no `docker` on PATH")
    return docker


def _compose() -> list[str]:
    docker = _docker()
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
def account(session: Any) -> Iterator[Any]:
    """An account the driver sets passwords on. Yields the admin session."""
    with contextlib.suppress(Exception):
        _run(session, f"drop user {ACCOUNT} cascade")
    _run(session, f'create user {ACCOUNT} identified by "Init1aaaaaaa"')
    _run(session, f"grant create session to {ACCOUNT}")
    try:
        yield session
    finally:
        with contextlib.suppress(Exception):
            _run(session, f"drop user {ACCOUNT} cascade")


def _run(session: Any, statement: str) -> None:
    with session.connection.cursor() as cursor:
        cursor.execute(statement)


def _set_password(session: Any, candidate: str) -> None:
    """Set the password with the driver, before a login with it.

    The unlock is there because the `printable_ascii` sweeps fail some logins on
    purpose, and the DEFAULT profile locks the account after ten.
    """
    _run(session, f"alter user {ACCOUNT} account unlock")
    session.set_password(ACCOUNT, Secret(candidate))


def _logs_in(sqlplus: str, session: Any, dsn: str, candidate: str) -> bool:
    """Set the password, then log in with it in SQL*Plus.

    The connect string goes to SQL*Plus on stdin, not in `argv` (invariant 1).
    """
    _set_password(session, candidate)
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


# --------------------------------------------------------------- JDBC URL ---

#: The JDK the JDBC login runs in, and the driver jar it loads. Both are pinned,
#: the jar by its checksum as well, so a new release is a change to these lines.
JDK_IMAGE = "eclipse-temurin:21.0.8_9-jdk-alpine"
OJDBC_URL = (
    "https://repo1.maven.org/maven2/com/oracle/database/jdbc/ojdbc11/"
    "23.26.3.0.0/ojdbc11-23.26.3.0.0.jar"
)
OJDBC_SHA256 = "764cc3f88454d1be117e155d01ed617467b984c9c68f13090dd6083799d2bb8c"

JDBC_SOURCE = Path(__file__).resolve().parents[1] / "test" / "jdbc" / "JdbcLogin.java"

#: The container a loopback DSN names: the stack's `oracle-free` under the
#: compose project, as `tests/driver/test_oracle_install_script.py` names it.
#: The JDBC container joins its network, because the stack publishes its ports
#: on the host's loopback only (#867), and another container cannot reach those
#: through the host on Linux.
ORACLE_CONTAINER = os.environ.get(
    "SOPULI_TEST_ORACLE_CONTAINER",
    f"{os.environ.get('COMPOSE_PROJECT_NAME', 'sopuli-test')}-oracle-free-1",
)

#: The listener's port inside :data:`ORACLE_CONTAINER`, whatever the host maps.
CONTAINER_PORT = 1521

#: The answers that mean the password broke the login: the driver refused the
#: URL (ORA-17067), read part of the password as the address (ORA-12261), or the
#: server refused the password it was sent (ORA-01017). Any other failure is a
#: fault in the test environment, not a finding about the password.
PASSWORD_FAILURES = ("FAILED ORA-17067 ", "FAILED ORA-12261 ", "FAILED ORA-01017 ")


@pytest.fixture(scope="session")
def jdk() -> str:
    """`docker`, with :data:`JDK_IMAGE` pulled, or a skip."""
    docker = _docker()
    present = subprocess.run(
        [docker, "image", "inspect", JDK_IMAGE], capture_output=True, check=False, timeout=TIMEOUT
    )
    if present.returncode != 0:
        pulled = subprocess.run(
            [docker, "pull", JDK_IMAGE], capture_output=True, text=True, check=False, timeout=600
        )
        if pulled.returncode != 0:
            pytest.skip(f"cannot pull {JDK_IMAGE}: {pulled.stderr.strip()}")
    return docker


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="session")
def ojdbc(pytestconfig: pytest.Config, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The ojdbc jar from Maven Central, kept in the pytest cache.

    Without the cache plugin, it goes in a temporary directory for this run. A
    jar whose checksum is not :data:`OJDBC_SHA256` is never used. A cached one
    is downloaded again. A downloaded one fails the test.
    """
    cache = getattr(pytestconfig, "cache", None)
    directory = tmp_path_factory.mktemp("ojdbc") if cache is None else cache.mkdir("ojdbc")
    jar = directory / OJDBC_URL.rsplit("/", 1)[-1]
    if jar.exists() and _sha256(jar) == OJDBC_SHA256:
        return jar
    try:
        with urllib.request.urlopen(OJDBC_URL, timeout=TIMEOUT) as response:
            jar.write_bytes(response.read())
    except (OSError, http.client.HTTPException) as error:
        pytest.skip(f"cannot download {OJDBC_URL}: {error}")
    digest = _sha256(jar)
    if digest != OJDBC_SHA256:
        jar.unlink()
        pytest.fail(f"{OJDBC_URL} has sha256 {digest}, not {OJDBC_SHA256}")
    return jar


def _jdbc_target(docker: str, dsn: str) -> tuple[str, list[str]]:
    """The DSN as a JDBC thin address, `//host:port/service`, and the network to use.

    A loopback DSN names the stack's Oracle container. The JDBC container joins
    that container's network and connects to its listener as `localhost`, so
    no published port is involved. Any other host is reached directly.
    """
    if "://" in dsn or "/" not in dsn:
        pytest.skip(f"the JDBC check needs an Easy Connect DSN, host:port/service, not {dsn}")
    if not dsn_is_loopback(dsn):
        return "//" + dsn.lstrip("/"), []
    present = subprocess.run(
        [docker, "container", "inspect", ORACLE_CONTAINER],
        capture_output=True,
        check=False,
        timeout=TIMEOUT,
    )
    if present.returncode != 0:
        pytest.skip(
            f"the DSN is on loopback and no container {ORACLE_CONTAINER} runs it; "
            f"set SOPULI_TEST_ORACLE_CONTAINER to the container that does"
        )
    service = dsn.lstrip("/")[len(dsn_host(dsn)) :].partition("/")[2]
    return f"//localhost:{CONTAINER_PORT}/{service}", [f"--network=container:{ORACLE_CONTAINER}"]


class _Jdbc:
    """`JdbcLogin.java` in a JDK container, one login for each password sent.

    One container for the whole test, because a JVM takes seconds to start. A
    reader thread hands each answer over, so a login that hangs fails the test
    after :data:`TIMEOUT` instead of hanging the lane. It fails rather than goes
    on, because the late answer would then be read as the next password's.

    stderr goes to a file, so a full pipe cannot stop the JVM.
    """

    def __init__(self, docker: str, jar: Path, address: str, network: list[str]) -> None:
        self._docker = docker
        self._name = f"sopuli-jdbc-{secrets.token_hex(4)}"
        # Closed in close(): the file lives as long as the container.
        self._stderr = tempfile.TemporaryFile(mode="w+", encoding="utf-8")  # noqa: SIM115
        self._process = subprocess.Popen(
            [
                docker,
                "run",
                "--rm",
                "-i",
                f"--name={self._name}",
                *network,
                "--mount",
                f"type=bind,src={jar.parent},dst=/ojdbc,readonly",
                "--mount",
                f"type=bind,src={JDBC_SOURCE.parent},dst=/src,readonly",
                JDK_IMAGE,
                "java",
                "-cp",
                f"/ojdbc/{jar.name}",
                f"/src/{JDBC_SOURCE.name}",
            ],  # fmt: skip
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._stderr,
            text=True,
            encoding="utf-8",
        )
        self._lines: queue.Queue[str] = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        try:
            self._send(ACCOUNT)
            self._send(address)
        except OSError as error:
            # `docker run` exited before it read stdin: a bad mount, or no daemon.
            self._fail(f"JdbcLogin did not start: {error}")
        ready = self._answer()
        if ready != "READY":
            self._fail(f"JdbcLogin did not start: {ready}")

    def _read(self) -> None:
        assert self._process.stdout is not None
        for line in self._process.stdout:
            self._lines.put(line.rstrip("\r\n"))
        self._lines.put("FAILED JdbcLogin exited")

    def _send(self, line: str) -> None:
        assert self._process.stdin is not None
        self._process.stdin.write(line + "\n")
        self._process.stdin.flush()

    def _answer(self) -> str:
        try:
            return self._lines.get(timeout=TIMEOUT)
        except queue.Empty:
            self._fail(f"JdbcLogin gave no answer in {TIMEOUT} s")

    def _fail(self, reason: str) -> NoReturn:
        self._stop()
        self._stderr.seek(0)
        errors = self._stderr.read()
        self.close()
        raise AssertionError(f"{reason}\n{errors}")

    def login(self, candidate: str) -> str:
        """`LOGGEDIN`, or `FAILED` and the reason."""
        self._send(candidate)
        return self._answer()

    def close(self) -> None:
        self._stop()
        self._stderr.close()

    def _stop(self) -> None:
        if self._process.stdin is not None and not self._process.stdin.closed:
            self._process.stdin.close()
        try:
            self._process.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            # `--rm` removes the container only when it exits, and killing the
            # client does not stop it.
            subprocess.run(
                [self._docker, "rm", "-f", self._name],
                capture_output=True,
                check=False,
                timeout=TIMEOUT,
            )
            self._process.kill()
            self._process.wait()


@pytest.fixture
def jdbc(jdk: str, ojdbc: Path, live_oracle: Environment) -> Iterator[_Jdbc]:
    """The JDBC login. Requested before ``account``, so a machine without Docker
    skips before the fixture touches the database."""
    login = _Jdbc(jdk, ojdbc, *_jdbc_target(jdk, live_oracle.dsn))
    try:
        yield login
    finally:
        login.close()


def _through_jdbc(jdbc: _Jdbc, session: Any, candidate: str, *, quoted: bool) -> str:
    """Set the password, then log in with it through a JDBC URL.

    ``quoted`` puts the password in double quotes in the URL. Returns
    :meth:`_Jdbc.login`'s answer.
    """
    _set_password(session, candidate)
    return jdbc.login(f'"{candidate}"' if quoted else candidate)


def _logs_in_through_jdbc(jdbc: _Jdbc, session: Any, candidate: str, *, quoted: bool) -> bool:
    """Whether the login worked. A failure that is not in
    :data:`PASSWORD_FAILURES` fails the test instead of counting against the
    password."""
    answer = _through_jdbc(jdbc, session, candidate, quoted=quoted)
    if answer == "LOGGEDIN":
        return True
    if answer.startswith(PASSWORD_FAILURES):
        return False
    pytest.fail(f"the JDBC login failed for a reason other than the password: {answer}")


@pytest.mark.parametrize("charset", SAFE)
def test_a_safe_password_logs_in_through_a_quoted_jdbc_url(
    charset: str, jdbc: _Jdbc, account: Any
) -> None:
    failed = [
        candidate
        for candidate in _samples(charset, "jdbc")
        if not _logs_in_through_jdbc(jdbc, account, candidate, quoted=True)
    ]

    assert failed == []


def test_printable_ascii_logs_in_through_a_quoted_jdbc_url(jdbc: _Jdbc, account: Any) -> None:
    def survives(candidate: str) -> bool:
        return _logs_in_through_jdbc(jdbc, account, candidate, quoted=True)

    assert _broken(survives, _swept(_specials("printable_ascii"))) == set()


def test_an_alnum_password_logs_in_through_an_unquoted_jdbc_url(jdbc: _Jdbc, account: Any) -> None:
    failed = [
        candidate
        for candidate in _drawn("alnum", DRAWS["jdbc"])
        if not _logs_in_through_jdbc(jdbc, account, candidate, quoted=False)
    ]

    assert failed == []


def test_an_unquoted_jdbc_url_breaks_on_the_characters_section_8_names(
    jdbc: _Jdbc, account: Any
) -> None:
    """`alnum_safe` is not safe here: its `-` and `.` are in the set."""

    def survives(candidate: str) -> bool:
        return _logs_in_through_jdbc(jdbc, account, candidate, quoted=False)

    assert _broken(survives, _swept(_specials("printable_ascii"))) == BREAKS["jdbc"]
    assert set(_specials("alnum_safe")) & BREAKS["jdbc"] == set("-.")


def test_an_unquoted_jdbc_url_refuses_alnum_safe_with_ora_17067(jdbc: _Jdbc, account: Any) -> None:
    """The #743 record says the failure names its cause: the driver refuses the
    URL, and does not report a wrong password."""
    answers = {
        candidate: _through_jdbc(jdbc, account, candidate, quoted=False)
        for candidate in _swept("-.")
    }

    assert {c: a for c, a in answers.items() if not a.startswith("FAILED ORA-17067 ")} == {}

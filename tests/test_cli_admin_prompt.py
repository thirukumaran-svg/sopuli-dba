"""`auth: prompt` reaches a terminal, from the CLI (#476). Tier 0, no pty.

`tests/test_admin.py` already covers what a prompter *does* -- it caches per
declared credential, it wraps the typed string once, it refuses when absent. All
of it passed while the CLI supplied no prompter at all, so every target
declaring `auth: prompt` was refused with "there is nobody here to ask",
including from a real interactive console. The method was unusable in every
build up to 0.61.0 and the suite was green.

That is the gap this file is for: **the subject here is the wiring, not the
prompter.** A unit test with an injected asker cannot see a missing argument at
the call site, because injecting the asker is precisely what the call site had
stopped doing. So the tests below run real commands through `click` and assert on
what reached the far side -- the password the driver was handed, and the number
of times the operator was asked for it.

No pty anywhere, and two substitutions rather than one because `CliRunner`
installs its own `sys.stdin` for the duration of `invoke`. So `terminal_prompter`
is asked directly about a stream that answers `isatty()`, and the runs are told
whether anybody is watching through the probe itself -- see the `watching`
fixture for why that is the smallest thing that could be faked. `getpass` is
substituted with a recorder throughout.

All three are what the boundary *consults*; none is what it decides. The decision
-- build a prompter or refuse, which asker, one per run or one per target --
stays under test in every case.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result

from sopuli.admin import PasswordPrompt
from sopuli.cli import cli
from sopuli.driver.protocol import (
    PASS,
    ChangeResult,
    Credential,
    PrivilegeAudit,
    Scope,
    UserState,
    VerifyResult,
)
from sopuli.exit_codes import ExitCode
from sopuli.invocation import terminal_prompter
from sopuli.secrets import Secret
from sopuli.store import MemoryStore, SecretStore

WriteConfig = Callable[[str], Path]

TYPED = "Correct-Horse-Battery-9"

#: One target, one declared credential, asked for interactively.
PROMPT_TARGET = """version: 1
targets:
  - name: orders-pdb
    type: oracle
    dsn: "db.example.com:1521/orders"
    admin: { username: C##SOPULI_SVC, auth: prompt }
"""

#: Two targets from *one* `target_sets:` entry, with a literal username. §3a:
#: one entry is one operator writing one credential down once, so the whole set
#: is one prompt -- and that is only true if one prompter serves the whole run.
ONE_ENTRY_TWO_TARGETS = """version: 1
target_sets:
  appdb:
    type: oracle
    name: "appdb-{env}-{tenant}"
    dsn: "db-dev.example.com:1521/{tenant}.pdb.example.com"
    environment: "{env}"
    admin: { username: C##SOPULI_SVC, auth: prompt }
    for_each:
      env:
        dev: { tenant: [alpha, beta] }
"""


class FakeSession:
    """Enough of a session for `doctor` to finish describing a target."""

    def scope(self) -> Scope:
        return Scope(type="pdb", container="ORDERS", read_write=True, capabilities=frozenset())

    def privileges(self) -> PrivilegeAudit:
        return PrivilegeAudit()

    def close(self) -> None:
        return None


class Terminal(io.StringIO):
    """A stdin that says it is one, which `StringIO` does not (`test_spinner.py`)."""

    def isatty(self) -> bool:
        return True


class Pipe(io.StringIO):
    """What a `StringIO` already is. Named, because "not a terminal" is the case."""


class Detached(io.StringIO):
    """The stream a scheduler leaves behind: asked, it raises (#416)."""

    def isatty(self) -> bool:
        raise ValueError("I/O operation on closed file")


@pytest.fixture
def watching(monkeypatch: pytest.MonkeyPatch) -> Callable[[bool], None]:
    """Answer the boundary's "is anybody there", for a run under `CliRunner`.

    The probe is substituted here and the *stream* is substituted in the four
    tests above, and the split is forced rather than chosen: `CliRunner.invoke`
    installs its own `sys.stdin` for the duration of the call, so a stream put
    there beforehand is gone by the time the boundary looks. Patching the probe
    is what survives that.

    It is the smallest thing that could be substituted and still leave the
    subject intact. `terminal_prompter` keeps its own decision -- which asker,
    and whether to build anything at all -- and `_pass_invocation` keeps the
    placement that makes it one per run. What is faked is one boolean about the
    machine, which is the half a tier-0 test cannot have and the half #416 gave
    a module and a suite of its own.
    """

    def answer(there: bool) -> None:
        monkeypatch.setattr("sopuli.invocation.is_a_terminal", lambda stream: there)

    return answer


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Callable[..., list[Credential]]:
    """Substitute the driver, and record the credential each connection got.

    The credential is the observable the whole file turns on: it is what
    `admin.resolve` produced, carried to the one place that would have used it.
    Asserting on the *document* instead would only say the target was reachable,
    which a target with no password at all can also be.
    """

    def install() -> list[Credential]:
        seen: list[Credential] = []

        class FakeDriver:
            def __init__(self, **_: Any) -> None:
                pass

            def connect(self, target: Any, credential: Credential) -> FakeSession:
                seen.append(credential)
                return FakeSession()

        class FakeModule:
            OracleDriver = FakeDriver

        monkeypatch.setattr("sopuli.cli.resolve_driver", lambda target: FakeModule)
        return seen

    return install


@pytest.fixture
def asked(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every line `getpass` was shown, in order. Substituted where it is *read*.

    `sopuli.invocation` holds the module and reaches through it at call time, so
    patching the attribute is what a run would actually consult -- as opposed to
    rebinding a name this code imported, which would leave the real one in place.
    """
    lines: list[str] = []

    def ask(line: str) -> str:
        lines.append(line)
        return TYPED

    monkeypatch.setattr("sopuli.invocation.getpass.getpass", ask)
    return lines


def _doctor(runner: CliRunner, config: Path) -> Result:
    return runner.invoke(cli, ["--config", str(config), "--output", "json", "doctor"])


# --------------------------------------------- the boundary's own decision ---


def test_a_terminal_gets_a_prompter_that_asks_with_getpass() -> None:
    prompter = terminal_prompter(Terminal())

    assert isinstance(prompter, PasswordPrompt)
    # Not any asker: the one whose echo is off. A prompter built on `input`
    # would satisfy every other assertion in this file and print the password.
    assert prompter.ask.__module__ == "getpass"


def test_a_pipe_gets_no_prompter() -> None:
    """P5, one stream one reader: `--from-stdin` owns the pipe, so nothing asks."""
    assert terminal_prompter(Pipe()) is None


def test_a_stream_that_cannot_answer_gets_no_prompter() -> None:
    """Under a scheduler stdin is detached, and that is the run that must not ask."""
    assert terminal_prompter(Detached()) is None


def test_no_stream_at_all_gets_no_prompter() -> None:
    """`pythonw.exe` has no stdin, and "there is no stream" is nobody watching."""
    assert terminal_prompter(None) is None


# ----------------------------------------------------------- and the wiring ---


def test_the_typed_password_reaches_the_driver(
    runner: CliRunner,
    write_config: WriteConfig,
    estate: Callable[..., list[Credential]],
    asked: list[str],
    watching: Callable[[bool], None],
) -> None:
    """The one #476 is about: before this, the run never got as far as asking."""
    watching(True)
    seen = estate()
    config = write_config(PROMPT_TARGET)

    result = _doctor(runner, config)

    assert result.exit_code == ExitCode.SUCCESS
    assert [credential.secret.reveal() for credential in seen if credential.secret] == [TYPED]
    assert [credential.username for credential in seen] == ["C##SOPULI_SVC"]
    # §3a: the question names both halves of the answer, because "Password:" on
    # its own is one nobody can answer correctly twice.
    assert asked == ["password for C##SOPULI_SVC on orders-pdb: "]


def test_one_entry_is_asked_once_however_many_targets_it_generates(
    runner: CliRunner,
    write_config: WriteConfig,
    estate: Callable[..., list[Credential]],
    asked: list[str],
    watching: Callable[[bool], None],
) -> None:
    """One prompter per *run*, which is the half a per-call-site one would lose.

    `PasswordPrompt` caches, so this passes trivially for one instance and fails
    for two -- and two is what building the prompter inside `resolve` or beside
    each connection would produce. An estate of thirty-four generated targets
    asking thirty-four times is the failure this shape exists to prevent, and it
    would not be caught anywhere else: every target still connects, and the run
    still succeeds.
    """
    watching(True)
    seen = estate()
    config = write_config(ONE_ENTRY_TWO_TARGETS)

    result = _doctor(runner, config)

    assert result.exit_code == ExitCode.SUCCESS
    assert len(seen) == 2
    assert {credential.secret.reveal() for credential in seen if credential.secret} == {TYPED}
    assert len(asked) == 1


def test_without_a_terminal_the_target_is_refused_and_nobody_is_asked(
    runner: CliRunner,
    write_config: WriteConfig,
    estate: Callable[..., list[Credential]],
    asked: list[str],
    watching: Callable[[bool], None],
) -> None:
    """The refusal survives the fix, which is the point of fixing it this way.

    A prompter exists only where stdin is a terminal, so the piped run reaches
    exactly the branch it did before -- and reaches it without having opened a
    connection, which is what `seen` being empty says.
    """
    watching(False)
    seen = estate()
    config = write_config(PROMPT_TARGET)

    result = _doctor(runner, config)
    document = json.loads(result.output)

    assert seen == []
    assert asked == []
    assert document["targets"][0]["reachable"] is False
    assert "nobody here to ask" in document["targets"][0]["error"]["message"]


def test_an_empty_answer_never_reaches_the_driver(
    runner: CliRunner,
    write_config: WriteConfig,
    estate: Callable[..., list[Credential]],
    monkeypatch: pytest.MonkeyPatch,
    watching: Callable[[bool], None],
) -> None:
    """#601: Enter on its own, or a paste the hidden prompt did not take. Sent,
    it was `DPY-4001` under `connectivity`; refused, it is a `config` finding on
    the target and no connection is opened -- `seen` is the driver's side of
    "nothing was sent"."""
    watching(True)
    seen = estate()
    monkeypatch.setattr("sopuli.invocation.getpass.getpass", lambda line: "")
    config = write_config(PROMPT_TARGET)

    result = _doctor(runner, config)
    document = json.loads(result.output)
    error = document["targets"][0]["error"]

    assert seen == []
    assert document["targets"][0]["reachable"] is False
    assert error["category"] == "config"
    assert "answer was empty" in error["message"]
    # The hint is the actionable half, and the emitted document is where a
    # reader meets it.
    assert "nothing was sent" in error["hint"]
    assert "paste" in error["hint"]


def test_the_password_is_not_in_the_document(
    runner: CliRunner,
    write_config: WriteConfig,
    estate: Callable[..., list[Credential]],
    asked: list[str],
    watching: Callable[[bool], None],
) -> None:
    """Invariant 2, asked of the source that arrives as a bare `str`.

    Every other admin source is already a `Secret` before it is anywhere near an
    output path. This one is typed at a terminal, so it is a plain string for the
    width of one function -- and this pins that the string does not travel.
    """
    watching(True)
    estate()
    config = write_config(PROMPT_TARGET)

    result = _doctor(runner, config)

    assert TYPED not in result.output


# ------------------------------------- the other two call sites, which differ ---
#
# `doctor` resolves through `_open_session`; `creds check` and `creds apply` each
# resolve for themselves. Three call sites, and the bug was one missing argument
# at each -- so a test that exercises one of them proves nothing about the other
# two. Copilot made exactly this point reviewing #482, and it was right: the
# first draft of this file covered `doctor` alone, and dropping `prompt=` from
# either of the others would have kept it green.

CHECK_CONFIG = """version: 1
vaults:
  vault-prod:
    type: hashicorp
    addr: https://vault-prod.example.com:8200
targets:
  - name: appdb-alpha
    type: oracle
    dsn: db-prod.example.com:1521/alpha.pdb.example.com
    environment: prod
    vault: vault-prod
    admin: { username: C##SOPULI_SVC, auth: prompt }
applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "apps/acme/{target}#password"
"""


class CredsSession:
    """Enough of a session for `creds check` and `creds apply` to finish."""

    def __init__(self) -> None:
        self.changed: list[tuple[str, str]] = []

    def scope(self) -> Scope:
        return Scope(type="pdb", container="ALPHA", read_write=True, capabilities=frozenset())

    def privileges(self) -> PrivilegeAudit:
        return PrivilegeAudit()

    def describe_user(self, account: str) -> UserState:
        return UserState(name=account.upper(), status="OPEN", password_file_member=False)

    def verify_password(self, account: str, secret: Secret, **_: Any) -> VerifyResult:
        return VerifyResult("login", PASS, latency_ms=7)

    def set_password(self, account: str, secret: Secret) -> ChangeResult:
        self.changed.append((account.upper(), secret.reveal()))
        return ChangeResult(changed=True)

    def close(self) -> None:
        return None


@pytest.fixture
def creds_estate(monkeypatch: pytest.MonkeyPatch) -> Callable[[], list[Credential]]:
    """A vault and a driver, recording the credential each connection was given."""

    def install() -> list[Credential]:
        seen: list[Credential] = []
        store = MemoryStore()
        store.write(
            "apps/acme/appdb-alpha", {"password": TYPED, "pending": "Anchor-Marble-4"}, cas=0
        )

        def fake_connect(vault: Any, **_: Any) -> SecretStore:
            return store

        class FakeDriver:
            def __init__(self, **_: Any) -> None:
                pass

            def connect(self, target: Any, credential: Credential) -> CredsSession:
                seen.append(credential)
                return CredsSession()

        class FakeModule:
            OracleDriver = FakeDriver

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        monkeypatch.setattr("sopuli.cli.resolve_driver", lambda target: FakeModule)
        return seen

    return install


@pytest.mark.parametrize("verb", [["creds", "check"], ["creds", "apply"]])
def test_the_typed_password_reaches_the_driver_on_the_creds_verbs(
    runner: CliRunner,
    write_config: WriteConfig,
    creds_estate: Callable[[], list[Credential]],
    asked: list[str],
    watching: Callable[[bool], None],
    verb: list[str],
) -> None:
    """`_check_target` and `_apply_target`, which resolve without `_open_session`."""
    watching(True)
    seen = creds_estate()
    config = write_config(CHECK_CONFIG)

    result = runner.invoke(cli, [*verb, "--config", str(config)])

    assert seen, f"{' '.join(verb)} opened no connection: {result.output}"
    assert [one.secret.reveal() for one in seen if one.secret] == [TYPED]
    assert asked == ["password for C##SOPULI_SVC on appdb-alpha: "]


@pytest.mark.parametrize("verb", [["creds", "check"], ["creds", "apply"]])
def test_the_creds_verbs_refuse_without_a_terminal(
    runner: CliRunner,
    write_config: WriteConfig,
    creds_estate: Callable[[], list[Credential]],
    asked: list[str],
    watching: Callable[[bool], None],
    verb: list[str],
) -> None:
    """A per-target finding on these verbs too, and no connection attempted."""
    watching(False)
    seen = creds_estate()
    config = write_config(CHECK_CONFIG)

    result = runner.invoke(cli, [*verb, "--config", str(config)])

    assert seen == []
    assert asked == []
    assert "nobody here to ask" in result.output

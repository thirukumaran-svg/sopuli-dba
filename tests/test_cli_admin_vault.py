"""`auth: { method: vault }` reaches a store, from the CLI. Tier 0.

The wiring check of `tests/test_cli_admin_prompt.py`, for `read_ref`.
`admin.resolve` takes its sources as suppliers -- `env` a mapping, `prompt` a
callable, `read_ref` a callable over a ref -- and the CLI has to pass each of
them. Without `read_ref`, `_read_ref`'s "no store was available here" would be
the only reachable branch, with a hint reading *this is a caller that supplied
no reader*.

So `method: vault` would fail on every run of every verb, in the source
principle P2 ranks highest of the three that need something from this machine:
`env` is flagged low-assurance and `prompt` needs a human, which would leave no
working unattended source at all.

`tests/test_admin.py` covers `resolve` with an injected reader, and those tests
would pass without the wiring. This file gives the same answer as
`test_cli_admin_prompt.py`: run the real commands and assert on what reached the
far side.

Two things are asserted that a unit test cannot see:

* the reader is **lazy** -- a target authenticating some other way must open no
  store, which is what makes `admin.resolve`'s "a run that authenticates by
  wallet never builds a store client" true, and ADR-006's "base opens no
  sockets" one layer down;
* it opens **one client per store per run**, however many targets share it.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result

from sopuli.admin import store_name
from sopuli.cli import cli
from sopuli.config.loading import load_layers
from sopuli.config.model import Config
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.driver.protocol import Credential, PrivilegeAudit, Scope
from sopuli.exit_codes import ExitCode
from sopuli.store import MemoryStore, SecretStore

WriteConfig = Callable[[str], Path]

STORED = "Correct-Horse-Battery-9"

VAULTS = """version: 1
vaults:
  vault-dev:
    type: hashicorp
    addr: https://vault-dev.example.com:8200
  vault-other:
    type: hashicorp
    addr: https://vault-other.example.com:8200
"""

#: The target from the issue: a ref with no prefix, resolved through the
#: target's own `vault:`.
VAULT_ADMIN = (
    VAULTS
    + """targets:
  - name: orders-pdb
    type: oracle
    dsn: "db.example.com:1521/orders"
    vault: vault-dev
    admin:
      username: C##SOPULI_SVC
      auth: { method: vault, secret: "ops/dba#password" }
"""
)

#: Two targets, one store. One client, not two.
TWO_TARGETS = (
    VAULT_ADMIN
    + """  - name: billing-pdb
    type: oracle
    dsn: "db.example.com:1521/billing"
    vault: vault-dev
    admin:
      username: C##SOPULI_SVC
      auth: { method: vault, secret: "ops/dba#password" }
"""
)

#: Authenticates from a wallet, and so must never reach a store.
WALLET_ADMIN = (
    VAULTS
    + """targets:
  - name: orders-pdb
    type: oracle
    dsn: ORDERS_DEV
    vault: vault-dev
    admin: { auth: external }
"""
)

#: `method: vault` and nowhere to read from: no prefix, no `vault:` on the
#: target, no `defaults.vault`.
NO_STORE = (
    VAULTS
    + """targets:
  - name: orders-pdb
    type: oracle
    dsn: "db.example.com:1521/orders"
    admin:
      username: C##SOPULI_SVC
      auth: { method: vault, secret: "ops/dba#password" }
"""
)


#: `defaults.vault` and no `vault:` on the target -- the third link.
DEFAULTS_VAULT = (
    VAULTS
    + """defaults:
  vault: vault-dev
targets:
  - name: orders-pdb
    type: oracle
    dsn: "db.example.com:1521/orders"
    admin:
      username: C##SOPULI_SVC
      auth: { method: vault, secret: "ops/dba#password" }
"""
)

#: A profile naming a store, appended to `NO_STORE` so the file itself says
#: nothing and only the run's layers can answer.
PROFILE = """profiles:
  ci:
    vault: vault-dev
"""


class FakeSession:
    def scope(self) -> Scope:
        return Scope(type="pdb", container="ORDERS", read_write=True, capabilities=frozenset())

    def privileges(self) -> PrivilegeAudit:
        return PrivilegeAudit()

    def close(self) -> None:
        return None


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Callable[..., dict[str, Any]]:
    """A driver, and a `connect` that records every store this run opened.

    `opened` is the list the laziness and one-client-per-store assertions turn
    on: what matters is not only that a credential arrived but how many times a
    vault was authenticated to get it.
    """

    def install(*, document: Any = None) -> dict[str, Any]:
        opened: list[str] = []
        seen: list[Credential] = []
        store = MemoryStore()
        store.write(
            "ops/dba",
            {"password": STORED} if document is None else document,
            cas=0,
        )

        def fake_connect(vault: Any, **_: Any) -> SecretStore:
            opened.append(vault.name)
            return store

        class FakeDriver:
            def __init__(self, **_: Any) -> None:
                pass

            def connect(self, target: Any, credential: Credential) -> FakeSession:
                seen.append(credential)
                return FakeSession()

        class FakeModule:
            OracleDriver = FakeDriver

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        monkeypatch.setattr("sopuli.cli.resolve_driver", lambda target: FakeModule)
        # `doctor`'s `vaults` section surveys every declared store over the real
        # client, which needs a token this tier has not got -- and an unreachable
        # store is exit 1, which would mask the target result under test. That
        # section has its own tests; nothing here is about it.
        monkeypatch.setattr("sopuli.cli.vault_survey", lambda *_, **__: ())
        return {"opened": opened, "seen": seen, "store": store}

    return install


def _doctor(runner: CliRunner, config: Path, *args: str) -> Result:
    return runner.invoke(cli, ["--config", str(config), *args, "doctor"])


# ----------------------------------------------------------- the store name ---


def _config(write: WriteConfig, text: str, *, profile: str | None = None) -> Config:
    """Load a file the P4 permission check will accept.

    Through the `write_config` fixture rather than writing here: `tmp_path` is
    0700 but a file inside it inherits the process umask, so a hand-written one
    is 0644 on a CI runner and `load_layers` refuses it. Windows ACLs pass
    either way, which is why the first version of this file was green locally
    and failed every POSIX job.
    """
    return load_layers((write(text),), profile=profile, env={})[1]


def test_the_refs_own_prefix_wins(write_config: WriteConfig) -> None:
    """§7 calls `vault-other:` an *explicit* vault, so nothing outranks it."""
    config = _config(write_config, VAULT_ADMIN)
    target = config.expanded_targets[0]

    found = store_name(
        target, parse_secret_ref("vault-other:ops/dba#password"), config=config, env={}
    )

    assert found == "vault-other"


def test_the_targets_vault_comes_next(write_config: WriteConfig) -> None:
    config = _config(write_config, VAULT_ADMIN)
    target = config.expanded_targets[0]

    found = store_name(target, parse_secret_ref("ops/dba#password"), config=config, env={})

    assert found == "vault-dev"


def test_defaults_vault_comes_after_the_target(write_config: WriteConfig) -> None:
    """The third link, which nothing else in this file exercises.

    It is the one an estate of thirty-four generated targets actually uses: one
    `defaults.vault` line rather than the same `vault:` written thirty-four
    times.
    """
    config = _config(write_config, DEFAULTS_VAULT)
    target = config.expanded_targets[0]

    found = store_name(target, parse_secret_ref("ops/dba#password"), config=config, env={})

    assert found == "vault-dev"


def test_a_profile_supplies_the_store(write_config: WriteConfig) -> None:
    """The last link, and the one a reader is most likely to doubt.

    A profile is P3's layer 3 and `defaults.vault` is layer 5, so this looks
    backwards until you see that it only runs where the file said nothing at
    all -- `test_the_run_layers_never_repoint_an_arrow` is the other half.
    """
    config = _config(write_config, NO_STORE + PROFILE, profile="ci")
    target = config.expanded_targets[0]

    found = store_name(target, parse_secret_ref("ops/dba#password"), config=config, env={})

    assert found == "vault-dev"


def test_the_variable_outranks_a_profile(write_config: WriteConfig) -> None:
    """Both fill holes, and between themselves P3 orders them: layer 2 over 3."""
    config = _config(write_config, NO_STORE + PROFILE, profile="ci")
    target = config.expanded_targets[0]

    found = store_name(
        target,
        parse_secret_ref("ops/dba#password"),
        config=config,
        env={"SOPULI_VAULT": "vault-other"},
    )

    assert found == "vault-other"


def test_the_run_layers_fill_a_hole(write_config: WriteConfig) -> None:
    """`SOPULI_VAULT` supplies a store where the file named none."""
    config = _config(write_config, NO_STORE)
    target = config.expanded_targets[0]
    ref = parse_secret_ref("ops/dba#password")

    assert store_name(target, ref, config=config, env={}) is None
    assert store_name(target, ref, config=config, env={"SOPULI_VAULT": "vault-dev"}) == "vault-dev"


def test_the_run_layers_never_repoint_an_arrow(write_config: WriteConfig) -> None:
    """The half that would be a security bug if it were precedence-ordered.

    A target naming its own store is a statement about *that database*. An
    exported `SOPULI_VAULT` -- a property of whichever shell the run started in
    -- must not silently send the credential that reaches production to a
    different vault. `binding_stores` makes the same choice for the same reason.
    """
    config = _config(write_config, VAULT_ADMIN)
    target = config.expanded_targets[0]

    found = store_name(
        target,
        parse_secret_ref("ops/dba#password"),
        config=config,
        env={"SOPULI_VAULT": "vault-other"},
    )

    assert found == "vault-dev"


# ------------------------------------------------------------- and the wiring ---


def test_the_stored_password_reaches_the_driver(
    runner: CliRunner, write_config: WriteConfig, estate: Callable[..., dict[str, Any]]
) -> None:
    """A `method: vault` admin source is read through the store, not refused."""
    harness = estate()
    config = write_config(VAULT_ADMIN)

    result = _doctor(runner, config, "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert [one.secret.reveal() for one in harness["seen"] if one.secret] == [STORED]
    assert [one.username for one in harness["seen"]] == ["C##SOPULI_SVC"]
    assert json.loads(result.output)["targets"][0]["reachable"] is True


def test_a_wallet_target_opens_no_store(
    runner: CliRunner, write_config: WriteConfig, estate: Callable[..., dict[str, Any]]
) -> None:
    """The laziness, which is a property of the *shape* rather than a nicety.

    `admin.resolve` only calls `read_ref` on the vault branch, so a reader that
    resolved a store name or opened a client when it was built would authenticate
    to a vault on behalf of a run that never needed one -- and would fail a
    wallet estate whose `vaults:` block happens to be unreachable.
    """
    harness = estate()
    config = write_config(WALLET_ADMIN)

    _doctor(runner, config, "--output", "json")

    assert harness["opened"] == []


def test_two_targets_sharing_a_store_authenticate_once(
    runner: CliRunner, write_config: WriteConfig, estate: Callable[..., dict[str, Any]]
) -> None:
    """One client per store per run, which is `_stores_for`'s stated rule.

    Thirty-four targets in one vault would otherwise be thirty-four
    authentications, and thirty-four entries in that vault's audit log for one
    scheduled run.
    """
    harness = estate()
    config = write_config(TWO_TARGETS)

    result = _doctor(runner, config, "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert len(harness["seen"]) == 2
    assert harness["opened"] == ["vault-dev"]


def test_nothing_says_which_store(
    runner: CliRunner, write_config: WriteConfig, estate: Callable[..., dict[str, Any]]
) -> None:
    harness = estate()
    config = write_config(NO_STORE)

    result = _doctor(runner, config, "--output", "json")
    entry = json.loads(result.output)["targets"][0]

    assert entry["reachable"] is False
    assert "nothing says which one" in entry["error"]["message"]
    assert harness["opened"] == []


def test_an_empty_path_says_the_store_answered(
    runner: CliRunner, write_config: WriteConfig, estate: Callable[..., dict[str, Any]]
) -> None:
    """Distinct from a store that could not be reached, and worded to say so.

    `read_secret` returns `None` for every way of finding nothing -- no
    document, no field, no key. They have one remedy here, which is to go and
    look at the path, so they get one message.
    """
    harness = estate(document={"something-else": STORED})
    config = write_config(VAULT_ADMIN)

    result = _doctor(runner, config, "--output", "json")
    entry = json.loads(result.output)["targets"][0]

    assert entry["reachable"] is False
    assert "there is nothing at" in entry["error"]["message"]
    assert "ops/dba#password" in entry["error"]["message"]
    # It got as far as opening the store, which is what distinguishes this from
    # the refusal above.
    assert harness["opened"] == ["vault-dev"]


def test_one_store_serving_both_halves_is_opened_once(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One client per store per run holds across the whole run, not only inside
    the reader.

    The ordinary arrangement: the admin credential and the application's
    documents live in the same vault. A cache private to `_admin_reader` would
    make the claim true inside the reader and false across the run.
    `creds check` would open `vault-dev` once for the bindings and once more for
    the admin ref, which is two authentications and two audit entries for one
    scheduled run.

    Asserted on `creds check` rather than `doctor` because `doctor` opens no
    binding stores, so a double open cannot show there.
    """
    opened: list[str] = []
    store = MemoryStore()
    store.write("ops/dba", {"password": STORED}, cas=0)
    store.write("apps/acme/orders-pdb", {"password": STORED}, cas=0)

    def fake_connect(vault: Any, **_: Any) -> SecretStore:
        opened.append(vault.name)
        return store

    class FakeDriver:
        def __init__(self, **_: Any) -> None:
            pass

        def connect(self, target: Any, credential: Credential) -> FakeSession:
            return FakeSession()

    class FakeModule:
        OracleDriver = FakeDriver

    monkeypatch.setattr("sopuli.cli.connect", fake_connect)
    monkeypatch.setattr("sopuli.cli.resolve_driver", lambda target: FakeModule)
    config = write_config(
        VAULT_ADMIN
        + """applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "apps/acme/{target}#password"
"""
    )

    runner.invoke(cli, ["creds", "check", "--config", str(config)])

    assert opened == ["vault-dev"]


# -------------------------------------------- the survey and the admin ref ---


def _surveyed(monkeypatch: pytest.MonkeyPatch, *, fail: bool = False) -> dict[str, Any]:
    """`connect` substituted in **both** places a `doctor` run opens a store.

    The `estate` fixture replaces the survey outright, which is right for every
    test above and is exactly what would hide a double open between the
    survey and the admin reader, so a test of it has to let both run and count
    them on one list.
    """
    opened: list[str] = []
    seen: list[Credential] = []
    store = MemoryStore()
    store.write("ops/dba", {"password": STORED}, cas=0)

    def fake_connect(vault: Any, **_: Any) -> SecretStore:
        opened.append(vault.name)
        if fail and vault.name == "vault-dev":
            raise RuntimeError("vault-dev refused the login")
        return store

    class FakeDriver:
        def __init__(self, **_: Any) -> None:
            pass

        def connect(self, target: Any, credential: Credential) -> FakeSession:
            seen.append(credential)
            return FakeSession()

    class FakeModule:
        OracleDriver = FakeDriver

    monkeypatch.setattr("sopuli.cli.connect", fake_connect)
    monkeypatch.setattr("sopuli.store.survey.connect", fake_connect)
    monkeypatch.setattr("sopuli.cli.resolve_driver", lambda target: FakeModule)
    return {"opened": opened, "seen": seen}


def test_the_survey_and_the_admin_ref_share_one_login(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`vault-dev` is surveyed and is where the admin credential lives.
    One authentication for both, not one each -- a vault's audit log showing
    twice the logins a `doctor` schedule accounts for reads as a compromise
    before it reads as a bug."""
    harness = _surveyed(monkeypatch)
    config = write_config(VAULT_ADMIN)

    result = _doctor(runner, config, "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert harness["opened"].count("vault-dev") == 1
    # The other declared store is still surveyed, once.
    assert harness["opened"].count("vault-other") == 1
    assert [one.secret.reveal() for one in harness["seen"] if one.secret] == [STORED]


def test_a_store_the_survey_could_not_open_is_tried_again_for_the_admin_ref(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not cached on failure, so the target's row carries its own failure
    rather than an absent client or a pointer back to the `vaults` section."""
    harness = _surveyed(monkeypatch, fail=True)
    config = write_config(VAULT_ADMIN)

    result = _doctor(runner, config, "--output", "json")
    emitted = json.loads(result.output)

    assert harness["opened"].count("vault-dev") == 2
    assert harness["seen"] == []
    (target,) = emitted["targets"]
    assert target["reachable"] is False
    assert "refused the login" in target["error"]["message"]

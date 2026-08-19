"""``sopuli lock status`` — the answer to exit 7 (#105).

Tier 0 in everything but posture: in-process through ``CliRunner``, with the
store handed in rather than dialled. The socket is the one part deliberately not
exercised here — :mod:`tests.store.test_lock_status_vault` does that against a
real Vault, and it is the only thing there that a fake could not tell us. What
this file is for is the wiring above it: which paths get surveyed, what the
document says, and what the two output modes do with the same run.

The seam is :func:`sopuli.store.registry.connect`, patched where ``sopuli.cli``
imported it. That is not a shortcut around the backend — the backend has its own
conformance suite and its own release gate — it is what keeps a test about *the
command* from also being a test about HTTP.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator

from sopuli.cli import cli
from sopuli.config.model import Vault
from sopuli.exit_codes import ExitCode
from sopuli.lock.keys import LockKey
from sopuli.lock.manager import lock_path
from sopuli.lock.record import DEFAULT_TTL, Holder, LockRecord
from sopuli.output.document import SCHEMA_VERSION
from sopuli.store import MemoryStore, SecretStore

RUN_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

HOLDER = Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli")

#: Two stores and two environments, so `--select` has something to narrow and
#: `mode` has two stores to be the weakest of.
CONFIG = """\
version: 1
vaults:
  vault-dev:
    type: hashicorp
    addr: https://vault-dev.example.com:8200
  vault-prod:
    type: hashicorp
    addr: https://vault-prod.example.com:8200
targets:
  - name: appdb-alpha
    type: oracle
    dsn: db-dev.example.com:1521/alpha.pdb.example.com
    environment: dev
    labels: { env: dev }
    vault: vault-dev
  - name: appdb-beta
    type: oracle
    dsn: db-prod.example.com:1521/beta.pdb.example.com
    environment: prod
    labels: { env: prod }
    vault: vault-prod
applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "apps/acme/{target}#password"
"""

DEV = LockKey(store="vault-dev", path="apps/acme/appdb-alpha")
PROD = LockKey(store="vault-prod", path="apps/acme/appdb-beta")


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8")))


def held(*, now: datetime | None = None, command: str = "creds rotate") -> dict[str, Any]:
    """A record as another run would have left it."""
    moment = now if now is not None else datetime.now(UTC)
    return LockRecord.acquired(
        correlation_id="01JTHEIRS",
        command=command,
        holder=HOLDER,
        now=moment,
    ).to_dict()


#: Puts records at lock paths and returns the stores, keyed as the config names
#: them. A callable rather than a fixture value so a test writes its own estate.
Stores = Callable[..., Mapping[str, SecretStore]]


@pytest.fixture
def with_locks(monkeypatch: pytest.MonkeyPatch) -> Stores:
    """Patch the store the command opens, and hand back what it will read.

    Patched on ``sopuli.cli`` rather than on the registry, because that is the
    name the command actually calls -- patching the definition would leave the
    already-imported reference in place and quietly test nothing.
    """

    def install(*records: tuple[LockKey, dict[str, Any]]) -> Mapping[str, SecretStore]:
        stores: dict[str, SecretStore] = {}
        for key, data in records:
            store = stores.setdefault(key.store, MemoryStore())
            store.write(lock_path(key), data, cas=0)

        def fake_connect(vault: Vault, *, env: Mapping[str, str]) -> SecretStore:
            return stores.setdefault(vault.name, MemoryStore())

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        return stores

    return install


def run(runner: CliRunner, config: Path, *args: str) -> Result:
    return runner.invoke(cli, ["lock", "status", "--config", str(config), *args])


def section(result: Result) -> dict[str, Any]:
    return dict(json.loads(result.output)["lock"])


# ------------------------------------------------------------- what it surveys ---


def test_a_quiet_estate_exits_zero_and_says_how_much_it_looked_at(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """A held lock is a finding, not a failure, so a survey that found none is
    not an achievement either -- both are exit 0. Exit 7 means *this run could
    not proceed*, and this run had nothing to proceed with."""
    with_locks()
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert "0 of 2 declared lock paths held" in result.output


def test_a_held_lock_names_the_holder_and_the_string_that_clears_it(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    with_locks((PROD, held()))
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert "vault-prod:apps/acme/appdb-beta" in result.output
    assert "svc_sopuli@ci-runner-3" in result.output
    assert "1 of 2 declared lock paths held" in result.output


def test_select_narrows_the_survey_to_the_estate_somebody_meant(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """This verb opens a socket per store, so a selector is not only a filter on
    the output -- it decides which vaults are contacted at all."""
    with_locks((DEV, held()), (PROD, held()))
    result = run(runner, write_config(CONFIG), "--select", "env=dev")

    assert result.exit_code == ExitCode.SUCCESS
    assert "vault-dev:apps/acme/appdb-alpha" in result.output
    assert "vault-prod" not in result.output
    assert "1 of 1 declared lock paths held" in result.output


def test_a_lapsed_claim_is_marked_rather_than_hidden(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """The distinction the whole command exists for: a colleague mid-rotation
    and a process that died need opposite responses."""
    long_ago = datetime.now(UTC) - DEFAULT_TTL - timedelta(hours=1)
    with_locks((PROD, held(now=long_ago)))

    result = run(runner, write_config(CONFIG))

    assert "expired" in result.output
    assert "1 past expiry" in result.output


# --------------------------------------------------------------- the document ---


def test_the_json_document_validates_and_carries_the_survey(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    with_locks: Stores,
    validator: Draft202012Validator,
) -> None:
    with_locks((PROD, held()))
    result = run(runner, write_config(CONFIG), "--output", "json")

    document = json.loads(result.output)
    assert not list(validator.iter_errors(document))
    assert document["command"] == "lock.status"
    assert document["exit_code"] == ExitCode.SUCCESS
    found = document["lock"]["found"]
    assert [(one["vault"], one["path"]) for one in found] == [(PROD.store, PROD.path)]
    assert found[0]["holder"]["correlation_id"] == "01JTHEIRS"


def test_the_summary_counts_paths_examined_not_locks_found(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """`found` is what was read; `summary.total` is what was looked at. The
    difference between the two is how many paths are free, which is why neither
    number is derivable from the other."""
    with_locks((PROD, held()))
    result = run(runner, write_config(CONFIG), "--output", "json")

    document = json.loads(result.output)
    assert document["summary"] == {"total": 2, "ok": 2, "changed": 0, "failed": 0}
    assert len(document["lock"]["found"]) == 1


def test_a_quiet_estate_still_emits_the_section(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """Absent means *no lock was needed*, which is not what happened here. An
    empty `found` is the finding."""
    with_locks()
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert section(result) == {"mode": "cas", "found": []}


def test_the_selection_is_recorded_in_the_document(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """A survey over part of the estate must say so, or a consumer counting one
    lock cannot tell a small estate from a filtered one."""
    with_locks((DEV, held()))
    result = run(runner, write_config(CONFIG), "--select", "env=dev", "--output", "json")

    assert json.loads(result.output)["invocation"]["selection"]["select"] == {"env": "dev"}


def test_it_takes_no_lock_of_its_own(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """#83 settled it for `check`, `status` and every `--dry-run`, and the reason
    is not politeness: an hourly survey that locked would block the rotations it
    exists to report on. Asserted against the store rather than the output --
    a write is what a lock is."""
    stores = with_locks()
    run(runner, write_config(CONFIG), "--output", "json")

    for store in stores.values():
        assert store.read(lock_path(DEV)) is None
        assert store.read(lock_path(PROD)) is None

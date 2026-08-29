"""``sopuli creds generate`` end to end (#254).

The first credential mutation, so the assertions worth having are about what
reaches the store and what does not: one write per document, a lock held around
it and released after, a compare-and-set that is never retried, and no plaintext
anywhere but the value at the path.

`MemoryStore` stands in for the vault, patched where ``sopuli.cli`` imported
`connect`. The real backend has its own conformance suite; this file is about the
command.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator

from sopuli.cli import cli
from sopuli.config.errors import ConfigError
from sopuli.config.model import Vault
from sopuli.exit_codes import ExitCode
from sopuli.lock.errors import LockDeniedError
from sopuli.lock.manager import lock_path
from sopuli.output.document import SCHEMA_VERSION
from sopuli.payload import PENDING
from sopuli.store import MemoryStore, SecretStore

RUN_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

#: Two accounts in one document -- Q7's default layout, with the pointer per
#: account that makes staging address them separately.
CONFIG = """\
version: 1
defaults:
  policy: app-standard
policies:
  app-standard:
    password: { length: 24, charset: alnum, first_char: alpha }
vaults:
  vault-prod:
    type: hashicorp
    addr: https://vault-prod.example.com:8200
targets:
  - name: appdb-alpha
    type: oracle
    dsn: db.example.com:1521/alpha.pdb.example.com
    environment: dev
    labels: { env: dev, tenant: alpha }
    vault: vault-prod
applications:
  - name: acme
    targets: [appdb-alpha]
    accounts: [acme_web_user, acme_batch_user]
    secret_template: "apps/acme/dev#DB_CREDENTIALS/{account}"
"""

PATH = "apps/acme/dev"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8")))


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> MemoryStore:
    """The one store the command opens, patched where `cli` imported `connect`."""
    memory = MemoryStore()

    def fake_connect(
        vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
    ) -> SecretStore:
        return memory

    monkeypatch.setattr("sopuli.cli.connect", fake_connect)
    return memory


def run(runner: CliRunner, config: Path, *args: str, stdin: str | None = None) -> Result:
    return runner.invoke(cli, ["creds", "generate", "--config", str(config), *args], input=stdin)


def document(result: Result) -> dict[str, Any]:
    return dict(json.loads(result.output))


def staged(store: MemoryStore) -> dict[str, Any]:
    found = store.read(PATH)
    assert found is not None
    return dict(found.data[PENDING])


def refused(result: Result) -> int:
    assert isinstance(result.exception, ConfigError), result.exception
    return int(result.exception.exit_code)


# ------------------------------------------------------------- the write ---


def test_it_stages_a_password_for_every_selected_account(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert set(staged(store)) == {"acme_web_user", "acme_batch_user"}


def test_each_account_gets_its_own_password(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """Sharing a document is a storage layout, not a shared credential."""
    run(runner, write_config(CONFIG))

    values = staged(store)
    assert values["acme_web_user"] != values["acme_batch_user"]


def test_one_document_is_one_write(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """Two accounts, one version. Two writes would leave a version describing a
    state nobody intended, and would be two chances to fail halfway."""
    run(runner, write_config(CONFIG))

    found = store.read(PATH)
    assert found is not None
    assert found.version == 1


def test_current_is_not_touched(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """Invariant 7's ordering begins here: nothing reaches `current` until every
    target has confirmed, and `generate` never confirms anything."""
    store.write(PATH, {"DB_CREDENTIALS": {"acme_web_user": "the-live-one"}}, cas=0)

    run(runner, write_config(CONFIG))

    found = store.read(PATH)
    assert found is not None
    assert found.data["DB_CREDENTIALS"]["acme_web_user"] == "the-live-one"


# ------------------------------------------------------ staging over itself ---


def test_a_second_run_replaces_pending_and_reports_a_change(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """#254's decision, and the one exemption from invariant 9: a fresh draw has
    no state to converge on, so `changed: false` would be false."""
    config = write_config(CONFIG)
    run(runner, config)
    first = staged(store)

    body = document(run(runner, config, "--output", "json"))

    assert staged(store)["acme_web_user"] != first["acme_web_user"]
    assert all(entry["changed"] is True for entry in body["results"])
    assert body["summary"]["changed"] == 2


def test_replacing_a_staged_password_warns_that_it_did(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """Safe, per UC-1 §4, and not silent: anything already holding the old
    staged password is now worthless."""
    config = write_config(CONFIG)
    run(runner, config)

    body = document(run(runner, config, "--output", "json"))

    warnings = body["results"][0]["warnings"]
    assert any("replaced a pending" in one["message"] for one in warnings)


# --------------------------------------------------------------- the lock ---


def test_the_run_takes_the_document_s_lock_and_releases_it(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """`generate` can take a lock at all precisely because the lock lives in the
    vault (Q2, #83) -- this command never opens a database connection."""
    body = document(run(runner, write_config(CONFIG), "--output", "json"))

    assert body["lock"]["mode"] == "cas"
    assert [one["path"] for one in body["lock"]["held"]] == [PATH]
    assert body["lock"]["held"][0]["released"] is True


def test_two_accounts_in_one_document_take_one_lock(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """Keyed on the path, which is what Q2 decided and why: per-account would
    miss the collision, and a run would deadlock against itself."""
    body = document(run(runner, write_config(CONFIG), "--output", "json"))

    assert len(body["lock"]["held"]) == 1


def test_a_held_lock_stops_the_run_and_writes_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """Exit 7, and the document is untouched: a run that loses the race is a run
    that touched nothing."""
    from datetime import UTC, datetime

    from sopuli.lock.keys import LockKey
    from sopuli.lock.record import Holder, LockRecord

    key = LockKey(store="vault-prod", path=PATH)
    store.write(
        lock_path(key),
        LockRecord.acquired(
            correlation_id="01JTHEIRS",
            command="creds rotate",
            holder=Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli"),
            now=datetime.now(UTC),
        ).to_dict(),
        cas=0,
    )

    result = run(runner, write_config(CONFIG))

    assert isinstance(result.exception, LockDeniedError)
    assert store.read(PATH) is None


# -------------------------------------------------------------- --dry-run ---


def test_dry_run_writes_nothing_and_takes_no_lock(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """Invariant 8. `plan` already says what would happen at the same grain, so
    there is no `results` and no state invented for "would have"."""
    body = document(run(runner, write_config(CONFIG), "--dry-run", "--output", "json"))

    assert store.read(PATH) is None
    assert "lock" not in body
    assert "results" not in body
    assert body["plan"]["blast_radius"]["accounts"] == 2


def test_dry_run_shows_the_document_it_would_write(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """Grouped the way the write will be, so an operator authorising a mutation
    sees two accounts sharing one write as one line rather than two that look
    independent."""
    result = run(runner, write_config(CONFIG), "--dry-run")

    assert "vault-prod:apps/acme/dev" in result.output
    assert "acme_web_user, acme_batch_user" in result.output
    assert "nothing was written" in result.output


# ----------------------------------------------------------- --from-stdin ---


def test_from_stdin_uses_the_supplied_password(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    run(runner, write_config(CONFIG), "--from-stdin", stdin="SuppliedPassword2026abcd\n")

    assert staged(store)["acme_web_user"] == "SuppliedPassword2026abcd"


def test_from_stdin_is_validated_against_the_same_policy(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """What stops `--from-stdin` becoming a way to write a password the policy
    would have refused."""
    result = run(runner, write_config(CONFIG), "--from-stdin", stdin="short\n")

    assert result.exception is not None
    assert store.read(PATH) is None


def test_no_policy_check_accepts_it_and_records_what_it_accepted(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    body = document(
        run(
            runner,
            write_config(CONFIG),
            "--from-stdin",
            "--no-policy-check",
            "--output",
            "json",
            stdin="short\n",
        )
    )

    assert staged(store)["acme_web_user"] == "short"
    warnings = body["results"][0]["warnings"]
    assert any("--no-policy-check accepted" in one["message"] for one in warnings)


def test_an_empty_stdin_is_refused(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    result = run(runner, write_config(CONFIG), "--from-stdin", stdin="")

    assert result.exception is not None
    assert store.read(PATH) is None


# ------------------------------------------------------------- the safety ---


def test_readonly_refuses_before_anything_is_opened(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """Staging is a mutation, and `readonly` is the operator declining in
    advance, in the file."""
    config = CONFIG.replace("defaults:\n", "defaults:\n  safety: { readonly: true }\n")

    assert refused(run(runner, write_config(config))) == ExitCode.ABORTED
    assert store.read(PATH) is None


def test_readonly_refuses_a_dry_run_too(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """The simple rule: under `readonly` the mutating verbs are unavailable, and
    the read-only verb is how you ask."""
    config = CONFIG.replace("defaults:\n", "defaults:\n  safety: { readonly: true }\n")

    assert refused(run(runner, write_config(config), "--dry-run")) == ExitCode.ABORTED


def test_max_targets_refuses_before_the_store_is_opened(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    config = CONFIG.replace("defaults:\n", "defaults:\n  safety: { max_targets: 0 }\n")

    result = run(runner, write_config(config))

    assert result.exception is not None
    assert store.read(PATH) is None


# ------------------------------------------------------------ the document ---


def test_the_document_validates(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    validator: Draft202012Validator,
) -> None:
    body = document(run(runner, write_config(CONFIG), "--output", "json"))

    assert not list(validator.iter_errors(body))
    assert [entry["state"] for entry in body["results"]] == ["PENDING_APPLY", "PENDING_APPLY"]


def test_the_result_addresses_the_stage_it_wrote(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    body = document(run(runner, write_config(CONFIG), "--output", "json"))

    secret = body["results"][0]["secret"]
    assert secret["stage"] == PENDING
    assert secret["version"] == 1
    assert secret["path"] == PATH


def test_no_password_reaches_the_document_or_the_terminal(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """Invariant 2. The only place the plaintext exists is at the path in the
    store; there is no `--reveal` here and no column for one."""
    result = run(runner, write_config(CONFIG), "--output", "json")
    secrets = set(staged(store).values())

    assert secrets
    for value in secrets:
        assert value not in result.output


def test_a_crlf_line_ending_is_stripped_whole(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """Caught by Copilot on #256. `--from-stdin` had its own copy of the
    strip-one-newline rule that handled only `\n`, so a password piped in on
    Windows kept a trailing `\r` -- and P4 is precisely the rule that says
    behaviour must be identical there. Now calls
    `sopuli.material.strip_one_newline` rather than restating it.
    """
    run(runner, write_config(CONFIG), "--from-stdin", stdin="SuppliedPassword2026abcd\r\n")

    assert staged(store)["acme_web_user"] == "SuppliedPassword2026abcd"


def test_a_trailing_space_in_a_supplied_password_survives(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """The other half of that rule: exactly one newline, never `.strip()`. A
    password may legitimately end in a space, and trimming it is a bug that
    surfaces much later as a credential that works nowhere."""
    run(
        runner,
        write_config(CONFIG),
        "--from-stdin",
        "--no-policy-check",
        stdin="SuppliedPassword2026abc \n",
    )

    assert staged(store)["acme_web_user"] == "SuppliedPassword2026abc "


def test_only_the_accounts_that_had_a_pending_are_told_it_was_replaced(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """Caught by Copilot on #256. The write is shared; what it replaced is not.

    One account had a staged password and its neighbour did not, and reporting
    the document's answer for both would tell somebody a credential was replaced
    that never existed -- sending them to look for it.
    """
    store.write(PATH, {PENDING: {"acme_web_user": "an-earlier-staged-one"}}, cas=0)

    body = document(run(runner, write_config(CONFIG), "--output", "json"))

    by_account = {entry["account"]: entry for entry in body["results"]}
    web = by_account["acme_web_user"].get("warnings", [])
    batch = by_account["acme_batch_user"].get("warnings", [])

    assert any("replaced a pending" in one["message"] for one in web)
    assert not any("replaced a pending" in one["message"] for one in batch)

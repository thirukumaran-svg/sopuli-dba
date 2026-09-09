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
from sopuli.clock import utc_now
from sopuli.config.errors import ConfigError
from sopuli.config.model import Vault
from sopuli.constraints import AccountConstraints
from sopuli.exit_codes import ExitCode
from sopuli.lock.errors import LockDeniedError
from sopuli.lock.keys import LockKey
from sopuli.lock.manager import lock_path
from sopuli.lock.record import Holder, LockRecord
from sopuli.output.document import SCHEMA_VERSION
from sopuli.passwords import ByteLimit
from sopuli.payload import ORIGIN, PENDING, PREVIOUS
from sopuli.store import MemoryStore, SecretStore
from sopuli.store.protocol import MetadataNotPermittedError

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

#: Two documents, so there is a second iteration for a fence check to stop at.
#: One target per document is the layout `01-configuration.md` §7 calls ordinary.
TWO_DOCUMENTS = """\
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
    vault: vault-prod
  - name: appdb-beta
    type: oracle
    dsn: db.example.com:1521/beta.pdb.example.com
    environment: dev
    vault: vault-prod
applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "apps/acme/{target}#DB_CREDENTIALS/{account}"
"""


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


def test_a_new_lock_path_is_made_to_require_a_compare_and_set(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """#390. The run creates the path, so the metadata it creates it with is what
    every later run is judged against -- and used to be refused by."""
    run(runner, write_config(CONFIG))

    metadata = store.metadata(lock_path(LockKey(store="vault-prod", path=PATH)))
    assert metadata is not None
    assert metadata.cas_required is True


def test_a_store_that_will_not_guard_the_path_says_so_where_it_can_be_read(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """The whole point of the degradation (#390): the run succeeds, and the fact
    that it could not arrange the guarantee reaches somebody.

    In the text, not only in `diagnostics[]` -- #309's rule, and this is a
    warning whose entire purpose is to send a reader to the vault.
    """

    def refuse(path: str) -> None:
        raise MetadataNotPermittedError(f"the store refused to set `cas_required` on {path!r}")

    store.require_cas = refuse  # type: ignore[method-assign]

    result = run(runner, write_config(CONFIG))

    assert result.exit_code == 0
    assert "SOPULI-W019" not in result.output  # the code is the JSON contract's, not the text's
    assert "not guarded against a write carrying no compare-and-set" in result.output

    # A second look at the same thing through the machine stream, and the path is
    # wiped first so that this run is a *first* acquisition too. Left alone it
    # would meet the exit-5 refusal instead -- which is the correct next thing to
    # happen and is asserted in `tests/lock/test_manager.py`, not here.
    store.paths.pop(lock_path(LockKey(store="vault-prod", path=PATH)), None)
    body = document(run(runner, write_config(CONFIG), "--output", "json"))

    assert "SOPULI-W019" in [one["code"] for one in body["diagnostics"]]


def test_a_held_lock_stops_the_run_and_writes_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """Exit 7, and the document is untouched: a run that loses the race is a run
    that touched nothing."""
    from datetime import UTC, datetime

    from sopuli.lock.keys import LockKey
    from sopuli.lock.record import Holder, LockRecord

    key = LockKey(store="vault-prod", path=PATH)
    # With the metadata a real rival run would have arranged (#390): a lock path
    # created without `cas_required` is refused by pre-flight, which is a
    # different refusal from the held-lock one under test here.
    store.require_cas(lock_path(key))
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


# ------------------------------------------------------------------ the fence ---


def test_a_takeover_mid_run_stops_before_the_next_document_is_staged(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    monkeypatch: pytest.MonkeyPatch,
    validator: Draft202012Validator,
) -> None:
    """#282, UC-1 §8: the fence is re-read before *every* vault write, including
    this one.

    The window is small here -- acquire, read, write -- but small is not a
    property the next change to this loop preserves, and a password staged under
    somebody else's lock is one the run that holds it will promote.

    Exit 4 rather than 7 for the reason `apply` splits on: one document has been
    staged, and 7 asserts that nothing happened.
    """
    seen: list[str] = []
    original = store.read
    plant = store.write
    alpha = LockKey(store="vault-prod", path="apps/acme/appdb-alpha")
    beta = LockKey(store="vault-prod", path="apps/acme/appdb-beta")

    def read(path: str, *args: Any, **fields: Any) -> Any:
        # On the *second* read of alpha's record, which is its fence check --
        # the first is the acquisition. Firing on the first would plant the
        # record before beta had been acquired, and the run would be refused at
        # acquisition instead: exit 7 by the other route, testing nothing new.
        if path == lock_path(alpha):
            seen.append(path)
            if len(seen) == 2:
                theirs = LockRecord.acquired(
                    correlation_id="01JSOMEBODYELSE",
                    command="creds rotate",
                    holder=Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli"),
                    now=utc_now(),
                )
                # Under the version it is at: since #390 the acquisition sets
                # `cas_required`, so an unguarded write is refused by the store.
                at = store.read(lock_path(beta))
                plant(lock_path(beta), theirs.to_dict(), cas=None if at is None else at.version)
        return original(path, *args, **fields)

    monkeypatch.setattr(store, "read", read)

    result = run(runner, write_config(TWO_DOCUMENTS), "--output", "json")
    found = document(result)

    validator.validate(found)
    assert found["exit_code"] == ExitCode.PARTIAL
    assert [one["code"] for one in found["diagnostics"] if one["level"] == "error"] == [
        "SOPULI-W011"
    ]
    assert store.read("apps/acme/appdb-alpha") is not None
    assert store.read("apps/acme/appdb-beta") is None


# ------------------------------------------------------- target constraints ---
#
# UC-1 §4 step 2 (#317). Every test above reaches this code and takes the
# unreachable path, because none of them patches a session and `db.example.com`
# does not exist -- which is itself the assertion that a target that will not
# answer costs the run nothing but strictness.


class _Session:
    """A connection that answers two questions and counts its own closing.

    The second question is per account and the first is not, which is the split
    §4 step 2 makes: how long a password may be is a property of the database,
    and what will judge it is a property of the account's profile.
    """

    def __init__(
        self, limit: ByteLimit, profiles: Mapping[str, AccountConstraints] | None = None
    ) -> None:
        self.limit = limit
        self.profiles = dict(profiles or {})
        self.asked: list[str] = []
        self.closed = False

    def byte_limit(self) -> ByteLimit:
        return self.limit

    def password_constraints(self, account: str) -> AccountConstraints | None:
        self.asked.append(account)
        return self.profiles.get(account)

    def close(self) -> None:
        self.closed = True


def _reachable(
    monkeypatch: pytest.MonkeyPatch,
    limits: Mapping[str, ByteLimit],
    profiles: Mapping[str, AccountConstraints] | None = None,
) -> dict[str, _Session]:
    """Targets that answer, by name. Anything unlisted refuses to connect."""
    opened: dict[str, _Session] = {}

    def fake_open(target: Any, invocation: Any, config: Any) -> _Session:
        if target.name not in limits:
            raise RuntimeError(f"no listener for {target.name}")
        opened[target.name] = _Session(limits[target.name], profiles)
        return opened[target.name]

    monkeypatch.setattr("sopuli.cli._open_session", fake_open)
    return opened


#: What the estate says about a password once one has been drawn -- the half of
#: §4 step 2 that reports rather than binds (#317). Keyed by the account name the
#: *config* uses; the value carries the database's own spelling, as the driver
#: returns it.
GUARDED = {
    "acme_web_user": AccountConstraints(
        account="ACME_WEB_USER",
        profile="ACME_PROF",
        verify_function="ORA12C_STRONG_VERIFY_FUNCTION",
        reuse_max="3",
        reuse_time="10",
        versions=("11G", "12C"),
    ),
    "acme_batch_user": AccountConstraints(
        account="ACME_BATCH_USER",
        profile="ACME_PROF",
        verify_function="ORA12C_STRONG_VERIFY_FUNCTION",
        reuse_max="3",
        reuse_time="10",
        versions=("11G", "12C"),
    ),
}


ASCII_128 = ByteLimit(max_bytes=128, encoding="ascii", charset="US7ASCII")
ASCII_8 = ByteLimit(max_bytes=8, encoding="ascii", charset="US7ASCII")


def test_an_unreachable_estate_falls_back_to_the_policy_and_says_so(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """§4's fallback, and the whole reason this is not a new way to fail.

    Staging a password for an estate that is down is a thing operators do. What
    the run may not do is stay quiet about which of the two answers it got.
    """
    result = run(runner, write_config(CONFIG), "--output", "json")
    found = document(result)

    assert found["exit_code"] == ExitCode.SUCCESS
    assert "SOPULI-W015" in [one.get("code") for one in found.get("diagnostics", [])]
    assert staged(store)


def test_offline_asks_nothing_and_warns_about_nothing(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A warning that fires because a flag was passed teaches its reader to
    filter it, so `--offline` is silent -- and it must genuinely not connect,
    which is what the exploding opener asserts."""

    def explode(target: Any, invocation: Any, config: Any) -> Any:
        raise AssertionError("--offline connected to a target")

    monkeypatch.setattr("sopuli.cli._open_session", explode)

    found = document(run(runner, write_config(CONFIG), "--offline", "--output", "json"))

    assert found["exit_code"] == ExitCode.SUCCESS
    assert "SOPULI-W015" not in [one.get("code") for one in found.get("diagnostics", [])]
    assert staged(store)


def test_a_reachable_estate_is_asked_once_per_target_not_once_per_account(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """What §4's "one representative target" means for a per-account command.

    `CONFIG` binds two accounts to one target. Asking per account would double
    the connections, by a factor the config decides rather than the operator.
    """
    calls: list[str] = []

    def counting(target: Any, invocation: Any, config: Any) -> _Session:
        calls.append(target.name)
        return _Session(ASCII_128)

    monkeypatch.setattr("sopuli.cli._open_session", counting)
    run(runner, write_config(CONFIG), "--output", "json")

    assert calls == ["appdb-alpha"]
    assert len(staged(store)) == 2, "two accounts, one connection"


def test_the_session_is_closed_after_the_constraint_is_read(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A read-only connection is still a connection, and this command holds a
    lock afterwards -- leaving one open would keep a session for the length of a
    vault write it has nothing to do with."""
    opened = _reachable(monkeypatch, {"appdb-alpha": ASCII_128})

    run(runner, write_config(CONFIG), "--output", "json")

    assert opened["appdb-alpha"].closed is True


def test_a_limit_the_policy_cannot_satisfy_is_refused_before_anything_is_staged(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refusal class #317 exists to remove, moved to where it can be fixed.

    A 24-character policy against a target holding 8 bytes is impossible, and
    without this it is discovered by `apply` -- after the vault has a `pending`
    that cannot be applied anywhere.
    """
    _reachable(monkeypatch, {"appdb-alpha": ASCII_8})

    result = run(runner, write_config(CONFIG))

    assert result.exit_code != 0
    assert store.read(PATH) is None


def test_the_strictest_target_governs_the_draw(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two targets, and the tighter one decides for both documents.

    The generous target would have accepted the policy; the run is refused all
    the same, because a password staged for the estate has to be applicable to
    every target in it.
    """
    _reachable(monkeypatch, {"appdb-alpha": ASCII_128, "appdb-beta": ASCII_8})

    result = run(runner, write_config(TWO_DOCUMENTS))

    assert result.exit_code != 0
    assert store.read("apps/acme/appdb-alpha") is None


def test_a_partly_reachable_estate_stages_and_says_the_limit_may_not_be_strictest(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Three of four targets is a caveat on how strict the answer is, not a
    reason to stop -- and not the same claim as having surveyed the estate."""
    _reachable(monkeypatch, {"appdb-alpha": ASCII_128})

    found = document(run(runner, write_config(TWO_DOCUMENTS), "--output", "json"))
    warnings = [one for one in found.get("diagnostics", []) if one.get("code") == "SOPULI-W015"]

    assert found["exit_code"] == ExitCode.SUCCESS
    assert len(warnings) == 1
    assert "appdb-beta" in warnings[0]["message"]
    assert "strictest" in warnings[0]["message"]


def test_the_constraints_section_reports_what_the_estate_said(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    monkeypatch: pytest.MonkeyPatch,
    validator: Draft202012Validator,
) -> None:
    """The whole of §4 step 2 in one document: the limit that bound the draw, and
    the three things that bind nothing and are reported anyway."""
    _reachable(monkeypatch, {"appdb-alpha": ASCII_128}, GUARDED)

    found = document(run(runner, write_config(CONFIG), "--output", "json"))
    validator.validate(found)
    section = found["constraints"]

    assert found["exit_code"] == ExitCode.SUCCESS
    assert section["source"] == "targets"
    assert section["max_password_bytes"] == 128
    assert section["targets"] == [
        {
            "target": "appdb-alpha",
            "reachable": True,
            "max_password_bytes": 128,
            "measured_as": "ascii",
            "character_set": "US7ASCII",
        }
    ]
    assert [one["account"] for one in section["accounts"]] == [
        "ACME_WEB_USER",
        "ACME_BATCH_USER",
    ]
    assert section["accounts"][0]["verify_function"] == {
        "state": "named",
        "name": "ORA12C_STRONG_VERIFY_FUNCTION",
    }
    assert section["accounts"][0]["password_versions"] == ["11G", "12C"]


def test_offline_emits_no_section_because_nothing_was_asked(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Absence means the question was not asked. A run that asked and learned
    nothing emits the section with `source: policy`, which is a different run."""

    def explode(target: Any, invocation: Any, config: Any) -> Any:
        raise AssertionError("--offline connected to a target")

    monkeypatch.setattr("sopuli.cli._open_session", explode)

    found = document(run(runner, write_config(CONFIG), "--offline", "--output", "json"))

    assert "constraints" not in found


def test_an_unreachable_estate_still_gets_a_section(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """`db.example.com` does not exist, so the run falls back -- and the section
    is the evidence that the estate was consulted, which is `install`'s rule."""
    found = document(run(runner, write_config(CONFIG), "--output", "json"))

    assert found["constraints"]["source"] == "policy"
    assert found["constraints"]["targets"] == [{"target": "appdb-alpha", "reachable": False}]
    assert "accounts" not in found["constraints"]


def test_a_verify_function_is_warned_about_once_for_the_profile(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two accounts, one profile, one warning -- and the password is still staged,
    because nothing here gates a draw."""
    _reachable(monkeypatch, {"appdb-alpha": ASCII_128}, GUARDED)

    found = document(run(runner, write_config(CONFIG), "--output", "json"))
    warnings = [one for one in found["diagnostics"] if one.get("code") == "SOPULI-W016"]

    assert len(warnings) == 1
    assert "ACME_WEB_USER, ACME_BATCH_USER" in warnings[0]["message"]
    assert warnings[0]["target"] == "appdb-alpha"
    assert len(staged(store)) == 2


def test_reuse_is_warned_about_only_when_a_password_was_supplied(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A drawn password cannot collide with a hashed history; a dictated one can."""
    _reachable(monkeypatch, {"appdb-alpha": ASCII_128}, GUARDED)

    drawn = document(run(runner, write_config(CONFIG), "--output", "json"))
    assert [one.get("code") for one in drawn["diagnostics"]].count("SOPULI-W017") == 0

    _reachable(monkeypatch, {"appdb-alpha": ASCII_128}, GUARDED)
    given = document(
        run(
            runner,
            write_config(CONFIG),
            "--from-stdin",
            "--output",
            "json",
            stdin="SuppliedPassw0rdForAcme1\n",
        )
    )
    reuse = [one for one in given["diagnostics"] if one.get("code") == "SOPULI-W017"]

    assert given["exit_code"] == ExitCode.SUCCESS, "the warning rides a run that staged"
    assert len(reuse) == 1
    assert "PASSWORD_REUSE_MAX 3" in reuse[0]["message"]


def test_a_profile_that_cannot_be_read_does_not_cost_the_run_its_limit(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The target answered the question that matters. Losing the byte limit
    because a report could not be assembled would turn a reporting change into a
    downgrade of the one reading that governs the draw."""

    class _Refusing(_Session):
        def password_constraints(self, account: str) -> AccountConstraints | None:
            raise RuntimeError("ORA-00942: table or view does not exist")

    def fake_open(target: Any, invocation: Any, config: Any) -> _Session:
        return _Refusing(ASCII_128)

    monkeypatch.setattr("sopuli.cli._open_session", fake_open)

    found = document(run(runner, write_config(CONFIG), "--output", "json"))

    assert found["constraints"]["source"] == "targets"
    assert found["constraints"]["max_password_bytes"] == 128
    assert "accounts" not in found["constraints"]
    assert [one.get("code") for one in found.get("diagnostics", [])] == []
    assert len(staged(store)) == 2


def test_the_terminal_says_what_bound_the_draw(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The JSON is the contract and this is the sentence an operator reads."""
    _reachable(monkeypatch, {"appdb-alpha": ASCII_128}, GUARDED)

    result = run(runner, write_config(CONFIG))

    assert "constraints: 128 bytes in US7ASCII, from appdb-alpha" in result.output


def test_the_notes_are_visible_to_somebody_reading_a_terminal(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#309's rule: a warning nobody can see in the default output is not
    surfaced. The emitter prints the command's text and not the document, so a
    verify function reported only in `diagnostics[]` is reported to nobody who
    ran this by hand."""
    _reachable(monkeypatch, {"appdb-alpha": ASCII_128}, GUARDED)

    output = run(runner, write_config(CONFIG)).output

    assert "1 note:" in output
    assert "ORA12C_STRONG_VERIFY_FUNCTION" in output


def test_the_unread_estate_is_said_once_and_not_twice(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """`SOPULI-W015` stays out of the notes block: the constraints line above it
    already says the estate was not read, and a block headed "notes" that repeats
    the line above teaches a reader to skip it."""
    output = run(runner, write_config(CONFIG)).output

    assert "constraints: no target answered" in output
    assert "note" not in output


# ------------------------------------------------------------- --promote (#257) ---
#
# UC-1 §4's adoption path, and invariant 7's one exception. The assertions worth
# having are about what ends up in the document and what a run is not allowed to
# do to it silently: `current` is the field applications read, and replacing it
# is the thing `--overwrite-current` exists to make somebody type.

CONTAINER = "DB_CREDENTIALS"


def current(store: MemoryStore) -> dict[str, Any]:
    """What the document's current stage holds, by account."""
    found = store.read(PATH)
    assert found is not None
    return dict(found.data[CONTAINER])


def seed_current(store: MemoryStore, **values: str) -> None:
    """A document that already advertises a password, as an estate in use has."""
    store.write(PATH, {CONTAINER: dict(values)}, cas=0)


def test_promote_writes_current_and_stages_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """S1: the account exists, its password is not in the vault, and one write
    adopts it. Staging first would mean a `pending` nothing has read and a
    `current` that does not exist."""
    result = run(runner, write_config(CONFIG), "--promote")

    assert result.exit_code == ExitCode.SUCCESS
    assert set(current(store)) == {"acme_web_user", "acme_batch_user"}
    found = store.read(PATH)
    assert found is not None
    assert found.data.get(PENDING, {}) == {}, "a promote stages nothing"


def test_promote_reports_vault_only(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    validator: Draft202012Validator,
) -> None:
    """#257 blocker 2. The vault holds this password and no database has been
    asked, which is the one thing none of the other states could say."""
    found = document(run(runner, write_config(CONFIG), "--promote", "--output", "json"))
    validator.validate(found)
    entry = found["results"][0]

    assert entry["state"] == "VAULT_ONLY"
    assert entry["changed"] is True
    assert entry["actions"][0] == {
        "kind": "vault_promote",
        "applied": True,
        "detail": "promoted to v1",
    }
    assert entry["secret"]["stage"] == "current"
    assert found["summary"]["by_state"] == {"VAULT_ONLY": 2}


def test_the_stamps_go_in_the_same_write(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """UC-1 §3 requires them beside the value, and one write is what makes the
    document never describe a state that was not true."""
    run(runner, write_config(CONFIG), "--promote")

    found = store.read(PATH)
    assert found is not None
    assert found.version == 1, "one write, not one per key"
    assert sorted(found.data["rotated_at"]) == ["acme_batch_user", "acme_web_user"]
    assert found.data["policy"]["acme_web_user"] == "app-standard"


def test_a_seeded_account_gets_no_previous(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """There was nothing to roll back to, and a `previous` naming the password
    just written would be a rollback target that never worked."""
    run(runner, write_config(CONFIG), "--promote")

    found = store.read(PATH)
    assert found is not None
    assert found.data.get(PREVIOUS, {}) == {}


def test_an_existing_current_is_refused_without_the_flag(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """Invariant 7's exception is `--overwrite-current`, and this is the gate.

    Exit 8 -- "aborted, or confirmation declined" -- because a required
    authorisation nobody gave is that: the file is not wrong and the run is not
    broken.
    """
    seed_current(store, acme_web_user="the-live-one")

    result = run(runner, write_config(CONFIG), "--promote")

    assert refused(result) == ExitCode.ABORTED
    assert current(store) == {"acme_web_user": "the-live-one"}, "nothing was written"


def test_the_refusal_names_the_accounts_rather_than_counting_them(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """The operator's next move is deciding whether *those* passwords may be
    replaced, and "1 account" sends them to `--dry-run` to find out which."""
    seed_current(store, acme_web_user="the-live-one")

    result = run(runner, write_config(CONFIG), "--promote")

    assert isinstance(result.exception, ConfigError)
    assert "acme_web_user" in str(result.exception)
    assert "--overwrite-current" in (result.exception.hint or "")


def test_a_dry_run_is_never_refused_and_shows_the_split(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """A preview is how somebody finds out they need the flag. Refusing to show
    it would leave them guessing which accounts it was about."""
    seed_current(store, acme_web_user="the-live-one")

    result = run(runner, write_config(CONFIG), "--promote", "--dry-run")

    assert result.exit_code == ExitCode.SUCCESS
    assert "SEEDED" in result.output
    assert "REPLACED" in result.output
    assert "nothing was written (--dry-run)" in result.output


def test_the_authorised_overwrite_moves_the_old_value_into_previous(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """The value `current` held, never the one being written -- or §8's rollback
    has nothing to roll back to."""
    seed_current(store, acme_web_user="the-live-one")

    result = run(runner, write_config(CONFIG), "--promote", "--overwrite-current")

    assert result.exit_code == ExitCode.SUCCESS
    found = store.read(PATH)
    assert found is not None
    assert found.data[PREVIOUS]["acme_web_user"] == "the-live-one"
    assert found.data[CONTAINER]["acme_web_user"] != "the-live-one"


def test_replacing_a_current_is_warned_about_per_account(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """A shared document can seed one account and replace another's `current` in
    one write, and telling the seeded account its password was replaced sends
    somebody looking for a credential that never existed."""
    seed_current(store, acme_web_user="the-live-one")

    found = document(
        run(
            runner,
            write_config(CONFIG),
            "--promote",
            "--overwrite-current",
            "--output",
            "json",
        )
    )
    by_account = {entry["account"]: entry for entry in found["results"]}

    replaced = [
        one["message"]
        for one in by_account["acme_web_user"].get("warnings", [])
        if "replaced the `current`" in one["message"]
    ]
    assert len(replaced) == 1
    assert "no database has been given" in replaced[0]
    assert by_account["acme_batch_user"].get("warnings", []) == []
    assert "replaced the current" in by_account["acme_web_user"]["actions"][0]["detail"]
    assert "replaced the current" not in by_account["acme_batch_user"]["actions"][0]["detail"]


def test_a_promote_clears_a_pending_that_would_otherwise_win(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """The hazard that makes clearing necessary rather than tidy.

    `creds apply --source` defaults to `pending` where there is one, so a staged
    password left beside a freshly promoted one is a password the next `apply`
    would prefer -- undoing this run without anybody asking it to.
    """
    store.write(PATH, {CONTAINER: {"acme_web_user": "the-live-one"}, PENDING: {}}, cas=0)
    run(runner, write_config(CONFIG))  # stage a pending for both accounts
    assert set(staged(store)) == {"acme_web_user", "acme_batch_user"}

    run(runner, write_config(CONFIG), "--promote", "--overwrite-current")

    found = store.read(PATH)
    assert found is not None
    assert found.data.get(PENDING, {}) == {}
    assert found.data.get(ORIGIN, {}) == {}


def test_a_current_that_appears_after_the_plan_is_not_overwritten(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The re-check under the lock. The plan-time read happens before acquiring,
    so a `current` written in between would otherwise be replaced by a run that
    was told there was none -- which is the one case the flag cannot have
    authorised, because nobody knew to pass it."""
    seed_current(store, acme_web_user="the-live-one")
    monkeypatch.setattr("sopuli.cli._current_holders", lambda writes, stores: {})

    found = document(run(runner, write_config(CONFIG), "--promote", "--output", "json"))

    assert found["exit_code"] == ExitCode.FAILURE
    assert {entry["state"] for entry in found["results"]} == {"ERROR"}
    assert "after the plan" in found["results"][0]["actions"][0]["detail"]
    assert current(store) == {"acme_web_user": "the-live-one"}, "nothing was written"


def test_the_terminal_says_promoted_rather_than_staged(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """Two verbs leaving the document in different states should not report the
    same word, and the advice that follows is the same for both: `apply` is what
    makes a database match either."""
    output = run(runner, write_config(CONFIG), "--promote").output

    assert "2 promoted to current" in output
    assert "staged" not in output
    assert "no database was changed" in output


def test_a_failed_promote_is_not_reported_as_a_pending_write(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The stage travels with the failure, not only with the success.

    Left to default, a refused promote reports `vault_write_pending` and
    `secret.stage: pending` -- a consumer reading it would conclude a `pending`
    is sitting there waiting for `apply`, when nothing was written at all.
    """
    seed_current(store, acme_web_user="the-live-one")
    monkeypatch.setattr("sopuli.cli._current_holders", lambda writes, stores: {})

    found = document(run(runner, write_config(CONFIG), "--promote", "--output", "json"))
    entry = found["results"][0]

    assert entry["state"] == "ERROR"
    assert entry["actions"][0]["kind"] == "vault_promote"
    assert entry["actions"][0]["applied"] is False
    assert entry["secret"]["stage"] == "current"


def test_a_document_shaped_wrongly_fails_that_document_and_not_the_run(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    validator: Draft202012Validator,
) -> None:
    """The config and the vault disagree about where a password lives.

    Reading it raises `SecretShapeError`, and letting that out would abort a run
    over twenty documents for one of them -- while the identical failure from the
    *write* is already a per-document finding. The plan-time read says nothing
    about such a document on purpose; this is where the disagreement is named.
    """
    store.write(PATH, {CONTAINER: {"acme_web_user": {"nested": "wrong"}}}, cas=0)

    found = document(
        run(runner, write_config(CONFIG), "--promote", "--overwrite-current", "--output", "json")
    )
    validator.validate(found)

    assert found["exit_code"] == ExitCode.FAILURE
    assert {entry["state"] for entry in found["results"]} == {"ERROR"}
    assert found["results"][0]["error"]["category"] == "vault"
    assert current(store) == {"acme_web_user": {"nested": "wrong"}}, "nothing was written"

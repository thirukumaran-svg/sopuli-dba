"""``sopuli lock status`` — the answer to exit 7.

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
from sopuli.config.binding_stores import NoStoreError
from sopuli.config.errors import ConfigError
from sopuli.config.model import Vault
from sopuli.diagnostics import UNADDRESSABLE_LOCK_PATH, UNLISTABLE_STORE, WARNINGS
from sopuli.exit_codes import ExitCode
from sopuli.lock.keys import LockKey
from sopuli.lock.manager import lock_path
from sopuli.lock.record import DEFAULT_TTL, Holder, LockRecord
from sopuli.output.document import SCHEMA_VERSION
from sopuli.store import CAS, MemoryStore, SecretStore, StoreError

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

#: The same estate plus an application whose store nothing in the file names.
#: Legal: `_check_has_somewhere_to_resolve_from` leaves it open because a
#: profile's `vault:` or `SOPULI_VAULT` may complete it once a run picks one, and
#: `vaults:` declares somewhere for them to point at.
UNRESOLVED_CONFIG = CONFIG.replace(
    """applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "apps/acme/{target}#password"
""",
    """  - name: appdb-gamma
    type: oracle
    dsn: db-dev.example.com:1521/gamma.pdb.example.com
    environment: dev
    labels: { env: dev }
applications:
  - name: acme
    accounts: [acme_web_user]
    targets: [appdb-alpha, appdb-beta]
    secret_template: "apps/acme/{target}#password"
  - name: beta
    accounts: [acme_beta_user]
    targets: [appdb-gamma]
    secret_template: "apps/beta/{target}#password"
""",
)

DEV = LockKey(store="vault-dev", path="apps/acme/appdb-alpha")
PROD = LockKey(store="vault-prod", path="apps/acme/appdb-beta")

#: A record at a path `CONFIG` does not declare -- the application was renamed,
#: or removed, and nothing points at its lock any more.
LEFTOVER = LockKey(store="vault-dev", path="apps/acme/appdb-retired")


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

        def fake_connect(
            vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
        ) -> SecretStore:
            return stores.setdefault(vault.name, MemoryStore())

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        return stores

    return install


def run(runner: CliRunner, config: Path, *args: str) -> Result:
    return runner.invoke(cli, ["lock", "status", "--config", str(config), *args])


def section(result: Result) -> dict[str, Any]:
    return dict(json.loads(result.output)["lock"])


# ---------------------------------------------------- a store nothing named ---


def test_a_selector_survives_a_binding_whose_store_is_unknown(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """`--select` does not fail over a binding it has already excluded.

    The command builds two estates, and the unfiltered one decides only what
    counts as *declared*. If it refused when any binding named no store, an
    estate where one application resolves its store from a profile could not run
    `lock status --app acme` at all: it would fail naming an account in a
    different application, which this run was never going to survey, and the
    narrowed call on the next line could not rescue it because the unfiltered one
    would already have raised.
    """
    with_locks((DEV, held()))

    result = run(runner, write_config(UNRESOLVED_CONFIG), "--app", "acme")

    assert result.exit_code == ExitCode.SUCCESS
    assert "names no store" not in result.output
    assert "apps/acme/appdb-alpha" in result.output


def test_a_binding_with_no_store_is_left_out_of_the_declared_set(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """Skipping it changes no answer, which is why skipping it is safe.

    The unfiltered estate exists to decide whether a *discovered* record is one
    the configuration declares. A binding whose store is unknown has no
    key to compare against a discovered path, so it can never be the reason a
    record is or is not declared -- and a record that really is undeclared still
    reports as one.

    Selected down to `acme`, because without a selector the *narrowed* estate is
    the whole estate and `beta`'s missing store is then a question this command
    really does need answered -- which is the test below.
    """
    with_locks((DEV, held()), (LEFTOVER, held()))

    result = run(runner, write_config(UNRESOLVED_CONFIG), "--app", "acme", "--output", "json")
    found = section(result)

    declared = {entry["path"]: entry["declared"] for entry in found["found"]}
    assert declared[DEV.path] is True
    assert declared[LEFTOVER.path] is False


def test_a_command_that_acts_on_the_keys_still_refuses(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """The refusal is right where the answer is acted on, and it stays.

    `declared_locks` refuses a binding with no store because a command about to
    take that lock must not survey a store it had to guess (invariant 4). The
    skip above applies to the *membership* pass only, so the narrowed estate --
    the one this command surveys -- must still refuse when the selector keeps
    such a binding.
    """
    result = run(runner, write_config(UNRESOLVED_CONFIG), "--app", "beta")

    # `CliRunner` drives the group rather than `sopuli.cli.main`, so the refusal
    # arrives as the exception and the runner's own code is 1. What the command
    # decided is the code the exception carries -- the same reading
    # `test_cli_lock_break.refused` takes.
    assert isinstance(result.exception, ConfigError), result.exception
    assert result.exception.exit_code == ExitCode.CONFIG_INVALID
    assert "names no store" in str(result.exception)
    assert "SOPULI_VAULT" in str(result.exception.hint)


#: Where `beta`'s lock lives when a run completes its store from the environment
#: or a profile, as `creds rotate` does before it takes the lock.
GAMMA = LockKey(store="vault-dev", path="apps/beta/appdb-gamma")


def test_sopuli_vault_completes_a_binding_with_no_store(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    with_locks: Stores,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rotation under SOPULI_VAULT locks in that store, so a survey looks there."""
    monkeypatch.setenv("SOPULI_VAULT", "vault-dev")
    with_locks((GAMMA, held()))

    result = run(runner, write_config(UNRESOLVED_CONFIG), "--app", "beta", "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS, result.exception
    found = {entry["path"]: entry for entry in section(result)["found"]}
    assert found[GAMMA.path]["declared"] is True


def test_a_profile_vault_completes_a_binding_with_no_store(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """The profile is the other run-time source C15 names."""
    with_locks((GAMMA, held()))
    profiled = UNRESOLVED_CONFIG + "profiles:\n  dev:\n    vault: vault-dev\n"

    result = run(
        runner, write_config(profiled), "--app", "beta", "--profile", "dev", "--output", "json"
    )

    assert result.exit_code == ExitCode.SUCCESS, result.exception
    found = {entry["path"]: entry for entry in section(result)["found"]}
    assert found[GAMMA.path]["declared"] is True


def test_a_completed_binding_counts_as_declared_outside_the_selection(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    with_locks: Stores,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The membership pass completes too, so `beta`'s lock is not a leftover.

    Selected down to `acme`, `beta` is not surveyed. Listing `vault-dev` finds
    its record, and the run's SOPULI_VAULT says that store is where `beta` locks,
    so the record is this configuration's and the selector keeps it out of the
    report. Without the completion it would be reported as `declared: false`.
    """
    monkeypatch.setenv("SOPULI_VAULT", "vault-dev")
    with_locks((DEV, held()), (GAMMA, held()))

    result = run(runner, write_config(UNRESOLVED_CONFIG), "--app", "acme", "--output", "json")

    paths = {entry["path"] for entry in section(result)["found"]}
    assert DEV.path in paths
    assert GAMMA.path not in paths


def test_an_undeclared_sopuli_vault_refuses_only_where_it_is_used(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    with_locks: Stores,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A SOPULI_VAULT naming no declared store is wrong only for a binding this run surveys.

    `--app acme` surveys nothing that needs it, so the run goes ahead, as the
    promotion gate does over a binding its selector left out (UC-1 §5). `--app beta`
    needs it, and refuses naming the variable.
    """
    monkeypatch.setenv("SOPULI_VAULT", "vault-nowhere")
    with_locks((DEV, held()))
    path = write_config(UNRESOLVED_CONFIG)

    unaffected = run(runner, path, "--app", "acme")
    refused = run(runner, path, "--app", "beta")

    assert unaffected.exit_code == ExitCode.SUCCESS, unaffected.exception
    assert isinstance(refused.exception, NoStoreError), refused.exception
    assert refused.exception.exit_code == ExitCode.CONFIG_INVALID
    assert "SOPULI_VAULT" in str(refused.exception.hint)


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


def test_the_token_file_flag_reaches_the_store(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The flag's wiring, end to end: it is a *location* all the way down.

    `lock status` opens a socket to the store, so the command line can supply a
    token here at all. What is asserted is what arrives at the backend -- a path,
    never a `Secret` -- because that is the property invariant 1 rests on: no
    signature between the parser and §3a's chain has a slot a credential could sit
    in.
    """
    seen: list[Path | None] = []

    def fake_connect(
        vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
    ) -> SecretStore:
        seen.append(token_file)
        return MemoryStore()

    monkeypatch.setattr("sopuli.cli.connect", fake_connect)
    path = tmp_path / "token"

    result = run(runner, write_config(CONFIG), "--vault-token-file", str(path))

    assert result.exit_code == ExitCode.SUCCESS
    assert seen == [path, path]  # one per declared store


# --------------------------------------- records this config does not declare ---


def test_a_leftover_record_is_reported_and_marked(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """The case that listing the store exists for. A record nothing points at
    any more is invisible to a survey of the declared set, and a lock nobody can
    see is a lock nobody can clear."""
    with_locks((LEFTOVER, held()))
    result = run(runner, write_config(CONFIG), "--output", "json")

    entries = {entry["path"]: entry for entry in section(result)["found"]}
    assert entries[LEFTOVER.path]["declared"] is False


def test_a_declared_record_is_marked_as_one(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """`declared` is on every entry, not only the leftovers: a consumer keeping
    its own locks filters on a field that is always there rather than on an
    absence, which is also what a producer that forgot the field emits."""
    with_locks((DEV, held()))
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert [entry["declared"] for entry in section(result)["found"]] == [True]


def test_the_text_view_puts_leftovers_under_a_heading_of_their_own(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """A seventh column would cost width on every row to answer a question that
    is usually "yes", and a marker on the LOCK cell would corrupt the one string
    the operator is about to paste into `lock break`. The heading carries it, and
    carries it without colour -- NO_COLOR is honoured."""
    with_locks((DEV, held()), (LEFTOVER, held()))
    result = run(runner, write_config(CONFIG))

    assert "not declared by this config" in result.output
    body = result.output.split("not declared by this config")[1]
    assert str(LEFTOVER) in body
    assert str(DEV) not in body


def test_a_clean_estate_shows_no_heading_at_all(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """The common case, and it must stay quiet: a heading that appeared on every
    run with nothing under it would train people not to read it."""
    with_locks((DEV, held()))
    result = run(runner, write_config(CONFIG))

    assert "not declared" not in result.output


def test_the_summary_counts_leftovers_apart_from_the_declared_proportion(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """A leftover was never in the denominator -- it is not a path this config
    would lock -- so folding it in would make "1 of 2" move when somebody else's
    estate changed."""
    with_locks((DEV, held()), (LEFTOVER, held()))
    result = run(runner, write_config(CONFIG))

    assert "1 of 2 declared lock paths held" in result.output
    assert "1 record at paths this config does not declare (1 held)" in result.output


def test_a_leftover_is_examined_and_counted_in_the_summary_total(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """`summary.total` is what was examined, and a discovered path was examined.
    Two declared paths plus one leftover is three."""
    with_locks((LEFTOVER, held()))
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert json.loads(result.output)["summary"] == {
        "total": 3,
        "ok": 3,
        "changed": 0,
        "failed": 0,
    }


def test_a_document_with_a_leftover_still_validates(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    with_locks: Stores,
    validator: Draft202012Validator,
) -> None:
    """Invariant 12: `declared` is a new required field, so the schema moved to
    1.9 and the samples have to prove it."""
    with_locks((DEV, held()), (LEFTOVER, held()))
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert not list(validator.iter_errors(json.loads(result.output)))


def test_selecting_does_not_turn_a_filtered_path_into_a_leftover(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """`declared` is judged against the **unfiltered** estate.

    `--select env=dev` narrows what is surveyed and which stores are opened; it
    does not un-declare the prod path. Reporting somebody's own lock as a
    leftover because this run was not looking at it would be alarming and wrong
    -- and the prod store is not contacted at all, so its record does not appear.
    """
    with_locks((DEV, held()), (PROD, held()))
    result = run(runner, write_config(CONFIG), "--select", "env=dev", "--output", "json")

    entries = section(result)["found"]
    assert [entry["path"] for entry in entries] == [DEV.path]
    assert entries[0]["declared"] is True


def test_a_leftover_is_still_found_under_a_selector(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """The filter decides which vaults are contacted; inside one that is, the
    whole lock prefix is still listed. Otherwise a narrowed survey would hide the
    leftovers in exactly the store the operator was looking at."""
    with_locks((DEV, held()), (LEFTOVER, held()))
    result = run(runner, write_config(CONFIG), "--select", "env=dev", "--output", "json")

    assert {entry["path"] for entry in section(result)["found"]} == {DEV.path, LEFTOVER.path}


# ------------------------------------------- a store that cannot be listed ---


@pytest.fixture
def unlistable(monkeypatch: pytest.MonkeyPatch) -> Callable[..., Mapping[str, SecretStore]]:
    """Stores with no `list` capability, holding whatever records a test names."""

    def install(*records: tuple[LockKey, dict[str, Any]]) -> Mapping[str, SecretStore]:
        stores: dict[str, SecretStore] = {}
        for key, data in records:
            store = stores.setdefault(key.store, MemoryStore(capabilities=frozenset({CAS})))
            store.write(lock_path(key), data, cas=0)

        def fake_connect(
            vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
        ) -> SecretStore:
            return stores.setdefault(vault.name, MemoryStore(capabilities=frozenset({CAS})))

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        return stores

    return install


def test_a_store_that_cannot_be_listed_warns_rather_than_failing(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    unlistable: Callable[..., Mapping[str, SecretStore]],
) -> None:
    """P2's third answer to a missing capability. Refusing would make `lock
    status` work on some backends and not others, and would cost the operator
    the report for every other store too."""
    unlistable((DEV, held()))
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS
    document = json.loads(result.output)
    codes = [diagnostic["code"] for diagnostic in document["diagnostics"]]
    assert UNLISTABLE_STORE in codes
    assert [entry["path"] for entry in document["lock"]["found"]] == [DEV.path]


def test_the_unlistable_warning_says_how_much_of_the_estate_was_seen(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    unlistable: Callable[..., Mapping[str, SecretStore]],
) -> None:
    """An empty `found[]` is something a consumer acts on -- it concludes there
    are no leftovers -- so a survey that could not look has to say so, or it
    hands back the same document as a clean estate."""
    unlistable()
    result = run(runner, write_config(CONFIG), "--output", "json")

    messages = [d["message"] for d in json.loads(result.output)["diagnostics"]]
    assert any("could not list" in message for message in messages)
    assert any("vault-dev" in message and "vault-prod" in message for message in messages)


def test_the_unlistable_warning_is_described_in_the_registry() -> None:
    """A code, once emitted, is part of the contract in the same way an enum
    value is (03-json-output.md §8)."""
    assert UNLISTABLE_STORE in WARNINGS
    assert "list" in WARNINGS[UNLISTABLE_STORE]


def test_a_lock_path_the_tool_cannot_address_is_reported_as_a_warning(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    with_locks: Stores,
    validator: Draft202012Validator,
) -> None:
    """A record written by hand at a path the tool refuses is not shown, but an
    operator looking for a stuck lock has to learn that it is there (#886)."""
    stores = with_locks((DEV, held()))
    stores["vault-dev"].write("locks/bad%3Fkey", held(), cas=0)

    result = run(runner, write_config(CONFIG), "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS
    document = json.loads(result.output)
    validator.validate(document)
    [warning] = [d for d in document["diagnostics"] if d["code"] == UNADDRESSABLE_LOCK_PATH]
    assert "'locks/bad%3Fkey'" in warning["message"]
    assert "'vault-dev'" in warning["message"]
    assert "own tools" in warning["message"], "it says what to do"
    assert [entry["path"] for entry in document["lock"]["found"]] == [DEV.path]


def test_the_unaddressable_path_warning_reaches_the_text_output(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    stores = with_locks((DEV, held()))
    stores["vault-dev"].write("locks/bad%3Fkey", held(), cas=0)

    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert "1 warning:" in result.output
    assert "skipped the lock record at 'locks/bad%3Fkey'" in result.output


def test_a_listable_store_produces_no_such_warning(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    with_locks((DEV, held()))
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert "diagnostics" not in json.loads(result.output)


def test_it_takes_no_lock_of_its_own(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """UC-1 §8 has `check`, `status` and every `--dry-run` take no lock, and the
    reason is not politeness: an hourly survey that locked would block the
    rotations it exists to report on. Asserted against the store rather than the
    output -- a write is what a lock is."""
    stores = with_locks()
    run(runner, write_config(CONFIG), "--output", "json")

    for store in stores.values():
        assert store.read(lock_path(DEV)) is None
        assert store.read(lock_path(PROD)) is None


# -------------------------------------------------------- UC-2's reset locks ---

#: A configuration with no `applications:` and no `accounts:` at all -- the
#: shape UC-2 alone produces, for which `lock status` must not report an empty
#: estate while a reset holds a lock. `personal_accounts:` declares one name and one predicate,
#: because the predicate is the reason the keys cannot be enumerated offline.
RESET_CONFIG = """\
version: 1
vaults:
  vault-dev:
    type: hashicorp
    addr: https://vault-dev.example.com:8200
targets:
  - name: appdb-alpha
    type: oracle
    dsn: db-dev.example.com:1521/alpha.pdb.example.com
    environment: dev
    labels: { env: dev }
    vault: vault-dev
personal_accounts:
  - accounts: [acme_dev_alice]
    policy: personal-standard
  - profile: ACME_DEV_PROF
    policy: personal-standard
reset_records:
  vault: vault-dev
  prefix: sopuli/personal-resets
delivery:
  method: manual
  manual:
    force_expire: true
policies:
  personal-standard:
    password: { length: 20, charset: alnum_safe, first_char: alpha }
"""

#: Where a reset of `acme_dev_alice` on `appdb-alpha` takes its lock: the
#: record's own path (UC-2 3.3), which no binding produces.
RESET_LOCK = LockKey(store="vault-dev", path="sopuli/personal-resets/appdb-alpha/acme_dev_alice")

#: The same, for somebody the file names nowhere -- admitted by the profile
#: predicate, or not admitted at all. Offline there is no way to tell, which is
#: why the region is reported by prefix rather than by key.
PREDICATE_LOCK = LockKey(store="vault-dev", path="sopuli/personal-resets/appdb-alpha/acme_dev_zoe")


#: `RESET_CONFIG` with an application beside the personal accounts, so one
#: survey holds both kinds of record and the summary has to count them apart.
BOUND_CONFIG = RESET_CONFIG.replace(
    "personal_accounts:",
    """applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "apps/acme/{target}#password"
personal_accounts:""",
    1,
)

#: `RESET_CONFIG` with the journal taken away -- a `manual` estate that keeps no
#: record, which UC-2 3.4 calls a documented mode. Nothing declares a lock path
#: here and nothing was listed, and that is the sentence this config exists to
#: keep distinct from the one above it.
NO_JOURNAL_CONFIG = RESET_CONFIG.replace(
    """reset_records:
  vault: vault-dev
  prefix: sopuli/personal-resets
""",
    "",
    1,
)

#: The same, with the application bound *under* the reset prefix. Nothing
#: forbids it, and it is where the two membership rules meet.
UNDER_PREFIX_CONFIG = RESET_CONFIG.replace(
    "personal_accounts:",
    """applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "sopuli/personal-resets/{target}#password"
personal_accounts:""",
    1,
)


def reset_held(**kwargs: Any) -> dict[str, Any]:
    return held(command="account reset-password", **kwargs)


def test_a_held_reset_lock_is_surveyed_although_no_binding_declares_it(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """A held reset lock appears in the survey.

    With the reset lock held, a UC-2-only configuration must not print
    `no lock paths are declared` while the vault holds a `held` record this tool
    wrote. A listing verb answering "nothing" while something is held is the one
    wrong answer it must not give.
    """
    with_locks((RESET_LOCK, reset_held()))

    result = run(runner, write_config(RESET_CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert "no lock paths are declared" not in result.output
    assert RESET_LOCK.path in result.output


def test_a_reset_lock_belongs_to_this_estate_rather_than_to_nobody(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """The third answer. `declared: false` would tell an operator a colleague's
    reset belongs to another configuration, and `declared_by: binding` would
    claim the file enumerates a path it can only describe by prefix."""
    with_locks((RESET_LOCK, reset_held()))

    result = run(runner, write_config(RESET_CONFIG), "--output", "json")

    entry = section(result)["found"][0]
    assert entry["declared"] is True
    assert entry["declared_by"] == "reset_records"


def test_a_predicate_declared_account_is_reported_like_any_other(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """The reason the region is listed rather than expanded.

    `acme_dev_zoe` is in no `accounts:` list; whether the profile admits her is a
    question only a database can answer, and this verb asks none. Listing the
    prefix reports her lock without needing to know -- which an enumeration of
    the name-declared accounts would not have done.
    """
    with_locks((RESET_LOCK, reset_held()), (PREDICATE_LOCK, reset_held()))

    result = run(runner, write_config(RESET_CONFIG), "--output", "json")

    entries = {entry["path"]: entry["declared_by"] for entry in section(result)["found"]}
    assert entries == {
        RESET_LOCK.path: "reset_records",
        PREDICATE_LOCK.path: "reset_records",
    }


def test_a_record_outside_the_declared_prefix_is_still_a_leftover(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """The region is a prefix, not the store. A record elsewhere in the same
    mount belongs to whoever put it there, and claiming it because the store is
    shared would stop leftovers being reported as leftovers."""
    with_locks((RESET_LOCK, reset_held()), (LEFTOVER, held()))

    result = run(runner, write_config(RESET_CONFIG), "--output", "json")

    entries = {entry["path"]: entry["declared_by"] for entry in section(result)["found"]}
    assert entries[LEFTOVER.path] is None
    assert entries[RESET_LOCK.path] == "reset_records"


def test_a_record_at_the_prefix_itself_is_not_claimed(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """`record_path` always appends a target and an account, so nothing this tool
    writes sits at the bare prefix. Claiming one would take an estate's own
    leftover on the strength of a shared spelling."""
    at_prefix = LockKey(store="vault-dev", path="sopuli/personal-resets")
    with_locks((at_prefix, held()))

    result = run(runner, write_config(RESET_CONFIG), "--output", "json")

    assert section(result)["found"][0]["declared_by"] is None


def test_the_reset_store_is_opened_although_no_binding_names_it(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """Membership is not the only step: with no bindings there would be no store
    in the set to open, so `discover()` would never contact the journal's vault
    and there would be nothing to classify."""
    stores = with_locks()

    result = run(runner, write_config(RESET_CONFIG), "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS
    assert "vault-dev" in stores


def test_an_empty_prefix_says_it_was_surveyed(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """*Nothing is held* and *nothing was surveyed* must not be the same
    sentence. A configuration that declares no journal keeps the shorter line."""
    with_locks()

    surveyed = run(runner, write_config(RESET_CONFIG))
    unsurveyed = run(runner, write_config(NO_JOURNAL_CONFIG))

    assert "nothing is held under the reset-record prefix" in surveyed.output
    assert unsurveyed.output.rstrip().endswith("no lock paths are declared")


def test_a_reset_lock_is_counted_beside_the_declared_paths_not_among_them(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """A leftover is out of the denominator because it is not this estate's; a
    reset lock is out of it although it is, because there is no denominator to
    put it in. Counting the records that happen to exist would print a proportion
    whose bottom number is its top one."""
    with_locks((DEV, held()), (RESET_LOCK, reset_held()))

    result = run(runner, write_config(BOUND_CONFIG))

    assert "1 of 1 declared lock paths held" in result.output
    assert "1 reset lock under the declared prefix (1 held)" in result.output


def test_a_reset_lock_gets_a_table_of_its_own(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """The heading carries the distinction, as the leftover table's does: a table
    read by eye answers "whose is this" once, above the rows, rather than in a
    seventh column that is the same word on almost every line."""
    with_locks((RESET_LOCK, reset_held()))

    result = run(runner, write_config(RESET_CONFIG))

    assert "personal-account resets, under the prefix this config declares:" in result.output
    assert "not declared by this config" not in result.output


def test_a_binding_under_the_reset_prefix_is_reported_as_the_binding_it_is(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """Specificity order. Nothing stops an operator pointing `reset_records:` at
    a prefix an application also binds under, and there the enumerated
    declaration is the one they can act on by name."""
    binding = LockKey(store="vault-dev", path="sopuli/personal-resets/appdb-alpha")
    with_locks((binding, held()))

    result = run(runner, write_config(UNDER_PREFIX_CONFIG), "--output", "json")

    assert section(result)["found"][0]["declared_by"] == "binding"


def test_the_document_with_a_reset_lock_validates(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    with_locks: Stores,
    validator: Draft202012Validator,
) -> None:
    """Invariant 12: `declared_by` is a required field of the lock entry, and a
    sample has to prove it -- including the `null` an entry nothing declares
    carries."""
    with_locks((RESET_LOCK, reset_held()), (LEFTOVER, held()))

    result = run(runner, write_config(RESET_CONFIG), "--output", "json")

    assert not list(validator.iter_errors(json.loads(result.output)))


def test_an_unreachable_reset_store_fails_the_survey(
    runner: CliRunner, write_config: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Opening the journal store is what makes the survey honest, so a build that
    does not open it must not pass.

    Asserted from the store's side rather than on the message: a build that left
    `reset_records.vault` out of the set it opens would never reach this `connect`
    at all, and the run would succeed with an empty estate.

    Exit 1, not a warning, and the same answer a binding's store gets.
    Answering "what is held" without contacting the store the locks live in is
    a false negative -- which is the difference from `SOPULI-W005`, where a store
    that cannot *list* is named and the rest of the estate is still reported.
    """
    asked: list[str] = []

    def refuse(vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None) -> Any:
        asked.append(vault.name)
        raise StoreError("could not reach the store: refused by the test")

    monkeypatch.setattr("sopuli.cli.connect", refuse)

    result = run(runner, write_config(RESET_CONFIG))

    assert asked == ["vault-dev"], "the journal's store was never opened"
    assert result.exit_code != ExitCode.SUCCESS

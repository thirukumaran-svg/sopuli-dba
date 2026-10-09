"""``sopuli lock break`` — the mutating half of the ``lock`` noun.

Tier 0 in everything but posture, like ``tests/test_cli_lock_status.py``: in
process through ``CliRunner``, with the store handed in rather than dialled.
``tests/store/test_lock_break_vault.py`` is where the socket and the fence are
exercised against a real Vault, and it is the only thing there a fake could not
tell us.

What this file is for is everything above the store: which refusals happen and in
which order, what the document says, what ``--dry-run`` and ``--confirm`` change,
and the two safety gates that arrive with this verb — ``safety.readonly``, which
no command consumed before it, and a confirmation nobody is there to give.
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
from sopuli.config.errors import ConfigError
from sopuli.config.model import Vault
from sopuli.diagnostics import LOCK_TAKEN_OVER, WARNINGS
from sopuli.exit_codes import ExitCode
from sopuli.lock.keys import LockKey
from sopuli.lock.manager import lock_path
from sopuli.lock.record import DEFAULT_TTL, HELD, RELEASED, Holder, LockRecord
from sopuli.output.document import SCHEMA_VERSION
from sopuli.store import MemoryStore, SecretStore

RUN_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

HOLDER = Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli")

CONFIG = """\
version: 1
vaults:
  vault-prod:
    type: hashicorp
    addr: https://vault-prod.example.com:8200
targets:
  - name: appdb-beta
    type: oracle
    dsn: db-prod.example.com:1521/beta.pdb.example.com
    environment: prod
    vault: vault-prod
applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "apps/acme/{target}#password"
"""

#: The one lock this configuration declares.
PROD = LockKey(store="vault-prod", path="apps/acme/appdb-beta")

#: A record at a path the configuration does not declare -- the application was
#: renamed, or removed. `lock status` reports it; this is the verb that has to
#: be able to clear it, or the survey would show something with no remedy.
LEFTOVER = LockKey(store="vault-prod", path="apps/acme/appdb-retired")

Stores = Callable[..., MemoryStore]


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8")))


def held(*, ago: timedelta = timedelta(minutes=1), state: str = HELD) -> dict[str, Any]:
    """A record as another run would have left it, taken ``ago`` ago."""
    record = LockRecord.acquired(
        correlation_id="01JTHEIRS",
        command="creds rotate",
        holder=HOLDER,
        now=datetime.now(UTC) - ago,
    )
    return (record if state == HELD else record.released()).to_dict()


#: Long enough ago that the claim has lapsed past the clock-skew margin.
LAPSED = DEFAULT_TTL + timedelta(hours=1)


@pytest.fixture
def with_locks(monkeypatch: pytest.MonkeyPatch) -> Stores:
    """Patch the store the command opens, and hand back what it will read.

    Patched on ``sopuli.cli`` rather than on the registry, because that is the
    name the command actually calls -- patching the definition would leave the
    already-imported reference in place and quietly test nothing.
    """

    def install(*records: tuple[LockKey, dict[str, Any]]) -> MemoryStore:
        store = MemoryStore()
        for key, data in records:
            store.write(lock_path(key), data, cas=0)

        def fake_connect(
            vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
        ) -> SecretStore:
            return store

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        return store

    return install


def run(runner: CliRunner, config: Path, *args: str, **kwargs: Any) -> Result:
    return runner.invoke(cli, ["lock", "break", "--config", str(config), *args], **kwargs)


def section(result: Result) -> dict[str, Any]:
    return dict(json.loads(result.output)["lock"])


def refused(result: Result) -> int:
    """The exit code a refusal *would* carry at the boundary.

    ``CliRunner`` drives the group rather than :func:`sopuli.cli.main`, so an
    exception that escapes a verb arrives here as the exception itself and the
    runner's own exit code is 1. The half worth asserting is what the command
    decided, which is the code the exception carries -- the same arrangement
    ``tests/store/test_lock_status_vault.py`` uses, and the reason both halves of
    the boundary read ``exc.exit_code`` rather than inferring one from a type.
    """
    assert isinstance(result.exception, ConfigError), result.exception
    return int(result.exception.exit_code)


# ------------------------------------------------------------- what it takes ---


def test_an_expired_lock_is_taken_and_the_holder_is_named(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """The case the verb exists for. The holder is reported because the write
    replaces their record -- if this run does not say who it was, nothing does."""
    with_locks((PROD, held(ago=LAPSED)))

    result = run(runner, write_config(CONFIG), str(PROD), "--confirm")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "svc_sopuli@ci-runner-3" in result.output
    assert "is fenced at version 2" in result.output


def test_the_write_is_a_released_record_and_never_a_delete(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """A KV v2 delete leaves the metadata, after which a first acquisition can
    never compare-and-set against version 0 again -- and that monotonic version
    *is* the fence, so a delete would break every future lock to clear one."""
    store = with_locks((PROD, held(ago=LAPSED)))

    run(runner, write_config(CONFIG), str(PROD), "--confirm")

    stored = store.read(lock_path(PROD))
    assert stored is not None
    assert stored.data["state"] == RELEASED
    assert stored.version == 2


def test_the_argument_is_the_string_lock_status_printed(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """UC-1 §8: the invocation in an exit-7 message is a paste rather than a
    translation. The two commands are driven here from one string for exactly
    that reason."""
    with_locks((PROD, held(ago=LAPSED)))
    config = write_config(CONFIG)

    survey = runner.invoke(cli, ["lock", "status", "--config", str(config)])
    printed = next(
        line.split()[0] for line in survey.output.splitlines() if line.startswith("vault-prod:")
    )

    assert run(runner, config, printed, "--confirm").exit_code == ExitCode.SUCCESS


def test_a_leftover_at_an_undeclared_path_can_be_cleared(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """`lock status` shows such a record on the argument that a lock nobody can
    see is a lock nobody can clear. This is the remedy, and without it the survey
    would surface something with nothing to do about it.

    Invariant 5 is untouched: the write lands under the store's lock prefix, in a
    store `vaults:` declares, and never touches the secret the lock guards."""
    store = with_locks((LEFTOVER, held(ago=LAPSED)))

    result = run(runner, write_config(CONFIG), str(LEFTOVER), "--confirm")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    stored = store.read(lock_path(LEFTOVER))
    assert stored is not None
    assert stored.data["state"] == RELEASED


# ------------------------------------------------------------ what it refuses ---


def test_a_live_lock_is_refused_with_exit_seven_naming_its_holder(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores, validator: Any
) -> None:
    """Somebody is working. The refusal is the same event a rotation losing the
    same lock reports, so it carries the same `denied` object -- the question at
    exit 7 must not depend on which command was asking."""
    with_locks((PROD, held()))

    result = run(runner, write_config(CONFIG), str(PROD), "--confirm", "--output", "json")
    document = json.loads(result.output)

    assert list(validator.iter_errors(document)) == []
    assert document["exit_code"] == ExitCode.LOCK_HELD
    assert document["error"]["category"] == "lock"
    assert document["lock"]["denied"]["reason"] == "held"
    assert document["lock"]["denied"]["expired"] is False
    assert document["lock"]["denied"]["holder"]["os_user"] == "svc_sopuli"
    assert "--force" in document["error"]["hint"]


def test_a_live_lock_is_left_untouched_when_it_is_refused(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """Exit 7 asserts that nothing happened, so nothing may have happened."""
    store = with_locks((PROD, held()))

    run(runner, write_config(CONFIG), str(PROD), "--confirm")

    stored = store.read(lock_path(PROD))
    assert stored is not None
    assert stored.data["state"] == HELD
    assert stored.version == 1


def test_force_takes_a_live_lock_and_says_so(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """`--force` is an audited override of a guardrail that is not a safety
    setting (decision P3), and on `lock break` it takes a lock that has not
    expired (UC-1 §8). `expired: false` in the entry is the audit: it is
    the case somebody reading the trail afterwards most needs to see named."""
    with_locks((PROD, held()))

    result = run(
        runner, write_config(CONFIG), str(PROD), "--confirm", "--force", "--output", "json"
    )

    assert result.exit_code == ExitCode.SUCCESS, result.output
    entry = section(result)["broken"][0]
    assert entry["applied"] is True
    assert entry["expired"] is False


def test_force_cannot_relax_readonly(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """Invariant 10: `--force` overrides guardrails asked of one lock at one
    moment (UC-1 §8), and never a safety setting. It is not a registered
    setting, so there is no layer for it to arrive on."""
    with_locks((PROD, held(ago=LAPSED)))
    config = write_config(CONFIG + "defaults:\n  safety:\n    readonly: true\n")

    assert refused(run(runner, config, str(PROD), "--confirm", "--force")) == ExitCode.ABORTED


def test_readonly_refuses_the_verb_and_names_where_it_was_set(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores, validator: Any
) -> None:
    """The first command to consume `safety.readonly`. Exit 8 rather than 9: the
    file is not wrong, the operator declined in advance by writing it."""
    store = with_locks((PROD, held(ago=LAPSED)))
    config = write_config(CONFIG + "defaults:\n  safety:\n    readonly: true\n")

    result = run(runner, config, str(PROD), "--confirm", "--output", "json")
    document = json.loads(result.output)

    assert list(validator.iter_errors(document)) == []
    assert document["exit_code"] == ExitCode.ABORTED
    assert document["error"]["category"] == "policy"
    assert "safety.readonly" in document["error"]["message"]
    assert "lock status" in document["error"]["hint"]
    # And nothing was touched on the way to refusing.
    stored = store.read(lock_path(PROD))
    assert stored is not None
    assert stored.version == 1


def test_readonly_refuses_a_dry_run_too(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """Not obviously right and deliberate: under `readonly` the mutating verbs
    are unavailable and `lock status` is how you ask. A rule that has to be
    reasoned about per flag is a rule nobody can rely on."""
    with_locks((PROD, held(ago=LAPSED)))
    config = write_config(CONFIG + "defaults:\n  safety:\n    readonly: true\n")

    assert refused(run(runner, config, str(PROD), "--dry-run")) == ExitCode.ABORTED


def test_a_store_that_cannot_fence_is_refused_at_plan_time(
    runner: CliRunner, write_config: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant 4, and the reason it matters here: without a fence, breaking a
    lock is deleting somebody's claim while they carry on rotating."""

    class Unfenced(MemoryStore):
        def supports(self) -> frozenset[str]:
            return frozenset()

    monkeypatch.setattr(
        "sopuli.cli.connect",
        lambda vault, *, env, token_file=None: Unfenced(),
    )

    result = run(runner, write_config(CONFIG), str(PROD), "--confirm", "--output", "json")
    document = json.loads(result.output)

    assert document["exit_code"] == ExitCode.UNSUPPORTED_CAPABILITY
    assert document["error"]["category"] == "capability"
    assert "no compare-and-set" in document["error"]["message"]


def test_an_advisory_only_store_is_refused_whatever_it_supports(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """The declaration decides, not the store: `MemoryStore` has `cas`, and this
    is still refused. Same combination `LockManager.__post_init__` refuses for
    `break_expired`, and refusing it in one place and allowing it in the other
    would be two guards disagreeing about one configuration."""
    with_locks((PROD, held(ago=LAPSED)))
    config = write_config(
        CONFIG.replace(
            "    addr: https://vault-prod.example.com:8200",
            "    addr: https://vault-prod.example.com:8200\n    locking: advisory-only",
        )
    )

    result = run(runner, config, str(PROD), "--confirm", "--force", "--output", "json")
    document = json.loads(result.output)

    assert document["exit_code"] == ExitCode.UNSUPPORTED_CAPABILITY
    assert "advisory-only" in document["error"]["message"]


def test_an_undeclared_vault_is_refused_the_way_every_other_name_is(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """Exit 9, like `policy sample nosuch`: argv resolved to a valid command, and
    the configuration turned out not to declare what it named."""
    with_locks()

    result = run(runner, write_config(CONFIG), "nosuch:apps/acme/db", "--confirm")

    assert refused(result) == ExitCode.CONFIG_INVALID
    assert "no vault named 'nosuch'" in str(result.exception)


def test_an_argument_that_is_not_a_lock_is_a_usage_error(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """Exit 2 and no run document (J7): argv did not resolve to a valid request,
    and nothing about any file is wrong."""
    result = run(runner, write_config(CONFIG), "nocolon", "--confirm")

    assert result.exit_code == ExitCode.USAGE
    assert "is not a lock" in result.output


# ------------------------------------------------------ nothing to break ---


def test_a_free_path_is_exit_zero_having_changed_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """A state, not a failure: the operator asked for the path to be clear and it
    is. Reporting this as an error would send somebody looking for a lock that
    does not exist."""
    with_locks()

    result = run(runner, write_config(CONFIG), str(PROD), "--confirm", "--output", "json")
    document = json.loads(result.output)

    assert document["exit_code"] == ExitCode.SUCCESS
    assert document["summary"]["changed"] == 0
    assert document["lock"] == {"mode": "cas", "broken": []}


def test_breaking_twice_reports_the_second_run_as_unchanged(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """Invariant 9, and it falls out rather than being arranged: the second run
    finds the released record the first one wrote, which is not a claim."""
    store = with_locks((PROD, held(ago=LAPSED)))
    config = write_config(CONFIG)

    first = run(runner, config, str(PROD), "--confirm", "--output", "json")
    second = run(runner, config, str(PROD), "--confirm", "--output", "json")

    assert json.loads(first.output)["summary"]["changed"] == 1
    assert json.loads(second.output)["summary"]["changed"] == 0
    assert json.loads(second.output)["exit_code"] == ExitCode.SUCCESS
    # And the second run wrote nothing: the version is where the first left it.
    stored = store.read(lock_path(PROD))
    assert stored is not None
    assert stored.version == 2


def test_nothing_to_break_says_so_in_the_document_as_well(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """An empty `broken` is the finding, and a consumer should not have to infer
    why it is empty."""
    with_locks()

    result = run(runner, write_config(CONFIG), str(PROD), "--confirm", "--output", "json")

    messages = [one["message"] for one in json.loads(result.output).get("diagnostics", [])]
    assert any("nothing to break" in message for message in messages)


# -------------------------------------------------------------- the dry run ---


def test_a_dry_run_prints_the_plan_and_writes_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """Invariant 8. The plan names the version it would compare against, because
    that number is what makes the takeover safe."""
    store = with_locks((PROD, held(ago=LAPSED)))

    result = run(runner, write_config(CONFIG), str(PROD), "--dry-run")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "nothing was written (--dry-run)" in result.output
    stored = store.read(lock_path(PROD))
    assert stored is not None
    assert stored.version == 1


def test_the_dry_run_and_the_run_that_follows_are_one_shape(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """What `applied` is for: a consumer diffing a plan against its outcome
    compares like with like rather than two different documents."""
    with_locks((PROD, held(ago=LAPSED)))
    config = write_config(CONFIG)

    planned = section(run(runner, config, str(PROD), "--dry-run", "--output", "json"))
    done = section(run(runner, config, str(PROD), "--confirm", "--output", "json"))

    assert planned["broken"][0].keys() == done["broken"][0].keys()
    assert planned["broken"][0]["applied"] is False
    assert planned["broken"][0]["new_version"] is None
    assert done["broken"][0]["applied"] is True
    assert done["broken"][0]["new_version"] == 2


def test_a_dry_run_needs_no_confirmation(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """Nothing is written, so there is nothing to agree to -- and a dry run that
    demanded `--confirm` would be one nobody uses to decide."""
    with_locks((PROD, held(ago=LAPSED)))

    assert run(runner, write_config(CONFIG), str(PROD), "--dry-run").exit_code == 0


# ----------------------------------------------------------- confirmation ---


def test_without_confirm_and_with_nobody_to_ask_it_refuses(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """The ratchet reading of P5's `--confirm`: the flag means *I have already
    decided*, and a closed stdin is not somebody deciding. Exit 8 naming the flag
    is more use than a prompt that reads EOF and aborts."""
    store = with_locks((PROD, held(ago=LAPSED)))

    result = run(runner, write_config(CONFIG), str(PROD))

    assert refused(result) == ExitCode.ABORTED
    assert "--confirm" in str(result.exception)
    stored = store.read(lock_path(PROD))
    assert stored is not None
    assert stored.version == 1


def test_a_prompt_declined_writes_nothing_and_exits_eight(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    with_locks: Stores,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P5's exit 8 -- confirmation declined -- and the plan is on stderr before
    the question, which is invariant 8's "prints a plan first"."""
    store = with_locks((PROD, held(ago=LAPSED)))
    monkeypatch.setattr("sopuli.cli._can_prompt", lambda: True)

    result = run(runner, write_config(CONFIG), str(PROD), input="n\n")

    assert result.exit_code == ExitCode.ABORTED
    stored = store.read(lock_path(PROD))
    assert stored is not None
    assert stored.version == 1


def test_a_prompt_accepted_breaks_the_lock(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    with_locks: Stores,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with_locks((PROD, held(ago=LAPSED)))
    monkeypatch.setattr("sopuli.cli._can_prompt", lambda: True)

    result = run(runner, write_config(CONFIG), str(PROD), input="y\n")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "take this lock from" in result.output


# ---------------------------------------------------------------- the document ---


def test_the_document_validates_and_reports_the_break(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores, validator: Any
) -> None:
    """Invariant 12: the schema is the test fixture, not documentation written
    afterwards."""
    with_locks((PROD, held(ago=LAPSED)))

    result = run(runner, write_config(CONFIG), str(PROD), "--confirm", "--output", "json")
    document = json.loads(result.output)

    assert list(validator.iter_errors(document)) == []
    assert document["command"] == "lock.break"
    assert document["summary"] == {"total": 1, "ok": 1, "changed": 1, "failed": 0}
    assert document["lock"]["broken"] == [
        {
            "vault": "vault-prod",
            "path": "apps/acme/appdb-beta",
            "applied": True,
            "state": HELD,
            "expired": True,
            "version": 1,
            "new_version": 2,
            "acquired_at": document["lock"]["broken"][0]["acquired_at"],
            "expires_at": document["lock"]["broken"][0]["expires_at"],
            "holder": {
                "host": "ci-runner-3",
                "pid": 8821,
                "os_user": "svc_sopuli",
                "correlation_id": "01JTHEIRS",
                "command": "creds rotate",
            },
        }
    ]


def test_a_break_warns_with_the_code_that_already_means_this(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """`SOPULI-W002` already means "a lock was taken from its holder". It is the
    same event whether a config key or a person decided it, and a consumer
    alerting on it wants both."""
    with_locks((PROD, held(ago=LAPSED)))

    result = run(runner, write_config(CONFIG), str(PROD), "--confirm", "--output", "json")

    codes = [one.get("code") for one in json.loads(result.output)["diagnostics"]]
    assert LOCK_TAKEN_OVER in codes
    assert LOCK_TAKEN_OVER in WARNINGS


def test_a_dry_run_does_not_claim_a_lock_was_taken(
    runner: CliRunner, write_config: Callable[[str], Path], with_locks: Stores
) -> None:
    """The warning describes something that happened. Emitting it for a plan
    would put a false entry in the audit trail the code exists to feed."""
    with_locks((PROD, held(ago=LAPSED)))

    result = run(runner, write_config(CONFIG), str(PROD), "--dry-run", "--output", "json")

    codes = [one.get("code") for one in json.loads(result.output).get("diagnostics", [])]
    assert LOCK_TAKEN_OVER not in codes


def test_a_profile_that_cannot_answer_refuses_even_at_a_terminal(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    with_locks: Stores,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`confirm: false` refuses before the prompt, and the lock is untouched
    (decision #610)."""
    store = with_locks((PROD, held(ago=LAPSED)))
    monkeypatch.setattr("sopuli.cli._can_prompt", lambda: True)
    config = write_config(CONFIG + "profiles:\n  ci:\n    confirm: false\n")

    result = run(runner, config, str(PROD), "--profile", "ci", input="y\n")

    assert refused(result) == ExitCode.ABORTED
    assert "profiles.ci.confirm" in str(getattr(result.exception, "hint", ""))
    stored = store.read(lock_path(PROD))
    assert stored is not None
    assert stored.version == 1

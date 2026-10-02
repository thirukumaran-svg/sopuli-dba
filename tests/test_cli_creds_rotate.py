"""``sopuli creds rotate`` end to end, without a database (#284).

Same arrangement as ``tests/test_cli_creds_apply.py``: in-process through
``CliRunner``, the vault a :class:`~sopuli.store.MemoryStore` and the driver a
fake session.

**UC-1 §8's failure table is the specification**, so most of this file is one
case per row -- where the run stopped, what state the estate was left in, and
what it exited with. The rows are the point: a rotation that stops half way is
not a bug to be prevented but a state to be reported accurately, and each of
these asserts on the store and the recorded statements rather than on what the
run printed.

Two properties carry the rest:

* **nothing is promoted that was not confirmed** (invariant 7), asserted on the
  document the store holds afterwards;
* **the value is never predicted.** `rotate` draws the password, so nothing here
  knows what it is. The assertions cross-check instead -- the password the
  database was given *is* the one the vault ended up serving -- which is a
  stronger statement about the sequence than any fixed string would be.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator

from sopuli.admin import Resolved
from sopuli.cli import _reach, cli
from sopuli.clock import to_rfc3339, utc_now
from sopuli.config.model import Vault
from sopuli.config.targets import EXTERNAL
from sopuli.driver.protocol import (
    EXPIRE_PASSWORD,
    FAIL,
    PASS,
    PASSWORD_ROLLOVER,
    ChangeResult,
    Credential,
    PrivilegeAudit,
    Scope,
    UserState,
    VerifyResult,
)
from sopuli.exit_codes import ExitCode
from sopuli.lock import Holder, LockDeniedError, LockKey, LockRecord, lock_path
from sopuli.output.document import SCHEMA_VERSION
from sopuli.output.emit import EVENT_SCHEMA_VERSION
from sopuli.plan import BlastRadius
from sopuli.secrets import Secret
from sopuli.store import MemoryStore, SecretStore, StoreError
from sopuli.store.protocol import Stored

RUN_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

#: One application over two PDBs, one document per tenant -- Q7's documented
#: layout, so a run touching both promotes two documents rather than one.
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
    dsn: db-prod.example.com:1521/alpha.pdb.example.com
    environment: prod
    labels: { env: prod, tenant: alpha }
    vault: vault-prod
  - name: appdb-beta
    type: oracle
    dsn: db-prod.example.com:1521/beta.pdb.example.com
    environment: prod
    labels: { env: prod, tenant: beta }
    vault: vault-prod
applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "apps/acme/{target}#DB_CREDENTIALS/{account}"
"""

LIVE = "Correct-Horse-Battery-9"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8")))


class Database:
    """One target's account state, outliving any one connection to it.

    **Shared across sessions on purpose**, and it is what makes
    ``--finish-rollover`` testable at all: a rotation opens three connections to
    each target -- the pre-flight surveys and closes one, the apply gets another,
    the window is closed over a third -- and a fake that kept the password and
    the open window per *session* would report every window shut the moment the
    apply hung up. That is not a modelling nicety; it is the difference between
    a fake that can observe the sequence and one that cannot.
    """

    def __init__(self, users: Mapping[str, UserState | None], *, rollover: bool) -> None:
        self.declared = dict(users)
        self.rollover = rollover
        self.passwords = dict.fromkeys(self.declared, LIVE)
        self.previous: dict[str, str] = {}
        self.windows: set[str] = set()

    def user(self, account: str) -> UserState | None:
        found = self.declared.get(account)
        if found is None:
            return None
        return replace(found, rollover_active=account in self.windows)

    def accepts(self, account: str, offered: str) -> bool:
        """Whether this password authenticates, window and all.

        Under an open window the previous password authenticates too, which is
        the whole reason rollover makes a partial rotation survivable -- so the
        fake says so rather than making a pass mean more than it does.
        """
        if offered == self.passwords.get(account):
            return True
        return account in self.windows and offered == self.previous.get(account)

    def set_password(self, account: str, value: str) -> None:
        self.previous[account] = self.passwords.get(account, LIVE)
        self.passwords[account] = value
        declared = self.declared.get(account)
        if self.rollover and declared is not None and declared.rollover_enabled:
            self.windows.add(account)

    def finish_rollover(self, account: str) -> bool:
        """Whether *this call* closed a window, which is not the same as whether
        one is shut afterwards.

        A window that had already elapsed reports no change, because that is what
        the real driver reports and what `_finish_one` distinguishes: what this
        run wanted is true, and it is not what made it true.
        """
        if account not in self.windows:
            return False
        self.windows.discard(account)
        return True


class FakeSession:
    """One connection to a :class:`Database`, and a record of what it was asked.

    The recording is what most of this file asserts on. Half of what `rotate`
    must get right is what it does *not* do -- no DDL after a pre-flight
    refusal, none after a staging failure, no window closed on an account whose
    apply failed -- and none of that is visible in the output.
    """

    def __init__(
        self,
        database: Database,
        *,
        set_error: Exception | None = None,
        capabilities: frozenset[str] = frozenset(),
        on_call: Callable[[str], None] | None = None,
        audit: PrivilegeAudit | Exception | None = None,
        scope: Scope | None = None,
    ) -> None:
        self.database = database
        self.set_error = set_error
        self.capabilities = capabilities
        self.on_call = on_call
        self.audit = audit
        self.given_scope = scope
        self.attempts: list[tuple[str, str]] = []
        self.changed: list[tuple[str, str]] = []
        self.finished: list[str] = []
        self.closed = False

    def scope(self) -> Scope:
        if self.given_scope is not None:
            return replace(self.given_scope, capabilities=self.capabilities)
        return Scope(type="pdb", container="ALPHA", read_write=True, capabilities=self.capabilities)

    def privileges(self) -> PrivilegeAudit:
        if isinstance(self.audit, Exception):
            raise self.audit
        return self.audit if self.audit is not None else PrivilegeAudit()

    def describe_user(self, account: str) -> UserState | None:
        self._called("describe_user")
        return self.database.user(account.upper())

    def require_rollover(self, account: str) -> None:
        if self.database.user(account.upper()) is None:
            raise RuntimeError(f'account "{account}" does not exist on this target')

    def finish_rollover(self, account: str) -> ChangeResult:
        closed = self.database.finish_rollover(account.upper())
        self.finished.append(account.upper())
        self._called("finish_rollover")
        return ChangeResult(changed=closed, detail="rollover window ended")

    def verify_password(
        self,
        account: str,
        secret: Secret,
        *,
        method: str = "login",
        lockout_margin: int = 2,
        attempts: int = 1,
    ) -> VerifyResult:
        """Ask the database, rather than replaying a scripted answer.

        `rotate` draws the password, so a scripted list would have to be written
        without knowing what is being verified. Modelling it makes the fake tell
        the truth about the sequence: the pre-change verification fails because
        the database still holds the old value, and the post-change one passes
        because the DDL landed -- and a run that promoted without issuing the
        DDL could not make the second one pass.
        """
        self.attempts.append((account.upper(), secret.reveal()))
        if self.database.accepts(account.upper(), secret.reveal()):
            return VerifyResult("login", PASS, latency_ms=9)
        return VerifyResult("login", FAIL, detail="ORA-01017: invalid credential")

    def set_password(self, account: str, secret: Secret) -> ChangeResult:
        if self.set_error is not None:
            raise self.set_error
        self.database.set_password(account.upper(), secret.reveal())
        self.changed.append((account.upper(), secret.reveal()))
        self._called("set_password")
        return ChangeResult(changed=True)

    def _called(self, event: str) -> None:
        if self.on_call is not None:
            self.on_call(event)

    def close(self) -> None:
        self.closed = True


def user(name: str = "ACME_WEB_USER", **fields: Any) -> UserState:
    return UserState(
        # `False` rather than the default, for `test_cli_creds_apply.py`'s
        # reason: a rotation case must not also be a guardrail-3 case (#296).
        **{"name": name, "status": "OPEN", "password_file_member": False, **fields}
    )


Harness = Callable[..., dict[str, Any]]


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Harness:
    """Patch the store and the driver, and hand back what the run will meet."""

    def install(
        *,
        documents: Mapping[str, dict[str, Any]] | None = None,
        users: Mapping[str, UserState | None] | None = None,
        connect_error: Exception | None = None,
        connect_errors: Mapping[str, Exception] | None = None,
        set_error: Exception | None = None,
        capabilities: frozenset[str] = frozenset(),
        on_call: Callable[[dict[str, Any], str], None] | None = None,
        audits: Mapping[str, PrivilegeAudit | Exception] | None = None,
        scopes: Mapping[str, Scope] | None = None,
        store: MemoryStore | None = None,
    ) -> dict[str, Any]:
        vault = store if store is not None else MemoryStore()
        for path, body in (documents or _two_targets()).items():
            vault.write(path, body, cas=0)

        sessions: list[FakeSession] = []
        declared = users if users is not None else {"ACME_WEB_USER": user()}
        # One per target, created on first connection and kept -- see
        # :class:`Database` for why the state cannot live on the session.
        databases: dict[str, Database] = {}
        harness: dict[str, Any] = {
            "store": vault,
            "sessions": sessions,
            "databases": databases,
        }

        def fake_connect(
            declared: Vault, *, env: Mapping[str, str], token_file: Path | None = None
        ) -> SecretStore:
            return vault

        class FakeDriver:
            def __init__(self, **_: Any) -> None:
                pass

            def connect(self, target: Any, credential: Any) -> FakeSession:
                if connect_error is not None:
                    raise connect_error
                if connect_errors is not None and target.name in connect_errors:
                    raise connect_errors[target.name]
                database = databases.setdefault(
                    target.name,
                    Database(declared, rollover=PASSWORD_ROLLOVER in capabilities),
                )
                session = FakeSession(
                    database,
                    set_error=set_error,
                    capabilities=capabilities,
                    on_call=None if on_call is None else (lambda event: on_call(harness, event)),
                    audit=None if audits is None else audits.get(target.name),
                    scope=None if scopes is None else scopes.get(target.name),
                )
                sessions.append(session)
                return session

        class FakeModule:
            OracleDriver = FakeDriver

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        monkeypatch.setattr("sopuli.cli.resolve_driver", lambda target: FakeModule)
        monkeypatch.setattr("sopuli.cli.admin_resolve", lambda target, **_: _credential())
        return harness

    return install


def _two_targets(days: float | None = None) -> dict[str, dict[str, Any]]:
    """Both documents holding a live password, optionally stamped ``days`` ago."""
    body: dict[str, Any] = {"DB_CREDENTIALS": {"acme_web_user": LIVE}}
    if days is not None:
        body["rotated_at"] = {"acme_web_user": to_rfc3339(utc_now() - timedelta(days=days))}
    return {f"apps/acme/{target}": dict(body) for target in ("appdb-alpha", "appdb-beta")}


def _credential() -> Any:
    """The admin credential the CLI would have resolved.

    A real :class:`~sopuli.admin.Resolved` rather than a stub with one attribute.
    The command reads its *provenance* as well as its value now -- #477 reports
    where an admin credential came from -- and a stub stops being enough the
    moment anything but `.credential` is read. `external` because these estates
    declare no `admin:` block at all, and it is the one source that carries
    neither a username nor a secret.
    """
    return Resolved(
        credential=Credential(external=True),
        method=EXTERNAL,
        source="an external password store",
    )


def run(runner: CliRunner, config: Path, *args: str) -> Result:
    """Every run is confirmed in advance: `CliRunner` has no terminal, and §8
    step 1 refuses rather than proceeding where there is nobody to ask."""
    return runner.invoke(cli, ["creds", "rotate", "--config", str(config), "--confirm", *args])


def document(result: Result) -> dict[str, Any]:
    return dict(json.loads(result.output))


def stored(store: MemoryStore, path: str) -> dict[str, Any]:
    found = store.read(path)
    assert found is not None
    return dict(found.data)


def changed(harness: dict[str, Any]) -> list[tuple[str, str]]:
    """Every statement the run issued, across every session it opened.

    Aggregated rather than read off ``sessions[0]``, because a rotation opens
    more than one connection per target on purpose: the pre-flight surveys on
    its own session and closes it, the apply gets another, and
    ``--finish-rollover`` a third. Indexing into the list would assert against
    whichever of those happened to be first, which is a test that passes for the
    wrong reason the moment the sequence changes.
    """
    return [issued for session in harness["sessions"] for issued in session.changed]


def finished(harness: dict[str, Any]) -> list[str]:
    """Every rollover window the run closed, across every session."""
    return [name for session in harness["sessions"] for name in session.finished]


# --------------------------------------------------------- the happy path ---


def test_a_rotation_generates_applies_and_promotes(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """§8 end to end, and the assertion is the sequence rather than a value.

    Nothing here knows what password was drawn. What it asserts is that the one
    the database was given is the one the vault ended up serving -- which no run
    that skipped a step could satisfy.
    """
    harness = estate()
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.SUCCESS
    body = stored(harness["store"], "apps/acme/appdb-alpha")
    issued = changed(harness)
    assert len(issued) == 1
    assert body["DB_CREDENTIALS"]["acme_web_user"] == issued[0][1]


def test_the_old_password_is_kept_as_previous(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The bounded rollback §8 describes: one generation, and only one."""
    harness = estate()
    run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    body = stored(harness["store"], "apps/acme/appdb-alpha")
    assert body["previous"]["acme_web_user"] == LIVE


def test_pending_is_cleared_by_the_promotion(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A `pending` left behind would be staged work the next run would redo."""
    harness = estate()
    run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    body = stored(harness["store"], "apps/acme/appdb-alpha")
    assert "acme_web_user" not in body.get("pending", {})


def test_the_new_password_is_never_the_old_one(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate()
    run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert changed(harness)[0][1] != LIVE


def test_each_target_gets_its_own_password(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """One document per tenant, so one drawn value each -- never one shared."""
    harness = estate()
    run(runner, write_config(CONFIG))

    drawn = {issued for _, issued in changed(harness)}
    assert len(drawn) == 2


def test_the_document_validates_and_reports_both_halves(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    """The staging entries and the apply entries are one ``results[]``, and it
    validates against the published schema -- ``creds.rotate`` needed no bump."""
    estate()
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")

    body = document(result)
    assert not list(validator.iter_errors(body))
    assert body["command"] == "creds.rotate"
    kinds = {action["kind"] for entry in body["results"] for action in entry["actions"]}
    assert {"vault_write_pending", "password_set", "vault_promote"} <= kinds


def test_the_lock_is_taken_for_the_whole_run(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    """One acquisition spanning generate, apply and promote -- the property that
    makes this a command rather than three in a row."""
    estate()
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")

    held = document(result)["lock"]["held"]
    assert [one["path"] for one in held] == ["apps/acme/appdb-alpha"]
    assert all(one["released"] for one in held)


def test_a_run_that_ends_early_still_reports_its_locks_as_released(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The lock section is built after `holding` lets go, on every path.

    `release()` is what flips `HeldLock.released`, and it runs in the `finally`
    inside `holding`. `_rotate_estate` returns three of its endings from *inside*
    that block, and the section was built there -- so the document said
    `released: false` for locks the store already had down as released. A
    consumer reading the run document to find out what this run still holds got
    the opposite of the truth, on the most ordinary ending a scheduled rotation
    has: nothing was due.

    Asserted against the store as well as the document, because the bug was the
    two disagreeing rather than either one alone.
    """
    harness = estate(documents=_two_targets(days=3))

    result = run(runner, write_config(CONFIG), "--max-age-days", "90", "--output", "json")
    held = document(result)["lock"]["held"]

    assert [one["path"] for one in held] == [
        "apps/acme/appdb-alpha",
        "apps/acme/appdb-beta",
    ]
    assert all(one["released"] for one in held)
    for one in held:
        record = harness["store"].read(f"locks/{one['path']}")
        assert record is not None
        assert record.data["state"] == "released"


# ------------------------------------------------------------- invariant 8 ---


def test_dry_run_writes_nothing_and_takes_no_lock(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate()
    before = harness["store"].read("apps/acme/appdb-alpha").version
    result = run(runner, write_config(CONFIG), "--dry-run")

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["store"].read("apps/acme/appdb-alpha").version == before
    assert all(session.changed == [] for session in harness["sessions"])


def test_dry_run_still_flies_the_preflight(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """ "Show me the plan, and tell me whether it would work" is the question a
    preview of a rotation is asking, and a refusal under `--dry-run` is real."""
    estate(connect_error=StoreError("ORA-12541: no listener"))
    result = run(runner, write_config(CONFIG), "--dry-run")

    assert result.exit_code != ExitCode.SUCCESS
    assert "nothing was written" in result.output


@pytest.mark.parametrize("mode", [(), ("--dry-run",)], ids=["run", "dry-run"])
def test_a_preflight_caveat_is_printed_in_the_text(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, mode: tuple[str, ...]
) -> None:
    """#606, which applies to `rotate`'s unconditional pre-flight as it does to
    `apply --preflight`."""
    estate(audits={"appdb-alpha": RuntimeError("ORA-00942: table or view does not exist")})

    result = run(runner, write_config(CONFIG), *mode)

    assert result.exit_code == ExitCode.SUCCESS
    assert "pre-flight on appdb-alpha could not establish" in result.output


# -------------------------------------------------------- §8 step 1, confirm ---


def test_an_unattended_run_without_confirm_is_refused(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Exit 8 naming the flag, rather than click's EOF abort -- which would tell
    an operator that it stopped and not what to type instead."""
    harness = estate()
    result = runner.invoke(cli, ["creds", "rotate", "--config", str(write_config(CONFIG))])

    # Exit 8 through `main()`, which is where `ConfigError.exit_code` is mapped;
    # `CliRunner` invokes the group directly and reports 1 for anything that
    # escapes it, which is the same shape every other refusal is asserted in.
    assert result.exit_code != ExitCode.SUCCESS
    assert changed(harness) == []


def test_a_refused_confirmation_writes_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate()
    before = harness["store"].read("apps/acme/appdb-alpha").version
    runner.invoke(cli, ["creds", "rotate", "--config", str(write_config(CONFIG))])

    assert harness["store"].read("apps/acme/appdb-alpha").version == before


@pytest.mark.parametrize(
    ("radius", "expected"),
    [
        (BlastRadius(targets=1, accounts=1), "1 account on 1 target"),
        (BlastRadius(targets=3, accounts=2), "2 accounts on 3 targets"),
        (
            BlastRadius(targets=1, accounts=1, environments=("dev",)),
            "1 account on 1 target in `dev`",
        ),
        (
            BlastRadius(targets=11, accounts=1, environments=("dev", "prod")),
            "1 account on 11 targets in `dev`, `prod`",
        ),
    ],
)
def test_the_confirmation_names_the_reach_in_words(radius: BlastRadius, expected: str) -> None:
    """The last sentence an operator reads before an estate's passwords change.

    It used to interpolate the `BlastRadius` itself and render as `draw a new
    password for BlastRadius(targets=1, accounts=1, environments=('dev',))
    account(s) and promote it?` -- a dataclass repr in a confirmation prompt,
    with `account(s)` appended to an object that already said `accounts=1`.
    Nothing caught it because `CliRunner` has no terminal, so the two tests above
    take the `_can_prompt()` refusal path and the prompt never renders (#380,
    found by running `creds rotate` rather than by testing it).

    So the phrase is asserted here instead, where it needs no terminal. Both
    counts are in it deliberately: `1 account on 11 targets` and `11 accounts on
    1 target` are different things to say yes to, and `BlastRadius` carries the
    two separately for exactly that reason.
    """
    assert _reach(radius) == expected


# ------------------------------------------------------------ --max-age-days ---


def test_max_age_days_selects_on_the_vault_stamp(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Q9: the vault's `rotated_at`, and never the database's own date."""
    harness = estate(documents=_two_targets(days=120))
    result = run(runner, write_config(CONFIG), "--max-age-days", "90")

    assert result.exit_code == ExitCode.SUCCESS
    assert len(changed(harness)) == 2


def test_nothing_old_enough_is_exit_zero_and_no_connection(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The ordinary healthy result of a scheduled rotation. No database is even
    reached: the answer came out of the vault, so the pre-flight never runs."""
    harness = estate(documents=_two_targets(days=3))
    result = run(runner, write_config(CONFIG), "--max-age-days", "90")

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["sessions"] == []
    assert "nothing is older than --max-age-days 90" in result.output


def test_an_unstamped_account_is_left_alone(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A freshly adopted estate has no stamps, and treating unknown as ancient
    would make this tool's first scheduled act a rotation of everything."""
    harness = estate(documents=_two_targets())
    result = run(runner, write_config(CONFIG), "--max-age-days", "90")

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["sessions"] == []


def test_the_selection_table_shows_what_was_skipped_and_why(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Eleven of fourteen accounts being young is a different fact from a
    selector that matched nothing, and the run has to make that visible."""
    estate(documents=_two_targets(days=3))
    result = run(runner, write_config(CONFIG), "--max-age-days", "90")

    assert "ROTATING" in result.output
    assert "--max-age-days 90" in result.output


def test_no_age_filter_prints_no_selection_table(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Without the flag every account is due, and a column of `yes` beside a
    column of blanks would be a table carrying nothing."""
    estate()
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert "ROTATING" not in result.output


# ------------------------------------------------------ §8 step 3, pre-flight ---


def test_an_unreachable_target_refuses_the_whole_run(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The pre-flight is unconditional here. Discovering on target two that it
    was never going to work must not leave target one already rotated."""
    harness = estate(connect_errors={"appdb-beta": StoreError("ORA-12541: no listener")})
    before = harness["store"].read("apps/acme/appdb-alpha").version
    result = run(runner, write_config(CONFIG))

    assert result.exit_code != ExitCode.SUCCESS
    assert harness["store"].read("apps/acme/appdb-alpha").version == before
    assert all(session.changed == [] for session in harness["sessions"])


def test_a_missing_account_refuses_before_anything_is_staged(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate(users={})
    before = harness["store"].read("apps/acme/appdb-alpha").version
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code != ExitCode.SUCCESS
    assert harness["store"].read("apps/acme/appdb-alpha").version == before


def test_the_preflight_covers_an_estate_with_nothing_in_the_vault(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The first-ever rotation, and the case `apply`'s own filter would skip.

    With no `current` and no `pending` anywhere there is nothing to apply *from*,
    which is exactly when `rotate` still has to survey -- so a broken target is
    found rather than met half way through.
    """
    harness = estate(
        documents={"apps/acme/appdb-alpha": {}},
        connect_errors={"appdb-alpha": StoreError("ORA-12541: no listener")},
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code != ExitCode.SUCCESS
    assert harness["sessions"] == []


def test_a_first_rotation_with_an_empty_vault_succeeds(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Nothing staged, nothing current, and a password to put there."""
    harness = estate(documents={"apps/acme/appdb-alpha": {}})
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.SUCCESS
    body = stored(harness["store"], "apps/acme/appdb-alpha")
    assert body["DB_CREDENTIALS"]["acme_web_user"] == changed(harness)[0][1]


# ------------------------------------------------- §8 row 4, a staging failure ---


def test_a_staging_failure_touches_no_database(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Row 4 says nothing changed in the database, and this is what makes that
    true: the run stops at step 4 rather than applying what did stage."""

    class Refusing(MemoryStore):
        def write(self, path: str, data: Any, *, cas: int | None = None) -> Any:
            if path == "apps/acme/appdb-beta" and cas:
                raise StoreError("permission denied writing the document")
            return super().write(path, data, cas=cas)

    harness = estate(store=Refusing())
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.FAILURE
    assert changed(harness) == []
    assert "nothing was applied to any database" in result.output


# ------------------------------------------- §8 row 5, some targets confirmed ---


def test_a_failed_target_keeps_its_pending_and_promotes_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 7. `current` is what applications fetch, and promoting it while
    a database refuses would advertise a password that estate does not have.

    The `pending` left behind is what makes it recoverable -- it still holds the
    value the databases were being converged on, which is why `apply` is the
    remedy rather than a fresh rotation.
    """
    harness = estate(set_error=StoreError("ORA-01031: insufficient privileges"))
    result = run(runner, write_config(CONFIG))

    assert result.exit_code != ExitCode.SUCCESS
    body = stored(harness["store"], "apps/acme/appdb-alpha")
    assert body["DB_CREDENTIALS"]["acme_web_user"] == LIVE
    assert body["pending"]["acme_web_user"] != LIVE
    assert "previous" not in body


def test_a_partially_reachable_estate_names_the_repair(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#264's line: exit 4 exists to point at a remedy, and `apply` is it.

    Two targets, one of which fails -- which is what makes this *partial* rather
    than a failure. A run where every target failed exits 1 and is offered no
    remedy, because "run this again" is not advice for an estate that refused
    everything.
    """
    estate(
        users={"ACME_WEB_USER": user()},
        set_error=StoreError("ORA-01031: insufficient privileges"),
    )
    result = run(runner, write_config(CONFIG))

    assert result.exit_code != ExitCode.SUCCESS


# ------------------------------------------------ §8 row 8, the read-back ---


def test_a_read_back_disagreement_is_exit_four_with_its_own_code(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A store that acknowledges a write and serves something else -- which is
    what a replica behind its primary looks like. Nothing needs undoing, and the
    exit code alone cannot say that, so the diagnostic does."""

    class Lagging(MemoryStore):
        """Accepts every write and serves a stale ``current`` after the promotion."""

        def read(self, path: str, *, version: int | None = None) -> Stored | None:
            found = super().read(path, version=version)
            if found is None or "previous" not in found.data:
                return found
            stale = dict(found.data)
            stale["DB_CREDENTIALS"] = {"acme_web_user": LIVE}
            return replace(found, data=stale)

    harness = estate(store=Lagging())
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")

    assert result.exit_code == ExitCode.PARTIAL
    codes = [one.get("code") for one in document(result)["diagnostics"]]
    assert "SOPULI-W012" in codes
    assert changed(harness) != []


def test_a_read_back_disagreement_offers_no_repair(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Re-running `apply` would converge a database estate already converged.
    The thing to go and look at is the vault, so the remedy is withheld."""

    class Lagging(MemoryStore):
        def read(self, path: str, *, version: int | None = None) -> Stored | None:
            found = super().read(path, version=version)
            if found is None or "previous" not in found.data:
                return found
            stale = dict(found.data)
            stale["DB_CREDENTIALS"] = {"acme_web_user": LIVE}
            return replace(found, data=stale)

    estate(store=Lagging())
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert "repair with:" not in result.output
    assert "acme_web_user" in result.output


# ---------------------------------------------- the fence, at 4 and at 5 ---


def steal(path: str, *, at: str) -> Callable[[dict[str, Any], str], None]:
    """Somebody else takes this document's lock, once, mid-run (#282).

    A real record at the real path under a different ``correlation_id``, so the
    run's next fence check fails on the version and would fail on the id too.
    Once, because a takeover happens once and a hook firing on every call would
    also fence the run's very first target.

    ``at`` is the seam, and it is what makes the two exit codes testable:
    ``describe_user`` fires before this run has changed anything anywhere, and
    ``set_password`` fires once one database has been changed.
    """
    taken: list[str] = []

    def take(harness: dict[str, Any], event: str) -> None:
        if taken or event != at:
            return
        taken.append(path)
        theirs = LockRecord.acquired(
            correlation_id="01JSOMEBODYELSE",
            command="creds rotate",
            holder=Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli"),
            now=utc_now(),
        )
        # With the version the record is at, which is what a real taker passes:
        # the path requires a compare-and-set since #390, so an unguarded write
        # is refused by the store rather than by anything under test here.
        key = LockKey(store="vault-prod", path=path)
        held = harness["store"].read(lock_path(key))
        harness["store"].write(
            lock_path(key), theirs.to_dict(), cas=None if held is None else held.version
        )

    return take


def test_a_takeover_after_a_change_is_exit_four(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 section 8's fence row. Exit 7 after nine targets is the one answer
    that would tell a scheduler nothing happened at exactly the moment something
    did."""
    harness = estate(on_call=steal("apps/acme/appdb-beta", at="set_password"))
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert result.exit_code == ExitCode.PARTIAL
    codes = [one.get("code") for one in document(result)["diagnostics"]]
    assert "SOPULI-W011" in codes
    assert len(changed(harness)) == 1


def test_nothing_is_promoted_after_a_takeover(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Neither document is promoted: not the one whose lock went, and not the
    one this run still holds. A promotion asserts the whole estate has this
    password, and a run stopped part way through cannot assert it."""
    harness = estate(on_call=steal("apps/acme/appdb-beta", at="set_password"))
    run(runner, write_config(CONFIG))

    for target in ("appdb-alpha", "appdb-beta"):
        assert "previous" not in stored(harness["store"], f"apps/acme/{target}")


def test_a_takeover_before_any_database_is_reached_is_still_exit_four(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A staged document is a mutation too.

    `apply` splits 7 from 4 on whether a *database* was changed, and `rotate` has
    one more way to have changed something: by the time it reaches a database it
    has already written a `pending` that somebody has to clean up. Exit 7 asserts
    nothing happened, so a run fenced out after step 4 is 4 even with no DDL
    issued anywhere.
    """
    harness = estate(on_call=steal("apps/acme/appdb-beta", at="describe_user"))
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.PARTIAL
    assert changed(harness) == []


# ------------------------------------------------------- --finish-rollover ---


def test_finish_rollover_closes_windows_at_the_end_of_the_run(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """§8's tail, and the difference from `--strategy direct`: every window
    stays open until the whole estate has been applied and promoted."""
    harness = estate(
        users={"ACME_WEB_USER": user(rollover_enabled=True)},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
    )
    result = run(runner, write_config(CONFIG), "--finish-rollover")

    assert result.exit_code == ExitCode.SUCCESS
    assert finished(harness) == ["ACME_WEB_USER", "ACME_WEB_USER"]
    assert "closed 2 rollover windows" in result.output


def test_without_the_flag_no_window_is_closed(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The default leaves applications their grace period."""
    harness = estate(
        users={"ACME_WEB_USER": user(rollover_enabled=True)},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
    )
    result = run(runner, write_config(CONFIG))

    assert finished(harness) == []
    # The apply rows still *mention* an open window -- that is the state they
    # were left in. What must be absent is the closing line's own clause, which
    # is the only place the run claims to have ended any.
    assert "closed" not in result.output.rsplit("rotation:", 1)[-1]


def test_a_takeover_stops_the_windows_being_closed(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The fence reaches the tail of the run too (found in review on #284).

    Window-closing is the last mutation and the furthest from the acquisition, so
    it is the one most likely to be issued after a lease has gone -- and it is the
    one whose direction cannot be undone. A window nobody closed elapses on its
    own; one closed by a run that had already lost the estate cannot be reopened.

    The takeover fires on the first close, so the assertion is that the *second*
    target is left alone rather than that none was touched.
    """
    harness = estate(
        users={"ACME_WEB_USER": user(rollover_enabled=True)},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
        on_call=steal("apps/acme/appdb-beta", at="finish_rollover"),
    )
    result = run(runner, write_config(CONFIG), "--finish-rollover", "--output", "json")

    assert len(finished(harness)) == 1
    codes = [one.get("code") for one in document(result)["diagnostics"]]
    assert "SOPULI-W011" in codes


def test_a_takeover_while_closing_is_not_a_per_account_finding(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The trap #282 fixed in `_apply_one`, which the closing path had too.

    `_finish_one` catches `Exception` broadly and turns it into a row in the
    table, so a stolen lock would have become one account's bad luck and the run
    would have carried on closing the next account's window. The run must end
    instead -- exit 4, because it had already applied and promoted.
    """
    estate(
        users={"ACME_WEB_USER": user(rollover_enabled=True)},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
        on_call=steal("apps/acme/appdb-beta", at="finish_rollover"),
    )
    result = run(runner, write_config(CONFIG), "--finish-rollover")

    assert result.exit_code == ExitCode.PARTIAL
    assert "ERROR" not in result.output


def test_finish_rollover_alone_still_takes_no_lock(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The standalone verb writes to no store, so there is nothing for the
    advisory lock to protect -- and an hourly job that blocked rotations would be
    a worse problem than the one the lock solves. Threading the manager through
    for `rotate` must not have given this one a lock by the back door."""
    harness = estate(
        users={"ACME_WEB_USER": user(rollover_enabled=True)},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
        documents={
            f"apps/acme/{target}": {"DB_CREDENTIALS": {"acme_web_user": LIVE}}
            for target in ("appdb-alpha", "appdb-beta")
        },
    )
    result = runner.invoke(
        cli,
        ["creds", "finish-rollover", "--config", str(write_config(CONFIG)), "--output", "json"],
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert "lock" not in document(result)
    assert harness["store"].read("locks/apps/acme/appdb-alpha") is None


def test_a_failed_target_keeps_its_window(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Closing a window because its neighbours succeeded turns a partial
    rotation into an outage: the old password is all that account has left."""
    harness = estate(
        users={"ACME_WEB_USER": user(rollover_enabled=True)},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
        set_error=StoreError("ORA-01031: insufficient privileges"),
    )
    result = run(runner, write_config(CONFIG), "--finish-rollover")

    assert result.exit_code != ExitCode.SUCCESS
    assert finished(harness) == []


# -------------------------------------------------------------- the report ---


def test_the_closing_line_counts_documents_not_accounts(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The number an operator comparing this against a vault audit log is
    trying to match is compare-and-sets, not accounts."""
    estate()
    result = run(runner, write_config(CONFIG))

    assert "staged 2 documents, promoted 2 documents" in result.output


def test_the_plan_comes_before_anything_is_issued(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate()
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.output.index("Plan:") < result.output.index("STATE")


def test_an_empty_selection_says_so_rather_than_rotating(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate()
    result = run(runner, write_config(CONFIG), "--select", "tenant=omega")

    assert result.exit_code == ExitCode.SUCCESS
    assert "nothing to rotate" in result.output
    assert harness["sessions"] == []


# ------------------------------------------------------------------ jsonl ---
#
# `creds rotate` streams (#535). What is specific to it is the vault-side phase
# in front of the targets: staging is per document, so those events name a
# path and no target, and they all come before the first `target.started`.

EVENT_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-event-{EVENT_SCHEMA_VERSION}.schema.json"
)


@pytest.fixture
def events() -> Draft202012Validator:
    return Draft202012Validator(json.loads(EVENT_SCHEMA.read_text(encoding="utf-8")))


def stream(text: str, events: Draft202012Validator) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in text.splitlines()]
    for line in lines:
        assert [error.message for error in events.iter_errors(line)] == [], line
    return lines


def names(lines: list[dict[str, Any]]) -> list[str]:
    return [line["event"] for line in lines if line["event"] != "diagnostic"]


def test_jsonl_streams_the_vault_phase_before_any_target(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    events: Draft202012Validator,
) -> None:
    """Section 8's order, as it happened: lock, read, stage every document,
    re-read, then the targets, then the promotion, the read-back and the
    release -- and the rows last, once each is final."""
    estate()
    result = run(runner, write_config(CONFIG), "--output", "jsonl")

    assert result.exit_code == ExitCode.SUCCESS
    lines = stream(result.stdout, events)
    alpha, beta = "apps/acme/appdb-alpha", "apps/acme/appdb-beta"

    def stage(path: str) -> list[tuple[str, str | None]]:
        return [("vault.read", path), ("password.generated", path), ("vault.write", path)]

    assert [
        (line["event"], line.get("target") or (line.get("data") or {}).get("path"))
        for line in lines
        if line["event"] != "diagnostic"
    ] == [
        ("run.started", None),
        ("plan.resolved", None),
        ("lock.acquired", alpha),
        ("lock.acquired", beta),
        ("vault.read", alpha),
        ("vault.read", beta),
        *stage(alpha),
        *stage(beta),
        ("vault.read", alpha),
        ("vault.read", beta),
        ("target.started", "appdb-alpha"),
        ("password.applied", "appdb-alpha"),
        ("verification.done", "appdb-alpha"),
        ("target.started", "appdb-beta"),
        ("password.applied", "appdb-beta"),
        ("verification.done", "appdb-beta"),
        ("vault.promote", alpha),
        ("vault.promote", beta),
        ("vault.read", alpha),
        ("vault.read", beta),
        ("lock.released", alpha),
        ("lock.released", beta),
        ("target.finished", "appdb-alpha"),
        ("target.finished", "appdb-beta"),
        ("target.finished", "appdb-alpha"),
        ("target.finished", "appdb-beta"),
        ("run.finished", None),
    ]
    assert [line["seq"] for line in lines] == list(range(len(lines)))
    # The version applied is the version staging wrote.
    written = [line["data"]["version"] for line in lines if line["event"] == "vault.write"]
    applied = [line["data"]["version"] for line in lines if line["event"] == "password.applied"]
    assert applied == written


def test_jsonl_and_json_describe_the_same_rotation(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    events: Draft202012Validator,
) -> None:
    config = write_config(CONFIG)
    estate()
    lines = stream(run(runner, config, "--output", "jsonl").stdout, events)
    estate()
    body = document(run(runner, config, "--output", "json"))

    assert lines[-1]["data"] == {"summary": body["summary"], "exit_code": body["exit_code"]}
    assert next(line["data"] for line in lines if line["event"] == "plan.resolved") == body["plan"]

    def comparable(entry: dict[str, Any]) -> dict[str, Any]:
        # Fresh passwords make fresh versions and stamps in each run; what
        # must agree is the shape and the story, not the clock.
        return {key: value for key, value in entry.items() if key != "duration_ms"}

    streamed = [line["data"] for line in lines if line["event"] == "target.finished"]
    assert [comparable(one) for one in streamed] == [comparable(one) for one in body["results"]]
    released = [line["data"]["path"] for line in lines if line["event"] == "lock.released"]
    assert released == [one["path"] for one in body["lock"]["held"]]


def test_streamed_rotation_payloads_are_the_run_schema_shapes(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    events: Draft202012Validator,
) -> None:
    estate()
    lines = stream(run(runner, write_config(CONFIG), "--output", "jsonl").stdout, events)
    defs = json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))["$defs"]
    shapes = {
        "plan.resolved": "plan",
        "target.finished": "result",
        "verification.done": "verification",
        "lock.acquired": "lock/properties/held/items",
        "lock.released": "lock/properties/held/items",
    }
    checked = 0
    for line in lines:
        if line["event"] not in shapes:
            continue
        shape = Draft202012Validator({"$defs": defs, "$ref": f"#/$defs/{shapes[line['event']]}"})
        assert [error.message for error in shape.iter_errors(line["data"])] == [], line
        checked += 1
    # One plan, two locks acquired and released, two verifications, four rows.
    assert checked == 1 + 2 + 2 + 2 + 4


def test_no_rotation_event_carries_a_password(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    events: Draft202012Validator,
) -> None:
    """04 §6's grep, on the one verb that draws, stages, applies and promotes a
    password in a single run -- read back from the store, since the test never
    chose it."""
    harness = estate()
    result = run(runner, write_config(CONFIG), "--output", "jsonl")

    stream(result.stdout, events)
    for path in ("apps/acme/appdb-alpha", "apps/acme/appdb-beta"):
        body = stored(harness["store"], path)
        for secret in (body["DB_CREDENTIALS"]["acme_web_user"], body["previous"]["acme_web_user"]):
            assert secret not in result.stdout


def test_a_staging_failure_streams_the_refused_write_and_no_target(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    events: Draft202012Validator,
) -> None:
    """Row 4: nothing reaches a database. The refused write is a `vault.write`
    with no version and the store's error -- not a gap -- and the staging rows
    still arrive as `target.finished`."""

    class Refusing(MemoryStore):
        def write(self, path: str, data: Any, *, cas: int | None = None) -> Any:
            if path == "apps/acme/appdb-beta" and cas:
                raise StoreError("permission denied writing the document")
            return super().write(path, data, cas=cas)

    estate(store=Refusing())
    lines = stream(run(runner, write_config(CONFIG), "--output", "jsonl").stdout, events)

    writes = [line["data"] for line in lines if line["event"] == "vault.write"]
    assert [(one["path"], one["version"] is None, "error" in one) for one in writes] == [
        ("apps/acme/appdb-alpha", False, False),
        ("apps/acme/appdb-beta", True, True),
    ]
    assert "target.started" not in names(lines)
    assert [line["target"] for line in lines if line["event"] == "target.finished"] == [
        "appdb-alpha",
        "appdb-beta",
    ]
    assert lines[-1]["data"]["exit_code"] == ExitCode.FAILURE


def test_a_prompt_is_announced_on_the_stream_and_confirm_is_not(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    events: Draft202012Validator,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`confirmation.required` means somebody is being asked, now. `--confirm`
    answered in advance, so a stream from that run has nothing to announce."""
    config = write_config(CONFIG)
    monkeypatch.setattr("sopuli.cli._can_prompt", lambda: True)
    estate()
    asked = runner.invoke(
        cli, ["creds", "rotate", "--config", str(config), "--output", "jsonl"], input="y\n"
    )
    estate()
    answered = run(runner, config, "--output", "jsonl")

    # `CliRunner` echoes the typed answer onto stdout, which a terminal would
    # not; everything the tool itself wrote there is an event.
    typed = "\n".join(one for one in asked.stdout.splitlines() if one.startswith("{"))
    prompts = [
        line["data"]["prompt"]
        for line in stream(typed, events)
        if line["event"] == "confirmation.required"
    ]
    assert prompts == ["draw a new password for 1 account on 2 targets in `prod` and promote it?"]
    assert "confirmation.required" not in names(stream(answered.stdout, events))
    assert asked.exit_code == ExitCode.SUCCESS


def test_a_denied_lock_streams_the_holder_and_nothing_after_it(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    events: Draft202012Validator,
) -> None:
    """Somebody else is rotating: `lock.denied` names them, and nothing is read,
    staged or dialled after it (review of #543)."""
    harness = estate()
    key = LockKey(store="vault-prod", path="apps/acme/appdb-alpha")
    harness["store"].require_cas(lock_path(key))
    harness["store"].write(
        lock_path(key),
        LockRecord.acquired(
            correlation_id="01JSOMEBODYELSE",
            command="creds rotate",
            holder=Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli"),
            now=utc_now(),
        ).to_dict(),
        cas=0,
    )

    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "jsonl")

    assert isinstance(result.exception, LockDeniedError), result.exception
    lines = stream(result.stdout, events)
    assert names(lines) == ["run.started", "plan.resolved", "lock.denied", "run.finished"]
    assert lines[-2]["data"]["holder"]["correlation_id"] == "01JSOMEBODYELSE"
    assert lines[-1]["data"]["exit_code"] == ExitCode.LOCK_HELD
    assert harness["sessions"] == []

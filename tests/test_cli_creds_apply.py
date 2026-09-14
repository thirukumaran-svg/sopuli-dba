"""``sopuli creds apply`` end to end, without a database (#259).

Same arrangement as ``tests/test_cli_creds_check.py``: in-process through
``CliRunner``, with the vault a :class:`~sopuli.store.MemoryStore` and the driver
a fake session. The real ones have their own suites; this file is about *the
command* -- what it reads, in what order, what it issues, what it promotes, and
what it exits with.

Two properties carry most of it, and both are about restraint:

* **nothing is promoted that was not confirmed** (invariant 7), asserted on the
  document the store actually holds afterwards rather than on what the run said;
* **a second run changes nothing** (invariant 9), asserted on the statements the
  fake session recorded rather than on ``changed`` -- a command can report
  ``false`` and still have issued the DDL.
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

from sopuli import apply, check
from sopuli.cli import cli
from sopuli.clock import to_rfc3339, utc_now
from sopuli.config.errors import ArgumentError
from sopuli.config.model import Vault
from sopuli.diagnostics import LOCK_TAKEN_OVER, REPAIR_DOCUMENT_STALE
from sopuli.driver.oracle.accounts import RolesUnreadableError
from sopuli.driver.oracle.errors import classify
from sopuli.driver.protocol import (
    ACCOUNT_UNLOCK,
    ATTRIBUTE_SET,
    EXPIRE_PASSWORD,
    FAIL,
    PASS,
    PASSWORD_ROLLOVER,
    SKIPPED,
    VERIFY_LOGIN,
    AccountAttributes,
    AttributeChange,
    ChangeResult,
    PrivilegeAudit,
    Scope,
    UnsupportedCapabilityError,
    UserState,
    VerifyResult,
)
from sopuli.exit_codes import ExitCode
from sopuli.lock import (
    CLOCK_SKEW,
    DEFAULT_TTL,
    Holder,
    LockDeniedError,
    LockKey,
    LockRecord,
    lock_path,
)
from sopuli.output.document import SCHEMA_VERSION
from sopuli.safety import RefusedError
from sopuli.secrets import Secret
from sopuli.settings.registry import DEFAULT_CONNECT_TIMEOUT_S, NO_QUERY_TIMEOUT
from sopuli.store import MemoryStore, SecretStore

RUN_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

#: One application over two PDBs, one document per tenant, a field per account --
#: Q7's documented layout, so the shared-document path is the one under test.
CONFIG = """\
version: 1
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

#: Two accounts in one document, which is what makes the promotion gate visible:
#: both must confirm before either is promoted.
SHARED_CONFIG = """\
version: 1
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
applications:
  - name: acme
    accounts: [acme_web_user, acme_batch_user]
    secret_template: "apps/acme/db#DB_CREDENTIALS/{account}"
"""

#: The same estate, with each target asserting the container it should be in.
#: §3a's assertion is opt-in, so it takes its own config: the one above asserts
#: nothing, which is the case that must keep passing.
ASSERTING_CONFIG = CONFIG.replace(
    "    labels: { env: prod, tenant: alpha }",
    "    labels: { env: prod, tenant: alpha }\n    oracle: { scope: pdb, container: ALPHA }",
).replace(
    "    labels: { env: prod, tenant: beta }",
    "    labels: { env: prod, tenant: beta }\n    oracle: { scope: pdb, container: BETA }",
)

#: The same estate, opted in to UC-1 §5's account unlock (#300). Opt-in is the
#: whole rule, so the config that declares it has to be a separate one: `CONFIG`
#: above declares no policy at all, which is the case that must go on refusing to
#: touch a locked account.
UNLOCKING_CONFIG = (
    CONFIG
    + """policies:
  app-standard:
    account:
      unlock_if_locked: true
defaults:
  policy: app-standard
"""
)

#: Two accounts in one document, both opted in to the unlock. The pairing is what
#: makes #347's second exposure visible: the fence is checked once per account, so
#: an account after the first in the same target is one the run reaches with a
#: lock it may no longer hold.
SHARED_UNLOCKING_CONFIG = (
    SHARED_CONFIG
    + """policies:
  app-standard:
    account:
      unlock_if_locked: true
defaults:
  policy: app-standard
"""
)

#: The same estate, with a profile that narrows both database budgets (#360).
#: Profile-only by declaration -- there is no flag and no environment variable --
#: so a test about these keys is a test about the file.
TIMEOUTS_CONFIG = (
    CONFIG
    + """profiles:
  ci:
    db:
      connect_timeout_s: 90
      query_timeout_s: 600
"""
)

#: The same estate, with #83's standing permission for an unattended runner.
#: Config-only by design -- there is no flag and no environment variable -- so a
#: test about it is a test about the file.
BREAK_EXPIRED_CONFIG = (
    CONFIG
    + """defaults:
  locking:
    break_expired: true
"""
)

#: The same permission, written in a profile instead. Both layers are declared in
#: `settings/registry.py` and only one of them is `defaults:`.
BREAK_EXPIRED_PROFILE_CONFIG = (
    CONFIG
    + """profiles:
  scheduled:
    locking:
      break_expired: true
"""
)

#: The same estate again, opted in to §5's profile assignment (#301). The profile
#: is one `FakeSession` knows about; `MOVING_TO_NOTHING` names one no database has.
ASSIGNING_CONFIG = (
    CONFIG
    + """policies:
  app-standard:
    account:
      profile: acme_app_prof
defaults:
  policy: app-standard
"""
)

MISSING_PROFILE_CONFIG = ASSIGNING_CONFIG.replace("acme_app_prof", "acme_no_such_prof")

LIVE = "Correct-Horse-Battery-9"
STAGED = "Vertical-Anchor-Marble-4"


#: One account over two targets sharing **one** document, with a policy to draw
#: from. That combination is what makes #312 visible: a refusal on the second
#: target has to restage the account and re-apply the first as well, or the
#: promotion advertises a password half the estate does not hold.
REDRAW_CONFIG = """\
version: 1
vaults:
  vault-prod:
    type: hashicorp
    addr: https://vault-prod.example.com:8200
policies:
  app-standard:
    password:
      length: 24
      charset: alnum
      first_char: alpha
defaults:
  policy: app-standard
targets:
  - name: appdb-alpha
    type: oracle
    dsn: db-prod.example.com:1521/alpha.pdb.example.com
    environment: prod
    vault: vault-prod
  - name: appdb-beta
    type: oracle
    dsn: db-prod.example.com:1521/beta.pdb.example.com
    environment: prod
    vault: vault-prod
applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "apps/acme/db#DB_CREDENTIALS/{account}"
"""

#: The document `REDRAW_CONFIG` writes, staged the way #311's `generate` leaves it.
REDRAW_DOCUMENT = "apps/acme/db"


def staged(origin: str | None = "generated") -> dict[str, dict[str, Any]]:
    """One shared document, optionally carrying #311's provenance key."""
    body: dict[str, Any] = {
        "DB_CREDENTIALS": {"acme_web_user": LIVE},
        "pending": {"acme_web_user": STAGED},
    }
    if origin is not None:
        body["origin"] = {"acme_web_user": origin}
    return {REDRAW_DOCUMENT: body}


#: What the driver raises when the server refuses the *value* -- built through
#: the real classification rather than as a bare exception, because
#: `DriverError.regenerate` is what decides whether a redraw happens at all
#: (#312). A `RuntimeError` carrying the same text answers `False` and would make
#: every assertion below pass by never reaching the code under test.
def refusal(code: str = "ORA-28003") -> Exception:
    return classify(code, f"{code}: ORA-20001: password must contain a punctuation").as_error()


REFUSED = "ORA-28003"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8")))


class FakeSession:
    """One target's worth of answers, and a record of everything it was asked.

    The recording is the point. Half of what `apply` must get right is what it
    does *not* do -- no DDL against a locked account, no second change on a
    re-run, no login beyond the two it budgeted -- and none of that is visible in
    the output.
    """

    def __init__(
        self,
        users: Mapping[str, UserState | None],
        answers: Mapping[str, list[VerifyResult]],
        *,
        set_error: Exception | None = None,
        refusals: Any = None,
        capabilities: frozenset[str] = frozenset(),
        rollover_refusal: Exception | None = None,
        on_call: Callable[[str], None] | None = None,
        scope: Scope | None = None,
        audit: PrivilegeAudit | Exception | None = None,
        describe_error: Exception | None = None,
        profile_error: Exception | None = None,
    ) -> None:
        self.profile_error = profile_error
        self.describe_error = describe_error
        self.on_call = on_call
        self.given_scope = scope
        self.audit = audit
        self.users = dict(users)
        self.answers = {name: list(results) for name, results in answers.items()}
        self.set_error = set_error
        # How many `set_password` calls `set_error` still applies to, shared
        # across every session the run opens -- a redraw reconnects, and a
        # counter per session would refuse the new password as often as the old.
        # `True` forever is the permanent refusal every existing test wants.
        self.refusals = refusals if refusals is not None else iter(lambda: True, object())
        self.capabilities = capabilities
        self.rollover_refusal = rollover_refusal
        self.attempts: list[tuple[str, str]] = []
        #: Every ``set_password`` this session was asked for, refused ones
        #: included. ``changed`` is the subset that landed.
        self.attempted: list[tuple[str, str]] = []
        #: Accounts this session actually issued ``ACCOUNT UNLOCK`` for, which is
        #: not the same list as the ones it was asked about -- invariant 9 for the
        #: attributes is that an account already open is not touched.
        self.unlocked: list[str] = []
        #: Accounts this session actually moved, as (account, profile). Not the
        #: ones it was asked about: an account already on the profile is not
        #: touched.
        self.assigned: list[tuple[str, str]] = []
        self.budgets: list[int] = []
        self.changed: list[tuple[str, str]] = []
        self.finished: list[str] = []
        self.closed = False

    def scope(self) -> Scope:
        if self.given_scope is not None:
            return replace(self.given_scope, capabilities=self.capabilities)
        return Scope(type="pdb", container="ALPHA", read_write=True, capabilities=self.capabilities)

    def privileges(self) -> PrivilegeAudit:
        """What `--preflight` reads, and what `doctor --check-privileges` does.

        An `Exception` in `audit` stands for the view a service account is not
        granted, which is a caveat rather than a refusal -- so the two have to be
        distinguishable here or the test cannot tell them apart either.
        """
        if isinstance(self.audit, Exception):
            raise self.audit
        return self.audit if self.audit is not None else PrivilegeAudit()

    def describe_user(self, account: str) -> UserState | None:
        self._called("describe_user")
        if self.describe_error is not None:
            raise self.describe_error
        found = self.users.get(account.upper())
        if found is None:
            return None
        # A window opens when the password is set on a rollover-enabled profile,
        # and closes when `finish_rollover` runs. Modelled rather than scripted,
        # because the command reads the state back after each of those and the
        # bug worth catching is it reading a stale one.
        opened = (
            bool(found.rollover_enabled)
            and any(name == found.name for name, _ in self.changed)
            and found.name not in self.finished
        )
        return replace(found, rollover_active=opened)

    #: What this database has in `DBA_PROFILES`, upper-cased as Oracle stores it.
    profiles = ("DEFAULT", "ACME_APP_PROF", "ACME_ROLLOVER_PROF")

    def resolve_profile(self, profile: str) -> str | None:
        """The dictionary's spelling, or `None`. The real driver's contract.

        `profile_error` stands for the read that could not be made at all --
        `DBA_PROFILES` refused, or the capability absent -- which is a different
        answer from "no such profile" and has to be distinguishable here or the
        test cannot tell them apart either.
        """
        if self.profile_error is not None:
            raise self.profile_error
        found = profile.upper()
        return found if found in self.profiles else None

    def apply_attributes(
        self, account: str, attributes: AccountAttributes
    ) -> tuple[AttributeChange, ...]:
        """The real driver's shape: read the state, act only where it differs.

        The state is *modelled* rather than scripted, the way the rollover window
        above is, because the command reads the account back afterwards and the
        bug worth catching is it acting on the state from before.
        """
        changes: list[AttributeChange] = []
        if attributes.unlock:
            changes.append(self._unlock(account))
        if attributes.profile is not None:
            changes.append(self._assign(account, attributes.profile))
        return tuple(changes)

    def _unlock(self, account: str) -> AttributeChange:
        found = self.users.get(account.upper())
        if found is None or not found.locked:
            return AttributeChange(
                ACCOUNT_UNLOCK, changed=False, detail="the account is not locked"
            )
        self.unlocked.append(account.upper())
        self.users[account.upper()] = replace(found, locked=False, status="OPEN")
        return AttributeChange(
            ACCOUNT_UNLOCK, changed=True, detail=f"account was {found.status.lower()}; unlocked"
        )

    def _assign(self, account: str, profile: str) -> AttributeChange:
        found = self.users.get(account.upper())
        if found is None:
            raise RuntimeError(f'account "{account}" does not exist on this target')
        spelling = self.resolve_profile(profile)
        if spelling is None:
            raise RuntimeError(f'profile "{profile}" does not exist on this target')
        if found.profile is not None and found.profile.upper() == spelling:
            return AttributeChange(
                ATTRIBUTE_SET, changed=False, detail=f"profile is already {spelling}"
            )
        was = found.profile or "unknown"
        self.assigned.append((account.upper(), spelling))
        self.users[account.upper()] = replace(found, profile=spelling)
        return AttributeChange(ATTRIBUTE_SET, changed=True, detail=f"profile {was} -> {spelling}")

    def require_rollover(self, account: str) -> None:
        # The real driver raises for a missing account before it looks at
        # anything else (#181), so this one does too -- otherwise the pre-flight
        # could skip a case the estate would meet.
        if account.upper() not in self.users:
            raise RuntimeError(f'account "{account}" does not exist on this target')
        if self.rollover_refusal is not None:
            raise self.rollover_refusal

    def finish_rollover(self, account: str) -> ChangeResult:
        self.finished.append(account.upper())
        return ChangeResult(changed=True, detail="rollover window ended")

    def verify_password(
        self,
        account: str,
        secret: Secret,
        *,
        method: str = VERIFY_LOGIN,
        lockout_margin: int = 2,
        attempts: int = 1,
    ) -> VerifyResult:
        self.attempts.append((account.upper(), secret.reveal()))
        self.budgets.append(attempts)
        queued = self.answers.get(account.upper(), [])
        return queued.pop(0) if queued else VerifyResult(VERIFY_LOGIN, PASS, latency_ms=9)

    def set_password(self, account: str, secret: Secret) -> ChangeResult:
        # Recorded before the refusal, unlike `changed` below, which only sees the
        # calls that succeeded. A bounded redraw has to be asserted on the
        # statements the server was *asked* for (#312): an unbounded loop issues
        # them for ever and appends nothing to a list of successes.
        self.attempted.append((account.upper(), secret.reveal()))
        if self.set_error is not None and next(self.refusals, False):
            raise self.set_error
        self.changed.append((account.upper(), secret.reveal()))
        self._called("set_password")
        return ChangeResult(changed=True)

    def _called(self, event: str) -> None:
        """The seam a takeover needs: something happens to the vault *while* this
        run is mid-estate.

        Two seams matter and they are one hook, because what separates the two
        cases the exit code splits on is only *when* it fires: before this
        session's first `describe_user`, nothing has been applied anywhere; after
        a `set_password`, one database has been changed. Hooked here rather than
        by patching `LockManager`, so the test exercises the real fence -- the
        record on the path really is somebody else's by the next check.
        """
        if self.on_call is not None:
            self.on_call(event)

    def close(self) -> None:
        self.closed = True


def user(name: str = "ACME_WEB_USER", **fields: Any) -> UserState:
    """One account as the database describes it.

    ``password_file_member`` defaults to ``False`` -- *asked and answered* -- so
    that a case about something else is not also a case about guardrail 3 having
    no input (#296). The estate that cannot answer it belongs in
    `test_cli_guardrails.py`, where it is the subject rather than a side effect.
    """
    return UserState(**{"name": name, "status": "OPEN", "password_file_member": False, **fields})


def passes(count: int = 2) -> list[VerifyResult]:
    return [VerifyResult(VERIFY_LOGIN, PASS, latency_ms=9)] * count


def drifted() -> list[VerifyResult]:
    """Refused, then accepted: the ordinary rotation, before and after."""
    return [
        VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017: invalid credential"),
        VerifyResult(VERIFY_LOGIN, PASS, latency_ms=9),
    ]


Harness = Callable[..., dict[str, Any]]


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Harness:
    """Patch the store and the driver, and hand back what the run will meet."""

    def install(
        *,
        documents: Mapping[str, dict[str, Any]] | None = None,
        users: Mapping[str, UserState | None] | None = None,
        answers: Mapping[str, list[VerifyResult]] | None = None,
        per_target: Mapping[str, Mapping[str, list[VerifyResult]]] | None = None,
        connect_error: Exception | None = None,
        set_error: Exception | None = None,
        refusals: int | None = None,
        capabilities: frozenset[str] = frozenset(),
        rollover_refusal: Exception | None = None,
        on_call: Callable[[dict[str, Any], str], None] | None = None,
        scopes: Mapping[str, Scope] | None = None,
        audits: Mapping[str, PrivilegeAudit | Exception] | None = None,
        describe_error: Exception | None = None,
        profile_error: Exception | None = None,
    ) -> dict[str, Any]:
        store = MemoryStore()
        for path, body in (documents or _staged_two_targets()).items():
            store.write(path, body, cas=0)

        sessions: list[FakeSession] = []
        # Built up front so `on_change` can reach the store it is about to
        # interfere with, and handed back unchanged at the end.
        harness: dict[str, Any] = {"store": store, "sessions": sessions}
        # One budget for the whole run: `refusals=2` is a server that rejects the
        # next two passwords whichever session presents them, which is what a
        # redraw meets once it reconnects (#312).
        budget = None if refusals is None else iter([True] * refusals)

        def fake_connect(
            vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
        ) -> SecretStore:
            return store

        class FakeDriver:
            def __init__(self, **kwargs: Any) -> None:
                # Recorded so a test can assert what the *command* handed the
                # driver, which is where #360's missing wire was. The session
                # fake below cannot see it: `timeouts` is settled at
                # construction and never reaches a statement.
                harness.setdefault("driver_kwargs", []).append(kwargs)

            def connect(self, target: Any, credential: Any) -> FakeSession:
                if connect_error is not None:
                    raise connect_error
                scripted = answers if answers is not None else {"ACME_WEB_USER": drifted()}
                if per_target is not None:
                    scripted = per_target[target.name]
                session = FakeSession(
                    users if users is not None else {"ACME_WEB_USER": user()},
                    scripted,
                    set_error=set_error,
                    refusals=budget,
                    capabilities=capabilities,
                    rollover_refusal=rollover_refusal,
                    on_call=None if on_call is None else (lambda event: on_call(harness, event)),
                    scope=None if scopes is None else scopes.get(target.name),
                    audit=None if audits is None else audits.get(target.name),
                    describe_error=describe_error,
                    profile_error=profile_error,
                )
                sessions.append(session)
                return session

        class FakeModule:
            OracleDriver = FakeDriver

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        monkeypatch.setattr("sopuli.cli.resolve_driver", lambda target: FakeModule)
        monkeypatch.setattr("sopuli.cli.admin_resolve", lambda target, env: _credential())
        return harness

    return install


def _staged_two_targets() -> dict[str, dict[str, Any]]:
    return {
        f"apps/acme/{target}": {
            "DB_CREDENTIALS": {"acme_web_user": LIVE},
            "pending": {"acme_web_user": STAGED},
        }
        for target in ("appdb-alpha", "appdb-beta")
    }


def _credential() -> Any:
    class Resolved:
        credential = object()

    return Resolved()


def run(runner: CliRunner, config: Path, *args: str) -> Result:
    return runner.invoke(cli, ["creds", "apply", "--config", str(config), *args])


def document(result: Result) -> dict[str, Any]:
    return dict(json.loads(result.output))


def stored(store: MemoryStore, path: str) -> dict[str, Any]:
    found = store.read(path)
    assert found is not None
    return dict(found.data)


# --------------------------------------------------------- the happy path ---


def test_a_staged_password_is_applied_and_promoted(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §5 end to end: the database takes `pending`, and only then does the
    vault promote it."""
    harness = estate()
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    body = stored(harness["store"], "apps/acme/appdb-alpha")
    assert body["DB_CREDENTIALS"]["acme_web_user"] == STAGED
    assert body["previous"]["acme_web_user"] == LIVE
    assert "acme_web_user" not in body.get("pending", {})


def test_the_database_is_changed_to_the_staged_value(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate()
    run(runner, write_config(CONFIG))

    for session in harness["sessions"]:
        assert session.changed == [("ACME_WEB_USER", STAGED)]


def test_the_promotion_stamps_who_and_when(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §3's stamps, per account, beside the value they describe."""
    harness = estate()
    run(runner, write_config(CONFIG))

    body = stored(harness["store"], "apps/acme/appdb-alpha")
    assert body["rotated_at"]["acme_web_user"].endswith("Z")
    assert "@" in body["rotated_by"]["acme_web_user"]
    assert body["targets"]["acme_web_user"] == ["appdb-alpha"]


def test_the_plan_and_the_source_table_come_before_anything_is_issued(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate()
    result = run(runner, write_config(CONFIG))

    assert result.output.index("Plan:") < result.output.index("SOURCE")
    assert result.output.index("SOURCE") < result.output.index("STATE")


def test_the_document_validates_and_reports_the_promotion(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    estate()
    result = run(runner, write_config(CONFIG), "--output", "json")

    body = document(result)
    assert not list(validator.iter_errors(body))
    kinds = [action["kind"] for action in body["results"][0]["actions"]]
    assert kinds == ["verify", "password_set", "verify", "vault_promote"]
    assert body["results"][0]["secret"]["stage"] == "current"


# ------------------------------------------------------------ idempotency ---


def test_a_second_run_changes_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 9 names `apply` as the convergent verb. With nothing staged and
    a password the database accepts, no DDL is issued at all."""
    harness = estate(
        documents={"apps/acme/appdb-alpha": {"DB_CREDENTIALS": {"acme_web_user": LIVE}}},
        answers={"ACME_WEB_USER": passes(1)},
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["sessions"][0].changed == []
    assert document(result)["results"][0]["changed"] is False


def test_nothing_is_promoted_when_nothing_was_staged(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A run that read `current` is a repair; the vault already holds what it
    should, and writing a new version would be a version describing no change."""
    harness = estate(
        documents={"apps/acme/appdb-alpha": {"DB_CREDENTIALS": {"acme_web_user": LIVE}}},
        answers={"ACME_WEB_USER": passes(1)},
    )
    before = harness["store"].read("apps/acme/appdb-alpha").version
    run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["store"].read("apps/acme/appdb-alpha").version == before


def test_a_repair_beside_a_rotation_exits_zero(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Two documents, one staged and one not. The repair has nothing to promote,
    so counting it as unpromoted would make a run where everything confirmed look
    like UC-1 §8 case 7 -- the database holding the new password while the vault
    still advertises the old one -- and exit 4 with nothing wrong."""
    harness = estate(
        documents={
            "apps/acme/appdb-alpha": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE},
                "pending": {"acme_web_user": STAGED},
            },
            "apps/acme/appdb-beta": {"DB_CREDENTIALS": {"acme_web_user": LIVE}},
        },
        per_target={
            "appdb-alpha": {"ACME_WEB_USER": drifted()},
            "appdb-beta": {"ACME_WEB_USER": passes(1)},
        },
    )
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"] == {}
    assert "previous" not in stored(harness["store"], "apps/acme/appdb-beta")


def test_a_drifted_target_is_repaired_from_current(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The repair case, and the one that makes the pre-flight login worth its
    cost: the same command converges a database that has fallen out of step."""
    harness = estate(
        documents={"apps/acme/appdb-alpha": {"DB_CREDENTIALS": {"acme_web_user": LIVE}}},
        answers={"ACME_WEB_USER": drifted()},
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["sessions"][0].changed == [("ACME_WEB_USER", LIVE)]


# ----------------------------------------------------- what is not touched ---


def test_a_locked_account_is_not_changed(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The DDL would succeed and could never be confirmed. Asserted on the
    session rather than on the state, because a command can report `LOCKED` and
    still have issued the statement."""
    harness = estate(
        users={"ACME_WEB_USER": user(status="LOCKED", locked=True)},
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].changed == []
    assert harness["sessions"][0].attempts == []
    assert check.LOCKED in result.output


def test_a_locked_account_is_left_locked_where_nothing_declared_otherwise(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Opt-in, never inferred (#300). An estate that has not asked for the unlock
    gets the refusal it had before, and the message names the key that changes
    it."""
    harness = estate(users={"ACME_WEB_USER": user(status="LOCKED", locked=True)})
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].unlocked == []
    assert "unlock_if_locked" in result.output


# ------------------------------------------------------------ the attributes ---


def test_a_locked_account_is_unlocked_and_then_rotated(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The case the tool could not serve at all (#267): `apply` refuses to change
    a locked account's password, so a locked application account had to be
    unlocked by hand. With §5's attribute declared, the run removes the reason and
    goes on to do the work."""
    harness = estate(users={"ACME_WEB_USER": user(status="LOCKED", locked=True)})
    result = run(runner, write_config(UNLOCKING_CONFIG), "--select", "tenant=alpha")

    session = harness["sessions"][0]
    assert session.unlocked == ["ACME_WEB_USER"]
    assert session.changed == [("ACME_WEB_USER", STAGED)]
    assert result.exit_code == ExitCode.SUCCESS


def test_the_unlock_happens_before_the_first_login(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A locked account refuses every login, so a pre-flight verification made
    before the unlock would spend an attempt to learn nothing -- against the
    counter UC-1 §7's margin exists to protect."""
    harness = estate(users={"ACME_WEB_USER": user(status="LOCKED", locked=True)})
    run(runner, write_config(UNLOCKING_CONFIG), "--select", "tenant=alpha")

    session = harness["sessions"][0]
    assert session.unlocked == ["ACME_WEB_USER"]
    assert session.attempts, "the run should still have verified after unlocking"


def test_the_unlock_is_promoted_only_once_every_target_confirmed(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Nothing about the attribute weakens invariant 7: the unlock is a change to
    the database, and the vault still waits for the verification."""
    harness = estate(users={"ACME_WEB_USER": user(status="LOCKED", locked=True)})
    run(runner, write_config(UNLOCKING_CONFIG), "--select", "tenant=alpha")

    body = stored(harness["store"], "apps/acme/appdb-alpha")
    assert body["DB_CREDENTIALS"]["acme_web_user"] == STAGED


def test_an_account_that_is_not_locked_is_not_unlocked(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    """Invariant 9 for the attributes. The row is still emitted -- a consumer
    inferring "not declared" from "not present" would be reading the policy out of
    the results -- and it says the step did not run.

    Validated as well as read, because `account_unlock` is a value in the schema's
    `action_kind` enum that nothing emitted until now."""
    harness = estate()
    result = run(
        runner, write_config(UNLOCKING_CONFIG), "--select", "tenant=alpha", "--output", "json"
    )

    assert harness["sessions"][0].unlocked == []
    body = document(result)
    assert not list(validator.iter_errors(body))
    entry = body["results"][0]
    unlock = next(action for action in entry["actions"] if action["kind"] == ACCOUNT_UNLOCK)
    assert unlock["applied"] is False


def test_the_plan_says_the_run_may_unlock(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 8: the plan comes first, and a mutation the run may make has to
    be in it. An estate that declared nothing must not imply it might."""
    estate()
    opted = run(runner, write_config(UNLOCKING_CONFIG), "--dry-run", "--output", "json")
    plain = run(runner, write_config(CONFIG), "--dry-run", "--output", "json")

    assert ACCOUNT_UNLOCK in document(opted)["plan"]["units"][0]["intent"]
    assert ACCOUNT_UNLOCK not in document(plain)["plan"]["units"][0]["intent"]


def test_the_dry_run_unlocks_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 8's other half: print the plan, take no lock, write nothing --
    and an attribute is a write like any other."""
    harness = estate(users={"ACME_WEB_USER": user(status="LOCKED", locked=True)})
    run(runner, write_config(UNLOCKING_CONFIG), "--dry-run")

    assert harness["sessions"] == []


def test_an_account_is_moved_to_the_profile_the_policy_names(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """§5's second attribute (#301): `ALTER USER … PROFILE …`, and then the
    rotation, in one run."""
    harness = estate(users={"ACME_WEB_USER": user(profile="ACME_LEGACY_PROF")})
    result = run(runner, write_config(ASSIGNING_CONFIG), "--select", "tenant=alpha")

    session = harness["sessions"][0]
    assert session.assigned == [("ACME_WEB_USER", "ACME_APP_PROF")]
    assert session.changed == [("ACME_WEB_USER", STAGED)]
    assert result.exit_code == ExitCode.SUCCESS


def test_an_account_already_on_the_profile_is_not_moved(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 9. The row is still reported, saying the step did not run."""
    harness = estate(users={"ACME_WEB_USER": user(profile="ACME_APP_PROF")})
    result = run(
        runner, write_config(ASSIGNING_CONFIG), "--select", "tenant=alpha", "--output", "json"
    )

    assert harness["sessions"][0].assigned == []
    entry = document(result)["results"][0]
    assignment = next(action for action in entry["actions"] if action["kind"] == ATTRIBUTE_SET)
    assert assignment["applied"] is False
    assert "already" in assignment["detail"]


def test_the_move_is_reported_as_its_own_action_naming_both_profiles(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    """`attribute_set` is the schema's own kind for this and was unused until now,
    so the detail is what says which attribute moved and where from."""
    estate(users={"ACME_WEB_USER": user(profile="ACME_LEGACY_PROF")})
    result = run(
        runner, write_config(ASSIGNING_CONFIG), "--select", "tenant=alpha", "--output", "json"
    )

    body = document(result)
    assert not list(validator.iter_errors(body))
    assignment = next(
        action for action in body["results"][0]["actions"] if action["kind"] == ATTRIBUTE_SET
    )
    assert assignment["detail"] == "profile ACME_LEGACY_PROF -> ACME_APP_PROF"


def test_a_profile_this_database_has_not_got_is_refused_before_anything_is_written(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §8 step 3 (#301): the survey asks, and the run refuses rather than
    discovering it on target nine with eight accounts already moved."""
    harness = estate(users={"ACME_WEB_USER": user(profile="ACME_LEGACY_PROF")})
    result = run(runner, write_config(MISSING_PROFILE_CONFIG), "--preflight")

    assert result.exit_code != ExitCode.SUCCESS
    assert "acme_no_such_prof" in result.output
    assert all(session.assigned == [] for session in harness["sessions"])
    assert all(session.changed == [] for session in harness["sessions"])
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]


def test_a_profile_read_that_failed_is_reported_and_does_not_stop_the_survey(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`_preflight_target`'s own rule: every probe that fails is a finding rather
    than an exception, because letting one escape takes every finding gathered so
    far with it. A read that failed has established nothing either way, so it does
    not block -- the driver asks again before its own statement."""
    estate(
        users={"ACME_WEB_USER": user(profile="ACME_LEGACY_PROF")},
        profile_error=RuntimeError("ORA-00942: table or view does not exist"),
    )
    result = run(runner, write_config(ASSIGNING_CONFIG), "--preflight", "--output", "json")

    # Reported for **both** targets: an escaping exception would have taken the
    # first target's findings with it and never reached the second.
    diagnostics = [one["message"] for one in document(result).get("diagnostics", [])]
    assert sum("could not establish" in one for one in diagnostics) == 2
    # Not blocking, so the run went on to try -- and the account is an ERROR
    # because the driver asks the same question again before its own statement.
    assert [one["state"] for one in document(result)["results"]] == [check.ERROR, check.ERROR]


def test_a_target_that_cannot_read_profiles_at_all_refuses_the_run(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 4, and the one exception the survey lets past: an assignment this
    run intends can never run against a target without the capability, and that is
    a plan-time refusal naming it rather than a finding among others."""
    harness = estate(
        users={"ACME_WEB_USER": user(profile="ACME_LEGACY_PROF")},
        profile_error=UnsupportedCapabilityError("profile_management", target="appdb-alpha"),
    )
    result = run(runner, write_config(ASSIGNING_CONFIG), "--preflight")

    assert isinstance(result.exception, UnsupportedCapabilityError)
    assert result.exception.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
    assert all(session.assigned == [] for session in harness["sessions"])
    assert all(session.changed == [] for session in harness["sessions"])


def test_naming_a_regime_over_a_profile_move_is_refused(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The interaction #301 designs against: a profile decides whether a rollover
    window opens, so a regime judged against the profile an account is *leaving*
    could be cleared and then run under one that opens a window."""
    harness = estate(users={"ACME_WEB_USER": user(profile="ACME_LEGACY_PROF")})
    result = run(runner, write_config(ASSIGNING_CONFIG), "--strategy", "staged")

    assert result.exit_code != ExitCode.SUCCESS
    # Nothing was moved and nothing was rotated: the refusal is a pre-flight one,
    # so it lands before the first mutation on the first target rather than after
    # the estate had been half walked.
    assert all(session.assigned == [] for session in harness["sessions"])
    assert all(session.changed == [] for session in harness["sessions"])
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]


def test_a_regime_is_fine_where_nothing_would_move(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The refusal is about the *move*, not about declaring a profile: an estate
    whose accounts already sit on the declared one rotates under a named regime
    exactly as it did before."""
    harness = estate(users={"ACME_WEB_USER": user(profile="ACME_APP_PROF")})
    result = run(runner, write_config(ASSIGNING_CONFIG), "--strategy", "staged")

    assert result.exit_code == ExitCode.SUCCESS
    assert applying(harness).changed == [("ACME_WEB_USER", STAGED)]


def test_the_plan_says_the_run_may_set_an_attribute(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate()
    opted = run(runner, write_config(ASSIGNING_CONFIG), "--dry-run", "--output", "json")
    plain = run(runner, write_config(CONFIG), "--dry-run", "--output", "json")

    assert ATTRIBUTE_SET in document(opted)["plan"]["units"][0]["intent"]
    assert ATTRIBUTE_SET not in document(plain)["plan"]["units"][0]["intent"]


def test_a_missing_account_is_reported_and_not_created(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate(users={})
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].changed == []
    assert check.ACCOUNT_MISSING in result.output
    assert result.exit_code == ExitCode.FAILURE


def test_an_empty_vault_fails_rather_than_reporting_success(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A mutating verb that exits 0 having converged nothing is the silent
    failure worth being loud about."""
    harness = estate(documents={"apps/acme/appdb-alpha": {"other": "value"}})
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.FAILURE
    assert harness["sessions"][0].changed == []
    assert "creds generate" in result.output


def test_dry_run_reads_the_vault_and_writes_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 8. The documents are still read -- which stage an account would
    be applied from is the thing worth reviewing, and a read needs no lock."""
    harness = estate()
    result = run(runner, write_config(CONFIG), "--dry-run")

    assert result.exit_code == ExitCode.SUCCESS
    assert "pending" in result.output
    assert "nothing was applied" in result.output
    assert harness["sessions"] == []
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]


# ----------------------------------------------------------- the promotion ---


def test_one_failed_target_stops_the_promotion_for_that_document(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 7 and UC-1 §5: promoting would advertise a password part of the
    estate does not have. Each target has its own document here, so only the one
    that failed is held back."""
    harness = estate(
        per_target={
            "appdb-alpha": {"ACME_WEB_USER": drifted()},
            "appdb-beta": {
                "ACME_WEB_USER": [
                    VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017"),
                    VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017"),
                ]
            },
        }
    )
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.PARTIAL
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"] == {}
    assert stored(harness["store"], "apps/acme/appdb-beta")["pending"]["acme_web_user"] == STAGED


def test_a_partial_run_names_the_invocation_that_repairs_it(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#264, and the half of exit 4 that was missing: the code exists to point at
    a remedy, and the remedy has to be narrowed the way this run was narrowed --
    otherwise the repair spends a login on every target the partial run already
    spent one on."""
    estate(
        per_target={
            "appdb-alpha": {"ACME_WEB_USER": drifted()},
            "appdb-beta": {
                "ACME_WEB_USER": [
                    VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017"),
                    VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017"),
                ]
            },
        }
    )
    config = write_config(CONFIG)

    result = run(runner, config, "--select", "env=prod")

    assert result.exit_code == ExitCode.PARTIAL
    assert f"repair with: sopuli creds apply --config {config} --select env=prod" in result.output


def test_a_run_that_worked_offers_no_repair(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The remedy is exit 4's, and a successful run naming one would be the table
    and the exit code describing the same run differently."""
    estate()

    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert "repair with:" not in result.output


def test_a_changed_database_with_no_promotion_carries_a_warning(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §8's highest-severity row: applications fetch `current`, and until
    the promotion lands they are fetching a password the database no longer
    has."""
    estate(
        answers={
            "ACME_WEB_USER": [
                VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017"),
                VerifyResult(VERIFY_LOGIN, SKIPPED, detail="within 2 of the limit"),
            ]
        }
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")

    warnings = document(result)["results"][0]["warnings"]
    assert any("was not promoted" in one["message"] for one in warnings)


# ------------------------------------------------------------------ the fence ---


#: The lock guarding the first target's document, which is the one every test in
#: this section writes a record onto.
ALPHA_LOCK = LockKey(store="vault-prod", path="apps/acme/appdb-alpha")


def other_run(*, now: Any) -> dict[str, Any]:
    """A held record left by somebody else, as of ``now``."""
    return LockRecord.acquired(
        correlation_id="01JSOMEBODYELSE",
        command="creds rotate",
        holder=Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli"),
        now=now,
    ).to_dict()


def lapsed() -> dict[str, Any]:
    """A record whose claim has run out, past the clock-skew margin.

    Taken out long enough ago that `expires_at` is behind *now* by more than
    `CLOCK_SKEW`, because a lock is not expired until it is past both -- and a
    test that only just cleared `expires_at` would pass or fail on how long the
    run took.
    """
    return other_run(now=utc_now() - DEFAULT_TTL - CLOCK_SKEW - timedelta(minutes=1))


def fresh() -> dict[str, Any]:
    """A record somebody is still working under."""
    return other_run(now=utc_now())


def steal(path: str, *, at: str) -> Callable[[dict[str, Any], str], None]:
    """Somebody else takes this document's lock, once, mid-run (#282).

    A real record at the real path written under a different `correlation_id`, so
    the run's next fence check fails on the version and would fail on the id too.
    Once, because a takeover happens once and a hook firing on every call would
    also fence the run's very first target.

    ``at`` is which seam it happens on, and it is what makes the two exit codes
    testable: ``describe_user`` fires before this run has changed anything, and
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


def test_a_takeover_after_a_change_stops_the_run_and_promotes_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §8's fence row: abort immediately, mutate nothing further. Exit 4
    rather than 7, because 7 asserts nothing happened and one database has just
    been changed."""
    harness = estate(on_call=steal("apps/acme/appdb-beta", at="set_password"))

    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.PARTIAL
    assert sum(len(session.changed) for session in harness["sessions"]) == 1
    # Neither document is promoted: not the one whose lock went, and not the one
    # this run still holds. A promotion asserts the whole estate has the password.
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]["acme_web_user"] == STAGED
    assert stored(harness["store"], "apps/acme/appdb-beta")["pending"]["acme_web_user"] == STAGED


def test_a_stopped_run_says_so_instead_of_offering_the_repair(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#264's line says *run this again*, which is the one thing not to do while
    somebody else holds this estate's lock."""
    estate(on_call=steal("apps/acme/appdb-beta", at="set_password"))

    result = run(runner, write_config(CONFIG))

    assert "taken over" in result.output
    assert "repair with:" not in result.output


def test_a_stopped_run_carries_the_code_that_separates_it_from_a_failed_one(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, validator: Any
) -> None:
    """Both exit 4, and they want opposite responses -- which is exactly what
    `03-json-output.md` §3 says a diagnostic code is for."""
    estate(on_call=steal("apps/acme/appdb-beta", at="set_password"))

    result = run(runner, write_config(CONFIG), "--output", "json")
    found = document(result)

    validator.validate(found)
    assert found["exit_code"] == ExitCode.PARTIAL
    assert [one["code"] for one in found["diagnostics"] if one["level"] == "error"] == [
        "SOPULI-W011"
    ]


def test_a_takeover_before_any_change_is_exit_seven(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The other half of the split `sopuli/lock/errors.py` leaves to the command.

    The lock went after this run acquired it and before it changed anything, so
    nothing happened -- which is what exit 7 asserts, and what exit 4 would deny.
    """
    harness = estate(on_call=steal("apps/acme/appdb-alpha", at="describe_user"))

    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.LOCK_HELD
    assert harness["sessions"][0].changed == []
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]["acme_web_user"] == STAGED


def test_the_attribute_pass_is_behind_the_fence(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#347. `apply_attributes` issues `ALTER USER ... ACCOUNT UNLOCK`, which is a
    database change like any other and was being made before any fence check.

    The takeover lands on this run's *first* `describe_user`, so the lock is
    somebody else's before the attribute pass is reached. Before #347 the only
    check in `_apply_one` ran after it, and this run unlocked an account on a
    lock it no longer held -- a smaller blast radius than a password and the same
    rule broken.
    """
    harness = estate(
        users={"ACME_WEB_USER": user(status="LOCKED", locked=True)},
        on_call=steal("apps/acme/appdb-alpha", at="describe_user"),
    )

    result = run(runner, write_config(UNLOCKING_CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.LOCK_HELD
    assert harness["sessions"][0].unlocked == []
    assert harness["sessions"][0].changed == []


def test_a_takeover_stops_the_next_account_before_its_attribute_pass(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The second half of #347's exposure: every account after the first *within*
    a target.

    `renew()` fences each target boundary, so a two-target estate is covered at
    the seam between them. Two accounts in one target have no seam -- the run
    goes straight from one to the next -- and the attribute pass was the first
    thing each of them did. The takeover here lands on the first account's
    `set_password`, so the first account's work stands and the second must not
    even be unlocked.
    """
    harness = estate(
        documents={
            "apps/acme/db": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
                "pending": {"acme_web_user": STAGED, "acme_batch_user": STAGED},
            }
        },
        users={
            "ACME_WEB_USER": user(status="LOCKED", locked=True),
            "ACME_BATCH_USER": user("ACME_BATCH_USER", status="LOCKED", locked=True),
        },
        answers={"ACME_WEB_USER": drifted(), "ACME_BATCH_USER": drifted()},
        on_call=steal("apps/acme/db", at="set_password"),
    )

    result = run(runner, write_config(SHARED_UNLOCKING_CONFIG))

    session = harness["sessions"][0]
    assert session.unlocked == ["ACME_WEB_USER"]
    assert session.changed == [("ACME_WEB_USER", STAGED)]
    assert result.exit_code == ExitCode.PARTIAL


def test_closing_the_rollover_window_is_behind_the_fence(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#347's second mutation. `creds finish-rollover` fences this same call and
    `creds apply` did not, which is one operation encoding two rules about
    whether the fence applies to it -- and only one of them can be the intended
    one.

    The window stays open, which is the safe direction: an operator can close it
    deliberately, and a window closed by a run that had lost its lock is an old
    password stopped working by somebody who was no longer holding the estate.
    """
    harness = estate(
        users={"ACME_WEB_USER": rollover_user()},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
        on_call=steal("apps/acme/appdb-alpha", at="set_password"),
    )

    run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--strategy", "direct")

    assert applying(harness).changed == [("ACME_WEB_USER", STAGED)]
    assert applying(harness).finished == []


def test_a_takeover_during_the_renewal_keeps_what_the_run_applied(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#346. The renewal's compare-and-set loses, and that is a *takeover*.

    `renew()` checks the fence and then writes, and a takeover can land in
    between -- or on lock two after lock one has already been rewritten. Every
    conflict used to become `LockDeniedError`, whose message said the run was
    "acquiring" a lock it had held since the first target, and which
    `_apply_estate` does not catch: it escaped to `creds apply`'s own handler,
    which set `document.lock` and re-raised, and the boundary mapped it to exit
    7. `document.results` was never set and the accumulated `applied` list went
    with the exception.

    So a scheduler was told **exit 7 -- nothing happened** at the exact moment
    the first target had already been re-passworded. Exit 4 with the results
    kept is what the split in `sopuli/lock/errors.py` describes, and what the
    command layer already does for every other takeover.
    """
    harness = estate()
    store = harness["store"]
    first = lock_path(LockKey(store="vault-prod", path="apps/acme/appdb-alpha"))
    write = store.write
    raced: list[str] = []

    def racing_write(path: str, data: Mapping[str, Any], *, cas: int | None = None) -> int:
        # The renewal is the first write to a lock path carrying a non-zero CAS:
        # acquisition passes 0, and the release comes after this. Somebody else
        # gets there with the version this run was about to use.
        if not raced and path == first and cas:
            raced.append(path)
            theirs = LockRecord.acquired(
                correlation_id="01JSOMEBODYELSE",
                command="creds rotate",
                holder=Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli"),
                now=utc_now(),
            )
            write(path, theirs.to_dict(), cas=cas)
        return int(write(path, data, cas=cas))

    store.write = racing_write

    result = run(runner, write_config(CONFIG), "--output", "json")
    found = document(result)

    assert raced, "the renewal never wrote, so this asserts nothing"
    assert found["exit_code"] == ExitCode.PARTIAL
    # The whole point: what the first target applied is still in the document.
    assert [one["account"] for one in found["results"]] == ["acme_web_user"]
    assert sum(len(session.changed) for session in harness["sessions"]) == 1


def plant_lock(store: Any, key: LockKey, body: dict[str, Any]) -> None:
    """Somebody else's lock record, planted the way a real run would leave it.

    The `require_cas` is not decoration: since #390 an acquisition arranges that
    guarantee on a path it creates, so a rival run's record comes with it. A
    record planted without it describes a path *nobody's* sopuli created, which
    pre-flight refuses on sight -- a different test from the one each caller
    below is writing.
    """
    store.require_cas(lock_path(key))
    store.write(lock_path(key), body, cas=0)


def test_an_expired_lock_stops_a_run_that_was_not_given_permission(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The default, and the behaviour #348 must not change by accident.

    An expired record is still somebody's claim until a person or a standing
    permission says otherwise: the holder may be alive and slow rather than
    dead. So without the key this is exit 7, and the hint names the two ways
    out.
    """
    harness = estate()
    plant_lock(harness["store"], ALPHA_LOCK, lapsed())

    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    # `CliRunner` drives the group rather than `sopuli.cli.main`, so the refusal
    # arrives as the exception and the runner's own code is 1. `LockDeniedError`
    # is what the boundary maps to exit 7, and it deliberately carries no code of
    # its own (`sopuli/lock/errors.py`).
    assert isinstance(result.exception, LockDeniedError), result.exception
    assert harness["sessions"] == []
    assert "break_expired" in str(result.exception)


def test_break_expired_in_defaults_lets_an_unattended_run_take_the_lock(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#348. The key was resolved, ratcheted, cross-checked twice, and
    implemented in `decide()` -- and no `LockManager` was ever built with it.

    So an operator set it, hit exit 7, was told by `_hint_for` to set the key
    they had already set, and had nothing in the output to tell them it was not
    consulted. This is that wire, asserted where it shows: the run proceeds.
    """
    harness = estate()
    plant_lock(harness["store"], ALPHA_LOCK, lapsed())

    result = run(runner, write_config(BREAK_EXPIRED_CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["sessions"][0].changed == [("ACME_WEB_USER", STAGED)]


def test_a_takeover_says_so_in_the_output(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, validator: Any
) -> None:
    """A guardrail that fires silently is half a guardrail, and this one did.

    `lock_diagnostics` was written and unit-tested and called by nothing -- the
    same shape as #348 itself -- so a run that broke somebody's lock said so
    nowhere. `01-configuration.md` §5.3 says this and `sopuli lock break` "emit
    the same warning code, because it is the same event", and `_taken_over`'s own
    docstring says why it has to: the evidence is gone from the path the moment
    the takeover write lands, so if this run does not report it, nothing ever
    does.
    """
    harness = estate()
    plant_lock(harness["store"], ALPHA_LOCK, lapsed())

    result = run(
        runner, write_config(BREAK_EXPIRED_CONFIG), "--select", "tenant=alpha", "--output", "json"
    )
    found = document(result)

    validator.validate(found)
    warnings = [one for one in found["diagnostics"] if one.get("code") == LOCK_TAKEN_OVER]
    assert len(warnings) == 1
    # The holder, so somebody can go and ask whether they were still working.
    assert "svc_sopuli@ci-runner-3" in warnings[0]["message"]


def test_break_expired_in_a_profile_reaches_the_manager_too(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Both layers the registry declares, not just the one the fix was written
    against. `defaults:` and a profile are the two, and a wire that carried only
    the first would be #348 again for every estate that puts it where
    `01-configuration.md` says it belongs -- "the profile is where this belongs:
    it is a property of running without anybody watching"."""
    harness = estate()
    plant_lock(harness["store"], ALPHA_LOCK, lapsed())

    result = run(
        runner,
        write_config(BREAK_EXPIRED_PROFILE_CONFIG),
        "--profile",
        "scheduled",
        "--select",
        "tenant=alpha",
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["sessions"][0].changed == [("ACME_WEB_USER", STAGED)]


def test_a_live_lock_is_refused_even_with_break_expired(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The permission is for a lock past `expires_at` plus the skew margin, and
    for nothing else. A colleague mid-rotation still holds theirs."""
    harness = estate()
    plant_lock(harness["store"], ALPHA_LOCK, fresh())

    result = run(runner, write_config(BREAK_EXPIRED_CONFIG), "--select", "tenant=alpha")

    assert isinstance(result.exception, LockDeniedError), result.exception
    assert "is locked by" in str(result.exception)
    assert harness["sessions"] == []


# ------------------------------------------------------------- the budgets ---


def test_both_database_budgets_reach_the_driver(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#360. `db.query_timeout_s` was resolved, ratcheted and passed to nobody.

    `_timeouts()` read `connect_timeout_s` and built `Timeouts(connect_s=...)`,
    so a profile writing `query_timeout_s` validated, appeared in `config show`,
    and changed nothing at all. The driver end had been complete since #176 --
    `Timeouts.query_s` becomes `Connection.call_timeout`, asserted in
    `tests/driver/test_oracle_connect.py` -- and the command-side wire was the
    missing half, which is exactly the half no test looked at.

    Asserted on what the *command* handed the driver rather than on what the
    driver did with it, because that is where the gap was: the driver was right
    all along.
    """
    harness = estate()

    result = run(
        runner, write_config(TIMEOUTS_CONFIG), "--profile", "ci", "--select", "tenant=alpha"
    )

    assert result.exit_code == ExitCode.SUCCESS
    timeouts = harness["driver_kwargs"][0]["timeouts"]
    assert (timeouts.connect_s, timeouts.query_s) == (90, 600)
    assert timeouts.call_timeout_ms == 600_000


def test_an_unset_query_budget_stays_unbounded(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Wiring the key does not change what the tool *imposes*, and that is the
    reason wiring it was safe.

    The built-in stays `NO_QUERY_TIMEOUT`: a call timeout cancels the round trip
    without undoing what the server did with it, `ALTER USER` is not
    transactional, and a rotation cut off at the wrong moment leaves a run that
    cannot say whether the password changed -- the one state invariant 7 has no
    answer for. An estate that never asked for a bound must not acquire one by
    way of this fix.
    """
    harness = estate()

    run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    timeouts = harness["driver_kwargs"][0]["timeouts"]
    assert timeouts.query_s == NO_QUERY_TIMEOUT
    assert timeouts.call_timeout_ms == 0
    assert timeouts.connect_s == DEFAULT_CONNECT_TIMEOUT_S


def test_the_lease_is_renewed_at_each_target_boundary(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §8 step 5. Visible as the lock record's version, because a renewal is
    a write -- which is also why it carries the boundary's fence check.

    Counted exactly rather than "more than before". Two targets means one
    boundary, so this path is written three times: acquired, renewed, released.
    Without the renewal it would be written twice, and a test asserting only that
    the version moved would pass either way.
    """
    harness = estate()
    assert harness["store"].read("locks/apps/acme/appdb-alpha") is None

    result = run(runner, write_config(CONFIG))
    after = harness["store"].read("locks/apps/acme/appdb-alpha")

    assert result.exit_code == ExitCode.SUCCESS
    assert after.version == 3


# --------------------------------------------------------------- the pre-flight ---


def test_without_the_flag_nothing_is_surveyed(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The cost is opt-in. A repair of one target should not pay for a survey of
    twenty, so with no `--preflight` and no `--strategy` the estate is connected
    to once per target and that once is the apply itself."""
    harness = estate()

    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.SUCCESS
    assert len(harness["sessions"]) == 1


def test_a_target_in_the_wrong_container_refuses_before_anything_is_written(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The edit this check exists for: a `dsn:` repointed at a different
    container, where everything keeps working against the wrong database."""
    harness = estate(scopes={"appdb-alpha": Scope(type="pdb", container="GAMMA", read_write=True)})

    result = run(runner, write_config(ASSERTING_CONFIG), "--select", "tenant=alpha", "--preflight")

    assert result.exit_code == ExitCode.FAILURE
    assert all(session.changed == [] for session in harness["sessions"])
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]["acme_web_user"] == STAGED
    assert "GAMMA" in result.output


def test_a_read_only_database_refuses_before_the_statement(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """P1 requires the refusal up front rather than a statement failing half way
    through it."""
    harness = estate(
        scopes={
            "appdb-alpha": Scope(
                type="pdb", container="ALPHA", read_write=False, open_mode="READ ONLY"
            )
        }
    )

    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--preflight")

    assert result.exit_code == ExitCode.FAILURE
    assert all(session.changed == [] for session in harness["sessions"])


def test_a_missing_privilege_refuses_the_run_and_says_which(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, validator: Any
) -> None:
    """Without this, the run fails at the verb that needs the grant, several
    commands from here, with an error about a dictionary view rather than about
    the install."""
    estate(audits={"appdb-alpha": PrivilegeAudit(missing=("GRANT ALTER USER",))})

    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--preflight",
        "--output",
        "json",
    )
    found = document(result)

    validator.validate(found)
    assert found["exit_code"] == ExitCode.FAILURE
    assert found["error"]["category"] == "authorization"
    assert "GRANT ALTER USER" in str(found["diagnostics"])


def test_an_unreadable_audit_is_a_caveat_and_not_a_refusal(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """An estate that will not grant the audit view must still be able to run a
    pre-flight -- and the guard that is not running has to say so, which is the
    rule UC-1 §7 writes for `check`'s LCOUNT guard."""
    estate(audits={"appdb-alpha": RuntimeError("ORA-00942: table or view does not exist")})

    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--preflight",
        "--output",
        "json",
    )
    found = document(result)

    assert found["exit_code"] == ExitCode.SUCCESS
    assert [one["level"] for one in found["diagnostics"]] == ["warning"]
    assert "could not be read" in found["diagnostics"][0]["message"]


def test_a_missing_account_refuses_a_preflighted_run(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`apply` alone reports this per account and carries on, which is right when
    nobody asked. Somebody who asked for a pre-flight asked to be told before it
    started, and a run that started anyway would have answered a different
    question.

    Asserted on the run-level `error` rather than on the exit code, because an
    ordinary run over a missing account exits 1 as well -- what separates the two
    is that this one never reached a target, so it has a reason for the run
    rather than a row per account.
    """
    estate(users={})

    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--preflight",
        "--output",
        "json",
    )
    found = document(result)

    assert found["exit_code"] == ExitCode.FAILURE
    assert found["error"]["category"] == "database"
    assert "acme_web_user" in str(found["diagnostics"])
    assert not found.get("results")


def test_an_unreachable_target_refuses_a_preflighted_run(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Without the flag this is a per-account finding and the run carries on;
    with it, being unable to reach a target is exactly what was asked about."""
    estate(connect_error=RuntimeError("ORA-12541: no listener"))

    result = run(runner, write_config(CONFIG), "--preflight", "--output", "json")
    found = document(result)

    assert found["exit_code"] == ExitCode.FAILURE
    assert found["error"]["category"] == "connectivity"


def test_a_clean_estate_preflights_and_then_applies(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The survey costs one connection per target and then the run proceeds
    normally -- two sessions per target, one that asked and one that changed."""
    harness = estate()

    result = run(runner, write_config(ASSERTING_CONFIG), "--select", "tenant=alpha", "--preflight")

    assert result.exit_code == ExitCode.SUCCESS
    assert len(harness["sessions"]) == 2
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"] == {}


def test_a_dry_run_still_preflights(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`--dry-run --preflight` is "show me the plan, and tell me whether it would
    work". Skipping the survey there would make the flag silently mean nothing on
    the invocation somebody reaches for first."""
    harness = estate(audits={"appdb-alpha": PrivilegeAudit(missing=("GRANT ALTER USER",))})

    result = run(
        runner, write_config(CONFIG), "--select", "tenant=alpha", "--preflight", "--dry-run"
    )

    assert result.exit_code == ExitCode.FAILURE
    assert "GRANT ALTER USER" in result.output
    assert all(session.changed == [] for session in harness["sessions"])


def test_an_account_whose_state_cannot_be_read_is_a_finding_and_not_a_crash(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`describe_user` raises where the account's *state* cannot be read rather
    than where the account is absent -- `RolesUnreadableError`, for a
    `DBA_ROLE_PRIVS` this service account is not granted.

    Letting it escape would abort the survey and take every finding gathered so
    far with it, which is the opposite of what a run asking "tell me everything
    first" wants. It blocks, unlike the unreadable privilege audit, because it is
    the input guardrail 4 refuses on: treating an unreadable answer as "holds no
    admin role" is the silent success that error exists to prevent.
    """
    estate(
        describe_error=RolesUnreadableError(
            'could not read the roles held by "acme_web_user"',
            hint="GRANT SELECT ON SYS.DBA_ROLE_PRIVS to the service account",
        ),
        audits={"appdb-alpha": PrivilegeAudit(missing=("GRANT ALTER USER",))},
    )

    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--preflight",
        "--output",
        "json",
    )
    found = document(result)

    assert found["exit_code"] == ExitCode.FAILURE
    # Both findings survive: the survey did not stop at the one that raised.
    messages = str(found["diagnostics"])
    assert "could not read the roles" in messages
    assert "GRANT ALTER USER" in messages


def test_every_problem_is_reported_rather_than_the_first(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A pre-flight exists so an estate can be fixed in one pass; reporting only
    the one that refused would turn a survey into a round trip per problem."""
    estate(
        audits={
            "appdb-alpha": PrivilegeAudit(missing=("GRANT ALTER USER",)),
            "appdb-beta": PrivilegeAudit(missing=("GRANT CREATE SESSION",)),
        }
    )

    result = run(runner, write_config(CONFIG), "--preflight")

    assert "GRANT ALTER USER" in result.output
    assert "GRANT CREATE SESSION" in result.output
    assert "2 problems over 2 targets" in result.output


def test_two_accounts_sharing_a_document_promote_together(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Q7's default layout: one write, one version, both accounts."""
    harness = estate(
        documents={
            "apps/acme/db": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
                "pending": {"acme_web_user": STAGED, "acme_batch_user": STAGED},
            }
        },
        users={"ACME_WEB_USER": user(), "ACME_BATCH_USER": user("ACME_BATCH_USER")},
        answers={"ACME_WEB_USER": drifted(), "ACME_BATCH_USER": drifted()},
    )
    before = harness["store"].read("apps/acme/db").version
    result = run(runner, write_config(SHARED_CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["store"].read("apps/acme/db").version == before + 1
    assert stored(harness["store"], "apps/acme/db")["pending"] == {}


def test_one_account_failing_holds_back_its_sibling_too(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """They share a document, so they share its commit. Promoting one and not the
    other would need two writes and would leave a document nobody intended."""
    harness = estate(
        documents={
            "apps/acme/db": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
                "pending": {"acme_web_user": STAGED, "acme_batch_user": STAGED},
            }
        },
        users={"ACME_WEB_USER": user(), "ACME_BATCH_USER": None},
        answers={"ACME_WEB_USER": drifted()},
    )
    result = run(runner, write_config(SHARED_CONFIG))

    assert result.exit_code == ExitCode.PARTIAL
    assert stored(harness["store"], "apps/acme/db")["pending"]["acme_web_user"] == STAGED


# -------------------------------------------------------------- the failures ---


def test_an_unreachable_target_is_a_finding_and_not_a_crash(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """And it means something stronger here than in `check`: a database that
    could not be reached cannot cause a password it does not have to be
    advertised."""
    harness = estate(connect_error=RuntimeError("ORA-12541: no listener"))
    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.FAILURE
    assert "ORA-12541" in result.output
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]


def test_a_refused_statement_is_reported_per_account(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """ORA-28003 and friends: the server refused the password, and this estate is
    one where it cannot be replaced.

    **This test used to assert that `apply` never redraws**, which #268 reversed
    and #312 built. It still asserts a refusal that stands, and now for the reason
    that survives that decision rather than the one that did not: `CONFIG`
    declares no policy and its documents carry no `origin`, so there is nothing to
    draw from and no evidence the tool drew what is staged. Both are refusals
    `may_redraw` makes, and either alone is enough.

    The error is built through the real classification, because
    `DriverError.regenerate` is what a redraw turns on -- a bare exception
    carrying the same text answers `False`, and this would pass without ever
    reaching the decision.
    """
    harness = estate(set_error=refusal())
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.FAILURE
    assert "ORA-28003" in result.output
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]["acme_web_user"] == STAGED


def test_readonly_refuses_before_anything_connects(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 10's ratchet, and invariant 4's timing.

    **`readonly` is set in the file**, which is the only place it can be set.
    This passed `--readonly` until #292, and there is no such option -- so click
    refused the argv, the command never ran, and the two assertions below were
    satisfied by a usage error. It would have passed with `refuse_if_readonly`
    deleted. Caught while wiring up `confirm_environments`, which is the same
    defect one layer along: a guard that looks enforced and is not.
    """
    harness = estate()
    result = run(
        runner,
        write_config(CONFIG + "defaults:\n  safety:\n    readonly: true\n"),
    )

    assert isinstance(result.exception, RefusedError)
    assert "safety.readonly" in str(result.exception)
    assert harness["sessions"] == []


def test_readonly_on_a_target_refuses_before_anything_connects(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The same guard, from the layer that was parsed and read by nothing (#424).

    `appdb-alpha` carried `safety: { readonly: true }` and the run applied a
    password to it -- the plan printed, the store was read, the database was
    reached. The refusal has to arrive at *plan* time, which is why the session
    list is asserted: a readonly target discovered while the estate is being
    walked is exactly the generic mid-execution failure invariant 4 forbids.
    """
    harness = estate()
    result = run(
        runner,
        write_config(
            CONFIG.replace(
                "    labels: { env: prod, tenant: alpha }",
                "    labels: { env: prod, tenant: alpha }\n    safety: { readonly: true }",
            )
        ),
    )

    assert isinstance(result.exception, RefusedError)
    assert "1 of the 2 targets it reaches" in str(result.exception)
    assert "appdb-alpha (targets[0].safety.readonly)" in (result.exception.hint or "")
    assert harness["sessions"] == []


def test_a_run_narrowed_past_a_readonly_target_proceeds(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#424 refuses the whole run rather than skipping the marked targets, so the
    narrowing the message offers has to actually work. If it did not, the refusal
    would be handing the operator advice the tool cannot honour."""
    estate(documents={"apps/acme/appdb-beta": {"pending": {"acme_web_user": STAGED}}})
    result = run(
        runner,
        write_config(
            CONFIG.replace(
                "    labels: { env: prod, tenant: alpha }",
                "    labels: { env: prod, tenant: alpha }\n    safety: { readonly: true }",
            )
        ),
        "--select",
        "tenant=beta",
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert "appdb-beta" in result.output


def test_readonly_on_a_group_refuses_and_names_the_key(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A whole population marked in one place, which is what §3a says a group's
    block is for. A group has no key of its own to point a target at, so the
    message pairs the target with the group's key."""
    harness = estate()
    result = run(
        runner,
        write_config(
            CONFIG + "groups:\n  prod-pdbs:\n    match: { env: prod }\n"
            "    safety: { readonly: true }\n"
        ),
    )

    assert isinstance(result.exception, RefusedError)
    assert "every target it reaches" in str(result.exception)
    assert "groups.prod-pdbs.safety.readonly" in (result.exception.hint or "")
    assert harness["sessions"] == []


def test_max_targets_on_a_target_bounds_the_run(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The ceiling was inert at this layer for the same reason `readonly` was, and
    #424 asked that it be measured rather than assumed."""
    harness = estate()
    result = run(
        runner,
        write_config(
            CONFIG.replace(
                "    labels: { env: prod, tenant: alpha }",
                "    labels: { env: prod, tenant: alpha }\n    safety: { max_targets: 1 }",
            )
        ),
    )

    assert isinstance(result.exception, RefusedError)
    assert "would reach 2 targets" in str(result.exception)
    assert "targets[0].safety.max_targets" in (result.exception.hint or "")
    assert harness["sessions"] == []


# ------------------------------------------------------- the lockout budget ---


def test_both_logins_are_budgeted_up_front(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §7 mitigation 1 counts attempts per *run*. Asking for one and then
    asking again would let a run spend two on a counter the guard was protecting
    from spending two."""
    harness = estate()
    run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].budgets == [2, 2]


def test_a_declined_pre_flight_still_applies(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The guard declining means the run cannot tell whether a change is needed,
    and `ALTER USER` is not a login -- so applying converges and costs the
    counter nothing."""
    harness = estate(
        answers={
            "ACME_WEB_USER": [
                VerifyResult(VERIFY_LOGIN, SKIPPED, detail="within 2 of the limit"),
                VerifyResult(VERIFY_LOGIN, PASS, latency_ms=9),
            ]
        }
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].changed == [("ACME_WEB_USER", STAGED)]
    assert result.exit_code == ExitCode.SUCCESS


# --------------------------------------------------------------- the strategy ---


def rollover_user(name: str = "ACME_WEB_USER") -> UserState:
    """An account whose profile grants a window."""
    return user(name, profile="APP_PROFILE", rollover_enabled=True, rollover_time="1")


def applying(harness: dict[str, Any]) -> Any:
    """The session that did the work.

    Not `sessions[0]`: an explicit `--strategy` surveys the estate first, so the
    first session per target is the pre-flight and it changes nothing by
    construction. Asserting on it would pass for the wrong reason.
    """
    return harness["sessions"][-1]


def test_rollover_is_the_default_where_the_estate_allows_it(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §6.3, and no flag needed: both passwords authenticate afterwards, so
    the run reports `ROLLOVER_ACTIVE` rather than `IN_SYNC`."""
    harness = estate(
        users={"ACME_WEB_USER": rollover_user()},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert check.ROLLOVER_ACTIVE in result.output
    assert harness["sessions"][0].finished == []


def test_the_window_is_reported_with_the_profile_that_grants_it(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`active` alone leaves a consumer inferring the deadline from a word, and
    `profile_rollover_time` is what says whether this was the regime asked for or
    the only one available."""
    estate(
        users={"ACME_WEB_USER": rollover_user()},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")

    rollover = document(result)["results"][0]["rollover"]
    assert rollover["active"] is True
    assert rollover["profile_rollover_time"] == "1"


def test_direct_closes_the_window_it_opened(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The difference between "the old password stops working in an hour" and
    "the old password stopped working just now"."""
    harness = estate(
        users={"ACME_WEB_USER": rollover_user()},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--strategy", "direct")

    assert applying(harness).finished == ["ACME_WEB_USER"]
    assert check.IN_SYNC in result.output
    assert "no longer works" in result.output


def test_direct_does_not_close_a_window_it_could_not_confirm(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Closing it on an unverified change leaves an account whose old password
    has stopped working and whose new one is not known to work -- the one state
    worse than the grace period `direct` exists to avoid."""
    harness = estate(
        users={"ACME_WEB_USER": rollover_user()},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
        answers={
            "ACME_WEB_USER": [
                VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017"),
                VerifyResult(VERIFY_LOGIN, SKIPPED, detail="within 2 of the limit"),
            ]
        },
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--strategy", "direct")

    assert applying(harness).changed
    assert applying(harness).finished == []
    assert result.exit_code != ExitCode.SUCCESS


def test_direct_against_a_plain_profile_closes_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The change was already immediate. A statement to prove it would have no
    work in it."""
    harness = estate(capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}))
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--strategy", "direct")

    assert applying(harness).finished == []
    assert result.exit_code == ExitCode.SUCCESS


def test_staged_against_a_rollover_profile_is_refused_before_anything_changes(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Oracle opens the window because the profile says so. Running anyway and
    reporting `staged` would tell an application team the old password had
    stopped working when it had not."""
    harness = estate(
        users={"ACME_WEB_USER": rollover_user()},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--strategy", "staged")

    assert result.exit_code != ExitCode.SUCCESS
    assert all(session.changed == [] for session in harness["sessions"])
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]


def test_an_unhonourable_strategy_stops_the_whole_estate(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 4, and the reason the pre-flight pays for a second connection:
    naming a regime is asking for a property of the *estate*, and honouring it on
    one PDB before discovering the second cannot would already have broken it."""
    harness = estate(
        users={"ACME_WEB_USER": rollover_user()},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
    )
    run(runner, write_config(CONFIG), "--strategy", "staged")

    assert all(session.changed == [] for session in harness["sessions"])
    for target in ("appdb-alpha", "appdb-beta"):
        assert stored(harness["store"], f"apps/acme/{target}")["pending"]


def test_the_default_strategy_costs_no_extra_connection(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The pre-flight is what `--strategy` buys and what it costs. With no flag
    there is nothing to refuse -- the regime is chosen per account from what that
    account can do -- so the run opens one session per target and no more."""
    harness = estate()
    run(runner, write_config(CONFIG))

    assert len(harness["sessions"]) == 2


def test_an_explicit_strategy_surveys_first(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Two sessions per target: one that clears the estate, one that changes it."""
    harness = estate(capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}))
    run(runner, write_config(CONFIG), "--strategy", "staged")

    assert len(harness["sessions"]) == 4


def test_a_capability_refusal_carries_invariant_4s_own_exit_code(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, validator: Any
) -> None:
    """Invariant 4: a distinct exit code, and a message naming the capability and
    the target.

    It was neither until #287. Every `DriverError` fell into the boundary's
    catch-all and came out as `internal` on exit 1, with the hint folded into a
    message prefixed by the exception's class name -- so the one refusal in this
    tool that has its own exit code did not use it, and `target_capability` had
    never been emitted at all.
    """
    estate(users={"ACME_WEB_USER": rollover_user()}, capabilities=frozenset({PASSWORD_ROLLOVER}))

    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--strategy",
        "direct",
        "--output",
        "json",
    )
    found = document(result)

    validator.validate(found)
    assert found["exit_code"] == ExitCode.UNSUPPORTED_CAPABILITY
    assert found["error"]["category"] == "capability"
    assert found["error"]["target_capability"] == EXPIRE_PASSWORD
    # The hint is its own field, and the message is the driver's own wording --
    # not `str(exc)` with the two run together, and not the class name in front.
    assert found["error"]["hint"]
    assert not found["error"]["message"].startswith("DriverError")


def test_a_configuration_refusal_is_a_database_error_and_not_internal(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The other half of #287: a refusal with no capability behind it is still the
    driver's, and `internal` means *this is a bug in sopuli* to whoever reads it.
    """
    estate(
        users={"ACME_WEB_USER": rollover_user()},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
    )

    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--strategy",
        "staged",
        "--output",
        "json",
    )
    found = document(result)

    assert found["exit_code"] == ExitCode.FAILURE
    assert found["error"]["category"] == "database"
    assert "target_capability" not in found["error"]


def test_rollover_is_refused_through_the_driver(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`require_rollover` owns both of its refusals (#181) and carries the exact
    `ALTER PROFILE` for the profile one. The command routes to it rather than
    restating either."""
    harness = estate(
        rollover_refusal=RuntimeError("profile APP_PROFILE grants no rollover window"),
    )
    result = run(runner, write_config(CONFIG), "--strategy", "rollover")

    assert result.exit_code != ExitCode.SUCCESS
    assert all(session.changed == [] for session in harness["sessions"])


def test_an_unreachable_target_is_not_a_strategy_problem(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The pre-flight skips it, and the run reports it per account with the
    vendor code -- which is a different thing to go and fix."""
    estate(connect_error=RuntimeError("ORA-12541: no listener"), capabilities=frozenset())
    result = run(runner, write_config(CONFIG), "--strategy", "staged")

    assert "ORA-12541" in result.output
    assert result.exit_code == ExitCode.FAILURE


def test_a_missing_account_does_not_refuse_the_estate_over_a_strategy(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`ACCOUNT_MISSING` is a state the run reports per account. The driver's
    `require_rollover` raises for one, having no way to know this caller would
    rather skip it, so the pre-flight has to check before asking -- otherwise an
    account the run was going to report on anyway takes the whole estate down."""
    harness = estate(users={})
    result = run(runner, write_config(CONFIG), "--strategy", "rollover")

    assert check.ACCOUNT_MISSING in result.output
    assert result.exit_code == ExitCode.FAILURE
    assert all(session.changed == [] for session in harness["sessions"])


# ------------------------------------------------------------- the rollback ---


def _rolled() -> dict[str, dict[str, Any]]:
    """A finished rotation with a `previous` to go back to."""
    return {
        "apps/acme/appdb-alpha": {
            "DB_CREDENTIALS": {"acme_web_user": LIVE},
            "previous": {"acme_web_user": "The-One-Before-2025"},
        }
    }


def test_a_rollback_puts_previous_back_and_swaps_the_vault(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """UC-1 §8's escape hatch. The estate ends consistent: `current` holds what
    the database now has, `previous` holds what was taken off it."""
    harness = estate(
        documents=_rolled(),
        answers={"ACME_WEB_USER": drifted()},
    )
    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--source",
        "previous",
        "--confirm",
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["sessions"][0].changed == [("ACME_WEB_USER", "The-One-Before-2025")]
    body = stored(harness["store"], "apps/acme/appdb-alpha")
    assert body["DB_CREDENTIALS"]["acme_web_user"] == "The-One-Before-2025"
    assert body["previous"]["acme_web_user"] == LIVE


def test_the_rollback_verdict_says_rolled_back(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The two runs are indistinguishable otherwise, and one of them moved an
    estate backwards on purpose."""
    estate(documents=_rolled(), answers={"ACME_WEB_USER": drifted()})
    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--source",
        "previous",
        "--confirm",
    )

    assert "1 rolled back" in result.output


def test_a_rollback_without_confirm_is_refused(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The one invocation whose *success* stops an application's credential
    working. A closed stdin is a refusal rather than a prompt that reads EOF."""
    harness = estate(documents=_rolled())
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--source", "previous")

    assert harness["sessions"] == []
    assert result.exit_code != ExitCode.SUCCESS


def test_a_rollback_with_no_previous_says_so(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Bounded to one generation (Q3, #84), so there is nothing to run and the
    message must not say `creds generate`."""
    harness = estate(
        documents={"apps/acme/appdb-alpha": {"DB_CREDENTIALS": {"acme_web_user": LIVE}}}
    )
    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--source",
        "previous",
        "--confirm",
    )

    assert harness["sessions"][0].changed == []
    assert "nothing to roll back to" in result.output
    assert result.exit_code == ExitCode.FAILURE


def test_a_rollback_under_a_rotation_in_flight_is_refused(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The `pending` would survive, and the next `apply` would move the estate
    forward with it -- undoing the undo, unattended."""
    harness = estate(
        documents={
            "apps/acme/appdb-alpha": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE},
                "pending": {"acme_web_user": STAGED},
                "previous": {"acme_web_user": "The-One-Before-2025"},
            }
        }
    )
    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--source",
        "previous",
        "--confirm",
    )

    assert harness["sessions"][0].changed == []
    assert "PENDING_APPLY" in result.output
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]["acme_web_user"] == STAGED


def test_a_rollback_dry_run_needs_no_confirmation(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A preview an operator has to authorise is a preview they will stop
    taking."""
    harness = estate(documents=_rolled())
    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--source",
        "previous",
        "--dry-run",
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert "previous" in result.output
    assert harness["sessions"] == []


# ------------------------------------------------------ the other two stages ---


def test_source_current_ignores_a_staged_pending(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The case for the flag: a staged password turns out to be wrong, and the
    estate goes back on what applications are actually reading -- without
    discarding the `pending`."""
    harness = estate(
        documents={
            "apps/acme/appdb-alpha": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE},
                "pending": {"acme_web_user": STAGED},
            }
        },
        answers={"ACME_WEB_USER": drifted()},
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--source", "current")

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["sessions"][0].changed == [("ACME_WEB_USER", LIVE)]
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]["acme_web_user"] == STAGED


def test_source_pending_does_not_fall_back_to_current(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """An explicit stage that holds nothing is a run that did not do what it was
    asked, and it must not quietly do something else."""
    harness = estate(
        documents={"apps/acme/appdb-alpha": {"DB_CREDENTIALS": {"acme_web_user": LIVE}}}
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--source", "pending")

    assert harness["sessions"][0].changed == []
    assert result.exit_code == ExitCode.FAILURE
    assert "creds generate" in result.output


# ------------------------------------------------ the redraw (#312, #268) ---


def test_a_refused_password_is_replaced_and_the_run_succeeds(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#268's decision, end to end. The server refuses the staged value once;
    the run draws another, stages it, applies it, and promotes that.

    This is the case UC-1 §6.4 was written for and the one `apply` used to answer
    with "go and run `creds generate` again, and hope".
    """
    harness = estate(documents=staged(), set_error=refusal(), refusals=1)

    result = run(runner, write_config(REDRAW_CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    document = stored(harness["store"], REDRAW_DOCUMENT)
    # Promoted, so `pending` is cleared -- and what `current` holds is neither
    # the refused value nor the one the run started with.
    assert document["DB_CREDENTIALS"]["acme_web_user"] not in (LIVE, STAGED)
    assert document["pending"] == {}


def test_every_target_of_a_redrawn_account_gets_the_new_password(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The reason a redraw is not a retry of the target that refused.

    One account, two targets, one document, one password. The first target took
    the staged value and the second refused it -- so both are applied again with
    the replacement, and the estate ends holding one password rather than two.
    """
    harness = estate(documents=staged(), set_error=refusal(), refusals=1)

    run(runner, write_config(REDRAW_CONFIG))

    promoted = stored(harness["store"], REDRAW_DOCUMENT)["DB_CREDENTIALS"]["acme_web_user"]
    issued = [secret for session in harness["sessions"] for _, secret in session.changed]
    # The last statement each target received carried the promoted value.
    assert issued[-2:] == [promoted, promoted]


def test_the_redraw_is_reported_on_the_row_and_in_the_diagnostics(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Never quietly. A redraw changes what the vault holds, so a run that did it
    silently would leave anything holding the old `pending` stale with no record
    of when it stopped being current."""
    estate(documents=staged(), set_error=refusal(), refusals=1)

    result = run(runner, write_config(REDRAW_CONFIG), "--output", "json")
    emitted = document(result)

    assert all(entry["redraws"] == 1 for entry in emitted["results"])
    warned = [one for one in emitted.get("diagnostics", []) if one["code"] == "password_redrawn"]
    assert len(warned) == 1
    assert "ORA-28003" in warned[0]["message"]


def test_an_ordinary_run_carries_no_redraws_field(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The field records redraws, not the budget for them: a `0` on every row of
    every ordinary run would bury the rows that carry one."""
    estate(documents=staged())

    emitted = document(run(runner, write_config(REDRAW_CONFIG), "--output", "json"))

    assert all("redraws" not in entry for entry in emitted["results"])


def test_a_supplied_password_is_reported_and_never_replaced(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#311's whole purpose. An external system dictated this value, so the run
    reports the refusal and leaves `pending` exactly as it found it."""
    harness = estate(documents=staged(origin="supplied"), set_error=refusal(), refusals=1)

    result = run(runner, write_config(REDRAW_CONFIG), "--output", "json")

    assert result.exit_code != ExitCode.SUCCESS
    assert stored(harness["store"], REDRAW_DOCUMENT)["pending"]["acme_web_user"] == STAGED
    declined = [
        one
        for one in document(result).get("diagnostics", [])
        if one["code"] == "password_not_redrawn"
    ]
    assert len(declined) == 1
    assert "did not draw" in declined[0]["message"]


def test_a_document_with_no_origin_is_not_redrawn(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Staged before #311 existed, which is the supplied case without the
    evidence. Guessing wrong here overwrites a dictated password, and the next
    `creds generate` heals it."""
    harness = estate(documents=staged(origin=None), set_error=refusal(), refusals=1)

    result = run(runner, write_config(REDRAW_CONFIG), "--output", "json")

    assert stored(harness["store"], REDRAW_DOCUMENT)["pending"]["acme_web_user"] == STAGED
    declined = [
        one
        for one in document(result).get("diagnostics", [])
        if one["code"] == "password_not_redrawn"
    ]
    assert "no record" in declined[0]["message"]


def test_a_server_that_refuses_everything_stops_at_the_budget(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A verify function this policy cannot satisfy. Three draws describe the
    target's rules rather than the draw, and the fourth learns nothing -- so the
    run stops and hands back the server's own message.

    The count is on `set_password` calls across every target, which is what a
    bounded loop has to be asserted on: an unbounded one passes every assertion
    about the exit code and hangs.
    """
    harness = estate(documents=staged(), set_error=refusal())

    result = run(runner, write_config(REDRAW_CONFIG), "--output", "json")

    assert result.exit_code != ExitCode.SUCCESS
    asked = [one for session in harness["sessions"] for one in session.attempted]
    # Two targets, three draws, and nothing beyond that. Asserted on the
    # statements the server was asked for rather than on the ones that landed:
    # none of these landed, and an unbounded loop would have issued them for ever.
    assert len(asked) == 2 * apply.DRAW_LIMIT
    assert len({secret for _, secret in asked}) == apply.DRAW_LIMIT
    assert "ORA-28003" in result.output
    assert stored(harness["store"], REDRAW_DOCUMENT)["pending"]["acme_web_user"] != STAGED


def test_each_draw_is_a_different_password(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#172's rule that the same value is never sent again: `ORA-28007` means
    this exact password is refused, so retrying it is the one thing certain not
    to work."""
    harness = estate(documents=staged(), set_error=refusal())

    run(runner, write_config(REDRAW_CONFIG))

    presented = [secret for session in harness["sessions"] for _, secret in session.attempted]
    assert len(set(presented)) == apply.DRAW_LIMIT
    # The value the run arrived with is drawn once and never sent again.
    assert presented.count(STAGED) == 2


def test_an_error_that_is_not_a_refusal_never_redraws(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """§6.4's rule for an unmapped code, reached through the whole command: the
    password was not the problem, so drawing another would change the vault on
    the strength of a guess."""
    harness = estate(documents=staged(), set_error=refusal("ORA-00600"))

    result = run(runner, write_config(REDRAW_CONFIG), "--output", "json")

    assert stored(harness["store"], REDRAW_DOCUMENT)["pending"]["acme_web_user"] == STAGED
    assert not [
        one for one in document(result).get("diagnostics", []) if one["code"] == "password_redrawn"
    ]


def test_an_account_with_no_policy_reports_rather_than_raising(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Drawing needs a policy and §8 refuses to invent one -- but this run was
    applying happily until the server refused a value, and turning that into a
    configuration error would replace a report of what the estate did with a
    complaint about a file nothing had changed."""
    harness = estate(documents=staged(), set_error=refusal(), refusals=1)
    without = REDRAW_CONFIG.replace("defaults:\n  policy: app-standard\n", "")

    result = run(runner, write_config(without), "--output", "json")

    assert result.exit_code != ExitCode.CONFIG_INVALID
    assert stored(harness["store"], REDRAW_DOCUMENT)["pending"]["acme_web_user"] == STAGED
    declined = [
        one
        for one in document(result).get("diagnostics", [])
        if one["code"] == "password_not_redrawn"
    ]
    assert "no password policy" in declined[0]["message"]


# ------------------------------------------------------ --repair (#391) ---


def _run_document(config: Path, results: list[dict[str, Any]]) -> dict[str, Any]:
    """A `creds check` document over `config`, carrying `results`.

    Built rather than captured, because what is under test is the *filter* and a
    captured document would tie these tests to whatever the estate happened to
    report. The one field that has to be real is `invocation.config_files`: the
    estate check compares it against what this run loaded (#402).
    """
    return {
        "schema_version": "1.20",
        "command": "creds.check",
        "invocation": {"correlation_id": "x", "dry_run": False, "config_files": [str(config)]},
        "results": results,
        "exit_code": 3,
    }


def _repair_file(tmp_path: Path, config: Path, results: list[dict[str, Any]]) -> Path:
    path = tmp_path / "previous.json"
    path.write_text(json.dumps(_run_document(config, results)), encoding="utf-8")
    return path


def test_repair_narrows_to_the_pairs_that_did_not_confirm(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, tmp_path: Path
) -> None:
    """The whole point of the flag: one login instead of two.

    `SHARED_CONFIG` puts two accounts in one document, and the previous run
    confirmed one of them. Asserted on what the session was asked to change,
    not on the summary -- a command can report the right count and still have
    dialled the target it was supposed to skip.
    """
    harness = estate(
        documents={
            "apps/acme/db": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
                "pending": {"acme_web_user": STAGED, "acme_batch_user": STAGED},
            }
        },
        users={"ACME_WEB_USER": user(), "ACME_BATCH_USER": user("ACME_BATCH_USER")},
        answers={"ACME_WEB_USER": drifted(), "ACME_BATCH_USER": drifted()},
    )
    config = write_config(SHARED_CONFIG)
    previous = _repair_file(
        tmp_path,
        config,
        [
            {"account": "acme_web_user", "target": "appdb-alpha", "state": "IN_SYNC"},
            {"account": "acme_batch_user", "target": "appdb-alpha", "state": "DRIFT"},
        ],
    )

    result = run(runner, config, "--repair", str(previous))

    assert result.exit_code == ExitCode.SUCCESS
    changed = [name for session in harness["sessions"] for name, _ in session.changed]
    assert changed == ["ACME_BATCH_USER"]


def test_repair_cannot_extend_the_declared_set(  # invariant 5
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, tmp_path: Path
) -> None:
    """A pair the document names and the config does not is dropped, not acted
    on -- and `--force` has nothing to say about it, because the whitelist is
    the one guardrail it never overrides."""
    estate(
        documents={
            "apps/acme/db": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
                "pending": {"acme_web_user": STAGED, "acme_batch_user": STAGED},
            }
        },
        users={"ACME_WEB_USER": user(), "ACME_BATCH_USER": user("ACME_BATCH_USER")},
        answers={"ACME_WEB_USER": drifted(), "ACME_BATCH_USER": drifted()},
    )
    config = write_config(SHARED_CONFIG)
    previous = _repair_file(
        tmp_path,
        config,
        [{"account": "gone_user", "target": "appdb-alpha", "state": "DRIFT"}],
    )

    result = run(runner, config, "--repair", str(previous), "--force")

    assert result.exit_code == ExitCode.SUCCESS
    assert "nothing to apply" in result.output


def test_repair_combines_with_the_other_selectors_as_and(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, tmp_path: Path
) -> None:
    """Every selector narrows and none extends, so a pair the document names on
    a target `--select` excluded is not reached."""
    estate()
    config = write_config(CONFIG)
    previous = _repair_file(
        tmp_path,
        config,
        [{"account": "acme_web_user", "target": "appdb-beta", "state": "DRIFT"}],
    )

    result = run(runner, config, "--repair", str(previous), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.SUCCESS
    assert "nothing to apply" in result.output


def test_a_document_from_another_estate_is_refused_before_any_target(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, tmp_path: Path
) -> None:
    """Exit 2 and no document, like every other selector that does not resolve.

    Asserted on the sessions as well as the exit code: "before a target is
    dialled" is the property #264 asked for, and an exit code alone does not
    show it.
    """
    harness = estate()
    config = write_config(CONFIG)
    previous = _repair_file(
        tmp_path,
        tmp_path / "somewhere-else.yaml",
        [{"account": "acme_web_user", "target": "appdb-alpha", "state": "DRIFT"}],
    )

    result = run(runner, config, "--repair", str(previous))

    assert isinstance(result.exception, ArgumentError)
    assert result.exception.exit_code == ExitCode.USAGE
    assert "different configuration" in str(result.exception)
    assert harness["sessions"] == []


def test_a_refused_repair_writes_no_document(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, tmp_path: Path
) -> None:
    """J7's rule: exit 2 is the only code that never produces one, and it stays
    usable as a consumer rule only if nothing puts a document on it."""
    estate()
    config = write_config(CONFIG)
    previous = _repair_file(tmp_path, tmp_path / "elsewhere.yaml", [])

    result = run(runner, config, "--repair", str(previous), "--output", "json")

    assert isinstance(result.exception, ArgumentError)
    assert result.exception.exit_code == ExitCode.USAGE
    assert result.stdout == ""


def test_a_stale_document_warns_and_proceeds(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, tmp_path: Path
) -> None:
    """Not a gate. The run does the work and says how old its instructions were
    -- printed as well as serialised, on #309's rule."""
    estate(
        documents={
            "apps/acme/db": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
                "pending": {"acme_web_user": STAGED, "acme_batch_user": STAGED},
            }
        },
        users={"ACME_WEB_USER": user(), "ACME_BATCH_USER": user("ACME_BATCH_USER")},
        answers={"ACME_WEB_USER": drifted(), "ACME_BATCH_USER": drifted()},
    )
    config = write_config(SHARED_CONFIG)
    body = _run_document(
        config, [{"account": "acme_batch_user", "target": "appdb-alpha", "state": "DRIFT"}]
    )
    body["invocation"]["finished_at"] = to_rfc3339(utc_now() - timedelta(days=9))
    previous = tmp_path / "old.json"
    previous.write_text(json.dumps(body), encoding="utf-8")

    result = run(runner, config, "--repair", str(previous))

    assert result.exit_code == ExitCode.SUCCESS
    assert "9 days old" in result.output


def test_a_stale_document_carries_its_code_into_the_document(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
    tmp_path: Path,
) -> None:
    estate(
        documents={
            "apps/acme/db": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
                "pending": {"acme_web_user": STAGED, "acme_batch_user": STAGED},
            }
        },
        users={"ACME_WEB_USER": user(), "ACME_BATCH_USER": user("ACME_BATCH_USER")},
        answers={"ACME_WEB_USER": drifted(), "ACME_BATCH_USER": drifted()},
    )
    config = write_config(SHARED_CONFIG)
    body = _run_document(
        config, [{"account": "acme_batch_user", "target": "appdb-alpha", "state": "DRIFT"}]
    )
    body["invocation"]["finished_at"] = to_rfc3339(utc_now() - timedelta(days=9))
    previous = tmp_path / "old.json"
    previous.write_text(json.dumps(body), encoding="utf-8")

    result = run(runner, config, "--repair", str(previous), "--output", "json")

    found = document(result)
    assert not list(validator.iter_errors(found))
    assert [one["code"] for one in found["diagnostics"]] == [REPAIR_DOCUMENT_STALE]


def test_the_blast_radius_counts_the_narrowed_run(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, tmp_path: Path
) -> None:
    """`max_targets` and `confirm_environments` read the plan, so the filter has
    to run before it -- a repair of one pair that asked for confirmation of the
    whole estate would be asking about work it is not going to do."""
    estate()
    config = write_config(CONFIG)
    previous = _repair_file(
        tmp_path,
        config,
        [{"account": "acme_web_user", "target": "appdb-alpha", "state": "DRIFT"}],
    )

    result = run(runner, config, "--repair", str(previous), "--output", "json")

    assert document(result)["plan"]["blast_radius"]["targets"] == 1

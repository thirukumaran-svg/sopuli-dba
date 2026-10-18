"""``sopuli creds apply`` end to end, without a database.

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
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator

from sopuli import apply, check
from sopuli.admin import Resolved
from sopuli.cli import _Applied, _left_out, _splice, cli
from sopuli.clock import to_rfc3339, utc_now
from sopuli.config.errors import ArgumentError
from sopuli.config.loading import build_config
from sopuli.config.model import Vault
from sopuli.config.targets import EXTERNAL
from sopuli.diagnostics import (
    CHANGED_NOT_PROMOTED,
    LOCK_TAKEN_OVER,
    PRIVILEGE_AUDIT_UNREAD,
    PROFILE_UNREAD,
    PROMOTION_FAILED,
    PROMOTION_WITHHELD,
    REPAIR_DOCUMENT_STALE,
)
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
    Credential,
    DriverError,
    Encryption,
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
from sopuli.output.emit import EVENT_SCHEMA_VERSION
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

#: The same estate, opted in to UC-1 §5's account unlock. Opt-in is the
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
#: puts a second account behind the fence: the fence is checked once per account,
#: so an account after the first in the same target is one the run reaches with a
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

#: The same estate, with a profile that narrows both database budgets.
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

#: The same estate, with the standing permission for an unattended runner
#: (`locking.break_expired`, `01-configuration.md`). Config-only by design --
#: there is no flag and no environment variable -- so a test about it is a test
#: about the file.
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

#: The same estate again, opted in to §5's profile assignment (decision #301). The
#: profile is one `FakeSession` knows about; `MISSING_PROFILE_CONFIG` names one no
#: database has.
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
#: from. That combination matters: a refusal on the second target has to
#: restage the account and re-apply the first as well, or the promotion
#: advertises a password half the estate does not hold.
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

#: `REDRAW_CONFIG` with a label per target, so a `--select` can narrow inside the
#: one document both targets share.
LABELLED_SHARED_CONFIG = REDRAW_CONFIG.replace(
    "    dsn: db-prod.example.com:1521/alpha.pdb.example.com\n",
    "    dsn: db-prod.example.com:1521/alpha.pdb.example.com\n    labels: { tenant: alpha }\n",
).replace(
    "    dsn: db-prod.example.com:1521/beta.pdb.example.com\n",
    "    dsn: db-prod.example.com:1521/beta.pdb.example.com\n    labels: { tenant: beta }\n",
)

#: The document `REDRAW_CONFIG` writes, staged the way `generate` leaves it.
REDRAW_DOCUMENT = "apps/acme/db"


def staged(origin: str | None = "generated") -> dict[str, dict[str, Any]]:
    """One shared document, optionally carrying the provenance key."""
    body: dict[str, Any] = {
        "DB_CREDENTIALS": {"acme_web_user": LIVE},
        "pending": {"acme_web_user": STAGED},
    }
    if origin is not None:
        body["origin"] = {"acme_web_user": origin}
    return {REDRAW_DOCUMENT: body}


#: What the driver raises when the server refuses the *value* -- built through
#: the real classification rather than as a bare exception, because
#: `DriverError.regenerate` is what decides whether a redraw happens at all.
#: A `RuntimeError` carrying the same text answers `False` and would make
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


#: An encrypted connection, the fakes' default, so SOPULI-W031/W032 appear only
#: in the tests about them.
TLS = Encryption(method="tls", protocol="tcps")


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
        encryption: Encryption = TLS,
        audit: PrivilegeAudit | Exception | None = None,
        describe_error: Exception | None = None,
        profile_error: Exception | None = None,
    ) -> None:
        self.profile_error = profile_error
        self.describe_error = describe_error
        self.on_call = on_call
        self.given_scope = scope
        self.encryption = encryption
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
            return replace(
                self.given_scope, capabilities=self.capabilities, encryption=self.encryption
            )
        return Scope(
            type="pdb",
            container="ALPHA",
            read_write=True,
            capabilities=self.capabilities,
            encryption=self.encryption,
        )

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
        self._called("apply_attributes")
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
        # anything else, so this one does too -- otherwise the pre-flight
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
        # statements the server was *asked* for: an unbounded loop issues
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

        Three seams, one hook, because what separates the cases is only *when*
        it fires: before this session's first `describe_user`, nothing has been
        applied anywhere; after `apply_attributes`, an account may have been
        unlocked; after a `set_password`, one database has been changed. Hooked
        here rather than by patching `LockManager`, so the test exercises the
        real fence -- the record on the path really is somebody else's by the
        next check.
        """
        if self.on_call is not None:
            self.on_call(event)

    def close(self) -> None:
        self.closed = True


def user(name: str = "ACME_WEB_USER", **fields: Any) -> UserState:
    """One account as the database describes it.

    ``password_file_member`` defaults to ``False`` -- *asked and answered* -- so
    that a case about something else is not also a case about guardrail 3 having
    no input. The estate that cannot answer it belongs in
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
        encryption: Encryption = TLS,
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
        # redraw meets once it reconnects.
        budget = None if refusals is None else iter([True] * refusals)

        def fake_connect(
            vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
        ) -> SecretStore:
            return store

        class FakeDriver:
            def __init__(self, **kwargs: Any) -> None:
                # Recorded so a test can assert what the *command* handed the
                # driver (decision #360). The session fake below cannot see it:
                # `timeouts` is settled at construction and never reaches a
                # statement.
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
                    encryption=encryption,
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


def _staged_two_targets() -> dict[str, dict[str, Any]]:
    return {
        f"apps/acme/{target}": {
            "DB_CREDENTIALS": {"acme_web_user": LIVE},
            "pending": {"acme_web_user": STAGED},
        }
        for target in ("appdb-alpha", "appdb-beta")
    }


def _credential() -> Any:
    """The admin credential the CLI would have resolved.

    A real :class:`~sopuli.admin.Resolved` rather than a stub with one attribute.
    The command reads its *provenance* as well as its value, because it reports
    where an admin credential came from, and a stub stops being enough the
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


# ------------------------------------------------- --debug: planning (#788) ---


def debug_lines(result: Result) -> list[str]:
    """The `plan` area's debug lines on stderr."""
    return [line for line in result.stderr.splitlines() if " plan: " in line]


def test_debug_names_a_target_a_selector_left_out(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate()
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--debug")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    left = [line for line in debug_lines(result) if "left out" in line]
    assert len(left) == 1
    assert left[0].endswith("plan: target appdb-beta left out by --select")
    assert STAGED not in result.stderr
    assert LIVE not in result.stderr


def test_debug_says_why_an_applied_password_was_left_alone(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The convergent case: the database already accepts the vault's `current`."""
    estate(
        documents={"apps/acme/appdb-alpha": {"DB_CREDENTIALS": {"acme_web_user": LIVE}}},
        answers={"ACME_WEB_USER": passes(1)},
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--debug")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert f"acme_web_user on appdb-alpha left alone: {check.IN_SYNC}, " in result.stderr
    assert LIVE not in result.stderr


def test_debug_says_why_a_locked_account_was_left_alone(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate(users={"ACME_WEB_USER": user(status="LOCKED", locked=True)})
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--debug")

    assert f"acme_web_user on appdb-alpha left alone: {check.LOCKED}, " in result.stderr
    assert STAGED not in result.stderr
    assert LIVE not in result.stderr


# ---------------------------------------------------- connection encryption ---

CLEAR = Encryption(method="none", protocol="tcp", hint="require NNE or TLS on the server")
UNKNOWN_ENCRYPTION = Encryption(method="unknown", protocol="tcp", hint="grant the view")


def _codes(result: Result) -> list[str]:
    return [one.get("code") for one in document(result).get("diagnostics", [])]


def test_a_password_sent_in_clear_warns_once_per_target(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#697: warn, never refuse. The change still happens, on both targets."""
    harness = estate(encryption=CLEAR)
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS
    assert all(session.changed for session in harness["sessions"])
    found = [one for one in document(result)["diagnostics"] if one.get("code") == "SOPULI-W031"]
    assert sorted(one["target"] for one in found) == ["appdb-alpha", "appdb-beta"]
    assert all("require NNE or TLS on the server" in one["message"] for one in found)


def test_an_unknown_encryption_has_a_code_of_its_own(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Could not tell is not the same finding as in clear."""
    estate(encryption=UNKNOWN_ENCRYPTION)
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert _codes(result).count("SOPULI-W032") == 2
    assert "SOPULI-W031" not in _codes(result)


def test_no_warning_where_no_password_was_sent(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """An account already in sync sends nothing, so there is nothing to warn about."""
    estate(
        documents={"apps/acme/appdb-alpha": {"DB_CREDENTIALS": {"acme_web_user": LIVE}}},
        answers={"ACME_WEB_USER": passes(1)},
        encryption=CLEAR,
    )
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")

    assert "SOPULI-W031" not in _codes(result)


def test_a_password_the_server_refused_still_warns(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The statement went out and was refused, so the password crossed anyway."""
    refused = DriverError("ORA-01031: insufficient privileges", code="ORA-01031")
    refused.password_sent = True
    estate(set_error=refused, encryption=CLEAR)
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert _codes(result).count("SOPULI-W031") == 2


def test_a_refusal_before_the_statement_does_not_warn(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Read-only, a missing account, a `"`: the driver refused, nothing was sent."""
    estate(set_error=DriverError("target is read-only"), encryption=CLEAR)
    result = run(runner, write_config(CONFIG), "--output", "json")

    assert "SOPULI-W031" not in _codes(result)


def test_a_redraw_keeps_what_the_first_pass_sent_in_clear() -> None:
    """Pass one sent the password in clear; pass two failed before sending.

    The row is the second pass's, but the first password still crossed the
    network, so the encryption it went over stays on the row.
    """
    binding = SimpleNamespace(account="acme_web_user", target="appdb-alpha")
    first = _Applied(
        binding,  # type: ignore[arg-type]
        None,
        check.Outcome(check.ERROR, "refused"),
        changed=True,
        encryption=CLEAR,
    )
    second = _Applied(
        binding,  # type: ignore[arg-type]
        None,
        check.Outcome(check.ERROR, "could not connect"),
        changed=False,
    )

    (spliced,) = _splice([first], [second])

    assert spliced.encryption == CLEAR
    assert spliced.outcome.detail == "could not connect", "the row is still the second pass's"


def test_the_warning_is_printed_as_well(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate(encryption=CLEAR)
    result = run(runner, write_config(CONFIG))

    assert "appdb-alpha: a password was sent over a connection that is not encrypted" in (
        result.output
    )


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
    """Opt-in, never inferred. An estate that has not asked for the unlock
    gets the refusal, and the message names the key that changes it."""
    harness = estate(users={"ACME_WEB_USER": user(status="LOCKED", locked=True)})
    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"][0].unlocked == []
    assert "unlock_if_locked" in result.output


# ------------------------------------------------------------ the attributes ---


def test_a_locked_account_is_unlocked_and_then_rotated(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`apply` refuses to change a locked account's password, so without §5's
    attribute an operator has to unlock a locked application account by hand.
    With the attribute declared, the run removes the reason and goes on to do
    the work."""
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
    """§5's second attribute (decision #301): `ALTER USER … PROFILE …`, and
    then the rotation, in one run."""
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
    """`attribute_set` is the schema's own kind for this, so the detail is what
    says which attribute moved and where from."""
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
    """UC-1 §8 step 3 (decision #301): the survey asks, and the run refuses
    rather than discovering it on target nine with eight accounts already
    moved."""
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
    diagnostics = document(result).get("diagnostics", [])
    unread = [one for one in diagnostics if "could not establish" in one["message"]]
    assert len(unread) == 2
    assert {one["code"] for one in unread} == {PROFILE_UNREAD}
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
    """The interaction to guard against: a profile decides whether a rollover
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
    """The `repair with:` line points at a remedy, and the remedy has to be narrowed
    the way this run was narrowed -- otherwise the repair spends a login on every
    target the partial run already spent one on."""
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


def outside_writer(store: Any, path: str) -> list[str]:
    """Another writer changes ``path`` just before this run's promotion of it (#805).

    The promotion is the run's only write to a secret path, so the first write
    there is the one to race. The other writer's write uses the version the
    promotion is about to send, so the promotion's compare-and-set is refused.
    """
    write = store.write
    raced: list[str] = []

    def racing_write(target: str, data: Mapping[str, Any], *, cas: int | None = None) -> int:
        if not raced and target == path:
            raced.append(target)
            held = store.read(target)
            assert held is not None
            write(target, {**held.data, "note": "somebody else"}, cas=cas)
        return int(write(target, data, cas=cas))

    store.write = racing_write
    return raced


def test_a_promotion_that_loses_its_compare_and_set_says_so(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    """UC-1 §8 row 7, reported where a reader looks (#805).

    Every target confirmed, so the rows are `IN_SYNC`. Before the fix exit 4 was
    the only sign: no `vault_promote` action, no error, `ok` in the summary and
    no diagnostic. The other document promotes as usual.
    """
    harness = estate()
    raced = outside_writer(harness["store"], "apps/acme/appdb-alpha")

    result = run(runner, write_config(CONFIG), "--output", "json")
    found = document(result)

    assert raced, "the promotion never wrote, so this asserts nothing"
    assert not list(validator.iter_errors(found))
    assert found["exit_code"] == ExitCode.PARTIAL
    alpha, beta = found["results"]
    assert alpha["target"] == "appdb-alpha"
    assert alpha["state"] == "IN_SYNC"
    promote = alpha["actions"][-1]
    assert promote["kind"] == "vault_promote"
    assert promote["applied"] is True
    assert "failed" in promote["detail"]
    assert "compare-and-set" in alpha["error"]["message"]
    assert any("SOPULI-W033" in one["message"] for one in alpha["warnings"])
    assert beta["actions"][-1]["detail"].startswith("promoted `pending` to `current`")
    assert "error" not in beta
    assert found["summary"]["ok"] == 1
    assert found["summary"]["failed"] == 1
    assert found["summary"]["by_state"] == {"IN_SYNC": 2}
    (failed,) = [one for one in found["diagnostics"] if one.get("code") == PROMOTION_FAILED]
    assert failed["level"] == "error"
    assert "apps/acme/appdb-alpha" in failed["message"]
    assert "acme_web_user" in failed["message"]
    assert "another writer" in failed["message"]
    assert stored(harness["store"], "apps/acme/appdb-alpha")["pending"]["acme_web_user"] == STAGED


def test_a_failed_promotion_is_printed_with_its_remedy(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The text output says it too: a diagnostic only in JSON reaches nobody at a
    terminal."""
    harness = estate()
    outside_writer(harness["store"], "apps/acme/appdb-alpha")

    result = run(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.PARTIAL
    assert "apps/acme/appdb-alpha was not promoted" in result.output
    assert "repair with: sopuli creds apply" in result.output


def test_a_failed_promotion_leaves_a_sibling_from_current_alone(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A sibling applied from `current` owed the write nothing, so its `current`
    is right: it is ok, carries no error, and is not named in `SOPULI-W033`."""
    harness = estate(
        documents={
            "apps/acme/db": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
                "pending": {"acme_web_user": STAGED},
            }
        },
        users={"ACME_WEB_USER": user(), "ACME_BATCH_USER": user("ACME_BATCH_USER")},
        answers={
            "ACME_WEB_USER": drifted(),
            "ACME_BATCH_USER": [VerifyResult(VERIFY_LOGIN, PASS, latency_ms=9)],
        },
    )
    outside_writer(harness["store"], "apps/acme/db")

    found = document(run(runner, write_config(SHARED_CONFIG), "--output", "json"))

    rows = {row["account"]: row for row in found["results"]}
    assert "error" in rows["acme_web_user"]
    assert "error" not in rows["acme_batch_user"]
    assert "vault_promote" not in [one["kind"] for one in rows["acme_batch_user"]["actions"]]
    assert (found["summary"]["ok"], found["summary"]["failed"]) == (1, 1)
    (failed,) = [one for one in found["diagnostics"] if one.get("code") == PROMOTION_FAILED]
    assert "for acme_web_user and" in failed["message"]


def test_a_failed_rollback_promotion_names_the_rollback_as_its_remedy(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A plain `creds apply` would apply `current` back and undo the rollback."""
    harness = estate(documents=_rolled(), answers={"ACME_WEB_USER": drifted()})
    outside_writer(harness["store"], "apps/acme/appdb-alpha")

    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--source",
        "previous",
        "--confirm",
        "--output",
        "json",
    )

    found = document(result)
    assert found["exit_code"] == ExitCode.PARTIAL
    (failed,) = [one for one in found["diagnostics"] if one.get("code") == PROMOTION_FAILED]
    assert "The databases have `previous`" in failed["message"]
    assert "--select tenant=alpha --source previous --confirm`" in failed["message"]


def test_a_failed_promotion_names_the_runs_own_repair(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The remedy keeps `--config` and the selectors, as the repair line does: a
    bare re-run would spend a login on every target of the estate."""
    harness = estate()
    outside_writer(harness["store"], "apps/acme/appdb-alpha")
    config = write_config(CONFIG)

    found = document(run(runner, config, "--select", "env=prod", "--output", "json"))

    (failed,) = [one for one in found["diagnostics"] if one.get("code") == PROMOTION_FAILED]
    assert f"run `sopuli creds apply --config {config} --select env=prod`" in failed["message"]


def test_a_failed_promotion_names_no_rerun_after_a_takeover(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Alpha's promotion fails, then the run finds beta's lock taken. Running
    again is the one thing not to do (SOPULI-W011), so W033 does not say to."""
    harness = estate()
    store = harness["store"]
    write = store.write
    beta = LockKey(store="vault-prod", path="apps/acme/appdb-beta")

    def racing_write(path: str, data: Mapping[str, Any], *, cas: int | None = None) -> int:
        if path == "apps/acme/appdb-alpha":
            held = store.read(path)
            write(path, {**held.data, "note": "somebody else"}, cas=cas)
            record = store.read(lock_path(beta))
            write(lock_path(beta), fresh(), cas=record.version)
        return int(write(path, data, cas=cas))

    store.write = racing_write

    found = document(run(runner, write_config(CONFIG), "--output", "json"))

    codes = [one.get("code") for one in found["diagnostics"]]
    assert "SOPULI-W011" in codes
    (failed,) = [one for one in found["diagnostics"] if one.get("code") == PROMOTION_FAILED]
    assert "run `sopuli creds apply" not in failed["message"]
    assert "another run then took over this run's lock" in failed["message"]


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
    """Somebody else takes this document's lock, once, mid-run.

    A real record at the real path written under a different `correlation_id`, so
    the run's next fence check fails on the version and would fail on the id too.
    Once, because a takeover happens once and a hook firing on every call would
    also fence the run's very first target.

    ``at`` is which seam it happens on, and it is what makes the two exit codes
    testable: ``describe_user`` fires before this run has changed anything,
    ``apply_attributes`` once an account may have been unlocked, and
    ``set_password`` once one database has been changed.
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
        # the path requires a compare-and-set, so an unguarded write
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
    """The `repair with:` line says *run this again*, which is the one thing not
    to do while somebody else holds this estate's lock."""
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
    """`apply_attributes` issues `ALTER USER ... ACCOUNT UNLOCK`, which is a
    database change like any other and needs a fence check before it.

    The takeover lands on this run's *first* `describe_user`, so the lock is
    somebody else's before the attribute pass is reached. A check that ran only
    after the attribute pass would unlock an account on a lock the run no longer
    holds -- a smaller blast radius than a password and the same rule broken.
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
    """The fence also covers every account after the first *within* a target.

    `renew()` fences each target boundary, so a two-target estate is covered at
    the seam between them. Two accounts in one target have no seam -- the run
    goes straight from one to the next -- and the attribute pass is the first
    thing each of them does. The takeover here lands on the first account's
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
    """Closing the rollover window is a database change, so it needs a fence
    check. `creds finish-rollover` fences this same call, and `creds apply` must
    follow the same rule, because one operation cannot have two rules about
    whether the fence applies to it.

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


def test_a_takeover_before_the_window_closes_keeps_the_row(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, validator: Any
) -> None:
    """#739: the password was set, so the account has a row, though the run
    stopped before `--strategy direct` closed the window. Without the row, the
    change and its encryption warning would be in no document."""
    harness = estate(
        users={"ACME_WEB_USER": rollover_user()},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
        on_call=steal("apps/acme/appdb-alpha", at="set_password"),
        encryption=CLEAR,
    )

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
    assert found["exit_code"] == ExitCode.PARTIAL
    assert applying(harness).finished == []
    [row] = found["results"]
    assert row["account"] == "acme_web_user"
    assert row["changed"] is True
    assert row["state"] == check.ROLLOVER_ACTIVE
    assert row["rollover"]["active"] is True
    setting = next(one for one in row["actions"] if one["kind"] == "password_set")
    assert "lost its lock before it closed the rollover window" in setting["detail"]
    assert "SOPULI-W031" in _codes(result)


def test_a_takeover_before_the_window_closes_streams_the_change(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, events: Any
) -> None:
    """The stream says what the document says: the password was applied."""
    estate(
        users={"ACME_WEB_USER": rollover_user()},
        capabilities=frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}),
        on_call=steal("apps/acme/appdb-alpha", at="set_password"),
    )

    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--strategy",
        "direct",
        "--output",
        "jsonl",
    )

    applied = [line for line in stream(result, events) if line["event"] == "password.applied"]
    assert [(line["account"], line["data"]["outcome"]) for line in applied] == [
        ("acme_web_user", check.ROLLOVER_ACTIVE)
    ]


def test_a_takeover_after_the_attribute_pass_keeps_the_row(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, validator: Any
) -> None:
    """The same gap one check earlier: the account was unlocked, and the check
    before `set_password` found the lock gone. The unlock is a change, so it has
    a row, and the row says the password was not set."""
    harness = estate(
        users={"ACME_WEB_USER": user(status="LOCKED", locked=True)},
        on_call=steal("apps/acme/appdb-alpha", at="apply_attributes"),
    )

    result = run(
        runner, write_config(UNLOCKING_CONFIG), "--select", "tenant=alpha", "--output", "json"
    )
    found = document(result)

    validator.validate(found)
    assert found["exit_code"] == ExitCode.PARTIAL
    assert harness["sessions"][0].unlocked == ["ACME_WEB_USER"]
    assert harness["sessions"][0].changed == []
    [row] = found["results"]
    # True for the unlock: the row's `changed` counts every change to the account.
    assert row["changed"] is True
    assert row["state"] == check.ERROR
    kinds = {one["kind"]: one for one in row["actions"]}
    assert kinds[ACCOUNT_UNLOCK]["applied"] is True
    assert "before setting its password" in kinds["password_set"]["detail"]
    assert row["error"]["category"] == "lock"


def test_a_takeover_after_the_attribute_pass_streams_no_password(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, events: Any
) -> None:
    """No `ALTER USER ... IDENTIFIED BY` was issued, so no `password.applied`."""
    estate(
        users={"ACME_WEB_USER": user(status="LOCKED", locked=True)},
        on_call=steal("apps/acme/appdb-alpha", at="apply_attributes"),
    )

    result = run(
        runner, write_config(UNLOCKING_CONFIG), "--select", "tenant=alpha", "--output", "jsonl"
    )

    assert "password.applied" not in [line["event"] for line in stream(result, events)]


def test_a_takeover_during_the_renewal_keeps_what_the_run_applied(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The renewal's compare-and-set loses, and that is a *takeover*.

    `renew()` checks the fence and then writes, and a takeover can land in
    between -- or on lock two after lock one has already been rewritten. The
    conflict has to be reported as a takeover and not as `LockDeniedError`,
    whose message says the run is "acquiring" a lock it has held since the
    first target. `_apply_estate` does not catch `LockDeniedError`, so it would
    reach the boundary as exit 7, and the accumulated `applied` list would go
    with the exception.

    A scheduler would then read **exit 7 -- nothing happened** at the exact
    moment the first target had already been re-passworded. Exit 4 with the
    results kept is what the split in `sopuli/lock/errors.py` describes, and
    what the command layer does for every other takeover.
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

    The `require_cas` is not decoration: an acquisition arranges that
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
    """The default, which wiring `break_expired` (decision #348) must not change.

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
    """Decision #348: the resolved key reaches every `LockManager`.

    Without that wire an operator who set the key would hit exit 7, be told by
    `_hint_for` to set the key they had already set, and have nothing in the
    output to tell them it was not consulted. This asserts the wire where it
    shows: the run proceeds.
    """
    harness = estate()
    plant_lock(harness["store"], ALPHA_LOCK, lapsed())

    result = run(runner, write_config(BREAK_EXPIRED_CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.SUCCESS
    assert harness["sessions"][0].changed == [("ACME_WEB_USER", STAGED)]


def test_a_takeover_says_so_in_the_output(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, validator: Any
) -> None:
    """A guardrail that fires silently is half a guardrail.

    The command has to call `lock_diagnostics`, or a run that broke somebody's
    lock says so nowhere. `01-configuration.md` §3a says this and
    `sopuli lock break` "emit the same warning code, because it is the same
    event", and `_taken_over`'s own docstring says why it has to: the evidence is
    gone from the path the moment the takeover write lands, so if this run does
    not report it, nothing ever does.
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
    """Both layers the registry declares. `defaults:` and a profile are the two,
    and a wire that carried only the first would fail every estate that puts the
    key where `01-configuration.md` says it belongs -- "the profile is where this
    belongs: it is a property of running without anybody watching"."""
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
    """Decision #360: both `db.*_timeout_s` keys reach the driver.

    `_timeouts()` builds `Timeouts` from `db.connect_timeout_s` and
    `db.query_timeout_s`. Without the command-side wire, a profile writing
    `query_timeout_s` would validate, appear in `config show`, and change
    nothing at all. The driver end is tested on its own: `Timeouts.query_s`
    becomes `Connection.call_timeout`, asserted in
    `tests/driver/test_oracle_connect.py`.

    Asserted on what the *command* handed the driver rather than on what the
    driver did with it, because the command-side wire is the part under test.
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
    assert found["diagnostics"][0]["code"] == PRIVILEGE_AUDIT_UNREAD


@pytest.mark.parametrize("mode", [(), ("--dry-run",)], ids=["run", "dry-run"])
def test_an_unreadable_audit_is_printed_in_the_text_as_well(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, mode: tuple[str, ...]
) -> None:
    """Decision #606: a survey that passed with a check missing must not read,
    in a terminal, like one that made every check -- least of all under
    `--dry-run`, where nothing runs afterwards to meet the cause."""
    estate(audits={"appdb-alpha": RuntimeError("ORA-00942: table or view does not exist")})

    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--preflight", *mode)

    assert result.exit_code == ExitCode.SUCCESS
    assert "pre-flight on appdb-alpha could not establish" in result.output
    assert "ORA-00942" in result.output


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


# ---------------------------- a run narrower than its promotion (decision #406) ---


def _both_staged() -> dict[str, dict[str, Any]]:
    return {
        "apps/acme/db": {
            "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
            "pending": {"acme_web_user": STAGED, "acme_batch_user": STAGED},
        }
    }


def test_a_run_narrowed_to_one_target_changes_it_and_does_not_promote(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 7, against a selector rather than against a failure.

    One account on two targets sharing one document. `--target` reaches one of
    them, and nothing fails -- which a gate that counted only the pairs this run
    visited would let promote, with the other database still holding the old
    password. Asserted on the stored document, per this file's rule.
    """
    harness = estate(documents=staged())
    config = write_config(REDRAW_CONFIG)

    result = run(runner, config, "--target", "appdb-alpha")

    assert result.exit_code == ExitCode.PARTIAL
    changed = [name for session in harness["sessions"] for name, _ in session.changed]
    assert changed == ["ACME_WEB_USER"]
    after = stored(harness["store"], REDRAW_DOCUMENT)
    assert after["DB_CREDENTIALS"] == {"acme_web_user": LIVE}
    assert after["pending"] == {"acme_web_user": STAGED}
    assert "acme_web_user on appdb-beta" in result.output


def _row(result: Result, target: str) -> dict[str, Any]:
    return next(one for one in document(result)["results"] if one["target"] == target)


def test_a_confirmed_row_of_a_narrowed_promotion_says_current_is_stale(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#873. appdb-alpha took the new password and `current` still holds the
    old one, so its row carries W049, pointing at W027 for the remedy. The
    summary counts it failed, not ok, as a failed promotion write's row is."""
    estate(documents=staged())

    result = run(runner, write_config(REDRAW_CONFIG), "--target", "appdb-alpha", "--output", "json")

    (warning,) = _row(result, "appdb-alpha")["warnings"]
    assert warning["code"] == CHANGED_NOT_PROMOTED
    assert PROMOTION_WITHHELD in warning["message"]
    summary = document(result)["summary"]
    assert (summary["ok"], summary["failed"]) == (0, 1)


def test_a_confirmed_row_beside_a_target_that_failed_says_current_is_stale(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """#873's third cause: one document, and appdb-beta did not confirm, so
    appdb-alpha is changed and confirmed while `current` is not moved."""
    estate(
        documents=staged(),
        per_target={
            "appdb-alpha": {"ACME_WEB_USER": drifted()},
            "appdb-beta": {
                "ACME_WEB_USER": [
                    VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017"),
                    VerifyResult(VERIFY_LOGIN, FAIL, detail="ORA-01017"),
                ]
            },
        },
    )

    result = run(runner, write_config(REDRAW_CONFIG), "--output", "json")

    (warning,) = _row(result, "appdb-alpha")["warnings"]
    assert warning["code"] == CHANGED_NOT_PROMOTED
    assert "another row of this document did not confirm" in warning["message"]
    # Both rows failed: beta did not confirm, and alpha confirmed with
    # `current` left stale. Counted once each.
    summary = document(result)["summary"]
    assert (summary["ok"], summary["failed"]) == (0, 2)


def test_the_withheld_promotion_names_the_wider_run_as_its_remedy(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The `repair with:` line echoes the selectors, and here that would be the
    invocation that withholds the promotion again."""
    estate(documents=staged())
    config = write_config(LABELLED_SHARED_CONFIG)

    result = run(runner, config, "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.PARTIAL
    remedy = result.output.split("repair with: ")[1].splitlines()[0]
    assert remedy == f"sopuli creds apply --config {config}"


def test_the_wider_run_finishes_what_the_narrow_one_left(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate(documents=staged())
    config = write_config(REDRAW_CONFIG)
    run(runner, config, "--target", "appdb-alpha")

    result = run(runner, config)

    assert result.exit_code == ExitCode.SUCCESS
    after = stored(harness["store"], REDRAW_DOCUMENT)
    assert after["DB_CREDENTIALS"] == {"acme_web_user": STAGED}
    assert after["pending"] == {}


def test_a_sibling_with_a_staged_password_holds_the_promotion_back(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
) -> None:
    """Narrowing *within* a shared document (decision #406).

    The sibling's `pending` may already be on its database -- an earlier partial
    run leaves exactly that -- and promoting past it would strand it there behind
    an exit 0. The code is what tells this exit 4 from a failed target's.
    """
    harness = estate(
        documents=_both_staged(),
        users={"ACME_WEB_USER": user(), "ACME_BATCH_USER": user("ACME_BATCH_USER")},
        answers={"ACME_WEB_USER": drifted(), "ACME_BATCH_USER": drifted()},
    )

    result = run(
        runner, write_config(SHARED_CONFIG), "--account", "acme_batch_user", "--output", "json"
    )

    found = document(result)
    assert not list(validator.iter_errors(found))
    assert found["exit_code"] == ExitCode.PARTIAL
    assert [one["code"] for one in found["diagnostics"]] == [PROMOTION_WITHHELD]
    assert "acme_web_user on appdb-alpha" in found["diagnostics"][0]["message"]
    assert found["results"][0]["state"] == check.IN_SYNC
    assert "promoted_to" not in found["results"][0]
    staged_before = _both_staged()["apps/acme/db"]["pending"]
    assert stored(harness["store"], "apps/acme/db")["pending"] == staged_before


def test_a_sibling_with_nothing_staged_is_not_needed(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """What keeps `--account` able to rotate one account in a shared document:
    a sibling with no rotation in flight has nothing for a promotion to strand."""
    harness = estate(
        documents={
            "apps/acme/db": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
                "pending": {"acme_batch_user": STAGED},
            }
        },
        users={"ACME_WEB_USER": user(), "ACME_BATCH_USER": user("ACME_BATCH_USER")},
        answers={"ACME_WEB_USER": drifted(), "ACME_BATCH_USER": drifted()},
    )

    result = run(runner, write_config(SHARED_CONFIG), "--account", "acme_batch_user")

    assert result.exit_code == ExitCode.SUCCESS
    after = stored(harness["store"], "apps/acme/db")
    assert after["DB_CREDENTIALS"] == {"acme_web_user": LIVE, "acme_batch_user": STAGED}


def test_a_dry_run_says_the_promotion_would_be_withheld(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate(documents=staged())

    result = run(runner, write_config(REDRAW_CONFIG), "--target", "appdb-alpha", "--dry-run")

    assert result.exit_code == ExitCode.SUCCESS
    assert "acme_web_user on appdb-beta" in result.output


def test_a_rollback_narrowed_to_one_target_does_not_swap_the_vault(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A rollback *is* a promotion, of the other neighbour, so the same gate
    stands in front of it."""
    body = {
        "DB_CREDENTIALS": {"acme_web_user": STAGED},
        "previous": {"acme_web_user": LIVE},
    }
    harness = estate(documents={REDRAW_DOCUMENT: body})

    result = run(
        runner,
        write_config(REDRAW_CONFIG),
        "--target",
        "appdb-alpha",
        "--source",
        "previous",
        "--confirm",
    )

    assert result.exit_code == ExitCode.PARTIAL
    after = stored(harness["store"], REDRAW_DOCUMENT)
    assert after["DB_CREDENTIALS"] == {"acme_web_user": STAGED}
    assert after["previous"] == {"acme_web_user": LIVE}


def test_a_rotation_narrower_than_its_promotion_is_refused_before_staging(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`apply` changes what it was pointed at and waits; `rotate` would draw a
    password, put it on half the estate and stop there by construction. So the
    same test is a refusal, and nothing is written -- asserted on the version."""
    harness = estate(documents={REDRAW_DOCUMENT: {"DB_CREDENTIALS": {"acme_web_user": LIVE}}})
    before = harness["store"].read(REDRAW_DOCUMENT).version

    result = runner.invoke(
        cli,
        [
            "creds",
            "rotate",
            "--config",
            str(write_config(REDRAW_CONFIG)),
            "--target",
            "appdb-alpha",
            "--confirm",
        ],
    )

    # The boundary that turns this into exit 8 is `main`'s, which `CliRunner`
    # does not go through -- the rollback refusal above is asserted the same way.
    assert isinstance(result.exception, RefusedError)
    assert "acme_web_user on appdb-beta" in str(result.exception)
    assert harness["store"].read(REDRAW_DOCUMENT).version == before
    assert harness["sessions"] == []


#: `REDRAW_CONFIG` with beta's store left to a default nobody set, so the binding
#: the gate is asked about has no store at all.
STORELESS_BETA_CONFIG = REDRAW_CONFIG.replace(
    "    dsn: db-prod.example.com:1521/beta.pdb.example.com\n    environment: prod\n"
    "    vault: vault-prod\n",
    "    dsn: db-prod.example.com:1521/beta.pdb.example.com\n    environment: prod\n",
)


def test_an_excluded_binding_with_no_store_holds_the_promotion_back(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Its store might resolve only when it is selected, so "no store" is not
    evidence that it lives in another document. The gate fails closed."""
    assert STORELESS_BETA_CONFIG != REDRAW_CONFIG
    harness = estate(documents=staged())

    result = run(runner, write_config(STORELESS_BETA_CONFIG), "--target", "appdb-alpha")

    assert result.exit_code == ExitCode.PARTIAL
    assert "acme_web_user on appdb-beta" in result.output
    assert stored(harness["store"], REDRAW_DOCUMENT)["pending"] == {"acme_web_user": STAGED}


def test_an_unused_default_store_does_not_refuse_a_narrowed_run(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`SOPULI_VAULT` naming an undeclared store is wrong only for a run that
    needed the default, and this one does not: the gate reads the whole estate,
    and reading it must not add a refusal the selected run would never meet."""
    monkeypatch.setenv("SOPULI_VAULT", "nosuch")
    estate(documents=staged())

    result = run(runner, write_config(STORELESS_BETA_CONFIG), "--target", "appdb-alpha")

    assert result.exit_code == ExitCode.PARTIAL
    assert "nosuch" not in result.output


def test_the_same_credential_spelled_differently_is_still_the_same_credential() -> None:
    """Two targets can address one value with refs that are not equal as
    strings -- an explicit store prefix on one of them. A rollback compares the
    credential and not the spelling."""
    config = build_config(yaml.safe_load(REDRAW_CONFIG))
    alpha, beta = config.bindings
    assert alpha.secret is not None
    assert beta.secret is not None
    beta = replace(beta, secret=replace(beta.secret, vault="vault-prod", path="apps//acme/db"))
    estate_ = replace(config, bindings=(alpha, beta))

    found = _left_out([alpha], [(alpha, False)], {}, estate_)

    assert [(one.account, one.target) for bindings in found.values() for one in bindings] == [
        ("acme_web_user", "appdb-beta")
    ]


def test_a_sibling_that_is_not_due_is_not_visited_by_the_rotation(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`--max-age-days` drops an account from the rotation without dropping it
    from the selection. A sibling that is not due and has a `pending` of its own
    is as unvisited as one a selector excluded."""
    recent = to_rfc3339(utc_now() - timedelta(days=1))
    old = to_rfc3339(utc_now() - timedelta(days=60))
    harness = estate(
        documents={
            "apps/acme/db": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
                "pending": {"acme_web_user": STAGED},
                "rotated_at": {"acme_web_user": recent, "acme_batch_user": old},
            }
        },
        users={"ACME_WEB_USER": user(), "ACME_BATCH_USER": user("ACME_BATCH_USER")},
    )
    before = harness["store"].read("apps/acme/db").version

    result = runner.invoke(
        cli,
        [
            "creds",
            "rotate",
            "--config",
            str(write_config(SHARED_CONFIG)),
            "--max-age-days",
            "30",
            "--confirm",
        ],
    )

    assert isinstance(result.exception, RefusedError)
    assert "acme_web_user on appdb-alpha" in str(result.exception)
    assert harness["store"].read("apps/acme/db").version == before


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

    `apply` redraws a refused password (decision #268), but not here: `CONFIG`
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


@pytest.mark.parametrize(
    ("code", "retryable"),
    [
        # A closed PDB may be opened again (#766); a refused login will not
        # change by itself. The second is an AuthenticationError, not a
        # MappedError, so both of `as_error`'s branches are covered.
        ("ORA-01109", True),
        ("ORA-01017", False),
    ],
)
def test_a_row_error_reports_whether_the_driver_found_it_retryable(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    validator: Draft202012Validator,
    code: str,
    retryable: bool,
) -> None:
    """#774: the driver's classification reaches `results[].error.retryable`."""
    estate(connect_error=classify(code, f"{code}: refused").as_error())

    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")
    found = document(result)

    assert list(validator.iter_errors(found)) == []
    (row,) = found["results"]
    assert row["error"]["code"] == code
    assert row["error"]["retryable"] is retryable


@pytest.mark.parametrize(
    "failure",
    [
        # No vendor code: the tool refused it itself.
        DriverError("target is read-only"),
        # An Oracle Net code with no row: its family places it, nothing more.
        classify("ORA-12170", "ORA-12170: TNS:Connect timeout occurred").as_error(),
    ],
    ids=["no-code", "family-only"],
)
def test_an_unclassified_row_error_has_no_retryable_field(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, failure: Exception
) -> None:
    """Nothing decided whether these clear, so the row says nothing rather than
    `false`, which would claim that something did."""
    estate(set_error=failure)

    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")
    found = document(result)

    (row,) = found["results"]
    assert row["state"] == "ERROR"
    assert "retryable" not in row["error"]


def test_readonly_refuses_before_anything_connects(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 10's ratchet, and invariant 4's timing.

    **`readonly` is set in the file**, which is the only place it can be set.
    There is no `--readonly` option. Passing one would make click refuse the
    argv, so the command would never run and the two assertions below would be
    satisfied by a usage error. The test would then pass with
    `refuse_if_readonly` deleted: a guard that looks enforced and is not.
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
    """The same guard, set on a target (decision #424).

    `appdb-alpha` carries `safety: { readonly: true }`. A run that applied a
    password to it would print the plan, read the store and reach the database.
    The refusal has to arrive at *plan* time, which is why the session
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
    """Decision #424 refuses the whole run rather than skipping the marked
    targets, so the narrowing the message offers has to actually work. If it did
    not, the refusal would be handing the operator advice the tool cannot
    honour."""
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
    """The ceiling is enforced on a target as `readonly` is (decision #424)."""
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

    A `DriverError` must not fall into the boundary's catch-all, where it would
    come out as `internal` on exit 1, with the hint folded into a message
    prefixed by the exception's class name. The one refusal in this tool that
    has its own exit code has to use it, and `target_capability` has to be
    emitted.
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
    """The counterpart: a refusal with no capability behind it is still the
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
    """`require_rollover` owns both of its refusals and carries the exact
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


def test_a_rollback_under_a_profile_that_cannot_answer_is_refused(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`confirm: false` refuses the rollback gate even at a terminal
    (decision #610)."""
    monkeypatch.setattr("sopuli.cli._can_prompt", lambda: True)
    harness = estate(documents=_rolled())
    config = write_config(CONFIG + "profiles:\n  ci:\n    confirm: false\n")
    result = run(
        runner, config, "--select", "tenant=alpha", "--source", "previous", "--profile", "ci"
    )

    assert harness["sessions"] == []
    assert "profiles.ci.confirm" in str(getattr(result.exception, "hint", ""))


def test_a_rollback_with_no_previous_says_so(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Bounded to one generation (Q3), so there is nothing to run and the
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


@pytest.mark.parametrize(
    ("source", "expected"),
    [((), False), (("--source", "previous"), True)],
    ids=["apply", "rollback"],
)
def test_the_plan_says_whether_the_run_needs_a_yes(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    source: tuple[str, ...],
    expected: bool,
) -> None:
    """A rollback asks every time, and a dry run of one reports that (#663).
    This estate lists no environment, so a plain `apply` asks nothing."""
    estate(documents=_rolled())
    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        *source,
        "--dry-run",
        "--output",
        "json",
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert document(result)["plan"]["confirmation_required"] is expected


# --------------------------------- the rollback and reuse (decision #568) ---


def _reusing(**limits: str) -> dict[str, UserState | None]:
    """ACME_WEB_USER on a profile with the given reuse limits.

    `5` / `UNLIMITED` by default, which is the tier-1 `SOPULI_REUSE` fixture and
    the regime where a password the account has held is never accepted again.
    """
    fields = {"password_reuse_max": "5", "password_reuse_time": "UNLIMITED", **limits}
    return {"ACME_WEB_USER": user(profile="SOPULI_REUSE", **fields)}


def _rollback(runner: CliRunner, config: Path, *extra: str) -> Any:
    return run(
        runner, config, "--select", "tenant=alpha", "--source", "previous", "--confirm", *extra
    )


def _coded(emitted: Mapping[str, Any], code: str) -> list[dict[str, Any]]:
    return [one for one in emitted.get("diagnostics", []) if one.get("code") == code]


def test_a_refused_rollback_on_a_reuse_profile_says_why_and_draws_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Decision #568. The profile is reported with both values, the row's hint
    does not tell the operator to draw another, and the redraw's refusal gives
    the rollback's reason rather than "no record of where that password came
    from", which describes `pending`'s provenance key and not the value that was
    refused."""
    harness = estate(documents=_rolled(), users=_reusing(), set_error=refusal("ORA-28007"))

    result = _rollback(runner, write_config(CONFIG), "--output", "json")
    emitted = document(result)

    assert result.exit_code == ExitCode.FAILURE
    assert harness["sessions"][0].attempted == [("ACME_WEB_USER", "The-One-Before-2025")]
    body = stored(harness["store"], "apps/acme/appdb-alpha")
    assert body["DB_CREDENTIALS"]["acme_web_user"] == LIVE
    assert body["previous"]["acme_web_user"] == "The-One-Before-2025"

    (warned,) = _coded(emitted, "SOPULI-W028")
    assert "SOPULI_REUSE" in warned["message"]
    assert "PASSWORD_REUSE_MAX 5" in warned["message"]
    assert "PASSWORD_REUSE_TIME UNLIMITED" in warned["message"]
    assert warned["target"] == "appdb-alpha"

    (row,) = emitted["results"]
    assert row["error"]["code"] == "ORA-28007"
    assert "draw another" not in row["error"]["hint"]
    assert "rollover window" in row["error"]["hint"]

    (declined,) = _coded(emitted, "SOPULI-W030")
    assert "rollback" in declined["message"]
    assert not _coded(emitted, "SOPULI-W029")


def test_the_reuse_warning_is_printed_as_well_as_serialised(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A warning only in `diagnostics[]` is invisible to the person who ran the
    rollback by hand, and they are who it is for."""
    estate(documents=_rolled(), users=_reusing(), set_error=refusal("ORA-28007"))

    result = _rollback(runner, write_config(CONFIG))

    assert 'profile "SOPULI_REUSE" restricts password reuse' in result.output


def test_a_rollback_the_profile_allowed_still_carries_the_warning(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Reported, never interpreted (UC-1 §4). With both limits numbers the rule
    counts changes this tool cannot see, so the warning does not claim to know
    the outcome and is not withdrawn when the statement succeeds."""
    estate(
        documents=_rolled(),
        users=_reusing(password_reuse_max="1", password_reuse_time="1"),
        answers={"ACME_WEB_USER": drifted()},
    )

    emitted = document(_rollback(runner, write_config(CONFIG), "--output", "json"))

    assert emitted["exit_code"] == ExitCode.SUCCESS
    assert len(_coded(emitted, "SOPULI-W028")) == 1


def test_a_rollback_on_an_unrestricted_profile_carries_no_reuse_warning(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Both limits `UNLIMITED` is Oracle's own `DEFAULT` outside ADB, and the
    regime where a rollback always works -- a warning there would be one every
    reader learns to skip."""
    estate(
        documents=_rolled(),
        users=_reusing(password_reuse_max="UNLIMITED", password_reuse_time="UNLIMITED"),
        answers={"ACME_WEB_USER": drifted()},
    )

    emitted = document(_rollback(runner, write_config(CONFIG), "--output", "json"))

    assert not _coded(emitted, "SOPULI-W028")


def test_a_forward_apply_on_a_reuse_profile_carries_no_reuse_warning(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A staged `pending` is a fresh draw and cannot be in the history, which is
    `SOPULI-W017`'s reasoning and the reason the rollback has a code of its own."""
    estate(
        documents={
            "apps/acme/appdb-alpha": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE},
                "pending": {"acme_web_user": STAGED},
            }
        },
        users=_reusing(),
    )

    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "json")

    assert not _coded(document(result), "SOPULI-W028")


def test_a_rollback_already_in_place_is_not_warned_about(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """No statement, so no reuse history was consulted: the warning is about the
    `ALTER USER` a run sends, not about the profile an account happens to sit on."""
    estate(documents=_rolled(), users=_reusing(), answers={"ACME_WEB_USER": passes()})

    emitted = document(_rollback(runner, write_config(CONFIG), "--output", "json"))

    assert not _coded(emitted, "SOPULI-W028")


# ------------------------------------------ the reuse warning, ahead of time ---


def test_a_preflight_preview_warns_about_a_reuse_profile_before_anything_runs(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`--dry-run --preflight` is "show me the plan, and tell me whether it would
    work", and the profile was already in hand: the survey reads it with
    `describe_user`. So the warning the run raises after the statement is raised
    here, before one is sent -- printed, and in the document."""
    harness = estate(documents=_rolled(), users=_reusing())

    text = _rollback(runner, write_config(CONFIG), "--dry-run", "--preflight")
    emitted = document(
        _rollback(runner, write_config(CONFIG), "--dry-run", "--preflight", "--output", "json")
    )

    assert text.exit_code == ExitCode.SUCCESS
    assert 'profile "SOPULI_REUSE" restricts password reuse' in text.output
    (warned,) = _coded(emitted, "SOPULI-W028")
    assert warned["target"] == "appdb-alpha"
    assert "PASSWORD_REUSE_MAX 5" in warned["message"]
    assert all(session.attempted == [] for session in harness["sessions"])


def test_a_plain_preview_still_connects_to_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A `--dry-run` without `--preflight` costs no logins, and that stays true:
    it cannot see the profile, so it says nothing about it."""
    harness = estate(documents=_rolled(), users=_reusing())

    emitted = document(_rollback(runner, write_config(CONFIG), "--dry-run", "--output", "json"))

    assert harness["sessions"] == []
    assert not _coded(emitted, "SOPULI-W028")


def test_a_preflight_preview_of_a_forward_apply_carries_no_reuse_warning(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The survey is told which pairs are rollbacks; a fresh `pending` on the
    same profile is not one."""
    estate(
        documents={
            "apps/acme/appdb-alpha": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE},
                "pending": {"acme_web_user": STAGED},
            }
        },
        users=_reusing(),
    )

    result = run(
        runner,
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--dry-run",
        "--preflight",
        "--output",
        "json",
    )

    assert not _coded(document(result), "SOPULI-W028")


def test_a_preflight_run_warns_once_not_twice(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """With `--preflight` the survey warns before the statement and the run would
    warn again after it. One (target, profile), one warning."""
    estate(documents=_rolled(), users=_reusing(), set_error=refusal("ORA-28007"))

    result = _rollback(runner, write_config(CONFIG), "--preflight", "--output", "json")
    text = _rollback(runner, write_config(CONFIG), "--preflight")

    assert len(_coded(document(result), "SOPULI-W028")) == 1
    assert text.output.count('profile "SOPULI_REUSE" restricts password reuse') == 1


def test_a_preflight_refusal_still_prints_the_reuse_warning(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A blocking finding beside W028 refuses the run, and the refusal is where
    somebody is already reading -- so the warning is printed there too, not only
    serialised. `_refuse_preflight` has to print the notes it is given, the stale
    `--repair` note included."""
    read_only = Scope(type="pdb", container="ALPHA", read_write=False, open_mode="READ ONLY")
    for extra in (("--dry-run",), ()):
        harness = estate(documents=_rolled(), users=_reusing(), scopes={"appdb-alpha": read_only})

        result = _rollback(runner, write_config(CONFIG), "--preflight", *extra)

        assert result.exit_code == ExitCode.FAILURE, extra
        assert 'profile "SOPULI_REUSE" restricts password reuse' in result.output, extra
        assert all(session.changed == [] for session in harness["sessions"])


def test_no_reuse_warning_ahead_of_a_profile_move(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The policy moves the account onto `ACME_APP_PROF` before the password, so
    the restricted profile read now is not the one the statement meets, and the
    destination's limits are not read. No prediction rather than a false one."""
    estate(documents=_rolled(), users=_reusing())

    emitted = document(
        run(
            runner,
            write_config(ASSIGNING_CONFIG),
            "--select",
            "tenant=alpha",
            "--source",
            "previous",
            "--dry-run",
            "--preflight",
            "--output",
            "json",
        )
    )

    assert not _coded(emitted, "SOPULI-W028")


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


# --------------------------------------------- the redraw (decision #268) ---


def test_a_refused_password_is_replaced_and_the_run_succeeds(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Decision #268, end to end. The server refuses the staged value once;
    the run draws another, stages it, applies it, and promotes that.

    This is the case UC-1 §6.4 is written for: the run does not stop with "go and
    run `creds generate` again, and hope".
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
    warned = [one for one in emitted.get("diagnostics", []) if one["code"] == "SOPULI-W029"]
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
    """An external system dictated this value, so the run reports the refusal
    and leaves `pending` exactly as it found it."""
    harness = estate(documents=staged(origin="supplied"), set_error=refusal(), refusals=1)

    result = run(runner, write_config(REDRAW_CONFIG), "--output", "json")

    assert result.exit_code != ExitCode.SUCCESS
    assert stored(harness["store"], REDRAW_DOCUMENT)["pending"]["acme_web_user"] == STAGED
    declined = [
        one for one in document(result).get("diagnostics", []) if one["code"] == "SOPULI-W030"
    ]
    assert len(declined) == 1
    assert "did not draw" in declined[0]["message"]


def test_a_document_with_no_origin_is_not_redrawn(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A document with no `origin` is treated as supplied, because nothing shows
    the tool drew it. Guessing wrong here overwrites a dictated password, and the
    next `creds generate` heals it."""
    harness = estate(documents=staged(origin=None), set_error=refusal(), refusals=1)

    result = run(runner, write_config(REDRAW_CONFIG), "--output", "json")

    assert stored(harness["store"], REDRAW_DOCUMENT)["pending"]["acme_web_user"] == STAGED
    declined = [
        one for one in document(result).get("diagnostics", []) if one["code"] == "SOPULI-W030"
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
    """The same value is never sent again: `ORA-28007` means this exact password
    is refused, so retrying it is the one thing certain not to work."""
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
        one for one in document(result).get("diagnostics", []) if one["code"] == "SOPULI-W029"
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
        one for one in document(result).get("diagnostics", []) if one["code"] == "SOPULI-W030"
    ]
    assert "no password policy" in declined[0]["message"]


# ------------------------------------------------------------- --repair ---


def _run_document(config: Path, results: list[dict[str, Any]]) -> dict[str, Any]:
    """A `creds check` document over `config`, carrying `results`.

    Built rather than captured, because what is under test is the *filter* and a
    captured document would tie these tests to whatever the estate happened to
    report. The one field that has to be real is `invocation.config_files`: the
    estate check compares it against what this run loaded.
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

    **Exit 4, and that is decision #406.** The account the repair skipped still
    has its `pending` staged, so the document is not promoted by a run that
    never asked its database anything; the narrowing buys the login and the
    promotion waits for a run wide enough to earn it.
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

    assert result.exit_code == ExitCode.PARTIAL
    changed = [name for session in harness["sessions"] for name, _ in session.changed]
    assert changed == ["ACME_BATCH_USER"]


def test_debug_names_a_binding_the_repair_set_left_out(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness, tmp_path: Path
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
    previous = _repair_file(
        tmp_path,
        config,
        [{"account": "acme_batch_user", "target": "appdb-alpha", "state": "DRIFT"}],
    )

    result = run(runner, config, "--repair", str(previous), "--debug")

    assert "acme_web_user on appdb-alpha left out by --repair" in result.stderr
    assert "acme_batch_user on appdb-alpha left out" not in result.stderr
    assert STAGED not in result.stderr
    assert LIVE not in result.stderr


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
    dialled" is the property that saves the logins (decision #264), and an exit
    code alone does not show it.
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
    -- printed as well as serialised."""
    estate(
        documents={
            "apps/acme/db": {
                "DB_CREDENTIALS": {"acme_web_user": LIVE, "acme_batch_user": LIVE},
                "pending": {"acme_batch_user": STAGED},
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
                "pending": {"acme_batch_user": STAGED},
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


# ------------------------------------------------------------------ jsonl ---
#
# `creds apply` streams under `--output jsonl`, and unlike `creds check` it
# changes something. The emitter's own rules -- framing, `seq`, redaction -- are
# `tests/test_output_jsonl.py`'s; these are about what this verb puts through it,
# and whether the stream and the document it stands beside describe one run.

EVENT_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-event-{EVENT_SCHEMA_VERSION}.schema.json"
)


@pytest.fixture
def events() -> Draft202012Validator:
    return Draft202012Validator(json.loads(EVENT_SCHEMA.read_text(encoding="utf-8")))


def stream(result: Result, events: Draft202012Validator) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in result.output.splitlines()]
    for line in lines:
        assert [error.message for error in events.iter_errors(line)] == [], line
    return lines


def sequence(lines: list[dict[str, Any]]) -> list[tuple[str, str | None]]:
    """What happened, in order, without the diagnostics that interleave it."""
    return [
        (line["event"], line.get("target") or (line.get("data") or {}).get("path"))
        for line in lines
        if line["event"] != "diagnostic"
    ]


def partial_estate(estate: Harness) -> dict[str, Any]:
    """Alpha confirms and beta never does: one document promotes, one does not."""
    return estate(
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


def test_jsonl_streams_a_rotation_in_the_order_it_happened(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    events: Draft202012Validator,
) -> None:
    """Lock, read under it, one target at a time, promote, let go -- and only
    then the rows, because a row is not final until its promotion is."""
    estate()
    result = run(runner, write_config(CONFIG), "--output", "jsonl")

    assert result.exit_code == ExitCode.SUCCESS
    lines = stream(result, events)
    alpha, beta = "apps/acme/appdb-alpha", "apps/acme/appdb-beta"
    assert sequence(lines) == [
        ("run.started", None),
        ("plan.resolved", None),
        ("lock.acquired", alpha),
        ("lock.acquired", beta),
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
        ("lock.released", alpha),
        ("lock.released", beta),
        ("target.finished", "appdb-alpha"),
        ("target.finished", "appdb-beta"),
        ("run.finished", None),
    ]
    assert [line["seq"] for line in lines] == list(range(len(lines)))
    assert len({line["correlation_id"] for line in lines}) == 1
    # The version applied is the one read, not the one the promotion produced --
    # and not `null`, which is what the first tier-1 run of this printed.
    read = {
        line["data"]["path"]: line["data"]["version"]
        for line in lines
        if line["event"] == "vault.read"
    }
    applied = [line["data"] for line in lines if line["event"] == "password.applied"]
    assert applied == [
        {"version": read[alpha], "outcome": "IN_SYNC"},
        {"version": read[beta], "outcome": "IN_SYNC"},
    ]
    assert None not in read.values()


def test_a_partial_apply_streams_the_database_change_and_no_promotion(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    events: Draft202012Validator,
) -> None:
    """A database changed and its document not promoted is `password.applied`
    with no `vault.promote` after it -- the same reading a stream cut short by a
    crash gives."""
    partial_estate(estate)
    lines = stream(run(runner, write_config(CONFIG), "--output", "jsonl"), events)

    applied = [line["target"] for line in lines if line["event"] == "password.applied"]
    promoted = [line["data"]["path"] for line in lines if line["event"] == "vault.promote"]
    assert applied == ["appdb-alpha", "appdb-beta"]
    assert promoted == ["apps/acme/appdb-alpha"]
    assert lines[-1]["data"]["exit_code"] == ExitCode.PARTIAL


def test_jsonl_and_json_describe_the_same_apply(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    events: Draft202012Validator,
) -> None:
    """03 §1: a consumer can use either without a second code path. Partial, so
    the exit code, the promotion and the warnings all have something to agree
    about -- and the lock section, which the stream carries as events."""
    config = write_config(CONFIG)
    partial_estate(estate)
    lines = stream(run(runner, config, "--output", "jsonl"), events)
    partial_estate(estate)
    body = document(run(runner, config, "--output", "json"))

    assert lines[-1]["data"] == {"summary": body["summary"], "exit_code": body["exit_code"]}
    assert next(line["data"] for line in lines if line["event"] == "plan.resolved") == body["plan"]

    def comparable(entry: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in entry.items() if key != "duration_ms"}

    streamed = [line["data"] for line in lines if line["event"] == "target.finished"]
    assert [comparable(entry) for entry in streamed] == [
        comparable(entry) for entry in body["results"]
    ]

    def locks(entries: list[dict[str, Any]]) -> list[tuple[str, str, bool]]:
        return [(one["vault"], one["path"], one["released"]) for one in entries]

    released = [line["data"] for line in lines if line["event"] == "lock.released"]
    assert locks(released) == locks(body["lock"]["held"])
    streamed_notes = [line["message"] for line in lines if line["event"] == "diagnostic"]
    assert streamed_notes == [one["message"] for one in body.get("diagnostics", [])]


def test_streamed_apply_payloads_are_the_run_schema_shapes(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    events: Draft202012Validator,
) -> None:
    """03 §5: payloads reuse the run schema's shapes. Checked against its
    `$defs` here rather than by a cross-file `$ref`, which would bind the event
    schema's version to the run schema's."""
    estate()
    lines = stream(run(runner, write_config(CONFIG), "--output", "jsonl"), events)
    defs = json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))["$defs"]

    def shape(pointer: str) -> Draft202012Validator:
        return Draft202012Validator({"$defs": defs, "$ref": f"#/$defs/{pointer}"})

    shapes = {
        "plan.resolved": "plan",
        "target.finished": "result",
        "verification.done": "verification",
        "lock.acquired": "lock/properties/held/items",
        "lock.released": "lock/properties/held/items",
    }
    checks = [
        (shape(shapes[line["event"]]), line["data"]) for line in lines if line["event"] in shapes
    ]
    checks.append((shape("summary"), lines[-1]["data"]["summary"]))
    # One plan, two of each per-target or per-document event, one summary.
    assert len(checks) == 1 + 2 * 4 + 1
    for validator, payload in checks:
        assert [error.message for error in validator.iter_errors(payload)] == [], payload


def test_a_denied_lock_is_streamed_with_its_holder(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    events: Draft202012Validator,
) -> None:
    """Exit 7's one question -- who holds it -- answered on the stream too,
    in the run document's own `lock.denied` shape."""
    harness = estate()
    plant_lock(harness["store"], ALPHA_LOCK, fresh())

    result = run(runner, write_config(CONFIG), "--select", "tenant=alpha", "--output", "jsonl")

    assert isinstance(result.exception, LockDeniedError), result.exception
    lines = stream(result, events)
    denied = [line["data"] for line in lines if line["event"] == "lock.denied"]
    assert len(denied) == 1
    assert denied[0]["path"] == ALPHA_LOCK.path
    assert denied[0]["holder"]["correlation_id"] == "01JSOMEBODYELSE"
    defs = json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))["$defs"]
    shape = Draft202012Validator({"$defs": defs, "$ref": "#/$defs/lock/properties/denied"})
    assert [error.message for error in shape.iter_errors(denied[0])] == []
    assert "target.started" not in [line["event"] for line in lines]


def test_a_dry_run_streams_its_reads_and_takes_no_lock(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    events: Draft202012Validator,
) -> None:
    estate()
    lines = stream(run(runner, write_config(CONFIG), "--dry-run", "--output", "jsonl"), events)

    assert [event for event, _ in sequence(lines)] == [
        "run.started",
        "plan.resolved",
        "vault.read",
        "vault.read",
        "run.finished",
    ]
    assert lines[0]["data"]["dry_run"] is True


def test_no_event_carries_a_password_not_even_a_redrawn_one(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    events: Draft202012Validator,
) -> None:
    """04 §6's release-gate grep, on the stream. The redraw is the path worth
    running: it draws a password this test never chose, stages it and applies
    it, so the only way to know what to grep for is to read it back."""
    harness = estate(documents=staged(), set_error=refusal(), refusals=1)

    result = run(runner, write_config(REDRAW_CONFIG), "--output", "jsonl")

    assert result.exit_code == ExitCode.SUCCESS
    lines = stream(result, events)
    drawn = stored(harness["store"], REDRAW_DOCUMENT)["DB_CREDENTIALS"]["acme_web_user"]
    for secret in (LIVE, STAGED, drawn):
        assert secret not in result.output
    generated = [line for line in lines if line["event"] == "password.generated"]
    assert [line["account"] for line in generated] == ["acme_web_user"]
    assert [line["data"]["stage"] for line in lines if line["event"] == "vault.write"] == [
        "pending"
    ]


def test_a_failure_after_the_statement_still_reports_the_change(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    events: Draft202012Validator,
) -> None:
    """The database took the password and the re-read after it failed. The row
    is `ERROR`, and it is also `changed` -- the database was mutated -- so the
    document counts it and the stream says `password.applied`. A row that said
    `changed: false` would hide exactly the applied-but-not-promoted state the
    stream exists to show."""

    def fail_after_set(harness: dict[str, Any], event: str) -> None:
        if event == "describe_user" and any(one.changed for one in harness["sessions"]):
            raise RuntimeError("ORA-03113: end-of-file on communication channel")

    config = write_config(CONFIG)
    estate(on_call=fail_after_set)
    lines = stream(run(runner, config, "--select", "tenant=alpha", "--output", "jsonl"), events)
    estate(on_call=fail_after_set)
    body = document(run(runner, config, "--select", "tenant=alpha", "--output", "json"))

    assert [line["target"] for line in lines if line["event"] == "password.applied"] == [
        "appdb-alpha"
    ]
    assert "vault.promote" not in [line["event"] for line in lines]
    assert body["results"][0]["state"] == "ERROR"
    assert body["results"][0]["changed"] is True
    assert body["summary"]["changed"] == 1


def test_the_redraw_codes_are_registered() -> None:
    """The redraw codes are in the registry, under its `SOPULI-W` spelling
    (decision #610)."""
    from sopuli.diagnostics import PASSWORD_NOT_REDRAWN, PASSWORD_REDRAWN, WARNINGS

    assert (PASSWORD_REDRAWN, PASSWORD_NOT_REDRAWN) == ("SOPULI-W029", "SOPULI-W030")
    assert PASSWORD_REDRAWN in WARNINGS
    assert PASSWORD_NOT_REDRAWN in WARNINGS

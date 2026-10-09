"""`doctor`'s ``vaults`` section, and what it does to the run (P4).

Tier 0 throughout. The survey opens sockets, but every socket it opens here goes
to a port nobody is listening on -- which needs no container, refuses in
microseconds, and is the one case a live Vault could never produce on demand.
Everything else is a :class:`~sopuli.store.survey.VaultReport` built by hand,
because the store layer's own reading of a `sys/health` answer is tested
against a real Vault there.

Three claims are load-bearing:

* **an unreachable vault fails the run**, at exit 1 and the same as an
  unreachable target. The vault is master (invariant 6), so a store nobody can
  reach is an estate on which no `creds` verb can do anything;
* **a degraded one does not, and neither does a skewed clock.** Something
  answered, and decision P5's argument applies: `doctor` must not refuse to
  survey an estate over a condition the person running it did not create;
* **`summary` still counts targets.** The exit code is deliberately not
  derivable from it, which `_doctor_exit` encodes and which a dead vault makes
  true a second way.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

from conftest import WriteConfig
from sopuli.cli import cli
from sopuli.clock import Skew, measure_skew
from sopuli.diagnostics import (
    CLOCK_SKEW_BEYOND_TOLERANCE,
    STORE_DEGRADED,
    WARNINGS,
    vault_diagnostics,
)
from sopuli.exit_codes import ExitCode
from sopuli.lock.record import CLOCK_SKEW
from sopuli.output.document import SCHEMA_VERSION
from sopuli.output.vault_view import build, render
from sopuli.store import BACKENDS, Backend
from sopuli.store.protocol import DEGRADED, OK, UNREACHABLE, StoreHealth
from sopuli.store.survey import VaultReport

SCHEMA = (
    Path(__file__).resolve().parent.parent
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

NOW = datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC)


def healthy(**overrides: Any) -> StoreHealth:
    fields: dict[str, Any] = {
        "status": OK,
        "version": "2.0.4",
        "server_time": NOW,
        "time_resolution": timedelta(seconds=1),
        "measured_at": NOW,
        "round_trip": timedelta(milliseconds=4),
        "authenticated": True,
    }
    fields.update(overrides)
    return StoreHealth(**fields)


def report(*, name: str = "vault-prod", skew: Skew | None = None, **overrides: Any) -> VaultReport:
    return VaultReport(
        name=name,
        type="hashicorp",
        health=healthy(**overrides),
        skew=skew,
        duration_ms=12,
    )


def skew_of(delta: timedelta, *, round_trip: timedelta = timedelta(0)) -> Skew:
    return measure_skew(server=NOW + delta, local=NOW, round_trip=round_trip, tolerance=CLOCK_SKEW)


# ------------------------------------------------------------- the section ---


def test_the_entry_validates_against_the_schema() -> None:
    """Invariant 12, on the shape 1.15 added."""
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator({**schema["$defs"]["vault_health"], "$defs": schema["$defs"]})

    validator.validate(build(report(skew=skew_of(timedelta(seconds=2)))))


def test_an_unreachable_entry_validates_too() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator({**schema["$defs"]["vault_health"], "$defs": schema["$defs"]})

    validator.validate(
        build(
            VaultReport(
                name="vault-prod",
                type="hashicorp",
                health=StoreHealth(status=UNREACHABLE, detail="connection refused"),
            )
        )
    )


def test_the_skew_fields_are_present_together() -> None:
    entry = build(report(skew=skew_of(timedelta(seconds=-3))))

    assert entry["skew_ms"] == -3000
    assert entry["skew_within_tolerance"] is True
    assert entry["tolerance_ms"] == 60_000
    assert "skew_uncertain_by_ms" in entry


def test_a_store_with_no_clock_reports_no_skew_rather_than_zero() -> None:
    """The confusion the whole measurement exists to avoid.

    `skew_ms: 0` would say the clocks agree. A backend that cannot tell the time
    has not said that, and a consumer alerting on drift must not read one as the
    other.
    """
    entry = build(report(server_time=None, measured_at=None, skew=None))

    assert "skew_ms" not in entry
    assert "server_time" not in entry
    assert "skew_within_tolerance" not in entry


def test_not_asked_about_a_credential_is_absent_rather_than_false() -> None:
    """A sealed store refuses the lookup, and `false` there blames a token for a seal."""
    entry = build(report(status=DEGRADED, detail="sealed", authenticated=None))

    assert "authenticated" not in entry


def test_a_refused_credential_is_reported_as_false() -> None:
    entry = build(report(status=DEGRADED, detail="the credential was refused", authenticated=False))

    assert entry["authenticated"] is False


def test_the_version_is_its_own_field() -> None:
    assert build(report())["version"] == "2.0.4"


def test_milliseconds_are_rounded_and_keep_their_sign() -> None:
    """A negative skew must not round towards zero and lose the direction.

    The sign is the half of the answer that says which clock to go and fix.
    """
    entry = build(report(skew=skew_of(timedelta(milliseconds=-1600))))

    assert entry["skew_ms"] == -1600


# ------------------------------------------------------------ the text form ---


def test_the_table_names_every_store() -> None:
    text = "\n".join(render([report(name="vault-prod"), report(name="vault-dev")]))

    assert "vault-prod" in text
    assert "vault-dev" in text


def test_a_store_with_no_clock_prints_a_dash_and_not_a_number() -> None:
    text = "\n".join(render([report(server_time=None, skew=None)]))

    assert "0ms" not in text


def test_a_skewed_clock_says_which_way_round_in_words() -> None:
    """The sign alone is not enough in a sentence.

    A reader who has to remember whether positive means the store is ahead will
    remember it wrongly half the time, and the two directions are different
    failures: one takes over live locks, the other refuses dead ones.
    """
    ahead = "\n".join(render([report(skew=skew_of(timedelta(minutes=5)))]))
    behind = "\n".join(render([report(skew=skew_of(timedelta(minutes=-5)))]))

    assert "behind" in ahead
    assert "ahead of" in behind


def test_an_unreachable_store_prints_the_reason_beside_the_table() -> None:
    text = "\n".join(
        render(
            [
                VaultReport(
                    name="vault-prod",
                    type="hashicorp",
                    health=StoreHealth(status=UNREACHABLE, detail="connection refused"),
                )
            ]
        )
    )

    assert "connection refused" in text


def test_the_text_form_stays_ascii() -> None:
    """P4: a section sign or an arrow kills the command mid-write on a Windows console."""
    text = "\n".join(
        render(
            [
                report(skew=skew_of(timedelta(minutes=5))),
                report(name="v2", status=DEGRADED, detail="sealed", authenticated=None),
            ]
        )
    )

    text.encode("ascii")


# ------------------------------------------------------------ diagnostics ---


def test_a_healthy_store_says_nothing() -> None:
    assert vault_diagnostics([report(skew=skew_of(timedelta(seconds=1)))]) == []


def test_a_degraded_store_is_a_warning() -> None:
    found = vault_diagnostics([report(status=DEGRADED, detail="sealed", authenticated=None)])

    assert [one.code for one in found] == [STORE_DEGRADED]
    assert found[0].level == "warning"
    assert "sealed" in found[0].message


def test_an_unreachable_store_gets_no_diagnostic() -> None:
    """It fails the run, so anything watching the exit code already knows.

    The `vaults[]` entry names which store and why. A diagnostic as well would
    report one condition twice and give the document two places that can
    disagree -- which is why an unreachable *target* has never had one either.
    """
    found = vault_diagnostics(
        [
            VaultReport(
                name="vault-prod",
                type="hashicorp",
                health=StoreHealth(status=UNREACHABLE, detail="connection refused"),
            )
        ]
    )

    assert found == []


def test_a_skewed_clock_is_a_warning_naming_the_store_and_the_tolerance() -> None:
    found = vault_diagnostics([report(skew=skew_of(timedelta(minutes=5)))])

    assert [one.code for one in found] == [CLOCK_SKEW_BEYOND_TOLERANCE]
    assert found[0].level == "warning"
    assert "vault-prod" in found[0].message
    assert "60s" in found[0].message


def test_a_difference_the_round_trip_explains_is_not_warned_about() -> None:
    """A slow link must not manufacture a warning about a clock that is fine."""
    found = vault_diagnostics(
        [report(skew=skew_of(timedelta(minutes=3), round_trip=timedelta(minutes=8)))]
    )

    assert found == []


def test_one_entry_per_store_rather_than_one_naming_all_of_them() -> None:
    """The operator's unit of action is a vault: one to unseal, one host to fix."""
    found = vault_diagnostics(
        [
            report(name="a", status=DEGRADED, detail="sealed", authenticated=None),
            report(name="b", status=DEGRADED, detail="standby", authenticated=None),
        ]
    )

    assert len(found) == 2


def test_every_code_emitted_is_one_the_registry_describes() -> None:
    """J3: a code is the contract, and one nothing documents is not a contract."""
    found = vault_diagnostics(
        [
            report(name="a", status=DEGRADED, detail="sealed", authenticated=None),
            report(name="b", skew=skew_of(timedelta(minutes=5))),
        ]
    )

    for one in found:
        assert one.code in WARNINGS


# ------------------------------------------------------- through the command ---


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


#: A store at a port nobody is listening on. Needs no container, refuses in
#: microseconds, and is the condition a live Vault cannot be asked to produce.
DEAD = """version: 1
vaults:
  vault-prod:
    type: hashicorp
    addr: http://127.0.0.1:1
    timeout_s: 1
    auth:
      method: token
"""


def _doctor(runner: CliRunner, config: Path) -> Any:
    return runner.invoke(cli, ["--config", str(config), "--output", "json", "doctor"])


def test_the_section_is_present_on_a_run_with_no_vaults_at_all(
    runner: CliRunner, write_config: WriteConfig
) -> None:
    """An empty array, not an absent section -- `install`'s rule and not `wallet`'s.

    Every estate that does anything has stores, so an empty array is a real
    answer here: it says the file declares none. A section that appeared only
    when something was wrong could never be quoted as evidence that nothing was.
    """
    result = _doctor(runner, write_config("version: 1\n"))

    assert result.exit_code == ExitCode.SUCCESS
    assert json.loads(result.output)["vaults"] == []


def test_an_unreachable_vault_fails_the_run(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exit 1, the same as an unreachable target and for a stronger reason.

    The vault is master and the direction is always vault to database (invariant
    6), so a store nobody can reach is an estate on which no `creds` verb can do
    anything -- a wider outage than one dead database rather than a narrower one.
    """
    monkeypatch.setenv("VAULT_TOKEN", "unused-because-nothing-answers")

    result = _doctor(runner, write_config(DEAD))

    assert result.exit_code == ExitCode.FAILURE
    document = json.loads(result.output)
    assert document["vaults"][0]["status"] == UNREACHABLE
    assert document["vaults"][0]["detail"]


def test_a_dead_vault_does_not_inflate_the_target_summary(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`summary` counts targets, and a vault is not one.

    The exit code is deliberately not derivable from the summary -- which
    `_doctor_exit` encodes, and which a dead vault makes true a second way.
    Inflating `failed` to make the arithmetic work would put a number in the
    document that no entry in `targets[]` accounts for.
    """
    monkeypatch.setenv("VAULT_TOKEN", "unused-because-nothing-answers")

    document = json.loads(_doctor(runner, write_config(DEAD)).output)

    assert document["exit_code"] == ExitCode.FAILURE
    assert document["summary"]["total"] == 0
    assert document["summary"]["failed"] == 0


def test_the_whole_document_validates_with_a_vault_in_it(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant 12: the samples validate, and CI is where that is enforced."""
    monkeypatch.setenv("VAULT_TOKEN", "unused-because-nothing-answers")
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    document = json.loads(_doctor(runner, write_config(DEAD)).output)

    Draft202012Validator(schema).validate(document)


def test_a_missing_backend_still_wins_the_exit_code(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Install shape outranks a dead vault, exactly as it outranks a dead target.

    A backend this machine cannot serve makes every store under it unreachable,
    so the two findings arrive together and only one of them names something the
    reader can go and fix. Exit 1 would point at the network and away from the
    one `pip` line.
    """
    monkeypatch.setenv("VAULT_TOKEN", "unused-because-nothing-answers")
    # The registry entry rather than the survey, so what runs is the real code
    # path over a table saying the client is a module this interpreter lacks --
    # the same arrangement `test_install_shape_section.py` uses.
    monkeypatch.setitem(
        BACKENDS,
        "hashicorp",
        Backend(
            module="sopuli.store.hashicorp",
            extra="hashicorp",
            provides=frozenset({"no_such_client"}),
        ),
    )

    result = _doctor(runner, write_config(DEAD))

    assert result.exit_code == ExitCode.CONFIG_INVALID


def test_an_exception_with_no_message_still_produces_a_readable_error(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same empty-message trap one layer up, in the shared error builder.

    `_as_error` is reached by every target and, since this change, by every
    store as well -- so an exception carrying no message would have crashed the
    command that exists to survive its own subject being broken.
    """

    def explode(*_: object, **__: object) -> None:
        raise RuntimeError

    monkeypatch.setattr("sopuli.store.survey.connect", explode)

    document = json.loads(_doctor(runner, write_config(DEAD)).output)

    assert document["vaults"][0]["detail"] == "RuntimeError"
    assert document["vaults"][0]["error"]["message"] == "RuntimeError"

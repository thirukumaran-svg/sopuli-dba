"""Opening every configured store, and never raising while doing it (#216).

The survey's own contract, apart from the section built out of it. Three ways
one store can go and all three are findings:

* it could not be **opened** -- a backend with no module, a client that is not
  installed, a refused login. An exception, caught here, kept whole so the
  boundary can report the category and code it carries;
* it was opened and **could not be reached** -- which arrives as a value rather
  than an exception, because ``health`` is the one method on the store interface
  that does not raise for that;
* it answered.

The tier-1 case at the end is the only one that needs a container, and it is the
one worth having: everything above is this module's reading of an outcome, and
that is the whole path against a real Vault.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from sopuli.config.model import Vault
from sopuli.lock.record import CLOCK_SKEW
from sopuli.store import MemoryStore, SecretStore
from sopuli.store.protocol import OK, UNREACHABLE
from sopuli.store.survey import survey

#: A port nobody is listening on. Needs no container and refuses in
#: microseconds, which is what keeps this whole file in tier 0.
NOWHERE = "http://127.0.0.1:1"


def vault(**overrides: object) -> Vault:
    fields: dict[str, object] = {
        "name": "vault-prod",
        "type": "hashicorp",
        "addr": NOWHERE,
        "timeout_s": 1,
    }
    fields.update(overrides)
    return Vault(**fields)  # type: ignore[arg-type]


def test_an_unreachable_store_is_a_report_and_not_a_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`doctor` surveys an estate: one dead store must not end the run.

    The same rule `targets[]` has followed since #212, and the reason `health`
    returns `unreachable` instead of raising it.
    """
    monkeypatch.setenv("VAULT_TOKEN", "unused-because-nothing-answers")

    report = survey([vault()], env={"VAULT_TOKEN": "unused"})[0]

    assert not report.reachable
    assert report.health.status == UNREACHABLE
    assert report.health.detail


def test_the_survey_continues_past_a_store_it_could_not_open() -> None:
    """The next store is still asked, which is the whole point of catching.

    `oci` is a type the config layer accepts and this build has no module for,
    so it fails at import rather than on the network -- a different failure from
    the one beside it, and neither may swallow the other.
    """
    reports = survey(
        [vault(name="v-oci", type="oci", addr=None), vault(name="v-dead")],
        env={"VAULT_TOKEN": "unused"},
    )

    assert [one.name for one in reports] == ["v-oci", "v-dead"]
    assert all(not one.reachable for one in reports)


def test_a_store_that_could_not_be_opened_keeps_its_exception() -> None:
    """Kept whole rather than flattened to a string.

    A missing backend is `SOPULI-20001` and a refused login is exit 6, and the
    boundary reads both off the exception. Re-deriving them from a message is
    how they stop agreeing with the rest of the document.
    """
    report = survey([vault(type="oci", addr=None)], env={})[0]

    assert report.failure is not None
    assert getattr(report.failure, "category", None) == "config"


def test_a_store_that_was_opened_and_did_not_answer_has_no_exception() -> None:
    """`detail` says why either way; `error` is only for something that threw.

    The distinction the section's docstring turns into a reading order, asserted
    here because it is easy to "fix" by manufacturing an exception so the two
    shapes match -- which would be inventing a classification.
    """
    report = survey([vault()], env={"VAULT_TOKEN": "unused"})[0]

    assert report.failure is None
    assert report.health.detail


def test_stores_are_reported_in_configuration_order() -> None:
    """The file is what the reader has open; a reordered survey hides the row."""
    names = ["zulu", "alpha", "mike"]

    reports = survey([vault(name=name) for name in names], env={"VAULT_TOKEN": "unused"})

    assert [one.name for one in reports] == names


def test_an_unreachable_store_reports_no_skew() -> None:
    """Nothing answered, so there is no clock to compare -- and never a zero."""
    report = survey([vault()], env={"VAULT_TOKEN": "unused"})[0]

    assert report.skew is None


def test_the_default_tolerance_is_the_lock_s(vault_stack: Any) -> None:
    """Tier 1: the whole path against a real Vault, tolerance and all.

    The default is `CLOCK_SKEW` and not a number of this module's choosing,
    because the entire argument for measuring skew is that `sopuli/lock/` already
    allows exactly that much when it decides whether a lease has expired.
    """
    stack = vault_stack

    report = survey(
        [Vault(name="vault-dev", type="hashicorp", addr=stack.addr, mount=stack.kv2_mount)],
        env={"VAULT_TOKEN": stack.token},
    )[0]

    assert report.health.status == OK
    assert report.skew is not None
    assert report.skew.tolerance == CLOCK_SKEW
    # A container shares the runner's clock, so the honest assertion is that the
    # reading is small -- not that it is zero, which whole-second resolution
    # makes it never quite be.
    assert abs(report.skew.delta) < timedelta(seconds=5)
    assert not report.skew.beyond_tolerance


def test_a_host_clock_five_minutes_out_trips_against_a_real_vault(
    vault_stack: Any,
) -> None:
    """Tier 1, and the case the issue asked for by name.

    "Skew is the interesting case and needs a deliberate offset rather than
    whatever the runner's clock happens to be, since a test that only ever sees
    ~0ms proves nothing about the comparison." So the *host* half is the injected
    one and the server half is a real `server_time_utc` off a real Vault.
    """
    stack = vault_stack

    report = survey(
        [Vault(name="vault-dev", type="hashicorp", addr=stack.addr, mount=stack.kv2_mount)],
        env={"VAULT_TOKEN": stack.token},
    )[0]

    assert report.health.measured_at is not None
    skewed = report.health.skew(CLOCK_SKEW, local=report.health.measured_at + timedelta(minutes=5))

    assert skewed is not None
    assert skewed.beyond_tolerance
    assert skewed.delta < timedelta(0)


def test_a_real_vault_accepts_the_token_it_was_opened_with(vault_stack: Any) -> None:
    """Tier 1: `sys/health` takes no token, so this is the half it cannot answer.

    A store whose credential expired answers the health probe perfectly. Without
    the second question a survey would report it `ok` beside a run that can read
    nothing.
    """
    stack = vault_stack

    report = survey(
        [Vault(name="vault-dev", type="hashicorp", addr=stack.addr, mount=stack.kv2_mount)],
        env={"VAULT_TOKEN": stack.token},
    )[0]

    assert report.health.authenticated is True


def test_a_real_vault_refusing_the_token_is_degraded_and_not_ok(
    vault_stack: Any,
) -> None:
    """Tier 1: the credential is wrong and the store is perfectly healthy.

    The one case that would silently pass as `ok` if the survey trusted
    `sys/health` alone -- and the one a laptop cannot fake, because it needs a
    real Vault to refuse a real token.
    """
    stack = vault_stack

    report = survey(
        [Vault(name="vault-dev", type="hashicorp", addr=stack.addr, mount=stack.kv2_mount)],
        env={"VAULT_TOKEN": "not-the-root-token"},
    )[0]

    assert report.reachable
    assert report.health.status != OK
    assert report.health.authenticated is False
    # Still reachable, so it must not fail the run: what the reader does next is
    # look at a token, not at the network.
    assert report.health.status != UNREACHABLE


def test_an_exception_carrying_no_message_does_not_break_the_survey(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one function whose contract is never to raise, raising.

    `"".splitlines()` is `[]`, so an exception with no message at all -- a bare
    `Exception()`, or a vendor client raising a class -- turned the reason for
    one store's failure into an `IndexError` that took the whole survey with it.
    Exactly the crash this module exists to prevent, arriving through the code
    that reports the crash.

    The class name rather than an empty string, because an empty `detail` reads
    as the tool having lost the reason rather than there never having been one.
    """

    def explode(*_: object, **__: object) -> None:
        raise RuntimeError

    monkeypatch.setattr("sopuli.store.survey.connect", explode)

    report = survey([vault()], env={})[0]

    assert report.health.status == UNREACHABLE
    assert report.health.detail == "RuntimeError"


# ------------------------------------------------- the run's client map (#489) ---


def _counting(monkeypatch: pytest.MonkeyPatch, *, fail: bool = False) -> list[str]:
    """Substitute `connect` with one that records each store it opens."""
    opened: list[str] = []

    def fake_connect(vault: Vault, **_: object) -> MemoryStore:
        opened.append(vault.name)
        if fail:
            raise RuntimeError("refused")
        return MemoryStore()

    monkeypatch.setattr("sopuli.store.survey.connect", fake_connect)
    return opened


def test_a_store_the_survey_opens_goes_into_the_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """So the next reader in the same `doctor` run -- a target's `method: vault`
    admin credential -- reuses this login rather than making a second."""
    opened = _counting(monkeypatch)
    cache: dict[str, SecretStore] = {}

    (report,) = survey([vault()], env={}, cache=cache)

    assert report.reachable
    assert opened == ["vault-prod"]
    assert list(cache) == ["vault-prod"]


def test_a_store_already_in_the_cache_is_not_opened_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The cache is read as well as filled, which is `_stores_for`'s contract."""
    opened = _counting(monkeypatch)
    cache: dict[str, SecretStore] = {"vault-prod": MemoryStore()}

    (report,) = survey([vault()], env={}, cache=cache)

    assert report.reachable
    assert opened == []


def test_a_store_that_could_not_be_opened_is_not_cached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A later reader tries it again and reports its own failure, rather than
    inheriting this survey's or finding nothing where a client should be."""
    _counting(monkeypatch, fail=True)
    cache: dict[str, SecretStore] = {}

    (report,) = survey([vault()], env={}, cache=cache)

    assert not report.reachable
    assert cache == {}


def test_without_a_cache_nothing_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every caller but `doctor` passes none, and opens one client per store."""
    opened = _counting(monkeypatch)

    survey([vault(), vault(name="vault-other")], env={})
    survey([vault()], env={})

    assert opened == ["vault-prod", "vault-other", "vault-prod"]

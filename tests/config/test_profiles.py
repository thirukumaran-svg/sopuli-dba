"""The ``profiles:`` section -- how a run is invoked (§5).

The parsing tests are ordinary. The ones that matter are the blocklist: §5's
whole point is that a profile changes *behaviour* and never *scope*, and a
selector-shaped option that is not a selector is a bad footgun in a tool that
rotates credentials. Each blocked key asserts on the message, not just the
exception, because "unknown key 'targets'" beside a list of known keys would send
somebody looking for the right spelling of a thing that must not exist here.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.profiles import build_profiles

SCHEDULED: dict[str, Any] = {
    "verify": {"method": "hash"},
    "output": "jsonl",
    "log_level": "warning",
}


def document(**profiles: Any) -> dict[str, Any]:
    return {"version": 1, "profiles": profiles}


def only(**keys: Any) -> Any:
    built = build_profiles(document(scheduled={**SCHEDULED, **keys}))
    assert len(built) == 1
    return built[0]


def test_a_profile_is_read_whole() -> None:
    profile = only(
        confirm=False,
        safety={"max_targets": 200},
        db={"connect_timeout_s": 30, "query_timeout_s": 120},
        rotation={"strategy": "staged"},
        vault="vault-prod",
        log_file="/var/log/sopuli.log",
    )

    assert profile.name == "scheduled"
    assert profile.verify.method == "hash"
    assert profile.output == "jsonl"
    assert profile.log_level == "warning"
    assert profile.log_file == "/var/log/sopuli.log"
    assert profile.confirm is False
    assert profile.safety is not None
    assert profile.safety.max_targets == 200
    assert profile.db.connect_timeout_s == 30
    assert profile.db.query_timeout_s == 120
    assert profile.rotation_strategy == "staged"
    assert profile.vault == "vault-prod"


def test_a_config_may_declare_no_profiles() -> None:
    assert build_profiles({"version": 1}) == ()


def test_profiles_keep_document_order() -> None:
    built = build_profiles(document(ci=SCHEDULED, scheduled=SCHEDULED))

    assert [profile.name for profile in built] == ["ci", "scheduled"]


# ------------------------------------------------------------- blocklist ---


@pytest.mark.parametrize(
    ("key", "value", "because"),
    [
        ("accounts", ["acme_web_user"], "must not vary by how you invoked the tool"),
        ("applications", [], "must not vary by how you invoked the tool"),
        ("secret", "ops/db#password", "must not vary by how you invoked the tool"),
        ("secret_template", "t/{account}", "must not vary by how you invoked the tool"),
        ("targets", ["cdb-root-dev"], "a profile is not a selector"),
        ("target_sets", {}, "a profile is not a selector"),
        ("groups", {}, "a profile is not a selector"),
        ("environment", "dev", "you cannot relabel prod as dev"),
        ("policies", {}, "a weaker password policy is a reviewed config change"),
    ],
)
def test_a_profile_may_not_change_what_a_run_acts_on(key: str, value: Any, because: str) -> None:
    """§5's blocklist. Every one of these is a wrong model rather than a typo, so
    the message says what a profile is instead of listing the known keys."""
    with pytest.raises(ConfigError) as caught:
        build_profiles(document(scheduled={**SCHEDULED, key: value}))

    rendered = str(caught.value)
    assert f"a profile may not set `{key}:`" in rendered
    assert because in rendered
    assert f"profiles.scheduled.{key}" in rendered


def test_a_blocked_key_is_not_reported_as_a_typo() -> None:
    """The distinction the blocklist exists to make: no list of known keys,
    because none of them is the one that was wanted."""
    with pytest.raises(ConfigError) as caught:
        build_profiles(document(scheduled={"targets": ["cdb-root-dev"]}))

    assert "known keys here" not in str(caught.value)


def test_an_ordinary_typo_still_gets_the_known_keys() -> None:
    with pytest.raises(ConfigError) as caught:
        build_profiles(document(scheduled={"ouput": "json"}))

    rendered = str(caught.value)
    assert "unknown key 'ouput'" in rendered
    assert "known keys here" in rendered


# ------------------------------------------------------------ closed sets ---


@pytest.mark.parametrize("output", ["text", "json", "jsonl"])
def test_every_output_format_is_accepted(output: str) -> None:
    assert only(output=output).output == output


def test_an_unknown_output_format_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_profiles(document(scheduled={"output": "yaml"}))

    assert "unknown output format 'yaml'" in str(caught.value)


def test_an_unknown_log_level_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_profiles(document(scheduled={"log_level": "verbose"}))

    assert "unknown log level 'verbose'" in str(caught.value)


def test_a_profile_may_only_set_the_rotation_strategy() -> None:
    """§5 lists `rotation.strategy` and nothing else. `rollover_hours` describes
    the credential's lifecycle, which belongs to the estate rather than to the
    machine running the command."""
    with pytest.raises(ConfigError) as caught:
        build_profiles(document(scheduled={"rotation": {"rollover_hours": 4}}))

    assert "unknown key 'rollover_hours'" in str(caught.value)


# ----------------------------------------------------------------- vault ---


def test_vault_is_a_store_name() -> None:
    assert only(vault="vault-prod").vault == "vault-prod"


def test_the_vault_block_form_is_refused_and_points_at_vaults() -> None:
    """§5's case -- token from a laptop, AppRole from CI -- is real, and C13 (#31)
    decided it is spelt `profiles.ci.vaults.<name>.auth`, not `vault.auth`:
    `vault:` names the store, `vaults:` describes it. The profile block arrives
    with the vault layer (#103), so the whitelist still refuses `vaults:` here;
    what this pins is that the mapping under `vault:` names its replacement."""
    with pytest.raises(ConfigError) as caught:
        build_profiles(document(scheduled={"vault": {"auth": {"method": "approle"}}}))

    rendered = str(caught.value)
    assert "is a store name, not a mapping" in rendered
    assert "`vaults:` keyed by its name" in rendered


# ------------------------------------------------------------------- db ---


@pytest.mark.parametrize("key", ["connect_timeout_s", "query_timeout_s"])
def test_a_timeout_below_one_second_is_refused(key: str) -> None:
    """A zero timeout is a hang, not an unlimited budget."""
    with pytest.raises(ConfigError) as caught:
        build_profiles(document(scheduled={"db": {key: 0}}))

    rendered = str(caught.value)
    assert f"{key} must be at least 1 second" in rendered
    assert "not an unlimited budget" in rendered


def test_safety_in_a_profile_is_read_like_any_other() -> None:
    """§5 resolution rule 5: a profile may ask for a looser blast radius, and the
    ratchet decides whether it gets one. Reading it is this layer's whole job."""
    profile = only(safety={"max_targets": 200, "confirm_environments": ["prod"]})

    assert profile.safety is not None
    assert profile.safety.max_targets == 200
    assert profile.safety.confirm_environments == ("prod",)

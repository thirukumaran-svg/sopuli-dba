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
from sopuli.config.loading import build_config
from sopuli.config.profiles import build_profiles, select_profile

SCHEDULED: dict[str, Any] = {
    "output": "jsonl",
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
        vault="vault-prod",
    )

    assert profile.name == "scheduled"
    assert profile.output == "jsonl"
    assert profile.confirm is False
    assert profile.safety is not None
    assert profile.safety.max_targets == 200
    assert profile.db.connect_timeout_s == 30
    assert profile.db.query_timeout_s == 120
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


@pytest.mark.parametrize("key", ["log_level", "log_file"])
def test_a_removed_log_key_is_refused_as_removed(key: str) -> None:
    """A config cannot turn on debug output (#629), and the refusal says the key
    was removed, so it does not read as a typo."""
    with pytest.raises(ConfigError) as caught:
        build_profiles(document(scheduled={key: "debug"}))

    assert f"`{key}:` was removed from profiles" in str(caught.value)
    assert "--debug" in str(caught.value)


@pytest.mark.parametrize(
    ("block", "value", "flags"),
    [
        ("verify", {"method": "hash"}, ("--method", "--lockout-margin")),
        ("rotation", {"strategy": "staged"}, ("--strategy",)),
    ],
)
def test_a_removed_block_is_refused_as_removed(
    block: str, value: dict[str, Any], flags: tuple[str, ...]
) -> None:
    """No run read either block, so they were removed (#787). The refusal names
    the flags that set what the block named."""
    with pytest.raises(ConfigError) as caught:
        build_profiles(document(scheduled={block: value}))

    rendered = str(caught.value)
    assert f"`{block}:` was removed from profiles" in rendered
    assert all(flag in rendered for flag in flags)


# ----------------------------------------------------------------- vault ---


def test_vault_is_a_store_name() -> None:
    assert only(vault="vault-prod").vault == "vault-prod"


def test_the_vault_block_form_is_refused_and_points_at_vaults() -> None:
    """§5's case -- token from a laptop, AppRole from CI -- is real, and C13
    decides it is spelt `profiles.ci.vaults.<name>.auth`, not `vault.auth`:
    `vault:` names the store, `vaults:` describes it. What this pins is that the
    mapping under `vault:` names its replacement."""
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


# ------------------------------------------------------------- activation ---
#
# §5's resolution rules 1 and 6. The chain itself -- `--profile`, then
# `SOPULI_PROFILE`, then `defaults.profile` -- is merged by the one resolver and
# arrives here as one name; what this layer decides is what that name resolves
# to, and what happens when it resolves to nothing.


def test_no_name_anywhere_leaves_no_profile_active() -> None:
    """ "Else none" is a real answer, and not the same as an empty profile: a run
    with none is one where layer 3 supplied nothing at all."""
    assert select_profile((), requested=None, declared_default=None) is None


def test_a_requested_name_selects_that_profile() -> None:
    profiles = build_profiles(document(ci={"output": "json"}, scheduled=SCHEDULED))

    active = select_profile(profiles, requested="ci", declared_default=None)

    assert active is not None
    assert active.name == "ci"


def test_defaults_profile_answers_when_nothing_was_requested() -> None:
    profiles = build_profiles(document(ci={"output": "json"}, scheduled=SCHEDULED))

    active = select_profile(profiles, requested=None, declared_default="scheduled")

    assert active is not None
    assert active.name == "scheduled"


def test_a_requested_name_outranks_defaults_profile() -> None:
    """Rule 4: layer 5 is the bottom of the file, and a name from above it wins."""
    profiles = build_profiles(document(ci={"output": "json"}, scheduled=SCHEDULED))

    active = select_profile(profiles, requested="ci", declared_default="scheduled")

    assert active is not None
    assert active.name == "ci"


def test_an_unknown_requested_name_is_refused_and_never_falls_back() -> None:
    """Rule 6, and the reason it is a rule: a typo in `--profile` that quietly
    gave you `defaults.profile` would give a scheduler interactive behaviour."""
    profiles = build_profiles(document(scheduled=SCHEDULED))

    with pytest.raises(ConfigError) as caught:
        select_profile(profiles, requested="schedluled", declared_default="scheduled")

    rendered = str(caught.value)
    assert "no profile named 'schedluled' is declared" in rendered
    assert "declared profiles: scheduled" in rendered


def test_an_unknown_defaults_profile_names_the_key_it_was_written_in() -> None:
    """A name the file wrote has a line to go and fix; one typed does not."""
    profiles = build_profiles(document(scheduled=SCHEDULED))

    with pytest.raises(ConfigError) as caught:
        select_profile(profiles, requested=None, declared_default="nosuch")

    rendered = str(caught.value)
    assert "defaults.profile" in rendered
    assert "no profile named 'nosuch' is declared" in rendered


def test_the_refusal_says_so_when_the_file_declares_no_profiles_at_all() -> None:
    with pytest.raises(ConfigError) as caught:
        select_profile((), requested="ci", declared_default=None)

    assert "there is no `profiles:`" in str(caught.value)


def test_selecting_a_profile_reaches_the_built_config() -> None:
    """Through `build_config`, because that is where the name is handed in and
    where everything downstream of it -- the vault patch -- reads the answer."""
    built = build_config({**document(ci={"output": "json"}), "defaults": {"profile": "ci"}})

    assert built.active_profile is not None
    assert built.active_profile.name == "ci"


def test_a_config_built_without_a_name_has_no_active_profile() -> None:
    built = build_config(document(scheduled=SCHEDULED))

    assert built.profiles != ()
    assert built.active_profile is None

"""``defaults:`` and ``runtime:`` -- the two sections about this installation.

Small, and one of them carries a question worth keeping visible: the reference
uses `defaults.vault` as a store *name* in §3 and as a block in P3's precedence
table, and one key cannot be both.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.defaults import build_defaults, build_runtime
from sopuli.config.errors import ConfigError


def document(**sections: Any) -> dict[str, Any]:
    return {"version": 1, **sections}


def test_defaults_are_read_whole() -> None:
    defaults = build_defaults(
        document(
            defaults={
                "vault": "vault-prod",
                "policy": "app-standard",
                "profile": "interactive",
                "safety": {"max_targets": 1, "confirm_environments": ["prod"]},
            }
        )
    )

    assert defaults.vault == "vault-prod"
    assert defaults.policy == "app-standard"
    assert defaults.profile == "interactive"
    assert defaults.safety is not None
    assert defaults.safety.max_targets == 1
    assert defaults.safety.confirm_environments == ("prod",)


def test_a_config_may_declare_no_defaults() -> None:
    empty = build_defaults(document())

    assert empty.vault is None
    assert empty.safety is None


def test_an_unknown_defaults_key_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_defaults(document(defaults={"polciy": "app-standard"}))

    rendered = str(caught.value)
    assert "unknown key 'polciy'" in rendered
    assert "known keys here: locking, policy, profile, safety, vault" in rendered


def test_the_vault_block_form_is_refused_and_points_at_vaults() -> None:
    """C13: `vault:` is a store *name* everywhere, and settings of
    a store are reached by naming it under `vaults:`. So `defaults.vault.addr` --
    P3's old example of layer 5 -- is now `defaults.vaults.<name>.addr`, and the
    mapping under `vault:` is refused with the form that replaces it.
    """
    with pytest.raises(ConfigError) as caught:
        build_defaults(document(defaults={"vault": {"addr": "https://vault.example.com"}}))

    rendered = str(caught.value)
    assert "is a store name, not a mapping" in rendered
    assert "`vaults:` keyed by its name" in rendered
    assert "defaults.vault" in rendered


# ---------------------------------------------------------------- runtime ---


def test_the_oracle_client_directory_is_read() -> None:
    runtime = build_runtime(
        document(runtime={"oracle": {"client_lib_dir": "C:\\Oracle\\instantclient_23_0"}})
    )

    assert runtime.oracle.client_lib_dir == "C:\\Oracle\\instantclient_23_0"


def test_a_config_may_declare_no_runtime() -> None:
    assert build_runtime(document()).oracle.client_lib_dir is None


def test_an_empty_runtime_is_allowed() -> None:
    """Unlike a target's `oracle: {}`, this is a section rather than a field
    group -- an installation with nothing to say about itself is the normal case,
    and `runtime:` left behind as a heading is not a half-finished sentence."""
    assert build_runtime(document(runtime={})).oracle.client_lib_dir is None


def test_an_unknown_runtime_key_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_runtime(document(runtime={"orcale": {}}))

    assert "unknown key 'orcale'" in str(caught.value)


def test_an_unknown_oracle_runtime_key_is_refused() -> None:
    """`runtime.oracle` is about the machine the tool runs on, not the database.
    A connection setting written here would look configured and do nothing."""
    with pytest.raises(ConfigError) as caught:
        build_runtime(document(runtime={"oracle": {"client_lib_dirs": "/opt/oracle"}}))

    rendered = str(caught.value)
    assert "unknown key 'client_lib_dirs'" in rendered
    assert "runtime.oracle" in rendered

"""A policy's `rotation:` and `verify:` keys warn that nothing reads them
(decision #610).

They validate, so without a warning a file writing them reads as configuring a
run. The verbs take these from flags; these tests pin the warning and its hint.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.codes import UNREAD_POLICY_KEYS
from sopuli.config.loading import build_config


def _policy(**blocks: Any) -> dict[str, Any]:
    return {
        "version": 1,
        "policies": {"app-standard": {"password": {"length": 24}, **blocks}},
    }


def test_a_policy_with_neither_block_does_not_warn() -> None:
    assert build_config(_policy()).warnings == ()


def test_each_block_warns_once_naming_its_keys() -> None:
    config = build_config(
        _policy(
            rotation={"strategy": "rollover", "max_age_days": 90},
            verify={"method": "hash"},
        )
    )

    found = {warning.at: warning for warning in config.warnings}
    assert set(found) == {"policies.app-standard.rotation", "policies.app-standard.verify"}
    rotation = found["policies.app-standard.rotation"]
    assert rotation.message == "`strategy`, `max_age_days` are parsed and not read"
    assert "`strategy` with `--strategy`" in str(rotation.hint)
    assert "`max_age_days` with `--max-age-days`" in str(rotation.hint)
    assert found["policies.app-standard.verify"].message == "`method` is parsed and not read"
    assert {warning.code for warning in config.warnings} == {UNREAD_POLICY_KEYS}


def test_a_key_no_flag_sets_says_so() -> None:
    """`keep_previous` has no flag, so the hint must not point at one."""
    config = build_config(_policy(rotation={"keep_previous": True}))

    (warning,) = config.warnings
    assert warning.hint == "no run reads these from a policy; nothing sets `keep_previous`"

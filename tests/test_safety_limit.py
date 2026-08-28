"""`safety.max_targets`, finally asked of something (#247).

The setting has been parsed since the config model was written and ratcheted
since the resolver was, and until now nothing read the answer. P5: "`--limit` /
`--max-targets` prevents a wildcard from hitting 200 PDBs by accident."

What is worth testing here is not the arithmetic. It is the two places a
plausible implementation goes wrong: counting the wrong noun, and inventing a
default the registry deliberately does not have.
"""

from __future__ import annotations

import pytest

from sopuli.exit_codes import ExitCode
from sopuli.plan import BlastRadius
from sopuli.safety import MAX_TARGETS, RefusedError, refuse_if_over_limit
from sopuli.settings import Contribution, Layer, Resolved, resolve


def ceiling(
    value: int | None, *, detail: str = "defaults.safety.max_targets"
) -> dict[str, Resolved]:
    """The resolver's answer for `max_targets`, or nobody having set one."""
    if value is None:
        return {}
    resolved = resolve(MAX_TARGETS, [Contribution(Layer.DEFAULTS, value, detail)])
    assert resolved is not None
    return {MAX_TARGETS: resolved}


def radius(targets: int, accounts: int = 1) -> BlastRadius:
    return BlastRadius(targets=targets, accounts=accounts, environments=("dev",))


# ------------------------------------------------------------ what it counts ---


def test_it_refuses_a_run_over_the_ceiling() -> None:
    with pytest.raises(RefusedError) as raised:
        refuse_if_over_limit(ceiling(20), radius(200), action="rotating")

    assert "200 targets" in str(raised.value)
    assert f"`{MAX_TARGETS}` is 20" in str(raised.value)


def test_a_run_exactly_at_the_ceiling_is_allowed() -> None:
    """`max_targets: 20` is a permission to reach twenty, not nineteen. Reading
    it the other way makes every number in every config file off by one."""
    refuse_if_over_limit(ceiling(20), radius(20), action="rotating")


def test_it_counts_targets_and_not_accounts() -> None:
    """Six accounts in one PDB is one target's worth of reach.

    The failure this guards is an implementation that counted units: it would
    refuse a run `max_targets: 1` was never aimed at, and the operator would have
    no way to express what they meant.
    """
    refuse_if_over_limit(ceiling(1), radius(targets=1, accounts=6), action="rotating")


# ----------------------------------------------------------- the non-default ---


def test_an_unset_ceiling_is_no_ceiling() -> None:
    """The registry gives `max_targets` no built-in on purpose: "an unset
    max_targets is no limit, which is not the same claim as a default limit the
    tool chose". P5's "default 1" is about *confirmation*, a different gate."""
    refuse_if_over_limit(ceiling(None), radius(200), action="rotating")


# -------------------------------------------------------------- the refusal ---


def test_the_refusal_carries_exit_8_and_the_policy_category() -> None:
    """Not a failure and not a bad file: the run did what it was configured to
    do. `refuse_if_readonly` settled this shape and this inherits it."""
    with pytest.raises(RefusedError) as raised:
        refuse_if_over_limit(ceiling(1), radius(2), action="rotating")

    assert raised.value.exit_code is ExitCode.ABORTED
    assert raised.value.category == "policy"


def test_the_hint_names_where_the_setting_was_written() -> None:
    """A ceiling an operator did not know about is the whole reason this refusal
    is confusing when it arrives, and `Resolved.location` is already the answer."""
    with pytest.raises(RefusedError) as raised:
        refuse_if_over_limit(
            ceiling(1, detail="profiles.ci.safety.max_targets"), radius(2), action="rotating"
        )

    assert "profiles.ci.safety.max_targets" in str(raised.value)


def test_the_action_appears_so_the_operator_knows_what_stopped() -> None:
    with pytest.raises(RefusedError, match="checking"):
        refuse_if_over_limit(ceiling(1), radius(2), action="checking")

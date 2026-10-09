"""`safety.confirm_environments`, asked of the run's plan.

The resolver ratchets the setting as a union, and `confirmation_demanded` reads
the answer. A config that looks like protection has to be protection. P5: "every
mutating command supports `--confirm`/`--yes`; interactive confirmation is
required by default when … the target is marked `environment: prod`."

What is worth testing is not the set intersection. It is the three places a
plausible implementation goes wrong: matching against the estate instead of the
run, inventing a built-in the registry deliberately does not have, and treating
a target with no environment as matching something.
"""

from __future__ import annotations

import pytest

from sopuli.exit_codes import ExitCode
from sopuli.plan import BlastRadius
from sopuli.safety import (
    CONFIRM_ENVIRONMENTS,
    RefusedError,
    confirmation_demanded,
    refuse_unconfirmed,
)
from sopuli.settings import Contribution, Layer, Resolved, resolve


def listed(
    *environments: str, detail: str = "defaults.safety.confirm_environments"
) -> dict[str, Resolved]:
    """The resolver's answer for the setting, or nobody having written one."""
    if not environments:
        return {}
    resolved = resolve(
        CONFIRM_ENVIRONMENTS, [Contribution(Layer.DEFAULTS, tuple(environments), detail)]
    )
    assert resolved is not None
    return {CONFIRM_ENVIRONMENTS: resolved}


def radius(*environments: str, targets: int = 1) -> BlastRadius:
    return BlastRadius(targets=targets, accounts=1, environments=environments)


# ------------------------------------------------------------ what it matches ---


def test_a_listed_environment_demands_confirmation() -> None:
    demand = confirmation_demanded(listed("prod"), radius("prod"))

    assert demand is not None
    assert demand.environments == ("prod",)
    assert demand.location == "defaults.safety.confirm_environments"


def test_an_unlisted_environment_does_not() -> None:
    assert confirmation_demanded(listed("prod"), radius("dev")) is None


def test_it_matches_against_the_run_and_not_the_estate() -> None:
    """The failure this guards is a gate that asks on every run.

    An estate declaring prod somewhere is the ordinary case; a run narrowed to
    dev by a selector reaches none of it. An implementation that consulted the
    config rather than the blast radius would prompt every time, and a setting
    that always asks is one that gets turned off within a week.
    """
    assert confirmation_demanded(listed("prod"), radius("dev", "staging")) is None


def test_only_the_reached_environments_are_named() -> None:
    """An operator who wrote `[prod, staging]` and is touching only staging
    should be asked about staging. Naming both would tell them their run reaches
    prod, which is the one thing they would act on and the one thing untrue."""
    demand = confirmation_demanded(listed("prod", "staging"), radius("staging"))

    assert demand is not None
    assert demand.environments == ("staging",)


def test_several_reached_environments_keep_estate_order() -> None:
    """A set's ordering would make the same two environments read as a different
    two between runs, which is `BlastRadius`'s own argument for keeping them
    ordered."""
    demand = confirmation_demanded(listed("prod", "staging"), radius("staging", "prod"))

    assert demand is not None
    assert demand.environments == ("staging", "prod")


def test_a_target_with_no_environment_matches_nothing() -> None:
    """`environment:` is optional, and `BlastRadius` contributes nothing for a
    target that declares none rather than an empty string -- so an entry matching
    `""` would be a rule nobody wrote."""
    assert confirmation_demanded(listed("prod"), radius()) is None


def test_matching_is_exact_rather_than_case_folded() -> None:
    """§6 already refuses to let an override relabel an environment, so two
    spellings of prod in one estate is a config problem to see rather than one to
    paper over in a comparison."""
    assert confirmation_demanded(listed("prod"), radius("PROD")) is None


# ----------------------------------------------------------- the non-default ---


def test_an_unset_setting_asks_nothing() -> None:
    """The registry gives it no built-in, and that is not an oversight: a
    built-in taking part in a union ratchet would be an unremovable floor, so
    `confirm_environments: [prod]` as a default could never be removed by any
    layer. §9's own worked example of that trap is `confirm`."""
    assert confirmation_demanded(listed(), radius("prod")) is None


def test_an_empty_list_asks_nothing() -> None:
    """The source layer reports an empty list as `None` deliberately -- a key
    nobody wrote and one written empty mean the same thing under a union -- and
    this must agree with it rather than treat `()` as a live setting."""
    resolved = resolve(CONFIRM_ENVIRONMENTS, [Contribution(Layer.DEFAULTS, (), "defaults")])
    answer = {} if resolved is None else {CONFIRM_ENVIRONMENTS: resolved}

    assert confirmation_demanded(answer, radius("prod")) is None


# -------------------------------------------------------------- the refusal ---


def test_the_refusal_carries_exit_8_and_the_policy_category() -> None:
    """`refuse_if_readonly` settled this shape and this inherits it: the file is
    not wrong and the run is not broken -- somebody wrote down that this
    environment needs a yes, and there was no yes."""
    demand = confirmation_demanded(listed("prod"), radius("prod"))
    assert demand is not None

    with pytest.raises(RefusedError) as raised:
        refuse_unconfirmed(demand, action="applying a password", targets=1)

    assert raised.value.exit_code is ExitCode.ABORTED
    assert raised.value.category == "policy"


def test_the_refusal_names_the_environment_and_the_reach() -> None:
    demand = confirmation_demanded(listed("prod"), radius("prod", targets=9))
    assert demand is not None

    with pytest.raises(RefusedError) as raised:
        refuse_unconfirmed(demand, action="applying a password", targets=9)

    assert "9 targets" in str(raised.value)
    assert "`prod`" in str(raised.value)


def test_the_hint_names_where_the_setting_was_written_and_what_to_type() -> None:
    """A `confirm_environments` an operator did not know about is the whole
    reason this refusal is confusing when it arrives -- and unlike `readonly`,
    there is something to type that proceeds, so the hint has to say so."""
    demand = confirmation_demanded(
        listed("prod", detail="profiles.scheduled.safety.confirm_environments"),
        radius("prod"),
    )
    assert demand is not None

    with pytest.raises(RefusedError) as raised:
        refuse_unconfirmed(demand, action="applying a password", targets=1)

    assert "profiles.scheduled.safety.confirm_environments" in str(raised.value.hint)
    assert "--confirm" in str(raised.value.hint)
    assert "--dry-run" in str(raised.value.hint)


def test_one_environment_and_several_read_correctly() -> None:
    """Grammar, and it is worth a test because the refusal is the whole output of
    the run that hits it."""
    one = confirmation_demanded(listed("prod"), radius("prod"))
    many = confirmation_demanded(listed("prod", "staging"), radius("prod", "staging"))
    assert one is not None
    assert many is not None

    with pytest.raises(RefusedError) as single:
        refuse_unconfirmed(one, action="rotating", targets=1)
    with pytest.raises(RefusedError) as plural:
        refuse_unconfirmed(many, action="rotating", targets=2)

    assert "1 target in `prod`" in str(single.value)
    assert "that environment" in str(single.value)
    assert "2 targets in `prod, staging`" in str(plural.value)
    assert "those environments" in str(plural.value)

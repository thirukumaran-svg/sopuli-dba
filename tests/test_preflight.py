"""What a pre-flight decides, before anything is written (UC-1 §8 step 3, #283).

Tier 0: every function under test is of values a caller already holds, so the
whole decision table is here without a container. The survey that produces those
values is `tests/test_cli_creds_apply.py`'s.

Two properties carry most of it, and both are about restraint:

* **an assertion nobody made always holds** -- the estate that filled nothing in
  is not the estate that filled it in wrongly;
* **not knowing is not the same as knowing something bad** -- an open mode the
  driver could not read is not a read-only database, and a privilege audit that
  was refused has established nothing either way.
"""

from __future__ import annotations

from sopuli import preflight
from sopuli.driver.protocol import Scope


def scope(**fields: object) -> Scope:
    return Scope(**{"type": "pdb", "container": "ALPHA", "read_write": True, **fields})  # type: ignore[arg-type]


# ------------------------------------------------------------ the assertion ---


def test_a_target_that_asserts_nothing_holds() -> None:
    """§3a's assertion is opt-in, and treating "said nothing" as "said something
    wrong" would refuse every estate that had not filled the field in."""
    assert preflight.assertion_holds(declared_scope=None, declared_container=None, scope=scope())


def test_a_container_matches_whatever_case_it_was_written_in() -> None:
    """An Oracle identifier is upper-cased on the way in, so `freepdb1` and
    `FREEPDB1` are one name rather than a mismatch to refuse a run over."""
    assert preflight.assertion_holds(declared_scope=None, declared_container="alpha", scope=scope())


def test_a_container_that_moved_does_not_hold() -> None:
    """The edit this check exists for: a `dsn:` repointed at a different
    container, where everything keeps working against the wrong database."""
    assert not preflight.assertion_holds(
        declared_scope=None, declared_container="alpha", scope=scope(container="BETA")
    )


def test_a_scope_that_disagrees_does_not_hold() -> None:
    assert not preflight.assertion_holds(
        declared_scope="cdb", declared_container=None, scope=scope()
    )


# ---------------------------------------------------------------- the survey ---


def test_a_clean_target_produces_nothing() -> None:
    assert preflight.survey("appdb-alpha", scope=scope()) == ()


def test_a_mismatch_names_both_values() -> None:
    """So the reader can see which of the two is wrong -- the file or the estate
    -- rather than being told only that they disagree."""
    (found,) = preflight.survey(
        "appdb-alpha", scope=scope(container="BETA"), declared_container="ALPHA"
    )

    assert found.check == preflight.SCOPE
    assert "'ALPHA'" in found.message
    assert "'BETA'" in found.message


def test_a_read_only_database_is_refused_up_front() -> None:
    """P1: on a physical standby the answer is false, and the refusal belongs
    before the statement rather than half way through it."""
    (found,) = preflight.survey("appdb-alpha", scope=scope(read_write=False, open_mode="READ ONLY"))

    assert found.check == preflight.SCOPE
    assert found.blocking


def test_an_unknown_open_mode_is_not_a_read_only_database() -> None:
    """A driver that could not determine it has not established that the database
    is read-only, and refusing on the unknown would turn a missing probe into an
    outage."""
    assert preflight.survey("appdb-alpha", scope=scope(read_write=None)) == ()


def test_a_missing_account_is_named_on_its_own_finding() -> None:
    """Per account rather than per target: which one is missing is the whole
    content of the finding."""
    found = preflight.survey(
        "appdb-alpha", scope=scope(), missing_accounts=["acme_web_user", "acme_batch_user"]
    )

    assert [one.account for one in found] == ["acme_web_user", "acme_batch_user"]
    assert all(one.check == preflight.ACCOUNT for one in found)


def test_missing_privileges_are_one_finding_and_are_authorization() -> None:
    """One install script to run, so one finding -- and the category is what a
    consumer branches on, which is not the same question as `check`."""
    (found,) = preflight.survey(
        "appdb-alpha",
        scope=scope(),
        missing_privileges=["GRANT ALTER USER", "GRANT CREATE SESSION"],
    )

    assert found.check == preflight.PRIVILEGES
    assert found.category == "authorization"
    assert "GRANT ALTER USER, GRANT CREATE SESSION" in found.message


def test_a_missing_profile_names_the_account_that_wanted_it() -> None:
    """#301. Per account, because two accounts on one target can sit under
    different policies -- and a message naming only the profile would leave the
    reader hunting for which account asked for it."""
    (found,) = preflight.survey(
        "appdb-alpha",
        scope=scope(),
        missing_profiles=[("acme_web_user", "ACME_APP_PROF")],
    )

    assert found.check == preflight.PROFILE
    assert found.account == "acme_web_user"
    assert "ACME_APP_PROF" in found.message
    assert found.category == "config"
    assert found.blocking


def test_a_missing_profile_says_the_tool_will_not_create_one() -> None:
    """Q4's position, in the place an operator meets it: sopuli assigns a profile
    and never creates or alters one."""
    (found,) = preflight.survey(
        "appdb-alpha", scope=scope(), missing_profiles=[("acme_web_user", "ACME_APP_PROF")]
    )

    assert found.hint is not None
    assert "never creates or alters" in found.hint


def test_a_missing_account_outranks_the_profile_it_wanted() -> None:
    """An account the database has not got explains everything else about it, so
    the profile question is not the one to send somebody to first."""
    findings = (
        preflight.Finding("appdb-alpha", preflight.PROFILE, "no such profile"),
        preflight.Finding("appdb-alpha", preflight.ACCOUNT, "no such user"),
    )

    found = preflight.refusal(findings)

    assert found is not None
    assert found.check == preflight.ACCOUNT


# ------------------------------------------------------------- the refusal ---


def test_the_refusal_is_the_check_closest_to_the_cause() -> None:
    """A container that turned out to be the wrong one explains every account
    that was not found in it, so reporting the account first would send somebody
    to the wrong problem."""
    findings = (
        preflight.Finding("appdb-alpha", preflight.ACCOUNT, "no such user"),
        preflight.Finding("appdb-alpha", preflight.SCOPE, "wrong container"),
    )

    found = preflight.refusal(findings)

    assert found is not None
    assert found.check == preflight.SCOPE


def test_unreachable_outranks_everything() -> None:
    findings = (
        preflight.Finding("appdb-beta", preflight.PRIVILEGES, "missing GRANT ALTER USER"),
        preflight.unreachable("appdb-alpha", message="ORA-12541"),
    )

    found = preflight.refusal(findings)

    assert found is not None
    assert found.target == "appdb-alpha"
    assert found.category == "connectivity"


def test_a_survey_of_caveats_alone_refuses_nothing() -> None:
    """An estate that will not grant the audit view must still be able to run a
    pre-flight; the caveat is reported and the run goes ahead."""
    findings = (
        preflight.Finding("appdb-alpha", preflight.PRIVILEGES, "could not be read", blocking=False),
    )

    assert preflight.refusal(findings) is None


def test_nothing_found_refuses_nothing() -> None:
    assert preflight.refusal(()) is None


def test_the_summary_counts_only_what_blocks() -> None:
    """A consumer reading one message needs to know whether it is looking at the
    whole problem or the first of several -- and a caveat is not a problem."""
    findings = (
        preflight.Finding("appdb-alpha", preflight.SCOPE, "wrong container"),
        preflight.Finding("appdb-beta", preflight.ACCOUNT, "no such user"),
        preflight.Finding("appdb-beta", preflight.PRIVILEGES, "unreadable", blocking=False),
    )

    line = preflight.summarise(findings)

    assert "2 problems over 2 targets" in line
    assert "appdb-alpha: wrong container" in line


def test_one_problem_reads_as_one() -> None:
    findings = (preflight.Finding("appdb-alpha", preflight.SCOPE, "wrong container"),)

    assert "1 problem over 1 target," in preflight.summarise(findings)

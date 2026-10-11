"""UC-1 §6.4's table, and the three rules that shape it.

Tier 0: a code and a message are two strings, so none of this needs a database.
What the tier-1 work adds later is the assurance that a real server really does
send these codes in these situations -- not what they mean, which is
decided here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sopuli.driver.oracle.errors import (
    ACCOUNT_LOCKED,
    CLIENT_LIBRARY,
    CONTAINER_MISUSE,
    EXPIRED,
    INSUFFICIENT_PRIVILEGE,
    INVALID_CREDENTIALS,
    LOCKED,
    PASSWORD_EXPIRED,
    PASSWORD_IN_GRACE,
    PASSWORD_REJECTED,
    PASSWORD_REUSED,
    RULES,
    UNKNOWN,
    UNREACHABLE,
    VERIFIER_MISMATCH,
    WALLET,
    Diagnosis,
    MappedError,
    classify,
    from_error,
)
from sopuli.driver.protocol import AuthenticationError, DriverError
from sopuli.exit_codes import ExitCode
from sopuli.output.document import SCHEMA_VERSION

RUN_SCHEMA = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

#: A message in the shape the server really sends one, so that "preserved
#: verbatim" is asserted against something that would be obvious if it were not.
SERVER = "ORA-01017: invalid username/password; logon denied"


def schema(name: str) -> Any:
    return json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))["$defs"][name]


# ------------------------------------------------------------ the vocabulary ---


def test_every_category_is_one_the_run_document_has() -> None:
    """A category the schema has never heard of would fail validation at the
    boundary, on a run that had already failed once."""
    documented = set(schema("error")["properties"]["category"]["enum"])

    assert {rule.category for rule in RULES.values()} <= documented


def test_every_state_is_one_the_run_document_has() -> None:
    documented = set(schema("state")["enum"])
    states = {rule.state for rule in RULES.values() if rule.state}

    assert states == {LOCKED, EXPIRED}
    assert states <= documented


def test_the_table_covers_every_row_uc1_names() -> None:
    """§6.4 is the specification, so its codes are the checklist.

    Named rather than counted: a row silently dropped in an edit is exactly what
    a length assertion would miss.
    """
    assert set(RULES) >= {
        "ORA-28003",
        "ORA-28007",
        "ORA-01017",
        "ORA-28000",
        "ORA-28001",
        "ORA-28002",
        "ORA-01031",
        "ORA-65040",
        "ORA-65048",
        "ORA-65066",
        "ORA-12154",
        "ORA-12541",
        "ORA-28040",
        "ORA-28759",
        "ORA-28768",
    }


# ------------------------------------------------------------ what rows mean ---


def test_the_servers_own_message_survives() -> None:
    """CLAUDE.md: never swallow an ORA- code -- map it, and preserve the
    server's message. The hint is added beside it, never over it."""
    found = classify("ORA-01017", SERVER)

    assert found.message == SERVER
    assert found.code == "ORA-01017"
    assert found.hint is not None
    assert SERVER in str(found.as_error())


@pytest.mark.parametrize(
    ("code", "kind"),
    [("ORA-28003", PASSWORD_REJECTED), ("ORA-28007", PASSWORD_REUSED)],
)
def test_a_refused_password_means_draw_another_and_never_resend(code: str, kind: str) -> None:
    """UC-1 §4 step 3's bounded loop, and the one thing that certainly will not
    work: sending the same value again.

    Two codes, two kinds, one consequence -- kept distinct because the *reason*
    reaches the operator: a verify function refusing a candidate and a reuse
    policy refusing one are different things to read at 03:00.
    """
    found = classify(code, "refused")

    assert found.kind == kind
    assert found.regenerate
    assert not found.retryable
    assert found.category == "policy"


def test_regenerate_and_retryable_are_never_the_same_row() -> None:
    """They mean opposite things about the *value*: one says it was bad, the
    other says the call was unlucky. A row claiming both would license a loop
    that resends a password the server has already refused."""
    for code in RULES:
        found = classify(code, "…")
        assert not (found.regenerate and found.retryable)


def test_invalid_credentials_carries_exit_six_and_leaves_the_verdict_open() -> None:
    """The row that cannot decide for its caller.

    Reaching the database as the admin account is exit 6; the same code from a
    verification login is DRIFT, exit 3, and `creds check`'s whole reason for
    existing. So the diagnosis carries the authentication reading and
    :meth:`Diagnosis.as_error` is only called by the caller that means it.
    """
    found = classify("ORA-01017", SERVER)

    assert found.kind == INVALID_CREDENTIALS
    assert found.exit_code == ExitCode.AUTH_FAILURE
    assert found.state is None
    assert isinstance(found.as_error(), AuthenticationError)


def test_lock_and_expiry_are_states_rather_than_drift() -> None:
    """UC-1 §7 mitigation 6: one ORA-01017 otherwise hides an expired password,
    a locked account and a genuinely wrong one behind one word."""
    assert classify("ORA-28000", "locked").state == LOCKED
    assert classify("ORA-28000", "locked").kind == ACCOUNT_LOCKED
    assert classify("ORA-28001", "expired").state == EXPIRED
    assert classify("ORA-28001", "expired").kind == PASSWORD_EXPIRED


def test_a_grace_period_is_informational_and_sets_no_state() -> None:
    """The row it would be easiest to edit wrongly, because it is the one that
    is not a failure.

    A password in its grace period still authenticates, so this must **not**
    carry a state: reporting `EXPIRED` here would tell an operator an account
    was unusable when it works, and `creds status` is where the warning belongs
    (UC-1 §9).
    """
    found = classify("ORA-28002", "the password will expire within 7 days")

    assert found.kind == PASSWORD_IN_GRACE
    assert found.category == "database"
    assert found.state is None
    assert not found.regenerate


def test_a_privilege_failure_names_the_grant_to_go_and_get() -> None:
    found = classify("ORA-01031", "insufficient privileges")

    assert found.kind == INSUFFICIENT_PRIVILEGE
    assert found.category == "authorization"
    assert found.hint is not None
    assert "ALTER USER" in found.hint


def test_a_container_misuse_is_a_config_problem_on_exit_nine() -> None:
    """The same landing as `statements.ContainerScopeError`, deliberately.

    Seeing ORA-65040 at all means the client-side guardrail did not do its job,
    since `container_clause` refuses that combination before a statement exists.
    It maps anyway: a guardrail that was bypassed is exactly when a clear message
    matters most.
    """
    found = classify("ORA-65040", "ORA-65040: unsupported operation")

    assert found.kind == CONTAINER_MISUSE
    assert found.category == "config"
    assert found.exit_code == ExitCode.CONFIG_INVALID


def test_an_application_common_account_says_where_to_rotate_it_instead() -> None:
    """``ORA-65066`` is reachable because ``app_pdb`` is not refused up front.

    An application-common account in an application PDB is refused by Oracle
    itself, measured both ways: this code with no container clause and
    ``ORA-65040`` with ``CONTAINER=ALL``. `container_clause` cannot pre-empt it,
    because an application-common name carries no marker to recognise it by --
    ``C##`` is forbidden in an application container (``ORA-60534``) -- so the
    message is the whole of the help the operator gets.
    """
    found = classify("ORA-65066", "ORA-65066: The specified changes must apply to all containers")

    assert found.kind == CONTAINER_MISUSE
    assert found.category == "config"
    assert found.exit_code == ExitCode.CONFIG_INVALID
    assert found.hint is not None
    assert "application root" in found.hint


def test_a_verifier_mismatch_explains_the_password_version_trap() -> None:
    """The failure that looks like a wrong password and is not: a password over
    30 bytes silently drops clients still on the 10G/11G verifiers."""
    found = classify("ORA-28040", "no matching authentication protocol")

    assert found.kind == VERIFIER_MISMATCH
    assert found.hint is not None
    assert "PASSWORD_VERSIONS" in found.hint


def test_only_a_plainly_transient_failure_is_marked_retryable() -> None:
    """`retryable` is the run document's field and a report, not an instruction:
    a listener that is down may come up, and nothing in sopuli loops on it."""
    assert classify("ORA-12541", "no listener").retryable
    assert not classify("ORA-12154", "could not resolve").retryable
    assert not classify("ORA-01017", SERVER).retryable


@pytest.mark.parametrize("code", ["ORA-28759", "ORA-28768"])
def test_a_wallet_failure_is_connectivity_and_says_where_to_look(code: str) -> None:
    """#472: neither message names a file, a wallet or TLS, so the hint does.

    Connectivity, not the `database` fallback: the server never saw the
    connection. Not retryable: the file stays missing until somebody fixes it.
    """
    found = classify(code, f"{code}: failure")

    assert found.kind == WALLET
    assert found.category == "connectivity"
    assert found.exit_code == ExitCode.FAILURE
    assert not found.retryable
    assert found.hint is not None
    assert "cwallet.sso" in found.hint
    assert "retry_count" in found.hint


def test_the_wallet_open_hint_lists_every_cause_it_cannot_tell_apart() -> None:
    """A missing wallet, a WALLET_LOCATION that points elsewhere and an
    unreadable `cwallet.sso` all raise ORA-28759 (measured, #472)."""
    hint = classify("ORA-28759", "ORA-28759: failure to open file").hint

    assert hint is not None
    assert "TNS_ADMIN" in hint
    assert "WALLET_LOCATION" in hint
    assert "readable" in hint


def test_the_client_library_is_a_local_problem_the_reader_can_fix() -> None:
    """Exit 9 and `config`, the same landing ADR-006 gives a backend that is
    configured and not installed -- fixed on this machine, by the person reading
    the message."""
    for code in ("DPI-1047", "DPY-3001"):
        found = classify(code, "…")
        assert found.kind == CLIENT_LIBRARY
        assert found.exit_code == ExitCode.CONFIG_INVALID
        assert found.hint is not None
        assert "Instant Client" in found.hint


def test_the_thin_mode_hint_gives_the_reasons_and_does_not_blame_oci() -> None:
    """D3 has three reasons and the hint names all three.

    What it must not say is that OCI-hosted databases require Native Network
    Encryption: an Autonomous Database uses TLS, and the operator most likely to
    read this hint is one pointing the tool at exactly that.
    """
    hint = classify("DPY-3001", "…").hint
    assert hint is not None
    assert "Native Network Encryption" in hint
    assert "12.1" in hint
    assert "external password store" in hint
    assert "OCI" not in hint
    assert "Autonomous" not in hint


# ------------------------------------------------------------ the fallbacks ---


def test_an_unnamed_net_error_lands_with_its_family() -> None:
    """ORA-12514 is not in the table and is unmistakably connectivity.

    The range is what stops it being reported as a database failure, which would
    send the operator to look at the wrong machine entirely.
    """
    found = classify("ORA-12514", "listener does not currently know of service")

    assert found.kind == UNREACHABLE
    assert found.category == "connectivity"


def test_an_unmapped_code_is_terminal_and_never_regenerates() -> None:
    """The decision, not the absence of one.

    An unclassified code might be transient and might be a value the server will
    refuse forever; of the two ways to be wrong, looping is the one that locks
    accounts. Drawing a fresh password would change the vault's state on the
    strength of a guess.
    """
    found = classify("ORA-00600", "internal error code")

    assert found.kind == UNKNOWN
    assert found.category == "database"
    assert not found.retryable
    assert not found.regenerate
    assert found.message == "internal error code"


def test_an_unmapped_client_code_is_still_placed_on_this_side_of_the_wire() -> None:
    assert classify("DPY-4011", "the database closed the connection").category == "connectivity"


def test_a_mapped_error_carries_the_rows_own_category_and_exit() -> None:
    """The class attributes are the default for a failure nobody classified;
    an instance carries what its code actually means."""
    raised = classify("ORA-65040", "…").as_error()

    assert isinstance(raised, MappedError)
    assert isinstance(raised, DriverError)
    assert raised.category == "config"
    assert raised.exit_code == ExitCode.CONFIG_INVALID
    assert raised.code == "ORA-65040"


def test_a_mapped_error_carries_regenerate_where_the_row_sets_it() -> None:
    """The seam for `creds apply`'s redraw. `sopuli.apply` is vendor-neutral and
    must not import this module to learn that Oracle refused a password, so the
    answer this row already computes travels on the exception `DriverError`
    declares it on."""
    assert classify("ORA-28003", "…").as_error().regenerate is True
    assert classify("ORA-28007", "…").as_error().regenerate is True


def test_every_other_mapped_error_denies_it_without_being_asked() -> None:
    """The default on the class, not a rule each row restates. A connectivity
    failure is not evidence about the password, and neither is a code nobody has
    classified."""
    assert classify("ORA-01031", "…").as_error().regenerate is False
    assert classify("ORA-99999", "…").as_error().regenerate is False
    assert DriverError("something went wrong").regenerate is False


# ------------------------------------------------------------- the extraction ---


class _Detail:
    """``oracledb``'s error object, in the shape this reads it."""

    full_code = "ORA-28007"
    code = 28007
    message = "ORA-28007: the password cannot be reused"


class _DatabaseError(Exception):
    """What the client raises, without importing the client to say so."""


class _ColonDetail:
    """A detail object whose code carries the punctuation of the message."""

    full_code = "ORA-01017:"
    message = SERVER


def test_a_vendor_exception_is_read_structurally() -> None:
    """No ``oracledb`` import, which is what keeps this module in tier 0 and
    importable in a base install."""
    found = from_error(_DatabaseError(_Detail()))

    assert found.code == "ORA-28007"
    assert found.kind == PASSWORD_REUSED
    assert found.message == _Detail.message


def test_a_code_is_recovered_from_the_message_when_there_is_no_detail() -> None:
    """The case that would otherwise be misplaced rather than merely unknown.

    An exception whose ``args[0]`` is a plain string has no ``full_code``, and
    without recovery an ``ORA-12154`` reports as a *database* failure — sending
    the operator to the wrong machine, which is what the Net/TNS range exists to
    prevent.
    """
    found = from_error(_DatabaseError("ORA-12154: TNS:could not resolve the connect identifier"))

    assert found.code == "ORA-12154"
    assert found.kind == UNREACHABLE
    assert found.category == "connectivity"


def test_recovering_a_code_never_rewrites_the_message() -> None:
    original = "ORA-01017: invalid username/password; logon denied"

    assert from_error(_DatabaseError(original)).message == original


def test_only_the_leading_code_is_read() -> None:
    """An ORA-28003 commonly carries an ORA-20000 from the verify function
    further along the message. The first one is what happened; the second is why,
    and it belongs in the message the operator reads rather than in the row that
    was matched."""
    found = from_error(
        _DatabaseError("ORA-28003: password verification failed\nORA-20000: too short")
    )

    assert found.code == "ORA-28003"
    assert found.kind == PASSWORD_REJECTED
    assert "ORA-20000" in found.message


def test_a_code_with_a_trailing_colon_still_matches_its_row() -> None:
    """A row that fails to match because of punctuation does not fail loudly --
    it silently becomes `unknown`, which is the one wrong answer that looks like
    an ordinary result."""
    assert classify("ORA-01017", SERVER).kind == from_error(_DatabaseError(_ColonDetail())).kind


def test_an_exception_carrying_nothing_recognisable_still_diagnoses() -> None:
    """ "The driver raised something we cannot read" is a failure the operator
    has to hear about in the same shape as every other -- not a KeyError, and not
    an AttributeError from this module."""
    found = from_error(_DatabaseError("something went wrong"))

    assert found.kind == UNKNOWN
    assert found.message == "something went wrong"
    assert isinstance(found, Diagnosis)


def test_an_exception_with_no_args_at_all_still_diagnoses() -> None:
    found = from_error(_DatabaseError())

    assert found.kind == UNKNOWN
    assert found.code == ""

"""Reading an account's state (#178). Tier 0.

The mapping from Oracle's dictionary onto `UserState` is pure, so it is tested
here. Every literal in this file — the compound `ACCOUNT_STATUS` strings, the
`DEFAULT` limit, the space-separated `PASSWORD_VERSIONS` — was read off 26ai Free
23.26.2.0.0 rather than invented, because the shapes are the part that cannot be
reasoned out.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest

from sopuli.constraints import NAMED, NONE, UNKNOWN
from sopuli.driver.oracle.accounts import (
    NAME_QUERY,
    PROFILE_NAME_QUERY,
    PROFILE_QUERY,
    PTIME_QUERY,
    PWFILE_QUERY,
    ROLE_NAME_QUERY,
    ROLES_QUERY,
    USER_QUERY,
    USER_QUERY_LEGACY,
    USER_QUERY_NO_CHANGE_DATE,
    DictionaryUnreadableError,
    RolesUnreadableError,
    describe,
    password_constraints,
    password_file_member,
    resolve_name,
    resolve_profile,
    resolve_role,
)
from sopuli.driver.protocol import DriverError

CHANGED = datetime(2026, 8, 22, 10, 41, 36)

#: `EXPIRY_DATE`, which both queries select last (#309). Naive, as `oracledb`
#: hands back an Oracle `DATE` -- the point of the fixture is that the driver
#: meets one, not that a test can build an aware datetime.
EXPIRES = datetime(2026, 9, 21, 10, 41, 36)


class _Cursor:
    """A cursor answering per statement, with `fetchall` for the multi-row reads."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.asked: list[str] = []
        self.sql = ""

    def execute(self, sql: str, parameters: Any = None, /) -> _Cursor:
        self.asked.append(sql)
        self.sql = sql
        return self

    def _answer(self) -> Any:
        answer = self.answers.get(self.sql)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def fetchone(self) -> Any:
        answer = self._answer()
        return answer[0] if isinstance(answer, list) and answer else answer

    def fetchall(self) -> Any:
        answer = self._answer()
        return answer if isinstance(answer, list) else []


def _ora(code: str, message: str = "") -> RuntimeError:
    return RuntimeError(f"{code}: {message or 'something the server said'}")


def _cursor(
    *,
    status: str = "OPEN",
    profile: str | None = "ACME_PROF",
    versions: str | None = "11G 12C",
    maintained: str | None = "N",
    changed: datetime | None = CHANGED,
    expires: datetime | None = EXPIRES,
    limits: list[tuple[str, str]] | None = None,
    roles: list[tuple[str]] | None = None,
    pwfile: Any = (0,),
) -> _Cursor:
    return _Cursor(
        {
            USER_QUERY: (
                "ACME_ORDERS_USER",
                status,
                profile,
                versions,
                maintained,
                changed,
                expires,
            ),
            PROFILE_QUERY: limits if limits is not None else [("FAILED_LOGIN_ATTEMPTS", "5")],
            ROLES_QUERY: roles if roles is not None else [],
            # `count(*)`, so a readable view always answers with a row. An
            # `ORA-00942` here is the ungranted view, which is the ordinary case
            # -- see the password-file section below.
            PWFILE_QUERY: pwfile,
        }
    )


# ------------------------------------------------------------ account status ---


def test_a_healthy_account_is_neither_locked_nor_expired() -> None:
    state = describe(_cursor(status="OPEN"), "acme_orders_user")

    assert state is not None
    assert not state.locked
    assert not state.expired
    assert not state.rollover_active
    assert state.status == "OPEN"


@pytest.mark.parametrize(
    ("status", "locked", "expired", "in_grace", "rollover"),
    [
        ("OPEN", False, False, False, False),
        ("OPEN & IN ROLLOVER", False, False, False, True),
        ("LOCKED", True, False, False, False),
        ("LOCKED(TIMED)", True, False, False, False),
        ("LOCKED & IN ROLLOVER", True, False, False, True),
        ("EXPIRED", False, True, False, False),
        ("EXPIRED & IN ROLLOVER", False, True, False, True),
        ("EXPIRED & LOCKED & IN ROLLOVER", True, True, False, True),
        # The three grace forms, all measured 2026-09-02 (#309). `expired` is
        # False in every one of them: the password still authenticates.
        ("EXPIRED(GRACE)", False, False, True, False),
        ("EXPIRED(GRACE) & LOCKED", True, False, True, False),
        ("EXPIRED(GRACE) & LOCKED(TIMED)", True, False, True, False),
    ],
)
def test_the_status_is_read_as_tokens_not_as_a_value(
    status: str, locked: bool, expired: bool, in_grace: bool, rollover: bool
) -> None:
    """`ACCOUNT_STATUS` is compound and `&`-joined.

    Every combination above was produced on 26ai -- the first eight by locking,
    expiring and rotating one account in turn, the three grace forms by a profile
    with a one-minute `PASSWORD_LIFE_TIME` (#309). Comparing the column to a value
    rather than reading tokens out of it would report
    `EXPIRED & LOCKED & IN ROLLOVER` as none of the three.

    **`EXPIRED(GRACE)` is the case the tokens are not enough for**, and it is why
    `expired` is not a bare substring test: the grace spelling *contains*
    `EXPIRED`, and an account in it still works. Reading the two as one made
    `check` report a healthy account as expired and skip the login that would
    have proved otherwise.
    """
    state = describe(_cursor(status=status), "acme_orders_user")

    assert state is not None
    assert state.locked is locked
    assert state.expired is expired
    assert state.in_grace is in_grace
    assert state.rollover_active is rollover


def test_expired_and_in_grace_are_never_both_true() -> None:
    """They are opposite claims about one password -- it has stopped working, or
    it has not -- and a caller reading either alone must not be able to see both.

    Asserted over every status this driver can meet rather than over the grace
    forms alone, because the trap is a *substring*: any future spelling carrying
    both tokens would satisfy two mutually exclusive fields at once.
    """
    for status in (
        "OPEN",
        "EXPIRED",
        "EXPIRED(GRACE)",
        "EXPIRED(GRACE) & LOCKED",
        "EXPIRED(GRACE) & LOCKED(TIMED)",
        "EXPIRED & LOCKED & IN ROLLOVER",
    ):
        state = describe(_cursor(status=status), "acme_orders_user")

        assert state is not None
        assert not (state.expired and state.in_grace), status


def test_the_status_is_reported_verbatim_as_well_as_parsed() -> None:
    """UC-1 §7 mitigation 6 wants `ACCOUNT_STATUS` reported unconditionally, so
    that `LOCKED`, `LOCKED (TIMED)` and `EXPIRED` stay three states rather than
    one `ORA-01017`. The flags are a convenience over it, never a replacement."""
    state = describe(_cursor(status="LOCKED(TIMED)"), "acme_orders_user")

    assert state is not None
    assert state.status == "LOCKED(TIMED)"


def test_an_open_rollover_window_reports_a_derived_end_date() -> None:
    """The dictionary says a window is open and never when it closes.

    #178 left this `None` rather than present an inference as a reading. #181
    reversed it, after searching `DBA_*` and the `V$` views and finding no column
    that exposes the end: the choice is between Oracle's own documented
    arithmetic over two values that *were* read and telling an operator nothing
    about their deadline. It is the one computed field in `UserState`.
    """
    state = describe(
        _cursor(
            status="OPEN & IN ROLLOVER",
            limits=[("PASSWORD_ROLLOVER_TIME", "1")],
            changed=CHANGED,
        ),
        "acme_orders_user",
    )

    assert state is not None
    assert state.rollover_active is True
    assert state.rollover_ends_at == CHANGED + timedelta(days=1)


def test_a_closed_window_has_no_end_to_report() -> None:
    """Populated only while a window is open: ending one early leaves the change
    date untouched, so the derivation would point into a future that no longer
    applies."""
    state = describe(
        _cursor(status="OPEN", limits=[("PASSWORD_ROLLOVER_TIME", "1")]), "acme_orders_user"
    )

    assert state is not None
    assert state.rollover_ends_at is None


# ------------------------------------------------------------------- absence ---


def test_a_missing_account_is_a_state_and_not_an_error() -> None:
    """UC-1's `ACCOUNT_MISSING`. The tool does not create accounts (Q8), so this
    is something to report rather than something to recover from."""
    cursor = _Cursor({USER_QUERY: None, USER_QUERY_NO_CHANGE_DATE: None, USER_QUERY_LEGACY: None})

    assert describe(cursor, "acme_no_such_user") is None


@pytest.mark.parametrize("code", ["ORA-00942", "ORA-01031", "ORA-41900"])
def test_an_unreadable_dba_users_is_a_missing_grant_and_not_a_missing_account(
    code: str,
) -> None:
    """#521. The probes' `read()` turned these into `None`, and `None` here is
    `ACCOUNT_MISSING` -- so a service account without the grant reported every
    account in the estate as absent, and the operator went looking for accounts
    rather than for a grant."""
    cursor = _Cursor({USER_QUERY: _ora(code, 'table or view "SYS"."DBA_USERS" does not exist')})

    with pytest.raises(DictionaryUnreadableError) as raised:
        describe(cursor, "acme_orders_user")

    assert raised.value.code == code
    assert "DBA_USERS" in raised.value.message, "the server's message is kept"
    assert "GRANT SELECT ON SYS.DBA_USERS" in (raised.value.hint or "")
    assert cursor.asked == [USER_QUERY], "a refused grant is not narrowed past"


def test_an_unrelated_failure_is_classified_rather_than_called_a_grant() -> None:
    cursor = _Cursor({USER_QUERY: _ora("ORA-03113", "end-of-file on communication channel")})

    with pytest.raises(DriverError) as raised:
        describe(cursor, "acme_orders_user")

    assert not isinstance(raised.value, DictionaryUnreadableError)
    assert raised.value.code == "ORA-03113"


def test_an_answered_query_with_no_row_is_not_asked_again() -> None:
    """The absence is the answer. The narrower shapes ask the same question and
    cannot change it."""
    cursor = _Cursor({USER_QUERY: None})

    assert describe(cursor, "acme_no_such_user") is None
    assert cursor.asked == [USER_QUERY]


def test_a_missing_column_on_the_narrowest_shape_is_not_an_absent_account() -> None:
    """`ORA-00904` narrows only while there is a narrower shape to try. On the
    last one it means the view is not what any release has, which is a failure
    rather than an account nobody created."""
    cursor = _Cursor(
        {
            USER_QUERY: _ora("ORA-00904"),
            USER_QUERY_NO_CHANGE_DATE: _ora("ORA-00904"),
            USER_QUERY_LEGACY: _ora("ORA-00904", '"EXPIRY_DATE": invalid identifier'),
        }
    )

    with pytest.raises(DriverError) as raised:
        describe(cursor, "acme_orders_user")

    assert raised.value.code == "ORA-00904"


def test_resolving_a_name_without_the_grant_raises() -> None:
    cursor = _Cursor({NAME_QUERY: _ora("ORA-00942")})

    with pytest.raises(DictionaryUnreadableError) as raised:
        resolve_name(cursor, "acme_orders_user")

    assert raised.value.code == "ORA-00942"


def test_resolving_a_name_the_database_has_not_got_is_none() -> None:
    assert resolve_name(_Cursor({NAME_QUERY: None}), "acme_no_such_user") is None


@pytest.mark.parametrize(
    ("resolve", "query", "view"),
    [
        (resolve_role, ROLE_NAME_QUERY, "DBA_ROLES"),
        (resolve_profile, PROFILE_NAME_QUERY, "DBA_PROFILES"),
    ],
)
def test_resolving_a_predicate_without_the_grant_raises(
    resolve: Any, query: str, view: str
) -> None:
    """#531. Read through the probes' rule, an ungranted view was "no such role",
    and the predicate was refused as a misspelling."""
    with pytest.raises(DictionaryUnreadableError) as raised:
        resolve(_Cursor({query: _ora("ORA-00942")}), "acme_dev_team")

    assert raised.value.code == "ORA-00942"
    assert f"GRANT SELECT ON SYS.{view}" in (raised.value.hint or "")


@pytest.mark.parametrize(
    ("resolve", "query"),
    [(resolve_role, ROLE_NAME_QUERY), (resolve_profile, PROFILE_NAME_QUERY)],
)
def test_a_predicate_naming_nothing_is_none(resolve: Any, query: str) -> None:
    assert resolve(_Cursor({query: None}), "acme_no_such_thing") is None


# --------------------------------------------------------------- the columns ---


def test_the_name_is_the_spelling_the_database_gave_back() -> None:
    """#171 puts this in the statement, never the raw string from config."""
    state = describe(_cursor(), "acme_orders_user")

    assert state is not None
    assert state.name == "ACME_ORDERS_USER"


def test_password_versions_are_split_on_spaces() -> None:
    """`"11G 12C"` is one column carrying a list, and a client still on the 11G
    verifier is what a password over 30 bytes silently breaks."""
    state = describe(_cursor(versions="11G 12C"), "acme_orders_user")

    assert state is not None
    assert state.password_versions == ("11G", "12C")


def test_the_effective_failed_login_limit_is_reported() -> None:
    """`DBA_PROFILES` reports the string `DEFAULT` for a resource the profile
    does not set — measured on a profile created with one limit, which reported
    `DEFAULT` for the other eight. `PROFILE_QUERY` resolves it in the database,
    so a word can never reach a caller expecting a threshold."""
    state = describe(_cursor(limits=[("FAILED_LOGIN_ATTEMPTS", "5")]), "acme_orders_user")

    assert state is not None
    assert state.failed_login_limit == "5"


def test_an_unlimited_limit_is_carried_as_the_word() -> None:
    """`UNLIMITED` is a legitimate effective value and is not a number. The field
    is a string for that reason, and #180's lockout guard has to read it as one."""
    state = describe(_cursor(limits=[("FAILED_LOGIN_ATTEMPTS", "UNLIMITED")]), "acme_orders_user")

    assert state is not None
    assert state.failed_login_limit == "UNLIMITED"


def test_the_profile_query_resolves_default_against_the_default_profile() -> None:
    """Pinned on the SQL, because the resolution happens in the database and a
    future edit that dropped the join would leave every unset limit reading as
    the literal word `DEFAULT`."""
    assert "'DEFAULT'" in PROFILE_QUERY
    assert "d.profile = 'DEFAULT'" in PROFILE_QUERY


# ----------------------------------------------------------------- 11.2's row ---


def test_a_release_without_password_change_date_falls_back(  # noqa: D401
) -> None:
    """`ORA-00904` *is* the answer to "does this release have the column".

    Invariant 3 in the small: the query is its own probe, so no capability and no
    version test is needed to find out.

    **This is 18c's shape, not 11.2's**, and the distinction is the point (#381).
    18c refuses `PASSWORD_CHANGE_DATE` and answers `ORACLE_MAINTAINED` perfectly
    well, so narrowing to the legacy query here would give up a guardrail input
    the release can supply. The next test is 11.2, which has neither.
    """
    cursor = _Cursor(
        {
            USER_QUERY: _ora("ORA-00904", '"PASSWORD_CHANGE_DATE": invalid identifier'),
            USER_QUERY_NO_CHANGE_DATE: (
                "ACME_ORDERS_USER",
                "OPEN",
                "DEFAULT",
                "10G 11G",
                "N",
                None,
                EXPIRES,
            ),
            PROFILE_QUERY: [("FAILED_LOGIN_ATTEMPTS", "10")],
            ROLES_QUERY: [],
        }
    )

    state = describe(cursor, "acme_orders_user")

    assert state is not None
    assert state.password_changed_at is None
    assert state.password_versions == ("10G", "11G")
    assert state.vendor_maintained is False, (
        "18c has ORACLE_MAINTAINED; only the change date is missing"
    )
    assert PTIME_QUERY not in cursor.asked, "no grant was declared, so SYS.USER$ is not read"
    assert state.password_changed_unknown is not None
    assert "SELECT ON SYS.USER$" in state.password_changed_unknown, "the reason names the remedy"


def test_a_missing_oracle_maintained_column_is_none_and_not_false() -> None:
    """Load-bearing: guardrail check 5's literal deny list is consulted *only*
    where check 2 could not answer, so a missing column reading as "not
    vendor-maintained" would switch off the fallback that exists for 11.2.

    11.2 refuses both columns, so both queries above it are `ORA-00904` and the
    legacy shape answers with `NULL` in each position. Until #381 this was the
    *only* row that produced `None` here on purpose, and 18c produced it by
    accident on the same path.
    """
    cursor = _Cursor(
        {
            USER_QUERY: _ora("ORA-00904"),
            USER_QUERY_NO_CHANGE_DATE: _ora("ORA-00904"),
            USER_QUERY_LEGACY: ("SYS", "OPEN", "DEFAULT", "11G", None, None, EXPIRES),
            PROFILE_QUERY: [],
            ROLES_QUERY: [],
        }
    )

    state = describe(cursor, "sys")

    assert state is not None
    assert state.vendor_maintained is None


@pytest.mark.parametrize(("flag", "expected"), [("Y", True), ("N", False)])
def test_oracle_maintained_is_read_where_the_column_exists(flag: str, expected: bool) -> None:
    state = describe(_cursor(maintained=flag), "acme_orders_user")

    assert state is not None
    assert state.vendor_maintained is expected


def test_a_password_change_date_is_carried_where_the_release_has_one() -> None:
    """Measured: two rotations two minutes apart moved the column, so it does
    track a rotation on a release that has it."""
    state = describe(_cursor(changed=CHANGED), "acme_orders_user")

    assert state is not None
    assert state.password_changed_at == CHANGED
    assert state.password_changed_unknown is None


# ------------------------------------------------ the PTIME fallback (#386) ---

#: What `SYS.USER$.PTIME` answers, deliberately a different moment from
#: :data:`CHANGED` so a test can tell which source a value came from.
PTIME = datetime(2026, 9, 8, 17, 7, 16)


def _no_change_date(**answers: Any) -> _Cursor:
    """18c's shape: the column is refused, `ORACLE_MAINTAINED` is not."""
    return _Cursor(
        {
            USER_QUERY: _ora("ORA-00904", '"PASSWORD_CHANGE_DATE": invalid identifier'),
            USER_QUERY_NO_CHANGE_DATE: (
                "ACME_ORDERS_USER",
                "OPEN",
                "DEFAULT",
                "11G 12C",
                "N",
                None,
                EXPIRES,
            ),
            PROFILE_QUERY: [],
            ROLES_QUERY: [],
            **answers,
        }
    )


def test_a_release_without_the_column_reads_ptime_where_the_grant_exists() -> None:
    """#386, option 2: 18c and 11.2 report what 19c+ report, when they can."""
    cursor = _no_change_date(**{PTIME_QUERY: (PTIME,)})

    state = describe(cursor, "acme_orders_user", user_dollar=True)

    assert state is not None
    assert state.password_changed_at == PTIME
    assert state.password_changed_unknown is None


def test_the_legacy_shape_falls_back_too() -> None:
    """11.2 answers neither column, and its date is behind the same grant."""
    cursor = _Cursor(
        {
            USER_QUERY: _ora("ORA-00904"),
            USER_QUERY_NO_CHANGE_DATE: _ora("ORA-00904"),
            USER_QUERY_LEGACY: ("ACME_ORDERS_USER", "OPEN", "DEFAULT", "10G 11G", None, None, None),
            PROFILE_QUERY: [],
            ROLES_QUERY: [],
            PTIME_QUERY: (PTIME,),
        }
    )

    state = describe(cursor, "acme_orders_user", user_dollar=True)

    assert state is not None
    assert state.password_changed_at == PTIME


def test_ptime_is_never_read_where_the_column_exists() -> None:
    """**One source per release**, which is what keeps a second source from
    becoming a second opinion (#383's lesson). Asserted with the grant declared,
    because that is the case where reading both would be possible."""
    cursor = _cursor(changed=CHANGED)
    cursor.answers[PTIME_QUERY] = (PTIME,)

    state = describe(cursor, "acme_orders_user", user_dollar=True)

    assert state is not None
    assert state.password_changed_at == CHANGED
    assert PTIME_QUERY not in cursor.asked


def test_an_empty_column_is_reported_as_empty_rather_than_retried() -> None:
    """A `NULL` in a column the release has is that release's answer. Retrying
    it against `PTIME` is exactly how one release would come to have two sources."""
    cursor = _cursor(changed=None)
    cursor.answers[PTIME_QUERY] = (PTIME,)

    state = describe(cursor, "acme_orders_user", user_dollar=True)

    assert state is not None
    assert state.password_changed_at is None
    assert PTIME_QUERY not in cursor.asked
    assert state.password_changed_unknown is not None
    assert "empty" in state.password_changed_unknown


def test_an_unreadable_sys_user_dollar_says_so_rather_than_naming_the_grant() -> None:
    """The capability said yes and the read said no -- a grant revoked mid-run.
    Telling the operator to grant what the probe found would send them in a
    circle, so the reason is a different sentence."""
    cursor = _no_change_date(**{PTIME_QUERY: _ora("ORA-01031")})

    state = describe(cursor, "acme_orders_user", user_dollar=True)

    assert state is not None
    assert state.password_changed_at is None
    assert state.password_changed_unknown is not None
    assert "could not be read" in state.password_changed_unknown


def test_a_ptime_read_that_is_not_an_enumerated_negative_raises() -> None:
    """`capabilities.read`'s rule, one level down: only the codes that mean *no*
    become `None`. Anything else is a question that should not have been asked,
    and a plausible "unknown" in its place is #195's failure."""
    cursor = _no_change_date(**{PTIME_QUERY: _ora("ORA-00600", "internal error")})

    with pytest.raises(Exception, match="ORA-00600"):
        describe(cursor, "acme_orders_user", user_dollar=True)


def test_the_fallback_is_bound_to_the_spelling_the_database_gave_back() -> None:
    """`failed_logins`' reason: `SYS.USER$.NAME` preserves a quoted lower-case
    spelling, so upper-casing here would find no row and read as unknown."""
    assert ":name" in PTIME_QUERY
    assert "upper(" not in PTIME_QUERY.lower()


# ------------------------------------------------------------------- roles ---


def test_the_roles_query_traverses_roles_held_through_other_roles() -> None:
    """Pinned on the SQL, because the hole it closes is invisible in the result.

    A flat `DBA_ROLE_PRIVS` read returns only direct grants, so an account
    granted a site role that itself holds `DBA` reports nothing guardrail 4
    refuses — and passes.

    `NOCYCLE` is asserted too, but as the defensive measure it is: Oracle refuses
    to create a role cycle (`ORA-01934`), so it cannot fire on a graph Oracle
    built. It costs nothing and the failure it would prevent is a tool that
    cannot describe any account at all.
    """
    assert "connect by nocycle" in ROLES_QUERY
    assert "start with" in ROLES_QUERY


def test_the_effective_limits_are_all_carried_rather_than_only_the_lockout_one() -> None:
    """One query resolves every password resource, so discarding the rest would
    force #181 and UC-1 §4's bounded regeneration into a second, uncoordinated
    read of the same profile."""
    state = describe(
        _cursor(
            limits=[
                ("FAILED_LOGIN_ATTEMPTS", "5"),
                ("PASSWORD_ROLLOVER_TIME", "1"),
                ("PASSWORD_REUSE_MAX", "UNLIMITED"),
                ("PASSWORD_REUSE_TIME", "365"),
            ]
        ),
        "acme_orders_user",
    )

    assert state is not None
    assert state.failed_login_limit == "5"
    assert state.rollover_time == "1"
    assert state.password_reuse_max == "UNLIMITED"
    assert state.password_reuse_time == "365"


def test_roles_are_upper_cased_the_way_a_database_spells_them() -> None:
    """Guardrail 4 compares against an upper-cased set."""
    state = describe(_cursor(roles=[("dba",), ("CONNECT",)]), "acme_orders_user")

    assert state is not None
    assert state.roles == frozenset({"DBA", "CONNECT"})


def test_an_account_holding_no_roles_reports_an_empty_set() -> None:
    state = describe(_cursor(roles=[]), "acme_orders_user")

    assert state is not None
    assert state.roles == frozenset()


def test_unreadable_roles_are_refused_rather_than_reported_as_none_held() -> None:
    """The one that matters.

    Measured: `DBA_ROLE_PRIVS` is `ORA-00942` under `02-oracle-privileges.md`
    §2's grant set as it stood, so a correctly installed service account could
    not read it. An empty set means *this account holds no admin role* and reads
    as a pass, so a missing grant would have turned guardrail 4 into a silent
    success — the same shape as a capability probe that could not be answered
    reporting absent (#195).
    """
    cursor = _cursor()
    cursor.answers[ROLES_QUERY] = _ora("ORA-00942", 'table or view "SYS"."DBA_ROLE_PRIVS"')

    with pytest.raises(RolesUnreadableError) as raised:
        describe(cursor, "acme_orders_user")

    assert "DBA_ROLE_PRIVS" in (raised.value.hint or "")
    assert raised.value.code == "ORA-00942", "the server's code is carried (#521)"
    assert "DBA_ROLE_PRIVS" in raised.value.message, "and so is its message"


def test_a_role_read_failing_for_another_reason_does_not_prescribe_a_grant() -> None:
    """#521. The grant hint was attached to every failure, so a dropped
    connection told the operator to `GRANT SELECT ON SYS.DBA_ROLE_PRIVS`."""
    cursor = _cursor()
    cursor.answers[ROLES_QUERY] = _ora("ORA-03113", "end-of-file on communication channel")

    with pytest.raises(DriverError) as raised:
        describe(cursor, "acme_orders_user")

    assert not isinstance(raised.value, RolesUnreadableError)
    assert raised.value.code == "ORA-03113"
    assert "DBA_ROLE_PRIVS" not in (raised.value.hint or "")


def test_roles_are_read_on_every_describe_rather_than_on_request() -> None:
    """#178 raised a lazy read, since roles are consulted only before a mutation
    and `creds status` reads this object for every account in an estate. Refused:
    a caller that forgot would get an empty `roles` that reads exactly like an
    account holding none, and a safety check must not depend on a caller
    remembering to enable its input."""
    cursor = _cursor()
    describe(cursor, "acme_orders_user")

    assert ROLES_QUERY in cursor.asked


def test_the_account_name_is_bound_and_never_interpolated() -> None:
    """Not invariant 14 — that forbids binding a *password*, and for the same
    reason this one is safe: `V$SQL_BIND_CAPTURE` keeps bind values in clear. An
    account name is not a secret, and building this string by concatenation is
    the habit that later writes a password into SQL text."""
    assert ":name" in USER_QUERY
    assert "acme" not in USER_QUERY.lower()


# ------------------------------------------------------------- password file ---
#
# Guardrail 3's input (#296), and the one dictionary read here that a correctly
# installed service account is expected to be refused. Every literal below was
# measured on 26ai Free 23.26.2.0.0 on 2026-09-05 -- see
# `tests/driver/test_oracle_accounts.py` for the tier-1 run that produced them.


def test_a_password_file_member_is_reported_as_one() -> None:
    assert password_file_member(_cursor(pwfile=(1,)), "ACME_WEB_USER") is True


def test_an_account_outside_the_password_file_is_reported_as_outside_it() -> None:
    assert password_file_member(_cursor(pwfile=(0,)), "ACME_ORDERS_USER") is False


def test_an_ungranted_view_is_none_and_never_false() -> None:
    """The whole of #296, in one assertion.

    `V$PWFILE_USERS` is outside `02-oracle-privileges.md` §2's grant set on
    purpose, so a correctly installed service account gets `ORA-00942` from it --
    measured, as `ORA-00942: table or view "SYS"."V_$PWFILE_USERS" does not
    exist`. That has to come back as *nobody looked*: `False` would mean *not a
    member*, guardrail 3 reads it as a pass, and the check silently never fires,
    which is the state this issue found the tool in.
    """
    cursor = _cursor()
    cursor.answers[PWFILE_QUERY] = _ora("ORA-00942", 'table or view "SYS"."V_$PWFILE_USERS"')

    assert password_file_member(cursor, "ACME_ORDERS_USER") is None


def test_the_password_file_is_read_on_every_describe() -> None:
    """A guardrail input, so it is read with the object a mutation reads -- the
    same rule roles are read under, and for the same reason: a caller that had to
    ask for it would get `None` by forgetting, and `None` is not a refusal."""
    cursor = _cursor()
    state = describe(cursor, "acme_orders_user")

    assert PWFILE_QUERY in cursor.asked
    assert state is not None
    assert state.password_file_member is False


def test_an_unreadable_password_file_still_describes_the_account() -> None:
    """Unlike `DBA_ROLE_PRIVS`, which raises.

    The asymmetry is the decision: §2 grants the roles view, so an account that
    cannot read it is misinstalled, while §2 deliberately does not grant this one
    -- so raising would refuse every mutation on every correctly installed
    target. The account is described, the field is `None`, and the guardrail
    turns that into a caveat.
    """
    cursor = _cursor()
    cursor.answers[PWFILE_QUERY] = _ora("ORA-00942", 'table or view "SYS"."V_$PWFILE_USERS"')

    state = describe(cursor, "acme_orders_user")

    assert state is not None
    assert state.password_file_member is None


def test_the_password_file_name_is_bound_unchanged() -> None:
    """Bound, and bound as the dictionary spelled it.

    `V$PWFILE_USERS.USERNAME` carries `DBA_USERS`' own spelling, so upper-casing
    here would miss a quoted lower-case account and answer a count of zero --
    which reads as *not a member* and is the one wrong answer that is silent.
    """
    cursor = _cursor()
    describe(cursor, "acme_orders_user")

    assert ":name" in PWFILE_QUERY
    assert "acme" not in PWFILE_QUERY.lower()


# ------------------------------------------------- password constraints (#317) ---
#
# UC-1 §4 step 2's reporting half. Every literal below was read off 26ai Free
# 23.26.2.0.0 on 2026-09-04, including the two that look like mistakes: a profile
# naming no verify function reports the **string** `NULL`, and a common profile
# read from inside a PDB reports the string `FROM ROOT`.

VERIFY = "PASSWORD_VERIFY_FUNCTION"
REUSE_MAX = "PASSWORD_REUSE_MAX"
REUSE_TIME = "PASSWORD_REUSE_TIME"


def test_a_named_verify_function_is_reported_with_its_name() -> None:
    found = password_constraints(
        _cursor(limits=[(VERIFY, "ORA12C_STRONG_VERIFY_FUNCTION")]), "acme_orders_user"
    )

    assert found is not None
    assert found.verify_state == NAMED
    assert found.verify_function == "ORA12C_STRONG_VERIFY_FUNCTION"


def test_the_string_null_is_a_profile_naming_none_and_not_a_function_called_null() -> None:
    """What `DEFAULT` carries, in the root and in a PDB alike. A reader taking
    the column at face value would report every default-profile account as
    guarded by a verify function named `NULL`."""
    found = password_constraints(_cursor(limits=[(VERIFY, "NULL")]), "acme_orders_user")

    assert found is not None
    assert found.verify_state == NONE
    assert found.verify_function is None


def test_from_root_is_a_not_knowing_and_never_an_absence() -> None:
    """The distinction #317 asks for, and the direction that cannot mislead.

    A common profile read from inside a PDB answers this. Reporting it as `none`
    would tell an operator that nothing will judge their password when something
    will -- and `not knowing is not a finding` (§5) is the rule, not `not
    knowing is a clean bill of health`.
    """
    found = password_constraints(_cursor(limits=[(VERIFY, "FROM ROOT")]), "acme_orders_user")

    assert found is not None
    assert found.verify_state == UNKNOWN
    assert found.verify_function is None


def test_a_profile_that_could_not_be_read_is_unknown_rather_than_clean() -> None:
    found = password_constraints(_cursor(limits=[]), "acme_orders_user")

    assert found is not None
    assert found.verify_state == UNKNOWN


def test_the_reuse_resources_are_carried_as_the_database_spells_them() -> None:
    """`UNLIMITED` is a word in a column a reader expects numbers in, and the two
    resources interact -- so they are reported rather than interpreted."""
    found = password_constraints(
        _cursor(limits=[(REUSE_MAX, "3"), (REUSE_TIME, "UNLIMITED")]), "acme_orders_user"
    )

    assert found is not None
    assert (found.reuse_max, found.reuse_time) == ("3", "UNLIMITED")
    assert found.reuse_enforced is True


def test_a_default_profile_restricts_no_reuse() -> None:
    found = password_constraints(
        _cursor(limits=[(REUSE_MAX, "UNLIMITED"), (REUSE_TIME, "UNLIMITED")]), "acme_orders_user"
    )

    assert found is not None
    assert found.reuse_enforced is False


def test_the_verifiers_the_account_holds_are_carried() -> None:
    found = password_constraints(_cursor(versions="11G 12C"), "acme_orders_user")

    assert found is not None
    assert found.versions == ("11G", "12C")


def test_the_spelling_is_the_databases_own() -> None:
    """`02-oracle-privileges.md` §4: the name that reaches anything is the one the
    dictionary gave back, never the config file's string."""
    found = password_constraints(_cursor(), "acme_orders_user")

    assert found is not None
    assert found.account == "ACME_ORDERS_USER"


def test_an_account_the_target_has_not_got_is_none() -> None:
    cursor = _Cursor({USER_QUERY: None, USER_QUERY_NO_CHANGE_DATE: None, USER_QUERY_LEGACY: None})

    assert password_constraints(cursor, "acme_orders_user") is None


def test_the_roles_query_is_not_asked() -> None:
    """The reason this returns its own type rather than a `UserState`: a staging
    command has nothing to guard, and guardrail 4's input is not read for it --
    so an absent `DBA_ROLE_PRIVS` grant cannot make `creds generate` fail for a
    reason unrelated to generating."""
    cursor = _cursor()
    password_constraints(cursor, "acme_orders_user")

    assert ROLES_QUERY not in cursor.asked

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

from sopuli.driver.oracle.accounts import (
    PROFILE_QUERY,
    ROLES_QUERY,
    USER_QUERY,
    USER_QUERY_NO_CHANGE_DATE,
    RolesUnreadableError,
    describe,
)

CHANGED = datetime(2026, 8, 22, 10, 41, 36)


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
    limits: list[tuple[str, str]] | None = None,
    roles: list[tuple[str]] | None = None,
) -> _Cursor:
    return _Cursor(
        {
            USER_QUERY: ("ACME_ORDERS_USER", status, profile, versions, maintained, changed),
            PROFILE_QUERY: limits if limits is not None else [("FAILED_LOGIN_ATTEMPTS", "5")],
            ROLES_QUERY: roles if roles is not None else [],
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
    ("status", "locked", "expired", "rollover"),
    [
        ("OPEN", False, False, False),
        ("OPEN & IN ROLLOVER", False, False, True),
        ("LOCKED", True, False, False),
        ("LOCKED(TIMED)", True, False, False),
        ("LOCKED & IN ROLLOVER", True, False, True),
        ("EXPIRED", False, True, False),
        ("EXPIRED & IN ROLLOVER", False, True, True),
        ("EXPIRED & LOCKED & IN ROLLOVER", True, True, True),
        ("EXPIRED(GRACE)", False, True, False),
    ],
)
def test_the_status_is_read_as_tokens_not_as_a_value(
    status: str, locked: bool, expired: bool, rollover: bool
) -> None:
    """`ACCOUNT_STATUS` is compound and `&`-joined.

    Every combination above except the two `(GRACE)`/`(TIMED)` spellings was
    produced on 26ai by locking, expiring and rotating one account in turn.
    Comparing the column to a value rather than reading tokens out of it would
    report `EXPIRED & LOCKED & IN ROLLOVER` as none of the three.
    """
    state = describe(_cursor(status=status), "acme_orders_user")

    assert state is not None
    assert state.locked is locked
    assert state.expired is expired
    assert state.rollover_active is rollover


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
    cursor = _Cursor({USER_QUERY: None, USER_QUERY_NO_CHANGE_DATE: None})

    assert describe(cursor, "acme_no_such_user") is None


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
    version test is needed to find out. 11.2 is the release, and both columns
    arrived in 12.1, so one fallback covers them together.
    """
    cursor = _Cursor(
        {
            USER_QUERY: _ora("ORA-00904", '"PASSWORD_CHANGE_DATE": invalid identifier'),
            USER_QUERY_NO_CHANGE_DATE: ("ACME_ORDERS_USER", "OPEN", "DEFAULT", "10G 11G"),
            PROFILE_QUERY: [("FAILED_LOGIN_ATTEMPTS", "10")],
            ROLES_QUERY: [],
        }
    )

    state = describe(cursor, "acme_orders_user")

    assert state is not None
    assert state.password_changed_at is None
    assert state.password_versions == ("10G", "11G")


def test_a_missing_oracle_maintained_column_is_none_and_not_false() -> None:
    """Load-bearing: guardrail check 5's literal deny list is consulted *only*
    where check 2 could not answer, so a missing column reading as "not
    vendor-maintained" would switch off the fallback that exists for 11.2."""
    cursor = _Cursor(
        {
            USER_QUERY: _ora("ORA-00904"),
            USER_QUERY_NO_CHANGE_DATE: ("SYS", "OPEN", "DEFAULT", "11G"),
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
    track a rotation on a release that has it. #87 is open about 11.2's source,
    not about this."""
    state = describe(_cursor(changed=CHANGED), "acme_orders_user")

    assert state is not None
    assert state.password_changed_at == CHANGED


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

"""What connecting needs, checked without connecting. Tier 0.

`sopuli/driver/oracle/client.py` imports no vendor client, which is what lets
this run on the tier-0 matrix where `oracledb` is not installed at all. That is
not a convenience: the three things asserted here are the ones that fail
*silently* rather than loudly.

* A username sent alongside external authentication connects as the wrong
  identity, and the audit trail records the wrong "who" (P5).
* A timeout that never left the profile waits at the driver's default, which is
  no timeout, which is a scheduled run that never returns.
* A missing-client message with the wrong platform's remediation sends somebody
  to `LD_LIBRARY_PATH` on Windows -- and the Windows hint is the one a Linux
  maintainer will never see for themselves.
"""

from __future__ import annotations

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target
from sopuli.driver.oracle.client import (
    CLIENT_LIB_DIR_ENV,
    CLIENT_NOT_LOADED,
    NO_CLIENT,
    ClientError,
    Timeouts,
    client_hint,
    connect_arguments,
    missing_client,
)
from sopuli.driver.protocol import Credential
from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret
from sopuli.settings.registry import DEFAULT_CONNECT_TIMEOUT_S, NO_QUERY_TIMEOUT, SETTINGS

DSN = "db-test.example.com:1521/CDBQA.pdb.example.com"
ALIAS = "CDBPROD"


def target(*, dsn: str = DSN, name: str = "cdb-root-qa") -> ExpandedTarget:
    return ExpandedTarget(
        target=Target(
            name=name,
            type="oracle",
            dsn=dsn,
            admin=AdminCredential(username="C##SOPULI_SVC", auth=AdminAuth(method="prompt")),
        ),
        index=0,
    )


# ------------------------------------------------------------------ arguments ---


def test_a_password_credential_sends_a_user_and_a_password() -> None:
    arguments = connect_arguments(
        target(),
        Credential(username="C##SOPULI_SVC", secret=Secret("hunter2")),
        timeouts=Timeouts(),
    )

    assert arguments["dsn"] == DSN
    assert arguments["user"] == "C##SOPULI_SVC"
    assert arguments["password"] == "hunter2"
    assert "externalauth" not in arguments


def test_external_sends_neither_a_user_nor_a_password() -> None:
    """`/@alias`: the wallet supplies both halves, and `externalauth` is what
    tells the client to look for one. A username sent here would connect as
    somebody the wallet did not choose -- §3a refuses one in the file for the
    same reason, and this is the other end of that rule."""
    arguments = connect_arguments(target(dsn=ALIAS), Credential(external=True), timeouts=Timeouts())

    assert arguments["externalauth"] is True
    assert "user" not in arguments
    assert "password" not in arguments
    assert arguments["dsn"] == ALIAS


@pytest.mark.parametrize(
    "dsn",
    [
        "db-test.example.com:1521/CDBQA.pdb.example.com",
        "CDBPROD",
        "tcps://db.example.com:2484/svc",
        "192.0.2.10:1521/FREEPDB1",
    ],
)
def test_the_dsn_is_passed_through_whatever_shape_it_is_in(dsn: str) -> None:
    """§3a allows Easy Connect and a TNS alias, and the client tells them apart
    itself. Parsing it here to decide which is which would re-implement that and
    get it wrong on the forms nobody tests."""
    arguments = connect_arguments(
        target(dsn=dsn), Credential(username="u", secret=Secret("p")), timeouts=Timeouts()
    )

    assert arguments["dsn"] == dsn


@pytest.mark.parametrize(
    "code",
    ["DPI-1047", "DPI-1050", "DPI-1072"],
    ids=["not-found", "too-old", "unsupported"],
)
def test_a_client_that_cannot_start_carries_its_code(
    monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    """Through `initialise`, not only `missing_client`: the match on the driver's
    code is what decides whether a real run gets `SOPULI-20004`."""
    session = pytest.importorskip("sopuli.driver.oracle.session")
    oracledb = pytest.importorskip("oracledb")

    def refuse(**_: object) -> None:
        raise oracledb.DatabaseError(f"{code}: the client library cannot be used")

    monkeypatch.setattr(session, "_initialised", False)
    monkeypatch.setattr(session.oracledb, "init_oracle_client", refuse)

    with pytest.raises(ClientError) as refused:
        session.initialise(env={}, platform="linux")

    assert refused.value.code == CLIENT_NOT_LOADED
    assert code in str(refused.value)


def test_a_credential_with_no_username_is_refused_before_the_connection() -> None:
    """Not a traceback and not an ORA-01017 twenty seconds later. The three ways
    to supply one are in the hint, because an operator hitting this has to pick
    one of them."""
    with pytest.raises(ConfigError) as refused:
        connect_arguments(target(), Credential(secret=Secret("hunter2")), timeouts=Timeouts())

    assert not isinstance(refused.value, ClientError)
    assert "cdb-root-qa" in str(refused.value)
    assert refused.value.exit_code == ExitCode.CONFIG_INVALID
    # The file or a variable fixes this, as for any `config` error, so no code (J3).
    assert refused.value.code is None
    hint = refused.value.hint or ""
    assert "SOPULI_DB_ADMIN_USER" in hint
    assert "external" in hint


# ------------------------------------------------------------------- timeouts ---


def test_the_connect_timeout_reaches_the_arguments() -> None:
    """The whole point of resolving one: a number in a profile that never left
    it is a number the driver's default silently replaces."""
    arguments = connect_arguments(
        target(),
        Credential(username="u", secret=Secret("p")),
        timeouts=Timeouts(connect_s=5),
    )

    assert arguments["tcp_connect_timeout"] == 5


def test_the_query_timeout_is_off_unless_somebody_asks() -> None:
    """A call timeout cancels the round trip without undoing what the server did
    with it, and `ALTER USER` is not transactional -- so an imposed default
    turns a slow success into a run that cannot say whether the password
    changed. Invariant 7 has no answer for that state."""
    assert Timeouts().query_s == NO_QUERY_TIMEOUT
    assert Timeouts().call_timeout_ms == 0


def test_a_query_timeout_that_was_asked_for_is_in_milliseconds() -> None:
    """python-oracledb takes `call_timeout` in milliseconds and the setting is
    in seconds. The units differ, the meaning does not."""
    assert Timeouts(query_s=90).call_timeout_ms == 90_000


def test_the_defaults_are_the_settings_registry_builtins() -> None:
    """Two spellings of one number is one number that will disagree. The
    resolver's built-in is the source, and `Timeouts` reads it -- so a caller
    with no resolved settings still gets the documented behaviour rather than
    the driver's own."""
    assert Timeouts().connect_s == DEFAULT_CONNECT_TIMEOUT_S
    assert SETTINGS["db.connect_timeout_s"].builtin == DEFAULT_CONNECT_TIMEOUT_S
    assert SETTINGS["db.query_timeout_s"].builtin == NO_QUERY_TIMEOUT


# --------------------------------------------------------- the missing client ---


@pytest.mark.parametrize("platform", ["linux", "win32", "darwin"])
def test_every_platform_gets_its_own_remediation(platform: str) -> None:
    """P4's table has three rows and they are genuinely different. The variable
    is in all of them because it is the answer that works everywhere."""
    hint = client_hint(platform)

    assert CLIENT_LIB_DIR_ENV in hint


def test_windows_names_the_redistributable_and_not_ld_library_path() -> None:
    """The failure that looks least like a missing client: every file is there
    and the load still fails. Sending a Windows operator to `LD_LIBRARY_PATH`
    is sending them nowhere."""
    hint = client_hint("win32")

    assert "PATH" in hint
    assert "Visual C++" in hint
    assert "LD_LIBRARY_PATH" not in hint


def test_linux_names_ld_library_path() -> None:
    assert "LD_LIBRARY_PATH" in client_hint("linux")


def test_the_drivers_own_diagnosis_survives_into_the_message() -> None:
    """A worked example from this project's own CI: the client was installed, on
    the path, and still gave DPI-1047 -- because Ubuntu 24.04 renamed
    `libaio.so.1`. A message that replaced that detail with a tidier sentence of
    ours would cost another round trip."""
    detail = f"{NO_CLIENT}: libclntsh.so: cannot open shared object file"

    error = missing_client(detail, platform="linux")

    assert detail in str(error)
    assert "thick mode is required" in str(error)
    assert error.exit_code == ExitCode.CONFIG_INVALID
    assert error.category == "config"
    assert error.code == CLIENT_NOT_LOADED == "SOPULI-20004"

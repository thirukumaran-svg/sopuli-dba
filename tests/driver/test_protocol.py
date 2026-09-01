"""The driver interface, checked against the documents that specify it.

Almost nothing here tests behaviour, because there is almost no behaviour yet.
What it tests is that four vocabularies are one vocabulary: P1's capability
table, the run document's ``scope`` object, the words ``config/targets.py``
accepts in a target's ``oracle.scope``, and the constants in
:mod:`sopuli.driver.protocol`.

That is worth a test file of its own rather than being left to review, because
drift between them is silent and asymmetric. A capability added to
``00-principles.md`` and not to the code is a capability nothing can report; a
scope the driver reports and the config layer has never heard of is an assertion
no file can make. Neither shows up as a failure anywhere else -- both just
quietly narrow what the tool can say.

CLAUDE.md: *the documents are the specification, not a description written
afterwards -- if they disagree with the code, that is a bug in one of them.*
``tests/config/test_design_document_examples.py`` makes that true of the config
reference by parsing its YAML; this does the same to P1 by parsing its table.
"""

from __future__ import annotations

import json
import re
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget
from sopuli.config.targets import ORACLE_SCOPES
from sopuli.driver import protocol
from sopuli.driver.protocol import (
    CAPABILITIES,
    OFFLINE_VERIFY,
    PASSWORD_ROLLOVER,
    SCOPE_TYPES,
    UNKNOWN,
    VERIFY_METHODS,
    VERIFY_RESULTS,
    AuthenticationError,
    ChangeResult,
    Credential,
    Driver,
    DriverError,
    Scope,
    Session,
    UnsupportedCapabilityError,
    UserState,
    VerifyResult,
    require_capability,
)
from sopuli.exit_codes import ExitCode
from sopuli.output.document import SCHEMA_VERSION
from sopuli.secrets import Secret

ROOT = Path(__file__).resolve().parents[2]
PRINCIPLES = ROOT / "docs" / "design" / "00-principles.md"
RUN_SCHEMA = ROOT / "docs" / "schemas" / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
INSTALL_SHAPE = ROOT / "tests" / "store" / "test_install_shape.py"

#: P1's capability table: the section, then the first column of each row. Scoped
#: to the section rather than run over the whole file, because the document is
#: full of tables and a looser pattern would quietly collect P2's store
#: capabilities as well -- which are a different vocabulary that happens to look
#: identical.
CAPABILITY_SECTION = re.compile(r"### Capability negotiation\n(.*?)\n### ", re.DOTALL)
TABLE_ROW = re.compile(r"^\| `([a-z_]+)`", re.MULTILINE)


def _documented_capabilities() -> set[str]:
    section = CAPABILITY_SECTION.search(PRINCIPLES.read_text(encoding="utf-8"))
    assert section, "P1's capability-negotiation section has moved or been renamed"
    return set(TABLE_ROW.findall(section.group(1)))


def _run_schema() -> Any:
    return json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))


def _defs(name: str) -> Any:
    return _run_schema()["$defs"][name]


# ----------------------------------------------------------- vocabularies ---


def test_the_capability_table_was_actually_found() -> None:
    """Guards the regex.

    Without this, a reformatted document turns the test below into a comparison
    of two empty sets -- green, and checking nothing.

    A named row rather than a count. The count was ``>= 8`` and had to be edited
    the first time the vocabulary shrank (#195 removed ``container_scope``),
    which makes the guard something a reader has to keep in step with the thing
    it guards -- and a guard that gets adjusted to fit is not guarding. A row
    that must be in any table worth calling P1's does the same job and needs no
    maintenance.
    """
    assert "password_rollover" in _documented_capabilities()


def test_capabilities_are_exactly_what_p1_documents() -> None:
    """The code and the table are one list.

    A capability in the document and not here can never be reported; one here
    and not in the document is a promise nobody wrote down. Both directions
    fail, which is why this is an equality and not a subset.
    """
    assert _documented_capabilities() == CAPABILITIES


def test_scope_types_are_the_run_documents() -> None:
    assert set(SCOPE_TYPES) == set(_defs("scope")["properties"]["type"]["enum"])


def test_scope_types_are_the_config_vocabulary_plus_unknown() -> None:
    """The word a file asserts and the word the driver reports are the same word.

    ``unknown`` is the deliberate asymmetry: the driver may find it, a config
    file may never claim it, and ``01-configuration.md`` §3a says so.
    """
    assert set(SCOPE_TYPES) == set(ORACLE_SCOPES) | {UNKNOWN}
    assert UNKNOWN not in ORACLE_SCOPES


def test_verification_vocabularies_are_the_run_documents() -> None:
    verification = _defs("verification")["properties"]
    assert set(VERIFY_METHODS) == set(verification["method"]["enum"])
    assert set(VERIFY_RESULTS) == set(verification["result"]["enum"])


def test_scope_carries_the_documents_fields() -> None:
    """`Scope` is the run document's ``scope`` object, minus two.

    ``labels`` belongs to the config -- a driver has no idea what a target set
    called this database -- and ``offline_verify_available`` is
    ``supports(OFFLINE_VERIFY)``, stored once rather than twice. Both exclusions
    are spelled out here so that a *third* one has to be argued for rather than
    slipped in.
    """
    documented = set(_defs("scope")["properties"])
    assert {field.name for field in fields(Scope)} == documented - {
        "labels",
        "offline_verify_available",
    }


def test_error_categories_are_the_run_documents() -> None:
    documented = set(_defs("error")["properties"]["category"]["enum"])
    for error in (DriverError, UnsupportedCapabilityError, AuthenticationError):
        assert error.category in documented


# ----------------------------------------------------------------- errors ---


def test_an_unsupported_capability_names_the_capability_and_the_target() -> None:
    """Invariant 4: never a generic error.

    The exception carries the capability as a field as well as in the message,
    because the run document has ``error.target_capability`` for it -- a
    consumer branches on that rather than parsing prose.
    """
    error = UnsupportedCapabilityError(PASSWORD_ROLLOVER, target="cdb1-pdb-orders")

    assert error.capability == PASSWORD_ROLLOVER
    assert error.target == "cdb1-pdb-orders"
    assert PASSWORD_ROLLOVER in str(error)
    assert "cdb1-pdb-orders" in str(error)
    assert error.exit_code == ExitCode.UNSUPPORTED_CAPABILITY


def test_authentication_failure_exits_six() -> None:
    """The same code the vault side uses, so a scheduler need not know which
    half of the run could not authenticate."""
    assert AuthenticationError("refused").exit_code == ExitCode.AUTH_FAILURE


def test_a_vendor_code_survives_onto_the_error() -> None:
    """CLAUDE.md: never swallow an ORA- code. #172 does the mapping; this is
    that there is somewhere for the answer to go."""
    error = DriverError("invalid credentials", code="ORA-01017", hint="check the vault")

    assert error.code == "ORA-01017"
    assert error.category == "database"
    assert "hint: check the vault" in str(error)


def test_require_capability_refuses_and_permits() -> None:
    without = Scope(type="pdb", capabilities=frozenset())
    with pytest.raises(UnsupportedCapabilityError) as refused:
        require_capability(without, PASSWORD_ROLLOVER, target="cdb1-pdb-billing")
    assert refused.value.capability == PASSWORD_ROLLOVER

    with_it = Scope(type="pdb", capabilities=frozenset({PASSWORD_ROLLOVER}))
    require_capability(with_it, PASSWORD_ROLLOVER, target="cdb1-pdb-billing")


def test_offline_verify_is_read_off_the_capability_set() -> None:
    """The field the schema has and this does not."""
    assert Scope(capabilities=frozenset({OFFLINE_VERIFY})).supports(OFFLINE_VERIFY)
    assert not Scope().supports(OFFLINE_VERIFY)


# ------------------------------------------------------------------ shape ---


class _Session:
    """The smallest thing that satisfies :class:`Session`."""

    def scope(self) -> Scope:
        return Scope(type="pdb", container="PDB1")

    #: The one account this stub knows about. Anything else is missing, which is
    #: what makes ``describe_user``'s ``None`` half testable at all.
    known = "acme_web_user"

    def describe_user(self, account: str) -> UserState | None:
        if account != self.known:
            return None
        return UserState(name=account.upper(), status="OPEN")

    def set_password(self, account: str, secret: Secret) -> ChangeResult:
        return ChangeResult(changed=True)

    def apply_attributes(
        self, account: str, attributes: protocol.AccountAttributes
    ) -> tuple[protocol.AttributeChange, ...]:
        if not attributes.unlock:
            return ()
        return (
            protocol.AttributeChange(
                protocol.ACCOUNT_UNLOCK, changed=False, detail="the account is not locked"
            ),
        )

    def verify_password(
        self,
        account: str,
        secret: Secret,
        *,
        method: str = protocol.VERIFY_LOGIN,
        lockout_margin: int = 2,
        attempts: int = 1,
    ) -> VerifyResult:
        return VerifyResult(method=method, result=protocol.PASS)

    def require_rollover(self, account: str) -> None:
        return None

    def finish_rollover(self, account: str) -> ChangeResult:
        return ChangeResult(changed=False, detail="no rollover window is open")

    def close(self) -> None:
        return None


class _Driver:
    def connect(self, target: ExpandedTarget, credential: Credential) -> Session:
        return _Session()


def test_an_implementation_satisfies_the_protocols_without_importing_them() -> None:
    """A `Protocol`, not a base class: neither class above inherits anything.

    That is the property being checked -- the Oracle driver will be written
    against ``oracledb`` and will satisfy this by shape, which is what keeps the
    interface a description of what commands need rather than a place to put
    shared code.
    """
    assert isinstance(_Session(), Session)
    assert isinstance(_Driver(), Driver)


def test_a_missing_account_is_none_rather_than_an_error() -> None:
    """UC-1's ``ACCOUNT_MISSING``: a state to report, not a failure to recover
    from. The tool does not create accounts (Q8), so an absent one is an answer.

    Both directions, because only the pair says anything: ``None`` alone would
    also be what a stub that had not been written yet returns.
    """
    session = _Session()

    assert session.describe_user("acme_batch_user") is None

    found = session.describe_user(_Session.known)
    assert found is not None
    assert found.name == "ACME_WEB_USER"


def test_the_no_vendor_client_property_lives_in_the_install_shape_test() -> None:
    """ADR-006 rule 3, pointed at the test that can actually hold it.

    This asserted ``"oracledb" not in sys.modules`` until #174, which was never
    the claim it appeared to be: it measured whether *anything in the process*
    had imported the client, so it passed by luck until a tier-1 fixture
    legitimately imported one, and would have gone on passing if this module
    grew a vendor import that some earlier test happened to trigger first.

    ``tests/store/test_install_shape.py`` is the real form and is strictly
    stronger: a subprocess with every client blocked at the import system, then
    every sopuli module outside a driver or a backend imported. What is left
    here is the pointer, because deleting the test outright would leave the
    property looking untested from this file.
    """
    assert INSTALL_SHAPE.exists()

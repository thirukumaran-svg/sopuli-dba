"""Wallet readability under ``auth: external`` (#215, P4). Tier 0.

Filesystem only -- no Oracle client, no container, no wallet that has to be a
real wallet. That is the whole point of the check being cheap: it answers *is
there a wallet here this process can read* without asking the client anything,
and the client's own connection attempt answers the rest a moment later.

The wallet files written below are a few bytes of nonsense on purpose. Nothing
here opens one, and a fixture that built a real Oracle wallet would be testing
`orapki` rather than this.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

from conftest import WriteConfig
from sopuli.cli import cli
from sopuli.config.errors import ConfigError
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target
from sopuli.diagnostics import WALLET_NOT_PRIVATE, WALLET_UNUSABLE, wallet_diagnostics
from sopuli.driver.oracle.wallet import AUTO_LOGIN, ENCRYPTED, survey
from sopuli.output.document import SCHEMA_VERSION
from sopuli.output.wallet_view import build, render

SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

EXTERNAL_TARGET = """version: 1
targets:
  - name: cdb-root-dev
    type: oracle
    dsn: "ORDERS_DEV"
    admin: { auth: external }
"""

PASSWORD_TARGET = """version: 1
targets:
  - name: orders-pdb
    type: oracle
    dsn: "db.example.com:1521/orders"
    admin: { username: C##SOPULI_SVC, auth: { method: env } }
"""


def _target(name: str, *, external: bool) -> ExpandedTarget:
    auth = AdminAuth(method="external") if external else AdminAuth(method="env")
    admin = AdminCredential(username=None if external else "C##SOPULI_SVC", auth=auth)
    return ExpandedTarget(
        target=Target(name=name, type="oracle", dsn="ORDERS_DEV", admin=admin),
        target_set=None,
        index=0,
    )


def _wallet_dir(tmp_path: Path, *files: str) -> Path:
    directory = tmp_path / "network" / "admin"
    directory.mkdir(parents=True, exist_ok=True)
    for name in files:
        path = directory / name
        path.write_bytes(b"not a real wallet")
        if sys.platform != "win32":
            path.chmod(0o600)
    return directory


def test_no_external_target_means_no_report_at_all() -> None:
    """Absence is the right answer here, unlike `install`'s always-present rule.

    Install shape is a fact about the machine that is always true of it. This is
    a fact about a configuration option most files never use, and a section
    warning about a missing wallet in every document that never needed one is
    noise rather than evidence.
    """
    assert survey([_target("orders-pdb", external=False)], tns_admin="/anywhere") is None


def test_the_report_names_every_external_target_over_the_expanded_estate() -> None:
    report = survey(
        [_target("a", external=True), _target("b", external=False), _target("c", external=True)],
        tns_admin=None,
    )

    assert report is not None
    assert report.required_by == ("a", "c")


def test_an_unset_tns_admin_has_nowhere_to_look(tmp_path: Path) -> None:
    """A distinct finding from "the directory is empty", because the fix differs.

    Telling somebody to check permissions on a directory that was never named is
    the failure the three-way split in `_why_unusable` exists to avoid.
    """
    report = survey([_target("a", external=True)], tns_admin=None)

    assert report is not None
    assert report.directory is None
    assert report.readable is False
    assert not report.usable

    (found,) = wallet_diagnostics(report)
    assert found.code == WALLET_UNUSABLE
    assert found.message.startswith("target 'a' uses external authentication")
    assert "$TNS_ADMIN is unset" in found.message


def test_a_directory_that_does_not_exist_is_not_readable(tmp_path: Path) -> None:
    report = survey([_target("a", external=True)], tns_admin=str(tmp_path / "nope"))

    assert report is not None
    assert report.readable is False
    assert "missing or not readable" in wallet_diagnostics(report)[0].message


def test_an_auto_login_wallet_is_usable(tmp_path: Path) -> None:
    directory = _wallet_dir(tmp_path, AUTO_LOGIN, ENCRYPTED)

    report = survey([_target("a", external=True)], tns_admin=str(directory))

    assert report is not None
    assert report.files == (AUTO_LOGIN, ENCRYPTED)
    assert report.auto_login
    assert report.usable
    assert wallet_diagnostics(report) == []


def test_an_encrypted_wallet_alone_is_not_enough(tmp_path: Path) -> None:
    """`ewallet.p12` needs a passphrase the tool has no way to supply.

    Worth its own case because the directory is not empty and the naive reading
    -- "is there a wallet here" -- says yes. An unattended rotation would then
    fail at the connection with a login error, which is exactly the surprise this
    check exists to move forward in time.
    """
    directory = _wallet_dir(tmp_path, ENCRYPTED)

    report = survey([_target("a", external=True)], tns_admin=str(directory))

    assert report is not None
    assert report.files == (ENCRYPTED,)
    assert not report.auto_login
    assert not report.usable

    (found,) = wallet_diagnostics(report)
    assert ENCRYPTED in found.message
    assert "passphrase" in found.message


def test_a_wallet_that_is_present_and_unreadable_is_not_usable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Presence is not access, and this is the case the whole report exists for.

    A wallet owned by the account a service runs as is ``is_file()`` from every
    account on the machine and opens from exactly one. The first version of this
    check asked ``is_file`` and reported ``auto_login: true`` for a wallet it
    could not read -- health, for precisely the failure it was written to
    explain. Found by Copilot on #241.

    The open is refused rather than the file's permissions changed, so the case
    runs identically on POSIX and on Windows: a real deny needs `chmod` on one and
    `icacls` on the other, and this is testing what the survey does with a refusal
    rather than how a platform produces one.
    """
    directory = _wallet_dir(tmp_path, AUTO_LOGIN)
    real_open = Path.open

    def refuse(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == AUTO_LOGIN:
            raise PermissionError(13, "Permission denied")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", refuse)
    report = survey([_target("a", external=True)], tns_admin=str(directory))

    assert report is not None
    assert report.readable, "the directory listed fine; only the file is refused"
    assert report.files == ()
    assert report.unreadable == (AUTO_LOGIN,)
    assert not report.auto_login
    assert not report.usable

    (found,) = wallet_diagnostics(report)
    assert found.code == WALLET_UNUSABLE
    assert "cannot read it" in found.message
    assert "which account this is running as" in found.message


def test_a_directory_that_cannot_be_listed_is_not_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`is_dir` needs only traverse permission on the parent.

    So it answers yes for a directory whose contents this process cannot see, and
    a preflight that called that readable would say the one thing that stops
    somebody looking further.
    """
    directory = _wallet_dir(tmp_path, AUTO_LOGIN)

    def refuse(self: Path) -> Any:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "iterdir", refuse)
    report = survey([_target("a", external=True)], tns_admin=str(directory))

    assert report is not None
    assert not report.readable
    assert report.files == ()
    assert "missing or not readable" in wallet_diagnostics(report)[0].message


def test_sqlnet_wallet_location_moves_the_search(tmp_path: Path) -> None:
    """The case that decides whether this check is trustworthy at all.

    ``WALLET_LOCATION`` puts the wallet somewhere other than ``TNS_ADMIN``, and a
    survey that did not follow it would report "no wallet" for a correctly
    configured estate -- sending somebody to fix a directory that was never
    wrong, which is worse than not checking.
    """
    tns = _wallet_dir(tmp_path)
    elsewhere = tmp_path / "wallet"
    elsewhere.mkdir()
    wallet = elsewhere / AUTO_LOGIN
    wallet.write_bytes(b"not a real wallet")
    if sys.platform != "win32":
        wallet.chmod(0o600)
    (tns / "sqlnet.ora").write_text(
        f"WALLET_LOCATION = (SOURCE=(METHOD=FILE)(METHOD_DATA=(DIRECTORY={elsewhere})))\n",
        encoding="utf-8",
    )

    report = survey([_target("a", external=True)], tns_admin=str(tns))

    assert report is not None
    assert report.from_sqlnet
    assert report.directory == str(elsewhere)
    assert report.usable


def test_a_commented_out_wallet_location_is_not_followed(tmp_path: Path) -> None:
    """Which is how most of them start life.

    Reading a commented redirect as the live one would point the whole report at
    a directory nobody uses, and every finding after that would be about the
    wrong place.
    """
    tns = _wallet_dir(tmp_path, AUTO_LOGIN)
    (tns / "sqlnet.ora").write_text(
        "# WALLET_LOCATION = (SOURCE=(METHOD=FILE)(METHOD_DATA=(DIRECTORY=/wrong)))\n",
        encoding="utf-8",
    )

    report = survey([_target("a", external=True)], tns_admin=str(tns))

    assert report is not None
    assert not report.from_sqlnet
    assert report.directory == str(tns)


def test_an_unreadable_sqlnet_is_treated_as_absent(tmp_path: Path) -> None:
    """`doctor` runs when things are broken, so a redirect it cannot read must
    not cost the report the rest of what it knows."""
    tns = _wallet_dir(tmp_path, AUTO_LOGIN)
    (tns / "sqlnet.ora").mkdir()  # a directory where a file was expected: OSError on read

    report = survey([_target("a", external=True)], tns_admin=str(tns))

    assert report is not None
    assert not report.from_sqlnet
    assert report.usable


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes; the ACL path is P4's own test")
def test_a_wallet_others_can_read_is_reported_and_does_not_fail(tmp_path: Path) -> None:
    """An auto-login wallet is a credential, so P4's config-file check applies.

    A **warning**, for the reason #213 settled for over-granted accounts: it is
    somebody else's file, and a `doctor` that refused to run over it would block
    the person who ran it, mid-incident, over a condition they did not create.
    """
    directory = _wallet_dir(tmp_path, AUTO_LOGIN)
    (directory / AUTO_LOGIN).chmod(0o644)

    report = survey([_target("a", external=True)], tns_admin=str(directory))

    assert report is not None
    # Still usable: it is there and readable. The problem is that it is readable
    # by more people than it should be, which is a different finding.
    assert report.usable
    assert [name for name, _reason in report.insecure] == [AUTO_LOGIN]

    (found,) = wallet_diagnostics(report)
    assert found.code == WALLET_NOT_PRIVATE
    assert found.level == "warning"
    assert AUTO_LOGIN in found.message


def test_a_refused_permission_check_becomes_a_finding_rather_than_ending_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The glue, on both platforms, which the POSIX test above cannot reach.

    P4's check is written to **refuse**: it raises `ConfigError`, which carries
    exit 9 and would end `doctor` outright. Catching it is what turns it into a
    report, and that catch is the only part of the permission path this module
    owns -- the platform logic itself is P4's and has its own tests.

    Worth pinning separately because the POSIX case above skips on Windows, so
    without this the Windows CI job would exercise none of it: an uncaught
    `ConfigError` from a DACL walk would surface as a dead run on the platform
    nobody tested, which is exactly the failure mode P4's own module docstring
    warns about for permission checks.
    """
    directory = _wallet_dir(tmp_path, AUTO_LOGIN)

    def refuse(path: Path, *, what: str = "config file") -> None:
        raise ConfigError(f"{what} is accessible to EVERYONE", source=path)

    monkeypatch.setattr("sopuli.driver.oracle.wallet.check_permissions", refuse)
    report = survey([_target("a", external=True)], tns_admin=str(directory))

    assert report is not None
    assert [name for name, _ in report.insecure] == [AUTO_LOGIN]
    (found,) = wallet_diagnostics(report)
    assert found.code == WALLET_NOT_PRIVATE
    assert "accessible to EVERYONE" in found.message


def test_one_entry_for_a_missing_wallet_however_many_targets_need_it() -> None:
    """There is one wallet per run.

    An estate with twenty external targets would otherwise say the same sentence
    twenty times about the same directory.
    """
    report = survey([_target(f"t{index}", external=True) for index in range(20)], tns_admin=None)

    assert report is not None
    found = wallet_diagnostics(report)
    assert len(found) == 1
    assert "20 targets, including 't0', use external authentication" in found[0].message


def test_the_section_validates_against_the_schema(tmp_path: Path) -> None:
    """Invariant 12, on the shape 1.14 added."""
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator({**schema["$defs"]["wallet_report"], "$defs": schema["$defs"]})
    report = survey([_target("a", external=True)], tns_admin=str(_wallet_dir(tmp_path, AUTO_LOGIN)))

    assert report is not None
    assert [f"{list(e.path)}: {e.message}" for e in validator.iter_errors(build(report))] == []


def test_an_empty_search_still_validates() -> None:
    """The nulls are the point: `tns_admin` and `directory` are always present.

    A consumer asking "where did it look" has to be able to tell *nowhere, the
    variable is unset* from *the producer does not report that*.
    """
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator({**schema["$defs"]["wallet_report"], "$defs": schema["$defs"]})
    report = survey([_target("a", external=True)], tns_admin=None)

    assert report is not None
    section = build(report)
    assert section["tns_admin"] is None
    assert section["directory"] is None
    assert [f"{list(e.path)}: {e.message}" for e in validator.iter_errors(section)] == []


def test_the_text_says_where_it_looked_and_why_there(tmp_path: Path) -> None:
    tns = _wallet_dir(tmp_path)
    elsewhere = tmp_path / "wallet"
    elsewhere.mkdir()
    (tns / "sqlnet.ora").write_text(
        f"WALLET_LOCATION = (SOURCE=(METHOD=FILE)(METHOD_DATA=(DIRECTORY={elsewhere})))\n",
        encoding="utf-8",
    )
    report = survey([_target("a", external=True)], tns_admin=str(tns))

    assert report is not None
    text = "\n".join(render(report))

    assert str(elsewhere) in text
    assert "sqlnet.ora WALLET_LOCATION" in text


def _refuse_to_connect(target: Any) -> Any:
    """Stand in for the driver, so `doctor` reports unreachable without dialling.

    `_examine` catches anything this raises and turns it into a not-connected
    ``targets[]`` entry, which is the state under test. What it must not do is
    reach the network, which is what makes the substitution necessary rather than
    convenient.
    """
    raise RuntimeError("the tier-0 test refused the connection")


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _doctor(runner: CliRunner, config: Path) -> Any:
    return runner.invoke(cli, ["--config", str(config), "--output", "json", "doctor"])


def test_doctor_omits_the_section_when_no_target_uses_external(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TNS_ADMIN", "/anywhere")
    config = write_config(PASSWORD_TARGET)

    document = json.loads(_doctor(runner, config).output)

    assert "wallet" not in document


def test_doctor_reports_the_wallet_and_does_not_fail_over_it(
    runner: CliRunner, write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The verdict question, decided: a missing wallet is not its own exit code.

    It rides on the target's own reachability, which the connection attempt
    settles a moment later. So the target here has to be unreachable, and this
    pins that the wallet finding did not add a *different* code on top of it.

    **The connection is refused locally rather than attempted**, which is what
    keeps this tier 0. An external target has a credential by definition, so
    `doctor` would otherwise really dial `ORDERS_DEV` -- 46 seconds of DNS and TCP
    timeouts in a tier that is supposed to finish in under sixty for all of it,
    and I/O in the tier defined by having none. Refusing at `resolve_driver`
    produces the same unreachable entry by a route that touches no network, and
    the wallet survey -- which is the subject -- runs before it either way.
    """
    monkeypatch.setenv("TNS_ADMIN", str(tmp_path / "empty"))
    monkeypatch.setattr("sopuli.cli.resolve_driver", _refuse_to_connect)
    config = write_config(EXTERNAL_TARGET)

    result = _doctor(runner, config)
    document = json.loads(result.output)

    assert document["wallet"]["required_by"] == ["cdb-root-dev"]
    assert document["wallet"]["auto_login"] is False
    codes = {one.get("code") for one in document["diagnostics"]}
    assert WALLET_UNUSABLE in codes
    # Exit 1 is the unreachable target, not the wallet. The wallet moved nothing.
    assert result.exit_code == 1
    assert document["targets"][0]["reachable"] is False

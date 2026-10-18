"""P4's config permission check, on both platforms.

The two halves share nothing but the function name, so they are tested
separately and each **skips with a reason** on the other platform rather than
branching inside a test (``04-testing.md``: tests declare what they need and say
why they skipped).

Neither half is fakeable. A POSIX mode test needs a real file with a real mode,
and an ACL test needs a real DACL; mocking either would test the mock. Both are
still tier 0 -- a temp file is not a container.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import load_document
from sopuli.config.permissions import check_permissions

posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX file modes; Windows has no st_mode worth reading",
)
windows_only = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows ACLs; there is no DACL to walk on this platform",
)


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    """A config file in a directory of its own, so tests cannot affect each other."""
    path = tmp_path / "sopuli.yaml"
    path.write_text("version: 1\n", encoding="utf-8")
    return path


# ------------------------------------------------------------------- POSIX ---


@posix_only
def test_owner_only_is_accepted(config_file: Path) -> None:
    config_file.chmod(0o600)
    check_permissions(config_file)


@posix_only
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660, 0o666, 0o777])
def test_any_group_or_other_access_is_refused(config_file: Path, mode: int) -> None:
    """Wider than §10's "readable", and deliberately so.

    A group-*writable* config is the worse problem: anyone who can write it can
    repoint secret_template at a path they control, and the tool will rotate a
    production password into it. 0o660 and 0o666 are in this list for that
    reason -- neither adds a read bit that 0o640 did not already have.
    """
    config_file.chmod(mode)

    with pytest.raises(ConfigError) as caught:
        check_permissions(config_file)

    assert f"{mode:04o}" in str(caught.value), "the message must name the actual mode"


@posix_only
def test_the_refusal_says_what_to_do(config_file: Path) -> None:
    config_file.chmod(0o644)

    with pytest.raises(ConfigError) as caught:
        check_permissions(config_file)

    assert "chmod 600" in str(caught.value)


@posix_only
def test_execute_only_is_still_refused(config_file: Path) -> None:
    """0o601 grants no read, but it is not a mode anyone set on purpose.

    The check is "does anyone else have any access", not "can anyone else read",
    so this refuses -- documented here so the behaviour is a decision rather
    than an accident of the bitmask.
    """
    config_file.chmod(0o601)

    with pytest.raises(ConfigError):
        check_permissions(config_file)


@pytest.fixture
def another_user(config_file: Path, monkeypatch: pytest.MonkeyPatch) -> int:
    """Run as a uid that does not own ``config_file``, and return the owner's.

    Making a file another user owns needs root, so the effective user is
    replaced instead: the file is real, the uid compared with it is not.
    """
    config_file.chmod(0o600)
    owner = config_file.stat().st_uid
    monkeypatch.setattr(os, "geteuid", lambda: owner + 1 if owner != 0 else 1000)
    return owner


@posix_only
def test_a_file_the_effective_user_owns_is_accepted(config_file: Path) -> None:
    config_file.chmod(0o600)
    check_permissions(config_file, owner=True)


@posix_only
def test_a_file_owned_by_another_user_is_refused(config_file: Path, another_user: int) -> None:
    """Mode 0600 does not help: the other user can still rewrite the file."""
    with pytest.raises(ConfigError) as caught:
        check_permissions(config_file, owner=True)

    message = str(caught.value)
    assert "config file is owned by another user" in message
    assert f"uid {another_user}" in message, "the message must name the owner"
    assert "chown" in message
    assert "sudo" in message, "the hint must say why sudo refuses a file you own"


@posix_only
def test_the_owner_is_checked_only_when_asked(config_file: Path, another_user: int) -> None:
    """The token file and the wallet survey do not ask: see the docstring."""
    check_permissions(config_file)


@posix_only
def test_a_file_root_owns_is_accepted(config_file: Path, another_user: int) -> None:
    """``sudo sopuli`` reads a config under /etc that root owns.

    The exemption matters only when sopuli runs as root: a root-owned file that
    passes the mode check is ``0600``, so no other user can open it. A
    root-owned file cannot be made without root, so the status says so.
    """
    root_owned = os.stat_result((0o100600, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    check_permissions(config_file, owner=True, status=root_owned)


@posix_only
def test_the_status_given_is_the_one_checked(config_file: Path) -> None:
    """The loader passes the open descriptor's ``fstat``, not the path's."""
    config_file.chmod(0o600)
    wider = os.stat_result((0o100644, 0, 0, 1, config_file.stat().st_uid, 0, 0, 0, 0, 0))

    with pytest.raises(ConfigError, match="mode 0644"):
        check_permissions(config_file, status=wider)


@posix_only
def test_the_loader_refuses_a_file_owned_by_another_user(
    config_file: Path, another_user: int
) -> None:
    with pytest.raises(ConfigError, match="owned by another user"):
        load_document(config_file)


@posix_only
def test_the_loader_checks_the_descriptor_it_reads(
    config_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The path is 0600 and the descriptor says 0644, so only the descriptor
    can be the source of the refusal."""
    config_file.chmod(0o600)
    wider = os.stat_result((0o100644, 0, 0, 1, config_file.stat().st_uid, 0, 0, 0, 0, 0))
    monkeypatch.setattr(os, "fstat", lambda _fd: wider)

    with pytest.raises(ConfigError, match="mode 0644"):
        load_document(config_file)


@posix_only
@pytest.mark.skipif(
    sys.platform != "win32" and os.getuid() == 0, reason="root can open a mode 000 file"
)
def test_a_file_that_cannot_be_opened_still_gets_the_owner_refusal(
    config_file: Path, another_user: int
) -> None:
    """The refusal says what to fix, where "permission denied" would not."""
    config_file.chmod(0o000)

    with pytest.raises(ConfigError, match="owned by another user"):
        load_document(config_file)


@windows_only
def test_the_owner_check_is_posix_only(locked_down: Path) -> None:
    check_permissions(locked_down, owner=True)


# ----------------------------------------------------------------- Windows ---


def _icacls(*args: str) -> None:
    result = subprocess.run(["icacls", *args], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture
def locked_down(config_file: Path) -> Path:
    """A file whose ACL is ours alone, rather than whatever the runner inherits.

    A CI runner's temp directory does not necessarily have the same default ACL
    as a workstation's, so the tests below set an explicit one instead of
    assuming. `/inheritance:r` drops inherited aces; `/grant:r` replaces rather
    than adds.
    """
    _icacls(str(config_file), "/inheritance:r", "/grant:r", f"{os.environ['USERNAME']}:F")
    return config_file


@windows_only
def test_a_file_only_the_owner_can_read_is_accepted(locked_down: Path) -> None:
    check_permissions(locked_down)


@windows_only
def test_a_normally_created_file_is_accepted(config_file: Path) -> None:
    """The check has to accept an ordinary file, or it is unusable.

    This is the test that caught the real bug: a file created under %TEMP%
    inherits an OWNER RIGHTS (S-1-3-4) ace and often no explicit ace for the
    user at all. Treating that as a third party refused every config file on
    the machine.
    """
    check_permissions(config_file)


@windows_only
@pytest.mark.parametrize(
    ("trustee", "expected"),
    [
        ("Everyone", "Everyone"),
        ("Users", "Users"),
        ("Authenticated Users", "Authenticated Users"),
    ],
)
def test_a_grant_to_anyone_else_is_refused(locked_down: Path, trustee: str, expected: str) -> None:
    _icacls(str(locked_down), "/grant", f"{trustee}:R")

    with pytest.raises(ConfigError) as caught:
        check_permissions(locked_down)

    assert expected in str(caught.value), "the message must name who can read it"


@windows_only
def test_a_write_only_grant_is_refused(locked_down: Path) -> None:
    """Tampering is the risk, so write counts even with no read bit at all.

    `(WD)` is FILE_WRITE_DATA on its own -- no READ_CONTROL, no SYNCHRONIZE, no
    generic right. Someone holding it can rewrite secret_template and point a
    production rotation at a path they control, without ever being able to read
    the file. An earlier version of this check only looked at read access and
    let it through; the POSIX half already refused the equivalent 0o020.
    """
    _icacls(str(locked_down), "/grant", "Everyone:(WD)")

    with pytest.raises(ConfigError) as caught:
        check_permissions(locked_down)

    assert "Everyone" in str(caught.value)


@windows_only
def test_permission_changing_rights_are_refused(locked_down: Path) -> None:
    """Whoever can rewrite the ACL can grant themselves everything else after."""
    _icacls(str(locked_down), "/grant", "Everyone:(WDAC)")

    with pytest.raises(ConfigError) as caught:
        check_permissions(locked_down)

    assert "Everyone" in str(caught.value)


@windows_only
def test_a_harmless_grant_is_not_refused(locked_down: Path) -> None:
    """The other side of the mask, and the reason it is not simply "any ACE".

    `(RA)` is FILE_READ_ATTRIBUTES: size and timestamps, not content. Refusing
    on that would make the check fire on incidental rights rather than on
    anything that puts the file at risk, and a security check nobody can satisfy
    gets turned off.
    """
    _icacls(str(locked_down), "/grant", "Everyone:(RA)")

    check_permissions(locked_down)


@windows_only
def test_administrators_and_system_do_not_count(locked_down: Path) -> None:
    """They can read any file on the machine whatever the ACL says.

    Refusing because they appear would refuse every file that exists, which is
    a check nobody can satisfy rather than a check.
    """
    _icacls(str(locked_down), "/grant", "*S-1-5-18:F", "/grant", "*S-1-5-32-544:F")

    check_permissions(locked_down)

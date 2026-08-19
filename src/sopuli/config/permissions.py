"""P4: refuse to run on a config file other people can get at.

The config holds no secrets by construction (C5) -- so the reason for this check
is not confidentiality, it is **tampering**. The file says which accounts are
managed and where their passwords are mastered. Anyone who can write it can
repoint ``secret_template`` at a path they control, and the tool will faithfully
rotate a production password and write it there. Invariant 6 makes the vault the
master record; this file decides which vault entry that is.

That is why the POSIX check is on ``0o077`` -- any group or other access -- and
not only on the read bits that ``01-configuration.md`` §10 names. Refusing a
world-*readable* file while accepting a group-*writable* one would be guarding
the smaller problem. The doc has been updated to match.

**Two callers, one check.** ``--vault-token-file`` (#145) points at a bearer
token on disk, which is exactly the thing this guards against being readable by
somebody else, so it goes through here too -- with ``what`` naming which file the
message is about. It is deliberately *not* extended to every ``file:``
MaterialRef: ``01-configuration.md`` §3a records that asymmetry and why it has to
stay (a Kubernetes projected token arrives mode 0644, and refusing it would break
a method P2 lists).

The two platforms need genuinely different code, which is the whole reason this
is its own module:

* POSIX has a mode. The check is one bitmask.
* Windows does not. ``os.stat().st_mode`` reports ``0o666`` for essentially
  every file regardless of its real ACL, so reading it would produce a check
  that always passes and looks like it works. The DACL has to be walked
  instead, via pywin32 (ADR-004 records that dependency).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from sopuli.config.errors import ConfigError

if TYPE_CHECKING:
    # types-pywin32 is platform-independent, so this resolves when mypy runs on
    # Linux even though the module itself only exists on Windows. That is what
    # gets the Windows-only branch below type-checked on both CI platforms.
    # PySID lives in _win32typing, not in win32security, which only re-exports
    # the functions.
    from _win32typing import PySID

#: Any bit here means someone other than the owner has some access.
GROUP_AND_OTHER = 0o077

POSIX_HINT = "chmod 600 the file, or move it somewhere only you can reach"
WINDOWS_HINT = 'remove the extra grant, e.g. icacls "<file>" /inheritance:r /grant:r "%USERNAME%:R"'


def check_permissions(path: Path, *, what: str = "config file") -> None:
    """Raise :class:`ConfigError` unless only the owner can reach ``path``.

    "Owner" is joined by the platform's own administrative identities, which can
    read any file regardless of what the ACL says: refusing because
    ``Administrators`` has access would refuse every file on the system. On
    Windows it is also joined by ``OWNER RIGHTS`` and ``CREATOR OWNER``, which
    are not accounts at all -- they resolve to whoever owns the file.

    ``what`` opens every message this raises. It is a parameter rather than a
    fixed string because the second caller guards a token file rather than the
    config (#145), and "config file is accessible to others" pointing at
    ``~/.vault-token`` would send somebody to edit the wrong file.
    """
    if sys.platform == "win32":
        _check_windows_acl(path, what)
    else:
        _check_posix_mode(path, what)


def _check_posix_mode(path: Path, what: str) -> None:
    mode = path.stat().st_mode & 0o777
    offending = mode & GROUP_AND_OTHER
    if offending:
        raise ConfigError(
            f"{what} is accessible to others (mode {mode:04o})",
            source=path,
            hint=POSIX_HINT,
        )


def _check_windows_acl(path: Path, what: str) -> None:
    """Walk the DACL and refuse if anyone unexpected is granted access.

    "Access" means read *or* write, matching the POSIX side -- see
    :func:`_unsafe_access_mask` for exactly which rights count and why the
    composite ones are excluded.

    Two deliberate simplifications, both of which fail *safe* -- they can make
    this refuse a file that was actually fine, never accept one that was not:

    **DENY aces are ignored.** Windows evaluates deny before allow, so a deny
    can take back what an allow granted. Honouring that properly means
    reimplementing access-check ordering; ignoring it means the worst case is a
    false refusal with a message naming the trustee, which a user can act on.

    **An unreadable DACL refuses.** A filesystem without ACL support (a FAT
    volume, some network shares) cannot answer the question. "I could not check"
    is not the same as "it is fine", and a security check that assumes the best
    when it cannot see is not a check.

    Inherited aces are counted like any other. Access granted by inheritance is
    access.
    """
    import ntsecuritycon
    import pywintypes
    import win32security

    try:
        descriptor = win32security.GetNamedSecurityInfo(
            str(path),
            win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
        )
    except pywintypes.error as error:
        raise ConfigError(
            f"cannot read the security descriptor of the {what}: {error.strerror}",
            source=path,
            hint="check the file is on a filesystem that supports ACLs",
        ) from error

    owner = descriptor.GetSecurityDescriptorOwner()
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None:
        # A NULL DACL is not "no permissions" -- it grants everyone full
        # control. The one case where the absence of a rule is the worst case.
        raise ConfigError(
            f"{what} has a NULL DACL, which grants everyone full control",
            source=path,
            hint=WINDOWS_HINT,
        )

    allowed = _permitted_sids()
    if owner is not None:
        allowed.append(owner)

    for index in range(dacl.GetAceCount()):
        (ace_type, _flags), mask, sid = dacl.GetAce(index)
        if ace_type != ntsecuritycon.ACCESS_ALLOWED_ACE_TYPE:
            continue
        if not mask & _UNSAFE_ACCESS:
            continue
        # PySID implements equality by comparing the SID itself, not identity.
        if any(sid == permitted for permitted in allowed):
            continue
        raise ConfigError(
            f"{what} is accessible to {_name_of(sid)}",
            source=path,
            hint=WINDOWS_HINT,
        )


def _permitted_sids() -> list[PySID]:
    """The identities whose read access says nothing about third parties.

    Built from the well-known constants rather than written out as
    ``S-1-5-18`` / ``S-1-5-32-544``, so this stays correct on a localised
    Windows and cannot drift into a typo.

    * **SYSTEM** and **Administrators** can read any file on the machine
      whatever the ACL says. Refusing because they appear would refuse every
      file that exists.
    * **OWNER RIGHTS** (``S-1-3-4``) and **CREATOR OWNER** (``S-1-3-0``) are not
      accounts -- they resolve to whoever owns the file. Found the hard way: a
      file created normally under ``%TEMP%`` inherits an ``OWNER RIGHTS`` ace
      and no explicit ace for the user at all, so without these two this check
      refuses an ordinary file that nobody else can read.
    """
    import win32security

    return [
        win32security.CreateWellKnownSid(win32security.WinLocalSystemSid),
        win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid),
        win32security.CreateWellKnownSid(win32security.WinCreatorOwnerRightsSid),
        win32security.CreateWellKnownSid(win32security.WinCreatorOwnerSid),
    ]


def _name_of(sid: PySID) -> str:
    """``DOMAIN\\name`` for a SID, falling back to its string form.

    The message has to say *who*, because "readable by others" leaves a user
    with nothing to remove. A SID that no longer resolves -- a deleted account,
    an unreachable domain -- still identifies the ace well enough to find it.
    """
    import win32security

    try:
        name, domain, _use = win32security.LookupAccountSid(None, sid)
    except Exception:  # noqa: BLE001 - an unresolvable SID is not an error here
        return str(win32security.ConvertSidToStringSid(sid))
    return f"{domain}\\{name}" if domain else name


def _unsafe_access_mask() -> int:
    """The rights that make a third party's ACE matter.

    Write is in here for the same reason the POSIX check is on ``0o077`` rather
    than on the read bits: the file carries a *tampering* risk, and someone who
    can rewrite ``secret_template`` does not need to be able to read it first.
    Leaving write out would have made this gate contradict its own rationale on
    one of the two platforms.

    ``WRITE_DAC`` and ``WRITE_OWNER`` count too. Whoever can change the ACL, or
    take ownership, can grant themselves everything else afterwards.

    The composite rights (``FILE_GENERIC_READ``, ``FILE_GENERIC_WRITE``,
    ``FILE_ALL_ACCESS``) are deliberately *not* listed, even though they are the
    ones an ACE usually carries. Each of them bundles ``READ_CONTROL`` and
    ``SYNCHRONIZE``, which nearly every ACE has, so including them would make
    this mask match essentially anything -- the check would still refuse the
    right files, but for the wrong reason and with no way to tell. Their
    meaningful bits are listed individually instead, so a real
    ``FILE_GENERIC_READ`` grant still matches through ``FILE_READ_DATA`` while a
    grant of nothing but ``READ_CONTROL`` does not.
    """
    import ntsecuritycon

    return (
        ntsecuritycon.FILE_READ_DATA
        | ntsecuritycon.FILE_READ_EA
        | ntsecuritycon.FILE_WRITE_DATA
        | ntsecuritycon.FILE_APPEND_DATA
        | ntsecuritycon.FILE_WRITE_EA
        | ntsecuritycon.DELETE
        | ntsecuritycon.WRITE_DAC
        | ntsecuritycon.WRITE_OWNER
        | ntsecuritycon.GENERIC_READ
        | ntsecuritycon.GENERIC_WRITE
        | ntsecuritycon.GENERIC_ALL
    )


_UNSAFE_ACCESS = _unsafe_access_mask() if sys.platform == "win32" else 0

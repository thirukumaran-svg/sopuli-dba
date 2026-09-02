"""Is there a wallet here, and can this process read it (P4, #215).

`01-configuration.md` §3a: a target using ``auth: external`` connects as
``/@alias``, and a secure external password store -- an Oracle wallet -- supplies
both halves of the credential. When the wallet is missing or unreadable the
connection fails, and it fails with an Oracle error **about the login**. That
sends somebody to the account and the password they do not have, rather than to
the file permissions they do.

`doctor` already reports that ``TNS_ADMIN`` is set. The gap this closes is
between *the variable is set* and *there is a wallet there this process can
read*, and those are different facts on every machine where a service runs as one
user and a DBA tests as another.

**The cheap check is the whole of the useful one.** Confirming the wallet
actually holds a credential for the alias means asking the Oracle client, and the
connection report already does that better than any inspection could: a target
that connects has proved its wallet works. What is left for this module is the
diagnosis when it does *not* -- turning "invalid username/password" into "there
is no wallet in the directory you pointed at", or into "there is one and this
process cannot read it". Interpreting ``cwallet.sso`` adds nothing to that and
would mean reverse-engineering a proprietary container in the one part of the
codebase where cleverness is least welcome.

**Readability is measured, not inferred.** One byte is read from each wallet
file and discarded, because presence is not access: a wallet owned by the
account a service runs as is ``is_file()`` from every account on the machine and
opens from exactly one. That gap is the subject of this module, so asking the
cheaper question would have reported health for precisely the failure the report
exists to explain. Nothing is parsed or kept -- reading is how you find out
whether reading works.

**Nothing here fails the run.** An unreadable wallet is not a separate verdict:
it rides on the target's own reachability, which the connection attempt decides a
moment later. This explains that failure rather than pre-empting it. A wallet
other people can read is reported the same way and for the reason #213 settled
for over-granted accounts -- it is somebody else's file and somebody else's
decision to fix, and a `doctor` that refused to run over it would block the
person who ran it, mid-incident, over a condition they did not create.

**Filesystem only.** No ``oracledb`` import, so this stays tier 0 and stays
importable on a machine with no Instant Client at all -- which is every tier-0 CI
job, and which is also the machine most likely to be running `doctor` to find out
why.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from sopuli.config.errors import ConfigError
from sopuli.config.model import ExpandedTarget
from sopuli.config.permissions import check_permissions
from sopuli.config.targets import EXTERNAL

#: The auto-login wallet. Present means the client can open the wallet with no
#: passphrase -- which is what makes ``auth: external`` unattended, and what
#: makes its file permissions a credential's file permissions.
AUTO_LOGIN = "cwallet.sso"

#: The PKCS#12 wallet. Usable, but needs a passphrase the tool has no way to
#: supply, so a directory holding only this one cannot serve an unattended run.
ENCRYPTED = "ewallet.p12"

#: What is looked for, in the order a report lists them.
WALLET_FILES = (AUTO_LOGIN, ENCRYPTED)

#: ``sqlnet.ora``'s redirect. ``WALLET_LOCATION`` moves the wallet somewhere
#: other than ``TNS_ADMIN``, and a survey that did not follow it would report "no
#: wallet" for a correctly configured estate -- which is worse than not checking,
#: because it sends somebody to fix a directory that was never wrong.
#:
#: Deliberately loose: it finds ``DIRECTORY = <path>`` anywhere in the file
#: rather than parsing the nested-parenthesis grammar around it. The strict
#: reading buys nothing here -- ``DIRECTORY`` appears in ``WALLET_LOCATION`` and
#: essentially nowhere else in a ``sqlnet.ora`` -- and a partial parser of a
#: format with ``IFILE``, comments and vendor extensions is exactly the kind of
#: nearly-right that reports a confident wrong answer.
_DIRECTORY = re.compile(r"\bDIRECTORY\s*=\s*([^)\s]+)", re.IGNORECASE)

#: A ``#`` to end of line. Stripped before the pattern above runs, so a commented
#: -out ``WALLET_LOCATION`` -- which is how most of them start life -- is not read
#: as the live one.
_COMMENT = re.compile(r"#.*$", re.MULTILINE)


@dataclass(frozen=True)
class WalletReport:
    """Where the wallet was looked for, and what was found there.

    ``required_by`` is never empty: this whole report is built only when
    something in the estate uses ``auth: external``, because a target with a
    password-based ``admin.auth`` has no wallet to report on and a section
    warning about one would be noise on most estates.
    """

    #: The expanded targets that use ``auth: external``, in config order.
    required_by: tuple[str, ...]
    #: ``$TNS_ADMIN`` as given, or ``None`` when the variable is unset.
    tns_admin: str | None
    #: Where the wallet was actually looked for. ``None`` when there was nowhere
    #: to look -- no ``TNS_ADMIN`` and no redirect.
    directory: str | None = None
    #: Whether :data:`directory` came from ``sqlnet.ora``'s ``WALLET_LOCATION``
    #: rather than from ``TNS_ADMIN``. Reported because a reader who checks the
    #: obvious directory and finds nothing needs to know the tool looked
    #: somewhere else.
    from_sqlnet: bool = False
    #: Whether :data:`directory` exists and this process could **list** it.
    #: Answered by listing it rather than by :meth:`~pathlib.Path.is_dir`, which
    #: needs only traverse permission on the parent and so says yes about a
    #: directory whose contents are unreadable.
    readable: bool = False
    #: Which of :data:`WALLET_FILES` are there **and openable by this process**.
    files: tuple[str, ...] = ()
    #: Wallet files that are there and cannot be read. The case this whole
    #: report exists for -- a wallet owned by the account the service runs as,
    #: surveyed by a DBA logged in as themselves -- and the one a presence check
    #: reports as healthy right up until the connection fails as a login error.
    unreadable: tuple[str, ...] = ()
    #: Wallet files somebody other than the owner can reach, with the reason.
    #: An auto-login wallet readable by others is a credential readable by
    #: others, which is P4's argument for the config-file check applied to the
    #: file that actually holds a password.
    insecure: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    @property
    def auto_login(self) -> bool:
        """Whether an unattended run can open this wallet without a passphrase.

        Reads :attr:`files`, which holds only what this process could actually
        open -- so a ``cwallet.sso`` that is present and unreadable answers
        ``False`` here, which is the answer the connection is about to give.
        """
        return AUTO_LOGIN in self.files

    @property
    def usable(self) -> bool:
        """Whether anything was found that could serve ``auth: external``.

        ``False`` is what the diagnostics hang off. Not a verdict on the run --
        the connection attempt is that -- but the difference between a login
        error nobody can explain and one that has already been explained.
        """
        return self.readable and self.auto_login


def external_targets(targets: Sequence[ExpandedTarget]) -> tuple[str, ...]:
    """The expanded targets that need a wallet, by name.

    Over the **expanded** estate rather than the ``targets:`` list, for the reason
    :func:`~sopuli.diagnostics.install_diagnostics` is: most targets are generated,
    and an estate that declares ``auth: external`` only in a ``target_sets:``
    entry would otherwise report that nothing needs a wallet.
    """
    found = []
    for expanded in targets:
        admin = expanded.target.admin
        if admin is not None and admin.auth is not None and admin.auth.method == EXTERNAL:
            found.append(expanded.name)
    return tuple(found)


def survey(targets: Sequence[ExpandedTarget], *, tns_admin: str | None) -> WalletReport | None:
    """What `doctor` can say about the wallet, or ``None`` when none is needed.

    ``tns_admin`` is passed rather than read from :data:`os.environ`, for the
    reason the rest of the tool passes it: a function that reaches for the
    environment itself cannot be tested against a different one.
    """
    required_by = external_targets(targets)
    if not required_by:
        return None

    directory, from_sqlnet = _wallet_directory(tns_admin)
    if directory is None:
        return WalletReport(required_by=required_by, tns_admin=tns_admin)

    found: list[str] = []
    unreadable: list[str] = []
    insecure: list[tuple[str, str]] = []
    present = _listing(directory)
    if present is not None:
        for name in WALLET_FILES:
            path = directory / name
            if name not in present:
                continue
            if not _can_read(path):
                unreadable.append(name)
                continue
            found.append(name)
            reason = _reachable_by_others(path)
            if reason is not None:
                insecure.append((name, reason))

    return WalletReport(
        required_by=required_by,
        tns_admin=tns_admin,
        directory=str(directory),
        from_sqlnet=from_sqlnet,
        readable=present is not None,
        files=tuple(found),
        unreadable=tuple(unreadable),
        insecure=tuple(insecure),
    )


def _listing(directory: Path) -> frozenset[str] | None:
    """What is in ``directory``, or ``None`` when it cannot be listed.

    **Listed rather than asked about.** :meth:`~pathlib.Path.is_dir` needs only
    traverse permission on the parent, so it answers yes for a directory whose
    contents this process cannot see -- and a readability preflight that reports
    a directory as readable when it cannot be read is worse than no preflight,
    because it says the one thing that stops somebody looking further.
    """
    try:
        return frozenset(entry.name for entry in directory.iterdir())
    except OSError:
        return None


def _can_read(path: Path) -> bool:
    """Whether this process can actually open ``path``.

    One byte, discarded. Presence is not access: a wallet owned by the account a
    service runs as is ``is_file()`` from any account on the machine, and opens
    from exactly one. That difference is the whole subject of this module, so
    asking the cheaper question would have reported health for precisely the
    failure the report exists to explain.

    Not :func:`os.access`, which on Windows reports the read-only *attribute*
    rather than the ACL and would answer yes for a file no ACE grants this user.
    Opening it is the only question whose answer means the same thing on both
    platforms -- and it is the same question the Oracle client is about to ask.

    **This is not "opening the wallet"** in the sense the design refuses. Nothing
    is parsed, interpreted or kept; the byte is read to learn whether reading
    works and is dropped immediately.
    """
    try:
        with path.open("rb") as handle:
            handle.read(1)
    except OSError:
        return False
    return True


def _wallet_directory(tns_admin: str | None) -> tuple[Path | None, bool]:
    """Where to look, and whether ``sqlnet.ora`` sent us there.

    ``WALLET_LOCATION`` wins over ``TNS_ADMIN`` because that is what the client
    does. A relative directory in it is resolved against ``TNS_ADMIN``, which is
    the only anchor available -- the client resolves against the process working
    directory, and reporting a path relative to wherever `doctor` happened to be
    invoked from would be a path nobody could act on.
    """
    if tns_admin is None:
        return None, False

    base = Path(tns_admin)
    redirect = _wallet_location(base / "sqlnet.ora")
    if redirect is None:
        return base, False
    return (redirect if redirect.is_absolute() else base / redirect), True


def _wallet_location(sqlnet: Path) -> Path | None:
    """``WALLET_LOCATION``'s directory from ``sqlnet.ora``, if it names one.

    Unreadable is treated as absent rather than raised. `doctor` is the command
    that runs when things are broken, and a permission error on a file that is
    only a redirect must not cost the report the rest of what it knows.
    """
    try:
        text = sqlnet.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    match = _DIRECTORY.search(_COMMENT.sub("", text))
    return Path(match.group(1).strip('"')) if match else None


def _reachable_by_others(path: Path) -> str | None:
    """Why somebody other than the owner can reach ``path``, or ``None``.

    **Reuses P4's own check rather than re-deriving it**, which is why this
    catches rather than asks: :func:`~sopuli.config.permissions.check_permissions`
    is written to refuse, and its message -- the POSIX mode, or the Windows
    trustee by name -- is the whole value of calling it. Two ways to phrase one
    check is how the two come to disagree, and this is a platform-specific
    security check where a disagreement would be invisible on whichever platform
    nobody happened to run.

    An unanswerable question is reported as a finding rather than swallowed. On
    Windows a filesystem with no ACL support raises the same
    :class:`~sopuli.config.errors.ConfigError`, and "I could not check" is not
    the same as "it is fine".
    """
    try:
        check_permissions(path, what="wallet file")
    except ConfigError as error:
        return str(getattr(error, "message", None) or error)
    except OSError as error:  # pragma: no cover - a file that vanished mid-survey
        return str(error)
    return None

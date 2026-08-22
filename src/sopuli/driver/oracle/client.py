"""What reaching Oracle needs, decided without reaching it (#176).

The half of connecting that is arithmetic: which arguments a target and a
credential add up to, how long to wait, and what to say when Instant Client is
not on this machine. None of it imports ``oracledb`` -- :mod:`.session` does
that -- which is what keeps every rule below tier 0, testable on a laptop with
no client and no database.

**Thick mode is not an option** (D3). Thin mode still has no Native Network
Encryption, which OCI-hosted databases require, so Instant Client is a runtime
prerequisite on every platform rather than a way to make things faster. That
makes a missing client an ordinary operational condition -- the single most
likely first-run failure this tool has -- and P4 requires it be diagnosable with
a per-platform hint rather than a bare ``DPI-1047`` traceback.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any

from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.model import ExpandedTarget
from sopuli.driver.protocol import Credential
from sopuli.settings.registry import DEFAULT_CONNECT_TIMEOUT_S, NO_QUERY_TIMEOUT

#: §6's variable: where Instant Client lives, when it is not somewhere the
#: platform's loader already looks. Passed to ``init_oracle_client(lib_dir=...)``.
CLIENT_LIB_DIR_ENV = "SOPULI_ORACLE_CLIENT_LIB_DIR"

#: What python-oracledb raises when it cannot load the client libraries. Matched
#: on the code rather than the message, which carries a URL and a paragraph of
#: prose that differs between releases.
NO_CLIENT = "DPI-1047"


class ClientError(ConfigError):
    """Instant Client is missing, or too broken to load.

    ``config`` and exit 9, the reading ADR-006 E5 already applied to a missing
    backend: the file is right and the database has refused nothing -- what is
    incomplete is *this machine*, and the person reading the message is the one
    who fixes it. Not ``capability``, which names something the database at the
    far end cannot do and no local action changes.

    No ``error.code``. J3 is open, three numbers have been allocated by hand,
    and a fourth allocated the same way would still not answer it.
    """


@dataclass(frozen=True)
class Timeouts:
    """The two budgets, resolved, so that neither is a driver default.

    Together rather than as two loose integers because they are asymmetric in a
    way a caller has to be told about once -- a connection that times out has
    applied nothing, and a call that times out cannot say what it applied. Both
    numbers and the reasoning live in :mod:`sopuli.settings.registry`, which is
    where their built-ins are; the defaults here exist so that a caller with no
    resolved settings still gets the documented behaviour rather than the
    driver's own.
    """

    connect_s: int = DEFAULT_CONNECT_TIMEOUT_S
    query_s: int = NO_QUERY_TIMEOUT

    @property
    def call_timeout_ms(self) -> int:
        """``Connection.call_timeout``, which python-oracledb takes in
        milliseconds. ``0`` disables it, which is what :data:`NO_QUERY_TIMEOUT`
        already means -- the units differ, the meaning does not."""
        return self.query_s * 1000


def client_hint(platform: str = sys.platform) -> str:
    """How to fix a missing client, *on the machine reading the message*.

    P4's table is the source: the library path is `LD_LIBRARY_PATH` on
    Linux and macOS, and on Windows the client goes on `PATH` and needs the
    Visual C++ redistributable besides -- which is the failure that looks least
    like a missing client, because the files are all there and the load still
    fails.

    ``platform`` is a parameter rather than a read of :data:`sys.platform`, so
    all three messages are testable from one machine. That is not a convenience:
    the Windows hint is the one most likely to be wrong and the one a Linux
    maintainer will never see.
    """
    if platform == "win32":
        return (
            f"install Oracle Instant Client, put its directory on PATH, and install the "
            f"Visual C++ redistributable it needs -- or point ${CLIENT_LIB_DIR_ENV} at it"
        )
    if platform == "darwin":
        return (
            f"install Oracle Instant Client and point ${CLIENT_LIB_DIR_ENV} at it, or set "
            f"DYLD_LIBRARY_PATH -- macOS is best-effort (D5) and the ARM64 client is 23.x, "
            f"which reaches 19c and later"
        )
    return (
        f"install Oracle Instant Client and put its directory on LD_LIBRARY_PATH, "
        f"or point ${CLIENT_LIB_DIR_ENV} at it"
    )


def missing_client(detail: str, *, platform: str | None = None) -> ClientError:
    """The refusal, keeping the driver's own diagnosis and adding ours.

    ``detail`` is python-oracledb's message and it goes in verbatim, because it
    names *which* library failed to load and often why. #184 is the worked
    example from this project's own CI: the client was installed, on the path,
    and still gave ``DPI-1047`` -- because Ubuntu 24.04 renamed ``libaio.so.1``.
    A message that had replaced that detail with our own tidier sentence would
    have cost another round trip, which is CLAUDE.md's "never swallow a vendor
    code" arriving from the client side rather than the server's.
    """
    return ClientError(
        f"Oracle Instant Client could not be loaded, and thick mode is required (D3): {detail}",
        at=ROOT,
        hint=client_hint(platform or sys.platform),
    )


def connect_arguments(
    target: ExpandedTarget,
    credential: Credential,
    *,
    timeouts: Timeouts,
    at: KeyPath = ROOT,
) -> dict[str, Any]:
    """Everything ``oracledb.connect`` is called with, as data.

    Separated from the call so that the assembly is tier 0. What goes wrong here
    is silent rather than loud -- a username sent alongside external
    authentication, a password left off, a timeout that never made it out of the
    profile -- and none of those raise; they connect as the wrong thing, or wait
    forever, and that is only visible if the arguments can be inspected without
    a database.

    Two shapes, and the difference is the whole of §3a's rule about wallets:

    * **external** connects as ``/@alias``. No user and no password, because the
      wallet supplies both, and ``externalauth`` is what tells the client to look
      for one. The config layer has already refused a ``username:`` beside it
      and already required the DSN be a TNS alias, so neither is re-checked --
      this consumes those rules rather than repeating them.
    * **everything else** sends a username and a password.

    ``dsn`` is passed through untouched in both forms. ``01-configuration.md``
    §3a allows Easy Connect and a TNS alias, and the client tells them apart
    itself: anything without a ``/`` or a ``:`` goes to ``TNS_ADMIN``. Parsing it
    here to decide which it is would be re-implementing that, and getting it
    wrong on the forms nobody tests -- ``tcps://``, an IPv6 literal, a full
    connect descriptor written inline.
    """
    arguments: dict[str, Any] = {
        "dsn": target.target.dsn,
        "tcp_connect_timeout": timeouts.connect_s,
    }

    if credential.external:
        arguments["externalauth"] = True
        return arguments

    if credential.username is None:
        raise ClientError(
            f"target {target.name!r} has no username to connect as",
            at=at,
            hint=(
                "write `admin: { username: … }`, set $SOPULI_DB_ADMIN_USER, or use "
                "`auth: external` so a wallet supplies it"
            ),
        )
    if credential.secret is None:  # pragma: no cover - `admin.resolve` never returns this
        raise ClientError(
            f"target {target.name!r} resolved no password and is not using a wallet",
            at=at,
        )

    arguments["user"] = credential.username
    # `reveal()` at the point of the driver call, which is invariant 2's second
    # permitted exception and the reason the method has that name: every place
    # plaintext legitimately leaves a `Secret` is one grep away.
    arguments["password"] = credential.secret.reveal()
    return arguments


#: The oldest server release a client of a given major can reach, per Oracle's
#: interoperability matrix. A 23.x client reaches 19c and later; a 19.x client
#: reaches 11.2 and later.
#:
#: **This is the one place a version number is read from a table**, and it is not
#: a violation of invariant 3: the rule is that the tool never branches on a
#: version *of the database from a config file*, and this is the version of the
#: **client library on this machine**, asked of the library itself. There is no
#: database to ask, which is the whole point -- `doctor` (#182) answers "is this
#: 11.2 target out of reach" before anybody waits on a connection that cannot
#: succeed (P4).
CLIENT_REACH: dict[int, tuple[int, int]] = {
    23: (19, 1),
    21: (12, 1),
    19: (11, 2),
    18: (11, 2),
    12: (10, 1),
}

#: What a client too new for a server answers with. Named because the message is
#: the diagnosis: "connections to this server version are no longer supported".
UNSUPPORTED_SERVER = "ORA-03134"


def reach_floor(client: tuple[int, ...]) -> tuple[int, int] | None:
    """The oldest server ``client`` can reach, or ``None`` for a major we have no
    row for -- in which case `doctor` says the version and makes no claim about
    reach, which is better than inventing one."""
    if not client:
        return None
    return CLIENT_REACH.get(client[0])


def describes_unreachable_server(code: str | None) -> bool:
    """Whether a failed connection looks like the client being too new.

    Kept as a question rather than a guess: `doctor` adds a sentence about the
    interoperability matrix when it is true, and says nothing when it is not.
    """
    return code == UNSUPPORTED_SERVER

"""Turning a :class:`~sopuli.config.model.MaterialRef` into a value.

The config layer parses ``{ env: NAME }`` and ``{ file: PATH }`` and stops
there. Nothing has ever read one, which is why every auth method in
``01-configuration.md`` §3a is unreachable: they all need material, and material
is named rather than written.

**Resolution is a function over a ref, never a method on one.** The type's own
docstring is the reason:

    There is no field for a value, and that absence is the guarantee: nothing
    downstream can be handed plaintext from this object because there is nowhere
    for plaintext to sit.

A ``MaterialRef`` that had been "resolved" would have to hold the value, and the
guarantee would end the moment somebody cached one. So the ref stays a location,
and what comes back is a :class:`~sopuli.secrets.Secret` -- which renders as
``***`` everywhere, per invariant 2, so a resolved credential is no more
dangerous to hold than the ref was.

**Here rather than in** :mod:`sopuli.config` **, which the issue proposed.**
Reading a file is I/O, and ``04-testing.md`` §4 makes "config parsing and
validation, target-set expansion, precedence resolution, SecretRef parsing" an
I/O-free layer as an architecture requirement. Resolution happens when something
connects, not when the file is read; putting it beside :mod:`sopuli.secrets`
keeps the builders provably unable to reach a credential.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.model import MaterialRef
from sopuli.config.permissions import check_permissions
from sopuli.secrets import Secret

#: Vault's own convention, and the last step of ``method: token``'s chain.
TOKEN_FILE = "~/.vault-token"

#: The flag that occupies the command line's position in that chain, decided in
#: ADR-007. It takes a **path**, never a token: a token as a command-line value
#: is visible in ``ps`` and in the Windows process list, which is invariant 1.
#: :mod:`sopuli.invocation` declares it and refuses the bare ``--vault-token``
#: somebody will type instead, because Vault's own CLI accepts ``-token=``.
TOKEN_FLAG = "--vault-token-file"

#: How the refusal and the exhausted-chain hint name every place a token may
#: come from. All four, in chain order, because somebody in a CI job where
#: writing a token to disk is awkward needs to know the variables already work --
#: a hint naming only the flag reads like the file form is the only way out.
TOKEN_SOURCES = (
    f"{TOKEN_FLAG} PATH",
    "$SOPULI_VAULT_TOKEN",
    "$VAULT_TOKEN",
    TOKEN_FILE,
)

#: The token chain of §3a, ranked. ``SOPULI_VAULT_TOKEN`` is not in §3a's
#: sentence and belongs here anyway: §6 lists it, and says the honoured
#: third-party variables rank *below* their ``SOPULI_*`` equivalent. Two
#: documents, one order.
TOKEN_VARIABLES = ("SOPULI_VAULT_TOKEN", "VAULT_TOKEN")


class MaterialError(ConfigError):
    """A named source held nothing to read.

    ``config`` and exit 9, by the same reasoning ADR-006 used for a missing
    backend (E5): the file is not wrong and the service has not refused
    anything -- what is incomplete is *this machine*, and the person reading the
    message is the one who fixes it, here, now.

    Distinct from the exit 6 an auth method raises when the store rejects a
    credential. That one means "we found it and it was not accepted"; this one
    means "there was nothing to send".

    No ``error.code``. An error gets one only where its category and exit code do
    not tell it apart (J3). Like most ``config`` errors, this is fixed in what the
    configuration points at: the variable or the path, which the message names.
    """


def resolve(ref: MaterialRef, *, env: Mapping[str, str], where: str) -> Secret:
    """The value ``ref`` points at.

    ``where`` names the position for the message -- ``vault "vault-prod" auth
    method "approle" key "secret_id"`` -- because the ref alone says ``env
    SOPULI_VAULT_SECRET_ID`` and an operator with three stores needs to know
    which one asked.

    ``env`` is passed in and never :data:`os.environ`, the arrangement
    :mod:`sopuli.config.discovery`, :mod:`sopuli.settings.sources` and
    :func:`sopuli.output.color.resolve_color` already use: a test that had to
    set a real variable to check a rule is a test that cannot run beside
    another one.
    """
    if ref.kind == "env":
        return _from_env(ref.location, env=env, where=where)
    if ref.kind == "file":
        return _from_file(Path(ref.location), where=where, wrote=ref.location)
    # Unreachable through a config file: `MATERIAL_KINDS` is a closed set the
    # builder validates against. Kept because this is also reachable from code.
    raise MaterialError(f"{where}: unknown material source {ref.kind!r}", at=ROOT)


def resolve_token(
    *,
    ref: MaterialRef | None,
    env: Mapping[str, str],
    token_file: Path | None = None,
    home: Path | None = None,
    where: str,
) -> Secret:
    """``method: token``'s source chain (§3a), in order, stopping at the end.

    ``token:`` written in the file wins outright -- a chain exists because the
    key is *optional*, not to be preferred over it. Then
    :data:`TOKEN_FLAG`'s path, then the variables in :data:`TOKEN_VARIABLES`,
    then ``~/.vault-token``.

    ``token_file`` is a **path and not a** :class:`~sopuli.secrets.Secret`,
    which is ADR-007's decision made structural: there is no parameter anywhere
    on this chain that a command-line *value* could arrive on, so invariant 1 is
    not something a future caller has to remember. It is also why resolution
    happens here rather than at the CLI boundary -- the flag stays a location
    for as long as every other step in the chain does, and a run that never
    reaches a store never reads the file.

    **The chain stays inside one method**, and that is the property worth
    protecting. Falling through to AppRole after the last step, into a *different*
    method, would make an authentication failure impossible to explain, because the
    thing that failed is not the thing the file names. So the end of this chain is
    an error, never a different method.
    """
    if ref is not None:
        return resolve(ref, env=env, where=where)
    if token_file is not None:
        return _from_token_file(token_file, where=where)
    for variable in TOKEN_VARIABLES:
        if env.get(variable):
            return Secret(env[variable])

    path = (home / ".vault-token") if home is not None else Path(TOKEN_FILE).expanduser()
    try:
        return _from_file(path, where=where, wrote=TOKEN_FILE)
    except MaterialError as error:
        if not isinstance(error.__cause__, FileNotFoundError):
            # The file is there and something else is wrong -- it is unreadable,
            # it is a directory, it is not UTF-8, it is empty. Every one of those
            # is a better diagnosis than "no token anywhere", and every one of
            # them has already been worded by `_from_file`.
            raise
        # Only a genuinely absent file means the chain ran out. Asked by trying
        # rather than by `path.exists()`, which returns False for a permission
        # error on the way to the file and would report "no token" for a token
        # that is sitting right there -- and which leaves a window between the
        # check and the read besides.
        raise MaterialError(
            f"{where}: no token, and none of the places it is looked for had one",
            at=ROOT,
            hint=(
                f"write `token: {{ file: … }}` on the store, or supply one of: "
                f"{', '.join(TOKEN_SOURCES[:-1])}, or `vault login` so that "
                f"{TOKEN_FILE} exists"
            ),
        ) from error


def _from_token_file(path: Path, *, where: str) -> Secret:
    """:data:`TOKEN_FLAG`'s file: read like any other, and permission-checked.

    **The one** ``file:`` **source that is permission-checked**, and the
    asymmetry is deliberate rather than an oversight. ``01-configuration.md``
    §3a keeps a config-written ``token: { file: … }`` unchecked because that path
    belongs to whatever provisioned it -- a Kubernetes projected token arrives
    mode 0644, and refusing to read it would break a method P2 lists. The
    ``~/.vault-token`` fallback stays unchecked for a different reason: it is
    Vault's own file, written 0600 by ``vault login``, and refusing the file
    another tool just wrote is refusing the bootstrap path ADR-007 names as the
    answer for a human at a terminal.

    What is left is the path an operator typed for *this* run, which is exactly
    P4's own case for the config file: the person reading the message is the one
    who can fix it, here, now.

    **Checked after reading, not before.** The check asks whether *others* can
    read the file, never whether we may -- so establishing that the file is there
    first costs nothing and buys the precise message ``_from_file`` already has
    for missing, empty, non-UTF-8 and unreadable. Asking ``path.exists()`` first
    would answer those worse and open a window between the question and the read
    besides. The secret is in memory either way; what the refusal prevents is
    *using* it.

    **The refusal names the file**, in this module's own shape rather than P4's:
    the path as the operator wrote it goes in the message, and what it expanded
    to goes in the hint, exactly as :func:`_from_file`'s four failures already do.
    Not :attr:`~sopuli.config.errors.ConfigError.source`, which the boundary
    renders as a ``file:line:col`` prefix and which means *the document being
    parsed* everywhere else -- a token file is not one, and putting it there
    would print the path in front of the ``vault "..."`` breadcrumb that says
    which store asked. The flag goes in the hint too: an operator with a token
    file, a ``token:`` key and two variables in play needs to know which of the
    four the run had in force.
    """
    wrote = str(path)
    secret = _from_file(path, where=where, wrote=wrote)
    resolved = path.expanduser()
    try:
        check_permissions(resolved, what=f"the token file {wrote}")
    except ConfigError as error:
        raise MaterialError(
            f"{where}: {error.message}",
            at=ROOT,
            hint="; ".join(
                part
                for part in (error.hint, f"{TOKEN_FLAG} named it, looked in {resolved}")
                if part
            ),
        ) from error
    return secret


def _from_env(name: str, *, env: Mapping[str, str], where: str) -> Secret:
    value = env.get(name)
    if not value:
        # Set-but-empty is "said nothing", per §6's rule for the whole table --
        # so a CI job clearing an inherited variable gets the same message as one
        # that never set it, which is the same situation described two ways.
        raise MaterialError(
            f"{where}: the environment variable {name} is not set",
            at=ROOT,
            hint=(
                "an empty value counts as unset (§6). Check the name, and that whatever "
                "exports it runs in the same process tree as this command"
            ),
        )
    return Secret(value)


def _from_file(path: Path, *, where: str, wrote: str) -> Secret:
    """Read one file, and say precisely which way it failed.

    ``wrote`` is what the config says rather than what it expanded to, so the
    message can quote the line the operator typed while the hint shows where it
    looked.

    **No permission check.** ``sopuli/config/permissions.py`` guards the *config
    file* under P4, because the tool chose where that lives and reads it on every
    invocation. This path is somebody else's: a Kubernetes projected token is
    mounted 0644 by the platform, and refusing to read it would break a method P2
    lists. The asymmetry is deliberate and `01-configuration.md` §3a says so.
    """
    resolved = path.expanduser()
    try:
        # **Bytes, then decode.** `read_text` opens in text mode, where Python's
        # universal-newline translation rewrites a CRLF, and a lone CR, into a
        # bare LF before this code ever sees them. For ordinary text that is a
        # convenience; for a credential it is the platform silently altering the
        # value, and a secret containing a carriage return would authenticate
        # nowhere while the file on disk looked exactly right. Reading bytes is
        # also what makes the newline handling below mean what it says, rather
        # than being dead code the decoder had already run.
        text = resolved.read_bytes().decode("utf-8")
    except FileNotFoundError as error:
        raise MaterialError(
            f"{where}: no file at {wrote}", at=ROOT, hint=f"looked in {resolved}"
        ) from error
    except IsADirectoryError as error:
        raise MaterialError(
            f"{where}: {wrote} is a directory, not a file", at=ROOT, hint=f"looked in {resolved}"
        ) from error
    except UnicodeDecodeError as error:
        # Named apart from "unreadable" because the fix is different and the
        # cause is usually a real one: a DER certificate or a key file saved by
        # a tool that wrote UTF-16.
        raise MaterialError(
            f"{where}: {wrote} is not UTF-8 text", at=ROOT, hint=f"looked in {resolved}"
        ) from error
    except OSError as error:
        raise MaterialError(
            f"{where}: could not read {wrote}: {error.strerror or error}",
            at=ROOT,
            hint=f"looked in {resolved}; check the file's permissions and the path above it",
        ) from error

    value = strip_one_newline(text)
    if not value:
        # An empty *file* is not the same as a missing one: it exists, something
        # created it, and the likely cause is a write that failed rather than a
        # path that is wrong. Same message for both would send somebody looking
        # in the wrong place.
        raise MaterialError(f"{where}: {wrote} is empty", at=ROOT, hint=f"looked in {resolved}")
    return Secret(value)


def strip_one_newline(text: str) -> str:
    """Remove exactly one trailing newline, and nothing else.

        **Public because there is more than one caller, and a second copy drifted.**
        `creds generate --from-stdin` reimplemented this rule, stripped only ``
    ``,
        and left a ``
    `` on every password piped in on Windows -- which is exactly
        where P4 demands identical behaviour. The rule is subtle enough to be worth
        stating once (below) and subtle enough that restating it goes wrong.

        ``~/.vault-token`` is the case that makes this load-bearing: Vault's own CLI
        writes it without a trailing newline and every text editor adds one, and a
        token with ``\\n`` on the end fails authentication with a 403 that says
        nothing whatever about whitespace.

        Not ``.strip()``. Leading whitespace in a secret is somebody's real secret,
        and a generated password may legitimately begin or end with a space in a
        charset that allows one -- silently trimming it is a bug that surfaces once,
        much later, as a password that works nowhere.
    """
    if text.endswith("\r\n"):
        return text[:-2]
    if text.endswith("\n"):
        return text[:-1]
    return text


def environment() -> Mapping[str, str]:
    """The process environment, for the boundary that has to supply one.

    Exists so that :data:`os.environ` appears once in this module's callers
    rather than once per call site -- the same reason
    :func:`sopuli.config.discovery.discover` takes its mapping as an argument.
    """
    return os.environ

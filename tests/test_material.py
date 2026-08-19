"""Resolving auth material (#137). Tier 0, and no ambient environment.

Every test passes its own mapping, so these run beside each other and beside
everything else -- the arrangement `discover` and `resolve_color` already use.
Nothing here touches `os.environ`, which the last test asserts rather than
trusts.

What is being protected is small and easy to get subtly wrong: a trailing
newline that fails authentication with a 403 mentioning no whitespace, and five
ways of "there was nothing to read" that an operator fixes in five different
places.
"""

from __future__ import annotations

import inspect
import os
import pathlib
import subprocess
import sys
from pathlib import Path

import pytest

from sopuli.config.model import MaterialRef
from sopuli.material import (
    TOKEN_FLAG,
    TOKEN_SOURCES,
    TOKEN_VARIABLES,
    MaterialError,
    resolve,
    resolve_token,
)
from sopuli.secrets import Secret

WHERE = 'vault "vault-prod" auth method "approle" key "secret_id"'

posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX file modes; Windows has no st_mode worth reading",
)
windows_only = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows ACLs; there is no DACL to walk on this platform",
)


def owner_only(path: Path) -> Path:
    """``path``, reachable by nobody but its owner, on either platform.

    The check ``--vault-token-file`` goes through is P4's, so a token file a test
    means to be *acceptable* has to actually be locked down -- a file written
    under ``tmp_path`` on POSIX inherits the umask and is usually 0644.
    """
    if sys.platform == "win32":
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{os.environ['USERNAME']}:F"],
            capture_output=True,
            check=True,
        )
    else:
        path.chmod(0o600)
    return path


def token_file(directory: Path, value: str = "s.from-flag") -> Path:
    """A token file the permission check accepts."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "token"
    path.write_text(value, encoding="utf-8")
    return owner_only(path)


def env_ref(name: str = "SOPULI_VAULT_SECRET_ID") -> MaterialRef:
    return MaterialRef(kind="env", location=name)


def file_ref(path: Path) -> MaterialRef:
    return MaterialRef(kind="file", location=str(path))


# ------------------------------------------------------------------ env ---


def test_an_environment_variable_resolves() -> None:
    secret = resolve(env_ref(), env={"SOPULI_VAULT_SECRET_ID": "s3cr3t"}, where=WHERE)

    assert secret.reveal() == "s3cr3t"


def test_what_comes_back_is_a_secret_and_renders_as_one() -> None:
    """Invariant 2, asserted here rather than trusted from `test_redaction.py`:
    this is a new plaintext-adjacent path, and the invariant names exactly three
    places plaintext may legitimately exist."""
    secret = resolve(env_ref(), env={"SOPULI_VAULT_SECRET_ID": "s3cr3t"}, where=WHERE)

    assert isinstance(secret, Secret)
    assert str(secret) == repr(secret) == "***"
    assert f"{secret}" == "***"
    assert "s3cr3t" not in f"{secret!r} {secret} {secret:>20}"


def test_an_unset_variable_names_itself_and_the_position() -> None:
    with pytest.raises(MaterialError) as caught:
        resolve(env_ref(), env={}, where=WHERE)

    message = str(caught.value)
    assert "SOPULI_VAULT_SECRET_ID" in message
    assert "secret_id" in message  # which key asked
    assert "vault-prod" in message  # which store asked


def test_a_variable_set_empty_counts_as_unset() -> None:
    """§6's rule for the whole table. A CI job clearing an inherited variable is
    in the same situation as one that never set it, and should not have to read
    two different messages to learn so."""
    with pytest.raises(MaterialError):
        resolve(env_ref(), env={"SOPULI_VAULT_SECRET_ID": ""}, where=WHERE)


def test_the_value_never_reaches_the_message() -> None:
    """The failure path cannot leak what the success path protects."""
    with pytest.raises(MaterialError) as caught:
        resolve(env_ref("MISSING"), env={"MISSING": ""}, where=WHERE)

    assert "***" not in str(caught.value)  # nothing was read, so nothing to redact
    assert str(caught.value).count("MISSING") >= 1


# ----------------------------------------------------------------- file ---


def test_a_file_resolves(tmp_path: Path) -> None:
    path = tmp_path / "secret_id"
    path.write_text("s3cr3t", encoding="utf-8")

    assert resolve(file_ref(path), env={}, where=WHERE).reveal() == "s3cr3t"


@pytest.mark.parametrize("ending", ["\n", "\r\n"])
def test_exactly_one_trailing_newline_is_stripped(tmp_path: Path, ending: str) -> None:
    """The case that makes this load-bearing: Vault's CLI writes ~/.vault-token
    without a trailing newline and every editor adds one, and a token with one on
    the end fails with a 403 that says nothing about whitespace."""
    path = tmp_path / "token"
    # Bytes, not `write_text`: in text mode on Windows the newline would be
    # translated again on the way out, putting something else on disk, and the
    # test would be measuring pytest's file handling rather than the resolver's.
    path.write_bytes(f"s.aaaa{ending}".encode())

    assert resolve(file_ref(path), env={}, where=WHERE).reveal() == "s.aaaa"


def test_only_one_newline_is_stripped(tmp_path: Path) -> None:
    """Two means the second one is part of the value, as far as this can tell.
    Guessing further is how a real secret gets quietly altered."""
    path = tmp_path / "token"
    path.write_bytes(b"s.aaaa\n\n")

    assert resolve(file_ref(path), env={}, where=WHERE).reveal() == "s.aaaa\n"


def test_a_carriage_return_inside_a_secret_survives(tmp_path: Path) -> None:
    """The reason the resolver reads bytes rather than text.

    Python's text mode applies universal-newline translation, which rewrites a
    lone carriage return into a line feed before any of this code sees it. For
    prose that is a convenience; for a credential it is the platform quietly
    altering the value, and the symptom is a secret that authenticates nowhere
    while the file on disk looks exactly right.
    """
    path = tmp_path / "password"
    path.write_bytes(b"we\rird\n")

    assert resolve(file_ref(path), env={}, where=WHERE).reveal() == "we\rird"


def test_leading_and_interior_whitespace_survive(tmp_path: Path) -> None:
    """Not `.strip()`. Leading whitespace in a secret is somebody's real secret,
    and a generated password may legitimately begin with a space in a charset
    that allows one -- trimming it is a bug that surfaces much later as a
    password that works nowhere."""
    path = tmp_path / "password"
    path.write_bytes(b"  sp ace  \n")

    assert resolve(file_ref(path), env={}, where=WHERE).reveal() == "  sp ace  "


def test_a_missing_file_says_where_it_looked(tmp_path: Path) -> None:
    path = tmp_path / "not-there"

    with pytest.raises(MaterialError) as caught:
        resolve(file_ref(path), env={}, where=WHERE)

    assert str(path) in str(caught.value)
    assert "secret_id" in str(caught.value)


def test_an_empty_file_is_not_a_missing_one(tmp_path: Path) -> None:
    """It exists, something created it, and the likely cause is a write that
    failed rather than a path that is wrong. One message for both would send
    somebody looking in the wrong place."""
    path = tmp_path / "secret_id"
    path.write_text("", encoding="utf-8")

    with pytest.raises(MaterialError) as caught:
        resolve(file_ref(path), env={}, where=WHERE)

    assert "empty" in str(caught.value)


def test_a_file_holding_only_a_newline_is_empty(tmp_path: Path) -> None:
    """What `printf '\\n' > token` leaves behind, and it is worth catching here:
    the alternative is authenticating with the empty string and reading a 403."""
    path = tmp_path / "token"
    path.write_bytes(b"\n")

    with pytest.raises(MaterialError) as caught:
        resolve(file_ref(path), env={}, where=WHERE)

    assert "empty" in str(caught.value)


def test_a_directory_is_named_as_such(tmp_path: Path) -> None:
    """A real mistake with mounted secrets: the mount point is the directory and
    the value is a file inside it."""
    with pytest.raises(MaterialError) as caught:
        resolve(file_ref(tmp_path), env={}, where=WHERE)

    assert "directory" in str(caught.value)


def test_a_file_that_is_not_utf8_is_named_as_such(tmp_path: Path) -> None:
    """Usually a DER certificate or something a tool saved as UTF-16, and the fix
    is different from every other failure here."""
    path = tmp_path / "secret_id"
    path.write_bytes(b"\xff\xfe\x00\x01 not text")

    with pytest.raises(MaterialError) as caught:
        resolve(file_ref(path), env={}, where=WHERE)

    assert "UTF-8" in str(caught.value)


def test_a_tilde_path_is_expanded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    (tmp_path / ".vault-token").write_bytes(b"s.from-home\n")

    ref = MaterialRef(kind="file", location="~/.vault-token")

    assert resolve(ref, env={}, where=WHERE).reveal() == "s.from-home"


# ------------------------------------------------------- the token chain ---


def test_a_written_token_wins_outright(tmp_path: Path) -> None:
    """The chain exists because the key is *optional*, not to be preferred over
    it."""
    path = tmp_path / "token"
    path.write_text("s.from-file", encoding="utf-8")

    secret = resolve_token(
        ref=file_ref(path),
        env={"VAULT_TOKEN": "s.from-env"},
        token_file=token_file(tmp_path / "flag"),
        where=WHERE,
    )

    assert secret.reveal() == "s.from-file"


def test_the_flag_outranks_the_environment(tmp_path: Path) -> None:
    secret = resolve_token(
        ref=None,
        env={"VAULT_TOKEN": "s.from-env"},
        token_file=token_file(tmp_path),
        where=WHERE,
    )

    assert secret.reveal() == "s.from-flag"


# ------------------------------------------------ --vault-token-file (#145) ---


def test_the_flag_names_a_path_and_never_a_token() -> None:
    """#145's decision, as the only shape the signature admits.

    ``resolve_token`` takes a *path*; there is no parameter anywhere on this
    chain that a command-line **value** could arrive on, which is what makes
    invariant 1 structural here rather than remembered. The assertion is on the
    signature because that is the thing a future edit would break.
    """
    parameters = inspect.signature(resolve_token).parameters

    assert parameters["token_file"].annotation == "Path | None"
    assert "flag" not in parameters


def test_the_flags_file_is_read_like_any_other(tmp_path: Path) -> None:
    """One trailing newline stripped, bytes rather than text -- the token file
    the flag names gets the same treatment as the one the config names."""
    path = tmp_path / "token"
    path.write_bytes(b"s.from-flag\n")
    owner_only(path)

    assert resolve_token(ref=None, env={}, token_file=path, where=WHERE).reveal() == "s.from-flag"


def test_a_tilde_in_the_flags_path_is_quoted_as_written_and_expanded_in_the_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`_from_file`'s split, applied to the refusal as well as to the read.

    The message quotes the line the operator typed and the hint shows where it
    looked, so a `~` that expanded somewhere surprising is visible rather than
    silently substituted.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    (tmp_path / "tok").write_text("s.exposed", encoding="utf-8")
    if sys.platform != "win32":
        (tmp_path / "tok").chmod(0o644)
    else:
        subprocess.run(
            ["icacls", str(tmp_path / "tok"), "/grant", "*S-1-1-0:(R)"],
            capture_output=True,
            check=True,
        )

    written = Path("~/tok")

    with pytest.raises(MaterialError) as caught:
        resolve_token(ref=None, env={}, token_file=written, where=WHERE)

    message = str(caught.value)
    # `str(written)`, not the literal: click hands the flag over as a `Path`, so
    # what the operator "wrote" is already in the platform's own spelling.
    assert str(written) in message
    assert str(tmp_path / "tok") in message


def test_a_missing_file_named_by_the_flag_says_so_rather_than_ending_the_chain(
    tmp_path: Path,
) -> None:
    """Naming a file that is not there is a typo, not an exhausted chain.

    Falling through to the variables would be the worse answer twice over: the
    run would authenticate with something the operator did not ask for, or fail
    with "no token anywhere" against a path they can see in their own shell
    history.
    """
    with pytest.raises(MaterialError) as caught:
        resolve_token(
            ref=None,
            env={"VAULT_TOKEN": "s.from-env"},
            token_file=tmp_path / "gone",
            where=WHERE,
        )

    assert "no file at" in str(caught.value)


@posix_only
def test_a_token_file_others_can_read_is_refused(tmp_path: Path) -> None:
    """P4's check, on the one ``file:`` source that gets it (ADR-007).

    A bearer token 0644 on a shared box is what the config-file check exists to
    prevent, one layer down -- and unlike a Kubernetes projected token, this path
    is one the operator typed for this run and can fix now.

    The refusal has to name the *file*, not only the flag: "chmod 600 the file"
    is not actionable against a run with a token file, a `token:` key and two
    variables in play. Which one was in force is the flag's job to say, and which
    file it was is the path's.
    """
    path = tmp_path / "token"
    path.write_text("s.exposed", encoding="utf-8")
    path.chmod(0o644)

    with pytest.raises(MaterialError) as caught:
        resolve_token(ref=None, env={}, token_file=path, where=WHERE)

    message = str(caught.value)
    assert str(path) in message
    assert "0644" in message
    assert TOKEN_FLAG in message
    assert "chmod 600" in message


@windows_only
def test_a_token_file_granted_to_a_third_party_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "token"
    path.write_text("s.exposed", encoding="utf-8")
    owner_only(path)
    subprocess.run(
        ["icacls", str(path), "/grant", "*S-1-1-0:(R)"],  # Everyone, read
        capture_output=True,
        check=True,
    )

    with pytest.raises(MaterialError) as caught:
        resolve_token(ref=None, env={}, token_file=path, where=WHERE)

    message = str(caught.value)
    assert str(path) in message
    assert TOKEN_FLAG in message


@posix_only
def test_a_config_written_token_file_is_still_not_permission_checked(tmp_path: Path) -> None:
    """§3a's asymmetry, which ADR-007 keeps rather than widens.

    ``/run/secrets/...`` belongs to whatever mounted it and a Kubernetes
    projected token arrives 0644. Refusing it would break a method P2 lists, so
    only the path the *command line* names is checked.
    """
    path = tmp_path / "mounted-token"
    path.write_text("s.mounted", encoding="utf-8")
    path.chmod(0o644)

    assert resolve_token(ref=file_ref(path), env={}, where=WHERE).reveal() == "s.mounted"


@posix_only
def test_the_home_token_file_is_still_not_permission_checked(tmp_path: Path) -> None:
    """The last step of the chain is Vault's own file, written 0600 by ``vault
    login`` -- and that login is the bootstrap ADR-007 names as the answer for a
    human at a terminal. Refusing to read the file another tool just wrote for us
    would refuse that path."""
    path = tmp_path / ".vault-token"
    path.write_text("s.from-home", encoding="utf-8")
    path.chmod(0o644)

    assert resolve_token(ref=None, env={}, home=tmp_path, where=WHERE).reveal() == "s.from-home"


def test_the_sopuli_variable_outranks_the_third_party_one() -> None:
    """§6: honoured third-party variables rank *below* their SOPULI_ equivalent.
    §3a's sentence names only VAULT_TOKEN; the order comes from putting the two
    documents together."""
    assert TOKEN_VARIABLES == ("SOPULI_VAULT_TOKEN", "VAULT_TOKEN")

    secret = resolve_token(
        ref=None,
        env={"SOPULI_VAULT_TOKEN": "s.sopuli", "VAULT_TOKEN": "s.third-party"},
        where=WHERE,
    )

    assert secret.reveal() == "s.sopuli"


def test_the_environment_outranks_the_token_file(tmp_path: Path) -> None:
    (tmp_path / ".vault-token").write_text("s.from-file", encoding="utf-8")

    secret = resolve_token(ref=None, env={"VAULT_TOKEN": "s.from-env"}, home=tmp_path, where=WHERE)

    assert secret.reveal() == "s.from-env"


def test_the_token_file_is_the_last_step(tmp_path: Path) -> None:
    (tmp_path / ".vault-token").write_bytes(b"s.from-file\n")

    secret = resolve_token(ref=None, env={}, home=tmp_path, where=WHERE)

    assert secret.reveal() == "s.from-file"


def test_an_empty_environment_variable_falls_through_to_the_file(tmp_path: Path) -> None:
    """Set-but-empty is "said nothing" here too, so clearing an inherited
    variable is a way of asking for the next step rather than an error."""
    (tmp_path / ".vault-token").write_text("s.from-file", encoding="utf-8")

    secret = resolve_token(ref=None, env={"VAULT_TOKEN": ""}, home=tmp_path, where=WHERE)

    assert secret.reveal() == "s.from-file"


def test_the_chain_ends_rather_than_falling_into_another_method(tmp_path: Path) -> None:
    """**The property worth protecting.** An earlier draft fell through to
    AppRole after the last step; falling into a *different* method makes an
    authentication failure impossible to explain, because the thing that failed
    is not the thing the file names. So the end of the chain is an error."""
    with pytest.raises(MaterialError) as caught:
        resolve_token(ref=None, env={}, home=tmp_path, where=WHERE)

    message = str(caught.value)
    # All four sources, not just the flag: somebody in a CI job where writing a
    # token to disk is awkward needs to know the variables already work.
    for source in TOKEN_SOURCES:
        assert source in message
    # Every step it tried, and nothing about a method it did not.
    assert "approle" not in message.lower().replace(WHERE.lower(), "")


def test_an_unreadable_token_file_is_not_reported_as_no_token(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The chain ends only for a file that is genuinely absent.

    `Path.exists()` returns False for a permission error on the way to the file,
    so asking it would report "no token anywhere" for a token sitting right
    there -- and would leave a window between the check and the read besides. So
    the read is attempted and only `FileNotFoundError` becomes the chain-end
    message; every other failure keeps the wording `_from_file` already gave it.

    Simulated rather than produced with real permissions, because the mode bits
    that deny a read differ per platform and the subject here is the branch, not
    the operating system.
    """
    real_read = pathlib.Path.read_bytes

    def refuse(self: pathlib.Path) -> bytes:
        if self.name == ".vault-token":
            raise PermissionError(13, "Permission denied")
        return real_read(self)

    monkeypatch.setattr(pathlib.Path, "read_bytes", refuse)
    (tmp_path / ".vault-token").write_bytes(b"s.unreadable")

    with pytest.raises(MaterialError) as caught:
        resolve_token(ref=None, env={}, home=tmp_path, where=WHERE)

    message = str(caught.value)
    assert "could not read" in message
    assert "no token" not in message


def test_an_empty_token_file_is_not_reported_as_no_token(tmp_path: Path) -> None:
    """It exists and something wrote it -- most likely a login that produced
    nothing. "No token anywhere" would send somebody to set a variable that was
    never the problem."""
    (tmp_path / ".vault-token").write_bytes(b"")

    with pytest.raises(MaterialError) as caught:
        resolve_token(ref=None, env={}, home=tmp_path, where=WHERE)

    assert "empty" in str(caught.value)


def test_nothing_here_reads_the_real_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Asserted rather than trusted: a single `os.environ` lookup would make
    every test above depend on the machine running it."""
    monkeypatch.setenv("VAULT_TOKEN", "s.from-the-real-environment")

    with pytest.raises(MaterialError):
        resolve(env_ref("VAULT_TOKEN"), env={}, where=WHERE)

    assert os.environ["VAULT_TOKEN"] == "s.from-the-real-environment"

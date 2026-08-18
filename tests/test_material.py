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

import os
import pathlib
from pathlib import Path

import pytest

from sopuli.config.model import MaterialRef
from sopuli.material import (
    TOKEN_VARIABLES,
    MaterialError,
    resolve,
    resolve_token,
)
from sopuli.secrets import Secret

WHERE = 'vault "vault-prod" auth method "approle" key "secret_id"'


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
        flag=Secret("s.from-flag"),
        where=WHERE,
    )

    assert secret.reveal() == "s.from-file"


def test_the_flag_outranks_the_environment(tmp_path: Path) -> None:
    secret = resolve_token(
        ref=None, env={"VAULT_TOKEN": "s.from-env"}, flag=Secret("s.from-flag"), where=WHERE
    )

    assert secret.reveal() == "s.from-flag"


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
    assert "--vault-token" in message
    assert "VAULT_TOKEN" in message
    assert "~/.vault-token" in message
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

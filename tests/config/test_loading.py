"""The file layer end to end: `load_document`, and `load_config` on top of it.

Fixtures use the fictional vocabulary the provenance note in
``01-configuration.md`` requires -- application ``acme``, accounts
``acme_*_user``, tenants ``alpha``…``theta``, hosts under ``example.com``. Never
a real hostname, account or vault path, in a test any more than in a document.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import SUPPORTED_VERSIONS, load_config, load_document

MINIMAL = "version: 1\n"

WORKED_EXAMPLE = """
version: 1

defaults:
  policy: app-standard

vaults:
  vault-dev:
    type: hashicorp
    addr: https://vault-dev.example.com
    mount: kv
    kv_version: 2
    auth: { method: token }

targets:
  - name: cdb-root-dev
    type: oracle
    environment: dev
    vault: vault-dev
    dsn: "db-dev.example.com:1521/CDBDEV.pdb.example.com"

accounts:
  - acme_web_user
  - acme_api_user

secret_template: "tenants/{tenant}#DB_CREDENTIALS/{account}"
policy: app-standard
"""


def test_a_minimal_document_loads(write_config: Callable[[str], Path]) -> None:
    assert load_document(write_config(MINIMAL)) == {"version": 1}


def test_the_worked_example_from_the_design_document_loads(
    write_config: Callable[[str], Path],
) -> None:
    """01-configuration.md §2 is the specification, so its own example must load.

    Not a full shape check -- that is the schema layer's job -- but if the
    document's example cannot get through the file layer, one of the two is
    wrong and this is where it shows up cheapest.
    """
    document = load_document(write_config(WORKED_EXAMPLE))

    assert document["accounts"] == ["acme_web_user", "acme_api_user"]
    assert document["vaults"]["vault-dev"]["addr"] == "https://vault-dev.example.com"


def test_a_byte_order_mark_is_tolerated(tmp_path: Path) -> None:
    """Notepad writes one and offers no way not to. Windows is a supported tier."""
    path = tmp_path / "sopuli.yaml"
    path.write_bytes(b"\xef\xbb\xbf" + MINIMAL.encode("utf-8"))
    if sys.platform != "win32":
        path.chmod(0o600)

    assert load_document(path) == {"version": 1}


def test_a_missing_file_says_so(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as caught:
        load_document(tmp_path / "absent.yaml")

    assert "does not exist" in str(caught.value)
    assert "--config" in str(caught.value)


def test_a_directory_is_not_reported_as_a_missing_file(tmp_path: Path) -> None:
    """`--config /etc/sopuli` instead of `--config /etc/sopuli/sopuli.yaml`.

    The path exists and is spelled correctly, so "does not exist" would send
    someone hunting for a typo that is not there.
    """
    directory = tmp_path / "sopuli"
    directory.mkdir()

    with pytest.raises(ConfigError) as caught:
        load_document(directory)

    rendered = str(caught.value)
    assert "not a file" in rendered
    assert "does not exist" not in rendered


def test_invalid_utf8_is_reported_as_such(tmp_path: Path) -> None:
    path = tmp_path / "sopuli.yaml"
    path.write_bytes(b"version: 1\nname: \xff\xfe\n")
    if sys.platform != "win32":
        path.chmod(0o600)

    with pytest.raises(ConfigError) as caught:
        load_document(path)

    assert "UTF-8" in str(caught.value)


# ------------------------------------------------------------------ shape ---


def test_an_empty_file_is_refused(write_config: Callable[[str], Path]) -> None:
    """Distinguished from the wrong-type case: the fix is to write some config."""
    with pytest.raises(ConfigError) as caught:
        load_document(write_config("# nothing but a comment\n"))

    assert "empty" in str(caught.value)


@pytest.mark.parametrize(
    "document",
    ["- acme_web_user\n- acme_api_user\n", "just a string\n", "42\n"],
    ids=["a list", "a string", "a number"],
)
def test_a_root_that_is_not_a_mapping_is_refused(
    write_config: Callable[[str], Path], document: str
) -> None:
    with pytest.raises(ConfigError) as caught:
        load_document(write_config(document))

    assert "must contain a mapping" in str(caught.value)


# ---------------------------------------------------------------- version ---


def test_a_document_with_no_version_is_refused(write_config: Callable[[str], Path]) -> None:
    """A file with no version cannot be migrated later: there is nothing to tell
    "written before versioning" from "written for a version we do not have"."""
    with pytest.raises(ConfigError) as caught:
        load_document(write_config("accounts: [acme_web_user]\n"))

    rendered = str(caught.value)
    assert "does not declare a version" in rendered
    assert "version" in rendered


def test_an_unsupported_version_names_what_is_supported(
    write_config: Callable[[str], Path],
) -> None:
    with pytest.raises(ConfigError) as caught:
        load_document(write_config("version: 4\n"))

    assert "unsupported config version 4" in str(caught.value)
    assert str(SUPPORTED_VERSIONS[-1]) in str(caught.value)


@pytest.mark.parametrize("literal", ['"1"', "1.5", "[1]"], ids=["string", "float", "list"])
def test_a_non_integer_version_is_refused(
    write_config: Callable[[str], Path], literal: str
) -> None:
    with pytest.raises(ConfigError) as caught:
        load_document(write_config(f"version: {literal}\n"))

    assert "version must be a number" in str(caught.value)


def test_a_boolean_version_does_not_pass_as_one(write_config: Callable[[str], Path]) -> None:
    """`bool` is a subclass of `int` and `True == 1`, so a membership test alone
    would accept `version: true` as version 1."""
    with pytest.raises(ConfigError) as caught:
        load_document(write_config("version: true\n"))

    assert "version must be a number" in str(caught.value)


def test_the_error_names_the_file_and_the_key(write_config: Callable[[str], Path]) -> None:
    """ "invalid config" is not an error message for a 130-line file."""
    path = write_config("version: 4\n")

    with pytest.raises(ConfigError) as caught:
        load_document(path)

    rendered = str(caught.value)
    assert str(path) in rendered
    assert "version:" in rendered


# ------------------------------------------------------------------ order ---


def test_permissions_are_checked_before_the_file_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reading first would put the contents of a file we are about to refuse
    into the process, which is the only thing the refusal was protecting."""
    path = tmp_path / "sopuli.yaml"
    path.write_text(MINIMAL, encoding="utf-8")
    order: list[str] = []

    def refuse(_: Path) -> None:
        order.append("permissions")
        raise ConfigError("nope")

    def record_read(*_args: object, **_kwargs: object) -> str:
        order.append("read")
        return ""

    monkeypatch.setattr("sopuli.config.loading.check_permissions", refuse)
    monkeypatch.setattr(Path, "read_text", record_read)

    with pytest.raises(ConfigError):
        load_document(path)

    assert order == ["permissions"]


# ---------------------------------------------------------- load_config ---


def test_load_config_builds_the_whole_file(write_config: Callable[[str], Path]) -> None:
    """`load_document` returns raw data; `load_config` is the two layers joined."""
    config = load_config(write_config(WORKED_EXAMPLE))

    assert config.version == 1
    assert [vault.name for vault in config.vaults] == ["vault-dev"]
    assert [target.name for target in config.targets] == ["cdb-root-dev"]
    assert [application.label for application in config.applications] == ["the inline application"]


def test_a_validation_error_names_the_file_it_came_from(
    write_config: Callable[[str], Path],
) -> None:
    """The builders work on raw data and have never seen a filename. Attaching it
    once, at the boundary, is what stops every message being `unknown key` with
    no clue which of several layered `--config` files said it."""
    path = write_config("version: 1\nvaults:\n  vault-dev:\n    type: hashicrop\n")

    with pytest.raises(ConfigError) as caught:
        load_config(path)

    rendered = str(caught.value)
    assert str(path) in rendered
    assert "vaults.vault-dev.type" in rendered

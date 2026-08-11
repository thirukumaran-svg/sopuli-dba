"""Several `--config` files, merged into one document (§9).

The rule is "deep merge for maps, replace for lists", and the asymmetry is the
whole subject. A mapping is a set of named settings and a later file adding one
must not delete the rest; a list is a whole answer, and merging two would produce
an estate that appears in no file -- a bad way to find out what the tool is about
to touch (invariant 5).

Merging happens on raw documents, after each file has been checked on its own.
That ordering is what keeps "this file is unreadable / unparseable / has no
version" pointing at a filename.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import load_config_from, load_documents, merge_documents

BASE = """
version: 1
vaults:
  vault-dev: { type: hashicorp, addr: "https://dev.example.com", kv_version: 2 }
targets:
  - name: cdb-root-dev
    type: oracle
    dsn: db-dev.example.com:1521/CDBDEV.pdb.example.com
"""


# ------------------------------------------------------------ merge rules ---


def test_a_later_document_wins_key_by_key() -> None:
    merged = merge_documents([{"version": 1, "a": "first"}, {"a": "second", "b": "new"}])

    assert merged == {"version": 1, "a": "second", "b": "new"}


def test_mappings_merge_rather_than_replace() -> None:
    """The reason the rule is not simply last-one-wins: an overlay that sets
    `vaults.vault-dev.addr` must not delete `vaults.vault-prod`."""
    merged = merge_documents(
        [
            {"vaults": {"dev": {"type": "hashicorp", "kv_version": 2}, "prod": {"type": "oci"}}},
            {"vaults": {"dev": {"addr": "https://elsewhere.example.com"}}},
        ]
    )

    assert merged["vaults"]["prod"] == {"type": "oci"}
    assert merged["vaults"]["dev"] == {
        "type": "hashicorp",
        "kv_version": 2,
        "addr": "https://elsewhere.example.com",
    }


def test_mappings_merge_at_every_depth() -> None:
    merged = merge_documents(
        [
            {"target_sets": {"appdb": {"for_each": {"env": {"dev": {"host": "a.example.com"}}}}}},
            {"target_sets": {"appdb": {"for_each": {"env": {"qa": {"host": "b.example.com"}}}}}},
        ]
    )

    assert sorted(merged["target_sets"]["appdb"]["for_each"]["env"]) == ["dev", "qa"]


def test_lists_are_replaced_whole() -> None:
    """Concatenating would build an estate that appears in no file, and
    `accounts:` is the list where that matters most (invariant 5)."""
    merged = merge_documents([{"accounts": ["acme_web_user"]}, {"accounts": ["acme_api_user"]}])

    assert merged["accounts"] == ["acme_api_user"]


def test_a_scalar_replaces_a_mapping_and_the_other_way_round() -> None:
    """Not a merge case at all: the types disagree, so the later file is simply
    the answer. Merging them would invent a third shape."""
    assert merge_documents([{"a": {"b": 1}}, {"a": "plain"}])["a"] == "plain"
    assert merge_documents([{"a": "plain"}, {"a": {"b": 1}}])["a"] == {"b": 1}


def test_merging_does_not_mutate_the_documents_it_was_given() -> None:
    """The loader hands these straight from the parser; a merge that edited them
    in place would make the second of two identical runs behave differently."""
    first: dict[str, Any] = {"vaults": {"dev": {"type": "hashicorp"}}}
    second: dict[str, Any] = {"vaults": {"dev": {"addr": "https://v.example.com"}}}

    merge_documents([first, second])

    assert first == {"vaults": {"dev": {"type": "hashicorp"}}}
    assert second == {"vaults": {"dev": {"addr": "https://v.example.com"}}}


def test_merging_nothing_is_an_empty_document() -> None:
    assert merge_documents([]) == {}


# ------------------------------------------------------------- the loader ---


def test_layered_files_load_as_one_config(tmp_path: Path, write_at: WriteAt) -> None:
    base = write_at(tmp_path / "base.yaml", BASE)
    overlay = write_at(tmp_path / "overlay.yaml", "version: 1\nvaults:\n  extra: { type: file }\n")

    config = load_config_from([base, overlay])

    assert [vault.name for vault in config.vaults] == ["vault-dev", "extra"]
    assert config.expanded_targets[0].name == "cdb-root-dev"


def test_an_overlay_can_redirect_a_setting_without_restating_the_rest(
    tmp_path: Path, write_at: WriteAt
) -> None:
    """P3's rationale for layering at all: a shared config committed to a repo,
    redirected per execution context without editing it."""
    base = write_at(tmp_path / "base.yaml", BASE)
    overlay = write_at(
        tmp_path / "overlay.yaml",
        'version: 1\nvaults:\n  vault-dev: { addr: "https://ci.example.com" }\n',
    )

    (vault,) = load_config_from([base, overlay]).vaults

    assert vault.addr == "https://ci.example.com"
    assert vault.type == "hashicorp"
    assert vault.kv_version == 2


def test_every_layer_is_checked_as_a_file_first(tmp_path: Path, write_at: WriteAt) -> None:
    """A parse error in the second file names the second file. Merging first
    would leave a message about a document that exists on no disk."""
    good = write_at(tmp_path / "base.yaml", BASE)
    broken = write_at(tmp_path / "broken.yaml", "version: 1\nvaults: [unclosed\n")

    with pytest.raises(ConfigError) as caught:
        load_documents([good, broken])

    assert str(broken) in str(caught.value)


def test_every_layer_declares_its_own_version(tmp_path: Path, write_at: WriteAt) -> None:
    """§9a requires it because a file with no version cannot be migrated later,
    and that does not weaken when the file is one of several."""
    base = write_at(tmp_path / "base.yaml", BASE)
    fragment = write_at(tmp_path / "fragment.yaml", "vaults:\n  extra: { type: file }\n")

    with pytest.raises(ConfigError) as caught:
        load_config_from([base, fragment])

    rendered = str(caught.value)
    assert "does not declare a version" in rendered
    assert str(fragment) in rendered


def test_a_validation_error_over_layers_keeps_its_key_path(
    tmp_path: Path, write_at: WriteAt
) -> None:
    """With one file an error names it. With several it cannot: the value may
    have been written in one and overridden in another, and naming either would
    be a guess. The key path is what locates it instead.
    """
    base = write_at(tmp_path / "base.yaml", BASE)
    overlay = write_at(tmp_path / "overlay.yaml", "version: 1\nvaults:\n  extra: { type: nope }\n")

    with pytest.raises(ConfigError) as caught:
        load_config_from([base, overlay])

    rendered = str(caught.value)
    assert "vaults.extra.type" in rendered
    assert str(base) not in rendered


def test_one_layer_still_names_its_file(tmp_path: Path, write_at: WriteAt) -> None:
    """The common case must not lose anything to the general one."""
    only = write_at(tmp_path / "only.yaml", "version: 1\nvaults:\n  extra: { type: nope }\n")

    with pytest.raises(ConfigError) as caught:
        load_config_from([only])

    assert str(only) in str(caught.value)


def test_loading_no_files_at_all_is_refused() -> None:
    """Unreachable through the CLI, since discovery raises first. Held here so
    that a future caller assembling paths itself cannot get an empty config
    object out of an empty list."""
    with pytest.raises(ConfigError) as caught:
        load_config_from([])

    assert "no config file to load" in str(caught.value)


WriteAt = Callable[[Path, str], Path]


@pytest.fixture
def write_at() -> WriteAt:
    """Write a config file at an exact path, with permissions P4 accepts."""

    def write(path: Path, text: str) -> Path:
        path.write_text(text, encoding="utf-8")
        if sys.platform != "win32":
            path.chmod(0o600)
        return path

    return write
